-- PKM §2.3 and §2.5 — the kernel emission API and the write path's
-- internals. What a guest can witness is here as a runtime test; what
-- runs only inside the kernel is deferred to the named case in the
-- pkm_kunit_kmes suite, which drives the same functions directly.

local sys = require("helpers.sys")
local kmes = require("helpers.kmes")
local stratafs = require("helpers.stratafs")

local vm = provium:vm("v", "kernel-only"):boot()
local vm2 = provium:vm("v2", "kernel-only", { cpus = 2 }):boot()

test("a kernel emitter writes to the CPU the caller executes on",
    { spec = "PKM *kernel-emit.executing-cpu" }, function(t)
        -- A worker pinned to cpu 1 triggers a copy-up: KACS's audit
        -- emitter runs in the caller's context, so the event lands on
        -- ring 1 and nowhere else.
        stratafs.with(vm2, "kmes-kcpu", {
            { name = "dest", flags = { "create" } },
            { name = "src", flags = { "ro" }, entries = { f = "original" } },
        }, function(s)
            local r0 = kmes.attach(vm2, 0)
            local r1 = kmes.attach(vm2, 1)
            t:assert(r0 and r1, "both rings attach")
            local worker = vm2:spawn_worker()
            local ok, err = pcall(function()
                t:assert_eq(worker:syscall(sys.NR.sched_setaffinity, {
                    args = { 0, 8, 0 },
                    bufs = { string.pack("<I8", 2) }, ptrs = { 2 },
                }).ret, 0, "the worker pins to cpu 1")
                local fd, errno = sys.open(worker, s:join("f"), sys.O.WRONLY)
                t:assert(fd, "opens the merged file: " ..
                    sys.errname(errno or 0))
                t:assert_eq(sys.write(worker, fd, "modified").ret, 8,
                    "and writes, copying up on cpu 1")
                sys.close(worker, fd)
            end)
            worker:kill(); worker:join()
            local on0 = kmes.of_type(kmes.drain(r0), "STRATAFS_COPY_UP")
            local on1 = kmes.of_type(kmes.drain(r1), "STRATAFS_COPY_UP")
            kmes.detach(r0); kmes.detach(r1)
            if not ok then error(err, 0) end
            t:assert_eq(#on1, 1, "the audit event is on cpu 1's ring")
            t:assert_eq(#on0, 0, "and nowhere else")
            t:assert_eq(on1[1].cpu, 1, "stamped with the CPU that wrote it")
        end)
    end)

test("rings persist independently of their consumers",
    { spec = "PKM *ring.independent-refcounted" }, function(t)
        -- Every consumer detaches; the ring carries on — the same
        -- object, its counters intact, greets the next one.
        local a = kmes.attach(vm, 0)
        t:assert(a, "a consumer attaches")
        t:assert_eq(kmes.emit(vm, "PIT_REF", kmes.PAYLOAD).ret, 0, "emit")
        local seq = kmes.of_type(kmes.drain(a), "PIT_REF")[1].sequence
        kmes.detach(a)
        t:assert_eq(kmes.emit(vm, "PIT_REF", kmes.PAYLOAD).ret, 0,
            "emission with no consumer at all")
        local b = kmes.attach(vm, 0)
        t:assert(b, "a later consumer attaches")
        t:assert_eq(kmes.emit(vm, "PIT_REF", kmes.PAYLOAD).ret, 0, "emit")
        local again = kmes.of_type(kmes.drain(b), "PIT_REF")[1]
        kmes.detach(b)
        t:assert_eq(again.sequence, seq + 2,
            "the same counter continued across the consumerless gap")
    end)

test("the overwrite walk keeps the live span within capacity",
    { spec = "PKM *ring.overwrite-advances-tail-first" }, function(t)
        -- Sampled between emits: the tail only ever advances, and at
        -- every step write - tail fits the buffer — the walk makes
        -- room before data lands, never after.
        local content = string.rep("ef", 29956)
        local payload = "\xda" .. string.pack(">I2", #content) .. content
        local ring = kmes.attach(vm, 0)
        t:assert(ring, "a ring attaches")
        local _, last_tail = kmes.positions(ring)
        for i = 1, 75 do
            t:assert_eq(kmes.emit(vm, "PIT_WALK", payload).ret, 0, "emit " .. i)
            local w, tl = kmes.positions(ring)
            t:assert(w - tl <= ring.capacity,
                "span within capacity at step " .. i)
            t:assert(tl >= last_tail, "tail monotone at step " .. i)
            last_tail = tl
        end
        t:assert(last_tail > 0, "and the walk really ran")
        kmes.detach(ring)
    end)

test("the capacity is a power of two inside the permitted range",
    { spec = "PKM *ring.capacity-range" }, function(t)
        local ring = kmes.attach(vm, 0)
        t:assert(ring, "a ring attaches")
        t:assert(ring.capacity >= 65536 and ring.capacity <= 268435456,
            "within 64 KiB to 256 MiB")
        t:assert_eq(ring.capacity & (ring.capacity - 1), 0, "a power of two")
        t:assert_eq(ring.capacity, 4194304, "the 4 MiB default, unconfigured")
        kmes.detach(ring)
    end)

test("rings exist for every possible CPU from initialisation",
    { spec = "PKM *ring.created-at-init-for-possible-cpus" }, function(t)
        -- Both of vm2's rings attach at generation 1 — created when
        -- the module loaded, never swapped, and cpu 1's was shown
        -- virgin (write_pos 0, first sequence 1) by wire.test.lua
        -- before anything had touched it.
        for cpu = 0, 1 do
            local ring = kmes.attach(vm2, cpu)
            t:assert(ring, "cpu " .. cpu .. "'s ring attaches")
            t:assert_eq(string.unpack("<I8", vm2:read_mem(ring.addr + 32, 8)),
                1, "at generation 1")
            kmes.detach(ring)
        end
    end)

test("a failing batch's validated prefix is visible, whole",
    { spec = "PKM *batch.prefix-visible-atomically" }, function(t)
        -- The observable face: after a batch fails at entry 3, the
        -- ring holds entries 1 and 2 complete — never a bare header,
        -- never entry 3. (That the prefix appears in one publication
        -- is the kernel-side half, under the pkm_kunit_kmes batch
        -- cases.)
        local batch = {
            { type = "PIT_PREFIX", payload = kmes.PAYLOAD },
            { type = "PIT_PREFIX", payload = "\x92\x01\x02" },
            { type = "PIT_PREFIX", payload = "\xc1" },
        }
        local events = kmes.recording(t, vm, function()
            t:assert_eq(kmes.emit_batch(vm, batch).errno, sys.E.INVAL,
                "the batch fails at its third entry")
        end)
        local mine = kmes.of_type(events, "PIT_PREFIX")
        t:assert_eq(#mine, 2, "exactly the prefix is visible")
        t:assert_eq(mine[1].raw:sub(mine[1].header_size + 1), kmes.PAYLOAD,
            "entry one whole")
        t:assert_eq(mine[2].raw:sub(mine[2].header_size + 1), "\x92\x01\x02",
            "entry two whole")
    end)

-- ---- kernel-side, deferred to the KUnit suite -----------------------

local function kunit_stub(name, spec, case, why)
    test(name, { spec = spec, covered_by = "kunit:pkm_kunit_kmes",
                 skip = why .. "; runs under " .. case }, function(t) end)
end

kunit_stub("kernel emission is fire-and-forget",
    "PKM *kernel-emit.fire-and-forget",
    "pkm_kunit_kmes_direct_emit_writes_single_event and the structural-" ..
    "drop case",
    "the API returns void and no guest operation surfaces a kernel " ..
    "emitter's drop")

kunit_stub("kernel emitters are trusted and unvalidated",
    "PKM *kernel-emit.trusted-unvalidated",
    "pkm_kunit_kmes_direct_emit_writes_single_event",
    "only a kernel caller can present an arbitrary payload to the " ..
    "kernel API")

kunit_stub("the kernel structural checks",
    "PKM *kernel-emit.structural-checks",
    "pkm_kunit_kmes_direct_invalid_type_drops_structurally",
    "no reachable kernel emitter produces a structurally invalid event")

kunit_stub("a kernel drop consumes its sequence number",
    "PKM *kernel-emit.drop-consumes-sequence",
    "pkm_kunit_kmes_direct_invalid_type_drops_structurally",
    "provoking a kernel-side drop needs a kernel caller")

kunit_stub("the drop counter is internal",
    "PKM *kernel-emit.drop-counter-internal",
    "the pkm_kunit_kmes suite, whose snapshot interface is the counter's " ..
    "one reader",
    "the counter is by specification not exposed to the ring metadata")

kunit_stub("the kernel batch rejects what the single path faults on",
    "PKM *kernel-emit.batch-stronger-checks",
    "pkm_kunit_kmes_kernel_batch_continues_after_structural_drop",
    "kernel batch descriptors cannot be built from userspace")

kunit_stub("the kernel batch continues past a failing event",
    "PKM *kernel-emit.batch-continues-past-failure",
    "pkm_kunit_kmes_kernel_batch_continues_after_structural_drop",
    "kernel batch descriptors cannot be built from userspace")

kunit_stub("the kernel batch publishes once",
    "PKM *kernel-emit.batch-publishes-once",
    "the pkm_kunit_kmes kernel-batch cases (with " ..
    "pkm_kunit_kmes_kernel_batch_empty_noop for the all-failed batch)",
    "publication ordering is invisible at syscall granularity")

kunit_stub("batch atomicity from deferred publication",
    "PKM *kernel-emit.batch-atomic-visibility",
    "the pkm_kunit_kmes kernel-batch cases",
    "a racing observer cannot be scheduled from the harness at " ..
    "sub-publication granularity")

kunit_stub("one tail transition per batch",
    "PKM *ring.batch-one-tail-transition",
    "the pkm_kunit_kmes kernel-batch cases",
    "tail transitions cannot be sampled mid-syscall from the harness")

kunit_stub("producer metadata is mirrored to the shared page",
    "PKM *ring.mirrored-metadata-stores",
    "pkm_kunit_kmes_attach_mapping_view_tracks_emission",
    "only the shared copy is visible from a guest, so the mirroring " ..
    "itself cannot be witnessed")

kunit_stub("the shared page is shmem, allocated at first attach",
    "PKM *ring.shared-page-lazy-shmem",
    "pkm_kunit_kmes_attach_repeated_same_cpu_shares_consumer_metadata",
    "the pre-attach state is by definition unobservable through a mapping")

kunit_stub("the staged-copy closes the TOCTOU window",
    "PKM *emit.staged-copy-closes-toctou",
    "pkm_kunit_kmes_emit_size_check_precedes_usercopy and the ordering " ..
    "cases around it",
    "the window lies inside one syscall; nothing at syscall granularity " ..
    "can race it")

kunit_stub("an out-of-range depth configuration rejects every payload",
    "PKM *event.payload.bad-depth-config-rejects-all",
    "pkm_kunit_kmes_runtime_nesting_depth_controls_validation and " ..
    "pkm_kunit_kmes_runtime_config_validates_ranges",
    "the range check refuses such a configuration before it can apply, " ..
    "so the defensive rejection needs the validator handed one directly")

kunit_stub("kernel emitters' payloads are never parsed",
    "PKM *event.payload.kernel-not-validated",
    "pkm_kunit_kmes_direct_emit_writes_single_event",
    "every reachable kernel emitter happens to emit valid msgpack")

kunit_stub("identity stamps are null without task context",
    "PKM *event.null-guid-means-unavailable",
    "pkm_kunit_kmes_identity_stamps_match_kacs_state",
    "interrupt-context emission cannot be provoked from a guest")

test("preemption is disabled across the kernel emission path",
    { spec = "PKM *kernel-emit.preemption-disabled-throughout",
      covered_by = "unreachable",
      skip = "a scheduling property with no userspace-visible witness; " ..
             "its consequences (single writer, stable cpu stamp) are " ..
             "tested, the mechanism is not" }, function(t)
    end)

test("pre-initialisation kernel emission is a silent no-op",
    { spec = "PKM *kernel-emit.pre-init-silent",
      covered_by = "unreachable",
      skip = "the window closes before PID 1 starts and the KUnit suite " ..
             "also runs after initialisation — NOTE: no coverage anywhere" },
    function(t)
    end)

test("a ring/CPU identity mismatch discards the event",
    { spec = "PKM *kernel-emit.cpu-mismatch-discard",
      covered_by = "unreachable",
      skip = "the mismatch is a defensive branch no correct caller can " ..
             "produce — NOTE: no KUnit case covers it either" }, function(t)
    end)

test("the kernel batch has no entry-count ceiling",
    { spec = "PKM *kernel-emit.batch-unbounded",
      covered_by = "unreachable",
      skip = "the absence of a bound has no boundary to probe, and only " ..
             "kernel callers reach the API" }, function(t)
    end)

test("the write path takes no locks and no cross-CPU atomics",
    { spec = "PKM *ring.lock-free-single-writer",
      covered_by = "unreachable",
      skip = "an implementation property of kernel code; its observable " ..
             "consequence — per-CPU rings that never interfere — is " ..
             "tested in wire.test.lua" }, function(t)
    end)

test("the wake is skipped before any consumer attaches",
    { spec = "PKM *ring.wake-skipped-before-attach",
      covered_by = "unreachable",
      skip = "the private counter that still advances is not visible " ..
             "until a consumer attaches, at which point the window is " ..
             "over — NOTE: no KUnit case covers it either" }, function(t)
    end)

test("a batch's staging is held simultaneously",
    { spec = "PKM *batch.staging-held-simultaneously",
      covered_by = "unreachable",
      skip = "transient kernel allocation is not measurable from a guest" },
    function(t)
    end)

test("a faulting final emitted_out store reports EFAULT after emitting",
    { spec = "PKM *batch.emitted-out-fault-after-emit",
      covered_by = "unreachable",
      skip = "needs the pointer to become unwritable between the zeroing " ..
             "store and the final one, inside a single syscall" }, function(t)
    end)

test("enumeration skips holes in a sparse possible-CPU mask",
    { spec = "PKM *attach.enumeration-skips-holes",
      skip = "needs a guest whose possible-CPU mask has holes; QEMU's " ..
             "-smp cannot produce one here, so every mask this profile " ..
             "sees is dense" }, function(t)
    end)

test("CPUs possible but offline at initialisation have rings",
    { spec = "PKM *attach.offline-possible-cpus-attachable",
      skip = "needs a guest booted with maxcpus= below its possible set; " ..
             "the profile's cmdline is fixed, so the boot-time offline " ..
             "state cannot be arranged (the taken-offline-later case is " ..
             "failure-modes.test.lua's)" }, function(t)
    end)
