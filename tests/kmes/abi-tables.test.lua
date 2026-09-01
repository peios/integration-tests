-- PKM §2.A and §2.B — the published numbers, each verified against
-- live behaviour: the metadata page offsets, the privilege masks, the
-- configuration constants, the syscall registration, and the
-- event-model bounds the tables encode.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local kmes = require("helpers.kmes")

local vm = provium:vm("v", "kernel-only"):boot()

test("the producer page's fields sit at their published offsets",
    { spec = "PKM *abi.producer-page-offsets" }, function(t)
        local ring = kmes.attach(vm, 0)
        t:assert(ring, "a ring attaches")
        local head = vm:read_mem(ring.addr, 136)
        t:assert_eq(head:sub(1, 8), "KMESRING", "magic at 0")
        t:assert_eq(string.unpack("<I4", head, 9), 1, "version at 8")
        t:assert_eq(string.unpack("<I2", head, 13), 0, "cpu_id at 12")
        t:assert_eq(string.unpack("<I8", head, 17), ring.capacity,
            "capacity at 16")
        t:assert_eq(string.unpack("<I8", head, 25), 8192, "data_offset at 24")
        t:assert(string.unpack("<I8", head, 33) >= 1, "generation at 32")
        local w0 = string.unpack("<I8", head, 65)
        t:assert(w0 >= string.unpack("<I8", head, 73),
            "write_pos at 64, at or past tail_pos at 72")
        t:assert_eq(kmes.emit(vm, "PIT_OFF", kmes.PAYLOAD).ret, 0, "an emit")
        t:assert(string.unpack("<I8", vm:read_mem(ring.addr + 64, 8)) > w0,
            "moves the value at 64 — it really is the write position")
        kmes.detach(ring)
    end)

test("need_wake is the byte at consumer offset 0",
    { spec = "PKM *abi.consumer-page-offset" }, function(t)
        local ring = kmes.attach(vm, 0)
        t:assert(ring, "a ring attaches")
        local c0 = string.unpack("<I8", vm:read_mem(ring.addr + 128, 8))
        t:assert(kmes.poke(vm, ring.addr + 4096, "\x01"),
            "one byte at page 1, offset 0")
        t:assert_eq(kmes.emit(vm, "PIT_NW", kmes.PAYLOAD).ret, 0, "an emit")
        t:assert_eq(string.unpack("<I8", vm:read_mem(ring.addr + 128, 8)),
            c0 + 1, "arms the wake — no other byte does that")
        kmes.poke(vm, ring.addr + 4096, "\x00")
        kmes.detach(ring)
    end)

test("the header base is 77 and header_size locates the payload",
    { spec = "PKM *abi.header-base-size" }, function(t)
        local events = kmes.recording(t, vm, function()
            t:assert_eq(kmes.emit(vm, "PIT_HB", kmes.PAYLOAD).ret, 0, "emit")
        end)
        local e = kmes.of_type(events, "PIT_HB")[1]
        t:assert(e, "the event arrives")
        t:assert_eq(e.header_size, 77 + 6,
            "header_size is KMES_EVENT_HEADER_BASE_SIZE plus the type length")
        t:assert_eq(e.raw:sub(78, 83), "PIT_HB", "and the type begins at 77")
    end)

test("events abut at event_size stride with nothing between",
    { spec = "PKM *event.wire-structure" }, function(t)
        -- The §2.2 structure summary as one observation: the drain
        -- walks the region by event_size alone, and back-to-back
        -- events of different shapes come out intact — true only if
        -- the next event begins exactly at the previous one's size.
        local events = kmes.recording(t, vm, function()
            t:assert_eq(kmes.emit_batch(vm, {
                { type = "PIT_STRIDE_A", payload = kmes.PAYLOAD },
                { type = "PIT_STRIDE_LONGER_NAME", payload = "\x90" },
                { type = "PIT_C", payload = "\x92\x01\x02" },
            }).ret, 0, "three differently-shaped events")
        end)
        t:assert_eq(#kmes.of_type(events, "PIT_STRIDE_A"), 1, "the first")
        t:assert_eq(#kmes.of_type(events, "PIT_STRIDE_LONGER_NAME"), 1,
            "the second, found at the first's event_size")
        local c = kmes.of_type(events, "PIT_C")[1]
        t:assert(c, "the third likewise")
        t:assert_eq(c.raw:sub(c.header_size + 1), "\x92\x01\x02",
            "each carrying exactly its own bytes")
    end)

test("the emit and attach gates are the published mask bits",
    { spec = "PKM *abi.privilege-masks" }, function(t)
        -- KMES_EMIT_REQUIRED_PRIVILEGE is 1<<21 and
        -- KMES_ATTACH_REQUIRED_PRIVILEGE is 1<<8: deleting exactly
        -- that bit disables exactly that syscall.
        kacs.as_dacl_bound(t, vm, function(worker)
            t:assert_eq(kmes.emit(worker, "PIT_MASK", kmes.PAYLOAD).errno,
                sys.E.PERM, "no bit 21: emit refused")
            local r = worker:syscall(kmes.SYS.ATTACH, {
                args = { 0, 0 }, bufs = { string.rep("\0", 8) }, ptrs = { 1 },
            })
            t:assert(r.ret >= 0, "while attach, gated on bit 8, still works")
            sys.close(worker, r.ret)
        end, { privs = kmes.PRIV.AUDIT })
        kacs.as_dacl_bound(t, vm, function(worker)
            t:assert_eq(kmes.emit(worker, "PIT_MASK", kmes.PAYLOAD).ret, 0,
                "no bit 8: emit still works")
            local r = worker:syscall(kmes.SYS.ATTACH, {
                args = { 0, 0 }, bufs = { string.rep("\0", 8) }, ptrs = { 1 },
            })
            t:assert_eq(r.errno, sys.E.PERM, "while attach is refused")
        end, { privs = kmes.PRIV.SECURITY })
    end)

test("the three privileges of the §2.B table behave as named",
    { spec = "PKM *syscalls.privileges-by-name" }, function(t)
        -- SeAuditPrivilege admits emitters, SeSecurityPrivilege admits
        -- consumers, SeTcbPrivilege lifts the rate limit — three
        -- distinct privileges for three distinct roles, exercised by
        -- toggling each on a private token.
        kacs.as_dacl_bound(t, vm, function(worker)
            t:assert(kmes.adjust_priv(worker, kacs, kmes.PRIV.SECURITY, false),
                "SeSecurityPrivilege off")
            t:assert_eq(worker:syscall(kmes.SYS.ATTACH, {
                args = { 0, 0 }, bufs = { string.rep("\0", 8) }, ptrs = { 1 },
            }).errno, sys.E.PERM, "attach refused")
            t:assert_eq(kmes.emit(worker, "PIT_NAMED", kmes.PAYLOAD).ret, 0,
                "emit unaffected")
            t:assert(kmes.adjust_priv(worker, kacs, kmes.PRIV.SECURITY, true),
                "SeSecurityPrivilege back on")
            local r = worker:syscall(kmes.SYS.ATTACH, {
                args = { 0, 0 }, bufs = { string.rep("\0", 8) }, ptrs = { 1 },
            })
            t:assert(r.ret >= 0, "attach admitted again")
            sys.close(worker, r.ret)
        end, { privs = 0 })
    end)

test("the configuration constants are the live defaults",
    { spec = "PKM *abi.config-constants" }, function(t)
        -- Each default in the §2.A table is what the kernel actually
        -- runs with on an unconfigured system; the boundary behaviour
        -- for each is measured in its own file, the values here.
        local ring = kmes.attach(vm, 0)
        t:assert(ring, "a ring attaches")
        t:assert_eq(ring.capacity, 4194304,
            "KMES_CONFIG_BUFFER_CAPACITY_DEFAULT")
        kmes.detach(ring)
        t:assert_eq(kmes.emit(vm, "PIT_CC", nil, {
            payload_ptr = 0xdead0000, payload_len = 65536 }).errno,
            sys.E.NOSPC, "KMES_CONFIG_MAX_EVENT_SIZE_DEFAULT is 65536")
        t:assert_eq(kmes.emit(vm, "PIT_CC", kmes.nested(33)).errno,
            sys.E.INVAL, "KMES_CONFIG_MAX_NESTING_DEPTH_DEFAULT is 32")
    end)

test("the slot query is the discovery protocol",
    { spec = "PKM *abi.ring-slot-discovery" }, function(t)
        -- KMES_ATTACH_QUERY_SLOTS answers the array size; enumeration
        -- walks 0..count-1 treating EINVAL as a hole, not the end. On
        -- this dense single-CPU guest: one slot, no holes, and the
        -- sentinel itself is far outside the index space.
        local r = vm:syscall(kmes.SYS.ATTACH, {
            args = { kmes.ATTACH_QUERY_SLOTS, 0 },
            bufs = { string.rep("\0", 8) }, ptrs = { 1 },
        })
        t:assert_eq(r.ret, 0, "the query answers")
        local slots = string.unpack("<I8", r.out_bufs[1])
        t:assert_eq(slots, 1, "one slot")
        for cpu = 0, slots - 1 do
            local ring, errno = kmes.attach(vm, cpu)
            t:assert(ring, "slot " .. cpu .. " attaches: " ..
                sys.errname(errno or 0))
            kmes.detach(ring)
        end
        local _, errno = kmes.attach(vm, slots)
        t:assert_eq(errno, sys.E.INVAL, "and past the count is EINVAL")
    end)

test("the batch ceiling is KMES_BATCH_MAX_ENTRIES",
    { spec = "PKM *abi.batch-max-entries" }, function(t)
        local entries = {}
        for i = 1, 257 do
            entries[i] = { type = "PIT_BM", payload = kmes.PAYLOAD }
        end
        t:assert_eq(kmes.emit_batch(vm, entries, { count = 257 }).errno,
            sys.E.INVAL, "257 is refused")
        entries[257] = nil
        t:assert_eq(kmes.emit_batch(vm, entries).ret, 0, "256 is the ceiling")
    end)

test("only the x86-64 entry point exists — x32 is not built",
    { spec = "PKM *build.syscalls-registered-common" }, function(t)
        -- The table rows are `common`, but this kernel is built
        -- without CONFIG_X86_X32_ABI, so an x32 invocation (bit 30
        -- set) is ENOSYS like every other x32 syscall here — the
        -- shipped posture §2.B records.
        local X32 = 0x40000000
        t:assert_eq(kmes.emit(vm, "PIT_X32", kmes.PAYLOAD).ret, 0,
            "the x86-64 form emits")
        local x = vm:syscall(kmes.SYS.EMIT + X32, {
            args = { 0, 7, 0, #kmes.PAYLOAD },
            bufs = { "PIT_X32", kmes.PAYLOAD },
            ptrs = { 0, 2 },
        })
        t:assert_eq(x.errno, 38, -- ENOSYS
            "the x32 form does not exist: " .. sys.errname(x.errno))
        t:assert_eq(vm:syscall(1 + X32, 1, 0, 0).errno, 38,
            "as x32 write does not either — the ABI is absent, not the row")
    end)

test("KMES is linked into the kernel, not loaded",
    { spec = "PKM *build.config-security-pkm" }, function(t)
        -- This guest has no module loading at all — no modules on the
        -- root, no modprobe, nothing after PID 1 but the agent. The
        -- syscalls answering from the first instant means the
        -- subsystem is in vmlinux, which is what a boolean
        -- CONFIG_SECURITY_PKM builds.
        t:assert_eq(kmes.emit(vm, "PIT_BUILTIN", kmes.PAYLOAD).ret, 0,
            "emit answers on a guest that has never loaded a module")
    end)

test("the type string is vocabulary, not structure",
    { spec = "PKM *event.type-opaque" }, function(t)
        local weird = { "PIT with spaces", "PIT/slash.dot:colon",
                        "PIT_\xf0\x9f\x94\x94" } -- a bell emoji is UTF-8 too
        local events = kmes.recording(t, vm, function()
            for _, name in ipairs(weird) do
                t:assert_eq(kmes.emit(vm, name, kmes.PAYLOAD).ret, 0,
                    "an emit typed " .. name)
            end
        end)
        for _, name in ipairs(weird) do
            t:assert_eq(#kmes.of_type(events, name), 1,
                name .. " round-trips verbatim")
        end
    end)

test("types are compared as raw bytes by consumers",
    { spec = "PKM *event.type-utf8-on-syscall-path" }, function(t)
        -- Validated as UTF-8 on the way in, never folded or
        -- normalised: two types differing only in case are two types.
        local events = kmes.recording(t, vm, function()
            t:assert_eq(kmes.emit(vm, "PIT_Case", kmes.PAYLOAD).ret, 0, "one")
            t:assert_eq(kmes.emit(vm, "PIT_case", kmes.PAYLOAD).ret, 0, "two")
        end)
        t:assert_eq(#kmes.of_type(events, "PIT_Case"), 1, "each its own")
        t:assert_eq(#kmes.of_type(events, "PIT_case"), 1, "vocabulary entry")
    end)

test("a type as long as u16 allows is an ordinary type",
    { spec = "PKM *event.limits.type-len-u16-nonzero" }, function(t)
        -- The header field is u16, so the ABI cannot express an
        -- overlong type; within it, only zero is refused. A 60000-byte
        -- type — absurd but encodable — emits.
        local huge = "PIT_HUGE_" .. string.rep("x", 59991)
        local events = kmes.recording(t, vm, function()
            t:assert_eq(kmes.emit(vm, huge, kmes.PAYLOAD).ret, 0,
                "a 60000-byte type emits")
        end)
        t:assert_eq(#kmes.of_type(events, huge), 1, "and round-trips")
        t:assert_eq(kmes.emit(vm, "", kmes.PAYLOAD, { type_len = 0 }).errno,
            sys.E.INVAL, "zero remains the one refused length")
    end)

test("total size arithmetic is u32 with overflow checked",
    { spec = "PKM *event.limits.total-fits-u32" }, function(t)
        local r = kmes.emit(vm, "PIT_U32", nil,
            { payload_ptr = 0xdead0000, payload_len = 0xFFFFFFFF })
        t:assert_eq(r.errno, sys.E.INVAL,
            "77 + type + u32-max overflows and is EINVAL, not a wrap: " ..
            sys.errname(r.errno))
    end)

test("MaxEventSize binds syscall emitters only",
    { spec = "PKM *event.limits.max-event-size-syscall-only" }, function(t)
        -- The syscall half measured here; the kernel-emitter
        -- exemption cannot be provoked from a guest (no kernel
        -- emitter here produces a >64 KiB event) and runs under
        -- pkm_kunit_kmes_direct_emit tests, which emit unbounded by
        -- the policy limit.
        t:assert_eq(kmes.emit(vm, "PIT_MES", nil, {
            payload_ptr = 0xdead0000,
            payload_len = kmes.DEFAULT.MAX_EVENT_SIZE }).errno, sys.E.NOSPC,
            "the syscall path is bound")
    end)

test("the four size bounds of §2.2, at their boundaries",
    { spec = "PKM *event.size-limits" }, function(t)
        -- The section anchor: nonzero type within u16, total within
        -- u32, the structural half-capacity, and the policy
        -- MaxEventSize — each measured at its edge elsewhere in this
        -- suite; here the section's composite shape: an event inside
        -- every bound emits, and each bound alone rejects.
        t:assert_eq(kmes.emit(vm, "PIT_BOUNDS", kmes.PAYLOAD).ret, 0,
            "inside every bound")
        t:assert_eq(kmes.emit(vm, "", kmes.PAYLOAD, { type_len = 0 }).errno,
            sys.E.INVAL, "outside the type bound")
        t:assert_eq(kmes.emit(vm, "PIT_BOUNDS", nil,
            { payload_ptr = 0xdead0000, payload_len = 0xFFFFFFFF }).errno,
            sys.E.INVAL, "outside u32")
        t:assert_eq(kmes.emit(vm, "PIT_BOUNDS", nil,
            { payload_ptr = 0xdead0000, payload_len = 70000 }).errno,
            sys.E.NOSPC, "outside MaxEventSize")
    end)

test("a rejected msgpack payload is the syscall's EINVAL",
    { spec = "PKM *emit.payload-msgpack-einval" }, function(t)
        t:assert_eq(kmes.emit(vm, "PIT_MP", "\x81\xa1k").errno, sys.E.INVAL,
            "a truncated map: " .. sys.errname(sys.E.INVAL))
        t:assert_eq(kmes.emit(vm, "PIT_MP", "\xd9\x10short").errno,
            sys.E.INVAL, "a str8 longer than its bytes")
    end)

test("a consumer bounded by write_pos never reads a partial event",
    { spec = "PKM *event.write-atomicity" }, function(t)
        -- The consumer-visible face of the release-store protocol:
        -- every drain up to write_pos yields whole events — sizes
        -- consistent, payloads decodable — however tightly the reads
        -- chase the writes. (The memory-ordering half is the PSPK
        -- contract, exercised in kernel context by the KUnit suite.)
        local ring = kmes.attach(vm, 0)
        t:assert(ring, "a ring attaches")
        for i = 1, 30 do
            t:assert_eq(kmes.emit(vm, "PIT_ATOMIC", kmes.PAYLOAD).ret, 0,
                "emit " .. i)
            local events = kmes.of_type(kmes.drain(ring), "PIT_ATOMIC")
            t:assert_eq(#events, 1, "drained immediately and whole at " .. i)
            t:assert_eq(events[1].raw:sub(events[1].header_size + 1),
                kmes.PAYLOAD, "payload complete")
        end
        kmes.detach(ring)
    end)

test("the appendix is generated from the uapi header",
    { spec = "PKM *abi.generated-from-source",
      covered_by = "ci:regenerate-and-diff",
      skip = "a CI property: gen-kmes-abi.py --check fails the pkm " ..
             "pre-push hook when §2.A drifts from pkm/uapi/pkm/kmes.h; " ..
             "not a VM test" }, function(t)
    end)

test("origin class values match the header constants",
    { spec = "PKM *abi.origin-class-values" }, function(t)
        -- KMES_ORIGIN_USERSPACE = 0 stamped by the syscall,
        -- KMES_ORIGIN_KACS = 2 observed on every audit record
        -- (identity.test.lua drives one); here the userspace value
        -- against its constant.
        local events = kmes.recording(t, vm, function()
            t:assert_eq(kmes.emit(vm, "PIT_OCV", kmes.PAYLOAD).ret, 0, "emit")
        end)
        t:assert_eq(kmes.of_type(events, "PIT_OCV")[1].origin,
            kmes.ORIGIN.USERSPACE, "0 is KMES_ORIGIN_USERSPACE")
    end)
