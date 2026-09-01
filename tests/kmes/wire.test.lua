-- PKM §2.2 and §2.A — the event as it crosses the ring: every header
-- field at its published offset, the stamps' content, ordering, and
-- the per-CPU scope of the sequence counter (on a two-CPU VM).

local sys = require("helpers.sys")
local kmes = require("helpers.kmes")

local vm = provium:vm("v", "kernel-only"):boot()

local function pin(who, cpu)
    local r = who:syscall(sys.NR.sched_setaffinity, {
        args = { 0, 8, 0 },
        bufs = { string.pack("<I8", 1 << cpu) },
        ptrs = { 2 },
    })
    return r.ret == 0
end

--- Emit pinned to one CPU. The main connection's syscalls are served
--- by whichever agent thread is free, so an affinity set by one
--- syscall does not bind the next — a worker serves its syscalls on
--- one thread, and the pin holds there.
local function pinned_emit(from_vm, cpu, type_name)
    local worker = from_vm:spawn_worker()
    local ok, err = pcall(function()
        assert(pin(worker, cpu), "pin to cpu " .. cpu)
        local r = kmes.emit(worker, type_name, kmes.PAYLOAD)
        assert(r.ret == 0, "pinned emit: " .. sys.errname(r.errno))
    end)
    worker:kill(); worker:join()
    if not ok then error(err, 0) end
end

test("every header field sits at its §2.A offset",
    { spec = "PKM *abi.event-header-layout" }, function(t)
        local type_name, payload = "PIT_WIRE", kmes.PAYLOAD
        local events = kmes.recording(t, vm, function()
            t:assert_eq(kmes.emit(vm, type_name, payload).ret, 0, "one event")
        end)
        local e = kmes.of_type(events, type_name)[1]
        t:assert(e, "arrives")
        local raw = e.raw

        t:assert_eq(string.unpack("<I4", raw, 1), #raw,
            "event_size at 0 is the whole event's byte length")
        t:assert_eq(#raw, kmes.HEADER_BASE + #type_name + #payload,
            "which is 77 + type_len + payload_len")
        t:assert_eq(string.unpack("<I4", raw, 5),
            kmes.HEADER_BASE + #type_name,
            "header_size at 4 is 77 + type_len")
        local ts = string.unpack("<I8", raw, 9)
        t:assert(ts > 1.7e18, "timestamp at 8 is nanoseconds since the epoch")
        t:assert(string.unpack("<I8", raw, 17) > 0, "sequence at 16")
        t:assert_eq(string.unpack("<I2", raw, 25), 0, "cpu_id at 24")
        t:assert_eq(string.unpack("<I1", raw, 27), 0, "origin_class at 26")
        t:assert_eq(string.unpack("<I2", raw, 76), #type_name,
            "type_len at 75")
        t:assert_eq(raw:sub(78, 77 + #type_name), type_name,
            "the type string at 77")
        t:assert_eq(raw:sub(78 + #type_name), payload,
            "and the payload immediately after, no padding between")
    end)

test("the identity GUIDs are the caller's, captured live",
    { spec = "PKM *event.identity-at-write-time" }, function(t)
        -- The agent is not impersonating, so effective equals true; the
        -- process GUID is KACS's, assigned at fork — a worker's event
        -- carries a different one and the same is never null here,
        -- where there is always task context.
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local events = kmes.recording(t, vm, function()
                t:assert_eq(kmes.emit(vm, "PIT_ID_AGENT", kmes.PAYLOAD).ret, 0,
                    "the agent emits")
                t:assert_eq(kmes.emit(worker, "PIT_ID_WORKER", kmes.PAYLOAD).ret,
                    0, "and a worker emits")
            end)
            local a = kmes.of_type(events, "PIT_ID_AGENT")[1]
            local w = kmes.of_type(events, "PIT_ID_WORKER")[1]
            t:assert(a and w, "both arrive")
            for _, e in ipairs({ a, w }) do
                t:assert_neq(e.effective_token, kmes.NULL_GUID,
                    "the effective token GUID is not null")
                t:assert_eq(e.effective_token, e.true_token,
                    "and equals the true token GUID absent impersonation")
                t:assert_neq(e.process_guid, kmes.NULL_GUID,
                    "the process GUID is not null")
            end
            t:assert_neq(a.process_guid, w.process_guid,
                "and the worker is stamped as its own process")
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
    end)

test("within one CPU, sequence orders and the timestamp does not",
    { spec = "PKM *event.ordering-contract" }, function(t)
        -- Two single emits: sequence strictly ascends and the wall
        -- clock never runs backwards across them. A batch's events all
        -- share one timestamp and are told apart by sequence — the
        -- §2.2 tie-break, exercised deliberately here.
        local events = kmes.recording(t, vm, function()
            t:assert_eq(kmes.emit(vm, "PIT_ORDER_A", kmes.PAYLOAD).ret, 0, "a")
            t:assert_eq(kmes.emit(vm, "PIT_ORDER_B", kmes.PAYLOAD).ret, 0, "b")
            t:assert_eq(kmes.emit_batch(vm, {
                { type = "PIT_ORDER_C", payload = kmes.PAYLOAD },
                { type = "PIT_ORDER_C", payload = kmes.PAYLOAD },
            }).ret, 0, "then a batch of two")
        end)
        local a = kmes.of_type(events, "PIT_ORDER_A")[1]
        local b = kmes.of_type(events, "PIT_ORDER_B")[1]
        local c = kmes.of_type(events, "PIT_ORDER_C")
        t:assert(a and b and #c == 2, "all four arrive")
        t:assert(b.sequence > a.sequence, "sequence strictly ascends")
        t:assert(b.timestamp >= a.timestamp, "the clock does not run backwards")
        t:assert_eq(c[1].timestamp, c[2].timestamp,
            "the batch pair share a timestamp")
        t:assert_eq(c[2].sequence, c[1].sequence + 1,
            "and only sequence tells them apart")
    end)

-- ---- two CPUs -------------------------------------------------------

local vm2 = provium:vm("v2", "kernel-only", { cpus = 2 }):boot()

test("a second CPU is a second slot",
    { spec = "PKM *attach.query-slots" }, function(t)
        local r = vm2:syscall(kmes.SYS.ATTACH, {
            args = { kmes.ATTACH_QUERY_SLOTS, 0 },
            bufs = { string.rep("\0", 8) },
            ptrs = { 1 },
        })
        t:assert_eq(r.ret, 0, "the query answers")
        t:assert_eq(string.unpack("<I8", r.out_bufs[1]), 2, "two slots")
    end)

test("each CPU counts its own sequence, from one",
    { spec = "PKM *event.sequence-starts-at-one" }, function(t)
        -- Nothing in this kernel-only guest emits on cpu 1 unprompted,
        -- so its ring is untouched since boot: the counter starts at
        -- zero when PKM loads and is incremented before it is taken,
        -- so the first event carries 1 — and cpu 0's counter, long
        -- since advanced, has no bearing on it.
        local r1 = kmes.attach(vm2, 1)
        t:assert(r1, "ring 1 attaches")
        local write_pos = kmes.positions(r1)
        t:assert_eq(write_pos, 0, "and has never been written")
        pinned_emit(vm2, 1, "PIT_FIRST")
        local events = kmes.of_type(kmes.drain(r1), "PIT_FIRST")
        kmes.detach(r1)
        t:assert_eq(#events, 1, "the event is on ring 1")
        t:assert_eq(events[1].sequence, 1, "carrying sequence 1")
    end)

test("the event lands on the executing CPU's ring, stamped with it",
    { spec = "PKM *event.stamp.cpu-id-of-write" }, function(t)
        local r0 = kmes.attach(vm2, 0)
        local r1 = kmes.attach(vm2, 1)
        t:assert(r0 and r1, "both rings attach")
        pinned_emit(vm2, 1, "PIT_CPU1")
        pinned_emit(vm2, 0, "PIT_CPU0")
        local on0, on1 = kmes.drain(r0), kmes.drain(r1)
        kmes.detach(r0); kmes.detach(r1)
        t:assert_eq(#kmes.of_type(on1, "PIT_CPU1"), 1,
            "the pinned-to-1 event is on ring 1")
        t:assert_eq(#kmes.of_type(on1, "PIT_CPU0"), 0, "and only there")
        t:assert_eq(#kmes.of_type(on0, "PIT_CPU0"), 1,
            "the pinned-to-0 event on ring 0")
        t:assert_eq(kmes.of_type(on1, "PIT_CPU1")[1].cpu, 1,
            "each stamped with the CPU that wrote it")
        t:assert_eq(kmes.of_type(on0, "PIT_CPU0")[1].cpu, 0, "respectively")
    end)

test("the two counters advance independently",
    { spec = "PKM *event.sequence-scoped-per-cpu" }, function(t)
        -- Bracket three cpu-0 emissions with two cpu-1 markers: the
        -- markers abut in cpu 1's sequence, so cpu 0's three advanced
        -- a different counter — and cpu 0's three abut in its own.
        local r0 = kmes.attach(vm2, 0)
        local r1 = kmes.attach(vm2, 1)
        t:assert(r0 and r1, "both rings attach")
        pinned_emit(vm2, 1, "PIT_SCOPE_MARK")
        for _ = 1, 3 do pinned_emit(vm2, 0, "PIT_SCOPE_BULK") end
        pinned_emit(vm2, 1, "PIT_SCOPE_MARK")
        local marks = kmes.of_type(kmes.drain(r1), "PIT_SCOPE_MARK")
        local bulk = kmes.of_type(kmes.drain(r0), "PIT_SCOPE_BULK")
        kmes.detach(r0); kmes.detach(r1)
        t:assert(#marks == 2 and #bulk == 3, "each ring got its own")
        t:assert_eq(marks[2].sequence, marks[1].sequence + 1,
            "cpu 1's markers abut: cpu 0's emissions advanced no shared counter")
        t:assert_eq(bulk[3].sequence, bulk[1].sequence + 2,
            "and cpu 0's three are contiguous in their own")
    end)

test("the stamps describe the moment of the write, not the entry",
    { spec = "PKM *emit.stamps-at-write-time" }, function(t)
        -- The observable half: a worker that changes CPU between
        -- syscalls gets each event stamped with the CPU that performed
        -- that write — nothing about the stamp was settled earlier.
        local r0 = kmes.attach(vm2, 0)
        local r1 = kmes.attach(vm2, 1)
        t:assert(r0 and r1, "both rings attach")
        local worker = vm2:spawn_worker()
        local ok, err = pcall(function()
            t:assert(pin(worker, 0), "the worker starts on cpu 0")
            t:assert_eq(kmes.emit(worker, "PIT_WHEN", kmes.PAYLOAD).ret, 0, "a")
            t:assert(pin(worker, 1), "moves to cpu 1")
            t:assert_eq(kmes.emit(worker, "PIT_WHEN", kmes.PAYLOAD).ret, 0, "b")
        end)
        worker:kill(); worker:join()
        local on0 = kmes.of_type(kmes.drain(r0), "PIT_WHEN")
        local on1 = kmes.of_type(kmes.drain(r1), "PIT_WHEN")
        kmes.detach(r0); kmes.detach(r1)
        if not ok then error(err, 0) end
        t:assert(#on0 == 1 and #on1 == 1, "one event per ring")
        t:assert_eq(on0[1].cpu, 0, "the first stamped where it wrote")
        t:assert_eq(on1[1].cpu, 1, "the second where it wrote next")
    end)

test("a never-written data region reads back zero",
    { spec = "PKM *ring.data-zeroed-once-not-scrubbed" }, function(t)
        -- The half of the claim a consumer can see from outside: the
        -- region is zeroed at creation, so bytes beyond write_pos on a
        -- fresh ring are zero, not uninitialised memory. (That stale
        -- bytes persist after overwrite — the other half — is what the
        -- consumer contract's event_size rule guards against.)
        local r1 = kmes.attach(vm2, 1)
        t:assert(r1, "ring 1 attaches")
        local write_pos = kmes.positions(r1)
        local sample = vm2:read_mem(r1.addr + 8192 + write_pos + 4096, 4096)
        kmes.detach(r1)
        t:assert_eq(sample, string.rep("\0", 4096),
            "a page past the write position is all zeroes")
    end)
