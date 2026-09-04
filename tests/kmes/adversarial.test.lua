-- The second pass: cases that do not come from a sentence of the TRM
-- but from asking where the code might disagree with it — boundary
-- arithmetic from both sides, aliased and hostile arguments, the
-- mapping's protection, a batch larger than its ring, and — with the
-- registry source at a 100/s rate and a 192 MiB guest — the token
-- accounting and allocation-failure paths the defaults keep out of
-- reach. Each test still cites the statement it stresses.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local kmes = require("helpers.kmes")
local hooks = require("helpers.hooks")
local registry = require("helpers.registry")

local vm = provium:vm("vadv", "kernel-only"):boot()

-- ---- arguments and arithmetic ---------------------------------------

test("the privilege gate precedes every validation step",
    { spec = "PKM *emit.validation-order" }, function(t)
        -- An unprivileged caller with an invalid request learns
        -- nothing about the request: EPERM, never EINVAL.
        kacs.as_dacl_bound(t, vm, function(worker)
            t:assert_eq(kmes.emit(worker, "", kmes.PAYLOAD, { type_len = 0 })
                .errno, sys.E.PERM, "zero type length behind the gate")
            t:assert_eq(kmes.emit(worker, "PIT_GATE", "\xc1").errno,
                sys.E.PERM, "invalid msgpack behind the gate")
            t:assert_eq(kmes.emit_batch(worker, {}, { count = 0 }).errno,
                sys.E.PERM, "a zero count behind the batch gate")
        end, { privs = kmes.PRIV.AUDIT })
    end)

test("the u32 total is checked at exactly 2^32",
    { spec = "PKM *event.limits.total-fits-u32" }, function(t)
        -- 77 + 1 + payload_len: the largest payload_len that still
        -- fits u32 gets past the overflow check and dies at the policy
        -- bound; one more overflows and is EINVAL.
        local fits = 0xFFFFFFFF - kmes.HEADER_BASE - 1
        t:assert_eq(kmes.emit(vm, "T", nil,
            { payload_ptr = 0xdead0000, payload_len = fits }).errno,
            sys.E.NOSPC, "a total of 0xFFFFFFFF is ENOSPC, not overflow")
        t:assert_eq(kmes.emit(vm, "T", nil,
            { payload_ptr = 0xdead0000, payload_len = fits + 1 }).errno,
            sys.E.INVAL, "a total of 2^32 is the overflow EINVAL")
    end)

test("an event that is almost all type string round-trips",
    { spec = "PKM *event.limits.type-len-u16-nonzero" }, function(t)
        -- type_len chosen so 77 + type_len + 1 == MaxEventSize, with a
        -- one-byte msgpack nil as the payload: every field at its
        -- limit at once.
        local type_len = kmes.DEFAULT.MAX_EVENT_SIZE - kmes.HEADER_BASE - 1
        local huge = "PIT_ALLTYPE_" .. string.rep("t", type_len - 12)
        local events = kmes.recording(t, vm, function()
            t:assert_eq(kmes.emit(vm, huge, "\xc0").ret, 0,
                "the maximal type with a nil payload is accepted")
            t:assert_eq(kmes.emit(vm, huge .. "t", "\xc0").errno, sys.E.NOSPC,
                "one more type byte is over the policy bound")
        end)
        local e = kmes.of_type(events, huge)[1]
        t:assert(e, "and it arrives")
        t:assert_eq(e.size, kmes.DEFAULT.MAX_EVENT_SIZE, "at the exact size")
        t:assert_eq(e.raw:sub(e.header_size + 1), "\xc0", "payload intact")
    end)

test("the ring maps only shared, at offset zero, at its exact size",
    { spec = "PKM *attach.capacity-and-fd-contract" }, function(t)
        local at = vm:syscall(kmes.SYS.ATTACH, {
            args = { 0, 0 }, bufs = { string.rep("\0", 8) }, ptrs = { 1 },
        })
        t:assert(at.ret >= 0, "attached")
        local fd = at.ret
        local len = 8192 + 2 * string.unpack("<I8", at.out_bufs[1])
        local RW = sys.PROT.READ | sys.PROT.WRITE
        t:assert_eq(vm:syscall(sys.NR.mmap, 0, len, RW, sys.MAP.PRIVATE, fd, 0)
            .errno, sys.E.INVAL, "MAP_PRIVATE is refused")
        t:assert_eq(vm:syscall(sys.NR.mmap, 0, len, RW, sys.MAP.SHARED, fd, 4096)
            .errno, sys.E.INVAL, "a nonzero offset is refused")
        t:assert_eq(vm:syscall(sys.NR.mmap, 0, 8192, RW, sys.MAP.SHARED, fd, 0)
            .errno, sys.E.INVAL, "metadata pages alone are refused")
        t:assert_eq(vm:syscall(sys.NR.mmap, 0, len + 4096, RW, sys.MAP.SHARED,
            fd, 0).errno, sys.E.INVAL, "one page too many is refused")
        local ok = vm:syscall(sys.NR.mmap, 0, len, RW, sys.MAP.SHARED, fd, 0)
        t:assert(ok.ret > 0, "the exact layout maps")
        sys.munmap(vm, ok.ret, len)
        sys.close(vm, fd)
    end)

test("only the consumer page is writable through the mapping",
    { spec = "PKM *abi.ring-mapping-layout" }, function(t)
        -- The mapping is opened PROT_WRITE across its whole length;
        -- the kernel clears the write upgrade on every page but the
        -- consumer's, so a store through the producer page or the
        -- data region faults, and can neither forge metadata nor
        -- corrupt an event another consumer will read.
        local ring = kmes.attach(vm, 0)
        t:assert(ring, "a ring attaches")
        local magic = vm:read_mem(ring.addr, 8)
        t:assert(not kmes.poke(vm, ring.addr, "XXXXXXXX"),
            "the producer page refuses a write")
        t:assert_eq(vm:read_mem(ring.addr, 8), magic, "and is unchanged")
        t:assert(not kmes.poke(vm, ring.addr + 8192, "XXXX"),
            "the data region refuses a write")
        t:assert(not kmes.poke(vm, ring.addr + 8192 + ring.capacity, "XXXX"),
            "as does its second mapping")
        t:assert(kmes.poke(vm, ring.addr + 4096, "\x00"),
            "while the consumer page accepts one")
        kmes.detach(ring)
    end)

test("need_wake is a boolean; the rest of the consumer page is noise",
    { spec = "PKM *ring.need-wake-protocol" }, function(t)
        local ring = kmes.attach(vm, 0)
        t:assert(ring, "a ring attaches")
        local function counter()
            return string.unpack("<I8", vm:read_mem(ring.addr + 128, 8))
        end
        -- Garbage everywhere on the page but byte 0.
        t:assert(kmes.poke(vm, ring.addr + 4096 + 1, string.rep("\xa5", 4095)),
            "4095 bytes of garbage land on the consumer page")
        local c0 = counter()
        t:assert_eq(kmes.emit(vm, "PIT_NOISE", kmes.PAYLOAD).ret, 0, "emit")
        t:assert_eq(counter(), c0, "nothing but byte 0 arms a wake")
        t:assert(kmes.poke(vm, ring.addr + 4096, "\x80"), "byte 0 = 0x80")
        t:assert_eq(kmes.emit(vm, "PIT_NOISE", kmes.PAYLOAD).ret, 0, "emit")
        t:assert_eq(counter(), c0 + 1, "any nonzero value is true")
        kmes.poke(vm, ring.addr + 4096, string.rep("\0", 4096))
        kmes.detach(ring)
    end)

test("the value beside the query sentinel is an ordinary bad index",
    { spec = "PKM *attach.query-slots" }, function(t)
        local _, errno = kmes.attach(vm, 0xFFFFFFFE)
        t:assert_eq(errno, sys.E.INVAL,
            "0xFFFFFFFE is EINVAL — only the exact sentinel queries")
    end)

-- PEI-659. The batch reserves for all its events before writing any,
-- walking the tail with the running offset. Once that walk crosses
-- the batch's own starting write_pos, the events it skips are this
-- batch's own, not yet written: it reads the previous lap's stale
-- bytes there, the corruption guard trips, and the tail jumps to the
-- end of the batch. Singles lapping the ring keep ~69 events with only
-- ring-full drops; the same bytes as one batch keep 49 with three
-- tail-resync drops.
test("a batch larger than the ring overwrites itself and stays whole",
    { spec = "PKM *ring.tail-resync-guard",
      tags = { "known-bug" } }, function(t)
        -- 256 x 60000 bytes is 15 MB into a 4 MiB ring: the batch laps
        -- its own output inside one syscall. The guard is for corrupt
        -- size fields; a healthy ring lapped by a healthy batch must
        -- never trip it, and the survivors are the contiguous newest
        -- suffix that fits.
        local content = string.rep("ij", (60000 - kmes.HEADER_BASE - 8 - 3) // 2)
        local payload = "\xda" .. string.pack(">I2", #content) .. content
        local entries = {}
        for i = 1, 256 do entries[i] = { type = "PIT_BIGB", payload = payload } end
        local ring = kmes.attach(vm, 0)
        t:assert(ring, "a ring attaches")
        t:assert(hooks.trace_start(vm, "kmes/kmes_drop"), "tracing drops")
        local r = kmes.emit_batch(vm, entries)
        local lines = hooks.trace_stop(vm, "kmes/kmes_drop")
        t:assert_eq(r.ret, 0, "the batch succeeds: " .. sys.errname(r.errno))
        t:assert_eq(r.emitted, 256, "all 256 emitted")
        local resyncs = 0
        for _, l in ipairs(lines) do
            if l:match("kmes_drop:.*reason=tail%-resync") then
                resyncs = resyncs + 1
            end
        end
        local kept = kmes.of_type(kmes.drain(ring), "PIT_BIGB")
        kmes.detach(ring)
        t:assert_eq(resyncs, 0,
            "a healthy ring never trips the corruption guard: " .. resyncs ..
            " tail-resync drops")
        t:assert(#kept >= 60 and #kept < 256,
            "the newest suffix that fits survives: " .. #kept .. " of 256")
        for i = 2, #kept do
            t:assert_eq(kept[i].sequence, kept[i - 1].sequence + 1,
                "contiguous at " .. i)
        end
    end)

-- ---- token accounting at a measurable rate --------------------------

local src = assert(registry.kmes_source(vm, {
    MaxEmitRatePerProcess = { registry.TYPE.DWORD, registry.dword(100) },
    MaxEventSize = { registry.TYPE.DWORD, registry.dword(65536) },
    MaxNestingDepth = { registry.TYPE.DWORD, registry.dword(32) },
    BufferCapacity = { registry.TYPE.QWORD, registry.qword(4194304) },
}))
local wkey = vm:spawn_worker()
local KMES_FD
do
    local o = src:pump_during(function()
        return registry.open_key_async(wkey, "Machine\\System\\KMES")
    end)
    assert(o.ret >= 0, "open KMES key: " .. sys.errname(o.errno))
    KMES_FD = o.ret
end
local function set_value(name, vtype, data)
    return src:pump_during(function()
        return registry.set_value_async(wkey, KMES_FD, name, vtype, data)
    end)
end

test("the batch reservation is judged before any entry is",
    { spec = "PKM *batch.tokens-reserved-atomically" }, function(t)
        -- At a rate of 100 the bucket can never hold 256 tokens, so a
        -- 256-entry batch whose first entry is invalid fails EAGAIN —
        -- the reservation (step 3) refused before staging (step 6)
        -- could ever notice the entry.
        kacs.as_dacl_bound(t, vm, function(worker)
            local entries = {}
            for i = 1, 256 do
                entries[i] = { type = "PIT_ORDER", payload = kmes.PAYLOAD }
            end
            entries[1].payload = "\xc1"
            local r = kmes.emit_batch(worker, entries)
            t:assert_eq(r.errno, sys.E.AGAIN,
                "EAGAIN, not the entry's EINVAL: " .. sys.errname(r.errno))
            t:assert_eq(r.emitted, 0, "and nothing emitted")
        end, { privs = kmes.PRIV.TCB })
    end)

test("a failing emit refunds the token it reserved",
    { spec = "PKM *emit.rate.reserve-then-refund" }, function(t)
        -- Bucket capacity 100, refill one token per 10 ms. Empty it,
        -- let ~30 tokens back, spend 25 syscalls on invalid payloads,
        -- then emit 25 valid events: with the refund every one of the
        -- 25 succeeds; without it the invalids would have burnt the
        -- tokens and most of the valid emits would be EAGAIN.
        kacs.as_dacl_bound(t, vm, function(worker)
            local emitted = 0
            for _ = 1, 400 do
                if kmes.emit(worker, "PIT_REFUND", kmes.PAYLOAD).ret ~= 0 then
                    break
                end
                emitted = emitted + 1
            end
            t:assert(emitted >= 100 and emitted < 400,
                "the bucket empties after about its capacity: " .. emitted)
            sys.nanosleep(vm, 0, 300 * 1000 * 1000)
            for i = 1, 25 do
                t:assert_eq(kmes.emit(worker, "PIT_REFUND", "\xc1").errno,
                    sys.E.INVAL, "invalid emit " .. i .. " is EINVAL")
            end
            for i = 1, 25 do
                local r = kmes.emit(worker, "PIT_REFUND", kmes.PAYLOAD)
                t:assert_eq(r.ret, 0, "valid emit " .. i ..
                    " still finds a token: " .. sys.errname(r.errno))
            end
        end, { privs = kmes.PRIV.TCB })
    end)

test("writing the current capacity swaps nothing",
    { spec = "PKM *config.bootstrap-sequence" }, function(t)
        -- Step 3: a BufferCapacity matching the current one changes
        -- nothing — the generation does not move.
        local ring = kmes.attach(vm, 0)
        local gen0 = string.unpack("<I8", vm:read_mem(ring.addr + 32, 8))
        t:assert_eq(set_value("BufferCapacity", registry.TYPE.QWORD,
            registry.qword(ring.capacity)).ret, 0, "the same value is written")
        t:assert_eq(string.unpack("<I8", vm:read_mem(ring.addr + 32, 8)), gen0,
            "and the generation is untouched — no swap for a no-op")
        kmes.detach(ring)
    end)

test("a capacity below the minimum is a u64 range rejection",
    { spec = "PKM *config.invalid-rejected-not-clamped" }, function(t)
        -- 32768 is a power of two but under the 64 KiB floor: the
        -- report names the range kind, and nothing rounds it up.
        local ring = kmes.attach(vm, 0)
        t:assert_eq(set_value("BufferCapacity", registry.TYPE.QWORD,
            registry.qword(32768)).ret, 0, "written")
        local reports = kmes.of_type(kmes.drain(ring), "KMES_SELF_CONFIG_INVALID")
        t:assert_eq(#reports, 1, "one report")
        t:assert_eq(reports[1].payload.received_kind, "u64_out_of_range",
            "of the u64 range kind")
        t:assert_eq(reports[1].payload.expected_min, 65536, "against 64 KiB")
        local after = kmes.attach(vm, 0)
        t:assert_eq(after.capacity, ring.capacity, "capacity unchanged")
        kmes.detach(after); kmes.detach(ring)
        t:assert_eq(set_value("BufferCapacity", registry.TYPE.QWORD,
            registry.qword(4194304)).ret, 0, "restored")
    end)

test("teardown (vadv)", {}, function(t)
    sys.close(wkey, KMES_FD)
    wkey:kill(); wkey:join()
    src:close()
    t:assert(true, "source torn down")
end)

-- ---- allocation failure, on a guest too small to hide it ------------

local vmem = provium:vm("vmem", "kernel-only", { memory = "192M" }):boot()
local src2 = assert(registry.kmes_source(vmem, {
    MaxEmitRatePerProcess = { registry.TYPE.DWORD, registry.dword(10000) },
    MaxEventSize = { registry.TYPE.DWORD, registry.dword(65536) },
    MaxNestingDepth = { registry.TYPE.DWORD, registry.dword(32) },
    BufferCapacity = { registry.TYPE.QWORD, registry.qword(4194304) },
}))
local wkey2 = vmem:spawn_worker()
local KMES_FD2
do
    local o = src2:pump_during(function()
        return registry.open_key_async(wkey2, "Machine\\System\\KMES")
    end)
    assert(o.ret >= 0, "open KMES key: " .. sys.errname(o.errno))
    KMES_FD2 = o.ret
end
local function set_value2(name, vtype, data)
    return src2:pump_during(function()
        return registry.set_value_async(wkey2, KMES_FD2, name, vtype, data)
    end)
end

test("an unallocatable capacity is reported, and the old ring stays",
    { spec = "PKM *config.swap-failed-event" }, function(t)
        -- 256 MiB is a valid capacity a 192 MiB guest cannot back.
        -- The value is written, the swap fails, a
        -- KMES_BUFFER_SWAP_FAILED event names both capacities and
        -- ENOMEM, and the live ring is untouched.
        local ring = kmes.attach(vmem, 0)
        t:assert(ring and ring.capacity == 4194304, "the 4 MiB ring is live")
        local gen0 = string.unpack("<I8", vmem:read_mem(ring.addr + 32, 8))
        t:assert_eq(set_value2("BufferCapacity", registry.TYPE.QWORD,
            registry.qword(268435456)).ret, 0, "256 MiB is written")
        local failed = kmes.of_type(kmes.drain(ring), "KMES_BUFFER_SWAP_FAILED")
        t:assert_eq(#failed, 1, "one swap-failed report")
        t:assert_eq(failed[1].origin, kmes.ORIGIN.KMES, "from KMES itself")
        t:assert_eq(failed[1].payload.requested_capacity, 268435456,
            "naming what was asked")
        t:assert_eq(failed[1].payload.retained_capacity, 4194304,
            "and what stays")
        t:assert_eq(failed[1].payload.errno, sys.E.NOMEM, "and ENOMEM")
        t:assert_eq(#kmes.of_type(kmes.drain(ring), "KMES_SELF_CONFIG_INVALID"),
            0, "with no invalid-value report — the value was valid")
        t:assert_eq(string.unpack("<I8", vmem:read_mem(ring.addr + 32, 8)), gen0,
            "the generation did not move")
        kmes.detach(ring)
    end)

test("a failed swap is not retried until the next configuration write",
    { spec = "PKM *ring.swap.alloc-failure-keeps-old" }, function(t)
        -- Still 256 MiB in the registry. Nothing happens on its own; a
        -- write to an unrelated value re-reads the key and tries the
        -- swap again — failing again — while consumers keep working.
        local ring = kmes.attach(vmem, 0)
        t:assert(ring and ring.capacity == 4194304, "still at 4 MiB")
        sys.nanosleep(vmem, 0, 200 * 1000 * 1000)
        t:assert_eq(#kmes.of_type(kmes.drain(ring), "KMES_BUFFER_SWAP_FAILED"),
            0, "no spontaneous retry in 200 ms")
        t:assert_eq(set_value2("MaxEventSize", registry.TYPE.DWORD,
            registry.dword(65536)).ret, 0, "an unrelated write lands")
        t:assert_eq(#kmes.of_type(kmes.drain(ring), "KMES_BUFFER_SWAP_FAILED"),
            1, "and the swap was attempted once more")
        t:assert_eq(kmes.emit(vmem, "PIT_ALIVE", kmes.PAYLOAD).ret, 0,
            "emission continues throughout")
        t:assert_eq(#kmes.of_type(kmes.drain(ring), "PIT_ALIVE"), 1,
            "into the ring the consumer still holds")
        kmes.detach(ring)
    end)

test("a failed swap rolls back the capacity and nothing else",
    { spec = "PKM *config.swap-failure-rolls-back-capacity-only" }, function(t)
        -- The registry still holds the unallocatable 256 MiB. A valid
        -- MaxNestingDepth written now shares the plan with it: the
        -- capacity swap runs first and fails, and the depth commits
        -- anyway — the administrator's other change survives the
        -- memory pressure that sank the swap. Fixing the capacity
        -- later swaps without disturbing it.
        t:assert_eq(kmes.emit(vmem, "PIT_RB", kmes.nested(20)).ret, 0,
            "depth 20 passes at the default 32")
        local ring = kmes.attach(vmem, 0)
        t:assert_eq(set_value2("MaxNestingDepth", registry.TYPE.DWORD,
            registry.dword(5)).ret, 0, "depth 5 is written")
        t:assert_eq(#kmes.of_type(kmes.drain(ring), "KMES_BUFFER_SWAP_FAILED"),
            1, "the swap was attempted and failed again")
        kmes.detach(ring)
        t:assert_eq(kmes.emit(vmem, "PIT_RB", kmes.nested(20)).errno,
            sys.E.INVAL, "and the depth took effect regardless")
        t:assert_eq(kmes.emit(vmem, "PIT_RB", kmes.nested(5)).ret, 0, "at 5")
        t:assert_eq(set_value2("BufferCapacity", registry.TYPE.QWORD,
            registry.qword(65536)).ret, 0, "an allocatable capacity is written")
        ring = kmes.attach(vmem, 0)
        t:assert_eq(ring.capacity, 65536, "the swap runs")
        kmes.detach(ring)
        t:assert_eq(kmes.emit(vmem, "PIT_RB", kmes.nested(6)).errno,
            sys.E.INVAL, "with the depth still 5")
    end)

test("teardown (vmem)", {}, function(t)
    sys.close(wkey2, KMES_FD2)
    wkey2:kill(); wkey2:join()
    src2:close()
    t:assert(true, "source torn down")
end)
