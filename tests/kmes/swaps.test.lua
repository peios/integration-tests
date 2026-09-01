-- PKM §2.5 — capacity swaps, driven live: a Lua-served Machine hive
-- (helpers/registry) carries BufferCapacity changes through the real
-- LCS watch → refresh → stop_machine path, and the consumer-visible
-- contract is asserted from both sides of a generation change.
--
-- Own VM: every test here reshapes the rings.

local sys = require("helpers.sys")
local kmes = require("helpers.kmes")
local hooks = require("helpers.hooks")
local registry = require("helpers.registry")

local vm = provium:vm("vswap", "kernel-only"):boot()

-- One source for the file: the hive with an (initially empty) KMES
-- key, bootstrap pumped, plus an open key fd for the writer.
local src = assert(registry.kmes_source(vm, {}))
local wkey = vm:spawn_worker()
local KMES_FD
do
    local o = src:pump_during(function()
        return registry.open_key_async(wkey, "Machine\\System\\KMES")
    end)
    assert(o.ret >= 0, "open KMES key: " .. sys.errname(o.errno))
    KMES_FD = o.ret
end

local function set_capacity(value)
    local r = src:pump_during(function()
        return registry.set_value_async(wkey, KMES_FD, "BufferCapacity",
            registry.TYPE.QWORD, registry.qword(value))
    end)
    assert(r.ret == 0, "set BufferCapacity: " .. sys.errname(r.errno))
end

test("a capacity change bumps the generation and rebinds new attaches",
    { spec = "PKM *ring.swap.generation-bump-signals-reattach" }, function(t)
        local old = kmes.attach(vm, 0)
        t:assert(old, "a consumer holds the current generation")
        t:assert_eq(old.capacity, kmes.DEFAULT.BUFFER_CAPACITY,
            "which is the boot default")
        local gen0 = string.unpack("<I8", vm:read_mem(old.addr + 32, 8))

        set_capacity(65536)

        local gen1 = string.unpack("<I8", vm:read_mem(old.addr + 32, 8))
        t:assert_eq(gen1, gen0 + 1,
            "the old mapping's published generation bumped in place")
        local fresh = kmes.attach(vm, 0)
        t:assert(fresh, "a new attach succeeds")
        t:assert_eq(fresh.capacity, 65536,
            "and binds the replacement ring at the new capacity")
        kmes.detach(fresh)
        kmes.detach(old)
    end)

test("migration re-compacts from zero and the sequence never breaks",
    { spec = "PKM *ring.swap.migration-recompacts" }, function(t)
        set_capacity(131072)
        local events = kmes.recording(t, vm, function()
            t:assert_eq(kmes.emit(vm, "PIT_SWAP_PRE", kmes.PAYLOAD).ret, 0,
                "an event lands before the swap")
            set_capacity(262144)
            t:assert_eq(kmes.emit(vm, "PIT_SWAP_POST", kmes.PAYLOAD).ret, 0,
                "and another after")
        end)
        -- kmes.recording attached before the swap: its drain of the
        -- OLD generation sees only the pre-swap event. The post-swap
        -- assertions read the new ring.
        local pre = kmes.of_type(events, "PIT_SWAP_PRE")
        t:assert_eq(#pre, 1, "the old mapping drained its own era")

        local ring = kmes.attach(vm, 0)
        t:assert(ring, "the new generation attaches")
        t:assert_eq(ring.capacity, 262144, "at the new capacity")
        local write_pos, tail_pos = kmes.positions(ring)
        t:assert_eq(tail_pos, 0, "the migrated ring re-compacts from zero")
        t:assert(write_pos > 0, "carrying the surviving events")
        ring.cursor = tail_pos
        local carried = kmes.drain(ring)
        local carried_pre = kmes.of_type(carried, "PIT_SWAP_PRE")
        local carried_post = kmes.of_type(carried, "PIT_SWAP_POST")
        t:assert_eq(#carried_pre, 1, "the pre-swap event survived migration")
        t:assert_eq(#carried_post, 1, "beside the post-swap one")
        t:assert(carried_post[1].sequence > carried_pre[1].sequence,
            "with the sequence continuous across the swap")
        kmes.detach(ring)
    end)

test("a shrinking swap keeps the newest suffix",
    { spec = "PKM *ring.swap.shrink-skips-oldest" }, function(t)
        set_capacity(1048576)
        -- Fill ~600 KiB of numbered events, then shrink to 64 KiB:
        -- only a tail of the newest survives.
        local content = string.rep("gh", 4096)
        local payload = "\xda" .. string.pack(">I2", #content) .. content
        for i = 1, 72 do
            t:assert_eq(kmes.emit(vm, "PIT_SHRINK", payload).ret, 0,
                "fill " .. i)
        end
        set_capacity(65536)
        local ring = kmes.attach(vm, 0)
        t:assert(ring, "the shrunk ring attaches")
        t:assert_eq(ring.capacity, 65536, "at 64 KiB")
        ring.cursor = 0
        local kept = kmes.of_type(kmes.drain(ring), "PIT_SHRINK")
        kmes.detach(ring)
        t:assert(#kept >= 1 and #kept < 72,
            "a strict suffix survived: " .. #kept .. " of 72")
        for i = 2, #kept do
            t:assert_eq(kept[i].sequence, kept[i - 1].sequence + 1,
                "contiguous at " .. i)
        end
    end)

test("consumers asleep on a dead generation are woken",
    { spec = "PKM *ring.swap.wakes-stale-sleepers" }, function(t)
        local ring = kmes.attach(vm, 0)
        t:assert(ring, "a consumer maps the current generation")
        local sleeper = vm:spawn_worker()
        local ok, err = pcall(function()
            local at = sleeper:syscall(kmes.SYS.ATTACH, {
                args = { 0, 0 }, bufs = { string.rep("\0", 8) }, ptrs = { 1 },
            })
            t:assert(at.ret >= 0, "the sleeper attaches")
            local capacity = string.unpack("<I8", at.out_bufs[1])
            local m = sleeper:syscall(sys.NR.mmap, 0, 8192 + 2 * capacity,
                sys.PROT.READ | sys.PROT.WRITE, sys.MAP.SHARED, at.ret, 0)
            t:assert(m.ret > 0, "and maps")
            local val = string.unpack("<I4",
                kmes.peek(sleeper, m.ret + 128, 4))
            t:assert(kmes.poke(vm, ring.addr + 4096, "\x01"), "need_wake set")
            local pending = sleeper:syscall_async(sys.NR.futex, {
                args = { m.ret + 128, 0, val, 0, 0, 0 },
                bufs = { string.pack("<i8i8", 10, 0) }, ptrs = { 3 },
            })
            sys.nanosleep(vm, 0, 50 * 1000 * 1000)
            set_capacity(131072)
            local woke = pending:await()
            t:assert_eq(woke.ret, 0,
                "the swap woke it rather than leaving it on a dead ring: " ..
                sys.errname(woke.errno))
        end)
        sleeper:kill(); sleeper:join()
        kmes.poke(vm, ring.addr + 4096, "\x00")
        kmes.detach(ring)
        if not ok then error(err, 0) end
    end)

test("old and new generations coexist until the last old fd closes",
    { spec = "PKM *ring.swap.generations-coexist" }, function(t)
        local old = kmes.attach(vm, 0)
        t:assert(old, "an old-generation consumer")
        t:assert_eq(kmes.emit(vm, "PIT_COEXIST", kmes.PAYLOAD).ret, 0,
            "an event in the old era")
        set_capacity(65536)
        -- The old mapping's pages stay valid: its metadata and its
        -- data still read, and its own drain still works, while a new
        -- consumer works the replacement.
        local events = kmes.of_type(kmes.drain(old), "PIT_COEXIST")
        t:assert_eq(#events, 1,
            "the superseded mapping still drains its events")
        local fresh = kmes.attach(vm, 0)
        t:assert(fresh and fresh.capacity == 65536,
            "while the new generation serves new consumers")
        t:assert_eq(kmes.emit(vm, "PIT_COEXIST2", kmes.PAYLOAD).ret, 0,
            "who receive new events")
        t:assert_eq(#kmes.of_type(kmes.drain(fresh), "PIT_COEXIST2"), 1,
            "on the new ring")
        kmes.detach(fresh)
        kmes.detach(old)
    end)

test("the swap lifecycle is traced begin to complete",
    { spec = "PKM *abi.trace.swap-reasons" }, function(t)
        t:assert(hooks.trace_start(vm, "kmes/kmes_swap"), "tracing starts")
        set_capacity(262144)
        local lines = hooks.trace_stop(vm, "kmes/kmes_swap")
        local seen = {}
        for _, l in ipairs(lines) do
            local reason = l:match("kmes_swap:.*reason=([%w%-]+)")
            if reason then seen[reason] = true end
        end
        t:assert(seen["begin"], "the swap traced its begin")
        t:assert(seen["complete"], "and its commit")
    end)

test("prepared rings are switched under stop_machine",
    { spec = "PKM *ring.swap-under-stop-machine" }, function(t)
        -- The section anchor, observed at its edges: emission works to
        -- the last moment before a swap and from the first after, the
        -- generation moves exactly once per swap, and nothing is lost
        -- at the boundary (the migration test above); the quiesced
        -- switch itself is kernel-internal.
        local old = kmes.attach(vm, 0)
        local gen0 = string.unpack("<I8", vm:read_mem(old.addr + 32, 8))
        t:assert_eq(kmes.emit(vm, "PIT_SM", kmes.PAYLOAD).ret, 0, "before")
        set_capacity(131072)
        t:assert_eq(kmes.emit(vm, "PIT_SM", kmes.PAYLOAD).ret, 0, "after")
        local gen1 = string.unpack("<I8", vm:read_mem(old.addr + 32, 8))
        t:assert_eq(gen1, gen0 + 1, "one swap, one generation step")
        kmes.detach(old)
    end)

test("an event over half the (shrunk) capacity is refused",
    { spec = "PKM *event.limits.half-capacity" }, function(t)
        -- The structural bound the compiled-in defaults hide: at a
        -- 64 KiB ring, capacity/2 (32 KiB) sits below MaxEventSize
        -- (64 KiB), and an event between the two is refused for the
        -- ring, not the policy. Exactly half is accepted.
        set_capacity(65536)
        local r = kmes.emit(vm, "PIT_HALF", nil,
            { payload_ptr = 0xdead0000, payload_len = 40000 })
        t:assert_eq(r.errno, sys.E.NOSPC,
            "40000 + header: inside MaxEventSize, over capacity/2: " ..
            sys.errname(r.errno))
        local type_name = "PIT_HALF"
        local exact = 32768 - kmes.HEADER_BASE - #type_name
        local payload = "\xda" .. string.pack(">I2", exact - 3) ..
            string.rep("h", exact - 3)
        t:assert_eq(kmes.emit(vm, type_name, payload).ret, 0,
            "an event of exactly half the capacity is accepted")
    end)

test("the capacity/2 check is a distinct validation stage",
    { spec = "PKM *emit.half-capacity-enospc" }, function(t)
        -- Same bound, cited from the syscall's validation order: the
        -- declared size alone triggers it — the pointer is never
        -- touched — and one byte over half is where it starts.
        local r = kmes.emit(vm, "PIT_HALFV", nil,
            { payload_ptr = 0xdead0000,
              payload_len = 32768 - kmes.HEADER_BASE - 8 + 1 })
        t:assert_eq(r.errno, sys.E.NOSPC,
            "one byte over half, bad pointer: " .. sys.errname(r.errno))
    end)

-- File teardown: the writer worker dies with the file's VM.
test("teardown", {}, function(t)
    sys.close(wkey, KMES_FD)
    wkey:kill(); wkey:join()
    src:close()
    t:assert(true, "source torn down")
end)
