-- PKM §2.5 — the ring under pressure and the notification protocol:
-- overwrite of the oldest events, the consumer's re-anchor, wrap
-- contiguity through the double mapping, and the need_wake/futex
-- machinery.

local sys = require("helpers.sys")
local kmes = require("helpers.kmes")

local vm = provium:vm("v", "kernel-only"):boot()

-- Mapping offsets (§2.A): the futex counter on the producer page, the
-- need_wake byte leading the consumer page.
local FUTEX_COUNTER = 128
local CONSUMER_PAGE = 4096
local FUTEX_WAIT, FUTEX_PRIVATE = 0, 128

-- One fill event: 60000 bytes on the wire — deliberately not a
-- divisor of the 4 MiB capacity, so a filling run is guaranteed to
-- lay events across the physical end of the buffer.
local FILL_TYPE = "PIT_FILL"
local FILL_SIZE = 60000
local fill_content = string.rep("ab", (FILL_SIZE - kmes.HEADER_BASE -
    #FILL_TYPE - 3) // 2)
local FILL_PAYLOAD = "\xda" .. string.pack(">I2", #fill_content) .. fill_content

test("a full ring overwrites the oldest and the reader re-anchors",
    { spec = "PKM *failure.overrun-is-normal" }, function(t)
        local ring = kmes.attach(vm, 0)
        t:assert(ring, "a ring attaches")
        t:assert_eq(kmes.emit(vm, "PIT_LAP_MARK", kmes.PAYLOAD).ret, 0,
            "a marker event goes in first, and is deliberately not drained")
        local fills = 80 -- 80 x 60000 > 4 MiB: more than one lap
        for i = 1, fills do
            local r = kmes.emit(vm, FILL_TYPE, FILL_PAYLOAD)
            t:assert_eq(r.ret, 0, "fill " .. i ..
                " is accepted — emission never fails from buffer pressure: " ..
                sys.errname(r.errno))
        end
        local write_pos, tail_pos = kmes.positions(ring)
        t:assert(write_pos - tail_pos <= ring.capacity,
            "the live span is bounded by the capacity — the tail advanced")
        t:assert(tail_pos > ring.cursor,
            "past this reader's position: it has been overtaken")
        local events = kmes.drain(ring)
        kmes.detach(ring)
        t:assert(#events > 0 and #events < fills + 1,
            "the drain re-anchors to the survivors: " .. #events ..
            " of " .. (fills + 1) .. " events remain")
        local last = events[#events].sequence
        local marker_seq = last - fills
        t:assert(events[1].sequence > marker_seq + 1,
            "and the loss shows as a sequence gap: the ring resumes at " ..
            events[1].sequence .. ", the marker was " .. marker_seq)
        t:assert_eq(events[#events].type, FILL_TYPE,
            "the newest events are the ones kept")
    end)

test("an event across the physical end reads back contiguous",
    { spec = "PKM *ring.consumer-sees-contiguous-wrap" }, function(t)
        -- The fill above laps the buffer; this one drains across the
        -- boundary and checks every surviving payload byte-for-byte.
        -- An event straddling the end would come back torn if the
        -- second mapping of the data pages were not there.
        local ring = kmes.attach(vm, 0)
        t:assert(ring, "a ring attaches")
        for i = 1, 80 do
            t:assert_eq(kmes.emit(vm, FILL_TYPE, FILL_PAYLOAD).ret, 0,
                "fill " .. i)
        end
        -- The surviving span always fits the buffer; what must be true
        -- before draining is that it crosses the physical end. Top up
        -- until it does — 60000 does not divide the capacity, so a
        -- crossing arrives within one more lap.
        local write_pos, tail_pos = kmes.positions(ring)
        local topup = 0
        while tail_pos % ring.capacity + (write_pos - tail_pos)
                <= ring.capacity do
            topup = topup + 1
            t:assert(topup < 80, "a crossing span arrives within another lap")
            t:assert_eq(kmes.emit(vm, FILL_TYPE, FILL_PAYLOAD).ret, 0, "top-up")
            write_pos, tail_pos = kmes.positions(ring)
        end
        local events = kmes.drain(ring)
        kmes.detach(ring)
        t:assert(#events > 0, "the crossing span drains")
        for i, e in ipairs(events) do
            t:assert_eq(e.size, FILL_SIZE, "event " .. i .. " keeps its size")
            if e.payload ~= fill_content then
                t:assert(false, "event " .. i .. " payload torn")
            end
        end
        t:assert(true, "every payload intact across the boundary")
    end)

test("notification costs one byte read until a consumer asks",
    { spec = "PKM *ring.need-wake-protocol" }, function(t)
        local ring = kmes.attach(vm, 0)
        t:assert(ring, "a ring attaches")
        local function counter()
            return string.unpack("<I8",
                vm:read_mem(ring.addr + FUTEX_COUNTER, 8))
        end
        local c0 = counter()
        t:assert_eq(kmes.emit(vm, "PIT_WAKE", kmes.PAYLOAD).ret, 0, "emit")
        t:assert_eq(counter(), c0,
            "need_wake clear: the futex counter does not move")
        t:assert(kmes.poke(vm, ring.addr + CONSUMER_PAGE, "\x01"),
            "the consumer sets need_wake")
        t:assert_eq(kmes.emit(vm, "PIT_WAKE", kmes.PAYLOAD).ret, 0, "emit")
        t:assert_eq(counter(), c0 + 1, "and the counter increments")
        t:assert_eq(kmes.emit(vm, "PIT_WAKE", kmes.PAYLOAD).ret, 0,
            "the byte stays set — clearing is the consumer's job")
        t:assert_eq(counter(), c0 + 2, "so the next emit signals again")
        t:assert(kmes.poke(vm, ring.addr + CONSUMER_PAGE, "\x00"),
            "the consumer clears it")
        t:assert_eq(kmes.emit(vm, "PIT_WAKE", kmes.PAYLOAD).ret, 0, "emit")
        t:assert_eq(counter(), c0 + 2, "and the counter is quiet again")
        kmes.detach(ring)
    end)

test("the futex is shared and inode-keyed; a private wait never wakes",
    { spec = "PKM *ring.futex-is-shared-inode-keyed" }, function(t)
        -- A consumer sleeps in its own process on its own mapping of
        -- the shmem producer page. The shared wait is woken by an
        -- emit; an identical wait with FUTEX_PRIVATE_FLAG times out
        -- against the same traffic, because a private futex is keyed
        -- by address space and the waker is the kernel.
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local at = worker:syscall(kmes.SYS.ATTACH, {
                args = { 0, 0 },
                bufs = { string.rep("\0", 8) },
                ptrs = { 1 },
            })
            t:assert(at.ret >= 0, "the worker attaches: " ..
                sys.errname(at.errno))
            local capacity = string.unpack("<I8", at.out_bufs[1])
            local m = worker:syscall(sys.NR.mmap, 0, 8192 + 2 * capacity,
                sys.PROT.READ | sys.PROT.WRITE, sys.MAP.SHARED, at.ret, 0)
            t:assert(m.ret > 0, "and maps the ring: " .. sys.errname(m.errno))
            local addr = m.ret

            -- The agent's own mapping of the same shared page, to set
            -- need_wake and to prove the two mappings are one page.
            local ring = kmes.attach(vm, 0)
            t:assert(ring, "the agent maps the same ring")

            local val = string.unpack("<I4", kmes.peek(worker, addr + FUTEX_COUNTER, 4))
            t:assert(kmes.poke(vm, ring.addr + CONSUMER_PAGE, "\x01"),
                "need_wake set through the agent's mapping")

            local timeout = string.pack("<i8i8", 5, 0)
            local pending = worker:syscall_async(sys.NR.futex, {
                args = { addr + FUTEX_COUNTER, FUTEX_WAIT, val, 0, 0, 0 },
                bufs = { timeout }, ptrs = { 3 },
            })
            sys.nanosleep(vm, 0, 50 * 1000 * 1000)
            t:assert_eq(kmes.emit(vm, "PIT_FUTEX", kmes.PAYLOAD).ret, 0,
                "an event lands while the worker sleeps")
            local woke = pending:await()
            t:assert_eq(woke.ret, 0,
                "and the shared wait is woken: " .. sys.errname(woke.errno))

            -- The same wait, private: never woken, only timed out.
            local val2 = string.unpack("<I4", kmes.peek(worker, addr + FUTEX_COUNTER, 4))
            t:assert(kmes.poke(vm, ring.addr + CONSUMER_PAGE, "\x01"),
                "need_wake set again")
            local short = string.pack("<i8i8", 0, 300 * 1000 * 1000)
            local p2 = worker:syscall_async(sys.NR.futex, {
                args = { addr + FUTEX_COUNTER, FUTEX_WAIT | FUTEX_PRIVATE,
                         val2, 0, 0, 0 },
                bufs = { short }, ptrs = { 3 },
            })
            sys.nanosleep(vm, 0, 50 * 1000 * 1000)
            t:assert_eq(kmes.emit(vm, "PIT_FUTEX", kmes.PAYLOAD).ret, 0,
                "the same traffic")
            local r2 = p2:await()
            t:assert_eq(r2.errno, 110, -- ETIMEDOUT
                "does not reach the private wait: " .. sys.errname(r2.errno))
            kmes.poke(vm, ring.addr + CONSUMER_PAGE, "\x00")
            kmes.detach(ring)
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
    end)

test("a consumer dying uncleanly costs the others nothing",
    { spec = "PKM *failure.consumer-crash-contained" }, function(t)
        -- A worker attaches, maps, and is killed without closing
        -- anything. The kernel path that reaps its fds releases the
        -- references; the ring, the writer, and a surviving consumer
        -- never notice.
        local survivor = kmes.attach(vm, 0)
        t:assert(survivor, "a surviving consumer attaches first")
        local worker = vm:spawn_worker()
        local at = worker:syscall(kmes.SYS.ATTACH, {
            args = { 0, 0 }, bufs = { string.rep("\0", 8) }, ptrs = { 1 },
        })
        t:assert(at.ret >= 0, "the doomed consumer attaches")
        local capacity = string.unpack("<I8", at.out_bufs[1])
        t:assert(worker:syscall(sys.NR.mmap, 0, 8192 + 2 * capacity,
            sys.PROT.READ | sys.PROT.WRITE, sys.MAP.SHARED, at.ret, 0).ret > 0,
            "and maps")
        worker:kill(); worker:join()
        t:assert_eq(kmes.emit(vm, "PIT_CRASH", kmes.PAYLOAD).ret, 0,
            "emission after the crash")
        local events = kmes.of_type(kmes.drain(survivor), "PIT_CRASH")
        kmes.detach(survivor)
        t:assert_eq(#events, 1, "reaches the survivor as if nothing happened")
    end)
