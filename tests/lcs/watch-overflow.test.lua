-- PKM §5.6.4 — the per-fd event queue and what a full one does.
--
-- The source seeds `NotificationQueueSize` at 16, the range minimum, so
-- a queue can be filled and overflowed with a couple of dozen writes
-- rather than a couple of hundred.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")

local vm = provium:vm("v", "kernel-only"):boot()

local ROOT = "Machine\\Software\\Test"
local QUEUE = 16 -- NotificationQueueSize, seeded below; the range minimum

local src = lcs.source(vm)
src:seed_param("NotificationQueueSize", QUEUE)
src:key(ROOT)
assert(src:register())
src:pump()

local w = vm:spawn_worker()

local function fresh(name)
    local c = lcs.create_key(src, w, { path = ROOT .. "\\" .. name })
    assert(c.ret >= 0, "creating " .. name .. ": " .. sys.errname(c.errno or 0))
    lcs.nonblock(w, c.ret)
    return c.ret
end

local function arm(t, fd)
    local n = lcs.notify(nil, w, fd, lcs.NOTIFY.ALL, false)
    t:assert_eq(n.ret, 0, "REG_IOC_NOTIFY arms: " .. sys.errname(n.errno or 0))
end

--- `count` distinct value writes on `fd`, named V1..Vcount.
local function write_n(fd, count)
    for i = 1, count do
        lcs.set_value(src, w, fd, "V" .. i, lcs.TYPE.DWORD, lcs.dword(i))
    end
end

local function count_of(events, etype)
    local n = 0
    for _, e in ipairs(events) do if e.type == etype then n = n + 1 end end
    return n
end

local function names_of(events)
    local out = {}
    for _, e in ipairs(events) do
        out[#out + 1] = e.type == lcs.WATCH.OVERFLOW and "OVERFLOW" or e.name
    end
    return out
end

-- ---- the queue --------------------------------------------------------

test("each armed fd has its own queue, bounded by NotificationQueueSize",
    { spec = "PKM *watch.overflow.each-fd-has-its-own-bounded-queue" }, function(t)
        local key = fresh("OwnQueue")
        local behind = lcs.open_watchable(src, w, -1, ROOT .. "\\OwnQueue",
            lcs.KEY_ALL_ACCESS).ret
        arm(t, key)
        arm(t, behind)
        write_n(key, QUEUE + 4)
        -- One fd was never read from; the other is drained here first.
        local drained = lcs.drain_events(w, key)
        t:assert_eq(#drained, QUEUE,
            "the queue holds at most NotificationQueueSize records: " .. #drained)
        lcs.set_value(src, w, key, "After", lcs.TYPE.DWORD, lcs.dword(1))
        local fresh_one = lcs.drain_events(w, key)
        t:assert_eq(#fresh_one, 1, "the drained fd's queue has room again")
        local other = lcs.drain_events(w, behind)
        t:assert_eq(#other, QUEUE,
            "and the other fd's queue is its own, independently bounded: " .. #other)
        sys.close(w, behind); sys.close(w, key)
    end)

test("delivery is best-effort: a watcher that falls behind is told that it has",
    { spec = "PKM *watch.overflow.delivery-is-best-effort" }, function(t)
        local prompt = fresh("BestEffort")
        arm(t, prompt)
        -- A watcher that reads promptly sees every change.
        for i = 1, QUEUE + 4 do
            lcs.set_value(src, w, prompt, "P" .. i, lcs.TYPE.DWORD, lcs.dword(i))
            local ev = lcs.drain_events(w, prompt)
            t:assert_eq(#ev, 1, "prompt read " .. i .. " saw its change")
            t:assert_eq(ev[1].type, lcs.WATCH.VALUE_SET, "as a VALUE_SET")
        end
        -- One that falls behind is told, rather than handed a partial
        -- history it cannot tell from a complete one.
        local behind = fresh("BestEffortBehind")
        arm(t, behind)
        write_n(behind, QUEUE + 4)
        local ev = lcs.drain_events(w, behind)
        t:assert_eq(count_of(ev, lcs.WATCH.OVERFLOW), 1,
            "the record it has is marked incomplete: " .. lcs.event_summary(ev))
        sys.close(w, behind); sys.close(w, prompt)
    end)

test("a full queue drops the oldest event, queues an OVERFLOW in its place, " ..
     "and discards the event that triggered it",
    { spec = "PKM *watch.overflow.full-queue-drops-the-oldest-event" }, function(t)
        local fd = fresh("FirstOverflow")
        arm(t, fd)
        write_n(fd, QUEUE + 1) -- exactly one event past a full queue
        local ev = lcs.drain_events(w, fd)
        local names = names_of(ev)
        t:assert_eq(#ev, QUEUE, "the queue is still bounded: " .. lcs.event_summary(ev))
        t:assert_eq(names[1], "V2", "the oldest queued event, V1, was dropped")
        t:assert_eq(names[#names], "OVERFLOW", "an OVERFLOW took its place in the queue")
        for _, n in ipairs(names) do
            t:assert(n ~= "V" .. (QUEUE + 1),
                "and the event that triggered the overflow was discarded, not queued")
        end
        sys.close(w, fd)
    end)

test("the OVERFLOW record is what the queue gains when it is full",
    { spec = "PKM *watch.overflow.full-queue-queues-an-overflow" }, function(t)
        local fd = fresh("QueuesOverflow")
        arm(t, fd)
        write_n(fd, QUEUE) -- fills it exactly
        local full = lcs.drain_events(w, fd)
        t:assert_eq(#full, QUEUE, "a queue filled exactly carries no OVERFLOW")
        t:assert_eq(count_of(full, lcs.WATCH.OVERFLOW), 0, "no OVERFLOW yet")

        write_n(fd, QUEUE + 1)
        local over = lcs.drain_events(w, fd)
        t:assert_eq(count_of(over, lcs.WATCH.OVERFLOW), 1,
            "one more event than fits queues an OVERFLOW: " .. lcs.event_summary(over))
        sys.close(w, fd)
    end)

test("the event that arrives at a full queue is discarded, not queued",
    { spec = "PKM *watch.overflow.triggering-event-is-discarded" }, function(t)
        local fd = fresh("Triggering")
        arm(t, fd)
        write_n(fd, QUEUE)
        lcs.set_value(src, w, fd, "Trigger", lcs.TYPE.DWORD, lcs.dword(1))
        local ev = lcs.drain_events(w, fd)
        for _, e in ipairs(ev) do
            t:assert(e.name ~= "Trigger",
                "the triggering event is nowhere in the queue: " .. lcs.event_summary(ev))
        end
        t:assert_eq(count_of(ev, lcs.WATCH.OVERFLOW), 1, "an OVERFLOW stands for it")
        sys.close(w, fd)
    end)

test("later events drop the oldest non-OVERFLOW and preserve the OVERFLOW",
    { spec = "PKM *watch.overflow.later-events-drop-the-oldest-and-preserve-the-overflow" },
    function(t)
        local fd = fresh("Preserve")
        arm(t, fd)
        write_n(fd, QUEUE + 4)
        local ev = lcs.drain_events(w, fd)
        local names = names_of(ev)
        t:assert_eq(#ev, QUEUE, "still bounded: " .. table.concat(names, ","))
        t:assert_eq(count_of(ev, lcs.WATCH.OVERFLOW), 1,
            "the single OVERFLOW was preserved rather than dropped as the oldest")
        -- V1..V4 were dropped to make room for the OVERFLOW and the
        -- three events after the one that triggered it.
        t:assert_eq(names[1], "V5", "the oldest non-OVERFLOW events made way")
        t:assert_eq(names[#names], "V" .. (QUEUE + 4),
            "and the queue carries the most recent history behind the OVERFLOW")
        sys.close(w, fd)
    end)

test("a queue holds at most one OVERFLOW at a time",
    { spec = "PKM *watch.overflow.at-most-one-overflow-per-queue" }, function(t)
        local fd = fresh("OneOverflow")
        arm(t, fd)
        write_n(fd, QUEUE * 4) -- far past the point where a second would be due
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(count_of(ev, lcs.WATCH.OVERFLOW), 1,
            "one OVERFLOW after " .. (QUEUE * 4) .. " events into a queue of " ..
            QUEUE .. ": " .. lcs.event_summary(ev))
        -- Draining and overflowing again queues a fresh one; the
        -- invariant is per queue state, not per fd lifetime.
        write_n(fd, QUEUE + 1)
        local again = lcs.drain_events(w, fd)
        t:assert_eq(count_of(again, lcs.WATCH.OVERFLOW), 1,
            "and one again once the queue was emptied and refilled")
        sys.close(w, fd)
    end)

test("an OVERFLOW does not describe what was dropped",
    { spec = "PKM *watch.overflow.dropped-events-are-not-described" }, function(t)
        local fd = fresh("NotDescribed")
        arm(t, fd)
        write_n(fd, QUEUE + 4)
        local ev = lcs.drain_events(w, fd)
        for _, e in ipairs(ev) do
            if e.type == lcs.WATCH.OVERFLOW then
                t:assert_eq(e.name, "", "the OVERFLOW names nothing")
                t:assert_eq(e.total_len, 8,
                    "and carries no payload beyond the eight-byte header, " ..
                    "so there is no way to learn what was dropped")
            end
        end
        t:assert_eq(count_of(ev, lcs.WATCH.OVERFLOW), 1, "an OVERFLOW was there to check")
        sys.close(w, fd)
    end)

test("events after an OVERFLOW are complete again",
    { spec = "PKM *watch.overflow.events-after-an-overflow-are-complete" }, function(t)
        local fd = fresh("Complete")
        arm(t, fd)
        write_n(fd, QUEUE + 4)
        local ev = lcs.drain_events(w, fd)
        local after, seen_overflow = {}, false
        for _, e in ipairs(ev) do
            if e.type == lcs.WATCH.OVERFLOW then
                seen_overflow = true
            elseif seen_overflow then
                after[#after + 1] = e.name
            end
        end
        t:assert(seen_overflow, "an OVERFLOW was queued: " .. lcs.event_summary(ev))
        t:assert_eq(table.concat(after, ","),
            "V" .. (QUEUE + 2) .. ",V" .. (QUEUE + 3) .. ",V" .. (QUEUE + 4),
            "every event after it is present, in order, with no further gaps")
        -- And the queue continues cleanly from there.
        lcs.set_value(src, w, fd, "Next", lcs.TYPE.DWORD, lcs.dword(1))
        local next_ev = lcs.drain_events(w, fd)
        t:assert_eq(#next_ev, 1, "the next change is delivered normally")
        t:assert_eq(next_ev[1].name, "Next", "and completely")
        sys.close(w, fd)
    end)

test("the only bound on watch memory is queue size times the fd limit",
    { spec = "PKM *watch.overflow.no-global-cap-beyond-queue-size-times-fd-limit" },
    function(t)
        -- No registry-specific global cap exists, so many armed fds
        -- each keep a full queue of their own: nothing collapses them
        -- or refuses to arm the next one.
        local key = fresh("NoGlobalCap")
        local fds = {}
        for i = 1, 12 do
            local o = lcs.open_watchable(src, w, -1, ROOT .. "\\NoGlobalCap",
                lcs.KEY_ALL_ACCESS)
            t:assert(o.ret >= 0, "fd " .. i .. " opened: " .. sys.errname(o.errno or 0))
            local n = lcs.notify(nil, w, o.ret, lcs.NOTIFY.ALL, false)
            t:assert_eq(n.ret, 0, "fd " .. i .. " armed: " .. sys.errname(n.errno or 0))
            fds[#fds + 1] = o.ret
        end
        write_n(key, QUEUE + 4)
        for i, fd in ipairs(fds) do
            local ev = lcs.drain_events(w, fd)
            t:assert_eq(#ev, QUEUE,
                "fd " .. i .. " kept its own full queue, capped only by " ..
                "NotificationQueueSize: " .. #ev)
        end
        for _, fd in ipairs(fds) do sys.close(w, fd) end
        sys.close(w, key)
    end)
