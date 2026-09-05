-- §5.8.3, Request Dispatch: the multiplexed channel, the in-flight
-- bound and the single deadline that covers all three of its waits,
-- what a timed-out record keeps hold of, requests with nobody waiting,
-- and the read/write/poll contract of /dev/pkm_registry.
--
-- The file's Machine source seeds two of the operational parameters
-- before registering, so a deadline is one second rather than thirty
-- and the in-flight bound is eight rather than 256 (§5.10.3).

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")

local vm = provium:vm("v", "kernel-only"):boot()

-- Not in helpers/sys's table, and this file is the only user.
local ETIMEDOUT, EMSGSIZE = 110, 90
local POLLIN, POLLOUT, POLLERR, POLLHUP = 0x1, 0x4, 0x8, 0x10
local MAX_IN_FLIGHT = 8
local TIMEOUT_MS = 1000
local PATH = "Machine\\Software\\Test"

local src = lcs.source(vm)
src:seed_param("RequestTimeoutMs", TIMEOUT_MS)
src:seed_param("MaxConcurrentRSIRequests", MAX_IN_FLIGHT)
local TEST_KEY = src:key(PATH)
assert(src:register())
src:pump()
local w = vm:spawn_worker()

--- poll(2) one fd for `events`, returning the revents mask.
local function poll(who, fd, events, timeout_ms)
    local r = who:syscall(sys.NR.poll, {
        args = { 0, 1, timeout_ms or 0 },
        bufs = { string.pack("<i4i2i2", fd, events, 0) }, ptrs = { 0 },
    })
    if r.ret < 0 then return nil, r.errno end
    return (select(3, string.unpack("<i4i2i2", r.out_bufs[1])))
end

--- A raw read(2) on the source's own device fd, bypassing the pump.
local function raw_read(size)
    local r = src.worker:syscall(sys.NR.read, {
        args = { src.fd, 0, size },
        bufs = { string.rep("\0", size) }, ptrs = { 1 },
    })
    if r.ret < 0 then return nil, r.errno end
    return r.out_bufs[1]:sub(1, r.ret)
end

--- Pump until `n` requests are held, or give up after `tries`.
local function pump_until_held(n, tries)
    for _ = 1, tries or 40 do
        if #src:held_ids() >= n then return true end
        src:pump(50)
    end
    return #src:held_ids() >= n
end

-- Multiplexing -------------------------------------------------------

test("a source may answer concurrent requests in any order",
    { spec = "PKM *source.dispatch.responses-may-arrive-in-any-order" }, function(t)
        local a, b = vm:spawn_worker(), vm:spawn_worker()
        src:intercept(lcs.OP.LOOKUP, function() return lcs.HOLD end)
        local pa = lcs.open_key_async(a, -1, PATH, lcs.RIGHT.KEY_READ)
        local pb = lcs.open_key_async(b, -1, PATH, lcs.RIGHT.KEY_READ)
        t:assert(pump_until_held(2), "both walks reached the source and are held")
        local ids = src:held_ids()
        t:assert_eq(#ids, 2, "two requests in flight, tagged with distinct ids")
        src:intercept(lcs.OP.LOOKUP, nil)
        -- Answer the newer one first: matching is by request id, not
        -- by arrival order.
        src:release(ids[2])
        src:release(ids[1])
        local ra = src:run(function() return pa end)
        local rb = src:run(function() return pb end)
        t:assert(ra.ret >= 0, "the first caller still got its answer: " ..
            sys.errname(ra.errno or 0))
        t:assert(rb.ret >= 0, "and so did the second: " .. sys.errname(rb.errno or 0))
        sys.close(a, ra.ret); sys.close(b, rb.ret)
        a:kill(); a:join(); b:kill(); b:join()
    end)

test("request ids are strictly increasing and never reused, including after a timeout",
    { spec = "PKM *source.dispatch.request-ids-never-reused" }, function(t)
        local seen = {}
        for _, e in ipairs(src.log) do seen[#seen + 1] = e.id end
        t:assert(#seen > 1, "the file has already made several requests")
        for i = 2, #seen do
            t:assert(seen[i] > seen[i - 1],
                "id " .. seen[i] .. " follows " .. seen[i - 1] .. " strictly")
        end
        -- Time one out, then check the next id is past it rather than
        -- reusing the id the abandoned record still holds.
        src:intercept(lcs.OP.LOOKUP, function() return lcs.HOLD end)
        local pending = lcs.open_key_async(w, -1, PATH, lcs.RIGHT.KEY_READ)
        t:assert(pump_until_held(1), "a lookup is held")
        local timed_out_id = src:held_ids()[1]
        local r = pending:await()
        t:assert_eq(r.errno, ETIMEDOUT, "the caller times out")
        src:intercept(lcs.OP.LOOKUP, nil)
        local mark = src:mark()
        local ok = lcs.open_key(src, w, -1, PATH, lcs.RIGHT.KEY_READ)
        t:assert(ok.ret >= 0, "a later call goes through: " .. sys.errname(ok.errno or 0))
        sys.close(w, ok.ret)
        for _, e in ipairs(src:served(lcs.OP.LOOKUP, mark)) do
            t:assert(e.id > timed_out_id,
                "id " .. e.id .. " is past the timed-out " .. timed_out_id ..
                ": ids are never reused while the connection lives")
        end
        src:release(timed_out_id)
    end)

-- The in-flight bound and the deadline --------------------------------

test("MaxConcurrentRSIRequests bounds in-flight requests, a caller that never gets a slot sends nothing, and a timeout frees none",
    { spec = { "PKM *source.dispatch.max-concurrent-bounds-in-flight", "PKM *source.dispatch.timeout-before-a-slot-sends-nothing", "PKM *source.dispatch.timeout-does-not-free-a-slot", "PKM *source.dispatch.record-kept-until-response-or-teardown", "PKM *source.dispatch.one-deadline-covers-three-waits" } }, function(t)
        local hold = {}
        for i = 1, MAX_IN_FLIGHT do hold[i] = vm:spawn_worker() end
        local queued = vm:spawn_worker()
        src:intercept(lcs.OP.LOOKUP, function() return lcs.HOLD end)
        local pendings = {}
        for i = 1, MAX_IN_FLIGHT do
            pendings[i] = lcs.open_key_async(hold[i], -1, PATH, lcs.RIGHT.KEY_READ)
        end
        t:assert(pump_until_held(MAX_IN_FLIGHT),
            "all " .. MAX_IN_FLIGHT .. " slots are occupied by unanswered requests")
        t:assert_eq(#src:held_ids(), MAX_IN_FLIGHT,
            "which is exactly MaxConcurrentRSIRequests")

        -- The next caller waits for a slot, and the deadline computed
        -- when it first tried to reserve one covers that wait too.
        local mark = src:mark()
        local blocked = lcs.open_key_async(queued, -1, PATH, lcs.RIGHT.KEY_READ)
        local r = blocked:await()
        t:assert_eq(r.errno, ETIMEDOUT,
            "the queued caller gets ETIMEDOUT from the same deadline")
        src:pump(50)
        t:assert_eq(#src:served(lcs.OP.LOOKUP, mark), 0,
            "and no request was sent: the deadline expired before a slot was reserved")

        -- A timeout does not free a slot; only a response or a
        -- teardown does. The next caller finds the table just as full.
        local mark2 = src:mark()
        local again = lcs.open_key_async(queued, -1, PATH, lcs.RIGHT.KEY_READ)
        t:assert_eq(again:await().errno, ETIMEDOUT,
            "the following caller times out as well: the records are still in the table")
        src:pump(50)
        t:assert_eq(#src:served(lcs.OP.LOOKUP, mark2), 0, "and it too sent nothing")

        -- Answering them is what frees the slots.
        src:intercept(lcs.OP.LOOKUP, nil)
        for _, id in ipairs(src:held_ids()) do src:release(id) end
        for i = 1, MAX_IN_FLIGHT do
            local rr = src:run(function() return pendings[i] end)
            if rr.ret >= 0 then sys.close(hold[i], rr.ret) end
        end
        local free = lcs.open_key(src, w, -1, PATH, lcs.RIGHT.KEY_READ)
        t:assert(free.ret >= 0,
            "with the records released the next caller is admitted: " ..
            sys.errname(free.errno or 0))
        sys.close(w, free.ret)
        for i = 1, MAX_IN_FLIGHT do hold[i]:kill(); hold[i]:join() end
        queued:kill(); queued:join()
    end)

test("a deadline expiring after dispatch returns ETIMEDOUT and detaches the caller from the record",
    { spec = { "PKM *source.dispatch.timeout-after-dispatch-is-etimedout", "PKM *source.dispatch.timeout-detaches-caller-from-record" } }, function(t)
        src:intercept(lcs.OP.QUERY_VALUES, function() return lcs.HOLD end)
        local r = lcs.open_key(src, w, -1, PATH, lcs.KEY_ALL_ACCESS)
        t:assert(r.ret >= 0, "open the key first")
        local fd = r.ret
        local pending = lcs.query_value_async(w, fd, "Anything")
        t:assert(pump_until_held(1), "the query reached the source and is held")
        local id = src:held_ids()[1]
        t:assert_eq(pending:await().errno, ETIMEDOUT, "the caller gets ETIMEDOUT")
        src:intercept(lcs.OP.QUERY_VALUES, nil)
        -- The caller is gone but the record is not: the source's answer
        -- is still accepted rather than rejected as unknown.
        local wrote = src:release(id)
        t:assert(wrote and wrote > 0,
            "the late answer is still accepted on the wire: the record outlived its caller")
        sys.close(w, fd)
    end)

test("the deadline is checked before admission is attempted, not only after a contention round is lost",
    { spec = "PKM *source.dispatch.deadline-checked-before-admission",
      covered_by = "kunit:pkm_lcs_kunit_source",
      skip = "the difference is between failing in the admission leg and failing in " ..
             "the wait leg, and both surface to the guest as the same ETIMEDOUT on the " ..
             "same call; runs under pkm_lcs_kunit_source_slot_timeout_sends_no_request" },
    function(t) end)

test("the request record holds the id, op code, transaction id, key GUID, limits and retained effect",
    { spec = "PKM *source.dispatch.record-contents",
      covered_by = "kunit:pkm_lcs_kunit_source",
      skip = "the record is a kernel object with no ioctl that reads it back; runs " ..
             "under pkm_lcs_kunit_source_read_retains_in_flight_until_release" },
    function(t) end)

test("the request id is allocated inside the queue lock, after the in-flight limit check",
    { spec = "PKM *source.dispatch.id-allocated-after-the-limit-check",
      covered_by = "kunit:pkm_lcs_kunit_source",
      skip = "a caller queued for a slot holds no id, and no id is observable until a " ..
             "request is dispatched; runs under " ..
             "pkm_lcs_kunit_source_in_flight_full_blocks_after_read" },
    function(t) end)

-- Requests with no caller ---------------------------------------------

test("RSI_DROP_KEY is dispatched with nobody waiting, occupies a slot, and is not a late response",
    { spec = { "PKM *source.dispatch.callerless-requests-are-dispatched", "PKM *source.dispatch.callerless-record-occupies-a-slot", "PKM *source.dispatch.callerless-is-not-a-late-response", "PKM *source.dispatch.timed-out-means-caller-detached-after-deadline" } },
    function(t) do
        local r = lcs.create_key(src, w, { parent_fd = -1,
            path = PATH .. "\\Doomed", access = lcs.KEY_ALL_ACCESS })
        t:assert(r.ret >= 0, "create a key to orphan: " .. sys.errname(r.errno or 0))
        t:assert_eq(lcs.delete_key(src, w, r.ret).ret, 0, "delete its last name")

        -- Closing the last fd to the now-orphaned key dispatches
        -- RSI_DROP_KEY with no caller behind it. Hold it.
        src:intercept(lcs.OP.DROP_KEY, function() return lcs.HOLD end)
        local mark = src:mark()
        sys.close(w, r.ret)
        t:assert(pump_until_held(1), "the drop was dispatched with nobody waiting")
        local served = src:served(lcs.OP.DROP_KEY, mark)
        t:assert_eq(#served, 1, "exactly one RSI_DROP_KEY")
        local drop_id = src:held_ids()[1]

        -- It is an ordinary in-flight record while it is unanswered.
        -- The bound is per source, so filling the rest of the table
        -- and finding one slot short proves it holds one.
        local hold = {}
        for i = 1, MAX_IN_FLIGHT - 1 do hold[i] = vm:spawn_worker() end
        src:intercept(lcs.OP.LOOKUP, function() return lcs.HOLD end)
        local pendings = {}
        for i = 1, MAX_IN_FLIGHT - 1 do
            pendings[i] = lcs.open_key_async(hold[i], -1, PATH, lcs.RIGHT.KEY_READ)
        end
        t:assert(pump_until_held(MAX_IN_FLIGHT),
            "the drop plus " .. (MAX_IN_FLIGHT - 1) .. " lookups fill the table")
        local extra = vm:spawn_worker()
        local blocked = lcs.open_key_async(extra, -1, PATH, lcs.RIGHT.KEY_READ)
        t:assert_eq(blocked:await().errno, ETIMEDOUT,
            "one more caller finds no slot: the caller-less record occupies one")
        extra:kill(); extra:join()

        src:intercept(lcs.OP.LOOKUP, nil)
        for _, id in ipairs(src:held_ids()) do
            if id ~= drop_id then src:release(id) end
        end
        for i = 1, MAX_IN_FLIGHT - 1 do
            local rr = src:run(function() return pendings[i] end)
            if rr.ret >= 0 then sys.close(hold[i], rr.ret) end
            hold[i]:kill(); hold[i]:join()
        end
        src:intercept(lcs.OP.DROP_KEY, nil)

        -- RSI_DROP_KEY is a mutating operation, and this answer arrives
        -- long after dispatch — but it never had a caller, so it is not
        -- a late response and the retained-effect rules do not apply to
        -- it. An unaccountable late mutation would tear the source
        -- down (§5.8.5); this one does not.
        local wrote = src:release(drop_id, lcs.STATUS.OK, "")
        t:assert(wrote and wrote > 0, "the answer is accepted")
        src:pump(50)
        t:assert(not src.hup, "and the slot is still up")
        local alive = lcs.open_key(src, w, -1, PATH, lcs.RIGHT.KEY_READ)
        t:assert(alive.ret >= 0,
            "a caller-less answer is not a timed-out one, and the source serves on: " ..
            sys.errname(alive.errno or 0))
        sys.close(w, alive.ret)
    end end)

-- The channel ---------------------------------------------------------

test("read returns exactly one request, and a buffer too small returns EMSGSIZE without consuming it",
    { spec = "PKM *source.dispatch.read-returns-one-request-or-emsgsize" }, function(t)
        -- Queue one request without pumping it, then read by hand.
        src:intercept(lcs.OP.LOOKUP, function() return lcs.HOLD end)
        local pending = lcs.open_key_async(w, -1, PATH, lcs.RIGHT.KEY_READ)
        for _ = 1, 40 do
            if poll(src.worker, src.fd, POLLIN, 50) & POLLIN ~= 0 then break end
        end
        local short, errno = raw_read(8)
        t:assert(not short, "a buffer too small for the next request does not read it")
        t:assert_eq(errno, EMSGSIZE, "EMSGSIZE")
        local full = raw_read(65536)
        t:assert(full, "and the request is still queued for a big enough buffer")
        local total, id, op = string.unpack("<I4I8I2", full)
        t:assert_eq(total, #full, "one complete request, framed by its own total_len")
        t:assert_eq(op, lcs.OP.LOOKUP, "the lookup that was queued")
        -- Answer it by hand so the caller does not time out.
        src:write_frame(lcs.response_frame(id, lcs.OP.LOOKUP, lcs.STATUS.NOT_FOUND, ""))
        src:intercept(lcs.OP.LOOKUP, nil)
        local r = src:run(function() return pending end)
        t:assert_eq(r.errno, sys.E.NOENT, "the caller sees the answer that was written")
    end)

test("an empty queue returns EAGAIN under O_NONBLOCK",
    { spec = "PKM *source.dispatch.empty-queue-blocks-or-eagain" }, function(t)
        -- The blocking and closing halves need a blocking descriptor
        -- and a teardown racing a reader; they run under
        -- pkm_lcs_kunit_source_request_blocking_read_wakes_on_enqueue
        -- and _wakes_on_closing.
        src:pump(50)
        local got, errno = raw_read(65536)
        t:assert(not got, "nothing is queued")
        t:assert_eq(errno, sys.E.AGAIN, "EAGAIN rather than a blocking wait")
    end)

test("poll reports the queue and the slot state, and an unregistered fd reports nothing",
    { spec = { "PKM *source.dispatch.poll-reports-queue-and-slot-state", "PKM *source.dispatch.unregistered-fd-polls-nothing" } }, function(t)
        local mask = POLLIN | POLLOUT
        src:pump(50)
        local quiet = poll(src.worker, src.fd, mask, 0)
        t:assert_eq(quiet & POLLOUT, POLLOUT, "an Active slot is writable")
        t:assert_eq(quiet & POLLIN, 0, "and not readable with an empty queue")

        src:intercept(lcs.OP.LOOKUP, function() return lcs.HOLD end)
        local pending = lcs.open_key_async(w, -1, PATH, lcs.RIGHT.KEY_READ)
        local busy = 0
        for _ = 1, 40 do
            busy = poll(src.worker, src.fd, mask, 50)
            if busy & POLLIN ~= 0 then break end
        end
        t:assert_eq(busy & POLLIN, POLLIN, "a queued request makes it readable")
        src:pump(50)
        src:intercept(lcs.OP.LOOKUP, nil)
        for _, id in ipairs(src:held_ids()) do src:release(id) end
        local r = src:run(function() return pending end)
        if r.ret >= 0 then sys.close(w, r.ret) end

        -- An fd that is open but has not registered reports nothing at
        -- all — neither readable nor writable nor in error.
        local unreg = vm:spawn_worker()
        local fd = assert(sys.open(unreg, lcs.DEVICE, sys.O.RDWR))
        t:assert_eq(poll(unreg, fd, mask | POLLERR | POLLHUP, 0), 0,
            "an unregistered fd polls nothing at all")
        sys.close(unreg, fd)
        unreg:kill(); unreg:join()
    end)

test("a response whose length does not equal its total_len is EINVAL and tears the connection down",
    { spec = { "PKM *source.dispatch.write-submits-one-response-of-exact-length", "PKM *source.dispatch.rejected-write-is-einval-and-tears-down", "PKM *source.dispatch.poll-reports-queue-and-slot-state" } }, function(t)
        local bad = lcs.source(vm, { hives = { { name = "ShortWrite" } } })
        bad:key("ShortWrite\\K")
        assert(bad:register())
        bad:pump()
        local w2 = vm:spawn_worker()
        -- Answer the first lookup with a frame one byte shorter than
        -- the total_len it declares.
        bad:intercept(lcs.OP.LOOKUP, function(self, req)
            local frame = lcs.response_frame(req.id, req.op, lcs.STATUS.NOT_FOUND, "")
            return frame:sub(1, #frame - 1)
        end)
        local r = lcs.open_key(bad, w2, -1, "ShortWrite\\K", lcs.RIGHT.KEY_READ)
        t:assert(r.ret < 0, "the caller does not get an answer")
        t:assert_eq(r.errno, sys.E.IO, "its request is completed EIO by the teardown")
        local revents = poll(bad.worker, bad.fd, POLLIN | POLLOUT | POLLERR | POLLHUP, 50)
        t:assert(revents & (POLLERR | POLLHUP) ~= 0,
            "and the slot is Down: poll reports POLLHUP | POLLERR")
        t:assert_eq(revents & POLLOUT, 0, "and no longer writable")
        local after = lcs.open_key(bad, w2, -1, "ShortWrite\\K", lcs.RIGHT.KEY_READ)
        t:assert_eq(after.errno, sys.E.IO, "the hive is unavailable afterwards")
        w2:kill(); w2:join()
    end)

test("a response carrying an unknown request id is EINVAL and tears the connection down",
    { spec = "PKM *source.dispatch.rejected-write-is-einval-and-tears-down" }, function(t)
        local bad = lcs.source(vm, { hives = { { name = "UnknownId" } } })
        bad:key("UnknownId\\K")
        assert(bad:register())
        bad:pump()
        local w2 = vm:spawn_worker()
        local ret, errno = bad:write_frame(
            lcs.response_frame(0xdeadbeef, lcs.OP.LOOKUP, lcs.STATUS.OK, ""))
        t:assert(ret < 0, "the write is rejected")
        t:assert_eq(errno, sys.E.INVAL, "EINVAL")
        local revents = poll(bad.worker, bad.fd, POLLIN | POLLOUT | POLLERR | POLLHUP, 50)
        t:assert(revents & (POLLERR | POLLHUP) ~= 0, "and the connection is torn down")
        local after = lcs.open_key(bad, w2, -1, "UnknownId\\K", lcs.RIGHT.KEY_READ)
        t:assert_eq(after.errno, sys.E.IO, "the source is Down")
        w2:kill(); w2:join()
    end)

test("a response whose op code is not the request's is EINVAL and tears the connection down",
    { spec = "PKM *source.dispatch.rejected-write-is-einval-and-tears-down" }, function(t)
        local bad = lcs.source(vm, { hives = { { name = "WrongOp" } } })
        bad:key("WrongOp\\K")
        assert(bad:register())
        bad:pump()
        local w2 = vm:spawn_worker()
        bad:intercept(lcs.OP.LOOKUP, function(self, req)
            return lcs.response_frame(req.id, lcs.OP.READ_KEY, lcs.STATUS.OK, "")
        end)
        local r = lcs.open_key(bad, w2, -1, "WrongOp\\K", lcs.RIGHT.KEY_READ)
        t:assert_eq(r.errno, sys.E.IO, "the waiter is completed EIO")
        local revents = poll(bad.worker, bad.fd, POLLIN | POLLOUT | POLLERR | POLLHUP, 50)
        t:assert(revents & (POLLERR | POLLHUP) ~= 0, "and the connection is torn down")
        w2:kill(); w2:join()
    end)
