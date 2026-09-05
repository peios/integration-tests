-- §5.8.5, second half: the late response problem. A caller that timed
-- out is gone, but the request is not, and what the kernel still owes
-- depends on exactly what the source eventually says.
--
-- Every case here is the same shape: hold a request, let the caller
-- time out, then answer. RequestTimeoutMs is seeded down to a second
-- so that "eventually" is a second rather than thirty.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local kmes = require("helpers.kmes")

local vm = provium:vm("v", "kernel-only"):boot()

local ETIMEDOUT = 110
local PATH = "Machine\\Software\\Test"

local src = lcs.source(vm)
src:seed_param("RequestTimeoutMs", 1000)
local TEST_KEY = src:key(PATH)
src:value(TEST_KEY, "V", lcs.TYPE.DWORD, lcs.dword(1))
assert(src:register())
src:pump()
local w = vm:spawn_worker()

--- A fresh subkey, so cases do not share a watch or a value.
local function fresh(name)
    local r = lcs.create_key(src, w, { parent_fd = -1, path = PATH .. "\\" .. name,
        access = lcs.KEY_ALL_ACCESS })
    assert(r.ret >= 0, "create " .. name .. ": " .. sys.errname(r.errno or 0))
    return r.ret
end

--- Hold the next request of `op`, run `call` until its caller times
--- out, and return the result and the held request id.
local function time_out(t, op, call, source)
    source = source or src
    source:intercept(op, function() return lcs.HOLD end)
    local pending = call()
    for _ = 1, 60 do
        if #source:held_ids() >= 1 then break end
        source:pump(50)
    end
    source:intercept(op, nil)
    local ids = source:held_ids()
    t:assert_eq(#ids, 1, "the request reached the source and is unanswered")
    local r = pending:await()
    t:assert_eq(r.errno, ETIMEDOUT, "the caller timed out")
    return r, ids[1]
end

local POLLIN = 0x1

--- Is `type` (optionally for `name`) among `events`?
local function has_event(events, etype, name)
    for _, e in ipairs(events) do
        if e.type == etype and (name == nil or e.name == name) then return true end
    end
    return false
end

--- Watch events queued on a key fd. read(2) on a key fd blocks when
--- its queue is empty, so a case asserting that *nothing* was
--- delivered has to poll first.
local function events_on(who, fd)
    local p = who:syscall(sys.NR.poll, {
        args = { 0, 1, 100 },
        bufs = { string.pack("<i4i2i2", fd, POLLIN, 0) }, ptrs = { 0 },
    })
    if p.ret <= 0 then return {} end
    local revents = select(3, string.unpack("<i4i2i2", p.out_bufs[1]))
    if revents & POLLIN == 0 then return {} end
    local e = lcs.read_events(nil, who, fd)
    return e.ret > 0 and e.events or {}
end

local function generation(fd)
    local info = lcs.query_key_info(src, w, fd)
    return info.ret == 0 and info.hive_generation or nil
end

-- A late error, and a late read ---------------------------------------

test("a late error releases the record with no effects at all",
    { spec = "PKM *source.late.error-has-no-effects" }, function(t)
        local fd = fresh("LateError")
        t:assert_eq(lcs.notify(nil, w, fd, lcs.NOTIFY.ALL, false).ret, 0, "arm a watch")
        local before = generation(fd)
        local _, id = time_out(t, lcs.OP.SET_VALUE, function()
            return lcs.set_value_async(w, fd, "V", lcs.TYPE.DWORD, lcs.dword(9))
        end)
        -- The source failed the write and says so, long after the fact.
        t:assert(src:release(id, lcs.STATUS.STORAGE_ERROR, "") > 0, "the late error is accepted")
        src:pump(100)
        t:assert_eq(#events_on(w, fd), 0, "no watch event")
        t:assert_eq(generation(fd), before, "no generation change")
        local q = lcs.query_value(src, w, fd, "V")
        t:assert_eq(q.errno, sys.E.NOENT, "and nothing was written")
        sys.close(w, fd)
    end)

test("a late successful read is validated and then discarded",
    { spec = { "PKM *source.late.read-is-validated-then-discarded", "PKM *source.late.validated-like-an-on-time-response" } }, function(t)
        local fd = fresh("LateRead")
        t:assert_eq(lcs.set_value(src, w, fd, "V", lcs.TYPE.DWORD, lcs.dword(5)).ret, 0, "seed")
        t:assert_eq(lcs.notify(nil, w, fd, lcs.NOTIFY.ALL, false).ret, 0, "arm a watch")
        local before = generation(fd)
        local _, id = time_out(t, lcs.OP.QUERY_VALUES, function()
            return lcs.query_value_async(w, fd, "V")
        end)
        t:assert(src:release(id) > 0, "the honest answer arrives late and is accepted")
        src:pump(100)
        t:assert_eq(#events_on(w, fd), 0, "nothing about a read changes kernel state")
        t:assert_eq(generation(fd), before, "no generation change")
        sys.close(w, fd)
    end)

test("a late response is validated exactly like an on-time one",
    { spec = "PKM *source.late.validated-like-an-on-time-response" }, function(t)
        local fd = fresh("LateValidated")
        local _, id = time_out(t, lcs.OP.QUERY_VALUES, function()
            return lcs.query_value_async(w, fd, "V")
        end)
        -- Trailing bytes are malformed data on a late read exactly as
        -- they are on an on-time one: the audit event is emitted even
        -- though there is nobody left to return EIO to.
        local events = kmes.recording(t, vm, function()
            local st, body = src:dispatch(src.held[id])
            src:release(id, st, body .. "\0")
            src:pump(100)
        end)
        local vf = kmes.of_type(events, "LCS_SOURCE_VALIDATION_FAILURE")
        t:assert_eq(#vf, 1, "the late response was validated and failed")
        t:assert_eq(vf[1].payload.validation_class, "malformed_response_payload",
            "with the same class an on-time response would have produced")
        local alive = lcs.query_value(src, w, fd, "V")
        t:assert(alive.ret == 0 or alive.errno == sys.E.NOENT,
            "and malformed data on a read leaves the source alive")
        sys.close(w, fd)
    end)

-- A late successful mutation ------------------------------------------

test("a late successful RSI_SET_VALUE applies the effects retained for it",
    { spec = { "PKM *source.late.mutation-applies-retained-effects", "PKM *source.late.replayable-effects-only-for-set-value-and-write-key" } },
    function(t)
        local fd = fresh("LateSetValue")
        t:assert_eq(lcs.notify(nil, w, fd, lcs.NOTIFY.ALL, false).ret, 0, "arm a watch")
        local before = generation(fd)
        local _, id = time_out(t, lcs.OP.SET_VALUE, function()
            return lcs.set_value_async(w, fd, "Late", lcs.TYPE.DWORD, lcs.dword(42))
        end)
        t:assert(src:release(id, lcs.STATUS.OK, "") > 0, "the source applied it after all")
        src:pump(100)
        -- The applied late mutation is announced by an OVERFLOW first
        -- (§5.6.3's business, not this section's) and then the event it
        -- owed; this case is about the latter being dispatched at all.
        local evs = events_on(w, fd)
        t:assert(has_event(evs, lcs.WATCH.VALUE_SET, "Late"),
            "the watch event the mutation owed is dispatched, for the value written")
        local after = generation(fd)
        t:assert(after and before and after > before,
            "and the hive generation increments (" .. tostring(before) .. " -> " ..
            tostring(after) .. ")")
        sys.close(w, fd)
    end)

test("a late successful RSI_WRITE_KEY applies its effects too",
    { spec = "PKM *source.late.replayable-effects-only-for-set-value-and-write-key" },
    function(t)
        local fd = fresh("LateWriteKey")
        t:assert_eq(lcs.notify(nil, w, fd, lcs.NOTIFY.ALL, false).ret, 0, "arm a watch")
        local before = generation(fd)
        local _, id = time_out(t, lcs.OP.WRITE_KEY, function()
            return lcs.set_security_async(w, fd, lcs.SI.DACL, lcs.permissive_sd())
        end)
        t:assert(src:release(id, lcs.STATUS.OK, "") > 0, "the descriptor write landed late")
        src:pump(100)
        local evs = events_on(w, fd)
        t:assert(has_event(evs, lcs.WATCH.SD_CHANGED),
            "the SD_CHANGED event is dispatched from the retained record")
        local after = generation(fd)
        t:assert(after and before and after > before, "and the generation increments")
        sys.close(w, fd)
    end)

test("a late successful mutation the kernel cannot account for tears the source down",
    { spec = { "PKM *source.late.unreplayable-mutation-tears-source-down", "PKM *source.late.replayable-effects-only-for-set-value-and-write-key" } },
    function(t)
        -- Creating a path entry retains no replayable effect, so a late
        -- success is a mutation LCS cannot describe. The conservative
        -- direction is to take the source down rather than leave a
        -- committed change with no watch event.
        local doomed = lcs.source(vm, { hives = { { name = "LateCreate" } } })
        doomed:key("LateCreate\\K")
        assert(doomed:register())
        doomed:pump()
        local w2 = vm:spawn_worker()
        local parent = lcs.open_key(doomed, w2, -1, "LateCreate\\K", lcs.KEY_ALL_ACCESS)
        t:assert(parent.ret >= 0, "open the parent")

        local _, id = time_out(t, lcs.OP.CREATE_ENTRY, function()
            return lcs.create_key_async(w2, { parent_fd = parent.ret, path = "Child",
                access = lcs.KEY_ALL_ACCESS })
        end, doomed)
        doomed:release(id, lcs.STATUS.OK, "")
        doomed:pump(100)
        local after = lcs.open_key(doomed, w2, -1, "LateCreate\\K", lcs.RIGHT.KEY_READ)
        t:assert_eq(after.errno, sys.E.IO,
            "the slot is Down: an unaccountable late mutation is not silently ignored")
        w2:kill(); w2:join()
    end)

-- Late transaction operations -----------------------------------------

test("a late successful RSI_BEGIN_TRANSACTION enqueues an abort for the id nobody will use",
    { spec = "PKM *source.late.begin-transaction-enqueues-an-abort" }, function(t)
        local fd = fresh("LateBegin")
        local txn = assert(lcs.begin_transaction(w))
        local mark = src:mark()
        local _, id = time_out(t, lcs.OP.BEGIN_TXN, function()
            return lcs.create_key_async(w, { parent_fd = fd, path = "Sub",
                access = lcs.KEY_ALL_ACCESS, txn_fd = txn })
        end)
        local began = src.held[id]
        local txn_id = string.unpack("<I8", began.payload)
        t:assert(src:release(id, lcs.STATUS.OK, "") > 0, "the source did open the transaction")
        src:pump(200)
        local aborts = src:served(lcs.OP.ABORT_TXN, mark)
        t:assert(#aborts >= 1, "LCS enqueues an abort for it")
        local matched = false
        for _, a in ipairs(aborts) do
            if string.unpack("<I8", a.payload) == txn_id then matched = true end
        end
        t:assert(matched, "for that transaction id, so no orphaned source state is left")
        sys.close(w, txn)
        sys.close(w, fd)
    end)

test("a late RSI_FLUSH releases the record with no effects",
    { spec = "PKM *source.late.abort-or-flush-releases-the-record" }, function(t)
        local fd = fresh("LateFlush")
        t:assert_eq(lcs.notify(nil, w, fd, lcs.NOTIFY.ALL, false).ret, 0, "arm a watch")
        local before = generation(fd)
        local _, id = time_out(t, lcs.OP.FLUSH, function() return lcs.flush_async(w, fd) end)
        t:assert(src:release(id, lcs.STATUS.OK, "") > 0, "the late flush answer is accepted")
        src:pump(100)
        t:assert_eq(#events_on(w, fd), 0, "no watch event")
        t:assert_eq(generation(fd), before, "no generation change")
        local alive = lcs.query_value(src, w, fd, "V")
        t:assert(alive.ret == 0 or alive.errno == sys.E.NOENT, "and the source is untouched")
        sys.close(w, fd)
    end)

test("a late successful commit applies the retained commit effects, so watchers see a transaction whose caller was told it timed out",
    { spec = "PKM *source.late.commit-applies-retained-commit-effects" }, function(t)
        local fd = fresh("LateCommit")
        t:assert_eq(lcs.notify(nil, w, fd, lcs.NOTIFY.ALL, false).ret, 0, "arm a watch")
        local before = generation(fd)
        local txn = assert(lcs.begin_transaction(w))
        t:assert_eq(lcs.set_value(src, w, fd, "InTxn", lcs.TYPE.DWORD, lcs.dword(3),
            { txn_fd = txn }).ret, 0, "a write inside a transaction")
        t:assert_eq(#events_on(w, fd), 0, "which publishes nothing before the commit")

        local _, id = time_out(t, lcs.OP.COMMIT_TXN, function()
            return lcs.commit_async(w, txn)
        end)
        t:assert(src:release(id, lcs.STATUS.OK, "") > 0, "the commit succeeded, late")
        src:pump(200)
        local evs = events_on(w, fd)
        t:assert(has_event(evs, lcs.WATCH.VALUE_SET, "InTxn"),
            "the transaction's watch events are dispatched anyway, for the value it wrote")
        local after = generation(fd)
        t:assert(after and before and after > before, "and the generation is published")
        sys.close(w, txn)
        sys.close(w, fd)
    end)

test("a malformed late commit response tears the source down",
    { spec = "PKM *source.late.malformed-commit-tears-source-down" }, function(t)
        local doomed = lcs.source(vm, { hives = { { name = "LateBadCommit" } } })
        doomed:key("LateBadCommit\\K")
        assert(doomed:register())
        doomed:pump()
        local w2 = vm:spawn_worker()
        local r = lcs.open_key(doomed, w2, -1, "LateBadCommit\\K", lcs.KEY_ALL_ACCESS)
        t:assert(r.ret >= 0, "open the key")
        local txn = assert(lcs.begin_transaction(w2))
        t:assert_eq(lcs.set_value(doomed, w2, r.ret, "V", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn }).ret, 0, "bind the transaction")

        local _, id = time_out(t, lcs.OP.COMMIT_TXN, function()
            return lcs.commit_async(w2, txn)
        end, doomed)
        -- LCS cannot tell whether the commit applied, and cannot
        -- account for what it would have to publish.
        doomed:release(id, lcs.STATUS.OK, "\0\0")
        doomed:pump(100)
        local after = lcs.open_key(doomed, w2, -1, "LateBadCommit\\K", lcs.RIGHT.KEY_READ)
        t:assert_eq(after.errno, sys.E.IO, "the slot is Down")
        w2:kill(); w2:join()
    end)

test("a late response whose retained request metadata is missing or invalid tears the source down",
    { spec = "PKM *source.late.unprocessable-effects-tear-source-down",
      covered_by = "kunit:pkm_lcs_kunit_transaction",
      skip = "the request record is kernel-internal and nothing a source can send " ..
             "corrupts it; a guest can only reach it through the response, which is " ..
             "the malformed-late-commit case above. Runs under " ..
             "pkm_lcs_kunit_late_mutation_without_metadata_downs_source" },
    function(t) end)
