-- PKM §5.7.3 — what `REG_IOC_COMMIT` triggers, the failures that leave
-- the transaction open, the indeterminate answer a post-dispatch
-- timeout gives, and what happens when the watch events cannot be
-- derived.
--
-- The late-response cases hold `RSI_COMMIT_TRANSACTION` at the source
-- with `lcs.HOLD` and answer it after `RequestTimeoutMs`, hot-swapped
-- down to its range minimum of one second.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")

local vm = provium:vm("v", "kernel-only"):boot()

local ROOT = "Machine\\Software\\Test"
local ETIMEDOUT = 110

local src = lcs.source(vm)
src:seed_param("RequestTimeoutMs", 30000)      -- the compiled-in default
src:seed_param("TransactionTimeoutMs", 30000)  -- the compiled-in default
src:seed_layer("high", { precedence = 10, enabled = true })
src:key(ROOT)
src:key(ROOT .. "\\Success")
src:key(ROOT .. "\\Failure")
src:key(ROOT .. "\\Late")
src:key(ROOT .. "\\Derive")
src:key(ROOT .. "\\Abort")
src:key(ROOT .. "\\Orphan\\Child")
src:key(ROOT .. "\\Derive\\C1")
src:key(ROOT .. "\\Derive\\C2")
src:key(ROOT .. "\\Derive\\C3")

local derive_key = src:key(ROOT .. "\\Derive")
for _, n in ipairs({ "D1", "D2", "D3" }) do
    src:value(derive_key, n, lcs.TYPE.DWORD, lcs.dword(1))
end

assert(src:register())
src:pump()

local w = vm:spawn_worker()

local function open_key(path)
    local r = lcs.open_key(src, w, -1, path, lcs.KEY_ALL_ACCESS)
    assert(r.ret >= 0, "opening " .. path .. ": " .. sys.errname(r.errno or 0))
    return r.ret
end

local function open_watched(t, path, subtree)
    local fd = open_key(path)
    lcs.nonblock(w, fd)
    local n = lcs.notify(nil, w, fd, lcs.NOTIFY.ALL, subtree or false)
    t:assert_eq(n.ret, 0, "arming a watch on " .. path .. ": " ..
        sys.errname(n.errno or 0))
    return fd
end

local params_fd = open_key(lcs.PARAMS_PATH)

local function set_param(t, name, value)
    local s = lcs.set_value(src, w, params_fd, name, lcs.TYPE.DWORD, lcs.dword(value))
    t:assert_eq(s.ret, 0, "setting " .. name .. ": " .. sys.errname(s.errno or 0))
end

local function generation(fd)
    return lcs.query_key_info(src, w, fd).hive_generation
end

-- ---- what commit sends -------------------------------------------------

test("REG_IOC_COMMIT sends one RSI_COMMIT_TRANSACTION for the bound transaction",
    { spec = "PKM *txn.commit.marks-in-flight-and-sends-rsi-commit" }, function(t)
        local fd = open_key(ROOT .. "\\Success")
        local txn = assert(lcs.begin_transaction(w))
        local mark = src:mark()
        lcs.set_value(src, w, fd, "Sent", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
        local write = src:served(lcs.OP.SET_VALUE, mark)[1]
        t:assert(write, "the write reached the source")
        t:assert_eq(lcs.commit(src, w, txn).ret, 0, "commit")
        local commits = src:served(lcs.OP.COMMIT_TXN, mark)
        t:assert_eq(#commits, 1, "exactly one RSI_COMMIT_TRANSACTION was sent")
        t:assert_eq(string.unpack("<I8", commits[1].payload), write.txn,
            "naming the transaction the operations were tagged with")
        sys.close(w, txn); sys.close(w, fd)
    end)

test("a lifetime timeout with a commit already in flight sends no abort",
    { spec = "PKM *txn.commit.marks-in-flight-and-sends-rsi-commit" }, function(t)
        -- The in-flight marker is what stops the timeout path from
        -- also telling the source to roll back.
        local fd = open_key(ROOT .. "\\Late")
        set_param(t, "RequestTimeoutMs", 1000)
        set_param(t, "TransactionTimeoutMs", 1000)
        src:intercept(lcs.OP.COMMIT_TXN, function() return lcs.HOLD end)
        local txn = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "InFlight", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        local mark = src:mark()
        local cm = lcs.commit(src, w, txn)
        t:assert_eq(cm.errno, ETIMEDOUT, "the commit request timed out")
        sys.nanosleep(vm, 2, 0)
        src:pump(150)
        t:assert_eq(#src:served(lcs.OP.ABORT_TXN, mark), 0,
            "and the lifetime timeout sent no RSI_ABORT_TRANSACTION, because a " ..
            "commit was already in flight")
        for _, id in ipairs(src:held_ids()) do src:release(id, lcs.STATUS.STORAGE_ERROR) end
        src:intercept(lcs.OP.COMMIT_TXN, nil)
        sys.nanosleep(vm, 0, 300000000)
        src:pump(150)
        set_param(t, "RequestTimeoutMs", 30000)
        set_param(t, "TransactionTimeoutMs", 30000)
        sys.close(w, txn); sys.close(w, fd)
    end)

-- ---- success ------------------------------------------------------------

test("a successful commit finalises the object, releases the log and returns zero",
    { spec = "PKM *txn.commit.success-finalises-and-returns-zero" }, function(t)
        local fd = open_watched(t, ROOT .. "\\Success")
        local txn = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "Final", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
        lcs.drain_events(w, fd)
        local cm = lcs.commit(src, w, txn)
        t:assert_eq(cm.ret, 0, "the ioctl returns 0: " .. sys.errname(cm.errno or 0))
        t:assert_eq(lcs.txn_status(nil, w, txn).state, lcs.TXN.COMMITTED,
            "the object becomes COMMITTED")
        local revents = lcs.poll_revents(w, txn, 0)
        t:assert_eq(revents & 0x18, 0x18, "poll waiters are woken")
        t:assert_eq(lcs.commit(nil, w, txn).errno, sys.E.INVAL,
            "and the log is released, so there is nothing left to commit")
        t:assert_eq(#lcs.drain_events(w, fd), 1, "the batch went out")
        lcs.notify(nil, w, fd, 0, false)
        sys.close(w, txn); sys.close(w, fd)
    end)

test("RSI_OK triggers the layer refresh, the generation bump, orphan tracking " ..
     "and the watch batch, all complete before the ioctl returns",
    { spec = "PKM *txn.commit.post-commit-step-order" }, function(t)
        local watcher = open_watched(t, ROOT .. "\\Orphan", true)
        local child = open_key(ROOT .. "\\Orphan\\Child")
        local before = generation(watcher)
        lcs.drain_events(w, watcher)

        local txn = assert(lcs.begin_transaction(w))
        local layer = lcs.create_key(src, w, {
            path = lcs.LAYERS_PATH .. "\\Stepwise", txn_fd = txn })
        t:assert(layer.ret >= 0, "creating a layer in the transaction: " ..
            sys.errname(layer.errno or 0))
        for _, v in ipairs({ { "Precedence", 50 }, { "Enabled", 1 } }) do
            lcs.set_value(src, w, layer.ret, v[1], lcs.TYPE.DWORD, lcs.dword(v[2]),
                { txn_fd = txn })
        end
        local d = lcs.delete_key(src, w, child, { txn_fd = txn })
        t:assert_eq(d.ret, 0, "and dropping the child's last path entry: " ..
            sys.errname(d.errno or 0))
        local cm = lcs.commit(src, w, txn)
        t:assert_eq(cm.ret, 0, "commit: " .. sys.errname(cm.errno or 0))

        -- Every one of the four steps has already happened.
        local use_layer = lcs.set_value(src, w, watcher, "InNewLayer", lcs.TYPE.DWORD,
            lcs.dword(1), { layer = "Stepwise" })
        t:assert_eq(use_layer.ret, 0,
            "the layer metadata cache was refreshed for the layer the transaction " ..
            "created: " .. sys.errname(use_layer.errno or 0))
        t:assert(generation(watcher) > before, "the hive generation was incremented")
        local rearm = lcs.notify(nil, w, child, lcs.NOTIFY.ALL, false)
        t:assert_eq(rearm.errno, sys.E.NOENT,
            "orphan tracking ran for the key that lost its last path entry")
        local ev = lcs.drain_events(w, watcher)
        t:assert(#ev >= 1, "and the watch batch was derived from the log: " ..
            lcs.event_summary(ev))
        lcs.notify(nil, w, watcher, 0, false)
        sys.close(w, layer.ret); sys.close(w, txn); sys.close(w, child)
        sys.close(w, watcher)
    end)

test("the hive generation is incremented once per committed transaction per hive",
    { spec = "PKM *txn.commit.generation-incremented-once-per-transaction-per-hive" },
    function(t)
        local fd = open_key(ROOT .. "\\Success")
        local before = generation(fd)
        local txn = assert(lcs.begin_transaction(w))
        for i = 1, 5 do
            lcs.set_value(src, w, fd, "G" .. i, lcs.TYPE.DWORD, lcs.dword(i),
                { txn_fd = txn })
        end
        t:assert_eq(lcs.commit(src, w, txn).ret, 0, "commit")
        t:assert_eq(generation(fd), before + 1,
            "five operations, one increment, however many the transaction contained")
        sys.close(w, txn); sys.close(w, fd)
    end)

-- ---- failures that leave the transaction open ---------------------------

test("RSI_TXN_BUSY becomes EBUSY and a synchronous commit failure becomes EIO",
    { spec = "PKM *txn.commit.busy-is-ebusy-and-commit-failure-is-eio" }, function(t)
        local fd = open_key(ROOT .. "\\Failure")
        local txn = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "Busy", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
        src.commit_status = lcs.STATUS.TXN_BUSY
        t:assert_eq(lcs.commit(src, w, txn).errno, sys.E.BUSY,
            "a source that cannot take the write lock answers RSI_TXN_BUSY: EBUSY")
        src.commit_status = lcs.STATUS.STORAGE_ERROR
        t:assert_eq(lcs.commit(src, w, txn).errno, sys.E.IO,
            "a synchronous commit failure becomes EIO")
        src.commit_status = nil
        sys.close(w, txn); src:pump(150); sys.close(w, fd)
    end)

test("a failed commit leaves the transaction ACTIVE_BOUND with its log, no events, " ..
     "and no poll wakeup",
    { spec = "PKM *txn.commit.failed-commit-stays-active-bound" }, function(t)
        local fd = open_watched(t, ROOT .. "\\Failure")
        local txn = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "Kept", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
        lcs.drain_events(w, fd)
        src.commit_status = lcs.STATUS.TXN_BUSY
        t:assert_eq(lcs.commit(src, w, txn).errno, sys.E.BUSY, "the commit fails EBUSY")
        t:assert_eq(lcs.txn_status(nil, w, txn).state, lcs.TXN.ACTIVE_BOUND,
            "the transaction stays ACTIVE_BOUND")
        t:assert_eq(lcs.txn_status(nil, w, txn).terminal_errno, 0,
            "with no terminal errno, because it is not terminal")
        t:assert_eq(#lcs.drain_events(w, fd), 0, "no watch events were emitted")
        t:assert_eq(lcs.poll_revents(w, txn, 0), 0,
            "and poll waiters were not woken as though it had become terminal")
        src.commit_status = nil
        lcs.notify(nil, w, fd, 0, false)
        sys.close(w, txn); src:pump(150); sys.close(w, fd)
    end)

test("a failed commit retains the mutation log, so a retry applies everything",
    { spec = "PKM *txn.commit.failed-commit-retains-the-log" }, function(t)
        local fd = open_key(ROOT .. "\\Failure")
        local txn = assert(lcs.begin_transaction(w))
        for _, n in ipairs({ "L1", "L2", "L3" }) do
            lcs.set_value(src, w, fd, n, lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
        end
        src.commit_status = lcs.STATUS.TXN_BUSY
        t:assert_eq(lcs.commit(src, w, txn).errno, sys.E.BUSY, "the commit fails")
        src.commit_status = nil
        t:assert_eq(lcs.commit(src, w, txn).ret, 0, "the retry succeeds: nothing was lost")
        for _, n in ipairs({ "L1", "L2", "L3" }) do
            t:assert_eq(lcs.query_value(src, w, fd, n).ret, 0,
                n .. " was applied by the retried commit")
        end
        sys.close(w, txn); sys.close(w, fd)
    end)

test("a failed commit emits no watch events at all",
    { spec = "PKM *txn.commit.failed-commit-emits-no-events" }, function(t)
        local fd = open_watched(t, ROOT .. "\\Failure")
        local txn = assert(lcs.begin_transaction(w))
        for _, n in ipairs({ "E1", "E2" }) do
            lcs.set_value(src, w, fd, n, lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
        end
        lcs.drain_events(w, fd)
        src.commit_status = lcs.STATUS.STORAGE_ERROR
        t:assert_eq(lcs.commit(src, w, txn).errno, sys.E.IO, "the commit fails EIO")
        t:assert_eq(#lcs.drain_events(w, fd), 0, "and emitted nothing")
        src.commit_status = nil
        t:assert_eq(lcs.commit(src, w, txn).ret, 0, "the retry succeeds")
        t:assert_eq(#lcs.drain_events(w, fd), 2, "and only then does the batch go out")
        lcs.notify(nil, w, fd, 0, false)
        sys.close(w, txn); sys.close(w, fd)
    end)

test("a failed commit does not wake poll waiters",
    { spec = "PKM *txn.commit.failed-commit-does-not-wake-poll-waiters" }, function(t)
        local fd = open_key(ROOT .. "\\Failure")
        local txn = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "P1", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
        src.commit_status = lcs.STATUS.TXN_BUSY
        for i = 1, 2 do
            t:assert_eq(lcs.commit(src, w, txn).errno, sys.E.BUSY, "failure " .. i)
            t:assert_eq(lcs.poll_revents(w, txn, 0), 0,
                "poll stays quiet after failure " .. i)
        end
        src.commit_status = nil
        t:assert_eq(lcs.commit(src, w, txn).ret, 0, "the eventual success")
        local revents = lcs.poll_revents(w, txn, 0)
        t:assert_eq(revents & 0x18, 0x18, "which does wake them")
        sys.close(w, txn); sys.close(w, fd)
    end)

test("the in-flight marker is cleared, so the caller may retry or close to abort",
    { spec = "PKM *txn.commit.in-flight-marker-cleared-so-retry-is-allowed" }, function(t)
        local fd = open_key(ROOT .. "\\Failure")
        local retry = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "Retried", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = retry })
        src.commit_status = lcs.STATUS.TXN_BUSY
        t:assert_eq(lcs.commit(src, w, retry).errno, sys.E.BUSY, "the first attempt fails")
        src.commit_status = nil
        t:assert_eq(lcs.commit(src, w, retry).ret, 0, "and a second is accepted")
        sys.close(w, retry)

        local closed = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "Closed", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = closed })
        src.commit_status = lcs.STATUS.TXN_BUSY
        t:assert_eq(lcs.commit(src, w, closed).errno, sys.E.BUSY, "this one fails too")
        src.commit_status = nil
        local aborts = src.aborts or 0
        sys.close(w, closed); src:pump(150)
        t:assert_eq((src.aborts or 0) - aborts, 1,
            "and closing the fd aborts it instead: nothing has been lost either way")
        t:assert_eq(lcs.query_value(src, w, fd, "Closed").errno, sys.E.NOENT,
            "the abandoned write is not there")
        sys.close(w, fd)
    end)

-- ---- timeout after dispatch ---------------------------------------------

test("a post-dispatch timeout keeps the log and leaves the request with the source",
    { spec = "PKM *txn.commit.post-dispatch-timeout-keeps-log-and-request" }, function(t)
        local fd = open_watched(t, ROOT .. "\\Late")
        set_param(t, "RequestTimeoutMs", 1000)
        src:intercept(lcs.OP.COMMIT_TXN, function() return lcs.HOLD end)
        local txn = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "Pending", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        lcs.drain_events(w, fd)
        local cm = lcs.commit(src, w, txn)
        t:assert_eq(cm.errno, ETIMEDOUT, "the caller receives ETIMEDOUT")
        t:assert_eq(lcs.txn_status(nil, w, txn).state, lcs.TXN.TIMED_OUT,
            "and the object becomes TIMED_OUT")
        t:assert_eq(#src:held_ids(), 1,
            "the request record stays in the source's in-flight table: the source " ..
            "may still answer")
        src:release(src:held_ids()[1])
        sys.nanosleep(vm, 1, 0)
        src:pump(150)
        t:assert_eq(#lcs.drain_events(w, fd), 1,
            "and the retained log was still there to produce the batch from")
        src:intercept(lcs.OP.COMMIT_TXN, nil)
        set_param(t, "RequestTimeoutMs", 30000)
        lcs.notify(nil, w, fd, 0, false)
        sys.close(w, txn); sys.close(w, fd)
    end)

test("ETIMEDOUT on a commit means may or may not have committed",
    { spec = "PKM *txn.commit.etimedout-is-indeterminate" }, function(t)
        local fd = open_key(ROOT .. "\\Late")
        set_param(t, "RequestTimeoutMs", 1000)
        src:intercept(lcs.OP.COMMIT_TXN, function() return lcs.HOLD end)

        -- The same ETIMEDOUT, two different outcomes.
        local committed = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "DidCommit", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = committed })
        t:assert_eq(lcs.commit(src, w, committed).errno, ETIMEDOUT, "ETIMEDOUT")
        src:release(src:held_ids()[1])
        sys.nanosleep(vm, 1, 0); src:pump(150)
        t:assert_eq(lcs.query_value(src, w, fd, "DidCommit").ret, 0,
            "this one did commit after all")
        sys.close(w, committed)

        local lost = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "DidNot", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = lost })
        t:assert_eq(lcs.commit(src, w, lost).errno, ETIMEDOUT, "the same ETIMEDOUT")
        src:release(src:held_ids()[1], lcs.STATUS.STORAGE_ERROR)
        sys.nanosleep(vm, 1, 0); src:pump(150)
        t:assert_eq(lcs.query_value(src, w, fd, "DidNot").errno, sys.E.NOENT,
            "and this one did not: the errno cannot tell a caller which happened")
        sys.close(w, lost)

        src:intercept(lcs.OP.COMMIT_TXN, nil)
        set_param(t, "RequestTimeoutMs", 30000)
        sys.close(w, fd)
    end)

test("a late RSI_OK applies the full set of kernel-side effects",
    { spec = "PKM *txn.commit.late-ok-applies-the-full-effects" }, function(t)
        local fd = open_watched(t, ROOT .. "\\Late")
        set_param(t, "RequestTimeoutMs", 1000)
        src:intercept(lcs.OP.COMMIT_TXN, function() return lcs.HOLD end)
        local before = generation(fd)
        local txn = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "LateOk", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
        lcs.drain_events(w, fd)
        t:assert_eq(lcs.commit(src, w, txn).errno, ETIMEDOUT, "the caller was told it timed out")
        t:assert_eq(#lcs.drain_events(w, fd), 0, "and nothing had gone out yet")

        src:release(src:held_ids()[1])
        sys.nanosleep(vm, 1, 0); src:pump(150)
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 1, "the same watch events an on-time commit would have " ..
            "produced go out: " .. lcs.event_summary(ev))
        t:assert_eq(ev[1].name, "LateOk", "naming the write")
        t:assert(generation(fd) > before, "and the same generation update was applied")
        t:assert_eq(lcs.query_value(src, w, fd, "LateOk").ret, 0, "the write is durable")
        src:intercept(lcs.OP.COMMIT_TXN, nil)
        set_param(t, "RequestTimeoutMs", 30000)
        lcs.notify(nil, w, fd, 0, false)
        sys.close(w, txn); sys.close(w, fd)
    end)

test("a late error releases the log with no effects",
    { spec = "PKM *txn.commit.late-error-releases-the-log-with-no-effects" }, function(t)
        local fd = open_watched(t, ROOT .. "\\Late")
        set_param(t, "RequestTimeoutMs", 1000)
        src:intercept(lcs.OP.COMMIT_TXN, function() return lcs.HOLD end)
        local before = generation(fd)
        local txn = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "LateError", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        lcs.drain_events(w, fd)
        t:assert_eq(lcs.commit(src, w, txn).errno, ETIMEDOUT, "ETIMEDOUT")
        src:release(src:held_ids()[1], lcs.STATUS.STORAGE_ERROR)
        sys.nanosleep(vm, 1, 0); src:pump(150)
        t:assert_eq(#lcs.drain_events(w, fd), 0, "no events followed the late error")
        t:assert_eq(generation(fd), before, "no generation update either")
        t:assert_eq(lcs.query_value(src, w, fd, "LateError").errno, sys.E.NOENT,
            "and nothing was applied")
        src:intercept(lcs.OP.COMMIT_TXN, nil)
        set_param(t, "RequestTimeoutMs", 30000)
        lcs.notify(nil, w, fd, 0, false)
        sys.close(w, txn); sys.close(w, fd)
    end)

test("a late success leaves the transaction TIMED_OUT, not COMMITTED",
    { spec = "PKM *txn.commit.late-success-leaves-the-state-timed-out" }, function(t)
        local fd = open_key(ROOT .. "\\Late")
        set_param(t, "RequestTimeoutMs", 1000)
        src:intercept(lcs.OP.COMMIT_TXN, function() return lcs.HOLD end)
        local txn = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "StateAfterLate", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        t:assert_eq(lcs.commit(src, w, txn).errno, ETIMEDOUT, "ETIMEDOUT")
        src:release(src:held_ids()[1])
        sys.nanosleep(vm, 1, 0); src:pump(150)
        t:assert_eq(lcs.query_value(src, w, fd, "StateAfterLate").ret, 0,
            "the writes are durable")
        local st = lcs.txn_status(nil, w, txn)
        t:assert_eq(st.state, lcs.TXN.TIMED_OUT,
            "but the state reflects what the caller was told, not what the source did")
        t:assert_eq(st.terminal_errno, ETIMEDOUT, "with a terminal_errno of ETIMEDOUT")
        src:intercept(lcs.OP.COMMIT_TXN, nil)
        set_param(t, "RequestTimeoutMs", 30000)
        sys.close(w, txn); sys.close(w, fd)
    end)

-- ---- when the watch events cannot be derived -----------------------------

test("events that cannot be derived become OVERFLOW, and the commit still succeeds",
    { spec = "PKM *txn.commit.underivable-events-become-overflow" }, function(t)
        -- Working out which keys a key deletion orphaned needs an
        -- RSI_LOOKUP that can only be made after the commit. Break that
        -- lookup from the moment the commit is served.
        local fd = open_watched(t, ROOT .. "\\Derive", true)
        local child = open_key(ROOT .. "\\Derive\\C1")
        lcs.drain_events(w, fd)
        src:intercept(lcs.OP.COMMIT_TXN, function(self)
            self:intercept(lcs.OP.LOOKUP,
                function() return lcs.STATUS.STORAGE_ERROR, "" end)
            return nil -- answer the commit honestly
        end)
        local txn = assert(lcs.begin_transaction(w))
        local d = lcs.delete_key(src, w, child, { txn_fd = txn })
        t:assert_eq(d.ret, 0, "dropping the child's last path entry: " ..
            sys.errname(d.errno or 0))
        local cm = lcs.commit(src, w, txn)
        src:intercept(lcs.OP.LOOKUP, nil)
        src:intercept(lcs.OP.COMMIT_TXN, nil)
        t:assert_eq(cm.ret, 0,
            "a successful commit is not reinterpreted as a failed one: " ..
            sys.errname(cm.errno or 0))
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 1, "and no partial set of events was emitted: " ..
            lcs.event_summary(ev))
        t:assert_eq(ev[1].type, lcs.WATCH.OVERFLOW,
            "OVERFLOW is delivered to the affected watcher instead")
        lcs.notify(nil, w, fd, 0, false)
        sys.close(w, txn); sys.close(w, child); sys.close(w, fd)
    end)

test("the carve-out covers the orphan lookup and the watch batch and nothing else",
    { spec = "PKM *txn.commit.carve-out-covers-only-orphan-lookup-and-watch-batch" },
    function(t)
        -- The two steps that query the source are the ones that may be
        -- answered with OVERFLOW; a failure in either does not fail the
        -- commit and does not mark the source Down.
        local fd = open_watched(t, ROOT .. "\\Derive", true)
        local child = open_key(ROOT .. "\\Derive\\C2")
        lcs.drain_events(w, fd)
        src:intercept(lcs.OP.COMMIT_TXN, function(self)
            self:intercept(lcs.OP.LOOKUP,
                function() return lcs.STATUS.STORAGE_ERROR, "" end)
            return nil
        end)
        local txn = assert(lcs.begin_transaction(w))
        lcs.delete_key(src, w, child, { txn_fd = txn })
        local cm = lcs.commit(src, w, txn)
        src:intercept(lcs.OP.LOOKUP, nil)
        src:intercept(lcs.OP.COMMIT_TXN, nil)
        t:assert_eq(cm.ret, 0, "the commit is reported as successful, which it was")
        t:assert_eq(#lcs.drain_events(w, fd), 1, "with OVERFLOW standing in for the batch")
        local still = lcs.query_value(src, w, fd, "D1")
        t:assert(still.ret == 0 or still.errno == sys.E.NOENT,
            "and the source was not marked Down: it still answers rather than " ..
            "returning EIO (" .. sys.errname(still.errno or 0) .. ")")
        lcs.notify(nil, w, fd, 0, false)
        sys.close(w, txn); sys.close(w, child); sys.close(w, fd)
    end)

test("overflow recovery is not undone by a late response",
    { spec = "PKM *txn.commit.overflow-recovery-is-not-undone-by-a-late-response" },
    function(t)
        local fd = open_watched(t, ROOT .. "\\Derive", true)
        local child = open_key(ROOT .. "\\Derive\\C3")
        set_param(t, "RequestTimeoutMs", 1000)
        lcs.drain_events(w, fd)
        src:intercept(lcs.OP.COMMIT_TXN, function() return lcs.HOLD end)
        local txn = assert(lcs.begin_transaction(w))
        lcs.delete_key(src, w, child, { txn_fd = txn })
        t:assert_eq(lcs.commit(src, w, txn).errno, ETIMEDOUT, "the commit timed out")

        -- The late answer arrives while the derivation cannot complete,
        -- so overflow recovery is chosen and the replay state released.
        src:intercept(lcs.OP.LOOKUP,
            function() return lcs.STATUS.STORAGE_ERROR, "" end)
        src:release(src:held_ids()[1])
        sys.nanosleep(vm, 1, 0); src:pump(150)
        src:intercept(lcs.OP.LOOKUP, nil)
        src:intercept(lcs.OP.COMMIT_TXN, nil)
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 1, "OVERFLOW recovery was chosen: " .. lcs.event_summary(ev))
        t:assert_eq(ev[1].type, lcs.WATCH.OVERFLOW, "OVERFLOW")

        -- Nothing resurrects the individual events afterwards.
        src:pump(200)
        sys.nanosleep(vm, 1, 0)
        src:pump(200)
        t:assert_eq(#lcs.drain_events(w, fd), 0,
            "and no individual events appear afterwards")
        set_param(t, "RequestTimeoutMs", 30000)
        lcs.notify(nil, w, fd, 0, false)
        sys.close(w, txn); sys.close(w, child); sys.close(w, fd)
    end)

test("a failure publishing the layer cache or recording the generation is EIO and " ..
     "marks the source Down",
    { spec = "PKM *txn.commit.cache-or-generation-failure-is-eio-and-marks-the-source-down",
      covered_by = "kunit:pkm_lcs_kunit_transaction",
      skip = "neither step is a source round trip, so no served source can " ..
             "make one fail: the generation record is kernel-side state " ..
             "and the layer publication is an in-memory table swap; runs " ..
             "under pkm_lcs_kunit_transaction_commit_generation_overflow_downs_source, " ..
             "which drives the counter to its ceiling so the record fails " ..
             "and asserts -EIO with the source marked Down" }, function(t) end)

-- ---- abort ---------------------------------------------------------------

test("aborting generates no events and releases the log",
    { spec = "PKM *txn.commit.abort-emits-no-events-and-releases-the-log" }, function(t)
        local fd = open_watched(t, ROOT .. "\\Abort")
        local txn = assert(lcs.begin_transaction(w))
        for _, n in ipairs({ "A1", "A2", "A3" }) do
            lcs.set_value(src, w, fd, n, lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
        end
        lcs.drain_events(w, fd)
        local before = generation(fd)
        sys.close(w, txn); src:pump(150)
        t:assert_eq(#lcs.drain_events(w, fd), 0, "aborting generates no events, ever")
        t:assert_eq(generation(fd), before, "and no generation update")
        for _, n in ipairs({ "A1", "A2", "A3" }) do
            t:assert_eq(lcs.query_value(src, w, fd, n).errno, sys.E.NOENT,
                n .. " was rolled back")
        end
        lcs.notify(nil, w, fd, 0, false)
        sys.close(w, fd)
    end)

test("the source is told to roll back with RSI_ABORT_TRANSACTION only when bound",
    { spec = "PKM *txn.commit.abort-sends-rsi-abort-when-bound" }, function(t)
        local fd = open_key(ROOT .. "\\Abort")
        local unbound = assert(lcs.begin_transaction(w))
        local mark = src:mark()
        sys.close(w, unbound); src:pump(150)
        t:assert_eq(#src:served(lcs.OP.ABORT_TXN, mark), 0,
            "an unbound transaction has no source to tell")

        local bound = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "Bound", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = bound })
        mark = src:mark()
        sys.close(w, bound); src:pump(150)
        local aborts = src:served(lcs.OP.ABORT_TXN, mark)
        t:assert_eq(#aborts, 1, "a bound one is told to roll back")
        t:assert(aborts[1] and #aborts[1].payload >= 8,
            "with the transaction id in the request")
        sys.close(w, fd)
    end)
