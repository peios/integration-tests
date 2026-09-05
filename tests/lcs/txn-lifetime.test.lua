-- PKM §5.7.1 — the scope and lifetime of a transaction: what
-- `reg_begin_transaction` does and does not do, what binds it, the six
-- states, the timeout, and the constraints that make it flat.
--
-- The source backs two hives so that the cross-hive rule can be shown
-- to be about the *hive*, not about the source. `TransactionTimeoutMs`
-- and `MaxBoundTransactionsPerSource` are hot-swapped by the cases that
-- need small values and put back afterwards.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")

local vm = provium:vm("v", "kernel-only"):boot()

local ROOT = "Machine\\Software\\Test"
local ETIMEDOUT = 110
local ENOTSUP = 95 -- EOPNOTSUPP

local src = lcs.source(vm, { hives = { { name = "Machine" }, { name = "Other" } } })
local other_root = src.hives[2].root
src:seed_param("TransactionTimeoutMs", 30000)          -- the compiled-in default
src:seed_param("MaxBoundTransactionsPerSource", 16)    -- the compiled-in default
src:key(ROOT)
src:key(ROOT .. "\\Binders")
src:key(ROOT .. "\\Reads")
src:key(ROOT .. "\\Atomic")
src:key(ROOT .. "\\States")
src:key(ROOT .. "\\Cap")
src:key(ROOT .. "\\Timeout")
src:key(ROOT .. "\\Down")
src:key("Other\\Thing", { root = other_root })
assert(src:register())
src:pump()

local w = vm:spawn_worker()

local function open_key(path, who)
    local r = lcs.open_key(src, who or w, -1, path, lcs.KEY_ALL_ACCESS)
    assert(r.ret >= 0, "opening " .. path .. ": " .. sys.errname(r.errno or 0))
    return r.ret
end

local root_fd = open_key(ROOT)
local params_fd = open_key(lcs.PARAMS_PATH)

local function state_of(txn)
    return lcs.txn_status(nil, w, txn).state
end

local function set_param(t, name, value)
    local s = lcs.set_value(src, w, params_fd, name, lcs.TYPE.DWORD, lcs.dword(value))
    t:assert_eq(s.ret, 0, "setting " .. name .. " to " .. value .. ": " ..
        sys.errname(s.errno or 0))
end

-- ---- what begin does --------------------------------------------------

test("reg_begin_transaction contacts no source",
    { spec = "PKM *txn.lifetime.begin-contacts-no-source" }, function(t)
        local mark = src:mark()
        local txn = assert(lcs.begin_transaction(w))
        t:assert(txn >= 0, "it takes no arguments and returns a transaction fd")
        src:pump(50)
        t:assert_eq(#src.log - mark + 1, 0,
            "no RSI request was sent: it allocates an id, makes an anonymous " ..
            "inode, starts the timer and returns")
        sys.close(w, txn)
    end)

test("a transaction begins in REG_TXN_ACTIVE_UNBOUND",
    { spec = "PKM *txn.lifetime.begins-active-unbound" }, function(t)
        local txn = assert(lcs.begin_transaction(w))
        local st = lcs.txn_status(nil, w, txn)
        t:assert_eq(st.ret, 0, "REG_IOC_TXN_STATUS: " .. sys.errname(st.errno or 0))
        t:assert_eq(st.state, lcs.TXN.ACTIVE_UNBOUND, "REG_TXN_ACTIVE_UNBOUND")
        t:assert_eq(st.state, 0, "which is 0")
        t:assert_eq(st.terminal_errno, 0, "and reports 0 while active")
        sys.close(w, txn)
    end)

test("operations grouped in a transaction commit together or not at all",
    { spec = "PKM *txn.lifetime.commit-together-or-not-at-all" }, function(t)
        local fd = open_key(ROOT .. "\\Atomic")
        local txn = assert(lcs.begin_transaction(w))
        for _, n in ipairs({ "One", "Two", "Three" }) do
            local s = lcs.set_value(src, w, fd, n, lcs.TYPE.DWORD, lcs.dword(1),
                { txn_fd = txn })
            t:assert_eq(s.ret, 0, "writing " .. n .. ": " .. sys.errname(s.errno or 0))
            local outside = lcs.query_value(src, w, fd, n)
            t:assert_eq(outside.errno, sys.E.NOENT, n .. " is not visible yet")
        end
        t:assert_eq(lcs.commit(src, w, txn).ret, 0, "commit")
        for _, n in ipairs({ "One", "Two", "Three" }) do
            t:assert_eq(lcs.query_value(src, w, fd, n).ret, 0, n .. " is visible now")
        end
        sys.close(w, txn)

        local abort = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "Never", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = abort })
        sys.close(w, abort); src:pump(50)
        t:assert_eq(lcs.query_value(src, w, fd, "Never").errno, sys.E.NOENT,
            "and an abandoned set commits nothing")
        sys.close(w, fd)
    end)

-- ---- binding ----------------------------------------------------------

test("a transaction binds to a source on its first mutating operation",
    { spec = "PKM *txn.lifetime.binds-on-first-mutating-operation" }, function(t)
        local fd = open_key(ROOT .. "\\Binders")
        local txn = assert(lcs.begin_transaction(w))
        t:assert_eq(state_of(txn), lcs.TXN.ACTIVE_UNBOUND, "unbound to start with")
        local s = lcs.set_value(src, w, fd, "First", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        t:assert_eq(s.ret, 0, "the first mutating operation: " .. sys.errname(s.errno or 0))
        t:assert_eq(state_of(txn), lcs.TXN.ACTIVE_BOUND, "REG_TXN_ACTIVE_BOUND")
        sys.close(w, txn); sys.close(w, fd); src:pump(50)
    end)

test("each of the seven mutating operations binds an unbound transaction",
    { spec = "PKM *txn.lifetime.the-seven-binding-operations" }, function(t)
        local function binds(name, fn)
            local txn = assert(lcs.begin_transaction(w))
            t:assert_eq(state_of(txn), lcs.TXN.ACTIVE_UNBOUND, name .. ": starts unbound")
            local r = fn(txn)
            t:assert(r == nil or r.ret >= 0, name .. ": accepted (" ..
                sys.errname(r and r.errno or 0) .. ")")
            t:assert_eq(state_of(txn), lcs.TXN.ACTIVE_BOUND, name .. " binds")
            sys.close(w, txn); src:pump(50)
        end
        local fd = open_key(ROOT .. "\\Binders")
        binds("writing a value", function(txn)
            return lcs.set_value(src, w, fd, "V", lcs.TYPE.DWORD, lcs.dword(1),
                { txn_fd = txn })
        end)
        lcs.set_value(src, w, fd, "Doomed", lcs.TYPE.DWORD, lcs.dword(1))
        binds("deleting a value entry", function(txn)
            return lcs.delete_value(src, w, fd, "Doomed", { txn_fd = txn })
        end)
        binds("setting a blanket tombstone", function(txn)
            return lcs.blanket_tombstone(src, w, fd, "base", true, { txn_fd = txn })
        end)
        binds("removing a blanket tombstone", function(txn)
            return lcs.blanket_tombstone(src, w, fd, "base", false, { txn_fd = txn })
        end)
        binds("creating a key", function(txn)
            local c = lcs.create_key(src, w, { parent_fd = fd, path = "Made", txn_fd = txn })
            if c.ret >= 0 then sys.close(w, c.ret) end
            return c
        end)
        binds("changing a Security Descriptor", function(txn)
            return lcs.set_security(src, w, fd, lcs.SI.DACL, lcs.permissive_sd(),
                { txn_fd = txn })
        end)

        local child = lcs.create_key(src, w, { parent_fd = fd, path = "Victim" })
        t:assert(child.ret >= 0, "a child to delete and hide: " ..
            sys.errname(child.errno or 0))
        binds("hiding a key", function(txn)
            return lcs.hide_key(src, w, child.ret, { layer = "base", txn_fd = txn })
        end)
        binds("deleting a key's path entry", function(txn)
            return lcs.delete_key(src, w, child.ret, { txn_fd = txn })
        end)
        sys.close(w, child.ret); sys.close(w, fd)
    end)

test("reads never bind, and an unbound read is sent with a transaction id of zero",
    { spec = "PKM *txn.lifetime.reads-never-bind" }, function(t)
        local fd = open_key(ROOT .. "\\Reads")
        lcs.set_value(src, w, fd, "Readable", lcs.TYPE.DWORD, lcs.dword(1))
        local txn = assert(lcs.begin_transaction(w))
        local reads = {
            { "query_value", function() return lcs.query_value(src, w, fd, "Readable",
                { txn_fd = txn }) end },
            { "query_values_batch", function() return lcs.query_values_batch(src, w, fd,
                { txn_fd = txn }) end },
            { "enum_values", function() return lcs.enum_values(src, w, fd, 0,
                { txn_fd = txn }) end },
            { "enum_subkeys", function() return lcs.enum_subkeys(src, w, fd, 0,
                { txn_fd = txn }) end },
        }
        for _, r in ipairs(reads) do
            r[2]()
            t:assert_eq(state_of(txn), lcs.TXN.ACTIVE_UNBOUND,
                r[1] .. " left the transaction unbound")
        end
        sys.close(w, txn); sys.close(w, fd)
    end)

test("a read passed an unbound transaction fd behaves as an ordinary read",
    { spec = "PKM *txn.lifetime.unbound-read-is-non-transactional" }, function(t)
        local fd = open_key(ROOT .. "\\Reads")
        lcs.set_value(src, w, fd, "Plain", lcs.TYPE.DWORD, lcs.dword(7))
        local txn = assert(lcs.begin_transaction(w))
        local mark = src:mark()
        local q = lcs.query_value(src, w, fd, "Plain", { txn_fd = txn })
        t:assert_eq(q.ret, 0, "the read succeeds: " .. sys.errname(q.errno or 0))
        t:assert_eq(q.data, lcs.dword(7), "with the committed value")
        local served = src:served(lcs.OP.QUERY_VALUES, mark)
        t:assert(#served >= 1, "the source was asked")
        t:assert_eq(served[1].txn, 0,
            "and the request carried a transaction id of zero")
        sys.close(w, txn); sys.close(w, fd)
    end)

test("a bound transaction still permits reads",
    { spec = "PKM *txn.lifetime.reads-are-permitted" }, function(t)
        local fd = open_key(ROOT .. "\\Reads")
        local txn = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "Written", lcs.TYPE.DWORD, lcs.dword(3), { txn_fd = txn })
        t:assert_eq(state_of(txn), lcs.TXN.ACTIVE_BOUND, "bound")
        local q = lcs.query_value(src, w, fd, "Written", { txn_fd = txn })
        t:assert_eq(q.ret, 0, "a transaction is not write-only: " ..
            sys.errname(q.errno or 0))
        t:assert_eq(q.data, lcs.dword(3), "which is what makes verify-then-write possible")
        sys.close(w, txn); sys.close(w, fd); src:pump(50)
    end)

test("a bound transaction rejects another hive with EXDEV, in the kernel",
    { spec = "PKM *txn.lifetime.cross-hive-operation-is-exdev-in-the-kernel" }, function(t)
        local fd = open_key(ROOT .. "\\Binders")
        local other = open_key("Other\\Thing")
        local txn = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "Bound", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
        local mark = src:mark()
        local x = lcs.set_value(nil, w, other, "Cross", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        t:assert_eq(x.errno, sys.E.XDEV, "EXDEV")
        src:pump(50)
        t:assert_eq(#src.log - mark + 1, 0,
            "and it failed before anything reached a source")
        sys.close(w, txn); sys.close(w, other); sys.close(w, fd); src:pump(50)
    end)

test("binding identity is the source and the hive root, so one source is not enough",
    { spec = "PKM *txn.lifetime.binding-identity-is-source-and-hive-root" }, function(t)
        -- Both hives are served by the same source. A transaction bound
        -- to `Machine` still refuses `Other`, so the identity carried on
        -- the transaction object is the pair, not the source alone.
        local fd = open_key(ROOT .. "\\Binders")
        local sibling = open_key(ROOT .. "\\Reads")
        local other = open_key("Other\\Thing")
        local txn = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "Bound", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
        local same_hive = lcs.set_value(src, w, sibling, "Sibling", lcs.TYPE.DWORD,
            lcs.dword(1), { txn_fd = txn })
        t:assert_eq(same_hive.ret, 0,
            "another key in the same hive is fine: " .. sys.errname(same_hive.errno or 0))
        local cross = lcs.set_value(nil, w, other, "Cross", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        t:assert_eq(cross.errno, sys.E.XDEV,
            "a different hive of the same source is not, so the hive root is part " ..
            "of the binding identity")
        sys.close(w, txn); sys.close(w, other); sys.close(w, sibling); sys.close(w, fd)
        src:pump(50)
    end)

test("a source that does not support transactions fails the binding operation ENOTSUP",
    { spec = "PKM *txn.lifetime.unsupported-source-binds-with-enotsup" }, function(t)
        local fd = open_key(ROOT .. "\\Binders")
        src.refuse_txn_mode = { [lcs.RSI_TXN_READ_WRITE] = true }
        local txn = assert(lcs.begin_transaction(w))
        t:assert(txn >= 0, "begin cannot fail for lack of support, because it picks no source")
        local mark = src:mark()
        local s = lcs.set_value(src, w, fd, "Nope", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        t:assert_eq(s.errno, ENOTSUP,
            "the failure surfaces on the operation that would have bound: ENOTSUP")
        t:assert(#src:served(lcs.OP.BEGIN_TXN, mark) >= 1,
            "and only after the source answered RSI_TXN_NOT_SUPPORTED on the attempt")
        src.refuse_txn_mode = nil
        sys.close(w, txn); sys.close(w, fd)
    end)

test("a failed bind leaves the transaction unbound and usable elsewhere",
    { spec = "PKM *txn.lifetime.failed-bind-leaves-the-transaction-unbound" }, function(t)
        local fd = open_key(ROOT .. "\\Binders")
        src.refuse_txn_mode = { [lcs.RSI_TXN_READ_WRITE] = true }
        local txn = assert(lcs.begin_transaction(w))
        local s = lcs.set_value(src, w, fd, "Nope", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        t:assert_eq(s.errno, ENOTSUP, "the bind failed")
        t:assert_eq(state_of(txn), lcs.TXN.ACTIVE_UNBOUND,
            "the transaction stays ACTIVE_UNBOUND with its binding untouched")
        src.refuse_txn_mode = nil
        local again = lcs.set_value(src, w, fd, "Yes", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        t:assert_eq(again.ret, 0, "and the caller can still use the fd: " ..
            sys.errname(again.errno or 0))
        t:assert_eq(state_of(txn), lcs.TXN.ACTIVE_BOUND, "binding when it can")
        sys.close(w, txn); sys.close(w, fd); src:pump(50)
    end)

-- ---- the states -------------------------------------------------------

test("the six transaction states and their terminal errnos",
    { spec = "PKM *txn.lifetime.the-six-transaction-states" }, function(t)
        t:assert_eq(lcs.TXN.ACTIVE_UNBOUND, 0, "REG_TXN_ACTIVE_UNBOUND is 0")
        t:assert_eq(lcs.TXN.ACTIVE_BOUND, 1, "REG_TXN_ACTIVE_BOUND is 1")
        t:assert_eq(lcs.TXN.COMMITTED, 2, "REG_TXN_COMMITTED is 2")
        t:assert_eq(lcs.TXN.ABORTED, 3, "REG_TXN_ABORTED is 3")
        t:assert_eq(lcs.TXN.TIMED_OUT, 4, "REG_TXN_TIMED_OUT is 4")
        t:assert_eq(lcs.TXN.SOURCE_DOWN, 5, "REG_TXN_SOURCE_DOWN is 5")

        local fd = open_key(ROOT .. "\\States")
        local txn = assert(lcs.begin_transaction(w))
        local st = lcs.txn_status(nil, w, txn)
        t:assert_eq(st.state, lcs.TXN.ACTIVE_UNBOUND, "unbound while active")
        t:assert_eq(st.terminal_errno, 0, "terminal_errno is 0 while active")
        lcs.set_value(src, w, fd, "A", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
        st = lcs.txn_status(nil, w, txn)
        t:assert_eq(st.state, lcs.TXN.ACTIVE_BOUND, "bound while active")
        t:assert_eq(st.terminal_errno, 0, "still 0")
        t:assert_eq(lcs.commit(src, w, txn).ret, 0, "commit")
        st = lcs.txn_status(nil, w, txn)
        t:assert_eq(st.state, lcs.TXN.COMMITTED, "COMMITTED")
        t:assert_eq(st.terminal_errno, 0, "reports 0 for COMMITTED")
        sys.close(w, txn)

        -- SOURCE_DOWN, from a bound transaction whose source goes away.
        local down = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "B", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = down })
        src:disconnect()
        st = lcs.txn_status(nil, w, down)
        t:assert_eq(st.state, lcs.TXN.SOURCE_DOWN, "REG_TXN_SOURCE_DOWN")
        t:assert_eq(st.terminal_errno, sys.E.IO, "with a terminal_errno of EIO")
        sys.close(w, down)
        assert(src:resume()); src:pump()
        sys.close(w, fd)
    end)

test("a committed transaction reports 0 but using its fd again returns EINVAL",
    { spec = "PKM *txn.lifetime.use-after-commit-is-einval" }, function(t)
        local fd = open_key(ROOT .. "\\States")
        local txn = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "C", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
        t:assert_eq(lcs.commit(src, w, txn).ret, 0, "commit")
        t:assert_eq(lcs.txn_status(nil, w, txn).terminal_errno, 0,
            "terminal_errno is 0 for COMMITTED")
        local use = lcs.set_value(nil, w, fd, "D", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        t:assert_eq(use.errno, sys.E.INVAL,
            "but it is not the errno a further operation returns: that is EINVAL")
        t:assert_eq(lcs.commit(nil, w, txn).errno, sys.E.INVAL,
            "a second REG_IOC_COMMIT is EINVAL too")
        sys.close(w, txn); sys.close(w, fd)
    end)

test("a terminal object stays addressable until the fd is closed",
    { spec = "PKM *txn.lifetime.terminal-object-stays-addressable-until-close" },
    function(t)
        local fd = open_key(ROOT .. "\\States")
        local txn = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "E", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
        t:assert_eq(lcs.commit(src, w, txn).ret, 0, "commit")
        for i = 1, 3 do
            local st = lcs.txn_status(nil, w, txn)
            t:assert_eq(st.ret, 0, "query " .. i .. " still answers: " ..
                sys.errname(st.errno or 0))
            t:assert_eq(st.state, lcs.TXN.COMMITTED, "with the terminal state")
        end
        t:assert_eq(sys.close(w, txn).ret, 0, "and close releases it")
        sys.close(w, fd)
    end)

test("close without committing aborts, telling the source to discard",
    { spec = "PKM *txn.lifetime.close-without-commit-aborts" }, function(t)
        local fd = open_key(ROOT .. "\\States")
        local txn = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "Discarded", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        local before = src.aborts or 0
        t:assert_eq(sys.close(w, txn).ret, 0, "close()")
        src:pump(100)
        t:assert_eq((src.aborts or 0) - before, 1,
            "RSI_ABORT_TRANSACTION reached the source")
        t:assert_eq(lcs.query_value(src, w, fd, "Discarded").errno, sys.E.NOENT,
            "and nothing the transaction wrote is visible")
        sys.close(w, fd)
    end)

test("process death closes the fd, which aborts: there are no orphaned transactions",
    { spec = "PKM *txn.lifetime.process-death-aborts-no-orphans" }, function(t)
        local w2 = vm:spawn_worker()
        local fd = open_key(ROOT .. "\\States", w2)
        local txn = assert(lcs.begin_transaction(w2))
        local s = lcs.set_value(src, w2, fd, "Orphan", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        t:assert_eq(s.ret, 0, "the other process bound a transaction: " ..
            sys.errname(s.errno or 0))
        local before = src.aborts or 0
        w2:kill(); w2:join()
        src:pump(200)
        t:assert_eq((src.aborts or 0) - before, 1,
            "the dead process's transaction was aborted at the source")
        t:assert_eq(lcs.query_value(src, w, root_fd, "Orphan").errno, sys.E.NOENT,
            "and left nothing behind")
    end)

test("a transaction fd is pollable and a terminal transition wakes it POLLERR|POLLHUP",
    { spec = "PKM *txn.lifetime.terminal-transition-wakes-poll-with-pollerr-pollhup" },
    function(t)
        local fd = open_key(ROOT .. "\\States")
        local txn = assert(lcs.begin_transaction(w))
        t:assert_eq(lcs.poll_revents(w, txn, 0), 0, "an active transaction is quiet")
        lcs.set_value(src, w, fd, "F", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
        t:assert_eq(lcs.poll_revents(w, txn, 0), 0, "still quiet once bound")
        t:assert_eq(lcs.commit(src, w, txn).ret, 0, "commit")
        local revents = lcs.poll_revents(w, txn, 0)
        t:assert_eq(revents & 0x08, 0x08, "POLLERR")
        t:assert_eq(revents & 0x10, 0x10, "POLLHUP")
        t:assert_eq(lcs.txn_status(nil, w, txn).state, lcs.TXN.COMMITTED,
            "and a caller that needs a race-free reason queries the status")
        sys.close(w, txn); sys.close(w, fd)
    end)

-- ---- constraints ------------------------------------------------------

test("transactions are flat: the transaction fd takes only COMMIT and TXN_STATUS",
    { spec = "PKM *txn.lifetime.transactions-are-flat" }, function(t)
        local txn = assert(lcs.begin_transaction(w))
        t:assert_eq(lcs.txn_status(nil, w, txn).ret, 0, "REG_IOC_TXN_STATUS is accepted")
        local rejected = {
            { "REG_IOC_QUERY_VALUE", function() return lcs.query_value(nil, w, txn, "X") end },
            { "REG_IOC_SET_VALUE", function() return lcs.set_value(nil, w, txn, "X",
                lcs.TYPE.DWORD, lcs.dword(1)) end },
            { "REG_IOC_QUERY_KEY_INFO", function() return lcs.query_key_info(nil, w, txn) end },
            { "REG_IOC_ENUM_SUBKEYS", function() return lcs.enum_subkeys(nil, w, txn, 0) end },
            { "REG_IOC_NOTIFY", function() return lcs.notify(nil, w, txn, lcs.NOTIFY.ALL,
                false) end },
            { "REG_IOC_FLUSH", function() return lcs.flush(nil, w, txn) end },
            { "REG_IOC_DELETE_KEY", function() return lcs.delete_key(nil, w, txn, {}) end },
        }
        for _, r in ipairs(rejected) do
            t:assert_eq(r[2]().errno, sys.E.NOTTY, r[1] .. " on a transaction fd is ENOTTY")
        end
        local fd = open_key(ROOT .. "\\States")
        lcs.set_value(src, w, fd, "Flat", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
        t:assert_eq(lcs.commit(src, w, txn).ret, 0, "REG_IOC_COMMIT is accepted")
        sys.close(w, txn); sys.close(w, fd)
    end)

test("a process may hold many transaction fds, each exactly one transaction",
    { spec = "PKM *txn.lifetime.one-transaction-per-fd" }, function(t)
        local fd = open_key(ROOT .. "\\States")
        local a = assert(lcs.begin_transaction(w))
        local b = assert(lcs.begin_transaction(w))
        t:assert(a ~= b, "two calls give two fds")
        lcs.set_value(src, w, fd, "A", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = a })
        t:assert_eq(state_of(a), lcs.TXN.ACTIVE_BOUND, "the first is bound")
        t:assert_eq(state_of(b), lcs.TXN.ACTIVE_UNBOUND,
            "and the second is a separate transaction, untouched by it")
        t:assert_eq(lcs.commit(src, w, a).ret, 0, "committing the first")
        t:assert_eq(state_of(a), lcs.TXN.COMMITTED, "moves only the first")
        t:assert_eq(state_of(b), lcs.TXN.ACTIVE_UNBOUND, "the second is still active")
        sys.close(w, a); sys.close(w, b); sys.close(w, fd)
    end)

test("an operation that would bind past MaxBoundTransactionsPerSource returns EBUSY " ..
     "before the source is contacted, leaving no entry behind",
    { spec = "PKM *txn.lifetime.bind-past-the-cap-returns-ebusy" }, function(t)
        local fd = open_key(ROOT .. "\\Cap")
        set_param(t, "MaxBoundTransactionsPerSource", 2)
        local held = {}
        for i = 1, 2 do
            local txn = assert(lcs.begin_transaction(w))
            local s = lcs.set_value(src, w, fd, "Held" .. i, lcs.TYPE.DWORD, lcs.dword(i),
                { txn_fd = txn })
            t:assert_eq(s.ret, 0, "bind " .. i .. " within the cap: " ..
                sys.errname(s.errno or 0))
            held[#held + 1] = txn
        end
        local over = assert(lcs.begin_transaction(w))
        local mark = src:mark()
        local s = lcs.set_value(src, w, fd, "Over", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = over })
        t:assert_eq(s.errno, sys.E.BUSY, "the third bind is EBUSY")
        t:assert_eq(state_of(over), lcs.TXN.ACTIVE_UNBOUND, "and it stayed unbound")
        t:assert_eq(#src:served(lcs.OP.BEGIN_TXN, mark), 0,
            "and no RSI_BEGIN_TRANSACTION was sent: the cap is tested before the " ..
            "source is contacted")
        for _, txn in ipairs(held) do sys.close(w, txn) end
        src:pump(50)
        sys.close(w, over)
        set_param(t, "MaxBoundTransactionsPerSource", 16)
        sys.close(w, fd)
    end)

test("the mutation-log entry allocated for a refused bind is freed on the way out",
    { spec = "PKM *txn.lifetime.cap-tested-after-log-entry-allocation" }, function(t)
        -- The allocation itself is kernel-internal (KUnit covers the
        -- ordering in pkm_lcs_kunit_transaction_bind_for_mutation_counter_cap).
        -- What a guest can see is the consequence: an operation refused
        -- by the cap leaves nothing in the log, so the transaction's
        -- later commit carries exactly the operations that were accepted.
        local fd = open_key(ROOT .. "\\Cap")
        set_param(t, "MaxBoundTransactionsPerSource", 1)
        local hog = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "Hog", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = hog })

        local mine = assert(lcs.begin_transaction(w))
        local refused = lcs.set_value(src, w, fd, "Refused", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = mine })
        t:assert_eq(refused.errno, sys.E.BUSY, "refused by the cap")
        sys.close(w, hog); src:pump(50)
        set_param(t, "MaxBoundTransactionsPerSource", 16)

        lcs.nonblock(w, fd)
        local n = lcs.notify(nil, w, fd, lcs.NOTIFY.ALL, false)
        t:assert_eq(n.ret, 0, "arming a watch to see what the commit produces")
        local ok = lcs.set_value(src, w, fd, "Accepted", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = mine })
        t:assert_eq(ok.ret, 0, "the same fd binds now: " .. sys.errname(ok.errno or 0))
        t:assert_eq(lcs.commit(src, w, mine).ret, 0, "commit")
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 1, "the batch is the accepted operation alone: " ..
            lcs.event_summary(ev))
        t:assert_eq(ev[1].name, "Accepted", "no entry survived from the refused attempt")
        t:assert_eq(lcs.query_value(src, w, fd, "Refused").errno, sys.E.NOENT,
            "and the refused write was never applied")
        lcs.notify(nil, w, fd, 0, false)
        sys.close(w, mine); sys.close(w, fd)
    end)

-- ---- the timeout ------------------------------------------------------
--
-- These hot-swap TransactionTimeoutMs down to its range minimum of one
-- second and put the default back before returning.

test("the lifetime timer starts when the fd is created, not at the first operation",
    { spec = "PKM *txn.lifetime.timer-starts-at-fd-creation" }, function(t)
        local fd = open_key(ROOT .. "\\Timeout")
        set_param(t, "TransactionTimeoutMs", 1000)
        local txn = assert(lcs.begin_transaction(w))
        sys.nanosleep(vm, 2, 0) -- longer than the timeout, with no operation at all
        local first = lcs.set_value(nil, w, fd, "TooLate", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        t:assert_eq(first.errno, ETIMEDOUT,
            "the very first operation is already too late: the timer ran from creation")
        t:assert_eq(state_of(txn), lcs.TXN.TIMED_OUT, "REG_TXN_TIMED_OUT")
        sys.close(w, txn)
        set_param(t, "TransactionTimeoutMs", 30000)
        sys.close(w, fd)
    end)

test("when the timer fires the object becomes TIMED_OUT and further use is ETIMEDOUT",
    { spec = "PKM *txn.lifetime.timeout-makes-further-use-etimedout" }, function(t)
        local fd = open_key(ROOT .. "\\Timeout")
        set_param(t, "TransactionTimeoutMs", 1000)
        local txn = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "Before", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
        sys.nanosleep(vm, 2, 0)
        src:pump(100)
        local st = lcs.txn_status(nil, w, txn)
        t:assert_eq(st.state, lcs.TXN.TIMED_OUT, "the object became TIMED_OUT")
        t:assert_eq(st.terminal_errno, ETIMEDOUT, "with a terminal_errno of ETIMEDOUT")
        local revents = lcs.poll_revents(w, txn, 0)
        t:assert_eq(revents & 0x18, 0x18, "poll waiters were woken POLLERR|POLLHUP")
        local use = lcs.set_value(nil, w, fd, "After", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        t:assert_eq(use.errno, ETIMEDOUT, "and further use of the fd returns ETIMEDOUT")
        t:assert_eq(lcs.commit(nil, w, txn).errno, ETIMEDOUT, "commit included")
        sys.close(w, txn)
        set_param(t, "TransactionTimeoutMs", 30000)
        sys.close(w, fd)
    end)

test("a timeout aborts a bound transaction at the source and leaves the fd in the table",
    { spec = "PKM *txn.lifetime.timeout-aborts-a-bound-transaction-at-the-source" },
    function(t)
        local fd = open_key(ROOT .. "\\Timeout")
        set_param(t, "TransactionTimeoutMs", 1000)
        local txn = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "Doomed", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
        local before = src.aborts or 0
        sys.nanosleep(vm, 2, 0)
        src:pump(200)
        t:assert_eq(state_of(txn), lcs.TXN.TIMED_OUT, "it timed out")
        t:assert_eq((src.aborts or 0) - before, 1,
            "RSI_ABORT_TRANSACTION was sent, because it was bound and no commit " ..
            "was in flight")
        t:assert_eq(lcs.query_value(src, w, fd, "Doomed").errno, sys.E.NOENT,
            "so the source discarded the writes")
        sys.close(w, txn)
        set_param(t, "TransactionTimeoutMs", 30000)
        sys.close(w, fd)
    end)

test("a timeout does not remove the fd from the caller's table",
    { spec = "PKM *txn.lifetime.timeout-leaves-the-fd-in-the-table" }, function(t)
        local fd = open_key(ROOT .. "\\Timeout")
        set_param(t, "TransactionTimeoutMs", 1000)
        local txn = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "Doomed", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
        sys.nanosleep(vm, 2, 0)
        src:pump(100)
        local st = lcs.txn_status(nil, w, txn)
        t:assert_eq(st.ret, 0, "the fd still addresses the object: " ..
            sys.errname(st.errno or 0))
        t:assert_eq(st.state, lcs.TXN.TIMED_OUT, "TIMED_OUT")
        t:assert_eq(sys.close(w, txn).ret, 0, "and close() still releases it normally")
        set_param(t, "TransactionTimeoutMs", 30000)
        sys.close(w, fd)
    end)

-- ---- the source going down before a bind ------------------------------

test("a binding operation against a Down source is EIO and leaves the transaction unbound",
    { spec = "PKM *txn.lifetime.source-down-before-bind-is-eio" }, function(t)
        local fd = open_key(ROOT .. "\\Down")
        src:disconnect()
        local txn = assert(lcs.begin_transaction(w))
        local s = lcs.set_value(nil, w, fd, "Down", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        t:assert_eq(s.errno, sys.E.IO, "the binding operation fails EIO")
        t:assert_eq(state_of(txn), lcs.TXN.ACTIVE_UNBOUND,
            "and the transaction likewise remains unbound")
        sys.close(w, txn)
        assert(src:resume()); src:pump()
        sys.close(w, fd)
    end)
