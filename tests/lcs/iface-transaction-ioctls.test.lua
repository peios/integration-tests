-- PKM §5.5.4 — Transaction ioctls: the two that act on a transaction
-- fd, why everything else on it is ENOTTY, and the two failure surfaces
-- the section names (commit on a committed or unbound transaction, and
-- REG_IOC_TXN_STATUS's single EFAULT).
--
-- The semantics of commit itself are §5.7.3; what is asserted here is
-- the ioctl surface.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")

local vm = provium:vm("v", "kernel-only"):boot()

local src, TEST = assert(lcs.machine(vm))
local w = vm:spawn_worker()

local function open_test(t)
    local r = lcs.open_key(src, w, -1, "Machine\\Software\\Test", lcs.KEY_ALL_ACCESS)
    t:assert(r.ret >= 0, "open Test: " .. sys.errname(r.errno or 0))
    return r.ret
end

-- Every key-fd ioctl number, with the direction and size §5.A gives it.
local KEY_IOCTLS = {
    { 0, lcs.IOC_DIR.WR, 64, "QUERY_VALUE" },
    { 1, lcs.IOC_DIR.W, 64, "SET_VALUE" },
    { 2, lcs.IOC_DIR.W, 40, "DELETE_VALUE" },
    { 3, lcs.IOC_DIR.W, 24, "BLANKET_TOMBSTONE" },
    { 4, lcs.IOC_DIR.WR, 24, "QUERY_VALUES_BATCH" },
    { 5, lcs.IOC_DIR.WR, 40, "ENUM_VALUES" },
    { 6, lcs.IOC_DIR.WR, 40, "ENUM_SUBKEYS" },
    { 7, lcs.IOC_DIR.WR, 64, "QUERY_KEY_INFO" },
    { 8, lcs.IOC_DIR.W, 24, "DELETE_KEY" },
    { 9, lcs.IOC_DIR.W, 24, "HIDE_KEY" },
    { 10, lcs.IOC_DIR.WR, 16, "GET_SECURITY" },
    { 11, lcs.IOC_DIR.W, 24, "SET_SECURITY" },
    { 12, lcs.IOC_DIR.W, 8, "NOTIFY" },
    { 13, lcs.IOC_DIR.NONE, 0, "FLUSH" },
    { 14, lcs.IOC_DIR.W, 4, "BACKUP" },
    { 15, lcs.IOC_DIR.W, 4, "RESTORE" },
}

test("two ioctls act on a transaction fd and everything else on it is ENOTTY",
    { spec = "PKM *txn-ioctl.only-two-others-are-enotty" }, function(t)
        local txn = assert(lcs.begin_transaction(w))
        -- The two that do exist reach their own argument handling
        -- rather than the dispatcher's default.
        local st = lcs.txn_status(nil, w, txn)
        t:assert_eq(st.ret, 0, "REG_IOC_TXN_STATUS is a transaction ioctl: " ..
            sys.errname(st.errno or 0))
        local cm = w:syscall(sys.NR.ioctl, { args = { txn, lcs.IOC.COMMIT, 0 } })
        t:assert(cm.errno ~= sys.E.NOTTY, "and so is REG_IOC_COMMIT")

        for _, e in ipairs(KEY_IOCTLS) do
            local r = w:syscall(sys.NR.ioctl, { args = { txn, lcs.ioc(e[2], e[1], e[3]), 0 } })
            t:assert_eq(r.errno, sys.E.NOTTY,
                "REG_IOC_" .. e[4] .. " is not a transaction ioctl: there are no savepoint " ..
                "or nesting operations to have")
        end
        local past = w:syscall(sys.NR.ioctl,
            { args = { txn, lcs.ioc(lcs.IOC_DIR.W, 18, 8), 0 } })
        t:assert_eq(past.errno, sys.E.NOTTY, "and neither is number 18")
        sys.close(w, txn)
    end)

test("REG_IOC_COMMIT is EINVAL on a transaction never bound to a source, and on a committed one",
    { spec = "PKM *txn-ioctl.commit.einval-when-committed-or-unbound" }, function(t)
        local unbound = assert(lcs.begin_transaction(w))
        local st = lcs.txn_status(nil, w, unbound)
        t:assert_eq(st.state, lcs.TXN.ACTIVE_UNBOUND, "the transaction never bound")
        local r = lcs.commit(nil, w, unbound)
        t:assert_eq(r.errno, sys.E.INVAL, "committing it is EINVAL")
        sys.close(w, unbound)

        local txn = assert(lcs.begin_transaction(w))
        local fd = open_test(t)
        local s = lcs.set_value(src, w, fd, "Committed", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        t:assert_eq(s.ret, 0, "a mutation binds it: " .. sys.errname(s.errno or 0))
        local first = lcs.commit(src, w, txn)
        t:assert_eq(first.ret, 0, "the commit succeeds: " .. sys.errname(first.errno or 0))
        local second = lcs.commit(nil, w, txn)
        t:assert_eq(second.errno, sys.E.INVAL, "and committing again is EINVAL")
        sys.close(w, txn)
        sys.close(w, fd)
    end)

test("REG_IOC_TXN_STATUS reads nothing from the caller and can fail only with EFAULT",
    { spec = "PKM *txn-ioctl.status.efault-is-the-only-failure" }, function(t)
        local txn = assert(lcs.begin_transaction(w))

        -- _IOR: the argument is output only, so garbage in it is fine.
        local garbage = lcs.raw_call(nil, w, {
            nr = sys.NR.ioctl, args = { txn, lcs.IOC.TXN_STATUS, 0 }, ptr_slot = 2,
            struct = string.rep("\xEE", 8),
        })
        t:assert_eq(garbage.ret, 0, "a pre-filled output structure is read by nobody: " ..
            sys.errname(garbage.errno or 0))
        local state, terminal = string.unpack("<I4i4", garbage.args_out)
        t:assert_eq(state, lcs.TXN.ACTIVE_UNBOUND, "the state is written over it")
        t:assert_eq(terminal, 0, "and so is terminal_errno")

        -- The one failure it has.
        local fault = w:syscall(sys.NR.ioctl, { args = { txn, lcs.IOC.TXN_STATUS, 0 } })
        t:assert_eq(fault.errno, sys.E.FAULT, "an unwritable output pointer is EFAULT")

        -- Every state it can be asked about answers, never fails.
        local fd = open_test(t)
        local s = lcs.set_value(src, w, fd, "Status", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        t:assert_eq(s.ret, 0, "bind: " .. sys.errname(s.errno or 0))
        local bound = lcs.txn_status(nil, w, txn)
        t:assert_eq(bound.ret, 0, "ACTIVE_BOUND reports")
        t:assert_eq(bound.state, lcs.TXN.ACTIVE_BOUND, "as ACTIVE_BOUND")
        t:assert_eq(bound.terminal_errno, 0, "with terminal_errno 0")
        t:assert_eq(lcs.commit(src, w, txn).ret, 0, "commit")
        local done = lcs.txn_status(nil, w, txn)
        t:assert_eq(done.ret, 0, "COMMITTED reports too, though the fd is otherwise finished")
        t:assert_eq(done.state, lcs.TXN.COMMITTED, "as COMMITTED")
        t:assert_eq(done.terminal_errno, 0, "with terminal_errno 0, not the EINVAL a further use gets")
        sys.close(w, txn)
        sys.close(w, fd)
    end)
