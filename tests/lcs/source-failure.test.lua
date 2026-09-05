-- §5.8.5, first half: what happens when a source dies — the slot, the
-- requests in flight, the key fds, the bound transactions and the
-- watches — plus the fd lifecycle at the end of the section.
--
-- Each case takes a source of its own: a Down slot keeps its hive
-- identities reserved, so a hive name is spent once a case has killed
-- the connection under it.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")

local vm = provium:vm("v", "kernel-only"):boot()

local POLLIN, POLLOUT, POLLERR, POLLHUP = 0x1, 0x4, 0x8, 0x10
-- prlimit64 and RLIMIT_NOFILE: not in helpers/sys, and only this file
-- needs them.
local NR_PRLIMIT64, RLIMIT_NOFILE, EMFILE = 302, 7, 24

local w = vm:spawn_worker()

--- A source backing one hive with `<hive>\K` seeded and a value on it.
local function hive_source(name)
    local s = lcs.source(vm, { hives = { { name = name } } })
    local key = s:key(name .. "\\K")
    s:value(key, "V", lcs.TYPE.DWORD, lcs.dword(7))
    assert(s:register(), "registering " .. name)
    s:pump()
    return s, key
end

local function poll(who, fd, events, timeout_ms)
    local r = who:syscall(sys.NR.poll, {
        args = { 0, 1, timeout_ms or 0 },
        bufs = { string.pack("<i4i2i2", fd, events, 0) }, ptrs = { 0 },
    })
    if r.ret < 0 then return nil, r.errno end
    return (select(3, string.unpack("<i4i2i2", r.out_bufs[1])))
end

--- Watch events queued on a key fd. read(2) on one blocks when the
--- queue is empty, so a case asserting that *nothing* was delivered
--- has to poll first.
local function queued_events(who, fd)
    local revents = poll(who, fd, POLLIN, 100)
    if not revents or revents & POLLIN == 0 then return {} end
    local e = lcs.read_events(nil, who, fd)
    return e.ret > 0 and e.events or {}
end

test("a source that dies leaves its slot Down and its hives unavailable",
    { spec = "PKM *source.failure.slot-marked-down-hives-unavailable" }, function(t)
        local src = hive_source("DiesDown")
        local up = lcs.open_key(src, w, -1, "DiesDown\\K", lcs.RIGHT.KEY_READ)
        t:assert(up.ret >= 0, "the hive serves while the connection lives")
        sys.close(w, up.ret)
        src:disconnect()
        local down = lcs.open_key(src, w, -1, "DiesDown\\K", lcs.RIGHT.KEY_READ)
        t:assert_eq(down.errno, sys.E.IO,
            "and afterwards the hive is unavailable: EIO")
    end)

test("every pending request fails EIO, including ones queued but never delivered",
    { spec = "PKM *source.failure.pending-requests-fail-eio" }, function(t)
        local src = hive_source("PendingEio")
        local delivered, queued = vm:spawn_worker(), vm:spawn_worker()
        -- One request read by the source and held unanswered, and one
        -- still sitting in the queue, never read.
        src:intercept(lcs.OP.LOOKUP, function() return lcs.HOLD end)
        local held = lcs.open_key_async(delivered, -1, "PendingEio\\K", lcs.RIGHT.KEY_READ)
        for _ = 1, 40 do
            if #src:held_ids() >= 1 then break end
            src:pump(50)
        end
        t:assert_eq(#src:held_ids(), 1, "one request delivered and unanswered")
        local never_read = lcs.open_key_async(queued, -1, "PendingEio\\K", lcs.RIGHT.KEY_READ)
        -- Deliberately not pumped: it is queued and undelivered.
        src:disconnect()
        t:assert_eq(held:await().errno, sys.E.IO, "the delivered request fails EIO")
        t:assert_eq(never_read:await().errno, sys.E.IO,
            "and so does the one that was only ever queued")
        delivered:kill(); delivered:join(); queued:kill(); queued:join()
    end)

test("open key fds stay valid across the outage, and round trips return EIO until the source returns",
    { spec = "PKM *source.failure.key-fds-stay-valid-round-trips-eio" }, function(t)
        local src = hive_source("FdsStayValid")
        local r = lcs.open_key(src, w, -1, "FdsStayValid\\K", lcs.KEY_ALL_ACCESS)
        t:assert(r.ret >= 0, "open a key")
        local fd = r.ret
        src:disconnect()
        t:assert_eq(lcs.query_value(src, w, fd, "V").errno, sys.E.IO,
            "an operation needing a round trip returns EIO")
        t:assert_eq(sys.close(w, fd).ret, 0, "the descriptor itself is still a valid fd")

        -- And a fresh one taken before the outage works again when the
        -- source comes back: the fd held a GUID and a granted mask,
        -- neither of which depended on the source.
        t:assert(src:register(), "the source comes back")
        src:pump()
        local again = lcs.open_key(src, w, -1, "FdsStayValid\\K", lcs.KEY_ALL_ACCESS)
        t:assert_eq(lcs.query_value(src, w, again.ret, "V").ret, 0, "and round trips work")
        sys.close(w, again.ret)
    end)

test("bound transactions enter REG_TXN_SOURCE_DOWN, wake their poll waiters, and refuse further use",
    { spec = "PKM *source.failure.bound-transactions-enter-source-down" }, function(t)
        local src = hive_source("TxnSourceDown")
        local txn = assert(lcs.begin_transaction(w))
        local r = lcs.create_key(src, w, { parent_fd = -1, path = "TxnSourceDown\\K\\Sub",
            access = lcs.KEY_ALL_ACCESS, txn_fd = txn })
        t:assert(r.ret >= 0, "a transaction bound to the source: " .. sys.errname(r.errno or 0))
        t:assert_eq(lcs.txn_status(nil, w, txn).state, lcs.TXN.ACTIVE_BOUND, "ACTIVE_BOUND")

        src:disconnect()
        local st = lcs.txn_status(nil, w, txn)
        t:assert_eq(st.state, lcs.TXN.SOURCE_DOWN, "the transaction enters REG_TXN_SOURCE_DOWN")
        local revents = poll(w, txn, POLLIN | POLLOUT | POLLERR | POLLHUP, 50)
        t:assert(revents & (POLLERR | POLLHUP) ~= 0,
            "its poll waiters are woken with POLLERR | POLLHUP")
        t:assert_eq(lcs.commit(src, w, txn).errno, sys.E.IO, "and further use of the fd is EIO")
        sys.close(w, r.ret)
        sys.close(w, txn)
    end)

test("watches stay armed across the outage, deliver nothing during it, and OVERFLOW on re-registration",
    { spec = "PKM *source.failure.watches-stay-armed" }, function(t)
        local src = hive_source("WatchesArmed")
        local r = lcs.open_key(src, w, -1, "WatchesArmed\\K", lcs.KEY_ALL_ACCESS)
        t:assert(r.ret >= 0, "open the watched key")
        local fd = r.ret
        t:assert_eq(lcs.notify(nil, w, fd, lcs.NOTIFY.ALL, false).ret, 0, "arm a watch")

        src:disconnect()
        t:assert_eq(#queued_events(w, fd), 0,
            "nothing is delivered while the source is away")

        t:assert(src:register(), "the source comes back")
        src:pump()
        local after = queued_events(w, fd)
        t:assert(#after > 0, "and the watch was still armed to receive")
        t:assert_eq(after[1].type, lcs.WATCH.OVERFLOW,
            "OVERFLOW, delivered on re-registration rather than on the disconnect")
        sys.close(w, fd)
    end)

test("process exit releases key fds and aborts transactions through ordinary kernel cleanup",
    { spec = "PKM *source.failure.process-exit-releases-fds" }, function(t)
        local src = hive_source("ProcessExit")
        local owner = vm:spawn_worker()
        local txn = assert(lcs.begin_transaction(owner))
        local r = lcs.create_key(src, owner, { parent_fd = -1, path = "ProcessExit\\K\\Sub",
            access = lcs.KEY_ALL_ACCESS, txn_fd = txn })
        t:assert(r.ret >= 0, "bind a transaction and hold a key fd in another process")
        local mark = src:mark()

        owner:kill(); owner:join()
        src:pump(200)
        t:assert(#src:served(lcs.OP.ABORT_TXN, mark) >= 1,
            "the transaction the exiting process left open was aborted")
    end)

test("key and transaction fds are ordinary descriptors bounded by RLIMIT_NOFILE, with no accounting of their own",
    { spec = "PKM *source.failure.no-registry-specific-fd-accounting" }, function(t)
        local src = hive_source("NoFdAccounting")
        local limited = vm:spawn_worker()
        -- Lower RLIMIT_NOFILE and watch key fds run into it: what stops
        -- them is the process's descriptor limit, not anything the
        -- registry counts.
        local LIMIT = 24
        local set = limited:syscall(NR_PRLIMIT64, {
            args = { 0, RLIMIT_NOFILE, 0, 0 },
            bufs = { string.pack("<I8I8", LIMIT, LIMIT) }, ptrs = { 2 },
        })
        t:assert_eq(set.ret, 0, "lower the descriptor limit: " .. sys.errname(set.errno or 0))

        local fds, refusal = {}, nil
        for _ = 1, LIMIT + 8 do
            local r = lcs.open_key(src, limited, -1, "NoFdAccounting\\K", lcs.RIGHT.KEY_READ)
            if r.ret < 0 then refusal = r.errno; break end
            fds[#fds + 1] = r.ret
        end
        t:assert(refusal, "opening key fds eventually fails")
        t:assert_eq(refusal, EMFILE,
            "with EMFILE from RLIMIT_NOFILE, not a registry-specific limit")
        t:assert(#fds < LIMIT + 8,
            "and it stopped at the descriptor limit (" .. #fds .. " opened)")
        for _, fd in ipairs(fds) do sys.close(limited, fd) end
        local again = lcs.open_key(src, limited, -1, "NoFdAccounting\\K", lcs.RIGHT.KEY_READ)
        t:assert(again.ret >= 0,
            "closing them makes room again, with nothing else reclaimed: " ..
            sys.errname(again.errno or 0))
        sys.close(limited, again.ret)
        limited:kill(); limited:join()
    end)
