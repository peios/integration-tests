-- loregd §4.4 — Waiting and Contention: the busy timeout, waiting for the
-- write connection, the volatile store's table locks, and abandoned
-- transactions.
--
-- Driven against a real loregd serving PtState. The dynamics here are
-- structural, not timing luck: a hive's write handle has MaxOpenConns=1,
-- so a second writer *cannot* proceed while a bound transaction holds that
-- one connection — it is blocked until the transaction releases it,
-- whatever the schedule. The volatile store runs in shared-cache mode with
-- journal_mode=memory and no MVCC, so a transaction that has written a
-- volatile table holds a table lock that blocks other connections' reads.
-- Each case holds the contended state for a bounded window (well under the
-- 25s busy_timeout and the kernel's 30s request timeout), proves the
-- waiter is still blocked, then releases it and shows it completes — so no
-- case depends on a race being won.

local loregd = require("helpers.loregd")
local lcs = require("helpers.lcs")
local sys = require("helpers.sys")

local KEY = loregd.KEY -- PtState\Durable

local vm = loregd.boot({ name = "loregd-contend" })
loregd.format(vm)
loregd.mount(vm)
loregd.start(vm)

loregd.new_key(vm, KEY):assert_ok()

local W = vm:spawn_worker()

local function open(t, who, path)
    local r = lcs.open_key(nil, who, -1, path, lcs.KEY_ALL_ACCESS, 0)
    t:assert(r.ret >= 0, "open " .. path .. ": ret=" .. tostring(r.ret) ..
        " errno=" .. sys.errname(r.errno or 0))
    return r.ret
end

-- A committed volatile key whose value a transaction can write to take the
-- volatile write-table lock, and a committed persistent value an ordinary
-- read can ask for.
loregd.set(vm, KEY, "Probe", "dword:1"):assert_ok()
do
    local vk = lcs.create_key(nil, W, { path = KEY .. "\\VolLock",
        flags = lcs.OPTION_VOLATILE, access = lcs.KEY_ALL_ACCESS })
    assert(vk.ret >= 0, "seed volatile key VolLock: ret=" .. tostring(vk.ret) ..
        " errno=" .. sys.errname(vk.errno or 0))
    sys.close(W, vk.ret)
end

-- ---- Waiting for the write connection ---------------------------------

-- "When a read-write transaction binds, it holds that connection until it
-- commits or aborts, so any other write to the same hive waits — and it
-- waits inside Go's connection pool, before SQLite is ever reached.
-- busy_timeout is not consulted, because there is no SQLite lock in
-- contention; the second writer simply has no connection to run on."
test("a bound transaction holds the write connection until it commits, and a " ..
     "second writer waits in the pool — no SQLite lock, no busy_timeout, no deadline",
    { spec = "loregd *contend.a-bound-transaction-holds-the-write-connection-until-it-commits-or-aborts " ..
             "*contend.a-second-writer-waits-in-the-connection-pool-unbounded-by-busy-timeout " ..
             "*contend.the-busy-timeout-bounds-only-sqlite-write-lock-contention " ..
             "*contend.no-database-operation-carries-a-deadline" }, function(t)
        loregd.set(vm, KEY, "Contended", "dword:0"):assert_ok()

        local A = vm:spawn_worker()
        local B = vm:spawn_worker()
        local fa = open(t, A, KEY)
        local fb = open(t, B, KEY)

        -- A binds the single write connection with a real mutating op.
        local txn = lcs.begin_transaction(A)
        local wa = lcs.set_value(nil, A, fa, "Contended", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        t:assert_eq(wa.ret, 0, "A's write binds the transaction: errno=" ..
            sys.errname(wa.errno or 0))

        -- B's non-transactional write has nowhere to run: it blocks in the
        -- connection pool, before SQLite, so busy_timeout (a SQLite pragma)
        -- never applies and nothing carries a deadline to abort the wait.
        local nr, spec, decode = lcs.build.set_value(fb, "Contended",
            lcs.TYPE.DWORD, lcs.dword(2))
        local pending = B:syscall_async(nr, spec)

        sys.nanosleep(vm, 2, 0)
        local _, mid = loregd.get(vm, KEY, "Contended")
        t:assert_eq(mid, "0",
            "after 2s the committed value is still 0: B is parked waiting for the " ..
            "write connection, not timed out by busy_timeout or any deadline")

        -- A commits, releasing the connection; B then gets it and runs.
        t:assert_eq(lcs.commit(nil, A, txn).ret, 0, "A commits and releases the connection")
        local wb = decode(pending:await())
        t:assert_eq(wb.ret, 0, "B's write completes once the connection is free: errno=" ..
            sys.errname(wb.errno or 0))
        local _, fin = loregd.get(vm, KEY, "Contended")
        t:assert_eq(fin, "2", "and lands, so the wait ended only when A released")

        sys.close(A, txn); sys.close(A, fa); sys.close(B, fb)
        A:kill(); A:join(); B:kill(); B:join()
    end)

-- "RSI_FLUSH is the one operation that refuses to join this queue. It
-- checks whether any transaction is bound to the hive and returns
-- RSI_TXN_BUSY immediately if one is."
test("FLUSH returns RSI_TXN_BUSY rather than queueing behind a bound transaction",
    { spec = "loregd *contend.flush-returns-rsi-txn-busy-rather-than-queueing-behind-a-transaction" },
    function(t)
        local A = vm:spawn_worker()
        local B = vm:spawn_worker()
        local fa = open(t, A, KEY)
        local fb = open(t, B, KEY)

        local txn = lcs.begin_transaction(A)
        local wa = lcs.set_value(nil, A, fa, "FlushGuard", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        t:assert_eq(wa.ret, 0, "A binds the transaction to the hive")

        local busy = lcs.flush(nil, B, fb)
        t:assert(busy.ret ~= 0, "the flush does not succeed while a transaction is bound")
        t:assert_eq(busy.errno, sys.E.BUSY,
            "it is refused immediately with RSI_TXN_BUSY (EBUSY), not queued: errno=" ..
            sys.errname(busy.errno or 0))

        -- Once the transaction is gone the very same flush proceeds.
        t:assert_eq(lcs.commit(nil, A, txn).ret, 0, "A commits")
        local ok = lcs.flush(nil, B, fb)
        t:assert_eq(ok.ret, 0, "and the flush now checkpoints: errno=" ..
            sys.errname(ok.errno or 0))

        sys.close(A, txn); sys.close(A, fa); sys.close(B, fb)
        A:kill(); A:join(); B:kill(); B:join()
    end)

-- "RSI_DELETE_LAYER, a non-transactional RSI_DROP_KEY, and the
-- conditional-write path of a non-transactional RSI_SET_VALUE all take the
-- write connection without that guard, and queue behind a bound
-- transaction." Shown via RSI_DROP_KEY (`reg del`), which shares the write
-- path with the other two: it waits for the connection rather than being
-- refused RSI_TXN_BUSY the way FLUSH is.
test("DROP_KEY queues behind a bound transaction (waits) rather than declining",
    { spec = "loregd *contend.delete-layer-drop-key-and-conditional-set-value-queue-behind-a-bound-transaction" },
    function(t)
        loregd.new_key(vm, KEY .. "\\DropMe"):assert_ok()

        local A = vm:spawn_worker()
        local fa = open(t, A, KEY)
        local txn = lcs.begin_transaction(A)
        local wa = lcs.set_value(nil, A, fa, "DropGuard", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        t:assert_eq(wa.ret, 0, "A binds and holds the write connection")

        -- `reg del` issues a non-transactional RSI_DROP_KEY, a write: it has
        -- no FLUSH-style guard, so it blocks on the held connection.
        local del = vm:run_async("reg del '" .. KEY .. "\\DropMe'")
        sys.nanosleep(vm, 2, 0)
        t:assert(not loregd.exited(vm, del:pid()),
            "after 2s the delete is still running: it queued behind the transaction " ..
            "rather than returning RSI_TXN_BUSY")

        -- Release; the queued delete then completes.
        t:assert_eq(lcs.commit(nil, A, txn).ret, 0, "A commits and frees the connection")
        local r = del:wait("10s")
        t:assert_eq(r.exit_code, 0, "the delete proceeds once the connection is free: " ..
            "stderr=" .. tostring(r.stderr))
        local gone = vm:run("reg ls '" .. KEY .. "\\DropMe'")
        t:assert(gone.exit_code ~= 0, "and the key is gone")

        sys.close(A, txn); sys.close(A, fa)
        A:kill(); A:join()
    end)

-- ---- Waiting on the volatile store ------------------------------------

-- "It therefore has no multi-version concurrency: readers and writers
-- contend for table locks rather than passing each other. A transaction
-- that has written any volatile.* table holds a write-table lock on it for
-- the transaction's whole lifetime. A volatile read on any other
-- connection waits for that lock … So while a transaction that has touched
-- volatile data is open, ordinary reads against the same hive block in
-- their serving goroutine rather than returning a status."
test("an open volatile-writing transaction blocks ordinary reads in their goroutine, " ..
     "unbounded, for the whole transaction lifetime (the volatile store has no MVCC)",
    { spec = "loregd *contend.the-volatile-store-has-no-multi-version-concurrency " ..
             "*contend.a-volatile-write-holds-a-table-lock-for-the-transactions-lifetime " ..
             "*contend.a-volatile-read-waits-unbounded-for-a-volatile-write-lock " ..
             "*contend.an-open-volatile-writing-transaction-blocks-ordinary-reads-in-their-goroutine" },
    function(t)
        local A = vm:spawn_worker()
        local vf = open(t, A, KEY .. "\\VolLock")
        local txn = lcs.begin_transaction(A)
        -- A write to a volatile.* table: takes the volatile write-table lock
        -- and holds it for the transaction's lifetime.
        local wa = lcs.set_value(nil, A, vf, "L", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        t:assert_eq(wa.ret, 0, "A writes a volatile value and takes the table lock: errno=" ..
            sys.errname(wa.errno or 0))

        -- An ordinary read of an unrelated *persistent* value still queries
        -- volatile in the same UNION ALL, so it blocks on the volatile lock.
        local rd = vm:run_async("reg get '" .. KEY .. "' Probe")
        sys.nanosleep(vm, 2, 0)
        t:assert(not loregd.exited(vm, rd:pid()),
            "after 2s the ordinary read is still blocked in loregd's goroutine — it " ..
            "waits for the volatile write-table lock, not returning a status")

        -- The lock is released only when the transaction ends; then the read
        -- returns, proving the wait lasted the transaction's lifetime.
        sys.close(A, txn) -- abort, releasing the volatile lock
        local r = rd:wait("10s")
        t:assert_eq(r.exit_code, 0, "the read completes once the transaction released " ..
            "the lock: stderr=" .. tostring(r.stderr))
        t:assert_eq((r.stdout:gsub("%s+$", "")), "1", "with the committed value")

        sys.close(A, vf)
        A:kill(); A:join()
    end)

-- "Contention confined to the persistent side behaves as WAL promises: a
-- transaction writing only the hive database does not block reads of it."
test("a transaction writing only the hive database does not block reads of it",
    { spec = "loregd *contend.a-write-to-the-hive-database-does-not-block-reads-of-it" },
    function(t)
        loregd.set(vm, KEY, "WalRead", "dword:9"):assert_ok()

        local A = vm:spawn_worker()
        local fa = open(t, A, KEY)
        local txn = lcs.begin_transaction(A)
        -- A persistent-only write: holds the write connection but takes no
        -- volatile lock, so WAL readers pass it freely.
        local wa = lcs.set_value(nil, A, fa, "WalWrite", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        t:assert_eq(wa.ret, 0, "A binds with a persistent-only write")

        local rd = vm:run_async("reg get '" .. KEY .. "' WalRead")
        sys.nanosleep(vm, 1, 0)
        t:assert(loregd.exited(vm, rd:pid()),
            "the read of the hive database completed while the write is still open — " ..
            "WAL readers are not blocked by a persistent writer")
        local r = rd:wait("5s")
        t:assert_eq(r.exit_code, 0, "and succeeded: stderr=" .. tostring(r.stderr))
        t:assert_eq((r.stdout:gsub("%s+$", "")), "9", "returning the committed value")

        sys.close(A, txn); sys.close(A, fa)
        A:kill(); A:join()
    end)

-- ---- Abandoned transactions -------------------------------------------

-- "Nothing reclaims a transaction that is never committed or aborted.
-- There is no timeout, and no sweep at any point in the daemon's life.
-- Such a transaction holds its hive's write connection … until the process
-- exits."
test("nothing reclaims an abandoned transaction: it keeps holding its write connection",
    { spec = "loregd *contend.nothing-reclaims-an-abandoned-transaction " ..
             "*contend.an-abandoned-transaction-holds-its-connection-and-locks-until-the-process-exits" },
    function(t)
        loregd.new_key(vm, KEY .. "\\Blocked"):assert_ok()

        local A = vm:spawn_worker()
        local fa = open(t, A, KEY)
        local txn = lcs.begin_transaction(A)
        local wa = lcs.set_value(nil, A, fa, "Held", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        t:assert_eq(wa.ret, 0, "A binds and holds the write connection")

        -- Leave it neither committed nor aborted. A second writer that
        -- arrives stays blocked across the whole window: loregd runs no
        -- reaper and no sweep, so the abandoned transaction keeps the
        -- connection.
        local other = vm:run_async("reg del '" .. KEY .. "\\Blocked'")
        sys.nanosleep(vm, 3, 0)
        t:assert(not loregd.exited(vm, other:pid()),
            "after 3s the second writer is still blocked: the abandoned transaction " ..
            "still holds the connection — nothing reclaimed it")
        t:assert_eq(lcs.txn_status(nil, A, txn).state, lcs.TXN.ACTIVE_BOUND,
            "and the transaction is still ACTIVE_BOUND")

        -- Only an explicit release frees it (a real abandon would hold until
        -- the process exits; here we release so the file's daemon is not
        -- left wedged for nothing).
        sys.close(A, txn)
        local r = other:wait("10s")
        t:assert_eq(r.exit_code, 0, "releasing it finally lets the second writer through")

        sys.close(A, fa)
        A:kill(); A:join()
    end)

-- ---- Homed on a loregd unit test (guest route closed) -----------------

-- The 25s busy_timeout is a compiled-in constant (hivedb.BusyTimeoutMs),
-- not surfaced to a guest; the 30s bound is the kernel's RequestTimeoutMs
-- default. TestBusyTimeout opens a hive and asserts PRAGMA busy_timeout ==
-- BusyTimeoutMs (25000). (Run green.)
test("the busy timeout is shorter than the kernel's request timeout",
    { spec = "loregd *contend.the-busy-timeout-is-shorter-than-the-kernels-request-timeout",
      skip = "the 25s busy_timeout is a compiled-in SQLite pragma constant not " ..
             "observable from a guest; the 30s request timeout is the kernel's",
      covered_by = "go:loregd internal/hivedb::TestBusyTimeout" },
    function() end)

-- ---- Coverage gaps (unreachable from a guest AND no loregd unit test) --
--
-- These are documented limitations or internal lock-domain distinctions
-- that a PtState guest cannot observe deterministically, and no existing
-- loregd Go test asserts them. Flagged for the coordinator to ticket a
-- unit test rather than cite one that does not prove the anchor.

-- The check is a TOCTOU window between hiveBusy() and the checkpoint. A
-- guest cannot hit the window deterministically without losing
-- determinism, and no unit test drives the race.
-- PEI-TBD-loregd-flush-check-racy-untested
test("the flush bound-transaction check is racy",
    { spec = "loregd *contend.the-flush-bound-transaction-check-is-racy",
      skip = "a race window (hiveBusy() then checkpoint) with no stable guest-visible " ..
             "outcome and no unit test — PEI-TBD-loregd-flush-check-racy-untested" },
    function() end)

-- Requires a long-lived read-only snapshot (a REG_IOC_BACKUP in progress)
-- concurrent with a flush; a guest backup is a single ioctl that cannot be
-- held mid-snapshot, and no unit test asserts hiveBusy's read-only-agnostic
-- behaviour (it returns true for any bound conn, snapshot or write).
-- PEI-TBD-loregd-flush-readonly-snapshot-untested
test("flush does not distinguish a read-only snapshot from a write binding",
    { spec = "loregd *contend.flush-does-not-distinguish-a-read-only-snapshot-from-a-write-binding",
      skip = "needs a REG_IOC_BACKUP snapshot held open during a flush, not " ..
             "deterministically reachable from a guest, and no unit test asserts it " ..
             "— PEI-TBD-loregd-flush-readonly-snapshot-untested" },
    function() end)

-- Read-only snapshots serve REG_IOC_BACKUP and are the kernel's own; the
-- symmetric volatile read-lock they hold is internal, and no unit test
-- asserts it.
-- PEI-TBD-loregd-readonly-snapshot-volatile-lock-untested
test("a read-only snapshot holds a volatile read-table lock for its lifetime",
    { spec = "loregd *contend.a-read-only-snapshot-holds-a-volatile-read-table-lock-for-its-lifetime",
      skip = "read-only snapshots are the kernel's own (REG_IOC_BACKUP); the volatile " ..
             "read-lock is internal and no unit test asserts it — " ..
             "PEI-TBD-loregd-readonly-snapshot-volatile-lock-untested" },
    function() end)

-- Every guest read UNION-queries main and volatile (§5.1), so during a
-- volatile write every guest read blocks (see the volatile-contention case
-- above); the persistent-side-only "does not block a hive-database read"
-- distinction cannot be isolated by a guest, and no unit test isolates the
-- lock domains.
-- PEI-TBD-loregd-volatile-only-write-hive-read-untested
test("a volatile-only write does not block reads of the hive database",
    { spec = "loregd *contend.a-volatile-only-write-does-not-block-reads-of-the-hive-database",
      skip = "no guest read touches only the hive database (all read ops UNION main " ..
             "and volatile), so during a volatile write every guest read blocks — the " ..
             "internal lock-domain distinction is unobservable and untested — " ..
             "PEI-TBD-loregd-volatile-only-write-hive-read-untested" },
    function() end)
