-- loregd §4.3 — Transactions: ids allocated by the kernel and bound to
-- connections lazily; read-write vs read-only; committing and aborting.
--
-- Driven end to end against a real loregd serving the PtState hive: the
-- LCS client ioctls (helpers/lcs) route Caller -> kernel LCS -> loregd,
-- so a plain worker syscall against PtState just works (the kernel talks
-- to loregd directly; there is no Lua pump). `reg_begin_transaction` is
-- SYSCALL_DEFINE0 and contacts no source, so the guest can only ever open
-- a *read-write* transaction; the kernel forwards RSI_BEGIN_TRANSACTION
-- to loregd lazily, when the transaction's first operation binds it to a
-- hive. Read-only source transactions are the kernel's own, opened only
-- for REG_IOC_BACKUP, and their internals are unobservable from a guest —
-- so those anchors are homed on the loregd Go unit tests that assert them
-- directly, with the guest route shown closed.

local loregd = require("helpers.loregd")
local lcs = require("helpers.lcs")
local sys = require("helpers.sys")

local KEY = loregd.KEY -- PtState\Durable

local vm = loregd.boot({ name = "loregd-txn" })
loregd.format(vm)
loregd.mount(vm)
loregd.start(vm)

-- The root and a key most cases write values under.
loregd.new_key(vm, KEY):assert_ok()

local W = vm:spawn_worker()

--- Open a PtState key, asserting the open succeeded; returns the fd.
local function open(t, path)
    local r = lcs.open_key(nil, W, -1, path, lcs.KEY_ALL_ACCESS, 0)
    t:assert(r.ret >= 0, "open " .. path .. ": ret=" .. tostring(r.ret) ..
        " errno=" .. sys.errname(r.errno or 0))
    return r.ret
end

--- The state field of a transaction fd (ACTIVE_UNBOUND / ACTIVE_BOUND / …).
local function state(txn)
    return lcs.txn_status(nil, W, txn).state
end

-- ---- Beginning --------------------------------------------------------

-- "loregd records the id as pending in the requested mode and returns
-- RSI_OK immediately. No connection is taken and no SQLite transaction is
-- opened." "loregd supports both modes … so it never returns
-- RSI_TXN_NOT_SUPPORTED."
test("begin records the id as pending, opens no SQLite transaction and takes " ..
     "no connection, and never answers RSI_TXN_NOT_SUPPORTED",
    { spec = "loregd *txn.begin-records-the-id-as-pending-and-returns-rsi-ok-immediately " ..
             "*txn.begin-takes-no-connection-and-opens-no-sqlite-transaction " ..
             "*txn.loregd-never-returns-rsi-txn-not-supported" }, function(t)
        local txn = lcs.begin_transaction(W)
        t:assert(txn, "begin_transaction returned a fd, not a failure — begin " ..
            "succeeds rather than answering RSI_TXN_NOT_SUPPORTED")
        t:assert_eq(state(txn), lcs.TXN.ACTIVE_UNBOUND,
            "the transaction is recorded as pending (ACTIVE_UNBOUND): no " ..
            "operation has bound it and no SQLite transaction is open")

        -- Begin took no connection: while the transaction is pending, the
        -- hive's single write connection is free, so an ordinary write and
        -- a FLUSH both go through. Had begin opened a SQLite transaction it
        -- would hold that connection and FLUSH would answer RSI_TXN_BUSY.
        local fd = open(t, KEY)
        local w = lcs.set_value(nil, W, fd, "Pending", lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(w.ret, 0, "an untagged write runs while the transaction is " ..
            "pending: errno=" .. sys.errname(w.errno or 0))
        local fl = lcs.flush(nil, W, fd)
        t:assert_eq(fl.ret, 0, "and a FLUSH is not refused RSI_TXN_BUSY, so begin " ..
            "holds no write connection: errno=" .. sys.errname(fl.errno or 0))

        sys.close(W, txn)
        sys.close(W, fd)
    end)

-- ---- Read-write transactions ------------------------------------------

-- "The transaction binds to a hive on its first mutating operation …
-- Once bound, every subsequent operation with that transaction id — reads
-- included — runs on the same connection. That is what provides
-- read-your-own-writes." Transaction ids are carried on every request.
test("a read-write transaction binds on its first mutating operation, its id " ..
     "rides every request, and it reads its own uncommitted writes on the same connection",
    { spec = "loregd *txn.a-read-write-transaction-binds-on-its-first-mutating-operation " ..
             "*txn.transaction-ids-are-allocated-by-the-kernel-and-carried-on-every-request " ..
             "*txn.once-bound-every-operation-on-the-transaction-runs-on-the-same-connection " ..
             "*txn.a-transaction-sees-its-own-uncommitted-writes" }, function(t)
        local fd = open(t, KEY)
        local txn = lcs.begin_transaction(W)
        t:assert_eq(state(txn), lcs.TXN.ACTIVE_UNBOUND, "unbound before any operation")

        local w = lcs.set_value(nil, W, fd, "Own", lcs.TYPE.DWORD, lcs.dword(7),
            { txn_fd = txn })
        t:assert_eq(w.ret, 0, "the first mutating operation: errno=" ..
            sys.errname(w.errno or 0))
        t:assert_eq(state(txn), lcs.TXN.ACTIVE_BOUND,
            "which binds the transaction (ACTIVE_BOUND)")

        -- A read tagged with the same id is routed, by that id, to the same
        -- bound connection, so it sees the uncommitted write.
        local inside = lcs.query_value(nil, W, fd, "Own", { txn_fd = txn })
        t:assert_eq(inside.ret, 0, "a tagged read finds the uncommitted value: " ..
            "errno=" .. sys.errname(inside.errno or 0))
        t:assert_eq(inside.data, lcs.dword(7), "with the value the transaction wrote")

        -- An untagged read, on a pool connection, cannot see it: the write
        -- lives only on the transaction's own connection.
        local outside = lcs.query_value(nil, W, fd, "Own")
        t:assert_eq(outside.errno, sys.E.NOENT,
            "an untagged read does not: the write is uncommitted and lives only " ..
            "on the bound connection")

        -- Abort by closing the fd; the uncommitted "Own" is discarded.
        sys.close(W, txn)
        sys.close(W, fd)
    end)

-- "Reads issued *before* the transaction binds go to the read pool
-- instead, since there is nothing uncommitted to see."
test("a read issued before the transaction binds goes to the read pool and does not bind it",
    { spec = "loregd *txn.a-read-issued-before-binding-goes-to-the-read-pool" }, function(t)
        loregd.set(vm, KEY, "Pre", "dword:5"):assert_ok()
        local fd = open(t, KEY)
        local txn = lcs.begin_transaction(W)

        local before = lcs.query_value(nil, W, fd, "Pre", { txn_fd = txn })
        t:assert_eq(before.ret, 0, "a tagged read before any mutation: errno=" ..
            sys.errname(before.errno or 0))
        t:assert_eq(before.data, lcs.dword(5),
            "returns the committed value, i.e. it was answered from the read pool")
        t:assert_eq(state(txn), lcs.TXN.ACTIVE_UNBOUND,
            "and the transaction is still unbound: a pre-bind read takes no connection")

        sys.close(W, txn)
        sys.close(W, fd)
    end)

-- "Because the connection has both the hive database and the volatile
-- database attached, a single SQLite transaction spans both. Persistent
-- and volatile mutations made inside one transaction commit together and
-- roll back together."
test("persistent and volatile mutations inside one transaction commit together and roll back together",
    { spec = "loregd *txn.persistent-and-volatile-mutations-commit-and-roll-back-together" },
    function(t)
        local fd = open(t, KEY)

        -- Commit together: one transaction sets a persistent value and
        -- creates a volatile key; commit makes both visible.
        local txn = lcs.begin_transaction(W)
        local pv = lcs.set_value(nil, W, fd, "Persist1", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        t:assert_eq(pv.ret, 0, "persistent write: errno=" .. sys.errname(pv.errno or 0))
        local ck = lcs.create_key(nil, W, { path = KEY .. "\\Vol1",
            flags = lcs.OPTION_VOLATILE, access = lcs.KEY_ALL_ACCESS, txn_fd = txn })
        t:assert(ck.ret >= 0, "volatile-key create in the same transaction: ret=" ..
            tostring(ck.ret) .. " errno=" .. sys.errname(ck.errno or 0))
        if ck.ret >= 0 then sys.close(W, ck.ret) end
        t:assert_eq(lcs.commit(nil, W, txn).ret, 0, "commit")
        sys.close(W, txn)

        t:assert_eq(lcs.query_value(nil, W, fd, "Persist1").data, lcs.dword(1),
            "the persistent value is visible after commit")
        local ov = lcs.open_key(nil, W, -1, KEY .. "\\Vol1", lcs.KEY_ALL_ACCESS, 0)
        t:assert(ov.ret >= 0, "and the volatile key is too — both committed together")
        if ov.ret >= 0 then sys.close(W, ov.ret) end

        -- Roll back together: the same two mutations, then abort; neither survives.
        local txn2 = lcs.begin_transaction(W)
        local pv2 = lcs.set_value(nil, W, fd, "Persist2", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn2 })
        t:assert_eq(pv2.ret, 0, "persistent write in the second transaction")
        local ck2 = lcs.create_key(nil, W, { path = KEY .. "\\Vol2",
            flags = lcs.OPTION_VOLATILE, access = lcs.KEY_ALL_ACCESS, txn_fd = txn2 })
        t:assert(ck2.ret >= 0, "volatile-key create in the second transaction")
        if ck2.ret >= 0 then sys.close(W, ck2.ret) end
        sys.close(W, txn2) -- abort by closing the transaction fd

        t:assert_eq(lcs.query_value(nil, W, fd, "Persist2").errno, sys.E.NOENT,
            "after abort the persistent mutation is gone")
        local ov2 = lcs.open_key(nil, W, -1, KEY .. "\\Vol2", lcs.KEY_ALL_ACCESS, 0)
        t:assert(ov2.ret < 0,
            "and so is the volatile one — they rolled back together (ret=" ..
            tostring(ov2.ret) .. ")")
        if ov2.ret >= 0 then sys.close(W, ov2.ret) end
        sys.close(W, fd)
    end)

-- ---- Committing and aborting ------------------------------------------

-- "RSI_COMMIT_TRANSACTION issues COMMIT on the bound connection and
-- returns RSI_OK."
test("commit issues COMMIT on the bound connection, returns RSI_OK, and publishes the write",
    { spec = "loregd *txn.commit-issues-commit-on-the-bound-connection-and-returns-rsi-ok" },
    function(t)
        local fd = open(t, KEY)
        local txn = lcs.begin_transaction(W)
        local w = lcs.set_value(nil, W, fd, "Committed", lcs.TYPE.DWORD, lcs.dword(11),
            { txn_fd = txn })
        t:assert_eq(w.ret, 0, "the write binds the transaction")

        local c = lcs.commit(nil, W, txn)
        t:assert_eq(c.ret, 0, "commit returns RSI_OK: errno=" .. sys.errname(c.errno or 0))
        t:assert_eq(state(txn), lcs.TXN.COMMITTED, "and the transaction is COMMITTED")

        t:assert_eq(lcs.query_value(nil, W, fd, "Committed").data, lcs.dword(11),
            "an ordinary read now sees the committed value")
        sys.close(W, txn)
        sys.close(W, fd)
    end)

-- "RSI_ABORT_TRANSACTION issues ROLLBACK, closes the connection, releases
-- any snapshot, runs the transaction's abort hooks." A guest aborts by
-- closing the transaction fd; the observable half is the rollback and the
-- release of the write connection (the abort hooks keep loregd's caches
-- consistent and are internal).
test("abort rolls back the transaction's writes and releases the write connection",
    { spec = "loregd *txn.abort-rolls-back-closes-the-connection-and-runs-the-abort-hooks" },
    function(t)
        local fd = open(t, KEY)
        local txn = lcs.begin_transaction(W)
        local w = lcs.set_value(nil, W, fd, "Rolled", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        t:assert_eq(w.ret, 0, "the write binds the transaction and holds the connection")

        sys.close(W, txn) -- RSI_ABORT_TRANSACTION: ROLLBACK + close the connection

        t:assert_eq(lcs.query_value(nil, W, fd, "Rolled").errno, sys.E.NOENT,
            "the uncommitted write was rolled back")
        -- The connection was closed and returned to the write handle, so a
        -- fresh write runs immediately rather than waiting on a held one.
        local after = lcs.set_value(nil, W, fd, "AfterAbort", lcs.TYPE.DWORD, lcs.dword(2))
        t:assert_eq(after.ret, 0, "and the write connection is free again: errno=" ..
            sys.errname(after.errno or 0))
        sys.close(W, fd)
    end)

-- "A transaction that is neither committed nor aborted is never cleaned
-- up: there is no timeout and no reaper. It holds its hive's write
-- connection until the process exits."
test("an uncommitted transaction is not reclaimed: it stays bound with no timeout or reaper",
    { spec = "loregd *txn.an-uncommitted-transaction-is-never-reclaimed" }, function(t)
        local fd = open(t, KEY)
        local txn = lcs.begin_transaction(W)
        local w = lcs.set_value(nil, W, fd, "Abandoned", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        t:assert_eq(w.ret, 0, "the transaction binds and holds the write connection")
        t:assert_eq(state(txn), lcs.TXN.ACTIVE_BOUND, "bound")

        -- Left neither committed nor aborted. loregd runs no reaper of its
        -- own, so across this window the binding simply persists (the
        -- kernel's own 30s transaction timeout is well beyond it).
        sys.nanosleep(vm, 3, 0)
        t:assert_eq(state(txn), lcs.TXN.ACTIVE_BOUND,
            "still bound after 3s: nothing in loregd reclaimed it")

        -- Do not leave the write connection wedged for later files: release it.
        sys.close(W, txn)
        sys.close(W, fd)
    end)

-- ---- Homed on loregd Go unit tests (guest route closed) ---------------
--
-- Each stub names the loregd handler test that asserts the property and
-- one sentence for why a PtState guest cannot observe it. All cited tests
-- were run green (`go test ./internal/handler/...`).

-- The kernel allocates a fresh, unique id for every reg_begin_transaction
-- (SYSCALL_DEFINE0 — the guest supplies no id), so a guest can never hand
-- loregd a duplicate active id.
test("re-using an active transaction id returns RSI_INVALID",
    { spec = "loregd *txn.re-using-an-active-transaction-id-returns-rsi-invalid",
      skip = "the guest never controls the transaction id (reg_begin_transaction " ..
             "is SYSCALL_DEFINE0), so it cannot present loregd a duplicate active id",
      covered_by = "go:loregd internal/handler::TestBeginTransactionDuplicate" },
    function() end)

-- The RSI_BEGIN_TRANSACTION mode field is filled by the kernel on every
-- begin; a guest cannot emit a mode-less frame. loregd's decoder defaults
-- an absent mode to read-write, and TestTransactionWriteAndCommit begins
-- with an 8-byte (mode-less) payload then performs a mutating write.
test("an absent mode field means read-write",
    { spec = "loregd *txn.an-absent-mode-field-means-read-write",
      skip = "the mode field is a wire detail the kernel always fills; a guest " ..
             "cannot send an absent-mode RSI_BEGIN_TRANSACTION frame",
      covered_by = "go:loregd internal/handler::TestTransactionWriteAndCommit" },
    function() end)

-- The kernel hive-scopes a request before it reaches loregd (the book
-- calls this a backstop) and the PtState harness serves a single hive, so
-- no guest operation can cross hives inside one transaction.
-- TestTransactionHiveConsistency binds a txn to hive1, writes hive2's GUID
-- and gets the "bound to different hive" error, which mapWriteErr's
-- default arm maps to RSI_STORAGE_ERROR.
test("an operation on another hive is rejected with RSI_STORAGE_ERROR",
    { spec = "loregd *txn.an-operation-on-another-hive-is-rejected-with-rsi-storage-error",
      skip = "the kernel enforces hive-scoping before loregd sees the request, " ..
             "and the PtState harness serves only one hive",
      covered_by = "go:loregd internal/handler::TestTransactionHiveConsistency" },
    function() end)

-- Read-only source transactions are the kernel's own (opened only for
-- REG_IOC_BACKUP); reg_begin_transaction always yields read-write, and a
-- backup exposes none of the snapshot internals. TestReadOnlyTxnSnapshotIsolation
-- begins a read-only txn, whose first read fixes the snapshot; the snapshot
-- stays at v1 while the pool observes an externally committed v2 (a stable
-- point-in-time view on a dedicated connection, exact for the persistent
-- value).
test("a read-only transaction binds on its first read",
    { spec = "loregd *txn.a-read-only-transaction-binds-on-its-first-read",
      skip = "a guest cannot begin a read-only transaction: reg_begin_transaction " ..
             "is SYSCALL_DEFINE0 and always sends RSI_TXN_READ_WRITE",
      covered_by = "go:loregd internal/handler::TestReadOnlyTxnSnapshotIsolation" },
    function() end)

test("a read-only transaction gets a dedicated connection outside the read pool",
    { spec = "loregd *txn.a-read-only-transaction-gets-a-dedicated-connection-outside-the-read-pool",
      skip = "read-only transactions are not guest-reachable; a stable snapshot " ..
             "held while the pool sees new writes is only possible on a dedicated " ..
             "connection (OpenSnapshotConn), not a pool one",
      covered_by = "go:loregd internal/handler::TestReadOnlyTxnSnapshotIsolation" },
    function() end)

test("every read in a read-only transaction observes the same snapshot",
    { spec = "loregd *txn.every-read-in-a-read-only-transaction-observes-the-same-snapshot",
      skip = "read-only transactions are not guest-reachable; the Go test re-reads " ..
             "within the txn and still sees v1 after an external v2 commit",
      covered_by = "go:loregd internal/handler::TestReadOnlyTxnSnapshotIsolation" },
    function() end)

test("the snapshot is exact for persistent data",
    { spec = "loregd *txn.the-snapshot-is-exact-for-persistent-data",
      skip = "read-only transactions are not guest-reachable; the snapshotted value " ..
             "is a persistent (main) value and reads back exactly v1",
      covered_by = "go:loregd internal/handler::TestReadOnlyTxnSnapshotIsolation" },
    function() end)

-- A mutating op tagged with a read-only txn is refused RSI_INVALID before
-- any write. TestReadOnlyTxnRejectsMutation tags SET_VALUE and CREATE_KEY
-- and asserts StatusInvalid plus zero rows written.
test("a mutation in a read-only transaction is rejected before any state changes",
    { spec = "loregd *txn.a-mutation-in-a-read-only-transaction-is-rejected-before-any-state-changes",
      skip = "read-only transactions are not guest-reachable",
      covered_by = "go:loregd internal/handler::TestReadOnlyTxnRejectsMutation" },
    function() end)

-- The kernel answers REG_IOC_COMMIT on an unbound/unknown transaction fd
-- with EINVAL locally (PKM *txn-ioctl.commit.einval-when-committed-or-unbound),
-- so loregd only ever receives commits for ids it bound.
-- TestCommitPreservesStateOnFailure commits unknown id 777 and gets
-- RSI_STORAGE_ERROR.
test("committing an unknown transaction id returns RSI_STORAGE_ERROR",
    { spec = "loregd *txn.committing-an-unknown-transaction-id-returns-rsi-storage-error",
      skip = "the kernel returns EINVAL for a commit on an unbound/unknown " ..
             "transaction fd before contacting loregd, so loregd never receives " ..
             "a commit for an id it did not bind",
      covered_by = "go:loregd internal/handler::TestCommitPreservesStateOnFailure" },
    function() end)

-- TestReadOnlyTxnReleaseAllowsReuse commits a read-only txn and shows the
-- id is immediately reusable — the snapshot connection and dedicated DB
-- were released.
test("committing a read-only transaction releases the snapshot",
    { spec = "loregd *txn.committing-a-read-only-transaction-releases-the-snapshot",
      skip = "read-only transactions are not guest-reachable",
      covered_by = "go:loregd internal/handler::TestReadOnlyTxnReleaseAllowsReuse" },
    function() end)

-- A guest aborts by closing the transaction fd, which can only abort an id
-- loregd bound; it cannot send RSI_ABORT for an id loregd never saw.
-- TestAbortUnknownTransaction aborts unknown id 999 and gets RSI_OK
-- (TestAbortAlreadyAborted double-aborts, also RSI_OK).
test("abort always returns RSI_OK, including for an unknown transaction id",
    { spec = "loregd *txn.abort-always-returns-rsi-ok-including-for-an-unknown-transaction-id",
      skip = "a guest can only abort by closing a live transaction fd; it cannot " ..
             "send RSI_ABORT for an id loregd never bound",
      covered_by = "go:loregd internal/handler::TestAbortUnknownTransaction" },
    function() end)

-- ---- Coverage gaps (unreachable from a guest AND no loregd unit test) --
--
-- These two properties are neither observable from a PtState guest nor
-- asserted by any existing loregd Go test. Rather than cite a test that
-- does not prove the anchor, they are flagged for the coordinator to
-- ticket a new unit test. See the report.

-- A SQLITE_BUSY at BEGIN IMMEDIATE (bind time) needs another connection
-- holding the hive's write lock, which loregd's single write connection
-- (MaxOpenConns=1) forbids: a second binder waits in the Go pool for the
-- one connection (never reaching BEGIN IMMEDIATE) rather than getting
-- SQLITE_BUSY, so this defensive path is not guest-reachable, and no unit
-- test drives it. PEI-TBD-loregd-busy-at-bind-untested
test("a busy database at bind time returns RSI_TXN_BUSY",
    { spec = "loregd *txn.a-busy-database-at-bind-time-returns-rsi-txn-busy",
      skip = "not guest-reachable: with one write connection a second binder " ..
             "waits in the pool rather than hitting SQLITE_BUSY at BEGIN IMMEDIATE, " ..
             "and no loregd unit test drives it — PEI-TBD-loregd-busy-at-bind-untested" },
    function() end)

-- Forcing a COMMIT itself to fail needs SQLITE_BUSY/error at COMMIT time,
-- which loregd's single-writer WAL model does not produce from a guest,
-- and no unit test drives a failing commit and asserts the txn stays open.
-- PEI-TBD-loregd-failed-commit-untested
test("a failed commit leaves the transaction open for retry or abort",
    { spec = "loregd *txn.a-failed-commit-leaves-the-transaction-open-for-retry-or-abort",
      skip = "not guest-reachable (a guest cannot make COMMIT fail under loregd's " ..
             "single-writer WAL model) and no loregd unit test asserts the " ..
             "leave-open behaviour — PEI-TBD-loregd-failed-commit-untested" },
    function() end)

-- The volatile store has no snapshot, so a volatile read inside a read-only
-- transaction sees the live store. Read-only transactions are not
-- guest-reachable, and no loregd unit test asserts this volatile-live read.
-- PEI-TBD-loregd-volatile-readonly-live-untested
test("a volatile read inside a read-only transaction sees the live store",
    { spec = "loregd *txn.a-volatile-read-inside-a-read-only-transaction-sees-the-live-store",
      skip = "read-only transactions are not guest-reachable and no loregd unit " ..
             "test asserts the volatile-live read inside one — " ..
             "PEI-TBD-loregd-volatile-readonly-live-untested" },
    function() end)
