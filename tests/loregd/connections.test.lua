-- loregd §4.1 (TRM 4--concurrency/1--connections) — the fixed set of
-- SQLite connections a hive holds, and which one an operation runs on.
--
-- Most of this chapter is internal: which of a hive's connections served a
-- read, the round-robin pool index, the snapshot connection's separateness,
-- the compiled-in pool size, and the per-connection PRAGMAs are not visible
-- to a guest — the kernel resolves paths to GUIDs and hands loregd a request
-- that names no connection. Those anchors are cited to the Go unit tests
-- that assert them, each with the one fact that proves the guest route is
-- closed. What IS reachable is the behaviour the single write connection
-- forces: a second writer waits for it, a read is served past it, and the
-- volatile store written on it is read back through a pool connection.
--
-- Reachability was established empirically: the LCS client ioctls in
-- helpers/lcs reach this real loregd on a plain worker syscall (the kernel
-- talks to loregd directly, so no Lua pump is needed), and a guest
-- reg_begin_transaction is SYSCALL_DEFINE0 in the kernel — it can only open a
-- READ-WRITE transaction, so the read-only-snapshot anchors are genuinely
-- unreachable and are cited to Go.

local loregd = require("helpers.loregd")
local lcs = require("helpers.lcs")
local sys = require("helpers.sys")

local KEY = loregd.KEY -- PtState\Durable

-- One file-scope loregd, driven by every case. A fresh daemon is started
-- inside the last case only, which is specifically about restart.
local vm = loregd.boot({ name = "loregd-conn" })
loregd.format(vm)
loregd.mount(vm)
local proc = loregd.start(vm)

-- The key every case writes under exists once, committed, up front.
loregd.new_key(vm, KEY):assert_ok()

-- Open a key fd on `worker` bound to PtState\Durable, asserting it resolved.
local function open_durable(t, worker)
    local r = lcs.open_key(nil, worker, -1, "PtState\\Durable", lcs.KEY_ALL_ACCESS, 0)
    t:assert(r.ret >= 0, "open PtState\\Durable: ret=" .. tostring(r.ret) ..
        " errno=" .. sys.errname(r.errno or 0))
    return r.ret
end

-- ---------------------------------------------------------------------------
-- Reachable: the single write connection serialises writers and is bypassed
-- by reads.
--
-- Book: "Every mutating operation, and every read inside a bound read-write
-- transaction [runs on the] Write [connection] ... One per hive."
-- "Every one of these is a Go database/sql handle limited to a single
-- underlying connection. That single limit is what serialises writes ... so
-- a second writer waits for the first to release it."
-- "Reads outside a transaction [use the Read pool] ... Selected round-robin."
-- ---------------------------------------------------------------------------
test("a second writer waits for the hive's one write connection while a read is served past it",
    {
        spec = "loregd " ..
            "*conn.a-second-writer-to-a-hive-waits-for-the-write-connection " ..
            "*conn.every-mutation-runs-on-the-hives-single-write-connection " ..
            "*conn.every-handle-is-limited-to-one-underlying-connection " ..
            "*conn.reads-outside-a-transaction-use-the-round-robin-read-pool",
    },
    function(t)
        loregd.set(vm, KEY, "C", "dword:0"):assert_ok()

        local W1 = vm:spawn_worker()
        local W2 = vm:spawn_worker()
        local fd1 = open_durable(t, W1)
        local fd2 = open_durable(t, W2)

        -- W1 opens a read-write transaction and mutates: getOrBindWrite pins
        -- the hive's one write connection with BEGIN IMMEDIATE and holds it
        -- until commit. This is the "every mutation runs on the single write
        -- connection" half — the mutation binds that connection.
        local txn = lcs.begin_transaction(W1)
        t:assert(txn, "W1 begin_transaction")
        local w1 = lcs.set_value(nil, W1, fd1, "C", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        t:assert_eq(w1.ret, 0, "W1 set in txn binds the write connection: ret=" ..
            tostring(w1.ret) .. " errno=" .. sys.errname(w1.errno or 0))

        -- W2 issues a NON-transactional write to the same hive, async. It
        -- routes to hive.WriteDB(), whose single underlying connection is the
        -- one W1 pinned (SetMaxOpenConns(1)), so it must wait — not error.
        local nr, spec, decode = lcs.build.set_value(fd2, "C", lcs.TYPE.DWORD, lcs.dword(2))
        local pending = W2:syscall_async(nr, spec)

        -- While W1 holds the write connection, a READ is still served: it
        -- goes to a read-pool connection, not the pinned write one. It sees
        -- the pre-transaction value, proving both that reads bypass the write
        -- connection and that W2's write has not been applied (it is waiting).
        sys.nanosleep(vm, 1, 0)
        local rr, mid = loregd.get(vm, KEY, "C")
        rr:assert_ok()
        t:assert_eq(mid, "0",
            "a read outside the transaction is served through the read pool " ..
            "while the write connection is pinned, and still shows 0 — the " ..
            "second writer has not applied its write, it is waiting: " .. mid)

        -- Release the write connection. Only now can W2 acquire it.
        local c = lcs.commit(nil, W1, txn)
        t:assert_eq(c.ret, 0, "W1 commit releases the write connection: ret=" ..
            tostring(c.ret))

        local w2r = decode(pending:await())
        t:assert_eq(w2r.ret, 0,
            "the second writer completes successfully once the connection is " ..
            "free — it waited for it rather than being refused: ret=" ..
            tostring(w2r.ret) .. " errno=" .. sys.errname(w2r.errno or 0))

        local _, fin = loregd.get(vm, KEY, "C")
        t:assert_eq(fin, "2",
            "the waiting writer's value is the one that lands last: " .. fin)
    end)

-- ---------------------------------------------------------------------------
-- Reachable: volatile tables written on the write connection are seen by a
-- read-pool connection through the shared-cache attach.
--
-- Book: "The volatile tables are created only on the write connection. Read
-- and snapshot connections attach the same shared-cache URI and see the
-- tables through it."
-- ---------------------------------------------------------------------------
test("a volatile value written on the write path is read back through a read-pool connection",
    {
        spec = "loregd " ..
            "*conn.read-and-snapshot-connections-see-volatile-tables-through-the-shared-cache-uri " ..
            "*conn.volatile-tables-are-created-only-on-the-write-connection",
    },
    function(t)
        local W = vm:spawn_worker()
        -- A volatile key + value: create_key with OPTION_VOLATILE and a
        -- set_value both route through the hive's write connection, which is
        -- the only connection on which the volatile tables are created.
        local cr = lcs.create_key(nil, W, {
            path = "PtState\\Durable\\Vol", access = lcs.KEY_ALL_ACCESS,
            flags = lcs.OPTION_VOLATILE,
        })
        t:assert(cr.ret >= 0, "create volatile key: ret=" .. tostring(cr.ret) ..
            " errno=" .. sys.errname(cr.errno or 0))
        local sv = lcs.set_value(nil, W, cr.ret, "VV", lcs.TYPE.DWORD, lcs.dword(9))
        t:assert_eq(sv.ret, 0, "set volatile value on the write connection: ret=" ..
            tostring(sv.ret) .. " errno=" .. sys.errname(sv.errno or 0))

        -- A non-transactional query routes to a read-pool connection — a
        -- different handle from the write one. It sees the volatile row only
        -- because it attaches the same shared-cache volatile database.
        local R = vm:spawn_worker()
        local rfd = lcs.open_key(nil, R, -1, "PtState\\Durable\\Vol",
            lcs.KEY_ALL_ACCESS, 0)
        t:assert(rfd.ret >= 0, "reopen the volatile key on a second worker: ret=" ..
            tostring(rfd.ret) .. " errno=" .. sys.errname(rfd.errno or 0))
        local q = lcs.query_value(nil, R, rfd.ret, "VV")
        t:assert_eq(q.ret, 0, "the read-pool query sees the volatile table: ret=" ..
            tostring(q.ret) .. " errno=" .. sys.errname(q.errno or 0))
        t:assert_eq(q.data, lcs.dword(9),
            "and returns the value written on the write connection — the read " ..
            "connection saw the volatile tables through the shared-cache URI")
    end)

-- ---------------------------------------------------------------------------
-- Not guest-observable — cited to Go unit tests. Each stub first states the
-- one fact that closes the guest route.
-- ---------------------------------------------------------------------------

-- Route closed: the volatile database is attached in-memory
-- (file:<hive>_volatile?mode=memory&cache=shared in hivedb.attachVolatile),
-- and a guest cannot run PRAGMA journal_mode against that attach. No Go test
-- asserts the journal_mode string directly; the cited test exercises the
-- volatile tables reached through that mode=memory attach. (Coverage note in
-- the ledger: the exact PRAGMA is unasserted in Go.)
test("the volatile database uses journal-mode memory not wal",
    {
        spec = "loregd *conn.the-volatile-database-uses-journal-mode-memory-not-wal",
        skip = true,
        covered_by = "go:loregd internal/hivedb::TestVolatileTablesExist",
    }, function() end)

-- Route closed: a guest reg_begin_transaction (SYSCALL_DEFINE0 in
-- transaction_fd.c) can only open a READ-WRITE transaction; the read-only
-- snapshot connection is reached only by REG_IOC_BACKUP internally, so a
-- guest cannot construct the read-only transaction this describes.
test("each read-only transaction gets its own snapshot connection",
    {
        spec = "loregd *conn.each-read-only-transaction-gets-its-own-snapshot-connection",
        skip = true,
        covered_by = "go:loregd internal/handler::TestReadOnlyTxnSnapshotIsolation",
    }, function() end)

-- Route closed: same — no guest read-only transaction exists to hold a
-- snapshot open, so its non-consumption of a pool slot is unobservable. The
-- cited test runs a read-only snapshot concurrently with pool reads that
-- keep working, showing the snapshot took no pool slot.
test("a snapshot connection never consumes a read-pool slot",
    {
        spec = "loregd *conn.a-snapshot-connection-never-consumes-a-read-pool-slot",
        skip = true,
        covered_by = "go:loregd internal/handler::TestReadOnlyTxnSnapshotIsolation",
    }, function() end)

-- Route closed: the persistent-reader snapshot is a read-only transaction,
-- which a guest cannot open (see above). MVCC snapshot stability is asserted
-- in Go: a value committed after the snapshot's first read stays invisible.
test("persistent readers see a consistent snapshot and do not block writers",
    {
        spec = "loregd *conn.persistent-readers-see-a-consistent-snapshot-and-do-not-block-writers",
        skip = true,
        covered_by = "go:loregd internal/handler::TestReadOnlyTxnSnapshotIsolation",
    }, function() end)

-- Route closed: the pool size is min(NumCPU,16), compiled into
-- hivedb.ReadPoolSize; loregd's only configuration is Name=Path hive specs,
-- so there is no guest input that changes it. config.Parse rejects anything
-- else, which the cited tests assert.
test("the read-pool size is compiled in and cannot be configured",
    {
        spec = "loregd *conn.the-pool-size-is-compiled-in-and-cannot-be-configured",
        skip = true,
        covered_by = "go:loregd internal/config::TestParseValid, go:loregd internal/config::TestParseErrors",
    }, function() end)

-- Route closed: the four PRAGMAs (journal_mode=wal, foreign_keys=ON,
-- busy_timeout=25000) and the volatile attach are set inside openConn and are
-- not queryable from a guest. Each is asserted by its own hivedb test.
test("connection state is established once when the connection is opened",
    {
        spec = "loregd *conn.connection-state-is-established-once-when-the-connection-is-opened",
        skip = true,
        covered_by = "go:loregd internal/hivedb::TestWALMode, go:loregd internal/hivedb::TestBusyTimeout, go:loregd internal/hivedb::TestForeignKeysEnabled, go:loregd internal/hivedb::TestVolatileTablesExist",
    }, function() end)

-- Route closed: which of a hive's connections a mutation routes to is
-- internal; a guest sees only the result. The cited test drives both the
-- values.go and handler.go mutating paths through writeQ and shows every one
-- is rejected under a read-only transaction, i.e. all route through the
-- transaction-aware write path.
test("the nine mutating operations route through the transaction-aware write path",
    {
        spec = "loregd *conn.nine-mutating-operations-route-through-the-transaction-aware-write-path",
        skip = true,
        covered_by = "go:loregd internal/handler::TestReadOnlyTxnRejectsMutation",
    }, function() end)

-- Route closed: read routing (pool vs. bound transaction connection) is
-- internal. The cited test shows a read tagged with a bound read-write
-- transaction returns that transaction's own uncommitted writes — i.e. it was
-- routed to the bound connection, not the pool.
test("the four read operations route to the read pool or the bound transaction",
    {
        spec = "loregd *conn.four-read-operations-route-to-the-read-pool-or-the-bound-transaction",
        skip = true,
        covered_by = "go:loregd internal/handler::TestQueryValuesReadYourOwnWrites",
    }, function() end)

-- Route closed: RSI_DELETE_LAYER has no guest ioctl (no REG_IOC_DELETE_LAYER
-- in the uapi) and RSI_FLUSH takes the write connection with no transaction to
-- join. The cited tests exercise both taking the write connection directly and
-- committing their own work.
test("delete-layer and flush take the write connection directly",
    {
        spec = "loregd *conn.delete-layer-and-flush-take-the-write-connection-directly",
        skip = true,
        covered_by = "go:loregd internal/handler::TestFlush, go:loregd internal/handler::TestDeleteLayerPurgesEntries",
    }, function() end)

-- Route closed: the kernel builds both RSI_FLUSH and RSI_DELETE_LAYER frames
-- with txn_id hardcoded to 0 (source_request.c), so a guest can never tag
-- either with a caller's transaction — they cannot join one. The cited test
-- confirms they consult the id only to refuse a read-only one.
test("neither delete-layer nor flush can join a caller's transaction",
    {
        spec = "loregd *conn.neither-delete-layer-nor-flush-can-join-a-callers-transaction",
        skip = true,
        covered_by = "go:loregd internal/handler::TestReadOnlyTxnRejectsDeleteLayerAndFlush",
    }, function() end)

-- Route PROVEN closed: the kernel passes txn_id=0 when it builds the RSI_FLUSH
-- and RSI_DELETE_LAYER frames (pkm/lcs/source_request.c build calls), so no
-- guest request can carry a read-only transaction into these ops. The Go test
-- drives the handlers directly with a read-only txn and asserts RSI_INVALID
-- (and that no rows were deleted).
test("delete-layer and flush decline a read-only transaction with rsi-invalid",
    {
        spec = "loregd *conn.delete-layer-and-flush-decline-a-read-only-transaction-with-rsi-invalid",
        skip = true,
        covered_by = "go:loregd internal/handler::TestReadOnlyTxnRejectsDeleteLayerAndFlush",
    }, function() end)

-- Route closed: RSI_DELETE_LAYER has no guest ioctl, so a guest cannot issue
-- one while a transaction holds a write connection. The Go test binds a write
-- connection in a transaction, issues delete-layer, and asserts RSI_TXN_BUSY
-- (not an indefinite block).
test("delete-layer declines with rsi-txn-busy rather than blocking",
    {
        spec = "loregd *conn.delete-layer-declines-with-rsi-txn-busy-rather-than-blocking",
        skip = true,
        covered_by = "go:loregd internal/handler::TestDeleteLayerDeclinesWhileATransactionHoldsAWrite",
    }, function() end)
