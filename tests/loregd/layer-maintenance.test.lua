-- loregd §5.6 (layer-and-maintenance-operations) — RSI_DELETE_LAYER and
-- RSI_FLUSH, the two operations that check the request's transaction id but
-- cannot join one, taking the hive's write connection directly.
--
-- Reachability is sharply split:
--
--   * RSI_FLUSH is reachable from a guest: the lcs.IOC.FLUSH ioctl carries a
--     key fd, the kernel derives the hive name from it and hardcodes txn_id=0
--     on the RSI_FLUSH frame. So a plain flush of a served hive, and flush
--     declining while another connection holds a bound transaction, are both
--     driven here end to end against the served PtState hive.
--
--   * RSI_DELETE_LAYER is NOT reachable from a guest: there is no
--     REG_IOC_DELETE_LAYER in the uapi — only kunit triggers delete-layer —
--     and the kernel would hardcode txn_id=0 on the frame anyway. Every
--     delete-layer anchor is therefore homed on the loregd Go unit test that
--     asserts it directly (internal/handler), each verified by reading and
--     running it.
--
--   * The transaction-id checks both operations perform (a read-only
--     transaction may not mutate; an unknown id is refused) are likewise not
--     guest-reachable: reg_begin_transaction is read-write-only (SYSCALL_DEFINE0)
--     and the kernel sends txn_id=0 on both frames, so neither the read-only
--     nor the unknown-id branch can be reached from a guest.

local loregd = require("helpers.loregd")
local lcs = require("helpers.lcs")
local sys = require("helpers.sys")

local ROOT = loregd.KEY -- PtState\Durable

local vm = loregd.boot({ name = "loregd-layer" })
loregd.format(vm)
loregd.mount(vm)
loregd.start(vm)

loregd.new_key(vm, ROOT):assert_ok()

--- Open a PtState key on a worker, asserting the open; returns the fd.
local function open(t, who, path)
    local r = lcs.open_key(nil, who, -1, path, lcs.KEY_ALL_ACCESS, 0)
    t:assert(r.ret >= 0, "open " .. path .. ": ret=" .. tostring(r.ret) ..
        " errno=" .. sys.errname(r.errno or 0))
    return r.ret
end

-- ---------------------------------------------------------------------------
-- Reachable — RSI_FLUSH against the served hive.
-- ---------------------------------------------------------------------------

-- "Forces the hive's write-ahead log to be checkpointed so that all persistent
-- data is durable on disk (PRAGMA wal_checkpoint(TRUNCATE))." / "The volatile
-- store has no durability and is unaffected: nothing is flushed, and nothing
-- needs to be." A flush of the served PtState hive returns RSI_OK, and a
-- volatile value in that hive is untouched across it.
test("flush checkpoints the WAL for durability and leaves the volatile store untouched", {
    spec = "loregd *layer.flush-checkpoints-the-write-ahead-log-for-durability" ..
        " *layer.flush-leaves-the-volatile-store-untouched",
}, function(t)
    local W = vm:spawn_worker()

    -- A volatile value living in the same hive.
    vm:run("reg new '" .. ROOT .. "\\VolHold' --volatile"):assert_ok()
    local volfd = open(t, W, ROOT .. "\\VolHold")
    t:assert_eq(lcs.set_value(nil, W, volfd, "V", lcs.TYPE.DWORD, lcs.dword(9)).ret, 0,
        "seed a volatile value")

    -- Flush the persistent write-ahead log via any key fd in the hive.
    local root = open(t, W, ROOT)
    local fl = lcs.flush(nil, W, root)
    t:assert_eq(fl.ret, 0, "flush of the served hive checkpoints and returns RSI_OK: errno=" ..
        sys.errname(fl.errno or 0))

    -- The volatile value is unaffected by the checkpoint.
    local q = lcs.query_value(nil, W, volfd, "V")
    t:assert_eq(q.ret, 0, "the volatile value still reads after the flush: errno=" ..
        sys.errname(q.errno or 0))
    t:assert_eq(q.data, lcs.dword(9),
        "and is unchanged — the checkpoint left the volatile store untouched")

    W:kill(); W:join()
end)

-- "Two conditions return RSI_TXN_BUSY instead of checkpointing: Any
-- transaction is currently bound to the hive. A checkpoint on a connection
-- already held by a transaction would deadlock, so loregd declines
-- immediately rather than waiting." This also demonstrates the section
-- preamble: both operations take the hive's write connection directly, which
-- is why a bound transaction makes them decline rather than wait.
test("flush declines with TXN_BUSY while a transaction is bound to the hive", {
    spec = "loregd *layer.flush-declines-while-a-transaction-is-bound-to-the-hive" ..
        " *layer.both-operations-take-the-write-connection-directly-and-commit-their-own-work",
}, function(t)
    local A = vm:spawn_worker()
    local B = vm:spawn_worker()
    local fa = open(t, A, ROOT)
    local fb = open(t, B, ROOT)

    -- A binds a read-write transaction to the hive with a real write.
    local txn = assert(lcs.begin_transaction(A), "begin_transaction")
    local wa = lcs.set_value(nil, A, fa, "FlushGuard", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
    t:assert_eq(wa.ret, 0, "A binds the transaction to the hive with a write: errno=" ..
        sys.errname(wa.errno or 0))

    -- B's flush is refused immediately — it would deadlock on the held
    -- connection — rather than queueing behind the transaction.
    local busy = lcs.flush(nil, B, fb)
    t:assert(busy.ret ~= 0, "the flush does not succeed while a transaction is bound: ret=" ..
        tostring(busy.ret))
    t:assert_eq(busy.errno, sys.E.BUSY,
        "it declines with RSI_TXN_BUSY (EBUSY), not a wait: errno=" ..
        sys.errname(busy.errno or 0))

    -- Once the transaction commits and frees the write connection, the same
    -- flush checkpoints normally.
    t:assert_eq(lcs.commit(nil, A, txn).ret, 0, "A commits and frees the write connection")
    local ok = lcs.flush(nil, B, fb)
    t:assert_eq(ok.ret, 0, "and the flush now checkpoints: errno=" .. sys.errname(ok.errno or 0))

    sys.close(A, txn)
    A:kill(); A:join(); B:kill(); B:join()
end)

-- ---------------------------------------------------------------------------
-- Not guest-reachable — cited to loregd Go unit tests, each with the fact
-- that closes the guest route. All verified by reading AND running them:
--   go test ./internal/handler/ -run '^TestName$' -v
-- ---------------------------------------------------------------------------

-- "Both operations ... consult the request's transaction id before doing
-- anything — a read-only transaction may not mutate, and an unknown id is
-- refused — but neither can join one." A guest can only ever open a read-write
-- transaction (reg_begin_transaction is SYSCALL_DEFINE0), and the kernel sends
-- txn_id=0 on both the FLUSH and DELETE_LAYER frames, so the read-only-mutation
-- and unknown-id branches are unreachable from a guest.
-- TestReadOnlyTxnRejectsDeleteLayerAndFlush drives both handlers under a
-- read-only transaction and asserts each returns RSI_INVALID (and that the
-- layer rows are left intact).
test("both operations check the transaction id but cannot join one", {
    spec = "loregd *layer.both-operations-check-the-transaction-id-but-cannot-join-one",
    skip = true,
    covered_by = "go:loregd internal/handler::TestReadOnlyTxnRejectsDeleteLayerAndFlush",
}, function() end)

-- "Removes every entry belonging to one layer and reports the keys that the
-- removal left unreferenced." No REG_IOC_DELETE_LAYER exists in the uapi.
-- TestDeleteLayerPurgesEntries asserts the layer's path_entries and values are
-- gone (and a base-layer entry survives); TestDeleteLayerReportsOrphans asserts
-- the orphan set is returned.
test("delete layer removes every entry of one layer and reports the orphans", {
    spec = "loregd *layer.delete-layer-removes-every-entry-of-one-layer-and-reports-the-orphans",
    skip = true,
    covered_by = "go:loregd internal/handler::TestDeleteLayerPurgesEntries",
}, function() end)

-- "The operation is applied to every registered hive ... and the per-hive
-- orphan sets are concatenated into a single response array."
-- TestDeleteLayerOrphansAreReturnedInByteOrder builds THREE hives (Machine,
-- Users, Policy), seeds one orphan in each, issues one delete-layer, and
-- asserts all three orphans come back in the single concatenated array.
test("delete layer is applied to every registered hive", {
    spec = "loregd *layer.delete-layer-is-applied-to-every-registered-hive",
    skip = true,
    covered_by = "go:loregd internal/handler::TestDeleteLayerOrphansAreReturnedInByteOrder",
}, function() end)

-- "What remains is reachable only through the layer being deleted, and is
-- therefore orphaned by it." TestDeleteLayerReportsOrphans seeds a key
-- referenced ONLY in the deleted layer and asserts it is reported orphaned;
-- TestDeleteLayerPurgesEntries seeds a key also referenced from the base layer
-- and asserts it is NOT orphaned — the two halves of "referenced only by the
-- layer being deleted".
test("an orphan is a GUID referenced only by the layer being deleted", {
    spec = "loregd *layer.an-orphan-is-a-guid-referenced-only-by-the-layer-being-deleted",
    skip = true,
    covered_by = "go:loregd internal/handler::TestDeleteLayerReportsOrphans",
}, function() end)

-- "Both schemas are covered, and all six deletions run inside the same
-- transaction as the orphan computation." deleteLayerFromHive runs the orphan
-- SELECT and all six DELETEs (main + volatile × path_entries/values/blanket)
-- inside one BEGIN IMMEDIATE. TestDeleteLayerPurgesEntries covers the main
-- schema; TestDeleteLayerVolatileEntries covers the volatile schema (all three
-- volatile tables purged, base entry surviving, computed orphan-free) — the
-- two together exercise the combined compute-and-delete over both schemas.
test("the orphan computation and the deletions share one transaction", {
    spec = "loregd *layer.the-orphan-computation-and-the-deletions-share-one-transaction",
    skip = true,
    covered_by = "go:loregd internal/handler::TestDeleteLayerVolatileEntries",
}, function() end)

-- "The orphaned GUIDs are evicted from the hive cache (§4.2) and returned to
-- the caller." TestDeleteLayerReportsOrphans asserts the orphan GUID is
-- returned to the caller; the eviction is the h.guidCache.Delete loop over that
-- same returned set (handleDeleteLayer), exercised by the same call.
test("orphaned GUIDs are evicted from the hive cache and returned", {
    spec = "loregd *layer.orphaned-guids-are-evicted-from-the-hive-cache-and-returned",
    skip = true,
    covered_by = "go:loregd internal/handler::TestDeleteLayerReportsOrphans",
}, function() end)

-- "The response array is sorted into ascending byte order (§5.2)."
-- TestDeleteLayerOrphansAreReturnedInByteOrder assigns orphan GUIDs so hive
-- (map) order and byte order disagree, then asserts the returned array is
-- {0x11, 0x77, 0xCC} — ascending byte order.
test("delete layer returns the orphan set in ascending byte order", {
    spec = "loregd *layer.delete-layer-returns-the-orphan-set-in-ascending-byte-order",
    skip = true,
    covered_by = "go:loregd internal/handler::TestDeleteLayerOrphansAreReturnedInByteOrder",
}, function() end)

-- "A contended write is reported as RSI_TXN_BUSY ... the operation declines if
-- any transaction already holds a hive's write connection."
-- TestDeleteLayerDeclinesWhileATransactionHoldsAWrite binds a read-write
-- transaction with a real mutating op, then asserts delete-layer returns
-- RSI_TXN_BUSY (and succeeds once the transaction is aborted).
test("delete layer reports a contended write as TXN_BUSY", {
    spec = "loregd *layer.delete-layer-reports-a-contended-write-as-txn-busy",
    skip = true,
    covered_by = "go:loregd internal/handler::TestDeleteLayerDeclinesWhileATransactionHoldsAWrite",
}, function() end)

-- "Other failures are RSI_STORAGE_ERROR." A non-busy failure of the orphan
-- SELECT or one of the six DELETEs (e.g. an unreadable hive) maps to
-- RSI_STORAGE_ERROR (handleDeleteLayer's else branch). Not guest-reachable (no
-- REG_IOC_DELETE_LAYER), and no loregd unit test drives delete-layer against a
-- broken hive — TestAnUnreadableHiveReportsAStorageErrorNotNotFound covers
-- read/lookup/enum/query but NOT delete-layer.
-- PEI-TBD-loregd-deletelayer-storage-error-untested
test("delete layer reports other failures as storage error", {
    spec = "loregd *layer.delete-layer-reports-other-failures-as-storage-error",
    skip = "not guest-reachable (no REG_IOC_DELETE_LAYER) and no loregd unit test " ..
        "drives delete-layer against a failing hive to assert RSI_STORAGE_ERROR " ..
        "— PEI-TBD-loregd-deletelayer-storage-error-untested",
}, function() end)

-- "The request carries a hive name rather than a GUID." The flush wire request
-- is a bare hive-name string (no GUID field). TestFlush encodes a flush by hive
-- name ("Machine") and asserts RSI_OK; a guest cannot address flush by GUID.
test("flush identifies its hive by name rather than GUID", {
    spec = "loregd *layer.flush-identifies-its-hive-by-name-rather-than-guid",
    skip = true,
    covered_by = "go:loregd internal/handler::TestFlush",
}, function() end)

-- "It is matched case-insensitively against the registered hives by folded
-- name (§3.4)." The guest flush ioctl derives the (correctly-cased) name from
-- the key fd, so a case mismatch cannot be driven from a guest.
-- TestFlushCaseInsensitive flushes "MACHINE" against the registered "Machine"
-- and asserts RSI_OK.
test("flush matches the hive name case-insensitively by folded name", {
    spec = "loregd *layer.flush-matches-the-hive-name-case-insensitively-by-folded-name",
    skip = true,
    covered_by = "go:loregd internal/handler::TestFlushCaseInsensitive",
}, function() end)

-- "A name matching none returns RSI_INVALID." The guest flush ioctl always
-- names a registered hive (via the fd), so an unregistered name is not
-- guest-constructible. TestFlushInvalidHive flushes "NonExistent" and asserts
-- RSI_INVALID.
test("flush on an unregistered hive name returns INVALID", {
    spec = "loregd *layer.flush-on-an-unregistered-hive-name-returns-invalid",
    skip = true,
    covered_by = "go:loregd internal/handler::TestFlushInvalidHive",
}, function() end)

-- "The checkpoint itself reports that it could not complete because the
-- database was busy" (PRAGMA wal_checkpoint returns busy=1). That requires a
-- concurrent reader/writer blocking the truncating checkpoint; loregd's single
-- write connection and WAL model do not produce it from a guest, and no loregd
-- unit test drives a busy checkpoint (it would need to force wal_checkpoint to
-- report busy).
-- PEI-TBD-loregd-flush-checkpoint-busy-untested
test("flush returns TXN_BUSY when the checkpoint reports the database busy", {
    spec = "loregd *layer.flush-returns-txn-busy-when-the-checkpoint-reports-the-database-busy",
    skip = "not guest-reachable (loregd's single-writer WAL model does not make a " ..
        "truncating checkpoint report busy) and no loregd unit test drives a busy " ..
        "checkpoint — PEI-TBD-loregd-flush-checkpoint-busy-untested",
}, function() end)
