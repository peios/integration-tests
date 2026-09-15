-- loregd §5.7 (Status Codes) — the seven RSI status codes loregd returns and
-- the three it never produces.
--
-- A guest never sees a raw RSI status: the kernel translates it to an errno
-- (pkm/lcs/source_response_plan.c pkm_lcs_rsi_status_errno):
--   RSI_OK->0  NOT_FOUND->ENOENT  ALREADY_EXISTS->EEXIST  STORAGE_ERROR->EIO
--   NOT_EMPTY->ENOTEMPTY  TOO_LARGE->ENOSPC  TXN_BUSY->EBUSY  INVALID->EINVAL
--   CAS_FAILED->EAGAIN  TXN_NOT_SUPPORTED->EOPNOTSUPP
-- The map is 1:1, but the same errno is also produced by the kernel's own
-- path walk and argument validation *before* a request ever reaches loregd
-- (ENOENT for a missing path component, EINVAL for a rejected ioctl), and for
-- creates the kernel absorbs RSI_ALREADY_EXISTS into an OPENED_EXISTING
-- disposition rather than surfacing EEXIST (source_response_plan.c:76). So for
-- most codes the errno a guest sees does not prove loregd returned that
-- status; those anchors are homed on internal unit tests, each read and run
-- (all PASS) before citing, with the guest route shown closed. RSI_OK (a
-- successful op and an idempotent delete) and RSI_CAS_FAILED (a conditional
-- set that does not match -> EAGAIN, which the kernel does not synthesise on
-- its own) ARE guest-observable and are the two VM cases here.

local loregd = require("helpers.loregd")
local lcs = require("helpers.lcs")
local sys = require("helpers.sys")

local vm = loregd.boot({ name = "loregd-status" })
loregd.format(vm)
loregd.mount(vm)
loregd.start(vm) -- one daemon for the whole file; no restart needed here

-- ==== reachable: RSI_OK and RSI_CAS_FAILED =============================

-- §5.7: "RSI_OK | 0 | The operation succeeded. Also returned by the
-- idempotent deletions when their target was already absent." A successful
-- write returns exit 0 (RSI_OK->0). An RSI_DELETE_VALUE_ENTRY whose target is
-- absent returns RSI_OK -> the ioctl returns 0, proving the idempotent-OK path
-- end to end.
-- This case also carries the summary anchor: loregd returns exactly seven RSI
-- codes. The other six are homed below — OK (here), CAS_FAILED (next),
-- NOT_FOUND, ALREADY_EXISTS, STORAGE_ERROR, TXN_BUSY, INVALID (unit-cited).
test("RSI_OK on success and on an idempotent deletion", {
    spec = "loregd *status.ok-is-returned-on-success-and-by-an-idempotent-deletion " ..
        "*status.loregd-returns-seven-of-the-rsi-status-codes",
}, function(t)
    local key = [[PtState\Ok]]
    loregd.new_key(vm, key):assert_ok()
    -- Success -> RSI_OK -> exit 0.
    loregd.set(vm, key, "Present", "dword:1"):assert_ok()

    -- Idempotent deletion of an absent value: RSI_DELETE_VALUE_ENTRY returns
    -- RSI_OK even though nothing matched. Driven through LCS so the ioctl's
    -- own return is observed (ret == 0), not reg's client-side view.
    local w = vm:spawn_worker()
    local r = lcs.open_key(nil, w, -1, key, lcs.KEY_ALL_ACCESS)
    t:assert(r.ret >= 0, "open " .. key .. ": " .. sys.errname(r.errno or 0))
    local dv = lcs.delete_value(nil, w, r.ret, "NeverExisted", {})
    t:assert_eq(dv.ret, 0,
        "deleting a value that was never there returns RSI_OK (0): got ret=" ..
        tostring(dv.ret) .. " errno=" .. sys.errname(dv.errno or 0))
end)

-- §5.7: "RSI_CAS_FAILED | 8 | A conditional RSI_SET_VALUE whose target was
-- absent or whose sequence did not match." A conditional set (expected_sequence
-- != 0) on a value that does not exist fails the CAS; loregd returns
-- RSI_CAS_FAILED, which the kernel maps to EAGAIN. The kernel does not perform
-- the compare itself — it forwards expected_sequence to the source — so an
-- EAGAIN here is loregd's status, observed end to end.
test("RSI_CAS_FAILED on a conditional set that does not match", {
    spec = "loregd *status.cas-failed-is-returned-when-a-conditional-set-value-does-not-match",
}, function(t)
    local key = [[PtState\Cas]]
    loregd.new_key(vm, key):assert_ok()

    local w = vm:spawn_worker()
    local r = lcs.open_key(nil, w, -1, key, lcs.KEY_ALL_ACCESS)
    t:assert(r.ret >= 0, "open " .. key .. ": " .. sys.errname(r.errno or 0))

    -- Conditional set on an absent value, demanding sequence 5. CAS fails.
    local sv = lcs.set_value(nil, w, r.ret, "Ghost", lcs.TYPE.DWORD, lcs.dword(1),
        { expected_seq = 5 })
    t:assert(sv.ret ~= 0,
        "a conditional set on an absent value must not succeed (ret=" ..
        tostring(sv.ret) .. ")")
    t:assert_eq(sv.errno, sys.E.AGAIN,
        "a mismatched conditional set surfaces RSI_CAS_FAILED as EAGAIN; got " ..
        sys.errname(sv.errno or 0))
end)

-- ==== unit-cited: statuses the kernel translates or the guest cannot reach ==

-- §5.7: "RSI_NOT_FOUND | 1 | A named key GUID exists in neither store, or
-- resolves to no registered hive. Also an update matching no row."
-- TestSetValueKeyNotFound (and TestReadKeyNotFound / TestQueryValuesKeyNotFound)
-- assert RSI_NOT_FOUND when the GUID is in neither store. Route closed: a
-- guest names paths, and the kernel's path walk answers ENOENT for a missing
-- component before dispatching to loregd, so the ENOENT a guest observes is
-- not attributable to loregd's RSI_NOT_FOUND specifically.
test("RSI_NOT_FOUND for an unknown GUID or unresolvable hive", {
    spec = "loregd *status.not-found-is-returned-for-an-unknown-guid-or-unresolvable-hive",
    skip = true,
    covered_by = "go:loregd internal/handler::TestSetValueKeyNotFound",
}, function() end)

-- §5.7: "RSI_ALREADY_EXISTS | 2 | A duplicate key GUID or path entry: the
-- target table's primary key, or the matching check against the other store."
-- TestCreateKeyDuplicate and TestCreateEntryDuplicate assert RSI_ALREADY_EXISTS
-- on a re-create; TestCreateKeyRejectsGUIDHeldByTheOtherStore /
-- TestCreateEntryRejectsTripleHeldByTheOtherStore cover the cross-store check.
-- Route closed: for a create the kernel converts RSI_ALREADY_EXISTS into an
-- OPENED_EXISTING disposition (source_response_plan.c:76-80), so a guest that
-- re-creates a key sees a successful open, never EEXIST — the status is not
-- guest-observable.
test("RSI_ALREADY_EXISTS for a duplicate key GUID or path entry", {
    spec = "loregd *status.already-exists-is-returned-for-a-duplicate-key-guid-or-path-entry",
    skip = true,
    covered_by = "go:loregd internal/handler::TestCreateKeyDuplicate",
}, function() end)

-- §5.7: "No value operation produces it — every value write is an
-- INSERT OR REPLACE." TestSetValueReplace writes over an existing value and
-- gets RSI_OK with the data replaced, never RSI_ALREADY_EXISTS. Structural:
-- there is no code path from a value write to StatusAlreadyExists (values.go
-- uses INSERT OR REPLACE throughout).
test("no value operation returns RSI_ALREADY_EXISTS", {
    spec = "loregd *status.no-value-operation-returns-already-exists",
    skip = true,
    covered_by = "go:loregd internal/handler::TestSetValueReplace",
}, function() end)

-- §5.7: "RSI_STORAGE_ERROR | 3 | A SQLite failure while serving the request.
-- Also an operation whose GUID belongs to a hive other than the one its
-- transaction is bound to, a mutating operation carrying an unknown
-- transaction id, and a failed commit that was not busy."
-- TestAnUnreadableHiveReportsAStorageErrorNotNotFound closes a hive under the
-- handler and asserts read key / lookup / enum / query values all return
-- RSI_STORAGE_ERROR (not NOT_FOUND). Route closed: a guest cannot make SQLite
-- fail, and the kernel binds each transaction to one hive and hardcodes the
-- txn id, so it cannot present a cross-hive or unknown-txn frame.
test("RSI_STORAGE_ERROR for a SQLite failure or a transaction mismatch", {
    spec = "loregd *status.storage-error-is-returned-for-a-sqlite-failure-or-a-transaction-mismatch",
    skip = true,
    covered_by = "go:loregd internal/handler::TestAnUnreadableHiveReportsAStorageErrorNotNotFound",
}, function() end)

-- §5.7: "RSI_TXN_BUSY | 6 | BEGIN IMMEDIATE found the database busy, a
-- conditional write could not begin its transaction, or RSI_FLUSH or
-- RSI_DELETE_LAYER found a transaction already bound to a hive's write
-- connection." TestDeleteLayerDeclinesWhileATransactionHoldsAWrite binds the
-- write connection with a mutating op, then asserts RSI_DELETE_LAYER returns
-- RSI_TXN_BUSY. Route closed: there is no REG_IOC_DELETE_LAYER in the uapi and
-- the kernel hardcodes txn_id=0 on RSI_FLUSH, so a guest cannot drive the
-- bound-connection contention that yields this status deterministically.
test("RSI_TXN_BUSY when a write cannot take the database", {
    spec = "loregd *status.txn-busy-is-returned-when-a-write-cannot-take-the-database",
    skip = true,
    covered_by = "go:loregd internal/handler::TestDeleteLayerDeclinesWhileATransactionHoldsAWrite",
}, function() end)

-- §5.7: "RSI_INVALID | 7 | An unknown opcode, a request whose payload cannot
-- be decoded, an out-of-range RSI_WRITE_KEY field mask, a mutating operation
-- carrying a read-only transaction id, an RSI_FLUSH naming an unregistered
-- hive, or an RSI_BEGIN_TRANSACTION re-using an active id."
-- TestWriteKeyInvalidMask asserts RSI_INVALID for a mask with a spare bit set;
-- the other triggers are covered by TestDispatchUnknownOpCode (unknown
-- opcode), TestReadOnlyTxnRejectsMutation (mutation on a read-only txn),
-- TestFlushInvalidHive (unregistered hive) and TestBeginTransactionDuplicate
-- (re-used active id). Route closed: the kernel builds and validates every RSI
-- frame it sends, so a guest cannot inject an unknown opcode or undecodable
-- payload, and reg_begin_transaction is SYSCALL_DEFINE0 with no read-only mode
-- a guest could tag a mutation with.
test("RSI_INVALID for a malformed or unacceptable request", {
    spec = "loregd *status.invalid-is-returned-for-a-malformed-or-unacceptable-request",
    skip = true,
    covered_by = "go:loregd internal/handler::TestWriteKeyInvalidMask",
}, function() end)

-- ==== unit/structural: the three codes loregd never produces ============

-- §5.7: "Three codes are defined by the interface and never produced by
-- loregd: RSI_NOT_EMPTY (4), RSI_TOO_LARGE (5), and RSI_TXN_NOT_SUPPORTED
-- (9)." Structural: a grep of internal/handler and internal/rsi for
-- StatusNotEmpty / StatusTooLarge / StatusTxnNotSupported finds no return
-- site (only the constant definitions in rsi/constants.go). loregd never
-- checks a key for emptiness before dropping it (drop/delete are
-- unconditional), never rejects a transaction mode (next), and never answers
-- an oversized frame (below). TestReadOnlyTxnRejectsMutation is cited as the
-- representative that the alternative paths are taken (a read-only txn is
-- accepted, not refused with TXN_NOT_SUPPORTED).
test("three interface codes are never produced by loregd", {
    spec = "loregd *status.three-interface-codes-are-never-produced-by-loregd",
    skip = true,
    covered_by = "go:loregd internal/handler::TestReadOnlyTxnRejectsMutation",
}, function() end)

-- §5.7: "RSI_TXN_NOT_SUPPORTED is never needed because loregd supports both
-- transaction modes." TestReadOnlyTxnRejectsMutation begins an
-- RSI_TXN_READ_ONLY transaction and gets RSI_OK (loregd accepts the read-only
-- mode); read-write is the default every other transaction test exercises. So
-- loregd never returns RSI_TXN_NOT_SUPPORTED. Structural / not guest-drivable:
-- reg_begin_transaction takes no mode argument.
test("RSI_TXN_NOT_SUPPORTED is never returned", {
    spec = "loregd *status.txn-not-supported-is-never-returned",
    skip = true,
    covered_by = "go:loregd internal/handler::TestReadOnlyTxnRejectsMutation",
}, function() end)

-- §5.7: "RSI_TOO_LARGE is never returned because an oversized or malformed
-- frame is not answered at all. Framing is validated before an opcode is
-- known, and a frame that fails validation ends the connection instead of
-- producing a response." TestServeMalformedFramingTearsDown feeds a frame
-- whose total_len does not match its length; Serve returns an error (tears the
-- connection down) rather than writing any response. TestRequestHeaderExceedsMaxSize
-- shows an oversized total_len is rejected at the framing layer. So loregd
-- never emits RSI_TOO_LARGE. Not guest-observable: the connection is gone, not
-- a status.
test("RSI_TOO_LARGE is never returned because a bad frame ends the connection", {
    spec = "loregd *status.too-large-is-never-returned-because-a-bad-frame-ends-the-connection",
    skip = true,
    covered_by = "go:loregd internal/device::TestServeMalformedFramingTearsDown",
}, function() end)
