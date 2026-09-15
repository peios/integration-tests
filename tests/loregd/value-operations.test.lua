-- loregd §5.5 (value-operations) — RSI_QUERY_VALUES, RSI_SET_VALUE,
-- RSI_DELETE_VALUE_ENTRY and RSI_SET_BLANKET_TOMBSTONE.
--
-- Driven end to end against a real loregd serving the PtState hive: the LCS
-- client ioctls (helpers/lcs) route Caller -> kernel LCS -> loregd, so a plain
-- worker syscall against PtState just works (the kernel talks to loregd
-- directly; there is no Lua pump — see transactions.test.lua).
--
-- Value set/query/delete and the conditional-write (CAS) path are reachable
-- via the LCS set_value / query_value / query_values_batch / delete_value /
-- blanket_tombstone ioctls. A few properties are not observable from a guest
-- and are homed on the loregd Go unit tests that assert them directly, each
-- with the fact that closes the guest route:
--
--   * The RSI_QUERY_VALUES response carries the raw per-layer value entries
--     and the key's blanket-tombstone list, both sorted (§5.2). The kernel
--     LCS resolves those into a single effective value per name before any
--     caller sees them (pkm_lcs_effective_value_snapshot); the guest
--     query_value / query_values_batch ioctls return resolved values, never
--     the raw entry/blanket blocks. So "also returns the blanket-tombstone
--     state" and "sorts value entries and blanket tombstones" are internal to
--     the wire response.
--   * Which SQLite store (main vs volatile) a write lands in is not
--     inspectable from a guest; the two store-routing anchors are unit-cited.
--   * The CAS BEGIN-IMMEDIATE-cannot-begin path needs SQLITE_BUSY at bind
--     time, which loregd's single write connection (MaxOpenConns=1) never
--     produces — a second writer waits in the Go pool rather than hitting
--     SQLITE_BUSY — and no unit test drives it (PEI-TBD).

local loregd = require("helpers.loregd")
local lcs = require("helpers.lcs")
local sys = require("helpers.sys")

local ROOT = loregd.KEY -- PtState\Durable

local vm = loregd.boot({ name = "loregd-value" })
loregd.format(vm)
loregd.mount(vm)
loregd.start(vm)

loregd.new_key(vm, ROOT):assert_ok()

local W = vm:spawn_worker()

--- Open a PtState key, asserting the open succeeded; returns the fd.
local function open(t, path)
    local r = lcs.open_key(nil, W, -1, path, lcs.KEY_ALL_ACCESS, 0)
    t:assert(r.ret >= 0, "open " .. path .. ": ret=" .. tostring(r.ret) ..
        " errno=" .. sys.errname(r.errno or 0))
    return r.ret
end

--- reg new '<ROOT>\<leaf>' and open it; returns the fd.
local function fresh(t, leaf)
    local path = ROOT .. "\\" .. leaf
    loregd.new_key(vm, path):assert_ok()
    return open(t, path), path
end

--- Names present in a key's whole value set (RSI_QUERY_VALUES query-all).
local function batch_names(fd)
    local r = lcs.query_values_batch(nil, W, fd)
    local names = {}
    if r.ret == 0 and r.values then
        for _, v in ipairs(r.values) do names[v.name] = v end
    end
    return r, names
end

-- ---------------------------------------------------------------------------
-- Reachable — VM tests against the served hive.
-- ---------------------------------------------------------------------------

-- "Returns every layer's entry for one value, or for all of a key's values
-- when the request sets the query-all flag." / "An existing key with no values
-- returns RSI_OK with empty arrays."
test("set writes a value entry; query returns one value or all; a valueless key returns empty", {
    spec = "loregd *value.set-value-writes-one-layers-entry-for-a-value" ..
        " *value.query-values-returns-one-value-or-all-of-a-keys-values" ..
        " *value.query-values-on-a-key-with-no-values-returns-empty-arrays",
}, function(t)
    local fd = fresh(t, "ValA")

    -- A key that holds no values: RSI_OK with an empty array, not an error.
    local empty = lcs.query_values_batch(nil, W, fd)
    t:assert_eq(empty.ret, 0, "query-all on a valueless key returns RSI_OK: errno=" ..
        sys.errname(empty.errno or 0))
    t:assert_eq(empty.count, 0, "and an empty array (count=0), not an error: count=" ..
        tostring(empty.count))

    -- set_value writes one layer's entry for a value.
    local s1 = lcs.set_value(nil, W, fd, "One", lcs.TYPE.DWORD, lcs.dword(11))
    t:assert_eq(s1.ret, 0, "set value One: errno=" .. sys.errname(s1.errno or 0))

    -- Single-value query returns exactly that value's entry.
    local q1 = lcs.query_value(nil, W, fd, "One")
    t:assert_eq(q1.ret, 0, "query the single value One: errno=" .. sys.errname(q1.errno or 0))
    t:assert_eq(q1.type, lcs.TYPE.DWORD, "One came back as its written type (DWORD)")
    t:assert_eq(q1.data, lcs.dword(11), "One came back with its written data")

    -- A second value, then query-all returns BOTH of the key's values.
    local s2 = lcs.set_value(nil, W, fd, "Two", lcs.TYPE.DWORD, lcs.dword(22))
    t:assert_eq(s2.ret, 0, "set value Two: errno=" .. sys.errname(s2.errno or 0))

    local rb, names = batch_names(fd)
    t:assert_eq(rb.ret, 0, "query-all returns RSI_OK: errno=" .. sys.errname(rb.errno or 0))
    t:assert(names["One"], "query-all returned One")
    t:assert(names["Two"], "query-all returned Two — all of the key's values")
end)

-- "Removes one layer's entry for one value, from both stores ... No
-- rows-affected check, so deleting an absent entry succeeds."
test("delete removes a value entry; deleting an absent entry succeeds", {
    spec = "loregd *value.delete-value-entry-removes-one-layers-entry-from-both-stores" ..
        " *value.deleting-an-absent-value-entry-succeeds",
}, function(t)
    local fd = fresh(t, "ValB")

    local s = lcs.set_value(nil, W, fd, "Del", lcs.TYPE.DWORD, lcs.dword(7))
    t:assert_eq(s.ret, 0, "seed the value: errno=" .. sys.errname(s.errno or 0))
    local _, before = batch_names(fd)
    t:assert(before["Del"], "the value is present before the delete")

    local d = lcs.delete_value(nil, W, fd, "Del")
    t:assert_eq(d.ret, 0, "delete the value entry: errno=" .. sys.errname(d.errno or 0))
    local _, after = batch_names(fd)
    t:assert(not after["Del"], "the value entry is gone after the delete")

    -- No rows-affected check: deleting a value that never existed still OKs.
    local d2 = lcs.delete_value(nil, W, fd, "NeverExisted")
    t:assert_eq(d2.ret, 0, "deleting an absent value entry succeeds (RSI_OK): errno=" ..
        sys.errname(d2.errno or 0))
end)

-- "When the request carries a non-zero expected_sequence, the write is a
-- compare-and-swap ... If the row is absent, or its sequence differs, the
-- operation returns RSI_CAS_FAILED and writes nothing." / "Outside a
-- transaction, the check and the write are wrapped in their own BEGIN
-- IMMEDIATE transaction" — this unbound (TxnID==0) path is the one exercised
-- here: the matching CAS commits, the stale CAS rolls back writing nothing.
test("a non-zero expected_sequence is a compare-and-swap; a stale one fails and writes nothing", {
    spec = "loregd *value.a-non-zero-expected-sequence-makes-the-write-a-compare-and-swap" ..
        " *value.a-failed-compare-and-swap-returns-cas-failed-and-writes-nothing" ..
        " *value.an-unbound-conditional-write-wraps-itself-in-begin-immediate",
}, function(t)
    local fd = fresh(t, "ValC")

    -- Seed a value and read back the sequence loregd assigned to its entry.
    local s = lcs.set_value(nil, W, fd, "Cas", lcs.TYPE.DWORD, lcs.dword(1))
    t:assert_eq(s.ret, 0, "seed Cas: errno=" .. sys.errname(s.errno or 0))
    local q0 = lcs.query_value(nil, W, fd, "Cas")
    t:assert_eq(q0.ret, 0, "read Cas back: errno=" .. sys.errname(q0.errno or 0))
    local seq = q0.sequence

    -- Matching expected_sequence: the compare succeeds and the write lands.
    local hit = lcs.set_value(nil, W, fd, "Cas", lcs.TYPE.DWORD, lcs.dword(2), { expected_seq = seq })
    t:assert_eq(hit.ret, 0, "CAS with the matching sequence succeeds: errno=" ..
        sys.errname(hit.errno or 0))
    local q1 = lcs.query_value(nil, W, fd, "Cas")
    t:assert_eq(q1.data, lcs.dword(2), "the matched CAS wrote the new data")
    t:assert(q1.sequence ~= seq, "and advanced the entry's sequence (was " ..
        tostring(seq) .. ", now " .. tostring(q1.sequence) .. ")")

    -- Stale expected_sequence: CAS_FAILED (EAGAIN) and NOTHING is written.
    local stale = lcs.set_value(nil, W, fd, "Cas", lcs.TYPE.DWORD, lcs.dword(3), { expected_seq = seq })
    t:assert(stale.ret ~= 0, "a stale CAS does not succeed: ret=" .. tostring(stale.ret))
    t:assert_eq(stale.errno, sys.E.AGAIN,
        "a failed compare-and-swap returns RSI_CAS_FAILED (EAGAIN): errno=" ..
        sys.errname(stale.errno or 0) .. " (" .. tostring(stale.errno) .. ")")
    local q2 = lcs.query_value(nil, W, fd, "Cas")
    t:assert_eq(q2.data, lcs.dword(2),
        "and writes nothing — the value is still the matched-CAS data, not 3")
end)

-- "Inside a transaction, the caller's transaction already provides the
-- isolation." The CAS runs on the transaction's pinned connection with no
-- BEGIN IMMEDIATE of its own; the match/mismatch semantics are unchanged.
test("a conditional write inside a transaction relies on the caller's isolation", {
    spec = "loregd *value.a-conditional-write-inside-a-transaction-relies-on-the-callers-isolation",
}, function(t)
    local fd = fresh(t, "ValD")
    t:assert_eq(lcs.set_value(nil, W, fd, "TCas", lcs.TYPE.DWORD, lcs.dword(1)).ret, 0, "seed TCas")
    local seq = lcs.query_value(nil, W, fd, "TCas").sequence

    local txn = assert(lcs.begin_transaction(W), "begin_transaction")

    -- Matching CAS bound to the caller's transaction: succeeds on the pinned
    -- connection, no BEGIN IMMEDIATE of its own (that would deadlock the one
    -- write connection the transaction already holds).
    local hit = lcs.set_value(nil, W, fd, "TCas", lcs.TYPE.DWORD, lcs.dword(2),
        { expected_seq = seq, txn_fd = txn })
    t:assert_eq(hit.ret, 0, "matched CAS inside the transaction succeeds: errno=" ..
        sys.errname(hit.errno or 0))

    -- Stale CAS inside the same transaction still fails CAS_FAILED.
    local stale = lcs.set_value(nil, W, fd, "TCas", lcs.TYPE.DWORD, lcs.dword(3),
        { expected_seq = seq, txn_fd = txn })
    t:assert_eq(stale.errno, sys.E.AGAIN,
        "a stale CAS inside the transaction returns RSI_CAS_FAILED (EAGAIN): errno=" ..
        sys.errname(stale.errno or 0))

    t:assert_eq(lcs.commit(nil, W, txn).ret, 0, "the transaction commits")
    sys.close(W, txn)
    t:assert_eq(lcs.query_value(nil, W, fd, "TCas").data, lcs.dword(2),
        "the committed value is the matched-CAS data")
end)

-- A GUID that resolves to no hive is RSI_NOT_FOUND for every value operation.
-- A key created inside a transaction and rolled back leaves a handle that
-- still names its GUID but now belongs to no hive (the abort hook evicts it
-- from loregd's cache), so each op below re-probes and finds nothing —
-- exactly the request-dispatch ghost-handle route.
test("query, set, delete and blanket-tombstone on an unresolvable GUID all return NOT_FOUND", {
    spec = "loregd *value.query-values-on-an-unresolvable-guid-returns-not-found" ..
        " *value.set-value-on-an-unknown-key-guid-returns-not-found" ..
        " *value.delete-value-entry-on-an-unresolvable-guid-returns-not-found" ..
        " *value.set-blanket-tombstone-on-an-unknown-key-guid-returns-not-found",
}, function(t)
    local txn = assert(lcs.begin_transaction(W), "begin_transaction")
    local cr = lcs.create_key(nil, W, {
        path = ROOT .. "\\GhostVal", access = lcs.KEY_ALL_ACCESS, txn_fd = txn,
    })
    t:assert(cr.ret >= 0, "create the ghost key in a transaction: ret=" .. tostring(cr.ret) ..
        " errno=" .. sys.errname(cr.errno or 0))
    local ghost = cr.ret
    sys.close(W, txn) -- rollback: the row is removed and the GUID evicted from cache

    local q = lcs.query_value(nil, W, ghost, "X")
    t:assert_eq(q.errno, sys.E.NOENT,
        "query values on the unresolvable GUID returns RSI_NOT_FOUND (ENOENT): errno=" ..
        sys.errname(q.errno or 0))

    local s = lcs.set_value(nil, W, ghost, "X", lcs.TYPE.DWORD, lcs.dword(1))
    t:assert_eq(s.errno, sys.E.NOENT,
        "set value on the unknown key GUID returns RSI_NOT_FOUND (ENOENT): errno=" ..
        sys.errname(s.errno or 0))

    local d = lcs.delete_value(nil, W, ghost, "X")
    t:assert_eq(d.errno, sys.E.NOENT,
        "delete value entry on the unresolvable GUID returns RSI_NOT_FOUND (ENOENT): errno=" ..
        sys.errname(d.errno or 0))

    local b = lcs.blanket_tombstone(nil, W, ghost, "base", true)
    t:assert_eq(b.errno, sys.E.NOENT,
        "set blanket tombstone on the unknown key GUID returns RSI_NOT_FOUND (ENOENT): errno=" ..
        sys.errname(b.errno or 0))
end)

-- "Sets or clears the tombstone that masks every value a key holds in lower
-- layers." The masking itself is a kernel-resolution property (a base-layer
-- blanket masks only layers below base, i.e. nothing a guest can see), but the
-- operation — the INSERT OR REPLACE that sets it and the DELETE that clears it
-- — reaches loregd and is exercised here end to end.
test("set and clear a blanket tombstone", {
    spec = "loregd *value.a-blanket-tombstone-masks-every-value-in-lower-layers",
}, function(t)
    local fd = fresh(t, "ValE")

    local set = lcs.blanket_tombstone(nil, W, fd, "base", true)
    t:assert_eq(set.ret, 0, "set the blanket tombstone: errno=" .. sys.errname(set.errno or 0))

    local clear = lcs.blanket_tombstone(nil, W, fd, "base", false)
    t:assert_eq(clear.ret, 0, "clear the blanket tombstone: errno=" .. sys.errname(clear.errno or 0))
end)

-- ---------------------------------------------------------------------------
-- Not guest-observable — cited to loregd Go unit tests, each with the fact
-- that closes the guest route.
-- ---------------------------------------------------------------------------

-- The QUERY_VALUES wire response carries the key's blanket-tombstone list
-- beside the value entries. The kernel LCS consumes it during value
-- resolution; the guest query ioctls surface only resolved values, never the
-- blanket block. TestQueryValuesWithBlanketTombstone asserts the response
-- carries blanketCount=1 with the stored layer ("gpo-1") and sequence (20).
test("query values also returns the blanket-tombstone state", {
    spec = "loregd *value.query-values-also-returns-the-blanket-tombstone-state",
    skip = true,
    covered_by = "go:loregd internal/handler::TestQueryValuesWithBlanketTombstone",
}, function() end)

-- Both the value entries and the blanket list travel sorted (§5.2). The sort
-- is applied inside loregd before the wire response the kernel resolves away,
-- so it is not guest-observable. TestBlanketTombstonesAreReturnedInACanonicalOrder
-- inserts blankets out of order across both stores and asserts a stable
-- (folded layer, sequence) order over 50 repeated calls; the value entries
-- beside them are sorted by the same key (queryValueEntries).
test("query values sorts value entries and blanket tombstones", {
    spec = "loregd *value.query-values-sorts-value-entries-and-blanket-tombstones",
    skip = true,
    covered_by = "go:loregd internal/handler::TestBlanketTombstonesAreReturnedInACanonicalOrder",
}, function() end)

-- The key's volatile flag selects main vs volatile [values]. Which SQLite
-- store holds a value is not inspectable from a guest. TestSetValueVolatileKey
-- sets a value on a volatile key and asserts it lands in volatile.[values]
-- with zero rows in main.[values].
test("set value targets the store of the key's volatile flag", {
    spec = "loregd *value.set-value-targets-the-store-of-the-keys-volatile-flag",
    skip = true,
    covered_by = "go:loregd internal/handler::TestSetValueVolatileKey",
}, function() end)

-- Same store-routing question for blanket tombstones, same guest-blindness.
-- TestSetBlanketTombstoneVolatileKey asserts a blanket set on a volatile key
-- lands in volatile.blanket_tombstones with zero rows in main.
test("set blanket tombstone targets the store of the key's volatile flag", {
    spec = "loregd *value.set-blanket-tombstone-targets-the-store-of-the-keys-volatile-flag",
    skip = true,
    covered_by = "go:loregd internal/handler::TestSetBlanketTombstoneVolatileKey",
}, function() end)

-- "If that transaction cannot begin because the database is busy, the
-- operation returns RSI_TXN_BUSY." The BEGIN IMMEDIATE for an unbound CAS can
-- only report SQLITE_BUSY if another connection holds the hive's write lock,
-- which loregd's single write connection (MaxOpenConns=1) forbids: a second
-- writer waits in the Go pool rather than reaching BEGIN IMMEDIATE. So this
-- defensive path is not guest-reachable, and no loregd unit test drives it.
-- PEI-TBD-loregd-cas-begin-busy-untested
test("a conditional write that cannot begin its transaction returns TXN_BUSY", {
    spec = "loregd *value.a-conditional-write-that-cannot-begin-its-transaction-returns-txn-busy",
    skip = "not guest-reachable: with one write connection a second writer waits " ..
        "in the pool rather than hitting SQLITE_BUSY at BEGIN IMMEDIATE, and no " ..
        "loregd unit test drives it — PEI-TBD-loregd-cas-begin-busy-untested",
}, function() end)
