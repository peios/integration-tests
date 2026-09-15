-- loregd book §5 "Key Operations" (5--request-handling/3--key-operations.md):
-- RSI_CREATE_KEY, RSI_READ_KEY, RSI_WRITE_KEY, RSI_DROP_KEY.
--
-- What a guest can observe of these against a real loregd, and how:
--
--   * A key created through `reg`/LCS round-trips: it reads back, and its
--     stored metadata (volatile flag, symlink flag, last_write_time, SD size)
--     comes back through RSI_READ_KEY. The kernel's REG_IOC_QUERY_KEY_INFO and
--     REG_IOC_GET_SECURITY both issue RSI_READ_KEY to loregd (pkm lcs/key_fd.c),
--     so `lcs.query_key_info` / `lcs.get_security` are the read-key probe, and
--     `reg info --json` echoes the same fields. (loregd has no QUERY_KEY_INFO
--     handler of its own; the info block is composed from RSI_READ_KEY plus
--     RSI_ENUM_CHILDREN.)
--   * RSI_WRITE_KEY is reachable only through its SD field: REG_IOC_SET_SECURITY
--     sends a write-key with field-mask bit 0 (SD). There is no guest ioctl that
--     carries an arbitrary field mask, so the mask-detail anchors (bit 1, spare
--     bits, the zero-mask existence check, no-row NOT_FOUND) are cited to Go
--     unit tests — the route that would forge a mask is closed.
--   * RSI_DROP_KEY is never issued by a guest request: the kernel emits it as
--     garbage collection when the last handle to an orphaned (delete-entried)
--     key closes (pkm lcs/key_fd.c:632). A guest sees only the key's absence,
--     which RSI_DELETE_ENTRY already produced, so the drop-key purge/atomicity/
--     cache anchors are cited to Go unit tests.
--   * A GUID is minted by LCS, never chosen by a guest, and an existing name is
--     opened rather than re-created, so a duplicate-GUID create cannot be forged
--     from a guest either — those two anchors are cited too.
--
-- One file-scope loregd on the PtState hive; every case drives it. No clean
-- SIGTERM is taken (idle loregd hangs on it, PEI-1122); the daemon is reaped
-- when the file ends.

local loregd = require("helpers.loregd")
local lcs = require("helpers.lcs")
local sys = require("helpers.sys")
local access = require("helpers.access")
local kacs = require("helpers.kacs")

local vm = loregd.boot({ name = "loregd-key" })
loregd.format(vm)
loregd.mount(vm)
loregd.start(vm)

local W = vm:spawn_worker()

--- Open a key and return its fd, or fail the test.
local function open(t, path)
    local r = lcs.open_key(nil, W, -1, path, lcs.KEY_ALL_ACCESS, 0)
    t:assert(r.ret >= 0, "open " .. path .. ": " .. sys.errname(r.errno or 0))
    return r.ret
end

--- A handle naming a GUID that resolves to no hive: create it inside a
--- read-write transaction, then roll the transaction back (closing the txn fd
--- aborts). The handle survives; the GUID it names does not.
local function ghost(t, path)
    local txn = lcs.begin_transaction(W)
    t:assert(txn, "begin_transaction for ghost")
    local cr = lcs.create_key(nil, W, { path = path, access = lcs.KEY_ALL_ACCESS, txn_fd = txn })
    t:assert(cr.ret >= 0, "create ghost " .. path .. ": " .. sys.errname(cr.errno or 0))
    sys.close(W, txn) -- abort
    return cr.ret
end

--- A DACL-only key SD, sized by how many ACEs it carries, so a write of a
--- larger SD is observable as a larger sd_size.
local function sd_with(n)
    local aces = {}
    local sids = { kacs.SID.EVERYONE, kacs.SID.AUTHENTICATED_USERS,
                   kacs.SID.ADMINISTRATORS, kacs.SID.LOCAL_SYSTEM }
    for i = 1, n do
        aces[i] = access.ace(access.ACE.ALLOWED, lcs.RIGHT.KEY_ALL_ACCESS,
            sids[(i - 1) % #sids + 1])
    end
    return lcs.sd(aces)
end

-- ============================ RSI_CREATE_KEY ============================

-- §5: "For a persistent key: INSERT INTO keys (...) VALUES (...)." The insert
-- is observable as the key existing afterwards — it reads back and enumerates
-- under its parent.
test("create key inserts a new key row that reads back",
    { spec = "loregd *key.create-key-inserts-a-new-key-row" },
    function(t)
        loregd.new_key(vm, [[PtState\Durable\Made]]):assert_ok()
        t:assert_eq(vm:run("reg info 'PtState\\Durable\\Made'").exit_code, 0,
            "the created key reads back (the INSERT landed a row)")
        local ls = vm:run("reg ls 'PtState\\Durable' --keys-only")
        ls:assert_ok()
        t:assert(ls.stdout:match("Made/"),
            "and enumerates under its parent: " .. ls.stdout)
    end)

-- §5: "last_write_time is not carried in the request. loregd sets it to the
-- current wall-clock time in Unix nanoseconds at insertion."
test("last write time is set by loregd at insertion",
    { spec = "loregd *key.last-write-time-is-set-by-loregd-at-insertion" },
    function(t)
        loregd.new_key(vm, [[PtState\Durable\LwtA]]):assert_ok()
        local a = lcs.query_key_info(nil, W, open(t, [[PtState\Durable\LwtA]]))
        t:assert_eq(a.ret, 0, "read key A: " .. sys.errname(a.errno or 0))
        -- A brief gap, then a second key: its stamp must be strictly later.
        vm:run("sleep 0.05")
        loregd.new_key(vm, [[PtState\Durable\LwtB]]):assert_ok()
        local b = lcs.query_key_info(nil, W, open(t, [[PtState\Durable\LwtB]]))
        t:assert_eq(b.ret, 0, "read key B: " .. sys.errname(b.errno or 0))

        local now = tonumber((vm:run("date +%s%N").stdout:gsub("%s+$", "")))
        -- Unix-nanosecond wall clock: past a 2020 epoch, not in the future.
        t:assert(a.last_write_time > 1600000000000000000 and a.last_write_time <= now,
            "last_write_time is a current wall-clock ns value set at insertion: "
            .. tostring(a.last_write_time) .. " (now " .. tostring(now) .. ")")
        t:assert(b.last_write_time > a.last_write_time,
            "the later insertion carries the later stamp — loregd set each at "
            .. "insertion, not a constant: A=" .. tostring(a.last_write_time)
            .. " B=" .. tostring(b.last_write_time))
    end)

-- §5: "An unresolvable parent GUID returns RSI_NOT_FOUND, after a fallback
-- check of the registered hives' root GUIDs."
-- Route closed at the guest: LCS dispatches RSI_CREATE_ENTRY (whose own parent
-- check fires first — see path-entry-operations *create-entry-on-an-
-- unresolvable-parent) before RSI_CREATE_KEY, so a guest create against an
-- unresolvable parent is refused before create-key's parent check is reached.
-- The cited test drives handleCreateKey directly with an unknown parent GUID.
test("create key on an unresolvable parent returns not-found (create-key's own check)",
    {
        spec = "loregd *key.an-unresolvable-parent-guid-returns-not-found",
        skip = true,
        covered_by = "go:loregd internal/handler::TestCreateKeyUnknownParent",
    }, function() end)

-- §5: "Uniqueness comes from the target table's primary key on guid, surfaced
-- as RSI_ALREADY_EXISTS."
-- Route closed: a key GUID is minted by LCS (PKM §5.2.3), never chosen by a
-- guest, and opening an existing name returns the existing handle rather than
-- re-issuing RSI_CREATE_KEY. A guest can therefore never present a duplicate
-- GUID to create-key. The cited test creates twice with the same GUID.
test("a duplicate GUID in the target table returns already-exists",
    {
        spec = "loregd *key.a-duplicate-guid-in-the-target-table-returns-already-exists",
        skip = true,
        covered_by = "go:loregd internal/handler::TestCreateKeyDuplicate",
    }, function() end)

-- §5: "loregd also asks the other store whether it holds the GUID before
-- inserting, and answers RSI_ALREADY_EXISTS if it does."
-- Route closed: as above, and a guest additionally cannot steer the same GUID
-- into both the persistent and volatile store. The cited table-driven test
-- creates the GUID in one store then the other and asserts it ends up in
-- exactly one.
test("a GUID held by the other store also returns already-exists",
    {
        spec = "loregd *key.a-guid-held-by-the-other-store-also-returns-already-exists",
        skip = true,
        covered_by = "go:loregd internal/handler::TestCreateKeyRejectsGUIDHeldByTheOtherStore",
    }, function() end)

-- §5: "The new GUID is added to the hive cache immediately, before the
-- enclosing transaction commits, with an abort hook to remove it if that
-- transaction rolls back."
test("a created GUID is cached before commit and dropped on rollback",
    { spec = "loregd *key.the-new-guid-is-cached-before-commit-and-dropped-on-rollback" },
    function(t)
        local txn = lcs.begin_transaction(W)
        t:assert(txn, "begin_transaction")
        local ck = lcs.create_key(nil, W, {
            path = [[PtState\Durable\CachedK]], access = lcs.KEY_ALL_ACCESS, txn_fd = txn })
        t:assert(ck.ret >= 0, "create key in txn: " .. sys.errname(ck.errno or 0))

        -- Create a child UNDER the just-created, still-uncommitted parent, in
        -- the same transaction. This resolves the parent only through the hive
        -- cache: the read pool cannot see a row the transaction has not
        -- committed. Its success is the proof the GUID was cached before commit.
        local sub = lcs.create_key(nil, W, {
            parent_fd = ck.ret, path = "Sub", access = lcs.KEY_ALL_ACCESS, txn_fd = txn })
        t:assert(sub.ret >= 0,
            "a child of the uncommitted parent creates — the parent GUID was in "
            .. "the cache before its transaction committed: " .. sys.errname(sub.errno or 0))

        sys.close(W, txn) -- abort: the abort hook must evict the cached GUID

        -- If the GUID had been left in the cache, resolveHive would hit the
        -- stale entry and answer (empty) OK; getting NOT_FOUND means it was
        -- evicted on rollback.
        local q = lcs.query_key_info(nil, W, ck.ret)
        t:assert(q.ret ~= 0 and q.errno == sys.E.NOENT,
            "after rollback the GUID resolves to no hive (NOT_FOUND), so the "
            .. "abort hook dropped it from the cache: ret=" .. tostring(q.ret)
            .. " errno=" .. sys.errname(q.errno or 0))
    end)

-- ============================ RSI_READ_KEY =============================

-- §5: the read-key SELECT returns "name, parent_guid, sd, volatile, symlink,
-- last_write_time"; "The volatile field in the response is the stored column
-- value." REG_IOC_QUERY_KEY_INFO issues RSI_READ_KEY, so its returned block is
-- read-key's stored metadata.
test("read key returns the stored key metadata, and the volatile field is the stored column", {
    spec = "loregd *key.read-key-returns-the-stored-key-metadata " ..
        "*key.the-volatile-field-returned-is-the-stored-column-value",
}, function(t)
    loregd.new_key(vm, [[PtState\Durable\MetaP]]):assert_ok()
    vm:run("reg new 'PtState\\Durable\\MetaV' --volatile"):assert_ok()

    local p = lcs.query_key_info(nil, W, open(t, [[PtState\Durable\MetaP]]))
    t:assert_eq(p.ret, 0, "read persistent key: " .. sys.errname(p.errno or 0))
    t:assert(p.sd_size > 0, "read-key returned the stored SD (size " .. tostring(p.sd_size) .. ")")
    t:assert_eq(p.symlink, false, "read-key returned the stored symlink flag (false)")
    t:assert_eq(p.volatile, false,
        "the volatile field returned for a persistent key is its stored 0")

    local v = lcs.query_key_info(nil, W, open(t, [[PtState\Durable\MetaV]]))
    t:assert_eq(v.ret, 0, "read volatile key: " .. sys.errname(v.errno or 0))
    t:assert_eq(v.volatile, true,
        "and for a volatile key is its stored 1 — the field is the stored column")

    -- reg info --json exposes the same read-key metadata to a plain caller.
    local j = vm:run("reg info 'PtState\\Durable\\MetaV' --json")
    j:assert_ok()
    t:assert(j.stdout:match('"volatile"%s*:%s*true'),
        "reg info echoes the same stored volatile column: " .. j.stdout)
end)

-- §5: "RSI_NOT_FOUND if the GUID is in neither store, and likewise if it
-- resolves to no hive." A rolled-back GUID satisfies both descriptions at once
-- (it is in no store and belongs to no hive); a read on its handle answers
-- NOT_FOUND.
test("read key returns not-found for a GUID in neither store / resolving to no hive", {
    spec = "loregd *key.read-key-returns-not-found-for-a-guid-in-neither-store " ..
        "*key.read-key-returns-not-found-when-the-guid-resolves-to-no-hive",
}, function(t)
    local g = ghost(t, [[PtState\Durable\NoSuchKey]])
    local q = lcs.query_key_info(nil, W, g)
    t:assert(q.ret ~= 0 and q.errno == sys.E.NOENT,
        "a read-key on a GUID in neither store and resolving to no hive is "
        .. "NOT_FOUND (ENOENT): ret=" .. tostring(q.ret)
        .. " errno=" .. sys.errname(q.errno or 0))
end)

-- ============================ RSI_WRITE_KEY ============================

-- §5: RSI_WRITE_KEY "Updates the two mutable fields of a key, selected by a
-- field mask": bit 0 (0x01) selects sd. REG_IOC_SET_SECURITY sends exactly
-- this write-key. Writing a larger SD grows the stored SD, observably, and
-- outside a transaction it takes effect immediately — a single auto-committed
-- statement, with no commit step.
test("write key updates the SD (mask bit 0), outside a transaction as one auto-committed statement", {
    spec = "loregd *key.mask-bit-0-selects-the-security-descriptor " ..
        "*key.write-key-outside-a-transaction-is-one-auto-committed-statement",
}, function(t)
    loregd.new_key(vm, [[PtState\Durable\SdKey]]):assert_ok()
    local fd = open(t, [[PtState\Durable\SdKey]])
    local before = lcs.query_key_info(nil, W, fd)
    t:assert_eq(before.ret, 0, "read SD size before: " .. sys.errname(before.errno or 0))

    local s = lcs.set_security(nil, W, fd, lcs.SI.DACL, sd_with(4))
    t:assert_eq(s.ret, 0, "set_security issues write-key(sd): " .. sys.errname(s.errno or 0))

    local after = lcs.query_key_info(nil, W, fd)
    t:assert_eq(after.ret, 0, "read SD size after: " .. sys.errname(after.errno or 0))
    t:assert(after.sd_size > before.sd_size,
        "write-key set the sd field (bit 0): the stored SD grew from "
        .. tostring(before.sd_size) .. " to " .. tostring(after.sd_size)
        .. ", and was visible immediately with no commit — one auto-committed statement")
end)

-- §5: "Inside one it runs on the transaction's connection." A write-key issued
-- inside a read-write transaction goes to that transaction's connection, so
-- rolling the transaction back reverts it — proof it was not auto-committed on
-- the write pool but ran on, and only on, the transaction's own connection.
test("write key inside a transaction runs on the transaction's connection",
    { spec = "loregd *key.write-key-inside-a-transaction-uses-its-connection" },
    function(t)
        loregd.new_key(vm, [[PtState\Durable\SdTxn]]):assert_ok()
        local fd = open(t, [[PtState\Durable\SdTxn]])
        local before = lcs.query_key_info(nil, W, fd).sd_size

        local txn = lcs.begin_transaction(W)
        t:assert(txn, "begin_transaction")
        local s = lcs.set_security(nil, W, fd, lcs.SI.DACL, sd_with(4), { txn_fd = txn })
        t:assert_eq(s.ret, 0, "write-key(sd) inside the txn: " .. sys.errname(s.errno or 0))
        sys.close(W, txn) -- abort

        local after = lcs.query_key_info(nil, W, fd).sd_size
        t:assert_eq(after, before,
            "the SD is unchanged after the transaction rolled back: the write ran "
            .. "on the transaction's connection (not auto-committed), so the abort "
            .. "reverted it — before=" .. tostring(before) .. " after=" .. tostring(after))
    end)

-- --- write-key field-mask details: not guest-reachable (no ioctl carries an
-- --- arbitrary field mask; only set_security, which fixes bit 0). Cited to Go
-- --- unit tests that drive handleWriteKey with each mask directly.

-- §5: "Updates the two mutable fields of a key, selected by a field mask"
-- (both sd and last_write_time). Only the SD half is guest-reachable (above);
-- the two-field update needs mask 0x03, which no guest ioctl sends.
test("write key updates the two mutable fields",
    {
        spec = "loregd *key.write-key-updates-the-two-mutable-fields",
        skip = true,
        covered_by = "go:loregd internal/handler::TestWriteKeyBothFields",
    }, function() end)

-- §5: bit 1 (0x02) selects last_write_time. No guest ioctl carries a write-key
-- last_write_time; the guest can only set the SD (bit 0) via set_security.
test("mask bit 1 selects the last write time",
    {
        spec = "loregd *key.mask-bit-1-selects-the-last-write-time",
        skip = true,
        covered_by = "go:loregd internal/handler::TestWriteKeyLastWriteTime",
    }, function() end)

-- §5: "Any other bit set returns RSI_INVALID." A guest cannot forge a spare
-- mask bit — set_security always emits a well-formed bit-0 mask.
test("a mask with any other bit set returns invalid",
    {
        spec = "loregd *key.a-mask-with-any-other-bit-set-returns-invalid",
        skip = true,
        covered_by = "go:loregd internal/handler::TestWriteKeyInvalidMask",
    }, function() end)

-- §5: "loregd builds one UPDATE from the mask, setting only the named fields."
-- The per-mask UPDATE means mask 0x01 touches sd only and 0x02 touches
-- last_write_time only; the cited tests each write one field and check that
-- field. Not guest-reachable (no arbitrary mask).
test("the update sets only the fields the mask names",
    {
        spec = "loregd *key.the-update-sets-only-the-fields-the-mask-names",
        skip = true,
        covered_by = "go:loregd internal/handler::TestWriteKeySD, go:loregd internal/handler::TestWriteKeyLastWriteTime",
    }, function() end)

-- §5: "A mask of 0x00 names no fields and acts as an existence check,
-- returning RSI_OK or RSI_NOT_FOUND." No guest ioctl sends a zero-mask
-- write-key.
test("a zero mask acts as an existence check",
    {
        spec = "loregd *key.a-zero-mask-acts-as-an-existence-check",
        skip = true,
        covered_by = "go:loregd internal/handler::TestWriteKeyNoOpMask, go:loregd internal/handler::TestWriteKeyNotFoundWithNoOpMask",
    }, function() end)

-- §5: "An update that matches no row also returns RSI_NOT_FOUND." The
-- rows-affected==0 branch needs a write-key against a resolvable hive whose row
-- is gone; not constructable from a guest handle.
test("an update matching no row returns not-found",
    {
        spec = "loregd *key.an-update-matching-no-row-returns-not-found",
        skip = true,
        covered_by = "go:loregd internal/handler::TestWriteKeyNotFound",
    }, function() end)

-- ============================ RSI_DROP_KEY =============================
--
-- RSI_DROP_KEY is emitted by the kernel as GC when the last handle to an
-- orphaned key closes (pkm lcs/key_fd.c:632); a guest never issues it directly
-- and observes only the key's absence, which RSI_DELETE_ENTRY already produced.
-- The purge shape, atomicity, idempotency and cache eviction are therefore
-- cited to Go unit tests.

-- §5: "Purges every trace of a GUID from both stores — four tables in each
-- schema." The cited test seeds a key with a path entry and a value, drops it,
-- and asserts keys, path_entries and values are all gone (blanket_tombstones is
-- the fourth statement in the same list).
test("drop key purges a GUID from four tables in each schema",
    {
        spec = "loregd *key.drop-key-purges-a-guid-from-four-tables-in-each-schema",
        skip = true,
        covered_by = "go:loregd internal/handler::TestDropKey",
    }, function() end)

-- §5: "Outside a transaction, the eight statements are wrapped in a
-- BEGIN IMMEDIATE transaction of their own so the purge is atomic." The cited
-- test drives the non-transactional drop, which runs handleDropKey's
-- hdr.TxnID==0 branch (tx.Begin()..Commit() around the eight deletes).
-- NOTE to coordinator: the write connection's DSN sets no `_txlock=immediate`
-- (hivedb.go:117), so Begin() opens a DEFERRED transaction, not literally
-- BEGIN IMMEDIATE. Atomicity is unaffected (one write connection, SetMaxOpenConns(1),
-- first statement is a write), so this is a spec/comment wording nuance, not a
-- behavioural bug — flagged, not tagged known-bug.
test("drop key outside a transaction wraps the purge in its own transaction",
    {
        spec = "loregd *key.drop-key-outside-a-transaction-wraps-the-purge-in-begin-immediate",
        skip = true,
        covered_by = "go:loregd internal/handler::TestDropKey",
    }, function() end)

-- §5: "Inside one, they run on the transaction's connection." The cited test
-- drops within a transaction and commits, asserting the row is gone.
test("drop key inside a transaction uses its connection",
    {
        spec = "loregd *key.drop-key-inside-a-transaction-uses-its-connection",
        skip = true,
        covered_by = "go:loregd internal/handler::TestDropKeyInTransaction",
    }, function() end)

-- §5: "Dropping a GUID that does not exist returns RSI_OK; so does one that
-- resolves to no hive. The operation is idempotent." The cited test drops a
-- GUID that was never created (in no store, resolving to no hive) and asserts
-- RSI_OK — the same answer a repeat drop of an already-dropped GUID gives.
test("dropping a GUID that does not exist / resolves to no hive returns OK; drop is idempotent", {
    spec = "loregd *key.dropping-a-guid-that-does-not-exist-returns-ok " ..
        "*key.dropping-a-guid-that-resolves-to-no-hive-returns-ok " ..
        "*key.drop-key-is-idempotent",
    skip = true,
    covered_by = "go:loregd internal/handler::TestDropKeyIdempotent",
}, function() end)

-- §5: "The GUID is evicted from the hive cache." The cited test asserts the
-- guidCache no longer holds the GUID after a drop. Not guest-observable (the
-- cache is internal).
test("drop key evicts the GUID from the hive cache",
    {
        spec = "loregd *key.drop-key-evicts-the-guid-from-the-hive-cache",
        skip = true,
        covered_by = "go:loregd internal/handler::TestDropKey",
    }, function() end)
