-- loregd book §5 "Path Entry Operations"
-- (5--request-handling/4--path-entry-operations.md): RSI_LOOKUP,
-- RSI_CREATE_ENTRY, RSI_HIDE_ENTRY, RSI_DELETE_ENTRY, RSI_ENUM_CHILDREN — the
-- per-layer entries that give a key its names.
--
-- What a guest can observe against a real loregd:
--
--   * A created name reads back and enumerates under its parent
--     (RSI_CREATE_ENTRY). A `reg`/LCS create issues create-entry then
--     create-key, so at entry time the child key's volatile flag is unknown and
--     the entry defaults to the persistent store (handler.go:390); its landing
--     there is visible after a reboot as a persistent entry outliving a volatile
--     key (the last, reboot, case).
--   * RSI_HIDE_ENTRY is reachable through REG_IOC_HIDE_KEY: hiding a key writes
--     a HIDDEN tombstone for its name, and the name then reads absent — which is
--     only possible if loregd returned the tombstone to the kernel (RSI_LOOKUP
--     returning HIDDEN entries).
--   * RSI_DELETE_ENTRY is reachable through REG_IOC_DELETE_KEY: it removes the
--     name's entry and the key reads absent.
--   * An unresolvable parent answers NOT_FOUND for lookup, create-entry,
--     delete-entry and hide-entry. A handle whose GUID was rolled back resolves
--     to no hive and serves as an unresolvable parent for lookup/create/delete;
--     for hide, a child whose parent has been dropped supplies one.
--   * RSI_LOOKUP dropping a dangling entry is reachable on the image (lookup
--     tolerates it since PEI-510) — reproduced with a persistent entry that
--     outlives its volatile key across a reboot.
--
-- Not guest-observable, cited to Go unit tests:
--   * The raw per-layer/per-GUID shape of a lookup response — the kernel
--     resolves layers away before a caller sees it, and PtState carries only the
--     base layer, so multi-layer wire shape is not guest-constructable.
--   * Which store a hide's tombstone or an entry lands in.
--   * The same-store and cross-store duplicate-triple rejections (LCS opens an
--     existing name rather than re-creating it; a guest cannot steer one triple
--     into both stores).
--   * RSI_ENUM_CHILDREN dropping a dangling child — FIXED IN SOURCE (1b307c0,
--     PEI-233) but NOT in the shipped loregd 0.21.8-3, which fails the whole
--     enumeration with a storage error (EIO). Cited to the PEI-233 Go tests,
--     not tested on the image (a VM test would fail against the shipped binary;
--     the EIO itself is already homed as a known-bug in durability/volatile-store).
--
-- Mediated boot so the reboot case can power-cut. Every non-reboot case runs on
-- the file-scope daemon; the reboot case is LAST and restarts loregd itself.

local loregd = require("helpers.loregd")
local lcs = require("helpers.lcs")
local sys = require("helpers.sys")

local vm = loregd.boot({ name = "loregd-entry", mediated = true })
local disk = vm:disk("hive")
loregd.format(vm)
loregd.mount(vm)
loregd.start(vm)

local W = vm:spawn_worker()

local function open(t, path)
    local r = lcs.open_key(nil, W, -1, path, lcs.KEY_ALL_ACCESS, 0)
    t:assert(r.ret >= 0, "open " .. path .. ": " .. sys.errname(r.errno or 0))
    return r.ret
end

--- A handle naming a GUID that resolves to no hive (an unresolvable parent):
--- create it in a read-write transaction and roll the transaction back.
local function ghost(t, path)
    local txn = lcs.begin_transaction(W)
    t:assert(txn, "begin_transaction for ghost")
    local cr = lcs.create_key(nil, W, { path = path, access = lcs.KEY_ALL_ACCESS, txn_fd = txn })
    t:assert(cr.ret >= 0, "create ghost " .. path .. ": " .. sys.errname(cr.errno or 0))
    sys.close(W, txn) -- abort
    return cr.ret
end

local function exists(key) return vm:run("reg info '" .. key .. "'").exit_code == 0 end

-- ============================ RSI_CREATE_ENTRY =========================

-- §5: create-entry "INSERT INTO path_entries (...) VALUES (?, ?, fold(?), ?, 0,
-- ?, ?)" — one layer's entry for a child name under a parent. Observable as the
-- named child reading back and enumerating.
test("create entry inserts one layer's entry for a child name",
    { spec = "loregd *entry.create-entry-inserts-one-layers-entry-for-a-child-name" },
    function(t)
        loregd.new_key(vm, [[PtState\Names\Kid]]):assert_ok()
        t:assert(exists([[PtState\Names\Kid]]),
            "the created name reads back — a path entry was inserted for it")
        local ls = vm:run("reg ls 'PtState\\Names' --keys-only")
        ls:assert_ok()
        t:assert(ls.stdout:match("Kid/"), "and enumerates under its parent: " .. ls.stdout)
    end)

-- §5: "An unresolvable parent GUID returns RSI_NOT_FOUND." create_key issues
-- RSI_CREATE_ENTRY(parent) first, so a create under a rolled-back parent handle
-- fails there.
test("create entry on an unresolvable parent returns not-found",
    { spec = "loregd *entry.create-entry-on-an-unresolvable-parent-returns-not-found" },
    function(t)
        local g = ghost(t, [[PtState\Names\GhostParent]])
        local cr = lcs.create_key(nil, W, { parent_fd = g, path = "Child", access = lcs.KEY_ALL_ACCESS })
        t:assert(cr.ret < 0 and cr.errno == sys.E.NOENT,
            "create-entry under a parent that resolves to no hive is NOT_FOUND "
            .. "(ENOENT): ret=" .. tostring(cr.ret) .. " errno=" .. sys.errname(cr.errno or 0))
    end)

-- §5: the target table follows the child key's volatile flag; "A child GUID in
-- neither store lands in the persistent table." Not observable in isolation
-- (the child is unknown for every guest create, since create-entry precedes
-- create-key), but it is exactly what the reboot case below relies on and
-- proves: a volatile child's entry, written before its key, lands persistent
-- and so outlives the key. The store-by-flag routing (when the key is known
-- first) is the cited Go test.
test("create entry targets the store of the child key's volatile flag",
    {
        spec = "loregd *entry.create-entry-targets-the-store-of-the-child-keys-volatile-flag",
        skip = true,
        covered_by = "go:loregd internal/handler::TestCreateEntryVolatileTarget",
    }, function() end)

-- §5: "RSI_ALREADY_EXISTS comes from the target table's primary key on
-- (parent_guid, child_name_folded, layer)." Route closed: LCS opens an existing
-- name (disposition OPENED_EXISTING) instead of re-issuing create-entry, so the
-- same-store duplicate rejection is never triggered from a guest.
test("create entry refuses a duplicate (parent, name, layer) triple",
    {
        spec = "loregd *entry.create-entry-refuses-a-duplicate-parent-name-layer-triple",
        skip = true,
        covered_by = "go:loregd internal/handler::TestCreateEntryDuplicate",
    }, function() end)

-- §5: "loregd also asks the other store for the same triple before inserting."
-- Route closed: a guest cannot place the same triple into both stores (the
-- child's volatile flag, unknown at entry time, sends every guest entry to one
-- store).
test("create entry checks both stores for a duplicate triple",
    {
        spec = "loregd *entry.create-entry-checks-both-stores-for-a-duplicate-triple",
        skip = true,
        covered_by = "go:loregd internal/handler::TestCreateEntryRejectsTripleHeldByTheOtherStore",
    }, function() end)

-- ============================ RSI_LOOKUP ===============================

-- §5: "HIDDEN entries are returned as entries but contribute no metadata GUID."
-- and RSI_HIDE_ENTRY "Writes a tombstone that masks the same name in lower
-- layers." Hiding a key writes a HIDDEN tombstone for its name; the name then
-- reads absent, which is only possible because loregd returned the tombstone
-- (carrying no target) to the kernel, which applied the mask.
test("a hide-entry tombstone masks the name, and lookup returns it with no metadata", {
    spec = "loregd *entry.hide-entry-writes-a-tombstone-masking-lower-layers " ..
        "*entry.lookup-returns-hidden-entries-with-no-metadata-guid",
}, function(t)
    loregd.new_key(vm, [[PtState\Names\Maskme]]):assert_ok()
    t:assert(exists([[PtState\Names\Maskme]]), "the name resolves before the hide")

    local hk = lcs.hide_key(nil, W, open(t, [[PtState\Names\Maskme]]), { layer = "base" })
    t:assert_eq(hk.ret, 0, "hide_key writes the tombstone: " .. sys.errname(hk.errno or 0))

    t:assert(not exists([[PtState\Names\Maskme]]),
        "the name now reads absent: loregd returned the HIDDEN entry (a tombstone "
        .. "with no metadata GUID) and the kernel masked the name with it")
end)

-- §5: "An unresolvable parent GUID returns RSI_NOT_FOUND." Opening a child
-- relative to a rolled-back parent handle issues RSI_LOOKUP(parent, child).
test("lookup on an unresolvable parent returns not-found",
    { spec = "loregd *entry.lookup-on-an-unresolvable-parent-returns-not-found" },
    function(t)
        local g = ghost(t, [[PtState\Names\GhostLookup]])
        local r = lcs.open_key(nil, W, g, "Child", lcs.KEY_ALL_ACCESS, 0)
        t:assert(r.ret < 0 and r.errno == sys.E.NOENT,
            "a lookup under a parent that resolves to no hive is NOT_FOUND "
            .. "(ENOENT): ret=" .. tostring(r.ret) .. " errno=" .. sys.errname(r.errno or 0))
    end)

-- §5: "Returns every layer's entry for one child name under one parent."
-- Wire-shape: the kernel resolves the raw per-layer entries away before a
-- caller sees them, and PtState carries only the base layer, so a multi-layer
-- lookup response is not guest-constructable. Cited to the Go tests that decode
-- the raw response.
test("lookup returns every layer's entry for one child name",
    {
        spec = "loregd *entry.lookup-returns-every-layers-entry-for-one-child-name",
        skip = true,
        covered_by = "go:loregd internal/handler::TestLookupFindsEntry, go:loregd internal/handler::TestLookupCaseInsensitive",
    }, function() end)

-- §5: "For each distinct non-HIDDEN target_guid, loregd fetches the key's
-- metadata — one query per GUID — and emits the blocks in ascending GUID
-- order." Wire-shape (the metadata block is consumed by the kernel).
test("lookup emits one metadata block per distinct target GUID",
    {
        spec = "loregd *entry.lookup-emits-one-metadata-block-per-distinct-target-guid",
        skip = true,
        covered_by = "go:loregd internal/handler::TestLookupFindsEntry",
    }, function() end)

-- §5: "loregd does no layer filtering and no resolution: every entry it holds
-- is returned, and choosing between them is the kernel's job." Wire-shape:
-- TestLookupFindsEntry shows loregd returns the raw entry (layer, target_type,
-- target_guid) unresolved; layer selection lives only in the kernel.
test("lookup does no layer filtering and no resolution",
    {
        spec = "loregd *entry.lookup-does-no-layer-filtering-and-no-resolution",
        skip = true,
        covered_by = "go:loregd internal/handler::TestLookupFindsEntry",
    }, function() end)

-- ============================ RSI_HIDE_ENTRY ===========================

-- §5: "A parent GUID in neither store returns RSI_NOT_FOUND." A hide's parent
-- is the hidden key's parent, so an unresolvable parent needs a child whose
-- parent has been dropped: hide the only child, delete the now-childless
-- parent, close its last handle (dropping it), then hide the child again — its
-- parent now resolves to no hive.
test("hide entry on an unresolvable parent returns not-found",
    { spec = "loregd *entry.hide-entry-on-an-unresolvable-parent-returns-not-found" },
    function(t)
        loregd.new_key(vm, [[PtState\Orphan\Child]]):assert_ok()
        local child = open(t, [[PtState\Orphan\Child]])
        local parent = open(t, [[PtState\Orphan]])

        -- The parent cannot be deleted while its child is visible.
        local d0 = lcs.delete_key(nil, W, parent)
        t:assert(d0.ret ~= 0, "the parent will not delete while its child is visible")

        -- Hide the child, then the parent is childless and deletes; closing its
        -- last handle drops the parent key.
        t:assert_eq(lcs.hide_key(nil, W, child, { layer = "base" }).ret, 0, "hide the child")
        t:assert_eq(lcs.delete_key(nil, W, parent).ret, 0, "delete the now-childless parent")
        sys.close(W, parent)

        -- Hiding the child again names a parent that resolves to no hive.
        local h = lcs.hide_key(nil, W, child, { layer = "role-x" })
        t:assert(h.ret < 0 and h.errno == sys.E.NOENT,
            "a hide whose parent resolves to no hive is NOT_FOUND (ENOENT): "
            .. "ret=" .. tostring(h.ret) .. " errno=" .. sys.errname(h.errno or 0))
    end)

-- §5: "target_type is 1 and target_guid is null." Wire-shape (the stored
-- columns are internal); the cited test reads them back from the DB.
test("a hide-entry tombstone has type one and a null target",
    {
        spec = "loregd *entry.a-hide-entry-tombstone-has-type-one-and-a-null-target",
        skip = true,
        covered_by = "go:loregd internal/handler::TestHideEntry",
    }, function() end)

-- §5: "The target table follows the parent key's volatile flag." Not
-- observable at the guest (which store holds the tombstone is internal).
test("hide entry targets the store of the parent key's volatile flag",
    {
        spec = "loregd *entry.hide-entry-targets-the-store-of-the-parent-keys-volatile-flag",
        skip = true,
        covered_by = "go:loregd internal/handler::TestHideEntryVolatileParent",
    }, function() end)

-- ============================ RSI_DELETE_ENTRY =========================

-- §5: "Removes one layer's entry for one name, from both stores." Observable as
-- the name reading absent after the delete. (The both-stores DELETE pair is
-- internal; the cited Go test asserts it.)
test("delete entry removes one layer's entry (the name reads absent)",
    { spec = "loregd *entry.delete-entry-removes-one-layers-entry-from-both-stores" },
    function(t)
        loregd.new_key(vm, [[PtState\Names\Delme]]):assert_ok()
        t:assert(exists([[PtState\Names\Delme]]), "the name resolves before the delete")
        local d = lcs.delete_key(nil, W, open(t, [[PtState\Names\Delme]]))
        t:assert_eq(d.ret, 0, "delete_key removes the entry: " .. sys.errname(d.errno or 0))
        t:assert(not exists([[PtState\Names\Delme]]),
            "the name reads absent after its layer entry was deleted")
    end)

-- §5: "No rows-affected check is made, so deleting an entry that is not there
-- succeeds." Route closed: the kernel resolves the key before issuing
-- RSI_DELETE_ENTRY and answers ENOENT for an already-absent key, so loregd's
-- no-rows-affected tolerance cannot be reached from a guest (verified: a second
-- delete_key on the same handle returns ENOENT).
test("deleting an absent entry succeeds",
    {
        spec = "loregd *entry.deleting-an-absent-entry-succeeds",
        skip = true,
        covered_by = "go:loregd internal/handler::TestDeleteEntryIdempotent",
    }, function() end)

-- §5: "A parent GUID that resolves to no hive returns RSI_NOT_FOUND rather than
-- succeeding." delete_key on a rolled-back handle names an unresolvable parent.
test("delete entry on an unresolvable parent returns not-found",
    { spec = "loregd *entry.delete-entry-on-an-unresolvable-parent-returns-not-found" },
    function(t)
        local g = ghost(t, [[PtState\Names\GhostDelete]])
        local d = lcs.delete_key(nil, W, g)
        t:assert(d.ret < 0 and d.errno == sys.E.NOENT,
            "a delete-entry whose parent resolves to no hive is NOT_FOUND "
            .. "(ENOENT): ret=" .. tostring(d.ret) .. " errno=" .. sys.errname(d.errno or 0))
    end)

-- ============================ RSI_ENUM_CHILDREN ========================

-- §5: "Returns every layer's entry for every child under a parent," and "Rows
-- are grouped by folded child name into one block per child." Observable:
-- every child enumerates, each as one block.
test("enum children returns every child, grouped into one block per folded name", {
    spec = "loregd *entry.enum-children-returns-every-layers-entry-for-every-child " ..
        "*entry.enum-children-groups-rows-into-one-block-per-folded-child-name",
}, function(t)
    loregd.new_key(vm, [[PtState\Kids\Alpha]]):assert_ok()
    loregd.new_key(vm, [[PtState\Kids\Bravo]]):assert_ok()
    loregd.new_key(vm, [[PtState\Kids\Charlie]]):assert_ok()

    local ls = vm:run("reg ls 'PtState\\Kids' --keys-only")
    ls:assert_ok()
    for _, name in ipairs({ "Alpha", "Bravo", "Charlie" }) do
        local _, n = ls.stdout:gsub(name .. "/", "")
        t:assert_eq(n, 1, "child " .. name .. " enumerates exactly once (one block per "
            .. "folded name): " .. ls.stdout)
    end
    -- (Grouping of the SAME folded name arriving in two layers into a single
    -- block is the cited go:loregd internal/handler::TestEnumChildrenDeterministicOrder;
    -- PtState carries only the base layer, so a two-layer child is not
    -- guest-constructable here.)
end)

-- §5: enum "including its treatment of an entry whose key record does not yet
-- exist: the entry is dropped, and a child left holding no entries at all is
-- dropped with it." FIXED IN SOURCE (1b307c0, PEI-233) but NOT in the shipped
-- loregd 0.21.8-3, which predates it and fails RSI_ENUM_CHILDREN on a dangling
-- entry with a storage error (EIO) — a VM test would fail against the image.
-- The EIO on the shipped binary is already homed as a known-bug in
-- volatile-store.test.lua / durability.test.lua; here the FIXED behaviour is
-- cited to its PEI-233 unit test (verified failing pre-1b307c0 per that commit).
test("enum children drops a child left holding no entries",
    {
        spec = "loregd *entry.enum-children-drops-a-child-left-holding-no-entries",
        skip = true,
        covered_by = "go:loregd internal/handler::TestEnumChildrenSkipsChildWhoseKeyIsNotYetVisible",
    }, function() end)

-- §5: "The metadata block for a dropped entry is omitted with it — the kernel
-- rejects a GUID-typed entry carrying no metadata, and equally a metadata block
-- no entry references." Same shipping lag as above; cited to the PEI-233 tests,
-- whose assertEnumMetadataCorresponds checks both directions of the entry↔
-- metadata correspondence.
test("enum children omits the metadata block of a dropped entry",
    {
        spec = "loregd *entry.enum-children-omits-the-metadata-block-of-a-dropped-entry",
        skip = true,
        covered_by = "go:loregd internal/handler::TestEnumChildrenSkipsChildWhoseKeyIsNotYetVisible, go:loregd internal/handler::TestEnumChildrenDropsOnlyTheDanglingLayerEntry",
    }, function() end)

-- ============================ reboot case (LAST) =======================

-- §5 (RSI_LOOKUP): "If a path entry names a target_guid for which no key record
-- exists, loregd drops that entry from the response and returns RSI_OK, so the
-- child reads as absent." Reachable on the image (lookup has tolerated a
-- dangling entry since PEI-510). Reproduced through the create-entry-before-
-- create-key store default: a volatile child of a persistent parent has its
-- path entry written to the PERSISTENT store, so after a reboot the entry
-- survives while its volatile key does not — a dangling entry. This one case
-- also proves *entry.create-entry-for-an-unknown-child-guid-lands-in-the-
-- persistent-store: the entry's survival IS its having landed persistent.
-- Must be last: it power-cuts and resets the VM.
test("lookup drops an entry whose key record is missing (and the unknown-child entry landed persistent)", {
    spec = "loregd *entry.lookup-drops-an-entry-whose-key-record-is-missing " ..
        "*entry.create-entry-for-an-unknown-child-guid-lands-in-the-persistent-store",
}, function(t)
    local NAME, FILE = "PtDangle", "/mnt/pt-hive/dangle.hive"
    local proc = loregd.start(vm, t, { hives = { NAME .. "=" .. FILE }, wait_for = NAME })

    loregd.new_key(vm, [[PtDangle\Parent]]):assert_ok()          -- persistent parent
    vm:run("reg new 'PtDangle\\Parent\\VKid' --volatile"):assert_ok() -- volatile child
    t:assert(exists([[PtDangle\Parent\VKid]]), "the volatile child resolves before the reboot")

    -- A reboot: loregd (and its in-memory volatile store) dies; the committed
    -- persistent parent AND the volatile child's persistent path entry survive
    -- the cut, but the child's volatile key row does not.
    disk:power_cut()
    vm:reset()
    loregd.mount(vm, t)
    loregd.start(vm, t, { hives = { NAME .. "=" .. FILE }, wait_for = NAME })

    -- The parent still resolves. Prove this with a pure lookup (open_key), NOT
    -- reg info: reg info composes query-key-info, which enumerates the parent's
    -- children, and RSI_ENUM_CHILDREN on a parent holding a dangling entry EIOs
    -- on the shipped loregd 0.21.8-3 (the PEI-233 lag) — that failure is homed
    -- elsewhere as a known-bug. RSI_LOOKUP, the operation under test, tolerates
    -- the dangling entry, so a lookup of the parent succeeds.
    local W2 = vm:spawn_worker() -- the file-scope worker died with vm:reset()
    local op = lcs.open_key(nil, W2, -1, [[PtDangle\Parent]], lcs.KEY_ALL_ACCESS, 0)
    t:assert(op.ret >= 0,
        "the persistent parent still resolves by lookup after the reboot: ret="
        .. tostring(op.ret) .. " errno=" .. sys.errname(op.errno or 0))

    -- The child reads absent rather than erroring: looking it up under the
    -- parent (reg info walks parent then looks up the child; the walk is
    -- lookups, no enumeration) drops the entry whose key record is gone and
    -- answers NOT_FOUND.
    local info = vm:run("reg info 'PtDangle\\Parent\\VKid'")
    t:assert_eq(info.exit_code, 2,
        "the child whose volatile key vanished reads as absent (NOT_FOUND, not a "
        .. "storage error): loregd dropped the dangling path entry — which had "
        .. "survived in the PERSISTENT store, where the create-before-key "
        .. "ordering put it — and returned OK. stdout=" .. info.stdout
        .. " stderr=" .. info.stderr)
    -- The daemon started inside this (final) test is reaped when the test ends.
end)
