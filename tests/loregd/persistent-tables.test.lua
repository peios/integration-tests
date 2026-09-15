-- loregd §3.2 — the four persistent data tables and what their columns mean.
--
-- The exact SQL shapes (which tables exist, their columns, their primary
-- keys, the partial index) are not exposed over RSI and the image has no
-- sqlite3, so those anchors are homed on internal/hivedb / internal/handler
-- unit tests (each read and run — all PASS — before citing). The *meanings*
-- that surface through behaviour are tested here against one file-scope
-- loregd serving the PtState hive.

local loregd = require("helpers.loregd")

local vm = loregd.boot({ name = "loregd-tables" })
loregd.format(vm)
loregd.mount(vm)
loregd.start(vm) -- one daemon for the whole file; no restart needed here

-- §3.2: "The tables hold what the kernel gives loregd and nothing derived
-- from it. Security descriptors are stored as opaque blobs ... no table
-- records a resolved or filtered view of anything." A binary value written
-- and read back byte-for-byte shows the payload is stored verbatim, not
-- reinterpreted or derived.
test("stored data is verbatim, not a derived view",
    { spec = "loregd *tables.no-table-records-a-derived-view-of-kernel-data" },
    function(t)
        local key = [[PtState\Opaque]]
        loregd.new_key(vm, key):assert_ok()
        loregd.set(vm, key, "Blob", "hex:00ff10de01"):assert_ok()
        local r = vm:run("reg get '" .. key .. "' Blob --raw")
        r:assert_ok()
        t:assert_eq(r.stdout, "\x00\xff\x10\xde\x01",
            "the binary payload reads back byte-identical, so loregd stored it " ..
            "opaquely rather than recording a derived or filtered view")
    end)

-- §3.2 keys.name: "The key's own name component, with case preserved as
-- written." Create with one case, look up with another: the response carries
-- the case as written.
test("a key name is stored with its case preserved",
    { spec = "loregd *tables.a-key-name-is-stored-with-its-case-preserved" },
    function(t)
        -- Create with one case, then enumerate the parent: RSI_ENUM_CHILDREN
        -- returns loregd's stored child_name column, so the case-preserved
        -- name comes back. (reg info's `name` is the kernel echoing the
        -- opened path — loregd has no QUERY_KEY_INFO handler — so it is not a
        -- loregd response and not used here.)
        loregd.new_key(vm, [[PtState\CaseTest\MixedCaseKey]]):assert_ok()
        local r = vm:run("reg ls 'PtState\\CaseTest' --keys-only")
        r:assert_ok()
        t:assert(r.stdout:match("MixedCaseKey/"),
            "enum returns the stored, case-preserved child name: " .. r.stdout)
        -- And a different-case lookup still resolves it: folded comparison.
        local found = vm:run("reg ls 'PtState\\CaseTest\\MIXEDCASEKEY'")
        t:assert_eq(found.exit_code, 0,
            "the key is found by a case-variant spelling (folded lookup): " ..
            found.stderr)
    end)

-- §3.2 keys.volatile: "In this table it is always 0 ... volatile keys live in
-- the volatile database." A key created without the volatile flag reports
-- volatile = false.
test("a persistent key reports volatile = 0",
    { spec = "loregd *tables.the-persistent-keys-table-always-stores-volatile-zero" },
    function(t)
        loregd.new_key(vm, [[PtState\PersistOnly]]):assert_ok()
        local r = vm:run("reg info 'PtState\\PersistOnly' --json")
        r:assert_ok()
        t:assert(r.stdout:match('"volatile"%s*:%s*false'),
            "a persistently-created key carries volatile = false (0): " .. r.stdout)
    end)

-- §3.2 path_entries.child_name_folded: "the folded form, which is what the
-- primary key uses — so a name collides case-insensitively within a layer."
-- Creating a second child differing only in case does not add a second child;
-- the folded primary key collides, and the first (case-preserved) name wins.
test("a child name collides case-insensitively within a layer",
    { spec = "loregd *tables.a-child-name-collides-case-insensitively-within-a-layer" },
    function(t)
        loregd.new_key(vm, [[PtState\Coll\Child]]):assert_ok()
        -- Same parent, same (base) layer, name differing only in case: the
        -- folded PK (parent, "child", base) already exists, so this resolves
        -- to the existing key rather than creating a rival entry.
        loregd.new_key(vm, [[PtState\Coll\CHILD]]):assert_ok()
        local r = vm:run("reg ls 'PtState\\Coll' --keys-only")
        r:assert_ok()
        local n = select(2, r.stdout:gsub("Child/", ""))
        t:assert_eq(n, 1,
            "exactly one child exists and it keeps the first-written case " ..
            "'Child' — the case-variant spelling collided in the layer: " .. r.stdout)
        t:assert(not r.stdout:match("CHILD"),
            "the second, upper-case spelling did not create a rival child")
    end)

-- §3.2 values.name: "The empty string is the key's default value." reg's `@`
-- names the default (empty-name) value.
test("the empty value name is the key's default value",
    { spec = "loregd *tables.the-empty-value-name-is-the-keys-default-value" },
    function(t)
        local key = [[PtState\Defaulted]]
        loregd.new_key(vm, key):assert_ok()
        loregd.set(vm, key, "@", "sz:iamdefault"):assert_ok()
        local r, v = loregd.get(vm, key, "@")
        r:assert_ok()
        t:assert_eq(v, "iamdefault",
            "the value set under the empty name (@) reads back as the key's " ..
            "default value")
    end)

-- §3.2 path_entries.target_type: "1 for HIDDEN (a tombstone masking lower
-- layers)." Hiding a key in the layer that holds it replaces its entry with a
-- HIDDEN tombstone, and the key stops resolving.
test("target_type 1 is a HIDDEN tombstone that masks a key",
    { spec = "loregd *tables.target-type-one-is-a-hidden-tombstone" },
    function(t)
        local key = [[PtState\Vic]]
        loregd.new_key(vm, key):assert_ok()
        t:assert_eq(vm:run("reg info '" .. key .. "'").exit_code, 0,
            "the key resolves before it is hidden")

        local h = vm:run("reg hide '" .. key .. "'")
        h:assert_ok()
        local after = vm:run("reg info '" .. key .. "'")
        t:assert(after.exit_code ~= 0,
            "after a HIDDEN tombstone replaces its path entry the key no " ..
            "longer resolves (stdout=" .. after.stdout .. " stderr=" .. after.stderr .. ")")
    end)

-- §3.2 values.type: "REG_TOMBSTONE (0xFFFF) marks a per-value tombstone."
-- Masking a value in the layer that holds it replaces it with a tombstone,
-- and the value stops resolving.
test("REG_TOMBSTONE marks a per-value tombstone",
    { spec = "loregd *tables.reg-tombstone-marks-a-per-value-tombstone" },
    function(t)
        local key = [[PtState\Masked]]
        loregd.new_key(vm, key):assert_ok()
        loregd.set(vm, key, "Doomed", "dword:9"):assert_ok()
        local before, v = loregd.get(vm, key, "Doomed")
        before:assert_ok()
        t:assert_eq(v, "9", "the value resolves before it is masked")

        local m = vm:run("reg mask '" .. key .. "' Doomed")
        m:assert_ok()
        local after = vm:run("reg get '" .. key .. "' Doomed")
        t:assert(after.exit_code ~= 0,
            "a per-value REG_TOMBSTONE masks the value, which no longer " ..
            "resolves (stdout=" .. after.stdout .. " stderr=" .. after.stderr .. ")")
    end)

-- ---- unit-cited: internal table/column shapes, no guest route --------

test("every hive database has the same four data tables", {
    spec = "loregd *tables.every-hive-database-has-the-same-four-data-tables",
    skip = true,
    -- The set of tables is not observable over RSI and there is no sqlite3 in
    -- the image. TestTablesExist asserts keys/path_entries/values/
    -- blanket_tombstones (and schema_version) all exist.
    covered_by = "go:loregd internal/hivedb::TestTablesExist",
}, function() end)

test("the keys table has the documented columns", {
    spec = "loregd *tables.the-keys-table",
    skip = true,
    -- Column layout is internal SQL. TestTablesExist proves the table, and
    -- TestRootKeyProperties reads name/name_folded/parent_guid/volatile/
    -- symlink back from a real row.
    covered_by = "go:loregd internal/hivedb::TestRootKeyProperties",
}, function() end)

test("the hive root is the key with a null parent", {
    spec = "loregd *tables.the-hive-root-is-the-key-with-a-null-parent",
    skip = true,
    -- parent_guid IS NULL is how the root is identified; a guest sees the root
    -- exists but not that its parent column is null. TestRootKeyProperties
    -- asserts parent_guid is nil on the root row.
    covered_by = "go:loregd internal/hivedb::TestRootKeyProperties",
}, function() end)

test("the path_entries table has the documented columns", {
    spec = "loregd *tables.the-path-entries-table",
    skip = true,
    covered_by = "go:loregd internal/hivedb::TestTablesExist",
}, function() end)

test("a path entry is one layer's opinion about one child name", {
    spec = "loregd *tables.a-path-entry-is-one-layers-opinion-about-one-child-name",
    skip = true,
    -- loregd stores one entry per (parent, name, layer); several layers may
    -- name the same child. TestEnumChildrenReportsAStableNameCase seeds two
    -- layers ("base", "vendor") that both name one child and shows loregd
    -- carries both entries.
    covered_by = "go:loregd internal/handler::TestEnumChildrenReportsAStableNameCase",
}, function() end)

test("loregd does not resolve between layers", {
    spec = "loregd *tables.loregd-does-not-resolve-between-layers",
    skip = true,
    -- The kernel resolves layer precedence before a guest sees an effective
    -- value, so a guest cannot observe loregd returning the unresolved stack.
    -- TestQueryValuesAll seeds the same value in two layers and asserts loregd
    -- returns all three rows (two layers of "A" plus "B"), unresolved.
    covered_by = "go:loregd internal/handler::TestQueryValuesAll",
}, function() end)

test("layer names are compared as binary", {
    spec = "loregd *tables.layer-names-are-compared-as-binary",
    skip = true,
    -- The layer column is stored and compared with its case intact (no fold),
    -- unlike child_name. A guest sees only the kernel's resolved value.
    -- TestBlanketTombstonesAreReturnedInACanonicalOrder stores layer "MIDDLE"
    -- and returns it verbatim ("MIDDLE/20"), which folding would collapse to
    -- "middle"; the folded form is used only for ordering, the raw layer is
    -- the primary-key/comparison term.
    covered_by = "go:loregd internal/handler::TestBlanketTombstonesAreReturnedInACanonicalOrder",
}, function() end)

test("the target_guid index covers only non-HIDDEN rows", {
    spec = "loregd *tables.the-target-guid-index-covers-only-non-hidden-rows",
    skip = true,
    -- A partial index (WHERE target_type = 0) is pure optimisation and not
    -- guest-observable; no sqlite3 to inspect it. It accelerates the reverse
    -- lookup orphan detection uses; TestCrashRecoveryOrphanedGUID exercises
    -- that reverse lookup end to end (an orphaned key with no path entry is
    -- cleaned, a referenced one is kept).
    covered_by = "go:loregd internal/hivedb::TestCrashRecoveryOrphanedGUID",
}, function() end)

test("the values table has the documented columns", {
    spec = "loregd *tables.the-values-table",
    skip = true,
    covered_by = "go:loregd internal/hivedb::TestTablesExist",
}, function() end)

test("the blanket_tombstones table records one row per key per layer", {
    spec = "loregd *tables.the-blanket-tombstones-table",
    skip = true,
    -- A base-layer blanket tombstone hides only layers *beneath* base (there
    -- are none), so its effect is not guest-observable without kernel layer
    -- precedence over a lower layer. TestSetBlanketTombstone asserts a
    -- blanket row is written to the blanket_tombstones table for a key+layer.
    covered_by = "go:loregd internal/handler::TestSetBlanketTombstone",
}, function() end)
