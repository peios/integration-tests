-- loregd §3.1 — the single-row schema_version table, the current version,
-- and how a version mismatch is handled.
--
-- Most of this chapter is about internal SQLite state (the schema_version
-- row, its integer, a second row, a missing version table). None of that is
-- exposed over RSI, and the image ships no sqlite3 to read or forge the
-- table, so the version integer and the mismatch branches are unit
-- territory (internal/hivedb). What IS reachable from a guest is the
-- observable consequence of the happy paths: loregd creating a brand-new
-- hive database and stamping it (§3.1: "The database is new. loregd creates
-- the persistent tables, the volatile tables, and inserts version 1, all in
-- one transaction."), and reopening that v1 database normally (§3.1:
-- "Version equals 1 | Normal startup.").
--
-- These two paths manage their own daemon because they are about startup and
-- restart; the disk is formatted and mounted once at file scope.

local loregd = require("helpers.loregd")

local KEY = loregd.KEY

local vm = loregd.boot({ name = "loregd-schema" })
loregd.format(vm)
loregd.mount(vm)

--- SIGKILL a daemon and wait for it to actually leave /proc, so the next
--- start reopens the hive file with no writer still holding it. SIGKILL,
--- not the clean SIGTERM `loregd.stop` sends — an idle loregd hangs on
--- SIGTERM (PEI-1122), and these cases are not about clean shutdown.
local function hardstop(proc)
    local pid = proc:pid()
    proc:kill("kill")
    wait_until(function() return loregd.exited(vm, pid) end,
        { timeout = 10, interval = 0.2, desc = "loregd to die after SIGKILL" })
    proc:wait("5s")
end

-- §3.1: "The database is new. loregd creates the persistent tables, the
-- volatile tables, and inserts version 1, all in one transaction." The hive
-- file does not exist yet on the freshly-mkfs'd disk; starting loregd must
-- create it, stamp it, and serve. (The single-transaction atomicity of the
-- stamp is not guest-observable — that is TestOpenCreatesNewDatabase — but
-- that the new database is created and stamped and then usable is.)
test("a brand-new hive database is created, stamped, and served",
    { spec = "loregd *schema.a-new-database-is-created-and-stamped-in-one-transaction" },
    function(t)
        local exists = vm:run("test -e " .. loregd.HIVE_FILE)
        t:assert(exists.exit_code ~= 0,
            "precondition: the hive file does not exist before the first start")

        local proc = loregd.start(vm, t) -- waits until `reg ls PtState` works
        loregd.new_key(vm, KEY):assert_ok()
        loregd.set(vm, KEY, "Fresh", "dword:1"):assert_ok()
        local r, v = loregd.get(vm, KEY, "Fresh")
        r:assert_ok()
        t:assert_eq(v, "1",
            "a value written to the just-created hive reads back, so the new " ..
            "database was created, stamped version 1, and is serving")

        local made = vm:run("test -e " .. loregd.HIVE_FILE)
        t:assert_eq(made.exit_code, 0, "and the hive file now exists on disk")
        hardstop(proc)
    end)

-- §3.1: "Version equals 1 | Normal startup." The database now exists at
-- version 1 (the previous case created it). Reopening it must start normally
-- and find the data intact — the version-1 path, exercised end to end.
test("an existing version-1 database starts normally",
    { spec = "loregd *schema.version-one-starts-normally" },
    function(t)
        local exists = vm:run("test -e " .. loregd.HIVE_FILE)
        t:assert_eq(exists.exit_code, 0,
            "precondition: a version-1 hive database is already on disk")

        local proc = loregd.start(vm, t)
        -- It served (loregd.start waits on `reg ls PtState`) and the data
        -- written under version 1 is still readable: a normal reopen.
        local r, v = loregd.get(vm, KEY, "Fresh")
        r:assert_ok()
        t:assert_eq(v, "1", "the version-1 database reopened and its data survived")
        -- And it still accepts writes, so this is a live normal startup, not
        -- a read-only degraded mode.
        loregd.set(vm, KEY, "Again", "dword:2"):assert_ok()
        local r2, v2 = loregd.get(vm, KEY, "Again")
        r2:assert_ok()
        t:assert_eq(v2, "2", "and the reopened database takes new writes")
        hardstop(proc)
    end)

-- ---- unit-cited: internal SQLite state, no guest route ----------------
--
-- schema_version is a private table. No RSI op and no `reg` command reports
-- the version integer, the row count, or the table's existence, and no
-- sqlite3 ships in the image to read it. These anchors are homed on the
-- internal/hivedb tests that assert the property directly; each was read and
-- run (all PASS) before being cited.

test("every hive database carries a schema_version row", {
    spec = "loregd *schema.every-hive-database-carries-a-schema-version",
    skip = true,
    -- Route closed: `reg ls PtState` proves a hive is served but says nothing
    -- about the schema_version table; no sqlite3 to inspect it.
    covered_by = "go:loregd internal/hivedb::TestSchemaVersionSingleRow",
}, function() end)

test("the current schema version is 1", {
    spec = "loregd *schema.the-current-version-is-one",
    skip = true,
    -- TestSchemaVersion asserts the stamped version equals schemaVersion,
    -- and schemaVersion is the const 1 (schema.go).
    covered_by = "go:loregd internal/hivedb::TestSchemaVersion",
}, function() end)

test("a schema version newer than 1 fails startup", {
    spec = "loregd *schema.a-newer-version-fails-startup",
    skip = true,
    -- Route closed: forging a version>1 row needs sqlite3 (absent) — loregd
    -- never writes a version above 1 itself. TestSchemaVersionTooNew builds a
    -- version-2 database on the host and asserts Open returns an error.
    covered_by = "go:loregd internal/hivedb::TestSchemaVersionTooNew",
}, function() end)

-- ---- coverage gaps: no guest route AND no unit test ------------------
--
-- The remaining mismatch branches are neither guest-reachable (no sqlite3 to
-- construct a below-one / two-row / no-version-table database, and loregd
-- never produces those states itself) NOR covered by any internal/hivedb
-- test. I verified the absence: the only version-guard unit test is
-- TestSchemaVersionTooNew (the version>1 branch). Citing it here would be a
-- citation to a test that does not prove the anchor, which the brief forbids.
-- Each is flagged with a PEI-TBD marker for the coordinator to ticket as a
-- coverage gap, not a code/spec disagreement — the code (schema.go
-- ensureSchema) does implement each of these.

test("a schema version below 1 fails startup", {
    spec = "loregd *schema.a-version-below-one-fails-startup",
    skip = true,
    -- PEI-TBD-loregd-schema-below-one-untested
    covered_by = "GAP: no guest route (no sqlite3 to build a v<1 database) and "
        .. "no internal/hivedb test covers the version<schemaVersion branch "
        .. "(schema.go:275) — PEI-TBD-loregd-schema-below-one-untested",
}, function() end)

test("there are no migrations", {
    spec = "loregd *schema.there-are-no-migrations",
    skip = true,
    -- Same code path as below-one: version<schemaVersion is reported as
    -- "requires migration (no migrations implemented)" (schema.go:276). No
    -- guest route and no unit test asserts the message or the absence of a
    -- migration table/step list.
    -- PEI-TBD-loregd-schema-no-migrations-untested
    covered_by = "GAP: no guest route and no internal/hivedb test asserts the "
        .. "no-migrations branch — PEI-TBD-loregd-schema-no-migrations-untested",
}, function() end)

test("a second schema_version row is not detected", {
    spec = "loregd *schema.a-second-version-row-is-not-detected",
    skip = true,
    -- Needs a schema_version table with two rows; loregd only ever inserts
    -- one and there is no sqlite3 to add a second. No unit test exercises the
    -- "first row read wins" behaviour.
    -- PEI-TBD-loregd-schema-second-row-untested
    covered_by = "GAP: no guest route (no sqlite3 to insert a second version "
        .. "row) and no internal/hivedb test — PEI-TBD-loregd-schema-second-row-untested",
}, function() end)

test("a database without a version table is stamped unvalidated", {
    spec = "loregd *schema.a-database-without-a-version-table-is-stamped-unvalidated",
    skip = true,
    -- Needs a database holding the data tables but no schema_version table;
    -- loregd always creates schema_version first, so it never produces this
    -- state, and no sqlite3 can forge it. No unit test covers the
    -- IF-NOT-EXISTS stamping of such a database.
    -- PEI-TBD-loregd-schema-no-version-table-untested
    covered_by = "GAP: no guest route and no internal/hivedb test — "
        .. "PEI-TBD-loregd-schema-no-version-table-untested",
}, function() end)
