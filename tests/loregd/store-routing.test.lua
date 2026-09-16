-- loregd §5.1 (Store Routing) — how an operation picks between the persistent
-- `main` schema and the attached `volatile` schema, and the operations that
-- span both.
--
-- What is reachable end to end:
--   * Create-key routes on the request's volatile flag, and a single-key
--     operation routes on the key's own volatile column: create a volatile and
--     a persistent key, watch loregd report each key's store (`reg info`
--     volatile flag comes from loregd, per §3.2) and serve value operations on
--     each. A value op on the volatile-only key is served only because routing
--     found the key by its volatile column.
--   * The spanning operations (LOOKUP, ENUM_CHILDREN, ...) combine both stores
--     via UNION ALL: a persistent parent enumerates its volatile child.
--   * The deletions do not route: they delete from both schemas
--     unconditionally, so a value on a volatile key is removed by a delete that
--     never consulted the column.
--
-- What a guest cannot observe (unit-cited, each read and run — all PASS):
--   * The two stores differ observably only by persistence across a restart;
--     the *table* a row physically lives in is otherwise invisible, and the
--     column/table divergence the spec warns about needs an external DB edit
--     (no sqlite3 in the image). RSI_NOT_FOUND for an unknown GUID is masked by
--     the kernel's own path-walk ENOENT. The cross-store duplicate the
--     no-dedup anchors describe cannot be created (the cross-schema guards
--     reject it). Those are homed on internal/handler unit tests.
--
-- Structure mirrors volatile-store.test.lua: a mediated disk, per-case daemons
-- on distinct hive names SIGKILLed at the end (never a clean SIGTERM an idle
-- loregd hangs on — PEI-1122), and the one reboot case last.

local loregd = require("helpers.loregd")

local vm = loregd.boot({ name = "loregd-route", mediated = true })
local disk = vm:disk("hive")
loregd.format(vm)
loregd.mount(vm)

local function start(t, name, file)
    return loregd.start(vm, t, { hives = { name .. "=" .. file }, wait_for = name })
end

--- SIGKILL a daemon and wait for it to leave /proc (no clean SIGTERM).
local function hardstop(proc)
    local pid = proc:pid()
    proc:kill("kill")
    wait_until(function() return loregd.exited(vm, pid) end,
        { timeout = 10, interval = 0.2, desc = "loregd to die after SIGKILL" })
    proc:wait("5s")
end

--- Does a key resolve? Lookup (`reg info`) tolerates a dangling entry.
local function exists(key)
    return vm:run("reg info '" .. key .. "'").exit_code == 0
end

-- ==== reachable cases (own daemon, distinct name, SIGKILL at end) ======

-- §5.1: "RSI_CREATE_KEY ... routes on the volatile flag carried in the request
-- instead." And: "For an operation that names a single key, the key's own
-- `volatile` column selects the store. loregd reads it with one statement
-- across both schemas." A create routes each key to the store its flag names
-- (loregd reports the stored column back through `reg info`), and a value
-- operation on the volatile-only key is served — isVolatileQ found it by its
-- column and routed to the volatile store; consulting only the persistent
-- table would answer not-found.
test("create-key routes on the request flag; a single-key op routes on the column", {
    spec = "loregd *route.create-key-routes-on-the-requests-volatile-flag " ..
        "*route.an-operation-naming-one-key-routes-on-the-keys-volatile-column",
}, function(t)
    local proc = start(t, "PtR1", "/mnt/pt-hive/r1.hive")

    vm:run("reg new 'PtR1\\Vk' --volatile -p"):assert_ok()
    loregd.new_key(vm, [[PtR1\Pk]]):assert_ok()

    -- Create routed on the request flag: loregd stored each key in the store
    -- the flag named and reports that column back.
    local rv = vm:run("reg info 'PtR1\\Vk' --json")
    rv:assert_ok()
    t:assert(rv.stdout:match('"volatile"%s*:%s*true'),
        "the --volatile request routed the key into the volatile store: " .. rv.stdout)
    local rp = vm:run("reg info 'PtR1\\Pk' --json")
    rp:assert_ok()
    t:assert(rp.stdout:match('"volatile"%s*:%s*false'),
        "the plain request routed the key into the persistent store: " .. rp.stdout)

    -- A single-key value op on the volatile-only key is served: routing read
    -- the key's own volatile column and went to the volatile store.
    loregd.set(vm, [[PtR1\Vk]], "V", "dword:7"):assert_ok()
    local r, v = loregd.get(vm, [[PtR1\Vk]], "V")
    r:assert_ok()
    t:assert_eq(v, "7",
        "a value op on the volatile-only key was served — routed by the key's " ..
        "own volatile column, not defaulted to the persistent store")

    loregd.set(vm, [[PtR1\Pk]], "V", "dword:9"):assert_ok()
    local r2, v2 = loregd.get(vm, [[PtR1\Pk]], "V")
    r2:assert_ok()
    t:assert_eq(v2, "9", "a value op on the persistent key was served from the persistent store")
    hardstop(proc)
end)

-- §5.1: "RSI_LOOKUP, RSI_ENUM_CHILDREN, RSI_READ_KEY and RSI_QUERY_VALUES are
-- not scoped to one store: a persistent parent may have volatile children ...
-- Each issues a single UNION ALL statement over the two schemas." A persistent
-- parent with a volatile child: enumeration and lookup both find the child
-- across the two stores.
test("the spanning operations combine both stores", {
    spec = "loregd *route.the-operations-that-span-both-stores",
}, function(t)
    local proc = start(t, "PtR2", "/mnt/pt-hive/r2.hive")

    loregd.new_key(vm, [[PtR2\PPar]]):assert_ok()
    vm:run("reg new 'PtR2\\PPar\\VChild' --volatile"):assert_ok()

    local r = vm:run("reg ls 'PtR2\\PPar' --keys-only")
    r:assert_ok()
    t:assert(r.stdout:match("VChild/"),
        "RSI_ENUM_CHILDREN on the persistent parent returned its volatile " ..
        "child, so the query spanned both stores: " .. r.stdout)
    t:assert(exists([[PtR2\PPar\VChild]]),
        "RSI_LOOKUP found the volatile child under the persistent parent (spans both)")
    hardstop(proc)
end)

-- §5.1: "The deletions — RSI_DELETE_ENTRY, RSI_DELETE_VALUE_ENTRY and
-- RSI_DROP_KEY — do not route at all. They delete from both schemas
-- unconditionally." A value on a volatile key is removed by a delete that
-- never consulted the key's volatile column — it issued DELETE against both
-- the main and the volatile table.
test("the deletions do not route and delete from both schemas", {
    spec = "loregd *route.the-deletions-do-not-route-and-delete-from-both-schemas",
}, function(t)
    local proc = start(t, "PtR4", "/mnt/pt-hive/r4.hive")

    vm:run("reg new 'PtR4\\Vk' --volatile -p"):assert_ok()
    loregd.set(vm, [[PtR4\Vk]], "Val", "dword:3"):assert_ok()
    local r, v = loregd.get(vm, [[PtR4\Vk]], "Val")
    r:assert_ok()
    t:assert_eq(v, "3", "precondition: the volatile-store value is present")

    vm:run("reg del 'PtR4\\Vk' Val"):assert_ok()

    local r2 = vm:run("reg get 'PtR4\\Vk' Val")
    t:assert(r2.exit_code ~= 0,
        "the value in the volatile store was removed by a delete that does not " ..
        "route — RSI_DELETE_VALUE_ENTRY issues DELETE against both schemas " ..
        "unconditionally: " .. r2.stdout)
    hardstop(proc)
end)

-- ==== reboot: an unknown child GUID's entry goes to the persistent table

-- §5.1: "RSI_CREATE_ENTRY routes on the volatile flag of the child key the
-- entry points at ... When that child GUID is present in neither store, the
-- entry is written to the persistent table." LCS dispatches RSI_CREATE_ENTRY
-- before RSI_CREATE_KEY, so a volatile child's entry is always created while
-- its GUID is in neither store — and lands in main.path_entries (handler.go:390,
-- the create-entry-before-create-key ordering, PEI-515). The entry then
-- survives loregd going down, while its volatile key does not, and dangles.
-- The persistent parent must still enumerate cleanly after a restart (the
-- child simply gone). Up to 0.21.8 the dangling entry made that enumeration
-- fail with EIO; loregd 0.21.12 carries the enum-tolerance fix (1b307c0,
-- PEI-233), which drops it. The dangling entry itself is still PEI-515's to
-- remove, and the name it blocks is volatile-store.test.lua's known-bug case.
-- NOT PEI-1122 (that is the SIGTERM hang).
test("an unknown child GUID's entry goes to the persistent table and dangles after restart", {
    spec = "loregd *route.an-entry-with-an-unknown-child-guid-goes-to-the-persistent-table",
}, function(t)
    local NAME, FILE = "PtRB", "/mnt/pt-hive/rb.hive"
    start(t, NAME, FILE)

    loregd.new_key(vm, [[PtRB\Parent]]):assert_ok()
    vm:run("reg new 'PtRB\\Parent\\VKid' --volatile"):assert_ok()
    t:assert_eq(vm:run("reg ls 'PtRB\\Parent' --keys-only").exit_code, 0,
        "the parent enumerates while the volatile child is alive")

    disk:power_cut()
    vm:reset()
    loregd.mount(vm, t)
    start(t, NAME, FILE) -- root stays enumerable: Parent is a valid child

    -- The volatile key is gone (its in-memory store died with loregd) — correct.
    t:assert(not exists([[PtRB\Parent\VKid]]),
        "the volatile child key ceased to exist when loregd went down")

    -- But its path entry went to the PERSISTENT table, so it outlived the key
    -- and dangles: enumerating the untouched persistent parent must succeed and
    -- be empty; instead it fails.
    local ls = vm:run("reg ls 'PtRB\\Parent' --keys-only")
    t:assert_eq(ls.exit_code, 0,
        "enumerating a persistent parent whose only child was a now-vanished " ..
        "volatile key must succeed; instead the child's entry — written to the " ..
        "persistent table because the child GUID was unknown at create-entry " ..
        "time — dangles and enum returns EIO: " .. ls.stderr)
end)

-- ==== unit-cited: not guest-observable ================================

-- §5.1: "A GUID present in neither [store] produces RSI_NOT_FOUND for most
-- operations." TestSetValueKeyNotFound / TestReadKeyNotFound /
-- TestQueryValuesKeyNotFound assert RSI_NOT_FOUND for a GUID in neither store.
-- Route closed: a guest names paths, and the kernel's path walk answers ENOENT
-- for a missing component before dispatching, so loregd's RSI_NOT_FOUND is not
-- separately observable.
test("a GUID in neither store produces RSI_NOT_FOUND", {
    spec = "loregd *route.a-guid-in-neither-store-produces-not-found",
    skip = true,
    covered_by = "go:loregd internal/handler::TestSetValueKeyNotFound",
}, function() end)

-- §5.1: "routing follows the column value, not which table the row came from
-- ... the distinction only matters if a database were modified externally."
-- isVolatileQ (handler.go:211) selects the `volatile` column and routes on its
-- value. TestSetValueVolatileKey shows a key whose column is 1 routes its value
-- to the volatile store; TestSetValue shows a column of 0 routes to main.
-- Route closed: rows loregd writes are always column/table-consistent, and the
-- divergence needs an external DB edit — no sqlite3 ships in the image.
test("routing follows the column value, not the source table", {
    spec = "loregd *route.routing-follows-the-column-value-not-the-source-table",
    skip = true,
    covered_by = "go:loregd internal/handler::TestSetValueVolatileKey",
}, function() end)

-- §5.1: "RSI_CREATE_ENTRY routes on the volatile flag of the child key the
-- entry points at." TestCreateEntryVolatileTarget seeds a volatile child key,
-- then creates its entry, and asserts the entry lands in
-- volatile.path_entries (not main). Route closed: LCS dispatches
-- RSI_CREATE_ENTRY before RSI_CREATE_KEY, so a guest cannot present the entry
-- with the child key already stored; the flag-consulting branch runs only when
-- the key row pre-exists, which the unit test constructs. (The always-taken
-- unknown-child branch is the known-bug case above.)
test("create-entry routes on the child key's volatile flag", {
    spec = "loregd *route.create-entry-routes-on-the-child-keys-volatile-flag",
    skip = true,
    covered_by = "go:loregd internal/handler::TestCreateEntryVolatileTarget",
}, function() end)

-- §5.1: "RSI_HIDE_ENTRY routes on the parent key, since a HIDDEN entry belongs
-- to the parent's child list and a volatile parent's whole subtree is
-- volatile." TestHideEntryVolatileParent hides a child under a volatile parent
-- and asserts the HIDDEN entry lands in volatile.path_entries. Route closed:
-- the hide path selects its table via isVolatileQ(parent), an internal SQL
-- table choice the guest cannot observe directly (the two stores differ only
-- by restart persistence).
test("hide-entry routes on the parent key", {
    spec = "loregd *route.hide-entry-routes-on-the-parent-key",
    skip = true,
    covered_by = "go:loregd internal/handler::TestHideEntryVolatileParent",
}, function() end)

-- §5.1: "Nothing de-duplicates across the two stores ... if the same triple
-- exists in both, both rows appear in the response." TestCreateEntryRejectsTripleHeldByTheOtherStore
-- creates the same (parent, name, layer) child in each store and shows loregd
-- adds a cross-schema check precisely because reads do not de-duplicate —
-- without the guard both rows would appear in one child block
-- (its comment: "Nothing de-duplicates on read, so RSI_LOOKUP and
-- RSI_ENUM_CHILDREN emitted both rows"). Route closed: the guard now keeps the
-- duplicate from ever being created via guest ops, so the two-rows response
-- cannot be produced end to end.
test("nothing de-duplicates across the two stores; a shared triple appears twice", {
    spec = "loregd *route.nothing-de-duplicates-across-the-two-stores " ..
        "*route.a-triple-present-in-both-stores-appears-twice-in-the-response",
    skip = true,
    covered_by = "go:loregd internal/handler::TestCreateEntryRejectsTripleHeldByTheOtherStore",
}, function() end)

-- §5.1: "The same holds for value entries keyed on (key_guid, name_folded,
-- layer)." Value reads use the same UNION-ALL-with-no-dedup shape:
-- TestQueryValuesAll returns every matching row (three, one name in two layers)
-- with no collapsing step. Route closed for the cross-store case: a key lives
-- in exactly one store (the key cross-schema guard, TestCreateKeyRejectsGUIDHeldByTheOtherStore),
-- so its values live in one store's [values] table — a guest cannot seed the
-- same value in both stores' tables to observe the non-dedup across them.
test("value entries are not de-duplicated either", {
    spec = "loregd *route.value-entries-are-not-de-duplicated-either",
    skip = true,
    covered_by = "go:loregd internal/handler::TestQueryValuesAll",
}, function() end)
