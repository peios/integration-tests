-- loregd §3.3 — the in-memory volatile store attached beside each hive.
--
-- Volatile lifetime and routing are reachable end to end: create a volatile
-- key, watch it answer, then take loregd down and watch it vanish while
-- persistent data survives.
--
-- Two mechanics shape the file:
--
--   * A bare SIGKILL + restart of loregd on the *same* hive name races the
--     kernel's asynchronous source teardown (the re-registration returns
--     ESTALE, or the new route never becomes ready). So the lifetime cases
--     take loregd down the way durability.test.lua does — a mediated-disk
--     `power_cut()` + `vm:reset()`, a full reboot that clears the kernel's
--     route state and kills loregd (and its in-memory volatile store) — and
--     rely on committed persistent data surviving the cut. The non-restart
--     cases each run their own daemon on a distinct hive name and SIGKILL it
--     at the end. Non-restart cases come first; the reboot cases come last.
--
--   * loregd has a known bug (PEI-515, the cases at the end of this file):
--     the path entry for a volatile child of a *persistent* parent is written
--     to the persistent table, so after a restart it dangles. The volatile
--     keys the reboot cases create are nested under a persistent holder, and
--     their disappearance is checked with a lookup (`reg info`), which drops
--     the dangling entry.

local loregd = require("helpers.loregd")
local lcs = require("helpers.lcs")
local sys = require("helpers.sys")

local vm = loregd.boot({ name = "loregd-volatile", mediated = true })
local disk = vm:disk("hive")
loregd.format(vm)
loregd.mount(vm)

local function start(t, name, file)
    return loregd.start(vm, t, { hives = { name .. "=" .. file }, wait_for = name })
end

--- SIGKILL a daemon and wait for the process to leave /proc. For the
--- non-restart cases, which do not re-register the name.
local function hardstop(proc)
    local pid = proc:pid()
    proc:kill("kill")
    wait_until(function() return loregd.exited(vm, pid) end,
        { timeout = 10, interval = 0.2, desc = "loregd to die after SIGKILL" })
    proc:wait("5s")
end

--- Does a key resolve? Uses lookup (`reg info`), which answers not-found for
--- a dangling entry.
local function exists(key)
    return vm:run("reg info '" .. key .. "'").exit_code == 0
end

-- ==== non-restart cases (own daemon, distinct name, SIGKILL at end) ====

-- §3.3: "RSI_CREATE_KEY ... the volatile flag in the request decides which
-- database receives it." / volatile.keys.volatile "defaults to 1 ... carries
-- that fact back out in responses". / "For an operation naming a single key,
-- the key's own storage decides ... whichever holds it determines where the
-- reads and writes go."
test("create_key is routed by the request's volatile flag", {
    spec = "loregd *volatile.create-key-is-routed-by-the-requests-volatile-flag " ..
        "*volatile.the-volatile-column-defaults-to-one " ..
        "*volatile.a-single-key-operation-follows-the-keys-own-store",
}, function(t)
    local proc = start(t, "PtFlag", "/mnt/pt-hive/flag.hive")

    vm:run("reg new 'PtFlag\\FlagVol' --volatile -p"):assert_ok()
    loregd.new_key(vm, [[PtFlag\FlagPers]]):assert_ok()

    local rv = vm:run("reg info 'PtFlag\\FlagVol' --json")
    rv:assert_ok()
    t:assert(rv.stdout:match('"volatile"%s*:%s*true'),
        "the --volatile request routed the key into the volatile store, whose " ..
        "volatile column defaults to 1 and comes back as true: " .. rv.stdout)

    local rp = vm:run("reg info 'PtFlag\\FlagPers' --json")
    rp:assert_ok()
    t:assert(rp.stdout:match('"volatile"%s*:%s*false'),
        "the plain request routed the key into the persistent store (0/false)")

    loregd.set(vm, [[PtFlag\FlagVol]], "VV", "dword:7"):assert_ok()
    local r, v = loregd.get(vm, [[PtFlag\FlagVol]], "VV")
    r:assert_ok()
    t:assert_eq(v, "7", "a value operation on the volatile key followed it into "
        .. "the volatile store")
    hardstop(proc)
end)

-- §3.3: "RSI_LOOKUP and RSI_ENUM_CHILDREN consult both and combine the
-- results, because a persistent parent may legitimately have volatile
-- children." No restart, so the volatile child's key is live and enumeration
-- of the persistent parent finds it across both stores.
test("lookup and enum children consult both stores",
    { spec = "loregd *volatile.lookup-and-enum-children-consult-both-stores" },
    function(t)
        local proc = start(t, "PtBoth", "/mnt/pt-hive/both.hive")

        loregd.new_key(vm, [[PtBoth\PPar]]):assert_ok()
        vm:run("reg new 'PtBoth\\PPar\\VChild' --volatile"):assert_ok()

        local r = vm:run("reg ls 'PtBoth\\PPar' --keys-only")
        r:assert_ok()
        t:assert(r.stdout:match("VChild/"),
            "enumerating the persistent parent returned its volatile child, so " ..
            "enum consulted both stores: " .. r.stdout)
        t:assert(exists([[PtBoth\PPar\VChild]]),
            "lookup found the volatile child under the persistent parent")
        hardstop(proc)
    end)

-- §3.3: "A shared-cache in-memory database exists as long as at least one
-- connection has it open. The write connection creates the volatile tables
-- and holds the database; the read connections ... attach the same URI and
-- see the same data through the shared cache." Two separate registry requests
-- (a write then a read) reach loregd on different connections; the volatile
-- database survived between them and the reader saw the writer's key.
test("the volatile database lives across requests; readers see the writer's data", {
    spec = "loregd *volatile.the-in-memory-database-lives-while-a-connection-holds-it " ..
        "*volatile.the-write-connection-creates-and-holds-the-volatile-database " ..
        "*volatile.readers-attach-the-same-uri-and-see-the-same-data",
}, function(t)
    local proc = start(t, "PtShare", "/mnt/pt-hive/shared.hive")

    vm:run("reg new 'PtShare\\Shared' --volatile -p"):assert_ok()
    loregd.set(vm, [[PtShare\Shared]], "S", "dword:3"):assert_ok()

    local r, v = loregd.get(vm, [[PtShare\Shared]], "S")
    r:assert_ok()
    t:assert_eq(v, "3",
        "a separate read request saw the volatile key an earlier write request "
        .. "created — the shared-cache database lived on and the reader attached "
        .. "the same URI")
    hardstop(proc)
end)

-- §3.3: "Each hive ... gets a second SQLite database, held entirely in
-- memory" and the URI "keeps one hive's volatile database distinct from
-- another's." A volatile key in one hive is invisible in the other. (That the
-- URI embeds the case-preserved hive name specifically is a code fact in
-- hivedb.attachVolatile; the observable consequence is this isolation.)
test("each hive gets its own volatile database", {
    spec = "loregd *volatile.each-hive-gets-a-second-in-memory-database " ..
        "*volatile.the-uri-uses-the-case-preserved-hive-name",
}, function(t)
    local proc = loregd.start(vm, t, {
        hives = { "Alpha=/mnt/pt-hive/alpha.hive", "Bravo=/mnt/pt-hive/bravo.hive" },
        wait_for = "Alpha",
    })
    wait_until(function() return vm:run("reg ls Bravo").exit_code == 0 end,
        { timeout = 30, interval = 0.5, desc = "the Bravo hive to register" })

    vm:run("reg new 'Alpha\\OnlyMine' --volatile -p"):assert_ok()
    t:assert(exists([[Alpha\OnlyMine]]), "the volatile key answers in its own hive")
    t:assert(not exists([[Bravo\OnlyMine]]),
        "the same-named key does not appear in the other hive: each hive has its "
        .. "own volatile database, keyed by its distinct URI")
    hardstop(proc)
end)

-- §3.3: "a transaction that mutates both persistent and volatile data commits
-- or rolls back as one unit" / "Volatile writes inside a transaction ...
-- disappear on rollback." Driven through the LCS client ioctls: one
-- transaction writes to both stores; committing lands both, aborting reverts
-- both. (A SQLite transaction spans every attached schema.) No restart.
test("a transaction spans both stores: commit lands both, abort reverts both", {
    spec = "loregd *volatile.a-transaction-across-both-stores-commits-or-rolls-back-as-one-unit " ..
        "*volatile.volatile-writes-are-invisible-until-commit-and-vanish-on-rollback",
}, function(t)
    local proc = start(t, "PtTxn", "/mnt/pt-hive/txn.hive")
    local w = vm:spawn_worker()

    loregd.new_key(vm, [[PtTxn\TxnC]]):assert_ok()
    loregd.new_key(vm, [[PtTxn\TxnA]]):assert_ok()

    local function open(path)
        local r = lcs.open_key(nil, w, -1, path, lcs.KEY_ALL_ACCESS)
        t:assert(r.ret >= 0, "open " .. path .. ": " .. sys.errname(r.errno or 0))
        return r.ret
    end

    -- COMMIT (positive control): set a persistent value and create a volatile
    -- key in one transaction; both land.
    local txn = assert(lcs.begin_transaction(w), "begin_transaction (commit case)")
    local persC = open([[PtTxn\TxnC]])
    local sv = lcs.set_value(nil, w, persC, "TxV", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
    t:assert_eq(sv.ret, 0, "set persistent value in txn: " .. sys.errname(sv.errno or 0))
    local ck = lcs.create_key(nil, w, { path = [[PtTxn\TxnCVol]], flags = lcs.OPTION_VOLATILE, txn_fd = txn })
    t:assert(ck.ret >= 0, "create volatile key in txn: " .. sys.errname(ck.errno or 0))
    local c = lcs.commit(nil, w, txn)
    t:assert_eq(c.ret, 0, "commit: " .. sys.errname(c.errno or 0))
    sys.close(w, txn)

    local rc, vc = loregd.get(vm, [[PtTxn\TxnC]], "TxV")
    t:assert_eq(rc.exit_code, 0, "committed persistent value is present: " .. rc.stderr)
    t:assert_eq(vc, "1", "committed persistent value has the written data")
    t:assert(exists([[PtTxn\TxnCVol]]), "committed volatile key is present")

    -- ABORT: same shape, then close the txn fd without committing. Neither
    -- write survives.
    local txn2 = assert(lcs.begin_transaction(w), "begin_transaction (abort case)")
    local persA = open([[PtTxn\TxnA]])
    local sv2 = lcs.set_value(nil, w, persA, "TxV", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn2 })
    t:assert_eq(sv2.ret, 0, "set persistent value in aborted txn: " .. sys.errname(sv2.errno or 0))
    local ck2 = lcs.create_key(nil, w, { path = [[PtTxn\TxnAVol]], flags = lcs.OPTION_VOLATILE, txn_fd = txn2 })
    t:assert(ck2.ret >= 0, "create volatile key in aborted txn: " .. sys.errname(ck2.errno or 0))
    sys.close(w, txn2) -- abort

    local ra = vm:run("reg get 'PtTxn\\TxnA' TxV")
    t:assert(ra.exit_code ~= 0,
        "the persistent value from the aborted transaction is gone (rolled back): "
        .. ra.stdout)
    t:assert(not exists([[PtTxn\TxnAVol]]),
        "and so is the volatile key — both halves reverted as one unit")
    hardstop(proc)
end)

-- ==== reboot cases (power_cut + vm:reset; must come last) =============

-- §3.3: "When loregd exits, the memory goes with the process and every
-- volatile key in every hive ceases to exist" / "Volatile keys ... never
-- reach the hive's database file" / "the volatile tables are always empty at
-- startup". The reboot takes loregd (and its in-memory store) down; the
-- committed persistent key survives the cut, the volatile one does not.
test("a volatile key dies with loregd; a persistent one survives", {
    spec = "loregd *volatile.every-volatile-key-ceases-to-exist-when-loregd-exits " ..
        "*volatile.volatile-keys-never-reach-the-hive-file " ..
        "*volatile.the-volatile-tables-are-always-empty-at-startup",
}, function(t)
    local NAME, FILE = "PtLife", "/mnt/pt-hive/life.hive"
    start(t, NAME, FILE)

    loregd.new_key(vm, [[PtLife\Holder]]):assert_ok()
    vm:run("reg new 'PtLife\\Holder\\Vol' --volatile"):assert_ok()
    loregd.new_key(vm, [[PtLife\PersKeep]]):assert_ok()
    loregd.set(vm, [[PtLife\PersKeep]], "V", "dword:5"):assert_ok()

    t:assert(exists([[PtLife\Holder\Vol]]), "the volatile key answers before the reboot")
    t:assert(exists([[PtLife\PersKeep]]), "the persistent key answers before the reboot")

    disk:power_cut()
    vm:reset()
    loregd.mount(vm, t)
    start(t, NAME, FILE)

    t:assert(not exists([[PtLife\Holder\Vol]]),
        "the volatile key is gone after loregd exited — it never reached the " ..
        "hive file, and the volatile tables came back empty at startup")
    local r, v = loregd.get(vm, [[PtLife\PersKeep]], "V")
    r:assert_ok()
    t:assert_eq(v, "5", "the committed persistent key and value survived the reboot")
end)

-- §3.3: "a persistent child beneath a volatile parent is forbidden by the
-- kernel's data model, so a volatile key's whole subtree is volatile." The
-- whole subtree vanishes when loregd exits.
test("a volatile key's whole subtree is volatile",
    { spec = "loregd *volatile.a-volatile-keys-whole-subtree-is-volatile" },
    function(t)
        local NAME, FILE = "PtSub", "/mnt/pt-hive/subtree.hive"
        start(t, NAME, FILE)

        loregd.new_key(vm, [[PtSub\SubHolder]]):assert_ok()
        vm:run("reg new 'PtSub\\SubHolder\\VTree' --volatile"):assert_ok()
        vm:run("reg new 'PtSub\\SubHolder\\VTree\\Kid' --volatile"):assert_ok()
        t:assert(exists([[PtSub\SubHolder\VTree\Kid]]),
            "the volatile subtree answers before the reboot")

        disk:power_cut()
        vm:reset()
        loregd.mount(vm, t)
        start(t, NAME, FILE)

        t:assert(not exists([[PtSub\SubHolder\VTree]]),
            "the volatile parent is gone after the reboot")
        t:assert(not exists([[PtSub\SubHolder\VTree\Kid]]),
            "and so is its child — the whole subtree was volatile and died with loregd")
    end)

-- ---- adversarial: a volatile child of a persistent parent -------------
--
-- §3.3 promises "a persistent parent may legitimately have volatile children"
-- and that a volatile key simply "ceases to exist when loregd exits". The
-- path entry for such a child is written to the *persistent* path_entries
-- table (handler.go:378 — RSI_CREATE_ENTRY arrives before RSI_CREATE_KEY, so
-- the child key's volatile flag is not yet known and the entry defaults to
-- persistent; PEI-515), and it is committed to the file. After the reboot it
-- outlives its key and dangles.
--
-- Up to 0.21.8 that dangling entry made enumerating the parent fail with EIO.
-- loregd 0.21.12 carries the enum-tolerance fix (1b307c0, PEI-233), which
-- drops it, so the first case guards that. The entry still occupies the
-- child's name, which the second case shows.
test("a persistent parent stays enumerable after a volatile child vanishes", {
    spec = "loregd *volatile.every-volatile-key-ceases-to-exist-when-loregd-exits",
}, function(t)
    local NAME, FILE = "PtBug", "/mnt/pt-hive/bug.hive"
    start(t, NAME, FILE)

    loregd.new_key(vm, [[PtBug\Parent]]):assert_ok()
    vm:run("reg new 'PtBug\\Parent\\VKid' --volatile"):assert_ok()
    t:assert_eq(vm:run("reg ls 'PtBug\\Parent' --keys-only").exit_code, 0,
        "the parent enumerates while the volatile child is alive")

    disk:power_cut()
    vm:reset()
    loregd.mount(vm, t)
    start(t, NAME, FILE) -- root stays enumerable: Parent is a valid child

    -- Spec: the volatile child has simply ceased to exist and the persistent
    -- parent is untouched, so enumerating it must succeed (and be empty).
    local ls = vm:run("reg ls 'PtBug\\Parent' --keys-only")
    t:assert_eq(ls.exit_code, 0,
        "enumerating a persistent parent whose only child was a now-vanished " ..
        "volatile key must succeed; instead the child's persistent path entry " ..
        "dangles and enum returns EIO: " .. ls.stderr)
end)

-- §3.3: "When loregd exits ... every volatile key in every hive ceases to
-- exist." A key that has ceased to exist leaves its name free, so after the
-- restart the same name must be creatable again under the same parent.
test("a vanished volatile child's name can be created again", {
    spec = "loregd *volatile.every-volatile-key-ceases-to-exist-when-loregd-exits",
    tags = { "known-bug" },
    -- PEI-515. The dangling persistent entry still holds the (parent, name,
    -- layer) triple, so RSI_CREATE_ENTRY answers RSI_ALREADY_EXISTS, and the
    -- lookup that follows drops that same entry as dangling. The create fails
    -- "not found", and the name stays unusable under that parent for good.
    -- 1b307c0 does not help here; this drops when the entry follows the
    -- volatile child instead of landing in the persistent table.
}, function(t)
    local NAME, FILE = "PtName", "/mnt/pt-hive/name.hive"
    start(t, NAME, FILE)

    loregd.new_key(vm, [[PtName\Parent]]):assert_ok()
    vm:run("reg new 'PtName\\Parent\\VKid' --volatile"):assert_ok()

    disk:power_cut()
    vm:reset()
    loregd.mount(vm, t)
    start(t, NAME, FILE)

    t:assert(not exists([[PtName\Parent\VKid]]),
        "precondition: the volatile child ceased to exist when loregd went down")
    local again = vm:run("reg new 'PtName\\Parent\\VKid'")
    t:assert_eq(again.exit_code, 0,
        "re-creating the vanished child's name must succeed; stdout: " ..
        again.stdout .. " stderr: " .. again.stderr)
    t:assert(exists([[PtName\Parent\VKid]]),
        "and the re-created key resolves")
end)

-- ---- unit-cited ------------------------------------------------------

test("the volatile schema mirrors the persistent one", {
    spec = "loregd *volatile.the-schema-mirrors-the-persistent-one",
    skip = true,
    -- The attached in-memory schema is internal SQL; no sqlite3 in the image.
    -- TestVolatileTablesExist asserts volatile.keys / volatile.path_entries /
    -- volatile.[values] / volatile.blanket_tombstones all exist with the same
    -- shape as the persistent tables.
    covered_by = "go:loregd internal/hivedb::TestVolatileTablesExist",
}, function() end)
