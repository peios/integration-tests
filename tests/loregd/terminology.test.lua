-- loregd §1.2 (Terminology) — the terms loregd adds to the kernel-side
-- registry vocabulary.
--
-- Where a term names a reachable behaviour it is proven against a real loregd:
-- the per-hive database file, case-folded comparison, the single write
-- connection's serialisation, and the in-memory volatile store's lifetime.
-- The read pool's round-robin selection and the read-only snapshot connection
-- are internal connection routing a caller never observes, and the orphan is a
-- storage-invariant a guest cannot construct; those three are homed on the
-- loregd Go unit tests that assert them, with the closed route noted.
--
-- One daemon serves the PtState cases at file scope. The two-hive case runs
-- its own daemon (distinct hive names) and SIGKILLs it; the volatile-lifetime
-- case reboots (power_cut + vm:reset) and comes last. The disk is mediated for
-- that reboot.

local loregd = require("helpers.loregd")
local lcs = require("helpers.lcs")
local sys = require("helpers.sys")

local KEY = loregd.KEY -- PtState\Durable

local vm = loregd.boot({ name = "loregd-term", mediated = true })
local disk = vm:disk("hive")
loregd.format(vm)
loregd.mount(vm)
local proc = loregd.start(vm)

--- Does a key resolve? Lookup (`reg info`), tolerant of a dangling entry.
local function exists(key)
    return vm:run("reg info '" .. key .. "'").exit_code == 0
end

--- The first 15 bytes of a file: the SQLite format-3 magic, or not.
local function is_sqlite(path)
    local r = vm:run("head -c 15 '" .. path .. "'")
    return r.exit_code == 0 and r.stdout == "SQLite format 3", r.stdout
end

--- SIGKILL a daemon and wait for it to leave /proc. These cases are not about
--- clean shutdown, and a SIGKILL needs no shutdown to complete.
local function hardstop(p)
    local pid = p:pid()
    p:kill("kill")
    wait_until(function() return loregd.exited(vm, pid) end,
        { timeout = 10, interval = 0.2, desc = "loregd to die after SIGKILL" })
    p:wait("5s")
end

-- ==== reachable: each hive has its own database file ====================

-- §1.2: "Hive database. The SQLite database file backing one hive. Each hive
-- registered by loregd has its own file, whose path is given on the command
-- line (§2.1)." Two hives named on one command line get two distinct SQLite
-- files at exactly those paths, and their data does not bleed across.
test("each hive has its own database file, at the path named on the command line",
    { spec = "loregd *term.each-hive-has-its-own-database-file" },
    function(t)
        local ALPHA, BRAVO = "/mnt/pt-hive/alpha.hive", "/mnt/pt-hive/bravo.hive"
        local p = loregd.start(vm, t, {
            hives = { "Alpha=" .. ALPHA, "Bravo=" .. BRAVO },
            wait_for = "Alpha",
        })
        wait_until(function() return vm:run("reg ls Bravo").exit_code == 0 end,
            { timeout = 30, interval = 0.5, desc = "the Bravo hive to register" })

        -- Each path named on the command line is now its own SQLite file.
        local aok, ahdr = is_sqlite(ALPHA)
        t:assert(aok, "Alpha's file exists at its command-line path and is SQLite: " .. ahdr)
        local bok, bhdr = is_sqlite(BRAVO)
        t:assert(bok, "Bravo's file exists at its command-line path and is SQLite: " .. bhdr)
        t:assert(ALPHA ~= BRAVO, "the two hives have distinct files")

        -- The two files back two independent hives: a key written to one is
        -- not in the other.
        loregd.new_key(vm, [[Alpha\OnlyInAlpha]]):assert_ok()
        t:assert(exists([[Alpha\OnlyInAlpha]]),
            "the key answers in its own hive's file")
        t:assert(not exists([[Bravo\OnlyInAlpha]]),
            "and not in the other hive's file — each hive has its own database")

        hardstop(p)
    end)

-- ==== reachable: the folded name drives case-insensitive comparison =====

-- §1.2: "Folded name. The case-folded form of a key name, value name, or child
-- name, stored in a `_folded` column beside the canonical case-preserving name
-- and used for all case-insensitive comparison (§3.4)." A key created in one
-- case resolves when looked up in another, and its value likewise — the
-- comparison is against the folded form, not the stored case.
test("a folded name is used for all case-insensitive comparison",
    { spec = "loregd *term.a-folded-name-is-used-for-all-case-insensitive-comparison" },
    function(t)
        loregd.new_key(vm, [[PtState\FoldName]]):assert_ok()
        loregd.set(vm, [[PtState\FoldName]], "MixedCase", "dword:9"):assert_ok()

        -- Key-name comparison folds: a differently-cased path resolves.
        t:assert(exists([[PtState\FOLDNAME]]),
            "an upper-cased path resolves to the mixed-case key: the key name is " ..
            "compared by its folded form")
        t:assert(exists([[PtState\foldname]]),
            "and a lower-cased path too")

        -- Value-name comparison folds: a differently-cased value name reads.
        local r, v = loregd.get(vm, [[PtState\FoldName]], "MIXEDCASE")
        r:assert_ok()
        t:assert_eq(v, "9",
            "a differently-cased value name reads the same value — value names " ..
            "compare by their folded form too")
    end)

-- ==== reachable: every mutation passes through the single write connection

-- §1.2: "Write connection. The single SQLite connection per hive through which
-- every mutation passes. Its uniqueness is what serialises writes (§4.1)."
-- Demonstrated by the funnel it is: a transaction bound on ONE key blocks a
-- write to a completely DIFFERENT key in the same hive. A per-key or per-table
-- lock would let the unrelated write proceed; because every mutation shares the
-- one write connection, the second write cannot run until the first releases it.
test("every mutation passes through the single write connection: a bound write " ..
     "on one key blocks a write to a different key", {
    spec = "loregd *term.every-mutation-passes-through-the-single-write-connection",
}, function(t)
    loregd.new_key(vm, [[PtState\Wc1]]):assert_ok()
    loregd.new_key(vm, [[PtState\Wc2]]):assert_ok()

    local A = vm:spawn_worker()
    local B = vm:spawn_worker()
    local function open(who, path)
        local r = lcs.open_key(nil, who, -1, path, lcs.KEY_ALL_ACCESS, 0)
        t:assert(r.ret >= 0, "open " .. path .. ": errno=" .. sys.errname(r.errno or 0))
        return r.ret
    end
    local fa = open(A, [[PtState\Wc1]])
    local fb = open(B, [[PtState\Wc2]])

    -- A binds the hive's single write connection with a write to Wc1.
    local txn = lcs.begin_transaction(A)
    local wa = lcs.set_value(nil, A, fa, "Held", lcs.TYPE.DWORD, lcs.dword(1),
        { txn_fd = txn })
    t:assert_eq(wa.ret, 0, "A's transactional write binds the write connection: errno=" ..
        sys.errname(wa.errno or 0))

    -- B writes a DIFFERENT key, Wc2, non-transactionally. It has no separate
    -- write path: it must wait for the one connection A holds.
    local nr, spec, decode = lcs.build.set_value(fb, "Blocked", lcs.TYPE.DWORD, lcs.dword(2))
    local pending = B:syscall_async(nr, spec)

    sys.nanosleep(vm, 2, 0)
    local probe = vm:run("reg get 'PtState\\Wc2' Blocked")
    t:assert(probe.exit_code ~= 0,
        "after 2s the write to the unrelated key Wc2 still has not landed: every " ..
        "mutation shares the one write connection, so it is parked behind A's " ..
        "transaction rather than proceeding on a path of its own")

    -- A commits, releasing the single connection; B's write to Wc2 then runs.
    t:assert_eq(lcs.commit(nil, A, txn).ret, 0, "A commits and releases the write connection")
    local wb = decode(pending:await())
    t:assert_eq(wb.ret, 0, "B's write to the different key completes once the " ..
        "connection is free: errno=" .. sys.errname(wb.errno or 0))
    local _, fin = loregd.get(vm, [[PtState\Wc2]], "Blocked")
    t:assert_eq(fin, "2", "and lands — the wait ended only when A freed the connection")

    sys.close(A, txn); sys.close(A, fa); sys.close(B, fb)
    A:kill(); A:join(); B:kill(); B:join()
end)

-- ==== unit-cited: internal connection routing a caller never sees =======

-- §1.2: "Read pool. The fixed set of connections serving reads that are not
-- part of a transaction, selected round-robin (§4.1)."
--
-- Genuinely not a guest-observable assertion: that the read pool serves
-- non-transactional reads is exercised by every non-transactional `reg get` in
-- this testset, but WHICH pool connection served a given read is never
-- surfaced to a caller — the response carries the data, not the connection
-- identity — and no loregd unit test asserts the rotation itself. The nearest
-- evidence is the mechanism in source: hivedb.go `ReadDB()` advances an atomic
-- counter and returns `readDBs[idx % len(readDBs)]`, over a pool built to
-- `ReadPoolSize()`. Homed as a skip stub because there is nothing a guest or a
-- unit test can assert about the round-robin choice beyond that source.
test("the read pool serves non-transactional reads round-robin", {
    spec = "loregd *term.the-read-pool-serves-non-transactional-reads-round-robin",
    skip = true,
}, function() end)

-- §1.2: "Snapshot connection. A dedicated connection opened for one read-only
-- transaction, pinning a point-in-time view of the hive database for that
-- transaction's lifetime (§4.3)."
--
-- Route closed: a guest can only ever begin a read-WRITE transaction
-- (reg_begin_transaction takes no mode argument), and the read-only snapshot
-- transaction that opens this connection is the kernel's own, used only inside
-- REG_IOC_BACKUP — never drivable as a general transaction from a caller.
-- TestReadOnlyTxnSnapshotIsolation opens a read-only transaction, fixes the
-- snapshot on its first read, commits a newer value OUTSIDE the transaction,
-- and shows the re-read within the transaction still sees the pinned
-- point-in-time value — the dedicated snapshot connection holds the view for
-- the transaction's lifetime, releasing it only on abort.
test("a snapshot connection pins a point-in-time view", {
    spec = "loregd *term.a-snapshot-connection-pins-a-point-in-time-view",
    skip = true,
    covered_by = "go:loregd internal/handler::TestReadOnlyTxnSnapshotIsolation",
}, function() end)

-- §1.2: "Orphan. A key record that no path entry in any layer points at.
-- Orphans are cleaned up at startup (§2.2) ..."
--
-- Route closed: a guest cannot construct a key record with no path entry
-- pointing at it. `reg` creates a key and its base path entry together; there
-- is no sqlite3 in the image to plant a bare key row; and RSI_DELETE_LAYER —
-- the operation that leaves orphans behind — is not guest-drivable (the kernel
-- hardcodes txn_id=0 on the frame and there is no REG_IOC_DELETE_LAYER in the
-- uapi). TestCrashRecoveryOrphanedGUID inserts a key row with no path entry
-- (plus a value on it), reopens the hive, and asserts both the key and its
-- value are gone — the orphan (a key nothing points at) is cleaned at startup;
-- TestCrashRecoveryPreservesNonOrphans shows a key WITH a path entry survives,
-- fixing the definition from both sides.
test("an orphan is a key record no path entry points at", {
    spec = "loregd *term.an-orphan-is-a-key-record-no-path-entry-points-at",
    skip = true,
    covered_by = "go:loregd internal/hivedb::TestCrashRecoveryOrphanedGUID",
}, function() end)

-- ==== reachable (reboot): the volatile database is in memory =============

-- §1.2: "Volatile database. The in-memory SQLite database backing one hive's
-- volatile keys ... It ... holds no data at startup, and is destroyed with the
-- process." A reboot ends the loregd process; the volatile key it held ceases
-- to exist (the in-memory database died with the process and came back empty),
-- while a committed persistent value survives — isolating the volatile store's
-- in-memory lifetime as the thing that was lost.
--
-- Reboots, so this case is last. The volatile key is nested under a persistent
-- holder so the dangling-entry restart bug (PEI-515) does not stop the root
-- enumerating during readiness.
test("the volatile database is in memory and destroyed with the process", {
    spec = "loregd *term.the-volatile-database-is-in-memory-and-destroyed-with-the-process",
}, function(t)
    loregd.new_key(vm, [[PtState\VolHolder]]):assert_ok()
    vm:run("reg new 'PtState\\VolHolder\\InMem' --volatile"):assert_ok()
    loregd.new_key(vm, [[PtState\PersistThrough]]):assert_ok()
    loregd.set(vm, [[PtState\PersistThrough]], "Keep", "dword:5"):assert_ok()

    t:assert(exists([[PtState\VolHolder\InMem]]),
        "the volatile key answers while the process holds its in-memory database")

    disk:power_cut()
    vm:reset()
    loregd.mount(vm, t)
    loregd.start(vm, t)

    t:assert(not exists([[PtState\VolHolder\InMem]]),
        "the volatile key is gone after the process ended — its in-memory " ..
        "database was destroyed with the process and came back holding no data")
    local r, v = loregd.get(vm, [[PtState\PersistThrough]], "Keep")
    r:assert_ok()
    t:assert_eq(v, "5",
        "while a committed persistent value survived — it was specifically the " ..
        "in-memory volatile database that died with the process")
end)
