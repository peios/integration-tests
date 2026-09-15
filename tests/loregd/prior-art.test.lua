-- loregd appendix A1 (Prior Art) — loregd is specified against SQLite, and its
-- on-disk format has no relationship to the Windows REGF hive format.
--
-- Both reachable claims are proven against a real loregd serving PtState: the
-- storage engine is SQLite (format-3 files, WAL sidecars), and loregd neither
-- reads nor writes a REGF file. The precedence rule between this manual and the
-- RSI specification is a documentation convention, not a runtime property, and
-- is homed as an explained skip stub.

local loregd = require("helpers.loregd")

local KEY = loregd.KEY -- PtState\Durable

local vm = loregd.boot({ name = "loregd-priorart" })
loregd.format(vm)
loregd.mount(vm)
loregd.start(vm)

--- The first 15 bytes of a file: the SQLite format-3 magic, or not.
local function header15(path)
    local r = vm:run("head -c 15 '" .. path .. "'")
    return r.exit_code == 0, r.stdout
end

-- ==== reachable: specified against SQLite ===============================

-- A1 (SQLite): "loregd's storage engine is SQLite, and it is specified against
-- SQLite rather than against an abstract store. The schema, the concurrency
-- model, and the operational behaviour all name SQLite features directly: WAL
-- mode for concurrent readers alongside a serialised writer ..." The hive file
-- is a SQLite format-3 database, and while loregd serves it a WAL sidecar is
-- present — the concrete SQLite feature the manual names, not an abstract
-- store.
test("loregd is specified against SQLite, not an abstract store",
    { spec = "loregd *priorart.loregd-is-specified-against-sqlite-not-an-abstract-store" },
    function(t)
        -- A committed write, so WAL is exercised.
        loregd.new_key(vm, KEY):assert_ok()
        loregd.set(vm, KEY, "SqliteProbe", "dword:1"):assert_ok()

        local ok, hdr = header15(loregd.HIVE_FILE)
        t:assert(ok and hdr == "SQLite format 3",
            "the hive's storage engine is SQLite (format-3 magic): " .. tostring(hdr))

        -- WAL mode names a concrete SQLite feature: while a WAL connection is
        -- open, SQLite keeps a -wal write-ahead log and a -shm shared-memory
        -- index beside the database file.
        local wal = vm:run("test -f '" .. loregd.HIVE_FILE .. "-wal'").exit_code == 0
        local shm = vm:run("test -f '" .. loregd.HIVE_FILE .. "-shm'").exit_code == 0
        t:assert(wal or shm,
            "a WAL sidecar file (-wal/-shm) sits beside the hive database, so the " ..
            "hive is in the WAL mode the manual names directly — wal=" ..
            tostring(wal) .. " shm=" .. tostring(shm))
    end)

-- ==== reachable: no REGF, read or written ===============================

-- A1 (Windows registry hive format): "The on-disk format has no relationship
-- to REGF whatsoever, and no REGF file can be read by loregd or written by
-- it." Two observable halves: loregd cannot open a REGF file as a hive (it is
-- not a SQLite database, so the daemon fails to serve it), and the file loregd
-- itself writes is a SQLite database carrying the SQLite magic, never the
-- `regf` magic of a Windows hive.
test("no REGF file can be read or written by loregd",
    { spec = "loregd *priorart.no-regf-file-can-be-read-or-written-by-loregd" },
    function(t)
        -- The file loregd WROTE is SQLite, not REGF: its magic is the SQLite
        -- format-3 string, not the `regf` of a Windows hive.
        local ok, hdr = header15(loregd.HIVE_FILE)
        t:assert(ok and hdr == "SQLite format 3",
            "the file loregd writes carries the SQLite magic, not REGF: " .. tostring(hdr))
        t:assert(hdr:sub(1, 4) ~= "regf",
            "the file loregd writes is not a `regf` Windows hive")

        -- loregd cannot READ a REGF file: hand it one as a hive and it fails
        -- to open it (a REGF file is not a SQLite database), so it never serves
        -- it. A Windows hive begins with the `regf` magic.
        local REGF = "/mnt/pt-hive/windows.regf"
        vm:write_file(REGF, "regf" .. string.rep("\0", 508))
        local reread = header15(REGF)
        t:assert(select(2, header15(REGF)):sub(1, 4) == "regf",
            "the planted file is a REGF-shaped file (regf magic)")

        local p = loregd.spawn(vm, { "Regf=" .. REGF })
        local r = p:wait("20s")
        t:assert(r.exit_code ~= 0,
            "loregd cannot open a REGF file as a hive — it exits with a failure " ..
            "rather than serving it: exit=" .. tostring(r.exit_code) ..
            " stderr=" .. tostring(r.stderr))
        t:assert(tostring(r.stderr):lower():find("database", 1, true) ~= nil,
            "and the failure is that the REGF file is not a SQLite database, so " ..
            "loregd could not read it: " .. tostring(r.stderr))

        -- It never registered the hive: a `reg` call for it does not resolve.
        t:assert(vm:run("reg info Regf").exit_code ~= 0,
            "the REGF-backed hive was never served")
    end)

-- ==== untestable prose: documentation precedence ========================

-- A1 (RSI): "Where this manual and the RSI specification disagree about wire
-- behaviour, the specification is correct and this manual has a bug — the RSI
-- is a contract with the kernel, and loregd is one implementation of one side
-- of it."
--
-- This is not an assertion about loregd's runtime at all: it is a
-- documentation conflict-resolution rule stating which of two documents is
-- authoritative when they disagree. There is no behaviour to observe and no
-- unit test that could assert it — any concrete wire behaviour is already
-- governed by the RSI specification (PSPK) and tested as an RSI-conformance
-- fact, not as a property of this manual. Homed as a skip stub because the
-- anchor states document precedence, and the nearest evidence is simply that
-- the RSI wire contract lives in, and is owned by, PSPK rather than here.
test("the RSI specification wins over this manual", {
    spec = "loregd *priorart.the-rsi-specification-wins-over-this-manual",
    skip = true,
}, function() end)
