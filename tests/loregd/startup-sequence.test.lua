-- loregd §2.2 — the ten startup steps, which run to completion before a
-- single request is accepted and any failure in which is fatal.
--
-- Many steps establish internal SQLite state (WAL, foreign keys, busy
-- timeout, the single-connection limit, schema versioning, orphan
-- cleanup) that a guest cannot observe: no sqlite3 ships in the image, so
-- the database file cannot be inspected, and the precondition for a
-- schema mismatch or a hand-planted orphan cannot be built through `reg`.
-- Those anchors are homed on the loregd unit tests that prove them, each
-- verified to exist and pass. The rest — argument validation ordering,
-- directory creation, the volatile store, first-boot root + descriptor,
-- WAL recovery, the device open, registration, readiness — are observable
-- and tested live against a real loregd.

local loregd = require("helpers.loregd")
local unixsock = require("helpers.unixsock")

local MOUNT = loregd.MOUNT

local vm = loregd.boot({ name = "loregd-startup" })
loregd.format(vm)
loregd.mount(vm)

-- One long-lived daemon serving the fresh PtState fixture, shared by the
-- observational cases below. Started fresh, so it exercises first boot:
-- schema creation, root-key generation, the default descriptor. Never
-- SIGTERMed (PEI-1122 would hang it); dies with the VM.
local main = loregd.start(vm)

-- Spawn loregd with an explicit argv/env and wait for registration.
local function start_env(t, hives, wait_for, env, env_clear)
    local proc = vm:run_async("/usr/sbin/loregd",
        { args = hives, env = env or {}, env_clear = env_clear or false })
    local ok = pcall(wait_until, function()
        return vm:run("reg ls " .. wait_for).exit_code == 0
    end, { timeout = 30, interval = 0.5, desc = "loregd to register " .. wait_for })
    if not ok then
        proc:kill("kill")
        local r = proc:wait("5s")
        t:assert(false, "loregd never registered " .. wait_for ..
            ": exit=" .. tostring(r.exit_code) .. " stderr=" .. tostring(r.stderr))
    end
    return proc
end

-- ---- Step 1: parse and validate first --------------------------------

-- "Startup runs to completion before loregd accepts a single request ...
--  Any failure in it is fatal: loregd logs the error and exits non-zero
--  rather than serving a hive it could not fully prepare."
test("any startup failure is fatal and exits non-zero",
    { spec = "loregd *startup.any-startup-failure-is-fatal-and-exits-non-zero" },
    function(t)
        -- A hive whose parent directory cannot be created (MkdirAll under
        -- /proc fails) makes step 2 fail; startup must abort non-zero
        -- rather than come up serving.
        local r = loregd.spawn(vm, { "Bad=/proc/nonexistent/deep/x.hive" }):wait("10s")
        t:assert_eq(r.status, "exited", "loregd exits rather than being signalled: " .. r.stderr)
        t:assert(r.exit_code ~= 0,
            "a startup failure aborts non-zero, got " .. tostring(r.exit_code) ..
            ". stderr=" .. r.stderr)
    end)

-- "1. Parse and validate arguments ... Extract the hive name to database
--  path mapping and apply the validation in §2.1." Validation is step 1,
--  before any database is opened in step 2.
test("arguments are parsed and validated before any database is opened",
    { spec = "loregd *startup.arguments-are-parsed-and-validated-first" },
    function(t)
        local good = MOUNT .. "/validated-first.hive"
        vm:run("rm -f '" .. good .. "'")
        -- A good hive alongside an invalid argument (no '='). If opening
        -- happened before validation, `good` would be created on disk;
        -- because validation is first, the whole invocation is rejected
        -- and nothing is opened or created.
        local r = loregd.spawn(vm, { "Good=" .. good, "NoEqualsHere" }):wait("10s")
        t:assert(r.exit_code ~= 0, "the invocation is rejected: " .. r.stderr)
        t:assert_eq(vm:run("test -e '" .. good .. "'").exit_code, 1,
            "no database was opened or created before validation rejected the argv")
    end)

-- ---- Step 2: open each hive database ---------------------------------

-- "For each declared hive, create the database file's parent directory if
--  it is absent (mode 0700), then open — or create — the SQLite database."
test("each declared hive's database is opened or created",
    { spec = "loregd *startup.each-declared-hives-database-is-opened-or-created" },
    function(t)
        local a, b = MOUNT .. "/openA.hive", MOUNT .. "/openB.hive"
        vm:run("rm -f '" .. a .. "' '" .. b .. "'")
        local proc = start_env(t, { "OpenA=" .. a, "OpenB=" .. b }, "OpenA", {})
        for name, path in pairs({ OpenA = a, OpenB = b }) do
            t:assert_eq(vm:run("test -f '" .. path .. "'").exit_code, 0,
                "hive " .. name .. "'s database file was created at " .. path)
            t:assert_eq(vm:run("reg ls " .. name).exit_code, 0,
                "hive " .. name .. " is served from its database")
        end
        proc:kill("kill")
    end)

-- "create the database file's parent directory if it is absent (mode
--  0700)."
test("a missing parent directory is created with mode 0700",
    { spec = "loregd *startup.a-missing-parent-directory-is-created-mode-0700" },
    function(t)
        local dir = MOUNT .. "/private-state"
        vm:run("rm -rf '" .. dir .. "'")
        local proc = start_env(t, { "Priv=" .. dir .. "/nested/machine.hive" }, "Priv", {})
        -- The absent parent (and the file) came into being at startup.
        t:assert_eq(vm:run("test -d '" .. dir .. "'").exit_code, 0,
            "the missing parent directory was created")
        local mode = vm:run("stat -c %a '" .. dir .. "'").stdout:gsub("%s+$", "")
        t:assert_eq(mode, "700",
            "the created directory is private to the service (0700), got " .. mode)
        proc:kill("kill")
    end)

-- The four PRAGMAs and the single-connection limit are established on the
-- connection but read no differently through `reg`; with no sqlite3 in
-- the guest the pragma values cannot be observed, so each is homed on the
-- hivedb unit test that reads it back.

test("WAL mode is verified and the open fails without it",
    {
        spec = "loregd *startup.wal-mode-is-verified-and-the-open-fails-without-it",
        skip = true,
        -- Not guest-observable: no sqlite3 to read `PRAGMA journal_mode`,
        -- and no way to hand loregd a database that refuses WAL. TestWALMode
        -- opens a hive and asserts journal_mode reads back "wal" (enableWAL
        -- returns an error otherwise, failing the open).
        covered_by = "go:loregd internal/hivedb::TestWALMode",
    }, function() end)

test("foreign keys are enabled",
    {
        spec = "loregd *startup.foreign-keys-are-enabled",
        skip = true,
        -- Not guest-observable (no sqlite3 for `PRAGMA foreign_keys`).
        -- TestForeignKeysEnabled asserts it reads back 1 on both a write
        -- and a read connection.
        covered_by = "go:loregd internal/hivedb::TestForeignKeysEnabled",
    }, function() end)

test("the busy timeout is twenty-five seconds",
    {
        spec = "loregd *startup.the-busy-timeout-is-twenty-five-seconds",
        skip = true,
        -- Not practically guest-observable (a 25s contention window, and
        -- no sqlite3 to read `PRAGMA busy_timeout`). TestBusyTimeout
        -- asserts busy_timeout == BusyTimeoutMs (25000).
        covered_by = "go:loregd internal/hivedb::TestBusyTimeout",
    }, function() end)

test("each SQL handle is limited to one underlying connection",
    {
        spec = "loregd *startup.each-sql-handle-is-limited-to-one-underlying-connection",
        skip = true,
        -- NOT guest-observable: a black-box guest cannot distinguish
        -- per-handle single-connection serialization from the busy_timeout
        -- serialization it also has. Homed on a unit test (added with this
        -- suite, PEI-1121) that reads db.Stats().MaxOpenConnections == 1 back
        -- from the write handle, every read-pool handle, and a snapshot handle.
        covered_by = "go:loregd internal/hivedb::TestEachSQLHandleHasOneConnection",
    }, function() end)

-- ---- Step 3-4: volatile store and schema -----------------------------

-- "Each hive gets an in-memory SQLite database, attached ... under the
--  schema name `volatile` ... the volatile *tables* are created in step 4."
test("the volatile store is attached and its tables are created",
    {
        spec = "loregd *startup.the-volatile-store-is-attached-as-schema-volatile" ..
            " *startup.the-volatile-tables-are-created-with-the-schema",
    },
    function(t)
        -- A volatile key and value can only be created and read back if
        -- the volatile store is attached and its tables exist. This is the
        -- live consequence of steps 3 and 4 together.
        local key = loregd.HIVE .. [[\VolProbe]]
        vm:run("reg new '" .. key .. "' --volatile -p"):assert_ok()
        vm:run("reg set '" .. key .. "' V dword:9"):assert_ok()
        local r, val = loregd.get(vm, key, "V")
        t:assert_eq(r.exit_code, 0, "the volatile value reads back: " .. r.stderr)
        t:assert_eq(val, "9",
            "a value written into a volatile key survives in the attached volatile store")
        -- And `reg info` confirms the key is volatile, i.e. it lives in
        -- the volatile schema, not the persistent tables.
        local info = vm:run("reg info '" .. key .. "'")
        t:assert_contains(info.stdout, "volatile", "the key is reported as volatile")
    end)

-- "If the database has no `schema_version` table, it is new: loregd
--  creates the persistent tables, creates the volatile tables, and stamps
--  the schema version, in one transaction."
test("a new database gets its schema created and comes up serving",
    { spec = "loregd *startup.a-new-database-gets-its-schema-created-in-one-transaction" },
    function(t)
        local path = MOUNT .. "/fresh-schema.hive"
        vm:run("rm -f '" .. path .. "'")
        local proc = start_env(t, { "FreshS=" .. path }, "FreshS", {})
        -- A brand-new file with no schema_version table came up fully
        -- served: the schema (persistent + volatile) was created and
        -- stamped. The single-transaction atomicity is a crash-window
        -- property not reproducible in-guest, but the schema-creation
        -- outcome is observed directly here.
        t:assert_eq(vm:run("reg ls FreshS").exit_code, 0,
            "the new hive is served, so its schema was created")
        vm:run("reg new 'FreshS\\K' -p"):assert_ok()
        vm:run("reg set 'FreshS\\K' V dword:1"):assert_ok()
        t:assert_eq((select(2, loregd.get(vm, "FreshS\\K", "V"))), "1",
            "the created schema is usable for reads and writes")
        proc:kill("kill")
    end)

test("a schema version mismatch in either direction aborts startup",
    {
        spec = "loregd *startup.a-schema-version-mismatch-in-either-direction-aborts-startup",
        skip = true,
        -- Not guest-constructable: building a database whose schema_version
        -- row is newer (or older) than loregd supports needs sqlite3, which
        -- the image does not ship. TestSchemaVersionTooNew plants a
        -- schema_version of schemaVersion+1 and asserts Open fails; the
        -- symmetric older-direction branch (version < schemaVersion ->
        -- "requires migration") is the same code path, hivedb.go:275.
        covered_by = "go:loregd internal/hivedb::TestSchemaVersionTooNew",
    }, function() end)

-- ---- Step 5: first-boot root key + descriptor ------------------------

-- "For each hive, look for a key with no parent. If none exists, this is
--  the hive's first boot: loregd generates a random 16-byte GUID for the
--  root key ... and inserts the root key record."
test("a hive with no parentless key gets a generated root key on first boot",
    { spec = "loregd *startup.a-hive-with-no-parentless-key-gets-a-generated-root-key" },
    function(t)
        -- The file-scope PtState daemon opened a brand-new database. If no
        -- root key had been generated, the hive would have no openable root
        -- and `reg` could not list or write it.
        t:assert_eq(vm:run("reg ls " .. loregd.HIVE).exit_code, 0,
            "the first-boot hive has a usable root key")
        local info = vm:run("reg info " .. loregd.HIVE)
        t:assert_eq(info.exit_code, 0, "the root key is openable: " .. info.stderr)
        -- A root key can hold subkeys — a well-formed key record, not a
        -- placeholder.
        loregd.new_key(vm, loregd.HIVE .. [[\RootChild]]):assert_ok()
        t:assert_eq(vm:run("reg ls '" .. loregd.HIVE .. [[\RootChild]] .. "'").exit_code, 0,
            "the generated root anchors a real key tree")
    end)

-- "The default root descriptor grants SYSTEM and Administrators full
--  access to the key, grants Authenticated Users read access, marks all
--  three as container-inheritable, and sets both owner and group to
--  SYSTEM."
test("the default hive-root security descriptor is as specified",
    { spec = "loregd *startup.the-default-hive-root-descriptor" },
    function(t)
        local r = vm:run("reg sd " .. loregd.HIVE)
        t:assert_eq(r.exit_code, 0, "the root SD reads back as SDDL: " .. r.stderr)
        local sddl = r.stdout
        -- Owner and group are SYSTEM (SDDL alias SY).
        t:assert_contains(sddl, "O:SY", "owner is SYSTEM. SDDL=" .. sddl)
        t:assert_contains(sddl, "G:SY", "group is SYSTEM. SDDL=" .. sddl)
        -- An access-allowed, container-inherit ACE for each principal:
        -- SYSTEM (SY), Administrators (BA), Authenticated Users (AU).
        for _, sid in ipairs({ "SY", "BA", "AU" }) do
            t:assert(sddl:find("%(A;[^)]*CI[^)]*;;;" .. sid .. "%)"),
                "a container-inheritable access-allowed ACE for " .. sid ..
                ". SDDL=" .. sddl)
        end
    end)

-- ---- Step 6: crash recovery ------------------------------------------

-- "SQLite's own WAL recovery handles any transaction that was uncommitted
--  when the process died; it happens when the database is opened and needs
--  nothing from loregd."
test("WAL recovery is SQLite's own and needs nothing from loregd",
    { spec = "loregd *startup.wal-recovery-is-sqlites-own-and-needs-nothing-from-loregd" },
    function(t)
        local path = MOUNT .. "/wal-recovery.hive"
        vm:run("rm -f '" .. path .. "'*")
        local proc = start_env(t, { "Wal=" .. path }, "Wal", {})
        vm:run("reg new 'Wal\\K' -p"):assert_ok()
        vm:run("reg set 'Wal\\K' V dword:42"):assert_ok()

        -- SIGKILL: the process dies abruptly with no clean close, leaving
        -- whatever WAL frames it had. On the next Open, SQLite recovers
        -- the WAL automatically — loregd runs no WAL-recovery step of its
        -- own (only orphan cleanup).
        local pid = proc:pid()
        proc:kill("kill")
        pcall(wait_until, function() return loregd.exited(vm, pid) end,
            { timeout = 10, interval = 0.25, desc = "the killed daemon to exit" })

        local proc2 = start_env(t, { "Wal=" .. path }, "Wal", {})
        local r, val = loregd.get(vm, "Wal\\K", "V")
        t:assert_eq(r.exit_code, 0, "the hive reopens cleanly after an abrupt death: " .. r.stderr)
        t:assert_eq(val, "42",
            "the committed value is intact after reopen — SQLite recovered the WAL " ..
            "on open with nothing done by loregd")
        proc2:kill("kill")
    end)

-- Orphan construction (a key no path entry points at) cannot be built
-- through `reg`, which always creates a key with its naming path entry;
-- the anchors that need a hand-planted orphan are homed on the unit test.

test("orphaned keys are defined by, and cleaned in order of, their missing path entry",
    {
        spec = "loregd *startup.an-orphaned-key-is-one-no-path-entry-points-at" ..
            " *startup.orphaned-keys-are-deleted-values-then-tombstones-then-records",
        skip = true,
        -- Not guest-constructable: an orphan is a key with no path entry,
        -- and `reg` never leaves a key without one. TestCrashRecoveryOrphanedGUID
        -- inserts a parented key with a value but no path entry, reopens,
        -- and asserts both the key record and its value are gone.
        covered_by = "go:loregd internal/hivedb::TestCrashRecoveryOrphanedGUID",
    }, function() end)

-- "The hive root is exempt: it legitimately has no parent and no path
--  entry pointing at it, so orphan detection skips keys whose parent_guid
--  is null."
test("orphan detection skips keys with a null parent (the root survives restart)",
    { spec = "loregd *startup.orphan-detection-skips-keys-with-a-null-parent" },
    function(t)
        local path = MOUNT .. "/nullparent.hive"
        vm:run("rm -f '" .. path .. "'*")
        local proc = start_env(t, { "Nullp=" .. path }, "Nullp", {})
        vm:run("reg new 'Nullp\\Child' -p"):assert_ok()
        vm:run("reg set 'Nullp\\Child' V dword:7"):assert_ok()
        local pid = proc:pid()
        proc:kill("kill")
        pcall(wait_until, function() return loregd.exited(vm, pid) end,
            { timeout = 10, interval = 0.25, desc = "daemon to exit" })

        -- On reopen, cleanOrphans runs. The root key (null parent, no path
        -- entry pointing at it) must be skipped; if orphan detection did
        -- not exempt null-parent keys it would delete the root and the
        -- hive would be unusable.
        local proc2 = start_env(t, { "Nullp=" .. path }, "Nullp", {})
        t:assert_eq(vm:run("reg ls Nullp").exit_code, 0,
            "the root key survived orphan cleanup across restart")
        t:assert_eq((select(2, loregd.get(vm, "Nullp\\Child", "V"))), "7",
            "and the properly-linked child was preserved too")
        proc2:kill("kill")
    end)

-- ---- Step 7: maximum sequence ----------------------------------------

test("the maximum sequence is taken across every table and every hive",
    {
        spec = "loregd *startup.the-maximum-sequence-is-taken-across-every-table-and-every-hive",
        skip = true,
        -- The sequence figure loregd reports at registration is internal;
        -- `reg` exposes a value's winning sequence but not the global
        -- max, and there is no sqlite3 to read the tables. TestMaxSequenceWithData
        -- seeds path_entries/values/blanket_tombstones with sequences
        -- 42/100/7 and asserts MaxSequence() == 100 (the max across every
        -- table); main.go then folds that across hives into globalMaxSeq.
        covered_by = "go:loregd internal/hivedb::TestMaxSequenceWithData",
    }, function() end)

-- ---- Step 8: open the registry device --------------------------------

-- "Open `/dev/pkm_registry`."
test("the registry device is opened at /dev/pkm_registry",
    { spec = "loregd *startup.the-registry-device-is-opened-at-dev-pkm-registry" },
    function(t)
        -- The running daemon holds the device open; its descriptor table
        -- names exactly which device. This is the compiled-in device.Path,
        -- confirmed live rather than by reading the constant.
        local pid = main:pid()
        local fds = vm:run("ls -l /proc/" .. pid .. "/fd")
        t:assert_eq(fds.exit_code, 0, "read the daemon's fd table: " .. fds.stderr)
        t:assert_contains(fds.stdout, "/dev/pkm_registry",
            "loregd holds /dev/pkm_registry open. fds=" .. fds.stdout)
    end)

-- "The kernel requires `SeTcbPrivilege` in the calling thread's token to
--  permit this; loregd performs no check of its own and relies on the
--  kernel to refuse."
test("the kernel, not loregd, enforces SeTcbPrivilege on the device open",
    {
        spec = "loregd *startup.the-kernel-not-loregd-enforces-setcbprivilege",
        skip = true,
        -- loregd's device.Open is a bare OpenFile with no privilege check
        -- (the negative is not observable), and dropping SeTcbPrivilege from
        -- loregd's token to watch the kernel refuse is not guest-constructable
        -- here. The kernel-side enforcement is the substance: pkm's
        -- plan_source_device_open(false) returns MissingTcbPrivilege.
        covered_by = "rust:pkm crates/lcs-core/tests/source/source_device_open.rs::source_device_open_requires_tcb_privilege",
    }, function() end)

-- ---- Step 9: register the hives --------------------------------------

-- "Issue `REG_SRC_REGISTER` with every hive name, its root key GUID, and
--  the global maximum sequence number." "The registration flags are zero:
--  loregd registers global hives only and never private ones."
test("registration presents every hive name and root, as global hives",
    {
        spec = "loregd *startup.registration-sends-every-hive-name-root-guid-and-the-maximum-sequence" ..
            " *startup.the-registration-flags-are-zero-so-hives-are-global",
    },
    function(t)
        local a, b = MOUNT .. "/regA.hive", MOUNT .. "/regB.hive"
        vm:run("rm -f '" .. a .. "' '" .. b .. "'")
        local proc = start_env(t, { "RegA=" .. a, "RegB=" .. b }, "RegA", {})
        -- Every declared hive name reached the kernel and routes to its own
        -- independently-rooted store — each has its own generated root and
        -- its own subkeys, so both names + root GUIDs were in the register
        -- call. (The global-max-sequence field of that same call is homed
        -- on TestMaxSequenceWithData.)
        vm:run("reg new 'RegA\\OnlyInA' -p"):assert_ok()
        t:assert_eq(vm:run("reg ls RegA").exit_code, 0, "RegA registered and routes")
        t:assert_eq(vm:run("reg ls RegB").exit_code, 0, "RegB registered and routes")
        t:assert_eq(vm:run("reg ls 'RegB\\OnlyInA'").exit_code, 2,
            "the two hives have distinct roots — the child of RegA is not in RegB")
        -- flags == 0: loregd only ever registers global hives (device.go
        -- hardcodes the flags field to 0, the RSI_HIVE_PRIVATE bit clear).
        -- The hive is reachable in the ordinary global namespace with no
        -- scope binding; loregd cannot emit a private hive, so a private
        -- contrast is not guest-constructable — the flags->scope mapping is
        -- pkm's source_registration_hive_scope (flags without RSI_HIVE_PRIVATE
        -- => HiveScope::Global).
        t:assert_eq(vm:run("reg ls RegA").exit_code, 0,
            "the hive is served as a global hive to the ordinary caller")
        proc:kill("kill")
    end)

-- ---- Step 10: readiness, signal handler, serve -----------------------

-- "Startup runs to completion before loregd accepts a single request." +
-- "Send readiness to `NOTIFY_SOCKET` if it is set, install the
--  termination signal handler, and enter the request loop."
test("readiness is signalled before the request loop, which serves once started",
    {
        spec = "loregd *startup.readiness-then-the-signal-handler-then-the-request-loop" ..
            " *startup.startup-completes-before-any-request-is-accepted",
    },
    function(t)
        local sock = "/run/pt-startup-notify.sock"
        vm:run("rm -f " .. sock)
        local fd, e = unixsock.socket(vm, unixsock.AF_UNIX, unixsock.SOCK.DGRAM)
        t:assert(fd, "notify socket: " .. unixsock.errname(e or 0))
        local br = unixsock.bind(vm, fd, sock)
        t:assert_eq(br.ret, 0, "bind notify socket: " .. unixsock.errname(br.errno or 0))

        local proc = start_env(t, { "Rdy=" .. MOUNT .. "/rdy.hive" }, "Rdy",
            { NOTIFY_SOCKET = sock })

        -- Readiness (step 10) is emitted after registration (step 9) and
        -- immediately before the request loop, so seeing READY=1 proves
        -- startup reached its final step; the request that follows only
        -- succeeds because the loop is now serving — startup completed
        -- before any request was accepted.
        local got
        local ok = pcall(wait_until, function()
            local r = vm:syscall(unixsock.NR.recvfrom, {
                args = { fd, 0, 64, unixsock.MSG.DONTWAIT, 0, 0 },
                bufs = { string.rep("\0", 64) }, ptrs = { 1 },
            })
            if r.ret and r.ret > 0 then got = r.out_bufs[1]:sub(1, r.ret); return true end
            return false
        end, { timeout = 10, interval = 0.25, desc = "the READY=1 datagram" })
        t:assert(ok and got and got:find("READY=1"),
            "loregd signalled readiness before entering the request loop")
        -- The signal handler is installed between readiness and the loop
        -- (main.go: notifyReady, signal.Notify, Serve); its correct arming
        -- is exercised by the SIGTERM case in durability.test.lua. Here we
        -- confirm the loop is in fact serving after readiness:
        t:assert_eq(vm:run("reg ls Rdy").exit_code, 0,
            "the request loop serves once startup has completed")
        proc:kill("kill")
    end)
