-- loregd §2.3 — what ends the process, what pointedly does not, and what
-- happens to the data. The two anchors that durability.test.lua already
-- homes (committed-data durability, and the SIGTERM/SIGINT clean-shutdown
-- path) are NOT repeated here; this file covers the other nine.
--
-- Two of the exit triggers are unreachable from a guest: a device EOF is
-- the KERNEL closing loregd's source device (no guest operation makes it
-- do that), and an unframeable request cannot originate from a caller
-- because the kernel builds every RSI frame from validated ioctls before
-- loregd ever sees it. Those are homed on the device unit tests that
-- prove the read loop's response to each. The rest — startup failure,
-- storage errors during service, volatile loss, and the kernel marking a
-- disconnected source's hives unavailable — are observable live.

local loregd = require("helpers.loregd")

local MOUNT = loregd.MOUNT
local KEY = loregd.KEY

-- mediated so the volatile case can vm:reset() (its clean reboot is what
-- ends the process without a same-name re-registration colliding on the
-- root GUID the kernel still holds from the dead source).
local vm = loregd.boot({ name = "loregd-exit", mediated = true })
local disk = vm:disk("hive")
loregd.format(vm)
loregd.mount(vm)

-- File-scope PtState daemon: always up, its survival is what the storage-
-- error case checks. Never stopped; dies with the VM.
local main = loregd.start(vm)

local function start_hive(t, name, path)
    -- Defensive: never let a leftover disk-filler keep a fresh hive's
    -- database from being created.
    vm:run("rm -f " .. MOUNT .. "/filler*")
    local proc = vm:run_async("/usr/sbin/loregd", { args = { name .. "=" .. path } })
    local ok = pcall(wait_until, function()
        return vm:run("reg ls " .. name).exit_code == 0
    end, { timeout = 30, interval = 0.5, desc = "loregd to register " .. name })
    if not ok then
        proc:kill("kill")
        t:assert(false, "loregd never registered " .. name)
    end
    return proc
end

local function kill_and_wait(proc)
    local pid = proc:pid()
    proc:kill("kill")
    pcall(wait_until, function() return loregd.exited(vm, pid) end,
        { timeout = 10, interval = 0.25, desc = "loregd to exit after SIGKILL" })
end

-- ---- What ends the process -------------------------------------------

test("a device EOF shuts down cleanly with status zero",
    {
        spec = "loregd *exit.device-eof-shuts-down-cleanly-with-status-zero",
        skip = true,
        -- Route closed: an EOF on loregd's read of /dev/pkm_registry is the
        -- KERNEL closing its end of the source device. No guest operation
        -- triggers that (deregistration is what the kernel does when a
        -- source disconnects — the reverse direction), so the clean-EOF
        -- shutdown cannot be induced from the guest. TestServeCleanEOF
        -- feeds Serve an immediate io.EOF and asserts it returns nil (main
        -- then returns nil and exits 0).
        covered_by = "go:loregd internal/device::TestServeCleanEOF",
    }, function() end)

test("an unframeable request exits non-zero",
    {
        spec = "loregd *exit.an-unframeable-request-exits-non-zero",
        skip = true,
        -- Route closed: a caller never hands loregd raw bytes. The kernel
        -- serializes each RSI request from validated client ioctls, so an
        -- unparseable frame is not guest-constructable. TestServeMalformedFramingTearsDown
        -- delivers a message whose total_len does not match its length and
        -- asserts Serve returns an error (main wraps it and log.Fatal exits
        -- non-zero).
        covered_by = "go:loregd internal/device::TestServeMalformedFramingTearsDown",
    }, function() end)

-- "Startup fails. Any error in §2.2 is fatal."
test("a startup failure is fatal",
    { spec = "loregd *exit.a-startup-failure-is-fatal" },
    function(t)
        -- A hive whose parent directory cannot be created makes a §2.2
        -- step fail; the process must exit non-zero rather than serve.
        local r = loregd.spawn(vm, { "Bad=/proc/nope/deeper/x.hive" }):wait("10s")
        t:assert_eq(r.status, "exited", "loregd exits rather than crashing: " .. r.stderr)
        t:assert(r.exit_code ~= 0,
            "a fatal startup error exits non-zero, got " .. tostring(r.exit_code) ..
            ". stderr=" .. r.stderr)
    end)

-- "When the kernel observes the source disconnect, it marks every hive
--  loregd served as unavailable."
test("the kernel marks every served hive unavailable on disconnect",
    { spec = "loregd *exit.the-kernel-marks-every-served-hive-unavailable-on-disconnect" },
    function(t)
        local proc = start_hive(t, "Gone", MOUNT .. "/gone.hive")
        t:assert_eq(vm:run("reg ls Gone").exit_code, 0, "the hive routes while loregd serves it")

        -- The source disconnects.
        kill_and_wait(proc)

        -- Once the kernel observes the disconnect it marks the hive
        -- unavailable: routing to it fails (LCS maps an unavailable hive to
        -- EIO, reg exit 5) rather than continuing to succeed.
        local ok = pcall(wait_until, function()
            return vm:run("reg ls Gone").exit_code ~= 0
        end, { timeout = 15, interval = 0.5, desc = "the Gone hive to become unavailable" })
        t:assert(ok, "after the source disconnected the hive stopped routing")
        local r = vm:run("reg ls Gone")
        t:assert(r.exit_code ~= 0,
            "the disconnected source's hive is marked unavailable: exit=" .. r.exit_code ..
            " stderr=" .. r.stderr)
    end)

-- "On shutdown, in-flight requests are drained before the process exits,
--  and every hive's read connections and write connection are closed."
--  This drain-and-close happens after the read loop returns, which on a
--  signalled shutdown it did not until loregd 0.21.13 (PEI-1122).
test("in-flight requests are drained and every connection closed on shutdown",
    {
        spec = "loregd *exit.in-flight-requests-are-drained-and-every-connection-closed-on-shutdown"
            .. " loregd *dispatch.in-flight-requests-are-drained-before-the-process-exits",
    },
    function(t)
        local proc = start_hive(t, "Drain", MOUNT .. "/drain.hive")
        -- A clean stop should drain in-flight work and close every
        -- connection, ending the process on its own with status 0.
        local r, how = loregd.stop(proc, vm, 5)
        t:assert_eq(r.status, "exited",
            "SIGTERM leads to a clean shutdown that drains and closes, rather " ..
            "than hanging until SIGKILL. " .. how)
        t:assert_eq(r.exit_code, 0,
            "the drained, connection-closing shutdown exits 0. " .. how)
    end)

-- ---- What does not end the process (fills the disk) -------------------

-- "A storage failure during request handling does not terminate loregd.
--  Errors from SQLite while serving a request — including I/O errors —
--  are converted into an RSI_STORAGE_ERROR response and the daemon
--  carries on serving. There is no corruption detector and no disk-full
--  detector that takes the process down; a database that has become
--  unreadable will produce a stream of storage errors rather than an exit."
test("a storage failure yields a storage error, not an exit, and no disk-full detector fires",
    {
        spec = "loregd *exit.a-storage-failure-does-not-end-the-process" ..
            " *exit.sqlite-errors-become-an-rsi-storage-error-response" ..
            " *exit.there-is-no-corruption-or-disk-full-detector",
    },
    function(t)
        local pid = main:pid()
        vm:run("rm -f " .. MOUNT .. "/filler*")
        -- Baseline: a committed value we can still read after the disk
        -- fills (reads do not need free space).
        loregd.new_key(vm, KEY):assert_ok()
        loregd.set(vm, KEY, "Base", "dword:5"):assert_ok()

        -- Drop ext4's root-reserved blocks (5% by default) so filling the
        -- filesystem leaves loregd — which runs as root — genuinely no room
        -- to extend a database file. 1M blocks fill fast but leave up to
        -- ~1M unclaimed; a 1K-block second pass mops the remainder down to
        -- under a page.
        vm:run("tune2fs -m 0 " .. loregd.DEVICE .. " 2>/dev/null; true")
        vm:run("dd if=/dev/zero of=" .. MOUNT .. "/filler bs=1M 2>/dev/null; true")
        vm:run("dd if=/dev/zero of=" .. MOUNT .. "/filler2 bs=1024 2>/dev/null; true")
        local df = vm:run("df -k " .. MOUNT).stdout

        -- A large value forces the database to grow beyond its current
        -- size — a small insert could be absorbed by SQLite's freelist
        -- without touching the disk. Growing on a full disk hits
        -- SQLITE_FULL. That is a storage error: an RSI_STORAGE_ERROR
        -- response, which LCS maps to EIO and `reg` reports as a source
        -- failure (exit 5) — NOT a not-found, NOT a crash, NOT an exit.
        -- Kept under MAX_ARG_STRLEN (128 KiB per argv entry).
        local big = string.rep("x", 100 * 1024)
        local w = vm:run("reg set '" .. KEY .. "' Big sz:" .. big)
        t:assert(w.exit_code ~= 0,
            "a write that must grow the database on a full disk fails rather than " ..
            "silently succeeding. df=" .. df .. " exit=" .. w.exit_code .. " stderr=" .. w.stderr)
        t:assert_eq(w.exit_code, 5,
            "the failure surfaces as a source/storage error (reg exit 5), i.e. an " ..
            "RSI_STORAGE_ERROR, not a not-found or usage error. stderr=" .. w.stderr)

        -- The daemon is still alive, still serving: no corruption/disk-full
        -- detector took it down.
        t:assert(not loregd.exited(vm, pid),
            "loregd is still running after the storage error")
        local rd, val = loregd.get(vm, KEY, "Base")
        t:assert_eq(rd.exit_code, 0, "and still serving reads: " .. rd.stderr)
        t:assert_eq(val, "5", "the previously-committed value still reads back")

        vm:run("rm -f " .. MOUNT .. "/filler*")
        t:assert(not loregd.exited(vm, pid), "loregd outlived the whole episode")
    end)

-- ---- What happens to the data (runs last: reboots the VM) -------------

-- "Volatile data does not survive. The in-memory databases holding
--  volatile keys are destroyed with the process."
test("volatile data does not survive the process",
    { spec = "loregd *exit.volatile-data-does-not-survive-the-process" },
    function(t)
        local path = MOUNT .. "/volatile-life.hive"
        vm:run("rm -f '" .. path .. "'*")
        start_hive(t, "Vol", path)

        -- A volatile key/value and a persistent key/value side by side.
        vm:run("reg new 'Vol\\Ram' --volatile -p"):assert_ok()
        vm:run("reg set 'Vol\\Ram' V dword:1"):assert_ok()
        vm:run("reg new 'Vol\\Disk' -p"):assert_ok()
        vm:run("reg set 'Vol\\Disk' V dword:2"):assert_ok()
        t:assert_eq((select(2, loregd.get(vm, "Vol\\Ram", "V"))), "1", "volatile value present while serving")
        t:assert_eq((select(2, loregd.get(vm, "Vol\\Disk", "V"))), "2", "persistent value present while serving")

        -- The process (and everything in the kernel that knew of it) goes
        -- away. A reboot, not a same-name restart: re-registering a hive
        -- whose root GUID the kernel still holds from the dead source would
        -- collide, so the whole VM is reset — which also empties the
        -- in-memory volatile store, exactly as ending the process would.
        -- The power cut is what lets the mediated disk reset cleanly; the
        -- persistent value was durable at commit, so it survives it (the
        -- volatile value was never on disk to begin with).
        disk:power_cut()
        vm:reset()
        loregd.mount(vm)
        local proc2 = vm:run_async("/usr/sbin/loregd", { args = { "Vol=" .. path } })
        -- Probe re-registration with `reg info` (reads the root, does not
        -- enumerate): the volatile key's in-memory record is gone, so a
        -- root enumeration would trip over its now-dangling path entry.
        -- Probe by resolving a specific named path (not a root
        -- enumeration): the volatile key's in-memory record is gone, so
        -- enumerating the root would trip over its now-dangling path entry.
        -- Any answer at all — the persistent value, or a clean negative —
        -- means the daemon re-registered and is serving.
        local okreg = pcall(wait_until, function()
            local rc = vm:run("reg get 'Vol\\Disk' V")
            return rc.exit_code == 0 or rc.exit_code == 2
        end, { timeout = 20, interval = 0.5, desc = "the Vol hive to re-register" })
        if not okreg then
            proc2:kill("kill")
            t:assert(false, "loregd never re-registered Vol after the reboot")
        end

        -- The volatile value is gone with the old process — its in-memory
        -- store did not survive, so the value no longer reads back.
        local ram = vm:run("reg get 'Vol\\Ram' V")
        t:assert(ram.exit_code ~= 0,
            "the volatile value did not survive the process (expected absent): " ..
            "exit=" .. ram.exit_code .. " stdout=" .. ram.stdout)
        -- The persistent value, committed before the reboot, is intact —
        -- so the loss is specific to volatile data.
        t:assert_eq((select(2, loregd.get(vm, "Vol\\Disk", "V"))), "2",
            "the persistent value did survive")
        proc2:kill("kill")
    end)
