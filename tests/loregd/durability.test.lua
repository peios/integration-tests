-- loregd §2.3 — what survives losing the machine, and what the daemon
-- finalises as it closes.
--
-- Every durability claim in the loregd book was untestable end to end
-- until now. The peinit profile boots a read-only ISO with the root as
-- tmpfs-over-squashfs, so nothing a test wrote survived a reboot, and
-- nothing could make loregd's own I/O fail (PEI-1104, PEI-1121).
--
-- What makes it testable is a **mediated** disk. provium serves it over
-- an NBD server of its own, holds each write in an overlay and commits
-- to the backing file only on FLUSH, so `disk:power_cut()` discards
-- exactly what was never made durable. Killing the VM is not a
-- substitute: unflushed writes through an ordinary drive sit in the
-- HOST's page cache and outlive the process, so the test would find
-- everything intact having proven nothing.
--
-- The hive under test is a SECOND loregd, not the image's registryd.
-- registryd starts at Phase 1, before the autorun queue that starts this
-- agent, so its hive is on the root filesystem before a test exists and
-- can never be relocated onto a disk. A second source is legitimate:
-- registration collides only on a route identity held by another
-- *Active* source (PKM *source.register.no-route-identity-collision),
-- and `PtState` is nobody's. Nothing in LCS knows which source is
-- loregd, so a hive of our own is served exactly as Machine is.
--
-- The mount is the part that needs care. ext4 classifies
-- `facs_deny_missing` (PKM *facs.storage.default-deny-missing), and a
-- filesystem straight out of mkfs carries no descriptors at all — so
-- every access to it, the agent's own included, is refused with EACCES.
-- Adopting the superblock under a synthesise class is the sanctioned
-- route (PKM *facs.storage.boot-artifacts-not-seeded), and the one
-- moment it can be done is before the mount is attached, which is what
-- `helpers/kacs.new_mount` exists for. Ephemeral rather than persistent:
-- a synthesised descriptor is never written back, so adopting the mount
-- adds no writes of its own to the disk whose durability is the subject.
-- (seed-sd would be the other route, and is not in this image.)

local peinit = require("helpers.peinit")
local sys = require("helpers.sys")
local kacs = require("helpers.kacs")

peinit.claim(1)

-- The profile attaches its ISO medium first, so a boot disk is the
-- second virtio device. Boot disks are attached after the profile's and
-- ids share one namespace, so this cannot silently displace the medium.
local DEVICE = "/dev/vdb"
local MOUNT = "/mnt/pt-hive"
local HIVE = "PtState"
local HIVE_FILE = MOUNT .. "/pt-state.hive"
local KEY = [[PtState\Durable]]

local vm = peinit.boot({
    name = "loregd-dur",
    boot = { disks = { { scratch = "256M", id = "hive", mediated = true } } },
})
local disk = vm:disk("hive")

--- The loregd this file started, or nil. File-scope so a test can hand
--- the running daemon to the next one rather than each starting its own
--- against a hive another is still holding open.
local loregd = nil

--- Adopt the disk's filesystem at MOUNT, usable.
---
--- `new_mount` sets the policy class on the mount fd between `fsmount`
--- and `move_mount`, which is the only window in which a superblock can
--- be named — after it is attached there is no fd to name it by.
local function mount_hive(t)
    local ok, stage, errno = kacs.new_mount(vm, "ext4", MOUNT,
        kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL, { source = DEVICE })
    t:assert(ok, "mounting " .. DEVICE .. " at " .. MOUNT .. ": " ..
        tostring(stage) .. " " .. sys.errname(errno or 0))
end

--- Start loregd on the hive and wait until the kernel will route to it.
---
--- Readiness is asked of LCS rather than read off the daemon's stdout:
--- what the test needs is not that loregd printed something but that a
--- `reg` invocation now reaches it, and those are different facts. The
--- daemon's own output is kept for the failure message, because a
--- loregd that died during startup says why on stderr and that is the
--- only place it is recorded.
local function start_loregd(t)
    local proc = vm:run_async("/usr/sbin/loregd",
        { args = { HIVE .. "=" .. HIVE_FILE } })

    local ok = pcall(wait_until, function()
        return vm:run("reg ls " .. HIVE).exit_code == 0
    end, { timeout = 30, interval = 0.5,
           desc = "loregd to register the " .. HIVE .. " hive" })

    if not ok then
        -- Take the daemon down so its captured output closes, then say
        -- what it managed to emit before giving up on it.
        proc:kill("term")
        local r = proc:wait("5s")
        t:assert(false, "loregd never registered " .. HIVE ..
            "; exit=" .. tostring(r.exit_code) ..
            " stdout=" .. tostring(r.stdout) ..
            " stderr=" .. tostring(r.stderr))
    end
    loregd = proc
    return proc
end

--- Everything needed to talk to the hive again after a reboot: the
--- filesystem is already made, so this mounts rather than formats.
local function remount_and_start(t)
    mount_hive(t)
    return start_loregd(t)
end

--- Read a DWORD back through the registry.
---
--- `reg get <key> <value>` prints the value bare — for a DWORD, the
--- number and nothing else — so this is the whole answer, not a field
--- of a decorated line.
local function read_dword(name)
    local r = vm:run("reg get '" .. KEY .. "' " .. name)
    return r, (r.stdout:gsub("%s+$", ""))
end

test("the disk is mediated, so a power cut is a real one", {}, function(t)
    -- Asserted first and on its own because every durability case below
    -- rests on it. `power_cut` errors on a disk that was not booted
    -- `mediated = true` rather than quietly doing nothing, so a cut that
    -- returns is a cut that can actually discard something — and without
    -- this check a misconfigured boot would make every later test pass
    -- by never losing any data at all.
    local ok, err = pcall(function() disk:power_cut() end)
    t:assert(ok, "power_cut on the hive disk: " .. tostring(err))

    local r = vm:run("test -b " .. DEVICE)
    t:assert_eq(r.exit_code, 0, DEVICE .. " is a block device in the guest")
end)

test("a value committed before the power cut is there after it",
    { spec = "loregd *exit.committed-data-is-durable-and-wal-state-is-finalised-at-close" },
    function(t)
        vm:run("mkfs.ext4 -F -q " .. DEVICE):assert_ok()
        mount_hive(t)
        start_loregd(t)

        vm:run("reg new '" .. KEY .. "' -p"):assert_ok()
        vm:run("reg set '" .. KEY .. "' Committed dword:1"):assert_ok()

        -- Read it back before the cut. Without this, "it was there
        -- afterwards" would not distinguish a value that survived from
        -- one that was never written.
        local before, value = read_dword("Committed")
        before:assert_ok()
        t:assert_eq(value, "1", "the value is readable before the cut")

        -- No unmount, no SIGTERM, no shutdown: the daemon is still
        -- running and the filesystem still mounted. That is the whole
        -- point — the claim is that data is durable at the moment each
        -- transaction commits, so anything that would flush on the way
        -- out would answer a different question.
        disk:power_cut()
        vm:reset()
        loregd = nil

        -- `vm:reset()` returns with the agent serving again, and the
        -- agent starts in Phase 1.5 — after registryd, which is all this
        -- needs. Nothing here waits for Phase 2.
        remount_and_start(t)

        local after, survived = read_dword("Committed")
        t:assert_eq(after.exit_code, 0,
            "the value reads back after the reboot: " .. after.stderr)
        t:assert_eq(survived, "1",
            "a committed value survived losing the machine with no clean " ..
            "shutdown, so the commit itself made it durable")
    end)

test("SIGTERM closes the device and shuts the daemon down cleanly",
    { spec = "loregd *exit.sigterm-and-sigint-close-the-device-for-a-clean-shutdown" },
    function(t)
        t:assert(loregd, "the previous test left a loregd running")

        loregd:kill("term")
        local r = loregd:wait("15s")
        loregd = nil

        t:assert_eq(r.exit_code, 0,
            "loregd exits 0 on SIGTERM — the handler closes the device, " ..
            "which unblocks the read loop into the same clean shutdown a " ..
            "device EOF produces. stderr=" .. tostring(r.stderr))
    end)

test("data written before a clean close is final",
    { spec = "loregd *exit.committed-data-is-durable-and-wal-state-is-finalised-at-close" },
    function(t)
        -- The other half of the sentence: SQLite finalises any
        -- outstanding WAL state as the connections close. So this writes,
        -- closes the daemon properly, and only then cuts the power — if
        -- anything were still owed to the disk at the moment the process
        -- exited, the cut would take it.
        start_loregd(t)
        vm:run("reg set '" .. KEY .. "' Finalised dword:7"):assert_ok()

        loregd:kill("term")
        local exit = loregd:wait("15s")
        loregd = nil
        t:assert_eq(exit.exit_code, 0, "the daemon closed cleanly first")

        disk:power_cut()
        vm:reset()

        remount_and_start(t)

        local r, value = read_dword("Finalised")
        t:assert_eq(r.exit_code, 0,
            "the value reads back after the reboot: " .. r.stderr)
        t:assert_eq(value, "7",
            "nothing was still owed to the disk when the process exited")

        -- And the earlier value is still there too: a second close did
        -- not cost the hive what the first one had already finalised.
        local _, earlier = read_dword("Committed")
        t:assert_eq(earlier, "1", "the value from the first cut is still there")
    end)
