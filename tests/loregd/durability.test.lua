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
--- The Process belongs to the test that called this. provium closes a
--- test's resources when the test ends — SIGTERM, then SIGKILL two
--- seconds later — whatever else still refers to them, so a daemon is
--- never handed from one test to the next: each test starts its own.
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
    return proc
end

--- Whether `pid` has finished: gone from /proc, or a zombie the agent
--- has not reaped yet. A zombie still has a /proc entry, so "the entry
--- is gone" alone would call an exited daemon alive.
local function exited(pid)
    local ok, status = pcall(vm.read_file, vm, "/proc/" .. pid .. "/status")
    return not ok or status:find("\nState:%s*Z") ~= nil
end

--- SIGTERM `proc` and say how it ended.
---
--- Returns the RunResult and a description for failure messages: the
--- exit status and loregd's own output — which says whether its signal
--- handler ever ran, since it logs `received terminated` before closing
--- the device.
---
--- When the daemon is still alive after `grace` seconds, the
--- description also carries where it is stuck: its /proc state and
--- signal masks, and every thread's wait channel. Taken BEFORE
--- `proc:wait` gives up and SIGKILLs it, because afterwards there is
--- nothing left to look at.
local function stop_loregd(proc, grace)
    local pid = proc:pid()
    proc:kill("term")

    local gone = pcall(wait_until, function() return exited(pid) end,
        { timeout = grace or 15, interval = 0.25, desc = "loregd to exit" })

    local where = ""
    if not gone then
        local lines = { "\n  still alive " .. (grace or 15) ..
            "s after SIGTERM (pid " .. pid .. "):" }
        local ok, status = pcall(vm.read_file, vm, "/proc/" .. pid .. "/status")
        if ok then
            for line in status:gmatch("[^\n]+") do
                if line:match("^State:") or line:match("^Sig") or line:match("^ShdPnd:") then
                    lines[#lines + 1] = "    " .. line
                end
            end
        end
        local tasks = vm:run("ls /proc/" .. pid .. "/task").stdout
        for tid in tasks:gmatch("%d+") do
            local _, wchan = pcall(vm.read_file, vm,
                "/proc/" .. pid .. "/task/" .. tid .. "/wchan")
            lines[#lines + 1] = "    thread " .. tid .. " waiting in " .. tostring(wchan)
        end
        where = table.concat(lines, "\n")
    end

    local r = proc:wait("5s")
    return r, ("exit=%s status=%s signal=%s%s\n  loregd stdout: %s\n  loregd stderr: %s")
        :format(tostring(r.exit_code), tostring(r.status), tostring(r.signal),
            where, tostring(r.stdout), tostring(r.stderr))
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

--- One sector of `char`, written to the raw disk with O_DIRECT, and
--- flushed only when asked.
---
--- O_DIRECT is the point. An ordinary write stops in the guest's page
--- cache and may never reach the disk, so "the backing file does not
--- have it" could not tell a write provium is holding from one the guest
--- never sent. With O_DIRECT, a write that returns has been acknowledged
--- by the device — which here is provium.
---
--- Not `dd oflag=direct`. O_DIRECT needs a buffer aligned to the
--- device's sector size, and peiosutils' dd retries any write that fails
--- EINVAL with O_DIRECT cleared, silently (`handle_o_direct_write`), so
--- a direct write the kernel refused would land in the page cache and
--- this check would pass for the wrong reason. The agent's own syscall
--- buffers carry no alignment either, but an anonymous mapping is
--- page-aligned: the pattern is read into one and written from there, so
--- a refusal comes back as an error instead of being hidden.
local function direct_write(t, sector, char, flush)
    local src = "/tmp/pt-sector-" .. char
    vm:write_file(src, string.rep(char, 512))

    local page = assert(sys.mmap(vm, -1, 4096,
        sys.PROT.READ | sys.PROT.WRITE, sys.MAP.PRIVATE | sys.MAP.ANONYMOUS))
    local sfd = assert(sys.open(vm, src, sys.O.RDONLY))
    local got = vm:syscall(sys.NR.read, sfd, page, 512)
    sys.close(vm, sfd)
    t:assert_eq(got.ret, 512, "the pattern read into the aligned page")

    local fd, errno = sys.open(vm, DEVICE, sys.O.RDWR | sys.O.DIRECT)
    t:assert(fd, "open " .. DEVICE .. " with O_DIRECT: " .. sys.errname(errno or 0))
    sys.lseek(vm, fd, sector * 512, 0)
    local w = vm:syscall(sys.NR.write, fd, page, 512)
    t:assert_eq(w.ret, 512, "a direct write to sector " .. sector .. ": " ..
        sys.errname(w.errno or 0))
    if flush then
        t:assert_eq(sys.fsync(vm, fd).ret, 0, "and the guest flushed it")
    end
    sys.close(vm, fd)
    sys.munmap(vm, page, 4096)
end

test("the disk is mediated: a write the guest never flushed is held, not committed",
    {}, function(t)
        -- Every durability case below rests on this. A power cut can only
        -- discard what provium is actually holding, so before trusting one
        -- the test watches provium hold something. On two raw sectors,
        -- before anything formats the disk, so no filesystem can blur it;
        -- the next case's mkfs overwrites both.
        local r = vm:run("test -b " .. DEVICE)
        t:assert_eq(r.exit_code, 0, DEVICE .. " is a block device in the guest")

        direct_write(t, 0, "D", true)   -- sent, and flushed
        direct_write(t, 1, "L", false)  -- sent, never flushed

        -- `read_sectors` reads the backing file on the host directly, so
        -- this is the disk's real contents, not what either cache believes.
        local ZERO = string.rep("\0", 512)
        t:assert_eq(disk:read_sectors(0, 1), string.rep("D", 512),
            "the flushed write was committed")
        t:assert_eq(disk:read_sectors(1, 1), ZERO,
            "the unflushed write was acknowledged but is held, not committed " ..
            "— on a disk provium did not mediate it would already be here")

        disk:power_cut()

        t:assert_eq(disk:read_sectors(0, 1), string.rep("D", 512),
            "the flushed write survives the cut")
        t:assert_eq(disk:read_sectors(1, 1), ZERO, "and the held one is gone")
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
    {
        spec = "loregd *exit.sigterm-and-sigint-close-the-device-for-a-clean-shutdown",
        -- PEI-1122: `main` hands the device fd to the registration ioctl
        -- through `dev.Fd()`, which puts it back into blocking mode, so
        -- the handler's `dev.Close()` cannot interrupt the read loop and
        -- an idle daemon never finishes shutting down.
        tags = { "known-bug" },
    },
    function(t)
        local r, how = stop_loregd(start_loregd(t))

        t:assert_eq(r.status, "exited",
            "loregd ends on its own after SIGTERM, rather than hanging " ..
            "until it is killed. " .. how)
        t:assert_eq(r.exit_code, 0,
            "and with status 0 — the handler closes the device, which " ..
            "unblocks the read loop into the same clean shutdown a device " ..
            "EOF produces. " .. how)
    end)

test("data written before a clean close is final",
    {
        spec = "loregd *exit.committed-data-is-durable-and-wal-state-is-finalised-at-close",
        -- PEI-1122: there is no clean close to test until SIGTERM ends the
        -- daemon, so this stops at its first assertion for the same reason.
        tags = { "known-bug" },
    },
    function(t)
        -- The other half of the sentence: SQLite finalises any
        -- outstanding WAL state as the connections close. So this writes,
        -- closes the daemon properly, and only then cuts the power — if
        -- anything were still owed to the disk at the moment the process
        -- exited, the cut would take it.
        local proc = start_loregd(t)
        vm:run("reg set '" .. KEY .. "' Finalised dword:7"):assert_ok()

        local exit, how = stop_loregd(proc)
        t:assert_eq(exit.exit_code, 0, "the daemon closed cleanly first. " .. how)

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
