-- loregd §2.3 — what survives losing the machine, and what the daemon
-- finalises as it closes.
--
-- The mediated disk is what makes durability testable: provium serves
-- it over an NBD server of its own, holds each write in an overlay and
-- commits to the backing file only on FLUSH, so `disk:power_cut()`
-- discards exactly what was never made durable. Killing the VM is not a
-- substitute: unflushed writes through an ordinary drive sit in the
-- HOST's page cache and outlive the process, so the test would find
-- everything intact having proven nothing.
--
-- The second-loregd harness (boot, mount, start, stop) lives in
-- helpers/loregd; this file adds only the O_DIRECT sector probe the
-- mediation guard needs.

local loregd = require("helpers.loregd")
local sys = require("helpers.sys")

local DEVICE = loregd.DEVICE
local KEY = loregd.KEY

local vm = loregd.boot({ name = "loregd-dur", mediated = true })
local disk = vm:disk("hive")

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
        loregd.format(vm, t)
        loregd.mount(vm, t)
        loregd.start(vm, t)

        loregd.new_key(vm, KEY):assert_ok()
        loregd.set(vm, KEY, "Committed", "dword:1"):assert_ok()

        -- Read it back before the cut. Without this, "it was there
        -- afterwards" would not distinguish a value that survived from
        -- one that was never written.
        local before, value = loregd.get(vm, KEY, "Committed")
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
        loregd.mount(vm, t)
        loregd.start(vm, t)

        local after, survived = loregd.get(vm, KEY, "Committed")
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
        local r, how = loregd.stop(loregd.start(vm, t), vm)

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
        local proc = loregd.start(vm, t)
        loregd.set(vm, KEY, "Finalised", "dword:7"):assert_ok()

        local exit, how = loregd.stop(proc, vm)
        t:assert_eq(exit.exit_code, 0, "the daemon closed cleanly first. " .. how)

        disk:power_cut()
        vm:reset()

        loregd.mount(vm, t)
        loregd.start(vm, t)

        local r, value = loregd.get(vm, KEY, "Finalised")
        t:assert_eq(r.exit_code, 0,
            "the value reads back after the reboot: " .. r.stderr)
        t:assert_eq(value, "7",
            "nothing was still owed to the disk when the process exited")

        -- And the earlier value is still there too: a second close did
        -- not cost the hive what the first one had already finalised.
        local _, earlier = loregd.get(vm, KEY, "Committed")
        t:assert_eq(earlier, "1", "the value from the first cut is still there")
    end)
