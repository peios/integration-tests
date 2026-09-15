-- peinit TRM §12.2 steps 6-8 and §12.4 — finalisation: the seed, the
-- unmounts, the read-only remounts, the sync and the final action, and
-- what happens if the kernel hands control back.
--
-- This used to be the thinnest file in the chapter. Steps 6 and 7 write
-- nothing to the console when they succeed, what peinit does print in
-- its finalising turn is written after a reboot(2) that does not return
-- (PEI-827), and the machine is gone a moment later — so most of what
-- §12.4 states was asserted only through its one visible consequence,
-- the kernel's "reboot: Power down".
--
-- Most of this file now reads a witness instead: `pt-shutwatch`
-- (tests/tools/pt-shutwatch.c, driven through helpers/shutdown.lua),
-- which runs outside PID 1 in a mount namespace of its own and reports
-- PID 1's syscalls, the seed directory's inotify events and PID 1's
-- mount table on the console as they happen. Its header says why the
-- private namespace matters: a watcher in PID 1's namespace would hold
-- mounts busy and change the outcomes it is there to report.
--
-- It also holds the final action back. With SeShutdownPrivilege — the
-- KACS privilege behind CAP_SYS_BOOT — disabled on PID 1's token,
-- reboot(2) fails with EPERM, peinit enters its failed-shutdown state,
-- and the machine stays up until the witness has written the whole
-- record; then the witness re-enables the privilege and the next retry
-- powers the machine off. Every step before the reboot is the one an
-- unheld shutdown takes. The hold is also, in its own right, the only
-- way a guest can make reboot(2) return — which is what the §12.4
-- failed-shutdown tests below are about.
--
-- One observed shutdown serves most of the tests: a boot with a staged
-- seed and a set of mounts the test owns, arranged so each §12.2 step 7
-- rule has something to act on — a deep tree, a mount held busy, a
-- mount held open for writing, and a pair of shared peers whose child
-- goes when its twin does. It is run once, on first use, and every test
-- that reads it asserts on the same record.

local peinit = require("helpers.peinit")
local shutdown = require("helpers.shutdown")
peinit.claim(1)

local function with_vm(opts, body)
    local vm = peinit.boot(opts)
    local ok, err = pcall(body, vm)
    pcall(function() vm:shutdown() end)
    if not ok then error(err, 0) end
end

local settle = peinit.settle

local function pause(seconds)
    pcall(wait_until, function() return false end,
        { timeout = seconds, interval = 0.25, desc = "a fixed pause" })
end

local function trigger(vm, command)
    pcall(function() vm:run(command, { timeout = 30 }) end)
end

local SEED = "/var/state/peinit/random-seed"
local STAGED_SEED = string.rep("pt-seed-", 64)

--- The staged seed's first sixteen bytes, as the witness renders them.
local STAGED_HEAD = (STAGED_SEED:sub(1, 16):gsub(".",
    function(c) return string.format("%02x", c:byte()) end))

local MS_REMOUNT_RDONLY = "0x21"
local RB_POWER_OFF = "0x4321fedc"

--- Hold the final action back for this many failed attempts.
local HELD_ATTEMPTS = 3

--- The observed shutdown, run once and shared.
---
--- Returns `{log, record, services}`: the whole console, the witness's
--- record parsed out of it, and `svctl --json list` as it answered while
--- PID 1 sat in its failed-shutdown state.
local observed_result, observed_error
local function observed()
    if observed_result then return observed_result end
    if observed_error then error(observed_error, 0) end
    local ok, result = pcall(function()
        local vm = peinit.boot({
            name = "observed",
            append = "peios.quiet=0",
            files = peinit.merge(shutdown.tool(), { [SEED:sub(2)] = STAGED_SEED }),
        })
        local inner_ok, inner = pcall(function()
            settle(vm)

            -- A tree four deep, so "deepest first" has more than the
            -- image's own depth-three /sys/fs/cgroup to be about. Every
            -- mount here is the test's, not peinit's: step 7 attempts
            -- every non-root mount in the namespace, not only its own.
            shutdown.tmpfs(vm, "pt-deep", "/mnt/pt-deep")
            shutdown.tmpfs(vm, "pt-deeper", "/mnt/pt-deep/a/b")

            -- Held busy by a process whose working directory is inside
            -- it: unmount fails with EBUSY, a read-only remount succeeds.
            shutdown.tmpfs(vm, "pt-busy", "/mnt/pt-busy")
            vm:run("cd /mnt/pt-busy && /bin/sleep 600 > /dev/null 2>&1 &")

            -- Held open for writing: unmount fails, and so does the
            -- read-only remount a file open for writing forbids.
            shutdown.tmpfs(vm, "pt-held", "/mnt/pt-held")
            vm:run("/bin/sleep 600 > /mnt/pt-held/log 2>&1 &")

            -- Two shared peers with a child mounted under one of them,
            -- which propagates to the other. Unmounting the first child
            -- takes its twin with it, so by the time step 7 reaches the
            -- twin — in its snapshot, at the same depth, later in order —
            -- it is already gone.
            shutdown.tmpfs(vm, "pt-peer", "/mnt/pt-peer-a", "shared")
            vm:run("mkdir -p /mnt/pt-peer-b /mnt/pt-peer-a/x"):assert_ok()
            vm:run("mount --bind /mnt/pt-peer-a /mnt/pt-peer-b"):assert_ok()
            shutdown.tmpfs(vm, "pt-x", "/mnt/pt-peer-a/x")
            assert(vm:run("cat /proc/self/mountinfo").stdout:find(" /mnt/pt-peer-b/x ", 1, true),
                "the child mount propagated to the second peer")

            shutdown.start(vm, { hold = HELD_ATTEMPTS })
            trigger(vm, "svctl shutdown poweroff")

            -- The first failed reboot(2) is the last call of the first
            -- finalising turn, so once it is on the record, so is all
            -- of steps 6 to 8.
            wait_until(function()
                return vm:console():read_log():find("sys_reboot %-> 0xffffffffffffffff")
            end, { timeout = 120, interval = 0.25, desc = "the first, held, final action" })

            -- PID 1 is in its failed-shutdown state now, and still
            -- answering: the control socket's `list` is one of the
            -- commands a shutdown lets through.
            local services = vm:run("svctl --json list").stdout

            shutdown.released(vm, 30)
            vm:console():expect("reboot: Power down", 30)
            pause(1)
            return { log = vm:console():read_log(), services = services }
        end)
        pcall(function() vm:shutdown() end)
        if not inner_ok then error(inner, 0) end
        inner.record = shutdown.record(inner.log)
        return inner
    end)
    if not ok then
        observed_error = result
        error(result, 0)
    end
    observed_result = result
    return result
end

--- The first call matching `pred` at or after `from`, and its index.
local function find_call(record, pred, from)
    for i = from or 1, #record.calls do
        if pred(record.calls[i]) then return record.calls[i], i end
    end
    return nil
end

local function first_umount(record)
    return find_call(record, function(c) return c.name == "umount" end)
end

local function depth(point)
    local n = 0
    for _ in point:gmatch("/[^/]+") do n = n + 1 end
    return n
end

test("the seed is 512 fresh bytes, SYSTEM-only, written after the services and before any unmount",
    { spec = "peinit *graceful.a-512-byte-seed-is-written-before-any-unmount" },
    function(t)
        local o = observed()
        local record = o.record
        local seeds = shutdown.entries(record, "seed")
        t:assert_eq(#seeds, 1, "one seed landed: " .. shutdown.render(record))
        local seed = seeds[1]

        t:assert_eq(seed.size, 512, "the seed is 512 bytes")
        t:assert_eq(seed.inode, "new", "and a new file, not the staged one rewritten in place")
        t:assert(seed.head ~= STAGED_HEAD and seed.head ~= string.rep("0", 32),
            "its bytes are fresh — not the seed this boot was handed, and not zeros: "
            .. seed.head)
        local write = find_call(record, function(c) return c.name == "write" end)
        t:assert(write and write.count == "0x200" and write.ret == 512,
            "written in one 512-byte write: " .. shutdown.render(record))

        -- After every service has stopped: when the seed landed no
        -- service cgroup held a process.
        t:assert_eq(seed.populated, "none",
            "no service cgroup still held a process when the seed was written")

        -- Before any unmount: on the ordered record, and in the mount
        -- table as the witness found it after each unmount.
        local _, renamed = find_call(record,
            function(c) return c.name == "rename" and c.newname == SEED end)
        local _, unmounted = first_umount(record)
        t:assert(renamed and unmounted and renamed < unmounted,
            "the seed was renamed into place before the first umount2: "
            .. shutdown.render(record))
        for _, gone in ipairs(shutdown.entries(record, "gone")) do
            t:assert_eq(gone.seed, "new",
                gone.point .. " had gone with the new seed already in place")
        end

        -- Protected so that only SYSTEM can read or replace it.
        local sd = shutdown.decode_sd(seed.sd)
        t:assert_eq(sd.owner, "S-1-5-18", "the seed is owned by SYSTEM")
        t:assert_eq(#sd.aces, 1, "its DACL has exactly one entry: " .. seed.sd)
        t:assert_eq(sd.aces[1].type, 0, "an allow")
        t:assert_eq(sd.aces[1].sid, "S-1-5-18", "for SYSTEM, and for nobody else")
    end)

test("the seed goes through a temporary file that is flushed, renamed over the old one, and its directory flushed",
    { spec = "peinit *graceful.the-seed-write-is-a-flush-and-atomic-rename" },
    function(t)
        local record = observed().record

        -- A temporary file in the seed's own directory, which is what
        -- puts it on the same filesystem as the seed: the witness watches
        -- that one directory, and this is where it was created.
        local temp
        for _, ev in ipairs(shutdown.entries(record, "fs")) do
            if ev.what:find("create", 1, true) and ev.name:match("^%.random%-seed%.tmp") then
                temp = ev.name
            end
        end
        t:assert(temp, "a temporary file was created beside the seed")

        -- Written, flushed, closed, renamed, then a second flush — of the
        -- directory, which is the one other thing opened here — all
        -- before step 7 begins.
        local write, iw = find_call(record, function(c) return c.name == "write" end)
        t:assert(write, "the seed write is on the record: " .. shutdown.render(record))
        local flush, iflush = find_call(record,
            function(c) return c.name == "fsync" and c.fd == write.fd end, iw)
        local close, iclose = find_call(record,
            function(c) return c.name == "close" and c.fd == write.fd end, iw)
        local rename, irename = find_call(record, function(c) return c.name == "rename" end, iw)
        local dir_flush, idir = find_call(record, function(c) return c.name == "fsync" end,
            irename)
        local _, iumount = first_umount(record)
        t:assert(flush and flush.ret == 0 and iflush > iw,
            "the file was flushed after it was written: " .. shutdown.render(record))
        t:assert(close and iclose > iflush and irename > iclose,
            "and closed before it was renamed")
        t:assert(rename.path == "/var/state/peinit/" .. temp and rename.newname == SEED
            and rename.ret == 0,
            "renamed from the temporary name straight over the seed: " .. rename.args)
        t:assert(dir_flush and dir_flush.ret == 0 and idir < iumount,
            "and a second flush followed the rename, before any unmount")

        local dir_opened = false
        for _, ev in ipairs(shutdown.entries(record, "fs")) do
            if ev.name == "." and ev.what:find("open", 1, true) then dir_opened = true end
        end
        t:assert(dir_opened, "the directory itself was opened: that is what was flushed")

        -- Atomic: one rename, seen from the directory as one move with
        -- one cookie, and the old seed never deleted first.
        local from, to, deleted
        for _, ev in ipairs(shutdown.entries(record, "fs")) do
            if ev.what:find("moved_from", 1, true) and ev.name == temp then from = ev.cookie end
            if ev.what:find("moved_to", 1, true) and ev.name == "random-seed" then to = ev.cookie end
            if ev.what:find("delete", 1, true) and ev.name == "random-seed" then deleted = true end
        end
        t:assert(from and from == to, "the move out of the temporary name and into the seed's "
            .. "are one rename (cookie " .. tostring(from) .. "/" .. tostring(to) .. ")")
        t:assert(not deleted, "and the old seed was replaced by it, never removed first")
    end)

test("every non-root mount in the namespace is unmounted, deepest first",
    { spec = "peinit *graceful.every-non-root-mount-is-unmounted-deepest-first" },
    function(t)
        local record = observed().record
        local expected = {}
        for _, mount in ipairs(shutdown.entries(record, "at-start")) do
            if mount.point ~= "/" then expected[mount.point] = true end
        end
        t:assert(expected["/mnt/pt-deep/a/b"] and expected["/proc"],
            "the table at the start holds both the test's mounts and the image's")

        local attempted, last_depth, order = {}, math.huge, {}
        for _, call in ipairs(shutdown.calls(record, "umount")) do
            attempted[call.path] = (attempted[call.path] or 0) + 1
            order[#order + 1] = call.path
            t:assert(depth(call.path) <= last_depth,
                call.path .. " was not attempted after a shallower mount: "
                .. table.concat(order, " "))
            last_depth = depth(call.path)
        end
        for point in pairs(expected) do
            t:assert_eq(attempted[point], 1,
                point .. " was attempted exactly once — every mount, not only peinit's own")
        end
        for point in pairs(attempted) do
            t:assert(expected[point], point .. " was in the table the step started from")
        end
        t:assert(not attempted["/"], "and the root was not among them")
    end)

test("the root is remounted read-only at the end of step 7 and never unmounted",
    { spec = "peinit *graceful.the-root-is-remounted-read-only-never-unmounted" },
    function(t)
        local record = observed().record
        local roots = {}
        for _, call in ipairs(shutdown.calls(record, "mount")) do
            if call.path == "/" then roots[#roots + 1] = call end
        end
        t:assert_eq(#roots, 1, "the root was remounted once: " .. shutdown.render(record))
        t:assert_eq(roots[1].flags, MS_REMOUNT_RDONLY, "with MS_REMOUNT|MS_RDONLY")
        t:assert_eq(roots[1].ret, 0, "and it succeeded")

        local umounts = shutdown.calls(record, "umount")
        local syncs = shutdown.calls(record, "sync")
        t:assert(roots[1].seq > umounts[#umounts].seq, "after the last unmount")
        t:assert(syncs[1] and roots[1].seq < syncs[1].seq, "and before the sync")
        for _, call in ipairs(umounts) do
            t:assert(call.path ~= "/", "umount2 was never called on the root")
        end

        local read_only = false
        for _, change in ipairs(shutdown.entries(record, "changed")) do
            if change.point == "/" and change.after:match("^ro,") then read_only = true end
        end
        t:assert(read_only, "and PID 1's own table shows the root read-only afterwards")
    end)

test("a failed read-only remount of the root is recorded and does not stop the sync or the final action",
    { spec = "peinit *graceful.the-root-is-remounted-read-only-never-unmounted" },
    function(t)
        -- A process holding a file open for writing on the root is what
        -- makes MS_RDONLY impossible there. The claim is that step 8 is
        -- reached anyway.
        with_vm({
            name = "rootheld",
            append = "peios.quiet=0",
            files = peinit.merge(shutdown.tool(), { [SEED:sub(2)] = STAGED_SEED }),
        }, function(vm)
            settle(vm)
            vm:run("/bin/sleep 600 > /pt-root-held 2>&1 &")
            shutdown.start(vm, { hold = 1 })
            trigger(vm, "svctl shutdown poweroff")
            shutdown.released(vm, 120)
            vm:console():expect("reboot: Power down", 30)
            pause(1)

            local record = shutdown.record(vm:console():read_log())
            local root, iroot = find_call(record,
                function(c) return c.name == "mount" and c.path == "/" end)
            t:assert(root and root.ret == shutdown.EBUSY,
                "the root's read-only remount failed with EBUSY: " .. shutdown.render(record))
            local sync = find_call(record, function(c) return c.name == "sync" end, iroot)
            local reboot = find_call(record, function(c) return c.name == "reboot" end, iroot)
            t:assert(sync and reboot and sync.seq < reboot.seq,
                "and sync() and reboot(2) followed it regardless")
            t:assert_eq(reboot.cmd, RB_POWER_OFF, "the final action was still the poweroff")
        end)
    end)

test("an unmount that fails falls back to a read-only remount, and a remount that fails is passed over",
    { spec = "peinit *graceful.a-failed-unmount-falls-back-to-a-read-only-remount" },
    function(t)
        local record = observed().record

        local function after(point)
            local umount, i = find_call(record,
                function(c) return c.name == "umount" and c.path == point end)
            return umount, record.calls[i + 1], record.calls[i + 2]
        end

        -- Held busy: the unmount fails, the remount is attempted at once
        -- and succeeds, and the table says so.
        local umount, remount = after("/mnt/pt-busy")
        t:assert_eq(umount.ret, shutdown.EBUSY, "/mnt/pt-busy would not unmount")
        t:assert(remount.name == "mount" and remount.path == "/mnt/pt-busy"
            and remount.flags == MS_REMOUNT_RDONLY,
            "so the very next call remounted it read-only: " .. shutdown.render(record))
        t:assert_eq(remount.ret, 0, "which succeeded")
        local now_ro = false
        for _, change in ipairs(shutdown.entries(record, "changed")) do
            if change.point == "/mnt/pt-busy" and change.after:match("^ro,") then now_ro = true end
        end
        t:assert(now_ro, "and the mount stayed, read-only")

        -- Held open for writing: the remount fails too, and the step
        -- moves straight on to the next mount point.
        local held, held_remount, next_call = after("/mnt/pt-held")
        t:assert_eq(held.ret, shutdown.EBUSY, "/mnt/pt-held would not unmount")
        t:assert(held_remount.name == "mount" and held_remount.path == "/mnt/pt-held"
            and held_remount.ret == shutdown.EBUSY,
            "its read-only remount was attempted and failed")
        t:assert(next_call.name == "umount" and next_call.path ~= "/mnt/pt-held",
            "and the next call was the next mount's unmount: that failure was passed over")

        -- The fallback is for failures only.
        for i, call in ipairs(record.calls) do
            if call.name == "umount" and call.ret == 0 then
                local following = record.calls[i + 1]
                t:assert(not (following and following.name == "mount"
                    and following.path == call.path),
                    call.path .. " unmounted, and was not remounted")
            end
        end
    end)

test("a mount point already gone by the time step 7 reaches it is a successful no-op",
    { spec = "peinit *graceful.a-mount-point-already-gone-is-a-no-op" },
    function(t)
        local record = observed().record
        local twin
        for _, mount in ipairs(shutdown.entries(record, "at-start")) do
            if mount.point == "/mnt/pt-peer-b/x" then twin = mount end
        end
        t:assert(twin, "the propagated twin was in the table step 7 started from")

        local first, ifirst = find_call(record,
            function(c) return c.name == "umount" and c.path == "/mnt/pt-peer-a/x" end)
        local gone, igone = find_call(record,
            function(c) return c.name == "umount" and c.path == "/mnt/pt-peer-b/x" end)
        t:assert(first and first.ret == 0 and gone and ifirst < igone,
            "unmounting the first peer's child came first, and took its twin with it")
        t:assert(gone.ret == shutdown.EINVAL or gone.ret == shutdown.ENOENT,
            "so the twin's own unmount found no mount there: " .. tostring(gone.ret))

        -- A failure is always followed by a read-only remount. None was
        -- attempted here: the missing mount was taken as done.
        for _, call in ipairs(shutdown.calls(record, "mount")) do
            t:assert(call.path ~= "/mnt/pt-peer-b/x",
                "no read-only remount was attempted on the mount that was already gone")
        end
        local next_call = record.calls[igone + 1]
        t:assert(next_call.name == "umount",
            "the step went straight on to the next mount: " .. next_call.name)
    end)

test("/proc goes before /run and /sys, and neither of those sends the step to its gone-check",
    { spec = "peinit *final.proc-is-unmounted-before-run-and-sys" },
    function(t)
        local record = observed().record
        local proc, iproc = find_call(record,
            function(c) return c.name == "umount" and c.path == "/proc" end)
        local run, irun = find_call(record,
            function(c) return c.name == "umount" and c.path == "/run" end)
        local sys, isys = find_call(record,
            function(c) return c.name == "umount" and c.path == "/sys" end)
        t:assert(proc and proc.ret == 0 and iproc < irun and iproc < isys,
            "/proc was unmounted before /run and /sys were attempted")

        -- Why the ordering is a latent hazard and not a live one: the
        -- "is it really gone?" check that would re-read mountinfo runs
        -- only after ENOENT or EINVAL, and neither mount answers that.
        -- /sys unmounts; /run here is busy, because the agent keeps its
        -- log open under it. Neither answer sends the step to the check.
        for _, call in ipairs({ run, sys }) do
            t:assert(call.ret ~= shutdown.ENOENT and call.ret ~= shutdown.EINVAL,
                call.path .. "'s unmount did not answer ENOENT or EINVAL, so its gone-check "
                .. "never ran: " .. tostring(call.ret))
        end
    end)

test("a final action that returns leaves PID 1 alive in a failed-shutdown state, restarting nothing",
    {
        spec = {
            "peinit *final.a-returning-final-action-enters-a-failed-shutdown-state",
            "peinit *final.a-failed-final-action-does-not-restart-services-or-enter-recovery",
        },
    },
    function(t)
        local o = observed()
        local record = o.record
        local reboots = shutdown.calls(record, "reboot")
        t:assert(#reboots >= HELD_ATTEMPTS + 1,
            "reboot(2) was attempted, failed, and attempted again: " .. shutdown.render(record))
        t:assert_eq(reboots[1].ret, shutdown.EPERM, "the first attempt returned EPERM")

        -- The failure is recorded, on the console, by a PID 1 that is
        -- still running — which is also what printing it proves.
        local began = o.log:find("peinit: shutdown Poweroff started", 1, true)
        t:assert(began, "the shutdown announced itself")
        local after = o.log:sub(began)
        t:assert(after:find('peinit: shutdown final action failed: Shutdown("reboot(poweroff) failed',
            1, true), "peinit recorded the failed final action")
        t:assert(reboots[2].seq > reboots[1].seq and reboots[2].t > reboots[1].t,
            "and kept going after it: PID 1 did not exit")

        -- Nothing was brought back. The retries are the final action and
        -- nothing else — no seed, no unmount, no service — and the
        -- control socket, still answering, has every service down.
        local _, ifirst = find_call(record, function(c) return c.name == "reboot" end)
        for i = ifirst + 1, #record.calls do
            local name = record.calls[i].name
            t:assert(name == "sync" or name == "reboot",
                "after the failed action PID 1 only synced and retried, not " .. name)
        end
        t:assert(not after:find("peinit: service [%w%-%._]+ started"),
            "no service was started after the shutdown began")
        for service, state in o.services:gmatch('"service":"([^"]+)","state":"([^"]+)"') do
            t:assert(state == "inactive" or state == "failed" or state == "abandoned",
                service .. " stayed down in the failed-shutdown state: " .. state)
        end
        t:assert(not o.log:find("peinit: entering recovery", 1, true),
            "and PID 1 did not enter recovery")

        -- The action that finally worked was the same one.
        t:assert(o.log:find("reboot: Power down", 1, true),
            "once reboot(2) could succeed, the machine powered off")
    end)

test("the failed final action is retried, the same action each time, at most once a second",
    {
        spec = "peinit *final.the-failed-action-is-retried-at-most-once-a-second",
        -- PEI-1088: the retry deadline is taken from
        -- the time the finalising turn began, not from when reboot(2)
        -- returned, so the first retry follows the failed attempt by one
        -- second less the length of steps 6 and 7 (0.98 s here), and
        -- later ones by one second less the jitter in sync()'s duration.
        -- PEI-1088: fixed in peinit d5395f1, "fix(shutdown):
        -- time the final action's retry from the attempt, not
        -- the turn". Green since 0.0.5-4.
    },
    function(t)
        local record = observed().record
        local reboots = shutdown.calls(record, "reboot")
        t:assert(#reboots >= HELD_ATTEMPTS + 1, "the action was retried: "
            .. shutdown.render(record))
        for i, reboot in ipairs(reboots) do
            t:assert_eq(reboot.cmd, RB_POWER_OFF, "attempt " .. i .. " was the same poweroff")
        end
        -- Each retry is preceded by its own sync.
        local calls = record.calls
        for i, call in ipairs(calls) do
            if call.name == "reboot" then
                t:assert(calls[i - 1] and calls[i - 1].name == "sync",
                    "reboot attempt at " .. call.t .. " was preceded by sync()")
            end
        end
        for i = 2, #reboots do
            local gap = reboots[i].t - reboots[i - 1].t
            t:assert(gap >= 1.0, string.format(
                "attempt %d came %.4f s after attempt %d: no more than once a second",
                i, gap, i - 1))
        end
    end)

test("a cleanup failure in steps 6 and 7 does not block the final action",
    { spec = "peinit *final.a-cleanup-failure-never-blocks-the-final-action" },
    function(t)
        -- An ordinary graceful poweroff on this image is already a
        -- shutdown with retained cleanup failures in it — though not for
        -- the reason §12.4's note gives (see the known-bug test above).
        -- The harness's agent holds /run/provium-agent.log open for
        -- writing, so /run neither unmounts nor remounts read-only: both
        -- answer EBUSY, on the witness's record. So this needs no
        -- arranging, and the claim is that it powers off anyway.
        with_vm({ name = "cleanup", append = "peios.quiet=0" }, function(vm)
            settle(vm)
            trigger(vm, "svctl shutdown poweroff")
            vm:console():expect("peinit: shutdown Poweroff started", 30)
            vm:console():expect("reboot: Power down", 60)

            local log = vm:console():read_log()
            t:assert(not log:find("peinit: entering recovery", 1, true),
                "and none of those failures took PID 1 into recovery")
            t:assert(not log:find("peinit: shutdown final action failed", 1, true),
                "nor stopped the final action from being reached")
        end)
    end)

test("RB_HALT_SYSTEM does not return, so halting does not reach the failed-shutdown state",
    { spec = "peinit *final.rb-halt-system-does-not-return-either" },
    function(t)
        -- The failed-shutdown state exists for a `reboot(2)` that comes
        -- back, and the halt case is called out as not being one. If it
        -- were, peinit would still be alive on the other side of "System
        -- halted", printing "shutdown final action failed" and retrying
        -- once a second. It prints nothing, because it is not running.
        with_vm({ name = "halted", append = "peios.quiet=0" }, function(vm)
            settle(vm)
            trigger(vm, "svctl shutdown halt")
            vm:console():expect("peinit: shutdown Halt started", 30)
            vm:console():expect("reboot: System halted", 60)

            local at_halt = #vm:console():read_log()
            -- Several retry intervals' worth of nothing.
            pause(8)
            local log = vm:console():read_log()
            t:assert(not log:find("peinit: shutdown final action failed", 1, true),
                "the halt did not come back as a failed final action")
            t:assert_eq(#log, at_halt,
                "and nothing at all was written after the kernel halted: PID 1 " ..
                "is not on the far side of RB_HALT_SYSTEM")
        end)
    end)
