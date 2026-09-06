-- prelude, area A: everything that happens before the first hook runs.
--
-- Phase 0 makes the rootfs private, phase 1 mounts /proc, /sys and /dev,
-- re-seeds /dev's security descriptor, and only then reads
-- /proc/cmdline. That ordering is the whole subject of this file: it is
-- what decides which mount options the kernel filesystems carry into the
-- new root, whether a mount failure is survivable, and which single line
-- of prelude's output escapes every command-line knob.
--
-- The three mounts are witnessed from the far side of the handoff —
-- prelude MS_MOVEs them into the new root, so the agent's
-- /proc/self/mountinfo is prelude's own mount table. Everything else is
-- witnessed on the console, which carries prelude's log lines whether
-- the boot completes or halts.
--
-- The command-line knobs themselves (peios.quiet, TERM, init=) and the
-- banner are in startup-cmdline.test.lua.

local prelude = require("helpers.prelude")

--- /proc/self/mountinfo, parsed into `{point, opts, optional, fstype}`.
---
---   25 28 0:23 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
---
--- `optional` is the propagation field between the options and the `-`
--- separator: empty for a private mount, `shared:N` for a shared one.
local function mounts(mi)
    local out = {}
    for line in mi:gmatch("[^\r\n]+") do
        local pre, post = line:match("^(.-) %- (.*)$")
        if pre then
            local f = {}
            for word in pre:gmatch("%S+") do f[#f + 1] = word end
            out[#out + 1] = {
                point = f[5],
                opts = f[6] or "",
                optional = table.concat(f, " ", 7),
                fstype = post:match("^(%S+)") or "",
            }
        end
    end
    return out
end

--- The mount prelude made at `point`. The agent that comes up on the new
--- root mounts its own /proc over prelude's, so a mountpoint can appear
--- twice; mountinfo is ordered by mount id, and prelude's mounts are the
--- older ones, so the first entry is always prelude's.
local function mount_at(entries, point)
    for _, m in ipairs(entries) do
        if m.point == point then return m end
    end
end

local function has_opt(m, flag)
    return ("," .. m.opts .. ","):find("," .. flag .. ",", 1, true) ~= nil
end

--- A stand-in for /usr/bin/seed-sd that fails prelude's own call — the
--- recursive one on /dev — and does the real work for everybody else.
---
--- The profile's root-mount hook seeds the tmpfs it mounts, and a fresh
--- tmpfs whose SD is MISSING is one KACS denies every access to, so a
--- stub that simply failed would take the boot down at the hook instead
--- of at the place under test. `sd set` stamps the same bootstrap
--- descriptor seed-sd's built-in one carries (SYSTEM and Administrators,
--- GenericAll, inheritable), which is all the hook needs.
local function seed_sd_stub(failure)
    return {
        path = "/usr/bin/seed-sd",
        mode = 0x1ed, -- 0755
        content = table.concat({
            "#!/usr/bin/sh",
            '# prelude calls `seed-sd -r /dev`; the hooks call `seed-sd <path>`.',
            'if [ "$1" = "-r" ]; then',
            '    echo "pt: seed-sd stub: $* refused" >&2',
            "    " .. failure,
            "fi",
            "exec sd set \"$1\" 'O:SYG:SYD:(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)' >/dev/null",
            "",
        }, "\n"),
    }
end

test("prelude mounts proc, sysfs and devtmpfs on the three kernel mountpoints",
    { spec = "prelude mount.kernel-filesystems-mounted" }, function(t)
        local vm = provium:vm("kernelfs", "prelude"):boot()
        local entries = mounts(vm:read_file("/proc/self/mountinfo"))
        for _, want in ipairs({ { "/proc", "proc" }, { "/sys", "sysfs" },
                                { "/dev", "devtmpfs" } }) do
            local m = mount_at(entries, want[1])
            t:assert(m, want[1] .. " is a mountpoint in the root prelude handed over")
            t:assert_eq(m.fstype, want[2],
                want[1] .. " carries the filesystem prelude mounted there")
        end
    end)

test("proc and sysfs are mounted nosuid, noexec and nodev; devtmpfs only nosuid",
    { spec = "prelude mount.kernel-filesystem-flags" }, function(t)
        local vm = provium:vm("mountflags", "prelude"):boot()
        local entries = mounts(vm:read_file("/proc/self/mountinfo"))

        for _, point in ipairs({ "/proc", "/sys" }) do
            local m = mount_at(entries, point)
            for _, flag in ipairs({ "nosuid", "noexec", "nodev" }) do
                t:assert(has_opt(m, flag),
                    point .. " carries MS_" .. flag:upper() .. ", not " .. m.opts)
            end
        end

        -- devtmpfs is the exception: device nodes are the point of it, so
        -- MS_NODEV is impossible, and MS_NOEXEC is not asked for either.
        local dev = mount_at(entries, "/dev")
        t:assert(has_opt(dev, "nosuid"), "/dev carries MS_NOSUID, not " .. dev.opts)
        t:assert(not has_opt(dev, "nodev"),
            "/dev carries MS_NOSUID only, and nodev is not among " .. dev.opts)
        t:assert(not has_opt(dev, "noexec"),
            "/dev carries MS_NOSUID only, and noexec is not among " .. dev.opts)
    end)

test("nothing prelude mounted propagates, so the mount-moves are not blocked",
    { spec = "prelude mount.rootfs-made-private-before-anything" }, function(t)
        -- Phase 0 is `mount(none, "/", MS_REC|MS_PRIVATE)`. Its effect is
        -- negative and it is the mounts made after it that show it: a
        -- shared mount cannot be MS_MOVEd, so the three that reached the
        -- new root must carry no propagation, and mountinfo's optional
        -- field is where a `shared:N` would appear if one did.
        local vm = provium:vm("private", "prelude"):boot()
        local entries = mounts(vm:read_file("/proc/self/mountinfo"))
        for _, point in ipairs({ "/proc", "/sys", "/dev" }) do
            local m = mount_at(entries, point)
            t:assert(not m.optional:find("shared:", 1, true),
                point .. " is private after the recursive MS_PRIVATE on /, " ..
                "so MS_MOVE could carry it into the new root; mountinfo " ..
                "says " .. (m.optional == "" and "(no propagation)" or m.optional))
        end
    end)

test("a kernel filesystem that cannot be mounted ends the boot",
    { spec = "prelude mount.failure-ends-the-boot" }, function(t)
        -- A regular file where /sys should be: the kernel's initramfs
        -- unpacker replaces the empty directory with it, and mounting
        -- sysfs onto a file is ENOTDIR. prelude's `do_mount(...)?` gives
        -- the error straight back to main, which halts.
        local vm = provium:vm("mountfail", "prelude")
        local out = prelude.boot_halts(t, vm, {
            files = { { path = "/sys", content = "not a directory\n" } },
        })
        t:assert(out:find("prelude: boot failed: Not a directory", 1, true),
            "the failed sysfs mount ended the boot: " .. out:sub(-400))
        t:assert(not out:find("seeded /dev", 1, true),
            "and it ended there: /dev is mounted after /sys, so the seed " ..
            "line prelude prints next never appeared")
        t:assert(not out:find("prelude: hook", 1, true), "no hook ran")
    end)

test("prelude re-seeds /dev the moment devtmpfs is mounted, before anything else",
    { spec = "prelude dev.seeded-after-devtmpfs" }, function(t)
        local vm = provium:vm("seedorder", "prelude"):boot()
        local log = vm:console():read_log()

        t:assert_eq(log:match("%] prelude: ([^\r\n]*)"), "seeded /dev",
            "`seeded /dev` is the first line prelude prints: the seed runs " ..
            "in phase 1, immediately after the devtmpfs mount")

        local seed = log:find("prelude: seeded /dev", 1, true)
        local banner = log:find("prelude · initramfs · PID 1", 1, true)
        local hook = log:find("prelude: hook sequence:", 1, true)
        t:assert(seed and banner and seed < banner,
            "the seed precedes the banner")
        t:assert(seed and hook and seed < hook,
            "and precedes the hook sequence prelude goes on to read")
    end)

test("seed-sd exiting non-zero is logged and the boot carries on",
    { spec = "prelude dev.seed-failure-is-not-fatal" }, function(t)
        local vm = provium:vm("seedfail", "prelude")
        vm:boot({ files = { seed_sd_stub("exit 3") } })

        local log = vm:console():read_log()
        t:assert(log:find(
            "prelude: seed-sd -r /dev exited with status 3; /dev stays " ..
            "SYSTEM-only for nodes it could not stamp", 1, true),
            "prelude named the status and what it costs: " .. log:sub(1, 600))
        t:assert(log:find("FAILED", 1, true), "logged at FAILED, never suppressed")
        t:assert_eq(vm:read_file("/proc/1/comm"):gsub("%s+$", ""), "peinit2",
            "and the boot completed anyway: a SYSTEM-only /dev is a degraded " ..
            "system, not an unbootable one")
    end)

test("a seed-sd prelude cannot wait on is logged and the boot carries on",
    { spec = "prelude dev.seed-failure-is-not-fatal" }, function(t)
        -- The other half of the claim: `spawn_and_wait` returns Err
        -- rather than a status when the child never exits normally, and
        -- that path has its own message.
        local vm = provium:vm("seedsignal", "prelude")
        vm:boot({ files = { seed_sd_stub("kill -TERM $$\n    sleep 5") } })

        local log = vm:console():read_log()
        t:assert(log:find(
            "prelude: seed /dev: /usr/bin/seed-sd: killed by signal 15; " ..
            "/dev stays SYSTEM-only", 1, true),
            "prelude reported the failed spawn: " .. log:sub(1, 600))
        t:assert_eq(vm:read_file("/proc/1/comm"):gsub("%s+$", ""), "peinit2",
            "and the boot completed anyway")
    end)

test("peios.quiet=2 cannot suppress the /dev seed line, which precedes the read",
    { spec = "prelude dev.seed-line-precedes-the-cmdline-read" }, function(t)
        local vm = provium:vm("seedquiet", "prelude")
        vm:boot({ kernel_cmdline_append = "peios.quiet=2" })
        local log = vm:console():read_log()

        t:assert(log:find("prelude: seeded /dev", 1, true),
            "the seed line survives the blackout: prelude emits it before it " ..
            "has read peios.quiet=2, and cannot obey a preference it has not read")
        -- The same ordering in the other knob: TERM=dumb is on the
        -- profile's own command line, and this line is still coloured.
        t:assert(log:find("\27[1;32mOK\27[0m  ] prelude: seeded /dev", 1, true),
            "and still carries the SGR bytes TERM=dumb turns off everywhere else")
        t:assert(not log:find("prelude: hook sequence:", 1, true),
            "while everything prelude says after the read is blacked out")
    end)

test("the command line is read after the three mounts, and takes effect from the banner on",
    { spec = "prelude cmdline.read-once-after-the-mounts" }, function(t)
        -- /proc/cmdline is unreadable until /proc is mounted, so the read
        -- sits at the end of phase 1 — after the mounts and after the
        -- seed. The console shows exactly where: the profile's TERM=dumb
        -- is honoured from the banner onward and by nothing before it.
        local vm = provium:vm("cmdlineread", "prelude"):boot()
        local log = vm:console():read_log()

        local seed = log:find("\27[1;32mOK\27[0m  ] prelude: seeded /dev", 1, true)
        t:assert(seed, "the line printed before the read is coloured")

        local at = log:find("prelude: seeded /dev", 1, true)
        local after = log:sub(at)
        t:assert(not after:find("\27[", 1, true),
            "and no line after it is: one read, between the seed and the " ..
            "banner, is what puts the boundary there")
        t:assert(after:find("[  OK  ] prelude: root mounted at /mnt/rootfs", 1, true),
            "the later success lines are the plain rendering")
    end)
