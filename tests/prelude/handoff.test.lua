-- Area E, first half: the root check and the handoff.
--
-- Everything here happens after the last hook has run, when prelude is
-- alone again: it decides whether anybody actually mounted a root, moves
-- the kernel filesystems across, empties the initramfs it booted from,
-- and chroots into what it found. Claims E1-E10.
--
-- Two oracles, and the split between them is the whole shape of this
-- file. prelude's console says what it did; the agent it exec'd — which
-- is running inside the new root, with the moved mounts under it — says
-- what survived. The initramfs itself is unreachable by the time anyone
-- can be asked a question, so a test that wants to know what the cleanup
-- walk did has to arrange for the answer to be visible from the far
-- side: a hook binds the directory in question into the new root before
-- the walk runs, and the agent reads it back through that bind.

local prelude = require("helpers.prelude")

--- `/proc/self/mountinfo`, parsed: one entry per mount in the namespace
--- that is reachable from the reading process's root. Fields are the
--- mount's own id, its parent's, where it is, and what it is.
local function mountinfo(vm)
    local out = {}
    for line in vm:read_file("/proc/self/mountinfo"):gmatch("[^\n]+") do
        local id, parent, point, rest = line:match("^(%d+) (%d+) %S+ %S+ (%S+) (.*)$")
        if id then
            out[#out + 1] = {
                id = tonumber(id),
                parent = tonumber(parent),
                point = point,
                fstype = rest:match("%- (%S+)"),
            }
        end
    end
    return out
end

--- The entry mounted at `point` with filesystem `fstype`, or nil.
local function mount_of(mounts, point, fstype)
    for _, m in ipairs(mounts) do
        if m.point == point and m.fstype == fstype then return m end
    end
    return nil
end

--- The first `pt|` report from `hook` that carries `field`.
local function mark_with(log, hook, field)
    for _, m in ipairs(prelude.marks(log)) do
        if m.hook == hook and m[field] then return m end
    end
    return nil
end

test("prelude provides /mnt/rootfs, empty and on the initramfs's own device, before the first hook runs",
    { spec = "prelude root.mountpoint-created-before-the-hooks" }, function(t)
        -- A hook that only looks. It runs first in the sequence and
        -- declares nothing, so it is ready on the first pass and reports
        -- the state of the mountpoint before anything has touched it.
        local probe = table.concat({
            "#!/usr/bin/sh",
            "# /// hook",
            "# ///",
            "set -eu",
            ". /fixtures/pt-hook.sh",
            "pt_gate probe",
            'pt_mark probe mnt="$([ -d /mnt ] && echo dir || echo absent)" \\',
            '    rootfs="$([ -d /mnt/rootfs ] && echo dir || echo absent)" \\',
            '    entries="$(ls -A /mnt/rootfs | wc -l)" \\',
            '    dev="$(stat -c %d /mnt/rootfs)" rootdev="$(stat -c %d /)"',
            "pt_mark probe outcome=satisfied",
            "exit 0",
            "",
        }, "\n")

        local vm = provium:vm("mountpoint", "prelude")
        vm:boot({ files = prelude.files({
            hooks = { probe = { body = probe } },
            order = { "probe" },
            keep = { "pt-mount-root.sh" },
        }) })
        local log = vm:console():read_log()

        t:assert_eq(prelude.ran(log)[1], "probe.sh",
            "the probe hook is the first thing prelude ran")

        local m = mark_with(log, "probe", "rootfs")
        t:assert(m, "the probe reported: " .. log:sub(-600))
        t:assert_eq(m.mnt, "dir", "/mnt exists before the hooks run")
        t:assert_eq(m.rootfs, "dir", "/mnt/rootfs exists before the hooks run")
        t:assert_eq(m.entries, "0", "and prelude left it empty — mounting a root is a hook's job")
        t:assert_eq(m.dev, m.rootdev,
            "nothing is mounted on it yet: it is still on the initramfs's own device, " ..
            "which is exactly what makes prelude's later same-device check mean anything")
    end)

test("a /mnt/rootfs on the initramfs's own device is no root, however full a hook makes it",
    { spec = "prelude root.same-device-is-no-root-mounted" }, function(t)
        -- The check is st_dev, not contents. This hook copies a complete
        -- root — including an executable /bin/peinit2, the first name in
        -- prelude's fallback chain — into the mountpoint without mounting
        -- anything, and prelude must still refuse the boot.
        local populate = table.concat({
            "#!/usr/bin/sh",
            "# /// hook",
            "# ///",
            "set -eu",
            ". /fixtures/pt-hook.sh",
            "pt_gate populate",
            "cp -a /fixtures/rootfs/. /mnt/rootfs/",
            'pt_mark populate init="$([ -x /mnt/rootfs/bin/peinit2 ] && echo present || echo absent)" \\',
            '    dev="$(stat -c %d /mnt/rootfs)" rootdev="$(stat -c %d /)"',
            "pt_mark populate outcome=satisfied",
            "exit 0",
            "",
        }, "\n")

        local vm = provium:vm("no-root", "prelude")
        local err = prelude.boot_halts(t, vm, { files = prelude.files({
            hooks = { populate = { body = populate } },
        }) })

        local m = mark_with(err, "populate", "init")
        t:assert(m, "the hook reported what it left behind: " .. err:sub(-600))
        t:assert_eq(m.init, "present", "an executable init is sitting in /mnt/rootfs")
        t:assert_eq(m.dev, m.rootdev, "and it is on the initramfs's own device")

        t:assert(err:find("boot failed: no hook mounted a root filesystem at /mnt/rootfs", 1, true),
            "prelude refused the boot for want of a root, naming the mountpoint: " .. err:sub(-600))
        t:assert(not err:find("exec /bin/peinit2", 1, true),
            "and never tried to exec the init it could see, because it never got past the check")
    end)

test("a root on another device is announced before anything is moved onto it",
    { spec = "prelude root.mounted-is-logged" }, function(t)
        local vm = provium:vm("root-logged", "prelude"):boot()
        local log = vm:console():read_log()

        local ok = log:find("[  OK  ] prelude: root mounted at /mnt/rootfs", 1, true)
        t:assert(ok, "prelude announced the root at OK: " .. log:sub(-600))

        local hooks_done = log:find("ran 3 hook invocation(s)", 1, true)
        local first_move = log:find("mount-move /proc", 1, true)
        t:assert(hooks_done and hooks_done < ok,
            "the check is made after the hooks, not before")
        t:assert(first_move and ok < first_move,
            "and before the handoff proper begins")
    end)

test("the kernel filesystems are moved into the new root, in order, and are the same mounts",
    { spec = "prelude handoff.kernel-filesystems-are-moved" }, function(t)
        local vm = provium:vm("moves", "prelude"):boot()
        local log = vm:console():read_log()

        local at = {}
        for _, sub in ipairs({ "proc", "sys", "dev" }) do
            at[sub] = log:find("mount-move /" .. sub .. " -> /mnt/rootfs/" .. sub, 1, true)
            t:assert(at[sub], "prelude logged the move of /" .. sub .. ": " .. log:sub(-600))
        end
        t:assert(at.proc < at.sys and at.sys < at.dev,
            "the three are moved in the order /proc, /sys, /dev")

        -- The far side. Each is under the new root now, and each was
        -- created before it: a mount id below the root's own is only
        -- possible for a mount that existed in the initramfs and was
        -- moved, never for one made freshly after the root appeared.
        local mounts = mountinfo(vm)
        local root = mount_of(mounts, "/", "tmpfs")
        t:assert(root, "the agent's root is the tmpfs a hook mounted")
        for _, pair in ipairs({ { "/proc", "proc" }, { "/sys", "sysfs" }, { "/dev", "devtmpfs" } }) do
            local m = mount_of(mounts, pair[1], pair[2])
            t:assert(m, pair[2] .. " is mounted at " .. pair[1] .. " in the new root")
            t:assert_eq(m.parent, root.id,
                pair[1] .. " hangs under the new root, not beside it")
            t:assert(m.id < root.id,
                pair[1] .. " predates the root it now sits in, so it was moved rather than remounted")
        end
    end)

test("a kernel filesystem that cannot be moved ends the boot, naming which one",
    { spec = "prelude handoff.failed-move-ends-the-boot" }, function(t)
        -- The new root ships /proc, /sys and /dev as empty mountpoint
        -- directories. Take one away and the move onto it has nowhere to
        -- land. /sys is the middle of the three, so the console also
        -- shows that prelude stopped there rather than carrying on.
        local vm = provium:vm("bad-move", "prelude")
        local err = prelude.boot_halts(t, vm, { files = prelude.files({
            hooks = { root = { body = prelude.root_hook("root", "rmdir /mnt/rootfs/sys") } },
        }) })

        t:assert(err:find("mount-move /proc -> /mnt/rootfs/proc", 1, true),
            "the first move was made")
        t:assert(err:find("boot failed: mount-move /sys: No such file or directory", 1, true),
            "and the boot ended on the second, named: " .. err:sub(-600))
        t:assert(not err:find("mount-move /dev", 1, true),
            "the third was never attempted")
        t:assert(not err:find("pivot: chroot", 1, true),
            "and prelude never reached the pivot")
    end)

test("the cleanup walk empties the old root's own device and leaves another device alone",
    { spec = "prelude cleanup.only-the-old-root-device-is-emptied" }, function(t)
        -- Neither half of this is visible from inside the new root by
        -- itself, so the hook binds both directories into the new root
        -- before the walk runs. After the pivot the agent reads them
        -- back through those binds: one is a tmpfs the walk had to skip,
        -- the other is on the initramfs's own device and had to go.
        local vm = provium:vm("cleanup-devices", "prelude")
        vm:boot({ files = prelude.files({
            hooks = { root = { body = prelude.root_hook("root", table.concat({
                "mkdir -p /pt-keep /pt-old",
                "mount -t tmpfs tmpfs /pt-keep",
                "seed-sd /pt-keep",
                "echo keep > /pt-keep/marker",
                "echo old > /pt-old/marker",
                "mkdir -p /mnt/rootfs/pt-keep /mnt/rootfs/pt-old",
                "mount --bind /pt-keep /mnt/rootfs/pt-keep",
                "mount --bind /pt-old /mnt/rootfs/pt-old",
                'pt_mark root keepdev="$(stat -c %d /pt-keep)" \\',
                '    olddev="$(stat -c %d /pt-old)" rootdev="$(stat -c %d /)"',
            }, "\n")) } },
        }) })
        local log = vm:console():read_log()

        local m = mark_with(log, "root", "keepdev")
        t:assert(m, "the hook reported the two devices: " .. log:sub(-600))
        t:assert(m.keepdev ~= m.rootdev, "/pt-keep is a mount, on a device of its own")
        t:assert_eq(m.olddev, m.rootdev, "/pt-old is on the initramfs's own device")

        t:assert_eq(vm:read_file("/pt-keep/marker"), "keep\n",
            "what lived on another device survived the walk: st_dev is what spares a mount")
        local ok = pcall(function() return vm:read_file("/pt-old/marker") end)
        t:assert(not ok,
            "and what lived on the old root's device is gone: the walk deletes everything " ..
            "whose st_dev matches /")
    end)

test("a directory left non-empty by a preserved mount is removed silently",
    { spec = "prelude cleanup.enotempty-is-expected" }, function(t)
        -- Every boot has this case in it already: /mnt is on the old
        -- root's device so the walk descends into it, /mnt/rootfs is the
        -- new root and is skipped for being elsewhere, and the rmdir of
        -- /mnt then cannot succeed. ENOTEMPTY there is the expected
        -- outcome, so prelude says nothing about it.
        local vm = provium:vm("enotempty", "prelude"):boot()
        local log = vm:console():read_log()

        t:assert(log:find("mount-move /dev -> /mnt/rootfs/dev", 1, true),
            "the walk ran: it comes right after the moves")
        t:assert(not log:find("cleanup:", 1, true),
            "and said nothing at all, though /mnt holds the new root and cannot be removed: " ..
            log:sub(-600))
    end)

test("any other cleanup error is a warning and the boot goes on",
    { spec = { "prelude cleanup.enotempty-is-expected",
               "prelude cleanup.failure-does-not-end-the-boot" } }, function(t)
        -- A bind of one initramfs directory onto another leaves a
        -- mountpoint on the old root's own device: the walk does not
        -- skip it, descends it, and then cannot remove it. EBUSY is not
        -- ENOTEMPTY, so unlike the /mnt case above this one is reported
        -- — and reported only, because a cleanup that cannot finish is
        -- not a reason to refuse a boot that is otherwise ready.
        local vm = provium:vm("cleanup-busy", "prelude")
        vm:boot({ files = prelude.files({
            hooks = { root = { body = prelude.root_hook("root", table.concat({
                "mkdir -p /pt-src /pt-busy",
                "mount --bind /pt-src /pt-busy",
            }, "\n")) } },
        }) })
        local log = vm:console():read_log()

        t:assert(log:find("[ WARN ] prelude: cleanup: rmdir /pt-busy failed: Resource busy",
            1, true), "the walk warned, naming the directory and the errno: " .. log:sub(-800))
        t:assert(log:find("pivot: chroot", 1, true),
            "and the boot carried on into the pivot")
        t:assert_eq(vm:read_file("/proc/1/comm"):gsub("%s+$", ""), "peinit2",
            "reaching the handoff: a cleanup failure does not end the boot")
    end)

test("the pivot is chdir, chroot, chdir, and the old root is left above it rather than moved",
    { spec = { "prelude handoff.pivot-is-chroot-not-pivot-root",
               "prelude handoff.pivot-failure-ends-the-boot" } }, function(t)
        local vm = provium:vm("pivot", "prelude"):boot()
        local log = vm:console():read_log()

        local steps = {}
        for _, step in ipairs({ "pivot: chdir rootfs", "pivot: chroot", "pivot: chdir /" }) do
            steps[#steps + 1] = log:find(step, 1, true)
            t:assert(steps[#steps], "prelude logged `" .. step .. "`: " .. log:sub(-600))
        end
        t:assert(steps[1] < steps[2] and steps[2] < steps[3],
            "the three steps are logged in order: chdir into the root, chroot to it, chdir to /")

        -- What chroot leaves behind that pivot_root would not. The
        -- initramfs rootfs is still the mount namespace's root and still
        -- the new root's parent mount — it is simply unreachable, so it
        -- does not appear in a mount table read from inside. A
        -- pivot_root would have made the new root the top of the tree,
        -- or put the old one somewhere nameable.
        local mounts = mountinfo(vm)
        local root = mount_of(mounts, "/", "tmpfs")
        t:assert(root, "the agent's root is the tmpfs the hook mounted")
        t:assert(root.parent ~= root.id, "which is not the root of the mount namespace")
        local parent_listed = false
        for _, m in ipairs(mounts) do
            if m.id == root.parent then parent_listed = true end
        end
        t:assert(not parent_listed,
            "and its parent — the initramfs prelude booted from — is not in the table at all: " ..
            "chroot made it unreachable instead of moving it aside")
    end)

test("a pivot step that fails ends the boot",
    { spec = "prelude handoff.pivot-failure-ends-the-boot",
      skip = "no guest can reach it. Phase 5 has already mount-moved /proc, /sys and /dev " ..
             "onto /mnt/rootfs by the time the pivot runs, and a successful move proves the " ..
             "path is a traversable directory — so chdir(/mnt/rootfs), chroot(.) and chdir(/) " ..
             "cannot then fail. Every way of breaking the path breaks phase 4 or phase 5 " ..
             "first, which is what the two tests above assert. Nothing covers this half: " ..
             "boot()'s phases have no unit tests in prelude's `mod tests` either. The test " ..
             "above covers the other half of the claim, that each pivot step is logged" },
    function(t) end)
