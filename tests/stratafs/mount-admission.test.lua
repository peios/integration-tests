-- PKM §4.2.3 — what a caller must be entitled to, what a configuration
-- has to satisfy, the order those are decided in, and loop detection.

local sys = require("helpers.sys")
local stratafs = require("helpers.stratafs")
local kacs = require("helpers.kacs")

local vm = provium:vm("v", "kernel-only"):boot()

-- A pair of ordinary strata for the cases whose subject is the
-- configuration rather than what the strata hold.
local base = stratafs.scenario(vm, "admission", {
    { name = "a", entries = { a = "a" } },
    { name = "b", entries = { b = "b" } },
}, { mount = false })
local A, B = base:in_stratum("a"), base:in_stratum("b")

local seq = 0
local function admit(spec)
    seq = seq + 1
    spec.at = spec.at or (base.root .. "/mnt" .. seq)
    return stratafs.try_mount(vm, spec), spec.at
end

local function refused_with(t, why, spec, errno)
    local r, at = admit(spec)
    if r.ret == 0 then stratafs.umount(vm, at) end
    t:assert_neq(r.ret, 0, why .. " is refused")
    t:assert_eq(r.errno, errno,
        why .. " gives " .. sys.errname(errno) .. ", not " .. sys.errname(r.errno))
end

-- §4.2.3's entitlement rules are about who is mounting, and everything
-- the agent does otherwise runs as root in the initial namespaces. A
-- worker in a new user namespace supplies the other side.
--
-- Its mounts land in its own mount namespace and go when it does, so a
-- mount that succeeds here needs no cleanup and cannot disturb anything
-- the rest of the file does.
--- Run `fn` as a caller in a new user namespace, and reap it after.
---
--- The worker holds a mount namespace of its own, so a mount it makes
--- survives as long as it does — leaving one running pins a superblock
--- the test file is trying to tear down. It is killed whether the body
--- passed or raised.
local function unprivileged(t, fn)
    local worker, errno = sys.unprivileged_worker(vm)
    t:assert(worker, "a user namespace is available: " .. sys.errname(errno or 0))
    t:assert_eq(worker:syscall(sys.NR.getuid).ret, 65534,
        "and the caller in it is unprivileged outside it")
    local ok, err = pcall(fn, worker)
    worker:kill()
    worker:join()
    if not ok then error(err, 0) end
end

local function mount_as(who, at, data)
    sys.mkdir(who, at)
    return sys.mount(who, {
        source = "stratafs", target = at, fstype = "stratafs", data = data,
    })
end

test("a stack with no create stratum takes no privilege of its own",
    { spec = "PKM *mount.create-requires-init-userns-cap" }, function(t)
        -- The filesystem type carries FS_USERNS_MOUNT: what the caller
        -- needs is only the access resolving the stratum paths already
        -- requires, which falls out of the resolution itself.
        unprivileged(t, function(worker)
            local at = base.root .. "/userns-nocreate"

            local r = mount_as(worker, at, "strata=" .. A .. ":" .. B)
            t:assert_eq(r.ret, 0,
                "an unprivileged mount in a user namespace is permitted: " ..
                sys.errname(r.errno))

            -- The same stack with create is a different proposition: the
            -- configuration would carry authority to materialise names in a
            -- real directory outside the mount.
            local withcreate = mount_as(worker, base.root .. "/userns-create",
                "strata=" .. A .. "+create:" .. B)
            t:assert_neq(withcreate.ret, 0, "the same stack with create is refused")
            t:assert_eq(withcreate.errno, sys.E.PERM,
                "with EPERM: " .. sys.errname(withcreate.errno))
        end)
    end)

test("a create-bearing stack requires the initial user namespace",
    { spec = "PKM *mount.admit.create-requires-privilege-eperm" }, function(t)
        unprivileged(t, function(worker)

            -- The caller holds a full capability set inside its own
            -- namespace; the test is stricter than the capability, because
            -- the credential's user namespace must *be* the initial one.
            for _, flags in ipairs({ "+create", "+create+am" }) do
                local r = mount_as(worker, base.root .. "/userns-c" .. flags:len(),
                    "strata=" .. A .. flags)
                t:assert_neq(r.ret, 0, "a create stratum (" .. flags .. ") is refused")
                t:assert_eq(r.errno, sys.E.PERM,
                    "with EPERM: " .. sys.errname(r.errno))
            end

            -- The control: the identical stack from the initial namespace.
            local r, at = admit({ data = "strata=" .. A .. "+create" })
            t:assert_eq(r.ret, 0,
                "and is admitted from the initial namespace: " .. sys.errname(r.errno))
            stratafs.umount(vm, at)
        end)
    end)

test("the entitlement test precedes every path resolution",
    { spec = "PKM *mount.admit.create-requires-privilege-eperm" }, function(t)
        -- The test is made in get_tree, before the tree is built and
        -- therefore before any stratum path is resolved. A create
        -- stratum that does not exist must still be EPERM and not
        -- ENOENT, or the refusal would be an oracle for what is there.
        unprivileged(t, function(worker)
            local missing = base.root .. "/absent-to-the-unprivileged"

            local r = mount_as(worker, base.root .. "/userns-order",
                "strata=" .. missing .. "+create")
            t:assert_neq(r.ret, 0, "an absent create stratum is refused")
            t:assert_eq(r.errno, sys.E.PERM,
                "with EPERM rather than ENOENT: " .. sys.errname(r.errno))

            local file = base.root .. "/a-regular-file"
            vm:write_file(file, "x")
            local r2 = mount_as(worker, base.root .. "/userns-order2",
                "strata=" .. file .. "+create")
            t:assert_eq(r2.errno, sys.E.PERM,
                "and a create stratum that is a regular file likewise: " ..
                sys.errname(r2.errno))
        end)
    end)

test("option-string conditions are decided before entitlement",
    { spec = "PKM *mount.admission-evaluation-order" }, function(t)
        -- The order is: everything that depends on nothing but the
        -- option string, then the EPERM admission test, then the paths.
        -- So a create-bearing stack that is also malformed is EINVAL,
        -- not EPERM, even from a caller who could never have mounted it.
        unprivileged(t, function(worker)

            local cases = {
                ["two create strata"] = "strata=" .. A .. "+create:" .. B .. "+create",
                ["create with ro"] = "strata=" .. A .. "+create+ro",
                ["create with an unknown flag"] = "strata=" .. A .. "+create+nope",
                ["create on a relative path"] = "strata=relative+create",
            }
            for why, data in pairs(cases) do
                local r = mount_as(worker, base.root .. "/userns-inval-" .. #why, data)
                t:assert_neq(r.ret, 0, why .. " is refused")
                t:assert_eq(r.errno, sys.E.INVAL,
                    why .. " gives EINVAL before the entitlement test, not " ..
                    sys.errname(r.errno))
            end
        end)
    end)

-- A directory no caller may traverse, holding names of every kind
-- behind it. Built once and shared: authoring a descriptor is the
-- expensive part, and both ordering cases want the same barrier.
local barrier_built = nil
local function barrier(t)
    if not barrier_built then
        local path = base.root .. "/barrier"
        vm:mkdir(path .. "/inner", { parents = true })
        vm:write_file(path .. "/inner/f", "f")
        vm:write_file(path .. "/a-file", "x")
        local r = kacs.set_sd(vm, path, kacs.deny_all())
        t:assert_eq(r.ret, 0, "the barrier descriptor is set: " .. sys.errname(r.errno))
        barrier_built = path
    end
    return barrier_built
end

test("a stratum the caller cannot resolve gives EACCES, not an oracle",
    { spec = "PKM *mount.admission-evaluation-order" }, function(t)
        -- The point of the ordering is that the validity conditions must
        -- not be an oracle: a caller with no right to traverse a
        -- directory should not learn from the errno whether it exists
        -- and whether it is a directory. For a single stratum that
        -- holds — the walk runs under the caller's credentials and its
        -- EACCES is propagated unchanged.
        local shut = barrier(t)
        kacs.as_dacl_bound(t, vm, function(worker)
            -- The control first: this caller can mount, so an EACCES
            -- below is about the stratum and not about the mounting.
            local ok = mount_as(worker, base.root .. "/oracle-control",
                "strata=" .. A)
            t:assert_eq(ok.ret, 0,
                "the caller can mount a stratum it can reach: " ..
                sys.errname(ok.errno))

            -- Behind the barrier, one errno whatever is there: a
            -- directory, a regular file, or nothing at all.
            local behind = {
                ["a directory"] = "/inner",
                ["a regular file"] = "/a-file",
                ["a name that does not exist"] = "/not-there",
                ["a name below a name that does not exist"] = "/no/such/tree",
            }
            for what, suffix in pairs(behind) do
                local r = mount_as(worker, base.root .. "/oracle" .. #suffix,
                    "strata=" .. shut .. suffix)
                t:assert_neq(r.ret, 0, what .. " behind the barrier is refused")
                t:assert_eq(r.errno, sys.E.ACCES,
                    what .. " is EACCES, disclosing nothing: " ..
                    sys.errname(r.errno))
            end
        end)
    end)

-- PEI-579. The specified ordering is stack-wide: entitlement for every
-- stratum, then the validity conditions. The strata are checked in one
-- loop instead — resolve, stat, type-test, compare — so stratum 0 is
-- fully judged before stratum 1 is resolved, and its errno reaches a
-- caller who was never entitled to name stratum 1. §4.2.3 records this
-- as a defect; the test states the specified behaviour.
test("entitlement is decided for the whole stack before any validity condition",
    { spec = "PKM *mount.admission-evaluation-order",
      tags = { "known-bug" } }, function(t)
        local shut = barrier(t)
        local file = base.root .. "/a-regular-file"
        vm:write_file(file, "x")
        local missing = base.root .. "/definitely-absent"

        kacs.as_dacl_bound(t, vm, function(worker)
            -- A stratum the caller can reach first, one it cannot
            -- second. What comes back must be that the caller was not
            -- entitled to the stack, not what the first stratum is.
            local notdir = mount_as(worker, base.root .. "/order-notdir",
                "strata=" .. file .. ":" .. shut .. "/inner")
            t:assert_eq(notdir.errno, sys.E.ACCES,
                "a regular file above an unreachable stratum is EACCES, not " ..
                sys.errname(notdir.errno))

            local absent = mount_as(worker, base.root .. "/order-absent",
                "strata=" .. missing .. ":" .. shut .. "/inner")
            t:assert_eq(absent.errno, sys.E.ACCES,
                "an absent stratum above an unreachable one is EACCES, not " ..
                sys.errname(absent.errno))
        end)
    end)

test("an empty stratum stack is refused",
    { spec = "PKM *mount.admit.empty-stack-einval" }, function(t)
        refused_with(t, "a stack with no strata",
            { data = "strata=" }, sys.E.INVAL)
    end)

test("a stack of more than sixteen strata is refused",
    { spec = "PKM *mount.admit.too-many-strata-einval" }, function(t)
        local seventeen = {}
        for i = 1, 17 do seventeen[i] = A end
        refused_with(t, "a seventeen-stratum stack",
            { data = "strata=" .. table.concat(seventeen, ":") }, sys.E.INVAL)
    end)

test("two create strata are refused",
    { spec = "PKM *mount.admit.multiple-create-einval" }, function(t)
        refused_with(t, "two strata carrying create",
            { data = "strata=" .. A .. "+create:" .. B .. "+create" }, sys.E.INVAL)
    end)

test("create and ro on one stratum are refused",
    { spec = "PKM *mount.admit.create-with-ro-einval" }, function(t)
        refused_with(t, "create and ro together",
            { data = "strata=" .. A .. "+create+ro" }, sys.E.INVAL)
        refused_with(t, "ro and create together",
            { data = "strata=" .. A .. "+ro+create" }, sys.E.INVAL)
    end)

test("the same directory twice in a stack is refused",
    { spec = "PKM *mount.admit.duplicate-stratum-einval" }, function(t)
        refused_with(t, "the same path twice",
            { data = "strata=" .. A .. ":" .. A }, sys.E.INVAL)
        refused_with(t, "the same path twice with different flags",
            { data = "strata=" .. A .. "+create:" .. A .. "+ro" }, sys.E.INVAL)
        refused_with(t, "the same path twice with another between",
            { data = "strata=" .. A .. ":" .. B .. ":" .. A }, sys.E.INVAL)
    end)

test("a malformed strata value is refused at admission",
    { spec = "PKM *mount.admit.malformed-value-einval" }, function(t)
        -- §4.2.2 enumerates the malformations; this records that they
        -- reach the caller as EINVAL from the mount, like every other
        -- validity condition.
        refused_with(t, "an unknown flag",
            { data = "strata=" .. A .. "+nope" }, sys.E.INVAL)
        refused_with(t, "a relative path",
            { data = "strata=not/absolute" }, sys.E.INVAL)
    end)

test("a stratum path naming something other than a directory is refused",
    { spec = "PKM *mount.admit.not-a-directory-enotdir" }, function(t)
        local file = base.root .. "/a-regular-file"
        vm:write_file(file, "not a directory")
        refused_with(t, "a stratum that is a regular file",
            { data = "strata=" .. file }, sys.E.NOTDIR)
        refused_with(t, "a regular file below a valid stratum",
            { data = "strata=" .. A .. ":" .. file }, sys.E.NOTDIR)

        local link = base.root .. "/link-to-file"
        local r = sys.symlink(vm, file, link)
        t:assert_eq(r.ret, 0, "symlink: " .. sys.errname(r.errno))
        refused_with(t, "a symlink resolving to a regular file",
            { data = "strata=" .. link }, sys.E.NOTDIR)
    end)

test("an absent stratum without am is refused",
    { spec = "PKM *mount.admit.absent-without-am-enoent" }, function(t)
        local missing = base.root .. "/nothing-here"
        refused_with(t, "an absent stratum on its own",
            { data = "strata=" .. missing }, sys.E.NOENT)
        refused_with(t, "an absent stratum below a present one",
            { data = "strata=" .. A .. ":" .. missing }, sys.E.NOENT)
        refused_with(t, "an absent stratum whose parent is absent too",
            { data = "strata=" .. base.root .. "/no/such/tree" }, sys.E.NOENT)
    end)

test("stacking stratafs past the kernel's maximum depth is refused",
    { spec = "PKM *mount.admit.stacking-depth-eloop" }, function(t)
        -- Each mount's stack depth is one more than the deepest of its
        -- strata, and FILESYSTEM_MAX_STACK_DEPTH is 2. So stratafs
        -- over an ordinary filesystem, and stratafs over that, are
        -- both fine; a third is not.
        local root = base.root .. "/depth"
        stratafs.populate(vm, root .. "/ground", { g = "g" })
        local one, two = root .. "/one", root .. "/two"
        stratafs.mount(vm, { at = one, strata = { { path = root .. "/ground" } } })
        local ok, err = pcall(function()
            t:assert_eq(vm:read_file(one .. "/g"), "g", "one deep works")
            stratafs.mount(vm, { at = two, strata = { { path = one } } })
            t:assert_eq(vm:read_file(two .. "/g"), "g", "two deep works")
            refused_with(t, "a third stratafs on top",
                { data = "strata=" .. two }, sys.E.LOOP)
        end)
        stratafs.umount(vm, two)
        stratafs.umount(vm, one)
        if not ok then error(err, 0) end
    end)

test("a stratum inside the mount point is refused",
    { spec = "PKM *mount.admit.recursive-stratum-eloop" }, function(t)
        local at = base.root .. "/recursive"
        stratafs.populate(vm, at .. "/inside", { f = "f" })
        refused_with(t, "a stratum below the mount point",
            { at = at, data = "strata=" .. at .. "/inside" }, sys.E.LOOP)
        refused_with(t, "the mount point itself as a stratum",
            { at = at, data = "strata=" .. at }, sys.E.LOOP)
        refused_with(t, "a stratum below the mount point beside a valid one",
            { at = at, data = "strata=" .. A .. ":" .. at .. "/inside" }, sys.E.LOOP)
    end)

test("a loop through another stratafs mount is refused",
    { spec = "PKM *mount.loop-detected-at-mount" }, function(t)
        -- The indirect case: this mount's stratum lies inside another
        -- stratafs mount, whose own strata include this mount point.
        -- Detected by recursing into any stratum whose superblock
        -- carries the stratafs magic.
        local root = base.root .. "/indirect"
        stratafs.populate(vm, root .. "/ground", { g = "g" })
        local outer, inner = root .. "/outer", root .. "/inner"
        vm:mkdir(inner, { parents = true })

        -- `outer` is a stratafs mount that has `inner` — where the
        -- second mount is going — among its strata.
        stratafs.mount(vm, { at = outer, strata = {
            { path = root .. "/ground" }, { path = inner },
        } })
        local ok, err = pcall(function()
            refused_with(t, "a stratum inside a mount whose strata include this " ..
                "mount point", { at = inner, data = "strata=" .. outer }, sys.E.LOOP)
        end)
        stratafs.umount(vm, outer)
        if not ok then error(err, 0) end
    end)

test("mount cookie exhaustion",
    { spec = "PKM *mount.admit.cookie-exhaustion-eagain",
      skip = "needs sixteen consecutive collisions of a random u64 in the " ..
             "live-mount table; not provokable from userspace, and not " ..
             "observable without a way to steer get_random_u64" },
    function(t) t:fail("unreachable") end)

test("two strata are the same when they resolve to one directory",
    { spec = "PKM *mount.duplicate-strata-by-inode" }, function(t)
        -- The comparison is on resolved inodes, not on path strings.
        local root = base.root .. "/by-inode"
        stratafs.populate(vm, root .. "/real", { f = "f" })
        local real = root .. "/real"

        local via_link = root .. "/via-link"
        local r = sys.symlink(vm, real, via_link)
        t:assert_eq(r.ret, 0, "symlink: " .. sys.errname(r.errno))
        refused_with(t, "one directory reached through a symlink and directly",
            { data = "strata=" .. real .. ":" .. via_link }, sys.E.INVAL)

        local via_bind = root .. "/via-bind"
        vm:mkdir(via_bind, { parents = true })
        local m = sys.mount(vm, { source = real, target = via_bind, flags = sys.MS_BIND })
        t:assert_eq(m.ret, 0, "bind mount: " .. sys.errname(m.errno))
        local ok, err = pcall(function()
            refused_with(t, "one directory reached through a bind mount and directly",
                { data = "strata=" .. real .. ":" .. via_bind }, sys.E.INVAL)
        end)
        sys.umount(vm, via_bind)
        if not ok then error(err, 0) end

        -- Absent strata are skipped and never compared, so the same
        -- absent path twice is not a duplicate.
        local missing = root .. "/absent"
        local rr, at = admit({ data = "strata=" .. real ..
            ":" .. missing .. "+am:" .. missing .. "+am" })
        t:assert_eq(rr.ret, 0,
            "the same absent path twice is legal: " .. sys.errname(rr.errno))
        if rr.ret == 0 then stratafs.umount(vm, at) end
    end)

test("option-string conditions are decided before any path is touched",
    { spec = "PKM *mount.admission-evaluation-order" }, function(t)
        -- The validity conditions that depend on nothing but the
        -- option string are reported whatever the paths are, so they
        -- cannot be used as an oracle for what exists.
        local missing = base.root .. "/definitely-absent"
        local file = base.root .. "/a-regular-file"
        vm:write_file(file, "x")

        refused_with(t, "two create strata that are both absent",
            { data = "strata=" .. missing .. "+create:" ..
                     missing .. "2+create" }, sys.E.INVAL)
        refused_with(t, "an unknown flag on an absent path",
            { data = "strata=" .. missing .. "+nope" }, sys.E.INVAL)
        refused_with(t, "create and ro on a path that is a regular file",
            { data = "strata=" .. file .. "+create+ro" }, sys.E.INVAL)
        refused_with(t, "seventeen absent strata",
            { data = "strata=" .. string.rep(missing .. ":", 16) .. missing },
            sys.E.INVAL)

        -- The strata themselves are then judged one at a time, in
        -- order: stratum 0 is resolved, stat'd and type-tested before
        -- stratum 1 is resolved at all.
        refused_with(t, "a regular file at index 0 above an absent stratum",
            { data = "strata=" .. file .. ":" .. missing }, sys.E.NOTDIR)
        refused_with(t, "an absent stratum at index 0 above a regular file",
            { data = "strata=" .. missing .. ":" .. file }, sys.E.NOENT)
    end)

test("two mounts may share a stratum and neither knows of the other",
    { spec = "PKM *mount.strata-shared-between-mounts" }, function(t)
        local root = base.root .. "/shared"
        stratafs.populate(vm, root .. "/common", { start = "s" })
        stratafs.populate(vm, root .. "/private", { p = "p" })
        local one, two = root .. "/one", root .. "/two"

        stratafs.mount(vm, { at = one, strata = {
            { path = root .. "/common", flags = { "create" } },
        } })
        stratafs.mount(vm, { at = two, strata = {
            { path = root .. "/private" },
            { path = root .. "/common", flags = { "create" } },
        } })
        local ok, err = pcall(function()
            t:assert_eq(vm:read_file(one .. "/start"), "s", "both mount")
            t:assert_eq(vm:read_file(two .. "/start"), "s", "over the same stratum")

            -- Where two mounts share a create stratum they mutate the
            -- same objects, with the same result as any two writers of
            -- one directory.
            t:assert(stratafs.try_create(vm, one .. "/from-one", "1"),
                "a creation through the first mount succeeds")
            t:assert_eq(vm:read_file(two .. "/from-one"), "1",
                "and is visible through the second, with no coordination")
            t:assert(stratafs.try_create(vm, two .. "/from-two", "2"),
                "and the other way round")
            t:assert_eq(vm:read_file(one .. "/from-two"), "2",
                "likewise")

            -- Each resolves independently: the second mount's own
            -- stratum is its own business.
            t:assert_eq(vm:read_file(two .. "/p"), "p",
                "the second mount's private stratum is only its own")
            t:assert(sys.stat(vm, one .. "/p") == nil,
                "and invisible to the first")
        end)
        stratafs.umount(vm, two)
        stratafs.umount(vm, one)
        if not ok then error(err, 0) end
    end)

test("a stack whose strata are all absent is legal",
    { spec = "PKM *mount.all-absent-stack-is-legal" }, function(t)
        local root = base.root .. "/all-absent"
        vm:mkdir(root, { parents = true })
        local r, at = admit({ data = "strata=" .. root .. "/one+am:" ..
                                      root .. "/two+am" })
        t:assert_eq(r.ret, 0,
            "the mount succeeds with no stratum root present: " ..
            sys.errname(r.errno))

        local ok, err = pcall(function()
            -- The superblock is real even with nothing under it.
            local fs = sys.statfs(vm, at)
            t:assert(fs, "the mount answers statfs")
            t:assert_eq(fs.type, 0x53545241, "as a stratafs")

            -- And a stratum root appearing is picked up with no
            -- remount, exactly as §4.2.4 requires of any stratum.
            vm:mkdir(root .. "/one", { parents = true })
            vm:write_file(root .. "/one/appeared", "a")
            t:assert_eq(vm:read_file(at .. "/appeared"), "a",
                "a stratum root appearing brings the mount to life")
        end)
        stratafs.umount(vm, at)
        if not ok then error(err, 0) end
    end)

-- PEI-575. Until some stratum root has existed, every access to the
-- root of an all-absent mount fails ENOENT, so the provider-less
-- attributes §4.2.3 specifies cannot be observed. The branch that
-- produces them is real: once a stratum root has appeared and gone
-- again, the same stat returns mode 040000 as written here.
test("the root of an all-absent stack is a directory with no permission bits",
    { spec = "PKM *mount.all-absent-stack-is-legal",
      tags = { "known-bug" } }, function(t)
        local root = base.root .. "/all-absent-root"
        vm:mkdir(root, { parents = true })
        local r, at = admit({ data = "strata=" .. root .. "/one+am" })
        t:assert_eq(r.ret, 0, "the mount succeeds: " .. sys.errname(r.errno))

        local ok, err = pcall(function()
            local st, errno = sys.stat(vm, at)
            t:assert(st, "the root stats: " .. sys.errname(errno or 0))
            t:assert(st.is_dir, "and is a directory")
            t:assert_eq(st.perm, 0, "with no permission bits")

            local entries = vm:listdir(at)
            t:assert_eq(#entries, 0, "and no entries")
        end)
        stratafs.umount(vm, at)
        if not ok then error(err, 0) end
    end)
