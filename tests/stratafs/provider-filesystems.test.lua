-- Cases whose subject is something a provider's own filesystem does,
-- which nothing the VM can create for itself exhibits.
--
-- Both use a prebuilt ext2 image (tests/fixtures/README.md): it has no
-- `filetype` feature, so its directory entries carry no type, and it
-- was built outside Peios, so its objects carry no security
-- descriptors.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local image = require("helpers.image")
local stratafs = require("helpers.stratafs")

local vm = provium:vm("v", "kernel-only"):boot()

local IMAGE = "../fixtures/ext2-nofiletype.img"

test("a participant reporting DT_UNKNOWN has it propagated unchanged",
    { spec = "PKM *enumerate.dt-unknown-propagated" }, function(t)
        -- Even though the child path is in hand and the real type could
        -- be derived, what the participant said is what is reported.
        local root = "/stratafs/dt-unknown"
        local mounted = root .. "/image"
        local release = image.mount(t, vm, {
            name = "dt-unknown", host_image = IMAGE, fstype = "ext2",
            at = mounted, policy = kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL,
        })

        local ok, err = pcall(function()
            -- The provider says DT_UNKNOWN for everything, directly.
            local direct = sys.open(vm, mounted .. "/stratum",
                sys.O.RDONLY | sys.O.DIRECTORY)
            t:assert(direct, "the image's directory opens directly")
            for _, e in ipairs(sys.getdents_all(vm, direct)) do
                t:assert_eq(e.type, sys.DT.UNKNOWN,
                    "`" .. e.name .. "` is DT_UNKNOWN on the provider itself")
            end
            sys.close(vm, direct)

            -- Give the image's directory a real descriptor. Its objects
            -- carry none — it was built outside Peios — and stratafs's
            -- merged-directory check turns that straight into EACCES
            -- (§4.6.4) rather than asking the provider to synthesise,
            -- so without this the participant cannot be enumerated at
            -- all. The directory entries' missing *type* is untouched
            -- by giving them an xattr, which is the point here.
            for _, path in ipairs({ "", "/sub", "/from_image", "/another",
                                    "/sub/nested" }) do
                local marked = kacs.set_sd(vm,
                    mounted .. "/stratum" .. path, kacs.grant(kacs.ALL_RIGHTS))
                t:assert_eq(marked.ret, 0, "`stratum" .. path ..
                    "` is given a descriptor: " .. sys.errname(marked.errno))
            end

            -- Merge it with an ordinary stratum that does report types.
            local tmp = root .. "/tmpfs-stratum"
            stratafs.populate(vm, tmp, { from_tmpfs = "t", subdir = stratafs.DIR })
            local at = root .. "/mnt"
            local r = stratafs.try_mount(vm, { at = at, strata = {
                { path = tmp, flags = { "create" } },
                { path = mounted .. "/stratum" },
            } })
            t:assert_eq(r.ret, 0, "the two mount together: " ..
                sys.errname(r.errno))

            local fd = sys.open(vm, at, sys.O.RDONLY | sys.O.DIRECTORY)
            t:assert(fd, "the merged directory opens")
            local seen = {}
            for _, e in ipairs(sys.getdents_all(vm, fd)) do seen[e.name] = e.type end
            sys.close(vm, fd)
            stratafs.umount(vm, at)

            -- What each participant said, unchanged, side by side in
            -- one listing.
            t:assert_eq(seen.from_tmpfs, sys.DT.REG,
                "the tmpfs participant's file keeps its real type")
            t:assert_eq(seen.subdir, sys.DT.DIR,
                "and its directory likewise")
            t:assert_eq(seen.from_image, sys.DT.UNKNOWN,
                "while the ext2 participant's file stays DT_UNKNOWN")
            t:assert_eq(seen.sub, sys.DT.UNKNOWN,
                "including a directory, whose type stratafs could have " ..
                "derived from the lookup it does anyway")

            -- The type was passed through rather than being unknown to
            -- stratafs: it looked the child up anyway, to get the inode
            -- number the entry carries.
            t:assert(seen.from_image ~= nil and seen.sub ~= nil,
                "both ext2 entries are listed, inode numbers and all")
        end)
        release()
        if not ok then error(err, 0) end
    end)

test("an object with no readable descriptor is denied under the mount's policy",
    { spec = "PKM *security.missing-descriptor-denied" }, function(t)
        -- The image's objects carry no descriptors at all: it was built
        -- outside Peios. Mounted while its filesystem still synthesises,
        -- the stratafs mount is admitted; once it stops, a read of a
        -- descriptor finds nothing and the stratafs superblock's own
        -- deny-missing class decides — the provider's policy is not
        -- consulted.
        local root = "/stratafs/no-descriptor"
        local mounted = root .. "/image"
        local release = image.mount(t, vm, {
            name = "no-descriptor", host_image = IMAGE, fstype = "ext2",
            at = mounted, policy = kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL,
        })

        local ok, err = pcall(function()
            -- The participant directory gets a descriptor, so the
            -- merged-directory check has something to evaluate and the
            -- mount is usable at all. Its files deliberately do not:
            -- an object with no descriptor is the whole subject here.
            local marked = kacs.set_sd(vm, mounted .. "/stratum",
                kacs.grant(kacs.ALL_RIGHTS))
            t:assert_eq(marked.ret, 0,
                "the participant directory is given a descriptor: " ..
                sys.errname(marked.errno))

            local tmp = root .. "/create"
            stratafs.populate(vm, tmp, {})
            local at = root .. "/mnt"
            local r = stratafs.try_mount(vm, { at = at, strata = {
                { path = tmp, flags = { "create" } },
                { path = mounted .. "/stratum" },
            } })
            t:assert_eq(r.ret, 0,
                "the mount is admitted while the provider synthesises: " ..
                sys.errname(r.errno))

            -- The control, on a different file: while the provider
            -- still answers for descriptors, an object of the image is
            -- reachable through the mount. A different file, so nothing
            -- is cached against the inode the case below tests.
            local before = sys.open(vm, at .. "/another", sys.O.RDONLY)
            t:assert(before,
                "an object of the image is reachable while it synthesises")
            sys.close(vm, before)

            -- Stop it synthesising. Nothing has touched the file
            -- through the mount, so no descriptor has been cached
            -- against its outer inode.
            local fd = sys.open(vm, mounted, sys.O.RDONLY | sys.O.DIRECTORY)
            t:assert(fd, "the provider mount opens")
            local set = kacs.set_mount_policy(vm, fd,
                kacs.MOUNT_POLICY.DENY_MISSING)
            sys.close(vm, fd)
            t:assert_eq(set.ret, 0, "and stops synthesising: " ..
                sys.errname(set.errno))

            local opened, e = sys.open(vm, at .. "/from_image", sys.O.RDONLY)
            if opened then sys.close(vm, opened) end
            t:assert(opened == nil,
                "the object is not reachable through the stratafs mount")
            t:assert_eq(e, sys.E.ACCES,
                "denied where a descriptor is absent: " .. sys.errname(e))

            stratafs.umount(vm, at)
        end)
        release()
        if not ok then error(err, 0) end
    end)
