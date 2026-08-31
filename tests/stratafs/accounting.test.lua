-- PKM §4.5.2 and §4.5.8 — where the storage a copy-up consumes is
-- charged.
--
-- Disk quota keys on the POSIX owner, and copy-up preserves it, so a
-- copy is accounted to the owner of the object it was copied from and
-- not to the caller who caused it. That is what makes §4.6.2's
-- exemption sound: a caller who may write a file in a stratum that will
-- not accept modification can cause an entry to appear in the create
-- stratum without holding rights over it, gaining neither access nor
-- space.
--
-- The create stratum has to be on a filesystem that accounts, so these
-- build one: a tmpfs with usrquota, in a synthesising policy class so
-- it is usable at all (a runtime mount is otherwise refused everything
-- under deny-missing).

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local stratafs = require("helpers.stratafs")

local vm = provium:vm("v", "kernel-only"):boot()

local SOURCE_OWNER, SOURCE_GROUP = 4242, 4243
local PAYLOAD = 512 * 1024

--- A create stratum on a quota-accounting filesystem, a `ro` source
--- stratum holding a large file owned by somebody else, and the mount
--- over both. Returns the scenario plus an fd on the quota filesystem.
local function accounting_fixture(t, name)
    local root = "/stratafs/" .. name
    local store = root .. "/quota-store"
    local ok, stage, errno = kacs.new_mount(vm, "tmpfs", store,
        kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL, { flags = { "usrquota" } })
    t:assert(ok, "a quota-accounting filesystem is created: " ..
        tostring(stage) .. " " .. sys.errname(errno or 0))

    local quota_fd = sys.open(vm, store, sys.O.RDONLY | sys.O.DIRECTORY)
    t:assert(quota_fd, "and opens")
    t:assert(sys.getquota(vm, quota_fd, 0),
        "and answers quotactl, so it is accounting")

    local dest = store .. "/dest"
    local src = root .. "/src"
    vm:mkdir(dest, { parents = true })
    stratafs.populate(vm, src, {})

    -- A large file in the source, owned by somebody other than the
    -- caller who will provoke the copy.
    local fd = sys.open(vm, src .. "/big",
        sys.O.WRONLY | sys.O.CREAT | sys.O.TRUNC, tonumber("666", 8))
    t:assert(fd, "the source file is created")
    local chunk = string.rep("x", 64 * 1024)
    for _ = 1, PAYLOAD // #chunk do sys.write(vm, fd, chunk) end
    sys.close(vm, fd)
    t:assert_eq(sys.chown(vm, src .. "/big", SOURCE_OWNER, SOURCE_GROUP).ret, 0,
        "and given an owner other than the caller's")

    local at = root .. "/mnt"
    local strata = {
        { path = dest, flags = { "create" } },
        { path = src, flags = { "ro" } },
    }
    local mounted = stratafs.try_mount(vm, { at = at, strata = strata })
    t:assert_eq(mounted.ret, 0, "the mount is admitted: " ..
        sys.errname(mounted.errno))

    return { root = root, store = store, dest = dest, src = src, at = at,
             quota_fd = quota_fd }, function()
        stratafs.umount(vm, at)
        sys.close(vm, quota_fd)
        sys.umount(vm, store)
    end
end

test("a copy is accounted to the owner it preserved",
    { spec = "PKM *copy-up.accounted-to-preserved-owner" }, function(t)
        local f, release = accounting_fixture(t, "accounting-copy-up")
        local ok, err = pcall(function()
            local owner_before = sys.getquota(vm, f.quota_fd, SOURCE_OWNER)
            local caller_before = sys.getquota(vm, f.quota_fd, 0)
            t:assert(owner_before and caller_before, "both quotas read")
            t:assert_eq(owner_before.curspace, 0,
                "the source's owner has consumed nothing on this filesystem")

            -- The caller is root, and is not the source's owner.
            t:assert(stratafs.try_write(vm, f.at .. "/big", "modified"),
                "the write copies the file up")
            t:assert_eq(sys.stat(vm, f.dest .. "/big").uid, SOURCE_OWNER,
                "and the copy carries the source's owner")

            local owner_after = sys.getquota(vm, f.quota_fd, SOURCE_OWNER)
            local caller_after = sys.getquota(vm, f.quota_fd, 0)

            t:assert(owner_after.curspace >= PAYLOAD,
                "the copy is charged to the owner it preserved (" ..
                owner_after.curspace .. " bytes)")
            t:assert_eq(owner_after.curinodes - owner_before.curinodes, 1,
                "including the inode")
            t:assert(caller_after.curspace - caller_before.curspace < PAYLOAD,
                "and not to the caller who provoked it (" ..
                (caller_after.curspace - caller_before.curspace) .. " bytes)")
        end)
        release()
        if not ok then error(err, 0) end
    end)

test("a caller who provokes a copy gains neither access nor space",
    { spec = "PKM *durability.copy-up-accounted-to-preserved-owner" },
    function(t)
        -- §4.6.2 permits a caller to cause a copy into a directory they
        -- hold no rights over, on the grounds that they gain nothing by
        -- it. This is the space half of that: the charge lands on the
        -- preserved owner even when the caller is bound by the DACL and
        -- holds nothing on the create stratum.
        local f, release = accounting_fixture(t, "accounting-exemption")
        local ok, err = pcall(function()
            kacs.set_sd(vm, f.src .. "/big", kacs.grant(kacs.ALL_RIGHTS))
            kacs.set_sd(vm, f.dest,
                kacs.grant_all_but(kacs.RIGHT.ADD_FILE
                    | kacs.RIGHT.ADD_SUBDIRECTORY))

            local owner_before = sys.getquota(vm, f.quota_fd, SOURCE_OWNER)
            local caller_before = sys.getquota(vm, f.quota_fd, 0)

            kacs.as_dacl_bound(t, vm, function(worker)
                local fd = sys.open(worker, f.at .. "/big", sys.O.RDWR)
                t:assert(fd, "the caller opens the file for writing")
                t:assert_eq(sys.write(worker, fd, "modified").ret, 8,
                    "and the write succeeds, copying up into a directory " ..
                    "they hold no rights over")
                sys.close(worker, fd)
            end)

            local owner_after = sys.getquota(vm, f.quota_fd, SOURCE_OWNER)
            local caller_after = sys.getquota(vm, f.quota_fd, 0)

            t:assert(owner_after.curspace - owner_before.curspace >= PAYLOAD,
                "the space is charged to the object's owner")
            t:assert(caller_after.curspace - caller_before.curspace < PAYLOAD,
                "and the caller who caused it is charged nothing like it")
            t:assert_eq(sys.stat(vm, f.dest .. "/big").uid, SOURCE_OWNER,
                "which follows from the copy carrying the preserved owner")
        end)
        release()
        if not ok then error(err, 0) end
    end)
