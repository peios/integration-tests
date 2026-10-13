-- PEI-264: a persistent provider's inode cache must be reclaimable while
-- the StrataFS view stays mounted. tmpfs would be an invalid oracle here:
-- its linked files necessarily retain in-memory inodes even without a view.
local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local fx = require("helpers.fixtures")
local stratafs = require("helpers.stratafs")
local vm = provium:vm("v", "kernel-only"):boot()

local function ext4_inodes()
    local slab = vm:read_file("/proc/slabinfo")
    local count = slab:match("\next4_inode_cache%s+(%d+)")
    assert(count, "ext4_inode_cache must be observable in /proc/slabinfo")
    return tonumber(count)
end

local function drop_caches(t)
    t:assert_eq(vm:syscall(162).ret, 0, "sync completes")
    vm:write_file("/proc/sys/vm/drop_caches", "3\n")
    -- Inodes are freed through RCU; allow a grace period before observing.
    sys.nanosleep(vm, 0, 100000000)
end

test("walking a view does not pin every provider inode until unmount",
    { spec = "PKM *inode.provider-reclaim-with-live-mount" }, function(t)
        if not fx.present(vm, "/fixtures/ext4.img") then
            t:skip("the profile was built without mkfs.ext4; no reclaim fixture")
            return
        end
        local device, loopfd, errno = fx.loop_attach(vm, "/fixtures/ext4.img")
        t:assert(device, "attach ext4 fixture: " .. tostring(loopfd) ..
            " " .. sys.errname(errno or 0))
        local backing, view = "/reclaim-provider", "/reclaim-view"
        local mounted, stage, mount_errno = kacs.new_mount(vm, "ext4", backing,
            kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL, { source = device })
        if not mounted then
            fx.loop_detach(vm, loopfd)
            error("mount ext4: " .. tostring(stage) .. " " ..
                sys.errname(mount_errno or 0))
        end
        local view_mounted = false
        local ok, err = pcall(function()
            local files = 1024
            -- StrataFS requires stored provider descriptors; it never asks
            -- an underlying mount to synthesize a missing one. The host-made
            -- ext4 root has none, even though direct access may synthesize it.
            local sd = kacs.grant(kacs.ALL_RIGHTS)
            t:assert_eq(kacs.set_sd(vm, backing, sd).ret, 0,
                "the provider root has a stored descriptor")
            for i = 1, files do
                local path = backing .. "/f" .. i
                vm:write_file(path, "x")
                t:assert_eq(kacs.set_sd(vm, path, sd).ret, 0,
                    "provider file " .. i .. " has a stored descriptor")
            end
            local before = ext4_inodes()
            for _ = 1, 20 do
                drop_caches(t)
                before = ext4_inodes()
                if before <= files // 4 then break end
            end
            t:assert(before <= files // 4,
                "control: direct ext4 access is reclaimable before mounting the view")
            stratafs.mount(vm, { at = view, strata = { backing } })
            view_mounted = true
            local identities = {}
            for i = 1, files do
                local st, stat_errno = sys.stat(vm, view .. "/f" .. i)
                t:assert(st, "file " .. i .. " resolves: " .. sys.errname(stat_errno or 0))
                identities[i] = st.ino
            end
            local after = ext4_inodes()
            for _ = 1, 20 do
                drop_caches(t)
                after = ext4_inodes()
                if after <= before + files // 4 then break end
            end
            -- A little slab/RCU slack is intentional. The old map retains
            -- all 1024 providers, well beyond this bound, until unmount.
            t:assert(after <= before + files // 4,
                "provider inodes reclaimed with view mounted: before=" ..
                before .. " after=" .. after .. " walked=" .. files)
            for _, i in ipairs({ 1, 257, 513, 1024 }) do
                t:assert_eq(sys.stat(vm, view .. "/f" .. i).ino, identities[i],
                    "reloading an evicted provider preserves its identity")
            end
        end)
        if view_mounted then stratafs.umount(vm, view) end
        sys.umount(vm, backing)
        fx.loop_detach(vm, loopfd)
        if not ok then error(err, 0) end
    end)
