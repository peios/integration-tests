-- Mounting a prebuilt filesystem image inside the guest.
--
-- Some provider behaviour cannot be produced by any filesystem the VM
-- can create for itself — a directory entry with no type, an object
-- with no Peios security descriptor — so those cases bring an image
-- with them. See tests/fixtures/README.md.
--
-- Two wrinkles. The kernel-only edition has no virtio-blk, so the
-- image is pushed into the guest and attached to a loop device rather
-- than given to `vm:attach_disk`. And a filesystem mounted at runtime
-- lands in the deny-missing policy class and is unusable, so it is
-- created through the new mount API and given a class in the one
-- moment it can be named by a descriptor (helpers/kacs).

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")

local M = {}

local LOOP_CTL_GET_FREE = 0x4C82
local LOOP_SET_FD = 0x4C00
local LOOP_CLR_FD = 0x4C01

--- Attach `guest_image` to a free loop device. Returns the device
--- path and its open fd, or `nil, stage, errno`.
function M.loop_attach(vm, guest_image)
    local ctl = sys.open(vm, "/dev/loop-control", sys.O.RDWR)
    if not ctl then return nil, "open loop-control", 0 end
    local free = vm:syscall(sys.NR.ioctl, ctl, LOOP_CTL_GET_FREE, 0)
    sys.close(vm, ctl)
    if free.ret < 0 then return nil, "LOOP_CTL_GET_FREE", free.errno end

    local node = "/dev/loop" .. free.ret
    local loopfd, lerr = sys.open(vm, node, sys.O.RDWR)
    if not loopfd then return nil, "open " .. node, lerr end
    local imgfd, ierr = sys.open(vm, guest_image, sys.O.RDWR)
    if not imgfd then
        sys.close(vm, loopfd)
        return nil, "open image", ierr
    end
    local set = vm:syscall(sys.NR.ioctl, loopfd, LOOP_SET_FD, imgfd)
    sys.close(vm, imgfd)
    if set.ret ~= 0 then
        sys.close(vm, loopfd)
        return nil, "LOOP_SET_FD", set.errno
    end
    return node, loopfd
end

--- Push an image into the guest, loop-mount it at `at`, and return a
--- release function. Raises with a useful message on failure.
---
--- `host_image` is resolved against the calling test file's directory,
--- as `vm:push_file` does — so a test in tests/stratafs/ names it
--- `"../fixtures/…"`.
function M.mount(t, vm, opts)
    local scratch = opts.scratch or "/stratafs/images"
    local guest_image = scratch .. "/" .. (opts.name or "image") .. ".img"
    vm:mkdir(scratch, { parents = true })
    vm:push_file(opts.host_image, guest_image)

    local node, loopfd_or_stage, errno = M.loop_attach(vm, guest_image)
    t:assert(node, "the image attaches to a loop device: " ..
        tostring(loopfd_or_stage) .. " " .. sys.errname(errno or 0))
    local loopfd = loopfd_or_stage

    local fs = vm:syscall(kacs.NR.fsopen, {
        args = { 0, 0 }, bufs = { sys.cstr(opts.fstype) }, ptrs = { 0 },
    })
    t:assert(fs.ret >= 0, "fsopen " .. opts.fstype .. ": " ..
        sys.errname(fs.errno))
    local src = vm:syscall(kacs.NR.fsconfig, {
        args = { fs.ret, kacs.FSCONFIG_SET_STRING, 0, 0, 0 },
        bufs = { sys.cstr("source"), sys.cstr(node) }, ptrs = { 2, 3 },
    })
    t:assert_eq(src.ret, 0, "naming the loop device as its source: " ..
        sys.errname(src.errno))
    local created = vm:syscall(kacs.NR.fsconfig, fs.ret,
        kacs.FSCONFIG_CMD_CREATE, 0, 0, 0)
    t:assert_eq(created.ret, 0, "the filesystem is created: " ..
        sys.errname(created.errno))

    local mount = vm:syscall(kacs.NR.fsmount, fs.ret, 0, 0)
    t:assert(mount.ret >= 0, "fsmount: " .. sys.errname(mount.errno))
    if opts.policy then
        local set = kacs.set_mount_policy(vm, mount.ret, opts.policy)
        t:assert_eq(set.ret, 0, "its policy class is set: " ..
            sys.errname(set.errno))
    end

    sys.mkdir_p(vm, opts.at)
    local moved = vm:syscall(kacs.NR.move_mount, {
        args = { mount.ret, 0, sys.AT_FDCWD, 0, kacs.MOVE_MOUNT_F_EMPTY_PATH },
        bufs = { sys.cstr(""), sys.cstr(opts.at) }, ptrs = { 1, 3 },
    })
    sys.close(vm, mount.ret)
    sys.close(vm, fs.ret)
    t:assert_eq(moved.ret, 0, "and it is attached at " .. opts.at .. ": " ..
        sys.errname(moved.errno))

    return function()
        sys.umount(vm, opts.at)
        vm:syscall(sys.NR.ioctl, loopfd, LOOP_CLR_FD, 0)
        sys.close(vm, loopfd)
    end
end

return M
