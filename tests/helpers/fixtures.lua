-- What the kernel-only profile's fixture initramfs carries under
-- /fixtures, and how a test gets it into play: a kernel module loaded,
-- an image attached to a loop device, a signed firmware blob sitting
-- where the loader will look for it. profiles/kernel-only/build.sh
-- describes the archive itself.
--
-- Every function takes the vm (or a worker) as its first argument; the
-- agent is SYSTEM with every privilege, which is what loading a module
-- or writing a module parameter needs.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")

local M = {}

M.DIR = "/fixtures"
M.MODULES = M.DIR .. "/modules"
M.FIRMWARE = M.DIR .. "/firmware"
M.NTFS_IMAGE = M.DIR .. "/ntfs.img"

M.NR = { finit_module = 313, delete_module = 176 }
-- finit_module(2) flags: the file is compressed as the kernel's
-- CONFIG_MODULE_COMPRESS made it, and the kernel decompresses it.
M.MODULE_INIT_COMPRESSED_FILE = 4

-- Loop device ioctls.
M.LOOP = { SET_FD = 0x4C00, CLR_FD = 0x4C01, CTL_GET_FREE = 0x4C82 }

--- Is `path` in the guest? A fixture build.sh left out (no signing
--- key, no mkntfs on the build host) is simply absent.
function M.present(vm, path)
    return pcall(function() return vm:stat(path) end)
end

--- The reason a firmware fixture is unusable on this build, or nil.
function M.firmware_unavailable(vm)
    if not M.present(vm, M.FIRMWARE .. "/signed.bin") then
        return "the profile was built without firmware fixtures"
    end
    if M.present(vm, M.FIRMWARE .. "/UNSIGNED") then
        return "the profile was built without a TCB signing key, so no firmware fixture is signed"
    end
    return nil
end

-- Modules ----------------------------------------------------------------------

--- Load `name` (`test_firmware`, `ntfs3`) from the fixture modules.
--- Already loaded is success. Returns true, or nil, errno.
function M.load_module(vm, name)
    local path = M.MODULES .. "/" .. name .. ".ko.zst"
    local fd, e = sys.open(vm, path, sys.O.RDONLY)
    if not fd then return nil, e end
    local r = vm:syscall(M.NR.finit_module, {
        args = { fd, 0, M.MODULE_INIT_COMPRESSED_FILE },
        bufs = { sys.cstr("") }, ptrs = { 1 },
    })
    sys.close(vm, fd)
    if r.ret ~= 0 and r.errno ~= sys.E.EXIST then return nil, r.errno end
    return true
end

--- Is a module of this name loaded? (`/sys/module/<name>` exists.)
function M.module_loaded(vm, name)
    return M.present(vm, "/sys/module/" .. name)
end

-- Loop devices -------------------------------------------------------------------

--- Attach `image` to a free loop device. Returns the device path and
--- the loop fd (keep it open for the life of the attachment; the
--- kernel tears the device down once the last reference goes), or
--- nil, stage, errno.
function M.loop_attach(vm, image)
    local ctl, e = sys.open(vm, "/dev/loop-control", sys.O.RDWR)
    if not ctl then return nil, "open /dev/loop-control", e end
    local n = vm:syscall(sys.NR.ioctl, ctl, M.LOOP.CTL_GET_FREE, 0)
    sys.close(vm, ctl)
    if n.ret < 0 then return nil, "LOOP_CTL_GET_FREE", n.errno end
    local dev = "/dev/loop" .. n.ret
    -- devtmpfs creates the node asynchronously; give it a moment.
    local loopfd, e2
    for _ = 1, 50 do
        loopfd, e2 = sys.open(vm, dev, sys.O.RDWR)
        if loopfd then break end
        sys.nanosleep(vm, 0, 20000000)
    end
    if not loopfd then return nil, "open " .. dev, e2 end
    local img, e3 = sys.open(vm, image, sys.O.RDWR)
    if not img then sys.close(vm, loopfd); return nil, "open " .. image, e3 end
    local set = vm:syscall(sys.NR.ioctl, loopfd, M.LOOP.SET_FD, img)
    sys.close(vm, img)
    if set.ret ~= 0 then sys.close(vm, loopfd); return nil, "LOOP_SET_FD", set.errno end
    return dev, loopfd
end

--- Detach: LOOP_CLR_FD and close.
function M.loop_detach(vm, loopfd)
    vm:syscall(sys.NR.ioctl, loopfd, M.LOOP.CLR_FD, 0)
    sys.close(vm, loopfd)
end

-- Firmware ------------------------------------------------------------------------

M.FW_PATH_PARAM = "/sys/module/firmware_class/parameters/path"
M.TEST_FW = "/sys/devices/virtual/misc/test_firmware"
M.SIG_XATTR = "security.peios.sig"

--- Stand up a firmware directory the loader will search: a fresh
--- tmpfs at `at` under a synthesising policy (so files created on it
--- carry descriptors and xattrs stick), each fixture blob copied in,
--- and each blob that has a sidecar stamped with it as
--- `security.peios.sig` — the way peipkg stamps a package's firmware
--- at install. Then the loader's search path is pointed at it.
---
--- Returns true, or nil, message.
function M.firmware_dir(vm, at)
    local ok, stage, errno = kacs.new_mount(vm, "tmpfs", at,
        kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL)
    if not ok then return nil, "tmpfs at " .. at .. ": " .. stage .. ": " .. sys.errname(errno or 0) end
    for _, entry in ipairs(vm:listdir(M.FIRMWARE)) do
        local name = entry.name
        if not name:find("%.peios%.sig$") and name ~= "UNSIGNED" then
            vm:write_file(at .. "/" .. name, vm:read_file(M.FIRMWARE .. "/" .. name))
            if M.present(vm, M.FIRMWARE .. "/" .. name .. ".peios.sig") then
                local r = sys.setxattr(vm, at .. "/" .. name, M.SIG_XATTR,
                    vm:read_file(M.FIRMWARE .. "/" .. name .. ".peios.sig"), 0)
                if r.ret ~= 0 then
                    return nil, "setxattr " .. M.SIG_XATTR .. " on " .. name .. ": " .. sys.errname(r.errno)
                end
            end
        end
    end
    vm:write_file(M.FW_PATH_PARAM, at)
    return true
end

--- Stamp `sidecar`'s bytes onto `path` as its signature (for the
--- cases that want a signature other than the blob's own).
function M.stamp_signature(vm, path, sidecar)
    return sys.setxattr(vm, path, M.SIG_XATTR, vm:read_file(sidecar), 0)
end

--- Ask the loader's self-test device for `name`. Returns true when the
--- load succeeded, or nil, errno — request_firmware()'s failure comes
--- back as the write's.
function M.request_firmware(vm, name)
    local fd, e = sys.open(vm, M.TEST_FW .. "/trigger_request", sys.O.WRONLY)
    if not fd then return nil, e end
    local r = sys.write(vm, fd, name)
    sys.close(vm, fd)
    if r.ret < 0 then return nil, r.errno end
    return true
end

--- Set one of test_firmware's `config_*` knobs.
function M.test_fw_config(vm, knob, value)
    local fd, e = sys.open(vm, M.TEST_FW .. "/" .. knob, sys.O.WRONLY)
    if not fd then return nil, e end
    local r = sys.write(vm, fd, tostring(value))
    sys.close(vm, fd)
    if r.ret < 0 then return nil, r.errno end
    return true
end

--- Read one of test_firmware's attributes.
function M.test_fw_read(vm, attr)
    local fd, e = sys.open(vm, M.TEST_FW .. "/" .. attr, sys.O.RDONLY)
    if not fd then return nil, e end
    local data, e2 = sys.read(vm, fd, 65536)
    sys.close(vm, fd)
    return data, e2
end

return M
