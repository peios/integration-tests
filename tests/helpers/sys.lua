-- Raw Linux syscalls, for a guest with no userspace to run commands in.
--
-- A kernel-only VM has no shell and no coreutils: the agent's own file
-- operations cover most of what a test needs, and everything else is a
-- syscall issued directly. This module is the syscall half — numbers,
-- struct layouts and errno names, in one place so a test reads as the
-- operation it is performing rather than as a calling convention.
--
-- x86_64 numbers and layouts throughout. Another architecture would
-- need its own table; nothing else here would change.

local M = {}

-- Syscall numbers.
M.NR = {
    mount      = 165,
    umount2    = 166,
    newfstatat = 262,
    symlinkat  = 266,
    fchownat   = 260,
    setresgid  = 119,
    setresuid  = 117,
}

-- Flags a test is likely to name.
M.AT_FDCWD            = -100
M.AT_SYMLINK_NOFOLLOW = 0x100
M.MS_RDONLY           = 1
M.MS_BIND             = 4096
M.MS_REMOUNT          = 32

-- Errnos, by the name the TRM uses for them.
M.E = {
    PERM = 1, NOENT = 2, IO = 5, BADF = 9, AGAIN = 11, ACCES = 13,
    EXIST = 17, XDEV = 18, NODEV = 19, NOTDIR = 20, ISDIR = 21,
    INVAL = 22, ROFS = 30, NOTEMPTY = 39, LOOP = 40, STALE = 116,
    NODATA = 61, RANGE = 34, OPNOTSUPP = 95, NOTTY = 25,
}

local NAME_OF = {}
for name, value in pairs(M.E) do NAME_OF[value] = name end

--- The name of an errno, for an assertion message: `ENOTEMPTY (39)`.
function M.errname(errno)
    if errno == 0 then return "success" end
    local name = NAME_OF[errno]
    return name and ("E" .. name .. " (" .. errno .. ")") or ("errno " .. errno)
end

--- A NUL-terminated byte string, as every path argument must be.
function M.cstr(s) return s .. "\0" end

-- struct stat, x86_64. Offsets are fixed by the ABI.
local STAT_SIZE = 144
local STAT = {
    dev = 1, ino = 9, nlink = 17, mode = 25, uid = 29, gid = 33,
    rdev = 41, size = 49,
}

--- stat(2) a path, returning the fields a stratafs test asserts on.
---
--- Returns `nil, errno` on failure, so a caller can assert on either
--- the fields or the refusal without a second call shape.
---
--- `opts.follow` defaults true; false uses AT_SYMLINK_NOFOLLOW, which
--- is how a test tells a symlink from what it points at.
function M.stat(vm, path, opts)
    opts = opts or {}
    local flags = (opts.follow == false) and M.AT_SYMLINK_NOFOLLOW or 0
    local r = vm:syscall(M.NR.newfstatat, {
        args = { M.AT_FDCWD, 0, 0, flags },
        bufs = { M.cstr(path), string.rep("\0", STAT_SIZE) },
        ptrs = { 1, 2 },
    })
    if r.ret ~= 0 then return nil, r.errno end
    local buf = r.out_bufs[2]
    local mode = string.unpack("<I4", buf, STAT.mode)
    return {
        dev   = string.unpack("<I8", buf, STAT.dev),
        ino   = string.unpack("<I8", buf, STAT.ino),
        nlink = string.unpack("<I8", buf, STAT.nlink),
        mode  = mode,
        perm  = mode & 0xFFF,
        uid   = string.unpack("<I4", buf, STAT.uid),
        gid   = string.unpack("<I4", buf, STAT.gid),
        size  = string.unpack("<i8", buf, STAT.size),
        -- S_IFMT is the top four bits of the type field.
        is_dir     = (mode & 0xF000) == 0x4000,
        is_symlink = (mode & 0xF000) == 0xA000,
        is_file    = (mode & 0xF000) == 0x8000,
    }
end

--- mount(2). Every argument is optional but `target`.
function M.mount(vm, spec)
    return vm:syscall(M.NR.mount, {
        args = { 0, 0, 0, spec.flags or 0, 0 },
        bufs = {
            M.cstr(spec.source or "none"),
            M.cstr(spec.target),
            M.cstr(spec.fstype or ""),
            M.cstr(spec.data or ""),
        },
        ptrs = { 0, 1, 2, 4 },
    })
end

--- umount2(2).
function M.umount(vm, target, flags)
    return vm:syscall(M.NR.umount2, {
        args = { 0, flags or 0 },
        bufs = { M.cstr(target) },
        ptrs = { 0 },
    })
end

--- symlink(2), as symlinkat(AT_FDCWD).
function M.symlink(vm, target, linkpath)
    return vm:syscall(M.NR.symlinkat, {
        args = { 0, M.AT_FDCWD, 0 },
        bufs = { M.cstr(target), M.cstr(linkpath) },
        ptrs = { 0, 2 },
    })
end

--- chown(2), as fchownat(AT_FDCWD). `-1` leaves a field alone.
function M.chown(vm, path, uid, gid)
    return vm:syscall(M.NR.fchownat, {
        args = { M.AT_FDCWD, 0, uid or -1, gid or -1, 0 },
        bufs = { M.cstr(path) },
        ptrs = { 1 },
    })
end

--- Bind-mount `from` at `to`, read-only.
---
--- Two calls: the kernel ignores MS_RDONLY on the bind itself, so the
--- read-only-ness has to be applied by a second remount. This is how a
--- test produces a provider whose *mount* is read-only, as distinct
--- from a stratum flagged `ro`.
function M.bind_ro(vm, from, to)
    local r = M.mount(vm, { source = from, target = to, flags = M.MS_BIND })
    if r.ret ~= 0 then return r end
    return M.mount(vm, {
        target = to,
        flags = M.MS_BIND | M.MS_REMOUNT | M.MS_RDONLY,
    })
end

return M
