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
    statfs     = 137,
    openat     = 257,
    close      = 3,
    ioctl      = 16,
    write      = 1,
    read       = 0,
    flock      = 73,
    fsync      = 74,
}

-- flock(2) operations.
M.LOCK_SH, M.LOCK_EX, M.LOCK_UN, M.LOCK_NB = 1, 2, 8, 4

-- Flags a test is likely to name.
M.AT_FDCWD            = -100
M.AT_SYMLINK_NOFOLLOW = 0x100
M.MS_RDONLY           = 1
M.MS_BIND             = 4096
M.MS_REMOUNT          = 32

-- open(2) flags.
M.O = {
    RDONLY = 0, WRONLY = 1, RDWR = 2, CREAT = 0x40, EXCL = 0x80,
    TRUNC = 0x200, APPEND = 0x400, DIRECTORY = 0x10000, NOFOLLOW = 0x20000,
    PATH = 0x200000, TMPFILE = 0x410000,
}

-- The inode flag ioctls, and the one flag stratafs's
-- accepts-modification predicate reads (§4.2.1).
M.FS_IOC_GETFLAGS = 0x80086601
M.FS_IOC_SETFLAGS = 0x40086602
M.FS_IMMUTABLE_FL = 0x00000010

-- Errnos, by the name the TRM uses for them.
M.E = {
    PERM = 1, NOENT = 2, IO = 5, BADF = 9, AGAIN = 11, ACCES = 13,
    EXIST = 17, XDEV = 18, NODEV = 19, NOTDIR = 20, ISDIR = 21,
    INVAL = 22, ROFS = 30, NOTEMPTY = 39, LOOP = 40, STALE = 116,
    NODATA = 61, RANGE = 34, OPNOTSUPP = 95, NOTTY = 25,
    NAMETOOLONG = 36, NOSPC = 28, MLINK = 31, TXTBSY = 26,
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

-- struct statfs, x86_64. 120 bytes; every field is 8 wide.
local STATFS_SIZE = 120
local STATFS = { type = 1, bsize = 9, namelen = 65, flags = 81 }

--- statfs(2), returning the fields that identify a superblock.
---
--- `type` is the filesystem magic — for stratafs, §4.A's `STRATAFS_MAGIC`.
--- Returns `nil, errno` on failure.
function M.statfs(vm, path)
    local r = vm:syscall(M.NR.statfs, {
        args = { 0, 0 },
        bufs = { M.cstr(path), string.rep("\0", STATFS_SIZE) },
        ptrs = { 0, 1 },
    })
    if r.ret ~= 0 then return nil, r.errno end
    local buf = r.out_bufs[2]
    return {
        type    = string.unpack("<I8", buf, STATFS.type),
        bsize   = string.unpack("<I8", buf, STATFS.bsize),
        namelen = string.unpack("<I8", buf, STATFS.namelen),
        flags   = string.unpack("<I8", buf, STATFS.flags),
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

--- openat(2) at AT_FDCWD. Returns the fd, or `nil, errno`.
---
--- The agent issues every syscall from one process, so an fd stays
--- open across calls and can be handed to `M.ioctl` or `M.close`.
function M.open(vm, path, flags, mode)
    local r = vm:syscall(M.NR.openat, {
        args = { M.AT_FDCWD, 0, flags or M.O.RDONLY, mode or 0 },
        bufs = { M.cstr(path) },
        ptrs = { 1 },
    })
    if r.ret < 0 then return nil, r.errno end
    return r.ret
end

--- write(2). Returns the raw syscall result.
function M.write(vm, fd, data)
    return vm:syscall(M.NR.write, {
        args = { fd, 0, #data },
        bufs = { data },
        ptrs = { 1 },
    })
end

--- close(2).
function M.close(vm, fd) return vm:syscall(M.NR.close, fd) end

--- ioctl(2) with a pointer to an in/out word — the shape the inode
--- flag ioctls take. Returns the word back, or `nil, errno`.
function M.ioctl_word(vm, fd, cmd, word)
    local r = vm:syscall(M.NR.ioctl, {
        args = { fd, cmd, 0 },
        bufs = { string.pack("<I8", word or 0) },
        ptrs = { 2 },
    })
    if r.ret ~= 0 then return nil, r.errno end
    return string.unpack("<I8", r.out_bufs[1])
end

--- Set or clear FS_IMMUTABLE_FL on a path.
---
--- The third term of the accepts-modification predicate (§4.2.1) is
--- specifically the immutable inode flag, so a test that wants a
--- provider which refuses modification *without* saying `ro` and
--- *without* a read-only mount sets this.
function M.set_immutable(vm, path, on)
    local fd, errno = M.open(vm, path, M.O.RDONLY)
    if not fd then return nil, errno end
    local flags, err = M.ioctl_word(vm, fd, M.FS_IOC_GETFLAGS, 0)
    if flags then
        if on == false then
            flags = flags & ~M.FS_IMMUTABLE_FL
        else
            flags = flags | M.FS_IMMUTABLE_FL
        end
        flags, err = M.ioctl_word(vm, fd, M.FS_IOC_SETFLAGS, flags)
    end
    M.close(vm, fd)
    if not flags then return nil, err end
    return true
end

--- flock(2).
function M.flock(vm, fd, operation)
    return vm:syscall(M.NR.flock, fd, operation)
end

--- fsync(2).
function M.fsync(vm, fd) return vm:syscall(M.NR.fsync, fd) end

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
