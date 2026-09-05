-- FACS (PKM §3.9): the file-specific enforcement surface.
--
-- Two things this module knows that the others do not.
--
-- The first is the *native open with a descriptor*. helpers/kacs.open
-- covers the ordinary shape; §3.9.2's caller-supplied-descriptor rules
-- need the `sd_ptr` / `sd_len` fields of `kacs_open_how` filled in, and
-- the create dispositions need the status word read back, so `M.open`
-- here is the full form.
--
-- The second is the *use-time syscall surface*: fcntl commands, ioctl
-- commands, fallocate modes, RWF flags, watch placement. §3.9.4 is one
-- long table of "this operation needs that right", and every row of it
-- is a raw syscall the guest has no userspace to issue for us.
--
-- Why use-time cases need no worker: the native open is strict, so a
-- descriptor opened with a desired mask carries *exactly* that mask
-- (§3.9.2), and a use-time check is `(granted & required) == required`
-- against the cached mask with no token consulted. The agent is SYSTEM
-- and every privilege it holds is irrelevant to a mask comparison. So
-- "an operation with the right, and the same operation without it" is
-- two native opens of the same file, and the DACL can grant everything.
-- Only the *live* checks — path-based metadata, chdir, watch placement,
-- execveat — consult the token, and those do need a bounded caller
-- (helpers/kacs.as_dacl_bound).
--
-- x86_64 numbers throughout. Every ioctl command was computed from the
-- kernel's own _IOC macros against the tree PKM is built from.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")

local M = {}

-- Syscall numbers the §3.9 surface needs and helpers/sys does not carry.
M.NR = {
    fcntl = 72, dup = 32, dup2 = 33, dup3 = 292,
    pread64 = 17, pwrite64 = 18, preadv2 = 327, pwritev2 = 328,
    statx = 332, fstatfs = 138, fdatasync = 75,
    chdir = 80, fchdir = 81, chroot = 161,
    fchmod = 91, fchown = 93, truncate = 76,
    faccessat = 269, faccessat2 = 439,
    fsetxattr = 190, fremovexattr = 199, lgetxattr = 192, lsetxattr = 189,
    -- helpers/sys carries flistxattr as 195, which is llistxattr; 196 is
    -- the descriptor form. Named here rather than corrected there,
    -- since other suites are running against that module.
    flistxattr = 196,
    inotify_init1 = 294, inotify_add_watch = 254, inotify_rm_watch = 255,
    fanotify_init = 300, fanotify_mark = 301,
    execveat = 322, memfd_create = 319,
    pidfd_getfd = 438, pidfd_open = 434,
    socket = 41, socketpair = 53, bind = 49, listen = 50, accept = 43,
    connect = 42, sendmsg = 46, recvmsg = 47,
    setns = 308, exit_group = 231,
}

-- fcntl commands. F_LINUX_SPECIFIC_BASE is 1024.
M.F = {
    DUPFD = 0, GETFD = 1, SETFD = 2, GETFL = 3, SETFL = 4,
    GETLK = 5, SETLK = 6, SETLKW = 7,
    SETOWN = 8, GETOWN = 9, SETSIG = 10, GETSIG = 11,
    SETOWN_EX = 15, GETOWN_EX = 16, GETOWNER_UIDS = 17,
    OFD_GETLK = 36, OFD_SETLK = 37, OFD_SETLKW = 38,
    SETLEASE = 1024, GETLEASE = 1025, NOTIFY = 1026,
    DUPFD_QUERY = 1027, CREATED_QUERY = 1028, DUPFD_CLOEXEC = 1030,
    SETPIPE_SZ = 1031, GETPIPE_SZ = 1032,
    ADD_SEALS = 1033, GET_SEALS = 1034,
    GET_RW_HINT = 1035, SET_RW_HINT = 1036,
    GET_FILE_RW_HINT = 1037, SET_FILE_RW_HINT = 1038,
    GETDELEG = 1039, SETDELEG = 1040,
    -- Not a command Linux defines: the "unknown command" §3.9.4 says
    -- fails closed on a managed descriptor.
    UNKNOWN = 1099,
}

-- struct flock, x86_64: short l_type; short l_whence; off_t l_start;
-- off_t l_len; pid_t l_pid; (32 bytes with padding).
M.LOCK = { RDLCK = 0, WRLCK = 1, UNLCK = 2 }
function M.flock_struct(ltype, whence, start, len)
    return string.pack("<i2i2i8i8i4i4", ltype, whence or 0, start or 0, len or 0, 0, 0)
end

-- dnotify events (F_NOTIFY).
M.DN = {
    ACCESS = 0x1, MODIFY = 0x2, CREATE = 0x4, DELETE = 0x8,
    RENAME = 0x10, ATTRIB = 0x20, MULTISHOT = 0x80000000,
}

-- fallocate(2) modes.
M.FALLOC = {
    ALLOCATE_RANGE = 0x00, KEEP_SIZE = 0x01, PUNCH_HOLE = 0x02,
    NO_HIDE_STALE = 0x04, COLLAPSE_RANGE = 0x08, ZERO_RANGE = 0x10,
    INSERT_RANGE = 0x20, UNSHARE_RANGE = 0x40, WRITE_ZEROES = 0x80,
}

-- preadv2/pwritev2 per-I/O flags.
M.RWF = { HIPRI = 0x1, DSYNC = 0x2, SYNC = 0x4, NOWAIT = 0x8,
          APPEND = 0x10, NOAPPEND = 0x20 }

-- inotify / fanotify.
M.IN = { ACCESS = 0x1, MODIFY = 0x2, ATTRIB = 0x4, CREATE = 0x100,
         DELETE = 0x200, ALL_EVENTS = 0x00000fff, NONBLOCK = 0x800, CLOEXEC = 0x80000 }
M.FAN = {
    CLOEXEC = 0x1, NONBLOCK = 0x2,
    CLASS_NOTIF = 0x0, CLASS_CONTENT = 0x4, CLASS_PRE_CONTENT = 0x8,
    REPORT_FID = 0x200,
    MARK_ADD = 0x1, MARK_REMOVE = 0x2,
    MARK_INODE = 0x0, MARK_MOUNT = 0x10, MARK_FILESYSTEM = 0x100,
    MODIFY = 0x2, OPEN = 0x20,
}

-- ioctl commands, by the right §3.9.4 assigns them.
M.IOC = {
    -- descriptor-local
    FIOCLEX = 0x5451, FIONCLEX = 0x5450, FIONBIO = 0x5421, FIOASYNC = 0x5452,
    -- common VFS
    FIBMAP = 0x00000001, FIGETBSZ = 0x00000002,
    FIFREEZE = 0xC0045877, FITHAW = 0xC0045878, FITRIM = 0xC0185879,
    FS_IOC_GETFSUUID = 0x80111500, FS_IOC_GETFSSYSFSPATH = 0x80811501,
    FS_IOC_GETLBMD_CAP = 0xC0101502,
    -- file and object
    FS_IOC_FIEMAP = 0xC020660B, FIONREAD = 0x0000541B,
    FS_IOC_GETFLAGS = 0x80086601, FS_IOC_SETFLAGS = 0x40086602,
    FS_IOC_GETVERSION = 0x80087601, FS_IOC_SETVERSION = 0x40087602,
    FS_IOC_RESVSP = 0x40305828, FS_IOC_RESVSP64 = 0x4030582A,
    FS_IOC_UNRESVSP = 0x40305829, FS_IOC_UNRESVSP64 = 0x4030582B,
    FS_IOC_ZERO_RANGE = 0x40305839,
    FICLONE = 0x40049409, FICLONERANGE = 0x4020940D, FIDEDUPERANGE = 0xC0189436,
    FIOQSIZE = 0x00005460,
    FS_IOC_FSGETXATTR = 0x801C581F, FS_IOC_FSSETXATTR = 0x401C5820,
    FS_IOC_GETFSLABEL = 0x81009431, FS_IOC_SETFSLABEL = 0x41009432,
    FS_IOC_GET_ENCRYPTION_PWSALT = 0x40106614,
    FS_IOC_GET_ENCRYPTION_POLICY = 0x400C6615,
    FS_IOC_GET_ENCRYPTION_POLICY_EX = 0xC0096616,
    FS_IOC_SET_ENCRYPTION_POLICY = 0x800C6613,
    FS_IOC_ADD_ENCRYPTION_KEY = 0xC0506617,
    FS_IOC_REMOVE_ENCRYPTION_KEY = 0xC0406618,
    FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS = 0xC0406619,
    FS_IOC_GET_ENCRYPTION_KEY_STATUS = 0xC080661A,
    BLKGETSIZE64 = 0x80081272, BLKFLSBUF = 0x00001261,
    -- 32-bit compat aliases, which take their native command's right
    FS_IOC32_GETFLAGS = 0x80046601, FS_IOC32_SETFLAGS = 0x40046602,
    FS_IOC32_GETVERSION = 0x80047601, FS_IOC32_SETVERSION = 0x40047602,
    FS_IOC_RESVSP_32 = 0x402C5828, FS_IOC_ZERO_RANGE_32 = 0x402C5839,
    -- Not a command any filesystem claims: the "unclassified" case.
    UNCLASSIFIED = 0x00007799,
}

-- mmap / mprotect protections beyond what helpers/sys carries.
M.PROT_EXEC = 4
M.MAP_SHARED_VALIDATE = 0x03

M.AT_EMPTY_PATH = 0x1000

-- Native open ---------------------------------------------------------------

--- kacs_open(2), in full: `access`, `disposition`, `options`, `flags`
--- (only AT_SYMLINK_NOFOLLOW is accepted there), `sd` (a caller-supplied
--- descriptor for a creating disposition) and `dirfd`.
---
--- Returns `fd, status` — the status word being one of
--- `M.STATUS.*` — or `nil, errno`. Unlike helpers/kacs.open there is no
--- default access: a §3.9.2 case always names the mask it is about.
function M.open(who, path, how)
    how = how or {}
    local sd = how.sd
    local hb = string.pack("<I4I4I4I4I8I4I4",
        how.access or 0,
        how.disposition or kacs.DISPOSITION.OPEN,
        how.options or 0, how.flags or 0,
        0, sd and #sd or 0, how.pad or 0)
    local bufs = { sys.cstr(path), hb, string.rep("\0", 4) }
    local nested
    if sd then
        bufs[4] = sd
        nested = { { parent = 2, child = 4, offset = 16 } }
    end
    local r = who:syscall(kacs.SYS.OPEN, {
        args = { how.dirfd or sys.AT_FDCWD, 0, 0, how.howsize or 32, 0 },
        bufs = bufs, ptrs = { 1, 2, 4 }, nested = nested,
    })
    if r.ret < 0 then return nil, r.errno end
    return r.ret, string.unpack("<I4", r.out_bufs[3])
end

M.STATUS = { OPENED = 1, CREATED = 2, OVERWRITTEN = 3, SUPERSEDED = 4 }

-- Workspaces ----------------------------------------------------------------

--- A directory under `/` (the root tmpfs, which is FACS-managed and
--- whose objects carry stored descriptors) granting every right to
--- everyone, with inheritance, so children created inside it are
--- reachable before a case sets its own descriptor.
---
--- `/tmp` is deliberately not used: it is a separate mount with no
--- descriptor on its root, so every object under it is denied.
function M.workspace(vm, name)
    local at = "/facs-" .. name
    vm:mkdir(at, { parents = true })
    kacs.set_sd(vm, at, kacs.grant(kacs.ALL_RIGHTS))
    return at
end

--- Create `path` with `content` and give it a DACL granting `mask`
--- (every right by default) to everyone. Returns the path.
function M.file(vm, path, content, mask)
    vm:write_file(path, content or "")
    kacs.set_sd(vm, path, kacs.grant(mask or kacs.ALL_RIGHTS))
    return path
end

--- Open `path` natively with exactly `access`, asserting it worked.
---
--- Because native open is strict the returned descriptor's cached mask
--- *is* `access` — which is what makes a use-time case a clean
--- experiment: the only variable is the bit under test.
function M.handle(t, who, path, access, how)
    how = how or {}
    how.access = access
    local fd, errno = M.open(who, path, how)
    t:assert(fd, "open " .. path .. " for 0x" .. string.format("%x", access) ..
        ": " .. sys.errname(errno or 0))
    return fd
end

-- Raw operations ------------------------------------------------------------

--- fcntl(2) with an integer argument. Returns the raw syscall result.
function M.fcntl(who, fd, cmd, arg)
    return who:syscall(M.NR.fcntl, fd, cmd, arg or 0)
end

--- fcntl(2) with a pointer argument (the lock commands). Returns the
--- raw result plus the buffer written back.
function M.fcntl_buf(who, fd, cmd, buf)
    return who:syscall(M.NR.fcntl, {
        args = { fd, cmd, 0 }, bufs = { buf }, ptrs = { 2 },
    })
end

--- ioctl(2) with a pointer to `buf` (or a null third argument when
--- `buf` is nil). Returns the raw syscall result.
function M.ioctl(who, fd, cmd, buf)
    if not buf then return who:syscall(sys.NR.ioctl, fd, cmd, 0) end
    return who:syscall(sys.NR.ioctl, {
        args = { fd, cmd, 0 }, bufs = { buf }, ptrs = { 2 },
    })
end

--- dup(2) / dup3(2).
function M.dup(who, fd) return who:syscall(M.NR.dup, fd) end
function M.dup3(who, oldfd, newfd, flags)
    return who:syscall(M.NR.dup3, oldfd, newfd, flags or 0)
end

--- pwrite64(2) — a positioned write, which §3.9.4 denies on an
--- append-only handle.
function M.pwrite(who, fd, data, offset)
    return who:syscall(M.NR.pwrite64, {
        args = { fd, 0, #data, offset or 0 }, bufs = { data }, ptrs = { 1 },
    })
end

--- pwritev2(2) with one iovec. `offset` of -1 means "the file position",
--- which is what distinguishes a positioned write from a sequential one.
---
--- The syscall takes the offset as (pos_l, pos_h); on a 64-bit kernel
--- pos_from_hilo() shifts pos_h clean out, so the whole offset goes in
--- pos_l and pos_h is zero — which is exactly what glibc's LO_HI_LONG
--- does there.
function M.pwritev2(who, fd, data, offset, flags)
    -- struct iovec { void *iov_base; size_t iov_len; }
    local iov = string.pack("<I8I8", 0, #data)
    if offset == nil then offset = -1 end
    return who:syscall(M.NR.pwritev2, {
        args = { fd, 0, 1, offset, 0, flags or 0 },
        bufs = { iov, data },
        ptrs = { 1 },
        nested = { { parent = 1, child = 2, offset = 0 } },
    })
end

--- mprotect(2).
function M.mprotect(who, addr, len, prot)
    return who:syscall(sys.NR.mprotect, addr, len, prot)
end

--- statx(2) against a descriptor (AT_EMPTY_PATH).
function M.statx_fd(who, fd)
    return who:syscall(M.NR.statx, {
        args = { fd, 0, M.AT_EMPTY_PATH, 0x7ff, 0 },
        bufs = { sys.cstr(""), string.rep("\0", 256) },
        ptrs = { 1, 4 },
    })
end

--- fstatfs(2).
function M.fstatfs(who, fd)
    return who:syscall(M.NR.fstatfs, {
        args = { fd, 0 }, bufs = { string.rep("\0", 120) }, ptrs = { 1 },
    })
end

--- fchmod(2) / fchown(2) / futimens(2) — the descriptor forms of the
--- metadata operations §3.9.4 assigns WRITE_DAC, WRITE_OWNER and
--- FILE_WRITE_ATTRIBUTES.
function M.fchmod(who, fd, mode)
    return who:syscall(M.NR.fchmod, fd, mode or tonumber("644", 8))
end
function M.fchown(who, fd, uid, gid)
    return who:syscall(M.NR.fchown, fd, uid or 0, gid or 0)
end
function M.futimens(who, fd, seconds)
    -- utimensat(fd, NULL, times, 0) is the futimens(3) form: a null
    -- pathname makes the descriptor itself the object.
    local times = string.pack("<i8i8i8i8", seconds or 1, 0, seconds or 1, 0)
    return who:syscall(sys.NR.utimensat, {
        args = { fd, 0, 0, 0 }, bufs = { times }, ptrs = { 2 },
    })
end

--- fsetxattr(2) / fremovexattr(2).
function M.fsetxattr(who, fd, name, value, flags)
    return who:syscall(M.NR.fsetxattr, {
        args = { fd, 0, 0, #value, flags or 0 },
        bufs = { sys.cstr(name), value }, ptrs = { 1, 2 },
    })
end
function M.fremovexattr(who, fd, name)
    return who:syscall(M.NR.fremovexattr, {
        args = { fd, 0 }, bufs = { sys.cstr(name) }, ptrs = { 1 },
    })
end

--- flistxattr(2), which §3.9.4 says needs no right at all.
function M.flistxattr(who, fd, size)
    size = size or 4096
    return who:syscall(M.NR.flistxattr, {
        args = { fd, 0, size }, bufs = { string.rep("\0", size) }, ptrs = { 1 },
    })
end

--- faccessat(2). `mode` is F_OK / R_OK / W_OK / X_OK.
M.F_OK, M.X_OK, M.W_OK, M.R_OK = 0, 1, 2, 4
function M.faccessat(who, path, mode)
    return who:syscall(M.NR.faccessat, {
        args = { sys.AT_FDCWD, 0, mode }, bufs = { sys.cstr(path) }, ptrs = { 1 },
    })
end

--- chdir(2) / chroot(2) / fchdir(2) — the explicit directory changes
--- §3.9.4 gives a live FILE_TRAVERSE check.
function M.chdir(who, path)
    return who:syscall(M.NR.chdir, {
        args = { 0 }, bufs = { sys.cstr(path) }, ptrs = { 0 },
    })
end
function M.chroot(who, path)
    return who:syscall(M.NR.chroot, {
        args = { 0 }, bufs = { sys.cstr(path) }, ptrs = { 0 },
    })
end
function M.fchdir(who, fd) return who:syscall(M.NR.fchdir, fd) end

--- truncate(2) by pathname.
function M.truncate(who, path, length)
    return who:syscall(M.NR.truncate, {
        args = { 0, length or 0 }, bufs = { sys.cstr(path) }, ptrs = { 0 },
    })
end

-- Watches -------------------------------------------------------------------

--- inotify_init1(2). Returns the fd, or `nil, errno`.
function M.inotify_init(who, flags)
    local r = who:syscall(M.NR.inotify_init1, flags or 0)
    if r.ret < 0 then return nil, r.errno end
    return r.ret
end

--- inotify_add_watch(2). Returns the watch descriptor, or `nil, errno`.
function M.inotify_add_watch(who, ifd, path, mask)
    local r = who:syscall(M.NR.inotify_add_watch, {
        args = { ifd, 0, mask or M.IN.ALL_EVENTS },
        bufs = { sys.cstr(path) }, ptrs = { 1 },
    })
    if r.ret < 0 then return nil, r.errno end
    return r.ret
end

--- fanotify_init(2). Returns the fd, or `nil, errno`.
function M.fanotify_init(who, flags, event_flags)
    local r = who:syscall(M.NR.fanotify_init, flags or 0, event_flags or 0)
    if r.ret < 0 then return nil, r.errno end
    return r.ret
end

--- fanotify_mark(2). Returns the raw syscall result.
---
--- Five arguments on x86_64: the __u64 mask is one register there, not
--- the hi/lo pair the 32-bit ABI splits it into.
function M.fanotify_mark(who, ffd, flags, mask, dirfd, path)
    return who:syscall(M.NR.fanotify_mark, {
        args = { ffd, flags, mask, dirfd or sys.AT_FDCWD, 0 },
        bufs = { sys.cstr(path or "") }, ptrs = { 4 },
    })
end

-- Execution -----------------------------------------------------------------

--- execveat(fd, "", NULL, NULL, AT_EMPTY_PATH) — descriptor-based exec,
--- which §3.9.4 gives a live AccessCheck in the bprm hook.
---
--- The guest has no program to run, so a case uses this for the *check*,
--- not the exec: a denial is EACCES and a grant reaches Linux's own
--- ENOEXEC / ENenter validation. Returns the raw syscall result.
function M.execveat_fd(who, fd)
    return who:syscall(M.NR.execveat, {
        args = { fd, 0, 0, 0, M.AT_EMPTY_PATH },
        bufs = { sys.cstr("") }, ptrs = { 1 },
    })
end

--- pidfd_getfd(2).
function M.pidfd_getfd(who, pidfd, targetfd)
    return who:syscall(M.NR.pidfd_getfd, pidfd, targetfd, 0)
end

return M
