-- The two object families of PKM §3.11 and §3.12 that are neither files
-- nor tokens: System V IPC objects, and the network objects — port
-- reservations and the identity stamped on an inet socket.
--
-- Both are addressed unlike anything else. A SysV object has no fd and
-- no path, so `kacs_get_sd` / `kacs_set_sd` name it by kind and id
-- (§3.D `abi-notes.sysv-sd-at-addressing`); a port reservation is a
-- registry *value* whose name is its selector, so a test seeds it
-- through helpers/registry and drives it with bind(2).
--
-- Numbers: `<pkm/ipc.h>` and `<pkm/net.h>` for the rights and the
-- SD-addressing flags, x86_64 for the syscalls.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local access = require("helpers.access")

local M = {}

M.NR = {
    socket = 41, bind = 49, listen = 50, connect = 42, accept4 = 288,
    getsockname = 51, setsockopt = 54, getsockopt = 55, close = 3,
    shmget = 29, shmat = 30, shmdt = 67, shmctl = 31,
    msgget = 68, msgsnd = 69, msgrcv = 70, msgctl = 71,
    semget = 64, semop = 65, semctl = 66,
}

-- ---- System V IPC ----------------------------------------------------

-- `kacs_get_sd` / `kacs_set_sd` addressing flags (<pkm/ipc.h>).
M.SD_AT = { SHM = 0x01000000, MSG = 0x02000000, SEM = 0x04000000 }

-- Object rights (<pkm/ipc.h>) plus the standard rights they compose with.
M.IPC = {
    READ = 0x00000001, WRITE = 0x00000002,
    QUERY_INFORMATION = 0x00000004, SET_INFORMATION = 0x00000008,
    DELETE = 0x00010000, READ_CONTROL = 0x00020000,
    WRITE_DAC = 0x00040000, WRITE_OWNER = 0x00080000,
    GENERIC_ALL = 0x10000000, GENERIC_EXECUTE = 0x20000000,
    GENERIC_WRITE = 0x40000000, GENERIC_READ = 0x80000000,
}

-- ipc_perm mode bits and *get flags.
M.IPC_CREAT, M.IPC_EXCL, M.IPC_NOWAIT = 0x200, 0x400, 0x800
M.MODE_0666 = tonumber("666", 8)

-- *ctl commands. The generic three, then the per-family ones.
M.CTL = {
    RMID = 0, SET = 1, STAT = 2, INFO = 3,
    SHM_LOCK = 11, SHM_UNLOCK = 12, SHM_STAT = 13, SHM_INFO = 14,
    SHM_STAT_ANY = 15,
    MSG_STAT = 11, MSG_INFO = 12, MSG_STAT_ANY = 13,
    SEM_GETPID = 11, SEM_GETVAL = 12, SEM_GETALL = 13, SEM_GETNCNT = 14,
    SEM_GETZCNT = 15, SEM_SETVAL = 16, SEM_SETALL = 17,
    SEM_STAT = 18, SEM_INFO = 19,
}

M.SHM_RDONLY = 0x1000

--- shmget/msgget/semget, returning the id or nil, errno.
function M.shmget(who, key, size, flags)
    local r = who:syscall(M.NR.shmget, key, size or 4096,
        flags or (M.IPC_CREAT | M.MODE_0666))
    if r.ret < 0 then return nil, r.errno end
    return r.ret
end

function M.msgget(who, key, flags)
    local r = who:syscall(M.NR.msgget, key, flags or (M.IPC_CREAT | M.MODE_0666))
    if r.ret < 0 then return nil, r.errno end
    return r.ret
end

function M.semget(who, key, nsems, flags)
    local r = who:syscall(M.NR.semget, key, nsems or 1,
        flags or (M.IPC_CREAT | M.MODE_0666))
    if r.ret < 0 then return nil, r.errno end
    return r.ret
end

--- shmat(2). Returns the raw result: `ret` is an address on success.
function M.shmat(who, id, flags)
    return who:syscall(M.NR.shmat, id, 0, flags or 0)
end

--- msgsnd(2) of a four-byte message of type 1, non-blocking.
function M.msgsnd(who, id, text)
    text = text or "abcd"
    return who:syscall(M.NR.msgsnd, {
        args = { id, 0, #text, M.IPC_NOWAIT },
        bufs = { string.pack("<i8", 1) .. text },
        ptrs = { 1 },
    })
end

--- msgrcv(2) of any type, non-blocking.
function M.msgrcv(who, id, size)
    size = size or 4
    return who:syscall(M.NR.msgrcv, {
        args = { id, 0, size, 0, M.IPC_NOWAIT },
        bufs = { string.rep("\0", 8 + size) },
        ptrs = { 1 },
    })
end

--- A *ctl command that writes a struct back: IPC_STAT and IPC_SET.
function M.ctl_buf(who, nr, id, cmd, buf)
    return who:syscall(nr, {
        args = { id, cmd, 0 },
        bufs = { buf or string.rep("\0", 128) },
        ptrs = { 2 },
    })
end

function M.shmctl(who, id, cmd) return who:syscall(M.NR.shmctl, id, cmd, 0) end
function M.msgctl(who, id, cmd) return who:syscall(M.NR.msgctl, id, cmd, 0) end
function M.semctl(who, id, num, cmd, arg)
    return who:syscall(M.NR.semctl, id, num, cmd, arg or 0)
end

--- Remove every id in `ids` of the given kind, ignoring failures. For a
--- test's own cleanup: SysV objects outlive their creator.
function M.rmid(who, nr, ids)
    for _, id in ipairs(ids) do
        if id then who:syscall(nr, id, M.CTL.RMID, 0) end
    end
end

--- kacs_get_sd against a SysV object addressed by (kind, id).
--- Returns the descriptor bytes, or nil, errno.
function M.ipc_get_sd(who, kind, id, info)
    local r = who:syscall(kacs.SYS.GET_SD, {
        args = { id, 0, info or (kacs.SI.OWNER | kacs.SI.GROUP | kacs.SI.DACL),
                 0, 4096, kind },
        bufs = { string.rep("\0", 4096) },
        ptrs = { 3 },
    })
    if r.ret < 0 then return nil, r.errno end
    return r.out_bufs[1]:sub(1, r.ret)
end

--- kacs_set_sd against a SysV object. Returns the raw syscall result.
function M.ipc_set_sd(who, kind, id, descriptor, info)
    return who:syscall(kacs.SYS.SET_SD, {
        args = { id, 0, info or kacs.SI.DACL, 0, #descriptor, kind },
        bufs = { descriptor },
        ptrs = { 3 },
    })
end

--- A DACL-only descriptor granting `mask` to one trustee and nothing to
--- anyone else — the shape a rights case wants.
function M.only(sid, mask)
    return kacs.descriptor(kacs.acl({ kacs.ace(kacs.ACE_ALLOWED, mask, sid) }))
end

-- ---- network objects -------------------------------------------------

M.AF_INET, M.AF_INET6 = 2, 10
M.SOCK_STREAM, M.SOCK_DGRAM = 1, 2
M.IPPROTO_TCP, M.IPPROTO_UDP = 6, 17
M.SOL_SOCKET, M.SO_REUSEADDR, M.SO_REUSEPORT = 1, 2, 15
M.SOL_KACS = 4096
M.KACS_SO_RESTAMP = 4
M.PORT_BIND, M.PORT_READ_CONTROL = 0x00000001, 0x00020000

--- struct sockaddr_in bound to INADDR_ANY.
function M.sockaddr_in(port)
    return string.pack("<I2", M.AF_INET) .. string.pack(">I2", port)
        .. string.pack(">I4", 0) .. string.rep("\0", 8)
end

--- struct sockaddr_in6 bound to in6addr_any.
function M.sockaddr_in6(port)
    return string.pack("<I2", M.AF_INET6) .. string.pack(">I2", port)
        .. string.pack("<I4", 0) .. string.rep("\0", 16) .. string.pack("<I4", 0)
end

M.SOCK_RAW, M.IPPROTO_ICMP = 3, 1

--- socket(2) for an inet family. Returns fd, or nil, errno.
function M.socket(who, family, socktype, protocol)
    local r = who:syscall(M.NR.socket, family or M.AF_INET,
        socktype or M.SOCK_STREAM, protocol or 0)
    if r.ret < 0 then return nil, r.errno end
    return r.ret
end

--- setsockopt(SOL_SOCKET, opt, 1).
function M.set_flag(who, fd, opt)
    return who:syscall(M.NR.setsockopt, {
        args = { fd, M.SOL_SOCKET, opt, 0, 4 },
        bufs = { string.pack("<i4", 1) },
        ptrs = { 3 },
    })
end

--- setsockopt(SOL_KACS, KACS_SO_RESTAMP): the caller's effective
--- identity replaces the socket's stamp.
function M.restamp(who, fd)
    return who:syscall(M.NR.setsockopt, {
        args = { fd, M.SOL_KACS, M.KACS_SO_RESTAMP, 0, 4 },
        bufs = { string.pack("<i4", 0) },
        ptrs = { 3 },
    })
end

--- bind(2) an inet socket to `port`.
---
--- `opts.family` (AF_INET, default), `opts.socktype`, `opts.reuse` (a
--- list of SO_* flags to set first), `opts.keep` (leave the socket open
--- and return the fd second). Returns the raw syscall result.
function M.bind(who, port, opts)
    opts = opts or {}
    local family = opts.family or M.AF_INET
    local fd, errno = M.socket(who, family, opts.socktype, opts.protocol)
    if not fd then return { ret = -1, errno = errno }, nil end
    for _, flag in ipairs(opts.reuse or {}) do M.set_flag(who, fd, flag) end
    local sa = (family == M.AF_INET6) and M.sockaddr_in6(port) or M.sockaddr_in(port)
    local r = who:syscall(M.NR.bind, {
        args = { fd, 0, (family == M.AF_INET6) and 28 or 16 },
        bufs = { sa }, ptrs = { 1 },
    })
    if opts.keep then return r, fd end
    sys.close(who, fd)
    return r
end

--- A port-reservation descriptor: owner and group SYSTEM, one
--- ACCESS_ALLOWED ACE per trustee carrying `mask` (PORT_BIND by
--- default), and an optional SACL.
function M.port_sd(sids, mask, sacl)
    local aces = {}
    for _, sid in ipairs(sids) do
        aces[#aces + 1] = access.ace(access.ACE.ALLOWED, mask or M.PORT_BIND, sid)
    end
    return access.simple(aces, { sacl = sacl })
end

--- The registry path the port table is read from (§3.12.1).
M.PORT_KEY_PATH = "System\\Network\\TcpIp\\PortReservations"
M.PORT_KEY_ABSOLUTE = "Machine\\" .. M.PORT_KEY_PATH

--- Seed a `helpers/registry` source with a port-reservation table.
--- `values` is a list of { selector, descriptor } pairs; the default
--- reservation is spelled "@". Call before `Source:register`.
function M.seed_port_table(src, values)
    local key = src:key(M.PORT_KEY_PATH)
    local registry = require("helpers.registry")
    for _, v in ipairs(values) do
        src:value(key, v[1], registry.TYPE.BINARY, v[2])
    end
    return key
end

return M
