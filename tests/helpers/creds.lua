-- The Linux-credential surfaces of PKM §3.10: the numbers a program
-- actually reads (getuid, getgroups, capget, /proc/self/status), the
-- setuid family, and raw netlink.
--
-- None of this is KACS ABI — it is the compatibility face KACS projects
-- a token onto, so everything here is ordinary Linux: x86_64 syscall
-- numbers, struct ucred, struct __user_cap_data_struct, and the netlink
-- message header. helpers/token mints the identity; this module reads
-- what Linux says about it.
--
-- A note on /proc: procfs resolves to the UNMANAGED mount class, so a
-- minted principal cannot open it at all. Only the agent (SYSTEM, with
-- the bypass privileges) reads /proc/self/status; a principal's
-- capability sets come back through capget(2), which needs no path.

local sys = require("helpers.sys")

local M = {}

M.NR = {
    getuid = 102, getgid = 104, geteuid = 107, getegid = 108,
    getgroups = 115, setgroups = 116,
    setuid = 105, setgid = 106, setresuid = 117, setresgid = 119,
    setfsuid = 122, setfsgid = 123,
    capget = 125, capset = 126, prctl = 157, reboot = 169,
    setpriority = 141, perf_event_open = 298, execve = 59,
    socket = 41, bind = 49, sendto = 44, recvfrom = 45, recvmsg = 47,
    getsockname = 51, setsockopt = 54, getsockopt = 55, socketpair = 53,
}

-- Linux capability bit numbers, by the name §3.10.2's tables use.
M.CAP = {
    CHOWN = 0, DAC_OVERRIDE = 1, DAC_READ_SEARCH = 2, FOWNER = 3,
    FSETID = 4, KILL = 5, SETGID = 6, SETUID = 7, SETPCAP = 8,
    LINUX_IMMUTABLE = 9, NET_BIND_SERVICE = 10, NET_BROADCAST = 11,
    NET_ADMIN = 12, NET_RAW = 13, IPC_LOCK = 14, IPC_OWNER = 15,
    SYS_MODULE = 16, SYS_RAWIO = 17, SYS_CHROOT = 18, SYS_PTRACE = 19,
    SYS_PACCT = 20, SYS_ADMIN = 21, SYS_BOOT = 22, SYS_NICE = 23,
    SYS_RESOURCE = 24, SYS_TIME = 25, SYS_TTY_CONFIG = 26, MKNOD = 27,
    LEASE = 28, AUDIT_WRITE = 29, AUDIT_CONTROL = 30, SETFCAP = 31,
    MAC_OVERRIDE = 32, MAC_ADMIN = 33, SYSLOG = 34, WAKE_ALARM = 35,
    BLOCK_SUSPEND = 36, AUDIT_READ = 37, PERFMON = 38, BPF = 39,
    CHECKPOINT_RESTORE = 40,
}

--- The twelve ALLOW capabilities of §3.10.2, in the table's order.
M.ALLOW_CAPS = {
    M.CAP.CHOWN, M.CAP.DAC_OVERRIDE, M.CAP.DAC_READ_SEARCH, M.CAP.FOWNER,
    M.CAP.FSETID, M.CAP.KILL, M.CAP.SETGID, M.CAP.SETUID,
    M.CAP.NET_BROADCAST, M.CAP.IPC_OWNER, M.CAP.LEASE,
    M.CAP.NET_BIND_SERVICE,
}

--- The three DENY capabilities of §3.10.2.
M.DENY_CAPS = { M.CAP.SETPCAP, M.CAP.SETFCAP, M.CAP.MAC_OVERRIDE }

--- The ALLOW set as one 64-bit mask.
M.ALLOW_MASK = (function()
    local mask = 0
    for _, cap in ipairs(M.ALLOW_CAPS) do mask = mask | (1 << cap) end
    return mask
end)()

-- prctl options and PR_CAP_AMBIENT sub-commands.
M.PR = { CAPBSET_READ = 23, CAPBSET_DROP = 24, CAP_AMBIENT = 47 }
M.PR_CAP_AMBIENT = { IS_SET = 1, RAISE = 2, LOWER = 3, CLEAR_ALL = 4 }

-- reboot(2). Only the CAD toggles are used here: they gate on
-- CAP_SYS_BOOT and change nothing a test cares about.
M.REBOOT_MAGIC1, M.REBOOT_MAGIC2 = 0xfee1dead, 0x28121969
M.REBOOT_CMD_CAD_OFF, M.REBOOT_CMD_CAD_ON = 0x00000000, 0x89ABCDEF

-- The v3 capability-set header the kernel accepts.
local CAP_VERSION_3 = 0x20080522

-- ---- credentials -----------------------------------------------------

function M.getuid(who) return who:syscall(M.NR.getuid).ret end
function M.geteuid(who) return who:syscall(M.NR.geteuid).ret end
function M.getgid(who) return who:syscall(M.NR.getgid).ret end
function M.getegid(who) return who:syscall(M.NR.getegid).ret end

--- getgroups(2). Returns the supplementary gids as a list, or nil, errno.
function M.getgroups(who, max)
    max = max or 64
    local r = who:syscall(M.NR.getgroups, {
        args = { max, 0 },
        bufs = { string.rep("\0", 4 * max) },
        ptrs = { 1 },
    })
    if r.ret < 0 then return nil, r.errno end
    local out = {}
    for i = 1, r.ret do
        out[i] = string.unpack("<I4", r.out_bufs[1], 1 + 4 * (i - 1))
    end
    return out
end

--- setgroups(2) with the given list.
function M.setgroups(who, gids)
    local parts = {}
    for i, g in ipairs(gids) do parts[i] = string.pack("<I4", g) end
    return who:syscall(M.NR.setgroups, {
        args = { #gids, 0 }, bufs = { table.concat(parts) }, ptrs = { 1 },
    })
end

--- A stable string for a group list, for assertion messages.
function M.groups_string(gids)
    return "[" .. table.concat(gids or {}, ",") .. "]"
end

-- ---- capabilities ----------------------------------------------------

--- capget(2) on the caller. Returns { effective, permitted, inheritable }
--- as 64-bit masks, or nil, errno.
function M.capget(who, pid)
    local r = who:syscall(M.NR.capget, {
        args = { 0, 0 },
        bufs = { string.pack("<I4i4", CAP_VERSION_3, pid or 0),
                 string.rep("\0", 24) },
        ptrs = { 0, 1 },
    })
    if r.ret ~= 0 then return nil, r.errno end
    local e0, p0, i0, e1, p1, i1 = string.unpack("<I4I4I4I4I4I4", r.out_bufs[2])
    return {
        effective = (e1 << 32) | e0,
        permitted = (p1 << 32) | p0,
        inheritable = (i1 << 32) | i0,
    }
end

--- capset(2) with three 64-bit masks. Returns the raw syscall result.
function M.capset(who, sets)
    local function lo(v) return v & 0xFFFFFFFF end
    local function hi(v) return (v >> 32) & 0xFFFFFFFF end
    return who:syscall(M.NR.capset, {
        args = { 0, 0 },
        bufs = { string.pack("<I4i4", CAP_VERSION_3, 0),
                 string.pack("<I4I4I4I4I4I4",
                     lo(sets.effective), lo(sets.permitted), lo(sets.inheritable),
                     hi(sets.effective), hi(sets.permitted), hi(sets.inheritable)) },
        ptrs = { 0, 1 },
    })
end

--- The capability bits of `mask`, as "CAP_CHOWN,CAP_LEASE", for a message.
function M.cap_names(mask)
    local names, by_bit = {}, {}
    for name, bit in pairs(M.CAP) do by_bit[bit] = name end
    for bit = 0, 63 do
        if mask & (1 << bit) ~= 0 then
            names[#names + 1] = "CAP_" .. (by_bit[bit] or ("?" .. bit))
        end
    end
    return #names > 0 and table.concat(names, ",") or "<none>"
end

--- /proc/self/status as a name → value table. Agent-only: procfs is an
--- unmanaged mount, so a minted principal cannot open it.
function M.proc_status(vm, path)
    local fd, errno = sys.open(vm, path or "/proc/self/status", sys.O.RDONLY)
    if not fd then return nil, errno end
    local data = sys.read(vm, fd, 16384)
    sys.close(vm, fd)
    if not data then return nil, 0 end
    local out = {}
    for line in data:gmatch("[^\n]+") do
        local k, v = line:match("^([%w_]+):%s*(.-)%s*$")
        if k then out[k] = v end
    end
    return out
end

--- A hex capability field from /proc/<pid>/status as a number.
function M.status_caps(status, field)
    local v = status and status[field]
    return v and tonumber(v, 16) or nil
end

-- ---- the setuid family ----------------------------------------------

function M.setuid(who, uid) return who:syscall(M.NR.setuid, uid) end
function M.setgid(who, gid) return who:syscall(M.NR.setgid, gid) end
function M.setresuid(who, r, e, s) return who:syscall(M.NR.setresuid, r, e, s) end
function M.setresgid(who, r, e, s) return who:syscall(M.NR.setresgid, r, e, s) end
function M.setfsuid(who, uid) return who:syscall(M.NR.setfsuid, uid) end
function M.setfsgid(who, gid) return who:syscall(M.NR.setfsgid, gid) end

--- access(2) through faccessat(AT_FDCWD), which is what glibc issues.
M.R_OK, M.W_OK, M.X_OK, M.F_OK = 4, 2, 1, 0
function M.faccessat(who, path, mode)
    return who:syscall(269, {
        args = { sys.AT_FDCWD, 0, mode, 0 },
        bufs = { sys.cstr(path) },
        ptrs = { 1 },
    })
end

--- reboot(2) with one of the CAD commands: the cheapest CAP_SYS_BOOT
--- gate that changes nothing.
function M.reboot(who, cmd)
    return who:syscall(M.NR.reboot, M.REBOOT_MAGIC1, M.REBOOT_MAGIC2,
        cmd or M.REBOOT_CMD_CAD_OFF, 0)
end

--- SO_PEERCRED on a connected socket. Returns { pid, uid, gid }.
M.SOL_SOCKET, M.SO_PEERCRED, M.SO_PASSCRED = 1, 17, 16
function M.peercred(who, fd)
    local r = who:syscall(M.NR.getsockopt, {
        args = { fd, M.SOL_SOCKET, M.SO_PEERCRED, 0, 0 },
        bufs = { string.rep("\0", 12), string.pack("<i4", 12) },
        ptrs = { 3, 4 },
    })
    if r.ret ~= 0 then return nil, r.errno end
    local pid, uid, gid = string.unpack("<i4I4I4", r.out_bufs[1])
    return { pid = pid, uid = uid, gid = gid }
end

--- socketpair(AF_UNIX, SOCK_STREAM). Returns the two fds, or nil, errno.
function M.socketpair(who)
    local r = who:syscall(M.NR.socketpair, {
        args = { 1, 1, 0, 0 }, bufs = { string.rep("\0", 8) }, ptrs = { 3 },
    })
    if r.ret ~= 0 then return nil, r.errno end
    local a, b = string.unpack("<i4i4", r.out_bufs[1])
    return a, b
end

-- ---- netlink ---------------------------------------------------------

M.AF_NETLINK, M.SOCK_RAW = 16, 3
M.NETLINK_ROUTE, M.NETLINK_USERSOCK = 0, 2
M.RTM_NEWLINK, M.RTM_GETLINK = 16, 18
M.NLMSG_ERROR, M.NLMSG_DONE = 2, 3
M.NLM_F_REQUEST, M.NLM_F_ACK, M.NLM_F_DUMP = 0x001, 0x004, 0x300
M.MSG_DONTWAIT = 0x40

--- socket(AF_NETLINK, SOCK_RAW, proto). Returns fd, or nil, errno.
function M.nl_open(who, proto)
    local r = who:syscall(M.NR.socket, M.AF_NETLINK, M.SOCK_RAW,
        proto or M.NETLINK_ROUTE)
    if r.ret < 0 then return nil, r.errno end
    return r.ret
end

--- struct sockaddr_nl.
function M.sockaddr_nl(pid, groups)
    return string.pack("<I2I2I4I4", M.AF_NETLINK, 0, pid or 0, groups or 0)
end

function M.nl_bind(who, fd, pid, groups)
    return who:syscall(M.NR.bind, {
        args = { fd, 0, 12 }, bufs = { M.sockaddr_nl(pid, groups) }, ptrs = { 1 },
    })
end

--- The netlink port the kernel assigned this socket.
function M.nl_port(who, fd)
    local r = who:syscall(M.NR.getsockname, {
        args = { fd, 0, 0 },
        bufs = { string.rep("\0", 12), string.pack("<i4", 12) },
        ptrs = { 1, 2 },
    })
    if r.ret ~= 0 then return nil, r.errno end
    return (string.unpack("<I4", r.out_bufs[1], 5))
end

--- One netlink message: header plus body.
function M.nlmsg(mtype, flags, seq, body)
    return string.pack("<I4I2I2I4I4", 16 + #body, mtype, flags, seq or 1, 0) .. body
end

--- struct ifinfomsg, 16 bytes.
function M.ifinfomsg(index, flags, change)
    return string.pack("<I1I1I2i4I4I4", 0, 0, 0, index or 0, flags or 0, change or 0)
end

--- sendto(2) a netlink message, optionally to another port.
function M.nl_send(who, fd, msg, dst_port)
    if dst_port then
        return who:syscall(M.NR.sendto, {
            args = { fd, 0, #msg, 0, 0, 12 },
            bufs = { msg, M.sockaddr_nl(dst_port, 0) },
            ptrs = { 1, 4 },
        })
    end
    return who:syscall(M.NR.sendto, {
        args = { fd, 0, #msg, 0, 0, 0 }, bufs = { msg }, ptrs = { 1 },
    })
end

--- recvfrom(2) one datagram. Returns the bytes, or nil, errno.
function M.nl_recv(who, fd, flags, size)
    size = size or 32768
    local r = who:syscall(M.NR.recvfrom, {
        args = { fd, 0, size, flags or 0, 0, 0 },
        bufs = { string.rep("\0", size) },
        ptrs = { 1 },
    })
    if r.ret < 0 then return nil, r.errno end
    return r.out_bufs[1]:sub(1, r.ret)
end

--- Read datagrams until the socket is empty. Returns how many.
function M.nl_drain(who, fd, limit)
    local n = 0
    while n < (limit or 200) do
        local data = M.nl_recv(who, fd, M.MSG_DONTWAIT)
        if not data or #data == 0 then break end
        n = n + 1
    end
    return n
end

--- The `error` field of the NLMSG_ERROR reply to a request, negated to
--- a positive errno; 0 for an ack. Returns nil plus a description when
--- the reply is not an error message.
function M.nl_ack(who, fd)
    local data = M.nl_recv(who, fd)
    if not data then return nil, "no reply" end
    local _, mtype = string.unpack("<I4I2", data)
    if mtype ~= M.NLMSG_ERROR then return nil, "message type " .. mtype end
    local err = string.unpack("<i4", data, 17)
    return -err
end

--- RTM_GETLINK as a dump: the request every caller may make.
function M.rtm_getlink_dump(who, fd, seq)
    return M.nl_send(who, fd,
        M.nlmsg(M.RTM_GETLINK, M.NLM_F_REQUEST | M.NLM_F_DUMP, seq, M.ifinfomsg()))
end

--- RTM_NEWLINK on the loopback interface, asking for an ack: a
--- configuration request, and a TCB operation on Peios.
function M.rtm_newlink(who, fd, seq)
    return M.nl_send(who, fd,
        M.nlmsg(M.RTM_NEWLINK, M.NLM_F_REQUEST | M.NLM_F_ACK, seq,
            M.ifinfomsg(1, 0, 1)))
end

--- Send RTM_NEWLINK and return the errno it is answered with (0 = ack).
function M.newlink_errno(who, fd, seq)
    local s = M.nl_send(who, fd, M.nlmsg(M.RTM_NEWLINK,
        M.NLM_F_REQUEST | M.NLM_F_ACK, seq, M.ifinfomsg(1, 0, 1)))
    if s.ret < 0 then return nil, "sendto: " .. sys.errname(s.errno) end
    return M.nl_ack(who, fd)
end

-- recvmsg(2) with a control buffer, for SCM_CREDENTIALS.
M.SCM_CREDENTIALS = 2

--- recvmsg(2) returning the payload and the first cmsg. Non-blocking.
function M.recvmsg_with_cmsg(who, fd, size)
    size = size or 8192
    local iovbuf = string.rep("\0", size)
    local ctl = string.rep("\0", 256)
    local iov = string.pack("<I8I8", 0, #iovbuf)
    -- struct msghdr: name, namelen, iov, iovlen, control, controllen, flags
    local mh = string.pack("<I8I4I4I8I8I8I8I4I4", 0, 0, 0, 0, 1, 0, #ctl, 0, 0)
    local r = who:syscall(M.NR.recvmsg, {
        args = { fd, 0, M.MSG_DONTWAIT },
        bufs = { mh, iov, iovbuf, ctl },
        ptrs = { 1 },
        nested = {
            { parent = 1, child = 2, offset = 16 },
            { parent = 2, child = 3, offset = 0 },
            { parent = 1, child = 4, offset = 32 },
        },
    })
    if r.ret < 0 then return nil, r.errno end
    local c = r.out_bufs[4]
    local clen, level, ctype = string.unpack("<I8I4I4", c)
    local out = { data = r.out_bufs[3]:sub(1, r.ret), cmsg_level = level,
                  cmsg_type = ctype, cmsg_len = clen }
    if clen >= 28 then
        local pid, uid, gid = string.unpack("<i4I4I4", c, 17)
        out.creds = { pid = pid, uid = uid, gid = gid }
    end
    return out
end

M.NR.sendmsg = 46
M.NR.getpid = 39

--- sendmsg(2) carrying one SCM_CREDENTIALS control message.
---
--- The kernel accepts a uid the sender does not hold only from a caller
--- with CAP_SETUID, which the switchboard always allows — so this is the
--- forgery §3.10.3 says is possible. Returns the raw syscall result.
function M.sendmsg_with_creds(who, fd, payload, ucred)
    local cmsg = string.pack("<I8I4I4i4I4I4", 28, M.SOL_SOCKET, M.SCM_CREDENTIALS,
        ucred.pid, ucred.uid, ucred.gid) .. string.rep("\0", 4)
    local iov = string.pack("<I8I8", 0, #payload)
    local mh = string.pack("<I8I4I4I8I8I8I8I4I4", 0, 0, 0, 0, 1, 0, #cmsg, 0, 0)
    return who:syscall(M.NR.sendmsg, {
        args = { fd, 0, 0 },
        bufs = { mh, iov, payload, cmsg },
        ptrs = { 1 },
        nested = {
            { parent = 1, child = 2, offset = 16 },
            { parent = 2, child = 3, offset = 0 },
            { parent = 1, child = 4, offset = 32 },
        },
    })
end

--- setsockopt(SOL_SOCKET, SO_PASSCRED, 1).
function M.set_passcred(who, fd)
    return who:syscall(M.NR.setsockopt, {
        args = { fd, M.SOL_SOCKET, M.SO_PASSCRED, 0, 4 },
        bufs = { string.pack("<i4", 1) },
        ptrs = { 3 },
    })
end

return M
