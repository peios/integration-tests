-- AF_UNIX sockets and the `SOL_KACS` option level, for the peer-identity
-- cases of PKM §3.5.3.
--
-- A kernel-only guest has no libc, so every socket call here is the raw
-- syscall with its structures packed by hand: `struct sockaddr_un`,
-- `struct msghdr` with its `iovec` and its control buffer, and the
-- `cmsghdr` a `KACS_SCM_TOKEN` arrives in. x86_64 layouts throughout.
--
-- The identity model this drives is PKM §3.5.3: a connection captures
-- the client's identity at `connect()` and the listener's at `listen()`,
-- `KACS_SO_PEER_TOKEN` reads the conveyed-identity register back as a
-- token fd, and per-message identity travels either automatically
-- (`KACS_SO_PASS_TOKEN`) or explicitly (a `KACS_SCM_TOKEN` cmsg).
--
-- Every socket here is a *pathname* socket unless a case asks for an
-- abstract one: an abstract bind installs a socket security descriptor
-- (§3.12) whose default DACL grants only the binder, Administrators and
-- SYSTEM, which would deny a cross-principal connect before the
-- identity question is reached.

local sys = require("helpers.sys")

local M = {}

M.NR = {
    socket = 41, connect = 42, accept = 43, sendto = 44, recvfrom = 45,
    sendmsg = 46, recvmsg = 47, shutdown = 48, bind = 49, listen = 50,
    getsockname = 51, getpeername = 52, socketpair = 53,
    setsockopt = 54, getsockopt = 55, accept4 = 288,
}

M.AF_UNIX, M.AF_INET = 1, 2
M.SOCK = { STREAM = 1, DGRAM = 2, SEQPACKET = 5 }

-- <pkm/socket.h>. SOL_KACS sits far above the upstream SOL_* range.
M.SOL_KACS = 4096
M.SO = {
    PEER_TOKEN = 1, IMPERSONATION_LEVEL = 2, PASS_TOKEN = 3, RESTAMP = 4,
}
M.SCM_TOKEN = 1

M.MSG = { PEEK = 0x02, CTRUNC = 0x08, TRUNC = 0x20, DONTWAIT = 0x40 }

--- The errnos the socket surface names that `sys.E` does not carry.
M.E = { NOTSOCK = 88, NOPROTOOPT = 92, NOTCONN = 107, PIPE = 32 }

--- `sys.errname`, extended with the socket-only errnos.
function M.errname(errno)
    for name, value in pairs(M.E) do
        if value == errno then return "E" .. name .. " (" .. errno .. ")" end
    end
    return sys.errname(errno)
end

local SOCKADDR_UN = 110  -- sizeof(struct sockaddr_un)

--- A `struct sockaddr_un` for a pathname (or, with a leading NUL, an
--- abstract name). Returns the bytes and the length to pass.
function M.sockaddr(path)
    local body = path .. string.rep("\0", SOCKADDR_UN - 2 - #path)
    -- An abstract name is exactly as long as its bytes; a pathname is
    -- NUL-terminated and the full structure length is accepted.
    local len = path:sub(1, 1) == "\0" and (2 + #path) or SOCKADDR_UN
    return string.pack("<I2", M.AF_UNIX) .. body, len
end

-- Sockets -------------------------------------------------------------------

--- socket(2). Returns fd, or nil, errno.
function M.socket(who, family, stype, protocol)
    local r = who:syscall(M.NR.socket, family or M.AF_UNIX,
        stype or M.SOCK.STREAM, protocol or 0)
    if r.ret < 0 then return nil, r.errno end
    return r.ret
end

--- socketpair(2). Returns the two fds, or nil, errno.
function M.socketpair(who, stype)
    local r = who:syscall(M.NR.socketpair, {
        args = { M.AF_UNIX, stype or M.SOCK.STREAM, 0, 0 },
        bufs = { string.rep("\0", 8) }, ptrs = { 3 },
    })
    if r.ret ~= 0 then return nil, r.errno end
    return string.unpack("<i4i4", r.out_bufs[1])
end

--- bind(2) to a AF_UNIX name. Returns the raw syscall result.
function M.bind(who, fd, path)
    local addr, len = M.sockaddr(path)
    return who:syscall(M.NR.bind, {
        args = { fd, 0, len }, bufs = { addr }, ptrs = { 1 },
    })
end

--- listen(2). Returns the raw syscall result.
function M.listen(who, fd, backlog)
    return who:syscall(M.NR.listen, fd, backlog or 8)
end

--- connect(2) to a AF_UNIX name. Returns the raw syscall result.
---
--- A stream connect against a listening socket with backlog to spare
--- completes without anyone calling `accept()`, so a test drives both
--- ends from one thread: bind, listen, connect, accept.
function M.connect(who, fd, path)
    local addr, len = M.sockaddr(path)
    return who:syscall(M.NR.connect, {
        args = { fd, 0, len }, bufs = { addr }, ptrs = { 1 },
    })
end

--- accept4(2) with no address. Returns fd, or nil, errno.
function M.accept(who, fd, flags)
    local r = who:syscall(M.NR.accept4, { args = { fd, 0, 0, flags or 0 } })
    if r.ret < 0 then return nil, r.errno end
    return r.ret
end

--- A connected pair on `path`: the listener, the accepted end and the
--- connecting end, all in `who`. Returns listener, accepted, client, or
--- nil and a message naming the step that failed.
function M.connected(who, path, stype)
    local srv, e = M.socket(who, M.AF_UNIX, stype or M.SOCK.STREAM)
    if not srv then return nil, "socket: " .. M.errname(e) end
    local r = M.bind(who, srv, path)
    if r.ret ~= 0 then return nil, "bind: " .. M.errname(r.errno) end
    r = M.listen(who, srv)
    if r.ret ~= 0 then return nil, "listen: " .. M.errname(r.errno) end
    local cli
    cli, e = M.socket(who, M.AF_UNIX, stype or M.SOCK.STREAM)
    if not cli then return nil, "socket: " .. M.errname(e) end
    r = M.connect(who, cli, path)
    if r.ret ~= 0 then return nil, "connect: " .. M.errname(r.errno) end
    local acc
    acc, e = M.accept(who, srv)
    if not acc then return nil, "accept: " .. M.errname(e) end
    return srv, acc, cli
end

-- SOL_KACS options -----------------------------------------------------------

--- getsockopt(2) at SOL_KACS for a 4-byte option. Returns the value, or
--- nil, errno.
function M.getopt(who, fd, optname)
    local r = who:syscall(M.NR.getsockopt, {
        args = { fd, M.SOL_KACS, optname, 0, 0 },
        bufs = { string.pack("<i4", -1), string.pack("<i4", 4) },
        ptrs = { 3, 4 },
    })
    if r.ret ~= 0 then return nil, r.errno end
    return (string.unpack("<i4", r.out_bufs[1]))
end

--- getsockopt(2) at SOL_KACS with a caller-chosen optlen, for the cases
--- whose subject is the length contract. Returns the raw result.
function M.getopt_raw(who, fd, optname, optlen)
    return who:syscall(M.NR.getsockopt, {
        args = { fd, M.SOL_KACS, optname, 0, 0 },
        bufs = { string.rep("\0", math.max(optlen, 1)), string.pack("<i4", optlen) },
        ptrs = { 3, 4 },
    })
end

--- setsockopt(2) at SOL_KACS for a 4-byte option. Returns the raw result.
function M.setopt(who, fd, optname, value)
    return who:syscall(M.NR.setsockopt, {
        args = { fd, M.SOL_KACS, optname, 0, 4 },
        bufs = { string.pack("<i4", value) }, ptrs = { 3 },
    })
end

--- `KACS_SO_PEER_TOKEN`: a token fd for this end's conveyed-identity
--- register. Returns fd, or nil, errno.
function M.peer_token(who, fd)
    return M.getopt(who, fd, M.SO.PEER_TOKEN)
end

--- `KACS_SO_IMPERSONATION_LEVEL`, the maximum level identity leaving
--- this end may be captured at.
function M.set_level(who, fd, level)
    return M.setopt(who, fd, M.SO.IMPERSONATION_LEVEL, level)
end

function M.level(who, fd) return M.getopt(who, fd, M.SO.IMPERSONATION_LEVEL) end

--- `KACS_SO_PASS_TOKEN`, sender-side automatic identity conveyance.
function M.set_pass_token(who, fd, on)
    return M.setopt(who, fd, M.SO.PASS_TOKEN, on and 1 or 0)
end

function M.pass_token(who, fd) return M.getopt(who, fd, M.SO.PASS_TOKEN) end

--- `KACS_SO_RESTAMP`: replace the identity a listener conveys with the
--- caller's own. Returns the raw result.
function M.restamp(who, fd) return M.setopt(who, fd, M.SO.RESTAMP, 0) end

-- sendmsg / recvmsg ----------------------------------------------------------

-- struct msghdr, x86_64: name, namelen (+pad), iov, iovlen, control,
-- controllen, flags (+pad). 56 bytes.
local MSGHDR_SIZE = 56
local MSGHDR = { iov = 16, iovlen = 24, control = 32, controllen = 40, flags = 48 }
-- struct cmsghdr: size_t len; int level; int type. Data follows, and
-- each cmsg is padded to an 8-byte boundary.
local CMSG_HDR = 16
local function cmsg_len(n) return CMSG_HDR + n end
local function cmsg_space(n) return CMSG_HDR + ((n + 7) & ~7) end
M.cmsg_space = cmsg_space

--- A `KACS_SCM_TOKEN` control buffer for one token fd.
function M.token_cmsg(fd)
    return string.pack("<I8I4I4i4", cmsg_len(4), M.SOL_KACS, M.SCM_TOKEN, fd)
        .. "\0\0\0\0"
end

--- sendmsg(2) of `data`, optionally attaching `token_fd` as a
--- `KACS_SCM_TOKEN` ancillary message. `opts.raw_control` overrides the
--- control buffer outright, for the malformed-cmsg cases; `opts.to`
--- names a destination (a datagram send needs no connection);
--- `opts.flags` are send flags.
---
--- Returns the raw syscall result.
function M.sendmsg(who, fd, data, opts)
    opts = opts or {}
    local control = opts.raw_control
    if not control and opts.token_fd then control = M.token_cmsg(opts.token_fd) end
    local bufs = { "", string.pack("<I8I8", 0, #data), data }
    local nested = {
        { parent = 1, child = 2, offset = MSGHDR.iov },
        { parent = 2, child = 3, offset = 0 },
    }
    if control then
        bufs[#bufs + 1] = control
        nested[#nested + 1] = { parent = 1, child = #bufs, offset = MSGHDR.control }
    end
    local namelen = 0
    if opts.to then
        local addr, alen = M.sockaddr(opts.to)
        namelen = alen
        bufs[#bufs + 1] = addr
        nested[#nested + 1] = { parent = 1, child = #bufs, offset = 0 }
    end
    bufs[1] = string.pack("<I8I4I4I8I8I8I8I4I4", 0, namelen, 0, 0, 1, 0,
        control and #control or 0, 0, 0)
    assert(#bufs[1] == MSGHDR_SIZE, "msghdr is " .. #bufs[1])
    return who:syscall(M.NR.sendmsg, {
        args = { fd, 0, opts.flags or 0 }, bufs = bufs, ptrs = { 1 }, nested = nested,
    })
end

--- recvmsg(2) into a buffer of `size` bytes with room for `opts.cmsg`
--- ancillary bytes (default: one token cmsg; pass 0 for none).
---
--- Returns a table: `ret`, `errno`, `data`, `flags`, `tokens` (the fds
--- from every `KACS_SCM_TOKEN` cmsg, in order), `cmsgs` (every cmsg as
--- `{ level, type, data }`), and `ctrunc`.
function M.recvmsg(who, fd, size, opts)
    opts = opts or {}
    local control_len = opts.cmsg == nil and cmsg_space(4) or opts.cmsg
    local bufs = { "", string.pack("<I8I8", 0, size), string.rep("\0", size) }
    local nested = {
        { parent = 1, child = 2, offset = MSGHDR.iov },
        { parent = 2, child = 3, offset = 0 },
    }
    if control_len > 0 then
        bufs[4] = string.rep("\0", control_len)
        nested[#nested + 1] = { parent = 1, child = 4, offset = MSGHDR.control }
    end
    bufs[1] = string.pack("<I8I4I4I8I8I8I8I4I4", 0, 0, 0, 0, 1, 0,
        control_len, 0, 0)
    local r = who:syscall(M.NR.recvmsg, {
        args = { fd, 0, opts.flags or 0 }, bufs = bufs, ptrs = { 1 }, nested = nested,
    })
    local out = { ret = r.ret, errno = r.errno, tokens = {}, cmsgs = {} }
    if r.ret < 0 then return out end
    out.data = r.out_bufs[3]:sub(1, r.ret)
    local hdr = r.out_bufs[1]
    out.flags = string.unpack("<I4", hdr, MSGHDR.flags + 1)
    out.ctrunc = (out.flags & M.MSG.CTRUNC) ~= 0
    local written = string.unpack("<I8", hdr, MSGHDR.controllen + 1)
    if control_len > 0 and written > 0 then
        local ctl, at = r.out_bufs[4], 1
        while at + CMSG_HDR <= written + 1 do
            local len, level, ctype = string.unpack("<I8I4I4", ctl, at)
            if len < CMSG_HDR then break end
            local body = ctl:sub(at + CMSG_HDR, at + len - 1)
            out.cmsgs[#out.cmsgs + 1] = { level = level, type = ctype, data = body }
            if level == M.SOL_KACS and ctype == M.SCM_TOKEN and #body >= 4 then
                out.tokens[#out.tokens + 1] = string.unpack("<i4", body)
            end
            at = at + ((len + 7) & ~7)
        end
    end
    return out
end

--- sendto(2) to a AF_UNIX name, for datagram cases.
function M.sendto(who, fd, data, path)
    local addr, len = M.sockaddr(path)
    return who:syscall(M.NR.sendto, {
        args = { fd, 0, #data, 0, 0, len },
        bufs = { data, addr }, ptrs = { 1, 4 },
    })
end

return M
