-- NTFE, the kernel's packet engine (PKM chapter 6), driven on the
-- kernel-only profile, where there is no registryd, no netd and no `ip`.
--
-- Three halves.
--
-- The *policy* is a `Machine\System\Network` tree served from Lua by
-- helpers/lcs. `ntfe.engine(vm, policy)` seeds it, registers the hive
-- and returns a handle; `E:replace(policy)` swaps the whole policy and
-- returns once the engine has walked it (§6.5, "In force"). A test of
-- ingestion itself writes through the real registry calls instead
-- (`E:write`, `E:create`, or helpers/lcs directly) and then `E:settle`s.
--
-- The *engine* is questioned through `/dev/peios-ntfe`: the status, the
-- verdict stream, and the counters, flows and listeners dumps, decoded
-- here by the layouts of §6.A.
--
-- The *traffic* is made with raw syscalls: interface ioctls instead of
-- `ip`, non-blocking sockets and poll() so nothing a DROP swallows can
-- hang the agent, and AF_PACKET for frames no socket would send.
--
-- Numbers: `<pkm/ntfe.h>` (ABI 5), `<linux/sockios.h>`, x86_64 syscalls.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")

local M = {}

M.DEVICE = "/dev/peios-ntfe"
M.ABI = 5
M.NETWORK_KEY = "Machine\\System\\Network"
M.RULES_KEY = M.NETWORK_KEY .. "\\Rules"

local function zeros(n) return string.rep("\0", n) end

local function cstr_at(buf, at, len)
    local s = buf:sub(at, at + len - 1)
    return (s:match("^[^%z]*"))
end

-- ---- ABI constants (§6.A) --------------------------------------------

M.SEAT = { INGRESS = 1, EGRESS = 2, LOCAL_IN = 3, LOCAL_OUT = 4 }
M.LAYER = { PACKET = 0, RAWPACKET = 1, FLOW = 2 }
M.VERDICT = { PASS = 0, REJECT = 1, DROP = 2 }
M.REJECT = { REFUSED = 0, PROHIBITED = 1 }
M.DIR = { IN = 0, OUT = 1 }
M.FLOW_STATE = { ABSENT = 0, NEW = 1, ESTABLISHED = 2, RELATED = 3,
                 INVALID = 4, UNTRACKED = 5 }
M.EV_F = { BACKSTOP = 0x01, FAIL_CLOSED = 0x02, REJECT_DEGRADED = 0x04,
           REJUDGED = 0x08, IDENTITY_UNRESOLVED = 0x10 }
M.LOCAL = { ABSENT = 0, PROGRAM = 1, KERNEL = 2, SHARED = 3, NONE = 4 }
M.KEY = { SRC_ADDR = 0x01, DST_ADDR = 0x02, INTERFACE = 0x04 }

M.EVENT_SIZE = 456
M.COUNTER_REC_SIZE = 232
M.FLOW_REC_SIZE = 568
M.LISTENER_REC_SIZE = 168
M.READ_MAX = 64

-- `struct peios_ntfe_status`, every member a u64, in struct order.
M.STATUS_FIELDS = {
    "abi", "generation", "enforcing", "events_dropped",
    "seen_ingress", "seen_egress", "seen_local_in", "deferred",
    "fallback_judged", "parse_errors", "judged", "permissive",
    "fail_closed", "verdict_pass", "verdict_drop", "verdict_reject",
    "reject_degraded", "fx_tags", "fx_counts", "fx_reports", "fx_prompts",
    "last_ingest_error", "last_ingest_t_ns",
    "tag_writes", "tag_untracked", "tag_refused",
    "count_writes", "count_key_absent", "count_refused",
    "reports_emitted", "counter_cells", "reporting_level",
    "seen_local_out", "flow_judged", "flow_cached", "flow_rejudged",
    "flow_expired", "flow_uncached",
    "refusals_emitted", "refusals_bypassed", "teardowns_emitted",
    "identity_unresolved",
    "changes_noted", "changes_walked", "contexts", "_reserved",
}
M.STATUS_SIZE = #M.STATUS_FIELDS * 8

local function ioc(dir, nr, size)
    return (dir << 30) | (size << 16) | (0x4E << 8) | nr -- type byte 'N'
end
M.ioc = ioc
M.IOC = {
    STATUS = ioc(2, 1, M.STATUS_SIZE),
    COUNTERS = ioc(3, 2, 24),
    FLOWS = ioc(3, 3, 24),
    LISTENERS = ioc(3, 4, 24),
}

-- ---- names -----------------------------------------------------------

--- FNV-1a-64 of a name: the identity the tag and counter stores key by,
--- and a sentence's `rule_hash` over the attributing path (§6.6, §6.B).
function M.name_hash(s)
    local h = 0xcbf29ce484222325
    for i = 1, #s do
        h = (h ~ s:byte(i)) * 0x100000001b3
    end
    return h
end

-- ---- addresses -------------------------------------------------------

M.AF_INET, M.AF_INET6, M.AF_PACKET = 2, 10, 17
M.SOCK_STREAM, M.SOCK_DGRAM, M.SOCK_RAW = 1, 2, 3
M.SOCK_NONBLOCK = 0x800
M.IPPROTO = { ICMP = 1, TCP = 6, UDP = 17, ICMPV6 = 58, SCTP = 132 }
M.ETH_P = { IP = 0x0800, ARP = 0x0806, VLAN = 0x8100, IPV6 = 0x86DD, ALL = 0x0003 }

--- "10.0.0.1" → 4 bytes, network order.
function M.ip4(s)
    local a, b, c, d = s:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    assert(a, "not an IPv4 address: " .. tostring(s))
    return string.char(tonumber(a), tonumber(b), tonumber(c), tonumber(d))
end

--- 4 bytes → "10.0.0.1".
function M.ip4_text(b)
    return string.format("%d.%d.%d.%d", b:byte(1, 4))
end

--- "fd00::1" → 16 bytes. Handles `::` and plain hextets; no embedded v4.
function M.ip6(s)
    local head, tail = s:match("^(.-)::(.*)$")
    local function groups(part)
        local out = {}
        for g in part:gmatch("[^:]+") do out[#out + 1] = tonumber(g, 16) end
        return out
    end
    local words
    if head then
        local h, t = groups(head), groups(tail)
        words = h
        for _ = 1, 8 - #h - #t do words[#words + 1] = 0 end
        for _, w in ipairs(t) do words[#words + 1] = w end
    else
        words = groups(s)
    end
    assert(#words == 8, "not an IPv6 address: " .. tostring(s))
    local out = {}
    for _, w in ipairs(words) do out[#out + 1] = string.pack(">I2", w) end
    return table.concat(out)
end

--- A sockaddr for `addr` (dotted v4 or a v6 containing ':') and `port`.
--- Returns the bytes and the family.
function M.sockaddr(addr, port, scope_ifindex)
    if addr:find(":", 1, true) then
        return string.pack("<I2", M.AF_INET6) .. string.pack(">I2", port)
            .. string.pack("<I4", 0) .. M.ip6(addr)
            .. string.pack("<I4", scope_ifindex or 0), M.AF_INET6
    end
    return string.pack("<I2", M.AF_INET) .. string.pack(">I2", port)
        .. M.ip4(addr) .. zeros(8), M.AF_INET
end

-- ---- interfaces, without `ip` ----------------------------------------

local NR = {
    socket = 41, connect = 42, accept4 = 288, sendto = 44, recvfrom = 45,
    shutdown = 48, bind = 49, listen = 50, getsockname = 51,
    setsockopt = 54, getsockopt = 55,
}
M.NR = NR

local SIOC = {
    GIFFLAGS = 0x8913, SIFFLAGS = 0x8914, SIFADDR = 0x8916,
    SIFNETMASK = 0x891c, GIFHWADDR = 0x8927, GIFINDEX = 0x8933,
}
M.IFF_UP, M.IFF_LOOPBACK = 0x1, 0x8

local function ifreq(name, payload)
    return name .. zeros(16 - #name) .. payload .. zeros(24 - #payload)
end

local function if_ioctl(who, family, cmd, req)
    local fd = who:syscall(NR.socket, family, M.SOCK_DGRAM, 0)
    if fd.ret < 0 then return nil, fd.errno end
    local r = who:syscall(sys.NR.ioctl, {
        args = { fd.ret, cmd, 0 }, bufs = { req }, ptrs = { 2 },
    })
    sys.close(who, fd.ret)
    if r.ret ~= 0 then return nil, r.errno end
    return r.out_bufs[1]
end

--- The interface's flags word, or nil, errno.
function M.if_flags(who, name)
    local out, errno = if_ioctl(who, M.AF_INET, SIOC.GIFFLAGS, ifreq(name, ""))
    if not out then return nil, errno end
    return (string.unpack("<I2", out, 17))
end

--- Bring an interface up. Returns true, or nil, errno.
function M.if_up(who, name)
    local flags, errno = M.if_flags(who, name)
    if not flags then return nil, errno end
    local out, e = if_ioctl(who, M.AF_INET, SIOC.SIFFLAGS,
        ifreq(name, string.pack("<I2", flags | M.IFF_UP)))
    if not out then return nil, e end
    return true
end

--- Take an interface down.
function M.if_down(who, name)
    local flags, errno = M.if_flags(who, name)
    if not flags then return nil, errno end
    local out, e = if_ioctl(who, M.AF_INET, SIOC.SIFFLAGS,
        ifreq(name, string.pack("<I2", flags & ~M.IFF_UP)))
    if not out then return nil, e end
    return true
end

--- The interface's index, or nil, errno.
function M.if_index(who, name)
    local out, errno = if_ioctl(who, M.AF_INET, SIOC.GIFINDEX, ifreq(name, ""))
    if not out then return nil, errno end
    return (string.unpack("<i4", out, 17))
end

--- The interface's 6-byte hardware address, or nil, errno.
function M.if_hwaddr(who, name)
    local out, errno = if_ioctl(who, M.AF_INET, SIOC.GIFHWADDR, ifreq(name, ""))
    if not out then return nil, errno end
    return out:sub(19, 24)
end

--- Give an interface an address and bring it up: "10.0.0.1" with a
--- prefix length (default 24), or a v6 address (default /64).
function M.if_addr(who, name, addr, prefix)
    if addr:find(":", 1, true) then
        local index, errno = M.if_index(who, name)
        if not index then return nil, errno end
        -- struct in6_ifreq: address, prefix length, interface index.
        local req = M.ip6(addr) .. string.pack("<I4i4", prefix or 64, index)
        local out, e = if_ioctl(who, M.AF_INET6, SIOC.SIFADDR, req)
        if not out then return nil, e end
        return M.if_up(who, name)
    end
    local out, errno = if_ioctl(who, M.AF_INET, SIOC.SIFADDR,
        ifreq(name, (M.sockaddr(addr, 0))))
    if not out then return nil, errno end
    local bits = prefix or 24
    local mask = bits == 0 and 0 or ((0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF)
    out, errno = if_ioctl(who, M.AF_INET, SIOC.SIFNETMASK,
        ifreq(name, string.pack("<I2", M.AF_INET) .. zeros(2)
            .. string.pack(">I4", mask)))
    if not out then return nil, errno end
    return M.if_up(who, name)
end

-- ---- sockets that cannot hang ----------------------------------------

M.POLLIN, M.POLLOUT, M.POLLERR, M.POLLHUP = 0x1, 0x4, 0x8, 0x10

--- poll(2) one fd. Returns the revents (0 on timeout).
function M.poll(who, fd, events, timeout_ms)
    local r = who:syscall(sys.NR.poll, {
        args = { 0, 1, timeout_ms or 0 },
        bufs = { string.pack("<i4i2i2", fd, events, 0) }, ptrs = { 0 },
    })
    if r.ret <= 0 then return 0 end
    return (select(3, string.unpack("<i4I2I2", r.out_bufs[1])))
end

--- The socket's pending error (SO_ERROR), clearing it.
function M.so_error(who, fd)
    local r = who:syscall(NR.getsockopt, {
        args = { fd, 1, 4, 0, 0 },
        bufs = { zeros(4), string.pack("<I4", 4) }, ptrs = { 3, 4 },
    })
    return (string.unpack("<i4", r.out_bufs[1]))
end

local function set_int_opt(who, fd, level, opt, value)
    return who:syscall(NR.setsockopt, {
        args = { fd, level, opt, 0, 4 },
        bufs = { string.pack("<i4", value) }, ptrs = { 3 },
    })
end
M.set_int_opt = set_int_opt

--- A non-blocking socket of `family`/`socktype`, optionally bound to
--- `o.bind = { addr, port }`. Returns fd, or nil, errno.
function M.socket(who, family, socktype, o)
    o = o or {}
    local r = who:syscall(NR.socket, family, socktype | M.SOCK_NONBLOCK,
        o.protocol or 0)
    if r.ret < 0 then return nil, r.errno end
    local fd = r.ret
    set_int_opt(who, fd, 1, 2, 1) -- SO_REUSEADDR
    if o.bind then
        local sa = M.sockaddr(o.bind[1], o.bind[2])
        local b = who:syscall(NR.bind, {
            args = { fd, 0, #sa }, bufs = { sa }, ptrs = { 1 },
        })
        if b.ret ~= 0 then sys.close(who, fd); return nil, b.errno end
    end
    return fd
end

--- A TCP listener on `addr`:`port`. Returns fd, or nil, errno.
function M.tcp_listen(who, addr, port)
    local _, family = M.sockaddr(addr, port)
    local fd, errno = M.socket(who, family, M.SOCK_STREAM, { bind = { addr, port } })
    if not fd then return nil, errno end
    local r = who:syscall(NR.listen, fd, 16)
    if r.ret ~= 0 then sys.close(who, fd); return nil, r.errno end
    return fd
end

--- accept(2) one pending connection within `timeout_ms` (default 1000).
--- Returns the connected fd, or nil.
function M.tcp_accept(who, listener, timeout_ms)
    if M.poll(who, listener, M.POLLIN, timeout_ms or 1000) & M.POLLIN == 0 then
        return nil
    end
    local r = who:syscall(NR.accept4, listener, 0, 0, M.SOCK_NONBLOCK)
    if r.ret < 0 then return nil, r.errno end
    return r.ret
end

--- Connect a TCP socket to `addr`:`port`, waiting at most `timeout_ms`
--- (default 1000) for the handshake.
---
--- Returns `fd` when it connected; `nil, errno` when the stack refused
--- it (ECONNREFUSED after a RST, EHOSTUNREACH after an ICMP error);
--- `nil, "timeout"` when nothing answered — what a DROP looks like from
--- here. `o.bind = { addr, port }` fixes the source.
function M.tcp_connect(who, addr, port, timeout_ms, o)
    local sa, family = M.sockaddr(addr, port, o and o.scope)
    local fd, errno = M.socket(who, family, M.SOCK_STREAM, o)
    if not fd then return nil, errno end
    local r = who:syscall(NR.connect, {
        args = { fd, 0, #sa }, bufs = { sa }, ptrs = { 1 },
    })
    if r.ret ~= 0 and r.errno ~= sys.E.INPROGRESS then
        sys.close(who, fd)
        return nil, r.errno
    end
    local revents = M.poll(who, fd, M.POLLOUT, timeout_ms or 1000)
    if revents == 0 then
        sys.close(who, fd)
        return nil, "timeout"
    end
    local err = M.so_error(who, fd)
    if err ~= 0 then
        sys.close(who, fd)
        return nil, err
    end
    return fd
end

--- A UDP socket connected to `addr`:`port` (so ICMP errors come back as
--- its SO_ERROR). Returns fd, or nil, errno.
function M.udp_connect(who, addr, port, o)
    local sa, family = M.sockaddr(addr, port, o and o.scope)
    local fd, errno = M.socket(who, family, M.SOCK_DGRAM, o)
    if not fd then return nil, errno end
    local r = who:syscall(NR.connect, {
        args = { fd, 0, #sa }, bufs = { sa }, ptrs = { 1 },
    })
    if r.ret ~= 0 then sys.close(who, fd); return nil, r.errno end
    return fd
end

--- A UDP socket bound to `addr`:`port`. Returns fd, or nil, errno.
function M.udp_bind(who, addr, port)
    local _, family = M.sockaddr(addr, port)
    return M.socket(who, family, M.SOCK_DGRAM, { bind = { addr, port } })
end

--- write(2) on a connected socket. Returns the raw result.
function M.send(who, fd, data)
    return who:syscall(sys.NR.write, {
        args = { fd, 0, #data }, bufs = { data }, ptrs = { 1 },
    })
end

--- sendto(2) on an unconnected socket.
function M.sendto(who, fd, data, addr, port, scope)
    local sa = M.sockaddr(addr, port, scope)
    return who:syscall(NR.sendto, {
        args = { fd, 0, #data, 0, 0, #sa }, bufs = { data, sa }, ptrs = { 1, 4 },
    })
end

--- Read what arrives on a socket within `timeout_ms` (default 500).
--- Returns the bytes; `nil, "timeout"` when nothing came; `nil, errno`
--- when the socket failed instead (a reset, a refusal).
function M.recv(who, fd, timeout_ms, size)
    local revents = M.poll(who, fd, M.POLLIN, timeout_ms or 500)
    if revents == 0 then return nil, "timeout" end
    size = size or 4096
    local r = who:syscall(sys.NR.read, {
        args = { fd, 0, size }, bufs = { zeros(size) }, ptrs = { 1 },
    })
    if r.ret < 0 then return nil, r.errno end
    return r.out_bufs[1]:sub(1, r.ret)
end

-- ---- frames (AF_PACKET) ----------------------------------------------

--- A non-blocking AF_PACKET/SOCK_RAW socket bound to interface `name`,
--- receiving every ethertype. Returns fd and the ifindex.
function M.packet_socket(who, name, ethertype)
    local index, errno = M.if_index(who, name)
    if not index then return nil, errno end
    local proto = ethertype or M.ETH_P.ALL
    local be = ((proto & 0xFF) << 8) | (proto >> 8)
    local r = who:syscall(NR.socket, M.AF_PACKET,
        M.SOCK_RAW | M.SOCK_NONBLOCK, be)
    if r.ret < 0 then return nil, r.errno end
    -- struct sockaddr_ll: family, protocol (BE), ifindex, hatype, pkttype,
    -- halen, addr[8].
    local sll = string.pack("<I2", M.AF_PACKET) .. string.pack(">I2", proto)
        .. string.pack("<i4I2I1I1", index, 0, 0, 0) .. zeros(8)
    local b = who:syscall(NR.bind, {
        args = { r.ret, 0, #sll }, bufs = { sll }, ptrs = { 1 },
    })
    if b.ret ~= 0 then sys.close(who, r.ret); return nil, b.errno end
    return r.ret, index
end

--- An Ethernet header. MACs are 6-byte strings.
function M.eth(dst, src, ethertype)
    return dst .. src .. string.pack(">I2", ethertype)
end

M.MAC_BROADCAST = string.rep("\xff", 6)

--- The Internet checksum of `bytes`.
function M.checksum(bytes)
    if #bytes % 2 == 1 then bytes = bytes .. "\0" end
    local sum = 0
    for i = 1, #bytes, 2 do
        sum = sum + (string.unpack(">I2", bytes, i))
    end
    while sum >> 16 ~= 0 do sum = (sum & 0xFFFF) + (sum >> 16) end
    return (~sum) & 0xFFFF
end

--- An IPv4 header (no options) for `payload_len` bytes of `protocol`.
--- `o`: ttl (64), tos (0), id (0), frag (the flags+offset word, 0).
function M.ipv4(src, dst, protocol, payload_len, o)
    o = o or {}
    local function header(csum)
        return string.pack(">I1I1I2I2I2I1I1I2", 0x45, o.tos or 0,
            20 + payload_len, o.id or 0, o.frag or 0, o.ttl or 64, protocol,
            csum) .. M.ip4(src) .. M.ip4(dst)
    end
    return header(M.checksum(header(0)))
end

--- A UDP datagram (header + data) with a correct checksum for v4.
function M.udp(src, dst, sport, dport, data)
    local len = 8 + #data
    local pseudo = M.ip4(src) .. M.ip4(dst) .. string.pack(">I1I1I2", 0, 17, len)
    local function seg(csum)
        return string.pack(">I2I2I2I2", sport, dport, len, csum) .. data
    end
    local csum = M.checksum(pseudo .. seg(0))
    if csum == 0 then csum = 0xFFFF end
    return seg(csum)
end

--- A TCP segment (no options) with a correct checksum for v4. `flags`
--- is the flag byte (FIN 0x01 .. CWR 0x80).
function M.tcp(src, dst, sport, dport, flags, o)
    o = o or {}
    local data = o.data or ""
    local pseudo = M.ip4(src) .. M.ip4(dst)
        .. string.pack(">I1I1I2", 0, 6, 20 + #data)
    local function seg(csum)
        return string.pack(">I2I2I4I4I1I1I2I2I2", sport, dport, o.seq or 1,
            o.ack or 0, 0x50, flags, o.window or 1024, csum, 0) .. data
    end
    return seg(M.checksum(pseudo .. seg(0)))
end
M.TCP = { FIN = 0x01, SYN = 0x02, RST = 0x04, PSH = 0x08, ACK = 0x10,
          URG = 0x20, ECE = 0x40, CWR = 0x80 }

--- An ICMP message (type, code, rest-of-header word, data).
function M.icmp(icmp_type, code, rest, data)
    data = data or ""
    local function msg(csum)
        return string.pack(">I1I1I2I4", icmp_type, code, csum, rest or 0) .. data
    end
    return msg(M.checksum(msg(0)))
end

--- An ARP request for `target_ip` from (`src_mac`, `src_ip`).
function M.arp_request(src_mac, src_ip, target_ip)
    return string.pack(">I2I2I1I1I2", 1, 0x0800, 6, 4, 1) .. src_mac
        .. M.ip4(src_ip) .. zeros(6) .. M.ip4(target_ip)
end

--- Send one frame on an AF_PACKET socket.
function M.send_frame(who, fd, frame)
    return M.send(who, fd, frame)
end

--- Dissect an Ethernet frame as far as the engine's facts go. Returns a
--- table: dst, src, ethertype, vlan, and for IPv4 `ip` = { src, dst,
--- protocol, ttl, tos, frag }, then `tcp` = { sport, dport, flags, seq,
--- ack }, `udp` = { sport, dport }, `icmp` = { type, code }.
function M.dissect(frame)
    local f = { dst = frame:sub(1, 6), src = frame:sub(7, 12) }
    local at = 13
    f.ethertype = string.unpack(">I2", frame, at); at = at + 2
    if f.ethertype == M.ETH_P.VLAN then
        f.vlan = string.unpack(">I2", frame, at) & 0x0FFF
        f.ethertype = string.unpack(">I2", frame, at + 2); at = at + 4
    end
    if f.ethertype == M.ETH_P.IP and #frame >= at + 19 then
        local vihl, tos, _, _, frag, ttl, proto = string.unpack(">I1I1I2I2I2I1I1", frame, at)
        f.ip = {
            src = M.ip4_text(frame:sub(at + 12, at + 15)),
            dst = M.ip4_text(frame:sub(at + 16, at + 19)),
            protocol = proto, ttl = ttl, tos = tos, frag = frag,
        }
        local l4 = at + (vihl & 0xF) * 4
        if proto == 6 and #frame >= l4 + 13 then
            local sport, dport, seq, ack, _, flags = string.unpack(">I2I2I4I4I1I1", frame, l4)
            f.tcp = { sport = sport, dport = dport, flags = flags, seq = seq, ack = ack }
        elseif proto == 17 and #frame >= l4 + 3 then
            local sport, dport = string.unpack(">I2I2", frame, l4)
            f.udp = { sport = sport, dport = dport }
        elseif proto == 1 and #frame >= l4 + 1 then
            f.icmp = { type = frame:byte(l4), code = frame:byte(l4 + 1) }
        end
    elseif f.ethertype == M.ETH_P.IPV6 and #frame >= at + 39 then
        f.ip6 = { next = frame:byte(at + 6), hop = frame:byte(at + 7),
                  src = frame:sub(at + 8, at + 23), dst = frame:sub(at + 24, at + 39) }
        local l4 = at + 40
        if f.ip6.next == 58 and #frame >= l4 + 1 then
            f.icmp6 = { type = frame:byte(l4), code = frame:byte(l4 + 1) }
        elseif f.ip6.next == 6 and #frame >= l4 + 13 then
            local sport, dport, seq, ack, _, flags = string.unpack(">I2I2I4I4I1I1", frame, l4)
            f.tcp = { sport = sport, dport = dport, flags = flags, seq = seq, ack = ack }
        end
    end
    return f
end

--- Every frame waiting on an AF_PACKET socket within `timeout_ms` of
--- quiet (default 200), dissected, with the raw bytes as `raw`.
function M.frames(who, fd, timeout_ms)
    local out = {}
    while true do
        local bytes = M.recv(who, fd, timeout_ms or 200, 2048)
        if not bytes then return out end
        local f = M.dissect(bytes)
        f.raw = bytes
        out[#out + 1] = f
    end
end

-- ---- links, over rtnetlink --------------------------------------------

local RTM = { NEWLINK = 16, DELLINK = 17, SETLINK = 19 }
local NLM_F = { REQUEST = 0x1, ACK = 0x4, EXCL = 0x200, CREATE = 0x400 }
local IFLA = { IFNAME = 3, LINK = 5, MASTER = 10, LINKINFO = 18, NET_NS_PID = 19 }

local function nla(attr, payload)
    local len = 4 + #payload
    return string.pack("<I2I2", len, attr) .. payload .. zeros((4 - len % 4) % 4)
end

-- struct ifinfomsg naming an interface by index (0: none).
local function ifinfo(index)
    return string.pack("<I1I1I2i4I4I4", 0, 0, 0, index or 0, 0, 0)
end

-- One rtnetlink request, acknowledged. Returns true, or nil, errno.
local function rtnl(who, msg_type, flags, body)
    local s = who:syscall(NR.socket, 16, M.SOCK_RAW, 0) -- AF_NETLINK, NETLINK_ROUTE
    if s.ret < 0 then return nil, s.errno end
    local msg = string.pack("<I4I2I2I4I4", 16 + #body, msg_type,
        flags | NLM_F.REQUEST | NLM_F.ACK, 1, 0) .. body
    local w = M.send(who, s.ret, msg)
    if w.ret < 0 then sys.close(who, s.ret); return nil, w.errno end
    local r = who:syscall(sys.NR.read, {
        args = { s.ret, 0, 4096 }, bufs = { zeros(4096) }, ptrs = { 1 },
    })
    sys.close(who, s.ret)
    if r.ret < 20 then return nil, r.errno end
    local _, reply_type = string.unpack("<I4I2", r.out_bufs[1])
    if reply_type ~= 2 then return nil, sys.E.IO end -- NLMSG_ERROR carries the ack
    local err = string.unpack("<i4", r.out_bufs[1], 17)
    if err ~= 0 then return nil, -err end
    return true
end

local fixtures = require("helpers.fixtures")

-- The modules each link kind needs, in load order (fixtures/modules).
local KIND_MODULES = {
    veth = { "veth" }, dummy = { "dummy" },
    vlan = { "llc", "stp", "garp", "mrp", "8021q" },
    bridge = { "llc", "stp", "bridge" },
}

--- Create a link: `kind` is "veth", "dummy", "vlan" or "bridge".
---
--- `o.peer` and `o.peer_pid` (veth): the other end's name, and the pid
--- of a process whose network namespace it is born into. `o.link` and
--- `o.id` (vlan): the parent's ifindex and the VLAN id. Loads the
--- kind's modules from the fixtures first. Returns true, or nil, errno.
function M.link_add(who, name, kind, o)
    o = o or {}
    for _, mod in ipairs(KIND_MODULES[kind] or {}) do
        local ok, errno = fixtures.load_module(who, mod)
        if not ok then return nil, errno end
    end
    local data = ""
    if kind == "veth" then
        local peer = ifinfo() .. nla(IFLA.IFNAME, o.peer .. "\0")
        if o.peer_pid then
            peer = peer .. nla(IFLA.NET_NS_PID, string.pack("<I4", o.peer_pid))
        end
        data = nla(2, nla(1, peer)) -- IFLA_INFO_DATA { VETH_INFO_PEER }
    elseif kind == "vlan" then
        data = nla(2, nla(1, string.pack("<I2", o.id))) -- IFLA_VLAN_ID
    end
    local body = ifinfo() .. nla(IFLA.IFNAME, name .. "\0")
    if o.link then body = body .. nla(IFLA.LINK, string.pack("<I4", o.link)) end
    body = body .. nla(IFLA.LINKINFO, nla(1, kind) .. data)
    return rtnl(who, RTM.NEWLINK, NLM_F.CREATE | NLM_F.EXCL, body)
end

--- Delete a link by name.
function M.link_del(who, name)
    local index, errno = M.if_index(who, name)
    if not index then return nil, errno end
    return rtnl(who, RTM.DELLINK, 0, ifinfo(index))
end

--- Enslave `name` to the bridge `master` (nil releases it).
function M.link_set_master(who, name, master)
    local index, errno = M.if_index(who, name)
    if not index then return nil, errno end
    local master_index = 0
    if master then
        master_index, errno = M.if_index(who, master)
        if not master_index then return nil, errno end
    end
    return rtnl(who, RTM.SETLINK, 0,
        ifinfo(index) .. nla(IFLA.MASTER, string.pack("<I4", master_index)))
end

-- ---- a second machine, in one VM --------------------------------------

M.CLONE_NEWNET = 0x40000000

--- A peer on the wire: a worker in its own network namespace, joined to
--- the VM's by a veth pair.
---
--- NTFE instruments the root namespace only (§6.2), so the worker's
--- namespace is a machine with no firewall, and what crosses the pair
--- meets the engine exactly as traffic from another host would: at the
--- device seats of `o.name`, then the IP seats. Every traffic function
--- here takes a `who`; pass the peer to act as the other machine.
---
--- `o`: name ("veth0"), peer ("peer0"), addr ("10.9.0.1"), peer_addr
--- ("10.9.0.2"), prefix (24), and optionally addr6 / peer_addr6. Call
--- at FILE scope (the peer is a worker). Returns the peer worker and
--- `o` filled in with what was used, plus `ifindex` and both MACs.
function M.peer(vm, o)
    o = o or {}
    local n = {
        name = o.name or "veth0", peer = o.peer or "peer0",
        addr = o.addr or "10.9.0.1", peer_addr = o.peer_addr or "10.9.0.2",
        prefix = o.prefix or 24, addr6 = o.addr6, peer_addr6 = o.peer_addr6,
    }
    local p = vm:spawn_worker()
    local r = p:syscall(sys.NR.unshare, M.CLONE_NEWNET)
    assert(r.ret == 0, "unshare(CLONE_NEWNET): " .. sys.errname(r.errno))
    local pid = p:syscall(sys.NR.getpid).ret
    local ok, errno = M.link_add(vm, n.name, "veth", { peer = n.peer, peer_pid = pid })
    assert(ok, "create the veth pair: " .. sys.errname(errno or 0))
    assert(M.if_up(p, "lo"))
    if not o.unaddressed then
        assert(M.if_addr(vm, n.name, n.addr, n.prefix))
        assert(M.if_addr(p, n.peer, n.peer_addr, n.prefix))
    else
        assert(M.if_up(vm, n.name)); assert(M.if_up(p, n.peer))
    end
    if n.addr6 then
        assert(M.if_addr(vm, n.name, n.addr6, 64))
        assert(M.if_addr(p, n.peer, n.peer_addr6, 64))
    end
    n.ifindex = assert(M.if_index(vm, n.name))
    n.mac = assert(M.if_hwaddr(vm, n.name))
    n.peer_mac = assert(M.if_hwaddr(p, n.peer))
    return p, n
end

-- ---- the device ------------------------------------------------------

--- Open the device. Returns fd, or nil, errno.
function M.open(who, flags)
    return sys.open(who, M.DEVICE, flags or sys.O.RDONLY)
end

--- The engine status as a table keyed by member name, or nil, errno.
function M.status(who, fd)
    local r = who:syscall(sys.NR.ioctl, {
        args = { fd, M.IOC.STATUS, 0 },
        bufs = { zeros(M.STATUS_SIZE) }, ptrs = { 2 },
    })
    if r.ret ~= 0 then return nil, r.errno end
    local s = {}
    for i, name in ipairs(M.STATUS_FIELDS) do
        s[name] = string.unpack("<I8", r.out_bufs[1], (i - 1) * 8 + 1)
    end
    return s
end

local function addr_of(family, bytes)
    if family == 4 then return M.ip4_text(bytes) end
    if family == 6 then return bytes end
    return nil
end

--- Decode one `struct peios_ntfe_event` at byte `at` of `buf`.
function M.decode_event(buf, at)
    at = at or 1
    local e = {}
    e.seq, e.t_ns, e.seat, e.layer, e.verdict, e.flags, e.direction,
        e.addr_family, e.protocol, e.flow_state, e.ifindex, e.src_port,
        e.dst_port, e.ether_type, e.reject_kind =
        string.unpack("<I8I8I1I1I1I1I1I1I1I1I4I2I2I2I1", buf, at)
    e.src = addr_of(e.addr_family, buf:sub(at + 36, at + 51))
    e.dst = addr_of(e.addr_family, buf:sub(at + 52, at + 67))
    e.length, e.effects = string.unpack("<I4I4", buf, at + 68)
    e.attributed = cstr_at(buf, at + 76, 96)
    e.fx = {
        tags = e.effects & 0xFF, counts = (e.effects >> 8) & 0xFF,
        reports = (e.effects >> 16) & 0xFF, prompts = (e.effects >> 24) & 0xFF,
    }
    e.backstop = e.flags & M.EV_F.BACKSTOP ~= 0
    e.fail_closed = e.flags & M.EV_F.FAIL_CLOSED ~= 0
    e.reject_degraded = e.flags & M.EV_F.REJECT_DEGRADED ~= 0
    e.rejudged = e.flags & M.EV_F.REJUDGED ~= 0
    e.identity_unresolved = e.flags & M.EV_F.IDENTITY_UNRESOLVED ~= 0
    local function endpoint(kind_at, unres_at, pid_at, guid_at, comm_at, user_at, svc_at)
        return {
            kind = buf:byte(at + kind_at),
            unresolved = buf:byte(at + unres_at) ~= 0,
            pid = string.unpack("<i4", buf, at + pid_at),
            guid = buf:sub(at + guid_at, at + guid_at + 15),
            comm = cstr_at(buf, at + comm_at, 16),
            user = M.sid_bytes(buf:sub(at + user_at, at + user_at + 67)),
            service = M.sid_bytes(buf:sub(at + svc_at, at + svc_at + 31)),
        }
    end
    e["local"] = endpoint(176, 178, 180, 188, 220, 252, 388)
    e.remote = endpoint(177, 179, 184, 204, 236, 320, 420)
    return e
end

--- A self-sized binary SID out of a fixed field: nil when all zero
--- (absent), else exactly its 8 + 4 × sub-authority-count bytes.
function M.sid_bytes(field)
    if field:byte(1) == 0 then return nil end
    return field:sub(1, 8 + 4 * field:byte(2))
end

--- read(2) the stream once: up to `max` records (default 64). Returns
--- the decoded events (possibly empty), or nil, errno.
function M.read_events(who, fd, max)
    local size = (max or M.READ_MAX) * M.EVENT_SIZE
    local r = who:syscall(sys.NR.read, {
        args = { fd, 0, size }, bufs = { zeros(size) }, ptrs = { 1 },
    })
    if r.ret < 0 then
        if r.errno == sys.E.AGAIN then return {} end
        return nil, r.errno
    end
    local out = {}
    for at = 1, r.ret, M.EVENT_SIZE do
        out[#out + 1] = M.decode_event(r.out_bufs[1], at)
    end
    return out, nil, r.ret
end

local function dump(who, fd, cmd, rec_size, capacity)
    capacity = capacity or 256
    local r = who:syscall(sys.NR.ioctl, {
        args = { fd, cmd, 0 },
        bufs = { string.pack("<I8I4I4I4I4", 0, capacity * rec_size, 0, 0, 0),
                 zeros(capacity * rec_size) },
        ptrs = { 2 },
        nested = { { parent = 1, child = 2, offset = 0 } },
    })
    if r.ret ~= 0 then return nil, r.errno end
    local count, total = string.unpack("<I4I4", r.out_bufs[1], 13)
    return r.out_bufs[2], count, total
end

--- The counters dump (§6.6): a list of cells, plus `total`.
function M.counters(who, fd, capacity)
    local buf, count, total = dump(who, fd, M.IOC.COUNTERS, M.COUNTER_REC_SIZE, capacity)
    if not buf then return nil, count end
    local out = { total = total }
    for i = 0, count - 1 do
        local at = i * M.COUNTER_REC_SIZE + 1
        local c = { name = cstr_at(buf, at, 64) }
        c.hash, c.keyspec, c.family = string.unpack("<I8I1I1", buf, at + 64)
        c.ifindex = string.unpack("<i4", buf, at + 76)
        c.src = addr_of(c.family, buf:sub(at + 80, at + 95))
        c.dst = addr_of(c.family, buf:sub(at + 96, at + 111))
        c.total, c.last_secs, c.n_windows = string.unpack("<I8I8I4", buf, at + 112)
        c.windows = {}
        for w = 0, c.n_windows - 1 do
            local secs = string.unpack("<I4", buf, at + 136 + w * 4)
            c.windows[secs] = string.unpack("<I8", buf, at + 168 + w * 8)
        end
        out[#out + 1] = c
    end
    return out
end

--- The flows dump (§6.8): a list of flows, plus `total`.
function M.flows(who, fd, capacity)
    local buf, count, total = dump(who, fd, M.IOC.FLOWS, M.FLOW_REC_SIZE, capacity)
    if not buf then return nil, count end
    local out = { total = total }
    for i = 0, count - 1 do
        local at = i * M.FLOW_REC_SIZE + 1
        local f = {}
        f.id, f.family, f.protocol, f.direction, f.loopback, f.seen_reply,
            f.assured, f.related, f.judged, f.ifindex, f.timeout_secs =
            string.unpack("<I4I1I1I1I1I1I1I1I1i4I4", buf, at)
        f.src = addr_of(f.family, buf:sub(at + 20, at + 35))
        f.dst = addr_of(f.family, buf:sub(at + 36, at + 51))
        f.src_port, f.dst_port, f.icmp_type, f.icmp_code, f.n_tags =
            string.unpack("<I2I2I1I1I1", buf, at + 52)
        f.start_secs = string.unpack("<I8", buf, at + 64)
        f.packets = { string.unpack("<I8I8", buf, at + 72) }
        f.packets[3] = nil
        f.bytes = { string.unpack("<I8I8", buf, at + 88) }
        f.bytes[3] = nil
        f.sentences, f.owners, f.tags = {}, {}, {}
        for s = 0, 1 do
            f.sentences[s] = {
                generation = string.unpack("<I8", buf, at + 104 + s * 8),
                expires_at = string.unpack("<i8", buf, at + 120 + s * 8),
                rule_hash = string.unpack("<I8", buf, at + 136 + s * 8),
                verdict = buf:byte(at + 152 + s),
                reject_kind = buf:byte(at + 154 + s),
            }
            f.owners[s] = {
                kind = buf:byte(at + 288 + s),
                unresolved = buf:byte(at + 290 + s) ~= 0,
                pid = string.unpack("<i4", buf, at + 296 + s * 4),
                guid = buf:sub(at + 304 + s * 16, at + 319 + s * 16),
                comm = cstr_at(buf, at + 336 + s * 16, 16),
                user = M.sid_bytes(buf:sub(at + 368 + s * 68, at + 435 + s * 68)),
                service = M.sid_bytes(buf:sub(at + 504 + s * 32, at + 535 + s * 32)),
            }
        end
        for n = 0, math.min(f.n_tags, 8) - 1 do
            f.tags[string.unpack("<I8", buf, at + 160 + n * 8)] =
                string.unpack("<I8", buf, at + 224 + n * 8)
        end
        out[#out + 1] = f
    end
    return out
end

--- The listeners dump (§6.9): a list of sockets, plus `total`.
function M.listeners(who, fd, capacity)
    local buf, count, total = dump(who, fd, M.IOC.LISTENERS, M.LISTENER_REC_SIZE, capacity)
    if not buf then return nil, count end
    local out = { total = total }
    for i = 0, count - 1 do
        local at = i * M.LISTENER_REC_SIZE + 1
        local l = {}
        l.family, l.protocol, l.reuseport, l.connected, l.v6only, l.owner_kind,
            l.owner_unresolved = string.unpack("<I1I1I1I1I1I1I1", buf, at)
        l.port = string.unpack("<I2", buf, at + 8)
        l.ifindex = string.unpack("<i4", buf, at + 12)
        l.addr = buf:sub(at + 16, at + 31)
        l.owner_pid = string.unpack("<i4", buf, at + 32)
        l.owner_guid = buf:sub(at + 36, at + 51)
        l.owner_comm = cstr_at(buf, at + 52, 16)
        l.owner_user = M.sid_bytes(buf:sub(at + 68, at + 135))
        l.owner_service = M.sid_bytes(buf:sub(at + 136, at + 167))
        out[#out + 1] = l
    end
    return out
end

-- ---- the policy, as a registry tree ----------------------------------

--- A REG_MULTI_SZ payload: each string NUL-terminated, then one more.
function M.multi_sz(list)
    local out = {}
    for _, s in ipairs(list) do out[#out + 1] = s .. "\0" end
    return table.concat(out) .. "\0"
end

--- Lower one Lua value to a registry (type, data) pair the way a policy
--- author would write it: a list is REG_MULTI_SZ, a string REG_SZ, an
--- integer REG_DWORD. `{ type = n, data = bytes }` passes through, for
--- the types a test wants to get wrong on purpose.
function M.lower(v)
    if type(v) == "table" then
        if v.type then return v.type, v.data end
        return lcs.TYPE.MULTI_SZ, M.multi_sz(v)
    elseif math.type(v) == "integer" then
        return lcs.TYPE.DWORD, lcs.dword(v)
    end
    return lcs.TYPE.SZ, lcs.sz(v)
end

-- Seed one rule and its exceptions. A rule is a table of values keyed by
-- value name; the reserved key `children` holds its exceptions by name.
local function seed_rule(src, path, rule)
    local key = src:key(path)
    for name, v in pairs(rule) do
        if name ~= "children" then
            local vtype, data = M.lower(v)
            src:value(key, name, vtype, data)
        end
    end
    for name, child in pairs(rule.children or {}) do
        seed_rule(src, path .. "\\" .. name, child)
    end
end

--- Seed a helpers/lcs source with a policy.
---
--- `policy` is keyed by layer (`Packet`, `RawPacket`, `Flow`, or any
--- other name a test wants under `Rules`), each a table of root rules by
--- name. A rule is a table of registry values by name — `Actions = {
--- "PASS" }`, `["DstPort.Equal"] = 22` — and `children` holds its
--- exceptions. `policy.values` are values of the Rules key itself
--- (`CurrentReportingLevel`).
function M.seed(src, policy)
    local rules_key = src:key(M.RULES_KEY)
    for name, v in pairs(policy.values or {}) do
        local vtype, data = M.lower(v)
        src:value(rules_key, name, vtype, data)
    end
    for layer, roots in pairs(policy) do
        if layer ~= "values" then
            src:key(M.RULES_KEY .. "\\" .. layer)
            for name, rule in pairs(roots) do
                seed_rule(src, M.RULES_KEY .. "\\" .. layer .. "\\" .. name, rule)
            end
        end
    end
end

--- Seed netd's inventory (§6.5, the context stage). `networks` maps a
--- network id to `{ Name =, Trust = }`; `interfaces` maps an interface
--- key name to its `Status` values, `{ Name = "eth0", Network = id }`.
function M.seed_inventory(src, networks, interfaces)
    src:key(M.NETWORK_KEY .. "\\Networks")
    src:key(M.NETWORK_KEY .. "\\Interfaces")
    for id, values in pairs(networks or {}) do
        local key = src:key(M.NETWORK_KEY .. "\\Networks\\" .. id)
        for name, v in pairs(values) do
            local vtype, data = M.lower(v)
            src:value(key, name, vtype, data)
        end
    end
    for ifname, status in pairs(interfaces or {}) do
        local key = src:key(M.NETWORK_KEY .. "\\Interfaces\\" .. ifname .. "\\Status")
        for name, v in pairs(status) do
            local vtype, data = M.lower(v)
            src:value(key, name, vtype, data)
        end
    end
end

-- ---- the engine handle -----------------------------------------------

local Engine = {}
Engine.__index = Engine
M.Engine = Engine

--- Boot-time fixture: serve a Machine hive holding `policy`, register
--- it, and open the device. Call at FILE scope — provium closes a
--- worker spawned inside a test() when that test ends, and the source
--- and the writer are workers.
---
--- `policy` nil seeds a Network key with an empty Rules key (nothing
--- publishes: generation stays 0); `o.no_network = true` seeds no
--- Network key at all. `o.seed(src)` runs before registration for
--- anything else the hive should hold.
---
--- Returns the handle: `E.vm`, `E.src` (the helpers/lcs source), `E.dev`
--- (a status fd on the main agent), `E.writer` (a worker for registry
--- calls), `E.net_fd` (the Network key, open on the writer).
function M.engine(vm, policy, o)
    o = o or {}
    local self = setmetatable({ vm = vm }, Engine)
    self.dev = assert(M.open(vm), "open " .. M.DEVICE)
    self.zero = assert(M.status(vm, self.dev))
    self.src = lcs.source(vm)
    if not o.no_network then
        self.src:key(M.RULES_KEY)
        if policy then M.seed(self.src, policy) end
    end
    if o.seed then o.seed(self.src) end
    assert(self.src:register())
    self.src:pump()
    self.writer = vm:spawn_worker()
    if not o.no_network then
        local r = lcs.open_key(self.src, self.writer, -1, M.NETWORK_KEY)
        assert(r.ret >= 0, "open the Network key: " .. sys.errname(r.errno))
        self.net_fd = r.ret
    end
    self.pokes = 0
    return self
end

--- The engine status.
function Engine:status()
    return assert(M.status(self.vm, self.dev))
end

--- Serve the source until the engine has walked every change it had
--- noted when this was called (§6.5, "In force"). The walk reads the
--- policy back through the source, so waiting without pumping would
--- wait forever. Returns the status that satisfied it; raises on a
--- timeout (default 5 s).
function Engine:settle(timeout_ms)
    local target = self:status().changes_noted
    local waited = 0
    while true do
        self.src:pump(20)
        local s = self:status()
        if s.changes_walked >= target then return s end
        waited = waited + 25
        if waited >= (timeout_ms or 5000) then
            error(string.format("the engine did not walk: noted %d, walked %d",
                s.changes_noted, s.changes_walked))
        end
    end
end

--- One real registry write under the Network key, which fires the
--- engine's watch. Returns the raw result.
function Engine:poke()
    self.pokes = self.pokes + 1
    return lcs.set_value(self.src, self.writer, self.net_fd, "TestPoke",
        lcs.TYPE.DWORD, lcs.dword(self.pokes))
end

-- Entries seeded after registration must resolve at the sequence the
-- kernel already knows, or its snapshot read would not see them.
local function seed_pinned(src, fn)
    local saved, real = src.seq, src.next_seq
    src.next_seq = function() return 1 end
    local ok, err = pcall(fn)
    src.next_seq = real
    src.seq = saved
    if not ok then error(err, 0) end
end

--- Replace the whole policy and wait for it to be in force.
---
--- A harness shortcut, not how an operator writes policy: the tree is
--- swapped in the Lua source directly and the engine is told with one
--- real write (`poke`), so the walk that follows reads the new policy.
--- That keeps a traffic test's setup to one round trip instead of one
--- per value. Tests of the write path itself use `E:create` / `E:write`.
---
--- Returns the settled status. A refused policy is not an error here:
--- read `last_ingest_error` from what comes back.
function Engine:replace(policy)
    local src = self.src
    local rules = assert(src:lookup(M.RULES_KEY), "no Rules key")
    src.store.entries[rules] = nil
    src.store.values[rules] = nil
    seed_pinned(src, function() M.seed(src, policy) end)
    local r = self:poke()
    assert(r.ret == 0, "poke: " .. sys.errname(r.errno))
    return self:settle()
end

--- Replace netd's inventory the same way (see `replace`).
function Engine:replace_inventory(networks, interfaces)
    local src = self.src
    for _, name in ipairs({ "Networks", "Interfaces" }) do
        local guid = src:lookup(M.NETWORK_KEY .. "\\" .. name)
        if guid then src.store.entries[guid] = nil end
    end
    seed_pinned(src, function() M.seed_inventory(src, networks, interfaces) end)
    local r = self:poke()
    assert(r.ret == 0, "poke: " .. sys.errname(r.errno))
    return self:settle()
end

--- reg_create_key at a path relative to the Network key, through LCS.
--- Returns the key fd (open on the writer), or nil, errno.
function Engine:create(path)
    local r = lcs.create_key(self.src, self.writer,
        { path = M.NETWORK_KEY .. "\\" .. path })
    if r.ret < 0 then return nil, r.errno end
    return r.ret
end

--- Set one value on a key fd through LCS, lowered as `M.lower` does.
function Engine:write(key_fd, name, v, o)
    local vtype, data = M.lower(v)
    return lcs.set_value(self.src, self.writer, key_fd, name, vtype, data, o)
end

--- Create a rule key and write its values through LCS, one registry
--- call each. Returns the key fd.
function Engine:write_rule(path, rule)
    local fd = assert(self:create(path))
    for name, v in pairs(rule) do
        if name ~= "children" then
            local r = self:write(fd, name, v)
            assert(r.ret == 0, "set " .. name .. ": " .. sys.errname(r.errno))
        end
    end
    return fd
end

--- Open the verdict stream: a second, non-blocking file on the device,
--- which the first `events` call makes the stream's reader.
function Engine:stream()
    if not self.stream_fd then
        self.stream_fd = assert(M.open(self.vm, sys.O.RDONLY | 0x800))
    end
    return self.stream_fd
end

--- Every event waiting in the ring, decoded, oldest first.
function Engine:events()
    local fd = self:stream()
    local out = {}
    while true do
        local batch = assert(M.read_events(self.vm, fd))
        if #batch == 0 then return out end
        for _, e in ipairs(batch) do out[#out + 1] = e end
    end
end

--- Discard what the ring holds, so the next `events` is what a test did.
function Engine:drain()
    self:events()
end

--- Run `fn` and return how far each status counter moved, plus the
--- events the run produced.
function Engine:during(fn)
    self:drain()
    local before = self:status()
    fn()
    local after = self:status()
    local delta = {}
    for _, name in ipairs(M.STATUS_FIELDS) do
        delta[name] = after[name] - before[name]
    end
    return delta, self:events(), after
end

function Engine:counters(capacity) return M.counters(self.vm, self.dev, capacity) end
function Engine:flows(capacity) return M.flows(self.vm, self.dev, capacity) end
function Engine:listeners(capacity) return M.listeners(self.vm, self.dev, capacity) end

--- The events of `list` matching every field of `want` (`attributed`,
--- `layer`, `seat`, `verdict`, `dst_port`, ...).
function M.matching(list, want)
    local out = {}
    for _, e in ipairs(list) do
        local ok = true
        for k, v in pairs(want) do
            if e[k] ~= v then ok = false; break end
        end
        if ok then out[#out + 1] = e end
    end
    return out
end

--- One line per event, for an assertion message.
function M.describe(list)
    local out = {}
    for _, e in ipairs(list) do
        out[#out + 1] = string.format("[seat %d layer %d verdict %d %s %s:%d>%s:%d flags %#x]",
            e.seat, e.layer, e.verdict, e.attributed, tostring(e.src), e.src_port,
            tostring(e.dst), e.dst_port, e.flags)
    end
    return table.concat(out, " ")
end

return M
