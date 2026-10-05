-- rtnetlink from the agent: dump the kernel's links, addresses and routes
-- with the flags and lifetimes a test needs to see, and add or remove an
-- address or route the way "somebody else" would.
--
-- The image ships no `ip`, and netd's own status reply shows addresses
-- without their flags and routes without their owner. This reads them
-- from the kernel directly, so a test can tell netd's route (protocol
-- 200) from a foreign one, a deprecated address from a preferred one, and
-- an address with a prefix route from one without.

local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")

local M = {}

M.RTM = { NEWLINK = 16, GETLINK = 18, NEWADDR = 20, DELADDR = 21, GETADDR = 22,
          NEWROUTE = 24, DELROUTE = 25, GETROUTE = 26 }
M.NLM_F = { REQUEST = 0x1, MULTI = 0x2, ACK = 0x4, DUMP = 0x300, REPLACE = 0x100,
            EXCL = 0x200, CREATE = 0x400 }
M.IFA_F = { SECONDARY = 0x01, NODAD = 0x02, OPTIMISTIC = 0x04, DADFAILED = 0x08,
            HOMEADDRESS = 0x10, DEPRECATED = 0x20, TENTATIVE = 0x40, PERMANENT = 0x80,
            MANAGETEMPADDR = 0x100, NOPREFIXROUTE = 0x200 }
M.RTPROT = { KERNEL = 2, BOOT = 3, STATIC = 4, RA = 9, NETD = 200 }
M.FOREVER = 0xFFFFFFFF

local AF_NETLINK, NETLINK_ROUTE = 16, 0

local function nla(attr, payload)
    local len = 4 + #payload
    return string.pack("<I2I2", len, attr) .. payload .. string.rep("\0", (4 - len % 4) % 4)
end

local function attrs(b, at, stop)
    local out = {}
    while at + 3 <= stop do
        local len, kind = string.unpack("<I2I2", b, at)
        if len < 4 then break end
        out[kind & 0x7FFF] = b:sub(at + 4, at + len - 1)
        at = at + ((len + 3) & ~3)
    end
    return out
end

local function ip_text(bytes)
    if #bytes == 4 then return ntfe.ip4_text(bytes) end
    local g = require("helpers.gateway")
    return g.ip6_text(bytes)
end

-- One request; returns every message of the reply (a dump's parts, or the
-- ack). Each: { type, flags, body = bytes after the nlmsghdr }.
local function exchange(who, msg_type, flags, body)
    local s = who:syscall(ntfe.NR.socket, AF_NETLINK, ntfe.SOCK_RAW, NETLINK_ROUTE)
    assert(s.ret >= 0, "netlink socket: " .. sys.errname(s.errno))
    local fd = s.ret
    local msg = string.pack("<I4I2I2I4I4", 16 + #body, msg_type,
        flags | M.NLM_F.REQUEST, 1, 0) .. body
    ntfe.send(who, fd, msg)
    local out = {}
    local done = false
    while not done do
        local buf = ntfe.recv(who, fd, 3000, 65536)
        if not buf then break end
        local at = 1
        while at + 15 <= #buf do
            local len, kind, fl = string.unpack("<I4I2I2", buf, at)
            if len < 16 then done = true; break end
            out[#out + 1] = { type = kind, flags = fl, body = buf:sub(at + 16, at + len - 1) }
            if kind == 3 or kind == 2 then done = true end -- DONE, ERROR (ack)
            if fl & M.NLM_F.MULTI == 0 and kind ~= 3 then done = true end
            at = at + ((len + 3) & ~3)
        end
    end
    sys.close(who, fd)
    return out
end

local function ack(msgs)
    for _, m in ipairs(msgs) do
        if m.type == 2 then
            local err = string.unpack("<i4", m.body)
            if err ~= 0 then return nil, -err end
            return true
        end
    end
    return nil, "no ack"
end

--- Every address: { index, family (4|6), address, prefix, scope, flags
--- (IFA_F_* incl. the 32-bit IFA_FLAGS), preferred, valid (lifetimes,
--- seconds, FOREVER = 0xffffffff), deprecated, tentative, noprefixroute,
--- broadcast }.
function M.addresses(who)
    local out = {}
    for _, m in ipairs(exchange(who, M.RTM.GETADDR, M.NLM_F.DUMP, string.pack("<I1I1I1I1i4", 0, 0, 0, 0, 0))) do
        if m.type == M.RTM.NEWADDR then
            local family, prefix, flags8, scope, index = string.unpack("<I1I1I1I1i4", m.body)
            local a = attrs(m.body, 9, #m.body)
            local addr = (family == 2 and (a[2] or a[1])) or a[1]
            local flags = a[8] and string.unpack("<I4", a[8]) or flags8
            local e = { index = index, family = family == 2 and 4 or 6,
                        address = addr and ip_text(addr), prefix = prefix, scope = scope,
                        flags = flags, broadcast = a[4] and ip_text(a[4]) }
            if a[6] then e.preferred, e.valid = string.unpack("<I4I4", a[6]) end
            e.deprecated = flags & M.IFA_F.DEPRECATED ~= 0
            e.tentative = flags & M.IFA_F.TENTATIVE ~= 0
            e.noprefixroute = flags & M.IFA_F.NOPREFIXROUTE ~= 0
            out[#out + 1] = e
        end
    end
    return out
end

--- Every route in every table: { family, dst ("0.0.0.0"/"::" for a
--- default), prefix, gateway, oif, metric, protocol, table, type, scope }.
function M.routes(who)
    local out = {}
    for _, fam in ipairs({ 2, 10 }) do
        local body = string.pack("<I1I1I1I1I1I1I1I1I4", fam, 0, 0, 0, 0, 0, 0, 0, 0)
        for _, m in ipairs(exchange(who, M.RTM.GETROUTE, M.NLM_F.DUMP, body)) do
            if m.type == M.RTM.NEWROUTE then
                local family, dst_len, _, _, tbl, proto, scope, rtype =
                    string.unpack("<I1I1I1I1I1I1I1I1", m.body)
                local a = attrs(m.body, 13, #m.body)
                local zero = family == 2 and "0.0.0.0" or "::"
                out[#out + 1] = {
                    family = family == 2 and 4 or 6,
                    dst = a[1] and ip_text(a[1]) or zero, prefix = dst_len,
                    gateway = a[5] and ip_text(a[5]),
                    oif = a[4] and string.unpack("<i4", a[4]),
                    metric = a[6] and string.unpack("<I4", a[6]) or 0,
                    protocol = proto, scope = scope, type = rtype,
                    table = a[15] and string.unpack("<I4", a[15]) or tbl,
                }
            end
        end
    end
    return out
end

--- The addresses on interface `index` (all, or only family `fam`).
function M.addresses_of(who, index, fam)
    local out = {}
    for _, a in ipairs(M.addresses(who)) do
        if a.index == index and (not fam or a.family == fam) then out[#out + 1] = a end
    end
    return out
end

--- The routes out of interface `index` in the main table (254).
function M.routes_of(who, index)
    local out = {}
    for _, r in ipairs(M.routes(who)) do
        if r.oif == index and r.table == 254 then out[#out + 1] = r end
    end
    return out
end

--- The address entry for `addr` on `index`, or nil.
function M.address(who, index, addr)
    for _, a in ipairs(M.addresses_of(who, index)) do
        if a.address == addr then return a end
    end
end

--- Add an address as another program would. `o`: prefix (24 / 64).
function M.add_address(who, index, addr, o)
    o = o or {}
    local v6 = addr:find(":", 1, true) ~= nil
    local bytes = v6 and ntfe.ip6(addr) or ntfe.ip4(addr)
    local body = string.pack("<I1I1I1I1i4", v6 and 10 or 2, o.prefix or (v6 and 64 or 24), 0, 0, index)
        .. nla(2, bytes) .. nla(1, bytes)
    return ack(exchange(who, M.RTM.NEWADDR, M.NLM_F.ACK | M.NLM_F.CREATE | M.NLM_F.EXCL, body))
end

--- Add a route as another program would. `r`: dst ("10.9.0.0"), prefix,
--- gateway, oif, metric, protocol (RTPROT.STATIC).
function M.add_route(who, r)
    local v6 = (r.dst or r.gateway):find(":", 1, true) ~= nil
    local ip = v6 and ntfe.ip6 or ntfe.ip4
    local body = string.pack("<I1I1I1I1I1I1I1I1I4", v6 and 10 or 2, r.prefix or 0, 0, 0, 254,
        r.protocol or M.RTPROT.STATIC, r.gateway and 0 or 253, 1, 0)
    if r.prefix and r.prefix > 0 then body = body .. nla(1, ip(r.dst)) end
    if r.gateway then body = body .. nla(5, ip(r.gateway)) end
    body = body .. nla(4, string.pack("<i4", r.oif))
    if r.metric then body = body .. nla(6, string.pack("<I4", r.metric)) end
    return ack(exchange(who, M.RTM.NEWROUTE, M.NLM_F.ACK | M.NLM_F.CREATE | M.NLM_F.EXCL, body))
end

return M
