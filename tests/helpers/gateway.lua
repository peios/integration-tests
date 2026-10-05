-- The scripted gateway for tests/network: a kernel-only VM on the same
-- provium bridge as the machine under test, playing the network's
-- servers from Lua.
--
-- The machine under test runs the whole system (netd, resolvd, the rest,
-- under peinit), and everything it learns about its network it learns
-- from this VM. Nothing here is a real server. Every reply is a frame
-- built byte by byte and sent on one AF_PACKET socket, so a test can
-- answer correctly, late, wrongly, twice, from the wrong address, or not
-- at all, as the case needs. Every frame the gateway sees is recorded, so
-- a test can also assert on what the machine sent.
--
-- The gateway's own kernel stays out of the way: it holds the gateway's
-- addresses (so it answers ARP and neighbour solicitation for them) and
-- one *absorber* socket on each server port (67, 547, 53), which reads
-- nothing but stops it answering a client with ICMP port-unreachable.
--
-- Nothing runs between Lua calls, so the servers only answer while the
-- test is pumping: `gw:serve{...}` reads and answers until a condition
-- holds or time runs out. The machine's clients retransmit, so a frame
-- that arrives while the test is busy elsewhere is answered at the next
-- pump, exactly as a slow server's would be.
--
--   local gw = gateway.boot({ bridge = lan })
--   gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
--   local sut = network.boot({ bridges = { lan } })
--   gw:serve({ timeout = 60, until_ = function() return network.bound(sut) end })

local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")

local M = {}

-- ---------------------------------------------------------------------------
-- Addresses
-- ---------------------------------------------------------------------------

M.ip4 = ntfe.ip4
M.ip4_text = ntfe.ip4_text
M.ip6 = ntfe.ip6

--- 16 bytes → RFC 5952 text, as netd and resolvd print addresses: lower
--- case, leading zeros dropped, the longest run of two or more zero
--- groups (the first, on a tie) written `::`.
function M.ip6_text(b)
    local g = {}
    for i = 1, 16, 2 do g[#g + 1] = string.unpack(">I2", b, i) end
    local best_at, best_len, at, len = 0, 0, 0, 0
    for i = 1, 8 do
        if g[i] == 0 then
            if len == 0 then at = i end
            len = len + 1
            if len > best_len then best_at, best_len = at, len end
        else
            len = 0
        end
    end
    local function hex(from, to)
        local out = {}
        for i = from, to do out[#out + 1] = string.format("%x", g[i]) end
        return table.concat(out, ":")
    end
    if best_len < 2 then return hex(1, 8) end
    return hex(1, best_at - 1) .. "::" .. hex(best_at + best_len, 8)
end

--- A 6-byte MAC → "52:54:00:12:34:56".
function M.mac_text(m)
    return string.format("%02x:%02x:%02x:%02x:%02x:%02x", m:byte(1, 6))
end

--- "52:54:00:12:34:56" → 6 bytes.
function M.mac(s)
    local out = {}
    for h in s:gmatch("%x%x") do out[#out + 1] = string.char(tonumber(h, 16)) end
    assert(#out == 6, "not a MAC: " .. tostring(s))
    return table.concat(out)
end

--- The modified-EUI-64 link-local address the kernel gives an interface
--- with MAC `m` (16 bytes).
function M.link_local(m)
    local b = { m:byte(1, 6) }
    return "\xfe\x80" .. string.rep("\0", 6)
        .. string.char(b[1] ~ 0x02, b[2], b[3], 0xff, 0xfe, b[4], b[5], b[6])
end

--- The Ethernet multicast address for IPv6 group `dst` (16 bytes).
function M.mcast_mac(dst) return "\x33\x33" .. dst:sub(13, 16) end

M.ALL_NODES = M.ip6("ff02::1")
M.ALL_ROUTERS = M.ip6("ff02::2")
M.ALL_DHCP_AGENTS = M.ip6("ff02::1:2")

-- ---------------------------------------------------------------------------
-- IPv6 framing
-- ---------------------------------------------------------------------------

--- An IPv6 header for `len` bytes of `next` from `src` to `dst` (16-byte
--- strings), with hop limit `hop` (default 255).
function M.ipv6(src, dst, next, len, hop)
    return string.pack(">I4I2I1I1", 0x60000000, len, next, hop or 255) .. src .. dst
end

local function l4_checksum6(src, dst, next, segment)
    return ntfe.checksum(src .. dst .. string.pack(">I4I3I1", #segment, 0, next) .. segment)
end

--- An ICMPv6 message: `body` is the whole message with its checksum field
--- (bytes 3–4) zero; the checksum is filled in.
function M.icmp6(src, dst, body)
    local csum = l4_checksum6(src, dst, 58, body)
    return body:sub(1, 2) .. string.pack(">I2", csum) .. body:sub(5)
end

--- A UDP datagram over IPv6, checksum included.
function M.udp6(src, dst, sport, dport, data)
    local function seg(csum)
        return string.pack(">I2I2I2I2", sport, dport, 8 + #data, csum) .. data
    end
    local csum = l4_checksum6(src, dst, 17, seg(0))
    if csum == 0 then csum = 0xFFFF end
    return seg(csum)
end

-- ---------------------------------------------------------------------------
-- DHCPv4
-- ---------------------------------------------------------------------------

M.DHCP = { DISCOVER = 1, OFFER = 2, REQUEST = 3, DECLINE = 4, ACK = 5,
           NAK = 6, RELEASE = 7, INFORM = 8 }
M.DHCP_NAME = {}
for k, v in pairs(M.DHCP) do M.DHCP_NAME[v] = k end

local COOKIE = "\x63\x82\x53\x63"

--- Decode a DHCP message (the UDP payload). Returns nil for anything that
--- is not one. Options come back twice: `options`, the ordered list of
--- `{code, data}`, and `opt[code]`, the first occurrence's data.
function M.dhcp_decode(p)
    if #p < 240 or p:sub(237, 240) ~= COOKIE then return nil end
    local m = {
        op = p:byte(1), htype = p:byte(2), hlen = p:byte(3),
        xid = string.unpack(">I4", p, 5), secs = string.unpack(">I2", p, 9),
        flags = string.unpack(">I2", p, 11),
        ciaddr = M.ip4_text(p:sub(13, 16)), yiaddr = M.ip4_text(p:sub(17, 20)),
        siaddr = M.ip4_text(p:sub(21, 24)), giaddr = M.ip4_text(p:sub(25, 28)),
        chaddr = p:sub(29, 34), options = {}, opt = {}, length = #p,
    }
    m.broadcast = m.flags & 0x8000 ~= 0
    local i = 241
    while i <= #p do
        local code = p:byte(i)
        if code == 255 then break end
        if code == 0 then
            i = i + 1
        else
            local len = p:byte(i + 1)
            if not len then break end
            local data = p:sub(i + 2, i + 1 + len)
            m.options[#m.options + 1] = { code, data }
            if m.opt[code] == nil then m.opt[code] = data end
            i = i + 2 + len
        end
    end
    m.type = m.opt[53] and m.opt[53]:byte(1)
    return m
end

--- Option payload builders.
M.opt = {}
function M.opt.ip(list)
    if type(list) == "string" then list = { list } end
    local out = {}
    for _, a in ipairs(list) do out[#out + 1] = M.ip4(a) end
    return table.concat(out)
end
function M.opt.u32(n) return string.pack(">I4", n) end
function M.opt.u16(n) return string.pack(">I2", n) end
function M.opt.u8(n) return string.char(n) end
--- Uncompressed RFC 1035 names, back to back (options 119, DHCPv6 24, DNSSL).
function M.opt.names(list)
    local out = {}
    for _, name in ipairs(list) do
        for label in name:gmatch("[^.]+") do out[#out + 1] = string.char(#label) .. label end
        out[#out + 1] = "\0"
    end
    return table.concat(out)
end
--- Classless static routes (option 121): `{ {"10.1.0.0", 16, "10.77.0.9"}, … }`.
function M.opt.classless(routes)
    local out = {}
    for _, r in ipairs(routes) do
        local dst, plen, gw = r[1], r[2], r[3]
        out[#out + 1] = string.char(plen) .. M.ip4(dst):sub(1, (plen + 7) // 8) .. M.ip4(gw)
    end
    return table.concat(out)
end

--- Encode a DHCP reply. `m`: op (2), xid, flags, ciaddr, yiaddr, siaddr,
--- giaddr, chaddr (6 bytes), options (list of `{code, data}`, emitted in
--- order, data longer than 255 cut), and `pad` (default 300).
function M.dhcp_encode(m)
    local parts = {
        string.char(m.op or 2, 1, 6, 0), string.pack(">I4I2I2", m.xid, 0, m.flags or 0),
        M.ip4(m.ciaddr or "0.0.0.0"), M.ip4(m.yiaddr or "0.0.0.0"),
        M.ip4(m.siaddr or "0.0.0.0"), M.ip4(m.giaddr or "0.0.0.0"),
        m.chaddr, string.rep("\0", 10 + 64 + 128), COOKIE,
    }
    for _, o in ipairs(m.options or {}) do
        local data = o[2]:sub(1, 255)
        parts[#parts + 1] = string.char(o[1], #data) .. data
    end
    parts[#parts + 1] = m.no_end and "" or "\xff"
    local out = table.concat(parts)
    local pad = m.pad or 300
    if #out < pad then out = out .. string.rep("\0", pad - #out) end
    return out
end

-- ---------------------------------------------------------------------------
-- Router advertisements
-- ---------------------------------------------------------------------------

--- A router advertisement body (checksum zero; `icmp6` fills it in).
---
--- `o`: hop (current hop limit field, 64), managed, other (the M and O
--- flags), lifetime (router lifetime, 1800), reachable, retrans,
--- prefixes = `{ {prefix="fd77::", len=64, L=true, A=true, valid=…,
--- preferred=…}, … }`, mtu, rdnss = `{lifetime=…, servers={…}}`, dnssl =
--- `{lifetime=…, domains={…}}`, source_mac (adds option 1), extra (raw
--- option bytes appended), code (0).
function M.ra(o)
    o = o or {}
    local flags = (o.managed and 0x80 or 0) | (o.other and 0x40 or 0)
    local body = string.pack(">I1I1I2I1I1I2I4I4", 134, o.code or 0, 0, o.hop or 64,
        flags, o.lifetime or 1800, o.reachable or 0, o.retrans or 0)
    if o.source_mac then body = body .. "\x01\x01" .. o.source_mac end
    for _, p in ipairs(o.prefixes or {}) do
        local pf = ((p.L ~= false) and 0x80 or 0) | ((p.A ~= false) and 0x40 or 0)
        body = body .. string.pack(">I1I1I1I1I4I4I4", 3, 4, p.len or 64, pf,
            p.valid or 86400, p.preferred or 14400, 0) .. M.ip6(p.prefix)
    end
    if o.mtu then body = body .. string.pack(">I1I1I2I4", 5, 1, 0, o.mtu) end
    if o.rdnss then
        local servers = o.rdnss.servers or {}
        body = body .. string.pack(">I1I1I2I4", 25, 1 + 2 * #servers, 0, o.rdnss.lifetime or 1200)
        for _, s in ipairs(servers) do body = body .. M.ip6(s) end
    end
    if o.dnssl then
        local names = M.opt.names(o.dnssl.domains or {})
        names = names .. string.rep("\0", (8 - (#names + 8) % 8) % 8)
        body = body .. string.pack(">I1I1I2I4", 31, (8 + #names) // 8, 0, o.dnssl.lifetime or 1200)
            .. names
    end
    return body .. (o.extra or "")
end

-- ---------------------------------------------------------------------------
-- DHCPv6
-- ---------------------------------------------------------------------------

M.DHCP6 = { SOLICIT = 1, ADVERTISE = 2, REQUEST = 3, REPLY = 7, INFORMATION_REQUEST = 11 }

--- Decode a DHCPv6 message. Options as `options` (ordered `{code, data}`)
--- and `opt[code]` (first).
function M.dhcp6_decode(p)
    if #p < 4 then return nil end
    local m = { type = p:byte(1), txid = p:sub(2, 4), options = {}, opt = {} }
    local i = 5
    while i + 3 <= #p do
        local code, len = string.unpack(">I2I2", p, i)
        local data = p:sub(i + 4, i + 3 + len)
        m.options[#m.options + 1] = { code, data }
        if m.opt[code] == nil then m.opt[code] = data end
        i = i + 4 + len
    end
    return m
end

--- Encode a DHCPv6 message: `type`, `txid` (3 bytes), options (list of
--- `{code, data}`).
function M.dhcp6_encode(m)
    local out = { string.char(m.type) .. m.txid }
    for _, o in ipairs(m.options or {}) do
        out[#out + 1] = string.pack(">I2I2", o[1], #o[2]) .. o[2]
    end
    return table.concat(out)
end

-- ---------------------------------------------------------------------------
-- The gateway VM
-- ---------------------------------------------------------------------------

local G = {}
G.__index = G

local AF_INET6 = ntfe.AF_INET6
local SIOCSIFFLAGS, IFF_PROMISC, IFF_ALLMULTI = 0x8914, 0x100, 0x200

--- Boot the gateway on `o.bridge` (or every bridge in `o.bridges`; the
--- first is the one the servers run on) and set it up.
---
--- `o`: name ("gw"), addr ("10.77.0.1"), prefix (24), addr6 ("fd77::1"),
--- memory ("512M"). Call at file scope, before the machine under test
--- boots, so the servers are ready for its first request.
function M.boot(o)
    o = o or {}
    local bridges = o.bridges or { o.bridge }
    assert(bridges[1], "gateway.boot: name a bridge")
    local vm = provium:vm(o.name or "gw", "kernel-only",
        { memory = o.memory or "512M", cpus = 1 })
    for _, br in ipairs(bridges) do br:attach(vm) end
    vm:boot()
    local g = setmetatable({
        vm = vm, ifname = o.ifname or "eth0",
        addr = o.addr or "10.77.0.1", prefix = o.prefix or 24,
        addr6 = o.addr6 or "fd77::1",
        seen = {},          -- every frame read, in order
        handlers = {},      -- name -> function(g, frame) returning true when it took the frame
        t0 = os.time(),
    }, G)
    assert(ntfe.if_up(vm, "lo"))
    assert(ntfe.if_addr(vm, g.ifname, g.addr, g.prefix))
    assert(ntfe.if_addr(vm, g.ifname, g.addr6, 64))
    g.ifindex = assert(ntfe.if_index(vm, g.ifname))
    g.mac = assert(ntfe.if_hwaddr(vm, g.ifname))
    g.ll = M.link_local(g.mac)
    -- Promiscuous and all-multicast, so a frame to any group the machine
    -- sends to (ff02::1:2, its own solicited-node groups) is seen.
    local flags = assert(ntfe.if_flags(vm, g.ifname))
    local fd = vm:syscall(ntfe.NR.socket, ntfe.AF_INET, ntfe.SOCK_DGRAM, 0).ret
    vm:syscall(sys.NR.ioctl, {
        args = { fd, SIOCSIFFLAGS, 0 },
        bufs = { g.ifname .. string.rep("\0", 16 - #g.ifname)
            .. string.pack("<I2", flags | IFF_PROMISC | IFF_ALLMULTI) .. string.rep("\0", 22) },
        ptrs = { 2 },
    })
    sys.close(vm, fd)
    g.ps = assert(ntfe.packet_socket(vm, g.ifname))
    g.absorbers = {
        assert(ntfe.udp_bind(vm, "0.0.0.0", 67)),
        assert(ntfe.socket(vm, AF_INET6, ntfe.SOCK_DGRAM, { bind = { "::", 547 } })),
        assert(ntfe.udp_bind(vm, "0.0.0.0", 53)),
        assert(ntfe.socket(vm, AF_INET6, ntfe.SOCK_DGRAM, { bind = { "::", 53 } })),
    }
    return g
end

--- Seconds since the gateway booted, by the host's clock (whole seconds).
function G:now() return os.time() - self.t0 end

--- Send one raw frame.
function G:send(frame)
    local r = ntfe.send_frame(self.vm, self.ps, frame)
    assert(r.ret == #frame, "gateway send: " .. sys.errname(r.errno or 0))
end

--- An IPv4/UDP frame from the gateway (or `o.src`, `o.src_mac`).
function G:send_udp4(dst_mac, dst_ip, sport, dport, payload, o)
    o = o or {}
    local src = o.src or self.addr
    local seg = ntfe.udp(src, dst_ip, sport, dport, payload)
    self:send(ntfe.eth(dst_mac, o.src_mac or self.mac, ntfe.ETH_P.IP)
        .. ntfe.ipv4(src, dst_ip, 17, #seg, { ttl = o.ttl or 64 }) .. seg)
end

--- An IPv6 frame carrying `l4` (protocol `next`) from the gateway's
--- link-local address (or `o.src`, 16 bytes) to `dst` (16 bytes), hop
--- limit `o.hop` (255).
function G:send_ip6(dst, next, l4, o)
    o = o or {}
    local dst_mac = o.dst_mac or (dst:byte(1) == 0xff and M.mcast_mac(dst)) or o.peer_mac
    assert(dst_mac, "send_ip6: no link-layer destination for a unicast address")
    self:send(ntfe.eth(dst_mac, o.src_mac or self.mac, ntfe.ETH_P.IPV6)
        .. M.ipv6(o.src or self.ll, dst, next, #l4, o.hop) .. l4)
end

--- Send a router advertisement built from `spec` (see `M.ra`). `o`: dst
--- (16 bytes, all-nodes), src (16 bytes, the gateway's link-local), hop
--- (255), peer_mac (for a unicast dst).
function G:send_ra(spec, o)
    o = o or {}
    local dst = o.dst or M.ALL_NODES
    local src = o.src or self.ll
    self:send_ip6(dst, 58, M.icmp6(src, dst, M.ra(spec)), o)
end

-- ---- reading ----------------------------------------------------------

-- The layer-4 view of one frame: adds `l4`, the transport payload after
-- the UDP header, and `src_ip`/`dst_ip` as text, for UDP over either
-- family; `icmp6_body` for ICMPv6.
local function annotate(f)
    local raw = f.raw
    if f.ethertype == ntfe.ETH_P.IP and f.ip then
        local ihl = (raw:byte(15) & 0xF) * 4
        local l4 = 15 + ihl
        f.src_ip, f.dst_ip = f.ip.src, f.ip.dst
        if f.ip.protocol == 17 and #raw >= l4 + 7 then
            local sport, dport, len = string.unpack(">I2I2I2", raw, l4)
            f.udp = { sport = sport, dport = dport }
            f.payload = raw:sub(l4 + 8, l4 + len - 1)
        end
    elseif f.ethertype == ntfe.ETH_P.IPV6 and f.ip6 then
        f.src_ip, f.dst_ip = M.ip6_text(f.ip6.src), M.ip6_text(f.ip6.dst)
        local l4 = 15 + 40
        if f.ip6.next == 17 and #raw >= l4 + 7 then
            local sport, dport, len = string.unpack(">I2I2I2", raw, l4)
            f.udp = { sport = sport, dport = dport }
            f.payload = raw:sub(l4 + 8, l4 + len - 1)
        elseif f.ip6.next == 58 then
            f.icmp6_body = raw:sub(l4)
        end
    end
    return f
end

--- Listen only to `mac` (6 bytes or text), and to any other peer named
--- the same way. The host's own end of the bridge and its TAPs carry
--- IPv6 link-local addresses and talk on the bridge (mDNS, router and
--- neighbour solicitations); once a peer is named, frames from anything
--- else are dropped unread, so they are neither answered nor counted.
--- `network.boot{gateway = gw}` names the machine under test.
function G:peer(mac)
    if #mac ~= 6 then mac = M.mac(mac) end
    self.peers = self.peers or {}
    self.peers[mac] = true
end

--- Read every frame waiting (within `wait_ms` of quiet, default 50),
--- record it in `self.seen` with the time it was read, and hand it to
--- the handlers. Frames the gateway sent itself are skipped, and so is
--- every frame from a source that is not a named peer, once one is.
function G:pump(wait_ms)
    local n = 0
    for _, f in ipairs(ntfe.frames(self.vm, self.ps, wait_ms or 50)) do
        if f.src ~= self.mac and (not self.peers or self.peers[f.src]) then
            annotate(f)
            f.at = self:now()
            self.seen[#self.seen + 1] = f
            for _, h in pairs(self.handlers) do
                if h(self, f) then break end
            end
            n = n + 1
        end
    end
    return n
end

--- Pump until `o.until_()` is true (checked after every pump, about
--- every 100 ms) or `o.timeout` seconds pass (default 30). Returns true
--- when the condition held, false on a timeout. Without `until_`, pumps
--- for the whole timeout.
function G:serve(o)
    o = o or {}
    local deadline = os.time() + (o.timeout or 30)
    repeat
        self:pump(100)
        if o.until_ and o.until_() then return true end
    until os.time() > deadline
    return o.until_ == nil or (o.until_() and true or false)
end

--- The frames seen so far that `pred(f)` accepts.
function G:frames(pred)
    local out = {}
    for _, f in ipairs(self.seen) do
        if not pred or pred(f) then out[#out + 1] = f end
    end
    return out
end

--- Forget what has been seen (a test's own window).
function G:forget() self.seen = {} end

-- ---- the DHCPv4 server ------------------------------------------------

--- Every DHCP message the machine sent, decoded, with `frame` and `at`.
function G:dhcp_messages(kind)
    local out = {}
    for _, f in ipairs(self.seen) do
        if f.udp and f.udp.dport == 67 and f.payload then
            local m = M.dhcp_decode(f.payload)
            if m and m.op == 1 and (not kind or m.type == kind) then
                m.frame, m.at = f, f.at
                out[#out + 1] = m
            end
        end
    end
    return out
end

--- Run a DHCPv4 server. `o`:
---   server    the server identifier (the gateway's address)
---   pool      addresses to hand out, in order ({"10.77.0.50"})
---   prefix    the subnet mask's length (the gateway's)
---   lease     lease time, seconds (3600); `t1`, `t2` optional
---   router    option 3 (the gateway's address; false for none)
---   dns       option 6 ({the gateway's address}; false for none)
---   options   extra `{code, data}` appended to every OFFER and ACK
---   on        a table of overrides, keyed `discover`, `request`,
---             `renew`, `reboot`, `release`: `function(m, default)`
---             returning the reply table to send (`default` is what the
---             server would send, already built), `false` to stay silent,
---             or nil for the default.
---   silent    true: record everything, answer nothing
--- Replies go back as the client asked: unicast to `ciaddr` when it is
--- set, broadcast when the broadcast flag is, unicast to `yiaddr`
--- otherwise.
function G:dhcp(o)
    o = o or {}
    local d = {
        server = o.server or self.addr, pool = o.pool or { "10.77.0.50" },
        prefix = o.prefix or self.prefix, lease = o.lease or 3600,
        t1 = o.t1, t2 = o.t2,
        router = o.router == nil and self.addr or o.router,
        dns = o.dns == nil and { self.addr } or o.dns,
        options = o.options or {}, on = o.on or {}, silent = o.silent,
        bindings = {}, next = 1,
    }
    self.dhcp_state = d
    local function mask(bits)
        local m = bits == 0 and 0 or ((0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF)
        return string.pack(">I4", m)
    end
    local function reply(m, kind, yiaddr)
        local opts = { { 53, string.char(kind) }, { 54, M.ip4(d.server) } }
        if kind ~= M.DHCP.NAK then
            opts[#opts + 1] = { 51, M.opt.u32(d.lease) }
            if d.t1 then opts[#opts + 1] = { 58, M.opt.u32(d.t1) } end
            if d.t2 then opts[#opts + 1] = { 59, M.opt.u32(d.t2) } end
            opts[#opts + 1] = { 1, mask(d.prefix) }
            if d.router then opts[#opts + 1] = { 3, M.opt.ip(d.router) } end
            if d.dns then opts[#opts + 1] = { 6, M.opt.ip(d.dns) } end
            for _, x in ipairs(d.options) do opts[#opts + 1] = x end
        end
        return { op = 2, xid = m.xid, flags = m.flags, chaddr = m.chaddr,
                 yiaddr = kind == M.DHCP.NAK and "0.0.0.0" or yiaddr,
                 siaddr = d.server, options = opts }
    end
    local function address_for(m)
        local key = m.chaddr
        if not d.bindings[key] then
            d.bindings[key] = d.pool[d.next] or d.pool[#d.pool]
            d.next = d.next + 1
        end
        return d.bindings[key]
    end
    local function send(m, frame, r)
        if not r then return end
        local payload = type(r) == "string" and r or M.dhcp_encode(r)
        local yiaddr = type(r) == "table" and r.yiaddr or "0.0.0.0"
        if m.ciaddr ~= "0.0.0.0" then
            self:send_udp4(frame.src, m.ciaddr, 67, 68, payload)
        elseif m.broadcast or yiaddr == "0.0.0.0" then
            self:send_udp4(ntfe.MAC_BROADCAST, "255.255.255.255", 67, 68, payload)
        else
            self:send_udp4(m.chaddr, yiaddr, 67, 68, payload)
        end
    end
    local function decide(name, m, default)
        local hook = d.on[name]
        if d.silent then return nil end
        if not hook then return default end
        local r = hook(m, default)
        if r == nil then return default end
        return r or nil
    end
    self.handlers.dhcp = function(g, f)
        if not (f.udp and f.udp.dport == 67 and f.payload) then return false end
        local m = M.dhcp_decode(f.payload)
        if not m or m.op ~= 1 then return false end
        if m.type == M.DHCP.DISCOVER then
            send(m, f, decide("discover", m, reply(m, M.DHCP.OFFER, address_for(m))))
        elseif m.type == M.DHCP.REQUEST then
            local requested = m.opt[50] and M.ip4_text(m.opt[50])
            if m.ciaddr ~= "0.0.0.0" then
                send(m, f, decide("renew", m, reply(m, M.DHCP.ACK, m.ciaddr)))
            elseif m.opt[54] then
                if M.ip4_text(m.opt[54]) ~= d.server then return true end
                local ok = requested == d.bindings[m.chaddr]
                send(m, f, decide("request", m,
                    reply(m, ok and M.DHCP.ACK or M.DHCP.NAK, requested)))
            else
                -- INIT-REBOOT: authoritative for its pool.
                local inpool = false
                for _, a in ipairs(d.pool) do if a == requested then inpool = true end end
                if inpool then d.bindings[m.chaddr] = requested end
                send(m, f, decide("reboot", m,
                    reply(m, inpool and M.DHCP.ACK or M.DHCP.NAK, requested)))
            end
        elseif m.type == M.DHCP.RELEASE then
            d.bindings[m.chaddr] = nil
            decide("release", m, nil)
        end
        return true
    end
    return d
end

--- Stop answering DHCP (frames are still recorded).
function G:dhcp_off() self.handlers.dhcp = nil end

-- ---- router advertisements ----------------------------------------------

--- Answer every router solicitation with the advertisement `spec` (see
--- `M.ra`), sent to all-nodes. `o.on_solicit(f)` may return a different
--- spec, or false to stay silent. Returns nothing.
function G:router(spec, o)
    o = o or {}
    self.ra_spec = spec
    self.handlers.router = function(g, f)
        if not (f.icmp6_body and f.icmp6_body:byte(1) == 133) then return false end
        local s = spec
        if o.on_solicit then
            local r = o.on_solicit(f)
            if r == false then return true end
            s = r or spec
        end
        g:send_ra(s, o.send)
        return true
    end
end

--- Every router solicitation seen.
function G:solicitations()
    return self:frames(function(f) return f.icmp6_body and f.icmp6_body:byte(1) == 133 end)
end

-- ---- stateless DHCPv6 ---------------------------------------------------

--- Answer INFORMATION-REQUESTs. `o`: dns (list of v6 addresses), domains,
--- refresh (option 32, seconds), duid (the server id, a DUID-LL from the
--- gateway's MAC), on (`function(m, default)` as for `dhcp`).
function G:dhcp6(o)
    o = o or {}
    local duid = o.duid or ("\0\3\0\1" .. self.mac)
    self.handlers.dhcp6 = function(g, f)
        if not (f.udp and f.udp.dport == 547 and f.payload) then return false end
        local m = M.dhcp6_decode(f.payload)
        if not m or m.type ~= M.DHCP6.INFORMATION_REQUEST then return true end
        local opts = { { 2, duid } }
        if m.opt[1] then table.insert(opts, 1, { 1, m.opt[1] }) end
        if o.dns then
            local b = {}
            for _, a in ipairs(o.dns) do b[#b + 1] = M.ip6(a) end
            opts[#opts + 1] = { 23, table.concat(b) }
        end
        if o.domains then opts[#opts + 1] = { 24, M.opt.names(o.domains) } end
        if o.refresh then opts[#opts + 1] = { 32, M.opt.u32(o.refresh) } end
        local r = { type = M.DHCP6.REPLY, txid = m.txid, options = opts }
        if o.on then
            local x = o.on(m, r)
            if x == false then return true end
            r = x or r
        end
        local payload = type(r) == "string" and r or M.dhcp6_encode(r)
        g:send_ip6(f.ip6.src, 17, M.udp6(g.ll, f.ip6.src, 547, 546, payload),
            { peer_mac = f.src })
        return true
    end
end

--- Every DHCPv6 message the machine sent, decoded.
function G:dhcp6_messages()
    local out = {}
    for _, f in ipairs(self.seen) do
        if f.udp and f.udp.dport == 547 and f.payload then
            local m = M.dhcp6_decode(f.payload)
            if m then m.frame, m.at = f, f.at; out[#out + 1] = m end
        end
    end
    return out
end

return M
