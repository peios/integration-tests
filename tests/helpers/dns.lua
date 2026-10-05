-- The scripted gateway's DNS server (helpers.gateway), and a DNS message
-- codec, for the resolvd and name-resolution tests in tests/network.
--
-- Over UDP the server works the way the gateway's DHCP servers do: the
-- gateway's kernel absorbs the query on its port-53 socket, the packet
-- socket sees a copy, and the reply is a frame built here, so it can be
-- right, late, repeated, truncated, garbled, or from an address or port
-- that never received the question.
--
-- TCP is the gateway's kernel's: one listener on [::]:53, which takes
-- IPv4 too, and the server reads each length-prefixed query and writes
-- the reply through a socket. A TCP reply is always to the question on
-- its own connection, so the levers there are the content, silence, and
-- closing.
--
-- Like every gateway server, this one answers only while the test pumps
-- (`gw:serve`). The machine's resolver retransmits, so a question sent
-- while the test is busy elsewhere is answered at the next pump, as a
-- slow server's would be. A reply given a `delay` is held and sent at the
-- first pump after it falls due.
--
--   local dns = require("helpers.dns")
--   dns.serve(gw, { zone = {
--       ["www.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.80" } },
--   } })
--   ...
--   for _, q in ipairs(dns.queries(gw)) do ... q.msg.questions[1].name ... end

local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")
local gateway = require("helpers.gateway")

local M = {}

M.TYPE = {
    A = 1, NS = 2, CNAME = 5, SOA = 6, PTR = 12, MX = 15, TXT = 16,
    AAAA = 28, SRV = 33, OPT = 41, ANY = 255,
}
M.TYPE_NAME = {}
for k, v in pairs(M.TYPE) do M.TYPE_NAME[v] = k end
M.CLASS = { IN = 1, CH = 3, HS = 4, ANY = 255 }
M.RCODE = { NOERROR = 0, FORMERR = 1, SERVFAIL = 2, NXDOMAIN = 3, NOTIMP = 4, REFUSED = 5 }

local function type_code(t) return type(t) == "string" and assert(M.TYPE[t], "dns: unknown type " .. t) or t end

-- ---------------------------------------------------------------------------
-- Names
-- ---------------------------------------------------------------------------

--- A name's labels, from text ("www.Example.test", a trailing dot or not;
--- "." or "" is the root). `\.` and `\\` escape, `\DDD` is a byte. A table
--- is taken as the labels themselves, raw.
function M.labels(name)
    if type(name) == "table" then return name end
    local out, cur, i = {}, {}, 1
    if name == "." then name = "" end
    while i <= #name do
        local c = name:sub(i, i)
        if c == "\\" then
            local d = name:match("^%d%d%d", i + 1)
            if d then cur[#cur + 1] = string.char(tonumber(d)); i = i + 4
            else cur[#cur + 1] = name:sub(i + 1, i + 1); i = i + 2 end
        elseif c == "." then
            out[#out + 1] = table.concat(cur); cur = {}; i = i + 1
        else
            cur[#cur + 1] = c; i = i + 1
        end
    end
    if #cur > 0 then out[#out + 1] = table.concat(cur) end
    return out
end

--- A name in wire form (uncompressed).
function M.name(name)
    local b = {}
    for _, l in ipairs(M.labels(name)) do
        assert(#l <= 63, "dns: a label longer than 63 bytes")
        b[#b + 1] = string.char(#l) .. l
    end
    return table.concat(b) .. "\0"
end

-- One label as text: printable bytes as they are, `.` and `\` escaped,
-- anything else as `\DDD`.
local function label_text(l)
    return (l:gsub("[^%w%-_*]", function(c)
        if c == "." or c == "\\" then return "\\" .. c end
        local n = c:byte()
        if n > 32 and n < 127 then return c end
        return string.format("\\%03d", n)
    end))
end

-- Read a name at `pos` (1-based) in `p`, following compression pointers.
-- Returns its text (no trailing dot; "." for the root) and the position
-- after it, or nil on a malformed name.
local function read_name(p, pos)
    local parts, after, hops = {}, nil, 0
    while true do
        local len = p:byte(pos)
        if not len then return nil end
        if len == 0 then
            pos = pos + 1
            break
        elseif len & 0xC0 == 0xC0 then
            local lo = p:byte(pos + 1)
            if not lo then return nil end
            after = after or pos + 2
            pos = ((len & 0x3F) << 8 | lo) + 1
            hops = hops + 1
            if hops > 64 then return nil end
        elseif len & 0xC0 ~= 0 then
            return nil
        else
            if pos + len > #p then return nil end
            parts[#parts + 1] = label_text(p:sub(pos + 1, pos + len))
            pos = pos + 1 + len
        end
    end
    local text = #parts == 0 and "." or table.concat(parts, ".")
    return text, after or pos
end
M.read_name = read_name

--- Two names compared as DNS compares them: ASCII case does not count.
function M.same_name(a, b)
    local function norm(n) return (n:gsub("%.$", ""):lower()) end
    if a == "." or a == "" then a = "" end
    if b == "." or b == "" then b = "" end
    return norm(a) == norm(b)
end

-- ---------------------------------------------------------------------------
-- Records
-- ---------------------------------------------------------------------------

-- A record's RDATA from `r.data`, by type; `r.rdata` (bytes) overrides.
local function rdata_of(r)
    if r.rdata then return r.rdata end
    local t, d = type_code(r.type), r.data
    if t == M.TYPE.A then return ntfe.ip4(d)
    elseif t == M.TYPE.AAAA then return ntfe.ip6(d)
    elseif t == M.TYPE.CNAME or t == M.TYPE.NS or t == M.TYPE.PTR then return M.name(d)
    elseif t == M.TYPE.MX then return string.pack(">I2", d.preference or d[1]) .. M.name(d.exchange or d[2])
    elseif t == M.TYPE.SRV then
        return string.pack(">I2I2I2", d.priority or 0, d.weight or 0, d.port) .. M.name(d.target)
    elseif t == M.TYPE.SOA then
        return M.name(d.mname or "ns.invalid") .. M.name(d.rname or "hostmaster.invalid")
            .. string.pack(">I4I4I4I4I4", d.serial or 1, d.refresh or 3600, d.retry or 600,
                d.expire or 86400, d.minimum or 60)
    elseif t == M.TYPE.TXT then
        local list = type(d) == "table" and d or { d }
        local b = {}
        for _, s in ipairs(list) do b[#b + 1] = string.char(#s) .. s end
        return table.concat(b)
    end
    error("dns: no `data` encoding for type " .. tostring(r.type) .. "; give `rdata`")
end

-- Decode a record's RDATA into `data`, where the type is known.
local function data_of(p, pos, t, len)
    local rd = p:sub(pos, pos + len - 1)
    if t == M.TYPE.A and len == 4 then return ntfe.ip4_text(rd)
    elseif t == M.TYPE.AAAA and len == 16 then return gateway.ip6_text(rd)
    elseif t == M.TYPE.CNAME or t == M.TYPE.NS or t == M.TYPE.PTR then return (read_name(p, pos))
    elseif t == M.TYPE.SOA then
        local mname, n1 = read_name(p, pos)
        if not mname then return nil end
        local rname, n2 = read_name(p, n1)
        if not rname or n2 + 19 > #p then return nil end
        local serial, refresh, retry, expire, minimum = string.unpack(">I4I4I4I4I4", p, n2)
        return { mname = mname, rname = rname, serial = serial, refresh = refresh,
                 retry = retry, expire = expire, minimum = minimum }
    elseif t == M.TYPE.TXT then
        local out, i = {}, 1
        while i <= #rd do
            local n = rd:byte(i)
            out[#out + 1] = rd:sub(i + 1, i + n)
            i = i + 1 + n
        end
        return out
    end
    return nil
end

-- ---------------------------------------------------------------------------
-- Messages
-- ---------------------------------------------------------------------------

--- Decode a DNS message. Returns a table: `id`, the header bits (`qr`,
--- `opcode`, `aa`, `tc`, `rd`, `ra`, `ad`, `cd`, `rcode`), `questions`
--- ({name, type, class}), and `answers`, `authority`, `additional`
--- ({name, type, class, ttl, rdata, data}); `edns` ({udp_size, version,
--- do_bit, flags}) when an OPT record is present. The rcode includes
--- OPT's extended bits. Returns nil and a reason for a malformed message.
function M.decode(p)
    if #p < 12 then return nil, "short header" end
    local id, flags, qd, an, ns, ar = string.unpack(">I2I2I2I2I2I2", p)
    local m = {
        id = id, flags = flags,
        qr = flags & 0x8000 ~= 0, opcode = (flags >> 11) & 0xF,
        aa = flags & 0x0400 ~= 0, tc = flags & 0x0200 ~= 0,
        rd = flags & 0x0100 ~= 0, ra = flags & 0x0080 ~= 0,
        ad = flags & 0x0020 ~= 0, cd = flags & 0x0010 ~= 0,
        rcode = flags & 0xF,
        questions = {}, answers = {}, authority = {}, additional = {},
        length = #p,
    }
    local pos = 13
    for _ = 1, qd do
        local name, nxt = read_name(p, pos)
        if not name or nxt + 3 > #p then return nil, "bad question" end
        local t, c = string.unpack(">I2I2", p, nxt)
        m.questions[#m.questions + 1] = { name = name, type = t, class = c }
        pos = nxt + 4
    end
    for _, sec in ipairs({ { "answers", an }, { "authority", ns }, { "additional", ar } }) do
        for _ = 1, sec[2] do
            local name, nxt = read_name(p, pos)
            if not name or nxt + 9 > #p then return nil, "bad record in " .. sec[1] end
            local t, c, ttl, len = string.unpack(">I2I2I4I2", p, nxt)
            local at = nxt + 10
            if at + len - 1 > #p then return nil, "short rdata in " .. sec[1] end
            local r = { name = name, type = t, class = c, ttl = ttl,
                        rdata = p:sub(at, at + len - 1), data = data_of(p, at, t, len) }
            local list = m[sec[1]]
            list[#list + 1] = r
            if t == M.TYPE.OPT then
                m.edns = { udp_size = c, version = (ttl >> 16) & 0xFF,
                           do_bit = ttl & 0x8000 ~= 0, flags = ttl & 0xFFFF,
                           ext_rcode = ttl >> 24 }
                m.rcode = m.rcode | ((ttl >> 24) << 4)
            end
            pos = at + len
        end
    end
    return m
end

--- Encode a message table (as `decode` gives, or written by hand). Names
--- are not compressed. Header bits default to false and rcode to 0;
--- `flags` (a 16-bit number) overrides them all. A record's `type` is a
--- name ("A") or a number, its `class` IN, its `ttl` 60. `edns` adds an
--- OPT record ({udp_size = 1232}). Counts are the lists' lengths unless
--- `counts = {qd, an, ns, ar}` says otherwise.
function M.encode(m)
    local flags = m.flags
    if not flags then
        local function b(v, bit) return v and bit or 0 end
        flags = b(m.qr, 0x8000) | ((m.opcode or 0) & 0xF) << 11 | b(m.aa, 0x0400)
            | b(m.tc, 0x0200) | b(m.rd, 0x0100) | b(m.ra, 0x0080)
            | b(m.ad, 0x0020) | b(m.cd, 0x0010) | ((m.rcode or 0) & 0xF)
    end
    local additional = {}
    for _, r in ipairs(m.additional or {}) do additional[#additional + 1] = r end
    if m.edns then
        local e = m.edns
        local ttl = (((m.rcode or 0) >> 4) & 0xFF) << 24 | (e.version or 0) << 16
            | (e.do_bit and 0x8000 or 0)
        additional[#additional + 1] = { name = ".", type = M.TYPE.OPT,
            class = e.udp_size or 1232, ttl = ttl, rdata = e.options or "" }
    end
    local qs, an, ns = m.questions or {}, m.answers or {}, m.authority or {}
    local counts = m.counts or { #qs, #an, #ns, #additional }
    local out = { string.pack(">I2I2I2I2I2I2", m.id or 0, flags, counts[1], counts[2], counts[3], counts[4]) }
    for _, q in ipairs(qs) do
        out[#out + 1] = M.name(q.name) .. string.pack(">I2I2", type_code(q.type), q.class or M.CLASS.IN)
    end
    for _, list in ipairs({ an, ns, additional }) do
        for _, r in ipairs(list) do
            local rd = rdata_of(r)
            out[#out + 1] = M.name(r.name) .. string.pack(">I2I2I4I2", type_code(r.type),
                r.class or M.CLASS.IN, r.ttl or 60, #rd) .. rd
        end
    end
    return table.concat(out)
end

--- A query message, as a client would send it (rd set, EDNS when
--- `o.edns`). For tests that put questions to the gateway's server
--- themselves, or build a reply from one.
function M.query(name, qtype, o)
    o = o or {}
    return { id = o.id or math.random(0, 0xFFFF), rd = o.rd ~= false,
             questions = { { name = name, type = type_code(qtype or "A"), class = o.class or M.CLASS.IN } },
             edns = o.edns }
end

-- ---------------------------------------------------------------------------
-- The server
-- ---------------------------------------------------------------------------

-- The zone's records at `name` (case-insensitive), or nil when the name
-- does not exist.
local function lookup(zone, name)
    for k, v in pairs(zone) do
        if M.same_name(k, name) then return v end
    end
end

-- The authority section of a negative answer: the zone's SOA, with its
-- minimum as the TTL (RFC 2308), when `soa` is given.
local function negative(soa)
    if not soa then return {} end
    local d = soa.data or soa
    return { { name = soa.name or ".", type = M.TYPE.SOA, ttl = soa.ttl or d.minimum or 60, data = d } }
end

--- The reply the zone gives to `q`, as a recursive server would give it:
--- the question echoed exactly as asked (case and all), aa and ra set, rd
--- copied, and CNAMEs followed within the zone, each step in the answer.
--- A name the zone lacks is NXDOMAIN, at the end of a chain too (RFC
--- 6604: the rcode speaks for the last name). A name without the type
--- is an empty NOERROR (NODATA). A negative reply carries the SOA when
--- the server has one. An EDNS query gets an OPT back.
function M.answer(q, zone, o)
    o = o or {}
    local r = { id = q.id, qr = true, opcode = q.opcode, aa = true, ra = true, rd = q.rd,
                questions = q.questions, answers = {}, authority = {}, additional = {} }
    if q.edns then r.edns = { udp_size = o.udp_size or 1232 } end
    local qn = q.questions[1]
    if not qn then r.rcode = M.RCODE.FORMERR; return r end
    if q.opcode ~= 0 then r.rcode = M.RCODE.NOTIMP; return r end
    local name, seen = qn.name, { [qn.name:lower()] = true }
    while true do
        local recs = lookup(zone, name)
        if not recs then
            r.rcode = M.RCODE.NXDOMAIN
            r.authority = negative(o.soa)
            return r
        end
        local cname, direct = nil, false
        for _, rec in ipairs(recs) do
            local t = type_code(rec.type)
            if t == qn.type or qn.type == M.TYPE.ANY then
                r.answers[#r.answers + 1] = { name = name, type = t, ttl = rec.ttl,
                    data = rec.data, rdata = rec.rdata }
                direct = true
            elseif t == M.TYPE.CNAME then
                cname = rec
            end
        end
        if direct or not cname then
            if not direct then r.authority = negative(o.soa) end
            return r
        end
        r.answers[#r.answers + 1] = { name = name, type = M.TYPE.CNAME, ttl = cname.ttl, data = cname.data }
        if seen[cname.data:lower()] then return r end   -- a loop: stop where it closes
        seen[cname.data:lower()] = true
        name = cname.data
    end
end

-- The largest UDP reply the client said it takes (512 without EDNS).
local function udp_limit(q)
    return q.edns and math.max(512, q.edns.udp_size) or 512
end

-- A reply cut to fit: TC set, every section but the question and OPT
-- emptied (RFC 2181 §9 allows sending what fits; servers mostly send
-- nothing, and so does this one).
local function truncated(r)
    local t = {}
    for k, v in pairs(r) do t[k] = v end
    t.tc, t.answers, t.authority, t.additional = true, {}, {}, {}
    return t
end

-- The gateway's float clock, in seconds (the gateway's wall clock; a
-- test moves only the machine's).
local function clock(g) return g.vm:clock():get() end

-- Send one UDP reply `payload` to the query frame `f`, from `o.src`
-- (default: the address the query went to) and port `o.sport` (53).
local function send_udp(g, f, payload, o)
    o = o or {}
    local sport = o.sport or 53
    if f.ethertype == ntfe.ETH_P.IP then
        g:send_udp4(f.src, f.src_ip, sport, f.udp.sport, payload, { src = o.src or f.dst_ip })
    else
        local src, dst = gateway.ip6(o.src or f.dst_ip), f.ip6.src
        g:send_ip6(dst, 17, gateway.udp6(src, dst, sport, f.udp.sport, payload),
            { src = src, peer_mac = f.src, hop = 64 })
    end
end

-- getsockname(2): the local address a TCP connection was accepted on, as
-- text (an IPv4-mapped address comes back as plain IPv4).
local function local_addr(g, fd)
    local r = g.vm:syscall(51, {
        args = { fd, 0, 0 }, bufs = { string.rep("\0", 28), string.pack("<I4", 28) }, ptrs = { 1, 2 },
    })
    if r.ret ~= 0 then return nil end
    local sa = r.out_bufs[1]
    local family = string.unpack("<I2", sa)
    if family == ntfe.AF_INET then return ntfe.ip4_text(sa:sub(5, 8)) end
    local a = sa:sub(9, 24)
    if a:sub(1, 12) == string.rep("\0", 10) .. "\xff\xff" then return ntfe.ip4_text(a:sub(13, 16)) end
    return gateway.ip6_text(a)
end

--- Run a DNS server on the gateway. `o`:
---   zone      { [name] = { {type=, ttl=, data= | rdata=}, ... } }
---   soa       the SOA for negative answers ({name=, ttl=, data={mname=,
---             rname=, serial=, refresh=, retry=, expire=, minimum=}})
---   udp_size  the OPT size this server advertises (1232)
---   tcp       false: no TCP listener, so a TCP question is refused (RST)
---   on        `function(q, default, ctx)`: q is the decoded query,
---             default the zone's reply (a table, already built), ctx
---             {transport = "udp"|"tcp", server = the address asked,
---             client = the asker's address (udp), at = clock seconds}.
---             Return nil for the default, false to stay silent (over TCP
---             the connection is then closed), a reply table, or bytes.
---             A reply table may also carry (`raw` replacing the
---             message itself, to send bytes with these levers):
---               raw     the payload bytes to send instead
---               delay   seconds to hold it (udp)
---               src     the source address to send it from (udp)
---               sport   the source port (udp; 53)
---               copies  how many times to send it (udp; 1)
---               close   close the connection after it (tcp)
---               no_truncate  send it whole however large (udp)
--- A UDP reply larger than the client said it takes is truncated (TC
--- set, sections emptied) unless the hook says otherwise.
---
--- Every question is logged in `gw.dns_log` ({msg, transport, server,
--- client, at}); read it with `M.queries(gw)`.
function M.serve(gw, o)
    o = o or {}
    local zone = o.zone or {}
    gw.dns_log = gw.dns_log or {}
    gw.dns_pending = gw.dns_pending or {}
    gw.dns_conns = gw.dns_conns or {}

    local function decide(q, ctx)
        local default = M.answer(q, zone, o)
        if not o.on then return default end
        local r = o.on(q, default, ctx)
        if r == nil then return default end
        return r
    end

    local function payload_of(q, r, transport)
        if type(r) == "string" then return r end
        if r.raw then return r.raw end
        if transport == "udp" and not r.no_truncate then
            local p = M.encode(r)
            if #p > udp_limit(q) then p = M.encode(truncated(r)) end
            return p
        end
        return M.encode(r)
    end

    -- UDP: answer from the frame.
    gw.handlers.dns = function(g, f)
        if not (f.udp and f.udp.dport == 53 and f.payload) then return false end
        local q = M.decode(f.payload)
        local now = clock(g)
        local ctx = { transport = "udp", server = f.dst_ip, client = f.src_ip, at = now, frame = f }
        g.dns_log[#g.dns_log + 1] = { msg = q, raw = f.payload, transport = "udp",
            server = f.dst_ip, client = f.src_ip, at = now }
        if not q or q.qr then return true end
        local r = decide(q, ctx)
        if r == false then return true end
        local payload = payload_of(q, r, "udp")
        local so = type(r) == "table" and r or {}
        local copies = so.copies or 1
        local send = function()
            for _ = 1, copies do send_udp(g, f, payload, so) end
        end
        if so.delay and so.delay > 0 then
            g.dns_pending[#g.dns_pending + 1] = { due = now + so.delay, send = send }
        else
            send()
        end
        return true
    end

    -- TCP: the kernel's listener, serviced at every pump.
    if o.tcp ~= false and not gw.dns_listener then
        gw.dns_listener = assert(ntfe.tcp_listen(gw.vm, "::", 53))
    end
    local function service(g)
        -- Held UDP replies that have fallen due.
        if #g.dns_pending > 0 then
            local now, keep = clock(g), {}
            for _, p in ipairs(g.dns_pending) do
                if p.due <= now then p.send() else keep[#keep + 1] = p end
            end
            g.dns_pending = keep
        end
        if not g.dns_listener then return end
        while true do
            local fd = ntfe.tcp_accept(g.vm, g.dns_listener, 0)
            if not fd then break end
            g.dns_conns[fd] = { buf = "", server = local_addr(g, fd) }
        end
        for fd, c in pairs(g.dns_conns) do
            local data, err = ntfe.recv(g.vm, fd, 0, 4096)
            if data and #data > 0 then
                c.buf = c.buf .. data
            elseif data or (err and err ~= "timeout") then
                sys.close(g.vm, fd)          -- the client closed, or the socket failed
                g.dns_conns[fd] = nil
                c = nil
            end
            while c and #c.buf >= 2 do
                local len = string.unpack(">I2", c.buf)
                if #c.buf < 2 + len then break end
                local raw = c.buf:sub(3, 2 + len)
                c.buf = c.buf:sub(3 + len)
                local q = M.decode(raw)
                local now = clock(g)
                g.dns_log[#g.dns_log + 1] = { msg = q, raw = raw, transport = "tcp",
                    server = c.server, at = now }
                local r = q and not q.qr and decide(q, { transport = "tcp", server = c.server, at = now })
                if r == false or r == nil then
                    sys.close(g.vm, fd)
                    g.dns_conns[fd] = nil
                    c = nil
                else
                    local p = payload_of(q, r, "tcp")
                    ntfe.send(g.vm, fd, string.pack(">I2", #p) .. p)
                    if type(r) == "table" and r.close then
                        sys.close(g.vm, fd)
                        g.dns_conns[fd] = nil
                        c = nil
                    end
                end
            end
        end
    end
    gw.ticks = gw.ticks or {}
    gw.ticks.dns = service
    -- The gateway's pump runs ticks after reading frames (helpers.gateway
    -- calls `self.ticks`); until then, wrap this gateway's pump.
    if not gateway.HAS_TICKS and not gw.dns_wrapped then
        local base = getmetatable(gw).pump
        gw.pump = function(self, wait_ms)
            local n = base(self, wait_ms)
            for _, tick in pairs(self.ticks) do tick(self) end
            return n
        end
        gw.dns_wrapped = true
    end
    return gw
end

--- Stop answering DNS. Questions are no longer logged. The TCP listener
--- stays open but unserviced, so a TCP question is accepted by the
--- gateway's kernel and never answered (a silent server, not a refusing
--- one).
function M.stop(gw)
    gw.handlers.dns = nil
    if gw.ticks then gw.ticks.dns = nil end
end

--- The questions the server has received, oldest first, optionally those
--- `pred(entry)` accepts. Each is {msg (decoded, nil if malformed), raw,
--- transport, server, client, at}.
function M.queries(gw, pred)
    local out = {}
    for _, e in ipairs(gw.dns_log or {}) do
        if not pred or pred(e) then out[#out + 1] = e end
    end
    return out
end

--- Forget the logged questions.
function M.forget(gw) gw.dns_log = {} end

return M
