-- resolvd §4.7 — the upstream query: what resolvd puts on the wire for
-- each transaction (socket and source port, ID and 0x20 case pattern and
-- the generator behind them, EDNS0, the TCP retry, link-local and zoned
-- servers), and PSPU §6.7 "Upstream behaviour": fresh ports, random IDs,
-- 0x20, EDNS0, TCP after truncation, demotion, server order and the
-- attempt limit.
--
-- Harness: the scripted gateway (helpers.gateway) with its DNS server
-- (helpers.dns) answering on two addresses, and a whole Peios
-- (helpers.network). The lease gives the scope its servers in the order
-- 10.77.0.2, 10.77.0.1 — not numeric order, so "the scope's order" can be
-- told from "lowest address first" — and the search domain example.test.
-- The server's `on` hook goes through `HOOK`, set by each test for its own
-- names; every UDP query's source port is recorded from its frame.
-- Questions are asked on the native socket from the agent while the
-- gateway pumps, with `no_cache`; `status` is read between pumps.
--
-- The generator test recovers resolvd's xorshift64* state from one
-- query's case pattern (an all-lower-case name of 76 letters: its first 64
-- letters are one whole generator output) and then predicts the ID and
-- case pattern of every later query exactly.
--
-- timed is stopped once the machine is up, so every upstream query is a
-- test's own: the counters and the generator move only for them.
--
-- Own VMs: two server addresses and a search domain from the start; the
-- last test edits the default profile (Dns.Servers) and resolvd's
-- registry, and puts both back.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local unixsock = require("helpers.unixsock")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")
local msgpack = require("helpers.msgpack")
local rtnl = require("helpers.rtnl")

peinit.claim(2)

local S1, S2 = "10.77.0.2", "10.77.0.1"     -- the scope's order
local RSOCK = "/run/resolvd/resolv.sock"
local A, TXT = 1, 16
local BOGUS = "10.66.6.6"

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
assert(rtnl.add_address(gw.vm, gw.ifindex, S1, { prefix = 24 }), "gateway address " .. S1)
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600, dns = { S1, S2 }, options = { { 15, "example.test" } } })

local ZONE = {}
local HOOK
local PORTS = {}        -- every UDP query: {name, sport, server, at}
dns.serve(gw, {
    zone = ZONE,
    soa = { name = "example.test", data = { minimum = 30 } },
    on = function(q, d, ctx)
        if ctx.transport == "udp" and ctx.frame then
            PORTS[#PORTS + 1] = { name = q.questions[1] and q.questions[1].name, sport = ctx.frame.udp.sport,
                                  server = ctx.server, at = ctx.at }
        end
        if HOOK then return HOOK(q, d, ctx) end
    end,
})
local sut = network.boot({ bridges = { lan }, gateway = gw })

-- ---- helpers ---------------------------------------------------------------

local function qname(q) return q and q.questions and q.questions[1] and q.questions[1].name end
local function is(name) return function(e) return e.msg and dns.same_name(qname(e.msg) or "", name) end end
local function questions_of(q)
    local out = {}
    for _, x in ipairs(q.questions) do out[#out + 1] = { name = x.name, type = x.type, class = x.class } end
    return out
end

local function send_reply(ctx, payload, o)
    o = o or {}
    local f = ctx.frame
    gw:send_udp4(f.src, f.src_ip, o.sport or 53, f.udp.sport, payload, { src = o.src or f.dst_ip })
end

local function rstatus()
    local s, err = network.call(sut, { query = "status" }, { path = RSOCK })
    assert(s and s.ok, "resolvd status: " .. tostring(err or (s and s.error)))
    return s
end
local function counters() return rstatus().counters end
local function eth0_scope(s)
    for _, sc in ipairs((s or rstatus()).scopes or {}) do if sc.interface == "eth0" then return sc end end
end
local function demoted() return table.concat((eth0_scope() or {}).demoted or {}, ",") end

local function ask(req)
    local fd = assert(unixsock.socket(sut, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
    local c = unixsock.connect(sut, fd, RSOCK)
    assert(c.ret == 0, "connect resolvd: " .. unixsock.errname(c.errno))
    local p = msgpack.encode(req)
    ntfe.send(sut, fd, string.pack("<I4", #p) .. p)
    return { fd = fd, buf = "" }
end
local function take(a)
    while true do
        if #a.buf >= 4 then
            local len = string.unpack("<I4", a.buf)
            if #a.buf >= 4 + len then return msgpack.decode(a.buf:sub(5, 4 + len)) end
        end
        local chunk = ntfe.recv(sut, a.fd, 0, 65536)
        if not chunk or #chunk == 0 then return nil end
        a.buf = a.buf .. chunk
    end
end
local function finish(a, timeout)
    local reply
    gw:serve({ timeout = timeout or 20, until_ = function() reply = take(a); return reply ~= nil end })
    sys.close(sut, a.fd)
    return reply
end
local function resolve(name, rtype, o)
    o = o or {}
    return finish(ask({ query = "resolve", name = name, type = rtype or A, no_cache = not o.cache }), o.timeout)
end

local function texts(r)
    local out = {}
    for _, rec in ipairs((r and r.records) or {}) do out[#out + 1] = rec.text end
    return table.concat(out, ",")
end
local function delta(c0, c1)
    return { sent = c1.upstream_sent - c0.upstream_sent, answered = c1.upstream_answered - c0.upstream_answered,
             failed = c1.upstream_failed - c0.upstream_failed }
end
local function dtext(d) return string.format("sent +%d answered +%d failed +%d", d.sent, d.answered, d.failed) end
local function qlog(t, qs)
    for i, e in ipairs(qs) do
        t:log(string.format("  query %d: %s to %s, id %s, %s, at %.2f", i, e.transport, tostring(e.server),
            e.msg and e.msg.id or "?", tostring(qname(e.msg)), e.at))
    end
end
local function servers_of(qs)
    local out = {}
    for _, e in ipairs(qs) do out[#out + 1] = e.transport .. "@" .. tostring(e.server) end
    return table.concat(out, ",")
end

local octet = 100
local function fresh(label)
    octet = octet + 1
    local name = label .. ".example.test"
    local addr = "10.77.0." .. octet
    ZONE[name] = { { type = "A", ttl = 60, data = addr } }
    return name, addr
end

--- resolvd's log lines (messages), newest first.
local function rlogs()
    local r = sut:run("evctl 'LOGS FROM resolvd SINCE 30m ago TAKE 1000'")
    local out = {}
    for line in r.stdout:gmatch("[^\n]+") do
        local msg = line:match('message="(.-)"  origin=')
        if msg then out[#out + 1] = (msg:gsub('\\"', '"')) end
    end
    return out
end
local function logged(text)
    for _, l in ipairs(rlogs()) do if l:find(text, 1, true) then return l end end
end

local ready = false
local function up(t)
    if ready then return end
    t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound a lease")
    sut:run("svctl stop timed")
    local ok = gw:serve({ timeout = 30, until_ = function()
        local s = network.call(sut, { query = "status" }, { path = RSOCK })
        if not (s and s.ok) then return false end
        local sc = eth0_scope(s)
        return sc ~= nil and table.concat(sc.servers or {}, ",") == S1 .. "," .. S2
            and table.concat(sc.domains or {}, ",") == "example.test"
    end })
    t:assert(ok, "resolvd has eth0's scope: servers " .. S1 .. ", " .. S2 .. "; domain example.test")
    gw:serve({ timeout = 2 })
    ready = true
end

-- ---------------------------------------------------------------------------
-- Server order, demotion (first: it needs both servers healthy)
-- ---------------------------------------------------------------------------

test("servers are asked one at a time in the scope's order, healthy first; one that times out, or answers SERVFAIL, REFUSED or FORMERR, is demoted behind its peer and the question moves to the next server",
    { spec = "PSPU *nri-resolution.servers-in-order-healthy-first PSPU *nri-resolution.failing-server-demoted PSPU *nri-resolution.question-moves-to-next-server" },
    function(t)
        up(t)
        t:assert_eq(demoted(), "", "both servers start healthy")

        -- Both healthy: the scope's first server, not the lower address.
        local n1, g1 = fresh("order1")
        dns.forget(gw)
        local r = resolve(n1, A)
        local qs = dns.queries(gw, is(n1))
        t:log("both healthy: " .. servers_of(qs))
        t:assert(r and r.outcome == "found" and texts(r) == g1, "found")
        t:assert_eq(servers_of(qs), "udp@" .. S1, "asked once, at the scope's first server")

        -- The first is silent: the second is asked only after the first's
        -- 2 s, never alongside it, and the first is demoted.
        local n2, g2 = fresh("order2")
        HOOK = function(q, _, ctx)
            if dns.same_name(qname(q) or "", n2) and ctx.server == S1 then return false end
        end
        dns.forget(gw)
        r = resolve(n2, A)
        HOOK = nil
        qs = dns.queries(gw, is(n2))
        qlog(t, qs)
        t:assert(r and r.outcome == "found" and texts(r) == g2, "found at the second server")
        t:assert_eq(servers_of(qs), "udp@" .. S1 .. ",udp@" .. S2, "the first server, then the next")
        local gap = qs[2].at - qs[1].at
        t:assert(gap >= 1.7, string.format("the next server only after the first's timeout (%.2f s): never in parallel", gap))
        t:assert_eq(demoted(), S1, "the server that timed out is demoted")

        -- Healthy first: the next question starts at the second server.
        local n3, g3 = fresh("order3")
        dns.forget(gw)
        r = resolve(n3, A)
        qs = dns.queries(gw, is(n3))
        t:assert(r and r.outcome == "found" and texts(r) == g3, "found")
        t:assert_eq(servers_of(qs), "udp@" .. S2, "a demoted server is tried after its peer")

        -- Error codes: each demotes the server that sent it and moves the
        -- question on at once.
        for _, rc in ipairs({ { "SERVFAIL", 2 }, { "REFUSED", 5 }, { "FORMERR", 1 } }) do
            local dem = demoted()
            local first = (dem == S1) and S2 or S1
            local other = (first == S1) and S2 or S1
            local n, g = fresh("order-" .. rc[1]:lower())
            HOOK = function(q, d, ctx)
                if dns.same_name(qname(q) or "", n) and ctx.server == first then
                    d.rcode, d.answers, d.authority = rc[2], {}, {}
                    return d
                end
            end
            dns.forget(gw)
            r = resolve(n, A)
            HOOK = nil
            qs = dns.queries(gw, is(n))
            local now = demoted()
            t:log(string.format("%s from %s: %s; demoted before [%s], after [%s]", rc[1], first, servers_of(qs), dem, now))
            t:assert(r and r.outcome == "found" and texts(r) == g, rc[1] .. ": found at the other server")
            t:assert_eq(servers_of(qs), "udp@" .. first .. ",udp@" .. other, rc[1] .. ": the healthy server, then the next")
            t:assert(qs[2].at - qs[1].at < 1.5, rc[1] .. ": moved on at once")
            t:assert_eq(now, first, rc[1] .. ": the server that answered it is demoted (its peer's answer lifted the peer's)")
        end
    end)

-- ---------------------------------------------------------------------------
-- The message
-- ---------------------------------------------------------------------------

test("the query: RD and nothing else set, one question — the case-randomised candidate, the type asked, class IN — and one OPT advertising 1 232 with DO, version and extended code 0; over UDP",
    { spec = "resolvd *engine-query.rd-set-other-flags-clear resolvd *engine-query.question-is-randomised-candidate-in-class-in resolvd *engine-query.opt-record-advertises-1232 PSPU *nri-resolution.udp-with-edns0" },
    function(t)
        up(t)
        ZONE["rhost.example.test"] = { { type = "TXT", ttl = 60, data = "rhost text" } }
        dns.forget(gw)
        -- A single label: the candidate is rhost.example.test.
        local r = resolve("rhost", TXT)
        local qs = dns.queries(gw, is("rhost.example.test"))
        t:assert(r and r.outcome == "found", "found")
        t:assert_eq(#qs, 1, "one query")
        local e = qs[1]
        local raw = e.raw
        local flags = string.unpack(">I2", raw, 3)
        local qd, an, ns, ar = string.unpack(">I2I2I2I2", raw, 5)
        local m = e.msg
        t:log(string.format("query: %s id %d flags 0x%04x counts %d/%d/%d/%d question %s type %d class %d",
            e.transport, m.id, flags, qd, an, ns, ar, qname(m), m.questions[1].type, m.questions[1].class))
        t:assert_eq(e.transport, "udp", "sent over UDP")
        t:assert_eq(flags, 0x0100, "RD set; QR, opcode, AA, TC, RA, Z, AD, CD and rcode clear")
        t:assert_eq(string.format("%d/%d/%d/%d", qd, an, ns, ar), "1/0/0/1", "one question, one additional, nothing else")
        t:assert(dns.same_name(qname(m), "rhost.example.test"), "the question is the candidate")
        t:assert_eq(m.questions[1].type, TXT, "the type asked")
        t:assert_eq(m.questions[1].class, 1, "class IN")
        local opt = m.additional[1]
        t:assert(opt and opt.type == 41, "the additional record is an OPT")
        t:log(string.format("OPT: owner %s size %d ttl 0x%08x rdata %d bytes", opt.name, opt.class, opt.ttl, #opt.rdata))
        t:assert_eq(opt.name, ".", "owned by the root")
        t:assert_eq(opt.class, 1232, "advertising 1 232 bytes")
        t:assert_eq(opt.ttl, 0, "extended code 0, version 0, DO clear")
        t:assert_eq(#opt.rdata, 0, "no options")
    end)

-- ---------------------------------------------------------------------------
-- Sockets
-- ---------------------------------------------------------------------------

--- resolvd's UDP sockets connected to port 53: {[local port] = remote
--- address text}, read from /proc in one guest command.
local function upstream_sockets(pid)
    local r = sut:run(string.format("ls -l /proc/%s/fd; echo ---; cat /proc/net/udp", pid))
    local fdtext, udp = r.stdout:match("^(.-)\n%-%-%-\n(.*)$")
    local inodes = {}
    for ino in (fdtext or ""):gmatch("socket:%[(%d+)%]") do inodes[ino] = true end
    local out = {}
    for line in (udp or ""):gmatch("[^\n]+") do
        local lport, raddr, rport, ino = line:match("^%s*%d+:%s+%x+:(%x+)%s+(%x+):(%x+)%s+%x+%s+%S+%s+%S+%s+%S+%s+%d+%s+%d+%s+(%d+)")
        if lport and inodes[ino] and tonumber(rport, 16) == 53 then
            local b = tonumber(raddr, 16)
            out[tonumber(lport, 16)] = string.format("%d.%d.%d.%d", b & 0xFF, (b >> 8) & 0xFF, (b >> 16) & 0xFF, b >> 24)
        end
    end
    return out
end

local function ports_text(map)
    local out = {}
    for p, a in pairs(map) do out[#out + 1] = p .. "->" .. a end
    table.sort(out)
    return table.concat(out, " ")
end

test("each transaction has its own UDP socket, from a fresh ephemeral port, connected to the server's port 53 and closed when the transaction ends; a datagram from any other address or port never reaches it",
    { spec = "resolvd *engine-query.socket-per-transaction resolvd *engine-query.udp-fresh-ephemeral-port resolvd *engine-query.udp-socket-connected-to-server PSPU *nri-resolution.fresh-source-port" },
    function(t)
        up(t)
        local pid = assert(peinit.pid_of_comm(sut, "resolvd"), "resolvd's pid")
        local lo, hi = sut:read_file("/proc/sys/net/ipv4/ip_local_port_range"):match("(%d+)%s+(%d+)")
        lo, hi = tonumber(lo), tonumber(hi)
        t:assert(upstream_sockets(pid) and next(upstream_sockets(pid)) == nil, "no upstream socket while nothing is asked")

        -- Two questions at once, each first query unanswered: two sockets.
        local na, ga = fresh("sock-a")
        local nb, gb = fresh("sock-b")
        local seen = {}
        HOOK = function(q, _, ctx)
            local n = qname(q) or ""
            for _, x in ipairs({ na, nb }) do
                if dns.same_name(n, x) then
                    seen[x] = (seen[x] or 0) + 1
                    if seen[x] == 1 then return false end
                end
            end
        end
        dns.forget(gw)
        local p0 = #PORTS
        local aa = ask({ query = "resolve", name = na, type = A, no_cache = true })
        local ab = ask({ query = "resolve", name = nb, type = A, no_cache = true })
        gw:serve({ timeout = 10, until_ = function() return (seen[na] or 0) >= 1 and (seen[nb] or 0) >= 1 end })
        local during = upstream_sockets(pid)
        local first = {}
        for i = p0 + 1, #PORTS do first[#first + 1] = PORTS[i] end
        t:log("first queries: " .. first[1].sport .. "@" .. first[1].server .. ", " .. first[2].sport .. "@" .. first[2].server
            .. "; resolvd's upstream sockets: " .. ports_text(during))
        t:assert_eq(#first, 2, "two queries")
        for _, f in ipairs(first) do
            t:assert_eq(during[f.sport], f.server, "the query from port " .. f.sport
                .. " has its own resolvd socket, connected to " .. f.server .. ":53")
        end
        t:assert(first[1].sport ~= first[2].sport, "two transactions, two ports")
        local ra, rb = finish(aa, 15), finish(ab, 15)
        HOOK = nil
        t:assert(ra and ra.outcome == "found" and texts(ra) == ga, "the first question answered on its retry")
        t:assert(rb and rb.outcome == "found" and texts(rb) == gb, "the second question answered on its retry")
        local after = upstream_sockets(pid)
        t:log("after: " .. ports_text(after))
        t:assert(next(after) == nil, "every transaction's socket is closed once it has ended")
        local retries = {}
        for i = p0 + 3, #PORTS do retries[#retries + 1] = PORTS[i] end
        t:assert_eq(#retries, 2, "two retries")
        for _, f in ipairs(retries) do
            t:assert(f.sport ~= first[1].sport and f.sport ~= first[2].sport, "a retry has a new port (" .. f.sport .. ")")
        end

        -- A run of questions: every port fresh, every one ephemeral.
        for i = 1, 6 do resolve(fresh("port" .. i), A) end
        local all, uniq = {}, {}
        for i = p0 + 1, #PORTS do
            local p = PORTS[i].sport
            all[#all + 1] = p
            t:assert(p >= lo and p <= hi, string.format("port %d is in the ephemeral range %d-%d", p, lo, hi))
            t:assert(not uniq[p], "port " .. p .. " is not reused")
            uniq[p] = true
        end
        t:log("source ports: " .. table.concat(all, " "))
        t:assert_eq(#all, 10, "ten queries")

        -- Matching replies from another address, and from another port, sent
        -- ahead of the real one: the kernel does not deliver them.
        local nc, gc = fresh("spoofed")
        HOOK = function(q, d, ctx)
            if not dns.same_name(qname(q) or "", nc) then return nil end
            local bad = { id = d.id, qr = true, rd = d.rd, ra = true, questions = questions_of(q),
                          answers = { { name = qname(q), type = "A", ttl = 60, data = BOGUS } }, edns = d.edns }
            send_reply(ctx, dns.encode(bad), { src = "10.77.0.9" })
            send_reply(ctx, dns.encode(bad), { sport = 5353 })
            return d
        end
        dns.forget(gw)
        local c0 = counters()
        local rc = resolve(nc, A)
        HOOK = nil
        local d = delta(c0, counters())
        local qs = dns.queries(gw, is(nc))
        t:log("spoofed then real: " .. tostring(rc and rc.outcome) .. " " .. texts(rc) .. "; " .. #qs .. " query; " .. dtext(d))
        t:assert(rc and rc.outcome == "found", "found")
        t:assert_eq(texts(rc), gc, "the real reply is used; the matching replies from 10.77.0.9:53 and from port 5353 never arrived")
        t:assert_eq(#qs, 1, "at the first query")
        t:assert_eq(d.failed, 0, "no failure")
    end)

-- ---------------------------------------------------------------------------
-- The generator
-- ---------------------------------------------------------------------------

local MUL = 0x2545F4914F6CDD1D
local INV = MUL
for _ = 1, 6 do INV = INV * (2 - MUL * INV) end
assert(INV * MUL == 1, "the multiplier's inverse mod 2^64")

local function step(x)
    x = x ~ (x >> 12)
    x = x ~ (x << 25)
    x = x ~ (x >> 27)
    return x
end
local function draw(g) g.s = step(g.s); return g.s * MUL end

local function is_letter(c) return c:match("^%a$") ~= nil end
local function swap(c) return c:lower() == c and c:upper() or c:lower() end

--- The case bits a name was sent with, against `asked` (same name): one
--- per letter, 1 where the case differs.
local function case_bits(asked, sent)
    local bits = {}
    for i = 1, #asked do
        local c = asked:sub(i, i)
        if is_letter(c) then bits[#bits + 1] = (sent:sub(i, i) ~= c) and 1 or 0 end
    end
    return bits
end

--- What the generator, in state `g`, makes of a transaction for `asked`:
--- the ID and the name as sent.
local function predict(g, asked)
    local id = draw(g) & 0xFFFF
    local bits, n = draw(g), 0
    local out = {}
    for i = 1, #asked do
        local c = asked:sub(i, i)
        if is_letter(c) then
            if n == 64 then bits, n = draw(g), 0 end
            if bits & 1 == 1 then c = swap(c) end
            bits, n = bits >> 1, n + 1
        end
        out[#out + 1] = c
    end
    return id, table.concat(out)
end

--- Recover the generator from `asked` (at least 64 letters, sent as
--- `sent`): the state after the draw that gave its first 64 case bits.
--- Returns the state table and the case bits beyond 64.
local function recover(asked, sent)
    local bits = case_bits(asked, sent)
    assert(#bits >= 64, "recover: fewer than 64 letters")
    local o = 0
    for i = 1, 64 do o = o | (bits[i] << (i - 1)) end
    local g = { s = o * INV }
    local rest = {}
    for i = 65, #bits do rest[#rest + 1] = bits[i] end
    return g, rest
end

-- 76 letters: a 63-letter label, then q7-r, example, test.
local function long_name(tag)
    local alpha = "abcdefghijklmnopqrstuvwxyz"
    local l = (alpha .. alpha .. alpha):sub(1, 63)
    return l .. "." .. tag .. "7-r.example.test"
end

--- Walk every query logged from the one at index `from` (exclusive) on,
--- predicting each from `g`. Returns {sent, asked, id, pid, pname, ok}.
local function walk(g, log, from)
    local out = {}
    for i = from + 1, #log do
        local e = log[i]
        local sent = qname(e.msg) or ""
        local asked = sent:lower()
        local pid, pname = predict(g, asked)
        out[#out + 1] = { sent = sent, transport = e.transport, id = e.msg.id, pid = pid, pname = pname,
                          ok = (pid == e.msg.id and pname == sent) }
    end
    return out
end

test("the ID is the low 16 bits of the transaction's first xorshift64* draw and the case pattern comes from the next, one bit per letter, lowest first, a new draw after 64; every transaction, a retry or a TCP retry included, gets its own",
    { spec = "resolvd *engine-query.generator-is-xorshift64-star resolvd *engine-query.letters-flipped-on-generator-bits resolvd *engine-query.case-bits-consumed-per-letter resolvd *engine-query.id-fresh-per-transaction resolvd *engine-query.new-pattern-every-transaction" },
    function(t)
        up(t)
        local long = long_name("q")
        dns.forget(gw)
        local r = resolve(long, A)
        t:assert(r and r.outcome == "notfound", "the long name asked (notfound)")
        local log = dns.queries(gw)
        t:assert_eq(#log, 1, "one query so far")
        local sent = qname(log[1].msg)
        t:log("asked " .. long .. "\nsent  " .. sent)
        local g, rest = recover(long, sent)
        -- The letters past 64 use the next draw, lowest bit first.
        local o3, want = draw(g), {}
        for i = 1, #rest do want[i] = (o3 >> (i - 1)) & 1 end
        t:assert_eq(table.concat(rest), table.concat(want),
            "letters 65-76 follow the next draw: the state is recovered, and bits go only to letters")

        -- Names with digits and hyphens; a truncated reply and its TCP
        -- retry; a timeout and its retry.
        local digits = "n0-1x9.example.test"
        ZONE[digits] = { { type = "A", ttl = 60, data = "10.77.0.90" } }
        local trunc = "trunc.example.test"
        ZONE[trunc] = { { type = "A", ttl = 60, data = "10.77.0.91" } }
        local slow, gslow = fresh("slow-0x20")
        local nslow = 0
        HOOK = function(q, d, ctx)
            local n = qname(q) or ""
            if dns.same_name(n, trunc) and ctx.transport == "udp" then d.tc, d.answers = true, {}; return d end
            if dns.same_name(n, slow) then
                nslow = nslow + 1
                if nslow == 1 then return false end
            end
        end
        t:assert(resolve(digits, A).outcome == "found", "digits name found")
        t:assert(resolve(trunc, A).outcome == "found", "truncated name found over TCP")
        local rs = resolve(slow, A)
        HOOK = nil
        t:assert(rs and texts(rs) == gslow, "slow name found on its retry")

        log = dns.queries(gw)
        local res = walk(g, log, 1)
        local good = 0
        for _, x in ipairs(res) do
            t:log(string.format("%s %-22s id %5d predicted %5d; sent %s predicted %s %s", x.transport, x.sent:lower(), x.id,
                x.pid, x.sent, x.pname, x.ok and "ok" or "MISMATCH"))
            if x.ok then good = good + 1 end
        end
        t:assert_eq(#res, 5, "five transactions: digits, truncated UDP and TCP, slow and its retry")
        t:assert_eq(res[2].transport .. res[3].transport, "udptcp", "the truncated reply was retried over TCP")
        t:assert_eq(good, #res, "every later ID and case pattern is exactly what the recovered generator gives")
    end)

-- PEI-1351: the ID and the case bits come from xorshift64*, so one query's
-- case pattern (64 letters) gives the generator's state, and every later ID
-- and pattern is predicted exactly. A forger who sees one query (the
-- upstream, anything on the path, an authoritative server for a name a local
-- program asks about) loses the ID and case from its work factor.
test("the message ID and the case pattern are random: what one query shows does not predict the next",
    { spec = "PSPU *nri-resolution.random-message-id PSPU *nri-resolution.case-randomised-and-echo-required", tags = { "known-bug" } },
    function(t)
        up(t)
        local long = long_name("z")
        dns.forget(gw)
        resolve(long, A)
        local log = dns.queries(gw)
        t:assert_eq(#log, 1, "one query")
        local sent = qname(log[1].msg)
        local upper, lower = sent:find("%u") ~= nil, sent:find("%l") ~= nil
        t:log("asked " .. long .. "\nsent  " .. sent)
        t:assert(upper and lower, "the case of the name is randomised")
        local g = recover(long, sent)
        draw(g)              -- the draw for letters 65-76

        -- The echo is required: a reply whose name differs in case is not used.
        local echo, gecho = fresh("echo")
        local n = 0
        HOOK = function(q, d)
            if not dns.same_name(qname(q) or "", echo) then return nil end
            n = n + 1
            if n > 1 then return nil end
            d.questions = questions_of(q)
            local nm = d.questions[1].name
            local i = nm:find("%a")
            d.questions[1].name = nm:sub(1, i - 1) .. swap(nm:sub(i, i)) .. nm:sub(i + 1)
            d.answers = { { name = qname(q), type = "A", ttl = 60, data = BOGUS } }
            return d
        end
        local re = resolve(echo, A)
        HOOK = nil
        t:assert(re and re.outcome == "found" and texts(re) == gecho, "the reply with the wrong case is not used")
        for i = 1, 3 do resolve(fresh("next" .. i), A) end

        log = dns.queries(gw)
        local res = walk(g, log, 1)
        local predicted = 0
        for _, x in ipairs(res) do
            t:log(string.format("%s id %5d predicted %5d; sent %s predicted %s", x.sent:lower(), x.id, x.pid, x.sent, x.pname))
            if x.ok then predicted = predicted + 1 end
        end
        t:assert_eq(#res, 5, "five later transactions")
        t:assert(predicted < #res, string.format("%d of %d later IDs and case patterns were predicted from one query", predicted, #res))
    end)

-- ---------------------------------------------------------------------------
-- TCP
-- ---------------------------------------------------------------------------

--- A name with 120 A records: its UDP reply (about 2 KB) is truncated by
--- the gateway's server, its TCP reply is whole.
local function big(label)
    local name = label .. ".example.test"
    local recs = {}
    for i = 1, 120 do recs[i] = { type = "A", ttl = 60, data = string.format("10.78.%d.%d", i // 250, i % 250) } end
    ZONE[name] = recs
    return name
end

test("a truncated UDP reply is retried over TCP, to the same server (not the first in order), as a new transaction with its own 2 s deadline that is not an attempt; one query per connection, which resolvd closes when the transaction ends",
    { spec = "resolvd *engine-query.truncated-udp-retried-over-tcp-same-server resolvd *engine-query.tcp-one-query-per-connection PSPU *nri-resolution.truncated-retried-over-tcp-same-server" },
    function(t)
        up(t)
        -- Same server: the truncated reply is held a second, and meanwhile
        -- another question gets SERVFAIL from that server, which puts it
        -- behind its peer. The TCP retry still goes to it.
        local s = rstatus()
        local dem = table.concat(eth0_scope(s).demoted or {}, ",")
        local F = (dem == S1) and S2 or S1
        local G = (F == S1) and S2 or S1
        local name = big("bigtc")
        local other, gother = fresh("servfail-meanwhile")
        HOOK = function(q, d, ctx)
            local n = qname(q) or ""
            if dns.same_name(n, name) and ctx.transport == "udp" then d.delay = 1.0; return d end
            if dns.same_name(n, other) and ctx.server == F then d.rcode, d.answers = 2, {}; return d end
        end
        dns.forget(gw)
        local a = ask({ query = "resolve", name = name, type = A, no_cache = true })
        gw:serve({ timeout = 10, until_ = function() return #dns.queries(gw, is(name)) >= 1 end })
        local ro = resolve(other, A)
        t:assert(ro and texts(ro) == gother, "the other question was answered by the peer")
        local dem_mid = demoted()
        t:log("while the truncated reply is held: demoted [" .. dem_mid .. "]")
        t:assert_eq(dem_mid, F, "the first server is now behind its peer")
        local r = finish(a, 15)
        local conns_open = 0
        for _ in pairs(gw.dns_conns) do conns_open = conns_open + 1 end
        local closed = gw:serve({ timeout = 5, until_ = function() return next(gw.dns_conns) == nil end })
        HOOK = nil
        local qs = dns.queries(gw, is(name))
        qlog(t, qs)
        t:assert(r and r.outcome == "found", "found")
        t:assert_eq(#r.records, 120, "the whole answer, from TCP")
        t:assert_eq(servers_of(qs), "udp@" .. F .. ",tcp@" .. F, "one UDP query, then one TCP query to the same server, not to " .. G)
        t:assert(closed, "resolvd closed the TCP connection once the transaction ended (" .. conns_open .. " open at the answer)")

        -- Own deadline, not an attempt: three truncated UDP replies, each
        -- followed by a TCP transaction that fails (a mismatched reply, so
        -- a timeout; then a close), then a third that answers. Six
        -- transactions, three of them attempts; the first TCP retry starts
        -- 1.2 s into the UDP transaction and still gets its own 2 s.
        local name2 = big("tcpbudget")
        local u, tc = 0, 0
        HOOK = function(q, d, ctx)
            if not dns.same_name(qname(q) or "", name2) then return nil end
            if ctx.transport == "udp" then
                u = u + 1
                if u == 1 then d.delay = 1.2 end
                return d                     -- truncated by the server (too big)
            end
            tc = tc + 1
            if tc == 1 then d.id = (d.id + 1) & 0xFFFF; return d end
            if tc == 2 then return false end
            return d
        end
        dns.forget(gw)
        local c0 = counters()
        local r2 = resolve(name2, A, { timeout = 25 })
        HOOK = nil
        local d = delta(c0, counters())
        qs = dns.queries(gw, is(name2))
        qlog(t, qs)
        t:log("budget: " .. tostring(r2 and r2.outcome) .. "; " .. dtext(d))
        local kinds = {}
        for _, e in ipairs(qs) do kinds[#kinds + 1] = e.transport end
        t:assert_eq(table.concat(kinds, ","), "udp,tcp,udp,tcp,udp,tcp", "three UDP attempts, each retried over TCP")
        t:assert(r2 and r2.outcome == "found" and #r2.records == 120, "the third TCP retry's answer is used: TCP retries are not attempts")
        local own = qs[3].at - qs[2].at
        local from_udp = qs[3].at - qs[1].at
        t:assert(own >= 1.7 and own <= 2.7, string.format("the first TCP retry timed out 2 s after it began (%.2f s)", own))
        t:assert(from_udp >= 2.8, string.format("not at the UDP transaction's deadline (%.2f s after the UDP query)", from_udp))
        t:assert_eq(d.sent, 6, "six transactions")
    end)

test("a TCP reply with TC set is used as it is",
    { spec = "resolvd *engine-query.truncated-tcp-reply-used-as-is" }, function(t)
        up(t)
        local name = big("tctcp")
        HOOK = function(q, d, ctx)
            if dns.same_name(qname(q) or "", name) and ctx.transport == "tcp" then d.tc = true; return d end
        end
        dns.forget(gw)
        local r = resolve(name, A)
        gw:serve({ timeout = 3 })
        HOOK = nil
        local qs = dns.queries(gw, is(name))
        qlog(t, qs)
        t:assert(r and r.outcome == "found", "found")
        t:assert_eq(#r.records, 120, "with the TCP reply's records")
        t:assert_eq(servers_of(qs):gsub("@[%d%.]+", ""), "udp,tcp", "and nothing asked after it")
    end)

-- ---------------------------------------------------------------------------
-- EDNS0 and the attempt limit
-- ---------------------------------------------------------------------------

test("there is no fallback to a query without EDNS0: FORMERR fails the attempt, and every attempt carries the OPT",
    { spec = "resolvd *engine-query.no-fallback-without-edns" }, function(t)
        up(t)
        local name = fresh("formerr")
        HOOK = function(q, d)
            if not dns.same_name(qname(q) or "", name) then return nil end
            d.rcode, d.answers, d.edns = 1, {}, nil
            return d
        end
        dns.forget(gw)
        local c0 = counters()
        local r = resolve(name, A)
        HOOK = nil
        local d = delta(c0, counters())
        local qs = dns.queries(gw, is(name))
        qlog(t, qs)
        t:log("formerr: " .. tostring(r and r.outcome) .. "; " .. dtext(d))
        t:assert(r and r.outcome == "unavailable", "unavailable after the attempts")
        t:assert_eq(#qs, 3, "three attempts")
        for i, e in ipairs(qs) do
            t:assert(e.msg.edns and e.msg.edns.udp_size == 1232, "attempt " .. i .. " still carries the OPT")
        end
        t:assert_eq(d.failed, 3, "each FORMERR failed its attempt")
    end)

-- PEI-1361: resolvd's budget is per candidate: a candidate that ends
-- notfound hands the next one three fresh attempts, so a question can make
-- far more than three (and TCP retries are not counted at all).
test("after the attempt limit the question is unavailable: three attempts, however many candidates",
    { spec = "PSPU *nri-resolution.attempt-limit-unavailable", tags = { "known-bug" } }, function(t)
        up(t)
        -- One candidate, no answer: three attempts, then unavailable.
        local plain = fresh("silent3")
        HOOK = function(q) if dns.same_name(qname(q) or "", plain) then return false end end
        dns.forget(gw)
        local r = resolve(plain, A, { timeout = 15 })
        HOOK = nil
        local qs = dns.queries(gw, is(plain))
        t:log("one candidate: " .. tostring(r and r.outcome) .. " after " .. #qs .. " queries")
        t:assert(r and r.outcome == "unavailable", "unavailable")
        t:assert_eq(#qs, 3, "after three attempts")

        -- Two candidates: lim.example.test (the scope's domain) times out
        -- once and is then NXDOMAIN; lim.extra.test (ExtraSearchDomains)
        -- never answers. The third attempt is the first to the second
        -- candidate.
        network.write(sut, "Dns", { ExtraSearchDomains = "multi:extra.test" })
        gw:serve({ timeout = 2 })
        local c1, c2 = "lim.example.test", "lim.extra.test"
        local n1 = 0
        HOOK = function(q)
            local n = qname(q) or ""
            if dns.same_name(n, c1) then
                n1 = n1 + 1
                if n1 == 1 then return false end
                return nil             -- NXDOMAIN: not in the zone
            end
            if dns.same_name(n, c2) then return false end
        end
        dns.forget(gw)
        local r2 = resolve("lim", A, { timeout = 20 })
        HOOK = nil
        network.reg(sut, { "del", network.KEY .. "\\Dns", "ExtraSearchDomains" })
        local q1, q2 = dns.queries(gw, is(c1)), dns.queries(gw, is(c2))
        t:log(string.format("two candidates: %s; %d queries for %s, %d for %s", tostring(r2 and r2.outcome), #q1, c1, #q2, c2))
        qlog(t, dns.queries(gw))
        t:assert(r2 and r2.outcome == "unavailable", "unavailable")
        t:assert_eq(#q1, 2, "the first candidate: a timeout, then NXDOMAIN")
        t:assert(#q2 >= 1, "the second candidate was asked")
        t:assert_eq(#q1 + #q2, 3, "three attempts for the question in all")
    end)

-- ---------------------------------------------------------------------------
-- Send failures, link-local and zoned servers (last: edits the profile)
-- ---------------------------------------------------------------------------

test("a send that fails is logged `upstream <server>: <error>` and fails the attempt at once; a timeout or a later TCP failure is not logged. A bare link-local server is sent to unscoped, so every attempt to it fails so",
    { spec = "resolvd *engine-query.send-failure-logged resolvd *engine-query.link-local-server-sent-unscoped" },
    function(t)
        up(t)
        -- The earlier tests had timeouts, mismatched TCP replies and TCP
        -- closes against both servers: none was logged.
        for _, srv in ipairs({ S1, S2 }) do
            local l = logged("upstream " .. srv)
            t:assert(l == nil, "no `upstream " .. srv .. "` line for a timeout or a TCP failure (" .. tostring(l) .. ")")
        end

        network.write(sut, "Profiles\\default", { ["Dns.Servers"] = "multi:fe80::1" })
        local ok = gw:serve({ timeout = 40, until_ = function()
            local s = network.call(sut, { query = "status" }, { path = RSOCK })
            local sc = s and s.ok and eth0_scope(s)
            return sc ~= nil and table.concat(sc.servers or {}, ",") == "fe80::1," .. S1 .. "," .. S2
        end })
        t:assert(ok, "resolvd has eth0's servers as fe80::1, then the lease's")
        local before = demoted()
        local name, good = fresh("linklocal")
        dns.forget(gw)
        local c0 = counters()
        local t0 = gw.vm:clock():get()
        local r = resolve(name, A)
        local took = gw.vm:clock():get() - t0
        local d = delta(c0, counters())
        local qs = dns.queries(gw, is(name))
        local line = logged("upstream fe80::1: ")
        local after = demoted()
        t:log(string.format("linklocal: %s %s via %s; %s; demoted before [%s] after [%s]; log: %s", tostring(r and r.outcome),
            texts(r), tostring(r and r.server), dtext(d), before, after, tostring(line)))
        qlog(t, qs)
        t:assert(r and r.outcome == "found" and texts(r) == good, "found at the next server")
        t:assert_eq(#qs, 1, "one query reached the gateway")
        t:assert(took < 1.5, string.format("answered in %.2f s: fe80::1's attempt failed at once, not at a deadline", took))
        t:assert_eq(d.sent, 2, "two transactions started: fe80::1's and the next")
        t:assert_eq(d.failed, 1, "fe80::1's failed")
        t:assert(line ~= nil, "the failure is logged `upstream fe80::1: <error>`")
        t:assert(after:find("fe80::1", 1, true) ~= nil, "fe80::1 is demoted")

        network.reg(sut, { "del", network.KEY .. "\\Profiles\\default", "Dns.Servers" })
        gw:serve({ timeout = 40, until_ = function()
            local s = network.call(sut, { query = "status" }, { path = RSOCK })
            local sc = s and s.ok and eth0_scope(s)
            return sc ~= nil and table.concat(sc.servers or {}, ",") == S1 .. "," .. S2
        end })
    end)

test("an address with a zone is not a server: FallbackServers skips fe80::1%eth0 and logs it",
    { spec = "resolvd *engine-query.zoned-server-address-dropped" }, function(t)
        up(t)
        network.write(sut, "Dns", { FallbackServers = "multi:fe80::1%eth0,10.77.0.1" })
        local s
        wait_until(function()
            s = rstatus()
            return table.concat(s.fallback_servers or {}, ",") ~= ""
        end, { timeout = 10, interval = 0.25, desc = "resolvd re-read its registry" })
        local line = logged("fe80::1%eth0")
        t:log("fallback_servers: " .. table.concat(s.fallback_servers or {}, ",") .. "; log: " .. tostring(line))
        network.reg(sut, { "del", network.KEY .. "\\Dns", "FallbackServers" })
        t:assert_eq(table.concat(s.fallback_servers, ","), "10.77.0.1", "the zoned address is dropped, the plain one kept")
        t:assert(line ~= nil and line:find("ignoring malformed address", 1, true) ~= nil,
            "it is logged as a malformed address")
    end)
