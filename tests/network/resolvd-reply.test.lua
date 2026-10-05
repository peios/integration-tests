-- resolvd §4.8 — reply validation: when an upstream reply matches its
-- transaction, what a datagram that does not match does to it (PEI-1338),
-- and what resolvd takes from a reply it uses; plus PSPU §6.7's rule that a
-- mismatched reply is ignored. The 4 096-byte read buffer of §4.7 is here
-- too, since what it does is cut a long datagram short.
--
-- Harness: the scripted gateway (helpers.gateway) with its DNS server
-- (helpers.dns) as the scope's one server, 10.77.0.1, and a whole Peios
-- (helpers.network). The server's `on` hook is routed through `HOOK`,
-- which each test sets for its own names: it can send any reply, send one
-- datagram by hand and then the default, or send a datagram longer than
-- the link's MTU as IPv4 fragments (built here; the helper sends single
-- frames). Questions are asked on the native socket from the agent, with
-- `no_cache`, while the gateway pumps; `status` (answered at once) is read
-- between pumps, so it can be read inside a transaction's 2 s window.
--
-- timed is stopped once the machine is up, so the only upstream questions
-- are the tests' own and the counters move only for them.
--
-- Own VMs: the reply levers are this file's; the generator, sockets and
-- server order are resolvd-query.test.lua's.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local unixsock = require("helpers.unixsock")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")
local msgpack = require("helpers.msgpack")

peinit.claim(2)

local SERVER = "10.77.0.1"
local RSOCK = "/run/resolvd/resolv.sock"
local A, AAAA, MX = 1, 28, 15
local BOGUS = "10.66.6.6"

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })

local ZONE = {}
local HOOK
dns.serve(gw, {
    zone = ZONE,
    soa = { name = "example.test", data = { minimum = 30 } },
    on = function(q, d, ctx) if HOOK then return HOOK(q, d, ctx) end end,
})
local sut = network.boot({ bridges = { lan }, gateway = gw })

-- ---- the gateway's levers -------------------------------------------------

local function qname(q) return q and q.questions and q.questions[1] and q.questions[1].name end

local function is(name) return function(e) return e.msg and dns.same_name(qname(e.msg) or "", name) end end

--- A copy of a question list, so a reply's can be changed without
--- touching the logged query's.
local function questions_of(q)
    local out = {}
    for _, x in ipairs(q.questions) do out[#out + 1] = { name = x.name, type = x.type, class = x.class } end
    return out
end

--- Send `payload` by hand as a UDP reply to the query in `ctx`, from
--- `o.src` (the address asked) and `o.sport` (53).
local function send_reply(ctx, payload, o)
    o = o or {}
    local f = ctx.frame
    gw:send_udp4(f.src, f.src_ip, o.sport or 53, f.udp.sport, payload, { src = o.src or f.dst_ip })
end

--- Send `payload` as a UDP reply in IPv4 fragments of at most 1 480
--- bytes, so a datagram longer than the MTU reaches the machine whole.
local frag_id = 0x5100
local function send_fragmented(ctx, payload)
    local f = ctx.frame
    local seg = ntfe.udp(f.dst_ip, f.src_ip, 53, f.udp.sport, payload)
    frag_id = frag_id + 1
    local off = 0
    while off < #seg do
        local chunk = seg:sub(off + 1, off + 1480)
        local more = off + #chunk < #seg
        gw:send(ntfe.eth(f.src, gw.mac, ntfe.ETH_P.IP)
            .. ntfe.ipv4(f.dst_ip, f.src_ip, 17, #chunk, { id = frag_id, frag = (more and 0x2000 or 0) | (off // 8) })
            .. chunk)
        off = off + #chunk
    end
end

--- `m` encoded to exactly `size` bytes, by an opaque private-type record
--- in the additional section (before the OPT, which stays last).
local function sized(m, size)
    local k, enc = 0, nil
    for _ = 1, 4 do
        m.additional = { { name = ".", type = 65280, ttl = 0, rdata = string.rep("p", k) } }
        enc = dns.encode(m)
        k = k + (size - #enc)
    end
    assert(#enc == size, "sized: " .. #enc .. " bytes, not " .. size)
    return enc
end

-- ---- the native socket ----------------------------------------------------

local function rstatus()
    local s, err = network.call(sut, { query = "status" }, { path = RSOCK })
    assert(s and s.ok, "resolvd status: " .. tostring(err or (s and s.error)))
    return s
end

local function counters() return rstatus().counters end

local function demoted()
    for _, sc in ipairs(rstatus().scopes or {}) do
        if sc.interface == "eth0" then return table.concat(sc.demoted or {}, ",") end
    end
    return "(no eth0 scope)"
end

local function ask(req)
    local fd = assert(unixsock.socket(sut, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
    local c = unixsock.connect(sut, fd, RSOCK)
    assert(c.ret == 0, "connect resolvd: " .. unixsock.errname(c.errno))
    local p = msgpack.encode(req)
    ntfe.send(sut, fd, string.pack("<I4", #p) .. p)
    return { fd = fd, buf = "" }
end

--- The reply to `a`, if it has come; never waits.
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

--- `resolve` `name` while the gateway pumps; the cache is skipped unless
--- `o.cache`.
local function resolve(name, rtype, o)
    o = o or {}
    return finish(ask({ query = "resolve", name = name, type = rtype or A, no_cache = not o.cache }), o.timeout)
end

local function texts(r)
    local out = {}
    for _, rec in ipairs((r and r.records) or {}) do out[#out + 1] = rec.text end
    return table.concat(out, ",")
end

local function names(r)
    local out = {}
    for _, rec in ipairs((r and r.records) or {}) do out[#out + 1] = rec.name end
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

local octet = 100
--- A fresh name in the zone with one A record; returns it and the address.
local function fresh(label)
    octet = octet + 1
    local name = label .. ".example.test"
    local addr = "10.77.0." .. octet
    ZONE[name] = { { type = "A", ttl = 60, data = addr } }
    return name, addr
end

local ready = false
local function up(t)
    if ready then return end
    t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound a lease")
    sut:run("svctl stop timed")
    local ok = gw:serve({ timeout = 30, until_ = function()
        local s = network.call(sut, { query = "status" }, { path = RSOCK })
        if not (s and s.ok) then return false end
        for _, sc in ipairs(s.scopes or {}) do
            if sc.interface == "eth0" and table.concat(sc.servers or {}, ",") == SERVER then return true end
        end
        return false
    end })
    t:assert(ok, "resolvd has eth0's scope with the gateway as its server")
    -- Let anything timed asked before it stopped be answered.
    gw:serve({ timeout = 2 })
    ready = true
end

--- Ask `label`.example.test (A) where the first query's reply is `first`'s
--- (applied to the default reply, whose answer is replaced by BOGUS) and
--- every later one is the default. Returns the reply, the name's queries,
--- the counter delta and the genuine address.
local function first_bad(t, label, first)
    local name, good = fresh(label)
    local n = 0
    HOOK = function(q, d, ctx)
        if not dns.same_name(qname(q) or "", name) then return nil end
        n = n + 1
        if n > 1 then return nil end
        d.questions = questions_of(q)
        d.answers = { { name = qname(q), type = "A", ttl = 60, data = BOGUS } }
        return first(d, q, ctx)
    end
    dns.forget(gw)
    local c0 = counters()
    local r = resolve(name, A)
    HOOK = nil
    local c1 = counters()
    local qs = dns.queries(gw, is(name))
    local d = delta(c0, c1)
    t:log(string.format("%s: %s %s; %s", label, tostring(r and r.outcome), texts(r), dtext(d)))
    qlog(t, qs)
    return r, qs, d, good
end

--- The reply was not used: the transaction ran to its deadline and the
--- second query's genuine answer came back.
local function not_used(t, r, qs, d, good, what)
    t:assert(r and r.ok, what .. ": a reply")
    t:assert_eq(r.outcome, "found", what .. ": found in the end")
    t:assert_eq(texts(r), good, what .. ": the genuine answer, never the mismatched reply's " .. BOGUS)
    t:assert_eq(#qs, 2, what .. ": asked twice")
    local gap = qs[2].at - qs[1].at
    t:assert(gap >= 1.7 and gap <= 3.2, string.format("%s: the second query at the first's 2 s deadline (%.2f s)", what, gap))
    t:assert_eq(d.failed, 1, what .. ": one failure, the timeout")
end

-- ---------------------------------------------------------------------------
-- A reply that is used
-- ---------------------------------------------------------------------------

test("NOERROR is found with the answer section's IN records in the server's order; NXDOMAIN is notfound",
    { spec = "resolvd *engine-reply.noerror-is-found resolvd *engine-reply.nxdomain-is-notfound resolvd *engine-reply.answer-records-of-class-in" },
    function(t)
        up(t)
        local name = "order.example.test"
        ZONE[name] = { { type = "A", ttl = 60, data = "10.77.0.83" } }
        HOOK = function(q, d)
            if not dns.same_name(qname(q) or "", name) then return nil end
            local at = qname(q)
            d.answers = {
                { name = at, type = "A", ttl = 60, data = "10.77.0.83" },
                { name = at, type = "A", class = dns.CLASS.CH, ttl = 60, data = "10.77.0.99" },
                { name = at, type = "A", ttl = 60, data = "10.77.0.81" },
                { name = at, type = "A", class = dns.CLASS.HS, ttl = 60, data = "10.77.0.98" },
                { name = at, type = "A", ttl = 60, data = "10.77.0.82" },
            }
            return d
        end
        local r = resolve(name, A)
        HOOK = nil
        t:log("found: " .. tostring(r and r.outcome) .. " rcode " .. tostring(r and r.rcode) .. " " .. texts(r))
        t:assert(r and r.ok, "a reply")
        t:assert_eq(r.outcome, "found", "NOERROR is found")
        t:assert_eq(r.rcode, 0, "rcode 0")
        t:assert_eq(r.source, "dns", "from the server")
        t:assert_eq(texts(r), "10.77.0.83,10.77.0.81,10.77.0.82", "the IN records, in the order sent; CH and HS dropped")

        local nx = resolve("absent.example.test", A)
        t:log("absent: " .. tostring(nx and nx.outcome) .. " rcode " .. tostring(nx and nx.rcode))
        t:assert(nx and nx.ok, "a reply")
        t:assert_eq(nx.outcome, "notfound", "NXDOMAIN is notfound")
        t:assert_eq(#(nx.records or {}), 0, "no records")
        t:assert_eq(#dns.queries(gw, is("absent.example.test")), 1, "asked once")
    end)

test("an NXDOMAIN's answer records are not taken",
    { spec = "resolvd *engine-reply.nxdomain-records-discarded" }, function(t)
        up(t)
        local name = "nxrec.example.test"
        HOOK = function(q, d)
            if not dns.same_name(qname(q) or "", name) then return nil end
            d.answers = { { name = qname(q), type = "A", ttl = 60, data = BOGUS } }
            return d       -- NXDOMAIN: the zone lacks the name
        end
        local r = resolve(name, A)
        HOOK = nil
        t:log("nxrec: " .. tostring(r and r.outcome) .. " records [" .. texts(r) .. "]")
        t:assert(r and r.ok, "a reply")
        t:assert_eq(r.outcome, "notfound", "notfound")
        t:assert_eq(#(r.records or {}), 0, "the record riding on the NXDOMAIN is discarded")
    end)

test("answer records are not checked against the question: another name's record and another type come back, and are cached with the answer",
    { spec = "resolvd *engine-reply.records-not-checked-against-question" }, function(t)
        up(t)
        local name = "unchecked.example.test"
        ZONE[name] = { { type = "A", ttl = 60, data = "10.77.0.84" } }
        HOOK = function(q, d)
            if not dns.same_name(qname(q) or "", name) then return nil end
            d.answers = {
                { name = qname(q), type = "A", ttl = 60, data = "10.77.0.84" },
                { name = "elsewhere.example.test", type = "A", ttl = 60, data = BOGUS },
                { name = qname(q), type = "MX", ttl = 60, data = { 10, "mx.example.test" } },
            }
            return d
        end
        local r = resolve(name, A)
        HOOK = nil
        t:log("unchecked: " .. texts(r) .. " names " .. names(r))
        t:assert(r and r.ok and r.outcome == "found", "found")
        t:assert_eq(texts(r), "10.77.0.84," .. BOGUS .. ",10 mx.example.test", "all three, in order")
        t:assert_eq(r.records[2].name, "elsewhere.example.test", "the unrelated owner name is returned")
        t:assert_eq(r.records[3].type, MX, "the unasked type is returned")
        local again = resolve(name, A, { cache = true })
        t:log("again: " .. tostring(again and again.source) .. " " .. texts(again))
        t:assert_eq(again.source, "cache", "the second ask is a cache hit")
        t:assert_eq(texts(again), "10.77.0.84," .. BOGUS .. ",10 mx.example.test", "cached with the answer")
        t:assert_eq(#dns.queries(gw, is(name)), 1, "asked upstream once")
    end)

test("the authority and additional sections are not returned",
    { spec = "resolvd *engine-reply.authority-and-additional-not-returned" }, function(t)
        up(t)
        local name, good = fresh("sections")
        HOOK = function(q, d)
            if not dns.same_name(qname(q) or "", name) then return nil end
            d.authority = { { name = "example.test", type = "NS", ttl = 60, data = "ns.example.test" } }
            d.additional = { { name = "ns.example.test", type = "A", ttl = 60, data = "10.77.0.53" } }
            return d
        end
        local r = resolve(name, A)
        HOOK = nil
        t:log("sections: " .. texts(r))
        t:assert(r and r.ok and r.outcome == "found", "found")
        t:assert_eq(texts(r), good, "only the answer section's record")
        t:assert_eq(#r.records, 1, "one record")
    end)

test("a NOERROR with no IN answer records — a referral, or a CH-only answer — is found with no records",
    { spec = "resolvd *engine-reply.empty-noerror-is-nodata" }, function(t)
        up(t)
        local ref = "referral.example.test"
        local ch = "chonly.example.test"
        HOOK = function(q, d)
            local n = qname(q) or ""
            if dns.same_name(n, ref) then
                d.aa, d.ra, d.rcode = false, false, 0
                d.answers = {}
                d.authority = { { name = "example.test", type = "NS", ttl = 60, data = "ns1.example.test" } }
                d.additional = { { name = "ns1.example.test", type = "A", ttl = 60, data = "10.77.0.53" } }
                return d
            elseif dns.same_name(n, ch) then
                d.rcode = 0
                d.answers = { { name = n, type = "A", class = dns.CLASS.CH, ttl = 60, data = BOGUS } }
                d.authority = {}
                return d
            end
        end
        local r1 = resolve(ref, A)
        local r2 = resolve(ch, A)
        HOOK = nil
        t:log("referral: " .. tostring(r1 and r1.outcome) .. " [" .. texts(r1) .. "]; ch-only: "
            .. tostring(r2 and r2.outcome) .. " [" .. texts(r2) .. "]")
        t:assert(r1 and r1.ok and r2 and r2.ok, "replies")
        t:assert_eq(r1.outcome, "found", "a referral is found")
        t:assert_eq(#(r1.records or {}), 0, "with no records")
        t:assert_eq(r2.outcome, "found", "a CH-only answer is found")
        t:assert_eq(#(r2.records or {}), 0, "with no records")
    end)

test("a record at the candidate gets the case asked; other records keep the server's case",
    { spec = "resolvd *engine-reply.candidate-case-restored" }, function(t)
        up(t)
        local asked = "CaseKept.Example.TEST"
        ZONE["casekept.example.test"] = { { type = "CNAME", ttl = 60, data = "TaRgEt.example.test" } }
        ZONE["target.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.85" } }
        dns.forget(gw)
        local r = resolve(asked, A)
        local sent = qname((dns.queries(gw, is(asked))[1] or {}).msg)
        t:log("sent " .. tostring(sent) .. "; records " .. names(r) .. " = " .. texts(r))
        t:assert(sent, "the question went upstream")
        t:assert(sent ~= asked, "the name was sent in another case (0x20)")
        t:assert(r and r.ok and r.outcome == "found", "found")
        t:assert_eq(#r.records, 2, "the CNAME and the A")
        t:assert_eq(r.records[1].name, asked, "the record at the candidate has the case asked, not the case sent")
        t:assert_eq(r.records[2].name, "TaRgEt.example.test", "the target's record keeps the server's case")
    end)

test("the server's AA, AD, RA and CD bits are carried into no answer: the native reply has no flags and stays unvalidated, the stub reply sets its own",
    { spec = "resolvd *engine-reply.upstream-flags-not-carried" }, function(t)
        up(t)
        local stubname, good1 = fresh("flags-stub")
        local natname, good2 = fresh("flags-native")
        HOOK = function(q, d)
            local n = qname(q) or ""
            if dns.same_name(n, stubname) or dns.same_name(n, natname) then
                d.aa, d.ad, d.cd, d.ra = true, true, true, false
                return d
            end
        end
        dns.forget(gw)
        -- The stub door, from inside the machine: rd set, cd clear.
        local fd = assert(ntfe.udp_connect(sut, "127.0.0.53", 53))
        ntfe.send(sut, fd, dns.encode(dns.query(stubname, "A", { id = 0x4242 })))
        local got
        gw:serve({ timeout = 10, until_ = function() got = ntfe.recv(sut, fd, 0, 4096); return got ~= nil end })
        sys.close(sut, fd)
        local up_reply = dns.queries(gw, is(stubname))[1]
        t:assert(up_reply, "the stub question went upstream")
        local m = got and dns.decode(got)
        t:assert(m, "a stub reply")
        t:log(string.format("stub reply: aa %s ad %s cd %s ra %s rcode %d answers %d", tostring(m.aa), tostring(m.ad),
            tostring(m.cd), tostring(m.ra), m.rcode, #m.answers))
        t:assert_eq(#m.answers, 1, "the stub answer carries the record")
        t:assert_eq(m.answers[1].data, good1, "the upstream record")
        t:assert_eq(m.aa, false, "AA clear, although the server set it")
        t:assert_eq(m.ad, false, "AD clear, although the server set it")
        t:assert_eq(m.cd, false, "CD as the stub client sent it, not the server's")
        t:assert_eq(m.ra, true, "RA set, although the server cleared it")

        local r = resolve(natname, A)
        HOOK = nil
        local keys = {}
        for k in pairs(r or {}) do keys[#keys + 1] = k end
        table.sort(keys)
        t:log("native reply keys: " .. table.concat(keys, ",") .. "; validation " .. tostring(r and r.validation))
        t:assert(r and r.outcome == "found" and texts(r) == good2, "the native answer is the server's")
        t:assert_eq(table.concat(keys, ","), "interface,kind,ok,outcome,rcode,records,server,source,validation",
            "the reply's fields: no flag is carried")
        t:assert_eq(r.validation, "unvalidated", "AD from the server does not make the answer validated")
    end)

test("the response code includes the OPT record's extended bits: header NOERROR or NXDOMAIN with an extended code is a failure, not found or notfound",
    { spec = "resolvd *engine-reply.extended-rcode-combined" }, function(t)
        up(t)
        -- rcode 16 = header 0 + extended 1; 19 = header 3 + extended 1.
        for _, code in ipairs({ 16, 19 }) do
            local r, qs, d, good = first_bad(t, "ext" .. code, function(rep)
                rep.rcode = code
                rep.edns = rep.edns or { udp_size = 1232 }
                return rep
            end)
            t:assert(r and r.ok, "a reply")
            t:assert_eq(r.outcome, "found", "rcode " .. code .. ": the retry's answer, so the first was a failure")
            t:assert_eq(texts(r), good, "rcode " .. code .. ": the genuine answer")
            t:assert_eq(#qs, 2, "rcode " .. code .. ": the failure moved the question on at once")
            t:assert(qs[2].at - qs[1].at < 1.5, "rcode " .. code .. ": without waiting for a deadline")
            t:assert_eq(d.failed, 1, "rcode " .. code .. ": counted as a failure")
            t:assert_eq(d.answered, 2, "rcode " .. code .. ": both replies matched")
        end
    end)

-- ---------------------------------------------------------------------------
-- Matching
-- ---------------------------------------------------------------------------

test("a reply with another ID is not used",
    { spec = "resolvd *engine-reply.match-id" }, function(t)
        up(t)
        local r, qs, d, good = first_bad(t, "badid", function(rep) rep.id = (rep.id + 1) & 0xFFFF; return rep end)
        not_used(t, r, qs, d, good, "wrong ID")
    end)

test("a reply without QR is not used",
    { spec = "resolvd *engine-reply.match-qr-set" }, function(t)
        up(t)
        local r, qs, d, good = first_bad(t, "noqr", function(rep) rep.qr = false; return rep end)
        not_used(t, r, qs, d, good, "QR clear")
    end)

test("a reply with no question, or with two, is not used",
    { spec = "resolvd *engine-reply.match-one-question" }, function(t)
        up(t)
        local r, qs, d, good = first_bad(t, "noq", function(rep) rep.questions = {}; return rep end)
        not_used(t, r, qs, d, good, "no question")
        r, qs, d, good = first_bad(t, "twoq", function(rep, q)
            rep.questions = questions_of(q)
            rep.questions[2] = { name = q.questions[1].name, type = q.questions[1].type, class = q.questions[1].class }
            return rep
        end)
        not_used(t, r, qs, d, good, "two questions")
    end)

test("a reply whose question has another type, or another class, is not used",
    { spec = "resolvd *engine-reply.match-type-and-class" }, function(t)
        up(t)
        local r, qs, d, good = first_bad(t, "badtype", function(rep) rep.questions[1].type = AAAA; return rep end)
        not_used(t, r, qs, d, good, "question type AAAA")
        r, qs, d, good = first_bad(t, "badclass", function(rep) rep.questions[1].class = dns.CLASS.CH; return rep end)
        not_used(t, r, qs, d, good, "question class CH")
    end)

test("a reply whose question name differs from the sent one only in case is not used",
    { spec = "resolvd *engine-reply.match-name-case-exact" }, function(t)
        up(t)
        local echoed
        local r, qs, d, good = first_bad(t, "casematch", function(rep)
            local n = rep.questions[1].name
            -- Flip the first letter's case: equal as a DNS name, not byte-for-byte.
            local i = n:find("%a")
            local c = n:sub(i, i)
            rep.questions[1].name = n:sub(1, i - 1) .. (c:lower() == c and c:upper() or c:lower()) .. n:sub(i + 1)
            echoed = rep.questions[1].name
            return rep
        end)
        t:log("sent " .. tostring(qname(qs[1] and qs[1].msg)) .. ", echoed " .. tostring(echoed))
        t:assert(dns.same_name(echoed, qname(qs[1].msg)) and echoed ~= qname(qs[1].msg),
            "the echo is the same name in another case")
        not_used(t, r, qs, d, good, "case differs")
    end)

test("a reply must decode, but bytes after its last section are tolerated",
    { spec = "resolvd *engine-reply.match-decodes" }, function(t)
        up(t)
        -- Trailing bytes: used at once.
        local name, good = fresh("trailing")
        HOOK = function(q, d)
            if not dns.same_name(qname(q) or "", name) then return nil end
            return { raw = dns.encode(d) .. "\0\1\2\3 trailing bytes" }
        end
        dns.forget(gw)
        local r = resolve(name, A)
        HOOK = nil
        local qs = dns.queries(gw, is(name))
        t:log("trailing: " .. tostring(r and r.outcome) .. " " .. texts(r) .. ", " .. #qs .. " query")
        t:assert(r and r.outcome == "found" and texts(r) == good, "a reply with trailing bytes is used")
        t:assert_eq(#qs, 1, "at once")

        -- A message that ends inside its last record: not used.
        local r2, qs2, d2, good2 = first_bad(t, "garbled", function(rep)
            local enc = dns.encode(rep)
            return { raw = enc:sub(1, #enc - 3) }
        end)
        not_used(t, r2, qs2, d2, good2, "cut inside its last record")
    end)

test("a datagram that does not decode — garbage, or a reply longer than the 4 096-byte read whose cut falls inside it — becomes a timeout; a reply of exactly 4 096 bytes, or a short one padded past 4 096, is used",
    { spec = "resolvd *engine-reply.undecodable-or-cut-short-datagram-becomes-timeout resolvd *engine-query.udp-read-buffer-4096" },
    function(t)
        up(t)
        -- Exactly 4 096 bytes: read whole, used at once.
        local name, good = fresh("exact4096")
        HOOK = function(q, d, ctx)
            if not dns.same_name(qname(q) or "", name) then return nil end
            send_fragmented(ctx, sized(d, 4096))
            return false
        end
        dns.forget(gw)
        local r = resolve(name, A)
        HOOK = nil
        local qs = dns.queries(gw, is(name))
        t:log("4096: " .. tostring(r and r.outcome) .. " " .. texts(r) .. ", " .. #qs .. " query")
        t:assert(r and r.outcome == "found" and texts(r) == good, "a 4 096-byte reply is used")
        t:assert_eq(#qs, 1, "at once")

        -- A short reply padded with junk to 4 500 bytes: the read cuts the
        -- junk, the message decodes, and it is used.
        name, good = fresh("padded")
        HOOK = function(q, d, ctx)
            if not dns.same_name(qname(q) or "", name) then return nil end
            local enc = dns.encode(d)
            send_fragmented(ctx, enc .. string.rep("j", 4500 - #enc))
            return false
        end
        dns.forget(gw)
        r = resolve(name, A)
        HOOK = nil
        qs = dns.queries(gw, is(name))
        t:log("padded: " .. tostring(r and r.outcome) .. " " .. texts(r) .. ", " .. #qs .. " query")
        t:assert(r and r.outcome == "found" and texts(r) == good, "a 4 500-byte datagram holding a short reply is used")
        t:assert_eq(#qs, 1, "at once")

        -- 4 097 bytes: the read loses the last byte, which is inside the
        -- last record, so it does not decode: a timeout and a retry.
        local r3, qs3, d3, good3 = first_bad(t, "over4096", function(rep, _, ctx)
            send_fragmented(ctx, sized(rep, 4097))
            return false
        end)
        not_used(t, r3, qs3, d3, good3, "a 4 097-byte reply")

        -- Garbage.
        local r4, qs4, d4, good4 = first_bad(t, "garbage", function()
            return { raw = "\0\0\0\0garbage" }
        end)
        not_used(t, r4, qs4, d4, good4, "garbage")
    end)

test("a non-matching datagram ends nothing by itself — no count, no demotion, no answer — but it costs the transaction its socket, so the real reply right behind it is lost and the transaction times out at 2 s, failing and demoting the server",
    { spec = "resolvd *engine-reply.non-matching-reply-ignored resolvd *engine-reply.non-matching-udp-datagram-becomes-timeout" },
    function(t)
        up(t)
        local name, good = fresh("window")
        local n = 0
        HOOK = function(q, d, ctx)
            if not dns.same_name(qname(q) or "", name) then return nil end
            n = n + 1
            if n == 1 then
                -- A wrong-ID copy first, then the genuine reply.
                local bad = { id = (d.id + 1) & 0xFFFF, qr = true, rd = d.rd, ra = true, questions = questions_of(q),
                              answers = { { name = qname(q), type = "A", ttl = 60, data = BOGUS } }, edns = d.edns }
                send_reply(ctx, dns.encode(bad))
                return d
            end
            d.delay = 1          -- the retry's answer waits a second, so the demotion can be seen
            return d
        end
        t:assert_eq(demoted(), "", "the server starts healthy")
        dns.forget(gw)
        local c0 = counters()
        local a = ask({ query = "resolve", name = name, type = A, no_cache = true })
        gw:serve({ timeout = 10, until_ = function() return #dns.queries(gw, is(name)) >= 1 end })
        gw:pump(100)
        local first_at = dns.queries(gw, is(name))[1].at
        local mid = counters()
        local mid_dem = demoted()
        local answered_yet = take(a)
        local elapsed = gw.vm:clock():get() - first_at
        local dm = delta(c0, mid)
        t:log(string.format("inside the window (%.2f s after the query): %s, demoted [%s], answer %s",
            elapsed, dtext(dm), mid_dem, tostring(answered_yet and answered_yet.outcome)))
        t:assert(elapsed < 1.9, "still inside the transaction's 2 s")
        t:assert_eq(dm.answered, 0, "neither datagram counted as answered")
        t:assert_eq(dm.failed, 0, "nothing counted as failed")
        t:assert_eq(mid_dem, "", "the server is not demoted for it")
        t:assert(answered_yet == nil, "the question is not answered by either datagram")
        t:assert_eq(#dns.queries(gw, is(name)), 1, "and not asked again yet")

        gw:serve({ timeout = 10, until_ = function() return #dns.queries(gw, is(name)) >= 2 end })
        local at_retry = counters()
        local retry_dem = demoted()
        local dr = delta(c0, at_retry)
        t:log(string.format("at the retry: %s, demoted [%s]", dtext(dr), retry_dem))
        local r = finish(a, 10)
        HOOK = nil
        local qs = dns.queries(gw, is(name))
        qlog(t, qs)
        local gap = qs[2].at - qs[1].at
        t:assert(gap >= 1.7 and gap <= 2.6, string.format("the retry came at the 2 s deadline (%.2f s)", gap))
        t:assert_eq(dr.failed, 1, "the deadline failed the transaction")
        t:assert_eq(dr.answered, 0, "the genuine first reply was never matched")
        t:assert_eq(retry_dem, SERVER, "the server is demoted")
        t:assert(r and r.outcome == "found" and texts(r) == good, "the retry's answer is used")
        t:assert_eq(demoted(), "", "and its NOERROR lifts the demotion")
    end)

test("a non-matching TCP reply also ends in a timeout",
    { spec = "resolvd *engine-reply.non-matching-tcp-reply-becomes-timeout" }, function(t)
        up(t)
        local name, good = fresh("tcpbad")
        local udp, tcp = 0, 0
        HOOK = function(q, d, ctx)
            if not dns.same_name(qname(q) or "", name) then return nil end
            if ctx.transport == "udp" then
                udp = udp + 1
                if udp == 1 then d.tc, d.answers = true, {}; return d end
                return d
            end
            tcp = tcp + 1
            d.id = (d.id + 1) & 0xFFFF
            d.answers = { { name = qname(q), type = "A", ttl = 60, data = BOGUS } }
            return d
        end
        dns.forget(gw)
        local c0 = counters()
        local r = resolve(name, A)
        HOOK = nil
        local d = delta(c0, counters())
        local qs = dns.queries(gw, is(name))
        t:log("tcpbad: " .. tostring(r and r.outcome) .. " " .. texts(r) .. "; " .. dtext(d))
        qlog(t, qs)
        t:assert_eq(#qs, 3, "UDP, TCP, UDP")
        t:assert_eq(qs[1].transport .. "," .. qs[2].transport .. "," .. qs[3].transport, "udp,tcp,udp", "in that order")
        local gap = qs[3].at - qs[2].at
        t:assert(gap >= 1.6 and gap <= 3.2, string.format("the next attempt at the TCP transaction's deadline (%.2f s)", gap))
        t:assert_eq(d.failed, 1, "one failure: the TCP transaction's timeout")
        t:assert(r and r.outcome == "found" and texts(r) == good, "the next attempt's genuine answer")
    end)

-- ---------------------------------------------------------------------------
-- PSPU §6.7
-- ---------------------------------------------------------------------------

-- PEI-1338: resolvd closes a UDP transaction's socket on the first datagram
-- read, matched or not, so a mismatched datagram ahead of the real reply
-- costs the transaction: the real reply is lost, the question waits out the
-- 2 s deadline, the server is demoted, and it is asked again.
test("a reply whose ID, question or case does not match is ignored, not a failure: the real reply right behind it is used",
    { spec = "PSPU *nri-resolution.mismatched-reply-ignored", tags = { "known-bug" } }, function(t)
        up(t)
        local kinds = {
            { "id", function(rep) rep.id = (rep.id + 1) & 0xFFFF end },
            { "question", function(rep) rep.questions[1].name = "other.example.test" end },
            { "case", function(rep)
                local n = rep.questions[1].name
                local i = n:find("%a")
                local c = n:sub(i, i)
                rep.questions[1].name = n:sub(1, i - 1) .. (c:lower() == c and c:upper() or c:lower()) .. n:sub(i + 1)
            end },
        }
        local results = {}
        for _, k in ipairs(kinds) do
            local name, good = fresh("ignored-" .. k[1])
            local n = 0
            HOOK = function(q, d, ctx)
                if not dns.same_name(qname(q) or "", name) then return nil end
                n = n + 1
                if n == 1 then
                    local bad = { id = d.id, qr = true, rd = d.rd, ra = true, questions = questions_of(q),
                                  answers = { { name = qname(q), type = "A", ttl = 60, data = BOGUS } }, edns = d.edns }
                    k[2](bad)
                    send_reply(ctx, dns.encode(bad))
                end
                return d
            end
            dns.forget(gw)
            local c0 = counters()
            local r = resolve(name, A)
            HOOK = nil
            local d = delta(c0, counters())
            local qs = dns.queries(gw, is(name))
            t:log(string.format("mismatched %s, then the real reply: %s %s; %d queries; %s", k[1],
                tostring(r and r.outcome), texts(r), #qs, dtext(d)))
            qlog(t, qs)
            t:assert(r and r.outcome == "found" and texts(r) == good, k[1] .. ": the real answer, never the mismatched one")
            results[#results + 1] = { kind = k[1], queries = #qs, failed = d.failed }
        end
        for _, x in ipairs(results) do
            t:assert_eq(x.queries, 1, "mismatched " .. x.kind .. ": the real reply behind it answers the first query")
            t:assert_eq(x.failed, 0, "mismatched " .. x.kind .. ": no failure counted")
        end
    end)
