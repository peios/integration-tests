-- resolvd TRM §6.2 — how the stub listener renders an engine answer as a
-- DNS reply: the header and question, each outcome, the CNAME for an
-- expanded name, EDNS, the UDP size limit and truncation, the reply that
-- cannot be encoded, and TCP carrying the whole answer. With them, the
-- PSPU §6.8 rendering requirements, which resolvd meets except one: an
-- empty answer at an expanded name has no CNAME (PEI-1348).
--
-- Harness: the scripted gateway (helpers.gateway) leases 10.77.0.50 and
-- is the DNS server; helpers.dns answers from a zone, and its `on` hook
-- sets upstream header bits, answers SERVFAIL, and hand-builds one
-- compressed TCP reply. The test is the stub client: the agent sends
-- hand-built queries to 127.0.0.53:53 over UDP and TCP and reads the
-- replies while the gateway pumps.
--
-- Single-label expansion uses `ExtraSearchDomains` = `example.test`,
-- written once by the first test that needs it and left in place.
--
-- Sizes. resolvd's encoder never compresses names, so a reply's size is
-- computable: 12 header + 22 for a `<x>.example.test` question + 32 per
-- A record at a 16-character owner (+ 11 for OPT). `ten.` (10 records)
-- is 365 bytes with OPT; `mid.` (20) is 674 without OPT and 685 with;
-- `big.` (100) is 3 245 — over the 1 232 resolvd asks upstream with, so
-- resolvd fetches it over TCP. The unencodable reply is 400 A records at
-- a 202-byte owner: 6.6 KB upstream with `C0 0C` pointers, 86 KB once
-- resolvd writes every owner out.
--
-- Own VMs: the tests share one machine; every name is unique to a test.
-- The SERVFAIL test demotes the gateway for 30 s, so it runs last.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")

peinit.claim(2)

local function a_records(owner, n, net)
    local out = {}
    for i = 1, n do
        out[i] = { type = "A", ttl = 60, data = string.format("10.%d.%d.%d", net, i // 256, i % 256) }
    end
    return out
end

local HUGE = string.rep("a", 60) .. "." .. string.rep("b", 60) .. "." .. string.rep("c", 60) .. ".huge.example.test"
local HUGE_N = 400

--- The compressed reply to `q` for HUGE: HUGE_N A records, each owner a
--- pointer to the question's name.
local function huge_reply(q)
    local qn = q.questions[1]
    local out = { string.pack(">I2I2I2I2I2I2", q.id, 0x8000 | (q.rd and 0x0100 or 0) | 0x0080, 1, HUGE_N, 0, 0),
        dns.name(qn.name), string.pack(">I2I2", qn.type, 1) }
    for i = 1, HUGE_N do
        out[#out + 1] = "\xC0\x0C" .. string.pack(">I2I2I4I2", 1, 1, 60, 4) .. string.char(10, 79, i // 256, i % 256)
    end
    return table.concat(out)
end

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
dns.serve(gw, {
    zone = {
        ["www.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.80" } },
        ["hdr.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.84" } },
        ["bits.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.85" } },
        ["edns.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.86" } },
        ["order.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.83" },
                                   { type = "A", ttl = 60, data = "10.77.0.81" },
                                   { type = "A", ttl = 60, data = "10.77.0.82" } },
        ["printer.example.test"] = { { type = "A", ttl = 50, data = "10.77.0.90" },
                                     { type = "A", ttl = 40, data = "10.77.0.91" } },
        ["ten.example.test"] = a_records("ten.example.test", 10, 70),
        ["mid.example.test"] = a_records("mid.example.test", 20, 71),
        ["big.example.test"] = a_records("big.example.test", 100, 72),
        ["fit.example.test"] = a_records("fit.example.test", 400, 73),
    },
    soa = { name = "example.test", data = { minimum = 30 } },
    on = function(q, default, ctx)
        local n = (q.questions[1] and q.questions[1].name or ""):lower()
        if n == "bits.example.test" then
            default.aa, default.ad, default.cd, default.ra = true, true, true, false
            return default
        elseif n == "fail.example.test" then
            default.rcode = dns.RCODE.SERVFAIL
            default.answers, default.authority = {}, {}
            return default
        elseif n == HUGE then
            if ctx.transport == "udp" then
                return { id = q.id, qr = true, rd = q.rd, ra = true, tc = true, questions = q.questions,
                         edns = q.edns and { udp_size = 1232 } or nil }
            end
            return huge_reply(q)
        end
    end,
})
local sut = network.boot({ bridges = { lan }, gateway = gw })

local STUB = "127.0.0.53"
local SOCK = "/run/resolvd/resolv.sock"

-- ---- helpers -----------------------------------------------------------

local function hex(s)
    return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local function rstatus()
    local s, err = network.call(sut, { query = "status" }, { path = SOCK })
    assert(s and s.ok, "resolvd status: " .. tostring(err or (s and s.error)))
    return s
end

local is_ready = false
local function ready(t)
    if is_ready then return end
    t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }),
        "netd bound a lease")
    t:assert(gw:serve({ timeout = 30, until_ = function()
        for _, sc in ipairs(rstatus().scopes or {}) do
            for _, s in ipairs(sc.servers or {}) do
                if s == "10.77.0.1" then return true end
            end
        end
        return false
    end }), "resolvd has 10.77.0.1 as a scope's server")
    is_ready = true
end

--- One UDP exchange while the gateway pumps: the decoded reply and the
--- raw bytes, or nil when nothing came within `timeout` seconds.
local function udp_exchange(bytes, timeout)
    local fd = assert(ntfe.udp_connect(sut, STUB, 53))
    ntfe.send(sut, fd, bytes)
    local got
    gw:serve({ timeout = timeout or 10, until_ = function()
        got = ntfe.recv(sut, fd, 20, 65536)
        return got ~= nil
    end })
    sys.close(sut, fd)
    return got and dns.decode(got), got
end

--- One TCP exchange while the gateway pumps. Returns the decoded reply
--- and the raw message; or nil, "closed" | "timeout", and whatever bytes
--- arrived.
local function tcp_exchange(bytes, timeout)
    local fd = assert(ntfe.tcp_connect(sut, STUB, 53, 2000))
    ntfe.send(sut, fd, string.pack(">I2", #bytes) .. bytes)
    local buf, closed = "", false
    local function whole() return #buf >= 2 and #buf >= 2 + string.unpack(">I2", buf) end
    gw:serve({ timeout = timeout or 15, until_ = function()
        local c, err = ntfe.recv(sut, fd, 20, 65536)
        if c and #c > 0 then buf = buf .. c
        elseif c or err ~= "timeout" then closed = true end
        return whole() or closed
    end })
    sys.close(sut, fd)
    if whole() then
        local raw = buf:sub(3, 2 + string.unpack(">I2", buf))
        return dns.decode(raw), raw
    end
    return nil, closed and "closed" or "timeout", buf
end

local function query(name, qtype, o)
    o = o or {}
    return dns.encode({ id = o.id or math.random(1, 0xFFFF), rd = o.rd ~= false, cd = o.cd,
        questions = { { name = name, type = qtype or "A" } }, edns = o.edns })
end

local function header(raw)
    local id, flags, qd, an, ns, ar = string.unpack(">I2I2I2I2I2I2", raw)
    return { id = id, flags = flags, qd = qd, an = an, ns = ns, ar = ar }
end

--- The question section's bytes of a message with one question.
local function question_bytes(raw)
    local _, after = dns.read_name(raw, 13)
    return raw:sub(13, after + 3)
end

local function asked(name)
    return dns.queries(gw, function(e)
        return e.msg and e.msg.questions[1] and dns.same_name(e.msg.questions[1].name, name)
    end)
end

local function datas(m)
    local out = {}
    for _, r in ipairs(m.answers) do out[#out + 1] = tostring(r.data) end
    return table.concat(out, ",")
end

local search_set = false
--- ExtraSearchDomains = example.test, and resolvd has taken it.
local function search_domain(t)
    if search_set then return end
    ready(t)
    network.write(sut, "Dns", { ExtraSearchDomains = "multi:example.test" })
    local m
    t:assert(gw:serve({ timeout = 20, until_ = function()
        m = udp_exchange(query("www", "A"), 3)
        return m and m.rcode == dns.RCODE.NOERROR
    end }), "resolvd expands single labels with example.test")
    search_set = true
end

-- ---- the header and question ---------------------------------------------

test("the reply copies the query's ID, opcode, RD, CD and question section",
    { spec = "resolvd *stub-render.copied-header-fields" }, function(t)
        ready(t)
        local q = query("HdR.ExAmPlE.tEsT", "A", { id = 0xBEEF, rd = false, cd = true })
        local m, raw = udp_exchange(q)
        t:assert(m, "answered")
        t:assert_eq(m.id, 0xBEEF, "the query's ID")
        t:assert_eq(m.opcode, 0, "opcode QUERY")
        t:assert_eq(m.rd, false, "RD clear, as in the query")
        t:assert_eq(m.cd, true, "CD set, as in the query")
        t:assert_eq(question_bytes(raw), question_bytes(q), "the question byte for byte, its case kept")

        local q2 = query("hDr.eXaMpLe.TeSt", "A", { id = 0x0102, rd = true, cd = false })
        local m2, raw2 = udp_exchange(q2)
        t:assert(m2, "answered again (from the cache)")
        t:assert_eq(m2.id, 0x0102, "the second query's ID")
        t:assert_eq(m2.rd, true, "RD set, as in the second query")
        t:assert_eq(m2.cd, false, "CD clear, as in the second query")
        t:assert_eq(question_bytes(raw2), question_bytes(q2), "its own question, in its own case")
    end)

test("QR and RA are set, AA, AD and TC clear, and no bit of the upstream reply comes through",
    { spec = "resolvd *stub-render.qr-ra-set-aa-ad-clear resolvd *stub-render.no-upstream-bits PSPU *nri-stub.ra-set PSPU *nri-stub.aa-clear" },
    function(t)
        ready(t)
        dns.forget(gw)
        local m, raw = udp_exchange(query("bits.example.test", "A", { id = 0x0201 }))
        t:assert(m, "answered")
        local up = asked("bits.example.test")
        t:assert(#up >= 1, "the name went upstream")
        t:log("stub reply flags " .. string.format("0x%04X", header(raw).flags))
        t:assert_eq(m.rcode, dns.RCODE.NOERROR, "NOERROR")
        t:assert(m.answers[1] and m.answers[1].data == "10.77.0.85", "with the record")
        t:assert_eq(string.format("0x%04X", header(raw).flags), "0x8180",
            "QR | RD | RA, nothing else: the upstream AA, AD and CD are not carried, and its clear RA is not either")
        t:assert(m.qr and m.ra, "QR and RA set")
        t:assert(not m.aa and not m.ad and not m.tc and not m.cd, "AA, AD, TC and CD clear")
    end)

-- ---- by outcome ------------------------------------------------------------

test("a found answer is NOERROR with the engine's records in the engine's order",
    { spec = "resolvd *stub-render.found-records-in-engine-order PSPU *nri-stub.found-is-noerror" },
    function(t)
        ready(t)
        local m = udp_exchange(query("order.example.test", "A", { id = 0x0301 }))
        t:assert(m, "answered")
        t:assert_eq(m.rcode, dns.RCODE.NOERROR, "NOERROR")
        t:assert_eq(datas(m), "10.77.0.83,10.77.0.81,10.77.0.82",
            "the records in the answer section, in the order the server sent them (not sorted)")
        local m2 = udp_exchange(query("order.example.test", "A", { id = 0x0302 }))
        t:assert_eq(datas(m2), "10.77.0.83,10.77.0.81,10.77.0.82", "the same order from the cache")
    end)

test("an answer found at an expanded name begins with a CNAME from the name asked, in its case, at the least TTL",
    { spec = "resolvd *stub-render.expansion-cname" }, function(t)
        search_domain(t)
        local m = udp_exchange(query("PrInTeR", "A", { id = 0x0401 }))
        t:assert(m, "answered")
        t:assert_eq(m.rcode, dns.RCODE.NOERROR, "NOERROR")
        local c = m.answers[1]
        t:assert(c and c.type == dns.TYPE.CNAME, "the answer section begins with a CNAME")
        t:log(string.format("CNAME %s -> %s ttl %d; then %d records", c.name, tostring(c.data), c.ttl, #m.answers - 1))
        t:assert_eq(c.name, "PrInTeR", "from the question's name, in the query's case")
        t:assert(dns.same_name(c.data, "printer.example.test"), "to the expanded name")
        t:assert_eq(#m.answers, 3, "followed by the two records")
        local least = math.huge
        for i = 2, #m.answers do
            t:assert(dns.same_name(m.answers[i].name, "printer.example.test") and m.answers[i].type == dns.TYPE.A,
                "record " .. i .. " is an A at the expanded name")
            least = math.min(least, m.answers[i].ttl)
        end
        t:assert_eq(c.ttl, least, "the CNAME's TTL is the least of the records'")
        t:assert_eq(c.ttl, 40, "which is the 40 s record's")

        -- A name answered at itself, in another case, gets no CNAME.
        local m2 = udp_exchange(query("WWW.Example.TEST", "A", { id = 0x0402 }))
        t:assert(m2 and m2.rcode == 0, "a multi-label name in odd case is answered")
        t:assert_eq(#m2.answers, 1, "with its one record and no CNAME")
        t:assert_eq(m2.answers[1].type, dns.TYPE.A, "an A record")
    end)

test("a found with no records at an expanded name is an empty NOERROR, with no CNAME",
    { spec = "resolvd *stub-render.expanded-nodata-has-no-cname" }, function(t)
        search_domain(t)
        local m, raw = udp_exchange(query("PrInTeR", "AAAA", { id = 0x0501 }))
        t:assert(m, "answered")
        t:log("printer AAAA -> " .. hex(raw))
        t:assert_eq(m.rcode, dns.RCODE.NOERROR, "NOERROR")
        t:assert_eq(header(raw).an, 0, "an empty answer section: no CNAME") -- PEI-1348 (the spec wants one)
        t:assert_eq(header(raw).ns, 0, "and an empty authority section")
    end)

test("an answer at an expanded name begins with a CNAME from the question name, records or not",
    { spec = "PSPU *nri-stub.expanded-answer-begins-with-cname", tags = { "known-bug" } }, function(t)
        search_domain(t)
        local m = udp_exchange(query("PrInTeR", "A", { id = 0x0601 }))
        t:assert(m and m.answers[1] and m.answers[1].type == dns.TYPE.CNAME
            and m.answers[1].name == "PrInTeR" and dns.same_name(m.answers[1].data, "printer.example.test"),
            "found with records at printer.example.test: the answer begins with the CNAME")
        local m2 = udp_exchange(query("PrInTeR", "AAAA", { id = 0x0602 }))
        t:assert(m2 and m2.rcode == dns.RCODE.NOERROR, "printer AAAA is found (NODATA) at printer.example.test")
        -- PEI-1348: resolvd sends an empty NOERROR with no CNAME when the expanded name has no records.
        t:assert(m2.answers[1] and m2.answers[1].type == dns.TYPE.CNAME
            and m2.answers[1].name == "PrInTeR" and dns.same_name(m2.answers[1].data, "printer.example.test"),
            "found without records at printer.example.test: the answer begins with the CNAME")
    end)

test("notfound is NXDOMAIN with empty answer and authority: no SOA",
    { spec = "resolvd *stub-render.nxdomain-without-soa PSPU *nri-stub.notfound-is-nxdomain" }, function(t)
        ready(t)
        dns.forget(gw)
        local m, raw = udp_exchange(query("gone.example.test", "A", { id = 0x0701 }))
        t:assert(m, "answered")
        local up = asked("gone.example.test")
        t:assert(#up >= 1, "the name went upstream")
        t:log("stub reply: " .. hex(raw))
        t:assert_eq(m.rcode, dns.RCODE.NXDOMAIN, "NXDOMAIN")
        local h = header(raw)
        t:assert_eq(h.an, 0, "an empty answer section")
        t:assert_eq(h.ns, 0, "an empty authority section: the upstream SOA is not passed on")
        t:assert_eq(h.ar, 0, "and nothing in additional")
    end)

-- ---- EDNS ------------------------------------------------------------------

test("a query with OPT gets an OPT of 1 232 bytes, DO clear, no options; one without gets none",
    { spec = "resolvd *stub-render.opt-echoed-with-1232" }, function(t)
        ready(t)
        local cookie = string.pack(">I2I2", 10, 8) .. "12345678"
        local m = udp_exchange(query("edns.example.test", "A",
            { id = 0x0801, edns = { udp_size = 4096, do_bit = true, options = cookie } }))
        t:assert(m and m.rcode == 0 and m.answers[1], "answered with the record")
        t:assert(m.edns, "the reply carries OPT")
        t:assert_eq(m.edns.udp_size, 1232, "advertising 1 232 bytes, not the query's 4 096")
        t:assert_eq(m.edns.do_bit, false, "DO clear")
        local opt
        for _, r in ipairs(m.additional) do if r.type == dns.TYPE.OPT then opt = r end end
        t:assert_eq(opt.rdata, "", "no options: the query's cookie is not echoed")
        t:assert_eq(#m.additional, 1, "OPT alone in additional")

        local m2, raw2 = udp_exchange(query("edns.example.test", "A", { id = 0x0802 }))
        t:assert(m2 and m2.answers[1], "answered without OPT")
        t:assert_eq(header(raw2).ar, 0, "no OPT in the reply")
    end)

-- ---- size and truncation ---------------------------------------------------

test("the UDP limit is the query's OPT size, or 512 when that is smaller or there is none",
    { spec = "resolvd *stub-render.udp-size-limit" }, function(t)
        ready(t)
        local m1, r1 = udp_exchange(query("mid.example.test", "A", { id = 0x0901, edns = { udp_size = 700 } }))
        t:assert(m1, "answered")
        t:log("mid, OPT 700: " .. #r1 .. " bytes, tc=" .. tostring(m1.tc))
        t:assert(#r1 > 512 and #r1 <= 700, "the whole reply is over 512 and within 700 (" .. #r1 .. ")")
        t:assert(not m1.tc and #m1.answers == 20, "OPT 700: sent whole, 20 records")

        local m2, r2 = udp_exchange(query("mid.example.test", "A", { id = 0x0902, edns = { udp_size = 600 } }))
        t:assert(m2, "answered")
        t:assert(m2.tc and #m2.answers == 0, "OPT 600: truncated (" .. #r2 .. " bytes)")

        local m3, r3 = udp_exchange(query("mid.example.test", "A", { id = 0x0903 }))
        t:assert(m3, "answered")
        t:assert(m3.tc and #m3.answers == 0, "no OPT: truncated at 512 (" .. #r3 .. " bytes)")

        local m4, r4 = udp_exchange(query("ten.example.test", "A", { id = 0x0904, edns = { udp_size = 100 } }))
        t:assert(m4, "answered")
        t:log("ten, OPT 100: " .. #r4 .. " bytes, tc=" .. tostring(m4.tc))
        t:assert(#r4 > 100 and #r4 <= 512, "the reply is over the 100 advertised and within 512 (" .. #r4 .. ")")
        t:assert(not m4.tc and #m4.answers == 10, "OPT 100: the limit is 512, so it is sent whole")
    end)

test("a truncated UDP reply keeps the header with TC set, the question and OPT, and carries no records",
    { spec = "resolvd *stub-render.truncated-reply-header-and-question resolvd *stub-render.truncated-reply-keeps-opt resolvd *stub-render.truncated-reply-has-no-records PSPU *nri-stub.oversized-udp-reply-truncated" },
    function(t)
        ready(t)
        local q = query("BiG.example.TEST", "A", { id = 0x0A01, rd = true, cd = true, edns = { udp_size = 1232 } })
        local m, raw = udp_exchange(q, 20)
        t:assert(m, "answered")
        t:log("big over UDP, OPT 1232 -> " .. hex(raw))
        local h = header(raw)
        t:assert_eq(h.id, 0x0A01, "the query's id")
        t:assert_eq(string.format("0x%04X", h.flags), "0x8390", "QR | TC | RD | RA | CD, NOERROR: the same header with TC set")
        t:assert_eq(h.qd, 1, "one question")
        t:assert_eq(question_bytes(raw), question_bytes(q), "the question as asked")
        t:assert_eq(h.an, 0, "no answer records")
        t:assert_eq(h.ns, 0, "no authority records")
        t:assert_eq(h.ar, 1, "one additional record")
        t:assert(m.edns and m.edns.udp_size == 1232 and not m.edns.do_bit, "the OPT, 1 232 and DO clear")

        local q2 = query("big.example.test", "A", { id = 0x0A02 })
        local m2, raw2 = udp_exchange(q2)
        t:assert(m2, "answered without OPT")
        local h2 = header(raw2)
        t:assert(m2.tc, "truncated")
        t:assert_eq(h2.an + h2.ns + h2.ar, 0, "no records at all, and no OPT since the query had none")
        t:assert_eq(#raw2, 12 + #question_bytes(q2), "header and question only")
    end)

test("over TCP the whole reply is sent",
    { spec = "resolvd *stub-render.tcp-sends-whole-reply PSPU *nri-stub.tcp-carries-whole-answer" }, function(t)
        ready(t)
        local m, raw = tcp_exchange(query("big.example.test", "A", { id = 0x0B01, edns = { udp_size = 1232 } }))
        t:assert(m, "answered over TCP (" .. tostring(raw) .. ")")
        t:assert(not m.tc, "not truncated")
        t:assert_eq(#m.answers, 100, "all 100 records")
        t:log("big over TCP: " .. #raw .. " bytes")
        t:assert(#raw > 1232, "a reply larger than any UDP limit")

        local m2, raw2 = tcp_exchange(query("fit.example.test", "A", { id = 0x0B02 }), 30)
        t:assert(m2, "fit (400 records) answered over TCP")
        t:assert_eq(#m2.answers, 400, "all 400 records")
        t:log("fit over TCP: " .. #raw2 .. " bytes")
    end)

test("a reply that cannot be encoded is not sent at all",
    { spec = "resolvd *stub-render.unencodable-reply-not-sent" }, function(t)
        ready(t)
        dns.forget(gw)
        local before = rstatus().counters
        local fd = assert(ntfe.udp_connect(sut, STUB, 53))
        ntfe.send(sut, fd, query(HUGE, "A", { id = 0x0C01, edns = { udp_size = 1232 } }))
        local tcp_seen = gw:serve({ timeout = 20, until_ = function()
            for _, e in ipairs(asked(HUGE)) do if e.transport == "tcp" then return true end end
            return false
        end })
        t:assert(tcp_seen, "resolvd took the truncated UDP answer and asked again over TCP")
        -- Give resolvd time to take the TCP reply and render it.
        local got
        gw:serve({ timeout = 3, until_ = function()
            got = ntfe.recv(sut, fd, 20, 65536)
            return got ~= nil
        end })
        local after = rstatus().counters
        t:log(string.format("upstream_answered %d -> %d, upstream_failed %d -> %d, cache_entries %d",
            before.upstream_answered, after.upstream_answered, before.upstream_failed, after.upstream_failed,
            rstatus().cache_entries))
        t:assert_eq(after.upstream_answered - before.upstream_answered, 2,
            "both the truncated UDP reply and the 400-record TCP reply were taken")
        t:assert_eq(after.upstream_failed, before.upstream_failed, "neither failed")
        t:assert_eq(got, nil, "no UDP reply at all, not even a truncated one (got "
            .. (got and #got .. " bytes" or "nothing") .. ")")

        -- Asked again, the answer comes from the cache at once; a probe
        -- sent after it on the same socket is answered first.
        ntfe.send(sut, fd, query(HUGE, "A", { id = 0x0C02 }))
        ntfe.send(sut, fd, query("localhost", "A", { id = 0x0C03 }))
        local first = ntfe.recv(sut, fd, 3000, 65536)
        local extra = ntfe.recv(sut, fd, 500, 65536)
        sys.close(sut, fd)
        t:assert(first and dns.decode(first).id == 0x0C03, "the first datagram back is the probe's")
        t:assert_eq(extra, nil, "and nothing follows it")

        local m, why, bytes = tcp_exchange(query(HUGE, "A", { id = 0x0C04 }))
        t:assert_eq(m, nil, "over TCP no reply either")
        t:assert_eq(why, "closed", "the connection is closed")
        t:assert_eq(bytes, "", "without a byte written")
        local n = network.call(sut, { query = "resolve", name = HUGE, type = 1, no_cache = false },
            { path = SOCK, timeout_ms = 5000 })
        t:log("native resolve of the same name: outcome " .. tostring(n and n.outcome)
            .. ", " .. tostring(n and n.records and #n.records) .. " records")
    end)

test("unavailable is SERVFAIL with empty sections",
    { spec = "resolvd *stub-render.servfail-empty PSPU *nri-stub.unavailable-is-servfail" }, function(t)
        ready(t)
        dns.forget(gw)
        local m, raw = udp_exchange(query("fail.example.test", "A", { id = 0x0D01 }), 20)
        t:assert(m, "answered")
        local up = asked("fail.example.test")
        t:log(#up .. " upstream attempts, each answered SERVFAIL; stub reply " .. hex(raw))
        t:assert(#up >= 3, "every attempt was asked and failed")
        t:assert_eq(m.rcode, dns.RCODE.SERVFAIL, "SERVFAIL")
        local h = header(raw)
        t:assert_eq(h.an + h.ns + h.ar, 0, "every section empty")
    end)
