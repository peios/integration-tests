-- resolvd TRM §6.1 — the stub listener receiving queries, UDP side: the
-- loopback-only source rule, the 4 096-byte read buffer, where replies
-- go, the checks a query passes or fails at the door (FORMERR, NOTIMP,
-- dropped) and the error replies' exact shape, what an accepted query
-- contributes (class, flags and EDNS ignored; escaped labels re-parsed),
-- and which stub queries are counted. With them, the PSPU §6.8 door
-- anchors that are about the same checks. TCP connections are
-- resolvd-stub-tcp.test.lua; replies to accepted queries are
-- resolvd-stub-render.test.lua.
--
-- Harness: the scripted gateway (helpers.gateway) leases 10.77.0.50 and
-- names itself as the DNS server; helpers.dns answers from a zone. The
-- test is the stub client: the agent opens UDP sockets to 127.0.0.53:53
-- in the guest, sends hand-built DNS messages (helpers.dns codec, raw
-- flag words where a test needs bits the codec does not name), and reads
-- the replies while the gateway pumps.
--
-- Absence is proved by order. resolvd reads every waiting datagram in one
-- pass and sends an error reply inline as it reads, before any accepted
-- query is answered; so a bad datagram followed on the same socket by a
-- `localhost A` probe (answered locally, at once) would have its reply,
-- if it had one, arrive before the probe's. The first datagram back
-- being the probe's is the proof that the bad one got nothing.
--
-- The non-loopback source is the machine's own leased address: a socket
-- bound to 10.77.0.50 sending to 127.0.0.53. A control datagram on the
-- same path to a test-owned socket on 127.0.0.53 proves the kernel (and
-- the packet filter) deliver such a datagram, so its absence of a reply
-- is resolvd's doing.
--
-- `queries` moves for NSS lookups too (timed's `N.time.peios.org` in the
-- background), so the counting test reads the counter tightly around one
-- burst and logs the gateway's view of the window.
--
-- Own VMs: the tests share one machine; every upstream name is unique,
-- so the cache never answers one test from another.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
dns.serve(gw, {
    zone = {
        ["chaos.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.81" } },
        ["flags.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.82" } },
        ["nonloop.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.83" } },
    },
    soa = { name = "example.test", data = { minimum = 30 } },
})
local sut = network.boot({ bridges = { lan }, gateway = gw })

local STUB = "127.0.0.53"
local SOCK = "/run/resolvd/resolv.sock"
local LEASED = "10.77.0.50"

-- ---- helpers -----------------------------------------------------------

local function hex(s)
    return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

--- resolvd's native status reply.
local function rstatus()
    local s, err = network.call(sut, { query = "status" }, { path = SOCK })
    assert(s and s.ok, "resolvd status: " .. tostring(err or (s and s.error)))
    return s
end

local is_ready = false
--- The lease is bound and resolvd has the gateway as a server.
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

--- A UDP socket connected to the stub door.
local function udp()
    return assert(ntfe.udp_connect(sut, STUB, 53))
end

--- The next datagram on `fd`, pumping the gateway meanwhile; nil and
--- "timeout" when none comes within `timeout` seconds.
local function recv_serving(fd, timeout)
    local got, err
    gw:serve({ timeout = timeout or 10, until_ = function()
        got, err = ntfe.recv(sut, fd, 20, 65536)
        return got ~= nil or err ~= "timeout"
    end })
    return got, err
end

--- recvfrom(2): the datagram, the source address and the source port.
local function recvfrom(fd, timeout_ms)
    if ntfe.poll(sut, fd, ntfe.POLLIN, timeout_ms or 2000) & ntfe.POLLIN == 0 then
        return nil, "timeout"
    end
    local r = sut:syscall(ntfe.NR.recvfrom, {
        args = { fd, 0, 65536, 0, 0, 0 },
        bufs = { string.rep("\0", 65536), string.rep("\0", 16), string.pack("<I4", 16) },
        ptrs = { 1, 4, 5 },
    })
    if r.ret < 0 then return nil, sys.errname(r.errno) end
    local sa = r.out_bufs[2]
    return r.out_bufs[1]:sub(1, r.ret), ntfe.ip4_text(sa:sub(5, 8)), string.unpack(">I2", sa, 3)
end

--- A `localhost A` query: answered by resolvd itself, at once.
local function probe(id)
    return dns.encode({ id = id, rd = true, questions = { { name = "localhost", type = "A" } } })
end

--- Send `bad` and then a probe on one socket; return the first datagram
--- back (decoded) and the raw bytes, and whether anything followed it.
local function bad_then_probe(bad, probe_id)
    local fd = udp()
    ntfe.send(sut, fd, bad)
    ntfe.send(sut, fd, probe(probe_id))
    local first = ntfe.recv(sut, fd, 3000, 65536)
    local extra = ntfe.recv(sut, fd, 500, 65536)
    sys.close(sut, fd)
    return first and dns.decode(first), first, extra
end

--- One UDP exchange: send `bytes`, return the decoded reply and raw.
local function exchange(bytes, timeout)
    local fd = udp()
    ntfe.send(sut, fd, bytes)
    local got = recv_serving(fd, timeout)
    sys.close(sut, fd)
    return got and dns.decode(got), got
end

--- The gateway's logged questions whose name is `name` (case-insensitive).
local function asked(name)
    return dns.queries(gw, function(e)
        return e.msg and e.msg.questions[1] and dns.same_name(e.msg.questions[1].name, name)
    end)
end

--- The labels of a query's question, raw, from its wire bytes.
local function wire_labels(raw)
    local out, pos = {}, 13
    while true do
        local len = raw:byte(pos)
        if not len or len == 0 then break end
        out[#out + 1] = raw:sub(pos + 1, pos + len)
        pos = pos + 1 + len
    end
    return out
end

--- The gateway's logged questions other than the image's NTP chatter.
local function foreign_questions()
    return dns.queries(gw, function(e)
        local n = e.msg and e.msg.questions[1] and e.msg.questions[1].name or ""
        return not n:lower():match("time%.peios%.org$")
    end)
end

--- The 12-byte header of a reply, as numbers.
local function header(raw)
    local id, flags, qd, an, ns, ar = string.unpack(">I2I2I2I2I2I2", raw)
    return { id = id, flags = flags, qd = qd, an = an, ns = ns, ar = ar }
end

-- ---- the source address ------------------------------------------------

test("a UDP query from a non-loopback source is dropped without a reply",
    { spec = "resolvd *stub-receive.udp-non-loopback-source-dropped PSPU *nri-stub.non-loopback-source-ignored" },
    function(t)
        ready(t)
        -- Control: the kernel delivers 10.77.0.50 -> 127.0.0.53 at all.
        local ctl = assert(ntfe.udp_bind(sut, STUB, 5399))
        local s = assert(ntfe.udp_bind(sut, LEASED, 0))
        ntfe.sendto(sut, s, "control", STUB, 5399)
        local data, from = recvfrom(ctl, 3000)
        sys.close(sut, ctl)
        t:assert_eq(data, "control", "a datagram from 10.77.0.50 to 127.0.0.53 is delivered (control)")
        t:assert_eq(from, LEASED, "and arrives with its non-loopback source")

        dns.forget(gw)
        local before = rstatus().counters.queries
        ntfe.sendto(sut, s, dns.encode(dns.query("nonloop.example.test", "A", { id = 0x5101 })), STUB, 53)
        ntfe.sendto(sut, s, probe(0x5102), STUB, 53)
        local got = recv_serving(s, 3)
        t:assert_eq(got, nil, "no reply reaches the non-loopback source (got "
            .. (got and hex(got) or "nothing") .. ")")
        t:assert_eq(#asked("nonloop.example.test"), 0, "and the question was never asked upstream")

        -- The same questions from a loopback source are answered.
        local m = exchange(dns.encode(dns.query("nonloop.example.test", "A", { id = 0x5103 })))
        t:assert(m and m.id == 0x5103 and m.rcode == 0 and m.answers[1]
            and m.answers[1].data == "10.77.0.83", "from loopback the same question is answered")
        t:log(string.format("queries %d -> %d (the loopback question is the one counted)",
            before, rstatus().counters.queries))
        sys.close(sut, s)
    end)

test("a UDP reply goes to the address and port the query came from",
    { spec = "resolvd *stub-receive.udp-reply-to-source" }, function(t)
        local a = assert(ntfe.udp_bind(sut, "127.0.0.77", 40053))
        local b = assert(ntfe.udp_bind(sut, "127.9.8.7", 40099))
        ntfe.sendto(sut, a, probe(0x5201), STUB, 53)
        ntfe.sendto(sut, b, probe(0x5202), STUB, 53)
        local da, fa, pa = recvfrom(a, 3000)
        local db, fb, pb = recvfrom(b, 3000)
        sys.close(sut, a); sys.close(sut, b)
        t:assert(da and db, "both sockets got a reply")
        t:assert_eq(dns.decode(da).id, 0x5201, "127.0.0.77:40053 got the reply to its own query")
        t:assert_eq(dns.decode(db).id, 0x5202, "127.9.8.7:40099 got the reply to its own query")
        t:assert_eq(fa .. ":" .. pa, "127.0.0.53:53", "sent from the stub address and port")
        t:assert_eq(fb .. ":" .. pb, "127.0.0.53:53", "both of them")
    end)

-- ---- the read buffer -----------------------------------------------------

--- A `localhost A` query padded with an unknown-type additional record
--- so the whole message is exactly `size` bytes.
local function padded_query(id, size)
    local function build(len)
        return dns.encode({ id = id, rd = true,
            questions = { { name = "localhost", type = "A" } },
            additional = { { name = ".", type = 65280, class = 1, ttl = 0, rdata = string.rep("x", len) } } })
    end
    local q = build(size - #build(0))
    assert(#q == size, "padded query is " .. #q .. " bytes")
    return q
end

test("a datagram is read into 4 096 bytes: a longer message is cut and answered FORMERR, padding beyond is ignored",
    { spec = "resolvd *stub-receive.udp-read-buffer-4096 resolvd *stub-receive.udp-oversized-query-formerr" },
    function(t)
        local m = exchange(padded_query(0x5301, 4096))
        t:assert(m, "a 4 096-byte query is answered")
        t:assert_eq(m.id, 0x5301, "its id")
        t:assert_eq(m.rcode, dns.RCODE.NOERROR, "NOERROR: it decoded whole")
        t:assert(m.answers[1] and m.answers[1].data == "127.0.0.1", "with localhost's address")

        local _, raw = exchange(padded_query(0x5302, 4097))
        t:assert(raw, "a 4 097-byte query gets a reply")
        local h = header(raw)
        t:log("4097-byte query -> " .. hex(raw))
        t:assert_eq(h.id, 0x5302, "the query's id")
        t:assert_eq(h.flags, 0x8001, "QR and FORMERR only: the message, cut at 4 096, no longer decodes")
        t:assert_eq(#raw, 12, "no sections")

        local base = probe(0x5303)
        local m2 = exchange(base .. string.rep("\0", 5000))
        t:assert(m2, "a short query padded past 4 096 bytes is answered")
        t:assert_eq(m2.id, 0x5303, "its id")
        t:assert_eq(m2.rcode, dns.RCODE.NOERROR, "as usual: the bytes after the message are ignored")
        t:assert(m2.answers[1] and m2.answers[1].data == "127.0.0.1", "with localhost's address")
    end)

-- ---- checking a query ----------------------------------------------------

test("an undecodable message of 12 bytes or more gets FORMERR: its id, QR, nothing else",
    { spec = "resolvd *stub-receive.undecodable-long-message-formerr" }, function(t)
        -- A header claiming a question that is not there, with every
        -- query bit set that a reply might be tempted to copy.
        local bare = string.pack(">I2I2I2I2I2I2", 0x4242, 0x2F70, 1, 0, 0, 0)
        local m, raw = bad_then_probe(bare, 0x5401)
        t:assert(raw, "a reply came")
        t:log("12-byte header-only query -> " .. hex(raw))
        t:assert_eq(raw, string.pack(">I2I2I2I2I2I2", 0x4242, 0x8001, 0, 0, 0, 0),
            "exactly: id 0x4242, flags QR|FORMERR, every count zero")

        -- A longer one, broken by a label with the reserved 0x40 prefix.
        local bad = string.pack(">I2I2I2I2I2I2", 0x4343, 0x0110, 1, 0, 0, 0) .. "\x41abc" .. string.rep("\0", 20)
        local _, raw2 = bad_then_probe(bad, 0x5402)
        t:assert(raw2, "a reply came")
        t:assert_eq(raw2, string.pack(">I2I2I2I2I2I2", 0x4343, 0x8001, 0, 0, 0, 0),
            "exactly: id 0x4343, flags QR|FORMERR, every count zero (RD and CD not copied)")
    end)

test("an undecodable message shorter than 12 bytes is dropped without a reply",
    { spec = "resolvd *stub-receive.undecodable-short-message-dropped" }, function(t)
        local m, raw, extra = bad_then_probe(string.pack(">I2I2I2", 0x4444, 0x0100, 1) .. "\0\0\0\0\0", 0x5501)
        t:assert(raw, "the probe was answered")
        t:assert_eq(m.id, 0x5501, "the first datagram back is the probe's answer: the 11 bytes got nothing")
        t:assert_eq(extra, nil, "and nothing follows it")
    end)

test("a message with QR set is dropped without a reply",
    { spec = "resolvd *stub-receive.response-dropped" }, function(t)
        local resp = dns.encode({ id = 0x4545, qr = true, rd = true, ra = true,
            questions = { { name = "localhost", type = "A" } },
            answers = { { name = "localhost", type = "A", data = "127.0.0.1" } } })
        local m, raw, extra = bad_then_probe(resp, 0x5601)
        t:assert(raw, "the probe was answered")
        t:assert_eq(m.id, 0x5601, "the first datagram back is the probe's answer: the response got nothing")
        t:assert_eq(extra, nil, "and nothing follows it")
    end)

test("a query with an opcode other than QUERY is answered NOTIMP",
    { spec = "resolvd *stub-receive.non-query-opcode-notimp PSPU *nri-stub.non-query-opcode-is-notimp" },
    function(t)
        for _, op in ipairs({ 1, 2, 4, 5, 15 }) do
            local q = dns.encode({ id = 0x5700 + op, opcode = op, rd = true,
                questions = { { name = "localhost", type = "A" } } })
            local m = bad_then_probe(q, 0x57F0 + op)
            t:assert(m, "opcode " .. op .. " got a reply")
            t:assert_eq(m.id, 0x5700 + op, "opcode " .. op .. ": the reply is to it")
            t:assert_eq(m.rcode, dns.RCODE.NOTIMP, "opcode " .. op .. ": NOTIMP")
            t:assert(m.qr, "opcode " .. op .. ": a response")
        end
    end)

test("a query with no question, or more than one, is answered FORMERR",
    { spec = "resolvd *stub-receive.question-count-formerr PSPU *nri-stub.bad-question-count-or-undecodable-is-formerr" },
    function(t)
        local none = dns.encode({ id = 0x5801, rd = true, questions = {} })
        local m0 = bad_then_probe(none, 0x58F1)
        t:assert(m0 and m0.id == 0x5801, "no question: a reply")
        t:assert_eq(m0.rcode, dns.RCODE.FORMERR, "no question: FORMERR")

        local two = dns.encode({ id = 0x5802, rd = true, questions = {
            { name = "localhost", type = "A" }, { name = "localhost", type = "AAAA" } } })
        local m2 = bad_then_probe(two, 0x58F2)
        t:assert(m2 and m2.id == 0x5802, "two questions: a reply")
        t:assert_eq(m2.rcode, dns.RCODE.FORMERR, "two questions: FORMERR")

        -- PSPU: undecodable with a header to echo is FORMERR too.
        local cut = dns.encode(dns.query("localhost", "A", { id = 0x5803 })):sub(1, 20)
        local m3 = bad_then_probe(cut, 0x58F3)
        t:assert(m3 and m3.id == 0x5803, "a cut message: a reply")
        t:assert_eq(m3.rcode, dns.RCODE.FORMERR, "a cut message: FORMERR")
    end)

test("NOTIMP and question-count FORMERR copy ID, opcode, RD and CD, set QR and RA, and nothing else",
    { spec = "resolvd *stub-receive.error-reply-header" }, function(t)
        -- opcode 5, AA, TC, RD, Z, AD, CD all set in the query.
        local q = dns.encode({ id = 0x5901, flags = 0x2F70,
            questions = { { name = "localhost", type = "A" } } })
        local _, raw = bad_then_probe(q, 0x59F1)
        t:assert(raw, "a reply")
        t:log("opcode 5, flags 0x2F70 -> " .. hex(raw:sub(1, 12)))
        t:assert_eq(string.format("0x%04X", header(raw).flags), "0xA994",
            "QR | opcode 5 | RD | RA | CD | NOTIMP: AA, TC, Z and AD are not copied")

        -- opcode 2, nothing else set: RD and CD stay clear.
        local q2 = dns.encode({ id = 0x5902, flags = 0x1000,
            questions = { { name = "localhost", type = "A" } } })
        local _, raw2 = bad_then_probe(q2, 0x59F2)
        t:assert_eq(string.format("0x%04X", header(raw2).flags), "0x9084",
            "QR | opcode 2 | RA | NOTIMP: RD and CD are copied, not set")

        -- FORMERR for two questions, with AA, TC, Z, AD and CD set.
        local q3 = dns.encode({ id = 0x5903, flags = 0x0670 | 0x0100,
            questions = { { name = "localhost", type = "A" }, { name = "localhost", type = "A" } } })
        local _, raw3 = bad_then_probe(q3, 0x59F3)
        t:assert_eq(header(raw3).id, 0x5903, "the query's id")
        t:assert_eq(string.format("0x%04X", header(raw3).flags), "0x8191",
            "QR | RD | RA | CD | FORMERR: AA, TC, Z and AD are not copied")
    end)

test("the error replies carry the query's question section, whatever it holds",
    { spec = "resolvd *stub-receive.error-reply-question" }, function(t)
        local qs = { { name = "Localhost", type = "A" }, { name = "WWW.example.TEST", type = "MX", class = 3 } }
        local q = dns.encode({ id = 0x5A01, rd = true, questions = qs })
        local _, raw = bad_then_probe(q, 0x5AF1)
        t:assert(raw, "a reply")
        local h = header(raw)
        t:assert_eq(h.qd, 2, "both questions are in the reply")
        t:assert_eq(raw:sub(13), q:sub(13), "byte for byte as asked: case, type and class kept")

        local q1 = dns.encode({ id = 0x5A02, opcode = 4,
            questions = { { name = "NoTiFy.example.test", type = "SOA", class = 255 } } })
        local _, raw1 = bad_then_probe(q1, 0x5AF2)
        t:assert(raw1, "a reply to the NOTIFY")
        t:assert_eq(header(raw1).qd, 1, "the one question is in the NOTIMP reply")
        t:assert_eq(raw1:sub(13), q1:sub(13), "byte for byte as asked")
    end)

test("the error replies carry an OPT of the query's own size, DO clear, no options, only when the query had one",
    { spec = "resolvd *stub-receive.error-reply-opt-size" }, function(t)
        local cookie = string.pack(">I2I2", 10, 8) .. "\1\2\3\4\5\6\7\8"
        local q = dns.encode({ id = 0x5B01, opcode = 2, rd = true,
            questions = { { name = "localhost", type = "A" } },
            edns = { udp_size = 3000, do_bit = true, options = cookie } })
        local m, raw = bad_then_probe(q, 0x5BF1)
        t:assert(m and m.id == 0x5B01, "a NOTIMP reply")
        t:log("NOTIMP with OPT -> " .. hex(raw))
        t:assert(m.edns, "it carries an OPT record")
        t:assert_eq(m.edns.udp_size, 3000, "advertising the query's size, not resolvd's 1 232")
        t:assert_eq(m.edns.do_bit, false, "DO clear")
        t:assert_eq(m.additional[1].rdata, "", "no options")
        t:assert_eq(#m.additional, 1, "and nothing else in additional")

        local q2 = dns.encode({ id = 0x5B02, rd = true, questions = {},
            edns = { udp_size = 700 } })
        local m2 = bad_then_probe(q2, 0x5BF2)
        t:assert(m2 and m2.id == 0x5B02 and m2.rcode == dns.RCODE.FORMERR, "a FORMERR reply")
        t:assert(m2.edns and m2.edns.udp_size == 700, "its OPT advertises 700, the query's size")

        local q3 = dns.encode({ id = 0x5B03, opcode = 2, rd = true,
            questions = { { name = "localhost", type = "A" } } })
        local _, raw3 = bad_then_probe(q3, 0x5BF3)
        t:assert_eq(header(raw3).ar, 0, "without an OPT in the query, the reply has none")
    end)

-- ---- what an accepted query contributes ----------------------------------

test("an accepted query's class is not looked at: any class is answered as IN",
    { spec = "resolvd *stub-receive.class-ignored" }, function(t)
        ready(t)
        dns.forget(gw)
        local q = dns.encode({ id = 0x5C01, rd = true,
            questions = { { name = "chaos.example.test", type = "A", class = dns.CLASS.CH } } })
        local m = exchange(q)
        t:assert(m, "a CH-class query is answered")
        t:assert_eq(m.rcode, dns.RCODE.NOERROR, "NOERROR")
        t:assert_eq(m.questions[1].class, dns.CLASS.CH, "the question is echoed as asked, class CH")
        t:assert(m.answers[1] and m.answers[1].data == "10.77.0.81" and m.answers[1].class == dns.CLASS.IN,
            "with the IN record of the same name")
        local up = asked("chaos.example.test")
        t:assert(#up >= 1, "the name went upstream")
        t:assert_eq(up[1].msg.questions[1].class, dns.CLASS.IN, "asked upstream as IN")
    end)

test("RD, CD, DO and EDNS options in an accepted query are not looked at",
    { spec = "resolvd *stub-receive.flags-and-edns-options-ignored" }, function(t)
        ready(t)
        dns.forget(gw)
        local cookie = string.pack(">I2I2", 10, 8) .. "abcdefgh"
        local q = dns.encode({ id = 0x5D01, rd = false, cd = true,
            questions = { { name = "flags.example.test", type = "A" } },
            edns = { udp_size = 4096, do_bit = true, options = cookie } })
        local m = exchange(q)
        t:assert(m, "answered")
        t:assert_eq(m.rcode, dns.RCODE.NOERROR, "NOERROR")
        t:assert(m.answers[1] and m.answers[1].data == "10.77.0.82",
            "with the record, fetched upstream although the query did not ask for recursion")
        local up = asked("flags.example.test")
        t:assert(#up >= 1, "the name went upstream")
        local u = up[1].msg
        t:log(string.format("upstream query: rd=%s cd=%s edns=%s do=%s options=%s", tostring(u.rd), tostring(u.cd),
            tostring(u.edns ~= nil), tostring(u.edns and u.edns.do_bit), u.edns and hex(u.additional[#u.additional].rdata) or "-"))
        t:assert_eq(u.rd, true, "resolvd asks with RD set, whatever the client's RD")
        t:assert_eq(u.cd, false, "the client's CD is not passed on")
        t:assert(not (u.edns and u.edns.do_bit), "nor its DO bit")
        for _, r in ipairs(u.additional) do
            if r.type == dns.TYPE.OPT then t:assert_eq(r.rdata, "", "nor its EDNS options") end
        end
    end)

test("a label holding a dot or an unprintable byte is asked as a different name",
    { spec = "resolvd *stub-receive.escaped-labels-asked-as-different-name" }, function(t)
        ready(t)
        dns.forget(gw)
        -- One wire label "foo.bar", under example.test.
        local m = exchange(dns.encode({ id = 0x5E01, rd = true,
            questions = { { name = { "foo.bar", "example", "test" }, type = "A" } } }))
        t:assert(m and m.id == 0x5E01, "answered")
        -- One label holding byte 0x01.
        local m2 = exchange(dns.encode({ id = 0x5E02, rd = true,
            questions = { { name = { "x\1y", "example", "test" }, type = "A" } } }))
        t:assert(m2 and m2.id == 0x5E02, "answered")

        local seen = {}
        for _, e in ipairs(foreign_questions()) do
            local labels = wire_labels(e.raw)
            for i, l in ipairs(labels) do labels[i] = l:lower() end
            seen[#seen + 1] = labels
            t:log("upstream asked: [" .. table.concat(labels, "|") .. "]")
        end
        local function was_asked(want)
            for _, l in ipairs(seen) do
                if table.concat(l, "\0") == table.concat(want, "\0") then return true end
            end
            return false
        end
        t:assert(was_asked({ "foo\\", "bar", "example", "test" }),
            "`foo.bar` became two labels, `foo\\` and `bar`: the escaped dot is a label boundary")
        t:assert(not was_asked({ "foo.bar", "example", "test" }), "the three-label name was never asked")
        t:assert(was_asked({ "x\\001y", "example", "test" }),
            "byte 0x01 became the four bytes `\\001` in the label")
    end)

test("when escaping takes a label past 63 bytes or the name past 255, the answer is notfound",
    { spec = "resolvd *stub-receive.escaped-label-overlong-is-notfound" }, function(t)
        ready(t)
        dns.forget(gw)
        -- 16 bytes of 0xC3: 64 once each is written \195.
        local m = exchange(dns.encode({ id = 0x5F01, rd = true,
            questions = { { name = { string.rep("\xC3", 16), "example", "test" }, type = "A" } } }))
        t:assert(m and m.id == 0x5F01, "answered")
        t:assert_eq(m.rcode, dns.RCODE.NXDOMAIN, "a 16-byte label of 0xC3 is NXDOMAIN (notfound)")
        -- 15 bytes of 0xC3 (60 escaped) stays within a label: asked upstream.
        local m15 = exchange(dns.encode({ id = 0x5F02, rd = true,
            questions = { { name = { string.rep("\xC3", 15), "example", "test" }, type = "A" } } }))
        t:assert(m15 and m15.id == 0x5F02, "the 15-byte label is answered too")
        -- Five 15-byte labels of 0x01: 81 bytes on the wire, 306 escaped.
        local long = {}
        for i = 1, 5 do long[i] = string.rep("\1", 15) end
        local m5 = exchange(dns.encode({ id = 0x5F03, rd = true,
            questions = { { name = long, type = "A" } } }))
        t:assert(m5 and m5.id == 0x5F03, "answered")
        t:assert_eq(m5.rcode, dns.RCODE.NXDOMAIN, "a name past 255 bytes once escaped is NXDOMAIN (notfound)")

        local up = foreign_questions()
        local n15, n16, nlong = 0, 0, 0
        for _, e in ipairs(up) do
            local l = wire_labels(e.raw)[1] or ""
            t:log("upstream asked, first label " .. #l .. " bytes: " .. l)
            if l == string.rep("\\195", 15) then n15 = n15 + 1 end
            if l == string.rep("\\195", 16) then n16 = n16 + 1 end
            if l:find("\\001", 1, true) then nlong = nlong + 1 end
        end
        t:assert(n15 >= 1, "the 15-byte label went upstream escaped (the control)")
        t:assert_eq(n16, 0, "the 16-byte label was never asked")
        t:assert_eq(nlong, 0, "the long name was never asked")
    end)

-- ---- counting --------------------------------------------------------------

test("every accepted stub query counts in `queries`; refused ones do not",
    { spec = "resolvd *stub-receive.refused-queries-not-counted" }, function(t)
        ready(t)
        local refused = {
            string.pack(">I2I2I2", 1, 0x0100, 1) .. "\0\0\0\0\0",                         -- short
            string.pack(">I2I2I2I2I2I2", 2, 0x0100, 1, 0, 0, 0),                           -- undecodable
            dns.encode({ id = 3, qr = true, questions = { { name = "localhost", type = "A" } } }), -- a response
            dns.encode({ id = 4, opcode = 2, questions = { { name = "localhost", type = "A" } } }), -- NOTIMP
            dns.encode({ id = 5, questions = {} }),                                         -- FORMERR
            dns.encode({ id = 6, questions = { { name = "localhost", type = "A" }, { name = "localhost", type = "A" } } }),
        }
        local nl = assert(ntfe.udp_bind(sut, LEASED, 0))
        local fd = udp()
        local attempt, delta = 0, nil
        repeat
            attempt = attempt + 1
            local before = rstatus().counters.queries
            ntfe.sendto(sut, nl, probe(0x6000 + attempt), STUB, 53)         -- non-loopback
            for _, b in ipairs(refused) do ntfe.send(sut, fd, b) end
            ntfe.send(sut, fd, probe(0x6100 + attempt))                     -- the one accepted
            local got
            repeat got = ntfe.recv(sut, fd, 2000, 65536)
            until not got or dns.decode(got).id == 0x6100 + attempt
            t:assert(got, "the accepted query was answered")
            delta = rstatus().counters.queries - before
            t:log(string.format("attempt %d: queries moved by %d", attempt, delta))
        until delta == 1 or attempt == 3
        sys.close(sut, fd); sys.close(sut, nl)
        t:assert_eq(delta, 1,
            "six refused messages, one non-loopback query and one accepted query move `queries` by one")

        -- And each accepted one counts, including one whose name does not parse.
        local d2
        attempt = 0
        repeat
            attempt = attempt + 1
            local before = rstatus().counters.queries
            local fd2 = udp()
            ntfe.send(sut, fd2, dns.encode({ id = 0x6201, rd = true,
                questions = { { name = { string.rep("\xC3", 16) }, type = "A" } } }))
            ntfe.send(sut, fd2, probe(0x6202))
            ntfe.send(sut, fd2, probe(0x6203))
            local n = 0
            while n < 3 and ntfe.recv(sut, fd2, 2000, 65536) do n = n + 1 end
            sys.close(sut, fd2)
            t:assert_eq(n, 3, "three accepted queries answered")
            d2 = rstatus().counters.queries - before
            t:log(string.format("attempt %d: queries moved by %d", attempt, d2))
        until d2 == 3 or attempt == 3
        t:assert_eq(d2, 3, "three accepted queries, one of a name that does not parse, count three")
    end)
