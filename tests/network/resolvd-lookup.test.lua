-- resolvd §4.9 and §5.3 (`lookup`), PSPU §6.5 (`lookup`): how a lookup
-- becomes one task per family, how the tasks' results are combined —
-- outcome, CNAME chasing, the canonical name, address order, source — and
-- the reply's shape.
--
-- Harness: the scripted gateway (helpers.gateway) with its DNS server
-- (helpers.dns), and a whole Peios (helpers.network). The gateway's DHCP
-- lease offers it as the one DNS server and `example.test` as the domain
-- (option 15), so a single label is expanded. Each test asks under names
-- of its own, so no answer is a cache hit by accident, and crafted answers
-- come from per-name hooks (`H`), built from the server's default reply so
-- the id and the 0x20-cased question always match.
--
-- Requests go straight to the native socket as SYSTEM: the request is
-- sent, the gateway is pumped (its server answers only then), and the
-- reply is read when it is whole (`ask`), so a test also knows the
-- gateway's clock at the moment the reply arrived.
--
-- Non-obvious:
--   * no zone-wide SOA: a negative answer without one is not cached, so
--     the image's background lookups of `N.time.peios.org` always reach
--     the gateway, and a window with none of them is a quiet window;
--   * a reply over 512 bytes is truncated and asked again over TCP, where
--     the hook runs again — the long CNAME chains go that way, so their
--     hooks are pure functions of the question;
--   * replies held back with `delay` stay well under resolvd's 2 s
--     per-server timeout, and `unavailable` is made with SERVFAIL (each
--     attempt fails at once) rather than silence;
--   * helpers.msgpack decodes bin as a string and drops nil-valued keys, so
--     the shape test reads the reply with a local typed walker (as
--     control-req.test.lua does).

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local unixsock = require("helpers.unixsock")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")
local msgpack = require("helpers.msgpack")

peinit.claim(2)

local SOCK = "/run/resolvd/resolv.sock"
local A, AAAA, CNAME = dns.TYPE.A, dns.TYPE.AAAA, dns.TYPE.CNAME

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600, options = { { 15, "example.test" } } })

local function rr(name, t, data, ttl) return { name = name, type = t, data = data, ttl = ttl or 60 } end

-- Per-name hooks, keyed by the lower-case question name.
local H = {}
dns.serve(gw, {
    zone = {
        ["fam-any.example.test"] = { rr(nil, "A", "10.77.0.31"), rr(nil, "AAAA", "fd77::31") },
        ["fam-v4.example.test"] = { rr(nil, "A", "10.77.0.32"), rr(nil, "AAAA", "fd77::32") },
        ["fam-v6.example.test"] = { rr(nil, "A", "10.77.0.33"), rr(nil, "AAAA", "fd77::33") },
        ["fam-absent.example.test"] = { rr(nil, "A", "10.77.0.34"), rr(nil, "AAAA", "fd77::34") },
        ["fam-upper.example.test"] = { rr(nil, "A", "10.77.0.35"), rr(nil, "AAAA", "fd77::35") },
        ["fam-bogus.example.test"] = { rr(nil, "A", "10.77.0.36"), rr(nil, "AAAA", "fd77::36") },
        ["out-nodata.example.test"] = { rr(nil, "A", "10.77.0.41") },
        ["out-servfail.example.test"] = { rr(nil, "A", "10.77.0.42") },
        ["out-empty.example.test"] = { rr(nil, "TXT", "no addresses here") },
        ["src-cachefirst.example.test"] = { rr(nil, "A", "10.77.0.73"), rr(nil, "AAAA", "fd77::73") },
        ["src-cachelast.example.test"] = { rr(nil, "A", "10.77.0.74") },
        ["printer.example.test"] = { rr(nil, "A", "10.77.0.81") },
        ["shape.example.test"] = { rr(nil, "A", "10.77.0.91", 77), rr(nil, "AAAA", "fd77::91", 78) },
    },
    on = function(q, default, ctx)
        local qn = q.questions[1]
        local h = qn and H[qn.name:lower()]
        if h then return h(q, default, ctx) end
    end,
})

local sut = network.boot({ bridges = { lan }, gateway = gw })

-- ---------------------------------------------------------------------------
-- Local helpers
-- ---------------------------------------------------------------------------

local function clock() return gw.vm:clock():get() end

--- A reply built from the server's default: same id, flags and question,
--- with these answers (owner nil = the question as asked), rcode and delay.
local function reply(q, default, answers, o)
    o = o or {}
    local r = {}
    for k, v in pairs(default) do r[k] = v end
    local qname = q.questions[1].name
    r.answers = {}
    for i, a in ipairs(answers or {}) do
        r.answers[i] = { name = a.name or qname, type = a.type, data = a.data, rdata = a.rdata, ttl = a.ttl or 60 }
    end
    r.authority, r.additional = {}, {}
    r.rcode = o.rcode or 0
    r.delay = o.delay
    return r
end

local function servfail(q, default) return reply(q, default, {}, { rcode = dns.RCODE.SERVFAIL }) end

--- Open a native connection and send `req`; returns a state for `poll`.
local function open(req)
    local fd = assert(unixsock.socket(sut, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
    local c = unixsock.connect(sut, fd, SOCK)
    assert(c.ret == 0, "connect " .. SOCK .. ": " .. unixsock.errname(c.errno))
    local payload = type(req) == "string" and req or msgpack.encode(req)
    ntfe.send(sut, fd, string.pack("<I4", #payload) .. payload)
    return { fd = fd, buf = "" }
end

--- Read what has arrived, without waiting; true once the reply is whole
--- (or the connection ended).
local function poll(st)
    while true do
        local chunk = ntfe.recv(sut, st.fd, 0, 65536)
        if not chunk then return false end
        if #chunk == 0 then st.eof = true; return true end
        st.buf = st.buf .. chunk
        if #st.buf >= 4 then
            local n = string.unpack("<I4", st.buf)
            if #st.buf >= 4 + n then
                st.body = st.buf:sub(5, 4 + n)
                st.at = clock()
                return true
            end
        end
    end
end

--- Send `req` on the native socket, pump the gateway until the reply is
--- whole, and return it decoded, plus the raw body and the gateway clock
--- at its arrival.
local function ask(req, o)
    o = o or {}
    local st = open(req)
    gw:serve({ timeout = o.timeout or 20, until_ = function() return poll(st) end })
    sys.close(sut, st.fd)
    assert(st.body, "no reply from resolvd to " .. (type(req) == "table" and tostring(req.query) .. " " .. tostring(req.name) or "a raw request"))
    return msgpack.decode(st.body), st.body, st.at
end

local function rstatus()
    local s, err = network.call(sut, { query = "status" }, { path = SOCK, timeout_ms = 3000 })
    assert(s and s.ok, "resolvd status: " .. tostring(err or (s and s.error)))
    return s
end

--- Wait until resolvd's scope for eth0 has the gateway as its server and
--- example.test as its domain.
local function ready(t)
    local ok = gw:serve({ timeout = 60, until_ = function()
        local s = network.call(sut, { query = "status" }, { path = SOCK, timeout_ms = 2000 })
        if not (s and s.ok) then return false end
        for _, sc in ipairs(s.scopes or {}) do
            if sc.interface == "eth0" and (sc.servers or {})[1] == "10.77.0.1" and (sc.domains or {})[1] == "example.test" then
                return true
            end
        end
        return false
    end })
    t:assert(ok, "resolvd has eth0's scope: server 10.77.0.1, domain example.test")
end

--- The UDP questions the gateway was asked for `name` (any case), of
--- `qtype` when given.
local function asked(name, qtype)
    return dns.queries(gw, function(e)
        local qn = e.msg and e.msg.questions[1]
        return e.transport == "udp" and qn ~= nil and dns.same_name(qn.name, name)
            and (qtype == nil or qn.type == qtype)
    end)
end

local function lookup(name, family)
    local req = { query = "lookup", name = name }
    if family ~= nil then req.family = family end
    return ask(req)
end

-- The reply's addresses as "addr/ttl" text, in order.
local function addrs(r)
    local out = {}
    for _, a in ipairs(r.addresses or {}) do out[#out + 1] = a.address .. "/" .. tostring(a.ttl) end
    return table.concat(out, " ")
end

local function addr_set(r)
    local out = {}
    for _, a in ipairs(r.addresses or {}) do out[#out + 1] = a.address end
    table.sort(out)
    return table.concat(out, " ")
end

local function show(r)
    return string.format("outcome=%s canonical=%s source=%s addresses=[%s]",
        tostring(r.outcome), tostring(r.canonical), tostring(r.source), addrs(r))
end

-- A MessagePack walker that keeps each value's wire type: every node is
-- {t = "map"|"array"|"str"|"bin"|"uint"|"int"|"bool"|"nil"|"float", v = …};
-- a map's `v` is keyed by its keys and its `keys` lists them in wire order.
local function typed(b, at)
    local tag = b:byte(at)
    assert(tag, "typed: ran off the end")
    local function map(n, from)
        local m = { t = "map", v = {}, keys = {} }
        for _ = 1, n do
            local k, v
            k, from = typed(b, from)
            v, from = typed(b, from)
            m.keys[#m.keys + 1] = k.v
            m.v[k.v] = v
        end
        return m, from
    end
    local function arr(n, from)
        local a = { t = "array", v = {} }
        for i = 1, n do a.v[i], from = typed(b, from) end
        return a, from
    end
    local function str(kind, n, from) return { t = kind, v = b:sub(from, from + n - 1) }, from + n end
    if tag <= 0x7f then return { t = "uint", v = tag }, at + 1 end
    if tag >= 0xe0 then return { t = "int", v = tag - 0x100 }, at + 1 end
    if tag <= 0x8f then return map(tag - 0x80, at + 1) end
    if tag <= 0x9f then return arr(tag - 0x90, at + 1) end
    if tag <= 0xbf then return str("str", tag - 0xa0, at + 1) end
    if tag == 0xc0 then return { t = "nil" }, at + 1 end
    if tag == 0xc2 or tag == 0xc3 then return { t = "bool", v = tag == 0xc3 }, at + 1 end
    if tag == 0xc4 then return str("bin", b:byte(at + 1), at + 2) end
    if tag == 0xc5 then return str("bin", string.unpack(">I2", b, at + 1), at + 3) end
    if tag == 0xc6 then return str("bin", string.unpack(">I4", b, at + 1), at + 5) end
    if tag == 0xd9 then return str("str", b:byte(at + 1), at + 2) end
    if tag == 0xda then return str("str", string.unpack(">I2", b, at + 1), at + 3) end
    if tag == 0xdb then return str("str", string.unpack(">I4", b, at + 1), at + 5) end
    if tag == 0xca or tag == 0xcb then return { t = "float" }, at + (tag == 0xca and 5 or 9) end
    if tag >= 0xcc and tag <= 0xcf then
        local w = ({ [0xcc] = 1, [0xcd] = 2, [0xce] = 4, [0xcf] = 8 })[tag]
        return { t = "uint", v = string.unpack(">I" .. w, b, at + 1) }, at + 1 + w
    end
    if tag >= 0xd0 and tag <= 0xd3 then
        local w = ({ [0xd0] = 1, [0xd1] = 2, [0xd2] = 4, [0xd3] = 8 })[tag]
        return { t = "int", v = string.unpack(">i" .. w, b, at + 1) }, at + 1 + w
    end
    if tag == 0xdc then return arr(string.unpack(">I2", b, at + 1), at + 3) end
    if tag == 0xdd then return arr(string.unpack(">I4", b, at + 1), at + 5) end
    if tag == 0xde then return map(string.unpack(">I2", b, at + 1), at + 3) end
    if tag == 0xdf then return map(string.unpack(">I4", b, at + 1), at + 5) end
    error(string.format("typed: unhandled tag 0x%02x", tag))
end

local function keyset(m)
    local k = {}
    for i, v in ipairs(m.keys) do k[i] = v end
    table.sort(k)
    return table.concat(k, ",")
end

-- ---------------------------------------------------------------------------
-- Tests
-- ---------------------------------------------------------------------------

test("lookup: `any` starts the A and AAAA tasks together, `inet` asks only A, `inet6` only AAAA; an absent family, or any other string, is `any`",
    { spec = "resolvd *engine-lookup.any-starts-both-families resolvd *engine-lookup.inet-asks-a resolvd *engine-lookup.inet6-asks-aaaa resolvd *native-requests.lookup-unknown-family-is-any PSPU *nri-requests.lookup-family-default-any" }, function(t)
        ready(t)

        -- `any`: both answers held back a second. Had the AAAA task waited
        -- for the A one, its question would come a second later.
        H["fam-any.example.test"] = function(q, d) return reply(q, d, d.answers, { delay = 1 }) end
        local r = lookup("fam-any.example.test", "any")
        t:log("any: " .. show(r))
        t:assert_eq(r.outcome, "found", "any: found")
        t:assert_eq(addr_set(r), "10.77.0.31 fd77::31", "any: both families' addresses")
        local qa, q6 = asked("fam-any.example.test", A), asked("fam-any.example.test", AAAA)
        t:assert(#qa >= 1 and #q6 >= 1, "any: the gateway was asked for A and for AAAA")
        local gap = math.abs(qa[1].at - q6[1].at)
        t:log(string.format("any: first A question at %.3f, first AAAA at %.3f (gap %.3f s; replies held 1 s)",
            qa[1].at, q6[1].at, gap))
        t:assert(gap < 0.5, "any: the two questions went out together, not one after the other's answer")

        -- `inet` and `inet6`: one family only. After the reply, a further
        -- second of pumping shows no question of the other type follows.
        for _, c in ipairs({ { "inet", "fam-v4.example.test", A, AAAA, "10.77.0.32" },
                             { "inet6", "fam-v6.example.test", AAAA, A, "fd77::33" } }) do
            local family, name, want, other, addr = c[1], c[2], c[3], c[4], c[5]
            r = lookup(name, family)
            gw:serve({ timeout = 1 })
            t:log(family .. ": " .. show(r) .. string.format("; questions %s=%d %s=%d",
                dns.TYPE_NAME[want], #asked(name, want), dns.TYPE_NAME[other], #asked(name, other)))
            t:assert_eq(r.outcome, "found", family .. ": found")
            t:assert_eq(addr_set(r), addr, family .. ": that family's address only")
            t:assert(#asked(name, want) >= 1, family .. ": asked " .. dns.TYPE_NAME[want])
            t:assert_eq(#asked(name, other), 0, family .. ": never asked " .. dns.TYPE_NAME[other])
        end

        -- No family, an upper-case `INET`, and a string that names nothing:
        -- each is `any`.
        for _, c in ipairs({ { nil, "fam-absent.example.test", "10.77.0.34 fd77::34" },
                             { "INET", "fam-upper.example.test", "10.77.0.35 fd77::35" },
                             { "bogus", "fam-bogus.example.test", "10.77.0.36 fd77::36" } }) do
            local family, name, set = c[1], c[2], c[3]
            r = lookup(name, family)
            local label = family and ("family " .. family) or "no family"
            t:log(label .. ": " .. show(r))
            t:assert_eq(r.ok, true, label .. ": answered")
            t:assert_eq(r.outcome, "found", label .. ": found")
            t:assert_eq(addr_set(r), set, label .. ": both families' addresses, as for any")
            t:assert(#asked(name, A) >= 1 and #asked(name, AAAA) >= 1, label .. ": A and AAAA both asked")
        end
    end)

test("lookup outcome: found when any task is found (records or not), else unavailable when any is unavailable, else notfound",
    { spec = "resolvd *engine-lookup.any-found-is-found resolvd *engine-lookup.unavailable-without-found resolvd *engine-lookup.all-notfound-is-notfound PSPU *nri-requests.lookup-outcome-rule" }, function(t)
        ready(t)
        -- A found, AAAA NODATA (found, no records).
        local r = lookup("out-nodata.example.test", "any")
        t:log("A found + AAAA NODATA: " .. show(r))
        t:assert_eq(r.outcome, "found", "A found, AAAA NODATA: found")
        t:assert_eq(addr_set(r), "10.77.0.41", "… with the IPv4 address only")

        -- A found, AAAA unavailable (SERVFAIL on every attempt).
        H["out-servfail.example.test"] = function(q, d)
            if q.questions[1].type == AAAA then return servfail(q, d) end
        end
        r = lookup("out-servfail.example.test", "any")
        t:log("A found + AAAA unavailable: " .. show(r) .. "; AAAA questions " .. #asked("out-servfail.example.test", AAAA))
        t:assert(#asked("out-servfail.example.test", AAAA) >= 1, "the AAAA question was asked and failed")
        t:assert_eq(r.outcome, "found", "A found, AAAA unavailable: found")
        t:assert_eq(addr_set(r), "10.77.0.42", "… with the IPv4 address only")

        -- Both NODATA: found, with no records at all.
        r = lookup("out-empty.example.test", "any")
        t:log("both NODATA: " .. show(r))
        t:assert_eq(r.outcome, "found", "both found without records: found")
        t:assert_eq(#(r.addresses or {}), 0, "… and no addresses")

        -- A NXDOMAIN, AAAA unavailable: none found, one unavailable.
        H["out-unavail.example.test"] = function(q, d)
            if q.questions[1].type == AAAA then return servfail(q, d) end
        end
        r = lookup("out-unavail.example.test", "any")
        t:log("A notfound + AAAA unavailable: " .. show(r))
        t:assert(#asked("out-unavail.example.test", A) >= 1, "A asked")
        t:assert_eq(r.outcome, "unavailable", "none found, one unavailable: unavailable")
        t:assert_eq(#(r.addresses or {}), 0, "… no addresses")

        -- Both NXDOMAIN.
        r = lookup("out-none.example.test", "any")
        t:log("both notfound: " .. show(r))
        t:assert(#asked("out-none.example.test", A) >= 1 and #asked("out-none.example.test", AAAA) >= 1, "both asked")
        t:assert_eq(r.outcome, "notfound", "every task notfound: notfound")
    end)

test("CNAME chasing follows the first record at the name when it is a CNAME and the asked type is absent there, case-insensitively, after expansion, and takes the addresses at the final name in answer order with their own TTLs",
    { spec = "resolvd *engine-lookup.cname-chase-follows-first-cname resolvd *engine-lookup.cname-chase-addresses-at-final-name PSPU *nri-requests.lookup-follows-cname-chain" }, function(t)
        ready(t)
        -- A two-step chain; an unrelated A record sits between the final
        -- name's two.
        H["ch-final.example.test"] = function(q, d)
            return reply(q, d, {
                rr(nil, CNAME, "ch-mid.example.test"),
                rr("ch-mid.example.test", CNAME, "ch-end.example.test"),
                rr("ch-end.example.test", A, "10.77.0.51", 50),
                rr("ch-other.example.test", A, "10.77.0.59", 40),
                rr("ch-end.example.test", A, "10.77.0.52", 70),
            })
        end
        local r = lookup("ch-final.example.test", "inet")
        t:log("chain: " .. show(r))
        t:assert_eq(r.outcome, "found", "chain: found")
        t:assert_eq(addrs(r), "10.77.0.51/50 10.77.0.52/70",
            "chain: the final name's A records, in answer order, each with its TTL; the unrelated one left out")
        t:assert_eq(r.canonical, "ch-end.example.test", "chain: canonical is where the chase ended")

        -- The first record at the name is an A: no chase.
        H["ch-first-a.example.test"] = function(q, d)
            return reply(q, d, {
                rr(nil, A, "10.77.0.53"),
                rr(nil, CNAME, "ch-x.example.test"),
                rr("ch-x.example.test", A, "10.77.0.54"),
            })
        end
        r = lookup("ch-first-a.example.test", "inet")
        t:log("first record an A: " .. show(r))
        t:assert_eq(addrs(r), "10.77.0.53/60", "first record not a CNAME: the name's own address, no chase")
        t:assert_eq(r.canonical, "ch-first-a.example.test", "… canonical the name asked")

        -- The first record is a CNAME, but the asked type is at the name too.
        H["ch-type-there.example.test"] = function(q, d)
            return reply(q, d, {
                rr(nil, CNAME, "ch-y.example.test"),
                rr(nil, A, "10.77.0.55"),
                rr("ch-y.example.test", A, "10.77.0.56"),
            })
        end
        r = lookup("ch-type-there.example.test", "inet")
        t:log("CNAME first, A also present: " .. show(r))
        t:assert_eq(addrs(r), "10.77.0.55/60", "the asked type at the name stops the chase")

        -- Owner names in another case than the question and the target.
        H["ch-case.example.test"] = function(q, d)
            return reply(q, d, {
                rr("CH-CASE.Example.TEST", CNAME, "Ch-End4.example.test"),
                rr("ch-end4.EXAMPLE.test", A, "10.77.0.57"),
            })
        end
        r = lookup("ch-case.example.test", "inet")
        t:log("mixed case: " .. show(r))
        t:assert_eq(addrs(r), "10.77.0.57/60", "names compared case-insensitively along the chain")
        t:assert(dns.same_name(r.canonical, "ch-end4.example.test"), "canonical is the chain's end")

        -- A single label: expanded with example.test, then chased.
        H["ch-short.example.test"] = function(q, d)
            return reply(q, d, {
                rr(nil, CNAME, "ch-long.example.test"),
                rr("ch-long.example.test", A, "10.77.0.58"),
            })
        end
        r = lookup("ch-short", "inet")
        t:log("single label: " .. show(r))
        t:assert(#asked("ch-short.example.test", A) >= 1, "the expanded name was asked")
        t:assert_eq(addrs(r), "10.77.0.58/60", "expanded, chased, and the chain's end's address returned")
        t:assert_eq(r.canonical, "ch-long.example.test", "canonical is the name after expansion and chasing")
    end)

test("the chase moves at most 16 times, so a loop ends; and it uses only the task's own answer, asking nothing further",
    { spec = "resolvd *engine-lookup.cname-chase-depth-16 resolvd *engine-lookup.chase-asks-no-further-question" }, function(t)
        ready(t)
        -- `prefix`-0 → … → `prefix`-n by CNAME, then an A at the end.
        local function chain(prefix, n, addr)
            H[prefix .. "-0.example.test"] = function(q, d)
                local ans = {}
                for i = 0, n - 1 do
                    ans[#ans + 1] = rr(string.format("%s-%d.example.test", prefix, i), CNAME,
                        string.format("%s-%d.example.test", prefix, i + 1))
                end
                ans[#ans + 1] = rr(string.format("%s-%d.example.test", prefix, n), A, addr)
                return reply(q, d, ans)
            end
        end
        chain("dep16", 16, "10.77.0.61")
        chain("dep17", 17, "10.77.0.62")

        local r = lookup("dep16-0.example.test", "inet")
        t:log("16 CNAMEs: " .. show(r))
        t:assert_eq(r.outcome, "found", "16 CNAMEs: found")
        t:assert_eq(addr_set(r), "10.77.0.61", "16 CNAMEs: the chase reaches the end and its address")
        t:assert_eq(r.canonical, "dep16-16.example.test", "16 CNAMEs: canonical is the 16th target")

        r = lookup("dep17-0.example.test", "inet")
        t:log("17 CNAMEs: " .. show(r))
        t:assert_eq(r.outcome, "found", "17 CNAMEs: still found")
        t:assert_eq(#(r.addresses or {}), 0, "17 CNAMEs: the chase stops at the 16th target, a CNAME, so no address")
        t:assert_eq(r.canonical, "dep17-0.example.test", "17 CNAMEs: no addresses, so canonical is the name asked")

        H["loop-a.example.test"] = function(q, d)
            return reply(q, d, {
                rr(nil, CNAME, "loop-b.example.test"),
                rr("loop-b.example.test", CNAME, "loop-a.example.test"),
            })
        end
        r = lookup("loop-a.example.test", "inet")
        t:log("loop: " .. show(r))
        t:assert_eq(r.outcome, "found", "a loop ends: found")
        t:assert_eq(#(r.addresses or {}), 0, "a loop: no addresses")

        -- A CNAME whose target's address the server left out.
        H["nq-head.example.test"] = function(q, d)
            return reply(q, d, { rr(nil, CNAME, "nq-away.example.test") })
        end
        r = lookup("nq-head.example.test", "inet")
        gw:serve({ timeout = 2 })
        t:log("dangling CNAME: " .. show(r) .. "; questions for nq-away: " .. #dns.queries(gw, function(e)
            return e.msg and e.msg.questions[1] and dns.same_name(e.msg.questions[1].name, "nq-away.example.test")
        end))
        t:assert_eq(r.outcome, "found", "a chain leaving the answer: found")
        t:assert_eq(#(r.addresses or {}), 0, "… with no addresses")
        t:assert_eq(#dns.queries(gw, function(e)
            return e.msg and e.msg.questions[1] and dns.same_name(e.msg.questions[1].name, "nq-away.example.test")
        end), 0, "no question is asked for the target")
    end)

test("the tasks run independently and the reply waits for the last; addresses follow completion order, canonical the later family's chain, source the last found task's",
    { spec = "resolvd *engine-lookup.tasks-independent-reply-after-last resolvd *engine-lookup.address-order-follows-completion resolvd *engine-lookup.canonical-name-rule resolvd *engine-lookup.source-of-last-found-task" }, function(t)
        ready(t)
        -- Each family's answer is a chain of its own; one family's answer
        -- is held back a second.
        local due = {}
        local function split(name, v4end, v4, v6end, v6, slow)
            H[name] = function(q, d, ctx)
                local qt = q.questions[1].type
                if qt == A then
                    return reply(q, d, { rr(nil, CNAME, v4end), rr(v4end, A, v4) },
                        { delay = slow == A and 1 or nil })
                elseif qt == AAAA then
                    if slow == AAAA then due[name] = due[name] or ctx.at + 1 end
                    return reply(q, d, { rr(nil, CNAME, v6end), rr(v6end, AAAA, v6) },
                        { delay = slow == AAAA and 1 or nil })
                end
            end
        end
        split("ord-v4first.example.test", "oa4.example.test", "10.77.0.71", "oa6.example.test", "fd77::71", AAAA)
        split("ord-v6first.example.test", "ob4.example.test", "10.77.0.72", "ob6.example.test", "fd77::72", A)

        local r, _, at = lookup("ord-v4first.example.test", "any")
        t:log(string.format("AAAA held: %s; reply at %.3f, AAAA reply due %.3f", show(r), at, due["ord-v4first.example.test"] or -1))
        t:assert_eq(r.outcome, "found", "found")
        t:assert_eq(addrs(r), "10.77.0.71/60 fd77::71/60", "A finished first: its address comes first")
        t:assert_eq(r.canonical, "oa6.example.test", "both produced addresses: canonical is the later (AAAA) chain's end")
        t:assert_eq(r.source, "dns", "source: dns")
        t:assert(due["ord-v4first.example.test"] and at >= due["ord-v4first.example.test"],
            "the reply came only after the held AAAA answer was sent, though A was answered at once")

        r = lookup("ord-v6first.example.test", "any")
        t:log("A held: " .. show(r))
        t:assert_eq(addrs(r), "fd77::72/60 10.77.0.72/60", "AAAA finished first: its address comes first")
        t:assert_eq(r.canonical, "ob4.example.test", "canonical is the later (A) chain's end")

        -- Different sources: A cached by an `inet` lookup, then `any`. The
        -- cached A task is done before the AAAA question goes out.
        r = lookup("src-cachefirst.example.test", "inet")
        t:assert_eq(addrs(r), "10.77.0.73/60", "primed: A from dns")
        local before_a = #asked("src-cachefirst.example.test", A)
        r = lookup("src-cachefirst.example.test", "any")
        t:log("A cached, AAAA from dns: " .. show(r))
        t:assert_eq(#asked("src-cachefirst.example.test", A), before_a, "the A task was answered from the cache (no new A question)")
        t:assert(#asked("src-cachefirst.example.test", AAAA) >= 1, "the AAAA task went to the server")
        t:assert_eq(r.addresses[1] and r.addresses[1].address, "10.77.0.73", "the cached A (finished first) comes first")
        t:assert_eq(r.addresses[2] and r.addresses[2].address, "fd77::73", "… then the AAAA from dns")
        t:assert_eq(r.addresses[2].ttl, 60, "the AAAA's TTL is the record's, fresh from the server")
        t:assert(r.addresses[1].ttl <= 60, "the A's TTL is the cached one, lowered by its age")
        t:assert_eq(r.source, "dns", "source is the last found task's: dns")

        -- The last task to finish is not found: source is the last *found*.
        r = lookup("src-cachelast.example.test", "inet")
        t:assert_eq(addrs(r), "10.77.0.74/60", "primed: A from dns")
        H["src-cachelast.example.test"] = function(q, d)
            if q.questions[1].type == AAAA then return servfail(q, d) end
        end
        r = lookup("src-cachelast.example.test", "any")
        t:log("A cached, AAAA unavailable: " .. show(r))
        t:assert_eq(r.outcome, "found", "found")
        t:assert_eq(r.source, "cache", "source is the last found task's (the cached A), not the unavailable AAAA's")

        -- Nothing found: local.
        r = lookup("src-none.example.test", "any")
        t:log("nothing found: " .. show(r))
        t:assert_eq(r.outcome, "notfound", "notfound")
        t:assert_eq(r.source, "local", "no task found: source local")

        -- The name as parsed, in presentation form without the trailing dot.
        r = lookup("Src-None2.Example.TEST.", "any")
        t:log("trailing dot, mixed case: " .. show(r))
        t:assert_eq(r.canonical, "Src-None2.Example.TEST", "no addresses: canonical is the name as parsed, without its trailing dot")
    end)

test("a found with no addresses leaves canonical as the name asked, even after expansion; an unparseable name is notfound at once with canonical `.`; a lookup counts one query",
    { spec = "resolvd *engine-lookup.canonical-unexpanded-without-addresses resolvd *engine-lookup.unparseable-name-canonical-root resolvd *engine-lookup.counts-one-query" }, function(t)
        ready(t)
        -- printer.example.test has an A and no AAAA.
        local r = lookup("printer", "inet6")
        t:log("printer, inet6: " .. show(r))
        t:assert(#asked("printer.example.test", AAAA) >= 1, "the expanded name was asked for AAAA")
        t:assert_eq(r.outcome, "found", "found (NODATA)")
        t:assert_eq(#(r.addresses or {}), 0, "no addresses")
        -- The resolver as built; the PSPU known-bug test below asserts the
        -- spec's view (the expanded name).
        t:assert_eq(r.canonical, "printer", "canonical stays the name asked, not the expanded printer.example.test")
        r = lookup("printer", "inet")
        t:log("printer, inet: " .. show(r))
        t:assert_eq(r.canonical, "printer.example.test", "with an address, canonical is the expanded name")

        -- Names that do not parse.
        for _, bad in ipairs({ "bad..name.example.test", string.rep("x", 64) .. ".example.test" }) do
            r = lookup(bad, "any")
            t:log(bad:sub(1, 20) .. "…: " .. show(r))
            t:assert_eq(r.outcome, "notfound", "unparseable: notfound")
            t:assert_eq(r.canonical, ".", "unparseable: canonical `.`")
            t:assert_eq(#(r.addresses or {}), 0, "unparseable: no addresses")
            t:assert_eq(r.source, "local", "unparseable: source local")
        end
        gw:serve({ timeout = 1 })
        t:assert_eq(#dns.queries(gw, function(e)
            local qn = e.msg and e.msg.questions[1]
            return qn ~= nil and (qn.name:lower():find("bad", 1, true) ~= nil or qn.name:lower():find("xxxxxxxx", 1, true) ~= nil)
        end), 0, "no question was asked for an unparseable name")

        -- One query per lookup, though an `any` lookup makes two tasks. The
        -- image's own background lookups also count, so the window is
        -- taken again if the gateway saw any other name inside it.
        local measured
        for try = 1, 5 do
            local name = string.format("count%d.example.test", try)
            local t0 = clock()
            local before = rstatus().counters.queries
            r = lookup(name, "any")
            local after = rstatus().counters.queries
            gw:serve({ timeout = 1 })
            local foreign = dns.queries(gw, function(e)
                local qn = e.msg and e.msg.questions[1]
                return e.at >= t0 and not (qn and qn.name:lower():find("^count%d"))
            end)
            t:log(string.format("window %d: queries %d -> %d; A asked %d, AAAA asked %d; other names in the window %d",
                try, before, after, #asked(name, A), #asked(name, AAAA), #foreign))
            if #foreign == 0 then
                t:assert(#asked(name, A) >= 1 and #asked(name, AAAA) >= 1, "the lookup made two tasks")
                measured = after - before
                break
            end
        end
        t:assert(measured ~= nil, "a quiet window was found")
        t:assert_eq(measured, 1, "an any lookup adds one to queries")
    end)

test("[PSPU] lookup canonical is the name the addresses belong to after expansion — also when the expanded name has none of the family",
    { spec = "PSPU *nri-requests.lookup-canonical-name", tags = { "known-bug" } }, function(t)
        ready(t)
        local r = lookup("printer", "any")
        t:log("printer, any: " .. show(r))
        t:assert_eq(r.canonical, "printer.example.test", "expanded and found with an address: the expanded name")
        r = lookup("printer", "inet6")
        t:log("printer, inet6: " .. show(r))
        -- PEI-1349: resolvd reports canonical "printer" (the name asked)
        -- when the expanded name's answer has no address of the family.
        t:assert_eq(r.canonical, "printer.example.test",
            "expansion applied (printer.example.test answered, NODATA): canonical is the expanded name")
    end)

test("the lookup reply is {ok, kind=addresses, outcome, canonical, addresses, source, validation}, each address exactly {address: string, ttl: uint}",
    { spec = "PSPU *nri-requests.lookup-addresses-shape" }, function(t)
        ready(t)
        local r, body = lookup("shape.example.test", "any")
        t:log("shape: " .. show(r))
        local m = typed(body, 1)
        t:assert_eq(m.t, "map", "the reply is a map")
        t:assert_eq(keyset(m), "addresses,canonical,kind,ok,outcome,source,validation", "the reply's keys")
        t:assert_eq(m.v.kind.v, "addresses", "kind addresses")
        for _, k in ipairs({ "kind", "outcome", "canonical", "source", "validation" }) do
            t:assert_eq(m.v[k].t, "str", k .. " is a string")
        end
        t:assert_eq(m.v.validation.v, "unvalidated", "validation unvalidated")
        t:assert_eq(m.v.addresses.t, "array", "addresses is an array")
        t:assert_eq(#m.v.addresses.v, 2, "two addresses")
        local seen = {}
        for i, a in ipairs(m.v.addresses.v) do
            t:assert_eq(a.t, "map", "address " .. i .. " is a map")
            t:assert_eq(keyset(a), "address,ttl", "address " .. i .. ": exactly address and ttl")
            t:assert_eq(a.v.address.t, "str", "address " .. i .. ": address is a string")
            t:assert_eq(a.v.ttl.t, "uint", "address " .. i .. ": ttl is an unsigned integer")
            seen[a.v.address.v] = a.v.ttl.v
        end
        t:assert_eq(seen["10.77.0.91"], 77, "the IPv4 address in its textual form, with its record's TTL")
        t:assert_eq(seen["fd77::91"], 78, "the IPv6 address in its textual form, with its record's TTL")
    end)
