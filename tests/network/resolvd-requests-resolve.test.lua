-- resolvd §5.3 (`resolve`, `reverse`, the record keys and their text
-- forms), §4.9 (`reverse` becomes a PTR question), and PSPU §6.5
-- (`resolve`, `reverse`, the answer reply, unknown requests and how a
-- client takes an error reply).
--
-- Harness: the scripted gateway (helpers.gateway) and its DNS server
-- (helpers.dns), and a whole Peios (helpers.network). The lease offers the
-- gateway as the one DNS server and `example.test` as the domain (option
-- 15). Crafted answers come from per-name hooks (`H`), built from the
-- server's default reply, so the id and the 0x20-cased question match;
-- record owners given as label tables carry bytes no presentation-form
-- name can (a dot, a space, 0xff inside a label).
--
-- Requests go to the native socket as SYSTEM: sent, then the gateway is
-- pumped until the reply is whole (`ask`). `resolv` runs in the guest
-- while the gateway pumps (`served`).
--
-- Non-obvious:
--   * no zone-wide SOA, so negative answers are cached only where a hook
--     adds one;
--   * a reply over 512 bytes is truncated and asked again over TCP, where
--     the hook runs again, so every hook is a pure function of the
--     question;
--   * helpers.msgpack decodes bin as a string and drops nil-valued keys, so
--     shape tests read the reply with a local typed walker (as
--     control-req.test.lua does);
--   * the last test writes `Dns ControlSecurity` and removes it again.

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
local T = dns.TYPE

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600, options = { { 15, "example.test" } } })

local function rr(name, t, data, ttl) return { name = name, type = t, data = data, ttl = ttl or 60 } end

-- fd77::ab:cd's reverse-mapping name: 32 nibbles, lowest first.
local V6 = "FD77::AB:CD"
local V6_HEX = "fd77" .. string.rep("0000", 5) .. "00ab00cd"
local V6_PTR
do
    local n = {}
    for i = #V6_HEX, 1, -1 do n[#n + 1] = V6_HEX:sub(i, i) end
    V6_PTR = table.concat(n, ".") .. ".ip6.arpa"
end

local H = {}
dns.serve(gw, {
    zone = {
        ["r1.example.test"] = { rr(nil, "A", "10.77.0.101"), rr(nil, "AAAA", "fd77::101") },
        ["r2.example.test"] = { rr(nil, "A", "10.77.0.102") },
        ["r4.example.test"] = { rr(nil, "A", "10.77.0.104", 44), rr(nil, "A", "10.77.0.114", 45) },
        ["r4b.example.test"] = { rr(nil, "A", "10.77.0.124") },
        ["r5short.example.test"] = { rr(nil, "A", "10.77.0.106") },
        ["99.0.77.10.in-addr.arpa"] = { rr(nil, "PTR", "printer99.example.test") },
        [V6_PTR] = { rr(nil, "PTR", "v6host.example.test") },
        ["r10.example.test"] = { rr(nil, "A", "10.77.0.110") },
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

local function reply(q, default, answers, o)
    o = o or {}
    local r = {}
    for k, v in pairs(default) do r[k] = v end
    local qname = q.questions[1].name
    r.answers = {}
    for i, a in ipairs(answers or {}) do
        r.answers[i] = { name = a.name or qname, type = a.type, data = a.data, rdata = a.rdata, ttl = a.ttl or 60 }
    end
    r.authority = o.authority or {}
    r.additional = o.additional or {}
    r.rcode = o.rcode or 0
    return r
end

local function open(req)
    local fd = assert(unixsock.socket(sut, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
    local c = unixsock.connect(sut, fd, SOCK)
    assert(c.ret == 0, "connect " .. SOCK .. ": " .. unixsock.errname(c.errno))
    local payload = type(req) == "string" and req or msgpack.encode(req)
    ntfe.send(sut, fd, string.pack("<I4", #payload) .. payload)
    return { fd = fd, buf = "" }
end

local function poll(st)
    while true do
        local chunk = ntfe.recv(sut, st.fd, 0, 65536)
        if not chunk then return false end
        if #chunk == 0 then st.eof = true; return true end
        st.buf = st.buf .. chunk
        if #st.buf >= 4 then
            local n = string.unpack("<I4", st.buf)
            if #st.buf >= 4 + n then st.body = st.buf:sub(5, 4 + n); return true end
        end
    end
end

--- Send `req`, pump the gateway until the reply is whole; the decoded
--- reply and its raw body.
local function ask(req, o)
    o = o or {}
    local st = open(req)
    gw:serve({ timeout = o.timeout or 20, until_ = function() return poll(st) end })
    sys.close(sut, st.fd)
    assert(st.body, "no reply from resolvd to " .. tostring(req.query) .. " " .. tostring(req.name or req.address))
    return msgpack.decode(st.body), st.body
end

local function resolve(name, rtype, extra)
    local req = { query = "resolve", name = name, type = rtype }
    for k, v in pairs(extra or {}) do req[k] = v end
    return ask(req)
end

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

local function asked(name, qtype)
    return dns.queries(gw, function(e)
        local qn = e.msg and e.msg.questions[1]
        return e.transport == "udp" and qn ~= nil and dns.same_name(qn.name, name)
            and (qtype == nil or qn.type == qtype)
    end)
end

--- Run `cmd` in the guest while the gateway pumps.
local function served(cmd, timeout)
    local p = sut:run_async("sh", { args = { "-c", cmd } })
    gw:serve({ timeout = timeout or 20, until_ = function() return p:status() == "exited" end })
    return p:wait(5)
end

local function show(r)
    local recs = {}
    for _, x in ipairs(r.records or {}) do
        recs[#recs + 1] = string.format("%s/%s/%s/%s", tostring(x.name), tostring(x.type), tostring(x.ttl), tostring(x.text))
    end
    return string.format("ok=%s outcome=%s source=%s server=%s interface=%s rcode=%s records=[%s] error=%s",
        tostring(r.ok), tostring(r.outcome), tostring(r.source), tostring(r.server), tostring(r.interface),
        tostring(r.rcode), table.concat(recs, "; "), tostring(r.error))
end

local function texts(r)
    local out = {}
    for _, x in ipairs(r.records or {}) do out[#out + 1] = x.text end
    return table.concat(out, " | ")
end

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

local function hex(s) return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end)) end

-- ---------------------------------------------------------------------------
-- Tests
-- ---------------------------------------------------------------------------

test("resolve: type is the record type number; a dns answer names its server, interface and rcode; a second ask is a cache hit unless no_cache, which defaults to false",
    { spec = "resolvd *native-requests.resolve-no-cache-default-false PSPU *nri-requests.resolve-no-cache-bypasses-cache PSPU *nri-requests.resolve-type-is-record-type-number PSPU *nri-requests.answer-server-for-dns PSPU *nri-requests.answer-interface PSPU *nri-requests.answer-rcode-for-dns" }, function(t)
        ready(t)
        local r = resolve("r1.example.test", 1)
        t:log("A, first: " .. show(r))
        t:assert_eq(r.ok, true, "answered")
        t:assert_eq(r.kind, "answer", "kind answer")
        t:assert_eq(r.outcome, "found", "found")
        t:assert_eq(#r.records, 1, "one record")
        t:assert_eq(r.records[1].type, 1, "type 1 asks for A records")
        t:assert_eq(r.records[1].text, "10.77.0.101", "the A record")
        t:assert_eq(r.source, "dns", "source dns")
        t:assert_eq(r.server, "10.77.0.1", "dns: the server that answered")
        t:assert_eq(r.interface, "eth0", "dns: the interface whose scope answered")
        t:assert_eq(r.rcode, 0, "dns: rcode NOERROR")
        local n = #asked("r1.example.test", T.A)
        t:assert_eq(n, 1, "one question went upstream")

        r = resolve("r1.example.test", 1)
        t:log("A, no no_cache: " .. show(r))
        t:assert_eq(r.source, "cache", "no no_cache: a cache hit")
        t:assert_eq(r.server, "10.77.0.1", "cache: the upstream whose answer was cached")
        t:assert_eq(r.interface, "eth0", "cache: the scope's interface")
        t:assert_eq(r.rcode, 0, "cache: the cached response's code")
        t:assert_eq(texts(r), "10.77.0.101", "cache: the same record")
        t:assert_eq(#asked("r1.example.test", T.A), n, "no question went upstream")

        r = resolve("r1.example.test", 1, { no_cache = true })
        t:log("A, no_cache=true: " .. show(r))
        t:assert_eq(r.source, "dns", "no_cache: past the cache, to the server")
        t:assert_eq(#asked("r1.example.test", T.A), n + 1, "no_cache: a new question went upstream")

        r = resolve("r1.example.test", 1, { no_cache = false })
        t:log("A, no_cache=false: " .. show(r))
        t:assert_eq(r.source, "cache", "no_cache=false is the default: a cache hit")

        r = resolve("r1.example.test", 28)
        t:log("AAAA: " .. show(r))
        t:assert_eq(#r.records, 1, "type 28: one record")
        t:assert_eq(r.records[1].type, 28, "type 28 asks for AAAA records")
        t:assert_eq(r.records[1].text, "fd77::101", "the AAAA record")
        t:assert_eq(#asked("r1.example.test", T.AAAA), 1, "the server was asked for type 28")

        -- NXDOMAIN, with an SOA so the negative answer is cached.
        H["r1-nx.example.test"] = function(q)
            return dns.answer(q, {}, { soa = { name = "example.test", data = { minimum = 30 } } })
        end
        r = resolve("r1-nx.example.test", 1)
        t:log("NXDOMAIN: " .. show(r))
        t:assert_eq(r.outcome, "notfound", "NXDOMAIN: notfound")
        t:assert_eq(r.source, "dns", "NXDOMAIN: source dns")
        t:assert_eq(r.rcode, 3, "dns: the response's code, NXDOMAIN")
        t:assert_eq(r.server, "10.77.0.1", "dns: the server")
        r = resolve("r1-nx.example.test", 1)
        t:log("NXDOMAIN again: " .. show(r))
        t:assert_eq(r.source, "cache", "cached negative: source cache")
        t:assert_eq(r.rcode, 3, "cache: the cached response's code")
        t:assert_eq(r.server, "10.77.0.1", "cache: the upstream whose answer was cached")

        -- Neither dns nor cache: no server, no interface, rcode 0.
        r = resolve("localhost", 1)
        t:log("localhost: " .. show(r))
        t:assert_eq(r.source, "synthetic", "localhost is synthetic")
        t:assert_eq(r.server, nil, "synthetic: no server")
        t:assert_eq(r.interface, nil, "synthetic: no interface")
        t:assert_eq(r.rcode, 0, "synthetic: rcode 0")
    end)

test("resolve takes any string as the name and hands it to the engine; source is one of synthetic, hosts, cache, dns and local",
    { spec = "resolvd *native-requests.resolve-name-accepted PSPU *nri-requests.answer-source-values" }, function(t)
        ready(t)
        local seen = {}
        local function note(r, what)
            t:log(what .. ": " .. show(r))
            seen[r.source] = true
        end
        -- Names the engine cannot parse: answered, not refused.
        for _, bad in ipairs({ "bad..name.example.test", string.rep("y", 64) .. ".example.test" }) do
            local r = resolve(bad, 1)
            note(r, bad:sub(1, 20) .. "…")
            t:assert_eq(r.ok, true, "an unparseable name is not refused at decoding")
            t:assert_eq(r.kind, "answer", "… it is answered")
            t:assert_eq(r.outcome, "notfound", "… notfound")
            t:assert_eq(r.source, "local", "… from nowhere: source local")
            t:assert_eq(#r.records, 0, "… no records")
        end
        gw:serve({ timeout = 1 })
        t:assert_eq(#dns.queries(gw, function(e)
            local qn = e.msg and e.msg.questions[1]
            return qn ~= nil and (qn.name:lower():find("bad", 1, true) ~= nil or qn.name:lower():find("yyyyyyyy", 1, true) ~= nil)
        end), 0, "nothing was asked upstream for them")

        note(resolve("localhost", 1), "localhost")
        network.write(sut, "Dns", {})   -- the parent first: `reg new` makes one level
        network.write(sut, [[Dns\Hosts]], { r9static = "sz:10.77.0.77" })
        local r
        t:assert(wait_until(function()
            r = resolve("r9static", 1)
            return r.source == "hosts"
        end, { timeout = 15, interval = 0.3, desc = "the static name" }), "the static name is answered")
        note(r, "static name")
        t:assert_eq(texts(r), "10.77.0.77", "the static name's address")
        note(resolve("r2.example.test", 1), "first ask")
        note(resolve("r2.example.test", 1), "second ask")
        local list = {}
        for s in pairs(seen) do list[#list + 1] = s end
        table.sort(list)
        t:assert_eq(table.concat(list, ","), "cache,dns,hosts,local,synthetic", "each of the five sources, and no other")
        network.delete(sut, [[Dns\Hosts]])
    end)

test("resolve forwards any type from 0 to 65535 as it is, ANY, OPT and types resolvd cannot parse included; a type beyond 65535 is refused",
    { spec = "resolvd *native-requests.resolve-type-forwarded-as-is" }, function(t)
        ready(t)
        for _, ty in ipairs({ 0, 41, 99, 255, 65280, 65535 }) do
            local name = string.format("type%d.example.test", ty)
            local r = resolve(name, ty)
            local q = dns.queries(gw, function(e)
                local qn = e.msg and e.msg.questions[1]
                return qn ~= nil and dns.same_name(qn.name, name)
            end)
            local types = {}
            for _, e in ipairs(q) do types[#types + 1] = tostring(e.msg.questions[1].type) end
            t:log(string.format("type %d: %s; the gateway was asked types [%s]", ty, show(r), table.concat(types, ",")))
            t:assert_eq(r.ok, true, "type " .. ty .. ": answered")
            t:assert(#q >= 1, "type " .. ty .. ": a question went upstream")
            for _, e in ipairs(q) do
                t:assert_eq(e.msg.questions[1].type, ty, "type " .. ty .. ": asked upstream as type " .. ty)
            end
        end
        local r = ask({ query = "resolve", name = "type65536.example.test", type = 65536 })
        t:log("type 65536: " .. show(r))
        t:assert_eq(r.ok, false, "type 65536: an error reply")
        t:assert_eq(r.error, "missing or malformed field type", "type 65536: the field is malformed")
    end)

test("the answer reply's fields have the MessagePack types named; records are {name: string, type: uint, ttl: uint, data: bin, text: string}; a name may carry a trailing dot; an address is text",
    { spec = "PSPU *nri-requests.answer-records-shape PSPU *nri-requests.field-encodings" }, function(t)
        ready(t)
        local r, body = resolve("r4.example.test", 1)
        t:log("r4: " .. show(r))
        local m = typed(body, 1)
        t:assert_eq(keyset(m), "interface,kind,ok,outcome,rcode,records,server,source,validation", "the answer reply's keys")
        local want = { ok = "bool", kind = "str", outcome = "str", records = "array", source = "str",
                       server = "str", interface = "str", validation = "str", rcode = "uint" }
        for k, ty in pairs(want) do t:assert_eq(m.v[k].t, ty, k .. " is " .. ty) end
        t:assert_eq(m.v.server.v, "10.77.0.1", "server: an address in its textual form")
        t:assert_eq(#m.v.records.v, 2, "two records")
        for i, rec in ipairs(m.v.records.v) do
            t:assert_eq(rec.t, "map", "record " .. i .. " is a map")
            t:assert_eq(keyset(rec), "data,name,text,ttl,type", "record " .. i .. ": name, type, ttl, data, text")
            t:assert_eq(rec.v.name.t, "str", "record " .. i .. ": name is a string")
            t:assert_eq(rec.v.type.t, "uint", "record " .. i .. ": type is a uint")
            t:assert_eq(rec.v.ttl.t, "uint", "record " .. i .. ": ttl is a uint")
            t:assert_eq(rec.v.data.t, "bin", "record " .. i .. ": data is bin")
            t:assert_eq(rec.v.text.t, "str", "record " .. i .. ": text is a string")
            t:assert_eq(rec.v.name.v, "r4.example.test", "record " .. i .. ": the owner in presentation form")
            t:assert_eq(rec.v.type.v, 1, "record " .. i .. ": type 1")
        end
        t:assert_eq(hex(m.v.records.v[1].v.data.v), "0a4d0068", "data: the A record's four bytes")
        t:assert_eq(m.v.records.v[1].v.ttl.v, 44, "ttl as the server sent it")

        -- A string or nil field, nil: still the key, nil-typed.
        local _, sbody = resolve("localhost", 1)
        local s = typed(sbody, 1)
        t:assert_eq(keyset(s), "interface,kind,ok,outcome,rcode,records,server,source,validation", "a synthetic answer has the same keys")
        t:assert_eq(s.v.server.t, "nil", "server is nil when there is none")
        t:assert_eq(s.v.interface.t, "nil", "interface is nil when there is none")

        -- The trailing dot: the same name, and the same cache key.
        local again = resolve("r4.example.test.", 1)
        t:log("r4.: " .. show(again))
        t:assert_eq(again.source, "cache", "with a trailing dot: the same name (a cache hit on it)")
        t:assert_eq(texts(again), texts(r), "… the same records")
        local fresh = resolve("r4b.example.test.", 1)
        t:log("r4b.: " .. show(fresh))
        t:assert_eq(fresh.outcome, "found", "a name first asked with a trailing dot is resolved")
        t:assert_eq(fresh.records[1].name, "r4b.example.test", "… its records named without the dot")
    end)

test("records are the answer section only, and an expanded name's records carry the expanded name",
    { spec = "PSPU *nri-requests.records-are-answer-section-only PSPU *nri-requests.expanded-records-carry-expanded-name" }, function(t)
        ready(t)
        H["r5-sections.example.test"] = function(q, d)
            return reply(q, d, { rr(nil, T.A, "10.77.0.105") }, {
                authority = { rr("example.test", T.NS, "ns1.example.test") },
                additional = { rr("ns1.example.test", T.A, "10.77.0.53") },
            })
        end
        local r = resolve("r5-sections.example.test", 1)
        t:log("three sections: " .. show(r))
        t:assert_eq(#r.records, 1, "one record: the answer section's")
        t:assert_eq(r.records[1].text, "10.77.0.105", "… the answer")

        r = resolve("r5short", 1)
        t:log("single label: " .. show(r))
        t:assert(#asked("r5short.example.test", T.A) >= 1, "the expanded name was asked")
        t:assert_eq(r.outcome, "found", "found at the expanded name")
        t:assert_eq(r.records[1].name, "r5short.example.test", "the record's name is the expanded name")
    end)

test("a record's name is in presentation form without a trailing dot: the root is `.`, a dot or backslash in a label is escaped, and a byte outside ! to ~ is \\DDD",
    { spec = "resolvd *native-requests.record-name-presentation" }, function(t)
        ready(t)
        H["r6-names.example.test"] = function(q, d)
            return reply(q, d, {
                rr(nil, T.TXT, "plain"),
                rr({ "a.b", "c\\d", "sp ace", "\x07\xff~!", "example", "test" }, T.TXT, "odd"),
                rr(".", T.TXT, "root"),
            })
        end
        local r = resolve("r6-names.example.test", T.TXT)
        t:log("names: " .. show(r))
        t:assert_eq(#r.records, 3, "three records")
        t:assert_eq(r.records[1].name, "r6-names.example.test", "an ordinary name, no trailing dot")
        t:assert_eq(r.records[2].name, [[a\.b.c\\d.sp\032ace.\007\255~!.example.test]],
            "a dot and a backslash escaped, space, 0x07 and 0xff as \\DDD, ~ and ! as they are")
        t:assert_eq(r.records[3].name, ".", "the root is `.`")
    end)

test("each record's text is its data in presentation form, by type",
    { spec = "resolvd *native-requests.record-text-forms" }, function(t)
        ready(t)
        local txt = { 'say "hi"', [[back\slash]], "bad\xff\xfeutf" }
        local want = {
            { T.A, "10.77.0.107" },
            { T.AAAA, "fd77::107" },
            { T.CNAME, [[t\.x.example.test]] },
            { T.PTR, "ptr.example.test" },
            { T.NS, "." },
            { T.SOA, "ns1.example.test hostmaster.example.test 2026100501 7200 900 1209600 300" },
            { T.MX, "10 mail.example.test" },
            { T.SRV, "1 2 5060 sip.example.test" },
            { T.TXT, [["say \"hi\"" "back\slash" "bad]] .. "\xEF\xBF\xBD\xEF\xBF\xBD" .. [[utf"]] },
            { 99, [[\# 3 0a0bff]] },
        }
        H["r7-forms.example.test"] = function(q, d)
            return reply(q, d, {
                rr(nil, T.A, "10.77.0.107"),
                rr(nil, T.AAAA, "fd77::107"),
                { type = T.CNAME, rdata = dns.name({ "t.x", "example", "test" }) },
                rr(nil, T.PTR, "ptr.example.test"),
                rr(nil, T.NS, "."),
                rr(nil, T.SOA, { mname = "ns1.example.test", rname = "hostmaster.example.test", serial = 2026100501,
                    refresh = 7200, retry = 900, expire = 1209600, minimum = 300 }),
                rr(nil, T.MX, { preference = 10, exchange = "mail.example.test" }),
                rr(nil, T.SRV, { priority = 1, weight = 2, port = 5060, target = "sip.example.test" }),
                rr(nil, T.TXT, txt),
                { type = 99, rdata = "\x0a\x0b\xff" },
            })
        end
        local r = resolve("r7-forms.example.test", T.TXT)
        t:log("forms: " .. show(r))
        t:assert_eq(#r.records, #want, "every record came back")
        for i, w in ipairs(want) do
            t:assert_eq(r.records[i].type, w[1], "record " .. i .. ": type " .. w[1])
            t:assert_eq(r.records[i].text, w[2], "record " .. i .. " (" .. (dns.TYPE_NAME[w[1]] or tostring(w[1])) .. "): text")
        end
    end)

test("a record's data is the rdata in uncompressed wire form, compression pointers resolved",
    { spec = "resolvd *native-requests.record-data-uncompressed-wire" }, function(t)
        ready(t)
        H["r8-mx.example.test"] = function(q)
            -- Header and the question as asked, then two MX records whose
            -- owners point at the question and whose second exchange
            -- points into the first's.
            local head = dns.encode({ id = q.id, qr = true, aa = true, ra = true, rd = q.rd,
                questions = q.questions, counts = { 1, 2, 0, 0 } })
            local rd1 = string.pack(">I2", 10) .. "\4mail\7example\4test\0"
            local rec1 = "\xC0\x0C" .. string.pack(">I2I2I4I2", T.MX, 1, 60, #rd1) .. rd1
            local example_at = #head + #rec1 - #"\7example\4test\0"   -- 0-based offset of "\7example"
            local rd2 = string.pack(">I2", 20) .. "\5mail2" .. string.pack(">I2", 0xC000 | example_at)
            local rec2 = "\xC0\x0C" .. string.pack(">I2I2I4I2", T.MX, 1, 60, #rd2) .. rd2
            return head .. rec1 .. rec2
        end
        local r = resolve("r8-mx.example.test", T.MX)
        t:log("compressed MX: " .. show(r))
        t:assert_eq(#r.records, 2, "two records")
        for i, x in ipairs(r.records) do t:log(string.format("record %d data %s", i, hex(x.data))) end
        t:assert_eq(r.records[1].name, "r8-mx.example.test", "an owner given as a pointer, resolved")
        t:assert_eq(hex(r.records[1].data), hex(string.pack(">I2", 10) .. "\4mail\7example\4test\0"),
            "record 1: the rdata as sent")
        t:assert_eq(hex(r.records[2].data), hex(string.pack(">I2", 20) .. "\5mail2\7example\4test\0"),
            "record 2: the pointer replaced by the labels it pointed at")
        t:assert_eq(r.records[2].text, "20 mail2.example.test", "record 2's text follows the pointer too")
    end)

test("reverse: the address's reverse-mapping name resolved for PTR exactly as resolve would, in-addr.arpa or 32 lower-case nibbles under ip6.arpa; anything that is not an address is an error",
    { spec = "resolvd *native-requests.reverse-bad-address-is-error resolvd *engine-lookup.reverse-is-ptr-resolve PSPU *nri-requests.reverse-is-ptr-resolve" }, function(t)
        ready(t)
        local r = ask({ query = "reverse", address = "10.77.0.99" })
        t:log("reverse 10.77.0.99: " .. show(r))
        t:assert_eq(r.kind, "answer", "an ordinary answer reply")
        t:assert_eq(r.outcome, "found", "found")
        t:assert_eq(r.source, "dns", "from the server")
        t:assert_eq(#r.records, 1, "one record")
        t:assert_eq(r.records[1].type, 12, "a PTR record")
        t:assert_eq(r.records[1].name, "99.0.77.10.in-addr.arpa", "at the octets reversed under in-addr.arpa")
        t:assert_eq(r.records[1].text, "printer99.example.test", "naming the host")
        local q = asked("99.0.77.10.in-addr.arpa")
        t:assert_eq(#q, 1, "one question upstream")
        t:assert_eq(q[1].msg.questions[1].type, 12, "… for PTR")

        -- The same question as a resolve: it shares the cache.
        local same = resolve("99.0.77.10.in-addr.arpa", 12)
        t:log("resolve of the PTR name: " .. show(same))
        t:assert_eq(same.source, "cache", "a resolve of the name after the reverse is a cache hit on it")
        t:assert_eq(texts(same), texts(r), "… with the same records")
        local again = ask({ query = "reverse", address = "10.77.0.99" })
        t:assert_eq(again.source, "cache", "a reverse again is a cache hit, as a resolve without no_cache is")

        r = ask({ query = "reverse", address = V6 })
        t:log("reverse " .. V6 .. ": " .. show(r))
        t:assert_eq(r.outcome, "found", "IPv6: found")
        t:assert_eq(r.records[1].name, V6_PTR, "IPv6: the 32 nibbles, reversed, lower-case hex, under ip6.arpa")
        t:assert_eq(r.records[1].text, "v6host.example.test", "IPv6: the PTR's target")
        t:assert_eq(#asked(V6_PTR, 12), 1, "IPv6: one PTR question upstream")

        for _, bad in ipairs({ "not-an-address", "10.77.0.256", "fe80::1%eth0", "" }) do
            local e = ask({ query = "reverse", address = bad })
            t:log(string.format("reverse %q: %s", tostring(bad), show(e)))
            t:assert_eq(e.ok, false, tostring(bad) .. ": an error reply")
            t:assert_eq(e.error, "missing or malformed field address", tostring(bad) .. ": the error")
        end
        local e = ask({ query = "reverse" })
        t:log("reverse with no address: " .. show(e))
        t:assert_eq(e.error, "missing or malformed field address", "no address: the same error")
    end)

test("an unknown query is answered with an error reply, and resolv takes an error reply as not answered, never as notfound",
    { spec = "PSPU *nri-requests.unknown-query-answered-with-error PSPU *nri-requests.client-treats-error-as-not-answered" }, function(t)
        ready(t)
        for _, name in ipairs({ "bogus", "Resolve", "subscribe" }) do
            local r, body = ask({ query = name })
            local m = typed(body, 1)
            t:log(string.format("query %q: keys %s, %s", name, keyset(m), show(r)))
            t:assert_eq(keyset(m), "error,ok", name .. ": an error reply, {ok, error}")
            t:assert_eq(r.ok, false, name .. ": ok false")
            t:assert_eq(r.error, string.format("unknown query %q", name), name .. ": names the query")
        end

        -- An error on a question: a descriptor that grants SYSTEM only the
        -- control right, so every question is `access denied`.
        local RESOLVER_CONTROL = 0x2
        local ok, err = pcall(function()
            network.write(sut, "Dns", { ControlSecurity = "hex:" .. peinit.system_descriptor_hex(RESOLVER_CONTROL) })
            local r
            t:assert(wait_until(function()
                r = network.call(sut, { query = "resolve", name = "r10.example.test", type = 1 }, { path = SOCK })
                return r ~= nil and r.ok == false
            end, { timeout = 15, interval = 0.3, desc = "the question denied" }), "the descriptor is in force")
            t:assert_eq(r.error, "access denied", "the question is refused with an error reply")

            for _, cmd in ipairs({ "resolv query r10.example.test A", "resolv lookup r10.example.test",
                                   "resolv reverse 10.77.0.99" }) do
                local x = served(cmd)
                t:log(string.format("%s -> exit %s, stdout %q, stderr %q", cmd, tostring(x.exit_code), x.stdout, x.stderr))
                t:assert_eq(x.exit_code, 1, cmd .. ": exits 1 (failure), not 2 (notfound) or 3 (unavailable)")
                t:assert(x.stderr:find("resolv: access denied", 1, true) ~= nil, cmd .. ": reports the error")
                t:assert(x.stdout:find("notfound", 1, true) == nil, cmd .. ": prints no notfound")
            end
            local f = served("resolv flush")
            t:assert_eq(f.exit_code, 0, "flush, a control request, is still allowed: the descriptor is the one written")
        end)
        network.reg(sut, { "del", network.KEY .. [[\Dns]], "ControlSecurity" })
        t:assert(wait_until(function()
            local r = network.call(sut, { query = "status" }, { path = SOCK })
            return r ~= nil and r.ok == true
        end, { timeout = 15, interval = 0.3, desc = "the default descriptor again" }), "ControlSecurity removed")
        if not ok then error(err, 0) end

        -- For contrast, a real absence: exit 2 and `notfound`.
        local x = served("resolv query r10-absent.example.test A")
        t:log(string.format("absent name -> exit %s, stdout %q", tostring(x.exit_code), x.stdout))
        t:assert_eq(x.exit_code, 2, "a notfound answer exits 2")
        t:assert(x.stdout:find("^notfound") ~= nil, "… and says notfound")
    end)
