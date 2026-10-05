-- resolvd §5.3 (`status`, `flush`, and when each request is answered) and
-- PSPU §6.5 (the `status` and `flush` replies).
--
-- Harness: the scripted gateway (helpers.gateway) and its DNS server
-- (helpers.dns), and a whole Peios (helpers.network). The gateway answers
-- DNS on 10.77.0.1 and on a second address, 10.77.0.2, added to its NIC
-- under the alias label eth0:1.
--
-- Own VMs, and the order matters: the lease starts with no DNS servers
-- (option 6 withheld) so the first test sees a scope with none; the
-- second adds `Dns FallbackServers`; the third names the machine and
-- re-arms the DHCP server with both addresses and renews, so the scope
-- gains its servers; the fourth demotes 10.77.0.1 and flushes; the fifth
-- holds a question unanswered; the last stops and starts netd.
--
-- Requests go to the native socket as SYSTEM. Status and flush are read
-- with the gateway idle (they need no upstream); questions are sent and
-- then the gateway is pumped until the reply is whole.
--
-- Non-obvious:
--   * the image's background lookups (`N.time.peios.org`) bump `queries`
--     at any moment; the flush test's counters are compared over a window
--     in which the gateway saw no question at all, and taken again if it
--     did. No zone-wide SOA, so those lookups are never cached and always
--     reach the gateway;
--   * helpers.msgpack drops nil-valued keys and decodes bin as a string, so
--     the shape assertions read the reply with a local typed walker (as
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

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
-- An alias label: SIOCSIFADDR on the interface's own name would replace
-- 10.77.0.1, not add to it.
assert(ntfe.if_addr(gw.vm, gw.ifname .. ":1", "10.77.0.2", 24))
local LEASE = { pool = { "10.77.0.50" }, lease = 3600, options = { { 15, "example.test" } } }
gw:dhcp({ pool = LEASE.pool, lease = LEASE.lease, options = LEASE.options, dns = false })

local function rr(t, data) return { type = t, data = data, ttl = 60 } end

local H = {}
dns.serve(gw, {
    zone = {
        ["fb.example.test"] = { rr("A", "10.77.0.201") },
        ["fl1.example.test"] = { rr("A", "10.77.0.202") },
        ["dm.example.test"] = { rr("A", "10.77.0.203") },
        ["held.example.test"] = { rr("A", "10.77.0.204") },
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

local function open(req)
    local fd = assert(unixsock.socket(sut, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
    local c = unixsock.connect(sut, fd, SOCK)
    assert(c.ret == 0, "connect " .. SOCK .. ": " .. unixsock.errname(c.errno))
    local payload = msgpack.encode(req)
    ntfe.send(sut, fd, string.pack("<I4", #payload) .. payload)
    return { fd = fd, buf = "" }
end

local function poll(st, wait_ms)
    while true do
        local chunk = ntfe.recv(sut, st.fd, wait_ms or 0, 65536)
        if not chunk then return false end
        if #chunk == 0 then st.eof = true; return true end
        st.buf = st.buf .. chunk
        if #st.buf >= 4 then
            local n = string.unpack("<I4", st.buf)
            if #st.buf >= 4 + n then st.body = st.buf:sub(5, 4 + n); return true end
        end
    end
end

--- A question: send, pump the gateway until the reply is whole.
local function ask(req)
    local st = open(req)
    gw:serve({ timeout = 20, until_ = function() return poll(st) end })
    sys.close(sut, st.fd)
    assert(st.body, "no reply from resolvd to " .. tostring(req.query) .. " " .. tostring(req.name))
    return msgpack.decode(st.body), st.body
end

--- A request that needs no upstream, the gateway left idle: the decoded
--- reply and its raw body.
local function call(req)
    local st = open(req)
    local deadline = clock() + 5
    while not poll(st, 200) and clock() < deadline do end
    sys.close(sut, st.fd)
    assert(st.body, "no reply from resolvd to " .. tostring(req.query))
    return msgpack.decode(st.body), st.body
end

local function rstatus() return (call({ query = "status" })) end

local function scope_of(s, name)
    for _, sc in ipairs(s.scopes or {}) do
        if sc.interface == name then return sc end
    end
end

--- Pump the gateway until `pred(status)` holds; the status, or nil.
local function wait_status(pred, timeout)
    local last
    local ok = gw:serve({ timeout = timeout or 60, until_ = function()
        local s = network.call(sut, { query = "status" }, { path = SOCK, timeout_ms = 2000 })
        if not (s and s.ok) then return false end
        last = s
        return pred(s) and true or false
    end })
    return ok and last or nil, last
end

local function list(l) return table.concat(l or {}, ",") end

local diag   -- below

--- Wait for eth0's scope to have both servers (the third test gives
--- them).
local function servers_up(t)
    local s = wait_status(function(s)
        local sc = scope_of(s, "eth0")
        return sc ~= nil and list(sc.servers) == "10.77.0.1,10.77.0.2"
    end)
    if not s then diag(t, "servers") end
    t:assert(s, "eth0's scope has servers 10.77.0.1 and 10.77.0.2")
    return s
end

local function resolve(name, extra)
    local req = { query = "resolve", name = name, type = 1 }
    for k, v in pairs(extra or {}) do req[k] = v end
    return ask(req)
end

local function asked(name)
    return dns.queries(gw, function(e)
        local qn = e.msg and e.msg.questions[1]
        return e.transport == "udp" and qn ~= nil and dns.same_name(qn.name, name)
    end)
end

local function show(r)
    local recs = {}
    for _, x in ipairs(r.records or {}) do recs[#recs + 1] = tostring(x.text) end
    return string.format("ok=%s outcome=%s source=%s server=%s interface=%s records=[%s] error=%s",
        tostring(r.ok), tostring(r.outcome), tostring(r.source), tostring(r.server), tostring(r.interface),
        table.concat(recs, " "), tostring(r.error))
end

--- resolvd's log lines, newest first (`resolvd: <level>: <message>`).
local function logs(since)
    local r = sut:run(string.format("evctl 'LOGS FROM resolvd SINCE %s TAKE 400'", since or "10m ago"))
    local out = {}
    for line in r.stdout:gmatch("[^\n]+") do
        local msg = line:match('message="(.-)"  origin=')
        if msg then out[#out + 1] = (msg:gsub('\\"', '"')) end
    end
    return out
end

local function count_logged(text, since)
    local n = 0
    for _, l in ipairs(logs(since)) do if l == text then n = n + 1 end end
    return n
end

--- Log what the machine and the gateway are doing, for a failure to
--- explain itself.
function diag(t, what)
    local l = logs("2m ago")
    for i = math.min(#l, 12), 1, -1 do t:log(what .. " resolvd log: " .. l[i]) end
    local i = network.iface(network.status(sut), "eth0")
    t:log(string.format("%s netd eth0: lease %s, addresses [%s], dns [%s]", what,
        tostring(i and i.lease and i.lease.state), list(i and i.addresses), list(i and i.dns)))
    local frames, ports = gw.seen, {}
    for k = math.max(1, #frames - 30), #frames do
        local f = frames[k]
        ports[#ports + 1] = string.format("%s@%s", f.udp and tostring(f.udp.dport) or tostring(f.ethertype), tostring(f.at))
    end
    t:log(what .. " gateway: " .. #frames .. " frames seen; last: " .. table.concat(ports, " "))
    t:log(what .. " gateway dns questions: " .. #dns.queries(gw))
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

local function sorted(l)
    local c = {}
    for i, v in ipairs(l or {}) do c[i] = v end
    table.sort(c)
    return table.concat(c, ",")
end

local COUNTERS = { "queries", "synthetic", "cache_hits", "upstream_sent", "upstream_answered", "upstream_failed", "refused" }

-- ---------------------------------------------------------------------------
-- Tests
-- ---------------------------------------------------------------------------

test("status: every scope in the snapshot, one with no servers that takes no part in routing included; subnets are the interface's own addresses; no level; the fields' types; an empty hostname when there is none",
    { spec = "resolvd *native-requests.status-scopes-every-scope resolvd *native-requests.status-subnets-are-interface-addresses resolvd *native-requests.status-level-not-reported PSPU *nri-requests.status-scopes PSPU *nri-requests.status-counters" }, function(t)
        local s = wait_status(function(s)
            local sc = scope_of(s, "eth0")
            for _, a in ipairs(sc and sc.subnets or {}) do
                if a == "10.77.0.50/24" then return true end
            end
            return false
        end)
        t:assert(s, "resolvd's status shows eth0's scope with the leased address")
        local _, body = call({ query = "status" })
        local m = typed(body, 1)
        t:log("status keys: " .. keyset(m))
        t:assert_eq(keyset(m), "cache_entries,counters,fallback_servers,hostname,kind,netd,ok,scopes", "the status reply's keys")
        local want = { ok = "bool", kind = "str", hostname = "str", netd = "bool", scopes = "array",
                       fallback_servers = "array", cache_entries = "uint", counters = "map" }
        for k, ty in pairs(want) do t:assert_eq(m.v[k].t, ty, k .. " is " .. ty) end
        t:assert_eq(m.v.kind.v, "status", "kind status")
        t:assert_eq(m.v.hostname.v, "", "no hostname yet: an empty string")
        t:assert_eq(keyset(m.v.counters), "cache_hits,queries,refused,synthetic,upstream_answered,upstream_failed,upstream_sent",
            "counters: the seven counters")
        for _, k in ipairs(COUNTERS) do t:assert_eq(m.v.counters.v[k].t, "uint", "counters." .. k .. " is a uint") end

        t:assert_eq(#m.v.scopes.v, 1, "one scope: eth0's, the one in the snapshot")
        local sc = m.v.scopes.v[1]
        t:log("scope keys: " .. keyset(sc))
        t:assert_eq(keyset(sc), "default_route,demoted,domains,exclusive,interface,metric,servers,subnets",
            "a scope's keys; its level is not among them")
        local swant = { interface = "str", servers = "array", domains = "array", default_route = "bool",
                        exclusive = "bool", metric = "uint", subnets = "array", demoted = "array" }
        for k, ty in pairs(swant) do t:assert_eq(sc.v[k].t, ty, "scope." .. k .. " is " .. ty) end
        for _, k in ipairs({ "servers", "domains", "subnets", "demoted" }) do
            for i, x in ipairs(sc.v[k].v) do t:assert_eq(x.t, "str", "scope." .. k .. "[" .. i .. "] is a string") end
        end
        t:assert_eq(sc.v.interface.v, "eth0", "the scope is eth0's")
        t:assert_eq(#sc.v.servers.v, 0, "the lease gave no servers: the scope has none, and is still listed")
        t:assert_eq(#sc.v.domains.v, 1, "one domain")
        t:assert_eq(sc.v.domains.v[1].v, "example.test", "the lease's domain")

        -- Subnets: the interface's own addresses, as netd reports them.
        local subnets = {}
        for i, x in ipairs(sc.v.subnets.v) do subnets[i] = x.v end
        local eth0 = network.iface(network.status(sut), "eth0")
        t:log("resolvd subnets: " .. sorted(subnets) .. "; netd addresses: " .. sorted(eth0.addresses))
        t:assert_eq(sorted(subnets), sorted(eth0.addresses), "subnets are exactly the interface's addresses")
        local has, net = false, false
        for _, a in ipairs(subnets) do
            if a == "10.77.0.50/24" then has = true end
            if a == "10.77.0.0/24" then net = true end
        end
        t:assert(has, "10.77.0.50/24: the address itself")
        t:assert(not net, "not 10.77.0.0/24, the network it is in")

        -- The serverless scope takes no part in routing: with no fallback,
        -- a question is unavailable and nothing is asked.
        local r = resolve("nr.example.test")
        gw:serve({ timeout = 1 })
        t:log("question with no servers anywhere: " .. show(r))
        t:assert_eq(r.outcome, "unavailable", "no routable scope: unavailable")
        t:assert_eq(#asked("nr.example.test"), 0, "nothing was asked upstream")
    end)

test("status fallback_servers: FallbackServers as parsed — trimmed, in canonical form, malformed strings dropped",
    { spec = "resolvd *native-requests.status-fallback-servers PSPU *nri-requests.status-fallback-servers" }, function(t)
        t:assert_eq(list(rstatus().fallback_servers), "", "none configured: an empty list")
        network.write(sut, "Dns", { FallbackServers = "multi: 10.77.0.1 ,fd77:0:0::1,not-an-address" })
        local s = wait_status(function(s) return #(s.fallback_servers or {}) > 0 end, 20)
        t:assert(s, "the fallback servers appear in status")
        t:log("fallback_servers: " .. list(s.fallback_servers) .. "; registry: "
            .. tostring(network.get(sut, "Dns", "FallbackServers")))
        t:assert_eq(list(s.fallback_servers), "10.77.0.1,fd77::1", "the two addresses, as parsed; the malformed string dropped")

        -- They are the servers in use: eth0 has none, so the fallback
        -- scope answers, and its answer is cached.
        local r = resolve("fb.example.test")
        t:log("via the fallback servers: " .. show(r))
        if r.source ~= "dns" then diag(t, "fallback") end
        t:assert_eq(r.source, "dns", "answered by a fallback server")
        t:assert_eq(r.server, "10.77.0.1", "… the first one")
        r = resolve("fb.example.test")
        t:assert_eq(r.source, "cache", "the fallback scope's answer is in the cache")
    end)

test("status hostname: the hostname in use, as the resolver knows it; servers from a renewed lease appear in the scope",
    { spec = "resolvd *native-requests.status-hostname PSPU *nri-requests.status-hostname" }, function(t)
        t:assert_eq(rstatus().hostname, "", "no name from netd or the kernel: an empty string")
        network.write(sut, network.KEY, { Hostname = "sz:r9-host" })
        local s = wait_status(function(s) return s.hostname ~= "" end, 20)
        local kernel = (sut:read_file("/proc/sys/kernel/hostname"):gsub("%s+$", ""))
        t:log("status hostname: " .. tostring(s and s.hostname) .. "; kernel: " .. kernel)
        t:assert(s, "a hostname appears")
        t:assert_eq(s.hostname, "r9-host", "the name netd set")
        t:assert_eq(kernel, "r9-host", "… the machine's name")

        -- Servers for the rest of the file.
        gw:dhcp({ pool = LEASE.pool, lease = LEASE.lease, options = LEASE.options, dns = { "10.77.0.1", "10.77.0.2" } })
        local rn = network.call(sut, { query = "renew", interface = "eth0" })
        t:assert(rn and rn.ok, "netd renews")
        s = servers_up(t)
        t:assert_eq(s.hostname, "r9-host", "the name is kept across the new snapshot")
    end)

test("status demoted lists the scope's servers demoted now; flush empties the cache of every scope, logs `cache flushed`, replies {ok: true} alone, and leaves demotions and counters",
    { spec = "resolvd *native-requests.status-demoted-servers resolvd *native-requests.flush-discards-everything resolvd *native-requests.flush-keeps-demotions-and-counters PSPU *nri-requests.flush-drops-every-cached-answer PSPU *nri-requests.status-cache-entries" }, function(t)
        servers_up(t)
        t:assert_eq(list(scope_of(rstatus(), "eth0").demoted), "", "no server demoted yet")

        -- 10.77.0.1 answers dm.example.test with SERVFAIL; 10.77.0.2 answers.
        H["dm.example.test"] = function(q, d, ctx)
            if ctx.server == "10.77.0.1" then
                local r = {}
                for k, v in pairs(d) do r[k] = v end
                r.answers, r.authority, r.rcode = {}, {}, dns.RCODE.SERVFAIL
                return r
            end
        end
        local r = resolve("dm.example.test")
        t:log("dm: " .. show(r))
        t:assert_eq(r.server, "10.77.0.2", "the second server answered after the first failed")
        local s = rstatus()
        local sc = scope_of(s, "eth0")
        t:log("demoted: " .. list(sc.demoted) .. " of servers " .. list(sc.servers))
        t:assert_eq(list(sc.demoted), "10.77.0.1", "demoted: the failed server, and only it")

        local logged_before = count_logged("resolvd: info: cache flushed")
        local before, after, flush_body, window
        for try = 1, 4 do
            r = resolve("fl1.example.test")
            t:assert(r.source == "dns" or r.source == "cache", "fl1 answered")
            t:assert_eq(resolve("fl1.example.test").source, "cache", "fl1 is cached")
            -- Back to back with the gateway idle, so no reply lands between.
            local t0 = clock()
            before = rstatus()
            local f
            f, flush_body = call({ query = "flush" })
            after = rstatus()
            gw:serve({ timeout = 1 })
            local inside = dns.queries(gw, function(e) return e.at >= t0 end)
            t:log(string.format("window %d: cache_entries %d -> %d; questions at the gateway in the window: %d",
                try, before.cache_entries, after.cache_entries, #inside))
            t:assert_eq(f.ok, true, "flush: ok")
            if #inside == 0 then window = try; break end
        end
        t:assert(window, "a quiet window was found")
        if window == 1 then
            -- fb.example.test (the fallback scope), fl1 and dm (eth0's).
            t:assert(before.cache_entries >= 3, "before: entries in the fallback scope and in eth0's")
        end
        t:assert(before.cache_entries >= 1, "before: the cache held entries")
        t:assert_eq(after.cache_entries, 0, "after: none, in any scope")

        local m = typed(flush_body, 1)
        t:assert_eq(keyset(m), "ok", "the flush reply is {ok} alone, no kind")
        t:assert_eq(m.v.ok.v, true, "ok is true")

        for _, k in ipairs(COUNTERS) do
            t:assert_eq(after.counters[k], before.counters[k], "counters." .. k .. " unchanged by the flush")
        end
        t:assert_eq(list(scope_of(after, "eth0").demoted), "10.77.0.1", "the demotion survives the flush")

        t:assert(wait_until(function() return count_logged("resolvd: info: cache flushed") > logged_before end,
            { timeout = 10, interval = 0.5, desc = "the log line" }), "`cache flushed` logged at info level")

        local n = #asked("fl1.example.test")
        r = resolve("fl1.example.test")
        t:log("fl1 after the flush: " .. show(r))
        t:assert_eq(r.source, "dns", "the flushed answer is gone: asked upstream again")
        t:assert_eq(#asked("fl1.example.test"), n + 1, "… one new question")
    end)

test("status and flush are answered at once while a question is held; the question's connection gets its reply only when the engine has an answer",
    { spec = "resolvd *native-requests.status-and-flush-answered-at-once resolvd *native-requests.questions-held-until-answered" }, function(t)
        servers_up(t)
        -- Sent with the gateway idle: its server answers nothing until pumped.
        local st = open({ query = "resolve", name = "held.example.test", type = 1 })
        local early = poll(st, 800)
        t:assert(not early and st.buf == "", "no reply to the question while nothing has answered it")

        local c0 = clock()
        local s = network.call(sut, { query = "status" }, { path = SOCK, timeout_ms = 3000 })
        local took_s = clock() - c0
        c0 = clock()
        local f = network.call(sut, { query = "flush" }, { path = SOCK, timeout_ms = 3000 })
        local took_f = clock() - c0
        t:log(string.format("status in %.3f s, flush in %.3f s, with the question outstanding", took_s, took_f))
        t:assert(s and s.ok and s.kind == "status", "status is answered")
        t:assert(took_s < 1, "status is answered at once, not after the question")
        t:assert(f and f.ok == true, "flush is answered")
        t:assert(took_f < 1, "flush is answered at once")
        t:assert(not poll(st, 200) and st.buf == "", "the question's connection is still waiting")

        t:assert(gw:serve({ timeout = 20, until_ = function() return poll(st) end }), "a reply once the gateway answers")
        sys.close(sut, st.fd)
        local r = msgpack.decode(st.body)
        t:log("held question: " .. show(r) .. "; questions upstream " .. #asked("held.example.test"))
        t:assert(#asked("held.example.test") >= 1, "the question went upstream")
        t:assert_eq(r.outcome, "found", "the reply is the engine's answer")
        t:assert_eq(r.records and r.records[1] and r.records[1].text, "10.77.0.204", "… with the record")
    end)

test("status netd says whether the netd channel is connected at this moment",
    { spec = "resolvd *native-requests.status-netd PSPU *nri-requests.status-netd-connected" }, function(t)
        t:assert_eq(rstatus().netd, true, "netd running: connected")
        sut:run("svctl stop netd"):assert_ok()
        local s = wait_status(function(s) return s.netd == false end, 20)
        t:assert(s, "netd stopped: status says not connected")
        sut:run("svctl start netd"):assert_ok()
        s = wait_status(function(s) return s.netd == true end, 40)
        t:assert(s, "netd started again: connected again")
    end)
