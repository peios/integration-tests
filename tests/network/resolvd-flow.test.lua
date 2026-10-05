-- resolvd §4.1 — how a question is answered: the path every task takes
-- (parse, synthetic names, candidates, routing, cache, network, the next
-- candidate), what each way out reports, the fallback scope's missing
-- interface, validation, and questions whose asker has gone; with PSPU
-- §6.6, the three outcomes and validation.
--
-- Harness: the scripted gateway (helpers.gateway) and its DNS server
-- (helpers.dns). Questions go to resolvd's native socket from the agent
-- while the gateway pumps (`ask`); the stub door (127.0.0.53) and the NSS
-- shim (through `ping`, which prints getaddrinfo's error) are asked from
-- the guest for the "at any door" requirements. A per-name hook makes
-- the server silent, late, or AD-setting for chosen names, and counts
-- the questions each name got.
--
-- The machine's DNS configuration is changed from the lease: the gateway
-- first leases with no DNS server and no domain (nothing can be routed,
-- and a single label has no candidate), then is re-armed with a server,
-- then with two search domains (option 119), each time followed by a
-- `renew`, which brings the new lease and a new snapshot. Last the
-- servers are taken away again mid-question, and `FallbackServers`
-- gives the fallback scope.
--
-- Not here: candidates going to different scopes (two interfaces) is
-- resolvd-flow-scopes.test.lua; the in-flight ceiling row is
-- resolvd-counters-ceiling.test.lua.
--
-- helpers.msgpack drops a map entry whose value is nil, so a nil
-- `server` or `interface` reads as absent; that is what is asserted.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local unixsock = require("helpers.unixsock")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")
local msgpack = require("helpers.msgpack")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600, dns = false })

-- Per-name behaviour: behave[name] = function(n, q, default, ctx), where
-- n counts the questions that name has had (both transports).
local behave, counts = {}, {}
local function key(name) return (name:lower():gsub("%.$", "")) end
local function silent() return false end
dns.serve(gw, {
    zone = {
        ["www.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.80" } },
        ["host.two.test"] = { { type = "A", ttl = 60, data = "10.77.0.90" } },
        ["fb.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.91" } },
        ["late.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.92" } },
        ["late2.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.93" } },
        ["signed.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.94" } },
        ["back.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.95" } },
        ["."] = { { type = "NS", ttl = 60, data = "a.root-servers.test" } },
    },
    soa = { name = "test", data = { minimum = 30 } },
    on = function(q, default, ctx)
        local qn = q.questions[1]
        if not qn then return nil end
        local k = key(qn.name)
        counts[k] = (counts[k] or 0) + 1
        local b = behave[k]
        if b then return b(counts[k], q, default, ctx) end
        return nil
    end,
})
local sut = network.boot({ bridges = { lan }, gateway = gw })

local SOCK = "/run/resolvd/resolv.sock"
local T = dns.TYPE

-- ---- resolvd -----------------------------------------------------------

--- Open a native connection and send `req`. Returns a handle whose
--- `poll()` reads what has arrived and is true once the reply is whole.
local function send_native(req)
    local fd = assert(unixsock.socket(sut, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
    local c = unixsock.connect(sut, fd, SOCK)
    assert(c.ret == 0, "connect: " .. unixsock.errname(c.errno))
    local p = msgpack.encode(req)
    ntfe.send(sut, fd, string.pack("<I4", #p) .. p)
    local h = { fd = fd, buf = "", req = req }
    function h.poll()
        if h.reply then return true end
        local chunk = ntfe.recv(sut, fd, 30, 65536)
        if chunk and #chunk > 0 then h.buf = h.buf .. chunk end
        if #h.buf >= 4 then
            local len = string.unpack("<I4", h.buf)
            if #h.buf >= 4 + len then
                h.reply = msgpack.decode(h.buf:sub(5, 4 + len))
                return true
            end
        end
        return false
    end
    return h
end

--- Pump the gateway until `h`'s reply is whole; close it; return it.
local function finish(h, timeout)
    if not h.poll() then gw:serve({ timeout = timeout or 20, until_ = h.poll }) end
    sys.close(sut, h.fd)
    assert(h.reply, "resolvd gave no reply to " .. tostring(h.req.query) .. " "
        .. tostring(h.req.name or h.req.address))
    return h.reply
end

local function ask(req, timeout) return finish(send_native(req), timeout) end

local function resolve(name, rtype, no_cache)
    return ask({ query = "resolve", name = name, type = rtype or T.A, no_cache = no_cache })
end

--- resolvd's status, without pumping (it is answered at once).
local function rstatus()
    local s, err = network.call(sut, { query = "status" }, { path = SOCK })
    assert(s and s.ok, "resolvd status: " .. tostring(err or (s and s.error)))
    return s
end

--- Pump until `pred(status)` holds.
local function serve_until_r(t, pred, what, timeout)
    local ok = gw:serve({ timeout = timeout or 20, until_ = function() return pred(rstatus()) end })
    t:assert(ok, what)
end

local function texts(r)
    local out = {}
    for _, rec in ipairs(r.records or {}) do
        out[#out + 1] = (dns.TYPE_NAME[rec.type] or tostring(rec.type)) .. " " .. tostring(rec.text)
    end
    return table.concat(out, ", ")
end

--- Assert every reported field of an answer. `want` = {outcome, source,
--- server, interface, rcode, records (texts)}; server and interface nil
--- mean absent.
local function report(t, r, want, what)
    t:log(string.format("%s: %s source=%s server=%s interface=%s rcode=%s validation=%s [%s]", what,
        tostring(r.outcome), tostring(r.source), tostring(r.server), tostring(r.interface),
        tostring(r.rcode), tostring(r.validation), texts(r)))
    t:assert(r.ok and r.kind == "answer", what .. ": an answer (" .. tostring(r.error) .. ")")
    t:assert_eq(r.outcome, want[1], what .. ": outcome")
    t:assert_eq(r.source, want[2], what .. ": source")
    t:assert_eq(r.server, want[3], what .. ": server")
    t:assert_eq(r.interface, want[4], what .. ": interface")
    t:assert_eq(r.rcode, want[5], what .. ": rcode")
    t:assert_eq(r.validation, "unvalidated", what .. ": validation")
    if want[6] then t:assert_eq(texts(r), want[6], what .. ": records") end
end

--- resolvd's log, newest first (`resolvd: <level>: <message>`).
local function rlogs()
    local r = sut:run("evctl 'LOGS FROM resolvd SINCE 30m ago TAKE 1000'")
    local out = {}
    for line in r.stdout:gmatch("[^\n]+") do
        local msg = line:match('message="(.-)"  origin=')
        if msg then out[#out + 1] = (msg:gsub('\\"', '"')) end
    end
    return out
end

local function count_lines(lines, text)
    local n = 0
    for _, l in ipairs(lines) do if l:find(text, 1, true) then n = n + 1 end end
    return n
end

-- ---- the gateway's view ----------------------------------------------------

local function asked(name, rtype)
    return dns.queries(gw, function(q)
        local qn = q.msg and q.msg.questions[1]
        return qn ~= nil and dns.same_name(qn.name, name) and (not rtype or qn.type == rtype)
    end)
end

local function port53_frames()
    return gw:frames(function(f) return f.udp ~= nil and f.udp.dport == 53 end)
end

local markers = 0
local function marker(t)
    markers = markers + 1
    local name = "marker" .. markers .. ".example.test"
    local r = resolve(name, T.A, true)
    t:assert(r.source == "dns" and #asked(name) >= 1, "the marker " .. name .. " went upstream")
end

-- ---- the guest's other doors ---------------------------------------------

local function stub(name, rtype, o)
    o = o or {}
    local fd = assert(ntfe.udp_connect(sut, "127.0.0.53", 53))
    local q = dns.query(name, rtype or "A", { id = math.random(1, 0xFFFF), edns = o.edns })
    q.ad = o.ad
    ntfe.send(sut, fd, dns.encode(q))
    local got = ntfe.recv(sut, fd, 50, 4096)
    if not got then
        gw:serve({ timeout = o.timeout or 15, until_ = function()
            got = ntfe.recv(sut, fd, 30, 4096)
            return got ~= nil
        end })
    end
    sys.close(sut, fd)
    assert(got, "no stub reply for " .. name)
    return assert(dns.decode(got))
end

--- Run `cmd` in the guest while the gateway pumps.
local function served(cmd, timeout)
    local p = sut:run_async("sh", { args = { "-c", cmd } })
    gw:serve({ timeout = timeout or 20, until_ = function() return p:status() == "exited" end })
    return p:wait(5)
end

--- Re-arm the gateway's DHCP with `o` over the defaults and renew.
local function relese(o)
    local d = { pool = { "10.77.0.50" }, lease = 3600 }
    for k, v in pairs(o or {}) do d[k] = v end
    gw:dhcp(d)
    local r = network.call(sut, { query = "renew", interface = "eth0" })
    assert(r and r.ok, "renew: " .. tostring(r and r.error))
end

local function eth0(s)
    for _, sc in ipairs(s.scopes or {}) do if sc.interface == "eth0" then return sc end end
end

local DOMAINS = { { 119, gateway.opt.names({ "one.test", "two.test" }) } }

-- ---------------------------------------------------------------------------
-- No server anywhere, no search domain.

test("a candidate no scope can take is answered unavailable, source local, no server, no interface, rcode 0",
    { spec = "resolvd *engine-flow.unroutable-candidate-is-unavailable resolvd *engine-flow.report-unroutable" },
    function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound")
        serve_until_r(t, function(s) return eth0(s) ~= nil end, "resolvd has eth0's scope")
        local s = rstatus()
        t:log(string.format("eth0: %d servers, %d domains; %d fallback servers", #eth0(s).servers,
            #eth0(s).domains, #s.fallback_servers))
        t:assert(#eth0(s).servers == 0 and #s.fallback_servers == 0, "no server anywhere")
        report(t, resolve("www.example.test", T.A), { "unavailable", "local", nil, nil, 0 }, "www.example.test A")
        report(t, resolve("a.b.c.example.test", T.MX), { "unavailable", "local", nil, nil, 0 }, "a.b.c.example.test MX")
        report(t, ask({ query = "reverse", address = "192.0.2.1" }), { "unavailable", "local", nil, nil, 0 },
            "reverse 192.0.2.1")
        gw:serve({ timeout = 1 })
        t:assert_eq(#port53_frames(), 0, "nothing was sent to any DNS server")
    end)

test("unavailable is never reported as notfound, at the native socket, the stub door or the NSS shim",
    { spec = "PSPU *nri-outcomes.unavailable-never-reported-as-notfound" }, function(t)
        report(t, resolve("www.example.test", T.A), { "unavailable", "local", nil, nil, 0 }, "native resolve")
        local l = ask({ query = "lookup", name = "www.example.test" })
        t:log("native lookup: " .. tostring(l.outcome))
        t:assert_eq(l.outcome, "unavailable", "native lookup: unavailable")
        local s = stub("www.example.test", "A")
        t:log("stub: rcode " .. s.rcode)
        t:assert_eq(s.rcode, dns.RCODE.SERVFAIL, "stub door: SERVFAIL, not NXDOMAIN")
        local p = served("ping -c 1 -W 1 www.example.test 2>&1")
        t:log("ping www.example.test: " .. p.stdout)
        t:assert(p.stdout:find("Temporary failure in name resolution", 1, true),
            "NSS shim: getaddrinfo says EAI_AGAIN, not that the name is unknown")
        -- The control: a name that is authoritatively absent reads differently.
        local n = served("ping -c 1 -W 1 lonely 2>&1")
        t:log("ping lonely (a single label with no domain: notfound): " .. n.stdout)
        t:assert(n.stdout:find("Name or service not known", 1, true), "the notfound control reads as unknown")
    end)

test("a name that does not parse is notfound at once: source local, no server, no interface, rcode 0",
    { spec = "resolvd *engine-flow.unparseable-name-is-notfound resolvd *engine-flow.report-unparseable" },
    function(t)
        local l63, l64 = string.rep("a", 63), string.rep("b", 64)
        local bad = {
            "a..example.test", ".example.test", "example.test..",
            l64 .. ".example.test",
            table.concat({ l63, l63, l63, l63 }, "."),   -- 257 bytes on the wire
        }
        for _, name in ipairs(bad) do
            report(t, resolve(name, T.A), { "notfound", "local", nil, nil, 0, "" }, #name .. "-byte " .. name:sub(1, 20))
        end
        local l = ask({ query = "lookup", name = "a..example.test" })
        t:assert_eq(l.outcome, "notfound", "lookup of a name that does not parse: notfound")
        -- The boundaries parse, reach routing, and find nothing to route to.
        local fits = table.concat({ l63, l63, l63, string.rep("c", 61) }, ".")   -- 255 bytes
        report(t, resolve(l63 .. ".example.test", T.A), { "unavailable", "local", nil, nil, 0 }, "a 63-byte label")
        report(t, resolve(fits, T.A), { "unavailable", "local", nil, nil, 0 }, "a 255-byte name")
    end)

test("a single label with no applicable search domain has no candidates: notfound, source local, no server, no interface, rcode 0",
    { spec = "resolvd *engine-flow.no-candidates-is-notfound resolvd *engine-flow.report-no-candidates" },
    function(t)
        local s = rstatus()
        t:assert(#eth0(s).domains == 0, "no search domain anywhere")
        report(t, resolve("printer", T.A), { "notfound", "local", nil, nil, 0, "" }, "printer")
        report(t, resolve("Printer.", T.AAAA), { "notfound", "local", nil, nil, 0, "" }, "Printer.")
        -- With no server either, a name that had candidates would be
        -- unavailable: this one never reached routing.
        report(t, resolve("printer.example.test", T.A), { "unavailable", "local", nil, nil, 0 }, "a two-label name, for contrast")
    end)

-- ---------------------------------------------------------------------------
-- A server.

test("a server's reply reports dns, the server, the scope's interface and the server's response code; NODATA is found",
    { spec = "resolvd *engine-flow.report-server-reply PSPU *nri-outcomes.nodata-is-found" }, function(t)
        relese({})
        serve_until_r(t, function(s) return eth0(s) and #eth0(s).servers == 1 end, "eth0's scope gets the server")
        report(t, resolve("www.example.test", T.A), { "found", "dns", "10.77.0.1", "eth0", 0, "A 10.77.0.80" },
            "www.example.test A")
        report(t, resolve("nx.example.test", T.A), { "notfound", "dns", "10.77.0.1", "eth0", 3, "" }, "nx.example.test A")
        report(t, resolve("www.example.test", T.AAAA), { "found", "dns", "10.77.0.1", "eth0", 0, "" },
            "www.example.test AAAA: the name exists without the type")
        local s = stub("www.example.test", "MX")
        t:log(string.format("stub MX: rcode %d, %d answers", s.rcode, #s.answers))
        t:assert_eq(s.rcode, dns.RCODE.NOERROR, "the stub door renders NODATA as NOERROR")
        t:assert_eq(#s.answers, 0, "with no answer")
    end)

test("notfound is authoritative absence: an NXDOMAIN, a single label with no domain to apply, or a name under .local",
    { spec = "PSPU *nri-outcomes.notfound-is-authoritative-absence" }, function(t)
        t:assert_eq(#eth0(rstatus()).domains, 0, "no search domain yet")
        report(t, resolve("absent.example.test", T.A), { "notfound", "dns", "10.77.0.1", "eth0", 3, "" },
            "absent.example.test: the server's NXDOMAIN")
        report(t, resolve("lonely", T.A), { "notfound", "local", nil, nil, 0, "" }, "lonely: a single label, no domain")
        report(t, resolve("nas.local", T.A), { "notfound", "synthetic", nil, nil, 0, "" }, "nas.local")
        -- A server that cannot answer is not an absence.
        behave["broken.example.test"] = function(_, _, default)
            default.rcode = dns.RCODE.SERVFAIL
            return default
        end
        report(t, resolve("broken.example.test", T.A), { "unavailable", "local", nil, "eth0", 0, "" },
            "broken.example.test: SERVFAIL from every attempt")
    end)

test("a cache hit reports cache, the server whose reply was cached, the scope's interface and the cached response code",
    { spec = "resolvd *engine-flow.report-cache-hit" }, function(t)
        dns.forget(gw)
        local r = resolve("www.example.test", T.A)
        report(t, r, { "found", "cache", "10.77.0.1", "eth0", 0, "A 10.77.0.80" }, "www.example.test A again")
        t:assert(r.records[1].ttl <= 60, "its TTL is no more than the server's")
        report(t, resolve("nx.example.test", T.A), { "notfound", "cache", "10.77.0.1", "eth0", 3, "" }, "nx.example.test again")
        report(t, resolve("www.example.test", T.AAAA), { "found", "cache", "10.77.0.1", "eth0", 0, "" }, "the NODATA again")
        marker(t)
        t:assert_eq(#asked("www.example.test") + #asked("nx.example.test"), 0, "none of them went upstream")
    end)

-- ---------------------------------------------------------------------------
-- A server and two search domains, one.test then two.test.

test("a notfound for a candidate, from a server or from the cache, moves to the next candidate",
    { spec = "resolvd *engine-flow.notfound-moves-to-next-candidate" }, function(t)
        relese({ options = DOMAINS })
        serve_until_r(t, function(s) return table.concat(eth0(s).domains, " ") == "one.test two.test" end,
            "eth0's scope gets the domains one.test and two.test")
        dns.forget(gw)
        local r = resolve("host", T.A)
        report(t, r, { "found", "dns", "10.77.0.1", "eth0", 0, "A 10.77.0.90" }, "host")
        t:assert_eq(r.records[1].name, "host.two.test", "found at the second candidate")
        local log = dns.queries(gw, function(q) return q.msg and q.msg.questions[1].name:lower():find("^host%.") end)
        local order = {}
        for _, q in ipairs(log) do order[#order + 1] = q.msg.questions[1].name:lower() end
        t:log("asked: " .. table.concat(order, ", "))
        t:assert_eq(table.concat(order, ", "), "host.one.test, host.two.test", "the first candidate's NXDOMAIN moved on to the second")
        -- Again: the first candidate's notfound is now a cache hit, and it moves on too.
        report(t, resolve("host", T.A), { "found", "cache", "10.77.0.1", "eth0", 0, "A 10.77.0.90" }, "host again")
        marker(t)
        t:assert_eq(#log, #dns.queries(gw, function(q) return q.msg and q.msg.questions[1].name:lower():find("^host%.") end),
            "nothing more was asked")
    end)

test("when every candidate is notfound the task is notfound, reported as the last candidate's server reply or cache hit",
    { spec = "resolvd *engine-flow.all-candidates-notfound-is-notfound resolvd *engine-flow.report-all-candidates-notfound" },
    function(t)
        dns.forget(gw)
        report(t, resolve("ghost", T.A), { "notfound", "dns", "10.77.0.1", "eth0", 3, "" }, "ghost: both NXDOMAIN from the server")
        t:assert_eq(#asked("ghost.one.test") + #asked("ghost.two.test"), 2, "both candidates were asked")
        report(t, resolve("ghost", T.A), { "notfound", "cache", "10.77.0.1", "eth0", 3, "" }, "ghost again: both from the cache")
        -- The first candidate from the cache, the last from the server.
        report(t, resolve("ghost2.one.test", T.A), { "notfound", "dns", "10.77.0.1", "eth0", 3, "" }, "ghost2.one.test, to cache it")
        dns.forget(gw)
        report(t, resolve("ghost2", T.A), { "notfound", "dns", "10.77.0.1", "eth0", 3, "" },
            "ghost2: the first candidate cached, the last asked")
        t:assert_eq(#asked("ghost2.one.test"), 0, "the first candidate came from the cache")
        t:assert_eq(#asked("ghost2.two.test"), 1, "the last went to the server")
    end)

test("synthetic names are checked on the name as asked, before candidates: reported synthetic or hosts with no server, interface or rcode",
    { spec = "resolvd *engine-flow.synthetic-check-first resolvd *engine-flow.report-synthetic" }, function(t)
        network.write(sut, "Dns", {})   -- `reg new` makes one level at a time
        network.write(sut, [[Dns\Hosts]], { printer = "sz:10.99.0.2" })
        t:assert(pcall(wait_until, function() return resolve("printer", T.A).source == "hosts" end,
            { timeout = 15, interval = 0.25 }), "the static name printer is applied")
        dns.forget(gw)
        report(t, resolve("printer", T.A), { "found", "hosts", nil, nil, 0, "A 10.99.0.2" }, "printer, a single label")
        report(t, resolve("localhost", T.A), { "found", "synthetic", nil, nil, 0, "A 127.0.0.1" }, "localhost, a single label")
        report(t, resolve("local", T.A), { "notfound", "synthetic", nil, nil, 0, "" }, "local, a single label")
        marker(t)
        for _, n in ipairs({ "printer", "localhost", "local" }) do
            t:assert_eq(#asked(n .. ".one.test") + #asked(n .. ".two.test") + #asked(n), 0, n .. " was not expanded or sent")
        end
        network.delete(sut, [[Dns\Hosts]])
    end)

test("the empty name and . are the root: not expanded, its own one candidate, routed and asked",
    { spec = "resolvd *engine-flow.empty-name-is-root" }, function(t)
        dns.forget(gw)
        report(t, resolve("", T.NS, true), { "found", "dns", "10.77.0.1", "eth0", 0, "NS a.root-servers.test" }, "the empty name, NS")
        report(t, resolve(".", T.NS, true), { "found", "dns", "10.77.0.1", "eth0", 0, "NS a.root-servers.test" }, ". NS")
        local roots = asked(".", T.NS)
        t:assert_eq(#roots, 2, "the root was asked, once for each")
        t:assert_eq(#asked("one.test") + #asked("two.test"), 0, "and never expanded with a search domain")
    end)

test("attempts exhausted is unavailable, source local, no server, the scope's interface, rcode 0; and unavailable is not cached",
    { spec = "resolvd *engine-flow.report-attempts-exhausted PSPU *nri-outcomes.unavailable-never-cached" }, function(t)
        behave["silent.example.test"] = silent
        local before = rstatus().cache_entries
        dns.forget(gw)
        report(t, resolve("silent.example.test", T.A), { "unavailable", "local", nil, "eth0", 0, "" },
            "silent.example.test")
        t:assert_eq(#asked("silent.example.test"), 3, "three attempts went to the server")
        t:assert_eq(rstatus().cache_entries, before, "no cache entry was made")
        local s = stub("silent.example.test", "A", { timeout = 30 })
        t:assert_eq(s.rcode, dns.RCODE.SERVFAIL, "the stub door's answer is SERVFAIL")
        -- The server answers now: the next question goes to it.
        behave["silent.example.test"] = function(_, q) return dns.answer(q, {
            ["silent.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.96" } } }) end
        dns.forget(gw)
        report(t, resolve("silent.example.test", T.A), { "found", "dns", "10.77.0.1", "eth0", 0, "A 10.77.0.96" },
            "silent.example.test once the server answers")
        t:assert_eq(#asked("silent.example.test"), 1, "it was asked again, not taken from a cache")
    end)

test("a scope left with no servers during a question answers unavailable, source local, no server, no interface, rcode 0",
    { spec = "resolvd *engine-flow.report-scope-without-servers" }, function(t)
        behave["dropout.example.test"] = silent
        dns.forget(gw)
        local h = send_native({ query = "resolve", name = "dropout.example.test", type = T.A })
        t:assert(gw:serve({ timeout = 5, until_ = function() return #asked("dropout.example.test") >= 1 end }),
            "the first attempt reached the server")
        relese({ dns = false, options = DOMAINS })
        local r = finish(h, 20)
        local s = rstatus()
        t:log("eth0's servers now: " .. #eth0(s).servers)
        t:assert_eq(#eth0(s).servers, 0, "eth0's scope has lost its server")
        report(t, r, { "unavailable", "local", nil, nil, 0, "" }, "dropout.example.test")
        t:assert_eq(#asked("dropout.example.test"), 1,
            "only the first attempt was sent: the second found no server, so attempts were not exhausted")
    end)

test("an answer through the fallback scope has no interface: a server's reply, a cache hit and exhausted attempts",
    { spec = "resolvd *engine-flow.fallback-scope-has-no-interface" }, function(t)
        network.write(sut, "Dns", { FallbackServers = "sz:10.77.0.1" })
        serve_until_r(t, function(s) return s.fallback_servers[1] == "10.77.0.1" end, "the fallback server is configured")
        report(t, resolve("fb.example.test", T.A), { "found", "dns", "10.77.0.1", nil, 0, "A 10.77.0.91" }, "fb.example.test")
        report(t, resolve("fb.example.test", T.A), { "found", "cache", "10.77.0.1", nil, 0, "A 10.77.0.91" }, "fb.example.test again")
        behave["silent2.example.test"] = silent
        dns.forget(gw)
        report(t, resolve("silent2.example.test", T.A), { "unavailable", "local", nil, nil, 0, "" }, "silent2.example.test")
        t:assert_eq(#asked("silent2.example.test"), 3, "three attempts: exhausted")
    end)

test("a question whose native asker has gone runs to completion, its reply is cached, and the failed write is logged",
    { spec = "resolvd *engine-flow.departed-asker-transactions-continue resolvd *engine-flow.departed-asker-reply-cached resolvd *engine-flow.departed-asker-answer-write-fails" },
    function(t)
        -- PEI-1343: abandoned questions are never cancelled; this asserts
        -- the TRM's present behaviour.
        -- Silent twice, answered at the third attempt.
        local late = function(n) if n < 3 then return false end end
        behave["late.example.test"] = late
        behave["late2.example.test"] = late
        local failed_before = count_lines(rlogs(), "control: reply failed")
        dns.forget(gw)
        local h = send_native({ query = "resolve", name = "late.example.test", type = T.A })
        t:assert(gw:serve({ timeout = 5, until_ = function() return #asked("late.example.test") >= 1 end }),
            "the first attempt went out")
        sys.close(sut, h.fd)
        t:assert(gw:serve({ timeout = 15, until_ = function() return #asked("late.example.test") >= 3 end }),
            "the second and third attempts went out after the asker left")
        local logged = gw:serve({ timeout = 5, until_ = function()
            return count_lines(rlogs(), "control: reply failed") > failed_before
        end })
        for _, l in ipairs(rlogs()) do
            if l:find("control: reply failed", 1, true) then t:log("log: " .. l); break end
        end
        t:assert(logged, "the answer's write failed and was logged")
        dns.forget(gw)
        report(t, resolve("late.example.test", T.A), { "found", "cache", "10.77.0.1", nil, 0, "A 10.77.0.92" },
            "late.example.test, asked again")

        -- A stub TCP client that hangs up: the same, and nothing is logged.
        local lines_before = #rlogs()
        local warn_before = count_lines(rlogs(), "resolvd: warn:")
        local fd = assert(ntfe.tcp_connect(sut, "127.0.0.53", 53, 2000))
        local p = dns.encode(dns.query("late2.example.test", "A", { id = 777 }))
        ntfe.send(sut, fd, string.pack(">I2", #p) .. p)
        t:assert(gw:serve({ timeout = 5, until_ = function() return #asked("late2.example.test") >= 1 end }),
            "the stub question's first attempt went out")
        sys.close(sut, fd)
        t:assert(gw:serve({ timeout = 15, until_ = function() return #asked("late2.example.test") >= 3 end }),
            "its retries went out after the client hung up")
        gw:serve({ timeout = 2 })
        local logs = rlogs()
        t:log(string.format("resolvd log lines: %d before, %d after", lines_before, #logs))
        for i = 1, #logs - lines_before do t:log("new: " .. logs[i]) end
        t:assert_eq(count_lines(logs, "resolvd: warn:"), warn_before, "no warning was logged for the stub client")
        report(t, resolve("late2.example.test", T.A), { "found", "cache", "10.77.0.1", nil, 0, "A 10.77.0.93" },
            "late2.example.test, asked again")
    end)

test("an upstream AD bit is not forwarded, and no stub reply carries AD: resolvd never validates to secure",
    { spec = "PSPU *nri-outcomes.ad-bit-only-when-secure PSPU *nri-outcomes.upstream-ad-not-forwarded" }, function(t)
        local set = 0
        behave["signed.example.test"] = function(_, _, default)
            default.ad = true
            set = set + 1
            return default
        end
        local s = stub("signed.example.test", "A", { ad = true, edns = { udp_size = 1232 } })
        t:log(string.format("stub signed.example.test: rcode %d ad %s, %d answers; upstream replies with AD: %d",
            s.rcode, tostring(s.ad), #s.answers, set))
        t:assert(set >= 1, "the server's reply carried AD")
        t:assert_eq(#s.answers, 1, "the answer came through")
        t:assert_eq(s.ad, false, "the stub reply's AD is clear")
        local again = stub("signed.example.test", "A", { ad = true })
        t:assert_eq(again.ad, false, "from the cache, AD is clear")
        local loc = stub("localhost", "A", { ad = true })
        t:assert_eq(loc.ad, false, "a synthetic answer: AD clear")
        local r = resolve("signed.example.test", T.A)
        t:assert_eq(r.validation, "unvalidated", "its native answer is unvalidated, not secure")
    end)

test("every answer and addresses reply carries validation, and it is unvalidated for every source and outcome",
    { spec = "resolvd *engine-flow.validation-always-unvalidated PSPU *nri-outcomes.every-answer-carries-validation PSPU *nri-outcomes.unvalidated-until-validating" },
    function(t)
        network.write(sut, [[Dns\Hosts]], { printer = "sz:10.99.0.2" })
        t:assert(pcall(wait_until, function() return resolve("printer", T.A).source == "hosts" end,
            { timeout = 15, interval = 0.25 }), "the static name printer is applied")
        local seen = {}
        local function check(r, what)
            t:log(string.format("%s: %s %s %s validation=%s", what, tostring(r.kind), tostring(r.outcome),
                tostring(r.source), tostring(r.validation)))
            t:assert_eq(r.validation, "unvalidated", what .. ": validation")
            seen[r.kind .. "/" .. tostring(r.source) .. "/" .. tostring(r.outcome)] = true
        end
        check(resolve("localhost", T.A), "synthetic")
        check(resolve("printer", T.A), "hosts")
        check(resolve("a..b", T.A), "unparseable")
        check(resolve("back.example.test", T.A), "dns found")
        check(resolve("back.example.test", T.A), "cache found")
        check(resolve("nope.example.test", T.A), "dns notfound")
        check(resolve("nope.example.test", T.A), "cache notfound")
        check(ask({ query = "reverse", address = "127.0.0.1" }), "reverse")
        check(ask({ query = "lookup", name = "back.example.test" }), "lookup from the network")
        check(ask({ query = "lookup", name = "localhost" }), "lookup synthetic")
        check(ask({ query = "lookup", name = "a..b" }), "lookup unparseable")
        -- Take every server away: unavailable.
        network.reg(sut, { "del", network.KEY .. "\\Dns", "FallbackServers" }):assert_ok()
        serve_until_r(t, function(s) return #s.fallback_servers == 0 end, "no fallback server")
        check(resolve("gone.example.test", T.A), "unavailable")
        check(ask({ query = "lookup", name = "gone.example.test" }), "lookup unavailable")
        local kinds = {}
        for k in pairs(seen) do kinds[#kinds + 1] = k end
        table.sort(kinds)
        t:log("covered: " .. table.concat(kinds, " "))
        for _, k in ipairs({ "answer/synthetic/found", "answer/hosts/found", "answer/local/notfound",
            "answer/dns/found", "answer/cache/found", "answer/dns/notfound", "answer/cache/notfound",
            "answer/local/unavailable", "addresses/dns/found", "addresses/synthetic/found",
            "addresses/local/unavailable" }) do
            t:assert(seen[k], "covered " .. k)
        end
    end)
