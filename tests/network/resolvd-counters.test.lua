-- resolvd §4.10 — the counters `status` reports: exactly what moves each
-- one, what is not counted, and what resets them. The `refused` counter
-- needs the in-flight ceiling, which is resolvd-counters-ceiling.test.lua.
--
-- Harness: the scripted gateway (helpers.gateway) leasing 10.77.0.50 with
-- itself as the DNS server and two search domains (option 119), and its
-- DNS server (helpers.dns), which a per-name hook makes truncate,
-- SERVFAIL, stay silent, or first answer with the wrong ID. Questions go
-- to the native socket from the agent while the gateway pumps, and to the
-- stub door from the guest. Each test reads the seven counters before
-- and after and asserts the whole difference, every counter, so a
-- counter that moved when it should not have fails too.
--
-- timed asks for its NTP servers' names through resolvd in the background
-- and would move `queries` and the upstream counters at its own pace, so
-- it is stopped first, and the counters are seen to be still before any
-- test reads a difference.
--
-- Own VMs: the tests stop timed, edit ControlSecurity and
-- FallbackServers, re-lease, and restart resolvd last (stop, clear
-- /run/resolvd, start; see that test).

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local unixsock = require("helpers.unixsock")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")
local msgpack = require("helpers.msgpack")
local kacs = require("helpers.kacs")

peinit.claim(2)

local DOMAINS = { { 119, gateway.opt.names({ "one.test", "two.test" }) } }
local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600, options = DOMAINS })

local big = {}
for i = 1, 40 do big[i] = { type = "A", ttl = 60, data = "10.77.1." .. i } end
local behave, counts = {}, {}
local function key(name) return (name:lower():gsub("%.$", "")) end
dns.serve(gw, {
    zone = {
        ["www.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.80" } },
        ["big.example.test"] = big,
        ["odd.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.81" } },
    },
    soa = { name = "test", data = { minimum = 30 } },
    on = function(q, default, ctx)
        local qn = q.questions[1]
        if not qn then return nil end
        local k = key(qn.name)
        counts[k] = (counts[k] or 0) + 1
        local b = behave[k]
        if b then return b(counts[k], q, default, ctx) end
    end,
})
local sut = network.boot({ bridges = { lan }, gateway = gw })

local SOCK = "/run/resolvd/resolv.sock"
local T = dns.TYPE
local NAMES = { "queries", "synthetic", "cache_hits", "upstream_sent", "upstream_answered", "upstream_failed", "refused" }

-- ---- resolvd -----------------------------------------------------------

local function ask(req, timeout)
    local fd = assert(unixsock.socket(sut, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
    local c = unixsock.connect(sut, fd, SOCK)
    assert(c.ret == 0, "connect: " .. unixsock.errname(c.errno))
    local p = msgpack.encode(req)
    ntfe.send(sut, fd, string.pack("<I4", #p) .. p)
    local buf, reply = "", nil
    local function poll()
        local chunk = ntfe.recv(sut, fd, 30, 65536)
        if chunk and #chunk > 0 then buf = buf .. chunk end
        if #buf >= 4 then
            local len = string.unpack("<I4", buf)
            if #buf >= 4 + len then
                reply = msgpack.decode(buf:sub(5, 4 + len))
                return true
            end
        end
        return false
    end
    if not poll() then gw:serve({ timeout = timeout or 20, until_ = poll }) end
    sys.close(sut, fd)
    assert(reply, "resolvd gave no reply to " .. tostring(req.query) .. " " .. tostring(req.name or req.address))
    return reply
end

local function resolve(name, rtype, no_cache)
    return ask({ query = "resolve", name = name, type = rtype or T.A, no_cache = no_cache })
end

local function rstatus()
    local s, err = network.call(sut, { query = "status" }, { path = SOCK })
    assert(s and s.ok, "resolvd status: " .. tostring(err or (s and s.error)))
    return s
end

local function counters() return rstatus().counters end

local function show(c)
    local parts = {}
    for _, k in ipairs(NAMES) do parts[#parts + 1] = k .. "=" .. tostring(c[k]) end
    return table.concat(parts, " ")
end

--- Assert that every counter moved by exactly `want[k]` (0 when absent).
local function moved(t, before, want, what)
    local after = counters()
    t:log(what .. ": before " .. show(before))
    t:log(what .. ": after  " .. show(after))
    for _, k in ipairs(NAMES) do
        t:assert_eq(after[k] - before[k], want[k] or 0, what .. ": " .. k)
    end
    return after
end

local function stub_udp(payload, timeout)
    local fd = assert(ntfe.udp_connect(sut, "127.0.0.53", 53))
    ntfe.send(sut, fd, payload)
    local got = ntfe.recv(sut, fd, 50, 4096)
    if not got and timeout then
        gw:serve({ timeout = timeout, until_ = function()
            got = ntfe.recv(sut, fd, 30, 4096)
            return got ~= nil
        end })
    end
    sys.close(sut, fd)
    return got and dns.decode(got)
end

local function stub_tcp(payload)
    local fd = assert(ntfe.tcp_connect(sut, "127.0.0.53", 53, 2000))
    ntfe.send(sut, fd, string.pack(">I2", #payload) .. payload)
    local got = ""
    gw:serve({ timeout = 10, until_ = function()
        local chunk = ntfe.recv(sut, fd, 30, 4096)
        if chunk then got = got .. chunk end
        return #got >= 2 and #got >= 2 + string.unpack(">I2", got)
    end })
    sys.close(sut, fd)
    return #got >= 2 and dns.decode(got:sub(3)) or nil
end

local function asked(name)
    return dns.queries(gw, function(q)
        local qn = q.msg and q.msg.questions[1]
        return qn ~= nil and dns.same_name(qn.name, name)
    end)
end

local function relese(o)
    local d = { pool = { "10.77.0.50" }, lease = 3600 }
    for k, v in pairs(o or {}) do d[k] = v end
    gw:dhcp(d)
    local r = network.call(sut, { query = "renew", interface = "eth0" })
    assert(r and r.ok, "renew: " .. tostring(r and r.error))
end

local function serve_until_r(t, pred, what, timeout)
    t:assert(gw:serve({ timeout = timeout or 20, until_ = function() return pred(rstatus()) end }), what)
end

-- ---------------------------------------------------------------------------

test("with timed stopped the counters are still, and status and flush requests and netd snapshots are not counted",
    { spec = "resolvd *engine-counters.status-flush-and-netd-not-counted" }, function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound")
        serve_until_r(t, function(s) return s.scopes[1] and #s.scopes[1].servers == 1
            and #s.scopes[1].domains == 2 end, "resolvd has eth0's server and domains")
        sut:run("svctl stop timed"):assert_ok()
        gw:serve({ timeout = 3 })
        local before = counters()
        gw:serve({ timeout = 3 })
        moved(t, before, {}, "three quiet seconds")

        before = counters()
        for _ = 1, 5 do rstatus() end
        t:assert(network.call(sut, { query = "flush" }, { path = SOCK }).ok, "flush")
        t:assert(network.call(sut, { query = "flush" }, { path = SOCK }).ok, "flush again")
        -- A new snapshot: the lease's domains change.
        relese({ options = { { 119, gateway.opt.names({ "three.test" }) } } })
        serve_until_r(t, function(s) return s.scopes[1].domains[1] == "three.test" end,
            "resolvd applied a new snapshot from netd")
        relese({ options = DOMAINS })
        serve_until_r(t, function(s) return #s.scopes[1].domains == 2 end, "and another, putting the domains back")
        moved(t, before, {}, "five statuses, two flushes, two snapshots")
    end)

test("queries counts every resolve, lookup and reverse and every accepted stub query, unparseable names included; synthetic every synthetic task, two for an any lookup of localhost",
    { spec = "resolvd *engine-counters.queries resolvd *engine-counters.synthetic" }, function(t)
        local before = counters()
        t:assert_eq(resolve("localhost", T.A).source, "synthetic", "resolve localhost")
        local l = ask({ query = "lookup", name = "localhost" })
        t:assert_eq(#l.addresses, 2, "lookup localhost, family any: both addresses")
        t:assert_eq(ask({ query = "reverse", address = "127.0.0.1" }).source, "synthetic", "reverse 127.0.0.1")
        t:assert_eq(resolve("printer.local", T.A).outcome, "notfound", ".local's notfound")
        t:assert_eq(resolve("a..b", T.A).source, "local", "a name that does not parse")
        local u = stub_udp(dns.encode(dns.query("localhost", "A", { id = 101 })))
        t:assert(u and u.rcode == 0 and #u.answers == 1, "a stub UDP query for localhost")
        local tc = stub_tcp(dns.encode(dns.query("localhost", "AAAA", { id = 102 })))
        t:assert(tc and tc.rcode == 0 and #tc.answers == 1, "a stub TCP query for localhost")
        -- Refused at the stub door: not counted.
        local resp = dns.query("localhost", "A", { id = 103 })
        resp.qr = true
        t:assert_eq(stub_udp(dns.encode(resp)), nil, "a response sent to the door is dropped")
        local two = dns.query("localhost", "A", { id = 104 })
        two.questions[2] = { name = "localhost", type = T.AAAA, class = 1 }
        local fe = stub_udp(dns.encode(two), 2)
        t:assert(fe and fe.rcode == dns.RCODE.FORMERR, "two questions: FORMERR")
        local op = dns.query("localhost", "A", { id = 105 })
        op.opcode = 2
        local ni = stub_udp(dns.encode(op), 2)
        t:assert(ni and ni.rcode == dns.RCODE.NOTIMP, "opcode STATUS: NOTIMP")
        moved(t, before, { queries = 7, synthetic = 7 }, "four native questions on synthetic names, one unparseable, two stub queries")
    end)

test("a request refused at the access check is not counted in queries",
    { spec = "resolvd *engine-counters.queries" }, function(t)
        -- Owner and group SYSTEM, and a DACL that grants nothing.
        local system = kacs.SID.LOCAL_SYSTEM
        local acl = kacs.acl({})
        local sd = string.pack("<I1I1I2I4I4I4I4", 1, 0, 0x8004, 20, 20 + #system, 0, 20 + 2 * #system)
            .. system .. system .. acl
        local hex = (sd:gsub(".", function(c) return string.format("%02x", c:byte()) end))
        local before = counters()
        network.write(sut, "Dns", { ControlSecurity = "hex:" .. hex })
        local answered, denied = 0, 0
        local ok = pcall(wait_until, function()
            local r = network.call(sut, { query = "resolve", name = "localhost", type = T.A }, { path = SOCK })
            if r and r.ok then answered = answered + 1; return false end
            return r ~= nil and r.error == "access denied"
        end, { timeout = 15, interval = 0.2 })
        t:assert(ok, "the descriptor that grants nothing takes effect")
        for _ = 1, 3 do
            local r = network.call(sut, { query = "resolve", name = "localhost", type = T.A }, { path = SOCK })
            t:assert(r and r.error == "access denied", "denied")
            denied = denied + 1
        end
        network.reg(sut, { "del", network.KEY .. "\\Dns", "ControlSecurity" }):assert_ok()
        t:assert(pcall(wait_until, function()
            local r = network.call(sut, { query = "status" }, { path = SOCK })
            return r ~= nil and r.ok == true
        end, { timeout = 15, interval = 0.2 }), "the default descriptor is back")
        t:log(string.format("%d answered before the descriptor applied, %d denied after", answered, denied + 1))
        moved(t, before, { queries = answered, synthetic = answered }, "only the answered requests")
    end)

test("cache_hits counts every candidate found live in the cache, a notfound hit that moves on included",
    { spec = "resolvd *engine-counters.cache-hits" }, function(t)
        local before = counters()
        t:assert_eq(resolve("www.example.test", T.A).source, "dns", "www: from the server")
        t:assert_eq(resolve("www.example.test", T.A).source, "cache", "www again: a hit")
        t:assert_eq(resolve("www.example.test", T.A, true).source, "dns", "www with no_cache: no hit")
        local g = resolve("ghost", T.A)
        t:assert(g.outcome == "notfound" and g.source == "dns", "ghost: both candidates NXDOMAIN from the server")
        g = resolve("ghost", T.A)
        t:assert(g.outcome == "notfound" and g.source == "cache", "ghost again: both from the cache")
        moved(t, before, { queries = 5, cache_hits = 3, upstream_sent = 4, upstream_answered = 4 },
            "www three times, ghost twice")
    end)

test("a truncated reply is answered and its TCP retry is sent and answered again",
    { spec = "resolvd *engine-counters.upstream-sent resolvd *engine-counters.upstream-answered" }, function(t)
        dns.forget(gw)
        local before = counters()
        local r = resolve("big.example.test", T.A)
        t:log(string.format("big.example.test: %s, %d records", tostring(r.outcome), #(r.records or {})))
        t:assert_eq(#r.records, 40, "the whole answer came over TCP")
        local q = asked("big.example.test")
        t:assert(#q == 2 and q[1].transport == "udp" and q[2].transport == "tcp", "asked over UDP, then TCP")
        moved(t, before, { queries = 1, upstream_sent = 2, upstream_answered = 2 }, "a truncated UDP reply and its TCP retry")
    end)

test("a SERVFAIL reply counts as answered and as failed",
    { spec = "resolvd *engine-counters.upstream-answered resolvd *engine-counters.upstream-failed" }, function(t)
        behave["fail.example.test"] = function(_, _, default)
            default.rcode = dns.RCODE.SERVFAIL
            return default
        end
        dns.forget(gw)
        local before = counters()
        local r = resolve("fail.example.test", T.A)
        t:assert_eq(r.outcome, "unavailable", "every attempt SERVFAIL: unavailable")
        t:assert_eq(#asked("fail.example.test"), 3, "three attempts")
        moved(t, before, { queries = 1, upstream_sent = 3, upstream_answered = 3, upstream_failed = 3 }, "three SERVFAILs")
    end)

test("a reply that does not match is not answered: its transaction times out and fails",
    { spec = "resolvd *engine-counters.upstream-answered" }, function(t)
        -- PEI-1338: any datagram on the upstream socket ends the
        -- transaction, so the mismatch becomes a 2 s timeout and a
        -- demotion; this asserts the TRM's present behaviour.
        behave["odd.example.test"] = function(n, _, default)
            if n == 1 then default.id = default.id ~ 1 end
            return default
        end
        dns.forget(gw)
        local before = counters()
        local r = resolve("odd.example.test", T.A)
        t:assert_eq(r.outcome, "found", "found at the second attempt")
        t:assert_eq(#asked("odd.example.test"), 2, "two attempts")
        moved(t, before, { queries = 1, upstream_sent = 2, upstream_answered = 1, upstream_failed = 1 },
            "a wrong-ID reply, then a right one")
    end)

test("a timeout counts as failed and not answered",
    { spec = "resolvd *engine-counters.upstream-failed" }, function(t)
        behave["quiet.example.test"] = function() return false end
        dns.forget(gw)
        local before = counters()
        local r = resolve("quiet.example.test", T.A)
        t:assert_eq(r.outcome, "unavailable", "unavailable")
        t:assert_eq(#asked("quiet.example.test"), 3, "three attempts reached the server")
        moved(t, before, { queries = 1, upstream_sent = 3, upstream_failed = 3 }, "three timeouts")
    end)

test("a transaction whose socket cannot connect is counted as sent and as failed, though nothing reached the wire",
    { spec = "resolvd *engine-counters.upstream-sent resolvd *engine-counters.upstream-failed" }, function(t)
        -- The interface's server goes, and the fallback scope's only
        -- server is an IPv6 address the machine has no route to.
        relese({ dns = false, options = DOMAINS })
        serve_until_r(t, function(s) return #s.scopes[1].servers == 0 end, "eth0's scope has no server")
        network.write(sut, "Dns", { FallbackServers = "sz:fd99::53" })
        serve_until_r(t, function(s) return s.fallback_servers[1] == "fd99::53" end, "the fallback server is fd99::53")
        gw:forget()
        local before = counters()
        local r = resolve("nowhere.example.test", T.A)
        t:assert_eq(r.outcome, "unavailable", "unavailable")
        moved(t, before, { queries = 1, upstream_sent = 3, upstream_failed = 3 }, "three sends that could not be made")
        gw:serve({ timeout = 1 })
        local out = gw:frames(function(f) return f.udp ~= nil and f.udp.dport == 53 end)
        t:assert_eq(#out, 0, "no query reached the wire")
        local logs = sut:run("evctl 'LOGS FROM resolvd SINCE 5m ago TAKE 50'").stdout
        local line = logs:match('message="(resolvd: warn: upstream fd99::53: [^"]*)"')
        t:log("log: " .. tostring(line))
        t:assert(line ~= nil, "each failure is logged against the server")
        network.reg(sut, { "del", network.KEY .. "\\Dns", "FallbackServers" }):assert_ok()
    end)

test("the counters are reset by a restart and by nothing else: flush leaves them",
    { spec = "resolvd *engine-counters.reset-only-by-restart" }, function(t)
        local before = counters()
        t:assert(before.queries > 0, "the counters have counted something")
        t:assert(network.call(sut, { query = "flush" }, { path = SOCK }).ok, "flush")
        moved(t, before, {}, "a flush")
        -- Stop, then start: on this image `svctl restart` leaves the new
        -- resolvd unable to set up /run/resolvd again (PEI-1373: a crash
        -- loop on `native socket: Permission denied`), so the directory is removed
        -- while the service is stopped and peinit provisions it anew.
        local pid = peinit.pid_of_comm(sut, "resolvd")
        sut:run("svctl stop resolvd"):assert_ok()
        t:assert(pcall(wait_until, function() return peinit.pid_of_comm(sut, "resolvd") == nil end,
            { timeout = 20, interval = 0.25 }), "resolvd stopped")
        sut:run("rm -rf /run/resolvd"):assert_ok()
        sut:run("svctl start resolvd"):assert_ok()
        t:assert(pcall(wait_until, function()
            local now = peinit.pid_of_comm(sut, "resolvd")
            if not now or now == pid then return false end
            local s = network.call(sut, { query = "status" }, { path = SOCK })
            return s ~= nil and s.ok == true
        end, { timeout = 30, interval = 0.25 }), "a new resolvd answers")
        local c = counters()
        t:log("after the restart: " .. show(c))
        for _, k in ipairs(NAMES) do t:assert_eq(c[k], 0, k .. " is zero") end
    end)
