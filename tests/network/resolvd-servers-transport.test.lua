-- resolvd TRM §4.6 "Servers, Attempts and Timeouts": the timeout, the
-- attempt limit, and every transport failure that fails an attempt; the
-- TCP retry that is not an attempt; the fallback servers' demotion,
-- which status does not report. PSPU §6.B's per-server timeout.
--
-- Harness: the scripted gateway (helpers.gateway) and its DNS server
-- (helpers.dns) at A = 10.77.0.1 and B = 10.77.0.2. The lease offers no
-- DNS server, so every question goes to the fallback scope, and each
-- test sets `FallbackServers` in the registry to the servers it needs:
-- the gateway's addresses, an IPv6 address the machine has no route to
-- (2001:db8::53; the gateway sends no router advertisements), or the
-- machine's own loopback, where nothing listens on port 53.
--
-- The gateway's hook decides by the name's first label:
--   silent-N    no reply
--   good-N      an answer
--   tcclose-N   UDP: TC set; TCP: the connection is closed unanswered
--   tcrst-N     UDP: TC set; TCP: refused (the listener is closed first)
--   tcslow-N    UDP: TC set, sent 1 s late; TCP: accepted by the
--               gateway's kernel and never read (the DNS server's tick
--               is swapped for one that only sends held UDP replies)
-- Answers have TTL 0, so nothing is cached. The image's background NTP
-- lookups also go to the fallback servers; A never answers them, so they
-- cannot clear the mark the second test relies on. Times come from the
-- gateway's query log (its clock) or from /proc/uptime in the guest.
--
-- Own VMs: a lease without DNS servers, and the gateway's TCP listener
-- closed and reopened.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")
local rtnl = require("helpers.rtnl")

peinit.claim(2)

local SOCK = "/run/resolvd/resolv.sock"
local A, B = "10.77.0.1", "10.77.0.2"

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
-- rtnl, not ntfe.if_addr: on eth0 the latter replaces the primary address.
assert(rtnl.add_address(gw.vm, gw.ifindex, B, { prefix = 24 }), "gateway address B")
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600, dns = false })

dns.serve(gw, {
    on = function(q, default, ctx)
        local qn = q.questions[1]
        local kind = qn and qn.name:lower():match("^(%a+)%-%d+%.tr%.test$")
        if not kind then
            -- Background names (the image's NTP lookups): A never answers
            -- them, so they cannot clear A's mark; B says NXDOMAIN.
            if ctx.server == A then return false end
            return nil
        end
        if kind == "silent" then return false end
        default.rcode, default.authority = 0, {}
        default.answers = { { name = qn.name, type = qn.type, ttl = 0, data = "10.77.3.1" } }
        if kind:match("^tc") then
            if ctx.transport == "tcp" then
                if kind == "tcclose" then return false end
                return default
            end
            default.tc, default.no_truncate = true, true
            if kind == "tcslow" then default.delay = 1.0 end
        end
        return default
    end,
})
local service = gw.ticks.dns

local sut = network.boot({ bridges = { lan }, gateway = gw })

local function rstatus()
    local s, err = network.call(sut, { query = "status" }, { path = SOCK })
    assert(s and s.ok ~= false, "resolvd status: " .. tostring(err or (s and s.error)))
    return s
end
local function list(xs) return table.concat(xs or {}, ",") end

--- Set the fallback servers and wait until resolvd has them.
local function fallback(t, servers)
    network.write(sut, "Dns", { FallbackServers = "multi:" .. table.concat(servers, ",") })
    t:assert(gw:serve({ timeout = 15, until_ = function()
        return list(rstatus().fallback_servers) == list(servers)
    end }), "resolvd's fallback servers are [" .. list(servers) .. "]")
end

--- resolvd's log lines, newest first (as network.logs, for resolvd).
local function rlogs()
    local r = sut:run("evctl 'LOGS FROM resolvd SINCE 10m ago TAKE 300'")
    local out = {}
    for line in r.stdout:gmatch("[^\n]+") do
        local msg = line:match('message="(.-)"  origin=')
        if msg then out[#out + 1] = (msg:gsub('\\"', '"')) end
    end
    return out
end
local function logged(text)
    for _, l in ipairs(rlogs()) do
        if l:find(text, 1, true) then return l end
    end
end

--- `resolv query` timed in the guest: outcome, elapsed seconds, output.
local function timed(t, name)
    local p = sut:run_async("sh", { args = { "-c",
        "cat /proc/uptime; resolv query " .. name .. " A; echo rc=$?; cat /proc/uptime" } })
    gw:serve({ timeout = 30, until_ = function() return p:status() == "exited" end })
    local out = p:wait(5).stdout
    local u = {}
    for a in out:gmatch("(%d+%.%d+) %d+%.%d+") do u[#u + 1] = tonumber(a) end
    local outcome = out:match("\n(%a+)%s")
    t:log(string.format("%s: %s", name, out:gsub("\n", " | ")))
    return outcome, (u[2] or 0) - (u[1] or 0), out
end

local function asked(name, transport)
    return dns.queries(gw, function(e)
        local q = e.msg and e.msg.questions[1]
        return q and dns.same_name(q.name, name) and (not transport or e.transport == transport)
    end)
end

test("one server: each of the three attempts goes to it, one at a time, each failing at its 2 s deadline; the third makes the question unavailable",
    { spec = "resolvd *engine-servers.transaction-timeout resolvd *engine-servers.timeout-fails-attempt resolvd *engine-servers.single-server-gets-every-attempt resolvd *engine-servers.attempts-per-candidate resolvd *engine-servers.third-failure-is-unavailable resolvd *engine-servers.attempts-sequential PSPU *nri-limits.per-server-timeout" },
    function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound a lease")
        fallback(t, { A })
        local c = rstatus().counters
        local outcome, elapsed = timed(t, "silent-1.tr.test")
        t:assert_eq(outcome, "unavailable", "unavailable after the attempts")
        gw:serve({ timeout = 3 })
        local q = asked("silent-1.tr.test")
        t:assert_eq(#q, 3, "three attempts, and no fourth")
        for i, e in ipairs(q) do
            t:assert_eq(e.server, A, "attempt " .. i .. " went to the one server")
            t:assert_eq(e.transport, "udp", "over UDP")
        end
        local gaps = { q[2].at - q[1].at, q[3].at - q[2].at }
        t:log(string.format("gaps %.2f s, %.2f s; question took %.2f s", gaps[1], gaps[2], elapsed))
        for i, g in ipairs(gaps) do
            t:assert(g >= 1.9 and g <= 2.5, string.format("attempt %d was sent when attempt %d timed out, 2 s on (%.2f s)",
                i + 1, i, g))
        end
        t:assert(elapsed >= 5.8 and elapsed <= 7.0, string.format("unavailable at the third deadline, ~6 s (%.2f s)", elapsed))
        -- (The counters are not compared here: the image's background
        -- lookups, which A never answers, time out alongside.)
        local c2 = rstatus().counters
        t:assert(c2.upstream_failed - c.upstream_failed >= 3, "the three timeouts were counted as failures")
    end)

test("the fallback servers are demoted like any other, and status does not report it",
    { spec = "resolvd *engine-servers.fallback-demotion-not-reported" }, function(t)
        -- A was demoted by the last test's timeouts; B is new and healthy.
        fallback(t, { A, B })
        local outcome = timed(t, "good-2.tr.test")
        t:assert_eq(outcome, "found", "answered")
        local q = asked("good-2.tr.test")
        t:assert(#q == 1 and q[1].server == B, "B was asked first, before the configured-first A: A is demoted")
        local s = rstatus()
        t:assert_eq(list(s.fallback_servers), A .. "," .. B, "status lists the fallback servers")
        for _, sc in ipairs(s.scopes or {}) do
            t:assert_eq(list(sc.demoted), "", "no scope reports a demoted server (" .. tostring(sc.interface) .. ")")
        end
        local keys = {}
        for k in pairs(s) do keys[#keys + 1] = k end
        table.sort(keys)
        t:log("status keys: " .. table.concat(keys, ","))
        for _, k in ipairs(keys) do
            t:assert(not (k:find("demot") and k ~= "scopes"), "no top-level field reports demotion: " .. k)
        end
        local r = sut:run("resolv status")
        t:log(r.stdout)
        local line = r.stdout:match("\nfallback[^\n]*")
        t:assert(line and line:find(A, 1, true) and not line:find("demoted", 1, true),
            "resolv status's fallback line names A without marking it")
    end)

test("an error sending, such as an unreachable network, fails the attempt at once",
    { spec = "resolvd *engine-servers.send-error-fails-attempt-at-once" }, function(t)
        fallback(t, { "2001:db8::53" })
        local c = rstatus().counters
        local outcome, elapsed = timed(t, "good-3.tr.test")
        t:assert_eq(outcome, "unavailable", "unavailable")
        t:assert(elapsed < 1.0, string.format("three attempts failed at once, not at their deadlines (%.2f s)", elapsed))
        local c2 = rstatus().counters
        -- At least: a background lookup may fail the same way meanwhile.
        t:assert(c2.upstream_failed - c.upstream_failed >= 3, "three failures counted")
        local line = logged("upstream 2001:db8::53: ")
        t:log("log: " .. tostring(line))
        t:assert(line ~= nil, "the send error was logged")
    end)

test("an error receiving on the UDP socket, such as the refusal after an ICMP port-unreachable, fails the attempt at once",
    { spec = "resolvd *engine-servers.udp-receive-error-fails-attempt" }, function(t)
        local ss = sut:run("ss -uln")
        t:log(ss.stdout)
        t:assert(not ss.stdout:find("127.0.0.1:53 ", 1, true), "nothing listens on 127.0.0.1:53/udp")
        fallback(t, { "127.0.0.1" })
        local c = rstatus().counters
        local outcome, elapsed = timed(t, "good-4.tr.test")
        t:assert_eq(outcome, "unavailable", "unavailable")
        t:assert(elapsed < 1.0, string.format("three attempts failed at once (%.2f s)", elapsed))
        local c2 = rstatus().counters
        t:assert(c2.upstream_failed - c.upstream_failed >= 3, "three failures counted")
        t:assert_eq(logged("upstream 127.0.0.1: "), nil, "the sends succeeded (no send error logged): the receive failed")
    end)

test("TCP: a connection that is refused, or closed before a whole reply, fails the attempt at once",
    { spec = "resolvd *engine-servers.tcp-connect-failure-fails-attempt resolvd *engine-servers.tcp-incomplete-reply-fails-attempt" },
    function(t)
        fallback(t, { A })
        -- Wait out A's demotion? Not needed: with one server every
        -- attempt goes to it either way.
        local outcome, elapsed = timed(t, "tcclose-5.tr.test")
        t:assert_eq(outcome, "unavailable", "every TCP retry closed unanswered: unavailable")
        t:assert_eq(#asked("tcclose-5.tr.test", "udp"), 3, "three attempts over UDP")
        t:assert_eq(#asked("tcclose-5.tr.test", "tcp"), 3, "each followed by its TCP retry, which was read and closed")
        t:assert(elapsed < 1.5, string.format("each close failed the attempt at once (%.2f s)", elapsed))

        -- Refused: close the gateway's listener, so a SYN to port 53 is reset.
        sys.close(gw.vm, gw.dns_listener)
        gw.dns_listener = nil
        gw:forget()
        outcome, elapsed = timed(t, "tcrst-6.tr.test")
        gw.dns_listener = assert(ntfe.tcp_listen(gw.vm, "::", 53))
        t:assert_eq(outcome, "unavailable", "every TCP retry refused: unavailable")
        t:assert_eq(#asked("tcrst-6.tr.test", "udp"), 3, "three attempts over UDP")
        -- The last SYN can still be queued on the gateway's packet socket
        -- when the question ends; read it before counting.
        gw:pump(300)
        -- A connection attempt is a source port: a SYN retransmitted
        -- under load (its RST lost or late) is the same attempt.
        local ports, syns = {}, 0
        for _, f in ipairs(gw.seen) do
            if f.ip and f.ip.protocol == 6 then
                local raw = f.raw
                local l4 = 15 + (raw:byte(15) & 0xF) * 4
                local sport, dport = string.unpack(">I2I2", raw, l4)
                local flags = raw:byte(l4 + 13)
                if dport == 53 and flags & 0x12 == 0x02 and not ports[sport] then
                    ports[sport] = true
                    syns = syns + 1
                end
            end
        end
        t:assert_eq(syns, 3, "three connection attempts (distinct source ports), each refused")
        t:assert(elapsed < 1.5, string.format("each refusal failed the attempt at once (%.2f s)", elapsed))
    end)

test("the TCP retry after a truncated reply has its own 2 s deadline and is not one of the three attempts",
    { spec = "resolvd *engine-servers.tcp-retry-not-an-attempt" }, function(t)
        gw.ticks.dns = function(g)   -- held UDP replies only; TCP is never read
            local now, keep = g.vm:clock():get(), {}
            for _, p in ipairs(g.dns_pending) do if p.due <= now then p.send() else keep[#keep + 1] = p end end
            g.dns_pending = keep
        end
        local outcome, elapsed = timed(t, "tcslow-7.tr.test")
        gw.ticks.dns = service
        t:assert_eq(outcome, "unavailable", "unavailable")
        local q = asked("tcslow-7.tr.test", "udp")
        t:assert_eq(#q, 3, "three UDP attempts: the TCP retries were not counted against them")
        local gaps = { q[2].at - q[1].at, q[3].at - q[2].at }
        t:log(string.format("gaps %.2f s, %.2f s; question %.2f s", gaps[1], gaps[2], elapsed))
        for i, g in ipairs(gaps) do
            -- TC lands 1 s after the query; the retry then waits its own
            -- 2 s, so the next attempt comes ~3 s after the last, not at
            -- the UDP transaction's 2 s deadline.
            t:assert(g >= 2.8 and g <= 3.6, string.format("gap %d: %.2f s, the TC delay plus the TCP retry's 2 s", i, g))
        end
        t:assert(elapsed >= 8.5 and elapsed <= 10.5, string.format("unavailable after ~9 s (%.2f s)", elapsed))
    end)
