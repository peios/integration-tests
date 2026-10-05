-- resolvd TRM §4.6 "Servers, Attempts and Timeouts": which server each
-- attempt goes to, demotion and how it ends, and the response codes
-- that fail an attempt; PSPU §6.B's demotion period.
--
-- Harness: the scripted gateway (helpers.gateway) answers DNS
-- (helpers.dns) on two addresses, A = 10.77.0.1 and B = 10.77.0.2, which
-- the lease offers in that order (DHCP option 6), so eth0's scope lists
-- A then B. The gateway's hook decides each reply from the name's first
-- label and the server asked (`ctx.server`):
--   good-N      both answer (NOERROR)
--   afail-N     A answers SERVFAIL, B answers
--   bfail-N     B answers SERVFAIL, A answers
--   bfailnx-N   B answers SERVFAIL, A answers NXDOMAIN
--   bfailtc-N   B answers SERVFAIL; A answers over UDP with TC set, and
--               over TCP in full
--   silent-N    neither answers
--   rcC-N       both answer with response code C (16 rides in OPT)
-- Every answer has TTL 0 and every NXDOMAIN lacks an SOA, so nothing is
-- cached and each question reaches the servers. The gateway's query log
-- (`dns.queries`, timestamped on the gateway's clock) shows which server
-- each attempt went to, in order; `status` shows which are demoted.
--
-- Demotion lasts 30 s, so the tests run in order and each states the
-- marks it starts from.
--
-- Any reply from A clears A's mark, any silence sets one, so no other
-- question may reach A or B while the tests read marks. The image asks
-- for N.time.peios.org in the background; a second scope takes those
-- questions away: a dummy link joined to a profile with a static
-- address, `Dns.Domains` peios.org (the longest-domain rule routes the
-- NTP names there) and `Dns.Servers` C = 10.77.0.3 then A. C answers
-- them, so A is never asked; and since dummy0's scope lists A too, it
-- also shows that a mark belongs to the address.
--
-- Own VMs: three DNS servers, a dummy link, and 30-second marks that
-- outlive a test.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local rtnl = require("helpers.rtnl")

peinit.claim(2)

local SOCK = "/run/resolvd/resolv.sock"
local A, B, C = "10.77.0.1", "10.77.0.2", "10.77.0.3"

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
-- rtnl, not ntfe.if_addr: on eth0 the latter replaces the primary address.
assert(rtnl.add_address(gw.vm, gw.ifindex, B, { prefix = 24 }), "gateway address B")
assert(rtnl.add_address(gw.vm, gw.ifindex, C, { prefix = 24 }), "gateway address C")
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600, dns = { A, B } })

dns.serve(gw, {
    on = function(q, default, ctx)
        local qn = q.questions[1]
        local kind = qn and qn.name:lower():match("^(%a+%d*)%-%d+%.srv%.test$")
        if not kind then return nil end   -- NXDOMAIN, no SOA
        local function answer(rcode)
            default.rcode, default.authority, default.answers = rcode or 0, {}, {}
            if (rcode or 0) == 0 then
                default.answers = { { name = qn.name, type = qn.type, ttl = 0, data = "10.77.2.1" } }
            end
            return default
        end
        if kind == "silent" then return false end
        local code = tonumber(kind:match("^rc(%d+)$"))
        if code then
            answer(code)
            if code > 15 then default.edns = default.edns or { udp_size = 1232 } end
            return default
        end
        local a = ctx.server == A
        if kind == "afail" then return answer(a and dns.RCODE.SERVFAIL or 0) end
        if kind == "bfail" then return answer(a and 0 or dns.RCODE.SERVFAIL) end
        if kind == "bfailnx" then return answer(a and dns.RCODE.NXDOMAIN or dns.RCODE.SERVFAIL) end
        if kind == "bfailtc" then
            if not a then return answer(dns.RCODE.SERVFAIL) end
            answer(0)
            if ctx.transport == "udp" then default.tc, default.no_truncate = true, true end
            return default
        end
        return answer(0)
    end,
})
local service = gw.ticks.dns   -- the DNS server's own tick (TCP and held replies)

local sut = network.boot({ bridges = { lan }, gateway = gw })

local function rstatus()
    local s, err = network.call(sut, { query = "status" }, { path = SOCK })
    assert(s and s.ok ~= false, "resolvd status: " .. tostring(err or (s and s.error)))
    return s
end

local function scope(name)
    for _, s in ipairs(rstatus().scopes or {}) do
        if s.interface == name then return s end
    end
end

local function list(xs) table.sort(xs or {}); return table.concat(xs or {}, ",") end
local function demoted(name) return list((scope(name or "eth0") or {}).demoted) end

local function served(cmd, timeout)
    local p = sut:run_async("sh", { args = { "-c", cmd } })
    gw:serve({ timeout = timeout or 30, until_ = function() return p:status() == "exited" end })
    return p:wait(5)
end

--- Ask `name` with `resolv query`; returns the outcome, the server it
--- names, and the servers asked for it, in order, with their times.
local function ask(t, name)
    local r = served("resolv query " .. name .. " A")
    local first = r.stdout:match("^[^\n]*")
    local outcome = first:match("^(%S+)")
    local via = first:match(" via (%S+)")
    local servers, times = {}, {}
    for _, e in ipairs(dns.queries(gw, function(e)
        local q = e.msg and e.msg.questions[1]
        return q and dns.same_name(q.name, name)
    end)) do
        servers[#servers + 1] = e.server .. (e.transport == "tcp" and "/tcp" or "")
        times[#times + 1] = e.at
    end
    t:log(string.format("%s: %s via %s; asked %s", name, tostring(outcome), tostring(via),
        table.concat(servers, " ")))
    return { outcome = outcome, via = via, asked = table.concat(servers, " "), times = times }
end

test("each attempt goes to the healthy servers first, in configured order, then the demoted ones; a demoted server is still asked",
    { spec = "resolvd *engine-servers.healthy-first-then-demoted resolvd *engine-servers.demoted-servers-still-asked" },
    function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound a lease")
        t:assert(gw:serve({ timeout = 20, until_ = function()
            return list((scope("eth0") or {}).servers) == list({ A, B })
        end }), "eth0's scope lists A and B")
        t:assert_eq(scope("eth0").servers[1], A, "A first, as the lease lists them")
        -- dummy0's scope, which takes the background names (see the header).
        network.write(sut, "Profiles\\ptdns", { ["Address.Static"] = "multi:10.99.0.1/24",
            ["Dns.Servers"] = "multi:" .. C .. "," .. A, ["Dns.Domains"] = "multi:peios.org" })
        network.write(sut, "Rules\\Interface\\pt-join", { ["Interface.Equal"] = "multi:dummy0",
            Priority = "dword:20", Actions = "multi:JOIN(ptdns)" })
        local mp = sut:run("modprobe dummy numdummies=1")
        t:assert_eq(mp.exit_code, 0, "dummy loads: " .. mp.stderr)
        t:assert(gw:serve({ timeout = 30, until_ = function()
            local d = scope("dummy0")
            return d ~= nil and list(d.servers) == list({ A, C })
        end }), "resolvd has dummy0's scope, listing C and A")
        dns.forget(gw)
        gw:serve({ timeout = 3 })
        local bg = dns.queries(gw, function(e)
            local q = e.msg and e.msg.questions[1]
            return q and not q.name:lower():match("%.srv%.test$") and e.server ~= C
        end)
        t:assert_eq(#bg, 0, "no other question reaches A or B")
        t:assert_eq(demoted(), "", "nothing is demoted")

        local r = ask(t, "afail-1.srv.test")
        t:assert_eq(r.asked, A .. " " .. B, "A first; its SERVFAIL fails the attempt and B is next")
        t:assert_eq(r.via, B, "B answered")
        t:assert_eq(demoted(), A, "A is demoted")
        r = ask(t, "good-1.srv.test")
        t:assert_eq(r.asked, B, "the healthy B goes before the demoted A, against configured order")
        r = ask(t, "bfail-2.srv.test")
        t:assert_eq(r.asked, B .. " " .. A, "B fails, and the demoted A is asked next")
        t:assert(r.outcome == "found" and r.via == A, "A answered")
    end)

local silent   -- the attempts of the next test's silent question, for the one after

test("a usable NOERROR or NXDOMAIN reply clears a server's mark at once; a truncated UDP reply does not, the TCP reply decides",
    { spec = "resolvd *engine-servers.good-reply-clears-demotion" }, function(t)
        t:assert_eq(demoted(), B, "B is demoted (the last test's SERVFAIL); A is not")
        local r = ask(t, "afail-5.srv.test")
        t:assert_eq(r.asked, A .. " " .. B, "A fails, then B")
        t:assert_eq(demoted(), A, "B's NOERROR cleared its mark; A's SERVFAIL set one")
        r = ask(t, "bfailnx-6.srv.test")
        t:assert_eq(r.asked, B .. " " .. A, "B fails, then the demoted A")
        t:assert_eq(r.outcome, "notfound", "A says NXDOMAIN")
        t:assert_eq(demoted(), B, "A's NXDOMAIN cleared its mark")

        r = ask(t, "afail-7.srv.test")
        t:assert_eq(demoted(), A, "A demoted again")
        -- B fails, so both are marked; A then answers over UDP with TC and
        -- the TCP retry is left unread while the marks are looked at.
        gw.ticks.dns = function(g)
            local now, keep = g.vm:clock():get(), {}
            for _, p in ipairs(g.dns_pending) do if p.due <= now then p.send() else keep[#keep + 1] = p end end
            g.dns_pending = keep
        end
        local p = sut:run_async("sh", { args = { "-c", "resolv query bfailtc-8.srv.test A" } })
        local tc_seen = gw:serve({ timeout = 10, until_ = function()
            return #dns.queries(gw, function(e)
                local q = e.msg and e.msg.questions[1]
                return q and dns.same_name(q.name, "bfailtc-8.srv.test") and e.server == A
            end) > 0
        end })
        t:assert(tc_seen, "A was asked over UDP and answered with TC set")
        gw:pump(200)
        local during = demoted()
        gw.ticks.dns = service
        gw:serve({ timeout = 10, until_ = function() return p:status() == "exited" end })
        local out = p:wait(5).stdout
        t:log("bfailtc-8: " .. out:gsub("\n", " | ") .. "; marks during the TCP retry: " .. during)
        t:assert_eq(during, list({ A, B }), "while the TCP retry is pending, A is still demoted: TC did not clear it")
        t:assert(out:match("^found%s+dns via " .. A:gsub("%.", "%%.")), "the TCP reply answered")
        t:assert_eq(demoted(), B, "the TCP reply's NOERROR cleared A's mark")
    end)

test("an attempt goes to the first server not yet asked, else to position n mod count of the order as it stands",
    { spec = "resolvd *engine-servers.server-choice-rule resolvd *engine-servers.order-recomputed-each-attempt" },
    function(t)
        local r = ask(t, "afail-9.srv.test")
        t:assert_eq(demoted(), A, "A is demoted, B healthy: the order is B, A")
        -- B first (healthy), times out and is demoted; A (not yet asked);
        -- then both are asked and both demoted, so the order is the
        -- configured one, A, B, and the third attempt (n = 2) takes A.
        -- Had the first order (B, A) stood, it would take B.
        r = ask(t, "silent-1.srv.test")
        t:assert_eq(r.outcome, "unavailable", "three timeouts: unavailable")
        t:assert_eq(r.asked, B .. " " .. A .. " " .. A, "B, then A, then A")
        silent = r
    end)

test("a failure marks the server for 30 s from that moment, a further failure moves the mark forward, and the mark then lapses",
    { spec = "resolvd *engine-servers.demotion-marks-address-for-30-seconds resolvd *engine-servers.demotion-period PSPU *nri-limits.demotion-period" },
    function(t)
        t:assert(silent and #silent.times == 3, "the silent question's three attempts are known")
        -- Each attempt failed at its 2 s deadline.
        local b_mark = silent.times[1] + 2 + 30
        local a_first = silent.times[2] + 2 + 30
        local a_mark = silent.times[3] + 2 + 30
        local clock = function() return gw.vm:clock():get() end
        t:assert_eq(demoted(), list({ A, B }), "both are demoted")
        local b_off, a_off
        gw:serve({ timeout = 45, until_ = function()
            local d = demoted()
            local now = clock()
            if not b_off and not d:find(B, 1, true) then b_off = now end
            if not a_off and not d:find(A, 1, true) then a_off = now end
            return a_off ~= nil and b_off ~= nil
        end })
        t:log(string.format("B's mark lapsed at %+.2f s against %.2f expected; A's at %+.2f against %.2f (first failure's mark %.2f)",
            (b_off or 0) - silent.times[1], b_mark - silent.times[1], (a_off or 0) - silent.times[1],
            a_mark - silent.times[1], a_first - silent.times[1]))
        t:assert(b_off and math.abs(b_off - b_mark) < 0.8, "B's mark lapsed 30 s after its failure")
        t:assert(a_off and math.abs(a_off - a_mark) < 0.8,
            "A's mark lapsed 30 s after its last failure, not its first (moved forward)")
        t:assert(a_off - b_off > 3, "A's later failure kept it demoted after B's lapsed")
    end)

test("a mark belongs to the address: a server two scopes list is demoted in both",
    { spec = "resolvd *engine-servers.demotion-is-per-address" }, function(t)
        t:assert_eq(list(scope("dummy0").servers), list({ A, C }), "dummy0's scope lists A (and C)")
        t:assert_eq(list(scope("eth0").servers), list({ A, B }), "eth0's lists A (and B)")
        t:assert_eq(demoted("dummy0"), "", "A is not demoted")
        t:assert_eq(demoted("eth0"), "", "in either scope")
        local r = ask(t, "afail-10.srv.test")
        t:assert_eq(r.asked, A .. " " .. B, "the question went through eth0's scope: A, then B")
        t:assert_eq(demoted("eth0"), A, "A is demoted in eth0's scope")
        t:assert_eq(demoted("dummy0"), A, "and in dummy0's, which asked it nothing")
    end)

test("SERVFAIL, FORMERR, NOTIMP, REFUSED, YXDOMAIN and an EDNS extended code each fail the attempt at once",
    { spec = "resolvd *engine-servers.failure-rcodes-fail-attempt" }, function(t)
        for _, code in ipairs({ 2, 1, 4, 5, 6, 16 }) do
            local failed = rstatus().counters.upstream_failed
            local r = ask(t, "rc" .. code .. "-1.srv.test")
            t:assert_eq(r.outcome, "unavailable", "rcode " .. code .. ": unavailable")
            t:assert_eq(#r.times, 3, "rcode " .. code .. ": three attempts")
            t:assert(r.times[3] - r.times[1] < 1.0,
                string.format("rcode %d: each reply ended its attempt at once (%.2f s for three)", code, r.times[3] - r.times[1]))
            t:assert_eq(rstatus().counters.upstream_failed, failed + 3, "rcode " .. code .. ": three failures counted")
        end
    end)
