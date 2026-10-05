-- Cross-component: the real producers end to end, where each side's own
-- testset used a stand-in. Two chains on the shipped default path:
--
--   netd readiness → peinit's level gate (netd TRM §8.2, peinit TRM
--   §7.5). deps-levels.test.lua proves the gate with netd never reaching
--   a level, and deps-levels-published.test.lua with a scripted pt-notify
--   publisher. Here netd publishes the levels itself, as the network
--   arrives: link with no lease, addressed once the link-local fallback
--   lands, routed after the gateway's ACK, absent when the cable goes.
--
--   netd → resolvd → the NSS shim (netd §8.3, resolvd §3.3, PSPU §6.9 and
--   §6.10). The DHCP-offered server and domain become resolvd's eth0
--   scope through netd's real snapshot channel (the resolvd-netd-* files
--   use an agent stand-in for netd), a single label is expanded with that
--   domain and answered by the gateway's DNS (helpers.dns), and `getent`
--   returns it through the shim.
--
-- Harness: the scripted gateway (helpers.gateway, helpers.dns) and a
-- whole Peios (helpers.network). Nothing in the network configuration is
-- the test's: `Profiles\default` and `Rules\Interface\wired` as shipped.
-- The only seed is five services that wait on netd's levels, each a
-- shell that stamps `<realtime ns> <pid>` into /run/<name>.started and
-- execs a long sleep, so "started" is a stamp on the guest's clock and
-- "still running" is the same pid alive. Three are boot-triggered
-- (`netd:link`, `netd:addressed`, and `network:routed` through the role,
-- as the netd service definition tells a dependent to write it); two are
-- started by hand later.
--
-- The gateway is silent (records, answers nothing) until the second test
-- arms it, so the machine's first DHCP exchange is the one the routed
-- dependent waits for, and the shipped profile's link-local fallback
-- (about 28 s after discovery began, netd §5.5) gives an `addressed`
-- level in between. The ordering claims ("after the ACK", "after netd's
-- readiness line") are on the guest's realtime clock: the dependent's
-- stamp against eventd's timestamps of netd's log lines and a guest
-- clock reading taken inside the gateway's ACK hook, which also records
-- the dependent's state at the instant the ACK is built.
--
-- Own VMs: the boot-time seed, the gateway's silence from the first
-- DISCOVER, and the cable pull at the end. Tests run in order.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")

peinit.claim(2)

local DOMAIN = "cross.test"
local SERVER = "10.77.0.1"
local PRINTER = "10.77.0.80"
local RSOCK = "/run/resolvd/resolv.sock"

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
local DHCP = { pool = { "10.77.0.50" }, lease = 3600, options = { { 15, DOMAIN } } }
gw:dhcp({ pool = DHCP.pool, lease = DHCP.lease, options = DHCP.options, silent = true })
dns.serve(gw, {
    zone = { ["printer." .. DOMAIN] = { { type = "A", ttl = 300, data = PRINTER } } },
    soa = { name = DOMAIN, data = { minimum = 30 } },
})

local function resident(name, target, boot)
    local values = {
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi", data = { "-c",
            "echo \"$(date +%s%N) $$\" > /run/" .. name .. ".started; exec /bin/sleep 100000" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "Requires", type = "multi", data = { target } },
    }
    if boot then values[#values + 1] = { name = "Triggers", type = "multi", data = { "boot" } } end
    return { path = [[Machine\System\Services\]] .. name, values = values }
end

local sut = network.boot({
    bridges = { lan }, gateway = gw,
    files = peinit.seed("zz-pt-cross", {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
        resident("pt-x-link", "netd:link", true),
        resident("pt-x-addressed", "netd:addressed", true),
        resident("pt-x-routed", "network:routed", true),
        resident("pt-x-routed2", "netd:routed", false),
        resident("pt-x-addressed2", "netd:addressed", false),
    }),
})

-- ---------------------------------------------------------------------------
-- Local instruments
-- ---------------------------------------------------------------------------

local function list(l) return "[" .. table.concat(l or {}, ", ") .. "]" end

local function svc(name)
    local r = sut:run("svctl --json status " .. name)
    local ok, v = pcall(json.decode, r.stdout)
    return (ok and v) or {}, r.stdout
end

local function now_ns()
    return assert(tonumber(sut:run("date +%s%N").stdout:match("%d+")), "guest clock")
end

--- The stamp a dependent wrote when it started: ns, pid; nil if none.
local function stamp(name)
    local r = sut:run("cat /run/" .. name .. ".started")
    if r.exit_code ~= 0 then return nil end
    local ns, pid = r.stdout:match("(%d+)%s+(%d+)")
    return tonumber(ns), tonumber(pid)
end

local function alive(pid)
    local r = sut:run("cat /proc/" .. pid .. "/comm")
    return r.exit_code == 0 and r.stdout:match("^(%S+)") == "sleep"
end

--- Assert `name` is held: inactive, its start operation open, no stamp.
local function held(t, name, what)
    local s, raw = svc(name)
    t:log(what .. ": " .. name .. " " .. raw:gsub("%s+$", ""))
    t:assert_eq(s.state, "inactive", what .. ": " .. name .. " has not started")
    t:assert(s.current_operation and s.current_operation.type == "start",
        what .. ": and its start operation is still open")
    t:assert_eq(stamp(name), nil, what .. ": " .. name .. " never ran")
end

--- Pump the gateway until `name` is active and has stamped; returns ns, pid.
local function started(t, name, what, timeout)
    local ok = gw:serve({ timeout = timeout or 30, until_ = function()
        return svc(name).state == "active" and stamp(name) ~= nil
    end })
    local s, raw = svc(name)
    t:assert(ok, what .. ": " .. name .. " started (" .. raw:gsub("%s+$", "") .. ")")
    return stamp(name)
end

--- netd's log, oldest first: { ts (realtime ns, eventd's), msg }.
local function netd_log()
    local r = sut:run("evctl 'LOGS FROM netd SINCE 1h ago TAKE 3000'")
    assert(r.exit_code == 0, "evctl: " .. r.stderr)
    local newest_first = {}
    for line in r.stdout:gmatch("[^\n]+") do
        local msg = line:match('message="(.-)"  origin=')
        local ts = tonumber(line:match("timestamp=(%d+)"))
        if msg and ts then newest_first[#newest_first + 1] = { ts = ts, msg = (msg:gsub('\\"', '"')) } end
    end
    local out = {}
    for i = #newest_first, 1, -1 do out[#out + 1] = newest_first[i] end
    return out
end

--- The first line containing `text` with a timestamp after `after` (ns).
local function first_line(lines, text, after)
    for _, l in ipairs(lines) do
        if l.ts > (after or 0) and l.msg:find(text, 1, true) then return l end
    end
end

local function readiness_lines(lines)
    local out = {}
    for _, l in ipairs(lines) do
        local lvl = l.msg:match("machine readiness is (%a+)")
        if lvl then out[#out + 1] = lvl end
    end
    return out
end

local function iface() return network.iface(network.status(sut), "eth0") end

-- ---------------------------------------------------------------------------
-- netd's levels gate peinit's dependents
-- ---------------------------------------------------------------------------

test("with the gateway silent, a dependent on netd:link starts, one on netd:addressed starts once the link-local fallback counts, and one on network:routed is held throughout",
    { spec = "peinit *ready.a-level-dependency-waits-for-the-level-as-well-as-the-service " ..
             "peinit *ready.a-level-is-recorded-against-the-sender-and-holds-a-mismatched-dependent " ..
             "peinit *ready.a-role-carrying-a-level-is-rewritten-to-the-provider-with-that-level " ..
             "peinit *ready.a-held-start-does-not-time-out " ..
             "netd *readiness.publish-on-change netd *readiness.usable-address netd *readiness.interface-level" },
    function(t)
        -- netd is up and has published link: the link dependent starts
        -- with no lease and no address anywhere.
        local link_ns = started(t, "pt-x-link", "no lease yet", 60)
        local i = iface()
        t:log(string.format("eth0 when pt-x-link started: level %s, carrier %s, lease %s, addresses %s",
            i.level, tostring(i.carrier), tostring(i.lease), list(i.addresses)))
        t:assert_eq(i.lease, nil, "the gateway has answered nothing: no lease")
        t:assert_eq(svc("netd").state, "active", "netd is active")
        local log = netd_log()
        local link_line = first_line(log, "machine readiness is link")
        t:assert(link_line, "netd logged `machine readiness is link`: " .. list(readiness_lines(log)))
        t:assert(link_ns >= link_line.ts,
            "pt-x-link started after netd published link (" .. link_ns .. " vs " .. link_line.ts .. ")")

        -- While the level is link, nothing above it has started.
        if network.status(sut).level == "link" then
            held(t, "pt-x-addressed", "level link")
        else
            t:log("the fallback had already landed; pt-x-addressed not checked at link")
        end
        held(t, "pt-x-routed", "level link")

        -- The fallback: about 28 s of unanswered discovery, then a
        -- 169.254/16 address, which is a usable address: addressed.
        local s = network.serve_until(gw, sut, function(x) return x.level == "addressed" end,
            { iface = "eth0", timeout = 75 })
        t:assert(s, "eth0 reaches addressed on the link-local fallback")
        local v4 = network.ipv4(network.iface(s, "eth0"))
        t:log("eth0 IPv4 at addressed: " .. list(v4))
        t:assert(#v4 == 1 and v4[1]:match("^169%.254%.%d+%.%d+/16$"), "the one IPv4 address is the 169.254/16 fallback")
        t:assert(#gw:dhcp_messages(gateway.DHCP.DISCOVER) >= 2, "discovery went on, unanswered")
        local addr_ns = started(t, "pt-x-addressed", "level addressed", 30)
        log = netd_log()
        local addr_line = first_line(log, "machine readiness is addressed")
        t:assert(addr_line, "netd logged `machine readiness is addressed`")
        t:assert(addr_ns >= addr_line.ts, "pt-x-addressed started after netd published addressed")

        -- network:routed is still held: the role resolved to netd (a
        -- missing `network` service would have failed it), and its start
        -- has waited out the whole silence without timing out.
        held(t, "pt-x-routed", "level addressed")
        t:assert(svc("pt-x-routed").cause ~= "dependency_failure", "not failed as a missing `network` service")
        t:log("readiness published so far: " .. list(readiness_lines(netd_log())))
    end)

test("network:routed starts after the gateway's ACK and after netd logs routed; the addressed dependent keeps running, and a new start on netd:addressed is held because a level is exact",
    { spec = "peinit *ready.only-the-level-itself-opens-a-hard-gate " ..
             "peinit *ready.a-level-is-matched-exactly-and-never-implied " ..
             "peinit *ready.a-level-dropping-after-the-start-does-nothing " ..
             "peinit *ready.a-level-dependency-waits-for-the-level-as-well-as-the-service " ..
             "netd *readiness.publish-on-change netd *readiness.machine-level netd *readiness.any-default-route-counts" },
    function(t)
        local _, addressed_pid = stamp("pt-x-addressed")
        t:assert(addressed_pid and alive(addressed_pid), "pt-x-addressed is running before the lease")

        -- The ACK hook records, at the instant the ACK is built, whether
        -- the routed dependent had started, and the guest's clock.
        local ack
        local function on_ack(m, default)
            if not ack and default and default.options[1][2] == string.char(gateway.DHCP.ACK) then
                ack = { state = svc("pt-x-routed").state, stamp = stamp("pt-x-routed"), ns = now_ns() }
            end
            return nil
        end
        gw:dhcp({ pool = DHCP.pool, lease = DHCP.lease, options = DHCP.options,
            on = { request = on_ack, reboot = on_ack } })
        local s = network.serve_until(gw, sut, network.bound, { iface = "eth0", timeout = 60 })
        t:assert(s, "netd bound the lease")
        local i = network.iface(s, "eth0")
        t:log("eth0 bound: level " .. tostring(i.level) .. ", addresses " .. list(i.addresses))
        t:assert(ack, "the gateway sent an ACK")
        t:assert_eq(ack.state, "inactive", "pt-x-routed had not started when the ACK was built")
        t:assert_eq(ack.stamp, nil, "and had never run")

        local routed_ns, routed_pid = started(t, "pt-x-routed", "after the ACK", 30)
        local log = netd_log()
        local lease_line = first_line(log, "lease 10.77.0.50/24 from " .. SERVER)
        t:assert(lease_line, "netd logged the lease")
        local routed_line = first_line(log, "machine readiness is routed", lease_line.ts - 1)
        t:assert(routed_line, "netd logged `machine readiness is routed` after it: " .. list(readiness_lines(log)))
        t:log(string.format("guest ns: ACK built %d; lease logged %d; routed logged %d; pt-x-routed started %d",
            ack.ns, lease_line.ts, routed_line.ts, routed_ns))
        t:assert(routed_ns > ack.ns, "pt-x-routed started after the ACK was sent")
        t:assert(routed_ns > lease_line.ts, "after netd took the lease")
        t:assert(routed_ns >= routed_line.ts, "and after netd's `machine readiness is routed`")
        t:assert_eq(network.status(sut).level, "routed", "the machine is routed")
        t:assert_eq(network.get(sut, network.KEY, "Readiness"), "routed", "Readiness says so")

        -- The level moved off `addressed` under a running dependent:
        -- nothing happens to it.
        t:assert(alive(addressed_pid), "pt-x-addressed is still the same running process")
        t:assert_eq(svc("pt-x-addressed").state, "active", "and still active")

        -- `routed` does not satisfy `netd:addressed`: a new start on it
        -- is held while the machine is routed.
        sut:run("svctl start pt-x-addressed2 --no-wait"):assert_ok()
        gw:serve({ timeout = 4 })
        t:assert_eq(network.status(sut).level, "routed", "still routed")
        held(t, "pt-x-addressed2", "level routed")
        t:assert(routed_pid and alive(routed_pid), "pt-x-routed is running")
    end)

-- ---------------------------------------------------------------------------
-- netd → resolvd → NSS, on the default path
-- ---------------------------------------------------------------------------

local function rstatus()
    local s, err = network.call(sut, { query = "status" }, { path = RSOCK })
    assert(s and s.ok, "resolvd status: " .. tostring(err or (s and s.error)))
    return s
end

local function scope_of(s, name)
    for _, sc in ipairs(s.scopes or {}) do
        if sc.interface == name then return sc end
    end
end

local function describe(s)
    local out = {}
    for _, sc in ipairs(s.scopes or {}) do
        out[#out + 1] = string.format("%s(metric %s%s servers=%s domains=%s)", tostring(sc.interface),
            tostring(sc.metric), sc.default_route and " default" or "", list(sc.servers), list(sc.domains))
    end
    return table.concat(out, "; ")
end

local function served(cmd, timeout)
    local p = sut:run_async("sh", { args = { "-c", cmd } })
    gw:serve({ timeout = timeout or 30, until_ = function() return p:status() == "exited" end })
    return p:wait(5)
end

test("the lease's DNS server and domain become resolvd's eth0 scope through netd's snapshot",
    { spec = "netd *snapshot.dns-merge netd *snapshot.scope-fields netd *snapshot.sent-on-change " ..
             "PSPU *nri-manager.snapshot-at-once-then-on-every-change PSPU *nri-manager.scope-servers-order " ..
             "PSPU *nri-manager.scope-domains-order PSPU *nri-manager.scope-default-route " ..
             "PSPU *nri-manager.resolver-replaces-scopes " ..
             "resolvd *netd-snapshot.summary-log-line resolvd *netd-snapshot.name-is-reported-interface" },
    function(t)
        local i = iface()
        t:log("netd eth0: dns " .. list(i.dns) .. ", search " .. list(i.search))
        t:assert_eq(list(i.dns), list({ SERVER }), "netd merged the lease's option 6 server (Dns.Offered)")
        t:assert_eq(list(i.search), list({ DOMAIN }), "and its option 15 domain")

        local last
        local ok = pcall(wait_until, function()
            last = rstatus()
            local sc = scope_of(last, "eth0")
            return sc ~= nil and list(sc.servers) == list({ SERVER }) and #(sc.domains or {}) == 1
                and sc.domains[1]:lower() == DOMAIN
        end, { timeout = 20, interval = 0.25, desc = "resolvd's eth0 scope" })
        t:log("resolvd scopes: " .. describe(last))
        t:assert(ok, "resolvd's eth0 scope carries the lease's server and domain")
        t:assert_eq(last.netd, true, "resolvd is connected to netd's channel")
        local sc = scope_of(last, "eth0")
        t:assert_eq(sc.default_route, true, "the scope claims the default route: eth0 is routed")
        t:assert_eq(sc.metric, 100, "at netd's metric")
        t:assert_eq(#last.scopes, 1, "eth0 is the only scope")

        -- What resolvd logged for that snapshot, and the one before the
        -- lease, which had no server: each snapshot replaced the last.
        local r = sut:run("evctl 'LOGS FROM resolvd SINCE 1h ago TAKE 3000'")
        local summaries = {}
        for line in r.stdout:gmatch("[^\n]+") do
            local msg = line:match('message="(.-)"  origin=')
            if msg and msg:find("netd: ", 1, true) then table.insert(summaries, 1, msg) end
        end
        t:log("resolvd snapshot summaries, oldest first:\n" .. table.concat(summaries, "\n"))
        t:assert_eq(summaries[#summaries], "resolvd: info: netd: eth0: 1 server(s), 1 domain(s), default",
            "the latest summary is the leased eth0 scope")
        local before = false
        for k = 1, #summaries - 1 do
            if summaries[k]:find("eth0: 0 server(s)", 1, true) then before = true end
        end
        t:assert(before, "an earlier snapshot showed eth0 with no server, before the lease")
    end)

test("a single label is expanded with the DHCP domain, answered by the gateway's DNS, and returned by getent through the shim",
    { spec = "PSPU *nri-resolution.single-label-never-sent-bare PSPU *nri-resolution.applicable-search-domains " ..
             "resolvd *engine-expansion.routable-scope-domains-then-extra " ..
             "PSPU *nri-shim.found-is-success PSPU *nri-shim.h-name-is-canonical" },
    function(t)
        dns.forget(gw)
        local q = served("resolv query printer A --no-cache")
        local head = q.stdout:match("^[^\n]*") or ""
        t:log("resolv query printer A -> " .. q.exit_code .. ":\n" .. q.stdout .. q.stderr)
        t:assert_eq(q.exit_code, 0, "resolv query succeeds")
        t:assert(head:match("^found%s+dns via " .. SERVER:gsub("%.", "%%.") .. " on eth0"),
            "found, from DNS, via the lease's server on eth0: " .. head)
        local rec = q.stdout:match("\n([^\n]*)")
        t:assert(rec and rec:lower():match("^printer%.cross%.test%.?\t%d+\ta\t10%.77%.0%.80$"),
            "the record is printer." .. DOMAIN .. " A " .. PRINTER .. ": " .. tostring(rec))

        local asked = {}
        for _, e in ipairs(dns.queries(gw)) do
            local qn = e.msg and e.msg.questions[1]
            if qn and qn.name:lower():match("^printer") then
                asked[#asked + 1] = qn.name:lower() .. "@" .. e.server .. "/" .. e.transport
            end
        end
        t:log("gateway asked: " .. list(asked))
        t:assert(#asked >= 1, "the gateway's DNS was asked")
        for _, a in ipairs(asked) do
            t:assert(a:match("^printer%.cross%.test%.?@" .. SERVER:gsub("%.", "%%.") .. "/"),
                "every question was the expanded name, at the lease's server, never the bare label: " .. a)
        end

        dns.forget(gw)
        local g = served("getent hosts printer")
        t:log("getent hosts printer -> " .. g.exit_code .. ": " .. g.stdout .. g.stderr)
        t:assert_eq(g.exit_code, 0, "getent finds it")
        local addr, name = g.stdout:match("^(%S+)%s+(%S+)")
        t:assert_eq(addr, PRINTER, "at the gateway's answer")
        t:assert_eq(name and name:lower(), "printer." .. DOMAIN, "named by the expanded, canonical name")
    end)

-- ---------------------------------------------------------------------------
-- The cable
-- ---------------------------------------------------------------------------

test("pulling the cable drops the level to absent and stops nothing; a dependent started meanwhile is held until netd publishes routed again",
    { spec = "peinit *ready.a-level-dropping-after-the-start-does-nothing " ..
             "peinit *ready.a-level-is-re-checked-at-every-release-rather-than-settled-at-planning " ..
             "peinit *ready.a-level-edge-is-kept-to-a-target-that-is-not-being-started " ..
             "peinit *ready.only-the-level-itself-opens-a-hard-gate " ..
             "netd *readiness.publish-on-change netd *readiness.machine-level" },
    function(t)
        local pids = {}
        for _, n in ipairs({ "pt-x-link", "pt-x-addressed", "pt-x-routed" }) do
            local _, pid = stamp(n)
            t:assert(pid and alive(pid), n .. " is running before the pull")
            pids[n] = pid
        end
        local nic = lan:nic(sut)
        nic:disconnect()
        local s = network.serve_until(gw, sut, function(x) return x.level == "absent" end, { timeout = 30 })
        t:assert(s, "with the cable out the machine is absent")
        t:assert(pcall(wait_until, function() return network.get(sut, network.KEY, "Readiness") == "absent" end,
            { timeout = 10, interval = 0.25, desc = "Readiness absent" }), "netd published absent")
        gw:serve({ timeout = 2 })
        for n, pid in pairs(pids) do
            t:assert(alive(pid), n .. " keeps running: the level dropping is not told to it")
            t:assert_eq(svc(n).state, "active", n .. " is still active")
        end

        -- netd is active and not being started; the condition is still
        -- checked against what it published last.
        local cut = now_ns()
        t:assert_eq(svc("netd").state, "active", "netd itself is active")
        sut:run("svctl start pt-x-routed2 --no-wait"):assert_ok()
        gw:serve({ timeout = 4 })
        held(t, "pt-x-routed2", "level absent")

        nic:reconnect()
        t:assert(network.serve_until(gw, sut, network.bound, { iface = "eth0", timeout = 60 }), "bound again")
        local ns = started(t, "pt-x-routed2", "routed again", 30)
        local log = netd_log()
        local again = first_line(log, "machine readiness is routed", cut)
        t:log("published since the pull: " .. list(readiness_lines(log)))
        t:assert(again, "netd published routed again after the pull")
        t:assert(ns >= again.ts, "pt-x-routed2 started after it (" .. ns .. " vs " .. again.ts .. ")")
        t:assert(alive(pids["pt-x-routed"]), "and the first routed dependent never restarted")
    end)

test("netd publishes only the current level and peinit matches it exactly: on DHCP the level goes link to routed, so a netd:addressed dependent is held through routed",
    { spec = "netd *readiness.peinit-matches-the-published-level" },
    function(t)
        -- PEI-1384 (decided: netd publishes the set of levels that hold,
        -- peinit matches membership). Asserted as it is today: peinit
        -- matches a level exactly (peinit §7.5), and netd publishes only
        -- the machine's current level, which on a DHCP network goes
        -- link -> routed in one pass without ever being addressed. So
        -- pt-x-addressed2, started while the machine was routed, has been
        -- held through routed, absent and routed again. When PEI-1384 is
        -- fixed this test and netd §8.2 change together.
        local log = netd_log()
        local seq = readiness_lines(log)
        t:log("machine levels published this boot: " .. list(seq))
        -- The levels since the cable pull: from the last `absent` on.
        local last_absent
        for k, lvl in ipairs(seq) do if lvl == "absent" then last_absent = k end end
        t:assert(last_absent, "netd published absent at the cable pull")
        local since = {}
        for k = last_absent, #seq do since[#since + 1] = seq[k] end
        t:log("published since the pull: " .. list(since))
        for _, lvl in ipairs(since) do
            t:assert(lvl ~= "addressed", "the DHCP path back to routed never published addressed")
        end
        t:assert_eq(since[#since], "routed", "and ended at routed")
        t:assert_eq(network.status(sut).level, "routed", "the machine is routed, above addressed")
        held(t, "pt-x-addressed2", "level routed, after the pull")
    end)
