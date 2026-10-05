-- resolvd §4.4 "Scope routing" and PSPU §6.7 "Routing", for scopes that
-- are up with no servers. Here resolvd and the contract part company:
--
-- - resolvd routes over **routable** scopes only (level link or better
--   *and* a server, TRM §1.3), so a serverless scope is skipped at every
--   step and the question goes on to another interface;
-- - PSPU §6.2 defines **up** as level link or better alone: a serverless
--   up scope "still takes every routing step it qualifies for, and a
--   question routed to it is `unavailable` without a query".
--
-- The TRM tests assert what resolvd does and pass. The PSPU tests assert
-- the contract and are `known-bug`: PEI-1337 (an exclusive scope with no
-- servers is not exclusive: the VPN leak), PEI-1360 (a default-route
-- claimant with no servers is skipped), and
-- PEI-1360 (the same for the search-domain and
-- subnet steps, not filed).
-- Each known-bug test gathers every observation before asserting, so its
-- log is the evidence whichever assertion fails first.
--
-- Harness: as resolvd-routing.test.lua — two dummy links joined to
-- profiles `r5a` (dummy0) and `r5b` (dummy1) beside eth0's DHCP scope,
-- each scope's server a different address on the gateway's one wire
-- (10.77.0.1 eth0, .2 dummy0, .3 dummy1), so the gateway's log and
-- `resolv query`'s `via … on …` say which scope a question went to. A
-- serverless eth0 is a DHCP lease without option 6, renewed. Every test
-- writes the whole configuration and waits for resolvd's `status` (and
-- netd's level) to show it, so no test depends on the one before.
--
-- Own VMs: the dummy module, two joined links, their profiles rewritten
-- throughout, and eth0's DHCP re-armed.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local rtnl = require("helpers.rtnl")

peinit.claim(2)

local RSOCK = "/run/resolvd/resolv.sock"
local SERVER = { E = "10.77.0.1", A = "10.77.0.2", B = "10.77.0.3" }
local PROFILE = { dummy0 = [[Profiles\r5a]], dummy1 = [[Profiles\r5b]] }

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
for _, a in ipairs({ SERVER.A, SERVER.B }) do
    assert(rtnl.add_address(gw.vm, gw.ifindex, a, { prefix = 24 }), "gateway address " .. a)
end
local dhcp = gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
dns.serve(gw, { zone = {} })
local sut = network.boot({ bridges = { lan }, gateway = gw })

-- ---------------------------------------------------------------------------
-- Local helpers (as resolvd-routing.test.lua)
-- ---------------------------------------------------------------------------

local KEY = network.KEY

local function full(path)
    if path:match("^Machine\\") then return path end
    return KEY .. "\\" .. path
end

--- One registry transaction: `{ {path, {name, type, data}, …}, … }`.
local function apply(keys)
    local doc, seen = { keys = {} }, {}
    local function add(path, values)
        if seen[path] and #values == 0 then return end
        seen[path] = true
        doc.keys[#doc.keys + 1] = { path = path, values = values }
    end
    for _, k in ipairs(keys) do
        local acc = KEY
        for part in k[1]:gmatch("[^\\]+") do
            acc = acc .. "\\" .. part
            if acc ~= full(k[1]) then add(acc, {}) end
        end
        local values = {}
        for i = 2, #k do values[#values + 1] = { name = k[i][1], type = k[i][2], data = k[i][3] } end
        add(full(k[1]), values)
    end
    sut:write_file("/tmp/r5-apply.json", peinit.encode_json(doc))
    local r = sut:run("reg apply /tmp/r5-apply.json")
    assert(r.exit_code == 0, "reg apply failed: " .. r.stdout .. r.stderr)
end

local function list_value(name, items)
    if #items == 0 then return { name, "sz", "" } end
    return { name, "multi", items }
end

local function same(a, b)
    if #a ~= #b then return false end
    for k = 1, #a do if a[k] ~= b[k] then return false end end
    return true
end

local function lower_all(l)
    local out = {}
    for i, v in ipairs(l or {}) do out[i] = v:lower() end
    return out
end

local function scope_of(s, ifname)
    for _, sc in ipairs((s and s.scopes) or {}) do
        if sc.interface == ifname then return sc end
    end
end

local function describe(s)
    if not s then return "no status" end
    local out = {}
    for _, sc in ipairs(s.scopes or {}) do
        out[#out + 1] = string.format("%s(metric %s%s%s servers=[%s] domains=[%s] subnets=[%s])",
            tostring(sc.interface), tostring(sc.metric), sc.default_route and " default" or "",
            sc.exclusive and " exclusive" or "", table.concat(sc.servers or {}, " "),
            table.concat(sc.domains or {}, " "), table.concat(sc.subnets or {}, " "))
    end
    return table.concat(out, "; ")
end

local function scope_matches(sc, p)
    if not same(sc.servers or {}, p.servers or {}) then return false, "servers" end
    if not same(lower_all(sc.domains), lower_all(p.domains)) then return false, "domains" end
    if (sc.exclusive == true) ~= (p.exclusive == true) then return false, "exclusive" end
    if (sc.default_route == true) ~= (p.default == true) then return false, "default_route" end
    if sc.metric ~= (p.metric or 100) then return false, "metric" end
    local subnets = {}
    for _, a in ipairs(sc.subnets or {}) do subnets[a] = true end
    for _, a in ipairs(p.addr or {}) do
        if not subnets[a] then return false, "subnet " .. a end
    end
    return true
end

local function profile_values(p)
    return {
        list_value("Address.Static", p.addr or {}),
        list_value("Dns.Servers", p.servers or {}),
        list_value("Dns.Domains", p.domains or {}),
        { "Dns.Exclusive", "dword", p.exclusive and 1 or 0 },
        { "Dns.Default", "dword", p.default and 1 or 0 },
        { "Route.Metric", "dword", p.metric or 100 },
    }
end

local eth0_serves = true
local function eth0_servers(t, on)
    if eth0_serves == on then return end
    dhcp.dns = on and { SERVER.E } or false
    local r = network.call(sut, { query = "renew", interface = "eth0" })
    t:assert(r and r.ok, "netd accepts a renew of eth0")
    eth0_serves = on
end

local set_up = false

--- Bring the scopes to `cfg` = { dummy0 = spec, dummy1 = spec, eth0 =
--- false (no servers) } and wait until resolvd and netd show it.
local function configure(t, cfg, what)
    local a, b = cfg.dummy0 or {}, cfg.dummy1 or {}
    apply({ { PROFILE.dummy0, table.unpack(profile_values(a)) },
            { PROFILE.dummy1, table.unpack(profile_values(b)) } })
    if not set_up then
        apply({
            { [[Rules\Interface\r5-d0]], { "Interface.Equal", "multi", { "dummy0" } },
                { "Priority", "dword", 20 }, { "Actions", "multi", { "JOIN(r5a)" } } },
            { [[Rules\Interface\r5-d1]], { "Interface.Equal", "multi", { "dummy1" } },
                { "Priority", "dword", 20 }, { "Actions", "multi", { "JOIN(r5b)" } } },
        })
        local mp = sut:run("modprobe dummy numdummies=2")
        t:assert_eq(mp.exit_code, 0, "the dummy module loads: " .. mp.stderr)
        set_up = true
    end
    eth0_servers(t, cfg.eth0 ~= false)
    local want = { dummy0 = a, dummy1 = b }
    local last, why
    local ok = gw:serve({ timeout = 45, until_ = function()
        local s = network.call(sut, { query = "status" }, { path = RSOCK })
        if not (s and s.scopes) then why = "resolvd status"; return false end
        last = s
        local ns = network.call(sut, { query = "status" })
        for ifn, p in pairs(want) do
            local sc = scope_of(s, ifn)
            if not sc then why = ifn .. " has no scope"; return false end
            local m, reason = scope_matches(sc, p)
            if not m then why = ifn .. " " .. reason; return false end
            local i = ns and network.iface(ns, ifn)
            local level = #(p.addr or {}) > 0 and "addressed" or "link"
            if not (i and i.level == level) then
                why = ifn .. " level " .. tostring(i and i.level) .. ", want " .. level
                return false
            end
        end
        local e = scope_of(s, "eth0")
        local servers = cfg.eth0 == false and {} or { SERVER.E }
        if not (e and same(e.servers or {}, servers) and e.default_route == true and e.metric == 100) then
            why = "eth0"
            return false
        end
        return true
    end })
    t:log((what or "configured") .. ": " .. describe(last))
    t:assert(ok, (what or "configured") .. ": resolvd shows the configuration (waiting on " .. tostring(why) .. ")")
    return last
end

local function served(cmd, timeout)
    local p = sut:run_async("sh", { args = { "-c", cmd } })
    gw:serve({ timeout = timeout or 30, until_ = function() return p:status() == "exited" end })
    return p:wait(5)
end

local function asked(name)
    name = name:gsub("%.$", "")
    local out = {}
    for _, e in ipairs(dns.queries(gw)) do
        local q = e.msg and e.msg.questions[1]
        if q and dns.same_name(q.name, name) then out[#out + 1] = e.server .. "/" .. e.transport end
    end
    return out
end

--- `resolv query <name> <type>`, pumping while it runs and for a second
--- after. Returns the exit status, the summary line's fields, and what the
--- gateway was asked for the name.
local function ask(t, name, qtype)
    local r = served("resolv query " .. name .. " " .. (qtype or "A"))
    gw:serve({ timeout = 1 })
    local head = r.stdout:match("^[^\n]*") or ""
    local out = {
        name = name, exit = r.exit_code, head = head,
        outcome = head:match("^(%S+)"), source = head:match("^%S+%s+(%S+)"),
        via = head:match(" via (%S+)"), on = head:match(" on (%S+)"),
        asked = asked(name),
    }
    t:log(string.format("resolv query %s %s -> exit %s `%s`; gateway asked [%s]", name, qtype or "A",
        tostring(r.exit_code), head, table.concat(out.asked, " ")))
    return out
end

--- resolvd's present behaviour: `name` went to `server` alone and the
--- answer names it and `iface`.
local function routed_to(t, name, server, iface, why, qtype)
    local r = ask(t, name, qtype)
    t:assert(same(r.asked, { server .. "/udp" }),
        why .. ": " .. name .. " asked once, at " .. server .. " only (asked [" .. table.concat(r.asked, " ") .. "])")
    t:assert_eq(r.exit, 2, why .. ": the server's NXDOMAIN makes it notfound")
    t:assert_eq(r.via, server, why .. ": resolvd names the server")
    t:assert_eq(r.on, iface, why .. ": and the scope's interface")
    return r
end

--- The contract's answer for a question routed to a scope with no
--- servers: `unavailable`, decided locally, and no query anywhere.
--- Asserted after every observation has been logged.
local function assert_unavailable_without_query(t, r, why)
    t:assert_eq(r.exit, 3, why .. ": " .. r.name .. " is unavailable (resolv exits 3; got `" .. r.head .. "`)")
    t:assert_eq(r.source, "local", why .. ": decided without the network")
    t:assert(#r.asked == 0, why .. ": no server was asked for " .. r.name
        .. " (asked [" .. table.concat(r.asked, " ") .. "])")
end

local function in_addr(a)
    local o = {}
    for x in a:gmatch("%d+") do table.insert(o, 1, x) end
    return table.concat(o, ".") .. ".in-addr.arpa"
end

local function setup(t)
    if not set_up then
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "eth0 bound a lease")
    end
end

-- ---------------------------------------------------------------------------
-- What resolvd does (TRM)
-- ---------------------------------------------------------------------------

test("only routable scopes take part: an up scope with no servers is never chosen, and its search domain, subnet and default-route flag have no effect",
    { spec = "resolvd *engine-routing.only-routable-scopes-take-part" }, function(t)
        setup(t)
        -- dummy0: addressed, no servers, corp.test, claims the default
        -- route at metric 50 (ahead of eth0's 100).
        configure(t, {
            dummy0 = { addr = { "10.91.0.1/24" }, domains = { "corp.test" }, default = true, metric = 50 },
            dummy1 = {},
        }, "dummy0 serverless with a domain, a subnet and the default-route flag")
        routed_to(t, "s1.corp.test", SERVER.E, "eth0", "a name under dummy0's domain")
        routed_to(t, in_addr("10.91.0.7"), SERVER.E, "eth0", "the reverse of an address in dummy0's subnet", "PTR")
        routed_to(t, "s1.other.test", SERVER.E, "eth0", "an unclaimed name, dummy0 being the lower-metric claimant")
    end)

test("an exclusive scope at link, or with no servers, is not exclusive: the first routes as an ordinary scope, the second takes part in nothing",
    { spec = "resolvd *engine-routing.exclusive-without-servers-or-address-not-exclusive" }, function(t)
        setup(t)
        configure(t, {
            dummy0 = { servers = { SERVER.A }, domains = { "vpn.test" }, exclusive = true, metric = 50 },
            dummy1 = {},
        }, "dummy0 exclusive at link, with a server")
        routed_to(t, "s2.other.test", SERVER.E, "eth0", "exclusive at link: an unclaimed name goes to the default route")
        routed_to(t, "s2.vpn.test", SERVER.A, "dummy0", "exclusive at link: step 2 still gives it its own domain")

        configure(t, {
            dummy0 = { addr = { "10.91.0.1/24" }, domains = { "vpn.test" }, exclusive = true, metric = 50 },
            dummy1 = {},
        }, "dummy0 exclusive and addressed, no servers")
        routed_to(t, "s2b.other.test", SERVER.E, "eth0", "exclusive with no servers: an unclaimed name goes to eth0")
        routed_to(t, "s2b.vpn.test", SERVER.E, "eth0", "exclusive with no servers: even its own domain goes to eth0")
    end)

test("step 5 is reached when no routable scope claims the default route, including when the only claimant has no servers: the lowest metric, then the earliest",
    { spec = "resolvd *engine-routing.step-lowest-metric" }, function(t)
        setup(t)
        -- eth0 (routed, so a claimant) has no server; neither dummy claims.
        configure(t, {
            dummy0 = { addr = { "10.91.0.1/24" }, servers = { SERVER.A }, metric = 200 },
            dummy1 = { addr = { "10.92.0.1/24" }, servers = { SERVER.B }, metric = 50 },
            eth0 = false,
        }, "eth0 claims with no server; dummy1 at 50, dummy0 at 200")
        routed_to(t, "s3.other.test", SERVER.B, "dummy1", "the lowest metric with a server")
        configure(t, {
            dummy0 = { addr = { "10.91.0.1/24" }, servers = { SERVER.A }, metric = 200 },
            dummy1 = { addr = { "10.92.0.1/24" }, servers = { SERVER.B }, metric = 200 },
            eth0 = false,
        }, "eth0 claims with no server; both dummies at 200")
        routed_to(t, "s3b.other.test", SERVER.A, "dummy0", "equal metrics: the earlier")
    end)

-- ---------------------------------------------------------------------------
-- What the contract requires (PSPU; known bugs)
-- ---------------------------------------------------------------------------

test("an exclusive scope at addressed takes every question even with no servers: each is unavailable without a query, and no other interface's server is consulted",
    { spec = "PSPU *nri-resolution.route-exclusive-takes-every-question PSPU *nri-resolution.exclusive-excludes-every-other-server",
      tags = { "known-bug" } }, function(t)
        setup(t)
        -- The VPN whose servers have not arrived: dummy0 exclusive and
        -- addressed, no servers yet; dummy1 holds eng.corp.test with a
        -- server; eth0 claims the default route with a server.
        configure(t, {
            dummy0 = { addr = { "10.91.0.1/24" }, domains = { "vpn.test" }, exclusive = true, metric = 200 },
            dummy1 = { addr = { "10.92.0.1/24" }, servers = { SERVER.B }, domains = { "eng.corp.test" }, metric = 50 },
        }, "dummy0 exclusive, addressed, serverless")
        local seen = {
            ask(t, "k1.other.test"),
            ask(t, "k1.eng.corp.test"),
            ask(t, "k1.vpn.test"),
            ask(t, in_addr("10.77.0.9"), "PTR"),
        }
        -- PEI-1337: resolvd ignores the serverless exclusive scope and
        -- routes on: k1.other.test, k1.vpn.test and the PTR go to eth0's
        -- 10.77.0.1, k1.eng.corp.test to dummy1's 10.77.0.3.
        for _, r in ipairs(seen) do
            assert_unavailable_without_query(t, r, "the exclusive scope takes it")
        end
    end)

test("of several exclusive scopes the lowest metric takes the question, with servers or without",
    { spec = "PSPU *nri-resolution.route-several-exclusive-lowest-metric", tags = { "known-bug" } }, function(t)
        setup(t)
        configure(t, {
            dummy0 = { addr = { "10.91.0.1/24" }, exclusive = true, metric = 50 },
            dummy1 = { addr = { "10.92.0.1/24" }, servers = { SERVER.B }, exclusive = true, metric = 200 },
        }, "dummy0 exclusive at 50 without servers, dummy1 exclusive at 200 with one")
        local r = ask(t, "k2.other.test")
        -- PEI-1337: resolvd skips serverless dummy0 and gives the question
        -- to dummy1, the higher-metric exclusive scope (10.77.0.3).
        assert_unavailable_without_query(t, r, "dummy0, the lowest-metric exclusive scope, takes it")
    end)

test("the default-route claimant with the lowest metric takes an unmatched question even with no servers; step 5 is only for when no interface claims",
    { spec = "PSPU *nri-resolution.route-default-route-claimant PSPU *nri-resolution.route-lowest-metric-with-servers",
      tags = { "known-bug" } }, function(t)
        setup(t)
        -- eth0 (routed: the claimant, metric 100) got no DNS server from
        -- DHCP; dummy0 has one and declines the default route
        -- (Dns.Default = 0), at a lower metric.
        configure(t, {
            dummy0 = { addr = { "10.91.0.1/24" }, servers = { SERVER.A }, metric = 50 },
            dummy1 = {},
            eth0 = false,
        }, "eth0 the only claimant, serverless; dummy0 declines with a server")
        local declined = ask(t, "k3.other.test")
        -- And a second claimant with a server, at a higher metric.
        configure(t, {
            dummy0 = { addr = { "10.91.0.1/24" }, servers = { SERVER.A }, metric = 50 },
            dummy1 = { addr = { "10.92.0.1/24" }, servers = { SERVER.B }, default = true, metric = 200 },
            eth0 = false,
        }, "eth0 claims at 100 serverless; dummy1 claims at 200 with a server")
        local outranked = ask(t, "k3b.other.test")
        -- PEI-1360: resolvd skips serverless eth0: k3.other.test goes to
        -- dummy0 (10.77.0.2), which declined the default route, and
        -- k3b.other.test to dummy1 (10.77.0.3), the higher-metric claimant.
        assert_unavailable_without_query(t, declined, "eth0, the only claimant, takes it")
        assert_unavailable_without_query(t, outranked, "eth0, the lowest-metric claimant, takes it")
    end)

test("a serverless up scope still takes steps 2 and 3: the longest matching search domain and the reverse subnet route to it, and the question is unavailable without a query",
    { spec = "PSPU *nri-resolution.route-longest-search-domain PSPU *nri-resolution.route-reverse-by-subnet",
      tags = { "known-bug" } }, function(t)
        setup(t)
        -- A VPN-like dummy0 whose servers have not arrived: addressed,
        -- corp.test, not exclusive; eth0 claims the default route.
        configure(t, {
            dummy0 = { addr = { "10.91.0.1/24" }, domains = { "corp.test" }, metric = 50 },
            dummy1 = {},
        }, "dummy0 serverless with corp.test and 10.91.0.1/24")
        local by_domain = ask(t, "k4.corp.test")
        local by_subnet = ask(t, in_addr("10.91.0.17"), "PTR")
        -- PEI-1360: resolvd skips serverless
        -- dummy0 at steps 2 and 3, and both go to eth0's 10.77.0.1: a
        -- corp.test name leaks to the LAN resolver.
        assert_unavailable_without_query(t, by_domain, "dummy0 holds the longest matching domain")
        assert_unavailable_without_query(t, by_subnet, "dummy0's address contains the named one")
    end)
