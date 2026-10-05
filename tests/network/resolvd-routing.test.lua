-- resolvd §4.4 "Scope routing", with PSPU §6.7 "Scopes" and the parts of
-- "Routing" resolvd meets — which scope each candidate goes to: the
-- exclusive step, the longest search domain and its tie-break, the
-- reverse subnet, the default-route claimant, the fallback scope, and
-- that a candidate's every attempt stays with its scope. The serverless
-- cases (a scope that is up with no servers), where resolvd and PSPU part
-- company, are in resolvd-routing-serverless.test.lua.
--
-- Harness: the scripted gateway (helpers.gateway) with its DNS server
-- (helpers.dns), and a whole Peios (helpers.network). Scopes are made
-- from two dummy links, joined by rules of the file's own to profiles
-- `r5a` (dummy0) and `r5b` (dummy1), beside eth0's DHCP scope. Each
-- scope's server is a different address on the gateway's one wire:
--
--   10.77.0.1  eth0's server (DHCP option 6)
--   10.77.0.2  dummy0's (`Dns.Servers` of r5a)
--   10.77.0.3  dummy1's (`Dns.Servers` of r5b)
--   10.77.0.4  the fallback server (`Dns FallbackServers`)
--
-- The dummies' own addresses are elsewhere (10.91/10.92), so every query
-- leaves by eth0's connected route whatever scope resolvd chose; PSPU
-- §6.7 is DNS routing only. The scope a question went to is therefore
-- the server address the gateway logged it at, and resolvd's own report
-- of it (`via <server> on <interface>` in `resolv query`). Every profile
-- change is one `reg apply` transaction writing all six values, and each
-- test waits for resolvd's `status` (and netd's level) to show the whole
-- configuration before asking anything. Absent names are NXDOMAIN with
-- no SOA, so no negative answer is cached and a name can be asked twice.
--
-- Own VMs: the file loads the dummy module, joins two links of its own,
-- rewrites their profiles throughout, and re-arms eth0's DHCP.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local rtnl = require("helpers.rtnl")

peinit.claim(2)

local RSOCK = "/run/resolvd/resolv.sock"
local SERVER = { E = "10.77.0.1", A = "10.77.0.2", B = "10.77.0.3", F = "10.77.0.4" }
local PROFILE = { dummy0 = [[Profiles\r5a]], dummy1 = [[Profiles\r5b]] }

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
for _, a in ipairs({ SERVER.A, SERVER.B, SERVER.F }) do
    assert(rtnl.add_address(gw.vm, gw.ifindex, a, { prefix = 24 }), "gateway address " .. a)
end
local dhcp = gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })

-- One DNS server for every address. `hook(q, default, ctx, name)` is a
-- test's own override (nil: the zone's answer); `name` is the question
-- name in lower case.
local ZONE = {}
local hook
dns.serve(gw, { zone = ZONE, on = function(q, default, ctx)
    local qn = q.questions[1]
    if not (hook and qn) then return nil end
    return hook(q, default, ctx, qn.name:lower())
end })

local sut = network.boot({ bridges = { lan }, gateway = gw })

-- ---------------------------------------------------------------------------
-- Local helpers
-- ---------------------------------------------------------------------------

local KEY = network.KEY

local function full(path)
    if path:match("^Machine\\") then return path end
    return KEY .. "\\" .. path
end

--- One registry transaction: `{ {path, {name, type, data}, …}, … }`
--- (as profile-values.test.lua). Missing ancestors are named.
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
        out[#out + 1] = string.format("%s(metric %s%s%s servers=[%s] domains=[%s] subnets=[%s] demoted=[%s])",
            tostring(sc.interface), tostring(sc.metric), sc.default_route and " default" or "",
            sc.exclusive and " exclusive" or "", table.concat(sc.servers or {}, " "),
            table.concat(sc.domains or {}, " "), table.concat(sc.subnets or {}, " "),
            table.concat(sc.demoted or {}, " "))
    end
    out[#out + 1] = "fallback=[" .. table.concat(s.fallback_servers or {}, " ") .. "]"
    return table.concat(out, "; ")
end

-- Whether a resolvd status scope is what profile spec `p` says.
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

--- The dummies' profiles' values, all six, as a profile spec says:
--- `addr`, `servers`, `domains` (lists), `exclusive`, `default`
--- (booleans), `metric` (100).
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

-- eth0's DNS servers come from the lease: re-arm the DHCP server with or
-- without option 6 and have netd renew.
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
--- false (no servers) }, and wait until resolvd shows it all and netd has
--- the dummies at the level their addresses give (addressed with a
--- static address, link without).
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

--- Set (a list) or remove (nil) `Dns FallbackServers`, and wait until
--- resolvd's status shows it.
local function fallback(t, servers)
    if servers then
        apply({ { "Dns", list_value("FallbackServers", servers) } })
    else
        network.reg(sut, { "del", full("Dns"), "FallbackServers" })
    end
    local want = servers or {}
    t:assert(wait_until(function()
        local s = network.call(sut, { query = "status" }, { path = RSOCK })
        return s ~= nil and same(s.fallback_servers or {}, want)
    end, { timeout = 15, interval = 0.25, desc = "resolvd's fallback servers" }), "fallback servers taken")
end

local function served(cmd, timeout)
    local p = sut:run_async("sh", { args = { "-c", cmd } })
    gw:serve({ timeout = timeout or 30, until_ = function() return p:status() == "exited" end })
    return p:wait(5)
end

--- Every question the gateway logged for `name` (any case), as
--- "server/transport" in arrival order.
local function asked(name)
    name = name:gsub("%.$", "")
    if name == "" then name = "." end
    local out = {}
    for _, e in ipairs(dns.queries(gw)) do
        local q = e.msg and e.msg.questions[1]
        if q and dns.same_name(q.name, name) then out[#out + 1] = e.server .. "/" .. e.transport end
    end
    return out
end

--- `resolv query <name> <type>`, pumping the gateway while it runs and
--- for a second after (a straggler, or a query to another scope, would
--- land then). Returns the exit status, the summary line's fields and
--- what the gateway was asked.
local function ask(t, name, qtype)
    local r = served("resolv query " .. name .. " " .. (qtype or "A"))
    gw:serve({ timeout = 1 })
    local head = r.stdout:match("^[^\n]*") or ""
    local out = {
        exit = r.exit_code, head = head, stdout = r.stdout, stderr = r.stderr,
        outcome = head:match("^(%S+)"), source = head:match("^%S+%s+(%S+)"),
        via = head:match(" via (%S+)"), on = head:match(" on (%S+)"),
        asked = asked(name),
    }
    t:log(string.format("resolv query %s %s -> exit %s `%s`%s; gateway asked [%s]", name, qtype or "A",
        tostring(r.exit_code), head, r.stderr ~= "" and (" stderr " .. r.stderr) or "",
        table.concat(out.asked, " ")))
    return out
end

--- Assert that the question for `name` went to `server` alone, once, over
--- UDP, and that resolvd reports the answer from that server on `iface`.
local function routed_to(t, name, server, iface, why, qtype)
    local r = ask(t, name, qtype)
    t:assert(same(r.asked, { server .. "/udp" }),
        why .. ": " .. name .. " asked once, at " .. server .. " only (asked [" .. table.concat(r.asked, " ") .. "])")
    t:assert_eq(r.exit, 2, why .. ": the server's NXDOMAIN makes it notfound")
    t:assert_eq(r.source, "dns", why .. ": answered by a server")
    t:assert_eq(r.via, server, why .. ": resolvd names the server")
    t:assert_eq(r.on, iface, why .. ": and the scope's interface")
    return r
end

local function in_addr(a)
    local o = {}
    for x in a:gmatch("%d+") do table.insert(o, 1, x) end
    return table.concat(o, ".") .. ".in-addr.arpa"
end

local function ip6_arpa(a)
    local b, n = gateway.ip6(a), {}
    for i = 16, 1, -1 do
        local x = b:byte(i)
        n[#n + 1] = string.format("%x.%x", x & 0xF, x >> 4)
    end
    return table.concat(n, ".") .. ".ip6.arpa"
end

local function setup(t)
    hook = nil
    if not set_up then
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "eth0 bound a lease")
    end
end

-- ---------------------------------------------------------------------------
-- Step 1
-- ---------------------------------------------------------------------------

test("step 1: an addressed exclusive scope with servers takes every candidate, whatever its name; of several, the lowest metric, then the earliest",
    { spec = "resolvd *engine-routing.step-exclusive resolvd *engine-routing.exclusive-takes-every-candidate" }, function(t)
        setup(t)
        -- dummy0 is exclusive at metric 200, worse than everyone; dummy1
        -- holds a matching search domain at metric 50; eth0 claims the
        -- default route and holds 10.77.0.0/24.
        configure(t, {
            dummy0 = { addr = { "10.91.0.1/24" }, servers = { SERVER.A }, domains = { "vpn.test" },
                exclusive = true, metric = 200 },
            dummy1 = { addr = { "10.92.0.1/24" }, servers = { SERVER.B }, domains = { "eng.corp.test" },
                metric = 50 },
        }, "dummy0 exclusive")
        routed_to(t, "r1.eng.corp.test", SERVER.A, "dummy0", "a name under dummy1's search domain")
        routed_to(t, "r1.other.test", SERVER.A, "dummy0", "a name nobody claims")
        routed_to(t, in_addr("10.77.0.9"), SERVER.A, "dummy0", "the reverse of an address in eth0's subnet", "PTR")
        routed_to(t, in_addr("10.92.0.9"), SERVER.A, "dummy0", "the reverse of an address in dummy1's subnet", "PTR")

        -- Two exclusive scopes: the lower metric takes everything, even a
        -- name under the other's own search domain.
        configure(t, {
            dummy0 = { addr = { "10.91.0.1/24" }, servers = { SERVER.A }, domains = { "vpn.test" },
                exclusive = true, metric = 200 },
            dummy1 = { addr = { "10.92.0.1/24" }, servers = { SERVER.B }, domains = { "eng.corp.test" },
                exclusive = true, metric = 50 },
        }, "both exclusive, dummy1 lower")
        routed_to(t, "r1b.vpn.test", SERVER.B, "dummy1", "two exclusive scopes, dummy1 at the lower metric")
        routed_to(t, "r1b.other.test", SERVER.B, "dummy1", "two exclusive scopes, any name")

        -- Equal metrics: the first in snapshot order, which at equal
        -- metrics is kernel index order (dummy0 first).
        local s = configure(t, {
            dummy0 = { addr = { "10.91.0.1/24" }, servers = { SERVER.A }, domains = { "vpn.test" },
                exclusive = true, metric = 200 },
            dummy1 = { addr = { "10.92.0.1/24" }, servers = { SERVER.B }, domains = { "eng.corp.test" },
                exclusive = true, metric = 200 },
        }, "both exclusive at metric 200")
        local order = {}
        for _, sc in ipairs(s.scopes) do order[#order + 1] = sc.interface end
        t:assert_eq(table.concat(order, ","), "eth0,dummy0,dummy1", "snapshot order puts dummy0 before dummy1")
        routed_to(t, "r1c.eng.corp.test", SERVER.A, "dummy0", "two exclusive scopes at one metric: the earlier")
    end)

-- ---------------------------------------------------------------------------
-- Step 2
-- ---------------------------------------------------------------------------

test("step 2: the scope holding the matching search domain with the most labels takes the candidate, compared label by label and case-insensitively; ties go to the lower metric, then the earlier scope",
    { spec = "resolvd *engine-routing.step-search-domain resolvd *engine-routing.search-domain-tie-break" }, function(t)
        setup(t)
        configure(t, {
            dummy0 = { addr = { "10.91.0.1/24" }, servers = { SERVER.A }, domains = { "corp.test" }, metric = 50 },
            dummy1 = { addr = { "10.92.0.1/24" }, servers = { SERVER.B }, domains = { "eng.corp.test" }, metric = 200 },
        }, "corp.test on dummy0 (50), eng.corp.test on dummy1 (200)")
        routed_to(t, "r2.eng.corp.test", SERVER.B, "dummy1", "three labels beat two, whatever the metric")
        routed_to(t, "R2u.ENG.Corp.TEST", SERVER.B, "dummy1", "the same in another case")
        routed_to(t, "eng.corp.test", SERVER.B, "dummy1", "a name equal to the domain")
        routed_to(t, "r2.xeng.corp.test", SERVER.A, "dummy0", "`xeng` is not the label `eng`: corp.test matches")
        routed_to(t, "r2.corp.test", SERVER.A, "dummy0", "only corp.test matches")
        routed_to(t, "r2.other.test", SERVER.E, "eth0", "no domain matches: on to the default route")

        configure(t, {
            dummy0 = { addr = { "10.91.0.1/24" }, servers = { SERVER.A }, domains = { "corp.test" }, metric = 200 },
            dummy1 = { addr = { "10.92.0.1/24" }, servers = { SERVER.B }, domains = { "corp.test" }, metric = 50 },
        }, "corp.test on both, dummy1 lower")
        routed_to(t, "r2t.corp.test", SERVER.B, "dummy1", "equal labels: the lower metric")

        configure(t, {
            dummy0 = { addr = { "10.91.0.1/24" }, servers = { SERVER.A }, domains = { "corp.test" }, metric = 50 },
            dummy1 = { addr = { "10.92.0.1/24" }, servers = { SERVER.B }, domains = { "CORP.test" }, metric = 50 },
        }, "corp.test on both at metric 50")
        routed_to(t, "r2u.corp.test", SERVER.A, "dummy0", "equal labels and metrics: the earlier scope")
    end)

-- ---------------------------------------------------------------------------
-- Step 3
-- ---------------------------------------------------------------------------

test("step 3: a reverse name goes to the scope holding an address whose prefix contains it, lowest metric then earliest; a search domain ahead of it wins",
    { spec = "resolvd *engine-routing.step-reverse-subnet resolvd *engine-routing.search-domain-beats-subnet" }, function(t)
        setup(t)
        -- eth0 claims the default route at metric 100; dummy0 holds
        -- 10.91.0.0/24 and fd91::/64 at metric 200.
        configure(t, {
            dummy0 = { addr = { "10.91.0.1/24", "fd91::1/64" }, servers = { SERVER.A }, metric = 200 },
            dummy1 = { addr = { "10.92.0.1/24" }, servers = { SERVER.B }, metric = 300 },
        }, "dummy0 holds 10.91.0.1/24 and fd91::1/64")
        routed_to(t, in_addr("10.91.0.7"), SERVER.A, "dummy0", "IPv4 in dummy0's prefix, ahead of the default route", "PTR")
        routed_to(t, ip6_arpa("fd91::7"), SERVER.A, "dummy0", "IPv6 in dummy0's prefix", "PTR")
        routed_to(t, in_addr("10.93.0.7"), SERVER.E, "eth0", "in nobody's prefix: the default route", "PTR")

        -- Both dummies hold 10.91.0.0/24: the lower metric, then the earlier.
        configure(t, {
            dummy0 = { addr = { "10.91.0.1/24" }, servers = { SERVER.A }, metric = 200 },
            dummy1 = { addr = { "10.92.0.1/24", "10.91.0.2/24" }, servers = { SERVER.B }, metric = 150 },
        }, "both hold 10.91.0.0/24, dummy1 lower")
        routed_to(t, in_addr("10.91.0.8"), SERVER.B, "dummy1", "two prefixes contain it: the lower metric", "PTR")
        configure(t, {
            dummy0 = { addr = { "10.91.0.1/24" }, servers = { SERVER.A }, metric = 200 },
            dummy1 = { addr = { "10.92.0.1/24", "10.91.0.2/24" }, servers = { SERVER.B }, metric = 200 },
        }, "both hold 10.91.0.0/24 at one metric")
        routed_to(t, in_addr("10.91.0.9"), SERVER.A, "dummy0", "two prefixes at one metric: the earlier", "PTR")

        -- dummy1 has `91.10.in-addr.arpa` as a search domain: step 2
        -- takes the name before the subnet rule is reached.
        configure(t, {
            dummy0 = { addr = { "10.91.0.1/24" }, servers = { SERVER.A }, metric = 50 },
            dummy1 = { addr = { "10.92.0.1/24" }, servers = { SERVER.B }, domains = { "91.10.in-addr.arpa" },
                metric = 300 },
        }, "dummy1 holds 91.10.in-addr.arpa as a search domain")
        routed_to(t, in_addr("10.91.0.10"), SERVER.B, "dummy1", "the search domain beats dummy0's subnet", "PTR")
    end)

-- ---------------------------------------------------------------------------
-- Step 4
-- ---------------------------------------------------------------------------

test("step 4: among the routable default-route claimants, the lowest metric takes the candidate, then the earliest",
    { spec = "resolvd *engine-routing.step-default-route" }, function(t)
        setup(t)
        -- dummy0 has the lowest metric of all but does not claim; dummy1
        -- claims at 200; eth0 (routed) claims at 100.
        configure(t, {
            dummy0 = { addr = { "10.91.0.1/24" }, servers = { SERVER.A }, metric = 50 },
            dummy1 = { addr = { "10.92.0.1/24" }, servers = { SERVER.B }, default = true, metric = 200 },
        }, "claimants eth0 (100) and dummy1 (200)")
        routed_to(t, "r4.other.test", SERVER.E, "eth0", "the lower-metric claimant, not the lowest metric overall")
        configure(t, {
            dummy0 = { addr = { "10.91.0.1/24" }, servers = { SERVER.A }, metric = 50 },
            dummy1 = { addr = { "10.92.0.1/24" }, servers = { SERVER.B }, default = true, metric = 80 },
        }, "claimants eth0 (100) and dummy1 (80)")
        routed_to(t, "r4b.other.test", SERVER.B, "dummy1", "dummy1 is now the lower-metric claimant")
        configure(t, {
            dummy0 = { addr = { "10.91.0.1/24" }, servers = { SERVER.A }, metric = 50 },
            dummy1 = { addr = { "10.92.0.1/24" }, servers = { SERVER.B }, default = true, metric = 100 },
        }, "claimants eth0 and dummy1, both at 100")
        routed_to(t, "r4c.other.test", SERVER.E, "eth0", "equal metrics: eth0 is earlier in the snapshot")
    end)

-- ---------------------------------------------------------------------------
-- A candidate stays with its scope; demotion does not move it
-- ---------------------------------------------------------------------------

test("every attempt for a candidate, and the TCP retry after a truncated reply, goes to its own scope's servers; when they fail it is unavailable and no other scope, nor the fallback, is asked",
    { spec = "resolvd *engine-routing.candidate-asks-only-its-scope PSPU *nri-resolution.exactly-one-scope-no-fan-out" }, function(t)
        setup(t)
        configure(t, {
            dummy0 = { addr = { "10.91.0.1/24" }, servers = { SERVER.A }, domains = { "corp.test" }, metric = 50 },
            dummy1 = { addr = { "10.92.0.1/24" }, servers = { SERVER.B }, metric = 200 },
        }, "corp.test on dummy0")
        fallback(t, { SERVER.F })
        ZONE["r5ok.corp.test"] = { { type = "A", ttl = 60, data = "10.77.0.85" } }
        hook = function(_, default, ctx, name)
            if name == "r5s.corp.test" then return false end           -- silent everywhere
            if name == "r5t.corp.test" then
                if ctx.transport == "tcp" then return false end         -- close the retry
                default.tc, default.answers = true, {}
                return default
            end
        end

        -- An answered question: one query, to one server.
        local ok = ask(t, "r5ok.corp.test")
        t:assert_eq(ok.exit, 0, "r5ok.corp.test is found")
        t:assert(same(ok.asked, { SERVER.A .. "/udp" }), "found with one query at dummy0's server alone")

        -- A silent server: three attempts, all at dummy0's server.
        local s = ask(t, "r5s.corp.test")
        t:assert_eq(s.exit, 3, "every attempt timed out: unavailable")
        t:assert_eq(s.on, "dummy0", "the attempts were dummy0's scope's")
        t:assert(same(s.asked, { SERVER.A .. "/udp", SERVER.A .. "/udp", SERVER.A .. "/udp" }),
            "three attempts, every one at 10.77.0.2: [" .. table.concat(s.asked, " ") .. "]")

        -- Truncated over UDP, closed over TCP: every transaction, both
        -- transports, at dummy0's server.
        local tr = ask(t, "r5t.corp.test")
        t:assert_eq(tr.exit, 3, "every attempt failed: unavailable")
        local udp, tcp = 0, 0
        for _, a in ipairs(tr.asked) do
            t:assert(a == SERVER.A .. "/udp" or a == SERVER.A .. "/tcp", "asked only at 10.77.0.2: " .. a)
            if a:match("/tcp$") then tcp = tcp + 1 else udp = udp + 1 end
        end
        t:assert_eq(udp, 3, "three UDP attempts")
        t:assert(tcp >= 1, "and the TCP retries went to the same server (" .. tcp .. ")")
        fallback(t, nil)
    end)

test("demotion does not move routing: a scope whose every server is demoted still takes its candidates",
    { spec = "resolvd *engine-routing.demotion-does-not-affect-routing" }, function(t)
        setup(t)
        configure(t, {
            dummy0 = { addr = { "10.91.0.1/24" }, servers = { SERVER.A }, domains = { "corp.test" }, metric = 50 },
            dummy1 = { addr = { "10.92.0.1/24" }, servers = { SERVER.B }, metric = 200 },
        }, "corp.test on dummy0")
        hook = function(_, default, _, name)
            if name == "r6a.corp.test" then default.rcode = dns.RCODE.SERVFAIL; return default end
        end
        local f = ask(t, "r6a.corp.test")
        t:assert_eq(f.exit, 3, "three SERVFAILs: unavailable")
        local st = network.call(sut, { query = "status" }, { path = RSOCK })
        local sc = scope_of(st, "dummy0")
        t:log("after the failures: " .. describe(st))
        t:assert(sc and same(sc.demoted or {}, { SERVER.A }), "dummy0's only server is demoted")
        routed_to(t, "r6b.corp.test", SERVER.A, "dummy0", "the next candidate under corp.test still goes to dummy0")
    end)

-- ---------------------------------------------------------------------------
-- No routable scope; the fallback scope
-- ---------------------------------------------------------------------------

test("with no scope able to take a question and no fallback servers, it is unavailable at once, without a query",
    { spec = "PSPU *nri-resolution.no-scope-is-unavailable-without-query" }, function(t)
        setup(t)
        fallback(t, nil)
        configure(t, { dummy0 = { addr = { "10.91.0.1/24" } }, dummy1 = {}, eth0 = false },
            "no scope has a server")
        local before = #dns.queries(gw)
        local r = ask(t, "r7a.other.test")
        t:assert_eq(r.exit, 3, "unavailable")
        t:assert_eq(r.outcome, "unavailable", "the summary says unavailable")
        t:assert_eq(r.source, "local", "decided locally")
        t:assert(#r.asked == 0, "no server was asked for it")
        local any = {}
        for i = before + 1, #dns.queries(gw) do
            local e = dns.queries(gw)[i]
            any[#any + 1] = (e.msg and e.msg.questions[1] and e.msg.questions[1].name or "?") .. "@" .. e.server
        end
        t:log("every question the gateway saw meanwhile: [" .. table.concat(any, " ") .. "]")
        t:assert(#any == 0, "the gateway saw no question at all")
    end)

test("with no routable scope the fallback scope takes the question: FallbackServers and ExtraSearchDomains; once an interface has a server the fallback takes nothing, and what was cached through it is not consulted",
    { spec = "resolvd *engine-routing.step-fallback resolvd *engine-routing.fallback-unused-while-any-interface-has-a-server PSPU *nri-resolution.fallback-scope-from-registry PSPU *nri-resolution.route-fallback-only-without-interface-servers" },
    function(t)
        setup(t)
        ZONE["r7c.fb.test"] = { { type = "A", ttl = 300, data = "10.77.0.87" } }
        configure(t, { dummy0 = { addr = { "10.91.0.1/24" } }, dummy1 = {}, eth0 = false },
            "no scope has a server")
        apply({ { "Dns", list_value("ExtraSearchDomains", { "fb.test" }) } })
        fallback(t, { SERVER.F })

        local r = ask(t, "r7b.other.test")
        t:assert(same(r.asked, { SERVER.F .. "/udp" }), "asked at the fallback server alone")
        t:assert_eq(r.via, SERVER.F, "resolvd names the fallback server")
        t:assert_eq(r.on, nil, "the fallback scope has no interface")
        local x = ask(t, "r7host")
        t:assert(same(asked("r7host.fb.test"), { SERVER.F .. "/udp" }),
            "a single label is expanded with ExtraSearchDomains and asked at the fallback server")
        t:assert_eq(x.exit, 2, "r7host.fb.test is NXDOMAIN")
        local c = ask(t, "r7c.fb.test")
        t:assert_eq(c.exit, 0, "r7c.fb.test found through the fallback scope, and cached there")
        t:assert_eq(c.via, SERVER.F, "from the fallback server")

        -- eth0's server comes back: the fallback takes nothing more, and
        -- its cached answer is not what answers.
        configure(t, { dummy0 = { addr = { "10.91.0.1/24" } }, dummy1 = {} }, "eth0 has its server again")
        local again = ask(t, "r7c.fb.test")
        t:assert_eq(again.exit, 0, "found")
        t:assert_eq(again.source, "dns", "from a server, not the fallback scope's cache entry")
        t:assert(same(again.asked, { SERVER.F .. "/udp", SERVER.E .. "/udp" }),
            "the second question went to eth0's server, the first having gone to the fallback")
        t:assert_eq(again.on, "eth0", "through eth0's scope")
        routed_to(t, "r7d.other.test", SERVER.E, "eth0", "with eth0 serving, an unclaimed name goes to eth0")
        network.reg(sut, { "del", full("Dns"), "ExtraSearchDomains" })
        fallback(t, nil)
    end)
