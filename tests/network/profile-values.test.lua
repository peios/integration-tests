-- netd §3.1, the values table — what netd does with each profile value:
-- `Address.Families` gating `Address.Offered`'s two clients, the statics
-- of both families, `Route.Gateway`'s last item per family,
-- `Route.Metric`, `Mtu.Value`, `Dns.Servers` and `Dns.Domains` (taken as
-- written), and the offer-taking switches `Route.Offered`, `Dns.Offered`,
-- `Mtu.Offered`, `Hostname.Announce` and `Dns.Default`; the per-value
-- refusals; and that every name in the table is in the vocabulary.
--
-- `Address.LinkLocal`, `Address.Temporary`, `Address.OnExpiry` and
-- `Hostname.Offered` point at behaviour other articles own (§5.5, §6.2,
-- §5.4, §8.4) and their files test it; here they are shown to be accepted
-- names in their shapes.
--
-- Harness: as profile.test.lua — the scripted gateway answers DHCPv4
-- (re-armed for the offer test with an MTU option) and records what the
-- machine sends; eth0 stands in a profile of the file's own through
-- `Rules\Interface\pt` (Interface eth0, Priority 50), whose Actions alone
-- change; every registry write is one `reg apply` transaction. Which
-- clients a profile ran is read from the gateway's capture. To make "no
-- router solicitation since" mean "this profile sent none", eth0 passes
-- through a profile with no clients (`quiet`) before the capture is
-- cleared, so the previous profile's discovery engine is gone first.
--
-- Own VMs: the tests rewrite the machine's interface layer and its MTU,
-- and set the machine's Hostname.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local rtnl = require("helpers.rtnl")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
local sut = network.boot({ bridges = { lan }, gateway = gw })

local KEY = network.KEY

-- ---------------------------------------------------------------------------
-- Local helpers (as profile.test.lua)
-- ---------------------------------------------------------------------------

local function full(path)
    if path == "" then return KEY end
    if path:match("^Machine\\") then return path end
    return KEY .. "\\" .. path
end

--- One registry transaction: `{ {path, {name, type, data}, …}, … }`.
--- Missing ancestors are named; the path "" is Machine\System\Network.
local function apply(keys)
    local doc, seen = { keys = {} }, {}
    local function add(path, values)
        if seen[path] and #values == 0 then return end
        seen[path] = true
        doc.keys[#doc.keys + 1] = { path = path, values = values }
    end
    for _, k in ipairs(keys) do
        local rel = k[1]
        local acc = KEY
        if not rel:match("^Machine\\") then
            for part in rel:gmatch("[^\\]+") do
                acc = acc .. "\\" .. part
                if acc ~= full(rel) then add(acc, {}) end
            end
        end
        local values = {}
        for i = 2, #k do
            local v = k[i]
            local e = { name = v[1], type = v[2] }
            e.data = v[3]
            values[#values + 1] = e
        end
        add(full(rel), values)
    end
    sut:write_file("/tmp/pt-b-apply.json", peinit.encode_json(doc))
    local r = sut:run("reg apply /tmp/pt-b-apply.json")
    assert(r.exit_code == 0, "reg apply failed: " .. r.stdout .. r.stderr)
end

local function delkey(path)
    local r = network.reg(sut, { "del", "-r", full(path) })
    assert(r.exit_code == 0, "reg del -r " .. path .. ": " .. r.stdout .. r.stderr)
end

local function eth0(s) return network.iface(s, "eth0") end

local function show(s)
    local i = eth0(s) or {}
    return string.format("refusal=%s verdict=%s rule=%s profile=%s up=%s addrs=[%s] dns=[%s] search=[%s] lease=%s",
        tostring(s.refusal), tostring(i.verdict), tostring(i.rule), tostring(i.profile),
        tostring(i.up), table.concat(i.addresses or {}, " "), table.concat(i.dns or {}, " "),
        table.concat(i.search or {}, " "), i.lease and i.lease.state or "nil")
end

local function wait_for(pred, desc, timeout)
    local s, last = network.serve_until(gw, sut, function(st)
        local i = eth0(st)
        return i ~= nil and pred(st, i)
    end, { timeout = timeout or 30 })
    if not s then error(desc .. ": timed out; last " .. (last and show(last) or "status: none"), 2) end
    return s, eth0(s)
end

local function same(a, b)
    if #a ~= #b then return false end
    for k = 1, #a do if a[k] ~= b[k] then return false end end
    return true
end

local function list(l) return "{" .. table.concat(l or {}, ", ") .. "}" end

local function target(actions)
    apply({ { [[Rules\Interface\pt]], { "Interface.Equal", "sz", "eth0" },
        { "Priority", "dword", 50 }, { "Actions", "multi", actions } } })
end

local function netd_routes(index, fam)
    local out = {}
    for _, r in ipairs(rtnl.routes_of(sut, index)) do
        if r.protocol == rtnl.RTPROT.NETD and (not fam or r.family == fam) then out[#out + 1] = r end
    end
    return out
end

local function default_route(index, fam)
    for _, r in ipairs(netd_routes(index, fam)) do
        if r.prefix == 0 then return r end
    end
end

local function mtu() return tonumber(sut:read_file("/sys/class/net/eth0/mtu"):match("%d+")) end

local function scope()
    local snap = network.call(sut, { query = "subscribe" })
    for _, sc in ipairs((snap and snap.scopes) or {}) do
        if sc.name == "eth0" then return sc end
    end
end

--- DHCPv4 DISCOVERs and REQUESTs seen since the last forget.
local function asks()
    local out = {}
    for _, m in ipairs(gw:dhcp_messages()) do
        if m.type == gateway.DHCP.DISCOVER or m.type == gateway.DHCP.REQUEST then out[#out + 1] = m end
    end
    return out
end

--- Stand eth0 in `quiet` (no clients), let the old clients' last words
--- arrive, then clear the capture.
local function quiet_then_forget()
    target({ "JOIN(quiet)" })
    wait_for(function(_, i) return i.profile == "quiet" and i.lease == nil end, "eth0 quiet")
    gw:serve({ timeout = 1 })
    gw:forget()
end

local IDX

-- ---------------------------------------------------------------------------
-- Tests
-- ---------------------------------------------------------------------------

test("Address.Offered runs DHCPv4 while IPv4 is in Address.Families and router discovery while IPv6 is; an empty list is neither",
    { spec = "netd *profile.values-as-tabled" }, function(t)
        local _, i = wait_for(function(_, i) return network.bound(i) end, "the baseline lease", 60)
        IDX = i.index
        apply({
            { [[Profiles\quiet]] },
            { [[Profiles\fam4]], { "Address.Offered", "dword", 1 }, { "Address.Families", "sz", "IPv4" } },
            { [[Profiles\fam6]], { "Address.Offered", "dword", 1 }, { "Address.Families", "multi", { "IPV6" } } },
            { [[Profiles\fam0]], { "Address.Offered", "dword", 1 }, { "Address.Families", "sz", "" } },
        })

        quiet_then_forget()
        target({ "JOIN(fam4)" })
        local s
        s, i = wait_for(function(_, i) return i.profile == "fam4" and network.bound(i) end, "fam4 bound", 45)
        gw:serve({ timeout = 3 })
        t:log("fam4: " .. show(s) .. string.format(" asks=%d rs=%d", #asks(), #gw:solicitations()))
        t:assert(#asks() > 0, "IPv4 only: the DHCPv4 client ran")
        t:assert_eq(#gw:solicitations(), 0, "IPv4 only: no router solicitation")

        quiet_then_forget()
        target({ "JOIN(fam6)" })
        s, i = wait_for(function(_, i) return i.profile == "fam6" and #gw:solicitations() > 0 end,
            "fam6 solicits routers", 30)
        gw:serve({ timeout = 3 })
        s, i = wait_for(function() return true end, "status")
        t:log("fam6: " .. show(s) .. string.format(" asks=%d rs=%d", #asks(), #gw:solicitations()))
        t:assert_eq(#asks(), 0, "IPv6 only: no DHCPv4 DISCOVER or REQUEST")
        t:assert(i.lease == nil, "IPv6 only: no lease")

        quiet_then_forget()
        target({ "JOIN(fam0)" })
        s, i = wait_for(function(_, i) return i.profile == "fam0" end, "fam0 joined")
        gw:serve({ timeout = 5 })
        t:log("fam0: " .. show(s) .. string.format(" asks=%d rs=%d", #asks(), #gw:solicitations()))
        t:assert_eq(#asks(), 0, "empty families: no DHCPv4")
        t:assert_eq(#gw:solicitations(), 0, "empty families: no router discovery")
        t:assert(s.refusal == nil, "an empty Address.Families is no fault")
    end)

test("Address.Static applies both families; Route.Gateway's last IPv4 and IPv6 items are the gateways; Route.Metric, Mtu.Value, Dns.Servers and Dns.Domains as written",
    { spec = "netd *profile.values-as-tabled" }, function(t)
        apply({ { [[Profiles\stat]],
            { "Address.Static", "multi", { "10.77.0.61/24", "fd77::61/64" } },
            { "Route.Gateway", "multi", { "10.77.0.9", "fd77::9", "10.77.0.1", "fd77::1" } },
            { "Route.Metric", "dword", 321 },
            { "Mtu.Value", "dword", 1400 },
            { "Dns.Servers", "multi", { "10.9.9.1", "fd99::1" } },
            -- Nothing validates a domain.
            { "Dns.Domains", "multi", { "Not A Domain!!", "corp.example" } } } })
        target({ "JOIN(stat)" })
        local s, i = wait_for(function(_, i)
            local r4, r6 = default_route(IDX, 4), default_route(IDX, 6)
            return i.profile == "stat" and network.has_address(i, "10.77.0.61") and network.has_address(i, "fd77::61")
                and r4 ~= nil and r6 ~= nil and mtu() == 1400
        end, "stat applied")
        t:log("stat: " .. show(s))
        t:assert(s.refusal == nil, "no refusal")
        local a4, a6 = rtnl.address(sut, IDX, "10.77.0.61"), rtnl.address(sut, IDX, "fd77::61")
        t:assert_eq(a4.prefix, 24, "10.77.0.61/24")
        t:assert_eq(a6.prefix, 64, "fd77::61/64")
        local r4, r6 = default_route(IDX, 4), default_route(IDX, 6)
        t:assert_eq(r4.gateway, "10.77.0.1", "the last IPv4 item is the IPv4 gateway")
        t:assert_eq(r6.gateway, "fd77::1", "the last IPv6 item is the IPv6 gateway")
        t:assert_eq(r4.metric, 321, "Route.Metric on the IPv4 default route")
        t:assert_eq(r6.metric, 321, "Route.Metric on the IPv6 default route")
        for _, r in ipairs(netd_routes(IDX)) do
            t:log(string.format("netd route %s/%d via %s metric %d", r.dst, r.prefix, tostring(r.gateway), r.metric))
            t:assert(r.gateway ~= "10.77.0.9" and r.gateway ~= "fd77::9", "no route via an earlier item")
        end
        t:assert_eq(mtu(), 1400, "Mtu.Value set the link's MTU")
        t:assert(same(i.dns, { "10.9.9.1", "fd99::1" }), "Dns.Servers, either family: " .. list(i.dns))
        t:assert(same(i.search, { "Not A Domain!!", "corp.example" }), "Dns.Domains as written: " .. list(i.search))

        -- Put the MTU back for what follows.
        apply({ { [[Profiles\stat]], { "Mtu.Value", "dword", 1500 } } })
        wait_for(function() return mtu() == 1500 end, "MTU 1500 again")
    end)

test("a value that does not parse for its row refuses the generation: Families, Static, OnExpiry, Gateway, Mtu.Value below 68, Dns.Servers",
    { spec = "netd *profile.values-as-tabled" }, function(t)
        local cases = {
            { "Address.Families", "multi", { "ipv4", "ipx" } },
            { "Address.Static", "sz", "10.77.0.61/33" },
            { "Address.Static", "sz", "fd77::61/129" },
            { "Address.Static", "sz", "10.77.0.61" },
            { "Address.OnExpiry", "sz", "hold" },
            { "Route.Gateway", "multi", { "10.77.0.1", "gateway" } },
            { "Mtu.Value", "dword", 67 },
            { "Dns.Servers", "multi", { "10.9.9.1", "ns1.example" } },
        }
        for _, c in ipairs(cases) do
            apply({ { [[Profiles\bad]], c } })
            local s = wait_for(function(st) return st.refusal ~= nil end, "refusal for " .. c[1])
            t:log(string.format("%s = %s -> %s", c[1], type(c[3]) == "table" and list(c[3]) or tostring(c[3]), s.refusal))
            t:assert_eq(s.refusal:sub(1, #"profile bad: "), "profile bad: ", "the profile is named")
            t:assert(s.refusal:lower():find(c[1]:lower(), 1, true) ~= nil, "the value is named: " .. s.refusal)
            delkey([[Profiles\bad]])
            wait_for(function(st) return st.refusal == nil end, "refusal cleared")
        end
        -- The boundary that is not refused: 68 would cost the link its IPv6
        -- (below 1280), so the accepted side is shown at 1280.
        -- Written beside an unknown name, so the generation is refused until
        -- that goes; then it builds, with 1280 in it.
        apply({ { [[Profiles\bad]], { "Bogus.Name", "dword", 1 }, { "Mtu.Value", "dword", 1280 } } })
        local s = wait_for(function(st) return st.refusal ~= nil end, "a refusal to clear")
        t:assert_eq(s.refusal, "profile bad: unknown value Bogus.Name", "refused for the stranger alone")
        local r = network.reg(sut, { "del", full([[Profiles\bad]]), "Bogus.Name" })
        assert(r.exit_code == 0)
        s = wait_for(function(st) return st.refusal == nil end, "Mtu.Value 1280 accepted")
        t:assert(s.refusal == nil, "Mtu.Value 1280 is accepted")
        delkey([[Profiles\bad]])
    end)

test("the offer switches: Route.Offered, Dns.Offered, Mtu.Offered, Hostname.Announce and Dns.Default",
    { spec = "netd *profile.values-as-tabled" }, function(t)
        -- The lease offers a router, a server and an MTU of 1420.
        gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600, options = { { 26, gateway.opt.u16(1420) } } })
        apply({
            { "", { "Hostname", "sz", "pt-b-host" } },
            { [[Profiles\plain]], { "Address.Offered", "dword", 1 }, { "Address.Families", "sz", "ipv4" },
                { "Dns.Servers", "sz", "10.9.9.9" } },
            { [[Profiles\offer]], { "Address.Offered", "dword", 1 }, { "Address.Families", "sz", "ipv4" },
                { "Dns.Servers", "sz", "10.9.9.9" },
                { "Route.Offered", "dword", 1 }, { "Dns.Offered", "dword", 1 }, { "Mtu.Offered", "dword", 1 },
                { "Hostname.Announce", "dword", 1 } },
        })

        -- Without the switches the lease is taken for its address alone.
        quiet_then_forget()
        target({ "JOIN(plain)" })
        local s, i = wait_for(function(_, i) return i.profile == "plain" and network.bound(i) end, "plain bound", 45)
        t:log("plain: " .. show(s) .. " mtu=" .. mtu())
        t:assert(network.has_address(i, "10.77.0.50"), "the lease's address")
        t:assert(default_route(IDX, 4) == nil, "no default route without Route.Offered")
        t:assert(same(i.dns, { "10.9.9.9" }), "the profile's server only, without Dns.Offered: " .. list(i.dns))
        t:assert_eq(mtu(), 1500, "the lease's MTU not taken without Mtu.Offered")
        for _, m in ipairs(asks()) do
            t:assert(m.opt[12] == nil, "no option 12 without Hostname.Announce")
        end

        quiet_then_forget()
        target({ "JOIN(offer)" })
        s, i = wait_for(function(_, i) return i.profile == "offer" and network.bound(i)
            and default_route(IDX, 4) ~= nil and mtu() == 1420 end, "offer bound", 45)
        t:log("offer: " .. show(s) .. " mtu=" .. mtu())
        local r = default_route(IDX, 4)
        t:assert_eq(r.gateway, "10.77.0.1", "Route.Offered: the lease's router is the default route")
        t:assert_eq(r.metric, 100, "at the wired default metric")
        t:assert(same(i.dns, { "10.9.9.9", "10.77.0.1" }), "Dns.Offered: the network's servers after the profile's: "
            .. list(i.dns))
        t:assert_eq(mtu(), 1420, "Mtu.Offered: the lease's MTU")
        local n = 0
        for _, m in ipairs(asks()) do
            n = n + 1
            t:assert_eq(m.opt[12], "pt-b-host", "Hostname.Announce: option 12 carries the Hostname")
        end
        t:assert(n > 0, "the client asked")
        local sc
        wait_for(function() sc = scope(); return sc ~= nil and sc.level == "routed" end, "eth0 routed in the snapshot")
        t:assert_eq(sc.default_route, true, "Dns.Default absent follows the level: routed")

        apply({ { [[Profiles\offer]], { "Dns.Default", "dword", 0 } } })
        wait_for(function(_, i)
            sc = scope()
            return network.bound(i) and sc ~= nil and sc.level == "routed" and sc.default_route == false
        end, "Dns.Default = 0", 45)
        t:assert_eq(sc.default_route, false, "Dns.Default present sets the flag, whatever the level")

        -- Put the MTU back for the record.
        apply({ { [[Profiles\offer]], { "Mtu.Value", "dword", 1500 } } })
        wait_for(function() return mtu() == 1500 end, "MTU 1500 again", 45)
    end)

test("every name in the table is in the vocabulary, in any case",
    { spec = "netd *profile.values-as-tabled" }, function(t)
        local values = {
            { "Address.Offered", "dword", 0 }, { "Address.Families", "multi", { "ipv4", "ipv6" } },
            { "Address.Static", "multi", { "10.99.0.1/24", "fd99::1/64" } },
            { "Address.LinkLocal", "dword", 1 }, { "Address.Temporary", "sz", "yes" },
            { "Address.OnExpiry", "sz", "Keep" }, { "Route.Offered", "dword", 1 },
            { "Route.Gateway", "multi", { "10.99.0.254", "fd99::fe" } }, { "Route.Metric", "dword", 10 },
            { "Mtu.Offered", "dword", 1 }, { "Mtu.Value", "dword", 1280 },
            { "Hostname.Announce", "dword", 1 }, { "Hostname.Offered", "dword", 1 },
            { "Dns.Offered", "dword", 1 }, { "Dns.Servers", "multi", { "10.99.0.53" } },
            { "Dns.Domains", "multi", { "vocab.example" } }, { "DNS.DEFAULT", "dword", 1 },
            { "dns.exclusive", "dword", 0 },
            -- The one outside it, so the generation is refused until it goes.
            { "Bogus.Name", "dword", 1 },
        }
        t:assert_eq(#values, 19, "the table's eighteen names, and one more")
        local key = { [[Profiles\vocab]] }
        for _, v in ipairs(values) do key[#key + 1] = v end
        apply({ key })
        local s = wait_for(function(st) return st.refusal ~= nil end, "Bogus.Name refused")
        t:assert_eq(s.refusal, "profile vocab: unknown value Bogus.Name", "only the stranger is refused")
        local r = network.reg(sut, { "del", full([[Profiles\vocab]]), "Bogus.Name" })
        assert(r.exit_code == 0)
        s = wait_for(function(st) return st.refusal == nil end, "the eighteen accepted")
        t:assert(s.refusal == nil, "every name in the table is accepted")
    end)
