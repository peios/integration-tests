-- netd §3.1 — Profiles: how netd resolves the profile tree. Every key
-- under `Profiles\` is a profile at every depth, looked up
-- case-insensitively; values inherit per name; `Enabled` is a switch, not
-- a value; every value is read in one of four shapes; an unknown name
-- refuses the generation; a static outside the families is dropped; and a
-- bare profile does nothing. The values table itself (what each value
-- makes netd do) is profile-values.test.lua.
--
-- Harness: the scripted gateway (helpers.gateway) answers DHCP and records
-- what the machine sends; the machine is the whole peinit image with the
-- shipped baseline (`Profiles\default`, `Rules\Interface\wired`). Each test
-- stands eth0 in a profile of its own through one rule of the file's own,
-- `Rules\Interface\pt` (`Interface.Equal = eth0`, Priority 50, above the
-- baseline's 10). Only that rule's `Actions` ever changes, so moving eth0
-- to another profile is one registry write.
--
-- Registry writes go through `reg apply`, one transaction each, not
-- network.write: a value-at-a-time write makes one generation per value,
-- and a profile seen half-written is a refusal or a client restart the
-- test did not ask for. Removing a value is `reg del <key> <value>`.
--
-- What netd made of a profile is read where it shows: `status` (verdict,
-- rule, profile, refusal, dns, search), the kernel through rtnl (the
-- addresses netd placed, and its routes, protocol 200), the DNS snapshot
-- (`Dns.Exclusive`, reachable only there) and the gateway's capture
-- (which clients ran). Most profiles here ask for no DHCP, so moving
-- between them costs no lease.
--
-- A refusal is the contract-grade proof that a generation was built:
-- `status.refusal` is set when one is refused and cleared only when one
-- builds (§3.2). So "this value is accepted" is shown by writing it while
-- a refusal stands and then watching the refusal clear when the cause is
-- removed, and "this value is refused" by the exact reason.
--
-- The wrong-shape message: netd builds it from the lower-cased value name
-- (`profile x: route.metric has the wrong shape`, for `Route.Metric`). The
-- TRM writes `<name> has the wrong shape` without fixing its case, and
-- value names are case-insensitive by its own rule, so it is compared
-- case-insensitively here.
--
-- Own VMs: the tests rewrite the machine's interface layer.

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
-- Local helpers
-- ---------------------------------------------------------------------------

local function full(path)
    if path:match("^Machine\\") then return path end
    return KEY .. "\\" .. path
end

--- One registry transaction. `keys`: `{ {path, {name, type, data}, …}, … }`
--- with paths under Machine\System\Network. Every missing ancestor
--- below Machine\System\Network is named too (reg apply creates only the
--- keys it is given).
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
        for part in rel:gmatch("[^\\]+") do
            acc = acc .. "\\" .. part
            if acc ~= full(rel) then add(acc, {}) end
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

--- Delete one value.
local function delval(path, name)
    local r = network.reg(sut, { "del", full(path), name })
    assert(r.exit_code == 0, "reg del value " .. name .. ": " .. r.stdout .. r.stderr)
end

local function eth0(s) return network.iface(s, "eth0") end

local function show(s)
    local i = eth0(s) or {}
    return string.format("refusal=%s verdict=%s rule=%s profile=%s up=%s addrs=[%s] dns=[%s] search=[%s] lease=%s",
        tostring(s.refusal), tostring(i.verdict), tostring(i.rule), tostring(i.profile),
        tostring(i.up), table.concat(i.addresses or {}, " "), table.concat(i.dns or {}, " "),
        table.concat(i.search or {}, " "), i.lease and i.lease.state or "nil")
end

--- Pump the gateway until `pred(status, eth0)` holds. Raises with the last
--- status on a timeout.
local function wait_for(pred, desc, timeout)
    local s, last = network.serve_until(gw, sut, function(st)
        local i = eth0(st)
        return i ~= nil and pred(st, i)
    end, { timeout = timeout or 30 })
    if not s then error(desc .. ": timed out; last " .. (last and show(last) or "status: none"), 2) end
    return s, eth0(s)
end

local function refused(t, text)
    local s = wait_for(function(st) return st.refusal == text end, "refusal " .. text)
    t:log("refused: " .. s.refusal)
    return s
end

local function refused_ci(t, prefix, tail)
    local s = wait_for(function(st)
        local r = st.refusal and st.refusal:lower()
        return r ~= nil and r:sub(1, #prefix) == prefix:lower() and r:sub(-#tail) == tail:lower()
    end, "refusal " .. prefix .. "…" .. tail)
    t:log("refused: " .. s.refusal)
    return s
end

local function same(a, b)
    if #a ~= #b then return false end
    for k = 1, #a do if a[k] ~= b[k] then return false end end
    return true
end

local function list(l) return "{" .. table.concat(l or {}, ", ") .. "}" end

--- Point Rules\Interface\pt at `actions` (a list).
local function target(actions)
    apply({ { [[Rules\Interface\pt]], { "Interface.Equal", "sz", "eth0" },
        { "Priority", "dword", 50 }, { "Actions", "multi", actions } } })
end

--- netd's routes (protocol 200) out of eth0.
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

--- eth0's IPv4 addresses as "a/p", from the kernel, sorted.
local function v4_addresses(index)
    local out = {}
    for _, a in ipairs(rtnl.addresses_of(sut, index, 4)) do out[#out + 1] = a.address .. "/" .. a.prefix end
    table.sort(out)
    return out
end

--- eth0's scope in the DNS snapshot (a `subscribe` answers with one at
--- once; the connection is then closed and netd drops it at its next send).
local function scope()
    local snap = network.call(sut, { query = "subscribe" })
    for _, sc in ipairs((snap and snap.scopes) or {}) do
        if sc.name == "eth0" then return sc end
    end
end

-- ---------------------------------------------------------------------------
-- Tests
-- ---------------------------------------------------------------------------

local IDX -- eth0's kernel index

test("a bare profile brings its interface up and does nothing else; the friendly default is four seeded values",
    { spec = "netd *profile.bare-profile-does-nothing" }, function(t)
        local s, i = wait_for(function(_, i) return network.bound(i) end, "the baseline lease", 60)
        IDX = i.index
        t:log("baseline: " .. show(s))

        -- The shipped default is four values, each 1, and nothing else.
        local r = network.reg(sut, { "export", full([[Profiles\default]]) })
        r:assert_ok()
        t:log(r.stdout)
        local vals, n = {}, 0
        for name, tok in r.stdout:gmatch("\n%s+(%S+) = ([^\n]+)") do vals[name] = tok; n = n + 1 end
        t:assert_eq(n, 4, "Profiles\\default carries exactly four values")
        for _, name in ipairs({ "Address.Offered", "Address.LinkLocal", "Route.Offered", "Dns.Offered" }) do
            t:assert_eq(vals[name], "dword:1", name .. " = 1 in the seed")
        end

        -- Hold eth0 DOWN first, so "brings it up" is something to see.
        apply({ { [[Profiles\bare]] } })
        target({ "DOWN" })
        wait_for(function(_, i) return i.verdict == "DOWN" and i.up == false end, "eth0 held down")
        gw:serve({ timeout = 1 })
        gw:forget()

        target({ "JOIN(bare)" })
        s, i = wait_for(function(_, i) return i.profile == "bare" and i.up == true end, "eth0 joined to bare")
        t:assert_eq(i.verdict, "JOIN", "verdict")
        t:assert_eq(i.rule, "pt", "attributed to pt")
        t:assert(s.refusal == nil, "no refusal")
        -- Router discovery would wait for a usable link-local address:
        -- wait for the kernel's fe80 to finish DAD, then give any client a
        -- few seconds to speak.
        wait_until(function()
            for _, a in ipairs(rtnl.addresses_of(sut, IDX, 6)) do
                if a.address:match("^fe80") and not a.tentative then return true end
            end
            return false
        end, { timeout = 20, interval = 0.25, desc = "eth0's link-local address usable" })
        gw:serve({ timeout = 5 })
        s, i = wait_for(function() return true end, "status")
        t:log("bare: " .. show(s))
        t:assert_eq(#gw:dhcp_messages(), 0, "no DHCPv4 client ran")
        t:assert_eq(#gw:solicitations(), 0, "no router discovery ran")
        t:assert_eq(#gw:dhcp6_messages(), 0, "no DHCPv6 ran")
        for _, a in ipairs(i.addresses) do
            t:assert(a:match("^fe80:") ~= nil, "only the kernel's link-local address: " .. a)
        end
        t:assert_eq(#netd_routes(IDX), 0, "no netd routes")
        t:assert_eq(#i.dns, 0, "no DNS servers")
        t:assert_eq(#i.search, 0, "no search domains")
        t:assert(i.lease == nil, "no lease")

        -- Families default to both: Address.Offered alone runs DHCPv4 and
        -- router discovery. Route.Offered and Dns.Offered default false, so
        -- the lease brings no route and no servers.
        apply({ { [[Profiles\solo]], { "Address.Offered", "dword", 1 } } })
        gw:forget()
        target({ "JOIN(solo)" })
        s, i = wait_for(function(_, i)
            return i.profile == "solo" and network.bound(i) and #gw:solicitations() > 0
        end, "solo: a lease and a router solicitation", 45)
        t:log("solo: " .. show(s))
        t:assert(network.has_address(i, "10.77.0.50"), "the lease's address is applied")
        t:assert(default_route(IDX, 4) == nil, "no default route without Route.Offered")
        t:assert_eq(#i.dns, 0, "no servers without Dns.Offered, though the lease offered 10.77.0.1")
    end)

test("every key under Profiles is a profile at every depth, named by its path; the Profiles key's own values are ignored",
    { spec = "netd *profile.every-key-is-a-profile" }, function(t)
        -- `Junk.Value` would refuse the generation on any profile.
        apply({
            { [[Profiles]], { "Junk.Value", "dword", 1 } },
            { [[Profiles\deep\er]], { "Dns.Domains", "sz", "er.example" } },
            { [[Profiles\deep\er\est]], { "Dns.Domains", "sz", "est.example" } },
        })
        target({ [[JOIN(deep\er\est)]] })
        local s, i = wait_for(function(_, i) return i.profile == "deep/er/est" end, "joined to deep/er/est")
        t:log(show(s))
        t:assert(s.refusal == nil, "the Profiles key's own Junk.Value is not a profile value")
        t:assert(same(i.search, { "est.example" }), "the third-level key's values: " .. list(i.search))

        target({ [[JOIN(deep\er)]] })
        s, i = wait_for(function(_, i) return i.profile == "deep/er" end, "joined to deep/er")
        t:assert(same(i.search, { "er.example" }), "an intermediate key is a profile too: " .. list(i.search))

        -- The same value on a key below Profiles is a profile's, and refuses.
        apply({ { [[Profiles\deep]], { "Junk.Value", "dword", 1 } } })
        refused(t, "profile deep: unknown value Junk.Value")
        delval([[Profiles\deep]], "Junk.Value")
        s = wait_for(function(st) return st.refusal == nil end, "refusal cleared")
        delval([[Profiles]], "Junk.Value")
        wait_for(function(st) return st.refusal == nil end, "still no refusal")
    end)

test("profiles are looked up case-insensitively and keep their path as written",
    { spec = "netd *profile.lookup-is-case-insensitive" }, function(t)
        apply({ { [[Profiles\CaseTest\Inner]], { "Dns.Domains", "sz", "inner.example" } } })
        target({ "JOIN(casetest/INNER)" })
        local s, i = wait_for(function(_, i) return i.rule == "pt" and i.profile ~= nil
            and i.profile:lower() == "casetest/inner" end, "joined to CaseTest/Inner")
        t:log(show(s))
        t:assert(s.refusal == nil, "JOIN(casetest/INNER) names the profile")
        t:assert_eq(i.profile, "CaseTest/Inner", "status reports the path as written")
        t:assert(same(i.search, { "inner.example" }), "its values: " .. list(i.search))
        local recorded
        wait_until(function()
            recorded = network.get(sut, [[Interfaces\]] .. i.ifid .. [[\Status]], "Profile")
            return recorded == "CaseTest/Inner"
        end, { timeout = 10, interval = 0.25, desc = "Status Profile as written" })
        t:assert_eq(recorded, "CaseTest/Inner", "Interfaces\\<id>\\Status Profile as written")
    end)

test("a profile inherits its ancestors' values per name, a named value replaces the inherited one whole, and a malformed parent refuses at the parent",
    { spec = "netd *profile.inheritance" }, function(t)
        apply({
            { [[Profiles\fam]],
                { "Address.Static", "multi", { "10.77.0.71/24" } },
                { "Route.Gateway", "sz", "10.77.0.1" },
                { "Route.Metric", "dword", 300 },
                { "Dns.Servers", "multi", { "10.9.9.1", "10.9.9.2" } },
                { "Dns.Domains", "multi", { "parent.example" } } },
            -- Value names compare case-insensitively: these override.
            { [[Profiles\fam\kid]],
                { "dns.servers", "multi", { "10.9.9.3" } },
                { "ADDRESS.STATIC", "multi", { "10.77.0.72/24" } } },
        })
        target({ [[JOIN(fam\kid)]] })
        local s, i = wait_for(function(_, i)
            local r = default_route(IDX, 4)
            return i.profile == "fam/kid" and same(v4_addresses(IDX), { "10.77.0.72/24" })
                and r ~= nil and r.metric == 300
        end, "fam/kid applied")
        t:log(show(s))
        t:assert(s.refusal == nil, "no refusal")
        t:assert(same(i.dns, { "10.9.9.3" }), "Dns.Servers replaced whole, not appended: " .. list(i.dns))
        t:assert(same(i.search, { "parent.example" }), "Dns.Domains inherited: " .. list(i.search))
        t:assert(same(v4_addresses(IDX), { "10.77.0.72/24" }), "Address.Static replaced (no .71): "
            .. list(v4_addresses(IDX)))
        local r = default_route(IDX, 4)
        t:assert_eq(r.gateway, "10.77.0.1", "Route.Gateway inherited")
        t:assert_eq(r.metric, 300, "Route.Metric inherited")

        -- A malformed value in the parent refuses at the parent, though the
        -- child names that value itself.
        apply({
            { [[Profiles\fam]], { "Route.Metric", "sz", "lots" } },
            { [[Profiles\fam\kid]], { "route.metric", "dword", 5 } },
        })
        s = refused_ci(t, "profile fam: ", "route.metric has the wrong shape")
        t:assert(s.refusal:find("fam/kid", 1, true) == nil, "the parent is named, not the child: " .. s.refusal)
        apply({ { [[Profiles\fam]], { "Route.Metric", "dword", 300 } } })
        wait_for(function(st) local r2 = default_route(IDX, 4)
            return st.refusal == nil and r2 ~= nil and r2.metric == 5 end, "parent mended; the child's metric")
        delval([[Profiles\fam\kid]], "route.metric")
        wait_for(function() local r2 = default_route(IDX, 4) return r2 ~= nil and r2.metric == 300 end,
            "the child inherits again")
    end)

test("Enabled is a switch: a profile is enabled only when it and every ancestor say so, a disabled one is still parsed",
    { spec = "netd *profile.enabled" }, function(t)
        apply({
            { [[Profiles\dark]], { "Enabled", "dword", 0 }, { "Dns.Domains", "sz", "dark.example" } },
            { [[Profiles\dark\kid]], { "Enabled", "dword", 1 }, { "Dns.Domains", "sz", "kid.example" } },
        })
        target({ [[JOIN(dark\kid)]] })
        -- The child cannot re-enable itself: pt abstains and wired speaks.
        local s, i = wait_for(function(_, i) return i.rule == "wired" end, "pt abstains under a disabled parent")
        t:log(show(s))
        t:assert(s.refusal == nil, "a JOIN of a disabled profile is no fault")
        t:assert_eq(i.profile, "default", "the baseline answers")

        -- Enabled takes the boolean shapes: "On" enables the parent.
        apply({ { [[Profiles\dark]], { "Enabled", "sz", "On" } } })
        s, i = wait_for(function(_, i) return i.rule == "pt" end, "dark enabled")
        t:assert_eq(i.profile, "dark/kid", "joined to dark/kid")
        t:assert(same(i.search, { "kid.example" }), "Enabled is not inherited as a value: " .. list(i.search))

        -- The child's own switch, as a string.
        apply({ { [[Profiles\dark\kid]], { "Enabled", "sz", "NO" } } })
        wait_for(function(_, i) return i.rule == "wired" end, "kid disabled by its own Enabled")

        -- Absent means enabled.
        delval([[Profiles\dark\kid]], "Enabled")
        s, i = wait_for(function(_, i) return i.rule == "pt" end, "kid enabled with Enabled absent")
        t:assert_eq(i.profile, "dark/kid", "joined again")

        -- Anything but a boolean shape refuses.
        apply({ { [[Profiles\dark\kid]], { "Enabled", "sz", "maybe" } } })
        s = wait_for(function(st) return st.refusal ~= nil end, "Enabled = maybe refused")
        t:log("refused: " .. s.refusal)
        t:assert_eq(s.refusal:sub(1, #"profile dark/kid:"), "profile dark/kid:", "the profile is named")
        t:assert(s.refusal:find("Enabled", 1, true) ~= nil, "Enabled is named")

        -- A disabled profile is still parsed: a malformed value refuses.
        apply({ { [[Profiles\dark\kid]], { "Enabled", "dword", 0 } } })
        wait_for(function(st, i) return st.refusal == nil and i.rule == "wired" end, "kid disabled again")
        apply({ { [[Profiles\dark\kid]], { "Mtu.Value", "sz", "big" } } })
        refused_ci(t, "profile dark/kid: ", "mtu.value has the wrong shape")
        delval([[Profiles\dark\kid]], "Mtu.Value")
        wait_for(function(st) return st.refusal == nil end, "refusal cleared")
    end)

test("values are read in four shapes: boolean, number, list and string; any other shape refuses",
    { spec = "netd *profile.value-shapes" }, function(t)
        apply({ { [[Profiles\shape]],
            { "Address.Static", "multi", { "10.77.0.80/24" } },
            { "Route.Gateway", "sz", "10.77.0.1" },
            { "Route.Metric", "dword", 250 } } })
        target({ "JOIN(shape)" })
        local function metric_is(m)
            wait_for(function(st, i)
                local r = default_route(IDX, 4)
                return i.profile == "shape" and st.refusal == nil and r ~= nil and r.metric == m
            end, "metric " .. m)
            t:log("metric " .. m)
        end
        local function shape_refused(name)
            refused_ci(t, "profile shape: ", name .. " has the wrong shape")
        end

        -- number: a DWORD, a QWORD, a string of digits with space around it.
        metric_is(250)
        apply({ { [[Profiles\shape]], { "Route.Metric", "sz", "  260 " } } })
        metric_is(260)
        apply({ { [[Profiles\shape]], { "Route.Metric", "qword", 270 } } })
        metric_is(270)
        apply({ { [[Profiles\shape]], { "Route.Metric", "sz", "-5" } } })
        shape_refused("route.metric")
        apply({ { [[Profiles\shape]], { "Route.Metric", "dword", 280 } } })
        metric_is(280)
        -- 2^32 does not fit 32 bits.
        apply({ { [[Profiles\shape]], { "Route.Metric", "qword", 4294967296 } } })
        shape_refused("route.metric")
        apply({ { [[Profiles\shape]], { "Route.Metric", "dword", 290 } } })
        metric_is(290)

        -- boolean, read through Dns.Exclusive in the DNS snapshot.
        local cases = {
            { "dword", 7, true }, { "dword", 0, false }, { "sz", "YES", true }, { "sz", "off", false },
            { "sz", "True", true }, { "sz", "0", false }, { "sz", "on", true }, { "sz", "No", false },
            { "sz", "1", true }, { "sz", "FALSE", false },
        }
        for _, c in ipairs(cases) do
            apply({ { [[Profiles\shape]], { "Dns.Exclusive", c[1], c[2] } } })
            local got
            wait_for(function(st)
                if st.refusal ~= nil then return false end
                local sc = scope()
                got = sc and sc.exclusive
                return got == c[3]
            end, string.format("Dns.Exclusive %s:%s reads %s", c[1], tostring(c[2]), tostring(c[3])))
            t:log(string.format("Dns.Exclusive = %s:%s -> exclusive %s", c[1], tostring(c[2]), tostring(got)))
        end
        -- Each wrong shape is mended before the next, so each refusal is
        -- this write's and not the last one's still standing.
        for _, bad in ipairs({ { "sz", "maybe" }, { "multi", { "1" } }, { "binary", "01" } }) do
            apply({ { [[Profiles\shape]], { "Dns.Exclusive", bad[1], bad[2] } } })
            shape_refused("dns.exclusive")
            apply({ { [[Profiles\shape]], { "Dns.Exclusive", "dword", 0 } } })
            wait_for(function(st) return st.refusal == nil end, "Dns.Exclusive mended")
        end

        -- list: a multi-string (empty items dropped), one string as one
        -- item, the empty string as the empty list.
        apply({ { [[Profiles\shape]], { "Dns.Servers", "multi", { "10.9.9.1", "", "10.9.9.2", "" } } } })
        local s, i = wait_for(function(_, i) return same(i.dns, { "10.9.9.1", "10.9.9.2" }) end,
            "two servers, the empty items dropped")
        t:log("dns " .. list(i.dns))
        apply({ { [[Profiles\shape]], { "Dns.Servers", "sz", "10.9.9.3" } } })
        s, i = wait_for(function(_, i) return same(i.dns, { "10.9.9.3" }) end, "one string, one server")
        apply({ { [[Profiles\shape]], { "Dns.Servers", "sz", "" } } })
        s, i = wait_for(function(st, i) return st.refusal == nil and #i.dns == 0 end, "the empty string, no servers")
        t:assert_eq(#i.dns, 0, "an empty string is the empty list")
        apply({ { [[Profiles\shape]], { "Dns.Servers", "dword", 1 } } })
        shape_refused("dns.servers")
        apply({ { [[Profiles\shape]], { "Dns.Servers", "sz", "10.9.9.4" } } })
        wait_for(function(st, i) return st.refusal == nil and same(i.dns, { "10.9.9.4" }) end, "Dns.Servers mended")

        -- string, through Address.OnExpiry: a string in any case, or an
        -- integer read as its decimal text, which is then neither Drop nor
        -- Keep. A list or a binary value is the wrong shape.
        apply({ { [[Profiles\shape]], { "Address.OnExpiry", "dword", 5 } } })
        s = wait_for(function(st) return st.refusal ~= nil end, "OnExpiry = 5 refused")
        t:log("refused: " .. s.refusal)
        t:assert(s.refusal:find('"5"', 1, true) ~= nil, "the integer was read as the string \"5\": " .. s.refusal)
        t:assert(s.refusal:lower():find("wrong shape", 1, true) == nil, "an integer is a string's shape")
        apply({ { [[Profiles\shape]], { "Address.OnExpiry", "sz", "KEEP" } } })
        wait_for(function(st) return st.refusal == nil end, "OnExpiry = KEEP accepted")
        for _, bad in ipairs({ { "multi", { "Keep" } }, { "binary", "4b656570" } }) do
            apply({ { [[Profiles\shape]], { "Address.OnExpiry", bad[1], bad[2] } } })
            shape_refused("address.onexpiry")
            apply({ { [[Profiles\shape]], { "Address.OnExpiry", "sz", "drop" } } })
            wait_for(function(st) return st.refusal == nil end, "OnExpiry = drop accepted")
        end
    end)

test("a value name outside the vocabulary refuses the generation; names compare case-insensitively",
    { spec = "netd *profile.unknown-name-refuses" }, function(t)
        apply({ { [[Profiles\shape]], { "Address.Dhcp4", "dword", 1 } } })
        refused(t, "profile shape: unknown value Address.Dhcp4")
        -- A known name in another case, written while the refusal stands…
        apply({ { [[Profiles\shape]], { "hOSTNAME.oFFERED", "dword", 0 } } })
        local s = wait_for(function(st) return st.refusal ~= nil end, "still refused")
        t:assert_eq(s.refusal, "profile shape: unknown value Address.Dhcp4", "only the unknown name is refused")
        -- …is accepted once the unknown one goes: the generation builds.
        delval([[Profiles\shape]], "Address.Dhcp4")
        s = wait_for(function(st) return st.refusal == nil end, "the generation builds")
        t:assert(s.refusal == nil, "hOSTNAME.oFFERED is in the vocabulary")
    end)

test("an Address.Static entry outside the profile's families is dropped without an error",
    { spec = "netd *profile.statics-outside-families-dropped" }, function(t)
        apply({ { [[Profiles\v4only]],
            { "Address.Families", "sz", "ipv4" },
            { "Address.Static", "multi", { "10.77.0.62/24", "fd77::62/64" } } } })
        target({ "JOIN(v4only)" })
        local s, i = wait_for(function(_, i)
            return i.profile == "v4only" and network.has_address(i, "10.77.0.62")
        end, "the IPv4 static applied")
        -- Give a second reconcile the chance to add the other.
        gw:serve({ timeout = 2 })
        s, i = wait_for(function() return true end, "status")
        t:log(show(s))
        t:assert(s.refusal == nil, "no refusal")
        t:assert(not network.has_address(i, "fd77::62"), "the IPv6 static is dropped")
        t:assert(rtnl.address(sut, IDX, "fd77::62") == nil, "and not in the kernel")

        apply({ { [[Profiles\v4only]], { "Address.Families", "sz", "ipv6" } } })
        s, i = wait_for(function(_, i)
            return network.has_address(i, "fd77::62") and not network.has_address(i, "10.77.0.62")
        end, "the families switched")
        t:log(show(s))
        t:assert(s.refusal == nil, "no refusal")
    end)
