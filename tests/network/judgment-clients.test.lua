-- netd §3.3 — what a verdict does: a change of outcome (a different
-- verdict, or the same profile edited) stops the interface's clients and
-- starts them again; DOWN holds the link down with nothing on it; IGNORE
-- plans nothing and so leaves what netd gave the interface where it is;
-- and a conflict — two rules tied on priority naming different profiles
-- — ignores the interface and names both rules.
--
-- Harness: the scripted gateway answers DHCPv4 and router solicitations
-- (a prefix fd77::/64 for SLAAC), and records what the machine sends, so
-- a client stopping shows as a RELEASE and a client starting as a fresh
-- REQUEST and router solicitation. The machine is the whole peinit image
-- with the shipped baseline. Every registry write is one `reg apply`
-- transaction. The kernel's view (rtnl) shows what netd left or removed.
--
-- The gateway answers only while the test pumps. The change-of-outcome
-- test uses that: after the edit it watches the kernel *without* pumping,
-- so the old lease's address and the old SLAAC address are seen to go
-- before any new answer could bring them back.
--
-- The conflict: a tie written at runtime is refused (§3.2), so it is
-- written, refused, and then netd is restarted. A generation taken at
-- startup is not checked for ties (§2.1), so the restarted netd judges
-- eth0 against the tie and meets the conflict.
--
-- Own VMs: the tests rewrite the interface layer and restart netd.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local rtnl = require("helpers.rtnl")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
gw:router({ prefixes = { { prefix = "fd77::", len = 64 } } })
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
--- Missing ancestors are named.
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
            values[#values + 1] = { name = v[1], type = v[2], data = v[3] }
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

local function delval(path, name)
    local r = network.reg(sut, { "del", full(path), name })
    assert(r.exit_code == 0, "reg del value " .. name .. ": " .. r.stdout .. r.stderr)
end

local function eth0(s) return network.iface(s, "eth0") end

local function show(s)
    local i = eth0(s) or {}
    return string.format("refusal=%s verdict=%s rule=%s profile=%s up=%s warning=%s addrs=[%s] lease=%s",
        tostring(s.refusal), tostring(i.verdict), tostring(i.rule), tostring(i.profile), tostring(i.up),
        tostring(i.warning), table.concat(i.addresses or {}, " "), i.lease and i.lease.state or "nil")
end

local function wait_for(pred, desc, timeout)
    local s, last = network.serve_until(gw, sut, function(st)
        local i = eth0(st)
        return i ~= nil and pred(st, i)
    end, { timeout = timeout or 30 })
    if not s then error(desc .. ": timed out; last " .. (last and show(last) or "status: none"), 2) end
    return s, eth0(s)
end

local function pt(actions)
    apply({ { [[Rules\Interface\pt]], { "Interface.Equal", "sz", "eth0" }, { "Priority", "dword", 50 },
        { "Actions", "multi", actions } } })
end

local IDX

--- The kernel's global IPv6 addresses on eth0 (SLAAC's), as text.
local function global6()
    local out = {}
    for _, a in ipairs(rtnl.addresses_of(sut, IDX, 6)) do
        if not a.address:match("^fe80") then out[#out + 1] = a.address end
    end
    return out
end

local function has4(addr) return rtnl.address(sut, IDX, addr) ~= nil end

local function default4()
    for _, r in ipairs(rtnl.routes_of(sut, IDX)) do
        if r.protocol == rtnl.RTPROT.NETD and r.family == 4 and r.prefix == 0 then return r end
    end
end

local function netd_routes()
    local out = {}
    for _, r in ipairs(rtnl.routes_of(sut, IDX)) do
        if r.protocol == rtnl.RTPROT.NETD then out[#out + 1] = r end
    end
    return out
end

local function asks()
    local out = {}
    for _, m in ipairs(gw:dhcp_messages()) do
        if m.type == gateway.DHCP.DISCOVER or m.type == gateway.DHCP.REQUEST then out[#out + 1] = m end
    end
    return out
end

--- Fully up under default: a lease, a SLAAC address and netd's route.
local function settled(desc)
    return wait_for(function(_, i)
        return i.profile == "default" and network.bound(i) and #global6() > 0 and default4() ~= nil
    end, desc or "joined, leased and autoconfigured", 60)
end

-- ---------------------------------------------------------------------------
-- Tests
-- ---------------------------------------------------------------------------

test("a change of outcome restarts the clients: an edit of the standing profile releases the lease and drops the SLAAC address; a new rule with the same outcome does not",
    { spec = "netd *judgment.change-restarts-clients" }, function(t)
        local _, i0 = wait_for(function() return true end, "status", 60)
        IDX = i0.index
        local s, i = settled()
        local slaac = global6()
        t:log("settled: " .. show(s) .. " slaac=" .. table.concat(slaac, " "))

        -- Same verdict, same profile, another rule: no restart.
        gw:forget()
        pt({ "JOIN(default)" })
        s, i = wait_for(function(_, i) return i.rule == "pt" end, "pt speaks")
        gw:serve({ timeout = 4 })
        t:assert_eq(#gw:dhcp_messages(gateway.DHCP.RELEASE), 0, "same outcome: no RELEASE")
        t:assert_eq(#asks(), 0, "same outcome: no new DHCP exchange")
        t:assert_eq(#gw:solicitations(), 0, "same outcome: no new router solicitation")
        t:assert(has4("10.77.0.50"), "the address stays")
        t:assert_eq(table.concat(global6(), " "), table.concat(slaac, " "), "the SLAAC address stays")

        -- Edit a value of the profile eth0 stands in. Do not pump: no new
        -- answer can arrive, so what goes is seen to go.
        gw:forget()
        apply({ { [[Profiles\default]], { "Dns.Domains", "sz", "edit.example" } } })
        wait_until(function() return not has4("10.77.0.50") and #global6() == 0 end,
            { timeout = 20, interval = 0.25, desc = "the lease's address and the SLAAC address removed" })
        t:log("after the edit, unpumped: v4 10.77.0.50 gone, global v6 gone")

        s, i = settled("the clients start again under the edited profile")
        t:log("again: " .. show(s) .. " slaac=" .. table.concat(global6(), " "))
        local releases = gw:dhcp_messages(gateway.DHCP.RELEASE)
        t:assert_eq(#releases, 1, "one RELEASE")
        t:assert_eq(releases[1].ciaddr, "10.77.0.50", "for the lease it held")
        local after = 0
        for _, m in ipairs(asks()) do
            if m.at >= releases[1].at then after = after + 1 end
        end
        t:assert(after > 0, "a new exchange followed the RELEASE")
        t:assert(#gw:solicitations() > 0, "router discovery started again")
        t:assert_eq(i.search[1], "edit.example", "against the new profile")
        t:assert_eq(i.rule, "pt", "the verdict's rule is unchanged")

        delval([[Profiles\default]], "Dns.Domains")
        delkey([[Rules\Interface\pt]])
        settled("back to the baseline")
    end)

test("DOWN keeps the link down with no addresses, no netd routes and no clients; JOIN brings it up with the profile's",
    { spec = "netd *judgment.verdict-effects" }, function(t)
        settled()
        pt({ "DOWN" })
        local s, i = wait_for(function(_, i) return i.verdict == "DOWN" and i.up == false end, "held down")
        wait_until(function() return not has4("10.77.0.50") end,
            { timeout = 10, interval = 0.25, desc = "the leased address removed" })
        gw:serve({ timeout = 1 })
        gw:forget()
        gw:serve({ timeout = 5 })
        s, i = wait_for(function() return true end, "status")
        t:log("down: " .. show(s))
        local flags = tonumber(sut:read_file("/sys/class/net/eth0/flags"):match("0x%x+"))
        t:assert(flags & 1 == 0, "the link is administratively down")
        t:assert_eq(#rtnl.addresses_of(sut, IDX, 4), 0, "no IPv4 address")
        t:assert_eq(#global6(), 0, "no global IPv6 address")
        t:assert_eq(#netd_routes(), 0, "no netd routes")
        t:assert_eq(#gw:dhcp_messages(), 0, "no DHCPv4 client")
        t:assert_eq(#gw:solicitations(), 0, "no router discovery")
        t:assert(i.lease == nil, "no lease")

        -- JOIN again: up, clients started as default asks, its addresses
        -- and routes.
        pt({ "JOIN(default)" })
        s, i = settled("joined again")
        t:log("joined: " .. show(s))
        t:assert_eq(i.up, true, "up")
        t:assert_eq(default4().gateway, "10.77.0.1", "the profile's default route")
        t:assert(#asks() > 0 and #gw:solicitations() > 0, "both clients ran")
    end)

test("an IGNOREd interface is left exactly as it is: what netd gave it stays, and nothing is planned for it",
    { spec = "netd *judgment.ignore-leaves-what-was-there" }, function(t)
        settled()
        local slaac = global6()
        gw:forget()
        pt({ "IGNORE" })
        local s, i = wait_for(function(_, i) return i.verdict == "IGNORE" end, "ignored")
        -- The client is stopped (its RELEASE), but the address it held is
        -- not removed: nothing desires its removal.
        wait_for(function() return #gw:dhcp_messages(gateway.DHCP.RELEASE) > 0 end, "the RELEASE")
        -- Something foreign, which a JOINed interface's reconcile would remove.
        assert(rtnl.add_address(sut, IDX, "10.77.0.99", { prefix = 24 }))
        local r = network.call(sut, { query = "reconcile" })
        t:assert(r and r.ok, "a full pass")
        gw:serve({ timeout = 4 })
        s, i = wait_for(function() return true end, "status")
        t:log("ignored: " .. show(s))
        t:assert(i.lease == nil, "the client is gone")
        t:assert_eq(#asks(), 0, "and no new one started")
        t:assert(has4("10.77.0.50"), "the leased address stays")
        local d = default4()
        t:assert(d ~= nil and d.gateway == "10.77.0.1", "netd's default route stays")
        t:assert_eq(table.concat(global6(), " "), table.concat(slaac, " "), "the SLAAC address stays")
        t:assert(has4("10.77.0.99"), "a foreign address is left alone")
        t:assert_eq(i.up, true, "the link is left up")

        delkey([[Rules\Interface\pt]])
        s, i = settled("joined again")
        -- Contrast: joined, the foreign address is reconciled away.
        wait_until(function() return not has4("10.77.0.99") end,
            { timeout = 10, interval = 0.25, desc = "the foreign address removed once joined" })
    end)

test("a conflict ignores the interface, attributes it to both rules, warns, and logs once",
    { spec = "netd *judgment.conflict-ignores-and-names-both" }, function(t)
        local s, i = settled()
        local ifid = i.ifid
        apply({
            { [[Profiles\rival]] },
            { [[Rules\Interface\rival]], { "Interface.Kind.Equal", "sz", "wired" }, { "Priority", "dword", 10 },
                { "Actions", "multi", { "JOIN(rival)" } } },
        })
        wait_for(function(st) return st.refusal == "rules rival vs wired tie on interface eth0" end,
            "refused at runtime")
        gw:forget()
        network.restart_netd(sut)
        s, i = wait_for(function(_, i) return i.rule == "rival vs wired" end, "the restarted netd meets the conflict")
        for _ = 1, 3 do
            local r = network.call(sut, { query = "reconcile" })
            t:assert(r and r.ok, "a full pass")
        end
        gw:serve({ timeout = 4 })
        s, i = wait_for(function() return true end, "status")
        t:log("conflict: " .. show(s))
        t:assert(i.verdict == nil, "no verdict")
        t:assert(i.profile == nil, "no profile: IGNORE")
        t:assert_eq(i.warning, "rules rival vs wired tie; the interface is ignored", "the warning")
        t:assert(s.refusal == nil, "taken at startup, not refused")
        t:assert_eq(#asks(), 0, "no DHCPv4 client")
        t:assert(has4("10.77.0.50"), "IGNORE: the address netd gave it stays")
        local rule, verdict
        wait_until(function()
            rule = network.get(sut, [[Interfaces\]] .. ifid .. [[\Status]], "Rule")
            verdict = network.get(sut, [[Interfaces\]] .. ifid .. [[\Status]], "Verdict")
            return rule == "rival vs wired" and verdict == nil
        end, { timeout = 10, interval = 0.25, desc = "Status Rule names both, Verdict removed" })
        local warned = 0
        for _, l in ipairs(network.logs(sut, { take = 400 })) do
            if l:find("rules rival vs wired tie; ignoring it", 1, true) then
                warned = warned + 1
                t:log("log: " .. l)
                t:assert(l:find("warn:", 1, true) ~= nil, "a warning")
            end
        end
        t:assert_eq(warned, 1, "logged once, the first time, over several passes")

        delkey([[Rules\Interface\rival]])
        delkey([[Profiles\rival]])
        s, i = settled("joined again once the tie is gone")
        t:assert(i.warning == nil, "the warning is gone")
    end)
