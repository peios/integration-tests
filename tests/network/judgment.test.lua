-- netd §3.3 — Judging an interface: the facts an interface is judged on,
-- when it is judged, that loopback never is, and how the verdict and its
-- attribution are read off the evaluation. What a verdict then does to
-- the interface's clients and state (a change of verdict, DOWN, IGNORE,
-- a conflict) is judgment-clients.test.lua.
--
-- Harness: the scripted gateway answers DHCPv4 and so lets netd identify
-- the network (`dhcp:10.77.0.1|10.77.0.0/24`); the machine is the whole
-- peinit image with the shipped baseline (`Rules\Interface\wired` JOINs
-- `default` at Priority 10). Every registry write is one `reg apply`
-- transaction.
--
-- The facts are probed one at a time with a rule `Rules\Interface\fact`
-- at Priority 50 that JOINs `default`, the profile eth0 already stands
-- in. Judgment compares outcomes (verdict and resolved profile), not the
-- rule, so moving between `fact` and `wired` restarts nothing: the lease,
-- and the network identified through it, stay put while the attribution
-- (`status.rule`) says whether the condition held. Each probe alternates
-- a matching value with a near miss, so every step is a visible change.
--
-- The fact values are checked against ground truth, not against netd's
-- own report: the MAC and driver from sysfs, the interface id and network
-- id recomputed (helpers.sha1) from the bus path, MAC and the gateway's
-- offer.
--
-- Own VMs: the tests rewrite the interface layer, write network records,
-- and pull the machine's cable.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local rtnl = require("helpers.rtnl")
local sha1 = require("helpers.sha1")

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

local function delkey(path, may_be_absent)
    local r = network.reg(sut, { "del", "-r", full(path) })
    assert(may_be_absent or r.exit_code == 0, "reg del -r " .. path .. ": " .. r.stdout .. r.stderr)
end

local function delval(path, name)
    local r = network.reg(sut, { "del", full(path), name })
    assert(r.exit_code == 0, "reg del value " .. name .. ": " .. r.stdout .. r.stderr)
end

local function eth0(s) return network.iface(s, "eth0") end

local function show(s)
    local i = eth0(s) or {}
    return string.format("refusal=%s verdict=%s rule=%s profile=%s up=%s network=%s name=%s trust=%s addrs=[%s] lease=%s",
        tostring(s.refusal), tostring(i.verdict), tostring(i.rule), tostring(i.profile), tostring(i.up),
        tostring(i.network), tostring(i.network_name), tostring(i.network_trust),
        table.concat(i.addresses or {}, " "), i.lease and i.lease.state or "nil")
end

local function wait_for(pred, desc, timeout)
    local s, last = network.serve_until(gw, sut, function(st)
        local i = eth0(st)
        return i ~= nil and pred(st, i)
    end, { timeout = timeout or 30 })
    if not s then error(desc .. ": timed out; last " .. (last and show(last) or "status: none"), 2) end
    return s, eth0(s)
end

local function cleared(desc)
    return wait_for(function(st) return st.refusal == nil end, desc or "refusal cleared")
end

--- Replace Rules\Interface\fact with one whose conditions are `conds`
--- (`{ {name, type, data}, … }`), JOINing default at Priority 50.
local function fact_rule(conds)
    delkey([[Rules\Interface\fact]], true)
    local k = { [[Rules\Interface\fact]], { "Priority", "dword", 50 }, { "Actions", "multi", { "JOIN(default)" } } }
    for _, c in ipairs(conds) do k[#k + 1] = c end
    apply({ k })
end

local function status_value(ifid, name)
    return network.get(sut, [[Interfaces\]] .. ifid .. [[\Status]], name)
end

local IDX, IFID, NETID

-- ---------------------------------------------------------------------------
-- Tests
-- ---------------------------------------------------------------------------

test("an interface is judged on its interface and network facts; a fact it lacks makes a condition false, not an error",
    { spec = "netd *judgment.facts" }, function(t)
        local s, i = wait_for(function(_, i) return network.bound(i) and i.network ~= nil end,
            "a lease and an identified network", 60)
        IDX, IFID, NETID = i.index, i.ifid, i.network
        t:log(show(s))

        -- Ground truth.
        local mac = sut:read_file("/sys/class/net/eth0/address"):match("%x%x:%x%x:%x%x:%x%x:%x%x:%x%x")
        local driver = sut:run("readlink /sys/class/net/eth0/device/driver").stdout:match("([^/%s]+)%s*$")
        local path = "pci-0000:00:02.0"
        local ifid = sha1.uuid5("peios-netd-ifid|" .. path .. "|" .. gateway.mac(mac))
        local netid = sha1.uuid5("peios-netd-network|wired|dhcp:10.77.0.1|10.77.0.0/24")
        t:log(string.format("mac=%s driver=%s ifid=%s netid=%s", mac, tostring(driver), ifid, netid))
        t:assert_eq(driver, "virtio_net", "the driver, from sysfs")
        t:assert_eq(IFID, ifid, "the interface id is the one recomputed")
        t:assert_eq(NETID, netid, "the network id is the one recomputed")
        local other_mac = mac:sub(1, 15) .. (mac:sub(16, 17) == "ff" and "fe" or "ff")

        local probes = {
            { "Interface.Equal", "eth0", "eth1" },
            { "Interface.Kind.Equal", "wired", "wireless" },
            { "Interface.Id.Equal", ifid, "00000000-0000-5000-8000-000000000000" },
            { "Interface.Mac.Equal", mac, other_mac },
            { "Interface.Path.Equal", path, "pci-0000:00:09.0" },
            { "Interface.Driver.Equal", "virtio_net", "e1000" },
            { "Network.Id.Equal", netid, "00000000-0000-5000-8000-000000000001" },
            { "Network.Kind.Equal", "wired", "wireless" },
        }
        for _, p in ipairs(probes) do
            fact_rule({ { p[1], "sz", p[2] } })
            wait_for(function(_, i) return i.rule == "fact" end, p[1] .. " = " .. p[2] .. " holds")
            fact_rule({ { p[1], "sz", p[3] } })
            s, i = wait_for(function(_, i) return i.rule == "wired" end, p[1] .. " = " .. p[3] .. " does not")
            t:assert(s.refusal == nil, p[1] .. ": no refusal")
            t:assert(network.bound(i), p[1] .. ": the lease stood throughout")
            t:log(p[1] .. ": holds for " .. p[2] .. ", not for " .. p[3])
        end

        -- Network.Name and Network.Trust come from the record, and are
        -- absent while it has none, or has an empty one: `Present = 0`
        -- holds, and any other condition on them is false, not an error.
        local rec = [[Networks\]] .. NETID
        for _, f in ipairs({ { "Name", "network_name", "Office" }, { "Trust", "network_trust", "trusted" } }) do
            local fact = "Network." .. f[1]
            fact_rule({ { fact .. ".Present", "dword", 0 } })
            s, i = wait_for(function(_, i) return i.rule == "fact" end, fact .. " absent")
            t:assert(i[f[2]] == nil, fact .. ": the record has none")
            fact_rule({ { fact .. ".Equal", "sz", f[3] } })
            s, i = wait_for(function(_, i) return i.rule == "wired" end, fact .. " = " .. f[3] .. " while absent")
            t:assert(s.refusal == nil, fact .. ": a condition on an absent fact is no error")
            apply({ { rec, { f[1], "sz", f[3] } } })
            s, i = wait_for(function(_, i) return i.rule == "fact" end, fact .. " = " .. f[3] .. " once recorded")
            t:assert_eq(i[f[2]], f[3], fact .. ": the record's value")
            apply({ { rec, { f[1], "sz", "" } } })
            s, i = wait_for(function(_, i) return i.rule == "wired" end, fact .. " empty is absent")
            t:assert(i[f[2]] == nil, fact .. ": an empty value is none")
            delval(rec, f[1])
            t:log(fact .. ": absent, then " .. f[3] .. ", then empty")
        end
        delkey([[Rules\Interface\fact]])
        wait_for(function(_, i) return i.rule == "wired" end, "fact gone")
    end)

test("loopback is never judged, never recorded and never changed",
    { spec = "netd *judgment.loopback-never-judged" }, function(t)
        local s = wait_for(function() return true end, "status")
        for _, i in ipairs(s.interfaces) do
            t:assert(i.name ~= "lo", "status lists no loopback")
        end
        t:assert_eq(#s.interfaces, 1, "eth0 alone")
        local r = network.reg(sut, { "export", full("Interfaces") })
        r:assert_ok()
        local records = 0
        for id in r.stdout:gmatch("%[key Machine\\System\\Network\\Interfaces\\([^\\%]]+)%]") do
            records = records + 1
            t:assert_eq(id, IFID, "the one record is eth0's")
        end
        t:assert_eq(records, 1, "no record for loopback")
        t:assert(r.stdout:find("Name = sz:lo\n", 1, true) == nil, "no Status Name lo")

        -- Rules that would hold loopback down, by name and by kind, written
        -- while a refusal stands so that its clearing proves them taken.
        apply({ { [[Rules\Interface\bad]], { "Actions", "multi", { "JOIN(nosuch)" } } } })
        wait_for(function(st) return st.refusal == "JOIN(nosuch) names no profile" end, "a refusal")
        apply({
            { [[Rules\Interface\loname]], { "Interface.Equal", "sz", "lo" }, { "Priority", "dword", 100 },
                { "Actions", "multi", { "DOWN" } } },
            { [[Rules\Interface\lokind]], { "Interface.Kind.Equal", "sz", "loopback" }, { "Priority", "dword", 100 },
                { "Actions", "multi", { "DOWN" } } },
        })
        delkey([[Rules\Interface\bad]])
        local i
        s, i = cleared("the loopback rules taken")
        local lo_index = tonumber(sut:read_file("/sys/class/net/lo/ifindex"):match("%d+"))
        local reconcile = network.call(sut, { query = "reconcile" })
        t:assert(reconcile and reconcile.ok, "a full pass")
        gw:serve({ timeout = 2 })
        local flags = tonumber(sut:read_file("/sys/class/net/lo/flags"):match("0x%x+"))
        t:log(string.format("lo flags 0x%x", flags))
        t:assert(flags & 1 == 1, "loopback is still up")
        local has127 = false
        for _, a in ipairs(rtnl.addresses_of(sut, lo_index, 4)) do
            if a.address == "127.0.0.1" then has127 = true end
        end
        t:assert(has127, "and keeps 127.0.0.1")
        s, i = wait_for(function() return true end, "status")
        t:assert_eq(#s.interfaces, 1, "still not judged into status")
        t:assert_eq(i.rule, "wired", "eth0 unaffected")
        t:assert_eq(i.up, true, "eth0 up")
        delkey([[Rules\Interface\loname]])
        delkey([[Rules\Interface\lokind]])
    end)

test("the verdict is read off the evaluation: JOIN's profile looked up case-insensitively, DOWN, IGNORE, and the backstop; attributed to the rule's path",
    { spec = "netd *judgment.verdict" }, function(t)
        local function pt(actions)
            apply({ { [[Rules\Interface\pt]], { "Interface.Equal", "sz", "eth0" }, { "Priority", "dword", 50 },
                { "Actions", "multi", actions } } })
        end
        pt({ "IGNORE" })
        local s, i = wait_for(function(_, i) return i.verdict == "IGNORE" end, "IGNORE")
        t:log(show(s))
        t:assert_eq(i.rule, "pt", "attributed to pt")
        t:assert(i.profile == nil, "no profile")
        wait_until(function() return status_value(IFID, "Verdict") == "IGNORE" end,
            { timeout = 10, interval = 0.25, desc = "Status Verdict IGNORE" })

        pt({ "DOWN" })
        s, i = wait_for(function(_, i) return i.verdict == "DOWN" and i.up == false end, "DOWN")
        t:log(show(s))
        t:assert_eq(i.rule, "pt", "attributed to pt")
        t:assert(i.profile == nil, "no profile")

        pt({ "JOIN(DEFAULT)" })
        s, i = wait_for(function(_, i) return i.verdict == "JOIN" and i.up == true end, "JOIN(DEFAULT)")
        t:log(show(s))
        t:assert_eq(i.profile, "default", "JOIN(DEFAULT) stands eth0 in default")
        t:assert_eq(i.rule, "pt", "attributed to pt")

        -- A rule that speaks from below another is attributed by its path.
        apply({ { [[Rules\Interface\pt\sub]], { "Interface.Kind.Equal", "sz", "wired" },
            { "Actions", "multi", { "JOIN(default)" } } } })
        s, i = wait_for(function(_, i) return i.rule == "pt/sub" end, "the exception speaks")
        t:assert_eq(i.verdict, "JOIN", "JOIN")
        delkey([[Rules\Interface\pt]])

        -- No rule speaks: the baseline switched off, and a rule with no
        -- verdict (NULL) abstaining. The backstop answers: IGNORE.
        apply({
            { [[Rules\Interface\wired]], { "Enabled", "dword", 0 } },
            { [[Rules\Interface\quiet]], { "Interface.Equal", "sz", "eth0" }, { "Actions", "multi", { "NULL" } } },
        })
        s, i = wait_for(function(_, i) return i.rule == "backstop" end, "the backstop")
        t:log(show(s))
        t:assert(i.verdict == nil, "no rule's verdict")
        t:assert(i.profile == nil, "no profile")
        wait_until(function() return status_value(IFID, "Rule") == nil end,
            { timeout = 10, interval = 0.25, desc = "Status Rule removed" })
        delkey([[Rules\Interface\quiet]])
        delval([[Rules\Interface\wired]], "Enabled")
        wait_for(function(_, i) return i.rule == "wired" and network.bound(i) end, "the baseline again", 45)
    end)

test("every non-loopback interface is judged on every full pass, not only when a generation lands",
    { spec = "netd *judgment.when" }, function(t)
        -- A rule over the network facts, JOINing the same profile: it
        -- speaks exactly while no network is identified.
        apply({ { [[Rules\Interface\nonet]], { "Network.Id.Present", "dword", 0 }, { "Priority", "dword", 50 },
            { "Actions", "multi", { "JOIN(default)" } } } })
        local s, i = wait_for(function(_, i) return i.network ~= nil and i.rule == "wired" end,
            "identified: nonet is silent", 45)
        local nic = lan:nic(sut)
        nic:disconnect()
        s, i = wait_for(function(_, i) return i.carrier == false end, "carrier lost")
        s, i = wait_for(function(_, i) return i.rule == "nonet" end, "re-judged without the network")
        t:log("unplugged: " .. show(s))
        t:assert(i.network == nil, "no network identified")
        nic:reconnect()
        s, i = wait_for(function(_, i) return i.network ~= nil and i.rule == "wired" end,
            "re-judged once the network is identified again", 60)
        t:log("plugged: " .. show(s))

        -- A network record's Name is no rule or profile: writing it builds
        -- no generation, and the next pass judges eth0 on it.
        apply({ { [[Rules\Interface\named]], { "Network.Name.Equal", "sz", "Lab" }, { "Priority", "dword", 60 },
            { "Actions", "multi", { "JOIN(default)" } } } })
        wait_for(function(st, i) return st.refusal == nil and i.rule == "wired" end, "named is silent")
        apply({ { [[Networks\]] .. NETID, { "Name", "sz", "Lab" } } })
        s, i = wait_for(function(_, i) return i.rule == "named" end, "judged on the record's Name")
        t:log("named: " .. show(s))
        delval([[Networks\]] .. NETID, "Name")
        delkey([[Rules\Interface\named]])
        delkey([[Rules\Interface\nonet]])
    end)
