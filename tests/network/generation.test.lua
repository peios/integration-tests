-- netd §3.2 — Building a generation: what refuses one and with what
-- words, what a refusal leaves in force and how it is reported, the JOIN
-- of a disabled profile (and how loosely a JOIN target is read), the lint
-- that is not a refusal, the tie that refuses at runtime, and the forest
-- that is not there at all.
--
-- Harness: the scripted gateway answers DHCPv4 and records what the
-- machine sends; the machine is the whole peinit image with the shipped
-- baseline (`Profiles\default`, `Rules\Interface\wired` at Priority 10).
-- Every registry write is one `reg apply` transaction (network.write
-- would make a generation per value, and a rule seen half-written is a
-- refusal the test did not ask for).
--
-- `status.refusal` is the instrument: set to the reason when a generation
-- is refused, cleared only when one builds. So "this generation was
-- taken" is shown by clearing a standing refusal, and "it was refused" by
-- the reason; "nothing changed" by the lease (no RELEASE at the gateway,
-- still bound) and by netd's default route keeping its metric.
--
-- Not reachable from a guest: the refusal row `bad name` (a rule key whose
-- name is empty or holds `/` or `\`). LCS refuses both separators inside
-- a key component, and an empty component, so no registry key can carry
-- such a name; pnp-core's own tests hold that row.
--
-- The nesting row ("Nesting deeper than 12 | from pnp-core") has its own
-- test, tagged known-bug: pnp-core at netd's pinned revision has no
-- nesting limit, so a 13-deep tree builds.
--
-- Own VMs: the tests rewrite (and once delete) the interface layer.

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
    return string.format("refusal=%s verdict=%s rule=%s profile=%s up=%s addrs=[%s] lease=%s",
        tostring(s.refusal), tostring(i.verdict), tostring(i.rule), tostring(i.profile),
        tostring(i.up), table.concat(i.addresses or {}, " "), i.lease and i.lease.state or "nil")
end

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

local function cleared(desc)
    return wait_for(function(st) return st.refusal == nil end, desc or "refusal cleared")
end

local function default_route(index)
    for _, r in ipairs(rtnl.routes_of(sut, index)) do
        if r.protocol == rtnl.RTPROT.NETD and r.family == 4 and r.prefix == 0 then return r end
    end
end

local function count(kind)
    return #gw:dhcp_messages(kind)
end

--- The netd log line carrying `text`, or nil.
local function log_line(text)
    for _, l in ipairs(network.logs(sut, { take = 400 })) do
        if l:find(text, 1, true) then return l end
    end
end

local IDX, IFID

-- ---------------------------------------------------------------------------
-- Tests
-- ---------------------------------------------------------------------------

test("a refused generation changes nothing, is logged at error and reported in status and net status, and stays recorded until one builds",
    { spec = "netd *generation.refusal-keeps-last-good-and-is-reported" }, function(t)
        local s, i = wait_for(function(_, i) return network.bound(i) and default_route(i.index) ~= nil end,
            "the baseline lease and route", 60)
        IDX, IFID = i.index, i.ifid
        t:assert_eq(default_route(IDX).metric, 100, "the baseline route's metric")
        gw:forget()

        -- One write: an edit eth0's profile would act on, and a rule that
        -- dooms the generation it is in.
        apply({
            { [[Profiles\default]], { "Route.Metric", "dword", 777 } },
            { [[Rules\Interface\bad]], { "Actions", "multi", { "JOIN(nosuch)" } } },
        })
        refused(t, "JOIN(nosuch) names no profile")
        gw:serve({ timeout = 3 })
        s, i = wait_for(function() return true end, "status")
        t:log(show(s))
        t:assert_eq(i.rule, "wired", "the last good generation still judges eth0")
        t:assert_eq(i.profile, "default", "in the same profile")
        t:assert(network.bound(i), "the lease is untouched")
        t:assert_eq(count(gateway.DHCP.RELEASE), 0, "no RELEASE: the clients were not restarted")
        t:assert_eq(count(gateway.DHCP.DISCOVER) + count(gateway.DHCP.REQUEST), 0, "no new exchange")
        t:assert_eq(default_route(IDX).metric, 100, "the refused generation's Route.Metric is not applied")

        local line = log_line("interface layer refused: JOIN(nosuch) names no profile; the last good generation stands")
        t:log("log: " .. tostring(line))
        t:assert(line ~= nil, "the refusal is logged")
        t:assert(line:find("error:", 1, true) ~= nil, "at error level")

        local r = sut:run("net status")
        r:assert_ok()
        t:log(r.stdout)
        t:assert(r.stdout:match("\npolicy%s+REFUSED: JOIN%(nosuch%) names no profile") ~= nil
            or r.stdout:match("^policy%s+REFUSED: JOIN%(nosuch%) names no profile") ~= nil,
            "net status prints a policy REFUSED line")

        -- A pass that builds nothing leaves the refusal recorded: a write
        -- outside the rules and profiles, then a reconcile request.
        apply({ { [[Interfaces\]] .. IFID, { "PtNote", "sz", "b" } } })
        local rec = network.call(sut, { query = "reconcile" })
        t:assert(rec and rec.ok, "reconcile answered")
        s = wait_for(function() return true end, "status")
        t:assert_eq(s.refusal, "JOIN(nosuch) names no profile", "still recorded after a pass")
        delval([[Interfaces\]] .. IFID, "PtNote")

        -- A newer refused generation replaces the reason.
        apply({ { [[Rules\Interface\bad]], { "Actions", "multi", { "JOIN(other)" } } } })
        refused(t, "JOIN(other) names no profile")

        -- A generation that builds clears it, and is taken whole.
        delkey([[Rules\Interface\bad]])
        s, i = wait_for(function(st, i)
            local d = default_route(IDX)
            return st.refusal == nil and network.bound(i) and d ~= nil and d.metric == 777
        end, "the good generation taken", 45)
        t:assert(s.refusal == nil, "the refusal is cleared")
        delval([[Profiles\default]], "Route.Metric")
        wait_for(function(_, i) local d = default_route(IDX)
            return network.bound(i) and d ~= nil and d.metric == 100 end, "the baseline metric again", 45)
    end)

test("a JOIN naming no profile refuses the generation, matching or not",
    { spec = "netd *generation.dangling-join-refuses" }, function(t)
        -- The rule matches nothing on this machine; its JOIN is still looked up.
        apply({ { [[Rules\Interface\dang]], { "Interface.Equal", "sz", "nosuchif" },
            { "Actions", "multi", { [[JOIN(No\Such)]] } } } })
        refused(t, "JOIN(No/Such) names no profile")
        apply({ { [[Profiles\No\Such]] } })
        cleared("the profile now exists")
        delkey([[Rules\Interface\dang]])
        delkey([[Profiles\No]])
        cleared()
    end)

test("everything pnp-core refuses at the interface layer refuses the generation, in netd's words",
    { spec = "netd *generation.refusal-causes" }, function(t)
        local cases = {
            { "unknown fact", { "Bogus.Equal", "sz", "x" }, "rule bad: unknown fact Bogus.Equal" },
            { "malformed operator", { "Interface.Kind.GreaterThan", "dword", 1 },
                "rule bad: bad operator in Interface.Kind.GreaterThan" },
            { "malformed pattern", { "Interface.Mac.Equal", "sz", "zz:zz:zz:zz:zz:zz" },
                "rule bad: bad pattern in Interface.Mac.Equal" },
            { "Actions not a list", { "Actions", "sz", "JOIN(default)" }, "rule bad: Actions is not a list" },
            { "a malformed action", { "Actions", "multi", { "FROB" } }, "rule bad: bad action (" },
            { "PASS", { "Actions", "multi", { "PASS" } }, "rule bad: an action the interface layer does not speak" },
            { "DROP", { "Actions", "multi", { "DROP" } }, "rule bad: an action the interface layer does not speak" },
            { "a key not at the layer", { "Tag.pt.Equal", "dword", 1 },
                "rule bad: Tag.pt.Equal does not exist at the interface layer" },
            { "Present on a fact never here", { "DstPort.Present", "dword", 1 },
                "rule bad: DstPort.Present on a fact that never exists at this layer" },
            { "Priority not an integer", { "Priority", "sz", "high" }, "rule bad: Priority is not an integer" },
            { "Enabled not 0 or 1", { "Enabled", "dword", 2 }, "rule bad: Enabled is not 0 or 1" },
            { "a JOIN naming no profile", { "Actions", "multi", { "JOIN(nosuch)" } }, "JOIN(nosuch) names no profile" },
            -- §3.2 "Lowering a rule": a value of another lowered shape.
            { "an unsupported value type", { "Interface.Kind.Equal", "binary", "01" },
                "rule bad: value Interface.Kind.Equal has an unsupported type" },
        }
        for _, c in ipairs(cases) do
            apply({ { [[Rules\Interface\bad]], c[2] } })
            local s = wait_for(function(st) return st.refusal ~= nil end, c[1])
            t:log(c[1] .. " -> " .. s.refusal)
            if c[3]:sub(-1) == "(" then
                t:assert_eq(s.refusal:sub(1, #c[3]), c[3], c[1])
                t:assert_eq(s.refusal:sub(-1), ")", c[1] .. ": the detail in parentheses")
            else
                t:assert_eq(s.refusal, c[3], c[1])
            end
            t:assert_eq(eth0(s).rule, "wired", "the last good generation stands")
            delkey([[Rules\Interface\bad]])
            cleared()
        end

        -- <path> is the rule's path below Rules\Interface.
        apply({ { [[Rules\Interface\wired\sub]], { "Bogus.Equal", "sz", "x" } } })
        refused(t, "rule wired/sub: unknown fact Bogus.Equal")
        delkey([[Rules\Interface\wired\sub]])
        cleared()

        -- A malformed profile: the profile parser's message.
        apply({ { [[Profiles\badp]], { "Bogus", "dword", 1 } } })
        refused(t, "profile badp: unknown value Bogus")
        delkey([[Profiles\badp]])
        cleared()
    end)

test("rule nesting deeper than 12 refuses the generation",
    { spec = "netd *generation.refusal-causes", tags = { "known-bug" } }, function(t)
        -- TRM-nesting-limit: netd builds a 13-deep rule tree. pnp-core at
        -- netd's pinned revision (pkm 9c1d56c) has no nesting check in
        -- build_forest; the only depth bound netd applies is its 16-level
        -- registry read (§2.3).
        apply({ { [[Rules\Interface\bad]], { "Actions", "multi", { "JOIN(nosuch)" } } } })
        refused(t, "JOIN(nosuch) names no profile")
        local path = [[Rules\Interface]]
        for n = 1, 13 do path = path .. "\\n" .. n end
        -- The thirteenth rule matches eth0 and JOINs the profile eth0 is
        -- already in (no client restarts), so if the tree is built, its
        -- attribution shows it was.
        apply({ { path, { "Interface.Equal", "sz", "eth0" }, { "Priority", "dword", 50 },
            { "Actions", "multi", { "JOIN(default)" } } } })
        delkey([[Rules\Interface\bad]])
        -- The bad rule's refusal goes either way; what replaces it is the
        -- question.
        local s = wait_for(function(st) return st.refusal ~= "JOIN(nosuch) names no profile" end,
            "the next generation judged")
        gw:serve({ timeout = 2 })
        s = wait_for(function() return true end, "status")
        t:log("after a 13-deep tree: refusal = " .. tostring(s.refusal) .. "; eth0's rule = " .. tostring(eth0(s).rule))
        local refusal = s.refusal
        delkey([[Rules\Interface\n1]])
        cleared()
        t:assert(refusal ~= nil, "a 13-deep rule tree is refused")
    end)

test("a condition on a fact never present at the interface layer is a lint, logged, and the generation is taken",
    { spec = "netd *generation.never-at-layer-is-a-lint" }, function(t)
        apply({ { [[Rules\Interface\bad]], { "Actions", "multi", { "JOIN(nosuch)" } } } })
        refused(t, "JOIN(nosuch) names no profile")
        -- Written while the refusal stands, so its clearing is this rule's
        -- generation being taken.
        apply({ { [[Rules\Interface\lint]], { "DstPort.Equal", "dword", 53 }, { "Priority", "dword", 100 },
            { "Actions", "multi", { "DOWN" } } } })
        delkey([[Rules\Interface\bad]])
        local s, i = cleared("the generation with the lint taken")
        t:log(show(s))
        local line
        wait_until(function()
            line = log_line("rule lint: DstPort.Equal can never hold at the interface layer")
            return line ~= nil
        end, { timeout = 10, interval = 0.5, desc = "the lint logged" })
        t:log("log: " .. line)
        t:assert(line:find("warn:", 1, true) ~= nil, "logged as a warning")
        t:assert(s.refusal == nil, "not a refusal")
        t:assert_eq(i.rule, "wired", "the condition never holds: the rule never speaks")
        t:assert_eq(i.up, true, "and eth0 is not held down")
        delkey([[Rules\Interface\lint]])
    end)

test("a JOIN of a disabled profile is replaced by NULL: the rule abstains and its parent or another tree answers",
    { spec = "netd *generation.join-of-disabled-profile-abstains" }, function(t)
        -- An exception under the baseline rule, JOINing `dim`, enabled first.
        apply({
            { [[Profiles\dim]], { "Enabled", "dword", 1 }, { "Dns.Domains", "sz", "dim.example" } },
            { [[Rules\Interface\wired\slot]], { "Interface.Path.Equal", "sz", "pci-0000:00:02.0" },
                { "Actions", "multi", { "JOIN(dim)" } } },
        })
        local s, i = wait_for(function(_, i) return i.rule == "wired/slot" end, "the exception speaks")
        t:assert_eq(i.profile, "dim", "joined to dim")
        apply({ { [[Profiles\dim]], { "Enabled", "dword", 0 } } })
        s, i = wait_for(function(_, i) return i.rule == "wired" end, "dim disabled")
        t:log(show(s))
        t:assert(s.refusal == nil, "a JOIN of a disabled profile is not a fault")
        t:assert_eq(i.profile, "default", "the parent rule speaks")

        -- A tree of its own, above the baseline: another tree answers.
        apply({
            { [[Profiles\dim]], { "Enabled", "dword", 1 } },
            { [[Rules\Interface\solo]], { "Interface.Equal", "sz", "eth0" }, { "Priority", "dword", 50 },
                { "Actions", "multi", { "JOIN(dim)" } } },
        })
        s, i = wait_for(function(_, i) return i.rule == "solo" end, "solo speaks")
        apply({ { [[Profiles\dim]], { "Enabled", "dword", 0 } } })
        s, i = wait_for(function(_, i) return i.rule == "wired" end, "solo abstains")
        t:assert(s.refusal == nil, "no refusal")
        t:assert_eq(i.profile, "default", "the other tree answers")
        delkey([[Rules\Interface\solo]])
        delkey([[Rules\Interface\wired\slot]])
        delkey([[Profiles\dim]])
        cleared()
    end)

test("a JOIN target is recognised loosely: whitespace, case and backslashes",
    { spec = "netd *generation.join-target-recognised-loosely" }, function(t)
        apply({
            { [[Profiles\Office\London]], { "Enabled", "dword", 1 } },
            { [[Rules\Interface\loose]], { "Interface.Equal", "sz", "eth0" }, { "Priority", "dword", 50 },
                { "Actions", "multi", { [[ join ( OFFICE\london ) ]] } } },
        })
        local s, i = wait_for(function(_, i) return i.rule == "loose" end, "the loose JOIN speaks")
        t:log(show(s))
        t:assert_eq(i.profile, "Office/London", "it names Office/London")
        -- Had netd not recognised it as naming the disabled profile, the
        -- rule would go on JOINing it: the judge's own lookup does not ask
        -- whether a profile is enabled.
        apply({ { [[Profiles\Office\London]], { "Enabled", "dword", 0 } } })
        s, i = wait_for(function(_, i) return i.rule == "wired" end, "the loose JOIN abstains")
        t:assert(s.refusal == nil, "no refusal")
        t:assert_eq(i.profile, "default", "the baseline answers")
        delkey([[Rules\Interface\loose]])
        delkey([[Profiles\Office]])
        cleared()
    end)

test("a generation built at runtime that ties two rules naming different profiles on an interface is refused",
    { spec = "netd *generation.runtime-tie-refuses" }, function(t)
        wait_for(function(_, i) return network.bound(i) end, "bound", 45)
        gw:forget()
        apply({
            { [[Profiles\rival]] },
            { [[Rules\Interface\rival]], { "Interface.Kind.Equal", "sz", "wired" }, { "Priority", "dword", 10 },
                { "Actions", "multi", { "JOIN(rival)" } } },
        })
        local s, i = refused(t, "rules rival vs wired tie on interface eth0")
        gw:serve({ timeout = 2 })
        s, i = wait_for(function() return true end, "status")
        t:assert_eq(i.rule, "wired", "the last good generation stands")
        t:assert_eq(i.profile, "default", "eth0 stays in default")
        t:assert(network.bound(i), "its lease untouched")
        t:assert_eq(count(gateway.DHCP.RELEASE), 0, "no client restarted")

        -- A tie naming the same profile is no conflict: written while the
        -- rival's refusal stands, it builds once the rival goes.
        apply({ { [[Rules\Interface\twin]], { "Interface.Kind.Equal", "sz", "wired" }, { "Priority", "dword", 10 },
            { "Actions", "multi", { "JOIN(default)" } } } })
        delkey([[Rules\Interface\rival]])
        s, i = cleared("twin taken")
        t:log("twin: " .. show(s))
        t:assert_eq(i.profile, "default", "eth0 in default")
        delkey([[Rules\Interface\twin]])
        delkey([[Profiles\rival]])
        cleared()
    end)

test("two rules JOINing one profile in different case are no tie",
    { spec = "netd *generation.runtime-tie-refuses", tags = { "known-bug" } }, function(t)
        -- PEI-1362: netd refuses this generation with "rules twin vs
        -- wired tie on interface eth0". pnp-core interns JOIN targets by
        -- their spelling, so JOIN(DEFAULT) and JOIN(default) are two verdict
        -- indexes, and two top-priority JOINs with different indexes are a
        -- conflict; netd's own lookup of either is case-insensitive and
        -- finds the one profile `default`.
        apply({ { [[Rules\Interface\bad]], { "Actions", "multi", { "JOIN(nosuch)" } } } })
        refused(t, "JOIN(nosuch) names no profile")
        apply({ { [[Rules\Interface\twin]], { "Interface.Kind.Equal", "sz", "wired" }, { "Priority", "dword", 10 },
            { "Actions", "multi", { "JOIN(DEFAULT)" } } } })
        delkey([[Rules\Interface\bad]])
        local s = wait_for(function(st) return st.refusal ~= "JOIN(nosuch) names no profile" end,
            "the next generation judged")
        t:log("JOIN(DEFAULT) beside JOIN(default) at one priority: refusal = " .. tostring(s.refusal))
        local refusal = s.refusal
        delkey([[Rules\Interface\twin]])
        cleared()
        t:assert(refusal == nil, "JOIN(DEFAULT) and JOIN(default) name one profile: no tie")
    end)

test("with no Rules\\Interface every interface meets the backstop, and the profiles are still built",
    { spec = "netd *generation.no-rules-means-backstop" }, function(t)
        delkey([[Rules\Interface]])
        local s, i = wait_for(function(_, i) return i.rule == "backstop" end, "the backstop answers")
        t:log(show(s))
        t:assert(s.refusal == nil, "no refusal")
        t:assert(i.verdict == nil, "no verdict: the backstop answered")
        t:assert(i.profile == nil, "no profile")
        local verdict, rule
        wait_until(function()
            verdict = network.get(sut, [[Interfaces\]] .. IFID .. [[\Status]], "Verdict")
            rule = network.get(sut, [[Interfaces\]] .. IFID .. [[\Status]], "Rule")
            return verdict == nil and rule == nil
        end, { timeout = 10, interval = 0.25, desc = "Status Verdict and Rule removed" })
        t:assert(verdict == nil and rule == nil, "the inventory records no rule")

        -- The profiles are still resolved, for nothing to name: a malformed
        -- one still refuses.
        apply({ { [[Profiles\junk]], { "Bogus", "dword", 1 } } })
        refused(t, "profile junk: unknown value Bogus")
        delkey([[Profiles\junk]])
        cleared()

        -- The baseline rule back, exactly as seeded.
        apply({ { [[Rules\Interface\wired]], { "Interface.Kind.Equal", "sz", "wired" }, { "Priority", "dword", 10 },
            { "Actions", "multi", { "JOIN(default)" } } } })
        s, i = wait_for(function(_, i) return i.rule == "wired" and network.bound(i) end, "the baseline again", 45)
        t:assert_eq(i.profile, "default", "joined to default again")
    end)
