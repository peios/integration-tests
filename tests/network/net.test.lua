-- netd §10.1 — The net command: each subcommand, the `net status`
-- rendering, how `net wait` and `net policy wait` decide, and the exit
-- statuses.
--
-- Harness: the scripted gateway (helpers.gateway) and a whole Peios
-- (helpers.network). `net` runs in the guest; its output is compared
-- with the control reply it renders (`network.status`), with runs of
-- spaces collapsed, since the TRM states what each line says and not
-- its columns.
--
-- The `net wait` timeouts are real: a wait with no usable timeout runs
-- its full 60 s with the cable pulled, so that test is the file's
-- longest. netd is stopped through peinit where a test needs it absent.
--
-- `net policy wait` is driven against the kernel's engine with a packet
-- rule it refuses (an unknown fact); the baseline generation stands
-- meanwhile, by design, and the rule is removed after.
--
-- Own VMs: the tests pull the cable, stop netd and delete and restore
-- the interface layer's keys.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
-- Option 15 gives the lease a domain, so `net status` has a search line.
local DHCP = { pool = { "10.77.0.50" }, lease = 3600, options = { { 15, "pt.example" } } }
gw:dhcp(DHCP)
local sut = network.boot({ bridges = { lan }, gateway = gw })

local KEY = network.KEY

-- ---------------------------------------------------------------------------
-- Local instruments
-- ---------------------------------------------------------------------------

--- Run `net` with `args` (a string, shell-quoted already).
local function net(args)
    return sut:run("net " .. args)
end

--- stdout's lines, runs of spaces collapsed, trailing space dropped.
local function lines_of(text)
    local out = {}
    for l in (text .. "\n"):gmatch("(.-)\n") do
        out[#out + 1] = (l:gsub("%s+", " "):gsub(" $", ""))
    end
    while out[#out] == "" do out[#out] = nil end
    return out
end

--- Assert two lists of lines are equal, line by line.
local function same_lines(t, got, want, what)
    for k = 1, math.max(#got, #want) do
        t:assert_eq(got[k], want[k], what .. ", line " .. k)
    end
end

local function has_line(lines, want)
    for _, l in ipairs(lines) do if l == want then return true end end
    return false
end

local function svc()
    return json.decode(sut:run("svctl --json status netd").stdout) or {}
end

local function settle()
    wait_until(function() return svc().current_operation == nil end,
        { timeout = 60, interval = 0.25, desc = "peinit's operation on netd to finish" })
end

local function stop_netd()
    sut:run("svctl stop netd")
    wait_until(function() return network.netd_pid(sut) == nil end,
        { timeout = 60, interval = 0.25, desc = "netd to stop" })
    settle()
end

local function start_netd()
    settle()
    sut:run("svctl start netd")
    wait_until(function()
        local s = network.call(sut, { query = "status" })
        return s ~= nil and s.ok == true
    end, { timeout = 60, interval = 0.25, desc = "netd answering" })
end

local function rebind(t)
    local s = network.serve_until(gw, sut, network.bound, { iface = "eth0", timeout = 60 })
    t:assert(s, "eth0 holds a bound lease")
    return s
end

local function set(key, name, typed)
    if not key:match("^Machine\\") then key = KEY .. (key ~= "" and "\\" .. key or "") end
    network.reg(sut, { "set", key, name, typed }):assert_ok()
end

local function unset(key, name)
    if not key:match("^Machine\\") then key = KEY .. (key ~= "" and "\\" .. key or "") end
    network.reg(sut, { "del", key, name }):assert_ok()
end

local function del_tree(key)
    network.reg(sut, { "del", "-r", KEY .. "\\" .. key }):assert_ok()
end

--- The engine's status as `net policy` prints it.
local function policy()
    local r = net("policy")
    r:assert_ok()
    return { text = r.stdout, generation = tonumber(r.stdout:match("generation%s+(%d+)")) }
end

local BAD_PACKET = [[Rules\Packet\pt-net-bad]]

--- Apply a registry batch (libreg's JSON document) in one transaction.
local function apply(doc)
    sut:write_file("/tmp/pt-batch.json", json.encode(doc))
    local r = network.reg(sut, { "apply", "/tmp/pt-batch.json" })
    assert(r.exit_code == 0, "reg apply: " .. r.stdout .. r.stderr)
end

--- A packet rule the engine refuses (an unknown fact), written in one
--- transaction so the engine notes it as one change.
local function write_bad_packet_rule()
    apply({ keys = { { path = KEY .. "\\" .. BAD_PACKET, values = {
        { name = "Bogus.Equal", type = "sz", data = "x" },
        { name = "Actions", type = "multi", data = { "PASS" } } } } } })
end

-- ---------------------------------------------------------------------------
-- Subcommands
-- ---------------------------------------------------------------------------

test("each subcommand does what the table says",
    { spec = "netd *net.subcommands" }, function(t)
        local s = rebind(t)
        -- version
        for _, v in ipairs({ "version", "--version" }) do
            local r = net(v)
            t:assert_eq(r.exit_code, 0, "net " .. v)
            t:assert_eq(r.stdout, "net 0.1.7\n", "net " .. v .. " prints net <version>")
        end
        -- status prints the status reply (its rendering has its own test).
        local r = net("status")
        t:assert_eq(r.exit_code, 0, "net status")
        t:assert(r.stdout:find("eth0  [" .. network.iface(s, "eth0").ifid .. "]", 1, true) ~= nil,
            "net status prints the reply")
        -- renew sends renew: the client asks its server, unicast, now.
        gw:forget()
        r = net("renew eth0")
        t:assert_eq(r.exit_code, 0, "net renew eth0")
        local renewed = gw:serve({ timeout = 10, until_ = function()
            for _, m in ipairs(gw:dhcp_messages(gateway.DHCP.REQUEST)) do
                if m.ciaddr == "10.77.0.50" then return true end
            end
        end })
        t:assert(renewed, "the gateway saw a renewing REQUEST (ciaddr 10.77.0.50)")
        -- reconcile sends reconcile.
        r = net("reconcile")
        t:assert_eq(r.exit_code, 0, "net reconcile")
        t:assert_eq(r.stdout, "", "and prints nothing")
        -- wait
        t:assert_eq(net("wait routed 5").exit_code, 0, "net wait routed, when routed")

        -- rules: one line per rule, indented by depth, priority,
        -- (disabled), conditions, actions or NULL.
        network.write(sut, [[Rules\Interface\pt-net-off]], {
            Enabled = "dword:0", Priority = "dword:5", ["Interface.Kind.Equal"] = "sz:wireless" })
        network.write(sut, [[Rules\Interface\pt-net-off\pt-sub]], {})
        r = net("rules")
        t:log("net rules:\n" .. r.stdout)
        t:assert_eq(r.exit_code, 0, "net rules")
        same_lines(t, lines_of(r.stdout), {
            "pt-net-off [5] (disabled) Interface.Kind.Equal=wireless -> NULL",
            " pt-net-off/pt-sub (everything) -> NULL",
            "wired [10] Interface.Kind.Equal=wired -> JOIN(default)",
        }, "every rule, depth-first, as the table describes")
        t:assert(r.stdout:find("\n  pt-net-off/pt-sub", 1, true) ~= nil, "an exception is indented by its depth")

        -- profiles: the values a profile sets itself, (inherits only),
        -- (disabled).
        network.write(sut, [[Profiles\default\pt-child]], {})
        network.write(sut, [[Profiles\pt-net-off]], { Enabled = "dword:0", ["Address.Offered"] = "dword:1" })
        r = net("profiles")
        t:log("net profiles:\n" .. r.stdout)
        t:assert_eq(r.exit_code, 0, "net profiles")
        same_lines(t, lines_of(r.stdout), {
            "default Address.LinkLocal=1 Address.Offered=1 Dns.Offered=1 Route.Offered=1",
            " default/pt-child (inherits only)",
            "pt-net-off (disabled) Address.Offered=1",
        }, "every profile, with only what it sets itself")
        local list = net("profile list")
        t:assert_eq(list.exit_code, 0, "net profile list")
        t:assert_eq(list.stdout, r.stdout, "net profile list is net profiles")
        del_tree([[Rules\Interface\pt-net-off]])
        del_tree([[Profiles\default\pt-child]])
        del_tree([[Profiles\pt-net-off]])

        -- policy wait, then policy: the engine walks the registry writes
        -- above a moment after each (net policy shows them unwalked until
        -- then), and the wait returns once it has.
        t:assert_eq(net("policy wait").exit_code, 0, "net policy wait")
        r = net("policy")
        t:log("net policy:\n" .. r.stdout)
        t:assert_eq(r.exit_code, 0, "net policy")
        local p = lines_of(r.stdout)
        t:assert_eq(p[1], "engine enforcing", "the engine is enforcing")
        t:assert(p[2]:match("^generation %d+$"), "the generation")
        t:assert_eq(p[3], "changes in force", "no unwalked changes")
        t:assert(p[#p]:match("^contexts %d+$"), "the context count")

        -- rules and profiles need no netd, and fail without their key.
        stop_netd()
        t:assert_eq(net("status").exit_code, 1, "netd is down")
        r = net("rules")
        t:assert_eq(r.exit_code, 0, "net rules without netd")
        t:assert(r.stdout:find("wired [10]", 1, true), "reads the registry")
        t:assert_eq(net("profiles").exit_code, 0, "net profiles without netd")
        sut:run("reg export --json '" .. KEY .. "\\Rules\\Interface' /tmp/pt-rules.json"):assert_ok()
        sut:run("reg export --json '" .. KEY .. "\\Profiles' /tmp/pt-profiles.json"):assert_ok()
        del_tree([[Rules\Interface]])
        del_tree("Profiles")
        r = net("rules")
        t:log("net rules, no key: " .. r.exit_code .. " " .. r.stderr)
        t:assert_eq(r.exit_code, 1, "net rules fails when Rules\\Interface does not exist")
        t:assert(r.stderr:find("net: " .. KEY .. "\\Rules\\Interface", 1, true), "naming the key")
        r = net("profiles")
        t:assert_eq(r.exit_code, 1, "net profiles fails when Profiles does not exist")
        t:assert(r.stderr:find("net: " .. KEY .. "\\Profiles", 1, true), "naming the key")
        network.reg(sut, { "apply", "/tmp/pt-profiles.json" }):assert_ok()
        network.reg(sut, { "apply", "/tmp/pt-rules.json" }):assert_ok()
        t:assert_eq(net("rules").exit_code, 0, "restored")
        start_netd()
        local back = rebind(t)
        t:assert_eq(network.iface(back, "eth0").rule, "wired", "netd judges by the restored rules")
    end)

-- ---------------------------------------------------------------------------
-- net status
-- ---------------------------------------------------------------------------

test("net status renders the status reply line by line",
    { spec = "netd *net.status-output" }, function(t)
        local s = rebind(t)
        local i = network.iface(s, "eth0")
        set([[Networks\]] .. i.network, "Name", "sz:pt-net-home")
        set([[Networks\]] .. i.network, "Trust", "sz:pt-trusted")
        s = network.serve_until(gw, sut, function(x) return x.network_trust == "pt-trusted" end,
            { iface = "eth0", timeout = 15 })
        t:assert(s, "the record's name and trust are in the reply")
        local r = net("status")
        s = network.status(sut)
        i = network.iface(s, "eth0")
        t:log("net status:\n" .. r.stdout .. "\nreply: " .. json.encode(s))
        local l = lines_of(r.stdout)
        t:assert_eq(l[1], "hostname (unset)", "the hostname line, (unset) when empty")
        t:assert_eq(l[2], "readiness " .. s.level, "the readiness line")
        t:assert_eq(l[3], "", "no policy line without a refusal")
        local want = {
            "eth0 [" .. i.ifid .. "]",
            " verdict JOIN(default) by wired",
            " state up, carrier",
            " readiness " .. i.level,
            " hardware " .. i.mac .. " " .. i.path .. " " .. i.driver,
            " network pt-net-home [" .. i.network .. "] trust pt-trusted",
        }
        for _, a in ipairs(i.addresses) do want[#want + 1] = " address " .. a end
        want[#want + 1] = " gateway " .. i.gateway
        t:assert_eq(i.gateway6, nil, "no IPv6 gateway, so no gateway6 line")
        want[#want + 1] = " dns " .. table.concat(i.dns, " ")
        want[#want + 1] = " search " .. table.concat(i.search, " ")
        for k, w in ipairs(want) do
            t:assert_eq(l[3 + k], w, "line " .. (3 + k))
        end
        local lease = l[3 + #want + 1]
        local left = tonumber((lease or ""):match("^ lease bound from 10%.77%.0%.1, (%d+)s left$"))
        t:assert(left and math.abs(left - i.lease.expires_in) <= 5, "the lease line: " .. tostring(lease))
        t:assert_eq(l[3 + #want + 2], nil, "and no warning line")
        t:assert_eq(i.search[1], "pt.example", "the search line carries the lease's domain")
        unset([[Networks\]] .. i.network, "Name")
        unset([[Networks\]] .. i.network, "Trust")

        -- A refusal.
        network.write(sut, [[Profiles\pt-net-bad]], { ["Address.Bogus"] = "dword:1" })
        wait_until(function() return network.status(sut).refusal ~= nil end,
            { timeout = 15, interval = 0.25, desc = "the refusal" })
        l = lines_of(net("status").stdout)
        t:assert_eq(l[3], "policy REFUSED: profile pt-net-bad: unknown value Address.Bogus (the last good generation stands)",
            "the policy line follows readiness")
        del_tree([[Profiles\pt-net-bad]])
        wait_until(function() return network.status(sut).refusal == nil end,
            { timeout = 15, interval = 0.25, desc = "the refusal to clear" })

        -- No rule: (none) by the backstop, and no readiness line.
        set([[Rules\Interface\wired]], "Enabled", "dword:0")
        wait_until(function() return network.iface(network.status(sut), "eth0").verdict == nil end,
            { timeout = 15, interval = 0.25, desc = "eth0 to lose its verdict" })
        i = network.iface(network.status(sut), "eth0")
        l = lines_of(net("status").stdout)
        t:log("unjudged:\n" .. table.concat(l, "\n"))
        t:assert_eq(i.rule, "backstop", "the backstop answers")
        t:assert_eq(l[5], " verdict (none) by backstop", "(none) by the rule that answered")
        t:assert(not has_line(l, " readiness " .. i.level), "no readiness line for an interface not joined")

        unset([[Rules\Interface\wired]], "Enabled")
        rebind(t)

        -- A warning, and (none) by the rules that tied: a tie present at
        -- startup (PEI-1333: taken at startup, the interface ignored with
        -- a warning; a runtime write of it is refused instead).
        local tie = { keys = {} }
        for _, n in ipairs({ "pt-tie-a", "pt-tie-b" }) do
            tie.keys[#tie.keys + 1] = { path = KEY .. [[\Profiles\]] .. n,
                values = { { name = "Address.Offered", type = "dword", data = 1 } } }
            tie.keys[#tie.keys + 1] = { path = KEY .. [[\Rules\Interface\]] .. n,
                values = { { name = "Interface.Kind.Equal", type = "sz", data = "wired" },
                           { name = "Priority", type = "dword", data = 20 },
                           { name = "Actions", type = "multi", data = { "JOIN(" .. n .. ")" } } } }
        end
        apply(tie)
        wait_until(function() return network.status(sut).refusal ~= nil end,
            { timeout = 15, interval = 0.25, desc = "the runtime tie to be refused" })
        network.restart_netd(sut)
        i = network.iface(network.status(sut), "eth0")
        l = lines_of(net("status").stdout)
        t:log("tied:\n" .. table.concat(l, "\n"))
        t:assert(i.warning, "the reply carries a warning")
        t:assert_eq(l[5], " verdict (none) by " .. i.rule, "(none) by the rules that tied")
        t:assert_eq(i.rule, "pt-tie-a vs pt-tie-b", "which are both named")
        t:assert_eq(l[#l], " warning " .. i.warning, "the warning line comes last")
        apply({ keys = {
            { path = KEY .. [[\Rules\Interface\pt-tie-a]], values = { { name = "Enabled", type = "dword", data = 0 } } },
            { path = KEY .. [[\Rules\Interface\pt-tie-b]], values = { { name = "Enabled", type = "dword", data = 0 } } },
        } })
        rebind(t)
        for _, k in ipairs({ [[Rules\Interface\pt-tie-a]], [[Rules\Interface\pt-tie-b]],
                             [[Profiles\pt-tie-a]], [[Profiles\pt-tie-b]] }) do
            del_tree(k)
        end
        wait_until(function() return network.status(sut).refusal == nil end,
            { timeout = 15, interval = 0.25, desc = "the baseline generation" })
    end)

-- ---------------------------------------------------------------------------
-- net policy wait
-- ---------------------------------------------------------------------------

test("net policy wait waits for the engine's noted changes to be walked, and fails on a refused walk",
    { spec = "netd *net.policy-wait" }, function(t)
        t:assert_eq(net("policy wait").exit_code, 0, "nothing pending: success")
        local before = policy()
        t:log("before:\n" .. before.text)
        -- A packet rule the engine refuses: an unknown fact.
        write_bad_packet_rule()
        local r = net("policy wait 10")
        t:log("policy wait after a refused write: " .. r.exit_code .. " " .. r.stderr)
        t:assert_eq(r.exit_code, 1, "a refused walk fails the wait")
        local errno, gen = r.stderr:match("net: the policy was refused %(errno (%d+)%); generation (%d+) stands")
        t:assert(errno and tonumber(errno) ~= 0, "naming the errno")
        t:assert_eq(tonumber(gen), before.generation, "and the generation that stands")
        local during = policy()
        t:log("refused:\n" .. during.text)
        t:assert(during.text:find("last walk   REFUSED (errno " .. errno .. "): the previous generation stands", 1, true),
            "net policy shows the refused walk")
        -- Repaired: the walk publishes, and the wait succeeds.
        del_tree(BAD_PACKET)
        r = net("policy wait 10")
        t:assert_eq(r.exit_code, 0, "after the repair the wait succeeds: " .. r.stderr)
        local after = policy()
        t:log("after:\n" .. after.text)
        -- The repaired policy is the standing one again, so the walk
        -- finds nothing to change and publishes nothing new.
        t:assert_eq(after.generation, before.generation, "the standing generation is still in force")
        t:assert(not after.text:find("REFUSED", 1, true), "and no refused walk is reported")
    end)

-- ---------------------------------------------------------------------------
-- net wait
-- ---------------------------------------------------------------------------

test("net wait polls until the level is met, rides out netd being unreachable, and times out",
    { spec = "netd *net.wait" }, function(t)
        rebind(t)
        t:assert_eq(net("wait addressed 5").exit_code, 0, "routed is at least addressed: met at once")
        local nic = lan:nic(sut)
        nic:disconnect()
        t:assert(network.serve_until(gw, sut, function(s) return s.level == "absent" end, { timeout = 30 }),
            "with the cable out the machine is absent")
        t:assert_eq(net("wait absent 1").exit_code, 0, "absent is met at once")
        local t0 = os.time()
        local no_number = sut:run_async("/usr/bin/net", { args = { "wait", "link", "soon" } })
        local no_arg = sut:run_async("/usr/bin/net", { args = { "wait", "link" } })
        local three = sut:run_async("/usr/bin/net", { args = { "wait", "link", "3" } })
        local r3 = three:wait("20s")
        local e3 = os.time() - t0
        t:log("net wait link 3: exit " .. r3.exit_code .. " after ~" .. e3 .. " s: " .. r3.stderr)
        t:assert_eq(r3.exit_code, 1, "a lapsed timeout fails")
        t:assert_eq(r3.stderr, "net: timed out waiting for link\n", "saying what it waited for")
        t:assert(e3 >= 2 and e3 <= 8, "after the 3 s it was given")
        -- netd unreachable: the error is printed and the wait goes on.
        stop_netd()
        sut:run("sleep 2")
        start_netd()
        local r1 = no_number:wait("90s")
        local e1 = os.time() - t0
        local r2 = no_arg:wait("30s")
        local e2 = os.time() - t0
        t:log(string.format("net wait link soon: exit %d after ~%d s\n%s", r1.exit_code, e1, r1.stderr))
        t:log(string.format("net wait link: exit %d after ~%d s\n%s", r2.exit_code, e2, r2.stderr))
        for _, x in ipairs({ { r1, e1, "a timeout that is not a number" }, { r2, e2, "no timeout" } }) do
            local r, e, what = x[1], x[2], x[3]
            t:assert_eq(r.exit_code, 1, what .. ": fails when it lapses")
            t:assert(r.stderr:find("net: cannot reach netd at /run/netd/control.sock", 1, true),
                what .. ": the error reaching netd was printed")
            t:assert(r.stderr:find("net: timed out waiting for link\n", 1, true), what .. ": and the wait went on to its end")
            t:assert(e >= 58 and e <= 68, what .. ": means 60 s (~" .. e .. ")")
        end
        -- Met: success as soon as the level arrives.
        local waiter = sut:run_async("/usr/bin/net", { args = { "wait", "link", "30" } })
        local tr = os.time()
        nic:reconnect()
        local rw = waiter:wait("40s")
        local ew = os.time() - tr
        t:log("net wait link 30 across the reconnect: exit " .. rw.exit_code .. " after ~" .. ew .. " s " .. rw.stderr)
        t:assert_eq(rw.exit_code, 0, "succeeds once the level is met")
        t:assert(ew < 20, "well before its timeout")
        rebind(t)
    end)

-- ---------------------------------------------------------------------------
-- Exit statuses
-- ---------------------------------------------------------------------------

test("net exits 0 on success, 1 on a failure, 2 on a usage error",
    { spec = "netd *net.exit-status" }, function(t)
        rebind(t)
        local function code(args, want, why)
            local r = net(args)
            t:log(string.format("net %s -> %d %s", args, r.exit_code, r.stderr:gsub("\n.*", "")))
            t:assert_eq(r.exit_code, want, "net " .. args .. ": " .. why)
            return r
        end
        code("status", 0, "success")
        code("reconcile", 0, "success")
        code("version", 0, "success")
        -- 2: usage.
        local u = code("bogus", 2, "an unknown subcommand")
        t:assert(u.stderr:find("^usage: net status"), "prints the usage")
        code("", 2, "no subcommand")
        code("renew", 2, "a wrong argument count")
        code("renew eth0 extra", 2, "a wrong argument count")
        code("status extra", 2, "a wrong argument count")
        code("wait", 2, "a wrong argument count")
        code("wait bogus", 2, "an unknown level")
        code("policy wait x", 2, "a non-numeric policy wait timeout")
        -- 1: an error reply.
        local e = code("renew nosuch", 1, "an error reply")
        t:assert_eq(e.stderr, "net: no interface nosuch\n", "the error is printed")
        -- 1: a refused policy.
        write_bad_packet_rule()
        code("policy wait 10", 1, "a refused policy")
        del_tree(BAD_PACKET)
        code("policy wait 10", 0, "repaired")
        -- 1: netd unreachable, a timeout, a key that cannot be opened.
        stop_netd()
        local d = code("status", 1, "netd unreachable")
        t:assert(d.stderr:find("net: cannot reach netd at /run/netd/control.sock", 1, true), "says so")
        code("reconcile", 1, "netd unreachable")
        code("renew eth0", 1, "netd unreachable")
        code("wait link 1", 1, "a timeout")
        sut:run("reg export --json '" .. KEY .. "\\Rules\\Interface' /tmp/pt-rules.json"):assert_ok()
        del_tree([[Rules\Interface]])
        code("rules", 1, "a registry key that cannot be opened")
        network.reg(sut, { "apply", "/tmp/pt-rules.json" }):assert_ok()
        code("rules", 0, "restored")
        start_netd()
        rebind(t)
    end)
