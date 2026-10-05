-- netd §2.1 — Startup with no Machine\System\Network: the configuration
-- is empty, the registry watch cannot be armed, a key created afterwards
-- is never read, and a restart of netd picks it up.
--
-- Harness: the scripted gateway (helpers.gateway) and a whole Peios
-- (helpers.network); netd stopped and started through peinit.
--
-- Own VMs, and the whole file is one test: the key is deleted, and it
-- holds more than netd's configuration (the kernel engine's packet
-- rules, the port reservations). It is saved with `reg export --json`
-- and put back with `reg apply` in one transaction.
--
-- netd must be STOPPED when the key goes: a running netd recreates
-- Machine\System\Network on its next pass (its inventory writes open or
-- create the key), so the deletion would never be what a start sees.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
local sut = network.boot({ bridges = { lan }, gateway = gw })

local KEY = network.KEY

local function guest_ns()
    return assert(tonumber(sut:run("date +%s%N").stdout:match("%d+")), "guest clock")
end

--- netd's log lines newer than `since` (guest ns), oldest first, in the
--- order eventd recorded them.
local function log_since(since)
    local r = sut:run("evctl 'LOGS FROM netd SINCE 1h ago TAKE 5000'")
    assert(r.exit_code == 0, "evctl: " .. r.stderr)
    local newest_first = {}
    for line in r.stdout:gmatch("[^\n]+") do
        local msg = line:match('message="(.-)"  origin=')
        local ts = tonumber(line:match("timestamp=(%d+)"))
        if msg and ts and ts > since then
            newest_first[#newest_first + 1] = { ts = ts, msg = (msg:gsub("\\(.)", "%1")) }
        end
    end
    local out = {}
    for i = #newest_first, 1, -1 do out[#out + 1] = newest_first[i] end
    return out
end

local function find(lines, text)
    for i, l in ipairs(lines) do
        if l.msg:find(text, 1, true) then return i end
    end
end

local function dump(t, lines)
    local out = {}
    for _, l in ipairs(lines) do out[#out + 1] = l.msg end
    t:log("netd log:\n" .. table.concat(out, "\n"))
end

local function svc()
    return json.decode(sut:run("svctl --json status netd").stdout) or {}
end

local function settle()
    wait_until(function() return svc().current_operation == nil end,
        { timeout = 60, interval = 0.25, desc = "peinit's operation on netd to finish" })
end

test("a configuration key missing at startup is read once: created later it is not read, and a restart reads it",
    { spec = "netd *startup.missing-root-is-read-once" }, function(t)
        local s = network.serve_until(gw, sut, network.bound, { iface = "eth0", timeout = 60 })
        t:assert(s, "bound under the baseline")
        t:assert_eq(network.iface(s, "eth0").rule, "wired", "joined by the shipped rule")

        sut:run("svctl stop netd")
        wait_until(function() return network.netd_pid(sut) == nil end,
            { timeout = 60, interval = 0.25, desc = "netd to stop" })
        settle()
        sut:run("reg export --json '" .. KEY .. "' /tmp/pt-network.json"):assert_ok()
        network.reg(sut, { "del", "-r", KEY }):assert_ok()
        t:assert(network.reg(sut, { "get", KEY }).exit_code ~= 0, "Machine\\System\\Network is gone")

        local mark = guest_ns()
        sut:run("svctl start netd")
        wait_until(function()
            local x = network.call(sut, { query = "status" })
            return x ~= nil and x.ok == true
        end, { timeout = 60, interval = 0.25, desc = "netd answering" })
        local lines = log_since(mark)
        dump(t, lines)
        t:assert(find(lines, "netd: warn: " .. KEY .. " does not exist; running with no policy") ~= nil,
            "the missing key is no configuration")
        t:assert(find(lines, "netd: warn: registry watch unavailable (") ~= nil
            and find(lines, "); configuration is read once") ~= nil,
            "and the watch cannot be armed")
        t:assert(find(lines, "0 rule tree(s), 0 profile(s), ") ~= nil, "no rules and no profiles")
        local i = network.iface(network.status(sut), "eth0")
        t:assert_eq(i.rule, "backstop", "the backstop answers for eth0")
        t:assert_eq(i.verdict, nil, "which is ignored")
        t:log("after netd's first pass the key " ..
            (network.reg(sut, { "get", KEY }).exit_code == 0 and "exists again (netd's inventory)" or "is still absent"))

        -- The configuration comes back, whole, in one transaction.
        mark = guest_ns()
        network.reg(sut, { "apply", "/tmp/pt-network.json" }):assert_ok()
        t:assert(network.reg(sut, { "get", KEY .. "\\Rules\\Interface\\wired" }).exit_code == 0,
            "the shipped rule is in the registry again")
        -- A full pass on demand, and time for any watch to have fired.
        sut:run("net reconcile"):assert_ok()
        gw:serve({ timeout = 3 })
        sut:run("net reconcile"):assert_ok()
        lines = log_since(mark)
        dump(t, lines)
        t:assert_eq(find(lines, "configuration changed"), nil, "the written key is never read")
        t:assert_eq(find(lines, "interface layer"), nil, "no generation is built from it")
        i = network.iface(network.status(sut), "eth0")
        t:assert_eq(i.rule, "backstop", "eth0 is still judged by the empty policy")

        -- A restart reads it.
        network.restart_netd(sut)
        local back = network.serve_until(gw, sut, network.bound, { iface = "eth0", timeout = 60 })
        t:assert(back, "the restarted netd joins eth0 and binds")
        i = network.iface(back, "eth0")
        t:assert_eq(i.rule, "wired", "by the shipped rule")
        t:assert_eq(i.profile, "default", "into the shipped profile")
    end)
