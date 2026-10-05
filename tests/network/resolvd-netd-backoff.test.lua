-- resolvd §3.2 — reconnection from startup: the backoff sequence when
-- netd is not there, the one `netd not reachable` warning, a failure at
-- connect counting as a failed attempt, a success resetting the backoff,
-- and what resolvd answers before it has ever had a snapshot.
--
-- Harness: the scripted gateway (helpers.gateway) with its DNS server
-- (helpers.dns), and a whole Peios (helpers.network). netd's socket is
-- renamed aside (netd keeps running and keeps the lease), so the path
-- resolvd connects to holds nothing, or a socket of the agent's.
--
-- How an attempt is seen: a failed attempt leaves no trace but the first
-- one's warning, so each case restarts resolvd with nothing at the path,
-- takes the time of that warning as the first attempt (T0), waits until
-- a chosen moment between two scheduled attempts, and only then starts
-- listening. The connection arrives at the next scheduled attempt, so
-- each case measures one gap of the sequence: 0.5, 1.5, 3.5, 7.5, 15.5,
-- 25.5, 35.5 s after T0. Every time is the guest's wall clock (`date`),
-- the clock eventd stamps log lines with.
--
-- Own VMs: resolvd is restarted seven times against a missing netd.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local unixsock = require("helpers.unixsock")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")
local dns = require("helpers.dns")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
local sut = network.boot({ bridges = { lan }, gateway = gw })

dns.serve(gw, { zone = {
    ["www.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.80" } },
} })

local RSOCK = "/run/resolvd/resolv.sock"
local ASIDE = "/run/netd/control.pt-aside.sock"
local SOCK_SDDL = "O:SYG:SYD:(A;;GA;;;SY)(A;;GRGWGX;;;WD)"
local UNREACHABLE = "resolvd: warn: netd not reachable ("
-- Not `svctl restart`: that leaves resolvd unable to bind its socket
-- (PEI-1373).
local RESTART = "svctl stop resolvd; rm -rf /run/resolvd; svctl start resolvd"

local function rstatus()
    local s, err = network.call(sut, { query = "status" }, { path = RSOCK })
    assert(s and s.ok, "resolvd status: " .. tostring(err or (s and s.error)))
    return s
end

--- The guest's wall clock, in seconds (float).
local function now()
    return assert(tonumber(sut:run("date +%s.%N").stdout:match("[%d%.]+")), "guest clock")
end

local function rlog(since)
    local r = sut:run("evctl 'LOGS FROM resolvd SINCE 1h ago TAKE 5000'")
    assert(r.exit_code == 0, "evctl: " .. r.stderr)
    local newest_first = {}
    for line in r.stdout:gmatch("[^\n]+") do
        local msg = line:match('message="(.-)"  origin=')
        local ts = tonumber(line:match("timestamp=(%d+)"))
        if msg and ts and ts / 1e9 > (since or 0) then
            newest_first[#newest_first + 1] = { ts = ts / 1e9, msg = (msg:gsub("\\(.)", "%1")) }
        end
    end
    local out = {}
    for i = #newest_first, 1, -1 do out[#out + 1] = newest_first[i] end
    return out
end

local function matching(lines, text)
    local out = {}
    for _, l in ipairs(lines) do if l.msg:find(text, 1, true) then out[#out + 1] = l end end
    return out
end

local function dump(t, lines)
    local out = {}
    for _, l in ipairs(lines) do out[#out + 1] = string.format("%.3f %s", l.ts, l.msg) end
    t:log("resolvd log:\n" .. table.concat(out, "\n"))
end

local function served(cmd, timeout)
    local p = sut:run_async("sh", { args = { "-c", cmd } })
    gw:serve({ timeout = timeout or 20, until_ = function() return p:status() == "exited" end })
    return p:wait(5)
end

-- ---- the path --------------------------------------------------------------

local fake = {}
local STAGE = "/run/netd/pt-staged.sock"

local function clear()
    if fake.l then sys.close(sut, fake.l) end
    fake.l, fake.mode = nil, nil
    sys.unlink(sut, network.CONTROL)
    sys.unlink(sut, STAGE)
end

--- A socket of the agent's at `path`, with netd's descriptor.
local function bound(path)
    local l = assert(unixsock.socket(sut, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
    local r = unixsock.bind(sut, l, path)
    assert(r.ret == 0, "bind: " .. unixsock.errname(r.errno))
    -- netd's own descriptor on its socket (netd §9.1): without it the file
    -- inherits /run's SYSTEM-only one and resolvd's connect is refused.
    local sd = sut:run("sd set " .. path .. " '" .. SOCK_SDDL .. "'", { timeout = 15 })
    assert(sd.exit_code == 0, "sd set: " .. sd.stdout .. sd.stderr)
    return l
end

--- A socket bound at the path, not yet listening: connect is refused.
local function bind_only()
    clear()
    fake.l, fake.mode = bound(network.CONTROL), "bound"
end

--- A listener made ready beside the path, so that going live is a single
--- rename(2) at the moment chosen.
local function stage()
    clear()
    fake.l, fake.mode = bound(STAGE), "staged"
    local r = unixsock.listen(sut, fake.l, 16)
    assert(r.ret == 0, "listen: " .. unixsock.errname(r.errno))
end

--- Start accepting at the path: listen on the bound socket, or move the
--- staged listener into place.
local function listen()
    if fake.mode == "bound" then
        local r = unixsock.listen(sut, fake.l, 16)
        assert(r.ret == 0, "listen: " .. unixsock.errname(r.errno))
    else
        if fake.mode ~= "staged" then stage() end
        local r = sys.rename(sut, STAGE, network.CONTROL)
        assert(r.ret == 0, "rename into place: " .. sys.errname(r.errno or 0))
    end
    fake.mode = "live"
end

--- Wait for a connection; returns {fd, at} (at: guest seconds).
local function accept(timeout_ms)
    local ev = ntfe.poll(sut, fake.l, ntfe.POLLIN, timeout_ms)
    if ev == 0 then return nil end
    local at = now()
    local fd = assert(unixsock.accept(sut, fake.l))
    return { fd = fd, at = at }
end

local function move_netd_aside(t)
    if fake.moved then return end
    local r = sys.rename(sut, network.CONTROL, ASIDE)
    t:assert(r.ret == 0, "netd's socket moved aside: " .. sys.errname(r.errno or 0))
    fake.moved = true
end

--- Restart resolvd with nothing listening at the path (`o.refused`: a
--- bound, unlistening socket there instead), and return the time of its
--- first attempt, read from its one warning, and the warning.
local function restart_unreachable(t, o)
    o = o or {}
    if o.refused then bind_only() else stage() end
    local since = now()
    sut:run(RESTART, { timeout = 30 }):assert_ok()
    local warn
    wait_until(function()
        warn = matching(rlog(since), UNREACHABLE)[1]
        return warn ~= nil
    end, { timeout = 10, interval = 0.05, desc = "the unreachable warning" })
    return warn.ts, warn.msg, since
end

--- One measurement: restart against a missing netd, start listening `x`
--- seconds after the first attempt, and return when the connection came,
--- relative to the first attempt, and when listening started. `during`
--- runs (after the restart) before the wait.
local function gap(t, x, want, o)
    o = o or {}
    if o.immediate then
        -- Too soon to read the warning first: listen as soon as the
        -- restart returns (readiness follows the first attempt), and read
        -- the first attempt's time afterwards.
        stage()
        local since = now()
        sut:run(RESTART, { timeout = 30 }):assert_ok()
        local before = now()
        listen()
        local c = accept(math.floor((want + 3) * 1000))
        local lines = rlog(since)
        local warn = matching(lines, UNREACHABLE)[1]
        assert(warn, "the first attempt failed and was logged")
        local m = { t0 = warn.ts, warning = warn.msg, listened = before - warn.ts, lines = lines,
            connected = c and (c.at - warn.ts) }
        if c then sys.close(sut, c.fd) end
        clear()
        return m
    end
    for _ = 1, 3 do
        local t0, warning, since = restart_unreachable(t, o)
        if o.during then o.during(t0) end
        local lead = t0 + x - now()
        if lead > 0.02 then
            sut:run(string.format("sleep %.3f", lead - 0.02))
            local listened = now() - t0
            listen()
            local c = accept(math.floor((want - listened + 3) * 1000))
            local lines = rlog(since)
            local m = { t0 = t0, warning = warning, listened = listened, lines = lines,
                connected = c and (c.at - t0) }
            if c then sys.close(sut, c.fd) end
            clear()
            return m
        end
        t:log(string.format("first attempt read too late to listen at +%.2fs; again", x))
    end
    error("could not place a listen at +" .. x .. " s")
end

local function check(t, m, prev, want)
    t:log(string.format("listening from +%.3fs; connected at +%s (expected +%.1f)", m.listened,
        m.connected and string.format("%.3f", m.connected) or "never", want))
    -- After the first attempt: no lower bound is needed, since nothing was
    -- at the path when resolvd started (its warning proves the first
    -- attempt failed) and listening began only after `svctl start`
    -- returned, which is after readiness, which follows the first attempt.
    t:assert((prev == 0 or m.listened > prev + 0.05) and m.listened < want - 0.05,
        string.format("listening began between the attempts at +%.1f and +%.1f", prev, want))
    t:assert(m.connected, "resolvd connected")
    t:assert(m.connected > want - 0.15 and m.connected < want + 0.4,
        string.format("at the attempt +%.1f s after the first (+%.3f)", want, m.connected))
end

-- ---------------------------------------------------------------------------

test("from a first attempt that fails, attempts come 0.5, 1.5, 3.5 and 7.5 s after it; a refused connect is a failed attempt like a missing socket",
    { spec = "resolvd *netd-reconnect.backoff-sequence resolvd *netd-subscribe.any-step-failure-is-failed-attempt" },
    function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound")
        move_netd_aside(t)
        local m = gap(t, 0.2, 0.5, { immediate = true })
        t:log("first warning: " .. m.warning)
        t:assert(m.warning:find("No such file or directory", 1, true), "the first failure: no socket at the path")
        check(t, m, 0, 0.5)
        check(t, gap(t, 0.9, 1.5), 0.5, 1.5)
        -- A socket bound but not listening: every connect is refused.
        m = gap(t, 2.5, 3.5, { refused = true })
        t:log("first warning: " .. m.warning)
        t:assert(m.warning:find("Connection refused", 1, true), "the first failure: connect refused")
        check(t, m, 1.5, 3.5)
        check(t, gap(t, 5, 7.5), 3.5, 7.5)
    end)

test("then 15.5 and 25.5 s after it, and every 10 s from there; one `netd not reachable` warning however many attempts fail",
    { spec = "resolvd *netd-reconnect.first-failure-logged-once" }, function(t)
        move_netd_aside(t)
        check(t, gap(t, 11, 15.5), 7.5, 15.5)
        local m = gap(t, 20, 25.5)
        check(t, m, 15.5, 25.5)
        dump(t, m.lines)
        local warnings = matching(m.lines, "netd not reachable")
        t:assert_eq(#warnings, 1, "six failed attempts, one warning")
        t:assert(m.warning:match("^resolvd: warn: netd not reachable %(.+%); retrying$"), "worded as documented: " .. m.warning)
        t:assert(#matching(m.lines, "resolvd: info: subscribed to netd") == 1, "then `subscribed to netd`")

        -- A resolvd whose first attempt succeeds never warns.
        listen()
        local since = now()
        sut:run(RESTART, { timeout = 30 }):assert_ok()
        local c = accept(10000)
        t:assert(c, "connected at once")
        sut:run("sleep 0.5")
        local lines = rlog(since)
        dump(t, lines)
        t:assert_eq(#matching(lines, "netd not reachable"), 0, "no warning when the first attempt succeeds")
        t:assert_eq(#matching(lines, "subscribed to netd"), 1, "subscribed")
        sys.close(sut, c.fd)
        clear()
    end)

test("before its first snapshot resolvd has no scopes: synthetic and static names are answered, the fallback servers used when configured, everything else unavailable; and attempts keep their 10 s pace (35.5 s)",
    { spec = "resolvd *netd-reconnect.no-snapshot-yet-behaviour" }, function(t)
        move_netd_aside(t)
        network.write(sut, "Dns", {})   -- `reg new` makes one level at a time
        network.write(sut, "Dns\\Hosts", { ["pt-static.test"] = "sz:10.77.5.5" })
        local seen = {}
        local m = gap(t, 30, 35.5, { during = function()
            local st = rstatus()
            seen.scopes, seen.netd = #(st.scopes or {}), st.netd
            local r = served("resolv query localhost A")
            seen.localhost = r.stdout
            r = served("resolv query pt-static.test A")
            seen.static = r.stdout
            r = served("resolv query www.example.test A")
            seen.www, seen.www_exit = r.stdout .. r.stderr, r.exit_code
            network.write(sut, "Dns", { FallbackServers = "multi:10.77.0.1" })
            wait_until(function() return (rstatus().fallback_servers or {})[1] == "10.77.0.1" end,
                { timeout = 10, interval = 0.1, desc = "the fallback server taken" })
            r = served("resolv query www.example.test A")
            seen.fallback, seen.fallback_exit = r.stdout, r.exit_code
            network.reg(sut, { "del", network.KEY .. "\\Dns", "FallbackServers" })
        end })
        for k, v in pairs(seen) do t:log(k .. ": " .. tostring(v)) end
        t:assert_eq(seen.scopes, 0, "no scopes")
        t:assert_eq(seen.netd, false, "not connected")
        t:assert(seen.localhost:find("^found  synthetic"), "localhost is synthetic")
        t:assert(seen.static:find("^found  hosts") and seen.static:find("10.77.5.5", 1, true), "a static name is answered")
        t:assert_eq(seen.www_exit, 3, "a network name with no fallback: unavailable")
        t:assert(seen.www:find("^unavailable"), "outcome unavailable")
        t:assert_eq(seen.fallback_exit, 0, "with a fallback server: found")
        t:assert(seen.fallback:find("^found  dns via 10%.77%.0%.1"), "through the fallback server")
        check(t, m, 25.5, 35.5)
        network.delete(sut, "Dns\\Hosts")
    end)

test("a success resets the backoff: grown to 10 s before it, the first retry after the next loss is 0.5 s",
    { spec = "resolvd *netd-reconnect.success-resets-backoff" }, function(t)
        move_netd_aside(t)
        -- Fail long enough for the backoff to reach its ceiling, then
        -- let the attempt at +25.5 s succeed.
        local t0 = restart_unreachable(t)
        sut:run(string.format("sleep %.3f", math.max(0, t0 + 20 - now())))
        listen()
        local c = accept(15000)
        t:assert(c, "connected")
        t:log(string.format("connected at +%.3f after a first attempt that failed", c.at - t0))
        t:assert(c.at - t0 > 25.3 and c.at - t0 < 26, "at +25.5 s: the backoff had reached 10 s")
        -- Lose the channel with nothing listening; listen again 0.25 s on.
        local since = now()
        stage()   -- the path is cleared; a listener waits beside it
        sys.close(sut, c.fd)
        sut:run("sleep 0.25")
        local listened = now()
        listen()
        local again = accept(5000)
        local lines = rlog(since)
        dump(t, lines)
        local lost = matching(lines, "lost the netd channel")[1]
        t:assert(lost, "the loss is logged")
        t:assert(again, "resolvd reconnected")
        t:log(string.format("loss at %.3f; listening from +%.3f; reconnected at +%.3f",
            lost.ts, listened - lost.ts, again.at - lost.ts))
        t:assert(listened - lost.ts < 0.45, "listening began before +0.5 s")
        t:assert(again.at - lost.ts > 0.35 and again.at - lost.ts < 0.9, "the first retry came 0.5 s after the loss")
        sys.close(sut, again.fd)
        clear()
    end)
