-- resolvd §3.2 "After a loss" — when an established channel is dropped,
-- the next attempt is 0.5 s later and, while attempts keep failing, the
-- ones after it come 0.5, 1, 2, 4, 8 and then 10 s apart; none of those
-- failures is logged as `netd not reachable`.
--
-- Harness: the scripted gateway (helpers.gateway) and a whole Peios
-- (helpers.network). The agent stands in for netd, as in
-- resolvd-netd-subscribe.test.lua (netd's socket renamed aside, a
-- listener of the agent's at the path, resolvd restarted onto it).
--
-- How a gap is measured: with resolvd connected, the stand-in removes its
-- listener and closes the connection — a loss, logged by resolvd (L) —
-- so the attempts after it fail. It starts listening again at a chosen
-- moment between two scheduled attempts; the connection arrives at the
-- next one. The attempts after a loss fall at L + 0.5, 1, 2, 4, 8, 16,
-- 26 s; each case measures one of them. Times are the guest's wall
-- clock, which eventd stamps log lines with.
--
-- Own VMs: resolvd runs against a stand-in netd. resolvd is restarted
-- with `svctl stop; rm -rf /run/resolvd; svctl start` (PEI-1373).

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local unixsock = require("helpers.unixsock")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
local sut = network.boot({ bridges = { lan }, gateway = gw })

local ASIDE = "/run/netd/control.pt-aside.sock"
local SOCK_SDDL = "O:SYG:SYD:(A;;GA;;;SY)(A;;GRGWGX;;;WD)"
local RESTART = "svctl stop resolvd; rm -rf /run/resolvd; svctl start resolvd"

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

-- ---- the stand-in ----------------------------------------------------------

local fake = {}
local STAGE = "/run/netd/pt-staged.sock"

--- A listener of the agent's at `path`, with netd's descriptor.
local function listener(path)
    sys.unlink(sut, path)
    local l = assert(unixsock.socket(sut, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
    local r = unixsock.bind(sut, l, path)
    assert(r.ret == 0, "bind: " .. unixsock.errname(r.errno))
    -- netd's own descriptor on its socket (netd §9.1): without it the file
    -- inherits /run's SYSTEM-only one and resolvd's connect is refused.
    local sd = sut:run("sd set " .. path .. " '" .. SOCK_SDDL .. "'", { timeout = 15 })
    assert(sd.exit_code == 0, "sd set: " .. sd.stdout .. sd.stderr)
    r = unixsock.listen(sut, l, 16)
    assert(r.ret == 0, "listen: " .. unixsock.errname(r.errno))
    return l
end

--- Stop listening at the path: attempts now fail (no such file).
local function clear()
    if fake.l then sys.close(sut, fake.l) end
    fake.l = nil
    sys.unlink(sut, network.CONTROL)
end

--- Move the listener staged beside the path into place: one rename(2).
local function go_live()
    local r = sys.rename(sut, STAGE, network.CONTROL)
    assert(r.ret == 0, "rename into place: " .. sys.errname(r.errno or 0))
    fake.l, fake.staged = fake.staged, nil
end

local function accept(timeout_ms)
    local ev = ntfe.poll(sut, fake.l, ntfe.POLLIN, timeout_ms)
    if ev == 0 then return nil end
    local at = now()
    local fd = assert(unixsock.accept(sut, fake.l))
    return { fd = fd, at = at }
end

local conn, start

-- ---------------------------------------------------------------------------

test("after a loss the attempts come 0.5 s after it, then 0.5, 1, 2, 4 and 8 s apart, then every 10 s; no `netd not reachable` warning for any of them",
    { spec = "resolvd *netd-reconnect.sequence-after-loss resolvd *netd-reconnect.no-unreachable-warning-after-loss" },
    function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound")
        local r = sys.rename(sut, network.CONTROL, ASIDE)
        t:assert(r.ret == 0, "netd's socket moved aside: " .. sys.errname(r.errno or 0))
        fake.l = listener(network.CONTROL)
        start = now()
        sut:run(RESTART, { timeout = 30 }):assert_ok()
        conn = accept(15000)
        t:assert(conn, "resolvd connected to the stand-in")

        -- Attempts after a loss at L: L+0.5, +1, +2, +4, +8, +16, +26.
        local cases = { { 0.2, 0, 0.5 }, { 0.75, 0.5, 1.0 }, { 1.5, 1.0, 2.0 }, { 3, 2.0, 4.0 },
            { 6, 4.0, 8.0 }, { 12, 8.0, 16.0 }, { 21, 16.0, 26.0 } }
        for _, c in ipairs(cases) do
            local x, prev, want = c[1], c[2], c[3]
            fake.staged = listener(STAGE)
            local since = now()
            clear()
            local closed_at = now()
            sys.close(sut, conn.fd)
            local lead = closed_at + x - now()
            if lead > 0.03 then sut:run(string.format("sleep %.3f", lead - 0.03)) end
            local listened = now()
            go_live()
            conn = accept(math.floor((want - x + 4) * 1000))
            local lines = rlog(since)
            local lost = matching(lines, "resolvd: warn: lost the netd channel; reconnecting")[1]
            t:assert(lost, "the loss is logged")
            t:log(string.format("loss at %.3f: listening from +%.3f; reconnected at +%s (expected +%.1f)",
                lost.ts, listened - lost.ts, conn and string.format("%.3f", conn.at - lost.ts) or "never", want))
            t:assert(listened - lost.ts > prev and listened - lost.ts < want - 0.05,
                string.format("listening began between the attempts at +%.1f and +%.1f", prev, want))
            t:assert(conn, "resolvd reconnected")
            t:assert(conn.at - lost.ts > want - 0.15 and conn.at - lost.ts < want + 0.4,
                string.format("at the attempt +%.1f s after the loss", want))
        end
        local all = rlog(start)
        dump(t, all)
        t:assert_eq(#matching(all, "netd not reachable"), 0,
            "dozens of failed attempts after losses, and not one `netd not reachable`")
        t:assert_eq(#matching(all, "lost the netd channel"), #cases, "one loss line per loss")
    end)
