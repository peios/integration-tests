-- netd §5.2 "Nobody answered", and §5.3's record of a lease: the
-- client's one-time report that discovery went unanswered (the interface
-- warning, and the link-local fallback it triggers), and a lease clearing
-- both.
--
-- Harness: the scripted gateway and one whole Peios machine on a private
-- bridge. A fresh client is made by a cable pull (a carrier loss stops the
-- client and forgets the network; reconnecting starts a new one), and the
-- gateway NAKs its INIT-REBOOT and ignores its DISCOVERs, so it sits in
-- Selecting from a known moment. The report comes at the fourth DISCOVER,
-- about 28 s in.
--
-- Own VMs: each "nobody answered" costs about half a minute of silence,
-- and the file edits Address.LinkLocal on the shipped profile.
--
-- The warning is looked at with Address.LinkLocal off. With it on, the
-- fallback address is added at the report, and the full pass that the
-- kernel's address event causes rewrites every interface's warning from
-- the rule judgement (main.rs sync_links), so it would be gone before a
-- status poll could see it (PEI-1364); the first test therefore turns the
-- fallback off, and the second (with it on) asserts on the address and
-- the log.

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
local nic = lan:nic(sut)

local D = gateway.DHCP
local PROFILE = "Profiles\\default"
local LEASED = "10.77.0.50"
local WARNING = "asked for an address; nobody answered"
local NETWORK = sha1.uuid5("peios-netd-network|wired|dhcp:10.77.0.1|10.77.0.0/24")
local INDEX = tonumber((sut:read_file("/sys/class/net/eth0/ifindex"):match("%d+")))

-- ---------------------------------------------------------------------------
-- Local helpers
-- ---------------------------------------------------------------------------

local function iface() return network.iface(network.status(sut), "eth0") end

local function bound(timeout)
    local s = network.serve_until(gw, sut, network.bound, { iface = true, timeout = timeout or 60 })
    assert(s, "netd did not bind a lease")
    return network.iface(s, "eth0")
end

local function renew()
    local r, err = network.call(sut, { query = "renew", interface = "eth0" })
    assert(r and r.ok, "renew: " .. tostring(err or (r and r.error)))
end

local function nak(m)
    return { op = 2, xid = m.xid, flags = m.flags, chaddr = m.chaddr, yiaddr = "0.0.0.0",
             siaddr = gw.addr, options = { { 53, string.char(D.NAK) }, { 54, gateway.ip4(gw.addr) } } }
end

local function count_logged(text)
    local n = 0
    for _, l in ipairs(network.logs(sut, { since = "30m ago", take = 2000 })) do
        if l:find(text, 1, true) then n = n + 1 end
    end
    return n
end

--- The 169.254/16 addresses on eth0.
local function link_locals()
    local out = {}
    for _, a in ipairs(rtnl.addresses_of(sut, INDEX, 4)) do
        if a.address:match("^169%.254%.") then out[#out + 1] = a.address .. "/" .. a.prefix end
    end
    return out
end

--- The DISCOVERs of the newest Selecting exchange (the last xid seen).
local function discovers()
    local all = gw:dhcp_messages(D.DISCOVER)
    local last = all[#all]
    local out = {}
    for _, m in ipairs(all) do if last and m.xid == last.xid then out[#out + 1] = m end end
    return out
end

--- The gateway NAKs an INIT-REBOOT and offers nothing: the client goes
--- straight to Selecting and stays there.
local function refuse_everything()
    gw:dhcp({ pool = { LEASED }, lease = 3600, on = {
        reboot = function(m) return nak(m) end,
        renew = function(m) return nak(m) end,
        discover = function() return false end,
    } })
end

--- Pump, polling the status reply, until `n` DISCOVERs of one exchange
--- have been seen and `extra` seconds more; returns every poll as
--- `{discovers = k, warning = …, at = gateway second}`.
local function watch_until_discovers(n, extra, timeout)
    local polls, reached = {}, nil
    gw:serve({ timeout = timeout or 60, until_ = function()
        local i = iface()
        local k = #discovers()
        polls[#polls + 1] = { discovers = k, warning = i.warning, at = gw:now() }
        if k >= n and not reached then reached = gw:now() end
        return reached ~= nil and gw:now() >= reached + extra
    end })
    assert(reached, "fewer than " .. n .. " DISCOVERs")
    return polls
end

-- ---------------------------------------------------------------------------
-- The warning
-- ---------------------------------------------------------------------------

test("the fourth DISCOVER reports that nobody answered (the warning); a lease then clears it and the network is identified",
    { spec = "netd *dhcp4-timers.no-offer-once-per-client netd *dhcp4-lease.bound-clears-link-local-and-warning" },
    function(t)
        bound()
        network.write(sut, PROFILE, { ["Address.LinkLocal"] = "dword:0" })
        -- The edit restarts the client; let it bind, then start a fresh one.
        gw:serve({ timeout = 2 })
        bound()
        refuse_everything()
        nic:disconnect()
        assert(network.serve_until(gw, sut, function(i) return i.carrier == false end,
            { iface = true, timeout = 20 }), "carrier did not drop")
        gw:forget()
        nic:reconnect()
        local polls = watch_until_discovers(4, 3, 60)
        local before4, after4 = {}, {}
        for _, p in ipairs(polls) do
            if p.discovers < 4 then before4[#before4 + 1] = tostring(p.warning)
            else after4[#after4 + 1] = tostring(p.warning) end
        end
        local ds = discovers()
        t:log(string.format("DISCOVER secs: %s", (function()
            local s = {}; for _, m in ipairs(ds) do s[#s + 1] = m.secs end; return table.concat(s, ",") end)()))
        t:log("warning before the 4th DISCOVER: " .. table.concat(before4, " | "))
        t:log("warning after it: " .. table.concat(after4, " | "))
        for _, w in ipairs(before4) do t:assert_eq(w, "nil", "no warning before the fourth DISCOVER") end
        t:assert(#after4 > 0, "polled after the fourth DISCOVER")
        for _, w in ipairs(after4) do t:assert_eq(w, WARNING, "the warning after the fourth DISCOVER") end
        t:assert(ds[4].secs - ds[1].secs >= 25 and ds[4].secs - ds[1].secs <= 31,
            "the fourth DISCOVER about 28 s after the first")
        t:assert_eq(#link_locals(), 0, "no fallback address while Address.LinkLocal is off")
        t:assert_eq(iface().network, nil, "no network identified while nobody answers")

        gw:dhcp({ pool = { LEASED }, lease = 3600 })
        local i = bound()
        t:log("after binding: warning " .. tostring(i.warning) .. ", network " .. tostring(i.network))
        t:assert_eq(i.warning, nil, "binding cleared the warning")
        local s = network.serve_until(gw, sut, function(x) return x.network ~= nil end,
            { iface = true, timeout = 5 })
        t:assert(s, "the network was identified")
        t:assert_eq(s and network.iface(s, "eth0").network, NETWORK, "as the gateway's network")
    end)

-- ---------------------------------------------------------------------------
-- The fallback, once per client
-- ---------------------------------------------------------------------------

-- PEI-1331: the report is made at most once per client, so a client that
-- lost a lease falls back to a link-local address only the first time.
-- This test asserts that current behaviour.
test("the report is made once in a client's life: a lease clears the fallback, and losing it does not fall back again",
    { spec = "netd *dhcp4-timers.no-offer-once-per-client netd *dhcp4-lease.bound-clears-link-local-and-warning" },
    function(t)
        bound()
        network.write(sut, PROFILE, { ["Address.LinkLocal"] = "dword:1" })
        gw:serve({ timeout = 2 })
        bound()
        local reports = count_logged("interface eth0: no DHCP offer; link-local")
        refuse_everything()
        nic:disconnect()
        assert(network.serve_until(gw, sut, function(i) return i.carrier == false end,
            { iface = true, timeout = 20 }), "carrier did not drop")
        gw:forget()
        nic:reconnect()
        watch_until_discovers(4, 0, 60)
        local fell_back = network.serve_until(gw, sut, function() return #link_locals() == 1 end,
            { timeout = 5 })
        t:log("link-local after the report: " .. table.concat(link_locals(), ","))
        t:assert(fell_back, "a link-local address after the fourth DISCOVER")
        -- Evidence for the report (not asserted: §5.2 does not say how long
        -- the warning lasts): what status shows with the fallback on.
        t:log("warning with the fallback on: " .. tostring(iface().warning))
        t:assert(link_locals()[1]:match("/16$"), "at prefix 16")
        t:assert_eq(count_logged("interface eth0: no DHCP offer; link-local"), reports + 1, "the report was logged")

        -- A lease clears the fallback address.
        gw:dhcp({ pool = { LEASED }, lease = 3600 })
        local i = bound()
        local cleared = network.serve_until(gw, sut, function() return #link_locals() == 0 end, { timeout = 10 })
        t:assert(cleared, "binding removed the link-local address")
        t:assert_eq(i.warning, nil, "and there is no warning")

        -- Lose the lease (a NAK while renewing) and let discovery go
        -- unanswered past the fourth DISCOVER again.
        refuse_everything()
        gw:forget()
        renew()
        watch_until_discovers(4, 4, 60)
        local ds = discovers()
        t:log(string.format("second round: %d DISCOVERs, secs %d..%d; link-locals: %s", #ds, ds[1].secs,
            ds[#ds].secs, table.concat(link_locals(), ",")))
        t:assert(#ds >= 4, "the client discovered four times again")
        t:assert_eq(#link_locals(), 0, "no second fallback: the report is not made again (PEI-1331)")
        t:assert_eq(count_logged("interface eth0: no DHCP offer; link-local"), reports + 1,
            "no second `no DHCP offer` line")
        t:assert_eq(iface().warning, nil, "and no warning")
        gw:dhcp({ pool = { LEASED }, lease = 3600 })
        bound()
    end)
