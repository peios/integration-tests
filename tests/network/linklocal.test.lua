-- netd TRM §5.5 — link-local fallback: when netd self-assigns a 169.254/16
-- address, which address it picks, and when the address goes again.
--
-- One gateway that records every DHCP message and answers none of them
-- (`gw:dhcp{silent = true}`) until the last test arms it. The machine
-- runs the shipped baseline, whose `Profiles\default` carries
-- `Address.LinkLocal`, so the fallback is reachable with no registry
-- edit at all. The file has its own pair because it needs discovery to
-- go unanswered from the first DISCOVER of the machine's life: a client
-- that ever held a lease starts in INIT-REBOOT, and `linklocal-static`
-- needs a profile edit this file must not see.
--
-- Timing comes from the client, not the gateway: each DISCOVER carries
-- `secs`, the seconds since its client started, while the gateway stamps
-- a frame only with the second it was pumped (the boot-time DISCOVER is
-- read at the first pump, long after it was sent). Where the TRM's claim
-- is about order — the address after the fourth DISCOVER, discovery
-- still going after it — order is what is asserted.
--
-- The address is computed here from the machine's MAC by the TRM's rule
-- and compared exactly. The no-MAC branch of the rule (interface index
-- times 2654435761) has no route from a guest: netd starts a DHCPv4
-- client only on a link with a MAC (main.rs `start_dhcp_where_due`), so
-- a link without one never reaches the fallback at all. That is recorded
-- in the agent report rather than tested.
--
-- Three tests, in order, sharing the pair: the report and the address;
-- stopping the client forgets it; a lease forgets it (the server is armed
-- only there).

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local rtnl = require("helpers.rtnl")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600, silent = true })
local sut = network.boot({ bridges = { lan }, gateway = gw })

local PROFILE = [[Profiles\default]]
local REPORT = "interface eth0: no DHCP offer; link-local "

--- The 169.254/16 entries of an interface's status addresses.
local function link_locals(i)
    local out = {}
    for _, a in ipairs((i and i.addresses) or {}) do
        if a:match("^169%.254%.") then out[#out + 1] = a end
    end
    return out
end

--- The TRM's derivation from a 6-byte MAC: seed = last four bytes,
--- big-endian; host = 256 + seed mod 64768.
local function expected_link_local(mac)
    local seed = string.unpack(">I4", mac, 3)
    local host = 256 + seed % 64768
    return string.format("169.254.%d.%d", host // 256, host % 256)
end

--- netd log lines containing `text` (plain), counted.
local function count_logged(text)
    local n = 0
    for _, l in ipairs(network.logs(sut, { take = 400 })) do
        if l:find(text, 1, true) then n = n + 1 end
    end
    return n
end

--- The DISCOVERs seen with transaction id `xid`, in order.
local function discovers(xid)
    local out = {}
    for _, m in ipairs(gw:dhcp_messages(gateway.DHCP.DISCOVER)) do
        if xid == nil or m.xid == xid then out[#out + 1] = m end
    end
    return out
end

local function status_iface()
    return network.iface(network.status(sut), "eth0")
end

local mac, expected, first_xid

test("at the client's fourth DISCOVER netd logs the report and desires the MAC-derived 169.254 address at /16",
    { spec = "netd *linklocal.when netd *linklocal.address-derivation" }, function(t)
        local i = status_iface()
        t:assert(i, "eth0 is in the status reply")
        mac = gateway.mac(i.mac)
        expected = expected_link_local(mac)
        t:log("eth0 MAC " .. i.mac .. " → expected link-local " .. expected)
        t:assert(expected:match("^169%.254%.") and expected ~= "169.254.0.0", "the rule gives a 169.254 address")

        -- Up to the third DISCOVER no report has been made and nothing is
        -- desired: the address must not be there yet.
        t:assert(gw:serve({ timeout = 40, until_ = function() return #discovers() >= 3 end }),
            "three DISCOVERs arrive from the silent network")
        local xid = discovers()[1].xid
        first_xid = xid
        t:assert_eq(#discovers(xid), #discovers(), "every DISCOVER so far is one client's (one xid)")
        local before = status_iface()
        t:assert_eq(#link_locals(before), 0,
            "no link-local address after three DISCOVERs: " .. table.concat(before.addresses, " "))
        t:assert_eq(count_logged(REPORT), 0, "and no report logged yet")

        -- Then the fourth DISCOVER, the report, and the address.
        local s = network.serve_until(gw, sut, function(x) return #link_locals(x) > 0 end,
            { iface = "eth0", timeout = 40 })
        t:assert(s, "a link-local address appears")
        -- The report and the fourth DISCOVER are one timer firing, so the
        -- status can show the address a pump before the gateway has read
        -- that DISCOVER off its socket. Read what is waiting first.
        gw:serve({ timeout = 1 })
        local d = discovers(xid)
        for n, m in ipairs(d) do t:log(string.format("DISCOVER %d: secs=%d, read at +%ds", n, m.secs, m.at)) end
        t:assert(#d >= 4, "the address came after the fourth DISCOVER (saw " .. #d .. ")")
        t:assert(#d <= 4, "and before the fifth: the report is made on the third retransmission")
        t:assert(d[4].secs >= 24 and d[4].secs <= 32,
            "the fourth DISCOVER is about 28 s after discovery began (secs = " .. d[4].secs .. ")")

        local i2 = network.iface(s, "eth0")
        local ll = link_locals(i2)
        t:assert_eq(#ll, 1, "exactly one link-local address: " .. table.concat(ll, " "))
        t:assert_eq(ll[1], expected .. "/16", "the address is the MAC's, at prefix 16")
        t:assert(network.logged(sut, REPORT .. expected),
            "netd logged `" .. REPORT .. expected .. "`")
        t:assert_eq(count_logged(REPORT), 1, "once")
        local k = rtnl.address(sut, i2.index, expected)
        t:assert(k, "the kernel holds " .. expected)
        t:assert_eq(k.prefix, 16, "at prefix 16 in the kernel too")
        t:assert_eq(i2.lease, nil, "no lease is held")
    end)

test("stopping the client forgets the link-local address and the next reconcile removes it",
    { spec = "netd *linklocal.dropped-on-lease-or-stop" }, function(t)
        t:assert(expected, "the first test found the address")
        t:assert_eq(#link_locals(status_iface()), 1, "the link-local address is held to begin with")
        local reports = count_logged(REPORT)
        -- Address.Offered = 0 changes the profile, which stops the DHCPv4
        -- client (§3.3), and wants no client in its place.
        network.write(sut, PROFILE, { ["Address.Offered"] = "dword:0" })
        local s = network.serve_until(gw, sut, function(x) return #link_locals(x) == 0 end,
            { iface = "eth0", timeout = 30 })
        t:assert(s, "the link-local address is removed once the client stops")
        local i = network.iface(s, "eth0")
        t:assert_eq(rtnl.address(sut, i.index, expected), nil, "and the kernel no longer holds it")
        t:assert_eq(count_logged(REPORT), reports, "with no new report: no client is running")

        -- Put the baseline back. A fresh client starts; it has never held
        -- a lease, so it opens with discovery again.
        network.write(sut, PROFILE, { ["Address.Offered"] = "dword:1" })
        t:assert(gw:serve({ timeout = 30, until_ = function()
            local d = gw:dhcp_messages(gateway.DHCP.DISCOVER)
            return d[#d].xid ~= first_xid
        end }), "a new client starts discovering")
    end)

test("a lease forgets the link-local address; discovery had carried on after the report",
    { spec = "netd *linklocal.dropped-on-lease-or-stop" }, function(t)
        t:assert(expected, "the first test found the address")
        -- The new client reports again (its flag is fresh) and takes the
        -- same address: the derivation is a pure function of the link.
        local all = gw:dhcp_messages(gateway.DHCP.DISCOVER)
        local xid = all[#all].xid
        local s = network.serve_until(gw, sut, function(x) return #link_locals(x) > 0 end,
            { iface = "eth0", timeout = 45 })
        t:assert(s, "the new client's report brings the link-local address back")
        t:assert_eq(link_locals(network.iface(s, "eth0"))[1], expected .. "/16", "the same address as before")
        local reported_after = #discovers(xid)
        t:log("DISCOVERs from client " .. string.format("%08x", xid) .. " at the report: " .. reported_after)

        -- Now a server answers. The client is still discovering, so its
        -- next DISCOVER is answered and it binds.
        gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
        s = network.serve_until(gw, sut, network.bound, { iface = "eth0", timeout = 60 })
        t:assert(s, "the client binds a lease")
        local d = discovers(xid)
        t:assert(#d > reported_after,
            "the DISCOVER that was answered came after the report (" .. #d .. " > " .. reported_after .. ")")
        t:log("answered DISCOVER: secs=" .. d[#d].secs)
        local i = network.iface(s, "eth0")
        -- The bind and the reconcile that follows it are one iteration,
        -- but give the status a moment to show it.
        s = network.serve_until(gw, sut, function(x)
            return #link_locals(x) == 0 and network.has_address(x, "10.77.0.50")
        end, { iface = "eth0", timeout = 15 })
        t:assert(s, "with a lease the link-local address is gone and the lease address is there: "
            .. table.concat(network.iface(network.status(sut), "eth0").addresses, " "))
        t:assert_eq(rtnl.address(sut, i.index, expected), nil, "the kernel no longer holds the link-local address")
        local k = rtnl.address(sut, i.index, "10.77.0.50")
        t:assert(k and k.prefix == 24, "the kernel holds the lease address at /24")
    end)
