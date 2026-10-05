-- netd TRM §5.7 (second half) — the address a network gave: netd writes
-- the lease address to the network record's `RequestedAddress`, and a
-- starting client asks for that address first, with an INIT-REBOOT
-- REQUEST; the operator may write it too, as a soft reservation.
--
-- The gateway's pool has two addresses, and its INIT-REBOOT handler is
-- authoritative for its pool: it ACKs a request for either and NAKs any
-- other. That makes all three outcomes the TRM names reachable from the
-- operator's side of `RequestedAddress`: an address the server agrees to
-- (kept in one round trip, no DISCOVER), one it refuses (NAK, then
-- discovery afresh), and silence (two REQUESTs, then discovery).
--
-- While a lease is held netd rewrites `RequestedAddress` on every pass,
-- so an operator's value only survives to a client start if it is written
-- while no lease is held: with the cable out. Losing carrier also forgets
-- the network the interface stood on, so a client starting after a cable
-- pull finds the address through the interface's `Status LastNetwork`
-- (the second source). The first source, the network identified on the
-- interface right now, is what a client restarted with the carrier held
-- uses: a profile edit does that (§3.3).
--
-- One pair; the tests run in order.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local sha1 = require("helpers.sha1")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
local server = gw:dhcp({ pool = { "10.77.0.50", "10.77.0.60" }, lease = 3600 })
local sut = network.boot({ bridges = { lan }, gateway = gw })

local NETID = sha1.uuid5("peios-netd-network|wired|dhcp:10.77.0.1|10.77.0.0/24")
local RECORD = "Networks\\" .. NETID

local function requested() return network.get(sut, RECORD, "RequestedAddress") end

--- The INIT-REBOOT REQUESTs seen: no ciaddr, option 50, no option 54.
local function reboots()
    local out = {}
    for _, m in ipairs(gw:dhcp_messages(gateway.DHCP.REQUEST)) do
        if m.ciaddr == "0.0.0.0" and m.opt[50] and not m.opt[54] then out[#out + 1] = m end
    end
    return out
end

local function bound_with(addr)
    return function(i) return network.bound(i) and network.has_address(i, addr) end
end

local function unplug()
    local nic = lan:nic(sut)
    nic:disconnect()
    assert(network.serve_until(gw, sut, function(x) return x.carrier == false end,
        { iface = "eth0", timeout = 20 }), "carrier goes")
    return nic
end

test("while a lease is held netd writes its address to the network's RequestedAddress whenever it differs",
    { spec = "netd *dhcp4-memory.requested-address" }, function(t)
        local s = network.serve_until(gw, sut, network.bound, { iface = "eth0", timeout = 60 })
        t:assert(s, "netd bound a lease")
        t:assert_eq(network.iface(s, "eth0").network, NETID, "the interface stands on the computed network")
        t:assert(wait_until(function() return requested() == "10.77.0.50" end,
            { timeout = 10, interval = 0.25, desc = "RequestedAddress to be written" }),
            "RequestedAddress is the lease address")
        -- Written by anyone else while the lease is held, it is put back on
        -- the next pass (the registry write itself triggers one).
        network.write(sut, RECORD, { RequestedAddress = "sz:10.77.0.99" })
        t:assert(wait_until(function()
            gw:serve({ timeout = 0 })
            return requested() == "10.77.0.50"
        end, { timeout = 15, interval = 0.25, desc = "netd to rewrite RequestedAddress" }),
            "netd rewrites RequestedAddress to the lease address")
    end)

test("a client restarted on an identified network opens with an INIT-REBOOT REQUEST for its RequestedAddress",
    { spec = "netd *dhcp4-memory.requested-address" }, function(t)
        gw:forget()
        -- A profile edit restarts the client with the carrier held; the
        -- network stays identified on the interface (§7.1).
        network.write(sut, [[Profiles\default]], { ["Route.Metric"] = "dword:100" })
        t:assert(gw:serve({ timeout = 15, until_ = function() return #reboots() >= 1 end }),
            "the restarted client sends an INIT-REBOOT REQUEST")
        local m = reboots()[1]
        t:assert_eq(gateway.ip4_text(m.opt[50]), "10.77.0.50", "for the RequestedAddress")
        local s = network.serve_until(gw, sut, bound_with("10.77.0.50"), { iface = "eth0", timeout = 15 })
        t:assert(s, "the server agrees and the address is kept")
        t:assert_eq(#gw:dhcp_messages(gateway.DHCP.DISCOVER), 0, "in one round trip: no DISCOVER")
        network.reg(sut, { "del", network.KEY .. [[\Profiles\default]], "Route.Metric" }):assert_ok()
        t:assert(network.serve_until(gw, sut, network.bound, { iface = "eth0", timeout = 20 }), "and binds again")
    end)

test("RequestedAddress written by the operator is a soft reservation the next client asks for first",
    { spec = "netd *dhcp4-memory.requested-address-is-a-soft-reservation" }, function(t)
        local nic = unplug()
        t:assert_eq(network.iface(network.status(sut), "eth0").network, nil, "the network is forgotten with the carrier")
        t:assert_eq(network.get(sut, "Interfaces\\" .. network.iface(network.status(sut), "eth0").ifid .. "\\Status",
            "LastNetwork"), NETID, "but Status LastNetwork still names it")
        network.write(sut, RECORD, { RequestedAddress = "sz:10.77.0.60" })
        gw:forget()
        nic:reconnect()
        local s = network.serve_until(gw, sut, bound_with("10.77.0.60"), { iface = "eth0", timeout = 30 })
        t:assert(s, "the machine holds the reserved address")
        local r = reboots()
        t:assert(#r >= 1, "the client opened with an INIT-REBOOT REQUEST")
        t:assert_eq(gateway.ip4_text(r[1].opt[50]), "10.77.0.60", "for the operator's address")
        t:assert_eq(#gw:dhcp_messages(gateway.DHCP.DISCOVER), 0, "which the server granted without discovery")
        t:assert(not network.has_address(network.iface(s, "eth0"), "10.77.0.50"), "the old address is gone")
    end)

test("a server that refuses the requested address NAKs it, and the client discovers afresh",
    { spec = "netd *dhcp4-memory.requested-address" }, function(t)
        local nic = unplug()
        network.write(sut, RECORD, { RequestedAddress = "sz:10.77.0.200" })
        gw:forget()
        nic:reconnect()
        local s = network.serve_until(gw, sut, network.bound, { iface = "eth0", timeout = 30 })
        t:assert(s, "the client binds")
        local r = reboots()
        t:assert(#r >= 1, "it asked for 10.77.0.200 first")
        t:assert_eq(gateway.ip4_text(r[1].opt[50]), "10.77.0.200", "the operator's address")
        local d = gw:dhcp_messages(gateway.DHCP.DISCOVER)
        t:assert(#d >= 1, "after the NAK it discovered")
        t:assert(d[1].opt[50] == nil, "and the DISCOVER no longer asks for the refused address")
        t:assert(network.has_address(network.iface(s, "eth0"), "10.77.0.60"), "the server's choice is bound")
        t:assert(wait_until(function() return requested() == "10.77.0.60" end,
            { timeout = 10, interval = 0.25, desc = "RequestedAddress to follow the lease" }),
            "RequestedAddress follows the new lease")
    end)

test("silence for two INIT-REBOOT transmissions also sends the client to discovery",
    { spec = "netd *dhcp4-memory.requested-address" }, function(t)
        server.on.reboot = function() return false end
        local nic = unplug()
        gw:forget()
        nic:reconnect()
        local s = network.serve_until(gw, sut, network.bound, { iface = "eth0", timeout = 40 })
        t:assert(s, "the client binds")
        local r = reboots()
        local d = gw:dhcp_messages(gateway.DHCP.DISCOVER)
        for _, m in ipairs(r) do t:log("INIT-REBOOT REQUEST secs=" .. m.secs .. " for " .. gateway.ip4_text(m.opt[50])) end
        t:assert_eq(#r, 2, "exactly two INIT-REBOOT REQUESTs went unanswered")
        t:assert(#d >= 1, "then a DISCOVER")
        t:assert(d[1].secs >= r[2].secs, "after the second REQUEST")
        server.on.reboot = nil
    end)
