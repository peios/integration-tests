-- PKM §6.3 — the frame facts: the ethertype as the stack holds it, the
-- VLAN as a fact of the frame at the device seats and of the device at
-- the IP seats, and the MAC pair — present on an Ethernet device with a
-- link header, the source alone (our own) on a locally generated packet
-- that has none yet, and nothing on the loopback.
--
-- Own VM: the policy is machine-wide state, and the VLAN devices made
-- here change the VM's interfaces.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local H = require("helpers.ntfe_snapshot")

local vm = provium:vm("vntfesnframe", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local peer, net = ntfe.peer(vm)
local E = ntfe.engine(vm, H.policy())
local wire = assert(ntfe.packet_socket(peer, net.peer))

-- VLAN 5 over the pair, on both machines.
assert(ntfe.link_add(vm, "veth0.5", "vlan", { link = net.ifindex, id = 5 }))
assert(ntfe.if_addr(vm, "veth0.5", "10.9.5.1", 24))
assert(ntfe.link_add(peer, "peer0.5", "vlan", { link = assert(ntfe.if_index(peer, net.peer)), id = 5 }))
assert(ntfe.if_addr(peer, "peer0.5", "10.9.5.2", 24))
local VLAN_INDEX = assert(ntfe.if_index(vm, "veth0.5"))

local S, L = ntfe.SEAT, ntfe.LAYER
local VM_MAC, PEER_MAC = H.mac_text(net.mac), H.mac_text(net.peer_mac)

local function publish(t, probes)
    local s = E:replace(H.policy(probes))
    t:assert_eq(s.last_ingest_error, 0, "the probe policy is accepted")
end

-- ---- the ethertype ----

test("the ethertype is the stack's protocol for the frame, not the first type field on the wire",
    { spec = "PKM *ntfe-snapshot.ethertype-from-skb-protocol" }, function(t)
        publish(t, {
            RawPacket = {
                arp = { ["EtherType.Equal"] = "arp" },
                ipv4 = { ["EtherType.Equal"] = "ipv4" },
                local_exp = { ["EtherType.Equal"] = 0x88B5 },
                dot1q = { ["EtherType.Equal"] = 0x8100, Priority = 20 },
            },
        })
        local _, events = H.inject(E, peer, wire, H.arp_frame(net),
            { { S.INGRESS, L.RAWPACKET, { ether_type = ntfe.ETH_P.ARP } } })
        local got, d = H.attribution(events, S.INGRESS, L.RAWPACKET, { ether_type = ntfe.ETH_P.ARP })
        t:assert_eq(got, "arp", "an ARP frame reads arp: " .. d)

        local exp = H.to_vm(net, 0x88B5, string.rep("\xAA", 46))
        local _, ev2 = H.inject(E, peer, wire, exp, { { S.INGRESS, L.RAWPACKET, { ether_type = 0x88B5 } } })
        local got2, d2 = H.attribution(ev2, S.INGRESS, L.RAWPACKET, { ether_type = 0x88B5 })
        t:assert_eq(got2, "local_exp", "an ethertype NTFE has no name for reads as its number: " .. d2)

        -- A tagged frame's first type field is 0x8100; the stack has moved
        -- the tag aside before the seat, and its protocol is what the tag
        -- carried.
        local udp = ntfe.udp(net.peer_addr, net.addr, 5000, 7301, "")
        local tagged = H.tagged_to_vm(net, 7, ntfe.ETH_P.IP,
            ntfe.ipv4(net.peer_addr, net.addr, 17, #udp) .. udp)
        local _, ev3 = H.inject(E, peer, wire, tagged, { { S.INGRESS, L.RAWPACKET, { dst_port = 7301 } } })
        local e = H.at(ev3, S.INGRESS, L.RAWPACKET, { dst_port = 7301 })[1]
        t:assert(e, "the tagged frame was judged: " .. ntfe.describe(ev3))
        t:assert_eq(e.ether_type, ntfe.ETH_P.IP, "with the IPv4 ethertype")
        t:assert_eq(e.attributed, "ipv4", "and the fact says IPv4, not 802.1Q")
    end)

-- ---- the VLAN ----

local VLAN_PROBES = {
    v5 = { ["Vlan.Equal"] = 5, Priority = 30 },
    v0 = { ["Vlan.Equal"] = 0, Priority = 20 },
    novlan = { ["Vlan.Present"] = 0, Priority = 10 },
}

test("inbound, the VLAN is the frame's tag at the device seat and the VLAN device's at the IP seat",
    { spec = "PKM *ntfe-snapshot.vlan-from-frame-tag-else-device" }, function(t)
        publish(t, { RawPacket = VLAN_PROBES, Packet = VLAN_PROBES })
        local udp = ntfe.udp("10.9.5.2", "10.9.5.1", 5000, 7302, "")
        local frame = H.tagged_to_vm(net, 5, ntfe.ETH_P.IP, ntfe.ipv4("10.9.5.2", "10.9.5.1", 17, #udp) .. udp)
        local _, events = H.inject(E, peer, wire, frame, {
            { S.INGRESS, L.RAWPACKET, { dst_port = 7302, ifindex = net.ifindex } },
            { S.INGRESS, L.RAWPACKET, { dst_port = 7302, ifindex = VLAN_INDEX } },
            { S.LOCAL_IN, L.PACKET, { dst_port = 7302 } },
        })
        for _, c in ipairs({
            { S.INGRESS, L.RAWPACKET, net.ifindex, "on veth0, from the tag on the frame" },
            { S.INGRESS, L.RAWPACKET, VLAN_INDEX, "on veth0.5, the tag stripped, from the device" },
        }) do
            local got, d = H.attribution(events, c[1], c[2], { dst_port = 7302, ifindex = c[3] })
            t:assert_eq(got, "v5", "the ingress seat reads VLAN 5 " .. c[4] .. ": " .. d)
        end
        local ip = H.at(events, S.LOCAL_IN, L.PACKET, { dst_port = 7302 })[1]
        t:assert(ip, "the datagram reached LOCAL_IN: " .. ntfe.describe(events))
        t:assert_eq(ip.ifindex, VLAN_INDEX, "re-parented onto the VLAN device")
        t:assert_eq(ip.attributed, "v5", "which gives the IP seat its VLAN")

        -- A priority tag (VID 0) on a port with no VLAN 0 device: the frame
        -- has a VLAN at ingress, and the IP seat, on veth0, has none.
        local udp0 = ntfe.udp(net.peer_addr, net.addr, 5000, 7303, "")
        local prio = H.tagged_to_vm(net, 0, ntfe.ETH_P.IP, ntfe.ipv4(net.peer_addr, net.addr, 17, #udp0) .. udp0, 3)
        local _, ev2 = H.inject(E, peer, wire, prio, {
            { S.INGRESS, L.RAWPACKET, { dst_port = 7303 } }, { S.LOCAL_IN, L.PACKET, { dst_port = 7303 } } })
        local g1, d1 = H.attribution(ev2, S.INGRESS, L.RAWPACKET, { dst_port = 7303 })
        t:assert_eq(g1, "v0", "the priority-tagged frame reads VLAN 0 at ingress: " .. d1)
        local g2, d2 = H.attribution(ev2, S.LOCAL_IN, L.PACKET, { dst_port = 7303 })
        t:assert_eq(g2, "novlan", "and no VLAN at the IP seat of a device that is not one: " .. d2)

        local _, ev3 = H.inject(E, peer, wire, H.udp_frame(net, 5000, 7304), {
            { S.INGRESS, L.RAWPACKET, { dst_port = 7304 } }, { S.LOCAL_IN, L.PACKET, { dst_port = 7304 } } })
        for _, seat in ipairs({ S.INGRESS, S.LOCAL_IN }) do
            local layer = seat == S.INGRESS and L.RAWPACKET or L.PACKET
            local got, d = H.attribution(ev3, seat, layer, { dst_port = 7304 })
            t:assert_eq(got, "novlan", "an untagged frame on veth0 has no VLAN at seat " .. seat .. ": " .. d)
        end
    end)

test("outbound, the VLAN is the device's until the tag is pushed, then the frame's",
    { spec = "PKM *ntfe-snapshot.vlan-from-frame-tag-else-device" }, function(t)
        publish(t, { Packet = VLAN_PROBES, RawPacket = VLAN_PROBES, Flow = VLAN_PROBES })
        local prx = assert(ntfe.udp_bind(peer, "10.9.5.2", 7305))
        local _, events = H.watch(E, function()
            local tx = assert(ntfe.udp_connect(vm, "10.9.5.2", 7305))
            ntfe.send(vm, tx, "tagged")
            t:assert_eq(ntfe.recv(peer, prx, 1000), "tagged", "the datagram crosses VLAN 5")
            sys.close(vm, tx)
        end, {
            { S.LOCAL_OUT, L.FLOW, { dst_port = 7305 } },
            { S.EGRESS, L.PACKET, { dst_port = 7305, ifindex = VLAN_INDEX } },
            { S.EGRESS, L.PACKET, { dst_port = 7305, ifindex = net.ifindex } },
        })
        sys.close(peer, prx)
        for _, c in ipairs({
            { S.LOCAL_OUT, L.FLOW, VLAN_INDEX, "the IP seat, from the VLAN device" },
            { S.EGRESS, L.PACKET, VLAN_INDEX, "egress on veth0.5, from the device" },
            { S.EGRESS, L.PACKET, net.ifindex, "egress on veth0, from the tag the VLAN device pushed" },
            { S.EGRESS, L.RAWPACKET, net.ifindex, "and RawPacket there likewise" },
        }) do
            local got, d = H.attribution(events, c[1], c[2], { dst_port = 7305, ifindex = c[3] })
            t:assert_eq(got, "v5", c[4] .. ": " .. d)
        end
    end)

-- ---- the MAC pair ----

test("on an Ethernet device with a link header, the snapshot has both MACs",
    { spec = "PKM *ntfe-snapshot.mac-pair-on-ethernet-with-mac-header" }, function(t)
        local pair = { ["SrcMac.Equal"] = PEER_MAC, ["DstMac.Equal"] = VM_MAC, Priority = 20 }
        local none = { ["SrcMac.Present"] = 0, ["DstMac.Present"] = 0 }
        publish(t, { RawPacket = { pair = pair }, Packet = { pair = pair, none = none } })
        local _, events = H.inject(E, peer, wire, H.udp_frame(net, 5000, 7306), {
            { S.INGRESS, L.RAWPACKET, { dst_port = 7306 } }, { S.LOCAL_IN, L.PACKET, { dst_port = 7306 } } })
        local g1, d1 = H.attribution(events, S.INGRESS, L.RAWPACKET, { dst_port = 7306 })
        t:assert_eq(g1, "pair", "the ingress seat reads the frame's source and destination: " .. d1)
        local g2, d2 = H.attribution(events, S.LOCAL_IN, L.PACKET, { dst_port = 7306 })
        t:assert_eq(g2, "pair", "and so does LOCAL_IN, the link header still set: " .. d2)

        -- The loopback is not an Ethernet device: no MACs at all.
        local lrx = assert(ntfe.udp_bind(vm, "127.0.0.1", 7307))
        local _, ev2 = H.watch(E, function()
            local tx = assert(ntfe.udp_connect(vm, "127.0.0.1", 7307))
            ntfe.send(vm, tx, "lo")
            sys.close(vm, tx)
        end, { { S.LOCAL_IN, L.PACKET, { dst_port = 7307 } } })
        sys.close(vm, lrx)
        local g3, d3 = H.attribution(ev2, S.LOCAL_IN, L.PACKET, { dst_port = 7307 })
        t:assert_eq(g3, "none", "a loopback packet has neither MAC: " .. d3)
    end)

test("a locally generated packet at an IP seat has our device's MAC as its source and no destination",
    { spec = "PKM *ntfe-snapshot.headerless-ip-seat-gets-device-source-mac PKM *ntfe-snapshot.headerless-ip-seat-dst-mac-absent" },
    function(t)
        publish(t, {
            Flow = {
                ours = { ["SrcMac.Equal"] = VM_MAC, Priority = 10 },
                theirs = { ["DstMac.Equal"] = PEER_MAC, Priority = 20 },
            },
            Packet = { theirs = { ["DstMac.Equal"] = PEER_MAC, ["SrcMac.Equal"] = VM_MAC } },
        })
        local prx = assert(ntfe.udp_bind(peer, net.peer_addr, 7308))
        local _, events = H.watch(E, function()
            local tx = assert(ntfe.udp_connect(vm, net.peer_addr, 7308))
            ntfe.send(vm, tx, "out")
            t:assert_eq(ntfe.recv(peer, prx, 1000), "out", "the datagram goes out")
            sys.close(vm, tx)
        end, { { S.LOCAL_OUT, L.FLOW, { dst_port = 7308 } }, { S.EGRESS, L.PACKET, { dst_port = 7308 } } })
        sys.close(peer, prx)
        local g1, d1 = H.attribution(events, S.LOCAL_OUT, L.FLOW, { dst_port = 7308 })
        t:assert_eq(g1, "ours",
            "LOCAL_OUT, before any link header, reads our own MAC as the source and no destination: " .. d1)
        local g2, d2 = H.attribution(events, S.EGRESS, L.PACKET, { dst_port = 7308 })
        t:assert_eq(g2, "theirs",
            "the destination exists only after neighbour resolution, at egress: " .. d2)
    end)
