-- PKM §6.2 — bridge ports. A frame on a port enslaved to a bridge is
-- switched at L2 and never reaches that port's IP stack, so the Packet
-- layer falls back to the port's ingress seat; the copy the bridge
-- delivers up to itself is a separate traversal of the bridge device,
-- judged there. And a refusal the bridge floods is cloned once per port:
-- every clone keeps the refusal bit, and every port's seat waves it
-- through.
--
-- The bridge br0 has two ports: veth1, whose other end is a second peer
-- (peer1, 10.8.0.2), and a dummy. br0 holds 10.8.0.1.
--
-- Own VM: the policy is machine-wide state, and the bridge is a fixture
-- no other file wants.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local seat = require("helpers.ntfe_seat")

local vm = provium:vm("vntfeseatbridge", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local peer, net = ntfe.peer(vm, { name = "veth1", peer = "peer1", unaddressed = true })
assert(ntfe.link_add(vm, "br0", "bridge"))
assert(ntfe.link_add(vm, "dum0", "dummy"))
assert(ntfe.link_set_master(vm, "veth1", "br0"))
assert(ntfe.link_set_master(vm, "dum0", "br0"))
assert(ntfe.if_up(vm, "dum0"))
assert(ntfe.if_addr(vm, "br0", "10.8.0.1", 24))
assert(ntfe.if_addr(peer, "peer1", "10.8.0.2", 24))
local BR = assert(ntfe.if_index(vm, "br0"))
local BR_MAC = assert(ntfe.if_hwaddr(vm, "br0"))
local DUM = assert(ntfe.if_index(vm, "dum0"))
local PORT = net.ifindex
local E = ntfe.engine(vm, seat.policy())
local wire = assert(ntfe.packet_socket(peer, "peer1"))

local S, L = ntfe.SEAT, ntfe.LAYER

local function use(extra)
    local s = E:replace(seat.policy(extra))
    assert(s.last_ingest_error == 0, "the test policy ingests: " .. s.last_ingest_error)
end

-- The bridge forwards only once its ports are forwarding.
local function bridge_ready()
    local l = assert(ntfe.tcp_listen(vm, "10.8.0.1", 7500))
    for _ = 1, 40 do
        local fd = ntfe.tcp_connect(peer, "10.8.0.1", 7500, 100)
        if fd then sys.close(peer, fd); sys.close(vm, l); return true end
    end
    sys.close(vm, l)
    return false
end
assert(bridge_ready(), "br0 forwards")

test("an IP frame on a bridge port is judged at the port's ingress by RawPacket and then Packet",
    { spec = "PKM *ntfe-seat.ingress-non-ip-or-bridge-port-rawpacket-then-packet "
          .. "PKM *ntfe-seat.packet-falls-back-to-ingress-iff-unreachable" }, function(t)
        local u = assert(ntfe.udp_bind(vm, "10.8.0.1", 7501))
        local frame = ntfe.eth(BR_MAC, net.peer_mac, ntfe.ETH_P.IP)
            .. ntfe.ipv4("10.8.0.2", "10.8.0.1", 17, 9)
            .. ntfe.udp("10.8.0.2", "10.8.0.1", 5501, 7501, "x")
        local got
        local delta, events = E:during(function()
            ntfe.send_frame(peer, wire, frame)
            got = ntfe.recv(vm, u, 300)
        end)
        sys.close(vm, u)
        t:assert(got, "the datagram reaches its socket")
        local mine = ntfe.matching(events, { dst_port = 7501 })
        t:assert_eq(seat.trail(mine, function(e) return e.ifindex == PORT end),
            "ingress:RawPacket ingress:Packet",
            "at the port: RawPacket, then the Packet layer's fallback: " .. ntfe.describe(mine))
        t:assert(delta.fallback_judged >= 1, "counted as a fallback")
    end)

test("whether a frame reaches the IP seats is decided by its device's disposition: a bridge port's never do, the bridge's own copy does",
    { spec = "PKM *ntfe-seat.reaches-ip-seat-from-ethertype-and-bridge-port" }, function(t)
        local u = assert(ntfe.udp_bind(vm, "10.8.0.1", 7502))
        local frame = ntfe.eth(BR_MAC, net.peer_mac, ntfe.ETH_P.IP)
            .. ntfe.ipv4("10.8.0.2", "10.8.0.1", 17, 9)
            .. ntfe.udp("10.8.0.2", "10.8.0.1", 5502, 7502, "x")
        local _, events = E:during(function()
            ntfe.send_frame(peer, wire, frame)
            ntfe.recv(vm, u, 300)
        end)
        sys.close(vm, u)
        local mine = ntfe.matching(events, { dst_port = 7502 })
        t:assert_eq(#ntfe.matching(mine, { ifindex = PORT, seat = S.INGRESS, layer = L.PACKET }), 1,
            "the IPv4 frame on the port was judged by Packet there: it would never reach an IP seat")
        t:assert_eq(seat.trail(mine, function(e) return e.ifindex == BR end),
            "ingress:RawPacket local_in:Packet local_in:Flow",
            "the copy delivered to the bridge is its own traversal, deferred at br0's ingress and judged at LOCAL_IN")
    end)

test("a refusal the bridge floods is cloned per port, and every clone keeps the refusal bit",
    { spec = "PKM *ntfe-seat.refusal-bit-survives-clone-and-copy" }, function(t)
        -- Unicast first: with peer1's MAC learned, the RST goes to one
        -- port. Then with learning off and the table flushed, the bridge
        -- floods it: br_flood clones the frame for all but the last port.
        -- If a clone lost the bit, that port's egress seat would judge it
        -- — with an event, and against a rule that drops every RST.
        use({
            Flow = { refused = { ["DstPort.Equal"] = 7503, Actions = { "REJECT" } } },
            RawPacket = { rst = { ["TcpFlags.Has"] = "RST", ["Direction.Equal"] = "out",
                                  Actions = { "DROP" } } },
        })
        local l = assert(ntfe.tcp_listen(vm, "10.8.0.1", 7503))
        local unicast = E:during(function()
            local _, why = ntfe.tcp_connect(peer, "10.8.0.1", 7503, 300)
            t:assert_eq(why, sys.E.CONNREFUSED, "the refusal reaches the peer through one port")
        end)
        t:assert_eq(unicast.refusals_bypassed, 3, "LOCAL_OUT, br0's egress and the one port's egress")
        for _, port in ipairs({ "veth1", "dum0" }) do
            assert(seat.write_file(vm, "/sys/class/net/" .. port .. "/brport/learning", 0))
        end
        assert(seat.write_file(vm, "/sys/class/net/br0/bridge/flush", 1))
        local flood, events = E:during(function()
            local _, why = ntfe.tcp_connect(peer, "10.8.0.1", 7503, 300)
            t:assert_eq(why, sys.E.CONNREFUSED, "the flooded refusal reaches the peer")
        end)
        for _, port in ipairs({ "veth1", "dum0" }) do
            seat.write_file(vm, "/sys/class/net/" .. port .. "/brport/learning", 1)
        end
        t:assert_eq(flood.refusals_emitted, 1, "one refusal")
        t:assert_eq(flood.refusals_bypassed, 4, "and a bypass at every port it was flooded to, the clone's included")
        local judged = {}
        for _, e in ipairs(events) do
            if e.seat == S.EGRESS and (e.ifindex == DUM or e.ifindex == PORT or e.ifindex == BR)
                and e.protocol == ntfe.IPPROTO.TCP then
                judged[#judged + 1] = e
            end
        end
        t:assert_eq(#judged, 0, "no egress seat judged any copy of it: " .. ntfe.describe(judged))
        sys.close(vm, l)
        use()
    end)
