-- PKM §6.3 — the snapshot as a whole: one immutable fact set per seat,
-- what a rule's own writes can and cannot see, how presence is carried
-- apart from value, and the absent-fact law that turns every missing
-- fact into a false condition.
--
-- A fact is seen by a probe rule that conditions on it, standing above a
-- PASS-everything baseline (helpers/ntfe_snapshot): the verdict event of
-- a traversal is attributed to the probe exactly when the probe's
-- condition held. Frames are hand-built on the peer, so a fact's value —
-- or its absence — is chosen, not hoped for.
--
-- Own VM: the policy is machine-wide state, and the counter and tag
-- stores these tests write must start empty.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local H = require("helpers.ntfe_snapshot")

local vm = provium:vm("vntfesnval", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local peer, net = ntfe.peer(vm)
local E = ntfe.engine(vm, H.policy())
local wire = assert(ntfe.packet_socket(peer, net.peer))

local S, L = ntfe.SEAT, ntfe.LAYER

local function publish(t, probes)
    local s = E:replace(H.policy(probes))
    t:assert_eq(s.last_ingest_error, 0, "the probe policy is accepted")
end

-- ---- one snapshot per seat ----

test("each seat builds one snapshot, and every layer judged there reads it",
    { spec = "PKM *ntfe-snapshot.built-once-per-seat-never-mutated" }, function(t)
        publish(t, {
            RawPacket = { arp = { ["EtherType.Equal"] = "arp", ["SrcMac.Equal"] = H.mac_text(net.peer_mac) } },
            Packet = { arp = { ["EtherType.Equal"] = "arp", ["SrcMac.Equal"] = H.mac_text(net.peer_mac) } },
        })
        -- An ARP frame never reaches an IP seat, so the ingress seat judges
        -- it in both RawPacket and (as the fallback) Packet.
        local _, events = H.inject(E, peer, wire, H.arp_frame(net), {
            { S.INGRESS, L.RAWPACKET, { ether_type = ntfe.ETH_P.ARP } },
            { S.INGRESS, L.PACKET, { ether_type = ntfe.ETH_P.ARP } },
        })
        local raw = H.at(events, S.INGRESS, L.RAWPACKET, { ether_type = ntfe.ETH_P.ARP })[1]
        local pkt = H.at(events, S.INGRESS, L.PACKET, { ether_type = ntfe.ETH_P.ARP })[1]
        t:assert(raw and pkt, "both layers judged the frame at ingress: " .. ntfe.describe(events))
        t:assert_eq(raw.attributed, "arp", "RawPacket saw the frame's facts")
        t:assert_eq(pkt.attributed, "arp", "and Packet saw the same ones")
        for _, field in ipairs({ "length", "ifindex", "direction", "flow_state", "addr_family", "ether_type" }) do
            t:assert_eq(pkt[field], raw[field], "the two judgments agree on " .. field)
        end
    end)

test("nothing a rule writes is visible to the evaluation that wrote it, only to the next",
    { spec = "PKM *ntfe-snapshot.writes-invisible-to-same-evaluation" }, function(t)
        publish(t, {
            Packet = {
                writer = { ["DstPort.Equal"] = 7101, Actions = { "TAG(stamped, Set)", "PASS" }, Priority = 5 },
                reader = { ["DstPort.Equal"] = 7101, ["Tag.stamped.Equal"] = 1, Priority = 20 },
            },
        })
        local rx = assert(ntfe.udp_bind(vm, net.addr, 7101))
        local tx = assert(ntfe.udp_connect(peer, net.addr, 7101))
        local function one(data)
            local _, events = H.watch(E, function()
                ntfe.send(peer, tx, data)
                t:assert_eq(ntfe.recv(vm, rx, 500), data, "the datagram is delivered")
            end, { { S.LOCAL_IN, L.PACKET, { dst_port = 7101 } } })
            return H.attribution(events, S.LOCAL_IN, L.PACKET, { dst_port = 7101 })
        end
        local first, d1 = one("first")
        t:assert_eq(first, "writer",
            "the first datagram's evaluation does not see the tag it is writing: " .. d1)
        local second, d2 = one("second")
        t:assert_eq(second, "reader", "the next datagram of the flow does: " .. d2)
        sys.close(peer, tx); sys.close(vm, rx)
    end)

-- ---- presence apart from value ----

test("a fact whose value is zero is present; presence is carried apart from the value",
    { spec = "PKM *ntfe-snapshot.has-bitmask-carries-presence" }, function(t)
        -- Distinct priorities: if an absent fact read as its zero value,
        -- the higher probe would claim a frame that lacks it.
        publish(t, {
            RawPacket = {
                sport0 = { ["SrcPort.Equal"] = 0, Priority = 30 },
                ttl0 = { ["Ttl.Equal"] = 0, Priority = 20 },
                vid0 = { ["Vlan.Equal"] = 0, Priority = 15 },
            },
        })
        local cases = {
            { "a UDP datagram from port 0", H.udp_frame(net, 0, 7102), "sport0", ntfe.IPPROTO.UDP },
            { "an ICMP message with TTL 0",
              H.to_vm(net, ntfe.ETH_P.IP, ntfe.ipv4(net.peer_addr, net.addr, 1, 8, { ttl = 0 })
                  .. ntfe.icmp(8, 0, 0x01020001)), "ttl0", ntfe.IPPROTO.ICMP },
            { "an ICMP message tagged VLAN 0",
              H.tagged_to_vm(net, 0, ntfe.ETH_P.IP, ntfe.ipv4(net.peer_addr, net.addr, 1, 8)
                  .. ntfe.icmp(8, 0, 0x01020002)), "vid0", ntfe.IPPROTO.ICMP },
            { "an untagged ICMP message with TTL 64",
              H.to_vm(net, ntfe.ETH_P.IP, ntfe.ipv4(net.peer_addr, net.addr, 1, 8)
                  .. ntfe.icmp(8, 0, 0x01020003)), "all", ntfe.IPPROTO.ICMP },
        }
        for _, c in ipairs(cases) do
            local want = { protocol = c[4], src = net.peer_addr }
            local _, events = H.inject(E, peer, wire, c[2], { { S.INGRESS, L.RAWPACKET, want } })
            local got, d = H.attribution(events, S.INGRESS, L.RAWPACKET, want)
            t:assert_eq(got, c[3], c[1] .. " is judged with exactly the facts it has: " .. d)
        end
    end)

test("an address is valid by its family: a frame with no IP header has none, 0.0.0.0 is one",
    { spec = "PKM *ntfe-snapshot.addr-family-is-address-validity" }, function(t)
        publish(t, {
            RawPacket = {
                anyaddr = { ["SrcAddr.Equal"] = "0.0.0.0/0", Priority = 20 },
                noaddr = { ["SrcAddr.Present"] = 0, Priority = 10 },
            },
        })
        local _, events = H.inject(E, peer, wire, H.arp_frame(net),
            { { S.INGRESS, L.RAWPACKET, { ether_type = ntfe.ETH_P.ARP } } })
        local arp = H.at(events, S.INGRESS, L.RAWPACKET, { ether_type = ntfe.ETH_P.ARP })[1]
        t:assert(arp, "the ARP frame was judged: " .. ntfe.describe(events))
        t:assert_eq(arp.addr_family, 0, "with no address family")
        t:assert_eq(arp.attributed, "noaddr", "and so with no source address at all")

        local udp = ntfe.udp("0.0.0.0", net.addr, 68, 7103, "")
        local frame = H.to_vm(net, ntfe.ETH_P.IP, ntfe.ipv4("0.0.0.0", net.addr, 17, #udp) .. udp)
        local _, ev2 = H.inject(E, peer, wire, frame, { { S.INGRESS, L.RAWPACKET, { dst_port = 7103 } } })
        local got, d = H.attribution(ev2, S.INGRESS, L.RAWPACKET, { dst_port = 7103 })
        t:assert_eq(got, "anyaddr", "while an all-zero IPv4 source is an address like any other: " .. d)
    end)

test("the protocol is valid exactly when an address family is",
    { spec = "PKM *ntfe-snapshot.protocol-valid-iff-family" }, function(t)
        publish(t, {
            RawPacket = {
                proto0 = { ["Protocol.Equal"] = 0, Priority = 20 },
                noproto = { ["Protocol.Present"] = 0, Priority = 10 },
            },
        })
        local _, events = H.inject(E, peer, wire, H.arp_frame(net),
            { { S.INGRESS, L.RAWPACKET, { ether_type = ntfe.ETH_P.ARP } } })
        local got, d = H.attribution(events, S.INGRESS, L.RAWPACKET, { ether_type = ntfe.ETH_P.ARP })
        t:assert_eq(got, "noproto", "a frame with no IP header has no protocol: " .. d)

        -- IP protocol 0 (hop-by-hop's number) in an IPv4 header: present, zero.
        local frame = H.to_vm(net, ntfe.ETH_P.IP, ntfe.ipv4(net.peer_addr, net.addr, 0, 8) .. string.rep("\0", 8))
        local want = { ether_type = ntfe.ETH_P.IP, protocol = 0, addr_family = 4 }
        local _, ev2 = H.inject(E, peer, wire, frame, { { S.INGRESS, L.RAWPACKET, want } })
        local got2, d2 = H.attribution(ev2, S.INGRESS, L.RAWPACKET, want)
        t:assert_eq(got2, "proto0", "an IPv4 packet carrying protocol 0 has the protocol 0: " .. d2)
    end)

test("the flow state's absence is its own value, apart from `untracked`",
    { spec = "PKM *ntfe-snapshot.flow-state-has-own-absent-value" }, function(t)
        publish(t, {
            Packet = {
                untracked = { ["FlowState.Equal"] = "untracked", Priority = 20 },
                nostate = { ["FlowState.Present"] = 0, Priority = 10 },
            },
        })
        -- The ARP frame's Packet judgment is at ingress, before conntrack.
        local _, events = H.inject(E, peer, wire, H.arp_frame(net),
            { { S.INGRESS, L.PACKET, { ether_type = ntfe.ETH_P.ARP } } })
        local arp = H.at(events, S.INGRESS, L.PACKET, { ether_type = ntfe.ETH_P.ARP })[1]
        t:assert(arp, "the ARP frame was judged by Packet at ingress: " .. ntfe.describe(events))
        t:assert_eq(arp.flow_state, ntfe.FLOW_STATE.ABSENT, "with the flow state ABSENT")
        t:assert_eq(arp.attributed, "nostate", "which no condition over the flow state can see")

        -- An unsolicited echo reply is one conntrack refuses to track.
        local frame = H.icmp_frame(net, 0, 0, 0x7e570001, "orphan")
        local want = { protocol = ntfe.IPPROTO.ICMP, src = net.peer_addr }
        local _, ev2 = H.inject(E, peer, wire, frame, { { S.LOCAL_IN, L.PACKET, want } })
        local reply = H.at(ev2, S.LOCAL_IN, L.PACKET, want)[1]
        t:assert(reply, "the echo reply reached LOCAL_IN: " .. ntfe.describe(ev2))
        t:assert_eq(reply.flow_state, ntfe.FLOW_STATE.UNTRACKED, "reading `untracked`")
        t:assert_eq(reply.attributed, "untracked", "a present value a condition matches")
    end)

test("`Related` is valid whenever there is a flow, so every judged flow has it",
    { spec = "PKM *ntfe-snapshot.flow-related-valid-iff-flow" }, function(t)
        publish(t, { Flow = { related = { ["Related.Present"] = 1 } } })
        local l = assert(ntfe.tcp_listen(vm, net.addr, 7104))
        local rx = assert(ntfe.udp_bind(vm, net.addr, 7105))
        local _, events = H.watch(E, function()
            local c = ntfe.tcp_connect(peer, net.addr, 7104)
            t:assert(c, "a TCP flow is made")
            if c then sys.close(peer, c) end
            local u = assert(ntfe.udp_connect(peer, net.addr, 7105))
            ntfe.send(peer, u, "x")
            sys.close(peer, u)
        end, {
            { S.LOCAL_IN, L.FLOW, { dst_port = 7104 } },
            { S.LOCAL_IN, L.FLOW, { dst_port = 7105 } },
        })
        sys.close(vm, l); sys.close(vm, rx)
        for _, port in ipairs({ 7104, 7105 }) do
            local got, d = H.attribution(events, S.LOCAL_IN, L.FLOW, { dst_port = port })
            t:assert_eq(got, "related", "the flow to " .. port .. " carries `Related`: " .. d)
        end
    end)

-- ---- the absent-fact law ----

test("a fact the packet lacks lifts to nothing on the core's side",
    { spec = "PKM *ntfe-snapshot.clear-bit-lifts-to-none" }, function(t)
        publish(t, {
            RawPacket = {
                noports = { ["DstPort.Present"] = 0, Priority = 20 },
                noicmp = { ["IcmpType.Present"] = 0, Priority = 10 },
            },
        })
        local icmp = H.icmp_frame(net, 8, 0, 0x01030001)
        local want = { protocol = ntfe.IPPROTO.ICMP, src = net.peer_addr }
        local _, events = H.inject(E, peer, wire, icmp, { { S.INGRESS, L.RAWPACKET, want } })
        local got, d = H.attribution(events, S.INGRESS, L.RAWPACKET, want)
        t:assert_eq(got, "noports", "an ICMP message has no ports: " .. d)

        local _, ev2 = H.inject(E, peer, wire, H.udp_frame(net, 5000, 7106),
            { { S.INGRESS, L.RAWPACKET, { dst_port = 7106 } } })
        local got2, d2 = H.attribution(ev2, S.INGRESS, L.RAWPACKET, { dst_port = 7106 })
        t:assert_eq(got2, "noicmp", "and a UDP datagram has no ICMP type: " .. d2)
    end)

test("every condition over an absent fact is false, the negative-sounding ones too",
    { spec = "PKM *ntfe-snapshot.condition-over-none-is-false" }, function(t)
        publish(t, {
            RawPacket = {
                ["no-syn"] = { ["TcpFlags.Hasnt"] = "SYN", Priority = 50 },
                ["port-below"] = { ["DstPort.LessThan"] = 65536, Priority = 40 },
                ["vlan-below"] = { ["Vlan.LessThan"] = 4096, Priority = 30 },
                ["icmp-below"] = { ["IcmpType.LessThan"] = 256, Priority = 20 },
            },
        })
        -- A UDP datagram has no TCP flags, no VLAN, no ICMP type: only
        -- `port-below` can hold.
        local _, events = H.inject(E, peer, wire, H.udp_frame(net, 5000, 7107),
            { { S.INGRESS, L.RAWPACKET, { dst_port = 7107 } } })
        local got, d = H.attribution(events, S.INGRESS, L.RAWPACKET, { dst_port = 7107 })
        t:assert_eq(got, "port-below",
            "`Hasnt` and `LessThan` are false over facts the datagram lacks: " .. d)

        -- An untagged ICMP message has no flags, no ports and no VLAN.
        local want = { protocol = ntfe.IPPROTO.ICMP, src = net.peer_addr }
        local _, ev2 = H.inject(E, peer, wire, H.icmp_frame(net, 8, 0, 0x01040001), {
            { S.INGRESS, L.RAWPACKET, want } })
        local got2, d2 = H.attribution(ev2, S.INGRESS, L.RAWPACKET, want)
        t:assert_eq(got2, "icmp-below", "the same for the ICMP message's absences: " .. d2)

        -- The control: over a TCP segment that has the flags, `Hasnt` holds.
        local _, ev3 = H.inject(E, peer, wire, H.tcp_frame(net, 5000, 7108, ntfe.TCP.ACK), {
            { S.INGRESS, L.RAWPACKET, { dst_port = 7108 } } })
        local got3, d3 = H.attribution(ev3, S.INGRESS, L.RAWPACKET, { dst_port = 7108 })
        t:assert_eq(got3, "no-syn", "while over a present fact the operator answers: " .. d3)
    end)

-- ---- the machinery facts ----

test("the bridge gives a Packet or Flow forest the tags the flow carries and the counter views the store holds",
    { spec = "PKM *ntfe-snapshot.bridge-fills-tags-and-counter-views" }, function(t)
        publish(t, {
            Packet = {
                stamp = { ["DstPort.Equal"] = 7109, Actions = { "TAG(marked, Set, 7)", "COUNT(arrivals)", "PASS" }, Priority = 5 },
                counted = { ["DstPort.Equal"] = 7109, ["Counter.arrivals.GreaterThan"] = 0, Priority = 20 },
            },
            Flow = { tagged = { ["Tag.marked.Equal"] = 7 } },
        })
        local rx = assert(ntfe.udp_bind(vm, net.addr, 7109))
        local tx = assert(ntfe.udp_connect(peer, net.addr, 7109))
        local _, events = H.watch(E, function()
            ntfe.send(peer, tx, "one")
            t:assert_eq(ntfe.recv(vm, rx, 500), "one", "the first datagram is delivered")
        end, { { S.LOCAL_IN, L.FLOW, { dst_port = 7109 } } })
        -- At LOCAL_IN the Flow forest judges after Packet's effects landed.
        local flow, d = H.attribution(events, S.LOCAL_IN, L.FLOW, { dst_port = 7109 })
        t:assert_eq(flow, "tagged", "the Flow forest reads the tag the flow now carries: " .. d)
        local _, ev2 = H.watch(E, function()
            ntfe.send(peer, tx, "two")
            t:assert_eq(ntfe.recv(vm, rx, 500), "two", "the second datagram is delivered")
        end, { { S.LOCAL_IN, L.PACKET, { dst_port = 7109 } } })
        local pkt, d2 = H.attribution(ev2, S.LOCAL_IN, L.PACKET, { dst_port = 7109 })
        t:assert_eq(pkt, "counted", "and the Packet forest reads the counter view: " .. d2)
        sys.close(peer, tx); sys.close(vm, rx)
    end)

test("the machinery facts are resolved before evaluation, against the forest evaluated",
    { spec = "PKM *ntfe-snapshot.machinery-facts-resolved-before-evaluation" }, function(t)
        publish(t, {
            Packet = {
                count = { ["DstPort.Equal"] = 7110, Actions = { "COUNT(landings)", "PASS" }, Priority = 5 },
                seen = { ["DstPort.Equal"] = 7110, ["Counter.landings.Present"] = 1, Priority = 20 },
            },
        })
        local rx = assert(ntfe.udp_bind(vm, net.addr, 7110))
        local tx = assert(ntfe.udp_connect(peer, net.addr, 7110))
        local got = {}
        for i = 1, 2 do
            local _, events = H.watch(E, function()
                ntfe.send(peer, tx, "n" .. i)
                ntfe.recv(vm, rx, 500)
            end, { { S.LOCAL_IN, L.PACKET, { dst_port = 7110 } } })
            got[i] = H.attribution(events, S.LOCAL_IN, L.PACKET, { dst_port = 7110 })
        end
        t:assert_eq(got[1], "count",
            "the first datagram's view was read before its own COUNT made the cell")
        t:assert_eq(got[2], "seen", "and the second reads the cell the first made")
        sys.close(peer, tx); sys.close(vm, rx)
    end)
