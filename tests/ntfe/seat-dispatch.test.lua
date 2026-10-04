-- PKM §6.2 — the dispatch law: which layers each seat judges, in what
-- order, how often; the Packet layer's deferral to its proper seat and
-- its fallback at ingress; the hand-off from Packet to the flow's
-- sentence at the IP seats; a layer with no forest; and what is judged
-- when a frame is too mangled to describe — or when evaluation fails.
--
-- The witness throughout is the verdict stream: every layer judgment,
-- PASS included, emits one event naming its seat and layer, so the
-- order and number of judgments a packet got is read off the events it
-- produced. Frames the tests need exactly one of are hand-built and sent
-- from the peer, so nothing a kernel retransmits can blur a count.
--
-- Own VM: the policy is machine-wide state, and the first test needs a
-- kernel that has never ingested one.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local seat = require("helpers.ntfe_seat")

local vm = provium:vm("vntfeseatdispatch", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local peer, net = ntfe.peer(vm)
local wire = assert(ntfe.packet_socket(peer, net.peer))
local sink = assert(ntfe.udp_bind(vm, net.addr, 7200))

-- Generation 0: one datagram through a kernel that has published nothing.
local dev = assert(ntfe.open(vm))
local gen0_before = assert(ntfe.status(vm, dev))
ntfe.send_frame(peer, wire, seat.udp4_frame(net, 5000, 7200, "gen0"))
local gen0_got = ntfe.recv(vm, sink, 500)
local gen0_after = assert(ntfe.status(vm, dev))

local E = ntfe.engine(vm, seat.policy())

local PASS, DROP = ntfe.VERDICT.PASS, ntfe.VERDICT.DROP
local S, L = ntfe.SEAT, ntfe.LAYER

local function use(extra)
    local s = E:replace(seat.policy(extra))
    assert(s.last_ingest_error == 0, "the test policy ingests: " .. s.last_ingest_error)
end

local function on_port(port, action)
    return { ["DstPort.Equal"] = port, Actions = { action } }
end

local function count(events, want)
    return #ntfe.matching(events, want)
end

-- One hand-built datagram from the peer to the sink on 7200; returns
-- the events it produced and whether it arrived.
local function one_datagram(sport)
    local got
    local delta, events = E:during(function()
        ntfe.send_frame(peer, wire, seat.udp4_frame(net, sport, 7200, "one"))
        got = ntfe.recv(vm, sink, 300)
    end)
    local mine = {}
    for _, e in ipairs(events) do
        if e.src_port == sport and e.dst_port == 7200 then mine[#mine + 1] = e end
    end
    return mine, got, delta
end

-- A frame of `ethertype` the stack has no handler for: nothing but the
-- engine ever looks at it.
local FOREIGN = 0x88B5
local function foreign_frame()
    return ntfe.eth(net.mac, net.peer_mac, FOREIGN) .. string.rep("\0", 46)
end

-- ---- the layers at each seat -------------------------------------------------

test("a layer with no published forest is permissive and counted as such",
    { spec = "PKM *ntfe-seat.unpublished-layer-permissive-and-counted" }, function(t)
        -- At generation 0 that is every layer.
        t:assert_eq(gen0_before.generation, 0, "nothing was published at boot")
        t:assert(gen0_got, "a datagram at generation 0 is delivered")
        t:assert_eq(gen0_after.judged - gen0_before.judged, 0, "judged by no forest")
        t:assert(gen0_after.permissive - gen0_before.permissive >= 2,
            "and counted permissive at its ingress and LOCAL_IN judgments")
        -- Later, a layer whose key is absent from the policy has no forest.
        local s = E:replace({ Flow = seat.PASS_ALL })
        t:assert_eq(s.last_ingest_error, 0, "a policy of the Flow layer alone ingests")
        local mine, got, delta = one_datagram(5201)
        t:assert(got, "the datagram passes the layers that have no forest")
        t:assert_eq(count(mine, { layer = L.RAWPACKET }) + count(mine, { layer = L.PACKET }), 0,
            "which judged nothing: " .. ntfe.describe(mine))
        t:assert(delta.permissive >= 2, "and counted each as permissive")
        t:assert_eq(count(mine, { layer = L.FLOW }), 1, "while the Flow layer judged it")
        use()
    end)

test("RawPacket judges all traffic at the device seats, unconditionally",
    { spec = "PKM *ntfe-seat.rawpacket-at-device-seats-unconditionally" }, function(t)
        local l = assert(ntfe.tcp_listen(vm, net.addr, 7201))
        local _, events = E:during(function()
            local fd = ntfe.tcp_connect(peer, net.addr, 7201)
            if fd then sys.close(peer, fd) end
            ntfe.send_frame(peer, wire, ntfe.eth(ntfe.MAC_BROADCAST, net.peer_mac, ntfe.ETH_P.ARP)
                .. ntfe.arp_request(net.peer_mac, net.peer_addr, net.addr))
            ntfe.send_frame(peer, wire, foreign_frame())
            ntfe.frames(peer, wire, 100)
        end)
        sys.close(vm, l)
        for _, c in ipairs({
            { ntfe.ETH_P.IP, S.INGRESS, "an inbound IPv4 frame" },
            { ntfe.ETH_P.IP, S.EGRESS, "an outbound IPv4 frame" },
            { ntfe.ETH_P.ARP, S.INGRESS, "an inbound ARP request" },
            { ntfe.ETH_P.ARP, S.EGRESS, "the outbound ARP reply" },
            { FOREIGN, S.INGRESS, "a frame of an ethertype nothing handles" },
        }) do
            t:assert(count(events, { ether_type = c[1], seat = c[2], layer = L.RAWPACKET }) >= 1,
                c[3] .. " is judged by RawPacket at the " .. seat.SEAT_NAME[c[2]] .. " seat")
        end
        t:assert_eq(count(events, { layer = L.RAWPACKET, seat = S.LOCAL_IN })
            + count(events, { layer = L.RAWPACKET, seat = S.LOCAL_OUT }), 0,
            "and never at the IP seats")
    end)

test("ingress judges an IP frame on a plain port with RawPacket alone, deferring Packet",
    { spec = "PKM *ntfe-seat.ingress-ip-plain-port-rawpacket-only" }, function(t)
        local mine, got, delta = one_datagram(5202)
        t:assert(got, "the datagram is delivered")
        t:assert_eq(seat.trail(mine, function(e) return e.seat == S.INGRESS end), "ingress:RawPacket",
            "the ingress seat judged it with RawPacket only")
        t:assert(delta.deferred >= 1, "and counted the Packet layer deferred")
        t:assert_eq(count(mine, { seat = S.LOCAL_IN, layer = L.PACKET }), 1,
            "to LOCAL_IN, where it was judged")
    end)

test("ingress judges a non-IP frame with RawPacket, then Packet",
    { spec = "PKM *ntfe-seat.ingress-non-ip-or-bridge-port-rawpacket-then-packet" }, function(t)
        local delta, events = E:during(function()
            ntfe.send_frame(peer, wire, foreign_frame())
        end)
        local mine = ntfe.matching(events, { ether_type = FOREIGN })
        t:assert_eq(seat.trail(mine), "ingress:RawPacket ingress:Packet",
            "RawPacket and then the Packet layer's fallback judgment, at ingress: "
            .. ntfe.describe(mine))
        -- At least: the peer's own ARP probes are fallbacks too.
        t:assert(delta.fallback_judged >= 1, "counted as a fallback")
    end)

test("LOCAL_IN judges the Packet layer, then the flow",
    { spec = "PKM *ntfe-seat.local-in-packet-then-flow" }, function(t)
        local mine = one_datagram(5203)
        t:assert_eq(seat.trail(mine, function(e) return e.seat == S.LOCAL_IN end),
            "local_in:Packet local_in:Flow", "Packet first, then Flow: " .. ntfe.describe(mine))
    end)

test("LOCAL_OUT judges only the flow",
    { spec = "PKM *ntfe-seat.local-out-flow-only" }, function(t)
        local pu = assert(ntfe.udp_bind(peer, net.peer_addr, 7202))
        local _, events = E:during(function()
            local u = assert(ntfe.udp_connect(vm, net.peer_addr, 7202))
            ntfe.send(vm, u, "out")
            t:assert(ntfe.recv(peer, pu, 300), "the datagram reaches the peer")
            sys.close(vm, u)
        end)
        sys.close(peer, pu)
        t:assert_eq(seat.trail(events, function(e) return e.seat == S.LOCAL_OUT end), "local_out:Flow",
            "LOCAL_OUT judged it with the Flow layer and nothing else")
    end)

test("egress judges the Packet layer, then RawPacket",
    { spec = "PKM *ntfe-seat.egress-packet-then-rawpacket" }, function(t)
        local pu = assert(ntfe.udp_bind(peer, net.peer_addr, 7203))
        local _, events = E:during(function()
            local u = assert(ntfe.udp_connect(vm, net.peer_addr, 7203))
            ntfe.send(vm, u, "out")
            ntfe.recv(peer, pu, 300)
            sys.close(vm, u)
        end)
        sys.close(peer, pu)
        t:assert_eq(seat.trail(events, function(e) return e.seat == S.EGRESS and e.dst_port == 7203 end),
            "egress:Packet egress:RawPacket", "Packet first, then RawPacket")
    end)

test("traversal order is wire order: RawPacket first in and last out, Flow last in and first out",
    { spec = "PKM *ntfe-seat.traversal-order-is-wire-order" }, function(t)
        local inbound = one_datagram(5204)
        t:assert_eq(seat.trail(inbound), "ingress:RawPacket local_in:Packet local_in:Flow",
            "inbound: wire, then packet, then flow")
        local pu = assert(ntfe.udp_bind(peer, net.peer_addr, 7204))
        local _, events = E:during(function()
            local u = assert(ntfe.udp_connect(vm, net.peer_addr, 7204))
            ntfe.send(vm, u, "out")
            ntfe.recv(peer, pu, 300)
            sys.close(vm, u)
        end)
        sys.close(peer, pu)
        t:assert_eq(seat.trail(events, function(e) return e.dst_port == 7204 end),
            "local_out:Flow egress:Packet egress:RawPacket", "outbound: flow, then packet, then wire")
    end)

test("each per-packet layer is evaluated once per traversal",
    { spec = "PKM *ntfe-seat.per-packet-layer-once-per-traversal" }, function(t)
        local mine = one_datagram(5205)
        t:assert_eq(count(mine, { layer = L.RAWPACKET }), 1, "one RawPacket judgment for one datagram")
        t:assert_eq(count(mine, { layer = L.PACKET }), 1, "one Packet judgment")
        local _, events = E:during(function()
            ntfe.send_frame(peer, wire, foreign_frame())
        end)
        local foreign = ntfe.matching(events, { ether_type = FOREIGN })
        t:assert_eq(count(foreign, { layer = L.RAWPACKET }), 1, "one RawPacket judgment for one non-IP frame")
        t:assert_eq(count(foreign, { layer = L.PACKET }), 1, "and one Packet judgment")
    end)

test("the Packet layer judges every traversal exactly once, at its proper seat",
    { spec = "PKM *ntfe-seat.packet-judged-exactly-once-at-proper-seat" }, function(t)
        -- A whole TCP conversation: every inbound packet is judged by the
        -- Packet layer at LOCAL_IN and every outbound one at egress, once
        -- each — as many Packet judgments as packets crossed the wire.
        local l = assert(ntfe.tcp_listen(vm, net.addr, 7205))
        local _, events = E:during(function()
            local fd = assert(ntfe.tcp_connect(peer, net.addr, 7205))
            local a = assert(ntfe.tcp_accept(vm, l))
            ntfe.send(peer, fd, "ping")
            ntfe.recv(vm, a, 300)
            ntfe.send(vm, a, "pong")
            ntfe.recv(peer, fd, 300)
            sys.close(peer, fd)
            sys.close(vm, a)
        end)
        sys.close(vm, l)
        local conv = {}
        for _, e in ipairs(events) do
            if e.src_port == 7205 or e.dst_port == 7205 then conv[#conv + 1] = e end
        end
        local wire_in = count(conv, { seat = S.INGRESS, layer = L.RAWPACKET })
        local wire_out = count(conv, { seat = S.EGRESS, layer = L.RAWPACKET })
        t:assert(wire_in >= 4 and wire_out >= 3, "a conversation crossed the wire both ways")
        t:assert_eq(count(conv, { seat = S.LOCAL_IN, layer = L.PACKET }), wire_in,
            "each inbound packet judged once by Packet, at LOCAL_IN")
        t:assert_eq(count(conv, { seat = S.EGRESS, layer = L.PACKET }), wire_out,
            "each outbound packet judged once by Packet, at egress")
        t:assert_eq(count(conv, { seat = S.INGRESS, layer = L.PACKET })
            + count(conv, { seat = S.LOCAL_OUT, layer = L.PACKET }), 0,
            "and never at the seats that are not its own")
    end)

test("the Packet layer falls back to ingress if and only if the traversal never reaches its proper seat",
    { spec = "PKM *ntfe-seat.packet-falls-back-to-ingress-iff-unreachable" }, function(t)
        local foreign_delta, foreign_ev = E:during(function()
            ntfe.send_frame(peer, wire, foreign_frame())
        end)
        t:assert_eq(count(ntfe.matching(foreign_ev, { ether_type = FOREIGN }),
            { seat = S.INGRESS, layer = L.PACKET }), 1, "a frame no IP hook will see falls back")
        t:assert(foreign_delta.fallback_judged >= 1, "and is counted a fallback")
        local mine = one_datagram(5206)
        t:assert_eq(count(mine, { seat = S.INGRESS, layer = L.PACKET }), 0,
            "an IP frame that will reach LOCAL_IN does not")
        t:assert_eq(count(mine, { seat = S.LOCAL_IN, layer = L.PACKET }), 1, "it is judged there")
    end)

test("whether a frame reaches the IP seats is decided by its ethertype",
    { spec = "PKM *ntfe-seat.reaches-ip-seat-from-ethertype-and-bridge-port" }, function(t)
        -- The bridge-port half of this law is in seat-bridge.test.lua.
        local v6_dst = "\x33\x33\x00\x00\x00\x01"
        local v6 = ntfe.eth(v6_dst, net.peer_mac, ntfe.ETH_P.IPV6)
            .. string.pack(">I4I2I1I1", 0x60000000, 8, 17, 1)
            .. ntfe.ip6("fe80::99") .. ntfe.ip6("ff02::1")
            .. string.pack(">I2I2I2I2", 5207, 7207, 8, 0)
        for _, c in ipairs({
            { ntfe.ETH_P.IP, seat.udp4_frame(net, 5207, 7200, "v4"), false, "an IPv4 frame" },
            { ntfe.ETH_P.IPV6, v6, false, "an IPv6 frame" },
            { ntfe.ETH_P.ARP, ntfe.eth(ntfe.MAC_BROADCAST, net.peer_mac, ntfe.ETH_P.ARP)
                .. ntfe.arp_request(net.peer_mac, net.peer_addr, net.addr), true, "an ARP frame" },
            { FOREIGN, foreign_frame(), true, "a frame of another ethertype" },
        }) do
            local _, events = E:during(function()
                ntfe.send_frame(peer, wire, c[2])
                ntfe.frames(peer, wire, 50)
            end)
            local at_ingress = ntfe.matching(events, { ether_type = c[1], seat = S.INGRESS })
            local fell_back = count(at_ingress, { layer = L.PACKET }) >= 1
            t:assert_eq(fell_back, c[3], c[4] .. (c[3] and " is judged by Packet at ingress"
                or " is deferred to the IP seats") .. ": " .. ntfe.describe(at_ingress))
        end
    end)

test("the first verdict that is not PASS ends the traversal",
    { spec = "PKM *ntfe-seat.first-non-pass-ends-traversal" }, function(t)
        use({
            RawPacket = { wire = { ["SrcPort.Equal"] = 5210, Actions = { "DROP" } },
                          ["wire-out"] = on_port(7211, "DROP") },
            Packet = { packet = { ["SrcPort.Equal"] = 5211, Actions = { "DROP" } },
                       ["packet-out"] = on_port(7210, "DROP") },
            Flow = { flow = on_port(7212, "DROP") },
        })
        local mine = one_datagram(5210)
        t:assert_eq(seat.trail(mine), "ingress:RawPacket", "a RawPacket DROP at ingress is the last judgment")
        mine = one_datagram(5211)
        t:assert_eq(seat.trail(mine), "ingress:RawPacket local_in:Packet",
            "a Packet DROP at LOCAL_IN leaves the flow unjudged")
        local pu = assert(ntfe.udp_bind(peer, net.peer_addr, 7210))
        for _, c in ipairs({
            { 7212, "local_out:Flow", "a Flow DROP at LOCAL_OUT never reaches egress" },
            { 7210, "local_out:Flow egress:Packet", "a Packet DROP at egress leaves RawPacket unasked" },
            { 7211, "local_out:Flow egress:Packet egress:RawPacket", "and RawPacket's own DROP is last" },
        }) do
            local _, events = E:during(function()
                local u = assert(ntfe.udp_connect(vm, net.peer_addr, c[1]))
                ntfe.send(vm, u, "out")
                sys.close(vm, u)
            end)
            local trail = seat.trail(events, function(e) return e.dst_port == c[1] end)
            t:assert_eq(trail, c[2], c[3])
            local last = {}
            for _, e in ipairs(events) do if e.dst_port == c[1] then last[#last + 1] = e end end
            table.sort(last, function(a, b) return a.seq < b.seq end)
            t:assert_eq(last[#last] and last[#last].verdict, DROP, c[3] .. ", and it was the DROP")
        end
        sys.close(peer, pu)
        use()
    end)

-- ---- from Packet to the flow ---------------------------------------------------

test("an untracked packet has no flow to judge, and the Packet verdict stands",
    { spec = "PKM *ntfe-seat.untracked-packet-keeps-packet-verdict" }, function(t)
        -- The Flow layer drops everything it judges. A SYN|FIN segment is
        -- one conntrack refuses to track, so no flow is judged and the
        -- Packet layer's PASS lets it reach TCP, which answers with a RST.
        use({ Flow = { all = { Actions = { "DROP" } } } })
        seat.flush(peer, wire)
        local delta, events = E:during(function()
            ntfe.send_frame(peer, wire, seat.tcp4_frame(net, 5212, 7213,
                ntfe.TCP.SYN | ntfe.TCP.FIN))
        end)
        local mine = ntfe.matching(events, { src_port = 5212 })
        local pkt = ntfe.matching(mine, { seat = S.LOCAL_IN, layer = L.PACKET })
        t:assert_eq(#pkt, 1, "the Packet layer judged it at LOCAL_IN: " .. ntfe.describe(mine))
        t:assert_eq(pkt[1] and pkt[1].flow_state, ntfe.FLOW_STATE.UNTRACKED, "as untracked")
        t:assert_eq(count(mine, { layer = L.FLOW }), 0, "the Flow layer was not asked")
        t:assert_eq(delta.flow_judged, 0, "and judged no flow")
        local answer = seat.from_vm(peer, net, wire, 200, function(f)
            return f.tcp and f.tcp.dport == 5212 and f.tcp.flags & ntfe.TCP.RST ~= 0
        end)
        t:assert(#answer >= 1, "the Packet layer's PASS stood: TCP got the segment and answered it")
        -- The control: a segment conntrack does track is the Flow layer's.
        local _, ev2 = E:during(function()
            ntfe.send_frame(peer, wire, seat.tcp4_frame(net, 5213, 7213, ntfe.TCP.SYN))
        end)
        t:assert_eq(count(ntfe.matching(ev2, { src_port = 5213 }), { layer = L.FLOW, verdict = DROP }), 1,
            "while a tracked SYN to the same port is judged by the Flow layer and dropped")
        use()
    end)

test("a tracked packet without a current sentence is evaluated by the Flow forest and sentenced",
    { spec = "PKM *ntfe-seat.unsentenced-flow-evaluated-and-sentenced" }, function(t)
        local l = assert(ntfe.tcp_listen(vm, net.addr, 7214))
        local fd
        local delta, events = E:during(function()
            fd = assert(ntfe.tcp_connect(peer, net.addr, 7214))
        end)
        local flow = ntfe.matching(events, { dst_port = 7214, layer = L.FLOW })
        t:assert_eq(#flow, 1, "the new flow's first packet was judged by the Flow layer")
        t:assert(delta.flow_judged >= 1, "counted in flow_judged")
        local found
        for _, f in ipairs(E:flows()) do
            if f.protocol == ntfe.IPPROTO.TCP and f.dst_port == 7214 then found = f end
        end
        t:assert(found, "the flow is in the flows dump")
        if found then
            local s = found.sentences[0]
            t:assert_eq(s.generation, E:status().generation, "sentenced at the current generation")
            t:assert_eq(s.verdict, PASS, "with the verdict it was given")
            t:assert_eq(s.rule_hash, ntfe.name_hash("all"), "by the rule that gave it")
        end
        sys.close(peer, fd)
        sys.close(vm, l)
    end)

test("a tracked packet with a current sentence gets that sentence, unevaluated",
    { spec = "PKM *ntfe-seat.tracked-packet-gets-current-sentence" }, function(t)
        local l = assert(ntfe.tcp_listen(vm, net.addr, 7215))
        local fd = assert(ntfe.tcp_connect(peer, net.addr, 7215))
        local a = assert(ntfe.tcp_accept(vm, l))
        local delta, events = E:during(function()
            for i = 1, 3 do
                ntfe.send(peer, fd, "data " .. i)
                t:assert(ntfe.recv(vm, a, 300), "packet " .. i .. " of the flow is delivered")
            end
        end)
        local mine = ntfe.matching(events, { dst_port = 7215 })
        t:assert(count(mine, { seat = S.LOCAL_IN, layer = L.PACKET }) >= 3,
            "the later packets are still judged by the Packet layer")
        t:assert_eq(count(mine, { layer = L.FLOW }), 0, "but not by the Flow layer")
        t:assert(delta.flow_cached >= 3, "they got the cached sentence")
        sys.close(peer, fd)
        sys.close(vm, a)
        sys.close(vm, l)
    end)

test("a flow's sentence answers for every later packet of the flow",
    { spec = "PKM *ntfe-seat.sentence-answers-for-later-packets" }, function(t)
        local l = assert(ntfe.tcp_listen(vm, net.addr, 7216))
        local fd = assert(ntfe.tcp_connect(peer, net.addr, 7216))
        local a = assert(ntfe.tcp_accept(vm, l))
        -- Re-sentence the established flow DROP; its next packet is judged
        -- once, and the sentence answers for every packet after it — the
        -- retransmissions included — without another evaluation.
        use({ Flow = { blocked = on_port(7216, "DROP") } })
        local delta, events = E:during(function()
            ntfe.send(peer, fd, "first")
            t:assert_eq(select(2, ntfe.recv(vm, a, 300)), "timeout", "the first is dropped")
            ntfe.send(peer, fd, "second")
            t:assert_eq(select(2, ntfe.recv(vm, a, 600)), "timeout", "and so is every later one")
        end)
        local judged = ntfe.matching(events, { dst_port = 7216, layer = L.FLOW })
        t:assert_eq(#judged, 1, "the flow was judged once: " .. ntfe.describe(judged))
        t:assert_eq(judged[1] and judged[1].attributed, "blocked", "by the rule that now holds")
        local later = count(ntfe.matching(events, { dst_port = 7216 }), { seat = S.LOCAL_IN, layer = L.PACKET }) - 1
        t:assert(later >= 1, "later packets arrived at LOCAL_IN")
        t:assert(delta.flow_cached >= later, "and each was answered by the sentence")
        use()
        sys.close(peer, fd)
        sys.close(vm, a)
        sys.close(vm, l)
    end)

test("the Flow layer judges every tracked flow once per local endpoint, at the IP seats",
    { spec = "PKM *ntfe-seat.flow-judged-once-per-local-endpoint" }, function(t)
        -- A flow to the peer has one local endpoint; a loopback flow two.
        local l = assert(ntfe.tcp_listen(vm, net.addr, 7217))
        local _, events = E:during(function()
            local fd = assert(ntfe.tcp_connect(peer, net.addr, 7217))
            local a = assert(ntfe.tcp_accept(vm, l))
            ntfe.send(peer, fd, "x"); ntfe.recv(vm, a, 300)
            ntfe.send(vm, a, "y"); ntfe.recv(peer, fd, 300)
            sys.close(peer, fd); sys.close(vm, a)
        end)
        sys.close(vm, l)
        local flow = ntfe.matching(events, { layer = L.FLOW })
        local mine = {}
        for _, e in ipairs(flow) do
            if e.dst_port == 7217 or e.src_port == 7217 then mine[#mine + 1] = e end
        end
        t:assert_eq(seat.trail(mine), "local_in:Flow",
            "a whole conversation with the peer is one Flow judgment, at LOCAL_IN")
        local ll = assert(ntfe.tcp_listen(vm, "127.0.0.1", 7218))
        _, events = E:during(function()
            local fd = assert(ntfe.tcp_connect(vm, "127.0.0.1", 7218))
            local a = assert(ntfe.tcp_accept(vm, ll))
            ntfe.send(vm, fd, "x"); ntfe.recv(vm, a, 300)
            ntfe.send(vm, a, "y"); ntfe.recv(vm, fd, 300)
            sys.close(vm, fd); sys.close(vm, a)
        end)
        sys.close(vm, ll)
        mine = {}
        for _, e in ipairs(ntfe.matching(events, { layer = L.FLOW })) do
            if e.dst_port == 7218 or e.src_port == 7218 then mine[#mine + 1] = e end
        end
        t:assert_eq(seat.trail(mine), "local_out:Flow local_in:Flow",
            "a loopback conversation is two: once at each endpoint's seat")
    end)

-- ---- what cannot be described, and what cannot be evaluated ---------------------

test("a frame too mangled to describe is counted and judged on its seat facts alone",
    { spec = "PKM *ntfe-seat.unbuildable-snapshot-judged-on-seat-facts" }, function(t)
        -- An IPv4 ethertype over a header that is not IPv4 (version 5).
        -- Every real IPv4 frame has a source address; the one rule that
        -- asks for an IPv4 frame without one matches only a snapshot
        -- built from the seat and the frame's link layer.
        use({ RawPacket = {
            addressless = { ["EtherType.Equal"] = "ipv4", ["SrcAddr.Present"] = 0,
                            Actions = { "REJECT(Prohibited)" } },
        } })
        local mangled = seat.ip4_raw_frame(net, "\x55" .. string.rep("\0", 39))
        local delta, events = E:during(function()
            ntfe.send_frame(peer, wire, mangled)
        end)
        t:assert_eq(delta.parse_errors, 1, "the snapshot that could not be built is counted")
        local ev = ntfe.matching(events, { attributed = "addressless" })
        t:assert_eq(#ev, 1, "the frame was still judged: " .. ntfe.describe(events))
        if ev[1] then
            t:assert_eq(ev[1].seat, S.INGRESS, "at the seat it arrived at")
            t:assert_eq(ev[1].ifindex, net.ifindex, "on its interface")
            t:assert_eq(ev[1].ether_type, ntfe.ETH_P.IP, "with its ethertype")
            t:assert_eq(ev[1].addr_family, 0, "and no address facts")
        end
        use()
    end)

test("an evaluation that fails drops the packet, counts fail_closed and reports it",
    { spec = "PKM *ntfe-seat.evaluation-failure-drops-counts-and-reports",
      covered_by = "kunit:pkm_kunit_ntfe",
      skip = "the only failure ntfe_rust_evaluate has is a refused GFP_ATOMIC " ..
             "allocation, and the kernel has no fault injection " ..
             "(CONFIG_FAULT_INJECTION unset), so the guest cannot make one; " ..
             "runs under ntfe_kunit_eval_failure_fails_closed, which forces " ..
             "peios_ntfe_policy_eval to answer -ENOMEM through a KUnit-only " ..
             "seam and asserts NF_DROP, fail_closed +1, and an event " ..
             "attributed `fail-closed` with PEIOS_NTFE_EV_F_FAIL_CLOSED, at a " ..
             "per-packet seat and in peios_ntfe_flow_dispatch (which writes no " ..
             "sentence); the Rust allocator's own refusal is not exercised" },
    function(t) end)
