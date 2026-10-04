-- PKM §6.8 — The Flow layer, one judgment per local endpoint: the flow
-- dispatch behind the Packet layer, the sentence a tracked packet reads
-- instead of evaluating, the untracked packet that has no flow to
-- judge, re-judgment of a stale sentence, and the flow view — the
-- original tuple and the originator's direction, which a packet in the
-- reply direction is judged as, while its refusal still answers the
-- packet in hand.
--
-- The flows here are normal ones, with one local endpoint: traffic
-- between the VM and a peer on a veth pair, whose own namespace NTFE
-- does not instrument, so it stands in for a remote host.
--
-- Own VM: the policy is machine-wide state.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local nf = require("helpers.ntfe_flow")

local vm = provium:vm("vntfeflowdisp", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local peer, net = ntfe.peer(vm)

local PASS_ALL = { all = { Actions = { "PASS" } } }
local E = ntfe.engine(vm, { RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = PASS_ALL })

local function flow_policy(flow)
    local s = E:replace({ RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = flow })
    assert(s.last_ingest_error == 0, "the policy is accepted: " .. s.last_ingest_error)
    return s
end

-- A UDP flow from the peer: an unconnected socket on each side, so no
-- refusal parks an error that would stop the next send.
local function udp_from_peer(sport, dport)
    local rx = assert(ntfe.udp_bind(vm, net.addr, dport))
    local tx = assert(ntfe.udp_bind(peer, net.peer_addr, sport))
    return rx, function(data)
        return ntfe.sendto(peer, tx, data, net.addr, dport)
    end
end

test("a connection is judged once, and every later packet of it reads the sentence",
    { spec = "PKM *ntfe-flow.decisions-run-once-per-connection PKM *ntfe-flow.current-sentence-applied-without-evaluation" },
    function(t)
        flow_policy(PASS_ALL)
        local l = assert(ntfe.tcp_listen(vm, net.addr, 7000))
        local delta, events = E:during(function()
            local c = assert(ntfe.tcp_connect(peer, net.addr, 7000))
            local s = assert(ntfe.tcp_accept(vm, l))
            for i = 1, 3 do
                ntfe.send(peer, c, "ask" .. i)
                t:assert_eq(ntfe.recv(vm, s), "ask" .. i, "the request arrives")
                ntfe.send(vm, s, "answer" .. i)
                t:assert_eq(ntfe.recv(peer, c), "answer" .. i, "and the answer")
            end
            sys.close(peer, c); sys.close(vm, s)
        end)
        sys.close(vm, l)
        local mine = nf.flow_events(events, { dst_port = 7000 })
        t:assert_eq(#mine, 1, "the whole connection is judged once: " .. ntfe.describe(mine))
        t:assert_eq(#nf.flow_events(events), delta.flow_judged,
            "and every Flow evaluation is one of the events")
        -- Handshake, three exchanges and the close cross the seats a dozen
        -- times; only the first packet evaluated.
        t:assert(delta.flow_cached >= 8,
            "every later packet, both ways, applied the sentence: " .. delta.flow_cached)
    end)

test("the flow dispatch is reached only by a packet the Packet layer passed",
    {
        spec = "PKM *ntfe-flow.dispatch-after-packet-pass",
        -- PEI-1311 (TRM). True inbound, where
        -- LOCAL_IN runs Packet and then the flow dispatch. Outbound the
        -- dispatch runs at LOCAL_OUT before the Packet layer has seen the
        -- packet (seats.c, peios_ntfe_hook_local_out; §6.2's own seat table
        -- says "LOCAL_OUT: the flow's sentence or Flow", and the policy
        -- reference puts Flow "first outbound (before Packet)"): a SYN the
        -- Packet layer drops at egress has already been judged and
        -- sentenced by the Flow layer. The §6.8 sentence holds for one
        -- direction only.
        tags = { "known-bug" },
    },
    function(t)
        E:replace({
            RawPacket = PASS_ALL,
            Packet = {
                all = { Actions = { "PASS" } },
                ["no-in"] = { ["DstPort.Equal"] = 7010, Actions = { "DROP" } },
                ["no-out"] = { ["DstPort.Equal"] = 7011, Actions = { "DROP" } },
            },
            Flow = PASS_ALL,
        })
        local l = assert(ntfe.tcp_listen(vm, net.addr, 7010))
        local _, inbound = E:during(function()
            local _, why = ntfe.tcp_connect(peer, net.addr, 7010, 300)
            t:assert_eq(why, "timeout", "an inbound SYN the Packet layer drops goes unanswered")
        end)
        sys.close(vm, l)
        t:assert(#ntfe.matching(inbound, { layer = ntfe.LAYER.PACKET, attributed = "no-in" }) >= 1,
            "it was dropped by the Packet layer: " .. ntfe.describe(inbound))
        t:assert_eq(#nf.flow_events(inbound, { dst_port = 7010 }), 0,
            "and never reached the Flow layer")

        local pl = assert(ntfe.tcp_listen(peer, net.peer_addr, 7011))
        local _, outbound = E:during(function()
            local _, why = ntfe.tcp_connect(vm, net.peer_addr, 7011, 300)
            t:assert_eq(why, "timeout", "an outbound SYN the Packet layer drops goes unanswered")
        end)
        sys.close(peer, pl)
        t:assert(#ntfe.matching(outbound, { layer = ntfe.LAYER.PACKET, attributed = "no-out" }) >= 1,
            "it was dropped by the Packet layer: " .. ntfe.describe(outbound))
        t:assert_eq(#nf.flow_events(outbound, { dst_port = 7011 }), 0,
            "and, as the TRM states it, never reached the Flow layer either: "
            .. ntfe.describe(nf.flow_events(outbound, { dst_port = 7011 })))
    end)

test("an untracked packet has no flow to judge, and the Packet verdict stands",
    { spec = "PKM *ntfe-flow.untracked-packet-keeps-packet-verdict" },
    function(t)
        flow_policy({ ["drop-all"] = { Actions = { "DROP" } } })
        -- A TCP segment with no flags: conntrack refuses it as invalid
        -- and leaves it untracked. The stack answers it with a reset,
        -- which conntrack refuses as well (a reset opens no flow).
        local ps = assert(ntfe.packet_socket(peer, net.peer))
        local seg = ntfe.tcp(net.peer_addr, net.addr, 4444, 7020, 0)
        local frame = ntfe.eth(net.mac, net.peer_mac, ntfe.ETH_P.IP)
            .. ntfe.ipv4(net.peer_addr, net.addr, ntfe.IPPROTO.TCP, #seg) .. seg
        local seen
        local _, events = E:during(function()
            ntfe.frames(peer, ps, 50)
            ntfe.send_frame(peer, ps, frame)
            seen = ntfe.frames(peer, ps, 300)
        end)
        sys.close(peer, ps)
        local inbound = ntfe.matching(events, {
            seat = ntfe.SEAT.LOCAL_IN, layer = ntfe.LAYER.PACKET, dst_port = 7020,
        })
        t:assert_eq(#inbound, 1, "the Packet layer judged the segment: " .. ntfe.describe(events))
        t:assert_eq(inbound[1].flow_state, ntfe.FLOW_STATE.UNTRACKED, "as untracked")
        t:assert_eq(#nf.flow_events(events, { dst_port = 7020 }), 0,
            "the Flow layer judged nothing inbound")
        t:assert_eq(#nf.flow_events(events, { src_port = 7020 }), 0, "nor outbound")
        local reset = false
        for _, f in ipairs(seen) do
            if f.tcp and f.ip.src == net.addr and f.tcp.sport == 7020
                and f.tcp.flags & ntfe.TCP.RST ~= 0 then
                reset = true
            end
        end
        t:assert(reset, "a Flow forest that drops everything stopped neither the "
            .. "segment nor the reset the stack sent back")
    end)

test("a stale sentence is evaluated again, rewritten, and the event says it was re-judged",
    { spec = "PKM *ntfe-flow.stale-sentence-evaluated-and-rewritten" },
    function(t)
        flow_policy({ first = { Actions = { "PASS" } } })
        local rx, send = udp_from_peer(7031, 7030)
        send("one")
        t:assert_eq(ntfe.recv(vm, rx), "one", "the flow's first datagram is passed")
        local before = assert(nf.flow(E, { src = net.peer_addr, src_port = 7031, dst_port = 7030 }))
        local s = flow_policy({ second = { Actions = { "PASS" } } })

        local delta, events = E:during(function()
            send("two")
            t:assert_eq(ntfe.recv(vm, rx), "two", "the next is passed under the new policy")
        end)
        local mine = nf.flow_events(events, { dst_port = 7030 })
        t:assert_eq(#mine, 1, "the next packet evaluated the Flow forest: " .. ntfe.describe(events))
        t:assert_eq(mine[1].attributed, "second", "the new one")
        t:assert(mine[1].rejudged, "and its event carries REJUDGED, replacing a stale sentence")
        t:assert_eq(delta.flow_rejudged, 1, "counted as a re-judgment by generation")
        t:assert_eq(delta.flow_expired, 0, "not by time")
        t:assert_eq(delta.flow_judged, #nf.flow_events(events), "and as a Flow judgment")
        t:assert_eq(delta.judged, #events, "and among every layer's judgments")

        local after = assert(nf.flow(E, { src = net.peer_addr, src_port = 7031, dst_port = 7030 }))
        t:assert_eq(before.sentences[0].rule_hash, ntfe.name_hash("first"),
            "the old sentence named the old rule")
        t:assert_eq(after.sentences[0].generation, s.generation,
            "the new sentence carries the current generation")
        t:assert_eq(after.sentences[0].rule_hash, ntfe.name_hash("second"), "and the new rule")

        local again = E:during(function()
            send("three")
            t:assert_eq(ntfe.recv(vm, rx), "three", "the third datagram is passed")
        end)
        t:assert(again.flow_cached >= 1, "by the rewritten sentence, now current")
        t:assert_eq(again.flow_rejudged, 0, "with nothing left to re-judge")
        sys.close(vm, rx)
    end)

test("a refusal is sent before the event, so the event confesses a refusal that could not be",
    { spec = "PKM *ntfe-flow.refusal-sent-before-event" },
    function(t)
        flow_policy({
            all = { Actions = { "PASS" } },
            refuse = { ["DstPort.Equal"] = { "7041", "7042" }, Actions = { "REJECT" } },
        })
        -- A broadcast destination has no refusal vocabulary: the REJECT
        -- is applied as a DROP, and only an event written after the
        -- attempt can say so.
        local b = assert(ntfe.udp_bind(vm, net.addr, 7040))
        ntfe.set_int_opt(vm, b, 1, 6, 1) -- SO_BROADCAST
        local delta, events = E:during(function()
            ntfe.sendto(vm, b, "anyone", "10.9.0.255", 7041)
        end)
        local refused = nf.flow_events(events, { dst_port = 7041 })
        t:assert_eq(#refused, 1, "the broadcast is judged: " .. ntfe.describe(events))
        t:assert_eq(refused[1].verdict, ntfe.VERDICT.REJECT, "as a REJECT")
        t:assert(refused[1].reject_degraded, "whose event confesses the refusal was not sent")
        t:assert_eq(delta.refusals_emitted, 0, "none was")
        t:assert_eq(delta.reject_degraded, 1, "and the degradation is counted")

        local delta2, events2 = E:during(function()
            ntfe.sendto(vm, b, "you", net.peer_addr, 7042)
        end)
        local sent = nf.flow_events(events2, { dst_port = 7042 })
        t:assert_eq(#sent, 1, "a unicast REJECT is judged: " .. ntfe.describe(events2))
        t:assert(not sent[1].reject_degraded, "and its event knows the refusal went out")
        t:assert_eq(delta2.refusals_emitted, 1, "as it did")
        sys.close(vm, b)
    end)

test("a normal flow has one sentence, slot 0, written at the originator's seat on its first packet",
    { spec = "PKM *ntfe-flow.normal-flow-one-sentence-slot-0 PKM *ntfe-flow.direction-is-originator-side" },
    function(t)
        local s = flow_policy(PASS_ALL)
        local l = assert(ntfe.tcp_listen(vm, net.addr, 7050))
        local pl = assert(ntfe.tcp_listen(peer, net.peer_addr, 7051))
        local _, events = E:during(function()
            local c = assert(ntfe.tcp_connect(peer, net.addr, 7050))
            local a = assert(ntfe.tcp_accept(vm, l))
            ntfe.send(vm, a, "reply first")
            t:assert_eq(ntfe.recv(peer, c), "reply first", "the inbound connection carries data")
            local o = assert(ntfe.tcp_connect(vm, net.peer_addr, 7051))
            local oa = assert(ntfe.tcp_accept(peer, pl))
            ntfe.send(peer, oa, "back")
            t:assert_eq(ntfe.recv(vm, o), "back", "and so does the outbound one")
        end)
        local inbound = nf.flow_events(events, { dst_port = 7050 })
        t:assert_eq(#inbound, 1, "the inbound flow is judged once: " .. ntfe.describe(inbound))
        t:assert_eq(inbound[1].seat, ntfe.SEAT.LOCAL_IN, "at the inbound seat, where its first packet arrived")
        t:assert_eq(inbound[1].direction, ntfe.DIR.IN, "as `in`, the originator's side")
        local outbound = nf.flow_events(events, { dst_port = 7051 })
        t:assert_eq(#outbound, 1, "the outbound flow is judged once: " .. ntfe.describe(outbound))
        t:assert_eq(outbound[1].seat, ntfe.SEAT.LOCAL_OUT, "at the outbound seat")
        t:assert_eq(outbound[1].direction, ntfe.DIR.OUT, "as `out`")

        for _, want in ipairs({
            { dst_port = 7050, dir = ntfe.DIR.IN }, { dst_port = 7051, dir = ntfe.DIR.OUT },
        }) do
            local f = assert(nf.flow(E, { protocol = ntfe.IPPROTO.TCP, dst_port = want.dst_port }))
            t:assert_eq(f.sentences[0].generation, s.generation, "the sentence is in slot 0")
            t:assert_eq(f.sentences[1].generation, 0, "and slot 1 is empty")
            t:assert_eq(f.loopback, 0, "on a flow that is not loopback")
            t:assert_eq(f.direction, want.dir, "whose recorded direction is the originator's")
            t:assert(f.packets[2] >= 1, "though packets went the other way too, judged by that sentence")
        end
    end)

test("a reply-direction packet is re-judged as the flow, while its refusal answers the packet itself",
    { spec = "PKM *ntfe-flow.judges-flow-view-not-packet PKM *ntfe-flow.reply-view-uses-original-tuple PKM *ntfe-flow.rejudgment-sees-first-judgment-facts PKM *ntfe-flow.refusal-answers-packet-in-hand PKM *ntfe-flow.event-describes-flow-as-judged" },
    function(t)
        flow_policy(PASS_ALL)
        -- Connected on both sides, so an ICMP error lands as the socket's
        -- error on whichever end it reaches.
        local mine = assert(ntfe.udp_connect(vm, net.peer_addr, 7061, { bind = { net.addr, 7060 } }))
        local theirs = assert(ntfe.udp_connect(peer, net.addr, 7060, { bind = { net.peer_addr, 7061 } }))
        ntfe.send(peer, theirs, "hello")
        t:assert_eq(ntfe.recv(vm, mine), "hello", "the peer opens the flow")

        -- If the reply were judged as the packet it is — 10.9.0.1:7060 to
        -- 10.9.0.2:7061, outbound — `outbound-ok` would pass it. Judged
        -- as the flow, inbound from 10.9.0.2:7061, it is refused.
        flow_policy({
            ["outbound-ok"] = { ["Direction.Equal"] = "out", Actions = { "PASS" } },
            ["inbound-7060"] = {
                ["Direction.Equal"] = "in", ["SrcAddr.Equal"] = net.peer_addr,
                ["SrcPort.Equal"] = 7061, ["DstPort.Equal"] = 7060,
                Actions = { "REJECT" },
            },
        })
        local delta, events = E:during(function()
            ntfe.send(vm, mine, "goodbye")
        end)
        local judged = nf.flow_events(events, { dst_port = 7060 })
        t:assert_eq(#judged, 1, "the reply re-judged the flow: " .. ntfe.describe(events))
        local e = judged[1]
        t:assert(e.rejudged, "a re-judgment")
        t:assert_eq(e.seat, ntfe.SEAT.LOCAL_OUT, "made on the reply, at the outbound seat")
        t:assert_eq(e.attributed, "inbound-7060", "by the rule for the flow, not for the packet")
        t:assert_eq(e.verdict, ntfe.VERDICT.REJECT, "which refuses it")
        t:assert_eq(e.direction, ntfe.DIR.IN, "the event gives the direction the first judgment recorded")
        t:assert_eq(e.src, net.peer_addr, "and the original tuple: the peer's address as source")
        t:assert_eq(e.src_port, 7061, "its port")
        t:assert_eq(e.dst, net.addr, "ours as destination")
        t:assert_eq(e.dst_port, 7060, "and our port")
        t:assert_eq(delta.refusals_emitted, 1, "a refusal is sent")
        t:assert_eq(nf.pending_error(vm, mine), sys.E.CONNREFUSED,
            "to the sender of the packet in hand, our own socket")
        t:assert_eq(nf.pending_error(peer, theirs, 100), 0, "not to the flow's originator")
        t:assert_eq(select(2, ntfe.recv(peer, theirs, 200)), "timeout", "who receives nothing")
        sys.close(vm, mine); sys.close(peer, theirs)
    end)

test("an ICMP reply is judged with the type of the flow's request",
    { spec = "PKM *ntfe-flow.reply-view-uses-original-tuple PKM *ntfe-flow.judges-flow-view-not-packet" },
    function(t)
        flow_policy(PASS_ALL)
        -- The peer stays quiet, so the only reply is the one built below,
        -- sent after the policy changes.
        assert(nf.write_file(peer, "/proc/sys/net/ipv4/icmp_echo_ignore_all", "1").ret > 0)
        local raw = assert(ntfe.socket(vm, ntfe.AF_INET, ntfe.SOCK_RAW, { protocol = ntfe.IPPROTO.ICMP }))
        local echo_id, payload = 0x4242, "flow-view"
        ntfe.sendto(vm, raw, ntfe.icmp(8, 0, (echo_id << 16) | 1, payload), net.peer_addr, 0)
        local f = assert(nf.flow(E, { protocol = ntfe.IPPROTO.ICMP, src_port = echo_id }))
        t:assert_eq(f.icmp_type, 8, "the flow is an echo request's")

        flow_policy({
            ["as-request"] = { ["IcmpType.Equal"] = 8, Actions = { "PASS" } },
            ["as-reply"] = { ["IcmpType.Equal"] = 0, Priority = 10, Actions = { "DROP" } },
        })
        local ps = assert(ntfe.packet_socket(peer, net.peer))
        local icmp = ntfe.icmp(0, 0, (echo_id << 16) | 1, payload)
        local _, events = E:during(function()
            ntfe.send_frame(peer, ps, ntfe.eth(net.mac, net.peer_mac, ntfe.ETH_P.IP)
                .. ntfe.ipv4(net.peer_addr, net.addr, ntfe.IPPROTO.ICMP, #icmp) .. icmp)
        end)
        sys.close(peer, ps)
        local judged = ntfe.matching(events, { layer = ntfe.LAYER.FLOW, seat = ntfe.SEAT.LOCAL_IN })
        t:assert_eq(#judged, 1, "the echo reply re-judged the flow: " .. ntfe.describe(events))
        t:assert_eq(judged[1].attributed, "as-request", "as an echo request, the tuple's type")
        t:assert_eq(judged[1].src, net.addr, "from the request's source")
        t:assert_eq(judged[1].direction, ntfe.DIR.OUT, "in the request's direction")
        sys.close(vm, raw)
        nf.write_file(peer, "/proc/sys/net/ipv4/icmp_echo_ignore_all", "0")
    end)
