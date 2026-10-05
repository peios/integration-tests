-- PKM §6.3 — the flow in the snapshot: the flow state per seat and how
-- conntrack's ctinfo maps onto it, the conntrack entry the snapshot
-- carries and what is scoped to it (tags, the sentence), the two facts
-- that exist only on a flow (`Related`, `Start.*`), the reply-direction
-- mark the Flow view turns back, the identity fields the view sets from
-- the flow's extension, and which layer is given what.
--
-- Own VM: the policy is machine-wide state, and these tests set the
-- guest's wall clock.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local token = require("helpers.token")
local H = require("helpers.ntfe_snapshot")

local vm = provium:vm("vntfesnflow", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local peer, net = ntfe.peer(vm)
local E = ntfe.engine(vm, H.policy())
local wire = assert(ntfe.packet_socket(peer, net.peer))
local AGENT_PID = vm:syscall(sys.NR.getpid).ret

local S, L, FS = ntfe.SEAT, ntfe.LAYER, ntfe.FLOW_STATE

local function publish(t, probes)
    local s = E:replace(H.policy(probes))
    t:assert_eq(s.last_ingest_error, 0, "the probe policy is accepted")
    return s
end

local function flow_to(port)
    for _, f in ipairs(E:flows()) do
        if f.dst_port == port then return f end
    end
end

local function hms(h, m, s) return h * 3600 + m * 60 + s end

-- The `Local.Process` text of a 16-byte GUID: lowercase 8-4-4-4-12.
-- The process GUID's PCDS text, as Local.Process reads it (PEI-1309).
local guid_text = require("helpers.ntfe_identity").guid_pcds

-- ---- the flow state ----

test("at the ingress seat conntrack has not run, and the flow state is absent",
    { spec = "PKM *ntfe-snapshot.ingress-flow-state-absent" }, function(t)
        publish(t, {})
        local rx = assert(ntfe.udp_bind(vm, net.addr, 7601))
        local _, events = H.inject(E, peer, wire, H.udp_frame(net, 5000, 7601, "x"), {
            { S.INGRESS, L.RAWPACKET, { dst_port = 7601 } }, { S.LOCAL_IN, L.PACKET, { dst_port = 7601 } } })
        sys.close(vm, rx)
        local ingress = H.at(events, S.INGRESS, L.RAWPACKET, { dst_port = 7601 })[1]
        local local_in = H.at(events, S.LOCAL_IN, L.PACKET, { dst_port = 7601 })[1]
        t:assert(ingress and local_in, "both seats judged the datagram: " .. H.describe(events))
        t:assert_eq(ingress.flow_state, FS.ABSENT, "ingress reads ABSENT")
        t:assert_eq(local_in.flow_state, FS.NEW, "where LOCAL_IN, after conntrack, reads `new`")
    end)

test("conntrack's ctinfo maps to new, established, related or untracked, in either direction",
    { spec = "PKM *ntfe-snapshot.ctinfo-maps-to-flow-state" }, function(t)
        publish(t, {
            Packet = {
                new = { ["FlowState.Equal"] = "new" },
                established = { ["FlowState.Equal"] = "established" },
                related = { ["FlowState.Equal"] = "related" },
                untracked = { ["FlowState.Equal"] = "untracked" },
            },
        })
        -- A TCP handshake from the peer: the SYN is new, our SYN-ACK is the
        -- established reply, the peer's ACK is established.
        local l = assert(ntfe.tcp_listen(vm, net.addr, 7602))
        local _, events = H.watch(E, function()
            local c = ntfe.tcp_connect(peer, net.addr, 7602)
            t:assert(c, "the handshake completes")
            if c then sys.close(peer, c) end
        end, {
            { S.LOCAL_IN, L.PACKET, { dst_port = 7602, flow_state = FS.ESTABLISHED } },
            { S.EGRESS, L.PACKET, { src_port = 7602 } },
        })
        sys.close(vm, l)
        local syn = H.at(events, S.LOCAL_IN, L.PACKET, { dst_port = 7602 })[1]
        t:assert_eq(syn and syn.attributed, "new", "the SYN is new: " .. H.describe(events))
        local synack = H.at(events, S.EGRESS, L.PACKET, { src_port = 7602 })[1]
        t:assert_eq(synack and synack.attributed, "established",
            "the SYN-ACK, IP_CT_ESTABLISHED_REPLY, is established")
        local ack = H.at(events, S.LOCAL_IN, L.PACKET, { dst_port = 7602, flow_state = FS.ESTABLISHED })[1]
        t:assert_eq(ack and ack.attributed, "established", "the ACK, IP_CT_ESTABLISHED, is established")

        -- Our datagram to a closed port: the outbound first packet is new
        -- at LOCAL_OUT, and the peer's port-unreachable is related.
        local _, ev2 = H.watch(E, function()
            local u = assert(ntfe.udp_connect(vm, net.peer_addr, 7603))
            ntfe.send(vm, u, "x")
            ntfe.recv(vm, u, 500)
            sys.close(vm, u)
        end, {
            { S.LOCAL_OUT, L.FLOW, { dst_port = 7603 } },
            { S.LOCAL_IN, L.PACKET, { protocol = ntfe.IPPROTO.ICMP, src = net.peer_addr } },
        })
        local out = H.at(ev2, S.LOCAL_OUT, L.FLOW, { dst_port = 7603 })[1]
        t:assert_eq(out and out.flow_state, FS.NEW, "LOCAL_OUT reads the first datagram as new")
        local err = H.at(ev2, S.LOCAL_IN, L.PACKET, { protocol = ntfe.IPPROTO.ICMP, src = net.peer_addr })[1]
        t:assert_eq(err and err.attributed, "related", "the ICMP error is IP_CT_RELATED_REPLY, related")

        -- The peer's datagram to our closed port: our answer is the
        -- related reply, at egress.
        local unreach = { protocol = ntfe.IPPROTO.ICMP, dst = net.peer_addr }
        local _, ev3 = H.inject(E, peer, wire, H.udp_frame(net, 5000, 7604), { { S.EGRESS, L.PACKET, unreach } })
        local ours = H.at(ev3, S.EGRESS, L.PACKET, unreach)[1]
        t:assert_eq(ours and ours.attributed, "related", "egress reads our error as related: " .. H.describe(ev3))

        -- An echo reply nobody asked for: conntrack keeps no entry.
        local orphan = { protocol = ntfe.IPPROTO.ICMP, src = net.peer_addr }
        local _, ev4 = H.inject(E, peer, wire, H.icmp_frame(net, 0, 0, 0x0f0f0001, "x"),
            { { S.LOCAL_IN, L.PACKET, orphan } })
        local o = H.at(ev4, S.LOCAL_IN, L.PACKET, orphan)[1]
        t:assert_eq(o and o.attributed, "untracked", "no entry is untracked: " .. H.describe(ev4))
    end)

test("`invalid` is reserved: a packet conntrack finds incoherent reads `untracked`",
    { spec = "PKM *ntfe-snapshot.invalid-flow-state-reserved" }, function(t)
        publish(t, {
            Packet = {
                invalid = { ["FlowState.Equal"] = "invalid", Priority = 20 },
                untracked = { ["FlowState.Equal"] = "untracked" },
            },
        })
        -- SYN and FIN together is no TCP state conntrack accepts.
        local _, events = H.inject(E, peer, wire,
            H.tcp_frame(net, 5000, 7605, ntfe.TCP.SYN | ntfe.TCP.FIN),
            { { S.LOCAL_IN, L.PACKET, { dst_port = 7605 } } })
        local e = H.at(events, S.LOCAL_IN, L.PACKET, { dst_port = 7605 })[1]
        t:assert(e, "the SYN|FIN segment reached LOCAL_IN: " .. H.describe(events))
        t:assert_eq(e.flow_state, FS.UNTRACKED, "with no entry")
        t:assert_eq(e.attributed, "untracked", "and an `invalid` condition does not match it")
    end)

-- ---- the flow itself ----

test("the snapshot's flow is the conntrack entry itself: what is written to it is on that entry",
    { spec = "PKM *ntfe-snapshot.flow-is-conn-never-template" }, function(t)
        -- No frontend exists to attach a conntrack template to a packet;
        -- what the guest can see is that the flow is the live entry of
        -- this datagram's tuple, the one the flows dump walks.
        publish(t, { Packet = { stamp = { ["DstPort.Equal"] = 7606, Actions = { "TAG(entry, Set, 42)", "PASS" } } } })
        local rx = assert(ntfe.udp_bind(vm, net.addr, 7606))
        local rx2 = assert(ntfe.udp_bind(vm, net.addr, 7607))
        H.watch(E, function()
            local a = assert(ntfe.udp_connect(peer, net.addr, 7606))
            ntfe.send(peer, a, "tagged")
            local b = assert(ntfe.udp_connect(peer, net.addr, 7607))
            ntfe.send(peer, b, "plain")
            sys.close(peer, a); sys.close(peer, b)
        end, { { S.LOCAL_IN, L.PACKET, { dst_port = 7606 } }, { S.LOCAL_IN, L.PACKET, { dst_port = 7607 } } })
        sys.close(vm, rx); sys.close(vm, rx2)
        local f = flow_to(7606)
        t:assert(f, "the flow is in conntrack's table")
        t:assert_eq(f.src, net.peer_addr, "keyed by the datagram's tuple")
        t:assert_eq(f.tags[ntfe.name_hash("entry")], 42, "and carrying the tag the rule wrote")
        local other = flow_to(7607)
        t:assert(other, "the other flow is there too")
        t:assert_eq(other.n_tags, 0, "and carries nothing: the tag is the one entry's")
    end)

test("tags are written to and read from the flow's extension, and the Flow verdict is cached there",
    { spec = "PKM *ntfe-snapshot.flow-scopes-tags-and-sentence" }, function(t)
        -- Tags flow upward only: Packet writes what Flow reads.
        local s = publish(t, {
            Packet = {
                writer = { ["DstPort.Equal"] = 7608, Actions = { "TAG(bypacket, Set, 3)", "PASS" }, Priority = 5 },
                reader = { ["DstPort.Equal"] = 7608, ["Tag.bypacket.Equal"] = 3, Priority = 20 },
            },
            Flow = { judge = { ["DstPort.Equal"] = 7608, ["Tag.bypacket.Equal"] = 3,
                               Actions = { "TAG(byflow, Set, 4)", "PASS" } } },
        })
        local rx = assert(ntfe.udp_bind(vm, net.addr, 7608))
        local tx = assert(ntfe.udp_connect(peer, net.addr, 7608))
        local _, events = H.watch(E, function()
            ntfe.send(peer, tx, "one")
            ntfe.recv(vm, rx, 500)
        end, { { S.LOCAL_IN, L.FLOW, { dst_port = 7608 } } })
        t:assert_eq(H.attribution(events, S.LOCAL_IN, L.FLOW, { dst_port = 7608 }), "judge",
            "the Flow layer judged the flow, reading the tag Packet had just written to it")
        local f = flow_to(7608)
        t:assert(f, "the flow is in the dump")
        t:assert_eq(f.tags[ntfe.name_hash("bypacket")], 3, "the Packet layer's TAG is on its extension")
        t:assert_eq(f.tags[ntfe.name_hash("byflow")], 4, "and so is the Flow layer's")
        t:assert_eq(f.sentences[0].generation, s.generation, "with the sentence of this generation")
        t:assert_eq(f.sentences[0].verdict, ntfe.VERDICT.PASS, "a PASS")
        t:assert_eq(f.sentences[0].rule_hash, ntfe.name_hash("judge"), "by the rule that judged")
        local _, ev2 = H.watch(E, function()
            ntfe.send(peer, tx, "two")
            ntfe.recv(vm, rx, 500)
        end, { { S.LOCAL_IN, L.PACKET, { dst_port = 7608 } } })
        t:assert_eq(H.attribution(ev2, S.LOCAL_IN, L.PACKET, { dst_port = 7608 }), "reader",
            "the next packet's Packet forest reads the tag from the same extension")
        t:assert_eq(#H.at(ev2, nil, L.FLOW, { dst_port = 7608 }), 0,
            "while the Flow verdict comes from the cache, unjudged")
        sys.close(peer, tx); sys.close(vm, rx)
    end)

test("the flow pointer stays valid for the hook because the skb holds the entry",
    { spec = "PKM *ntfe-snapshot.flow-pointer-valid-for-hook",
      covered_by = "kunit:pkm_kunit_ntfe",
      skip = "a lifetime argument: the guest cannot make an entry die while a hook " ..
             "holds its skb (no ctnetlink or other way to delete an entry in " ..
             "the kernel-only profile, and a correct kernel shows nothing either " ..
             "way); runs under ntfe_kunit_flow_pointer_held_by_skb, which drops " ..
             "every reference but the skb's, evaluates a forest that writes and " ..
             "reads a tag through the snapshot's flow pointer, and checks the " ..
             "entry is freed only with the skb" },
    function(t) end)

test("`Related` is whether the flow was expected by another, not whether the packet is related",
    { spec = "PKM *ntfe-snapshot.flow-related-is-ct-master-set" }, function(t)
        -- Only an expectation sets ct->master, and with no helper frontend
        -- none can be made here; what is visible is that a flow nobody
        -- expected reads Related = 0, even when the packet judging it is a
        -- related ICMP error.
        local prx = assert(ntfe.udp_bind(peer, net.peer_addr, 7609))
        local tx = assert(ntfe.udp_connect(vm, net.peer_addr, 7609))
        publish(t, {})
        local _, events = H.watch(E, function()
            ntfe.send(vm, tx, "x")
            ntfe.recv(peer, prx, 500)
        end, { { S.LOCAL_OUT, L.FLOW, { dst_port = 7609 } } })
        local first = H.at(events, S.LOCAL_OUT, L.FLOW, { dst_port = 7609 })[1]
        t:assert(first, "the flow was judged: " .. H.describe(events))
        local sport = first.src_port

        publish(t, {
            Packet = { state = { ["FlowState.Equal"] = "related" } },
            Flow = {
                expected = { ["Related.Equal"] = 1, Priority = 20 },
                unexpected = { ["Related.Equal"] = 0 },
            },
        })
        -- The peer sends a port-unreachable quoting our datagram by hand
        -- (its socket is open, so the stack would not).
        local inner_udp = ntfe.udp(net.addr, net.peer_addr, sport, 7609, "x")
        local quoted = ntfe.ipv4(net.addr, net.peer_addr, 17, #inner_udp) .. inner_udp:sub(1, 8)
        local err = { protocol = ntfe.IPPROTO.ICMP, src = net.peer_addr }
        -- The Flow view of the error is turned back to the flow's tuple.
        local view = { protocol = ntfe.IPPROTO.ICMP, src = net.addr, rejudged = true }
        local _, ev2 = H.inject(E, peer, wire, H.icmp_frame(net, 3, 3, 0, quoted), {
            { S.LOCAL_IN, L.PACKET, err }, { S.LOCAL_IN, L.FLOW, view } })
        t:assert_eq(H.attribution(ev2, S.LOCAL_IN, L.PACKET, err), "state",
            "the error reads FlowState related: " .. H.describe(ev2))
        local rejudged = H.at(ev2, S.LOCAL_IN, L.FLOW, view)[1]
        t:assert(rejudged, "and re-judges the flow it belongs to: " .. H.describe(ev2))
        t:assert_eq(rejudged.attributed, "unexpected", "whose Related is 0: no flow expected it")
        t:assert_eq(flow_to(7609).related, 0, "as the dump says too")
        sys.close(vm, tx); sys.close(peer, prx)
    end)

test("`Start.*` is the flow's start time from its extension, through the clock's calendar",
    { spec = "PKM *ntfe-snapshot.flow-start-from-extension-start-secs" }, function(t)
        local start = H.TUESDAY + hms(7, 5, 9)
        local born = {
            ["Start.Year.Equal"] = 2026, ["Start.Month.Equal"] = 9, ["Start.DayOfMonth.Equal"] = 22,
            ["Start.DayOfWeek.Equal"] = 2, ["Start.Hour.Equal"] = 7, ["Start.Minute.Equal"] = 5,
            ["Start.Second.Equal"] = "9-15",
        }
        publish(t, { Flow = { born = born } })
        local l = assert(ntfe.tcp_listen(peer, net.peer_addr, 7610))
        vm:clock():set(start)
        local c, a
        local _, events = H.watch(E, function()
            c = assert(ntfe.tcp_connect(vm, net.peer_addr, 7610))
            a = assert(ntfe.tcp_accept(peer, l))
        end, { { S.LOCAL_OUT, L.FLOW, { dst_port = 7610 } } })
        t:assert_eq(H.attribution(events, S.LOCAL_OUT, L.FLOW, { dst_port = 7610 }), "born",
            "the first judgment reads the start time's calendar")
        local f = flow_to(7610)
        t:assert(f.start_secs >= start and f.start_secs <= start + 6,
            "stamped in the extension when the entry was made: " .. f.start_secs)

        -- Two days and three hours on, the live clock has moved and the
        -- start has not.
        vm:clock():set(start + 2 * 86400 + 3 * 3600)
        local later = {}
        for k, v in pairs(born) do later[k] = v end
        later["Time.DayOfMonth.Equal"] = 24
        later["Time.Hour.Equal"] = 10
        publish(t, { Flow = { later = later } })
        local _, ev2 = H.watch(E, function()
            ntfe.send(peer, a, "later")
            ntfe.recv(vm, c, 500)
        end, { { S.LOCAL_IN, L.FLOW, { dst_port = 7610 } } })
        -- The view of the peer's reply carries the flow's own tuple.
        t:assert_eq(H.attribution(ev2, S.LOCAL_IN, L.FLOW, { dst_port = 7610 }), "later",
            "a re-judgment reads the same start beside the new time: " .. H.describe(ev2))
        sys.close(vm, c); sys.close(peer, a); sys.close(peer, l)
    end)

test("a reply packet is marked as one, and the Flow view turns its tuple back into the flow's",
    { spec = "PKM *ntfe-snapshot.flow-reply-marks-reply-direction" }, function(t)
        publish(t, {})
        local l = assert(ntfe.tcp_listen(peer, net.peer_addr, 7611))
        local c = assert(ntfe.tcp_connect(vm, net.peer_addr, 7611))
        local a = assert(ntfe.tcp_accept(peer, l))
        publish(t, {
            Flow = { original = {
                ["Direction.Equal"] = "out", ["SrcAddr.Equal"] = net.addr,
                ["DstAddr.Equal"] = net.peer_addr, ["DstPort.Equal"] = 7611,
            } },
        })
        -- The peer speaks first after the change: the stale flow is
        -- re-judged on a packet travelling in the reply direction.
        local _, events = H.watch(E, function()
            ntfe.send(peer, a, "reply")
            t:assert_eq(ntfe.recv(vm, c, 500), "reply", "the reply arrives")
        end, { { S.LOCAL_IN, L.FLOW, {} }, { S.LOCAL_IN, L.PACKET, { src_port = 7611 } } })
        local pkt = H.at(events, S.LOCAL_IN, L.PACKET, { src_port = 7611 })[1]
        t:assert(pkt, "the reply was judged by Packet: " .. H.describe(events))
        t:assert_eq(pkt.direction, ntfe.DIR.IN, "as the inbound packet it is")
        local flow = H.at(events, S.LOCAL_IN, L.FLOW, {})[1]
        t:assert(flow, "and re-judged by Flow: " .. H.describe(events))
        t:assert(flow.rejudged, "flagged a re-judgment")
        t:assert_eq(flow.attributed, "original", "with the flow's own tuple and direction")
        t:assert_eq(flow.src, net.addr, "the source swapped back to us")
        t:assert_eq(flow.dst_port, 7611, "the destination port back to the peer's")
        t:assert_eq(flow.direction, ntfe.DIR.OUT, "and the direction back to outbound")
        sys.close(vm, c); sys.close(peer, a); sys.close(peer, l)
    end)

-- ---- what each layer is given ----

test("a RawPacket forest is given no tags, whatever the flow carries",
    { spec = "PKM *ntfe-snapshot.rawpacket-forest-gets-no-tags" }, function(t)
        publish(t, {
            RawPacket = {
                writer = { ["Direction.Equal"] = "out", ["DstPort.Equal"] = 7612,
                           Actions = { "TAG(wire, Set)", "PASS" }, Priority = 5 },
                reader = { ["Direction.Equal"] = "out", ["DstPort.Equal"] = 7612,
                           ["Tag.wire.Equal"] = 1, Priority = 20 },
            },
            Packet = { reader = { ["Direction.Equal"] = "out", ["DstPort.Equal"] = 7612,
                                  ["Tag.wire.Equal"] = 1 } },
        })
        local prx = assert(ntfe.udp_bind(peer, net.peer_addr, 7612))
        local tx = assert(ntfe.udp_connect(vm, net.peer_addr, 7612))
        local got = {}
        for i = 1, 2 do
            local _, events = H.watch(E, function()
                ntfe.send(vm, tx, "n" .. i)
                ntfe.recv(peer, prx, 500)
            end, { { S.EGRESS, L.RAWPACKET, { dst_port = 7612 } } })
            got[i] = {
                raw = H.attribution(events, S.EGRESS, L.RAWPACKET, { dst_port = 7612 }),
                pkt = H.attribution(events, S.EGRESS, L.PACKET, { dst_port = 7612 }),
            }
        end
        t:assert_eq(flow_to(7612).tags[ntfe.name_hash("wire")], 1, "RawPacket's TAG is on the flow")
        t:assert_eq(got[2].pkt, "reader", "and the next packet's Packet forest reads it")
        t:assert_eq(got[2].raw, "writer", "but the RawPacket forest, the lowest layer, is never given it")
        sys.close(vm, tx); sys.close(peer, prx)
    end)

test("the flow-only facts are given to a Flow forest alone",
    { spec = "PKM *ntfe-snapshot.flow-only-facts-for-flow-forest-alone" }, function(t)
        local function probes(prefix)
            return {
                [prefix .. "related"] = { ["Related.Equal"] = 0, ["DstPort.Equal"] = 7613 },
                [prefix .. "start"] = { ["Start.Year.GreaterThan"] = 2000, ["DstPort.Equal"] = 7614 },
                [prefix .. "local"] = { ["Local.Equal"] = "program", ["DstPort.Equal"] = 7615 },
            }
        end
        publish(t, { RawPacket = probes("raw-"), Packet = probes("pkt-"), Flow = probes("flow-") })
        local waits, rx = {}, {}
        for port = 7613, 7615 do
            rx[port] = assert(ntfe.udp_bind(vm, net.addr, port))
            waits[#waits + 1] = { S.LOCAL_IN, L.FLOW, { dst_port = port } }
            waits[#waits + 1] = { S.LOCAL_IN, L.PACKET, { dst_port = port } }
            waits[#waits + 1] = { S.INGRESS, L.RAWPACKET, { dst_port = port } }
        end
        local _, events = H.watch(E, function()
            for port = 7613, 7615 do
                local u = assert(ntfe.udp_connect(peer, net.addr, port))
                ntfe.send(peer, u, "x")
                sys.close(peer, u)
            end
        end, waits)
        for port, fact in pairs({ [7613] = "related", [7614] = "start", [7615] = "local" }) do
            local function at(seat, layer)
                return H.attribution(events, seat, layer, { dst_port = port })
            end
            t:assert_eq(at(S.LOCAL_IN, L.FLOW), "flow-" .. fact, "the Flow forest is given " .. fact)
            t:assert_eq(at(S.LOCAL_IN, L.PACKET), "all", "the Packet forest at the same seat is not")
            t:assert_eq(at(S.INGRESS, L.RAWPACKET), "all", "nor the RawPacket forest")
        end
        for _, fd in pairs(rx) do sys.close(vm, fd) end
    end)

-- ---- the identity fields ----

test("the Flow view's identity fields come from the flow's extension: kind, process, pid and comm",
    { spec = "PKM *ntfe-snapshot.identity-fields-set-from-flow-extension" }, function(t)
        publish(t, {})
        local rx = assert(ntfe.udp_bind(vm, "127.0.0.1", 7616))
        local tx = assert(ntfe.udp_connect(vm, "127.0.0.1", 7616))
        local _, events = H.watch(E, function()
            ntfe.send(vm, tx, "x")
            ntfe.recv(vm, rx, 500)
        end, { { S.LOCAL_OUT, L.FLOW, { dst_port = 7616 } }, { S.LOCAL_IN, L.FLOW, { dst_port = 7616 } } })
        local out = H.at(events, S.LOCAL_OUT, L.FLOW, { dst_port = 7616 })[1]
        t:assert(out, "the loopback flow was judged as the sender: " .. H.describe(events))
        t:assert_eq(out["local"].kind, ntfe.LOCAL.PROGRAM, "its local end is a program")
        t:assert_eq(out["local"].pid, AGENT_PID, "the process that sent")
        t:assert(out["local"].comm ~= "", "named by its comm")
        t:assert(out["local"].guid ~= string.rep("\0", 16), "with its process GUID")
        t:assert_eq(out.remote.kind, ntfe.LOCAL.PROGRAM, "and on loopback the other end is one too")
        local f = flow_to(7616)
        t:assert_eq(f.owners[0].pid, out["local"].pid, "as recorded on the flow's extension")
        t:assert_eq(f.owners[0].guid, out["local"].guid, "GUID and all")

        -- A re-judgment reads them back from the extension unchanged.
        publish(t, { Flow = { again = { ["DstPort.Equal"] = 7616 } } })
        local _, ev2 = H.watch(E, function()
            ntfe.send(vm, tx, "y")
            ntfe.recv(vm, rx, 500)
        end, { { S.LOCAL_OUT, L.FLOW, { dst_port = 7616 } } })
        local again = H.at(ev2, S.LOCAL_OUT, L.FLOW, { dst_port = 7616 })[1]
        t:assert(again and again.rejudged, "the flow was re-judged: " .. H.describe(ev2))
        t:assert_eq(again["local"].guid, out["local"].guid, "with the same local end")
        t:assert_eq(again["local"].comm, out["local"].comm, "comm and all")
        sys.close(vm, tx); sys.close(vm, rx)
    end)

test("a program end lifts into a principal the Local.* conditions question",
    { spec = "PKM *ntfe-snapshot.program-end-lifts-to-principal" }, function(t)
        publish(t, {})
        local rx = assert(ntfe.udp_bind(vm, net.addr, 7617))
        local _, events = H.watch(E, function()
            local u = assert(ntfe.udp_connect(peer, net.addr, 7617))
            ntfe.send(peer, u, "x")
            sys.close(peer, u)
        end, { { S.LOCAL_IN, L.FLOW, { dst_port = 7617 } } })
        local first = H.at(events, S.LOCAL_IN, L.FLOW, { dst_port = 7617 })[1]
        t:assert(first and first["local"].user, "the receiving program's user is in the event")
        local user = token.sid_string(first["local"].user)
        local process = guid_text(first["local"].guid)

        publish(t, {
            Flow = {
                wrong = { ["Local.User.Equal"] = "S-1-5-21-1-2-3-4", Priority = 30 },
                principal = { ["Local.User.Equal"] = user, ["Local.Process.Equal"] = process,
                              ["Local.Integrity.Equal"] = "0-1000000", Priority = 20 },
            },
        })
        local _, ev2 = H.watch(E, function()
            local u = assert(ntfe.udp_connect(peer, net.addr, 7617))
            ntfe.send(peer, u, "y")
            sys.close(peer, u)
        end, { { S.LOCAL_IN, L.FLOW, { dst_port = 7617 } } })
        sys.close(vm, rx)
        t:assert_eq(H.attribution(ev2, S.LOCAL_IN, L.FLOW, { dst_port = 7617 }), "principal",
            "the receiving socket's token answers for " .. user .. " and process " .. process
            .. ": " .. H.describe(ev2))
    end)

test("every other snapshot leaves the identity fields zero, and they lift to absent",
    { spec = "PKM *ntfe-snapshot.identity-fields-zero-elsewhere-lift-absent" }, function(t)
        local program = { ["Local.Equal"] = "program", ["DstPort.Equal"] = 7618 }
        publish(t, { Packet = { program = program }, RawPacket = { program = program }, Flow = { program = program } })
        local rx = assert(ntfe.udp_bind(vm, net.addr, 7618))
        local _, events = H.watch(E, function()
            local u = assert(ntfe.udp_connect(peer, net.addr, 7618))
            ntfe.send(peer, u, "x")
            sys.close(peer, u)
        end, {
            { S.INGRESS, L.RAWPACKET, { dst_port = 7618 } },
            { S.LOCAL_IN, L.PACKET, { dst_port = 7618 } },
            { S.LOCAL_IN, L.FLOW, { dst_port = 7618 } },
        })
        sys.close(vm, rx)
        local flow = H.at(events, S.LOCAL_IN, L.FLOW, { dst_port = 7618 })[1]
        t:assert_eq(flow and flow.attributed, "program", "the Flow view has a program at its local end")
        for _, c in ipairs({ { S.INGRESS, L.RAWPACKET, "RawPacket" }, { S.LOCAL_IN, L.PACKET, "Packet" } }) do
            local e = H.at(events, c[1], c[2], { dst_port = 7618 })[1]
            t:assert(e, c[3] .. " judged the datagram: " .. H.describe(events))
            t:assert_eq(e["local"].kind, ntfe.LOCAL.ABSENT, c[3] .. "'s snapshot has no local end")
            t:assert_eq(e["local"].pid, 0, "no pid")
            t:assert_eq(e["local"].user, nil, "no user")
            t:assert_eq(e.attributed, "all", "and `Local` is absent there, so nothing matches it")
        end
    end)
