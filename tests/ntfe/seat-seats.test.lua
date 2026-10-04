-- PKM §6.2 — the seats: the per-device ingress and egress hooks that a
-- netdevice notifier attaches to every interface (those born before NTFE
-- included), what they see (frames, before conntrack), the IP seats at
-- LOCAL_IN and LOCAL_OUT (after conntrack has classified the flow, before
-- it is confirmed), and the one namespace that is instrumented.
--
-- Own VM: the policy is machine-wide state, and the tests create and
-- destroy interfaces.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local seat = require("helpers.ntfe_seat")

local vm = provium:vm("vntfeseatseats", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local peer, net = ntfe.peer(vm)
local E = ntfe.engine(vm, seat.policy())
local wire = assert(ntfe.packet_socket(peer, net.peer))
local LO = assert(ntfe.if_index(vm, "lo"))

local S, L = ntfe.SEAT, ntfe.LAYER

local function use(extra)
    local s = E:replace(seat.policy(extra))
    assert(s.last_ingest_error == 0, "the test policy ingests: " .. s.last_ingest_error)
end

local function count(events, want) return #ntfe.matching(events, want) end

local function find_flow(port)
    for _, f in ipairs(E:flows()) do
        if f.dst_port == port then return f end
    end
end

-- ---- the device seats ------------------------------------------------------

test("a device registered after boot gets both device seats, and a new one in its place gets its own",
    { spec = "PKM *ntfe-seat.device-seats-follow-netdev-notifier" }, function(t)
        -- A veth pair with both ends in this namespace: an ARP request
        -- out of one end is a frame at its egress seat and at the other
        -- end's ingress seat.
        local function pair_seats(round)
            assert(ntfe.link_add(vm, "vx0", "veth", { peer = "vx1" }))
            assert(ntfe.if_addr(vm, "vx0", "10.78.0.1", 24))
            assert(ntfe.if_up(vm, "vx1"))
            local a, b = ntfe.if_index(vm, "vx0"), ntfe.if_index(vm, "vx1")
            local _, events = E:during(function()
                local u = assert(ntfe.udp_connect(vm, "10.78.0.3", 7400))
                ntfe.send(vm, u, "who has")
                ntfe.recv(vm, u, 100)
                sys.close(vm, u)
            end)
            t:assert(count(events, { seat = S.EGRESS, ifindex = a }) >= 1,
                round .. ": the new device's egress seat judged its first frame")
            t:assert(count(events, { seat = S.INGRESS, ifindex = b }) >= 1,
                round .. ": and its twin's ingress seat")
            assert(ntfe.link_del(vm, "vx0"))
            return a, b
        end
        local a1, b1 = pair_seats("created")
        local a2, b2 = pair_seats("re-created after deletion")
        t:assert(a2 ~= a1 and b2 ~= b1, "the second pair are new devices, with seats of their own")
    end)

test("an interface that existed before NTFE started has its seats too",
    { spec = "PKM *ntfe-seat.boot-time-interfaces-get-seats" }, function(t)
        -- Loopback is registered with the namespace, long before NTFE's
        -- late initcall registers the notifier.
        local l = assert(ntfe.tcp_listen(vm, "127.0.0.1", 7401))
        local _, events = E:during(function()
            local fd = assert(ntfe.tcp_connect(vm, "127.0.0.1", 7401))
            sys.close(vm, fd)
        end)
        sys.close(vm, l)
        t:assert(count(events, { seat = S.EGRESS, ifindex = LO, layer = L.RAWPACKET }) >= 1,
            "loopback's egress seat judges")
        t:assert(count(events, { seat = S.INGRESS, ifindex = LO, layer = L.RAWPACKET }) >= 1,
            "and its ingress seat")
    end)

test("the device seats see frames: Ethernet header present, VLAN tags visible, conntrack not yet run",
    { spec = "PKM *ntfe-seat.device-seats-see-frames" }, function(t)
        local function mac_text(m)
            return string.format("%02x:%02x:%02x:%02x:%02x:%02x", m:byte(1, 6))
        end
        local pi = assert(ntfe.if_index(peer, net.peer))
        assert(ntfe.link_add(vm, "veth0.100", "vlan", { link = net.ifindex, id = 100 }))
        assert(ntfe.link_add(peer, "peer0.100", "vlan", { link = pi, id = 100 }))
        assert(ntfe.if_addr(vm, "veth0.100", "10.9.100.1", 24))
        assert(ntfe.if_addr(peer, "peer0.100", "10.9.100.2", 24))
        use({ RawPacket = {
            frame = { ["SrcMac.Equal"] = mac_text(net.peer_mac), ["DstMac.Equal"] = mac_text(net.mac),
                      ["EtherType.Equal"] = "ipv4", ["DstPort.Equal"] = 7402, Actions = { "DROP" } },
            tagged = { ["Vlan.Equal"] = 100, ["SrcMac.Equal"] = mac_text(net.peer_mac),
                       ["DstPort.Equal"] = 7403, Actions = { "DROP" } },
        } })
        local l = assert(ntfe.tcp_listen(vm, "0.0.0.0", 7403))
        local _, events = E:during(function()
            ntfe.tcp_connect(peer, net.addr, 7402, 200)
            ntfe.tcp_connect(peer, "10.9.100.1", 7403, 200)
        end)
        sys.close(vm, l)
        local framed = ntfe.matching(events, { attributed = "frame" })
        t:assert(#framed >= 1 and framed[1].seat == S.INGRESS,
            "a rule on both MACs and the ethertype matched at ingress: " .. ntfe.describe(events))
        local tagged = ntfe.matching(events, { attributed = "tagged" })
        t:assert(#tagged >= 1 and tagged[1].seat == S.INGRESS and tagged[1].ifindex == net.ifindex,
            "a rule on the VLAN tag matched the tagged frame on the parent device")
        -- An established connection: the same packet reads as part of a
        -- flow at LOCAL_IN, and as nothing of the kind at ingress.
        use()
        local l2 = assert(ntfe.tcp_listen(vm, net.addr, 7404))
        local fd = assert(ntfe.tcp_connect(peer, net.addr, 7404))
        local a = assert(ntfe.tcp_accept(vm, l2))
        local _, ev2 = E:during(function()
            ntfe.send(peer, fd, "established")
            ntfe.recv(vm, a, 300)
        end)
        local data = ntfe.matching(ev2, { dst_port = 7404 })
        local at_ingress = ntfe.matching(data, { seat = S.INGRESS })
        local at_local_in = ntfe.matching(data, { seat = S.LOCAL_IN })
        t:assert(#at_ingress >= 1 and #at_local_in >= 1, "the data segment met both seats")
        for _, e in ipairs(at_ingress) do
            t:assert_eq(e.flow_state, ntfe.FLOW_STATE.ABSENT, "at ingress there is no flow state yet")
        end
        t:assert_eq(at_local_in[1] and at_local_in[1].flow_state, ntfe.FLOW_STATE.ESTABLISHED,
            "at LOCAL_IN the same packet is of an established flow")
        sys.close(peer, fd); sys.close(vm, a); sys.close(vm, l2)
        ntfe.link_del(peer, "peer0.100")
        ntfe.link_del(vm, "veth0.100")
    end)

-- ---- the IP seats ------------------------------------------------------------

test("the inbound IP seat stands after conntrack and defragmentation, before the flow is confirmed",
    { spec = "PKM *ntfe-seat.ip-inbound-at-local-in-filter-priority" }, function(t)
        use({ Flow = { unconfirmed = { ["DstPort.Equal"] = 7406, Actions = { "DROP" } } } })
        local u = assert(ntfe.udp_bind(vm, net.addr, 7405))
        local seg = ntfe.udp(net.peer_addr, net.addr, 5405, 7405, string.rep("d", 40))
        local frags = {
            seat.ip4_raw_frame(net, ntfe.ipv4(net.peer_addr, net.addr, 17, 24,
                { id = 0x4405, frag = 0x2000 }) .. seg:sub(1, 24)),
            seat.ip4_raw_frame(net, ntfe.ipv4(net.peer_addr, net.addr, 17, #seg - 24,
                { id = 0x4405, frag = 3 }) .. seg:sub(25)),
        }
        local got
        local _, events = E:during(function()
            for _, f in ipairs(frags) do ntfe.send_frame(peer, wire, f) end
            got = ntfe.recv(vm, u, 300)
        end)
        local mine = {}
        for _, e in ipairs(events) do
            if e.protocol == ntfe.IPPROTO.UDP and e.src == net.peer_addr then mine[#mine + 1] = e end
        end
        t:assert_eq(count(mine, { seat = S.INGRESS }), 2, "ingress judged the two fragments as they came")
        local li = ntfe.matching(mine, { seat = S.LOCAL_IN, layer = L.PACKET })
        t:assert_eq(#li, 1, "LOCAL_IN judged one packet: defragmentation had run")
        t:assert_eq(li[1] and li[1].length, 20 + #seg, "the whole datagram")
        t:assert_eq(li[1] and li[1].flow_state, ntfe.FLOW_STATE.NEW, "already classified by conntrack")
        t:assert_eq(got and #got, 40, "and delivered whole")
        t:assert(find_flow(7405), "a flow the seat passed is confirmed after it")
        -- Conntrack confirms at the end of this hook: a flow dropped here
        -- never was.
        local l = assert(ntfe.tcp_listen(vm, net.addr, 7406))
        local _, why = ntfe.tcp_connect(peer, net.addr, 7406, 200)
        t:assert_eq(why, "timeout", "a flow the seat drops is dropped")
        t:assert_eq(find_flow(7406), nil, "and conntrack holds no entry for it: it was never confirmed")
        sys.close(vm, l)
        sys.close(vm, u)
        use()
    end)

test("the outbound IP seat stands after conntrack, with the sending socket attached, before confirmation",
    { spec = "PKM *ntfe-seat.ip-outbound-at-local-out-filter-priority" }, function(t)
        use({ Flow = { unconfirmed = { ["DstPort.Equal"] = 7408, Actions = { "DROP" } } } })
        local pl = assert(ntfe.tcp_listen(peer, net.peer_addr, 7407))
        local pl2 = assert(ntfe.tcp_listen(peer, net.peer_addr, 7408))
        local _, events = E:during(function()
            local fd = assert(ntfe.tcp_connect(vm, net.peer_addr, 7407))
            sys.close(vm, fd)
        end)
        local first = ntfe.matching(events, { seat = S.LOCAL_OUT, dst_port = 7407 })
        t:assert_eq(#first, 1, "the first packet was judged at LOCAL_OUT")
        if first[1] then
            t:assert_eq(first[1].flow_state, ntfe.FLOW_STATE.NEW, "its flow already classified by conntrack")
            t:assert_eq(first[1]["local"].kind, ntfe.LOCAL.PROGRAM,
                "and the program that sent it known, from the socket it carries")
        end
        t:assert(find_flow(7407), "a flow the seat passed is confirmed after it")
        local _, why = ntfe.tcp_connect(vm, net.peer_addr, 7408, 200)
        t:assert(why ~= nil, "a flow the seat drops does not connect")
        t:assert_eq(find_flow(7408), nil, "and was never confirmed")
        sys.close(peer, pl)
        sys.close(peer, pl2)
        use()
    end)

test("only the initial network namespace is instrumented",
    { spec = "PKM *ntfe-seat.only-init-net-instrumented" }, function(t)
        -- The Flow layer drops every flow it judges. The peer's own
        -- namespace has an interface (its end of the veth pair) and a
        -- loopback, neither of which is ours.
        use({ Flow = { all = { Actions = { "DROP" } } } })
        local pl = assert(ntfe.tcp_listen(peer, "127.0.0.1", 7409))
        local l = assert(ntfe.tcp_listen(vm, "127.0.0.1", 7409))
        local _, events = E:during(function()
            local fd, why = ntfe.tcp_connect(peer, "127.0.0.1", 7409, 300)
            t:assert(fd, "the peer's loopback connection is untouched: " .. tostring(why))
            if fd then sys.close(peer, fd) end
        end)
        t:assert_eq(#ntfe.matching(events, { dst_port = 7409 }), 0, "and nothing judged it")
        local _, why = ntfe.tcp_connect(vm, "127.0.0.1", 7409, 200)
        t:assert_eq(why, "timeout", "while the same connection here is dropped")
        sys.close(peer, pl)
        sys.close(vm, l)
        -- The peer's end of the pair: frames it sends cross its egress
        -- before ours, and only ours judges them.
        use()
        local u = assert(ntfe.udp_bind(vm, net.addr, 7410))
        local _, ev2 = E:during(function()
            ntfe.send_frame(peer, wire, seat.udp4_frame(net, 5410, 7410, "x"))
            ntfe.recv(vm, u, 300)
        end)
        local mine = ntfe.matching(ev2, { dst_port = 7410 })
        t:assert(#mine >= 1, "the datagram was judged here")
        t:assert_eq(count(mine, { seat = S.EGRESS }), 0, "and no egress seat ever saw it")
        for _, e in ipairs(mine) do
            t:assert_eq(e.ifindex, net.ifindex, "every judgment was on this namespace's device")
        end
        sys.close(vm, u)
    end)
