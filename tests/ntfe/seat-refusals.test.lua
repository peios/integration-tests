-- PKM §6.2 — applying a verdict: PASS continues and then accepts, DROP
-- is a silent NF_DROP, REJECT is NF_DROP plus a refusal phrased by its
-- kind and the packet's protocol, for IPv4 and IPv6, from every seat;
-- how each seat delivers its refusal (to the wire peer from ingress,
-- through LOCAL_OUT from everywhere else); when a REJECT degrades to a
-- DROP; and the refusal law — NTFE does not judge its own refusals.
--
-- The peer is the other machine: everything it sees of a refusal is
-- read off its packet socket, so "a RST came back" means a RST frame
-- from the VM's MAC, not just an errno. Every refused port also has a
-- listener (or a bound socket) behind it, so an answer can only be
-- NTFE's: the stack itself has nothing to refuse.
--
-- Own VM: the policy is machine-wide state, and the tests change
-- sysctls (rp_filter) that would bleed into anything sharing it.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local seat = require("helpers.ntfe_seat")

local vm = provium:vm("vntfeseatrefuse", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local peer, net = ntfe.peer(vm)
local ADDR6, PEER6 = "fd09::1", "fd09::2"
assert(seat.addr6(vm, net.name, ADDR6))
assert(seat.addr6(peer, net.peer, PEER6))
local E = ntfe.engine(vm, seat.policy())
local wire = assert(ntfe.packet_socket(peer, net.peer))
local LO = assert(ntfe.if_index(vm, "lo"))

local REJECT, DROP, PASS = ntfe.VERDICT.REJECT, ntfe.VERDICT.DROP, ntfe.VERDICT.PASS

local function on_port(port, action, extra)
    local r = { ["DstPort.Equal"] = port, Actions = { action } }
    for k, v in pairs(extra or {}) do r[k] = v end
    return r
end

local function use(extra)
    local s = E:replace(seat.policy(extra))
    assert(s.last_ingest_error == 0, "the test policy ingests: " .. s.last_ingest_error)
end

local function is_rst(f) return f.tcp and f.tcp.flags & ntfe.TCP.RST ~= 0 end

-- The answer the VM put on the wire for one exchange, by family.
local function icmp_of(f, v6)
    if v6 then return f.icmp6 and { f.icmp6.type, f.icmp6.code } end
    return f.icmp and { f.icmp.type, f.icmp.code }
end

-- ---- applying a verdict ------------------------------------------------

test("PASS continues to the next layer and, after the last, the packet is accepted",
    { spec = "PKM *ntfe-seat.pass-continues-then-accept" }, function(t)
        use()
        local l = assert(ntfe.tcp_listen(vm, net.addr, 7010))
        local fd
        local _, events = E:during(function()
            fd = ntfe.tcp_connect(peer, net.addr, 7010)
        end)
        local a = ntfe.tcp_accept(vm, l, 200)
        t:assert(fd, "the peer's connection is made")
        t:assert(a, "and the VM's listener accepts it")
        local syn = {}
        for _, e in ipairs(events) do
            if e.dst_port == 7010 and #syn < 3 then syn[#syn + 1] = e end
        end
        t:assert_eq(seat.trail(syn), "ingress:RawPacket local_in:Packet local_in:Flow",
            "the SYN passed each layer in turn: " .. ntfe.describe(events))
        for _, e in ipairs(syn) do t:assert_eq(e.verdict, PASS, "every one a PASS") end
        if fd then sys.close(peer, fd) end
        if a then sys.close(vm, a) end
        sys.close(vm, l)
    end)

test("DROP is NF_DROP: the packet is discarded and nothing answers",
    { spec = "PKM *ntfe-seat.drop-is-nf-drop" }, function(t)
        use({ Flow = { dropped = on_port(7011, "DROP") } })
        local l = assert(ntfe.tcp_listen(vm, net.addr, 7011))
        seat.flush(peer, wire)
        local delta, events = E:during(function()
            local _, why = ntfe.tcp_connect(peer, net.addr, 7011, 300)
            t:assert_eq(why, "timeout", "the peer's connect hears nothing")
        end)
        t:assert(not ntfe.tcp_accept(vm, l, 50), "the listener behind the port never sees it")
        local answers = seat.from_vm(peer, net, wire, 100, function(f)
            return (f.tcp and f.tcp.sport == 7011) or f.icmp ~= nil
        end)
        t:assert_eq(#answers, 0, "no RST or ICMP went back on the wire")
        t:assert(#ntfe.matching(events, { attributed = "dropped", verdict = DROP }) >= 1,
            "the drop is the rule's: " .. ntfe.describe(events))
        t:assert_eq(delta.refusals_emitted, 0, "and no refusal was emitted")
        sys.close(vm, l)
    end)

test("REJECT is NF_DROP plus a refusal",
    { spec = "PKM *ntfe-seat.reject-is-drop-plus-refusal" }, function(t)
        use({ Flow = { refused = on_port(7012, "REJECT") } })
        local l = assert(ntfe.tcp_listen(vm, net.addr, 7012))
        local delta, events = E:during(function()
            local _, why = ntfe.tcp_connect(peer, net.addr, 7012, 500)
            t:assert_eq(why, sys.E.CONNREFUSED, "the peer is told no")
        end)
        t:assert(not ntfe.tcp_accept(vm, l, 50),
            "the packet itself was dropped: the listener behind the port never sees it")
        t:assert_eq(#ntfe.matching(events, { attributed = "refused", verdict = REJECT }), 1,
            "one REJECT verdict: " .. ntfe.describe(events))
        t:assert_eq(delta.refusals_emitted, 1, "and one refusal sent")
        sys.close(vm, l)
    end)

-- ---- the kinds -----------------------------------------------------------

-- One refused exchange from the peer, `proto` "tcp" or "udp", over
-- `family` 4 or 6; returns the answer frames the VM put on the wire.
local function refuse_from_peer(t, proto, v6, port)
    local addr = v6 and ADDR6 or net.addr
    local sink
    if proto == "tcp" then sink = assert(ntfe.tcp_listen(vm, addr, port))
    else sink = assert(ntfe.udp_bind(vm, addr, port)) end
    seat.flush(peer, wire)
    local delta = E:during(function()
        if proto == "tcp" then
            ntfe.tcp_connect(peer, addr, port, 300)
        else
            local u = assert(ntfe.udp_connect(peer, addr, port))
            ntfe.send(peer, u, "refuse me")
            ntfe.recv(peer, u, 200)
            sys.close(peer, u)
        end
    end)
    sys.close(vm, sink)
    t:assert_eq(delta.refusals_emitted, 1, proto .. "/v" .. (v6 and 6 or 4) .. " was refused once")
    return seat.from_vm(peer, net, wire, 100, function(f)
        return (f.tcp and f.tcp.sport == port) or f.icmp or (f.icmp6 and f.icmp6.type < 128)
    end)
end

test("the Refused kind is a RST for TCP and port-unreachable otherwise, in IPv4 and IPv6",
    { spec = "PKM *ntfe-seat.refused-kind-rst-or-port-unreachable" }, function(t)
        use({ Flow = {
            tcp = on_port(7013, "REJECT(Refused)"),
            udp = on_port(7014, "REJECT"), -- the default kind
        } })
        for _, v6 in ipairs({ false, true }) do
            local tag = v6 and "IPv6" or "IPv4"
            local tcp = refuse_from_peer(t, "tcp", v6, 7013)
            t:assert(#tcp >= 1 and is_rst(tcp[1]), tag .. " TCP is answered with a RST")
            local udp = refuse_from_peer(t, "udp", v6, 7014)
            local got = udp[1] and icmp_of(udp[1], v6)
            local want = v6 and { 1, 4 } or { 3, 3 }
            t:assert(got and got[1] == want[1] and got[2] == want[2],
                string.format("%s UDP with port-unreachable (%d/%d), got %s", tag,
                    want[1], want[2], got and (got[1] .. "/" .. got[2]) or "nothing"))
        end
    end)

test("the Prohibited kind is ICMP admin-prohibited for every protocol, in IPv4 and IPv6",
    { spec = "PKM *ntfe-seat.prohibited-kind-admin-filtered" }, function(t)
        use({ Flow = {
            tcp = on_port(7015, "REJECT(Prohibited)"),
            udp = on_port(7016, "REJECT(Prohibited)"),
        } })
        for _, v6 in ipairs({ false, true }) do
            local want = v6 and { 1, 1 } or { 3, 13 }
            for _, c in ipairs({ { "tcp", 7015 }, { "udp", 7016 } }) do
                local frames = refuse_from_peer(t, c[1], v6, c[2])
                local got = frames[1] and icmp_of(frames[1], v6)
                t:assert(got and got[1] == want[1] and got[2] == want[2],
                    string.format("%s over IPv%d is answered %d/%d, got %s", c[1],
                        v6 and 6 or 4, want[1], want[2],
                        got and (got[1] .. "/" .. got[2]) or "nothing"))
                t:assert(not (frames[1] and is_rst(frames[1])), "and never with a RST")
            end
        end
    end)

-- ---- every seat ----------------------------------------------------------

-- Refuse one connection per (layer, seat) case in each family, and say
-- where it was judged and that the connecting socket was told.
local function refuse_at_each(t, cases)
    local listen4 = assert(ntfe.tcp_listen(peer, net.peer_addr, 7021))
    local listen6 = assert(ntfe.tcp_listen(peer, PEER6, 7021))
    local mine4 = assert(ntfe.tcp_listen(vm, net.addr, 7020))
    local mine6 = assert(ntfe.tcp_listen(vm, ADDR6, 7020))
    local ok, err = pcall(function()
        for _, c in ipairs(cases) do
            local layer, want_seat, want_layer, inbound = c[1], c[2], c[3], c[4]
            local port = inbound and 7020 or 7021
            use({ [layer] = { refused = on_port(port, "REJECT") } })
            for _, v6 in ipairs({ false, true }) do
                local where = string.format("%s at %s over IPv%d", layer,
                    seat.SEAT_NAME[want_seat], v6 and 6 or 4)
                local delta, events = E:during(function()
                    local fd, why
                    if inbound then
                        fd, why = ntfe.tcp_connect(peer, v6 and ADDR6 or net.addr, port, 500)
                    else
                        fd, why = ntfe.tcp_connect(vm, v6 and PEER6 or net.peer_addr, port, 500)
                    end
                    t:assert_eq(why, sys.E.CONNREFUSED, where .. " refuses the connection")
                    if fd then sys.close(inbound and peer or vm, fd) end
                end)
                local judged = ntfe.matching(events, { attributed = "refused", verdict = REJECT })
                t:assert(#judged >= 1 and judged[1].seat == want_seat and judged[1].layer == want_layer,
                    where .. " is where it was judged: " .. ntfe.describe(judged))
                t:assert(delta.refusals_emitted >= 1, where .. " sent the refusal")
                t:assert_eq(delta.reject_degraded, 0, where .. " did not degrade")
            end
        end
    end)
    for _, fd in ipairs({ listen4, listen6 }) do sys.close(peer, fd) end
    for _, fd in ipairs({ mine4, mine6 }) do sys.close(vm, fd) end
    if not ok then error(err, 0) end
end

test("every seat can refuse IP traffic, in both families: ingress, LOCAL_IN and LOCAL_OUT",
    { spec = "PKM *ntfe-seat.every-seat-can-refuse-ip" }, function(t)
        refuse_at_each(t, {
            -- inbound: the peer connects to us on 7020
            { "RawPacket", ntfe.SEAT.INGRESS, ntfe.LAYER.RAWPACKET, true },
            { "Packet", ntfe.SEAT.LOCAL_IN, ntfe.LAYER.PACKET, true },
            { "Flow", ntfe.SEAT.LOCAL_IN, ntfe.LAYER.FLOW, true },
            -- outbound: we connect to the peer on 7021
            { "Flow", ntfe.SEAT.LOCAL_OUT, ntfe.LAYER.FLOW, false },
        })
    end)

test("every seat can refuse IP traffic, in both families: egress",
    { spec = "PKM *ntfe-seat.every-seat-can-refuse-ip",
      tags = { "known-bug" },
      -- PEI-1300. At the egress seat
      -- skb->data is at the Ethernet header, but the frame-less reject
      -- builders read the transport header at ip_hdrlen() from skb->data,
      -- so the answer quotes the wrong bytes. Seen live by tapping lo: a
      -- Packet-layer REJECT of an outbound SYN to port 7024 forges a RST
      -- from port 16390 to port 16384 (0x4006, 0x4000: the IP header's
      -- frag/TTL/protocol words), which no socket owns; the connect
      -- times out with refusals_emitted +1. A UDP send refused there
      -- puts nothing on loopback at all and the socket never fails.
      -- Upstream, nft_reject_netdev registers for NF_NETDEV_INGRESS
      -- only, so these builders were never run at an egress hook there.
    }, function(t)
        refuse_at_each(t, {
            { "Packet", ntfe.SEAT.EGRESS, ntfe.LAYER.PACKET, false },
            { "RawPacket", ntfe.SEAT.EGRESS, ntfe.LAYER.RAWPACKET, false },
        })
    end)

-- ---- delivery --------------------------------------------------------------

test("from the ingress seat the refusal goes straight back to the wire peer, its frame's MACs swapped",
    { spec = "PKM *ntfe-seat.ingress-refusal-sent-to-wire-peer" }, function(t)
        use({ RawPacket = { refused = on_port(7022, "REJECT") } })
        local l = assert(ntfe.tcp_listen(vm, net.addr, 7022))
        seat.flush(peer, wire)
        local delta, events = E:during(function()
            local _, why = ntfe.tcp_connect(peer, net.addr, 7022, 500)
            t:assert_eq(why, sys.E.CONNREFUSED, "the peer is refused")
        end)
        local rst = seat.from_vm(peer, net, wire, 100, is_rst)
        t:assert(#rst >= 1, "a RST frame came back on the wire")
        if rst[1] then
            t:assert_eq(rst[1].dst, net.peer_mac, "addressed to the MAC the SYN came from")
            t:assert_eq(rst[1].src, net.mac, "from the MAC the SYN was sent to")
            t:assert_eq(rst[1].ip.src, net.addr, "answering for the address the SYN was for")
            t:assert_eq(rst[1].tcp.sport, 7022, "and its port")
        end
        -- Straight onto the device: the only hook it crosses after
        -- leaving the engine is the device's own egress seat.
        t:assert_eq(delta.refusals_bypassed, 1, "it crossed one seat on its way out, not the IP ones")
        local ip_seats = 0
        for _, e in ipairs(events) do
            if e.src_port == 7022 and (e.seat == ntfe.SEAT.LOCAL_OUT or e.seat == ntfe.SEAT.LOCAL_IN) then
                ip_seats = ip_seats + 1
            end
        end
        t:assert_eq(ip_seats, 0, "and nothing of it came near an IP seat")
        sys.close(vm, l)
    end)

test("from every other seat the refusal is routed and sent through LOCAL_OUT",
    { spec = "PKM *ntfe-seat.non-ingress-refusal-routed-through-local-out" }, function(t)
        local l = assert(ntfe.tcp_listen(vm, net.addr, 7023))
        local pl = assert(ntfe.tcp_listen(peer, net.peer_addr, 7024))
        -- Inbound, from LOCAL_IN: out through LOCAL_OUT and the device's
        -- egress seat, as any locally generated packet goes.
        use({ Flow = { refused = on_port(7023, "REJECT"), out = on_port(7024, "REJECT") } })
        local delta = E:during(function()
            ntfe.tcp_connect(peer, net.addr, 7023, 500)
        end)
        t:assert_eq(delta.refusals_emitted, 1, "the inbound refusal was sent")
        t:assert_eq(delta.refusals_bypassed, 2, "across LOCAL_OUT and the egress seat")
        -- Outbound, from LOCAL_OUT: routed to ourselves, it crosses
        -- LOCAL_OUT, loopback's egress and ingress seats, and LOCAL_IN.
        delta = E:during(function()
            ntfe.tcp_connect(vm, net.peer_addr, 7024, 500)
        end)
        t:assert_eq(delta.refusals_emitted, 1, "the outbound refusal was sent")
        t:assert_eq(delta.refusals_bypassed, 4,
            "across LOCAL_OUT, loopback's two device seats and LOCAL_IN")
        -- And from egress, the same routed path. (What it carries from
        -- there is wrong — see the egress known-bug above — but the route
        -- it takes is the one this statement is about.)
        use({ Packet = { out = on_port(7024, "REJECT") } })
        delta = E:during(function()
            ntfe.tcp_connect(vm, net.peer_addr, 7024, 100)
        end)
        t:assert_eq(delta.refusals_emitted, 1, "the egress refusal was sent")
        t:assert_eq(delta.refusals_bypassed, 4, "by the same route")
        sys.close(vm, l)
        sys.close(peer, pl)
    end)

test("an inbound refusal is routed out to the peer with our address as its source",
    { spec = "PKM *ntfe-seat.inbound-refusal-routed-to-peer" }, function(t)
        use({ Packet = { refused = on_port(7025, "REJECT"), prohibited = on_port(7026, "REJECT(Prohibited)") } })
        local l = assert(ntfe.tcp_listen(vm, net.addr, 7025))
        local u = assert(ntfe.udp_bind(vm, net.addr, 7026))
        seat.flush(peer, wire)
        ntfe.tcp_connect(peer, net.addr, 7025, 500)
        local rst = seat.from_vm(peer, net, wire, 100, is_rst)
        t:assert(#rst >= 1, "the RST reached the peer on the wire")
        if rst[1] then
            t:assert_eq(rst[1].ip.src, net.addr, "from our address")
            t:assert_eq(rst[1].ip.dst, net.peer_addr, "to the peer's")
            t:assert_eq(rst[1].dst, net.peer_mac, "delivered to the peer's MAC by the route")
        end
        local pu = assert(ntfe.udp_connect(peer, net.addr, 7026))
        ntfe.send(peer, pu, "x")
        local icmp = seat.from_vm(peer, net, wire, 100, function(f) return f.icmp end)
        t:assert(#icmp >= 1 and icmp[1].ip.src == net.addr and icmp[1].ip.dst == net.peer_addr,
            "an ICMP answer is routed the same way")
        sys.close(peer, pu)
        sys.close(vm, u)
        sys.close(vm, l)
    end)

test("an outbound refusal fails the local socket at once, and nothing reaches the wire",
    { spec = "PKM *ntfe-seat.outbound-refusal-fails-local-socket-at-once" }, function(t)
        use({ Flow = {
            refused = on_port(7027, "REJECT"),
            prohibited = on_port(7028, "REJECT(Prohibited)"),
        } })
        local l1 = assert(ntfe.tcp_listen(peer, "0.0.0.0", 7027))
        local l2 = assert(ntfe.tcp_listen(peer, "0.0.0.0", 7028))
        local l6 = assert(ntfe.tcp_listen(peer, PEER6, 7027))
        seat.flush(peer, wire)
        -- 100 ms is far short of a SYN retransmission: only an answer
        -- delivered with the refused packet itself can fail the connect.
        for _, c in ipairs({
            { net.peer_addr, 7027, sys.E.CONNREFUSED, "a Refused TCP connect" },
            { PEER6, 7027, sys.E.CONNREFUSED, "a Refused TCP connect over IPv6" },
            { net.peer_addr, 7028, sys.E.HOSTUNREACH, "a Prohibited TCP connect" },
        }) do
            local _, why = ntfe.tcp_connect(vm, c[1], c[2], 100)
            t:assert_eq(why, c[3], c[4] .. " fails at once: " .. tostring(why))
        end
        for _, c in ipairs({
            { net.peer_addr, 7027, sys.E.CONNREFUSED, "a Refused UDP send" },
            { PEER6, 7027, sys.E.CONNREFUSED, "a Refused UDP send over IPv6" },
            { net.peer_addr, 7028, sys.E.HOSTUNREACH, "a Prohibited UDP send" },
        }) do
            local u = assert(ntfe.udp_connect(vm, c[1], c[2]))
            ntfe.send(vm, u, "x")
            local _, why = ntfe.recv(vm, u, 100)
            t:assert_eq(why, c[3], c[4] .. " fails the socket at once: " .. tostring(why))
            sys.close(vm, u)
        end
        local out = seat.from_vm(peer, net, wire, 100, function(f)
            return f.tcp or f.udp
        end)
        t:assert_eq(#out, 0, "and the refused packets never left the machine")
        t:assert(not ntfe.tcp_accept(peer, l1, 20), "the peer's listener saw nothing")
        for _, fd in ipairs({ l1, l2, l6 }) do sys.close(peer, fd) end
    end)

test("an outbound IPv6 Prohibited refusal fails a TCP connect at once",
    { spec = "PKM *ntfe-seat.outbound-refusal-fails-local-socket-at-once",
      tags = { "known-bug" },
      -- PEI-1307. Seen live: a
      -- 100 ms connect times out with refusals_emitted +1; a 2.5 s one
      -- fails EACCES with refusals_emitted +2, i.e. only at the first SYN
      -- retransmission's refusal. The IPv4 twin (ICMP 3/13) fails at
      -- once, and a Refused IPv6 connect (a RST) does too. Consistent
      -- with the first ICMPv6 error reaching tcp_v6_err while connect()
      -- still owns the socket and being filed as a soft error — a
      -- hypothesis, since the IPv4 path has the same owned-socket check.
    }, function(t)
        use({ Flow = { prohibited = on_port(7029, "REJECT(Prohibited)") } })
        local l = assert(ntfe.tcp_listen(peer, PEER6, 7029))
        local _, why = ntfe.tcp_connect(vm, PEER6, 7029, 100)
        t:assert(why ~= "timeout", "the connect fails before a SYN retransmission: " .. tostring(why))
        sys.close(peer, l)
    end)

test("an outbound IPv6 Prohibited refusal fails the socket with ECONNREFUSED or EHOSTUNREACH",
    { spec = "PKM *ntfe-seat.outbound-refusal-fails-local-socket-at-once",
      tags = { "known-bug" },
      -- PEI-1311 (TRM). ICMPv6 type 1 code 1
      -- maps to EACCES in icmpv6_err_convert, so a Prohibited refusal
      -- over IPv6 fails the socket with EACCES, not either errno the TRM
      -- names; the code plainly intends the kernel's own mapping, so the
      -- TRM's list is the thing to widen. Seen live on a UDP send.
    }, function(t)
        use({ Flow = { prohibited = on_port(7029, "REJECT(Prohibited)") } })
        local u = assert(ntfe.udp_connect(vm, PEER6, 7029))
        ntfe.send(vm, u, "x")
        local _, why = ntfe.recv(vm, u, 200)
        t:assert(why == sys.E.CONNREFUSED or why == sys.E.HOSTUNREACH,
            "the socket fails with one of the two: " .. tostring(why))
        sys.close(vm, u)
    end)

test("the forged answer arrives over loopback with its route, so source validation never sees it",
    { spec = "PKM *ntfe-seat.outbound-refusal-skips-source-validation" }, function(t)
        use({ Flow = { refused = on_port(7030, "REJECT") } })
        local l = assert(ntfe.tcp_listen(peer, net.peer_addr, 7030))
        local sink = assert(ntfe.udp_bind(vm, net.addr, 7031))
        local lo = assert(ntfe.packet_socket(vm, "lo"))
        local paths = { "all", "default", "lo", net.name }
        for _, p in ipairs(paths) do
            assert(seat.write_file(vm, "/proc/sys/net/ipv4/conf/" .. p .. "/rp_filter", 1))
        end
        -- The control: a packet with the peer's address as its source,
        -- put on loopback without a route, is a martian and is dropped.
        local forged = string.rep("\0", 12) .. string.pack(">I2", ntfe.ETH_P.IP)
            .. ntfe.ipv4(net.peer_addr, net.addr, ntfe.IPPROTO.UDP, 9)
            .. ntfe.udp(net.peer_addr, net.addr, 5555, 7031, "x")
        ntfe.send(vm, lo, forged)
        local got = ntfe.recv(vm, sink, 200)
        -- The refusal carries the same foreign source over the same device.
        local _, why = ntfe.tcp_connect(vm, net.peer_addr, 7030, 100)
        for _, p in ipairs(paths) do
            seat.write_file(vm, "/proc/sys/net/ipv4/conf/" .. p .. "/rp_filter", 0)
        end
        t:assert_eq(got, nil, "strict source validation drops the peer's address arriving on loopback")
        t:assert_eq(why, sys.E.CONNREFUSED, "yet the refusal arriving the same way fails the connect at once")
        sys.close(vm, lo)
        sys.close(vm, sink)
        sys.close(peer, l)
    end)

test("refusals sent are counted in refusals_emitted",
    { spec = "PKM *ntfe-seat.refusals-sent-counted" }, function(t)
        use({ Flow = { refused = on_port(7032, "REJECT") } })
        local l = assert(ntfe.tcp_listen(vm, net.addr, 7032))
        local u = assert(ntfe.udp_bind(vm, net.addr, 7032))
        local delta = E:during(function()
            ntfe.tcp_connect(peer, net.addr, 7032, 300)
            ntfe.tcp_connect(peer, ADDR6, 7032, 300)
            local pu = assert(ntfe.udp_connect(peer, net.addr, 7032))
            ntfe.send(peer, pu, "x")
            ntfe.recv(peer, pu, 100)
            sys.close(peer, pu)
        end)
        t:assert_eq(delta.refusals_emitted, 3, "three refusals, three counted")
        t:assert_eq(delta.verdict_reject, 3, "one per REJECT")
        sys.close(vm, u)
        sys.close(vm, l)
    end)

-- ---- degradation -----------------------------------------------------------

test("a REJECT with nothing to send degrades to DROP: counted, flagged, its kind still named",
    { spec = "PKM *ntfe-seat.reject-degrades-to-drop-when-nothing-to-send" }, function(t)
        -- Each case is told apart by a TTL (or a source MAC, for ARP) so
        -- the peer's own housekeeping can never match. No route to
        -- reason from and a failed allocation have no guest-side trigger:
        -- every packet that reaches a seat after routing has a route, and
        -- the kernel has no fault injection.
        local FAKE_MAC = "\x02\x00\x00\x00\x00\x99"
        use({
            RawPacket = {
                arp = { ["SrcMac.Equal"] = "02:00:00:00:00:99",
                        Actions = { "REJECT(Prohibited)" } },
                ["bcast-mac"] = { ["Ttl.Equal"] = 41, Actions = { "REJECT" } },
                ["frag-first"] = { ["Ttl.Equal"] = 42, Actions = { "REJECT" } },
                ["frag-later"] = { ["Ttl.Equal"] = 43, Actions = { "REJECT(Prohibited)" } },
                ["bad-csum"] = { ["Ttl.Equal"] = 44, Actions = { "REJECT" } },
                ["a-reset"] = { ["Ttl.Equal"] = 45, Actions = { "REJECT" } },
                ["an-unreach"] = { ["Ttl.Equal"] = 46, Actions = { "REJECT" } },
            },
            Packet = {
                ["bcast-ip"] = { ["Ttl.Equal"] = 47, Actions = { "REJECT" } },
                multicast = { ["Ttl.Equal"] = 48, Actions = { "REJECT(Prohibited)" } },
            },
        })
        local sink = assert(ntfe.udp_bind(vm, "0.0.0.0", 7033))
        local seg = ntfe.udp(net.peer_addr, net.addr, 5000, 7033, string.rep("f", 40))
        local quoted = ntfe.ipv4(net.addr, net.peer_addr, 17, 9) .. ntfe.udp(net.addr, net.peer_addr, 7033, 5000, "x")
        local cases = {
            { "arp", ntfe.REJECT.PROHIBITED, "a non-IP frame",
              ntfe.eth(ntfe.MAC_BROADCAST, FAKE_MAC, ntfe.ETH_P.ARP)
                .. ntfe.arp_request(FAKE_MAC, net.peer_addr, net.addr) },
            { "bcast-mac", ntfe.REJECT.REFUSED, "a frame to the broadcast MAC",
              seat.udp4_frame(net, 5000, 7033, "x", { dst_mac = ntfe.MAC_BROADCAST, ip = { ttl = 41 } }) },
            { "frag-first", ntfe.REJECT.REFUSED, "a first fragment",
              seat.ip4_raw_frame(net, ntfe.ipv4(net.peer_addr, net.addr, 17, 24,
                  { id = 9, frag = 0x2000, ttl = 42 }) .. seg:sub(1, 24)) },
            { "frag-later", ntfe.REJECT.PROHIBITED, "a later fragment",
              seat.ip4_raw_frame(net, ntfe.ipv4(net.peer_addr, net.addr, 17, 24,
                  { id = 10, frag = 3, ttl = 43 }) .. seg:sub(25)) },
            { "bad-csum", ntfe.REJECT.REFUSED, "a datagram that fails its checksum",
              seat.udp4_frame(net, 5000, 7033, "x", { bad_csum = true, ip = { ttl = 44 } }) },
            { "a-reset", ntfe.REJECT.REFUSED, "a RST (a refusal of a refusal)",
              seat.tcp4_frame(net, 5000, 7033, ntfe.TCP.RST | ntfe.TCP.ACK, { ip = { ttl = 45 } }) },
            { "an-unreach", ntfe.REJECT.REFUSED, "a port-unreachable (a refusal of a refusal)",
              seat.ip4_raw_frame(net, ntfe.ipv4(net.peer_addr, net.addr, 1, 8 + #quoted, { ttl = 46 })
                  .. ntfe.icmp(3, 3, 0, quoted)) },
            { "bcast-ip", ntfe.REJECT.REFUSED, "a datagram to the subnet broadcast",
              ntfe.eth(ntfe.MAC_BROADCAST, net.peer_mac, ntfe.ETH_P.IP)
                .. ntfe.ipv4(net.peer_addr, "10.9.0.255", 17, 9, { ttl = 47 })
                .. ntfe.udp(net.peer_addr, "10.9.0.255", 5000, 7033, "x") },
            { "multicast", ntfe.REJECT.PROHIBITED, "a datagram to a multicast group",
              ntfe.eth("\x01\x00\x5e\x00\x00\x01", net.peer_mac, ntfe.ETH_P.IP)
                .. ntfe.ipv4(net.peer_addr, "224.0.0.1", 17, 9, { ttl = 48 })
                .. ntfe.udp(net.peer_addr, "224.0.0.1", 5000, 7033, "x") },
        }
        for _, c in ipairs(cases) do
            local name, kind, what, frame = c[1], c[2], c[3], c[4]
            seat.flush(peer, wire)
            local delta, events = E:during(function()
                ntfe.send_frame(peer, wire, frame)
                ntfe.frames(peer, wire, 100)
            end)
            local ev = ntfe.matching(events, { attributed = name })
            t:assert_eq(#ev, 1, what .. " was judged once: " .. ntfe.describe(events))
            if ev[1] then
                t:assert_eq(ev[1].verdict, REJECT, what .. ": the event still says REJECT")
                t:assert_eq(ev[1].reject_kind, kind, what .. ": and names the kind")
                t:assert(ev[1].reject_degraded, what .. ": flagged REJECT_DEGRADED")
            end
            t:assert_eq(delta.reject_degraded, 1, what .. ": counted in reject_degraded")
            t:assert_eq(delta.refusals_emitted, 0, what .. ": and nothing was sent")
        end
        sys.close(vm, sink)
    end)

-- ---- the refusal law -------------------------------------------------------

test("a refusal is attached to the flow it refuses and marked, so conntrack files it and NTFE waves it through",
    { spec = "PKM *ntfe-seat.refusal-attached-to-flow-and-marked" }, function(t)
        -- The conntrack statistics count ICMP errors that conntrack had to
        -- classify and could not place. The control: an orphan
        -- port-unreachable from the peer is counted. A refusal NTFE sent
        -- about a flow not yet confirmed would be just such an orphan,
        -- were it not attached to that flow already.
        local function icmp_errors()
            local fd = assert(sys.open(vm, "/proc/net/stat/nf_conntrack"))
            local text = sys.read(vm, fd, 8192)
            sys.close(vm, fd)
            local header, sum, col = nil, 0, nil
            for line in text:gmatch("[^\n]+") do
                if not header then
                    header = line
                    local i = 0
                    for name in line:gmatch("%S+") do
                        i = i + 1
                        if name == "icmp_error" then col = i end
                    end
                else
                    local i = 0
                    for v in line:gmatch("%S+") do
                        i = i + 1
                        if i == col then sum = sum + tonumber(v, 16) end
                    end
                end
            end
            assert(col, "an icmp_error column: " .. tostring(header))
            return sum
        end
        use({ Packet = { refused = on_port(7034, "REJECT") } })
        local u = assert(ntfe.udp_bind(vm, net.addr, 7034))
        local before = icmp_errors()
        local quoted = ntfe.ipv4(net.addr, net.peer_addr, 17, 9)
            .. ntfe.udp(net.addr, net.peer_addr, 4444, 4445, "x")
        ntfe.send_frame(peer, wire, seat.ip4_raw_frame(net,
            ntfe.ipv4(net.peer_addr, net.addr, 1, 8 + #quoted) .. ntfe.icmp(3, 3, 0, quoted)))
        ntfe.frames(peer, wire, 100)
        local after_orphan = icmp_errors()
        local delta, events = E:during(function()
            local pu = assert(ntfe.udp_connect(peer, net.addr, 7034))
            ntfe.send(peer, pu, "x")
            local _, why = ntfe.recv(peer, pu, 200)
            t:assert_eq(why, sys.E.CONNREFUSED, "the peer's datagram was refused")
            sys.close(peer, pu)
        end)
        t:assert_eq(after_orphan, before + 1, "an orphan ICMP error is one conntrack cannot place")
        t:assert_eq(icmp_errors(), after_orphan,
            "the refusal about an unconfirmed flow is not: conntrack already had it filed")
        t:assert_eq(delta.refusals_emitted, 1, "one refusal")
        t:assert_eq(delta.refusals_bypassed, 2, "marked: LOCAL_OUT and the egress seat waved it through")
        local icmp = ntfe.matching(events, { protocol = ntfe.IPPROTO.ICMP })
        t:assert_eq(#icmp, 0, "and no seat judged it: " .. ntfe.describe(icmp))
        sys.close(vm, u)
    end)

test("every hook waves NTFE's own refusals through unjudged, counting them",
    { spec = "PKM *ntfe-seat.refusals-bypass-every-hook" }, function(t)
        -- Rules that drop every RST and every ICMP error in every layer,
        -- in both directions: if any seat judged the refusals they could
        -- not arrive.
        local kill = {
            rst = { ["TcpFlags.Has"] = "RST", Actions = { "DROP" } },
            icmp = { ["Protocol.Equal"] = "icmp", Actions = { "DROP" } },
        }
        use({ RawPacket = kill, Packet = kill, Flow = {
            refused = on_port(7035, "REJECT"), out = on_port(7036, "REJECT"),
            icmp = { ["Protocol.Equal"] = "icmp", Actions = { "DROP" } },
        } })
        local l = assert(ntfe.tcp_listen(vm, net.addr, 7035))
        local pl = assert(ntfe.tcp_listen(peer, net.peer_addr, 7036))
        local delta, events = E:during(function()
            local _, why = ntfe.tcp_connect(peer, net.addr, 7035, 500)
            t:assert_eq(why, sys.E.CONNREFUSED,
                "an inbound refusal crosses LOCAL_OUT and egress despite rules that drop it")
            _, why = ntfe.tcp_connect(vm, net.peer_addr, 7036, 100)
            t:assert_eq(why, sys.E.CONNREFUSED,
                "an outbound one crosses loopback's seats and LOCAL_IN the same way")
        end)
        t:assert_eq(delta.refusals_emitted, 2, "two refusals")
        t:assert_eq(delta.refusals_bypassed, 6, "every hook they crossed counted a bypass")
        local judged = {}
        for _, e in ipairs(events) do
            if e.attributed == "rst" or e.attributed == "icmp" or e.ifindex == LO then
                judged[#judged + 1] = e
            end
        end
        t:assert_eq(#judged, 0, "and none of them judged one: " .. ntfe.describe(judged))
        sys.close(vm, l)
        sys.close(peer, pl)
    end)
