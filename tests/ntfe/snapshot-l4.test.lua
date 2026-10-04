-- PKM §6.3 — the L4 facts: ports for TCP, UDP and SCTP, the TCP flag
-- byte, ICMP and ICMPv6 type and code, and what a header too short to
-- read leaves behind — absent facts, never a fault.
--
-- Every packet is hand-built on the peer and judged at the VM's ingress
-- seat by RawPacket, before anything in the stack has checked it.
--
-- Own VM: the policy is machine-wide state.

local ntfe = require("helpers.ntfe")
local H = require("helpers.ntfe_snapshot")

local vm = provium:vm("vntfesnl4", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local peer, net = ntfe.peer(vm)
local E = ntfe.engine(vm, H.policy())
local wire = assert(ntfe.packet_socket(peer, net.peer))

local S, L = ntfe.SEAT, ntfe.LAYER
local VM6, PEER6 = "fd00:9::1", "fd00:9::2"

local function publish(t, probes)
    local s = E:replace(H.policy(probes))
    t:assert_eq(s.last_ingest_error, 0, "the probe policy is accepted")
end

-- An IPv4 packet of `protocol` carrying `l4` from the peer, as a frame;
-- `claimed` lies about how long the L4 part is.
local function ip4(protocol, l4, claimed)
    return H.to_vm(net, ntfe.ETH_P.IP,
        ntfe.ipv4(net.peer_addr, net.addr, protocol, claimed or #l4) .. l4)
end

-- Inject and return the ingress RawPacket event matching `want`.
local function judged(frame, want)
    local _, events = H.inject(E, peer, wire, frame, { { S.INGRESS, L.RAWPACKET, want } })
    return H.at(events, S.INGRESS, L.RAWPACKET, want)[1], H.describe(events)
end

test("TCP, UDP and SCTP have ports",
    { spec = "PKM *ntfe-snapshot.ports-for-tcp-udp-sctp" }, function(t)
        publish(t, {
            RawPacket = {
                tcp = { ["Protocol.Equal"] = "tcp", ["SrcPort.Equal"] = 5001, ["DstPort.Equal"] = 7501 },
                udp = { ["Protocol.Equal"] = "udp", ["SrcPort.Equal"] = 5002, ["DstPort.Equal"] = 7502 },
                sctp = { ["Protocol.Equal"] = "sctp", ["SrcPort.Equal"] = 5003, ["DstPort.Equal"] = 7503 },
            },
        })
        for _, c in ipairs({
            { "tcp", H.tcp_frame(net, 5001, 7501, ntfe.TCP.SYN), 7501 },
            { "udp", H.udp_frame(net, 5002, 7502), 7502 },
            { "sctp", ip4(ntfe.IPPROTO.SCTP, H.sctp(5003, 7503) .. string.rep("\0", 16)), 7503 },
        }) do
            local e, d = judged(c[2], { dst_port = c[3] })
            t:assert(e, c[1] .. " was judged: " .. d)
            t:assert_eq(e.attributed, c[1], "a " .. c[1] .. " header's ports are its source and destination")
        end
    end)

test("TcpFlags is FIN..CWR as the eight low bits of the TCP header's 13th byte",
    { spec = "PKM *ntfe-snapshot.tcp-flags-encoding" }, function(t)
        local names = { "FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR" }
        local probes = {
            every = { ["TcpFlags.Has"] = names, Priority = 30 },
            none = { ["TcpFlags.Hasnt"] = names, ["Protocol.Equal"] = "tcp", Priority = 20 },
        }
        for _, n in ipairs(names) do probes["flag-" .. n] = { ["TcpFlags.Has"] = n } end
        publish(t, { RawPacket = probes })
        for i, n in ipairs(names) do
            local port = 7510 + i
            local e, d = judged(H.tcp_frame(net, 5000, port, 1 << (i - 1)), { dst_port = port })
            t:assert(e, n .. " was judged: " .. d)
            t:assert_eq(e.attributed, "flag-" .. n, "bit " .. (i - 1) .. " of the flag byte is " .. n)
        end
        local e, d = judged(H.tcp_frame(net, 5000, 7519, 0xFF), { dst_port = 7519 })
        t:assert(e, "the all-flags segment was judged: " .. d)
        t:assert_eq(e.attributed, "every", "all eight bits are all eight flags")

        -- The 13th byte's neighbour holds the data offset and the NS bit;
        -- with every flag clear and NS set, no flag is read.
        local seg = ntfe.tcp(net.peer_addr, net.addr, 5000, 7520, 0)
        seg = seg:sub(1, 12) .. "\x51" .. seg:sub(14)
        local e2, d2 = judged(ip4(ntfe.IPPROTO.TCP, seg), { dst_port = 7520 })
        t:assert(e2, "the NS-only segment was judged: " .. d2)
        t:assert_eq(e2.attributed, "none", "the 12th byte's bits are not flags")
    end)

test("ICMP and ICMPv6 give their type and code",
    { spec = "PKM *ntfe-snapshot.icmp-type-and-code" }, function(t)
        publish(t, {
            RawPacket = {
                echo = { ["Protocol.Equal"] = "icmp", ["IcmpType.Equal"] = 8, ["IcmpCode.Equal"] = 0 },
                filtered = { ["Protocol.Equal"] = "icmp", ["IcmpType.Equal"] = 3, ["IcmpCode.Equal"] = 13 },
                echo6 = { ["Protocol.Equal"] = "icmpv6", ["IcmpType.Equal"] = 128, ["IcmpCode.Equal"] = 0 },
                unreach6 = { ["Protocol.Equal"] = "icmpv6", ["IcmpType.Equal"] = 1, ["IcmpCode.Equal"] = 4 },
            },
        })
        local v4 = { protocol = ntfe.IPPROTO.ICMP, src = net.peer_addr }
        local e1, d1 = judged(H.icmp_frame(net, 8, 0, 0x0b0b0001), v4)
        t:assert_eq(e1 and e1.attributed, "echo", "an echo request is type 8 code 0: " .. d1)
        local e2, d2 = judged(H.icmp_frame(net, 3, 13, 0, string.rep("\0", 28)), v4)
        t:assert_eq(e2 and e2.attributed, "filtered", "an admin-filtered unreachable is type 3 code 13: " .. d2)

        local v6 = { protocol = ntfe.IPPROTO.ICMPV6, src = ntfe.ip6(PEER6) }
        local function icmp6(ty, code)
            local msg = H.icmp6(PEER6, VM6, ty, code, string.rep("\0", 4))
            return H.to_vm(net, ntfe.ETH_P.IPV6, H.ipv6(PEER6, VM6, H.NEXTHDR.ICMPV6, #msg) .. msg)
        end
        local e3, d3 = judged(icmp6(128, 0), v6)
        t:assert_eq(e3 and e3.attributed, "echo6", "an ICMPv6 echo request is type 128 code 0: " .. d3)
        local e4, d4 = judged(icmp6(1, 4), v6)
        t:assert_eq(e4 and e4.attributed, "unreach6", "an ICMPv6 port unreachable is type 1 code 4: " .. d4)
    end)

test("a header too short to read yields absent facts, and the packet is judged on the rest",
    { spec = "PKM *ntfe-snapshot.truncated-headers-yield-absent-facts" }, function(t)
        publish(t, {
            RawPacket = {
                tcpcut = { ["Protocol.Equal"] = "tcp", ["SrcAddr.Equal"] = net.peer_addr,
                           ["DstPort.Present"] = 0, ["TcpFlags.Present"] = 0 },
                udpcut = { ["Protocol.Equal"] = "udp", ["DstPort.Present"] = 0 },
                icmpcut = { ["Protocol.Equal"] = "icmp", ["IcmpType.Present"] = 0 },
                ipcut = { ["EtherType.Equal"] = "ipv4", ["SrcAddr.Present"] = 0, ["Protocol.Present"] = 0 },
            },
        })
        -- Ten bytes of a twenty-byte TCP header, though the IP header
        -- claims the whole of it.
        local tcp = ntfe.tcp(net.peer_addr, net.addr, 5000, 7530, ntfe.TCP.SYN):sub(1, 10)
        local e1, d1 = judged(ip4(ntfe.IPPROTO.TCP, tcp, 20), { protocol = ntfe.IPPROTO.TCP, src = net.peer_addr })
        t:assert_eq(e1 and e1.attributed, "tcpcut",
            "a cut TCP header has no ports and no flags, and keeps its addresses: " .. d1)
        local e2, d2 = judged(ip4(ntfe.IPPROTO.UDP, "\x13\x88\x1d", 8), { protocol = ntfe.IPPROTO.UDP, src = net.peer_addr })
        t:assert_eq(e2 and e2.attributed, "udpcut", "a three-byte UDP header has no ports: " .. d2)
        local e3, d3 = judged(ip4(ntfe.IPPROTO.ICMP, "\8\0", 8), { protocol = ntfe.IPPROTO.ICMP, src = net.peer_addr })
        t:assert_eq(e3 and e3.attributed, "icmpcut",
            "an ICMP header of two bytes has no type, though its first byte is there: " .. d3)

        -- An IPv4 header of twelve bytes: nothing past the ethertype.
        local stub = H.to_vm(net, ntfe.ETH_P.IP, ntfe.ipv4(net.peer_addr, net.addr, 17, 0):sub(1, 12))
        local delta, events = H.inject(E, peer, wire, stub,
            { { S.INGRESS, L.RAWPACKET, { ether_type = ntfe.ETH_P.IP, addr_family = 0 } } })
        local got, d4 = H.attribution(events, S.INGRESS, L.RAWPACKET, { ether_type = ntfe.ETH_P.IP, addr_family = 0 })
        t:assert_eq(got, "ipcut", "a cut IP header leaves only the frame's facts, and is judged on them: " .. d4)
        t:assert(delta.parse_errors >= 1, "the unbuildable IP part is counted")
    end)
