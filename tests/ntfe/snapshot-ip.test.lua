-- PKM §6.3 — the IP facts: IPv4's addresses, TTL, DSCP, fragment flag and
-- protocol, with the L4 header found past the options; IPv6's addresses,
-- hop limit and DSCP, and the bounded walk of its extension headers that
-- finds the fragment header and the protocol.
--
-- Every packet here is hand-built on the peer and judged at the VM's
-- ingress seat by RawPacket, where nothing has yet reassembled, checked
-- or dropped it: what the snapshot makes of the bytes is all there is.
--
-- Own VM: the policy is machine-wide state.

local ntfe = require("helpers.ntfe")
local H = require("helpers.ntfe_snapshot")

local vm = provium:vm("vntfesnip", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local peer, net = ntfe.peer(vm)
local E = ntfe.engine(vm, H.policy())
local wire = assert(ntfe.packet_socket(peer, net.peer))

local S, L = ntfe.SEAT, ntfe.LAYER
local NH = H.NEXTHDR
local VM6 = "fd00:9::1"

local function publish(t, probes)
    local s = E:replace(H.policy(probes))
    t:assert_eq(s.last_ingest_error, 0, "the probe policy is accepted")
end

-- Send an IPv6 packet from `src` with `nexthdr` and `payload`; return the
-- ingress RawPacket event for it and a description.
local function v6(src, nexthdr, payload, o)
    local frame = H.to_vm(net, ntfe.ETH_P.IPV6, H.ipv6(src, VM6, nexthdr, #payload, o) .. payload)
    local want = { addr_family = 6, src = ntfe.ip6(src) }
    local _, events = H.inject(E, peer, wire, frame, { { S.INGRESS, L.RAWPACKET, want } })
    local e = H.at(events, S.INGRESS, L.RAWPACKET, want)[1]
    return e, H.describe(events)
end

-- ---- IPv4 ----

test("IPv4 gives the addresses, TTL, DSCP, fragment flag and protocol, and the ports past the options",
    { spec = "PKM *ntfe-snapshot.ipv4-facts" }, function(t)
        publish(t, {
            RawPacket = {
                whole = {
                    ["SrcAddr.Equal"] = net.peer_addr, ["DstAddr.Equal"] = net.addr,
                    ["Ttl.Equal"] = 33, ["Dscp.Equal"] = 46, ["Fragment.Equal"] = 0,
                    ["Protocol.Equal"] = "udp", ["SrcPort.Equal"] = 5000, ["DstPort.Equal"] = 7401,
                },
                first = { ["Fragment.Equal"] = 1, ["DstPort.Equal"] = 7402 },
                later = { ["Fragment.Equal"] = 1, ["DstPort.Present"] = 0, ["Protocol.Equal"] = "udp" },
            },
        })
        -- Four bytes of options (NOP NOP NOP EOL): the UDP header starts at
        -- ihl * 4 = 24. Read at 20 it would give ports 257 and 256.
        local opts = "\1\1\1\0"
        local function datagram(dport, o)
            local udp = ntfe.udp(net.peer_addr, net.addr, 5000, dport, "payload!")
            return H.to_vm(net, ntfe.ETH_P.IP,
                H.ipv4_opts(net.peer_addr, net.addr, 17, #udp, opts, o) .. udp)
        end
        -- TOS 0xBA: DSCP 46 (EF) in the high six bits, ECN 2 in the low two.
        local _, events = H.inject(E, peer, wire, datagram(7401, { ttl = 33, tos = 0xBA }),
            { { S.INGRESS, L.RAWPACKET, { dst_port = 7401 } } })
        local e = H.at(events, S.INGRESS, L.RAWPACKET, { dst_port = 7401 })[1]
        t:assert(e, "the datagram was judged: " .. ntfe.describe(events))
        t:assert_eq(e.src_port, 5000, "its ports are read from past the options")
        t:assert_eq(e.attributed, "whole", "and every IPv4 fact is as the header says")

        -- MF set: a first fragment, its UDP header aboard.
        local _, ev2 = H.inject(E, peer, wire, datagram(7402, { frag = 0x2000, id = 0x4242 }),
            { { S.INGRESS, L.RAWPACKET, { dst_port = 7402 } } })
        local g2, d2 = H.attribution(ev2, S.INGRESS, L.RAWPACKET, { dst_port = 7402 })
        t:assert_eq(g2, "first", "IP_MF makes a fragment, whose first piece still has its ports: " .. d2)

        -- A non-zero offset: a later fragment, whose first bytes look like
        -- a UDP header and are not one.
        local _, ev3 = H.inject(E, peer, wire, datagram(7403, { frag = 0x0002, id = 0x4243 }),
            { { S.INGRESS, L.RAWPACKET, { protocol = 17, src = net.peer_addr } } })
        local e3 = H.at(ev3, S.INGRESS, L.RAWPACKET, { protocol = 17, src = net.peer_addr })[1]
        t:assert(e3, "the later fragment was judged: " .. ntfe.describe(ev3))
        t:assert_eq(e3.attributed, "later", "a fragment offset makes a fragment, with no L4 facts")
        t:assert_eq(e3.dst_port, 0, "its payload is not read as ports")
    end)

-- ---- IPv6 ----

test("IPv6 gives the addresses, hop limit and DSCP, and the walk skips each options or routing header by its length",
    { spec = "PKM *ntfe-snapshot.ipv6-extension-walk-bounded-eight-hops" }, function(t)
        local src = "fd00:9::a1"
        publish(t, {
            RawPacket = {
                v6 = {
                    ["SrcAddr.Equal"] = src, ["DstAddr.Equal"] = VM6, ["Ttl.Equal"] = 17,
                    ["Dscp.Equal"] = 46, ["Fragment.Equal"] = 0, ["Protocol.Equal"] = "udp",
                    ["SrcPort.Equal"] = 5000, ["DstPort.Equal"] = 7410,
                },
            },
        })
        -- Hop-by-hop (8 bytes), routing (16), destination options (24),
        -- then UDP: each skipped by (hdrlen + 1) * 8.
        local udp = H.udp6(src, VM6, 5000, 7410, "x")
        local chain = H.ext_opts(NH.ROUTING, 0) .. H.ext_routing(NH.DEST, 1)
            .. H.ext_opts(NH.UDP, 2) .. udp
        -- Traffic class 0xBA: DSCP 46.
        local e, d = v6(src, NH.HOP, chain, { hop = 17, tc = 0xBA })
        t:assert(e, "the packet was judged: " .. d)
        t:assert_eq(e.dst_port, 7410, "its ports are found behind three extension headers")
        t:assert_eq(e.attributed, "v6", "and every IPv6 fact is as the header says")
    end)

test("the extension-header walk is bounded at eight hops",
    { spec = "PKM *ntfe-snapshot.ipv6-extension-walk-bounded-eight-hops" }, function(t)
        publish(t, { RawPacket = { udp = { ["DstPort.Equal"] = 7411 } } })
        local function chain(src, n)
            local out = H.udp6(src, VM6, 5000, 7411, "x")
            for i = 1, n do out = H.ext_opts(i == 1 and NH.UDP or NH.DEST, 0) .. out end
            return out
        end
        -- Seven headers: the UDP header is the walk's eighth step.
        local e7, d7 = v6("fd00:9::a7", NH.DEST, chain("fd00:9::a7", 7))
        t:assert(e7, "the seven-header packet was judged: " .. d7)
        t:assert_eq(e7.attributed, "udp", "seven extension headers are walked to the ports")
        -- Eight: the walk ends before it reaches UDP.
        local e8, d8 = v6("fd00:9::a8", NH.DEST, chain("fd00:9::a8", 8))
        t:assert(e8, "the eight-header packet was judged: " .. d8)
        t:assert_eq(e8.attributed, "all", "eight are one too many: no ports are read")
        t:assert_eq(e8.dst_port, 0, "the event has none either")
    end)

test("a fragment header sets the fragment fact, and a first fragment keeps its L4 facts",
    { spec = "PKM *ntfe-snapshot.ipv6-fragment-header-sets-fragment" }, function(t)
        publish(t, { RawPacket = { first = { ["Fragment.Equal"] = 1, ["DstPort.Equal"] = 7412 } } })
        local src = "fd00:9::b1"
        local udp = H.udp6(src, VM6, 5000, 7412, "x")
        local e, d = v6(src, NH.FRAGMENT, H.ext_fragment(NH.UDP, 0, true) .. udp)
        t:assert(e, "the first fragment was judged: " .. d)
        t:assert_eq(e.attributed, "first", "as a fragment, its ports read")
    end)

test("a non-first IPv6 fragment ends the walk with no L4 facts",
    { spec = "PKM *ntfe-snapshot.ipv6-non-first-fragment-has-no-l4" }, function(t)
        publish(t, { RawPacket = { later = { ["Fragment.Equal"] = 1, ["DstPort.Present"] = 0 } } })
        local src = "fd00:9::b2"
        -- What follows the fragment header looks like a UDP header and is
        -- the middle of a datagram.
        local udp = H.udp6(src, VM6, 5000, 7413, "x")
        local e, d = v6(src, NH.FRAGMENT, H.ext_fragment(NH.UDP, 1, false) .. udp)
        t:assert(e, "the later fragment was judged: " .. d)
        t:assert_eq(e.attributed, "later", "as a fragment with no ports")
        t:assert_eq(e.dst_port, 0, "nothing past the fragment header is read")
    end)

test("the protocol is the header the walk stops at: an MLD report behind hop-by-hop reads icmpv6",
    { spec = "PKM *ntfe-snapshot.ipv6-protocol-is-walk-terminus" }, function(t)
        publish(t, {
            RawPacket = {
                mld = { ["Protocol.Equal"] = "icmpv6", ["IcmpType.Equal"] = 143, Priority = 20 },
                hop = { ["Protocol.Equal"] = 0, Priority = 10 },
            },
        })
        local src = "fd00:9::c1"
        local report = H.icmp6(src, "ff02::16", 143, 0, string.rep("\0", 4))
        local e, d = v6(src, NH.HOP, H.ext_opts(NH.ICMPV6, 0) .. report, { hop = 1 })
        t:assert(e, "the report was judged: " .. d)
        t:assert_eq(e.protocol, ntfe.IPPROTO.ICMPV6, "its protocol is ICMPv6")
        t:assert_eq(e.attributed, "mld", "and an MLD-report rule matches it")
    end)

test("a walk that stops early still names a header it stopped at, never hop-by-hop's 0",
    { spec = "PKM *ntfe-snapshot.ipv6-protocol-is-walk-terminus",
      tags = { "known-bug" },
      -- PEI-1304. snapshot_ipv6() sets
      -- snap->protocol only in the walk's default arm. A non-first fragment
      -- (fragment header, offset 1), a destination-options header cut short
      -- by the end of the packet, and a chain of eight options headers each
      -- leave the walk through another exit, and the bridge — protocol
      -- valid iff the family is — lifts the zeroed field as Protocol = 0,
      -- hop-by-hop's number, a header none of these packets stopped at.
      -- Observed: the event's protocol is 0 in all three, and a
      -- `Protocol.Equal = 0` rule matches them. The TRM's letter puts the
      -- protocol at the header the walk stops at (44, 60); the IPv4 side
      -- reports a later fragment's real protocol.
    }, function(t)
        publish(t, { RawPacket = { hop = { ["Protocol.Equal"] = 0 } } })
        local cases = {}
        do
            local src = "fd00:9::d1"
            cases[#cases + 1] = { src, NH.FRAGMENT,
                H.ext_fragment(NH.UDP, 1, false) .. H.udp6(src, VM6, 5000, 7414, "x"),
                "a non-first fragment" }
        end
        cases[#cases + 1] = { "fd00:9::d2", NH.DEST, "\17", "a truncated options header" }
        do
            local src = "fd00:9::d3"
            local out = H.udp6(src, VM6, 5000, 7415, "x")
            for i = 1, 8 do out = H.ext_opts(i == 1 and NH.UDP or NH.DEST, 0) .. out end
            cases[#cases + 1] = { src, NH.DEST, out, "an exhausted walk" }
        end
        -- Every case is sent before any is asserted, so a failure records
        -- what all three read.
        local seen, record = {}, {}
        for i, c in ipairs(cases) do
            local e, d = v6(c[1], c[2], c[3])
            seen[i] = e
            record[#record + 1] = c[4] .. " -> " .. (e and ("protocol " .. e.protocol .. ", " .. e.attributed) or d)
        end
        local all = table.concat(record, "; ")
        for i, c in ipairs(cases) do
            local e = seen[i]
            t:assert(e, c[4] .. " was judged: " .. all)
            t:assert(e.protocol ~= 0, c[4] .. " does not read as protocol 0: " .. all)
            t:assert_eq(e.attributed, "all", "and a protocol-0 rule does not match " .. c[4])
        end
    end)
