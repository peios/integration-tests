-- The fact snapshot (PKM §6.3), seen from outside: frames hand-built on
-- the peer, and probe rules that say which facts a seat was given.
--
-- A fact is seen by a rule that conditions on it. `policy` lays a
-- PASS-everything baseline (`all`) in every layer and adds the probes
-- above it at a higher priority, so a traversal is attributed to a probe
-- exactly when the probe's condition held there.
--
-- The frame builders cover what helpers/ntfe does not: IPv4 options,
-- IPv6 and its extension headers, SCTP, 802.1Q tags.

local ntfe = require("helpers.ntfe")

local M = {}

M.PROBE_PRIORITY = 10

--- A policy of probes over the baseline. `probes` is keyed by layer
--- (`RawPacket`, `Packet`, `Flow`), each a table of rules by name; a
--- probe with no Actions passes, and with no Priority stands at
--- PROBE_PRIORITY.
function M.policy(probes)
    local policy = {}
    for _, layer in ipairs({ "RawPacket", "Packet", "Flow" }) do
        local roots = { all = { Actions = { "PASS" } } }
        for name, rule in pairs((probes or {})[layer] or {}) do
            local r = {}
            for k, v in pairs(rule) do r[k] = v end
            r.Actions = r.Actions or { "PASS" }
            r.Priority = r.Priority or M.PROBE_PRIORITY
            roots[name] = r
        end
        policy[layer] = roots
    end
    for k, v in pairs(probes or {}) do
        if policy[k] == nil then policy[k] = v end
    end
    return policy
end

--- 6 bytes → "aa:bb:cc:dd:ee:ff".
function M.mac_text(bytes)
    return string.format("%02x:%02x:%02x:%02x:%02x:%02x", bytes:byte(1, 6))
end

--- The events of `list` at `seat` and `layer` (either may be nil), with
--- the further fields of `want`.
function M.at(list, seat, layer, want)
    local w = {}
    for k, v in pairs(want or {}) do w[k] = v end
    w.seat, w.layer = seat, layer
    return ntfe.matching(list, w)
end

--- One line per event, as ntfe.describe, with the protocol and with
--- IPv6 addresses printable.
function M.describe(list)
    local function addr(e, a)
        if e.addr_family ~= 6 then return tostring(a) end
        local words = { string.unpack(">I2I2I2I2I2I2I2I2", a) }
        words[9] = nil
        for i, w in ipairs(words) do words[i] = string.format("%x", w) end
        return "[" .. table.concat(words, ":") .. "]"
    end
    local out = {}
    for _, e in ipairs(list) do
        out[#out + 1] = string.format("[seat %d layer %d verdict %d %s proto %d %s:%d>%s:%d]",
            e.seat, e.layer, e.verdict, e.attributed, e.protocol, addr(e, e.src), e.src_port,
            addr(e, e.dst), e.dst_port)
    end
    return table.concat(out, " ")
end

--- The attribution of the first event at `seat`/`layer` matching
--- `want`, or nil; and a description of what there was, for messages.
function M.attribution(list, seat, layer, want)
    local found = M.at(list, seat, layer, want)
    if #found == 0 then return nil, "no event there: " .. M.describe(list) end
    return found[1].attributed, M.describe(found)
end

--- Run `fn` and gather the verdict events until each of `waits` — a
--- list of `{ seat, layer, fields }` — has been seen, or `timeout_ms`
--- (default 1000) has passed. The verdicts of frames the peer sends are
--- reached in the VM's softirq after `fn` returns, so this waits on the
--- stream itself (poll) rather than taking one read; the budget is of
--- quiet, so chatter cannot use it up. Returns the status
--- deltas and the events, as Engine:during does.
function M.watch(E, fn, waits, timeout_ms)
    E:drain()
    local before = E:status()
    fn()
    local events = {}
    local deadline = timeout_ms or 1000
    local waited = 0
    local function satisfied()
        for _, w in ipairs(waits or {}) do
            if #M.at(events, w[1], w[2], w[3]) == 0 then return false end
        end
        return true
    end
    while true do
        for _, e in ipairs(E:events()) do events[#events + 1] = e end
        if satisfied() or waited >= deadline then break end
        -- Only quiet counts against the budget: unrelated traffic (the
        -- VM's own ARP and IPv6 chatter) wakes the poll without spending it.
        if ntfe.poll(E.vm, E:stream(), ntfe.POLLIN, 50) == 0 then
            waited = waited + 50
        else
            waited = waited + 5
        end
    end
    local after = E:status()
    local delta = {}
    for _, name in ipairs(ntfe.STATUS_FIELDS) do
        delta[name] = after[name] - before[name]
    end
    return delta, events, after
end

--- Send `frame` from the peer's packet socket and gather its verdicts
--- as `watch` does.
function M.inject(E, peer, fd, frame, waits, timeout_ms)
    return M.watch(E, function()
        local r = ntfe.send_frame(peer, fd, frame)
        assert(r.ret == #frame, "the peer's packet socket sent the frame")
    end, waits, timeout_ms)
end

--- A UDP datagram from the peer to the VM as a whole frame, with the
--- IPv4 header options `o` (ntfe.ipv4's).
function M.udp_frame(net, sport, dport, data, o)
    local udp = ntfe.udp(net.peer_addr, net.addr, sport, dport, data or "")
    return M.to_vm(net, ntfe.ETH_P.IP,
        ntfe.ipv4(net.peer_addr, net.addr, ntfe.IPPROTO.UDP, #udp, o) .. udp)
end

--- A TCP segment from the peer to the VM as a whole frame.
function M.tcp_frame(net, sport, dport, flags, o)
    local tcp = ntfe.tcp(net.peer_addr, net.addr, sport, dport, flags, o)
    return M.to_vm(net, ntfe.ETH_P.IP,
        ntfe.ipv4(net.peer_addr, net.addr, ntfe.IPPROTO.TCP, #tcp, o and o.ip) .. tcp)
end

--- An ICMP message from the peer to the VM as a whole frame.
function M.icmp_frame(net, icmp_type, code, rest, data)
    local icmp = ntfe.icmp(icmp_type, code, rest, data)
    return M.to_vm(net, ntfe.ETH_P.IP,
        ntfe.ipv4(net.peer_addr, net.addr, ntfe.IPPROTO.ICMP, #icmp) .. icmp)
end

--- An ARP request from the peer for the VM's address.
function M.arp_frame(net)
    return ntfe.eth(ntfe.MAC_BROADCAST, net.peer_mac, ntfe.ETH_P.ARP)
        .. ntfe.arp_request(net.peer_mac, net.peer_addr, net.addr)
end

-- Midnight UTC, Tuesday 22 September 2026: a calendar anchor for the
-- clock tests (ISO day 2).
M.TUESDAY = 1790035200

-- ---- frames ------------------------------------------------------------

--- An Ethernet frame to the VM's end of the pair, from the peer's.
function M.to_vm(net, ethertype, payload)
    return ntfe.eth(net.mac, net.peer_mac, ethertype) .. payload
end

--- The same with an 802.1Q tag (`vid`, priority `pcp`).
function M.tagged_to_vm(net, vid, ethertype, payload, pcp)
    return net.mac .. net.peer_mac
        .. string.pack(">I2I2I2", ntfe.ETH_P.VLAN, ((pcp or 0) << 13) | vid, ethertype)
        .. payload
end

--- An IPv4 header with `options` (a multiple of four bytes) for
--- `payload_len` bytes of `protocol`. `o` as ntfe.ipv4, plus `total`
--- to lie about the total length.
function M.ipv4_opts(src, dst, protocol, payload_len, options, o)
    o = o or {}
    local ihl = 5 + #options // 4
    local function header(csum)
        return string.pack(">I1I1I2I2I2I1I1I2", 0x40 | ihl, o.tos or 0,
            o.total or (ihl * 4 + payload_len), o.id or 0, o.frag or 0,
            o.ttl or 64, protocol, csum) .. ntfe.ip4(src) .. ntfe.ip4(dst) .. options
    end
    return header(ntfe.checksum(header(0)))
end

M.NEXTHDR = { HOP = 0, TCP = 6, UDP = 17, ROUTING = 43, FRAGMENT = 44,
              ICMPV6 = 58, NONE = 59, DEST = 60, SCTP = 132 }

--- An IPv6 header. `o`: hop (64), tc (traffic class, 0), flow (0).
function M.ipv6(src, dst, nexthdr, payload_len, o)
    o = o or {}
    local word = (6 << 28) | ((o.tc or 0) << 20) | (o.flow or 0)
    return string.pack(">I4I2I1I1", word, payload_len, nexthdr, o.hop or 64)
        .. ntfe.ip6(src) .. ntfe.ip6(dst)
end

--- A hop-by-hop or destination-options header of `(hdrlen + 1) * 8`
--- bytes, padded with one PadN option.
function M.ext_opts(nexthdr, hdrlen)
    local pad = (hdrlen + 1) * 8 - 2
    return string.pack(">I1I1", nexthdr, hdrlen)
        .. string.pack(">I1I1", 1, pad - 2) .. string.rep("\0", pad - 2)
end

--- A routing header (type 4, segments left 0) of `(hdrlen + 1) * 8` bytes.
function M.ext_routing(nexthdr, hdrlen)
    return string.pack(">I1I1I1I1", nexthdr, hdrlen, 4, 0)
        .. string.rep("\0", (hdrlen + 1) * 8 - 4)
end

--- A fragment header: `offset` in 8-byte units, `more` the M flag.
function M.ext_fragment(nexthdr, offset, more, id)
    return string.pack(">I1I1I2I4", nexthdr, 0, (offset << 3) | (more and 1 or 0),
        id or 0x1234)
end

--- A UDP header and data with a correct IPv6 checksum.
function M.udp6(src, dst, sport, dport, data)
    local len = 8 + #data
    local pseudo = ntfe.ip6(src) .. ntfe.ip6(dst) .. string.pack(">I4I3I1", len, 0, 17)
    local function seg(csum)
        return string.pack(">I2I2I2I2", sport, dport, len, csum) .. data
    end
    local csum = ntfe.checksum(pseudo .. seg(0))
    if csum == 0 then csum = 0xFFFF end
    return seg(csum)
end

--- An ICMPv6 message with a correct checksum over `src`/`dst`.
function M.icmp6(src, dst, icmp_type, code, body)
    body = body or string.rep("\0", 4)
    local len = 4 + #body
    local pseudo = ntfe.ip6(src) .. ntfe.ip6(dst) .. string.pack(">I4I3I1", len, 0, 58)
    local function msg(csum)
        return string.pack(">I1I1I2", icmp_type, code, csum) .. body
    end
    return msg(ntfe.checksum(pseudo .. msg(0)))
end

--- An SCTP common header (no chunks; the checksum is not computed).
function M.sctp(sport, dport)
    return string.pack(">I2I2I4I4", sport, dport, 0, 0)
end

return M
