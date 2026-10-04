-- PKM §6.B — "Event fields": what each member of `struct
-- peios_ntfe_event` means. The attribution path and its two reserved
-- values, the packed effect counts, the reject kind, the REJUDGED flag
-- and the events a cached sentence does not produce, the layer and seat
-- numbers of the Flow layer, a Flow event's direction, the address and
-- port bytes, flow_state 0 against 5, and the identity fields of both
-- endpoints.
--
-- Records are read raw from the engine's stream so a statement about
-- bytes (the NUL after a truncated path, a zeroed field) is checked on
-- the bytes, not on a decoder's reading of them.
--
-- Own VM: the policy is machine-wide state, and the identity tests need
-- a peer on the wire and principals of their own.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local raw = require("helpers.ntfe_abi_notes")
local token = require("helpers.token")

local vm = provium:vm("vntfeabiev", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local peer, net = ntfe.peer(vm)

local PASS_ALL = { all = { Actions = { "PASS" } } }
local BASE = { RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = PASS_ALL }
local E = ntfe.engine(vm, BASE)

--- A policy: BASE with extra rules per layer.
local function policy(extra)
    local p = {}
    for layer, roots in pairs(BASE) do
        p[layer] = {}
        for k, v in pairs(roots) do p[layer][k] = v end
        for k, v in pairs((extra or {})[layer] or {}) do p[layer][k] = v end
    end
    return p
end

--- Run `fn`; return the status deltas and the events it produced, each
--- with its raw record bytes.
local function during(fn)
    local fd = E:stream()
    raw.drain(vm, fd)
    local before = E:status()
    fn()
    local after = E:status()
    local delta = {}
    for _, name in ipairs(ntfe.STATUS_FIELDS) do delta[name] = after[name] - before[name] end
    return delta, raw.drain(vm, fd)
end

local function connect_and_close(who, addr, port, timeout)
    local fd, why = ntfe.tcp_connect(who, addr, port, timeout or 1000)
    if fd then sys.close(who, fd) end
    return fd ~= nil, why
end

local function all_zero(bytes) return not bytes:find("[^%z]") end

-- Byte ranges (0-based offset, length) of the identity members.
local IDENTITY = { 176, 456 - 176 }
local REMOTE = {
    { 177, 1 }, { 179, 1 }, { 184, 4 }, { 204, 16 }, { 236, 16 }, { 320, 68 }, { 420, 32 },
}
local function bytes_at(e, off, len) return e.raw:sub(off + 1, off + len) end

-- ---- attribution ----

test("`attributed` is the winning rule's path relative to its layer key, NUL-terminated",
    { spec = "PKM *ntfe-abi-notes.event-attributed-relative-nul-truncated" }, function(t)
        E:replace(policy({ Flow = { outer = {
            ["DstPort.Equal"] = 7001, Actions = { "PASS" }, Priority = 10,
            children = { inner = { ["Protocol.Equal"] = "tcp", Actions = { "PASS" } } },
        } } }))
        local l = assert(ntfe.tcp_listen(vm, "127.0.0.1", 7001))
        local _, evs = during(function() connect_and_close(vm, "127.0.0.1", 7001) end)
        sys.close(vm, l)
        local hits = ntfe.matching(evs, { layer = 2, dst_port = 7001 })
        t:assert(#hits >= 1, "the flow is judged: " .. ntfe.describe(evs))
        t:assert_eq(hits[1].attributed, "outer/inner",
            "the path starts below `Rules\\Flow`, each step joined by `/`")
        t:assert_eq(bytes_at(hits[1], 76 + #"outer/inner", 1), "\0", "and a NUL ends it")
    end)

test("an attribution path longer than the field is truncated to 95 bytes and a NUL",
    { spec = "PKM *ntfe-abi-notes.event-attributed-relative-nul-truncated" }, function(t)
        local a, b = string.rep("a", 60), string.rep("b", 60)
        E:replace(policy({ Flow = { [a] = {
            ["DstPort.Equal"] = 7002, Actions = { "PASS" },
            children = { [b] = { ["Protocol.Equal"] = "tcp", Actions = { "PASS" } } },
        } } }))
        local l = assert(ntfe.tcp_listen(vm, "127.0.0.1", 7002))
        local _, evs = during(function() connect_and_close(vm, "127.0.0.1", 7002) end)
        sys.close(vm, l)
        local hits = ntfe.matching(evs, { layer = 2, dst_port = 7002 })
        t:assert(#hits >= 1, "the flow is judged")
        local path = a .. "/" .. b
        t:assert_eq(bytes_at(hits[1], 76, 95), path:sub(1, 95),
            "the field holds the path's first PEIOS_NTFE_EV_ATTR_LEN - 1 bytes")
        t:assert_eq(bytes_at(hits[1], 76 + 95, 1), "\0", "and its last byte is the NUL")
    end)

test("`backstop` is the attribution when nothing yielded a verdict",
    { spec = "PKM *ntfe-abi-notes.event-attributed-reserved-values" }, function(t)
        E:replace({ RawPacket = PASS_ALL, Packet = PASS_ALL,
                    Flow = { only = { ["DstPort.Equal"] = 1, Actions = { "PASS" } } } })
        local _, evs = during(function() connect_and_close(vm, "127.0.0.1", 7003, 300) end)
        E:replace(BASE)
        local hits = ntfe.matching(evs, { layer = 2, dst_port = 7003 })
        t:assert(#hits >= 1, "a flow no rule speaks for is judged: " .. ntfe.describe(evs))
        t:assert_eq(hits[1].attributed, "backstop", "attributed to `backstop`")
        t:assert(hits[1].backstop, "with the BACKSTOP flag")
        t:assert_eq(bytes_at(hits[1], 76, 9), "backstop\0", "as the bytes `backstop` and a NUL")
    end)

test("`fail-closed` is the attribution when evaluation failed",
    { spec = "PKM *ntfe-abi-notes.event-attributed-reserved-values", covered_by = "kunit:TODO",
      skip = "evaluation fails only when an atomic allocation fails mid-walk " ..
             "(ntfe_rust_evaluate's -ENOMEM); the kernel under test has no fault " ..
             "injection, so no guest packet makes it fail. No pkm_kunit_ntfe case " ..
             "covers it: wanted, a case failing the evaluation's allocation and " ..
             "expecting a DROP event with FAIL_CLOSED set and `attributed` " ..
             "\"fail-closed\"" },
    function(t) end)

-- ---- effects ----

test("`effects` packs the yielded counts as tags | counts << 8 | reports << 16 | prompts << 24",
    { spec = "PKM *ntfe-abi-notes.event-effects-packing-saturating" }, function(t)
        local m = { ["DstPort.Equal"] = 7004, ["Direction.Equal"] = "in" }
        local function rule(actions)
            local r = { Actions = actions }
            for k, v in pairs(m) do r[k] = v end
            return r
        end
        E:replace(policy({ Packet = {
            fx = rule({ "TAG(a, Set)", "COUNT(c1)", "COUNT(c2)", "PROMPT(h1, PASS)",
                        "PROMPT(h2, PASS)", "PROMPT(h3, PASS)", "PROMPT(h4, PASS)" }),
            r1 = rule({ "REPORT(5)" }), r2 = rule({ "REPORT(5)" }), r3 = rule({ "REPORT(5)" }),
        } }))
        local rx = assert(ntfe.udp_bind(vm, "127.0.0.1", 7004))
        local tx = assert(ntfe.udp_connect(vm, "127.0.0.1", 7004))
        local _, evs = during(function() ntfe.send(vm, tx, "x") end)
        sys.close(vm, tx); sys.close(vm, rx)
        local hits = ntfe.matching(evs, { layer = 0, seat = 3, dst_port = 7004 })
        t:assert_eq(#hits, 1, "the inbound Packet judgment: " .. ntfe.describe(evs))
        t:assert_eq(hits[1].effects, 1 | 2 << 8 | 3 << 16 | 4 << 24,
            "one tag, two counts, three reports and four prompts, a byte each")
    end)

test("each packed effect count saturates at 255",
    { spec = "PKM *ntfe-abi-notes.event-effects-packing-saturating" }, function(t)
        local actions = { "PASS" }
        for _ = 1, 300 do actions[#actions + 1] = "TAG(t, Add)" end
        E:replace(policy({ Packet = { many = {
            ["DstPort.Equal"] = 7005, ["Direction.Equal"] = "in", Actions = actions,
        } } }))
        local rx = assert(ntfe.udp_bind(vm, "127.0.0.1", 7005))
        local tx = assert(ntfe.udp_connect(vm, "127.0.0.1", 7005))
        local delta, evs = during(function() ntfe.send(vm, tx, "x") end)
        sys.close(vm, tx); sys.close(vm, rx)
        local hits = ntfe.matching(evs, { layer = 0, seat = 3, dst_port = 7005 })
        t:assert_eq(#hits, 1, "the inbound Packet judgment")
        t:assert_eq(delta.fx_tags, 300, "300 tag effects were yielded")
        t:assert_eq(hits[1].effects, 255, "and the event's byte for them stops at 255")
    end)

test("`effects` counts what the evaluation yielded, not what the stores applied",
    { spec = "PKM *ntfe-abi-notes.event-effects-yielded-not-applied" }, function(t)
        -- The ingress seat stands before conntrack: a TAG there has no
        -- flow to land on. The evaluation yielded it all the same.
        E:replace(policy({ RawPacket = { tagger = {
            ["DstPort.Equal"] = 7006, ["Direction.Equal"] = "in",
            Actions = { "TAG(x, Set)", "PASS" },
        } } }))
        local rx = assert(ntfe.udp_bind(vm, "127.0.0.1", 7006))
        local tx = assert(ntfe.udp_connect(vm, "127.0.0.1", 7006))
        local delta, evs = during(function() ntfe.send(vm, tx, "x") end)
        sys.close(vm, tx); sys.close(vm, rx)
        local hits = ntfe.matching(evs, { layer = 1, seat = 1, dst_port = 7006 })
        t:assert_eq(#hits, 1, "the ingress RawPacket judgment")
        t:assert_eq(hits[1].fx.tags, 1, "the event says one tag was yielded")
        t:assert_eq(delta.tag_writes, 0, "the tag store applied none")
        t:assert_eq(delta.tag_untracked, 1, "and confessed it in the status instead")
    end)

-- ---- reject kind ----

test("a REJECT event carries the kind of refusal the rule chose",
    { spec = "PKM *ntfe-abi-notes.event-reject-kind-only-on-reject" }, function(t)
        E:replace(policy({ Flow = {
            prohibited = { ["DstPort.Equal"] = 7007, Actions = { "REJECT(Prohibited)" } },
            refused = { ["DstPort.Equal"] = 7008, Actions = { "REJECT(Refused)" } },
        } }))
        local _, evs = during(function()
            connect_and_close(vm, "127.0.0.1", 7007, 300)
            connect_and_close(vm, "127.0.0.1", 7008, 300)
        end)
        local p = ntfe.matching(evs, { layer = 2, dst_port = 7007 })
        local r = ntfe.matching(evs, { layer = 2, dst_port = 7008 })
        t:assert(#p >= 1 and #r >= 1, "both flows are judged: " .. ntfe.describe(evs))
        t:assert_eq(p[1].verdict, ntfe.VERDICT.REJECT, "a REJECT")
        t:assert_eq(p[1].reject_kind, ntfe.REJECT.PROHIBITED, "of kind Prohibited (1)")
        t:assert_eq(r[1].verdict, ntfe.VERDICT.REJECT, "and a REJECT")
        t:assert_eq(r[1].reject_kind, ntfe.REJECT.REFUSED, "of kind Refused (0)")
    end)

test("a degraded REJECT still carries the kind the rule chose",
    { spec = "PKM *ntfe-abi-notes.event-degraded-reject-keeps-kind" }, function(t)
        -- ARP has no refusal vocabulary: the REJECT is applied as a DROP.
        E:replace(policy({ Packet = { noarp = {
            ["EtherType.Equal"] = "arp", Actions = { "REJECT(Prohibited)" },
        } } }))
        local pfd = assert(ntfe.packet_socket(vm, "lo"))
        local frame = ntfe.eth(ntfe.MAC_BROADCAST, string.rep("\0", 6), ntfe.ETH_P.ARP)
            .. ntfe.arp_request(string.rep("\0", 6), "127.0.0.1", "127.0.0.9")
        local delta, evs = during(function() ntfe.send_frame(vm, pfd, frame) end)
        sys.close(vm, pfd)
        E:replace(BASE)
        local hits = ntfe.matching(evs, { layer = 0, attributed = "noarp" })
        t:assert(#hits >= 1, "the ARP frame is judged: " .. ntfe.describe(evs))
        t:assert_eq(hits[1].verdict, ntfe.VERDICT.REJECT, "the event still says REJECT")
        t:assert(hits[1].reject_degraded, "flagged REJECT_DEGRADED")
        t:assert_eq(hits[1].reject_kind, ntfe.REJECT.PROHIBITED, "naming the kind the rule chose")
        t:assert(delta.reject_degraded >= 1, "and the degradation is counted")
    end)

-- ---- the Flow layer's events ----

test("a Flow-layer evaluation that replaced a stale sentence is flagged REJUDGED",
    { spec = "PKM *ntfe-abi-notes.event-rejudged-flag" }, function(t)
        E:replace(BASE)
        local l = assert(ntfe.tcp_listen(vm, "127.0.0.1", 7009))
        local c, first
        _, first = during(function() c = assert(ntfe.tcp_connect(vm, "127.0.0.1", 7009)) end)
        local s = assert(ntfe.tcp_accept(vm, l))
        local judged = ntfe.matching(first, { layer = 2, dst_port = 7009 })
        t:assert(#judged >= 1, "the new flow is judged")
        for _, e in ipairs(judged) do t:assert(not e.rejudged, "its first judgment is not a re-judgment") end
        E:replace(policy({ Flow = { other = { ["DstPort.Equal"] = 2, Actions = { "DROP" } } } }))
        local _, later = during(function() ntfe.send(vm, c, "after the change") end)
        local again = ntfe.matching(later, { layer = 2, dst_port = 7009 })
        t:assert(#again >= 1, "after a policy change the flow's next packet is judged again: "
            .. ntfe.describe(later))
        t:assert(again[1].rejudged, "and that evaluation is flagged REJUDGED")
        sys.close(vm, c); sys.close(vm, s); sys.close(vm, l)
        E:replace(BASE)
    end)

test("a packet answered by a current sentence produces no event",
    { spec = "PKM *ntfe-abi-notes.cached-sentence-packet-no-event" }, function(t)
        local rx = assert(ntfe.udp_bind(vm, "127.0.0.1", 7010))
        local tx = assert(ntfe.udp_connect(vm, "127.0.0.1", 7010))
        local _, first = during(function() ntfe.send(vm, tx, "one") end)
        t:assert(#ntfe.matching(first, { layer = 2, dst_port = 7010 }) >= 1,
            "the flow's first datagram is judged")
        local delta, second = during(function() ntfe.send(vm, tx, "two") end)
        t:assert_eq(#ntfe.matching(second, { layer = 2 }), 0,
            "its second is answered by the sentence and emits no Flow event")
        t:assert(delta.flow_cached >= 1, "the cache answered it")
        t:assert(#ntfe.matching(second, { layer = 0 }) >= 1,
            "while the per-packet layers still report it")
        sys.close(vm, tx); sys.close(vm, rx)
    end)

test("layer 2 is `Flow`, and seat 4 is `LOCAL_OUT`",
    { spec = "PKM *ntfe-abi-notes.layer-2-flow-seat-4-local-out" }, function(t)
        local _, evs = during(function()
            local fd = assert(ntfe.udp_connect(vm, "127.0.0.1", 7011))
            ntfe.send(vm, fd, "x")
            sys.close(vm, fd)
        end)
        local out = ntfe.matching(evs, { seat = 4, dst_port = 7011 })
        t:assert_eq(#out, 1, "the outbound IP seat judged one thing: " .. ntfe.describe(evs))
        t:assert_eq(out[1].layer, 2, "the flow, in layer 2")
        t:assert_eq(out[1].direction, ntfe.DIR.OUT, "outbound")
        t:assert_eq(#ntfe.matching(evs, { layer = 2, seat = 2 }), 0, "and no other seat judges layer 2 outbound")
    end)

test("a Flow event's direction is the endpoint judged",
    { spec = "PKM *ntfe-abi-notes.flow-event-direction-is-endpoint-judged" }, function(t)
        -- Outbound to the peer: the originator is this machine.
        local pl = assert(ntfe.tcp_listen(peer, net.peer_addr, 7012))
        local _, evs = during(function() connect_and_close(vm, net.peer_addr, 7012) end)
        sys.close(peer, pl)
        local f = ntfe.matching(evs, { layer = 2 })
        t:assert_eq(#f, 1, "an outbound flow is judged once: " .. ntfe.describe(evs))
        t:assert_eq(f[1].direction, ntfe.DIR.OUT, "as `out`, the originator's side")
        t:assert_eq(f[1].seat, ntfe.SEAT.LOCAL_OUT, "at the outbound seat")
        -- Inbound from the peer: the reply packets go out but the flow is `in`.
        local l = assert(ntfe.tcp_listen(vm, net.addr, 7013))
        _, evs = during(function()
            connect_and_close(peer, net.addr, 7013)
            local s = ntfe.tcp_accept(vm, l)
            if s then sys.close(vm, s) end
        end)
        sys.close(vm, l)
        f = ntfe.matching(evs, { layer = 2 })
        t:assert_eq(#f, 1, "an inbound flow is judged once: " .. ntfe.describe(evs))
        t:assert_eq(f[1].direction, ntfe.DIR.IN, "as `in`")
        t:assert_eq(f[1].seat, ntfe.SEAT.LOCAL_IN, "at the inbound seat")
        -- Loopback: two endpoints, two judgments, each its own seat's.
        local ll = assert(ntfe.tcp_listen(vm, "127.0.0.1", 7014))
        _, evs = during(function() connect_and_close(vm, "127.0.0.1", 7014) end)
        sys.close(vm, ll)
        local o = ntfe.matching(evs, { layer = 2, seat = ntfe.SEAT.LOCAL_OUT, dst_port = 7014 })
        local i = ntfe.matching(evs, { layer = 2, seat = ntfe.SEAT.LOCAL_IN, dst_port = 7014 })
        t:assert_eq(#o, 1, "a loopback flow is judged at the outbound seat")
        t:assert_eq(#i, 1, "and at the inbound seat")
        t:assert_eq(o[1].direction, ntfe.DIR.OUT, "the outbound judgment says `out`")
        t:assert_eq(i[1].direction, ntfe.DIR.IN, "the inbound one `in`")
    end)

-- ---- addresses, ports, flow state ----

test("addresses are the first 4 bytes for IPv4 and all 16 for IPv6; family 0 has none",
    { spec = "PKM *ntfe-abi-notes.event-address-bytes-by-family" }, function(t)
        local _, evs = during(function()
            local fd = assert(ntfe.udp_connect(vm, "127.0.0.1", 7015))
            ntfe.send(vm, fd, "x")
            sys.close(vm, fd)
        end)
        local v4 = ntfe.matching(evs, { layer = 0, dst_port = 7015 })[1]
        t:assert(v4, "an IPv4 packet is judged")
        t:assert_eq(v4.addr_family, 4, "family 4")
        t:assert_eq(bytes_at(v4, 36, 4), ntfe.ip4("127.0.0.1"), "its source is the first 4 bytes")
        t:assert_eq(bytes_at(v4, 52, 4), ntfe.ip4("127.0.0.1"), "and so is its destination")

        _, evs = during(function()
            local fd = assert(ntfe.udp_connect(vm, "::1", 7016))
            ntfe.send(vm, fd, "x")
            sys.close(vm, fd)
        end)
        local v6 = ntfe.matching(evs, { layer = 0, dst_port = 7016 })[1]
        t:assert(v6, "an IPv6 packet is judged: " .. ntfe.describe(evs))
        t:assert_eq(v6.addr_family, 6, "family 6")
        t:assert_eq(bytes_at(v6, 36, 16), ntfe.ip6("::1"), "its source is all 16 bytes")
        t:assert_eq(bytes_at(v6, 52, 16), ntfe.ip6("::1"), "and so is its destination")

        local pfd = assert(ntfe.packet_socket(vm, "lo"))
        _, evs = during(function()
            ntfe.send_frame(vm, pfd, ntfe.eth(ntfe.MAC_BROADCAST, string.rep("\0", 6), ntfe.ETH_P.ARP)
                .. ntfe.arp_request(string.rep("\0", 6), "127.0.0.1", "127.0.0.9"))
        end)
        sys.close(vm, pfd)
        local arp = nil
        for _, e in ipairs(evs) do if e.ether_type == ntfe.ETH_P.ARP then arp = e end end
        t:assert(arp, "an ARP frame is judged: " .. ntfe.describe(evs))
        t:assert_eq(arp.addr_family, 0, "with family 0: it has no IP addresses to give")
    end)

test("ports are 0 when the packet has none, and `protocol` says so",
    { spec = "PKM *ntfe-abi-notes.event-ports-zero-when-absent" }, function(t)
        local rs = vm:syscall(ntfe.NR.socket, ntfe.AF_INET, ntfe.SOCK_RAW, ntfe.IPPROTO.ICMP)
        t:assert(rs.ret >= 0, "a raw ICMP socket opens")
        local _, evs = during(function()
            ntfe.sendto(vm, rs.ret, ntfe.icmp(8, 0, 0x4242 << 16 | 1, "ping"), "127.0.0.1", 0)
        end)
        sys.close(vm, rs.ret)
        local icmp = ntfe.matching(evs, { protocol = ntfe.IPPROTO.ICMP })
        t:assert(#icmp >= 1, "the ICMP packets are judged")
        for _, e in ipairs(icmp) do
            t:assert_eq(e.src_port, 0, "ICMP has no source port: 0")
            t:assert_eq(e.dst_port, 0, "nor a destination port: 0")
        end
    end)

test("flow_state 0 means the fact was absent; untracked is 5",
    { spec = "PKM *ntfe-abi-notes.event-flow-state-0-absent-5-untracked" }, function(t)
        -- An echo reply nobody asked for: conntrack will not open a flow
        -- for it and leaves the packet untracked.
        local rs = vm:syscall(ntfe.NR.socket, ntfe.AF_INET, ntfe.SOCK_RAW, ntfe.IPPROTO.ICMP)
        local _, evs = during(function()
            ntfe.sendto(vm, rs.ret, ntfe.icmp(0, 0, 0x4343 << 16 | 1, "pong"), "127.0.0.1", 0)
        end)
        sys.close(vm, rs.ret)
        local ingress = ntfe.matching(evs, { seat = ntfe.SEAT.INGRESS, protocol = 1 })
        local local_in = ntfe.matching(evs, { seat = ntfe.SEAT.LOCAL_IN, layer = 0, protocol = 1 })
        t:assert(#ingress >= 1 and #local_in >= 1, "it is judged at ingress and at the inbound seat: "
            .. ntfe.describe(evs))
        t:assert_eq(ingress[1].flow_state, 0, "the ingress seat has no flow facts: 0")
        t:assert_eq(local_in[1].flow_state, 5, "after conntrack, untracked is 5")
        _, evs = during(function()
            local fd = assert(ntfe.udp_connect(vm, "127.0.0.1", 7017))
            ntfe.send(vm, fd, "x")
            sys.close(vm, fd)
        end)
        local tracked_ingress = ntfe.matching(evs, { seat = ntfe.SEAT.INGRESS, dst_port = 7017 })
        local tracked_in = ntfe.matching(evs, { seat = ntfe.SEAT.LOCAL_IN, layer = 0, dst_port = 7017 })
        t:assert_eq(tracked_ingress[1].flow_state, 0,
            "a tracked flow's packet still reads 0 at ingress: absent, not untracked")
        t:assert_eq(tracked_in[1].flow_state, ntfe.FLOW_STATE.NEW, "and `new` once tracked")
    end)

-- ---- identity ----

test("the identity fields are set on Flow events only, and zero elsewhere",
    { spec = "PKM *ntfe-abi-notes.event-identity-fields-flow-only" }, function(t)
        local l = assert(ntfe.tcp_listen(vm, "127.0.0.1", 7018))
        local _, evs = during(function() connect_and_close(vm, "127.0.0.1", 7018) end)
        sys.close(vm, l)
        local flow = ntfe.matching(evs, { layer = 2, dst_port = 7018 })
        t:assert(#flow >= 1, "the flow is judged")
        t:assert_eq(flow[1]["local"].kind, ntfe.LOCAL.PROGRAM, "a Flow event names its endpoint")
        local others = 0
        for _, e in ipairs(evs) do
            if e.layer ~= 2 then
                others = others + 1
                t:assert(all_zero(bytes_at(e, IDENTITY[1], IDENTITY[2])),
                    "a layer-" .. e.layer .. " event's identity bytes are all zero")
            end
        end
        t:assert(others >= 2, "checked on the per-packet layers' events too")
    end)

test("an endpoint kind is ABSENT on a non-Flow event, and for `remote` when the other end is not local",
    { spec = "PKM *ntfe-abi-notes.event-kind-absent-cases" }, function(t)
        local pl = assert(ntfe.tcp_listen(peer, net.peer_addr, 7019))
        local _, evs = during(function() connect_and_close(vm, net.peer_addr, 7019) end)
        sys.close(peer, pl)
        local flow = ntfe.matching(evs, { layer = 2 })
        t:assert_eq(#flow, 1, "the flow to the peer is judged")
        t:assert_eq(flow[1].raw:byte(177 + 1), ntfe.LOCAL.ABSENT,
            "`remote_kind` is ABSENT: the other end is another machine")
        t:assert_eq(flow[1]["local"].kind, ntfe.LOCAL.PROGRAM, "while `local_kind` names this end")
        for _, e in ipairs(evs) do
            if e.layer ~= 2 then
                t:assert_eq(e.raw:byte(176 + 1), ntfe.LOCAL.ABSENT, "a non-Flow event's `local_kind` is ABSENT")
                t:assert_eq(e.raw:byte(177 + 1), ntfe.LOCAL.ABSENT, "and its `remote_kind`")
            end
        end
    end)

test("the `remote` fields are filled only on a loopback flow",
    { spec = "PKM *ntfe-abi-notes.event-remote-loopback-only" }, function(t)
        local l = assert(ntfe.tcp_listen(vm, "127.0.0.1", 7020))
        local _, evs = during(function() connect_and_close(vm, "127.0.0.1", 7020) end)
        sys.close(vm, l)
        local lo = ntfe.matching(evs, { layer = 2, dst_port = 7020 })
        t:assert(#lo >= 1, "the loopback flow is judged")
        t:assert_eq(lo[1].remote.kind, ntfe.LOCAL.PROGRAM, "its other end is a program on this machine")
        t:assert(lo[1].remote.pid > 0, "with a pid")
        t:assert(lo[1].remote.user, "and a user SID")
        local pl = assert(ntfe.tcp_listen(peer, net.peer_addr, 7021))
        _, evs = during(function() connect_and_close(vm, net.peer_addr, 7021) end)
        sys.close(peer, pl)
        local far = ntfe.matching(evs, { layer = 2 })
        t:assert_eq(#far, 1, "a flow to the peer is judged")
        for _, r in ipairs(REMOTE) do
            t:assert(all_zero(bytes_at(far[1], r[1], r[2])),
                "and every `remote` byte at offset " .. r[1] .. " is zero")
        end
    end)

test("a PROGRAM end carries its process's guid, pid and comm, its user SID and service SID",
    { spec = "PKM *ntfe-abi-notes.event-program-end-fields" }, function(t)
        local service = token.sid(5, 80, 11, 22, 33, 44, 55)
        local groups = {
            { sid = token.SID.EVERYONE, attributes = 0x7 },
            { sid = service, attributes = 0x7 },
        }
        local pl = assert(ntfe.tcp_listen(peer, net.peer_addr, 7022))
        token.as_principal(t, vm, {
            groups = groups, privs_present = 1 << 21, privs_enabled = 1 << 21,
        }, function(w)
            local pid = w:syscall(sys.NR.getpid).ret
            local guid = raw.process_guid(vm, w)
            t:assert(guid, "the principal's process GUID is known to KMES")
            local _, evs = during(function() connect_and_close(w, net.peer_addr, 7022) end)
            local f = ntfe.matching(evs, { layer = 2 })[1]
            t:assert(f, "the principal's flow is judged: " .. ntfe.describe(evs))
            local me = f["local"]
            t:assert_eq(me.kind, ntfe.LOCAL.PROGRAM, "its end is a PROGRAM")
            t:assert_eq(me.pid, pid, "`local_pid` is the process's")
            t:assert_eq(me.comm, raw.comm(vm, pid), "`local_comm` its comm")
            t:assert_eq(me.guid, guid, "`local_guid` its process GUID")
            t:assert_eq(bytes_at(f, 252, 1), "\1", "`local_user` is a binary SID (revision 1)")
            t:assert_eq(f.raw:byte(252 + 2), 5, "whose byte 1 is its sub-authority count")
            t:assert_eq(me.user, token.SID.TEST_USER, "and which is the token's user")
            t:assert(all_zero(bytes_at(f, 252 + #token.SID.TEST_USER, 68 - #token.SID.TEST_USER)),
                "self-sized: the rest of the field is zero")
            t:assert_eq(me.service, service, "`local_service` is its per-service SID")
        end)
        local _, evs = during(function() connect_and_close(vm, net.peer_addr, 7022) end)
        sys.close(peer, pl)
        local f = ntfe.matching(evs, { layer = 2 })[1]
        t:assert(f, "the agent's own flow is judged")
        t:assert_eq(f["local"].user, token.SID.LOCAL_SYSTEM, "a program with no service")
        t:assert(all_zero(bytes_at(f, 388, 32)), "has a `local_service` of all zero: absent")
    end)

test("on a loopback flow, each end's fields are its own program's",
    { spec = "PKM *ntfe-abi-notes.event-program-end-fields", tags = { "known-bug" },
      -- PEI-1301. At the outbound seat the other
      -- end of a loopback flow is resolved by ntfe_identity_receiver(),
      -- whose early-demux shortcut takes skb->sk when it is a full
      -- socket; at LOCAL_OUT that is the *sending* socket, so the
      -- receiver is reported as the sender and recorded so for the flow.
      -- Seen live: a worker (pid 221) connecting to a listener the agent
      -- (pid 1) owns gives, at both seats, local_pid = remote_pid = 221.
    }, function(t)
        local W = vm:spawn_worker()
        local wpid = W:syscall(sys.NR.getpid).ret
        local agent = vm:syscall(sys.NR.getpid).ret
        local l = assert(ntfe.tcp_listen(vm, "127.0.0.1", 7023))
        local _, evs = during(function() connect_and_close(W, "127.0.0.1", 7023) end)
        sys.close(vm, l)
        local out = ntfe.matching(evs, { layer = 2, seat = ntfe.SEAT.LOCAL_OUT, dst_port = 7023 })[1]
        local inn = ntfe.matching(evs, { layer = 2, seat = ntfe.SEAT.LOCAL_IN, dst_port = 7023 })[1]
        t:assert(out and inn, "both ends are judged")
        t:assert_eq(out["local"].pid, wpid, "the outbound judgment's own end is the connecting worker")
        t:assert_eq(out.remote.pid, agent, "its other end the listening agent")
        t:assert_eq(inn["local"].pid, agent, "the inbound judgment's own end is the listening agent")
        t:assert_eq(inn.remote.pid, wpid, "its other end the worker")
    end)

test("`*_unresolved` says an end could not be attributed",
    { spec = "PKM *ntfe-abi-notes.event-unresolved-flag" }, function(t)
        -- A datagram put straight onto the loopback by a packet socket
        -- never crossed the outbound seat, so nobody recorded its sender:
        -- the inbound seat cannot see who sent it, and says so.
        local rx = assert(ntfe.udp_bind(vm, "127.0.0.1", 7201))
        local delta, evs = during(function() raw.inject_lo_udp(vm, 7200, 7201, "who sent this") end)
        local f = ntfe.matching(evs, { layer = 2, dst_port = 7201 })
        t:assert_eq(#f, 1, "the flow is judged at the inbound seat: " .. ntfe.describe(evs))
        t:assert(f[1].remote.unresolved, "`remote_unresolved` says the sender could not be attributed")
        t:assert_eq(f[1].remote.kind, ntfe.LOCAL.ABSENT, "and reports it as absent")
        t:assert(f[1].identity_unresolved, "the event is flagged IDENTITY_UNRESOLVED")
        t:assert_eq(f[1]["local"].kind, ntfe.LOCAL.PROGRAM, "while the receiving end is known")
        t:assert(not f[1]["local"].unresolved, "and resolved")
        t:assert(delta.identity_unresolved >= 1, "and the status counts it")
        sys.close(vm, rx)
    end)
