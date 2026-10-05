-- PKM §6.6 — the stores: reports. A REPORT whose level clears
-- `CurrentReportingLevel` becomes one KMES event of origin class 4 and
-- type `network-report`, whose msgpack payload is a string-keyed map of
-- the attribution, the level, the seat and layer, the verdict, the
-- packet and the generation — only the keys the packet has. The payload
-- is built in a fixed 512-byte buffer under a map16 header; one that
-- would not fit is dropped rather than truncated, and `reports_emitted`
-- counts only what reached the ring.
--
-- The events are read from every CPU's KMES ring (helpers/ntfe_store);
-- the payload is decoded with a reader that knows map16, which the
-- generic helpers/kmes reader does not.
--
-- Own VM: the policy, and with it CurrentReportingLevel, is machine-wide
-- state.

local ntfe = require("helpers.ntfe")
local S = require("helpers.ntfe_store")

local vm = provium:vm("vntfestrep", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local peer, net = ntfe.peer(vm)
local pfd = assert(ntfe.packet_socket(peer, net.peer))
local rec = S.recorder(vm)

local PASS_ALL = { all = { Actions = { "PASS" } } }
local LEVEL = 3

local function with(packet, raw)
    local p = { all = { Actions = { "PASS" } } }
    for name, rule in pairs(packet or {}) do p[name] = rule end
    local r = { all = { Actions = { "PASS" } } }
    for name, rule in pairs(raw or {}) do r[name] = rule end
    return { values = { CurrentReportingLevel = LEVEL }, RawPacket = r, Packet = p, Flow = PASS_ALL }
end

local E = ntfe.engine(vm, with())

local socks = {}
local function send(port, payload)
    if not socks[port] then
        socks[port] = {
            l = assert(ntfe.udp_bind(vm, net.addr, port)),
            c = assert(ntfe.udp_connect(peer, net.addr, port)),
        }
    end
    ntfe.send(peer, socks[port].c, payload or "x")
    ntfe.recv(vm, socks[port].l, 200)
end

-- Run `fn`; return the network reports it produced, the status deltas
-- and the verdict events.
local function reporting(fn)
    rec:drain()
    local delta, events = E:during(fn)
    return S.reports(rec:drain()), delta, events
end

local function keyset(keys)
    local set = {}
    for _, k in ipairs(keys) do set[k] = true end
    return set
end

-- ---- one event ----------------------------------------------------------

test("a REPORT at or past CurrentReportingLevel becomes one KMES event of origin class 4, type network-report",
    { spec = "PKM *ntfe-store.report-becomes-one-kmes-event" }, function(t)
        local s = E:replace(with({
            loud = { ["DstPort.Equal"] = 7501, Actions = { "REPORT(3)" } },
            quiet = { ["DstPort.Equal"] = 7502, Actions = { "REPORT(2)" } },
            double = { ["DstPort.Equal"] = 7503, Actions = { "REPORT(4)", "REPORT(5)" } },
        }))
        t:assert_eq(s.last_ingest_error, 0, "the policy is accepted")
        t:assert_eq(s.reporting_level, LEVEL, "CurrentReportingLevel is in force")
        local reports = reporting(function() send(7501) end)
        t:assert_eq(#reports, 1, "a level-3 REPORT under level 3 is one event")
        t:assert_eq(reports[1].origin, S.ORIGIN_NTFE, "of origin class KMES_ORIGIN_NTFE (4)")
        t:assert_eq(reports[1].type, "network-report", "and type network-report")
        t:assert(reports[1].report, "carrying a payload that decodes: "
            .. tostring(reports[1].report == nil))
        t:assert_eq(reports[1].report.rule, "loud", "from the reporting rule")
        reports = reporting(function() send(7502) end)
        t:assert_eq(#reports, 0, "a level-2 REPORT under level 3 is no event")
        reports = reporting(function() send(7503) end)
        t:assert_eq(#reports, 1, "a rule reporting twice is still one event")
        t:assert_eq(reports[1].report.level, 5, "at its higher level")
    end)

-- ---- the payload ----------------------------------------------------------

test("the payload is a string-keyed map of the attribution, level, seat, verdict, packet, generation and time",
    { spec = "PKM *ntfe-store.report-payload-keys" }, function(t)
        local s = E:replace(with({
            guard = { ["Protocol.Equal"] = "tcp", children = {
                ssh = { ["DstPort.Equal"] = 7510, Actions = { "REJECT(Prohibited)", "REPORT(4)" } },
            } },
        }))
        local before = vm:clock():get_ns()
        local reports, _, events = reporting(function()
            local fd = ntfe.tcp_connect(peer, net.addr, 7510, 500)
            t:assert(not fd, "the connection is refused")
        end)
        local after = vm:clock():get_ns()
        t:assert(#reports >= 1, "the refused SYN is reported")
        local r, keys = reports[1].report, reports[1].keys
        local want = { "rule", "rule_hash", "level", "layer", "seat", "verdict", "reject_kind",
                       "direction", "interface", "ifindex", "ether_type", "family",
                       "protocol", "src", "dst", "src_port", "dst_port", "flow_state",
                       "length", "generation", "t_ns" }
        local have = keyset(keys)
        for _, k in ipairs(want) do t:assert(have[k], "the payload has `" .. k .. "`") end
        t:assert_eq(#keys, #want, "and nothing else")
        local ev = ntfe.matching(events, { layer = ntfe.LAYER.PACKET, dst_port = 7510 })[1]
        t:assert(ev, "the verdict event is there to compare with")
        t:assert_eq(r.rule, "guard/ssh", "rule: the attribution path")
        t:assert_eq(r.rule_hash, ntfe.name_hash("guard/ssh"), "rule_hash: its FNV-1a-64")
        t:assert_eq(r.level, 4, "level")
        t:assert_eq(r.layer, "Packet", "layer")
        t:assert_eq(r.seat, "local-in", "seat")
        t:assert_eq(r.verdict, "REJECT", "verdict")
        t:assert_eq(r.reject_kind, "Prohibited", "reject_kind, since it was a reject")
        t:assert_eq(r.direction, "in", "direction")
        t:assert_eq(r.interface, net.name, "interface")
        t:assert_eq(r.ifindex, net.ifindex, "ifindex")
        t:assert_eq(r.ether_type, ntfe.ETH_P.IP, "ether_type")
        t:assert_eq(r.family, 4, "family")
        t:assert_eq(r.protocol, ntfe.IPPROTO.TCP, "protocol")
        t:assert_eq(r.src, net.peer_addr, "src, as text")
        t:assert_eq(r.dst, net.addr, "dst, as text")
        t:assert_eq(r.src_port, ev.src_port, "src_port")
        t:assert_eq(r.dst_port, 7510, "dst_port")
        t:assert_eq(r.flow_state, "new", "flow_state")
        t:assert_eq(r.length, ev.length, "length")
        t:assert_eq(r.generation, s.generation, "generation")
        t:assert(r.t_ns >= before and r.t_ns <= after, "t_ns, CLOCK_REALTIME nanoseconds")
        E:replace(with({ udp = { ["DstPort.Equal"] = 7511, Actions = { "REPORT(3)" } } }))
        local plain = reporting(function() send(7511) end)
        t:assert(plain[1] and plain[1].report.reject_kind == nil,
            "a report of a PASS has no reject_kind")
    end)

test("only the keys the packet has are present",
    { spec = "PKM *ntfe-store.report-omits-absent-packet-keys" }, function(t)
        local MAC = "\x02\x00\x00\x00\x75\x20"
        E:replace(with({
            arp = { ["Direction.Equal"] = "in", ["SrcMac.Equal"] = "02:00:00:00:75:20",
                    ["EtherType.Equal"] = "arp", Actions = { "REPORT(3)" } },
            ping = { ["Direction.Equal"] = "in", ["Protocol.Equal"] = "icmp",
                     ["IcmpType.Equal"] = 8, Actions = { "REPORT(3)" } },
        }, {
            wire = { ["Direction.Equal"] = "in", ["DstPort.Equal"] = 7520,
                     Actions = { "REPORT(3)" } },
        }))
        local function only(reports, rule)
            for _, r in ipairs(reports) do
                if r.report and r.report.rule == rule then return r end
            end
        end
        local arp = only(reporting(function()
            ntfe.send_frame(peer, pfd, ntfe.eth(ntfe.MAC_BROADCAST, MAC, ntfe.ETH_P.ARP)
                .. ntfe.arp_request(MAC, "10.9.0.98", "10.9.0.97"))
        end), "arp")
        t:assert(arp, "an ARP frame is reported")
        local have = keyset(arp.keys)
        for _, k in ipairs({ "protocol", "src", "dst", "src_port", "dst_port", "flow_state" }) do
            t:assert(not have[k], "an ARP report has no `" .. k .. "`")
        end
        t:assert_eq(arp.report.ether_type, ntfe.ETH_P.ARP, "but does say what it was")
        t:assert_eq(arp.report.seat, "ingress", "and where: the fallback judgment at ingress")

        local echo = ntfe.icmp(8, 0, 0x12340001, "ping")
        local ping = only(reporting(function()
            ntfe.send_frame(peer, pfd, ntfe.eth(net.mac, net.peer_mac, ntfe.ETH_P.IP)
                .. ntfe.ipv4(net.peer_addr, net.addr, ntfe.IPPROTO.ICMP, #echo) .. echo)
        end), "ping")
        t:assert(ping, "an ICMP echo is reported")
        have = keyset(ping.keys)
        t:assert(have.src and have.dst and have.protocol, "with its addresses and protocol")
        t:assert(not have.src_port and not have.dst_port, "but no ports, which ICMP lacks")
        t:assert(not have.reject_kind, "and no reject_kind for a verdict that was no reject")

        local wire = only(reporting(function() send(7520) end), "wire")
        t:assert(wire, "a datagram at the ingress seat is reported by RawPacket")
        have = keyset(wire.keys)
        t:assert(have.src_port and have.dst_port, "with its ports")
        t:assert(not have.flow_state, "but no flow_state: conntrack has not run at ingress")
    end)

test("the payload is one map16 whose count is patched to the keys written",
    { spec = "PKM *ntfe-store.report-payload-built-on-stack" }, function(t)
        E:replace(with({ udp = { ["DstPort.Equal"] = 7530, Actions = { "REPORT(3)" } } }))
        local reports = reporting(function() send(7530) end)
        t:assert_eq(#reports, 1, "one report")
        local bytes = reports[1].payload_bytes
        t:assert_eq(bytes:byte(1), 0xde, "a map16 header")
        local count = string.unpack(">I2", bytes, 2)
        local _, keys, used = S.decode_payload(bytes)
        t:assert_eq(count, #keys, "whose count is the number of keys that follow")
        t:assert_eq(used, #bytes, "which fill the payload exactly")
        t:assert(#bytes <= 512, "inside the 512-byte buffer: " .. #bytes)
    end)

-- A long text form for both IPv6 addresses (39 characters: no zero
-- group to compress), and a rule path too long for the room they leave.
local V6_SRC = "fd12:3456:789a:bcde:f012:3456:789a:bcd1"
local V6_DST = "fd12:3456:789a:bcde:f012:3456:789a:bcd2"
local LONG_A, LONG_B, LONG_C = string.rep("r", 120), string.rep("s", 120), string.rep("t", 30)

test("a rule path too long for the payload is cut to fit and said, and the event still goes",
    { spec = "PKM *ntfe-store.report-long-rule-cut-and-said" }, function(t)
        -- Such a report was once dropped silently (PEI-1310).
        local leaf = { ["Direction.Equal"] = "in", ["DstPort.Equal"] = 7541, Actions = { "REPORT(5)" } }
        local s = E:replace(with(nil, {
            [LONG_A] = { children = { [LONG_B] = { children = { [LONG_C] = leaf } } } },
            short = { ["Direction.Equal"] = "in", ["DstPort.Equal"] = 7542, Actions = { "REPORT(5)" } },
        }))
        local path = LONG_A .. "/" .. LONG_B .. "/" .. LONG_C
        t:assert_eq(s.last_ingest_error, 0, "a 272-character rule path is accepted")
        local function frame(dport)
            local udp = S.udp6(V6_SRC, V6_DST, 40000, dport, "x")
            return ntfe.eth(net.mac, net.peer_mac, ntfe.ETH_P.IPV6)
                .. S.ipv6(V6_SRC, V6_DST, ntfe.IPPROTO.UDP, #udp) .. udp
        end
        local control, d = reporting(function() ntfe.send_frame(peer, pfd, frame(7542)) end)
        t:assert_eq(#control, 1, "the frame reported by a short-named rule is one event")
        t:assert_eq(d.reports_emitted, 1, "emitted")
        t:assert_eq(control[1].report.src, V6_SRC, "naming the long addresses")
        t:assert(not control[1].report.rule_truncated, "a short path is not cut")
        -- The long path as a str16 (3 + 272) where "short" took a fixstr
        -- (1 + 5): the same report, 269 bytes longer.
        local would = #control[1].payload_bytes + (3 + #path) - (1 + #"short")
        t:assert(would > 512, "the whole long path would need " .. would .. " bytes")
        local cut, dd = reporting(function() ntfe.send_frame(peer, pfd, frame(7541)) end)
        t:assert_eq(#cut, 1, "the long-named rule's report reaches KMES")
        t:assert_eq(dd.reports_emitted, 1, "and is counted as emitted")
        local r = cut[1] and cut[1].report or {}
        t:assert(#cut[1].payload_bytes <= 512, "inside the 512-byte buffer: " .. #cut[1].payload_bytes)
        t:assert_eq(r.rule_truncated, 1, "rule_truncated says the path was cut")
        t:assert(#r.rule < #path and path:sub(1, #r.rule) == r.rule,
            "rule is a prefix of the path: " .. #r.rule .. " of " .. #path .. " characters")
        t:assert_eq(r.rule_hash, ntfe.name_hash(path), "and rule_hash names the whole path")
    end)

test("reports_emitted counts the events that reached the ring",
    { spec = "PKM *ntfe-store.reports-emitted-counts-ring-arrivals" }, function(t)
        E:replace(with({
            udp = { ["DstPort.Equal"] = 7550, Actions = { "REPORT(4)" } },
            under = { ["DstPort.Equal"] = 7551, Actions = { "REPORT(1)" } },
        }))
        local reports, d = reporting(function()
            for _ = 1, 5 do send(7550) end
            for _ = 1, 3 do send(7551) end
        end)
        t:assert_eq(#reports, 5, "five reports clear the level")
        t:assert_eq(d.reports_emitted, 5, "and reports_emitted moved by exactly those five")
        t:assert_eq(d.fx_reports, 5, "the three under the level were never issued")
    end)
