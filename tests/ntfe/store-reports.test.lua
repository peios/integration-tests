-- PKM §6.6 — the stores: reports. A REPORT whose level clears
-- `CurrentReportingLevel` becomes one KMES event of origin class 4 and
-- type `ntfe.verdict.reported`, whose msgpack payload is nested maps,
-- one per path segment: `rule` (the attribution, the level, the layer
-- and seat), `outcome` (the verdict), `network`, `source`, `destination`
-- and `flow` (the packet) and `policy` (the generation) — only the keys
-- the packet has. The payload is built in a fixed 512-byte buffer; a
-- rule name too long for it is cut and said, never dropped, and
-- `reports_emitted` counts only what reached the ring.
--
-- The events are read from every CPU's KMES ring (helpers/ntfe_store);
-- the payload is decoded with a reader that keeps every map's keys in
-- wire order, so each level is held to its exact key list.
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

-- Hold one map of the payload to exactly `want`: every key present, and
-- nothing else (the count catches a duplicate key too).
local function exactly(t, map, want, what)
    local keys = S.keys_of(map) or {}
    local have = keyset(keys)
    for _, k in ipairs(want) do t:assert(have[k], what .. " has `" .. k .. "`") end
    t:assert_eq(#keys, #want, "and " .. what .. " has nothing else")
end

-- ---- one event ----------------------------------------------------------

test("a REPORT at or past CurrentReportingLevel becomes one KMES event of origin class 4, type ntfe.verdict.reported",
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
        t:assert_eq(reports[1].type, "ntfe.verdict.reported", "and type ntfe.verdict.reported")
        t:assert(reports[1].report, "carrying a payload that decodes: "
            .. tostring(reports[1].report == nil))
        t:assert_eq((reports[1].report.rule or {}).name, "loud", "from the reporting rule")
        reports = reporting(function() send(7502) end)
        t:assert_eq(#reports, 0, "a level-2 REPORT under level 3 is no event")
        reports = reporting(function() send(7503) end)
        t:assert_eq(#reports, 1, "a rule reporting twice is still one event")
        t:assert_eq((reports[1].report.rule or {})["report-level"], 5, "at its higher level")
    end)

-- ---- the payload ----------------------------------------------------------

test("the payload nests the attribution, level, seat, verdict, packet and generation; the time is the header's",
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
        local r = reports[1].report
        exactly(t, r, { "rule", "outcome", "network", "source", "destination", "flow", "policy" },
            "the payload")
        local rule, outcome, nw = r.rule or {}, r.outcome or {}, r.network or {}
        local src, dst = r.source or {}, r.destination or {}
        exactly(t, rule, { "name", "hash", "report-level", "layer", "seat" }, "rule")
        exactly(t, outcome, { "verdict", "reason" }, "outcome")
        exactly(t, nw, { "direction", "interface", "ether-type", "family", "protocol", "length" },
            "network")
        exactly(t, nw.interface, { "name", "index" }, "network.interface")
        exactly(t, src, { "address", "port" }, "source")
        exactly(t, dst, { "address", "port" }, "destination")
        exactly(t, r.flow, { "state" }, "flow")
        exactly(t, r.policy, { "generation" }, "policy")
        local ev = ntfe.matching(events, { layer = ntfe.LAYER.PACKET, dst_port = 7510 })[1]
        t:assert(ev, "the verdict event is there to compare with")
        t:assert_eq(rule.name, "guard/ssh", "rule.name: the attribution path")
        t:assert_eq(rule.hash, ntfe.name_hash("guard/ssh"), "rule.hash: its FNV-1a-64")
        t:assert_eq(rule["report-level"], 4, "rule.report-level")
        t:assert_eq(rule.layer, "packet", "rule.layer")
        t:assert_eq(rule.seat, "local-in", "rule.seat")
        t:assert_eq(outcome.verdict, "reject", "outcome.verdict")
        t:assert_eq(outcome.reason, "prohibited", "outcome.reason, since it was a reject")
        t:assert_eq(nw.direction, "in", "network.direction")
        t:assert_eq((nw.interface or {}).name, net.name, "network.interface.name")
        t:assert_eq((nw.interface or {}).index, net.ifindex, "network.interface.index")
        t:assert_eq(nw["ether-type"], ntfe.ETH_P.IP, "network.ether-type")
        t:assert_eq(nw.family, 2, "network.family: AF_INET, the AF_* number")
        t:assert_eq(nw.protocol, ntfe.IPPROTO.TCP, "network.protocol")
        t:assert_eq(src.address, net.peer_addr, "source.address, as text")
        t:assert_eq(dst.address, net.addr, "destination.address, as text")
        t:assert_eq(src.port, ev.src_port, "source.port")
        t:assert_eq(dst.port, 7510, "destination.port")
        t:assert_eq((r.flow or {}).state, "new", "flow.state")
        t:assert_eq(nw.length, ev.length, "network.length")
        t:assert_eq((r.policy or {}).generation, s.generation, "policy.generation")
        t:assert(reports[1].timestamp >= before and reports[1].timestamp <= after,
            "the time is the KMES header's, CLOCK_REALTIME nanoseconds")
        E:replace(with({ udp = { ["DstPort.Equal"] = 7511, Actions = { "REPORT(3)" } } }))
        local plain = reporting(function() send(7511) end)
        t:assert(plain[1], "a PASS is reported")
        exactly(t, plain[1] and plain[1].report.outcome, { "verdict" },
            "a report of a PASS: outcome, with no reason,")
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
                if r.report and (r.report.rule or {}).name == rule then return r end
            end
        end
        local arp = only(reporting(function()
            ntfe.send_frame(peer, pfd, ntfe.eth(ntfe.MAC_BROADCAST, MAC, ntfe.ETH_P.ARP)
                .. ntfe.arp_request(MAC, "10.9.0.98", "10.9.0.97"))
        end), "arp")
        t:assert(arp, "an ARP frame is reported")
        -- No address family: no source, destination or protocol; and
        -- judged at ingress, before conntrack, so no flow.
        exactly(t, arp.report, { "rule", "outcome", "network", "policy" }, "an ARP report")
        exactly(t, arp.report.network, { "direction", "interface", "ether-type", "family", "length" },
            "an ARP report's network")
        t:assert_eq(arp.report.network["ether-type"], ntfe.ETH_P.ARP, "but does say what it was")
        t:assert_eq(arp.report.network.family, 0, "with family AF_UNSPEC")
        t:assert_eq(arp.report.rule.seat, "ingress", "and where: the fallback judgment at ingress")

        local echo = ntfe.icmp(8, 0, 0x12340001, "ping")
        local ping = only(reporting(function()
            ntfe.send_frame(peer, pfd, ntfe.eth(net.mac, net.peer_mac, ntfe.ETH_P.IP)
                .. ntfe.ipv4(net.peer_addr, net.addr, ntfe.IPPROTO.ICMP, #echo) .. echo)
        end), "ping")
        t:assert(ping, "an ICMP echo is reported")
        local have = keyset(ping.keys)
        t:assert(have.source and have.destination and ping.report.network.protocol,
            "with its addresses and protocol")
        exactly(t, ping.report.source, { "address" }, "but source, with no port, which ICMP lacks,")
        exactly(t, ping.report.destination, { "address" }, "and destination")
        exactly(t, ping.report.outcome, { "verdict" },
            "and outcome, with no reason for a verdict that was no reject,")

        local wire = only(reporting(function() send(7520) end), "wire")
        t:assert(wire, "a datagram at the ingress seat is reported by RawPacket")
        exactly(t, wire.report.source, { "address", "port" }, "with source and its port")
        exactly(t, wire.report.destination, { "address", "port" }, "and destination and its port")
        have = keyset(wire.keys)
        t:assert(not have.flow, "but no flow: conntrack has not run at ingress")
    end)

test("the payload is one map whose every count is the keys written, filling it exactly",
    { spec = "PKM *ntfe-store.report-payload-built-on-stack" }, function(t)
        E:replace(with({ udp = { ["DstPort.Equal"] = 7530, Actions = { "REPORT(3)" } } }))
        local reports = reporting(function() send(7530) end)
        t:assert_eq(#reports, 1, "one report")
        local bytes = reports[1].payload_bytes
        local tag = bytes:byte(1)
        t:assert(tag >= 0x80 and tag <= 0x8f, string.format("a fixmap header: 0x%02x", tag))
        local _, keys, used = S.decode_payload(bytes)
        t:assert_eq(tag - 0x80, #keys, "whose count is the number of keys that follow")
        -- A nested count that disagreed with its keys would misread
        -- everything after it, so the decode would not land on the end.
        t:assert_eq(used, #bytes, "and every map's keys fill the payload exactly")
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
        t:assert_eq((control[1].report.source or {}).address, V6_SRC, "naming the long addresses")
        exactly(t, control[1].report.rule, { "name", "hash", "report-level", "layer", "seat" },
            "a short path is not cut: rule")
        -- The long name as a str16 (3 + 272) where "short" took a fixstr
        -- (1 + 5): the same report, 269 bytes longer.
        local would = #control[1].payload_bytes + (3 + #path) - (1 + #"short")
        t:assert(would > 512, "the whole long path would need " .. would .. " bytes")
        local cut, dd = reporting(function() ntfe.send_frame(peer, pfd, frame(7541)) end)
        t:assert_eq(#cut, 1, "the long-named rule's report reaches KMES")
        t:assert_eq(dd.reports_emitted, 1, "and is counted as emitted")
        local r = cut[1] and cut[1].report and cut[1].report.rule or {}
        t:assert(#cut[1].payload_bytes <= 512, "inside the 512-byte buffer: " .. #cut[1].payload_bytes)
        exactly(t, r, { "name", "hash", "report-level", "layer", "seat", "name-truncated" }, "rule")
        t:assert_eq(r["name-truncated"], true, "rule.name-truncated, a bool, says the path was cut")
        t:assert(#r.name < #path and path:sub(1, #r.name) == r.name,
            "rule.name is a prefix of the path: " .. #r.name .. " of " .. #path .. " characters")
        t:assert_eq(r.hash, ntfe.name_hash(path), "and rule.hash names the whole path")
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
