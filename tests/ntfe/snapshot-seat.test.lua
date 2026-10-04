-- PKM §6.3 — the seat facts: the seat, the direction and the interface a
-- traversal stands on, whether that device is the loopback, the length
-- as the stack sees it, and the wall clock — read as UTC with an ISO day
-- of the week, kept as epoch seconds for the Flow layer's sentence expiry,
-- and given to every layer though only the Flow seat acts on its trace.
--
-- Own VM: the policy is machine-wide state, and these tests set the
-- guest's wall clock.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local H = require("helpers.ntfe_snapshot")

local vm = provium:vm("vntfesnseat", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local peer, net = ntfe.peer(vm)
local E = ntfe.engine(vm, H.policy())
local wire = assert(ntfe.packet_socket(peer, net.peer))
local LO_INDEX = assert(ntfe.if_index(vm, "lo"))

local S, L = ntfe.SEAT, ntfe.LAYER

local function publish(t, probes)
    local s = E:replace(H.policy(probes))
    t:assert_eq(s.last_ingest_error, 0, "the probe policy is accepted")
end

local function hms(h, m, s) return h * 3600 + m * 60 + s end

-- ---- seat, direction, interface, loopback ----

test("the seat facts name the direction and the interface, by index and by name",
    { spec = "PKM *ntfe-snapshot.loopback-flag-from-iff-loopback" }, function(t)
        publish(t, {
            Packet = {
                ["veth-in"] = { ["Interface.Equal"] = "veth0", ["Direction.Equal"] = "in" },
                ["veth-out"] = { ["Interface.Equal"] = "veth0", ["Direction.Equal"] = "out" },
                ["lo-in"] = { ["Interface.Equal"] = "lo", ["Direction.Equal"] = "in" },
            },
        })
        local rx = assert(ntfe.udp_bind(vm, net.addr, 7201))
        local prx = assert(ntfe.udp_bind(peer, net.peer_addr, 7202))
        local lrx = assert(ntfe.udp_bind(vm, "127.0.0.1", 7203))
        local _, events = H.watch(E, function()
            local a = assert(ntfe.udp_connect(peer, net.addr, 7201))
            ntfe.send(peer, a, "in")
            local b = assert(ntfe.udp_connect(vm, net.peer_addr, 7202))
            ntfe.send(vm, b, "out")
            local c = assert(ntfe.udp_connect(vm, "127.0.0.1", 7203))
            ntfe.send(vm, c, "lo")
            sys.close(peer, a); sys.close(vm, b); sys.close(vm, c)
        end, {
            { S.LOCAL_IN, L.PACKET, { dst_port = 7201 } },
            { S.EGRESS, L.PACKET, { dst_port = 7202 } },
            { S.LOCAL_IN, L.PACKET, { dst_port = 7203 } },
        })
        sys.close(vm, rx); sys.close(peer, prx); sys.close(vm, lrx)
        for _, c in ipairs({
            { S.LOCAL_IN, 7201, "veth-in", net.ifindex, ntfe.DIR.IN },
            { S.EGRESS, 7202, "veth-out", net.ifindex, ntfe.DIR.OUT },
            { S.LOCAL_IN, 7203, "lo-in", LO_INDEX, ntfe.DIR.IN },
        }) do
            local e = H.at(events, c[1], L.PACKET, { dst_port = c[2] })[1]
            t:assert(e, "the datagram to " .. c[2] .. " was judged: " .. ntfe.describe(events))
            t:assert_eq(e.attributed, c[3], "matched by interface name and direction")
            t:assert_eq(e.ifindex, c[4], "and carries the interface's index")
            t:assert_eq(e.direction, c[5], "and the direction")
        end
    end)

test("a flow on the loopback device has two local endpoints, so the Flow layer judges it twice",
    { spec = "PKM *ntfe-snapshot.loopback-flag-from-iff-loopback" }, function(t)
        publish(t, {})
        local lrx = assert(ntfe.udp_bind(vm, "127.0.0.1", 7204))
        local prx = assert(ntfe.udp_bind(peer, net.peer_addr, 7205))
        local _, events = H.watch(E, function()
            local c = assert(ntfe.udp_connect(vm, "127.0.0.1", 7204))
            ntfe.send(vm, c, "lo")
            t:assert_eq(ntfe.recv(vm, lrx, 500), "lo", "the loopback datagram arrives")
            local b = assert(ntfe.udp_connect(vm, net.peer_addr, 7205))
            ntfe.send(vm, b, "veth")
            t:assert_eq(ntfe.recv(peer, prx, 500), "veth", "the wire datagram arrives")
            sys.close(vm, c); sys.close(vm, b)
        end, {
            { S.LOCAL_IN, L.FLOW, { dst_port = 7204 } },
            { S.LOCAL_OUT, L.FLOW, { dst_port = 7205 } },
        })
        sys.close(vm, lrx); sys.close(peer, prx)
        local lo = ntfe.matching(events, { layer = L.FLOW, dst_port = 7204 })
        t:assert_eq(#lo, 2, "the loopback flow is judged once per endpoint: " .. ntfe.describe(lo))
        t:assert_eq(#H.at(lo, S.LOCAL_OUT, L.FLOW), 1, "as the sender at LOCAL_OUT")
        t:assert_eq(#H.at(lo, S.LOCAL_IN, L.FLOW), 1, "and as the receiver at LOCAL_IN")
        local wired = ntfe.matching(events, { layer = L.FLOW, dst_port = 7205 })
        t:assert_eq(#wired, 1, "while the flow over the veth is judged once: " .. ntfe.describe(wired))
        for _, f in ipairs(E:flows()) do
            if f.dst_port == 7204 then t:assert_eq(f.loopback, 1, "the dump calls the first loopback") end
            if f.dst_port == 7205 then t:assert_eq(f.loopback, 0, "and the second not") end
        end
    end)

-- ---- length ----

test("the length is the stack's view of the packet at the seat, not the wire's",
    { spec = "PKM *ntfe-snapshot.length-is-skb-len" }, function(t)
        publish(t, { RawPacket = { len48 = { ["Length.Equal"] = 48 } }, Packet = { len28 = { ["Length.Equal"] = 28 } } })
        -- 14 bytes of Ethernet header, a 28-byte IPv4/UDP datagram, and 20
        -- bytes of trailing padding the IP header does not count: 62 on
        -- the wire.
        local frame = H.udp_frame(net, 5000, 7206) .. string.rep("\0", 20)
        t:assert_eq(#frame, 62, "the frame is 62 bytes long")
        -- Nothing listens on 7206, so the VM answers port-unreachable.
        local unreachable = { protocol = ntfe.IPPROTO.ICMP, dst = net.peer_addr }
        local _, events = H.inject(E, peer, wire, frame, {
            { S.INGRESS, L.RAWPACKET, { dst_port = 7206 } },
            { S.LOCAL_IN, L.PACKET, { dst_port = 7206 } },
            { S.EGRESS, L.PACKET, unreachable },
        })
        local raw = H.at(events, S.INGRESS, L.RAWPACKET, { dst_port = 7206 })[1]
        local pkt = H.at(events, S.LOCAL_IN, L.PACKET, { dst_port = 7206 })[1]
        t:assert(raw and pkt, "both seats judged it: " .. ntfe.describe(events))
        t:assert_eq(raw.length, 48,
            "at ingress the link header is already pulled and the padding not yet trimmed")
        t:assert_eq(raw.attributed, "len48", "and the Length fact says the same")
        t:assert_eq(pkt.length, 28, "at LOCAL_IN the IP layer has trimmed the datagram to its own length")
        t:assert_eq(pkt.attributed, "len28", "and the Length fact follows")
        -- Outbound, the egress seat stands after the link header is pushed.
        local answer = H.at(events, S.EGRESS, L.PACKET, unreachable)[1]
        t:assert(answer, "the answer was judged at egress: " .. ntfe.describe(events))
        t:assert_eq(answer.length, 14 + 20 + 8 + 28,
            "counting its Ethernet header, the IP and ICMP headers and the quoted datagram")
    end)

-- ---- the clock ----

test("the clock is read as UTC, with the day of the week numbered ISO, 1 = Monday to 7 = Sunday",
    { spec = "PKM *ntfe-snapshot.clock-is-utc-with-iso-day-of-week" }, function(t)
        local probes = {}
        for d = 1, 7 do probes["dow" .. d] = { ["Time.DayOfWeek.Equal"] = d } end
        publish(t, { RawPacket = probes })
        for d = 1, 7 do
            -- TUESDAY is ISO day 2.
            vm:clock():set(H.TUESDAY + (d - 2) * 86400 + hms(13, 45, 30))
            local port = 7210 + d
            local _, events = H.inject(E, peer, wire, H.udp_frame(net, 5000, port),
                { { S.INGRESS, L.RAWPACKET, { dst_port = port } } })
            local got, desc = H.attribution(events, S.INGRESS, L.RAWPACKET, { dst_port = port })
            t:assert_eq(got, "dow" .. d, "day " .. d .. " of the ISO week reads " .. d .. ": " .. desc)
        end
        -- One instant, every calendar field: 23:59:30 on Tuesday 22
        -- September 2026, UTC.
        publish(t, { RawPacket = { calendar = {
            ["Time.Year.Equal"] = 2026, ["Time.Month.Equal"] = 9, ["Time.DayOfMonth.Equal"] = 22,
            ["Time.DayOfWeek.Equal"] = 2, ["Time.Hour.Equal"] = 23, ["Time.Minute.Equal"] = 59,
            ["Time.Second.Equal"] = "30-50",
        } } })
        vm:clock():set(H.TUESDAY + hms(23, 59, 30))
        local _, events = H.inject(E, peer, wire, H.udp_frame(net, 5000, 7218),
            { { S.INGRESS, L.RAWPACKET, { dst_port = 7218 } } })
        local got, desc = H.attribution(events, S.INGRESS, L.RAWPACKET, { dst_port = 7218 })
        t:assert_eq(got, "calendar", "every Time fact is the UTC calendar of the epoch second: " .. desc)
    end)

test("the clock is kept as epoch seconds, from which the sentence's expiry is reckoned",
    { spec = "PKM *ntfe-snapshot.clock-kept-as-epoch-seconds" }, function(t)
        publish(t, { Flow = { minute = { ["Time.Minute.Equal"] = 20, ["DstPort.Equal"] = 7220 } } })
        local prx = assert(ntfe.udp_bind(peer, net.peer_addr, 7220))
        local tx = assert(ntfe.udp_connect(vm, net.peer_addr, 7220))
        vm:clock():set(H.TUESDAY + hms(10, 20, 15))
        local _, events = H.watch(E, function()
            ntfe.send(vm, tx, "a")
            t:assert_eq(ntfe.recv(peer, prx, 500), "a", "the first datagram goes out")
        end, { { S.LOCAL_OUT, L.FLOW, { dst_port = 7220 } } })
        local got, desc = H.attribution(events, S.LOCAL_OUT, L.FLOW, { dst_port = 7220 })
        t:assert_eq(got, "minute", "the flow is judged in minute 20: " .. desc)
        local sentence
        for _, f in ipairs(E:flows()) do
            if f.dst_port == 7220 then sentence = f.sentences[0] end
        end
        t:assert(sentence, "the flow holds a sentence")
        t:assert_eq(sentence.expires_at, H.TUESDAY + hms(10, 21, 0),
            "which expires at the exact epoch second minute 20 ends")

        vm:clock():set(H.TUESDAY + hms(10, 21, 5))
        local delta, ev2 = H.watch(E, function()
            ntfe.send(vm, tx, "b")
            t:assert_eq(ntfe.recv(peer, prx, 500), "b", "the second datagram goes out")
        end, { { S.LOCAL_OUT, L.FLOW, { dst_port = 7220 } } })
        local again = H.at(ev2, S.LOCAL_OUT, L.FLOW, { dst_port = 7220 })[1]
        t:assert(again, "past the expiry the flow is judged again: " .. ntfe.describe(ev2))
        t:assert(again.rejudged, "flagged as a re-judgment")
        t:assert_eq(again.attributed, "all", "now outside minute 20")
        t:assert_eq(delta.flow_expired, 1, "and counted as an expiry")
        sys.close(vm, tx); sys.close(peer, prx)
    end)

test("the clock is given to every layer",
    { spec = "PKM *ntfe-snapshot.clock-and-time-trace-given-to-every-layer" }, function(t)
        local hour = { ["Time.Hour.Equal"] = 9 }
        publish(t, { RawPacket = { hour = hour }, Packet = { hour = hour }, Flow = { hour = hour } })
        vm:clock():set(H.TUESDAY + hms(9, 15, 0))
        local rx = assert(ntfe.udp_bind(vm, net.addr, 7221))
        local _, events = H.inject(E, peer, wire, H.udp_frame(net, 5000, 7221, "x"), {
            { S.INGRESS, L.RAWPACKET, { dst_port = 7221 } },
            { S.LOCAL_IN, L.PACKET, { dst_port = 7221 } },
            { S.LOCAL_IN, L.FLOW, { dst_port = 7221 } },
        })
        sys.close(vm, rx)
        for _, c in ipairs({
            { S.INGRESS, L.RAWPACKET, "RawPacket" }, { S.LOCAL_IN, L.PACKET, "Packet" },
            { S.LOCAL_IN, L.FLOW, "Flow" },
        }) do
            local got, desc = H.attribution(events, c[1], c[2], { dst_port = 7221 })
            t:assert_eq(got, "hour", c[3] .. " reads the hour: " .. desc)
        end
        -- And the trace of the consulted condition with it: the Flow
        -- sentence's expiry is the hour's end.
        for _, f in ipairs(E:flows()) do
            if f.dst_port == 7221 then
                t:assert_eq(f.sentences[0].expires_at, H.TUESDAY + hms(10, 0, 0),
                    "the Flow judgment carried its time trace into the sentence")
            end
        end
    end)

test("only the Flow seat acts on the time trace: a per-packet time condition expires nothing",
    { spec = "PKM *ntfe-snapshot.only-flow-seat-acts-on-time-trace" }, function(t)
        publish(t, { Packet = { minute = { ["Time.Minute.Equal"] = 40, ["DstPort.Equal"] = 7222 } } })
        local prx = assert(ntfe.udp_bind(peer, net.peer_addr, 7222))
        local tx = assert(ntfe.udp_connect(vm, net.peer_addr, 7222))
        vm:clock():set(H.TUESDAY + hms(8, 40, 10))
        local _, events = H.watch(E, function()
            ntfe.send(vm, tx, "a")
            ntfe.recv(peer, prx, 500)
        end, { { S.EGRESS, L.PACKET, { dst_port = 7222 } }, { S.LOCAL_OUT, L.FLOW, { dst_port = 7222 } } })
        local got, desc = H.attribution(events, S.EGRESS, L.PACKET, { dst_port = 7222 })
        t:assert_eq(got, "minute", "the Packet layer consulted the minute: " .. desc)
        for _, f in ipairs(E:flows()) do
            if f.dst_port == 7222 then
                t:assert_eq(f.sentences[0].expires_at, 0,
                    "but the Flow sentence, which consulted no time, never expires")
            end
        end
        vm:clock():set(H.TUESDAY + hms(8, 41, 10))
        local delta, ev2 = H.watch(E, function()
            ntfe.send(vm, tx, "b")
            ntfe.recv(peer, prx, 500)
        end, { { S.EGRESS, L.PACKET, { dst_port = 7222 } } })
        local got2, desc2 = H.attribution(ev2, S.EGRESS, L.PACKET, { dst_port = 7222 })
        t:assert_eq(got2, "all", "past the flip the Packet layer simply answers differently: " .. desc2)
        t:assert_eq(#H.at(ev2, nil, L.FLOW, { dst_port = 7222 }), 0,
            "while the flow's sentence still stands, unjudged")
        t:assert_eq(delta.flow_expired, 0, "and nothing expired")
        sys.close(vm, tx); sys.close(peer, prx)
    end)
