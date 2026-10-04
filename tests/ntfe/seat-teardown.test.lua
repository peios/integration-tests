-- PKM §6.2 — tearing down the far end. When a REJECT refuses a packet of
-- an established TCP connection, the refused end hears the kind's story
-- and the far end is reset too: the refused packet itself, turned into
-- a RST and sent where it was going. Counted; never for a new flow, for
-- UDP, for a reset, or from the ingress seat.
--
-- An established flow is refused by changing the policy under it: the
-- next packet re-judges the flow (§6.8) and meets the REJECT. Both
-- sockets are then asked what happened, and the resets are read off the
-- wire (the peer's packet socket) and off loopback (a tap in the VM).
--
-- Own VM: the policy is machine-wide state.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local seat = require("helpers.ntfe_seat")

local vm = provium:vm("vntfeseatteardown", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local peer, net = ntfe.peer(vm)
local ADDR6, PEER6 = "fd09::1", "fd09::2"
assert(seat.addr6(vm, net.name, ADDR6))
assert(seat.addr6(peer, net.peer, PEER6))
local E = ntfe.engine(vm, seat.policy())
local wire = assert(ntfe.packet_socket(peer, net.peer))
local lotap = assert(ntfe.packet_socket(vm, "lo"))

local REJECT = ntfe.VERDICT.REJECT

local function use(extra)
    local s = E:replace(seat.policy(extra))
    assert(s.last_ingest_error == 0, "the test policy ingests: " .. s.last_ingest_error)
end

local function on_port(port, action)
    return { ["DstPort.Equal"] = port, Actions = { action } }
end

local function is_rst(f) return f.tcp and f.tcp.flags & ntfe.TCP.RST ~= 0 end

-- A connection made under the baseline: `inbound` means the peer called
-- us. Returns the client and server fds (client on the caller's side).
local function establish(t, port, inbound, v6)
    use()
    local mine, theirs = v6 and ADDR6 or net.addr, v6 and PEER6 or net.peer_addr
    local server_who, client_who = vm, peer
    local addr = mine
    if not inbound then server_who, client_who, addr = peer, vm, theirs end
    local l = assert(ntfe.tcp_listen(server_who, addr, port))
    local c = assert(ntfe.tcp_connect(client_who, addr, port))
    local s = assert(ntfe.tcp_accept(server_who, l))
    -- One round trip, so the flow is past its handshake both ways.
    ntfe.send(client_who, c, "hello")
    t:assert(ntfe.recv(server_who, s, 300), "the connection carries data before the change")
    ntfe.send(server_who, s, "hello back")
    t:assert(ntfe.recv(client_who, c, 300), "both ways")
    sys.close(server_who, l)
    return { client = c, server = s, client_who = client_who, server_who = server_who }
end

local function close(conn)
    sys.close(conn.client_who, conn.client)
    sys.close(conn.server_who, conn.server)
end

-- ---- the far end is torn down ------------------------------------------------

test("an inbound packet of an established TCP flow refused at LOCAL_IN resets both ends",
    { spec = "PKM *ntfe-seat.established-tcp-reject-tears-down-far-end PKM *ntfe-seat.teardowns-counted" },
    function(t)
        for _, v6 in ipairs({ false, true }) do
            local fam = v6 and "IPv6" or "IPv4"
            local port = v6 and 7311 or 7301
            local conn = establish(t, port, true, v6)
            use({ Flow = { refused = on_port(port, "REJECT") } })
            seat.flush(peer, wire)
            ntfe.frames(vm, lotap, 20)
            local delta, events = E:during(function()
                ntfe.send(peer, conn.client, "refuse this")
                local _, why = ntfe.recv(peer, conn.client, 300)
                t:assert_eq(why, sys.E.CONNRESET, fam .. ": the refused end is reset by the refusal")
                _, why = ntfe.recv(vm, conn.server, 300)
                t:assert_eq(why, sys.E.CONNRESET, fam .. ": and our own end, the far one, is reset too")
            end)
            local ev = ntfe.matching(events, { attributed = "refused", verdict = REJECT })
            t:assert(#ev >= 1 and ev[1].flow_state == ntfe.FLOW_STATE.ESTABLISHED,
                fam .. ": the refused packet was of an established flow: " .. ntfe.describe(ev))
            t:assert_eq(delta.teardowns_emitted, 1, fam .. ": one teardown, counted in teardowns_emitted")
            t:assert_eq(delta.refusals_emitted, 1, fam .. ": beside the one refusal")
            -- The teardown is the refused packet itself, reset, delivered
            -- over loopback to the socket it was going to.
            local data = seat.to_vm(peer, net, wire, 100, function(f)
                return f.tcp and f.tcp.dport == port and not is_rst(f)
            end)
            local refused = data[#data]
            local resets = {}
            for _, f in ipairs(ntfe.frames(vm, lotap, 100)) do
                if is_rst(f) and f.tcp.dport == port then resets[#resets + 1] = f end
            end
            t:assert(refused and #resets >= 1, fam .. ": the reset crossed loopback")
            if refused and resets[1] then
                local r = resets[1]
                t:assert_eq(r.tcp.sport, refused.tcp.sport, fam .. ": from the refused packet's port")
                t:assert_eq(r.tcp.seq, refused.tcp.seq, fam .. ": with its sequence number")
                t:assert_eq(r.tcp.ack, refused.tcp.ack, fam .. ": and its acknowledgement")
                local src = v6 and r.ip6 and r.ip6.src or (r.ip and r.ip.src)
                t:assert_eq(src, v6 and ntfe.ip6(PEER6) or net.peer_addr, fam .. ": and its source address")
            end
            close(conn)
        end
    end)

test("an outbound packet of an established TCP flow refused at LOCAL_OUT resets the peer on the wire",
    { spec = "PKM *ntfe-seat.established-tcp-reject-tears-down-far-end PKM *ntfe-seat.teardowns-counted" },
    function(t)
        for _, v6 in ipairs({ false, true }) do
            local fam = v6 and "IPv6" or "IPv4"
            local port = v6 and 7312 or 7302
            local conn = establish(t, port, false, v6)
            seat.flush(peer, wire)
            use({ Flow = { refused = on_port(port, "REJECT") } })
            -- The last segment we put on the wire before the change has the
            -- sequence number the refused one will carry: nothing was sent
            -- in between.
            local delta = E:during(function()
                ntfe.send(vm, conn.client, "refuse this")
                local _, why = ntfe.recv(vm, conn.client, 300)
                t:assert_eq(why, sys.E.CONNRESET, fam .. ": our socket, the refused end, is reset")
                _, why = ntfe.recv(peer, conn.server, 300)
                t:assert_eq(why, sys.E.CONNRESET, fam .. ": and the peer, the far end, is reset too")
            end)
            t:assert_eq(delta.teardowns_emitted, 1, fam .. ": one teardown, counted")
            local resets = seat.from_vm(peer, net, wire, 100, function(f)
                return is_rst(f) and f.tcp.dport == port
            end)
            t:assert_eq(#resets, 1, fam .. ": one reset reached the peer from us")
            if resets[1] then
                local r = resets[1]
                local src = v6 and r.ip6 and r.ip6.src or (r.ip and r.ip.src)
                t:assert_eq(src, v6 and ntfe.ip6(ADDR6) or net.addr, fam .. ": from our address")
                t:assert_eq(r.tcp.flags & ntfe.TCP.PSH, 0, fam .. ": carrying no data")
            end
            close(conn)
        end
    end)

-- ---- and when it is not ------------------------------------------------------

test("a new flow and a UDP flow have no far end to tear down",
    { spec = "PKM *ntfe-seat.no-teardown-for-new-flow-or-udp" }, function(t)
        use({ Flow = { refused = on_port(7303, "REJECT"), out = on_port(7304, "REJECT") } })
        local l = assert(ntfe.tcp_listen(vm, net.addr, 7303))
        local pl = assert(ntfe.tcp_listen(peer, net.peer_addr, 7304))
        local delta = E:during(function()
            ntfe.tcp_connect(peer, net.addr, 7303, 300)
            ntfe.tcp_connect(vm, net.peer_addr, 7304, 100)
        end)
        t:assert_eq(delta.refusals_emitted, 2, "two new TCP flows were refused, in each direction")
        t:assert_eq(delta.teardowns_emitted, 0, "and neither was torn down")
        sys.close(vm, l)
        sys.close(peer, pl)
        -- A UDP flow that has seen traffic both ways, then refused.
        use()
        local u = assert(ntfe.udp_bind(vm, net.addr, 7305))
        local pu = assert(ntfe.udp_connect(peer, net.addr, 7305, { bind = { net.peer_addr, 5305 } }))
        ntfe.send(peer, pu, "ping")
        t:assert(ntfe.recv(vm, u, 300), "the UDP flow carries a datagram in")
        ntfe.sendto(vm, u, "pong", net.peer_addr, 5305)
        t:assert(ntfe.recv(peer, pu, 300), "and a reply out")
        use({ Flow = { udp = on_port(7305, "REJECT") } })
        local d2, events = E:during(function()
            ntfe.send(peer, pu, "refuse this")
            local _, why = ntfe.recv(peer, pu, 300)
            t:assert_eq(why, sys.E.CONNREFUSED, "the established UDP flow is refused")
        end)
        local ev = ntfe.matching(events, { attributed = "udp" })
        t:assert(#ev >= 1 and ev[1].flow_state == ntfe.FLOW_STATE.ESTABLISHED,
            "as an established flow: " .. ntfe.describe(ev))
        t:assert_eq(d2.refusals_emitted, 1, "one refusal")
        t:assert_eq(d2.teardowns_emitted, 0, "and no teardown")
        sys.close(peer, pu)
        sys.close(vm, u)
    end)

test("a reset is never answered with a reset",
    { spec = "PKM *ntfe-seat.no-teardown-of-a-reset" }, function(t)
        -- The first packet after the change is the peer's RST (SO_LINGER
        -- zero). Refused, its refusal would be a RST answering a RST: the
        -- builder declines and the REJECT degrades. Prohibited, the peer
        -- is told with an ICMP — and still no reset follows.
        for _, c in ipairs({
            { 7306, "REJECT", 0, 1, "Refused" },
            { 7307, "REJECT(Prohibited)", 1, 0, "Prohibited" },
        }) do
            local port, action, refusals, degraded, kind = c[1], c[2], c[3], c[4], c[5]
            local conn = establish(t, port, true, false)
            use({ Flow = { refused = on_port(port, action) } })
            seat.flush(peer, wire)
            local delta, events = E:during(function()
                seat.linger_zero(peer, conn.client)
                sys.close(peer, conn.client)
                local _, why = ntfe.recv(vm, conn.server, 300)
                t:assert_eq(why, "timeout", kind .. ": the peer's RST was refused, so our socket never heard it")
            end)
            local ev = ntfe.matching(events, { attributed = "refused" })
            t:assert(#ev >= 1, kind .. ": the RST was judged: " .. ntfe.describe(events))
            t:assert_eq(delta.refusals_emitted, refusals, kind .. ": refusals sent")
            t:assert_eq(delta.reject_degraded, degraded, kind .. ": degraded")
            t:assert_eq(delta.teardowns_emitted, 0, kind .. ": and no teardown")
            local resets = seat.from_vm(peer, net, wire, 100, is_rst)
            t:assert_eq(#resets, 0, kind .. ": no reset went back on the wire")
            sys.close(vm, conn.server)
        end
    end)

test("the ingress seat has no flow facts and never tears down",
    { spec = "PKM *ntfe-seat.ingress-never-tears-down" }, function(t)
        local conn = establish(t, 7308, true, false)
        use({ RawPacket = { refused = on_port(7308, "REJECT") } })
        local delta, events = E:during(function()
            ntfe.send(peer, conn.client, "refuse this")
            local _, why = ntfe.recv(peer, conn.client, 300)
            t:assert_eq(why, sys.E.CONNRESET, "the peer is refused from the ingress seat")
            _, why = ntfe.recv(vm, conn.server, 300)
            t:assert_eq(why, "timeout", "and our end, which never saw the packet, is left alone")
        end)
        local ev = ntfe.matching(events, { attributed = "refused" })
        t:assert(#ev >= 1 and ev[1].seat == ntfe.SEAT.INGRESS, "the refusal was the ingress seat's")
        t:assert_eq(ev[1] and ev[1].flow_state, ntfe.FLOW_STATE.ABSENT, "where there are no flow facts")
        t:assert_eq(delta.refusals_emitted, 1, "one refusal")
        t:assert_eq(delta.teardowns_emitted, 0, "and no teardown, though the connection was established")
        close(conn)
    end)
