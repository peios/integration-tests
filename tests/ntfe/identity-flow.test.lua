-- PKM §6.9 — the identities as a flow holds them: looked up once, at
-- the flow's first judgment and only when a Flow forest is published;
-- both ends of a loopback flow resolved by the outbound seat and read
-- by the inbound one; `Remote` absent off loopback; recorded on the
-- conntrack extension and never replaced while the flow lives; and the
-- token reference the record holds let go when conntrack frees it.
--
-- The loopback sender the inbound seat cannot see is reached by
-- injecting a loopback-addressed packet on `lo` through AF_PACKET: it
-- arrives at the inbound seat having passed no outbound one.
--
-- Own VM: the policy is machine-wide state, and the file sets lo's
-- route_localnet and accept_local (for the injected packet) and,
-- briefly, conntrack's UDP timeout.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local token = require("helpers.token")
local id = require("helpers.ntfe_identity")

local vm = provium:vm("vntfeidf", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local peer, net = ntfe.peer(vm)

local w = vm:spawn_worker()
id.set_comm(w, "pit-flow")
local W_PID = id.pid(w)
local AGENT_PID = id.pid(vm)

-- A packet from 127.0.0.1 that arrives on lo without a route attached is
-- a martian unless lo accepts local and loopback sources.
id.sysctl(vm, "/proc/sys/net/ipv4/conf/lo/route_localnet", "1")
id.sysctl(vm, "/proc/sys/net/ipv4/conf/lo/accept_local", "1")

local E = ntfe.engine(vm, id.policy())

local X = { user_sid = token.SID.TEST_USER }
local Y = { user_sid = token.SID.TEST_USER_2 }

local function stamp_as(fd, spec)
    id.as(w, spec, function() id.restamp(w, fd) end)
end

--- A socket on the peer bound to `port`, so datagrams the VM sends there
--- are taken rather than answered with an unreachable (which would
--- turn a connected sender's next send into ECONNREFUSED).
local function sink(port)
    return assert(ntfe.udp_bind(peer, net.peer_addr, port))
end

--- One datagram from the peer to the VM, from `sport`.
local function from_peer(port, sport, data)
    local s = assert(ntfe.udp_connect(peer, net.addr, port, { bind = { net.peer_addr, sport } }))
    ntfe.send(peer, s, data or "x")
    sys.close(peer, s)
end

-- ---- when the lookup runs --------------------------------------------

test("the ends are looked up once per flow, at its first judgment, and only when a Flow forest exists",
    { spec = "PKM *ntfe-identity.lookup-once-per-flow-only-with-flow-forest" }, function(t)
        E:replace(id.policy(nil, { no_flow = true }))
        local s = assert(ntfe.udp_bind(w, net.addr, 7300))
        stamp_as(s, X)
        local delta, events = E:during(function() from_peer(7300, 7301, "unjudged") end)
        t:assert(ntfe.recv(w, s, 300), "with no Flow forest the flow is let through")
        t:assert_eq(#id.flow_events(events), 0, "unjudged")
        t:assert_eq(delta.identity_unresolved, 0, "and nothing was confessed either")
        local rec = id.flow_record(E, ntfe.IPPROTO.UDP, 7300, 7301)
        t:assert(rec, "the flow is tracked")
        t:assert_eq(rec and rec.owners[0].kind, ntfe.LOCAL.ABSENT, "with no end recorded: nothing was looked up")

        -- Who stands there is asked at the first judgment, so a stamp
        -- made since the flow began is the one read.
        stamp_as(s, Y)
        E:replace(id.policy())
        _, events = E:during(function() from_peer(7300, 7301, "first judgment") end)
        local first = id.flow_events(events, { dst_port = 7300 })
        t:assert_eq(#first, 1, "the publication brings the flow its first judgment: " .. ntfe.describe(events))
        t:assert_eq(first[1] and first[1]["local"].user, token.SID.TEST_USER_2,
            "which looks the receiver up then")

        stamp_as(s, X)
        delta, events = E:during(function() from_peer(7300, 7301, "cached") end)
        t:assert_eq(#id.flow_events(events), 0, "later packets are not judged again")
        t:assert(delta.flow_cached >= 1, "they answer to the sentence")
        rec = id.flow_record(E, ntfe.IPPROTO.UDP, 7300, 7301)
        t:assert_eq(rec and rec.owners[0].user, token.SID.TEST_USER_2, "and the end recorded is the one looked up")
        t:assert(ntfe.recv(w, s, 300), "the datagrams arrive")
        sys.close(w, s)
    end)

-- ---- loopback --------------------------------------------------------

--- A loopback UDP flow from the agent (SYSTEM, pid 1) to a socket of w's
--- bound while impersonating Y. Returns the events, the record and the
--- server's port.
local function loopback_flow(t, port_hint)
    E:replace(id.policy())
    local server
    id.as(w, Y, function() server = assert(ntfe.udp_bind(w, "127.0.0.1", 0)) end)
    local port = id.port_of(w, server)
    local _, events = E:during(function()
        local c = assert(ntfe.udp_connect(vm, "127.0.0.1", port))
        ntfe.send(vm, c, port_hint)
        t:assert_eq(ntfe.recv(w, server, 300), port_hint, "the datagram crosses lo")
        sys.close(vm, c)
    end)
    sys.close(w, server)
    return events, id.flow_record(E, ntfe.IPPROTO.UDP, port), port
end

test("the outbound seat resolves both ends of a loopback flow on its first packet",
    { spec = "PKM *ntfe-identity.loopback-outbound-seat-resolves-both-ends",
      tags = { "known-bug" },
      -- PEI-1301. The other end is resolved
      -- by ntfe_identity_receiver() on the outbound packet, whose first
      -- step takes `skb->sk` as an early-demuxed receiver; at LOCAL_OUT
      -- `skb->sk` is the *sending* socket, so the far end is recorded as
      -- the sender. Here the receiver's socket was stamped TEST_USER_2
      -- in pid W_PID and both ends read SYSTEM in pid 1 (the agent), in
      -- the LOCAL_OUT event and in the record's slot 1.
    }, function(t)
        local events, rec, port = loopback_flow(t, "both-ends")
        local out = id.flow_events(events, { seat = ntfe.SEAT.LOCAL_OUT, dst_port = port })
        t:assert_eq(#out, 1, "the outbound seat judged the flow: " .. ntfe.describe(events))
        local l, r = out[1] and out[1]["local"] or {}, out[1] and out[1].remote or {}
        t:assert_eq(l.pid, AGENT_PID, "its own end is the sender, from the socket")
        t:assert_eq(l.user, token.SID.LOCAL_SYSTEM, "SYSTEM")
        t:assert_eq(r.kind, ntfe.LOCAL.PROGRAM, "the other end is resolved there too")
        t:assert_eq(r.user, token.SID.TEST_USER_2, "as the receiving socket's owner: " .. id.describe_end(r))
        t:assert_eq(r.pid, W_PID, "in the receiving process")
        t:assert(rec, "the flow is in the dump")
        t:assert_eq(rec and rec.owners[0].pid, AGENT_PID, "the record's slot 0 is the sender")
        t:assert_eq(rec and rec.owners[1].user, token.SID.TEST_USER_2, "and slot 1 the receiver")
    end)

test("the inbound seat reads a loopback flow's ends from the record: Local its own, Remote the sender",
    { spec = "PKM *ntfe-identity.loopback-inbound-local-own-remote-sender",
      tags = { "known-bug" },
      -- PEI-1301. The inbound seat reads
      -- what the outbound seat recorded, and that recorded the sender
      -- for both slots (see the test above), so the LOCAL_IN judgment's
      -- Local is the sender (SYSTEM, pid 1) instead of the receiving
      -- socket (TEST_USER_2, pid W_PID). Remote is right, by accident.
    }, function(t)
        local events, _, port = loopback_flow(t, "inbound")
        local inb = id.flow_events(events, { seat = ntfe.SEAT.LOCAL_IN, dst_port = port })
        t:assert_eq(#inb, 1, "the inbound seat judged the flow as its own: " .. ntfe.describe(events))
        local l, r = inb[1] and inb[1]["local"] or {}, inb[1] and inb[1].remote or {}
        t:assert_eq(l.user, token.SID.TEST_USER_2, "Local is the receiving end: " .. id.describe_end(l))
        t:assert_eq(l.pid, W_PID, "in the receiving process")
        t:assert_eq(r.user, token.SID.LOCAL_SYSTEM, "Remote is the sender: " .. id.describe_end(r))
        t:assert_eq(r.pid, AGENT_PID, "in the sending process")
    end)

test("a loopback flow whose sender the inbound seat cannot see reads Remote as absent, and confesses it",
    { spec = "PKM *ntfe-identity.loopback-no-extension-remote-absent-confessed" }, function(t)
        -- Failing the extension's allocation is not something a guest
        -- can arrange. The branch it leads to — the inbound seat asked
        -- for a loopback flow's other end with nothing recorded by an
        -- outbound seat — is reached by a packet that never passed one:
        -- a loopback datagram injected on lo with AF_PACKET.
        E:replace(id.policy({
            ["sender-unknown"] = { ["Remote.Present"] = 0, Actions = { "PASS" } },
        }))
        local s = assert(ntfe.udp_bind(w, "0.0.0.0", 7320))
        local p = assert(ntfe.packet_socket(vm, "lo"))
        local udp = ntfe.udp("127.0.0.1", "127.0.0.1", 40320, 7320, "injected")
        local frame = ntfe.eth(string.rep("\0", 6), string.rep("\0", 6), ntfe.ETH_P.IP)
            .. ntfe.ipv4("127.0.0.1", "127.0.0.1", ntfe.IPPROTO.UDP, #udp) .. udp
        local delta, events = E:during(function()
            t:assert_eq(ntfe.send_frame(vm, p, frame).ret, #frame, "the frame is sent on lo")
            t:assert_eq(ntfe.recv(w, s, 500), "injected", "and delivered")
        end)
        sys.close(vm, p); sys.close(w, s)
        local got = id.flow_events(events, { dst_port = 7320 })
        t:assert_eq(#got, 1, "the inbound seat judged it: " .. ntfe.describe(events))
        local e = got[1] or { ["local"] = {}, remote = {} }
        t:assert_eq(e.seat, ntfe.SEAT.LOCAL_IN, "there")
        t:assert_eq(e["local"].kind, ntfe.LOCAL.PROGRAM, "its own end is found")
        t:assert_eq(e.remote.kind, ntfe.LOCAL.ABSENT, "the sender is absent")
        t:assert_eq(e.attributed, "all/sender-unknown", "to the policy as well")
        t:assert(e.remote.unresolved, "and confessed on the end")
        t:assert(e.identity_unresolved, "on the event")
        t:assert(delta.identity_unresolved >= 1, "and in the status")
    end)

test("off loopback Remote is always absent",
    { spec = "PKM *ntfe-identity.remote-absent-off-loopback" }, function(t)
        E:replace(id.policy({
            afar = { ["Remote.Present"] = 0, Actions = { "PASS" } },
        }))
        local s = assert(ntfe.udp_bind(w, net.addr, 7330))
        local _, events = E:during(function()
            from_peer(7330, 7331, "inbound")
            local c = assert(ntfe.udp_connect(w, net.peer_addr, 7332))
            ntfe.send(w, c, "outbound")
            sys.close(w, c)
        end)
        sys.close(w, s)
        for _, c in ipairs({ { "inbound", 7330 }, { "outbound", 7332 } }) do
            local got = id.flow_events(events, { dst_port = c[2] })
            t:assert(#got >= 1, c[1] .. " was judged: " .. ntfe.describe(events))
            local r = got[1] and got[1].remote or {}
            t:assert_eq(r.kind, ntfe.LOCAL.ABSENT, "an " .. c[1] .. " flow has no Remote")
            t:assert(not r.unresolved, "which is the law, not a confession")
            t:assert_eq(got[1] and got[1].attributed, "all/afar", "and Remote.Present = 0 holds")
        end
        -- The same rule on loopback, where a far end exists, does not.
        local events2, _, port = loopback_flow(t, "near")
        local near = id.flow_events(events2, { seat = ntfe.SEAT.LOCAL_OUT, dst_port = port })
        t:assert(#near >= 1 and near[1].remote.kind ~= ntfe.LOCAL.ABSENT,
            "a loopback flow has one: " .. ntfe.describe(events2))
    end)

-- ---- fixed for the flow's life ---------------------------------------

test("the ends recorded at the first judgment are never replaced while the flow lives",
    { spec = "PKM *ntfe-identity.fixed-at-first-judgment" }, function(t)
        local sinks = { sink(7340), sink(7341), sink(7342) }
        -- A restamp, then a re-judgment forced by a policy change.
        E:replace(id.policy())
        local s = assert(ntfe.udp_connect(w, net.peer_addr, 7340))
        stamp_as(s, X)
        local _, events = E:during(function() ntfe.send(w, s, "first") end)
        t:assert_eq(#id.flow_events(events, { dst_port = 7340 }), 1, "the flow is judged as X's")
        stamp_as(s, Y)
        E:replace(id.policy({ bump = id.bump() }))
        _, events = E:during(function() ntfe.send(w, s, "after a restamp and a new policy") end)
        local re = id.flow_events(events, { dst_port = 7340 })
        t:assert(#re == 1 and re[1].rejudged, "the new policy re-judges the flow: " .. ntfe.describe(events))
        t:assert_eq(re[1] and re[1]["local"].user, token.SID.TEST_USER,
            "with the principal of its first judgment, not the restamp's")
        local fresh = assert(ntfe.udp_connect(w, net.peer_addr, 7341))
        id.as(w, Y, function() id.restamp(w, fresh) end)
        _, events = E:during(function() ntfe.send(w, fresh, "a new flow") end)
        local nf = id.flow_events(events, { dst_port = 7341 })
        t:assert_eq(nf[1] and nf[1]["local"].user, token.SID.TEST_USER_2, "while a new flow sees the new stamp")
        sys.close(w, s); sys.close(w, fresh)

        -- A time edge: a sentence that consulted the hour expires when
        -- the hour turns.
        -- Mid-hour, so the judgment cannot straddle a turn by accident.
        local now = math.floor(vm:clock():get() / 3600) * 3600 + 1800
        vm:clock():set(now)
        local hour = math.floor(now / 3600) % 24
        E:replace(id.policy({ ["this-hour"] = { ["Time.Hour.Equal"] = hour, Actions = { "PASS" } } }))
        local timed = assert(ntfe.udp_connect(w, net.peer_addr, 7342))
        stamp_as(timed, X)
        _, events = E:during(function() ntfe.send(w, timed, "this hour") end)
        local first = id.flow_events(events, { dst_port = 7342 })
        t:assert_eq(first[1] and first[1].attributed, "all/this-hour", "the sentence consulted the hour")
        stamp_as(timed, Y)
        vm:clock():set(now + 2 * 3600)
        local delta
        delta, events = E:during(function() ntfe.send(w, timed, "two hours on") end)
        vm:clock():set(now + 1)
        local edge = id.flow_events(events, { dst_port = 7342 })
        t:assert(delta.flow_expired >= 1 and #edge == 1, "the time edge re-judges it: " .. ntfe.describe(events))
        t:assert_eq(edge[1] and edge[1]["local"].user, token.SID.TEST_USER, "with the same principal")
        sys.close(w, timed)
        for _, fd in ipairs(sinks) do sys.close(peer, fd) end

        -- A SO_REUSEPORT sibling taking the port over.
        E:replace(id.policy())
        local a = id.reuseport_udp(w, net.addr, 7343)
        stamp_as(a, X)
        _, events = E:during(function() from_peer(7343, 7344, "to a") end)
        t:assert_eq(ntfe.recv(w, a, 300), "to a", "the first member receives")
        local b = id.reuseport_udp(w, net.addr, 7343)
        stamp_as(b, Y)
        sys.close(w, a)
        E:replace(id.policy({ bump = id.bump() }))
        _, events = E:during(function() from_peer(7343, 7344, "to b") end)
        t:assert_eq(ntfe.recv(w, b, 300), "to b", "the sibling has taken the port over")
        local over = id.flow_events(events, { dst_port = 7343 })
        t:assert(#over == 1 and over[1].rejudged, "the flow is re-judged: " .. ntfe.describe(events))
        t:assert_eq(over[1] and over[1]["local"].user, token.SID.TEST_USER,
            "and still names the member that held the port at its first judgment")
        sys.close(w, b)
    end)

test("the flow holds a counted reference to each end's token and lets it go when conntrack frees the flow",
    { spec = "PKM *ntfe-identity.token-ref-per-slot-released-on-free" }, function(t)
        -- A logon session dies with its last token, and
        -- kacs_destroy_empty_logon_session says EBUSY while any lives:
        -- that is the token's reference count, seen from outside.
        E:replace(id.policy())
        local function principal_sends(port, send)
            local x, session = id.principal(t, vm, X)
            local fd = assert(ntfe.udp_connect(x, net.peer_addr, port, { bind = { net.addr, 0 } }))
            local sport = id.port_of(x, fd)
            if send then ntfe.send(x, fd, "x") end
            sys.close(x, fd)
            x:kill(); x:join()
            return session, sport
        end
        local function busy(session)
            return token.destroy_empty_logon_session(vm, session).errno == sys.E.BUSY
        end
        local function wait_until(pred, ms)
            for _ = 1, ms // 50 do
                if pred() then return true end
                sys.nanosleep(vm, 0, 50000000)
            end
            return pred()
        end

        local quiet = principal_sends(7350, false)
        t:assert(wait_until(function() return not busy(quiet) end, 2000),
            "with no flow, a principal's session goes with its process and socket")

        id.sysctl(vm, "/proc/sys/net/netfilter/nf_conntrack_udp_timeout", "1")
        local ok, err = pcall(function()
            local session, sport = principal_sends(7351, true)
            t:assert(busy(session), "with a judged flow, the token outlives the socket and the process")
            t:assert(wait_until(function()
                return id.flow_record(E, ntfe.IPPROTO.UDP, 7351, sport) == nil
            end, 5000), "the flow times out")
            t:assert(busy(session), "an expired flow conntrack has not freed still holds it")
            -- A packet on the same tuple makes conntrack reap the expired
            -- entry it finds there.
            local again = assert(ntfe.udp_connect(vm, net.peer_addr, 7351, { bind = { net.addr, sport } }))
            ntfe.send(vm, again, "reap")
            sys.close(vm, again)
            t:assert(wait_until(function() return not busy(session) end, 2000),
                "once conntrack frees the flow, the reference is released")
        end)
        id.sysctl(vm, "/proc/sys/net/netfilter/nf_conntrack_udp_timeout", "30")
        if not ok then error(err, 0) end
    end)

test("of two CPUs racing to resolve a new flow, the first record stands and the loser lets go",
    { spec = "PKM *ntfe-identity.resolve-race-first-record-stands",
      covered_by = "kunit:pkm_kunit_ntfe",
      skip = "two CPUs reaching ntfe_flow_identity() for one flow's first " ..
             "packets at once cannot be arranged from the guest, and the " ..
             "outcome (one record, one reference) is identical to the " ..
             "uncontended case; runs under ntfe_kunit_identity_resolve_race, " ..
             "which checks the first record stands. The loser's reference " ..
             "release is not asserted: KACS exposes no token reference count" },
    function(t) end)
