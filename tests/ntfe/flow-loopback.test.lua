-- PKM §6.8 — The Flow layer on loopback, and with no Flow forest: a
-- loopback flow has both its endpoints on this machine, so it is judged
-- twice on its first packet — once at each endpoint's seat, each as
-- that endpoint's direction — holds two sentences, and answers every
-- packet to the stricter of them; a stale sentence of the other
-- endpoint waits for its own seat. Where no Flow forest exists at all,
-- the layer is permissive and caches nothing.
--
-- No peer here: every packet in this VM is a loopback one, so the seat
-- counters move only for what a test sends.
--
-- Own VM: the policy and the clock are machine-wide state, and the
-- first test needs a kernel that has never ingested a policy.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local nf = require("helpers.ntfe_flow")

local vm = provium:vm("vntfeflowlo", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local LO = "127.0.0.1"

-- Generation 0: one datagram on a loopback flow before any policy exists.
local dev = assert(ntfe.open(vm))
local boot_rx = assert(ntfe.udp_bind(vm, LO, 8000))
local boot_tx = assert(ntfe.udp_connect(vm, LO, 8000, { bind = { LO, 8001 } }))
local at_boot = assert(ntfe.status(vm, dev))
ntfe.send(vm, boot_tx, "boot")
local boot_got = ntfe.recv(vm, boot_rx)
local after_boot = assert(ntfe.status(vm, dev))
local boot_flows = assert(ntfe.flows(vm, dev))

local PASS_ALL = { all = { Actions = { "PASS" } } }
local E = ntfe.engine(vm, { RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = PASS_ALL })

local function flow_policy(flow)
    local s = E:replace({ RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = flow })
    assert(s.last_ingest_error == 0, "the policy is accepted: " .. s.last_ingest_error)
    return s
end

-- A loopback UDP flow from `sport` to `dport`: the receiver, and a
-- connected sender (so a refusal lands as its socket error).
local function lo_flow(sport, dport, addr)
    addr = addr or LO
    local rx = assert(ntfe.udp_bind(vm, addr, dport))
    local tx = assert(ntfe.udp_connect(vm, addr, dport, { bind = { addr, sport } }))
    return rx, tx
end

-- Send one datagram and report what became of it: the send's result
-- (an NF_DROP at LOCAL_OUT fails the send with EPERM), the error a
-- refusal parked on the sender, and whether it arrived.
local function shoot(rx, tx, data)
    local r = ntfe.send(vm, tx, data)
    local err = nf.pending_error(vm, tx, 100)
    local got = ntfe.recv(vm, rx, 100)
    return { sent = r.ret == #data, errno = r.errno, err = err, got = got }
end

-- Put the clock 10 minutes into the next whole hour; returns the hour.
local function next_hour()
    local now = math.floor(vm:clock():get())
    local base = now - now % 3600 + 3600
    vm:clock():set(base + 600)
    return (base // 3600) % 24
end

local function find(sport, dport)
    return nf.flow(E, { protocol = ntfe.IPPROTO.UDP, src_port = sport, dst_port = dport })
end

test("no Flow forest at all is permissive, counted, and caches nothing",
    { spec = "PKM *ntfe-flow.no-forest-permissive-uncached" },
    function(t)
        -- Generation 0.
        t:assert_eq(at_boot.generation, 0, "the first datagram was sent at generation 0")
        t:assert_eq(boot_got, "boot", "and was let through")
        t:assert_eq(after_boot.flow_judged - at_boot.flow_judged, 0, "judged by no Flow forest")
        t:assert(after_boot.permissive - at_boot.permissive >= 2,
            "counted as permissive at both endpoints' seats")
        local f = nf.flows_matching(boot_flows, { protocol = ntfe.IPPROTO.UDP, src_port = 8001 })[1]
        t:assert(f, "the flow is tracked")
        t:assert_eq(f.sentences[0].generation, 0, "and holds no sentence in slot 0")
        t:assert_eq(f.sentences[1].generation, 0, "nor in slot 1")
        t:assert_eq(f.judged, 0, "and was never judged")

        -- A published policy with no Flow key.
        local s = E:replace({ RawPacket = PASS_ALL, Packet = PASS_ALL })
        t:assert_eq(s.last_ingest_error, 0, "a policy with no Flow key is accepted")
        local delta = E:during(function()
            t:assert_eq(shoot(boot_rx, boot_tx, "no-forest").got, "no-forest", "and lets the flow through")
        end)
        t:assert_eq(delta.flow_judged, 0, "judging nothing")
        t:assert_eq(delta.permissive, 2, "counted permissive once at each endpoint, the only layer without a forest")
        f = assert(find(8001, 8000))
        t:assert_eq(f.sentences[0].generation + f.sentences[1].generation, 0, "still caching nothing")

        -- With a Flow forest back, the flow is judged from scratch.
        flow_policy(PASS_ALL)
        local d2, events = E:during(function() shoot(boot_rx, boot_tx, "forest") end)
        local judged = nf.flow_events(events, { dst_port = 8000 })
        t:assert_eq(d2.flow_judged, 2, "the next packet is judged at both endpoints")
        t:assert(#judged == 2 and not judged[1].rejudged and not judged[2].rejudged,
            "as a first judgment, with no stale sentence to replace: " .. ntfe.describe(judged))
    end)

test("a loopback flow is judged at both endpoints on its first packet, each as its own direction",
    { spec = "PKM *ntfe-flow.loopback-two-sentences-same-first-packet PKM *ntfe-flow.loopback-view-takes-slot-direction" },
    function(t)
        local s = flow_policy({
            ["out-side"] = { ["Direction.Equal"] = "out", Actions = { "PASS" } },
            ["in-side"] = { ["Direction.Equal"] = "in", Actions = { "PASS" } },
        })
        local rx, tx = lo_flow(8011, 8010)
        local delta, events = E:during(function()
            t:assert_eq(shoot(rx, tx, "first").got, "first", "the first datagram arrives")
        end)
        local judged = nf.flow_events(events, { dst_port = 8010 })
        t:assert_eq(#judged, 2, "and was judged twice: " .. ntfe.describe(judged))
        t:assert_eq(delta.flow_judged, 2, "counted twice")
        t:assert(judged[1].seq < judged[2].seq, "in traversal order")
        t:assert_eq(judged[1].seat, ntfe.SEAT.LOCAL_OUT, "first at the outbound endpoint")
        t:assert_eq(judged[1].direction, ntfe.DIR.OUT, "as `out`")
        t:assert_eq(judged[1].attributed, "out-side", "matching the outbound rule")
        t:assert_eq(judged[2].seat, ntfe.SEAT.LOCAL_IN, "then at the inbound endpoint")
        t:assert_eq(judged[2].direction, ntfe.DIR.IN, "as `in`")
        t:assert_eq(judged[2].attributed, "in-side", "matching the inbound rule")
        local f = assert(find(8011, 8010))
        t:assert_eq(f.loopback, 1, "the dump calls the flow loopback")
        t:assert_eq(f.sentences[0].generation, s.generation, "slot 0 holds the outbound sentence")
        t:assert_eq(f.sentences[0].rule_hash, ntfe.name_hash("out-side"), "by the outbound rule")
        t:assert_eq(f.sentences[1].generation, s.generation, "slot 1 the inbound one")
        t:assert_eq(f.sentences[1].rule_hash, ntfe.name_hash("in-side"), "by the inbound rule")

        -- The reply, re-judged after a new generation: a normal flow's
        -- reply would be turned round to the originator's `in`; on
        -- loopback each seat judges as its own endpoint.
        flow_policy({
            ["out-again"] = { ["Direction.Equal"] = "out", Actions = { "PASS" } },
            ["in-again"] = { ["Direction.Equal"] = "in", Actions = { "PASS" } },
        })
        local _, replies = E:during(function()
            local r = ntfe.sendto(vm, rx, "reply", LO, 8011)
            t:assert_eq(r.ret, 5, "the reply is sent")
            t:assert_eq(ntfe.recv(vm, tx), "reply", "and arrives")
        end)
        local rj = nf.flow_events(replies, { dst_port = 8010 })
        t:assert_eq(#rj, 2, "the reply re-judged both endpoints: " .. ntfe.describe(replies))
        t:assert_eq(rj[1].seat, ntfe.SEAT.LOCAL_OUT, "the outbound seat first")
        t:assert_eq(rj[1].direction, ntfe.DIR.OUT, "still judging as `out`")
        t:assert_eq(rj[1].attributed, "out-again", "by the outbound rule")
        t:assert_eq(rj[1].src_port, 8011, "on the original tuple")
        t:assert_eq(rj[2].direction, ntfe.DIR.IN, "and the inbound seat as `in`")
        t:assert_eq(rj[2].attributed, "in-again", "by the inbound rule")
        sys.close(vm, rx); sys.close(vm, tx)
    end)

test("loopback-ness is the seat's device, not the address",
    { spec = "PKM *ntfe-flow.loopback-by-seat-device" },
    function(t)
        -- An address of our own on another device is still reached
        -- through `lo`.
        -- (Loading the dummy module makes a dummy0 of its own.)
        assert(ntfe.link_add(vm, "dummy7", "dummy"))
        assert(ntfe.if_addr(vm, "dummy7", "10.7.0.1", 24))
        local s = flow_policy(PASS_ALL)
        local rx, tx = lo_flow(8021, 8020, "10.7.0.1")
        local _, events = E:during(function()
            t:assert_eq(shoot(rx, tx, "self").got, "self", "a datagram to our own 10.7.0.1 arrives")
        end)
        t:assert_eq(#nf.flow_events(events, { dst_port = 8020 }), 2,
            "judged at both endpoints, as loopback: " .. ntfe.describe(events))
        local f = assert(find(8021, 8020))
        t:assert_eq(f.src, "10.7.0.1", "the flow is between dummy7's address and itself")
        t:assert_eq(f.loopback, 1, "and is loopback")
        t:assert_eq(f.ifindex, assert(ntfe.if_index(vm, "lo")), "by the device it crossed, lo")
        t:assert_eq(f.sentences[1].generation, s.generation, "with both sentences")
        sys.close(vm, rx); sys.close(vm, tx)
        ntfe.link_del(vm, "dummy7")
    end)

test("every cached packet of a loopback flow answers to the stricter sentence: DROP, REJECT(Refused), REJECT(Prohibited), PASS",
    { spec = "PKM *ntfe-flow.loopback-stricter-sentence-applies" },
    function(t)
        -- DROP over PASS: the inbound endpoint's DROP stops the next
        -- packet at the outbound seat, before it reaches the inbound one.
        flow_policy({
            ["out-ok"] = { ["Direction.Equal"] = "out", Actions = { "PASS" } },
            ["in-drop"] = { ["Direction.Equal"] = "in", Actions = { "DROP" } },
        })
        local rx, tx = lo_flow(8031, 8030)
        local first = shoot(rx, tx, "one")
        t:assert(first.sent and not first.got, "the first datagram leaves and is dropped on arrival")
        local delta, events = E:during(function()
            local second = shoot(rx, tx, "two")
            t:assert(not second.sent, "the next is refused at the outbound seat")
            t:assert_eq(second.errno, sys.E.PERM, "dropped there, failing the send")
        end)
        t:assert_eq(delta.seen_local_in, 0, "it never reached the inbound seat")
        t:assert_eq(#nf.flow_events(events), 0, "no endpoint was judged again")
        t:assert(delta.flow_cached >= 1, "the outbound endpoint read its own PASS, and applied the DROP")
        sys.close(vm, rx); sys.close(vm, tx)

        -- REJECT(Refused) over REJECT(Prohibited), and DROP over REJECT:
        -- the outbound endpoint passes until the hour turns, then refuses
        -- for itself, while the inbound endpoint's sentence stays current.
        for _, c in ipairs({
            { port = 8040, inbound = "REJECT", want_err = sys.E.CONNREFUSED,
              outbound = "REJECT(Prohibited)", why = "the inbound REJECT(Refused)" },
            { port = 8050, inbound = "DROP", want_err = 0,
              outbound = "REJECT", why = "the inbound DROP" },
        }) do
            local hour = next_hour()
            flow_policy({
                ["out-in-hours"] = { ["Direction.Equal"] = "out", ["Time.Hour.Equal"] = hour,
                                     Priority = 10, Actions = { "PASS" } },
                ["out-after"] = { ["Direction.Equal"] = "out", Actions = { c.outbound } },
                ["in-side"] = { ["Direction.Equal"] = "in", Actions = { c.inbound } },
            })
            local r, s2 = lo_flow(c.port + 1, c.port)
            shoot(r, s2, "judged at both")
            next_hour()
            shoot(r, s2, "outbound re-judged")
            local d, ev = E:during(function()
                local third = shoot(r, s2, "cached at both")
                t:assert(not third.sent and not third.got, "a cached packet is stopped")
                t:assert_eq(third.err, c.want_err, "as " .. c.why .. " says, not as the outbound "
                    .. c.outbound .. " does: " .. sys.errname(third.err))
            end)
            t:assert_eq(#nf.flow_events(ev), 0, "with both sentences current and read, not re-judged")
            t:assert_eq(d.refusals_emitted, c.want_err == 0 and 0 or 1, "and refused only as that one says")
            sys.close(vm, r); sys.close(vm, s2)
        end
    end)

test("the packet that re-judges one endpoint answers to the other's stricter sentence too",
    {
        spec = "PKM *ntfe-flow.loopback-stricter-sentence-applies",
        -- PEI-1303. flow.c,
        -- peios_ntfe_flow_dispatch(): when this endpoint's evaluation
        -- yields REJECT, the refusal is sent and NF_DROP returned at once
        -- (lines 441-451), before the comparison with the other
        -- endpoint's sentence (460-466). So the one packet that re-judges
        -- the outbound endpoint to REJECT is refused with that endpoint's
        -- kind even when the inbound endpoint holds a current DROP or a
        -- stricter REJECT(Refused); every later (cached) packet does
        -- answer to the stricter, which the test above shows.
        tags = { "known-bug" },
    },
    function(t)
        -- Both cases run before either is asserted, so a failure reports
        -- the first while the second has still been exercised.
        local cases = {
            { port = 8060, inbound = "DROP", outbound = "REJECT",
              want_err = 0, why = "silently, as the inbound DROP says" },
            { port = 8070, inbound = "REJECT", outbound = "REJECT(Prohibited)",
              want_err = sys.E.CONNREFUSED, why = "as the inbound REJECT(Refused) says" },
        }
        for _, c in ipairs(cases) do
            local hour = next_hour()
            flow_policy({
                ["out-in-hours"] = { ["Direction.Equal"] = "out", ["Time.Hour.Equal"] = hour,
                                     Priority = 10, Actions = { "PASS" } },
                ["out-after"] = { ["Direction.Equal"] = "out", Actions = { c.outbound } },
                ["in-side"] = { ["Direction.Equal"] = "in", Actions = { c.inbound } },
            })
            local r, s2 = lo_flow(c.port + 1, c.port)
            shoot(r, s2, "judged at both")
            next_hour()
            local d, ev = E:during(function()
                c.turned = shoot(r, s2, "outbound re-judged")
            end)
            c.delta, c.events = d, ev
            sys.close(vm, r); sys.close(vm, s2)
        end
        for _, c in ipairs(cases) do
            local rj = nf.flow_events(c.events, { dst_port = c.port })
            t:assert(#rj == 1 and rj[1].rejudged,
                "the outbound endpoint was re-judged at the time edge: " .. ntfe.describe(c.events))
            t:assert(not c.turned.got, "and the packet that re-judged it is stopped")
            t:assert_eq(c.turned.err, c.want_err, "refused " .. c.why .. ", not as the outbound "
                .. c.outbound .. " does: " .. sys.errname(c.turned.err))
            t:assert_eq(c.delta.refusals_emitted, c.want_err == 0 and 0 or 1,
                "and only the stricter sentence's refusal was sent")
        end
    end)

test("a stale sentence of the other endpoint is not applied; its own seat refreshes it",
    { spec = "PKM *ntfe-flow.stale-other-slot-not-applied" },
    function(t)
        flow_policy({
            ["out-ok"] = { ["Direction.Equal"] = "out", Actions = { "PASS" } },
            ["in-drop"] = { ["Direction.Equal"] = "in", Actions = { "DROP" } },
        })
        local rx, tx = lo_flow(8081, 8080)
        shoot(rx, tx, "one")
        t:assert(not shoot(rx, tx, "two").sent, "under one generation the inbound DROP stops packets at the outbound seat")

        flow_policy({
            ["out-ok-2"] = { ["Direction.Equal"] = "out", Actions = { "PASS" } },
            ["in-drop-2"] = { ["Direction.Equal"] = "in", Actions = { "DROP" } },
        })
        local delta, events = E:during(function()
            local three = shoot(rx, tx, "three")
            t:assert(three.sent, "after a new generation the next packet leaves the outbound seat: "
                .. sys.errname(three.errno or 0))
            t:assert(not three.got, "and is dropped at the inbound one")
        end)
        t:assert_eq(delta.seen_local_in, 1, "it reached the inbound seat")
        local judged = nf.flow_events(events, { dst_port = 8080 })
        t:assert_eq(#judged, 2, "both endpoints re-judged it, each at its own seat: " .. ntfe.describe(judged))
        t:assert_eq(judged[1].attributed, "out-ok-2", "the outbound endpoint first")
        t:assert_eq(judged[2].seat, ntfe.SEAT.LOCAL_IN, "the inbound endpoint at its own seat")
        t:assert_eq(judged[2].attributed, "in-drop-2", "refreshing its sentence")
        t:assert(judged[2].rejudged, "as a re-judgment")
        t:assert(not shoot(rx, tx, "four").sent, "and from then on its current DROP applies at the outbound seat again")
        sys.close(vm, rx); sys.close(vm, tx)
    end)
