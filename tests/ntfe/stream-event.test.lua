-- PKM §6.7 — what one event records: one per real evaluation and none
-- for a permissive layer or a cached sentence; the flags; the effect
-- counts packed a byte each; the attributing path, relative to the layer
-- key and cut at 96 bytes; and on a Flow event, both endpoints'
-- identities as the judgment read them.
--
-- Traffic is UDP and TCP on loopback, where one machine is both ends:
-- every datagram crosses the outbound seats and then the inbound ones,
-- so one send shows the whole traversal.
--
-- Own VM: the policy is machine-wide state.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local token = require("helpers.token")
local stream = require("helpers.ntfe_stream")

local vm = provium:vm("vntfeev", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))

local PASS_ALL = { all = { Actions = { "PASS" } } }
local BASE = { RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = PASS_ALL }
local E = ntfe.engine(vm, BASE)

-- A second process for the far end of a loopback flow.
local far = vm:spawn_worker()

local function with(layer, rules)
    local p = { RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = PASS_ALL }
    local merged = { all = { Actions = { "PASS" } } }
    for name, rule in pairs(rules) do merged[name] = rule end
    p[layer] = merged
    return p
end

local function pairs_of(events)
    local seen = {}
    for _, e in ipairs(events) do
        local k = e.seat .. "/" .. e.layer
        seen[k] = (seen[k] or 0) + 1
    end
    return seen
end

-- ---- one event per evaluation ----------------------------------------

test("every evaluation against a published forest appends exactly one event",
    { spec = "PKM *ntfe-stream.each-evaluation-appends-one-event" }, function(t)
        E:replace(BASE)
        local tx = stream.udp_pair(vm, 7200)
        local delta, events = E:during(function()
            t:assert_eq(ntfe.send(vm, tx, "x").ret, 1, "a new flow's first datagram")
        end)
        t:assert_eq(#events, delta.judged, "one event for each evaluation the status counts")
        t:assert_eq(#events, 6, "six evaluations: " .. ntfe.describe(events))
        local seen = pairs_of(events)
        for _, k in ipairs({
            ntfe.SEAT.LOCAL_OUT .. "/" .. ntfe.LAYER.FLOW,
            ntfe.SEAT.EGRESS .. "/" .. ntfe.LAYER.PACKET,
            ntfe.SEAT.EGRESS .. "/" .. ntfe.LAYER.RAWPACKET,
            ntfe.SEAT.INGRESS .. "/" .. ntfe.LAYER.RAWPACKET,
            ntfe.SEAT.LOCAL_IN .. "/" .. ntfe.LAYER.PACKET,
            ntfe.SEAT.LOCAL_IN .. "/" .. ntfe.LAYER.FLOW,
        }) do
            t:assert_eq(seen[k], 1, "seat/layer " .. k .. " recorded once")
        end
    end)

test("a layer with no forest is permissive and emits nothing",
    { spec = "PKM *ntfe-stream.permissive-emits-no-event" }, function(t)
        -- No Flow key at all: that layer has no forest in this generation.
        E:replace({ RawPacket = PASS_ALL, Packet = PASS_ALL })
        local tx = stream.udp_pair(vm, 7201)
        local delta, events = E:during(function()
            t:assert_eq(ntfe.send(vm, tx, "x").ret, 1, "a new flow's first datagram")
        end)
        t:assert_eq(delta.permissive, 2,
            "both Flow evaluations found no forest and were let through")
        t:assert_eq(#ntfe.matching(events, { layer = ntfe.LAYER.FLOW }), 0,
            "and neither left an event: " .. ntfe.describe(events))
        t:assert_eq(#events, delta.judged, "only the judged layers did")
        E:replace(BASE)
    end)

test("a packet answered by its flow's cached sentence emits nothing",
    { spec = "PKM *ntfe-stream.cached-sentence-emits-no-event" }, function(t)
        local tx = stream.udp_pair(vm, 7202)
        local _, first = E:during(function() ntfe.send(vm, tx, "x") end)
        t:assert_eq(#ntfe.matching(first, { layer = ntfe.LAYER.FLOW }), 2,
            "the first datagram is judged at both of the loopback flow's endpoints")
        local delta, events = E:during(function() ntfe.send(vm, tx, "x") end)
        t:assert_eq(delta.flow_cached, 2, "the second is answered by both sentences")
        t:assert_eq(#ntfe.matching(events, { layer = ntfe.LAYER.FLOW }), 0,
            "with no Flow event")
        t:assert_eq(#events, 4, "only the four per-packet evaluations are recorded")
    end)

test("the viewer hides events about its own TCP port, and counts them",
    { spec = "PKM *ntfe-stream.viewer-hides-own-port-events",
      covered_by = "cargo:TODO pnp/pnpd",
      skip = "a statement about pnpd, the userspace viewer, which the " ..
             "kernel-only profile does not run; the kernel's stream carries " ..
             "every event, its own port's included. The filter is " ..
             "pnp/pnpd/src/engine.rs Engine::push (own_hidden), which has no " ..
             "test. Missing: a pnpd unit test pushing TCP events on and off " ..
             "own_port and asserting what is kept and own_verdicts_hidden" },
    function(t) end)

-- ---- what an event says ----------------------------------------------

test("an event's flags name the backstop, a degraded reject and a re-judged sentence",
    { spec = "PKM *ntfe-stream.event-flags" }, function(t)
        -- FAIL_CLOSED and IDENTITY_UNRESOLVED have no guest route (see the
        -- confession stubs in stream-confessions); the three that do are
        -- produced here.
        E:replace({
            RawPacket = {
                all = { Actions = { "PASS" } },
                refuse = { ["EtherType.Equal"] = stream.ETH_EXPERIMENTAL,
                           Actions = { "REJECT(Prohibited)" } },
            },
            Packet = {
                only = { ["DstPort.Equal"] = 7212, Actions = { "PASS" } },
                frames = { ["EtherType.Equal"] = stream.ETH_EXPERIMENTAL, Actions = { "PASS" } },
            },
            Flow = PASS_ALL,
        })
        local tx = stream.udp_pair(vm, 7210)
        local _, events = E:during(function() ntfe.send(vm, tx, "x") end)
        local back = ntfe.matching(events, { layer = ntfe.LAYER.PACKET, dst_port = 7210 })[1]
        t:assert(back, "a packet no Packet rule speaks for is judged: " .. ntfe.describe(events))
        t:assert_eq(back.flags, ntfe.EV_F.BACKSTOP, "flagged BACKSTOP")
        t:assert_eq(back.attributed, "backstop", "attributed to the backstop")
        t:assert_eq(back.verdict, ntfe.VERDICT.DROP, "which dropped it")

        -- A frame that is not IP has no refusal vocabulary.
        _, events = E:during(function() stream.lo_frame(vm) end)
        local degraded = ntfe.matching(events, { attributed = "refuse" })[1]
        t:assert(degraded, "the REJECT of a non-IP frame is recorded: " .. ntfe.describe(events))
        t:assert_eq(degraded.flags, ntfe.EV_F.REJECT_DEGRADED, "flagged REJECT_DEGRADED")
        t:assert_eq(degraded.verdict, ntfe.VERDICT.REJECT, "as the REJECT it was")
        t:assert_eq(degraded.reject_kind, ntfe.REJECT.PROHIBITED, "naming the kind the rule chose")

        tx = stream.udp_pair(vm, 7212)
        ntfe.send(vm, tx, "x")
        E:replace({ RawPacket = PASS_ALL, Packet = PASS_ALL,
                    Flow = { all = { Actions = { "PASS" } }, again = { ["DstPort.Equal"] = 1 } } })
        _, events = E:during(function() ntfe.send(vm, tx, "x") end)
        local rejudged = ntfe.matching(events, { layer = ntfe.LAYER.FLOW })
        t:assert_eq(#rejudged, 2, "a new generation re-judges both endpoints' sentences: "
            .. ntfe.describe(events))
        for _, e in ipairs(rejudged) do
            t:assert_eq(e.flags & ntfe.EV_F.REJUDGED, ntfe.EV_F.REJUDGED, "each flagged REJUDGED")
        end
        for _, e in ipairs(ntfe.matching(events, { layer = ntfe.LAYER.PACKET })) do
            t:assert_eq(e.flags, 0, "and a per-packet event carries no flag it did not earn")
        end
        E:replace(BASE)
    end)

test("an event packs the effect counts a byte each, saturating at 255",
    { spec = "PKM *ntfe-stream.event-effect-counts-packed-saturating" }, function(t)
        local actions = { "PASS" }
        for _ = 1, 300 do actions[#actions + 1] = "TAG(t, Add)" end
        for _, a in ipairs({ "COUNT(c)", "COUNT(c, 2)", "COUNT(c, 3)",
                             "REPORT(1)", "PROMPT(h, PASS)", "PROMPT(h, PASS)" }) do
            actions[#actions + 1] = a
        end
        local s = E:replace(with("Packet", {
            fx = { ["DstPort.Equal"] = 7220, Priority = 10, Actions = actions },
        }))
        t:assert_eq(s.last_ingest_error, 0, "a rule with 306 actions is accepted")
        local tx = stream.udp_pair(vm, 7220)
        ntfe.send(vm, tx, "x")
        local delta, events = E:during(function() ntfe.send(vm, tx, "x") end)
        local fx = ntfe.matching(events, { attributed = "fx", seat = ntfe.SEAT.LOCAL_IN })[1]
        t:assert(fx, "the rule judged the datagram inbound: " .. ntfe.describe(events))
        t:assert_eq(fx.effects & 0xFF, 255, "300 tags saturate the low byte at 255")
        t:assert_eq((fx.effects >> 8) & 0xFF, 3, "without spilling into the counts byte")
        t:assert_eq((fx.effects >> 16) & 0xFF, 1, "reports in the third byte")
        t:assert_eq(fx.effects >> 24, 2, "prompts in the fourth")
        t:assert_eq(delta.fx_tags, 600,
            "while the status counts every tag of both Packet evaluations, unsaturated")
        E:replace(BASE)
    end)

test("an event's path is truncated to 96 bytes",
    { spec = "PKM *ntfe-stream.event-attributed-path-truncated-96" }, function(t)
        local root, child = string.rep("a", 60), string.rep("b", 60)
        E:replace(with("Packet", {
            [root] = { ["DstPort.Equal"] = 7230, Priority = 10, Actions = { "PASS" },
                       children = { [child] = { ["Protocol.Equal"] = "udp",
                                                Actions = { "PASS" } } } },
        }))
        local tx = stream.udp_pair(vm, 7230)
        local _, events = E:during(function() ntfe.send(vm, tx, "x") end)
        local e = ntfe.matching(events, { seat = ntfe.SEAT.LOCAL_IN, layer = ntfe.LAYER.PACKET })[1]
        t:assert(e, "the datagram is judged inbound")
        local path = root .. "/" .. child
        t:assert_eq(#path, 121, "the rule's whole path is 121 bytes")
        t:assert_eq(e.attributed, path:sub(1, 95),
            "the event keeps its first 95 and the terminating NUL")
        E:replace(BASE)
    end)

test("an event's path is relative to the layer key",
    { spec = "PKM *ntfe-stream.path-relative-to-layer-key" }, function(t)
        E:replace(with("Packet", {
            ["no-inbound"] = { ["DstPort.Equal"] = 7240, Priority = 10, Actions = { "DROP" },
                               children = { ssh = { ["SrcAddr.Equal"] = "127.0.0.1",
                                                    Actions = { "PASS" } } } },
        }))
        local tx = stream.udp_pair(vm, 7240)
        local _, events = E:during(function() ntfe.send(vm, tx, "x") end)
        local e = ntfe.matching(events, { seat = ntfe.SEAT.LOCAL_IN, layer = ntfe.LAYER.PACKET })[1]
        t:assert(e, "the datagram is judged inbound: " .. ntfe.describe(events))
        t:assert_eq(e.attributed, "no-inbound/ssh",
            "the exception is named from below the layer key, with `/` between rules")
        E:replace(BASE)
    end)

test("a Flow event carries both endpoints' identities, as binary SIDs",
    { spec = "PKM *ntfe-stream.flow-event-carries-endpoint-identities",
      tags = { "known-bug" },
      -- PEI-1301. The far end of a loopback
      -- flow is recorded as the sender itself: connecting from the agent
      -- (pid 1) to a listener a worker owns (the listeners dump says pid
      -- 220), the LOCAL_OUT Flow event's remote, the LOCAL_IN event's
      -- local and the flow record's slot 1 all read pid 1 and the
      -- connecting thread's comm. identity.c ntfe_identity_receiver()
      -- takes skb->sk as an early-demux result whenever it is a full
      -- socket, but at LOCAL_OUT skb->sk is the socket that sent the
      -- packet, so the "receiver lookup run early" never runs. The local
      -- end's fields are right.
    }, function(t)
        local far_pid = far:syscall(39).ret
        local name = vm:syscall(157, { -- prctl(PR_GET_NAME)
            args = { 16, 0 }, bufs = { string.rep("\0", 16) }, ptrs = { 1 },
        })
        local comm = name.out_bufs[1]:match("^[^%z]*")
        local near_user = token.query(vm, assert(token.open_self(vm)), token.CLASS.USER)
        local far_user = token.query(far, assert(token.open_self(far)), token.CLASS.USER)
        local listener = assert(ntfe.tcp_listen(far, "127.0.0.1", 7250))
        local _, events = E:during(function()
            local fd = ntfe.tcp_connect(vm, "127.0.0.1", 7250)
            t:assert(fd, "a loopback connection to another process")
            if fd then sys.close(vm, fd) end
        end)
        local out = ntfe.matching(events, { layer = ntfe.LAYER.FLOW, seat = ntfe.SEAT.LOCAL_OUT,
                                            dst_port = 7250 })[1]
        local inb = ntfe.matching(events, { layer = ntfe.LAYER.FLOW, seat = ntfe.SEAT.LOCAL_IN,
                                            dst_port = 7250 })[1]
        t:assert(out and inb, "both endpoints are judged: " .. ntfe.describe(events))
        for _, e in ipairs(events) do
            if e.layer ~= ntfe.LAYER.FLOW then
                t:assert(e["local"].kind == 0 and e.remote.kind == 0 and e["local"].pid == 0
                    and e["local"].user == nil,
                    "a per-packet event carries no identity")
            end
        end

        local l, r = out["local"], out.remote
        t:assert_eq(l.kind, ntfe.LOCAL.PROGRAM, "the outbound judgment's own end is a program")
        t:assert_eq(l.pid, 1, "this one, by pid")
        t:assert_eq(l.comm, comm, "and comm, the connecting thread's")
        t:assert_eq(l.user, near_user, "its user SID, binary, as its token has it")
        t:assert_eq(l.service, nil, "and no service SID: it is no service")
        t:assert_neq(l.guid, string.rep("\0", 16), "with a process GUID")

        local owner
        for _, li in ipairs(E:listeners()) do
            if li.port == 7250 then owner = li.owner_pid end
        end
        sys.close(far, listener)
        t:assert_eq(owner, far_pid, "the listener is the other process's, by the listeners dump")
        t:assert_eq(r.kind, ntfe.LOCAL.PROGRAM, "the other end is the listening program")
        t:assert_eq(r.pid, far_pid, "the other process")
        t:assert_eq(r.user, far_user, "with its user SID")
        t:assert_neq(r.guid, l.guid, "and its own GUID")
        t:assert_eq(inb["local"].pid, far_pid, "the inbound judgment's own end is the listener")
        t:assert_eq(inb.remote.pid, 1, "and its remote the connecting program")
        t:assert_eq(inb["local"].guid, r.guid, "the same identities, seen from the other side")
        t:assert_eq(inb.remote.guid, l.guid, "both ways round")
    end)
