-- PKM §6.7, "Confessions, collected" — everything NTFE declines to do is
-- counted in the status: a reject it could not send, a frame it could
-- not describe, a tag or a count it could not land, a packet a sentence
-- answered, a refusal it waved through, a generation it refused, an
-- event it could not keep. Each is provoked here and found where the
-- list says; the two with no guest route are stubs naming the unit
-- test that runs them.
--
-- The last test reads the status the earlier ones left behind, so this
-- file runs top to bottom.
--
-- Own VM: the policy and the counters are machine-wide state.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local stream = require("helpers.ntfe_stream")

local vm = provium:vm("vntfeconf", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))

local PASS_ALL = { all = { Actions = { "PASS" } } }
local BASE = { RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = PASS_ALL }
local E = ntfe.engine(vm, BASE)

local function with(layer, rules)
    local p = { RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = PASS_ALL }
    local merged = { all = { Actions = { "PASS" } } }
    for name, rule in pairs(rules) do merged[name] = rule end
    p[layer] = merged
    return p
end

-- A generation refused along the way, for the summary.
local refused_error

test("a REJECT it could not send is counted in reject_degraded and flagged on its event",
    { spec = "PKM *ntfe-stream.confess-reject-degraded" }, function(t)
        E:replace(with("RawPacket", {
            refuse = { ["EtherType.Equal"] = stream.ETH_EXPERIMENTAL, Actions = { "REJECT" } },
        }))
        -- A non-IP frame, which no refusal can answer. The egress seat's
        -- drop fails the send itself.
        local d, events = E:during(function() stream.lo_frame(vm) end)
        t:assert_eq(d.reject_degraded, 1, "the REJECT degraded and was counted")
        t:assert_eq(d.refusals_emitted, 0, "nothing having been sent")
        local e = ntfe.matching(events, { attributed = "refuse" })[1]
        t:assert(e, "the REJECT has its event: " .. ntfe.describe(events))
        t:assert(e.reject_degraded, "flagged REJECT_DEGRADED")
        t:assert_eq(e.verdict, ntfe.VERDICT.REJECT, "still a REJECT")
        t:assert_eq(d.seen_ingress, 0, "the frame dropped at egress, as a DROP would have")
        E:replace(BASE)
    end)

test("an evaluation it could not finish is counted in fail_closed and has an event",
    { spec = "PKM *ntfe-stream.confess-fail-closed",
      covered_by = "kunit:pkm_kunit_ntfe",
      skip = "evaluation fails only when a GFP_ATOMIC allocation is refused " ..
             "mid-walk (ntfe_rust_evaluate's -ENOMEM paths); this kernel has " ..
             "no fault injection (CONFIG_FAULT_INJECTION is off), so the guest " ..
             "cannot cause one; runs under ntfe_kunit_eval_failure_fails_closed, " ..
             "which forces peios_ntfe_policy_eval to answer -ENOMEM through a " ..
             "KUnit-only seam and asserts the drop, fail_closed, and the " ..
             "`fail-closed` event with the FAIL_CLOSED flag (the Rust " ..
             "allocator's own refusal is not exercised)" },
    function(t) end)

test("a frame it could not describe is counted in parse_errors",
    { spec = "PKM *ntfe-stream.confess-parse-errors" }, function(t)
        local d, events = E:during(function()
            t:assert(stream.garbage_ipv4(vm).ret > 0, "a frame that says IPv4 and is version 0")
        end)
        t:assert_eq(d.parse_errors, 2, "counted at egress and again at ingress")
        t:assert(#events >= 1, "while the frame is still judged on what could be read")
        for _, e in ipairs(events) do
            t:assert_eq(e.addr_family, 0, "which holds no IP facts")
        end
    end)

test("a tag it could not write is counted in tag_untracked or tag_refused",
    { spec = "PKM *ntfe-stream.confess-tag-not-written" }, function(t)
        local many = { "PASS" }
        for i = 1, 65 do many[#many + 1] = "TAG(t" .. i .. ", Set)" end
        E:replace({
            RawPacket = {
                all = { Actions = { "PASS" } },
                early = { ["Direction.Equal"] = "in", ["DstPort.Equal"] = 7410,
                          Actions = { "PASS", "TAG(early, Set)" } },
            },
            Packet = {
                all = { Actions = { "PASS" } },
                flood = { ["Direction.Equal"] = "in", ["DstPort.Equal"] = 7411, Actions = many },
            },
            Flow = PASS_ALL,
        })
        local tx = stream.udp_pair(vm, 7410)
        local d = E:during(function() ntfe.send(vm, tx, "x") end)
        t:assert_eq(d.tag_untracked, 1, "a TAG at the ingress seat, before any flow exists")
        t:assert_eq(d.tag_writes, 0, "writes nothing")

        tx = stream.udp_pair(vm, 7411)
        d = E:during(function() ntfe.send(vm, tx, "x") end)
        t:assert_eq(d.tag_refused, 1, "a 65th distinct tag on one flow is refused")
        t:assert_eq(d.tag_writes, 64, "the first 64 having landed")
        E:replace(BASE)
    end)

test("a count it could not land is counted in count_key_absent or count_refused",
    { spec = "PKM *ntfe-stream.confess-count-not-landed" }, function(t)
        E:replace({
            RawPacket = {
                all = { Actions = { "PASS" } },
                frames = { ["EtherType.Equal"] = stream.ETH_EXPERIMENTAL,
                           Actions = { "PASS", "COUNT(by_src)" } },
            },
            Packet = {
                all = { Actions = { "PASS" } },
                tally = { ["Direction.Equal"] = "in", ["DstPort.Equal"] = 7420,
                          Actions = { "PASS", "COUNT(by_dst)" } },
                v1 = { ["Counter.by_src(1m, SrcAddr).GreaterThan"] = 1000000, Actions = { "DROP" } },
                v2 = { ["Counter.by_dst(1m, DstAddr).GreaterThan"] = 1000000, Actions = { "DROP" } },
            },
            Flow = PASS_ALL,
        })
        local d = E:during(function() stream.lo_frame(vm) end)
        t:assert_eq(d.count_key_absent, 2,
            "a frame with no source address has no cell in a SrcAddr table, at either device seat")
        t:assert_eq(d.count_writes, 0, "and lands nowhere")

        -- Every 127/8 address is this machine's: 4100 destinations, 4100
        -- keys, in a table capped at 4096 whose cells are all fresh.
        local rx = assert(ntfe.udp_bind(vm, "0.0.0.0", 7420))
        local tx = assert(ntfe.socket(vm, ntfe.AF_INET, ntfe.SOCK_DGRAM))
        local before = E:status()
        for i = 0, 4099 do
            ntfe.sendto(vm, tx, "", string.format("127.1.%d.%d", i // 256, i % 256), 7420)
        end
        local after = E:status()
        sys.close(vm, tx); sys.close(vm, rx)
        t:assert_eq(after.count_writes - before.count_writes, 4096, "4096 keys get a cell")
        t:assert_eq(after.count_refused - before.count_refused, 4,
            "and the four past the cap, with nothing idle to reap, are refused")
        E:replace(BASE)
    end)

-- "A sentence it could not keep → flow_uncached" is confessed in
-- flow-sentence.test.lua, which has the means to make a flow with no
-- extension (a ctnetlink entry) and cites this list's anchor beside its
-- own.

test("an endpoint it could not attribute is counted in identity_unresolved and flagged on its event",
    { spec = "PKM *ntfe-stream.confess-identity-unresolved",
      covered_by = "kunit:pkm_kunit_ntfe",
      skip = "every guest task has a token, so every inet socket is stamped " ..
             "(kacs/socket.c pkm_kacs_socket_stamp_owner), and the inbound " ..
             "seat reads a loopback sender from the flow's extension, missing " ..
             "only on an allocation failure; no route leaves an endpoint " ..
             "unattributed; runs under ntfe_kunit_identity_unresolved: an " ..
             "unstamped socket resolves as KERNEL + unresolved, counted in " ..
             "identity_unresolved and flagged " ..
             "PEIOS_NTFE_EV_F_IDENTITY_UNRESOLVED on its event" },
    function(t) end)

test("a packet a current sentence answered is counted in flow_cached instead of judged",
    { spec = "PKM *ntfe-stream.confess-flow-cached" }, function(t)
        local tx, rx = stream.udp_pair(vm, 7430)
        ntfe.send(vm, tx, "first")
        t:assert(ntfe.recv(vm, rx), "the flow's first datagram is judged and delivered")
        local d, events = E:during(function() ntfe.send(vm, tx, "second") end)
        t:assert_eq(ntfe.recv(vm, rx), "second", "the next one is delivered")
        t:assert_eq(d.flow_cached, 2, "answered by both of its endpoints' sentences, counted")
        t:assert_eq(d.flow_judged, 0, "not judged")
        t:assert_eq(#ntfe.matching(events, { layer = ntfe.LAYER.FLOW }), 0,
            "and leaving no Flow event, the counter being the only trace")
    end)

test("a refusal it did not judge because it was its own is counted in refusals_bypassed",
    { spec = "PKM *ntfe-stream.confess-refusals-bypassed" }, function(t)
        E:replace(with("Packet", {
            refuse = { ["Direction.Equal"] = "in", ["DstPort.Equal"] = 7440, Priority = 10,
                       Actions = { "REJECT" } },
        }))
        local d, events = E:during(function()
            local _, why = ntfe.tcp_connect(vm, "127.0.0.1", 7440, 500)
            t:assert_eq(why, sys.E.CONNREFUSED, "the SYN is answered with a reset")
        end)
        t:assert_eq(d.refusals_emitted, 1, "one answer was built and sent")
        t:assert(d.refusals_bypassed >= 1,
            "the seats it crossed waved it through, counted: " .. d.refusals_bypassed)
        t:assert_eq(#ntfe.matching(events, { src_port = 7440 }), 0,
            "and none of them judged it: " .. ntfe.describe(events))
        E:replace(BASE)
    end)

test("a generation it could not accept is confessed in last_ingest_error",
    { spec = "PKM *ntfe-stream.confess-ingest-error" }, function(t)
        local before = E:status()
        local s = E:replace({
            RawPacket = PASS_ALL, Packet = PASS_ALL,
            Flow = { broken = { ["Bogus.Equal"] = 1, Actions = { "PASS" } } },
        })
        refused_error = s.last_ingest_error
        t:assert(s.last_ingest_error ~= 0, "the refusal is in the status: " .. s.last_ingest_error)
        t:assert_eq(s.generation, before.generation, "and the generation in force is the old one")
        t:assert(s.last_ingest_t_ns > before.last_ingest_t_ns, "dated by the walk that refused it")
        E:replace(BASE)
    end)

test("everything NTFE declines to do is counted somewhere in the status",
    { spec = "PKM *ntfe-stream.every-refusal-counted" }, function(t)
        -- What this file provoked, read back from the status at the end:
        -- every reachable confession has moved since the engine came up.
        -- The viewer's half of the sentence is pnpd's, outside this
        -- profile. fail_closed, flow_uncached and identity_unresolved are
        -- in the status, but nothing here can move them (stubs above).
        local s = E:status()
        for _, c in ipairs({
            "reject_degraded", "fail_closed", "parse_errors", "tag_untracked",
            "tag_refused", "count_key_absent", "count_refused", "flow_uncached",
            "identity_unresolved", "flow_cached", "refusals_bypassed",
            "last_ingest_error", "events_dropped",
        }) do
            t:assert(s[c] ~= nil, c .. " is a status counter")
        end
        for _, c in ipairs({
            "reject_degraded", "parse_errors", "tag_untracked", "tag_refused",
            "count_key_absent", "count_refused", "flow_cached", "refusals_bypassed",
        }) do
            t:assert(s[c] > E.zero[c], c .. " confessed what it declined: " .. s[c])
        end
        t:assert(refused_error and refused_error ~= 0, "last_ingest_error the generation refused")
        -- The 4100 new flows above left some 24000 events nobody read.
        t:assert(s.events_dropped > E.zero.events_dropped,
            "events_dropped the events nobody read in time: " .. s.events_dropped)
    end)
