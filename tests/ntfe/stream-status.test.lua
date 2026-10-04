-- PKM §6.7 — the status: the ABI version, the generation and whether
-- anything is enforced, and every counter group of the table, each moved
-- by the traffic that should move it and by nothing else; the two
-- invariants a reader can check (`judged`, `permissive`); and the
-- counters and flows dumps' short-buffer contract.
--
-- The generation-0 half is measured at file scope, before the hive that
-- publishes the first policy is registered.
--
-- Own VM: the policy is machine-wide state, and the first measurement
-- needs a kernel that has never ingested one.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local stream = require("helpers.ntfe_stream")

local vm = provium:vm("vntfestat", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))

-- Generation 0: three datagrams on a fresh flow, judged by no forest.
local dev = assert(ntfe.open(vm))
local g0_before = assert(ntfe.status(vm, dev))
local g0_tx = stream.udp_pair(vm, 7300)
for _ = 1, 3 do assert(ntfe.send(vm, g0_tx, "x").ret == 1) end
local g0_after = assert(ntfe.status(vm, dev))
-- Read on a file of its own and close it, so the engine handle's stream
-- can claim the ring later.
local g0_reader = assert(ntfe.open(vm, sys.O.RDONLY | 0x800))
local g0_events = ntfe.read_events(vm, g0_reader)
sys.close(vm, g0_reader)

local PASS_ALL = { all = { Actions = { "PASS" } } }
local BASE = { RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = PASS_ALL }
local E = ntfe.engine(vm, BASE)

local function with(layer, rules, extra)
    local p = { RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = PASS_ALL }
    local merged = { all = { Actions = { "PASS" } } }
    for name, rule in pairs(rules) do merged[name] = rule end
    p[layer] = merged
    for k, v in pairs(extra or {}) do p[k] = v end
    return p
end

-- A non-IP frame through loopback: out of the egress seat, back in at
-- the ingress seat, where only RawPacket and the Packet fallback see it.
local LOCAL_EXPERIMENTAL = stream.ETH_EXPERIMENTAL
local function non_ip_frame() return stream.lo_frame(vm) end
local function garbage_ipv4_frame() return stream.garbage_ipv4(vm) end

local function count_where(events, pred)
    return #stream.where(events, pred)
end

-- ---- the status itself -------------------------------------------------

test("the status carries ABI version 5",
    { spec = "PKM *ntfe-stream.status-abi-version-5" }, function(t)
        t:assert_eq(g0_before.abi, 5, "before any policy")
        t:assert_eq(E:status().abi, 5, "and after")
    end)

test("the status carries the generation, whether any layer enforces, the ring's drops and the counters",
    { spec = "PKM *ntfe-stream.status-ioctl-contents" }, function(t)
        t:assert_eq(g0_before.generation, 0, "at boot, generation 0")
        t:assert_eq(g0_before.enforcing, 0, "and nothing enforced")
        local s = E:status()
        t:assert(s.generation >= 1, "a published policy is a generation")
        t:assert_eq(s.enforcing, 1, "and enforced")
        local none = E:replace({})
        t:assert_eq(none.last_ingest_error, 0, "a Rules key with no layer under it is a policy")
        t:assert_eq(none.generation, s.generation + 1, "the next generation")
        t:assert_eq(none.enforcing, 0, "in which no layer enforces")
        local back = E:replace(BASE)
        t:assert_eq(back.enforcing, 1, "and a layer coming back enforces again")
        t:assert_eq(back.events_dropped, 0, "no ring overflow is confessed when none happened")
        local delta = E:during(function() ntfe.send(vm, g0_tx, "x") end)
        t:assert(delta.judged > 0 and delta.seen_egress > 0,
            "and the engine counters follow the traffic")
    end)

test("the counters are plain 64-bit atomics, not per-CPU",
    { spec = "PKM *ntfe-stream.counters-plain-64bit-atomics",
      covered_by = "build:pkm/ntfe/ntfe.h",
      skip = "how a counter is stored is invisible from outside: per-CPU " ..
             "counters summed at read would report the same numbers; " ..
             "struct peios_ntfe_stats (atomic64_t members) is where it is held" },
    function(t) end)

-- ---- the counter groups --------------------------------------------------

test("the seat counters count each seat's traversals, and how the ingress seat dealt with them",
    { spec = "PKM *ntfe-stream.counters-seats" }, function(t)
        local tx = stream.udp_pair(vm, 7310)
        ntfe.send(vm, tx, "x")
        local d = E:during(function() ntfe.send(vm, tx, "x") end)
        t:assert_eq(d.seen_local_out, 1, "a datagram on loopback leaves through LOCAL_OUT once")
        t:assert_eq(d.seen_egress, 1, "and the egress seat once")
        t:assert_eq(d.seen_ingress, 1, "comes back through the ingress seat once")
        t:assert_eq(d.seen_local_in, 1, "and LOCAL_IN once")
        t:assert_eq(d.deferred, 1, "an IP traversal at ingress is left for the IP seat")
        t:assert_eq(d.fallback_judged, 0, "not judged there")

        d = E:during(function()
            t:assert(non_ip_frame().ret > 0, "a non-IP frame is sent")
        end)
        t:assert_eq(d.seen_egress, 1, "a non-IP frame crosses egress")
        t:assert_eq(d.seen_ingress, 1, "and ingress")
        t:assert_eq(d.fallback_judged, 1, "where the Packet layer judges it, there being no IP seat")
        t:assert_eq(d.deferred, 0, "rather than deferring it")
        t:assert_eq(d.seen_local_in + d.seen_local_out, 0, "and no IP seat sees it")
    end)

test("the evaluation counters count judged, permissive, unparseable and failed evaluations",
    { spec = "PKM *ntfe-stream.counters-evaluation" }, function(t)
        local tx = stream.udp_pair(vm, 7311)
        ntfe.send(vm, tx, "x")
        local d, events = E:during(function() ntfe.send(vm, tx, "x") end)
        t:assert_eq(d.judged, #events, "every judged evaluation is counted in `judged`")
        t:assert_eq(d.permissive, 0, "with every layer published, none is permissive")
        E:replace({ RawPacket = PASS_ALL, Packet = PASS_ALL })
        d = E:during(function() ntfe.send(vm, tx, "x") end)
        t:assert_eq(d.permissive, 2, "with no Flow forest, both Flow evaluations are `permissive`")
        E:replace(BASE)
        d = E:during(function()
            t:assert(garbage_ipv4_frame().ret > 0, "a frame that says IPv4 and is not")
        end)
        t:assert_eq(d.parse_errors, 2, "is a parse error at egress and again at ingress")
        t:assert_eq(d.fail_closed, 0, "and nothing failed closed throughout")
    end)

test("the verdict counters count each verdict, and each reject that degraded",
    { spec = "PKM *ntfe-stream.counters-verdicts" }, function(t)
        E:replace({
            RawPacket = {
                all = { Actions = { "PASS" } },
                -- A frame that is not IP has no refusal vocabulary.
                mute = { ["EtherType.Equal"] = LOCAL_EXPERIMENTAL, Actions = { "REJECT" } },
            },
            Packet = {
                all = { Actions = { "PASS" } },
                drop = { ["Direction.Equal"] = "in", ["DstPort.Equal"] = 7320, Actions = { "DROP" } },
                refuse = { ["Direction.Equal"] = "in", ["DstPort.Equal"] = 7321,
                           Actions = { "REJECT" } },
            },
            Flow = PASS_ALL,
        })
        local d, events = E:during(function()
            for port = 7320, 7321 do
                local tx = stream.udp_pair(vm, port)
                ntfe.send(vm, tx, "x")
            end
            non_ip_frame()
        end)
        local function n(v) return count_where(events, function(e) return e.verdict == v end) end
        t:assert_eq(d.verdict_pass, n(ntfe.VERDICT.PASS), "verdict_pass counts every PASS")
        t:assert_eq(d.verdict_drop, n(ntfe.VERDICT.DROP), "verdict_drop every DROP")
        t:assert_eq(d.verdict_reject, n(ntfe.VERDICT.REJECT), "verdict_reject every REJECT")
        t:assert_eq(n(ntfe.VERDICT.DROP), 1, "of which there was one DROP")
        t:assert_eq(n(ntfe.VERDICT.REJECT), 2, "and two REJECTs")
        t:assert_eq(d.reject_degraded, 1,
            "reject_degraded counts the one that had nothing to answer with")
        t:assert_eq(count_where(events, function(e) return e.reject_degraded end), 1,
            "the one its event confesses")
        E:replace(BASE)
    end)

test("the effects counters count what evaluations yielded",
    { spec = "PKM *ntfe-stream.counters-effects-yielded" }, function(t)
        E:replace(with("Packet", {
            fx = { ["DstPort.Equal"] = 7330, Priority = 10,
                   Actions = { "PASS", "TAG(a, Set)", "TAG(b, Set)", "COUNT(c)",
                               "REPORT(1)", "PROMPT(h, PASS)" } },
        }))
        local tx = stream.udp_pair(vm, 7330)
        local d, events = E:during(function() ntfe.send(vm, tx, "x") end)
        local fx = ntfe.matching(events, { attributed = "fx" })
        t:assert_eq(#fx, 2, "the rule judged the datagram at egress and at LOCAL_IN")
        t:assert_eq(d.fx_tags, 4, "fx_tags: two TAGs each")
        t:assert_eq(d.fx_counts, 2, "fx_counts: one COUNT each")
        t:assert_eq(d.fx_reports, 2, "fx_reports: one REPORT each")
        t:assert_eq(d.fx_prompts, 2, "fx_prompts: one PROMPT each")
        E:replace(BASE)
    end)

test("the ingestion counters say how the last walk went, when, at what reporting level, and how far it got",
    { spec = "PKM *ntfe-stream.counters-ingestion" }, function(t)
        local before_ns = stream.now_ns(vm)
        local s = E:replace({ RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = PASS_ALL,
                              values = { CurrentReportingLevel = 3 } })
        local after_ns = stream.now_ns(vm)
        t:assert_eq(s.last_ingest_error, 0, "a good policy: last_ingest_error 0")
        t:assert(s.last_ingest_t_ns >= before_ns and s.last_ingest_t_ns <= after_ns,
            "last_ingest_t_ns is the wall-clock moment of that walk")
        t:assert_eq(s.reporting_level, 3, "reporting_level is the generation's CurrentReportingLevel")
        t:assert_eq(s.changes_walked, s.changes_noted, "the walk caught up with every change noted")
        local noted = s.changes_noted
        E:poke()
        t:assert(E:status().changes_noted > noted, "a write under the Network key is noted")
        s = E:settle()
        t:assert(s.changes_walked > noted, "and walked")

        s = E:replace({ RawPacket = PASS_ALL, Packet = PASS_ALL,
                        Flow = { broken = { ["NoSuchFact.Equal"] = 1, Actions = { "PASS" } } } })
        t:assert(s.last_ingest_error ~= 0, "a refused policy: last_ingest_error says why")
        s = E:replace(BASE)
        t:assert_eq(s.reporting_level, 1, "an absent CurrentReportingLevel reads 1")
        t:assert_eq(s.last_ingest_error, 0, "and the next good walk clears the error")

        t:assert_eq(s.contexts, 0, "no inventory: no interface in the context table")
        s = E:replace_inventory({ home = { Name = "Home", Trust = "trusted" } },
                                { lo0 = { Name = "lo", Network = "home" } })
        t:assert_eq(s.contexts, 1, "contexts counts the interfaces netd placed on a network")
        s = E:replace_inventory({}, {})
        t:assert_eq(s.contexts, 0, "and drops them when the inventory does")
    end)

test("the store counters count tag and count writes, what they could not land, reports and cells",
    { spec = "PKM *ntfe-stream.counters-stores" }, function(t)
        local many = { "PASS" }
        for i = 1, 65 do many[#many + 1] = "TAG(t" .. i .. ", Set)" end
        E:replace({
            RawPacket = {
                all = { Actions = { "PASS" } },
                early = { ["Direction.Equal"] = "in", ["DstPort.Equal"] = 7340,
                          Actions = { "PASS", "TAG(early, Set)" } },
                frame = { ["EtherType.Equal"] = LOCAL_EXPERIMENTAL, Actions = { "PASS", "COUNT(s)" } },
            },
            Packet = {
                all = { Actions = { "PASS" } },
                fx = { ["Direction.Equal"] = "in", ["DstPort.Equal"] = 7340,
                       Actions = { "PASS", "TAG(t, Add)", "COUNT(s)", "REPORT(1)" } },
                flood = { ["Direction.Equal"] = "in", ["DstPort.Equal"] = 7341, Actions = many },
                view = { ["Counter.s(1m, SrcAddr).GreaterThan"] = 1000000, Actions = { "DROP" } },
            },
            Flow = PASS_ALL,
        })
        local tx = stream.udp_pair(vm, 7340)
        local d = E:during(function() ntfe.send(vm, tx, "x") end)
        t:assert_eq(d.tag_writes, 1, "tag_writes counts the TAG applied to the flow")
        t:assert_eq(d.tag_untracked, 1, "tag_untracked the one at the ingress seat, which has no flow")
        t:assert_eq(d.count_writes, 1, "count_writes the COUNT landed in a cell")
        t:assert_eq(d.reports_emitted, 1, "reports_emitted the REPORT that reached KMES")
        t:assert(E:status().counter_cells >= 1, "counter_cells the cells that now exist")
        local cells = E:counters()
        t:assert_eq(E:status().counter_cells, cells.total, "as many as the dump lists")

        d = E:during(function() non_ip_frame() end)
        t:assert_eq(d.count_key_absent, 2,
            "count_key_absent the COUNTs of a frame with no address to key by, at both device seats")

        local flood = stream.udp_pair(vm, 7341)
        d = E:during(function() ntfe.send(vm, flood, "x") end)
        t:assert_eq(d.tag_writes, 64, "64 distinct tags land on one flow")
        t:assert_eq(d.tag_refused, 1, "tag_refused the 65th, past the tripwire")
        t:assert_eq(d.count_refused, 0, "count_refused stays for a full table (stream-confessions)")
        E:replace(BASE)
    end)

test("the Flow-layer counters count judgments, cached answers, and the two kinds of staleness",
    { spec = "PKM *ntfe-stream.counters-flow-layer" }, function(t)
        E:replace(with("Flow", {
            timed = { ["Time.Year.GreaterThan"] = 2000, Actions = { "PASS" } },
        }))
        local tx = stream.udp_pair(vm, 7350)
        local d = E:during(function() ntfe.send(vm, tx, "x") end)
        t:assert_eq(d.flow_judged, 2, "flow_judged: a new loopback flow's two endpoints")
        d = E:during(function() ntfe.send(vm, tx, "x") end)
        t:assert_eq(d.flow_cached, 2, "flow_cached: the next datagram answered by both sentences")
        t:assert_eq(d.flow_judged, 0, "with no evaluation")

        E:replace(with("Flow", {
            timed = { ["Time.Year.GreaterThan"] = 2001, Actions = { "PASS" } },
        }))
        d = E:during(function() ntfe.send(vm, tx, "x") end)
        t:assert_eq(d.flow_rejudged, 2, "flow_rejudged: a new generation made both sentences stale")
        t:assert_eq(d.flow_judged, 2, "and both were judged again")

        -- A Year condition was consulted, so each sentence expires at the
        -- next midnight. Two days on, both have.
        local clock = vm:clock()
        local now = clock:get()
        clock:set(now + 2 * 86400)
        d = E:during(function() ntfe.send(vm, tx, "x") end)
        clock:set(now)
        t:assert_eq(d.flow_expired, 2, "flow_expired: a time edge made both sentences stale")
        t:assert_eq(d.flow_rejudged, 0, "which is not counted as a generation's staleness")
        t:assert_eq(d.flow_uncached, 0,
            "flow_uncached: every flow had an extension to hold its sentence")
        E:replace(BASE)
    end)

test("the refusal counters count answers sent, own answers waved through, and far-end teardowns",
    { spec = "PKM *ntfe-stream.counters-refusals" }, function(t)
        E:replace(with("Packet", {
            refuse = { ["Direction.Equal"] = "in", ["DstPort.Equal"] = 7361, Priority = 10,
                       Actions = { "REJECT" } },
        }))
        local listener = assert(ntfe.tcp_listen(vm, "127.0.0.1", 7361))
        local d, events = E:during(function()
            local _, why = ntfe.tcp_connect(vm, "127.0.0.1", 7361, 500)
            t:assert_eq(why, sys.E.CONNREFUSED, "a refused SYN is answered with a reset")
        end)
        sys.close(vm, listener)
        t:assert_eq(d.refusals_emitted, 1, "refusals_emitted counts the answer sent")
        t:assert(d.refusals_bypassed >= 2,
            "refusals_bypassed counts each seat the answer crossed unjudged: " .. d.refusals_bypassed)
        t:assert_eq(#ntfe.matching(events, { src_port = 7361 }), 0,
            "and the answer itself was never judged")

        -- An established connection, then a policy that refuses its data.
        E:replace(BASE)
        listener = assert(ntfe.tcp_listen(vm, "127.0.0.1", 7362))
        local client = assert(ntfe.tcp_connect(vm, "127.0.0.1", 7362))
        local server = assert(ntfe.tcp_accept(vm, listener))
        E:replace(with("Packet", {
            refuse = { ["Direction.Equal"] = "in", ["DstPort.Equal"] = 7362, Priority = 10,
                       Actions = { "REJECT" } },
        }))
        d = E:during(function() ntfe.send(vm, client, "data") end)
        t:assert_eq(d.teardowns_emitted, 1,
            "teardowns_emitted counts the reset sent to the far end of an established flow")
        local _, why = ntfe.recv(vm, server, 500)
        t:assert_eq(why, sys.E.CONNRESET, "which the far end received")
        sys.close(vm, client); sys.close(vm, server); sys.close(vm, listener)
        E:replace(BASE)
    end)

test("identity_unresolved counts endpoints that could not be attributed",
    { spec = "PKM *ntfe-stream.counters-identity",
      covered_by = "kunit:TODO",
      skip = "no guest route makes an endpoint unattributable: every task the " ..
             "agent can run has a token, so every inet socket is stamped " ..
             "(kacs/socket.c), and the inbound seat reads a loopback sender " ..
             "from the flow's extension, which only an atomic allocation " ..
             "failure leaves missing (no fault injection in this kernel). " ..
             "Missing: a kunit case resolving an unstamped socket and an " ..
             "extension-less loopback flow, asserting the counter, the event " ..
             "flag and the record's slot flag" },
    function(t) end)

-- ---- the invariants ------------------------------------------------------

test("judged counts every evaluation against a live forest, Flow included",
    { spec = "PKM *ntfe-stream.judged-counts-live-forest-evaluations" }, function(t)
        local listener = assert(ntfe.tcp_listen(vm, "127.0.0.1", 7370))
        local d, events = E:during(function()
            local fd = ntfe.tcp_connect(vm, "127.0.0.1", 7370)
            t:assert(fd, "a loopback connection")
            ntfe.send(vm, fd, "hello")
            sys.close(vm, fd)
        end)
        sys.close(vm, listener)
        local flow = count_where(events, function(e) return e.layer == ntfe.LAYER.FLOW end)
        t:assert_eq(d.judged, #events, "judged is the number of evaluations, each one event")
        t:assert_eq(d.flow_judged, flow, "flow_judged the Flow evaluations among them")
        t:assert_eq(d.judged - d.flow_judged, #events - flow,
            "so judged - flow_judged is the per-packet count")
        t:assert(flow >= 2 and #events - flow > flow, "with both kinds present")
    end)

test("permissive counts the layer evaluations that found no forest — at generation 0, all of them",
    { spec = "PKM *ntfe-stream.permissive-counts-forestless-evaluations" }, function(t)
        local d = {}
        for _, name in ipairs(ntfe.STATUS_FIELDS) do d[name] = g0_after[name] - g0_before[name] end
        t:assert_eq(d.seen_egress, 3, "three datagrams crossed every seat at generation 0")
        t:assert_eq(d.judged, 0, "none was judged")
        t:assert_eq(#g0_events, 0, "none left an event")
        -- Per traversal: egress Packet and RawPacket, ingress RawPacket (IP
        -- is deferred), LOCAL_IN Packet and Flow, LOCAL_OUT Flow.
        t:assert_eq(d.permissive,
            2 * d.seen_egress + d.seen_ingress + 2 * d.seen_local_in + d.seen_local_out,
            "and every layer evaluation of every traversal was counted permissive")

        E:replace({ RawPacket = PASS_ALL, Packet = PASS_ALL })
        local tx = stream.udp_pair(vm, 7380)
        local p = E:during(function() ntfe.send(vm, tx, "x") end)
        t:assert_eq(p.permissive, p.seen_local_out + p.seen_local_in,
            "under a generation without a Flow forest, exactly the Flow evaluations are")
        t:assert_eq(p.judged, 4, "the published layers being judged")
        E:replace(BASE)
    end)

-- ---- the dumps' short-buffer contract ------------------------------------

test("the counters dump says how many cells it wrote and how many exist",
    { spec = "PKM *ntfe-stream.counters-ioctl-short-buffer-visible" }, function(t)
        E:replace(with("Packet", {
            tally = { ["Direction.Equal"] = "in", ["DstPort.Equal"] = 7390,
                      Actions = { "PASS", "COUNT(cells)" } },
            view = { ["Counter.cells(DstAddr).GreaterThan"] = 1000000, Actions = { "DROP" } },
        }))
        local rx = assert(ntfe.udp_bind(vm, "0.0.0.0", 7390))
        local tx = assert(ntfe.socket(vm, ntfe.AF_INET, ntfe.SOCK_DGRAM))
        for _, dst in ipairs({ "127.0.0.1", "127.0.0.2", "127.0.0.3" }) do
            ntfe.sendto(vm, tx, "x", dst, 7390)
        end
        sys.close(vm, tx); sys.close(vm, rx)
        local all = E:counters(64)
        t:assert_eq(#all, all.total, "a buffer with room gets every cell")
        t:assert(all.total >= 3, "three destinations, three cells at least: " .. all.total)
        local one = E:counters(1)
        t:assert_eq(#one, 1, "a buffer for one gets one")
        t:assert_eq(one.total, all.total, "and is told how many there are")
        local none = E:counters(0)
        t:assert_eq(#none, 0, "an empty buffer gets none")
        t:assert_eq(none.total, all.total, "and is told the same")
        E:replace(BASE)
    end)

test("the flows dump says how many flows it wrote and how many it saw",
    { spec = "PKM *ntfe-stream.flows-ioctl-short-buffer-visible" }, function(t)
        for port = 7395, 7397 do ntfe.send(vm, (stream.udp_pair(vm, port)), "x") end
        local all = E:flows(256)
        t:assert_eq(#all, all.total, "a buffer with room gets every flow")
        t:assert(all.total >= 3, "at least the three just made: " .. all.total)
        local one = E:flows(1)
        t:assert_eq(#one, 1, "a buffer for one gets one")
        t:assert(one.total >= 3 and math.abs(one.total - all.total) <= 2,
            "and is told how many there are")
        local none = E:flows(0)
        t:assert_eq(#none, 0, "an empty buffer gets none")
        t:assert_eq(none.total, one.total, "and is told the same")
    end)
