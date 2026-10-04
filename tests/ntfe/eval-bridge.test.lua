-- PKM §6.4 — The evaluation as data, and the bridge that carries it:
-- the machinery facts resolved before evaluation (tags for Packet and
-- Flow forests and never for RawPacket, counter views, the Flow
-- forest's own facts), the reporting level passed in, the outcome
-- written, and then — only then — the effects applied: a COUNT after
-- this packet's own view reads, a REPORT naming the verdict just
-- computed. Effects reach their stores by name and hash, a
-- `COUNT(x, Length)` with the packet's length.
--
-- Rules whose store effects are measured carry `Direction.Equal = "out"`
-- so only the EGRESS Packet evaluation of a loopback datagram resolves
-- them. The statements about how the bridge is built — pure core,
-- read-side RCU, atomic allocation, stores that never sleep — have no
-- surface a guest can reach and are cited as skips naming where each is
-- held.
--
-- Own VM: the policy and the counter store are machine-wide state.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local ev = require("helpers.ntfe_eval")

local vm = provium:vm("vntfeevb", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local E = ntfe.engine(vm, ev.policy("Packet", ev.PASS_ALL))

local V, K = ntfe.VERDICT, ntfe.REJECT

-- The Packet forest: a catch-all plus `rules`.
local function packet(rules, values)
    rules.all = { Actions = { "PASS" } }
    return ev.policy("Packet", rules, values)
end

-- Send `n` datagrams on one flow to `port`; returns how many arrived and
-- the events of the whole run.
local function one_flow(port, n)
    local rx = assert(ntfe.udp_bind(vm, "127.0.0.1", port))
    local tx = assert(ntfe.udp_connect(vm, "127.0.0.1", port))
    local arrived, per = 0, {}
    for i = 1, n do
        local _, events = E:during(function() ntfe.send(vm, tx, "datagram " .. i) end)
        local got = ntfe.recv(vm, rx, 300)
        if got then arrived = arrived + 1 end
        per[i] = { arrived = got ~= nil, events = events }
    end
    sys.close(vm, tx)
    sys.close(vm, rx)
    return arrived, per
end

local function egress_packet(events, port)
    return ntfe.matching(events, { seat = ntfe.SEAT.EGRESS, layer = ntfe.LAYER.PACKET,
                                   dst_port = port })[1]
end

-- ---- the evaluation as data ----

test("COUNT(x, Length) counts the packet's length",
    { spec = "PKM *ntfe-eval.count-length-is-packet-length-or-zero" }, function(t)
        -- The kernel's snapshot always has a length, so the "or 0" branch
        -- has no guest route; pnp-core's
        -- tests/laws_machinery.rs::effects_carry_store_identities_and_resolved_amounts
        -- resolves a length-less snapshot's amount to 0.
        ev.publish(t, E, packet({
            bytes = { ["DstPort.Equal"] = 7601, ["Direction.Equal"] = "out",
                      Actions = { "PASS", "COUNT(length-stream, Length)" } },
            viewer = { ["DstPort.Equal"] = 7609, ["Counter.length-stream.GreaterThan"] = 1000000,
                       Actions = { "DROP" } },
        }))
        local e = ev.probe(E, 7601).packet()
        t:assert(e.length > 0, "the evaluation saw a length: " .. e.length)
        local cells = ev.cells(E, "length-stream")
        t:assert_eq(cells[1] and cells[1].total, e.length,
            "and the stream was counted by exactly that many bytes")
    end)

test("effects reach their stores by name and by hash",
    { spec = "PKM *ntfe-eval.effects-carry-name-and-hash" }, function(t)
        ev.publish(t, E, packet({
            named = { ["DstPort.Equal"] = 7611, ["Direction.Equal"] = "out",
                      Actions = { "PASS", "TAG(named-tag, Set, 9)", "COUNT(named-stream)", "REPORT(5)" } },
            viewer = { ["DstPort.Equal"] = 7619, ["Counter.named-stream.GreaterThan"] = 1000000,
                       Actions = { "DROP" } },
        }))
        local reports = ev.reports(t, vm, function() ev.probe(E, 7611) end)
        t:assert_eq(ev.flow_to(E, 7611).tags[ntfe.name_hash("named-tag")], 9,
            "the tag lands on the flow under the FNV-1a hash of its name")
        local cells = ev.cells(E, "named-stream")
        t:assert_eq(#cells, 1, "the count lands in the stream of that name")
        t:assert_eq(cells[1] and cells[1].hash, ntfe.name_hash("named-stream"), "keyed by its hash")
        t:assert_eq(#reports, 1, "the report is emitted")
        t:assert_eq(reports[1] and reports[1].payload.rule, "named", "naming its rule")
        t:assert_eq(reports[1] and reports[1].payload.level, 5, "at its level")
    end)

-- ---- the bridge ----

test("the evaluation runs inside the kernel's RCU read section",
    { spec = "PKM *ntfe-eval.bridge-runs-under-rcu-read-lock",
      covered_by = "build:pkm/ntfe/policy.c",
      skip = "a locking discipline with no outward sign: a guest cannot tell " ..
             "whether the forest it was judged by was held by rcu_read_lock(); " ..
             "peios_ntfe_policy_eval() in policy.c takes it around the call" },
    function(t) end)

test("a RawPacket forest is given no tags, even ones its own layer wrote",
    { spec = "PKM *ntfe-eval.rawpacket-forest-reads-no-tags" }, function(t)
        -- The tag is written at RawPacket on the way out (EGRESS has the
        -- flow); a RawPacket read of it is the same height and so allowed
        -- by ingestion. The Packet layer, which runs first at EGRESS,
        -- witnesses that the tag is there on the second datagram.
        local p = ev.policy("RawPacket", {
            all = { Actions = { "PASS" } },
            marker = { ["DstPort.Equal"] = 7621, ["Direction.Equal"] = "out",
                       Actions = { "PASS", "TAG(rawmark, Set)" } },
            reader = { ["DstPort.Equal"] = 7621, ["Tag.rawmark.Equal"] = 1, Actions = { "DROP" } },
        })
        p.Packet = {
            all = { Actions = { "PASS" } },
            witness = { ["DstPort.Equal"] = 7621, ["Direction.Equal"] = "out",
                        ["Tag.rawmark.Equal"] = 1, Actions = { "PASS", "COUNT(rawmark-seen)" } },
        }
        ev.publish(t, E, p)
        local arrived, per = one_flow(7621, 2)
        local witness = egress_packet(per[2].events, 7621)
        t:assert_eq(witness and witness.fx.counts, 1,
            "the Packet forest reads the tag RawPacket wrote on the first datagram")
        local raw = ntfe.matching(per[2].events, { seat = ntfe.SEAT.EGRESS,
            layer = ntfe.LAYER.RAWPACKET, dst_port = 7621 })[1]
        t:assert(raw, "the RawPacket forest judges the second datagram too")
        t:assert(raw.attributed ~= "reader", "but its rule on the tag never matches")
        t:assert_eq(arrived, 2, "and both datagrams arrive")
    end)

test("the bridge resolves the tags, counter views and Flow facts before evaluating",
    { spec = "PKM *ntfe-eval.bridge-resolves-machinery-facts-before-eval" }, function(t)
        ev.clock_at(vm, 10 * ev.HOUR)
        local p = packet({
            tagger = { ["DstPort.Equal"] = 7631, ["Direction.Equal"] = "out",
                       Actions = { "PASS", "TAG(resolved-tag, Set, 4)", "COUNT(resolved-stream)" } },
            ["tag-reader"] = { ["DstPort.Equal"] = 7631, ["Direction.Equal"] = "out",
                               ["Tag.resolved-tag.Equal"] = 4, Actions = { "PASS", "REPORT(5)" } },
            ["view-reader"] = { ["DstPort.Equal"] = 7631, ["Direction.Equal"] = "out",
                                ["Counter.resolved-stream.GreaterThan"] = 0,
                                Actions = { "PASS", "PROMPT(user, PASS)" } },
        })
        p.Flow = {
            all = { Actions = { "PASS" } },
            facts = { ["DstPort.Equal"] = 7631, ["Related.Equal"] = 0, ["Start.Year.Equal"] = 2026,
                      ["Start.Hour.Equal"] = 10, Priority = 1, Actions = { "PASS" } },
        }
        ev.publish(t, E, p)
        local _, per = one_flow(7631, 2)
        local first = egress_packet(per[1].events, 7631)
        t:assert_eq(first.fx.reports + first.fx.prompts, 0,
            "on the first datagram there is no tag or count to read yet")
        local second = egress_packet(per[2].events, 7631)
        t:assert_eq(second.fx.reports, 1, "on the second the flow's tag was resolved and matched")
        t:assert_eq(second.fx.prompts, 1, "and the stream's view was resolved and matched")
        local flow = ntfe.matching(per[1].events, { seat = ntfe.SEAT.LOCAL_OUT,
            layer = ntfe.LAYER.FLOW, dst_port = 7631 })[1]
        t:assert_eq(flow and flow.attributed, "facts",
            "the Flow forest was given Related and Start.*, and matched on them")
    end)

test("the reporting level is passed to the evaluation",
    { spec = "PKM *ntfe-eval.bridge-passes-reporting-level" }, function(t)
        local s = ev.publish(t, E, packet({
            low = { ["DstPort.Equal"] = 7641, ["Direction.Equal"] = "out", Actions = { "PASS", "REPORT(2)" } },
            high = { ["DstPort.Equal"] = 7642, ["Direction.Equal"] = "out", Actions = { "PASS", "REPORT(3)" } },
        }, { CurrentReportingLevel = 3 }))
        t:assert_eq(s.reporting_level, 3, "the engine holds the published level")
        local low = ev.reports(t, vm, function() ev.probe(E, 7641) end)
        t:assert_eq(#low, 0, "a level-2 report stays below it")
        local high = ev.reports(t, vm, function() ev.probe(E, 7642) end)
        t:assert_eq(#high, 1, "a level-3 report clears it")
    end)

test("the outcome carries the verdict, the reject kind, the backstop flag, the truncated attribution and the expiry",
    { spec = "PKM *ntfe-eval.bridge-writes-outcome" }, function(t)
        local a, b, c = string.rep("a", 40), string.rep("b", 40), string.rep("c", 40)
        local path = a .. "/" .. b .. "/" .. c
        ev.publish(t, E, ev.policy("Packet", {
            [a] = { ["DstPort.Equal"] = 7651, Actions = { "DROP" },
                    children = { [b] = { ["Protocol.Equal"] = 17, Actions = { "DROP" },
                        children = { [c] = { ["SrcAddr.Equal"] = "127.0.0.1",
                                             Actions = { "REJECT(Prohibited)" } } } } } },
        }))
        local r = ev.probe(E, 7651)
        local e = r.packet()
        t:assert_eq(e.verdict, V.REJECT, "the verdict")
        t:assert_eq(e.reject_kind, K.PROHIBITED, "its kind")
        t:assert(not e.backstop, "the backstop flag")
        t:assert_eq(e.attributed, path:sub(1, 95),
            "and the " .. #path .. "-byte attribution cut to the 95 bytes that fit with its NUL")
        t:assert_eq(ev.probe(E, 7652).packet().backstop, true, "the flag is set when the backstop answers")
        local f = ev.flow_to(E, 7651)
        t:assert_eq(f and f.sentences[0].expires_at, 0,
            "an evaluation that consulted no clock has expiry 0, never")
    end)

test("effects are applied after the verdict is written",
    { spec = "PKM *ntfe-eval.effects-applied-after-verdict PKM *ntfe-eval.report-names-the-verdict" },
    function(t)
        -- The reporting rule loses collation: what its report names can
        -- only be the evaluation's verdict, known once collation is done.
        ev.publish(t, E, ev.policy("Packet", {
            reporter = { ["DstPort.Equal"] = { "7661", "7662" }, Actions = { "PASS", "REPORT(3)" } },
            dropper = { ["DstPort.Equal"] = 7661, Actions = { "DROP" } },
            prohibitor = { ["DstPort.Equal"] = 7662, Actions = { "REJECT(Prohibited)" } },
        }))
        local reports = ev.reports(t, vm, function() ev.probe(E, 7661) end)
        t:assert_eq(#reports, 1, "the losing rule reports")
        local p = reports[1] and reports[1].payload or {}
        t:assert_eq(p.rule, "reporter", "as itself")
        t:assert_eq(p.verdict, "DROP", "naming the DROP that won, not its own PASS")
        t:assert_eq(p.layer, "Packet", "in the layer that judged")

        reports = ev.reports(t, vm, function() ev.probe(E, 7662) end)
        p = reports[1] and reports[1].payload or {}
        t:assert_eq(p.verdict, "REJECT", "a REJECT that wins is named")
        t:assert_eq(p.reject_kind, "Prohibited", "with its kind")
    end)

test("a COUNT lands after this packet's own view reads, so a rule cannot trip its own threshold",
    { spec = "PKM *ntfe-eval.count-cannot-trip-own-threshold" }, function(t)
        ev.publish(t, E, packet({
            counter = { ["DstPort.Equal"] = 7671, ["Direction.Equal"] = "out",
                        Actions = { "PASS", "COUNT(trip-stream)" } },
            tripwire = { ["DstPort.Equal"] = 7671, ["Direction.Equal"] = "out",
                         ["Counter.trip-stream.GreaterThan"] = 0, Actions = { "DROP" } },
        }))
        local _, per = one_flow(7671, 2)
        t:assert(per[1].arrived, "the first datagram, whose own COUNT makes the stream 1, passes")
        local e = egress_packet(per[1].events, 7671)
        t:assert(e and e.attributed ~= "tripwire", "the tripwire read the stream before the count")
        t:assert(not per[2].arrived, "the second datagram meets the count the first left")
        e = egress_packet(per[2].events, 7671)
        t:assert_eq(e and e.attributed, "tripwire", "and the tripwire drops it")
    end)

test("every allocation in the lift and the evaluation is GFP_ATOMIC",
    { spec = "PKM *ntfe-eval.bridge-allocations-are-atomic",
      covered_by = "build:pkm/crates/pnp-core/src/pkm_alloc.rs",
      skip = "the allocation flags are not observable from a guest; pkm_alloc's " ..
             "kernel-mode Vec passes GFP_ATOMIC on every allocation, and the " ..
             "bridge allocates through nothing else" },
    function(t) end)

test("an allocation failure in the evaluation fails the hook closed",
    { spec = "PKM *ntfe-eval.allocation-failure-fails-closed",
      covered_by = "kunit:TODO",
      skip = "a guest cannot make a GFP_ATOMIC allocation fail: the kernel is built " ..
             "without CONFIG_FAULT_INJECTION. Wanted: a pkm_kunit_ntfe case that makes " ..
             "ntfe_rust_evaluate() return -ENOMEM for one packet and asserts NF_DROP, " ..
             "fail_closed +1, and an event attributed `fail-closed` with FAIL_CLOSED set" },
    function(t) end)

test("the store calls never sleep",
    { spec = "PKM *ntfe-eval.store-calls-never-sleep",
      covered_by = "build:pkm/ntfe/counters.c",
      skip = "sleeping in the hook would show only as a kernel splat, and the guest " ..
             "has no kernel log; tags.c, counters.c and report.c take only _bh " ..
             "spinlocks, allocate GFP_ATOMIC and emit into a per-CPU ring" },
    function(t) end)

test("evaluation is one pure, allocation-fallible function shared by cargo and the kernel",
    { spec = "PKM *ntfe-eval.evaluate-is-pure-and-shared",
      covered_by = "build:pkm/kernel/stage-rust-core.sh",
      skip = "a statement about the source: the same pnp-core is staged into the " ..
             "kernel and tested under cargo, which a running kernel cannot show" },
    function(t) end)
