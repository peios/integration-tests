-- PKM §6.4 — Evaluation, steps 5 and 6, and the six steps together:
-- every yielded verdict is a candidate; the highest effective priority
-- wins, then the strictest verdict (DROP > REJECT(Refused) >
-- REJECT(Prohibited) > PASS); a rule's priority is its own, else its
-- parent's, else 0; with no candidate at all the compiled-in backstop
-- drops, and says so. What the evaluation hands back is read from the
-- verdict event and, for its expiry, the Flow sentence.
--
-- Own VM: the policy and the wall clock are machine-wide state.

local ntfe = require("helpers.ntfe")
local ev = require("helpers.ntfe_eval")

local vm = provium:vm("vntfeevc", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local E = ntfe.engine(vm, ev.policy("Packet", ev.PASS_ALL))

local V, K = ntfe.VERDICT, ntfe.REJECT

test("the six steps run in order: match, trigger, resolve, abstain, collate, backstop",
    { spec = "PKM *ntfe-eval.six-steps-in-order" }, function(t)
        -- One evaluation that needs every step: a disabled exception is
        -- out at matching; the enabled one triggers and shadows its root;
        -- resolving it yields only a TAG, so it abstains and the root
        -- speaks; collation weighs that DROP (priority 1) against another
        -- tree's PASS (priority 0). A port no rule names falls through all
        -- six to the backstop.
        ev.publish(t, E, ev.policy("Packet", {
            region = {
                ["DstPort.Equal"] = 7501, Priority = 1, Actions = { "DROP", "COUNT(region-spoke)" },
                children = {
                    quiet = { ["Protocol.Equal"] = 17, Actions = { "TAG(quiet-ran, Set)" } },
                    off = { ["SrcAddr.Equal"] = "127.0.0.1", Enabled = 0,
                            Actions = { "PROMPT(user, PASS)" } },
                },
            },
            open = { ["DstPort.Equal"] = 7501, Actions = { "PASS", "REPORT(5)" } },
        }))
        local r = ev.probe(E, 7501)
        local e = r.packet()
        t:assert_eq(e.fx.prompts, 0, "the disabled exception never matched")
        t:assert_eq(e.fx.tags, 1, "the triggered exception resolved its TAG")
        t:assert_eq(e.fx.counts, 1, "abstained, and its root spoke")
        t:assert_eq(e.fx.reports, 1, "the other tree resolved too")
        t:assert_eq(e.attributed, "region", "collation chose the speaker's higher priority")
        t:assert_eq(e.verdict, V.DROP, "and its DROP")
        t:assert(not e.backstop, "so the backstop was not needed")
        t:assert_eq(r.arrived, 0, "and the datagram is dropped")

        e = ev.probe(E, 7502).packet()
        t:assert_eq(e.attributed, "backstop", "where nothing yields, the last step answers")
    end)

test("every yielded verdict is a candidate, a speaker's and a fallback's included",
    { spec = "PKM *ntfe-eval.every-verdict-is-a-candidate" }, function(t)
        local function policy(open_priority)
            return ev.policy("Packet", {
                spoken = {
                    ["DstPort.Equal"] = 7511, Actions = { "DROP" },
                    children = { abstainer = { ["Protocol.Equal"] = 17 } },
                },
                prompted = { ["DstPort.Equal"] = 7512, Actions = { "PROMPT(user, REJECT)" } },
                open = { ["DstPort.Equal"] = { "7511", "7512" }, Priority = open_priority,
                         Actions = { "PASS" } },
            })
        end
        ev.publish(t, E, policy(0))
        t:assert_eq(ev.probe(E, 7511).packet().attributed, "spoken",
            "a speaker's DROP beats a PASS of equal priority")
        local e = ev.probe(E, 7512).packet()
        t:assert_eq(e.attributed, "prompted", "so does a PROMPT fallback's REJECT")
        t:assert_eq(e.verdict, V.REJECT, "as a REJECT")

        ev.publish(t, E, policy(1))
        t:assert_eq(ev.probe(E, 7511).packet().attributed, "open",
            "and both lose to the PASS once it outranks them: each was weighed, not assumed")
        t:assert_eq(ev.probe(E, 7512).packet().attributed, "open", "the fallback's too")
    end)

test("the highest priority wins, and at equal priority the strictest verdict",
    { spec = "PKM *ntfe-eval.highest-priority-then-strictest-wins" }, function(t)
        -- port, winner, loser, verdict, reject kind, what is shown
        local cases = {
            { 7521, { Priority = 10, Actions = { "PASS" } }, { Priority = 5, Actions = { "DROP" } },
              V.PASS, nil, "priority 10 PASS over priority 5 DROP" },
            { 7522, { Actions = { "DROP" } }, { Actions = { "REJECT" } },
              V.DROP, nil, "DROP over REJECT" },
            { 7523, { Actions = { "REJECT(Refused)" } }, { Actions = { "REJECT(Prohibited)" } },
              V.REJECT, K.REFUSED, "REJECT(Refused) over REJECT(Prohibited)" },
            { 7524, { Actions = { "REJECT(Prohibited)" } }, { Actions = { "PASS" } },
              V.REJECT, K.PROHIBITED, "REJECT(Prohibited) over PASS" },
        }
        -- Each pair twice, under names that swap which tree the walk meets
        -- first.
        for _, order in ipairs({ { "a-", "b-" }, { "b-", "a-" } }) do
            local rules = {}
            for _, c in ipairs(cases) do
                local winner, loser = c[2], c[3]
                winner["DstPort.Equal"], loser["DstPort.Equal"] = c[1], c[1]
                rules[order[1] .. c[1]] = winner
                rules[order[2] .. c[1]] = loser
            end
            ev.publish(t, E, ev.policy("Packet", rules))
            for _, c in ipairs(cases) do
                local e = ev.probe(E, c[1]).packet()
                t:assert_eq(e.attributed, order[1] .. c[1], c[6] .. ", " .. order[1] .. " named first")
                t:assert_eq(e.verdict, c[4], "with its verdict")
                if c[5] then t:assert_eq(e.reject_kind, c[5], "and its kind") end
            end
        end
    end)

test("a rule's effective priority is its own, else its parent's, else 0",
    { spec = "PKM *ntfe-eval.effective-priority-inherits-from-parent" }, function(t)
        local function lineage(port, child_priority)
            return {
                ["DstPort.Equal"] = port, Priority = 10, Actions = { "DROP" },
                children = { child = {
                    ["Protocol.Equal"] = 17, Priority = child_priority, Actions = { "PASS" },
                    children = { grandchild = { ["SrcAddr.Equal"] = "127.0.0.1", Actions = { "PASS" } } },
                } },
            }
        end
        ev.publish(t, E, ev.policy("Packet", {
            inherits = lineage(7531, nil),
            overrides = lineage(7532, 1),
            rival = { ["DstPort.Equal"] = { "7531", "7532" }, Priority = 5, Actions = { "DROP" } },
            unranked = { ["DstPort.Equal"] = 7533, Actions = { "DROP" } },
            ranked = { ["DstPort.Equal"] = 7533, Priority = 1, Actions = { "PASS" } },
        }))
        local e = ev.probe(E, 7531).packet()
        t:assert_eq(e.attributed, "inherits/child/grandchild",
            "a grandchild with no Priority of its own carries its grandparent's 10 past a priority-5 DROP")
        t:assert_eq(e.verdict, V.PASS, "and passes")
        t:assert_eq(ev.probe(E, 7532).packet().attributed, "rival",
            "when its parent sets 1, it inherits the nearer value and loses")
        t:assert_eq(ev.probe(E, 7533).packet().attributed, "ranked",
            "a root with no Priority at all stands at 0, below a priority-1 PASS")
    end)

test("with no candidate at all, the backstop drops and the evaluation is flagged",
    { spec = "PKM *ntfe-eval.no-candidate-drops-via-flagged-backstop" }, function(t)
        ev.publish(t, E, ev.policy("Packet", {
            elsewhere = { ["DstPort.Equal"] = 7549, Actions = { "PASS" } },
            closed = { ["DstPort.Equal"] = 7542, Actions = { "DROP" } },
        }))
        local r = ev.probe(E, 7541)
        local e = r.packet()
        t:assert_eq(e.verdict, V.DROP, "nothing matches, and the verdict is DROP")
        t:assert_eq(e.attributed, "backstop", "attributed to the backstop")
        t:assert(e.backstop, "and flagged so")
        t:assert_eq(r.arrived, 0, "the datagram is dropped")
        t:assert(r.delta.verdict_drop >= 1, "and counted as a drop")

        e = ev.probe(E, 7542).packet()
        t:assert(not e.backstop, "a rule's own DROP carries no such flag")
    end)

test("the backstop cannot be removed: a layer with nothing permissive in it drops",
    { spec = "PKM *ntfe-eval.backstop-is-undeletable" }, function(t)
        -- No rules at all, then a catch-all PASS that is switched off:
        -- the permission a policy grants is always a visible rule, and
        -- without one there is only the backstop.
        for _, c in ipairs({
            { {}, "an empty Packet layer" },
            { { all = { Enabled = 0, Actions = { "PASS" } } }, "a layer whose only PASS is disabled" },
        }) do
            local s = ev.publish(t, E, ev.policy("Packet", c[1]))
            t:assert_eq(s.enforcing, 1, c[2] .. " is enforced")
            local r = ev.probe(E, 7551)
            local e = r.packet()
            t:assert(e, c[2] .. " judges the datagram: " .. ntfe.describe(r.events))
            t:assert_eq(e.attributed, "backstop", c[2] .. " answers with the backstop")
            t:assert_eq(e.verdict, V.DROP, "which drops")
            t:assert_eq(r.arrived, 0, "the datagram")
        end
    end)

test("the evaluation hands back the verdict, attribution, backstop flag, effects and expiry",
    { spec = "PKM *ntfe-eval.evaluation-carries-every-candidate-and-effect" }, function(t)
        -- The candidate list itself does not cross the bridge (struct
        -- peios_ntfe_outcome has no field for it); that losers are kept
        -- beside the winner is asserted by pnp-core's
        -- tests/laws_verdicts.rs::higher_priority_beats_stricter_verdict.
        -- Everything else is read here from one Flow evaluation.
        ev.clock_at(vm, 10 * ev.HOUR + 30 * 60)
        ev.publish(t, E, ev.policy("Flow", {
            winner = { ["DstPort.Equal"] = 7561, ["Time.Hour.Equal"] = "9-17", Priority = 2,
                       Actions = { "PASS", "COUNT(winner-stream)" } },
            loser = { ["DstPort.Equal"] = 7561,
                      Actions = { "DROP", "TAG(loser-flow-tag, Set)", "REPORT(5)" } },
        }))
        local r = ev.probe(E, 7561)
        local e = r.flow()
        t:assert(e, "the flow is judged: " .. ntfe.describe(r.events))
        t:assert_eq(e.verdict, V.PASS, "the winning verdict")
        t:assert_eq(e.attributed, "winner", "its attribution")
        t:assert(not e.backstop, "the backstop flag, clear")
        t:assert_eq(e.fx.counts, 1, "the winner's effects")
        t:assert_eq(e.fx.tags, 1, "and the loser's")
        t:assert_eq(e.fx.reports, 1, "every one of them")
        t:assert_eq(ev.flow_to(E, 7561).sentences[0].expires_at, ev.MONDAY + 18 * ev.HOUR,
            "and the expiry, kept as the sentence's")
    end)
