-- PKM §6.4 — Evaluation, step 1: which rules match. A rule matches only
-- when it is enabled and all of its conditions hold; a list value is an
-- OR inside its one field and the fields are still ANDed; a disabled
-- rule takes its whole subtree with it.
--
-- Every case scopes its rules to its own UDP port in the Packet forest,
-- with no catch-all, so a datagram nothing matches meets the backstop
-- and says so in its event.
--
-- Own VM: the policy is machine-wide state.

local ntfe = require("helpers.ntfe")
local ev = require("helpers.ntfe_eval")

local vm = provium:vm("vntfeevm", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local E = ntfe.engine(vm, ev.policy("Packet", ev.PASS_ALL))

test("a rule matches only when it is enabled and every one of its conditions holds",
    { spec = "PKM *ntfe-eval.rule-matches-iff-enabled-and-all-conditions-hold" }, function(t)
        ev.publish(t, E, ev.policy("Packet", {
            both = { ["DstPort.Equal"] = 7101, ["Protocol.Equal"] = 17, Actions = { "PASS" } },
            ["one-fails"] = { ["DstPort.Equal"] = 7102, ["Protocol.Equal"] = 6, Actions = { "PASS" } },
            off = { ["DstPort.Equal"] = 7103, Enabled = 0, Actions = { "PASS" } },
        }))
        local r = ev.probe(E, 7101)
        local e = r.packet()
        t:assert(e, "the datagram is judged: " .. ntfe.describe(r.events))
        t:assert_eq(e.attributed, "both", "a rule whose conditions all hold matches")
        t:assert_eq(e.verdict, ntfe.VERDICT.PASS, "and its PASS stands")
        t:assert_eq(r.arrived, 1, "so the datagram arrives")

        e = ev.probe(E, 7102).packet()
        t:assert_eq(e.attributed, "backstop",
            "one false condition is enough for a rule not to match")
        t:assert(e.backstop, "and nothing else spoke")

        e = ev.probe(E, 7103).packet()
        t:assert_eq(e.attributed, "backstop",
            "a disabled rule does not match even with every condition holding")
        t:assert_eq(e.verdict, ntfe.VERDICT.DROP, "so the backstop drops")
    end)

test("a list value is a disjunction within its field, and the fields stay a conjunction",
    { spec = "PKM *ntfe-eval.list-value-is-disjunction-within-field" }, function(t)
        ev.publish(t, E, ev.policy("Packet", {
            either = { ["DstPort.Equal"] = { "7111", "7112" }, ["Protocol.Equal"] = 17,
                       Actions = { "PASS" } },
            ["wrong-protocols"] = { ["DstPort.Equal"] = { "7114", "7115" },
                                    ["Protocol.Equal"] = { "6", "132" }, Actions = { "PASS" } },
        }))
        for _, port in ipairs({ 7111, 7112 }) do
            local e = ev.probe(E, port).packet()
            t:assert_eq(e.attributed, "either", "port " .. port .. " is one of the listed values")
        end
        t:assert_eq(ev.probe(E, 7113).packet().attributed, "backstop",
            "a port not in the list does not match")
        t:assert_eq(ev.probe(E, 7114).packet().attributed, "backstop",
            "and a listed port with a protocol in none of the other field's values does not either")
    end)

test("a disabled rule never matches, so nothing beneath it is reachable",
    { spec = "PKM *ntfe-eval.disabled-rule-subtree-unreachable" }, function(t)
        local function tree(enabled, port)
            return {
                ["DstPort.Equal"] = port, Enabled = enabled, Actions = { "DROP" },
                children = { udp = { ["Protocol.Equal"] = 17, Actions = { "PASS" } } },
            }
        end
        ev.publish(t, E, ev.policy("Packet", {
            off = tree(0, 7121),
            on = tree(1, 7122),
        }))
        local e = ev.probe(E, 7122).packet()
        t:assert_eq(e.attributed, "on/udp", "under an enabled parent the exception matches")
        t:assert_eq(e.verdict, ntfe.VERDICT.PASS, "and passes")

        local r = ev.probe(E, 7121)
        e = r.packet()
        t:assert_eq(e.attributed, "backstop",
            "under a disabled parent the same exception never triggers")
        t:assert(e.backstop, "flagged as the backstop's answer")
        t:assert_eq(r.arrived, 0, "and the datagram is dropped")
    end)
