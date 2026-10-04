-- PKM §6.4 — Evaluation, steps 2 and 4: the trigger set and abstention.
-- A node triggers when it matches and no child does; a matching child
-- shadows its parent, and only within one lineage. A triggered rule
-- with no verdict climbs its own parentage to the nearest ancestor with
-- a direct verdict, which speaks for the region once; the ancestors in
-- between execute nothing, and a branch with no speaker contributes
-- nothing.
--
-- Who ran is read from the effect counts of the one evaluation under
-- test (the Packet layer at EGRESS): each rule in a tree carries a
-- different species of side effect — COUNT, TAG, REPORT, PROMPT — so the
-- counts say exactly which action lists resolved. The default
-- `CurrentReportingLevel` is 1, so a REPORT that resolved is always
-- counted.
--
-- Own VM: the policy is machine-wide state.

local ntfe = require("helpers.ntfe")
local ev = require("helpers.ntfe_eval")

local vm = provium:vm("vntfeevs", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local E = ntfe.engine(vm, ev.policy("Packet", ev.PASS_ALL))

local V = ntfe.VERDICT

-- ---- the trigger set ----

test("a matching child shadows its parent",
    { spec = "PKM *ntfe-eval.matching-child-shadows-its-parent" }, function(t)
        local function tree(port, child_protocol)
            return {
                ["DstPort.Equal"] = port, Actions = { "DROP", "COUNT(parent-ran)" },
                children = { exception = { ["Protocol.Equal"] = child_protocol, Actions = { "PASS" } } },
            }
        end
        ev.publish(t, E, ev.policy("Packet", {
            shadowed = tree(7301, 17),
            ["not-shadowed"] = tree(7302, 6),
        }))
        local r = ev.probe(E, 7301)
        local e = r.packet()
        t:assert_eq(e.attributed, "shadowed/exception", "the matching exception triggers")
        t:assert_eq(e.verdict, V.PASS, "with its own verdict")
        t:assert_eq(e.fx.counts, 0, "and the parent it shadows executes nothing")
        t:assert_eq(r.arrived, 1, "so the datagram arrives")

        e = ev.probe(E, 7302).packet()
        t:assert_eq(e.attributed, "not-shadowed", "a parent whose child does not match triggers itself")
        t:assert_eq(e.verdict, V.DROP, "and drops")
        t:assert_eq(e.fx.counts, 1, "running its own side effects")
    end)

test("two trees never shadow each other, and their order means nothing",
    { spec = "PKM *ntfe-eval.trees-never-shadow-each-other" }, function(t)
        -- The same two trees under swapped names, so the walk meets them
        -- in the other order.
        for _, names in ipairs({ { "a-open", "z-closed" }, { "z-open", "a-closed" } }) do
            ev.publish(t, E, ev.policy("Packet", {
                [names[1]] = { ["DstPort.Equal"] = 7311, Actions = { "PASS", "COUNT(open-ran)" } },
                [names[2]] = { ["DstPort.Equal"] = 7311, ["Protocol.Equal"] = 17,
                               Actions = { "DROP", "TAG(closed-ran, Set)" } },
            }))
            local e = ev.probe(E, 7311).packet()
            t:assert_eq(e.fx.counts, 1, names[1] .. " triggers though " .. names[2] .. " also matches")
            t:assert_eq(e.fx.tags, 1, "and so does " .. names[2])
            t:assert_eq(e.attributed, names[2], "collation, not shadowing, picks between them")
            t:assert_eq(e.verdict, V.DROP, "the stricter at equal priority")
        end
    end)

test("a match deep in a lineage is reported up, so every ancestor knows it was shadowed",
    { spec = "PKM *ntfe-eval.walk-reports-match-to-parent" }, function(t)
        ev.publish(t, E, ev.policy("Packet", {
            top = {
                ["DstPort.Equal"] = 7321, Actions = { "DROP", "COUNT(top-ran)" },
                children = { mid = {
                    ["Protocol.Equal"] = 17, Actions = { "REJECT", "REPORT(5)" },
                    children = {
                        leaf = { ["SrcAddr.Equal"] = "127.0.0.1", Actions = { "PASS", "TAG(leaf-ran, Set)" } },
                        missing = { ["SrcAddr.Equal"] = "10.0.0.1", Actions = { "DROP" } },
                    },
                } },
            },
        }))
        local r = ev.probe(E, 7321)
        local e = r.packet()
        t:assert_eq(e.attributed, "top/mid/leaf", "the deepest match triggers")
        t:assert_eq(e.verdict, V.PASS, "and its verdict is the answer")
        t:assert_eq(e.fx.tags, 1, "its side effects run")
        t:assert_eq(e.fx.reports, 0, "its parent learned it was shadowed and ran nothing")
        t:assert_eq(e.fx.counts, 0, "and so did the grandparent, two levels up")
        t:assert_eq(r.arrived, 1, "so the datagram arrives")
    end)

-- ---- abstention ----

test("an abstaining rule climbs to its nearest ancestor with a verdict, which speaks for it",
    { spec = "PKM *ntfe-eval.abstainer-climbs-to-nearest-verdict-ancestor PKM *ntfe-eval.speaker-verdict-attributed-to-speaker" },
    function(t)
        ev.publish(t, E, ev.policy("Packet", {
            gp = {
                ["DstPort.Equal"] = 7331, Actions = { "DROP", "REPORT(5)" },
                children = { parent = {
                    ["Protocol.Equal"] = 17, Actions = { "PASS", "COUNT(speaker-ran)" },
                    children = { leaf = { ["SrcAddr.Equal"] = "127.0.0.1",
                                          Actions = { "TAG(abstainer-ran, Set)" } } },
                } },
            },
        }))
        local r = ev.probe(E, 7331)
        local e = r.packet()
        t:assert_eq(e.fx.tags, 1, "the abstaining leaf's own side effects run")
        t:assert_eq(e.verdict, V.PASS, "its nearest verdict-bearing ancestor answers")
        t:assert_eq(e.fx.counts, 1, "with its full action list resolved")
        t:assert_eq(e.fx.reports, 0, "and no further ancestor is asked")
        t:assert_eq(e.attributed, "gp/parent",
            "the verdict is attributed to the speaker, not to gp/parent/leaf")
        t:assert_eq(r.arrived, 1, "so the datagram arrives")
    end)

test("a verdict inside a PROMPT fallback does not make a rule a speaker",
    { spec = "PKM *ntfe-eval.prompt-fallback-verdict-is-not-direct" }, function(t)
        local function tree(port, leaf_src)
            return {
                ["DstPort.Equal"] = port, Actions = { "PASS", "COUNT(gp-spoke)" },
                children = { prompter = {
                    ["Protocol.Equal"] = 17, Actions = { "PROMPT(user, DROP)" },
                    children = { leaf = { ["SrcAddr.Equal"] = leaf_src } },
                } },
            }
        end
        ev.publish(t, E, ev.policy("Packet", {
            climbs = tree(7341, "127.0.0.1"),
            prompts = tree(7342, "10.0.0.1"),
        }))
        local e = ev.probe(E, 7341).packet()
        t:assert_eq(e.attributed, "climbs",
            "the abstaining leaf climbs past the PROMPT rule to the PASS above it")
        t:assert_eq(e.verdict, V.PASS, "whose verdict answers")
        t:assert_eq(e.fx.prompts, 0, "and the PROMPT rule, passed over, issues nothing")

        e = ev.probe(E, 7342).packet()
        t:assert_eq(e.attributed, "prompts/prompter",
            "the same PROMPT rule, triggered itself, yields its fallback")
        t:assert_eq(e.verdict, V.DROP, "the DROP inside the PROMPT")
        t:assert_eq(e.fx.prompts, 1, "having issued the prompt")
    end)

test("a speaker reached by several abstainers executes once",
    { spec = "PKM *ntfe-eval.speaker-executes-once-per-evaluation" }, function(t)
        ev.publish(t, E, ev.policy("Packet", {
            speaker = {
                ["DstPort.Equal"] = 7351, Actions = { "PASS", "COUNT(spoke)" },
                children = {
                    one = { ["Protocol.Equal"] = 17 },
                    two = { ["SrcAddr.Equal"] = "127.0.0.1" },
                    three = { ["DstAddr.Equal"] = "127.0.0.1", Actions = { "NULL" } },
                },
            },
        }))
        local e = ev.probe(E, 7351).packet()
        t:assert_eq(e.attributed, "speaker", "three abstaining exceptions all climb to one speaker")
        t:assert_eq(e.fx.counts, 1, "which resolves its action list once, not three times")
    end)

test("abstaining ancestors between an abstainer and its speaker execute nothing",
    { spec = "PKM *ntfe-eval.intermediate-abstainers-execute-nothing" }, function(t)
        ev.publish(t, E, ev.policy("Packet", {
            top = {
                ["DstPort.Equal"] = 7361, Actions = { "DROP", "COUNT(top-spoke)" },
                children = { mid = {
                    ["Protocol.Equal"] = 17, Actions = { "REPORT(5)", "TAG(mid-ran, Set)" },
                    children = { leaf = { ["SrcAddr.Equal"] = "127.0.0.1", Actions = { "NULL" } } },
                } },
            },
        }))
        local e = ev.probe(E, 7361).packet()
        t:assert_eq(e.attributed, "top", "the leaf's speaker is the first ancestor with a verdict")
        t:assert_eq(e.verdict, V.DROP, "which answers")
        t:assert_eq(e.fx.counts, 1, "and runs its side effects")
        t:assert_eq(e.fx.reports, 0, "while the verdictless rule climbed past reports nothing")
        t:assert_eq(e.fx.tags, 0, "and tags nothing")
    end)

test("a branch with no verdict anywhere in its parentage contributes nothing",
    { spec = "PKM *ntfe-eval.verdictless-branch-contributes-nothing" }, function(t)
        ev.publish(t, E, ev.policy("Packet", {
            lonely = {
                ["DstPort.Equal"] = { "7371", "7372" }, Actions = { "COUNT(lonely-ran)" },
                children = { leaf = { ["Protocol.Equal"] = 17 } },
            },
            other = { ["DstPort.Equal"] = 7371, Actions = { "REJECT" } },
        }))
        local e = ev.probe(E, 7371).packet()
        t:assert_eq(e.attributed, "other", "another tree answers for the verdictless branch")
        t:assert_eq(e.verdict, V.REJECT, "with its REJECT")
        t:assert_eq(e.fx.counts, 0, "and the branch's shadowed root ran nothing")

        e = ev.probe(E, 7372).packet()
        t:assert_eq(e.attributed, "backstop", "with no other tree, the backstop answers")
        t:assert(e.backstop, "flagged as such")
        t:assert_eq(e.verdict, V.DROP, "and drops")
    end)
