-- PKM §6.4 — Evaluation, step 3: resolving a triggered rule. Its action
-- list resolves once: the verdicts fold to the strictest, TAG and COUNT
-- push effects, REPORT folds to its highest level and is gated by
-- `CurrentReportingLevel`, and PROMPT — with no handler transport in
-- this release — is issued and its fallback taken in place, nested at
-- most four deep. Side effects run whether or not the rule's verdict
-- wins.
--
-- Rules whose store effects are counted carry `Direction.Equal = "out"`,
-- so of the two Packet evaluations a loopback datagram meets only the
-- one at EGRESS resolves them; a catch-all passes the other.
--
-- Own VM: the policy is machine-wide state.

local ntfe = require("helpers.ntfe")
local ev = require("helpers.ntfe_eval")

local vm = provium:vm("vntfeevr", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local E = ntfe.engine(vm, ev.policy("Packet", ev.PASS_ALL))

local V, K = ntfe.VERDICT, ntfe.REJECT

-- The Packet forest: a catch-all plus `rules`.
local function packet(rules, values)
    rules.all = { Actions = { "PASS" } }
    return ev.policy("Packet", rules, values)
end

test("a triggered rule's action list is resolved once per evaluation",
    { spec = "PKM *ntfe-eval.triggered-rule-resolved-once" }, function(t)
        ev.publish(t, E, packet({
            once = { ["DstPort.Equal"] = 7401, ["Direction.Equal"] = "out",
                     Actions = { "PASS", "TAG(once-tag, Add)", "COUNT(once-stream)" } },
        }))
        local e = ev.probe(E, 7401).packet()
        t:assert_eq(e.fx.tags, 1, "the evaluation yields its TAG once")
        t:assert_eq(e.fx.counts, 1, "and its COUNT once")
        local f = ev.flow_to(E, 7401)
        t:assert_eq(f.tags[ntfe.name_hash("once-tag")], 1,
            "so the flow's tag, added to from zero, reads 1")
    end)

test("a rule's verdict actions fold to the strictest listed",
    { spec = "PKM *ntfe-eval.verdict-actions-fold-to-strictest" }, function(t)
        local cases = {
            { 7411, { "PASS", "DROP" }, V.DROP },
            { 7412, { "REJECT", "PASS" }, V.REJECT, K.REFUSED },
            { 7413, { "REJECT(Prohibited)", "REJECT(Refused)" }, V.REJECT, K.REFUSED },
            { 7414, { "PASS", "REJECT(Prohibited)" }, V.REJECT, K.PROHIBITED },
            { 7415, { "DROP", "REJECT", "PASS" }, V.DROP },
        }
        local rules = {}
        for _, c in ipairs(cases) do
            rules["at-" .. c[1]] = { ["DstPort.Equal"] = c[1], Priority = 1, Actions = c[2] }
        end
        ev.publish(t, E, packet(rules))
        for _, c in ipairs(cases) do
            local e = ev.probe(E, c[1]).packet()
            local list = table.concat(c[2], ", ")
            t:assert_eq(e.attributed, "at-" .. c[1], list .. " is one rule")
            t:assert_eq(e.verdict, c[3], "and " .. list .. " yields its strictest verdict")
            if c[4] then
                t:assert_eq(e.reject_kind, c[4], "of the stricter kind, " .. list)
            end
        end
    end)

test("TAG and COUNT push effects that the stores apply",
    { spec = "PKM *ntfe-eval.tag-and-count-push-effects" }, function(t)
        ev.publish(t, E, packet({
            pusher = { ["DstPort.Equal"] = 7421, ["Direction.Equal"] = "out",
                       Actions = { "PASS", "TAG(pushed, Set, 7)", "COUNT(pushed-stream, 3)" } },
            -- A view materializes the stream's table; it never matches.
            viewer = { ["DstPort.Equal"] = 7429, ["Counter.pushed-stream.GreaterThan"] = 1000000,
                       Actions = { "DROP" } },
        }))
        local r = ev.probe(E, 7421)
        local e = r.packet()
        t:assert_eq(e.fx.tags, 1, "the evaluation yields one tag effect")
        t:assert_eq(e.fx.counts, 1, "and one count effect")
        t:assert_eq(r.delta.fx_tags, 1, "the status counts the tag yielded")
        t:assert_eq(r.delta.fx_counts, 1, "and the count")
        t:assert_eq(r.delta.tag_writes, 1, "the tag store applied one write")
        t:assert_eq(r.delta.count_writes, 1, "and so did the counter store")
        t:assert_eq(ev.flow_to(E, 7421).tags[ntfe.name_hash("pushed")], 7,
            "the flow carries the tag at the value set")
        local cells = ev.cells(E, "pushed-stream")
        t:assert_eq(#cells, 1, "the stream has its one cell")
        t:assert_eq(cells[1] and cells[1].total, 3, "holding the amount counted")
    end)

test("REPORT folds to the highest level listed and emits once if that level clears the threshold",
    { spec = "PKM *ntfe-eval.report-folds-to-highest-level-and-gates" }, function(t)
        local rule = { ["DstPort.Equal"] = 7431, ["Direction.Equal"] = "out",
                       Actions = { "PASS", "REPORT(2)", "REPORT(4)", "REPORT(3)" } }
        for _, c in ipairs({
            { nil, 1, "with no threshold set (1)" },
            { 4, 1, "at a threshold equal to the folded level" },
            { 5, 0, "and not at all above it" },
        }) do
            ev.publish(t, E, packet({ reporter = rule }, { CurrentReportingLevel = c[1] }))
            local r
            local reports = ev.reports(t, vm, function() r = ev.probe(E, 7431) end)
            t:assert_eq(r.packet().fx.reports, c[2], "the rule yields " .. c[2] .. " report " .. c[3])
            t:assert_eq(#reports, c[2], "and KMES receives " .. c[2] .. " " .. c[3])
            if c[2] == 1 then
                t:assert_eq(reports[1].payload.level, 4, "at the highest level listed, " .. c[3])
                t:assert_eq(reports[1].payload.rule, "reporter", "attributed to the rule")
            end
        end
    end)

test("PROMPT is issued and, with no handler to answer, its fallback resolves in place",
    { spec = "PKM *ntfe-eval.prompt-resolves-fallback-in-place" }, function(t)
        ev.publish(t, E, ev.policy("Packet", {
            drops = { ["DstPort.Equal"] = 7441, Actions = { "PROMPT(user, DROP)" } },
            prohibits = { ["DstPort.Equal"] = 7442, Actions = { "PROMPT(user, REJECT(Prohibited))" } },
            parent = {
                ["DstPort.Equal"] = 7443, Actions = { "PASS" },
                children = { silent = { ["Protocol.Equal"] = 17, Actions = { "PROMPT(user)" } } },
            },
        }))
        local r = ev.probe(E, 7441)
        local e = r.packet()
        t:assert_eq(e.fx.prompts, 1, "the prompt is issued")
        t:assert_eq(e.verdict, V.DROP, "and its DROP fallback is the rule's verdict")
        t:assert_eq(e.attributed, "drops", "the rule's own")
        t:assert_eq(r.arrived, 0, "so the datagram is dropped")

        e = ev.probe(E, 7442).packet()
        t:assert_eq(e.verdict, V.REJECT, "a REJECT fallback rejects")
        t:assert_eq(e.reject_kind, K.PROHIBITED, "with the kind written in the fallback")

        r = ev.probe(E, 7443)
        e = r.packet()
        t:assert_eq(e.fx.prompts, 1, "a prompt with no fallback is still issued")
        t:assert_eq(e.attributed, "parent", "and its rule abstains, so its parent speaks")
        t:assert_eq(r.arrived, 1, "passing the datagram")
    end)

test("PROMPT fallbacks nest at most four deep",
    { spec = "PKM *ntfe-eval.prompt-chain-bounded-at-four" }, function(t)
        local s = ev.publish(t, E, ev.policy("Packet", {
            chain = { ["DstPort.Equal"] = 7451,
                      Actions = { "PROMPT(a, PROMPT(b, PROMPT(c, PROMPT(d, REJECT(Prohibited)))))" } },
        }))
        local e = ev.probe(E, 7451).packet()
        t:assert_eq(e.fx.prompts, 4, "four nested prompts are each issued")
        t:assert_eq(e.verdict, V.REJECT, "and the innermost fallback decides")
        t:assert_eq(e.reject_kind, K.PROHIBITED, "exactly as written")

        local refused = E:replace(ev.policy("Packet", {
            chain = { ["DstPort.Equal"] = 7451,
                      Actions = { "PROMPT(a, PROMPT(b, PROMPT(c, PROMPT(d, PROMPT(e, DROP)))))" } },
        }))
        t:assert(refused.last_ingest_error ~= 0, "a fifth level is refused at ingestion")
        t:assert_eq(refused.generation, s.generation, "and the four-deep policy stays in force")
    end)

test("side effects execute whether or not their rule's verdict wins",
    { spec = "PKM *ntfe-eval.side-effects-execute-regardless-of-verdict" }, function(t)
        ev.publish(t, E, ev.policy("Packet", {
            winner = { ["DstPort.Equal"] = 7461, Priority = 10, Actions = { "PASS" } },
            loser = { ["DstPort.Equal"] = 7461,
                      Actions = { "DROP", "COUNT(loser-stream)", "TAG(loser-tag, Set)",
                                  "REPORT(5)", "PROMPT(user, DROP)" } },
        }))
        local r = ev.probe(E, 7461)
        local e = r.packet()
        t:assert_eq(e.attributed, "winner", "the higher-priority PASS wins")
        t:assert_eq(r.arrived, 1, "and the datagram arrives")
        t:assert_eq(e.fx.counts, 1, "yet the losing rule's COUNT ran")
        t:assert_eq(e.fx.tags, 1, "its TAG")
        t:assert_eq(e.fx.reports, 1, "its REPORT")
        t:assert_eq(e.fx.prompts, 1, "and its PROMPT")
        t:assert_eq(ev.flow_to(E, 7461).tags[ntfe.name_hash("loser-tag")], 1,
            "and the tag it set is on the flow")
    end)
