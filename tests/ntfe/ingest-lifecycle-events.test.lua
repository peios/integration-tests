-- PKM §6.5 — In the event stream: NTFE's own lifecycle in KMES. Every
-- publication writes `ntfe.policy.published` (the generation, the one it
-- replaced, the layers and both reporting thresholds); every refused
-- walk writes `ntfe.policy.rejected`, with the walk's errno and a reason
-- that names the defect, and the rule it is in. The same refusal of the
-- same policy is written once, however many walks re-read it.
--
-- The events are read from every CPU's KMES ring (helpers/ntfe_store)
-- and decoded keeping each map's keys in wire order, so every level is
-- held to its exact key list.
--
-- Own VM: the policy is machine-wide state, and the last test takes the
-- Rules key away.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local ntfe = require("helpers.ntfe")
local ing = require("helpers.ntfe_ingest")
local S = require("helpers.ntfe_store")

local vm = provium:vm("vntfelce", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local rec = S.recorder(vm)

local T = lcs.TYPE
local function typed(vtype, data) return { type = vtype, data = data } end

-- The policy every refusal must leave in force: port 6901 is rejected
-- by a rule called `standing`.
local STANDING = ing.policy({
    standing = { ["DstPort.Equal"] = 6901, Actions = { "REJECT" } },
})
local E = ing.engine(vm, STANDING)

-- Replace the policy and settle; return the status and the lifecycle
-- events the walk wrote, decoded.
local function replacing(policy)
    rec:drain()
    local s = ing.replace(E, policy)
    local events = rec:drain()
    return s, S.decoded(events, S.PUBLISHED_TYPE), S.decoded(events, S.REJECTED_TYPE)
end

-- A walk that reads the policy as it stands: one write under the
-- Network key, as netd's inventory writes are.
local function rewalking()
    rec:drain()
    ing.poke(E)
    local s = ing.settle(E, 120000)
    local events = rec:drain()
    return s, S.decoded(events, S.PUBLISHED_TYPE), S.decoded(events, S.REJECTED_TYPE)
end

local function keyset(keys)
    local set = {}
    for _, k in ipairs(keys or {}) do set[k] = true end
    return set
end

-- Hold one map of a payload to exactly `want`.
local function exactly(t, map, want, what)
    local keys = S.keys_of(map) or {}
    local have = keyset(keys)
    for _, k in ipairs(want) do t:assert(have[k], what .. " has `" .. k .. "`") end
    t:assert_eq(#keys, #want, "and " .. what .. " has nothing else: " .. table.concat(keys, ", "))
end

local function only(t, events, what)
    t:assert_eq(#events, 1, what .. ": exactly one event")
    local e = events[1] or {}
    t:assert_eq(e.origin, S.ORIGIN_NTFE, what .. ": of origin class KMES_ORIGIN_NTFE (4)")
    t:assert(e.payload, what .. ": with a payload that decodes")
    return e.payload or {}
end

-- ---- ntfe.policy.published --------------------------------------------

test("every publication writes one ntfe.policy.published: the generation, its predecessor, the layers and both thresholds",
    { spec = "PKM *ntfe-ingest.publish-emits-policy-published " ..
             "PKM *ntfe-ingest.published-event-payload" }, function(t)
        local s1, pub1 = replacing(ing.policy({
            standing = { ["DstPort.Equal"] = 6901, Actions = { "REJECT" } },
            first = { ["DstPort.Equal"] = 6902, Actions = { "PASS" } },
        }, { values = { CurrentReportingLevel = 2 } }))
        t:assert_eq(s1.last_ingest_error, 0, "the first policy is accepted")
        local p1 = only(t, pub1, "the first publication").policy or {}

        -- Two layers only, and another threshold.
        local s2, pub2, rej2 = replacing({
            values = { CurrentReportingLevel = 5 },
            Packet = ing.PASS_ALL,
            Flow = { all = { Actions = { "PASS" } },
                     standing = { ["DstPort.Equal"] = 6901, Actions = { "REJECT" } } },
        })
        t:assert_eq(s2.last_ingest_error, 0, "the second policy is accepted")
        t:assert(s2.generation > s1.generation, "and published")
        t:assert_eq(#rej2, 0, "an accepted policy writes no ntfe.policy.rejected")
        local r = only(t, pub2, "the second publication")
        exactly(t, r, { "policy" }, "the payload")
        local p = r.policy or {}
        exactly(t, p, { "generation", "generation-previous", "layers", "report-threshold",
                        "report-threshold-previous" }, "policy")
        t:assert_eq(p.generation, s2.generation, "policy.generation: the generation now in force")
        t:assert_eq(p.generation, s1.generation + 1, "one past the first")
        t:assert_eq(p["generation-previous"], p1.generation,
            "policy.generation-previous: the generation of the policy it replaced")
        local layers = p.layers or {}
        t:assert_eq(#layers, 2, "policy.layers: the layers with a forest")
        t:assert_eq(layers[1], "packet", "in the catalogue's order")
        t:assert_eq(layers[2], "flow", "packet before flow")
        t:assert_eq(p["report-threshold"], 5, "policy.report-threshold: the new CurrentReportingLevel")
        t:assert_eq(p["report-threshold-previous"], 2, "policy.report-threshold-previous: the replaced one")

        -- Every layer, and the threshold back to its default.
        local s3, pub3 = replacing(STANDING)
        local p3 = only(t, pub3, "the third publication").policy or {}
        t:assert_eq(p3.generation, s3.generation, "the third generation")
        t:assert_eq(p3["generation-previous"], s2.generation, "replacing the second")
        local all = p3.layers or {}
        t:assert_eq(table.concat(all, ","), "raw-packet,packet,flow",
            "all three layers, raw-packet first")
        t:assert_eq(p3["report-threshold"], 1, "an absent CurrentReportingLevel is 1")
        t:assert_eq(p3["report-threshold-previous"], 5, "and the replaced one was 5")
    end)

test("a walk that reads the policy unchanged publishes nothing and writes nothing",
    { spec = "PKM *ntfe-ingest.unchanged-walk-writes-no-published-event" }, function(t)
        local before = ing.replace(E, STANDING)
        local s, pub, rej = rewalking()
        t:assert_eq(s.last_ingest_error, 0, "the walk succeeds")
        t:assert_eq(s.generation, before.generation, "and publishes nothing")
        t:assert_eq(#pub, 0, "so no ntfe.policy.published")
        t:assert_eq(#rej, 0, "and no ntfe.policy.rejected")
    end)

-- ---- ntfe.policy.rejected ---------------------------------------------

test("a refused policy writes one ntfe.policy.rejected naming the rule, its layer and why",
    { spec = "PKM *ntfe-ingest.refusal-emits-policy-rejected " ..
             "PKM *ntfe-ingest.rejected-event-payload " ..
             "PKM *ntfe-ingest.build-refusal-reason-crosses-bridge" }, function(t)
        local good = ing.replace(E, STANDING)
        t:assert_eq(good.last_ingest_error, 0, "the standing policy is in force first")
        local s, pub, rej = replacing(ing.policy({
            standing = { ["DstPort.Equal"] = 6901, Actions = { "REJECT" } },
            guard = { ["DstPort.Equal"] = 6903, Actions = { "PASS" },
                      children = { ssh = { ["SrcPort.Equal"] = 22, Actions = { "FROB" } } } },
        }))
        t:assert_eq(s.last_ingest_error, ing.EINVAL, "the policy is refused, EINVAL in the status")
        t:assert_eq(s.generation, good.generation, "and nothing is published")
        t:assert_eq(#pub, 0, "so no ntfe.policy.published")
        local r = only(t, rej, "the refusal")
        exactly(t, r, { "policy", "outcome", "rule" }, "the payload")
        exactly(t, r.policy, { "generation", "previous-retained" }, "policy")
        exactly(t, r.outcome, { "errno", "reason" }, "outcome")
        exactly(t, r.rule, { "layer", "action-error", "name" }, "rule")
        local p, o, rule = r.policy or {}, r.outcome or {}, r.rule or {}
        t:assert_eq(p.generation, good.generation, "policy.generation: the generation still in force")
        t:assert_eq(p["previous-retained"], true, "policy.previous-retained: true")
        t:assert_eq(o.errno, -ing.EINVAL, "outcome.errno: the walk's, negative")
        t:assert_eq(o.reason, "bad-action", "outcome.reason: the builder's own name for it")
        t:assert_eq(rule.name, "guard/ssh", "rule.name: the path below the layer key")
        t:assert_eq(rule.layer, "flow", "rule.layer")
        t:assert_eq(rule["action-error"], "unknown-action", "rule.action-error")
        t:assert_eq(ing.verdict(vm, 6901), "reject", "the standing policy still judges")
    end)

-- Each refusal, from a standing policy, with the reason, the errno and
-- the rule it must name (nil: no rule map), and the layer (nil: none).
local function flow_rule(values, extra)
    local rule = { ["DstPort.Equal"] = 6904, Actions = { "REJECT" } }
    for k, v in pairs(values) do rule[k] = v end
    return ing.policy({ probe = rule }, extra)
end

local function chain(levels)
    local rule = { ["DstPort.Equal"] = 6905, Actions = { "REJECT" } }
    local path = {}
    for i = levels - 1, 1, -1 do
        rule = { ["DstPort.Equal"] = 6905, Actions = { "PASS" }, children = { ["d" .. i] = rule } }
    end
    path[1] = "chain"
    for i = 1, levels - 1 do path[#path + 1] = "d" .. i end
    return ing.policy({ chain = rule }), table.concat(path, "/")
end

local function nine_windows()
    local flow = { w = { ["DstPort.Equal"] = 6906, Actions = { "COUNT(win)", "PASS" } } }
    for i = 1, 9 do
        flow["r" .. i] = { ["DstPort.Equal"] = 6907,
                           ["Counter.win(" .. (i * 10) .. "s).GreaterThan"] = 1000,
                           Actions = { "DROP" } }
    end
    return ing.policy(flow)
end

local deep, deep_path = chain(14)

local REASONS = {
    { "PKM *ntfe-ingest.build-refusal-reason-crosses-bridge", "an unknown fact",
      flow_rule({ ["NoSuchFact.Equal"] = 1 }), "unknown-fact", ing.EINVAL, "probe", "flow" },
    { "PKM *ntfe-ingest.build-refusal-reason-crosses-bridge", "a Priority written as text",
      flow_rule({ Priority = "5" }), "bad-priority", ing.EINVAL, "probe", "flow" },
    { "PKM *ntfe-ingest.build-refusal-reason-crosses-bridge", "a downward tag read across forests",
      ing.policy({ w = { ["DstPort.Equal"] = 6904, Actions = { "TAG(up, Set)", "PASS" } } },
          { Packet = { all = { Actions = { "PASS" } },
                       r = { ["Tag.up.Equal"] = 1, Actions = { "PASS" } } } }),
      "tag-downward-read", ing.EINVAL, "r", nil },
    { "PKM *ntfe-ingest.walk-refusal-reasons", "a REG_BINARY value in a rule",
      flow_rule({ Note = typed(T.BINARY, "\x22\x1a") }), "bad-value-type", ing.EINVAL, "probe", "flow" },
    { "PKM *ntfe-ingest.walk-refusal-reasons", "a two-byte REG_DWORD in a rule",
      flow_rule({ Priority = typed(T.DWORD, "\3\0") }), "bad-value-length", ing.EINVAL, "probe", "flow" },
    { "PKM *ntfe-ingest.walk-refusal-reasons", "a CurrentReportingLevel of 9",
      ing.policy(nil, { values = { CurrentReportingLevel = 9 } }),
      "bad-reporting-level", ing.EINVAL, nil, nil },
    { "PKM *ntfe-ingest.walk-refusal-reasons", "a chain of 14 rules",
      deep, "rule-too-deep", ing.E2BIG, deep_path, "flow" },
    { "PKM *ntfe-ingest.walk-refusal-reasons", "nine windows on one counter table",
      nine_windows(), "counter-store-refused", ing.E2BIG, nil, nil },
}

for _, c in ipairs(REASONS) do
    local spec, what, bad, reason, errno, rule, layer = table.unpack(c, 1, 7)
    test("ntfe.policy.rejected names " .. what .. " as " .. reason,
        { spec = spec }, function(t)
            local good = ing.replace(E, STANDING)
            t:assert_eq(good.last_ingest_error, 0, what .. ": the standing policy is in force first")
            local s, pub, rej = replacing(bad)
            t:assert_eq(s.last_ingest_error, errno, what .. ": refused with the errno it always had")
            t:assert_eq(#pub, 0, what .. ": nothing is published")
            local r = only(t, rej, what)
            t:assert_eq((r.outcome or {}).reason, reason, what .. ": outcome.reason")
            t:assert_eq((r.outcome or {}).errno, -errno, what .. ": outcome.errno")
            if rule == nil then
                t:assert_eq(r.rule, nil, what .. ": names no rule")
                exactly(t, r, { "policy", "outcome" }, what .. ": the payload")
            else
                local m = r.rule or {}
                t:assert_eq(m.name, rule, what .. ": rule.name")
                t:assert_eq(m.layer, layer, what .. ": rule.layer")
                t:assert_eq(m["action-error"], nil, what .. ": no action error")
            end
        end)
end

test("the same refusal is written once however many walks re-read it, and an accepted walk starts the count again",
    { spec = "PKM *ntfe-ingest.repeated-refusal-written-once" }, function(t)
        local bad = flow_rule({ Enabled = 2 })
        local other = flow_rule({ Enabled = 3 })
        ing.replace(E, STANDING)
        local s, _, rej = replacing(bad)
        t:assert_eq(s.last_ingest_error, ing.EINVAL, "the policy is refused")
        t:assert_eq(#rej, 1, "and the refusal written")
        t:assert_eq(((rej[1] or {}).payload or {}).outcome.reason, "bad-enabled", "as bad-enabled")
        for i = 1, 2 do
            local again, pub_again, rej_again = rewalking()
            t:assert_eq(again.last_ingest_error, ing.EINVAL, "walk " .. i .. " refuses it again")
            t:assert_eq(again.changes_walked, again.changes_noted, "walk " .. i .. " ran")
            t:assert_eq(#rej_again, 0, "walk " .. i .. " writes no second record")
            t:assert_eq(#pub_again, 0, "nor publishes")
        end
        -- Another defect is another refusal.
        local _, _, rej_other = replacing(other)
        t:assert_eq(#rej_other, 1, "a different policy refused is written")
        -- An accepted walk clears it, even one that publishes nothing
        -- (the standing policy is the one still in force): the first
        -- defect is written again.
        local ok, pub_ok = replacing(STANDING)
        t:assert_eq(ok.last_ingest_error, 0, "the standing policy is accepted")
        t:assert_eq(#pub_ok, 0, "unchanged, so nothing is published")
        local _, _, rej_back = replacing(bad)
        t:assert_eq(#rej_back, 1, "and the old refusal, after it, is written again")
    end)

-- Last: it takes the Rules key away.
test("a walk that finds no Rules key writes ntfe.policy.rejected once, with no errno and no rule",
    { spec = "PKM *ntfe-ingest.absent-rules-key-emits-rejected " ..
             "PKM *ntfe-ingest.repeated-refusal-written-once" }, function(t)
        local before = ing.replace(E, STANDING)
        rec:drain()
        -- Delete the whole Rules subtree, leaves first, in one
        -- transaction: one walk sees the key gone.
        local txn = assert(lcs.begin_transaction(E.writer))
        local paths = {}
        for _, layer in ipairs({ "RawPacket", "Packet", "Flow" }) do
            paths[#paths + 1] = "Rules\\" .. layer .. "\\all"
        end
        paths[#paths + 1] = "Rules\\Flow\\standing"
        for _, layer in ipairs({ "RawPacket", "Packet", "Flow" }) do
            paths[#paths + 1] = "Rules\\" .. layer
        end
        paths[#paths + 1] = "Rules"
        for _, p in ipairs(paths) do
            local fd = ing.open(E, p)
            local r = ing.quick(E, function(w) return lcs.delete_key_async(w, fd, { txn_fd = txn }) end)
            t:assert_eq(r.ret, 0, "delete " .. p .. ": " .. sys.errname(r.errno or 0))
        end
        local r = ing.quick(E, function(w) return lcs.commit_async(w, txn) end)
        sys.close(E.writer, txn)
        t:assert_eq(r.ret, 0, "the deletion commits")
        local s = ing.settle(E, 120000)
        local events = rec:drain()
        t:assert_eq(s.generation, before.generation, "the previous generation stands")
        t:assert_eq(s.last_ingest_error, 0, "with no error: an absent key is no failure")
        t:assert_eq(#S.decoded(events, S.PUBLISHED_TYPE), 0, "nothing is published")
        local rej = S.decoded(events, S.REJECTED_TYPE)
        local m = only(t, rej, "the missing Rules key")
        exactly(t, m, { "policy", "outcome" }, "the payload: no rule")
        exactly(t, m.outcome, { "reason" }, "outcome: no errno")
        t:assert_eq((m.outcome or {}).reason, "no-rules-key", "outcome.reason")
        t:assert_eq((m.policy or {}).generation, before.generation, "policy.generation: the one still in force")
        t:assert_eq((m.policy or {})["previous-retained"], true, "policy.previous-retained")
        -- The next walk finds the same nothing, and writes nothing.
        local _, pub_again, rej_again = rewalking()
        t:assert_eq(#rej_again, 0, "a later walk without the key writes no second record")
        t:assert_eq(#pub_again, 0, "nor publishes")
    end)
