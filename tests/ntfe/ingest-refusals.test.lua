-- PKM §6.5 — Building and validating, and publication: every condition
-- that refuses a generation, driven live. Each refusal is written as a
-- pair: the policy with the defect, which must leave the previous
-- generation in force with `last_ingest_error` set, and the same policy
-- with only that defect repaired, which must publish. The kernel
-- reports every builder refusal as one errno, so the pair is what pins
-- each refusal to its cause.
--
-- The cross-forest checks (tag and stream hashes across every forest,
-- views with no writer, downward tag reads) and the counter store that
-- publication materializes are driven the same way. Hash collisions use
-- real FNV-1a-64 collisions found offline (helpers/ntfe_ingest).
--
-- Own VM: the policy is machine-wide state, and every test here swaps
-- it.

local ntfe = require("helpers.ntfe")
local ing = require("helpers.ntfe_ingest")

local vm = provium:vm("vntfeirf", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))

-- The standing policy every refusal must leave in force: port 6301 is
-- rejected by a rule called `standing`.
local STANDING = ing.policy({
    standing = { ["DstPort.Equal"] = 6301, Actions = { "REJECT" } },
})
local E = ing.engine(vm, STANDING)

-- Re-establish the standing policy, then try `bad`: it must be refused
-- with `errno` (EINVAL unless given; `false` for any), leaving the
-- standing generation in force. Returns the status after the attempt.
local function refused(t, what, bad, errno)
    local before = ing.replace(E, STANDING)
    t:assert_eq(before.last_ingest_error, 0, what .. ": the standing policy is in force first")
    local s = ing.replace(E, bad)
    if errno == false then
        t:assert(s.last_ingest_error ~= 0, what .. ": refused")
    else
        t:assert_eq(s.last_ingest_error, errno or ing.EINVAL,
            what .. ": refused, with the errno in the status")
    end
    t:assert_eq(s.generation, before.generation,
        what .. ": and no generation is published")
    return s
end

-- `good` (the same policy with the defect repaired) must publish.
local function accepted(t, what, good)
    local before = E:status()
    local s = ing.replace(E, good)
    t:assert_eq(s.last_ingest_error, 0, what .. ": with the defect repaired it is accepted")
    t:assert(s.generation > before.generation, what .. ": and published")
end

-- A Flow rule with `values` (plus a REJECT on 6302) inside an otherwise
-- working policy.
local function flow_rule(values, extra)
    local rule = { ["DstPort.Equal"] = 6302, Actions = { "REJECT" } }
    for k, v in pairs(values) do rule[k] = v end
    return ing.policy({ probe = rule }, extra)
end

-- ---- the builder's refusals ------------------------------------------

local REFUSALS = {
    { "PKM *ntfe-ingest.refuse-unknown-fact", "an unknown fact",
      { ["NoSuchFact.Equal"] = 1 }, { ["SrcPort.Equal"] = 1 } },
    { "PKM *ntfe-ingest.refuse-unknown-fact", "a condition key with no operator",
      { ["SrcPort"] = 1 }, { ["SrcPort.Equal"] = 1 } },
    { "PKM *ntfe-ingest.refuse-unsupported-operator", "Has on an integer fact",
      { ["SrcPort.Has"] = { "SYN" } }, { ["TcpFlags.Has"] = { "SYN" } } },
    { "PKM *ntfe-ingest.refuse-unsupported-operator", "GreaterThan on an address",
      { ["SrcAddr.GreaterThan"] = "10.0.0.1" }, { ["SrcAddr.Equal"] = "10.0.0.1" } },
    { "PKM *ntfe-ingest.refuse-unparsable-pattern", "a port that is not a number",
      { ["SrcPort.Equal"] = "ssh-ish" }, { ["SrcPort.Equal"] = "22" } },
    { "PKM *ntfe-ingest.refuse-unparsable-pattern", "an address that does not parse",
      { ["SrcAddr.Equal"] = "999.1.1.1" }, { ["SrcAddr.Equal"] = "9.1.1.1" } },
    { "PKM *ntfe-ingest.refuse-unparsable-pattern", "a backwards range",
      { ["SrcPort.Equal"] = "9-1" }, { ["SrcPort.Equal"] = "1-9" } },
    { "PKM *ntfe-ingest.refuse-unparsable-counter-view", "a counter view with a bad duration",
      { ["Counter.seen(10q).GreaterThan"] = 5 }, { ["Counter.seen(10s).GreaterThan"] = 5 } },
    { "PKM *ntfe-ingest.refuse-unparsable-counter-view", "a counter view keyed by an unknown fact",
      { ["Counter.seen(Ttl).GreaterThan"] = 5 }, { ["Counter.seen(SrcAddr).GreaterThan"] = 5 } },
    { "PKM *ntfe-ingest.refuse-unparsable-counter-view", "a counter view with a duplicate argument",
      { ["Counter.seen(10s, 20s).GreaterThan"] = 5 }, { ["Counter.seen(10s, SrcAddr).GreaterThan"] = 5 } },
    { "PKM *ntfe-ingest.refuse-unparsable-counter-view", "a counter window over the one-day horizon",
      { ["Counter.seen(25h).GreaterThan"] = 5 }, { ["Counter.seen(24h).GreaterThan"] = 5 } },
    { "PKM *ntfe-ingest.refuse-non-list-actions", "Actions as a string",
      { Actions = "REJECT" }, { Actions = { "REJECT" } } },
    { "PKM *ntfe-ingest.refuse-non-list-actions", "Actions as a number",
      { Actions = 1 }, { Actions = { "REJECT" } } },
    { "PKM *ntfe-ingest.refuse-unparsable-action", "an action that is not in the language",
      { Actions = { "FROB" } }, { Actions = { "DROP" } } },
    { "PKM *ntfe-ingest.refuse-unparsable-action", "an action with unbalanced parentheses",
      { Actions = { "TAG(x, Set" } }, { Actions = { "TAG(x, Set)" } } },
    { "PKM *ntfe-ingest.refuse-unparsable-action", "an action of the wrong arity",
      { Actions = { "PASS(1)" } }, { Actions = { "PASS" } } },
    { "PKM *ntfe-ingest.refuse-unknown-reject-kind", "a REJECT kind that was never minted",
      { Actions = { "REJECT(HostUnreachable)" } }, { Actions = { "REJECT(Prohibited)" } } },
    { "PKM *ntfe-ingest.refuse-non-integer-priority", "a Priority written as text",
      { Priority = "5" }, { Priority = 5 } },
    { "PKM *ntfe-ingest.refuse-non-integer-priority", "a Priority written as a list",
      { Priority = { "5" } }, { Priority = 5 } },
    { "PKM *ntfe-ingest.refuse-enabled-not-0-or-1", "Enabled = 2",
      { Enabled = 2 }, { Enabled = 0 } },
    { "PKM *ntfe-ingest.refuse-enabled-not-0-or-1", "Enabled written as text",
      { Enabled = "1" }, { Enabled = 1 } },
}

for _, c in ipairs(REFUSALS) do
    local spec, what, bad, good = c[1], c[2], c[3], c[4]
    test("the builder refuses " .. what .. ", and accepts the rule without it",
        { spec = spec }, function(t)
            -- The stream the counter views read is written, so a view
            -- that parses is not refused for being dead.
            local writer = { RawPacket = { all = { Actions = { "PASS", "COUNT(seen)" } } } }
            refused(t, what, flow_rule(bad, writer))
            accepted(t, what, flow_rule(good, writer))
        end)
end

test("a refused policy leaves the previous generation enforcing",
    { spec = "PKM *ntfe-ingest.refused-walk-keeps-previous-generation " ..
             "PKM *ntfe-ingest.refusal-logged-and-previous-stays-active" }, function(t)
        refused(t, "a broken rule", ing.policy({
            standing = { ["DstPort.Equal"] = 6301, Actions = { "PASS" } },
            broken = { ["NoSuchFact.Equal"] = 1, Actions = { "DROP" } },
        }))
        -- The refused policy would have passed 6301; the standing one
        -- rejects it, and still does.
        local delta, events = E:during(function()
            t:assert_eq(ing.verdict(vm, 6301), "reject", "the standing rule still speaks")
        end)
        t:assert(#ntfe.matching(events, { attributed = "standing", verdict = ntfe.VERDICT.REJECT }) >= 1,
            "attributed to the standing rule: " .. ntfe.describe(events))
        t:assert(delta.verdict_reject >= 1, "and counted")
    end)

test("a rule name containing a path separator is refused",
    { spec = "PKM *ntfe-ingest.refuse-rule-name-with-path-separator" }, function(t)
        -- LCS treats `/` as a separator too: reg_create_key cannot make
        -- such a key, and a source that serves one has the walk fail in
        -- LCS's own name check (EIO) before the builder sees the name.
        -- The refusal is what a running kernel can show; the builder's
        -- own check is pnp-core's rule_names_with_path_separators_are_rejected.
        local r = ing.quick_create(E, "Rules\\Flow\\half/half")
        t:assert(r.ret < 0, "the registry will not create a key named with a slash")
        refused(t, "a slash in the name", ing.policy({
            ["half/half"] = { ["DstPort.Equal"] = 6302, Actions = { "REJECT" } },
        }), false)
        accepted(t, "a slash in the name", ing.policy({
            ["half-half"] = { ["DstPort.Equal"] = 6302, Actions = { "REJECT" } },
        }))
        refused(t, "a slash in an exception's name", ing.policy({
            parent = { ["DstPort.Equal"] = 6302, Actions = { "REJECT" },
                       children = { ["a/b"] = { ["SrcPort.Equal"] = 1, Actions = { "PASS" } } } },
        }), false)
    end)

test("two distinct tag names whose hashes collide are refused",
    { spec = "PKM *ntfe-ingest.refuse-name-hash-collision" }, function(t)
        local a, b = ing.COLLIDING[1][1], ing.COLLIDING[1][2]
        refused(t, "colliding tags written by one forest", ing.policy({
            wa = { ["DstPort.Equal"] = 6302, Actions = { "TAG(" .. a .. ", Set)", "PASS" } },
            wb = { ["DstPort.Equal"] = 6303, Actions = { "TAG(" .. b .. ", Set)", "PASS" } },
        }))
        -- A name mentioned only in a condition is in the set too.
        refused(t, "a written tag colliding with a read one", ing.policy({
            wa = { ["DstPort.Equal"] = 6302, Actions = { "TAG(" .. a .. ", Set)", "PASS" } },
            rb = { ["Tag." .. b .. ".Equal"] = 1, Actions = { "PASS" } },
        }))
        -- And a PROMPT fallback's TAG.
        refused(t, "a PROMPT fallback's tag colliding", ing.policy({
            wa = { ["DstPort.Equal"] = 6302, Actions = { "TAG(" .. a .. ", Set)", "PASS" } },
            pb = { ["DstPort.Equal"] = 6303, Actions = { "PROMPT(h, TAG(" .. b .. ", Add))" } },
        }))
        accepted(t, "either colliding tag alone", ing.policy({
            wa = { ["DstPort.Equal"] = 6302, Actions = { "TAG(" .. a .. ", Set)", "PASS" } },
            rb = { ["Tag." .. a .. ".Equal"] = 1, Actions = { "PASS" } },
        }))
    end)

test("two distinct stream names whose hashes collide are refused",
    { spec = "PKM *ntfe-ingest.refuse-name-hash-collision" }, function(t)
        local a, b = ing.COLLIDING[2][1], ing.COLLIDING[2][2]
        refused(t, "colliding streams", ing.policy({
            ca = { ["DstPort.Equal"] = 6302, Actions = { "COUNT(" .. a .. ")", "PASS" } },
            cb = { ["DstPort.Equal"] = 6303, Actions = { "COUNT(" .. b .. ")", "PASS" } },
        }))
        accepted(t, "one of the colliding streams", ing.policy({
            ca = { ["DstPort.Equal"] = 6302, Actions = { "COUNT(" .. a .. ")", "PASS" } },
            cb = { ["DstPort.Equal"] = 6303, Actions = { "COUNT(" .. a .. ", 2)", "PASS" } },
        }))
    end)

-- ---- across forests ---------------------------------------------------

test("tag and stream hashes must be distinct across every forest",
    { spec = "PKM *ntfe-ingest.hashes-distinct-across-forests" }, function(t)
        local ta, tb = ing.COLLIDING[3][1], ing.COLLIDING[3][2]
        -- Each forest alone is sound; together they share the stores.
        refused(t, "colliding tags in two forests", ing.policy({
            fb = { ["DstPort.Equal"] = 6302, Actions = { "TAG(" .. tb .. ", Set)", "PASS" } },
        }, { Packet = { all = { Actions = { "PASS", "TAG(" .. ta .. ", Set)" } } } }))
        accepted(t, "the same tag in two forests", ing.policy({
            fb = { ["DstPort.Equal"] = 6302, Actions = { "TAG(" .. ta .. ", Set)", "PASS" } },
        }, { Packet = { all = { Actions = { "PASS", "TAG(" .. ta .. ", Set)" } } } }))
        local sa, sb = ing.COLLIDING[4][1], ing.COLLIDING[4][2]
        refused(t, "colliding streams in two forests", ing.policy({
            fb = { ["DstPort.Equal"] = 6302, Actions = { "COUNT(" .. sb .. ")", "PASS" } },
        }, { RawPacket = { all = { Actions = { "PASS", "COUNT(" .. sa .. ")" } } } }))
        accepted(t, "the same stream in two forests", ing.policy({
            fb = { ["DstPort.Equal"] = 6302, Actions = { "COUNT(" .. sa .. ")", "PASS" } },
        }, { RawPacket = { all = { Actions = { "PASS", "COUNT(" .. sa .. ")" } } } }))
    end)

test("a counter view over a stream no rule writes is refused; a writer in any forest satisfies it",
    { spec = "PKM *ntfe-ingest.refuse-view-without-writer" }, function(t)
        local reader = { ["Counter.unwritten(10s).GreaterThan"] = 3 }
        refused(t, "a view with no writer", flow_rule(reader))
        accepted(t, "a view whose writer is in the RawPacket forest", flow_rule(reader,
            { RawPacket = { all = { Actions = { "PASS", "COUNT(unwritten)" } } } }))
        accepted(t, "a view whose writer is in its own forest", ing.policy({
            probe = { ["DstPort.Equal"] = 6302, ["Counter.unwritten(10s).GreaterThan"] = 3,
                      Actions = { "REJECT" } },
            w = { ["DstPort.Equal"] = 6303, Actions = { "COUNT(unwritten)", "PASS" } },
        }))
    end)

test("no forest may read a tag a higher forest writes",
    { spec = "PKM *ntfe-ingest.refuse-downward-tag-read" }, function(t)
        -- Flow writes `up`, Packet reads it: a downward read.
        refused(t, "Packet reading a tag Flow writes", ing.policy({
            w = { ["DstPort.Equal"] = 6302, Actions = { "TAG(up, Set)", "PASS" } },
        }, { Packet = { all = { Actions = { "PASS" } },
                        r = { ["Tag.up.Equal"] = 1, Actions = { "PASS" } } } }))
        -- Packet writes, Flow reads: upward, legal.
        accepted(t, "Flow reading a tag Packet writes", ing.policy({
            r = { ["Tag.up.Equal"] = 1, Actions = { "PASS" } },
        }, { Packet = { all = { Actions = { "PASS", "TAG(up, Set)" } } } }))
        -- A forest reading its own tag is not downward either.
        accepted(t, "Flow reading its own tag", ing.policy({
            w = { ["DstPort.Equal"] = 6302, Actions = { "TAG(up, Set)", "PASS" } },
            r = { ["Tag.up.Equal"] = 1, Actions = { "PASS" } },
        }))
    end)

-- ---- publication -------------------------------------------------------

-- `n` distinct windows over one stream, unkeyed: one counter table.
local function windows(n)
    local flow = { w = { ["DstPort.Equal"] = 6302, Actions = { "COUNT(win)", "PASS" } } }
    for i = 1, n do
        flow["r" .. i] = { ["DstPort.Equal"] = 6303,
                           ["Counter.win(" .. (i * 10) .. "s).GreaterThan"] = 1000,
                           Actions = { "DROP" } }
    end
    return ing.policy(flow)
end

test("a counter store that cannot be built refuses the generation before anything is swapped",
    { spec = "PKM *ntfe-ingest.unbuildable-counter-store-refuses-generation " ..
             "PKM *ntfe-ingest.generation-advances-only-after-checks" }, function(t)
        -- Nine windows on one table; every forest builds and the
        -- cross-forest check passes, and it is publication that refuses.
        refused(t, "nine windows on one table", windows(9), ing.E2BIG)
        t:assert_eq(ing.verdict(vm, 6301), "reject", "the standing rule still speaks")
        accepted(t, "eight windows on one table", windows(8))
    end)

test("a refused cross-forest check advances nothing and the standing policy keeps judging",
    { spec = "PKM *ntfe-ingest.generation-advances-only-after-checks" }, function(t)
        refused(t, "a downward tag read", ing.policy({
            standing = { ["DstPort.Equal"] = 6301, Actions = { "PASS" } },
            w = { ["DstPort.Equal"] = 6302, Actions = { "TAG(down, Set)", "PASS" } },
        }, { Packet = { all = { Actions = { "PASS" } },
                        r = { ["Tag.down.Equal"] = 1, Actions = { "PASS" } } } }))
        t:assert_eq(ing.verdict(vm, 6301), "reject",
            "the policy that failed the check never judged anything")
    end)

test("every walk records its outcome and its time in the status",
    { spec = "PKM *ntfe-ingest.walk-outcome-in-status" }, function(t)
        local before_ns = ing.realtime_ns(vm)
        local ok = ing.replace(E, STANDING)
        t:assert_eq(ok.last_ingest_error, 0, "a walk that publishes records 0")
        t:assert(ok.last_ingest_t_ns >= before_ns, "and its time, on the realtime clock")
        local bad = ing.replace(E, flow_rule({ Enabled = 7 }))
        t:assert_eq(bad.last_ingest_error, ing.EINVAL,
            "a refused walk records the positive errno: " .. bad.last_ingest_error)
        t:assert(bad.last_ingest_t_ns > ok.last_ingest_t_ns, "and its own time")
        -- A walk that publishes nothing new still records its outcome:
        -- the error goes back to 0.
        local same = ing.replace(E, STANDING)
        local again = ing.replace(E, STANDING)
        t:assert_eq(again.last_ingest_error, 0, "an unchanged walk records success")
        t:assert_eq(again.generation, same.generation, "though it published nothing")
        t:assert(again.last_ingest_t_ns > same.last_ingest_t_ns, "and is timestamped")
        t:assert(again.last_ingest_t_ns <= ing.realtime_ns(vm), "never in the future")
    end)
