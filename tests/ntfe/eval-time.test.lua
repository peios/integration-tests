-- PKM §6.4 — Evaluation, step 1, the clock: live-time conditions are
-- evaluated last, the conjunction stops at the first false condition,
-- and every time condition actually reached records when it would next
-- flip. The earliest such flip is the evaluation's `expires_at`, which
-- the Flow layer keeps as its sentence's expiry and the per-packet
-- layers ignore.
--
-- The expiry is read from the flows dump (sentence slot 0, the outbound
-- judgment of a loopback flow). The guest clock is set to known moments
-- of Monday 2026-09-21 (UTC) so every expected flip is exact. The Flow
-- forest under test always holds a catch-all PASS with no time in it,
-- so whatever the rule under test does, the flow lives and its sentence
-- can be read; the rule under test carries `Priority = 1` where its
-- attribution is the evidence that it matched.
--
-- Own VM: the policy and the wall clock are machine-wide state.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local ev = require("helpers.ntfe_eval")

local vm = provium:vm("vntfeevt", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local E = ntfe.engine(vm, ev.policy("Flow", ev.PASS_ALL))

local H, D, MON = ev.HOUR, ev.DAY, ev.MONDAY

-- The Flow forest: the catch-all plus `rules`.
local function flow_policy(rules)
    rules.all = { Actions = { "PASS" } }
    return ev.policy("Flow", rules)
end

-- Judge one new flow to `port` and return its slot-0 sentence and the
-- outbound Flow event.
local function judge(t, port)
    local r = ev.probe(E, port)
    local f = ev.flow_to(E, port)
    t:assert(f, "the flow to " .. port .. " is in the dump")
    return f.sentences[0], r.flow()
end

test("a reached time condition records the moment it would next flip",
    { spec = "PKM *ntfe-eval.reached-clock-conditions-record-next-flip PKM *ntfe-eval.clock-flip-scans-one-cycle-ahead" },
    function(t)
        local cases = {
            -- Monday 10:30: hour 10 is in 9-17 until 18:00.
            { 7201, "Time.Hour.Equal", "9-17", MON + 18 * H },
            -- Every hour is below 24: the condition never flips.
            { 7202, "Time.Hour.LessThan", 24, 0 },
            -- Minute 30 is in 0-44 until 10:45.
            { 7203, "Time.Minute.Equal", "0-44", MON + 10 * H + 45 * 60 },
            -- Monday (ISO 1) is in 1-5 until Saturday 00:00.
            { 7204, "Time.DayOfWeek.Equal", "1-5", MON + 5 * D },
            -- Second 0 is below 30 until 10:30:30.
            { 7205, "Time.Second.LessThan", 30, MON + 10 * H + 30 * 60 + 30 },
        }
        local rules = {}
        for _, c in ipairs(cases) do
            rules["at-" .. c[1]] = { ["DstPort.Equal"] = c[1], [c[2]] = c[3],
                                     Priority = 1, Actions = { "PASS" } }
        end
        ev.publish(t, E, flow_policy(rules))
        for _, c in ipairs(cases) do
            ev.clock_at(vm, 10 * H + 30 * 60)
            local s, e = judge(t, c[1])
            t:assert_eq(e and e.attributed, "at-" .. c[1],
                c[2] .. " " .. tostring(c[3]) .. " holds at Monday 10:30 and its rule wins")
            t:assert_eq(s.expires_at, c[4],
                "and the sentence expires where " .. c[2] .. " " .. tostring(c[3]) .. " next flips")
        end
    end)

test("day-of-month, month and year conditions flip at the next midnight",
    { spec = "PKM *ntfe-eval.calendar-fields-flip-at-next-midnight" }, function(t)
        local cases = {
            { 7211, "Time.DayOfMonth.Equal", 21 },
            { 7212, "Time.Month.Equal", 9 },
            { 7213, "Time.Year.Equal", 2026 },
            -- True for every year there is: still "next midnight", since
            -- these fields are not scanned.
            { 7214, "Time.Year.GreaterThan", 1 },
        }
        local rules = {}
        for _, c in ipairs(cases) do
            rules["at-" .. c[1]] = { ["DstPort.Equal"] = c[1], [c[2]] = c[3],
                                     Priority = 1, Actions = { "PASS" } }
        end
        ev.publish(t, E, flow_policy(rules))
        for _, c in ipairs(cases) do
            ev.clock_at(vm, 10 * H + 30 * 60)
            local s, e = judge(t, c[1])
            t:assert_eq(e and e.attributed, "at-" .. c[1], c[2] .. " holds on 2026-09-21")
            t:assert_eq(s.expires_at, MON + D,
                "and the sentence expires at the next midnight")
        end
    end)

test("a false time condition is consulted too, so a rule that missed only on the clock matches later",
    { spec = "PKM *ntfe-eval.false-clock-condition-is-consulted" }, function(t)
        ev.publish(t, E, flow_policy({
            ["office-hours"] = { ["DstPort.Equal"] = 7221, ["Time.Hour.Equal"] = "9-17",
                                 Priority = 1, Actions = { "DROP" } },
        }))
        ev.clock_at(vm, 8 * H + 30 * 60)
        local rx = assert(ntfe.udp_bind(vm, "127.0.0.1", 7221))
        local tx = assert(ntfe.udp_connect(vm, "127.0.0.1", 7221))
        local _, first = E:during(function() ntfe.send(vm, tx, "early") end)
        t:assert(ntfe.recv(vm, rx, 300), "at 08:30 the higher-priority rule misses and the datagram passes")
        local early = ntfe.matching(first, { layer = ntfe.LAYER.FLOW, dst_port = 7221 })[1]
        t:assert_eq(early and early.attributed, "all", "on the catch-all")
        t:assert_eq(ev.flow_to(E, 7221).sentences[0].expires_at, MON + 9 * H,
            "yet the sentence expires at 09:00, where the false condition would flip")

        ev.clock_at(vm, 9 * H + 5)
        local delta, later = E:during(function() ntfe.send(vm, tx, "late") end)
        local _, why = ntfe.recv(vm, rx, 300)
        t:assert_eq(why, "timeout", "after 09:00 the same flow's next datagram is dropped")
        t:assert(delta.flow_expired >= 1, "its sentence having gone stale on the clock")
        local judged = ntfe.matching(later, { seat = ntfe.SEAT.LOCAL_OUT, layer = ntfe.LAYER.FLOW,
                                              dst_port = 7221 })[1]
        t:assert_eq(judged and judged.attributed, "office-hours",
            "and the re-judgment finds the rule now matches: " .. ntfe.describe(later))
        sys.close(vm, tx)
        sys.close(vm, rx)
    end)

test("a rule whose other conditions fail first never consults its clock",
    { spec = "PKM *ntfe-eval.unreached-clock-condition-not-consulted" }, function(t)
        ev.publish(t, E, flow_policy({
            elsewhere = { ["DstPort.Equal"] = 7299, ["Time.Hour.Equal"] = "9-17",
                          Actions = { "DROP" } },
        }))
        ev.clock_at(vm, 10 * H + 30 * 60)
        local s, e = judge(t, 7231)
        t:assert_eq(e and e.attributed, "all", "the port condition fails, so only the catch-all matches")
        t:assert_eq(s.expires_at, 0,
            "and the time condition behind it contributes no expiry (it would have said 18:00)")
    end)

test("the conjunction stops at the first false condition",
    { spec = "PKM *ntfe-eval.conjunction-stops-at-first-false" }, function(t)
        -- Both conditions are live-time, so they keep the order the
        -- registry gives them: Time.Hour before Time.Year. At 23:30 the
        -- hour condition is false and would flip at 11:00 tomorrow; the
        -- year condition would flip at midnight, which is sooner.
        ev.publish(t, E, flow_policy({
            ["eleven-oclock"] = { ["DstPort.Equal"] = 7241, ["Time.Hour.Equal"] = 11,
                                  ["Time.Year.GreaterThan"] = 1, Actions = { "DROP" } },
        }))
        ev.clock_at(vm, 23 * H + 30 * 60)
        local s = judge(t, 7241)
        t:assert_eq(s.expires_at, MON + D + 11 * H,
            "the expiry is the false hour condition's flip, not the midnight the year condition would add")
    end)

test("live-time conditions are evaluated after every other condition",
    { spec = "PKM *ntfe-eval.live-time-conditions-evaluated-last" }, function(t)
        -- The registry hands a rule's values sorted by name, so `Vlan`
        -- comes after `Time.Year`. Absent on loopback, the Vlan condition
        -- is false; were the stored order kept, the year condition would
        -- be reached first and record the next midnight.
        ev.publish(t, E, flow_policy({
            ["vlan-and-year"] = { ["DstPort.Equal"] = 7251, ["Time.Year.GreaterThan"] = 1,
                                  ["Vlan.Equal"] = 5, Actions = { "DROP" } },
            ["year-alone"] = { ["DstPort.Equal"] = 7252, ["Time.Year.GreaterThan"] = 1,
                               Actions = { "PASS" } },
        }))
        ev.clock_at(vm, 10 * H + 30 * 60)
        t:assert_eq(judge(t, 7252).expires_at, MON + D,
            "the year condition, when reached, records the next midnight")
        local sentence, e = judge(t, 7251)
        t:assert_eq(e and e.attributed, "all", "the Vlan condition fails")
        t:assert_eq(sentence.expires_at, 0,
            "and fails before the year condition is reached, though it is stored after it")
    end)

test("the earliest consulted flip is the evaluation's expiry, and the Flow sentence's",
    { spec = "PKM *ntfe-eval.expires-at-is-earliest-consulted-flip" }, function(t)
        ev.publish(t, E, flow_policy({
            hours = { ["DstPort.Equal"] = 7261, ["Time.Hour.Equal"] = "9-17", Actions = { "PASS" } },
            minutes = { ["DstPort.Equal"] = 7261, ["Time.Minute.LessThan"] = 45, Actions = { "PASS" } },
            today = { ["DstPort.Equal"] = 7261, ["Time.DayOfMonth.Equal"] = 21, Actions = { "PASS" } },
        }))
        ev.clock_at(vm, 10 * H + 30 * 60)
        local s = judge(t, 7261)
        t:assert_eq(s.expires_at, MON + 10 * H + 45 * 60,
            "three rules in three trees consulted the clock, and 10:45 is the soonest flip among them")
    end)

test("the per-packet layers compute an expiry and ignore it",
    { spec = "PKM *ntfe-eval.per-packet-layers-ignore-expires-at" }, function(t)
        -- The time condition lives in the Packet forest. Its flip at 18:00
        -- is computed there and goes nowhere: the Flow forest has no time
        -- condition, and the Packet layer keeps nothing between packets.
        local p = ev.policy("Packet", {
            all = { Actions = { "PASS" } },
            ["office-hours"] = { ["DstPort.Equal"] = 7271, ["Time.Hour.Equal"] = "9-17",
                                 Actions = { "DROP" } },
        })
        ev.publish(t, E, p)
        ev.clock_at(vm, 10 * H + 30 * 60)
        local rx = assert(ntfe.udp_bind(vm, "127.0.0.1", 7271))
        local tx = assert(ntfe.udp_connect(vm, "127.0.0.1", 7271))
        local _, first = E:during(function() ntfe.send(vm, tx, "in hours") end)
        local _, why = ntfe.recv(vm, rx, 300)
        t:assert_eq(why, "timeout", "at 10:30 the Packet rule drops")
        local e = ntfe.matching(first, { seat = ntfe.SEAT.EGRESS, layer = ntfe.LAYER.PACKET,
                                         dst_port = 7271 })[1]
        t:assert_eq(e and e.attributed, "office-hours", "on its time condition")
        t:assert_eq(ev.flow_to(E, 7271).sentences[0].expires_at, 0,
            "and the flow's sentence carries no expiry from it")

        ev.clock_at(vm, 18 * H + 30 * 60)
        ntfe.send(vm, tx, "after hours")
        t:assert(ntfe.recv(vm, rx, 300), "at 18:30 the next datagram is judged afresh and passes")
        sys.close(vm, tx)
        sys.close(vm, rx)
    end)
