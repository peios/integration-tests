-- peinit TRM §9.3 — where a timer's last-run history lives, and what
-- peinit does with it at boot.
--
-- The chapter is about crossing a reboot, and this harness cannot cross
-- one: every write lands in the overlay's tmpfs upper and nothing
-- survives. What it *can* do is arrange for the history to already be
-- there when peinit first looks, which is the same thing from peinit's
-- side — the boot-time read cannot tell a value written by a previous
-- boot from one written a moment earlier by something else.
--
-- So the history is seeded, by an autorun script staged into
-- /lcl/policy/autorun.d. Autoruns are Phase 1 step 7: after the image's
-- own `10-apply-seeds.sh` has created these service keys, and before
-- Phase 2 reads the service graph or a single timer is registered.
-- `20-pt-history.sh` sorts after both of the image's own scripts, so it
-- runs last of the three and the keys it writes into exist.
--
-- It computes its timestamps from `date +%s` rather than hard-coding
-- them, because two of them have to be *relative* to the boot: "long
-- past due" and "recorded a minute ago" are the two sides of the
-- catch-up decision, and only one of them can be written as a constant.
--
-- The schedules chosen for the "not yet due" cases are yearly rather
-- than daily. A daily schedule with a last run a minute ago is not due
-- — except during the one minute a day when it is, and a test that
-- fails once every one thousand four hundred and forty runs is worse
-- than no test.
--
-- Value names under TimerState are written out here in their encoded
-- form, `%2A-01-01%2000%3A00%3A00` and friends, rather than computed.
-- The encoding is one of the claims; deriving the expected name with
-- the same rule the test is checking would assert nothing.

local peinit = require("helpers.peinit")
peinit.claim(1)

local FILES = {
    ["pt/tick.sh"] = [[
echo "$1" >> /run/pt-ticks
]],
    -- Records that it started, then takes long enough that a test can
    -- look at the registry while it is still running.
    ["pt/slow.sh"] = [[
echo "$1" >> /run/pt-ticks
/bin/sleep 20
]],
    ["lcl/policy/autorun.d/20-pt-history.sh"] = { exec = true, [[#!/bin/sh
# Give some of this test's timers a last-run history, as a previous boot
# would have left it. Runs at phase 1.5, after 10-apply-seeds.sh has
# created the service keys and before Phase 2 registers any timer.
set -eu

now=$(/bin/date +%s)
# Four hundred days ago: hundreds of missed runs for a daily schedule.
old=$(( (now - 34560000) * 1000000000 ))
# A minute ago: recorded, and nowhere near due for a yearly schedule.
recent=$(( (now - 60) * 1000000000 ))

qword() { /bin/reg set "$1" "$2" "qword:$3"; }

qword 'Machine\System\Services\pt-p-old' LastTimerRun "$old"
qword 'Machine\System\Services\pt-p-off' LastTimerRun "$old"
qword 'Machine\System\Services\pt-p-recent' LastTimerRun "$recent"

# A multi-trigger service whose stored history is keyed by schedule
# string: one name matches a trigger it still has, the other names a
# schedule it no longer carries.
/bin/reg new 'Machine\System\Services\pt-p-orphan\TimerState'
qword 'Machine\System\Services\pt-p-orphan\TimerState' \
    '%2A-01-01%2000%3A00%3A00' "$recent"
qword 'Machine\System\Services\pt-p-orphan\TimerState' \
    '%2A-03-01%2000%3A00%3A00' "$recent"

echo "seeded timer history at $now"
]] },
}

local function service(name, list)
    local values = {
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Type", type = "dword", data = 1 },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
    }
    for _, v in ipairs(list) do values[#values + 1] = v end
    return { path = [[Machine\System\Services\pt-p-]] .. name, values = values }
end

local function ticker(name, schedules, extra)
    local list = {
        { name = "Arguments", type = "multi", data = { "/pt/tick.sh", name } },
        { name = "Triggers", type = "multi", data = schedules },
    }
    for _, v in ipairs(extra or {}) do list[#list + 1] = v end
    return service(name, list)
end

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },

    -- One trigger, no history: the first-boot case, whose timestamp
    -- lives at a fixed name on the service's own key.
    ticker("single", { "timer:*-*-* 02:00:00" }),

    -- Two triggers, no history: one timestamp each, under a subkey,
    -- named by the schedule. The first of the two is the schedule the
    -- TRM works through as its encoding example.
    ticker("multi", { "timer:*-*-* 02:00:00", "timer:*-*-* 03:00:00" }),

    -- The same schedule twice. Two triggers, so per-trigger storage —
    -- and one name, so one timestamp.
    ticker("dup", { "timer:*-*-* 05:00:00", "timer:*-*-* 05:00:00" }),

    -- History from four hundred days ago on a daily schedule.
    ticker("old", { "timer:*-*-* 02:00:00" }),

    -- History from a minute ago on a yearly schedule: recorded, and not
    -- due again for months.
    ticker("recent", { "timer:*-01-01 00:00:00" }),

    -- The same overdue history as pt-p-old, and persistence off.
    ticker("off", { "timer:*-*-* 02:00:00" },
        { { name = "TimerPersistent", type = "dword", data = 0 } }),

    -- Two triggers; the seeded history names one of them and one
    -- schedule this service no longer has.
    ticker("orphan", { "timer:*-01-01 00:00:00", "timer:*-02-01 00:00:00" }),

    -- Catches up at boot and then runs for twenty seconds, so the
    -- registry can be read while it is still going.
    service("slow", {
        { name = "Arguments", type = "multi", data = { "/pt/slow.sh", "slow" } },
        { name = "Triggers", type = "multi", data = { "timer:*-*-* 02:00:00" } },
    }),
}

local vm = peinit.boot({
    name = "persist",
    files = peinit.merge(FILES, peinit.seed("pt-p", SERVICES)),
})

local function ticks()
    local counts = setmetatable({}, { __index = function() return 0 end })
    for _, line in ipairs(peinit.lines(vm:run("cat /run/pt-ticks 2>/dev/null").stdout)) do
        rawset(counts, line, counts[line] + 1)
    end
    return counts
end

local KEY = [[Machine\System\Services\pt-p-]]

--- Every value on a key, as name -> {type, data}. Missing key = nil.
local function values_of(key)
    local out = vm:run("reg get '" .. key .. "'")
    if out.exit_code ~= 0 then return nil end
    local values = {}
    for _, line in ipairs(peinit.lines(out.stdout)) do
        local name, ty, data = line:match("^(%S+) = (%S+) (.*)$")
        if name then values[name] = { type = ty, data = data } end
    end
    return values
end

--- Whether `key` has a TimerState subkey.
local function has_timer_state(key)
    local out = vm:run("reg ls '" .. key .. "' --keys-only")
    return out.exit_code == 0 and out.stdout:find("TimerState", 1, true) ~= nil
end

--- The guest's idea of now, in nanoseconds.
local function now_ns()
    return tonumber(vm:run("date +%s").stdout:match("%d+")) * 1000000000
end

-- Every catch-up this boot is going to do has been decided by the time
-- the slowest of them has recorded a run. pt-p-slow catches up like the
-- rest and then stays running, so waiting for its tick is a mark that
-- the registration pass is behind us without waiting on a clock.
wait_until(function() return ticks()["slow"] > 0 end,
    { timeout = peinit.STAGE_TIMEOUT, interval = 0.5,
      desc = "the boot's catch-up firings" })

test("a service with one timer records its last run on its own key, as a REG_QWORD",
    {
        spec = {
            "peinit *persist.last-run-timestamps-are-reg-qword-values",
            "peinit *persist.a-single-trigger-stores-lasttimerrun-on-the-service-key",
            "peinit *persist.a-trigger-with-no-history-catches-up-once",
            "peinit *persist.timerpersistent-is-on-by-default",
        },
    },
    function(t)
        -- pt-p-single carries no TimerPersistent value at all, so the
        -- default is what decided this: peinit went looking for a last
        -- run, found none, and treated "no history" the same way it
        -- treats history that has come due — one firing, now.
        wait_until(function() return ticks()["single"] > 0 end,
            { timeout = 30, interval = 0.5, desc = "the first-boot catch-up" })
        t:assert_eq(ticks()["single"], 1,
            "a trigger with no history catches up exactly once")

        local values = values_of(KEY .. "single")
        local last = values["LastTimerRun"]
        t:assert(last, "the timestamp is on the service's own key, at a fixed name")
        t:assert_eq(last.type, "REG_QWORD", "as a REG_QWORD")

        -- And it is a wall-clock nanosecond count from this boot rather
        -- than an uptime or a second count, which is §9.4's claim about
        -- which clock the recording is made on.
        local recorded = tonumber(last.data)
        local now = now_ns()
        t:assert(recorded > now - 600 * 1000000000 and recorded <= now + 1000000000,
            string.format("and it is when the timer fired: %d against a clock at %d",
                recorded, now))

        -- One trigger means no subkey: the per-trigger layout is what a
        -- service gets when it has more than one, not the layout with a
        -- single entry in it.
        t:assert(not has_timer_state(KEY .. "single"),
            "and there is no TimerState subkey for a single-trigger service")
    end)

test("a service with several timers records one timestamp per trigger, named by the schedule",
    {
        spec = {
            "peinit *persist.multiple-triggers-store-one-timestamp-per-trigger-under-timerstate",
            "peinit *persist.a-schedule-name-is-percent-encoded-with-uppercase-hex",
        },
    },
    function(t)
        wait_until(function() return ticks()["multi"] >= 2 end,
            { timeout = 30, interval = 0.5,
              desc = "both of the multi-trigger service's catch-ups" })

        -- Two triggers, both without history, so both are overdue at
        -- boot. They are separate computations against separate
        -- descriptors, so both fire; the Oneshot pending flag turns the
        -- second into a run that follows the first (§9.2).
        t:assert_eq(ticks()["multi"], 2,
            "one catch-up per trigger, not one per service")

        local state = values_of(KEY .. "multi\\TimerState")
        t:assert(state, "the timestamps are under a TimerState subkey")

        -- The names, byte for byte. `*` is %2A, the separating space is
        -- %20 and `:` is %3A, with the hex digits in upper case; the
        -- digits and the hyphens pass through. The first of these is
        -- the expansion the TRM writes out.
        local expected = {
            ["%2A-%2A-%2A%2002%3A00%3A00"] = true,
            ["%2A-%2A-%2A%2003%3A00%3A00"] = true,
        }
        for name, value in pairs(state) do
            t:assert(expected[name],
                "TimerState holds only the encoded schedules: found " .. name)
            t:assert_eq(value.type, "REG_QWORD", name .. " is a REG_QWORD")
            expected[name] = nil
        end
        for name in pairs(expected) do
            t:fail("no timestamp was recorded under " .. name)
        end

        -- And nothing at the single-trigger name, so the two layouts
        -- are alternatives rather than one being a superset.
        local values = values_of(KEY .. "multi")
        t:assert(not values["LastTimerRun"],
            "a multi-trigger service has no LastTimerRun on its own key")
    end)

test("two identical schedules on one service share a single timestamp",
    { spec = "peinit *persist.two-identical-schedules-share-one-timestamp" },
    function(t)
        -- pt-p-dup names the same schedule twice. That is two triggers
        -- as far as the storage layout is concerned — it gets the
        -- per-trigger subkey — but the two encode to one name, so there
        -- is one value and the second firing overwrites the first.
        wait_until(function() return ticks()["dup"] > 0 end,
            { timeout = 30, interval = 0.5, desc = "the duplicate schedule to fire" })

        local state = values_of(KEY .. "dup\\TimerState")
        t:assert(state, "storage is per-trigger, since there are two triggers")
        local names = {}
        for name in pairs(state) do names[#names + 1] = name end
        t:assert_eq(#names, 1,
            "and the two identical schedules share one timestamp: " ..
            table.concat(names, ", "))
        t:assert_eq(names[1], "%2A-%2A-%2A%2005%3A00%3A00",
            "under the encoding of the schedule they both are")
    end)

test("however many runs were missed, the catch-up is one run",
    {
        spec = {
            "peinit *persist.a-missed-run-is-caught-up-once-at-boot",
            "peinit *persist.catch-up-is-one-run-however-many-were-missed",
        },
    },
    function(t)
        -- pt-p-old's history says its daily schedule last ran four
        -- hundred days ago. The next occurrence after that is long
        -- past, so a run was missed — and so were three hundred and
        -- ninety nine others.
        wait_until(function() return ticks()["old"] > 0 end,
            { timeout = 30, interval = 0.5, desc = "the overdue catch-up" })
        vm:run("sleep 3")
        t:assert_eq(ticks()["old"], 1,
            "four hundred missed days produce one run, not four hundred")

        -- The control: the same read of the same value, with history
        -- that has not come due. peinit computes the next occurrence
        -- after the recorded run, finds it is still ahead, and arms for
        -- it rather than firing.
        t:assert_eq(ticks()["recent"], 0,
            "a trigger whose next occurrence is still ahead does not catch up")
    end)

test("TimerPersistent=0 neither reads the history nor writes it",
    { spec = "peinit *persist.timerpersistent-zero-ignores-history" },
    function(t)
        -- pt-p-off has exactly pt-p-old's schedule and exactly
        -- pt-p-old's four-hundred-day-old history. pt-p-old caught up;
        -- this one did not, which can only be because the value was
        -- never read.
        t:assert_eq(ticks()["off"], 0,
            "the overdue history was not consulted")

        -- And it is untouched: the seeded value is still the seeded
        -- value, so nothing was written back either.
        local seeded = values_of(KEY .. "off")["LastTimerRun"]
        t:assert(seeded, "the seeded value is still there")
        local recorded = tonumber(seeded.data)
        t:assert(recorded < now_ns() - 86400 * 1000000000,
            "still four hundred days old rather than rewritten: " .. seeded.data)
    end)

test("the timestamp is written when the start is initiated, not when the service finishes",
    { spec = "peinit *persist.the-timestamp-is-written-when-the-start-is-initiated" },
    function(t)
        -- pt-p-slow catches up at boot and then runs for twenty
        -- seconds. If the timestamp were recorded on completion there
        -- would be nothing to read for those twenty seconds; the claim
        -- is that the run counts as attempted the moment it starts, so
        -- that a service which crashes half way through is not
        -- re-triggered on the next boot as though it had been missed.
        local state = vm:run("svctl --json status pt-p-slow").stdout
        local phase = state:match('"state":"([^"]*)"')
        t:assert(phase == "starting" or phase == "active",
            "the service is still running: " .. state)

        local last = values_of(KEY .. "slow")["LastTimerRun"]
        t:assert(last, "and its last run is already recorded: " .. state)
        t:assert_eq(last.type, "REG_QWORD", "as a REG_QWORD")
    end)

test("a reload re-arms every timer from now and catches nothing up",
    { spec = "peinit *persist.a-reload-re-arms-from-now-with-no-catch-up" },
    function(t)
        -- The same definition that caught up at boot, introduced by a
        -- reload instead. pt-p-single is the control and it is already
        -- in the record above: no history, persistence on, one run at
        -- boot. This one is identical in every respect except the
        -- moment peinit first sees it, and it must not run.
        local key = [[Machine\System\Services\pt-p-added]]
        vm:run("reg new '" .. key .. "'"):assert_ok()
        vm:run("reg set '" .. key .. "' ImagePath 'sz:/bin/sh'"):assert_ok()
        vm:run("reg set '" .. key .. "' Arguments 'multi:/pt/tick.sh,added'"):assert_ok()
        vm:run("reg set '" .. key .. "' Type 'dword:1'"):assert_ok()
        vm:run("reg set '" .. key .. "' Identity 'sz:SYSTEM'"):assert_ok()
        vm:run("reg set '" .. key .. "' Readiness 'dword:1'"):assert_ok()
        vm:run("reg set '" .. key .. [[' Triggers 'multi:timer:*-*-* 02:00:00']])
            :assert_ok()
        vm:run("svctl --json reload-config"):assert_ok()

        vm:run("sleep 8")
        t:assert_eq(ticks()["added"], 0,
            "history is consulted at boot only, so the reload armed for 2am " ..
            "rather than firing")
        t:assert_eq(ticks()["single"], 1,
            "while the same definition present at boot did catch up, once")
    end)

test("changing a schedule orphans the timestamp stored under its old name",
    { spec = "peinit *persist.changing-a-schedule-orphans-its-history" },
    function(t)
        -- pt-p-orphan is the state a service is in one boot after
        -- somebody edited one of its two schedules. Its stored history
        -- is keyed by schedule string: `*-01-01 00:00:00` still names a
        -- trigger it has, `*-03-01 00:00:00` names one it does not, and
        -- the trigger it acquired instead — `*-02-01 00:00:00` — has no
        -- entry at all.
        --
        -- So peinit finds history for one trigger and none for the
        -- other, and the one with none catches up: the spurious run the
        -- TRM's note describes, which is the whole cost of keying by
        -- schedule.
        wait_until(function() return ticks()["orphan"] > 0 end,
            { timeout = 30, interval = 0.5, desc = "the orphaned trigger's catch-up" })
        vm:run("sleep 3")
        t:assert_eq(ticks()["orphan"], 1,
            "exactly one trigger had no history, so exactly one caught up")

        local state = values_of(KEY .. "orphan\\TimerState")
        t:assert(state["%2A-03-01%2000%3A00%3A00"],
            "the timestamp for the schedule the service no longer has is still there")
        t:assert(state["%2A-02-01%2000%3A00%3A00"],
            "the schedule it has instead recorded its own run under its own name")
        t:assert(state["%2A-01-01%2000%3A00%3A00"],
            "and the trigger whose history was current kept it")

        -- The two seeded values were written at the same instant. The
        -- one whose trigger still exists was read and not rewritten;
        -- the orphan was never looked at. They should therefore still
        -- agree, while the trigger that caught up is a boot later.
        t:assert_eq(state["%2A-01-01%2000%3A00%3A00"].data,
            state["%2A-03-01%2000%3A00%3A00"].data,
            "neither of the seeded timestamps moved")
        t:assert(tonumber(state["%2A-02-01%2000%3A00%3A00"].data) >
            tonumber(state["%2A-01-01%2000%3A00%3A00"].data),
            "and the catch-up recorded a later one")
    end)
