-- peinit TRM §9.4 — jitter, and which clock a deadline is measured
-- against.
--
-- Two halves, and they need opposite conditions, so the file is in two
-- halves too and the order is load-bearing.
--
-- The jitter half is about *when inside a second* a firing lands, which
-- means the guest's clock has to be left alone while it is measured. It
-- runs first, on a five-second schedule, and reads the second-of-minute
-- each run recorded. With no jitter every run lands on a multiple of
-- five; with two seconds of jitter they scatter across the three
-- seconds after it and never before it.
--
-- The clock half then moves the guest's wall clock about, which is the
-- only way to reach any of §9.4's claims: a realtime step, a forward
-- jump over an occurrence, a backward jump, a deadline that elapsed
-- while nothing was looking. `date -s` is a discontinuous set of
-- CLOCK_REALTIME, which is exactly the event `TFD_TIMER_CANCEL_ON_SET`
-- exists for, so these are not simulations of the thing — they are the
-- thing.
--
-- The interval-timer claim is the mirror image and is checked in the
-- same half: a health check on a twenty-second interval must be
-- *unmoved* by an hour-long jump, because a monotonic deadline has no
-- opinion about the wall clock.
--
-- History is seeded by an autorun script staged into
-- /lcl/policy/autorun.d, which runs at phase 1.5 — after the image's
-- seed-apply has created these keys and before Phase 2 registers a
-- timer, so peinit's boot-time read finds it. See
-- timer-persistence.test.lua, which does the same thing at more length.

local peinit = require("helpers.peinit")
peinit.claim(1)

local FILES = {
    -- The second-of-minute is the measurement, so it goes in the line.
    ["pt/tick.sh"] = [[
echo "$1 $(date +%S)" >> /run/pt-ticks
]],
    ["pt/hc.sh"] = [[
echo check >> /run/pt-hc.log
]],
    ["lcl/policy/autorun.d/20-pt-history.sh"] = { exec = true, [[#!/bin/sh
# A last run in the future, and one in the recent past, for the two
# services whose boot-time catch-up decision is about which side of now
# the recorded timestamp falls on.
set -eu

now=$(/bin/date +%s)
ahead=$(( (now + 31536000) * 1000000000 ))
behind=$(( (now - 60) * 1000000000 ))

/bin/reg set 'Machine\System\Services\pt-j-ahead' LastTimerRun "qword:$ahead"
/bin/reg set 'Machine\System\Services\pt-j-behind' LastTimerRun "qword:$behind"

echo "seeded timer history at $now"
]] },
}

local function service(name, list)
    local values = {
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Type", type = "dword", data = 1 },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "Arguments", type = "multi", data = { "/pt/tick.sh", name } },
    }
    for _, v in ipairs(list) do values[#values + 1] = v end
    return { path = [[Machine\System\Services\pt-j-]] .. name, values = values }
end

--- Jitter is in whole seconds, and the schedule's period has to be
--- longer than the window or there is no residue a firing may not have.
--- Five and two: a firing may land on second 0, 1 or 2 of each group of
--- five, and never on 4 — which is what "never early" looks like from
--- outside.
local PERIOD, JITTER = 5, 2

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },

    -- The two jitter subjects, identical apart from TimerJitter.
    service("nojitter", {
        { name = "Triggers", type = "multi", data = { "timer:*-*-* *:*:0/5" } },
        { name = "TimerPersistent", type = "dword", data = 0 },
    }),
    service("jitter", {
        { name = "Triggers", type = "multi", data = { "timer:*-*-* *:*:0/5" } },
        { name = "TimerJitter", type = "dword", data = JITTER },
        { name = "TimerPersistent", type = "dword", data = 0 },
    }),

    -- Ten minutes of jitter and a catch-up due at boot. If the catch-up
    -- were jittered it would arrive somewhere in the next ten minutes.
    service("bootjitter", {
        { name = "Triggers", type = "multi", data = { "timer:*-*-* 02:00:00" } },
        { name = "TimerJitter", type = "dword", data = 600 },
    }),

    -- Seeded with a last run a year in the future, and one a minute in
    -- the past, on a schedule that is nowhere near due either way.
    service("ahead", {
        { name = "Triggers", type = "multi", data = { "timer:*-01-01 00:00:00" } },
    }),
    service("behind", {
        { name = "Triggers", type = "multi", data = { "timer:*-01-01 00:00:00" } },
    }),

    -- The clock-step subject: one daily occurrence, no jitter, no
    -- history, so every firing it does is one a clock move caused.
    service("daily", {
        { name = "Triggers", type = "multi", data = { "timer:*-*-* 02:00:00" } },
        { name = "TimerPersistent", type = "dword", data = 0 },
    }),

    -- The same, with a wide jitter window, for a step that lands inside
    -- one.
    service("window", {
        { name = "Triggers", type = "multi", data = { "timer:*-*-* 04:00:00" } },
        { name = "TimerJitter", type = "dword", data = 600 },
        { name = "TimerPersistent", type = "dword", data = 0 },
    }),

    -- Records its last run, so what a firing writes can be compared
    -- against the wall clock at the moment it fired.
    service("stamp", {
        { name = "Triggers", type = "multi", data = { "timer:*-*-* 06:00:00" } },
    }),

    -- Simple, resident, with a health check on a twenty-second
    -- interval. Its deadline is an interval rather than a schedule.
    {
        path = [[Machine\System\Services\pt-j-health]],
        values = {
            { name = "ImagePath", type = "sz", data = "/bin/sleep" },
            { name = "Arguments", type = "multi", data = { "100000" } },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
            { name = "Triggers", type = "multi", data = { "boot" } },
            { name = "HealthCheck", type = "sz", data = "/bin/sh /pt/hc.sh" },
            { name = "HealthCheckInterval", type = "dword", data = 20 },
            { name = "HealthCheckRetries", type = "dword", data = 3 },
            { name = "RestartWindow", type = "dword", data = 120 },
        },
    },
}

local vm = peinit.boot({
    name = "jitter",
    files = peinit.merge(FILES, peinit.seed("pt-j", SERVICES)),
})

--- Every firing so far, as a list of second-of-minute values per
--- service, in the order they happened.
local function runs()
    local out = setmetatable({}, { __index = function(tbl, key)
        local fresh = {}
        rawset(tbl, key, fresh)
        return fresh
    end })
    for _, line in ipairs(peinit.lines(vm:run("cat /run/pt-ticks 2>/dev/null").stdout)) do
        local name, second = line:match("^(%S+) (%d+)$")
        if name then
            local list = out[name]
            list[#list + 1] = tonumber(second)
        end
    end
    return out
end

local function count(name)
    return #runs()[name]
end

--- `count(name)` once it has stopped moving.
---
--- Every clock step below crosses at least one occurrence, so a firing
--- is already on its way when the step returns. A baseline taken on a
--- fixed sleep races it: on a busy host peinit's turn lands after the
--- sleep, the baseline is one too low, and the *next* assertion — which
--- is usually that nothing fired — sees that late firing and fails.
--- Waiting for the count to hold still instead makes the baseline mean
--- what it says.
local function settled_count(name)
    local last = count(name)
    wait_until(function()
        vm:run("sleep 2")
        local now = count(name)
        if now == last then return true end
        last = now
        return false
    end, { timeout = 90, interval = 0, desc = name .. "'s firings to settle" })
    return last
end

--- Assert that `name` fired exactly `expected` more times than `before`.
---
--- The wait is for the firings to arrive and the settle is for any
--- further ones to show up, so the assertion is still an exact count —
--- "one firing, not three" is proved by the settle, not by the wait.
--- What this does not do is call a slow firing a missing one, which is
--- the only way these ever failed under load.
local function expect_firings(t, name, before, expected, why)
    wait_until(function() return count(name) >= before + expected end,
        { timeout = 90, interval = 0.5, desc = why })
    vm:run("sleep 4")
    t:assert_eq(count(name), before + expected, why)
end

--- The boot catch-up evidence, taken before anything else has had time
--- to happen.
---
--- pt-j-bootjitter has ten minutes of jitter and a catch-up due, so a
--- jittered catch-up would land anywhere in the next six hundred
--- seconds. Ten is the whole budget here, and it has to be spent at the
--- top of the file rather than inside a test, because every test below
--- takes longer than that and would make the wait meaningless.
local boot_catch_up_ran = (function()
    local ok = pcall(function()
        wait_until(function() return count("bootjitter") > 0 end,
            { timeout = 10, interval = 0.2, desc = "the boot catch-up" })
    end)
    return ok
end)()

--- Forty-two seconds of the two five-second schedules, sampled once and
--- read by the two tests below.
---
--- Both need the same window: the point of the pair is that the only
--- difference between the two services is TimerJitter, so measuring
--- them at different times would leave load as an explanation for any
--- difference in what they did.
local SAMPLE = (function()
    vm:run("sleep 42")
    return runs()
end)()

test("with TimerJitter unset a timer fires on its schedule and nowhere near it",
    { spec = "peinit *jitter.zero-jitter-consults-no-randomness" },
    function(t)
        -- Zero is the default and it is a genuine short-circuit: no
        -- randomness is drawn, so the armed deadline is the occurrence
        -- the calendar produced and nothing else. Every firing lands on
        -- a multiple of five seconds.
        local plain = SAMPLE["nojitter"]
        t:assert(#plain >= 5, string.format(
            "the unjittered timer fired repeatedly: %d runs", #plain))
        for _, second in ipairs(plain) do
            t:assert_eq(second % PERIOD, 0, string.format(
                "with TimerJitter unset every firing is on the schedule, " ..
                "not near it: fired at :%02d", second))
        end
    end)

test("TimerJitter delays each firing by a fresh amount and skips none of them",
    {
        spec = {
            "peinit *jitter.a-random-delay-of-zero-to-timerjitter-seconds-is-added-to-each-firing",
            "peinit *jitter.the-delay-is-recomputed-on-every-firing",
            "peinit *jitter.a-timer-never-fires-early",
        },
        -- PEI-TBD: TimerJitter drops firings instead of delaying
        -- them. Measured against an otherwise identical schedule, only
        -- about one occurrence in (TimerJitter + 1) produces a run at
        -- all, and every run that does happen lands on the un-jittered
        -- occurrence rather than after it.
        tags = { "known-bug" },
    },
    function(t)
        -- The same schedule as the test above, with TimerJitter=2. What
        -- §9.4 says should change is *when inside the window* each
        -- firing lands -- a delay of nought, one or two seconds, drawn
        -- afresh each time and only ever added. What must not change is
        -- how many firings there are: jitter displaces an occurrence,
        -- it does not cancel one.
        local plain = SAMPLE["nojitter"]
        local jittered = SAMPLE["jitter"]
        local function shown()
            return string.format("jittered: %s / unjittered: %s",
                table.concat(jittered, ","), table.concat(plain, ","))
        end

        -- One firing per occurrence. One less than the unjittered timer
        -- is allowed for, because a delay can push the last firing of
        -- the window past its end.
        t:assert(#jittered >= #plain - 1, string.format(
            "a jittered timer fires as often as an unjittered one: %d against %d (%s)",
            #jittered, #plain, shown()))

        local delays = {}
        local distinct = {}
        local distinct_count = 0
        for _, second in ipairs(jittered) do
            local delay = second % PERIOD
            delays[#delays + 1] = delay
            -- Never early. A delay is added to the computed occurrence
            -- and only ever added, so a firing may land on second 0, 1
            -- or 2 of a group of five -- 3 if the process took a moment
            -- to reach `date` -- but never on 4, which would be one
            -- second before the occurrence rather than after it.
            t:assert(delay ~= PERIOD - 1, string.format(
                "a jittered firing is late, never early: fired at :%02d", second))
            if not distinct[delay] then
                distinct[delay] = true
                distinct_count = distinct_count + 1
            end
        end

        -- A delay was actually applied. With a window of two seconds
        -- and five or more firings, every one of them landing exactly
        -- on the occurrence means nothing was added.
        t:assert(distinct[1] or distinct[2], string.format(
            "the delay is added to the occurrence: delays were %s (%s)",
            table.concat(delays, ","), shown()))

        -- And it is drawn per firing rather than once per timer.
        t:assert(distinct_count >= 2, string.format(
            "the delay is recomputed each firing, so it varies: delays were %s",
            table.concat(delays, ",")))
    end)

test("the boot catch-up fires immediately however wide the jitter window is",
    { spec = "peinit *jitter.the-boot-catch-up-firing-is-not-jittered" },
    function(t)
        -- TimerJitter=600 on a service with a catch-up due. The catch-up
        -- is not an occurrence the calendar produced, so there is
        -- nothing to add a delay to: it happens now, and jitter starts
        -- applying at the occurrence armed after it.
        t:assert(boot_catch_up_ran,
            "the catch-up ran within ten seconds of the boot, not within ten minutes")
        t:assert_eq(count("bootjitter"), 1,
            "and once")
    end)

test("a last run recorded in the future is treated as no history at all",
    {
        spec = {
            "peinit *jitter.a-last-run-timestamp-in-the-future-is-treated-as-unknown",
            "peinit *jitter.a-boot-time-catch-up-decision-is-never-revisited",
        },
    },
    function(t)
        -- pt-j-ahead and pt-j-behind carry the same yearly schedule and
        -- differ only in which side of the boot's wall clock their
        -- recorded last run falls on. A year in the past would not be
        -- due; a year in the *future* cannot be believed, so peinit
        -- throws the history away and catches up.
        t:assert_eq(count("ahead"), 1,
            "history from the future is unusable, so the trigger caught up once")
        t:assert_eq(count("behind"), 0,
            "while history from a minute ago is ordinary and not yet due")

        -- And the check is a boot-time one. Ten minutes backwards puts
        -- pt-j-behind's recorded last run in the future by exactly the
        -- test the boot applied -- and nothing happens, because there
        -- is no runtime equivalent of it.
        --
        -- Ten minutes rather than a round date, and backwards rather
        -- than forwards, because the move must not cross the schedule's
        -- own next occurrence. A jump to some future month would fire
        -- this timer for an entirely ordinary reason and prove nothing.
        vm:run([[date -s "@$(( $(date +%s) - 600 ))"]]):assert_ok()
        vm:run("sleep 6")
        t:assert_eq(count("behind"), 0,
            "a clock move does not re-run the boot's catch-up decision")

        -- Put it back, so the tests below start from a clock that is
        -- roughly the host's rather than ten minutes behind it.
        vm:run([[date -s "@$(( $(date +%s) + 600 ))"]]):assert_ok()
    end)

test("an interval deadline is measured on the monotonic clock and a wall-clock jump does not move it",
    { spec = "peinit *jitter.interval-timers-are-monotonic" },
    function(t)
        -- A health check on a twenty-second interval, and an hour added
        -- to the wall clock. On a realtime deadline that hour is one
        -- hundred and eighty missed intervals; on a monotonic one it is
        -- nothing at all, because no elapsed time has passed.
        local function checks()
            local ok, text = pcall(function() return vm:read_file("/run/pt-hc.log") end)
            return ok and #peinit.lines(text) or 0
        end
        -- Ninety seconds for a twenty-second interval: the bound is
        -- there to fail a check that never runs, not to time one that
        -- is merely late behind four other VMs.
        wait_until(function() return checks() > 0 end,
            { timeout = 90, interval = 0.5, desc = "the first health check" })

        local before = checks()
        vm:run("date -s '2027-05-01 13:00:00'"):assert_ok()
        vm:run("sleep 6")
        local after = checks()

        t:assert(after - before <= 1, string.format(
            "an hour of wall clock is no elapsed time: %d checks became %d",
            before, after))

        -- And the interval still works afterwards, so what happened is
        -- that the deadline was left alone rather than lost.
        wait_until(function() return checks() > after end,
            { timeout = 60, interval = 0.5,
              desc = "the interval to come round again" })
    end)

test("a calendar timer stays anchored to its wall-clock time across a clock correction",
    {
        spec = {
            "peinit *jitter.calendar-timers-are-absolute-realtime-timers-cancelled-on-a-clock-set",
            "peinit *jitter.a-forward-step-across-an-occurrence-fires-it-once",
        },
    },
    function(t)
        -- pt-j-daily is `*-*-* 02:00:00`. Put the clock at one in the
        -- morning: the step itself crosses whatever occurrence was
        -- armed, so one firing lands while the clock settles, and then
        -- nothing, because it is not two o'clock.
        vm:run("date -s '2027-05-10 01:00:00'"):assert_ok()
        local settled = settled_count("daily")

        vm:run("sleep 6")
        t:assert_eq(count("daily"), settled,
            "at one in the morning a two o'clock timer does not fire")

        -- Now walk up to two o'clock on the new clock. The timer fires
        -- there, which is the claim: the descriptor was cancelled when
        -- the clock was set, the occurrence was recomputed against the
        -- clock the machine now has, and `*-*-* 02:00:00` still means
        -- two in the morning rather than the absolute instant it
        -- happened to mean before.
        vm:run("date -s '2027-05-10 01:59:52'"):assert_ok()
        vm:run("sleep 4")
        local before_boundary = count("daily")
        t:assert_eq(before_boundary, settled,
            "eight seconds before the hour, still nothing")

        expect_firings(t, "daily", before_boundary, 1,
            "and at two o'clock exactly, once")
    end)

test("a jump over several occurrences fires once, and a jump backwards fires not at all",
    {
        spec = {
            "peinit *jitter.a-missed-occurrence-within-one-uptime-fires-once",
            "peinit *jitter.an-elapsed-absolute-deadline-fires-once-on-resume",
            "peinit *jitter.a-backward-step-pushes-the-next-firing-later",
        },
    },
    function(t)
        -- Three days forward, over three two-o'clocks. peinit reads an
        -- expiration count from the descriptor and ignores it: the
        -- deadline elapsed, so the timer fires, once, and then computes
        -- the next occurrence from the clock it now has. A suspend long
        -- enough to cross a week produces the same one firing for the
        -- same reason.
        local before = settled_count("daily")
        vm:run("date -s '2027-05-13 03:00:00'"):assert_ok()
        expect_firings(t, "daily", before, 1,
            "three elapsed occurrences produce one firing, not three")

        -- And backwards. The clock goes back two hours, to before the
        -- two o'clock that has just passed on this day -- so the next
        -- occurrence is an hour ahead rather than behind, and the timer
        -- waits for it.
        local after_jump = count("daily")
        vm:run("date -s '2027-05-13 01:00:00'"):assert_ok()
        vm:run("sleep 8")
        t:assert_eq(count("daily"), after_jump,
            "a backward step pushes the next firing later rather than tripping it")
    end)

test("a step that lands inside a jitter window fires at the un-jittered time",
    { spec = "peinit *jitter.a-step-inside-a-jitter-window-fires-at-the-unjittered-time" },
    function(t)
        -- pt-j-window is `*-*-* 04:00:00` with ten minutes of jitter,
        -- so it is armed for four o'clock plus some number of seconds
        -- up to six hundred. Put the clock thirty seconds past four:
        -- the armed deadline is almost certainly still ahead, and the
        -- timer fires anyway, because what peinit compares the new
        -- clock against on a cancellation is the *scheduled* time and
        -- not the jittered one.
        --
        -- If the draw happened to be under thirty seconds the timer
        -- would have been due regardless, so this can be weaker than it
        -- looks -- but never wrong. It is the un-jittered comparison
        -- that makes it reliable rather than one-in-twenty.
        -- Eight seconds of settle, not four. The move to just before
        -- four o'clock is itself a jump over a week of occurrences, so
        -- it triggers a catch-up of its own, and a baseline taken
        -- before that landed would count it as the firing under test.
        vm:run("date -s '2027-05-20 03:59:50'"):assert_ok()
        local before = settled_count("window")

        vm:run("date -s '2027-05-20 04:00:30'"):assert_ok()
        expect_firings(t, "window", before, 1,
            "the firing happened as soon as the clock passed the scheduled time")
    end)

test("a last run is recorded against the wall clock rather than elapsed time",
    { spec = "peinit *jitter.last-run-timestamps-are-recorded-on-the-realtime-clock" },
    function(t)
        -- The guest's wall clock is now a year ahead of where it booted
        -- and its uptime is a couple of minutes. pt-j-stamp records its
        -- last run, so what it wrote after a firing under the moved
        -- clock says which of the two the record is taken from.
        --- The recorded last run, or nil while there is none.
        local function stamp()
            local out = vm:run(
                [[reg get 'Machine\System\Services\pt-j-stamp' LastTimerRun]])
            return out.exit_code == 0 and tonumber(out.stdout:match("%d+")) or nil
        end

        -- Waiting for the record to change, rather than sleeping for as
        -- long as it ought to take: the subject is the value the firing
        -- wrote, so the firing is the thing to wait for. A fixed sleep
        -- here read the *previous* firing's value on a busy host and
        -- compared it against a clock that had since moved.
        local previous = stamp()
        vm:run("date -s '2027-05-21 05:59:50'"):assert_ok()
        local recorded = wait_until(function()
            local current = stamp()
            return current and current ~= previous and current
        end, {
            timeout = 90,
            interval = 0.5,
            desc = "a firing under the moved clock to record its last run",
        })
        local now = tonumber(vm:run("date +%s").stdout:match("%d+")) * 1000000000

        t:assert(recorded > now - 120 * 1000000000 and recorded <= now + 1000000000,
            string.format(
                "the timestamp follows the wall clock it fired under: %d against %d",
                recorded, now))
    end)
