-- peinit TRM §9.1 — what a calendar expression *means*, as opposed to
-- whether it parses.
--
-- timer-calendar-grammar.test.lua gets a long way on "does this arm",
-- because an expression that matches nothing is reported. It cannot get
-- at the two claims that are about *when* a schedule fires: what the
-- named shortcuts expand to, and which day a weekday name picks.
--
-- Both are answered here by moving the guest's wall clock. That is the
-- honest way in rather than a shortcut around one: calendar timers are
-- armed as absolute CLOCK_REALTIME deadlines with
-- `TFD_TIMER_CANCEL_ON_SET` (§9.4), so a `date -s` is exactly the event
-- peinit is built to handle — the descriptor is cancelled, the next
-- occurrence is recomputed against the new clock, and the timer re-arms.
-- Waiting for a real 1 January is the only alternative.
--
-- Every clock move follows the same shape, and the shape is the point:
--
--   set the clock ten seconds before the boundary
--   sleep, and let the step's own catch-up firings land and be counted
--   snapshot
--   sleep across the boundary
--   snapshot
--
-- The first sleep matters. A step forward over months crosses occurrence
-- after occurrence, and each crossed timer fires once when its
-- descriptor is cancelled and found overdue (§9.4). Those firings are
-- real and are not what is being measured, so they are allowed to
-- happen and are then excluded by taking the baseline after them. What
-- the second window sees is only the boundary.
--
-- The rate tests come first, before any clock move, and their
-- definitions are disabled once they are done: a `*:*:*` service starts
-- once a second for as long as it is armed, and every later clock step
-- would give it another catch-up on top.

local peinit = require("helpers.peinit")
peinit.claim(1)

local FILES = {
    -- One line per firing, in one file, named by whoever fired. Cheaper
    -- to read than a file per service, and the ordering is a record of
    -- what happened in what order if a case ever needs explaining.
    ["pt/tick.sh"] = [[
echo "$1" >> /run/pt-ticks
]],
}

--- Services whose firing rate is the evidence. Read once, over one
--- window, with no clock involved.
local RATE = {
    { "every-second", "*-*-* *:*:*" },
    { "every-third", "*-*-* *:*:0/3" },
    { "second-zero", "*-*-* *:*:00" },
    { "hour-minute", "*-*-* *:*" },
}

--- Weekday names that must all mean Monday, plus one that must not.
---
--- The three Monday spellings need service names that differ by more
--- than case: registry key names are case-insensitive, so `wd-monday`
--- and `wd-MONDAY` would be one key and the second seed would land on
--- top of the first.
local WEEKDAY = {
    { "wd-abbrev", "Mon *-*-* *:*:*" },
    { "wd-full", "Monday *-*-* *:*:*" },
    { "wd-shouted", "MONDAY *-*-* *:*:*" },
    { "wd-tuesday", "Tue *-*-* *:*:*" },
}

--- Every named shortcut, one service each.
local SHORTCUT = {
    { "sc-minutely", "minutely" },
    { "sc-hourly", "hourly" },
    { "sc-daily", "daily" },
    { "sc-weekly", "weekly" },
    { "sc-monthly", "monthly" },
    { "sc-quarterly", "quarterly" },
    { "sc-semiannually", "semiannually" },
    { "sc-yearly", "yearly" },
    { "sc-annually", "annually" },
}

local function timer_service(id, schedule)
    return {
        path = [[Machine\System\Services\pt-m-]] .. id,
        values = {
            { name = "ImagePath", type = "sz", data = "/bin/sh" },
            { name = "Arguments", type = "multi", data = { "/pt/tick.sh", id } },
            { name = "Type", type = "dword", data = 1 },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
            { name = "Triggers", type = "multi", data = { "timer:" .. schedule } },
            -- Without this every one of these catches up at boot
            -- (§9.3), which puts a firing in the log that no schedule
            -- asked for.
            { name = "TimerPersistent", type = "dword", data = 0 },
        },
    }
end

local keys = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },
}
for _, group in ipairs({ RATE, WEEKDAY, SHORTCUT }) do
    for _, case in ipairs(group) do
        keys[#keys + 1] = timer_service(case[1], case[2])
    end
end

local vm = peinit.boot({
    name = "cal-meaning",
    files = peinit.merge(FILES, peinit.seed("pt-m", keys)),
})

--- How many times each service has fired, so far, as a table.
local function ticks()
    local counts = {}
    local text = vm:run("cat /run/pt-ticks 2>/dev/null").stdout
    for _, line in ipairs(peinit.lines(text)) do
        counts[line] = (counts[line] or 0) + 1
    end
    return counts
end

--- Firings between two snapshots. A service that has never fired at all
--- is absent from both, so the result is defaulted to zero rather than
--- left nil — "did not fire" is the interesting answer here, and it
--- should read as a number.
local function since(before, after)
    local delta = setmetatable({}, { __index = function() return 0 end })
    for name, count in pairs(after) do
        rawset(delta, name, count - (before[name] or 0))
    end
    return delta
end

--- Move the clock to ten seconds before `boundary`, let the step's own
--- catch-up firings land, then watch the boundary go past.
---
--- Returns the firings that happened in the eight seconds after the
--- baseline, and only those: the baseline is taken after the step has
--- settled, so the catch-up firings the step itself caused are already
--- counted and cancel out.
---
--- The two clock reads are not decoration. The settle has to finish
--- *before* the boundary and the window has to end *after* it; a slow
--- round trip on either side quietly moves the window off the boundary,
--- and the resulting empty delta is indistinguishable from a schedule
--- that did not match. Asserting where the guest's clock actually got
--- to turns that into the mis-measurement it is.
local SETTLE, WINDOW = 4, 8

--- The guest's wall clock, in the same form `at` and `boundary` are
--- written in, so the three compare as strings.
local function guest_now()
    return (vm:run([[date '+%Y-%m-%d %H:%M:%S']]).stdout:gsub("%s+$", ""))
end

--- `at` is written out rather than derived from `boundary`, because
--- four of the boundaries below are midnight and subtracting ten
--- seconds from midnight is a change of date.
local function across(t, at, boundary)
    vm:run("date -s '" .. at .. "'"):assert_ok()
    vm:run("sleep " .. SETTLE)

    local settled_at = guest_now()
    t:assert(settled_at < boundary, string.format(
        "the baseline was taken before %s, not after it: the guest reached %s",
        boundary, settled_at))
    local before = ticks()

    vm:run("sleep " .. WINDOW)
    local ended_at = guest_now()
    t:assert(ended_at > boundary, string.format(
        "and the window ran past %s: the guest reached %s", boundary, ended_at))

    t:log(string.format("%s: window %s .. %s", boundary, settled_at, ended_at))
    return since(before, ticks())
end

--- Assert exactly which of `group` fired, by name.
local function fired_exactly(t, delta, group, expected, what)
    local wanted = {}
    for _, id in ipairs(expected) do wanted[id] = true end
    for _, case in ipairs(group) do
        local id = case[1]
        local count = delta[id] or 0
        if wanted[id] then
            t:assert(count > 0, string.format(
                "`%s` matches %s and fired", case[2], what))
        else
            t:assert_eq(count, 0, string.format(
                "`%s` does not match %s", case[2], what))
        end
    end
end

test("a wildcard, a step and a bare value in the second field fire at different rates",
    {
        spec = {
            "peinit *cal.numeric-components-and-the-weekday-take-wildcards-lists-ranges-and-steps",
            "peinit *cal.a-step-matches-every-multiple-above-its-start",
            "peinit *cal.hour-minute-defaults-the-seconds-to-zero",
        },
    },
    function(t)
        -- Four schedules that differ only in the second field, counted
        -- over one twelve-second window. `*` is every second, `0/3` is
        -- every third — the value and every multiple of the step above
        -- it — and a bare `00` is once a minute, so inside twelve
        -- seconds it fires at most once.
        --
        -- `*:*` is the fourth, and it is the one that says what the
        -- omitted second field defaults to: it behaves as `*:*:00` and
        -- not as `*:*:*`, which is only true if the missing seconds
        -- default to `00` rather than to a wildcard.
        local before = ticks()
        vm:run("sleep 12")
        local delta = since(before, ticks())

        t:assert(delta["every-second"] >= 6, string.format(
            "`*:*:*` fired about once a second: %d in twelve seconds",
            delta["every-second"]))
        t:assert(delta["every-third"] >= 2 and delta["every-third"] <= 6,
            string.format("`*:*:0/3` fired about every third second: %d",
                delta["every-third"]))
        t:assert(delta["every-third"] < delta["every-second"],
            "and less often than the wildcard")
        t:assert(delta["second-zero"] <= 1, string.format(
            "`*:*:00` fired at most once, at the turn of a minute: %d",
            delta["second-zero"]))
        t:assert(delta["hour-minute"] <= 1, string.format(
            "`*:*` did the same, so its seconds defaulted to 00: %d",
            delta["hour-minute"]))
    end)

test("the per-second definitions stop being armed once they are disabled",
    { spec = "peinit *evalt.a-disabled-service-is-neither-registered-nor-fired" },
    function(t)
        -- Housekeeping with a claim attached. The rate services would
        -- otherwise fire once a second through every clock move below,
        -- and each move would hand them a catch-up as well. Disabling
        -- them is the supported way to take a timer out of the plan,
        -- and that it works is §9.2's claim.
        for _, case in ipairs(RATE) do
            vm:run(string.format(
                [[reg set 'Machine\System\Services\pt-m-%s' Disabled 'dword:1']],
                case[1])):assert_ok()
        end
        vm:run("svctl --json reload-config"):assert_ok()

        local before = ticks()
        vm:run("sleep 6")
        local delta = since(before, ticks())
        for _, case in ipairs(RATE) do
            t:assert_eq(delta[case[1]] or 0, 0, string.format(
                "the disabled `%s` has no armed trigger left", case[2]))
        end
    end)

test("a weekday name picks that day, whether abbreviated, spelled out or shouted",
    { spec = "peinit *cal.weekday-names-are-english-case-insensitive-and-abbreviable" },
    function(t)
        -- `Mon`, `Monday` and `MONDAY` on an otherwise identical
        -- every-second schedule, against `Tue` on the same. Put the
        -- clock on a Tuesday and only the last of them may fire; put it
        -- on a Monday and only the first three may.
        --
        -- 2027-01-05 is a Tuesday and 2027-01-11 the following Monday.
        -- Both are in the future from any plausible run date, so every
        -- move is a step forward. The schedules fire every second, so
        -- the time of day is immaterial: what is being read is which
        -- names are armed at all on the day the clock now says it is.
        local tuesday = across(t, "2027-01-05 11:59:50", "2027-01-05 12:00:00")
        fired_exactly(t, tuesday, WEEKDAY, { "wd-tuesday" }, "a Tuesday")

        local monday = across(t, "2027-01-11 11:59:50", "2027-01-11 12:00:00")
        fired_exactly(t, monday, WEEKDAY,
            { "wd-abbrev", "wd-full", "wd-shouted" }, "a Monday")
    end)

test("each named shortcut fires exactly where its equivalent expression would",
    {
        spec = {
            "peinit *cal.the-named-shortcuts-expand-to-the-equivalent-expression",
            "peinit *cal.a-timezone-is-an-iana-name-and-its-absence-means-system-local",
        },
    },
    function(t)
        -- Six calendar boundaries, chosen so that no two shortcuts
        -- agree across all of them. Every one of the nine is pinned by
        -- the set of boundaries it fires on and the set it does not:
        --
        --   2027-01-01 00:00  Friday, first of a year and a quarter
        --   2027-02-01 00:00  Monday, first of a month only
        --   2027-04-01 00:00  Thursday, first of a quarter
        --   2027-07-01 00:00  Thursday, first of a half-year
        --   2027-07-01 12:34  a minute boundary and nothing else
        --   2027-07-01 13:00  an hour boundary that is not midnight
        --
        -- The weekday of each date is what separates `weekly` from
        -- `daily`: 1 January 2027 is a Friday, so a Monday schedule
        -- must sit that boundary out, and 1 February 2027 is a Monday,
        -- so it must not sit that one out.
        --
        -- None of these expressions carries a timezone, and the times
        -- they are being held to are the guest's own — `date -s` sets
        -- local time, and midnight here is midnight on the system
        -- clock. That is the other half of the timezone rule: an
        -- expression with no zone is interpreted in system-local time
        -- rather than being pinned to UTC or to anything else.
        local new_year = across(t, "2026-12-31 23:59:50", "2027-01-01 00:00:00")
        fired_exactly(t, new_year, SHORTCUT, {
            "sc-minutely", "sc-hourly", "sc-daily", "sc-monthly",
            "sc-quarterly", "sc-semiannually", "sc-yearly", "sc-annually",
        }, "midnight on Friday 1 January")

        local february = across(t, "2027-01-31 23:59:50", "2027-02-01 00:00:00")
        fired_exactly(t, february, SHORTCUT, {
            "sc-minutely", "sc-hourly", "sc-daily", "sc-weekly", "sc-monthly",
        }, "midnight on Monday 1 February")

        local april = across(t, "2027-03-31 23:59:50", "2027-04-01 00:00:00")
        fired_exactly(t, april, SHORTCUT, {
            "sc-minutely", "sc-hourly", "sc-daily", "sc-monthly", "sc-quarterly",
        }, "midnight on Thursday 1 April")

        local july = across(t, "2027-06-30 23:59:50", "2027-07-01 00:00:00")
        fired_exactly(t, july, SHORTCUT, {
            "sc-minutely", "sc-hourly", "sc-daily", "sc-monthly",
            "sc-quarterly", "sc-semiannually",
        }, "midnight on Thursday 1 July")

        local minute = across(t, "2027-07-01 12:33:50", "2027-07-01 12:34:00")
        fired_exactly(t, minute, SHORTCUT, { "sc-minutely" },
            "a minute that begins no hour")

        local hour = across(t, "2027-07-01 12:59:50", "2027-07-01 13:00:00")
        fired_exactly(t, hour, SHORTCUT, { "sc-minutely", "sc-hourly" },
            "an hour that is not midnight")
    end)
