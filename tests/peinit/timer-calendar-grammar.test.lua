-- peinit TRM §9.1 — the OnCalendar grammar peinit actually parses, as
-- seen from a booted machine.
--
-- The parser has no interface of its own. The only way in from the guest
-- is a `timer:<schedule>` trigger on a service definition, and the only
-- way out is what peinit does with the definition, which is one of
-- exactly three things:
--
--   * the schedule parses and has a next occurrence — the service is
--     left Inactive and nothing is said about it;
--   * the schedule does not parse — graph validation (§7.4) blocks the
--     service, so it is Failed with cause `validation_error`, and the
--     timer registration separately reports `ParseSchedule` on the
--     console;
--   * the schedule parses but matches nothing inside the search horizon
--     — validation has no complaint, so the service stays Inactive, and
--     the console carries `ComputeNext … NoFutureOccurrence`.
--
-- That third outcome is the interesting one, because it turns *meaning*
-- into something a static boot can observe. `*-02-30` never matches, so
-- "is there a next occurrence" answers questions about what a component
-- means without waiting for a firing: `*-02~30` has no occurrence
-- because February is never 30 days long, while `*-02~30/1` does,
-- because the step after `~` walks the offset downwards into range.
-- Several claims below are proved by exactly that contrast, and each
-- pair is chosen so that it is true in every year rather than in this
-- one.
--
-- Every definition here carries `TimerPersistent=0`. On the default
-- (persistent) setting a trigger with no history catches up at boot
-- (§9.3), which would start every one of these services during the boot
-- this file is reading; the schedules are the subject, not the runs.
--
-- The console warnings arrive *after* `phase2 boot complete`: timer
-- registration happens on the way into the runtime loop, after the mark
-- `peinit.boot` waits for. So the file waits for the last service's
-- warning — `zz-sentinel`, whose name sorts last and whose schedule is
-- unsatisfiable — before reading the log.

local peinit = require("helpers.peinit")
peinit.claim(1)

--- What peinit is expected to make of a schedule.
local ARMS = "arms"            -- parses, has an occurrence, nothing said
local PARSE = "parse"          -- rejected by the parser
local NOMATCH = "nomatch"      -- parses, matches nothing in ten years

-- id, schedule, outcome, and for a rejection a fragment of the reason
-- peinit gives. The ids are short because they become service names and
-- the service name is what ties a console warning to a row.
local CASES = {
    -- Positional shape: each field may be present or absent, and which
    -- is which is worked out from the shape of the token.
    { "shape-full", "Mon *-*-* 02:00:00", ARMS },
    { "shape-date-time", "*-*-* 02:00:00", ARMS },
    { "shape-time-only", "02:00:00", ARMS },
    { "shape-hour-minute", "02:00", ARMS },
    { "shape-weekday-time", "Mon 02:00:00", ARMS },
    { "shape-date-only", "*-*-01", ARMS },

    -- Component ranges. 0..9999, 1..12, 1..31, 0..23, 0..59, 0..59.
    { "range-year-max", "9999-*-* 00:00:00", NOMATCH }, -- parses; too far
    { "range-year-zero", "0-*-* 00:00:00", NOMATCH },   -- parses; long past
    { "range-year-over", "10000-01-01 00:00:00", PARSE, "year" },
    { "range-month-over", "*-13-01 00:00:00", PARSE, "month" },
    { "range-month-zero", "*-0-01 00:00:00", PARSE, "month" },
    { "range-day-over", "*-01-32 00:00:00", PARSE, "day" },
    { "range-day-zero", "*-01-0 00:00:00", PARSE, "day" },
    { "range-hour-over", "*-*-* 24:00:00", PARSE, "hour" },
    { "range-minute-over", "*-*-* 00:60:00", PARSE, "minute" },
    { "range-second-over", "*-*-* 00:00:60", PARSE, "second" },

    -- Wildcards, lists, ranges and steps, in the components where they
    -- can be checked without waiting for a firing. Each pair is a
    -- contrast: the left member matches nothing, the right one differs
    -- by exactly the construct under test and matches.
    { "wild-day", "*-02-* 00:00:00", ARMS },
    { "list-miss", "*-02-30,31 00:00:00", NOMATCH },
    { "list-hit", "*-02-29,30 00:00:00", ARMS },
    { "rangedots-miss", "*-02-30..31 00:00:00", NOMATCH },
    { "rangedots-hit", "*-02-28..31 00:00:00", ARMS },
    { "step-miss", "*-02-30/1 00:00:00", NOMATCH },
    { "step-hit", "*-02-28/1 00:00:00", ARMS },
    { "step-minute", "*-*-* *:00/15:00", ARMS },
    { "rev-day", "*-*-20..10 00:00:00", PARSE, "range start is after range end" },
    { "rev-month", "*-10..1-01 00:00:00", PARSE, "range start is after range end" },
    { "rev-weekday", "Fri..Mon *-*-* 00:00:00", PARSE },
    { "step-zero", "*-*-* *:0/0:00", PARSE, "step must be greater than zero" },
    { "list-empty", "*-*-* 1,,2:00:00", PARSE, "list contains an empty item" },

    -- Weekday names: abbreviated or full, either case, in lists and
    -- ranges. A name that is not a weekday is not a weekday.
    { "wd-abbrev", "Mon *-*-* 00:00:00", ARMS },
    { "wd-full", "Monday *-*-* 00:00:00", ARMS },
    { "wd-upper", "MONDAY *-*-* 00:00:00", ARMS },
    { "wd-lower", "sun *-*-* 00:00:00", ARMS },
    { "wd-tues", "Tues *-*-* 00:00:00", ARMS },
    { "wd-list", "Tues,Thurs *-*-* 00:00:00", ARMS },
    { "wd-range", "Mon..Fri *-*-* 09:00:00", ARMS },
    { "wd-bogus", "Munday *-*-* 00:00:00", PARSE },

    -- Last day of the month. `~N` counts back from the end, so it is
    -- bounded by how long the month actually is: 30 back from the end of
    -- February is nowhere, 30 back from the end of January is the 2nd.
    -- With a step it walks *downwards*, which brings the same offset
    -- into range.
    { "tilde-last", "*-*~01 00:00:00", ARMS },
    { "tilde-jan30", "*-01~30 00:00:00", ARMS },
    { "tilde-feb30", "*-02~30 00:00:00", NOMATCH },
    { "tilde-feb30-step", "*-02~30/1 00:00:00", ARMS },
    { "tilde-wild", "*-*~* 00:00:00", ARMS },
    { "tilde-range-miss", "*-02~30..31 00:00:00", NOMATCH },
    { "tilde-range-hit", "*-02~28..31 00:00:00", ARMS },
    { "tilde-list", "*-*~1,2 00:00:00", ARMS },

    -- Named shortcuts, every one of them, in three spellings.
    { "sc-minutely", "minutely", ARMS },
    { "sc-hourly", "hourly", ARMS },
    { "sc-daily", "daily", ARMS },
    { "sc-weekly", "weekly", ARMS },
    { "sc-monthly", "monthly", ARMS },
    { "sc-quarterly", "quarterly", ARMS },
    { "sc-semiannually", "semiannually", ARMS },
    { "sc-yearly", "yearly", ARMS },
    { "sc-annually", "annually", ARMS },
    { "sc-upper", "DAILY", ARMS },
    { "sc-mixed", "DaIlY", ARMS },

    -- Precision: seconds, and nothing finer.
    { "frac-second", "*-*-* 00:00:00.5", PARSE, "FractionalSecondsUnsupported" },
    { "frac-minute", "*-*-* 00:00.5:00", PARSE, "FractionalSecondsUnsupported" },

    -- Parses, matches nothing. Not a parse error, and the search gives
    -- up rather than walking to the end of the calendar.
    { "unsat-feb30", "*-02-30 00:00:00", NOMATCH },
    { "unsat-past-year", "2020-*-* 00:00:00", NOMATCH },
    { "unsat-far-year", "2060-01-01 00:00:00", NOMATCH },
    { "sat-near-year", "*-01-01 00:00:00", ARMS },

    -- Sorts last, so its console warning is the mark that every other
    -- registration has already been decided.
    { "zz-sentinel", "2061-01-01 00:00:00", NOMATCH },
}

-- The timezone cases live apart because they all fail on this image for
-- one reason (see the last test in this file), and mixing them into the
-- matrix above would make it read as though the grammar rejected them.
local TZ_CASES = {
    { "tz-named", "*-*-* 02:00:00 Europe/London" },
    { "tz-utc", "*-*-* 02:00:00 UTC" },
    { "tz-shortcut", "daily UTC" },
}

-- Ranges in the time component, apart for the same reason: they fail,
-- and not because of anything the range rules say. §9.1's own example
-- of a range is `8..17`, and the only field a bare `8..17` can be is the
-- hour.
local TIME_RANGE_CASES = {
    { "trange-hour", "*-*-* 8..17:00:00" },
    { "trange-hour-padded", "*-*-* 08..17:00:00" },
    { "trange-minute", "*-*-* 09:00..30:00" },
    { "trange-second", "*-*-* 09:00:00..30" },
}

local function timer_service(name, schedule)
    return {
        path = [[Machine\System\Services\]] .. name,
        values = {
            { name = "ImagePath", type = "sz", data = "/bin/true" },
            { name = "Type", type = "dword", data = 1 },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
            -- No boot trigger: the schedule is the whole definition.
            { name = "Triggers", type = "multi", data = { "timer:" .. schedule } },
            -- See the header: the default would run every one of these
            -- once at boot as a catch-up.
            { name = "TimerPersistent", type = "dword", data = 0 },
        },
    }
end

local keys = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },
}
for _, case in ipairs(CASES) do
    keys[#keys + 1] = timer_service("pt-cal-" .. case[1], case[2])
end
for _, case in ipairs(TZ_CASES) do
    keys[#keys + 1] = timer_service("pt-cal-" .. case[1], case[2])
end
for _, case in ipairs(TIME_RANGE_CASES) do
    keys[#keys + 1] = timer_service("pt-cal-" .. case[1], case[2])
end

local vm = peinit.boot({
    name = "cal-grammar",
    files = peinit.seed("pt-cal", keys),
})

--- Every "calendar timer not armed" line, keyed by the service it names.
---
--- Collected once, after the sentinel's warning has appeared, because
--- the registration pass runs after the boot mark `peinit.boot` waits
--- for and the lines arrive in service-name order.
---
--- The sentinel's schedule is unsatisfiable rather than unparseable on
--- purpose. An unparseable one would also be named by the *earlier*
--- line graph validation writes, and waiting for its name would return
--- before the registration pass had said anything at all.
local warnings = (function()
    wait_until(function()
        return vm:console():read_log():find("pt-cal-zz-sentinel", 1, true)
    end, { timeout = peinit.STAGE_TIMEOUT, interval = 0.5,
           desc = "the last timer registration to be decided" })
    local by_service = {}
    for _, line in ipairs(peinit.lines(vm:console():read_log())) do
        if line:find("calendar timer not armed", 1, true) then
            local service = line:match('service: "([%w%-]+)"')
            if service then by_service[service] = line end
        end
    end
    return by_service
end)()

local function status(name)
    local out = vm:run("svctl --json status pt-cal-" .. name).stdout
    return {
        state = out:match('"state":"([^"]*)"'),
        cause = out:match('"cause":"([^"]*)"'),
        raw = out,
    }
end

--- Assert one row of the matrix, and return what was observed so a
--- caller can say more about it.
local function check(t, case)
    local id, schedule, outcome, reason = case[1], case[2], case[3], case[4]
    local name = "pt-cal-" .. id
    local warning = warnings[name]
    local st = status(id)
    local where = string.format("%s (`%s`)", id, schedule)

    if outcome == ARMS then
        t:assert(warning == nil,
            where .. " armed, so nothing is reported about it: " .. tostring(warning))
        t:assert_eq(st.state, "inactive", where .. " is loaded and idle")
    elseif outcome == PARSE then
        t:assert(warning, where .. " was rejected and said so on the console")
        t:assert(warning:find("ParseSchedule", 1, true),
            where .. " failed in the parser, not in the search: " .. warning)
        -- Graph validation parses the same schedule and blocks the
        -- service, which is the half an administrator sees in `svctl`.
        t:assert_eq(st.state, "failed", where .. " was blocked: " .. st.raw)
        t:assert_eq(st.cause, "validation_error", where .. " for a validation reason")
        if reason then
            t:assert(warning:find(reason, 1, true),
                where .. " names why: " .. warning)
        end
    elseif outcome == NOMATCH then
        t:assert(warning, where .. " has no occurrence and said so on the console")
        t:assert(warning:find("ComputeNext", 1, true) and
            warning:find("NoFutureOccurrence", 1, true),
            where .. " failed the search rather than the parser: " .. warning)
        -- The parser had no complaint, so validation had none either.
        t:assert_eq(st.state, "inactive",
            where .. " parses, so the service is not blocked: " .. st.raw)
    end
    return st, warning
end

local function only(ids)
    local wanted = {}
    for _, id in ipairs(ids) do wanted[id] = true end
    local out = {}
    for _, case in ipairs(CASES) do
        if wanted[case[1]] then out[#out + 1] = case end
    end
    return out
end

test("each field of the expression is optional and recognised by its shape",
    {
        spec = {
            "peinit *cal.fields-are-optional-and-identified-positionally",
            "peinit *cal.a-time-only-expression-implies-every-date",
            "peinit *cal.hour-minute-defaults-the-seconds-to-zero",
        },
    },
    function(t)
        -- Weekday, date and time in every combination that leaves at
        -- least one of them present. A bare time is a whole schedule,
        -- which is only true if the missing date defaults to `*-*-*`;
        -- if it did not, `02:00:00` would have no date to match and
        -- would have shown up as NoFutureOccurrence rather than arming.
        for _, case in ipairs(only({ "shape-full", "shape-date-time", "shape-time-only",
            "shape-hour-minute", "shape-weekday-time", "shape-date-only" })) do
            check(t, case)
        end
    end)

test("years, months, days, hours, minutes and seconds each have a fixed range",
    { spec = "peinit *cal.numeric-components-have-fixed-ranges" },
    function(t)
        -- The rejections name the field they are about, so this also
        -- pins which position peinit read each number out of.
        for _, case in ipairs(only({ "range-year-over", "range-month-over",
            "range-month-zero", "range-day-over", "range-day-zero", "range-hour-over",
            "range-minute-over", "range-second-over" })) do
            check(t, case)
        end
        -- The ends of the ranges are inside them: 0 and 9999 are years
        -- peinit accepts, and neither has an occurrence for reasons
        -- that are about the calendar rather than about the parser.
        for _, case in ipairs(only({ "range-year-max", "range-year-zero" })) do
            check(t, case)
        end
    end)

test("a numeric component takes a wildcard, a list, a range or a step",
    {
        spec = {
            "peinit *cal.numeric-components-and-the-weekday-take-wildcards-lists-ranges-and-steps",
            "peinit *cal.a-step-matches-every-multiple-above-its-start",
        },
    },
    function(t)
        -- Each construct is checked against February, whose length is
        -- the smallest of any month, by pairing a day expression that
        -- reaches into it with one that does not. The pair differs by
        -- one member, so what separates them is the construct.
        --
        -- `*-02-30,31` and `*-02-30..31` never match; adding 29 or 28
        -- to the same list or range makes them match. A list and a
        -- range are therefore unions of their members, and the range
        -- includes its endpoints.
        --
        -- `*-02-30/1` is the step case, and it is the sharpest: a step
        -- on a single value walks *upward* to the top of the field, so
        -- 30/1 is {30, 31} and matches no February, while 28/1 is
        -- {28..31} and matches every one.
        for _, case in ipairs(only({ "wild-day", "list-miss", "list-hit",
            "rangedots-miss", "rangedots-hit", "step-miss", "step-hit",
            "step-minute" })) do
            check(t, case)
        end
    end)

test("a range is accepted in the hour, minute and second fields",
    {
        spec = "peinit *cal.numeric-components-and-the-weekday-take-wildcards-lists-ranges-and-steps",
        -- PEI-831: parse_time refuses any time component containing a
        -- '.', which is what `..` is made of, so no range can be
        -- written anywhere in the time. `8..17` is §9.1's own example.
        tags = { "known-bug" },
    },
    function(t)
        -- The day and month fields take `a..b` (checked above), and the
        -- TRM says every numeric component does. The time component
        -- does not: the fractional-seconds check runs over the whole
        -- token before it is split on `:`, sees the dots that make up
        -- the range operator, and reports a fraction.
        for _, case in ipairs(TIME_RANGE_CASES) do
            local warning = warnings["pt-cal-" .. case[1]]
            t:assert(not warning, string.format(
                "`%s` is a range in a numeric component and should arm: %s",
                case[2], tostring(warning)))
        end
    end)

test("a reversed range is a parse error rather than a wrap-around",
    { spec = "peinit *cal.a-reversed-range-is-a-parse-error" },
    function(t)
        -- Day and month say so in as many words. The weekday case is
        -- rejected too, but by a different route: a token that does not
        -- parse as a weekday is not treated as the weekday field at
        -- all, so `Fri..Mon` falls through to the timezone position and
        -- is reported as a bad timezone. The claim under test is that
        -- it does not wrap around, and it does not.
        for _, case in ipairs(only({ "rev-day", "rev-month", "rev-weekday" })) do
            check(t, case)
        end
        -- A step of zero would make a repetition match everything or
        -- nothing depending on how the walk is written; it is refused.
        for _, case in ipairs(only({ "step-zero", "list-empty" })) do
            check(t, case)
        end
    end)

test("weekdays are English names, in either case, abbreviated or full",
    { spec = "peinit *cal.weekday-names-are-english-case-insensitive-and-abbreviable" },
    function(t)
        for _, case in ipairs(only({ "wd-abbrev", "wd-full", "wd-upper", "wd-lower",
            "wd-tues", "wd-list", "wd-range", "wd-bogus" })) do
            check(t, case)
        end
    end)

test("a tilde counts the day back from the end of the month, and a step after it walks down",
    {
        spec = {
            "peinit *cal.a-tilde-counts-the-day-from-the-end-of-the-month",
            "peinit *cal.a-step-after-a-tilde-walks-the-offset-downwards",
            "peinit *cal.wildcards-ranges-and-lists-are-accepted-after-a-tilde",
        },
    },
    function(t)
        -- `~30` is thirty days back from the end. January has 31 days,
        -- so that is the 2nd and it matches every year; February has 28
        -- or 29, so there is no such day and the search finds nothing.
        -- That contrast is what says the offset is counted from the end
        -- and bounded by the month's real length.
        for _, case in ipairs(only({ "tilde-last", "tilde-jan30", "tilde-feb30" })) do
            check(t, case)
        end

        -- And the direction of the step. `*-02~30` alone is {30}, which
        -- never matches. `*-02~30/1` is the same expression with a step
        -- of one, and it matches every February — which can only be
        -- true if the step walked the offset *down* from 30 towards 1,
        -- picking up 28 on the way. An upward walk would have produced
        -- {30, 31} and matched nothing at all.
        for _, case in ipairs(only({ "tilde-feb30-step" })) do check(t, case) end

        for _, case in ipairs(only({ "tilde-wild", "tilde-range-miss",
            "tilde-range-hit", "tilde-list" })) do
            check(t, case)
        end
    end)

test("every named shortcut is accepted, whatever its case",
    {
        spec = {
            "peinit *cal.the-named-shortcuts-expand-to-the-equivalent-expression",
            "peinit *cal.shortcut-names-are-case-insensitive-and-take-a-trailing-timezone",
        },
    },
    function(t)
        -- Acceptance only. What each one expands *to* is a claim about
        -- when it fires, and timer-calendar-meaning.test.lua takes the
        -- nine of them across a set of calendar boundaries to establish
        -- that. The trailing-timezone half of the case-insensitivity
        -- claim is the last test in this file.
        for _, case in ipairs(only({ "sc-minutely", "sc-hourly", "sc-daily",
            "sc-weekly", "sc-monthly", "sc-quarterly", "sc-semiannually",
            "sc-yearly", "sc-annually", "sc-upper", "sc-mixed" })) do
            check(t, case)
        end
    end)

test("a fraction anywhere in the time component is a parse error",
    {
        spec = {
            "peinit *cal.a-fraction-in-the-time-component-is-a-parse-error",
            "peinit *compat.sub-second-precision-is-not-parsed",
        },
    },
    function(t)
        -- §1.4's "one deliberate subtraction" from systemd's
        -- OnCalendar, seen from the outside: the fraction is refused by
        -- name rather than truncated, so a definition that asks for
        -- sub-second scheduling is a definition that does not load.
        for _, case in ipairs(only({ "frac-second", "frac-minute" })) do
            check(t, case)
        end
    end)

test("an expression that can never match parses, and the search gives up on it",
    {
        spec = {
            "peinit *cal.an-unsatisfiable-expression-is-not-a-parse-error",
            "peinit *cal.an-unsatisfiable-expression-is-walked-for-ten-years",
            "peinit *evalt.the-next-occurrence-search-gives-up-after-ten-years",
        },
    },
    function(t)
        -- The two halves are different failures and peinit keeps them
        -- apart. `*-02-30` and a year already past are grammatical, so
        -- validation admits the definition and only the occurrence
        -- search objects — which is why these services are Inactive
        -- rather than Failed.
        for _, case in ipairs(only({ "unsat-feb30", "unsat-past-year" })) do
            check(t, case)
        end

        -- And the horizon. `2060-01-01` is a perfectly ordinary future
        -- date; the only thing wrong with it is that it is more than
        -- ten years away, and peinit reports that against the one
        -- service rather than walking the calendar to find it. The
        -- control is the same expression with the year left open,
        -- whose first occurrence is inside a year.
        check(t, only({ "unsat-far-year" })[1])
        check(t, only({ "sat-near-year" })[1])
    end)

test("a timezone suffix names an IANA zone",
    {
        spec = {
            "peinit *cal.a-timezone-is-an-iana-name-and-its-absence-means-system-local",
            "peinit *cal.shortcut-names-are-case-insensitive-and-take-a-trailing-timezone",
        },
        -- PEI-832: the image ships no /usr/share/zoneinfo, so jiff has
        -- no database to resolve against and every timezone suffix --
        -- including the bare `UTC` the TRM names -- is a parse error.
        tags = { "known-bug" },
    },
    function(t)
        -- The absence half holds: every schedule in this file with no
        -- timezone was interpreted against the system zone and armed.
        -- The presence half does not. `Europe/London` and `UTC` are
        -- both IANA names and both are refused, with a message about
        -- the database rather than about the name, so a schedule cannot
        -- name a zone on this system at all.
        for _, case in ipairs(TZ_CASES) do
            local name = "pt-cal-" .. case[1]
            local warning = warnings[name]
            t:assert(not warning,
                string.format("`%s` names a real IANA zone and should arm: %s",
                    case[2], tostring(warning)))
        end
    end)

test("an unrecognised timezone is refused rather than quietly taken as UTC",
    { spec = "peinit *cal.an-unrecognised-timezone-is-a-parse-error" },
    function(t)
        -- This half is reachable whether or not a zone database is
        -- present: a name peinit cannot resolve stops the definition
        -- loading. `Munday` and `Fri..Mon` above reach the same code by
        -- accident of position; this one asks for it directly.
        vm:run([[reg new 'Machine\System\Services\pt-cal-tz-bogus']]):assert_ok()
        vm:run([[reg set 'Machine\System\Services\pt-cal-tz-bogus' ImagePath 'sz:/bin/true']])
            :assert_ok()
        vm:run([[reg set 'Machine\System\Services\pt-cal-tz-bogus' Identity 'sz:SYSTEM']])
            :assert_ok()
        vm:run([[reg set 'Machine\System\Services\pt-cal-tz-bogus' Type 'dword:1']])
            :assert_ok()
        vm:run([[reg set 'Machine\System\Services\pt-cal-tz-bogus' Readiness 'dword:1']])
            :assert_ok()
        vm:run([[reg set 'Machine\System\Services\pt-cal-tz-bogus' Triggers ]] ..
            [['multi:timer:*-*-* 02:00:00 Mars/Olympus']]):assert_ok()

        -- reload-config validates the whole graph and reports its
        -- findings, which is a sharper reading of the parser's verdict
        -- than the console line: the message comes back verbatim.
        local reload = vm:run("svctl --json reload-config")
        t:assert(reload.exit_code ~= 0,
            "the reload was refused: " .. reload.stdout)
        t:assert(reload.stdout:find("pt-cal-tz-bogus", 1, true) and
            reload.stdout:find("invalid timezone 'Mars/Olympus'", 1, true),
            "and named that zone as the reason rather than falling back to UTC: "
            .. reload.stdout)
    end)
