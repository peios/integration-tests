-- peinit TRM §9.2 — arming and firing: what a timer trigger does to the
-- service it is attached to.
--
-- §9.1 is about a string; this is about a running machine. Everything
-- here needs a firing to have happened, and a firing that has to wait
-- for a calendar boundary is a firing this suite cannot afford — so the
-- schedules are seconds-granular. `*-*-* *:*:*` fires every second and
-- `*-*-* *:*:0/3` every third, which turns "did this service start
-- again" into something a ten-second window answers.
--
-- Two of the definitions are deliberately never meant to run: one is
-- disabled and one has a schedule the parser refuses. They are here as
-- the negative half of claims whose positive half is a sibling that did
-- run in the same boot — "only that trigger failed" is a statement
-- about two services, not one.
--
-- The firing log is one file, `/run/pt-ticks`, a line per run naming
-- whoever ran. Counting lines is how every claim below is read, and
-- taking a snapshot before and after a window is how a claim about
-- "while it was already running" is separated from one about the boot.

local peinit = require("helpers.peinit")
peinit.claim(1)

local FILES = {
    ["pt/tick.sh"] = [[
echo "$1" >> /run/pt-ticks
]],
    -- Logs, then stays running for far longer than its triggers fire,
    -- so every firing after the first lands while it is still Active.
    ["pt/slow.sh"] = [[
echo "$1" >> /run/pt-ticks
/bin/sleep 8
]],
    -- Logs and fails, which is what puts its service into Backoff.
    ["pt/blip.sh"] = [[
echo "$1" >> /run/pt-ticks
exit 1
]],
}

local function values(list)
    local out = {
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
    }
    for _, v in ipairs(list) do out[#out + 1] = v end
    return out
end

local function service(name, list)
    return { path = [[Machine\System\Services\]] .. name, values = values(list) }
end

--- A Oneshot that logs under `id` and exits, on `schedules`.
local function ticker(id, schedules, extra)
    local list = {
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi", data = { "/pt/tick.sh", id } },
        { name = "Type", type = "dword", data = 1 },
        { name = "Triggers", type = "multi", data = schedules },
        { name = "TimerPersistent", type = "dword", data = 0 },
    }
    for _, v in ipairs(extra or {}) do list[#list + 1] = v end
    return service("pt-e-" .. id, list)
end

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },

    -- The plain case: an ordinary Oneshot with nothing but a schedule.
    ticker("oneshot", { "timer:*-*-* *:*:0/3" }),

    -- A schedule the parser refuses, next to one it accepts. Neither
    -- knows about the other, which is the point.
    ticker("bad", { "timer:*-*-* 25:00:00" }),
    ticker("good", { "timer:*-*-* *:*:0/3" }),

    -- Armed once a second and never allowed to run.
    ticker("disabled", { "timer:*-*-* *:*:*" },
        { { name = "Disabled", type = "dword", data = 1 } }),

    -- Three triggers, all firing during a run that takes eight seconds.
    -- The three are distinct strings so they are three descriptors with
    -- three separate computations; what they share is the service.
    service("pt-e-collapse", {
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi", data = { "/pt/slow.sh", "collapse" } },
        { name = "Type", type = "dword", data = 1 },
        { name = "Triggers", type = "multi", data = {
            "timer:*-*-* *:*:0/2", "timer:*-*-* *:*:1/2", "timer:*-*-* *:*:*",
        } },
        { name = "TimerPersistent", type = "dword", data = 0 },
    }),

    -- Simple, started at boot, resident, and fired at once a second for
    -- as long as the test watches it.
    service("pt-e-resident", {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "100000" } },
        { name = "Triggers", type = "multi", data = { "boot", "timer:*-*-* *:*:*" } },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "TimerPersistent", type = "dword", data = 0 },
    }),

    -- Simple, started at boot, exits non-zero immediately, and then
    -- spends a minute in Backoff waiting for its restart delay. Fired
    -- at once a second throughout.
    service("pt-e-backoff", {
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi", data = { "/pt/blip.sh", "backoff" } },
        { name = "Triggers", type = "multi", data = { "boot", "timer:*-*-* *:*:*" } },
        { name = "RestartPolicy", type = "dword", data = 2 },
        { name = "RestartDelay", type = "dword", data = 60 },
        { name = "RestartWindow", type = "dword", data = 600 },
        { name = "TimerPersistent", type = "dword", data = 0 },
    }),

    -- Two triggers with very different periods, and history left on
    -- (the default), so each one's last run is recorded separately.
    service("pt-e-separate", {
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi", data = { "/pt/tick.sh", "separate" } },
        { name = "Type", type = "dword", data = 1 },
        { name = "Triggers", type = "multi", data = {
            "timer:*-*-* *:*:0/3", "timer:*-*-* 02:00:00",
        } },
    }),
}

local vm = peinit.boot({
    name = "eval",
    files = peinit.merge(FILES, peinit.seed("pt-e", SERVICES)),
})

local function ticks()
    local counts = setmetatable({}, { __index = function() return 0 end })
    for _, line in ipairs(peinit.lines(vm:run("cat /run/pt-ticks 2>/dev/null").stdout)) do
        rawset(counts, line, counts[line] + 1)
    end
    return counts
end

local function status(name)
    local out = vm:run("svctl --json status pt-e-" .. name).stdout
    return {
        state = out:match('"state":"([^"]*)"'),
        cause = out:match('"cause":"([^"]*)"'),
        raw = out,
    }
end

local function main_pid(name)
    local ok, procs = pcall(function()
        return vm:read_file("/sys/fs/cgroup/peinit/pt-e-" .. name .. "/main/cgroup.procs")
    end)
    return ok and procs:match("^(%d+)") or nil
end

--- The console line reporting the schedule peinit would not arm.
---
--- Waited for rather than read at the boot mark: timer registration
--- happens on the way into the runtime loop, after `phase2 boot
--- complete`. The wait is for the whole line rather than for the
--- service name, because the name also appears in the *earlier* line
--- graph validation writes about the same definition, and matching that
--- one would return before the registration pass had said anything.
local rejection = wait_until(function()
    for _, line in ipairs(peinit.lines(vm:console():read_log())) do
        if line:find("calendar timer not armed", 1, true) and
            line:find("pt-e-bad", 1, true) then
            return line
        end
    end
end, { timeout = peinit.STAGE_TIMEOUT, interval = 0.5,
       desc = "the rejected schedule to be reported" })

test("a schedule starts an ordinary service, and the start is attributed to the timer",
    {
        spec = {
            "peinit *evalt.a-timer-is-a-trigger-on-an-ordinary-service",
            "peinit *evalt.a-firing-is-classified-from-the-services-type-and-state",
        },
    },
    function(t)
        -- pt-e-oneshot has no boot trigger and nothing depends on it,
        -- so the only thing that can have started it is its schedule.
        -- It is otherwise an entirely ordinary Oneshot: same fields,
        -- same launch path, same console line.
        wait_until(function() return ticks()["oneshot"] > 0 end,
            { timeout = 30, interval = 0.5, desc = "the first firing" })
        vm:console():expect("peinit: service pt-e-oneshot started", peinit.STAGE_TIMEOUT)

        -- And peinit says where the start came from rather than
        -- treating it as an anonymous one: the transition it recorded
        -- names the timer.
        local st = status("oneshot")
        t:assert(st.cause == "timer" or st.cause == "clean_exit",
            "the service's last transition came from the timer path: " .. st.raw)

        -- It keeps going. A trigger is a schedule, not a one-off.
        local before = ticks()["oneshot"]
        vm:run("sleep 8")
        t:assert(ticks()["oneshot"] > before,
            "and it fired again three seconds later, as the schedule says")
    end)

test("a schedule that will not parse fails that trigger and nothing else",
    { spec = "peinit *evalt.a-bad-schedule-fails-only-its-own-trigger-and-is-reported" },
    function(t)
        -- `*-*-* 25:00:00` has no 25th hour. peinit reports it against
        -- the one service, on the console, rather than abandoning the
        -- registration pass -- which is what it used to do, taking
        -- every other timer on the machine down with it.
        t:assert(rejection, "the bad schedule was reported on the console")
        t:assert(rejection:find("ParseSchedule", 1, true),
            "as a parse failure: " .. rejection)

        -- Graph validation reached the same verdict, so the service is
        -- Failed rather than quietly idle.
        t:assert_eq(status("bad").state, "failed",
            "and the service was blocked: " .. status("bad").raw)

        -- Its neighbour, seeded in the same file with a schedule of the
        -- same shape, armed and is firing.
        wait_until(function() return ticks()["good"] > 0 end,
            { timeout = 30, interval = 0.5,
              desc = "the sibling with a valid schedule to fire" })
    end)

test("a disabled service gets neither a registration nor a firing",
    { spec = "peinit *evalt.a-disabled-service-is-neither-registered-nor-fired" },
    function(t)
        -- Armed once a second if it were armed at all, and the machine
        -- has been up for long enough by now that a single missed
        -- exclusion would show.
        t:assert_eq(ticks()["disabled"], 0,
            "the disabled service has never run")

        -- Nor was it rejected: it was not considered. A definition
        -- excluded from the plan produces no console line either way,
        -- which is what separates "not registered" from "registered and
        -- refused".
        local log = vm:console():read_log()
        t:assert(not log:find("pt-e-disabled", 1, true),
            "and peinit said nothing about it at all")
    end)

test("a firing at a Simple service that is already running does nothing",
    { spec = "peinit *evalt.a-firing-is-classified-from-the-services-type-and-state" },
    function(t)
        -- pt-e-resident is started by its boot trigger and sleeps for a
        -- day. Its timer fires once a second regardless. A firing that
        -- was treated as a start request would restart it, or queue an
        -- operation that eventually did; the process is the witness.
        local before = main_pid("resident")
        t:assert(before, "the resident service is running")
        t:assert_eq(status("resident").state, "active", "and Active")

        vm:run("sleep 8")

        t:assert_eq(main_pid("resident"), before,
            "eight seconds and eight firings later it is the same process")
        t:assert_eq(status("resident").state, "active", "in the same state")
    end)

test("a firing at a service waiting out its restart backoff does nothing",
    { spec = "peinit *evalt.a-firing-in-any-other-state-does-nothing" },
    function(t)
        -- Backoff is not one of the states a firing starts from, and it
        -- is the one where the difference matters most: a service in
        -- Backoff is *going* to start again, and a timer firing that
        -- brought that forward would quietly defeat the restart delay.
        --
        -- This one exits non-zero immediately with a sixty-second
        -- delay, so it settles into Backoff within a second of boot and
        -- stays there for the whole test.
        wait_until(function() return status("backoff").state == "backoff" end,
            { timeout = 60, interval = 0.5, desc = "the service to enter Backoff" })
        local runs = ticks()["backoff"]

        vm:run("sleep 10")

        t:assert_eq(status("backoff").state, "backoff", "it is still in Backoff")
        t:assert_eq(ticks()["backoff"], runs,
            "and ten firings later it has not been started again")
    end)

test("a Oneshot fired repeatedly during one run gets exactly one catch-up",
    {
        spec = {
            "peinit *evalt.a-oneshot-firing-mid-run-becomes-one-pending-run",
            "peinit *evalt.multiple-firings-during-one-run-collapse-into-one",
        },
    },
    function(t)
        -- pt-e-collapse takes eight seconds to run and carries three
        -- triggers, one of which fires every second. So each run has
        -- somewhere around twenty firings landing on top of it, from
        -- three separate descriptors.
        --
        -- If firings queued, the service would run back to back
        -- forever and the count over a window would track the number of
        -- firings. If the pending flag were per trigger rather than per
        -- service, three catch-ups would follow each run. What the TRM
        -- says is one, so a window of thirty seconds -- three runs'
        -- worth of eight seconds, plus the catch-up between them --
        -- should hold about three runs and certainly not twenty.
        wait_until(function() return ticks()["collapse"] > 0 end,
            { timeout = 30, interval = 0.5, desc = "the first run" })

        local before = ticks()["collapse"]
        vm:run("sleep 30")
        local runs = ticks()["collapse"] - before

        t:assert(runs >= 2, string.format(
            "the pending run really does follow the one it collapsed into: %d runs",
            runs))
        t:assert(runs <= 6, string.format(
            "but a run's worth of firings collapsed into one, not one start each: "
            .. "%d runs in thirty seconds", runs))
    end)

test("triggers on one service keep their own next firing and their own history",
    { spec = "peinit *evalt.triggers-on-one-service-are-independent" },
    function(t)
        -- pt-e-separate has two triggers: one every three seconds, one
        -- at 2am. They share a service and, being a Oneshot, they share
        -- its pending flag -- and nothing else. Each has its own
        -- descriptor, its own next-occurrence computation and, because
        -- the service has more than one, its own last-run value under
        -- TimerState (§9.3).
        --
        -- So the two timestamps must diverge: the frequent one moves
        -- every few seconds while the daily one keeps whatever the boot
        -- catch-up wrote and does not move again.
        local function history()
            local out = vm:run(
                [[reg get 'Machine\System\Services\pt-e-separate\TimerState']])
            out:assert_ok()
            local values = {}
            for _, line in ipairs(peinit.lines(out.stdout)) do
                local name, data = line:match("^(%S+) = REG_QWORD (%d+)$")
                if name then values[name] = data end
            end
            return values
        end

        local frequent = "%2A-%2A-%2A%20%2A%3A%2A%3A0%2F3"
        local daily = "%2A-%2A-%2A%2002%3A00%3A00"

        local first = wait_until(function()
            local h = history()
            return h[frequent] and h[daily] and h
        end, { timeout = 30, interval = 0.5,
               desc = "both triggers to have recorded a run" })

        vm:run("sleep 8")
        local second = history()

        t:assert(second[frequent] ~= first[frequent],
            "the three-second trigger fired again and recorded it: " ..
            tostring(first[frequent]) .. " -> " .. tostring(second[frequent]))
        t:assert_eq(second[daily], first[daily],
            "while the daily trigger on the same service did not, and kept its own")
    end)

test("a trigger introduced by a configuration reload is armed like any other",
    { spec = "peinit *evalt.every-active-trigger-gets-its-own-armed-descriptor" },
    function(t)
        -- First, take pt-e-bad's schedule away. A reload validates the
        -- whole graph and refuses all of it if any one definition is
        -- invalid (§10.4), so the deliberately broken schedule that the
        -- earlier test needed would make every reload from here on
        -- fail. Its evidence has already been read.
        vm:run([[reg del 'Machine\System\Services\pt-e-bad' Triggers]]):assert_ok()

        -- The other half of "at boot, and whenever timer configuration
        -- changes". peinit had never seen this definition when it built
        -- its plan; a registry write and a reload are the whole of what
        -- it takes to get a timerfd for it.
        local key = [[Machine\System\Services\pt-e-added]]
        vm:run("reg new '" .. key .. "'"):assert_ok()
        vm:run("reg set '" .. key .. "' ImagePath 'sz:/bin/sh'"):assert_ok()
        vm:run("reg set '" .. key .. "' Arguments 'multi:/pt/tick.sh,added'"):assert_ok()
        vm:run("reg set '" .. key .. "' Type 'dword:1'"):assert_ok()
        vm:run("reg set '" .. key .. "' Identity 'sz:SYSTEM'"):assert_ok()
        vm:run("reg set '" .. key .. "' Readiness 'dword:1'"):assert_ok()
        vm:run("reg set '" .. key .. "' TimerPersistent 'dword:0'"):assert_ok()
        t:assert_eq(ticks()["added"], 0, "the new service has never run")

        vm:run("reg set '" .. key .. [[' Triggers 'multi:timer:*-*-* *:*:0/3']])
            :assert_ok()
        vm:run("svctl --json reload-config"):assert_ok()

        wait_until(function() return ticks()["added"] > 0 end,
            { timeout = 30, interval = 0.5,
              desc = "the trigger added by the reload to fire" })
    end)
