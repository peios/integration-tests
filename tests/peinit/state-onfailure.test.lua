-- peinit TRM §6.3 — OnFailure: when entering Failed starts the named
-- handler, when it does not, and what bounds a chain of handlers.
--
-- Every handler here is a Oneshot that appends a line to `/run` and
-- exits. "The handler ran" is then a line count rather than a state, and
-- a line count is the only form of the question that survives a Oneshot
-- having finished before a test can look. "The handler did not run" is
-- the same measurement, taken after the failure it should not have
-- responded to has definitely happened.
--
-- The distinction the file turns on is between a failure and a retry. A
-- crash-looping service transits Backoff on every attempt and Failed
-- only once, at the end, so a handler that fires per retry and a handler
-- that fires per failure differ by a factor of the retry budget -- which
-- is why `pt-of-retry` is given a budget of three rather than one.

local peinit = require("helpers.peinit")
peinit.claim(1)

--- A Oneshot handler that records having been asked to run.
local function counter(tag)
    return "/bin/date +%s >> /run/pt-of-" .. tag .. ".log\n"
end

local FILES = {
    ["pt/of-plain.sh"] = counter("plain"),
    ["pt/of-retry.sh"] = counter("retry"),
    ["pt/of-assert.sh"] = counter("assert"),
    ["pt/of-invalid.sh"] = counter("invalid"),
    ["pt/of-manual.sh"] = counter("manual"),
}

local function service(name, values)
    local base = { { name = "Identity", type = "sz", data = "SYSTEM" } }
    for _, value in ipairs(values) do base[#base + 1] = value end
    return { path = [[Machine\System\Services\]] .. name, values = base }
end

local BOOT = { name = "Triggers", type = "multi", data = { "boot" } }
local NOTIFY = { name = "Readiness", type = "dword", data = 0 }
local NEVER = { name = "RestartPolicy", type = "dword", data = 0 }
local FALSE = { name = "ImagePath", type = "sz", data = "/bin/false" }

--- The Oneshot handler shape: runs once, records itself, exits.
local function handler(name, script)
    return service(name, {
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi", data = { "/pt/" .. script } },
        { name = "Type", type = "dword", data = 1 },
        { name = "Readiness", type = "dword", data = 1 },
    })
end

local function on_failure(target)
    return { name = "OnFailure", type = "sz", data = target }
end

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },

    -- A crash with no retries: one entry to Failed, one handler start.
    service("pt-of-plain", { BOOT, NOTIFY, NEVER, FALSE, on_failure("pt-of-plainh") }),
    handler("pt-of-plainh", "of-plain.sh"),

    -- The same crash with a budget of three. Failed is entered once, at
    -- the end, however many times Backoff is.
    service("pt-of-retry", {
        BOOT, NOTIFY, FALSE, on_failure("pt-of-retryh"),
        { name = "RestartPolicy", type = "dword", data = 2 },
        { name = "RestartDelay", type = "dword", data = 1 },
        { name = "RestartMaxRetries", type = "dword", data = 3 },
        { name = "RestartWindow", type = "dword", data = 300 },
    }),
    handler("pt-of-retryh", "of-retry.sh"),

    -- Definition and graph breakage, which OnFailure is explicitly not
    -- for. An assert that cannot hold, and a Oneshot declaring a
    -- HealthCheck it could never run.
    service("pt-of-assert", {
        BOOT, NEVER, on_failure("pt-of-asserth"),
        { name = "ImagePath", type = "sz", data = "/bin/true" },
        { name = "Type", type = "dword", data = 1 },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "Asserts", type = "multi", data = { "path:/pt/absent" } },
    }),
    handler("pt-of-asserth", "of-assert.sh"),
    service("pt-of-invalid", {
        BOOT, NEVER, on_failure("pt-of-invalidh"),
        { name = "ImagePath", type = "sz", data = "/bin/true" },
        { name = "Type", type = "dword", data = 1 },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "HealthCheck", type = "sz", data = "/bin/true" },
        { name = "HealthCheckInterval", type = "dword", data = 1 },
        { name = "HealthCheckRetries", type = "dword", data = 2 },
        { name = "RestartWindow", type = "dword", data = 120 },
    }),
    handler("pt-of-invalidh", "of-invalid.sh"),

    -- A handler that is already Active when the failure happens.
    service("pt-of-running", { BOOT, NOTIFY, NEVER, FALSE, on_failure("pt-of-resident") }),
    service("pt-of-resident", {
        BOOT,
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
        { name = "Readiness", type = "dword", data = 1 },
    }),

    -- Two services naming each other. Neither can succeed, so the chain
    -- would run forever if nothing bounded it.
    service("pt-of-loopa", { BOOT, NOTIFY, NEVER, FALSE, on_failure("pt-of-loopb") }),
    service("pt-of-loopb", { NOTIFY, NEVER, FALSE, on_failure("pt-of-loopa") }),

    -- Failed by hand, twice, so the same Oneshot handler is asked twice.
    service("pt-of-manual", { NOTIFY, NEVER, FALSE, on_failure("pt-of-manualh") }),
    handler("pt-of-manualh", "of-manual.sh"),
}

--- A chain of eighteen services, each naming the next as its handler and
--- none of them able to succeed. No service appears twice, so the set
--- bound has nothing to catch and only the depth bound can end it.
---
--- The originating failure is the first; the sixteen handlers after it
--- are the whole depth budget, and the eighteenth is one past it.
local CHAIN_LENGTH = 18
local function chain_name(index)
    return string.format("pt-of-c%02d", index)
end
for index = 1, CHAIN_LENGTH do
    local values = { NOTIFY, NEVER, FALSE }
    if index == 1 then values[#values + 1] = BOOT end
    if index < CHAIN_LENGTH then
        values[#values + 1] = on_failure(chain_name(index + 1))
    end
    SERVICES[#SERVICES + 1] = service(chain_name(index), values)
end

local vm = peinit.boot({
    name = "onfailure",
    files = peinit.merge(FILES, peinit.seed("pt-onfailure", SERVICES)),
})

local function status(name)
    local out = vm:run("svctl --json status " .. name)
    out:assert_ok()
    return json.decode(out.stdout)
end

local function settle(name, want, desc)
    return wait_until(function()
        local view = status(name)
        return view.state == want and view or nil
    end, { timeout = 120, interval = 0.3, desc = desc or (name .. " to reach " .. want) })
end

local function runs(tag)
    local ok, text = pcall(function() return vm:read_file("/run/pt-of-" .. tag .. ".log") end)
    if not ok then return 0 end
    return #peinit.lines(text)
end

test("entering Failed starts the service named in OnFailure",
    { spec = "peinit *cause.entering-failed-starts-the-named-onfailure-service" },
    function(t)
        local failed = settle("pt-of-plain", "failed", "pt-of-plain to fail")
        t:assert_eq(failed.cause, "process_crash", "on an ordinary crash")

        wait_until(function() return runs("plain") >= 1 end,
            { timeout = 60, interval = 0.5, desc = "pt-of-plainh to be started" })
        t:assert_eq(runs("plain"), 1, "the handler ran exactly once for the one failure")
    end)

test("OnFailure fires once per failure, not once per retry, and fires on budget exhaustion",
    {
        spec = {
            "peinit *cause.onfailure-fires-at-most-once-per-failure",
            "peinit *cause.onfailure-fires-for-a-non-critical-budget-exhaustion",
            "peinit *trans.onfailure-does-not-fire-on-each-retry",
            "peinit *trans.a-restart-never-passes-through-failed",
        },
    },
    function(t)
        -- pt-of-retry crashes four times: three of them are Backoff and
        -- the fourth is Failed. A handler that fired on each retry would
        -- have run four times.
        local view = settle("pt-of-retry", "failed", "pt-of-retry to spend its budget")
        t:assert_eq(view.cause, "restart_budget_exhausted",
            "the entry to Failed is the exhaustion, at the end of the retries")

        -- The three restarts before it went to Backoff and not through
        -- Failed, which is the same fact read the other way round: a
        -- transit through Failed would have started the handler.

        wait_until(function() return runs("retry") >= 1 end,
            { timeout = 60, interval = 0.5, desc = "pt-of-retryh to be started" })
        vm:run("sleep 3")
        t:assert_eq(runs("retry"), 1,
            "one entry to Failed, one handler start, despite three restarts before it")
    end)

test("OnFailure does not fire for definition or graph breakage",
    { spec = "peinit *cause.onfailure-does-not-fire-for-shutdown-or-definition-breakage" },
    function(t)
        -- An assert that cannot hold, and a definition the graph
        -- rejects. Both reach Failed; neither is runtime degradation a
        -- fallback could stand in for.
        local asserted = settle("pt-of-assert", "failed", "pt-of-assert to fail its assert")
        t:assert_eq(asserted.cause, "assertion_error", "on the assert")
        local invalid = settle("pt-of-invalid", "failed", "pt-of-invalid to be rejected")
        t:assert_eq(invalid.cause, "validation_error", "on the definition")

        -- The plain crash beside them did start its handler, so a
        -- handler start is something this boot demonstrably does.
        wait_until(function() return runs("plain") >= 1 end,
            { timeout = 60, interval = 0.5, desc = "the control case's handler" })
        t:assert_eq(runs("assert"), 0, "the assert failure started no handler")
        t:assert_eq(runs("invalid"), 0, "and neither did the rejected definition")
    end)

test("a handler that is already Active is not started again",
    {
        spec = {
            "peinit *cause.a-handler-already-active-or-reloading-starts-nothing",
            "peinit *cause.a-satisfied-handler-start-records-no-chain-entry",
        },
    },
    function(t)
        local resident = settle("pt-of-resident", "active", "the handler to be up at boot")
        local job = resident.current_job.id
        settle("pt-of-running", "failed", "pt-of-running to fail")

        -- The failure resolved as satisfied: the handler is the same
        -- incarnation it was before, and no operation was created
        -- against it.
        vm:run("sleep 2")
        local after = status("pt-of-resident")
        t:assert_eq(after.state, "active", "the handler is still the one that was running")
        t:assert_eq(after.current_job.id, job,
            "on the same activation, so nothing restarted it")
        t:assert(not after.current_operation,
            "and no operation was created for a start that resolved as satisfied")
    end)

test("a handler in any other state is started normally, so a Oneshot runs again for a new failure",
    { spec = "peinit *cause.a-handler-in-any-other-state-is-started-normally" },
    function(t)
        -- pt-of-manual is failed by hand. Its handler is a Oneshot, so
        -- after the first failure it has run and gone Inactive -- a
        -- state a start has an arrow out of.
        vm:run("svctl --json --no-wait start pt-of-manual"):assert_ok()
        settle("pt-of-manual", "failed", "pt-of-manual's first failure")
        wait_until(function() return runs("manual") >= 1 end,
            { timeout = 60, interval = 0.5, desc = "the handler's first run" })
        settle("pt-of-manualh", "inactive", "the handler to finish its first run")

        -- A second, separate failure.
        vm:run("svctl reset pt-of-manual"):assert_ok()
        vm:run("svctl --json --no-wait start pt-of-manual"):assert_ok()
        settle("pt-of-manual", "failed", "pt-of-manual's second failure")
        wait_until(function() return runs("manual") >= 2 end,
            { timeout = 60, interval = 0.5, desc = "the handler's second run" })
        t:assert_eq(runs("manual"), 2,
            "the Oneshot handler ran again for the new failure")
    end)

test("a chain of handlers that names itself is suppressed and audited",
    {
        spec = {
            "peinit *cause.a-handler-already-in-the-chain-is-not-started-again",
            "peinit *cause.a-suppressed-loop-records-an-audit-event",
        },
    },
    function(t)
        -- pt-of-loopa's handler is pt-of-loopb and pt-of-loopb's is
        -- pt-of-loopa. Neither can succeed, so without the guard the
        -- pair would hand off forever.
        settle("pt-of-loopa", "failed", "pt-of-loopa to fail")
        settle("pt-of-loopb", "failed", "pt-of-loopb to be started as its handler and fail")

        -- The guard records which bound it tripped rather than stopping
        -- silently.
        local event = wait_until(function()
            local out = vm:run(
                "evctl 'EVENTS on_failure.loop_suppressed SINCE 1h ago TAKE 50' --format jsonl")
            for _, line in ipairs(peinit.lines(out.stdout)) do
                if line:find("pt%-of%-loop") then return line end
            end
            return nil
        end, { timeout = 90, interval = 1, desc = "an on_failure.loop_suppressed event" })
        t:assert(event:find("pt-of-loop", 1, true),
            "the event names the pair whose chain was cut: " .. event)

        -- And the machine settled rather than cycling: the two services
        -- are Failed and stay that way.
        vm:run("sleep 3")
        t:assert_eq(status("pt-of-loopa").state, "failed", "pt-of-loopa settled")
        t:assert_eq(status("pt-of-loopb").state, "failed", "pt-of-loopb settled")
    end)

test("a chain of handlers is not followed past a depth of sixteen",
    {
        spec = {
            "peinit *cause.the-chain-is-not-followed-past-a-depth-of-sixteen",
            "peinit *cause.a-suppressed-loop-records-an-audit-event",
        },
    },
    function(t)
        -- Eighteen distinct services, each handing off to the next.
        -- Nothing repeats, so the set bound cannot be what stops this;
        -- the only thing that can is the fixed depth.
        --
        -- The first failure is the origin and the sixteen after it are
        -- the whole budget, so the seventeenth handler -- the eighteenth
        -- service -- is the one refused.
        local last_started = chain_name(CHAIN_LENGTH - 1)
        local refused = chain_name(CHAIN_LENGTH)
        settle(last_started, "failed", last_started .. " to be reached and fail")

        local event = wait_until(function()
            local out = vm:run(
                "evctl 'EVENTS on_failure.loop_suppressed SINCE 1h ago TAKE 50' --format jsonl")
            for _, line in ipairs(peinit.lines(out.stdout)) do
                if line:find(refused, 1, true) then return line end
            end
            return nil
        end, { timeout = 90, interval = 1, desc = "a max-depth on_failure.loop_suppressed event" })
        t:assert(event:find("max_depth", 1, true),
            "the event says the depth bound is what tripped, not the cycle bound: " .. event)
        t:assert(event:find(last_started, 1, true),
            "and names the failure the refused handoff came from: " .. event)

        -- The refused handler was never started: it is exactly where the
        -- boot left it.
        vm:run("sleep 2")
        local view = status(refused)
        t:assert_eq(view.state, "inactive",
            refused .. " was never started: " .. view.state)
        t:assert(not view.cause, "with no transition recorded against it at all")
    end)
