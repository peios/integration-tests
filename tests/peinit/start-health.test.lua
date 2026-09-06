-- peinit TRM §5.6 — health checks: a watchdog says a service is still
-- ticking, a health check says it still works.
--
-- Every claim here is about repetition over time, so the definitions are
-- staged with one-second intervals and short retry budgets: what would
-- otherwise take minutes of a default-configured service happens inside
-- a test. The probes write to /run as they run, which is what turns
-- "the previous check is still running, so the next one is skipped" into
-- a line count.
--
-- Two of the definitions are not meant to start at all. The flap
-- constraint is enforced when a definition arrives, so a violating one
-- is evidence about validation rather than about a running service.

local peinit = require("helpers.peinit")

local FILES = {
    -- Records where and as whom peinit ran it. `$PPID` rather than
    -- /proc/self/stat: a command substitution runs in a subshell, whose
    -- parent is this shell rather than whoever forked it.
    ["pt/hc-ok.sh"] = [[
echo "ppid=$PPID cgroup=$(cat /proc/self/cgroup) user=$(/bin/token user)" >> /run/pt-hc-ok.log
]],
    -- Logs each invocation and then takes far longer than the interval,
    -- so the intervals that fire while it runs have something to be
    -- counted against.
    ["pt/hc-slow.sh"] = [[
echo tick >> /run/pt-hc-overlap.log
/bin/sleep 6
]],
    -- Always fails, and keeps a running count of how many times it has
    -- been asked. The count survives a restart, since /run does.
    ["pt/hc-count.sh"] = [[
n=$(cat /run/pt-hc-budget.n 2>/dev/null || echo 0)
echo $((n + 1)) > /run/pt-hc-budget.n
exit 1
]],
    -- Fails, succeeds, fails, succeeds. With a retry budget of two, a
    -- service whose failure count resets on success can never reach it.
    ["pt/hc-alt.sh"] = [[
n=$(cat /run/pt-hc-alt.n 2>/dev/null || echo 0)
n=$((n + 1))
echo $n > /run/pt-hc-alt.n
echo $n >> /run/pt-hc-alt.log
if [ $((n % 2)) -eq 0 ]; then exit 0; else exit 1; fi
]],
}

local function simple(name, extra)
    local values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
    }
    for _, value in ipairs(extra) do values[#values + 1] = value end
    return { path = [[Machine\System\Services\]] .. name, values = values }
end

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },
    -- A check that passes. HookIdentity is deliberately something other
    -- than the service's own identity, and the service has no hooks, so
    -- the only thing it can affect is whether the health check picks it
    -- up -- which it must not.
    simple("pt-hc-ok", {
        { name = "HookIdentity", type = "sz", data = "LocalService" },
        { name = "HealthCheck", type = "sz", data = "/bin/sh /pt/hc-ok.sh" },
        { name = "HealthCheckInterval", type = "dword", data = 2 },
        { name = "HealthCheckRetries", type = "dword", data = 3 },
        { name = "RestartWindow", type = "dword", data = 120 },
    }),
    -- A check that always fails, with a budget of two and a window wide
    -- enough to satisfy the flap constraint.
    simple("pt-hc-fail", {
        { name = "HealthCheck", type = "sz", data = "/bin/false" },
        { name = "HealthCheckInterval", type = "dword", data = 1 },
        { name = "HealthCheckRetries", type = "dword", data = 2 },
        { name = "RestartWindow", type = "dword", data = 10 },
        { name = "RestartPolicy", type = "dword", data = 2 },
    }),
    -- A check that never finishes, with a one-second timeout.
    simple("pt-hc-timeout", {
        { name = "HealthCheck", type = "sz", data = "/bin/sleep 300" },
        { name = "HealthCheckInterval", type = "dword", data = 1 },
        { name = "HealthCheckTimeout", type = "dword", data = 1 },
        { name = "HealthCheckRetries", type = "dword", data = 2 },
        { name = "RestartWindow", type = "dword", data = 10 },
        { name = "RestartPolicy", type = "dword", data = 2 },
    }),
    -- A check that takes six seconds on a one-second interval, so five
    -- intervals fire while it is still running.
    simple("pt-hc-overlap", {
        { name = "HealthCheck", type = "sz", data = "/bin/sh /pt/hc-slow.sh" },
        { name = "HealthCheckInterval", type = "dword", data = 1 },
        { name = "HealthCheckTimeout", type = "dword", data = 60 },
        { name = "HealthCheckRetries", type = "dword", data = 3 },
        { name = "RestartWindow", type = "dword", data = 120 },
    }),
    -- Always fails, and counts its own invocations, with a budget of
    -- five: how many failures it takes to reach a restart is readable
    -- from the counter at the moment the main process is replaced.
    simple("pt-hc-budget", {
        { name = "HealthCheck", type = "sz", data = "/bin/sh /pt/hc-count.sh" },
        { name = "HealthCheckInterval", type = "dword", data = 1 },
        { name = "HealthCheckRetries", type = "dword", data = 5 },
        { name = "RestartWindow", type = "dword", data = 120 },
        { name = "RestartPolicy", type = "dword", data = 2 },
    }),
    simple("pt-hc-alternating", {
        { name = "HealthCheck", type = "sz", data = "/bin/sh /pt/hc-alt.sh" },
        { name = "HealthCheckInterval", type = "dword", data = 1 },
        { name = "HealthCheckRetries", type = "dword", data = 2 },
        { name = "RestartWindow", type = "dword", data = 120 },
        { name = "RestartPolicy", type = "dword", data = 2 },
    }),
    -- 3 x 60 = 180, which is not less than the 120-second window: the
    -- service could fail checks forever without the restart counter ever
    -- reaching its limit.
    simple("pt-hc-flap", {
        { name = "HealthCheck", type = "sz", data = "/bin/true" },
        { name = "HealthCheckInterval", type = "dword", data = 60 },
        { name = "HealthCheckRetries", type = "dword", data = 3 },
        { name = "RestartWindow", type = "dword", data = 120 },
    }),
    -- A Oneshot whose timing is perfectly valid -- 2 x 1 is well inside
    -- the window -- and which is rejected anyway, for declaring a
    -- HealthCheck it will never run.
    simple("pt-hc-oneshot", {
        { name = "Type", type = "dword", data = 1 },
        { name = "HealthCheck", type = "sz", data = "/bin/true" },
        { name = "HealthCheckInterval", type = "dword", data = 1 },
        { name = "HealthCheckRetries", type = "dword", data = 2 },
        { name = "RestartWindow", type = "dword", data = 120 },
    }),
}

local vm = peinit.boot({
    name = "health",
    files = peinit.merge(FILES, peinit.seed("pt-health", SERVICES)),
})

local function main_pid(service)
    local ok, procs = pcall(function()
        return vm:read_file("/sys/fs/cgroup/peinit/" .. service .. "/main/cgroup.procs")
    end)
    return ok and procs:match("^(%d+)") or nil
end

local function lines_of(path)
    local ok, text = pcall(function() return vm:read_file(path) end)
    if not ok then return {} end
    return peinit.lines(text)
end

--- Watch the two retry-budget subjects for their first restart, once,
--- immediately after the boot.
---
--- Both are `RestartPolicy=Always` services whose probes keep failing,
--- so they spend their restart budgets and settle into Failed within a
--- minute or so. Sampling them here rather than inside the tests means
--- the tests read a record of the first restart rather than racing the
--- machine for it — and means the long-running cases later in the file
--- cannot consume the window this evidence lives in.
local budget = (function()
    local watched = { ["pt-hc-budget"] = {}, ["pt-hc-alternating"] = {} }
    for service, record in pairs(watched) do
        record.first = wait_until(function() return main_pid(service) end,
            { timeout = 60, interval = 0.3, desc = service .. " to start" })
    end
    for _ = 1, 100 do
        for service, record in pairs(watched) do
            local now = main_pid(service)
            if not record.restarted_at and now and now ~= record.first then
                record.restarted_at =
                    vm:run("cat /run/pt-hc-" ..
                        (service == "pt-hc-budget" and "budget.n" or "alt.log") ..
                        " 2>/dev/null | wc -l").stdout:gsub("%s+$", "")
                if service == "pt-hc-budget" then
                    record.restarted_at =
                        vm:run("cat /run/pt-hc-budget.n").stdout:gsub("%s+$", "")
                end
            end
        end
        if watched["pt-hc-budget"].restarted_at
            and watched["pt-hc-alternating"].restarted_at then
            break
        end
        vm:run("sleep 0.2")
    end
    for _, record in pairs(watched) do
        record.checks = nil
    end
    watched["pt-hc-alternating"].invocations = #lines_of("/run/pt-hc-alt.log")
    return watched
end)()

test("a health check runs with the service's own token, in an ephemeral health/ cgroup under peinit",
    {
        spec = {
            "peinit *health.the-check-runs-with-the-services-own-token",
            "peinit *health.an-invocation-runs-in-the-health-cgroup-as-a-child-of-peinit",
        },
    },
    function(t)
        local first = wait_until(function()
            local lines = lines_of("/run/pt-hc-ok.log")
            return lines[1]
        end, { timeout = 60, interval = 0.5, desc = "pt-hc-ok's first health check" })

        -- The service's identity is SYSTEM and its HookIdentity is
        -- LocalService. The check reports SYSTEM, so it took the
        -- service's own token and never HookIdentity -- it checks the
        -- service's health from the service's own vantage point.
        t:assert(first:find("SYSTEM") or first:find("S%-1%-5%-18"),
            "the check ran as the service's identity: " .. first)
        t:assert(not (first:find("LocalService") or first:find("S%-1%-5%-19")),
            "and not as HookIdentity: " .. first)

        -- In the service's health/ sub-cgroup, and as a child of peinit
        -- rather than of the service.
        t:assert(first:find("cgroup=0::/peinit/pt%-hc%-ok/health"),
            "the invocation ran in the service's health/ sub-cgroup: " .. first)
        t:assert(first:find("ppid=1"),
            "as a child of peinit, not of the service: " .. first)

        -- Ephemeral: the sub-cgroup is killed when the check completes,
        -- so between invocations it holds nothing.
        wait_until(function()
            return vm:read_file("/sys/fs/cgroup/peinit/pt-hc-ok/health/cgroup.procs") == ""
        end, { timeout = 30, interval = 0.5, desc = "the health cgroup to be emptied" })
    end)

test("an interval that fires while the previous check is still running is skipped",
    { spec = "peinit *health.an-overlapping-check-is-skipped" },
    function(t)
        -- The check takes six seconds and the interval is one second, so
        -- an implementation that started one per interval would have
        -- half a dozen running at once. Wait for two invocations, then
        -- check how much time they took between them: at one per
        -- interval the second would have started a second after the
        -- first, not six.
        wait_until(function()
            return #lines_of("/run/pt-hc-overlap.log") >= 2
        end, { timeout = 90, interval = 0.5, desc = "two overlapping-check invocations" })

        local ticks = #lines_of("/run/pt-hc-overlap.log")
        local running = tonumber(
            vm:run("cat /sys/fs/cgroup/peinit/pt-hc-overlap/health/cgroup.procs | wc -l").stdout)
        t:assert(running <= 3,
            "at most one invocation is in flight (a shell and its sleep), not one per " ..
            "interval: " .. tostring(running) .. " processes in health/")

        -- And the service is untouched by the skipping: nothing is
        -- counted for an interval that was skipped, so the retry budget
        -- of three is never spent.
        t:assert_contains(vm:run("svctl status pt-hc-overlap").stdout, "active",
            "the service is still Active after " .. ticks .. " invocations")
    end)

test("a failing check marks the service unhealthy and restarts it through the ordinary restart policy",
    { spec = "peinit *health.consecutive-failures-restart-the-service" },
    function(t)
        -- The probe says the service is unhealthy, and the response is
        -- the restart policy rather than anything health-specific: the
        -- service goes to Backoff with the health check named as the
        -- cause, exactly as it would after a crash.
        local status = wait_until(function()
            local out = json.decode(vm:run("svctl --json status pt-hc-fail").stdout)
            return out.health == "unhealthy" and out or nil
        end, { timeout = 60, interval = 0.5, desc = "pt-hc-fail to be marked unhealthy" })
        t:assert_eq(status.cause, "health_check_failure",
            "the recorded cause is the health check")
        t:assert(status.state == "backoff" or status.state == "starting" or
            status.state == "active",
            "and the service is going round the restart policy: " .. status.state)
    end)

test("the restart happens only after HealthCheckRetries consecutive failures",
    {
        spec = "peinit *health.consecutive-failures-restart-the-service",
        tags = { "known-bug" },
    },
    function(t)
        -- pt-hc-budget's probe counts its own invocations and always
        -- fails, with a budget of five. The service should survive four
        -- of them. peinit restarts it after the first: each activation
        -- gets exactly one invocation before being torn down, so the
        -- counter is nowhere near the budget when the main process is
        -- replaced.
        local at_restart = budget["pt-hc-budget"].restarted_at
        t:assert(at_restart, "pt-hc-budget was restarted at all")
        t:assert(tonumber(at_restart) >= 5,
            "the service survived four failures and was restarted on the fifth; " ..
            "it had failed " .. at_restart .. " time(s)")
    end)

test("a check that exceeds HealthCheckTimeout counts as a failure",
    { spec = "peinit *health.a-timed-out-check-counts-as-a-failure" },
    function(t)
        -- `/bin/sleep 300` never returns an answer at all, so nothing
        -- here is the probe reporting the service unhealthy: its
        -- sub-cgroup is killed at the one-second timeout, and the only
        -- thing that could have marked the service unhealthy is that
        -- timeout being counted as a failure.
        local status = wait_until(function()
            local out = json.decode(vm:run("svctl --json status pt-hc-timeout").stdout)
            return out.health == "unhealthy" and out or nil
        end, { timeout = 60, interval = 0.5,
               desc = "pt-hc-timeout to be marked unhealthy" })
        t:assert_eq(status.health, "unhealthy",
            "the service is unhealthy, and the only evidence peinit has about it " ..
            "is the timeout, since the probe never reported anything")

        -- The health check is also the only thing that can move this
        -- service at all -- it is `/bin/sleep 3600`, which does not exit
        -- -- so whatever state the restart policy has taken it to by
        -- now, the timeout is what put it there.
        t:assert(status.state ~= "active" or status.cause == "health_check_failure",
            "and it is being restarted rather than left alone: " ..
            status.state .. "/" .. tostring(status.cause))
    end)

test("the failure count resets the moment a check succeeds",
    {
        spec = "peinit *health.a-success-resets-the-failure-count",
        tags = { "known-bug" },
    },
    function(t)
        -- The probe fails on every odd invocation and succeeds on every
        -- even one, with a budget of two. Two *consecutive* failures
        -- never happen, so a service whose count resets on success is
        -- never restarted.
        --
        -- It is restarted after the first failure, which is the same
        -- defect the budget case above records: a count that never
        -- accumulates has nothing to reset.
        local record = budget["pt-hc-alternating"]
        t:assert(record.invocations >= 2,
            "the probe was asked more than once: " .. record.invocations .. " invocation(s)")
        t:assert(record.restarted_at == nil,
            "the service was never restarted, because no two failures were consecutive")
    end)

test("a definition violating the flap constraint is blocked at boot and never started",
    {
        spec = {
            "peinit *health.the-flap-constraint",
            "peinit *health.a-violating-definition-is-blocked-at-boot",
        },
    },
    function(t)
        -- HealthCheckRetries x HealthCheckInterval must be less than
        -- RestartWindow, or the service stays healthy long enough
        -- between failures to reset the restart counter and restarts
        -- forever. 3 x 60 is not less than 120.
        local status = vm:run("svctl status pt-hc-flap").stdout
        t:assert(not status:find("active"),
            "the service was never started: " .. status)
        t:assert(status:find("validation_error") or
            vm:console():read_log():find("ValidationError"),
            "and the reason given is a validation error: " .. status)

        -- The constraint applies only where a check will actually run.
        -- Every other staged definition here has a HealthCheck too, and
        -- the ones whose arithmetic holds started normally.
        t:assert_contains(vm:run("svctl status pt-hc-ok").stdout, "active",
            "a definition whose arithmetic holds is unaffected")
    end)

test("a Oneshot that declares a HealthCheck is rejected for declaring one, not for its timing",
    {
        spec = {
            "peinit *health.a-health-check-on-a-non-simple-service-is-rejected",
            "peinit *health.the-constraint-applies-only-to-simple-services",
        },
    },
    function(t)
        -- pt-hc-oneshot's timing is valid: 2 x 1 is well inside its
        -- 120-second window, so the flap constraint has nothing to say
        -- about it. It is rejected anyway, because a Oneshot never runs
        -- a health check and declaring one is the thing actually wrong
        -- with the definition.
        local status = vm:run("svctl status pt-hc-oneshot").stdout
        t:assert(not status:find("active"), "the Oneshot was not started: " .. status)
        t:assert_contains(status, "validation_error",
            "it was rejected as a validation error")

        -- Nothing about its timing could have produced that: the
        -- constraint applies only where a check will actually run, and a
        -- Oneshot never runs one -- so the finding can only be the
        -- unschedulable HealthCheck itself. An operator adjusting
        -- RestartWindow here would get nowhere, which is the point of
        -- reporting it this way round.
        t:assert_contains(vm:console():read_log(),
            "peinit: service pt-hc-oneshot failed: ValidationError",
            "and the boot blocked it rather than starting it")
    end)

test("a violating definition arriving on reload-config is a finding, and a finding rejects the reload",
    { spec = "peinit *health.a-violating-definition-rejects-a-reload" },
    function(t)
        -- A window narrower than the failure cycle, written into a
        -- definition that was valid at boot.
        vm:run([[reg set 'Machine\System\Services\pt-hc-ok' RestartWindow dword:5]]):assert_ok()

        local reload = vm:run("svctl reload-config")
        t:assert(reload.exit_code ~= 0 or reload.stdout:lower():find("reject") or
            reload.stdout:lower():find("finding") or reload.stderr ~= "",
            "the reload was rejected: rc=" .. reload.exit_code ..
            " out=" .. reload.stdout .. " err=" .. reload.stderr)

        -- Rejected entire: the service is still running on the
        -- definition it started with rather than on a partially applied
        -- one.
        t:assert_contains(vm:run("svctl status pt-hc-ok").stdout, "active",
            "and the running service was left alone")
    end)
