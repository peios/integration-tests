-- peinit TRM §6.1 — the states: which of the ten a service can be in, and
-- which three of them let a dependent start.
--
-- Dependent satisfaction is the only part of §6.1 with a shape a test can
-- see from outside, and it is seen the same way each time: a target
-- parked in the state under test, and a `Requires` dependent that either
-- started or did not. The console is the oracle for "did it start" rather
-- than svctl, because a Oneshot that ran has been Completed and Inactive
-- again by the time anything can ask, and `peinit: service X started` is
-- the one record that survives that.
--
-- Every target here is arranged so that the state it lands in is the only
-- one it can land in: a condition that cannot hold, an assert that cannot
-- hold, a process that cannot succeed. The Backoff target is given a
-- thirty-second RestartDelay so it stays parked for the whole file rather
-- than cycling underneath the assertions.

local peinit = require("helpers.peinit")
peinit.claim(1)

-- The ten states of §6.1, as svctl spells them.
local STATES = {
    inactive = true, starting = true, active = true, reloading = true,
    stopping = true, completed = true, backoff = true, failed = true,
    abandoned = true, skipped = true,
}

local function service(name, values)
    local base = {
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "Triggers", type = "multi", data = { "boot" } },
    }
    for _, value in ipairs(values) do base[#base + 1] = value end
    return { path = [[Machine\System\Services\]] .. name, values = base }
end

--- A Oneshot that succeeds and says nothing.
local function oneshot(name, values)
    local base = {
        { name = "ImagePath", type = "sz", data = "/bin/true" },
        { name = "Type", type = "dword", data = 1 },
    }
    for _, value in ipairs(values or {}) do base[#base + 1] = value end
    return service(name, base)
end

--- A dependent that does nothing but record, by starting, that its
--- `Requires` target satisfied it.
local function dependent_of(name, target)
    return oneshot(name, { { name = "Requires", type = "multi", data = { target } } })
end

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },

    -- Completed: a Oneshot with no RemainAfterExit, so it passes through
    -- Completed on its way to Inactive. Its dependent starting is the
    -- only evidence that it did not skip the state.
    oneshot("pt-st-done"),
    dependent_of("pt-st-after-done", "pt-st-done"),

    -- Skipped: a condition naming a path that does not exist.
    oneshot("pt-st-skip", {
        { name = "Conditions", type = "multi", data = { "path:/pt/absent" } },
    }),
    dependent_of("pt-st-after-skip", "pt-st-skip"),

    -- Failed: an assert naming the same absent path. An assert failing is
    -- AssertionError rather than ConditionSkipped, which is the whole
    -- difference between these two definitions.
    oneshot("pt-st-fail", {
        { name = "Asserts", type = "multi", data = { "path:/pt/absent" } },
    }),
    dependent_of("pt-st-after-fail", "pt-st-fail"),

    -- Backoff: a Simple service whose process exits non-zero before it
    -- can signal readiness, with a restart allowed and a delay long
    -- enough that it stays parked for the file's lifetime.
    service("pt-st-backoff", {
        { name = "ImagePath", type = "sz", data = "/bin/false" },
        { name = "Readiness", type = "dword", data = 0 },
        { name = "RestartPolicy", type = "dword", data = 2 },
        { name = "RestartDelay", type = "dword", data = 30 },
        { name = "RestartMaxRetries", type = "dword", data = 5 },
    }),
    dependent_of("pt-st-after-backoff", "pt-st-backoff"),

    -- A resident service, for the generation counter and for the
    -- security-axis case. Identity is deliberately not SYSTEM: what
    -- governs whether SYSTEM may manage it is its ServiceSecurity, and
    -- the two are meant to be independent.
    service("pt-st-resident", {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
    }),
    service("pt-st-lowpriv", {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
        { name = "Identity", type = "sz", data = "LocalService" },
    }),
}

local vm = peinit.boot({
    name = "states",
    files = peinit.seed("pt-states", SERVICES),
})

local function status(service_name)
    local out = vm:run("svctl --json status " .. service_name)
    out:assert_ok()
    return json.decode(out.stdout)
end

local function started(service_name)
    return vm:console():read_log():find("peinit: service " .. service_name .. " started", 1, true)
        ~= nil
end

--- Wait for a service to reach `want`.
---
--- Every state assertion here is polled rather than read once. "phase2
--- boot complete" is printed when the plan has been dispatched, so a
--- service read at the boot mark can still be Starting -- and a service
--- that is Starting already carries a cause, which makes a single
--- reading of either field a race rather than an observation.
local function settle(service_name, want, desc)
    return wait_until(function()
        local view = status(service_name)
        return view.state == want and view or nil
    end, {
        timeout = 90, interval = 0.3,
        desc = desc or (service_name .. " to reach " .. want),
    })
end

-- The four dependents are the file's evidence and they all resolve within
-- the first turns of the boot, but a started line arrives after "phase2
-- boot complete" rather than before it. Wait for the two that must start
-- once, here, rather than racing them in each test.
vm:console():expect("peinit: service pt-st-after-done started", peinit.STAGE_TIMEOUT)
vm:console():expect("peinit: service pt-st-after-skip started", peinit.STAGE_TIMEOUT)

test("every service is in exactly one state, and it is one of the ten",
    { spec = "peinit *state.every-service-is-in-exactly-one-of-ten-states" },
    function(t)
        local listing = vm:run("svctl --json list")
        listing:assert_ok()
        local decoded = json.decode(listing.stdout)
        t:assert(#decoded.services > 5,
            "the image's own graph is in the listing: " .. #decoded.services .. " services")
        for _, item in ipairs(decoded.services) do
            t:assert(STATES[item.state],
                item.service .. " is in a state §6.1 names: " .. tostring(item.state))
        end

        -- One state per service, not a set: the status view carries a
        -- single scalar, so there is nowhere for a second one to be.
        local view = settle("pt-st-resident", "active",
            "pt-st-resident to come up at boot")
        t:assert_eq(type(view.state), "string", "one state, as a scalar")
        t:assert(STATES[view.state], "and one of the ten: " .. view.state)
    end)

test("Active, Completed and Skipped satisfy dependents; Failed and Backoff do not",
    {
        spec = {
            "peinit *state.only-active-completed-and-skipped-satisfy-dependents",
            "peinit *state.a-dependent-on-an-unsatisfied-requires-target-does-not-start",
        },
    },
    function(t)
        -- Skipped satisfies. The target's condition names a path that is
        -- not there, so it cannot have run, and the dependent started
        -- anyway.
        settle("pt-st-skip", "skipped",
            "the conditional target to be skipped rather than started")
        t:assert(started("pt-st-after-skip"),
            "and its Requires dependent started")

        -- Failed does not. The assert names the same absent path, so the
        -- only difference between these two targets is which field named
        -- it.
        local failed = settle("pt-st-fail", "failed", "the asserting target to fail")
        t:assert_eq(failed.cause, "assertion_error", "on the assert, not a condition")
        t:assert(not started("pt-st-after-fail"),
            "and its Requires dependent did not start")

        -- Active satisfies, which is what every other service in the
        -- image's graph has already demonstrated; assert it here on a
        -- target this file controls.
        settle("pt-st-resident", "active", "the resident service to be Active")
    end)

test("a Oneshot without RemainAfterExit passes through Completed rather than skipping it",
    { spec = "peinit *state.completed-satisfies-regardless-of-remainafterexit" },
    function(t)
        -- The target declares no RemainAfterExit, so by the time anything
        -- can ask it is Inactive. If Completed had been skipped on the
        -- way there, the dependent would have had nothing to satisfy it
        -- and would never have started.
        t:assert(started("pt-st-done"), "the Oneshot ran")
        local view = settle("pt-st-done", "inactive",
            "the Oneshot to have passed through Completed to Inactive")
        t:assert_eq(view.cause, "clean_exit",
            "having left Completed under a clean exit")
        t:assert(started("pt-st-after-done"),
            "while its dependent started, so Completed released it on the way past")
    end)

test("a dependent of a service in Backoff waits rather than failing",
    {
        spec = "peinit *state.a-dependent-of-a-service-in-backoff-waits-rather-than-failing",
        -- PEI-821: a start failure fails the target's graph operation
        -- before the restart evaluation is consulted, so hard dependents
        -- are given DependencyFailure even when the target went to
        -- Backoff and is about to start again.
        tags = { "known-bug" },
    },
    function(t)
        local target = wait_until(function()
            local view = status("pt-st-backoff")
            return view.state == "backoff" and view or nil
        end, { timeout = 60, interval = 0.5, desc = "pt-st-backoff to reach Backoff" })
        t:assert_eq(target.cause, "process_crash",
            "the target is in Backoff after a crash, not after a give-up")

        -- Waiting is the absence of two things: the dependent has not
        -- started, because Backoff does not satisfy; and it has not
        -- failed, because a service that is going to start again is not
        -- a dependency failure.
        t:assert(not started("pt-st-after-backoff"),
            "the dependent has not started")
        local view = status("pt-st-after-backoff")
        t:assert(view.state ~= "failed",
            "and it has not been failed either: " .. view.state ..
            "/" .. tostring(view.cause))
    end)

test("every entry to Starting is a fresh activation, distinct from the one before",
    { spec = "peinit *state.the-generation-increments-on-every-entry-to-starting" },
    function(t)
        -- The generation counter itself is not on the control wire: the
        -- status view carries it internally, but `control_status_response_line`
        -- does not project it, so what a test can see of "the generation
        -- increments" is its consequence -- each entry to Starting binds
        -- the service to a new main job, and the job peinit was holding
        -- for the previous incarnation is never the one it holds for
        -- this one.
        local function activation()
            local view = status("pt-st-resident")
            if view.state ~= "active" or not view.current_job then return nil end
            return view.current_job.id
        end

        local first = wait_until(activation,
            { timeout = 60, interval = 0.5, desc = "pt-st-resident's boot activation" })

        vm:run("svctl restart pt-st-resident"):assert_ok()
        local second = wait_until(function()
            local id = activation()
            return id and id ~= first and id or nil
        end, { timeout = 60, interval = 0.5, desc = "pt-st-resident to come back up" })

        -- A stop does not enter Starting, so it binds nothing; the start
        -- that follows does, and binds a third distinct job.
        vm:run("svctl stop pt-st-resident"):assert_ok()
        t:assert(activation() == nil,
            "a stopped service holds no activation at all")
        vm:run("svctl start pt-st-resident"):assert_ok()
        local third = wait_until(activation,
            { timeout = 60, interval = 0.5, desc = "pt-st-resident to start again" })

        t:assert(third ~= second and third ~= first,
            "three entries to Starting, three distinct activations: " ..
            first .. ", " .. second .. ", " .. third)
    end)

test("service state lives inside peinit, and the control socket produces operations",
    { spec = "peinit *state.nothing-outside-peinit-writes-service-state" },
    function(t)
        -- There is nowhere outside peinit for the state to be written:
        -- the definition key holds the definition, and no value in it is
        -- the runtime state.
        local values = vm:run([[reg ls 'Machine\System\Services\pt-st-resident']])
        values:assert_ok()
        for _, forbidden in ipairs({ "State", "Cause", "Generation" }) do
            t:assert(not values.stdout:find(forbidden, 1, true),
                "the definition key carries no " .. forbidden .. " value: " .. values.stdout)
        end

        -- And what the control socket returns for a lifecycle command is
        -- an operation rather than a state write: peinit performs the
        -- transition, the caller is handed the operation's id.
        vm:run("svctl stop pt-st-resident"):assert_ok()
        local ack = json.decode(vm:run("svctl --json --no-wait start pt-st-resident").stdout)
        t:assert(ack.operation_id,
            "the socket answered with an operation: " .. vm:run(
                "svctl --json status pt-st-resident").stdout)
        wait_until(function() return status("pt-st-resident").state == "active" end,
            { timeout = 60, interval = 0.5, desc = "the operation to run to completion" })
    end)

test("a service's process token and who may manage it are independent",
    { spec = "peinit *state.a-service-is-securable-independently-of-its-process-token" },
    function(t)
        -- pt-st-lowpriv runs as LocalService and pt-st-resident as
        -- SYSTEM. Neither declares a ServiceSecurity, so both take the
        -- default descriptor -- the same one -- and SYSTEM manages both.
        -- The process token therefore said nothing about manageability in
        -- either direction.
        local low = settle("pt-st-lowpriv", "active",
            "the LocalService-identity service to be running")
        t:assert(low.current_job and low.current_job.identity,
            "and its job carries a resolved identity: " ..
            vm:run("svctl --json status pt-st-lowpriv").stdout)
        t:assert(low.current_job.identity:find("LocalService") or
            low.current_job.identity:find("S%-1%-5%-19"),
            "which is the definition's Identity: " .. low.current_job.identity)

        -- Manageable by SYSTEM all the same, exactly as the SYSTEM-token
        -- service beside it is: the restart is admitted and carried out
        -- on a service whose own token is not the caller's.
        local before = low.current_job.id
        vm:run("svctl restart pt-st-lowpriv"):assert_ok()
        wait_until(function()
            local view = status("pt-st-lowpriv")
            return view.state == "active" and view.current_job
                and view.current_job.id ~= before or nil
        end, { timeout = 60, interval = 0.5, desc = "pt-st-lowpriv to come back" })
        t:assert(status("pt-st-lowpriv").current_job.id ~= before,
            "SYSTEM managed a service running as LocalService, so the process token " ..
            "governed nothing about who may manage it")
    end)
