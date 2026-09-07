-- peinit TRM §6.3 — the cause taxonomy and the four restart-eligibility
-- classes.
--
-- The class a cause belongs to is not directly observable, so each one
-- is asserted through the decision it makes: whether the policy was
-- consulted, and whether the budget was spent. A definition is built so
-- that only one class can produce the outcome seen. `pt-cs-always`
-- exits zero and is restarted anyway, which only the Always-only class
-- does; `pt-cs-bound` has RestartPolicy=Never and a budget of zero and is
-- started again anyway, which only the budget-exempt class does; and
-- `pt-cs-stopme` is Always and is not restarted, which only a
-- never-restart cause produces.
--
-- The boot carries `peios.quiet=0` because one assertion is on a console
-- record produced after the boot, and the default level stays out of a
-- terminal a service owns -- which /dev/console is, once the boot has
-- finished.

local peinit = require("helpers.peinit")
peinit.claim(1)

local FILES = {
    -- Reaches Active -- Readiness is Alive, so the process existing is
    -- enough -- holds it for a second, and then exits successfully.
    ["pt/cs-clean.sh"] = [[
/bin/date +%s >> /run/pt-cs-clean.log
/bin/sleep 1
exit 0
]],
}

local function service(name, values)
    local base = { { name = "Identity", type = "sz", data = "SYSTEM" } }
    for _, value in ipairs(values) do base[#base + 1] = value end
    return { path = [[Machine\System\Services\]] .. name, values = base }
end

local BOOT = { name = "Triggers", type = "multi", data = { "boot" } }
local ALIVE = { name = "Readiness", type = "dword", data = 1 }
local ALWAYS = { name = "RestartPolicy", type = "dword", data = 2 }
local RESIDENT = {
    { name = "ImagePath", type = "sz", data = "/bin/sleep" },
    { name = "Arguments", type = "multi", data = { "3600" } },
}

local function with(base, extra)
    local out = {}
    for _, value in ipairs(base) do out[#out + 1] = value end
    for _, value in ipairs(extra) do out[#out + 1] = value end
    return out
end

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },

    -- Nothing about this service fails. Under Always it is restarted all
    -- the same, on the same doubling delay and out of the same budget as
    -- a crash would have spent.
    service("pt-cs-always", {
        BOOT, ALIVE, ALWAYS,
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi", data = { "/pt/cs-clean.sh" } },
        { name = "RestartDelay", type = "dword", data = 1 },
        { name = "RestartMaxRetries", type = "dword", data = 3 },
        { name = "RestartWindow", type = "dword", data = 300 },
    }),

    -- A binding pair. The bound service has no restart policy and no
    -- budget at all, so anything that starts it again did so without
    -- consulting either.
    service("pt-cs-anchor", with(RESIDENT, { BOOT, ALIVE })),
    service("pt-cs-bound", with(RESIDENT, {
        BOOT, ALIVE,
        { name = "BindsTo", type = "multi", data = { "pt-cs-anchor" } },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "RestartMaxRetries", type = "dword", data = 0 },
    })),

    -- Always, and stopped by hand: the policy is not consulted for an
    -- explicit stop, so it stays down.
    service("pt-cs-stopme", with(RESIDENT, {
        BOOT, ALIVE, ALWAYS,
        { name = "RestartDelay", type = "dword", data = 1 },
        { name = "RestartMaxRetries", type = "dword", data = 5 },
    })),

    -- Always, and skipped: a condition that does not hold is not a
    -- failure to retry.
    service("pt-cs-skip", with(RESIDENT, {
        BOOT, ALIVE, ALWAYS,
        { name = "Conditions", type = "multi", data = { "path:/pt/absent" } },
        { name = "RestartDelay", type = "dword", data = 1 },
        { name = "RestartMaxRetries", type = "dword", data = 5 },
    })),
}

local vm = peinit.boot({
    name = "causes",
    append = "peios.quiet=0",
    files = peinit.merge(FILES, peinit.seed("pt-causes", SERVICES)),
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

local function stamps(path)
    local ok, text = pcall(function() return vm:read_file(path) end)
    if not ok then return {} end
    local out = {}
    for _, line in ipairs(peinit.lines(text)) do out[#out + 1] = tonumber(line) end
    return out
end

test("every transition carries the cause of the most recent one",
    { spec = "peinit *cause.every-transition-carries-the-cause-of-the-most-recent-transition" },
    function(t)
        -- Three transitions in a row on one service, each leaving a
        -- different cause behind: the field tracks the latest rather
        -- than the first.
        local up = settle("pt-cs-stopme", "active", "pt-cs-stopme to come up at boot")
        t:assert(up.cause == "explicit_start" or up.cause == "dependency_start",
            "the boot plan's start is what put it here: " .. tostring(up.cause))

        vm:run("svctl stop pt-cs-stopme"):assert_ok()
        t:assert_eq(settle("pt-cs-stopme", "inactive", "the stop to finish").cause,
            "explicit_stop", "and the stop replaced it")

        vm:run("svctl start pt-cs-stopme"):assert_ok()
        t:assert_eq(settle("pt-cs-stopme", "active", "the start to finish").cause,
            "explicit_start", "and the start replaced that")
    end)

test("a never-restart cause does not consult the policy, even under Always",
    { spec = "peinit *cause.a-never-restart-cause-does-not-consult-the-policy" },
    function(t)
        -- pt-cs-stopme is RestartPolicy=Always with five retries. An
        -- explicit stop is not a failure, so none of that is looked at.
        vm:run("svctl stop pt-cs-stopme"):assert_ok()
        settle("pt-cs-stopme", "inactive", "pt-cs-stopme to stop")
        vm:run("sleep 4")
        local view = status("pt-cs-stopme")
        t:assert_eq(view.state, "inactive",
            "an Always service stopped by hand stays stopped: " .. view.state)
        t:assert_eq(view.cause, "explicit_stop", "under the stop's own cause")

        -- The same for a condition that does not hold: Skipped is a
        -- service that has succeeded by not applying, not one to retry.
        local skipped = settle("pt-cs-skip", "skipped", "pt-cs-skip to be skipped")
        t:assert_eq(skipped.cause, "condition_skipped", "on its condition")
        vm:run("sleep 3")
        t:assert_eq(status("pt-cs-skip").state, "skipped",
            "and Always did not turn that into a retry loop")
    end)

test("CleanExitRestart uses the same backoff and the same budget as a failure",
    {
        spec = {
            "peinit *cause.cleanexitrestart-uses-the-same-backoff-and-budget-as-a-failure",
            "peinit *cause.a-restart-eligible-cause-consults-the-policy-and-the-budget",
        },
    },
    function(t)
        -- Nothing about pt-cs-always fails: it reaches Active and exits
        -- zero. Under Always that is a restart all the same, and it is
        -- throttled and budgeted exactly as a crash would be.
        local cycling = wait_until(function()
            local view = status("pt-cs-always")
            return view.cause == "clean_exit_restart" and view or nil
        end, { timeout = 90, interval = 0.3,
               desc = "pt-cs-always to be restarted by policy" })
        t:assert_eq(cycling.cause, "clean_exit_restart",
            "the success is recorded as a success, not as a crash")

        -- The same budget: three retries and no more, and the exhaustion
        -- is the ordinary one.
        local spent = settle("pt-cs-always", "failed",
            "pt-cs-always to spend its budget on successful exits")
        t:assert_eq(spent.cause, "restart_budget_exhausted",
            "a clean exit under Always spends the budget a failure would have")
        local launches = stamps("/run/pt-cs-clean.log")
        t:assert_eq(#launches, 4, "one run plus three restarts")

        -- The same backoff: the gaps grow, and each carries the one
        -- second the process itself spends running.
        local gaps = {}
        for index = 2, #launches do gaps[#gaps + 1] = launches[index] - launches[index - 1] end
        t:assert(gaps[#gaps] > gaps[1],
            "the delay doubled between restarts as it would after a crash: " ..
            table.concat(gaps, ", "))
    end)

test("BindsToRecovery restarts a service with no policy and no budget",
    { spec = "peinit *cause.bindstorecovery-is-exempt-from-the-policy-and-the-budget" },
    function(t)
        settle("pt-cs-anchor", "active", "the binding target to come up")
        local bound = settle("pt-cs-bound", "active", "the bound service to come up")
        local first = bound.current_job.id

        -- Stopping the target takes the bound service down with it, and
        -- the cause records that rather than a generic failure.
        vm:run("svctl stop pt-cs-anchor"):assert_ok()
        local propagated = settle("pt-cs-bound", "failed",
            "pt-cs-bound to follow its binding target down")
        t:assert_eq(propagated.cause, "binds_to_propagation",
            "it was stopped because its dependency went away")

        -- RestartPolicy=Never and RestartMaxRetries=0: nothing in the
        -- policy or the budget could authorise another start. The target
        -- returning does.
        vm:run("svctl start pt-cs-anchor"):assert_ok()
        local recovered = wait_until(function()
            local view = status("pt-cs-bound")
            return view.state == "active" and view.current_job
                and view.current_job.id ~= first and view or nil
        end, { timeout = 90, interval = 0.3, desc = "pt-cs-bound to be recovered" })
        t:assert_eq(recovered.cause, "binds_to_recovery",
            "and the cause names the recovery rather than a restart policy")
    end)

test("a transition to Failed produces a console record naming the service and the cause",
    { spec = "peinit *cause.every-transition-produces-a-record" },
    function(t)
        -- Two of the four things §6.3 asks a record to cover -- what
        -- failed, and why -- are on the console line peinit writes when
        -- a service enters Failed. The other two are asserted nowhere
        -- here because peinit emits them nowhere: see the report.
        settle("pt-cs-always", "failed", "pt-cs-always to have failed")
        local log = vm:console():read_log()
        t:assert(log:find("peinit: service pt-cs-always failed: RestartBudgetExhausted", 1, true),
            "the record names the service that failed and the cause it failed with")
    end)
