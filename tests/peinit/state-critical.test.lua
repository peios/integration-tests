-- peinit TRM §6.4 — ErrorControl: what a Critical service exhausting its
-- restart budget costs the machine.
--
-- Its own file because the asserted outcome is a reboot. The VM does not
-- survive it, so nothing may follow -- and nothing here may depend on
-- reading the guest afterwards. Every assertion is on the console, which
-- the host records whether or not the machine is still answering.
--
-- Both services fail the same way and for the same reason: an
-- `ExecStartPre` that cannot succeed, which is a startup failure -- the
-- route §6.4 singles out, because a service that never gets as far as
-- running would otherwise settle in Failed with no escalation at all.
-- They differ in one dword, `ErrorControl`, and neither is boot-triggered:
-- the reboot has to happen where a test can watch it rather than during
-- the boot the harness is still waiting on.
--
-- `peios.quiet=0`, because one assertion is that a handler's start line
-- is absent. At the default level nothing peinit writes after the boot
-- reaches the console at all, and the assertion would pass for the wrong
-- reason.

local peinit = require("helpers.peinit")
peinit.claim(1)

local function failing(name, extra)
    local values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        -- The pre-hook cannot succeed, so the service never reaches its
        -- own process: the budget is spent purely on startup failures.
        { name = "ExecStartPre", type = "multi", data = { "/bin/false" } },
        { name = "RestartPolicy", type = "dword", data = 2 },
        { name = "RestartDelay", type = "dword", data = 1 },
        { name = "RestartMaxRetries", type = "dword", data = 1 },
        { name = "RestartWindow", type = "dword", data = 300 },
    }
    for _, value in ipairs(extra) do values[#values + 1] = value end
    return { path = [[Machine\System\Services\]] .. name, values = values }
end

local function handler(name)
    return {
        path = [[Machine\System\Services\]] .. name,
        values = {
            { name = "ImagePath", type = "sz", data = "/bin/true" },
            { name = "Type", type = "dword", data = 1 },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
        },
    }
end

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },

    -- Normal, which is the default: the service stays Failed and the
    -- handler runs. This is the control, and it also fixes that a
    -- handler start is visible on this console.
    failing("pt-cr-normal", {
        { name = "OnFailure", type = "sz", data = "pt-cr-normalh" },
    }),
    handler("pt-cr-normalh"),

    -- Critical: the reboot takes precedence and no fallback is started.
    failing("pt-cr-boom", {
        { name = "ErrorControl", type = "dword", data = 1 },
        { name = "OnFailure", type = "sz", data = "pt-cr-boomh" },
    }),
    handler("pt-cr-boomh"),
}

local vm = peinit.boot({
    name = "critical",
    append = "peios.quiet=0",
    files = peinit.seed("pt-critical", SERVICES),
})

--- Whether the guest is still answering. A reboot ends the VM rather
--- than starting a second boot: provium runs QEMU with `-no-reboot`, so a
--- guest reset exits the VMM, and "the machine went down" is the shape
--- the assertion has to take.
local function still_up()
    local ok, result = pcall(function() return vm:run("true") end)
    return ok and result.exit_code == 0
end

test("a Normal service exhausting its budget stays Failed and starts its handler",
    {
        spec = {
            "peinit *restart.errorcontrol-normal-leaves-the-service-failed",
            "peinit *cause.onfailure-fires-for-a-non-critical-budget-exhaustion",
        },
    },
    function(t)
        -- The same failure the Critical case uses, under the default
        -- ErrorControl. It also fixes what a handler start looks like on
        -- this console, so its absence in the next test means something.
        vm:run("svctl --json --no-wait start pt-cr-normal"):assert_ok()
        vm:console():expect("peinit: service pt-cr-normal failed: RestartBudgetExhausted",
            peinit.STAGE_TIMEOUT)
        vm:console():expect("peinit: service pt-cr-normalh started", peinit.STAGE_TIMEOUT)
        t:assert_eq(vm:run("svctl --json status pt-cr-normal").stdout:match('"state":"(%w+)"'),
            "failed", "a Normal service stays Failed rather than costing the machine")
        t:assert(still_up(), "and the machine is still running")
    end)

test("a Critical service exhausting its budget on startup failures reboots the machine",
    {
        spec = {
            "peinit *restart.errorcontrol-critical-syncs-and-reboots",
            "peinit *restart.a-budget-exhausted-by-startup-failures-still-reboots-a-critical-service",
            "peinit *cause.a-critical-budget-exhaustion-starts-no-handler",
        },
    },
    function(t)
        -- Last in the file: the asserted outcome ends the VM.
        vm:run("svctl --json --no-wait start pt-cr-boom"):assert_ok()

        -- The precondition, first: the budget really did run out, so
        -- what follows is about the escalation rather than about the
        -- service never getting there. Guarded, because the machine may
        -- go down underneath the poll -- which is the outcome wanted.
        local settled
        pcall(function()
            settled = wait_until(function()
                local out = vm:run("svctl --json status pt-cr-boom")
                return out.exit_code == 0
                    and out.stdout:find('"cause":"restart_budget_exhausted"', 1, true)
                    and out.stdout or nil
            end, { timeout = 45, interval = 0.5, desc = "pt-cr-boom to run out of budget" })
        end)

        -- The reboot takes precedence over OnFailure, so the handler
        -- must not have run either. Read before the wait below, while
        -- the console log is certainly complete.
        local log = vm:console():read_log()
        t:assert(log:find("peinit: service pt-cr-normalh started", 1, true),
            "the Normal service's handler ran, so a handler start is visible here")
        t:assert(not log:find("peinit: service pt-cr-boomh started", 1, true),
            "and the Critical service's handler did not run")

        local down = false
        for _ = 1, 45 do
            if not still_up() then
                down = true
                break
            end
            pcall(function() vm:run("sleep 1") end)
        end
        t:assert(down,
            "peinit synced and rebooted for its Critical service; instead the machine " ..
            "is still up with the service at " .. tostring(settled))
    end)
