-- peinit TRM §6.4 — the restart policies: which failures reach the
-- restart evaluation, and what each policy does with one.
--
-- Every service here is built so that the only variable is the policy or
-- the exit code. `pt-rs-never` and `pt-rs-onfailure` run the same
-- process; `pt-rs-successcode` and `pt-rs-failcode` differ by one digit
-- in the code they exit with. What the assertions read is the pair
-- (state, cause) out of `svctl --json status`: Failed with
-- `process_crash` is a policy declining to restart, Failed with
-- `restart_budget_exhausted` is a budget running out, and those are the
-- two outcomes the pseudocode in §6.4 distinguishes.
--
-- The counting services stamp `/run` on every launch, because how many
-- times a service was started is not a question the control interface
-- answers and a restart that has already happened leaves no other trace.

local peinit = require("helpers.peinit")
peinit.claim(1)

local FILES = {
    -- Stamps its launch and then refuses to become ready, so the only
    -- thing that can end the activation is StartTimeout.
    ["pt/rs-hang.sh"] = [[
/bin/date +%s >> /run/pt-rs-hang.log
/bin/sleep 300
]],
    -- Runs once and succeeds, counting itself.
    ["pt/rs-once.sh"] = [[
/bin/date +%s >> /run/pt-rs-once.log
exit 0
]],
    -- Stamps its launch and crashes: the ordinary restart-eligible
    -- failure, counted the same way.
    ["pt/rs-spend.sh"] = [[
/bin/date +%s >> /run/pt-rs-spend.log
exit 1
]],
}

local function service(name, values)
    local base = {
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 0 },
        { name = "Triggers", type = "multi", data = { "boot" } },
    }
    for _, value in ipairs(values) do base[#base + 1] = value end
    return { path = [[Machine\System\Services\]] .. name, values = base }
end

local FALSE = { name = "ImagePath", type = "sz", data = "/bin/false" }

--- `/bin/sh -c "exit N"`, so a definition can choose its exit code.
local function exits(code)
    return {
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi", data = { "-c", "exit " .. code } },
    }
end

local function with(values, extra)
    local out = {}
    for _, value in ipairs(values) do out[#out + 1] = value end
    for _, value in ipairs(extra) do out[#out + 1] = value end
    return out
end

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },

    -- Never. The process fails; the policy declines.
    service("pt-rs-never", {
        FALSE,
        { name = "RestartPolicy", type = "dword", data = 0 },
    }),

    -- OnFailure, same process. The only difference from pt-rs-never is
    -- the policy dword, so a different outcome is the policy's doing.
    service("pt-rs-onfailure", {
        FALSE,
        { name = "RestartPolicy", type = "dword", data = 1 },
        { name = "RestartDelay", type = "dword", data = 30 },
        { name = "RestartMaxRetries", type = "dword", data = 5 },
    }),

    -- OnFailure with the exit code listed as a success. The exit is
    -- before readiness -- Readiness is Notify and the process never
    -- notifies -- so this is also the pre-readiness half of the
    -- SuccessExitCodes rule.
    service("pt-rs-successcode", with(exits(3), {
        { name = "RestartPolicy", type = "dword", data = 1 },
        { name = "SuccessExitCodes", type = "multi", data = { "3" } },
        { name = "RestartDelay", type = "dword", data = 30 },
        { name = "RestartMaxRetries", type = "dword", data = 5 },
    })),

    -- The same definition exiting with a code that is not listed.
    service("pt-rs-failcode", with(exits(4), {
        { name = "RestartPolicy", type = "dword", data = 1 },
        { name = "SuccessExitCodes", type = "multi", data = { "3" } },
        { name = "RestartDelay", type = "dword", data = 30 },
        { name = "RestartMaxRetries", type = "dword", data = 5 },
    })),

    -- Always, and the exit code is one SuccessExitCodes lists. Always
    -- restarts regardless of the code, so the list must not save it.
    service("pt-rs-alwayscode", with(exits(3), {
        { name = "RestartPolicy", type = "dword", data = 2 },
        { name = "SuccessExitCodes", type = "multi", data = { "3" } },
        { name = "RestartDelay", type = "dword", data = 30 },
        { name = "RestartMaxRetries", type = "dword", data = 5 },
    })),

    -- A Oneshot under Always that succeeds. It counts its own launches,
    -- because "was not restarted" is a claim about how many times it
    -- ran.
    service("pt-rs-oneshot", {
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi", data = { "/pt/rs-once.sh" } },
        { name = "Type", type = "dword", data = 1 },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 2 },
        { name = "RestartDelay", type = "dword", data = 1 },
        { name = "RestartMaxRetries", type = "dword", data = 5 },
    }),

    -- A service that never becomes ready, with a three-second
    -- StartTimeout and a one-second backoff. Each launch stamps the
    -- clock, so the gaps say whether each activation got a full
    -- StartTimeout of its own. Its SuccessExitCodes cannot save it: a
    -- readiness deadline carries no exit code.
    service("pt-rs-hang", {
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi", data = { "/pt/rs-hang.sh" } },
        { name = "StartTimeout", type = "dword", data = 3 },
        { name = "RestartPolicy", type = "dword", data = 1 },
        { name = "SuccessExitCodes", type = "multi", data = { "0", "1", "2", "3" } },
        { name = "RestartDelay", type = "dword", data = 1 },
        { name = "RestartMaxRetries", type = "dword", data = 4 },
        { name = "RestartWindow", type = "dword", data = 120 },
    }),

    -- The same budget question on the ordinary path: a process that
    -- exits non-zero at once, with three retries and a one-second
    -- delay. It stamps every launch, so the number of restarts the
    -- budget bought is countable.
    service("pt-rs-spend", {
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi", data = { "/pt/rs-spend.sh" } },
        { name = "RestartPolicy", type = "dword", data = 2 },
        { name = "RestartDelay", type = "dword", data = 1 },
        { name = "RestartMaxRetries", type = "dword", data = 3 },
        { name = "RestartWindow", type = "dword", data = 120 },
    }),
}

local vm = peinit.boot({
    name = "restart",
    files = peinit.merge(FILES, peinit.seed("pt-restart", SERVICES)),
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
    for _, line in ipairs(peinit.lines(text)) do
        out[#out + 1] = tonumber(line)
    end
    return out
end

test("RestartPolicy=Never leaves a failed service Failed, and OnFailure restarts the same process",
    { spec = "peinit *restart.the-three-policies" },
    function(t)
        -- Two definitions running `/bin/false`, differing in one dword.
        local never = settle("pt-rs-never", "failed", "pt-rs-never to give up")
        t:assert_eq(never.cause, "process_crash",
            "the policy declined, so the cause is still the crash rather than a budget")

        local onfailure = settle("pt-rs-onfailure", "backoff",
            "pt-rs-onfailure to be scheduled for another go")
        t:assert_eq(onfailure.cause, "process_crash",
            "and the restart-eligible one is on the restart path with the same cause")

        -- Never means never: nothing moves it afterwards.
        vm:run("sleep 3")
        t:assert_eq(status("pt-rs-never").state, "failed",
            "the Never service is still Failed three seconds later")
    end)

test("an exit code in SuccessExitCodes is not a failure under OnFailure, on either side of readiness",
    {
        spec = {
            "peinit *restart.the-three-policies",
            "peinit *restart.successexitcodes-applies-to-a-pre-readiness-exit-too",
        },
    },
    function(t)
        -- Readiness is Notify and neither process notifies, so both
        -- exits were observed from Starting -- before readiness. The
        -- listed code is still treated as a success there.
        local listed = settle("pt-rs-successcode", "failed",
            "pt-rs-successcode to settle")
        t:assert_eq(listed.cause, "process_crash",
            "the exit was observed as a process exit")
        vm:run("sleep 2")
        t:assert_eq(status("pt-rs-successcode").state, "failed",
            "and a listed exit code was not restarted")

        -- One digit different, and the same definition restarts.
        local unlisted = settle("pt-rs-failcode", "backoff",
            "pt-rs-failcode to be restarted")
        t:assert_eq(unlisted.cause, "process_crash",
            "an unlisted code is an ordinary crash: " .. tostring(unlisted.cause))
    end)

test("Always restarts regardless of the exit code, SuccessExitCodes included",
    { spec = "peinit *restart.the-three-policies" },
    function(t)
        -- pt-rs-alwayscode exits with a code its own SuccessExitCodes
        -- lists. Under OnFailure that stops the restart -- pt-rs-successcode
        -- beside it proves so -- and under Always it does not.
        local view = settle("pt-rs-alwayscode", "backoff",
            "pt-rs-alwayscode to be restarted anyway")
        t:assert_eq(view.cause, "process_crash",
            "the code SuccessExitCodes lists did not reach the policy under Always")
    end)

test("a Oneshot that succeeds is not restarted, whatever RestartPolicy says",
    { spec = "peinit *restart.a-oneshot-that-succeeds-is-not-restarted-whatever-the-policy" },
    function(t)
        -- RestartPolicy=Always and a one-second delay: if a successful
        -- Oneshot were restart-eligible, the counter would climb once a
        -- second for as long as this file runs.
        wait_until(function() return #stamps("/run/pt-rs-once.log") >= 1 end,
            { timeout = 60, interval = 0.5, desc = "pt-rs-oneshot to run" })
        local view = settle("pt-rs-oneshot", "inactive",
            "pt-rs-oneshot to finish")
        t:assert_eq(view.cause, "clean_exit",
            "it left Completed under a clean exit rather than a restart")

        vm:run("sleep 5")
        t:assert_eq(#stamps("/run/pt-rs-once.log"), 1,
            "five seconds and a one-second delay later it has still run exactly once")
        t:assert_eq(status("pt-rs-oneshot").state, "inactive",
            "and it is Inactive rather than cycling")
    end)

test("each relaunch gets a fresh StartTimeout, and a readiness deadline carries no exit code",
    {
        spec = {
            "peinit *restart.a-relaunch-gets-a-fresh-starttimeout",
            "peinit *restart.a-failure-with-no-exit-code-cannot-match-successexitcodes",
        },
    },
    function(t)
        -- The process never becomes ready, so every activation ends at
        -- StartTimeout: three seconds of it, plus one second of backoff.
        -- An activation that inherited the previous one's deadline would
        -- end the moment it began, and the stamps would be a second
        -- apart rather than four.
        local launches = wait_until(function()
            local seen = stamps("/run/pt-rs-hang.log")
            return #seen >= 3 and seen or nil
        end, { timeout = 120, interval = 0.5, desc = "three activations of pt-rs-hang" })

        for index = 2, #launches do
            local gap = launches[index] - launches[index - 1]
            t:assert(gap >= 3,
                "activation " .. index .. " began " .. gap .. "s after the last, which is " ..
                "at least the StartTimeout it was given afresh")
        end

        -- And it was restarted at all, despite SuccessExitCodes listing
        -- 0 through 3: the readiness deadline is not a process exit, so
        -- there is no code for the list to match.
        t:assert(#launches >= 3,
            "a readiness timeout reached the restart evaluation " .. #launches ..
            " times without SuccessExitCodes excusing it")
    end)

test("exhausting the budget is Failed with RestartBudgetExhausted, and Normal leaves it there",
    {
        spec = {
            "peinit *restart.exhaustion-is-failed-with-restartbudgetexhausted",
            "peinit *restart.errorcontrol-normal-leaves-the-service-failed",
        },
    },
    function(t)
        -- pt-rs-spend has three retries and no ErrorControl, so it
        -- defaults to Normal. After the third restart the next failure
        -- is not restarted.
        local view = settle("pt-rs-spend", "failed",
            "pt-rs-spend to spend its budget")
        t:assert_eq(view.cause, "restart_budget_exhausted",
            "the cause names the budget rather than the failure that spent it")
        t:assert_eq(#stamps("/run/pt-rs-spend.log"), 4,
            "one activation plus three restarts, and then no more")

        -- Normal: it stays there. The machine is still up, which is the
        -- whole difference from Critical.
        vm:run("sleep 6")
        local after = status("pt-rs-spend")
        t:assert_eq(after.state, "failed", "it is still Failed")
        t:assert_eq(#stamps("/run/pt-rs-spend.log"), 4,
            "and was not started again")
        t:assert_eq(vm:run("svctl list").exit_code, 0,
            "while peinit is still running the machine")
    end)

test("a budget spent on readiness timeouts buys RestartMaxRetries restarts too",
    {
        spec = "peinit *restart.exhaustion-is-failed-with-restartbudgetexhausted",
        -- PEI-822: a readiness timeout costs two of the budget rather
        -- than one, so a service configured for four retries is given
        -- two.
        tags = { "known-bug" },
    },
    function(t)
        -- pt-rs-hang is configured for four retries and never becomes
        -- ready, so it should be activated five times before its budget
        -- runs out -- the same arithmetic pt-rs-spend gets on the
        -- ordinary crash path, applied to a different eligible cause.
        local view = settle("pt-rs-hang", "failed",
            "pt-rs-hang to spend its budget")
        t:assert_eq(view.cause, "restart_budget_exhausted",
            "the budget is what ended it")
        t:assert_eq(#stamps("/run/pt-rs-hang.log"), 5,
            "one activation plus four restarts")
    end)
