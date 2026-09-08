-- peinit TRM §12.2 — submitted jobs in a shutdown: they are all stopped
-- when it begins, `submit` is refused for the rest of it, the other job
-- commands keep answering, and the sequence does not finish while one is
-- still alive.
--
-- Every job here is one that ignores SIGTERM. That is what makes any of
-- this observable: a job that dies on the signal is gone before a test
-- can ask about it, whereas one that does not is still there to be
-- questioned, still carrying the cause peinit stopped it with, and still
-- holding the shutdown open while the questions are asked.
--
-- PEI-811 is the hazard here: under load a shutdown's jobs socket has
-- once been seen gone before any submit was refused. The window in each
-- test is held open by a service with a long StopTimeout rather than by
-- luck, which is the best defence available from this side.

local peinit = require("helpers.peinit")
peinit.claim(1)

-- A job that traps SIGTERM and keeps running. Short sleeps in a loop
-- rather than one long one, so the shell — which is what holds the trap
-- — is the process that survives the signal.
local IGNORES_TERM =
    [[/bin/sh -c "trap '' TERM; while :; do sleep 1; done"]]

local function with_vm(opts, body)
    local vm = peinit.boot(opts)
    local ok, err = pcall(body, vm)
    pcall(function() vm:shutdown() end)
    if not ok then error(err, 0) end
end

local function states(vm)
    local out, any = {}, false
    for name, state in vm:run("svctl --json list").stdout
        :gmatch('"service":"([^"]+)","state":"([^"]+)"') do
        out[name] = state
        any = true
    end
    assert(any, "svctl list answered with no services")
    return out
end

local function settle(vm)
    wait_until(function()
        for name, state in pairs(states(vm)) do
            if state == "starting" and not name:find("^pt%-") then return false end
        end
        return true
    end, { timeout = 60, interval = 0.5, desc = "the image's own services to settle" })
end

local function pause(seconds)
    pcall(wait_until, function() return false end,
        { timeout = seconds, interval = 0.25, desc = "a fixed pause" })
end

local function trigger(vm, command)
    pcall(function() vm:run(command, { timeout = 30 }) end)
end

local function submit(vm, stop_timeout)
    local r = vm:run("svctl --json job submit --stop-timeout " .. stop_timeout ..
        " " .. IGNORES_TERM)
    r:assert_ok()
    local id = r.stdout:match('"id":"([^"]+)"')
    assert(id, "no job identifier in: " .. r.stdout)
    return id
end

local function stubborn(stop_timeout)
    return {
        path = [[Machine\System\Services\pt-stubborn]],
        values = {
            { name = "ImagePath", type = "sz", data = "/bin/sh" },
            { name = "Arguments", type = "multi",
              data = { "-c", "trap '' TERM; while :; do sleep 1; done" } },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
            { name = "StopTimeout", type = "dword", data = stop_timeout },
            { name = "RestartPolicy", type = "dword", data = 0 },
            { name = "Triggers", type = "multi", data = { "boot" } },
        },
    }
end

local function holding_seed()
    return peinit.seed("pt-jobs", {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
        stubborn(40),
    })
end

test("every live submitted job is stopped with cause shutdown when the shutdown begins",
    { spec = "peinit *graceful.every-live-submitted-job-is-stopped-at-once" },
    function(t)
        with_vm({
            name = "jobstop",
            append = "peios.quiet=0",
            files = holding_seed(),
        }, function(vm)
            settle(vm)
            local id = submit(vm, 40)
            t:assert_eq(vm:run("svctl --json job status " .. id).stdout
                :match('"state":"([^"]+)"'), "running",
                "the job is running before the shutdown")

            trigger(vm, "svctl shutdown poweroff")
            vm:console():expect("peinit: shutdown stopping pt-stubborn", 30)

            -- The job ignored the SIGTERM, so it is still there to be
            -- asked — and it now carries the cause peinit stopped it
            -- with, which is what a stop at the start of a shutdown
            -- looks like from the outside.
            local view = vm:run("svctl --json job status " .. id)
            view:assert_ok()
            t:assert_eq(view.stdout:match('"cause":"([^"]+)"'), "shutdown",
                "the job was stopped with cause `shutdown`: " .. view.stdout)
        end)
    end)

test("submit is refused for the rest of the shutdown while the other job commands keep answering",
    { spec = "peinit *graceful.submit-is-refused-while-the-other-job-commands-keep-answering" },
    function(t)
        with_vm({
            name = "jobgate",
            append = "peios.quiet=0",
            files = holding_seed(),
        }, function(vm)
            settle(vm)
            local id = submit(vm, 40)

            trigger(vm, "svctl shutdown poweroff")
            vm:console():expect("peinit: shutdown stopping pt-stubborn", 30)

            local refused = vm:run("svctl --json job submit /bin/true")
            t:assert_eq(refused.stdout:match('"code":"([^"]+)"'), "INVALID_STATE",
                "a submit during the shutdown is refused as invalid for the state: "
                .. refused.stdout .. refused.stderr)

            -- The read-only half of the jobs vocabulary is unaffected,
            -- and so is `stop`: an administrator watching a shutdown
            -- take its jobs down has a reason to ask, and to hurry one
            -- along.
            for _, command in ipairs({
                "job list",
                "job status " .. id,
                "job stop --no-wait " .. id,
            }) do
                local r = vm:run("svctl --json " .. command)
                t:assert(not r.stdout:find("INVALID_STATE", 1, true),
                    "`" .. command .. "` was not refused by the shutdown gate: " .. r.stdout)
            end
        end)
    end)

test("the sequence does not reach its final action while a submitted job is live",
    { spec = "peinit *graceful.step-6-waits-for-every-live-submitted-job" },
    function(t)
        -- No service holds this one open: the image's own graph stops in
        -- a few seconds, and the only thing left is a job that ignores
        -- SIGTERM and has been given twenty-five seconds to reconsider.
        -- If a live job did not hold the sequence, the machine would be
        -- gone long before that.
        with_vm({ name = "jobhold", append = "peios.quiet=0" }, function(vm)
            settle(vm)
            submit(vm, 25)

            trigger(vm, "svctl shutdown poweroff")
            vm:console():expect("peinit: shutdown Poweroff started", 30)
            pause(12)
            t:assert(not vm:console():read_log():find("reboot: Power down", 1, true),
                "twelve seconds in, with every service stopped, the shutdown was " ..
                "still waiting on the job")

            vm:console():expect("reboot: Power down", 60)
            t:assert(true, "and finished once the job's own stop_timeout had run out")
        end)
    end)

test("the global timeout sweep kills a live job too",
    { spec = "peinit *graceful.the-global-timeout-sweep-kills-live-jobs-too" },
    function(t)
        -- A job whose stop_timeout is ten minutes and a ShutdownTimeout
        -- of six seconds. Only the global sweep can end this: if it did
        -- not reach submitted jobs, the sequence would sit on the job's
        -- own deadline and the machine would still be up when the test
        -- gave up.
        with_vm({
            name = "jobsweep",
            append = "peios.quiet=0",
            files = peinit.seed("pt-jobsweep", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Boot]], values = {
                    { name = "ShutdownTimeout", type = "dword", data = 6 },
                    { name = "PostKillTimeout", type = "dword", data = 1 },
                } },
            }),
        }, function(vm)
            settle(vm)
            submit(vm, 600)

            -- The bounds are generous because they only have to fail a
            -- sweep that never comes: if the sweep did not reach
            -- submitted jobs the sequence would sit on the job's own
            -- ten-minute deadline, which no bound here could reach. What
            -- they must not do is call a slow sweep a missing one, and
            -- at thirty seconds they did that on a loaded host.
            trigger(vm, "svctl shutdown poweroff")
            vm:console():expect("peinit: shutdown Poweroff started", 60)
            vm:console():expect("peinit: shutdown global timeout expired", 120)
            vm:console():expect("reboot: Power down", 120)
            t:assert(true, "the sweep killed the job and the shutdown finished")
        end)
    end)
