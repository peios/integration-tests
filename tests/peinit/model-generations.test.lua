-- peinit TRM §3.7 — configuration generations: peinit works from a
-- snapshot, and a registry write reaches a service at a moment that
-- depends on which field it touched and on what the service is doing.
--
-- §10.4 already owns reload-config as a command, and its anchors cover
-- a new service becoming startable and a running one keeping its
-- process. What §3.7 adds, and what this file is, is the *classes*: a
-- pinned field and a runtime-reloaded field on the same running
-- service, changed in the same read, must land at different moments,
-- and that difference is the claim.
--
-- Two of the subjects are timed rather than staged. `pt-starting` is a
-- service that never becomes ready, so it can be caught mid-start and
-- its start timeout changed under it; `pt-secs` in `model-formats`
-- established that such a timeout is really seconds, so what is
-- measured here is only which of the two values was used.
--
-- The last test stops registryd's process with SIGSTOP rather than
-- stopping the service. peinit still believes registryd is running, so
-- nothing is restarted and nothing about the graph changes -- the only
-- thing that has changed is that a registry read would now block
-- forever, which is precisely the condition §3.7's note says the model
-- exists to survive.

local peinit = require("helpers.peinit")
peinit.claim(1)

local FILES = {
    -- A main process that stays up without being /bin/sleep, so that
    -- `readlink /proc/PID/exe` can tell one generation's ImagePath from
    -- another's.
    ["pt/idle.sh"] = "while true; do /bin/sleep 1; done\n",
    -- Rewrites a later service's definition from inside the boot, in
    -- the window where the plan is fixed but the service has not
    -- started.
    ["pt/rewrite.sh"] = [[
reg set 'Machine\System\Services\pt-late' Arguments 'multi:222222'
/bin/sleep 3
]],
    -- One line per run, for the timer-arming claim.
    ["pt/tick.sh"] = 'echo tick >> "/run/pt-tick-$1"\n',
}

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },
}

local function service(name, values)
    SERVICES[#SERVICES + 1] =
        { path = [[Machine\System\Services\]] .. name, values = values }
end

--- A SYSTEM daemon that is ready by existing.
local function daemon(name, extra)
    local values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "100000" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
    }
    for _, value in ipairs(extra) do
        local replaced = false
        for i, existing in ipairs(values) do
            if existing.name:lower() == value.name:lower() then
                values[i] = value
                replaced = true
                break
            end
        end
        if not replaced then values[#values + 1] = value end
    end
    service(name, values)
end

-- The boot-window write. pt-writer rewrites pt-late's Arguments and
-- then lingers; pt-late requires it, so it is still unstarted when the
-- write lands.
service("pt-writer", {
    { name = "ImagePath", type = "sz", data = "/bin/sh" },
    { name = "Arguments", type = "multi", data = { "/pt/rewrite.sh" } },
    { name = "Identity", type = "sz", data = "SYSTEM" },
    { name = "Type", type = "dword", data = 1 },
    { name = "RemainAfterExit", type = "dword", data = 1 },
    { name = "StartTimeout", type = "dword", data = 60 },
    { name = "Triggers", type = "multi", data = { "boot" } },
})
daemon("pt-late", {
    { name = "Arguments", type = "multi", data = { "111111" } },
    { name = "Requires", type = "multi", data = { "pt-writer" } },
    { name = "Triggers", type = "multi", data = { "boot" } },
})

-- Running subjects for the mutability classes.
daemon("pt-pinned", { { name = "Triggers", type = "multi", data = { "boot" } } })
daemon("pt-next", { { name = "Triggers", type = "multi", data = { "boot" } } })
-- `RestartPolicy` is the reloaded-at-runtime field with the sharpest
-- observable: its next relevant event is the next time the main process
-- goes away, and whether the service comes back says which value was in
-- force. Both start at Never; only one of them is changed.
daemon("pt-runtime", { { name = "Triggers", type = "multi", data = { "boot" } } })
daemon("pt-runtime-ctl", { { name = "Triggers", type = "multi", data = { "boot" } } })

-- Never becomes ready, so it can be caught while Starting.
service("pt-starting", {
    { name = "ImagePath", type = "sz", data = "/bin/sleep" },
    { name = "Arguments", type = "multi", data = { "300" } },
    { name = "Identity", type = "sz", data = "SYSTEM" },
    { name = "StartTimeout", type = "dword", data = 12 },
    { name = "RestartPolicy", type = "dword", data = 0 },
})

-- Inactive subjects: what a start reads out of the model.
daemon("pt-inactive", { { name = "Arguments", type = "multi", data = { "111111" } } })
daemon("pt-dep-target", {})
daemon("pt-dep-source", {})

-- A ticker with no trigger at all, for the "arms a timer added to an
-- inactive service" claim.
service("pt-arm", {
    { name = "ImagePath", type = "sz", data = "/bin/sh" },
    { name = "Arguments", type = "multi", data = { "/pt/tick.sh", "pt-arm" } },
    { name = "Identity", type = "sz", data = "SYSTEM" },
    { name = "Type", type = "dword", data = 1 },
})

-- A demand-only service whose global environment is read at its start.
daemon("pt-env", {})

local vm = peinit.boot({
    name = "generations",
    files = peinit.merge(FILES, peinit.seed("pt-generations", SERVICES)),
})

local function status(service_name)
    local r = vm:run("svctl --json status " .. service_name)
    if r.stdout:find("UNKNOWN_SERVICE", 1, true) then return nil end
    local ok, decoded = pcall(json.decode, r.stdout)
    return ok and decoded or nil
end

local function pid_of(service_name)
    local st = status(service_name)
    return st and st.current_job and st.current_job.pid or nil
end

local function await(service_name, state, timeout)
    return wait_until(function()
        local st = status(service_name)
        return st and st.state == state and st or nil
    end, {
        timeout = timeout or 90, interval = 0.4,
        desc = service_name .. " to reach " .. state,
    })
end

local function cmdline(pid)
    return (vm:read_file("/proc/" .. tostring(pid) .. "/cmdline"):gsub("%z", " "))
end

--- argv[0] of a running process: the path peinit handed to `execve`.
---
--- `/proc/PID/exe` is not the oracle here. The image's `/bin/sleep` is a
--- link into a multi-call binary, so `readlink` on it answers
--- `/bin/peiosutils` for every one of them and cannot tell one
--- `ImagePath` from another. argv[0] is the string peinit exec'd, which
--- is exactly the field under test.
local function argv0(pid)
    return (cmdline(pid):match("^(%S+)") or "")
end

test("a registry write during the boot window reaches a service that has not started yet",
    {
        spec = "peinit *confgen.a-write-during-the-boot-window-reaches-a-not-yet-started-service",
        -- PEI-834: the Phase 2 boot context is built from a snapshot of
        -- every definition taken when the plan was fixed, and a
        -- boot-plan service released later starts from that snapshot.
        -- The reload the write triggers updates the model but not the
        -- context, so a boot-plan service that has not started yet
        -- starts on the old definition.
        tags = { "known-bug" },
    },
    function(t)
        -- The watches are armed as the event loop starts: after the plan
        -- is fixed, but while the boot-plan services are still starting.
        -- pt-writer runs inside that window and rewrites pt-late's
        -- Arguments; pt-late requires pt-writer, so it is still waiting
        -- when the write lands and the reload it triggers is processed.
        --
        -- The argument vector is fixed at exec, so /proc says which
        -- generation the process that eventually started belongs to.
        await("pt-writer", "completed")
        local late = await("pt-late", "active")
        local pid = late.current_job and late.current_job.pid
        t:assert(pid, "pt-late started")
        local at_boot = cmdline(pid)

        -- First, the premise, so that a failure below is about *when*
        -- the write landed rather than about whether it happened. The
        -- registry holds the new arguments and a restart picks them up,
        -- so the write and the reload it triggered both worked.
        local written = vm:run([[reg get 'Machine\System\Services\pt-late' Arguments]])
        written:assert_ok()
        t:assert(written.stdout:find("222222", 1, true),
            "the write during the boot window reached the registry: " ..
            written.stdout)
        vm:run("svctl --json restart pt-late"):assert_ok()
        local after = await("pt-late", "active")
        t:assert(cmdline(after.current_job.pid):find("222222", 1, true),
            "and the model has it, since a restart starts on it: " ..
            cmdline(after.current_job.pid))

        -- And the claim itself: the service had not started when the
        -- write landed, so its own start should have used it.
        t:assert(at_boot:find("222222", 1, true),
            "the boot start used the definition written during the boot rather " ..
            "than the one the plan was built from: " .. at_boot)
    end)

test("a pinned field takes effect only when the service is restarted",
    { spec = "peinit *confgen.the-pinned-fields" },
    function(t)
        -- `ImagePath` is pinned to the running definition. Changing it
        -- under a running service changes nothing about that service
        -- until it is started again -- which is the difference between
        -- this class and the reloaded-at-runtime one below, on the same
        -- machine and in the same reload.
        local before = await("pt-pinned", "active")
        local pid = before.current_job.pid
        t:assert_eq(argv0(pid), "/bin/sleep", "it is running /bin/sleep")

        vm:run([[reg set 'Machine\System\Services\pt-pinned' ImagePath 'sz:/bin/sh']])
            :assert_ok()
        vm:run([[reg set 'Machine\System\Services\pt-pinned' Arguments ]] ..
            [['multi:/pt/idle.sh']]):assert_ok()
        vm:run("svctl --json reload-config"):assert_ok()

        t:assert_eq(pid_of("pt-pinned"), pid,
            "the reload did not disturb the running process")
        t:assert_eq(argv0(pid), "/bin/sleep",
            "which is still the binary the pinned definition named")

        -- And the restart is when it lands.
        vm:run("svctl --json restart pt-pinned"):assert_ok()
        local after = await("pt-pinned", "active")
        local new_pid = after.current_job.pid
        t:assert(new_pid ~= pid, "the restart made a new process")
        t:assert_eq(argv0(new_pid), "/bin/sh",
            "running the ImagePath the change named: " .. cmdline(new_pid))
    end)

test("a next-start field changes nothing while the service runs, and applies at the next start",
    { spec = "peinit *confgen.the-next-start-fields" },
    function(t)
        -- `Conditions` is in the applied-on-the-next-start class. Adding
        -- one that does not hold to a running service must not skip it
        -- where it stands: the checks belong to a start, and this
        -- service is past its own.
        local before = await("pt-runtime", "active")
        local runtime_pid = before.current_job.pid

        local pinned = await("pt-next", "active")
        local pid = pinned.current_job.pid

        vm:run([[reg set 'Machine\System\Services\pt-next' Conditions ]] ..
            [['multi:path:/pt-absent']]):assert_ok()
        vm:run("svctl --json reload-config"):assert_ok()

        local still = status("pt-next")
        t:assert_eq(still.state, "active",
            "a condition that does not hold did not skip a running service: " ..
            tostring(still.state))
        t:assert_eq(pid_of("pt-next"), pid, "which kept its process")

        -- And it is the next start that evaluates it.
        vm:run("svctl --json restart pt-next")
        local after = wait_until(function()
            local st = status("pt-next")
            return st and st.state ~= "active" and st.state ~= "starting" and st or nil
        end, { timeout = 90, interval = 0.4, desc = "pt-next to be re-evaluated" })
        t:assert_eq(after.state, "skipped",
            "the restart evaluated the condition and skipped the service: " ..
            tostring(after.state))
        t:assert_eq(after.cause, "condition_skipped", "on the condition")

        -- pt-runtime is untouched by all of that, and is the subject of
        -- the next test.
        t:assert_eq(pid_of("pt-runtime"), runtime_pid,
            "the other running service was not disturbed either")
    end)

test("a runtime-reloaded field takes effect at the next relevant event, with no restart",
    { spec = "peinit *confgen.the-runtime-reloaded-fields" },
    function(t)
        -- `RestartPolicy` is in the reloaded-at-runtime class. Its next
        -- relevant event is the next time the main process goes away,
        -- and what happens then says which value was in force -- so the
        -- change can be shown to have landed without the service having
        -- been restarted to pick it up, which is the whole distinction
        -- from the two classes above.
        --
        -- pt-runtime and pt-runtime-ctl are the same definition, both
        -- seeded RestartPolicy=Never. Only one of them is changed.
        local before = await("pt-runtime", "active")
        local pid = before.current_job.pid
        local control = await("pt-runtime-ctl", "active")
        local control_pid = control.current_job.pid

        vm:run([[reg set 'Machine\System\Services\pt-runtime' RestartPolicy ]] ..
            [['dword:2']]):assert_ok()
        vm:run("svctl --json reload-config"):assert_ok()

        -- Nothing was restarted by the reload itself.
        t:assert_eq(pid_of("pt-runtime"), pid,
            "the reload left the running process alone")

        -- Now the relevant event. The service comes back, on a policy it
        -- was never restarted to acquire.
        vm:run("kill -9 " .. tostring(pid))
        local restarted = wait_until(function()
            local st = status("pt-runtime")
            local now = st and st.current_job and st.current_job.pid
            return now and now ~= pid and st or nil
        end, { timeout = 90, interval = 0.4,
               desc = "pt-runtime to restart on its reloaded policy" })
        t:assert_eq(restarted.state, "active",
            "the changed RestartPolicy was in force at the next relevant event")

        -- And the control, whose policy was not changed, does not come
        -- back from the identical kill.
        vm:run("kill -9 " .. tostring(control_pid))
        local stopped = wait_until(function()
            local st = status("pt-runtime-ctl")
            return st and st.state ~= "active" and st or nil
        end, { timeout = 90, interval = 0.4, desc = "pt-runtime-ctl to fail" })
        t:assert_eq(stopped.state, "failed",
            "the service still on RestartPolicy=Never stayed down: " ..
            tostring(stopped.state))
    end)

test("a field changed while a service is Starting does not take effect until the next start",
    { spec = "peinit *confgen.a-field-changed-while-starting-takes-effect-at-the-next-start" },
    function(t)
        -- peinit snapshots a service's definition when it starts it, and
        -- the snapshot governs the whole start lifecycle -- including
        -- the readiness timeout. pt-starting never notifies, so it is
        -- reliably Starting for twelve seconds, which is long enough to
        -- change its StartTimeout to ten minutes underneath it.
        --
        -- If the change applied to the start in flight the service would
        -- still be Starting when this test gave up. It fails on the
        -- twelve it was started with.
        vm:run("svctl --json start pt-starting --no-wait")
        await("pt-starting", "starting", 30)

        vm:run([[reg set 'Machine\System\Services\pt-starting' StartTimeout ]] ..
            [['dword:600']]):assert_ok()
        vm:run("svctl --json reload-config"):assert_ok()

        local st = wait_until(function()
            local s = status("pt-starting")
            return s and s.state == "failed" and s or nil
        end, { timeout = 90, interval = 0.5,
               desc = "pt-starting to time out on the generation it started with" })
        t:assert_eq(st.cause, "readiness_timeout",
            "the start in flight kept the timeout it was snapshotted with")

        -- And the change is there for the next start, so the reload did
        -- happen and the value really did move.
        local written = vm:run([[reg get 'Machine\System\Services\pt-starting' StartTimeout]])
        written:assert_ok()
        t:assert(written.stdout:find("600"),
            "the registry holds the new value for the next start: " .. written.stdout)
    end)

test("an inactive service starts from the current model",
    { spec = "peinit *confgen.an-inactive-service-starts-from-the-current-model" },
    function(t)
        -- A service in Inactive has no activation snapshot, so there is
        -- nothing pinned and a start reads whatever the model now says.
        vm:run([[reg set 'Machine\System\Services\pt-inactive' Arguments ]] ..
            [['multi:333333']]):assert_ok()
        vm:run("svctl --json reload-config"):assert_ok()
        vm:run("svctl --json start pt-inactive"):assert_ok()

        local st = await("pt-inactive", "active")
        t:assert(cmdline(st.current_job.pid):find("333333", 1, true),
            "the start used the changed definition: " ..
            cmdline(st.current_job.pid))

        -- A dependency change is the same story, and is the bullet §3.7
        -- calls out: for an inactive service it takes effect at the next
        -- start.
        t:assert(status("pt-dep-target").state == "inactive",
            "the dependency target is not running")
        vm:run([[reg set 'Machine\System\Services\pt-dep-source' Requires ]] ..
            [['multi:pt-dep-target']]):assert_ok()
        vm:run("svctl --json reload-config"):assert_ok()
        vm:run("svctl --json start pt-dep-source"):assert_ok()

        await("pt-dep-source", "active")
        t:assert_eq(await("pt-dep-target", "active").state, "active",
            "the dependency added while the service was inactive was pulled in " ..
            "by its next start")
    end)

test("Triggers and Disabled take effect at once on a service that is not running",
    { spec = "peinit *confgen.triggers-and-disabled-take-effect-at-once-on-a-service-that-is-not-running" },
    function(t)
        -- The exception to the pinned class. pt-arm has no trigger at
        -- all and has never run. Giving it a timer arms it, without
        -- anything being started or restarted -- which is the sentence's
        -- own example.
        t:assert_eq(status("pt-arm").state, "inactive", "pt-arm has never run")
        t:assert(vm:run("test -e /run/pt-tick-pt-arm").exit_code ~= 0,
            "and has left nothing behind")

        vm:run([[reg set 'Machine\System\Services\pt-arm' Triggers ]] ..
            [['multi:timer:*-*-* *:*:0/2']]):assert_ok()
        vm:run("svctl --json reload-config"):assert_ok()

        wait_until(function()
            return vm:run("test -e /run/pt-tick-pt-arm").exit_code == 0
        end, { timeout = 60, interval = 0.5,
               desc = "the timer added to an inactive service to fire" })

        -- And `Disabled` the same way: set on a service that is not
        -- running, it is in force by the time anything asks. A hard
        -- dependent is what asks -- peinit refuses to start something
        -- that requires a disabled service.
        -- The dependent first: stopping a target out from under a
        -- running dependent is a different question from this one.
        vm:run("svctl --json stop pt-dep-source"):assert_ok()
        vm:run("svctl --json stop pt-dep-target"):assert_ok()
        await("pt-dep-source", "inactive")
        await("pt-dep-target", "inactive")

        vm:run([[reg set 'Machine\System\Services\pt-dep-target' Disabled 'dword:1']])
            :assert_ok()
        vm:run("svctl --json reload-config"):assert_ok()

        -- The evidence is what the start did, not what it answered: a
        -- start whose hard dependency is disabled is blocked, so neither
        -- service runs. The identical start a moment ago -- in the
        -- previous test, with the flag not yet set -- brought both up.
        vm:run("svctl --json start pt-dep-source")
        vm:run("sleep 3")
        t:assert_eq((status("pt-dep-source") or {}).state, "inactive",
            "a start requiring a service disabled a moment ago did not run: " ..
            tostring((status("pt-dep-source") or {}).state))
        t:assert_eq((status("pt-dep-target") or {}).state, "inactive",
            "and the disabled dependency was not pulled in either: " ..
            tostring((status("pt-dep-target") or {}).state))
    end)

test("the watch covers both the services key and the init key",
    { spec = "peinit *confgen.the-watch-covers-services-and-init" },
    function(t)
        -- Nothing below issues a reload-config. Each half is a registry
        -- write and then a question about a peinit that was never told
        -- to look.
        --
        -- The services half: a key that did not exist at boot.
        t:assert(vm:run("svctl --json status pt-watched").stdout
            :find("UNKNOWN_SERVICE", 1, true), "pt-watched does not exist yet")
        local batch = peinit.encode_json({ keys = { {
            path = [[Machine\System\Services\pt-watched]],
            values = {
                { name = "ImagePath", type = "sz", data = "/bin/true" },
                { name = "Type", type = "dword", data = 1 },
            },
        } } })
        vm:run("cat > /tmp/pt-watched.json <<'PT_JSON_EOF'\n" .. batch ..
            "\nPT_JSON_EOF\nreg apply /tmp/pt-watched.json"):assert_ok()
        wait_until(function() return status("pt-watched") ~= nil end,
            { timeout = 60, interval = 0.5,
              desc = "the services watch to deliver a new key" })

        -- The init half. The global environment layer lives under
        -- `Machine\System\Init\EnvVars` and is re-read by the same full
        -- reload any watch event triggers, so a variable written there
        -- reaches the next service to start -- and only if the init key
        -- is watched at all.
        vm:run([[reg new 'Machine\System\Init\EnvVars']])
        vm:run([[reg set 'Machine\System\Init\EnvVars' PT_INIT_WATCH 'sz:seen']])
            :assert_ok()
        -- No reload-config here either: the write is the whole input.
        vm:run("sleep 2")
        vm:run("svctl --json start pt-env"):assert_ok()

        local env = await("pt-env", "active")
        local text = vm:read_file("/proc/" .. tostring(env.current_job.pid) ..
            "/environ"):gsub("%z", "\n")
        t:assert(text:find("PT_INIT_WATCH=seen", 1, true),
            "a write under Machine\\System\\Init reached peinit through the " ..
            "watch, with no reload-config asked for: " .. text)
    end)

test("peinit answers from its in-memory model rather than from the registry",
    { spec = "peinit *confgen.peinit-answers-from-the-model-rather-than-the-registry" },
    function(t)
        -- The registry is read synchronously exactly twice -- at Phase 2
        -- and on a reload-config -- and at all other times peinit works
        -- from the model. The way to show that is to make a registry
        -- read impossible and ask peinit questions anyway.
        --
        -- SIGSTOP rather than `svctl stop registryd`: stopping the
        -- service would be peinit's own doing and would change the
        -- graph. Stopping the *process* changes nothing peinit knows --
        -- registryd is still Active as far as it is concerned -- so the
        -- only difference between before and after is that anything
        -- requiring registryd would now block forever.
        local registryd = pid_of("registryd")
        t:assert(registryd, "registryd is running")

        vm:run("kill -STOP " .. tostring(registryd)):assert_ok()

        -- Every one of these is answered while no registry read could
        -- have completed.
        local list = vm:run("svctl --json list")
        list:assert_ok()
        t:assert(list.stdout:find('"service":"pt-pinned"', 1, true),
            "the whole service list is answered from the model: " .. list.stdout)

        local one = vm:run("svctl --json status pt-pinned")
        one:assert_ok()
        t:assert(one.stdout:find('"service":"pt-pinned"', 1, true),
            "and so is a single service's whole record: " .. one.stdout)
        t:assert(one.stdout:find('"state":"', 1, true),
            "with the state in it, which only the model holds")

        vm:run("kill -CONT " .. tostring(registryd)):assert_ok()
        t:assert_eq(pid_of("registryd"), registryd,
            "and registryd was never disturbed as a service")
    end)
