-- peinit TRM §3.1 — services: what a Simple service's process is, what a
-- Oneshot's readiness means, and why peinit has nothing to say to a
-- daemon that forks away from it.
--
-- Everything here is about a running service rather than about a
-- definition, so it is one boot with a dozen staged definitions rather
-- than the registry probes §3.2–§3.6 are asked with (`model-decode`).
-- The definitions are timed to settle inside a test run: the timeout
-- cases use four- and six-second budgets where a default-configured
-- service would use thirty.
--
-- Two services exist only as controls. `pt-alive` is `pt-notify` with
-- `Readiness=1` and nothing else changed, so the difference between them
-- is the readiness rule and nothing about the binary; `pt-ost-ok` is
-- `pt-ost-sum` with a budget the same work fits inside, so the failure
-- of the other one is about the budget rather than about the work.

local peinit = require("helpers.peinit")
peinit.claim(1)

local FILES = {
    -- A Oneshot that fails with a specific code, for SuccessExitCodes.
    ["pt/exit3.sh"] = "exit 3\n",
    -- Post-hook markers. Two scripts rather than one with an argument,
    -- so that the file that appears says which service put it there.
    ["pt/post-ok.sh"] = "echo ran > /run/pt-post-ok\n",
    ["pt/post-fail.sh"] = "echo ran > /run/pt-post-fail\n",
    -- A daemon that forks and gets out of the way, which is exactly what
    -- §3.1 says peinit does not support.
    ["pt/daemonise.sh"] = "/bin/sleep 100000 &\nexit 0\n",
}

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },
}

local function service(name, values)
    SERVICES[#SERVICES + 1] =
        { path = [[Machine\System\Services\]] .. name, values = values }
end

--- A boot-triggered SYSTEM service, with `extra` merged over the top.
---
--- Merged by value name rather than appended: a key carrying the same
--- value twice is a registry write that overwrites itself, and which of
--- the two survived would depend on `reg apply`'s ordering rather than
--- on what the test meant.
local function boot_service(name, extra)
    local values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "100000" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Triggers", type = "multi", data = { "boot" } },
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

-- A Simple daemon that says nothing and is ready by existing. Its
-- process is the service: killing it stops the service.
boot_service("pt-alive", {
    { name = "Readiness", type = "dword", data = 1 },
    { name = "RestartPolicy", type = "dword", data = 0 },
})

-- The same service on the default readiness rule. `/bin/sleep` never
-- sends READY=1, so it never becomes ready by existing. The start
-- timeout is wide enough that it is still waiting throughout this file.
boot_service("pt-notify", {
    { name = "StartTimeout", type = "dword", data = 240 },
    { name = "RestartPolicy", type = "dword", data = 0 },
})

-- Oneshots. Every one of them is left on the default Readiness -- Notify
-- -- because §3.1's claim is that the field is ignored for this type.
boot_service("pt-one-ok", {
    { name = "Type", type = "dword", data = 1 },
    { name = "ImagePath", type = "sz", data = "/bin/true" },
    { name = "Arguments", type = "multi", data = {} },
})
boot_service("pt-one-remain", {
    { name = "Type", type = "dword", data = 1 },
    { name = "ImagePath", type = "sz", data = "/bin/true" },
    { name = "Arguments", type = "multi", data = {} },
    { name = "RemainAfterExit", type = "dword", data = 1 },
})
boot_service("pt-one-fail", {
    { name = "Type", type = "dword", data = 1 },
    { name = "ImagePath", type = "sz", data = "/bin/false" },
    { name = "Arguments", type = "multi", data = {} },
    { name = "RestartPolicy", type = "dword", data = 0 },
})
-- Exit 3, listed as a success. RemainAfterExit so that Completed is
-- still readable when the test asks.
boot_service("pt-one-code", {
    { name = "Type", type = "dword", data = 1 },
    { name = "ImagePath", type = "sz", data = "/bin/sh" },
    { name = "Arguments", type = "multi", data = { "/pt/exit3.sh" } },
    { name = "SuccessExitCodes", type = "multi", data = { "3" } },
    { name = "RemainAfterExit", type = "dword", data = 1 },
})
-- The same exit code, not listed.
boot_service("pt-one-code-no", {
    { name = "Type", type = "dword", data = 1 },
    { name = "ImagePath", type = "sz", data = "/bin/sh" },
    { name = "Arguments", type = "multi", data = { "/pt/exit3.sh" } },
    { name = "RestartPolicy", type = "dword", data = 0 },
})

-- Post-hooks on a Oneshot, on both sides of the success question.
boot_service("pt-one-post", {
    { name = "Type", type = "dword", data = 1 },
    { name = "ImagePath", type = "sz", data = "/bin/true" },
    { name = "Arguments", type = "multi", data = {} },
    { name = "RemainAfterExit", type = "dword", data = 1 },
    { name = "ExecStartPost", type = "multi", data = { "/bin/sh /pt/post-ok.sh" } },
})
boot_service("pt-one-post-fail", {
    { name = "Type", type = "dword", data = 1 },
    { name = "ImagePath", type = "sz", data = "/bin/false" },
    { name = "Arguments", type = "multi", data = {} },
    { name = "RestartPolicy", type = "dword", data = 0 },
    { name = "ExecStartPost", type = "multi", data = { "/bin/sh /pt/post-fail.sh" } },
})

-- StartTimeout on a Oneshot. Four seconds of pre-hook and four of main
-- process fit in neither a six-second budget nor any single leg of it,
-- which is what makes the failure evidence about the whole execution.
boot_service("pt-ost-sum", {
    { name = "Type", type = "dword", data = 1 },
    { name = "Arguments", type = "multi", data = { "4" } },
    { name = "ExecStartPre", type = "multi", data = { "/bin/sleep 4" } },
    { name = "StartTimeout", type = "dword", data = 6 },
    { name = "RestartPolicy", type = "dword", data = 0 },
})
-- The same shape inside its budget.
boot_service("pt-ost-ok", {
    { name = "Type", type = "dword", data = 1 },
    { name = "Arguments", type = "multi", data = { "1" } },
    { name = "ExecStartPre", type = "multi", data = { "/bin/sleep 1" } },
    { name = "StartTimeout", type = "dword", data = 30 },
    { name = "RemainAfterExit", type = "dword", data = 1 },
})
-- And a budget the pre-hook alone blows, so that the first pre-hook is
-- shown to be inside the window rather than before it.
boot_service("pt-ost-hook", {
    { name = "Type", type = "dword", data = 1 },
    { name = "ImagePath", type = "sz", data = "/bin/true" },
    { name = "Arguments", type = "multi", data = {} },
    { name = "ExecStartPre", type = "multi", data = { "/bin/sleep 20" } },
    { name = "StartTimeout", type = "dword", data = 4 },
    { name = "RestartPolicy", type = "dword", data = 0 },
})

-- A service whose binary forks a long-running process and exits.
boot_service("pt-fork", {
    { name = "ImagePath", type = "sz", data = "/bin/sh" },
    { name = "Arguments", type = "multi", data = { "/pt/daemonise.sh" } },
    { name = "Readiness", type = "dword", data = 1 },
    { name = "RestartPolicy", type = "dword", data = 0 },
})

local vm = peinit.boot({
    name = "services",
    files = peinit.merge(FILES, peinit.seed("pt-services", SERVICES)),
})

local function status(service_name)
    local r = vm:run("svctl --json status " .. service_name)
    if r.stdout:find("UNKNOWN_SERVICE", 1, true) then return nil end
    local ok, decoded = pcall(json.decode, r.stdout)
    return ok and decoded or nil
end

--- Wait until `service_name` has stopped moving: anything but Starting,
--- and anything but the Inactive it sits in before it is dispatched.
local function settled(service_name, timeout)
    return wait_until(function()
        local st = status(service_name)
        if not st then return nil end
        if st.state == "starting" or st.state == "inactive" then return nil end
        return st
    end, {
        timeout = timeout or 90, interval = 0.4,
        desc = service_name .. " to settle",
    })
end

--- The same, for a service whose settled state *is* Inactive.
---
--- Inactive is both "not started yet" and "started, finished, and let
--- go of", and a status read cannot tell them apart. The console can:
--- peinit prints a started line when the start completes, so waiting
--- for that first makes the Inactive that follows the one after the run
--- rather than the one before it.
local function settled_after_start(service_name, timeout)
    vm:console():expect("peinit: service " .. service_name .. " started",
        timeout or peinit.STAGE_TIMEOUT)
    return wait_until(function()
        local st = status(service_name)
        return st and st.state ~= "starting" and st or nil
    end, {
        timeout = 60, interval = 0.4,
        desc = service_name .. " to settle after its start",
    })
end

local function exists(path)
    return vm:run("test -e " .. path).exit_code == 0
end

test("a Simple service's main process is the service, and when it exits the service has stopped",
    { spec = "peinit *svc.a-simple-services-main-process-is-the-service" },
    function(t)
        local before = settled("pt-alive")
        t:assert_eq(before.state, "active", "the daemon is running")
        local pid = before.current_job and before.current_job.pid
        t:assert(pid, "and peinit holds a main job for it: " .. json.encode(before))

        -- The process peinit forked *is* the service. Nothing stops the
        -- service here and nothing reloads anything: the process is
        -- killed from underneath peinit, and that alone ends the
        -- service. RestartPolicy is Never, so what follows the exit is
        -- the exit and not a restart.
        vm:run("kill -9 " .. tostring(pid))

        local after = wait_until(function()
            local st = status("pt-alive")
            return st and st.state ~= "active" and st or nil
        end, { timeout = 60, interval = 0.3, desc = "pt-alive to leave Active" })
        t:assert_eq(after.state, "failed",
            "killing the process ended the service: " .. tostring(after.state))
        t:assert_eq(after.cause, "process_crash",
            "and peinit read the exit as the process it was supervising going away")
        t:assert(after.current_job == nil,
            "there is no main job left, because there is no main process")
    end)

test("Notify readiness waits for READY=1 and Alive does not",
    {
        spec = {
            "peinit *svc.notify-waits-for-ready-and-alive-does-not",
            "peinit *schema.the-field-table",
        },
    },
    function(t)
        -- pt-notify and pt-alive run the same binary with the same
        -- arguments as the same principal. The only difference is
        -- Readiness -- absent on one, so the table's default of 0
        -- (Notify) applies, and 1 (Alive) on the other.
        --
        -- `/bin/sleep` sends no notification ever, so a service waiting
        -- for READY=1 waits until its start timeout. pt-notify's is four
        -- minutes, so it is still waiting.
        local notify = status("pt-notify")
        t:assert(notify, "pt-notify exists")
        t:assert_eq(notify.state, "starting",
            "an un-notifying process on the default Notify readiness is still " ..
            "Starting: " .. tostring(notify.state))
        t:assert(notify.current_job and notify.current_job.pid,
            "even though its process is running -- readiness is not existence")

        -- The identical service told to be ready by existing reached
        -- Active at boot. (The first test in this file has since killed
        -- it, so the console rather than the status is where that is
        -- still recorded.)
        t:assert(vm:console():read_log():find("peinit: service pt-alive started", 1, true),
            "while Alive readiness reached Active on the process existing")
    end)

test("a Oneshot ignores Readiness: its readiness is a successful exit",
    { spec = "peinit *svc.a-oneshots-readiness-field-is-ignored" },
    function(t)
        -- Every Oneshot in this file is on the default Readiness, which
        -- is Notify. A Simple service on that setting is still Starting
        -- (the test above), because `/bin/true` sends no READY=1 either.
        -- These reach a terminal state anyway, which they could only do
        -- on the exit.
        local ok = settled_after_start("pt-one-ok")
        t:assert(ok.state == "inactive" or ok.state == "completed",
            "a Oneshot that exited 0 is finished rather than waiting for a " ..
            "notification it will never get: " .. tostring(ok.state))
        t:assert(vm:console():read_log():find("peinit: service pt-one-ok started", 1, true),
            "and peinit reported it started, on the strength of the exit")
    end)

test("a Oneshot succeeds on exit code 0 or any code SuccessExitCodes lists",
    {
        spec = {
            "peinit *svc.a-oneshot-succeeds-on-zero-or-a-listed-code",
            "peinit *svc.a-nonzero-oneshot-exit-is-failed",
        },
    },
    function(t)
        -- Exit 0 is success without listing.
        local zero = settled_after_start("pt-one-ok")
        t:assert(zero.state ~= "failed", "exit 0 is success: " .. tostring(zero.state))

        -- A non-zero exit is Failed.
        local failed = settled("pt-one-fail")
        t:assert_eq(failed.state, "failed", "a non-zero exit goes to Failed")

        -- And the same non-zero exit, listed, is success. pt-one-code
        -- and pt-one-code-no run the identical script; the only
        -- difference is SuccessExitCodes.
        local listed = settled("pt-one-code")
        t:assert_eq(listed.state, "completed",
            "exit 3 with SuccessExitCodes=[3] is success: " .. tostring(listed.state))
        local unlisted = settled("pt-one-code-no")
        t:assert_eq(unlisted.state, "failed",
            "and the same exit code unlisted is a failure: " .. tostring(unlisted.state))
    end)

test("RemainAfterExit holds a successful Oneshot in Completed",
    { spec = "peinit *svc.remainafterexit-holds-a-completed-oneshot" },
    function(t)
        -- Two Oneshots that both exit 0. The one with RemainAfterExit=1
        -- stays in Completed, so a status query shows the work as
        -- finished; the one without passes through it to Inactive.
        local remain = settled("pt-one-remain")
        t:assert_eq(remain.state, "completed",
            "RemainAfterExit=1 stays Completed: " .. tostring(remain.state))

        local through = settled_after_start("pt-one-ok")
        t:assert_eq(through.state, "inactive",
            "and without it the service ends up Inactive: " .. tostring(through.state))
    end)

test("a Oneshot's ExecStartPost runs after a successful exit, and not at all after a failure",
    { spec = "peinit *svc.a-oneshots-post-hooks-run-after-a-successful-exit" },
    function(t)
        -- pt-one-post never signals readiness -- it is a Oneshot on the
        -- default Notify setting running `/bin/true`. Its post-hook ran
        -- anyway, so what ran it was the exit.
        local ok = settled("pt-one-post")
        t:assert_eq(ok.state, "completed", "the Oneshot succeeded")
        wait_until(function() return exists("/run/pt-post-ok") end,
            { timeout = 30, interval = 0.3, desc = "the post-hook marker" })

        -- And the failing one's post-hook did not run at all. Its
        -- service settled some time ago, so the absence is settled too
        -- rather than a race with a hook still to be dispatched.
        local failed = settled("pt-one-post-fail")
        t:assert_eq(failed.state, "failed", "the failing Oneshot failed")
        vm:run("sleep 2")
        t:assert(not exists("/run/pt-post-fail"),
            "and its ExecStartPost never ran")
    end)

test("a Oneshot's StartTimeout covers the whole execution, from the first pre-hook to the exit",
    { spec = "peinit *svc.a-oneshots-starttimeout-covers-the-whole-execution" },
    function(t)
        -- pt-ost-sum spends four seconds in a pre-hook and four in its
        -- main process, on a six-second budget. Neither leg alone
        -- exceeds it. It fails anyway, so the budget is spent across
        -- both -- it is one deadline over the whole execution rather
        -- than one per stage.
        local sum = settled("pt-ost-sum")
        t:assert_eq(sum.state, "failed",
            "four seconds of hook plus four of process does not fit six: " ..
            tostring(sum.state))
        t:assert_eq(sum.cause, "readiness_timeout",
            "and the deadline landed during the main process, not the hook")

        -- The same shape with a budget it fits inside completes, so the
        -- failure above is the budget and not the work.
        local ok = settled("pt-ost-ok")
        t:assert_eq(ok.state, "completed",
            "one second of hook plus one of process fits thirty")

        -- And the first pre-hook is inside the window: a hook that
        -- outlasts the whole budget on its own fails the start before
        -- the main process is reached at all.
        local hook = settled("pt-ost-hook")
        t:assert_eq(hook.state, "failed", "a hook longer than the budget fails the start")
        t:assert_eq(hook.cause, "pre_hook_failure",
            "with the deadline landing in the pre-hooks")
    end)

test("supervision follows the process peinit forked, not one that forks away from it",
    { spec = "peinit *svc.supervision-follows-the-forked-child" },
    function(t)
        -- pt-fork is the shape §3.1 says peinit does not support: the
        -- binary starts a long-running process and exits. peinit holds a
        -- pidfd on the child it forked and nothing else, so the exit of
        -- that child is the end of the service -- there is no way to
        -- point supervision at the process that is still running, and no
        -- attempt to guess at one.
        local st = settled_after_start("pt-fork")
        t:assert(st.state ~= "active",
            "the service did not stay Active on the strength of the process its " ..
            "binary left behind: " .. tostring(st.state))
        t:assert_eq(st.cause, "clean_exit",
            "peinit read the direct child's exit(0) as the service ending")
        t:assert(st.current_job == nil, "and holds no main job for it")
    end)

test("WorkingDirectory defaults to /",
    { spec = "peinit *schema.the-field-table" },
    function(t)
        -- One more of the schema table's defaults, read off a running
        -- process. pt-notify names no WorkingDirectory and is still
        -- running, so its cwd is the default the table gives.
        local notify = status("pt-notify")
        t:assert(notify and notify.current_job and notify.current_job.pid,
            "pt-notify has a live process")
        local cwd = vm:run("readlink /proc/" .. tostring(notify.current_job.pid) .. "/cwd")
        cwd:assert_ok()
        t:assert_eq((cwd.stdout:gsub("%s+$", "")), "/",
            "a service that names no WorkingDirectory runs in /: " .. cwd.stdout)
    end)
