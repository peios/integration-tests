-- peinit TRM §6.2 — the transitions: the ones the table lists, and the
-- four things the table settles.
--
-- Everything here is read out of `svctl --json status`, which carries the
-- state and the cause of the most recent transition. A cause is what
-- makes two transitions with the same endpoints distinguishable — a
-- Simple service reaching Inactive because it succeeded and one reaching
-- it because it was stopped are the same arrow with different labels —
-- so the assertions are on the pair rather than on the state alone.
--
-- The definitions are arranged so that each one has exactly one route
-- through the table. A service whose process is `/bin/false` cannot
-- succeed; one whose process is `/bin/sleep 2` under `Readiness=Alive`
-- cannot fail; one that another service Conflicts with cannot stop for
-- any other reason. Where a service must sit still for a later
-- assertion it is given a thirty-second RestartDelay, which parks it in
-- Backoff for longer than the file runs.

local peinit = require("helpers.peinit")
peinit.claim(1)

local function service(name, values)
    local base = {
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
    }
    for _, value in ipairs(values) do base[#base + 1] = value end
    return { path = [[Machine\System\Services\]] .. name, values = base }
end

local BOOT = { name = "Triggers", type = "multi", data = { "boot" } }
local RESIDENT = { name = "ImagePath", type = "sz", data = "/bin/sleep" }
local FOREVER = { name = "Arguments", type = "multi", data = { "3600" } }

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },

    -- A Simple service that runs for two seconds and exits zero, with a
    -- policy that is not Always. The only transition it can make out of
    -- Active is the clean one.
    service("pt-tr-clean", {
        BOOT,
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "2" } },
        { name = "RestartPolicy", type = "dword", data = 0 },
    }),

    -- The same shape under RestartPolicy=Always. Nothing about it fails,
    -- so anything that restarts it is the policy rather than a failure.
    -- A generous retry budget keeps it cycling for the whole file.
    service("pt-tr-always", {
        BOOT,
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "1" } },
        { name = "RestartPolicy", type = "dword", data = 2 },
        { name = "RestartDelay", type = "dword", data = 1 },
        { name = "RestartMaxRetries", type = "dword", data = 100 },
        { name = "RestartWindow", type = "dword", data = 120 },
    }),

    -- Readiness=Notify with a process that exits non-zero at once: it
    -- cannot reach Active, so its exit is observed from Starting.
    service("pt-tr-preready", {
        BOOT,
        { name = "ImagePath", type = "sz", data = "/bin/false" },
        { name = "Readiness", type = "dword", data = 0 },
        { name = "RestartPolicy", type = "dword", data = 1 },
        { name = "RestartDelay", type = "dword", data = 30 },
        { name = "RestartMaxRetries", type = "dword", data = 5 },
    }),

    -- A conflict pair. The victim boots; the winner does not, and is
    -- started by hand so the eviction happens where a test can watch it.
    service("pt-tr-victim", { BOOT, RESIDENT, FOREVER }),
    service("pt-tr-winner", {
        RESIDENT, FOREVER,
        { name = "Conflicts", type = "multi", data = { "pt-tr-victim" } },
    }),

    -- A Oneshot that takes a long time. peinit's terminal handler
    -- accounts for a main exit in four states -- Starting, and
    -- Active/Reloading/Stopping for a *Simple* service -- so a Oneshot
    -- that is stopped mid-run is in a state that no longer expects an
    -- exit by the time its process reports one. The generous StopTimeout
    -- keeps the stop's own escalation out of the window under test.
    service("pt-tr-oneshot", {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "120" } },
        { name = "Type", type = "dword", data = 1 },
        { name = "StopTimeout", type = "dword", data = 120 },
        { name = "StartTimeout", type = "dword", data = 120 },
    }),

    -- Never triggered and never depended on, so it stays Inactive: the
    -- subject for commands the table has no arrow for.
    service("pt-tr-idle", { RESIDENT, FOREVER }),

    -- A plain resident service, for the restart legs.
    service("pt-tr-cycle", { BOOT, RESIDENT, FOREVER }),
}

-- `peios.quiet=0`, because one assertion below is on a console line
-- produced after the boot. The default level stays out of a terminal a
-- service owns, and by the time the boot is complete a login service
-- owns /dev/console -- so every peinit message below Critical is dropped
-- from that point on, silently. Verbose writes everything regardless of
-- who owns the terminal, which is what makes a post-boot console
-- assertion possible at all.
local vm = peinit.boot({
    name = "transitions",
    append = "peios.quiet=0",
    files = peinit.seed("pt-transitions", SERVICES),
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
    end, { timeout = 90, interval = 0.3, desc = desc or (name .. " to reach " .. want) })
end

test("a Simple service exiting zero goes to Inactive under CleanExit",
    { spec = "peinit *trans.a-simple-clean-exit-goes-to-inactive-under-cleanexit" },
    function(t)
        local view = settle("pt-tr-clean", "inactive", "pt-tr-clean to finish its two seconds")
        t:assert_eq(view.cause, "clean_exit",
            "the cause names the success, not a failure")

        -- And it stays there: the policy was not Always, so nothing
        -- consulted it and nothing restarted the service.
        vm:run("sleep 3")
        local later = status("pt-tr-clean")
        t:assert_eq(later.state, "inactive",
            "three seconds later it is still Inactive: " .. later.state)
        t:assert(not later.current_job,
            "with no process, so the clean exit was terminal")
    end)

test("the same clean exit under RestartPolicy=Always goes to Backoff as CleanExitRestart",
    { spec = "peinit *trans.a-clean-exit-under-always-goes-to-backoff-as-cleanexitrestart" },
    function(t)
        -- pt-tr-always differs from pt-tr-clean in one dword. Its process
        -- exits zero every time, so a cause naming a crash would be a
        -- lie; the cause peinit records says the process succeeded and
        -- the policy asked for another one.
        local view = wait_until(function()
            local current = status("pt-tr-always")
            return current.cause == "clean_exit_restart" and current or nil
        end, { timeout = 90, interval = 0.3, desc = "pt-tr-always to be restarted by policy" })
        t:assert_eq(view.cause, "clean_exit_restart",
            "a successful exit restarted by policy is its own cause")
        t:assert(view.state == "backoff" or view.state == "starting",
            "and the state it is in is the restart path: " .. view.state)

        -- Never a crash: the service's process is `/bin/sleep 1`, which
        -- cannot exit non-zero, so process_crash never appears for it.
        local seen_crash = false
        for _ = 1, 12 do
            if status("pt-tr-always").cause == "process_crash" then seen_crash = true end
            vm:run("sleep 0.5")
        end
        t:assert(not seen_crash,
            "a clean exit is never reported as a crash")
    end)

test("a Simple process that exits before readiness is a restart-eligible ProcessCrash",
    { spec = "peinit *trans.a-pre-readiness-exit-is-a-restart-eligible-processcrash" },
    function(t)
        -- Readiness=Notify and a process that exits at once, so peinit
        -- observed the exit from Starting rather than from Active.
        local view = settle("pt-tr-preready", "backoff",
            "pt-tr-preready to be scheduled for another go")
        t:assert_eq(view.cause, "process_crash",
            "the pre-readiness exit is a ProcessCrash: " .. tostring(view.cause))

        -- Restart-eligible rather than terminal: it is in Backoff, which
        -- is the state a service reaches only when a retry is coming.
        t:assert_eq(view.state, "backoff",
            "and it is waiting to start again rather than Failed")
    end)

test("a service stopped by a conflict fails carrying ConflictEviction, not a generic failure",
    { spec = "peinit *trans.stopping-to-failed-carries-the-cause-that-started-the-stop" },
    function(t)
        settle("pt-tr-victim", "active", "pt-tr-victim to come up at boot")

        -- Starting the winner is the only thing that happens to the
        -- victim, so whatever cause it ends up with came from the
        -- eviction.
        vm:run("svctl start pt-tr-winner"):assert_ok()
        local view = settle("pt-tr-victim", "failed",
            "pt-tr-victim to be evicted by its conflict")
        t:assert_eq(view.cause, "conflict_eviction",
            "the stop that failed it remembered why it began: " .. tostring(view.cause))

        -- The winner is up, which is what the eviction was for.
        settle("pt-tr-winner", "active", "pt-tr-winner to take the victim's place")
    end)

test("an exit arriving for a service that no longer expects one performs no transition",
    {
        spec = {
            "peinit *trans.an-exit-in-an-unexpected-state-performs-no-transition",
            "peinit *trans.an-unexpected-exit-does-not-cost-the-machine",
        },
    },
    function(t)
        -- Stopping a Oneshot mid-run is the route this harness can
        -- reach. The three the manual names -- a watchdog timeout, a
        -- health escalation, the post-kill give-up -- all kill the
        -- service cgroup and fail the main job in the same turn they
        -- move the service, so the SIGCHLD that follows finds no job to
        -- report; and Abandoned needs a process that survives SIGKILL,
        -- which a guest cannot be made to produce. What is left is a
        -- state peinit's terminal handler accounts for only for a Simple
        -- service, so the Oneshot's exit arrives somewhere with no arm
        -- to take it -- the same code path, reached from a different
        -- side.
        vm:run("svctl --no-wait start pt-tr-oneshot"):assert_ok()
        settle("pt-tr-oneshot", "starting", "the Oneshot to be running its process")

        vm:run("svctl --no-wait stop pt-tr-oneshot"):assert_ok()
        vm:console():expect(
            "peinit: service pt-tr-oneshot main process exited in state Stopping; " ..
            "no action taken", 60)

        -- No transition was performed for that exit: the service kept
        -- the state the stop put it in.
        local after = status("pt-tr-oneshot")
        t:assert_eq(after.state, "stopping",
            "the service kept the state it had: " .. after.state)
        t:assert_eq(after.cause, "explicit_stop",
            "and the cause it had, so nothing was recorded for the exit")

        -- And the machine is still here. A late exit used to be treated
        -- as a broken runtime invariant, which took PID 1 into recovery.
        t:assert_eq(vm:run("svctl list").exit_code, 0,
            "peinit is still answering the control socket")
        t:assert(not vm:console():read_log():find("Recovery mode", 1, true),
            "and did not drop the machine into recovery")
        t:assert_eq(status("pt-tr-cycle").state, "active",
            "and the services around it are untouched")
    end)

test("a transition the table does not list cannot be requested",
    { spec = "peinit *trans.a-transition-absent-from-the-table-is-not-performed" },
    function(t)
        -- There is no Inactive-to-Reloading arrow, no Active-to-Inactive
        -- arrow under a reset, and no Backoff-to-Reloading arrow. peinit
        -- refuses each rather than inventing one, and the service is left
        -- exactly where it was.
        local refusals = {
            { command = "reload pt-tr-idle", service = "pt-tr-idle", from = "inactive" },
            { command = "reset pt-tr-cycle", service = "pt-tr-cycle", from = "active" },
            { command = "reload pt-tr-preready", service = "pt-tr-preready", from = "backoff" },
        }
        for _, refusal in ipairs(refusals) do
            local before = status(refusal.service)
            t:assert_eq(before.state, refusal.from,
                refusal.service .. " is " .. refusal.from .. " before the command")
            local result = vm:run("svctl --json " .. refusal.command)
            t:assert(result.exit_code ~= 0 or result.stdout:find('"status":"error"', 1, true),
                "`svctl " .. refusal.command .. "` was refused: rc=" .. result.exit_code ..
                " out=" .. result.stdout)
            t:assert_eq(status(refusal.service).state, refusal.from,
                "and " .. refusal.service .. " is still " .. refusal.from)
        end
    end)
