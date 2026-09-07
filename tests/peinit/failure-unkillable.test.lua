-- peinit TRM §14.3 — unkillable processes: Abandoned, and what peinit
-- does with a process that outlives the service that gave up on it.
--
-- The chapter's scenario is a D-state process, and nothing in a VM can
-- be put into uninterruptible sleep on demand. But the condition peinit
-- actually tests is narrower than the story: it kills `main/`, arms a
-- post-kill deadline, and asks `cgroup.events` whether `main/` is still
-- populated when the deadline fires. That question can be answered
-- honestly without a D-state process — by making it true.
--
-- So the provocation below has two halves.
--
-- `pt-stuck` ignores SIGTERM and carries a two-second `StopTimeout`, so
-- `svctl stop` escalates to a cgroup kill. Before the stop, the test
-- moves the service's own main process out of `main/` into a cgroup of
-- its own: a process outside the cgroup is not killed by a write to that
-- cgroup's `cgroup.kill`, which is exactly the position a D-state
-- process is in — SIGKILL sent, process still there. Second, a keeper
-- script drops a fresh live process into `main/` every second, so when
-- the post-kill deadline fires the cgroup reports populated. That is the
-- one input peinit reads, and it is genuinely true.
--
-- `PostKillTimeout` is seeded up to twenty seconds so the keeper has a
-- wide window to win; at the five-second default this is a race against
-- a shell loop.
--
-- Everything after that is real: the transition, the cause, the leak
-- record, the command matrix, the late exit and the reset are all
-- peinit's own behaviour on a service it has given up on. One VM, one
-- provocation, and the tests below read the state it leaves — in order,
-- because the exit in the third test and the reset in the fourth each
-- consume the state the previous one asserts on.
--
-- login-console is disabled because it takes /dev/console once the boot
-- settles (§11.6), and two of these claims are console lines.

local peinit = require("helpers.peinit")
peinit.claim(1)

local ROOT = "/sys/fs/cgroup/peinit/pt-stuck"
local ESCAPE = "/sys/fs/cgroup/pt-escape"

local FILES = {
    -- Ignores SIGTERM, so a stop has to escalate to the cgroup kill.
    ["pt/stuck.sh"] = { [[
trap '' TERM
while : ; do /bin/sleep 1 ; done
]], exec = true },
    -- Keeps main/ populated across the post-kill deadline. Each
    -- iteration forks a fresh sleep and moves it into main/: whatever
    -- the kill took, the next iteration replaces. The long sleep means
    -- the survivors are still there for the reset test.
    ["pt/keeper.sh"] = { [[
N=0
while [ $N -lt 40 ] ; do
  /bin/sleep 300 &
  echo $! > ]] .. ROOT .. [[/main/cgroup.procs
  N=$((N+1))
  /bin/sleep 1
done
]], exec = true },
}

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Boot]], values = {
        { name = "PostKillTimeout", type = "dword", data = 20 },
    } },
    { path = [[Machine\System\Services]] },
    { path = [[Machine\System\Services\login-console]], values = {
        { name = "Disabled", type = "dword", data = 1 },
    } },
    { path = [[Machine\System\Services\pt-stuck]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi", data = { "/pt/stuck.sh" } },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "StopTimeout", type = "dword", data = 2 },
    } },
}

local vm = peinit.boot({
    name = "unkillable",
    files = peinit.merge(FILES, peinit.seed("pt-unkillable", SERVICES)),
})

local function status()
    return json.decode(vm:run("svctl --json status pt-stuck").stdout)
end

--- Provoke the abandonment, once, for the whole file. Returns the id of
--- the stop operation that gave up, and the main process's pid.
local main_process_pid, stop_operation_id = (function()
    local pid = wait_until(function()
        local ok, procs = pcall(function()
            return vm:read_file(ROOT .. "/main/cgroup.procs")
        end)
        return ok and procs:match("^(%d+)") or nil
    end, { timeout = 60, interval = 0.5, desc = "pt-stuck to have a main process" })

    -- Out of main/, so the cgroup kill cannot reach it. peinit tracks
    -- the process by pidfd rather than by cgroup membership, so it is
    -- still the service's main process and still peinit's child.
    vm:run("mkdir -p " .. ESCAPE):assert_ok()
    vm:run("echo " .. pid .. " > " .. ESCAPE .. "/cgroup.procs"):assert_ok()

    vm:run("/pt/keeper.sh > /dev/null 2>&1 &")
    -- `--no-wait`: the stop is going to fail after the post-kill
    -- deadline, and what is wanted here is the operation's identifier
    -- rather than a twenty-second wait for it to say so.
    local ack = vm:run("svctl stop pt-stuck --no-wait")
    ack:assert_ok()
    local operation = ack.stdout:match("operation:%s*(%S+)")

    wait_until(function()
        return status().state == "abandoned" or nil
    end, { timeout = 60, interval = 1, desc = "pt-stuck to be abandoned" })
    return pid, operation
end)()

-- Read while the operation is still within its retention window: a
-- terminal operation is dropped rather than retained (§1.4), so this is
-- taken now rather than in the test that asserts on it.
local stop_operation_raw = vm:run("svctl --json op " .. stop_operation_id).stdout
local stop_operation = json.decode(stop_operation_raw).operation

test("a main process that survives the kill abandons the service and leaks its tree",
    { spec = "peinit *cgroup.an-unkillable-main-process-abandons-the-service" },
    function(t)
        local view = status()
        t:assert_eq(view.state, "abandoned",
            "the service peinit could not empty went to Abandoned")
        t:assert_eq(view.cause, "process_unkillable", "with cause ProcessUnkillable")

        -- The condition peinit judged on is still true, which is what
        -- makes the transition the right one rather than a coincidence.
        t:assert(vm:read_file(ROOT .. "/main/cgroup.procs"):match("%d"),
            "main/ was still populated when the post-kill deadline fired")

        -- Supervision stops and the cgroup is leaked: the service root
        -- is recorded as a `service_tree` leak, the most serious kind,
        -- because the whole tree including main/ could not be reclaimed.
        local leaked = {}
        for _, warning in ipairs(view.warnings or {}) do
            leaked[warning.path] = warning.type
        end
        t:assert_eq(leaked[ROOT], "service_tree",
            "the service root is recorded as leaked: " ..
            vm:run("svctl --json status pt-stuck").stdout)
    end)

test("the stop that gave up stays failed, and only reset is left",
    {
        spec = {
            "peinit *unkillable.the-stop-that-gave-up-stays-failed",
            "peinit *dispatch.abandoned-accepts-only-reset",
        },
    },
    function(t)
        -- Abandoning is not a way of completing the stop. The operation
        -- that asked for it is failed, and says why.
        t:assert_eq(stop_operation.state, "failed",
            "the stop operation failed rather than completing: " .. stop_operation_raw)
        t:assert_contains(stop_operation_raw,
            "service cgroup remained populated after SIGKILL",
            "naming the cgroup that would not empty")

        -- Every lifecycle command against an Abandoned service is
        -- invalid except reset. `reset` is deliberately not sent here:
        -- it is the fourth test's subject, and it would clear the state
        -- the third test needs.
        for _, command in ipairs({ "start", "stop", "restart", "reload" }) do
            local r = vm:run("svctl " .. command .. " pt-stuck")
            t:assert(r.exit_code ~= 0, command .. " was refused")
            t:assert_contains(r.stderr, "INVALID_STATE",
                command .. " was refused for the state rather than for anything else")
        end
    end)

test("the main job stays open, and the exit that finally arrives changes nothing",
    {
        spec = {
            "peinit *unkillable.abandoning-a-service-does-not-close-its-main-job",
            "peinit *trans.an-exit-in-an-unexpected-state-performs-no-transition",
        },
    },
    function(t)
        -- The process is still there, so there is still something to
        -- reap: peinit keeps the job open against the possibility that
        -- it eventually exits.
        local before = status()
        t:assert(before.current_job, "the abandoned service still has a main job")
        t:assert_eq(tostring(before.current_job.pid), main_process_pid,
            "and it is the process that survived the kill")
        t:assert_eq(before.current_job.type, "service_main", "as its main job")

        -- The exit peinit was holding the job for. Here it is a kill
        -- from outside; in the scenario the chapter describes it is the
        -- hung I/O finally completing.
        vm:run("kill -9 " .. main_process_pid)

        -- News about the process, not a retroactive success for the stop
        -- that gave up on it: recorded, and nothing else.
        vm:console():expect(
            "peinit: service pt-stuck main process exited in state Abandoned; " ..
            "no action taken", peinit.STAGE_TIMEOUT)

        local after = wait_until(function()
            local view = status()
            return view.current_job == nil and view or nil
        end, { timeout = 30, interval = 0.5, desc = "peinit to reap the main process" })
        t:assert_eq(after.state, "abandoned", "the service is still Abandoned")
        t:assert_eq(after.cause, "process_unkillable",
            "with the cause it had, so no transition was performed")
        t:assert_eq(stop_operation.state, "failed",
            "and the stop it gave up on is still failed")
    end)

test("a reset of a still-populated service warns, in the acknowledgement and on the console",
    {
        spec = {
            "peinit *trans.a-reset-of-a-populated-abandoned-service-warns-and-leaves-the-cgroup-leaked",
            "peinit *trans.the-reset-warning-is-also-written-to-the-console",
        },
        -- PEI-817: the abandoned-service reset probes the cgroup
        -- generation the service has *now*, but recording the leak on
        -- the way into Abandoned already advanced it — so the re-check
        -- reads a tree that has never existed, always finds it empty,
        -- never warns, and runs its cleanup against the wrong root.
        tags = { "known-bug" },
    },
    function(t)
        -- main/ still holds the keeper's processes, so the re-check a
        -- reset performs finds it populated. peinit returns the service
        -- to Inactive anyway — refusing would leave an operator with a
        -- service they can neither run nor clear — and says what it
        -- could not do.
        t:assert(vm:read_file(ROOT .. "/main/cgroup.procs"):match("%d"),
            "main/ is still populated at the moment of the reset")

        local reset = vm:run("svctl reset pt-stuck")
        reset:assert_ok()

        t:assert_eq(status().state, "inactive", "the service returned to Inactive")
        -- And the tree it could not reclaim is still in the hierarchy.
        t:assert_eq(vm:stat(ROOT).entry_type, "directory",
            "with the cgroup it could not remove still there")

        -- The acknowledgement does carry a warning, but it is the
        -- generic "service has leaked sub-cgroups from a previous
        -- generation" of §5.7, which any service with a leak on record
        -- gets. The one this rule is about — the re-check having found
        -- main/ still populated — is missing, because the re-check never
        -- found anything: recording the leak advanced the service's
        -- cgroup generation before the reset ran, so the reset probes
        -- pt-stuck%gen1/main, which has never existed.
        t:assert_contains(reset.stdout,
            "abandoned main cgroup for service pt-stuck is still populated after reset",
            "the acknowledgement carries the warning")
        t:assert_contains(reset.stdout, "cgroup remains leaked",
            "saying the cgroup is still leaked")
        t:assert_contains(reset.stdout, "D-state process requires investigation",
            "and what that means for the machine")

        -- The same warning reaches the console, so a reset issued
        -- without reading the response still leaves a trace.
        vm:console():expect(
            "abandoned main cgroup for service pt-stuck is still populated after reset",
            peinit.STAGE_TIMEOUT)
    end)
