-- peinit TRM §14.4 — resource exhaustion: what a supervised process
-- costs PID 1, and what a launch does when it cannot have it.
--
-- Most of this section is about a syscall failing for want of a
-- resource, and exhausting PID 1's descriptor table or the machine's
-- memory from inside the guest would take the whole system down long
-- before it produced the one failed `clone3` the claim is about. The
-- PID limit is the exception, and the reason is §5.1: peinit sets no
-- cgroup limits of its own, so the pids controller is free for a test to
-- turn on and point at the subtree peinit clones into. That makes the
-- third test below a real EAGAIN out of a real `clone3` rather than a
-- stand-in for one.
--
-- The first two tests are the two halves of the descriptor inventory
-- those claims rest on: what a supervised process costs, and whether it
-- stops costing it once it is gone. The second is tagged, because peinit
-- does not give the descriptors back.
--
-- Counting is done by classifying every entry in /proc/1/fd rather than
-- by counting them, because the count alone cannot tell a pidfd from a
-- control connection that happened to be open at the same moment.

local peinit = require("helpers.peinit")
peinit.claim(1)

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },
    { path = [[Machine\System\Services\login-console]], values = {
        { name = "Disabled", type = "dword", data = 1 },
    } },
    -- Resident, started on demand: one supervised process, held for as
    -- long as the test wants it.
    { path = [[Machine\System\Services\pt-live]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "100000" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
    } },
    -- Runs and is gone: after it exits there is no supervised process
    -- left, so there is nothing for peinit to still be holding.
    { path = [[Machine\System\Services\pt-brief]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/true" },
        { name = "Type", type = "dword", data = 1 },
        { name = "Identity", type = "sz", data = "SYSTEM" },
    } },
    -- For the PID-limit test. Restarts always, with a short delay and a
    -- budget deep enough to survive the failures the limit causes, so
    -- that the retry after the limit is lifted is the same activation's
    -- own next attempt rather than a fresh command.
    { path = [[Machine\System\Services\pt-fork]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "100000" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 2 },
        { name = "RestartDelay", type = "dword", data = 5 },
        { name = "RestartMaxRetries", type = "dword", data = 20 },
    } },
    -- For the filesystem-condition test: the same Oneshot as pt-brief,
    -- once with a condition that never holds (so the check helper runs
    -- and nothing else does) and once with one that always holds (so the
    -- helper runs and then the start does).
    { path = [[Machine\System\Services\pt-cond-skip]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/true" },
        { name = "Type", type = "dword", data = 1 },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Conditions", type = "multi", data = { "path:/pt-exhaust-absent" } },
    } },
    { path = [[Machine\System\Services\pt-cond-pass]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/true" },
        { name = "Type", type = "dword", data = 1 },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Conditions", type = "multi", data = { "directory:/run" } },
    } },
}

--- For the OnFailure test: an origin that fails once, and two resident
--- handlers that name each other. RestartWindow is short so "held for a
--- RestartWindow" is seconds rather than two minutes, and RestartPolicy
--- is Never so that killing a handler is one failure, not a restart.
local function onfailure_trio(tag)
    local function resident(name, handler)
        return { path = [[Machine\System\Services\]] .. name, values = {
            { name = "ImagePath", type = "sz", data = "/bin/sleep" },
            { name = "Arguments", type = "multi", data = { "100000" } },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
            { name = "RestartPolicy", type = "dword", data = 0 },
            { name = "RestartWindow", type = "dword", data = 3 },
            { name = "OnFailure", type = "sz", data = handler },
        } }
    end
    SERVICES[#SERVICES + 1] = { path = [[Machine\System\Services\pt-of-origin]] .. tag, values = {
        { name = "ImagePath", type = "sz", data = "/bin/false" },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "OnFailure", type = "sz", data = "pt-of-b" .. tag },
    } }
    SERVICES[#SERVICES + 1] = resident("pt-of-b" .. tag, "pt-of-c" .. tag)
    SERVICES[#SERVICES + 1] = resident("pt-of-c" .. tag, "pt-of-b" .. tag)
end
onfailure_trio("")
onfailure_trio("-quick")

local vm = peinit.boot({
    name = "exhaust",
    files = peinit.seed("pt-exhaust", SERVICES),
})

--- Every descriptor PID 1 holds, as a map of number to link target.
local function descriptors()
    local fds = {}
    for _, entry in ipairs(vm:listdir("/proc/1/fd")) do
        fds[entry.name] = vm:run("readlink /proc/1/fd/" .. entry.name)
            .stdout:gsub("%s+$", "")
    end
    return fds
end

--- What `after` holds that `before` did not, counted by kind.
local function gained(before, after)
    local counts = { pidfd = 0, pipe = 0, other = 0 }
    local detail = {}
    for fd, target in pairs(after) do
        if not before[fd] then
            detail[#detail + 1] = fd .. " -> " .. target
            local kind = (target:find("pidfd", 1, true) and "pidfd")
                or (target:find("^pipe:") and "pipe")
                or "other"
            counts[kind] = counts[kind] + 1
        end
    end
    table.sort(detail)
    return counts, table.concat(detail, ", ")
end

--- How many pidfds PID 1 holds.
local function pidfd_count()
    local n = 0
    for _, target in pairs(descriptors()) do
        if target:find("pidfd", 1, true) then n = n + 1 end
    end
    return n
end

test("a supervised process costs peinit a pidfd and two pipes",
    { spec = "peinit *exhaust.the-descriptors-peinit-holds" },
    function(t)
        -- The first two entries of the inventory, which are also the two
        -- that scale with the number of services: one pidfd for the
        -- process itself, and one pipe each for its stdout and stderr
        -- (§11.1). Settling before each snapshot, because a control
        -- connection is a descriptor too and svctl has just been using
        -- one.
        vm:clock():sleep("2s")
        local before = descriptors()
        vm:run("svctl start pt-live"):assert_ok()
        vm:clock():sleep("2s")
        local after = descriptors()

        local counts, detail = gained(before, after)
        t:assert_eq(counts.pidfd, 1, "one pidfd for the process: " .. detail)
        t:assert_eq(counts.pipe, 2, "and two pipes for its output: " .. detail)
        t:assert_eq(counts.other, 0, "and nothing else: " .. detail)
    end)

test("a service that has exited costs nothing, because there is no process to hold",
    {
        spec = "peinit *exhaust.the-descriptors-peinit-holds",
        -- PEI-816: peinit retains one pidfd per service activation for
        -- the life of the process. The descriptor is not released when
        -- the process is reaped, so PID 1's descriptor table grows by
        -- one on every start of any service — an unbounded leak in the
        -- one process that cannot be restarted to clear it.
        tags = { "known-bug" },
    },
    function(t)
        -- The inventory is per *supervised process*. A Oneshot that has
        -- run and exited is not one, so ten of them in a row should cost
        -- the same as none: there is nothing left to hold a pidfd for.
        --
        -- This is not the leak §14.4 describes — that one is two
        -- descriptors per start and only for a service using filesystem
        -- conditions. pt-brief has no conditions, and loses one.
        vm:clock():sleep("2s")
        local before = pidfd_count()
        for _ = 1, 10 do vm:run("svctl start pt-brief"):assert_ok() end
        vm:clock():sleep("5s")

        t:assert_eq(json.decode(vm:run("svctl --json status pt-brief").stdout).state,
            "inactive", "the ten runs are all over")
        t:assert_eq(pidfd_count(), before,
            "and peinit is holding no more pidfds than before them")
    end)

test("a launch that runs into the PID limit fails the start and is tried again",
    { spec = "peinit *exhaust.a-pid-limit-at-launch-is-a-restart-eligible-parentsetupfailure" },
    function(t)
        -- peinit sets no cgroup limits of its own (§5.1), which is what
        -- makes this reachable: the pids controller can be turned on
        -- from outside and pointed at the subtree peinit clones into.
        -- Every service process is cloned with CLONE_INTO_CGROUP under
        -- /sys/fs/cgroup/peinit, so a pids limit on that subtree makes
        -- the clone3 itself return EAGAIN — the real kernel path the
        -- claim is about, not a stand-in for it.
        vm:run("echo +pids > /sys/fs/cgroup/cgroup.subtree_control"):assert_ok()
        local current = tonumber(
            vm:read_file("/sys/fs/cgroup/peinit/pids.current"):match("%d+"))
        t:assert(current and current > 1,
            "the subtree is accounted: pids.current = " .. tostring(current))
        vm:run("echo 1 > /sys/fs/cgroup/peinit/pids.max"):assert_ok()

        -- Below the number of processes already in the subtree, so the
        -- next clone into it cannot succeed.
        local start = vm:run("svctl start pt-fork")
        local view = json.decode(vm:run("svctl --json status pt-fork").stdout)
        t:assert_eq(view.cause, "parent_setup_failure",
            "the launch failed as a ParentSetupFailure: " .. start.stdout)
        t:assert_eq(view.state, "backoff",
            "and the cause is restart-eligible, so the service is in Backoff "
            .. "waiting to try again rather than Failed")

        -- "gets another go" is the half that matters: lift the limit and
        -- the pending retry succeeds, without anyone issuing a second
        -- start.
        vm:run("echo max > /sys/fs/cgroup/peinit/pids.max"):assert_ok()
        wait_until(function()
            return json.decode(vm:run("svctl --json status pt-fork").stdout)
                .state == "active" or nil
        end, { timeout = 90, interval = 1, desc = "the retry to succeed" })
    end)

local function status(name)
    return json.decode(vm:run("svctl --json status " .. name).stdout)
end

local function reach(name, want, desc)
    return wait_until(function()
        local view = status(name)
        return view.state == want and view or nil
    end, { timeout = 60, interval = 0.3, desc = desc or (name .. " to reach " .. want) })
end

test("a filesystem condition costs no descriptors beyond the start itself",
    { spec = "peinit *exhaust.a-filesystem-condition-leaks-no-descriptors" },
    function(t)
        -- A filesystem condition is checked by a helper peinit clones for
        -- the purpose, and the helper costs PID 1 a result pipe and a
        -- pidfd while it runs. Once it has reported, both are closed.
        --
        -- The cleanest measurement is a condition that never holds: the
        -- helper runs, the service is Skipped, and nothing is started —
        -- so there is no main process for peinit to be holding anything
        -- for, and the right answer is exactly what it held before.
        vm:clock():sleep("2s")
        local before = descriptors()
        for _ = 1, 5 do
            vm:run("svctl start pt-cond-skip")
            t:assert_eq(status("pt-cond-skip").state, "skipped",
                "the condition did not hold, so the service was skipped")
        end
        vm:clock():sleep("2s")
        local counts, detail = gained(before, descriptors())
        t:assert_eq(counts.pidfd, 0, "five helpers left no pidfd behind: " .. detail)
        t:assert_eq(counts.pipe, 0, "and no result pipe: " .. detail)
        t:assert_eq(counts.other, 0, "and nothing else: " .. detail)

        -- A condition that holds is a helper and then a start. Whatever an
        -- ordinary start costs — and PEI-816 means a finished Oneshot is
        -- not free — the one with a condition must cost no more than the
        -- same Oneshot without one.
        vm:clock():sleep("2s")
        local plain_before = descriptors()
        for _ = 1, 5 do vm:run("svctl start pt-brief"):assert_ok() end
        vm:clock():sleep("2s")
        local plain = gained(plain_before, descriptors())

        local cond_before = descriptors()
        for _ = 1, 5 do vm:run("svctl start pt-cond-pass"):assert_ok() end
        vm:clock():sleep("2s")
        local cond, cond_detail = gained(cond_before, descriptors())
        t:assert_eq(status("pt-cond-pass").state, "inactive", "the conditioned runs are over")
        t:assert_eq(cond.pidfd, plain.pidfd,
            "five conditioned starts held as many pidfds as five plain ones: " .. cond_detail)
        t:assert_eq(cond.pipe, plain.pipe,
            "and as many pipes: " .. cond_detail)
        t:assert_eq(cond.other, plain.other, "and nothing else: " .. cond_detail)
    end)

test("an OnFailure chain entry is cleared once its handler has held for a RestartWindow",
    { spec = "peinit *exhaust.an-onfailure-chain-entry-is-cleared-once-the-handler-holds" },
    function(t)
        -- pt-of-b's handler is pt-of-c and pt-of-c's is pt-of-b. The
        -- chain from one failure will not start a handler already in it,
        -- so whether the pair can hand off B -> C -> B depends entirely on
        -- whether a handler that has taken over stops counting against
        -- the failure that started it.
        --
        -- The control first, with nothing allowed to hold: pt-of-b-quick
        -- and pt-of-c-quick are killed the moment they are up, so both are
        -- still entries of the chain their origin's failure started, and
        -- the hand-back to pt-of-b-quick is refused.
        local function kill(name)
            local pid = status(name).current_job.pid
            vm:run("kill -9 " .. pid):assert_ok()
            return reach(name, "failed", name .. " to fail")
        end

        vm:run("svctl --no-wait start pt-of-origin-quick")
        reach("pt-of-origin-quick", "failed", "the control's origin to fail")
        reach("pt-of-b-quick", "active", "the control's first handler to start")
        kill("pt-of-b-quick")
        reach("pt-of-c-quick", "active", "the control's second handler to start")
        kill("pt-of-c-quick")
        vm:clock():sleep("4s")
        t:assert_eq(status("pt-of-b-quick").state, "failed",
            "a handler still in the chain is not started again")

        -- Now the same hand-offs with each handler allowed to hold for its
        -- RestartWindow (three seconds) before it is killed. Each holding
        -- handler retires its entry, so its own failure starts a fresh
        -- chain — and the hand-back that was refused above goes through.
        vm:run("svctl --no-wait start pt-of-origin")
        reach("pt-of-origin", "failed", "the origin to fail")
        local first = reach("pt-of-b", "active", "the first handler to start").current_job.id
        vm:clock():sleep("6s")
        kill("pt-of-b")
        reach("pt-of-c", "active", "the second handler to start")
        vm:clock():sleep("6s")
        kill("pt-of-c")
        local again = reach("pt-of-b", "active",
            "pt-of-b to be started again as pt-of-c's handler")
        t:assert(again.current_job.id ~= first,
            "on a new activation, not the one that was killed")
    end)

-- Companion to the PID-limit test above: every parent-side launch failure is
-- classified ParentSetupFailure whatever its errno, and the unit test drives
-- the ENOMEM form of the clone3 failure through the supervisor to Backoff and
-- a successful relaunch.
test("a memory exhaustion at launch is a restart-eligible ParentSetupFailure",
    {
        spec = "peinit *exhaust.a-memory-exhaustion-at-launch-is-a-restart-eligible-parentsetupfailure",
        covered_by = "cargo:peinit2 supervisor::tests::launch_failure::a_clone3_enomem_is_a_restart_eligible_parent_setup_failure",
        skip = "clone3's ENOMEM comes from commit and kernel-memory accounting charged to PID 1 itself, so exhausting it from a guest fails PID 1's and the Critical daemons' own allocations first; runs under cargo test -p peinit2 --all-features --lib supervisor::tests::launch_failure::a_clone3_enomem_is_a_restart_eligible_parent_setup_failure",
    },
    function(t) end)

test("a graph execution context and its associations are retired once drained",
    {
        spec = "peinit *exhaust.graph-execution-contexts-are-retired",
        covered_by = "cargo:peinit2 supervisor::tests::on_demand_start::a_drained_graph_context_is_retired_with_its_associations",
        skip = "graph execution contexts and their operation associations have no control, KMES or /proc surface for a guest to count; runs under cargo test -p peinit2 --all-features --lib supervisor::tests::on_demand_start::a_drained_graph_context_is_retired_with_its_associations",
    },
    function(t) end)
