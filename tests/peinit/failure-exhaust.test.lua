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
}

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
