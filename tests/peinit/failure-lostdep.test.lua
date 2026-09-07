-- peinit TRM §14.2 — losing a dependency.
--
-- Most of this section restates rules anchored elsewhere: the authd
-- failure path is §4.3's, the eventd handoff is §11.4's, and `BindsTo`
-- and a crashing `Requires` target are §7.1's. What is stated here and
-- nowhere else is two things, and this file is those two.
--
-- The first is that authd and eventd are Critical, which is what turns
-- "no user-facing service can start" into "the machine reboots" rather
-- than into a system that sits there broken. ErrorControl is not exposed
-- by any query, so the oracle is the one place a running system says it
-- out loud: §5.4 sets `oom_score_adj` to -1000 for a Critical service
-- and leaves everything else at the default.
--
-- The second is the fate of a dependent that is blocked on a dependency
-- that never becomes satisfying. `pt-slow` below is a Notify service
-- that never notifies, so it sits in Starting for its whole 200-second
-- `StartTimeout`; `pt-wait` requires it and carries a `StartTimeout` of
-- 8. If the dependent's clock ran from when it started running it would
-- never expire, because it never starts running at all — so the
-- expiry, and its arithmetic, are the claim.

local peinit = require("helpers.peinit")
peinit.claim(1)

local FILES = {
    -- Runs forever and never signals readiness, so its Notify start
    -- never completes and it holds Starting for the length of the file.
    ["pt/never-ready.sh"] = { [[
while : ; do /bin/sleep 5 ; done
]], exec = true },
}

local WAIT_TIMEOUT_SECS = 8

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },
    { path = [[Machine\System\Services\login-console]], values = {
        { name = "Disabled", type = "dword", data = 1 },
    } },
    -- The dependency that never becomes satisfying. Readiness 0 is
    -- Notify; the script never sends one, and the long StartTimeout
    -- keeps it in Starting rather than failing out from under the
    -- dependent and turning this into a test about propagation.
    { path = [[Machine\System\Services\pt-slow]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi", data = { "/pt/never-ready.sh" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 0 },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "StartTimeout", type = "dword", data = 200 },
    } },
    -- The dependent. It leaves a file behind if it ever runs, which is
    -- how the test tells "blocked and then failed" from "started and
    -- then failed".
    { path = [[Machine\System\Services\pt-wait]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/touch" },
        { name = "Arguments", type = "multi", data = { "/pt-wait-ran" } },
        { name = "Type", type = "dword", data = 1 },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Requires", type = "multi", data = { "pt-slow" } },
        { name = "StartTimeout", type = "dword", data = WAIT_TIMEOUT_SECS },
    } },
    -- An ordinary Normal service, so the -1000 below means something.
    { path = [[Machine\System\Services\pt-normal]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "100000" } },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
    } },
}

local vm = peinit.boot({
    name = "lostdep",
    files = peinit.merge(FILES, peinit.seed("pt-lostdep", SERVICES)),
})

local function main_pid(service)
    local status = json.decode(vm:run("svctl --json status " .. service).stdout)
    return status.current_job and status.current_job.pid
end

local function oom_score_adj(service)
    local pid = wait_until(function() return main_pid(service) end,
        { timeout = 60, interval = 0.5, desc = service .. " to have a main process" })
    return vm:read_file("/proc/" .. pid .. "/oom_score_adj"):gsub("%s+$", "")
end

test("authd and eventd are both Critical services",
    {
        spec = {
            "peinit *lostdep.authd-is-a-critical-service",
            "peinit *lostdep.eventd-is-a-critical-service",
        },
    },
    function(t)
        -- A Critical service is one whose loss reboots the machine, and
        -- the reason both of these are Critical is exactly the reason
        -- this section gives: without authd nothing user-facing can
        -- start, and without eventd the machine is silently losing its
        -- audit history. Neither is a state to sit in.
        t:assert_eq(oom_score_adj("authd"), "-1000",
            "authd's main process is OOM-immune, so peinit read it as Critical")
        t:assert_eq(oom_score_adj("eventd"), "-1000",
            "and so is eventd's")
        t:assert_eq(oom_score_adj("pt-normal"), "0",
            "while an ErrorControl=Normal service is left at the default, "
            .. "so -1000 distinguishes rather than being what every service gets")
    end)

test("a dependent blocked on a dependency that never satisfies fails on its own clock",
    {
        spec = {
            "peinit *lostdep.a-blocked-dependent-fails-when-its-operation-lifetime-expires",
            "peinit *lostdep.the-start-timeout-runs-from-when-the-operation-was-created",
        },
    },
    function(t)
        -- pt-slow is pulled in by the start of its dependent and stays
        -- in Starting; pt-wait therefore never becomes runnable. The
        -- start returns when pt-wait's own operation lifetime runs out.
        local before = tonumber(vm:run("date +%s").stdout:match("%d+"))
        local start = vm:run("svctl start pt-wait")
        local after = tonumber(vm:run("date +%s").stdout:match("%d+"))
        local elapsed = after - before

        t:assert(start.exit_code ~= 0,
            "the blocked start failed rather than hanging: " .. start.stdout)
        t:assert_contains(start.stderr, "OPERATION_TIMEOUT",
            "and failed by running out of operation lifetime")

        -- The arithmetic. pt-wait's own StartTimeout is 8 seconds and
        -- pt-slow's is 200: a deadline taken from the dependency, or one
        -- that only started counting once pt-wait itself began running,
        -- could not have expired here at all. The band is loose on the
        -- upper side because this is a real VM, and tight on the lower
        -- side because that is the half that would catch a deadline
        -- taken from the wrong service.
        t:assert(elapsed >= WAIT_TIMEOUT_SECS - 1,
            ("the wait lasted about its own StartTimeout, not less: %ds"):format(elapsed))
        t:assert(elapsed < WAIT_TIMEOUT_SECS * 3,
            ("and not the dependency's 200s: %ds"):format(elapsed))

        -- The dependency is still sitting in Starting, so the dependent
        -- did not fail because the dependency failed.
        local slow = json.decode(vm:run("svctl --json status pt-slow").stdout)
        t:assert_eq(slow.state, "starting",
            "the dependency was still starting when the dependent gave up")

        -- And the dependent never ran: the timeout was spent queued
        -- behind the dependency rather than executing.
        local ran = vm:run("ls /pt-wait-ran")
        t:assert(ran.exit_code ~= 0,
            "the dependent never executed its image: " .. ran.stdout)
        t:assert(not vm:console():read_log():find("peinit: service pt%-wait started"),
            "and peinit never reported it started")
    end)
