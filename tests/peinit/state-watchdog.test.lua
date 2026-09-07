-- peinit TRM §6.6 — the watchdog.
--
-- Most of §6.6 is about two notification fields, `WATCHDOG_USEC` and
-- `EXTEND_TIMEOUT_USEC`, and the image ships no tool that can write to a
-- Unix datagram socket -- so nothing in this harness can send either.
-- What is left, and what this file is, is the half of the watchdog that
-- a definition alone decides: `WatchdogTimeout` arms a timer, a service
-- that does not ping it is failed for a missed ping, and zero arms
-- nothing.
--
-- Three services with the same process and the same readiness, differing
-- only in the watchdog interval and the restart policy. `/bin/sleep
-- 3600` cannot exit, cannot fail, and cannot notify, so the watchdog is
-- the only thing that can move any of them -- which is what makes "it
-- moved" evidence about the watchdog rather than about the process.

local peinit = require("helpers.peinit")
peinit.claim(1)

local function service(name, values)
    local base = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "Triggers", type = "multi", data = { "boot" } },
    }
    for _, value in ipairs(values) do base[#base + 1] = value end
    return { path = [[Machine\System\Services\]] .. name, values = base }
end

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },

    -- Armed, and restart-eligible: the missed ping should take the
    -- ordinary restart path. The long delay parks it in Backoff where a
    -- test can read it rather than cycling underneath one.
    service("pt-wd-armed", {
        { name = "WatchdogTimeout", type = "dword", data = 3 },
        { name = "RestartPolicy", type = "dword", data = 2 },
        { name = "RestartDelay", type = "dword", data = 30 },
        { name = "RestartMaxRetries", type = "dword", data = 5 },
    }),

    -- Armed, and not restart-eligible: the same missed ping, consulted
    -- against a policy that declines.
    service("pt-wd-never", {
        { name = "WatchdogTimeout", type = "dword", data = 3 },
        { name = "RestartPolicy", type = "dword", data = 0 },
    }),

    -- No WatchdogTimeout at all, which is the default of zero. Nothing
    -- pings it either, and nothing should happen to it.
    service("pt-wd-off", {
        { name = "RestartPolicy", type = "dword", data = 2 },
        { name = "RestartDelay", type = "dword", data = 30 },
        { name = "RestartMaxRetries", type = "dword", data = 5 },
    }),
}

local vm = peinit.boot({
    name = "watchdog",
    files = peinit.seed("pt-watchdog", SERVICES),
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

test("a service that misses its WatchdogTimeout is failed for the missed ping",
    {
        spec = {
            "peinit *wdog.watchdogtimeout-sets-the-ping-interval-and-zero-disables-it",
            "peinit *wdog.a-missed-ping-takes-the-ordinary-restart-path",
        },
    },
    function(t)
        -- `/bin/sleep 3600` cannot exit and cannot notify, so nothing
        -- but the watchdog can move this service.
        local view = settle("pt-wd-armed", "backoff",
            "pt-wd-armed to miss its watchdog")
        t:assert_eq(view.cause, "watchdog_timeout",
            "the cause names the missed keepalive")

        -- The ordinary restart path: Backoff, not Failed, because a
        -- restart was allowed and the budget held.
        t:assert_eq(view.state, "backoff",
            "and it is scheduled to start again rather than given up on")
    end)

test("a missed ping against RestartPolicy=Never is Failed rather than Backoff",
    { spec = "peinit *wdog.a-missed-ping-takes-the-ordinary-restart-path" },
    function(t)
        -- The same watchdog and the same silent process, consulted
        -- against a policy that declines: the missed ping goes through
        -- the restart evaluation like any other eligible cause, and the
        -- evaluation is what decides which way it lands.
        local view = settle("pt-wd-never", "failed",
            "pt-wd-never to be failed by its watchdog")
        t:assert_eq(view.cause, "watchdog_timeout",
            "on the same cause as the restart-eligible one")
        t:assert(not view.current_job,
            "and its process was taken with it")
    end)

test("WatchdogTimeout=0, the default, arms nothing",
    { spec = "peinit *wdog.watchdogtimeout-sets-the-ping-interval-and-zero-disables-it" },
    function(t)
        -- pt-wd-off runs the same silent process and declares no
        -- watchdog. Its two neighbours have already been moved by
        -- theirs, so enough time has passed for a three-second interval
        -- to have fired several times over.
        settle("pt-wd-armed", "backoff", "the armed service to have fired")
        local view = status("pt-wd-off")
        t:assert_eq(view.state, "active",
            "a service with no watchdog is untouched by not pinging one: " .. view.state)
        t:assert(view.current_job, "and still has its process")

        vm:run("sleep 5")
        t:assert_eq(status("pt-wd-off").state, "active",
            "and stays that way")
    end)
