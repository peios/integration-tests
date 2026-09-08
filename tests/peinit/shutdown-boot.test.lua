-- peinit TRM §12.2 step 1 and "Shutdown during boot" — what setting the
-- shutdown flag stops, and what happens when it is set while Phase 2 is
-- still bringing the machine up.
--
-- These are all negative claims: nothing starts. A negative is only
-- worth anything if the thing would otherwise have happened, so each
-- test arranges a service that demonstrably does start on its own — a
-- restart policy that has just been exercised, a timer that has just
-- fired twice — and then shows the shutdown stopping it. The window to
-- observe any of it is held open by a service that ignores SIGTERM and
-- has to be waited out.
--
-- `peios.quiet=0` on every boot: at the default the image's console
-- login owns peinit's terminal and none of the lines below are printed.

local peinit = require("helpers.peinit")
peinit.claim(1)

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

--- How many times `pattern` appears after the shutdown began.
local function count_after_shutdown(vm, pattern)
    local log = vm:console():read_log()
    local at = log:find("peinit: shutdown Poweroff started", 1, true)
    if not at then return nil end
    local n = 0
    for _ in log:sub(at):gmatch(pattern) do n = n + 1 end
    return n
end

test("a service with a restart policy that has just used it is not started again once the flag is set",
    { spec = "peinit *graceful.no-new-service-starts-once-the-flag-is-set" },
    function(t)
        -- pt-flap dies a second after it starts and is always restarted,
        -- so the console accumulates a "service pt-flap started" line
        -- every couple of seconds — which makes "it stopped happening"
        -- an observation rather than an absence. pt-stubborn then holds
        -- the shutdown open for long enough that several more would have
        -- landed.
        with_vm({
            name = "nostart",
            append = "peios.quiet=0",
            files = peinit.seed("pt-nostart", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                { path = [[Machine\System\Services\pt-flap]], values = {
                    { name = "ImagePath", type = "sz", data = "/bin/sleep" },
                    { name = "Arguments", type = "multi", data = { "1" } },
                    { name = "Identity", type = "sz", data = "SYSTEM" },
                    { name = "Readiness", type = "dword", data = 1 },
                    { name = "RestartPolicy", type = "dword", data = 2 },
                    { name = "RestartDelay", type = "dword", data = 1 },
                    { name = "RestartMaxRetries", type = "dword", data = 500 },
                    { name = "RestartWindow", type = "dword", data = 3600 },
                    { name = "Triggers", type = "multi", data = { "boot" } },
                } },
                stubborn(25),
            }),
        }, function(vm)
            settle(vm)
            wait_until(function()
                local n = 0
                for _ in vm:console():read_log():gmatch("peinit: service pt%-flap started") do
                    n = n + 1
                end
                return n >= 3
            end, { timeout = 60, interval = 0.5, desc = "pt-flap to restart a few times" })

            trigger(vm, "svctl shutdown poweroff")
            vm:console():expect("peinit: shutdown stopping pt-stubborn", 30)
            -- Several restart delays' worth of shutdown, all of which
            -- pt-stubborn is holding open.
            pause(8)

            t:assert_eq(count_after_shutdown(vm, "peinit: service pt%-flap started"), 0,
                "a service that had been restarting every second was not started " ..
                "once more after the shutdown flag was set")
        end)
    end)

test("a timer firing during the shutdown window starts nothing",
    { spec = "peinit *graceful.a-timer-firing-during-shutdown-is-a-no-op" },
    function(t)
        -- A one-second calendar schedule, so the timerfd is firing
        -- continuously on both sides of the shutdown. peinit gates the
        -- handler rather than the fd: the firings keep happening and
        -- stop producing starts.
        with_vm({
            name = "timer",
            append = "peios.quiet=0",
            files = peinit.seed("pt-timer", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                { path = [[Machine\System\Services\pt-tick]], values = {
                    { name = "ImagePath", type = "sz", data = "/bin/true" },
                    { name = "Type", type = "dword", data = 1 },
                    { name = "Identity", type = "sz", data = "SYSTEM" },
                    { name = "Triggers", type = "multi", data = { "timer:*:*:*" } },
                } },
                stubborn(25),
            }),
        }, function(vm)
            settle(vm)
            wait_until(function()
                local n = 0
                for _ in vm:console():read_log():gmatch("peinit: service pt%-tick started") do
                    n = n + 1
                end
                return n >= 2
            end, { timeout = 60, interval = 0.5, desc = "the timer to fire twice" })

            trigger(vm, "svctl shutdown poweroff")
            vm:console():expect("peinit: shutdown stopping pt-stubborn", 30)
            pause(8)

            t:assert_eq(count_after_shutdown(vm, "peinit: service pt%-tick started"), 0,
                "eight seconds of one-second firings started nothing")
        end)
    end)

test("a shutdown requested while Phase 2 is still running takes effect immediately",
    {
        spec = "peinit *graceful.a-shutdown-during-phase-2-takes-effect-immediately",
        -- PEI-826: cancelling a Starting service's unforked job removes
        -- the job record while its process-setup fd is still registered,
        -- and the next readiness on that fd raises UnknownJob out of the
        -- runtime loop, which takes PID 1 into recovery instead of
        -- finishing the shutdown.
        tags = { "known-bug" },
    },
    function(t)
        -- Deliberately NOT settled, and waited only as far as "phase2
        -- boot starting" rather than the usual "boot complete", so the
        -- command lands while services are still being launched. That
        -- is the case the manual says is supported: Starting services
        -- are SIGKILLed, whatever reached Active is stopped gracefully,
        -- and the boot is abandoned.
        --
        -- The sixteen extra services are there to widen the window. What
        -- breaks is a service whose launch has forked but whose setup
        -- status peinit has not read yet — a job in Created — and one
        -- machine's worth of image services gives only a few instants of
        -- that. Sixteen more launching at the same moment makes it the
        -- ordinary case rather than a race the test loses half the time.
        local filler = {
            { path = [[Machine\System]] },
            { path = [[Machine\System\Services]] },
        }
        for i = 1, 16 do
            filler[#filler + 1] = {
                path = [[Machine\System\Services\pt-fill-]] .. i,
                values = {
                    { name = "ImagePath", type = "sz", data = "/bin/sleep" },
                    { name = "Arguments", type = "multi", data = { "100000" } },
                    { name = "Identity", type = "sz", data = "SYSTEM" },
                    { name = "Readiness", type = "dword", data = 1 },
                    { name = "RestartPolicy", type = "dword", data = 0 },
                    { name = "Triggers", type = "multi", data = { "boot" } },
                },
            }
        end
        with_vm({
            name = "duringboot",
            append = "peios.quiet=0",
            stage = "phase2_starting",
            files = peinit.seed("pt-duringboot", filler),
        }, function(vm)
            trigger(vm, "svctl shutdown poweroff")

            local down = pcall(function()
                vm:console():expect("reboot: Power down", 90)
            end)
            local log = vm:console():read_log()
            local recovery = log:match("peinit: entering recovery[^\r\n]*")
            t:assert(log:find("peinit: shutdown Poweroff started", 1, true) or recovery,
                "the shutdown request reached peinit")
            t:assert(not recovery,
                "a shutdown during Phase 2 did not take PID 1 into recovery: " ..
                tostring(recovery))
            t:assert(down, "and the machine reached its final action")
        end)
    end)
