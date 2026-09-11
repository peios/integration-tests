-- peinit TRM §6.4 and §6.6 where they meet a shutdown — what a failure
-- does to a machine that is already going down, whose OnFailure handler
-- runs when, and the deadline a timeout extension buys a service that is
-- being stopped.
--
-- The chapter-6 rules are about ordinary running; each of these is the
-- rule's shutdown clause or its edge, so they live with the shutdown
-- files and read the shutdown's own console narrative. `peios.quiet=0`
-- on every boot, so that narrative reaches the console, and each boot
-- settles its own services before it triggers anything (PEI-826).
--
-- Two of these need a machine that survives a Critical reboot, to see
-- what peinit did not do on the way to it. `pt-shutwatch`
-- (helpers/shutdown.lua) holds the final action back: with PID 1's
-- SeShutdownPrivilege disabled its reboot(2) fails with EPERM, and the
-- machine is still there to be asked afterwards.

local peinit = require("helpers.peinit")
local shutdown = require("helpers.shutdown")
peinit.claim(1)

local function with_vm(opts, body)
    local vm = peinit.boot(opts)
    local ok, err = pcall(body, vm)
    pcall(function() vm:shutdown() end)
    if not ok then error(err, 0) end
end

local function pause(seconds)
    pcall(wait_until, function() return false end,
        { timeout = seconds, interval = 0.25, desc = "a fixed pause" })
end

local function trigger(vm, command)
    pcall(function() vm:run(command, { timeout = 30 }) end)
end

local function status(vm, service)
    return json.decode(vm:run("svctl --json status " .. service).stdout)
end

local function main_pid(vm, service)
    return wait_until(function()
        local view = status(vm, service)
        return view.state == "active" and view.current_job and view.current_job.pid or nil
    end, { timeout = 60, interval = 0.5, desc = service .. " to be running" })
end

--- The console from `from` on.
local function since(vm, from)
    return vm:console():read_log():sub(from + 1)
end

local function resident(name, extra)
    local values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "100000" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
    }
    for _, value in ipairs(extra or {}) do values[#values + 1] = value end
    return { path = [[Machine\System\Services\]] .. name, values = values }
end

--- A Critical service whose first failure spends its whole budget, with an
--- OnFailure handler. Outside a shutdown that failure reboots the machine.
local function critical_owed(name, handler, extra)
    local values = {
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "ErrorControl", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 2 },
        { name = "RestartMaxRetries", type = "dword", data = 0 },
        { name = "OnFailure", type = "sz", data = handler },
    }
    for _, value in ipairs(extra or {}) do values[#values + 1] = value end
    return resident(name, values)
end

-- Ignores SIGTERM, so a graceful stop has to wait out its StopTimeout.
local function stubborn(name, stop_timeout, extra)
    local values = {
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi",
          data = { "-c", "trap '' TERM; while :; do sleep 1; done" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "StopTimeout", type = "dword", data = stop_timeout },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "Triggers", type = "multi", data = { "boot" } },
    }
    for _, value in ipairs(extra or {}) do values[#values + 1] = value end
    return { path = [[Machine\System\Services\]] .. name, values = values }
end

test("the OnFailure handler is skipped exactly when a reboot is owed, and never otherwise",
    { spec = "peinit *restart.the-handler-is-skipped-exactly-when-a-reboot-is-owed" },
    function(t)
        -- Two Critical services with handlers. pt-crit-never has
        -- RestartPolicy=Never, so its failure stays Failed with the crash
        -- as its cause: it is Critical, but no reboot is owed, and its
        -- handler has to run. pt-crit-owed spends its whole budget on
        -- its first failure: a reboot is owed, and its handler must not
        -- run — which only a machine that survives the reboot can show,
        -- so the witness holds the final action back.
        with_vm({
            name = "handlers",
            append = "peios.quiet=0",
            -- The staged seed is only there so the witness's seed
            -- directory exists; nothing here reads it.
            files = peinit.merge(shutdown.tool(),
                { ["var/state/peinit/random-seed"] = string.rep("pt-seed-", 64) },
                peinit.seed("pt-handlers", {
                    { path = [[Machine\System]] },
                    { path = [[Machine\System\Services]] },
                    resident("pt-crit-never", {
                        { name = "Triggers", type = "multi", data = { "boot" } },
                        { name = "ErrorControl", type = "dword", data = 1 },
                        { name = "RestartPolicy", type = "dword", data = 0 },
                        { name = "OnFailure", type = "sz", data = "pt-handler-never" },
                    }),
                    resident("pt-handler-never"),
                    critical_owed("pt-crit-owed", "pt-handler-owed"),
                    resident("pt-handler-owed"),
                })),
        }, function(vm)
            peinit.settle(vm, { all = true })

            -- Critical, failed, no reboot owed: the handler runs.
            local never = main_pid(vm, "pt-crit-never")
            local from = #vm:console():read_log()
            vm:run("kill -9 " .. never):assert_ok()
            vm:console():expect("peinit: service pt-handler-never started", 30)
            local view = status(vm, "pt-crit-never")
            t:assert_eq(view.state, "failed", "pt-crit-never failed")
            t:assert(view.cause ~= "restart_budget_exhausted",
                "with its crash as the cause, so no reboot was owed: " .. tostring(view.cause))
            t:assert(not since(vm, from):find("reboot:", 1, true),
                "the machine did not reboot")

            -- Critical, out of budget, reboot owed: the handler is skipped.
            local owed = main_pid(vm, "pt-crit-owed")
            shutdown.start(vm, { hold = 1000 })
            from = #vm:console():read_log()
            vm:run("kill -9 " .. owed):assert_ok()
            wait_until(function()
                return since(vm, from):find("sys_reboot %-> 0xffffffffffffffff")
            end, { timeout = 30, interval = 0.25, desc = "the owed reboot to be attempted" })
            local record = shutdown.record(since(vm, from))
            local reboots = shutdown.calls(record, "reboot")
            t:assert(reboots[1] and reboots[1].cmd == "0x1234567",
                "the reboot owed to pt-crit-owed was attempted: " .. shutdown.render(record))

            -- Time enough for a handler to have been queued and launched.
            pause(3)
            t:assert_eq(status(vm, "pt-crit-owed").cause, "restart_budget_exhausted",
                "pt-crit-owed failed out of budget")
            t:assert_eq(status(vm, "pt-handler-owed").state, "inactive",
                "and its handler was never started")
            t:assert(not since(vm, from):find("peinit: service pt-handler-owed started", 1, true),
                "no start of it was reported either")
        end)
    end)

--- A Critical service fails in the middle of a shutdown: the scenario
--- both tests below run, in two arrangements.
---
--- pt-crit is the same Critical, out-of-budget-at-once service as above —
--- the one whose failure outside a shutdown is a reboot. pt-hold ignores
--- SIGTERM for twenty seconds and depends on it, so pt-crit is in a later
--- wave: still running while pt-hold is waited out, and killed there.
---
--- `chain` is how many services stand between pt-hold and pt-crit. With
--- none, pt-crit shares the second wave with the image's own lpsd. With
--- two, it is in the fourth wave, one past the image's deepest, alone.
local function critical_during_shutdown(t, name, chain)
    local keys = {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
        critical_owed("pt-crit", "pt-handler"),
        resident("pt-handler"),
    }
    local first = "pt-crit"
    for i = chain, 1, -1 do
        local link = "pt-link-" .. i
        keys[#keys + 1] = resident(link, {
            { name = "Requires", type = "multi", data = { first } },
        })
        first = link
    end
    keys[#keys + 1] = stubborn("pt-hold", 20, {
        { name = "Requires", type = "multi", data = { first } },
    })

    with_vm({
        name = name,
        append = "peios.quiet=0",
        files = peinit.seed("pt-" .. name, keys),
    }, function(vm)
        peinit.settle(vm, { all = true })
        local pid = main_pid(vm, "pt-crit")

        trigger(vm, "svctl shutdown poweroff")
        vm:console():expect("peinit: shutdown stopping pt-hold", 30)
        local began = vm:console():read_log():find("peinit: shutdown Poweroff started", 1, true)
        t:assert_eq(status(vm, "pt-crit").state, "active",
            "pt-crit is still running, in a wave after pt-hold's")

        vm:run("kill -9 " .. pid):assert_ok()
        wait_until(function() return status(vm, "pt-crit").state == "failed" end,
            { timeout = 30, interval = 0.25, desc = "pt-crit's failure to be recorded" })
        pause(3)

        local during = vm:console():read_log():sub(began)
        t:assert(not during:find("reboot:", 1, true),
            "the failure did not reboot the machine")
        t:assert(not during:find("peinit: service pt-handler started", 1, true),
            "its OnFailure handler was not started")
        t:assert(not during:find("peinit: service pt-crit started", 1, true),
            "and it was not restarted")

        -- The system was already going down, and goes on down: to the
        -- shutdown's own final action, not the Critical reboot's, and not
        -- anywhere else.
        local ended = pcall(function() vm:console():expect("reboot: Power down", 60) end)
        local after = vm:console():read_log():sub(began)
        t:assert(not after:find("peinit: entering recovery", 1, true),
            "the shutdown did not end in recovery: "
            .. tostring(after:match("peinit: entering recovery[^\r\n]*")))
        t:assert(ended, "the machine powered off")
        t:assert(not after:find("reboot: Restarting system", 1, true),
            "as the shutdown asked, rather than rebooting")
    end)
end

test("a Critical failure during a shutdown is recorded, reboots nothing and starts no handler",
    {
        spec = {
            "peinit *graceful.a-critical-failure-during-shutdown-does-not-reboot",
            "peinit *restart.a-failure-during-shutdown-neither-reboots-nor-starts-a-handler",
        },
    },
    function(t)
        -- pt-crit alone in its wave, so nothing else is waiting when the
        -- wave comes round to a service that has already failed.
        critical_during_shutdown(t, "shutdown-critical-alone", 2)
    end)

test("a Critical failure during a shutdown, in a wave it shares, lets the shutdown finish",
    {
        spec = "peinit *graceful.a-critical-failure-during-shutdown-does-not-reboot",
        -- PEI-1086: a participant that fails
        -- after the plan is made and before its wave begins stays in the
        -- plan as an ordinary participant. If anything else in its wave is
        -- still running the wave is begun, begin_stop_wave asks for the
        -- failed one's running main job (supervisor/shutdown_wave/mod.rs:63,
        -- process_target), gets MissingRunningService, and the error ends
        -- PID 1's event loop: recovery, mid-shutdown.
        tags = { "known-bug" },
    },
    function(t)
        -- pt-crit shares the second wave with the image's lpsd, which is
        -- still running when that wave begins.
        critical_during_shutdown(t, "shutdown-critical-shared", 0)
    end)

--- A service that asks for more time: pt-extend (tests/tools/pt-extend.c)
--- as its main process, which ignores SIGTERM, reports ready, and then
--- sends EXTEND_TIMEOUT_USEC=`usec` once a second — at once, or once `go`
--- exists and then `count` times.
local function extender(name, stop_timeout, usec, go, count, extra)
    local args = { usec }
    if go then
        args[#args + 1] = go
        args[#args + 1] = tostring(count)
    end
    local values = {
        { name = "ImagePath", type = "sz", data = "/usr/bin/pt-extend" },
        { name = "Arguments", type = "multi", data = args },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 0 },
        { name = "StopTimeout", type = "dword", data = stop_timeout },
        { name = "RestartPolicy", type = "dword", data = 0 },
    }
    for _, value in ipairs(extra or {}) do values[#values + 1] = value end
    return { path = [[Machine\System\Services\]] .. name, values = values }
end

local LATE_GO = "/run/pt-late-go"

-- One boot serves both extension tests. Seconds from the shutdown, T:
--
--   pt-ext    wave 0, StopTimeout 3, asking for 40 s every second from
--             the moment it is ready until it is killed. Its fourfold cap
--             is 12 s from its wave, the global deadline 90: it is killed
--             at 12 — not at 3, and not at 40.
--   pt-front  wave 0, ignores SIGTERM for its StopTimeout of 16, and
--             requires pt-late, which is what keeps pt-late's wave back.
--   pt-late   wave 1, StopTimeout 5. Told to go once the shutdown has
--             begun, it asks for 60 s three times, a second apart, and
--             then keeps quiet — all long before its wave at T+16.
local extension_result, extension_error
local function extension_boot()
    if extension_result then return extension_result end
    if extension_error then error(extension_error, 0) end
    local ok, result = pcall(function()
        local vm = peinit.boot({
            name = "extensions",
            append = "peios.quiet=0",
            files = peinit.merge(peinit.tool("pt-extend"), peinit.seed("pt-extensions", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                extender("pt-ext", 3, "40000000", nil, nil,
                    { { name = "Triggers", type = "multi", data = { "boot" } } }),
                stubborn("pt-front", 16, {
                    { name = "Requires", type = "multi", data = { "pt-late" } },
                }),
                extender("pt-late", 5, "60000000", LATE_GO, 3),
            })),
        })
        local inner_ok, inner = pcall(function()
            peinit.settle(vm, { all = true })
            local pids = {}
            for _, service in ipairs({ "pt-ext", "pt-late", "pt-front" }) do
                pids[service] = main_pid(vm, service)
            end
            local from = #vm:console():read_log()
            trigger(vm, "svctl shutdown poweroff")
            vm:console():expect("peinit: shutdown stopping pt-ext", 30)
            vm:run("touch " .. LATE_GO):assert_ok()

            -- pt-late's three requests, delivered — sendmsg succeeded on
            -- all three — and all of them before its wave began.
            local wanted = "pid=" .. pids["pt-late"]
                .. " send rc=%d+ errno=0 EXTEND_TIMEOUT_USEC=60000000"
            local late_sent = pcall(function()
                wait_until(function()
                    local ok, text = pcall(function() return vm:read_file("/run/pt-extend.log") end)
                    if not ok then return nil end
                    local n = 0
                    for _ in text:gmatch(wanted) do n = n + 1 end
                    return n >= 3 or nil
                end, { timeout = 10, interval = 0.25, desc = "pt-late's three requests" })
            end)
            local late_sent_before_wave = late_sent
                and not since(vm, from):find("peinit: shutdown stopping pt-late", 1, true)

            -- pt-ext: not killed at its three-second StopTimeout, and killed
            -- once the fourfold cap is reached.
            pause(8)
            local ext_early = since(vm, from):find("peinit: shutdown killing pt-ext", 1, true) ~= nil
            local ext_killed = pcall(function()
                vm:console():expect("peinit: shutdown killing pt-ext", 12)
            end)

            -- pt-late: its wave begins when pt-front is killed, and it is
            -- then watched for ten seconds.
            local late_wave = pcall(function()
                wait_until(function()
                    return since(vm, from):find("peinit: shutdown stopping pt-late", 1, true)
                end, { timeout = 40, interval = 0.25, desc = "pt-late's wave" })
            end)
            pause(10)
            local log = since(vm, from)
            return {
                log = log,
                ext_early = ext_early,
                ext_killed = ext_killed,
                late_wave = late_wave,
                late_sent = late_sent,
                late_sent_before_wave = late_sent_before_wave,
                late_early = log:find("peinit: shutdown killing pt-late", 1, true) ~= nil,
            }
        end)
        pcall(function() vm:shutdown() end)
        if not inner_ok then error(inner, 0) end
        return inner
    end)
    if not ok then
        extension_error = result
        error(result, 0)
    end
    extension_result = result
    return result
end

test("during a shutdown an extension is capped at four times StopTimeout when that is the stricter cap",
    { spec = "peinit *wdog.during-shutdown-the-stricter-of-the-two-caps-wins" },
    function(t)
        local r = extension_boot()
        t:assert(not r.ext_early,
            "eight seconds into its wave pt-ext was not yet killed: its 40-second request "
            .. "had moved the deadline past its three-second StopTimeout")
        t:assert(r.ext_killed,
            "and it was killed by twenty, long before the forty it asked for: "
            .. "held to four times its StopTimeout, the stricter of the two caps")
    end)

test("during a shutdown an extension is held to the global deadline when that is the stricter cap",
    {
        spec = "peinit *wdog.during-shutdown-the-stricter-of-the-two-caps-wins",
        covered_by = "cargo:peinit2 supervisor::tests::notify::shutdown::shutdown_extend_timeout_takes_the_stricter_of_the_fourfold_and_global_caps",
        skip = "a deadline capped at the global ShutdownTimeout expires at the same instant as the global timeout itself, whose sweep kills every participant regardless, so from outside the two are the same event; runs under cargo test -p peinit2 --all-features --lib supervisor::tests::notify::shutdown::shutdown_extend_timeout_takes_the_stricter_of_the_fourfold_and_global_caps",
    },
    function(t) end)

test("an extension sent during a shutdown, before the service's stop wave, is remembered for it",
    {
        spec = "peinit *wdog.an-extension-before-the-services-stop-wave-is-remembered",
        -- PEI-1090: an Active service's
        -- EXTEND_TIMEOUT_USEC during a shutdown, before its wave has a
        -- deadline, is dropped: the shutdown path finds no stop deadline
        -- and returns, and the transition path finds a non-transitional
        -- state and returns (supervisor/notify/shutdown_timeout.rs:30-38,
        -- supervisor/notify/timeout_extension.rs:59-67). Its wave then
        -- starts it on a fresh StopTimeout.
        tags = { "known-bug" },
    },
    function(t)
        local r = extension_boot()
        t:assert(r.late_sent and r.late_sent_before_wave,
            "pt-late sent its three 60-second requests after the shutdown began and "
            .. "before its own wave did")
        t:assert(r.late_wave, "pt-late's wave began: " .. r.log:sub(-2000))
        local from = r.log:find("peinit: shutdown stopping pt-late", 1, true)
        t:assert(not r.late_early,
            "ten seconds into its wave pt-late — StopTimeout 5, and 60 seconds asked for "
            .. "before the wave began — had not been killed: the request was remembered "
            .. "and applied, up to its fourfold cap. From its wave on:\n"
            .. r.log:sub(from or 1, (from or 1) + 1500))
    end)
