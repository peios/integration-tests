-- peinit TRM §12.1 — the four paths that initiate a shutdown: the
-- control socket, a signal to PID 1, the power button, and a Critical
-- service that has run out of restart budget.
--
-- Three things shape every file in this chapter.
--
-- The subject destroys the machine it is tested on, so the console is
-- the oracle. `vm:console():read_log()` reads a file on the host and
-- keeps answering after the guest is gone; `vm:run` does not. Everything
-- a test needs is therefore gathered before the shutdown is triggered,
-- and asserted against the console afterwards.
--
-- Every boot here passes `peios.quiet=0`. The image's `login-console`
-- and `atriumd` own peinit's console once they are up, and at the
-- default `peios.quiet=1` peinit stays out of a terminal a service owns
-- — which silences the whole shutdown narrative except its Critical
-- lines. `peios.quiet=0` changes only what peinit is willing to print,
-- not what it does, and it is the difference between an oracle and
-- nothing at all.
--
-- Every test settles the boot before triggering anything. A shutdown
-- requested while a service is still Starting takes PID 1 into recovery
-- (PEI-826, asserted in shutdown-boot.test.lua), which would otherwise
-- turn every test in the chapter into an intermittent failure.
--
-- `peinit.claim(1)` and one VM alive at a time: a boot is about two
-- seconds here, so a test that needs three machines takes three of them
-- in turn rather than holding three at once.

local peinit = require("helpers.peinit")
peinit.claim(1)

--- Boot, run `body(vm)`, and release the VM before returning.
---
--- Releasing is what keeps the file's peak at one. A machine that has
--- powered itself off still holds provium's reservation until it is
--- closed, so a test that boots a second one without this fails on the
--- claim rather than queueing.
local function with_vm(opts, body)
    local vm = peinit.boot(opts)
    local ok, err = pcall(body, vm)
    pcall(function() vm:shutdown() end)
    if not ok then error(err, 0) end
end

--- Wait until nothing in the service table is still Starting.
local function settle(vm)
    wait_until(function()
        return not vm:run("svctl --json list").stdout:find('"state":"starting"', 1, true)
    end, { timeout = 60, interval = 0.5, desc = "the boot to settle" })
end

--- Issue something that ends the machine. The guest may die mid-command,
--- which is not a failure of the command.
local function trigger(vm, command)
    pcall(function() vm:run(command, { timeout = 30 }) end)
end

-- A service that ignores SIGTERM, so peinit has to wait out its
-- StopTimeout. A loop of short sleeps rather than one long one: SIGTERM
-- goes to the whole cgroup, and a single `sleep` child dies on the first
-- signal and takes the shell's exit with it.
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

test("the control socket's shutdown command names a kind, and each kind reaches its own kernel action",
    {
        spec = {
            "peinit *sdtrig.a-shutdown-command-names-poweroff-reboot-or-halt",
            "peinit *graceful.the-final-action-is-reboot2-with-the-kinds-command",
        },
    },
    function(t)
        -- The kernel names the reboot(2) command it was given on its way
        -- out, which is the only place the three RB_ constants are
        -- distinguishable from outside peinit: RB_POWER_OFF prints
        -- "Power down", RB_AUTOBOOT "Restarting system", RB_HALT_SYSTEM
        -- "System halted".
        local kinds = {
            { "poweroff", "peinit: shutdown Poweroff started", "reboot: Power down" },
            { "reboot", "peinit: shutdown Reboot started", "reboot: Restarting system" },
            { "halt", "peinit: shutdown Halt started", "reboot: System halted" },
        }
        for _, case in ipairs(kinds) do
            local kind, banner, kernel = case[1], case[2], case[3]
            with_vm({ name = "kind-" .. kind, append = "peios.quiet=0" }, function(vm)
                settle(vm)
                trigger(vm, "svctl shutdown " .. kind)
                vm:console():expect(banner, 30)
                vm:console():expect(kernel, 60)
                t:assert(true, kind .. " reached " .. kernel)
            end)
        end
    end)

test("SIGINT reboots, SIGTERM and SIGPWR power off",
    { spec = "peinit *sdtrig.sigint-reboots-and-sigterm-and-sigpwr-power-off" },
    function(t)
        -- `kill` is the shell's builtin, so this keeps working after
        -- registryd and the rest have gone. SIGPWR has no portable name
        -- in the guest's shell, so it goes by number: 30 on x86-64.
        local signals = {
            { "-INT", "peinit: shutdown Reboot started" },
            { "-TERM", "peinit: shutdown Poweroff started" },
            { "-30", "peinit: shutdown Poweroff started" },
        }
        for _, case in ipairs(signals) do
            local signal, banner = case[1], case[2]
            with_vm({ name = "sig" .. signal:gsub("-", ""), append = "peios.quiet=0" }, function(vm)
                settle(vm)
                trigger(vm, "kill " .. signal .. " 1")
                vm:console():expect(banner, 30)
                t:assert(true, "kill " .. signal .. " 1 gave: " .. banner)
            end)
        end
    end)

test("three SIGINTs inside five seconds force an immediate reboot, even once a graceful one has begun",
    {
        spec = {
            "peinit *sdtrig.three-sigints-in-five-seconds-force-an-immediate-reboot",
            "peinit *sdtrig.three-presses-force-even-after-a-graceful-shutdown-has-begun",
        },
    },
    function(t)
        -- The press is recorded before the already-shutting-down check,
        -- so the first SIGINT starting a graceful reboot does not stop
        -- the next two forcing one. What makes the difference visible is
        -- a service that ignores SIGTERM with a StopTimeout far longer
        -- than the test: the graceful path would sit on it for 120
        -- seconds and then print "shutdown killing pt-stubborn"; the
        -- forced path SIGKILLs every cgroup and reboots without ever
        -- reaching that deadline.
        --
        -- All three presses go in one guest command, a second apart.
        -- Both halves of that matter. A second apart, because SIGINT is
        -- a standard signal and a second one arriving while the first is
        -- still pending is merged rather than queued — three sent back
        -- to back can reach the signalfd as one. And in one command,
        -- because the window is a sliding five seconds measured from
        -- when peinit *reads* each press: waiting on the console between
        -- them lets a loaded host age the first one out, and then there
        -- are only ever two in the window.
        with_vm({
            name = "forced",
            append = "peios.quiet=0",
            files = peinit.seed("pt-forced", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                stubborn(120),
            }),
        }, function(vm)
            settle(vm)
            t:assert(vm:run("svctl --json status pt-stubborn").stdout
                :find('"state":"active"', 1, true),
                "the service that will hold the graceful reboot open is running")

            trigger(vm, "kill -INT 1; sleep 1; kill -INT 1; sleep 1; kill -INT 1")
            vm:console():expect("reboot: Restarting system", 60)

            local log = vm:console():read_log()
            -- The first press did begin a graceful reboot: its banner
            -- and its SIGTERM to the stubborn service are both on the
            -- console, written at the end of the turn that handled it.
            t:assert(log:find("peinit: shutdown Reboot started", 1, true),
                "the first press began a graceful reboot")
            t:assert(log:find("peinit: shutdown stopping pt-stubborn", 1, true),
                "which had got as far as asking the stubborn service to stop")
            -- And the machine still went down long before that service's
            -- 120-second StopTimeout could expire, which only the forced
            -- path does.
            t:assert(not log:find("peinit: shutdown killing pt-stubborn", 1, true),
                "the machine went down before the graceful StopTimeout could expire, " ..
                "so the reboot was forced rather than waited out")
        end)
    end)

test("a power button press is a graceful poweroff, and the release that follows it is not a second one",
    {
        spec = {
            "peinit *sdtrig.a-power-button-press-is-a-graceful-poweroff",
            "peinit *sdtrig.only-a-key-press-initiates",
        },
    },
    function(t)
        -- `vm:power_button()` is QMP `system_powerdown`, which is the
        -- machine's ACPI power button. The guest's ACPI button driver
        -- turns it into an EV_KEY/KEY_POWER press followed immediately
        -- by a release on /dev/input/event*, so this exercises both
        -- halves of the rule at once: the press initiates, and the
        -- release does not — a second initiation would be answered with
        -- "already in progress" and there is none.
        with_vm({ name = "pbutton", append = "peios.quiet=0" }, function(vm)
            settle(vm)
            local devices = vm:run("ls /dev/input")
            t:assert(devices.stdout:find("event", 1, true),
                "the guest has input event devices for peinit to have opened: " ..
                devices.stdout)

            vm:power_button()
            vm:console():expect("peinit: shutdown Poweroff started", 30)
            vm:console():expect("reboot: Power down", 60)

            local log = vm:console():read_log()
            t:assert(not log:find("already in progress", 1, true),
                "only the press initiated; the release that followed it did not")
        end)
    end)

test("a Critical service out of restart budget reboots the machine without a graceful sequence",
    {
        spec = {
            "peinit *sdtrig.a-critical-service-out-of-restart-budget-reboots-immediately",
            "peinit *final.the-three-paths-do-different-amounts-of-work",
        },
    },
    function(t)
        -- No boot trigger: the service is started by hand once the
        -- machine has settled, so the reboot cannot race the boot this
        -- test is standing on. RestartMaxRetries=1 with a one-second
        -- delay spends the budget in a couple of seconds.
        --
        -- The Critical path is the one that does the least work: no stop
        -- waves, no seed, no unmount, just sync and reboot. What that
        -- looks like from here is a machine that reboots with no
        -- "peinit: shutdown" line of any kind on the console — the
        -- graceful sequence, whose every step announces itself, was
        -- never entered.
        --
        -- The lines peinit means to print on the way out —
        -- "critical service X failed" and "exhausted its restart budget;
        -- rebooting" — are NOT asserted, because they never arrive. A
        -- turn's console output is written after the turn's work, and
        -- this turn's work ends in a reboot(2) that does not return. So
        -- the evidence is the two starts (an original and the one
        -- restart the budget allowed) followed by the kernel's own line.
        with_vm({
            name = "critical",
            append = "peios.quiet=0",
            files = peinit.seed("pt-critical", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                { path = [[Machine\System\Services\pt-crit]], values = {
                    { name = "ImagePath", type = "sz", data = "/bin/false" },
                    { name = "Identity", type = "sz", data = "SYSTEM" },
                    { name = "Readiness", type = "dword", data = 1 },
                    { name = "RestartPolicy", type = "dword", data = 2 },
                    { name = "RestartMaxRetries", type = "dword", data = 1 },
                    { name = "RestartDelay", type = "dword", data = 1 },
                    { name = "RestartWindow", type = "dword", data = 60 },
                    { name = "ErrorControl", type = "dword", data = 1 },
                } },
            }),
        }, function(vm)
            settle(vm)
            local before = vm:console():read_log()
            t:assert(not before:find("peinit: shutdown ", 1, true),
                "nothing had begun a shutdown before the Critical service was started")

            trigger(vm, "svctl --no-wait start pt-crit")
            vm:console():expect("reboot: Restarting system", 60)

            local log = vm:console():read_log()
            local after = log:sub(#before)
            local starts = 0
            for _ in after:gmatch("peinit: service pt%-crit started") do starts = starts + 1 end
            t:assert_eq(starts, 2,
                "the service started, was restarted once, and the budget was then spent")
            t:assert(not log:find("peinit: shutdown ", 1, true),
                "and the machine rebooted without entering the graceful sequence")
        end)
    end)
