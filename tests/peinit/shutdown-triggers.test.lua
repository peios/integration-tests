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
    -- pt-signal, staged TCB-signed: PID 1 is TCB-signed and refuses a
    -- signal from the shell's unsigned `kill`.
    opts.files = peinit.merge(opts.files or {}, peinit.tool("pt-signal", { signed = true }))
    local vm = peinit.boot(opts)
    local ok, err = pcall(body, vm)
    pcall(function() vm:shutdown() end)
    if not ok then error(err, 0) end
end

--- Wait until nothing in the service table has a boot operation in
--- flight, this file's own services included.
local function settle(vm) peinit.settle(vm, { all = true }) end

--- Issue something that ends the machine. The guest may die mid-command,
--- which is not a failure of the command.
local function trigger(vm, command)
    pcall(function() vm:run(command, { timeout = 30 }) end)
end

--- Wait `seconds` on the host, without asking the guest for anything.
local function pause(seconds)
    pcall(wait_until, function() return false end,
        { timeout = seconds, interval = 0.25, desc = "a fixed pause" })
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
        -- pt-signal, staged TCB-signed by with_vm: PID 1 is TCB-signed and
        -- refuses the shell's unsigned `kill`. Numbers, x86-64: SIGINT 2,
        -- SIGTERM 15, SIGPWR 30.
        local signals = {
            { "INT", 2, "peinit: shutdown Reboot started" },
            { "TERM", 15, "peinit: shutdown Poweroff started" },
            { "PWR", 30, "peinit: shutdown Poweroff started" },
        }
        for _, case in ipairs(signals) do
            local signal, number, banner = case[1], case[2], case[3]
            with_vm({ name = "sig" .. signal, append = "peios.quiet=0" }, function(vm)
                settle(vm)
                trigger(vm, "/usr/bin/pt-signal 1 " .. number)
                vm:console():expect(banner, 30)
                t:assert(true, "SIG" .. signal .. " to PID 1 gave: " .. banner)
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

            trigger(vm, "/usr/bin/pt-signal 1 2 3 1") -- SIGINT, three times, 1 s apart
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
            -- 120-second StopTimeout could expire (the 60-second wait
            -- above is the bound), which only the forced path does --
            -- and, since PEI-827 lets a finalising turn's console output
            -- out, it says so. The forced path kills every cgroup and
            -- announces each kill with the same "shutdown killing" line
            -- the graceful escalation uses, so that line no longer tells
            -- the two apart; the banner does.
            t:assert(log:find("peinit: shutdown forced reboot requested", 1, true),
                "the third press forced the reboot rather than waiting the " ..
                "graceful StopTimeout out")
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
        -- The lines peinit prints on the way out — "critical service X
        -- failed" and "exhausted its restart budget; rebooting" — used
        -- not to arrive: a turn's console output was written after the
        -- turn's work, and this turn's work ended in a reboot(2) that
        -- does not return. Since PEI-827 the turn writes its console
        -- output before taking a final action, so both lines precede
        -- the kernel's own. The evidence is the two starts (an original
        -- and the one restart the budget allowed), the two lines, and
        -- then the kernel's.
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
            t:assert(after:find("peinit: critical service pt-crit failed: ", 1, true),
                "peinit said which Critical service failed before it rebooted")
            local budget = after:find(
                "peinit: critical service pt-crit exhausted its restart budget; rebooting",
                1, true)
            t:assert(budget, "and that the restart budget was what ran out")
            t:assert(budget < after:find("reboot: Restarting system", 1, true),
                "and said so before the kernel's own line, not never")
            t:assert(not log:find("peinit: shutdown ", 1, true),
                "and the machine rebooted without entering the graceful sequence")
        end)
    end)

--- PID 1's descriptors, as `fd -> target` pairs from /proc/1/fd. Read by
--- the agent: PID 1 is TCB-signed, and PIP refuses the shell's `ls` its
--- /proc (helpers/peinit.lua).
local function pid1_fds(vm)
    return peinit.fds(vm, 1)
end

--- The descriptors registered with PID 1's event loop, as a set, read from
--- the `tfd:` lines of its epoll descriptor's fdinfo.
local function pid1_registered(vm)
    local epoll
    for fd, target in pairs(pid1_fds(vm)) do
        if target:find("[eventpoll]", 1, true) then epoll = fd end
    end
    assert(epoll, "PID 1 has an epoll descriptor")
    local out = {}
    local info = assert(peinit.proc(vm, 1, "fdinfo/" .. epoll))
    for tfd in info:gmatch("tfd:%s*(%d+)") do
        out[tonumber(tfd)] = true
    end
    return out
end

--- PID 1's CPU time so far, in clock ticks: utime plus stime.
local function pid1_ticks(vm)
    local stat = assert(peinit.proc(vm, 1, "stat"))
    -- The fields after the parenthesised command; utime and stime are the
    -- 12th and 13th of them.
    local fields = {}
    for field in stat:match("%) (.*)$"):gmatch("%S+") do fields[#fields + 1] = field end
    return tonumber(fields[12]) + tonumber(fields[13])
end

test("the power button path survives a missing /dev/input, and the socket and signal paths remain",
    { spec = "peinit *sdtrig.the-power-button-path-is-fail-soft" },
    function(t)
        -- An autorun runs before the runtime opens the input devices, so
        -- one that moves /dev/input aside hands peinit a machine without
        -- one. The move is undone by nothing: this boot has no input
        -- devices as far as peinit is concerned.
        with_vm({
            name = "noinput",
            append = "peios.quiet=0",
            files = {
                ["lcl/policy/autorun.d/90-pt-hide-input.sh"] = {
                    "#!/bin/sh\nmv /dev/input /dev/pt-input-hidden && echo pt-input-hidden\n",
                    exec = true,
                },
            },
        }, function(vm)
            t:assert(vm:console():read_log():find("pt-input-hidden", 1, true),
                "/dev/input was out of the way before the runtime looked for it")
            settle(vm)
            for fd, target in pairs(pid1_fds(vm)) do
                t:assert(not target:find("input", 1, true),
                    "PID 1 holds no input device (fd " .. fd .. " is " .. target .. ")")
            end
            -- The boot went on without it, the control socket answers…
            vm:run("svctl --json list"):assert_ok()
            -- …and a signal still shuts the machine down.
            trigger(vm, "/usr/bin/pt-signal 1 15") -- SIGTERM
            vm:console():expect("peinit: shutdown Poweroff started", 30)
            vm:console():expect("reboot: Power down", 60)
        end)
    end)

test("an input device that cannot be opened or registered, or that fails later, costs only that device",
    { spec = "peinit *sdtrig.the-power-button-path-is-fail-soft" },
    function(t)
        -- Two bad entries staged into /dev/input before the runtime opens
        -- it: event90 is a dangling symlink, which cannot be opened;
        -- event91 is an empty regular file, which opens but which epoll
        -- refuses to register. Then, at runtime, the AT keyboard is
        -- unbound from its driver: its evdev node goes away, and the
        -- descriptor PID 1 registered for it starts failing reads —
        -- EPOLLHUP, level-triggered, for as long as it stays registered.
        with_vm({
            name = "badinput",
            append = "peios.quiet=0",
            files = {
                ["lcl/policy/autorun.d/90-pt-bad-input.sh"] = {
                    "#!/bin/sh\nln -s /pt-nowhere /dev/input/event90\n"
                        .. ": > /dev/input/event91\necho pt-bad-input\n",
                    exec = true,
                },
            },
        }, function(vm)
            t:assert(vm:console():read_log():find("pt-bad-input", 1, true),
                "the bad entries were in /dev/input before the runtime looked")
            settle(vm)

            local held, keyboard = {}, nil
            local devices = vm:run("cat /proc/bus/input/devices").stdout
            local node = devices:match('N: Name="AT Translated Set 2 keyboard".-H: Handlers=[^\n]-(event%d+)')
            t:assert(node, "the guest has an AT keyboard: " .. devices)
            for fd, target in pairs(pid1_fds(vm)) do
                local name = target:match("^/dev/input/(event%d+)")
                if name then held[name] = fd end
                if name == node then keyboard = fd end
            end
            t:assert(not held.event90, "the device that could not be opened was passed over")
            t:assert(not held.event91,
                "the one that could not be registered was let go rather than kept")
            t:assert(keyboard, "the keyboard's device is held: " .. node)
            t:assert(pid1_registered(vm)[keyboard],
                "and registered with PID 1's event loop (fd " .. keyboard .. ")")

            -- The keyboard goes away under PID 1.
            vm:run("echo -n serio0 > /sys/bus/serio/drivers/atkbd/unbind"):assert_ok()
            wait_until(function() return not pid1_registered(vm)[keyboard] end,
                { timeout = 15, interval = 0.25,
                  desc = "the failing descriptor to be removed from the event loop" })
            t:assert(true, "the descriptor that failed to read was removed from the event loop")

            -- A level-triggered hangup left registered would have PID 1 at
            -- a full CPU. Three seconds of it idle instead.
            local before = pid1_ticks(vm)
            pause(3)
            local spent = pid1_ticks(vm) - before
            t:assert(spent < 50,
                "PID 1 used " .. spent .. " ticks in three seconds: it is not spinning")

            -- The rest of the path is untouched: the power button still
            -- powers the machine off.
            vm:power_button()
            vm:console():expect("peinit: shutdown Poweroff started", 30)
            vm:console():expect("reboot: Power down", 60)
        end)
    end)
