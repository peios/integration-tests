-- Peinit TRM §11.3, event loop fairness — which of several ready sources
-- PID 1 handles first.
--
-- A ranking only shows when two sources are ready in the same epoll wait,
-- and an idle PID 1 answers every event the instant it arrives. So every
-- test here first keeps PID 1 busy, makes two things happen in a chosen
-- order while it is, and then lets it go: its next epoll wait returns both
-- at once, and what PID 1 did first says which it took first.
--
-- Busy is arranged through the one call PID 1 makes that waits on
-- somebody else. A service whose identity is not SYSTEM needs a token
-- from authd, and peinit asks for it from its own process, synchronously
-- (`boundary/linux_launch/authd.rs`, bounded at fifteen seconds). With
-- authd stopped, starting such a service leaves PID 1 sitting in that
-- recvmsg — not in epoll — while the kernel queues every event that would
-- have woken it onto its ready list, in the order they happen. Continuing
-- authd lets the start finish and the loop come round.
--
-- The order the two events arrive in is the design of each test. The
-- lower-ranked source is made ready FIRST, so that arrival order and
-- priority disagree; a loop that took events as they came would act on
-- it first, and only a ranking puts the other one ahead.
--
-- The shutdown deadline timer's place — below signals, above everything
-- else — is not reached: it is armed only during a shutdown, which is
-- itself the signal whose rank is in question. That part is the unit test
-- output-flood.test.lua's stub names.
--
-- The file's last test is not about ordering. It is what happened when the
-- first version of this file paused PID 1 with ptrace instead: see there.

local peinit = require("helpers.peinit")
peinit.claim(1)

local MEM, CPUS = "1G", 1

local function read_or_empty(vm, path)
    local ok, text = pcall(function() return vm:read_file(path) end)
    return ok and tostring(text) or ""
end

--- A service that makes PID 1 wait on authd when it is started. The
--- identity is one authd refuses, so the start ends in a plain failure the
--- moment authd answers — nothing is left Starting behind the test, which
--- matters to a test that then shuts the machine down (PEI-826).
local BLOCKER = {
    path = [[Machine\System\Services\pt-blocker]],
    values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
        { name = "Identity", type = "sz", data = "pt-nobody" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
    },
}

--- Stop authd and start pt-blocker, and return once PID 1 is waiting on
--- authd. Returns the function that lets it go.
---
--- svctl is run in the foreground, not backgrounded. A backgrounded
--- process whose shell exits is re-parented to PID 1, and its exit is then
--- a SIGCHLD for PID 1 — which would make PID 1's signalfd ready early, at
--- a moment nobody chose, and spoil every ordering below. `--no-wait` is
--- answered before the start reaches authd, so the foreground call returns.
local function hold_pid1(t, vm)
    local authd = vm:run("svctl status authd").stdout:match("pid: (%d+)")
    t:assert(authd, "authd is running")
    vm:run("kill -STOP " .. authd):assert_ok()
    vm:run("svctl start pt-blocker --no-wait"):assert_ok()
    wait_until(function()
        return read_or_empty(vm, "/proc/1/wchan"):find("unix_stream_read", 1, true)
    end, { timeout = 10, interval = 0.1, desc = "PID 1 to be waiting on authd" })
    return function()
        vm:run("kill -CONT " .. authd):assert_ok()
    end
end

--- The signals pending for PID 1, as a number. PID 1 blocks every signal
--- it takes through its signalfd, so while it is held a signal sent to it
--- sits here; which bits are set, and when, is the arrival order of the
--- signal source.
local function pending_signals(vm)
    local status = read_or_empty(vm, "/proc/1/status")
    local shared = tonumber(status:match("ShdPnd:%s*(%x+)") or "0", 16)
    local own = tonumber(status:match("SigPnd:%s*(%x+)") or "0", 16)
    return shared | own
end

local SIGINT_BIT, SIGCHLD_BIT = 1 << (2 - 1), 1 << (17 - 1)

test("a child's exit is reaped before a control request that arrived ahead of it",
    { spec = "peinit *flood.signals-are-handled-at-the-highest-priority" },
    function(t)
        local vm = peinit.boot({
            memory = MEM, cpus = CPUS,
            name = "fair-sigchld",
            files = peinit.merge(
                peinit.tool("pt-ctl"),
                peinit.seed("zz-pt-fair", {
                    { path = [[Machine\System]] },
                    { path = [[Machine\System\Services]] },
                    BLOCKER,
                    {
                        path = [[Machine\System\Services\pt-victim]],
                        values = {
                            { name = "ImagePath", type = "sz", data = "/bin/sleep" },
                            { name = "Arguments", type = "multi", data = { "3600" } },
                            { name = "Identity", type = "sz", data = "SYSTEM" },
                            { name = "Readiness", type = "dword", data = 1 },
                            { name = "Triggers", type = "multi", data = { "boot" } },
                            { name = "RestartPolicy", type = "dword", data = 0 },
                        },
                    },
                })
            ),
        })
        peinit.settle(vm, { all = true })
        local pid = vm:run("svctl status pt-victim").stdout:match("pid: (%d+)")
        t:assert(pid, "pt-victim is running")

        -- A control connection, accepted now, that asks about pt-victim
        -- three seconds from now — by which time PID 1 is held.
        vm:run("( /usr/bin/pt-ctl --log /run/pt-fair-ctl.log sleep 3 " ..
            [['{"command":"status","service":"pt-victim"}' ) > /dev/null 2>&1 &]]):assert_ok()
        wait_until(function() return read_or_empty(vm, "/run/pt-fair-ctl.log"):find("connect rc=0", 1, true) end,
            { timeout = 10, interval = 0.1, desc = "pt-ctl to connect" })
        vm:run("sleep 1")

        local release = hold_pid1(t, vm)

        -- First to arrive: the request. Second: pt-victim's death, which
        -- is a SIGCHLD for PID 1.
        wait_until(function() return read_or_empty(vm, "/run/pt-fair-ctl.log"):find("request-json", 1, true) end,
            { timeout = 10, interval = 0.1, desc = "the status request to be sent" })
        vm:run("sleep 1")
        t:assert_eq(pending_signals(vm), 0,
            "no signal was pending for PID 1 when the request arrived, so the request is first")
        vm:run("kill -9 " .. pid):assert_ok()
        vm:run("sleep 1")
        t:assert(pending_signals(vm) & SIGCHLD_BIT ~= 0,
            "and the SIGCHLD for pt-victim arrived after it")
        t:assert(not read_or_empty(vm, "/run/pt-fair-ctl.log"):find("reply", 1, true),
            "PID 1 had answered nothing while it was held")
        t:assert(read_or_empty(vm, "/proc/1/wchan"):find("unix_stream_read", 1, true),
            "and it was still waiting on authd when both events were in")

        release()
        local reply = wait_until(function()
            return read_or_empty(vm, "/run/pt-fair-ctl.log"):match("reply%-json ([^\n]*)")
        end, { timeout = 15, interval = 0.2, desc = "the status reply" })

        -- The answer to the request that arrived first already knows about
        -- the exit that arrived second: the SIGCHLD was reaped, and the
        -- service moved on, before the request was read.
        local after = vm:run("svctl --json status pt-victim").stdout:match('"state":"(%w+)"')
        local answered = reply:match('"state":"(%w+)"')
        t:assert(after and after ~= "active", "pt-victim's death was reaped: it is " .. tostring(after))
        t:assert_eq(answered, after,
            "and the request that arrived before it was answered after it: " .. reply)
    end)

--- One machine, two shutdown triggers that disagree about the kind, made
--- ready in `order` while PID 1 is held. Returns the console.
local function race_button_and_sigint(t, name, order)
    local vm = peinit.boot({
        memory = MEM, cpus = CPUS,
        name = name,
        -- The console is login-console's by now, and at the default quiet
        -- level peinit stays out of a terminal a service holds; `0` lets
        -- the shutdown narration through (see shutdown-triggers).
        append = "peios.quiet=0",
        files = peinit.seed("zz-pt-fair", {
            { path = [[Machine\System]] },
            { path = [[Machine\System\Services]] },
            BLOCKER,
        }),
    })
    peinit.settle(vm, { all = true })
    local release = hold_pid1(t, vm)
    t:assert_eq(pending_signals(vm), 0, name .. ": no signal was pending for PID 1 before either trigger")
    for _, trigger in ipairs(order) do
        if trigger == "button" then
            vm:power_button()
        else
            vm:run("kill -INT 1"):assert_ok()
        end
        vm:run("sleep 1")
    end
    t:assert_eq(pending_signals(vm), SIGINT_BIT,
        name .. ": SIGINT, and only SIGINT, was pending when PID 1 was let go")
    release()
    -- The first one PID 1 acts on decides the kind; the second is answered
    -- "already in progress".
    pcall(function() vm:console():expect("already in progress", 40) end)
    local log = vm:console():read_log()
    pcall(function() vm:shutdown() end)
    return log
end

test("the power button and a signal are taken in the order they came, whichever came first",
    { spec = "peinit *flood.the-power-button-shares-the-top-priority" },
    function(t)
        -- The button asks for a poweroff and SIGINT for a reboot, so the
        -- kind of the shutdown that starts names the one handled first.
        -- Both orders, because a button ranked below signals would lose
        -- the first race and one ranked above them would win the second:
        -- sharing the top priority is the only rule that takes each in
        -- the order it arrived.
        local first = race_button_and_sigint(t, "fair-button-first", { "button", "sigint" })
        t:assert(first:find("peinit: shutdown Poweroff started", 1, true),
            "button then SIGINT: the button's poweroff started: " .. first:sub(-1500))
        t:assert(not first:find("peinit: shutdown Reboot started", 1, true),
            "and SIGINT's reboot did not")
        t:assert(first:find("already in progress", 1, true),
            "SIGINT was handled too, second, and found the shutdown under way")

        local second = race_button_and_sigint(t, "fair-sigint-first", { "sigint", "button" })
        t:assert(second:find("peinit: shutdown Reboot started", 1, true),
            "SIGINT then button: SIGINT's reboot started: " .. second:sub(-1500))
        t:assert(not second:find("peinit: shutdown Poweroff started", 1, true),
            "and the button's poweroff did not")
        t:assert(second:find("already in progress", 1, true),
            "the button was handled too, second, and found the shutdown under way")
    end)

test("PID 1 carries on when its epoll wait is interrupted by a tracer",
    { tags = { "known-bug" } },
    function(t)
        -- PEI-1085: an epoll_wait that returns EINTR is treated as a
        -- fatal runtime-loop error, and PID 1 enters recovery.
        --
        -- No TRM claim is about this, which is why it cites nothing; it is
        -- here because it is what stopped this file pausing PID 1 the
        -- direct way. `pt-pause1` seizes PID 1 with ptrace and interrupts
        -- it — what `strace -p 1` or a debugger does on attach. epoll_wait
        -- with a timeout is one of the calls Linux fails with EINTR after a
        -- stop, handler or no handler (signal(7)), and peinit's wait
        -- wrapper passes the error up (boundary/linux_epoll/syscall.rs), so
        -- the loop fails with `Wait(... Interrupted system call ...)` and
        -- the console says `[ CRIT ] peinit: entering recovery: Runtime`.
        local vm = peinit.boot({
            memory = MEM, cpus = CPUS,
            name = "fair-eintr",
            files = peinit.tool("pt-pause1"),
        })
        peinit.settle(vm, { all = true })
        vm:run("( /usr/bin/pt-pause1 /run/pt-pause.log 2 ) > /dev/null 2>&1 &"):assert_ok()
        wait_until(function() return read_or_empty(vm, "/run/pt-pause.log"):find("resumed", 1, true) end,
            { timeout = 15, interval = 0.2, desc = "the pause to end" })
        t:assert(read_or_empty(vm, "/run/pt-pause.log"):find("^paused"),
            "PID 1 was paused and let go: " .. read_or_empty(vm, "/run/pt-pause.log"))
        vm:run("sleep 2")

        local answered = vm:run("svctl status eventd")
        t:assert_eq(answered.exit_code, 0,
            "PID 1 still answers on its control socket: " .. answered.stdout .. answered.stderr)
        t:assert(not vm:console():read_log():find("entering recovery", 1, true),
            "and it did not go to recovery: " ..
            tostring(vm:console():read_log():match("[^\n]*entering recovery[^\n]*")))
    end)
