-- peinit TRM §12.2 step 4 — the stop deadline: whose clock a wave runs
-- on, and what happens when the cgroup will not empty.
--
-- Split out of shutdown-waves.test.lua because every test here is a
-- waiting test. One sits out twenty seconds of an already-running
-- StopTimeout before it even asks for a shutdown; one waits out a
-- post-kill deadline; and the file's budget is the same 300 seconds as
-- everyone else's.
--
-- `peios.quiet=0` on every boot: the image's console login owns peinit's
-- terminal once it is up, and at the default peinit stays out of a
-- terminal a service owns — which silences the whole shutdown narrative.
-- Every test settles the image's own services first, because a shutdown
-- requested while one of them is still Starting takes PID 1 into
-- recovery (PEI-826, in shutdown-boot.test.lua).

local peinit = require("helpers.peinit")
peinit.claim(1)

local function with_vm(opts, body)
    local vm = peinit.boot(opts)
    local ok, err = pcall(body, vm)
    pcall(function() vm:shutdown() end)
    if not ok then error(err, 0) end
end

--- Every service's state, by name.
---
--- `svctl --json list` emits each service's members in alphabetical key
--- order, which puts `"service"` immediately before `"state"` — so one
--- pattern reads the pair without a JSON parser the guest has not got.
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

-- Blind to this suite's `pt-` services, which are the subject here. See
-- `helpers.peinit.settle` for why it waits on operations rather than on
-- Starting.
local settle = peinit.settle

--- Wait `seconds` on the host, without asking the guest for anything.
local function pause(seconds)
    pcall(wait_until, function() return false end,
        { timeout = seconds, interval = 0.25, desc = "a fixed pause" })
end

local function trigger(vm, command)
    pcall(function() vm:run(command, { timeout = 30 }) end)
end

--- The console from byte `from` on.
local function since(vm, from)
    return vm:console():read_log():sub(from + 1)
end

-- Ignores SIGTERM, so peinit has to wait out its StopTimeout. A loop of
-- short sleeps rather than one long one: the signal goes to the whole
-- cgroup, and a single `sleep` child dies on the first one and takes the
-- shell's exit with it.
local function stubborn(stop_timeout, extra)
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
    return { path = [[Machine\System\Services\pt-stubborn]], values = values }
end

test("a service that sent STOPPING=1 is not sent a SIGTERM at all",
    { spec = "peinit *graceful.a-service-that-sent-stopping-gets-no-sigterm" },
    function(t)
        -- Two services running the same program with the same
        -- StopTimeout, differing in one step of their script: one sends
        -- STOPPING=1 after it reports ready, the other does not. Neither
        -- traps SIGTERM, so the difference in what becomes of them is
        -- entirely a difference in what peinit sent.
        --
        -- The console line is the same for both — a suppressed SIGTERM
        -- still reads as `shutdown stopping X` — so the evidence is what
        -- follows it: the one that was signalled dies on the signal and
        -- is reaped; the one that was not sits out its whole stop
        -- deadline and is killed.
        --
        -- pt-notify has to be the service's *main* process, because
        -- peinit authenticates a notification by its sender's pid and
        -- nothing else counts. `peinit.tool` stages the binary; it is
        -- test apparatus and is not in the image.
        local function notifier(name, script)
            return { path = [[Machine\System\Services\]] .. name, values = {
                { name = "ImagePath", type = "sz", data = "/usr/bin/pt-notify" },
                { name = "Arguments", type = "multi", data = script },
                { name = "Identity", type = "sz", data = "SYSTEM" },
                { name = "Readiness", type = "dword", data = 0 },
                { name = "StopTimeout", type = "dword", data = 8 },
                { name = "RestartPolicy", type = "dword", data = 0 },
                { name = "Triggers", type = "multi", data = { "boot" } },
            } }
        end
        with_vm({
            name = "stoppingnotify",
            append = "peios.quiet=0",
            files = peinit.merge(
                peinit.tool("pt-notify"),
                peinit.seed("pt-stoppingnotify", {
                    { path = [[Machine\System]] },
                    { path = [[Machine\System\Services]] },
                    -- The leading `sleep 1` is not padding. peinit
                    -- authenticates a notification by matching the
                    -- sender's pid against a service's current main
                    -- job, and immediately after exec it has not yet
                    -- processed the launch that would record one — so
                    -- the first datagram a service sends is routinely
                    -- refused as an unauthenticated sender, and a
                    -- READY=1 sent there is simply lost.
                    notifier("pt-says-stopping",
                        { "sleep", "1", "send", "READY=1", "send", "STOPPING=1",
                          "sleep", "300" }),
                    notifier("pt-silent",
                        { "sleep", "1", "send", "READY=1", "sleep", "300" }),
                })),
        }, function(vm)
            settle(vm)
            local up = wait_until(function()
                local seen = states(vm)
                if seen["pt-says-stopping"] == "active" and seen["pt-silent"] == "active" then
                    return seen
                end
                return nil
            end, { timeout = 60, interval = 0.5, desc = "both notifiers to report ready" })
            t:assert(up, "both services reported READY=1 and are Active")

            trigger(vm, "svctl shutdown poweroff")
            vm:console():expect("peinit: shutdown service pt-silent exited", 30)
            local early = vm:console():read_log()
            t:assert(not early:find("peinit: shutdown service pt-says-stopping exited", 1, true),
                "the service that had said STOPPING=1 was still running when the one " ..
                "that had not was already reaped: it was never sent the signal")

            vm:console():expect("peinit: shutdown killing pt-says-stopping", 30)
            local log = vm:console():read_log()
            t:assert(not log:find("peinit: shutdown killing pt-silent", 1, true),
                "while the service that was signalled never needed killing")
        end)
    end)

test("a cgroup still populated after the post-kill timeout is abandoned, and the shutdown carries on",
    { spec = "peinit *graceful.a-cgroup-that-survives-the-post-kill-timeout-is-abandoned" },
    function(t)
        -- The condition peinit actually reads is narrower than the
        -- chapter's D-state story: it kills the service root, arms a
        -- post-kill deadline, and asks whether the root is still
        -- populated when the deadline fires. That can be made true
        -- honestly. A keeper outside the service drops a fresh process
        -- into a sibling of `main/` every second, so whatever the root
        -- kill takes, the next iteration replaces — the same provocation
        -- failure-unkillable.test.lua uses for the explicit-stop path.
        --
        -- pt-stubborn is here to hold the shutdown open past the
        -- abandonment. Without it the wave completes in the same turn
        -- the abandonment happens in, the shutdown finalises, and a
        -- turn's console output is written after its work (PEI-827) —
        -- so the line this test reads would never be printed.
        local ROOT = "/sys/fs/cgroup/peinit/pt-abandon"
        with_vm({
            name = "abandoned",
            append = "peios.quiet=0",
            files = peinit.merge({
                ["pt/stuck.sh"] = { [[
trap '' TERM
while : ; do /bin/sleep 1 ; done
]], exec = true },
                ["pt/keeper.sh"] = { [[
N=0
while [ $N -lt 60 ] ; do
  /bin/sleep 300 &
  echo $! > $1/cgroup.procs
  N=$((N+1))
  /bin/sleep 1
done
]], exec = true },
            }, peinit.seed("pt-abandoned", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Boot]], values = {
                    { name = "PostKillTimeout", type = "dword", data = 12 },
                } },
                { path = [[Machine\System\Services]] },
                { path = [[Machine\System\Services\pt-abandon]], values = {
                    { name = "ImagePath", type = "sz", data = "/bin/sh" },
                    { name = "Arguments", type = "multi", data = { "/pt/stuck.sh" } },
                    { name = "Identity", type = "sz", data = "SYSTEM" },
                    { name = "Readiness", type = "dword", data = 1 },
                    { name = "RestartPolicy", type = "dword", data = 0 },
                    { name = "StopTimeout", type = "dword", data = 2 },
                    { name = "Triggers", type = "multi", data = { "boot" } },
                } },
                stubborn(45),
            })),
        }, function(vm)
            settle(vm)
            local main_pid = wait_until(function()
                local ok, procs = pcall(function()
                    return vm:read_file(ROOT .. "/main/cgroup.procs")
                end)
                return ok and procs:match("^(%d+)") or nil
            end, { timeout = 60, interval = 0.5, desc = "pt-abandon to have a main process" })

            -- The main process has to survive the kill, or the wave sees
            -- it exit, completes the stop, and the post-kill deadline
            -- this test is about never fires. `cgroup.kill` reaches a
            -- cgroup and its descendants, so surviving means being
            -- outside the service tree altogether — which is the
            -- position a D-state process is in, and the same move
            -- failure-unkillable.test.lua makes for the explicit-stop
            -- path. peinit tracks the process by pidfd rather than by
            -- cgroup membership, so it is still the service's main
            -- process and still peinit's child.
            vm:run("mkdir -p /sys/fs/cgroup/pt-escape"):assert_ok()
            vm:run("echo " .. main_pid .. " > /sys/fs/cgroup/pt-escape/cgroup.procs")
                :assert_ok()

            -- And the service root has to still report populated when
            -- the deadline fires, which is the one input peinit reads.
            -- The keeper drops a fresh process into a sibling of `main/`
            -- every second, so whatever the root kill takes, the next
            -- iteration replaces.
            vm:run("mkdir -p " .. ROOT .. "/pt-keep"):assert_ok()
            vm:run("/pt/keeper.sh " .. ROOT .. "/pt-keep > /dev/null 2>&1 &")
            t:assert(vm:read_file(ROOT .. "/pt-keep/cgroup.procs"):match("%d"),
                "the keeper has a process in a sibling of main/")

            trigger(vm, "svctl shutdown poweroff")
            vm:console():expect("peinit: shutdown killing pt-abandon", 40)
            vm:console():expect("peinit: shutdown abandoned pt-abandon", 60)

            -- `status` is one of the queries the shutdown gate lets
            -- through, so the cause and the leak can still be read off
            -- the machine that is going down.
            local view = json.decode(vm:run("svctl --json status pt-abandon").stdout)
            t:assert_eq(view.state, "abandoned", "the service went to Abandoned")
            t:assert_eq(view.cause, "process_unkillable", "with cause ProcessUnkillable")
            local leaked = {}
            for _, warning in ipairs(view.warnings or {}) do
                leaked[warning.path] = warning.type
            end
            t:assert_eq(leaked[ROOT], "service_tree",
                "and its cgroup is recorded as leaked rather than reclaimed")

            -- The shutdown did not stop for it: the next wave is still
            -- being worked through.
            t:assert(vm:console():read_log()
                :find("peinit: shutdown stopping pt-stubborn", 1, true),
                "and the shutdown carried on with the rest of the plan")
        end)
    end)

test("a participant whose stop evidence is gone is killed at once, and only it loses its graceful period",
    {
        spec = {
            "peinit *graceful.unsubstantiable-evidence-fails-closed",
            "peinit *graceful.an-unsubstantiated-deadline-kills-without-a-graceful-period",
            "peinit *graceful.failing-closed-costs-only-that-participant",
            "peinit *graceful.the-retained-evidence-must-meet-five-conditions",
        },
    },
    function(t)
        -- The evidence for an already-Stopping participant under an
        -- explicit stop is that stop operation's retained timing. It goes
        -- missing, honestly, once the stop's own StopTimeout has expired:
        -- peinit escalates to a cgroup kill and drops the timeout it no
        -- longer needs, while the operation stays in flight waiting for
        -- the service to go. So a service whose stop has escalated and
        -- that has not yet gone is a Stopping service with an in-flight
        -- stop and no retained timing — the missing-evidence case.
        --
        -- Not going is the failure-unkillable move: the main process is
        -- moved out of the service's cgroup, where the cgroup kill cannot
        -- reach it, and peinit, which tracks it by pidfd, keeps waiting.
        -- The stop's StopTimeout is two seconds and the shutdown comes
        -- six seconds after it. The console line the claim is about names
        -- the missing evidence, which is itself the proof that the
        -- escalation had happened by then.
        --
        -- pt-stubborn is the other participant, on its full twelve
        -- seconds, and the claim is that it keeps them.
        local ROOT = "/sys/fs/cgroup/peinit/pt-stuck"
        with_vm({
            name = "unsubstantiated",
            append = "peios.quiet=0",
            files = peinit.merge({
                ["pt/stuck.sh"] = { "trap '' TERM\nwhile : ; do /bin/sleep 1 ; done\n", exec = true },
            }, peinit.seed("pt-unsubstantiated", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Boot]], values = {
                    { name = "PostKillTimeout", type = "dword", data = 60 },
                } },
                { path = [[Machine\System\Services]] },
                { path = [[Machine\System\Services\pt-stuck]], values = {
                    { name = "ImagePath", type = "sz", data = "/bin/sh" },
                    { name = "Arguments", type = "multi", data = { "/pt/stuck.sh" } },
                    { name = "Identity", type = "sz", data = "SYSTEM" },
                    { name = "Readiness", type = "dword", data = 1 },
                    { name = "RestartPolicy", type = "dword", data = 0 },
                    { name = "StopTimeout", type = "dword", data = 2 },
                    { name = "Triggers", type = "multi", data = { "boot" } },
                } },
                stubborn(12),
            })),
        }, function(vm)
            settle(vm)
            local main_pid = wait_until(function()
                local ok, procs = pcall(function()
                    return vm:read_file(ROOT .. "/main/cgroup.procs")
                end)
                return ok and procs:match("^(%d+)") or nil
            end, { timeout = 60, interval = 0.5, desc = "pt-stuck to have a main process" })
            vm:run("mkdir -p /sys/fs/cgroup/pt-escape"):assert_ok()
            vm:run("echo " .. main_pid .. " > /sys/fs/cgroup/pt-escape/cgroup.procs"):assert_ok()

            trigger(vm, "svctl stop pt-stuck --no-wait")
            pause(6)
            t:assert_eq(states(vm)["pt-stuck"], "stopping",
                "three StopTimeouts later pt-stuck is still Stopping, its main process out of reach")

            local before = #vm:console():read_log()
            trigger(vm, "svctl shutdown poweroff")
            vm:console():expect(
                "peinit: shutdown cannot substantiate a stop timeout for pt-stuck "
                .. "(no retained timeout for the in-flight stop operation); "
                .. "killing it without a graceful period", 30)
            vm:console():expect("peinit: shutdown killing pt-stuck", 10)
            local early = vm:console():read_log():sub(before)
            t:assert(early:find("peinit: shutdown stopping pt-stubborn", 1, true),
                "the other participant was asked to stop as usual")
            t:assert(not early:find("peinit: shutdown killing pt-stubborn", 1, true),
                "and was not killed along with it")

            -- Every other participant keeps its full StopTimeout.
            pause(6)
            t:assert(not vm:console():read_log():sub(before)
                :find("peinit: shutdown killing pt-stubborn", 1, true),
                "six seconds on, pt-stubborn was still inside its twelve")

            -- And the shutdown runs to completion. The process that
            -- escaped is let go, rather than making the test sit out the
            -- post-kill deadline its abandonment would take.
            vm:run("kill -9 " .. main_pid)
            vm:console():expect("peinit: shutdown killing pt-stubborn", 30)
            vm:console():expect("reboot: Power down", 90)
            t:assert(true, "the shutdown finished")
        end)
    end)

test("an operation that expires while Pending fails, and its service is not signalled before its wave",
    { spec = "peinit *graceful.a-pending-operations-expiry-does-not-signal-the-service-early" },
    function(t)
        -- A shutdown creates no operations of its own (op.shutdown-is-
        -- declared-but-not-produced) and refuses the commands that would,
        -- so a Pending operation during one is one that was queued before
        -- it began. The one that can be arranged is a start queued behind
        -- an explicit stop: StartTimeout 3, measured from creation, while
        -- the stop has sixty seconds to run.
        --
        -- pt-back is the service it is for. pt-stubborn requires it, which
        -- keeps pt-back's wave back until pt-stubborn's twenty seconds are
        -- up. pt-back ignores SIGTERM and notes each one it gets; it has
        -- had one already, from the explicit stop. Between the queued
        -- start's expiry and its own wave, nothing may reach it.
        with_vm({
            name = "pendingexpiry",
            append = "peios.quiet=0",
            files = peinit.seed("pt-pendingexpiry", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                { path = [[Machine\System\Services\pt-back]], values = {
                    { name = "ImagePath", type = "sz", data = "/bin/sh" },
                    { name = "Arguments", type = "multi",
                      data = { "-c", "trap 'echo term >> /run/pt-back-terms' TERM; "
                          .. "while :; do sleep 1; done" } },
                    { name = "Identity", type = "sz", data = "SYSTEM" },
                    { name = "Readiness", type = "dword", data = 1 },
                    { name = "StopTimeout", type = "dword", data = 60 },
                    { name = "StartTimeout", type = "dword", data = 3 },
                    { name = "RestartPolicy", type = "dword", data = 0 },
                } },
                stubborn(20, { { name = "Requires", type = "multi", data = { "pt-back" } } }),
            }),
        }, function(vm)
            settle(vm)
            wait_until(function() return states(vm)["pt-back"] == "active" end,
                { timeout = 30, interval = 0.5, desc = "pt-back to be running" })
            local pid = json.decode(vm:run("svctl --json status pt-back").stdout).current_job.pid

            vm:run("svctl --json stop pt-back --no-wait"):assert_ok()
            wait_until(function()
                local ok, text = pcall(function() return vm:read_file("/run/pt-back-terms") end)
                return ok and text:find("term", 1, true)
            end, { timeout = 10, interval = 0.25, desc = "the explicit stop's SIGTERM" })

            -- The start is queued behind the stop by a caller that waits.
            vm:run("(svctl --json start pt-back > /run/pt-start-answer 2>&1; "
                .. "echo rc=$? >> /run/pt-start-answer) > /dev/null 2>&1 &")
            pause(1)
            local from = #vm:console():read_log()
            trigger(vm, "svctl shutdown poweroff")
            vm:console():expect("peinit: shutdown stopping pt-stubborn", 30)

            -- Past the start's lifetime, and well inside pt-stubborn's
            -- twenty seconds.
            pause(8)
            local answer = vm:read_file("/run/pt-start-answer")
            t:assert(answer:find('"code":"OPERATION_TIMEOUT"', 1, true)
                and answer:find("rc=1", 1, true),
                "the queued start expired during the shutdown and its waiter was failed "
                .. "with it: " .. answer)

            local during = since(vm, from)
            t:assert(not during:find("pt-back", 1, true),
                "the shutdown had not touched pt-back: its wave was not yet due")
            t:assert(vm:run("kill -0 " .. pid):ok(), "pt-back's main process is still there")
            local terms = 0
            for _ in vm:read_file("/run/pt-back-terms"):gmatch("term") do terms = terms + 1 end
            t:assert_eq(terms, 1,
                "and has had only the one SIGTERM, from the explicit stop: the expiry sent nothing")

            -- Its wave comes when pt-stubborn's does not stand in its way.
            vm:console():expect("peinit: shutdown killing pt-stubborn", 30)
            vm:console():expect("peinit: shutdown waiting for pt-back", 30)
        end)
    end)

test("service-level stop evidence that is missing, stale, mismatched or backwards gets no graceful period",
    {
        spec = "peinit *graceful.the-retained-evidence-must-meet-five-conditions",
        covered_by = "cargo:peinit2 supervisor::tests::shutdown::retained_evidence::retained_evidence_failing_any_condition_gets_no_graceful_period",
        skip = "service-level evidence is recorded by the transition into Stopping with that transition's own cause and deadline, and cleared when the service leaves Stopping, so no guest can make it absent-but-Stopping, stale, mismatched or backwards — only the in-flight stop's evidence can go missing, which the test above provokes; runs under cargo test -p peinit2 --all-features --lib supervisor::tests::shutdown::retained_evidence::retained_evidence_failing_any_condition_gets_no_graceful_period",
    },
    function(t) end)

test("an already-Stopping service joins the wave without a second SIGTERM, on the clock it was already on",
    {
        spec = {
            "peinit *graceful.a-stopping-service-joins-the-waves-without-another-sigterm",
            "peinit *graceful.an-already-stopping-services-clock-is-not-reset",
        },
    },
    function(t)
        -- A 30-second StopTimeout, an explicit stop, and 20 seconds of
        -- waiting before the shutdown. What is left of the service's
        -- budget is about ten seconds. If the shutdown reset the clock
        -- it would be thirty, so a kill inside eighteen is only possible
        -- on the retained deadline.
        with_vm({
            name = "stopping",
            append = "peios.quiet=0",
            files = peinit.seed("pt-stopping", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                stubborn(30),
            }),
        }, function(vm)
            settle(vm)
            trigger(vm, "svctl --no-wait stop pt-stubborn")
            wait_until(function() return states(vm)["pt-stubborn"] == "stopping" end,
                { timeout = 30, interval = 0.3, desc = "pt-stubborn to enter Stopping" })
            pause(20)

            trigger(vm, "svctl shutdown poweroff")
            vm:console():expect("peinit: shutdown waiting for pt-stubborn", 30)
            local waiting = vm:console():read_log()
            t:assert(not waiting:find("peinit: shutdown stopping pt-stubborn", 1, true),
                "it was not sent a second SIGTERM: the wave reports it as waited for")
            t:assert(not waiting:find("peinit: shutdown killing pt-stubborn", 1, true),
                "and its retained deadline had not yet expired")

            vm:console():expect("peinit: shutdown killing pt-stubborn", 18)
            t:assert(true,
                "the kill came on what was left of the original StopTimeout, " ..
                "not on a fresh one")
        end)
    end)

