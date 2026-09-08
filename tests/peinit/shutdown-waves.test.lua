-- peinit TRM §12.2 steps 3–5 — who joins the stop waves, in what order,
-- and what bounds the whole thing.
--
-- The console is the oracle for all of it. Each wave decision has its
-- own line — `shutdown stopping X` for a service that is sent SIGTERM,
-- `shutdown waiting for X` for one already on a stop path, `shutdown
-- killing X` for a cgroup SIGKILL, `shutdown service X exited` for a
-- reap — so the plan peinit built is legible from outside without
-- reading a single byte of its state, which is just as well because the
-- machine is gone by the time a test could ask.
--
-- Every boot passes `peios.quiet=0`, without which the image's console
-- login owns peinit's terminal and silences all of the above; and every
-- test settles the image's own services first, because a shutdown
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

--- Wait until none of the image's own services is still Starting.
---
--- Deliberately blind to this suite's `pt-` services: one test here
--- wants one parked in Starting, and waiting for it would deadlock.
local function settle(vm)
    wait_until(function()
        for name, state in pairs(states(vm)) do
            if state == "starting" and not name:find("^pt%-") then return false end
        end
        return true
    end, { timeout = 60, interval = 0.5, desc = "the image's own services to settle" })
end

--- Wait `seconds` on the host, without asking the guest for anything.
local function pause(seconds)
    pcall(wait_until, function() return false end,
        { timeout = seconds, interval = 0.25, desc = "a fixed pause" })
end

local function trigger(vm, command)
    pcall(function() vm:run(command, { timeout = 30 }) end)
end

local function resident(name, extra)
    local values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "100000" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
    }
    for _, value in ipairs(extra or {}) do values[#values + 1] = value end
    return { path = [[Machine\System\Services\]] .. name, values = values }
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

test("no service is stopped until everything depending on it has stopped",
    { spec = "peinit *graceful.no-service-stops-until-its-dependents-have" },
    function(t)
        -- A three-link chain, so the waves have something to be in the
        -- order of: pt-leaf requires pt-mid requires pt-base. Only the
        -- leaf carries a boot trigger; the other two are pulled in by
        -- the hard dependency, which is also what puts them in later
        -- waves.
        with_vm({
            name = "order",
            append = "peios.quiet=0",
            files = peinit.seed("pt-order", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                resident("pt-leaf", {
                    { name = "Triggers", type = "multi", data = { "boot" } },
                    { name = "Requires", type = "multi", data = { "pt-mid" } },
                }),
                resident("pt-mid", {
                    { name = "Requires", type = "multi", data = { "pt-base" } },
                }),
                resident("pt-base"),
            }),
        }, function(vm)
            settle(vm)
            local up = states(vm)
            for _, name in ipairs({ "pt-leaf", "pt-mid", "pt-base" }) do
                t:assert_eq(up[name], "active", name .. " is up before the shutdown")
            end

            trigger(vm, "svctl shutdown poweroff")
            vm:console():expect("peinit: shutdown stopping pt-base", 60)
            local log = vm:console():read_log()

            local leaf = log:find("peinit: shutdown stopping pt-leaf", 1, true)
            local leaf_gone = log:find("peinit: shutdown service pt-leaf exited", 1, true)
            local mid = log:find("peinit: shutdown stopping pt-mid", 1, true)
            local mid_gone = log:find("peinit: shutdown service pt-mid exited", 1, true)
            local base = log:find("peinit: shutdown stopping pt-base", 1, true)
            t:assert(leaf and leaf_gone and mid and mid_gone and base,
                "every step of the chain is on the console")
            t:assert(leaf < leaf_gone and leaf_gone < mid,
                "pt-mid was not signalled until its dependent pt-leaf had exited")
            t:assert(mid < mid_gone and mid_gone < base,
                "and pt-base not until pt-mid had")
        end)
    end)

test("an eligible service gets SIGTERM, then its StopTimeout, then a SIGKILL to its whole cgroup",
    {
        spec = {
            "peinit *graceful.each-eligible-service-gets-sigterm-then-a-cgroup-sigkill-at-stoptimeout",
            "peinit *graceful.active-and-reloading-enter-the-waves",
        },
    },
    function(t)
        -- Two Active services, identical but for what they do with
        -- SIGTERM. The one that takes it is reaped and never killed; the
        -- one that ignores it is killed, and not before its StopTimeout.
        with_vm({
            name = "sigterm",
            append = "peios.quiet=0",
            files = peinit.seed("pt-sigterm", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                resident("pt-polite", {
                    { name = "Triggers", type = "multi", data = { "boot" } },
                    { name = "StopTimeout", type = "dword", data = 20 },
                }),
                stubborn(12),
            }),
        }, function(vm)
            settle(vm)
            local up = states(vm)
            t:assert_eq(up["pt-polite"], "active", "the polite service is up")
            t:assert_eq(up["pt-stubborn"], "active", "and so is the stubborn one")

            trigger(vm, "svctl shutdown poweroff")
            vm:console():expect("peinit: shutdown stopping pt-stubborn", 30)

            -- The SIGTERM has landed. Nothing has been killed yet, and
            -- nothing may be for another dozen seconds.
            local early = vm:console():read_log()
            t:assert(not early:find("peinit: shutdown killing pt-stubborn", 1, true),
                "the kill did not follow the SIGTERM immediately")
            pause(4)
            t:assert(not vm:console():read_log()
                :find("peinit: shutdown killing pt-stubborn", 1, true),
                "and had still not, four seconds into a twelve-second StopTimeout")

            vm:console():expect("peinit: shutdown killing pt-stubborn", 30)

            local log = vm:console():read_log()
            t:assert(log:find("peinit: shutdown stopping pt-polite", 1, true),
                "the polite service was signalled too")
            t:assert(log:find("peinit: shutdown service pt-polite exited", 1, true),
                "and exited on the signal")
            t:assert(not log:find("peinit: shutdown killing pt-polite", 1, true),
                "so it was never killed: SIGTERM first, the cgroup kill only on expiry")
        end)
    end)

test("a Completed oneshot and the states that do not participate stay out of the waves",
    {
        spec = {
            "peinit *graceful.completed-services-are-transitioned-to-inactive",
            "peinit *graceful.five-states-do-not-participate",
        },
    },
    function(t)
        -- One service per non-participating state, arranged the way
        -- control-matrix arranges them, plus a Completed oneshot with a
        -- dependent so the release of its dependency relationship has
        -- something to be visible through: pt-after requires it, is
        -- Active, and stops cleanly in the waves rather than blocking on
        -- a dependency that is not in them.
        with_vm({
            name = "classify",
            append = "peios.quiet=0",
            files = peinit.seed("pt-classify", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                { path = [[Machine\System\Services\pt-completed]], values = {
                    { name = "ImagePath", type = "sz", data = "/bin/true" },
                    { name = "Type", type = "dword", data = 1 },
                    { name = "Identity", type = "sz", data = "SYSTEM" },
                    { name = "RemainAfterExit", type = "dword", data = 1 },
                    { name = "Triggers", type = "multi", data = { "boot" } },
                } },
                resident("pt-after", {
                    { name = "Triggers", type = "multi", data = { "boot" } },
                    { name = "Requires", type = "multi", data = { "pt-completed" } },
                }),
                -- Inactive: nothing triggers it and nothing needs it.
                resident("pt-inactive"),
                -- Failed: a oneshot that exits non-zero and is never
                -- restarted.
                { path = [[Machine\System\Services\pt-failed]], values = {
                    { name = "ImagePath", type = "sz", data = "/bin/false" },
                    { name = "Type", type = "dword", data = 1 },
                    { name = "Identity", type = "sz", data = "SYSTEM" },
                    { name = "RestartPolicy", type = "dword", data = 0 },
                    { name = "Triggers", type = "multi", data = { "boot" } },
                } },
                -- Backoff: crashes at once, always restarted, with a
                -- delay long enough that it sits there for the test.
                { path = [[Machine\System\Services\pt-backoff]], values = {
                    { name = "ImagePath", type = "sz", data = "/bin/false" },
                    { name = "Identity", type = "sz", data = "SYSTEM" },
                    { name = "Readiness", type = "dword", data = 1 },
                    { name = "RestartPolicy", type = "dword", data = 2 },
                    { name = "RestartDelay", type = "dword", data = 120 },
                    { name = "RestartMaxRetries", type = "dword", data = 50 },
                    { name = "Triggers", type = "multi", data = { "boot" } },
                } },
                -- Skipped: a condition on a path that is not there.
                resident("pt-skipped", {
                    { name = "Triggers", type = "multi", data = { "boot" } },
                    { name = "Conditions", type = "multi",
                      data = { "path:/pt-not-here" } },
                }),
            }),
        }, function(vm)
            settle(vm)
            local before = wait_until(function()
                local seen = states(vm)
                for name, want in pairs({
                    ["pt-completed"] = "completed",
                    ["pt-after"] = "active",
                    ["pt-inactive"] = "inactive",
                    ["pt-failed"] = "failed",
                    ["pt-backoff"] = "backoff",
                    ["pt-skipped"] = "skipped",
                }) do
                    if seen[name] ~= want then return nil end
                end
                return seen
            end, { timeout = 60, interval = 0.5, desc = "the six states to be arranged" })
            t:assert(before, "every state this test needs was arranged")

            trigger(vm, "svctl shutdown poweroff")
            -- pt-after is Active, so it is in a wave; waiting for it to
            -- exit is what tells us the plan for this boot has been
            -- fully dispatched and reaped.
            vm:console():expect("peinit: shutdown service pt-after exited", 60)

            local log = vm:console():read_log()
            -- `find` returns a start AND an end, and `sub` takes both, so
            -- the index has to be pulled out into a single value first.
            -- Passing the call through directly leaves `shutdown` holding
            -- just the matched line, and every "is X absent from it?"
            -- below then passes for the wrong reason.
            local began = log:find("peinit: shutdown Poweroff started", 1, true)
            t:assert(began, "the shutdown announced itself")
            local shutdown = log:sub(began)
            for _, name in ipairs({
                "pt-completed", "pt-inactive", "pt-failed", "pt-backoff", "pt-skipped",
            }) do
                for _, verb in ipairs({ "stopping", "waiting for", "killing" }) do
                    t:assert(not shutdown:find("peinit: shutdown " .. verb .. " " .. name, 1, true),
                        name .. " was not a participant: no `" .. verb .. "` line for it")
                end
            end
            t:assert(shutdown:find("peinit: shutdown stopping pt-after", 1, true),
                "while its Active dependent was stopped, so the Completed service's " ..
                "dependency relationship did not hold it back")
        end)
    end)

test("a Starting service is cancelled and SIGKILLed rather than stopped",
    { spec = "peinit *graceful.a-starting-service-is-killed-and-failed" },
    function(t)
        -- Readiness=notify with a process that never notifies parks the
        -- service in Starting for its whole StartTimeout, which is set
        -- far beyond the test. A Starting service is not stop-eligible:
        -- peinit cancels the startup and kills the cgroup, which reads
        -- as `killing` rather than `stopping`.
        with_vm({
            name = "starting",
            append = "peios.quiet=0",
            files = peinit.seed("pt-starting", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                resident("pt-stuck", {
                    { name = "Triggers", type = "multi", data = { "boot" } },
                    { name = "Readiness", type = "dword", data = 0 },
                    { name = "StartTimeout", type = "dword", data = 600 },
                }),
            }),
        }, function(vm)
            settle(vm)
            wait_until(function() return states(vm)["pt-stuck"] == "starting" end,
                { timeout = 60, interval = 0.5, desc = "pt-stuck to park in Starting" })

            trigger(vm, "svctl shutdown poweroff")
            vm:console():expect("peinit: shutdown killing pt-stuck", 60)

            local log = vm:console():read_log()
            t:assert(not log:find("peinit: shutdown stopping pt-stuck", 1, true),
                "it was never asked politely: a Starting service is not stop-eligible")
        end)
    end)

test("the global timeout kills whatever is left and the shutdown finishes anyway",
    {
        spec = {
            "peinit *graceful.shutdowntimeout-and-postkilltimeout-bound-the-sequence",
            "peinit *graceful.on-the-global-timeout-everything-remaining-is-killed",
        },
    },
    function(t)
        -- ShutdownTimeout well under the one service's StopTimeout, so
        -- the sequence runs out of time before that service runs out of
        -- grace. The global sweep then kills it regardless and the
        -- machine still reaches its final action.
        with_vm({
            name = "globaltimeout",
            append = "peios.quiet=0",
            files = peinit.seed("pt-globaltimeout", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Boot]], values = {
                    { name = "ShutdownTimeout", type = "dword", data = 6 },
                    { name = "PostKillTimeout", type = "dword", data = 1 },
                } },
                { path = [[Machine\System\Services]] },
                stubborn(600),
            }),
        }, function(vm)
            settle(vm)
            t:assert_eq(vm:run([[reg get 'Machine\System\Boot' ShutdownTimeout]])
                .stdout:match("%d+"), "6",
                "the boot knob this test depends on is in the registry")

            -- Generous bounds, because each is only here to fail a step
            -- that never comes: the ordering is what this test asserts,
            -- and the console gives that whatever the wall clock did.
            -- At thirty and sixty seconds these lapsed on a host busy
            -- with something else, which says nothing about the
            -- shutdown.
            trigger(vm, "svctl shutdown poweroff")
            vm:console():expect("peinit: shutdown stopping pt-stubborn", 90)
            vm:console():expect("peinit: shutdown global timeout expired", 90)
            vm:console():expect("peinit: shutdown killing pt-stubborn", 90)
            vm:console():expect("reboot: Power down", 120)
            t:assert(true, "the shutdown ran to its final action despite the survivor")
        end)
    end)
