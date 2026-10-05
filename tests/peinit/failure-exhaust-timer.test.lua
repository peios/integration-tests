-- peinit TRM §14.4 — the one fork outside the launch machinery: the
-- last-run write a persistent timer makes on every firing.
--
-- The write is a plain fork of PID 1 that makes one registry call and
-- `_exit`s, so normally it is gone in a millisecond or two and there is
-- nothing to look at. Stopping registryd holds it: the child's registry
-- request waits on a source that is not answering, and for as long as
-- registryd stays stopped the child is a process like any other, visible
-- in /proc — its stack sitting in the kernel's LCS response wait.
-- SIGSTOP rather than a kill, because a dead source fails its requests at
-- once; a stopped one keeps its slot and simply does not reply, and a
-- SIGCONT lets every held write finish. The freeze is a few seconds, far
-- inside LCS's thirty-second request timeout.
--
-- What marks such a child as the write rather than as anything the launch
-- machinery makes: it is a child of PID 1, it never exec'd — /proc/N/exe
-- is PID 1's own image — and it sits in PID 1's own cgroup, where every
-- process the launch path makes is cloned into a service's (§5.1). The
-- provium agent is also a child of PID 1 in PID 1's cgroup, but it exec'd
-- its own binary, so the image check tells it apart.
--
-- One VM per test: each freezes registryd and counts firings, and a boot
-- that reached the runtime is fine to end when the test does.

local peinit = require("helpers.peinit")
peinit.claim(1)

local function ticker(name, schedule, persistent)
    local values = {
        { name = "ImagePath", type = "sz", data = "/bin/true" },
        { name = "Type", type = "dword", data = 1 },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Triggers", type = "multi", data = { schedule } },
    }
    if not persistent then
        values[#values + 1] = { name = "TimerPersistent", type = "dword", data = 0 }
    end
    return { path = [[Machine\System\Services\]] .. name, values = values }
end

local function boot_with(name, timer)
    local vm = peinit.boot({
        name = name,
        files = peinit.seed("pt-" .. name, {
            { path = [[Machine\System]] },
            { path = [[Machine\System\Services]] },
            -- login-console takes /dev/console once the boot settles, after
            -- which peinit's "service started" lines — how these tests count
            -- firings — are no longer written there.
            { path = [[Machine\System\Services\login-console]], values = {
                { name = "Disabled", type = "dword", data = 1 },
            } },
            timer,
        }),
    })
    peinit.settle(vm)
    return vm
end

local function trim(text) return (text:gsub("%s+$", "")) end

--- PID 1's children that are bare forks of it: never exec'd (their image
--- is PID 1's own), and still in PID 1's own cgroup. Returns the pids.
---
--- Read by the agent. PID 1 is TCB-signed, and so is a bare fork of it —
--- the label is the binary's and only an exec changes it — so PIP refuses
--- the shell's `cat` and `readlink` the /proc of both (helpers/peinit.lua).
local function bare_forks(vm, pid1_exe, pid1_cgroup)
    local found = {}
    local children = assert(peinit.proc(vm, 1, "task/1/children"))
    for pid in children:gmatch("%d+") do
        local exe = peinit.proc_link(vm, pid, "exe")
        local cgroup = peinit.proc(vm, pid, "cgroup")
        -- A child can exit between the listing and the look; that is a
        -- process that is gone, not a bare fork.
        if exe and cgroup and trim(exe) == pid1_exe and trim(cgroup) == pid1_cgroup then
            found[#found + 1] = pid
        end
    end
    return found
end

local function started(vm, service)
    local count = 0
    local pat = "peinit: service " .. service:gsub("%-", "%%-") .. " started"
    for _ in vm:console():read_log():gmatch(pat) do count = count + 1 end
    return count
end

local function wait_for_second(lo, hi)
    wait_until(function()
        local s = os.time() % 10
        return (s >= lo and s <= hi) or nil
    end, { timeout = 20, interval = 0.2, desc = "the right point in the ten-second cycle" })
end

--- A firing-count and bare-fork sample taken without a firing landing
--- mid-read: read the count, the forks, and the count again, and retry
--- until the two count reads agree. With registryd frozen no writer
--- drains, so the fork count is monotonic and this converges.
local function stable_sample(vm, service, pid1_exe, pid1_cgroup)
    return wait_until(function()
        local a = started(vm, service)
        local forks = bare_forks(vm, pid1_exe, pid1_cgroup)
        local b = started(vm, service)
        if a == b then return { fired = a, forks = forks } end
        return nil
    end, { timeout = 15, interval = 0.2, desc = "a sample with no firing mid-read" })
end

test("a persistent timer's firing forks PID 1 for its last-run write, and that is the only fork outside the launch path",
    { spec = "peinit *exhaust.the-timer-last-run-write-is-the-only-fork-outside-the-launch-path" },
    function(t)
        -- Persistent (the default), firing five seconds into every ten.
        local vm = boot_with("timer-persistent", ticker("pt-tw", "timer:*-*-* *:*:5/10", true))
        local pid1_exe = trim(assert(peinit.proc_link(vm, 1, "exe")))
        local pid1_cgroup = trim(vm:read_file("/proc/1/cgroup"))
        local registryd = json.decode(vm:run("svctl --json status registryd").stdout).current_job.pid
        t:assert(registryd, "registryd has a main process")

        -- Freeze registryd at rest, with no writer outstanding — every
        -- earlier write drained while registryd was answering.
        wait_for_second(0, 2)
        wait_until(function() return #bare_forks(vm, pid1_exe, pid1_cgroup) == 0 or nil end,
            { timeout = 12, interval = 0.3, desc = "PID 1 to hold no bare fork of itself at rest" })
        local base = stable_sample(vm, "pt-tw", pid1_exe, pid1_cgroup)
        t:assert_eq(#base.forks, 0, "the sample agrees: none at rest")
        vm:run("kill -STOP " .. registryd):assert_ok()

        local ok, err = pcall(function()
            -- Let two firings land (~twenty seconds). Each starts its
            -- service through the launch path and forks one writer, now
            -- stuck on the frozen registry; with nothing draining, the
            -- forks accumulate one per firing.
            wait_until(function() return started(vm, "pt-tw") >= base.fired + 2 or nil end,
                { timeout = 30, interval = 0.3, desc = "two persistent firings" })
            local s = stable_sample(vm, "pt-tw", pid1_exe, pid1_cgroup)
            local firings = s.fired - base.fired
            t:assert(firings >= 2, "the timer fired: " .. firings)
            t:assert_eq(#s.forks, firings,
                ("one bare fork of PID 1 per firing, and no other: %d firings, forks %s"):format(
                    firings, table.concat(s.forks, ",")))

            -- Each is PID 1's image forked and not exec'd, blocked in the
            -- kernel's LCS response wait — what a last-run write does, and
            -- nothing a launch does.
            for _, writer in ipairs(s.forks) do
                t:assert_eq(trim(peinit.proc(vm, writer, "comm") or ""),
                    trim(assert(peinit.proc(vm, 1, "comm"))),
                    "writer " .. writer .. " is PID 1's image, forked not exec'd")
                local wchan = trim(peinit.proc(vm, writer, "wchan") or "")
                t:assert(wchan:find("lcs", 1, true) or wchan:find("source_response", 1, true),
                    "writer " .. writer .. " is blocked in the registry write, not idle: " .. wchan)
            end
        end)
        vm:run("kill -CONT " .. registryd)
        if not ok then error(err, 0) end

        -- With registryd back every held write lands and every writer
        -- exits, so PID 1 is holding none again.
        wait_until(function() return #bare_forks(vm, pid1_exe, pid1_cgroup) == 0 or nil end,
            { timeout = 15, interval = 0.3,
              desc = "the held writers to exit once their writes returned" })
    end)

test("a non-persistent timer's firing forks nothing outside the launch path",
    {
        spec = "peinit *exhaust.the-timer-last-run-write-is-the-only-fork-outside-the-launch-path",
        -- PEI-1083: §14.4 says the last-run fork is "one child per
        -- firing of a persistent timer", and §9.3 says
        -- TimerPersistent=0 "ignores history entirely". But
        -- the runtime firing path queues a last-run write for every timer
        -- regardless of persistence (the runtime timer entry drops the
        -- persistent flag), so a non-persistent firing forks a writer and
        -- writes LastTimerRun just like a persistent one. This test asserts
        -- the TRM and stays red until peinit stops writing for
        -- non-persistent timers.
        -- PEI-1083: fixed in peinit 41f8deb, "fix(timer): skip
        -- the LastTimerRun write for a TimerPersistent=0
        -- firing". Green since 0.0.5-4.
    },
    function(t)
        -- Non-persistent, firing on every ten.
        local vm = boot_with("timer-nonpersistent", ticker("pt-np", "timer:*-*-* *:*:0/10", false))
        local pid1_exe = trim(assert(peinit.proc_link(vm, 1, "exe")))
        local pid1_cgroup = trim(vm:read_file("/proc/1/cgroup"))
        local registryd = json.decode(vm:run("svctl --json status registryd").stdout).current_job.pid

        wait_for_second(5, 7)
        wait_until(function() return #bare_forks(vm, pid1_exe, pid1_cgroup) == 0 or nil end,
            { timeout = 12, interval = 0.3, desc = "PID 1 to hold no bare fork at rest" })
        local base = stable_sample(vm, "pt-np", pid1_exe, pid1_cgroup)
        t:assert_eq(#base.forks, 0, "none at rest")
        vm:run("kill -STOP " .. registryd):assert_ok()

        local ok, err = pcall(function()
            wait_until(function() return started(vm, "pt-np") >= base.fired + 2 or nil end,
                { timeout = 35, interval = 0.3, desc = "two non-persistent firings" })
            local s = stable_sample(vm, "pt-np", pid1_exe, pid1_cgroup)
            t:assert(s.fired - base.fired >= 2, "the timer fired")
            -- A TimerPersistent=0 timer has no history to record, so its
            -- firing should be a launch and nothing else.
            t:assert_eq(#s.forks, 0,
                "a non-persistent firing forked nothing outside the launch path: "
                .. table.concat(s.forks, ","))
        end)
        vm:run("kill -CONT " .. registryd)
        if not ok then error(err, 0) end
    end)
