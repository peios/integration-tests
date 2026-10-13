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
    -- PEINIT_TEST_BINARY, when set, boots a candidate PID 1 in place of the
    -- shipped one, so the writer's descriptor cleanup is the candidate's.
    local vm = peinit.boot({
        name = name,
        files = peinit.test_binary("peinit", peinit.seed("pt-" .. name, {
            { path = [[Machine\System]] },
            { path = [[Machine\System\Services]] },
            -- login-console takes /dev/console once the boot settles, after
            -- which peinit's "service started" lines — how these tests count
            -- firings — are no longer written there.
            { path = [[Machine\System\Services\login-console]], values = {
                { name = "Disabled", type = "dword", data = 1 },
            } },
            timer,
        })),
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

-- PEI-1498: hold the writer in real LCS I/O, inspect its descriptors, then
-- prove that closing inherited handles did not break either storage layout.
for _, per_trigger in ipairs({ false, true }) do
    local layout = per_trigger and "per-trigger" or "single"
    test("a " .. layout .. " timer writer drops supervision descriptors and still records its timestamp",
        { spec = "peinit *evalt.timer-writer-closes-inherited-descriptors-before-opening-its-key" },
        function(t)
            local service = "pt-fd-" .. layout
            local timer = ticker(service, "timer:*-*-* *:*:5/10", true)
            if per_trigger then
                for _, value in ipairs(timer.values) do
                    if value.name == "Triggers" then
                        value.data = { "timer:*-*-* *:*:5/10", "timer:*-*-* *:*:6/10" }
                    end
                end
            end
            local vm = boot_with("timer-fds-" .. layout, timer)
            local key = [[Machine\System\Services\]] .. service .. (per_trigger and [[\TimerState]] or "")
            local names = per_trigger and {
                "%2A-%2A-%2A%20%2A%3A%2A%3A5%2F10",
                "%2A-%2A-%2A%20%2A%3A%2A%3A6%2F10",
            } or { "LastTimerRun" }
            local function timestamps()
                local out = vm:run("reg get '" .. key .. "'")
                local values = {}
                if out.exit_code == 0 then
                    for _, line in ipairs(peinit.lines(out.stdout)) do
                        local name, ty, data = line:match("^(%S+) = (%S+) (.*)$")
                        if name and ty == "REG_QWORD" then values[name] = tonumber(data) end
                    end
                end
                return values
            end
            local before = wait_until(function()
                local values = timestamps()
                for _, name in ipairs(names) do if not values[name] then return nil end end
                return values
            end, { timeout = 20, interval = 0.3, desc = "initial " .. layout .. " history" })
            local pid1_exe = trim(assert(peinit.proc_link(vm, 1, "exe")))
            local pid1_cgroup = trim(assert(peinit.proc(vm, 1, "cgroup")))
            local parent_fds = peinit.fds(vm, 1)
            local has_epoll = false
            for fd, target in pairs(parent_fds) do
                if fd >= 3 and target:find("eventpoll", 1, true) then has_epoll = true end
            end
            t:assert(has_epoll, "premise: PID 1 holds a supervision epoll descriptor")
            local registryd = json.decode(vm:run("svctl --json status registryd").stdout).current_job.pid
            t:assert(registryd, "registryd is running")
            wait_for_second(0, 2)
            wait_until(function() return #bare_forks(vm, pid1_exe, pid1_cgroup) == 0 or nil end,
                { timeout = 8, interval = 0.1, desc = "no prior writer before freezing registryd" })
            local baseline = started(vm, service)
            vm:run("kill -STOP " .. registryd):assert_ok()
            local stopped_ns
            local ok, err = pcall(function()
                local clock = vm:syscall(228, { -- CLOCK_REALTIME, without launching a process
                    args = { 0, 0 }, bufs = { string.rep("\0", 16) }, ptrs = { 1 },
                })
                local seconds, nanos = string.unpack("<i8i8", clock.out_bufs[1])
                stopped_ns = seconds * 1000000000 + nanos
                wait_until(function()
                    return started(vm, service) >= baseline + #names or nil
                end, { timeout = 15, interval = 0.2, desc = "fresh " .. layout .. " firings" })
                local writers = bare_forks(vm, pid1_exe, pid1_cgroup)
                t:assert(#writers >= #names, "each fresh timestamp write is still held in LCS")
                for _, writer in ipairs(writers) do
                    local wchan = trim(peinit.proc(vm, writer, "wchan") or "")
                    t:assert(wchan:find("lcs", 1, true) or wchan:find("source_response", 1, true),
                        "writer is blocked in LCS: " .. wchan)
                    local fds = peinit.fds(vm, writer)
                    local own_keys = 0
                    for fd, target in pairs(fds) do
                        if fd >= 3 then
                            t:assert_eq(target, "anon_inode:[lcs-key]",
                                "writer " .. writer .. " fd " .. fd .. " is its own registry key")
                            own_keys = own_keys + 1
                        end
                    end
                    t:assert(own_keys <= 1, "only the writer's freshly opened key can remain")
                    for fd = 0, 2 do
                        if parent_fds[fd] then
                            t:assert_eq(fds[fd], parent_fds[fd], "standard descriptor " .. fd .. " retained")
                        end
                    end
                end
                local current = peinit.fds(vm, 1)
                for fd, target in pairs(parent_fds) do
                    if target:find("eventpoll", 1, true) then
                        t:assert_eq(current[fd], target, "PID 1 retains its supervision descriptor")
                    end
                end
            end)
            -- Always resume the source, including assertion/setup failures.
            vm:run("kill -CONT " .. registryd):assert_ok()
            if not ok then error(err, 0) end
            wait_until(function()
                local values = timestamps()
                for _, name in ipairs(names) do
                    if not values[name] or values[name] <= before[name] or values[name] < stopped_ns then
                        return nil
                    end
                end
                return true
            end, { timeout = 12, interval = 0.2, desc = "held writes advance every " .. layout .. " REG_QWORD" })
            wait_until(function() return #bare_forks(vm, pid1_exe, pid1_cgroup) == 0 or nil end,
                { timeout = 8, interval = 0.1, desc = "completed writers are reaped" })
        end)
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
