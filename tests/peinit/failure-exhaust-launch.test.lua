-- peinit TRM §14.4 — a launch that finds PID 1 out of descriptors fails
-- the start with ParentSetupFailure, and the service gets another go.
--
-- The lever is PID 1's own RLIMIT_NOFILE. prlimit64 on another process is
-- a PROCESS_SET_INFORMATION request under KACS, which the agent's SYSTEM
-- token holds over PID 1, so the test can lower peinit's soft limit from
-- the side and raise it again, without touching anything peinit holds.
-- A descriptor number at or above the limit cannot be allocated, and the
-- kernel hands out the lowest free number — so a limit placed on the
-- (k+1)th free slot of PID 1's table leaves exactly k descriptors to
-- allocate, whatever PID 1 already holds above it.
--
-- A launch allocates in a fixed order (boundary/linux_launch/process.rs):
-- the service's token, its cgroup directory, /dev/null, then three pipes
-- with pipe2 — setup status, stdout, stderr — and finally the pidfd that
-- clone3 returns. Three slots therefore run out at the first pipe2, and
-- nine at clone3's pidfd. Each case is measured once, on its own service,
-- and the console line peinit writes for a failed launch says which call
-- ran out, so a miscount shows up as the wrong call rather than as a pass.
--
-- The launches are timer-driven, not `svctl start`: a control connection
-- would need a descriptor of its own to be accepted, and peinit must not
-- be asked anything while the limit is down. Nothing talks to PID 1 from
-- the moment the limit is lowered until it is restored; the failure is
-- read off the console on the host side. TimerPersistent=0, because a
-- persistent timer forks a helper for its last-run write on every firing.
--
-- login-console is disabled because it takes /dev/console once the boot
-- settles, after which peinit's launch-failure lines would not be written
-- there.

local peinit = require("helpers.peinit")
peinit.claim(1)

--- A Oneshot that records each run, fired by its own timer every twenty
--- seconds at `phase` past, and retried four seconds after a failure.
local function recorder(name, phase)
    return { path = [[Machine\System\Services\]] .. name, values = {
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi",
          data = { "-c", "/bin/date +%s >> /run/" .. name .. ".runs" } },
        { name = "Type", type = "dword", data = 1 },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Triggers", type = "multi", data = { "timer:*-*-* *:*:" .. phase .. "/20" } },
        { name = "TimerPersistent", type = "dword", data = 0 },
        { name = "RestartPolicy", type = "dword", data = 1 },
        { name = "RestartDelay", type = "dword", data = 4 },
    } }
end

local vm = peinit.boot({
    name = "exhaust-launch",
    files = peinit.seed("pt-exhaust-launch", {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
        { path = [[Machine\System\Services\login-console]], values = {
            { name = "Disabled", type = "dword", data = 1 },
        } },
        recorder("pt-fd-pipe", 0),
        recorder("pt-fd-clone", 10),
    }),
})
peinit.settle(vm)

local RLIMIT_NOFILE = 7
local PRLIMIT64 = 302

--- PID 1's RLIMIT_NOFILE, as {soft, hard}.
local function nofile()
    local r = vm:syscall(PRLIMIT64, {
        args = { 1, RLIMIT_NOFILE, 0, 0 },
        bufs = { string.rep("\0", 16) },
        ptrs = { 3 },
    })
    assert(r.ret == 0, "prlimit64 read of PID 1 failed: errno " .. tostring(r.errno))
    return { string.unpack("<I8I8", r.out_bufs[1]) }
end

local original = nofile()

local function set_soft_limit(soft)
    local r = vm:syscall(PRLIMIT64, {
        args = { 1, RLIMIT_NOFILE, 0, 0 },
        bufs = { string.pack("<I8I8", soft, original[2]) },
        ptrs = { 2 },
    })
    return r.ret == 0, r.errno
end

--- The descriptor numbers PID 1 is not using, lowest first.
local function free_slots()
    local used, highest = {}, 0
    for _, entry in ipairs(vm:listdir("/proc/1/fd")) do
        local n = tonumber(entry.name)
        if n then
            used[n] = true
            if n > highest then highest = n end
        end
    end
    local free = {}
    for n = 0, highest + 32 do
        if not used[n] then free[#free + 1] = n end
    end
    return free
end

local function runs(name)
    local ok, text = pcall(function() return vm:read_file("/run/" .. name .. ".runs") end)
    return ok and #peinit.lines(text) or 0
end

--- Block until the host clock is `lo`..`hi` seconds into a twenty-second
--- cycle. The guest's clock is the host's (the RTC), to the second.
local function wait_for_window(lo, hi)
    wait_until(function()
        local s = os.time() % 20
        return (s >= lo and s <= hi) or nil
    end, { timeout = 30, interval = 0.2, desc = "the measurement window" })
end

--- Leave PID 1 exactly `slots` free descriptors, let `service`'s timer
--- fire into that, and put the limit back the moment the console says the
--- launch failed. Returns the console line and the service's status as it
--- stood right after the failure.
local function exhaust(t, service, window_lo, slots)
    wait_for_window(window_lo, window_lo + 2)
    local free = free_slots()
    local limit = free[slots + 1]
    local mark = #vm:console():read_log()
    local runs_before = runs(service)

    local ok, errno = set_soft_limit(limit)
    t:assert(ok, "PID 1's soft RLIMIT_NOFILE was lowered to " .. limit .. " (errno " ..
        tostring(errno) .. ")")
    local line = wait_until(function()
        local log = vm:console():read_log():sub(mark + 1)
        return log:match("[^\r\n]*peinit: service " .. service:gsub("%-", "%%-") ..
            " failed to launch[^\r\n]*")
    end, { timeout = 15, interval = 0.1, desc = service .. "'s timer to fire into the limit" })
    local restored = set_soft_limit(original[1])
    t:assert(restored, "and restored")

    local view = json.decode(vm:run("svctl --json status " .. service).stdout)
    return line, view, runs_before, ("%d free slots below %d (free: %s)"):format(
        slots, limit, table.concat(free, ",", 1, math.min(#free, slots + 2)))
end

test("a launch that runs PID 1 out of descriptors fails with ParentSetupFailure and is tried again",
    { spec = "peinit *exhaust.a-descriptor-exhaustion-at-launch-is-a-restart-eligible-parentsetupfailure" },
    function(t)
        t:assert(original[1] > 0, "PID 1's RLIMIT_NOFILE reads back: " .. original[1])

        -- pipe2. pt-fd-pipe fires on the minute's twenties; three slots
        -- are the token, the cgroup directory and /dev/null.
        local line, view, before, detail = exhaust(t, "pt-fd-pipe", 14, 3)
        t:assert(line:find("ParentSetupFailure: pipe2(", 1, true),
            "the start failed at pipe2, as a ParentSetupFailure (" .. detail .. "): " .. line)
        t:assert(line:find("Too many open files (os error 24)", 1, true),
            "with EMFILE: " .. line)
        t:assert_eq(view.cause, "parent_setup_failure", "the service's cause")
        t:assert_eq(view.state, "backoff",
            "and the cause is restart-eligible, so it waits in Backoff rather than Failed")
        -- Another go: the retry four seconds on, well before the timer's
        -- next firing twenty seconds on, and with descriptors to spare.
        wait_until(function() return runs("pt-fd-pipe") > before or nil end,
            { timeout = 12, interval = 0.3, desc = "pt-fd-pipe's retry to run" })

        -- clone3. pt-fd-clone fires ten seconds later in the cycle; nine
        -- slots are the six before and the three pipes' six descriptors,
        -- so the one clone3 needs for the pidfd is not there.
        line, view, before, detail = exhaust(t, "pt-fd-clone", 4, 9)
        t:assert(line:find("ParentSetupFailure: clone3(", 1, true),
            "the start failed at clone3, as a ParentSetupFailure (" .. detail .. "): " .. line)
        t:assert(line:find("Too many open files (os error 24)", 1, true),
            "with EMFILE: " .. line)
        t:assert_eq(view.cause, "parent_setup_failure", "the service's cause")
        t:assert_eq(view.state, "backoff", "and it waits in Backoff")
        wait_until(function() return runs("pt-fd-clone") > before or nil end,
            { timeout = 12, interval = 0.3, desc = "pt-fd-clone's retry to run" })
    end)
