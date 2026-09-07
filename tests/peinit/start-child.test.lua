-- peinit TRM §5.4 — the child path: the straight line of setup between
-- `clone3` returning in the child and `execve`.
--
-- Every step of it is either invisible or visible for the rest of the
-- process's life, and the visible ones are all in /proc: the descriptor
-- table says which streams the child was given and which of peinit's it
-- was not, `status` says what happened to the signal mask and the
-- dispositions, `oom_score_adj` says which side of the ErrorControl
-- split the service is on, and `stat`'s tty field says whether the two
-- terminal steps ran.
--
-- The subjects are two staged services differing only in
-- `ErrorControl`, and the image's own login-console, which is the one
-- service on the machine with a `TTYPath`.

local peinit = require("helpers.peinit")
peinit.claim(1)

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },
    { path = [[Machine\System\Services\pt-child]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "ErrorControl", type = "dword", data = 0 },
    } },
    -- Identical but for ErrorControl=Critical, so that the only thing
    -- that can explain a difference in oom_score_adj is that field.
    { path = [[Machine\System\Services\pt-critical]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "ErrorControl", type = "dword", data = 1 },
    } },
}

local vm = peinit.boot({ name = "child", files = peinit.seed("pt-child", SERVICES) })

--- The main process of a service, once it has one.
local function main_pid(service)
    return wait_until(function()
        local ok, procs = pcall(function()
            return vm:read_file("/sys/fs/cgroup/peinit/" .. service .. "/main/cgroup.procs")
        end)
        return ok and procs:match("^(%d+)") or nil
    end, { timeout = 60, interval = 0.5, desc = service .. " to have a main process" })
end

--- `/proc/<pid>/fd` as a map of descriptor number to its target.
local function descriptors(pid)
    local fds = {}
    for _, entry in ipairs(vm:listdir("/proc/" .. pid .. "/fd")) do
        local link = vm:run("readlink /proc/" .. pid .. "/fd/" .. entry.name)
        fds[tonumber(entry.name)] = link.stdout:gsub("%s+$", "")
    end
    return fds
end

--- The named field of `/proc/<pid>/status`.
local function status_field(pid, name)
    return vm:read_file("/proc/" .. pid .. "/status"):match("\n" .. name .. ":%s*([^\r\n]+)")
end

--- `/proc/<pid>/stat` as an array of fields. `comm` is parenthesised and
--- may contain spaces, so it is cut out before the split rather than
--- being split on.
local function stat_fields(pid)
    local raw = vm:read_file("/proc/" .. pid .. "/stat")
    local pid_field, rest = raw:match("^(%d+) %b() (.*)$")
    local fields = { pid_field, "comm" }
    for field in rest:gmatch("%S+") do fields[#fields + 1] = field end
    return fields
end

test("a service without a TTYPath gets /dev/null on stdin and the output pipes on stdout and stderr",
    { spec = "peinit *child.the-standard-streams" },
    function(t)
        local fds = descriptors(main_pid("pt-child"))
        t:assert_eq(fds[0], "/dev/null", "stdin is /dev/null")
        t:assert(fds[1] and fds[1]:find("^pipe:"),
            "stdout is a pipe, which is what peinit captures for logging: " .. tostring(fds[1]))
        t:assert(fds[2] and fds[2]:find("^pipe:"),
            "and so is stderr: " .. tostring(fds[2]))
        t:assert(fds[1] ~= fds[2],
            "two pipes rather than one, so the two streams stay distinguishable")
    end)

test("a service inherits its standard streams and nothing else of peinit's",
    {
        spec = {
            "peinit *child.only-the-streams-and-injected-descriptors-are-inherited",
            "peinit *child.natively-opened-descriptors-have-cloexec-set-by-hand",
        },
    },
    function(t)
        -- /bin/sleep opens nothing of its own, so its descriptor table
        -- is exactly what it was handed. pt-child has no fd store, so
        -- what it was handed is its three streams.
        local fds = descriptors(main_pid("pt-child"))
        local highest = 0
        for number in pairs(fds) do highest = math.max(highest, number) end
        t:assert_eq(highest, 2,
            "the service holds descriptors 0, 1 and 2 and nothing above them")

        -- There was plenty for it to inherit. peinit itself is holding
        -- sockets, an epoll instance, pidfds, timerfds and the input
        -- devices it opened for the power button -- and, per launch, an
        -- O_PATH descriptor on the service's own cgroup directory. Not
        -- one of them crossed the exec, which is the close-on-exec
        -- discipline working, including on the descriptors the Peios
        -- native file interface hands back without the flag set.
        local held = descriptors(1)
        local kinds = {}
        for _, target in pairs(held) do kinds[#kinds + 1] = target end
        local joined = table.concat(kinds, " ")
        t:assert(joined:find("eventpoll", 1, true),
            "peinit holds its epoll instance: " .. joined)
        t:assert(joined:find("socket:", 1, true), "and sockets")
        t:assert(not joined:find("/sys/fs/cgroup", 1, true),
            "peinit does not keep a cgroup directory descriptor open between launches")

        -- Nothing peinit holds appears in the service's table. Checked
        -- by target rather than by number, since the two tables would
        -- otherwise only be compared where they happen to collide.
        for number, target in pairs(fds) do
            if number > 2 then
                t:fail("the service inherited fd " .. number .. " -> " .. target)
            end
        end
    end)

test("the child starts with an empty signal mask and no inherited dispositions",
    { spec = "peinit *child.the-signal-mask-is-emptied-and-dispositions-reset" },
    function(t)
        -- peinit blocks every signal for its signalfd, and a child
        -- inherits that mask across the fork. Both halves are visible at
        -- once: PID 1's mask is nearly full and it is ignoring at least
        -- one signal; the service it forked has neither.
        local peinit_blocked = status_field(1, "SigBlk")
        t:assert(peinit_blocked and peinit_blocked ~= "0000000000000000",
            "peinit is running with signals blocked: " .. tostring(peinit_blocked))
        t:assert(status_field(1, "SigIgn") ~= "0000000000000000",
            "and with at least one disposition set to ignore")

        local pid = main_pid("pt-child")
        t:assert_eq(status_field(pid, "SigBlk"), "0000000000000000",
            "the service's signal mask is empty")
        t:assert_eq(status_field(pid, "SigIgn"), "0000000000000000",
            "and it is ignoring nothing, so the dispositions were reset to SIG_DFL")
    end)

test("oom_score_adj is -1000 for a Critical service and 0 for everything else",
    { spec = "peinit *child.oom-score-adj-follows-error-control" },
    function(t)
        local critical = vm:read_file("/proc/" .. main_pid("pt-critical") .. "/oom_score_adj")
        t:assert_eq(critical:gsub("%s+$", ""), "-1000",
            "a Critical service is OOM-immune, because its loss reboots the machine")

        local normal = vm:read_file("/proc/" .. main_pid("pt-child") .. "/oom_score_adj")
        t:assert_eq(normal:gsub("%s+$", ""), "0",
            "and an ordinary one is left where the kernel put it")
    end)

test("a service with a TTYPath owns its terminal on all three streams; one without has no terminal at all",
    {
        spec = {
            "peinit *child.the-child-setup-order",
            "peinit *child.setsid-precedes-the-stream-setup",
            "peinit *child.a-terminal-attached-service-gets-the-terminal-on-all-three-streams",
            "peinit *child.without-a-ttypath-the-terminal-steps-do-not-run",
        },
    },
    function(t)
        -- The image's login-console is the one service with a TTYPath.
        -- It is triggered on boot:settled, so it starts some way after
        -- the boot mark.
        local pid = main_pid("login-console")
        local fds = descriptors(pid)
        for _, stream in ipairs({ 0, 1, 2 }) do
            t:assert_eq(fds[stream], "/dev/console",
                "stream " .. stream .. " is the terminal it asked for")
        end
        -- Not the daemon wiring: the /dev/null descriptor and both pipe
        -- pairs were closed, so its output is not captured for logging.
        for number, target in pairs(fds) do
            t:assert(not target:find("^pipe:"),
                "fd " .. number .. " is not an output pipe: " .. target)
        end

        -- And it acquired the terminal as its *controlling* terminal,
        -- which is what the ordering of the first four steps buys.
        -- TIOCSCTTY with a literal zero fails for anything but a session
        -- leader that owns no terminal, so the setsid() of step 2 must
        -- have run first; and setsid() drops a controlling terminal, so
        -- it must also have run before the streams were attached in
        -- step 3. A non-zero tty is the evidence that both held.
        local tty = tonumber(stat_fields(pid)[7])
        t:assert(tty and tty ~= 0,
            "login-console has a controlling terminal: tty_nr " .. tostring(tty))

        -- Without a TTYPath neither step runs, so an ordinary service
        -- has no controlling terminal -- the same position peinit is in.
        t:assert_eq(tonumber(stat_fields(main_pid("pt-child"))[7]), 0,
            "a service with no TTYPath acquired no controlling terminal")
        t:assert_eq(tonumber(stat_fields(1)[7]), 0,
            "which is peinit's own position, whose session it stayed in")
    end)
