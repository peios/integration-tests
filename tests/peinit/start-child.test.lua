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
-- `ErrorControl`, a third Critical one narrowed by `RequiredPrivileges`,
-- and the image's own login-console, whose `TTYPath` is the system
-- console.

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
    -- Critical again, but narrowed to a token that cannot lower
    -- oom_score_adj itself: no SeIncreaseQuotaPrivilege. It starts only
    -- because peinit sets the score before installing the token
    -- (PEI-1150).
    { path = [[Machine\System\Services\pt-critical-narrow]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "RequiredPrivileges", type = "multi", data = { "SeChangeNotifyPrivilege" } },
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

--- `/proc/<pid>/fd` as a map of descriptor number to its target. The links
--- are read by the agent too: one of the processes read here is PID 1,
--- which is TCB-signed, and PIP refuses the shell's `readlink` its /proc.
local function descriptors(pid)
    local fds = {}
    for _, entry in ipairs(vm:listdir("/proc/" .. pid .. "/fd")) do
        fds[tonumber(entry.name)] = peinit.proc_link(vm, pid, "fd/" .. entry.name) or ""
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

test("a Critical service whose token lacks SeIncreaseQuotaPrivilege still starts OOM-immune",
    { spec = "peinit *child.resources-are-set-before-the-token-is-installed" },
    function(t)
        local narrow = vm:read_file("/proc/" .. main_pid("pt-critical-narrow") .. "/oom_score_adj")
        t:assert_eq(narrow:gsub("%s+$", ""), "-1000",
            "the score was peinit's act under its own credentials, not the service token's")
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
        -- The image's login-console has a TTYPath (as do its login-ttyN
        -- siblings on the virtual consoles). It is triggered on
        -- boot:settled, so it starts some way after the boot mark.
        local pid = main_pid("login-console")
        local fds = descriptors(pid)
        -- It asked for `/dev/console`, and what it is given is the device
        -- that alias names on this boot: §11.6 resolves `/dev/console` in a
        -- TTYPath from the last entry of /sys/class/tty/console/active,
        -- `tty0` pinned to `/dev/tty1`, so that a VT switch cannot move a
        -- session (PEI-1187). On this profile that is the serial port.
        local active = vm:read_file("/sys/class/tty/console/active")
        local last
        for name in active:gmatch("%S+") do last = name end
        t:assert(last, "the kernel names an active console: " .. active)
        local endpoint = "/dev/" .. ((last == "tty0") and "tty1" or last)
        for _, stream in ipairs({ 0, 1, 2 }) do
            t:assert_eq(fds[stream], endpoint,
                "stream " .. stream .. " is the terminal it asked for, resolved")
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

-- Two steps of the child path have no visible surface. The exit codes are
-- the child's own `_exit` values, and peinit acts on the error pipe rather
-- than on the child's wait status -- so a pre-exec failure never surfaces a
-- 126 or 127 to a guest. And the NOTIFY_SOCKET confirmation only fails when
-- the variable is absent, which peinit's own environment construction never
-- lets happen. Both are proved in the crate.

test("a setup failure exits 126 and a failed exec 127",
    {
        spec = "peinit *child.a-setup-failure-exits-126-and-a-failed-exec-127",
        covered_by = "cargo:peinit2 boundary::linux_launch::process::child::tests::child_setup_and_exec_use_the_conventional_exit_codes",
        skip = "peinit reports a pre-exec failure through the error pipe and kills the cgroup rather than surfacing the child's wait status, so the 126/127 exit codes never reach a guest; runs under cargo test -p peinit2 --all-features --lib boundary::linux_launch::process::child::tests::child_setup_and_exec_use_the_conventional_exit_codes",
    },
    function(t) end)

test("the child confirms NOTIFY_SOCKET is present rather than setting it",
    {
        spec = "peinit *child.notify-socket-is-confirmed-not-set",
        covered_by = "cargo:peinit2 boundary::linux_launch::command::tests::notify_socket_confirmation_discriminates_present_from_absent",
        skip = "peinit always inserts NOTIFY_SOCKET in the base environment and filters any configured value out of the layers below, so a guest cannot make the variable absent and drive the child's confirmation to its EINVAL failure; runs under cargo test -p peinit2 --all-features --lib boundary::linux_launch::command::tests::notify_socket_confirmation_discriminates_present_from_absent",
    },
    function(t) end)
