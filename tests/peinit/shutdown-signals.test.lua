-- peinit TRM §12.3 — signals: every one blocked and read through a
-- signalfd from the event loop, and what peinit does with the statuses
-- it reaps.
--
-- Nothing here shuts the machine down, so this is the one file in the
-- chapter that can share a single VM across every test. What it costs
-- instead is indirection: the signalfd and its mask are not visible to
-- any tool the guest ships, so the evidence is `/proc/1/status`,
-- `/proc/1/fd` and `/proc/1/fdinfo` — which say exactly what was blocked
-- and with what flags the descriptor was created, and say it about the
-- running PID 1 rather than about the source.
--
-- The reaping rules are read through submitted jobs. A job's view
-- carries the normalised status — `exit_code` for a child that exited,
-- `exit_signal` for one that was signalled — which is the same
-- normalisation every service exit goes through, exposed where a test
-- can see it.

local peinit = require("helpers.peinit")
peinit.claim(1)

local vm = peinit.boot({ name = "signals" })

--- Every service's state, by name. `svctl --json list` emits each
--- service's members in alphabetical key order, which puts `"service"`
--- immediately before `"state"`.
local function states()
    local out, any = {}, false
    for name, state in vm:run("svctl --json list").stdout
        :gmatch('"service":"([^"]+)","state":"([^"]+)"') do
        out[name] = state
        any = true
    end
    assert(any, "svctl list answered with no services")
    return out
end

--- A stable, comparable rendering of the service table.
local function state_summary()
    local names = {}
    local seen = states()
    for name in pairs(seen) do names[#names + 1] = name end
    table.sort(names)
    local parts = {}
    for _, name in ipairs(names) do parts[#parts + 1] = name .. "=" .. seen[name] end
    return table.concat(parts, " ")
end

-- Settle the boot once, at file scope. Nothing here shuts the machine
-- down, but one test compares the service table before and after an
-- unrelated event, and a boot still in progress would move it on its own.
wait_until(function()
    for _, state in pairs(states()) do
        if state == "starting" then return false end
    end
    return true
end, { timeout = 60, interval = 0.5, desc = "the boot to settle" })

-- Signal numbers on x86-64, for the mask arithmetic below.
local SIGHUP, SIGINT, SIGKILL, SIGUSR1 = 1, 2, 9, 10
local SIGPIPE, SIGTERM, SIGCHLD, SIGSTOP, SIGPWR = 13, 15, 17, 19, 30

local NIBBLE_BIT = { [0] = 1, [1] = 2, [2] = 4, [3] = 8 }

--- Is `signal` set in a `/proc`-style 64-bit hex signal mask?
---
--- Done a nibble at a time rather than with `tonumber(hex, 16)`: the
--- mask has bit 63 set, which does not fit a Lua integer as a positive
--- number, and the float it degrades to has lost the low bits this needs.
local function mask_has(hex, signal)
    local bit = signal - 1
    local index = #hex - (bit // 4)
    local nibble = tonumber(hex:sub(index, index), 16)
    assert(nibble, "not a hex mask: " .. hex)
    return nibble & NIBBLE_BIT[bit % 4] ~= 0
end

--- One `Name:\tvalue` field out of /proc/1/status.
local function proc1_status(field)
    local text = vm:run("cat /proc/1/status").stdout
    return text:match(field .. ":%s*(%S+)")
end

test("PID 1 blocks every blockable signal and reads them through a nonblocking, cloexec signalfd",
    {
        spec = {
            "peinit *signal.every-signal-is-blocked-and-read-through-a-signalfd",
            "peinit *signal.the-mask-is-every-blockable-signal",
            "peinit *signal.the-signalfd-carries-the-same-mask-and-is-cloexec-nonblocking",
        },
    },
    function(t)
        local blocked = proc1_status("SigBlk")
        t:assert(blocked, "PID 1 reports a blocked mask")
        for _, signal in ipairs({ SIGHUP, SIGINT, SIGUSR1, SIGPIPE, SIGTERM, SIGCHLD, SIGPWR }) do
            t:assert(mask_has(blocked, signal),
                "signal " .. signal .. " is blocked (SigBlk " .. blocked .. ")")
        end
        -- The two the kernel will not let anyone block, and which are
        -- therefore never delivered through a signalfd either.
        t:assert(not mask_has(blocked, SIGKILL),
            "SIGKILL is not in the mask: it is not blockable")
        t:assert(not mask_has(blocked, SIGSTOP),
            "SIGSTOP is not in the mask either")

        -- The descriptor itself. `ls -l /proc/1/fd` names what each fd
        -- points at, and a signalfd shows as an anon_inode.
        local fds = vm:run("ls -l /proc/1/fd")
        fds:assert_ok()
        local signalfd = fds.stdout:match("(%d+) %-> anon_inode:%[signalfd%]")
        t:assert(signalfd, "PID 1 holds a signalfd: " .. fds.stdout)

        local info = vm:run("cat /proc/1/fdinfo/" .. signalfd)
        info:assert_ok()
        local sigmask = info.stdout:match("sigmask:%s*(%x+)")
        t:assert(sigmask, "the signalfd reports its mask: " .. info.stdout)
        t:assert_eq(sigmask, blocked,
            "and it is the same mask that was installed with rt_sigprocmask")

        local flags = tonumber(info.stdout:match("flags:%s*(%d+)"), 8)
        t:assert(flags, "the signalfd reports its flags: " .. info.stdout)
        t:assert(flags & 0x800 ~= 0, "created SFD_NONBLOCK (O_NONBLOCK)")
        t:assert(flags & 0x80000 ~= 0, "and SFD_CLOEXEC (O_CLOEXEC)")
    end)

test("the only signals PID 1 catches are the Rust runtime's stack-overflow guard",
    {
        spec = {
            "peinit *signal.peinit-installs-no-signal-handlers-of-its-own",
            "peinit *signal.the-two-caught-signals-are-the-runtimes-guard",
        },
    },
    function(t)
        -- The point of reading signals from the event loop is that
        -- nothing of peinit's runs asynchronously, and /proc says what
        -- could: SigCgt is the set of signals with a handler installed.
        --
        -- It is not empty, and the two bits in it are the ones the Rust
        -- runtime sets for its stack-overflow guard — SIGSEGV (11) and
        -- SIGBUS (7), which is 0x440. Nothing peinit installs is in
        -- there, and the guard runs on an alternate stack over state
        -- peinit does not own, so the async-signal-safety argument holds.
        local caught = proc1_status("SigCgt")
        t:assert(caught, "PID 1 reports a caught mask")
        t:assert_eq(tonumber(caught, 16), 0x440,
            "exactly SIGSEGV and SIGBUS are caught, and nothing else: " .. caught)
    end)

test("SIGHUP, SIGPIPE and everything else are ignored, and no signal can kill PID 1",
    {
        spec = {
            "peinit *signal.sighup-and-sigpipe-are-ignored",
            "peinit *signal.every-other-signal-is-ignored-and-none-can-kill-pid-1",
        },
    },
    function(t)
        -- SIGKILL is in the list on purpose. It is the one signal that
        -- cannot be blocked, so it is the one that tests the kernel's
        -- protection of PID 1 rather than peinit's mask — and if that
        -- protection were not there, nothing after this line would run.
        local before = vm:run("cat /proc/1/comm")
        before:assert_ok()

        for _, signal in ipairs({ "HUP", "PIPE", "USR1", "USR2", "QUIT", "ABRT", "KILL" }) do
            vm:run("kill -" .. signal .. " 1"):assert_ok()
        end

        local after = vm:run("cat /proc/1/comm")
        after:assert_ok()
        t:assert_eq(after.stdout, before.stdout,
            "PID 1 is the same process it was before seven signals were sent at it")
        vm:run("svctl list"):assert_ok()

        local log = vm:console():read_log()
        t:assert(not log:find("peinit: shutdown ", 1, true),
            "and none of them was taken for a shutdown request")
    end)

test("an orphan reparented to PID 1 is reaped, and attributed to nothing",
    {
        spec = {
            "peinit *signal.orphans-reparented-to-pid-1-are-reaped-as-untracked",
            "peinit *signal.the-wait-status-is-normalised-before-policy-sees-it",
        },
    },
    function(t)
        local before = state_summary()

        -- Double fork: the middle shell exits at once, so the innermost
        -- process is reparented to PID 1 while it is still running. It
        -- leaves a marker so the test knows it really ran, and then
        -- exits non-zero — a status that belongs to no job peinit has.
        vm:run("rm -f /run/pt-orphan"):assert_ok()
        vm:run("( ( sleep 1; echo ran > /run/pt-orphan; exit 7 ) & ) &"):assert_ok()
        wait_until(function()
            return vm:run("cat /run/pt-orphan 2>/dev/null").stdout:find("ran", 1, true)
        end, { timeout = 90, interval = 0.3, desc = "the orphan to run" })

        -- Nothing peinit does not know about is left behind as a zombie:
        -- as PID 1 it reaps whatever is reparented to it.
        wait_until(function()
            local stats = vm:run("cat /proc/[0-9]*/stat 2>/dev/null").stdout
            for line in stats:gmatch("[^\r\n]+") do
                local state, ppid = line:match("%)%s+(%a)%s+(%d+)")
                if state == "Z" and ppid == "1" then return false end
            end
            return true
        end, { timeout = 90, interval = 0.3, desc = "the orphan to be reaped" })

        -- And it was attributed to nothing: an untracked reap must not
        -- move any service.
        t:assert_eq(state_summary(), before,
            "no service changed state because of a child that belonged to none")
    end)

test("an exited child carries its exact exit code and a signalled one carries its signal",
    {
        spec = {
            "peinit *signal.an-exited-child-carries-its-exact-exit-code",
            "peinit *signal.a-signalled-child-carries-the-signal-and-the-core-dump-bit",
        },
    },
    function(t)
        -- A submitted job's view is the normalised status, exposed. The
        -- same normalisation stands behind every service exit; this is
        -- simply the place a test can read the numbers off.
        local function run_job(command)
            local submitted = vm:run("svctl --json job submit " .. command)
            submitted:assert_ok()
            local id = submitted.stdout:match('"id":"([^"]+)"')
            assert(id, "no job identifier in: " .. submitted.stdout)
            return wait_until(function()
                local view = vm:run("svctl --json job status " .. id).stdout
                local state = view:match('"state":"([^"]+)"')
                if state == "running" or state == "created" then return nil end
                return view
            end, { timeout = 60, interval = 0.3, desc = "job " .. id .. " to end" })
        end

        -- The full 0..255 range is claimed, so the exit code that would
        -- be truncated by a naive `WEXITSTATUS` mistake is the one worth
        -- asking for, alongside an ordinary one.
        for _, code in ipairs({ 42, 255 }) do
            local view = run_job([[/bin/sh -c "exit ]] .. code .. [["]])
            t:assert_eq(view:match('"exit_code":(%-?%d+)'), tostring(code),
                "an exited child carried exit code " .. code .. ": " .. view)
            t:assert(view:match('"exit_signal":null'),
                "and no terminating signal: " .. view)
        end

        -- `$$` is single-quoted so the guest's shell leaves it for the
        -- job's own shell, which then kills itself with SIGUSR1 (10).
        local killed = run_job([[/bin/sh -c 'kill -USR1 $$']])
        t:assert_eq(killed:match('"exit_signal":(%d+)'), tostring(SIGUSR1),
            "a signalled child carried the terminating signal number: " .. killed)
        t:assert(killed:match('"exit_code":null'),
            "and no exit code, because it never exited: " .. killed)
    end)
