-- peinit TRM §6.5 — reload: choosing between the signal path and the
-- command path, how each one resolves, and what interrupts them.
--
-- The image ships no tool that can write to a Unix datagram socket, so
-- nothing here can send `RELOADING=1` or `READY=1`. That removes the
-- confirmed outcome and the extended wait from reach and leaves the
-- other half of the protocol, which is the half a service that does not
-- implement the handshake gets: a detection window that expires, an
-- advisory outcome, and a service still Active at the end of it.
--
-- The services trap the signals they are sent and append to `/run`,
-- because a signal that was delivered and a signal that was not are
-- otherwise the same observation. They loop over a one-second sleep
-- rather than blocking forever: a shell runs a trap between commands, so
-- a handler on a process blocked in a single long sleep would not run
-- until the sleep returned.
--
-- `peios.quiet=0`, because two assertions are about a console line that
-- is *not* there, and at the default level nothing peinit writes after
-- the boot reaches the console anyway -- which would make those
-- assertions pass for the wrong reason.

local peinit = require("helpers.peinit")
peinit.claim(2)

local FILES = {
    -- Records the signals it is sent, and survives them: a service that
    -- died on SIGHUP would make the reload path untestable.
    ["pt/rl-daemon.sh"] = [[
trap 'echo hup >> /run/pt-rl-$1.log' HUP
trap 'echo usr1 >> /run/pt-rl-$1.log' USR1
while true; do
    /bin/sleep 1
done
]],
    -- A reload command that records where and as whom peinit ran it.
    ["pt/rl-reload.sh"] = [[
echo "cgroup=$(cat /proc/self/cgroup) user=$(/bin/token user)" >> /run/pt-rl-cmd.log
exit 0
]],
}

local function service(name, values)
    local base = {
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "Triggers", type = "multi", data = { "boot" } },
    }
    for _, value in ipairs(values) do base[#base + 1] = value end
    return { path = [[Machine\System\Services\]] .. name, values = base }
end

--- The signal-trapping daemon, tagged so each service has its own log.
local function daemon(name, tag, extra)
    local values = {
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi", data = { "/pt/rl-daemon.sh", tag } },
    }
    for _, value in ipairs(extra or {}) do values[#values + 1] = value end
    return service(name, values)
end

local RESIDENT = {
    { name = "ImagePath", type = "sz", data = "/bin/sleep" },
    { name = "Arguments", type = "multi", data = { "3600" } },
}

local function resident(name, extra)
    local values = {}
    for _, value in ipairs(RESIDENT) do values[#values + 1] = value end
    for _, value in ipairs(extra or {}) do values[#values + 1] = value end
    return service(name, values)
end

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },

    -- No ExecReload at all.
    daemon("pt-rl-hup", "hup"),
    -- A named signal instead.
    daemon("pt-rl-usr1", "usr1", {
        { name = "ExecReload", type = "sz", data = "signal:SIGUSR1" },
    }),
    -- No ExecReload, and a StartTimeout shorter than the detection
    -- window: the window is not clamped to it.
    daemon("pt-rl-short", "short", {
        { name = "StartTimeout", type = "dword", data = 1 },
    }),
    -- Interrupted mid-reload by a stop, and by a crash. Both are given
    -- a reload command that outlives the interruption.
    daemon("pt-rl-stop", "stop", {
        { name = "ExecReload", type = "sz", data = "/bin/sleep 60" },
        { name = "StartTimeout", type = "dword", data = 60 },
    }),
    daemon("pt-rl-crash", "crash", {
        { name = "ExecReload", type = "sz", data = "/bin/sleep 60" },
        { name = "StartTimeout", type = "dword", data = 60 },
        { name = "RestartPolicy", type = "dword", data = 2 },
        { name = "RestartDelay", type = "dword", data = 30 },
        { name = "RestartMaxRetries", type = "dword", data = 5 },
    }),

    -- The command path. HookIdentity is deliberately something other
    -- than the service's own identity, so a reload command that took it
    -- would say so.
    resident("pt-rl-cmd", {
        { name = "HookIdentity", type = "sz", data = "LocalService" },
        { name = "ExecReload", type = "sz", data = "/bin/sh /pt/rl-reload.sh" },
    }),
    resident("pt-rl-cmdfail", {
        { name = "ExecReload", type = "sz", data = "/bin/false" },
    }),
    resident("pt-rl-cmdslow", {
        { name = "ExecReload", type = "sz", data = "/bin/sleep 60" },
        { name = "StartTimeout", type = "dword", data = 2 },
    }),
}

local vm = peinit.boot({
    name = "reload",
    append = "peios.quiet=0",
    files = peinit.merge(FILES, peinit.seed("pt-reload", SERVICES)),
})

local function status(name)
    local out = vm:run("svctl --json status " .. name)
    if out.exit_code ~= 0 then
        local lines = peinit.lines(vm:console():read_log())
        local tail = {}
        for i = math.max(1, #lines - 30), #lines do tail[#tail + 1] = lines[i] end
        error("svctl status " .. name .. ": " .. out.stderr .. " CONSOLE: " ..
            table.concat(tail, " | "))
    end
    return json.decode(out.stdout)
end

local function settle(name, want, desc)
    return wait_until(function()
        local view = status(name)
        return view.state == want and view or nil
    end, { timeout = 90, interval = 0.2, desc = desc or (name .. " to reach " .. want) })
end

local function log_lines(path)
    local ok, text = pcall(function() return vm:read_file(path) end)
    if not ok then return {} end
    return peinit.lines(text)
end

--- A reload that waits, with the guest's own clock either side of it, so
--- how long peinit held the operation open is measurable.
local function timed_reload(name)
    local out = vm:run("/bin/date +%s; svctl --json --wait reload " .. name .. "; /bin/date +%s")
    local before, body, after = out.stdout:match("^%s*(%d+)%s+({.*})%s+(%d+)%s*$")
    return {
        elapsed = before and (tonumber(after) - tonumber(before)),
        ack = body and json.decode(body) or nil,
        raw = out.stdout,
    }
end

for _, name in ipairs({ "pt-rl-hup", "pt-rl-usr1", "pt-rl-short", "pt-rl-cmd" }) do
    settle(name, "active", name .. " to come up at boot")
end

test("an absent ExecReload means SIGHUP, and the service is Reloading and then Active again",
    {
        spec = {
            "peinit *reload.an-absent-execreload-means-sighup",
            "peinit *reload.a-reload-moves-the-service-to-reloading",
            "peinit *reload.the-handshake-needs-no-per-service-configuration",
        },
    },
    function(t)
        -- pt-rl-hup declares nothing at all about reloading or about
        -- notifications, and gets the whole protocol regardless.
        local reload = timed_reload("pt-rl-hup")
        t:assert(reload.ack, "the reload was answered: " .. reload.raw)
        t:assert_eq(reload.ack.state, "active",
            "and the service is Active at the end of it")

        local seen = log_lines("/run/pt-rl-hup.log")
        t:assert(#seen >= 1, "the main process was signalled")
        t:assert_eq(seen[1], "hup",
            "with SIGHUP, which is what an absent ExecReload means")
    end)

test("a signal: value sends that signal instead",
    { spec = "peinit *reload.a-signal-value-sends-that-signal" },
    function(t)
        timed_reload("pt-rl-usr1")
        local seen = wait_until(function()
            local lines = log_lines("/run/pt-rl-usr1.log")
            return lines[1] and lines or nil
        end, { timeout = 30, interval = 0.5, desc = "pt-rl-usr1 to be signalled" })
        t:assert_eq(seen[1], "usr1",
            "the named signal was sent")
        for _, line in ipairs(seen) do
            t:assert(line ~= "hup",
                "and SIGHUP was not, so the value replaced the default rather than adding to it")
        end
    end)

test("the detection window is two seconds and a short StartTimeout does not shorten it",
    {
        spec = {
            "peinit *reload.the-detection-window-is-a-fixed-two-seconds",
            "peinit *reload.a-short-starttimeout-does-not-shorten-the-detection-window",
            "peinit *reload.every-reload-path-has-a-timeout",
            -- Only the branch a service that sends nothing takes. The
            -- other three are notification-driven and this image ships
            -- no tool that can send one.
            "peinit *reload.the-signal-path-resolves-on-the-main-processs-notifications",
        },
    },
    function(t)
        -- Neither service can answer the handshake, so both reloads
        -- resolve when the window expires. That is the window, measured.
        local ordinary = timed_reload("pt-rl-hup")
        t:assert(ordinary.elapsed and ordinary.elapsed >= 2,
            "a reload that nothing answers takes the whole window: " ..
            tostring(ordinary.elapsed) .. "s")
        t:assert(ordinary.elapsed <= 8,
            "and then resolves rather than hanging: " .. tostring(ordinary.elapsed) .. "s")

        -- pt-rl-short's StartTimeout is one second, and a reload
        -- operation's lifetime is exactly StartTimeout -- so a `--wait`
        -- caller is told the operation timed out at one second. The
        -- window is a different clock: if it were clamped to the
        -- operation's deadline the service would be back in Active by
        -- then, and it is not.
        --
        -- Issued and sampled in one guest command, so the sleep is the
        -- only thing between them.
        local probe = vm:run(
            "svctl --json --no-wait reload pt-rl-short >/dev/null; /bin/sleep 1; " ..
            "svctl --json status pt-rl-short")
        t:assert(probe.stdout:find('"state":"reloading"', 1, true),
            "a second after the reload -- past a StartTimeout of one -- the service is " ..
            "still Reloading, so the window was not clamped to it: " .. probe.stdout)
        settle("pt-rl-short", "active", "pt-rl-short's window to expire")
    end)

test("the outcome is carried in the operation's result, and an expiring window stays quiet",
    {
        spec = {
            "peinit *reload.the-outcome-is-carried-in-the-operations-result",
            "peinit *reload.a-detection-window-expiring-stays-quiet",
        },
    },
    function(t)
        local reload = timed_reload("pt-rl-hup")
        t:assert_eq(reload.ack.mode, "advisory",
            "a window that expired with no answer is advisory: " .. reload.raw)

        local operation = json.decode(
            vm:run("svctl --json operation-status " .. reload.ack.operation_id).stdout).operation
        t:assert_eq(operation.state, "completed", "the operation completed")
        t:assert(operation.result and operation.result:find("detection window expired", 1, true),
            "and its result says which way it resolved: " .. tostring(operation.result))

        -- Quiet: an expiring window is the ordinary outcome for a
        -- service that does not implement the handshake, so it is not
        -- reported. The boot is Verbose, so a line that peinit wrote
        -- would be on the console.
        t:assert(not vm:console():read_log():find("signalled RELOADING=1", 1, true),
            "no console report for an expiring detection window")
        local events = vm:run(
            "evctl 'EVENTS service.reload_unconfirmed SINCE 1h ago TAKE 50' --format jsonl")
        t:assert(not events.stdout:find("pt-rl-", 1, true),
            "and no service.reload_unconfirmed event: " .. events.stdout)
    end)

test("a reload command runs in the service's hooks cgroup under the service's own identity",
    { spec = "peinit *reload.a-reload-command-runs-in-hooks-under-the-services-own-identity" },
    function(t)
        timed_reload("pt-rl-cmd")
        local record = wait_until(function()
            return log_lines("/run/pt-rl-cmd.log")[1]
        end, { timeout = 30, interval = 0.5, desc = "the reload command to run" })

        t:assert(record:find("cgroup=0::/peinit/pt%-rl%-cmd/hooks"),
            "the command ran in the service's hooks/ sub-cgroup: " .. record)
        t:assert(record:find("SYSTEM") or record:find("S%-1%-5%-18"),
            "as the service's own identity: " .. record)
        t:assert(not (record:find("LocalService") or record:find("S%-1%-5%-19")),
            "and not as HookIdentity, which does not apply to a reload: " .. record)
    end)

test("a reload command that fails leaves the running service Active",
    {
        spec = {
            "peinit *reload.the-command-exit-gates-failure-and-ready-gates-confirmation",
            "peinit *reload.a-failed-reload-never-takes-a-service-out-of-active",
        },
    },
    function(t)
        local before = status("pt-rl-cmdfail")
        t:assert_eq(before.state, "active", "the service is up before the reload")

        local reload = timed_reload("pt-rl-cmdfail")
        t:assert_eq(reload.ack.mode, "failed",
            "the command's non-zero exit is what failed the reload: " .. reload.raw)
        t:assert_eq(reload.ack.state, "active",
            "and the service is still Active")
        t:assert_eq(status("pt-rl-cmdfail").current_job.id, before.current_job.id,
            "on the same activation, so nothing restarted it")
    end)

test("a reload command that outruns StartTimeout is killed and the reload fails",
    {
        spec = {
            "peinit *reload.the-command-exit-gates-failure-and-ready-gates-confirmation",
            "peinit *reload.every-reload-path-has-a-timeout",
            "peinit *reload.a-failed-reload-never-takes-a-service-out-of-active",
        },
    },
    function(t)
        -- The command sleeps for a minute against a two-second
        -- StartTimeout. A reload operation's own lifetime is also
        -- StartTimeout, so the caller waiting on it is told the
        -- operation timed out rather than being handed the "failed"
        -- outcome; what the manual's rule is about is the service, and
        -- the service is what is asserted here.
        local before = status("pt-rl-cmdslow")
        local reload = timed_reload("pt-rl-cmdslow")
        t:assert(reload.elapsed and reload.elapsed <= 20,
            "the reload resolved at the timeout rather than running for a minute: " ..
            tostring(reload.elapsed) .. "s")

        local after = settle("pt-rl-cmdslow", "active",
            "pt-rl-cmdslow to be returned to Active")
        t:assert_eq(after.current_job.id, before.current_job.id,
            "on the same activation, so the failed reload did not restart it")

        -- The hooks sub-cgroup was killed, taking the sleep with it.
        wait_until(function()
            local procs = vm:run(
                "cat /sys/fs/cgroup/peinit/pt-rl-cmdslow/hooks/cgroup.procs 2>/dev/null")
            return procs.stdout:match("^%s*$") ~= nil
        end, { timeout = 30, interval = 0.5, desc = "the reload command's cgroup to be emptied" })
    end)

test("a crash while Reloading is a ProcessCrash on the ordinary restart path",
    {
        spec = {
            "peinit *reload.a-crash-while-reloading-is-a-processcrash-on-the-restart-path",
            "peinit *reload.a-crash-cancels-the-timers-and-kills-the-reload-command",
        },
    },
    function(t)
        local up = settle("pt-rl-crash", "active", "pt-rl-crash to come up")
        vm:run("svctl --json --no-wait reload pt-rl-crash"):assert_ok()
        settle("pt-rl-crash", "reloading", "pt-rl-crash to enter Reloading")

        -- Kill the main process out from under the reload.
        vm:run("kill -9 " .. tostring(up.current_job.pid)):assert_ok()
        local crashed = settle("pt-rl-crash", "backoff",
            "pt-rl-crash to take the restart path out of Reloading")
        t:assert_eq(crashed.cause, "process_crash",
            "the crash, not the reload, is what moved it")

        -- The in-flight reload command was killed with it, and the
        -- reload timers went too -- the service is waiting out a restart
        -- delay rather than a reload deadline.
        wait_until(function()
            local procs = vm:run(
                "cat /sys/fs/cgroup/peinit/pt-rl-crash/hooks/cgroup.procs 2>/dev/null")
            return procs.stdout:match("^%s*$") ~= nil
        end, { timeout = 30, interval = 0.5, desc = "the reload command's cgroup to be emptied" })
        vm:run("sleep 4")
        t:assert_eq(status("pt-rl-crash").state, "backoff",
            "and no reload deadline fired to move it back to Active")
    end)

test("a stop while Reloading cancels the reload and sends SIGTERM at once",
    {
        spec = "peinit *reload.a-stop-while-reloading-cancels-the-reload-and-sigterms-at-once",
        -- PEI-820: the stop drops the reload's deadlines and kills the
        -- command's cgroup, but leaves the command's JOB, whose terminal
        -- event then moves the service to Active unconditionally. From
        -- Inactive that is not a listed transition, the runtime loop
        -- treats the rejection as fatal, and PID 1 enters recovery.
        tags = { "known-bug" },
    },
    function(t)
        -- Its own VM: the failure mode takes the whole machine down, and
        -- a shared one would fail every test after this rather than this
        -- one.
        local own = peinit.boot({
            name = "reload-stop",
            append = "peios.quiet=0",
            files = peinit.merge(FILES, peinit.seed("pt-reload", SERVICES)),
        })
        local function own_status(name)
            local out = own:run("svctl --json status " .. name)
            if out.exit_code ~= 0 then
                local lines = peinit.lines(own:console():read_log())
                local tail = {}
                for i = math.max(1, #lines - 6), #lines do tail[#tail + 1] = lines[i] end
                error("svctl status " .. name .. ": " .. out.stderr .. " CONSOLE: " ..
                    table.concat(tail, " | "))
            end
            return json.decode(out.stdout)
        end
        local function own_settle(name, want, desc)
            return wait_until(function()
                local view = own_status(name)
                return view.state == want and view or nil
            end, { timeout = 90, interval = 0.2, desc = desc })
        end

        own_settle("pt-rl-stop", "active", "pt-rl-stop to come up")
        local reload = json.decode(
            own:run("svctl --json --no-wait reload pt-rl-stop").stdout)
        t:assert(reload.operation_id, "the reload was accepted")
        own_settle("pt-rl-stop", "reloading", "pt-rl-stop to enter Reloading")

        -- The reload command is a sixty-second sleep and StartTimeout is
        -- sixty seconds, so anything that finishes promptly did so
        -- because the stop cancelled the reload rather than waited it
        -- out.
        own:run("svctl --no-wait stop pt-rl-stop"):assert_ok()
        own_settle("pt-rl-stop", "inactive", "pt-rl-stop to stop")
        t:assert_eq(own_status("pt-rl-stop").cause, "explicit_stop",
            "under the stop's own cause")

        -- The reload operation was abandoned rather than completed.
        local operation = json.decode(
            own:run("svctl --json operation-status " .. reload.operation_id).stdout).operation
        t:assert(operation.state == "aborted" or operation.state == "cancelled",
            "the reload operation was aborted: " .. tostring(operation.state))

        -- And the command's cgroup went with it.
        local procs = own:run("cat /sys/fs/cgroup/peinit/pt-rl-stop/hooks/cgroup.procs 2>/dev/null")
        t:assert(procs.stdout:match("^%s*$"),
            "the reload command's cgroup was killed: " .. procs.stdout)
    end)
