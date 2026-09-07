-- Peinit TRM §10.1, §10.5, §10.7 — the three sockets peinit serves the
-- running system on: the control socket every runtime command arrives
-- on, the datagram socket services report themselves ready over, and the
-- sequenced-packet socket jobs are submitted to.
--
-- All three are made in Phase 1 and live for the lifetime of the system,
-- so a completed boot is the right place to look at them. What the
-- chapter says about each is mostly a claim about its Security
-- Descriptor, and under KACS that descriptor is the entire access
-- policy: the kernel checks it at connect(), before peinit has any say.
-- So the descriptors are read off the live inodes rather than inferred
-- from peinit having started.

local peinit = require("helpers.peinit")
peinit.claim(2)

local vm = peinit.boot()

-- One long-running service to look at from the outside. Alive readiness
-- and no restart policy, so it is simply up for the whole file.
local function resident(name)
    return {
        path = [[Machine\System\Services\]] .. name,
        values = {
            { name = "ImagePath", type = "sz", data = "/bin/sleep" },
            { name = "Arguments", type = "multi", data = { "100000" } },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
            { name = "RestartPolicy", type = "dword", data = 0 },
            { name = "Triggers", type = "multi", data = { "boot" } },
        },
    }
end

--- The PID of the first process whose comm is `name`.
local function pid_of(vm, name)
    return vm:run(
        'for p in /proc/[0-9]*; do ' ..
        '[ "$(cat "$p/comm" 2>/dev/null)" = ' .. name .. ' ] && echo "${p#/proc/}"; ' ..
        'done'
    ).stdout:match("%d+")
end

--- A process's environment as a name -> value table.
local function environ(vm, pid)
    local set = {}
    for entry in vm:read_file("/proc/" .. pid .. "/environ"):gmatch("[^%z]+") do
        set[entry:match("^([^=]+)")] = entry:match("=(.*)$")
    end
    return set
end

test("the control socket carries the descriptor the chapter states, and only that",
    { spec = "peinit *control.the-socket-descriptor" },
    function(t)
        -- O:SYG:SYD:(A;;GA;;;SY)(A;;GA;;;BA). `sd show` renders a mask
        -- it has no letter for in hex, and GenericAll is 0x10000000.
        local sd = vm:run("sd show /run/services/peinit/control.sock")
        sd:assert_ok()
        local text = sd.stdout
        t:assert(text:find("Owner:%s+Local System"), "owned by SYSTEM: " .. text)
        t:assert(text:find("DACL: %(2 ACEs%)"),
            "exactly two ACEs, so nothing has been added: " .. text)
        t:assert(text:find("allow Local System %(S%-1%-5%-18%)%s+0x10000000"),
            "SYSTEM has GenericAll")
        t:assert(text:find("allow BUILTIN\\Administrators %(S%-1%-5%-32%-544%)%s+0x10000000"),
            "Administrators have GenericAll")

        -- The point of the two-ACE assertion above: nobody else may
        -- reach it. Administering the system is not for everyone, and
        -- the kernel enforces that at connect() rather than peinit.
        t:assert(not text:find("S%-1%-1%-0"), "no Everyone ACE: " .. text)
        t:assert(not text:find("S%-1%-5%-11"), "no Authenticated Users ACE: " .. text)
    end)

test("the jobs socket adds one ACE to the control socket's, and it is the write right",
    { spec = "peinit *jobs.the-socket-descriptor" },
    function(t)
        -- O:SYG:SYD:(A;;GA;;;SY)(A;;GA;;;BA)(A;;FW;;;AU). FW is what a
        -- connect() on a pathname socket needs, so this third ACE is
        -- the whole submission policy: being able to connect IS the
        -- permission to submit.
        local text = vm:run("sd show /run/services/peinit/jobs.sock").stdout
        t:assert(text:find("DACL: %(3 ACEs%)"), "three ACEs: " .. text)
        t:assert(text:find("allow Local System %(S%-1%-5%-18%)%s+0x10000000"), "SYSTEM full")
        t:assert(text:find("allow BUILTIN\\Administrators"), "Administrators full")
        t:assert(text:find("allow Authenticated Users %(S%-1%-5%-11%)%s+w"),
            "every authenticated principal may write, which is to say connect: " .. text)
    end)

test("the notification socket grants the Service group, and not Administrators",
    { spec = "peinit *notify.the-socket-descriptor" },
    function(t)
        -- O:SYG:SYD:(A;;GA;;;SY)(A;;FW;;;S-1-5-6). The absence of
        -- Administrators is the interesting half: an administrator has
        -- no business asserting that a service is ready.
        local text = vm:run("sd show /run/services/peinit/notify.sock").stdout
        t:assert(text:find("DACL: %(2 ACEs%)"), "two ACEs: " .. text)
        t:assert(text:find("allow Local System %(S%-1%-5%-18%)%s+0x10000000"), "SYSTEM full")
        t:assert(text:find("allow Service %(S%-1%-5%-6%)%s+w"),
            "the Service group may write: " .. text)
        t:assert(not text:find("S%-1%-5%-32%-544"),
            "and Administrators are absent, unlike the control socket: " .. text)
    end)

test("the directory the three sit in gives services traverse and nothing more",
    { spec = "peinit *notify.the-parent-directory-descriptor" },
    function(t)
        -- One constant serves both the notify socket's creation and the
        -- control socket's, because ensure_directory re-stamps a
        -- directory that already exists — so two different descriptors
        -- would silently leave whichever ran last. The traverse ACE is
        -- what a service needs to reach notify.sock at all.
        local text = vm:run("sd show /run/services/peinit").stdout
        t:assert(text:find("DACL: %(3 ACEs%)"), "three ACEs: " .. text)
        t:assert(text:find("allow Local System %(S%-1%-5%-18%)%s+0x10000000"), "SYSTEM full")
        t:assert(text:find("allow BUILTIN\\Administrators %(S%-1%-5%-32%-544%)%s+0x10000000"),
            "Administrators full")
        -- GenericExecute is 0x20000000, and on Peios execute is traverse.
        t:assert(text:find("allow Service %(S%-1%-5%-6%)%s+0x20000000"),
            "the Service group has traverse only, not write: " .. text)
    end)

test("no connection descriptor of peinit's reaches a service",
    { spec = "peinit *control.no-connection-descriptor-is-inherited" },
    function(t)
        -- The listener is created with SOCK_CLOEXEC and connections come
        -- from accept4 with the same flag, so nothing peinit accepts can
        -- survive into a service it later spawns. The evidence is a
        -- service's own descriptor table: peinit gives it standard input,
        -- output and error, and the claim is that it gives it nothing
        -- else by accident.
        local other = peinit.boot({
            name = "sock-fds",
            files = peinit.seed("pt-sockfd", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                resident("pt-resident"),
            }),
        })
        local pid = pid_of(other, "sleep")
        t:assert(pid, "the resident service is running")

        local listing = other:run("ls /proc/" .. pid .. "/fd").stdout
        local fds = {}
        for fd in listing:gmatch("%d+") do fds[#fds + 1] = fd end
        table.sort(fds)
        t:assert_eq(table.concat(fds, ","), "0,1,2",
            "the service holds exactly the three standard descriptors, got: " .. listing)
    end)

test("the jobs socket is sequenced-packet and the notification socket is a datagram",
    {
        spec = {
            "peinit *jobs.the-socket-is-sequenced-packet",
            "peinit *notify.there-is-one-datagram-socket-for-every-service",
        },
    },
    function(t)
        -- The socket type is not cosmetic on either. SOCK_SEQPACKET is
        -- what ties an attached token and descriptors to the one record
        -- they were sent with, so peinit never has to decide which
        -- request an attachment belongs to. And there is exactly one
        -- notification socket, not one per service.
        --
        -- /proc/net/unix column 5 is the socket type: 1 stream,
        -- 2 datagram, 5 seqpacket. The kernel prints it zero-padded to
        -- four hex digits, so it is read as a number rather than
        -- compared as a string.
        local types, notify_lines = {}, 0
        for line in vm:read_file("/proc/net/unix"):gmatch("[^\r\n]+") do
            local kind, path = line:match("%s(%x+)%s+%x+%s+%d+%s+(/%S+)$")
            if path then
                types[path] = tonumber(kind, 16)
                if path == "/run/services/peinit/notify.sock" then
                    notify_lines = notify_lines + 1
                end
            end
        end

        t:assert_eq(types["/run/services/peinit/jobs.sock"], 5,
            "jobs.sock is SOCK_SEQPACKET")
        t:assert_eq(types["/run/services/peinit/control.sock"], 1,
            "control.sock is a stream, as §10.1 says")
        t:assert_eq(types["/run/services/peinit/notify.sock"], 2,
            "notify.sock is a datagram")
        t:assert_eq(notify_lines, 1,
            "and there is one of it, bound once, rather than one per service")
    end)

test("every service is handed the notification path through NOTIFY_SOCKET",
    { spec = "peinit *notify.the-path-reaches-a-service-through-notify-socket" },
    function(t)
        -- The path is an implementation detail and nothing hardcodes it,
        -- which is only true if peinit really does put it in the
        -- environment of everything it starts.
        local other = peinit.boot({
            name = "notify-env",
            files = peinit.seed("pt-notifyenv", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                resident("pt-resident"),
            }),
        })
        local env = environ(other, pid_of(other, "sleep"))
        t:assert_eq(env.NOTIFY_SOCKET, "/run/services/peinit/notify.sock",
            "the service was told where to report, got: " .. tostring(env.NOTIFY_SOCKET))
    end)

test("the kernel command line moves the notification socket, and the services follow it",
    {
        spec = "peinit *notify.the-path-is-overridable-on-the-kernel-command-line",
        tags = { "known-bug" },
    },
    function(t)
        -- If services really do learn the path from the environment
        -- rather than from a constant, then moving it has to move them
        -- with it — and that is the whole reason the override is safe to
        -- offer at all.
        --
        -- It is not, today. peinit tells a service the overridden path
        -- and then binds the default one, so every service is pointed at
        -- a socket that does not exist and nothing with Notify readiness
        -- can report itself ready: the platform graph stalls with authd,
        -- netd and pnpd in Starting and everything below them Inactive.
        -- The assertions below state the manual, and the first of them
        -- is the one that fails.
        --
        -- The override deliberately stays inside /run/services/peinit,
        -- because a path anywhere else fails a second and earlier way.
        -- The notify bind is what creates that directory chain, so
        -- moving it leaves the control socket's own creation with no
        -- parent to work from, and PID 1 enters recovery with
        -- `stat parent of /run/services/peinit: No such file or directory`.
        local moved = "/run/services/peinit/pt-elsewhere.sock"
        local other = peinit.boot({
            name = "notify-moved",
            append = "peios.notifysocket=" .. moved,
            files = peinit.seed("pt-notifymove", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                resident("pt-resident"),
            }),
        })

        -- Nothing is bound where the service is told to write.
        local stat = other:run("stat -c %F " .. moved)
        t:assert(stat.exit_code == 0 and stat.stdout:find("socket"),
            "peinit bound the socket where the command line said: " ..
            tostring(stat.stderr))

        -- And the default path is no longer in use.
        t:assert(other:run("stat -c %F /run/services/peinit/notify.sock").exit_code ~= 0,
            "nothing was left bound at the default path")

        -- This half already works: the environment carries the override.
        local env = environ(other, pid_of(other, "sleep"))
        t:assert_eq(env.NOTIFY_SOCKET, moved,
            "and the service was told the same path, got: " .. tostring(env.NOTIFY_SOCKET))
    end)

test("the platform services report themselves ready, and peinit believes their main jobs",
    { spec = "peinit *notify.only-a-services-main-job-may-notify" },
    function(t)
        -- Authentication routes a datagram by scanning for the current
        -- *service-main* job whose PID matches the sender's. Only a main
        -- job is ever a candidate, which is what makes NotifyAccess=Main
        -- the only mode there is.
        --
        -- The accepted half of that rule is what a booted system shows.
        -- Every platform service here declares Notify readiness, so
        -- none of them can reach Active by running: peinit only moves
        -- them there on a READY=1 that passed all five steps, sent by
        -- the process it is holding as that service's main job.
        --
        -- The refused half — that a hook or a health check cannot notify
        -- on a service's behalf — needs a process that sends a datagram
        -- without being anyone's main job, and this image ships no tool
        -- that can write to a Unix datagram socket.
        local notify_readiness = {}
        for _, service in ipairs({ "authd", "netd", "lpsd", "pnpd", "installerd" }) do
            local value = vm:run(
                [[reg get 'Machine\System\Services\]] .. service .. [[' Readiness]])
            -- 0 is Notify, and it is also the default when the value is
            -- absent, so a failed read counts as Notify too.
            if value.exit_code ~= 0 or value.stdout:match("0") then
                notify_readiness[#notify_readiness + 1] = service
            end
        end
        t:assert(#notify_readiness >= 3,
            "the image has services that must notify to become ready, and it has " ..
            #notify_readiness)

        for _, service in ipairs(notify_readiness) do
            local status = vm:run("svctl --json status " .. service)
            status:assert_ok()
            t:assert_eq(status.stdout:match('"state":"([^"]+)"'), "active",
                service .. " reached Active, which for Notify readiness it can only " ..
                "do on an accepted READY=1: " .. status.stdout)

            -- And the job peinit holds for it is a service main job —
            -- the only kind a notification is ever matched against.
            t:assert(status.stdout:find('"type":"service_main"', 1, true),
                service .. " has a main job for peinit to have matched the sender " ..
                "against: " .. status.stdout)
        end
    end)

test("a timestamp on the wire is a wall clock, and one that agrees with the machine's",
    { spec = "peinit *control.timestamps-are-projected-from-the-monotonic-clock" },
    function(t)
        -- Elapsed-time decisions inside peinit stay monotonic; only the
        -- presentation is wall-clock, projected through the current
        -- offset between the two clocks at the moment of answering. What
        -- that is observable as: a timestamp peinit puts on the wire
        -- tracks the machine's own realtime clock rather than uptime.
        --
        -- Both readings are taken in the guest and compared there, to
        -- the minute: the host's clock and time zone are not part of the
        -- claim, and a job submitted between two `date` calls must carry
        -- a stamp from the same minute as one of them.
        local fmt = "date -u +%Y-%m-%dT%H:%M"
        local reading = vm:run(fmt .. "; svctl --json job submit /bin/true; " .. fmt)
        reading:assert_ok()
        local before, json, after =
            reading.stdout:match("^%s*(%S+)%s+({.*})%s+(%S+)%s*$")
        t:assert(json, "got a submit answer between two clock readings: " .. reading.stdout)

        local created = json:match('"created_at":"([^"]+)"')
        t:assert(created, "the job view carries a creation timestamp: " .. json)
        t:assert(created:match("^%d%d%d%d%-%d%d%-%d%dT%d%d:%d%d:%d%d[%.%d]*Z$"),
            "and it is RFC 3339 in UTC: " .. created)

        local minute = created:sub(1, #before)
        t:assert(minute == before or minute == after,
            "the wire timestamp is the machine's wall clock, not its uptime: "
            .. created .. " between " .. before .. " and " .. after)

        -- Within one job the presentation stays ordered, because the
        -- monotonic stamps behind it are.
        local started = json:match('"started_at":"([^"]+)"')
        t:assert(started and started >= created,
            "created_at does not follow started_at: " .. json)
    end)

test("a connection blocked on a slow operation outlives ConnectionTimeout",
    { spec = "peinit *control.a-connection-with-work-in-flight-is-never-idle" },
    function(t)
        -- A connection is idle only when it has nothing in flight. One
        -- blocked on a wait=true operation is never idle and is never
        -- closed by ConnectionTimeout, which defaults to 30 seconds — it
        -- stays open until the operation resolves, bounded by the
        -- operation's own timeout instead.
        --
        -- So: a service whose readiness never arrives, with a start
        -- timeout deliberately longer than ConnectionTimeout. svctl
        -- start waits by default. If the connection were treated as
        -- idle, svctl would lose the socket at 30 seconds; if it is not,
        -- it gets a real answer at 45.
        local other = peinit.boot({
            name = "slow-op",
            files = peinit.seed("pt-slowop", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                {
                    path = [[Machine\System\Services\pt-slow]],
                    values = {
                        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
                        { name = "Arguments", type = "multi", data = { "300" } },
                        { name = "Identity", type = "sz", data = "SYSTEM" },
                        -- Notify readiness, and /bin/sleep never notifies.
                        { name = "Readiness", type = "dword", data = 0 },
                        { name = "StartTimeout", type = "dword", data = 45 },
                        { name = "RestartPolicy", type = "dword", data = 0 },
                    },
                },
            }),
        })

        local started = os.time()
        local result = other:run("svctl --json start pt-slow", { timeout = 120 })
        local elapsed = os.time() - started

        -- The claim is about the connection, so the assertion is about
        -- the connection: peinit answered, on the socket svctl opened
        -- before the timeout would have closed it.
        t:assert(not (result.stderr or ""):find("connect ", 1, true),
            "the connection was still there to answer on: " .. tostring(result.stderr))
        t:assert(not (result.stderr or ""):find("closed before a complete response", 1, true),
            "and peinit did not drop it mid-operation: " .. tostring(result.stderr))
        t:assert(result.stdout:find("{", 1, true) or (result.stderr or ""):find(":", 1, true),
            "a protocol response came back: " .. result.stdout .. " / " .. tostring(result.stderr))
        t:assert(elapsed > 30,
            "and it was held past the 30-second ConnectionTimeout (" .. elapsed .. "s)")
    end)
