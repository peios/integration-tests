-- Peinit TRM §10.7 — the jobs socket: the second door, on which a job
-- is submitted and managed, and §10.6's one externally visible corner,
-- the fd store's effect on a service's environment.
--
-- svctl is the client throughout, and one property of it is load-bearing
-- here: it opens a connection per operation and closes it afterwards.
-- That makes it the right instrument for the claims about a connection
-- carrying an identity and nothing else, and the wrong one for the
-- claims about holding a connection open — the connection limits and the
-- idle timeout need a client that keeps one, which this suite has not
-- got.

local peinit = require("helpers.peinit")

local vm = peinit.boot({ name = "jobs" })

--- Submit a job and return its identifier.
local function submit(vm, arguments)
    local r = vm:run("svctl --json job submit " .. arguments)
    r:assert_ok()
    local id = r.stdout:match('"id":"([^"]+)"')
    assert(id, "no job identifier in: " .. r.stdout)
    return id, r.stdout
end

test("a job outlives the connection it was submitted on",
    { spec = "peinit *jobs.closing-a-connection-does-not-affect-its-jobs" },
    function(t)
        -- A connection carries an identity and nothing else. A job
        -- belongs to its submitter's identity, so closing the connection
        -- it arrived on does not touch it, and a submitter that
        -- reconnects finds its jobs where it left them.
        --
        -- svctl gives that for free: each of the three commands below is
        -- a separate connection, opened and closed. If a job were tied
        -- to its connection, the second would find nothing.
        local id = submit(vm, "/bin/sleep 60")

        local status = vm:run("svctl --json job status " .. id)
        status:assert_ok()
        t:assert_eq(status.stdout:match('"state":"([^"]+)"'), "running",
            "the job is still running on a connection it never saw: " .. status.stdout)

        local listed = vm:run("svctl --json job list")
        listed:assert_ok()
        t:assert(listed.stdout:find(id, 1, true),
            "and a third connection still lists it: " .. listed.stdout)

        vm:run("svctl --json job stop " .. id):assert_ok()
    end)

test("the identity a job runs under is the one captured from the connection's peer",
    { spec = "peinit *jobs.the-peer-token-and-pidfd-are-captured-on-accept" },
    function(t)
        -- peinit captures the peer's identity once, on accept, and a
        -- submit with no token attached opens the job identity through
        -- the peer's own process handle. The observable consequence is
        -- that the job's submitter and identity are the SID of whoever
        -- was on the other end of the socket — not a default, and not
        -- peinit's own choice.
        local caller = vm:run("token user")
        caller:assert_ok()
        local sid = caller.stdout:match("S%-[%d%-]+")
        t:assert(sid, "the caller has a SID: " .. caller.stdout)

        local _, view = submit(vm, "/bin/true")
        t:assert_eq(view:match('"submitter":"([^"]+)"'), sid,
            "the job records the connecting peer as its submitter: " .. view)
        t:assert_eq(view:match('"identity":"([^"]+)"'), sid,
            "and runs as that identity, opened through the peer handle: " .. view)
    end)

test("a response on the jobs socket is one compact JSON object",
    { spec = "peinit *jobs.a-response-is-one-compact-json-object" },
    function(t)
        -- `svctl --json` prints the response bytes as peinit sent them,
        -- so this is the wire form rather than a re-encoding of it. One
        -- object, no terminator, and no whitespace between members: a
        -- reader on a sequenced-packet socket gets the whole record or
        -- nothing, so there is nothing for a separator to do.
        local r = vm:run("svctl --json job submit /bin/true")
        r:assert_ok()
        local body = r.stdout:gsub("\r?\n$", "")

        t:assert(not body:find("\n"), "the response is one line: " .. body)
        t:assert(body:sub(1, 1) == "{" and body:sub(-1) == "}",
            "and one JSON object with nothing around it: " .. body)
        t:assert(not body:find('", "', 1, true),
            "members are not separated by whitespace: " .. body)
        t:assert(not body:find('": "', 1, true),
            "nor are names from values: " .. body)
    end)

-- The Submit wait of §10.7's table — set by `submit`, answered when the
-- job leaves `created` — has no test here. svctl never sets the
-- protocol's `wait` on a submit: `svctl job submit --wait` submits
-- without it and then issues a separate `wait` on the same connection,
-- so what that exercises is the Wait row below, not the Submit row.

test("a wait is answered when the job reaches the condition it named",
    { spec = "peinit *jobs.the-wait-wait" },
    function(t)
        -- `wait` is answered when its condition holds. For a job with no
        -- readiness of its own that is the terminal condition, and the
        -- answer is the job view at that moment — so the state it
        -- carries is the terminal one, not the state at the time of
        -- asking.
        local id = submit(vm, "/bin/sleep 3")

        local waited = vm:run("svctl --json job wait " .. id, { timeout = 60 })
        waited:assert_ok()
        t:assert_eq(waited.stdout:match('"state":"([^"]+)"'), "completed",
            "the wait returned the terminal view: " .. waited.stdout)
        t:assert(waited.stdout:find('"ended_at":"', 1, true),
            "with the end recorded: " .. waited.stdout)
    end)

test("a stop with wait is answered when the job is terminal, not when the stop is sent",
    {
        spec = {
            "peinit *jobs.the-stop-wait",
            "peinit *jobs.waits-are-flushed-when-a-jobs-state-moves",
        },
    },
    function(t)
        -- `svctl job stop` waits by default. The wait is registered on
        -- the connection and answered by the flush that runs when the
        -- job's state moves — so what comes back is the job after it
        -- died, rather than an acknowledgement that a signal was sent.
        local id = submit(vm, "/bin/sleep 300")

        local stopped = vm:run("svctl --json job stop " .. id, { timeout = 90 })
        stopped:assert_ok()
        local state = stopped.stdout:match('"state":"([^"]+)"')
        t:assert(state ~= "running",
            "the answer is not the still-running job: " .. stopped.stdout)
        t:assert(stopped.stdout:find('"ended_at":"', 1, true),
            "it is the terminal view, carrying the moment it ended: " .. stopped.stdout)

        -- And the flush answered with the real outcome rather than a
        -- placeholder: a job killed by a signal says which one.
        t:assert(stopped.stdout:find('"exit_signal":%d')
            or stopped.stdout:find('"exit_code":%d'),
            "with how it ended: " .. stopped.stdout)
    end)

test("a connection with a wait outstanding is not closed by JobsConnectionTimeout",
    { spec = "peinit *jobs.a-connection-with-a-pending-wait-is-never-idle" },
    function(t)
        -- JobsConnectionTimeout is 30 seconds and peinit closes an idle
        -- connection when it expires. A connection with a pending wait
        -- is not idle: a wait has no timeout of its own and is bounded
        -- by the job, so a submitter waiting on a job that outlives the
        -- timeout keeps its connection.
        --
        -- 40 seconds of sleep, comfortably past the 30-second deadline.
        local id = submit(vm, "/bin/sleep 40")

        local started = os.time()
        local waited = vm:run("svctl --json job wait " .. id, { timeout = 120 })
        local elapsed = os.time() - started

        t:assert(not (waited.stderr or ""):find("connect ", 1, true),
            "the connection was not dropped: " .. tostring(waited.stderr))
        t:assert(not (waited.stderr or ""):find("reset by peer", 1, true),
            "nor reset out from under the wait: " .. tostring(waited.stderr))
        waited:assert_ok()
        t:assert_eq(waited.stdout:match('"state":"([^"]+)"'), "completed",
            "and it was answered with the job's terminal view: " .. waited.stdout)
        t:assert(elapsed > 30,
            "after being held past the 30-second idle deadline (" .. elapsed .. "s)")
    end)

test("during shutdown the jobs socket stays open and refuses only submit",
    { spec = "peinit *jobs.submit-is-refused-during-shutdown" },
    function(t)
        -- The jobs socket is not closed when a shutdown starts. `submit`
        -- is refused with INVALID_STATE — there is no point starting
        -- work the shutdown is about to stop — while status, wait, stop
        -- and signal keep answering, because a submitter watching its
        -- job die has a reason to ask.
        local other = peinit.boot({
            name = "jobs-shutdown",
            files = peinit.seed("pt-jobsdown", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                {
                    path = [[Machine\System\Services\pt-stubborn]],
                    values = {
                        { name = "ImagePath", type = "sz", data = "/bin/sh" },
                        { name = "Arguments", type = "multi",
                          data = { "-c", "trap '' TERM; while :; do sleep 1; done" } },
                        { name = "Identity", type = "sz", data = "SYSTEM" },
                        { name = "Readiness", type = "dword", data = 1 },
                        { name = "StopTimeout", type = "dword", data = 30 },
                        { name = "RestartPolicy", type = "dword", data = 0 },
                        { name = "Triggers", type = "multi", data = { "boot" } },
                    },
                },
            }),
        })

        t:assert(other:run("svctl --json status pt-stubborn").stdout
                :find('"state":"active"', 1, true),
            "the service that will hold the shutdown open is running")

        -- A job to ask about once the shutdown is under way, submitted
        -- while submitting is still allowed.
        local id = submit(other, "/bin/sleep 300")

        -- The refusal is retried for, because the window opens some
        -- milliseconds after `shutdown` is acknowledged. `status` is
        -- then asked on the same socket, and asserted not to have been
        -- refused rather than to have been answered: the socket does go
        -- away eventually, and a request that arrives after it has is
        -- not the rule failing.
        local probe = other:run(
            "svctl shutdown poweroff >/dev/null 2>&1 & " ..
            "i=0; while [ $i -lt 5000 ]; do " ..
            "  out=$(svctl --json job submit /bin/true 2>&1); " ..
            "  case \"$out\" in " ..
            "    *INVALID_STATE*) " ..
            "      echo \"REFUSED:$out\"; " ..
            "      echo \"STATUS:$(svctl --json job status " .. id .. " 2>&1)\"; " ..
            "      break;; " ..
            "    *'No such file'*) echo MISSED; break;; " ..
            "  esac; i=$((i+1)); done; echo END",
            { timeout = 120 })

        t:assert(not probe.stdout:find("MISSED", 1, true),
            "the shutdown window was caught while the socket was still there: "
            .. probe.stdout)
        t:assert(probe.stdout:find("REFUSED:", 1, true),
            "a submit during shutdown was refused: " .. probe.stdout)
        t:assert(probe.stdout:find('REFUSED:.*"code":"INVALID_STATE"'),
            "as invalid for the state: " .. probe.stdout)

        local status = probe.stdout:match("STATUS:([^\r\n]*)")
        t:assert(status, "`status` was tried on the same socket: " .. probe.stdout)
        t:assert(not status:find("INVALID_STATE", 1, true),
            "and was not refused with it, because only submit is: " .. status)
    end)

test("a service with no fd store is given none of the descriptor-passing variables",
    {
        spec = {
            "peinit *fdstore.fdstoremax-defaults-to-zero-and-zero-disables-the-store",
            "peinit *fdstore.the-listen-variables-are-omitted-when-the-store-is-empty",
        },
    },
    function(t)
        -- FdStoreMax defaults to 0, which disables the store, so a
        -- definition that does not ask for one has nothing stored for
        -- it. LISTEN_FDS, LISTEN_FDNAMES and LISTEN_PID are then omitted
        -- entirely rather than set to zero or to an empty string — which
        -- matters, because a conforming client tests for their presence.
        local other = peinit.boot({
            name = "fdstore-empty",
            files = peinit.seed("pt-fdstore", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                {
                    path = [[Machine\System\Services\pt-nostore]],
                    values = {
                        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
                        { name = "Arguments", type = "multi", data = { "100000" } },
                        { name = "Identity", type = "sz", data = "SYSTEM" },
                        { name = "Readiness", type = "dword", data = 1 },
                        { name = "RestartPolicy", type = "dword", data = 0 },
                        { name = "Triggers", type = "multi", data = { "boot" } },
                    },
                },
            }),
        })

        local pid = other:run(
            'for p in /proc/[0-9]*; do ' ..
            '[ "$(cat "$p/comm" 2>/dev/null)" = sleep ] && echo "${p#/proc/}"; ' ..
            'done'
        ).stdout:match("%d+")
        t:assert(pid, "the service is running")

        local names = {}
        for entry in other:read_file("/proc/" .. pid .. "/environ"):gmatch("[^%z]+") do
            names[entry:match("^([^=]+)")] = true
        end
        for _, variable in ipairs({ "LISTEN_FDS", "LISTEN_FDNAMES", "LISTEN_PID" }) do
            t:assert(not names[variable],
                variable .. " is absent from a service with no stored descriptors")
        end

        -- The environment is not simply empty, so the absences above are
        -- about the store rather than about nothing being set at all.
        t:assert(names.NOTIFY_SOCKET,
            "while the variables peinit does set are there")
    end)
