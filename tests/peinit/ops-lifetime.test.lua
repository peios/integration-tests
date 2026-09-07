-- peinit TRM §8.5 — a submitted job's lifetime: its deadlines, the two
-- ways it can be made to stop, and what its end records.
--
-- The submission half of §8.5 is in `ops-submitted.test.lua`.
--
-- Everything here is driven with `svctl job submit` and its per-job
-- options, because that is the only surface through which a test can
-- give one job a two-second timeout and the next a stop timeout of its
-- own. Each submission is its own connection — peinit closes a jobs
-- connection idle for 30 seconds — so a job outliving the command that
-- created it is normal rather than something to work around.
--
-- Two shell shapes recur. `trap "" TERM` makes a job that a stop cannot
-- talk out of, so the kill deadline is what ends it; `trap "exit 0"
-- TERM` makes one that agrees to go, which is the case where a stop
-- ends in `completed` rather than `failed`. The guest's shell runs traps
-- between commands, so the loop body is a one-second sleep and the
-- handler fires within about a second of the signal.

local peinit = require("helpers.peinit")
-- Two: the file's own VM, plus the one the shutdown test boots and
-- takes down with it.
peinit.claim(2)

local vm = peinit.boot({ name = "opslife" })

local function submit(arguments)
    local r = vm:run("svctl --json job submit " .. arguments, { timeout = 120 })
    r:assert_ok()
    local id = r.stdout:match('"id":"([^"]+)"')
    assert(id, "no job identifier in: " .. r.stdout)
    return id, r.stdout
end

local function status(id)
    local r = vm:run("svctl --json job status " .. id)
    return {
        raw = r.stdout,
        code = r.stdout:match('"code":"([^"]+)"'),
        state = r.stdout:match('"state":"([^"]+)"'),
        cause = r.stdout:match('"cause":"([^"]+)"'),
        exit_code = r.stdout:match('"exit_code":(%d+)'),
        exit_signal = r.stdout:match('"exit_signal":(%d+)'),
        null_cause = r.stdout:find('"cause":null', 1, true) ~= nil,
    }
end

--- Poll a job until it is terminal, or give up and return what it says.
local function settle(id, seconds)
    for _ = 1, seconds or 40 do
        local view = status(id)
        if view.state ~= "running" and view.state ~= "created" then return view end
        vm:run("sleep 1")
    end
    return status(id)
end

-- A job that refuses SIGTERM, and one that accepts it and exits 0.
local IGNORES_TERM = [[/bin/sh -c 'trap "" TERM; while :; do sleep 1; done']]
local HANDLES_TERM = [[/bin/sh -c 'trap "exit 0" TERM; while :; do sleep 1; done']]

test("a job's own timeout stops it, with the timeout recorded as the cause",
    { spec = "peinit *submit.the-submitted-job-deadlines" },
    function(t)
        -- The `Timeout` row: due at `started_at + timeout`, and what
        -- happens then is a stop rather than a kill, so the cause on the
        -- ended job says the deadline rather than saying somebody asked.
        -- Two seconds against a job that would run for two minutes.
        local id = submit("--timeout 2 /bin/sleep 120")
        local view = settle(id, 30)

        t:assert(view.state == "failed" or view.state == "completed",
            "the job ended at its timeout: " .. view.raw)
        t:assert_eq(view.cause, "timeout",
            "and the timeout is what peinit recorded: " .. view.raw)
        t:assert(view.raw:find('"ended_at":"', 1, true),
            "with the moment it ended: " .. view.raw)
    end)

test("a notify job that never becomes ready is stopped at its readiness timeout",
    { spec = "peinit *submit.the-submitted-job-deadlines" },
    function(t)
        -- The `ReadinessTimeout` row, which applies only to a job that
        -- declared `readiness: notify` and has not yet said `READY=1`.
        -- /bin/sleep never will, so the deadline is what ends it — and
        -- the job's view carries `ready: false` while it waits, which is
        -- what makes it a job the row applies to.
        local id, view = submit("--readiness notify --readiness-timeout 2 /bin/sleep 120")
        t:assert(view:find('"ready":false', 1, true),
            "the job is one with a readiness protocol, not yet ready: " .. view)

        local ended = settle(id, 30)
        t:assert_eq(ended.cause, "readiness_timeout",
            "the readiness deadline ended it: " .. ended.raw)

        -- A job with no readiness protocol has `ready: null` and no such
        -- deadline, which is what confines the row to notify jobs.
        local plain_id, plain = submit("/bin/sleep 3")
        t:assert(plain:find('"ready":null', 1, true),
            "a job with no readiness protocol reports none: " .. plain)
        local plain_end = settle(plain_id, 30)
        t:assert(plain_end.null_cause,
            "and ends of its own accord rather than at a readiness deadline: "
            .. plain_end.raw)
        t:assert_eq(plain_end.state, "completed",
            "having simply finished: " .. plain_end.raw)
    end)

test("a stop signals the job, and kills its cgroup at the stop timeout",
    {
        spec = {
            "peinit *submit.a-stop-sigterms-the-main-process-and-arms-the-kill-deadline",
            "peinit *submit.at-the-kill-deadline-the-cgroup-is-killed",
            "peinit *submit.a-stopped-job-killed-by-the-signal-fails-with-the-same-cause",
        },
    },
    function(t)
        -- A stop is a request first and force second. This job ignores
        -- the request, so what ends it is the kill at its two-second
        -- stop timeout — and the record says both halves: SIGKILL as the
        -- signal that ended it, and `explicit_stop` as the reason peinit
        -- was applying force at all.
        local id = submit("--stop-timeout 2 " .. IGNORES_TERM)
        t:assert_eq(status(id).state, "running", "the job is up")

        local stopped = vm:run("svctl --json job stop " .. id, { timeout = 90 })
        stopped:assert_ok()

        local view = settle(id, 30)
        t:assert_eq(view.state, "failed",
            "a job that had to be killed failed: " .. view.raw)
        t:assert_eq(view.exit_signal, "9",
            "killed rather than asked, because it would not go: " .. view.raw)
        t:assert_eq(view.cause, "explicit_stop",
            "with the stop still recorded as the reason: " .. view.raw)
    end)

test("a stop the process agrees to completes the job, with the stop as its cause",
    {
        spec = {
            "peinit *submit.a-stop-the-process-handled-completes-with-cause-explicit-stop",
            "peinit *submit.cause-is-null-when-the-process-ended-of-its-own-accord",
        },
    },
    function(t)
        -- Two facts, both recorded: peinit asked, and the process
        -- agreed. So the state is `completed` — the process exited
        -- successfully — and the cause is `explicit_stop`, because it
        -- would not have exited then if nobody had asked. A job nobody
        -- asked anything of has a null cause, which is what makes the
        -- cause above information rather than decoration.
        local id = submit("--stop-timeout 20 " .. HANDLES_TERM)
        t:assert_eq(status(id).state, "running", "the job is up")

        vm:run("svctl --json job stop " .. id, { timeout = 90 }):assert_ok()
        local view = settle(id, 30)
        t:assert_eq(view.state, "completed",
            "the process handled the signal and exited 0: " .. view.raw)
        t:assert_eq(view.exit_code, "0", "with an exit code, not a signal: " .. view.raw)
        t:assert_eq(view.cause, "explicit_stop",
            "and peinit's asking is recorded too: " .. view.raw)

        local undisturbed = submit("/bin/true")
        local ended = settle(undisturbed, 30)
        t:assert_eq(ended.state, "completed", "an undisturbed job completes: " .. ended.raw)
        t:assert(ended.null_cause,
            "with no cause, because peinit decided nothing: " .. ended.raw)
    end)

test("a second stop changes nothing, and a stop on a job that has ended is a no-op",
    { spec = "peinit *submit.a-second-stop-changes-nothing-and-a-stop-on-a-terminal-job-is-a-no-op" },
    function(t)
        -- Stopping is idempotent in both directions. A stop against a
        -- job already stopping does not restart the kill deadline — so a
        -- job with a long stop timeout, stopped twice in quick
        -- succession, is still alive after a second stop that would have
        -- re-armed anything. And a stop against a job that is already
        -- over is answered with the view it already had.
        local id = submit("--stop-timeout 30 " .. IGNORES_TERM)
        vm:run("svctl --no-wait --json job stop " .. id):assert_ok()
        local first = status(id)
        t:assert_eq(first.state, "running",
            "the first stop is under way and the job has not died yet: " .. first.raw)

        vm:run("svctl --no-wait --json job stop " .. id):assert_ok()
        local second = status(id)
        t:assert_eq(second.state, "running",
            "the second stop changed nothing: " .. second.raw)
        t:assert(second.null_cause == first.null_cause,
            "and did not re-record the cause")

        -- A terminal job: the answer is the unchanged view, not an
        -- error and not a second attempt at anything.
        local done = submit("/bin/true")
        local ended = settle(done, 30)
        local restopped = vm:run("svctl --json job stop " .. done, { timeout = 60 })
        restopped:assert_ok()
        t:assert_eq(restopped.stdout:match('"state":"([^"]+)"'), ended.state,
            "a stop on an ended job answers with the state it already had: "
            .. restopped.stdout)
        t:assert(not restopped.stdout:find('"code"', 1, true),
            "and is not an error: " .. restopped.stdout)

        vm:run("svctl --json job signal " .. id .. " KILL")
    end)

test("signal is the raw mechanism, on a running job only",
    {
        spec = {
            "peinit *submit.signal-acts-on-a-running-job-only",
            "peinit *submit.a-signalled-kill-produces-a-failed-job-with-a-null-cause",
        },
    },
    function(t)
        -- `signal` sends one signal and nothing else: no cause is
        -- recorded, because peinit did not decide anything about the
        -- job's end — a caller did, and the signal is the whole record
        -- of it. That is exactly what distinguishes it from `stop`,
        -- which is why a submitter that wants the job *ended* uses stop.
        local id = submit("/bin/sleep 120")
        vm:run("svctl --json job signal " .. id .. " KILL"):assert_ok()

        local view = settle(id, 30)
        t:assert_eq(view.state, "failed", "the killed job failed: " .. view.raw)
        t:assert_eq(view.exit_signal, "9", "carrying the signal that ended it: " .. view.raw)
        t:assert(view.null_cause,
            "and no cause, because peinit decided nothing: " .. view.raw)

        -- The same command against the job now that it is over is
        -- refused for the state rather than silently doing nothing.
        local again = vm:run("svctl --json job signal " .. id .. " TERM")
        t:assert_eq(again.stdout:match('"code":"([^"]+)"'), "INVALID_STATE",
            "signalling a job that is not running is invalid: " .. again.stdout)
    end)

test("success is exit zero, or one of the codes the submission called successful",
    { spec = "peinit *submit.success-is-exit-zero-or-a-code-in-success-exit-codes" },
    function(t)
        -- Zero always completes a job. Anything else fails it unless the
        -- submission said otherwise — and the same code, submitted with
        -- and without `--success-exit-code`, lands on opposite sides of
        -- that line, which is what makes it the definition rather than a
        -- property of the code.
        local zero = settle(submit("/bin/true"), 30)
        t:assert_eq(zero.state, "completed", "exit 0 completes: " .. zero.raw)

        local three = settle(submit([[/bin/sh -c 'exit 3']]), 30)
        t:assert_eq(three.state, "failed", "exit 3 fails: " .. three.raw)
        t:assert_eq(three.exit_code, "3", "with the code recorded: " .. three.raw)

        local allowed = settle(submit([[--success-exit-code 3 /bin/sh -c 'exit 3']]), 30)
        t:assert_eq(allowed.state, "completed",
            "the same code completes when the submission called it a success: "
            .. allowed.raw)
        t:assert_eq(allowed.exit_code, "3",
            "and the code is still what it was: " .. allowed.raw)

        -- A signal is not an exit code and cannot be declared a success.
        local killed = submit("/bin/sleep 120")
        vm:run("svctl --json job signal " .. killed .. " KILL"):assert_ok()
        t:assert_eq(settle(killed, 30).state, "failed",
            "a signalled job fails whatever the submission said")
    end)

test("every live job is stopped when a shutdown begins, with shutdown as its cause",
    { spec = "peinit *submit.every-live-job-is-stopped-with-cause-shutdown" },
    function(t)
        -- A job has no dependencies, so there is no wave to place it in:
        -- when a shutdown starts, every live job is stopped at once.
        --
        -- The observation is made without racing the shutdown at all. A
        -- `wait` is registered on the job *before* the shutdown is
        -- asked for, so the connection carrying it already exists when
        -- the sockets start going away; it is answered by the flush that
        -- runs when the job's state moves, and what it carries is the
        -- terminal view with the cause peinit recorded. A SIGTERM-proof
        -- service holds the shutdown open long enough for the answer to
        -- be read back out.
        local other = peinit.boot({
            name = "opslife-down",
            files = peinit.seed("pt-lifedown", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                { path = [[Machine\System\Services\pt-holds-open]], values = {
                    { name = "ImagePath", type = "sz", data = "/bin/sh" },
                    { name = "Arguments", type = "multi",
                      data = { "-c", "trap '' TERM; while :; do sleep 1; done" } },
                    { name = "Identity", type = "sz", data = "SYSTEM" },
                    { name = "Readiness", type = "dword", data = 1 },
                    { name = "StopTimeout", type = "dword", data = 40 },
                    { name = "RestartPolicy", type = "dword", data = 0 },
                    { name = "Triggers", type = "multi", data = { "boot" } },
                } },
            }),
        })

        local created = other:run("svctl --json job submit /bin/sleep 300", { timeout = 60 })
        created:assert_ok()
        local id = created.stdout:match('"id":"([^"]+)"')
        t:assert(id, "a job is running when the shutdown starts: " .. created.stdout)

        other:run("mkdir -p /pt")
        local probe = other:run(
            "svctl --json job wait " .. id .. " > /pt/waited 2>&1 & " ..
            "sleep 2; " ..
            "svctl shutdown poweroff >/dev/null 2>&1; " ..
            "sleep 5; " ..
            "echo \"SAW:$(cat /pt/waited)\"",
            { timeout = 120 })

        local saw = probe.stdout:match("SAW:([^\r\n]*)")
        t:assert(saw and #saw > 0,
            "the wait registered before the shutdown was answered: " .. probe.stdout)
        t:assert_eq(saw:match('"cause":"([^"]+)"'), "shutdown",
            "and the shutdown is what peinit recorded as the job's cause: " .. saw)
        t:assert(saw:find('"ended_at":"', 1, true),
            "with the job over rather than merely asked to stop: " .. saw)
    end)
