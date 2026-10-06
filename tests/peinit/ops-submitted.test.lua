-- peinit TRM §8.5 — the submitted job: the two doors, the two
-- identities, and what `submit` does before a job exists.
--
-- The lifetime half of §8.5 — deadlines, stopping, ending, shutdown — is
-- in `ops-lifetime.test.lua`; this file is submission.
--
-- Two things are worth knowing before reading the seeds.
--
-- The console is SYSTEM, and SYSTEM is exempt from the per-submitter
-- quota, so a quota test cannot be driven from it. The route to a second
-- principal is the one the suite has: a registry-defined oneshot service
-- with `Identity = LocalService`, whose script submits and writes what
-- it was told into a runtime directory the console then reads. That is
-- also what makes the "connecting is the permission" claim testable at
-- all — LocalService is admitted by the jobs socket's own descriptor
-- and by nothing peinit decides.
--
-- And `MaxJobsPerSubmitter` is seeded down to 2. The shipped default is
-- 64, which a shell loop could reach but not cheaply, and the claim is
-- about the bound rather than about its value.
--
-- The last two tests speak the jobs socket from a provium worker
-- (helpers/peinit_client.lua) rather than through svctl: one attaches tokens
-- svctl never would, and the other sends a record larger than any
-- command line can carry.

local peinit = require("helpers.peinit")
local token = require("helpers.token")
local us = require("helpers.unixsock")
local f = require("helpers.peinit_client")
local revstrm = require("helpers.revstrm")
-- One VM for the file: the quota probe runs once at boot and the rest
-- is submissions, which need no boot of their own.
peinit.claim(1)

-- The quota probe, run as LocalService.
--
-- Two live jobs fill a limit of 2 and the third is refused. One of the
-- two is then killed, which makes it terminal without forgetting it —
-- its entry is retained for another minute — and a fourth submission
-- succeeds into the slot that freed, which is the difference between
-- "terminal" and "purged". A fifth is refused again, so the fourth's
-- success was a freed slot rather than the bound having gone away.
--
-- `signal` rather than `stop` because `job stop` is a control-socket
-- command and this probe is deliberately not an administrator; the
-- identifier is pulled out of the submit's answer with POSIX parameter
-- expansion, the guest's shell having no grep or sed.
local QUOTA_PROBE = [[
mkdir -p /run/pt-quota
: > /run/pt-quota/out
first=$(svctl --json job submit /bin/sleep 120 2>&1)
echo "live1 $first" >> /run/pt-quota/out
echo "live2 $(svctl --json job submit /bin/sleep 120 2>&1)" >> /run/pt-quota/out
echo "over $(svctl --json job submit /bin/sleep 120 2>&1)" >> /run/pt-quota/out
rest=${first#*\"id\":\"}
id=${rest%%\"*}
echo "killed $(svctl --json job signal $id KILL 2>&1)" >> /run/pt-quota/out
sleep 2
echo "refill $(svctl --json job submit /bin/sleep 120 2>&1)" >> /run/pt-quota/out
echo "again $(svctl --json job submit /bin/sleep 120 2>&1)" >> /run/pt-quota/out
]]

local function definitions()
    return {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Init]], values = {
            { name = "MaxJobsPerSubmitter", type = "dword", data = 2 },
            -- Room for a definition past the 2 MiB argument bound, which
            -- the default 64 KiB record limit would refuse as
            -- REQUEST_TOO_LARGE before the definition was ever read.
            { name = "MaxJobMessageSize", type = "dword", data = 4194304 },
        } },
        { path = [[Machine\System\Services]] },
        { path = [[Machine\System\Services\pt-quota]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/sh" },
            { name = "Arguments", type = "multi", data = { "-c", QUOTA_PROBE } },
            { name = "Type", type = "dword", data = 1 },
            { name = "Identity", type = "sz", data = "LocalService" },
            { name = "RemainAfterExit", type = "dword", data = 1 },
            { name = "RuntimeDirectories", type = "multi", data = { "pt-quota" } },
            { name = "RestartPolicy", type = "dword", data = 0 },
            { name = "Triggers", type = "multi", data = { "boot" } },
        } },
    }
end

-- pt-notify is the job image for the notification tests at the end of
-- the file: a submitted job speaks the notification socket like a
-- service, and nothing in the image can be a job's main process and
-- write a datagram with credentials.
--
-- The seed also switches every `peinit.*` event on in the emission
-- policy: `peinit.job.created` and `peinit.job.status.reported`, which
-- tests below count, are verbose and off by default.
local function seed_keys()
    local keys = definitions()
    for _, key in ipairs(peinit.verbose_events_keys()) do keys[#keys + 1] = key end
    return keys
end

local vm = peinit.boot({
    name = "opssub",
    files = peinit.merge(peinit.tool("pt-notify"), peinit.seed("pt-sub", seed_keys())),
})

--- Submit a job and return its identifier and the view the submit
--- answered with. Every `svctl job submit` is its own connection: peinit
--- closes a jobs connection idle for 30 seconds, so a test that held one
--- open across its own waits would be racing the timeout.
local function submit(arguments)
    local r = vm:run("svctl --json job submit " .. arguments, { timeout = 120 })
    r:assert_ok()
    local id = r.stdout:match('"id":"([^"]+)"')
    assert(id, "no job identifier in: " .. r.stdout)
    return id, r.stdout
end

--- The raw answer to a submission, for the cases where it is a refusal.
local function try_submit(arguments)
    local r = vm:run("svctl --json job submit " .. arguments, { timeout = 120 })
    return {
        raw = r.stdout .. " / " .. tostring(r.stderr),
        code = r.stdout:match('"code":"([^"]+)"'),
        message = r.stdout:match('"message":"([^"]*)"'),
        id = r.stdout:match('"id":"([^"]+)"'),
    }
end

local function status(id)
    local r = vm:run("svctl --json job status " .. id)
    return { raw = r.stdout, code = r.stdout:match('"code":"([^"]+)"'),
             state = r.stdout:match('"state":"([^"]+)"'),
             cause = r.stdout:match('"cause":"([^"]+)"') }
end

--- Every event of the given types in the ring, oldest first (see
--- helpers/revstrm).
local function events(globs)
    return revstrm.snapshot(vm, globs)
end

--- Whether `event` is about the job `id`, by its `object.job.guid`.
local function about_job(event, id)
    return revstrm.guid(revstrm.field(event, "object.job.guid")) == id:lower()
end

local SYSTEM_SID = "S-1-5-18"
local LOCAL_SERVICE_SID = "S-1-5-19"

--- The quota probe's output, one entry per labelled submission.
local function quota_results(t)
    for _ = 1, 40 do
        local state = vm:run("svctl --json status pt-quota").stdout:match('"state":"([^"]+)"')
        if state == "completed" or state == "failed" then break end
        vm:run("sleep 1")
    end
    local text = vm:read_file("/run/pt-quota/out")
    t:assert(text and #text > 0, "the LocalService probe wrote its results")
    local out = {}
    for line in tostring(text):gmatch("[^\r\n]+") do
        local label, body = line:match("^(%w+) (.*)$")
        if label then
            out[label] = {
                raw = body,
                code = body:match('"code":"([^"]+)"'),
                id = body:match('"id":"([^"]+)"'),
                submitter = body:match('"submitter":"([^"]+)"'),
                identity = body:match('"identity":"([^"]+)"'),
            }
        end
    end
    return out
end

test("being admitted by the jobs socket is the whole permission to submit",
    {
        spec = {
            "peinit *submit.connecting-to-the-jobs-socket-is-the-permission-to-submit",
            "peinit *submit.with-no-token-attached-the-job-runs-as-the-peers-primary-token",
        },
    },
    function(t)
        -- A LocalService oneshot connects to the jobs socket and
        -- submits. peinit runs no access check of its own before a
        -- submit, so the only thing that admitted it was the socket's
        -- filesystem descriptor — and the job it got is recorded against
        -- the connecting principal, and runs as that principal's own
        -- primary token rather than as peinit or as the console.
        local results = quota_results(t)
        t:assert(results.live1, "the probe's first submission was recorded: "
            .. tostring(results.live1 and results.live1.raw))
        t:assert(not results.live1.code,
            "a principal that is not SYSTEM was allowed to submit: " .. results.live1.raw)
        t:assert_eq(results.live1.submitter, LOCAL_SERVICE_SID,
            "the connection's identity is what was recorded: " .. results.live1.raw)
        t:assert_eq(results.live1.identity, LOCAL_SERVICE_SID,
            "and the job runs as that principal, not as peinit: " .. results.live1.raw)

        -- The console's own submissions are recorded against SYSTEM, so
        -- the SID above is a fact about who connected rather than a
        -- constant peinit fills in.
        local _, mine = submit("/bin/true")
        t:assert_eq(mine:match('"submitter":"([^"]+)"'), SYSTEM_SID,
            "while the console's submissions are SYSTEM's: " .. mine)
    end)

test("a submitter's live jobs are counted against MaxJobsPerSubmitter",
    {
        spec = {
            "peinit *submit.the-quota-counts-a-submitters-live-jobs",
            "peinit *submit.a-job-stops-counting-against-the-quota-when-it-is-terminal",
        },
    },
    function(t)
        -- The bound is two, and it is per submitter rather than global.
        -- The interesting half is what "live" means: a job that has
        -- ended stops counting at once, even though its entry is still
        -- there to be asked about for another minute.
        local results = quota_results(t)

        t:assert(not results.live1.code, "the first job was accepted: " .. results.live1.raw)
        t:assert(not results.live2.code, "and the second: " .. results.live2.raw)
        t:assert_eq(results.over.code, "QUOTA_EXCEEDED",
            "the third was refused at the bound: " .. results.over.raw)
        t:assert(results.over.raw:find("limit of 2", 1, true),
            "against the limit the registry set: " .. results.over.raw)
        t:assert(not results.killed.code,
            "one of the two live jobs was killed: " .. results.killed.raw)
        t:assert(not results.refill.code,
            "the killed job's slot came back at once: " .. results.refill.raw)
        t:assert_eq(results.again.code, "QUOTA_EXCEEDED",
            "and the bound still holds with two live again: " .. results.again.raw)

        -- The killed job is still answerable, which is what makes
        -- `refill` a statement about terminal rather than about purged:
        -- peinit had not forgotten the job when it gave the slot back.
        local retained = status(results.live1.id)
        t:assert_eq(retained.state, "failed",
            "the killed job is terminal and still retained: " .. retained.raw)

        -- SYSTEM is exempt: three live jobs at once, past the same bound.
        local system_jobs = {}
        for _ = 1, 3 do system_jobs[#system_jobs + 1] = submit("/bin/sleep 60") end
        for index, id in ipairs(system_jobs) do
            t:assert_eq(status(id).state, "running",
                "SYSTEM's job " .. index .. " is running past the limit of two")
        end
        for _, id in ipairs(system_jobs) do
            vm:run("svctl --json job stop " .. id, { timeout = 60 })
        end
    end)

test("a malformed definition is refused before anything is created",
    {
        spec = {
            "peinit *submit.a-malformed-definition-is-invalid-arguments",
            "peinit *submit.a-refusal-leaves-nothing-behind",
        },
    },
    function(t)
        -- Validation is the first step, so a definition that does not
        -- parse is refused before an identity is established, before the
        -- quota is touched and before a record exists. The evidence that
        -- nothing was created is that the ring gained no
        -- `peinit.job.created` across the refusal and the job list is the
        -- same length.
        local function job_creations()
            return #events({ "peinit.job.created" })
        end
        local function listed()
            local r = vm:run("svctl --json job list")
            r:assert_ok()
            local count = 0
            for _ in r.stdout:gmatch('"id":"') do count = count + 1 end
            return count
        end

        local before_events, before_listed = job_creations(), listed()

        local relative = try_submit("--cwd not-absolute /bin/true")
        t:assert_eq(relative.code, "INVALID_ARGUMENTS",
            "a relative working directory is refused: " .. relative.raw)
        t:assert(not relative.id, "with no job to name: " .. relative.raw)

        t:assert_eq(job_creations(), before_events,
            "no job was created by the refused submission")
        t:assert_eq(listed(), before_listed,
            "and none appeared in the job list")
    end)

test("the definition's fields are validated, and the answer says which one failed",
    {
        spec = {
            "peinit *submit.the-definitions-defaults-and-validation",
            "peinit *submit.descriptors-must-match-the-attachment-count",
        },
    },
    function(t)
        -- Four rows of the definition table, each refused with the field
        -- named. `image_path` is the row that is deliberately *not*
        -- checked: peinit does not stat it, because whether it can be
        -- executed is a question only the job's own identity can answer,
        -- so a path that does not exist is accepted here and fails at
        -- exec instead.
        local cwd = try_submit("--cwd rel /bin/true")
        t:assert_eq(cwd.code, "INVALID_ARGUMENTS", "working_directory must be absolute")
        t:assert(cwd.message:find("working_directory", 1, true),
            "and the field is named: " .. cwd.raw)

        local stop_timeout = try_submit("--stop-timeout 0 /bin/true")
        t:assert_eq(stop_timeout.code, "INVALID_ARGUMENTS", "stop_timeout must be positive")
        t:assert(stop_timeout.message:find("stop_timeout", 1, true),
            "and the field is named: " .. stop_timeout.raw)

        -- A descriptor name may not contain the LISTEN_FDNAMES
        -- separator, because the job could not then tell its
        -- descriptors apart.
        local separator = try_submit("--fd 'a:b=1' /bin/true")
        t:assert_eq(separator.code, "INVALID_ARGUMENTS", "a descriptor name may not hold ':'")
        t:assert(separator.message:find("descriptors", 1, true),
            "and the field is named: " .. separator.raw)

        -- `descriptors` has to match the attachments exactly: its length
        -- plus one if `output` is set equals the number of descriptors
        -- on the message. Both consistent forms are accepted — two
        -- names and two attachments, and one name plus a sink for two
        -- attachments again.
        --
        -- The refusal half of that identity cannot be reached from
        -- here: svctl attaches exactly one descriptor per `--fd` and one
        -- more for `--output`, so every message it builds already
        -- matches. A mismatched one needs a client that can send the
        -- definition and the attachments independently.
        t:assert(submit("--fd ONE=1 --fd TWO=2 /bin/true"),
            "two named descriptors and two attachments are accepted")
        t:assert(submit("--fd ONE=1 --output /bin/true"),
            "and one name plus a sink, which is two attachments for one name")

        local missing = try_submit("/pt-not-a-program")
        t:assert(not missing.code,
            "an image path that does not exist is not a definition error: " .. missing.raw)
        t:assert(missing.id, "the submission was accepted and a job created: " .. missing.raw)
    end)

test("the submit is answered when the job leaves Created, whichever way it left",
    {
        spec = {
            "peinit *submit.the-submit-is-answered-when-the-job-leaves-created",
            "peinit *submit.a-failed-launch-is-still-status-ok",
            "peinit *submit.a-launch-failure-is-parent-setup-failure-or-pre-exec-failure",
        },
    },
    function(t)
        -- The submitter is not told "accepted"; it is told what
        -- happened. A job that execs is answered Running with a PID
        -- already in the view — the answer waited for exec confirmation.
        -- A job that could not exec is answered with a terminal view,
        -- and still `"status": "ok"`, because the submission succeeded
        -- even though the launch did not: the failure is a property of
        -- the job, and it is in the job's `cause`.
        local _, running = submit("/bin/sleep 60")
        t:assert_eq(running:match('"state":"([^"]+)"'), "running",
            "a job that exec'd is answered Running: " .. running)
        t:assert(running:match('"pid":(%d+)'),
            "with the PID the exec produced: " .. running)
        t:assert(running:find('"started_at":"', 1, true),
            "and the moment it started: " .. running)

        local _, failed = submit("/pt-not-a-program")
        t:assert(failed:find('"status":"ok"', 1, true),
            "a launch that failed is still an answered submission: " .. failed)
        t:assert_eq(failed:match('"state":"([^"]+)"'), "failed",
            "with a terminal view: " .. failed)
        t:assert_eq(failed:match('"cause":"([^"]+)"'), "pre_exec_failure",
            "whose cause is the child-side failure between fork and exec: " .. failed)
    end)

test("the default descriptor admits the submitter, SYSTEM and Administrators, and no one else",
    { spec = "peinit *submit.the-default-descriptor-grants-the-submitter-system-and-administrators" },
    function(t)
        -- A submission that says nothing about access gets a descriptor
        -- built from the submitter's SID. The consequence a test can
        -- see: a job LocalService submitted, without LocalService having
        -- asked for it, is visible to the console because the console is
        -- SYSTEM — and the job's own identity, which is also
        -- LocalService here, was granted nothing by name.
        local results = quota_results(t)
        t:assert(results.live1.id, "the LocalService probe's job has an identifier")

        local seen = vm:run("svctl --json job status " .. results.live1.id)
        seen:assert_ok()
        t:assert_eq(seen.stdout:match('"submitter":"([^"]+)"'), LOCAL_SERVICE_SID,
            "SYSTEM can see a job it did not submit: " .. seen.stdout)

        -- And the console's own jobs are visible to the console, which
        -- is the submitter half of the same DACL.
        local mine = submit("/bin/sleep 30")
        t:assert_eq(status(mine).state, "running",
            "a submitter can see its own job")
        vm:run("svctl --json job stop " .. mine, { timeout = 60 })
    end)

test("a supplied descriptor is used exactly as given, even when it locks its submitter out",
    {
        spec = {
            "peinit *submit.a-supplied-descriptor-is-used-as-given",
            "peinit *submit.a-denial-is-answered-access-denied",
            "peinit *submit.both-doors-check-the-same-descriptor",
        },
    },
    function(t)
        -- The descriptor below grants everything to a group the console
        -- is not in, and names the console nowhere. peinit adds no
        -- default entries to make up for that, so the submitter cannot
        -- query, stop or signal the job it just created — on either
        -- door, because both check the same descriptor.
        local id, view = submit("--security-descriptor " ..
            "'O:S-1-5-32-546G:S-1-5-32-546D:(A;;GA;;;S-1-5-32-546)' /bin/sleep 30")
        t:assert(view:find('"status":"ok"', 1, true),
            "the submission itself is not refused: " .. view)

        -- The control socket's door.
        local queried = vm:run("svctl --json job status " .. id)
        t:assert_eq(queried.stdout:match('"code":"([^"]+)"'), "ACCESS_DENIED",
            "job-status is refused: " .. queried.stdout)
        local stopped = vm:run("svctl --json job stop " .. id, { timeout = 60 })
        t:assert_eq(stopped.stdout:match('"code":"([^"]+)"'), "ACCESS_DENIED",
            "job-stop is refused: " .. stopped.stdout)

        -- The jobs socket's door, on the same job and the same
        -- descriptor.
        local signalled = vm:run("svctl --json job signal " .. id .. " TERM")
        t:assert_eq(signalled.stdout:match('"code":"([^"]+)"'), "ACCESS_DENIED",
            "signal is refused on the other socket too: " .. signalled.stdout)
        local waited = vm:run("svctl --json job wait " .. id, { timeout = 60 })
        t:assert_eq(waited.stdout:match('"code":"([^"]+)"'), "ACCESS_DENIED",
            "and so is wait: " .. waited.stdout)
    end)

test("a submitted job runs in a cgroup of its own under the jobs tree",
    { spec = "peinit *submit.the-job-runs-in-a-cgroup-of-its-own-under-peinit-jobs" },
    function(t)
        -- A job is not a service and does not live in the service tree:
        -- its containment is named by its own identifier, under
        -- `/peinit/jobs/`. The job reads its own cgroup line, which is
        -- the guest's own answer rather than a path a test assembled.
        vm:run("mkdir -p /pt")
        local id = submit("/bin/sh -c 'cat /proc/self/cgroup > /pt/cgroup'")
        vm:run("svctl --json job wait " .. id, { timeout = 60 })

        local line = tostring(vm:read_file("/pt/cgroup")):gsub("%s+$", "")
        t:assert_eq(line, "0::/peinit/jobs/" .. id,
            "the job's cgroup is named by its identifier under the jobs tree: " .. line)
    end)

test("attached descriptors arrive from 3 upward with the LISTEN variables set",
    {
        spec = {
            "peinit *submit.attached-descriptors-are-placed-from-three-upward-with-the-listen-variables",
            "peinit *submit.a-submitter-cannot-override-the-protocol-variables",
        },
    },
    function(t)
        -- Two descriptors, named. The job should find them at 3 and 4
        -- with close-on-exec cleared — it is past the exec, so anything
        -- it can still see was not closed by it — and be told how many
        -- and what they are called. The submission also tries to set
        -- NOTIFY_SOCKET, which is layered under the protocol variables
        -- and so cannot win.
        vm:run("mkdir -p /pt")
        local id = submit("--fd ALPHA=1 --fd BETA=2 --env NOTIFY_SOCKET=/pt-bogus " ..
            "--env PT_MINE=kept " ..
            "/bin/sh -c 'cat /proc/self/environ > /pt/env; ls /proc/self/fd > /pt/fds'")
        vm:run("svctl --json job wait " .. id, { timeout = 60 })

        local env = {}
        for entry in tostring(vm:read_file("/pt/env")):gmatch("[^%z]+") do
            local name, value = entry:match("^([^=]+)=(.*)$")
            if name then env[name] = value end
        end

        t:assert_eq(env.LISTEN_FDS, "2", "the job is told how many descriptors it has")
        t:assert_eq(env.LISTEN_FDNAMES, "ALPHA:BETA",
            "and their names, in attachment order: " .. tostring(env.LISTEN_FDNAMES))
        t:assert(env.LISTEN_PID, "and which process they were meant for")

        local fds = {}
        for fd in tostring(vm:read_file("/pt/fds")):gmatch("%d+") do fds[fd] = true end
        t:assert(fds["3"] and fds["4"],
            "the descriptors themselves are at 3 and 4, past the exec")

        t:assert_eq(env.NOTIFY_SOCKET, "/run/services/peinit/notify.sock",
            "NOTIFY_SOCKET is peinit's, not the submitter's: " .. tostring(env.NOTIFY_SOCKET))
        t:assert_eq(env.PT_MINE, "kept",
            "while a variable that is not the protocol's survives")
    end)

test("svctl's job commands are split across the two sockets",
    { spec = "peinit *submit.the-two-halves-of-svctls-job-commands" },
    function(t)
        -- `list`, `status` and `stop` are an administrator's, and go to
        -- the control socket; `submit`, `wait` and `signal` are a
        -- submitter's, and go to the jobs socket. Pointing one of the
        -- two path options at nothing shows which half each command
        -- belongs to: the command that needs the missing socket cannot
        -- connect, and the other is unaffected.
        local id = submit("/bin/sleep 60")

        local status_without_jobs =
            vm:run("svctl --jobs-socket /pt-none --json job status " .. id)
        t:assert(not tostring(status_without_jobs.stderr):find("connect", 1, true),
            "job status does not need the jobs socket: "
            .. tostring(status_without_jobs.stderr))
        t:assert_eq(status_without_jobs.stdout:match('"state":"([^"]+)"'), "running",
            "and answers from the control socket: " .. status_without_jobs.stdout)

        local status_without_control =
            vm:run("svctl --socket /pt-none --json job status " .. id)
        t:assert(tostring(status_without_control.stderr):find("/pt%-none"),
            "while without the control socket it cannot connect: "
            .. tostring(status_without_control.stderr))

        local submit_without_control =
            vm:run("svctl --socket /pt-none --json job submit /bin/true")
        t:assert(submit_without_control.stdout:find('"status":"ok"', 1, true),
            "submit does not need the control socket: " .. submit_without_control.stdout)

        local submit_without_jobs =
            vm:run("svctl --jobs-socket /pt-none --json job submit /bin/true")
        t:assert(tostring(submit_without_jobs.stderr):find("/pt%-none"),
            "while without the jobs socket it cannot connect: "
            .. tostring(submit_without_jobs.stderr))

        vm:run("svctl --json job stop " .. id, { timeout = 60 })
    end)

--- Submit pt-notify as a job running `steps`, then writing a marker and
--- sleeping. Returns the job's identifier once the steps have run.
---
--- The first step is always `sleep 1`: a datagram sent the instant after
--- exec can arrive before peinit has recorded the job's pid, and is then
--- refused as coming from no one it supervises.
local function notifying_job(name, options, steps)
    local quoted = {}
    for _, step in ipairs(steps) do quoted[#quoted + 1] = "'" .. step .. "'" end
    local done = "/run/" .. name .. ".done"
    local id = submit(options .. " /usr/bin/pt-notify sleep 1 " .. table.concat(quoted, " ")
        .. " write " .. done .. " ok sleep 100000")
    wait_until(function() return vm:run("test -f " .. done):ok() or nil end,
        { timeout = 60, interval = 0.2, desc = name .. " to run its notification steps" })
    -- The marker is written after the last datagram is sent; peinit still
    -- has to read it.
    vm:run("sleep 0.5")
    return id
end

test("a submitted job's notifications set what §8.5 says, and nothing else",
    { spec = "peinit *submit.the-notification-fields-a-submitted-job-may-send" },
    function(t)
        -- Every row of the table, in one job. The literal `\n` in each
        -- message is pt-notify's line separator.
        local id = notifying_job("pt-jn-fields", "--readiness notify --stop-timeout 3", {
            "send", "STATUS=working\\nPROGRESS=3/10\\nPROGRESS_UNIT=items",
            -- N above T: that line is dropped, never repaired, and the rest
            -- of the datagram is applied.
            "send", "PROGRESS=11/10\\nSTATUS=still working",
            -- A unit outside the three is dropped.
            "send", "PROGRESS_UNIT=furlongs",
            -- A job has no reload, no watchdog and no fd store.
            "send", "RELOADING=1\\nWATCHDOG=1",
            "send", "READY=1",
            "send", "STOPPING=1",
        })

        local view = vm:run("svctl --json job status " .. id).stdout
        t:assert_eq(view:match('"state":"([^"]+)"'), "running",
            "the job is still running, none of it taken as a reason to act: " .. view)
        t:assert(view:find('"ready":true', 1, true),
            "READY=1 made a notify job ready: " .. view)
        t:assert_eq(view:match('"status_text":"([^"]*)"'), "still working",
            "STATUS= is retained, and the later datagram's is the one kept: " .. view)
        t:assert(view:find('"current":3,', 1, true) and view:find('"total":10,', 1, true),
            "PROGRESS=3/10 is retained and the out-of-range 11/10 was dropped: " .. view)
        t:assert(view:find('"unit":"items"', 1, true),
            "PROGRESS_UNIT=items is retained and the unknown unit was dropped: " .. view)

        -- STOPPING=1 was recorded, so the stop sends no termination
        -- signal. pt-notify does not handle SIGTERM: had one been sent the
        -- job would have died of it at once. It dies instead of the kill
        -- at its three-second stop deadline.
        local stopped = vm:run("svctl --json job stop " .. id, { timeout = 60 }).stdout
        t:assert_eq(stopped:match('"exit_signal":(%d+)'), "9",
            "a job that sent STOPPING=1 is not sent SIGTERM, and is killed at the deadline: "
            .. stopped)
    end)

test("peinit.job.status.reported is emitted at most once per job per second, and the view stays current",
    { spec = "peinit *emit.job-status-is-emitted-at-most-once-per-job-per-second" },
    function(t)
        -- Twenty status updates, sent back to back — far more than one a
        -- second. Every one changes status_text, so every one is due an
        -- event; the rate limit is what stops twenty arriving.
        local steps = {}
        for k = 1, 20 do
            steps[#steps + 1] = "send"
            steps[#steps + 1] = "STATUS=update " .. k
        end
        local id = notifying_job("pt-jn-rate", "", steps)

        -- A query sees the latest value, whatever the events are doing.
        local view = vm:run("svctl --json job status " .. id).stdout
        t:assert_eq(view:match('"status_text":"([^"]*)"'), "update 20",
            "the view is current on every query: " .. view)

        -- The burst took well under a second. Give any trailing event its
        -- second, then count.
        vm:run("sleep 2")
        local count = 0
        for _, event in ipairs(events({ "peinit.job.status.reported" })) do
            if about_job(event, id) then count = count + 1 end
        end
        t:assert(count >= 1, "the burst produced a peinit.job.status.reported event")
        t:assert(count <= 2,
            "and at most one a second — twenty updates inside one second gave " .. count)

        vm:run("svctl --json job stop " .. id, { timeout = 60 })
    end)

test("an attached token below Impersonation level is refused with BAD_TOKEN",
    { spec = "peinit *submit.a-token-below-impersonation-level-is-refused-with-bad-token" },
    function(t)
        -- svctl submits as the caller's own primary token and never
        -- attaches one, so the worker does it: a token minted for a local
        -- user at a chosen level, carried on the `submit` record as a
        -- KACS_SCM_TOKEN. The worker is SYSTEM, holds
        -- SeImpersonatePrivilege, and so passes the kernel's attach gate
        -- for any level, and what reaches peinit is the token at the
        -- level it was minted at.
        local SUBMIT = '{"command":"submit","image_path":"/bin/true"}'
        local user_sid = token.sid_string(token.SID.TEST_USER)

        f.with_worker(vm, function(w)
            local function submit_with(level)
                local tok = assert(token.mint(w, {
                    user_sid = token.SID.TEST_USER,
                    token_type = token.TYPE.IMPERSONATION,
                    impersonation_level = level,
                }))
                local fd, err = us.socket(w, us.AF_UNIX, us.SOCK.SEQPACKET)
                assert(fd, "socket: " .. tostring(err))
                assert(us.connect(w, fd, f.JOBS_SOCKET).ret == 0, "connect to the jobs socket")
                local answer, why = f.jobs_request(w, fd, SUBMIT, tok)
                w:syscall(3, fd); w:syscall(3, tok)
                assert(answer, "no answer to the submit: " .. tostring(why))
                return {
                    raw = answer,
                    code = answer:match('"code":"([^"]+)"'),
                    identity = answer:match('"identity":"([^"]+)"'),
                }
            end

            -- The control: at Impersonation the token is a job identity,
            -- and the job runs as the user it names.
            local acting = submit_with(token.LEVEL.IMPERSONATION)
            t:assert(acting.raw:find('"status":"ok"', 1, true) and not acting.code,
                "an Impersonation-level token is accepted: " .. acting.raw)
            t:assert_eq(acting.identity, user_sid,
                "and the job's identity is the user the token names: " .. acting.raw)

            -- Below it, refused, and refused as a bad token rather than
            -- for anything about who the token names — which is the same
            -- user as the control.
            local identification = submit_with(token.LEVEL.IDENTIFICATION)
            t:assert_eq(identification.code, "BAD_TOKEN",
                "an Identification-level token is refused: " .. identification.raw)
            local anonymous = submit_with(token.LEVEL.ANONYMOUS)
            t:assert_eq(anonymous.code, "BAD_TOKEN",
                "and so is an Anonymous-level one: " .. anonymous.raw)
        end)
    end)

test("arguments and environment together are refused past 2 MiB",
    {
        spec = "peinit *submit.arguments-and-environment-are-bounded-at-two-mib",
        -- One byte over is refused cleanly, which is what this asserts.
        -- The other side of the boundary — a definition *at* 2 MiB, which
        -- the article says is accepted — cannot be exercised here: peinit
        -- accepts it, runs it, and then could not emit its
        -- `peinit.job.ended` KMES event, whose payload carries the whole ~2 MiB `arguments`
        -- array. `kmes_emit` fails with ENOSPC and that ends the runtime
        -- loop, taking PID 1 to recovery. A definition that fills one
        -- default 64 KiB record already does it (PEI-1082). So this file
        -- proves only the refusal, and does not send an accepted large
        -- definition that would kill the machine for every test after
        -- it; the accept side is ops-submitted-large.test.lua, on a boot
        -- of its own.
    },
    function(t)
        -- The bound is on argv plus envp as execve counts them: every
        -- string and its terminating NUL, the image path as argv[0], and
        -- each variable as NAME=VALUE. 2 MiB + 1 of that does not fit in
        -- a default-sized record, so this boot raises MaxJobMessageSize to 4 MiB
        -- (in `definitions()` above); and it does not fit a sequenced-
        -- packet socket's default send buffer either, so the worker
        -- forces its own up before it sends. The one byte that tips the
        -- total over the limit is in the environment, so the message the
        -- refusal names counts argv and envp together rather than only
        -- one of them.
        local LIMIT = 2 * 1024 * 1024
        local image = "/bin/true"
        local arguments, bytes = {}, #image + 1
        for k = 1, 20 do
            arguments[k] = string.rep("a", 100000)
            bytes = bytes + 100001
        end
        local pad = 101
        local env_bytes = #"PT_PAD" + 1 + pad + 1
        local last = LIMIT + 1 - bytes - env_bytes - 1
        local list = {}
        for k = 1, #arguments do list[k] = '"' .. arguments[k] .. '"' end
        list[#list + 1] = '"' .. string.rep("b", last) .. '"'
        local over = '{"command":"submit","image_path":"' .. image .. '","arguments":[' ..
            table.concat(list, ",") .. '],"environment":{"PT_PAD":"' ..
            string.rep("c", pad) .. '"}}'
        t:assert_eq(bytes + last + 1 + env_bytes, LIMIT + 1,
            "the definition totals one byte over 2 MiB")

        -- Room in the send buffer for the ~2 MiB record. SO_SNDBUFFORCE
        -- is the privileged form, which the worker's SYSTEM token holds;
        -- the plain one is capped by wmem_max, raised first in case the
        -- force is ever not available.
        vm:run("echo 16777216 > /proc/sys/net/core/wmem_max")

        f.with_worker(vm, function(w)
            local fd = assert(us.socket(w, us.AF_UNIX, us.SOCK.SEQPACKET))
            local size = string.pack("<i4", 8 * 1024 * 1024)
            local forced = w:syscall(us.NR.setsockopt, {
                args = { fd, 1, 32, 0, 4 }, bufs = { size }, ptrs = { 3 } })
            if forced.ret ~= 0 then
                w:syscall(us.NR.setsockopt, {
                    args = { fd, 1, 7, 0, 4 }, bufs = { size }, ptrs = { 3 } })
            end
            local connected = us.connect(w, fd, f.JOBS_SOCKET)
            assert(connected.ret == 0, "connect to the jobs socket: " ..
                us.errname(connected.errno))
            local refused, why = f.jobs_request(w, fd, over)
            w:syscall(3, fd)
            assert(refused, "no answer to the over-limit submit: " .. tostring(why))

            t:assert_eq(refused:match('"code":"([^"]+)"'), "INVALID_ARGUMENTS",
                "a definition one byte over 2 MiB is refused: " .. refused:sub(1, 300))
            t:assert(refused:find("total " .. (LIMIT + 1) .. " bytes, over the " ..
                LIMIT .. " limit", 1, true),
                "counting argv and envp together against the 2 MiB bound: " ..
                refused:sub(1, 300))
        end)

        -- And the refusal left peinit answering: a definition over the
        -- bound is rejected, not a message that ends the runtime loop.
        t:assert(vm:run("svctl --json job submit /bin/true"):ok(),
            "peinit still serves the jobs socket after the refusal")
    end)

test("a job whose arguments outgrow peinit.job.ended is recorded with a cut that says so",
    { spec = "peinit *emit.job-ended-cuts-its-arguments-and-says-so" },
    function(t)
        -- A 100 KiB argument, well inside this boot's raised
        -- MaxJobMessageSize and the 2 MiB bound. Its `peinit.job.ended`
        -- cannot carry it whole: the event keeps 32 KiB of whole
        -- arguments and says so itself, in
        -- `object.job.arguments-truncated` and `-count`; no separate
        -- notice follows it. Before PEI-1082 the oversized event was
        -- refused by the ring and the refusal ended the runtime loop.
        local big = string.rep("a", 100000)
        local record = '{"command":"submit","image_path":"/bin/true","arguments":["' ..
            big .. '"]}'
        local id
        f.with_worker(vm, function(w)
            local fd = assert(us.socket(w, us.AF_UNIX, us.SOCK.SEQPACKET))
            local connected = us.connect(w, fd, f.JOBS_SOCKET)
            assert(connected.ret == 0, "connect to the jobs socket: " ..
                us.errname(connected.errno))
            local answer, why = f.jobs_request(w, fd, record)
            w:syscall(3, fd)
            assert(answer, "no answer to the submit: " .. tostring(why))
            id = answer:match('"id":"([^"]+)"')
            t:assert(id and answer:find('"status":"ok"', 1, true),
                "a 100 KiB argument is accepted: " .. answer:sub(1, 300))
        end)

        local waited = vm:run("svctl --json job wait " .. id, { timeout = 60 })
        t:assert(waited:ok() and waited.stdout:match('"state":"([^"]+)"') == "completed",
            "the job ran to completion: " .. waited.stdout .. tostring(waited.stderr))
        t:assert(vm:run("svctl --json job submit /bin/true"):ok(),
            "and peinit still serves the jobs socket after its peinit.job.ended")

        local field = revstrm.field
        local ended, dropped
        for _, event in ipairs(events({ "peinit.job.ended", "peinit.event.dropped" })) do
            if about_job(event, id) then
                if event.type == "peinit.job.ended" then ended = event end
                if event.type == "peinit.event.dropped" then dropped = event end
            end
        end
        t:assert(ended, "the job's peinit.job.ended reached the ring")
        t:assert_eq(field(ended, "object.job.arguments-truncated"), "true",
            "and says its arguments were cut: " .. ended.payload)
        t:assert_eq(field(ended, "object.job.arguments-count"), "1",
            "naming how many there were: " .. ended.payload)
        t:assert_eq(field(ended, "object.job.arguments"), "[]",
            "keeping only the whole arguments that fit, here none: " .. ended.payload)
        t:assert(not ended.payload:find(big, 1, true),
            "the 100 KiB argument itself is not in it")
        t:assert(not dropped, "and nothing about the job was dropped")
    end)

-- A stop on a job still queued for launch cancels it before it runs. No
-- guest can hold a job in the launch queue long enough to stop it there:
-- the queue drains one job per pump step, a `submit` is not answered
-- until its own job has left Created, and the window between enqueue and
-- launch is a single turn. It is a unit test in the peinit crate.
test("a stop on a queued job cancels it before it runs",
    {
        spec = "peinit *submit.a-stop-on-a-queued-job-cancels-it-before-it-runs",
        covered_by = "cargo:peinit2 supervisor::tests::submitted::stop::stopping_a_job_that_has_not_launched_cancels_it",
        skip = "a job sits in the launch queue for one pump step, too briefly for a guest to " ..
            "stop it there, and a submit is not answered until its job has left Created; runs under " ..
            "cargo test -p peinit2 --all-features --lib " ..
            "supervisor::tests::submitted::stop::stopping_a_job_that_has_not_launched_cancels_it",
    },
    function(t) end)
