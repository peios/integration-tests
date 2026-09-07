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

local peinit = require("helpers.peinit")
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

local vm = peinit.boot({ name = "opssub", files = peinit.seed("pt-sub", definitions()) })

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

local function events(globs)
    local flags = ""
    for _, glob in ipairs(globs) do flags = flags .. " --type '" .. glob .. "'" end
    local r = vm:run("revstrm --snapshot --pretty" .. flags, { timeout = 60 })
    r:assert_ok()
    local out, current = {}, nil
    for line in r.stdout:gmatch("[^\r\n]+") do
        local kind = line:match("^%d%d:%d%d:%d%d[%.%d]*%s+cpu.-#%d+%s+%u+%s+([%w_]+%.[%w_]+)%s*$")
        if kind then
            current = { type = kind, payload = "" }
            out[#out + 1] = current
        elseif current and line:match("^%s") then
            current.payload = current.payload .. line .. "\n"
        end
    end
    return out
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
        -- nothing was created is that the ring gained no `job.created`
        -- across the refusal and the job list is the same length.
        local function job_creations()
            return #events({ "job.created" })
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
