-- peinit TRM §8.1 — the job: one supervised process execution, its
-- lifecycle, the rules that say which of its nullable fields are
-- populated, and how long it survives.
--
-- Most of what §8.1 states is about the *record*, and the record is
-- never handed out whole on either socket: the control interface shows a
-- service's current job as four fields, and the jobs interface shows a
-- submitted job's view. The one place the full record appears is the
-- KMES event stream, which is where a `job.ended` payload carries every
-- field the article lists. So the instrument here is `revstrm
-- --snapshot`, the guest's own probe onto the ring — it needs
-- SeSecurityPrivilege, which the console has, and `--type` takes a glob
-- so a snapshot can be narrowed to `job.*` before the boot's several
-- hundred other events arrive.
--
-- A submitted job (§8.5) is the only job a test can create on demand, so
-- it stands in for "a job" wherever the claim is about jobs in general.
-- Where the claim is specifically about a service's job — a restart
-- creating a new one, a status query naming the current one — the seeded
-- services below are the subject instead.

local peinit = require("helpers.peinit")
-- One VM for the file: every claim here is about a job rather than
-- about a boot, and one booted Peios produces all six job types.
peinit.claim(1)

--- One service exercising every hook peinit forks for, so that a single
--- boot produces a job of each type. The health check interval is short
--- because the first check is what the type census needs, and a reload
--- is issued by hand.
local function definitions()
    return {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
        { path = [[Machine\System\Services\pt-forks]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/sleep" },
            { name = "Arguments", type = "multi", data = { "100000" } },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
            { name = "ExecStartPre", type = "multi", data = { "/bin/true" } },
            { name = "ExecStartPost", type = "multi", data = { "/bin/true" } },
            { name = "ExecReload", type = "sz", data = "/bin/true" },
            { name = "HealthCheck", type = "sz", data = "/bin/true" },
            { name = "HealthCheckInterval", type = "dword", data = 1 },
            { name = "HealthCheckRetries", type = "dword", data = 3 },
            { name = "RestartPolicy", type = "dword", data = 0 },
            { name = "Triggers", type = "multi", data = { "boot" } },
        } },
        -- The restart subject, deliberately without hooks or a health
        -- check: what that test is about is the job identifier moving,
        -- and a service with four other kinds of job in flight would
        -- make a failure there ambiguous.
        { path = [[Machine\System\Services\pt-plain]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/sleep" },
            { name = "Arguments", type = "multi", data = { "100000" } },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
            { name = "RestartPolicy", type = "dword", data = 0 },
            { name = "Triggers", type = "multi", data = { "boot" } },
        } },
    }
end

local vm = peinit.boot({ name = "opsjob", files = peinit.seed("pt-job", definitions()) })

--- Submit a job and return its identifier and the view the submit
--- answered with.
local function submit(arguments)
    local r = vm:run("svctl --json job submit " .. arguments)
    r:assert_ok()
    local id = r.stdout:match('"id":"([^"]+)"')
    assert(id, "no job identifier in: " .. r.stdout)
    return id, r.stdout
end

--- Every event whose type matches one of `globs`, as
--- `{type, payload}`, oldest first.
---
--- `--snapshot` drains what the ring holds and exits, so this is finite;
--- without it revstrm follows the stream and never returns. `--pretty`
--- rather than the default line form because the default caps the
--- payload at a couple of hundred characters and elides the rest, which
--- silently hides exactly the fields §8.1 is about. The pretty form is
--- a header line followed by indented `key   value` rows, so an event
--- is a header plus every indented line under it.
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

--- The value of one field in a pretty-rendered payload, without the
--- quotes a string carries.
local function field(event, name)
    local value = event.payload:match("\n?%s+" .. name .. "%s%s+([^\r\n]*)")
    if not value then return nil end
    return (value:gsub('^"', ""):gsub('"$', ""))
end

--- Wait until `service` is Active.
---
--- `peinit.boot` returns at the phase-2 mark, which is when the plan was
--- dispatched rather than when it finished, so a command sent
--- immediately afterwards can arrive while the boot's own start is still
--- Running — and a reload against a Starting service is refused for the
--- state, which looks from here like the reload hook never running.
local function wait_active(service)
    for _ = 1, 60 do
        local state = vm:run("svctl --json status " .. service)
            .stdout:match('"state":"([^"]+)"')
        if state == "active" then return end
        vm:run("sleep 1")
    end
    error(service .. " never reached Active")
end

--- The events of `kind` mentioning one job identifier, oldest first.
local function events_for(kind, id)
    local out = {}
    for _, event in ipairs(events({ kind })) do
        if field(event, "job_id") == id then out[#out + 1] = event end
    end
    return out
end

test("every fork peinit performs is a job, and the job records which kind it was",
    { spec = "peinit *job.every-fork-peinit-performs-is-a-job" },
    function(t)
        -- The six job types are the six things peinit forks for. One
        -- seeded service carries a pre-start hook, a post-start hook, a
        -- reload command and a health check as well as its own main
        -- binary; a submitted job is the sixth. A census of the ring's
        -- `job.created` payloads should therefore name all six.
        wait_active("pt-forks")
        vm:run("svctl --json reload pt-forks", { timeout = 90 }):assert_ok()
        submit("/bin/true")
        -- The health check runs on its interval rather than at start, so
        -- the census waits out one before taking it.
        vm:run("sleep 4", { timeout = 30 })

        local seen = {}
        for _, event in ipairs(events({ "job.created" })) do
            local kind = field(event, "type")
            if kind then seen[kind] = true end
        end

        for _, kind in ipairs({ "service_main", "pre_exec_hook", "post_exec_hook",
                                "reload_hook", "health_check", "submitted" }) do
            t:assert(seen[kind], "peinit forked a " .. kind .. " job")
        end
    end)

test("a restart creates a new job, and the service's status names the current one",
    {
        spec = {
            "peinit *job.a-restart-creates-a-new-job",
            "peinit *job.a-status-query-returns-the-services-current-main-job",
        },
    },
    function(t)
        -- A service is a definition; a job is one execution of it. The
        -- observable consequence is that the identifier a status query
        -- reports moves when the service is restarted, and moves to a
        -- job with a different process — a restart that reported the
        -- same job identifier would mean peinit had reused the record
        -- for a second execution.
        local before = vm:run("svctl --json status pt-plain")
        before:assert_ok()
        local first_job = before.stdout:match('"current_job":{"id":"([^"]+)"')
        local first_pid = before.stdout:match('"pid":(%d+)')
        t:assert(first_job, "a status query names the current main job: " .. before.stdout)

        vm:run("svctl --json restart pt-plain", { timeout = 90 }):assert_ok()

        local after = vm:run("svctl --json status pt-plain")
        after:assert_ok()
        local second_job = after.stdout:match('"current_job":{"id":"([^"]+)"')
        local second_pid = after.stdout:match('"pid":(%d+)')
        t:assert(second_job, "and still names one afterwards: " .. after.stdout)
        t:assert(second_job ~= first_job,
            "the restart created a new job: " .. first_job .. " -> " .. second_job)
        t:assert(second_pid ~= first_pid,
            "running a new process: " .. tostring(first_pid) .. " -> " .. tostring(second_pid))
        t:assert(after.stdout:find('"type":"service_main"', 1, true),
            "and the job the service tracks is its main one: " .. after.stdout)
    end)

test("a job goes Created, then Running, then to a terminal state",
    { spec = "peinit *job.the-lifecycle-states" },
    function(t)
        -- The three events a job emits are the three states it passes
        -- through, in order. A job that exits 0 ends Completed; one that
        -- exits non-zero ends Failed. Both are read from the ring rather
        -- than from a view, because the view of a terminal job is built
        -- from the retained outcome and cannot show the Created it
        -- passed through.
        local ok_id = submit("/bin/true")
        local bad_id = submit("/bin/false")
        vm:run("svctl --json job wait " .. ok_id, { timeout = 60 })
        vm:run("svctl --json job wait " .. bad_id, { timeout = 60 })

        local states = { [ok_id] = {}, [bad_id] = {} }
        for _, event in ipairs(events({ "job.created", "job.started", "job.ended" })) do
            local seq = states[field(event, "job_id")]
            if seq then seq[#seq + 1] = field(event, "state") end
        end

        t:assert_eq(table.concat(states[ok_id], ","), "created,running,completed",
            "a job that exits 0 passes Created, Running, Completed")
        t:assert_eq(table.concat(states[bad_id], ","), "created,running,failed",
            "and one that exits non-zero ends Failed instead")
    end)

test("a job that never forks still has an identity, and its process fields stay null",
    {
        spec = {
            "peinit *job.the-id-is-assigned-before-the-fork",
            "peinit *job.a-setup-failure-goes-created-to-failed-with-the-exit-fields-null",
        },
    },
    function(t)
        -- An image path that does not exist fails in the child, between
        -- fork and exec. The identifier is already assigned, so the
        -- submitter is answered with a job view rather than an error
        -- with nothing to name — and every field that describes a
        -- process is null, because there was never a process: no PID, no
        -- start, no exit code and no signal. `ended_at` is set, and what
        -- it records is when peinit classified the failure.
        local id, view = submit("/pt-not-a-program")
        t:assert(id:match("^%x+%-%x+%-%x+%-%x+%-%x+$"),
            "the job has an identifier despite never forking: " .. view)

        t:assert_eq(view:match('"state":"([^"]+)"'), "failed", "it is Failed: " .. view)
        t:assert_eq(view:match('"cause":"([^"]+)"'), "pre_exec_failure",
            "with the cause of the failure recorded: " .. view)
        for _, field in ipairs({ "pid", "started_at", "exit_code", "exit_signal" }) do
            t:assert(view:find('"' .. field .. '":null', 1, true),
                field .. " is null, because there was no process: " .. view)
        end
        t:assert(view:find('"ended_at":"', 1, true),
            "while ended_at records when peinit classified it: " .. view)
    end)

test("exit_code and exit_signal are never both populated",
    { spec = "peinit *job.exit-code-and-exit-signal-are-never-both-populated" },
    function(t)
        -- A process either exits with a status or is killed by a signal.
        -- Two jobs, one of each: the exited one carries a code and no
        -- signal, the signalled one a signal and no code.
        local exited = submit("/bin/false")
        vm:run("svctl --json job wait " .. exited, { timeout = 60 })
        local exited_view = vm:run("svctl --json job status " .. exited)
        exited_view:assert_ok()
        t:assert(exited_view.stdout:find('"exit_code":1', 1, true),
            "a job that exited carries its code: " .. exited_view.stdout)
        t:assert(exited_view.stdout:find('"exit_signal":null', 1, true),
            "and no signal: " .. exited_view.stdout)

        local killed = submit("/bin/sleep 300")
        vm:run("svctl --json job signal " .. killed .. " KILL"):assert_ok()
        vm:run("svctl --json job wait " .. killed, { timeout = 60 })
        local killed_view = vm:run("svctl --json job status " .. killed)
        killed_view:assert_ok()
        t:assert(killed_view.stdout:find('"exit_signal":9', 1, true),
            "a job that was killed carries its signal: " .. killed_view.stdout)
        t:assert(killed_view.stdout:find('"exit_code":null', 1, true),
            "and no exit code: " .. killed_view.stdout)
    end)

test("a submitted job's resolved identity is its job identity's user SID",
    { spec = "peinit *job.a-submitted-jobs-resolved-identity-is-the-job-identitys-user-sid" },
    function(t)
        -- `resolved_identity` is the identity string a job was launched
        -- under. For a service that is a name — SYSTEM, LocalService —
        -- because a name is what the definition gave. A submission names
        -- nobody, so what is recorded is the SID of the token peinit
        -- opened, and the record in the event stream says so.
        local caller = vm:run("token user")
        caller:assert_ok()
        local sid = caller.stdout:match("S%-[%d%-]+")
        t:assert(sid, "the console has a SID: " .. caller.stdout)

        local id = submit("/bin/true")
        vm:run("svctl --json job wait " .. id, { timeout = 60 })
        local event = events_for("job.ended", id)[1]
        t:assert(event, "the job's end was emitted")
        t:assert_eq(field(event, "resolved_identity"), sid,
            "and records the SID rather than a name: " .. event.payload)

        -- The same job, seen through a service's eyes, would carry a
        -- name — which is what makes the SID here a property of
        -- submission rather than of the event encoding.
        local service = vm:run("svctl --json status pt-plain")
        t:assert(service.stdout:find('"identity":"SYSTEM"', 1, true),
            "a service's job reports the name it was defined with: " .. service.stdout)
    end)

test("a terminal job's record is emitted whole and then dropped",
    { spec = "peinit *job.a-terminal-job-is-emitted-then-dropped" },
    function(t)
        -- peinit keeps no job history: the last thing it does with a
        -- record is put it in an event. `job.ended` therefore carries
        -- the fields no view exposes — the arguments, the cgroup, the
        -- pidfd, the creation timestamp — and afterwards the only thing
        -- that can answer for the job is the retained entry, which does
        -- not have a PID to report.
        local id = submit("/bin/sleep 1")
        vm:run("svctl --json job wait " .. id, { timeout = 60 })

        local event = events_for("job.ended", id)[1]
        t:assert(event, "the terminal job was emitted")
        for _, name in ipairs({ "arguments", "cgroup_id", "created_at_ns",
                                "started_at_ns", "ended_at_ns", "resolved_identity",
                                "pidfd", "duration_ns" }) do
            t:assert(field(event, name),
                "the event carries the record's " .. name .. ": " .. event.payload)
        end

        local view = vm:run("svctl --json job status " .. id)
        view:assert_ok()
        t:assert(view.stdout:find('"pid":null', 1, true),
            "and what answers afterwards has no record to take a PID from: "
            .. view.stdout)
    end)

test("a submitted job's entry outlives its record by sixty seconds, and then it is unknown",
    {
        spec = {
            "peinit *job.a-submitted-jobs-entry-outlives-its-record-by-sixty-seconds",
            "peinit *submit.a-purged-or-unknown-identifier-is-unknown-job-either-way",
        },
    },
    function(t)
        -- The record goes when the job ends. The entry stays, so a
        -- submitter that was not watching can still collect the outcome;
        -- after the grace period it is purged and the identifier means
        -- nothing again. 60 seconds is the retention, so a job asked
        -- about at 5 seconds answers and one asked about at 75 does not.
        local id = submit("/bin/true")
        vm:run("svctl --json job wait " .. id, { timeout = 60 })

        local soon = vm:run("svctl --json job status " .. id)
        soon:assert_ok()
        t:assert_eq(soon.stdout:match('"state":"([^"]+)"'), "completed",
            "the outcome is still there straight after the job ended: " .. soon.stdout)

        vm:run("sleep 75", { timeout = 120 })

        local later = vm:run("svctl --json job status " .. id)
        t:assert_eq(later.stdout:match('"code":"([^"]+)"'), "UNKNOWN_JOB",
            "and is gone once the retention window has passed: " .. later.stdout)

        -- A purged identifier and one that never named anything are
        -- answered the same way: peinit does not distinguish "you had
        -- this and it expired" from "there was never such a job", and a
        -- caller cannot tell them apart either.
        local never = vm:run("svctl --json job status 00000000-0000-7000-8000-000000000000")
        t:assert_eq(never.stdout:match('"code":"([^"]+)"'), "UNKNOWN_JOB",
            "as is an identifier that never named a job: " .. never.stdout)
    end)
