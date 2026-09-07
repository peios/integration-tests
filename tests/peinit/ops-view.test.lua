-- peinit TRM §8.6 — what the job and operation model looks like from
-- outside: what a command answers with, when it blocks, and the one
-- shape a submitted job is reported in.
--
-- Everything here is about the answer rather than about the machinery,
-- so `svctl --json` is the whole instrument: it prints the response
-- bytes as peinit sent them, which makes the *shape* of an answer — an
-- acknowledgement naming an operation, a status view naming none, a job
-- view — evidence rather than a re-encoding.
--
-- Timing claims are measured in the guest rather than on the host.
-- `os.clock()` in the harness is CPU time and does not advance while a
-- command blocks, and `os.time()` has one-second resolution against
-- deadlines that are a few seconds apart; bracketing the command with
-- the guest's own `date +%s` measures the thing the claim is about.
--
-- The seeds are shaped around holding an answer open. `Readiness = 0` is
-- notify readiness, so a service whose process never sends `READY=1`
-- keeps its start operation Running until `StartTimeout` — which is how
-- a blocking command is made to block for a known number of seconds.
-- `pt-rel-*` have a reload command that sleeps, for the same reason on
-- the reload path.

local peinit = require("helpers.peinit")
-- One VM for the file: every test here reads an answer, and the seeds
-- give each of them a service of its own to read it about.
peinit.claim(1)

local function never_ready(name, timeout)
    return { path = [[Machine\System\Services\]] .. name, values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "100000" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 0 },
        { name = "StartTimeout", type = "dword", data = timeout },
        { name = "RestartPolicy", type = "dword", data = 0 },
    } }
end

local function reloadable(name)
    return { path = [[Machine\System\Services\]] .. name, values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "100000" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "ExecReload", type = "sz", data = "/bin/sleep 12" },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "Triggers", type = "multi", data = { "boot" } },
    } }
end

local function definitions()
    return {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
        { path = [[Machine\System\Services\pt-plain]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/sleep" },
            { name = "Arguments", type = "multi", data = { "100000" } },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
            { name = "RestartPolicy", type = "dword", data = 0 },
            { name = "Triggers", type = "multi", data = { "boot" } },
        } },
        { path = [[Machine\System\Services\pt-idle]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/true" },
            { name = "Type", type = "dword", data = 1 },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "RestartPolicy", type = "dword", data = 0 },
        } },
        -- A terminal state for a reset to clear.
        { path = [[Machine\System\Services\pt-fails]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/false" },
            { name = "Type", type = "dword", data = 1 },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "RestartPolicy", type = "dword", data = 0 },
            { name = "Triggers", type = "multi", data = { "boot" } },
        } },
        never_ready("pt-blocks", 8),
        never_ready("pt-outlasts", 45),
        never_ready("pt-merges", 200),
        reloadable("pt-rel-a"),
        reloadable("pt-rel-b"),
    }
end

local vm = peinit.boot({ name = "opsview", files = peinit.seed("pt-view", definitions()) })

--- Run `command` in the guest and return its stdout and how many
--- seconds it took, measured by the guest's own clock.
local function timed(command, seconds)
    local r = vm:run("s=$(date +%s); " .. command ..
        " > /tmp/pt-timed.out 2>/tmp/pt-timed.err; e=$(date +%s); echo $((e-s))",
        { timeout = seconds or 180 })
    return {
        elapsed = tonumber(r.stdout:match("(%d+)%s*$")),
        stdout = tostring(vm:read_file("/tmp/pt-timed.out")),
        stderr = tostring(vm:read_file("/tmp/pt-timed.err")),
    }
end

local function send(command, no_wait)
    local run = vm:run("svctl " .. (no_wait and "--no-wait --json " or "--json ") .. command,
        { timeout = 180 })
    return {
        raw = run.stdout .. " / " .. tostring(run.stderr),
        stdout = run.stdout,
        operation = run.stdout:match('"operation_id":"([^"]+)"'),
        state = run.stdout:match('"state":"([^"]+)"'),
        code = run.stdout:match('"code":"([^"]+)"'),
    }
end

local function operation(id)
    local run = vm:run("svctl --json operation-status " .. tostring(id))
    local out = { raw = run.stdout }
    for name, value in run.stdout:gmatch('"([%w_]+)":"([^"]*)"') do out[name] = value end
    for _, name in ipairs({ "result", "error", "merged_into", "started_at" }) do
        if run.stdout:find('"' .. name .. '":null', 1, true) then out[name] = false end
    end
    return out
end

local function settle(id, seconds)
    for _ = 1, seconds or 40 do
        local view = operation(id)
        if view.state ~= "pending" and view.state ~= "running" then return view end
        vm:run("sleep 1")
    end
    return operation(id)
end

local function submit(arguments)
    local r = vm:run("svctl --json job submit " .. arguments, { timeout = 120 })
    r:assert_ok()
    local id = r.stdout:match('"id":"([^"]+)"')
    assert(id, "no job identifier in: " .. r.stdout)
    return id, r.stdout
end

--- Pretty-printed KMES events of the given types, oldest first. Only
--- one claim here needs the ring: a merged operation's identifier is
--- deliberately not given to the caller who merged, so the only way to
--- ask peinit about that record is to read the identifier out of the
--- `operation.merged` event.
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

local function event_field(event, name)
    local value = event.payload:match("\n?%s+" .. name .. "%s%s+([^\r\n]*)")
    if not value then return nil end
    return (value:gsub('^"', ""):gsub('"$', ""))
end

--- The member names of a flat JSON object, ignoring nested ones.
local function members(json)
    local names = {}
    for name in json:gmatch('"([%w_]+)":') do names[name] = true end
    return names
end

test("a command that does something names the operation; one that does not returns the status",
    {
        spec = {
            "peinit *protoview.every-lifecycle-command-returns-an-identifier",
            "peinit *protoview.a-command-with-nothing-to-do-returns-the-status-instead",
        },
    },
    function(t)
        -- The shape of the answer is the difference. A command that
        -- created, queued or executed an operation acknowledges with
        -- that operation's identifier, which the caller can then poll. A
        -- command with nothing to do has no identifier to give, so it
        -- answers with the service's status instead — an honest "here is
        -- where things stand" rather than an acknowledgement of work
        -- that does not exist.
        -- Already comes first, while pt-plain is still the Active
        -- service the boot left: the service is where the command would
        -- take it, so there is nothing to do and nothing to name.
        local already = send("start pt-plain")
        t:assert(not already.code, "starting an Active service is not an error: "
            .. already.raw)
        t:assert(not already.operation,
            "and names no operation: " .. already.raw)
        t:assert(already.stdout:find('"service":"pt-plain"', 1, true),
            "because what came back is the service's status: " .. already.raw)

        -- Each of the five verbs, on a service where it has work to do.
        for _, command in ipairs({ "start pt-idle", "restart pt-idle", "reset pt-fails",
                                   "stop pt-plain" }) do
            local answer = send(command)
            t:assert(answer.operation,
                command .. " named the operation it created: " .. answer.raw)
        end
        send("start pt-plain")

        -- Noop: the command has no effect at all. pt-idle is a Oneshot
        -- that does not remain after exit, so it is Inactive again by
        -- now and a stop has nothing to stop.
        local noop = send("stop pt-idle")
        t:assert(not noop.code, "stopping an Inactive service is not an error: " .. noop.raw)
        t:assert(not noop.operation, "and names no operation: " .. noop.raw)
        t:assert(noop.stdout:find('"current_job":', 1, true),
            "the answer is a status view: " .. noop.raw)
    end)

test("the job commands answer with a job view and never an operation",
    { spec = "peinit *protoview.the-job-commands-never-create-an-operation" },
    function(t)
        -- A submitted job has no state machine to contend for, so there
        -- is nothing for an operation to serialise: `job-stop` acts on
        -- the job directly. All three job commands therefore answer in
        -- the job's own shape and none of them names an operation.
        local id = submit("/bin/sleep 60")

        local queried = vm:run("svctl --json job status " .. id)
        queried:assert_ok()
        t:assert(not queried.stdout:find("operation", 1, true),
            "job status names no operation: " .. queried.stdout)
        t:assert(queried.stdout:find('"type":"submitted"', 1, true),
            "and answers in the job view: " .. queried.stdout)

        local listed = vm:run("svctl --json job list")
        listed:assert_ok()
        t:assert(not listed.stdout:find("operation", 1, true),
            "job list names no operation: " .. listed.stdout)

        local stopped = vm:run("svctl --json job stop " .. id, { timeout = 90 })
        stopped:assert_ok()
        t:assert(not stopped.stdout:find("operation", 1, true),
            "job stop names no operation either: " .. stopped.stdout)
        t:assert(stopped.stdout:find('"type":"submitted"', 1, true),
            "it answers with the job it acted on: " .. stopped.stdout)
    end)

test("a lifecycle command blocks until its operation is terminal, and reload does not",
    {
        spec = {
            "peinit *protoview.lifecycle-commands-block-until-the-operation-is-terminal",
            "peinit *protoview.reload-returns-immediately-unless-asked-otherwise",
        },
    },
    function(t)
        -- pt-blocks never becomes ready, so its start runs for the whole
        -- eight-second StartTimeout and then fails. A caller that
        -- blocked is one that was still waiting eight seconds later and
        -- was then told the outcome — not one that was acknowledged and
        -- left to poll.
        local blocked = timed("svctl --json start pt-blocks", 120)
        t:assert(blocked.elapsed and blocked.elapsed >= 7,
            "the start blocked for its operation's whole lifetime: "
            .. tostring(blocked.elapsed) .. "s")
        t:assert(blocked.stdout:find("OPERATION_TIMEOUT", 1, true)
            or blocked.stdout:find('"state"', 1, true),
            "and was answered with the outcome: " .. blocked.stdout)

        -- Reload is the exception: the caller gets the identifier at
        -- once and can poll it, because a reload's outcome is often
        -- advisory. The reload command sleeps twelve seconds, so a
        -- command that returned in under three did not wait for it.
        local quick = timed("svctl --json reload pt-rel-a", 120)
        t:assert(quick.elapsed and quick.elapsed < 4,
            "reload returned without waiting: " .. tostring(quick.elapsed) .. "s")
        local id = quick.stdout:match('"operation_id":"([^"]+)"')
        t:assert(id, "with the identifier to poll: " .. quick.stdout)
        t:assert_eq(operation(id).state, "running",
            "for an operation that is still going")

        -- Asked otherwise, it waits like the rest.
        local waited = timed("svctl --wait --json reload pt-rel-b", 120)
        t:assert(waited.elapsed and waited.elapsed >= 10,
            "--wait made the same command block: " .. tostring(waited.elapsed) .. "s")
    end)

test("a connection with an operation outstanding is not closed by the idle timeout",
    { spec = "peinit *protoview.a-waiting-connection-is-never-closed-by-the-idle-timeout" },
    function(t)
        -- The control socket's idle timeout is thirty seconds. A
        -- connection waiting on an operation is not idle, so a caller
        -- blocked on a start that takes forty-five seconds is still
        -- there to be answered — the wait is bounded by the operation's
        -- lifetime and by nothing else.
        local blocked = timed("svctl --json start pt-outlasts", 180)
        t:assert(blocked.elapsed and blocked.elapsed > 30,
            "the caller was held past the thirty-second deadline: "
            .. tostring(blocked.elapsed) .. "s")
        t:assert(not blocked.stderr:find("reset by peer", 1, true),
            "the connection was not reset under it: " .. blocked.stderr)
        t:assert(not blocked.stderr:find("connect ", 1, true),
            "nor dropped: " .. blocked.stderr)
        t:assert(#blocked.stdout > 0,
            "and it was answered: " .. blocked.stdout .. " / " .. blocked.stderr)
    end)

test("a merged caller gets an identifier older than its own request",
    {
        spec = {
            "peinit *protoview.a-merged-caller-blocks-on-the-surviving-operations-outcome",
            "peinit *protoview.a-merged-callers-identifier-is-older-than-their-request",
        },
    },
    function(t)
        -- Nothing tells the second caller it merged. What it can see, if
        -- it looks, is that the operation it was given was requested
        -- before it sent its command — which is right, because that is
        -- when the work it is now waiting on began. ISO-8601 UTC
        -- timestamps of fixed width compare as strings, so "earlier
        -- than" is a comparison rather than a parse.
        local first = send("start pt-merges", true)
        t:assert(first.operation, "a start is in flight: " .. first.raw)

        vm:run("sleep 3")
        local before = vm:run("date -u +%Y-%m-%dT%H:%M:%S").stdout:match("[%d%-T:]+")
        t:assert(before, "the guest's clock was read before the second command")

        local second = send("start pt-merges", true)
        t:assert_eq(second.operation, first.operation,
            "the second caller was given the surviving operation: " .. second.raw)

        local view = operation(second.operation)
        local requested = view.requested_at:sub(1, 19)
        t:assert(requested < before,
            "whose request predates the command that was given it: "
            .. requested .. " < " .. before)

        -- And it is the surviving operation's outcome the second caller
        -- is now attached to: one operation, one result, for both.
        t:assert_eq(view.state, "running", "which is still running: " .. view.raw)
        t:assert_eq(view.service, "pt-merges", "against the service both asked about")
    end)

test("what a terminal operation's answer carries",
    { spec = "peinit *protoview.what-an-operations-result-carries" },
    function(t)
        -- Four terminal shapes, four different things to say. A
        -- completed stop carries the state the service ended in; a
        -- failure carries the reason; an aborted operation carries why
        -- it was abandoned; and a merged one carries the identifier of
        -- the operation that survived instead of it.
        send("start pt-plain")
        local stopped = settle(send("stop pt-plain", true).operation)
        t:assert_eq(stopped.state, "completed", "the stop completed: " .. stopped.raw)
        t:assert_eq(stopped.result, "inactive",
            "carrying the state the service ended in: " .. stopped.raw)
        t:assert_eq(stopped.error, false, "and no error: " .. stopped.raw)

        local failed = settle(send("start pt-blocks", true).operation, 20)
        t:assert_eq(failed.state, "failed", "the start failed: " .. failed.raw)
        t:assert(failed.error and #failed.error > 0,
            "carrying the failure reason: " .. failed.raw)
        t:assert_eq(failed.result, false, "and no result: " .. failed.raw)

        local start = send("start pt-outlasts", true)
        send("stop pt-outlasts", true)
        local aborted = settle(start.operation, 20)
        t:assert_eq(aborted.state, "aborted", "the superseded start was aborted: "
            .. aborted.raw)
        t:assert(aborted.error and #aborted.error > 0,
            "carrying why: " .. aborted.raw)

        -- Merged: the record is stored under an identifier the merging
        -- caller is not given, so it is found in the ring and then asked
        -- about by that identifier.
        local merged_id
        for _, event in ipairs(events({ "operation.merged" })) do
            if event_field(event, "service") == "pt-merges" then
                merged_id = event_field(event, "operation_id")
            end
        end
        t:assert(merged_id, "a merge was recorded for pt-merges")
        local merged = operation(merged_id)
        t:assert_eq(merged.state, "merged", "that operation is Merged: " .. merged.raw)
        t:assert(merged.merged_into and #merged.merged_into > 0,
            "carrying the identifier of the one that survived: " .. merged.raw)
    end)

test("a reload's answer says which mode the reload resolved in",
    { spec = "peinit *protoview.a-reloads-result-determines-its-mode" },
    function(t)
        -- A reload can be confirmed by the service, assumed by peinit,
        -- or failed, and the difference matters to a caller: "the
        -- configuration is live" and "peinit ran the command and nobody
        -- said otherwise" are not the same claim. pt-rel-a has no
        -- readiness protocol, so peinit can only assume — the mode is
        -- `advisory`.
        local answer = vm:run("svctl --wait --json reload pt-rel-a", { timeout = 120 })
        answer:assert_ok()
        t:assert_eq(answer.stdout:match('"mode":"([^"]+)"'), "advisory",
            "a reload nobody confirmed is advisory: " .. answer.stdout)
        t:assert(answer.stdout:match('"operation_id":"([^"]+)"'),
            "and the answer still names the operation: " .. answer.stdout)
    end)

test("the job view is one shape, with every inapplicable field present and null",
    {
        spec = {
            "peinit *protoview.the-job-view-and-its-fields",
            "peinit *protoview.every-inapplicable-field-is-present-and-null",
        },
    },
    function(t)
        -- The view is a fixed shape rather than a set of fields that
        -- come and go: a reader can index every member of it without
        -- checking whether this particular job has one. A running job
        -- with no readiness protocol therefore reports `ready: null`
        -- rather than omitting it, and once the job is over `pid` is
        -- null too, because there is no process left to name.
        local id, running = submit("/bin/sleep 30")
        local names = members(running)
        for _, name in ipairs({ "id", "type", "state", "cause", "submitter", "identity",
                                "logon_session", "description", "image_path", "pid",
                                "ready", "exit_code", "exit_signal", "status_text",
                                "progress", "created_at", "started_at", "ended_at" }) do
            t:assert(names[name], "the view carries " .. name .. ": " .. running)
        end
        t:assert(running:find('"type":"submitted"', 1, true),
            "typed submitted: " .. running)

        for _, name in ipairs({ "cause", "ready", "exit_code", "exit_signal",
                                "status_text", "progress", "ended_at" }) do
            t:assert(running:find('"' .. name .. '":null', 1, true),
                name .. " is present and null while the job runs: " .. running)
        end
        t:assert(running:match('"pid":(%d+)'), "and pid is a process: " .. running)

        vm:run("svctl --json job stop " .. id, { timeout = 90 }):assert_ok()
        local ended = vm:run("svctl --json job status " .. id)
        ended:assert_ok()
        t:assert(ended.stdout:find('"pid":null', 1, true),
            "pid is null once the job is terminal: " .. ended.stdout)
        t:assert(ended.stdout:find('"ended_at":"', 1, true),
            "while ended_at is now a time: " .. ended.stdout)
    end)

test("a submitter and an administrator see the same job view on their different sockets",
    { spec = "peinit *protoview.the-job-view-is-one-shape-on-both-sockets" },
    function(t)
        -- `wait` is answered on the jobs socket and `job-status` on the
        -- control socket, and what comes back is the same record in the
        -- same shape — the same member names, and the same values for
        -- the fields that do not move between the two reads.
        local id = submit("/bin/sleep 2")
        local waited = vm:run("svctl --json job wait " .. id, { timeout = 90 })
        waited:assert_ok()
        local queried = vm:run("svctl --json job status " .. id)
        queried:assert_ok()

        local from_jobs, from_control = members(waited.stdout), members(queried.stdout)
        for name in pairs(from_jobs) do
            t:assert(from_control[name],
                name .. " is in both views: " .. waited.stdout .. " / " .. queried.stdout)
        end
        for name in pairs(from_control) do
            t:assert(from_jobs[name],
                name .. " is in both views: " .. waited.stdout .. " / " .. queried.stdout)
        end

        for _, name in ipairs({ "id", "type", "state", "submitter", "identity",
                                "image_path" }) do
            t:assert_eq(waited.stdout:match('"' .. name .. '":"([^"]*)"'),
                queried.stdout:match('"' .. name .. '":"([^"]*)"'),
                name .. " agrees across the two sockets")
        end

        -- The timestamps are the same instant, projected onto the wall
        -- clock at the moment each answer was built: peinit holds them
        -- as monotonic nanoseconds and converts on the way out, so the
        -- last few digits differ between two reads of one record.
        -- Milliseconds is finer than anything that distinguishes two
        -- jobs and coarser than the projection's drift.
        for _, name in ipairs({ "created_at", "ended_at" }) do
            local from_jobs_at = waited.stdout:match('"' .. name .. '":"([^"]*)"')
            local from_control_at = queried.stdout:match('"' .. name .. '":"([^"]*)"')
            t:assert(from_jobs_at and from_control_at, name .. " is a time in both views")
            t:assert_eq(from_jobs_at:sub(1, 23), from_control_at:sub(1, 23),
                name .. " is the same instant on both sockets: "
                .. from_jobs_at .. " / " .. from_control_at)
        end
    end)

test("job-list shows only the jobs the caller may query",
    { spec = "peinit *protoview.job-list-is-filtered-by-job-query" },
    function(t)
        -- The list is the same views, per job, with `JOB_QUERY` checked
        -- on each. A job whose descriptor names nobody the caller is
        -- therefore does not appear — and it is not an error, because a
        -- list of what you may see is a complete answer to what was
        -- asked.
        local visible = submit("/bin/sleep 60")
        local hidden = submit("--security-descriptor " ..
            "'O:S-1-5-32-546G:S-1-5-32-546D:(A;;GA;;;S-1-5-32-546)' /bin/sleep 60")

        local listed = vm:run("svctl --json job list")
        listed:assert_ok()
        t:assert(listed.stdout:find(visible, 1, true),
            "a job the caller may query is listed: " .. listed.stdout)
        t:assert(not listed.stdout:find(hidden, 1, true),
            "one it may not is left out: " .. listed.stdout)
        t:assert(not listed.stdout:find('"code"', 1, true),
            "and the listing itself is not an error: " .. listed.stdout)

        vm:run("svctl --json job stop " .. visible, { timeout = 60 })
    end)
