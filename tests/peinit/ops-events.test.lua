-- peinit TRM §8.4 — the structured event peinit emits at every job and
-- operation transition, and the audit records that go the same way.
--
-- The subject here is the KMES ring itself, so the instrument is the
-- guest's own probe onto it: `revstrm --snapshot` drains what the ring
-- holds and exits, `--type` takes a glob, and `--pretty` prints the
-- decoded msgpack payload as indented `key   value` rows. The default
-- one-line form caps the payload and elides the rest, which would hide
-- most of what this article is about, so every read below is a pretty
-- one.
--
-- That revstrm can decode a payload at all is itself part of the claim:
-- an event whose body is not msgpack renders as
-- `<N byte(s), undecodable>` rather than as fields, so a snapshot with
-- no such line is a snapshot of well-formed records.
--
-- A snapshot is not a transcript of the boot either. The ring has a
-- consumer, and `--snapshot` prints what is still buffered: the first
-- sequence number in a snapshot is routinely well above 1, so the
-- opening events of Phase 2 — the boot plan's whole block of
-- `operation.requested`, for one — are usually already gone while the
-- rest of the boot is still there. A test that needs a particular kind
-- of event makes one rather than expecting the boot's copy to have
-- survived.
--
-- Two of the article's events cannot be produced from here. `job.status`
-- and `output.dropped` both need a submitted job that speaks the
-- notification protocol or holds an output sink open, and the guest
-- ships no client that can send a datagram to `NOTIFY_SOCKET` as the job
-- it is talking about — peinit verifies the sender against the job's own
-- pidfd, so a helper process cannot stand in for it.

local peinit = require("helpers.peinit")
-- One VM for the file: the subject is one ring, and reading it is what
-- every test does.
peinit.claim(1)

local function definitions()
    return {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
        -- A two-deep chain, started by hand, so that one graph context's
        -- events can be picked out of the ring without the boot's.
        { path = [[Machine\System\Services\pt-leaf]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/sleep" },
            { name = "Arguments", type = "multi", data = { "100000" } },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
            { name = "RestartPolicy", type = "dword", data = 0 },
        } },
        { path = [[Machine\System\Services\pt-mid]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/sleep" },
            { name = "Arguments", type = "multi", data = { "100000" } },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
            { name = "Requires", type = "multi", data = { "pt-leaf" } },
            { name = "RestartPolicy", type = "dword", data = 0 },
        } },
        { path = [[Machine\System\Services\pt-chain]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/sleep" },
            { name = "Arguments", type = "multi", data = { "100000" } },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
            { name = "Requires", type = "multi", data = { "pt-mid" } },
            { name = "RestartPolicy", type = "dword", data = 0 },
        } },
        -- The subject of every test that just needs an administrator's
        -- operation to exist. The chain above is left alone until the
        -- graph test, because that test reads the whole stream for its
        -- members and an earlier start of one of them would be
        -- indistinguishable from the graph's own.
        { path = [[Machine\System\Services\pt-plain]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/sleep" },
            { name = "Arguments", type = "multi", data = { "100000" } },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
            { name = "RestartPolicy", type = "dword", data = 0 },
            { name = "Triggers", type = "multi", data = { "boot" } },
        } },
        -- Never ready, so a start against it is still Running when the
        -- next command arrives and can be superseded.
        { path = [[Machine\System\Services\pt-hangs]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/sleep" },
            { name = "Arguments", type = "multi", data = { "100000" } },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 0 },
            { name = "StartTimeout", type = "dword", data = 200 },
            { name = "RestartPolicy", type = "dword", data = 0 },
        } },
    }
end

--- A service that ignores SIGTERM, so its stop occupies the service for
--- the whole StopTimeout and a start sent after it is queued behind one
--- that will not finish. StartTimeout is four seconds, which is what the
--- queued start then fails at.
---
--- One per test that needs it: a stop that never completes leaves the
--- service unusable, so two tests cannot share a subject.
local function stubborn(name)
    return { path = [[Machine\System\Services\]] .. name, values = {
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi",
          data = { "-c", "trap '' TERM; while :; do sleep 1; done" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "StopTimeout", type = "dword", data = 120 },
        { name = "StartTimeout", type = "dword", data = 4 },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "Triggers", type = "multi", data = { "boot" } },
    } }
end

local function seed()
    local keys = definitions()
    keys[#keys + 1] = stubborn("pt-stub-duration")
    keys[#keys + 1] = stubborn("pt-stub-reason")
    return peinit.seed("pt-ev", keys)
end

local vm = peinit.boot({ name = "opsev", files = seed() })

--- Every event of the given types, oldest first, as
--- `{type, payload, index}` with the payload as revstrm's pretty form.
local function events(globs)
    local flags = ""
    for _, glob in ipairs(globs) do flags = flags .. " --type '" .. glob .. "'" end
    local r = vm:run("revstrm --snapshot --pretty" .. flags, { timeout = 60 })
    r:assert_ok()
    local out, current = {}, nil
    for line in r.stdout:gmatch("[^\r\n]+") do
        local kind = line:match("^%d%d:%d%d:%d%d[%.%d]*%s+cpu.-#%d+%s+%u+%s+([%w_]+%.[%w_]+)%s*$")
        if kind then
            current = { type = kind, payload = "", index = #out + 1, header = line }
            out[#out + 1] = current
        elseif current and line:match("^%s") then
            current.payload = current.payload .. line .. "\n"
        end
    end
    return out, r.stdout
end

local function field(event, name)
    local value = event.payload:match("\n?%s+" .. name .. "%s%s+([^\r\n]*)")
    if not value then return nil end
    return (value:gsub('^"', ""):gsub('"$', ""))
end

--- Whether the payload has a member called `name` at all. A member
--- whose value is a nested map is printed as `name:` on its own line
--- with the map indented beneath, so it has no inline value for `field`
--- to return — `caller` is one, and asking whether it is present is a
--- different question from asking what it says.
local function has_field(event, name)
    return field(event, name) ~= nil
        or event.payload:match("\n?%s+" .. name .. ":%s*\n") ~= nil
end

local function submit(arguments)
    local r = vm:run("svctl --json job submit " .. arguments)
    r:assert_ok()
    local id = r.stdout:match('"id":"([^"]+)"')
    assert(id, "no job identifier in: " .. r.stdout)
    return id, r.stdout
end

local function first_where(list, predicate)
    for _, item in ipairs(list) do
        if predicate(item) then return item end
    end
    return nil
end

test("job and operation transitions arrive in the ring as decodable msgpack records",
    { spec = "peinit *emit.every-job-and-operation-transition-emits-a-kmes-event" },
    function(t)
        -- Every transition, not a sample of them: one boot has already
        -- produced both families, and a submitted job adds a third
        -- job-lifecycle triple. What the snapshot must not contain is a
        -- record revstrm could not decode — the payloads are msgpack per
        -- the KMES event-record format, and a payload that is not would
        -- render as a byte count and a hex preview instead of fields.
        local id = submit("/bin/true")
        vm:run("svctl --json job wait " .. id, { timeout = 60 })
        -- The boot's own `operation.requested` events are emitted in one
        -- block at the very start of Phase 2, and a snapshot taken later
        -- routinely begins after them: the ring has a consumer, and
        -- `--snapshot` shows only what is still buffered. So the census
        -- makes its own — one control command produces the kind the
        -- boot's copy has aged out of, on a service nothing else in this
        -- file touches.
        vm:run("svctl --json restart pt-plain", { timeout = 90 }):assert_ok()

        local all, raw = events({ "job.*", "operation.*" })
        t:assert(#all > 10, "the ring holds this boot's lifecycle events: " .. #all)
        t:assert(not raw:find("undecodable", 1, true),
            "and every one of them decoded as msgpack")

        local kinds = {}
        for _, event in ipairs(all) do kinds[event.type] = true end
        for _, kind in ipairs({ "job.created", "job.started", "job.ended",
                                "operation.requested", "operation.started",
                                "operation.completed" }) do
            t:assert(kinds[kind], kind .. " is in the ring")
        end

        -- The origin column says userspace: these are peinit's own
        -- emissions through `kmes_emit`, not something the kernel
        -- recorded on its behalf.
        t:assert(all[1].header:find("USR", 1, true),
            "emitted by userspace: " .. all[1].header)
    end)

test("peinit's runtime directory holds no event socket",
    { spec = "peinit *emit.there-is-no-event-socket" },
    function(t)
        -- Structured events reach eventd through the ring and nothing
        -- else, so there is no connection for them to travel over. What
        -- peinit does listen on is its two doors and the notification
        -- socket — and a directory listing is the whole proof, because
        -- an event socket would have to be somewhere for eventd to
        -- connect to.
        local listing = vm:run("ls /run/services/peinit")
        listing:assert_ok()
        local known = {
            ["control.sock"] = true, ["jobs.sock"] = true, ["notify.sock"] = true,
        }
        local found = {}
        for name in listing.stdout:gmatch("[^%s]+") do
            found[#found + 1] = name
            t:assert(known[name],
                "peinit listens on nothing beyond its documented sockets, found: "
                .. name .. " (" .. listing.stdout .. ")")
        end
        t:assert(#found >= 2, "the sockets that do exist are there: " .. listing.stdout)
    end)

test("the three job events and what each carries",
    { spec = "peinit *emit.the-three-job-events" },
    function(t)
        -- One job, three events, each carrying what the article says it
        -- does: the object's existence, the exec that succeeded, and the
        -- end with the whole record behind it.
        local id = submit("/bin/sleep 1")
        vm:run("svctl --json job wait " .. id, { timeout = 60 })
        local mine = {}
        for _, event in ipairs(events({ "job.*" })) do
            if field(event, "job_id") == id then mine[event.type] = event end
        end

        local created = mine["job.created"]
        t:assert(created, "the job's creation was emitted")
        for _, name in ipairs({ "job_id", "service", "type", "image_path", "identity",
                                "operation_id" }) do
            t:assert(field(created, name), "job.created carries " .. name
                .. ": " .. created.payload)
        end

        local started = mine["job.started"]
        t:assert(started, "the exec that succeeded was emitted")
        for _, name in ipairs({ "job_id", "pid", "cgroup_id" }) do
            t:assert(field(started, name), "job.started carries " .. name
                .. ": " .. started.payload)
        end
        t:assert(tonumber(field(started, "pid")), "with a real PID: " .. started.payload)

        local ended = mine["job.ended"]
        t:assert(ended, "the end was emitted")
        for _, name in ipairs({ "job_id", "final_state", "exit_code", "exit_signal",
                                "duration_ns", "failure_cause" }) do
            t:assert(field(ended, name), "job.ended carries " .. name
                .. ": " .. ended.payload)
        end
        t:assert_eq(field(ended, "final_state"), "completed",
            "naming the state it ended in: " .. ended.payload)
    end)

test("a submitted job's events carry a null service and a null operation",
    { spec = "peinit *emit.a-submitted-jobs-events-carry-a-null-service-and-operation" },
    function(t)
        -- A submitted job rides the same three events as a service's.
        -- What distinguishes it in the stream is what it does not have:
        -- no service, because nothing defined it, and no operation,
        -- because nothing was requested of a state machine. A service's
        -- job has both, which is what makes the nulls meaningful.
        local id = submit("/bin/true")
        vm:run("svctl --json job wait " .. id, { timeout = 60 })

        local seen = 0
        for _, event in ipairs(events({ "job.*" })) do
            if field(event, "job_id") == id then
                seen = seen + 1
                t:assert_eq(field(event, "type"), "submitted",
                    event.type .. " is typed submitted: " .. event.payload)
                t:assert_eq(field(event, "service"), "nil",
                    event.type .. " has no service: " .. event.payload)
                t:assert_eq(field(event, "operation_id"), "nil",
                    event.type .. " has no operation: " .. event.payload)
            end
        end
        t:assert_eq(seen, 3, "all three of the job's events were found")

        local service_job = first_where(events({ "job.created" }), function(event)
            return field(event, "type") == "service_main"
        end)
        t:assert(service_job, "a service's job is in the ring too")
        t:assert(field(service_job, "service") ~= "nil",
            "and that one names its service: " .. service_job.payload)
    end)

test("a job command refused by the job's descriptor is recorded as job.access_denied",
    {
        spec = {
            "peinit *emit.a-refused-job-command-emits-job-access-denied",
            "peinit *emit.job-list-records-one-denial-per-job-it-omitted",
        },
    },
    function(t)
        -- A job submitted with a descriptor that names nobody the caller
        -- is refuses every command, including the submitter's own. Each
        -- refusal is an event with the caller, the target, the right by
        -- name and both access masks — and `job-list`, which refuses
        -- nothing visibly, records a denial for each job it silently
        -- left out.
        local id = submit("--security-descriptor " ..
            "'O:S-1-5-32-546G:S-1-5-32-546D:(A;;GA;;;S-1-5-32-546)' /bin/sleep 30")

        local before = 0
        for _, event in ipairs(events({ "job.access_denied" })) do
            if field(event, "target") == id then before = before + 1 end
        end

        local denied = vm:run("svctl --json job status " .. id)
        t:assert_eq(denied.stdout:match('"code":"([^"]+)"'), "ACCESS_DENIED",
            "the query was refused: " .. denied.stdout)

        local query = first_where(events({ "job.access_denied" }), function(event)
            return field(event, "target") == id
                and field(event, "requested_right") == "JOB_QUERY"
        end)
        t:assert(query, "and recorded as a denial")
        t:assert_eq(field(query, "caller_sid"), vm:run("token user").stdout:match("S%-[%d%-]+"),
            "naming who asked: " .. query.payload)
        t:assert_eq(field(query, "target_type"), "job",
            "and what they asked about: " .. query.payload)
        t:assert_eq(field(query, "requested_access_bits"), "1",
            "with the bits requested: " .. query.payload)
        t:assert(field(query, "granted_access_bits"),
            "and the bits granted: " .. query.payload)

        -- job-list omits the job rather than failing, and says so in the
        -- ring: one more denial than the listing before it.
        local listed = vm:run("svctl --json job list")
        listed:assert_ok()
        t:assert(not listed.stdout:find(id, 1, true),
            "job-list left the job out: " .. listed.stdout)

        local after = 0
        for _, event in ipairs(events({ "job.access_denied" })) do
            if field(event, "target") == id then after = after + 1 end
        end
        t:assert(after > before + 1,
            "and recorded a denial for the job it omitted (" .. before .. " -> "
            .. after .. ")")
    end)

test("every operation event carries the same five facts, and each kind adds its own",
    {
        spec = {
            "peinit *emit.every-operation-event-carries-the-common-fields",
            "peinit *emit.the-operation-events-and-what-they-add",
        },
    },
    function(t)
        -- The common fields make an operation event self-describing
        -- without a reader having to correlate it with anything. `caller`
        -- is the one that is sometimes null, and it is null exactly when
        -- no client asked: a boot-plan start has none, an administrator's
        -- command has one.
        vm:run("svctl --json restart pt-plain", { timeout = 90 })

        local all = events({ "operation.*" })
        for _, event in ipairs(all) do
            for _, name in ipairs({ "operation_id", "type", "service", "source",
                                    "caller", "state" }) do
                t:assert(has_field(event, name),
                    event.type .. " carries " .. name .. ": " .. event.payload)
            end
        end

        local completed = first_where(all, function(e) return e.type == "operation.completed" end)
        t:assert(completed, "a completed operation is in the ring")
        t:assert(field(completed, "duration_ns"), "operation.completed adds duration_ns")
        t:assert(field(completed, "result"), "and result: " .. completed.payload)

        local requested = first_where(all, function(e) return e.type == "operation.requested" end)
        t:assert(requested, "a requested operation is in the ring")
        t:assert(not field(requested, "duration_ns"),
            "operation.requested adds nothing: " .. requested.payload)
        t:assert(not field(requested, "result"),
            "no result either: " .. requested.payload)

        local admin = first_where(all, function(e) return field(e, "source") == "admin" end)
        t:assert(admin, "an administrator's operation is in the ring")
        t:assert(admin.payload:find("caller:", 1, true),
            "carrying the caller's token summary: " .. admin.payload)
        local boot = first_where(all, function(e) return field(e, "source") == "boot" end)
        t:assert(boot, "and a boot-plan operation")
        t:assert_eq(field(boot, "caller"), "nil",
            "whose caller is null, because nobody asked: " .. boot.payload)
    end)

test("duration_ns counts from creation, so an operation that never ran still has one",
    { spec = "peinit *emit.duration-ns-is-measured-from-creation" },
    function(t)
        -- The sharpest case for "from creation" is an operation that
        -- never executed at all. A start queued behind pt-stubborn's
        -- SIGTERM-proof stop fails at its own four-second StartTimeout
        -- without ever being dispatched: there is no execution to
        -- measure, and yet `operation.failed` carries a duration of
        -- about the four seconds the caller waited.
        vm:run("svctl --no-wait --json stop pt-stub-duration"):assert_ok()
        local queued = vm:run("svctl --no-wait --json start pt-stub-duration")
        queued:assert_ok()
        local id = queued.stdout:match('"operation_id":"([^"]+)"')
        t:assert(id, "the start was queued: " .. queued.stdout)
        t:assert_eq(vm:run("svctl --json operation-status " .. id).stdout
            :match('"state":"([^"]+)"'), "pending",
            "and is Pending behind the stop that will not finish")

        vm:run("sleep 8", { timeout = 30 })

        local mine = {}
        for _, event in ipairs(events({ "operation.*" })) do
            if field(event, "operation_id") == id then mine[event.type] = event end
        end
        t:assert(mine["operation.requested"], "the queued start was requested")
        t:assert(not mine["operation.started"],
            "and never started, so nothing about it was executed")

        local failed = mine["operation.failed"]
        t:assert(failed, "but it failed: " .. tostring(failed and failed.payload))
        local duration = tonumber(field(failed, "duration_ns"))
        t:assert(duration and duration >= 4 * 1000000000,
            "with a duration of at least the four seconds the caller waited: "
            .. tostring(duration))
        t:assert(duration < 60 * 1000000000,
            "and not of the whole stop it was queued behind: " .. tostring(duration))
    end)

test("the reason a lifecycle ended appears under three names across the two surfaces",
    { spec = "peinit *emit.the-failure-reason-appears-under-three-names" },
    function(t)
        -- One string, three field names: `failure_reason` when the
        -- operation failed, `reason` when it was cancelled or aborted,
        -- and `error` in the control interface's view of either. A
        -- reader correlating a ring record with a poll answer has to
        -- know that, which is why it is stated.
        local start = vm:run("svctl --no-wait --json start pt-hangs")
        start:assert_ok()
        local start_id = start.stdout:match('"operation_id":"([^"]+)"')
        vm:run("svctl --no-wait --json stop pt-hangs"):assert_ok()
        vm:run("sleep 2")

        local aborted = first_where(events({ "operation.aborted" }), function(event)
            return field(event, "operation_id") == start_id
        end)
        t:assert(aborted, "the superseded start was aborted")
        local reason = field(aborted, "reason")
        t:assert(reason, "operation.aborted names it `reason`: " .. aborted.payload)
        t:assert(not field(aborted, "failure_reason"),
            "not `failure_reason`: " .. aborted.payload)

        local view = vm:run("svctl --json operation-status " .. start_id)
        view:assert_ok()
        t:assert_eq(view.stdout:match('"error":"([^"]*)"'), reason,
            "and the control view calls the same string `error`: " .. view.stdout)

        -- The failed case, for the third name.
        vm:run("svctl --no-wait --json stop pt-stub-reason")
        local queued = vm:run("svctl --no-wait --json start pt-stub-reason")
        local failed_id = queued.stdout:match('"operation_id":"([^"]+)"')
        vm:run("sleep 8", { timeout = 30 })
        local failed = first_where(events({ "operation.failed" }), function(event)
            return field(event, "operation_id") == failed_id
        end)
        t:assert(failed, "the timed-out start failed")
        t:assert(field(failed, "failure_reason"),
            "operation.failed names it `failure_reason`: " .. failed.payload)
        local failed_view = vm:run("svctl --json operation-status " .. failed_id)
        t:assert_eq(failed_view.stdout:match('"error":"([^"]*)"'),
            field(failed, "failure_reason"),
            "which the control view also calls `error`: " .. failed_view.stdout)
    end)

test("a graph context's operations are all requested before any of them starts",
    {
        spec = {
            "peinit *emit.a-graph-contexts-operations-are-requested-when-the-context-is-built",
            "peinit *emit.a-graph-dispatchs-events-are-emitted-in-causal-order",
        },
    },
    function(t)
        -- A start against a service with unsatisfied dependencies builds
        -- a graph context, and every operation in it is requested there
        -- and then rather than when its turn comes. The observable
        -- consequence is the shape of the stream: the dependencies'
        -- `operation.requested` events all arrive together, and what a
        -- release emits later is `operation.started`.
        vm:run("svctl --json start pt-chain", { timeout = 90 })

        local members = { ["pt-leaf"] = true, ["pt-mid"] = true }
        local stream = events({ "operation.requested", "operation.started",
                                "operation.completed" })
        local last_requested, first_started
        local leaf_completed, mid_started
        for _, event in ipairs(stream) do
            local service = field(event, "service")
            if members[service] then
                if event.type == "operation.requested" then
                    last_requested = event.index
                elseif event.type == "operation.started" then
                    first_started = first_started or event.index
                end
            end
            if service == "pt-leaf" and event.type == "operation.completed" then
                leaf_completed = event.index
            elseif service == "pt-mid" and event.type == "operation.started" then
                mid_started = event.index
            end
        end

        t:assert(last_requested, "the graph's dependency operations were requested")
        t:assert(first_started, "and at least one of them was later started")
        t:assert(last_requested < first_started,
            "every one was requested before any started (" .. last_requested
            .. " < " .. first_started .. ")")

        -- Causal order: the operation whose outcome satisfied the graph
        -- input is reported terminal before the events for what its
        -- dispatch released. A reader replaying the stream in order
        -- never sees an effect before its cause.
        t:assert(leaf_completed and mid_started,
            "the dependency completed and its dependent then started")
        t:assert(leaf_completed < mid_started,
            "and the completion was emitted first (" .. tostring(leaf_completed)
            .. " < " .. tostring(mid_started) .. ")")
    end)

test("peinit's own audit records go into the same ring as the lifecycle events",
    { spec = "peinit *emit.audit-records-go-through-the-same-path" },
    function(t)
        -- The audit records are not a separate stream with separate
        -- guarantees: they are events, in the same ring, with the same
        -- encoding, interleaved with the lifecycle ones by sequence
        -- number. `graph.operation_terminal` is the one every boot
        -- produces, and `job.access_denied` is one a test can provoke —
        -- between them they show an audit record and a lifecycle record
        -- sharing the stream.
        local graph = events({ "graph.operation_terminal" })
        t:assert(#graph > 0, "the boot's graph outcomes are in the ring")
        for _, name in ipairs({ "context_id", "service", "operation_id", "outcome" }) do
            t:assert(field(graph[1], name),
                "graph.operation_terminal carries " .. name .. ": " .. graph[1].payload)
        end

        local mixed = events({ "graph.*", "operation.*", "job.*" })
        local kinds = {}
        for _, event in ipairs(mixed) do kinds[event.type] = true end
        t:assert(kinds["graph.operation_terminal"] and kinds["operation.completed"],
            "an audit record and a lifecycle record came out of one snapshot")
    end)
