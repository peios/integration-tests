-- peinit TRM §8.4 — the structured event peinit emits at every job and
-- operation transition, and the audit records that go the same way.
--
-- The subject here is the KMES ring itself, so the instrument is the
-- guest's own probe onto it: `revstrm --snapshot` drains what the ring
-- holds and exits, `--type` takes a glob, and `--pretty` prints the
-- decoded msgpack payload, a nested map, as indented `key   value` rows
-- with each nested map's key on a line of its own. helpers/revstrm reads
-- that back into dotted catalogue paths (`object.job.guid`). The default
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
-- `peinit.operation.requested`, for one — are usually already gone while
-- the rest of the boot is still there. A test that needs a particular
-- kind of event makes one rather than expecting the boot's copy to have
-- survived.
--
-- The emission policy (PGSS §6.9) decides which of peinit's events are
-- written at all, and with nothing set a `verbose` type is off. This
-- file's seed switches every `peinit.*` type on, because several tests
-- read verbose ones (`peinit.job.created`, `peinit.operation.started`,
-- `peinit.graph.operation.ended`); the policy test takes the switch away
-- and puts it back.
--
-- Two of the article's events cannot be produced from here.
-- `peinit.job.status.reported` and `peinit.job.output.dropped` both need a
-- submitted job that speaks the notification protocol or holds an output
-- sink open, and the guest ships no client that can send a datagram to
-- `NOTIFY_SOCKET` as the job it is talking about — peinit verifies the
-- sender against the job's own pidfd, so a helper process cannot stand
-- in for it.

local peinit = require("helpers.peinit")
local revstrm = require("helpers.revstrm")
local eventd = require("helpers.eventd")
-- One VM for the file: the subject is one ring, and reading it is what
-- every test does.
peinit.claim(1)

local POLICY_KEY = [[Machine\Generic\Events\peinit]]

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
    for _, key in ipairs(peinit.verbose_events_keys()) do keys[#keys + 1] = key end
    return peinit.seed("pt-ev", keys)
end

local vm = peinit.boot({ name = "opsev", files = seed() })

--- Every event of the given types, oldest first (see helpers/revstrm).
local function events(globs)
    return revstrm.snapshot(vm, globs)
end

local field = revstrm.field
local has = revstrm.has

--- The leading nanosecond count of a `uint.duration`, which revstrm
--- prints as `N ns (…)` — `4000000000ns (4s)`.
local function nanoseconds(text)
    return text and tonumber(text:match("^(%d+)ns"))
end

local function submit(arguments)
    local r = vm:run("svctl --json job submit " .. arguments)
    r:assert_ok()
    local id = r.stdout:match('"id":"([^"]+)"')
    assert(id, "no job identifier in: " .. r.stdout)
    return id, r.stdout
end

--- Whether `event` is about the job `id`: its `object.job.guid`, a
--- `bin.guid`, read back as the text svctl printed.
local function about_job(event, id)
    return revstrm.guid(field(event, "object.job.guid")) == id:lower()
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
        -- The boot's own `peinit.operation.requested` events are emitted
        -- in one block at the very start of Phase 2, and a snapshot taken
        -- later routinely begins after them: the ring has a consumer, and
        -- `--snapshot` shows only what is still buffered. So the census
        -- makes its own — one control command produces the kind the
        -- boot's copy has aged out of, on a service nothing else in this
        -- file touches.
        vm:run("svctl --json restart pt-plain", { timeout = 90 }):assert_ok()

        local all, raw = events({ "peinit.job.*", "peinit.operation.*" })
        t:assert(#all > 10, "the ring holds this boot's lifecycle events: " .. #all)
        t:assert(not raw:find("undecodable", 1, true),
            "and every one of them decoded as msgpack")

        local kinds = {}
        for _, event in ipairs(all) do kinds[event.type] = true end
        for _, kind in ipairs({ "peinit.job.created", "peinit.job.started",
                                "peinit.job.ended", "peinit.operation.requested",
                                "peinit.operation.started", "peinit.operation.ended" }) do
            t:assert(kinds[kind], kind .. " is in the ring")
        end

        -- The origin column says userspace: these are peinit's own
        -- emissions through `kmes_emit`, not something the kernel
        -- recorded on its behalf.
        t:assert(all[1].header:find("USR", 1, true),
            "emitted by userspace: " .. all[1].header)
    end)

test("every event is a peinit.* catalogue type whose payload is a nested map",
    { spec = "peinit *emit.every-event-is-a-catalogue-type-with-a-nested-payload" },
    function(t)
        -- Each type is one peinit.evman names, and each payload is a map
        -- of maps under the catalogue's paths: the job under
        -- `object.job`, its outcome under `outcome`. A value peinit does
        -- not have is a key it does not write, never a nil.
        local id = submit("/bin/true")
        vm:run("svctl --json job wait " .. id, { timeout = 60 })

        local all, raw = events({ "peinit.*" })
        t:assert(#all > 0, "peinit's events are in the ring")
        for _, event in ipairs(all) do
            t:assert(event.type:match("^peinit%.[a-z][a-z0-9%-]*%.[a-z0-9%.%-]+$"),
                "a peinit.* type in kebab-case segments: " .. event.type)
        end
        t:assert(not raw:find("%s+nil\n"), "and no value anywhere is nil:\n" .. raw)

        local ended = first_where(all, function(event)
            return event.type == "peinit.job.ended" and about_job(event, id)
        end)
        t:assert(ended, "the job's end is in the ring")
        t:assert(has(ended, "object") and has(ended, "object.job"),
            "its payload nests the job under object.job: " .. ended.payload)
        t:assert_eq(field(ended, "object.job.type"), "submitted",
            "named by the catalogue's path: " .. ended.payload)
        t:assert_eq(field(ended, "outcome.success"), "true",
            "its outcome under outcome: " .. ended.payload)
        for _, flat in ipairs({ "job_id", "final_state", "token_summary", "image_path" }) do
            t:assert(not has(ended, flat),
                "the old flat key " .. flat .. " is gone: " .. ended.payload)
        end
    end)

test("peinit asks the emission policy before it builds an event",
    { spec = "peinit *emit.peinit-asks-the-emission-policy-before-building-an-event" },
    function(t)
        -- `peinit.job.created` is verbose: off unless the policy turns it
        -- on. The seed turned every peinit type on; take the switch away
        -- and a new job has its start but no creation, put it back and
        -- the next has both. `peinit.job.started` is standard and never
        -- moves. A changed key applies within a second (PGSS §6.9).
        vm:run("reg del '" .. POLICY_KEY .. "' Enabled"):assert_ok()
        vm:run("sleep 3")
        local off = submit("/bin/true")
        vm:run("svctl --json job wait " .. off, { timeout = 60 })

        vm:run("reg set '" .. POLICY_KEY .. "' Enabled dword:1"):assert_ok()
        vm:run("sleep 3")
        local on = submit("/bin/true")
        vm:run("svctl --json job wait " .. on, { timeout = 60 })

        local kinds = { [off] = {}, [on] = {} }
        for _, event in ipairs(events({ "peinit.job.*" })) do
            for id, seen in pairs(kinds) do
                if about_job(event, id) then seen[event.type] = true end
            end
        end
        t:assert(kinds[off]["peinit.job.started"] and kinds[off]["peinit.job.ended"],
            "with the policy unset the standard job events are written")
        t:assert(not kinds[off]["peinit.job.created"],
            "and the verbose peinit.job.created is not")
        t:assert(kinds[on]["peinit.job.created"],
            "with peinit switched on, peinit.job.created is written again")
        t:assert(kinds[on]["peinit.job.started"] and kinds[on]["peinit.job.ended"],
            "beside the standard ones")
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
        for _, event in ipairs(events({ "peinit.job.*" })) do
            if about_job(event, id) then mine[event.type] = event end
        end

        local created = mine["peinit.job.created"]
        t:assert(created, "the job's creation was emitted")
        for _, path in ipairs({ "object.job.guid", "object.job.type", "object.job.state",
                                "object.job.executable", "object.job.token.sid" }) do
            t:assert(field(created, path), "peinit.job.created carries " .. path
                .. ": " .. created.payload)
        end
        t:assert_eq(field(created, "object.job.state"), "created",
            "in the created state: " .. created.payload)

        local started = mine["peinit.job.started"]
        t:assert(started, "the exec that succeeded was emitted")
        for _, path in ipairs({ "object.job.guid", "object.process.pid",
                                "object.cgroup.path" }) do
            t:assert(field(started, path), "peinit.job.started carries " .. path
                .. ": " .. started.payload)
        end
        t:assert(tonumber(field(started, "object.process.pid")),
            "with a real PID: " .. started.payload)

        local ended = mine["peinit.job.ended"]
        t:assert(ended, "the end was emitted")
        for _, path in ipairs({ "object.job.guid", "object.job.state", "outcome.success",
                                "object.process.exit-code", "object.job.duration",
                                "object.job.created-time", "object.job.started-time" }) do
            t:assert(field(ended, path), "peinit.job.ended carries " .. path
                .. ": " .. ended.payload)
        end
        t:assert_eq(field(ended, "object.job.state"), "completed",
            "naming the state it ended in: " .. ended.payload)
        t:assert_eq(field(ended, "outcome.success"), "true",
            "and that it succeeded: " .. ended.payload)
        t:assert(not has(ended, "outcome.detail"),
            "with no failure detail, because it did not fail: " .. ended.payload)
        t:assert(not has(ended, "object.process.exit-signal"),
            "and no signal, because none ended it: " .. ended.payload)
    end)

test("a submitted job's events carry no service and no operation",
    { spec = "peinit *emit.a-submitted-jobs-events-carry-no-service-and-no-operation" },
    function(t)
        -- A submitted job rides the same three events as a service's.
        -- What distinguishes it in the stream is what it does not have:
        -- no service, because nothing defined it, and no operation,
        -- because nothing was requested of a state machine. A service's
        -- job has both, which is what makes their absence meaningful.
        local id = submit("/bin/true")
        vm:run("svctl --json job wait " .. id, { timeout = 60 })

        local seen = 0
        for _, event in ipairs(events({ "peinit.job.*" })) do
            if about_job(event, id) then
                seen = seen + 1
                t:assert_eq(field(event, "object.job.type"), "submitted",
                    event.type .. " is typed submitted: " .. event.payload)
                t:assert(not has(event, "object.service"),
                    event.type .. " has no service: " .. event.payload)
                t:assert(not has(event, "object.operation"),
                    event.type .. " has no operation: " .. event.payload)
                t:assert(not has(event, "object.job.activation-generation"),
                    event.type .. " has no service's generation: " .. event.payload)
            end
        end
        t:assert_eq(seen, 3, "all three of the job's events were found")

        local service_job = first_where(events({ "peinit.job.created" }), function(event)
            return field(event, "object.job.type") == "service-main"
        end)
        t:assert(service_job, "a service's job is in the ring too")
        t:assert(field(service_job, "object.service.name"),
            "and that one names its service: " .. service_job.payload)
    end)

--- The hex of a binary value in an eventd row: evctl writes one as
--- `{"$binary": "<hex>"}`.
local function row_hex(value)
    if type(value) == "table" then value = value["$binary"] end
    return type(value) == "string" and value:lower() or nil
end

--- A GUID's canonical text as the hex of its PCDS binary form, the bytes
--- a `bin.guid` field carries: the first three fields byte-reversed, the
--- last eight bytes as they are.
local function pcds_hex(uuid)
    local h = uuid:lower():gsub("[{}%-]", "")
    local function rev(s)
        local out = ""
        for i = #s - 1, 1, -2 do out = out .. s:sub(i, i + 1) end
        return out
    end
    return rev(h:sub(1, 8)) .. rev(h:sub(9, 12)) .. rev(h:sub(13, 16)) .. h:sub(17)
end

--- A SID's SDDL text as the hex of its binary form, as a `bin.sid` field
--- carries it: revision, sub-authority count, the 48-bit authority big-
--- endian, each sub-authority as 32 bits little-endian.
local function sid_hex(sddl)
    local parts = {}
    for n in sddl:gmatch("%d+") do parts[#parts + 1] = tonumber(n) end
    -- parts: revision, authority, sub-authorities…
    local out = string.format("%02x%02x", parts[1], #parts - 2)
    out = out .. string.format("%012x", parts[2])
    for i = 3, #parts do
        local v = parts[i]
        out = out .. string.format("%02x%02x%02x%02x", v & 0xff, (v >> 8) & 0xff,
            (v >> 16) & 0xff, (v >> 24) & 0xff)
    end
    return out
end

--- Whether an eventd row's `object.job.guid` is the job `id`.
local function row_names_job(row, id)
    return row_hex(row["object.job.guid"]) == pcds_hex(id)
end

--- `kacs.audit.access.checked` records for the job `id`, from eventd.
local function job_audits(id)
    local rows = eventd.rows(vm, 'EVENTS kacs.audit.access.checked WHERE object.kind == "job" '
        .. "SINCE 1h ago TAKE 1000")
    local mine = {}
    for _, row in ipairs(rows) do
        if row_names_job(row, id) then mine[#mine + 1] = row end
    end
    return mine
end

test("a job command refused by the job's descriptor is recorded by KACS, not by peinit",
    {
        spec = {
            "peinit *emit.a-refused-command-is-recorded-by-kacs",
            "peinit *emit.every-access-check-names-its-object-in-an-audit-context",
        },
    },
    function(t)
        -- A job submitted with a descriptor that names nobody the caller
        -- is refuses every command, including the submitter's own. peinit
        -- writes no event of its own about it: the decision is KACS's,
        -- recorded as `kacs.audit.access.checked` because the
        -- descriptor's SACL asks for every refusal, and peinit's check
        -- named the job in its audit context so the record says which.
        -- `job-list`, which refuses nothing visibly, checks each job it
        -- lists, and its refusals are recorded the same way.
        local id = submit("--security-descriptor " ..
            "'O:S-1-5-32-546G:S-1-5-32-546D:(A;;GA;;;S-1-5-32-546)S:(AU;FA;0x7;;;WD)' "
            .. "/bin/sleep 30")
        eventd.ready(vm)
        local before = #job_audits(id)

        local denied = vm:run("svctl --json job status " .. id)
        t:assert_eq(denied.stdout:match('"code":"([^"]+)"'), "ACCESS_DENIED",
            "the query was refused: " .. denied.stdout)

        local rows = eventd.wait_rows(vm,
            'EVENTS kacs.audit.access.checked WHERE object.kind == "job" SINCE 1h ago TAKE 1000',
            function(rs)
                for _, row in ipairs(rs) do
                    if row_names_job(row, id) and row["access.requested"] == 1 then
                        return true
                    end
                end
                return false
            end, { timeout = 30, desc = "the refused JOB_QUERY's record" })
        local query = nil
        for _, row in ipairs(rows) do
            if row_names_job(row, id) and row["access.requested"] == 1 then query = row end
        end
        t:assert(query, "the refusal was recorded")
        t:assert_eq(query["object.kind"], "job", "against a job")
        t:assert_eq(query["fields.attestation.userspace"], true,
            "which peinit asserted, not KACS")
        local caller = vm:run("token user").stdout:match("S%-[%d%-]+")
        t:assert_eq(row_hex(query["subject.token.sid"]), sid_hex(caller),
            "naming who asked, " .. tostring(caller))
        t:assert(query["access.granted"] ~= nil, "and what they were granted")

        local own = events({ "access.denied", "job.access_denied", "peinit.*denied*" })
        t:assert_eq(#own, 0, "peinit wrote no denial event of its own")

        -- job-list omits the job rather than failing, and its check of the
        -- job is recorded too: one more record than before it.
        local listed = vm:run("svctl --json job list")
        listed:assert_ok()
        t:assert(not listed.stdout:find(id, 1, true),
            "job-list left the job out: " .. listed.stdout)
        local after = #job_audits(id)
        for _ = 1, 20 do
            if after > before + 1 then break end
            vm:run("sleep 1")
            after = #job_audits(id)
        end
        t:assert(after > before + 1,
            "and the check of the job it omitted was recorded (" .. before .. " -> "
            .. after .. ")")
    end)

test("every operation event carries the same facts, and each kind adds its own",
    {
        spec = {
            "peinit *emit.every-operation-event-carries-the-common-fields",
            "peinit *emit.the-operation-events-and-what-they-add",
        },
    },
    function(t)
        -- The common fields make an operation event self-describing
        -- without a reader having to correlate it with anything. The
        -- subject is the one that is sometimes absent, and it is absent
        -- exactly when no client asked: a boot-plan start has none, an
        -- administrator's command names who sent it.
        vm:run("svctl --json restart pt-plain", { timeout = 90 })

        local all = events({ "peinit.operation.*" })
        for _, event in ipairs(all) do
            for _, path in ipairs({ "object.operation.guid", "object.operation.type",
                                    "object.service.name", "object.operation.source",
                                    "object.operation.state" }) do
                t:assert(field(event, path),
                    event.type .. " carries " .. path .. ": " .. event.payload)
            end
        end

        local completed = first_where(all, function(e)
            return e.type == "peinit.operation.ended"
                and field(e, "object.operation.state") == "completed"
        end)
        t:assert(completed, "a completed operation is in the ring")
        t:assert(field(completed, "object.operation.duration"),
            "peinit.operation.ended adds its duration: " .. completed.payload)
        t:assert_eq(field(completed, "outcome.success"), "true",
            "and its outcome: " .. completed.payload)
        t:assert(field(completed, "outcome.detail"), "and its result: " .. completed.payload)

        local requested = first_where(all, function(e)
            return e.type == "peinit.operation.requested"
        end)
        t:assert(requested, "a requested operation is in the ring")
        t:assert(not has(requested, "object.operation.duration"),
            "peinit.operation.requested adds nothing: " .. requested.payload)
        t:assert(not has(requested, "outcome"),
            "no outcome either: " .. requested.payload)

        local admin = first_where(all, function(e)
            return field(e, "object.operation.source") == "admin"
        end)
        t:assert(admin, "an administrator's operation is in the ring")
        t:assert(field(admin, "subject.token.sid"),
            "naming the client who asked: " .. admin.payload)
        local boot = first_where(all, function(e)
            return field(e, "object.operation.source") == "boot"
        end)
        t:assert(boot, "and a boot-plan operation")
        t:assert(not has(boot, "subject"),
            "which has no subject, because nobody asked: " .. boot.payload)
    end)

test("an operation's duration counts from its request, so one that never ran still has one",
    { spec = "peinit *emit.an-operations-duration-is-measured-from-its-request" },
    function(t)
        -- The sharpest case for "from the request" is an operation that
        -- never executed at all. A start queued behind pt-stubborn's
        -- SIGTERM-proof stop fails at its own four-second StartTimeout
        -- without ever being dispatched: there is no execution to
        -- measure, and yet its `peinit.operation.ended` carries a
        -- duration of about the four seconds the caller waited.
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
        for _, event in ipairs(events({ "peinit.operation.*" })) do
            if revstrm.guid(field(event, "object.operation.guid")) == id:lower() then
                mine[event.type] = event
            end
        end
        t:assert(mine["peinit.operation.requested"], "the queued start was requested")
        t:assert(not mine["peinit.operation.started"],
            "and never started, so nothing about it was executed")

        local failed = mine["peinit.operation.ended"]
        t:assert(failed, "but it ended: " .. tostring(failed and failed.payload))
        t:assert_eq(field(failed, "object.operation.state"), "failed",
            "having failed: " .. failed.payload)
        local duration = nanoseconds(field(failed, "object.operation.duration"))
        t:assert(duration and duration >= 4 * 1000000000,
            "with a duration of at least the four seconds the caller waited: "
            .. tostring(duration))
        t:assert(duration < 60 * 1000000000,
            "and not of the whole stop it was queued behind: " .. tostring(duration))
    end)

test("an operation's result is its outcome.detail, and the control view's error",
    { spec = "peinit *emit.an-operations-result-is-its-outcome-detail" },
    function(t)
        -- Every way an operation ends is one type, told apart by its
        -- state, and its result is one field however it ended:
        -- `outcome.detail`, which the control interface's view of the
        -- same operation calls `error`.
        local start = vm:run("svctl --no-wait --json start pt-hangs")
        start:assert_ok()
        local start_id = start.stdout:match('"operation_id":"([^"]+)"')
        vm:run("svctl --no-wait --json stop pt-hangs"):assert_ok()
        vm:run("sleep 2")

        local function ended(id)
            return first_where(events({ "peinit.operation.ended" }), function(event)
                return revstrm.guid(field(event, "object.operation.guid")) == id:lower()
            end)
        end

        local aborted = ended(start_id)
        t:assert(aborted, "the superseded start ended")
        t:assert_eq(field(aborted, "object.operation.state"), "aborted",
            "aborted: " .. aborted.payload)
        t:assert_eq(field(aborted, "outcome.success"), "false",
            "and not a success: " .. aborted.payload)
        local reason = field(aborted, "outcome.detail")
        t:assert(reason, "its result is outcome.detail: " .. aborted.payload)

        local view = vm:run("svctl --json operation-status " .. start_id)
        view:assert_ok()
        t:assert_eq(view.stdout:match('"error":"([^"]*)"'), reason,
            "and the control view calls the same string `error`: " .. view.stdout)

        -- The failed case: the same field.
        vm:run("svctl --no-wait --json stop pt-stub-reason")
        local queued = vm:run("svctl --no-wait --json start pt-stub-reason")
        local failed_id = queued.stdout:match('"operation_id":"([^"]+)"')
        vm:run("sleep 8", { timeout = 30 })
        local failed = ended(failed_id)
        t:assert(failed, "the timed-out start ended")
        t:assert_eq(field(failed, "object.operation.state"), "failed",
            "failed: " .. failed.payload)
        t:assert(field(failed, "outcome.detail"),
            "with its result in outcome.detail too: " .. failed.payload)
        local failed_view = vm:run("svctl --json operation-status " .. failed_id)
        t:assert_eq(failed_view.stdout:match('"error":"([^"]*)"'),
            field(failed, "outcome.detail"),
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
        -- `peinit.operation.requested` events all arrive together, and
        -- what a release emits later is `peinit.operation.started`.
        vm:run("svctl --json start pt-chain", { timeout = 90 })

        local members = { ["pt-leaf"] = true, ["pt-mid"] = true }
        local stream = events({ "peinit.operation.requested", "peinit.operation.started",
                                "peinit.operation.ended" })
        local last_requested, first_started
        local leaf_completed, mid_started
        for _, event in ipairs(stream) do
            local service = field(event, "object.service.name")
            if members[service] then
                if event.type == "peinit.operation.requested" then
                    last_requested = event.index
                elseif event.type == "peinit.operation.started" then
                    first_started = first_started or event.index
                end
            end
            if service == "pt-leaf" and event.type == "peinit.operation.ended"
                and field(event, "object.operation.state") == "completed" then
                leaf_completed = event.index
            elseif service == "pt-mid" and event.type == "peinit.operation.started" then
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
        -- number. `peinit.graph.operation.ended` is the one every boot
        -- produces — between it and an operation's own end, an audit
        -- record and a lifecycle record share the stream.
        local graph = events({ "peinit.graph.operation.ended" })
        t:assert(#graph > 0, "the boot's graph outcomes are in the ring")
        for _, path in ipairs({ "graph.context", "object.service.name",
                                "object.operation.guid", "outcome.success" }) do
            t:assert(field(graph[1], path),
                "peinit.graph.operation.ended carries " .. path .. ": " .. graph[1].payload)
        end

        local mixed = events({ "peinit.graph.*", "peinit.operation.*", "peinit.job.*" })
        local kinds = {}
        for _, event in ipairs(mixed) do kinds[event.type] = true end
        t:assert(kinds["peinit.graph.operation.ended"] and kinds["peinit.operation.ended"],
            "an audit record and a lifecycle record came out of one snapshot")
    end)

-- peinit.job.output.dropped is a unit test in the peinit crate, cited
-- here: the event fires when peinit's write to a submitted job's output
-- sink returns EAGAIN -- a sink pipe held full and unread while the job
-- floods it -- and the "once per job, on the first drop" bookkeeping
-- lives inside PID 1's log-pipe reader. The guest ships no client that
-- can hold a sink descriptor open and unread to provoke it, and the
-- drop-once rule has no observable surface but the event itself.

test("peinit.job.output.dropped is emitted once per job, on the first drop",
    {
        spec = "peinit *emit.output-dropped-is-emitted-once-per-job",
        covered_by = "cargo:peinit2 runtime::logging::tests::a_sink_that_would_block_counts_each_dropped_line_and_reports_the_first",
        skip = "the drop needs peinit's write to a submitter's sink to return EAGAIN on a " ..
            "full, unread sink pipe, which no guest client can hold open; runs under cargo test " ..
            "-p peinit2 --all-features --lib " ..
            "runtime::logging::tests::a_sink_that_would_block_counts_each_dropped_line_and_reports_the_first",
    },
    function(t) end)
