-- peinit TRM §8.2 — the operation: a requested state machine action as
-- an object, with its own identifier, states, source, timeout and
-- retention.
--
-- `svctl operation-status` is the whole instrument for most of this: it
-- returns an operation by identifier with its type, service, source,
-- state, result, error and three timestamps, which is nearly the record.
-- The exceptions are the states a caller never gets an identifier for —
-- Merged, whose record is stored under an identifier the merging caller
-- is deliberately not told (§8.6) — and those are read out of the KMES
-- ring instead, where `operation.merged` names both halves.
--
-- Two things about the seeds below. `Readiness = 0` is notify readiness,
-- and a service that never sends `READY=1` therefore sits in Starting
-- with its start operation Running for as long as `StartTimeout` allows:
-- that is how a test gets an operation to still be in flight when the
-- next command arrives. And `pt-stubborn` ignores SIGTERM, so its stop
-- occupies the service for its whole `StopTimeout` — long enough for a
-- start queued behind it to blow a four-second `StartTimeout` without
-- ever running, which is what the queue-time claim needs.

local peinit = require("helpers.peinit")
-- One VM for the file: each test works on a service of its own, so
-- nothing here needs a boot to itself.
peinit.claim(1)

local function definitions()
    return {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
        { path = [[Machine\System\Services\pt-simple]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/sleep" },
            { name = "Arguments", type = "multi", data = { "100000" } },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
            { name = "RestartPolicy", type = "dword", data = 0 },
            { name = "Triggers", type = "multi", data = { "boot" } },
        } },
        { path = [[Machine\System\Services\pt-oneshot]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/true" },
            { name = "Type", type = "dword", data = 1 },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "RemainAfterExit", type = "dword", data = 1 },
            { name = "RestartPolicy", type = "dword", data = 0 },
        } },
        { path = [[Machine\System\Services\pt-crashes]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/false" },
            { name = "Type", type = "dword", data = 1 },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "RestartPolicy", type = "dword", data = 0 },
        } },
        -- Two never-ready services: one for the merge, one for the
        -- abort, because each ends its subject's start operation.
        { path = [[Machine\System\Services\pt-hangs]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/sleep" },
            { name = "Arguments", type = "multi", data = { "100000" } },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 0 },
            { name = "StartTimeout", type = "dword", data = 200 },
            { name = "RestartPolicy", type = "dword", data = 0 },
        } },
        { path = [[Machine\System\Services\pt-hangs2]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/sleep" },
            { name = "Arguments", type = "multi", data = { "100000" } },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 0 },
            { name = "StartTimeout", type = "dword", data = 200 },
            { name = "RestartPolicy", type = "dword", data = 0 },
        } },
        { path = [[Machine\System\Services\pt-stubborn]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/sh" },
            { name = "Arguments", type = "multi",
              data = { "-c", "trap '' TERM; while :; do sleep 1; done" } },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
            { name = "StopTimeout", type = "dword", data = 40 },
            { name = "StartTimeout", type = "dword", data = 4 },
            { name = "RestartPolicy", type = "dword", data = 0 },
            { name = "Triggers", type = "multi", data = { "boot" } },
        } },
    }
end

local vm = peinit.boot({ name = "opsop", files = peinit.seed("pt-op", definitions()) })

--- `svctl <command>` as JSON, with the fields a lifecycle answer
--- carries pulled out. `no_wait` is opt-in because svctl refuses it on
--- the commands that never wait, and a usage error would read from here
--- like a command that did nothing.
local function send(command, no_wait)
    local run = vm:run("svctl " .. (no_wait and "--no-wait --json " or "--json ") .. command,
        { timeout = 120 })
    return {
        raw = run.stdout .. " / " .. tostring(run.stderr),
        operation = run.stdout:match('"operation_id":"([^"]+)"'),
        state = run.stdout:match('"state":"([^"]+)"'),
        code = run.stdout:match('"code":"([^"]+)"'),
    }
end

--- The operation view for `id`, as a table of its JSON fields.
local function operation(id)
    local run = vm:run("svctl --json operation-status " .. id)
    local out = { raw = run.stdout }
    for name, value in run.stdout:gmatch('"([%w_]+)":"([^"]*)"') do out[name] = value end
    out.code = run.stdout:match('"code":"([^"]+)"')
    for _, name in ipairs({ "result", "error", "started_at", "completed_at", "merged_into" }) do
        if run.stdout:find('"' .. name .. '":null', 1, true) then out[name] = false end
    end
    return out
end

--- Poll `operation-status` until the operation is terminal, or give up.
local function settle(id, seconds)
    for _ = 1, seconds or 30 do
        local view = operation(id)
        if view.state ~= "pending" and view.state ~= "running" then return view end
        vm:run("sleep 1")
    end
    return operation(id)
end

--- Pretty-printed KMES events of the given types, oldest first. The
--- default line form caps the payload, so `--pretty` is what a test
--- reads a named field out of.
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

local function field(event, name)
    local value = event.payload:match("\n?%s+" .. name .. "%s%s+([^\r\n]*)")
    if not value then return nil end
    return (value:gsub('^"', ""):gsub('"$', ""))
end

test("a lifecycle command creates an operation rather than changing state directly",
    { spec = "peinit *op.every-control-command-creates-an-operation" },
    function(t)
        -- The evidence that a command went through an operation is that
        -- it named one: the answer carries an identifier, and that
        -- identifier is a first-class object peinit will still describe
        -- afterwards — its type, its service, who asked and when.
        local started = send("start pt-oneshot")
        t:assert(started.operation, "a start named an operation: " .. started.raw)

        local view = operation(started.operation)
        t:assert_eq(view.id, started.operation, "which peinit can be asked about: " .. view.raw)
        t:assert_eq(view.type, "start", "it is a start")
        t:assert_eq(view.service, "pt-oneshot", "against the service the command named")
        t:assert_eq(view.source, "admin", "created because a control client asked")
    end)

test("the states an operation can be in",
    { spec = "peinit *op.the-operation-states" },
    function(t)
        -- Completed and Failed come from operations that ran; Aborted
        -- from one superseded while it was running; Merged from one that
        -- never became a second piece of work at all. Merged is the only
        -- one whose identifier no caller is given, so it is taken out of
        -- the ring — `operation.merged` names the merged operation and
        -- the one it merged into, and peinit will describe the merged
        -- one when asked by that identifier.
        local completed = settle(send("start pt-oneshot", true).operation)
        t:assert_eq(completed.state, "completed", "a start that reached its goal: "
            .. completed.raw)

        local failed = settle(send("start pt-crashes", true).operation)
        t:assert_eq(failed.state, "failed", "a start whose service crashed: " .. failed.raw)

        -- Aborted: a stop supersedes a start that is still running.
        local hanging = send("start pt-hangs2", true)
        t:assert(hanging.operation, "the never-ready service's start is in flight")
        send("stop pt-hangs2", true)
        local aborted = settle(hanging.operation)
        t:assert_eq(aborted.state, "aborted", "the superseded start is Aborted: " .. aborted.raw)

        -- Merged: two identical starts, one operation to wait on.
        local first = send("start pt-hangs", true)
        local second = send("start pt-hangs", true)
        t:assert_eq(second.operation, first.operation,
            "the second caller was given the first operation")

        local merged_id
        for _, event in ipairs(events({ "operation.merged" })) do
            if field(event, "service") == "pt-hangs" then
                merged_id = field(event, "operation_id")
            end
        end
        t:assert(merged_id, "a merge was recorded for pt-hangs")
        t:assert(merged_id ~= first.operation,
            "under an identifier of its own, which the caller was not given")

        local merged = operation(merged_id)
        t:assert_eq(merged.state, "merged", "and that operation is Merged: " .. merged.raw)
        t:assert_eq(merged.merged_into, first.operation,
            "recording which operation it merged into: " .. merged.raw)
    end)

test("an operation records why peinit created it",
    { spec = "peinit *op.the-operation-sources" },
    function(t)
        -- The source is the reason, not the caller. A control client's
        -- command is `admin` and carries the caller's token; the Phase 2
        -- plan's starts are `boot` and carry no caller at all, because
        -- nobody asked for them.
        local admin = operation(send("start pt-oneshot", true).operation)
        t:assert_eq(admin.source, "admin", "a control command's operation: " .. admin.raw)

        local boot_starts, admin_starts = 0, 0
        for _, event in ipairs(events({ "operation.requested", "operation.started" })) do
            if field(event, "source") == "boot" then
                boot_starts = boot_starts + 1
                t:assert_eq(field(event, "caller"), "nil",
                    "a boot operation has no caller: " .. event.payload)
            elseif field(event, "source") == "admin" then
                admin_starts = admin_starts + 1
            end
        end
        t:assert(boot_starts > 0, "the boot plan's operations carry the boot source")
        t:assert(admin_starts > 0, "and a control client's carry admin")
    end)

test("a start completes when its service reaches the state it was aiming at",
    {
        spec = {
            "peinit *op.a-start-completes-when-the-service-reaches-its-goal-state",
            "peinit *op.a-stop-completes-when-the-service-reaches-inactive",
        },
    },
    function(t)
        -- What "completed" means differs by service type, and the
        -- operation's result says which goal was reached: a Simple
        -- service is Active once its process is judged ready, a Oneshot
        -- is Completed when its process exits successfully. A stop is
        -- complete when the service is no longer running.
        local simple = settle(send("restart pt-simple", true).operation)
        t:assert_eq(simple.state, "completed", "the Simple service's start completed: "
            .. simple.raw)
        t:assert_eq(vm:run("svctl --json status pt-simple").stdout:match('"state":"([^"]+)"'),
            "active", "with the service Active")

        local oneshot = settle(send("start pt-oneshot", true).operation)
        t:assert_eq(oneshot.state, "completed", "the Oneshot's start completed: "
            .. oneshot.raw)
        t:assert_eq(vm:run("svctl --json status pt-oneshot").stdout:match('"state":"([^"]+)"'),
            "completed", "with the service Completed")

        local stopped = settle(send("stop pt-simple", true).operation)
        t:assert_eq(stopped.state, "completed", "and the stop completed: " .. stopped.raw)
        t:assert_eq(vm:run("svctl --json status pt-simple").stdout:match('"state":"([^"]+)"'),
            "inactive", "with the service Inactive")
        vm:run("svctl --json start pt-simple", { timeout = 90 })
    end)

test("a restart is one operation across both of its legs, and stays a restart",
    { spec = "peinit *op.a-restart-keeps-one-identifier-and-type-across-both-legs" },
    function(t)
        -- A restart is a stop and then a start, but it is not two
        -- operations: the caller is given one identifier, and that
        -- identifier describes a `restart` for the whole of both phases
        -- rather than becoming a `stop` and then a `start`. The ring
        -- shows the same thing from the other side — one requested, one
        -- started and one terminal event, all typed `restart`.
        local before = vm:run("svctl --json status pt-simple").stdout:match('"pid":(%d+)')
        local restart = send("restart pt-simple")
        t:assert(restart.operation, "the restart named an operation: " .. restart.raw)

        local view = settle(restart.operation)
        t:assert_eq(view.type, "restart", "which is still a restart when it is over: "
            .. view.raw)
        t:assert_eq(view.state, "completed", "and completed: " .. view.raw)

        local after = vm:run("svctl --json status pt-simple").stdout:match('"pid":(%d+)')
        t:assert(after and after ~= before,
            "the service really went down and came back: " .. tostring(before)
            .. " -> " .. tostring(after))

        local types = {}
        for _, event in ipairs(events({ "operation.requested", "operation.started",
                                        "operation.completed" })) do
            if field(event, "operation_id") == restart.operation then
                types[#types + 1] = event.type .. "/" .. tostring(field(event, "type"))
            end
        end
        t:assert_eq(table.concat(types, " "),
            "operation.requested/restart operation.started/restart " ..
            "operation.completed/restart",
            "one operation, typed restart at every step")
    end)

test("a reset is synchronous",
    { spec = "peinit *op.reset-is-synchronous" },
    function(t)
        -- Reset has no work to wait for: it clears a terminal state and
        -- that is all. So the operation it creates is already over by
        -- the time the caller is answered — requested, started and
        -- completed in the one turn — rather than being something the
        -- caller then polls.
        send("start pt-crashes", true)
        settle(send("start pt-crashes", true).operation)
        t:assert_eq(vm:run("svctl --json status pt-crashes").stdout:match('"state":"([^"]+)"'),
            "failed", "the service is in a terminal state to clear")

        local reset = send("reset pt-crashes")
        t:assert(reset.operation, "the reset named an operation: " .. reset.raw)
        local view = operation(reset.operation)
        t:assert_eq(view.state, "completed",
            "which was already complete when the caller was answered: " .. view.raw)
        t:assert_eq(view.started_at, view.completed_at,
            "having started and completed in the same instant: " .. view.raw)
        t:assert_eq(vm:run("svctl --json status pt-crashes").stdout:match('"state":"([^"]+)"'),
            "inactive", "and the service is Inactive")
    end)

test("a start that sits queued past StartTimeout fails without ever running",
    {
        spec = {
            "peinit *op.a-start-inherits-starttimeout-and-a-stop-stoptimeout",
            "peinit *op.the-operation-clock-starts-at-creation-including-queue-time",
        },
    },
    function(t)
        -- pt-stubborn ignores SIGTERM, so its stop holds the service for
        -- the whole 40-second StopTimeout. A start sent straight after
        -- is queued behind it, and its own 4-second StartTimeout is
        -- measured from when the caller sent it — not from when peinit
        -- would have got round to it. So it fails while still Pending:
        -- `started_at` is null, which is the proof it never ran, and the
        -- error names the timeout rather than anything about the
        -- service.
        local stop = send("stop pt-stubborn", true)
        t:assert(stop.operation, "the stop is under way: " .. stop.raw)

        local queued = send("start pt-stubborn", true)
        t:assert(queued.operation, "the start was accepted and queued: " .. queued.raw)
        t:assert(queued.operation ~= stop.operation, "as an operation of its own")

        local pending = operation(queued.operation)
        t:assert_eq(pending.state, "pending", "and is Pending, not running: " .. pending.raw)

        local view = settle(queued.operation, 20)
        t:assert_eq(view.state, "failed",
            "it failed at its own StartTimeout, with the stop still draining: " .. view.raw)
        t:assert_eq(view.started_at, false,
            "without ever having started: " .. view.raw)
        t:assert(view.error and view.error:find("operation_timeout", 1, true),
            "and the failure is the operation's maximum lifetime: " .. view.raw)

        local still_stopping =
            vm:run("svctl --json status pt-stubborn").stdout:match('"state":"([^"]+)"')
        t:assert_eq(still_stopping, "stopping",
            "while the stop it was queued behind is still going")
    end)

test("a terminal operation is dropped after its sixty-second grace period",
    { spec = "peinit *op.a-terminal-operation-is-dropped-after-sixty-seconds" },
    function(t)
        -- peinit keeps no operation history either. A terminal operation
        -- stays queryable just long enough for a client that was polling
        -- to collect the result, and is then gone — a poll at 5 seconds
        -- is answered and one at 75 is not.
        local id = settle(send("start pt-oneshot", true).operation).id
        t:assert(id, "there is a terminal operation to ask about")

        vm:run("sleep 75", { timeout = 120 })

        local gone = operation(id)
        t:assert_eq(gone.code, "UNKNOWN_OPERATION",
            "the operation is no longer held: " .. gone.raw)
    end)
