-- peinit TRM §8.3 — resolving a new operation against one already
-- Pending or Running for the same service: what merges, what supersedes
-- what, and what is refused outright.
--
-- Three things shape this file.
--
-- The first is that most of the rows need an operation that is still in
-- flight when the next command arrives, and the only reliable way to
-- hold one there is a service that never becomes ready. `pt-hangs*` are
-- notify-readiness services whose process never sends `READY=1`, so
-- their start operations stay Running for a 200-second `StartTimeout`;
-- `pt-stub*` ignore SIGTERM, so their stops occupy the whole
-- `StopTimeout`; `pt-rel*` have a reload command that sleeps, so their
-- reloads are still Running a command later.
--
-- The second is that the table's four `(Pending)` rows are not reachable
-- from outside. An operation is Pending because another is ahead of it
-- in the service's queue, and resolution is always against the head of
-- that queue — so the Pending one is never the operation a new command
-- is resolved against. The window in which a Pending operation is at the
-- head, between the previous one being removed and the work pump
-- dispatching it, is a few milliseconds wide and cannot be aimed at.
--
-- The third is why the `known-bug` tests below boot a VM of their own.
-- Seven rows do not hold. Five of them end with peinit's runtime loop
-- failing and peinit entering Recovery — which takes the control socket
-- with it and leaves the VM useless for anything after — and two are
-- answered INTERNAL_ERROR. Each is isolated so that the row it names is
-- the only thing its failure can be about.
--
-- One divergence is deliberately NOT encoded here. §8.3 says a new
-- Start while a Reload is active is rejected; the code's admission
-- matrix classifies a start against a Reloading service as ALREADY and
-- answers with the service's status before conflict resolution is
-- reached. The reload half of the same sentence does hold, and that is
-- what the test below asserts.

local peinit = require("helpers.peinit")
-- Two: the shared VM the reachable rows run on, plus the one the test
-- in hand boots for a row that ends peinit.
peinit.claim(2)

local function hangs(name)
    return { path = [[Machine\System\Services\]] .. name, values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "100000" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 0 },
        { name = "StartTimeout", type = "dword", data = 200 },
        { name = "RestartPolicy", type = "dword", data = 0 },
    } }
end

local function stubborn(name)
    return { path = [[Machine\System\Services\]] .. name, values = {
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi",
          data = { "-c", "trap '' TERM; while :; do sleep 1; done" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "StopTimeout", type = "dword", data = 60 },
        { name = "StartTimeout", type = "dword", data = 60 },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "Triggers", type = "multi", data = { "boot" } },
    } }
end

local function reloadable(name)
    return { path = [[Machine\System\Services\]] .. name, values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "100000" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "ExecReload", type = "sz", data = "/bin/sleep 20" },
        { name = "StopTimeout", type = "dword", data = 60 },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "Triggers", type = "multi", data = { "boot" } },
    } }
end

local function definitions()
    local keys = {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
        -- A dependency chain: pt-needs Requires a oneshot that fails,
        -- pt-wants only Wants one.
        { path = [[Machine\System\Services\pt-dep-bad]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/false" },
            { name = "Type", type = "dword", data = 1 },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "RestartPolicy", type = "dword", data = 0 },
        } },
        { path = [[Machine\System\Services\pt-needs]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/sleep" },
            { name = "Arguments", type = "multi", data = { "100000" } },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
            { name = "Requires", type = "multi", data = { "pt-dep-bad" } },
            { name = "RestartPolicy", type = "dword", data = 0 },
        } },
        { path = [[Machine\System\Services\pt-wants]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/sleep" },
            { name = "Arguments", type = "multi", data = { "100000" } },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
            { name = "Wants", type = "multi", data = { "pt-dep-bad2" } },
            { name = "RestartPolicy", type = "dword", data = 0 },
        } },
        { path = [[Machine\System\Services\pt-dep-bad2]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/false" },
            { name = "Type", type = "dword", data = 1 },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "RestartPolicy", type = "dword", data = 0 },
        } },
        -- Crashes at once and is always restarted, after a delay long
        -- enough that the RestartPolicy start is visible in the ring
        -- rather than lost in a storm of them.
        { path = [[Machine\System\Services\pt-flaps]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/false" },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
            { name = "RestartPolicy", type = "dword", data = 2 },
            { name = "RestartDelay", type = "dword", data = 2 },
            { name = "RestartMaxRetries", type = "dword", data = 20 },
            { name = "Triggers", type = "multi", data = { "boot" } },
        } },
    }
    for i = 1, 4 do
        keys[#keys + 1] = hangs("pt-hangs" .. i)
        keys[#keys + 1] = stubborn("pt-stub" .. i)
        keys[#keys + 1] = reloadable("pt-rel" .. i)
    end
    return keys
end

local SEED = peinit.seed("pt-conflict", definitions())

local function boot(name)
    return peinit.boot({ name = name, files = SEED })
end

local shared = boot("opscx")

--- `svctl <command>` as JSON against `vm`, with the fields a lifecycle
--- answer carries pulled out.
local function send(vm, command, no_wait)
    local run = vm:run("svctl " .. (no_wait and "--no-wait --json " or "--json ") .. command,
        { timeout = 120 })
    return {
        raw = run.stdout .. " / " .. tostring(run.stderr),
        operation = run.stdout:match('"operation_id":"([^"]+)"'),
        state = run.stdout:match('"state":"([^"]+)"'),
        code = run.stdout:match('"code":"([^"]+)"'),
    }
end

local function operation(vm, id)
    local run = vm:run("svctl --json operation-status " .. tostring(id))
    local out = { raw = run.stdout }
    for name, value in run.stdout:gmatch('"([%w_]+)":"([^"]*)"') do out[name] = value end
    out.code = run.stdout:match('"code":"([^"]+)"')
    return out
end

--- The `state` a status query reports for `service`.
local function state_of(vm, service)
    return vm:run("svctl --json status " .. service).stdout:match('"state":"([^"]+)"')
end

local function settle(vm, id, seconds)
    for _ = 1, seconds or 40 do
        local view = operation(vm, id)
        if view.state ~= "pending" and view.state ~= "running" then return view end
        vm:run("sleep 1")
    end
    return operation(vm, id)
end

--- Whether peinit is still serving. A runtime-loop failure takes peinit
--- into Recovery, which unlinks the control socket — so "is the socket
--- there" is the cheapest test for "did that command end PID 1's
--- supervision".
local function supervising(vm)
    return not tostring(vm:run("svctl --json list").stderr):find("No such file", 1, true)
end

--- The `entering recovery` line peinit printed, if it did.
local function recovery_line(vm)
    return tostring(vm:console():read_log()):match("entering recovery: [^\r\n]*")
end

local function events(vm, globs)
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

test("an operation of the same type merges, and the new caller gets the existing identifier",
    { spec = "peinit *conflict.an-operation-of-the-same-type-merges" },
    function(t)
        -- Start on Start, Stop on Stop, Reload on Reload. In each case
        -- the second caller is handed the identifier of the operation
        -- already in flight, so there is one piece of work and one
        -- outcome for both of them to wait on.
        local start1 = send(shared, "start pt-hangs1", true)
        local start2 = send(shared, "start pt-hangs1", true)
        t:assert(start1.operation, "the first start named an operation: " .. start1.raw)
        t:assert_eq(start2.operation, start1.operation,
            "the second start merged into it: " .. start2.raw)

        local stop1 = send(shared, "stop pt-stub1", true)
        local stop2 = send(shared, "stop pt-stub1", true)
        t:assert(stop1.operation, "the first stop named an operation: " .. stop1.raw)
        t:assert_eq(stop2.operation, stop1.operation,
            "the second stop merged into it: " .. stop2.raw)

        local reload1 = send(shared, "reload pt-rel1")
        local reload2 = send(shared, "reload pt-rel1")
        t:assert(reload1.operation, "the first reload named an operation: " .. reload1.raw)
        t:assert_eq(reload2.operation, reload1.operation,
            "the second reload merged into it: " .. reload2.raw)
    end)

test("a stop supersedes a running start, and the start records that it was superseded",
    {
        spec = {
            "peinit *conflict.stop-wins-over-start",
            "peinit *conflict.a-superseded-start-records-that-it-was-superseded",
            "peinit *conflict.the-cross-type-resolutions",
        },
    },
    function(t)
        -- The `Start (Running) | Stop` row, and the first two
        -- principles. An explicit stop takes priority over a start that
        -- is still running: the start is aborted rather than left to
        -- finish, a stop is created as an operation of its own, and the
        -- aborted start says why it ended.
        local start = send(shared, "start pt-hangs2", true)
        t:assert(start.operation, "a start is running: " .. start.raw)

        local stop = send(shared, "stop pt-hangs2", true)
        t:assert(stop.operation, "the stop was created: " .. stop.raw)
        t:assert(stop.operation ~= start.operation,
            "as a separate operation rather than merging into the start")

        local aborted = settle(shared, start.operation)
        t:assert_eq(aborted.state, "aborted",
            "and the start was aborted, not left running: " .. aborted.raw)
        t:assert_eq(aborted.error, "superseded_by_later_operation",
            "recorded as superseded by what came later: " .. aborted.raw)
    end)

test("a start requested while a stop is draining is queued behind it",
    { spec = "peinit *conflict.the-cross-type-resolutions" },
    function(t)
        -- The `Stop (either) | Start` row: the stop is not disturbed and
        -- the start becomes a second operation waiting its turn, which
        -- is the "a queued start can follow" half of the first
        -- principle.
        local stop = send(shared, "stop pt-stub2", true)
        t:assert(stop.operation, "the stop is under way: " .. stop.raw)

        local start = send(shared, "start pt-stub2", true)
        t:assert(start.operation, "the start was accepted: " .. start.raw)
        t:assert(start.operation ~= stop.operation, "as an operation of its own")
        t:assert_eq(operation(shared, start.operation).state, "pending",
            "sitting Pending behind the stop")
        t:assert_eq(operation(shared, stop.operation).state, "running",
            "which is still the operation being executed")
    end)

test("a reset is refused while anything is in flight",
    {
        spec = {
            "peinit *conflict.reset-is-rejected-while-anything-is-in-flight",
            "peinit *conflict.the-cross-type-resolutions",
        },
    },
    function(t)
        -- The `Anything (either) | Reset` row. Reset means "clear a
        -- terminal state"; a service with an operation in flight has no
        -- terminal state to clear, so the command is refused rather than
        -- queued or merged.
        local start = send(shared, "start pt-hangs3", true)
        t:assert(start.operation, "a start is in flight: " .. start.raw)

        local reset = send(shared, "reset pt-hangs3")
        t:assert_eq(reset.code, "INVALID_STATE",
            "the reset was refused: " .. reset.raw)
        t:assert(not reset.operation, "and created nothing: " .. reset.raw)
        t:assert_eq(operation(shared, start.operation).state, "running",
            "leaving the start it collided with untouched")
    end)

test("a reload is refused while a start, a stop or a restart is active",
    { spec = "peinit *conflict.combinations-outside-the-table-are-rejected" },
    function(t)
        -- Reload is not in the cross-type table against Start, Stop or
        -- Restart, and a combination outside the table is refused. Each
        -- of the three is set up on a service of its own, because a
        -- refusal has to be about the operation in flight rather than
        -- about something the previous case left behind.
        send(shared, "start pt-hangs4", true)
        local against_start = send(shared, "reload pt-hangs4")
        t:assert_eq(against_start.code, "INVALID_STATE",
            "a reload while a start is active: " .. against_start.raw)

        send(shared, "stop pt-stub3", true)
        local against_stop = send(shared, "reload pt-stub3")
        t:assert_eq(against_stop.code, "INVALID_STATE",
            "a reload while a stop is active: " .. against_stop.raw)

        send(shared, "restart pt-stub4", true)
        local against_restart = send(shared, "reload pt-stub4")
        t:assert_eq(against_restart.code, "INVALID_STATE",
            "a reload while a restart is active: " .. against_restart.raw)
    end)

test("a start while a reload is active is answered with the status, not refused",
    { spec = "peinit *conflict.a-start-while-reloading-is-answered-with-the-status" },
    function(t)
        -- The other half of the sentence above, and it behaves the other
        -- way. A reloading service is already where a start would take
        -- it, so the admission matrix answers ALREADY with the current
        -- status and the request never reaches conflict resolution —
        -- which is why there is no error and no operation.
        --
        -- pt-rel2's ExecReload sleeps twenty seconds, so the reload is
        -- still running when the start arrives.
        send(shared, "reload pt-rel2", true)
        wait_until(function()
            return send(shared, "status pt-rel2").state == "reloading" or nil
        end, { timeout = 60, interval = 0.3, desc = "pt-rel2 to be reloading" })

        local start = send(shared, "start pt-rel2")
        t:assert(not start.code,
            "the start was not refused: " .. start.raw)
        t:assert(not start.operation,
            "and created no operation, so it never reached conflict resolution: "
            .. start.raw)
        t:assert_eq(start.state, "reloading",
            "it was answered with the service's current state instead")
    end)

test("a start operation is created for each unsatisfied dependency",
    {
        spec = {
            "peinit *conflict.a-failed-requires-dependency-fails-the-parent",
            "peinit *conflict.a-failed-wants-dependency-does-not-fail-the-parent",
        },
    },
    function(t)
        -- A dependency is started by an operation of its own, with the
        -- source that says why it exists. What that operation's failure
        -- then does to the parent is the whole difference between
        -- Requires and Wants: a failed Requires takes the parent down
        -- with it, a failed Wants does not.
        local needs = settle(shared, send(shared, "start pt-needs", true).operation)
        t:assert_eq(needs.state, "failed",
            "a start whose Requires dependency failed fails: " .. needs.raw)
        t:assert(needs.error and needs.error:lower():find("dependency"),
            "naming the dependency as the reason: " .. needs.raw)

        local wants = settle(shared, send(shared, "start pt-wants", true).operation)
        t:assert_eq(wants.state, "completed",
            "while a failed Wants dependency does not stop the parent: " .. wants.raw)
        t:assert_eq(state_of(shared, "pt-wants"), "active",
            "and the service came up")

        local sources = {}
        for _, event in ipairs(events(shared, { "operation.requested" })) do
            local service = field(event, "service")
            if service == "pt-dep-bad" or service == "pt-dep-bad2" then
                sources[field(event, "source")] = true
            end
        end
        t:assert(sources.dependency_propagation,
            "and each dependency's start says a dependency asked for it")
    end)

test("a restart-eligible failure creates a start with the RestartPolicy source",
    { spec = "peinit *conflict.a-restart-eligible-failure-creates-a-start-with-source-restartpolicy" },
    function(t)
        -- The restart policy does not reach into the state machine: it
        -- asks for a start like anything else, and the operation it
        -- creates carries `restart_policy` as its reason. pt-flaps
        -- crashes on start and is always restarted, so a few seconds of
        -- boot is enough to produce several.
        shared:run("sleep 6", { timeout = 30 })
        local found = false
        for _, event in ipairs(events(shared, { "operation.requested" })) do
            if field(event, "service") == "pt-flaps"
                and field(event, "source") == "restart_policy" then
                found = true
                t:assert_eq(field(event, "type"), "start",
                    "the restart policy asked for a start: " .. event.payload)
                t:assert_eq(field(event, "caller"), "nil",
                    "with no caller, because nobody asked: " .. event.payload)
            end
        end
        t:assert(found, "a restart-policy start was requested for the crashing service")
    end)

test("the boot plan's starts carry the Boot source",
    { spec = "peinit *conflict.boot-generated-starts-use-the-boot-source" },
    function(t)
        -- Boot is a mode, not an operation: there is nothing called a
        -- "boot operation" to observe. What it leaves behind is a start
        -- per service, each labelled with the mode that generated it.
        local boot_services = {}
        for _, event in ipairs(events(shared, { "operation.requested",
                                                "operation.started" })) do
            if field(event, "source") == "boot" then
                t:assert_eq(field(event, "type"), "start",
                    "a boot-generated operation is a start: " .. event.payload)
                boot_services[field(event, "service")] = true
            end
        end
        t:assert(boot_services["pt-stub1"] or boot_services["pt-rel1"],
            "the seeded boot services were started by the boot plan")
    end)

-- The rows below end with peinit's runtime loop failing. Each boots a VM
-- of its own, because a VM whose peinit has entered Recovery cannot
-- serve the next test.

test("a restart requested while a start is running is queued, not fatal",
    {
        spec = {
            "peinit *conflict.the-cross-type-resolutions",
        },
        -- PEI-824: `Start (Running) | Restart` — the restart is accepted
        -- and queued, and peinit's runtime loop then fails with
        -- JobTerminal(UnsupportedStoppingOperation), taking PID 1 into
        -- Recovery.
        tags = { "known-bug" },
    },
    function(t)
        local vm = boot("opscx-sr")
        local start = send(vm, "start pt-hangs1", true)
        t:assert(start.operation, "a start is running: " .. start.raw)

        local restart = send(vm, "restart pt-hangs1", true)
        t:assert(restart.operation, "the restart was queued: " .. restart.raw)
        vm:run("sleep 2")

        t:assert(supervising(vm),
            "and peinit is still supervising: " .. tostring(recovery_line(vm)))
    end)

test("a restart requested while a stop is draining is queued, not fatal",
    {
        spec = {
            "peinit *conflict.the-cross-type-resolutions",
        },
        -- PEI-824: `Stop (either) | Restart` — the queued restart's stop
        -- leg transitions a service that is already Stopping, and the
        -- InvalidTransition ends peinit's runtime loop.
        tags = { "known-bug" },
    },
    function(t)
        local vm = boot("opscx-qr")
        local stop = send(vm, "stop pt-stub1", true)
        t:assert(stop.operation, "a stop is draining: " .. stop.raw)

        local restart = send(vm, "restart pt-stub1", true)
        t:assert(restart.operation, "the restart was queued: " .. restart.raw)
        vm:run("sleep 2")

        t:assert(supervising(vm),
            "and peinit is still supervising: " .. tostring(recovery_line(vm)))
    end)

test("a second restart while one is in progress is queued, not fatal",
    {
        spec = {
            "peinit *conflict.restart-is-not-mergeable-with-itself",
        },
        -- PEI-824: `Restart (either) | Restart` — the same
        -- InvalidTransition as the row above, reached by the second
        -- restart's stop leg.
        tags = { "known-bug" },
    },
    function(t)
        local vm = boot("opscx-rr")
        local first = send(vm, "restart pt-stub1", true)
        t:assert(first.operation, "a restart is in progress: " .. first.raw)

        local second = send(vm, "restart pt-stub1", true)
        t:assert(second.operation, "the second restart was accepted: " .. second.raw)
        t:assert(second.operation ~= first.operation,
            "as an operation of its own, because restart does not merge with itself")
        vm:run("sleep 2")

        t:assert(supervising(vm),
            "and peinit is still supervising: " .. tostring(recovery_line(vm)))
    end)

test("a stop aborts a running restart and is created in its place",
    {
        spec = {
            "peinit *conflict.the-cross-type-resolutions",
        },
        -- PEI-824: `Restart (Running) | Stop` — the conflict table says
        -- abort-then-create, the admission matrix expects a merge
        -- because the service is Stopping, and the mismatch is answered
        -- INTERNAL_ERROR.
        tags = { "known-bug" },
    },
    function(t)
        local vm = boot("opscx-rs")
        local restart = send(vm, "restart pt-stub1", true)
        t:assert(restart.operation, "a restart is running: " .. restart.raw)

        local stop = send(vm, "stop pt-stub1", true)
        t:assert(not stop.code, "the stop was not refused: " .. stop.raw)
        t:assert(stop.operation, "and named the stop it created: " .. stop.raw)
        t:assert_eq(settle(vm, restart.operation, 10).state, "aborted",
            "with the restart aborted in its place")
    end)

test("a start merges into a running restart, which already includes one",
    {
        spec = {
            "peinit *conflict.an-operation-of-the-same-type-merges",
        },
        -- PEI-824: `Restart | Start` — the conflict table says merge,
        -- the admission matrix expects a queue because the service is
        -- Stopping, and the mismatch is answered INTERNAL_ERROR.
        tags = { "known-bug" },
    },
    function(t)
        local vm = boot("opscx-rm")
        local restart = send(vm, "restart pt-stub1", true)
        t:assert(restart.operation, "a restart is running: " .. restart.raw)

        local start = send(vm, "start pt-stub1", true)
        t:assert(not start.code, "the start was not refused: " .. start.raw)
        t:assert_eq(start.operation, restart.operation,
            "it merged into the restart, which already includes a start: " .. start.raw)
    end)

test("a stop aborts a running reload and is created in its place",
    {
        spec = {
            "peinit *conflict.the-cross-type-resolutions",
        },
        -- PEI-824: `Reload (Running) | Stop` — the abort is accepted,
        -- and peinit's runtime loop then fails on an InvalidTransition
        -- back to Active for the reload it just abandoned. PEI-820 is
        -- the same defect, found from chapter 6 and located: the stop
        -- cancels the reload's deadlines and cgroup but not its job.
        tags = { "known-bug" },
    },
    function(t)
        local vm = boot("opscx-ls")
        local reload = send(vm, "reload pt-rel1")
        t:assert(reload.operation, "a reload is running: " .. reload.raw)

        local stop = send(vm, "stop pt-rel1", true)
        t:assert(stop.operation, "the stop was created: " .. stop.raw)
        vm:run("sleep 3")

        t:assert(supervising(vm),
            "and peinit is still supervising: " .. tostring(recovery_line(vm)))
        t:assert_eq(operation(vm, reload.operation).state, "aborted",
            "with the reload aborted")
    end)

test("a restart aborts a running reload and is created in its place",
    {
        spec = {
            "peinit *conflict.the-cross-type-resolutions",
        },
        -- PEI-824: `Reload (Running) | Restart` — as the row above.
        tags = { "known-bug" },
    },
    function(t)
        local vm = boot("opscx-lr")
        local reload = send(vm, "reload pt-rel1")
        t:assert(reload.operation, "a reload is running: " .. reload.raw)

        local restart = send(vm, "restart pt-rel1", true)
        t:assert(restart.operation, "the restart was created: " .. restart.raw)
        vm:run("sleep 3")

        t:assert(supervising(vm),
            "and peinit is still supervising: " .. tostring(recovery_line(vm)))
        t:assert_eq(operation(vm, reload.operation).state, "aborted",
            "with the reload aborted")
    end)
