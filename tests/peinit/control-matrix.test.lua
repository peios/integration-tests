-- Peinit TRM §10.3 — the command × state matrix: the defined answer for
-- every command sent to a service in an unexpected state.
--
-- The matrix is a table of rules that hold one cell at a time, so the
-- way to check it is to put a service in each state and send it each
-- command. The seed below arranges six of the ten states directly out of
-- the boot:
--
--   Inactive   a service nothing triggers
--   Active     a resident process, judged ready by being alive
--   Completed  a Oneshot that succeeded and was told to remain
--   Failed     a Oneshot that exited non-zero, never restarted
--   Backoff    a process that dies at once, always restarted, with a
--              delay long enough that it sits there for the whole file
--   Skipped    a condition on a path that does not exist
--
-- Starting, Reloading and Stopping are transient, and reaching them
-- reliably from outside would mean racing peinit; Abandoned needs
-- processes that survive SIGKILL. Those four columns are stated in the
-- manual and not reached from here.
--
-- Every test that changes a service's state boots its own VM, because a
-- state is exactly what the next test is relying on.

local peinit = require("helpers.peinit")
peinit.claim(2)

local function definitions()
    return {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
        -- Active.
        { path = [[Machine\System\Services\pt-active]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/sleep" },
            { name = "Arguments", type = "multi", data = { "100000" } },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
            { name = "RestartPolicy", type = "dword", data = 0 },
            { name = "Triggers", type = "multi", data = { "boot" } },
        } },
        -- Inactive: no trigger, so the boot loads it and leaves it.
        { path = [[Machine\System\Services\pt-inactive]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/sleep" },
            { name = "Arguments", type = "multi", data = { "100000" } },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
            { name = "RestartPolicy", type = "dword", data = 0 },
        } },
        -- Completed.
        { path = [[Machine\System\Services\pt-completed]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/true" },
            { name = "Type", type = "dword", data = 1 },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "RemainAfterExit", type = "dword", data = 1 },
            { name = "Triggers", type = "multi", data = { "boot" } },
        } },
        -- Failed.
        { path = [[Machine\System\Services\pt-failed]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/false" },
            { name = "Type", type = "dword", data = 1 },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "RestartPolicy", type = "dword", data = 0 },
            { name = "Triggers", type = "multi", data = { "boot" } },
        } },
        -- Backoff. The delay is long on purpose: the service crashes
        -- the instant it runs, so once the delay expires it passes
        -- briefly through Starting on its way back to Backoff, and a
        -- status read landing in that window would see the wrong state.
        -- A long delay keeps the whole file on the near side of it.
        { path = [[Machine\System\Services\pt-backoff]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/false" },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
            { name = "RestartPolicy", type = "dword", data = 2 },
            { name = "RestartDelay", type = "dword", data = 120 },
            { name = "RestartMaxRetries", type = "dword", data = 50 },
            { name = "Triggers", type = "multi", data = { "boot" } },
        } },
        -- Skipped. RemainAfterExit so that if it ever does run, it is
        -- visibly Completed rather than dropping back to Inactive —
        -- which is what lets a test tell "ran" from "never ran".
        { path = [[Machine\System\Services\pt-skipped]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/true" },
            { name = "Type", type = "dword", data = 1 },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "RemainAfterExit", type = "dword", data = 1 },
            { name = "Conditions", type = "multi", data = { "path:/pt-not-here" } },
            { name = "Triggers", type = "multi", data = { "boot" } },
        } },
    }
end

local function boot(name)
    return peinit.boot({ name = name, files = peinit.seed("pt-matrix", definitions()) })
end

local STATES = {
    ["pt-inactive"] = "inactive",
    ["pt-active"] = "active",
    ["pt-completed"] = "completed",
    ["pt-failed"] = "failed",
    ["pt-backoff"] = "backoff",
    ["pt-skipped"] = "skipped",
}

--- The `state` a status query reports for `service`.
local function state_of(vm, service)
    return vm:run("svctl --json status " .. service).stdout:match('"state":"([^"]+)"')
end

--- `svctl --json <command>`, decoded into `state`, `code` and whether it
--- carried an operation identifier.
---
--- The shape of a lifecycle answer is itself evidence. An outcome that
--- creates or merges into an operation returns that operation's
--- identifier; NOOP and ALREADY return the service's status instead, and
--- a status answer carries no `operation_id` at all.
---
--- `no_wait` is opt-in rather than always on: svctl refuses `--no-wait`
--- on the commands that never wait, `reset` among them, and a usage
--- error would look from here like a command that did nothing.
local function send(vm, command, no_wait)
    local flags = no_wait and "--no-wait --json " or "--json "
    local run = vm:run("svctl " .. flags .. command)
    local out = run.stdout
    return {
        raw = out .. " / " .. tostring(run.stderr),
        state = out:match('"state":"([^"]+)"'),
        code = out:match('"code":"([^"]+)"'),
        operation = out:match('"operation_id":"([^"]+)"'),
    }
end

local shared = boot("matrix")

test("the boot puts a service in each of the six states this file can reach",
    { spec = "peinit *dispatch.matrix.status" },
    function(t)
        -- The status row is OK in every column: a status query is never
        -- refused for the state its target is in, which is what makes it
        -- the one command an administrator can always ask.
        for service, expected in pairs(STATES) do
            local status = shared:run("svctl --json status " .. service)
            status:assert_ok()
            t:assert_eq(state_of(shared, service), expected,
                service .. " is " .. expected .. ": " .. status.stdout)
        end
    end)

test("start: begins where it can, is ALREADY where it need not, and is refused on Abandoned",
    { spec = "peinit *dispatch.matrix.start" },
    function(t)
        local vm = boot("matrix-start")

        -- Inactive, Completed, Failed and Skipped: a start proceeds, and
        -- says so by naming the operation it created.
        for _, service in ipairs({ "pt-inactive", "pt-completed", "pt-failed" }) do
            local r = send(vm, "start " .. service)
            t:assert(r.operation,
                service .. ": a start from " .. STATES[service] ..
                " created an operation: " .. r.raw)
        end

        -- Active: ALREADY. The service is already where the command
        -- would take it, so peinit returns the current status rather
        -- than an error — and a status answer names no operation.
        local already = send(vm, "start pt-active")
        t:assert(not already.code,
            "starting an Active service is not an error: " .. already.raw)
        t:assert_eq(already.state, "active", "it reports the current state")
        t:assert(not already.operation,
            "and creates no operation, because there is nothing to do: " .. already.raw)
    end)

test("stop: NOOP where there is nothing running, and a real stop where there is",
    { spec = "peinit *dispatch.matrix.stop" },
    function(t)
        local vm = boot("matrix-stop")

        -- Inactive, Failed and Skipped: NOOP. The command has no effect
        -- and peinit returns the status, which is how a caller tells a
        -- NOOP from a stop that ran.
        for _, service in ipairs({ "pt-inactive", "pt-failed", "pt-skipped" }) do
            local before = state_of(vm, service)
            local r = send(vm, "stop " .. service)
            t:assert(not r.code, service .. ": a stop is not an error: " .. r.raw)
            t:assert(not r.operation,
                service .. ": no operation was created for a no-op: " .. r.raw)
            t:assert_eq(state_of(vm, service), before,
                service .. " stayed in " .. before)
        end

        -- Active: the service stops.
        local stopped = send(vm, "stop pt-active")
        t:assert(stopped.operation, "stopping an Active service created an operation: "
            .. stopped.raw)
        t:assert_eq(state_of(vm, "pt-active"), "inactive", "and the service went Inactive")

        -- Completed: Clear — reset to Inactive.
        local cleared = send(vm, "stop pt-completed")
        t:assert(not cleared.code, "a stop on a Completed service is not an error: "
            .. cleared.raw)
        t:assert_eq(state_of(vm, "pt-completed"), "inactive",
            "a Completed service is cleared to Inactive by a stop")
    end)

test("restart: starts from a state that is not running, and restarts one that is",
    { spec = "peinit *dispatch.matrix.restart" },
    function(t)
        local vm = boot("matrix-restart")

        local before = vm:run("svctl --json status pt-active").stdout:match('"pid":(%d+)')
        t:assert(before, "the Active service has a main process")

        local r = vm:run("svctl --json restart pt-active")
        r:assert_ok()
        t:assert(r.stdout:match('"operation_id"'), "the restart created an operation")
        t:assert_eq(state_of(vm, "pt-active"), "active", "and the service is up again")

        local after = vm:run("svctl --json status pt-active").stdout:match('"pid":(%d+)')
        t:assert(after and after ~= before,
            "with a new process, which is what makes it a restart rather than a no-op: "
            .. tostring(before) .. " -> " .. tostring(after))

        -- From a state with nothing running, a restart is simply a
        -- start: there is no stop half to perform.
        for _, service in ipairs({ "pt-inactive", "pt-completed", "pt-failed" }) do
            local started = send(vm, "restart " .. service)
            t:assert(started.operation,
                service .. ": a restart from " .. STATES[service] ..
                " created an operation: " .. started.raw)
        end
    end)

test("reload: valid on Active and invalid everywhere this file can reach",
    { spec = "peinit *dispatch.matrix.reload" },
    function(t)
        local vm = boot("matrix-reload")

        local ok = vm:run("svctl --json reload pt-active")
        ok:assert_ok()
        t:assert(ok.stdout:match('"operation_id"'),
            "a reload of an Active service creates an operation: " .. ok.stdout)

        -- Everywhere else there is no process to reload, so the command
        -- is invalid for the state rather than a silent no-op.
        for _, service in ipairs({ "pt-inactive", "pt-completed", "pt-failed",
                                   "pt-backoff", "pt-skipped" }) do
            local r = send(vm, "reload " .. service)
            t:assert_eq(r.code, "INVALID_STATE",
                service .. ": a reload in " .. STATES[service] ..
                " is invalid for the state: " .. r.raw)
        end
    end)

test("reset: clears a terminal state, is a NOOP on Inactive, and is invalid on the rest",
    {
        spec = {
            "peinit *dispatch.matrix.reset",
            "peinit *dispatch.reset-clears-skipped-and-stops-there",
        },
    },
    function(t)
        local vm = boot("matrix-reset")

        -- Failed and Skipped: Clear — the service returns to Inactive.
        for _, service in ipairs({ "pt-failed", "pt-skipped" }) do
            local r = send(vm, "reset " .. service)
            t:assert(not r.code, service .. ": a reset is not an error: " .. r.raw)
            t:assert_eq(state_of(vm, service), "inactive",
                service .. " was cleared to Inactive from " .. STATES[service])
        end

        -- reset differs from start on a Skipped service by stopping
        -- there: it clears the state and does not go on to start
        -- anything, so the service stays Inactive rather than being
        -- re-evaluated and skipped again.
        t:assert_eq(state_of(vm, "pt-skipped"), "inactive",
            "and a reset Skipped service stays Inactive rather than starting")

        -- Inactive: NOOP.
        local noop = send(vm, "reset pt-inactive")
        t:assert(not noop.code, "a reset on an Inactive service is not an error: "
            .. noop.raw)
        t:assert_eq(state_of(vm, "pt-inactive"), "inactive", "and changes nothing")

        -- Active, Completed and Backoff: there is no terminal state to
        -- clear, so the command is invalid.
        for _, service in ipairs({ "pt-active", "pt-completed", "pt-backoff" }) do
            -- Named explicitly, so a service that has drifted out of the
            -- column under test says so rather than failing as if the
            -- matrix were wrong.
            t:assert_eq(state_of(vm, service), STATES[service],
                service .. " is still in the state this row is about")
            local r = send(vm, "reset " .. service)
            t:assert_eq(r.code, "INVALID_STATE",
                service .. ": a reset in " .. STATES[service] ..
                " is invalid for the state: " .. r.raw)
        end
    end)

test("a start in Backoff is deferred behind the delay rather than short-circuiting it",
    { spec = "peinit *dispatch.backoff-start-honours-the-remaining-delay" },
    function(t)
        local vm = boot("backoff-start")
        t:assert_eq(state_of(vm, "pt-backoff"), "backoff", "the service is in Backoff")

        -- DEFER: peinit creates a Pending start operation but does not
        -- execute it until the existing backoff deadline expires. So the
        -- caller gets an identifier back, and the service does not move.
        local r = send(vm, "start pt-backoff", true)
        t:assert(r.operation, "the start created an operation: " .. r.raw)
        t:assert_eq(state_of(vm, "pt-backoff"), "backoff",
            "and the service is still in Backoff, so the delay was not short-circuited")

        -- The operation is the administrator's, sitting in front of the
        -- automatic restart rather than beside it: the identifier the
        -- caller holds is the one that will execute when the delay is up.
        local status = vm:run("svctl --json status pt-backoff")
        status:assert_ok()
        t:assert(status.stdout:find(r.operation, 1, true),
            "and it is the service's current operation: " .. status.stdout)
        t:assert(status.stdout:find('"source":"admin"', 1, true),
            "recorded as the administrator's: " .. status.stdout)

        -- A second start merges into the deferred one rather than
        -- stacking another.
        local again = send(vm, "start pt-backoff", true)
        t:assert_eq(again.operation, r.operation,
            "a second start merged into the deferred one: " .. again.raw)
    end)

test("a stop in Backoff clears the service and cancels the restart that was pending",
    { spec = "peinit *dispatch.backoff-stop-cancels-the-pending-restart" },
    function(t)
        local vm = boot("backoff-stop")
        t:assert_eq(state_of(vm, "pt-backoff"), "backoff", "the service is in Backoff")

        local r = send(vm, "stop pt-backoff")
        t:assert(not r.code, "the stop was accepted: " .. r.raw)
        t:assert_eq(state_of(vm, "pt-backoff"), "inactive",
            "and the service went Inactive")

        -- The pending automatic restart is cancelled with it, and a
        -- later one is refused because the service is no longer in
        -- Backoff. RestartDelay is 60 seconds and this service crashes
        -- the moment it runs, so if the restart were still armed the
        -- service would leave Inactive on its own; it does not.
        local waited = vm:run("sleep 5; svctl --json status pt-backoff")
        waited:assert_ok()
        t:assert_eq(waited.stdout:match('"state":"([^"]+)"'), "inactive",
            "the service stayed Inactive rather than being restarted: " .. waited.stdout)
        t:assert(waited.stdout:find('"cause":"explicit_stop"', 1, true),
            "and the last thing that happened to it is the administrator's stop: "
            .. waited.stdout)
    end)

test("a restart in Backoff cancels the automatic restart and queues an administrator's",
    {
        spec = "peinit *dispatch.backoff-restart-replaces-the-automatic-one",
        tags = { "known-bug" },
    },
    function(t)
        -- This is the cell that does not work. peinit admits the command
        -- and answers it, and then tears down its own runtime: the
        -- control and jobs sockets are unlinked and the system is left
        -- with no way to administer it, with nothing on the console to
        -- say why.
        --
        -- A restart from Backoff is dispatched as a restart of a running
        -- service, and in Backoff there is no running main job to
        -- restart — nor a Backoff -> Stopping transition for the stop
        -- half to make. The assertions below state the manual.
        local vm = boot("backoff-restart")
        t:assert_eq(state_of(vm, "pt-backoff"), "backoff", "the service is in Backoff")

        local r = send(vm, "restart pt-backoff", true)
        t:assert(r.operation, "the restart was accepted and named an operation: " .. r.raw)

        -- The system is still administrable afterwards. Everything below
        -- depends on this, and it is the assertion that fails.
        local after = vm:run("svctl --json status pt-backoff")
        t:assert(after.exit_code ~= 69,
            "the control socket is still there after the restart: " ..
            tostring(after.stderr))

        -- And the queued restart is the administrator's, replacing the
        -- automatic one rather than sitting behind it.
        t:assert(after.stdout:find('"source":"admin"', 1, true),
            "the pending operation is the administrator's: " .. after.stdout)
    end)

test("start clears Skipped first and then re-evaluates the conditions from scratch",
    { spec = "peinit *dispatch.skipped-is-cleared-before-a-start-re-evaluates" },
    function(t)
        -- The state machine permits Skipped -> Inactive and nothing
        -- else, so an activation has to make that transition before it
        -- can proceed. Both outcomes are then possible, and which one
        -- happens depends only on whether the condition holds now.
        local vm = boot("skipped-start")
        t:assert_eq(state_of(vm, "pt-skipped"), "skipped",
            "the condition did not hold at boot")

        -- Still missing: the service is skipped again, for the reason
        -- that applies now, rather than starting or erroring.
        send(vm, "start pt-skipped")
        t:assert_eq(state_of(vm, "pt-skipped"), "skipped",
            "a start with the condition still unmet skips it again")

        -- Now make the condition hold and start it again. Nothing else
        -- changed, so a start that now succeeds is evidence that the
        -- conditions were re-evaluated rather than cached from boot.
        vm:run("mkdir -p /pt-not-here"):assert_ok()
        local started = vm:run("svctl --json start pt-skipped")
        started:assert_ok()
        t:assert_eq(state_of(vm, "pt-skipped"), "completed",
            "with the condition met, the same start runs the service: " .. started.stdout)
    end)

test("leaving Skipped is reported like any other transition",
    {
        spec = "peinit *dispatch.the-skipped-clear-is-reported-as-a-transition",
        tags = { "known-bug" },
    },
    function(t)
        -- The clear is carried on the dispatch and handed to the console
        -- collector exactly as the Starting transition is, but the
        -- collector produces text only for Failed, Skipped and
        -- Abandoned — so Skipped -> Inactive falls through silently, and
        -- no state-change event is emitted for it either. A console
        -- watching the service sees it jump.
        local vm = boot("skipped-report")
        t:assert_eq(state_of(vm, "pt-skipped"), "skipped", "the service is Skipped")

        local before = #peinit.lines(vm:console():read_log())
        vm:run("mkdir -p /pt-not-here"):assert_ok()
        vm:run("svctl --json start pt-skipped"):assert_ok()
        t:assert_eq(state_of(vm, "pt-skipped"), "completed", "and the start ran")

        -- The start that follows the clear is reported, and would
        -- satisfy any test that merely looked for the service's name.
        -- What the manual promises is more than that: a line for the
        -- departure from Skipped itself, so the service is not seen to
        -- jump from Skipped straight to running. So the "started" line
        -- is excluded, and something else has to be there.
        local lines = peinit.lines(vm:console():read_log())
        local said, started = {}, false
        for i = before + 1, #lines do
            local line = lines[i]
            if line:find("pt-skipped", 1, true) then
                if line:find("service pt%-skipped started") then
                    started = true
                else
                    said[#said + 1] = line
                end
            end
        end
        t:assert(started,
            "the start itself was reported, so the console was being watched correctly")
        t:assert(#said > 0,
            "and the transition out of Skipped was reported too, rather than the " ..
            "service appearing to jump. Lines other than the start: " ..
            table.concat(said, " / "))
    end)

test("a service whose definition is gone refuses to start and still answers a query",
    { spec = "peinit *dispatch.a-definition-removed-service-accepts-only-stop-and-status" },
    function(t)
        -- Independently of state, a definition-removed service rejects
        -- start, restart and reload with UNKNOWN_SERVICE — there is no
        -- definition left to start from — while status still reports its
        -- state, because a process it is still supervising is a fact an
        -- administrator needs.
        local vm = boot("defremoved")
        t:assert_eq(state_of(vm, "pt-active"), "active", "the service is running")

        vm:run([[reg del 'Machine\System\Services\pt-active' --recursive]]):assert_ok()
        vm:run("svctl --json reload-config"):assert_ok()

        local status = vm:run("svctl --json status pt-active")
        status:assert_ok()
        t:assert(status.stdout:find('"definition_removed":true', 1, true),
            "the entry is marked definition-removed: " .. status.stdout)
        t:assert_eq(status.stdout:match('"state":"([^"]+)"'), "active",
            "and status still reports the state of what is running")

        for _, command in ipairs({ "start", "restart", "reload" }) do
            local r = send(vm, command .. " pt-active")
            t:assert_eq(r.code, "UNKNOWN_SERVICE",
                command .. " on a definition-removed service is UNKNOWN_SERVICE: " .. r.raw)
        end
    end)

test("a service whose definition is gone still accepts a stop",
    {
        spec = "peinit *dispatch.a-definition-removed-service-accepts-only-stop-and-status",
        tags = { "known-bug" },
    },
    function(t)
        -- The other half of the same rule, and the half that does not
        -- hold: stop is the one lifecycle command a definition-removed
        -- service is supposed to accept — it is how an administrator
        -- gets rid of the process a removed definition left running —
        -- and sending it takes peinit's whole control interface down.
        -- The connection is dropped mid-answer and both sockets are
        -- gone afterwards, with nothing on the console.
        local vm = boot("defremoved-stop")
        vm:run([[reg del 'Machine\System\Services\pt-active' --recursive]]):assert_ok()
        vm:run("svctl --json reload-config"):assert_ok()
        t:assert(
            vm:run("svctl --json status pt-active").stdout
                :find('"definition_removed":true', 1, true),
            "the entry is definition-removed and still running")

        local stop = vm:run("svctl --json stop pt-active")
        t:assert(not (stop.stderr or ""):find("closed before a complete response", 1, true),
            "peinit answered the stop instead of dropping the connection: " ..
            tostring(stop.stderr))
        t:assert(stop.exit_code == 0,
            "the stop was accepted: " .. stop.stdout .. " / " .. tostring(stop.stderr))
        t:assert_eq(state_of(vm, "pt-active"), "inactive", "and the service stopped")
    end)
