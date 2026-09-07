-- Peinit TRM §10.2 — the fixed sequence a parsed command runs before it
-- does anything: the shutdown gate, target resolution, the access check,
-- and what is filtered rather than denied.
--
-- Everything reachable here is on the resolution and filtering side. The
-- access check itself needs a caller peinit will refuse, and this
-- profile has one principal — SYSTEM — with every right on everything,
-- so the rights table and the denial path are stated in the manual and
-- left for a suite that can log a second principal on.

local peinit = require("helpers.peinit")
peinit.claim(2)

local function resident(name)
    return {
        path = [[Machine\System\Services\]] .. name,
        values = {
            { name = "ImagePath", type = "sz", data = "/bin/sleep" },
            { name = "Arguments", type = "multi", data = { "100000" } },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
            { name = "RestartPolicy", type = "dword", data = 0 },
            { name = "Triggers", type = "multi", data = { "boot" } },
        },
    }
end

local files = peinit.seed("pt-dispatch", {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },
    resident("pt-resident"),
})

local vm = peinit.boot({ name = "dispatch", files = files })

--- `svctl --json …`, as the decoded error code or nil when it succeeded.
local function error_code(vm, command)
    return vm:run("svctl --json " .. command).stdout:match('"code":"([^"]+)"')
end

test("a command naming nothing peinit holds is answered as unknown, by kind",
    { spec = "peinit *dispatch.an-unresolvable-target-is-unknown" },
    function(t)
        -- Resolution happens before the access check and before anything
        -- else: peinit does not synthesise a descriptor for something
        -- that does not exist, so there is nothing to check against and
        -- the answer says only that the name resolved to nothing.
        t:assert_eq(error_code(vm, "status pt-no-such-service"), "UNKNOWN_SERVICE",
            "a service name nothing defines")
        t:assert_eq(error_code(vm, "start pt-no-such-service"), "UNKNOWN_SERVICE",
            "and the same for a lifecycle command")

        -- A job identifier is a different kind of name, and gets a
        -- different answer. The identifier below is well-formed — an
        -- unparseable one is refused earlier, as bad arguments.
        t:assert_eq(
            error_code(vm, "job status 00000000-0000-7000-8000-000000000000"),
            "UNKNOWN_JOB",
            "a job identifier naming no submitted job peinit holds")
    end)

test("an unknown operation identifier is reported as unknown rather than refused",
    { spec = "peinit *dispatch.operation-status-resolves-before-it-checks" },
    function(t)
        -- operation-status resolves the operation before it checks the
        -- right, so an identifier that names nothing is unknown
        -- regardless of who asked. The half of that visible from a
        -- caller with every right is that resolution really does come
        -- first: a well-formed identifier for an operation that never
        -- existed returns UNKNOWN_OPERATION, not a right-related error.
        t:assert_eq(
            error_code(vm, "op 00000000-0000-7000-8000-000000000000"),
            "UNKNOWN_OPERATION",
            "an operation identifier that resolves to nothing")

        -- And an identifier that does resolve is answered, which is what
        -- makes the negative above worth anything.
        local ack = vm:run("svctl --json restart pt-resident")
        ack:assert_ok()
        local id = ack.stdout:match('"operation_id":"([^"]+)"')
        t:assert(id, "a restart produced an operation identifier: " .. ack.stdout)
        local view = vm:run("svctl --json op " .. id)
        view:assert_ok()
        t:assert(view.stdout:find(id, 1, true),
            "and operation-status resolved it: " .. view.stdout)
    end)

test("a definition-removed service is in the list, and the list does not say so",
    { spec = "peinit *dispatch.a-definition-removed-service-is-listed-without-saying-so" },
    function(t)
        -- The rule is a pair, and both halves matter: omitting the
        -- service from `list` would make a running process invisible,
        -- while flagging it there would put a fact in a bulk listing
        -- that only a deliberate query should surface.
        local other = peinit.boot({
            name = "defremoved-list",
            files = peinit.seed("pt-defrm", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                resident("pt-resident"),
            }),
        })
        other:run([[reg del 'Machine\System\Services\pt-resident' --recursive]]):assert_ok()
        other:run("svctl --json reload-config"):assert_ok()

        local status = other:run("svctl --json status pt-resident")
        status:assert_ok()
        t:assert(status.stdout:find('"definition_removed":true', 1, true),
            "a status query says the definition is gone: " .. status.stdout)

        local list = other:run("svctl --json list")
        list:assert_ok()
        -- Pick the one entry out of the array and look at it alone: the
        -- other services carry no such field either, so searching the
        -- whole document would prove nothing.
        local entry = list.stdout:match('{[^{}]*"service":"pt%-resident"[^{}]*}')
        t:assert(entry, "the service is still listed: " .. list.stdout)
        t:assert(not entry:find("definition_removed", 1, true),
            "and its list entry does not mention it: " .. entry)
    end)

test("job-stop stops the job directly and creates no operation",
    { spec = "peinit *dispatch.job-stop-creates-no-operation" },
    function(t)
        -- A lifecycle command on a service returns the identifier of the
        -- operation it created, and `svctl op` can then be asked about
        -- it. job-stop is not that: it stops the job itself, and the
        -- answer it gives back is the job's own terminal view.
        local submit = vm:run("svctl --json job submit /bin/sleep 300")
        submit:assert_ok()
        local id = submit.stdout:match('"id":"([^"]+)"')
        t:assert(id, "a job was submitted: " .. submit.stdout)

        local stop = vm:run("svctl --json job stop " .. id)
        stop:assert_ok()
        t:assert(not stop.stdout:find("operation_id", 1, true),
            "the answer names no operation: " .. stop.stdout)
        t:assert(not stop.stdout:find('"operation"', 1, true),
            "and carries no operation of any other name: " .. stop.stdout)
        t:assert(stop.stdout:find('"id":"' .. id .. '"', 1, true),
            "it is the job's own view that comes back: " .. stop.stdout)
    end)

test("job-list narrows by its request filters before anything else looks at an entry",
    {
        spec = {
            "peinit *dispatch.job-list-filters-before-it-checks",
            "peinit *dispatch.terminal-jobs-within-retention-are-listed",
        },
    },
    function(t)
        -- Two jobs in different states, so a state filter has something
        -- to remove. The response does not say whether a filter or a
        -- right took an entry out, which is the point of running the
        -- filters first.
        local done = vm:run("svctl --json job submit /bin/true")
        done:assert_ok()
        local done_id = done.stdout:match('"id":"([^"]+)"')

        local live = vm:run("svctl --json job submit /bin/sleep 300")
        live:assert_ok()
        local live_id = live.stdout:match('"id":"([^"]+)"')
        t:assert(done_id and live_id, "two jobs were submitted")

        -- A terminal job stays listed while it is within its retention,
        -- which is why a caller that wants only live ones has to say so.
        local all = vm:run("svctl --json job list")
        all:assert_ok()
        t:assert(all.stdout:find(done_id, 1, true),
            "the job that already finished is still listed: " .. all.stdout)
        t:assert(all.stdout:find(live_id, 1, true), "and so is the running one")

        local running = vm:run("svctl --json job list --state running")
        running:assert_ok()
        t:assert(running.stdout:find(live_id, 1, true),
            "filtering by state keeps the running job: " .. running.stdout)
        t:assert(not running.stdout:find(done_id, 1, true),
            "and removes the terminal one: " .. running.stdout)

        -- A filter that matches nothing is an empty, successful answer
        -- rather than an error — the same shape a fully filtered-out
        -- list has, so the two are indistinguishable to the caller.
        local none = vm:run("svctl --json job list --submitter S-1-5-21-0-0-0-1000")
        none:assert_ok()
        t:assert(none.stdout:find('"jobs":[]', 1, true),
            "a filter matching nothing answers with an empty list: " .. none.stdout)

        vm:run("svctl --json job stop " .. live_id)
    end)

test("the shutdown gate refuses the lifecycle commands and keeps the query ones",
    { spec = "peinit *dispatch.the-shutdown-gate" },
    function(t)
        -- While peinit is shutting down, everything except status, list,
        -- operation-status, job-status, job-list and job-stop is
        -- rejected. Catching that needs a shutdown slow enough to ask a
        -- question during, so this boot carries a service that ignores
        -- SIGTERM: peinit waits out its StopTimeout before killing it,
        -- and the window is that wait.
        local seed = peinit.seed("pt-gate", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                {
                    path = [[Machine\System\Services\pt-stubborn]],
                    values = {
                        { name = "ImagePath", type = "sz", data = "/bin/sh" },
                        -- A loop rather than one long sleep: SIGTERM goes
                        -- to the whole cgroup, so a single `sleep 600`
                        -- child dies on the first signal and takes the
                        -- shell's exit with it. Re-running a short sleep
                        -- keeps the shell — which ignores TERM — alive
                        -- for the full StopTimeout.
                        { name = "Arguments", type = "multi",
                          data = { "-c", "trap '' TERM; while :; do sleep 1; done" } },
                        { name = "Identity", type = "sz", data = "SYSTEM" },
                        { name = "Readiness", type = "dword", data = 1 },
                        { name = "StopTimeout", type = "dword", data = 30 },
                        { name = "RestartPolicy", type = "dword", data = 0 },
                        { name = "Triggers", type = "multi", data = { "boot" } },
                    },
                },
        })

        -- The window still opens and closes in the time a couple of
        -- svctl invocations take, and whether a probe lands inside it
        -- depends on how the guest is scheduled. Two things make that
        -- reliable rather than lucky. The shutdown is requested from
        -- inside the probe loop, a few iterations in, so the loop is
        -- already hot when it starts; and the whole race is run again on
        -- a fresh VM if it is lost, because a machine that has begun
        -- shutting down cannot be asked twice.
        local probe, missed
        for attempt = 1, 3 do
            local other = peinit.boot({
                name = "shutdown-gate-" .. attempt,
                files = seed,
            })

            -- The window depends on that service actually holding the
            -- shutdown open, so check it is up before racing anything.
            t:assert(other:run("svctl --json status pt-stubborn").stdout
                    :find('"state":"active"', 1, true),
                "the service that will hold the shutdown open is running")

            -- The moment the gated command lands, the two ungated
            -- commands are asked and their answers kept verbatim.
            --
            -- What the ungated pair is asserted on afterwards is that
            -- neither was *refused*, rather than that both were
            -- answered: the socket goes away with the runtime at the end
            -- of the shutdown, so a command issued microseconds after
            -- the gate was observed may find nothing to connect to. That
            -- is not the rule failing. Being told INVALID_STATE would be.
            local run = other:run(
                "i=0; while [ $i -lt 5000 ]; do " ..
                "  [ $i -eq 3 ] && { svctl shutdown poweroff >/dev/null 2>&1 & }; " ..
                "  out=$(svctl --json start pt-stubborn 2>&1); " ..
                "  case \"$out\" in " ..
                "    *INVALID_STATE*) " ..
                "      echo \"GATED:$out\"; " ..
                "      echo \"LIST:$(svctl --json list 2>&1)\"; " ..
                "      echo \"JOBLIST:$(svctl --json job list 2>&1)\"; " ..
                "      break;; " ..
                "    *'No such file'*) echo MISSED; break;; " ..
                "  esac; i=$((i+1)); done; echo END",
                { timeout = 120 })

            if run.stdout:find("GATED:", 1, true) then
                probe = run.stdout
                break
            end
            missed = run.stdout
            -- A lost race leaves a machine that is shutting down anyway.
            -- Release it before the next attempt, so the retries never
            -- hold more of the file's claim than one gate VM at a time.
            other:shutdown()
        end

        t:assert(probe,
            "a lifecycle command during shutdown was refused, in three attempts. " ..
            "Last: " .. tostring(missed))

        -- The gate runs before the access check, so the refusal says the
        -- command is invalid for the current state rather than that the
        -- caller lacks a right. This caller has every right, so the code
        -- is the only thing that distinguishes the two.
        t:assert(probe:find('GATED:.*"code":"INVALID_STATE"'),
            "and refused as invalid for the state, not as ACCESS_DENIED: " .. probe)
        t:assert(not probe:find("ACCESS_DENIED", 1, true),
            "nothing was answered as a denial: " .. probe)

        -- list and job-list are two of the six commands the gate lets
        -- through. job-list stays open because a shutdown stops every
        -- submitted job anyway, and an administrator watching that has a
        -- reason to ask.
        local list = probe:match("LIST:([^\r\n]*)")
        local job_list = probe:match("JOBLIST:([^\r\n]*)")
        t:assert(list and job_list, "both ungated commands were tried: " .. probe)
        t:assert(not list:find("INVALID_STATE", 1, true),
            "`list` was not refused by the gate: " .. list)
        t:assert(not job_list:find("INVALID_STATE", 1, true),
            "nor was `job-list`: " .. job_list)
    end)
