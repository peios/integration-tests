-- peinit TRM §3.8 — service removal: what happens to an entry when its
-- definition disappears, which turns entirely on whether there is a
-- process still to supervise.
--
-- §10.2 and §10.3 own what a definition-removed service *answers* to a
-- control request (their `dispatch.*` anchors, in `control-matrix`).
-- What §3.8 owns, and what this file is, is the two dispositions: an
-- entry with nothing running is discarded on the spot, and an entry
-- with something running is kept, marked, and discarded when that
-- something goes away.
--
-- The not-running half needs a service in each of the states §3.8 lists,
-- so the seed carries five of them and each is driven into its state at
-- boot. `pt-backoff` is the one worth explaining: it exits non-zero and
-- restarts always, with a thirty-second first delay, so it sits between
-- attempts for long enough to have its definition pulled out from under
-- it. It is also the interesting case -- it looks like it has something
-- pending, and it does not.
--
-- Nothing here sends `stop` to a definition-removed service. §10.3 has
-- that case, and records that it currently takes peinit's control
-- interface down with it -- which would take every later test in this
-- file with it too. Every instance here is ended by killing its process.

local peinit = require("helpers.peinit")
peinit.claim(1)

local FILES = {
    -- Ignores SIGTERM, so a stop leg lasts its whole StopTimeout and
    -- there is a window to remove a definition in.
    ["pt/stubborn.sh"] = [[
trap '' TERM
while true; do /bin/sleep 1; done
]],
}

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },
}

local function service(name, values)
    SERVICES[#SERVICES + 1] =
        { path = [[Machine\System\Services\]] .. name, values = values }
end

local function daemon(name, extra)
    local values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "100000" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
    }
    for _, value in ipairs(extra) do
        local replaced = false
        for i, existing in ipairs(values) do
            if existing.name:lower() == value.name:lower() then
                values[i] = value
                replaced = true
                break
            end
        end
        if not replaced then values[#values + 1] = value end
    end
    service(name, values)
end

-- One service in each of the states §3.8 says is discarded on the spot.
daemon("pt-inactive", {})
service("pt-failed", {
    { name = "ImagePath", type = "sz", data = "/bin/false" },
    { name = "Identity", type = "sz", data = "SYSTEM" },
    { name = "Type", type = "dword", data = 1 },
    { name = "RestartPolicy", type = "dword", data = 0 },
    { name = "Triggers", type = "multi", data = { "boot" } },
})
service("pt-completed", {
    { name = "ImagePath", type = "sz", data = "/bin/true" },
    { name = "Identity", type = "sz", data = "SYSTEM" },
    { name = "Type", type = "dword", data = 1 },
    { name = "RemainAfterExit", type = "dword", data = 1 },
    { name = "Triggers", type = "multi", data = { "boot" } },
})
daemon("pt-skipped", {
    { name = "Conditions", type = "multi", data = { "path:/pt-absent" } },
    { name = "Triggers", type = "multi", data = { "boot" } },
})
-- Exits at once and restarts always, on a delay wide enough to be
-- caught in.
service("pt-backoff", {
    { name = "ImagePath", type = "sz", data = "/bin/false" },
    { name = "Identity", type = "sz", data = "SYSTEM" },
    { name = "Readiness", type = "dword", data = 1 },
    { name = "RestartPolicy", type = "dword", data = 2 },
    { name = "RestartDelay", type = "dword", data = 40 },
    { name = "RestartMaxRetries", type = "dword", data = 20 },
    { name = "RestartWindow", type = "dword", data = 600 },
    { name = "Triggers", type = "multi", data = { "boot" } },
})

-- The running half. pt-gone restarts always, so "not restarted" after
-- its definition goes is a policy that would otherwise have applied;
-- pt-stay is the identical service with its definition left alone, and
-- is what shows the policy applying.
local function restarting(name)
    service(name, {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "100000" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 2 },
        { name = "RestartDelay", type = "dword", data = 1 },
        { name = "RestartMaxRetries", type = "dword", data = 10 },
        { name = "RestartWindow", type = "dword", data = 600 },
        { name = "Triggers", type = "multi", data = { "boot" } },
    })
end
restarting("pt-gone")
restarting("pt-stay")

-- There is deliberately no service here that hard-requires pt-gone.
--
-- §3.8's two dependent claims -- that a definition-removed instance
-- keeps satisfying its dependents, and that after the discard the
-- dependent's next start sees an unresolved dependency -- cannot be
-- staged from the registry. A read in which one service `Requires`
-- another that the read does not define is refused entire by graph
-- validation (`MissingHardDependency`), and a refused reload applies
-- nothing at all: the removal itself never lands. Leaving such a
-- dependent in the seed does not fail those two tests, it silently
-- disables every removal in the file, which is how this was found.

-- A service whose stop leg lasts, for the restart-in-its-stop-phase
-- case.
service("pt-drain", {
    { name = "ImagePath", type = "sz", data = "/bin/sh" },
    { name = "Arguments", type = "multi", data = { "/pt/stubborn.sh" } },
    { name = "Identity", type = "sz", data = "SYSTEM" },
    { name = "Readiness", type = "dword", data = 1 },
    { name = "StopTimeout", type = "dword", data = 15 },
    { name = "RestartPolicy", type = "dword", data = 0 },
    { name = "Triggers", type = "multi", data = { "boot" } },
})

local vm = peinit.boot({
    name = "removal",
    files = peinit.merge(FILES, peinit.seed("pt-removal", SERVICES)),
})

local function status(service_name)
    local r = vm:run("svctl --json status " .. service_name)
    if r.stdout:find("UNKNOWN_SERVICE", 1, true) then return nil end
    local ok, decoded = pcall(json.decode, r.stdout)
    return ok and decoded or nil
end

local function pid_of(service_name)
    local st = status(service_name)
    return st and st.current_job and st.current_job.pid or nil
end

local function await(service_name, state, timeout)
    return wait_until(function()
        local st = status(service_name)
        return st and st.state == state and st or nil
    end, {
        timeout = timeout or 90, interval = 0.4,
        desc = service_name .. " to reach " .. state,
    })
end

--- Delete a service's key. No reload-config: §3.8 says peinit learns of
--- a removal through the ordinary change-notification path, and every
--- test in this file leans on that.
local function remove_definition(service_name)
    vm:run([[reg del 'Machine\System\Services\]] .. service_name ..
        [[' --recursive]]):assert_ok()
end

local function forgotten(service_name, timeout)
    return wait_until(function()
        return status(service_name) == nil and true or nil
    end, {
        timeout = timeout or 60, interval = 0.4,
        desc = service_name .. " to be discarded",
    })
end

test("an entry with nothing running is discarded as soon as the removal arrives",
    {
        spec = {
            "peinit *remove.a-removal-arrives-through-the-watch",
            "peinit *remove.a-non-running-entry-is-discarded-immediately",
        },
    },
    function(t)
        -- Four of the states §3.8 lists, each reached at boot and each
        -- discarded when its key goes. Nothing issues a reload-config:
        -- the deletion alone is the input, which is the
        -- change-notification claim.
        local expected = {
            ["pt-inactive"] = "inactive",
            ["pt-failed"] = "failed",
            ["pt-completed"] = "completed",
            ["pt-skipped"] = "skipped",
        }
        for service_name, state in pairs(expected) do
            local st = await(service_name, state)
            t:assert_eq(st.state, state, service_name .. " is " .. state)
        end

        for service_name in pairs(expected) do
            remove_definition(service_name)
        end

        local left = {}
        for service_name in pairs(expected) do
            local ok = pcall(forgotten, service_name)
            if not ok then
                left[#left + 1] = service_name .. " (" ..
                    tostring((status(service_name) or {}).state) .. ")"
            end
        end
        t:assert_eq(#left, 0,
            "every non-running entry was discarded; these survived: " ..
            table.concat(left, ", "))

        -- And the discard is total, not a marking: `list` does not carry
        -- them either.
        local list = vm:run("svctl --json list")
        list:assert_ok()
        t:assert(not list.stdout:find("pt-inactive", 1, true),
            "the discarded entries are gone from the list too: " .. list.stdout)
    end)

test("a service in Backoff is discarded like any other entry with nothing running",
    { spec = "peinit *remove.backoff-is-discarded-like-any-other-non-running-state" },
    function(t)
        -- The case that is not obvious. A service between restart
        -- attempts looks like it has something pending -- there is a
        -- restart coming -- but it has no process, and once the
        -- definition is gone there is nothing left to restart it from.
        -- So there is neither an instance to supervise nor a restart to
        -- wait for, and the entry goes.
        local backoff = await("pt-backoff", "backoff", 120)
        t:assert_eq(backoff.state, "backoff", "the service is between attempts")
        t:assert(backoff.current_job == nil,
            "with no process: that is why it belongs in the discard list")

        remove_definition("pt-backoff")
        forgotten("pt-backoff")
        t:assert(status("pt-backoff") == nil,
            "the entry was discarded rather than kept waiting for a restart " ..
            "that can never happen")
    end)

test("an entry with a running instance is not killed: it is marked definition-removed",
    {
        spec = {
            "peinit *remove.a-running-instance-is-not-killed",
            "peinit *remove.the-entry-is-marked-definition-removed",
        },
    },
    function(t)
        -- The running process is a job, and a job's lifecycle is
        -- independent of the definition that produced it. Removing the
        -- definition stops future management; it does not terminate work
        -- in progress.
        local before = await("pt-gone", "active")
        local pid = before.current_job.pid

        remove_definition("pt-gone")

        local marked = wait_until(function()
            local st = status("pt-gone")
            return st and st.definition_removed and st or nil
        end, { timeout = 60, interval = 0.4,
               desc = "pt-gone to be marked definition-removed" })
        t:assert_eq(marked.state, "active",
            "the service is still Active: " .. tostring(marked.state))
        t:assert_eq(marked.definition_removed, true,
            "and marked definition-removed")
        t:assert_eq(pid_of("pt-gone"), pid,
            "on the same process, which was never signalled")
        t:assert_eq(vm:run("test -d /proc/" .. tostring(pid)).exit_code, 0,
            "and which is still alive in the kernel")
    end)

test("when the instance exits it is not restarted, and the entry is discarded",
    {
        spec = {
            "peinit *remove.an-exit-is-not-restarted-and-the-entry-is-discarded",
            "peinit *remove.a-crash-is-routed-to-failed-rather-than-a-restart",
        },
    },
    function(t)
        -- pt-gone restarts always. Its definition is gone, so
        -- RestartPolicy is moot: there is nothing left to restart from,
        -- and a crash is routed to Failed rather than into a restart.
        -- The entry is then discarded.
        local pid = pid_of("pt-gone")
        t:assert(pid, "pt-gone is still running its original instance")

        vm:run("kill -9 " .. tostring(pid))
        forgotten("pt-gone")
        t:assert(status("pt-gone") == nil,
            "the entry went with the instance, rather than going round the " ..
            "restart policy")

        -- pt-stay is the identical definition, left in the registry. The
        -- same kill restarts it, so the policy really would have applied
        -- to pt-gone had there been a definition to apply it from.
        local stay = await("pt-stay", "active")
        local stay_pid = stay.current_job.pid
        vm:run("kill -9 " .. tostring(stay_pid))
        local restarted = wait_until(function()
            local st = status("pt-stay")
            local now = st and st.current_job and st.current_job.pid
            return now and now ~= stay_pid and st or nil
        end, { timeout = 90, interval = 0.4, desc = "pt-stay to be restarted" })
        t:assert(restarted.current_job.pid ~= stay_pid,
            "the service whose definition survived was restarted after the same kill")
    end)

test("a restart already in its stop phase drains the instance and is then aborted",
    { spec = "peinit *remove.a-restart-in-its-stop-leg-is-aborted" },
    function(t)
        -- The window a package upgrade opens: remove the definition,
        -- then restart the service. The stop phase still drains the
        -- existing instance -- it is work in progress -- but the start
        -- phase has nothing to start from, so the operation is abandoned
        -- with a reason that says exactly that, and the entry takes the
        -- ordinary removal discard.
        local before = await("pt-drain", "active")
        local pid = before.current_job.pid

        local restart = vm:run("svctl --json restart pt-drain --no-wait")
        restart:assert_ok()
        local operation = restart.stdout:match('"operation_id":"([^"]+)"')
        t:assert(operation, "the restart reported an operation: " .. restart.stdout)
        t:assert(vm:run("svctl --json operation-status " .. operation).stdout
            :find('"type":"restart"', 1, true),
            "and it is the restart, which is what has a stop leg and a start leg")

        -- pt-drain ignores SIGTERM, so the stop leg lasts its fifteen
        -- second StopTimeout and there is time to pull the definition
        -- out from under it.
        await("pt-drain", "stopping", 30)
        remove_definition("pt-drain")

        local marked = wait_until(function()
            local st = status("pt-drain")
            return st and st.definition_removed and st or nil
        end, { timeout = 60, interval = 0.4,
               desc = "pt-drain to be marked definition-removed mid-stop" })
        t:assert_eq(marked.state, "stopping",
            "the stop leg is still draining the instance: " .. tostring(marked.state))
        t:assert_eq(pid_of("pt-drain"), pid, "on the process it started with")

        -- When the instance finally goes, the start leg does not begin --
        -- there is nothing to start from -- and the entry takes the
        -- ordinary removal discard.
        --
        -- The abort's own reason string,
        -- `definition_removed_during_restart_stop_leg`, is not readable
        -- from here: the operation record is discarded with the entry,
        -- so `operation-status` answers UNKNOWN_SERVICE from the moment
        -- the instance exits, and the string reaches neither the console
        -- nor any query. What is observable is everything around it.
        forgotten("pt-drain", 90)
        t:assert(status("pt-drain") == nil,
            "the entry took the ordinary removal discard when the instance exited")
        t:assert(vm:run("test -d /proc/" .. tostring(pid)).exit_code ~= 0,
            "the instance it was draining is gone")

        -- The start leg never ran: a restart that had reached its start
        -- phase would have left a second process behind, and there is no
        -- process for this service at all.
        local procs = vm:run(
            "for p in /proc/[0-9]*; do cat $p/cmdline 2>/dev/null | tr '\\0' ' '; " ..
            "echo; done")
        t:assert(not procs.stdout:find("/pt/stubborn.sh", 1, true),
            "and nothing was started in its place: " .. procs.stdout)

        -- And the operation went with it, rather than being left live
        -- against a service that no longer exists.
        local final = vm:run("svctl --json operation-status " .. operation)
        t:assert(final.exit_code ~= 0,
            "the restart operation is no longer live: " .. final.stdout)
    end)
