-- peinit TRM §7.3 — graph execution: starting everything whose
-- dependencies are satisfied, again and again, until nothing is left.
--
-- The oracle for most of this is `graph.operation_terminal`, the KMES
-- event peinit emits when a member of an execution context reaches a
-- terminal outcome. It carries the context the event was dispatched
-- through, which is the only place a *context* is visible from the
-- guest at all: `svctl` has no vocabulary for one. That is what makes
-- "one boot context and one per explicit start", and "one event per
-- associated context", checkable rather than merely plausible.
--
-- Two claims here are about what does NOT happen — a dependency already
-- satisfying is not restarted, a dormant sub-tree is not started — so
-- each has a companion in the same seed that does happen, and the pair
-- is the evidence. A test that only asserts an absence cannot tell a
-- rule being followed from a graph that never reached the case.

-- Every machine here is booted with 800 MiB rather than the helper's
-- default gigabyte, and the claim says so. A booted guest uses about
-- 300 MiB — the squashfs is read off the medium rather than held in RAM
-- — so the assertions are identical at either size, and a file that
-- claims 1.8 GiB instead of 2.2 GiB still fits a pool several of these
-- files are queueing against.

local peinit = require("helpers.peinit")
peinit.claim(2, { memory_mib = 800 })

--- Wait until `text` appears anywhere in the console log.
---
--- `console():expect` consumes the stream up to whatever it matched, so
--- a later call looking for a line that was already passed waits for a
--- second occurrence that never comes. Reading the whole accumulated log
--- instead makes the order the tests run in irrelevant, which matters
--- here because several of them assert on lines the boot produced.
local function wait_for_line(machine, text, why)
    return wait_until(function()
        return machine:console():read_log():find(text, 1, true) and true or nil
    end, { timeout = peinit.STAGE_TIMEOUT, interval = 0.5, desc = why or text })
end

local BOOT = { name = "Triggers", type = "multi", data = { "boot" } }

local function service(name, image, args, extra)
    local values = {
        { name = "ImagePath", type = "sz", data = image },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
    }
    if args then values[#values + 1] = { name = "Arguments", type = "multi", data = args } end
    for _, value in ipairs(extra or {}) do values[#values + 1] = value end
    return { path = [[Machine\System\Services\]] .. name, values = values }
end

local function oneshot(name, extra)
    local values = { { name = "Type", type = "dword", data = 1 } }
    for _, value in ipairs(extra or {}) do values[#values + 1] = value end
    return service(name, "/bin/true", nil, values)
end

local function daemon(name, extra)
    return service(name, "/bin/sleep", { "3600" }, extra)
end

local function requires(...) return { name = "Requires", type = "multi", data = { ... } } end
local function wants(...) return { name = "Wants", type = "multi", data = { ... } } end

local vm = peinit.boot({
    memory = "800M",
    name = "exec",
    files = peinit.seed("zz-pt-exec", {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },

        -- A chain, for ordering and for transitive failure propagation.
        -- pt-x-c fails, so pt-x-b and then pt-x-a must fail too.
        service("pt-x-c", "/bin/false", nil, { { name = "Type", type = "dword", data = 1 } }),
        oneshot("pt-x-b", { BOOT, requires("pt-x-c") }),
        oneshot("pt-x-a", { BOOT, requires("pt-x-b") }),

        -- A chain that works, for the release rule and for ordering.
        oneshot("pt-x-base"),
        oneshot("pt-x-mid", { requires("pt-x-base") }),
        oneshot("pt-x-top", { BOOT, requires("pt-x-mid") }),

        -- A dependency that is Active before anything asks for it.
        daemon("pt-x-resident", { BOOT }),
        oneshot("pt-x-usesresident", { requires("pt-x-resident") }),

        -- A dependency that never reports ready, so its operation stays
        -- live long enough to be read: Readiness=Notify on a service
        -- that never notifies.
        service("pt-x-neverready", "/bin/sleep", { "3600" },
            { { name = "Readiness", type = "dword", data = 0 } }),
        oneshot("pt-x-needsnotify", { requires("pt-x-neverready") }),

        -- Disabled: blocks a hard dependent on both paths, is skipped
        -- by a soft one, and can still be started by hand.
        oneshot("pt-x-off", { { name = "Disabled", type = "dword", data = 1 } }),
        oneshot("pt-x-hardoff", { BOOT, requires("pt-x-off") }),
        oneshot("pt-x-softoff", { BOOT, wants("pt-x-off") }),
        oneshot("pt-x-hardoff-ondemand", { requires("pt-x-off") }),

        -- A shared dependency slow enough that a second start of a
        -- different dependent lands while it is still in flight.
        service("pt-x-shared", "/bin/sleep", { "6" },
            { { name = "Type", type = "dword", data = 1 } }),
        oneshot("pt-x-sharer1", { requires("pt-x-shared") }),
        oneshot("pt-x-sharer2", { requires("pt-x-shared") }),

        -- A root whose pre-start condition does not hold, so it is
        -- terminated before its dependency was ever needed. The
        -- dependency is dormant at that moment, and gets pruned.
        oneshot("pt-x-dormant"),
        oneshot("pt-x-skipped", { BOOT, requires("pt-x-dormant"),
            { name = "Conditions", type = "multi", data = { "path:/pt-not-here" } } }),
    }),
})

local function status(name)
    return json.decode(vm:run("svctl --json status " .. name).stdout)
end

local function wait_for_state(name, state, why)
    return wait_until(function()
        local current = status(name)
        return current.state == state and current or nil
    end, { timeout = 60, interval = 0.4, desc = why or (name .. " to reach " .. state) })
end

--- Every `graph.operation_terminal` record, as a list of
--- {service, context_id, operation_id, outcome}.
local function terminals()
    local out = vm:run(
        "evctl 'EVENTS graph.operation_terminal SINCE 1h ago TAKE 600' --format jsonl").stdout
    local records = {}
    for line in out:gmatch("[^\r\n]+") do
        local service_name = line:match('"service":"([^"]*)"')
        if service_name then
            records[#records + 1] = {
                service = service_name,
                context_id = tonumber(line:match('"context_id":(%d+)')),
                operation_id = line:match('"operation_id":"([^"]*)"'),
                outcome = line:match('"outcome":"([^"]*)"'),
            }
        end
    end
    return records
end

local function wait_for_terminal(name, why)
    return wait_until(function()
        for _, record in ipairs(terminals()) do
            if record.service == name then return record end
        end
        return nil
    end, { timeout = 90, interval = 1, desc = why or ("a terminal record for " .. name) })
end

test("a member starts only once every one of its dependencies is satisfied",
    { spec = "peinit *exec.a-member-starts-when-every-one-of-its-dependencies-is-satisfied" },
    function(t)
        -- pt-x-top is the only boot-triggered member of its chain; the
        -- other two are in the graph because it needs them, and the
        -- order they start in is the release rule at work.
        for _, name in ipairs({ "pt-x-base", "pt-x-mid", "pt-x-top" }) do
            wait_for_line(vm, "peinit: service " .. name .. " started")
        end
        local at = {}
        for index, name in ipairs(peinit.started_services(vm:console():read_log())) do
            at[name] = at[name] or index
        end
        t:assert(at["pt-x-base"] < at["pt-x-mid"] and at["pt-x-mid"] < at["pt-x-top"],
            "the chain started bottom-up: base=" .. tostring(at["pt-x-base"]) ..
            " mid=" .. tostring(at["pt-x-mid"]) .. " top=" .. tostring(at["pt-x-top"]))
    end)

test("failure propagation walks the whole chain of hard dependents",
    { spec = "peinit *exec.failure-propagation-is-transitive" },
    function(t)
        -- pt-x-c fails at runtime rather than at validation: it is a
        -- perfectly valid definition whose process exits non-zero. So
        -- this is the execution-time propagation, not the planner's.
        wait_for_state("pt-x-c", "failed")
        local middle = wait_for_state("pt-x-b", "failed")
        local far = wait_for_state("pt-x-a", "failed")
        t:assert_eq(middle.cause, "dependency_failure",
            "the direct dependent failed on its dependency")
        t:assert_eq(far.cause, "dependency_failure",
            "and so did the one two edges away, which is the transitivity")
        t:assert(not vm:console():read_log():find("peinit: service pt%-x%-a started"),
            "the far dependent never ran")
    end)

test("the boot is one context and every explicit start gets its own",
    { spec = "peinit *exec.there-is-one-boot-context-and-one-per-explicit-start" },
    function(t)
        -- Everything the boot plan started went through one context.
        local boot_contexts = {}
        for _, record in ipairs(terminals()) do
            if record.service == "pt-x-top" or record.service == "pt-x-base"
                or record.service == "authd" then
                boot_contexts[record.context_id] = true
            end
        end
        local boot_ids = {}
        for id in pairs(boot_contexts) do boot_ids[#boot_ids + 1] = id end
        t:assert_eq(#boot_ids, 1,
            "the boot dispatched through exactly one context, saw " .. #boot_ids)
        local boot_context = boot_ids[1]

        -- Two explicit starts, two more contexts, neither of them the
        -- boot's. They are distinct runtime objects, which is what lets
        -- them overlap.
        vm:run("svctl start pt-x-usesresident"):assert_ok()
        local first = wait_for_terminal("pt-x-usesresident")
        vm:run("svctl start pt-x-softoff"):assert_ok()
        local second = wait_until(function()
            for _, record in ipairs(terminals()) do
                if record.service == "pt-x-softoff" and record.context_id ~= boot_context then
                    return record
                end
            end
            return nil
        end, { timeout = 90, interval = 1, desc = "a second on-demand context" })

        t:assert(first.context_id ~= boot_context,
            "an explicit start is not dispatched through the boot context")
        t:assert(second.context_id ~= boot_context,
            "and neither is the next one")
        t:assert(first.context_id ~= second.context_id,
            "two explicit starts are two contexts, got " ..
            first.context_id .. " and " .. second.context_id)
    end)

test("a dependency shared by two overlapping starts is one operation both contexts hear about",
    {
        spec = {
            "peinit *exec.a-shared-dependency-is-one-operation-both-contexts-hear-about",
            "peinit *exec.a-terminal-outcome-dispatches-one-graph-event-per-associated-context",
        },
    },
    function(t)
        -- pt-x-shared sleeps for six seconds, so the second start
        -- arrives while the first one's dependency is still in flight
        -- and merges into the operation already running for it rather
        -- than requesting a second.
        vm:run("svctl start pt-x-sharer1 --no-wait"):assert_ok()
        vm:run("svctl start pt-x-sharer2 --no-wait"):assert_ok()

        local records = wait_until(function()
            local shared = {}
            for _, record in ipairs(terminals()) do
                if record.service == "pt-x-shared" then shared[#shared + 1] = record end
            end
            return #shared >= 2 and shared or nil
        end, { timeout = 90, interval = 1,
               desc = "two terminal records for the shared dependency" })

        -- One operation, dispatched once per associated context: the
        -- two records carry the same operation id and different
        -- contexts. Two operations would mean the merge did not happen
        -- and the dependency was started twice.
        t:assert_eq(records[1].operation_id, records[2].operation_id,
            "both contexts are hearing about the same operation")
        t:assert(records[1].context_id ~= records[2].context_id,
            "and the outcome was dispatched once per context, got " ..
            records[1].context_id .. " and " .. records[2].context_id)

        wait_for_state("pt-x-sharer1", "inactive", "pt-x-sharer1 to complete")
        wait_for_state("pt-x-sharer2", "inactive", "pt-x-sharer2 to complete")
    end)

test("a dependency already in a satisfying state is not restarted",
    { spec = "peinit *exec.a-dependency-already-in-a-satisfying-state-is-not-restarted" },
    function(t)
        local before = wait_for_state("pt-x-resident", "active")
        t:assert(before.current_job and before.current_job.pid,
            "the resident dependency has a process")

        -- pt-x-usesresident was started in an earlier test and again
        -- here; either way its dependency was already Active, so its
        -- dependency is already met and there is nothing to start.
        vm:run("svctl start pt-x-usesresident"):assert_ok()
        vm:run("sleep 1")
        local after = status("pt-x-resident")
        t:assert_eq(after.state, "active", "the dependency is still the one that was running")
        t:assert_eq(after.current_job.pid, before.current_job.pid,
            "and it is the same process: a restart would have replaced it")
    end)

test("a dependency started on demand carries DependencyPropagation and DependencyStart",
    {
        spec = {
            "peinit *exec.an-on-demand-start-resolves-its-closure-first",
            "peinit *exec.a-dependency-started-on-demand-carries-dependencypropagation",
        },
    },
    function(t)
        -- pt-x-neverready declares Notify readiness and never notifies,
        -- so it sits in Starting with its operation still live — which
        -- is what makes the operation's *source* readable at all.
        vm:run("svctl start pt-x-needsnotify --no-wait"):assert_ok()
        local dependency = wait_until(function()
            local current = status("pt-x-neverready")
            return current.state == "starting" and current.current_operation and current or nil
        end, { timeout = 60, interval = 0.4,
               desc = "the dependency to be started by the request for its dependent" })

        -- The closure was resolved first: nothing asked for
        -- pt-x-neverready, and it has no trigger of its own.
        t:assert_eq(dependency.cause, "dependency_start",
            "the dependency was started because something depended on it")
        t:assert_eq(dependency.current_operation.source, "dependency_propagation",
            "and the operation is attributed to the propagation rather than the administrator")

        -- The requested service is still waiting behind it.
        t:assert_eq(status("pt-x-needsnotify").state, "inactive",
            "the dependent has not started, because its dependency has not become satisfying")
    end)

test("a disabled hard-dependency target blocks its dependent on both paths",
    { spec = "peinit *exec.a-disabled-hard-dependency-target-blocks-the-dependent" },
    function(t)
        -- Boot: pt-x-hardoff is boot-triggered and requires a disabled
        -- service, and was blocked rather than started.
        local at_boot = status("pt-x-hardoff")
        t:assert_eq(at_boot.state, "failed", "the boot-path dependent was blocked")
        t:assert_eq(at_boot.cause, "dependency_failure",
            "on the ground that its dependency is unavailable")

        -- On demand: the same rule, reached the other way. Nobody
        -- started the disabled service explicitly — something that
        -- requires it did — so starting it here would defeat the flag
        -- by a route its description does not consider.
        --
        -- What the block looks like on this path is that nothing runs.
        -- `svctl start` returns without complaint and reports the
        -- service still inactive, which is worth knowing but is not the
        -- claim; the claim is that neither service was started.
        vm:run("svctl start pt-x-hardoff-ondemand")
        vm:run("sleep 2")
        local requested = status("pt-x-hardoff-ondemand")
        t:assert(requested.state ~= "active" and requested.cause ~= "clean_exit",
            "the dependent did not run: " .. requested.state ..
            "/" .. tostring(requested.cause))
        local target = status("pt-x-off")
        t:assert(target.cause == nil,
            "and the disabled service was never started to satisfy it: " ..
            vm:run("svctl --json status pt-x-off").stdout)
    end)

test("a disabled Wants target is skipped, and the disabled service can still be started by hand",
    {
        spec = {
            "peinit *exec.a-disabled-wants-target-is-skipped-rather-than-blocking",
            "peinit *exec.a-disabled-service-can-still-be-started-explicitly",
        },
    },
    function(t)
        -- A soft dependency is advisory, so there is nothing to fail.
        wait_for_line(vm, "peinit: service pt-x-softoff started")
        t:assert(not vm:console():read_log():find("peinit: service pt%-x%-off started"),
            "the disabled service was not pulled in by the Wants either")

        -- The escape hatch: an administrator starting it directly is
        -- exactly the case Disabled leaves open.
        vm:run("svctl start pt-x-off"):assert_ok()
        local started = wait_until(function()
            local current = status("pt-x-off")
            return current.cause ~= nil and current or nil
        end, { timeout = 60, interval = 0.4, desc = "the disabled service to run" })
        t:assert_eq(started.cause, "clean_exit",
            "starting the disabled service by hand still works")
    end)

test("a dormant dependency of a member that never needed it is pruned rather than started",
    { spec = "peinit *exec.an-unneeded-member-is-pruned-rather-than-started" },
    function(t)
        -- pt-x-skipped's pre-start condition names a path that does not
        -- exist, so the member terminates before its dependency was
        -- ever needed. pt-x-dormant is in the boot plan — it is in the
        -- closure — and is cancelled instead of started.
        local skipped = wait_until(function()
            local current = status("pt-x-skipped")
            return current.state ~= "inactive" and current or nil
        end, { timeout = 60, interval = 0.4, desc = "pt-x-skipped to settle" })
        t:assert(skipped.state == "skipped" or skipped.state == "failed",
            "the condition kept the dependent from running: " .. skipped.state)

        t:assert(not vm:console():read_log():find("peinit: service pt%-x%-dormant started"),
            "its dormant dependency was never started")
        local dormant = status("pt-x-dormant")
        t:assert_eq(dormant.state, "inactive", "the pruned member did not run")
        t:assert(dormant.current_operation == nil,
            "and the operation reserved for it was cancelled rather than left pending: " ..
            vm:run("svctl --json status pt-x-dormant").stdout)

        -- The companion: pt-x-base is the same shape — a triggerless
        -- Oneshot pulled in by a dependent — and it did start, so the
        -- absence above is the pruning rather than the plan.
        t:assert(vm:console():read_log():find("peinit: service pt%-x%-base started"),
            "a dormant member whose dependent did need it was started")
    end)

test("MaxParallelStarts is a per-context budget, not a machine-wide one",
    { spec = "peinit *exec.maxparallelstarts-is-counted-per-context" },
    function(t)
        -- A limit of one. Two explicit starts of two unrelated services
        -- are two contexts, so each gets its own slot and both are in
        -- flight at once; a machine-wide counter would hold the second
        -- until the first was done.
        --
        -- Notify readiness with nothing to notify is what keeps a start
        -- in flight long enough to be observed: the process exists, the
        -- member counts as running in its context, and it stays that
        -- way.
        local other = peinit.boot({
            memory = "800M",
            name = "parallel",
            files = peinit.seed("zz-pt-parallel", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Boot]], values = {
                    { name = "MaxParallelStarts", type = "dword", data = 1 },
                } },
                { path = [[Machine\System\Services]] },
                service("pt-x-slot1", "/bin/sleep", { "3600" },
                    { { name = "Readiness", type = "dword", data = 0 } }),
                service("pt-x-slot2", "/bin/sleep", { "3600" },
                    { { name = "Readiness", type = "dword", data = 0 } }),
            }),
        })
        other:run("svctl start pt-x-slot1 --no-wait"):assert_ok()
        other:run("svctl start pt-x-slot2 --no-wait"):assert_ok()

        local both = wait_until(function()
            local first = json.decode(other:run("svctl --json status pt-x-slot1").stdout)
            local second = json.decode(other:run("svctl --json status pt-x-slot2").stdout)
            local running = first.current_job and first.current_job.pid
                and second.current_job and second.current_job.pid
            return running and { first, second } or nil
        end, { timeout = 60, interval = 0.5,
               desc = "both on-demand starts to be in flight at once" })

        t:assert_eq(both[1].state, "starting", "the first start is still in flight")
        t:assert_eq(both[2].state, "starting", "and so is the second")
        t:assert(both[1].current_job.pid ~= both[2].current_job.pid,
            "two processes, under a limit of one: the budget is per context")
        t:assert_eq(other:run([[reg get 'Machine\System\Boot' MaxParallelStarts]])
            .stdout:match("%d+"), "1",
            "and the limit peinit read really was one")
    end)

test("shutdown stops dependents before their dependencies, ordered only by the hard edges",
    {
        spec = {
            "peinit *exec.shutdown-stops-dependents-before-their-dependencies",
            "peinit *exec.only-hard-dependencies-order-the-shutdown",
            "peinit *exec.there-is-no-floor-or-pinning-in-the-shutdown-order",
        },
    },
    function(t)
        -- Its own machine: a shutdown ends the VM, so nothing can run
        -- after it.
        --
        -- Every service the claims are about is deliberately kept out
        -- of the *first* stop wave, by giving each of them a hard
        -- dependent. The first wave is not observable from here: it is
        -- emitted in the same instant the shutdown is dispatched, and
        -- neither the captured console log (which `read_log` stops
        -- returning once the VM is no longer running) nor a console
        -- stream opened beforehand receives it. Later waves arrive
        -- reliably, and a claim about relative order does not need the
        -- first one.
        -- The wave-one members take four seconds to die, which is the
        -- only way the waves after them are observable: the console
        -- around the moment the stream is opened is lost, and a
        -- shutdown whose waves are milliseconds apart puts all of them
        -- inside that window. `sh` runs a trap between commands, so
        -- the one-second sleep loop bounds how long the TERM waits.
        local SLOW_STOP = [==[#!/bin/sh
trap 'sleep 4; exit 0' TERM
while :; do sleep 1; done
]==]
        local other = peinit.boot({
            memory = "800M",
            name = "shutdown",
            files = peinit.merge(
                { ["lcl/pt/slow-stop.sh"] = { SLOW_STOP, exec = true } },
                peinit.seed("zz-pt-shutdown", {
                    { path = [[Machine\System]] },
                    { path = [[Machine\System\Services]] },
                    -- A hard chain. pt-x-tip is the wave-one member
                    -- that keeps the other two out of it, and it is
                    -- one of the two that stop slowly.
                    daemon("pt-x-bottom", { BOOT }),
                    daemon("pt-x-middle", { BOOT, requires("pt-x-bottom") }),
                    service("pt-x-tip", "/lcl/pt/slow-stop.sh", nil,
                        { BOOT, requires("pt-x-middle") }),
                    -- A soft pair. pt-x-guard hard-requires both, so
                    -- both are one wave behind it — and if a `Wants`
                    -- ordered the shutdown, pt-x-softtarget would be a
                    -- wave behind pt-x-softly rather than beside it.
                    daemon("pt-x-softtarget", { BOOT }),
                    daemon("pt-x-softly", { BOOT, wants("pt-x-softtarget") }),
                    service("pt-x-guard", "/lcl/pt/slow-stop.sh", nil,
                        { BOOT, requires("pt-x-softtarget", "pt-x-softly") }),
                })
            ),
        })
        for _, name in ipairs({ "pt-x-bottom", "pt-x-middle", "pt-x-tip",
                                "pt-x-softtarget", "pt-x-softly", "pt-x-guard" }) do
            wait_for_line(other, "peinit: service " .. name .. " started")
        end

        -- Read the console as a live stream: `read_log` re-reads the
        -- captured log file and returns nothing at all once the VM has
        -- stopped running, so a poll arriving after the poweroff gets
        -- an empty string and the whole shutdown with it.
        local stream = other:console():read()
        for _ = 1, 4 do stream:drain(0.5) end
        local requested = other:run("svctl shutdown poweroff")
        t:assert(requested.exit_code == 0,
            "the shutdown was accepted: rc=" .. requested.exit_code ..
            " out=" .. requested.stdout .. " err=" .. requested.stderr)

        --- The stop lines in `source`, in order, first occurrence only.
        local function names_in(source)
            local seen, names = {}, {}
            for name in source:gmatch("peinit: shutdown stopping ([%w%-%._]+)") do
                if not seen[name] then
                    seen[name] = true
                    names[#names + 1] = name
                end
            end
            return names
        end

        -- Two independent captures, because each loses a different
        -- part: the stream misses the burst around the moment it is
        -- first read, and the log file stops being readable the instant
        -- the VM is no longer running. Whichever saw more of the
        -- shutdown is the one parsed.
        local text, best_log = "", ""
        for _ = 1, 30 do
            local ok, chunks = pcall(function() return stream:drain(0.5) end)
            if not ok then break end
            for _, chunk in ipairs(chunks) do text = text .. chunk end
            local snapshot = other:console():read_log()
            if #snapshot > #best_log then best_log = snapshot end
            -- The last wave is the one holding pt-x-bottom, and
            -- pt-x-middle is the wave before it: once both are in one
            -- of the captures there is nothing left to wait for.
            local function has_both(source)
                local names = {}
                for _, name in ipairs(names_in(source)) do names[name] = true end
                return names["pt-x-middle"] and names["pt-x-bottom"]
            end
            if has_both(text) or has_both(best_log) then break end
        end
        pcall(function() stream:close() end)

        local stopped = names_in(text)
        if #names_in(best_log) > #stopped then stopped = names_in(best_log) end

        -- peinit emits a wave's stop lines in one go, sorted by service
        -- name, so a name that sorts *before* its predecessor is the
        -- first member of the next wave. That is what splits the list
        -- into waves without peinit having to number them.
        local waves, current, previous = {}, {}, nil
        for _, name in ipairs(stopped) do
            if previous and name < previous then
                waves[#waves + 1] = current
                current = {}
            end
            current[#current + 1] = name
            previous = name
        end
        if #current > 0 then waves[#waves + 1] = current end
        local rendered = table.concat(stopped, ", ") .. " | console: " .. text:sub(1, 2000)

        local function wave_of(name)
            for index, wave in ipairs(waves) do
                for _, member in ipairs(wave) do
                    if member == name then return index end
                end
            end
            return nil
        end

        -- Reverse topological order: the dependent stops in an earlier
        -- wave than the service it requires.
        t:assert(wave_of("pt-x-middle"), "pt-x-middle was stopped: " .. rendered)
        t:assert(wave_of("pt-x-bottom"), "and so was pt-x-bottom: " .. rendered)
        t:assert(wave_of("pt-x-middle") < wave_of("pt-x-bottom"),
            "the dependent stopped a wave before its dependency: " .. rendered)

        -- Only hard dependencies contribute to the ordering, so a
        -- `Wants` dependent does not push its target into a later wave:
        -- the two come off together.
        t:assert(wave_of("pt-x-softtarget"), "pt-x-softtarget was stopped: " .. rendered)
        t:assert(wave_of("pt-x-softly"), "and so was pt-x-softly: " .. rendered)
        t:assert_eq(wave_of("pt-x-softtarget"), wave_of("pt-x-softly"),
            "a Wants edge did not order them into separate waves: " .. rendered)

        -- The ordering is emergent from what the definitions declare:
        -- there is no floor under the TCB services and no pinning, so
        -- the shipped daemons are interleaved with the test's rather
        -- than held to the end. authd stops in the same wave as a
        -- service this test invented, because that is where its own
        -- declared dependents put it.
        t:assert(wave_of("authd"), "authd was stopped: " .. rendered)
        t:assert_eq(wave_of("authd"), wave_of("pt-x-bottom"),
            "a TCB service takes its place from its own edges: " .. rendered)
    end)
