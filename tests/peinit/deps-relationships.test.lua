-- peinit TRM §7.1 — relationships: what Requires, Wants, BindsTo and
-- Conflicts each mean at start, at stop and on failure.
--
-- Nearly everything here is a claim about a *pair* of services, so the
-- file stages one graph containing every pair it needs and boots it
-- once. The pairs are independent of each other by construction — no
-- service appears in two of them — which is what makes one boot enough
-- and keeps a failure in one pair from being mistaken for a failure in
-- another.
--
-- Two shapes recur. A Oneshot running `/bin/true` is a service that
-- exists only to satisfy something: it starts, completes, and releases
-- its dependents without staying resident. A Simple service running
-- `/bin/sleep 3600` is one that stays Active, which is what a claim
-- about stopping, crashing or evicting a *running* service needs.
--
-- The console is the oracle for ordering, because it is the only place
-- that records when each service started relative to the others.
-- `peinit: phase2 boot complete` is printed when the plan is
-- dispatched, so every "service X started" line arrives after it and
-- has to be waited for rather than read off the log at the boot mark.

-- Every machine here is booted with 800 MiB rather than the helper's
-- default gigabyte, and the claim says so. A booted guest uses about
-- 300 MiB — the squashfs is read off the medium rather than held in RAM
-- — so the assertions are identical at either size, and a file that
-- claims 1.8 GiB instead of 2.2 GiB still fits a pool several of these
-- files are queueing against.

local peinit = require("helpers.peinit")
peinit.claim(1, { memory_mib = 800 })

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
        -- Alive readiness: these services do not speak the notification
        -- protocol, so nothing else could ever move them to Active.
        { name = "Readiness", type = "dword", data = 1 },
    }
    if args then values[#values + 1] = { name = "Arguments", type = "multi", data = args } end
    for _, value in ipairs(extra or {}) do values[#values + 1] = value end
    return { path = [[Machine\System\Services\]] .. name, values = values }
end

--- A service that runs, succeeds and completes.
local function oneshot(name, extra)
    local values = { { name = "Type", type = "dword", data = 1 } }
    for _, value in ipairs(extra or {}) do values[#values + 1] = value end
    return service(name, "/bin/true", nil, values)
end

--- A Oneshot that fails, for the failure-propagation pairs.
local function failing(name, extra)
    local values = { { name = "Type", type = "dword", data = 1 } }
    for _, value in ipairs(extra or {}) do values[#values + 1] = value end
    return service(name, "/bin/false", nil, values)
end

--- A service that stays Active until something stops it.
local function daemon(name, extra)
    return service(name, "/bin/sleep", { "3600" }, extra)
end

local function requires(...) return { name = "Requires", type = "multi", data = { ... } } end
local function wants(...) return { name = "Wants", type = "multi", data = { ... } } end
local function binds_to(...) return { name = "BindsTo", type = "multi", data = { ... } } end
local function conflicts(...) return { name = "Conflicts", type = "multi", data = { ... } } end

local vm = peinit.boot({
    memory = "800M",
    name = "rel",
    files = peinit.seed("zz-pt-rel", {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },

        -- Requires pulls a triggerless target into the boot graph.
        oneshot("pt-rel-target"),
        oneshot("pt-rel-needs", { BOOT, requires("pt-rel-target") }),

        -- A Requires target that fails takes its dependent with it, and
        -- the dependent never runs.
        failing("pt-rel-badtarget", { BOOT }),
        oneshot("pt-rel-afterbad", { BOOT, requires("pt-rel-badtarget") }),

        -- Stopping a Requires target must not stop the dependent.
        daemon("pt-rel-stoptarget", { BOOT }),
        daemon("pt-rel-stopdep", { BOOT, requires("pt-rel-stoptarget") }),

        -- Nor must the target crashing.
        daemon("pt-rel-crashtarget", { BOOT }),
        daemon("pt-rel-crashdep", { BOOT, requires("pt-rel-crashtarget") }),

        -- Wants: a target that exists and is enabled is started first,
        -- and the dependent waits for it to reach a terminal state. The
        -- target sleeps, so "waited" and "did not wait" are four
        -- seconds apart on the console rather than a coin toss.
        service("pt-rel-slowwanted", "/bin/sleep", { "4" },
            { { name = "Type", type = "dword", data = 1 } }),
        oneshot("pt-rel-wanter", { BOOT, wants("pt-rel-slowwanted") }),

        -- Wants: a target that fails does not stop the dependent.
        failing("pt-rel-badwanted", { BOOT }),
        oneshot("pt-rel-softdep", { BOOT, wants("pt-rel-badwanted") }),

        -- BindsTo starts exactly as Requires does: a triggerless target
        -- is pulled in and started before the dependent.
        oneshot("pt-rel-bindpulled"),
        oneshot("pt-rel-binder", { BOOT, binds_to("pt-rel-bindpulled") }),

        -- BindsTo stop propagation and recovery, with a restart budget
        -- of one so that a recovery which spent it would be visible.
        daemon("pt-rel-bindtarget", { BOOT }),
        daemon("pt-rel-bound", { BOOT, binds_to("pt-rel-bindtarget"),
            { name = "RestartPolicy", type = "dword", data = 2 },
            { name = "RestartMaxRetries", type = "dword", data = 1 },
            { name = "RestartWindow", type = "dword", data = 600 } }),

        -- Conflicts, declared by the boot-triggered one and resolved by
        -- starting the other. The declaration runs the "wrong" way
        -- round on purpose: pt-rel-confb names nothing.
        daemon("pt-rel-confa", { BOOT, conflicts("pt-rel-confb") }),
        daemon("pt-rel-confb"),

        -- A conflict target that does not exist is dropped, so the
        -- service that names it starts normally.
        oneshot("pt-rel-confghost", { BOOT, conflicts("pt-rel-nobody") }),

        -- A cycle of length one.
        oneshot("pt-rel-self", { BOOT, requires("pt-rel-self") }),
    }),
})

local function status(service_name)
    return json.decode(vm:run("svctl --json status " .. service_name).stdout)
end

local function wait_for_state(service_name, state, why)
    return wait_until(function()
        local current = status(service_name)
        return current.state == state and current or nil
    end, { timeout = 60, interval = 0.4, desc = why or (service_name .. " to reach " .. state) })
end

test("a Requires target that is not boot-triggered is pulled in and started first",
    { spec = "peinit *rel.a-requires-target-is-started-first-with-dependencystart" },
    function(t)
        wait_for_line(vm, "peinit: service pt-rel-target started")
        wait_for_line(vm, "peinit: service pt-rel-needs started")

        -- Order, not merely presence: the target has to have reached a
        -- dependent-satisfying state before the dependent starts.
        local started = peinit.started_services(vm:console():read_log())
        local at = {}
        for index, name in ipairs(started) do at[name] = at[name] or index end
        t:assert(at["pt-rel-target"] < at["pt-rel-needs"],
            "the target started before the service that requires it")

        -- Nothing triggered pt-rel-target itself; the only reason it is
        -- in the boot graph at all is the Requires edge.
        t:assert(vm:run([[reg get 'Machine\System\Services\pt-rel-target' Triggers]]).exit_code ~= 0,
            "pt-rel-target has no trigger of its own")
    end)

test("a Requires target entering Failed fails the dependent with DependencyFailure",
    { spec = "peinit *rel.a-failed-requires-target-fails-the-dependent" },
    function(t)
        local dependent = wait_for_state("pt-rel-afterbad", "failed")
        t:assert_eq(dependent.cause, "dependency_failure",
            "the dependent failed because its dependency did")

        -- And it never ran: a service that had been started and then
        -- failed would have had a job.
        t:assert(not vm:console():read_log():find("peinit: service pt%-rel%-afterbad started"),
            "the dependent was never started")
    end)

test("stopping a Requires target leaves the dependent running",
    { spec = "peinit *rel.stopping-a-requires-target-does-not-stop-the-dependent" },
    function(t)
        wait_for_state("pt-rel-stopdep", "active")
        vm:run("svctl stop pt-rel-stoptarget"):assert_ok()
        wait_for_state("pt-rel-stoptarget", "inactive")

        -- Give the supervisor a turn or two to propagate anything it
        -- was going to propagate, then check nothing was.
        vm:run("sleep 2")
        local dependent = status("pt-rel-stopdep")
        t:assert_eq(dependent.state, "active",
            "the dependent is untouched by its dependency stopping")
    end)

test("a Requires target crashing leaves an Active dependent alone",
    { spec = "peinit *rel.a-requires-target-crashing-leaves-an-active-dependent-alone" },
    function(t)
        local target = wait_for_state("pt-rel-crashtarget", "active")
        wait_for_state("pt-rel-crashdep", "active")
        t:assert(target.current_job and target.current_job.pid,
            "the target has a process to kill")

        -- A crash rather than a stop: the process dies without peinit
        -- having asked it to, which is the case the manual separates
        -- from an administrative stop.
        vm:run("kill -9 " .. target.current_job.pid)
        wait_until(function()
            return status("pt-rel-crashtarget").state ~= "active"
        end, { timeout = 60, interval = 0.4, desc = "the target to leave Active" })

        vm:run("sleep 2")
        t:assert_eq(status("pt-rel-crashdep").state, "active",
            "the dependent kept running after its dependency crashed")
    end)

test("a Wants dependent waits for its target to reach a terminal state, satisfying or not",
    {
        spec = {
            "peinit *rel.a-wants-target-that-exists-and-is-enabled-is-started-first",
            "peinit *rel.a-wants-dependent-waits-only-for-a-terminal-state",
        },
    },
    function(t)
        wait_for_line(vm, "peinit: service pt-rel-slowwanted started")
        wait_for_line(vm, "peinit: service pt-rel-wanter started")
        local started = peinit.started_services(vm:console():read_log())
        local at = {}
        for index, name in ipairs(started) do at[name] = at[name] or index end
        t:assert(at["pt-rel-slowwanted"] < at["pt-rel-wanter"],
            "the wanted service started first")

        -- The waiting is the claim, not the ordering of the two start
        -- lines: the target sleeps four seconds, so a dependent that
        -- did not wait for a terminal state would have started while
        -- the target was still running rather than after it completed.
        t:assert_eq(status("pt-rel-slowwanted").state, "inactive",
            "the wanted Oneshot has completed")
    end)

test("a Wants target that fails does not stop its dependent",
    { spec = "peinit *rel.a-failing-or-absent-wants-target-does-not-stop-the-dependent" },
    function(t)
        wait_for_state("pt-rel-badwanted", "failed")
        wait_for_line(vm, "peinit: service pt-rel-softdep started")
        t:assert_eq(status("pt-rel-softdep").cause, "clean_exit",
            "the dependent ran to completion despite its Wants target failing")
    end)

test("BindsTo starts its target exactly as Requires would",
    { spec = "peinit *rel.bindsto-starts-exactly-as-requires-does" },
    function(t)
        wait_for_line(vm, "peinit: service pt-rel-bindpulled started")
        wait_for_line(vm, "peinit: service pt-rel-binder started")
        local started = peinit.started_services(vm:console():read_log())
        local at = {}
        for index, name in ipairs(started) do at[name] = at[name] or index end
        t:assert(at["pt-rel-bindpulled"] < at["pt-rel-binder"],
            "a triggerless BindsTo target is pulled into the boot graph and started first")
    end)

test("a BindsTo target stopping stops the dependent, and its return restarts it",
    {
        spec = {
            "peinit *rel.a-bindsto-target-stopping-stops-the-dependent",
            "peinit *rel.a-bindsto-target-returning-to-active-restarts-the-dependent",
            "peinit *rel.bindsto-implies-requires",
        },
    },
    function(t)
        -- BindsTo implies Requires: pt-rel-bound declares only BindsTo,
        -- and the target was still started before it.
        wait_for_line(vm, "peinit: service pt-rel-bindtarget started")
        wait_for_line(vm, "peinit: service pt-rel-bound started")
        wait_for_state("pt-rel-bound", "active")

        vm:run("svctl stop pt-rel-bindtarget"):assert_ok()
        local bound = wait_for_state("pt-rel-bound", "failed")
        t:assert_eq(bound.cause, "binds_to_propagation",
            "the dependent stopped because its binding target went away")

        vm:run("svctl start pt-rel-bindtarget"):assert_ok()
        local recovered = wait_for_state("pt-rel-bound", "active")
        t:assert_eq(recovered.cause, "binds_to_recovery",
            "and peinit brought it back when the target returned to Active")
    end)

test("a BindsTo recovery does not spend the dependent's restart budget",
    { spec = "peinit *rel.a-bindsto-recovery-restart-does-not-consume-the-restart-budget" },
    function(t)
        -- pt-rel-bound allows one restart per ten minutes. The test
        -- above already spent one recovery; two more here make three,
        -- which a budget of one could not have paid for. If recoveries
        -- were charged to it, the service would be left Failed rather
        -- than Active on the second or third pass.
        for pass = 1, 2 do
            vm:run("svctl stop pt-rel-bindtarget"):assert_ok()
            wait_for_state("pt-rel-bound", "failed",
                "pt-rel-bound to stop with its target on pass " .. pass)
            vm:run("svctl start pt-rel-bindtarget"):assert_ok()
            local recovered = wait_for_state("pt-rel-bound", "active",
                "pt-rel-bound to come back on pass " .. pass)
            t:assert_eq(recovered.cause, "binds_to_recovery",
                "recovery " .. (pass + 1) .. " happened despite a budget of one")
        end
    end)

test("starting a service evicts an Active one that conflicts with it, in either direction",
    {
        spec = {
            "peinit *rel.starting-a-service-evicts-an-active-conflicting-one",
            "peinit *rel.conflicts-are-symmetric",
        },
    },
    function(t)
        -- pt-rel-confa declares the conflict; pt-rel-confb declares
        -- nothing. Starting confb has to evict confa anyway, which is
        -- the whole of the symmetry claim: peinit scans both a starting
        -- service's own conflicts and everything declaring one against
        -- it.
        wait_for_state("pt-rel-confa", "active")
        vm:run("svctl start pt-rel-confb"):assert_ok()

        local evicted = wait_for_state("pt-rel-confa", "failed")
        t:assert_eq(evicted.cause, "conflict_eviction",
            "the conflicting service was stopped as a conflict eviction")
        t:assert_eq(status("pt-rel-confb").state, "active",
            "and the service that was starting is now the one running")
    end)

test("a conflict target that does not exist is dropped",
    { spec = "peinit *rel.a-missing-conflict-target-is-dropped" },
    function(t)
        -- Nothing to conflict with, so nothing happens: the service
        -- starts as if the field were absent. Contrast a missing
        -- Requires target, which fails the dependent.
        wait_for_line(vm, "peinit: service pt-rel-confghost started")
        t:assert_eq(status("pt-rel-confghost").cause, "clean_exit",
            "the service naming a conflict target that does not exist ran normally")
    end)

test("a service that names itself is a cycle of length one",
    { spec = "peinit *rel.a-self-reference-is-a-cycle-of-length-one" },
    function(t)
        local self_referring = status("pt-rel-self")
        t:assert_eq(self_referring.state, "failed", "the self-referring service was not started")
        t:assert_eq(self_referring.cause, "cycle_detected",
            "and the reason given is a cycle, which is what a self-reference is")

        -- The finding names the one-service cycle, so an administrator
        -- reading the event stream sees the cycle rather than a bare
        -- refusal.
        local events = wait_until(function()
            local out = vm:run(
                "evctl 'EVENTS graph.validation_error SINCE 1h ago TAKE 400' --format jsonl").stdout
            return out:find("pt%-rel%-self") and out or nil
        end, { timeout = 60, interval = 1, desc = "the cycle finding to reach eventd" })
        t:assert(events:find('"message":"dependency cycle: pt-rel-self"', 1, true),
            "the logged cycle path is the service on its own")
    end)
