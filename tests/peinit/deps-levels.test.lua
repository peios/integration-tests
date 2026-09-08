-- peinit TRM §7.5 — readiness levels: waiting for a condition inside
-- another service, in that service's own words.
--
-- The publisher here is netd, because it is the only thing on a booted
-- Peios that publishes a level at all: the image ships no tool that can
-- write a Unix datagram, and a level arrives only over the notification
-- socket, from a process peinit is holding as some service's main job.
-- That bounds what this file can say. It can prove everything about the
-- gate *closing* — that a level dependency waits, that it waits for
-- ever, that it is re-checked live, that the publisher going away does
-- not open a hard one — because netd on this VM is Active and publishes
-- no level the tests ask for. It cannot prove anything that needs a
-- level to actually arrive: exactness, retraction, and the hard gate
-- opening. Those are reported as unreachable rather than half-tested
-- here.
--
-- The VM has only a loopback interface, so netd comes up, reports
-- READY=1, and never reaches link, addressed or routed. A dependent on
-- any level of netd therefore waits — which is precisely the state the
-- manual describes as "netd is up and merely not routed yet".

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
local NO_SUCH_LEVEL = "pt-no-such-level"

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

local function requires(...) return { name = "Requires", type = "multi", data = { ... } } end
local function wants(...) return { name = "Wants", type = "multi", data = { ... } } end

local vm = peinit.boot({
    memory = "800M",
    name = "levels",
    files = peinit.seed("zz-pt-levels", {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },

        -- A plain dependency on the same service, as the control: netd
        -- is Active, so this one is released and the difference between
        -- the two is the level and nothing else.
        oneshot("pt-lv-plain", { BOOT, requires("netd") }),

        -- The hard gate, on a level netd will never publish.
        oneshot("pt-lv-hold", { BOOT, requires("netd:" .. NO_SUCH_LEVEL) }),

        -- The soft gate on the same condition. It waits while netd is
        -- running and could still publish it, and proceeds once netd is
        -- not.
        oneshot("pt-lv-soft", { BOOT, wants("netd:" .. NO_SUCH_LEVEL) }),

        -- A trailing colon is a typo, and reads as the plain
        -- dependency it looks like rather than a request for the empty
        -- level.
        oneshot("pt-lv-colon", { BOOT, requires("netd:") }),

        -- On demand, against a target that is already Active and so is
        -- not part of the start plan at all.
        oneshot("pt-lv-ondemand", { requires("netd:" .. NO_SUCH_LEVEL) }),

        -- The same condition written through the role netd fills.
        oneshot("pt-lv-role", { requires("network:" .. NO_SUCH_LEVEL) }),
        oneshot("pt-lv-bootrole", { BOOT, requires("network:" .. NO_SUCH_LEVEL) }),

        -- A role nothing fills, which is a missing hard dependency
        -- named after what the definition wrote.
        oneshot("pt-lv-norole", { BOOT, requires("pt-no-such-role:" .. NO_SUCH_LEVEL) }),
    }),
})

local function status(name)
    return json.decode(vm:run("svctl --json status " .. name).stdout)
end

local function findings(needle)
    return wait_until(function()
        local out = vm:run(
            "evctl 'EVENTS graph.validation_error SINCE 1h ago TAKE 400' --format jsonl").stdout
        return out:find(needle) and out or nil
    end, { timeout = 60, interval = 1, desc = "graph.validation_error containing " .. needle })
end

test("a level dependency waits for the level as well as for the service",
    {
        spec = {
            "peinit *ready.a-level-dependency-waits-for-the-level-as-well-as-the-service",
            "peinit *ready.a-level-is-recorded-against-the-sender-and-holds-a-mismatched-dependent",
        },
    },
    function(t)
        -- netd is Active: the plain dependent was released by exactly
        -- the fact the level dependent is still waiting on. netd
        -- declares Notify readiness, so it reaches Active a moment
        -- after the boot mark this file waited for rather than at it.
        wait_until(function()
            return status("netd").state == "active" or nil
        end, { timeout = 60, interval = 0.5, desc = "netd to report itself ready" })
        wait_for_line(vm, "peinit: service pt-lv-plain started")

        local held = status("pt-lv-hold")
        t:assert_eq(held.state, "inactive",
            "the level dependent has not started, though its service is Active")
        t:assert(not vm:console():read_log():find("peinit: service pt%-lv%-hold started"),
            "and it never did")
    end)

test("a held start does not time out; the service stays inactive and its operation stays pending",
    { spec = "peinit *ready.a-held-start-does-not-time-out" },
    function(t)
        -- The declared semantics, not a hang: the condition was never
        -- met, so the start never happened. The operation is the
        -- evidence that peinit is still holding it rather than having
        -- given up on it.
        local held = status("pt-lv-hold")
        t:assert(held.current_operation,
            "the start operation is still open: " ..
            vm:run("svctl --json status pt-lv-hold").stdout)
        t:assert_eq(held.current_operation.type, "start", "and it is the start")

        -- Long enough that any timeout worth the name would have
        -- fired. The image's own start timeouts are tens of seconds.
        vm:run("sleep 25")
        local later = status("pt-lv-hold")
        t:assert_eq(later.state, "inactive", "still inactive after waiting")
        t:assert(later.current_operation, "and the operation is still pending, not failed")
        t:assert_eq(later.current_operation.id, held.current_operation.id,
            "it is the same operation, not a retry")
    end)

test("a trailing colon reads as a plain dependency",
    { spec = "peinit *ready.a-trailing-colon-is-a-plain-dependency" },
    function(t)
        -- Treating `netd:` as a request for the empty level would
        -- produce a condition nothing could ever satisfy — the state
        -- pt-lv-hold is in. It starts instead.
        wait_for_line(vm, "peinit: service pt-lv-colon started")
        t:assert_eq(status("pt-lv-colon").cause, "clean_exit",
            "the service with the stray colon ran normally")
    end)

test("the target splits on the first colon, and no service is ever looked for by the whole string",
    {
        spec = {
            "peinit *ready.a-declared-target-splits-on-the-first-colon",
            "peinit *ready.a-service-name-can-never-contain-a-colon",
        },
    },
    function(t)
        -- If the graph were keyed on the raw string it would go looking
        -- for a service called `netd:pt-no-such-level`, find nothing,
        -- and fail the dependent as a missing hard dependency. It is
        -- held instead, which means the split happened and the service
        -- half resolved to netd.
        t:assert_eq(status("pt-lv-hold").state, "inactive",
            "the level dependent is waiting rather than failed")
        local events = vm:run(
            "evctl 'EVENTS graph.validation_error SINCE 1h ago TAKE 400' --format jsonl").stdout
        t:assert(not events:find("netd:" .. NO_SUCH_LEVEL, 1, true),
            "nothing went looking for a service named with the level attached: " .. events)

        -- The property the split rests on: a colon is not a character a
        -- service name may contain, so no existing definition can
        -- accidentally become a level dependency. peinit rejects a
        -- definition whose name has one.
        vm:run([[reg new 'Machine\System\Services\pt-lv:bad']]):assert_ok()
        vm:run([[reg set 'Machine\System\Services\pt-lv:bad' ImagePath 'sz:/bin/true']])
        local reload = vm:run("svctl --json reload-config")
        t:assert(reload.exit_code ~= 0 or reload.stdout:find("error", 1, true),
            "a service name containing a colon is rejected: rc=" .. reload.exit_code ..
            " out=" .. reload.stdout .. " err=" .. reload.stderr)
        vm:run([[reg del 'Machine\System\Services\pt-lv:bad' --recursive]])
    end)

test("the gate is re-checked live against a target that is not being started",
    {
        spec = {
            "peinit *ready.a-level-is-re-checked-at-every-release-rather-than-settled-at-planning",
            "peinit *ready.a-level-edge-is-kept-to-a-target-that-is-not-being-started",
        },
    },
    function(t)
        -- netd is Active before this start is planned, so it is not in
        -- the start plan: there is nothing to start. The *condition* on
        -- it still is, which is the whole point — a graph that kept
        -- only the edges it was starting would have released this
        -- immediately.
        t:assert_eq(status("netd").state, "active",
            "the target was already satisfying when the start was planned")
        vm:run("svctl start pt-lv-ondemand --no-wait"):assert_ok()
        vm:run("sleep 3")

        local held = status("pt-lv-ondemand")
        t:assert_eq(held.state, "inactive",
            "the start is held on a condition about a service nobody is starting")
        t:assert(held.current_operation, "and its operation is still open")
    end)

test("a role carrying a level resolves to the provider with the level intact",
    {
        spec = "peinit *ready.a-role-carrying-a-level-is-rewritten-to-the-provider-with-that-level",
    },
    function(t)
        -- netd declares Provides = ["network"]. `network:X` therefore
        -- has to become `netd:X`, and a dependent on it has to be held
        -- exactly as one written against netd directly is. If the role
        -- were left as written the entry would be a missing hard
        -- dependency and the start would fail rather than wait.
        t:assert(vm:run([[reg get 'Machine\System\Services\netd' Provides]]).stdout
            :find("network", 1, true), "netd fills the network role")

        vm:run("svctl start pt-lv-role --no-wait"):assert_ok()
        vm:run("sleep 3")
        local held = status("pt-lv-role")
        t:assert_eq(held.state, "inactive",
            "the role-and-level dependent is waiting, so the role resolved to netd")
        t:assert(held.current_operation,
            "with its start operation still open rather than failed: " ..
            vm:run("svctl --json status pt-lv-role").stdout)
        t:assert(held.cause ~= "dependency_failure",
            "and not blocked on a missing dependency called `network`")
    end)

test("a role carrying a level is not resolved on the boot path",
    {
        spec = "peinit *ready.a-role-carrying-a-level-is-rewritten-to-the-provider-with-that-level",
        -- PEI-829: run_phase2_boot_with_retained builds the boot plan
        -- from the raw registry definitions and only afterwards builds
        -- the service table from role-synthesised ones, so a declared
        -- role reference is resolved on every path except the boot one.
        tags = { "known-bug" },
    },
    function(t)
        -- The same definition as pt-lv-role, boot-triggered. It should
        -- be held on `netd:pt-no-such-level`, exactly as its on-demand
        -- twin is. It is failed as a missing hard dependency on
        -- `network` instead.
        local at_boot = status("pt-lv-bootrole")
        t:assert_eq(at_boot.state, "inactive",
            "the boot-path dependent is waiting on the level, not failed: " ..
            tostring(at_boot.cause))
    end)

test("a role no service fills is a missing hard dependency, named as the definition wrote it",
    { spec = "peinit *ready.an-unfilled-role-fails-validation-naming-the-role" },
    function(t)
        local entry = status("pt-lv-norole")
        t:assert_eq(entry.state, "failed", "the dependent on an unfilled role was failed")
        t:assert_eq(entry.cause, "dependency_failure", "as a dependency failure")

        -- Named as written: the operator typed `pt-no-such-role`, and
        -- that is what the finding says is missing. The level is
        -- stripped, because a level qualifies a service and there is no
        -- service here to qualify.
        local events = findings("pt%-lv%-norole")
        t:assert(events:find(
            '"message":"service pt-lv-norole has missing hard dependency pt-no-such-role"',
            1, true), "the finding names the role the definition wrote: " .. events)
    end)

test("netd fills the network role, and timed is the other shipped publisher",
    { spec = "peinit *ready.netd-and-timed-are-the-shipped-publishers" },
    function(t)
        -- The half of the table a booted machine can answer: both
        -- services are here, and netd is the one filling the role whose
        -- levels Peios Network Policy defines. What levels each
        -- actually publishes is not readable from the guest — peinit
        -- records a level but exposes it nowhere — and is reported as
        -- unreachable rather than half-checked.
        t:assert(vm:run([[reg get 'Machine\System\Services\netd' Provides]]).stdout
            :find("network", 1, true), "netd declares the network role")
        t:assert_eq(status("timed").state, "active", "and timed is running")
        t:assert_eq(status("netd").state, "active", "as is netd")
    end)

test("the publisher going away does not open a hard gate",
    {
        spec = {
            "peinit *ready.only-the-level-itself-opens-a-hard-gate",
            "peinit *ready.each-relationship-keeps-its-semantics-with-a-level",
        },
    },
    function(t)
        -- Takes netd away from everything above, so it and the test
        -- after it come last in the file.
        --
        -- A `LEVEL=` arriving from the publisher is the only thing that
        -- can open a Requires or BindsTo gate. The publisher leaving a
        -- dependent-satisfying state is emphatically not that, and here
        -- it is the same condition as the soft waiter's — so the two
        -- relationships part company on exactly the semantics each
        -- already had.
        local held = status("pt-lv-hold")
        t:assert_eq(held.state, "inactive", "the hard waiter is held before the stop")

        local stopped = vm:run("svctl stop netd")
        t:assert(stopped.exit_code == 0, "netd stopped: rc=" .. stopped.exit_code ..
            " out=" .. stopped.stdout .. " err=" .. stopped.stderr)
        t:assert_eq(status("netd").state, "inactive", "and it is no longer running")
        vm:run("sleep 5")

        local after = status("pt-lv-hold")
        t:assert_eq(after.state, "inactive",
            "the Requires dependent is still held: the publisher going away is not the level")
        t:assert(after.cause == nil,
            "and it never ran: " .. vm:run("svctl --json status pt-lv-hold").stdout)
        t:assert(not vm:console():read_log():find("peinit: service pt%-lv%-hold started"),
            "nor did it at any point earlier")
    end)

test("a start held on a level survives its publisher going away",
    {
        spec = "peinit *ready.a-held-start-does-not-time-out",
        -- PEI-830: the condition is still unmet — netd has stopped and
        -- has certainly not published the level — so the start should
        -- still be pending. Instead the operation disappears from
        -- `svctl status` the moment the publisher leaves a
        -- dependent-satisfying state, while the service stays Inactive
        -- with no recorded cause: the start neither happened nor
        -- failed, and there is no longer an operation saying so.
        tags = { "known-bug" },
    },
    function(t)
        -- The test above stopped netd. What the manual says a held
        -- start looks like — "the service stays inactive and the start
        -- operation stays pending, visible in `svctl status` as an
        -- operation that has not completed" — is a statement about the
        -- condition never being met, and it has not been met here
        -- either.
        local after = status("pt-lv-hold")
        t:assert(after.current_operation,
            "the start operation is still open: " ..
            vm:run("svctl --json status pt-lv-hold").stdout)
    end)

test("a soft level waiter proceeds once the publisher is no longer running",
    {
        spec = "peinit *ready.a-publisher-leaving-a-satisfying-state-releases-wants-waiters",
        -- PEI-830: the release does not reliably reach a `Wants` level
        -- waiter that came from the boot graph. On a machine where the
        -- boot context is the only context, stopping the publisher
        -- releases nothing, and no later event ever does: a subsequent
        -- explicit start, a restart of the publisher and a second stop
        -- all leave the waiter held. Doing one unrelated `svctl start`
        -- *before* the publisher is stopped makes the same stop release
        -- it, which is what makes this a scheduling defect rather than
        -- the declared semantics.
        tags = { "known-bug" },
    },
    function(t)
        -- netd was stopped by the test above and is not coming back, so
        -- nobody is running who could still publish the level. A soft
        -- dependency waits only while somebody could, and proceeds once
        -- nobody can — which is what keeps `Wants` failure-tolerant,
        -- the property that defines it.
        t:assert_eq(status("netd").state, "inactive", "the publisher is gone")

        local released = wait_until(function()
            local current = status("pt-lv-soft")
            return current.cause ~= nil and current or nil
        end, { timeout = 60, interval = 0.5,
               desc = "the soft waiter to be released by its publisher going away" })
        t:assert_eq(released.cause, "clean_exit",
            "the soft waiter ran once nobody could publish the level")
    end)
