-- Peinit TRM §2.6 — the downgrade: a Full boot that discovers a
-- configuration it cannot start and continues in Safe mode instead.
--
-- One boot carries the whole section, because the section's own claim is
-- that a machine can be downgraded by more than one thing at once and must
-- be told about all of them. So the seed arranges both entry conditions on
-- the same machine:
--
--   pt-dg-crit  <-> pt-dg-norm    a dependency cycle with a Critical service in it
--   pt-dg-clash <-> pt-dg-other   a boot conflict with a Critical service in it
--
-- In each pair only one side is Critical, which is the shape the downgrade
-- is designed around: Safe mode drops the non-Critical side out of the
-- graph entirely, so the rebuild has no cycle and no conflict left to
-- trip over and the Critical service actually starts. A pair where both
-- sides were Critical would survive the rebuild and be blocked by it, which
-- is a different case and a different section.
--
-- Nothing on the command line asks for Safe mode. The banner therefore says
-- Full boot — it is written before Phase 2 has looked at the graph — and
-- counting banners is how this file says "in place, without rebooting": a
-- reboot would put a second prelude banner and a second peinit banner on
-- the console, and there is exactly one of each.

local peinit = require("helpers.peinit")
peinit.claim(1)

local RESIDENT = "#!/bin/sh\nwhile : ; do sleep 30; done\n"

local function boot_service(name, extra)
    local values = {
        { name = "ImagePath", type = "sz", data = "/lcl/pt/dg-resident.sh" },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "Triggers", type = "multi", data = { "boot" } },
    }
    for _, value in ipairs(extra or {}) do values[#values + 1] = value end
    return { path = [[Machine\System\Services\]] .. name, values = values }
end

local CRITICAL = { name = "ErrorControl", type = "dword", data = 1 }

local vm = peinit.boot({
    name = "downgrade",
    files = peinit.merge(
        { ["lcl/pt/dg-resident.sh"] = { RESIDENT, exec = true } },
        peinit.seed("zz-pt-downgrade", {
            { path = [[Machine\System]] },
            { path = [[Machine\System\Services]] },
            boot_service("pt-dg-crit", {
                CRITICAL,
                { name = "Requires", type = "multi", data = { "pt-dg-norm" } },
            }),
            boot_service("pt-dg-norm", {
                { name = "Requires", type = "multi", data = { "pt-dg-crit" } },
            }),
            boot_service("pt-dg-clash", {
                CRITICAL,
                { name = "Conflicts", type = "multi", data = { "pt-dg-other" } },
            }),
            boot_service("pt-dg-other"),
        })
    ),
})

-- `phase2 boot complete` is printed when the plan has been dispatched; the
-- per-service `started` lines are runtime job events and arrive after it.
-- Both eligible services are waited for here, so the log every test below
-- reads is one in which the rebuilt graph has finished running — which is
-- also what makes the absence of the other two services meaningful.
vm:console():expect("peinit: service pt-dg-crit started", peinit.STAGE_TIMEOUT)
vm:console():expect("peinit: service pt-dg-clash started", peinit.STAGE_TIMEOUT)
local log = vm:console():read_log()

local function occurrences(haystack, needle)
    local count, at = 0, 1
    while true do
        local found = haystack:find(needle, at, true)
        if not found then return count end
        count = count + 1
        at = found + 1
    end
end

local function state_of(service)
    local status = vm:run("svctl --json status " .. service)
    status:assert_ok()
    return status.stdout:match('"state":"([^"]+)"')
end

test("a cycle involving a Critical service downgrades the boot where it stands",
    { spec = "peinit *mode.a-critical-cycle-downgrades-in-place" },
    function(t)
        t:assert(log:find(
            "peinit: boot downgraded to safe mode: critical service in dependency cycle", 1, true),
            "peinit named the cycle as a downgrade cause")
        t:assert(log:find("pt-dg-crit", 1, true) and log:find("pt-dg-norm", 1, true),
            "and named the services in it")

        -- In place: one trip through the firmware, one prelude, one peinit.
        -- A cycle is a configuration error and a reboot would find it again,
        -- which is why this is the one downgrade path that does not reboot.
        t:assert_eq(occurrences(log, peinit.marks.prelude_banner), 1,
            "the machine booted once")
        t:assert_eq(occurrences(log, peinit.marks.banner), 1,
            "and peinit took over once")
        t:assert(log:find("Full boot", 1, true),
            "it started as a Full boot, so Safe mode was reached by downgrade")

        -- And the downgrade did what a downgrade is for: the Critical
        -- service in the cycle started, because the rebuild dropped the
        -- non-eligible half of it.
        t:assert(log:find("peinit: service pt-dg-crit started", 1, true),
            "the Critical service started in the rebuilt graph")
    end)

test("an unresolvable conflict involving a Critical service downgrades the boot where it stands",
    { spec = "peinit *mode.a-critical-conflict-downgrades-in-place" },
    function(t)
        t:assert(log:find(
            "peinit: boot downgraded to safe mode: critical boot-triggered services " ..
            "pt-dg-clash and pt-dg-other conflict", 1, true),
            "peinit named the conflicting pair as a downgrade cause")
        t:assert_eq(occurrences(log, peinit.marks.banner), 1,
            "and reached Safe mode without rebooting")
        t:assert(log:find("peinit: service pt-dg-clash started", 1, true),
            "the Critical side of the conflict started in the rebuilt graph")
    end)

test("every finding that forced the downgrade is reported, not just the first",
    { spec = "peinit *mode.every-downgrade-finding-is-reported" },
    function(t)
        -- Both causes are present on this machine at once. An operator
        -- shown only one of them would fix it and reboot straight back into
        -- Safe mode, which is the whole reason the findings are collected
        -- rather than counted.
        t:assert_eq(occurrences(log, "peinit: boot downgraded to safe mode:"), 2,
            "both findings reached the console")
        t:assert(log:find("dependency cycle", 1, true), "the cycle was one of them")
        t:assert(log:find("conflict", 1, true), "and the conflict was the other")
    end)

test("the downgrade reason is recorded at boot level, on the console and as an event",
    { spec = "peinit *mode.the-downgrade-reason-is-recorded-at-boot-level" },
    function(t)
        -- The console half. Written before anything about individual
        -- services, because it explains the shape of everything below it.
        local downgrade_at = log:find("peinit: boot downgraded to safe mode:", 1, true)
        t:assert(downgrade_at, "the console carries the reason")

        -- The event half. `boot.safe_mode_downgrade`, one per finding,
        -- naming the services involved — this is the account that survives
        -- the boot, since nothing about these services' own state records
        -- it. eventd is Critical, so a Safe boot of this image still has it.
        local events
        for _ = 1, 60 do
            events = vm:run(
                "evctl 'EVENTS boot.safe_mode_downgrade SINCE 1h ago TAKE 20' --format jsonl")
            if events.exit_code == 0 and events.stdout:find("safe_mode_downgrade", 1, true) then
                break
            end
            vm:clock():sleep("500ms")
        end
        t:assert(events.exit_code == 0,
            "the event store answered: " .. tostring(events.stderr))
        t:assert(events.stdout:find("pt%-dg%-crit") and events.stdout:find("pt%-dg%-norm"),
            "an event named the cycle's services: " .. events.stdout)
        t:assert(events.stdout:find("pt%-dg%-clash") and events.stdout:find("pt%-dg%-other"),
            "and another named the conflicting pair: " .. events.stdout)
    end)

test("a service excluded from the rebuilt graph is not marked Failed for forcing Safe mode",
    { spec = "peinit *mode.a-service-excluded-from-the-rebuild-is-not-marked-failed" },
    function(t)
        -- The rebuild discards the Full-mode graph, so a service that
        -- caused the downgrade and is then left out of the rebuild is
        -- never entered into the blocked set. `status` keeps meaning
        -- "this service is broken", and neither of these is: Safe mode
        -- was simply never going to start them.
        --
        -- Both of these are non-Critical, so the rebuild excludes them.
        -- A service that survives into it gets no such protection — that
        -- is the test below.
        for _, service in ipairs({ "pt-dg-norm", "pt-dg-other" }) do
            t:assert_eq(state_of(service), "inactive",
                service .. " forced the downgrade and was left unstarted, not Failed")
        end
        -- Nor did peinit report them as failures on the way past.
        t:assert(not log:find("peinit: service pt-dg-norm failed", 1, true),
            "no failure was reported for the cycle's other half")
        t:assert(not log:find("peinit: service pt-dg-other failed", 1, true),
            "nor for the conflict's other half")
    end)
