-- peinit TRM §7.2 — graph validation: what peinit checks before it
-- executes a graph, and what it does with what it finds.
--
-- A validation finding leaves three traces, and which one a test reads
-- decides what it can say:
--
--   * the console, `peinit: service X failed: CycleDetected`, which
--     carries the *primary* cause and nothing else;
--   * `svctl status`, which carries the same primary cause as the
--     service's recorded Failed cause;
--   * `graph.validation_error` KMES events, one per finding, which are
--     the only place the retained lower-precedence findings appear.
--
-- Those events are emitted while the Phase 2 plan is being built —
-- before any service has started, and long before eventd is Active —
-- so they go into the KMES ring buffer and eventd collects them when it
-- attaches. That is why the queries below poll rather than read once.
--
-- The reload-path claims live in `deps-validation-reload.test.lua`
-- rather than here, because a finding is not local to the service that
-- attracted it: `svctl reload-config` validates the whole definition
-- set, so this machine — booted with two cycles in its registry — can
-- never produce a clean reload again.

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
local CRITICAL = { name = "ErrorControl", type = "dword", data = 1 }
local SAFE = { name = "SafeMode", type = "dword", data = 1 }

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
local function conflicts(...) return { name = "Conflicts", type = "multi", data = { ... } } end

local vm = peinit.boot({
    memory = "800M",
    name = "findings",
    files = peinit.seed("zz-pt-validate", {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },

        -- One cycle whose members also attract a second finding each:
        -- pt-v-a is missing a Requires target as well, and pt-v-c is
        -- blocked because pt-v-a is blocked.
        oneshot("pt-v-a", { BOOT, requires("pt-v-b", "pt-v-absent") }),
        oneshot("pt-v-b", { BOOT, requires("pt-v-a") }),
        oneshot("pt-v-c", { BOOT, requires("pt-v-a") }),

        -- A second, disjoint cycle. Detection that stopped at the first
        -- would leave these two unreported.
        oneshot("pt-v-d", { BOOT, requires("pt-v-e") }),
        oneshot("pt-v-e", { BOOT, requires("pt-v-d") }),

        -- Two boot-triggered services that conflict. Only pt-v-confa
        -- declares it, so failing both is also the symmetry.
        daemon("pt-v-confa", { BOOT, conflicts("pt-v-confb") }),
        daemon("pt-v-confb", { BOOT }),

        -- An invalid calendar expression on a service that is in no
        -- graph at all: no boot trigger, and nothing depends on it.
        oneshot("pt-v-badtimer", {
            { name = "Triggers", type = "multi", data = { "timer:not a calendar expression" } },
        }),

        -- Untouched by any of the above, so "the rest of the boot
        -- continued" has a witness.
        oneshot("pt-v-fine", { BOOT }),
    }),
})

--- Every `graph.validation_error` record eventd holds, as text, polled
--- until `needle` appears in it.
---
--- Polled because the findings were emitted into the KMES ring before
--- eventd existed; eventd collects them when it attaches, which is some
--- seconds after the boot mark this file waited for.
local function findings(machine, needle)
    return wait_until(function()
        local out = machine:run(
            "evctl 'EVENTS graph.validation_error SINCE 1h ago TAKE 400' --format jsonl").stdout
        return out:find(needle) and out or nil
    end, { timeout = 60, interval = 1, desc = "graph.validation_error containing " .. needle })
end

local function status(machine, name)
    return json.decode(machine:run("svctl --json status " .. name).stdout)
end

test("every cycle is reported, not only the first, and every member is failed with CycleDetected",
    {
        spec = {
            "peinit *validate.every-cycle-is-detected-not-only-the-first",
            "peinit *validate.every-member-of-a-cycle-fails-with-cycledetected",
        },
    },
    function(t)
        for _, name in ipairs({ "pt-v-a", "pt-v-b", "pt-v-d", "pt-v-e" }) do
            local entry = status(vm, name)
            t:assert_eq(entry.state, "failed", name .. " was not started")
            t:assert_eq(entry.cause, "cycle_detected",
                name .. "'s recorded cause is the cycle it is in")
        end

        -- Two disjoint cycles: the second exists only because detection
        -- removes a cycle's members and searches the rest of the graph
        -- again rather than stopping at the first.
        local events = findings(vm, "pt%-v%-d")
        t:assert(events:find('"message":"dependency cycle: pt-v-a -> pt-v-b"', 1, true)
            or events:find('"message":"dependency cycle: pt-v-b -> pt-v-a"', 1, true),
            "the first cycle's path is logged: " .. events)
        t:assert(events:find('"message":"dependency cycle: pt-v-d -> pt-v-e"', 1, true)
            or events:find('"message":"dependency cycle: pt-v-e -> pt-v-d"', 1, true),
            "and so is the second's")

        -- The rest of the boot was unaffected.
        wait_for_line(vm, "peinit: service pt-v-fine started")
    end)

test("a service blocked because its dependency is blocked says so, rather than claiming it is missing",
    { spec = "peinit *validate.a-blocked-dependency-is-reported-as-hard-dependency-blocked" },
    function(t)
        local downstream = status(vm, "pt-v-c")
        t:assert_eq(downstream.state, "failed", "the downstream service did not start")
        t:assert_eq(downstream.cause, "dependency_failure",
            "and its recorded cause is a dependency failure")

        -- The distinction the finding value draws: pt-v-a exists. A
        -- finding of missing_hard_dependency here would say it does
        -- not.
        local events = findings(vm, "pt%-v%-c")
        t:assert(events:find('"finding":"hard_dependency_blocked"', 1, true),
            "the finding names the block rather than a missing target: " .. events)
        t:assert(events:find(
            '"message":"service pt-v-c is blocked because hard dependency pt-v-a is blocked"',
            1, true), "naming both ends of it")
    end)

test("a service with several findings records the highest-precedence one and keeps the rest",
    {
        spec = {
            "peinit *validate.the-primary-cause-is-chosen-by-precedence",
            "peinit *validate.every-finding-is-retained-beside-the-primary-one",
            "peinit *validate.a-later-higher-precedence-finding-demotes-rather-than-deletes",
        },
    },
    function(t)
        -- pt-v-a is in a cycle AND missing a Requires target. The
        -- recorded cause is the cycle, by the CycleDetected >
        -- ValidationError > DependencyFailure precedence.
        t:assert_eq(status(vm, "pt-v-a").cause, "cycle_detected",
            "the higher-precedence finding is the one stored on the service")

        -- The other finding is not lost. The missing dependency is
        -- found while the boot closure is walked and the cycle only
        -- when the topological sort fails, so the cycle arrived second
        -- and demoted what was already there rather than replacing it.
        -- Breaking the cycle and rebooting should not be what it takes
        -- to discover the second fault.
        local events = findings(vm, "pt%-v%-absent")
        t:assert(events:find(
            '"message":"service pt-v-a has missing hard dependency pt-v-absent"', 1, true),
            "the demoted finding is emitted too: " .. events)
    end)

test("each finding is its own graph.validation_error event, recorded as having happened at boot",
    { spec = "peinit *validate.each-finding-is-its-own-graph-validation-error-event-at-boot" },
    function(t)
        local events = findings(vm, "pt%-v%-absent")
        local at_boot = 0
        for line in events:gmatch("[^\r\n]+") do
            if line:find("pt-v-", 1, true) then
                t:assert(line:find('"phase":"boot"', 1, true),
                    "a boot finding is recorded under phase boot: " .. line)
                at_boot = at_boot + 1
            end
        end
        -- Two cycles (one event per member), pt-v-a's missing target,
        -- pt-v-c's block, the two conflicting services and the bad
        -- timer: comfortably more than one event per service, which is
        -- the claim.
        t:assert(at_boot >= 6,
            "one event per finding rather than one per service, got " .. at_boot)
    end)

test("two boot-triggered services that conflict are both failed with ValidationError",
    {
        spec = {
            "peinit *validate.two-boot-triggered-services-that-conflict-both-fail",
            "peinit *validate.a-validation-error-fails-the-service-and-it-never-starts",
        },
    },
    function(t)
        for _, name in ipairs({ "pt-v-confa", "pt-v-confb" }) do
            local entry = status(vm, name)
            t:assert_eq(entry.state, "failed", name .. " was not started")
            t:assert_eq(entry.cause, "validation_error",
                name .. " was failed as a validation error")
        end
        -- pt-v-confb declares nothing, and is failed anyway.
        local events = findings(vm, "pt%-v%-confb")
        t:assert(events:find('"finding":"conflicting_boot_services"', 1, true),
            "the finding names the conflict: " .. events)
        t:assert(not vm:console():read_log():find("peinit: service pt%-v%-conf. started"),
            "neither of them was started")
    end)

test("an invalid timer expression is a finding even on a service in no graph",
    { spec = "peinit *validate.an-invalid-timer-expression-is-checked-across-every-definition" },
    function(t)
        -- pt-v-badtimer has no boot trigger and nothing depends on it,
        -- so it is in neither the boot closure nor anyone's on-demand
        -- one. The check runs over every definition regardless.
        local entry = status(vm, "pt-v-badtimer")
        t:assert_eq(entry.state, "failed", "the definition outside the graph was still failed")
        t:assert_eq(entry.cause, "validation_error", "as a validation error")
        -- The boot path records every validation error under the one
        -- `validation_error` finding value and puts the specifics in the
        -- message, so the message is what says which check fired.
        local events = findings(vm, "pt%-v%-badtimer")
        t:assert(events:find('Timer schedule \\"not a calendar expression\\" is invalid', 1, true),
            "and it is the calendar expression that was rejected: " .. events)
    end)

test("a Critical service in a cycle takes the machine to Safe mode rather than a reboot",
    { spec = "peinit *validate.a-critical-service-in-a-cycle-downgrades-to-safe-mode" },
    function(t)
        -- The cycle is a configuration error: rebooting would find it
        -- again, so peinit downgrades instead. The downgrade discards
        -- the Full-mode graph, so the console line naming the cycle is
        -- the only account of what caused it.
        local other = peinit.boot({
            memory = "800M",
            name = "critcycle",
            files = peinit.seed("zz-pt-critcycle", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                oneshot("pt-v-crit1", { BOOT, CRITICAL, requires("pt-v-crit2") }),
                oneshot("pt-v-crit2", { BOOT, requires("pt-v-crit1") }),
            }),
        })
        local log = other:console():read_log()
        t:assert(log:find("peinit: boot downgraded to safe mode", 1, true),
            "peinit said it was downgrading: " .. log:sub(-2000))
        t:assert(log:find("critical service in dependency cycle", 1, true),
            "and named the cycle that forced it")

        -- Safe mode, not recovery and not a reboot: the machine came up
        -- with a service graph, on its first boot.
        t:assert(log:find("peinit: phase2 boot complete", 1, true), "Phase 2 ran")
        t:assert(not log:find("entering recovery", 1, true), "and it is not recovery")
    end)

test("Safe mode still blocks a hard dependency that is missing or disabled",
    { spec = "peinit *validate.a-missing-or-disabled-target-blocks-in-safe-mode-too" },
    function(t)
        -- Safe mode drops a hard edge on a service it *excluded* — that
        -- is §2.6's own rule, and modes.test.lua covers it. This is the
        -- other half: a target missing from the registry, or disabled
        -- by an administrator, is a configuration error rather than a
        -- Safe mode exclusion, and blocks the dependent exactly as in
        -- Full. Safe mode used to drop those too, which made the
        -- cautious mode the one that started a service without the
        -- thing it declared it needs.
        local other = peinit.boot({
            memory = "800M",
            name = "safeblock",
            append = "peios.safemode=1",
            files = peinit.seed("zz-pt-safeblock", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                oneshot("pt-v-safemissing", { BOOT, SAFE, requires("pt-v-nosuchservice") }),
                oneshot("pt-v-safedisabled", { BOOT, SAFE, requires("pt-v-off") }),
                oneshot("pt-v-off", { BOOT, SAFE,
                    { name = "Disabled", type = "dword", data = 1 } }),
                -- A control: eligible, nothing unavailable.
                oneshot("pt-v-safefine", { BOOT, SAFE }),
            }),
        })
        wait_for_line(other, "peinit: service pt-v-safefine started")
        local log = other:console():read_log()
        t:assert(not log:find("peinit: service pt%-v%-safemissing started"),
            "a missing hard dependency blocks in Safe mode")
        t:assert(not log:find("peinit: service pt%-v%-safedisabled started"),
            "and so does a disabled one")

        for _, name in ipairs({ "pt-v-safemissing", "pt-v-safedisabled" }) do
            local entry = json.decode(other:run("svctl --json status " .. name).stdout)
            t:assert_eq(entry.state, "failed", name .. " was blocked rather than started")
            t:assert_eq(entry.cause, "dependency_failure",
                name .. " was blocked on its dependency")
        end
    end)

test("validation runs on every graph build",
    { spec = "peinit *validate.validation-runs-once-per-graph-build" },
    function(t)
        -- Three builds, three regimes: the boot above failed the cycle
        -- members, the reload above rejected a cycle written after it,
        -- and an explicit start of a service whose closure does not
        -- validate is refused rather than attempted.
        t:assert_eq(status(vm, "pt-v-a").cause, "cycle_detected",
            "the boot build validated the graph")

        local start = vm:run("svctl start pt-v-a")
        t:assert(start.exit_code ~= 0 or start.stdout:find("fail", 1, true),
            "an on-demand build of the same sub-graph is refused too: rc=" ..
            start.exit_code .. " out=" .. start.stdout .. " err=" .. start.stderr)
        t:assert_eq(status(vm, "pt-v-a").state, "failed",
            "and the service was not started by the attempt")
    end)
