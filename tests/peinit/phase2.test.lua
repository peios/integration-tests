-- Peinit TRM §2.5 — Phase 2: the registry-driven phase.
--
-- Every claim here is about what peinit does with the service graph it
-- reads out of the registry, so the tests put a graph there. A seed file
-- staged into /lcl/policy/autoapply.d is applied by the image's own
-- autorun at Phase 1 step 7, which is before both path provisioning
-- (step 8) and the Phase 2 read — so what peinit plans is what the test
-- wrote.

local peinit = require("helpers.peinit")
peinit.claim(2)

local vm = peinit.boot()

-- A definition that does nothing but succeed, for tests that care about
-- the graph rather than the service. Oneshot: it runs, completes, and
-- releases its dependents without staying resident.
local function oneshot(name, extra)
    local values = {
        { name = "ImagePath", type = "sz", data = "/bin/true" },
        { name = "Type", type = "dword", data = 1 },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
    }
    for _, v in ipairs(extra or {}) do values[#values + 1] = v end
    return { path = [[Machine\System\Services\]] .. name, values = values }
end

test("the definitions come from Machine\\System\\Services, one key per service",
    { spec = "peinit *phase2.definitions-come-from-the-services-key" },
    function(t)
        -- The image's own services are all there as sibling keys, and
        -- the ones the console reported starting are among them.
        local listing = vm:run([[reg ls 'Machine\System\Services' --keys-only]])
        listing:assert_ok()
        for _, name in ipairs(peinit.started_services(vm:console():read_log())) do
            t:assert(listing.stdout:find(name, 1, true),
                name .. " started and has a key under Services")
        end
    end)

test("only a boot-triggered service is a root; a triggerless one is loaded and left alone",
    {
        spec = {
            "peinit *phase2.only-boot-triggered-services-are-roots",
            "peinit *phase2.a-demand-only-service-can-still-be-pulled-in",
        },
    },
    function(t)
        local other = peinit.boot({
            name = "roots",
            files = peinit.seed("pt-roots", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                -- Rooted: carries a boot trigger.
                oneshot("pt-root", {
                    { name = "Triggers", type = "multi", data = { "boot" } },
                    { name = "Requires", type = "multi", data = { "pt-pulled" } },
                }),
                -- Pulled in by the above despite having no trigger.
                oneshot("pt-pulled"),
                -- Neither triggered nor depended on: demand-only.
                oneshot("pt-idle"),
            }),
        })
        -- "phase2 boot complete" is printed when the plan has been
        -- dispatched; each "service X started" is printed when that
        -- service's job event arrives, which is after it. So a started
        -- line is waited for, not read off the log at the mark.
        other:console():expect("peinit: service pt-root started", peinit.STAGE_TIMEOUT)
        other:console():expect("peinit: service pt-pulled started", peinit.STAGE_TIMEOUT)
        t:assert(not other:console():read_log():find("peinit: service pt%-idle started"),
            "while the service nothing triggered or required stayed demand-only")

        -- Demand-only is not the same as absent: it is in the model and
        -- an administrator can start it by hand. The console is the
        -- oracle rather than svctl's own output, because what is being
        -- asserted is that peinit started it, not how status renders.
        other:run("svctl start pt-idle"):assert_ok()
        other:console():expect("peinit: service pt-idle started", peinit.STAGE_TIMEOUT)
    end)

test("a disabled service is loaded into the model but excluded from the boot graph",
    { spec = "peinit *phase2.a-disabled-service-is-loaded-but-not-booted" },
    function(t)
        local other = peinit.boot({
            name = "disabled",
            files = peinit.seed("pt-disabled", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                oneshot("pt-off", {
                    { name = "Triggers", type = "multi", data = { "boot" } },
                    { name = "Disabled", type = "dword", data = 1 },
                }),
            }),
        })
        t:assert(not other:console():read_log():find("peinit: service pt%-off started"),
            "a Disabled=1 service did not start at boot despite its boot trigger")
        -- Excluded from the graph, not from the model — svctl can see it.
        local status = other:run("svctl status pt-off")
        status:assert_ok()
        t:assert(status.stdout ~= "", "and it is still a service peinit knows about")
    end)

test("an undecodable definition fails only itself, and the boot proceeds",
    {
        spec = "peinit *phase2.an-undecodable-definition-fails-only-that-service",
        -- PEI-812: the planner blocks the undecodable service with
        -- ValidationError, but the service table has no entry for it,
        -- so applying the block fails with UnknownService and the
        -- whole boot goes to recovery.
        tags = { "known-bug" },
    },
    function(t)
        -- This used to take the machine to the recovery console; the
        -- failure-summary table said so long after the code stopped
        -- doing it (PEI-798). An unclosed quote in a command is one of
        -- the decode failures the manual lists — in a *command* field.
        -- ImagePath is a path and is not command-parsed at all: a quote
        -- in it is taken literally, the exec fails with ENOENT at
        -- launch, and the service goes to Backoff. That is a different
        -- failure from the one this test is about, and an earlier
        -- version of this test asserted on it by mistake.
        local other = peinit.boot({
            name = "undecodable",
            files = peinit.seed("pt-bad", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                oneshot("pt-broken", {
                    { name = "Triggers", type = "multi", data = { "boot" } },
                    { name = "ExecStartPre", type = "multi", data = { '/bin/true "unclosed' } },
                }),
                oneshot("pt-fine", {
                    { name = "Triggers", type = "multi", data = { "boot" } },
                }),
            }),
        })
        -- boot() waited for "phase2 boot complete", so the boot did not
        -- go to recovery. The sibling's started line arrives after that
        -- mark, so it is waited for rather than read off the log.
        other:console():expect("peinit: service pt-fine started", peinit.STAGE_TIMEOUT)

        -- A decode failure is applied when the plan is built, so by the
        -- time the boot is complete the state is settled: no waiting.
        local status = other:run("svctl --json status pt-broken").stdout
        t:assert(status:find('"state":"failed"', 1, true),
            "the broken one is Failed: " .. status)
        t:assert(status:find('"cause":"validation_error"', 1, true),
            "with cause ValidationError: " .. status)
    end)

test("a missing Requires target blocks its dependent, and the block propagates",
    { spec = "peinit *phase2.a-missing-hard-dependency-blocks-and-propagates" },
    function(t)
        local other = peinit.boot({
            name = "missing-dep",
            files = peinit.seed("pt-missing", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                oneshot("pt-blocked", {
                    { name = "Triggers", type = "multi", data = { "boot" } },
                    { name = "Requires", type = "multi", data = { "pt-nonexistent" } },
                }),
                -- Depends on the blocked one, so the block has somewhere
                -- to propagate to.
                oneshot("pt-downstream", {
                    { name = "Triggers", type = "multi", data = { "boot" } },
                    { name = "Requires", type = "multi", data = { "pt-blocked" } },
                }),
            }),
        })
        local log = other:console():read_log()
        t:assert(not log:find("peinit: service pt%-blocked started"),
            "the service whose Requires target does not exist did not start")
        t:assert(not log:find("peinit: service pt%-downstream started"),
            "and neither did the service that required it")
        t:assert(log:find("peinit: phase2 boot complete", 1, true),
            "while the boot itself completed")
    end)

test("a missing Wants target is ignored rather than blocking",
    { spec = "peinit *phase2.a-missing-wants-target-is-ignored" },
    function(t)
        local other = peinit.boot({
            name = "missing-wants",
            files = peinit.seed("pt-wants", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                oneshot("pt-wanter", {
                    { name = "Triggers", type = "multi", data = { "boot" } },
                    { name = "Wants", type = "multi", data = { "pt-nonexistent" } },
                }),
            }),
        })
        -- Waited for, not read at the mark: the started line follows
        -- "phase2 boot complete".
        other:console():expect("peinit: service pt-wanter started", peinit.STAGE_TIMEOUT)
    end)

test("MaxParallelStarts bounds how many services start at once",
    { spec = "peinit *phase2.maxparallelstarts-bounds-concurrency" },
    function(t)
        -- Ten is the default and an absent key uses it, which is what
        -- every other test in this file has been running under.
        local absent = vm:run([[reg get 'Machine\System\Boot' MaxParallelStarts]])
        t:assert(absent.code ~= 0,
            "the image ships no MaxParallelStarts, so the boots above used the default")

        -- Set it to one and the starts serialise. The evidence is
        -- ordering: with a limit of one, no service can report started
        -- before the previous one has.
        local other = peinit.boot({
            name = "serial",
            files = peinit.seed("pt-serial", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Boot]], values = {
                    { name = "MaxParallelStarts", type = "dword", data = 1 },
                } },
                { path = [[Machine\System\Services]] },
            }),
        })
        t:assert(other:console():read_log():find("peinit: phase2 boot complete", 1, true),
            "a limit of one still completes the boot, serially")
        t:assert_eq(
            other:run([[reg get 'Machine\System\Boot' MaxParallelStarts]]).stdout:match("%d+"),
            "1", "and the value peinit read is the one the seed wrote")
    end)

test("an invalid MaxParallelStarts is recovery, because a limit of zero would hang the boot",
    { spec = "peinit *phase2.an-invalid-maxparallelstarts-is-recovery" },
    function(t)
        local other = peinit.boot({
            name = "zero-parallel",
            stage = false,
            files = peinit.seed("pt-zero", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Boot]], values = {
                    { name = "MaxParallelStarts", type = "dword", data = 0 },
                } },
            }),
        })
        -- Recovery is a boot outcome, not a failure to boot: the machine
        -- comes up with a shell rather than a service graph. The console
        -- is the oracle, because in recovery peinit starts no agent.
        other:console():expect("recovery", peinit.STAGE_TIMEOUT)
        local log = other:console():read_log()
        t:assert(not log:find("peinit: phase2 boot complete", 1, true),
            "Phase 2 did not complete")
    end)
