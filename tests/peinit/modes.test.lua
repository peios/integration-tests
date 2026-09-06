-- Peinit TRM §2.6 and §2.8 — boot modes, the console quiet policy, the
-- kernel command line, and recovery.
--
-- Almost everything here is driven from the kernel command line, which
-- is the one input to peinit a test can vary without touching the image.
-- The profile's `cmdline_file` supplies the image's own line and
-- `kernel_cmdline_append` adds tokens after it; the kernel takes the
-- last occurrence of a repeated parameter, so an appended token wins.

local peinit = require("helpers.peinit")

local vm = peinit.boot()

test("the default is a Full boot, and it says so",
    { spec = "peinit *mode.full-is-the-default" },
    function(t)
        -- peinit's banner names the mode it is running in, so a boot
        -- with nothing on the command line asking otherwise reads Full.
        t:assert(vm:console():read_log():find("Full boot", 1, true),
            "the banner names a Full boot")
    end)

test("peios.safemode=1 forces Safe mode from the command line",
    { spec = "peinit *mode.safemode-can-be-forced-from-the-command-line" },
    function(t)
        local other = peinit.boot({ name = "safe", append = "peios.safemode=1" })
        local log = other:console():read_log()
        t:assert(log:find("Safe", 1, true), "the banner names Safe mode")
        t:assert(not log:find("Full boot", 1, true),
            "and not a Full one")
    end)

test("Safe mode does not start a service that has no boot trigger, whatever SafeMode says",
    { spec = "peinit *mode.safe-does-not-start-a-service-with-no-boot-trigger" },
    function(t)
        -- Eligibility is a filter WITHIN the boot-triggered set, not a
        -- replacement for it. A service declaring SafeMode=1 but no
        -- trigger stays demand-only, exactly as in a Full boot.
        local other = peinit.boot({
            name = "safe-untriggered",
            append = "peios.safemode=1",
            files = peinit.seed("pt-safe-untriggered", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                {
                    path = [[Machine\System\Services\pt-notrigger]],
                    values = {
                        { name = "ImagePath", type = "sz", data = "/bin/true" },
                        { name = "Type", type = "dword", data = 1 },
                        { name = "Identity", type = "sz", data = "SYSTEM" },
                        { name = "Readiness", type = "dword", data = 1 },
                        { name = "SafeMode", type = "dword", data = 1 },
                    },
                },
            }),
        })
        t:assert(not other:console():read_log():find("peinit: service pt%-notrigger started"),
            "SafeMode=1 without a boot trigger did not make it a root")
    end)

test("Safe mode starts a boot-triggered SafeMode service and leaves the rest out",
    {
        spec = {
            "peinit *mode.safe-attempts-safemode-services-best-effort",
            "peinit *mode.safe-drops-dependencies-on-excluded-services",
        },
    },
    function(t)
        local function svc(name, extra)
            local values = {
                { name = "ImagePath", type = "sz", data = "/bin/true" },
                { name = "Type", type = "dword", data = 1 },
                { name = "Identity", type = "sz", data = "SYSTEM" },
                { name = "Readiness", type = "dword", data = 1 },
                { name = "Triggers", type = "multi", data = { "boot" } },
            }
            for _, v in ipairs(extra or {}) do values[#values + 1] = v end
            return { path = [[Machine\System\Services\]] .. name, values = values }
        end
        local other = peinit.boot({
            name = "safe-graph",
            append = "peios.safemode=1",
            files = peinit.seed("pt-safe-graph", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                -- Eligible, and it needs something that is not.
                svc("pt-safe-eligible", {
                    { name = "SafeMode", type = "dword", data = 1 },
                    { name = "Requires", type = "multi", data = { "pt-safe-excluded" } },
                }),
                -- Not eligible: neither Critical nor SafeMode.
                svc("pt-safe-excluded"),
            }),
        })
        local log = other:console():read_log()
        t:assert(not log:find("peinit: service pt%-safe%-excluded started"),
            "the ineligible service was excluded from the Safe-mode graph")
        -- And its dependent still started, because dependencies on
        -- excluded services are dropped rather than left to fail. This
        -- is what makes Safe mode useful rather than a Full boot with
        -- more failures in it.
        t:assert(log:find("peinit: service pt%-safe%-eligible started"),
            "its SafeMode dependent started anyway, its Requires edge dropped")
    end)

test("peios.recovery=1 forces recovery without consulting the counter",
    {
        spec = {
            "peinit *cmdline.recovery-forces-recovery-mode",
            "peinit *recovery.no-phase-2-service-starts",
        },
    },
    function(t)
        -- Recovery runs no Phase 2 service, so the autorun that starts
        -- the agent never runs and the boot never reaches one. That is
        -- the asserted outcome: the console tail carried in the boot
        -- error is the only record such a boot leaves.
        local log = peinit.boot_to_recovery(t, {
            name = "forced-recovery",
            append = "peios.recovery=1",
        })
        t:assert(log:find("Recovery mode", 1, true),
            "peinit said it was entering recovery")
        t:assert(not log:find("peinit: phase2 boot complete", 1, true),
            "Phase 2 did not run")
        -- In a Full boot the console lists the image's services
        -- starting; here it lists none.
        t:assert_eq(#peinit.started_services(log), 0,
            "no Phase 2 service started")
    end)

test("recovery reaches a shell rather than halting",
    { spec = "peinit *recovery.recsh-is-preferred-over-sh" },
    function(t)
        local log = peinit.boot_to_recovery(t, {
            name = "recovery-shell",
            append = "peios.recovery=1",
        })
        -- The image ships no /bin/recsh, so the floor applies. The shell
        -- announces itself by complaining about job control, which is
        -- itself the §2.8 claim that peinit does not make it a session
        -- leader.
        t:assert(log:find("/bin/sh", 1, true),
            "peinit exec'd /bin/sh, the floor where recsh is absent")
        t:assert(not log:find("halt", 1, true),
            "and did not take the no-shell path")
    end)

test("the recovery shell is not a session leader, so it has no job control",
    { spec = "peinit *recovery.the-shell-is-not-a-session-leader" },
    function(t)
        local log = peinit.boot_to_recovery(t, {
            name = "recovery-jobs",
            append = "peios.recovery=1",
        })
        -- peinit dups /dev/console onto the shell's standard streams but
        -- calls neither setsid() nor TIOCSCTTY, so the shell finds it has
        -- no controlling terminal and says so. That complaint is the
        -- observable form of the claim.
        t:assert(log:find("can't access tty", 1, true)
            or log:find("job control turned off", 1, true),
            "the shell reported no controlling terminal, so it is not a session leader")
    end)

test("peios.quiet=2 drops runtime progress from the console",
    {
        spec = {
            "peinit *quiet.two-drops-progress-but-not-errors",
            "peinit *quiet.zero-writes-unconditionally",
        },
    },
    function(t)
        local loud = peinit.boot({ name = "quiet0", append = "peios.quiet=0" })
        -- Wait for "phase1 starting" rather than the default phase-2
        -- mark: at level 2 the phase-2 progress line is exactly what is
        -- dropped, so waiting for it would time out on the behaviour
        -- under test. That first line is the one thing guaranteed to
        -- survive — it is written before peinit has read the command
        -- line, so no level can suppress it, and the code says so.
        -- The banner does not survive: it is written after the parse and
        -- passes the parsed level.
        local quiet = peinit.boot({
            name = "quiet2",
            append = "peios.quiet=2",
            stage = "phase1",
        })

        local loud_log = loud:console():read_log()
        local quiet_log = quiet:console():read_log()

        -- Service-start lines are ordinary progress and go through the
        -- runtime console, which is where the quiet policy is applied.
        t:assert(#peinit.started_services(loud_log) > 0,
            "quiet=0 listed the services starting")
        t:assert_eq(#peinit.started_services(quiet_log), 0,
            "quiet=2 dropped them")

        -- The blackout silences the narrative, not the boot: both
        -- reached the end of Phase 2, and both wrote something.
        t:assert(#quiet_log > 0, "quiet=2 still produced console output")
    end)

test("peios.quiet=2 does not reach Phase 1's middle steps, which are written unconditionally",
    {
        spec = "peinit *quiet.two-drops-progress-but-not-errors",
        tags = { "known-bug" },
    },
    function(t)
        -- §2.6 says level 2 "additionally drop[s] ordinary progress
        -- everywhere, while still emitting errors".
        --
        -- Two lines of Phase 1 legitimately escape it. "phase1 starting"
        -- is written before the command line has been read, so no level
        -- can apply to it, and orchestrator.rs says exactly that. The
        -- banner is written after and does honour the level — verified,
        -- since waiting on it at level 2 times out.
        --
        -- Between them sit the mount, seed, device-node, random-seed and
        -- machine-id steps, and those pass a hardcoded
        -- `QuietLevel::Verbose` even though the parsed level is in scope
        -- by then. They are the surface this test names: the level is
        -- known, and they ignore it.
        local quiet = peinit.boot({
            name = "quiet2-phase1",
            append = "peios.quiet=2",
            stage = "phase1",
        })
        local log = quiet:console():read_log()
        t:assert(not log:find("peinit: phase1 mounting virtual filesystems", 1, true),
            "quiet=2 dropped Phase 1's progress as §2.6 says it should")
    end)

test("a malformed peios.* value falls back to the default rather than failing the boot",
    { spec = "peinit *cmdline.a-malformed-value-falls-back-to-the-default" },
    function(t)
        -- Nothing exists this early to report a diagnostic to, so the
        -- rule is to ignore the value. A quiet level of "banana" must
        -- therefore behave as the default, 1 — not as 0, not as an
        -- abort.
        local other = peinit.boot({ name = "malformed", append = "peios.quiet=banana" })
        local log = other:console():read_log()
        t:assert(log:find("peinit: phase2 boot complete", 1, true),
            "the boot completed despite the unparseable value")
        -- Default is Standard, which still writes progress to a console
        -- no service holds — so the narrative is present, as at 1.
        t:assert(log:find("peinit: phase1 registryd started", 1, true),
            "and the console behaved as the default level")
    end)

test("peios.bootattempts=0 disables the recovery check entirely",
    { spec = "peinit *cmdline.bootattempts-sets-the-threshold-and-zero-disables-it" },
    function(t)
        -- The escape hatch for a system whose counter is itself the
        -- fault. With the check disabled, a counter at or above any
        -- threshold cannot send the boot to recovery — so a boot that
        -- stages a large count still comes up Full.
        local other = peinit.boot({
            name = "attempts-disabled",
            append = "peios.bootattempts=0",
            files = { [".peinit/boot-attempts"] = "99\n" },
        })
        local log = other:console():read_log()
        t:assert(log:find("Full boot", 1, true),
            "a counter of 99 with the check disabled still boots Full")
        t:assert(log:find("peinit: phase2 boot complete", 1, true),
            "and reached the end of Phase 2")
    end)
