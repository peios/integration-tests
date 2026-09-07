-- Peinit TRM §2.7 — the boot attempt counter: the on-disk counter that
-- turns a repeated failure into an escalation.
--
-- Split out of modes.test.lua because these boot a VM each and the two
-- groups together exceeded the harness's per-file time budget when the
-- host is running other suites.
--
-- Every case here stages a starting count into /.peinit/boot-attempts,
-- which the profile's pt-stage.sh hook writes into the root before
-- prelude chroots — so peinit reads a counter this test chose.

local peinit = require("helpers.peinit")
peinit.claim(2)

local vm = peinit.boot()

test("the boot attempt counter is a plain decimal file on the root, reset by a successful boot",
    {
        spec = {
            "peinit *attempts.the-counter-is-a-file-on-the-root",
            "peinit *attempts.a-successful-boot-resets-the-counter",
        },
    },
    function(t)
        -- Deliberately not in the registry, because the registry may be
        -- the reason the boot is failing.
        local raw = vm:read_file("/.peinit/boot-attempts")
        t:assert(raw:match("^%s*%d+%s*$"), "a plain decimal integer: " .. raw)

        -- The reset happens only after every Critical service has held a
        -- satisfying state for BootSuccessGrace, which defaults to 30
        -- seconds — longer than this test would otherwise wait. Seed it
        -- down to one and the reset is observable promptly, which is a
        -- fair test of the rule rather than of the default.
        local other = peinit.boot({
            name = "counter-reset",
            files = peinit.merge(
                { [".peinit/boot-attempts"] = "2\n" },
                peinit.seed("pt-grace", {
                    { path = [[Machine\System]] },
                    { path = [[Machine\System\Boot]], values = {
                        { name = "BootSuccessGrace", type = "dword", data = 1 },
                    } },
                })
            ),
        })
        other:console():expect("peinit: phase2 boot complete", peinit.STAGE_TIMEOUT)
        -- The increment happens before Phase 2, so the file reads 3 until
        -- the boot is declared successful and it goes back to 0.
        local settled
        for _ = 1, 30 do
            settled = other:read_file("/.peinit/boot-attempts"):match("%d+")
            if settled == "0" then break end
            other:clock():sleep("500ms")
        end
        t:assert_eq(settled, "0", "a successful boot reset the counter")
    end)

test("a counter that cannot be read sends the boot to recovery",
    { spec = "peinit *attempts.an-unreadable-counter-is-recovery" },
    function(t)
        -- A counter that cannot be trusted to escalate is worse than
        -- none, so peinit does not treat garbage as zero.
        local log = peinit.boot_to_recovery(t, {
            name = "attempts-garbage",
            files = { [".peinit/boot-attempts"] = "not a number\n" },
        })
        t:assert(log:find("BootAttemptCounter", 1, true),
            "peinit named the counter as the reason: " .. log:sub(-400))
        t:assert(not log:find("peinit: phase2 boot complete", 1, true),
            "Phase 2 did not run")
    end)

test("the counter increments once per boot, and the threshold is checked before it",
    {
        spec = {
            "peinit *attempts.the-counter-increments-once-per-boot",
            "peinit *attempts.the-threshold-is-checked-pre-increment",
        },
    },
    function(t)
        -- A staged counter of 1 with a threshold of 3: the pre-increment
        -- value is below the threshold, so this boots, and the increment
        -- leaves 2 rather than 1 or 3.
        local other = peinit.boot({
            name = "counter-increment",
            append = "peios.bootattempts=3",
            files = peinit.merge(
                { [".peinit/boot-attempts"] = "1\n" },
                -- A grace long enough that the reset cannot land before
                -- the read below, which is what makes the increment
                -- observable at all.
                peinit.seed("pt-long-grace", {
                    { path = [[Machine\System]] },
                    { path = [[Machine\System\Boot]], values = {
                        { name = "BootSuccessGrace", type = "dword", data = 600 },
                    } },
                })
            ),
        })
        t:assert(other:console():read_log():find("Full boot", 1, true),
            "1 is below the threshold of 3, so the boot proceeded")
        t:assert_eq(other:read_file("/.peinit/boot-attempts"):match("%d+"), "2",
            "and the counter advanced by exactly one")
    end)

test("a pre-increment counter at the threshold sends the boot to recovery",
    { spec = "peinit *attempts.the-default-threshold-is-three" },
    function(t)
        -- The default threshold is 3, so a counter already at 3 admits no
        -- further attempt. Stated without peios.bootattempts= on the
        -- command line, so it is the default being tested.
        local log = peinit.boot_to_recovery(t, {
            name = "counter-threshold",
            files = { [".peinit/boot-attempts"] = "3\n" },
        })
        t:assert(log:find("Recovery mode", 1, true),
            "three prior attempts reached the default threshold: " .. log:sub(-400))
    end)
