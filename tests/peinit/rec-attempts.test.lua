-- Peinit TRM §2.7 — the ends of the boot attempt counter's cycle: what an
-- absent counter reads as, what disabling the check does and does not
-- disable, and which side of the increment the two recovery entries fall
-- on.
--
-- attempts.test.lua covers the middle of the cycle — the file's shape, the
-- pre-increment threshold check, the reset — from ordinary boots. The cases
-- here need either a command line of their own or a boot that ends in
-- recovery, so each test brings its own machine and there is no file-scope
-- VM to share.
--
-- The two recovery cases would otherwise be unobservable. A boot that
-- reaches recovery starts no Phase 2 service and therefore no agent, and
-- nothing it writes to the root survives the reboot that would be needed to
-- read it back — so the counter after a recovery can only be read from
-- inside that recovery. /bin/recsh is how: recovery prefers it over
-- /bin/sh and treats it as an opaque executable, /bin's highest-precedence
-- stratum is /lcl/bin, and a script staged there is therefore the shell
-- peinit execs. It prints the counter and then sleeps rather than exiting,
-- so the respawn loop does not push the rest of the console out of the tail
-- the harness keeps.
--
-- `BootSuccessGrace` is seeded high in the two ordinary boots for the
-- opposite reason attempts.test.lua seeds it low: these tests read the
-- counter mid-life, and the reset that follows a successful boot would
-- otherwise race them to it.

local peinit = require("helpers.peinit")
peinit.claim(1)

--- A `Machine\System\Boot` that will not declare the boot a success while
--- a test is still looking at the counter.
local function slow_grace(name)
    return peinit.seed(name, {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Boot]], values = {
            { name = "BootSuccessGrace", type = "dword", data = 600 },
        } },
    })
end

--- A recovery shell that reports the counter file verbatim.
---
--- Verbatim, not parsed: one of the two cases below stages something that
--- is not a number at all, and the claim is that peinit left exactly that
--- there.
local COUNTER_REPORTER = table.concat({
    "#!/bin/sh",
    "echo pt-rec: counter=$(cat /.peinit/boot-attempts 2>&1)",
    "echo pt-rec: end",
    "sleep 3600",
    "",
}, "\n")

test("an absent counter file reads as zero rather than as a fault",
    { spec = "peinit *attempts.an-absent-counter-is-zero" },
    function(t)
        -- The image ships no /.peinit at all, which is the state of every
        -- machine on its first boot: peinit has to read that as "no failed
        -- attempts yet" rather than as an unreadable counter, or a fresh
        -- system would go straight to recovery.
        local vm = peinit.boot({
            name = "attempts-absent",
            files = slow_grace("zz-pt-absent"),
        })
        t:assert(vm:console():read_log():find("Full boot", 1, true),
            "an absent counter did not send the boot to recovery")
        -- Zero, then incremented once for this attempt: the file that was
        -- not there now reads 1, which no other starting value produces.
        t:assert_eq(vm:read_file("/.peinit/boot-attempts"):match("%d+"), "1",
            "the absent counter was read as 0 and this attempt recorded against it")
    end)

test("peios.bootattempts=0 disables the check without disabling the counter",
    { spec = "peinit *attempts.a-threshold-of-zero-disables-the-check" },
    function(t)
        -- The escape hatch for a system whose counter is itself the fault.
        -- 3 is the default threshold, so this counter would send an
        -- ordinary boot to recovery — attempts.test.lua asserts exactly
        -- that. With the check disabled it boots instead.
        local vm = peinit.boot({
            name = "attempts-threshold-zero",
            append = "peios.bootattempts=0",
            files = peinit.merge(
                { [".peinit/boot-attempts"] = "3\n" },
                slow_grace("zz-pt-threshold-zero")
            ),
        })
        local log = vm:console():read_log()
        t:assert(log:find("Full boot", 1, true),
            "a counter at the default threshold booted anyway")
        t:assert(log:find("peinit: phase2 boot complete", 1, true),
            "and reached the end of Phase 2")
        -- What is switched off is the comparison, not the bookkeeping: the
        -- attempt is still recorded, so re-enabling the check on the next
        -- boot escalates from a truthful count.
        t:assert_eq(vm:read_file("/.peinit/boot-attempts"):match("%d+"), "4",
            "and the attempt was still counted")
    end)

test("a forced recovery still records the attempt",
    { spec = "peinit *attempts.forced-recovery-still-increments" },
    function(t)
        -- `peios.recovery=1` skips the counter READ — there is no threshold
        -- to compare against when the answer is already recovery — but the
        -- increment sits before the forced-recovery branch and happens
        -- anyway. So an operator who forces recovery and then reboots
        -- normally finds the attempt on the record.
        local console = peinit.boot_to_recovery(t, {
            name = "attempts-forced",
            agent_timeout = 20,
            append = "peios.recovery=1",
            files = peinit.merge(
                { ["lcl/bin/recsh"] = { COUNTER_REPORTER, exec = true } },
                { [".peinit/boot-attempts"] = "5\n" }
            ),
        })
        t:assert(console:find("peinit: entering recovery: ForcedByKernelCommandLine", 1, true),
            "recovery was forced from the command line: " .. console:sub(-500))
        t:assert_eq(console:match("pt%-rec: counter=(%d+)"), "6",
            "and the counter advanced by one: " ..
            tostring(console:match("pt%-rec: counter=([^\r\n]*)")))
    end)

test("a recovery entered before the increment does not advance the counter",
    { spec = "peinit *attempts.an-early-recovery-does-not-advance-the-counter" },
    function(t)
        -- The increment happens after the mount, seed, machine ID and clock
        -- steps, because reading the kernel command line needs /proc — so
        -- every recovery entered before it leaves the counter where it was.
        --
        -- The entry used is an unreadable counter, which is the only one of
        -- those the harness can arrange: a mount failure, a machine ID
        -- failure and an unreadable command line are all states the profile
        -- has no lever on. It is the same early return — the read is two
        -- statements above the increment — and the staged value doubles as
        -- its own marker: `pt-garbage` is not a number, so it cannot have
        -- been written by an increment, and finding it unchanged is finding
        -- that nothing wrote to the file at all.
        local console = peinit.boot_to_recovery(t, {
            name = "attempts-early",
            agent_timeout = 20,
            files = peinit.merge(
                { ["lcl/bin/recsh"] = { COUNTER_REPORTER, exec = true } },
                { [".peinit/boot-attempts"] = "pt-garbage\n" }
            ),
        })
        t:assert(console:find("peinit: entering recovery: BootAttemptCounter", 1, true),
            "the counter is what sent this boot to recovery: " .. console:sub(-500))
        t:assert_eq(console:match("pt%-rec: counter=([^\r\n]*)"), "pt-garbage",
            "and the counter file is exactly as it was staged")
    end)
