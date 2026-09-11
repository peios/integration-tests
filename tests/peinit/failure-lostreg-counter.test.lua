-- peinit TRM §14.1 — a Phase 1 registryd failure sends peinit to recovery
-- and still burns a boot attempt.
--
-- The increment sits before the registryd start in Phase 1 (§2.7), so a
-- registryd that will not start enters recovery with the counter already
-- advanced — which is why a persistently broken registryd walks the
-- counter up to the recovery threshold even though every boot fails the
-- same way.
--
-- The counter cannot be read back the usual way: a boot that reaches
-- recovery starts no Phase 2 service and no agent, and nothing it writes
-- to the root survives the reboot that reading it back would need. So the
-- recovery shell reports it. Recovery prefers /bin/recsh over /bin/sh and
-- treats it as an opaque executable, and /bin's highest-precedence stratum
-- is /lcl/bin — so a script staged at lcl/bin/recsh is the shell peinit
-- execs. It prints the counter and sleeps, and the console tail
-- boot_to_recovery returns carries the line.
--
-- registryd is broken by staging an unexecutable file over it: /sbin is a
-- StrataFS view whose create layer is /lcl/sbin, so lcl/sbin/registryd is
-- the binary peinit execs, and staged without the execute bit — which
-- under KACS is the intrinsic "this is executable" flag — the exec fails
-- and the start fails before readiness.

local peinit = require("helpers.peinit")
peinit.claim(1)

local COUNTER_REPORTER = table.concat({
    "#!/bin/sh",
    "echo pt-rec: counter=$(cat /.peinit/boot-attempts 2>&1)",
    "echo pt-rec: end",
    "sleep 3600",
    "",
}, "\n")

test("a Phase 1 registryd failure enters recovery with the boot attempt counter already incremented",
    { spec = "peinit *lostreg.a-phase-1-registryd-failure-still-increments-the-counter" },
    function(t)
        -- A counter of 1, well below the default threshold of 3, so the
        -- recovery here is registryd's doing and not the counter's. The
        -- increment runs before the registryd step, so recovery finds it
        -- at 2.
        local console = peinit.boot_to_recovery(t, {
            name = "lostreg-counter",
            agent_timeout = 20,
            files = peinit.merge(
                { ["lcl/bin/recsh"] = { COUNTER_REPORTER, exec = true } },
                { ["lcl/sbin/registryd"] = "#!/bin/sh\nexit 0\n" },
                { [".peinit/boot-attempts"] = "1\n" }
            ),
        })

        t:assert(console:find("peinit: entering recovery: Registryd", 1, true),
            "registryd is what sent this boot to recovery: " .. console:sub(-700))
        t:assert(not console:find("peinit: entering recovery: BootAttemptThreshold", 1, true),
            "and not the counter's own threshold")
        t:assert_eq(console:match("pt%-rec: counter=(%d+)"), "2",
            "the counter was incremented before the registryd step, so recovery finds 1 -> 2: "
            .. tostring(console:match("pt%-rec: counter=([^\r\n]*)")))
    end)
