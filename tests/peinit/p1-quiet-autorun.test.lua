-- Peinit TRM §2.3 step 7 — the one thing about the autorun step that is
-- not about running scripts: its console output is not subject to the
-- quiet policy.
--
-- The contrast needs a boot at `peios.quiet=2`, where ordinary progress
-- is dropped everywhere. Everything peinit says about its own progress
-- goes through the policy; what a script said does not, because a script
-- that ran this early and went wrong is the thing an operator most needs
-- to see and the least able to go looking for afterwards.
--
-- The boot waits for the autorun mark rather than for Phase 2, since the
-- Phase 2 line is exactly one of the ones level 2 drops.

local peinit = require("helpers.peinit")
peinit.claim(1)

test("an autorun script's output reaches the console at a quiet level that drops peinit's own",
    { spec = "peinit *phase1.autorun-output-bypasses-the-quiet-policy" },
    function(t)
        local vm = peinit.boot({
            name = "quiet-autorun",
            append = "peios.quiet=2",
            stage = "autoruns",
            files = {
                ["lcl/policy/autorun.d/50-pt-loud.sh"] =
                    { "#!/bin/sh\necho pt-loud-marker\necho pt-loud-stderr >&2\n",
                      exec = true },
            },
        })
        local log = vm:console():read_log()

        -- What the script said, on both streams, attributed to the
        -- script rather than to peinit.
        t:assert(log:find("50%-pt%-loud.sh: pt%-loud%-marker"),
            "the script's stdout reached the console: " .. log:sub(-900))
        t:assert(log:find("pt-loud-stderr", 1, true),
            "and so did its stderr")
        -- The step's own summary line takes the same route, so it
        -- survives the blackout too.
        t:assert(log:find("peinit: ran ", 1, true),
            "as did the step's summary")

        -- And the comparison that makes the claim mean something: at
        -- this level peinit's own progress is gone. registryd's start
        -- line is written before the autorun step and through the quiet
        -- policy, so a console holding the script's line and not that
        -- one is the bypass.
        t:assert(not log:find("peinit: phase1 registryd started", 1, true),
            "while peinit's own progress line for the step before was dropped")
        t:assert(not log:find("peinit: phase2 boot complete", 1, true),
            "and so was Phase 2's")
        t:assert_eq(#peinit.started_services(log), 0,
            "and every service start line with them")
    end)
