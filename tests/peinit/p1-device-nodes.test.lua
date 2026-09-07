-- Peinit TRM §2.3 step 2 — the device node policy is advisory: a node
-- that is not there is noted and skipped, and the boot goes on.
--
-- The seven nodes in the policy list are all provided by devtmpfs, so on
-- an ordinary boot every one of them exists and this arm never runs
-- (phase1.test.lua asserts the seven-of-seven case). Blacklisting the
-- pty layer's initcall removes `/dev/ptmx` from that list without
-- removing anything the boot needs — the other six come from the memory
-- device driver and the tty core, and taking either of those out takes
-- the console or `/dev/null` with it.
--
-- What this file cannot reach is the other arm: a node that exists and
-- cannot be stamped. peinit holds the privilege that makes the stamp
-- succeed, and nothing a test can stage reaches into devtmpfs to make a
-- node it cannot write.

local peinit = require("helpers.peinit")
peinit.claim(1)

test("a device node that does not exist is noted and skipped, and the boot continues",
    { spec = "peinit *phase1.device-node-stamping-is-advisory" },
    function(t)
        local vm = peinit.boot({
            name = "devnodes-missing",
            append = "initcall_blacklist=pty_init",
        })
        local log = vm:console():read_log()

        -- Noted, by name and as an absence rather than a failure: a node
        -- that is not there grants nothing to anyone, so there is no
        -- exposure to correct.
        t:assert(log:find("peinit: phase1 device node /dev/ptmx absent; nothing to stamp", 1, true),
            "peinit said which node was missing: " .. log:sub(-900))
        t:assert(not log:find("device node policy failed", 1, true),
            "and did not report it as a failure")

        -- Skipped, not aborted: the other six were stamped, and the
        -- count says so.
        t:assert(log:find("device node policy applied to 6 node%(s%)"),
            "the remaining six nodes were stamped")
        local null = vm:run("sd show /dev/null")
        null:assert_ok()
        t:assert(null.stdout:find("S%-1%-1%-0") or null.stdout:find(";WD"),
            "/dev/null still got its descriptor: " .. null.stdout)

        -- And the step did not end the boot, which is what "advisory"
        -- means.
        t:assert(not log:find("entering recovery", 1, true), "no recovery")
        t:assert(log:find("peinit: phase2 boot complete", 1, true),
            "the boot completed")

        -- The premise, checked from inside: the node really is absent,
        -- so the branch above was the one taken.
        local ptmx = vm:run("stat -c %F /dev/ptmx")
        t:assert(not ptmx:ok(), "/dev/ptmx is absent: " .. ptmx.stdout)
    end)
