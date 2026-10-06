-- Peinit TRM §2.8 — recovery records why it was entered, as a KMES audit
-- event, before it does anything else.
--
-- Most recoveries happen before the provium agent exists, and the console
-- tail is then all a test has — which is enough for the console line
-- (rec-recovery.test.lua reads it) but not for the event, because nothing
-- in a recovery boot can be asked to read the ring. So this file enters
-- recovery LATE: an autorun script (Phase 1 step 7, after the agent has
-- been started from the same queue) puts a directory where the control
-- socket is about to be bound in step 9, and the bind fails. peinit then
-- enters recovery with the agent still running beside it, and the agent
-- can read the ring with `revstrm --snapshot`.
--
-- Nothing drains the ring in this boot: eventd is a Phase 2 service and
-- Phase 2 never ran, so the record is still buffered when the snapshot is
-- taken. `peinit.recovery.entered` is essential, so no emission policy
-- can have kept it out.

local peinit = require("helpers.peinit")
local revstrm = require("helpers.revstrm")
peinit.claim(1)

test("entering recovery emits a peinit.recovery.entered audit event naming the reason",
    { spec = "peinit *recovery.the-reason-is-audited" },
    function(t)
        local vm = peinit.boot({
            name = "rec-audit",
            stage = "autoruns",
            files = {
                ["lcl/policy/autorun.d/20-pt-block.sh"] = {
                    "#!/bin/sh\nmkdir -p /run/services/peinit/control.sock\n",
                    exec = true,
                },
            },
        })
        vm:console():expect("entering recovery", peinit.STAGE_TIMEOUT)
        local log = vm:console():read_log()
        t:assert(log:find("peinit: entering recovery: Infrastructure", 1, true),
            "the boot went to recovery from the infrastructure step: " .. log:sub(-600))

        -- The ring, as the agent sees it, each payload read back into the
        -- dotted paths the catalogue names.
        local events, raw = revstrm.snapshot(vm, { "peinit.recovery.*" })
        t:assert_eq(#events, 1, "exactly one recovery event is in the ring: " .. raw)
        local event = events[1]
        t:assert_eq(event.type, "peinit.recovery.entered", "and it is the entry record")

        -- The reason is recorded twice over: as a stable label a consumer
        -- can switch on, and as the error's own words a person can read
        -- (never Rust Debug output).
        t:assert_eq(revstrm.field(event, "outcome.reason"), "infrastructure",
            "the reason label names the step that failed: " .. event.payload)
        local detail = tostring(revstrm.field(event, "outcome.detail"))
        t:assert(detail:find("bind control socket", 1, true),
            "and the detail carries the failure itself: " .. event.payload)
        t:assert(not detail:find("Infrastructure(", 1, true),
            "in its own words, not as a Debug rendering: " .. detail)
    end)
