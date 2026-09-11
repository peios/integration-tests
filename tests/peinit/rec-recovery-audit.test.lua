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
-- taken.

local peinit = require("helpers.peinit")
peinit.claim(1)

test("entering recovery emits a recovery.entered audit event naming the reason",
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

        -- The ring, as the agent sees it. `--pretty` prints the msgpack
        -- payload as indented `key   value` rows under a header line
        -- that ends in the event type.
        local snapshot = vm:run("revstrm --snapshot --pretty --type 'recovery.*'",
            { timeout = 60 })
        snapshot:assert_ok()
        local events, current = {}, nil
        for line in snapshot.stdout:gmatch("[^\r\n]+") do
            local kind = line:match(
                "^%d%d:%d%d:%d%d[%.%d]*%s+cpu.-#%d+%s+%u+%s+([%w_]+%.[%w_]+)%s*$")
            if kind then
                current = { type = kind, payload = "" }
                events[#events + 1] = current
            elseif current and line:match("^%s") then
                current.payload = current.payload .. line .. "\n"
            end
        end
        t:assert_eq(#events, 1,
            "exactly one recovery event is in the ring: " .. snapshot.stdout)
        local event = events[1]
        t:assert_eq(event.type, "recovery.entered", "and it is the entry record")

        local function field(name)
            local value = event.payload:match("\n?%s+" .. name .. "%s%s+([^\r\n]*)")
            return value and (value:gsub('^"', ""):gsub('"$', ""))
        end
        -- The reason is recorded twice over: as a stable label a consumer
        -- can switch on, and as the full detail a person can read.
        t:assert_eq(field("reason"), "infrastructure",
            "the reason label names the step that failed: " .. event.payload)
        t:assert(tostring(field("detail")):find("bind control socket", 1, true),
            "and the detail carries the failure itself: " .. event.payload)
    end)
