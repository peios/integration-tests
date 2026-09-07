-- Peinit TRM §2.6 — Safe mode is a boot-time verdict, not a runtime one.
--
-- The entry list for Safe mode has three items and a Critical service
-- crashing is not one of them: that failure follows the ordinary path
-- (restart budget, reboot, counter increment, recovery), and the machine it
-- happens on stays in the mode it booted in. The claim is a negative, so
-- the file is built around making the negative observable rather than
-- vacuous.
--
-- `pt-rt-plain` is what does that. It is boot-triggered and neither
-- Critical nor `SafeMode`, so it is a service that a Safe-mode graph would
-- not contain — it starts on this Full boot, and if peinit ever rebuilt the
-- graph in Safe mode it would be the first thing to go. It is still running
-- at the end of the file, so no rebuild happened.
--
-- `pt-rt-crit` is Critical and `RestartPolicy=Never`, which is what keeps
-- this test from rebooting the machine out from under itself. The reboot a
-- Critical failure eventually earns is owed to `RestartBudgetExhausted`
-- specifically, and a policy of Never fails the service on the exit cause
-- instead — so the runtime failure happens, is recorded, and the machine
-- stays up to be asked about it. It has no boot trigger, so the failure is
-- unambiguously a runtime one rather than part of the boot.

local peinit = require("helpers.peinit")
peinit.claim(1)

local RESIDENT = "#!/bin/sh\nwhile : ; do sleep 30; done\n"

local vm = peinit.boot({
    name = "runtime-critical",
    files = peinit.merge(
        { ["lcl/pt/rt-resident.sh"] = { RESIDENT, exec = true } },
        peinit.seed("zz-pt-runtime", {
            { path = [[Machine\System]] },
            { path = [[Machine\System\Services]] },
            {
                path = [[Machine\System\Services\pt-rt-crit]],
                values = {
                    { name = "ImagePath", type = "sz", data = "/bin/false" },
                    { name = "Type", type = "dword", data = 1 },
                    { name = "Identity", type = "sz", data = "SYSTEM" },
                    { name = "Readiness", type = "dword", data = 1 },
                    { name = "ErrorControl", type = "dword", data = 1 },
                    { name = "RestartPolicy", type = "dword", data = 0 },
                },
            },
            {
                path = [[Machine\System\Services\pt-rt-plain]],
                values = {
                    { name = "ImagePath", type = "sz", data = "/lcl/pt/rt-resident.sh" },
                    { name = "Identity", type = "sz", data = "SYSTEM" },
                    { name = "Readiness", type = "dword", data = 1 },
                    { name = "Triggers", type = "multi", data = { "boot" } },
                },
            },
        })
    ),
})

vm:console():expect("peinit: service pt-rt-plain started", peinit.STAGE_TIMEOUT)

local function state_of(service)
    local status = vm:run("svctl --json status " .. service)
    status:assert_ok()
    return status.stdout:match('"state":"([^"]+)"')
end

-- Not `assert_ok`: the point of this start is that it fails.
vm:run("svctl start pt-rt-crit")
local crashed
for _ = 1, 60 do
    crashed = state_of("pt-rt-crit")
    if crashed == "failed" then break end
    vm:clock():sleep("500ms")
end

local log = vm:console():read_log()

local function occurrences(haystack, needle)
    local count, at = 0, 1
    while true do
        local found = haystack:find(needle, at, true)
        if not found then return count end
        count = count + 1
        at = found + 1
    end
end

test("a Critical service failing at runtime does not put the machine into Safe mode",
    { spec = "peinit *mode.a-runtime-critical-failure-does-not-enter-safe-mode" },
    function(t)
        t:assert_eq(crashed, "failed",
            "the Critical service really did fail at runtime")

        -- Nothing was downgraded. A downgrade writes its reason to the
        -- console before anything else, so its absence is the absence of the
        -- verdict rather than of a symptom.
        t:assert_eq(occurrences(log, "peinit: boot downgraded to safe mode:"), 0,
            "no downgrade was recorded")
        t:assert(log:find("Full boot", 1, true),
            "the machine is in the mode it booted in")

        -- And no rebuild happened, which a Safe mode entry would have
        -- required: a service a Safe graph would exclude is still running.
        t:assert_eq(state_of("pt-rt-plain"), "active",
            "a service ineligible for Safe mode is still running")

        -- Nor did the machine take the other branch of that sentence and
        -- reboot: this failure was not a budget exhaustion.
        t:assert_eq(occurrences(log, peinit.marks.banner), 1,
            "the machine did not reboot either")
    end)
