-- Peinit TRM §2.6 — the other half of the downgrade rule: what happens
-- to a service that forced Safe mode and then survives into the rebuilt
-- graph.
--
-- rec-modes-downgrade.test.lua covers the shape the downgrade was
-- designed around, where only one side of the offending pair is
-- Critical: Safe mode drops the non-Critical side, the rebuild has no
-- cycle left, and the service that forced the downgrade is left
-- Inactive rather than Failed.
--
-- This is the shape that does not work out so neatly. Both sides are
-- Critical, so both are eligible in Safe mode, the rebuilt graph
-- contains the same cycle, and the cycle blocker fails them there. That
-- is the right outcome — two Critical services requiring each other is
-- a configuration no order can start, and saying so is more useful than
-- leaving them Inactive with no explanation — but it means §2.6's
-- protection is about being *excluded from the rebuild*, not about
-- having caused the downgrade.
--
-- Its own file because it needs its own boot, and the sibling file's
-- single-boot narrative is load-bearing there.

local peinit = require("helpers.peinit")
peinit.claim(1)

local RESIDENT = "#!/bin/sh\nwhile : ; do sleep 30; done\n"

local function critical_service(name, requires)
    return { path = [[Machine\System\Services\]] .. name, values = {
        { name = "ImagePath", type = "sz", data = "/lcl/pt/cc-resident.sh" },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "ErrorControl", type = "dword", data = 1 },
        { name = "Requires", type = "multi", data = { requires } },
    } }
end

local vm = peinit.boot({
    name = "critcycle",
    files = peinit.merge(
        { ["lcl/pt/cc-resident.sh"] = { RESIDENT, exec = true } },
        peinit.seed("zz-pt-critcycle", {
            { path = [[Machine\System]] },
            { path = [[Machine\System\Services]] },
            critical_service("pt-cc-a", "pt-cc-b"),
            critical_service("pt-cc-b", "pt-cc-a"),
        })),
})

local log = vm:console():read_log()

local function view(service)
    return json.decode(vm:run("svctl --json status " .. service).stdout)
end

test("a service that survives the Safe-mode rebuild can still fail in it",
    { spec = "peinit *mode.a-service-that-survives-the-rebuild-can-still-fail-there" },
    function(t)
        -- The downgrade happened, and named the cycle that caused it.
        t:assert(log:find("boot downgraded to safe mode", 1, true),
            "a critical cycle downgraded the boot: " .. log:sub(-1200))

        -- And both members are Failed, with the cause that says why:
        -- they are in the rebuilt graph, and the rebuilt graph still has
        -- the cycle. Being the reason for the downgrade bought them
        -- nothing, because Safe mode did not exclude them.
        for _, service in ipairs({ "pt-cc-a", "pt-cc-b" }) do
            local seen = view(service)
            t:assert_eq(seen.state, "failed",
                service .. " survived the rebuild and was blocked in it")
            t:assert_eq(seen.cause, "cycle_detected",
                service .. " says the cycle is why")
        end
    end)
