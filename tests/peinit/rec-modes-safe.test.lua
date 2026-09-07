-- Peinit TRM §2.6 — what Safe mode starts, and what a Safe boot that
-- succeeds does to the boot attempt counter.
--
-- One boot, forced with `peios.safemode=1`, because every claim here is
-- about the same thing: which services a Safe boot considers eligible. The
-- eligibility filter has two arms — `ErrorControl=Critical` and
-- `SafeMode=1` — and modes.test.lua already covers the `SafeMode=1` arm
-- from a seeded service. This file covers the Critical arm, and it covers
-- it twice over.
--
-- The first is a seeded service that declares Critical and nothing else, so
-- there is no `SafeMode` value anywhere near it to be doing the work. The
-- second is the image's own platform graph, which is the honest version of
-- the same question: authd, lpsd and eventd ship with `ErrorControl=1` and
-- no `SafeMode` value at all, and if Critical did not imply SafeMode a Safe
-- boot of this image would come up with no authority and no event store.
-- The assertions read the absence of the value out of the registry rather
-- than trusting the seed files on disk, since it is what peinit saw that
-- matters.
--
-- `BootSuccessGrace` is seeded down to a second for the same reason
-- attempts.test.lua seeds it: the reset lands only after every Critical
-- service has held a satisfying state for the grace, and the default is
-- thirty seconds of a test doing nothing.

local peinit = require("helpers.peinit")
peinit.claim(1)

local RESIDENT = "#!/bin/sh\nwhile : ; do sleep 30; done\n"

--- A boot-triggered service, with whatever `extra` values distinguish it.
--- Deliberately minimal otherwise: the fields that are not here are the
--- ones the eligibility filter must not be reading.
local function boot_service(name, extra)
    local values = {
        { name = "ImagePath", type = "sz", data = "/lcl/pt/safe-resident.sh" },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "Triggers", type = "multi", data = { "boot" } },
    }
    for _, value in ipairs(extra or {}) do values[#values + 1] = value end
    return { path = [[Machine\System\Services\]] .. name, values = values }
end

local vm = peinit.boot({
    name = "safe-eligibility",
    append = "peios.safemode=1",
    files = peinit.merge(
        { ["lcl/pt/safe-resident.sh"] = { RESIDENT, exec = true } },
        { [".peinit/boot-attempts"] = "2\n" },
        peinit.seed("zz-pt-safe", {
            { path = [[Machine\System]] },
            { path = [[Machine\System\Boot]], values = {
                { name = "BootSuccessGrace", type = "dword", data = 1 },
            } },
            { path = [[Machine\System\Services]] },
            -- Critical, and nothing else. No SafeMode value at all.
            boot_service("pt-safe-crit", {
                { name = "ErrorControl", type = "dword", data = 1 },
            }),
            -- Neither Critical nor SafeMode: the control for both arms.
            boot_service("pt-safe-plain"),
        })
    ),
})

local log = vm:console():read_log()

local function state_of(service)
    local status = vm:run("svctl --json status " .. service)
    status:assert_ok()
    return status.stdout:match('"state":"([^"]+)"')
end

--- `state_of`, once the service has stopped moving.
---
--- The console mark `peinit.boot` waits for is the point at which the plan
--- has been dispatched, not the point at which it has finished: a Notify
--- service is still in Starting there, waiting on its own READY=1. Reading
--- the state at the boot mark is therefore reading a stopwatch, and a
--- service that reaches Active a hundred milliseconds later reads as
--- Starting.
local function settled_state(service)
    local state
    for _ = 1, 60 do
        state = state_of(service)
        if state ~= "starting" then return state end
        vm:clock():sleep("500ms")
    end
    return state
end

test("Safe mode starts a Critical service, and leaves a service that is neither behind",
    { spec = "peinit *mode.safe-starts-critical-services" },
    function(t)
        t:assert(log:find("Safe", 1, true), "this boot is a Safe one")
        t:assert(log:find("peinit: service pt-safe-crit started", 1, true),
            "the Critical service was in the Safe mode boot set")
        t:assert(not log:find("peinit: service pt-safe-plain started", 1, true),
            "and the one that is neither Critical nor SafeMode was not")
        t:assert_eq(state_of("pt-safe-plain"), "inactive",
            "the ineligible service was left alone rather than failed")
    end)

test("a Critical service needs no SafeMode value, as the image's own platform graph shows",
    { spec = "peinit *mode.critical-implies-safemode" },
    function(t)
        -- The image ships authd, lpsd and eventd with ErrorControl=1 and no
        -- SafeMode value. If the implication did not hold, a Safe boot would
        -- come up with none of them.
        for _, service in ipairs({ "authd", "lpsd", "eventd" }) do
            local key = [[Machine\System\Services\]] .. service
            local error_control = vm:run("reg get '" .. key .. "' ErrorControl")
            error_control:assert_ok()
            t:assert(error_control.stdout:find("1"),
                service .. " is Critical: " .. error_control.stdout)

            local safe_mode = vm:run("reg get '" .. key .. "' SafeMode")
            t:assert(safe_mode.exit_code ~= 0,
                service .. " declares no SafeMode value, and got: " .. safe_mode.stdout)

            t:assert_eq(settled_state(service), "active",
                service .. " started in Safe mode on its ErrorControl alone")
        end

        -- And the same reading of the same registry says trustd is neither,
        -- so the two arms of the filter are being read and not ignored.
        local trustd_key = [[Machine\System\Services\trustd]]
        t:assert(vm:run("reg get '" .. trustd_key .. "' SafeMode").exit_code ~= 0,
            "trustd declares no SafeMode either")
        t:assert(vm:run("reg get '" .. trustd_key .. "' ErrorControl").stdout:find("0"),
            "and it is not Critical")
        t:assert_eq(state_of("trustd"), "inactive", "so Safe mode did not start it")

        -- The seeded case, with nothing else in the definition that could be
        -- doing the work.
        t:assert(vm:run(
            "reg get 'Machine\\System\\Services\\pt-safe-crit' SafeMode").exit_code ~= 0,
            "and the seeded Critical service declares no SafeMode value")
    end)

test("a Safe boot that succeeds resets the boot attempt counter",
    { spec = "peinit *mode.a-successful-safe-boot-resets-the-counter" },
    function(t)
        -- Staged at 2 and incremented to 3 before Phase 2, so a reset is
        -- visible as a change rather than as a value that was always there.
        local settled
        for _ = 1, 60 do
            settled = vm:read_file("/.peinit/boot-attempts"):match("%d+")
            if settled == "0" then break end
            vm:clock():sleep("500ms")
        end
        t:assert_eq(settled, "0",
            "a Safe boot reaching health resets the counter, exactly as a Full one does")
    end)
