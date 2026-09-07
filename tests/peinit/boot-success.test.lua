-- peinit TRM §2.5 — boot success: when peinit decides the boot worked.
--
-- Success has no console line and no control verb. Its one observable is
-- its consequence: a successful boot resets the boot attempt counter
-- (§2.7), the plain decimal file at /.peinit/boot-attempts. So both tests
-- here stage a non-zero counter and watch for it to become zero — a
-- reset that can only have come from peinit declaring the boot a success.
--
-- Both also seed a short `BootSuccessGrace`. The default is thirty
-- seconds of continuously-held health, which is a fair setting for a
-- machine and a poor one for a test: it would put every reading half a
-- minute after the event it is about. Shortening it tests the rule
-- rather than the default, and the default itself is the subject of a
-- different chapter.
--
-- The criterion is over EVERY Critical service in the plan, the image's
-- own included, so a service this file adds can only ever make the
-- criterion harder to satisfy. That is what makes the counter a usable
-- oracle: a reset means every Critical service satisfied it, so a
-- definition designed to fail one reading and pass another decides the
-- outcome on its own.
--
-- One VM per test, sequential: the two need different grace periods and
-- the grace is read once, at the top of Phase 2.

local peinit = require("helpers.peinit")
peinit.claim(1)

local BOOT = { name = "Triggers", type = "multi", data = { "boot" } }
local ONESHOT = { name = "Type", type = "dword", data = 1 }
local CRITICAL = { name = "ErrorControl", type = "dword", data = 1 }

local function svc(name, image, args, extra)
    local values = {
        { name = "ImagePath", type = "sz", data = image },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
    }
    if args then values[#values + 1] = { name = "Arguments", type = "multi", data = args } end
    for _, v in ipairs(extra or {}) do values[#values + 1] = v end
    return { path = [[Machine\System\Services\]] .. name, values = values }
end

local function oneshot(name, extra)
    local e = { ONESHOT }
    for _, v in ipairs(extra or {}) do e[#e + 1] = v end
    return svc(name, "/bin/true", nil, e)
end

local function counter(vm)
    return vm:read_file("/.peinit/boot-attempts"):match("%d+")
end

--- Poll for the reset, returning whether it happened inside `ticks`
--- half-seconds.
local function wait_for_reset(vm, ticks)
    for _ = 1, ticks do
        if counter(vm) == "0" then return true end
        vm:clock():sleep("500ms")
    end
    return counter(vm) == "0"
end

local function state(vm, service)
    return vm:run("svctl --json status " .. service).stdout:match('"state":"([^"]+)"')
end

test("the criterion is a dependent-satisfying state, not Active",
    { spec = "peinit *success.the-criterion-is-satisfying-not-active" },
    function(t)
        -- Two Critical services that can never be Active. A Oneshot with
        -- RemainAfterExit stops at Completed; a service whose condition
        -- does not hold stops at Skipped. Both satisfy dependents, and a
        -- criterion written as "Active" would leave this machine unable
        -- ever to call its boot successful.
        local vm = peinit.boot({
            name = "satisfying",
            files = peinit.merge(
                { [".peinit/boot-attempts"] = "2\n" },
                peinit.seed("zz-pt-satisfying", {
                    { path = [[Machine\System]] },
                    { path = [[Machine\System\Boot]], values = {
                        { name = "BootSuccessGrace", type = "dword", data = 1 },
                    } },
                    { path = [[Machine\System\Services]] },
                    oneshot("pt-crit-completed", { BOOT, CRITICAL,
                        { name = "RemainAfterExit", type = "dword", data = 1 } }),
                    oneshot("pt-crit-skipped", { BOOT, CRITICAL,
                        { name = "Conditions", type = "multi", data = { "path:/pt-not-here" } } }),
                })
            ),
        })

        for _ = 1, 80 do
            if state(vm, "pt-crit-completed") == "completed"
                and state(vm, "pt-crit-skipped") == "skipped" then
                break
            end
            vm:clock():sleep("250ms")
        end
        t:assert_eq(state(vm, "pt-crit-completed"), "completed",
            "the Critical Oneshot came to rest in Completed, never Active")
        t:assert_eq(state(vm, "pt-crit-skipped"), "skipped",
            "and the Critical service whose condition did not hold, in Skipped")

        t:assert(wait_for_reset(vm, 80),
            "the boot was declared successful with neither of them Active, "
            .. "so the counter was reset; it read " .. tostring(counter(vm)))
    end)

test("the grace period must be held continuously",
    { spec = "peinit *success.the-grace-period-must-be-held-continuously" },
    function(t)
        -- A Critical service that holds a satisfying state until it is
        -- told not to. Ten seconds of grace, and the stop below lands
        -- within the first few of them.
        local vm = peinit.boot({
            name = "continuous",
            files = peinit.merge(
                { [".peinit/boot-attempts"] = "2\n" },
                peinit.seed("zz-pt-continuous", {
                    { path = [[Machine\System]] },
                    { path = [[Machine\System\Boot]], values = {
                        { name = "BootSuccessGrace", type = "dword", data = 10 },
                    } },
                    { path = [[Machine\System\Services]] },
                    svc("pt-crit-daemon", "/bin/sleep", { "3600" }, { BOOT, CRITICAL,
                        { name = "RestartPolicy", type = "dword", data = 0 } }),
                })
            ),
        })

        local active = false
        for _ = 1, 60 do
            if state(vm, "pt-crit-daemon") == "active" then
                active = true
                break
            end
            vm:clock():sleep("250ms")
        end
        t:assert(active, "the Critical service reached Active")
        t:assert(counter(vm) ~= "0",
            "and the grace has not elapsed yet, so the boot is not yet successful")

        -- Break the run. An explicit stop is not a failure — no restart
        -- budget, no reboot — it is simply a Critical service that is no
        -- longer in a state that satisfies anything.
        vm:run("svctl stop pt-crit-daemon"):assert_ok()
        t:assert(state(vm, "pt-crit-daemon") ~= "active",
            "the Critical service left its satisfying state: "
            .. tostring(state(vm, "pt-crit-daemon")))

        -- Fifteen seconds with it stopped: half again the grace period,
        -- so a boot that counted from the FIRST time the service was
        -- satisfying would have been declared successful by now.
        for _ = 1, 30 do
            t:assert(counter(vm) ~= "0",
                "the boot is not declared successful while a Critical service is down")
            vm:clock():sleep("500ms")
        end

        -- Put it back, and the grace runs again from here.
        vm:run("svctl start pt-crit-daemon"):assert_ok()
        t:assert(wait_for_reset(vm, 80),
            "once the service held a satisfying state for the whole grace period, "
            .. "the boot was declared successful; the counter read " .. tostring(counter(vm)))
    end)
