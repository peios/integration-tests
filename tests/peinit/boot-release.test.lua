-- peinit TRM §2.5 — starting: what a service reaching a state does to the
-- services waiting on it.
--
-- Four claims, one boot. Each is a pair — a target and a dependent whose
-- only reason to wait is that target — so the pairs cannot interfere, and
-- the two that share a target (`pt-r-slowfail`) share it on purpose: the
-- whole difference between `Requires` and `Wants` is what the two
-- dependents do about the same terminal state.
--
-- Two things are staged rather than assumed:
--
-- `login-console` is disabled. It is the image's own `boot:settled`
-- service, it owns /dev/console, and once it has the device peinit's
-- console messages stop appearing there — which would silently empty the
-- ordering assertions below. Disabling it costs this file nothing: no
-- claim here is about a deferred start.
--
-- `pt-r-slowok` and `pt-r-slowfail` sleep before exiting. A target that
-- finishes instantly proves nothing about waiting, because a dependent
-- starting immediately afterwards is indistinguishable from one that
-- never waited at all.

local peinit = require("helpers.peinit")
peinit.claim(1)

local BOOT = { name = "Triggers", type = "multi", data = { "boot" } }
local ONESHOT = { name = "Type", type = "dword", data = 1 }
--- Never restart: these services are meant to reach a terminal state and
--- stay there. The default is OnFailure, which would put the two that
--- exit non-zero into Backoff instead.
local NEVER = { name = "RestartPolicy", type = "dword", data = 0 }

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

--- A boot-triggered Oneshot whose only job is to require one target.
local function dependent(name, kind, target)
    return oneshot(name, { BOOT, { name = kind, type = "multi", data = { target } } })
end

local vm = peinit.boot({
    name = "release",
    files = peinit.seed("zz-pt-release", {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
        { path = [[Machine\System\Services\login-console]], values = {
            { name = "Disabled", type = "dword", data = 1 },
        } },

        -- The three satisfying states, one target each.
        svc("pt-r-alive", "/bin/sleep", { "3600" }, { BOOT }),
        dependent("pt-r-after-alive", "Requires", "pt-r-alive"),
        oneshot("pt-r-remain", { BOOT, { name = "RemainAfterExit", type = "dword", data = 1 } }),
        dependent("pt-r-after-remain", "Requires", "pt-r-remain"),
        oneshot("pt-r-skip", { BOOT,
            { name = "Conditions", type = "multi", data = { "path:/pt-not-here" } } }),
        dependent("pt-r-after-skip", "Requires", "pt-r-skip"),

        -- A Oneshot with no RemainAfterExit: Completed, then Inactive.
        oneshot("pt-r-once", { BOOT }),
        dependent("pt-r-after-once", "Requires", "pt-r-once"),

        -- A target that takes its time and then succeeds.
        svc("pt-r-slowok", "/bin/sh", { "-c", "sleep 5; exit 0" }, { ONESHOT, BOOT, NEVER }),
        dependent("pt-r-after-slowok", "Requires", "pt-r-slowok"),

        -- A target that takes its time and then fails: terminal, and not
        -- satisfying. Two dependents, differing only in the word.
        svc("pt-r-slowfail", "/bin/sh", { "-c", "sleep 3; exit 1" }, { ONESHOT, BOOT, NEVER }),
        dependent("pt-r-hard", "Requires", "pt-r-slowfail"),
        dependent("pt-r-wants", "Wants", "pt-r-slowfail"),
    }),
})

local function status(service)
    return vm:run("svctl --json status " .. service).stdout
end

local function state(service)
    return status(service):match('"state":"([^"]+)"')
end

--- The cause peinit last recorded, or nil. Meaningful as "never ran"
--- only once the boot has stopped moving: a service in Starting already
--- has a cause.
local function cause(service)
    return status(service):match('"cause":"([^"]+)"')
end

-- Sampled while the boot is still running, because the claim is about
-- what has NOT happened yet: every reading taken while `pt-r-slowok` is
-- still in Starting must find `pt-r-after-slowok` untouched. The target
-- sleeps five seconds, so there is a wide window to sample; the counts
-- are asserted in the test below rather than here, so a bad sample fails
-- the test that cares rather than the whole file.
local SAMPLES, VIOLATIONS = 0, 0
for _ = 1, 60 do
    if state("pt-r-slowok") == "starting" then break end
    vm:clock():sleep("100ms")
end
for _ = 1, 100 do
    if state("pt-r-slowok") ~= "starting" then break end
    SAMPLES = SAMPLES + 1
    if state("pt-r-after-slowok") ~= "inactive" or cause("pt-r-after-slowok") ~= nil then
        VIOLATIONS = VIOLATIONS + 1
    end
    vm:clock():sleep("100ms")
end

-- The barrier. "phase2 boot complete" is printed when the plan has been
-- dispatched, so every start is still ahead of it and a status read at
-- that mark races the boot.
--
-- Named services rather than the whole table: waiting for `svctl list`
-- to show nothing moving waits for the image's services too, and one of
-- those can sit in Starting for tens of seconds on a loaded host. Every
-- service this file defines ends up with a recorded cause — including
-- the two that are never started, which are given one by being skipped
-- and by being failed for their dependency — so the whole set is a
-- usable barrier.
local EXPECTED = {
    "pt-r-alive", "pt-r-after-alive",
    "pt-r-remain", "pt-r-after-remain",
    "pt-r-skip", "pt-r-after-skip",
    "pt-r-once", "pt-r-after-once",
    "pt-r-slowok", "pt-r-after-slowok",
    "pt-r-slowfail", "pt-r-hard", "pt-r-wants",
}
local reached_rest = false
for _ = 1, 400 do
    local moving = false
    for _, service in ipairs(EXPECTED) do
        local text = status(service)
        local at_rest = text:match('"state":"([^"]+)"')
        if not text:match('"cause":"[^"]+"')
            or at_rest == "starting" or at_rest == "backoff"
            or at_rest == "stopping" or at_rest == "reloading" then
            moving = true
        end
    end
    if not moving then
        reached_rest = true
        break
    end
    vm:clock():sleep("250ms")
end
assert(reached_rest, "the services this file defines never came to rest")

local LOG = vm:console():read_log()

--- Where peinit reported a service started, or nil. Plain find, not a
--- pattern: every service name here contains a hyphen, which a Lua
--- pattern reads as a repetition operator.
local function started_at(service)
    return LOG:find("peinit: service " .. service .. " started", 1, true)
end

test("a service reaching a dependent-satisfying state releases its dependents",
    { spec = "peinit *phase2.a-satisfying-state-releases-dependents" },
    function(t)
        -- The three states the chapter names, one pair each: Active for a
        -- Simple service, Completed for a Oneshot that remains, Skipped
        -- for a service whose conditions did not hold.
        t:assert_eq(state("pt-r-alive"), "active", "the Simple target is Active")
        t:assert_eq(state("pt-r-remain"), "completed", "the remaining Oneshot is Completed")
        t:assert_eq(state("pt-r-skip"), "skipped", "the conditioned service is Skipped")
        t:assert_eq(cause("pt-r-skip"), "condition_skipped",
            "for its condition rather than for anything else")

        for _, name in ipairs({ "pt-r-after-alive", "pt-r-after-remain", "pt-r-after-skip" }) do
            t:assert(cause(name), name .. " was released and ran: " .. status(name))
        end

        -- Released after, not alongside: each dependent's start follows
        -- its target's.
        for _, pair in ipairs({ { "pt-r-alive", "pt-r-after-alive" },
                                { "pt-r-remain", "pt-r-after-remain" } }) do
            local target, waiter = pair[1], pair[2]
            t:assert(started_at(target) and started_at(waiter)
                and started_at(target) < started_at(waiter),
                waiter .. " started after " .. target)
        end
        -- Skipped has no start of its own to order against; that it was
        -- never started at all, and released its dependent anyway, is the
        -- claim.
        t:assert(not started_at("pt-r-skip"),
            "the skipped service never started, and still released its dependent")
    end)

test("a Oneshot releases its dependents through Completed before going Inactive",
    { spec = "peinit *phase2.a-oneshot-releases-dependents-before-going-inactive" },
    function(t)
        -- Without RemainAfterExit the service does not stay Completed, so
        -- the state it is found in afterwards is Inactive — which does
        -- not satisfy dependents. Its dependent ran regardless, so the
        -- release happened on the way through.
        t:assert_eq(state("pt-r-once"), "inactive",
            "the Oneshot ended Inactive: " .. status("pt-r-once"))
        t:assert_eq(cause("pt-r-once"), "clean_exit", "having exited cleanly")
        t:assert(cause("pt-r-after-once"),
            "and its dependent was released and ran: " .. status("pt-r-after-once"))
        t:assert(started_at("pt-r-once") < started_at("pt-r-after-once"),
            "in that order")

        -- The contrast that makes the transit visible: the same
        -- definition plus RemainAfterExit stays in Completed.
        t:assert_eq(state("pt-r-remain"), "completed",
            "while the Oneshot that remains is still Completed")
    end)

test("a hard dependent waits for its target to reach a satisfying state, not merely a terminal one",
    { spec = "peinit *phase2.a-hard-dependent-waits-for-a-satisfying-state" },
    function(t)
        -- Waiting, first: for as long as the slow target had not
        -- finished, its dependent had not been started.
        t:assert(SAMPLES > 0,
            "the target was observed in Starting at all, so the wait was sampled")
        t:assert_eq(VIOLATIONS, 0,
            "in " .. SAMPLES .. " readings taken while the target was still Starting, "
            .. "its dependent was never started")
        t:assert_eq(state("pt-r-slowok"), "inactive",
            "the slow target then completed: " .. status("pt-r-slowok"))
        t:assert(cause("pt-r-after-slowok"), "and released its dependent")

        -- And what it waits for is satisfying rather than terminal.
        -- pt-r-slowfail reaches Failed, which is as terminal as a state
        -- gets, and its hard dependent is failed rather than released.
        t:assert_eq(state("pt-r-slowfail"), "failed", "the failing target is Failed")
        t:assert_eq(cause("pt-r-slowfail"), "process_crash", "for its own exit")
        t:assert_eq(state("pt-r-hard"), "failed", "and its hard dependent is Failed too")
        t:assert_eq(cause("pt-r-hard"), "dependency_failure",
            "for the dependency rather than for anything it did itself")
        t:assert(not started_at("pt-r-hard"), "having never been started")
    end)

test("a Wants dependent waits only for a terminal state, satisfying or not",
    { spec = "peinit *phase2.a-wants-dependent-waits-only-for-a-terminal-state" },
    function(t)
        -- The same target, in the same boot, that failed pt-r-hard.
        t:assert_eq(state("pt-r-slowfail"), "failed", "the shared target is Failed")
        t:assert(cause("pt-r-wants"),
            "the Wants dependent ran regardless: " .. status("pt-r-wants"))

        -- Ordering is what makes this "waits only for" rather than
        -- "does not wait": the target sleeps three seconds before
        -- failing, and the dependent starts after it has.
        local failed_at = LOG:find("peinit: service pt%-r%-slowfail failed")
        t:assert(failed_at, "peinit reported the target failing: " .. LOG:sub(-800))
        t:assert(started_at("pt-r-wants") > failed_at,
            "and the Wants dependent started after that, not before it")
    end)
