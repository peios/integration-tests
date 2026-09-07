-- peinit TRM §2.5 — deferred starts: what "the boot has stopped moving"
-- means, and what happens when it has.
--
-- This file is the settling half. Everything here happens on a boot whose
-- plan reaches rest, with `SettleTimeout` set to ten minutes so that a
-- deferred service starting at all can only be the set having
-- settled — the deadline is not going to arrive inside this test. The
-- deadline half, where nothing settles and the clock is what ends the
-- wait, is boot-settle-deadline.test.lua.
--
-- The plan is stocked deliberately: one service ending in each of the
-- settled states the chapter names that a test can produce — Active,
-- Completed, Failed, Skipped and Inactive — so "settled" is being
-- asserted over the set of states rather than over one convenient one.
-- Abandoned is the sixth and has no route from here; see the report.
--
-- `login-console` is disabled. It is the image's own `boot:settled`
-- service and it takes /dev/console when it starts, after which peinit's
-- console messages no longer appear there — including the one this file
-- asserts the ABSENCE of, which would then be absent for the wrong
-- reason. With it disabled the console stays peinit's and the deferred
-- services under test are the only ones in the dispatch.
--
-- The boot attempt counter is staged at 2 with a one-second success
-- grace, so that "the boot was unaffected" can be asserted as the boot
-- actually being declared successful rather than merely not crashing.

local peinit = require("helpers.peinit")
peinit.claim(1)

local BOOT = { name = "Triggers", type = "multi", data = { "boot" } }
local SETTLED = { name = "Triggers", type = "multi", data = { "boot:settled" } }
local ONESHOT = { name = "Type", type = "dword", data = 1 }
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

local vm = peinit.boot({
    name = "settle",
    files = peinit.merge(
        { [".peinit/boot-attempts"] = "2\n" },
        peinit.seed("zz-pt-settle", {
            { path = [[Machine\System]] },
            { path = [[Machine\System\Boot]], values = {
                { name = "SettleTimeout", type = "dword", data = 600 },
                { name = "BootSuccessGrace", type = "dword", data = 1 },
            } },
            { path = [[Machine\System\Services]] },
            { path = [[Machine\System\Services\login-console]], values = {
                { name = "Disabled", type = "dword", data = 1 },
            } },

            -- One plan service per settled state.
            svc("pt-s-active", "/bin/sleep", { "3600" }, { BOOT }),
            oneshot("pt-s-completed", { BOOT,
                { name = "RemainAfterExit", type = "dword", data = 1 } }),
            oneshot("pt-s-inactive", { BOOT }),
            svc("pt-s-failed", "/bin/false", nil, { ONESHOT, BOOT, NEVER }),
            oneshot("pt-s-skipped", { BOOT,
                { name = "Conditions", type = "multi", data = { "path:/pt-not-here" } } }),

            -- Two deferred services that can start, and one that cannot:
            -- its Requires target is not in the registry at all.
            oneshot("pt-defer-one", { SETTLED }),
            oneshot("pt-defer-two", { SETTLED }),
            oneshot("pt-defer-broken", { SETTLED,
                { name = "Requires", type = "multi", data = { "pt-nonexistent" } } }),
        })
    ),
})

local function status(service)
    return vm:run("svctl --json status " .. service).stdout
end

local function state(service)
    return status(service):match('"state":"([^"]+)"')
end

--- The cause peinit last recorded for a service, or nil if it has never
--- transitioned. For a deferred service in a finished boot that is the
--- difference between "was started" and "was not".
local function cause(service)
    return status(service):match('"cause":"([^"]+)"')
end

-- Wait for the dispatch, and then for what it started to come to rest.
--
-- Polling on the service table rather than `console():expect` because
-- the console stream is consumed by whoever reads it first and every
-- test below wants the whole log.
--
-- Both conditions, not just the cause: a service acquires its cause on
-- entering Starting, so a table read taken the moment a cause appears
-- can still catch it mid-start — and the tests below assert the state
-- each deferred service ENDED in.
local function at_rest(service)
    local here = state(service)
    return cause(service) ~= nil and here ~= "starting" and here ~= "backoff"
        and here ~= "stopping" and here ~= "reloading"
end

local dispatched = false
for _ = 1, 480 do
    if at_rest("pt-defer-one") and at_rest("pt-defer-two") then
        dispatched = true
        break
    end
    vm:clock():sleep("250ms")
end

local LOG = vm:console():read_log()

--- How many times peinit reported this service starting. Plain find, not
--- a pattern: every name here contains a hyphen, which a Lua pattern
--- reads as a repetition operator.
local function start_count(service)
    local needle, count, at = "peinit: service " .. service .. " started", 0, 1
    while true do
        local found = LOG:find(needle, at, true)
        if not found then return count end
        count, at = count + 1, found + 1
    end
end

test("every plan service in a state it will not leave counts as settled, and the deferred services then start",
    { spec = "peinit *settle.which-states-count-as-settled" },
    function(t)
        t:assert(dispatched, "the deferred services were started within the test's budget")

        -- The five settled states a test can produce, one service each.
        -- Abandoned is the sixth the chapter names and there is no route
        -- to it from the harness.
        local expected = {
            ["pt-s-active"] = "active",
            ["pt-s-completed"] = "completed",
            ["pt-s-failed"] = "failed",
            ["pt-s-skipped"] = "skipped",
            ["pt-s-inactive"] = "inactive",
        }
        for service, want in pairs(expected) do
            t:assert_eq(state(service), want, service .. " came to rest in " .. want)
        end

        -- With `SettleTimeout` at ten minutes, a dispatch inside this
        -- test's budget cannot be the deadline: the set settling is the
        -- only thing that could have ended the wait. peinit says so
        -- itself by not printing the line it prints when the clock wins.
        -- Ten minutes rather than a tighter figure because the margin
        -- has to cover the image's own graph on a loaded host, where a
        -- service can sit in Starting for tens of seconds.
        t:assert(not LOG:find("boot did not settle in time", 1, true),
            "the wait ended on the set settling, not on the deadline: " .. LOG:sub(-800))
        t:assert_eq(
            vm:run([[reg get 'Machine\System\Boot' SettleTimeout]]).stdout:match("%d+"), "600",
            "and the deadline peinit read really was ten minutes away")
    end)

test("the deferred services start once each",
    { spec = "peinit *settle.deferred-services-start-once-each" },
    function(t)
        -- Once, not once per settled service and not once per turn: the
        -- dispatch fires at most once for the whole boot.
        t:assert_eq(start_count("pt-defer-one"), 1, "pt-defer-one started exactly once")
        t:assert_eq(start_count("pt-defer-two"), 1, "pt-defer-two started exactly once")

        -- Independently, too: neither is named in the other's definition,
        -- and both ran.
        t:assert_eq(state("pt-defer-one"), "inactive", "pt-defer-one ran to completion")
        t:assert_eq(state("pt-defer-two"), "inactive", "pt-defer-two ran to completion")

        -- Still once a few seconds later, so the count above is not just
        -- a reading taken before a second dispatch.
        vm:clock():sleep("3s")
        local later = vm:console():read_log()
        local _, again = later:gsub("peinit: service pt%-defer%-one started", "")
        t:assert_eq(again, 1, "and still exactly once after the boot went quiet")
    end)

test("a deferred service that cannot be started is dropped, and the boot is unaffected",
    { spec = "peinit *settle.a-failed-deferred-start-does-not-affect-the-boot" },
    function(t)
        -- The one that cannot start: its `Requires` target is not a
        -- service on this machine.
        t:assert(not cause("pt-defer-broken"),
            "the deferred service with an unsatisfiable dependency never started: "
            .. status("pt-defer-broken"))

        -- One refusing service does not stop the others.
        t:assert(cause("pt-defer-one") and cause("pt-defer-two"),
            "both of its siblings started regardless")

        -- And it does not affect the boot. Not merely "the boot did not
        -- crash": the boot was declared successful, which is what resets
        -- the attempt counter the profile staged at 2.
        t:assert(LOG:find("peinit: phase2 boot complete", 1, true), "the boot completed")
        local counter
        for _ = 1, 60 do
            counter = vm:read_file("/.peinit/boot-attempts"):match("%d+")
            if counter == "0" then break end
            vm:clock():sleep("500ms")
        end
        t:assert_eq(counter, "0",
            "and was declared successful, resetting the boot attempt counter")
    end)
