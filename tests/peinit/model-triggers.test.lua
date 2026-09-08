-- peinit TRM §3.4 — triggers, from the running side. What the forms
-- *mean* rather than which of them decode: `model-decode` owns the
-- arity rules, and this file owns what happens once a definition
-- carrying them is loaded.
--
-- The `Disabled` claims are the substance of it, and they are stronger
-- than "a disabled service does not start at boot" (which §2.5 already
-- covers): *no* trigger fires, of any kind, and the timers of a
-- disabled service are not even armed. A timer is the only trigger that
-- keeps firing, so it is the one that can show "not armed" rather than
-- "did not happen to fire" -- `*-*-* *:*:0/2` is every two seconds, and
-- twenty-odd seconds of it is evidence.
--
-- Every timer service writes a line per run to its own file under /run,
-- so a run count is a line count and the difference between a service
-- whose timer is armed and one whose timer is not is visible rather
-- than inferred.

local peinit = require("helpers.peinit")
peinit.claim(1)

local FILES = {
    -- One line per invocation, into a file named after the caller.
    ["pt/tick.sh"] = 'echo tick >> "/run/pt-tick-$1"\n',
}

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },
}

local function service(name, values)
    SERVICES[#SERVICES + 1] =
        { path = [[Machine\System\Services\]] .. name, values = values }
end

--- A Oneshot that records one line per run, as SYSTEM.
local function ticker(name, values)
    local out = {
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi", data = { "/pt/tick.sh", name } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Type", type = "dword", data = 1 },
    }
    for _, value in ipairs(values) do out[#out + 1] = value end
    service(name, out)
end

-- A timer on a Simple service and a boot trigger on a Oneshot: §3.4
-- says the two are independent, and the pair is the whole claim.
service("pt-simple-timer", {
    { name = "ImagePath", type = "sz", data = "/bin/sleep" },
    { name = "Arguments", type = "multi", data = { "1" } },
    { name = "Identity", type = "sz", data = "SYSTEM" },
    { name = "Readiness", type = "dword", data = 1 },
    -- Type is absent, so this is a Simple service, and it carries a
    -- timer.
    { name = "Triggers", type = "multi", data = { "timer:*-*-* *:*:0/2" } },
    { name = "RestartPolicy", type = "dword", data = 0 },
})
ticker("pt-oneshot-boot", {
    { name = "Triggers", type = "multi", data = { "boot" } },
    { name = "RemainAfterExit", type = "dword", data = 1 },
})

-- The same timer, enabled and disabled. Everything but `Disabled` is
-- identical, so the difference between their run counts is the flag.
ticker("pt-timer-on", {
    { name = "Triggers", type = "multi", data = { "timer:*-*-* *:*:0/2" } },
})
ticker("pt-timer-off", {
    { name = "Triggers", type = "multi", data = { "timer:*-*-* *:*:0/2" } },
    { name = "Disabled", type = "dword", data = 1 },
})

-- A disabled service carrying every trigger type at once: none of them
-- may fire, and a `boot:settled` one is the case a boot-only rule would
-- miss.
service("pt-disabled-all", {
    { name = "ImagePath", type = "sz", data = "/bin/sh" },
    { name = "Arguments", type = "multi", data = { "/pt/tick.sh", "pt-disabled-all" } },
    { name = "Identity", type = "sz", data = "SYSTEM" },
    { name = "Type", type = "dword", data = 1 },
    { name = "RemainAfterExit", type = "dword", data = 1 },
    { name = "Disabled", type = "dword", data = 1 },
    { name = "TTYPath", type = "sz", data = "/dev/tty9" },
    { name = "Triggers", type = "multi", data = {
        "boot", "boot:settled", "tty:released", "timer:*-*-* *:*:0/2",
        -- A trigger type peinit does not know, which §3.4 says is
        -- suppressed too: "not any trigger type added later".
        "pt-future:whatever",
    } },
})

-- Two boot triggers on one service. Multiple triggers of one type are
-- allowed, and the service is started once rather than twice.
ticker("pt-two-boots", {
    { name = "Triggers", type = "multi", data = { "boot", "boot" } },
    { name = "RemainAfterExit", type = "dword", data = 1 },
})

local vm = peinit.boot({
    name = "triggers",
    files = peinit.merge(FILES, peinit.seed("pt-triggers", SERVICES)),
})

local function status(service_name)
    local r = vm:run("svctl --json status " .. service_name)
    if r.stdout:find("UNKNOWN_SERVICE", 1, true) then return nil end
    local ok, decoded = pcall(json.decode, r.stdout)
    return ok and decoded or nil
end

--- How many times `service_name`'s ticker has run.
local function ticks(service_name)
    local r = vm:run("cat /run/pt-tick-" .. service_name .. " 2>/dev/null | wc -l")
    return tonumber((r.stdout:gsub("%s+$", ""))) or 0
end

-- Let the two-second timers run for a while, once, here rather than
-- inside each test: the disabled cases are proved by a count that stays
-- at zero over a window the enabled one filled, and a window measured
-- separately per test would be arguing from different evidence each
-- time.
local ARMED_TICKS = wait_until(function()
    local n = ticks("pt-timer-on")
    return n >= 5 and n or nil
end, { timeout = 90, interval = 1, desc = "the enabled timer to fire five times" })

test("triggers are independent of service type",
    { spec = "peinit *trig.triggers-are-independent-of-service-type" },
    function(t)
        -- A Simple service with a timer, and a Oneshot started at boot.
        -- Both of the crossings §3.4 names, on one machine.
        local oneshot = wait_until(function()
            local st = status("pt-oneshot-boot")
            return st and st.state == "completed" and st or nil
        end, { timeout = 60, interval = 0.4, desc = "the boot-triggered Oneshot" })
        t:assert_eq(oneshot.state, "completed", "a Oneshot started at boot")
        t:assert(ticks("pt-oneshot-boot") >= 1, "and ran")

        -- The Simple service's timer fires and starts it. Its Type is
        -- absent, so it is Simple by the schema's default, and it is
        -- `/bin/sleep 1` rather than a ticker because what matters is
        -- that a *Simple* service was activated by a timer at all.
        --
        -- The started line is the evidence rather than a sampled status:
        -- the service runs for a second every two, so a status read is a
        -- coin toss, while the line is a fact the console keeps.
        vm:console():expect("peinit: service pt-simple-timer started",
            peinit.STAGE_TIMEOUT)
        t:assert(status("pt-simple-timer"),
            "a Simple service was activated by a timer")
    end)

test("multiple triggers of one type are allowed, and start the service once",
    { spec = "peinit *trig.multiple-triggers-of-one-type-are-allowed" },
    function(t)
        local st = wait_until(function()
            local s = status("pt-two-boots")
            return s and s.state == "completed" and s or nil
        end, { timeout = 60, interval = 0.4, desc = "the twice-boot-triggered service" })
        t:assert_eq(st.state, "completed", "a service with two boot triggers started")

        -- One service, one activation: the trigger list is a set of
        -- reasons to start rather than a list of starts to perform.
        vm:run("sleep 2")
        t:assert_eq(ticks("pt-two-boots"), 1,
            "and ran once, not once per trigger")
    end)

test("Disabled suppresses every trigger, of every kind",
    { spec = "peinit *trig.disabled-suppresses-every-trigger" },
    function(t)
        -- pt-disabled-all carries a boot trigger, a deferred boot
        -- trigger, a terminal handover trigger and a two-second
        -- timer, and a trigger type peinit does not recognise. The boot
        -- is long finished, the settle deadline has passed, and the
        -- timer has had the window above to fire in. None of them
        -- started it.
        local st = status("pt-disabled-all")
        t:assert(st, "the service is loaded")
        t:assert_eq(st.state, "inactive",
            "a disabled service carrying five triggers was never activated: " ..
            tostring(st.state))
        t:assert_eq(ticks("pt-disabled-all"), 0, "and never ran")

        -- And the console agrees, which rules out a start that happened
        -- and left no file behind.
        t:assert(not vm:console():read_log()
            :find("peinit: service pt-disabled-all started", 1, true),
            "peinit never reported starting it")
    end)

test("a disabled service's timers are neither armed nor serviced",
    { spec = "peinit *trig.a-disabled-services-timers-are-not-armed" },
    function(t)
        -- pt-timer-on and pt-timer-off are the same definition but for
        -- the flag, and they were loaded from the same read. One has
        -- fired repeatedly; the other has not fired at all.
        t:assert(ARMED_TICKS >= 5,
            "the enabled timer fired " .. ARMED_TICKS .. " times")
        t:assert_eq(ticks("pt-timer-off"), 0,
            "and the identical disabled one fired none")

        local off = status("pt-timer-off")
        t:assert(off, "the disabled service is loaded, not discarded")
        t:assert_eq(off.state, "inactive", "and is sitting Inactive")
    end)

test("a disabled service is still loaded, and an explicit start still works",
    { spec = "peinit *trig.a-disabled-service-can-still-be-started-explicitly" },
    function(t)
        -- `Disabled` suppresses automatic activation and nothing else,
        -- so an administrator can still start the service by hand. That
        -- is why §3.4 says the flag is not an access-control mechanism.
        local before = ticks("pt-timer-off")
        local started = vm:run("svctl --json start pt-timer-off")
        started:assert_ok()

        wait_until(function() return ticks("pt-timer-off") > before end,
            { timeout = 30, interval = 0.3,
              desc = "the disabled service to run when told to" })
        t:assert(ticks("pt-timer-off") > before,
            "an explicit start ran a service no trigger was allowed to")
    end)
