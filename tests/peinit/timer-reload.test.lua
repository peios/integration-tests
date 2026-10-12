-- PEI-1381: reloads must not redraw jitter or postpone unchanged timers.
local peinit = require("helpers.peinit")
peinit.claim(1)
local KEY = [[Machine\System\Services\]]
local YEARLY = "*-01-01 00:00:00 UTC"
local SLOW = "*-*-* *:*:0/20 UTC"
local function timer_service(name, schedule, persistent, jitter)
    return { path = KEY .. name, values = {
        { name = "ImagePath", type = "sz", data = "/bin/true" },
        { name = "Type", type = "dword", data = 1 },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "Triggers", type = "multi", data = { "timer:" .. schedule } },
        { name = "TimerPersistent", type = "dword", data = persistent },
        { name = "TimerJitter", type = "dword", data = jitter },
    } }
end
local files = peinit.seed("pt-timer-reload", {
    { path = [[Machine\System]] }, { path = [[Machine\System\Services]] },
    timer_service("pt-reload-yearly", YEARLY, 0, 10),
    timer_service("pt-reload-slow", SLOW, 0, 10),
    timer_service("pt-reload-writer", "*-*-* *:*:0/3 UTC", 1, 0),
})
files = peinit.test_binary("peinit", files)
local vm = peinit.boot({ name = "timer-reload", files = files })
local function timer(name)
    local result = vm:run("svctl --json status " .. name)
    result:assert_ok()
    return assert(json.decode(result.stdout).timers[1])
end
local function history()
    return vm:run("reg get '" .. KEY .. "pt-reload-writer'").stdout:match("LastTimerRun = [^\r\n]+")
end

test("explicit reload preserves an unchanged timer deadline and its jitter",
    { spec = "peinit *persist.unchanged-timers-keep-their-armed-firing", tags = { "pei1381" } }, function(t)
        local before = timer("pt-reload-yearly")
        for _ = 1, 3 do
            vm:run("svctl --json reload-config"):assert_ok()
            local after = timer("pt-reload-yearly")
            t:assert_eq(after.scheduled_at, before.scheduled_at, "same occurrence")
            t:assert_eq(after.fires_at, before.fires_at, "same jittered deadline")
        end
    end)

test("frequent persistent timer writes do not postpone another timer's firing",
    { spec = "peinit *persist.unchanged-timers-keep-their-armed-firing", tags = { "pei1381" } }, function(t)
        local before = timer("pt-reload-slow")
        local yearly = timer("pt-reload-yearly")
        local written = history()
        local changes, fired = 0, false
        wait_until(function()
            local next_written = history()
            if next_written and next_written ~= written then
                written, changes = next_written, changes + 1
            end
            local current = timer("pt-reload-slow")
            if current.last_fired_at ~= before.last_fired_at then fired = true end
            if not fired then
                t:assert_eq(current.scheduled_at, before.scheduled_at, "bookkeeping keeps the occurrence")
                t:assert_eq(current.fires_at, before.fires_at, "bookkeeping keeps its deadline")
            end
            local still_yearly = timer("pt-reload-yearly")
            t:assert_eq(still_yearly.fires_at, yearly.fires_at, "registry watch does not redraw jitter")
            return fired and changes >= 2
        end, { timeout = 45, interval = 0.25, desc = "slow timer to fire amid persistent bookkeeping" })
        t:log("observed " .. changes .. " new LastTimerRun values and a slow-timer firing")
    end)

test("changed timer settings re-arm and disabling removes the trigger",
    { spec = "peinit *control.reload-config.calendar-timers-are-re-armed-without-catch-up", tags = { "pei1381" } }, function(t)
        vm:run("reg set '" .. KEY .. "pt-reload-yearly' TimerJitter dword:0"):assert_ok()
        vm:run("svctl --json reload-config"):assert_ok()
        local changed = timer("pt-reload-yearly")
        t:assert_eq(changed.fires_at, changed.scheduled_at, "changed jitter takes effect")
        vm:run("reg set '" .. KEY .. "pt-reload-yearly' Disabled dword:1"):assert_ok()
        vm:run("svctl --json reload-config"):assert_ok()
        local status = json.decode(vm:run("svctl --json status pt-reload-yearly").stdout)
        t:assert_eq(#status.timers, 0, "disabled timer unregistered")
    end)
