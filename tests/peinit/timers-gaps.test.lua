-- peinit TRM §9.2 — evaluation and arming: what `status` says about a
-- timer, where those figures come from, when a trigger last fired, and
-- what a firing does for a service whose definition has gone.
--
-- The instrument is `svctl --json status`, whose `timers` array is the
-- supervisor's copy of the armed table (PSPU §4.14): per trigger the
-- occurrence armed (`scheduled_at`), when it will fire with its jitter
-- (`fires_at`), when it last fired (`last_fired_at`), or why it did not
-- arm (`not_armed`). A firing is read back through the same view, as the
-- `last_fired_at` it leaves, which is peinit's own record of when it
-- acted on the timer.
--
-- Some of the history is seeded, the way timer-persistence.test.lua does
-- it: an autorun script writes LastTimerRun values after the image's own
-- seeds have made the service keys and before Phase 2 registers a single
-- timer, which from peinit's side is the same as a previous boot having
-- left them there.
--
-- The schedules are UTC so that what `status` reports can be compared
-- with a constant, and either yearly (never due inside a run of this
-- file) or every few seconds (always due inside one).

local peinit = require("helpers.peinit")
peinit.claim(1)

local KEY = [[Machine\System\Services\]]

local FILES = {
    ["lcl/policy/autorun.d/20-pt-t-history.sh"] = { exec = true, [[#!/bin/sh
# A last run for some of this file's timers, as a previous boot would have
# left it. Runs at phase 1.5, after 10-apply-seeds.sh has created the keys.
set -eu
now=$(/bin/date +%s)
# A minute ago: recorded, and months short of due for a yearly schedule.
recent=$(( (now - 60) * 1000000000 ))
/bin/reg set 'Machine\System\Services\pt-t-seeded' LastTimerRun "qword:$recent"
# On a trigger that is not persistent, which therefore never reads it.
/bin/reg set 'Machine\System\Services\pt-t-jitter' LastTimerRun "qword:$recent"
]] },
}

local function service(name, list)
    local values = {
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
    }
    for _, v in ipairs(list) do values[#values + 1] = v end
    return { path = KEY .. name, values = values }
end

local function oneshot(name, triggers, extra)
    local list = {
        { name = "ImagePath", type = "sz", data = "/bin/true" },
        { name = "Type", type = "dword", data = 1 },
        { name = "Triggers", type = "multi", data = triggers },
    }
    for _, v in ipairs(extra or {}) do list[#list + 1] = v end
    return service(name, list)
end

local function resident(name, triggers, extra)
    local list = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "100000" } },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "Triggers", type = "multi", data = triggers },
    }
    for _, v in ipairs(extra or {}) do list[#list + 1] = v end
    return service(name, list)
end

local YEARLY = "*-01-01 00:00:00 UTC"

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },
    -- Two triggers, one every twenty seconds and one yearly, with a
    -- ten-second jitter on both. Not persistent: its seeded history is
    -- never read.
    oneshot("pt-t-jitter", { "timer:*-*-* *:*:0/20 UTC", "timer:" .. YEARLY }, {
        { name = "TimerJitter", type = "dword", data = 10 },
        { name = "TimerPersistent", type = "dword", data = 0 },
    }),
    -- Two triggers that will not arm, for two different reasons.
    oneshot("pt-t-bad", { "timer:*-*-* 25:00:00", "timer:*-02-30" }),
    -- Disabled: it has a trigger, and status reports none.
    oneshot("pt-t-disabled", { "timer:" .. YEARLY }, {
        { name = "Disabled", type = "dword", data = 1 },
    }),
    -- Persistent, with a recent run seeded, running for the length of the
    -- file so that deleting its definition does not discard it.
    resident("pt-t-seeded", { "boot", "timer:" .. YEARLY }),
    -- Persistent with no history at all: it catches up at boot.
    oneshot("pt-t-catchup", { "timer:" .. YEARLY }),
    -- pt-t-draining, the one whose definition is deleted while it runs,
    -- is not here: it is defined by its own test. It fires every three
    -- seconds and records each run, and every one of those registry
    -- writes reaches peinit's registry watch as a reload — which re-arms
    -- every timer from now and draws its jitter again. Defined from boot,
    -- it kept pushing pt-t-jitter's firing out of reach.
    -- Yearly and not persistent: the one the clock is stepped under.
    oneshot("pt-t-yearly", { "timer:" .. YEARLY }, {
        { name = "TimerPersistent", type = "dword", data = 0 },
    }),
}

local vm = peinit.boot({
    name = "timers-gaps",
    files = peinit.merge(FILES, peinit.seed("pt-t-gaps", SERVICES)),
})

--- Seconds since the epoch for an RFC 3339 UTC time as peinit writes them
--- (`2026-10-05T11:13:04.265324310Z`), or nil.
local function epoch(text)
    if type(text) ~= "string" then return nil end
    local y, mo, d, h, mi, s = text:match("^(%d+)-(%d+)-(%d+)T(%d+):(%d+):([%d%.]+)Z$")
    if not y then return nil end
    y, mo, d = tonumber(y), tonumber(mo), tonumber(d)
    y = mo <= 2 and y - 1 or y
    local era = (y >= 0 and y or y - 399) // 400
    local yoe = y - era * 400
    local doy = (153 * (mo + (mo > 2 and -3 or 9)) + 2) // 5 + d - 1
    local doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    local days = era * 146097 + doe - 719468
    return days * 86400 + tonumber(h) * 3600 + tonumber(mi) * 60 + tonumber(s)
end

local function status(name)
    return json.decode(vm:run("svctl --json status " .. name).stdout)
end

--- The status entry for one schedule of a service's timers.
local function timer(view, schedule)
    for _, entry in ipairs(view.timers or {}) do
        if entry.schedule == schedule then return entry end
    end
end

--- A qword value from the registry, as an integer, or nil.
local function qword(key, name)
    local out = vm:run("reg get '" .. key .. "'")
    if out.exit_code ~= 0 then return nil end
    for _, line in ipairs(peinit.lines(out.stdout)) do
        local n, data = line:match("^(%S+) = %S+ (%d+)")
        if n == name then return math.tointeger(tonumber(data)) or tonumber(data) end
    end
end

local function key_exists(key)
    return vm:run("reg get '" .. key .. "'").exit_code == 0
end

local function pause(seconds)
    pcall(wait_until, function() return false end,
        { timeout = seconds, interval = 0.25, desc = "a fixed pause" })
end

-- What the boot left, read before any test moves it.
local BOOT = {
    jitter = status("pt-t-jitter"),
    seeded = status("pt-t-seeded"),
    seeded_ns = qword(KEY .. "pt-t-seeded", "LastTimerRun"),
}

local EVERY_20 = "*-*-* *:*:0/20 UTC"

test("status reports every trigger of a service that is not disabled, armed or not, and list the soonest",
    { spec = "peinit *evalt.status-reports-each-trigger-as-armed" },
    function(t)
        -- Armed: the occurrence, the time it fires with its jitter drawn,
        -- and nothing in `not_armed`.
        local view = status("pt-t-jitter")
        t:assert_eq(#view.timers, 2, "both of pt-t-jitter's triggers are reported")
        for _, schedule in ipairs({ EVERY_20, YEARLY }) do
            local entry = timer(view, schedule)
            t:assert(entry, schedule .. " is reported")
            local at, fires = epoch(entry and entry.scheduled_at), epoch(entry and entry.fires_at)
            t:assert(at and fires, schedule .. " has an armed occurrence and a firing time: " ..
                tostring(entry and entry.scheduled_at) .. " / " .. tostring(entry and entry.fires_at))
            t:assert(fires >= at and fires <= at + 10,
                schedule .. " fires within its ten-second jitter of the occurrence: " ..
                entry.scheduled_at .. " -> " .. entry.fires_at)
            t:assert(entry.not_armed == nil, schedule .. " has no not_armed reason")
        end
        t:assert_eq(timer(view, YEARLY).scheduled_at:sub(6, 19), "01-01T00:00:00",
            "the yearly trigger's occurrence is New Year, UTC")

        -- Not armed: only the schedule and the reason.
        local bad = status("pt-t-bad")
        t:assert_eq(#bad.timers, 2, "both of pt-t-bad's triggers are reported, though neither armed")
        for _, schedule in ipairs({ "*-*-* 25:00:00", "*-02-30" }) do
            local entry = timer(bad, schedule)
            t:assert(entry and type(entry.not_armed) == "string" and #entry.not_armed > 0,
                schedule .. " says why it did not arm: " .. tostring(entry and entry.not_armed))
            t:assert(entry and entry.scheduled_at == nil and entry.fires_at == nil,
                schedule .. " has no occurrence and no firing time")
        end

        -- A disabled service's triggers are not reported at all.
        t:assert_eq(#(status("pt-t-disabled").timers or {}), 0,
            "a disabled service reports no timers")

        -- `list` carries each service's soonest `fires_at`.
        local list = json.decode(vm:run("svctl --json list").stdout)
        local by_name = {}
        for _, entry in ipairs(list.services) do by_name[entry.service] = entry end
        local soonest
        for _, entry in ipairs(status("pt-t-jitter").timers) do
            if entry.fires_at and (not soonest or epoch(entry.fires_at) < epoch(soonest)) then
                soonest = entry.fires_at
            end
        end
        -- The two reads straddle a possible firing; allow one re-arm.
        local listed = by_name["pt-t-jitter"].next_timer_at
        t:assert(listed and (listed == soonest or math.abs(epoch(listed) - epoch(soonest)) <= 30),
            "list's next_timer_at is the soonest fires_at: " .. tostring(listed) ..
            " vs " .. tostring(soonest))
        t:assert(by_name["pt-t-bad"].next_timer_at == nil,
            "and null for a service none of whose timers is armed")

        -- pt-t-bad has done its job. Graph validation refuses a
        -- configuration carrying its schedule (§7.4), so while it is
        -- defined every later reload — `reload-config` and the registry
        -- watch's alike — would be refused, and the tests after this one
        -- reload. A deletion is a configuration without it, and passes.
        vm:run("reg del '" .. KEY .. "pt-t-bad' --recursive"):assert_ok()
        wait_until(function()
            return vm:run("svctl --json status pt-t-bad").stdout
                :find("UNKNOWN_SERVICE", 1, true) or nil
        end, { timeout = 20, interval = 0.25, desc = "pt-t-bad to be gone" })
    end)

--- The guest's wall clock, in seconds (fractional).
local function guest_now()
    return tonumber(vm:run("date +%s.%N").stdout:match("[%d%.]+"))
end

--- Wait for pt-t-jitter's next firing after the one `last` names, and
--- return the trigger's entry as it stands after it.
local function next_firing(last)
    return wait_until(function()
        local entry = timer(status("pt-t-jitter"), EVERY_20)
        return entry.last_fired_at ~= last and entry or nil
    end, { timeout = 45, interval = 0.25, desc = "pt-t-jitter's next firing" })
end

test("the figures status reports are the ones armed, and are given again after each firing",
    { spec = "peinit *evalt.what-is-reported-is-what-is-armed" },
    function(t)
        local armed = timer(status("pt-t-jitter"), EVERY_20)

        -- The trigger fires at the time status gave, jitter and all: the
        -- firing peinit records is at `fires_at`, not at `scheduled_at`.
        local fired = next_firing(armed.last_fired_at)
        local acted = epoch(fired.last_fired_at)
        t:assert(math.abs(acted - epoch(armed.fires_at)) <= 1.5,
            "it fired when status said it would, " .. armed.fires_at ..
            ", and acted at " .. fired.last_fired_at)
        t:assert(acted >= epoch(armed.scheduled_at),
            "which is never before the occurrence itself")

        -- Re-armed after the firing, with the figures given again.
        t:assert(epoch(fired.scheduled_at) > epoch(armed.scheduled_at),
            "after the firing the next occurrence is reported: " .. fired.scheduled_at)
        local at, fires = epoch(fired.scheduled_at), epoch(fired.fires_at)
        t:assert(fires >= at and fires <= at + 10,
            "with its own jitter: " .. fired.scheduled_at .. " -> " .. fired.fires_at)

        -- And those are armed too: the firing after that one is at them.
        local again = next_firing(fired.last_fired_at)
        t:assert(math.abs(epoch(again.last_fired_at) - fires) <= 1.5,
            "the next firing is at the re-armed figure too: " .. fired.fires_at ..
            ", acted at " .. again.last_fired_at)
    end)

test("a reload re-arms from now, and status reports that arming rather than the one it replaced",
    { spec = "peinit *evalt.what-is-reported-is-what-is-armed" },
    function(t)
        -- The case where the two can differ: a reload while an occurrence
        -- has passed and its jitter has not. A reload re-arms every
        -- trigger from now (§9.3), so that occurrence is dropped and the
        -- next one armed. Wait for an arming with a jitter window wide
        -- enough to land a reload in.
        local window = wait_until(function()
            local entry = timer(status("pt-t-jitter"), EVERY_20)
            local now = guest_now()
            local at, fires = epoch(entry.scheduled_at), epoch(entry.fires_at)
            return fires - at >= 4 and now < at and entry or nil
        end, { timeout = 120, interval = 0.5, desc = "an arming with a usable jitter window" })
        wait_until(function()
            return guest_now() > epoch(window.scheduled_at) + 0.5 or nil
        end, { timeout = 30, interval = 0.1, desc = "the occurrence to pass" })

        vm:run("svctl --json reload-config"):assert_ok()
        local reloaded_at = guest_now()
        t:assert(reloaded_at < epoch(window.fires_at),
            "premise: the reload landed inside the jitter window (" .. reloaded_at ..
            " < " .. window.fires_at .. ")")
        local armed = timer(status("pt-t-jitter"), EVERY_20)
        t:assert(epoch(armed.scheduled_at) > reloaded_at,
            "status reports the occurrence the reload armed, after the reload, not the " ..
            "dropped one: " .. armed.scheduled_at .. " / " .. armed.fires_at ..
            " (before the reload: " .. window.scheduled_at .. " / " .. window.fires_at .. ")")

        -- And the trigger fires at what status now says.
        local fired = next_firing(armed.last_fired_at)
        t:assert(math.abs(epoch(fired.last_fired_at) - epoch(armed.fires_at)) <= 1.5,
            "it fired at the reported figure " .. armed.fires_at ..
            ", acting at " .. fired.last_fired_at)
    end)

test("when a trigger last fired is seeded at boot and kept across a reload, and a deleted-and-remade definition keeps it",
    { spec = "peinit *evalt.the-last-firing-is-seeded-at-boot-and-kept-across-a-reload" },
    function(t)
        -- Seeded at boot from the recorded timestamp of a persistent
        -- trigger that was not due.
        t:assert(BOOT.seeded_ns, "premise: a last run was seeded for pt-t-seeded")
        local seeded = timer(BOOT.seeded, YEARLY)
        t:assert(seeded and seeded.last_fired_at,
            "pt-t-seeded reports a last firing from boot on")
        t:assert(math.abs(epoch(seeded.last_fired_at) - BOOT.seeded_ns / 1e9) < 0.001,
            "and it is the recorded one: " .. tostring(seeded.last_fired_at) ..
            " for " .. tostring(BOOT.seeded_ns))

        -- Set by a boot catch-up.
        local catchup = timer(status("pt-t-catchup"), YEARLY)
        local written = qword(KEY .. "pt-t-catchup", "LastTimerRun")
        t:assert(catchup.last_fired_at and written,
            "pt-t-catchup caught up at boot and recorded it")
        t:assert(math.abs(epoch(catchup.last_fired_at) - written / 1e9) < 1,
            "and reports that catch-up as its last firing")

        -- A non-persistent trigger records nothing and reads nothing: its
        -- seeded LastTimerRun is not what it reports.
        t:assert(timer(BOOT.jitter, YEARLY).last_fired_at == nil,
            "a non-persistent trigger reports no firing before peinit started, history or not")

        -- Kept across a reload, which re-arms from now and reads no history.
        vm:run("svctl --json reload-config"):assert_ok()
        t:assert_eq(timer(status("pt-t-seeded"), YEARLY).last_fired_at, seeded.last_fired_at,
            "a reload keeps it")

        -- Deleted, and made again, as the same service and schedule.
        -- pt-t-seeded is running, so the deletion leaves it in the table
        -- withdrawn rather than discarding it (§3.8).
        vm:run("reg del '" .. KEY .. "pt-t-seeded' --recursive"):assert_ok()
        wait_until(function() return status("pt-t-seeded").definition_removed == true or nil end,
            { timeout = 20, interval = 0.25, desc = "the deletion to be seen" })
        t:assert_eq(timer(status("pt-t-seeded"), YEARLY).last_fired_at, seeded.last_fired_at,
            "kept while the definition is withdrawn")
        local key = KEY .. "pt-t-seeded"
        vm:run("reg new '" .. key .. "'"):assert_ok()
        for _, set in ipairs({
            "ImagePath 'sz:/bin/sleep'", "Arguments 'multi:100000'", "Identity 'sz:SYSTEM'",
            "Readiness 'dword:1'", "RestartPolicy 'dword:0'",
        }) do
            vm:run("reg set '" .. key .. "' " .. set):assert_ok()
        end
        vm:run("reg set '" .. key .. "' Triggers 'multi:boot,timer:" .. YEARLY .. "'"):assert_ok()
        wait_until(function() return status("pt-t-seeded").definition_removed == false or nil end,
            { timeout = 20, interval = 0.25, desc = "the definition to be back" })
        vm:run("svctl --json reload-config"):assert_ok()
        t:assert_eq(timer(status("pt-t-seeded"), YEARLY).last_fired_at, seeded.last_fired_at,
            "and kept when it is made again, the same service and schedule")
    end)

test("no last run is recorded for a definition deleted while its service runs on",
    { spec = "peinit *evalt.no-last-run-is-recorded-for-a-deleted-definition" },
    function(t)
        local key = KEY .. "pt-t-draining"
        -- Resident, persistent, firing every three seconds.
        vm:write_file("/tmp/pt-t-draining.json", peinit.encode_json({ keys = {
            resident("pt-t-draining", { "timer:*-*-* *:*:0/3 UTC" }),
        } }))
        vm:run("reg apply /tmp/pt-t-draining.json"):assert_ok()
        wait_until(function()
            return not vm:run("svctl --json status pt-t-draining").stdout
                :find("UNKNOWN_SERVICE", 1, true) or nil
        end, { timeout = 20, interval = 0.25, desc = "pt-t-draining's definition to be loaded" })
        vm:run("svctl start pt-t-draining", { timeout = 60 }):assert_ok()

        -- Premise: it fires and records, every three seconds.
        local first = wait_until(function() return qword(key, "LastTimerRun") end,
            { timeout = 20, interval = 0.5, desc = "pt-t-draining's first recorded run" })
        wait_until(function()
            local now = qword(key, "LastTimerRun")
            return now and now ~= first or nil
        end, { timeout = 20, interval = 0.5, desc = "a second recorded run" })

        vm:run("reg del '" .. key .. "' --recursive"):assert_ok()
        local withdrawn = wait_until(function()
            local v = status("pt-t-draining")
            return v.definition_removed == true and v or nil
        end, { timeout = 20, interval = 0.25, desc = "the deletion to be seen" })
        t:assert_eq(withdrawn.state, "active", "premise: the service runs on, withdrawn")
        local before = timer(withdrawn, "*-*-* *:*:0/3 UTC")
        t:assert(before, "premise: its trigger is still armed")

        -- Several firings later, peinit has acted on the timer and
        -- written nothing.
        local fired = wait_until(function()
            local entry = timer(status("pt-t-draining"), "*-*-* *:*:0/3 UTC")
            return entry and entry.last_fired_at ~= before.last_fired_at
                and epoch(entry.last_fired_at) > epoch(before.last_fired_at) + 5 and entry or nil
        end, { timeout = 30, interval = 0.5, desc = "two more firings of the withdrawn service" })
        t:assert(fired, "premise: the timer fired while the definition was gone")
        pause(1)
        t:assert(not key_exists(key),
            "and the service's key was not made again by a last-run write")
    end)

test("a firing for a service that has been discarded does nothing, and is not an error",
    { spec = "peinit *evalt.a-firing-for-a-service-that-is-gone-does-nothing" },
    function(t)
        local key = KEY .. "pt-t-draining"
        t:assert(status("pt-t-draining").definition_removed == true,
            "premise: pt-t-draining is the withdrawn service the previous test left")

        -- Stopped, it is discarded; nothing re-plans its timer, which
        -- comes due again within three seconds.
        vm:run("svctl stop pt-t-draining", { timeout = 60 })
        wait_until(function()
            return vm:run("svctl --json status pt-t-draining").stdout
                :find("UNKNOWN_SERVICE", 1, true) or nil
        end, { timeout = 20, interval = 0.25, desc = "pt-t-draining to be discarded" })

        -- Several periods. An error out of the firing would have taken
        -- PID 1 into recovery (PEI-1234); a start would have needed a
        -- definition; a last-run write would have made the key again.
        pause(10)
        t:assert(vm:run("svctl --json list").stdout:find('"services"', 1, true),
            "peinit is still answering its control socket, not in recovery")
        local recovery = vm:run("revstrm --snapshot --pretty --type 'peinit.recovery.entered'",
            { timeout = 60 })
        t:assert(not recovery.stdout:find("peinit.recovery.entered", 1, true),
            "and never entered recovery: " .. recovery.stdout)
        t:assert(vm:run("svctl --json status pt-t-draining").stdout:find("UNKNOWN_SERVICE", 1, true),
            "the service is still gone: nothing started it again")
        t:assert(not key_exists(key), "and no last run was recorded for it")
    end)

test("a clock change re-arms a trigger, and status reports the occurrence armed against the new clock",
    { spec = "peinit *evalt.what-is-reported-is-what-is-armed" },
    function(t)
        local year = tonumber(vm:run("date -u +%Y").stdout:match("%d+"))
        local before = timer(status("pt-t-yearly"), YEARLY)
        t:assert_eq(before.scheduled_at, ("%d-01-01T00:00:00.000000000Z"):format(year + 1),
            "premise: armed for the coming New Year")

        -- Past that New Year. The trigger is recomputed against the new
        -- wall clock and armed again; status is given that arming.
        vm:run(("date -u -s '%d-05-10 01:00:00'"):format(year + 1)):assert_ok()
        local after = wait_until(function()
            local entry = timer(status("pt-t-yearly"), YEARLY)
            return entry.scheduled_at ~= before.scheduled_at and entry or nil
        end, { timeout = 20, interval = 0.25, desc = "the re-arm after the clock change" })
        t:assert_eq(after.scheduled_at, ("%d-01-01T00:00:00.000000000Z"):format(year + 2),
            "the reported occurrence is the one after the new now")
        t:assert_eq(after.fires_at, after.scheduled_at, "with no jitter to add")
    end)
