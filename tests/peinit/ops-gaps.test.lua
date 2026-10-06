-- peinit TRM §8.2 — operations: what a start's clocks are tied to. A start
-- the graph is holding has no lifetime, a released one gets it from the
-- release, and a start that has ended takes its readiness deadline with
-- it.
--
-- The holds are read two ways. On the boot path, where the graph holds a
-- dependent of a target that crashed into Backoff, the record is the
-- `peinit.operation.ended` event: a start that completed, as itself, after
-- several times its own `StartTimeout`, was held without a clock and got
-- one from its release. On the on-demand path the instrument is
-- `svctl operation-status`, as in ops-operations.test.lua: a held start
-- is an operation that stays Pending, with no `started_at`, for longer
-- than its own `StartTimeout`.
--
-- The readiness-deadline claim is read off the service instead, because
-- what a stale deadline did (PEI-1267) was fail the *next* start of the
-- same service, and that is what a test can watch for: the next start
-- running past the moment the stale deadline would have come due,
-- untouched, with no `peinit.internal-error.contained` on the ring.

local peinit = require("helpers.peinit")
local revstrm = require("helpers.revstrm")
peinit.claim(1)

local function service(name, values)
    local out = {
        { name = "Identity", type = "sz", data = "SYSTEM" },
    }
    for _, v in ipairs(values) do out[#out + 1] = v end
    return { path = [[Machine\System\Services\]] .. name, values = out }
end

local function resident(name, extra)
    local values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "100000" } },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
    }
    for _, v in ipairs(extra or {}) do values[#values + 1] = v end
    return service(name, values)
end

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },

    -- Started at boot, crashes on its first launch before it is ready,
    -- and comes up on its second, fifteen seconds later: a target in
    -- Backoff, which is one of the TRM's facts with no clock of its own.
    -- Notify, so that the first launch never satisfies anybody; an Alive
    -- service would be Active, and release its dependents, the moment it
    -- was launched.
    service("pt-flaky", {
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi", data = { "-c",
            "[ -e /run/pt-flaky-once ] && " ..
            "exec /usr/bin/pt-notify sleep 1 send READY=1 sleep 100000; " ..
            "touch /run/pt-flaky-once; exit 1" } },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "Readiness", type = "dword", data = 0 },
        { name = "StartTimeout", type = "dword", data = 60 },
        { name = "RestartPolicy", type = "dword", data = 1 },
        { name = "RestartDelay", type = "dword", data = 15 },
        { name = "RestartMaxRetries", type = "dword", data = 10 },
        { name = "RestartWindow", type = "dword", data = 600 },
    }),
    -- Held on pt-flaky's Backoff, with a StartTimeout a fifth of the hold.
    resident("pt-held", {
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "Requires", type = "multi", data = { "pt-flaky" } },
        { name = "StartTimeout", type = "dword", data = 3 },
    }),
    -- Held on pt-held, which is itself held only on a clockless fact.
    resident("pt-held-twice", {
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "Requires", type = "multi", data = { "pt-held" } },
        { name = "StartTimeout", type = "dword", data = 3 },
    }),

    -- The same pair again, for the on-demand path: not started at boot,
    -- failing on every launch until /run/pt-flaky2-ok exists.
    service("pt-flaky2", {
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi", data = {
            "-c", "[ -e /run/pt-flaky2-ok ] && exec /bin/sleep 100000; exit 1" } },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 1 },
        { name = "RestartDelay", type = "dword", data = 20 },
        { name = "RestartMaxRetries", type = "dword", data = 10 },
        { name = "RestartWindow", type = "dword", data = 600 },
    }),
    resident("pt-held2", {
        { name = "Requires", type = "multi", data = { "pt-flaky2" } },
        { name = "StartTimeout", type = "dword", data = 3 },
    }),

    -- A target that is starting, and stays Starting: Notify, never
    -- ready, with a long StartTimeout. That is a dependency with a clock.
    service("pt-slowstart", {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "100000" } },
        { name = "Readiness", type = "dword", data = 0 },
        { name = "StartTimeout", type = "dword", data = 60 },
        { name = "RestartPolicy", type = "dword", data = 0 },
    }),
    resident("pt-on-starting", {
        { name = "Requires", type = "multi", data = { "pt-slowstart" } },
        { name = "StartTimeout", type = "dword", data = 4 },
    }),

    -- Notify. Never ready on its first start; on any start after
    -- /run/pt-aborted-ready exists it says READY=1 a second in. The
    -- `exec` keeps the main job's pid, which is what peinit authenticates
    -- a notification by.
    service("pt-aborted", {
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi", data = { "-c",
            "[ -e /run/pt-aborted-ready ] && exec /usr/bin/pt-notify sleep 1 send READY=1 sleep 100000; " ..
            "exec /bin/sleep 100000" } },
        { name = "Readiness", type = "dword", data = 0 },
        { name = "StartTimeout", type = "dword", data = 10 },
        { name = "RestartPolicy", type = "dword", data = 0 },
    }),
}

local vm = peinit.boot({
    name = "ops-gaps",
    files = peinit.merge(peinit.tool("pt-notify"), peinit.seed("pt-ops-gaps", SERVICES)),
})

--- `svctl <command>` as JSON, with the operation identifier pulled out.
local function send(command)
    local run = vm:run("svctl --no-wait --json " .. command, { timeout = 60 })
    return {
        raw = run.stdout .. " / " .. tostring(run.stderr),
        operation = run.stdout:match('"operation_id":"([^"]+)"'),
    }
end

--- The operation view for `id`, as a table of its string fields, with
--- the nullable timestamps as `false` when null.
local function operation(id)
    local run = vm:run("svctl --json operation-status " .. id)
    local out = { raw = run.stdout }
    for name, value in run.stdout:gmatch('"([%w_]+)":"([^"]*)"') do out[name] = value end
    for _, name in ipairs({ "result", "error", "started_at", "completed_at" }) do
        if run.stdout:find('"' .. name .. '":null', 1, true) then out[name] = false end
    end
    return out
end

local function state_of(name)
    return vm:run("svctl --json status " .. name).stdout:match('"state":"([^"]+)"')
end

--- Wait `seconds` on the host without asking the guest anything.
local function pause(seconds)
    pcall(wait_until, function() return false end,
        { timeout = seconds, interval = 0.25, desc = "a fixed pause" })
end

--- How many times `name` appears in the `peinit.internal-error.contained`
--- events on the ring. The snapshot is filtered to that one type, so any
--- mention of the service is an event about it.
local function internal_errors_for(name)
    local r = vm:run("revstrm --snapshot --pretty --type 'peinit.internal-error.contained'",
        { timeout = 60 })
    r:assert_ok()
    local n = 0
    for _ in r.stdout:gmatch((name:gsub("%-", "%%-"))) do n = n + 1 end
    return n, r.stdout
end

--- Seconds since the epoch for an RFC 3339 UTC time as peinit writes them
--- (`2026-10-05T11:13:04.265324310Z`), or nil.
local function epoch(text)
    if not text then return nil end
    local y, mo, d, h, mi, s = text:match("^(%d+)-(%d+)-(%d+)T(%d+):(%d+):([%d%.]+)Z$")
    if not y then return nil end
    y, mo, d = tonumber(y), tonumber(mo), tonumber(d)
    -- Days from the civil date (Howard Hinnant's algorithm).
    y = mo <= 2 and y - 1 or y
    local era = (y >= 0 and y or y - 399) // 400
    local yoe = y - era * 400
    local doy = (153 * (mo + (mo > 2 and -3 or 9)) + 2) // 5 + d - 1
    local doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    local days = era * 146097 + doe - 719468
    return days * 86400 + tonumber(h) * 3600 + tonumber(mi) * 60 + tonumber(s)
end

--- The `peinit.operation.*` events on the ring for `service`, oldest
--- first, each with the fields this file reads: the event type, the
--- operation's source and state, its duration in nanoseconds and its
--- result.
local function operation_events(service)
    local out = {}
    for _, e in ipairs(revstrm.snapshot(vm, { "peinit.operation.*" })) do
        if revstrm.field(e, "object.service.name") == service then
            local duration = revstrm.field(e, "object.operation.duration")
            out[#out + 1] = {
                event = e.type,
                raw = e.payload,
                source = revstrm.field(e, "object.operation.source"),
                state = revstrm.field(e, "object.operation.state"),
                duration_ns = duration and duration:match("^(%d+)ns"),
                result = revstrm.field(e, "outcome.detail"),
            }
        end
    end
    return out
end

--- The boot start of `name`, from its terminal event on the ring: the
--- event, whose `state` says how it ended, and a one-line summary of every
--- event seen.
local function boot_start(name)
    local terminal, seen = nil, {}
    for _, e in ipairs(operation_events(name)) do
        seen[#seen + 1] = e.event .. " " .. (e.raw:gsub("%s+", " "))
        if e.source == "boot" and e.event == "peinit.operation.ended" then
            terminal = e
        end
    end
    return terminal, table.concat(seen, " | ")
end

--- Wait until the boot plan has settled `name` one way or the other.
local function boot_settled(name)
    return wait_until(function()
        local s = state_of(name)
        if s == "active" then return s end
        local terminal = boot_start(name)
        return terminal and s or nil
    end, { timeout = 60, interval = 0.5, desc = name .. "'s boot start to settle" })
end

--- Premise shared by the two boot-path tests: pt-flaky really did crash
--- and wait out its delay. Its first launch left /run/pt-flaky-once
--- behind; the instance running now started a restart delay after that.
local function assert_target_backed_off(t)
    wait_until(function() return state_of("pt-flaky") == "active" or nil end,
        { timeout = 60, interval = 0.5, desc = "pt-flaky's relaunch to come up" })
    local crashed_at = tonumber(vm:run("stat -c %Y /run/pt-flaky-once").stdout:match("%d+"))
    t:assert(crashed_at, "premise: pt-flaky's first launch ran and exited")
    local job = json.decode(vm:run("svctl --json status pt-flaky").stdout).current_job
    local up_at = epoch(job and job.started_at)
    t:assert(up_at and crashed_at and up_at - crashed_at >= 12,
        "premise: its relaunch came up after the fifteen-second Backoff (" ..
        tostring(up_at and crashed_at and (up_at - crashed_at)) .. "s after the crash)")
end

test("a start the boot graph holds on a target in Backoff has no lifetime, and gets one from its release",
    { spec = "peinit *op.a-held-start-has-no-lifetime" },
    function(t)
        -- pt-flaky crashed on its boot launch and sat fifteen seconds in
        -- Backoff before its relaunch came up. pt-held's boot start waited
        -- on it all that time: five times its three-second StartTimeout.
        assert_target_backed_off(t)
        boot_settled("pt-held")
        local terminal, seen = boot_start("pt-held")
        t:assert(terminal and terminal.state == "completed",
            "pt-held's boot start completed rather than failing: " .. seen)
        local held_for = tonumber(terminal and terminal.duration_ns or 0) / 1e9
        -- A clock run from creation would have failed it at three seconds
        -- while it waited; one that only paused, or that resumed from
        -- creation on release, would have expired it on the spot.
        t:assert(held_for > 9,
            "its start lived " .. held_for .. "s, three times its StartTimeout and " ..
            "more, and still completed: it had no lifetime while held")
        t:assert(terminal and terminal.result and terminal.result:find("process started", 1, true),
            "and it completed by running, after the release: " ..
            tostring(terminal and terminal.result))
        t:assert_eq(state_of("pt-held"), "active", "pt-held is up")
    end)

test("a start held on a dependent that is itself held only on a clockless fact has no lifetime either",
    {
        spec = "peinit *op.a-held-start-has-no-lifetime",
        tags = { "known-bug" },
        -- PEI-1380, peinit 0.0.10: pt-held-twice (Requires pt-held, StartTimeout 3)
        -- is held without expiring for as long as pt-held is held on
        -- pt-flaky's Backoff, but the moment pt-held is released its
        -- start fails with "operation_timeout: operation maximum lifetime
        -- expired", duration ~16s: the hold's time was charged to it on
        -- release, where the TRM says the clock does not run across a
        -- hold and a released start's lifetime runs from the release.
    },
    function(t)
        assert_target_backed_off(t)
        boot_settled("pt-held-twice")
        local terminal, seen = boot_start("pt-held-twice")
        t:assert(terminal and terminal.state == "completed",
            "pt-held-twice's boot start completed rather than failing: " .. seen)
        t:assert_eq(state_of("pt-held-twice"), "active",
            "and pt-held-twice is up, behind pt-held")
    end)

test("an on-demand start of a dependent of a target in Backoff is held, not refused",
    {
        spec = {
            "peinit *op.a-held-start-has-no-lifetime",
            "peinit *state.a-dependent-of-a-service-in-backoff-waits-rather-than-failing",
        },
        tags = { "known-bug" },
        -- PEI-1379, peinit 0.0.10: the boot graph holds a dependent of a target in
        -- Backoff (the test above), but `svctl start` of the same kind of
        -- dependent is answered INTERNAL_ERROR "control request failed",
        -- for Requires and Wants alike, and no operation is created.
    },
    function(t)
        vm:run("rm -f /run/pt-flaky2-ok")
        send("start pt-flaky2")
        wait_until(function() return state_of("pt-flaky2") == "backoff" or nil end,
            { timeout = 30, interval = 0.25, desc = "pt-flaky2 to fail into Backoff" })

        local held = send("start pt-held2")
        t:assert(held.operation,
            "the dependent's start is accepted, to be held while its target is in Backoff: " ..
            held.raw)
        if not held.operation then return end

        -- Three times its StartTimeout: a lifetime run from creation would
        -- have failed it by now.
        pause(9)
        t:assert_eq(state_of("pt-flaky2"), "backoff",
            "premise: the target is still waiting out its restart delay")
        local view = operation(held.operation)
        t:assert_eq(view.state, "pending",
            "the held start is still Pending after three StartTimeouts: " .. view.raw)
        t:assert_eq(view.started_at, false, "and has not run: " .. view.raw)

        vm:run("touch /run/pt-flaky2-ok"):assert_ok()
        local done = wait_until(function()
            local v = operation(held.operation)
            return (v.state ~= "pending" and v.state ~= "running") and v or nil
        end, { timeout = 40, interval = 0.5, desc = "the held start to finish" })
        t:assert_eq(done.state, "completed",
            "released, it ran under the lifetime it got from the release: " .. done.raw)
    end)

test("a start waiting on a dependency that is itself starting keeps its own lifetime",
    { spec = "peinit *op.a-held-start-has-no-lifetime" },
    function(t)
        -- The contrast. A dependency that is starting is bounded by its
        -- own StartTimeout (sixty seconds here), so it is a fact with a
        -- clock, the wait on it is not a hold, and the dependent's four
        -- seconds run from creation as usual.
        send("start pt-slowstart")
        wait_until(function() return state_of("pt-slowstart") == "starting" or nil end,
            { timeout = 30, interval = 0.25, desc = "pt-slowstart to be Starting" })

        local dependent = send("start pt-on-starting")
        t:assert(dependent.operation, "the dependent's start was accepted: " .. dependent.raw)
        local view = wait_until(function()
            local v = operation(dependent.operation)
            return (v.state ~= "pending" and v.state ~= "running") and v or nil
        end, { timeout = 30, interval = 0.5, desc = "the dependent's operation to end" })
        t:assert_eq(view.state, "failed",
            "it failed at its own StartTimeout: " .. view.raw)
        t:assert(view.error and view.error:find("operation_timeout", 1, true),
            "on its maximum lifetime: " .. view.raw)
        t:assert_eq(state_of("pt-slowstart"), "starting",
            "while the dependency it waited on is still Starting, inside its own clock")
        vm:run("svctl stop pt-slowstart", { timeout = 60 })
    end)

test("a start aborted by a stop takes its readiness deadline with it",
    { spec = "peinit *op.an-ended-start-leaves-no-readiness-deadline" },
    function(t)
        -- The first start is never going to be ready, and arms a
        -- ten-second readiness deadline.
        vm:run("rm -f /run/pt-aborted-ready")
        local first = send("start pt-aborted")
        t:assert(first.operation, "the first start was accepted: " .. first.raw)
        wait_until(function() return state_of("pt-aborted") == "starting" or nil end,
            { timeout = 30, interval = 0.25, desc = "pt-aborted to be Starting" })
        local armed_at = os.time()

        -- A stop lands on the Starting service and aborts the start.
        vm:run("svctl stop pt-aborted", { timeout = 60 })
        t:assert_eq(operation(first.operation).state, "aborted",
            "premise: the stop aborted the start it landed on")
        t:assert_eq(state_of("pt-aborted"), "inactive", "and the service is down")

        -- The next start says READY=1 a second in, well before the
        -- aborted start's deadline would have come due.
        vm:run("touch /run/pt-aborted-ready"):assert_ok()
        local second = send("start pt-aborted")
        local ready = wait_until(function()
            local v = operation(second.operation)
            return v.state ~= "pending" and v.state ~= "running" and v or nil
        end, { timeout = 30, interval = 0.25, desc = "the second start to finish" })
        t:assert_eq(ready.state, "completed", "the second start reached Active: " .. ready.raw)
        local pid = vm:run("svctl status pt-aborted").stdout:match("pid: (%d+)")
        t:assert(os.time() < armed_at + 10,
            "premise: it was up before the aborted start's deadline came due")

        -- Past the old deadline, with margin. Acted on, it would fail this
        -- start as an internal error (and then again on every timer turn).
        pcall(wait_until, function() return os.time() >= armed_at + 16 or nil end,
            { timeout = 20, interval = 0.25, desc = "the old deadline to pass" })
        local status = json.decode(vm:run("svctl --json status pt-aborted").stdout)
        t:assert_eq(status.state, "active",
            "the service is still Active past the aborted start's deadline: " ..
            tostring(status.state) .. " / " .. tostring(status.cause))
        t:assert_eq(vm:run("svctl status pt-aborted").stdout:match("pid: (%d+)"), pid,
            "on the same main process")
        local n, raw = internal_errors_for("pt-aborted")
        t:assert_eq(n, 0, "and no internal error was raised against it: " .. raw)
        vm:run("svctl stop pt-aborted", { timeout = 60 })
    end)
