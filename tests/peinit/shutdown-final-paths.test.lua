-- peinit TRM §12.2 step 8 and §12.4 — the three paths that reach the
-- kernel, and how much each does on the way: the graceful sequence, the
-- forced reboot of three SIGINTs, and the reboot a Critical service out
-- of restart budget causes.
--
-- What separates them happens in PID 1's last turn, which prints nothing
-- that reaches the console (PEI-827) — so every path here is read
-- through `pt-shutwatch` (helpers/shutdown.lua has the story), holding
-- the final action back so the machine stays up until the record is
-- complete, and so that what each path does with a final action that
-- returns is on the record too. The same witness sees the graceful
-- path's seed write and unmounts, which is what makes their absence from
-- the other two paths evidence rather than a gap in the record.
--
-- `peios.quiet=0` on every boot, so the shutdown narrative reaches the
-- console at all; each boot settles before it triggers anything (PEI-826).

local peinit = require("helpers.peinit")
local shutdown = require("helpers.shutdown")
peinit.claim(1)

local SEED = "/var/state/peinit/random-seed"

local RB_POWER_OFF = "0x4321fedc"
local RB_AUTOBOOT = "0x1234567"

local function pause(seconds)
    pcall(wait_until, function() return false end,
        { timeout = seconds, interval = 0.25, desc = "a fixed pause" })
end

local function trigger(vm, command)
    pcall(function() vm:run(command, { timeout = 30 }) end)
end

-- Ignores SIGTERM, so a graceful shutdown has to wait out its
-- StopTimeout: long enough here that only the forced path ends it.
local STUBBORN = {
    path = [[Machine\System\Services\pt-stubborn]],
    values = {
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi",
          data = { "-c", "trap '' TERM; while :; do sleep 1; done" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "StopTimeout", type = "dword", data = 120 },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "Triggers", type = "multi", data = { "boot" } },
    },
}

-- Fails at once and is always restarted, one retry allowed: started by
-- hand, it spends its budget in a couple of seconds.
local CRITICAL = {
    path = [[Machine\System\Services\pt-crit]],
    values = {
        { name = "ImagePath", type = "sz", data = "/bin/false" },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 2 },
        { name = "RestartMaxRetries", type = "dword", data = 1 },
        { name = "RestartDelay", type = "dword", data = 1 },
        { name = "RestartWindow", type = "dword", data = 60 },
        { name = "ErrorControl", type = "dword", data = 1 },
    },
}

local PATHS = {
    graceful = {
        services = {},
        fire = function(vm) trigger(vm, "svctl shutdown poweroff") end,
        kernel = "reboot: Power down",
        cmd = RB_POWER_OFF,
    },
    forced = {
        services = { STUBBORN },
        -- One guest command, a second apart: see shutdown-triggers for
        -- why both halves of that matter.
        fire = function(vm)
            trigger(vm, "kill -INT 1; sleep 1; kill -INT 1; sleep 1; kill -INT 1")
        end,
        kernel = "reboot: Restarting system",
        cmd = RB_AUTOBOOT,
    },
    critical = {
        services = { CRITICAL },
        fire = function(vm) trigger(vm, "svctl --no-wait start pt-crit") end,
        kernel = "reboot: Restarting system",
        cmd = RB_AUTOBOOT,
    },
}

--- How many of each path's final actions the witness holds back, and how
--- long a test watches after the first one failed: long enough for that
--- many once-a-second retries and one more.
local HELD = 3
local WATCH_AFTER_FAILURE = 4.5

--- Run one path to the kernel, once, and return the witness's record.
---
--- The final action is held back HELD times. After the first attempt
--- has failed the test watches for WATCH_AFTER_FAILURE seconds and takes
--- the record as it then stands; whatever the path does with a failed
--- final action is on it. It does not wait for the kernel's own line:
--- a path that never retries never gets there.
local records, failures = {}, {}
local function run_path(name)
    if records[name] then return records[name] end
    if failures[name] then error(failures[name], 0) end
    local path = PATHS[name]
    local keys = { { path = [[Machine\System]] }, { path = [[Machine\System\Services]] } }
    for _, service in ipairs(path.services) do keys[#keys + 1] = service end
    local vm = peinit.boot({
        name = name,
        append = "peios.quiet=0",
        files = peinit.merge(
            shutdown.tool(),
            { [SEED:sub(2)] = string.rep("pt-seed-", 64) },
            peinit.seed("pt-" .. name, keys)),
    })
    local ok, result = pcall(function()
        peinit.settle(vm, { all = true })
        shutdown.start(vm, { hold = HELD })
        path.fire(vm)
        wait_until(function()
            return vm:console():read_log():find("sys_reboot %-> 0xffffffffffffffff")
        end, { timeout = 120, interval = 0.25, desc = name .. ": the first, held, final action" })
        pause(WATCH_AFTER_FAILURE)
        local log = vm:console():read_log()
        return { log = log, record = shutdown.record(log) }
    end)
    pcall(function() vm:shutdown() end)
    if not ok then
        failures[name] = result
        error(result, 0)
    end
    records[name] = result.record
    return result.record
end

--- The calls up to and including the first final action.
local function to_first_reboot(record)
    local out = {}
    for _, call in ipairs(record.calls) do
        out[#out + 1] = call
        if call.name == "reboot" then return out end
    end
    return out
end

test("sync() is called before the final action on all three paths",
    { spec = "peinit *graceful.sync-is-called-on-all-three-paths" },
    function(t)
        for _, name in ipairs({ "graceful", "forced", "critical" }) do
            local record = run_path(name)
            local calls = record.calls
            local reboot, at
            for i, call in ipairs(calls) do
                if call.name == "reboot" then reboot, at = call, i break end
            end
            t:assert(reboot, name .. ": the final action is on the record: "
                .. shutdown.render(record))
            t:assert_eq(reboot.cmd, PATHS[name].cmd, name .. ": with its own reboot(2) command")
            local before = calls[at - 1]
            t:assert(before and before.name == "sync" and before.ret == 0,
                name .. ": sync() was the call immediately before it: " .. shutdown.render(record))
        end
    end)

test("the forced and Critical paths skip the seed and the unmounts and go straight to sync and the final action",
    { spec = "peinit *final.the-abrupt-paths-skip-the-seed-and-the-unmounts" },
    function(t)
        -- The witness sees steps 6 and 7 when they happen: on the graceful
        -- path they are all there, so their absence below is an absence.
        local graceful = run_path("graceful")
        t:assert(#shutdown.entries(graceful, "seed") == 1
            and #shutdown.calls(graceful, "umount") > 0,
            "the witness records a seed write and unmounts on the graceful path: "
            .. shutdown.render(graceful))

        -- The claim is about the way to the final action, so the calls
        -- read here end at the first reboot(2). What a path does after a
        -- final action that returned is §12.4's failed-shutdown state,
        -- and is the next test's subject.
        for _, name in ipairs({ "forced", "critical" }) do
            local record = run_path(name)
            local calls = to_first_reboot(record)
            local last = calls[#calls]
            t:assert(last and last.name == "reboot",
                name .. ": the path reached the final action: " .. shutdown.render(record))
            local seen = {}
            for _, call in ipairs(calls) do
                seen[#seen + 1] = call.name
                t:assert(call.name ~= "rename", name .. ": nothing was renamed on the way")
                t:assert(not (call.name == "write" and call.count == "0x200"),
                    name .. ": no 512-byte seed write on the way")
                t:assert(call.name ~= "umount", name .. ": nothing was unmounted on the way")
                t:assert(call.name ~= "mount",
                    name .. ": nothing was remounted on the way, the root included")
            end
            -- Minimal: sync(), then the final action, and nothing between.
            t:assert_eq(table.concat(seen, " "), "sync reboot",
                name .. ": the way to the kernel was sync() and reboot(2) alone")
        end
    end)

test("a final action that returns is retried as the same sync() and reboot(2), on every path",
    {
        spec = "peinit *final.the-failed-action-is-retried-at-most-once-a-second",
        -- PEI-1087: the two abrupt paths do not retry
        -- their final action. On the Critical path nothing arms the
        -- shutdown deadline timer after the attempt, so the retry
        -- deadline never fires and the machine sits refusing commands
        -- with every service still running. On the forced path the reaps
        -- of the services it SIGKILLed advance shutdown progress over an
        -- empty plan, which overwrites the Failed state with Ready, and
        -- the next drive runs a full graceful finalisation — seed write,
        -- unmounts, read-only remounts — before the sync and reboot.
        -- PEI-1087: fixed in peinit afcf56d, "fix(shutdown):
        -- retry a failed forced or Critical final action as the
        -- same action". Green since 0.0.5-4.
    },
    function(t)
        for _, name in ipairs({ "graceful", "forced", "critical" }) do
            local record = run_path(name)
            local reboots = shutdown.calls(record, "reboot")
            t:assert(reboots[1] and reboots[1].ret == shutdown.EPERM,
                name .. ": the first final action returned: " .. shutdown.render(record))
            t:assert(#reboots >= 2, name .. ": and within " .. WATCH_AFTER_FAILURE
                .. " seconds it was retried: " .. shutdown.render(record))
            local after, first = {}, nil
            for i, call in ipairs(record.calls) do
                if first then after[#after + 1] = call.name end
                if not first and call.name == "reboot" then first = i end
            end
            for _, name_after in ipairs(after) do
                t:assert(name_after == "sync" or name_after == "reboot",
                    name .. ": the retry was the same sync() and reboot(2), not " .. name_after
                    .. ": " .. table.concat(after, " "))
            end
            for _, reboot in ipairs(reboots) do
                t:assert_eq(reboot.cmd, PATHS[name].cmd, name .. ": with the same command")
            end
        end
    end)
