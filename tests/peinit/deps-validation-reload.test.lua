-- peinit TRM §7.2 — graph validation on the reload path.
--
-- Split from `deps-validation.test.lua` for a reason that is itself the
-- subject: `svctl reload-config` validates the *whole* definition set,
-- so a machine booted with a cycle in its registry can never produce a
-- clean reload again. Every reload-path claim therefore needs a machine
-- whose definitions were valid to begin with, which is what this file
-- boots — and the findings-heavy machine lives in the other file.

-- Every machine here is booted with 800 MiB rather than the helper's
-- default gigabyte, and the claim says so. A booted guest uses about
-- 300 MiB — the squashfs is read off the medium rather than held in RAM
-- — so the assertions are identical at either size, and a file that
-- claims 1.8 GiB instead of 2.2 GiB still fits a pool several of these
-- files are queueing against.

local peinit = require("helpers.peinit")
peinit.claim(1, { memory_mib = 800 })

--- Wait until `text` appears anywhere in the console log.
---
--- `console():expect` consumes the stream up to whatever it matched, so
--- a later call looking for a line that was already passed waits for a
--- second occurrence that never comes. Reading the whole accumulated log
--- instead makes the order the tests run in irrelevant.
local function wait_for_line(machine, text, why)
    return wait_until(function()
        return machine:console():read_log():find(text, 1, true) and true or nil
    end, { timeout = peinit.STAGE_TIMEOUT, interval = 0.5, desc = why or text })
end

local BOOT = { name = "Triggers", type = "multi", data = { "boot" } }

local function service(name, image, args, extra)
    local values = {
        { name = "ImagePath", type = "sz", data = image },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
    }
    if args then values[#values + 1] = { name = "Arguments", type = "multi", data = args } end
    for _, value in ipairs(extra or {}) do values[#values + 1] = value end
    return { path = [[Machine\System\Services\]] .. name, values = values }
end

local function oneshot(name, extra)
    local values = { { name = "Type", type = "dword", data = 1 } }
    for _, value in ipairs(extra or {}) do values[#values + 1] = value end
    return service(name, "/bin/true", nil, values)
end

local function daemon(name, extra)
    return service(name, "/bin/sleep", { "3600" }, extra)
end

local function requires(...) return { name = "Requires", type = "multi", data = { ... } } end

-- Only the Alive-readiness pair, which is a warning rather than a
-- finding: the set validates, so a reload of it can succeed.
local clean = peinit.boot({
    memory = "800M",
    name = "clean",
    files = peinit.seed("zz-pt-clean", {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
        daemon("pt-v-alive", { BOOT }),
        oneshot("pt-v-needsalive", { BOOT, requires("pt-v-alive") }),
    }),
})

local function status(machine, name)
    return json.decode(machine:run("svctl --json status " .. name).stdout)
end

test("a validation warning is reported and changes nothing",
    {
        spec = {
            "peinit *validate.a-validation-warning-does-not-prevent-the-graph-from-running",
            "peinit *validate.alive-readiness-with-a-hard-dependent-is-warned-about",
        },
    },
    function(t)
        -- pt-v-alive uses Alive readiness — the process existing is all
        -- peinit knows about it — and pt-v-needsalive depends on it
        -- hard, so it is waiting on the wrong thing. Both ran anyway.
        wait_for_line(clean, "peinit: service pt-v-alive started")
        wait_for_line(clean, "peinit: service pt-v-needsalive started")

        local reload = clean:run("svctl --json reload-config")
        reload:assert_ok()
        local out = json.decode(reload.stdout)
        t:assert_eq(out.status, "ok", "the reload succeeded despite the warning")
        local warned = false
        for _, warning in ipairs(out.warnings or {}) do
            if warning:find("pt-v-alive", 1, true) and warning:find("pt-v-needsalive", 1, true) then
                warned = true
            end
        end
        t:assert(warned, "the warning names the service and its hard dependent: " ..
            reload.stdout)
    end)

test("a finding on the reload path rejects the whole reload and is recorded under that phase",
    { spec = "peinit *validate.reload-validation-rejects-the-whole-reload-under-phase-reload-config" },
    function(t)
        -- A cycle written into two definitions that did not exist at
        -- boot. Boot marks individual services and continues; reload
        -- reports everything and changes nothing, so what peinit knows
        -- afterwards is the evidence.
        clean:run([[reg new 'Machine\System\Services\pt-v-r1']]):assert_ok()
        clean:run([[reg set 'Machine\System\Services\pt-v-r1' ImagePath 'sz:/bin/true']])
            :assert_ok()
        clean:run([[reg set 'Machine\System\Services\pt-v-r1' Requires 'multi:pt-v-r2']])
            :assert_ok()
        clean:run([[reg new 'Machine\System\Services\pt-v-r2']]):assert_ok()
        clean:run([[reg set 'Machine\System\Services\pt-v-r2' ImagePath 'sz:/bin/true']])
            :assert_ok()
        clean:run([[reg set 'Machine\System\Services\pt-v-r2' Requires 'multi:pt-v-r1']])
            :assert_ok()

        local reload = clean:run("svctl --json reload-config")
        t:assert(reload.exit_code ~= 0 or reload.stdout:find("error", 1, true),
            "the reload was rejected: rc=" .. reload.exit_code ..
            " out=" .. reload.stdout .. " err=" .. reload.stderr)

        -- Wholesale: neither new definition was installed, so peinit
        -- does not know either of them.
        t:assert(clean:run("svctl status pt-v-r1").exit_code ~= 0,
            "the rejected generation was not applied even in part")
        -- And the previous generation stays live.
        t:assert_eq(status(clean, "pt-v-alive").state, "active",
            "the running services were left alone")

        -- The findings are recorded under the reload phase, so one
        -- consumer filter catches both regimes and can tell them apart.
        local events = wait_until(function()
            local out = clean:run(
                "evctl 'EVENTS graph.validation_error SINCE 1h ago TAKE 400' --format jsonl").stdout
            return out:find("reload_config") and out or nil
        end, { timeout = 60, interval = 1, desc = "a reload_config finding" })
        t:assert(events:find('"phase":"reload_config"', 1, true),
            "the reload findings carry phase reload_config")
        t:assert(events:find("pt%-v%-r1") or events:find("pt%-v%-r2"),
            "and name the definitions that caused it: " .. events)
    end)
