-- peinit TRM §7.4 — the boot and on-demand paths, and the three places
-- a bad definition can surface.
--
-- The three places are a claim about *where* a fault is caught, so each
-- test here needs two faults of different kinds and has to show they
-- landed differently. A definition that does not parse and one that
-- parses but does not fit look identical from `svctl status` — both are
-- Failed with `ValidationError` — so the discriminator is what else
-- happened: a decode failure is found while the registry is read, and a
-- graph finding while the plan is built, which is why only the latter
-- appears as a `graph.validation_error` event naming the graph problem.
--
-- The reload half of each is the sharper evidence, because the two
-- paths disagree there: boot marks one service and continues, reload
-- rejects everything.

-- Every machine here is booted with 800 MiB rather than the helper's
-- default gigabyte, and the claim says so. A booted guest uses about
-- 300 MiB — the squashfs is read off the medium rather than held in RAM
-- — so the assertions are identical at either size, and a file that
-- claims 1.8 GiB instead of 2.2 GiB still fits a pool several of these
-- files are queueing against.

local peinit = require("helpers.peinit")
peinit.claim(2, { memory_mib = 800 })

--- Wait until `text` appears anywhere in the console log.
---
--- `console():expect` consumes the stream up to whatever it matched, so
--- a later call looking for a line that was already passed waits for a
--- second occurrence that never comes. Reading the whole accumulated log
--- instead makes the order the tests run in irrelevant, which matters
--- here because several of them assert on lines the boot produced.
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

local function requires(...) return { name = "Requires", type = "multi", data = { ... } } end

local vm = peinit.boot({
    memory = "800M",
    name = "paths",
    files = peinit.seed("zz-pt-paths", {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },

        -- Parses, fits, and fails at start: the binary is not there.
        -- Nothing about the definition is wrong until peinit tries to
        -- spawn it.
        service("pt-p-nobinary", "/pt/not-a-binary", nil, { BOOT }),

        -- Parses, does not fit: a cycle. Caught when the plan is built.
        oneshot("pt-p-cyc1", { BOOT, requires("pt-p-cyc2") }),
        oneshot("pt-p-cyc2", { BOOT, requires("pt-p-cyc1") }),

        -- An untouched service, so "the rest continue" has a witness.
        oneshot("pt-p-fine", { BOOT }),
    }),
})

local function status(machine, name)
    return json.decode(machine:run("svctl --json status " .. name).stdout)
end

test("a definition that parses and fits but cannot run is caught at start, not before",
    { spec = "peinit *ondemand.a-precondition-that-does-not-hold-is-caught-at-start" },
    function(t)
        -- The definition is perfectly well formed and sits in the graph
        -- like any other. peinit plans it, dispatches it, and only then
        -- discovers there is nothing at that path — so what fails is
        -- the activation rather than the definition.
        local failed = wait_until(function()
            local current = status(vm, "pt-p-nobinary")
            return (current.state == "failed" or current.state == "backoff") and current or nil
        end, { timeout = 60, interval = 0.5, desc = "pt-p-nobinary to fail its launch" })
        t:assert(failed.cause ~= "validation_error",
            "it was not rejected as a definition problem: " .. tostring(failed.cause))
        t:assert(vm:console():read_log():find("peinit: service pt%-p%-nobinary failed to launch"),
            "peinit reported it as a launch failure, which is a start-time fault")

        -- Nothing found it before then: a definition problem would have
        -- produced a graph finding while the plan was built.
        local events = vm:run(
            "evctl 'EVENTS graph.validation_error SINCE 1h ago TAKE 400' --format jsonl").stdout
        t:assert(not events:find("pt%-p%-nobinary"),
            "and graph validation had nothing to say about it: " .. events)
    end)

test("a definition that parses but does not fit is caught at graph validation",
    { spec = "peinit *ondemand.a-definition-that-does-not-fit-is-caught-at-graph-validation" },
    function(t)
        -- A cycle is invisible in either definition on its own;
        -- validation is the first place that can see the two together.
        for _, name in ipairs({ "pt-p-cyc1", "pt-p-cyc2" }) do
            local entry = status(vm, name)
            t:assert_eq(entry.state, "failed", name .. " was failed")
            t:assert_eq(entry.cause, "cycle_detected", name .. " was failed for the cycle")
        end
        local events = wait_until(function()
            local out = vm:run(
                "evctl 'EVENTS graph.validation_error SINCE 1h ago TAKE 400' --format jsonl").stdout
            return out:find("pt%-p%-cyc") and out or nil
        end, { timeout = 60, interval = 1, desc = "the cycle finding" })
        t:assert(events:find('"phase":"boot"', 1, true),
            "the finding was made while the boot graph was built")
    end)

test("at boot a validation finding fails one service and the rest continue; on demand the start fails",
    { spec = "peinit *ondemand.the-boot-and-on-demand-paths-differ-beyond-scope" },
    function(t)
        -- Boot: two services failed, everything else came up.
        wait_for_line(vm, "peinit: service pt-p-fine started")
        t:assert(vm:console():read_log():find("peinit: phase2 boot complete", 1, true),
            "the boot itself completed")

        -- On demand: the same sub-graph does not validate, and the
        -- consequence is an error to the caller rather than one failed
        -- service and a machine that carries on.
        local start = vm:run("svctl start pt-p-cyc1")
        t:assert(start.exit_code ~= 0 or start.stdout:find("fail", 1, true),
            "the explicit start failed: rc=" .. start.exit_code ..
            " out=" .. start.stdout .. " err=" .. start.stderr)
        t:assert_eq(status(vm, "pt-p-cyc1").state, "failed",
            "and nothing was started by the attempt")
    end)

test("a definition that does not parse is caught when the registry is read, and rejects a whole reload",
    { spec = "peinit *ondemand.a-definition-that-does-not-parse-is-caught-when-the-registry-is-read" },
    function(t)
        -- Its own machine, because the reload path validates the whole
        -- definition set and this one has to start from a set that
        -- reloads cleanly.
        --
        -- The boot half of this bullet — a decode failure at boot
        -- failing that service and letting the rest continue — is
        -- PEI-812 and is covered, failing, by phase2.test.lua. What is
        -- reachable is the reload half, where the consequence is the
        -- opposite: one undecodable key rejects the entire transaction.
        local other = peinit.boot({
            memory = "800M",
            name = "decode",
            files = peinit.seed("zz-pt-decode", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                oneshot("pt-p-decode", { BOOT }),
            }),
        })
        wait_for_line(other, "peinit: service pt-p-decode started")

        -- `Type` is a dword with two legal values. Three is not one of
        -- them, and nothing about the graph is involved: this is one
        -- key, read on its own, refusing to become a definition.
        other:run([[reg set 'Machine\System\Services\pt-p-decode' Type dword:3]]):assert_ok()

        local reload = other:run("svctl --json reload-config")
        t:assert(reload.exit_code ~= 0 or reload.stdout:find("error", 1, true),
            "the reload was rejected outright: rc=" .. reload.exit_code ..
            " out=" .. reload.stdout .. " err=" .. reload.stderr)

        -- Rejected whole: the previous generation stays live, and the
        -- service is still the one it was.
        local entry = status(other, "pt-p-decode")
        t:assert(entry.state ~= "failed",
            "the running generation was left alone: " .. entry.state)
    end)
