-- peinit TRM §3.5 — conditions and asserts: what each of the four check
-- types actually asks, what a failure of each kind costs, and when the
-- answers are computed.
--
-- §5.2 already owns *where* the evaluation sits in a start (its
-- `start.*` anchors, in `start-evaluation.test.lua`), and
-- `model-decode` owns which check strings decode. What is left, and
-- what this file is, is the semantics: `file:` is not `directory:`, a
-- failed condition and a failed assert differ in what they do to
-- dependents, the two lists are asked in order, and an answer is
-- computed once per activation rather than whenever it is next needed.
--
-- The subjects are staged so that each claim has a control alongside it
-- that differs in one thing. `pt-file-on-dir` and `pt-dir-on-dir` name
-- the same path and differ only in the check type; `pt-cond-dep` and
-- `pt-assert-dep` are the same graph with the failing entry moved from
-- one list to the other.
--
-- The caching claim needs a fact that is TRUE when the checks run and
-- false by the time the service would start, rather than the other way
-- round: a service whose condition fails is Skipped at once and never
-- waits for anything, so the interesting direction is the one where the
-- service does wait. `/run/pt-vanish` is made by an autorun before Phase
-- 2, `pt-cached` is conditional on it and requires a Oneshot that takes
-- ten seconds, and `pt-remover` deletes it four seconds in. A service
-- that re-asked would be Skipped; one that starts on the cached answer
-- is Active with the directory long gone.

local peinit = require("helpers.peinit")
peinit.claim(1)

local FILES = {
    -- Records that it ran, for the pre-exec-ordering claim.
    ["pt/hook.sh"] = "echo ran > /run/pt-hook-ran\n",
    -- The directory `pt-cached`'s condition names, in place before Phase
    -- 2 reads a definition. An autorun rather than a service, because it
    -- has to be true before any check is evaluated and Phase 1 step 7 is
    -- the last thing that happens before the graph is built.
    ["lcl/policy/autorun.d/50-pt-vanish.sh"] =
        { "#!/bin/sh\nmkdir -p /run/pt-vanish\n", exec = true },
}

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },
}

local function service(name, values)
    SERVICES[#SERVICES + 1] =
        { path = [[Machine\System\Services\]] .. name, values = values }
end

--- A boot-triggered SYSTEM daemon that is ready by existing.
local function daemon(name, extra)
    local values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "100000" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "RestartPolicy", type = "dword", data = 0 },
    }
    for _, value in ipairs(extra) do
        local replaced = false
        for i, existing in ipairs(values) do
            if existing.name:lower() == value.name:lower() then
                values[i] = value
                replaced = true
                break
            end
        end
        if not replaced then values[#values + 1] = value end
    end
    service(name, values)
end

-- The four check types, each asked about a path where the answer is
-- known and where a *different* type would answer differently. /run is
-- a directory and /etc/machine-id is a regular file that Phase 1
-- guarantees exists, so `file:` and `directory:` disagree about both of
-- them and `path:` agrees with neither's refusal.
daemon("pt-path-on-dir", { { name = "Conditions", type = "multi", data = { "path:/run" } } })
daemon("pt-file-on-dir", { { name = "Conditions", type = "multi", data = { "file:/run" } } })
daemon("pt-dir-on-dir", { { name = "Conditions", type = "multi", data = { "directory:/run" } } })
daemon("pt-file-on-file",
    { { name = "Conditions", type = "multi", data = { "file:/etc/machine-id" } } })
daemon("pt-dir-on-file",
    { { name = "Conditions", type = "multi", data = { "directory:/etc/machine-id" } } })
daemon("pt-path-on-missing",
    { { name = "Conditions", type = "multi", data = { "path:/pt-absent" } } })

-- The registry check, on a service that exists in the model and on one
-- that does not. Both name a key under the cached services root, so the
-- difference between them is what the check resolves against.
daemon("pt-reg-present", {
    { name = "Conditions", type = "multi",
      data = { [[registry:Machine\System\Services\pt-path-on-dir]] } },
})
daemon("pt-reg-absent", {
    { name = "Conditions", type = "multi",
      data = { [[registry:Machine\System\Services\pt-no-such-service]] } },
})

-- AND, in both directions.
daemon("pt-and-all-true", {
    { name = "Conditions", type = "multi", data = { "path:/run", "directory:/run" } },
})
daemon("pt-and-one-false", {
    { name = "Conditions", type = "multi", data = { "path:/run", "path:/pt-absent" } },
})

-- Order. A condition that fails and an assert that fails, on the same
-- service: the outcome says which list was consulted.
daemon("pt-order", {
    { name = "Conditions", type = "multi", data = { "path:/pt-absent" } },
    { name = "Asserts", type = "multi", data = { "path:/pt-also-absent" } },
})

-- The consequence of each kind of failure, as seen by a dependent. The
-- two subjects are the same graph with the failing entry in a different
-- list.
daemon("pt-cond-skips", {
    { name = "Conditions", type = "multi", data = { "path:/pt-absent" } },
})
daemon("pt-cond-dep", {
    { name = "Requires", type = "multi", data = { "pt-cond-skips" } },
})
daemon("pt-assert-fails", {
    { name = "Asserts", type = "multi", data = { "path:/pt-absent" } },
})
daemon("pt-assert-dep", {
    { name = "Requires", type = "multi", data = { "pt-assert-fails" } },
})

-- Checks run before any pre-exec hook: a service whose condition fails
-- must never have run one.
daemon("pt-hook-never", {
    { name = "Conditions", type = "multi", data = { "path:/pt-absent" } },
    { name = "ExecStartPre", type = "multi", data = { "/bin/sh /pt/hook.sh" } },
})

-- Caching. `pt-cached` is conditional on a directory that exists when
-- its checks are evaluated and is deleted while it waits for `pt-slow`.
service("pt-slow", {
    { name = "ImagePath", type = "sz", data = "/bin/sleep" },
    { name = "Arguments", type = "multi", data = { "10" } },
    { name = "Identity", type = "sz", data = "SYSTEM" },
    { name = "Type", type = "dword", data = 1 },
    { name = "RemainAfterExit", type = "dword", data = 1 },
    { name = "StartTimeout", type = "dword", data = 60 },
    { name = "Triggers", type = "multi", data = { "boot" } },
})
service("pt-remover", {
    { name = "ImagePath", type = "sz", data = "/bin/sh" },
    -- `sh -c` with the work inline rather than a staged script: a staged
    -- file is readable only by SYSTEM, and keeping the two probes'
    -- shapes identical means one of them working says nothing about the
    -- other's identity.
    { name = "Arguments", type = "multi",
      data = { "-c", "/bin/sleep 4; rmdir /run/pt-vanish" } },
    { name = "Identity", type = "sz", data = "SYSTEM" },
    { name = "Type", type = "dword", data = 1 },
    { name = "RemainAfterExit", type = "dword", data = 1 },
    { name = "StartTimeout", type = "dword", data = 60 },
    { name = "Triggers", type = "multi", data = { "boot" } },
})
daemon("pt-cached", {
    { name = "Requires", type = "multi", data = { "pt-slow" } },
    { name = "Conditions", type = "multi", data = { "directory:/run/pt-vanish" } },
    { name = "StartTimeout", type = "dword", data = 60 },
})

local vm = peinit.boot({
    name = "checks",
    files = peinit.merge(FILES, peinit.seed("pt-checks", SERVICES)),
})

local function status(service_name)
    local r = vm:run("svctl --json status " .. service_name)
    if r.stdout:find("UNKNOWN_SERVICE", 1, true) then return nil end
    local ok, decoded = pcall(json.decode, r.stdout)
    return ok and decoded or nil
end

local function settled(service_name, timeout)
    return wait_until(function()
        local st = status(service_name)
        if not st then return nil end
        if st.state == "starting" or st.state == "inactive" then return nil end
        return st
    end, {
        -- Generous: several agents share this host, so a boot and the
        -- starts behind it can take much longer than they do alone. A
        -- tight bound here would turn load into a test failure.
        timeout = timeout or 150, interval = 0.4,
        desc = service_name .. " to settle",
    })
end

test("the four check types ask four different questions",
    { spec = "peinit *check.the-four-check-types" },
    function(t)
        -- /run is a directory that exists and /etc/machine-id is a regular
        -- file that exists, so every row of §3.5's table has a subject
        -- here where it passes and one where it does not -- and the
        -- pairs differ only in the check type.
        local expected = {
            ["pt-path-on-dir"] = "active",     -- path: any type will do
            ["pt-dir-on-dir"] = "active",      -- directory: a directory
            ["pt-file-on-dir"] = "skipped",    -- file: a directory is not one
            ["pt-file-on-file"] = "active",    -- file: a regular file
            ["pt-dir-on-file"] = "skipped",    -- directory: a file is not one
            ["pt-path-on-missing"] = "skipped", -- path: nothing is there
        }
        local wrong = {}
        for service_name, want in pairs(expected) do
            local st = settled(service_name)
            if st.state ~= want then
                wrong[#wrong + 1] = service_name .. " -> " .. tostring(st.state) ..
                    " (wanted " .. want .. ")"
            end
        end
        t:assert_eq(#wrong, 0,
            "each check type passes exactly where its table row says; these did " ..
            "not: " .. table.concat(wrong, ", "))

        -- The registry row is answered from the in-memory model rather
        -- than by a read, so what it can ask about is whether a service
        -- is in it. Both subjects name a key under the cached services
        -- root; only one of them names a service that exists.
        t:assert_eq(settled("pt-reg-present").state, "active",
            "a registry check on a service in the model passes")
        t:assert_eq(settled("pt-reg-absent").state, "skipped",
            "and one on a name nothing defines does not")
    end)

test("a registry check under the services key is a service-existence test",
    { spec = "peinit *check.a-services-registry-check-is-a-service-existence-test" },
    function(t)
        -- Narrower than the load-time rule suggests: the check decoded
        -- because the key is under a cached root, but what it resolves
        -- against is the service table. pt-no-such-service has no
        -- definition, so the check is false -- and it would be false for
        -- any subkey of the services key that is not a service, since
        -- services are the only thing the model holds there.
        local absent = settled("pt-reg-absent")
        t:assert_eq(absent.state, "skipped", "the check was false")
        t:assert_eq(absent.cause, "condition_skipped",
            "because the condition did not hold, not because anything failed")

        local present = settled("pt-reg-present")
        t:assert_eq(present.state, "active",
            "and naming a service that is in the model is true")
    end)

test("all entries of a kind are AND'd",
    { spec = "peinit *check.entries-of-a-kind-are-anded" },
    function(t)
        t:assert_eq(settled("pt-and-all-true").state, "active",
            "two conditions that both hold start the service")
        local one_false = settled("pt-and-one-false")
        t:assert_eq(one_false.state, "skipped",
            "and one that does not is enough to skip it")
        t:assert_eq(one_false.cause, "condition_skipped",
            "on the condition rather than anything else")
    end)

test("conditions are evaluated before asserts",
    { spec = "peinit *check.conditions-are-evaluated-before-asserts" },
    function(t)
        -- pt-order has a failing condition and a failing assert. The two
        -- have different outcomes -- Skipped and Failed/AssertionError --
        -- so which one the service ends up in says which list decided
        -- it. Asserts are only asked if every condition passed, so this
        -- one is Skipped and its assert was never reached.
        local st = settled("pt-order")
        t:assert_eq(st.state, "skipped",
            "the condition decided it: " .. tostring(st.state) .. "/" ..
            tostring(st.cause))
        t:assert_eq(st.cause, "condition_skipped",
            "and the assert, which also fails, was never consulted")
    end)

test("a failed condition skips the service and satisfies its dependents; a failed assert fails it and does not",
    {
        spec = {
            "peinit *check.a-skipped-service-satisfies-its-dependents",
            "peinit *check.a-failed-assert-fails-the-service-with-assertionerror",
        },
    },
    function(t)
        -- The same graph twice, with the failing check moved from one
        -- list to the other. That is the whole difference between the
        -- two kinds, so the two dependents' outcomes are what "what
        -- differs is the consequence of a failure" means.
        local skipped = settled("pt-cond-skips")
        t:assert_eq(skipped.state, "skipped", "a failed condition skips the service")
        t:assert_eq(skipped.cause, "condition_skipped", "with the condition as the cause")
        local cond_dep = settled("pt-cond-dep")
        t:assert_eq(cond_dep.state, "active",
            "and Skipped satisfies a hard dependent, which starts: " ..
            tostring(cond_dep.state) .. "/" .. tostring(cond_dep.cause))

        local failed = settled("pt-assert-fails")
        t:assert_eq(failed.state, "failed", "a failed assert fails the service")
        t:assert_eq(failed.cause, "assertion_error", "with cause AssertionError")
        local assert_dep = settled("pt-assert-dep")
        t:assert_eq(assert_dep.state, "failed",
            "and a hard dependent of a failed service fails rather than starting: " ..
            tostring(assert_dep.state))
        t:assert_eq(assert_dep.cause, "dependency_failure",
            "through the ordinary dependency propagation")
    end)

test("checks are evaluated before any pre-exec hook",
    { spec = "peinit *check.checks-precede-dependency-resolution-and-the-hooks" },
    function(t)
        -- pt-hook-never has a condition that does not hold and a
        -- pre-exec hook that would leave a file behind. It is Skipped
        -- and the file does not exist, so the checks were asked first --
        -- had the hook run first, the file would be there whatever
        -- happened afterwards.
        local st = settled("pt-hook-never")
        t:assert_eq(st.state, "skipped", "the service was skipped by its condition")
        t:assert_eq(vm:run("test -e /run/pt-hook-ran").exit_code ~= 0, true,
            "and its ExecStartPre never ran")
    end)

test("a check result is computed once, before the dependencies start, and cached for the activation",
    {
        spec = {
            "peinit *check.the-result-is-cached-for-the-activation",
            "peinit *check.checks-precede-dependency-resolution-and-the-hooks",
        },
    },
    function(t)
        -- pt-cached requires pt-slow, which takes ten seconds, and is
        -- conditional on a directory pt-remover deletes four seconds in.
        -- Its checks are asked before the dependency starts, when the
        -- directory is there; by the time the wait is over it is gone. A
        -- service that re-asked when it was finally released would be
        -- Skipped.
        --
        -- The premises first, so that a failure below is about the
        -- caching rather than about the world not being what the test
        -- thinks.
        local slow = settled("pt-slow")
        t:assert_eq(slow.state, "completed", "the ten-second dependency finished")
        local remover = settled("pt-remover")
        t:assert_eq(remover.state, "completed", "and the directory was deleted")
        t:assert(vm:run("test -d /run/pt-vanish").exit_code ~= 0,
            "the condition's subject is gone")

        local cached = settled("pt-cached")
        t:assert_eq(cached.state, "active",
            "the service started on the answer that was true when it began " ..
            "waiting, not on a fresh one: " .. tostring(cached.state) .. "/" ..
            tostring(cached.cause))
    end)
