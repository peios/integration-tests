-- peinit TRM §3.8 — why a definition-removed entry never has dependents.
--
-- The removal that would create one does not land. A read in which one
-- service `Requires` another the read does not define is refused entire
-- by graph validation, and a refused read applies nothing — so deleting
-- a service that something still requires leaves the registry changed
-- and the model exactly as it was.
--
-- Its own file, deliberately. The refused state is sticky: while the
-- dangling `Requires` is in the registry, *every* later reload is
-- refused too, so a test that leaves one behind silently disables every
-- removal in the file after it rather than failing itself.
-- model-removal.test.lua says so in a comment and carries no such
-- service; this file is where the claim itself is checked, on a machine
-- nothing else depends on.

local peinit = require("helpers.peinit")
peinit.claim(1)

local function resident(name, extra)
    local values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "100000" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "Triggers", type = "multi", data = { "boot" } },
    }
    for _, value in ipairs(extra or {}) do values[#values + 1] = value end
    return { path = [[Machine\System\Services\]] .. name, values = values }
end

local vm = peinit.boot({
    name = "dangling",
    files = peinit.seed("pt-dangling", {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
        resident("pt-dg-target"),
        resident("pt-dg-dependent", {
            { name = "Requires", type = "multi", data = { "pt-dg-target" } },
        }),
    }),
})

local function status(service_name)
    local r = vm:run("svctl --json status " .. service_name)
    if r.stdout:find("UNKNOWN_SERVICE", 1, true) then return nil end
    local ok, decoded = pcall(json.decode, r.stdout)
    return ok and decoded or nil
end

test("a removal that would leave a dangling hard dependency is refused whole",
    { spec = "peinit *remove.a-removal-leaving-a-dangling-dependency-is-refused" },
    function(t)
        -- Both are up, and the dependent really does require the target,
        -- so the removal below is the case under test rather than a
        -- removal of something nothing wanted.
        t:assert(status("pt-dg-target"), "the target is in the model")
        t:assert(status("pt-dg-dependent"), "and so is the service requiring it")

        vm:run([[reg del 'Machine\System\Services\pt-dg-target' --recursive]])
            :assert_ok()

        -- The registry has changed; the model must not have. peinit
        -- picks the change up on its own watch, so the explicit reload
        -- is only here to read the refusal back — the answer is the same
        -- either way.
        local reload = vm:run("svctl --json reload-config")
        t:assert(reload.stdout:find("MissingHardDependency", 1, true)
            or reload.stdout:find("INVALID_STATE", 1, true),
            "the read was refused for the dangling dependency: " .. reload.stdout)

        local target = status("pt-dg-target")
        t:assert(target, "the target is still in the model, key or no key")
        t:assert(not target.definition_removed,
            "and was not marked definition-removed, because nothing was applied")
        t:assert_eq(target.state, "active",
            "it is still running, untouched by the refused read")
    end)
