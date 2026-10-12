-- PEI-352: accepted registry checks must resolve from the cached model.
local peinit = require("helpers.peinit")
peinit.claim(1)
local KEY = [[Machine\System\Services\]]
local function definition(name, field, check)
    return { path = KEY .. name, values = {
        { name = "ImagePath", type = "sz", data = "/bin/true" },
        { name = "Type", type = "dword", data = 1 },
        { name = "RemainAfterExit", type = "dword", data = 1 },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = field, type = "multi", data = { "registry:" .. check } },
    } }
end
local files = peinit.seed("pt-registry-checks", {
    { path = [[Machine\System]] }, { path = [[Machine\System\Services]] },
    definition("pt-unsupported-condition", "Conditions", [[Machine\System\Init\EnvVars]]),
    definition("pt-unsupported-assert", "Asserts", [[Machine\System\Services\pt-target\EnvVars]]),
    definition("pt-target", "Conditions", [[Machine\System\Init]]),
})
local binary = os.getenv("PEINIT_TEST_BINARY")
if binary then
    local f = assert(io.open(binary, "rb"))
    files["bin/peinit2"] = { f:read("*a"), exec = true }
    f:close()
end
local vm = peinit.boot({ name = "registry-check-scope", files = files })
local function status(name)
    local result = vm:run("svctl --json status " .. name)
    result:assert_ok()
    return json.decode(result.stdout)
end
local function reload()
    local result = vm:run("svctl --json reload-config")
    result:assert_ok()
    return json.decode(result.stdout)
end
local function listed(values, name)
    for _, value in ipairs(values or {}) do if value.service == name then return value end end
    return false
end

test("unsupported Conditions and Asserts are decode errors before any start",
    { spec = "peinit *check.a-registry-check-must-name-a-cached-key", tags = { "pei352" } }, function(t)
        local result = reload()
        for _, case in ipairs({ { "pt-unsupported-condition", "Conditions" }, { "pt-unsupported-assert", "Asserts" } }) do
            local name = case[1]
            local detail = listed(result.undecodable, name)
            t:assert(detail, name .. " is listed as undecodable")
            t:assert_eq(detail.field, case[2], "diagnostic identifies the invalid field")
            local view = status(name)
            t:assert_eq(view.state, "failed", "invalid definition is not a runnable service")
            t:assert_eq(view.cause, "validation_error", "load-time error rather than skipped/assertion_error")
        end
    end)

test("valid cached roots and immediate service checks still start; repaired definitions reload",
    { spec = "peinit *check.a-services-registry-check-is-a-service-existence-test", tags = { "pei352" } }, function(t)
        for _, case in ipairs({
            { "pt-unsupported-condition", "Conditions", [[Machine\System\Services]] },
            { "pt-unsupported-assert", "Asserts", [[Machine\System\Services\pt-target]] },
        }) do
            vm:run("reg set '" .. KEY .. case[1] .. "' " .. case[2] .. " 'multi:registry:" .. case[3] .. "'"):assert_ok()
        end
        local result = reload()
        for _, name in ipairs({ "pt-target", "pt-unsupported-condition", "pt-unsupported-assert" }) do
            t:assert(not listed(result.undecodable, name), "repaired definition is decodable")
            vm:run("svctl start " .. name):assert_ok()
            local view = wait_until(function()
                local current = status(name)
                return current.state == "completed" and current or nil
            end, { timeout = 20, interval = 0.25, desc = name .. " to complete" })
            t:assert_eq(view.state, "completed", "cached check passes")
        end
    end)
