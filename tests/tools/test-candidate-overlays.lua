-- Host-only contract checks: lua tests/tools/test-candidate-overlays.lua
package.path = "tests/?.lua;" .. package.path
local peinit = require("helpers.peinit")
local network = require("helpers.network")
local original_getenv = os.getenv
local env = {}
os.getenv = function(name) return env[name] end
local path = os.tmpname()
local f = assert(io.open(path, "wb"))
f:write("candidate\0bytes")
f:close()
local existing = { ["seed.reg"] = "registry seed", ["usr/sbin/resolvd"] = "original" }
local absent = network.test_binary("resolvd", existing)
assert(absent ~= existing and absent["seed.reg"] == existing["seed.reg"])
assert(absent["usr/sbin/resolvd"] == "original")
env.RESOLVD_TEST_BINARY = path
env.RESOLVD_TEST_SERVICE = path
local candidate = network.test_binary("resolvd", existing)
assert(candidate["usr/sbin/resolvd"][1] == "candidate\0bytes")
assert(candidate["usr/sbin/resolvd"].exec)
assert(candidate["tmp/resolvd-service.reg"] == nil)
assert(existing["usr/sbin/resolvd"] == "original")
local service = network.test_binary("resolvd", existing, true)
assert(service["tmp/resolvd-service.reg"][1] == "candidate\0bytes")
assert(service["tmp/resolvd-service.reg"].exec == false)
for name, dest in pairs({peinit="bin/peinit2",trustd="usr/sbin/trustd",loregd="usr/sbin/loregd"}) do
    env[name:upper() .. "_TEST_BINARY"] = path
    assert(peinit.test_binary(name, existing)[dest].exec)
end
env.NETD_TEST_BINARY = path
assert(network.test_binary("netd", existing)["usr/sbin/netd"].exec)
env.RESOLVD_TEST_BINARY = path .. ".missing"
local ok, err = pcall(network.test_binary, "resolvd", existing)
assert(not ok and tostring(err):find("RESOLVD_TEST_BINARY", 1, true))
os.getenv = original_getenv
os.remove(path)
print("candidate overlay contracts pass")
