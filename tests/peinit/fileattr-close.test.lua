-- PEI-746: concurrent close after AT_EMPTY_PATH has acquired its file.
-- A KASAN kernel with panic_on_warn=1 turns a lifetime report into failure.
local peinit = require("helpers.peinit")
local stratafs = require("helpers.stratafs")
peinit.claim(1, { memory_mib = 2048, cpus = 2 })
local vm = peinit.boot({
    name = "fileattr-close", memory = "2G", cpus = 2,
    files = peinit.tool("pt-fileattr-close", { signed = true }),
    append = "panic_on_warn=1",
})

local function race(t, path)
    local r = vm:run("pt-fileattr-close '" .. path .. "'", { timeout = 120 })
    t:log(r.stdout or "")
    t:log(r.stderr or "")
    t:assert_eq(r.exit_code, 0, "both attribute calls survive concurrent close")
end

test("unsupported file attributes retain the file through metadata cleanup", function(t)
    race(t, "/dev/null")
end)

test("tmpfs file attributes survive concurrent close", function(t)
    vm:write_file("/run/fileattr-close", "test")
    race(t, "/run/fileattr-close")
end)

test("StrataFS file attributes survive concurrent close", function(t)
    stratafs.with(vm, "fileattr-close", {
        { name = "upper", flags = { "create" }, entries = { f = "test" } },
    }, function(s) race(t, s:join("f")) end)
end)
