-- A host-controlled syscall per record is too slow to race a batch's
-- overwrite loop. Run the producer and consumer together inside the VM.
local sys = require("helpers.sys")
local vm = provium:vm("v", "kernel-only", { cpus = 2 }):boot()

test("a concurrent batch reader rejects overwritten records before accepting payloads",
    { spec = "PKM *ring.batch-one-tail-transition" }, function(t)
        local pipe = assert(io.popen("sh tests/tools/build.sh pt-kmes-batch-race", "r"))
        local path = pipe:read("*l")
        assert(pipe:close() and path, "could not build the concurrent KMES helper")
        local file = assert(io.open(path, "rb"))
        local bytes = file:read("*a")
        file:close()
        local at = "/pt-kmes-batch-race"
        vm:write_file(at, bytes)
        t:assert_eq(sys.chmod(vm, at, tonumber("755", 8)).ret, 0, "helper is executable")
        local result = vm:run(at, { args = {}, timeout = "40s" })
        t:log(result.stdout)
        t:assert_eq(result.exit_code, 0, result.stdout .. result.stderr)
        t:assert(result.stdout:match("batches=512 accepted=%d+ discarded=%d+ wraps=%d+"),
            "helper reports sustained concurrent work: " .. result.stdout)
    end)
