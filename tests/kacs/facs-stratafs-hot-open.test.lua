-- PEI-1492 / PEI-1438 qualification: hot-file opens on the booted system's
-- StrataFS views. The peinit profile's / is overlay, not StrataFS. /bin and
-- /lib are real StrataFS mounts; these explicit library aliases exercise
-- those views, not the ELF interpreter's ordinary /lib64 lookup route.
-- KUnit separately counts provider reads; timing here cannot prove O(N).
local peinit = require("helpers.peinit")
peinit.claim(1, { cpus = 2 })

local vm = peinit.boot({
    name = "stratafs-hot-open", cpus = 2, memory = "1G",
    files = peinit.tool("pt-hot-open"),
})

test("hot StrataFS system files complete serial and contended open workloads", {
    spec = "PKM *facs.storage.stratafs-read-contention",
    tags = { "pei1492", "qualification", "benchmark" },
}, function(t)
    local mounts = vm:read_file("/proc/self/mountinfo")
    for line in mounts:gmatch("[^\n]+") do
        local point = line:match("^%d+ %d+ %S+ %S+ (%S+) ")
        if point == "/" or point == "/bin" or point == "/lib" then
            t:log("hot-open mount: " .. line)
        end
    end
    local paths = {
        "/lib/x86_64-linux-peios/libc.so.6",
        "/lib/x86_64-linux-peios/ld-linux-x86-64.so.2",
        "/bin/peinit2",
    }
    local iterations = 4096
    for _, path in ipairs(paths) do
        for _, workers in ipairs({ 1, 2, 4, 8 }) do
            for trial = 1, 3 do
                local result = vm:run(string.format("/usr/bin/pt-hot-open %s %d %d",
                    path, workers, iterations), { timeout = 120 })
                t:log(string.format("hot-open trial=%d %s", trial, result.stdout))
                result:assert_ok()
                local report = json.decode(result.stdout)
                t:assert_eq(report.path, path, "the requested system path")
                t:assert_eq(report.target_fstype, "0x53545241", "opened fd is on StrataFS")
                t:assert_eq(report.workers, workers, "requested concurrency")
                t:assert_eq(report.completed_workers, workers, "every opener completed")
                t:assert_eq(report.attempts, workers * iterations, "all operations attempted")
                t:assert_eq(report.opens, workers * iterations, "all opens succeeded")
                t:assert_eq(report.closes, workers * iterations, "all descriptors closed")
                t:assert_eq(#report.results, workers, "one completion record per worker")
                for _, worker in ipairs(report.results) do
                    t:assert_eq(worker.errno, 0, "worker returned no syscall error")
                    t:assert_eq(worker.closes, iterations, "worker completed its full workload")
                end
                -- elapsed_ns and operations_per_second are recorded only:
                -- host load and hardware must not determine conformance.
            end
        end
    end
end)
