-- PEI-1344: the shipped service limit and bounded handling of local fd
-- exhaustion. Only the disposable resolver process gets a reduced limit;
-- the host and other guest processes keep their original limits.
local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")
local unixsock = require("helpers.unixsock")

peinit.claim(2)
local SOCK = "/run/resolvd/resolv.sock"
local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
dns.serve(gw, { zone = { ["www.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.80" } } } })
local files = {}
for env, path in pairs({ RESOLVD_TEST_BINARY = "usr/sbin/resolvd", RESOLVD_TEST_SERVICE = "tmp/resolvd-service.reg" }) do
    local source = os.getenv(env)
    if source then
        local f = assert(io.open(source, "rb"))
        files[path] = { f:read("*a"), exec = env == "RESOLVD_TEST_BINARY" }
        f:close()
    end
end
local sut = network.boot({ bridges = { lan }, gateway = gw, files = files })

local function status()
    return assert(network.call(sut, { query = "status" }, { path = SOCK }))
end
local function ready(t)
    t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound")
    t:assert(gw:serve({ timeout = 20, until_ = function()
        local current = network.call(sut, { query = "status" }, { path = SOCK, timeout_ms = 1000 }) or {}
        for _, scope in ipairs(current.scopes or {}) do
            if (scope.servers or {})[1] == "10.77.0.1" then return true end
        end
    end }), "resolver has the local fixture server")
end
local function limits(pid)
    local soft, hard = sut:read_file("/proc/" .. pid .. "/limits"):match("Max open files%s+(%d+)%s+(%d+)")
    return assert(tonumber(soft)), assert(tonumber(hard))
end
local function set_limit(pid, soft, hard)
    return sut:syscall(302, { args = { pid, 7, 0, 0 }, bufs = { string.pack("<I8I8", soft, hard) }, ptrs = { 2 } })
end
local function native()
    local fd = assert(unixsock.socket(sut, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
    assert(unixsock.connect(sut, fd, SOCK).ret == 0, "native connect")
    return fd
end

test("resolvd's service reserves descriptor headroom for upstream transactions and their waiters",
    { spec = "resolvd *engine-servers.in-flight-ceiling-value", tags = { "pei-1344" } }, function(t)
        ready(t)
        if os.getenv("RESOLVD_TEST_SERVICE") then
            network.reg(sut, { "apply", "/tmp/resolvd-service.reg" }):assert_ok()
            sut:run("svctl stop resolvd"):assert_ok()
            wait_until(function() return peinit.pid_of_comm(sut, "resolvd") == nil end,
                { timeout = 20, interval = 0.1, desc = "resolvd stopped" })
            -- The cached image needs its runtime directory reprovisioned.
            sut:run("rm -rf /run/resolvd"):assert_ok()
            sut:run("svctl start resolvd"):assert_ok()
            ready(t)
        end
        local soft, hard = limits(peinit.pid_of_comm(sut, "resolvd"))
        t:log(string.format("descriptor limits: %d / %d", soft, hard))
        t:assert(soft >= 16384 and hard >= 16384, "service applies descriptor headroom")
    end)

test("local descriptor exhaustion does not demote servers or busy-spin either listener, and recovery needs no restart",
    { spec = "resolvd *engine-servers.send-error-fails-attempt-at-once resolvd *failure-signals.listener-errors-logged-and-survived", tags = { "pei-1344", "pei-1344-resource" } }, function(t)
        ready(t)
        sut:run("svctl stop timed"):assert_ok()
        gw:serve({ timeout = 7 })
        local pid = assert(peinit.pid_of_comm(sut, "resolvd"))
        local soft, hard = limits(pid)
        local before = status().counters
        local held = {}
        local function hold(fd) held[#held + 1] = fd; return fd end
        local native_count, tcp_count
        local ok, err = pcall(function()
            local question = hold(assert(ntfe.udp_connect(sut, "127.0.0.53", 53)))
            t:assert_eq(set_limit(pid, 64, hard).ret, 0, "reduce only the disposable resolver's soft limit")
            for _ = 1, 70 do hold(native()) end
            hold(assert(ntfe.tcp_connect(sut, "127.0.0.53", 53, 1000)))
            wait_until(function() return #sut:listdir("/proc/" .. pid .. "/fd") >= 64 end,
                { timeout = 3, interval = 0.05, desc = "resolver at the controlled descriptor limit" })
            local payload = dns.encode({ id = 0x1344, rd = true,
                questions = { { name = "www.example.test", type = 1, class = 1 } } })
            t:assert_eq(ntfe.send(sut, question, payload).ret, #payload, "send local stub question")
            local answer = assert(dns.decode(assert(ntfe.recv(sut, question, 3000, 4096))))
            t:assert_eq(answer.rcode, 2, "resource failure answers SERVFAIL")
            gw:serve({ timeout = 1.0 })
            local logs = sut:run("evctl 'LOGS FROM resolvd SINCE 10s ago TAKE 2000'").stdout
            local ignored
            ignored, native_count = logs:gsub("native accept:", "")
            ignored, tcp_count = logs:gsub("stub tcp accept:", "")
            t:log(string.format("accept warnings: native %d, TCP %d", native_count, tcp_count))
        end)
        local restored = set_limit(pid, soft, hard)
        for _, fd in ipairs(held) do sys.close(sut, fd) end
        t:assert_eq(restored.ret, 0, "restore the resolver limit")
        if not ok then error(err, 0) end
        gw:serve({ timeout = 0.5 })
        local after = status()
        t:assert_eq(after.counters.upstream_sent - before.upstream_sent, 3, "bounded retry budget is preserved")
        t:assert_eq(after.counters.upstream_failed - before.upstream_failed, 3, "each failed transaction is counted")
        for _, scope in ipairs(after.scopes or {}) do
            t:assert_eq(#(scope.demoted or {}), 0, "healthy servers remain healthy")
        end
        t:assert(native_count >= 1 and native_count <= 16, "native accept retries are bounded")
        t:assert(tcp_count >= 1 and tcp_count <= 16, "TCP accept retries are bounded")
        local p = sut:run_async("resolv", { args = { "query", "www.example.test", "A" } })
        gw:serve({ timeout = 15, until_ = function() return p:status() == "exited" end })
        t:assert(p:wait(5).stdout:match("^found"), "resolution recovers without restarting")
        t:assert_eq(peinit.pid_of_comm(sut, "resolvd"), pid, "same daemon process")
    end)
