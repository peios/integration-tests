-- PSPU §6.3 — the three doors and the one resolution behind them: the
-- native socket, the stub listener and the NSS shim all answer, a bare
-- name is expanded, routed and cached once for all of them, static
-- names are answered at each, /etc/resolv.conf is the constant pointer,
-- and there is no fourth path (no `files`, no direct DNS). Also resolvd
-- §9.1's rule that answering a question logs nothing.
--
-- Harness: the scripted gateway (helpers.gateway) with its DNS server
-- (helpers.dns), and a whole Peios (helpers.network). The doors are
-- asked from inside the guest: the native socket from the agent
-- (unixsock), the stub door over UDP and TCP (ntfe), and the shim
-- through glibc (`getent`), each while the gateway pumps.
--
-- The gateway's lease carries the search domain corp.test (option 15),
-- so a bare `printer` is expanded by resolvd to printer.corp.test.
--
-- Own VMs: the last tests write /etc/hosts and /etc/nsswitch.conf, stop
-- resolvd, and wait out upstream timeouts; each puts back what it
-- changed.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")
local unixsock = require("helpers.unixsock")
local msgpack = require("helpers.msgpack")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600, dns = { "10.77.0.1" }, options = { { 15, "corp.test" } } })
dns.serve(gw, {
    zone = {
        ["printer.corp.test"] = { { type = "A", ttl = 300, data = "10.77.0.90" },
                                  { type = "AAAA", ttl = 300, data = "fd77::90" } },
        ["www.doors.test"] = { { type = "A", ttl = 300, data = "10.77.0.80" } },
        ["fail.doors.test"] = { { type = "A", ttl = 300, data = "10.77.0.81" } },
    },
    soa = { name = "doors.test", data = { minimum = 30 } },
    on = function(q, default)
        local name = (q.questions[1] and q.questions[1].name or ""):lower()
        if name:match("^slow") then return false end
        if name == "fail.doors.test" then
            default.rcode = dns.RCODE.SERVFAIL
            default.answers = {}
            return default
        end
    end,
})
local sut = network.boot({ bridges = { lan }, gateway = gw })

local SOCK = "/run/resolvd/resolv.sock"

-- ---------------------------------------------------------------------------
-- Local instruments
-- ---------------------------------------------------------------------------

local function rcall(req, timeout_ms)
    return network.call(sut, req, { path = SOCK, timeout_ms = timeout_ms or 3000 })
end

local function rpid() return peinit.pid_of_comm(sut, "resolvd") end

local function guest_ns()
    return assert(tonumber(sut:run("date +%s%N").stdout:match("%d+")), "guest clock")
end

local function log_since(since)
    local r = sut:run("evctl 'LOGS FROM resolvd SINCE 1h ago TAKE 5000'")
    assert(r.exit_code == 0, "evctl: " .. r.stderr)
    local newest_first = {}
    for line in r.stdout:gmatch("[^\n]+") do
        local msg = line:match('message="(.-)"  origin=')
        local ts = tonumber(line:match("timestamp=(%d+)"))
        if msg and ts and ts > since then newest_first[#newest_first + 1] = (msg:gsub("\\(.)", "%1")) end
    end
    local out = {}
    for i = #newest_first, 1, -1 do out[#out + 1] = newest_first[i] end
    return out
end

--- A shell command run while the gateway pumps.
local function served(cmd, timeout)
    local p = sut:run_async("sh", { args = { "-c", cmd } })
    gw:serve({ timeout = timeout or 20, until_ = function() return p:status() == "exited" end })
    return p:wait(5)
end

--- The native door: one request, the gateway pumped until the reply.
local function native(req, timeout)
    local fd = assert(unixsock.socket(sut, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
    local c = unixsock.connect(sut, fd, SOCK)
    assert(c.ret == 0, "connect: " .. unixsock.errname(c.errno))
    local p = msgpack.encode(req)
    ntfe.send(sut, fd, string.pack("<I4", #p) .. p)
    local buf, reply = "", nil
    gw:serve({ timeout = timeout or 20, until_ = function()
        local chunk = ntfe.recv(sut, fd, 20, 65536)
        if chunk and #chunk > 0 then buf = buf .. chunk end
        if #buf >= 4 then
            local len = string.unpack("<I4", buf)
            if #buf >= 4 + len then reply = msgpack.decode(buf:sub(5, 4 + len)); return true end
        end
        return false
    end })
    sys.close(sut, fd)
    return reply
end

--- The stub door over UDP or TCP; the decoded reply.
local function stub(name, qtype, tcp, timeout)
    local q = dns.encode(dns.query(name, qtype or "A", { id = 31337 }))
    local fd
    if tcp then
        fd = assert(ntfe.tcp_connect(sut, "127.0.0.53", 53, 2000))
        ntfe.send(sut, fd, string.pack(">I2", #q) .. q)
    else
        fd = assert(ntfe.udp_connect(sut, "127.0.0.53", 53))
        ntfe.send(sut, fd, q)
    end
    local buf, got = "", nil
    gw:serve({ timeout = timeout or 20, until_ = function()
        local chunk = ntfe.recv(sut, fd, 20, 65536)
        if chunk and #chunk > 0 then buf = buf .. chunk end
        if not tcp and #buf > 0 then got = buf; return true end
        if tcp and #buf >= 2 and #buf >= 2 + string.unpack(">I2", buf) then got = buf:sub(3); return true end
        return false
    end })
    sys.close(sut, fd)
    return got and dns.decode(got)
end

local function queries_for(fragment)
    return dns.queries(gw, function(q)
        return q.msg and q.msg.questions[1] and q.msg.questions[1].name:lower():find(fragment, 1, true) ~= nil
    end)
end

local function data_of(reply, rtype)
    local out = {}
    for _, r in ipairs(reply and reply.answers or {}) do
        if r.type == dns.TYPE[rtype] then out[#out + 1] = tostring(r.data) end
    end
    return table.concat(out, ",")
end

local function routed(t)
    t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "eth0 bound")
    wait_until(function()
        local s = rcall({ query = "status" })
        return s and s.scopes[1] and s.scopes[1].servers[1] == "10.77.0.1" and s.scopes[1].domains[1] == "corp.test"
    end, { timeout = 30, interval = 0.25, desc = "resolvd's eth0 scope with its server and corp.test" })
end

-- ---------------------------------------------------------------------------
-- The doors
-- ---------------------------------------------------------------------------

test("a resolver offers three doors: the native socket, the stub listener, and the NSS shim",
    { spec = "PSPU *nri-doors.offers-three-doors" }, function(t)
        routed(t)
        local n = native({ query = "resolve", name = "www.doors.test", type = 1 })
        t:assert(n and n.outcome == "found" and n.records[1].text == "10.77.0.80", "the native socket answers")
        local u = stub("www.doors.test", "A", false)
        t:assert_eq(data_of(u, "A"), "10.77.0.80", "the stub listener answers over UDP")
        local tc = stub("www.doors.test", "A", true)
        t:assert_eq(data_of(tc, "A"), "10.77.0.80", "and over TCP")
        local g = served("getent ahostsv4 www.doors.test")
        t:log("getent: " .. g.stdout)
        t:assert(g.exit_code == 0 and g.stdout:find("10.77.0.80", 1, true) ~= nil, "glibc answers through the shim")
    end)

test("every door runs the same resolution: a bare name is expanded, routed and cached once for all three",
    { spec = "PSPU *nri-doors.one-resolution-function-behind-every-door" }, function(t)
        routed(t)
        sut:run("resolv flush"):assert_ok()
        dns.forget(gw)
        local before = rcall({ query = "status" }).counters
        -- The shim first: glibc asks for both families.
        local g = served("getent ahosts printer")
        t:log("getent ahosts printer:\n" .. g.stdout)
        t:assert(g.exit_code == 0 and g.stdout:find("10.77.0.90", 1, true) and g.stdout:find("fd77::90", 1, true),
            "the shim gets printer.corp.test's addresses for `printer`")
        -- The native socket: the same expansion and scope, from the cache.
        local n = native({ query = "resolve", name = "printer", type = 1 })
        t:log("native: " .. json.encode(n))
        t:assert(n and n.outcome == "found" and n.records[1].text == "10.77.0.90", "the native socket answers `printer`")
        t:assert_eq(n.records[1].name, "printer.corp.test", "at the expanded name")
        t:assert_eq(n.interface, "eth0", "routed to eth0's scope")
        t:assert_eq(n.source, "cache", "from the cache the shim's question filled")
        -- The stub door, both transports: the same again.
        local u = stub("printer", "A", false)
        t:assert_eq(data_of(u, "A"), "10.77.0.90", "the stub door answers `printer` over UDP")
        t:assert_eq(data_of(u, "CNAME"), "printer.corp.test", "with the expansion shown as a CNAME")
        local tc = stub("printer", "AAAA", true)
        t:assert_eq(data_of(tc, "AAAA"), "fd77::90", "and AAAA over TCP")
        local after = rcall({ query = "status" }).counters
        t:log("counters before " .. json.encode(before) .. " after " .. json.encode(after))
        t:assert_eq(after.cache_hits - before.cache_hits, 3, "the three later questions were cache hits")
        local qs = dns.queries(gw, function(q) return q.msg and q.msg.questions[1]
            and not q.msg.questions[1].name:lower():find("time.peios.org", 1, true) end)
        local names = {}
        for _, q in ipairs(qs) do names[#names + 1] = q.msg.questions[1].name:lower() .. "/" .. q.msg.questions[1].type end
        table.sort(names)
        t:log("upstream: " .. table.concat(names, " "))
        t:assert_eq(table.concat(names, " "), "printer.corp.test/1 printer.corp.test/28",
            "upstream was asked once per type, at the expanded name only, never `printer` bare")
    end)

test("a static name from the registry is answered at every door, and never asked upstream",
    { spec = "PSPU *nri-doors.static-names-answered-at-every-door" }, function(t)
        routed(t)
        network.write(sut, "Dns", {})
        network.write(sut, [[Dns\Hosts]], { ["pt-printer"] = "multi:10.9.8.7" })
        wait_until(function()
            local r = rcall({ query = "resolve", name = "pt-printer", type = 1 })
            return r and r.outcome == "found"
        end, { timeout = 10, interval = 0.25, desc = "the static name in force" })
        dns.forget(gw)
        local n = native({ query = "resolve", name = "pt-printer", type = 1 })
        t:assert(n and n.records[1] and n.records[1].text == "10.9.8.7", "the native socket")
        t:assert_eq(data_of(stub("pt-printer", "A", false), "A"), "10.9.8.7", "the stub door over UDP")
        t:assert_eq(data_of(stub("pt-printer", "A", true), "A"), "10.9.8.7", "the stub door over TCP")
        local g = served("getent hosts pt-printer")
        t:log("getent hosts pt-printer: " .. g.stdout)
        t:assert(g.exit_code == 0 and g.stdout:find("10.9.8.7", 1, true) ~= nil, "the shim")
        t:assert_eq(#queries_for("pt-printer"), 0, "no door sent it upstream")
        network.reg(sut, { "del", "-r", [[Machine\System\Network\Dns]] })
    end)

test("/etc/resolv.conf is the constant nameserver 127.0.0.53 / options edns0, shipped as /usr/etc/resolv.conf and never rewritten",
    { spec = "PSPU *nri-doors.resolv-conf-is-constant" }, function(t)
        routed(t)
        local etc = sut:read_file("/etc/resolv.conf")
        local usr = sut:read_file("/usr/etc/resolv.conf")
        t:log("/etc/resolv.conf:\n" .. etc)
        t:assert_eq(etc, usr, "/etc/resolv.conf is /usr/etc/resolv.conf")
        local directives = {}
        for line in etc:gmatch("[^\n]+") do
            if not line:match("^%s*#") and line:match("%S") then directives[#directives + 1] = line end
        end
        t:assert_eq(table.concat(directives, "|"), "nameserver 127.0.0.53|options edns0",
            "it says nameserver 127.0.0.53 and options edns0, and nothing else: no search list")
        t:assert(sut:run("peipkg files dev.peios.resolvd").stdout:find("/usr/etc/resolv.conf\n", 1, true) ~= nil,
            "shipped by the resolver's package")
        -- netd's servers and domains (corp.test) are in force, and change:
        -- the file does not follow.
        local mtime = sut:stat("/etc/resolv.conf").mtime_ns
        local dhcp = gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600, dns = { "10.77.0.1", "10.77.0.2" },
            options = { { 15, "other.test" } } })
        t:assert(network.call(sut, { query = "renew", interface = "eth0" }).ok, "renew")
        wait_until(function()
            gw:pump(100)
            local s = rcall({ query = "status" })
            return s and s.scopes[1] and #s.scopes[1].servers == 2
        end, { timeout = 30, interval = 0.1, desc = "the new servers in resolvd" })
        t:assert_eq(sut:read_file("/etc/resolv.conf"), etc, "the file is unchanged after the scope changed")
        t:assert_eq(sut:stat("/etc/resolv.conf").mtime_ns, mtime, "and was not rewritten")
        -- Put the lease back.
        dhcp.dns = { "10.77.0.1" }
        dhcp.options = { { 15, "corp.test" } }
        t:assert(network.call(sut, { query = "renew", interface = "eth0" }).ok, "renew")
        routed(t)
    end)

test("there is no fourth policy path: no files source behind the shim, and no direct DNS when resolvd is down",
    { spec = "PSPU *nri-doors.no-fourth-policy-path" }, function(t)
        routed(t)
        -- A hosts file and a switch that names `files` are not read.
        local wrote = {}
        for _, f in ipairs({ { "hosts", "10.9.9.9 pt-filehost\n" }, { "nsswitch.conf", "hosts: files dns\n" } }) do
            local path = "/etc/" .. f[1]
            if not pcall(sut.write_file, sut, path, f[2]) then
                path = "/lcl/etc/" .. f[1]
                sut:write_file(path, f[2])
            end
            wrote[#wrote + 1] = path
            t:assert_eq(sut:read_file("/etc/" .. f[1]), f[2], "/etc/" .. f[1] .. " is in place")
        end
        local ok, err = pcall(function()
            dns.forget(gw)
            local g = served("getent hosts pt-filehost")
            t:log("getent hosts pt-filehost: [" .. g.exit_code .. "] " .. g.stdout)
            t:assert_eq(g.exit_code, 2, "a name only /etc/hosts holds is not found")
            -- It went to resolvd, which expanded it with corp.test and
            -- asked; nothing answered from the file.
            for _, q in ipairs(queries_for("pt-filehost")) do
                t:assert_eq(q.msg.questions[1].name:lower(), "pt-filehost.corp.test", "asked only as resolvd expands it")
            end
            t:assert_eq(served("getent ahostsv4 www.doors.test").exit_code, 0, "names still resolve through resolvd")

            -- resolvd down: the shim answers localhost itself and nothing
            -- else, and nothing goes to the network or to 127.0.0.53.
            sut:run("svctl stop resolvd"):assert_ok()
            wait_until(function() return rpid() == nil end, { timeout = 30, interval = 0.25, desc = "resolvd stopped" })
            dns.forget(gw)
            local lh = served("getent hosts localhost")
            t:log("localhost without resolvd: [" .. lh.exit_code .. "] " .. lh.stdout)
            t:assert_eq(lh.exit_code, 0, "localhost is answered by the shim")
            local w = served("getent ahostsv4 www.doors.test")
            t:log("www.doors.test without resolvd: [" .. w.exit_code .. "] " .. w.stdout .. w.stderr)
            t:assert(w.exit_code ~= 0, "another name is not answered")
            local f2 = served("getent hosts pt-filehost")
            t:assert(f2.exit_code ~= 0, "not even from /etc/hosts")
            gw:serve({ timeout = 3 })
            t:assert_eq(#queries_for("www.doors.test"), 0, "no direct DNS query reached the network")
        end)
        for _, path in ipairs(wrote) do sut:run("rm -f " .. path) end
        if rpid() == nil then
            -- The service cannot remove its own stale socket (PEI-1373).
            sut:run("rm -f " .. SOCK)
            sut:run("svctl start resolvd")
            wait_until(function() local s = rcall({ query = "status" }, 500); return s ~= nil and s.ok end,
                { timeout = 30, interval = 0.25, desc = "resolvd back" })
        end
        if not ok then error(err, 0) end
    end)

-- ---------------------------------------------------------------------------
-- §9.1: answering a question logs nothing
-- ---------------------------------------------------------------------------

test("answering a question writes no log line, however it is answered, timeouts and demotions included",
    { spec = "resolvd *failure-signals.no-per-question-logging" }, function(t)
        routed(t)
        network.write(sut, "Dns", {})
        network.write(sut, [[Dns\Hosts]], { ["pt-quiet"] = "multi:10.9.8.6" })
        sut:run("sleep 1")
        local mark = guest_ns()
        local results = {}
        local function note(what, ok) results[#results + 1] = what; t:assert(ok, what) end
        note("synthetic", (native({ query = "resolve", name = "localhost", type = 1 }) or {}).source == "synthetic")
        note("static", (native({ query = "resolve", name = "pt-quiet", type = 1 }) or {}).source == "hosts")
        note("server", (native({ query = "resolve", name = "www.doors.test", type = 1, no_cache = true }) or {}).source == "dns")
        note("cache", (native({ query = "resolve", name = "www.doors.test", type = 1 }) or {}).source == "cache")
        note("notfound", (native({ query = "resolve", name = "nx.doors.test", type = 1 }) or {}).outcome == "notfound")
        note("servfail and demotion", (native({ query = "resolve", name = "fail.doors.test", type = 1 }) or {}).outcome == "unavailable")
        local demoted = rcall({ query = "status" }).scopes[1].demoted
        t:assert_eq(demoted[1], "10.77.0.1", "the server was demoted")
        note("stub UDP", stub("www.doors.test", "A", false) ~= nil)
        note("stub TCP", stub("www.doors.test", "A", true) ~= nil)
        note("shim", served("getent ahostsv4 www.doors.test").exit_code == 0)
        local slow = native({ query = "resolve", name = "slow.doors.test", type = 1 }, 20)
        note("timeouts to unavailable", slow and slow.outcome == "unavailable")
        local lines = log_since(mark)
        t:log("answered: " .. table.concat(results, ", ") .. "\nlog since:\n" .. table.concat(lines, "\n"))
        t:assert_eq(#lines, 0, "no line was logged for any of them")
        network.reg(sut, { "del", "-r", [[Machine\System\Network\Dns]] })
    end)
