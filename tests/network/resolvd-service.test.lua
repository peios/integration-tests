-- resolvd §1.2 and §2.1 — what is installed where, and the service: the
-- definition seed and its values, the identity resolvd runs as, the port
-- reservation, readiness as peinit is told it, what a restart keeps and
-- loses, and the shape and destination of resolvd's log lines.
--
-- Harness: the scripted gateway (helpers.gateway) with its DNS server
-- (helpers.dns), and a whole Peios (helpers.network) with resolvd under
-- peinit. resolvd is read where it publishes: its native socket
-- (`status`), the registry, /proc, peinit (`svctl`, eventd's events) and
-- eventd's copy of its standard error (`evctl LOGS FROM resolvd`).
--
-- Own VMs: the tests restart resolvd, kill it, stop netd, set the
-- kernel's hostname, and in the last test delete and re-apply resolvd's
-- own service definition; each puts back what it changed.
--
-- The installed-path tests ask the package database (`peipkg files`)
-- which package put each file there, as well as the filesystem.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")
local access = require("helpers.access")
local token = require("helpers.token")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600, dns = { "10.77.0.1" } })
dns.serve(gw, {
    zone = {
        ["www.svc.test"] = { { type = "A", ttl = 300, data = "10.77.0.80" } },
        ["fail.svc.test"] = { { type = "A", ttl = 300, data = "10.77.0.81" } },
    },
    soa = { name = "svc.test", data = { minimum = 30 } },
    on = function(q, default)
        local name = q.questions[1] and q.questions[1].name or ""
        if dns.same_name(name, "fail.svc.test") then
            default.rcode = dns.RCODE.SERVFAIL
            default.answers = {}
            return default
        end
    end,
})
local sut = network.boot({ bridges = { lan }, gateway = gw })

local SOCK = "/run/resolvd/resolv.sock"
local SID = "S-1-5-80-3864064249-1823296737-2008945602-1354971773-2894779966"
local SERVICE_KEY = [[Machine\System\Services\resolvd]]
local MIRROR = "resolvd: warn: /dev/kmsg mirror unavailable (Permission denied (os error 13)): log lines go to stderr only"

-- ---------------------------------------------------------------------------
-- Local instruments
-- ---------------------------------------------------------------------------

local function sh(cmd)
    return sut:run("sh", { args = { "-c", cmd } })
end

local function rpid() return peinit.pid_of_comm(sut, "resolvd") end

--- One native request, answered without the network.
local function rcall(req, timeout_ms)
    return network.call(sut, req, { path = SOCK, timeout_ms = timeout_ms or 3000 })
end

local function rstatus()
    local s, err = rcall({ query = "status" })
    assert(s and s.ok, "resolvd status: " .. tostring(err or (s and s.error)))
    return s
end

local function svc(name)
    return json.decode(sut:run("svctl --json status " .. (name or "resolvd")).stdout) or {}
end

local function guest_ns()
    return assert(tonumber(sut:run("date +%s%N").stdout:match("%d+")), "guest clock")
end

--- Wait until resolvd answers on its socket (a new process when `old`).
local function answering(old, timeout)
    wait_until(function()
        local p = rpid()
        if not p or p == old then return false end
        local s = rcall({ query = "status" }, 500)
        return s ~= nil and s.ok == true
    end, { timeout = timeout or 30, interval = 0.25, desc = "a resolvd answering on " .. SOCK })
    return rpid()
end

--- Restart resolvd through peinit. The socket the old process leaves is
--- removed by the agent first: the service cannot remove it itself
--- (PEI-1373, resolvd-sockets.test.lua).
local function restart()
    local before = rpid()
    sut:run("svctl stop resolvd"):assert_ok()
    wait_until(function() return rpid() == nil end, { timeout = 30, interval = 0.25, desc = "resolvd stopped" })
    sut:run("rm -f " .. SOCK):assert_ok()
    sut:run("svctl start resolvd"):assert_ok()
    return answering(before)
end

--- A native request whose answer needs the network: sent, then the
--- gateway pumped until the reply is whole.
local function ask(req, timeout)
    local unixsock = require("helpers.unixsock")
    local msgpack = require("helpers.msgpack")
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

--- resolvd's log lines newer than `since` (guest ns), oldest first, each
--- {msg, job, ts}. evctl lists newest first in the order eventd recorded
--- them; lines written together can carry one timestamp, so that order
--- (not the timestamp) is the sequence.
local function log_since(since)
    local r = sut:run("evctl 'LOGS FROM resolvd SINCE 1h ago TAKE 5000'")
    assert(r.exit_code == 0, "evctl: " .. r.stderr)
    local newest_first = {}
    for line in r.stdout:gmatch("[^\n]+") do
        local msg = line:match('message="(.-)"  origin=')
        local ts = tonumber(line:match("timestamp=(%d+)"))
        local job = line:match('job_id="(.-)"')
        if msg and ts and ts > (since or 0) then
            newest_first[#newest_first + 1] = { ts = ts, job = job, msg = (msg:gsub("\\(.)", "%1")) }
        end
    end
    local out = {}
    for i = #newest_first, 1, -1 do out[#out + 1] = newest_first[i] end
    return out
end

local function dump(t, lines, what)
    local out = {}
    for _, l in ipairs(lines) do out[#out + 1] = (l.job or "?") .. "  " .. l.msg end
    t:log((what or "resolvd log") .. ":\n" .. table.concat(out, "\n"))
end

--- The lines of one process run (one peinit job), oldest first.
local function of_job(lines, job)
    local out = {}
    for _, l in ipairs(lines) do if l.job == job then out[#out + 1] = l.msg end end
    return out
end

--- The registry values of `key` as `reg export --json` gives them, by name.
local function values_of(key)
    local tmp = "/tmp/pt-export.json"
    network.reg(sut, { "export", "--json", key, tmp }):assert_ok()
    local doc = json.decode(sut:read_file(tmp))
    local out = {}
    for _, k in ipairs(doc.keys or {}) do
        if k.path == key then
            for _, v in ipairs(k.values or {}) do out[v.name] = v end
        end
    end
    return out
end

--- A shipped seed file's values for `key`, by name.
local function seed_values(path, key)
    local doc = json.decode(sut:read_file(path))
    local out = {}
    for _, k in ipairs(doc.keys or {}) do
        if k.path == key then
            for _, v in ipairs(k.values or {}) do out[v.name] = v end
        end
    end
    return out
end

local function package_files(pkg)
    local r = sut:run("peipkg files " .. pkg)
    assert(r.exit_code == 0, "peipkg files " .. pkg .. ": " .. r.stderr)
    local set = {}
    for line in r.stdout:gmatch("[^\n]+") do set[line] = true end
    return set, r.stdout
end

local function exists(path)
    return (pcall(function() return sut:stat(path) end))
end

local function same(a, b)
    if type(a) ~= type(b) then return false end
    if type(a) ~= "table" then return a == b end
    return json.encode(a) == json.encode(b)
end

local function hex_bytes(h)
    return (h:gsub("%x%x", function(x) return string.char(tonumber(x, 16)) end))
end

-- ---------------------------------------------------------------------------
-- What is installed where
-- ---------------------------------------------------------------------------

test("the daemon, the operator command and the NSS shim are installed at their documented paths by their packages",
    { spec = "resolvd *coverage.daemon-installed-path resolvd *coverage.resolv-installed-path resolvd *coverage.shim-installed-path" },
    function(t)
        local daemon = package_files("dev.peios.resolvd")
        local cmd = package_files("dev.peios.resolv")
        local shim = package_files("dev.peios.resolvd-nss")
        local SHIM = "/usr/lib/x86_64-linux-peios/libnss_peios_net.so.2"
        t:assert(daemon["/usr/sbin/resolvd"], "dev.peios.resolvd installs /usr/sbin/resolvd")
        t:assert(cmd["/usr/bin/resolv"], "dev.peios.resolv installs /usr/bin/resolv")
        t:assert(shim[SHIM], "dev.peios.resolvd-nss installs " .. SHIM)
        for _, p in ipairs({ "/usr/sbin/resolvd", "/usr/bin/resolv", SHIM }) do
            t:assert(exists(p), p .. " is on disk")
        end

        -- The daemon peinit runs is that binary.
        local pid = assert(rpid(), "resolvd is running")
        local exe = peinit.proc_link(sut, pid, "exe")
        t:log("resolvd exe: " .. tostring(exe))
        t:assert_eq(exe, "/usr/sbin/resolvd", "the running daemon is /usr/sbin/resolvd")
        -- The command is that binary, and it reaches the daemon.
        local v = sut:run("/usr/bin/resolv version")
        t:log("resolv version: " .. v.stdout .. v.stderr)
        t:assert(v.exit_code == 0 and v.stdout:match("^resolv %d+%.%d+%.%d+") ~= nil, "/usr/bin/resolv runs")
        t:assert(sut:run("/usr/bin/resolv status").exit_code == 0, "and asks resolvd")
        -- The shim is a shared object of that name, and glibc's host
        -- lookups work through it.
        local head = sut:read_file(SHIM):sub(1, 18)
        t:assert_eq(head:sub(1, 4), "\127ELF", "the shim is an ELF object")
        t:assert_eq(string.unpack("<I2", head, 17), 3, "a shared object (ET_DYN)")
        t:assert(sut:read_file(SHIM):find("libnss_peios_net.so.2", 1, true) ~= nil, "whose soname is libnss_peios_net.so.2")
        local g = sut:run("getent hosts localhost")
        t:log("getent hosts localhost: " .. g.stdout)
        t:assert_eq(g.exit_code, 0, "getent hosts localhost answers")
    end)

test("dev.peios.resolvd ships the constant resolv.conf, both seeds, the regman reference and resolvd(8); dev.peios.resolv ships resolv(1)",
    { spec = "resolvd *coverage.packaged-files" }, function(t)
        local daemon, listing = package_files("dev.peios.resolvd")
        local cmd = package_files("dev.peios.resolv")
        t:log("peipkg files dev.peios.resolvd:\n" .. listing)
        for _, p in ipairs({ "/usr/etc/resolv.conf", "/usr/share/regim/resolvd-service.reg",
                             "/usr/share/regim/resolvd-port.reg", "/usr/share/regman/resolvd.regman",
                             "/usr/share/man/man8/resolvd.8.gz" }) do
            t:assert(daemon[p], "dev.peios.resolvd installs " .. p)
            t:assert(exists(p), p .. " is on disk")
        end
        t:assert(cmd["/usr/share/man/man1/resolv.1.gz"], "dev.peios.resolv installs resolv(1)")
        t:assert(exists("/usr/share/man/man1/resolv.1.gz"), "resolv(1) is on disk")
        -- The -debuginfo and -debugsource packages are build outputs; the
        -- image installs none of them and no repository is configured,
        -- so they are not visible from the guest.
        local l = sut:run("peipkg list")
        t:log("installed resolv* packages:\n" .. (l.stdout:gsub("[^\n]*\n", function(x)
            return x:find("resolv", 1, true) and x or "" end)))
    end)

-- ---------------------------------------------------------------------------
-- The service definition
-- ---------------------------------------------------------------------------

test("ImagePath is /usr/sbin/resolvd and resolvd is started with no arguments",
    { spec = "resolvd *service.image-path-no-arguments" }, function(t)
        local live = values_of(SERVICE_KEY)
        t:assert_eq(live.ImagePath and live.ImagePath.data, "/usr/sbin/resolvd", "ImagePath")
        t:assert_eq(live.ImagePath and live.ImagePath.type, "sz", "a REG_SZ")
        t:assert_eq(live.Arguments, nil, "no Arguments value")
        local cmdline = peinit.proc(sut, rpid(), "cmdline")
        t:log("cmdline: " .. (cmdline:gsub("%z", "\\0")))
        t:assert_eq(cmdline, "/usr/sbin/resolvd\0", "argv is the path alone")
    end)

test("Triggers is boot and peinit started resolvd from the boot transaction",
    { spec = "resolvd *service.triggered-at-boot" }, function(t)
        local live = values_of(SERVICE_KEY)
        t:assert_eq(live.Triggers and live.Triggers.type, "multi", "Triggers is a REG_MULTI_SZ")
        t:assert(same(live.Triggers and live.Triggers.data, { "boot" }), "holding boot")
        -- peinit records an operation's end as `peinit.operation.ended`,
        -- told apart by `object.operation.state`; evctl's pretty form
        -- prints each flattened field as `path=value`.
        local r = sut:run("evctl 'EVENTS peinit.operation.ended SINCE 1h ago TAKE 5000'")
        local found
        for line in r.stdout:gmatch("[^\n]+") do
            if line:find('event.type="peinit.operation.ended"', 1, true)
                and line:find('object.service.name="resolvd"', 1, true)
                and line:find('object.operation.type="start"', 1, true) then
                t:log(line:sub(1, 400))
                if line:find('object.operation.source="boot"', 1, true)
                    and line:find('object.operation.state="completed"', 1, true) then found = true end
            end
        end
        t:assert(found, "a completed start operation for resolvd with source boot")
    end)

test("Identity is Service: resolvd's token user is its own service SID",
    { spec = "resolvd *service.identity-is-own-virtual-account" }, function(t)
        local live = values_of(SERVICE_KEY)
        t:assert_eq(live.Identity and live.Identity.data, "Service", "Identity")
        local tok = peinit.token(sut, rpid())
        t:log("token principal: " .. json.encode(tok.principal))
        t:assert_eq(tok.principal.user, SID, "the user SID is resolvd's service SID")
        t:assert(tok.principal.user ~= "S-1-5-19" and tok.principal.user ~= "S-1-5-20"
            and tok.principal.user ~= "S-1-5-18", "not LocalService, NetworkService or SYSTEM")
        t:assert_eq(svc().current_job and svc().current_job.identity, "Service", "peinit runs it as Service")
    end)

test("Readiness is 0, notify: peinit hands resolvd a NOTIFY_SOCKET",
    { spec = "resolvd *service.readiness-is-notify" }, function(t)
        local live = values_of(SERVICE_KEY)
        t:assert_eq(live.Readiness and live.Readiness.type, "dword", "Readiness is a REG_DWORD")
        t:assert_eq(live.Readiness and live.Readiness.data, 0, "of 0")
        local show = sut:run("svctl definition show resolvd").stdout
        t:assert(show:match("Readiness%s+Notify") ~= nil, "which peinit reads as Notify")
        local env = peinit.proc(sut, rpid(), "environ") or ""
        t:log("environ: " .. (env:gsub("%z", " ")))
        t:assert(env:find("NOTIFY_SOCKET=", 1, true) ~= nil, "and resolvd's environment names a notify socket")
        t:assert_eq(svc().state, "active", "resolvd is active (READY=1 was taken)")
    end)

test("RuntimeDirectories is resolvd: peinit creates /run/resolvd",
    { spec = "resolvd *service.runtime-directory" }, function(t)
        local live = values_of(SERVICE_KEY)
        t:assert(same(live.RuntimeDirectories and live.RuntimeDirectories.data, { "resolvd" }), "RuntimeDirectories")
        -- Take the directory away and start the service: it is back, and
        -- owned by SYSTEM, not by resolvd's account, so peinit (SYSTEM)
        -- made it before resolvd ran.
        sut:run("svctl stop resolvd"):assert_ok()
        wait_until(function() return rpid() == nil end, { timeout = 30, interval = 0.25, desc = "resolvd stopped" })
        sut:run("rm -rf /run/resolvd"):assert_ok()
        t:assert(not exists("/run/resolvd"), "/run/resolvd removed")
        sut:run("svctl start resolvd"):assert_ok()
        answering(nil)
        local kacs = require("helpers.kacs")
        local sd = assert(kacs.get_sd(sut, "/run/resolvd", kacs.SI.OWNER), "the directory's owner")
        local owner = token.sid_string(access.parse_sd(sd).owner)
        t:log("/run/resolvd owner: " .. owner)
        t:assert_eq(owner, "S-1-5-18", "/run/resolvd exists again, created by peinit (SYSTEM)")
    end)

test("RestartPolicy is 2: a resolvd that dies is started again",
    { spec = "resolvd *service.restart-policy-always" }, function(t)
        local live = values_of(SERVICE_KEY)
        t:assert_eq(live.RestartPolicy and live.RestartPolicy.data, 2, "RestartPolicy")
        for _, sig in ipairs({ "KILL", "TERM" }) do
            local before = rpid()
            local old_jobs = {}
            for _, l in ipairs(log_since(0)) do old_jobs[l.job] = true end
            local mark = guest_ns()
            peinit.signal(sut, before, sig)
            -- A new run shows as log lines from a job the old process was not.
            local new_job, causes = nil, {}
            wait_until(function()
                local s = svc()
                causes[#causes + 1] = tostring(s.state) .. "/" .. tostring(s.cause)
                for _, l in ipairs(log_since(mark)) do
                    if not old_jobs[l.job] then new_job = l.job end
                end
                return new_job ~= nil
            end, { timeout = 30, interval = 0.25, desc = "peinit to start resolvd again" })
            local lines = log_since(mark)
            dump(t, lines, "after SIG" .. sig)
            t:log("peinit states seen: " .. table.concat(causes, " "))
            t:assert(new_job ~= nil, "after SIG" .. sig .. " peinit started resolvd again")
            local by_policy = false
            for _, c in ipairs(causes) do
                if c:find("restart_policy", 1, true) or c:find("process_crash", 1, true) then by_policy = true end
            end
            t:assert(by_policy, "under its restart policy, not by anyone's request")
            -- The new run cannot remove the socket the dead one left
            -- (PEI-1373); take it away so the next
            -- attempt the policy makes comes up.
            sut:run("svctl stop resolvd")
            wait_until(function() return rpid() == nil end, { timeout = 30, interval = 0.25, desc = "resolvd stopped" })
            sut:run("rm -f " .. SOCK)
            sut:run("svctl start resolvd")
            local after = answering(before, 60)
            t:log(string.format("SIG%s: pid %s -> %s", sig, before, after))
            wait_until(function() return svc().state == "active" end, { timeout = 20, interval = 0.25, desc = "active again" })
        end
    end)

-- ---------------------------------------------------------------------------
-- The port reservation
-- ---------------------------------------------------------------------------

test("the port seed writes tcp,udp:53 under TcpIp\\PortReservations as REG_BINARY",
    { spec = "resolvd *service.port-reservation-seed" }, function(t)
        local KEY = [[Machine\System\Network\TcpIp\PortReservations]]
        local seed = seed_values("/usr/share/regim/resolvd-port.reg", KEY)
        local names = {}
        for k in pairs(seed) do names[#names + 1] = k end
        t:assert_eq(table.concat(names, ","), "tcp,udp:53", "the seed writes one value, tcp,udp:53")
        t:assert_eq(seed["tcp,udp:53"].type, "binary", "of type binary")
        local live = values_of(KEY)
        t:assert(live["tcp,udp:53"] ~= nil, "the value is in the registry")
        t:assert_eq(live["tcp,udp:53"].type, "binary", "as REG_BINARY")
        t:assert_eq(live["tcp,udp:53"].data, seed["tcp,udp:53"].data, "holding the seed's bytes")
        -- It is what lets resolvd (no privilege) hold port 53.
        local tcp = sut:read_file("/proc/net/tcp")
        t:assert(tcp:find("3500007F:0035", 1, true) ~= nil, "127.0.0.53:53 is bound")
    end)

test("the reservation's descriptor grants SYSTEM and resolvd's service SID, and is more specific than tcp,udp:1-1023",
    { spec = "resolvd *service.reservation-granted-to-system-and-service-sid" }, function(t)
        local KEY = [[Machine\System\Network\TcpIp\PortReservations]]
        local live = values_of(KEY)
        local sd = access.parse_sd(hex_bytes(live["tcp,udp:53"].data))
        local trustees = {}
        for _, a in ipairs(sd.dacl.aces) do
            trustees[#trustees + 1] = string.format("%s:%d:%08x", token.sid_string(a.sid), a.type, a.mask)
        end
        t:log("tcp,udp:53 DACL: " .. table.concat(trustees, " "))
        t:assert_eq(#sd.dacl.aces, 2, "two entries")
        t:assert_eq(token.sid_string(sd.dacl.aces[1].sid), "S-1-5-18", "SYSTEM")
        t:assert_eq(token.sid_string(sd.dacl.aces[2].sid), SID, "and resolvd's service SID")
        for _, a in ipairs(sd.dacl.aces) do t:assert_eq(a.type, 0, "each an allow entry") end
        t:assert_eq(sd.dacl.aces[1].mask, sd.dacl.aces[2].mask, "granting the same right")
        t:assert(live["tcp,udp:1-1023"] ~= nil, "the kernel package's tcp,udp:1-1023 is there too")
        local wide = access.parse_sd(hex_bytes(live["tcp,udp:1-1023"].data))
        local any_resolvd = false
        for _, a in ipairs(wide.dacl.aces) do
            if token.sid_string(a.sid) == SID then any_resolvd = true end
        end
        t:assert(not any_resolvd, "which does not name resolvd: tcp,udp:53 alone admits it")
    end)

-- ---------------------------------------------------------------------------
-- Restart
-- ---------------------------------------------------------------------------

test("a restarted resolvd has an empty cache, no demoted servers and zeroed counters",
    { spec = "resolvd *service.restart-empties-cache resolvd *service.restart-clears-demotions" }, function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "eth0 bound")
        wait_until(function()
            local s = rstatus()
            return s.scopes[1] and s.scopes[1].servers[1] == "10.77.0.1"
        end, { timeout = 30, interval = 0.25, desc = "resolvd's eth0 scope with its server" })
        local a = ask({ query = "resolve", name = "www.svc.test", type = 1 })
        t:assert(a and a.outcome == "found", "www.svc.test answered by the server")
        local f = ask({ query = "resolve", name = "fail.svc.test", type = 1 })
        t:log("fail.svc.test: " .. json.encode(f))
        local before = rstatus()
        t:log("before: cache " .. before.cache_entries .. " demoted " .. json.encode(before.scopes[1].demoted)
            .. " counters " .. json.encode(before.counters))
        t:assert(before.cache_entries >= 1, "the answer is cached")
        t:assert(same(before.scopes[1].demoted, { "10.77.0.1" }), "the SERVFAILing server is demoted")
        t:assert(before.counters.queries >= 2, "questions were counted")

        restart()
        local after = rstatus()
        t:log("first status after the restart: " .. json.encode(after.counters))
        t:assert_eq(after.cache_entries, 0, "at once the cache is empty")
        for k, v in pairs(after.counters) do t:assert_eq(v, 0, "counter " .. k .. " is zero") end
        wait_until(function()
            after = rstatus()
            return after.scopes[1] ~= nil and after.scopes[1].servers[1] == "10.77.0.1"
        end, { timeout = 30, interval = 0.25, desc = "the scope back from netd" })
        t:log("after: cache " .. after.cache_entries .. " demoted " .. json.encode(after.scopes[1] and after.scopes[1].demoted)
            .. " counters " .. json.encode(after.counters))
        t:assert(after.scopes[1] ~= nil, "the scope is back from netd")
        t:assert_eq(#after.scopes[1].demoted, 0, "no server is demoted")
        -- And the formerly demoted server is asked first again: a fresh
        -- question goes upstream (not from the lost cache).
        dns.forget(gw)
        local b = ask({ query = "resolve", name = "www.svc.test", type = 1 })
        t:assert(b and b.outcome == "found" and b.source == "dns", "www.svc.test is asked upstream again")
        t:assert_eq(#dns.queries(gw, function(q)
            return q.msg and q.msg.questions[1] and dns.same_name(q.msg.questions[1].name, "www.svc.test")
        end), 1, "one query reached the server")
    end)

test("until netd is reached again, a restarted resolvd has no scopes and the kernel's hostname",
    { spec = "resolvd *service.restart-starts-without-scopes" }, function(t)
        sut:write_file("/proc/sys/kernel/hostname", "pt-kernel-name\n")
        sut:run("svctl stop netd"):assert_ok()
        wait_until(function() return network.netd_pid(sut) == nil end, { timeout = 30, interval = 0.25, desc = "netd stopped" })
        local ok, err = pcall(function()
            restart()
            local s = rstatus()
            t:log("without netd: " .. json.encode({ netd = s.netd, scopes = s.scopes, hostname = s.hostname }))
            t:assert_eq(s.netd, false, "netd is not connected")
            t:assert_eq(#s.scopes, 0, "no scopes")
            t:assert_eq(s.hostname, "pt-kernel-name", "the kernel's hostname")
        end)
        sut:run("svctl start netd")
        wait_until(function()
            local x = network.call(sut, { query = "status" })
            return x ~= nil and x.ok == true
        end, { timeout = 60, interval = 0.25, desc = "netd back" })
        sut:write_file("/proc/sys/kernel/hostname", "(none)\n")
        if not ok then error(err, 0) end
        -- netd is back; the first snapshot brings the scope.
        local got
        gw:serve({ timeout = 60, until_ = function()
            local s = rcall({ query = "status" }, 500)
            if s and s.netd and s.scopes[1] and s.scopes[1].servers[1] == "10.77.0.1" then got = s; return true end
            return false
        end })
        t:assert(got ~= nil, "after netd is reached the eth0 scope arrives")
    end)

-- ---------------------------------------------------------------------------
-- Log lines
-- ---------------------------------------------------------------------------

test("every line resolvd logs is `resolvd: <info|warn|error>: <text>` on standard error, read through eventd",
    { spec = "resolvd *service.log-line-format" }, function(t)
        -- Make a warning and some info lines.
        network.write(sut, "Dns", { FallbackServers = "multi:pt-not-an-address" })
        network.delete(sut, "Dns"):assert_ok()
        sut:run("resolv flush"):assert_ok()
        local lines = log_since(0)
        dump(t, lines)
        local levels = {}
        for _, l in ipairs(lines) do
            local level = l.msg:match("^resolvd: (%a+): .")
            t:assert(level == "info" or level == "warn" or level == "error",
                "`" .. l.msg .. "` has the resolvd: <level>: form")
            levels[level or "?"] = true
        end
        t:assert(levels.info and levels.warn, "info and warn lines were both seen")
        -- peinit's forwarder records them as the service's standard error.
        local r = sut:run("evctl 'LOGS FROM resolvd SINCE 1h ago TAKE 3'")
        for line in r.stdout:gmatch("[^\n]+") do
            t:assert(line:find("is_error=true", 1, true) ~= nil, "eventd holds the line as stderr output")
        end
    end)

test("the /dev/kmsg mirror fails once per process, directly after the first line, and nothing reaches the kernel log",
    { spec = "resolvd *service.kmsg-mirror-fails-once" }, function(t)
        local mark = guest_ns()
        -- A run that fails at once: the first line is its fatal error
        -- (the stale socket it cannot remove, PEI-1373).
        sut:run("svctl stop resolvd"):assert_ok()
        wait_until(function() return rpid() == nil end, { timeout = 30, interval = 0.25, desc = "resolvd stopped" })
        sut:run("svctl start resolvd")
        wait_until(function()
            for _, l in ipairs(log_since(mark)) do
                if l.msg:find("resolvd: error: native socket:", 1, true) then return true end
            end
            return false
        end, { timeout = 20, interval = 0.25, desc = "a run that fails at its native socket" })
        -- A start without a stale socket but with a Dns warning first.
        sut:run("svctl stop resolvd"):assert_ok()
        wait_until(function() return rpid() == nil end, { timeout = 30, interval = 0.25, desc = "resolvd stopped" })
        sut:run("rm -f " .. SOCK):assert_ok()
        network.write(sut, "Dns", { FallbackServers = "multi:pt-bad-address" })
        sut:run("svctl start resolvd"):assert_ok()
        answering(nil)
        -- More lines from that process, after the mirror's.
        network.delete(sut, "Dns"):assert_ok()
        sut:run("resolv flush"):assert_ok()
        wait_until(function()
            for _, l in ipairs(log_since(mark)) do
                if l.msg == "resolvd: info: cache flushed" then return true end
            end
            return false
        end, { timeout = 10, interval = 0.25, desc = "the flush logged" })
        local lines = log_since(0)
        dump(t, lines)

        -- One peinit job per process run.
        local jobs, order = {}, {}
        for _, l in ipairs(lines) do
            if not jobs[l.job] then jobs[l.job] = {}; order[#order + 1] = l.job end
            local j = jobs[l.job]
            j[#j + 1] = l.msg
        end
        t:assert(#order >= 3, "several runs are in the log")
        local failed, warned
        for _, job in ipairs(order) do
            local j = jobs[job]
            local n = 0
            for _, m in ipairs(j) do if m == MIRROR then n = n + 1 end end
            t:assert_eq(n, 1, "run " .. job .. " writes the mirror line once")
            t:assert_eq(j[2], MIRROR, "run " .. job .. ": the mirror line is the second line")
            if j[1]:find("resolvd: error: native socket:", 1, true) then failed = j end
            if j[1]:find("Dns FallbackServers", 1, true) then warned = j end
        end
        local boot = jobs[order[1]]
        t:assert_eq(boot[1], "resolvd: info: subscribed to netd", "boot: the first line is the first netd attempt")
        t:assert_eq(boot[3], "resolvd: info: listening on /run/resolvd/resolv.sock and 127.0.0.53:53",
            "which comes before the listening line")
        t:assert(failed ~= nil, "a run whose first line is an error also writes the mirror line second")
        t:assert(warned ~= nil, "a run with a Dns warning")
        t:assert_eq(warned[1], 'resolvd: warn: Dns FallbackServers: ignoring malformed address "pt-bad-address"',
            "with a Dns warning and no stale socket: the first line is the warning")
        t:assert(#warned >= 5, "that run logged on after the mirror line, and nothing more about the mirror")

        -- Nothing of resolvd's reaches the kernel log; netd's (SYSTEM) does.
        local kmsg = sh("timeout 2 cat /dev/kmsg; true").stdout
        local netd_lines = select(2, kmsg:gsub("netd: info:", ""))
        local resolvd_lines = select(2, kmsg:gsub("resolvd:", ""))
        t:log(string.format("kernel log: %d bytes, %d netd lines, %d resolvd lines", #kmsg, netd_lines, resolvd_lines))
        t:assert(netd_lines > 0, "the kernel log is readable and holds netd's mirrored lines")
        t:assert_eq(resolvd_lines, 0, "and none of resolvd's")
    end)

-- ---------------------------------------------------------------------------
-- The seed is inert until applied (last: it removes the definition)
-- ---------------------------------------------------------------------------

test("the definition is the shipped seed's; the seed does nothing until applied, and applying it restores the service",
    { spec = "resolvd *service.definition-seed-inert-until-applied" }, function(t)
        local SEED = "/usr/share/regim/resolvd-service.reg"
        local seed = seed_values(SEED, SERVICE_KEY)
        local live = values_of(SERVICE_KEY)
        local n = 0
        for name, v in pairs(seed) do
            n = n + 1
            t:assert(live[name] and live[name].type == v.type and same(live[name].data, v.data),
                "live " .. name .. " is the seed's " .. json.encode(v.data))
        end
        for name in pairs(live) do
            t:assert(seed[name] ~= nil, "live value " .. name .. " comes from the seed")
        end
        t:assert_eq(n, 9, "the seed carries nine values")
        -- The image stages seeds for the boot autorun, which drains
        -- /lcl/policy/autoapply.d; the package's own directory is not it.
        local script = sut:read_file("/lcl/policy/autorun.d/10-apply-seeds.sh")
        t:log("10-apply-seeds.sh:\n" .. script)
        t:assert(script:find("autoapply.d", 1, true) ~= nil, "the boot autorun applies autoapply.d")
        t:assert(script:find("/usr/share/regim", 1, true) == nil, "and not the package's seed directory")

        local saved = "/tmp/pt-resolvd-def.json"
        network.reg(sut, { "export", "--json", SERVICE_KEY, saved }):assert_ok()
        sut:run("svctl stop resolvd"):assert_ok()
        wait_until(function() return rpid() == nil end, { timeout = 30, interval = 0.25, desc = "resolvd stopped" })
        sut:run("rm -f " .. SOCK)
        local ok, err = pcall(function()
            network.reg(sut, { "del", "-r", SERVICE_KEY }):assert_ok()
            sut:run("svctl reload-config")
            local s = sut:run("svctl start resolvd")
            t:log("start without a definition: [" .. s.exit_code .. "] " .. s.stdout .. s.stderr)
            t:assert(s.exit_code ~= 0, "with the key gone peinit has no resolvd to start")
            t:assert(network.reg(sut, { "get", SERVICE_KEY }).exit_code ~= 0,
                "and /usr/share/regim/resolvd-service.reg did not put it back")
            t:assert(rpid() == nil, "resolvd is not running")
            network.reg(sut, { "apply", "/usr/share/regim/resolvd-service.reg" }):assert_ok()
            sut:run("svctl reload-config")
            sut:run("svctl start resolvd"):assert_ok()
            answering(nil)
            t:assert_eq(svc().state, "active", "applying the seed gives peinit the service back")
        end)
        if not ok then
            network.reg(sut, { "apply", saved })
            sut:run("svctl reload-config")
            sut:run("svctl start resolvd")
            error(err, 0)
        end
    end)
