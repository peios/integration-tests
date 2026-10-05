-- resolvd §2.2 — the startup steps that read the machine, run by the
-- service itself: a Dns key that is missing or unreadable, a registry
-- watch that cannot be armed, and the kernel's hostname. The steps that
-- need a chosen environment, a fatal failure or a lowered limit are in
-- resolvd-startup-hand.test.lua.
--
-- Harness: the scripted gateway (helpers.gateway) with its DNS server
-- (helpers.dns), and a whole Peios (helpers.network). resolvd is
-- restarted through peinit and read through its native socket and
-- eventd (`evctl LOGS FROM resolvd`).
--
-- Refusals are made with key descriptors (`reg sd`): an entry denying
-- resolvd's service SID KEY_NOTIFY on Machine\System\Network makes the
-- watch fail to arm while the configuration itself stays readable; one
-- denying it KEY_QUERY_VALUE|KEY_ENUMERATE_SUB_KEYS on the Dns key makes
-- that key unreadable. Each descriptor is put back.
--
-- Own VMs: the tests change key descriptors under Machine\System\Network
-- and the kernel's hostname, and restart resolvd.

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
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600, dns = { "10.77.0.1" } })
dns.serve(gw, {
    zone = {
        ["www.start.test"] = { { type = "A", ttl = 300, data = "10.77.0.80" } },
    },
    soa = { name = "start.test", data = { minimum = 30 } },
})
local sut = network.boot({ bridges = { lan }, gateway = gw })

local SOCK = "/run/resolvd/resolv.sock"
local SID = "S-1-5-80-3864064249-1823296737-2008945602-1354971773-2894779966"
local NETWORK = [[Machine\System\Network]]
local DNS = [[Machine\System\Network\Dns]]

-- ---------------------------------------------------------------------------
-- Local instruments
-- ---------------------------------------------------------------------------

local function rcall(req, timeout_ms)
    return network.call(sut, req, { path = SOCK, timeout_ms = timeout_ms or 3000 })
end

local function rstatus()
    local s, err = rcall({ query = "status" })
    assert(s and s.ok, "resolvd status: " .. tostring(err or (s and s.error)))
    return s
end

local function rpid() return peinit.pid_of_comm(sut, "resolvd") end

--- Restart resolvd through peinit. The socket the old process leaves is
--- removed by the agent first: the service cannot remove it itself
--- (PEI-1373, resolvd-sockets.test.lua).
local function restart()
    local before = rpid()
    sut:run("svctl stop resolvd"):assert_ok()
    wait_until(function() return rpid() == nil end, { timeout = 30, interval = 0.25, desc = "resolvd stopped" })
    sut:run("rm -f " .. SOCK):assert_ok()
    sut:run("svctl start resolvd"):assert_ok()
    wait_until(function()
        local p = rpid()
        if not p or p == before then return false end
        local s = rcall({ query = "status" }, 500)
        return s ~= nil and s.ok == true
    end, { timeout = 30, interval = 0.25, desc = "a new resolvd answering" })
end

local function guest_ns()
    return assert(tonumber(sut:run("date +%s%N").stdout:match("%d+")), "guest clock")
end

--- resolvd's log lines newer than `since` (guest ns), oldest first.
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

local function find(lines, text)
    for i, l in ipairs(lines) do if l:find(text, 1, true) then return i end end
end

--- A key's descriptor as SDDL (owner, group, DACL).
local function sddl(key)
    local r = network.reg(sut, { "sd", key })
    assert(r.exit_code == 0, "reg sd " .. key .. ": " .. r.stderr)
    return (r.stdout:gsub("%s+$", ""))
end

--- The key's DACL with a deny entry for resolvd's SID put first.
local function deny_first(key, rights)
    local current = sddl(key)
    local flags, aces = current:match("D:([A-Z]*)(%(.*)$")
    assert(aces, "a DACL in " .. current)
    local dacl = "D:" .. flags .. "(D;;" .. rights .. ";;;" .. SID .. ")" .. aces:gsub("S:.*$", "")
    local r = network.reg(sut, { "sd", key, "--dacl", "--set", dacl })
    assert(r.exit_code == 0, "reg sd --set: " .. r.stdout .. r.stderr)
    return current, dacl
end

local function put_back(key, original)
    local dacl = original:match("(D:.-)S:") or original:match("(D:.*)$")
    network.reg(sut, { "sd", key, "--dacl", "--set", dacl }):assert_ok()
end

--- A native request whose answer may need the network.
local function ask(req, timeout)
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

-- ---------------------------------------------------------------------------
-- Step 3: the Dns key
-- ---------------------------------------------------------------------------

test("a missing or unreadable Dns key is not an error: every value takes its default",
    { spec = "resolvd *startup.missing-dns-key-is-not-an-error" }, function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "eth0 bound")
        -- Missing: the shipped image has no Dns key.
        t:assert(network.reg(sut, { "get", DNS }).exit_code ~= 0, "Machine\\System\\Network\\Dns does not exist")
        local mark = guest_ns()
        restart()
        local s = rstatus()
        local lines = log_since(mark)
        t:log("start with no Dns key:\n" .. table.concat(lines, "\n"))
        t:assert_eq(#s.fallback_servers, 0, "no fallback servers")
        t:assert_eq(find(lines, "Dns"), nil, "nothing logged about the key")
        t:assert_eq(find(lines, ": error: "), nil, "no error")
        t:assert(find(lines, "listening on") ~= nil, "startup completed")

        -- Readable: the values are taken.
        network.write(sut, "Dns", { FallbackServers = "multi:10.77.0.98" })
        network.write(sut, [[Dns\Hosts]], { ["pt-unread.start.test"] = "multi:10.9.9.1" })
        restart()
        t:assert_eq(rstatus().fallback_servers[1], "10.77.0.98", "readable, FallbackServers is read")
        local r = rcall({ query = "resolve", name = "pt-unread.start.test", type = 1 })
        t:assert(r and r.outcome == "found" and r.records[1].text == "10.9.9.1", "and the static name")

        -- Unreadable: resolvd's account may not open it.
        local original = deny_first(DNS, "0x9")
        local ok, err = pcall(function()
            mark = guest_ns()
            restart()
            s = rstatus()
            lines = log_since(mark)
            t:log("start with an unreadable Dns key:\n" .. table.concat(lines, "\n"))
            t:assert_eq(#s.fallback_servers, 0, "unreadable: no fallback servers")
            local u = ask({ query = "resolve", name = "pt-unread.start.test", type = 1 })
            t:log("pt-unread.start.test: " .. json.encode(u))
            t:assert(u and u.source ~= "hosts" and u.outcome ~= "found", "and no static names")
            t:assert_eq(find(lines, "Dns"), nil, "nothing logged about the key")
            t:assert_eq(find(lines, ": error: "), nil, "no error")
            t:assert(find(lines, "listening on") ~= nil, "startup completed")
        end)
        put_back(DNS, original)
        network.reg(sut, { "del", "-r", DNS })
        restart()
        if not ok then error(err, 0) end
    end)

-- ---------------------------------------------------------------------------
-- Step 4: the watch
-- ---------------------------------------------------------------------------

test("a registry watch that cannot be armed is logged; the configuration read at startup is used until a restart",
    { spec = "resolvd *startup.watch-failure-reads-configuration-once" }, function(t)
        local original = deny_first(NETWORK, "0x10")
        local ok, err = pcall(function()
            local mark = guest_ns()
            restart()
            local lines = log_since(mark)
            t:log("start with KEY_NOTIFY denied:\n" .. table.concat(lines, "\n"))
            local i = find(lines, "resolvd: warn: registry watch unavailable (")
            t:assert(i ~= nil, "`registry watch unavailable (<error>)` at warn")
            t:assert(lines[i]:find("); configuration is read once", 1, true) ~= nil, "`; configuration is read once`")
            t:assert(find(lines, "listening on") ~= nil, "startup went on")
            t:assert_eq(#rstatus().fallback_servers, 0, "no fallback servers configured")

            mark = guest_ns()
            network.write(sut, "Dns", { FallbackServers = "multi:10.77.0.99" })
            sut:run("sleep 2")
            t:assert_eq(#rstatus().fallback_servers, 0, "a change is not seen")
            t:assert_eq(find(log_since(mark), "configuration changed"), nil, "and nothing is applied")

            restart()
            t:assert_eq(rstatus().fallback_servers[1], "10.77.0.99", "a restart reads it")
        end)
        put_back(NETWORK, original)
        network.reg(sut, { "del", "-r", DNS })
        restart()
        -- The watch is armed again: a change applies live.
        local mark = guest_ns()
        network.write(sut, "Dns", { FallbackServers = "multi:10.77.0.97" })
        wait_until(function() return rstatus().fallback_servers[1] == "10.77.0.97" end,
            { timeout = 10, interval = 0.25, desc = "the change applied live" })
        t:assert(find(log_since(mark), "configuration changed") ~= nil, "configuration changed")
        network.reg(sut, { "del", "-r", DNS })
        if not ok then error(err, 0) end
    end)

-- ---------------------------------------------------------------------------
-- Step 6: the kernel's hostname
-- ---------------------------------------------------------------------------

test("a kernel hostname that is (none) or empty counts as no hostname",
    { spec = "resolvd *startup.kernel-hostname-none-is-no-hostname" }, function(t)
        local function kernel(name)
            sut:write_file("/proc/sys/kernel/hostname", name .. "\n")
            return (sut:read_file("/proc/sys/kernel/hostname"):gsub("\n$", ""))
        end
        local ok, err = pcall(function()
            t:assert_eq(kernel("(none)"), "(none)", "kernel hostname (none)")
            restart()
            local s = rstatus()
            t:assert_eq(s.hostname, "", "(none) is no hostname")
            local text = sut:run("resolv status").stdout
            t:assert(text:match("hostname%s+%(unset%)") ~= nil, "resolv status shows it unset")
            local r = rcall({ query = "resolve", name = "(none)", type = 1 })
            t:log("resolve (none): " .. json.encode(r))
            t:assert(not (r and r.outcome == "found"), "and `(none)` is not answered as this machine")

            t:assert_eq(kernel("pt-kern-host"), "pt-kern-host", "kernel hostname pt-kern-host")
            restart()
            t:assert_eq(rstatus().hostname, "pt-kern-host", "a real kernel hostname is taken")
            local h = rcall({ query = "resolve", name = "pt-kern-host", type = 1 })
            t:assert(h and h.outcome == "found" and h.source == "synthetic", "and answered as this machine")

            t:assert_eq(kernel(""), "", "kernel hostname empty (written as a bare newline)")
            restart()
            t:assert_eq(rstatus().hostname, "", "an empty one is no hostname")
        end)
        kernel("(none)")
        restart()
        if not ok then error(err, 0) end
    end)
