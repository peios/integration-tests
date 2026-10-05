-- The machine under test for tests/network: a whole Peios (the peinit
-- profile) on a provium bridge, and the means to read what netd made of
-- the network the scripted gateway (helpers.gateway) is playing.
--
-- The machine's only NIC is on the bridge: provium gives a VM no other
-- network, so whatever netd and resolvd learn, they learn from the
-- gateway. It is attached before boot, so netd finds it at its first
-- pass exactly as it would a real card.
--
-- netd is read where it publishes: its control socket (`status`, the same
-- reply `net status` prints), the registry (`reg`), and the kernel
-- (`/proc`). The agent runs as SYSTEM, which the control object's default
-- descriptor admits to every request.

local peinit = require("helpers.peinit")
local msgpack = require("helpers.msgpack")
local unixsock = require("helpers.unixsock")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")

local M = {}

M.CONTROL = "/run/netd/control.sock"
M.KEY = [[Machine\System\Network]]

--- Boot the machine under test on `o.bridges` (one NIC per bridge, in
--- order). Every other option is `helpers.peinit.boot`'s. Returns the VM.
function M.boot(o)
    o = o or {}
    o.name = o.name or "sut"
    return peinit.boot(o)
end

-- ---------------------------------------------------------------------------
-- netd's control socket
-- ---------------------------------------------------------------------------

local function read_exact(who, fd, n, timeout_ms)
    local got = {}
    local have = 0
    while have < n do
        local chunk, err = ntfe.recv(who, fd, timeout_ms or 5000, n - have)
        if not chunk then return nil, err end
        if #chunk == 0 then return nil, "closed" end
        got[#got + 1] = chunk
        have = have + #chunk
    end
    return table.concat(got)
end

--- Send one request to netd and read the reply. `request` is a Lua table
--- (`{query = "status"}`) or raw payload bytes. `o.who` (the agent),
--- `o.timeout_ms` (5000). Returns the decoded reply, or nil and a reason.
function M.call(vm, request, o)
    o = o or {}
    local who = o.who or vm
    local fd, e = unixsock.socket(who, unixsock.AF_UNIX, unixsock.SOCK.STREAM)
    if not fd then return nil, "socket: " .. unixsock.errname(e) end
    local r = unixsock.connect(who, fd, o.path or M.CONTROL)
    if r.ret ~= 0 then
        sys.close(who, fd)
        return nil, "connect: " .. unixsock.errname(r.errno)
    end
    local payload = type(request) == "string" and request or msgpack.encode(request)
    local frame = (o.length and string.pack("<I4", o.length) or string.pack("<I4", #payload)) .. payload
    ntfe.send(who, fd, frame)
    local head, err = read_exact(who, fd, 4, o.timeout_ms)
    if not head then sys.close(who, fd); return nil, "no reply: " .. tostring(err) end
    local len = string.unpack("<I4", head)
    local body
    body, err = read_exact(who, fd, len, o.timeout_ms)
    sys.close(who, fd)
    if not body then return nil, "short reply: " .. tostring(err) end
    return (msgpack.decode(body))
end

--- netd's status reply, decoded. Raises if netd does not answer.
function M.status(vm)
    local s, err = M.call(vm, { query = "status" })
    assert(s, "netd status: " .. tostring(err))
    assert(s.ok, "netd status: " .. tostring(s.error))
    return s
end

--- The status of the interface named `name`, or the only one there is.
function M.iface(status, name)
    for _, i in ipairs(status.interfaces or {}) do
        if not name or i.name == name or i.ifid == name then return i end
    end
end

--- Whether `addr` (text, no prefix) is among the interface's addresses.
function M.has_address(i, addr)
    for _, a in ipairs((i and i.addresses) or {}) do
        if a:match("^([^/]+)") == addr then return true end
    end
    return false
end

--- The interface's IPv4 addresses (`a/p` text), in the order reported.
function M.ipv4(i)
    local out = {}
    for _, a in ipairs((i and i.addresses) or {}) do
        if not a:find(":", 1, true) then out[#out + 1] = a end
    end
    return out
end

--- The interface's global IPv6 addresses (`a/p` text): every IPv6 one
--- that is not link-local.
function M.ipv6(i)
    local out = {}
    for _, a in ipairs((i and i.addresses) or {}) do
        if a:find(":", 1, true) and not a:match("^fe[89ab]") then out[#out + 1] = a end
    end
    return out
end

--- Pump the gateway until `pred(status)` holds for the machine's status
--- (or the interface `o.iface`'s, when `o.iface` is given as true or a
--- name). Returns the status that satisfied it, or nil on a timeout
--- (`o.timeout`, 60 s).
function M.serve_until(gw, vm, pred, o)
    o = o or {}
    local last
    local ok = gw:serve({ timeout = o.timeout or 60, until_ = function()
        local s = M.call(vm, { query = "status" })
        if not (s and s.ok) then return false end
        last = s
        local subject = s
        if o.iface then subject = M.iface(s, o.iface ~= true and o.iface or nil) end
        return subject ~= nil and pred(subject) and true or false
    end })
    if ok then return last end
    return nil, last
end

--- Predicate for `serve_until{iface=true}`: the interface holds a bound
--- DHCPv4 lease.
function M.bound(i) return i.lease ~= nil and i.lease.state == "bound" end

-- ---------------------------------------------------------------------------
-- The guest
-- ---------------------------------------------------------------------------

--- netd's log lines, newest first, as eventd holds them (`evctl LOGS FROM
--- netd`). `o.since` ("10m ago"), `o.take` (200). Each entry is the line
--- text, `netd: <level>: <message>`.
function M.logs(vm, o)
    o = o or {}
    local r = vm:run(string.format("evctl 'LOGS FROM netd SINCE %s TAKE %d'",
        o.since or "10m ago", o.take or 200))
    local out = {}
    for line in r.stdout:gmatch("[^\n]+") do
        local msg = line:match('message="(.-)"  origin=')
        if msg then out[#out + 1] = (msg:gsub('\\"', '"')) end
    end
    return out
end

--- Whether any netd log line contains `text` (plain).
function M.logged(vm, text, o)
    for _, l in ipairs(M.logs(vm, o)) do
        if l:find(text, 1, true) then return true end
    end
    return false
end

--- netd's process id, or nil.
function M.netd_pid(vm) return peinit.pid_of_comm(vm, "netd") end

--- Restart netd through peinit and wait for the new process's control
--- socket to answer. Returns the new pid.
function M.restart_netd(vm)
    local before = M.netd_pid(vm)
    vm:run("svctl restart netd"):assert_ok()
    wait_until(function()
        local now = M.netd_pid(vm)
        if not now or now == before then return false end
        local s = M.call(vm, { query = "status" })
        return s ~= nil and s.ok == true
    end, { timeout = 30, interval = 0.25, desc = "a new netd answering" })
    return M.netd_pid(vm)
end

--- The machine's network interfaces other than loopback, by kernel name.
function M.links(vm)
    local r = vm:run("ls /sys/class/net")
    r:assert_ok()
    local out = {}
    for name in r.stdout:gmatch("%S+") do
        if name ~= "lo" then out[#out + 1] = name end
    end
    table.sort(out)
    return out
end

--- Run `reg` with `args` (a list, each quoted) and return the result.
function M.reg(vm, args)
    local quoted = {}
    for _, a in ipairs(args) do quoted[#quoted + 1] = "'" .. a:gsub("'", "'\\''") .. "'" end
    return vm:run("REG_ASSUME_YES=1 reg " .. table.concat(quoted, " "))
end

--- Create `key` (relative to Machine\System\Network unless it starts with
--- `Machine\`) and set `values` on it: `{ ["Address.Offered"] = "dword:1",
--- Actions = "multi:JOIN(x)" }`, values in `reg`'s typed form.
function M.write(vm, key, values)
    if not key:match("^Machine\\") then key = M.KEY .. "\\" .. key end
    M.reg(vm, { "new", key })
    local names = {}
    for k in pairs(values or {}) do names[#names + 1] = k end
    table.sort(names)
    for _, k in ipairs(names) do
        M.reg(vm, { "set", key, k, values[k] }):assert_ok()
    end
    return key
end

--- Delete `key` and everything under it.
function M.delete(vm, key)
    if not key:match("^Machine\\") then key = M.KEY .. "\\" .. key end
    return M.reg(vm, { "del", key })
end

--- A registry value's text as `reg get` prints it, or nil when it is
--- absent.
function M.get(vm, key, name)
    if not key:match("^Machine\\") then key = M.KEY .. "\\" .. key end
    local r = M.reg(vm, { "get", key, name })
    if r.exit_code ~= 0 then return nil end
    return (r.stdout:gsub("%s+$", ""))
end

return M
