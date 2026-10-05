-- PSPU §6.8 — the stub door as a door: DNS over UDP and TCP on
-- 127.0.0.53 port 53 and on nothing else, anonymous and outside the
-- control object, and bound through a port reservation shipped as a
-- registry seed rather than through any privilege. How queries are read
-- and replies rendered is resolvd TRM §6, in resolvd-stub-receive,
-- resolvd-stub-tcp and resolvd-stub-render.
--
-- Harness: the scripted gateway (helpers.gateway) leases 10.77.0.50, so
-- the machine has a routable address for the door not to listen on, and
-- is the DNS server (helpers.dns). The agent asks through the door as
-- SYSTEM, and as a minted ordinary principal (helpers.token).
--
-- Where resolvd listens is read twice: from the kernel's socket tables
-- (/proc/net/{udp,tcp,udp6,tcp6}, matched to resolvd's descriptors by
-- inode), and by asking every other local address on port 53.
--
-- The binding claim is shown with a minted token: one whose user is
-- resolvd's service SID and which holds no privilege at all can bind
-- port 53; an ordinary user cannot. That is the reservation, not a
-- privilege, doing the work.
--
-- Own VMs: the anonymity test rewrites ControlSecurity (and puts it
-- back).

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")
local token = require("helpers.token")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
dns.serve(gw, {
    zone = { ["www.example.test"] = { { type = "A", ttl = 300, data = "10.77.0.80" } } },
    soa = { name = "example.test", data = { minimum = 30 } },
})
local sut = network.boot({ bridges = { lan }, gateway = gw })

local STUB = "127.0.0.53"
local SOCK = "/run/resolvd/resolv.sock"
local LEASED = "10.77.0.50"
local SERVICE_SID = "S-1-5-80-3864064249-1823296737-2008945602-1354971773-2894779966"
local SERVICE_SID_BIN = token.sid(5, 80, 3864064249, 1823296737, 2008945602, 1354971773, 2894779966)

-- ---- helpers -----------------------------------------------------------

local function hex(s)
    return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local function native_status(who)
    return network.call(sut, { query = "status" }, { path = SOCK, who = who })
end

local is_ready = false
local function ready(t)
    if is_ready then return end
    t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }),
        "netd bound a lease")
    t:assert(gw:serve({ timeout = 30, until_ = function()
        local s = native_status()
        for _, sc in ipairs(s and s.scopes or {}) do
            for _, a in ipairs(sc.servers or {}) do
                if a == "10.77.0.1" then return true end
            end
        end
        return false
    end }), "resolvd has 10.77.0.1 as a scope's server")
    is_ready = true
end

local function query(name, id, qtype)
    return dns.encode({ id = id, rd = true, questions = { { name = name, type = qtype or "A" } } })
end

local function udp_ask(who, bytes, timeout)
    local fd = assert(ntfe.udp_connect(who, STUB, 53))
    ntfe.send(who, fd, bytes)
    local got, err
    if who == sut then
        gw:serve({ timeout = timeout or 10, until_ = function()
            got, err = ntfe.recv(sut, fd, 20, 65536)
            return got ~= nil
        end })
    else
        got, err = ntfe.recv(who, fd, (timeout or 3) * 1000, 65536)
    end
    sys.close(who, fd)
    return got and dns.decode(got), err
end

local function tcp_ask(bytes, timeout)
    local fd = assert(ntfe.tcp_connect(sut, STUB, 53, 2000))
    ntfe.send(sut, fd, string.pack(">I2", #bytes) .. bytes)
    local buf = ""
    gw:serve({ timeout = timeout or 10, until_ = function()
        local c = ntfe.recv(sut, fd, 20, 65536)
        if c then buf = buf .. c end
        return #buf >= 2 and #buf >= 2 + string.unpack(">I2", buf)
    end })
    sys.close(sut, fd)
    if #buf >= 2 and #buf >= 2 + string.unpack(">I2", buf) then
        return dns.decode(buf:sub(3, 2 + string.unpack(">I2", buf)))
    end
end

--- The kernel's sockets of one table: { local_addr, local_port, state, inode }.
--- Addresses are the table's hex (IPv4 `3500007F` is 127.0.0.53).
local function socket_table(name)
    local out = {}
    for line in sut:read_file("/proc/net/" .. name):gmatch("[^\n]+") do
        local f = {}
        for w in line:gmatch("%S+") do f[#f + 1] = w end
        local addr, port = (f[2] or ""):match("^(%x+):(%x+)$")
        if addr and f[1]:match("^%d+:$") then
            out[#out + 1] = { table = name, addr = addr, port = tonumber(port, 16), state = f[4], inode = f[10] }
        end
    end
    return out
end

local function hex_ip4(h)
    local n = tonumber(h, 16)
    return string.format("%d.%d.%d.%d", n & 0xFF, (n >> 8) & 0xFF, (n >> 16) & 0xFF, n >> 24)
end

-- ---- the door ------------------------------------------------------------

test("the door answers DNS over UDP and over TCP on 127.0.0.53 port 53",
    { spec = "PSPU *nri-stub.dns-over-udp-and-tcp" }, function(t)
        ready(t)
        local m = udp_ask(sut, query("www.example.test", 0x8101))
        t:assert(m and m.id == 0x8101 and m.qr, "a UDP query is answered")
        t:assert(m.answers[1] and m.answers[1].data == "10.77.0.80", "with the record")
        local m2 = tcp_ask(query("www.example.test", 0x8102))
        t:assert(m2 and m2.id == 0x8102 and m2.qr, "a TCP query is answered")
        t:assert(m2.answers[1] and m2.answers[1].data == "10.77.0.80", "with the record")
    end)

test("the door listens on 127.0.0.53 and on no other address: not ::1, not a routable one",
    { spec = "PSPU *nri-stub.listens-on-127-0-0-53-only" }, function(t)
        ready(t)
        local pid = assert(peinit.pid_of_comm(sut, "resolvd"), "resolvd is running")
        local mine = {}
        for _, target in pairs(peinit.fds(sut, pid)) do
            local ino = target:match("^socket:%[(%d+)%]$")
            if ino then mine[ino] = true end
        end
        local port53 = {}
        for _, name in ipairs({ "udp", "tcp", "udp6", "tcp6" }) do
            for _, s in ipairs(socket_table(name)) do
                if s.port == 53 then
                    port53[#port53 + 1] = s
                    t:log(string.format("%s %s:53 state %s inode %s%s", name,
                        #s.addr == 8 and hex_ip4(s.addr) or s.addr, s.state, s.inode,
                        mine[s.inode] and " (resolvd)" or ""))
                end
            end
        end
        -- Every socket with local port 53 is at 127.0.0.53: resolvd's two,
        -- plus the door's own accepted connections (the previous test's,
        -- in TIME_WAIT), which are not listeners.
        local seen = {}
        for _, s in ipairs(port53) do
            t:assert(s.table == "udp" or s.table == "tcp", "no IPv6 socket has local port 53: " .. s.table .. " " .. s.addr)
            t:assert_eq(hex_ip4(s.addr), STUB, s.table .. ": the only local address on port 53 is 127.0.0.53")
            if s.table == "udp" or s.state == "0A" then
                t:assert(mine[s.inode], s.table .. " 127.0.0.53:53 (state " .. s.state .. ") is resolvd's socket")
                seen[s.table] = (seen[s.table] or 0) + 1
            end
        end
        t:assert_eq(seen.udp, 1, "one UDP socket on 127.0.0.53:53")
        t:assert_eq(seen.tcp, 1, "one TCP listener, on 127.0.0.53:53")

        -- Nothing answers on port 53 at any other local address.
        for _, addr in ipairs({ "127.0.0.1", LEASED, "::1" }) do
            local fd, err = ntfe.tcp_connect(sut, addr, 53, 2000)
            t:log("tcp " .. addr .. ":53 -> " .. (fd and "connected" or tostring(err)))
            if fd then sys.close(sut, fd) end
            t:assert(not fd, "no TCP listener on " .. addr .. ":53")
            local u = ntfe.udp_connect(sut, addr, 53)
            if u then
                ntfe.send(sut, u, query("localhost", 0x8201))
                local got, uerr = ntfe.recv(sut, u, 1500, 4096)
                sys.close(sut, u)
                t:log("udp " .. addr .. ":53 -> " .. (got and "a reply" or tostring(uerr)))
                t:assert(not got, "no UDP reply from " .. addr .. ":53")
            end
        end
    end)

test("the door is anonymous: it answers everyone, whatever the control object says",
    { spec = "PSPU *nri-stub.anonymous-not-governed-by-control-object" }, function(t)
        ready(t)
        local key = network.KEY .. [[\Dns]]
        local s0 = native_status()
        t:assert(s0 and s0.ok, "the native socket answers SYSTEM to begin with")
        -- A control object that grants SYSTEM nothing.
        network.write(sut, "Dns", { ControlSecurity = "hex:" .. peinit.system_descriptor_hex(0) })
        local denied
        t:assert(gw:serve({ timeout = 15, until_ = function()
            denied = native_status()
            return denied and denied.ok == false
        end }), "resolvd took the new control object")
        t:log("native status as SYSTEM: ok=" .. tostring(denied.ok) .. " error=" .. tostring(denied.error))
        t:assert_eq(denied.error, "access denied", "the native socket now refuses SYSTEM")

        local ok, err = pcall(function()
            local m = udp_ask(sut, query("www.example.test", 0x8301))
            t:assert(m and m.id == 0x8301 and m.rcode == 0 and m.answers[1]
                and m.answers[1].data == "10.77.0.80", "the stub door still answers SYSTEM")
            local m2 = udp_ask(sut, query("localhost", 0x8302))
            t:assert(m2 and m2.answers[1] and m2.answers[1].data == "127.0.0.1", "local names too")
            token.as_principal(t, sut, {}, function(w)
                local nm = native_status(w)
                t:log("native status as an ordinary user: " .. tostring(nm and nm.error))
                t:assert(nm and nm.ok == false, "the native socket refuses an ordinary user as well")
                local m3 = udp_ask(w, query("www.example.test", 0x8303))
                t:assert(m3 and m3.id == 0x8303 and m3.rcode == 0 and m3.answers[1]
                    and m3.answers[1].data == "10.77.0.80", "the stub door answers an ordinary user")
                local m4 = udp_ask(w, query("localhost", 0x8304))
                t:assert(m4 and m4.answers[1] and m4.answers[1].data == "127.0.0.1", "local names too")
            end)
        end)
        network.reg(sut, { "del", key, "ControlSecurity" })
        t:assert(gw:serve({ timeout = 15, until_ = function()
            local s = native_status()
            return s and s.ok
        end }), "with ControlSecurity removed, SYSTEM is admitted again")
        if not ok then error(err, 0) end
    end)

-- ---- binding the port ------------------------------------------------------

test("resolvd's port reservation for tcp,udp:53 is a registry seed granting its service SID",
    { spec = "PSPU *nri-stub.port-reservation-seed" }, function(t)
        local key = [[Machine\System\Network\TcpIp\PortReservations]]
        local r = network.reg(sut, { "get", key, "tcp,udp:53" })
        t:log("reg get " .. key .. " tcp,udp:53 -> exit " .. tostring(r.exit_code) .. ": " .. r.stdout .. r.stderr)
        t:assert_eq(r.exit_code, 0, "the reservation value is in the registry")
        local h = r.stdout:gsub("^hex:", ""):gsub("[^%x]", "")
        local sd = h:gsub("%x%x", function(b) return string.char(tonumber(b, 16)) end)
        local p = token.parse_sd(sd)
        t:assert(p.dacl, "it is a descriptor with a DACL")
        local granted = {}
        for _, ace in ipairs(p.dacl) do
            if ace.sid then
                t:log(string.format("ACE type %d mask 0x%08X %s", ace.type, ace.mask, token.sid_string(ace.sid)))
                if ace.type == 0 then granted[token.sid_string(ace.sid)] = ace.mask end
            end
        end
        t:assert(granted[SERVICE_SID], "an allow ACE for resolvd's service SID")
        t:assert(granted["S-1-5-18"], "and one for SYSTEM")

        local pid = assert(peinit.pid_of_comm(sut, "resolvd"), "resolvd is running")
        local tok = peinit.token(sut, pid)
        local has = tok.principal.user == SERVICE_SID
        for _, g in ipairs(tok.groups) do
            if g.sid == SERVICE_SID and g.attrs:find("enabled", 1, true) then has = true end
        end
        t:log("resolvd runs as " .. tok.principal.user)
        t:assert(has, "resolvd's token carries that service SID")
    end)

test("binding the door needs no privilege: resolvd holds none, and its SID alone can bind port 53",
    { spec = "PSPU *nri-stub.binds-without-privilege" }, function(t)
        ready(t)
        local pid = assert(peinit.pid_of_comm(sut, "resolvd"), "resolvd is running")
        local tok = peinit.token(sut, pid)
        local names = {}
        for _, p in ipairs(tok.privileges) do
            names[#names + 1] = p.name .. " (" .. p.attrs .. ")"
            t:assert(p.name ~= "SeTcb", "resolvd's token does not hold SeTcbPrivilege")
        end
        t:log("resolvd's privileges: " .. (#names > 0 and table.concat(names, ", ") or "none"))
        -- Linux capabilities: KACS gives every process the same ALLOW set
        -- (0-7, 10, 11, 15, 28 = 0x10008cff) as DAC-neutralising substrate,
        -- not as a grant; a privilege-mapped capability would show beyond it.
        local function cap_eff(p)
            return tonumber((peinit.proc(sut, p, "status") or ""):match("CapEff:%s*(%x+)") or "", 16)
        end
        local caps = cap_eff(pid)
        t:log(string.format("resolvd CapEff 0x%x", caps or -1))
        t:assert_eq(caps, 0x10008cff, "resolvd holds only the ALLOW substrate every process holds")
        -- And it holds the door's sockets.
        local listening = 0
        local mine = {}
        for _, target in pairs(peinit.fds(sut, pid)) do
            local ino = target:match("^socket:%[(%d+)%]$")
            if ino then mine[ino] = true end
        end
        for _, name in ipairs({ "udp", "tcp" }) do
            for line in sut:read_file("/proc/net/" .. name):gmatch("[^\n]+") do
                local f = {}
                for w in line:gmatch("%S+") do f[#f + 1] = w end
                if f[2] == "3500007F:0035" and mine[f[10]] then listening = listening + 1 end
            end
        end
        t:assert_eq(listening, 2, "while holding both 127.0.0.53:53 sockets")

        -- A token with resolvd's service SID and no privilege binds port 53
        -- on another loopback address; an ordinary user's cannot.
        token.as_principal(t, sut, { user_sid = SERVICE_SID_BIN, privs_present = 0, privs_enabled = 0 }, function(w)
            local u, ue = ntfe.udp_bind(w, "127.0.0.77", 53)
            t:log("service SID, no privileges: udp bind 127.0.0.77:53 -> " .. (u and "ok" or sys.errname(ue)))
            t:assert(u, "the service SID binds UDP 127.0.0.77:53 with no privilege")
            if u then sys.close(w, u) end
            local l, le = ntfe.tcp_listen(w, "127.0.0.77", 53)
            t:log("service SID, no privileges: tcp listen 127.0.0.77:53 -> " .. (l and "ok" or sys.errname(le)))
            t:assert(l, "and TCP 127.0.0.77:53")
            if l then sys.close(w, l) end
        end)
        token.as_principal(t, sut, {}, function(w)
            local wcaps = cap_eff(w:syscall(sys.NR.getpid).ret)
            t:log(string.format("ordinary user's worker CapEff 0x%x", wcaps or -1))
            t:assert_eq(wcaps, caps, "an ordinary user holds the same Linux capabilities as resolvd")
            local u, ue = ntfe.udp_bind(w, "127.0.0.77", 53)
            t:log("ordinary user: udp bind 127.0.0.77:53 -> " .. (u and "ok" or sys.errname(ue)))
            if u then sys.close(w, u) end
            t:assert(not u, "an ordinary user cannot bind port 53: the reservation is what admits resolvd")
        end)
    end)
