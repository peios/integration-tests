-- resolvd §2.4 — the native socket and its directory (modes, the DACL
-- written on both, their owners, a stale socket), the stub listener's two
-- sockets and nothing else bound, and connections that no longer count
-- against the 256 once their request has been read. Also §9.1's
-- `could not build a descriptor` line.
--
-- Harness: the scripted gateway (helpers.gateway) with its DNS server
-- (helpers.dns), and a whole Peios (helpers.network). Descriptors are
-- read with kacs_get_sd (helpers.kacs) and parsed (helpers.access);
-- sockets from /proc/net and resolvd's /proc/<pid>/fd.
--
-- The tests that need the directory in a state peinit would not leave
-- it in (absent, or a different mode) run the binary by hand from the
-- agent with the service stopped, as resolvd-startup-hand.test.lua does,
-- and the service is started again afterwards.
--
-- The 256 tests hold 257 connections at once; the questions behind the
-- first 256 go to a server that never answers, so each is read and
-- waiting while the 257th arrives.
--
-- Own VMs: resolvd is stopped, run by hand and restarted, and its
-- runtime directory is removed and recreated.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")
local unixsock = require("helpers.unixsock")
local msgpack = require("helpers.msgpack")
local kacs = require("helpers.kacs")
local access = require("helpers.access")
local token = require("helpers.token")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600, dns = { "10.77.0.1" } })
dns.serve(gw, {
    zone = {
        ["www.sock.test"] = { { type = "A", ttl = 300, data = "10.77.0.80" } },
    },
    soa = { name = "sock.test", data = { minimum = 30 } },
    on = function(q)
        local name = q.questions[1] and q.questions[1].name or ""
        if name:lower():match("^slow") then return false end
    end,
})
local sut = network.boot({ bridges = { lan }, gateway = gw })

local SOCK = "/run/resolvd/resolv.sock"
local DIR = "/run/resolvd"
local SID = "S-1-5-80-3864064249-1823296737-2008945602-1354971773-2894779966"
local ERR = "/tmp/pt-resolvd.err"

-- ---------------------------------------------------------------------------
-- Local instruments
-- ---------------------------------------------------------------------------

local function rcall(req, timeout_ms)
    return network.call(sut, req, { path = SOCK, timeout_ms = timeout_ms or 3000 })
end

local function rpid() return peinit.pid_of_comm(sut, "resolvd") end

local function answering(old)
    wait_until(function()
        local p = rpid()
        if not p or p == old then return false end
        local s = rcall({ query = "status" }, 500)
        return s ~= nil and s.ok == true
    end, { timeout = 30, interval = 0.25, desc = "a resolvd answering" })
    return rpid()
end

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

--- The socket inodes resolvd holds, as a set.
local function socket_inodes(pid)
    local set = {}
    for _, target in pairs(peinit.fds(sut, pid)) do
        local ino = target:match("^socket:%[(%d+)%]$")
        if ino then set[ino] = true end
    end
    return set
end

--- Rows of /proc/net/<file> whose inode is in `inodes`: {local, state, inode}.
local function net_rows(file, inodes)
    local out = {}
    for line in sut:read_file("/proc/net/" .. file):gmatch("[^\n]+") do
        local fields = {}
        for w in line:gmatch("%S+") do fields[#fields + 1] = w end
        if fields[1] and fields[1]:match("^%d+:$") and inodes[fields[10]] then
            out[#out + 1] = { ["local"] = fields[2], state = fields[4], inode = fields[10] }
        end
    end
    return out
end

local function fd_of_inode(pid, ino)
    for fd, target in pairs(peinit.fds(sut, pid)) do
        if target == "socket:[" .. ino .. "]" then return fd end
    end
end

local function descriptor(path, info)
    local sd, errno = kacs.get_sd(sut, path, info)
    assert(sd, "kacs_get_sd " .. path .. ": " .. sys.errname(errno or 0))
    return access.parse_sd(sd)
end

local function stop_service()
    sut:run("svctl stop resolvd"):assert_ok()
    wait_until(function() return rpid() == nil end, { timeout = 30, interval = 0.25, desc = "resolvd stopped" })
end

--- Start the service; any socket left behind is removed first (the
--- service cannot, PEI-1373).
local function start_service()
    sut:run("rm -f " .. SOCK)
    sut:run("svctl reset resolvd")
    sut:run("svctl start resolvd")
    return answering(nil)
end

local function native_request(req)
    local fd = assert(unixsock.socket(sut, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
    local c = unixsock.connect(sut, fd, SOCK)
    assert(c.ret == 0, "connect: " .. unixsock.errname(c.errno))
    if req then
        local p = msgpack.encode(req)
        ntfe.send(sut, fd, string.pack("<I4", #p) .. p)
    end
    return fd
end

--- Read one whole native reply from `fd` within `ms`; nil and why.
local function native_reply(fd, ms)
    local buf = ""
    local deadline = os.time() + math.ceil(ms / 1000) + 1
    while os.time() <= deadline do
        local chunk, err = ntfe.recv(sut, fd, 200, 65536)
        if chunk == "" then return nil, "closed" end
        if chunk then buf = buf .. chunk elseif err ~= "timeout" then return nil, err end
        if #buf >= 4 then
            local len = string.unpack("<I4", buf)
            if #buf >= 4 + len then return msgpack.decode(buf:sub(5, 4 + len)) end
        end
    end
    return nil, "timeout"
end

-- ---------------------------------------------------------------------------
-- The stub listener's sockets
-- ---------------------------------------------------------------------------

test("the stub listener is a UDP socket and a TCP listener on 127.0.0.53:53, both nonblocking",
    { spec = "resolvd *sockets.stub-udp-and-tcp-on-127-0-0-53" }, function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "eth0 bound")
        local pid = rpid()
        local inodes = socket_inodes(pid)
        local udp = net_rows("udp", inodes)
        local tcp = net_rows("tcp", inodes)
        t:log("resolvd udp: " .. json.encode(udp) .. "\nresolvd tcp: " .. json.encode(tcp))
        local u, l
        for _, r in ipairs(udp) do if r["local"] == "3500007F:0035" then u = r end end
        for _, r in ipairs(tcp) do if r["local"] == "3500007F:0035" and r.state == "0A" then l = r end end
        t:assert(u ~= nil, "resolvd holds a UDP socket on 127.0.0.53:53")
        t:assert(l ~= nil, "and a listening TCP socket on 127.0.0.53:53")
        for what, row in pairs({ udp = u, tcp = l }) do
            if row then
                local fd = fd_of_inode(pid, row.inode)
                local flags = tonumber(peinit.proc(sut, pid, "fdinfo/" .. fd):match("flags:%s*(%d+)"), 8)
                t:log(string.format("%s: fd %d flags %o", what, fd, flags))
                t:assert(flags & 0x800 ~= 0, what .. " is O_NONBLOCK")
            end
        end
        -- Both answer.
        local fd = assert(ntfe.udp_connect(sut, "127.0.0.53", 53))
        ntfe.send(sut, fd, dns.encode(dns.query("localhost", "A", { id = 7 })))
        local got = ntfe.recv(sut, fd, 2000, 4096)
        sys.close(sut, fd)
        t:assert(got and dns.decode(got).id == 7, "UDP answers")
        local tfd = ntfe.tcp_connect(sut, "127.0.0.53", 53, 1000)
        t:assert(tfd ~= nil, "TCP accepts")
        if tfd then
            local q = dns.encode(dns.query("localhost", "A", { id = 8 }))
            ntfe.send(sut, tfd, string.pack(">I2", #q) .. q)
            local r = ntfe.recv(sut, tfd, 2000, 4096)
            sys.close(sut, tfd)
            t:assert(r and #r > 2 and dns.decode(r:sub(3)).id == 8, "TCP answers")
        end
    end)

test("nothing else is bound: not ::1, not the machine's addresses, not the wildcard",
    { spec = "resolvd *sockets.nothing-bound-on-other-addresses" }, function(t)
        local pid = rpid()
        local inodes = socket_inodes(pid)
        local rows, all = {}, {}
        for _, f in ipairs({ "udp", "tcp", "udp6", "tcp6" }) do
            for _, r in ipairs(net_rows(f, inodes)) do
                local row = f .. " " .. r["local"] .. " " .. r.state
                all[#all + 1] = row
                -- Port 53 anywhere, or any TCP listener: what a door would be.
                -- (A transaction's upstream socket is on an ephemeral port.)
                if r["local"]:match(":0035$") or (f:match("^tcp") and r.state == "0A") then rows[#rows + 1] = row end
            end
        end
        t:log("resolvd's inet sockets:\n" .. table.concat(all, "\n"))
        table.sort(rows)
        t:assert_eq(table.concat(rows, "|"), "tcp 3500007F:0035 0A|udp 3500007F:0035 07",
            "exactly the two stub sockets, both on 127.0.0.53")
        -- Nobody answers DNS anywhere else on the machine.
        for _, addr in ipairs({ "::1", "127.0.0.1", "10.77.0.50" }) do
            local c, err = ntfe.tcp_connect(sut, addr, 53, 1000)
            t:assert(c == nil, "TCP " .. addr .. ":53 is not listened on (" .. tostring(err) .. ")")
            if c then sys.close(sut, c) end
            local u = assert(ntfe.udp_connect(sut, addr, 53))
            ntfe.send(sut, u, dns.encode(dns.query("localhost", "A")))
            t:assert_eq(ntfe.recv(sut, u, 500, 4096), nil, "UDP " .. addr .. ":53 gets no answer")
            sys.close(sut, u)
        end
    end)

-- ---------------------------------------------------------------------------
-- The native socket and its directory
-- ---------------------------------------------------------------------------

test("the native socket's mode is 0666", { spec = "resolvd *sockets.socket-mode-0666" }, function(t)
    local st = sut:stat(SOCK)
    t:log("resolv.sock: " .. json.encode(st))
    t:assert_eq(st.entry_type, "socket", "a socket")
    t:assert_eq(st.perm, 438, "mode 0666")
end)

test("the directory and the socket carry the DACL SYSTEM:GENERIC_ALL, Everyone:GENERIC_READ|WRITE|EXECUTE",
    { spec = "resolvd *sockets.directory-and-socket-dacl" }, function(t)
        for _, path in ipairs({ DIR, SOCK }) do
            local d = descriptor(path, kacs.SI.DACL)
            local aces = d.dacl and d.dacl.aces or {}
            local text = {}
            for _, a in ipairs(aces) do
                text[#text + 1] = string.format("type %d flags %02x mask %08x %s", a.type, a.flags, a.mask, token.sid_string(a.sid))
            end
            t:log(path .. " DACL:\n" .. table.concat(text, "\n"))
            t:assert_eq(#aces, 2, path .. ": two entries")
            t:assert(aces[1] and aces[1].type == 0 and aces[1].mask == 0x10000000
                and token.sid_string(aces[1].sid) == "S-1-5-18", path .. ": SYSTEM is allowed GENERIC_ALL")
            t:assert(aces[2] and aces[2].type == 0 and aces[2].mask == 0xE0000000
                and token.sid_string(aces[2].sid) == "S-1-1-0", path .. ": Everyone is allowed GENERIC_READ|WRITE|EXECUTE")
        end
    end)

test("only the DACL is written: the directory and the socket stay owned by resolvd's account",
    { spec = "resolvd *sockets.owner-left-as-resolvd", tags = { "known-bug" } }, function(t)
        -- TRM-runtime-dir-owner-is-system: peinit creates /run/resolvd
        -- (RuntimeDirectories) before resolvd runs, so the directory is
        -- owned by SYSTEM (S-1-5-18); resolvd creates only the socket, which
        -- is owned by its service SID. resolvd leaves both owners as it
        -- found them, but they are not both its own.
        local sock = token.sid_string(descriptor(SOCK, kacs.SI.OWNER).owner)
        local dir = token.sid_string(descriptor(DIR, kacs.SI.OWNER).owner)
        t:log("owner of " .. SOCK .. ": " .. sock .. "\nowner of " .. DIR .. ": " .. dir)
        t:assert_eq(sock, SID, "the socket is owned by resolvd's service SID")
        t:assert_eq(dir, SID, "the directory is owned by resolvd's service SID")
    end)

test("a socket file left by a previous run is removed and the removal logged at warn",
    { spec = "resolvd *sockets.stale-socket-removed-and-logged", tags = { "known-bug" } }, function(t)
        -- PEI-1373: the service cannot remove the socket its previous run
        -- left. Startup step 1 fails with `native socket: Permission
        -- denied (os error 13)` and peinit's restart policy loops on it
        -- (backoff/process_crash) until somebody else removes the file;
        -- removing the socket alone (not the directory) is enough for the
        -- next start to succeed, so the step refused is the removal (the
        -- socket's own DACL, written by resolvd, grants nobody but SYSTEM
        -- DELETE). Every stop/start, `svctl restart` and crash of the
        -- service ends this way.
        stop_service()
        local st = sut:stat(SOCK)
        t:assert_eq(st.entry_type, "socket", "the stopped resolvd left its socket behind")
        local mark = guest_ns()
        sut:run("svctl start resolvd")
        local ok = pcall(wait_until, function()
            local s = rcall({ query = "status" }, 300)
            return s ~= nil and s.ok == true
        end, { timeout = 15, interval = 0.25, desc = "the service answering" })
        local lines = log_since(mark)
        local s = json.decode(sut:run("svctl --json status resolvd").stdout) or {}
        t:log("log:\n" .. table.concat(lines, "\n") .. "\nservice: " .. tostring(s.state) .. "/" .. tostring(s.cause))
        -- Put the service back before judging.
        if not ok then
            sut:run("svctl stop resolvd")
            start_service()
        end
        t:assert(ok, "the restarted service answers")
        t:assert_eq(lines[1], "resolvd: warn: removed a stale /run/resolvd/resolv.sock", "its first line is the removal, at warn")
    end)

test("a descriptor that cannot be written is logged at error and startup carries on",
    { spec = "resolvd *sockets.descriptor-failure-logged-not-fatal",
      skip = "no route: the write needs WRITE_DAC on the object, and so does the chmod resolvd makes on the same object " ..
          "just before it (FACS: chmod requires WRITE_DAC; a read-only mount refuses both with EROFS), and that chmod " ..
          "failing is fatal (§2.2 step 1); the directory and socket are on tmpfs, which always stores descriptors. " ..
          "resolvd has no unit test of protect() either (control.rs has no tests)" }, function(t) end)

test("a descriptor that cannot be built is logged as `could not build a descriptor: <error>`",
    { spec = "resolvd *failure-signals.descriptor-build-failure-line",
      skip = "no route: the descriptor is built from two well-known SIDs and constant masks (control.rs protect()), " ..
          "which AclBuilder and SdBuilder never refuse; no input reaches it. No unit test covers it" }, function(t) end)

-- ---------------------------------------------------------------------------
-- The 256
-- ---------------------------------------------------------------------------

test("a native or stub TCP connection whose request has been read no longer counts against the 256",
    { spec = "resolvd *sockets.answered-connections-not-counted" }, function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "eth0 bound")
        wait_until(function()
            local s = rcall({ query = "status" })
            return s and s.scopes[1] and s.scopes[1].servers[1] == "10.77.0.1"
        end, { timeout = 30, interval = 0.25, desc = "eth0's server in resolvd" })

        -- Control: 256 connections still sending fill the count, and the
        -- 257th is turned away.
        local held = {}
        for i = 1, 256 do held[i] = native_request(nil) end
        sut:run("sleep 0.3")
        local extra = native_request({ query = "status" })
        local r, why = native_reply(extra, 1500)
        t:log("257th with 256 still sending: " .. tostring(r and "a reply" or why))
        t:assert(r == nil, "with 256 connections still sending, a 257th is not served")
        sys.close(sut, extra)
        for _, fd in ipairs(held) do sys.close(sut, fd) end
        sut:run("sleep 0.5")

        -- Native: 256 complete requests, each waiting on a server that
        -- never answers; the 257th is served.
        held = {}
        for i = 1, 256 do held[i] = native_request({ query = "resolve", name = "slow-" .. i .. ".sock.test", type = 1 }) end
        sut:run("sleep 0.3")
        extra = native_request({ query = "status" })
        r, why = native_reply(extra, 2000)
        t:assert(r and r.ok, "with 256 requests read and waiting, a 257th connection is served (" .. tostring(why) .. ")")
        sys.close(sut, extra)
        local answered = 0
        for _, fd in ipairs(held) do
            if ntfe.recv(sut, fd, 0, 16) then answered = answered + 1 end
        end
        t:assert_eq(answered, 0, "and none of the 256 had been answered: they were all still waiting")
        for _, fd in ipairs(held) do sys.close(sut, fd) end
        -- Let those questions run out (three 2 s attempts).
        sut:run("sleep 7")

        -- Stub TCP: the same with DNS queries.
        held = {}
        for i = 1, 256 do
            local fd = assert(ntfe.tcp_connect(sut, "127.0.0.53", 53, 2000), "stub TCP connection " .. i)
            local q = dns.encode(dns.query("slow-tcp-" .. i .. ".sock.test", "A", { id = i }))
            ntfe.send(sut, fd, string.pack(">I2", #q) .. q)
            held[i] = fd
        end
        sut:run("sleep 0.3")
        local tfd = ntfe.tcp_connect(sut, "127.0.0.53", 53, 2000)
        t:assert(tfd ~= nil, "a 257th stub TCP connection is accepted")
        if tfd then
            local q = dns.encode(dns.query("localhost", "A", { id = 999 }))
            ntfe.send(sut, tfd, string.pack(">I2", #q) .. q)
            local rep = ntfe.recv(sut, tfd, 2000, 4096)
            t:assert(rep and #rep > 2 and dns.decode(rep:sub(3)).id == 999,
                "and its query answered while 256 read queries wait")
            sys.close(sut, tfd)
        end
        answered = 0
        for _, fd in ipairs(held) do
            if ntfe.recv(sut, fd, 0, 16) then answered = answered + 1 end
        end
        t:assert_eq(answered, 0, "none of the 256 had been answered")
        for _, fd in ipairs(held) do sys.close(sut, fd) end
        sut:run("sleep 7")
    end)

-- ---------------------------------------------------------------------------
-- The directory's mode, set by resolvd (hand-run: peinit is not involved)
-- ---------------------------------------------------------------------------

test("resolvd creates /run/resolvd when it is missing and sets its mode to 0755 either way",
    { spec = "resolvd *sockets.runtime-directory-mode-0755" }, function(t)
        local st = sut:stat(DIR)
        t:assert_eq(st.perm, 493, "the service's directory is 0755")
        stop_service()
        local function hand_run()
            local p = sut:run_async("sh", { args = { "-c", "exec /usr/sbin/resolvd 2>" .. ERR } })
            wait_until(function() return p:status() == "exited" or rcall({ query = "status" }, 300) ~= nil end,
                { timeout = 20, interval = 0.1, desc = "the hand-run resolvd" })
            return p
        end
        local ok, err = pcall(function()
            local c = sys.chmod(sut, DIR, tonumber("700", 8))
            t:assert_eq(c.ret, 0, "chmod 0700: " .. sys.errname(c.errno or 0))
            t:assert_eq(sut:stat(DIR).perm, 448, "directory set to 0700")
            local p = hand_run()
            local after = sut:stat(DIR).perm
            local sock = sut:stat(SOCK).perm
            p:kill("kill"); p:wait(10)
            t:assert_eq(after, 493, "an existing directory is set to 0755")
            t:assert_eq(sock, 438, "and the socket in it to 0666")

            sut:run("rm -rf " .. DIR):assert_ok()
            p = hand_run()
            local made = sut:stat(DIR)
            p:kill("kill"); p:wait(10)
            t:assert_eq(made.entry_type, "directory", "a missing directory is created")
            t:assert_eq(made.perm, 493, "with mode 0755")
        end)
        -- The hand-run (SYSTEM) socket cannot be removed by the service.
        sut:run("rm -f " .. SOCK)
        start_service()
        if not ok then error(err, 0) end
    end)
