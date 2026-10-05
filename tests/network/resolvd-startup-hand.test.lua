-- resolvd §2.2 and §2.1 "Readiness" — the startup sequence, run by hand:
-- READY=1 and what is open when it is sent, readiness without netd, a
-- notify socket that cannot be reached, the fatal steps (the native
-- socket, the stub listener, poll), a signal leaving the socket behind,
-- the random generator's seed, and (§9.1) errors on a listening socket.
--
-- Harness: the scripted gateway (helpers.gateway) with its DNS server
-- (helpers.dns), and a whole Peios (helpers.network). peinit does not
-- show what a service sent it, and a service cannot be given a chosen
-- NOTIFY_SOCKET, resource limit or a failing step, so the resolvd
-- service is stopped for the whole file and the same binary is run from
-- the agent (as SYSTEM), as readiness-notify.test.lua does for netd. Its
-- standard error goes to a file in /tmp. The service is started again by
-- the last test.
--
-- The process limit is lowered with prlimit(2) from the agent on the
-- hand-run process, the agent's own child. (A probe setting and reading
-- the limit of the service's process in one call was refused, EACCES.)
--
-- The generator's seed: eight known bytes are bind-mounted over
-- /dev/urandom while the hand-run resolvd starts, and the DNS ids and
-- 0x20 case patterns of its first upstream queries are computed here
-- with the engine's xorshift64* (engine.rs `random`, `send`) and
-- compared. With an empty file there instead, the read fails and the
-- seed is the wall clock in nanoseconds: the window around the exec is
-- searched for the seed that produces the observed queries.
--
-- Own VMs: the resolvd service is stopped, netd is stopped once, files
-- are mounted over /dev/urandom, and a SYSTEM-owned socket is left at
-- /run/resolvd/resolv.sock between runs (the service cannot remove one;
-- the last test does before starting it).

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
        ["www.hand.test"] = { { type = "A", ttl = 300, data = "10.77.0.80" } },
        ["seed-a.hand.test"] = { { type = "A", ttl = 300, data = "10.77.0.81" } },
        ["seed-b.hand.test"] = { { type = "A", ttl = 300, data = "10.77.0.82" } },
        ["clock-a.hand.test"] = { { type = "A", ttl = 300, data = "10.77.0.83" } },
        ["clock-b.hand.test"] = { { type = "A", ttl = 300, data = "10.77.0.84" } },
    },
    soa = { name = "hand.test", data = { minimum = 30 } },
})
local sut = network.boot({ bridges = { lan }, gateway = gw })

local SOCK = "/run/resolvd/resolv.sock"
local ERR = "/tmp/pt-resolvd.err"
local NOTIFY = "/run/pt-resolvd-notify.sock"
local LISTENING = "resolvd: info: listening on /run/resolvd/resolv.sock and 127.0.0.53:53"

-- ---------------------------------------------------------------------------
-- Local instruments
-- ---------------------------------------------------------------------------

local function rcall(req, timeout_ms)
    return network.call(sut, req, { path = SOCK, timeout_ms = timeout_ms or 3000 })
end

local function exists(path)
    return (pcall(function() return sut:stat(path) end))
end

--- The hand-run resolvd's standard error so far, as lines.
local function stderr_lines()
    local ok, text = pcall(sut.read_file, sut, ERR)
    local out = {}
    if ok then for l in text:gmatch("[^\n]+") do out[#out + 1] = l end end
    return out
end

local function index_of(lines, text, plain_prefix)
    for i, l in ipairs(lines) do
        if (plain_prefix and l:sub(1, #text) == text) or l == text then return i end
    end
end

--- Start /usr/sbin/resolvd from the agent with `env` added to the
--- agent's environment, standard error to ERR. Unless `o.no_wait`, wait
--- until it answers on its socket or exits.
local function start(env, o)
    sut:run("rm -f " .. ERR)
    local pre = (o and o.pre) or ""
    local p = sut:run_async("sh", { args = { "-c", pre .. "exec /usr/sbin/resolvd 2>" .. ERR }, env = env or {} })
    if not (o and o.no_wait) then
        wait_until(function()
            return p:status() == "exited" or rcall({ query = "status" }, 300) ~= nil
        end, { timeout = 20, interval = 0.1, desc = "the hand-run resolvd answering or exiting" })
    end
    return p
end

local function finish(p)
    if p:status() ~= "exited" then p:kill("kill") end
    return p:wait(10)
end

--- Run `fn(p)` against a hand-run resolvd and always end the process.
local function with_resolvd(t, env, fn, o)
    local p = start(env, o)
    local ok, err = pcall(fn, p)
    local res = finish(p)
    local head = sut:run("head -n 25 " .. ERR .. "; echo \"($(wc -l < " .. ERR .. ") lines)\"").stdout
    t:log("stderr:\n" .. head)
    if not ok then error(err, 0) end
    return res
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

--- One stub UDP question; the decoded reply or nil.
local function stub_udp(name, qtype, wait_ms)
    local fd = assert(ntfe.udp_connect(sut, "127.0.0.53", 53))
    ntfe.send(sut, fd, dns.encode(dns.query(name, qtype or "A", { id = 4242 })))
    local got = ntfe.recv(sut, fd, wait_ms or 2000, 4096)
    sys.close(sut, fd)
    return got and dns.decode(got)
end

--- prlimit64(pid, RLIMIT_NOFILE, {soft, hard}, NULL).
local function set_nofile(pid, soft, hard)
    return sut:syscall(302, { args = { tonumber(pid), 7, 0, 0 },
        bufs = { string.pack("<I8I8", soft, hard or 4096) }, ptrs = { 2 } })
end

local function stop_service(name)
    sut:run("svctl stop " .. name):assert_ok()
    wait_until(function() return peinit.pid_of_comm(sut, name) == nil end,
        { timeout = 30, interval = 0.25, desc = name .. " stopped" })
end

-- ---------------------------------------------------------------------------
-- The generator (engine.rs: xorshift64*, two draws per transaction)
-- ---------------------------------------------------------------------------

local MUL = 0x2545F4914F6CDD1D

local function draw(x)
    x = x ~ (x >> 12)
    x = x ~ (x << 25)
    x = x ~ (x >> 27)
    return x, x * MUL
end

--- The (id, name) of the next `n` transactions from a generator in
--- state `x`, for the lowercase names `names[k]`.
local function predict(x, names)
    local out = {}
    for k, name in ipairs(names) do
        local id, bits
        x, id = draw(x)
        x, bits = draw(x)
        local used = 0
        local sent = name:gsub("%a", function(c)
            if used == 64 then x, bits = draw(x); used = 0 end
            local flip = bits & 1 == 1
            bits = bits >> 1
            used = used + 1
            return flip and c:upper() or c
        end)
        out[k] = { id = id & 0xFFFF, name = sent }
    end
    return out
end

--- Every UDP question the gateway has logged, oldest first, as
--- {id, name (as sent)}.
local function questions()
    local out = {}
    for _, q in ipairs(dns.queries(gw, function(e) return e.transport == "udp" end)) do
        if q.msg and q.msg.questions[1] then
            out[#out + 1] = { id = q.msg.id, name = q.msg.questions[1].name }
        end
    end
    return out
end

local function lower_names(qs)
    local out = {}
    for k, q in ipairs(qs) do out[k] = q.name:lower() end
    return out
end

-- ---------------------------------------------------------------------------
-- Readiness
-- ---------------------------------------------------------------------------

test("READY=1 comes once both doors are open and the registry has been read, after the listening line",
    { spec = "resolvd *service.ready-after-doors-open resolvd *startup.listening-log-line" }, function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "eth0 bound")
        stop_service("resolvd")
        network.write(sut, "Dns", {})
        network.write(sut, [[Dns\Hosts]], { ["pt-static.hand.test"] = "multi:10.9.8.7" })
        local nfd = assert(unixsock.socket(sut, unixsock.AF_UNIX, unixsock.SOCK.DGRAM))
        sut:run("rm -f " .. NOTIFY)
        t:assert_eq(unixsock.bind(sut, nfd, NOTIFY).ret, 0, "bound the notify socket")
        with_resolvd(t, { NOTIFY_SOCKET = NOTIFY }, function()
            local ready = ntfe.recv(sut, nfd, 15000, 512)
            t:assert_eq(ready, "READY=1", "READY=1 arrives")
            -- At that moment: the listening line is already written...
            local lines = stderr_lines()
            t:assert(index_of(lines, LISTENING) ~= nil, "the listening line was logged before READY=1")
            -- ...and every door answers, with the registry's names.
            local u = stub_udp("pt-static.hand.test", "A", 1000)
            t:assert(u and u.answers[1] and u.answers[1].data == "10.9.8.7",
                "the stub UDP socket answers a registry name at once")
            local tfd = ntfe.tcp_connect(sut, "127.0.0.53", 53, 1000)
            t:assert(tfd ~= nil, "the stub TCP listener accepts at once")
            if tfd then sys.close(sut, tfd) end
            local s = rcall({ query = "status" }, 1000)
            t:assert(s and s.ok, "the native socket answers at once")
            t:assert_eq(ntfe.recv(sut, nfd, 1500, 512), nil, "READY=1 is sent once")
            -- The listening line itself.
            local n = 0
            for _, l in ipairs(stderr_lines()) do if l:find("listening on", 1, true) then n = n + 1 end end
            t:assert_eq(n, 1, "one listening line, at info level, naming both doors")
            t:assert(index_of(lines, "resolvd: info: subscribed to netd") < index_of(lines, LISTENING),
                "after the first netd attempt")
        end)
        sys.close(sut, nfd)
    end)

test("without netd, the first attempt fails at once, READY=1 is still sent, and the doors answer before any snapshot",
    { spec = "resolvd *service.ready-does-not-wait-for-netd resolvd *startup.first-netd-attempt-immediate-and-not-fatal resolvd *startup.answers-before-first-snapshot" },
    function(t)
        stop_service("netd")
        local nfd = assert(unixsock.socket(sut, unixsock.AF_UNIX, unixsock.SOCK.DGRAM))
        sut:run("rm -f " .. NOTIFY)
        t:assert_eq(unixsock.bind(sut, nfd, NOTIFY).ret, 0, "bound the notify socket")
        local ok, err = pcall(with_resolvd, t, { NOTIFY_SOCKET = NOTIFY }, function()
            t:assert_eq(ntfe.recv(sut, nfd, 15000, 512), "READY=1", "READY=1 arrives with netd down")
            local lines = stderr_lines()
            local i_fail = index_of(lines, "resolvd: warn: netd not reachable (", true)
            local i_listen = index_of(lines, LISTENING)
            t:assert(i_fail ~= nil, "the failed attempt is logged")
            t:assert(lines[i_fail]:find("); retrying", 1, true) ~= nil, "as `netd not reachable (<error>); retrying`")
            t:assert(i_listen ~= nil and i_fail < i_listen, "and it was made before the listening line")
            local s = rcall({ query = "status" })
            t:log("status: " .. json.encode(s))
            t:assert_eq(s.netd, false, "not connected")
            t:assert_eq(#s.scopes, 0, "no scopes")
            -- Answered at once without a snapshot.
            local l = rcall({ query = "resolve", name = "localhost", type = 1 })
            t:assert(l and l.outcome == "found" and l.records[1].text == "127.0.0.1", "localhost is answered")
            local st = rcall({ query = "resolve", name = "pt-static.hand.test", type = 1 })
            t:assert(st and st.outcome == "found" and st.records[1].text == "10.9.8.7", "a static name is answered")
            dns.forget(gw)
            local w = rcall({ query = "resolve", name = "www.hand.test", type = 1 })
            t:log("www.hand.test before a snapshot: " .. json.encode(w))
            t:assert(w and w.outcome == "unavailable", "a name that needs a server is unavailable")
            t:assert_eq(#dns.queries(gw), 0, "and nothing was asked upstream")
            -- netd comes back: the retry finds it and the snapshot routes.
            sut:run("svctl start netd")
            local snap
            gw:serve({ timeout = 60, until_ = function()
                local x = rcall({ query = "status" }, 500)
                if x and x.netd and x.scopes[1] and x.scopes[1].servers[1] == "10.77.0.1" then snap = x; return true end
                return false
            end })
            t:assert(snap ~= nil, "the reconnection subscribes and a snapshot with eth0's server arrives")
            lines = stderr_lines()
            local i_sub = index_of(lines, "resolvd: info: subscribed to netd")
            t:assert(i_sub ~= nil and i_sub > i_listen, "subscribed to netd, by a retry after startup")
            local w2 = ask({ query = "resolve", name = "www.hand.test", type = 1 })
            t:assert(w2 and w2.outcome == "found", "and the name is answered once a scope has a server")
        end)
        sys.close(sut, nfd)
        if network.netd_pid(sut) == nil then sut:run("svctl start netd") end
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound again")
        if not ok then error(err, 0) end
    end)

test("a readiness notification that cannot be sent is logged and startup carries on; with no NOTIFY_SOCKET nothing is sent",
    { spec = "resolvd *service.notify-failure-not-fatal" }, function(t)
        with_resolvd(t, { NOTIFY_SOCKET = "/run/pt-no-such-notify.sock" }, function(p)
            local s = rcall({ query = "status" })
            t:assert(s and s.ok, "resolvd runs and answers")
            local lines = stderr_lines()
            t:assert(index_of(lines, "resolvd: warn: readiness notify: No such file or directory (os error 2)") ~= nil,
                "the failed send is logged as `readiness notify: <error>`")
            t:assert(index_of(lines, "resolvd: warn: readiness notify: ", true) > index_of(lines, LISTENING),
                "after the listening line")
            t:assert_eq(p:status(), "running", "and resolvd carries on")
        end)
        with_resolvd(t, {}, function(p)
            local env = peinit.proc(sut, p:pid(), "environ") or ""
            t:assert(env:find("NOTIFY_SOCKET", 1, true) == nil, "no NOTIFY_SOCKET in the environment")
            t:assert(rcall({ query = "status" }).ok, "resolvd runs and answers")
            t:assert_eq(index_of(stderr_lines(), "resolvd: warn: readiness notify: ", true), nil, "and logs nothing about readiness")
        end)
    end)

-- ---------------------------------------------------------------------------
-- Exiting
-- ---------------------------------------------------------------------------

test("resolvd installs no handler for the terminating signals: SIGTERM ends it and the socket file is left behind",
    { spec = "resolvd *startup.no-signal-handlers-socket-left-behind" }, function(t)
        local p = start({})
        local status = peinit.proc(sut, p:pid(), "status")
        local cgt = tonumber(status:match("SigCgt:%s*(%x+)"), 16)
        t:log(string.format("SigCgt %x", cgt))
        for name, n in pairs({ HUP = 1, INT = 2, QUIT = 3, USR1 = 10, USR2 = 12, TERM = 15 }) do
            t:assert_eq(cgt & (1 << (n - 1)), 0, "no handler for SIG" .. name)
        end
        p:kill("term")
        local res = p:wait(10)
        t:log("ended: status=" .. tostring(res.status) .. " signal=" .. tostring(res.signal) .. " code=" .. tostring(res.exit_code))
        t:assert_eq(res.signal, 15, "ended by SIGTERM's default disposition")
        local st = sut:stat(SOCK)
        t:assert_eq(st.entry_type, "socket", "/run/resolvd/resolv.sock is left behind")
        t:assert(rcall({ query = "status" }, 500) == nil, "with nothing listening on it")
    end)

test("a native socket that cannot be set up is fatal: logged at error level, exit status 1, nothing bound",
    { spec = "resolvd *startup.native-socket-failure-is-fatal" }, function(t)
        sut:run("rm -f " .. SOCK .. " && mkdir -p " .. SOCK .. "/pt-block"):assert_ok()
        local res = with_resolvd(t, {}, function(p)
            wait_until(function() return p:status() == "exited" end, { timeout = 10, interval = 0.1, desc = "resolvd to exit" })
        end)
        local lines = stderr_lines()
        sut:run("rm -rf " .. SOCK):assert_ok()
        t:log("exit " .. tostring(res.exit_code))
        t:assert_eq(res.exit_code, 1, "exit status 1")
        t:assert(index_of(lines, "resolvd: error: native socket: ", true) ~= nil, "`native socket: <error>` at error level")
        t:assert(lines[index_of(lines, "resolvd: error: native socket: ", true)]:find("Is a directory", 1, true) ~= nil,
            "naming the failure (a directory where the stale socket would be removed)")
        t:assert_eq(index_of(lines, LISTENING), nil, "it never reached the listening line")
        t:assert(sut:read_file("/proc/net/udp"):find("3500007F:0035", 1, true) == nil, "nothing holds 127.0.0.53:53/udp")
        -- (Connections from earlier tests may linger in TIME_WAIT; only a listener counts.)
        t:assert(sut:read_file("/proc/net/tcp"):find("3500007F:0035 00000000:0000 0A", 1, true) == nil,
            "nor listens on 127.0.0.53:53/tcp")
    end)

test("a stub listener that cannot bind is fatal, for the UDP socket and for the TCP listener",
    { spec = "resolvd *startup.stub-listener-failure-is-fatal" }, function(t)
        for _, which in ipairs({ "udp", "tcp" }) do
            local held = which == "udp" and ntfe.udp_bind(sut, "127.0.0.53", 53) or ntfe.tcp_listen(sut, "127.0.0.53", 53)
            t:assert(held ~= nil, "the agent holds 127.0.0.53:53/" .. which)
            local res = with_resolvd(t, {}, function(p)
                wait_until(function() return p:status() == "exited" end, { timeout = 10, interval = 0.1, desc = "resolvd to exit" })
            end)
            sys.close(sut, held)
            local lines = stderr_lines()
            t:assert_eq(res.exit_code, 1, which .. ": exit status 1")
            t:assert(index_of(lines, "resolvd: error: stub listener on 127.0.0.53:53: Address already in use (os error 98)") ~= nil,
                which .. ": `stub listener on 127.0.0.53:53: <error>` at error level")
            t:assert_eq(index_of(lines, LISTENING), nil, which .. ": it never reached the listening line")
            t:assert_eq(sut:stat(SOCK).entry_type, "socket", which .. ": the native socket (step 1) had been made first")
        end
    end)

test("a poll that fails with anything but EINTR is logged and resolvd exits with status 1",
    { spec = "resolvd *startup.poll-failure-exits" }, function(t)
        local res = with_resolvd(t, {}, function(p)
            -- poll(2) refuses a set larger than RLIMIT_NOFILE with EINVAL.
            local r = set_nofile(p:pid(), 2)
            t:assert_eq(r.ret, 0, "prlimit lowered the hand-run resolvd's descriptor limit: " .. sys.errname(r.errno or 0))
            -- Wake the loop so it polls again.
            stub_udp("localhost", "A", 500)
            wait_until(function() return p:status() == "exited" end, { timeout = 10, interval = 0.1, desc = "resolvd to exit" })
        end)
        t:assert_eq(res.exit_code, 1, "exit status 1")
        t:assert(index_of(stderr_lines(), "resolvd: error: poll: Invalid argument (os error 22)") ~= nil,
            "`poll: <error>` at error level")
    end)

-- ---------------------------------------------------------------------------
-- §9.1: an error on a listening socket
-- ---------------------------------------------------------------------------

test("an accept that fails is logged at warn and the loop goes on",
    { spec = "resolvd *failure-signals.listener-errors-logged-and-survived" }, function(t)
        -- Of the three lines, `stub udp: <error>` has no route: a read on
        -- an unconnected UDP socket fails only for memory exhaustion.
        -- The two accepts fail with EMFILE once the descriptor limit is
        -- the descriptors already open.
        with_resolvd(t, {}, function(p)
            local pid = p:pid()
            local top = 0
            for fd in pairs(peinit.fds(sut, pid)) do if fd > top then top = fd end end
            t:assert_eq(set_nofile(pid, top + 1, 4096).ret, 0, "descriptor limit set to the descriptors open")
            local nfd = assert(unixsock.socket(sut, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
            t:assert_eq(unixsock.connect(sut, nfd, SOCK).ret, 0, "a native connection waits in the backlog")
            local tfd = ntfe.tcp_connect(sut, "127.0.0.53", 53, 1000)
            t:assert(tfd ~= nil, "a stub TCP connection waits in the backlog")
            -- The loop goes on: a question that needs no descriptor is answered.
            local u = stub_udp("localhost", "A", 2000)
            t:assert(u and u.answers[1] and u.answers[1].data == "127.0.0.1", "the stub UDP door still answers")
            t:assert_eq(set_nofile(pid, 1024, 4096).ret, 0, "limit restored")
            local body = msgpack.encode({ query = "status" })
            ntfe.send(sut, nfd, string.pack("<I4", #body) .. body)
            local rep = ntfe.recv(sut, nfd, 3000, 65536)
            t:assert(rep and #rep > 4, "the native connection is accepted and answered once descriptors are available")
            sys.close(sut, nfd)
            if tfd then sys.close(sut, tfd) end
            t:assert_eq(p:status(), "running", "resolvd is still running")
            local native = sut:run("grep -m1 'native accept' " .. ERR).stdout:gsub("%s+$", "")
            local stub = sut:run("grep -m1 'stub tcp accept' " .. ERR).stdout:gsub("%s+$", "")
            local count = sut:run("grep -c 'accept: ' " .. ERR).stdout:gsub("%s+$", "")
            t:log("first native: " .. native .. "\nfirst stub: " .. stub .. "\naccept lines: " .. count
                .. " (PEI-1344: the listener stays readable, so the loop retries every pass)")
            t:assert_eq(native, "resolvd: warn: native accept: Too many open files (os error 24)", "`native accept: <error>` at warn")
            t:assert_eq(stub, "resolvd: warn: stub tcp accept: Too many open files (os error 24)", "`stub tcp accept: <error>` at warn")
        end)
    end)

-- ---------------------------------------------------------------------------
-- The generator
-- ---------------------------------------------------------------------------

test("the generator is seeded from eight bytes of /dev/urandom, or from the wall clock in nanoseconds when it cannot be read",
    { spec = "resolvd *startup.generator-seeded-from-urandom" }, function(t)
        local SEED = "\x11\x22\x33\x44\x55\x66\x77\x88"
        sut:write_file("/tmp/pt-seed", SEED)
        sut:write_file("/tmp/pt-empty", "")
        t:assert(network.serve_until(gw, sut, function(i) return network.bound(i) end, { iface = true, timeout = 60 }), "bound")

        -- urandom: the seed is those eight bytes, little-endian.
        dns.forget(gw)
        sut:run("mount --bind /tmp/pt-seed /dev/urandom"):assert_ok()
        local ok, err = pcall(with_resolvd, t, {}, function()
            sut:run("umount /dev/urandom"):assert_ok()
            t:assert(ask({ query = "resolve", name = "seed-a.hand.test", type = 1 }).outcome == "found", "seed-a answered")
            t:assert(ask({ query = "resolve", name = "seed-b.hand.test", type = 1 }).outcome == "found", "seed-b answered")
        end)
        sut:run("umount /dev/urandom 2>/dev/null; true")
        if not ok then error(err, 0) end
        local seen = questions()
        local want = predict(string.unpack("<I8", SEED) | 1, lower_names(seen))
        for k, q in ipairs(seen) do
            t:log(string.format("query %d: id %d name %s; predicted id %d name %s", k, q.id, q.name, want[k].id, want[k].name))
        end
        t:assert(#seen >= 2, "two or more queries were sent")
        for k = 1, #seen do
            t:assert_eq(seen[k].id, want[k].id, "query " .. k .. "'s id is the seeded generator's")
            t:assert_eq(seen[k].name, want[k].name, "query " .. k .. "'s 0x20 pattern is the seeded generator's")
        end

        -- No urandom: the seed is the time of the read, in ns.
        dns.forget(gw)
        sut:run("mount --bind /tmp/pt-empty /dev/urandom"):assert_ok()
        ok, err = pcall(with_resolvd, t, {}, function()
            sut:run("umount /dev/urandom"):assert_ok()
            t:assert(ask({ query = "resolve", name = "clock-a.hand.test", type = 1 }).outcome == "found", "clock-a answered")
            t:assert(ask({ query = "resolve", name = "clock-b.hand.test", type = 1 }).outcome == "found", "clock-b answered")
        end, { pre = "date +%s%N > /tmp/pt-t0; " })
        sut:run("umount /dev/urandom 2>/dev/null; true")
        if not ok then error(err, 0) end
        seen = questions()
        t:assert(#seen >= 2, "two or more queries were sent")
        local names = lower_names(seen)
        local t0 = assert(tonumber(sut:read_file("/tmp/pt-t0"):match("%d+")), "exec time")
        t:assert(predict(string.unpack("<I8", SEED) | 1, names)[1].id ~= seen[1].id or
            predict(string.unpack("<I8", SEED) | 1, names)[1].name ~= seen[1].name, "not the old seed")
        -- Search the 300 ms after the exec (the read is step 5 of startup).
        local found, candidates = {}, 0
        local id1 = seen[1].id
        for s = t0, t0 + 300000000 do
            local x = s | 1
            local _, out = draw(x)
            if out & 0xFFFF == id1 then
                candidates = candidates + 1
                local p = predict(x, names)
                local all = true
                for k = 1, #seen do
                    if p[k].id ~= seen[k].id or p[k].name ~= seen[k].name then all = false; break end
                end
                if all then found[#found + 1] = s end
            end
        end
        t:log(string.format("exec at %d ns; %d candidate seeds by the first id; matches: %s", t0, candidates,
            table.concat((function() local o = {} for _, s in ipairs(found) do o[#o + 1] = tostring(s) .. " (+" .. (s - t0) .. " ns)" end return o end)(), ", ")))
        t:assert(#found >= 1, "a wall-clock seed shortly after the exec produces every query's id and 0x20 pattern")
        t:assert(found[1] - t0 < 300000000, "within the startup window")
    end)

-- ---------------------------------------------------------------------------
-- Put the service back
-- ---------------------------------------------------------------------------

test("the resolvd service starts again once the hand-run socket is gone", {}, function(t)
    sut:run("rm -rf " .. SOCK .. " " .. NOTIFY .. " /tmp/pt-seed /tmp/pt-empty"):assert_ok()
    network.reg(sut, { "del", "-r", [[Machine\System\Network\Dns]] })
    sut:run("svctl reset resolvd")
    sut:run("svctl start resolvd")
    wait_until(function()
        local s = rcall({ query = "status" }, 500)
        return s ~= nil and s.ok == true and peinit.pid_of_comm(sut, "resolvd") ~= nil
    end, { timeout = 30, interval = 0.25, desc = "the service answering" })
    t:assert(rcall({ query = "status" }).ok, "the service answers")
end)
