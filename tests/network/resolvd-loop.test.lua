-- resolvd §2.5 — the event loop: one thread in one poll, the poll
-- timeout, the order ready descriptors are serviced in, timers after
-- descriptors, local answers within the iteration, and replies written
-- blocking, with a one-second timeout on each write call.
--
-- Harness: the scripted gateway (helpers.gateway) with its DNS server
-- (helpers.dns), and a whole Peios (helpers.network) with resolvd under
-- peinit.
--
-- What the loop is doing is read from /proc/<pid>/syscall while it is
-- blocked: syscall 7 is poll(2), and the third argument is the timeout
-- in milliseconds it computed (-1 for none).
--
-- Order is shown by stopping resolvd (SIGSTOP), making several kinds of
-- descriptor ready at once, and resuming it (SIGCONT): one poll then
-- returns them all, and the order they are serviced in shows in what
-- reaches the gateway (each serviced question sends its upstream query
-- at once) and in the order of resolvd's log lines. That the inputs are
-- really pending at the moment of SIGCONT is checked first: the receive
-- queues of the sockets concerned (/proc/net/udp, `ss -x`).
--
-- The large replies for the blocking-write test are static names with
-- many addresses (`Dns\Hosts`), answered without the network.
--
-- Own VMs: resolvd is stopped and resumed, netd is stopped once, and the
-- tests write Dns registry values; each is removed.

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
local dhcp = gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600, dns = { "10.77.0.1" } })

local servfailed = {}
-- The image's time service asks for N.time.peios.org in the background;
-- answered here for an hour, so its questions are cache hits and never
-- leave a transaction pending in the middle of a measurement.
local zone = {
    ["www.loop.test"] = { { type = "A", ttl = 300, data = "10.77.0.80" } },
    ["x.loop.test"] = { { type = "A", ttl = 300, data = "10.77.0.81" } },
    ["u.loop.test"] = { { type = "A", ttl = 300, data = "10.77.0.82" } },
    ["t.loop.test"] = { { type = "A", ttl = 300, data = "10.77.0.83" } },
    ["n.loop.test"] = { { type = "A", ttl = 300, data = "10.77.0.84" } },
    ["late.loop.test"] = { { type = "A", ttl = 300, data = "10.77.0.85" } },
    ["delay.loop.test"] = { { type = "A", ttl = 300, data = "10.77.0.86" } },
    ["cached.loop.test"] = { { type = "A", ttl = 300, data = "10.77.0.87" } },
}
for n = 0, 3 do
    zone[n .. ".time.peios.org"] = { { type = "A", ttl = 3600, data = "10.77.0.123" },
                                     { type = "AAAA", ttl = 3600, data = "fd77::123" } }
end
dns.serve(gw, {
    zone = zone,
    soa = { name = "loop.test", data = { minimum = 30 } },
    on = function(q, default)
        local name = (q.questions[1] and q.questions[1].name or ""):lower()
        if name:match("^slow") then return false end
        if name == "x.loop.test" and not servfailed[name] then
            -- The first time: SERVFAIL, held a second (so it arrives while
            -- resolvd is stopped); the retry it causes gets the answer.
            servfailed[name] = true
            default.rcode = dns.RCODE.SERVFAIL
            default.answers = {}
            default.delay = 1
            return default
        end
        if name == "late.loop.test" then default.delay = 3; return default end
        if name == "delay.loop.test" then default.delay = 1; return default end
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

local function find(lines, text)
    for i, l in ipairs(lines) do if l:find(text, 1, true) then return i end end
end

--- The poll resolvd is blocked in: {nfds, timeout} (timeout -1 for
--- none), read from /proc/<pid>/syscall once it is in one.
local function blocked_poll(pid)
    local fields
    wait_until(function()
        local s = peinit.proc(sut, pid, "syscall") or ""
        fields = {}
        for w in s:gmatch("%S+") do fields[#fields + 1] = w end
        return fields[1] == "7"
    end, { timeout = 5, interval = 0.05, desc = "resolvd blocked in poll" })
    local timeout = fields[4] == "0xffffffffffffffff" and -1 or tonumber(fields[4]:sub(3), 16)
    return { nfds = tonumber(fields[3]:sub(3), 16), timeout = timeout, raw = table.concat(fields, " ") }
end

--- Pump the gateway until resolvd has nothing pending (its poll has no
--- timeout): background questions answered and cached.
local function quiesce(pid)
    local last
    local ok = gw:serve({ timeout = 30, until_ = function()
        last = blocked_poll(pid)
        return last.timeout == -1
    end })
    assert(ok, "resolvd never came to rest: " .. tostring(last and last.raw))
    return last
end

local function switches(pid)
    local st = peinit.proc(sut, pid, "status") or ""
    return tonumber(st:match("\nvoluntary_ctxt_switches:%s*(%d+)"))
end

local function native_open(req)
    local fd = assert(unixsock.socket(sut, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
    local c = unixsock.connect(sut, fd, SOCK)
    assert(c.ret == 0, "connect: " .. unixsock.errname(c.errno))
    if req then
        local p = msgpack.encode(req)
        ntfe.send(sut, fd, string.pack("<I4", #p) .. p)
    end
    return fd
end

local function native_frame(req)
    local p = msgpack.encode(req)
    return string.pack("<I4", #p) .. p
end

--- Pump the gateway until one whole native reply is read from `fd`.
local function native_reply(fd, timeout)
    local buf, reply = "", nil
    gw:serve({ timeout = timeout or 10, until_ = function()
        local chunk = ntfe.recv(sut, fd, 20, 65536)
        if chunk == "" then return true end
        if chunk then buf = buf .. chunk end
        if #buf >= 4 then
            local len = string.unpack("<I4", buf)
            if #buf >= 4 + len then reply = msgpack.decode(buf:sub(5, 4 + len)); return true end
        end
        return false
    end })
    return reply
end

local function dns_frame(name, qtype, id)
    local q = dns.encode(dns.query(name, qtype or "A", { id = id or 1 }))
    return string.pack(">I2", #q) .. q
end

--- Pump the gateway until a DNS reply is read from a stub socket.
local function stub_reply(fd, tcp, timeout)
    local got
    gw:serve({ timeout = timeout or 10, until_ = function()
        local chunk = ntfe.recv(sut, fd, 20, 65536)
        if chunk and #chunk > 0 then got = chunk; return true end
        return false
    end })
    if got and tcp then got = got:sub(3) end
    return got and dns.decode(got)
end

local function udp_ask(name, qtype)
    local fd = assert(ntfe.udp_connect(sut, "127.0.0.53", 53))
    ntfe.send(sut, fd, dns.encode(dns.query(name, qtype or "A", { id = 77 })))
    return fd
end

--- The milliseconds a stub UDP question for `name` takes to be answered.
local function udp_latency(name)
    local fd = assert(ntfe.udp_connect(sut, "127.0.0.53", 53))
    local t0 = guest_ns()
    ntfe.send(sut, fd, dns.encode(dns.query(name, "A", { id = 78 })))
    local got = ntfe.recv(sut, fd, 5000, 4096)
    local t1 = guest_ns()
    sys.close(sut, fd)
    assert(got, "no answer for " .. name)
    return (t1 - t0) / 1e6, dns.decode(got)
end

--- The first appearance of each of `names` in the gateway's query log,
--- in order.
local function query_order(names)
    local want, seen, out = {}, {}, {}
    for _, n in ipairs(names) do want[n] = true end
    for _, q in ipairs(dns.queries(gw)) do
        local n = q.msg and q.msg.questions[1] and q.msg.questions[1].name:lower()
        if n and want[n] and not seen[n] then seen[n] = true; out[#out + 1] = n end
    end
    return out
end

--- Receive-queue bytes on resolvd's UDP sockets: {stub, upstream}.
local function udp_queues(pid)
    local inodes = {}
    for _, target in pairs(peinit.fds(sut, pid)) do
        local ino = target:match("^socket:%[(%d+)%]$")
        if ino then inodes[ino] = true end
    end
    local stub, upstream = 0, 0
    for line in sut:read_file("/proc/net/udp"):gmatch("[^\n]+") do
        local f = {}
        for w in line:gmatch("%S+") do f[#f + 1] = w end
        if f[1] and f[1]:match("^%d+:$") and inodes[f[10]] then
            local rx = tonumber(f[5]:match(":(%x+)$"), 16)
            if f[2] == "3500007F:0035" then stub = stub + rx else upstream = upstream + rx end
        end
    end
    return stub, upstream
end

--- Bytes queued to resolvd on its netd channel (`ss -x`): the channel
--- is resolvd's one unix socket with no path.
local function netd_queue(pid)
    local mine = {}
    for _, target in pairs(peinit.fds(sut, pid)) do
        local ino = target:match("^socket:%[(%d+)%]$")
        if ino then mine[ino] = true end
    end
    local r = sut:run("ss -xn")
    for line in r.stdout:gmatch("[^\n]+") do
        local f = {}
        for w in line:gmatch("%S+") do f[#f + 1] = w end
        -- Netid State Recv-Q Send-Q Local Port Peer Port
        if f[1] == "u_str" and f[5] == "*" and mine[f[6]] then return tonumber(f[3]), line end
    end
    return nil, r.stdout
end

--- A nonblocking TCP connection to the stub door with a small receive
--- buffer, set before the handshake so the window is small too.
local function small_tcp()
    local sa, family = ntfe.sockaddr("127.0.0.53", 53)
    local fd = assert(ntfe.socket(sut, family, ntfe.SOCK_STREAM))
    ntfe.set_int_opt(sut, fd, 1, 8, 1) -- SO_RCVBUF: the kernel's minimum
    local r = sut:syscall(ntfe.NR.connect, { args = { fd, 0, #sa }, bufs = { sa }, ptrs = { 1 } })
    assert(r.ret == 0 or r.errno == sys.E.INPROGRESS, "connect: " .. sys.errname(r.errno or 0))
    assert(ntfe.poll(sut, fd, ntfe.POLLOUT, 2000) ~= 0, "connected")
    return fd
end

--- Write `Dns\Hosts\<name>` with `n` IPv6 addresses in one transaction.
local function many_addresses(name, n)
    local list = {}
    for i = 1, n do list[i] = string.format("fd99::%x:%x", i // 65536, i % 65536) end
    local doc = { keys = { { path = [[Machine\System\Network\Dns]] }, { path = [[Machine\System\Network\Dns\Hosts]],
        values = { { name = name, type = "multi", data = list } } } } }
    sut:write_file("/tmp/pt-hosts.json", json.encode(doc))
    network.reg(sut, { "apply", "/tmp/pt-hosts.json" }):assert_ok()
end

local function bound_and_routed(t)
    t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "eth0 bound")
    wait_until(function()
        local s = rcall({ query = "status" })
        return s and s.netd and s.scopes[1] and s.scopes[1].servers[1] == "10.77.0.1"
    end, { timeout = 30, interval = 0.25, desc = "eth0's server in resolvd" })
end

-- ---------------------------------------------------------------------------
-- One thread, one poll
-- ---------------------------------------------------------------------------

test("resolvd is one thread, and at rest it is blocked in poll(2) over its listeners, netd channel and watch",
    { spec = "resolvd *loop.single-thread-single-poll" }, function(t)
        bound_and_routed(t)
        local pid = rpid()
        local tasks = sut:listdir("/proc/" .. pid .. "/task")
        t:assert_eq(#tasks, 1, "one thread")
        local p = quiesce(pid)
        t:log("at rest: " .. p.raw)
        t:assert_eq(p.nfds, 5, "one poll over five descriptors: native, stub UDP, stub TCP, netd, watch")
        -- Busy with upstream questions, still one thread in one poll.
        local fds = {}
        for i = 1, 3 do fds[i] = native_open({ query = "resolve", name = "slow-" .. i .. ".loop.test", type = 1 }) end
        sut:run("sleep 0.3")
        local busy = blocked_poll(pid)
        t:log("with three upstream questions: " .. busy.raw)
        t:assert_eq(#sut:listdir("/proc/" .. pid .. "/task"), 1, "still one thread")
        t:assert_eq(busy.nfds, 8, "the same poll, now with the three upstream sockets")
        for _, fd in ipairs(fds) do sys.close(sut, fd) end
        sut:run("sleep 6.5")
    end)

-- ---------------------------------------------------------------------------
-- The poll timeout
-- ---------------------------------------------------------------------------

test("the poll timeout is the time to the earliest pending moment, and none at all when nothing is pending",
    { spec = "resolvd *loop.poll-timeout-is-earliest-deadline" }, function(t)
        bound_and_routed(t)
        local pid = rpid()
        -- Nothing pending: no timeout, and no wake-ups.
        local rest = quiesce(pid)
        t:assert_eq(rest.timeout, -1, "at rest the loop sleeps until a descriptor is ready")
        local s0 = switches(pid)
        sut:run("sleep 3")
        t:log("voluntary switches over 3 s at rest: " .. (switches(pid) - s0))

        -- An upstream transaction: its 2 s deadline.
        local q = native_open({ query = "resolve", name = "slow-a.loop.test", type = 1 })
        sut:run("sleep 0.2")
        local up = blocked_poll(pid)
        t:log("transaction pending: " .. up.raw)
        t:assert(up.timeout > 1000 and up.timeout <= 2000, "the transaction's deadline (" .. up.timeout .. " ms)")
        sys.close(sut, q)
        sut:run("sleep 6.5")

        -- A stub TCP connection still sending (10 s), then a native one
        -- (5 s): the earlier of the two.
        local tcp = assert(ntfe.tcp_connect(sut, "127.0.0.53", 53, 1000))
        ntfe.send(sut, tcp, "\0")
        sut:run("sleep 0.2")
        local one = blocked_poll(pid)
        t:log("stub TCP pending: " .. one.raw)
        t:assert(one.timeout > 9000 and one.timeout <= 10000, "the stub connection's 10 s bound (" .. one.timeout .. " ms)")
        local t0 = guest_ns()
        local nat = native_open(nil)
        ntfe.send(sut, nat, "\1\0")
        sut:run("sleep 0.2")
        local two = blocked_poll(pid)
        t:log("native pending too: " .. two.raw)
        t:assert(two.timeout > 4000 and two.timeout <= 5000, "the native connection's 5 s bound, the earlier (" .. two.timeout .. " ms)")
        local s1 = switches(pid)
        -- Nothing else happens until that moment: the native one is closed then.
        local eof = ntfe.recv(sut, nat, 8000, 16)
        local closed_after = (guest_ns() - t0) / 1e9
        t:log(string.format("native closed after %.2f s; voluntary switches meanwhile %d", closed_after, switches(pid) - s1))
        t:assert_eq(eof, "", "the native connection is closed")
        t:assert(closed_after >= 4.8 and closed_after <= 6.0, "at its 5 s bound")
        local three = blocked_poll(pid)
        t:log("stub TCP pending alone again: " .. three.raw)
        t:assert(three.timeout > 3500 and three.timeout <= 5000, "then the stub connection's remaining time (" .. three.timeout .. " ms)")
        t:assert_eq(ntfe.recv(sut, tcp, 8000, 16), "", "and it is closed at its 10 s bound")
        sys.close(sut, nat)
        sys.close(sut, tcp)

        -- netd unreachable: the next reconnection attempt.
        sut:run("svctl stop netd"):assert_ok()
        local ok, err = pcall(function()
            wait_until(function() return rcall({ query = "status" }).netd == false end,
                { timeout = 10, interval = 0.2, desc = "resolvd sees netd gone" })
            local nd = blocked_poll(pid)
            t:log("netd unreachable: " .. nd.raw)
            t:assert(nd.timeout >= 0 and nd.timeout <= 10000, "the next reconnection (" .. nd.timeout .. " ms)")
        end)
        sut:run("svctl start netd")
        bound_and_routed(t)
        if not ok then error(err, 0) end
    end)

-- ---------------------------------------------------------------------------
-- Service order
-- ---------------------------------------------------------------------------

test("ready descriptors are serviced upstream, stub UDP, stub TCP, native, netd, then the registry watch",
    { spec = "resolvd *loop.service-order" }, function(t)
        bound_and_routed(t)
        local pid = rpid()
        -- Connections accepted now, written to while resolvd is stopped.
        local tcp = assert(ntfe.tcp_connect(sut, "127.0.0.53", 53, 1000))
        local nat_q = native_open(nil)
        local nat_flush = native_open(nil)
        sut:run("sleep 0.3")
        -- x's first query is answered SERVFAIL a second late.
        local xfd = udp_ask("x.loop.test")
        t:assert(gw:serve({ timeout = 10, until_ = function() return #query_order({ "x.loop.test" }) == 1 end }),
            "x.loop.test's first query reached the server")
        peinit.signal(sut, pid, "STOP")
        local ok, err = pcall(function()
            -- netd: a renewed lease with a search domain, so a snapshot is sent.
            dhcp.options = { { 15, "order.test" } }
            t:assert(network.call(sut, { query = "renew", interface = "eth0" }).ok, "renew")
            local queued
            gw:serve({ timeout = 15, until_ = function() queued = netd_queue(pid); return (queued or 0) > 0 end })
            t:assert((queued or 0) > 0, "a snapshot waits on the netd channel (" .. tostring(queued) .. " bytes)")
            -- The other doors and the registry.
            local ufd = udp_ask("u.loop.test")
            ntfe.send(sut, tcp, dns_frame("t.loop.test"))
            ntfe.send(sut, nat_q, native_frame({ query = "resolve", name = "n.loop.test", type = 1 }))
            ntfe.send(sut, nat_flush, native_frame({ query = "flush" }))
            network.write(sut, "Dns", { ExtraSearchDomains = "multi:pt-order.test" })
            -- x's SERVFAIL, held by the gateway, is sent.
            gw:serve({ timeout = 5, until_ = function() return #(gw.dns_pending or {}) == 0 end })
            t:assert_eq(#(gw.dns_pending or {}), 0, "the gateway has sent x's held reply")
            local stub_q, up_q = udp_queues(pid)
            t:log(string.format("queued while stopped: stub UDP %d bytes, upstream %d bytes, netd %d bytes", stub_q, up_q, queued))
            t:assert(stub_q > 0, "a stub UDP query waits")
            t:assert(up_q > 0, "an upstream reply waits")
            local mark = guest_ns()
            dns.forget(gw)
            peinit.signal(sut, pid, "CONT")
            gw:serve({ timeout = 5, until_ = function()
                return #query_order({ "x.loop.test", "u.loop.test", "t.loop.test", "n.loop.test" }) == 4
            end })
            local order = query_order({ "x.loop.test", "u.loop.test", "t.loop.test", "n.loop.test" })
            t:log("upstream queries after SIGCONT, in order: " .. table.concat(order, ", "))
            t:assert_eq(table.concat(order, ","), "x.loop.test,u.loop.test,t.loop.test,n.loop.test",
                "the upstream reply (x's retry), then stub UDP, then stub TCP, then native")
            local lines = log_since(mark)
            t:log("log after SIGCONT:\n" .. table.concat(lines, "\n"))
            local i_flush, i_netd, i_conf = find(lines, "cache flushed"), find(lines, "resolvd: info: netd: "),
                find(lines, "configuration changed")
            t:assert(i_flush and i_netd and i_conf, "the flush, the snapshot and the change were all applied")
            t:assert(i_flush < i_netd, "native requests before the netd channel")
            t:assert(i_netd < i_conf, "the netd channel before the registry watch")
            -- Everyone is answered.
            t:assert(stub_reply(ufd, false), "u answered")
            t:assert(stub_reply(tcp, true), "t answered")
            t:assert(native_reply(nat_q), "n answered")
            sys.close(sut, ufd)
        end)
        peinit.signal(sut, pid, "CONT", { check = false })
        for _, fd in ipairs({ xfd, tcp, nat_q, nat_flush }) do sys.close(sut, fd) end
        network.reg(sut, { "del", "-r", [[Machine\System\Network\Dns]] })
        dhcp.options = {}
        if not ok then error(err, 0) end
    end)

-- ---------------------------------------------------------------------------
-- Timers after descriptors
-- ---------------------------------------------------------------------------

test("timers run after descriptors: what arrived before a deadline that has passed is still taken",
    { spec = "resolvd *loop.timers-run-after-descriptors" }, function(t)
        bound_and_routed(t)
        local pid = rpid()
        -- A native request and a stub TCP query, each half sent.
        local nat = native_open(nil)
        local full = native_frame({ query = "status" })
        ntfe.send(sut, nat, full:sub(1, 2))
        local tcp = assert(ntfe.tcp_connect(sut, "127.0.0.53", 53, 1000))
        local q = dns_frame("localhost", "A", 4321)
        ntfe.send(sut, tcp, q:sub(1, 1))
        -- An upstream question whose reply comes after its 2 s deadline.
        local lfd = udp_ask("late.loop.test")
        t:assert(gw:serve({ timeout = 10, until_ = function() return #query_order({ "late.loop.test" }) == 1 end }),
            "late.loop.test's query reached the server")
        peinit.signal(sut, pid, "STOP")
        local t0 = guest_ns()
        local ok, err = pcall(function()
            -- Past all three bounds: the reply (3 s), native (5 s), stub TCP (10 s).
            gw:serve({ timeout = 4, until_ = function() return select(2, udp_queues(pid)) > 0 end })
            t:assert(select(2, udp_queues(pid)) > 0, "the late reply waits on its socket")
            repeat sut:run("sleep 0.5") until (guest_ns() - t0) / 1e9 > 11
            ntfe.send(sut, nat, full:sub(3))
            ntfe.send(sut, tcp, q:sub(2))
            dns.forget(gw)
            t:log(string.format("stopped for %.1f s", (guest_ns() - t0) / 1e9))
            peinit.signal(sut, pid, "CONT")
            local s = native_reply(nat, 5)
            t:assert(s and s.ok and s.kind == "status", "the native request completed past its 5 s bound is answered")
            local a = stub_reply(tcp, true, 5)
            t:assert(a and a.id == 4321, "the stub TCP query completed past its 10 s bound is answered")
            local l = stub_reply(lfd, false, 5)
            t:assert(l and l.answers[1] and l.answers[1].data == "10.77.0.85",
                "the reply that arrived past its transaction's deadline is the answer")
            gw:serve({ timeout = 2 })
            t:assert_eq(#query_order({ "late.loop.test" }), 0, "and no retry was sent for it")
        end)
        peinit.signal(sut, pid, "CONT", { check = false })
        for _, fd in ipairs({ nat, tcp, lfd }) do sys.close(sut, fd) end
        if not ok then error(err, 0) end
    end)

-- ---------------------------------------------------------------------------
-- Answers within the iteration
-- ---------------------------------------------------------------------------

test("local answers are given at once, and a networked one as soon as its reply arrives",
    { spec = "resolvd *loop.local-answers-within-the-iteration" }, function(t)
        bound_and_routed(t)
        network.write(sut, "Dns", {})
        network.write(sut, [[Dns\Hosts]], { ["pt-static.loop.test"] = "multi:10.9.8.7" })
        wait_until(function()
            local r = rcall({ query = "resolve", name = "pt-static.loop.test", type = 1 })
            return r and r.outcome == "found"
        end, { timeout = 10, interval = 0.25, desc = "the static name in force" })
        local c = native_open({ query = "resolve", name = "cached.loop.test", type = 1 })
        t:assert(native_reply(c), "cached.loop.test answered and cached")
        sys.close(sut, c)
        -- A transaction outstanding, so the loop has a deadline 2 s off.
        local slow = native_open({ query = "resolve", name = "slow-b.loop.test", type = 1 })
        sut:run("sleep 0.2")
        local pid = rpid()
        t:assert(blocked_poll(pid).timeout > 1000, "a transaction is pending")
        for _, case in ipairs({ { "localhost", "synthetic" }, { "pt-static.loop.test", "static" }, { "cached.loop.test", "cached" } }) do
            local ms, reply = udp_latency(case[1])
            t:log(string.format("%s (%s): %.0f ms", case[1], case[2], ms))
            t:assert(reply.rcode == 0 and reply.answers[1] ~= nil, case[2] .. " answer given")
            t:assert(ms < 400, case[2] .. " answer given at once, not at the pending deadline")
        end
        sys.close(sut, slow)
        -- The networked question: its reply is held 1 s; the answer comes then.
        local t0 = guest_ns()
        local d = udp_ask("delay.loop.test")
        local a = stub_reply(d, false, 10)
        local took = (guest_ns() - t0) / 1e9
        sys.close(sut, d)
        t:log(string.format("delay.loop.test answered after %.2f s", took))
        t:assert(a and a.answers[1] and a.answers[1].data == "10.77.0.86", "answered from the server")
        t:assert(took >= 0.9 and took < 1.8, "when the reply arrived (1 s), not at a later deadline (2 s)")
        network.reg(sut, { "del", "-r", [[Machine\System\Network\Dns]] })
        sut:run("sleep 6")
    end)

-- ---------------------------------------------------------------------------
-- Blocking writes
-- ---------------------------------------------------------------------------

test("native and stub TCP replies are written blocking, a second per write call: a client that does not read holds the loop",
    { spec = "resolvd *loop.replies-written-blocking" }, function(t)
        -- PEI-1342: the blocking writes are the documented current
        -- behaviour; the stall is the defect filed against them. The stall
        -- is shown on the native door. On the stub TCP door it does not
        -- happen here: a DNS reply is at most 64 KB, and loopback TCP sizes
        -- the send buffer from its 64 KB MSS (well over that), so even the
        -- largest reply to a client that never reads fits and is written
        -- at once, which is the TRM's "a reply that fits" case. (With a
        -- small client MSS the send buffer is small and the stub TCP write
        -- stalls too; resolvd-servers-tcpstall.test.lua uses that.)
        bound_and_routed(t)
        many_addresses("ptbig", 1700)       -- a 58 KB DNS reply
        many_addresses("ptbignat", 6000)    -- a native reply far beyond a unix socket's buffer
        sut:run("sleep 1")
        local base = udp_latency("localhost")
        t:log(string.format("stub UDP localhost at rest: %.0f ms", base))
        t:assert(base < 300, "at rest a local answer is quick")

        -- A small reply to a client that does not read fits its buffers.
        local small = small_tcp()
        ntfe.send(sut, small, dns_frame("localhost", "AAAA", 5))
        local ms = udp_latency("localhost")
        t:log(string.format("after a small TCP reply nobody reads: %.0f ms", ms))
        t:assert(ms < 300, "a reply that fits is written at once")
        sys.close(sut, small)

        -- The largest stub TCP reply, to a client that does not read: it
        -- fits loopback's send buffer, so it too is written at once...
        local big = small_tcp()
        ntfe.send(sut, big, dns_frame("ptbig", "AAAA", 6))
        ms = udp_latency("localhost")
        t:log(string.format("during a 58 KB stub TCP reply nobody reads: %.0f ms", ms))
        t:assert(ms < 300, "a 58 KB stub TCP reply fits and is written at once")
        -- ...and whole: the client reads all of it afterwards.
        local got = ""
        repeat
            local chunk = ntfe.recv(sut, big, 1000, 65536)
            if chunk and #chunk > 0 then got = got .. chunk end
        until not chunk or chunk == "" or (#got >= 2 and #got >= 2 + string.unpack(">I2", got))
        local reply = #got >= 2 and dns.decode(got:sub(3)) or nil
        t:log(string.format("the client then read %d bytes, %d answers", #got, reply and #reply.answers or -1))
        t:assert(reply and #reply.answers == 1700, "the whole reply was in the buffers")
        sys.close(sut, big)

        -- A large native reply to a client that does not read.
        local mark = guest_ns()
        local nat = native_open({ query = "resolve", name = "ptbignat", type = 28 })
        ms = udp_latency("localhost")
        t:log(string.format("during a large native reply nobody reads: %.0f ms", ms))
        local after = udp_latency("localhost")
        sys.close(sut, nat)
        local lines = log_since(mark)
        t:log("log:\n" .. table.concat(lines, "\n"))
        network.reg(sut, { "del", "-r", [[Machine\System\Network\Dns]] })
        t:assert(after < 300, "the loop lets go afterwards (" .. math.floor(after) .. " ms)")
        t:assert(find(lines, "resolvd: warn: control: reply failed: ") ~= nil, "the abandoned native write is logged")
        -- The one-second timeout is per write call, and this reply takes
        -- two: the first fills the socket buffer, blocks its second and
        -- returns short; the second sends nothing and times out, which
        -- ends the write. A client that does not read holds the loop for
        -- about two seconds (2026 and 2084 ms measured).
        t:assert(ms > 1300, "for more than one call's second (" .. math.floor(ms) .. " ms)")
        t:assert(ms < 2700, "and for about two seconds: two calls (" .. math.floor(ms) .. " ms)")
    end)
