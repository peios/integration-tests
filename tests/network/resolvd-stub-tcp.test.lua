-- resolvd TRM §6.1 — the stub listener's TCP side: the 256-connection
-- cap, the loopback-only source rule, the buffer ceiling, one query per
-- connection, a half-close behind the query, the ten-second delivery
-- bound and its end once the query has arrived; and, from §6.2, that a
-- failed TCP reply write is not logged. UDP and the query checks are
-- resolvd-stub-receive.test.lua.
--
-- Harness: the scripted gateway (helpers.gateway) leases 10.77.0.50 and
-- is the DNS server (helpers.dns), its `on` hook silencing or delaying
-- chosen names. The agent is the stub client, on raw sockets to
-- 127.0.0.53:53 in the guest.
--
-- Two claims are about bytes already waiting when resolvd reads: the
-- buffer ceiling (more than 65 537 bytes in one read pass) and the
-- half-close (the end of file behind the query). A writer racing a
-- one-vCPU event loop cannot place them reliably, so those tests stop
-- resolvd (SIGSTOP), connect — the kernel completes the handshake in the
-- listen backlog — write everything, and let resolvd go (SIGCONT): its
-- first read pass then finds it all.
--
-- The cap test opens 256 connections with bare socket+connect (two
-- syscalls each: the ten-second bound runs from each accept, so the cap
-- must be reached and probed well inside it), checks them all with one
-- poll(2), and counts resolvd's descriptors to see what it accepted.
--
-- Own VMs: the tests hold many connections and stop resolvd briefly.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")

peinit.claim(2)

local slow_silenced = 0
local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
dns.serve(gw, {
    zone = {
        ["first.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.91" } },
        ["second.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.92" } },
        ["halfclose.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.93" } },
        ["halfopen.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.94" } },
        ["slow.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.95" } },
        ["late.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.96" } },
    },
    soa = { name = "example.test", data = { minimum = 30 } },
    on = function(q, default, ctx)
        local n = (q.questions[1] and q.questions[1].name or ""):lower()
        if n == "slow.example.test" and ctx.transport == "udp" and slow_silenced == 0 then
            slow_silenced = slow_silenced + 1
            return false
        elseif (n == "halfopen.example.test" or n == "late.example.test") and ctx.transport == "udp" then
            default.delay = 1.5
            return default
        end
    end,
})
local sut = network.boot({ bridges = { lan }, gateway = gw })

local STUB = "127.0.0.53"
local SOCK = "/run/resolvd/resolv.sock"
local LEASED = "10.77.0.50"
local POLLRDHUP = 0x2000

-- ---- helpers -----------------------------------------------------------

local function hex(s)
    return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local function clock() return sut:clock():get() end

local function rstatus()
    local s, err = network.call(sut, { query = "status" }, { path = SOCK })
    assert(s and s.ok, "resolvd status: " .. tostring(err or (s and s.error)))
    return s
end

local is_ready = false
local function ready(t)
    if is_ready then return end
    t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }),
        "netd bound a lease")
    t:assert(gw:serve({ timeout = 30, until_ = function()
        for _, sc in ipairs(rstatus().scopes or {}) do
            for _, s in ipairs(sc.servers or {}) do
                if s == "10.77.0.1" then return true end
            end
        end
        return false
    end }), "resolvd has 10.77.0.1 as a scope's server")
    is_ready = true
end

local function resolvd_pid() return assert(peinit.pid_of_comm(sut, "resolvd"), "resolvd is running") end

--- How many descriptors resolvd holds.
local function resolvd_fds(pid)
    local n = 0
    for _ in pairs(peinit.fds(sut, pid)) do n = n + 1 end
    return n
end

local function frame(msg) return string.pack(">I2", #msg) .. msg end

local function query(name, id, qtype)
    return dns.encode({ id = id, rd = true, questions = { { name = name, type = qtype or "A" } } })
end

local function connect(o)
    return assert(ntfe.tcp_connect(sut, STUB, 53, 3000, o))
end

--- Read from a TCP stub connection while the gateway pumps, until a
--- whole reply has arrived or the connection ends. Returns
--- { reply = decoded or nil, raw, bytes = all bytes read, closed = how
--- it ended ("eof", an errno name, or nil while still open), at = clock
--- when it settled }.
local function read_reply(fd, timeout)
    local buf, closed = "", nil
    local function whole() return #buf >= 2 and #buf >= 2 + string.unpack(">I2", buf) end
    gw:serve({ timeout = timeout or 10, until_ = function()
        local c, err = ntfe.recv(sut, fd, 20, 65536)
        if c and #c > 0 then buf = buf .. c
        elseif c then closed = "eof"
        elseif err ~= "timeout" then closed = sys.errname(err) end
        return whole() or closed ~= nil
    end })
    local out = { bytes = buf, closed = closed, at = clock() }
    if whole() then
        out.raw = buf:sub(3, 2 + string.unpack(">I2", buf))
        out.reply = dns.decode(out.raw)
    end
    return out
end

local function asked(name)
    return dns.queries(gw, function(e)
        return e.msg and e.msg.questions[1] and dns.same_name(e.msg.questions[1].name, name)
    end)
end

--- poll(2) over many descriptors at once; the revents of each.
local function poll_all(fds, events, timeout_ms)
    local b = {}
    for _, fd in ipairs(fds) do b[#b + 1] = string.pack("<i4i2i2", fd, events, 0) end
    local r = sut:syscall(sys.NR.poll, { args = { 0, #fds, timeout_ms or 0 }, bufs = { table.concat(b) }, ptrs = { 0 } })
    local out = {}
    for i = 1, #fds do out[i] = select(3, string.unpack("<i4I2I2", r.out_bufs[1], (i - 1) * 8 + 1)) end
    return out
end

--- A nonblocking TCP socket connecting to the stub door: socket and
--- connect only.
local function open_raw()
    local r = sut:syscall(ntfe.NR.socket, ntfe.AF_INET, ntfe.SOCK_STREAM | ntfe.SOCK_NONBLOCK, 0)
    assert(r.ret >= 0, "socket: " .. sys.errname(r.errno))
    local sa = ntfe.sockaddr(STUB, 53)
    local c = sut:syscall(ntfe.NR.connect, { args = { r.ret, 0, #sa }, bufs = { sa }, ptrs = { 1 } })
    assert(c.ret == 0 or c.errno == sys.E.INPROGRESS, "connect: " .. sys.errname(c.errno))
    return r.ret
end

--- Write all of `data` on a nonblocking socket, as far as the kernel
--- takes it now. Returns the bytes written.
local function send_some(fd, data)
    local off = 0
    while off < #data do
        local r = ntfe.send(sut, fd, data:sub(off + 1, off + 65536))
        if r.ret <= 0 then break end
        off = off + r.ret
    end
    return off
end

--- resolvd's log messages, newest first.
local function rlogs()
    local r = sut:run("evctl 'LOGS FROM resolvd SINCE 10m ago TAKE 1000'")
    local out = {}
    for line in r.stdout:gmatch("[^\n]+") do
        local msg = line:match('message="(.-)"  origin=')
        if msg then out[#out + 1] = (msg:gsub('\\"', '"')) end
    end
    return out
end

-- ---- the cap -----------------------------------------------------------

test("when 256 accepted stub connections are still sending, the next one is closed at once",
    { spec = "resolvd *stub-receive.tcp-pending-cap-256" }, function(t)
        ready(t)
        local pid = resolvd_pid()
        local base = resolvd_fds(pid)
        local t0 = clock()
        local held = {}
        for i = 1, 256 do held[i] = open_raw() end
        t:log(string.format("256 connects issued in %.2f s; resolvd held %d descriptors before", clock() - t0, base))
        local settled = false
        local dl = clock() + 6
        repeat
            local rev = poll_all(held, ntfe.POLLIN | ntfe.POLLOUT | POLLRDHUP, 0)
            local connected, ended = 0, 0
            for _, r in ipairs(rev) do
                if r & ntfe.POLLOUT ~= 0 then connected = connected + 1 end
                if r & (ntfe.POLLIN | POLLRDHUP | ntfe.POLLHUP) ~= 0 then ended = ended + 1 end
            end
            settled = connected == 256 and ended == 0 and resolvd_fds(pid) >= base + 256
            if not settled then
                t:log(string.format("+%.2f s: %d connected, %d ended, resolvd fds %d",
                    clock() - t0, connected, ended, resolvd_fds(pid)))
            end
        until settled or clock() > dl
        t:assert(settled, "all 256 are connected, none closed, and resolvd holds them")
        local held_fds = resolvd_fds(pid)
        t:log(string.format("+%.2f s: resolvd holds %d descriptors (%d more)", clock() - t0, held_fds, held_fds - base))

        local extra = open_raw()
        local data, err = ntfe.recv(sut, extra, 2000)
        t:log(string.format("+%.2f s: the 257th: %s", clock() - t0,
            data and ("read " .. #data .. " bytes") or tostring(err)))
        t:assert(data == "" or err == sys.E.CONNRESET, "the 257th connection is closed at once, with nothing written")
        t:assert_eq(resolvd_fds(pid), held_fds, "resolvd holds no more descriptors than before it")
        local rev = poll_all(held, ntfe.POLLIN | POLLRDHUP, 0)
        local ended = 0
        for _, r in ipairs(rev) do if r ~= 0 then ended = ended + 1 end end
        t:assert_eq(ended, 0, "the 256 are all still held")

        -- One leaves; the next is held, and its query is answered.
        sys.close(sut, held[1])
        table.remove(held, 1)
        gw:serve({ timeout = 1, until_ = function() return resolvd_fds(pid) < held_fds end })
        local again = open_raw()
        t:assert(ntfe.poll(sut, again, ntfe.POLLOUT, 2000) & ntfe.POLLOUT ~= 0, "a new connection connects")
        ntfe.send(sut, again, frame(query("localhost", 0x7101)))
        local r = read_reply(again, 3)
        t:assert(r.reply and r.reply.id == 0x7101, "with one place free, a new connection is held and answered")
        local elapsed = clock() - t0
        t:log(string.format("+%.2f s: all of it within the ten-second bound", elapsed))
        t:assert(elapsed < 9.5, "the cap was probed before the first connections' ten-second bound")
        sys.close(sut, again); sys.close(sut, extra)
        for _, fd in ipairs(held) do sys.close(sut, fd) end
    end)

test("a TCP connection from a non-loopback source is closed at once, without a reply",
    { spec = "resolvd *stub-receive.tcp-non-loopback-source-closed" }, function(t)
        ready(t)
        local fd = connect({ bind = { LEASED, 0 } })
        ntfe.send(sut, fd, frame(query("localhost", 0x7201)))
        local r = read_reply(fd, 3)
        sys.close(sut, fd)
        t:log("non-loopback: closed=" .. tostring(r.closed) .. ", " .. #r.bytes .. " bytes")
        t:assert(r.closed ~= nil, "the connection was closed")
        t:assert_eq(r.bytes, "", "without a byte of reply")

        local fd2 = connect()
        local d, err = ntfe.recv(sut, fd2, 1000)
        t:assert(d == nil and err == "timeout", "a loopback connection is held open")
        ntfe.send(sut, fd2, frame(query("localhost", 0x7202)))
        local r2 = read_reply(fd2, 3)
        sys.close(sut, fd2)
        t:assert(r2.reply and r2.reply.id == 0x7202, "and its query answered")
    end)

-- ---- reading a query -----------------------------------------------------

test("a connection with more than 65 537 bytes buffered is closed without a reply",
    { spec = "resolvd *stub-receive.tcp-buffer-ceiling" }, function(t)
        ready(t)
        -- Control: exactly one 65 535-byte message is read and checked
        -- (0xFF bytes do not decode: FORMERR).
        local body = string.rep("\255", 65535)
        local fd = connect()
        local data = string.pack(">I2", 0xFFFF) .. body
        local off = 0
        gw:serve({ timeout = 10, until_ = function()
            off = off + send_some(fd, data:sub(off + 1))
            return off == #data
        end })
        t:assert_eq(off, #data, "the 65 537-byte frame was written")
        local r = read_reply(fd, 5)
        sys.close(sut, fd)
        t:assert(r.raw, "a whole 65 535-byte message is answered (" .. tostring(r.closed) .. ")")
        t:log("65 537 bytes -> " .. hex(r.raw or ""))
        t:assert_eq(r.raw, string.pack(">I2I2I2I2I2I2", 0xFFFF, 0x8001, 0, 0, 0, 0), "FORMERR for it")

        -- Over the ceiling: the frame and 4 096 bytes more, all waiting
        -- when resolvd first reads.
        local pid = resolvd_pid()
        local more = data .. string.rep("\255", 4096)
        peinit.signal(sut, pid, "STOP")
        local fd2, queued
        local ok, err = pcall(function()
            fd2 = connect()
            queued = send_some(fd2, more)
        end)
        peinit.signal(sut, pid, "CONT")
        t:assert(ok, "connected and wrote while resolvd was stopped: " .. tostring(err))
        t:log(string.format("queued %d of %d bytes before resolvd ran", queued, #more))
        local rest = more:sub(queued + 1)
        while #rest > 0 do
            if ntfe.poll(sut, fd2, ntfe.POLLOUT, 1000) & ntfe.POLLOUT == 0 then break end
            local n = send_some(fd2, rest)
            if n == 0 then break end
            rest = rest:sub(n + 1)
        end
        local r2 = read_reply(fd2, 5)
        sys.close(sut, fd2)
        t:log("over the ceiling: closed=" .. tostring(r2.closed) .. ", " .. #r2.bytes .. " bytes")
        t:assert(r2.closed ~= nil, "the connection was closed")
        t:assert_eq(r2.bytes, "", "without a reply")
    end)

test("a connection carries one query: what follows the first message is ignored, and it closes after the answer",
    { spec = "resolvd *stub-receive.tcp-one-query-per-connection" }, function(t)
        ready(t)
        dns.forget(gw)
        local fd = connect()
        ntfe.send(sut, fd, frame(query("first.example.test", 0x7401)) .. frame(query("second.example.test", 0x7402)))
        local r = read_reply(fd, 10)
        t:assert(r.reply and r.reply.id == 0x7401, "the first query is answered")
        t:assert(r.reply.answers[1] and r.reply.answers[1].data == "10.77.0.91", "with its record")
        t:assert_eq(#r.bytes, 2 + #r.raw, "and nothing more arrived with it")
        local after = read_reply(fd, 3)
        sys.close(sut, fd)
        t:assert_eq(after.closed, "eof", "then the connection is closed")
        t:assert_eq(after.bytes, "", "with no second reply")
        gw:serve({ timeout = 2 })
        t:assert(#asked("first.example.test") >= 1, "the first name was asked upstream")
        t:assert_eq(#asked("second.example.test"), 0, "the second never was")
    end)

test("a query with the end of file already behind it gets no reply; one whose end of file comes later is answered",
    { spec = "resolvd *stub-receive.tcp-query-then-half-close-dropped" }, function(t)
        ready(t)
        dns.forget(gw)
        local pid = resolvd_pid()
        peinit.signal(sut, pid, "STOP")
        local fd, sh
        local ok, err = pcall(function()
            fd = connect()
            ntfe.send(sut, fd, frame(query("halfclose.example.test", 0x7501)))
            sh = sut:syscall(ntfe.NR.shutdown, fd, 1)   -- SHUT_WR
        end)
        peinit.signal(sut, pid, "CONT")
        t:assert(ok, "query and shutdown written while resolvd was stopped: " .. tostring(err))
        t:assert_eq(sh.ret, 0, "shutdown(SHUT_WR)")
        local r = read_reply(fd, 4)
        sys.close(sut, fd)
        t:log("query + EOF waiting: closed=" .. tostring(r.closed) .. ", " .. #r.bytes .. " bytes")
        t:assert_eq(r.closed, "eof", "the connection is closed")
        t:assert_eq(r.bytes, "", "without a reply")
        t:assert_eq(#asked("halfclose.example.test"), 0, "and the query was never checked or asked")

        -- The end of file after resolvd has read the query (its question
        -- has gone upstream; the answer is held 1.5 s).
        local fd2 = connect()
        ntfe.send(sut, fd2, frame(query("halfopen.example.test", 0x7502)))
        t:assert(gw:serve({ timeout = 10, until_ = function() return #asked("halfopen.example.test") > 0 end }),
            "resolvd read the query and asked upstream")
        local sh2 = sut:syscall(ntfe.NR.shutdown, fd2, 1)
        t:assert_eq(sh2.ret, 0, "then shutdown(SHUT_WR)")
        local r2 = read_reply(fd2, 8)
        sys.close(sut, fd2)
        t:assert(r2.reply and r2.reply.id == 0x7502, "the query is answered as usual")
        t:assert(r2.reply.answers[1] and r2.reply.answers[1].data == "10.77.0.94", "with its record")
    end)

test("a connection that has not delivered a whole message ten seconds after it was accepted is closed",
    { spec = "resolvd *stub-receive.tcp-ten-second-delivery-bound" }, function(t)
        ready(t)
        local fd = connect()
        local t0 = clock()
        ntfe.send(sut, fd, "\0")   -- one byte of a length
        local r = read_reply(fd, 15)
        sys.close(sut, fd)
        local took = r.at - t0
        t:log(string.format("closed=%s after %.2f s, %d bytes", tostring(r.closed), took, #r.bytes))
        t:assert(r.closed ~= nil, "the connection was closed")
        t:assert_eq(r.bytes, "", "without a reply")
        t:assert(took >= 9.5 and took <= 12, string.format("about ten seconds after it was made (%.2f s)", took))
    end)

test("once its query has arrived, a connection is held past ten seconds until the engine answers",
    { spec = "resolvd *stub-receive.tcp-bound-ends-once-query-arrives" }, function(t)
        ready(t)
        local fd = connect()
        local t0 = clock()
        gw:serve({ timeout = 12, until_ = function() return clock() - t0 >= 9 end })
        local d, err = ntfe.recv(sut, fd, 0)
        t:assert(d == nil and err == "timeout", "still open 9 s in")
        -- The first UDP attempt is not answered: the answer comes from the
        -- second, about two seconds later.
        ntfe.send(sut, fd, frame(query("slow.example.test", 0x7701)))
        local r = read_reply(fd, 10)
        sys.close(sut, fd)
        local took = r.at - t0
        t:log(string.format("answered after %.2f s (first attempt silenced: %d)", took, slow_silenced))
        t:assert(r.reply and r.reply.id == 0x7701, "the query is answered")
        t:assert(r.reply.answers[1] and r.reply.answers[1].data == "10.77.0.95", "with its record")
        t:assert(took > 10.2, string.format("more than ten seconds after the connection was made (%.2f s)", took))
    end)

-- ---- writing the reply -----------------------------------------------------

test("a TCP reply that cannot be written is not logged",
    { spec = "resolvd *stub-render.tcp-write-failure-not-logged" }, function(t)
        ready(t)
        dns.forget(gw)
        local pid = resolvd_pid()
        local before_logs = rlogs()
        t:assert(#before_logs > 0, "resolvd's log can be read (" .. #before_logs .. " lines)")
        local before = rstatus().counters
        local fd = connect()
        ntfe.send(sut, fd, frame(query("late.example.test", 0x7801)))
        t:assert(gw:serve({ timeout = 10, until_ = function() return #asked("late.example.test") > 0 end }),
            "resolvd asked upstream (the answer is held 1.5 s)")
        -- Reset the connection: SO_LINGER {on, 0} and close.
        local so = sut:syscall(ntfe.NR.setsockopt, { args = { fd, 1, 13, 0, 8 },
            bufs = { string.pack("<i4i4", 1, 0) }, ptrs = { 3 } })
        t:assert_eq(so.ret, 0, "SO_LINGER set")
        sys.close(sut, fd)
        t:assert(gw:serve({ timeout = 10, until_ = function()
            return rstatus().counters.upstream_answered > before.upstream_answered
        end }), "the answer arrived and was delivered to the reset connection")
        gw:serve({ timeout = 1 })
        local after_logs = rlogs()
        -- The lines new since before (newest first, so a prefix).
        local new = {}
        for i = 1, #after_logs - #before_logs do new[#new + 1] = after_logs[i] end
        t:log(#new .. " new resolvd log lines: " .. table.concat(new, " | "))
        for _, l in ipairs(new) do
            local low = l:lower()
            t:assert(not (low:find("stub") or low:find("tcp") or low:find("write") or low:find("pipe")
                or low:find("reset") or low:find("broken")), "no line about the failed write: " .. l)
        end
        t:assert_eq(resolvd_pid(), pid, "resolvd carried on")
        local probe = connect()
        ntfe.send(sut, probe, frame(query("late.example.test", 0x7802)))
        local r = read_reply(probe, 5)
        sys.close(sut, probe)
        t:assert(r.reply and r.reply.answers[1] and r.reply.answers[1].data == "10.77.0.96",
            "and the answer it could not deliver was cached and is served")
    end)
