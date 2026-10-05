-- PSPU §6.B "Limits": the mainline values resolvd uses for the native
-- channel's message ceiling, delivery bound and pending-connection cap,
-- the stub door's TCP client cap and delivery bound, the EDNS0 buffer it
-- advertises upstream, and the network-manager reconnect backoff. (The
-- per-server timeout, attempts, demotion period, TTL caps and cache size
-- are proven beside the resolvd behaviour they bound, in
-- resolvd-servers*, resolvd-cache* ; the in-flight ceiling in
-- resolvd-limits-inflight.)
--
-- Harness: the scripted gateway (helpers.gateway) and its DNS server
-- (helpers.dns) on the lease. The agent opens the native socket and the
-- stub door's TCP port itself, from inside the machine, as any local
-- client would; times are the machine's own clock (`sut:clock()`),
-- read around each step. The backoff test stops netd with `svctl` and
-- watches `status`'s `netd` flag, on the gateway's clock.
--
-- The backoff test comes last: it takes netd away twice.
--
-- Own VMs: hundreds of held connections, and netd stopped.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")
local unixsock = require("helpers.unixsock")
local msgpack = require("helpers.msgpack")

peinit.claim(2)

local SOCK = "/run/resolvd/resolv.sock"

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
dns.serve(gw, { zone = { ["www.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.80" } } } })
local sut = network.boot({ bridges = { lan }, gateway = gw })

local function rstatus()
    local s, err = network.call(sut, { query = "status" }, { path = SOCK })
    assert(s and s.ok ~= false, "resolvd status: " .. tostring(err or (s and s.error)))
    return s
end

local function now() return sut:clock():get() end

--- A connection to the native socket. Returns the fd.
local function native()
    local fd = assert(unixsock.socket(sut, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
    local r = unixsock.connect(sut, fd, SOCK)
    assert(r.ret == 0, "connect: " .. unixsock.errname(r.errno))
    return fd
end

--- Whether `fd` has been closed by the other end (EOF or reset waiting).
local function closed(fd, wait_ms)
    local ev = ntfe.poll(sut, fd, ntfe.POLLIN, wait_ms or 0)
    if ev == 0 then return false end
    local data, err = ntfe.recv(sut, fd, 0, 4096)
    return data == "" or (data == nil and err ~= "timeout"), data
end

local function read_reply(fd)
    local buf = ""
    while #buf < 4 or #buf < 4 + string.unpack("<I4", buf) do
        local chunk = ntfe.recv(sut, fd, 3000, 65536)
        if not chunk or #chunk == 0 then return nil, buf end
        buf = buf .. chunk
    end
    return msgpack.decode(buf:sub(5, 4 + string.unpack("<I4", buf)))
end

local function close_all(fds) for _, fd in ipairs(fds) do sys.close(sut, fd) end end

test("upstream queries advertise an EDNS0 buffer of 1 232 bytes",
    { spec = "PSPU *nri-limits.edns0-buffer" }, function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound a lease")
        local p = sut:run_async("sh", { args = { "-c", "resolv query www.example.test A" } })
        gw:serve({ timeout = 15, until_ = function() return p:status() == "exited" end })
        t:assert(p:wait(5).stdout:match("^found"), "answered")
        local q = dns.queries(gw, function(e)
            local m = e.msg
            return m and m.questions[1] and dns.same_name(m.questions[1].name, "www.example.test")
        end)
        t:assert(#q >= 1, "the question reached the server")
        t:assert(q[1].msg.edns ~= nil, "with an OPT record")
        t:assert_eq(q[1].msg.edns.udp_size, 1232, "advertising 1 232 bytes")
    end)

test("the native channel's message ceiling is 65 536 bytes",
    { spec = "PSPU *nri-limits.native-message-ceiling" }, function(t)
        -- A request of exactly 65 536 bytes: status, padded by an unknown key.
        local req = { query = "status", pad = "" }
        local n = 65536 - #msgpack.encode({ query = "status", pad = string.rep("x", 1000) }) + 1000
        req.pad = string.rep("x", n)
        local payload = msgpack.encode(req)
        t:assert_eq(#payload, 65536, "the padded request is 65 536 bytes")
        local r, err = network.call(sut, payload, { path = SOCK })
        t:assert(r and r.ok == true and r.cache_entries ~= nil, "a 65 536-byte request is answered: " .. tostring(err))
        -- A length of 65 537 is refused.
        r, err = network.call(sut, msgpack.encode({ query = "status" }), { path = SOCK, length = 65537 })
        t:assert(r ~= nil, "a reply came: " .. tostring(err))
        t:assert_eq(r.ok, false, "refused")
        t:assert_eq(r.error, "request too large", "as too large")
    end)

test("the native channel holds 256 connections still delivering a request, and closes each one 5 s after it was accepted",
    { spec = "PSPU *nri-limits.native-pending-connections PSPU *nri-limits.native-request-delivery-bound" },
    function(t)
        local fds = {}
        local t0 = now()
        for i = 1, 256 do fds[i] = native() end
        local opened = now() - t0
        t:log(string.format("256 connections opened in %.2f s", opened))
        local extra = native()
        local t1 = now()
        local shut = closed(extra, 1000)
        t:assert(shut, "the 257th connection is closed at once")
        t:assert(now() - t1 < 1.0, "within a second")
        local open = 0
        for _, fd in ipairs(fds) do if not closed(fd) then open = open + 1 end end
        t:assert_eq(open, 256, "the 256 are all still held")
        sys.close(sut, extra)
        close_all(fds)

        -- One connection that delivers half a request: closed at 5 s.
        local fd = native()
        local start = now()
        ntfe.send(sut, fd, string.pack("<I4", 20) .. "\x81")
        local early = closed(fd, 4000)
        local at4 = now() - start
        t:assert(not early, string.format("still open %.2f s after it was accepted", at4))
        local late = closed(fd, 3000)
        local at = now() - start
        t:log(string.format("closed %.2f s after it was accepted", at))
        t:assert(late, "closed without a reply")
        t:assert(at >= 4.5 and at <= 6.0, string.format("at 5 s (%.2f s)", at))
        sys.close(sut, fd)
    end)

test("the stub door holds 256 TCP clients still sending a query, and closes each one 10 s after it was accepted",
    { spec = "PSPU *nri-limits.stub-tcp-clients PSPU *nri-limits.stub-tcp-client-bound" }, function(t)
        local fds = {}
        local t0 = now()
        for i = 1, 256 do
            fds[i] = assert(ntfe.tcp_connect(sut, "127.0.0.53", 53, 2000), "stub TCP connection " .. i)
        end
        t:log(string.format("256 TCP clients connected in %.2f s", now() - t0))
        local extra = assert(ntfe.tcp_connect(sut, "127.0.0.53", 53, 2000), "the 257th connects")
        local t1 = now()
        t:assert(closed(extra, 1000), "the 257th is closed at once")
        t:assert(now() - t1 < 1.0, "within a second")
        local open = 0
        for _, fd in ipairs(fds) do if not closed(fd) then open = open + 1 end end
        t:assert_eq(open, 256, "the 256 are all still held")
        sys.close(sut, extra)
        close_all(fds)

        local fd = assert(ntfe.tcp_connect(sut, "127.0.0.53", 53, 2000))
        local start = now()
        ntfe.send(sut, fd, "\0\40")   -- a length, and no message
        local early = closed(fd, 9000)
        local at9 = now() - start
        t:assert(not early, string.format("still open %.2f s after it was accepted", at9))
        local late = closed(fd, 3000)
        local at = now() - start
        t:log(string.format("closed %.2f s after it was accepted", at))
        t:assert(late, "closed without a reply")
        t:assert(at >= 9.5 and at <= 11.0, string.format("at 10 s (%.2f s)", at))
        sys.close(sut, fd)
    end)

test("the network-manager channel is retried after 0.5 s, the wait doubling to a ceiling of 10 s",
    { spec = "PSPU *nri-limits.manager-reconnect-backoff" }, function(t)
        local clock = function() return gw.vm:clock():get() end
        t:assert_eq(rstatus().netd, true, "resolvd is connected to netd")
        -- Away for d seconds; with attempts at 0.5, 1, 2, 4, 8, 16, 26, 36 s
        -- after the loss, netd back at 9 s is found at 16 s, and back at
        -- 18 s is found at 26 s (doubling unbounded would say 32).
        for _, c in ipairs({ { away = 9, expect = 16 }, { away = 18, expect = 26 } }) do
            sut:run("svctl stop netd"):assert_ok()
            local lost = clock()
            t:assert(gw:serve({ timeout = 5, until_ = function() return rstatus().netd == false end }),
                "resolvd sees netd go")
            gw:serve({ timeout = 60, until_ = function() return clock() - lost >= c.away end })
            sut:run("svctl start netd"):assert_ok()
            local back = clock() - lost
            local found
            gw:serve({ timeout = 40, until_ = function()
                if rstatus().netd then found = clock() - lost; return true end
                return false
            end })
            t:log(string.format("netd away %.1f s (started again at %+.2f s); resolvd reconnected at %+.2f s, expected %+d s",
                c.away, back, found or -1, c.expect))
            t:assert(found and math.abs(found - c.expect) <= 0.8,
                string.format("netd back at %d s is found by the attempt at %d s", c.away, c.expect))
            -- Let netd settle before the next round.
            network.serve_until(gw, sut, network.bound, { iface = true, timeout = 30 })
            gw:serve({ timeout = 2 })
        end
    end)
