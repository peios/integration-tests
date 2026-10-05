-- resolvd TRM §4.6 "What fails an attempt": a TCP connection that hangs
-- up after it is established but before resolvd has sent the query.
--
-- resolvd writes the query on the first POLLOUT after connecting, so in
-- the ordinary course nothing can come between the handshake and the
-- write. This file makes room by stalling resolvd's single loop thread
-- with a defect the TRM records (PEI-1342,
-- `loop.replies-written-blocking`): a stub TCP reply is written blocking, so a stub
-- client that asks for a large cached answer and never reads stops the
-- loop while the write waits (each write call up to a second; with
-- partial progress, about three seconds in all). The client reading its
-- reply ends the stall at once (closing it does not), which lets the
-- test end each stall when it chooses. If
-- PEI-1342 is fixed, this lever is gone and the file needs another.
--
-- The sequence (resolvd services upstream sockets before stub clients
-- in each loop iteration):
--   1. big.example.test TXT (~61 KB) is cached (fetched over TCP).
--   2. Two stub TCP clients, S1 and S2, connect with the smallest
--      receive buffer and a 536-byte MSS (so resolvd's send buffer is
--      sized small and the write blocks), and never read.
--   3. `resolv query stall.example.test` sends its first UDP attempt;
--      the gateway holds its reply, a truncated one (TC set).
--   4. S1 asks for big.example.test: resolvd stalls writing it. During
--      the stall the TC reply is released and S2 asks too; then S1
--      reads its reply, ending the stall.
--   5. The next iteration takes the TC reply first, connects to the
--      server over TCP, then serves S2 and stalls again.
--   6. During that stall the connection's handshake completes in the
--      kernels; the gateway accepts it, finds no bytes, and resets it;
--      then S2 reads its reply, ending the stall.
--   7. When the loop wakes, the connection is in error before its query
--      was written: the attempt fails at once and the second UDP attempt
--      goes out, well inside the TCP transaction's own 2 s deadline.
--
-- Harness: the scripted gateway (helpers.gateway) and its DNS server
-- (helpers.dns) on the lease. The DNS server's tick is swapped, while
-- the TCP connection is awaited, for one that sends held UDP replies and
-- accepts and resets every TCP connection, noting what it had received.
--
-- Own VMs: the gateway's TCP handling is replaced, and resolvd's loop is
-- stalled on purpose.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")

peinit.claim(2)

local SOCK = "/run/resolvd/resolv.sock"
local A = "10.77.0.1"

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })

local txt = {}
for i = 1, 220 do txt[i] = { type = "TXT", ttl = 3600, data = string.format("%03d", i) .. string.rep("x", 247) } end

local stall_udp = 0
dns.serve(gw, {
    zone = { ["big.example.test"] = txt },
    on = function(q, default, ctx)
        local qn = q.questions[1]
        if not (qn and dns.same_name(qn.name, "stall.example.test")) then return nil end
        default.rcode, default.authority = 0, {}
        default.answers = { { name = qn.name, type = "A", ttl = 0, data = "10.77.4.1" } }
        if ctx.transport == "udp" then
            stall_udp = stall_udp + 1
            if stall_udp == 1 then default.tc, default.no_truncate, default.delay = true, true, 1000 end
        end
        return default
    end,
})
local service = gw.ticks.dns

local sut = network.boot({ bridges = { lan }, gateway = gw })

local function rstatus()
    local s, err = network.call(sut, { query = "status" }, { path = SOCK })
    assert(s and s.ok ~= false, "resolvd status: " .. tostring(err or (s and s.error)))
    return s
end

local function clock() return gw.vm:clock():get() end

--- A stub TCP client with the smallest receive buffer, connected.
local function slow_client()
    local fd = assert(ntfe.socket(sut, ntfe.AF_INET, ntfe.SOCK_STREAM))
    ntfe.set_int_opt(sut, fd, 1, 8, 1)     -- SO_RCVBUF: the kernel's minimum
    -- TCP_MAXSEG: a small MSS in the SYN. On loopback the 64 KB MSS would
    -- size resolvd's send buffer to hold the whole reply, and the write
    -- would never block.
    ntfe.set_int_opt(sut, fd, 6, 2, 536)
    local sa = ntfe.sockaddr("127.0.0.53", 53)
    sut:syscall(ntfe.NR.connect, { args = { fd, 0, #sa }, bufs = { sa }, ptrs = { 1 } })
    assert(ntfe.poll(sut, fd, ntfe.POLLOUT, 2000) & ntfe.POLLOUT ~= 0, "the stub door accepted a slow client")
    return fd
end

local function stub_query(id)
    local m = dns.encode(dns.query("big.example.test", "TXT", { id = id }))
    return string.pack(">I2", #m) .. m
end

--- The gateway tick while the connection is awaited: held UDP replies
--- go out; each TCP connection is accepted, read without waiting, and
--- reset (SO_LINGER 0, then close).
local resets = {}
local after_reset   -- called once a connection has been reset
local function resetting(g)
    local now, keep = clock(), {}
    for _, p in ipairs(g.dns_pending) do if p.due <= now then p.send() else keep[#keep + 1] = p end end
    g.dns_pending = keep
    while true do
        local fd = ntfe.tcp_accept(g.vm, g.dns_listener, 0)
        if not fd then break end
        local at = clock()
        local got = ntfe.recv(g.vm, fd, 0, 4096)
        g.vm:syscall(ntfe.NR.setsockopt, { args = { fd, 1, 13, 0, 8 },
            bufs = { string.pack("<i4i4", 1, 0) }, ptrs = { 3 } })
        sys.close(g.vm, fd)
        resets[#resets + 1] = { at = at, bytes = got and #got or 0 }
        if after_reset then after_reset(); after_reset = nil end
    end
end

test("a TCP connection that hangs up after the handshake, before the query is sent, fails the attempt at once",
    { spec = "resolvd *engine-servers.tcp-error-before-query-sent-fails-attempt" }, function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound a lease")
        t:assert(gw:serve({ timeout = 20, until_ = function()
            local s = rstatus().scopes or {}
            return s[1] ~= nil and (s[1].servers or {})[1] == A
        end }), "resolvd has the lease's server")
        local function served(cmd)
            local p = sut:run_async("sh", { args = { "-c", cmd } })
            gw:serve({ timeout = 20, until_ = function() return p:status() == "exited" end })
            return p:wait(5).stdout
        end
        -- Through the stub door (a native reply this size exceeds the
        -- client's 65 536-byte ceiling).
        local dig = "dig +tcp +short @127.0.0.53 big.example.test TXT | wc -l"
        local n1 = served(dig)
        local hits = rstatus().counters.cache_hits
        local n2 = served(dig)
        t:log("dig lines: " .. n1:gsub("%s", "") .. ", then " .. n2:gsub("%s", ""))
        t:assert_eq(tonumber(n1:match("%d+")), 220, "the large answer fetched: 220 records")
        t:assert_eq(tonumber(n2:match("%d+")), 220, "and asked again")
        t:assert_eq(rstatus().counters.cache_hits, hits + 1, "from the cache")

        local s1, s2 = slow_client(), slow_client()
        gw:serve({ timeout = 1 })   -- both accepted by resolvd
        local failed0 = rstatus().counters.upstream_failed

        local p = sut:run_async("sh", { args = { "-c", "resolv query stall.example.test A" } })
        t:assert(gw:serve({ timeout = 10, until_ = function() return stall_udp >= 1 end }),
            "the first UDP attempt arrived; its truncated reply is held")
        gw.ticks.dns = resetting
        -- A stall ends when its client reads the reply (closing it does
        -- not: the write stays blocked).
        local function drain(fd)
            local n = 0
            while true do
                local got = ntfe.recv(sut, fd, 300, 65536)
                if not got or #got == 0 then return n end
                n = n + #got
            end
        end
        -- Stall 2 ends when the gateway has reset resolvd's connection.
        local reset_closed_at, drained
        after_reset = function() drained = drain(s2); reset_closed_at = clock() end
        -- Stall 1; the TC reply and S2's query land during it; then S1
        -- reads its reply, ending it.
        ntfe.send(sut, s1, stub_query(101))
        local released = clock()
        for _, h in ipairs(gw.dns_pending) do h.due = 0 end
        gw:pump(1)
        ntfe.send(sut, s2, stub_query(102))
        local d1 = drain(s1)
        t:log(string.format("S1 read %d bytes, done %+.2f s after the TC release", d1, clock() - released))
        gw:serve({ timeout = 10, until_ = function() return p:status() == "exited" end })
        gw.ticks.dns = service
        local out = p:wait(5).stdout
        after_reset = nil
        sys.close(sut, s1)
        sys.close(sut, s2)
        if reset_closed_at then
            t:log(string.format("S2 read %d bytes, done %+.2f s after the TC release", drained or 0, reset_closed_at - released))
        end

        local udp = dns.queries(gw, function(e)
            local q = e.msg and e.msg.questions[1]
            return q and e.transport == "udp" and dns.same_name(q.name, "stall.example.test")
        end)
        t:log(string.format("answer: %s; UDP attempts %d; resets %d", out:gsub("\n", " | "), #udp, #resets))
        for i, r in ipairs(resets) do
            t:log(string.format("reset %d: accepted %+.2f s after the TC release, %d bytes received", i, r.at - released, r.bytes))
        end
        if udp[2] then t:log(string.format("second UDP attempt %+.2f s after the TC release", udp[2].at - released)) end
        t:assert_eq(#resets, 1, "resolvd's TCP connection completed its handshake and was accepted")
        t:assert_eq(resets[1].bytes, 0, "no byte of the query had arrived when it was reset: resolvd's loop was stalled")
        t:assert(udp[2] ~= nil, "a second UDP attempt followed")
        -- The TCP transaction began after the release, so its deadline is
        -- at least 2 s after it; the next attempt came well before.
        t:assert(udp[2].at - released < 1.9,
            string.format("the next attempt came at once, not at the TCP deadline (%.2f s after the release)", udp[2].at - released))
        t:assert(out:match("^found%s+dns"), "the second attempt answered")
        t:assert_eq(rstatus().counters.upstream_failed - failed0, 1, "the reset counted as one failure")
    end)
