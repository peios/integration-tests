-- PEI-1343: admission bounds keep UDP traffic from consuming every door.
-- The gateway leaves *.fl.test unanswered. No host-facing traffic is made.
-- All limits are tested on the running resolver, with its ordinary service
-- descriptor limit. Earlier versions used one UDP endpoint to fill 4 096
-- transactions; that route is deliberately no longer available.
--
-- covered_by: resolvd engine host tests in_flight_is_bounded_and_refused_beyond_it
-- and every_send_checks_capacity_but_replacing_a_transaction_can_reuse_its_slot:
-- PSPU *nri-limits.upstream-in-flight
-- resolvd *engine-servers.in-flight-ceiling-value
-- resolvd *engine-servers.in-flight-ceiling-refuses-new-transactions
-- resolvd *engine-servers.retries-checked-against-ceiling
-- resolvd *engine-servers.local-answers-unaffected-by-ceiling
-- resolvd *engine-flow.report-in-flight-ceiling
-- These are engine-unit coverage, not claims of reaching 4 096 through a VM door.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")

peinit.claim(2)
local SOCK = "/run/resolvd/resolv.sock"
local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
dns.serve(gw, {
    zone = { ["healthy.example.test"] = { { type = "A", ttl = 0, data = "10.77.0.80" } } },
    on = function(q)
        if q.questions[1] and q.questions[1].name:lower():match("%.fl%.test$") then return false end
    end,
})
local sut = network.boot({ bridges = { lan }, gateway = gw, files = network.test_binary("resolvd", {}) })
local pid, rest
local function status()
    return assert(network.call(sut, { query = "status" }, { path = SOCK }))
end
local function fds() return #sut:listdir("/proc/" .. pid .. "/fd") end
local function drain(t)
    t:assert(wait_until(function() return fds() <= rest end,
        { timeout = 10, interval = 0.05, desc = "UDP questions expired" }), "all pending questions drained")
end
local function peer() return assert(ntfe.udp_connect(sut, "127.0.0.53", 53)) end
local function query(id, name)
    return dns.encode(dns.query(name or ("h" .. id .. ".fl.test"), "A", { id = id }))
end
local function send(fd, id, name)
    local bytes = query(id, name)
    assert(ntfe.send(sut, fd, bytes).ret == #bytes, "whole datagram sent")
end
local function answer(fd)
    return assert(dns.decode(assert(ntfe.recv(sut, fd, 1500, 4096))))
end
local function fill(t, peers, first)
    for p, fd in ipairs(peers) do
        for i = 1, 16 do
            send(fd, first + (p - 1) * 16 + i)
        end
    end
end

test("one UDP endpoint holds 16 questions; excess gets SERVFAIL and another endpoint still resolves",
    { spec = "resolvd *stub-receive.udp-pending-budgets PSPU *nri-limits.stub-udp-pending", tags = { "pei-1343" } }, function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound")
        t:assert(gw:serve({ timeout = 20, until_ = function()
            for _, sc in ipairs(status().scopes or {}) do
                if (sc.servers or {})[1] == "10.77.0.1" then return true end
            end
        end }), "resolver has the fixture DNS server")
        sut:run("svctl stop timed"):assert_ok()
        gw:serve({ timeout = 7 })
        pid = assert(peinit.pid_of_comm(sut, "resolvd"))
        rest = fds()
        local p = peer()
        local before = status().counters
        fill(t, { p }, 0)
        send(p, 17, "localhost")
        local refused = answer(p)
        t:assert_eq(refused.id, 17, "only the excess question answered immediately")
        t:assert_eq(refused.rcode, 2, "SERVFAIL even for a local answer when admission is full")
        local after = status().counters
        t:assert_eq(after.queries - before.queries, 17, "all valid questions counted")
        t:assert_eq(after.refused - before.refused, 1, "only the excess refused")
        t:assert_eq(fds() - rest, 16, "16 transactions retained")
        local other = peer()
        send(other, 18, "localhost")
        t:assert_eq(answer(other).rcode, 0, "another source port has its own allowance")
        sys.close(sut, other)
        drain(t)
        -- UDP close does not cancel, and no response has been read from
        -- the first 16 questions. Read their timeout replies before reuse.
        for _ = 1, 16 do t:assert_eq(answer(p).rcode, 2, "pending question timed out") end
        send(p, 19, "localhost")
        t:assert_eq(answer(p).rcode, 0, "completion releases the endpoint's slots")
        sys.close(sut, p)
    end)

test("changing UDP ports cannot exceed 256 pending questions or exhaust native and TCP service",
    { spec = "resolvd *stub-receive.udp-pending-budgets PSPU *nri-limits.stub-udp-pending", tags = { "pei-1343" } }, function(t)
        local peers = {}
        for _ = 1, 16 do peers[#peers + 1] = peer() end
        local before = status().counters
        fill(t, peers, 100)
        t:assert(wait_until(function() return fds() - rest == 256 end,
            { timeout = 1, interval = 0.01, desc = "aggregate UDP capacity" }), "256 UDP questions are held")
        local fresh = peer()
        send(fresh, 400, "localhost")
        t:assert_eq(answer(fresh).rcode, 2, "even a new endpoint is refused at the aggregate bound")
        local mid = status().counters
        t:assert_eq(mid.queries - before.queries, 257, "all 257 arrivals counted")
        t:assert_eq(mid.refused - before.refused, 1, "only the aggregate overflow refused")
        local native = sut:run_async("resolv", { args = { "query", "healthy.example.test", "A" } })
        local tcp = assert(ntfe.tcp_connect(sut, "127.0.0.53", 53, 1000))
        local bytes = query(401, "healthy.example.test")
        ntfe.send(sut, tcp, string.pack(">I2", #bytes) .. bytes)
        t:assert(gw:serve({ timeout = 4, until_ = function()
            return native:status() == "exited" and ntfe.poll(sut, tcp, ntfe.POLLIN, 0) ~= 0
        end }), "both stream doors answer while UDP capacity is occupied")
        t:assert(native:wait(1).stdout:match("^found%s+dns"), "uncached native query resolved")
        local received = ""
        repeat
            local chunk = assert(ntfe.recv(sut, tcp, 1000, 4096))
            assert(#chunk > 0, "TCP reply closed before its full frame")
            received = received .. chunk
        until #received >= 2 and #received >= 2 + string.unpack(">I2", received)
        local reply = assert(dns.decode(received:sub(3)))
        t:assert_eq(reply.rcode, 0, "uncached TCP query resolved")
        t:assert_eq(reply.answers[1].data, "10.77.0.80", "correct answer")
        t:assert_eq(fds() - rest, 256, "UDP questions remain pending while other doors work")
        sys.close(sut, tcp)
        for _, fd in ipairs(peers) do sys.close(sut, fd) end
        sys.close(sut, fresh)
        drain(t)
    end)
