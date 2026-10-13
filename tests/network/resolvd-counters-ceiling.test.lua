-- PEI-1343: pending UDP refusals increment queries and refused exactly
-- once, never upstream_sent. A bounded local burst also probes whether
-- the native status door keeps making progress while UDP is busy.
-- The engine ceiling itself is covered by host tests, documented in
-- resolvd-limits-inflight.test.lua.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
dns.serve(gw, {
    zone = {},
    on = function(q)
        local qn = q.questions[1]
        if qn and qn.name:lower():find("flood%.test$") then return false end
    end,
})
local sut = network.boot({ bridges = { lan }, gateway = gw, files = network.test_binary("resolvd", {}) })

local SOCK = "/run/resolvd/resolv.sock"
local NAMES = { "queries", "synthetic", "cache_hits", "upstream_sent", "upstream_answered", "upstream_failed", "refused" }

local function rstatus()
    local s, err = network.call(sut, { query = "status" }, { path = SOCK })
    assert(s and s.ok, "resolvd status: " .. tostring(err or (s and s.error)))
    return s
end

local function show(c)
    local parts = {}
    for _, k in ipairs(NAMES) do parts[#parts + 1] = k .. "=" .. tostring(c[k]) end
    return table.concat(parts, " ")
end

-- The flood: `n` queries for h<i>.flood.test, A, from one UDP socket, in
-- bursts of 100 every 20 ms: the stub socket's receive buffer holds only
-- a few hundred datagrams (the pacing of resolvd-limits-inflight).
local FLOOD = [[
exec 3>/dev/udp/127.0.0.53/53
i=0
while [ $i -lt %d ]; do
  j=0
  while [ $j -lt 100 ]; do
    printf '\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05h%%04d\x05flood\x04test\x00\x00\x01\x00\x01' $i >&3
    i=$((i+1)); j=$((j+1))
  done
  sleep 0.02
done
]]

test("a UDP burst is refused by its endpoint budget while native status stays responsive",
    { spec = "resolvd *engine-counters.refused resolvd *engine-counters.queries resolvd *stub-receive.udp-pending-budgets resolvd *loop.listener-batches", tags = { "pei-1343" } }, function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound")
        t:assert(gw:serve({ timeout = 20, until_ = function()
            local s = rstatus()
            return s.scopes[1] ~= nil and #s.scopes[1].servers == 1
        end }), "resolvd has eth0's server")
        sut:run("svctl stop timed"):assert_ok()
        gw:serve({ timeout = 7 })
        local before = rstatus().counters
        sut:write_file("/run/pt-flood.sh", string.format(FLOOD, 3000))
        local flood = sut:run_async("bash", { args = { "/run/pt-flood.sh" } })
        local start = sut:clock():get()
        local during = rstatus()
        t:assert(during.ok, "native status answered during the UDP burst")
        t:assert(sut:clock():get() - start < 1, "within one second")
        flood:wait(10):assert_ok()
        -- Drain all queued datagrams before inspecting exact accounting.
        local mid, last = rstatus().counters, nil
        repeat
            last = mid
            sut:run("sleep 0.05")
            mid = rstatus().counters
        until mid.queries == last.queries
        t:log("before: " .. show(before) .. "; after: " .. show(mid))
        local asked = mid.queries - before.queries
        t:assert(asked > 16, "more questions arrived than the endpoint can hold")
        t:assert_eq(mid.refused - before.refused, asked - 16, "every overflow counted exactly once")
        t:assert_eq(mid.upstream_sent - before.upstream_sent, 16, "overflow never allocated an upstream transaction")
        t:assert_eq(mid.upstream_answered - before.upstream_answered, 0, "the held server has not answered")
        local local_answer = network.call(sut, { query = "resolve", name = "localhost", type = 1 }, { path = SOCK })
        t:assert_eq(local_answer.outcome, "found", "native local answers remain available")
        local after = rstatus().counters
        t:assert_eq(after.queries - mid.queries, 1, "only the native query counted")
        t:assert_eq(after.refused, mid.refused, "native answer was not refused")
    end)
