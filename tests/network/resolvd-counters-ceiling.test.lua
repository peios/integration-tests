-- resolvd §4.1 and §4.10 — the in-flight ceiling: a question whose first
-- attempt finds 4 096 transactions in flight is refused, answered
-- unavailable with source local and no server, interface or rcode, and
-- counted in `refused`.
--
-- Harness: the scripted gateway (helpers.gateway) leasing 10.77.0.50 with
-- itself as the DNS server, whose DNS server (helpers.dns) is silent for
-- every name under flood.test, so each question holds one transaction for
-- its three two-second attempts. A guest bash loop writes thousands of
-- stub queries for distinct flood.test names to 127.0.0.53 through
-- /dev/udp, which fills the in-flight table within the six seconds a
-- question lasts.
--
-- Each transaction holds a socket, and resolvd runs with the default
-- descriptor limit (PEI-1344: no LimitNOFILE), below 4 096; at that limit
-- bind fails first and the ceiling is never reached. The test therefore
-- raises resolvd's RLIMIT_NOFILE (shipped 1 024 soft, 4 096 hard) to
-- 16 384 with prlimit64 from the agent, as resolvd-limits-inflight does:
-- a lever on the environment, not on resolvd's logic, and logged.
--
-- Own VMs: the flood leaves thousands of transactions and a demoted
-- server behind; nothing runs after it.

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
local sut = network.boot({ bridges = { lan }, gateway = gw })

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

--- resolvd's descriptor limits: soft, hard.
local function nofile(pid)
    local text = sut:read_file("/proc/" .. pid .. "/limits")
    local soft, hard = text:match("Max open files%s+(%S+)%s+(%S+)")
    return tonumber(soft), tonumber(hard), text:match("Max open files[^\n]*")
end

-- The flood: `n` queries for h<i>.flood.test, A, from one UDP socket, in
-- bursts of 200 every 20 ms: the stub socket's receive buffer holds only
-- a few hundred datagrams (the pacing of resolvd-limits-inflight).
local FLOOD = [[
exec 3>/dev/udp/127.0.0.53/53
i=0
while [ $i -lt %d ]; do
  j=0
  while [ $j -lt 200 ]; do
    printf '\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05h%%04d\x05flood\x04test\x00\x00\x01\x00\x01' $i >&3
    i=$((i+1)); j=$((j+1))
  done
  sleep 0.02
done
]]

test("at the in-flight ceiling a first attempt is refused: unavailable, source local, no server, no interface, rcode 0, counted in refused",
    { spec = "resolvd *engine-flow.report-in-flight-ceiling resolvd *engine-counters.refused" }, function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound")
        t:assert(gw:serve({ timeout = 20, until_ = function()
            local s = rstatus()
            return s.scopes[1] ~= nil and #s.scopes[1].servers == 1
        end }), "resolvd has eth0's server")
        sut:run("svctl stop timed"):assert_ok()
        gw:serve({ timeout = 2 })

        local pid = assert(peinit.pid_of_comm(sut, "resolvd"), "resolvd's pid")
        local soft, hard, line = nofile(pid)
        t:log("resolvd " .. pid .. ": " .. tostring(line))
        -- Shipped: 1 024 soft, 4 096 hard. Both are raised to 16 384.
        -- prlimit64(pid, RLIMIT_NOFILE, &new, NULL)
        local r = sut:syscall(302, {
            args = { tonumber(pid), 7, 0, 0 },
            bufs = { string.pack("<I8I8", 16384, 16384) },
            ptrs = { 2 },
        })
        t:log("prlimit64 -> " .. tostring(r.ret) .. " errno " .. tostring(r.errno))
        t:assert_eq(r.ret, 0, "prlimit64 raised resolvd's descriptor limit")
        soft, hard, line = nofile(pid)
        t:log("now: " .. tostring(line))
        t:assert_eq(soft, 16384, "the soft limit is 16 384")

        local before = rstatus().counters
        t:log("before: " .. show(before))
        sut:write_file("/run/pt-flood.sh", string.format(FLOOD, 4600))
        local f = sut:run("bash /run/pt-flood.sh")
        t:log("flood: exit " .. tostring(f.exit_code) .. " " .. tostring(f.stderr))
        -- Wait for resolvd to have taken every datagram it is going to:
        -- no new question means no new first attempt, so nothing else can
        -- be refused while the probe is asked. (Retries go on; they are
        -- not checked against the ceiling.)
        local mid, last = rstatus().counters, nil
        repeat
            last = mid
            sut:run("sleep 0.2")
            mid = rstatus().counters
        until mid.queries == last.queries
        t:log("after the flood: " .. show(mid))
        local r = network.call(sut, { query = "resolve", name = "probe.flood.test", type = 1 }, { path = SOCK })
        t:assert(r and r.ok, "the probe was answered")
        t:log(string.format("probe: %s source=%s server=%s interface=%s rcode=%s", tostring(r.outcome),
            tostring(r.source), tostring(r.server), tostring(r.interface), tostring(r.rcode)))
        local after = rstatus().counters
        t:log("after the probe: " .. show(after))
        t:assert(mid.refused > before.refused, "the flood reached the ceiling: questions were refused")
        t:assert(mid.upstream_sent - before.upstream_sent >= 4096, "with 4 096 transactions started")
        t:assert_eq(r.outcome, "unavailable", "the probe: unavailable")
        t:assert_eq(r.source, "local", "the probe: source local")
        t:assert_eq(r.server, nil, "the probe: no server")
        t:assert_eq(r.interface, nil, "the probe: no interface")
        t:assert_eq(r.rcode, 0, "the probe: rcode 0")
        t:assert_eq(after.queries - mid.queries, 1, "the probe is the only new question")
        t:assert_eq(after.refused - mid.refused, 1, "and it was counted in refused")
    end)
