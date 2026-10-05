-- resolvd TRM §4.6 "The in-flight ceiling" and PSPU §6.B's
-- upstream-in-flight row: 4 096 outstanding upstream transactions.
--
-- Harness: the scripted gateway (helpers.gateway) holds the lease and the
-- DNS server address (10.77.0.1), and is not pumped during a flood, so
-- nothing answers: every question holds one transaction, one UDP socket,
-- for its three 2-second attempts. The flood comes from inside the
-- machine: bash writes stub queries to 127.0.0.53 through /dev/udp, in
-- paced bursts (the stub socket's receive buffer holds only a few
-- hundred), far faster than the agent's syscalls could. resolvd's open
-- descriptors (`/proc/<pid>/fd`, sampled by a separate process, so the
-- sampling needs none of resolvd's) are the in-flight count: one socket
-- per transaction above the resting count.
--
-- As shipped, resolvd's descriptor limit is 1 024 soft and 4 096 hard
-- (it sets no LimitNOFILE), below the ceiling, so the first test floods
-- the shipped daemon. The rest first raise its limit with prlimit64 from
-- the agent, so that the ceiling, not EMFILE, is what binds.
--
-- The time service is stopped first, so its background lookups do not
-- share the counts.
--
-- Own VMs: floods, and a daemon whose limits are changed.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")

peinit.claim(2)

local SOCK = "/run/resolvd/resolv.sock"
local CEILING = 4096

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
dns.serve(gw, {
    zone = { ["held.example.test"] = { { type = "A", ttl = 3600, data = "10.77.0.80" } } },
    on = function(q)
        local qn = q.questions[1]
        if qn and qn.name:lower():match("%.fl%.test$") then return false end
    end,
})
local sut = network.boot({ bridges = { lan }, gateway = gw })

local function rstatus()
    local s, err = network.call(sut, { query = "status" }, { path = SOCK })
    assert(s and s.ok ~= false, "resolvd status: " .. tostring(err or (s and s.error)))
    return s
end

local pid
local function fds()
    local r = sut:run("ls /proc/" .. pid .. "/fd | wc -l")
    return tonumber(r.stdout:match("%d+"))
end

--- Start a flood of `n` distinct stub questions `<tag><i>.fl.test` A,
--- in bursts of `burst` every 20 ms. Returns the process.
local function flood(tag, n, burst)
    -- A query: id 0x1234, rd, one question; the name is tag + 5 digits.
    local label = tag .. "%05d"
    local llen = #tag + 5
    local fmt = "\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00"
        .. string.format("\\x%02x", llen) .. label .. "\\x02fl\\x04test\\x00\\x00\\x01\\x00\\x01"
    local script = string.format(
        "exec 3<>/dev/udp/127.0.0.53/53; i=0; while [ $i -lt %d ]; do " ..
        "j=0; while [ $j -lt %d ] && [ $i -lt %d ]; do printf '%s' $i >&3; i=$((i+1)); j=$((j+1)); done; " ..
        "sleep 0.02; done", n, burst, n, fmt)
    return sut:run_async("bash", { args = { "-c", script } })
end

--- Sample resolvd's descriptor count until `p` has exited and `extra`
--- seconds more; returns the largest count seen and the samples.
local function sample(p, extra)
    local max, samples, done_at = 0, {}, nil
    local clock = function() return sut:clock():get() end
    while true do
        local n = fds() or 0
        samples[#samples + 1] = n
        if n > max then max = n end
        if not done_at and p:status() == "exited" then done_at = clock() end
        if done_at and clock() - done_at >= extra then break end
    end
    return max, samples
end

local function drain(t, rest)
    t:assert(wait_until(function() return fds() <= rest end, { timeout = 30, interval = 0.5,
        desc = "resolvd's transactions drained" }), "drained")
end

local rest   -- resolvd's descriptors at rest

test("as shipped, 1 500 outstanding transactions fit under the 4 096 in-flight bound",
    { spec = "PSPU *nri-limits.upstream-in-flight", tags = { "known-bug" } }, function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound a lease")
        t:assert(gw:serve({ timeout = 20, until_ = function()
            local s = rstatus().scopes or {}
            return s[1] ~= nil and (s[1].servers or {})[1] == "10.77.0.1"
        end }), "resolvd has the lease's server")
        pid = peinit.pid_of_comm(sut, "resolvd")
        t:log(sut:read_file("/proc/" .. pid .. "/limits"):match("Max open files[^\n]*"))
        -- The time service's background lookups would share the counts.
        local st = sut:run("svctl stop timed")
        t:log("svctl stop timed: exit " .. tostring(st.exit_code) .. " " .. st.stdout .. st.stderr)
        gw:serve({ timeout = 7 })   -- let any lookup already made finish
        rest = math.huge
        for _ = 1, 5 do rest = math.min(rest, fds()) end
        t:log("descriptors at rest: " .. rest)
        local c0 = rstatus().counters
        local p = flood("a", 1500, 100)
        local max = sample(p, 1.0)
        p:wait(10)
        t:log("most descriptors held during the flood: " .. max)
        drain(t, rest)
        local c1 = rstatus().counters
        local warn = sut:run("evctl 'LOGS FROM resolvd SINCE 5m ago TAKE 400'").stdout
        local emfile = warn:match('message="([^"]*upstream 10%.77%.0%.1: [^"]*)"')
        t:log(string.format("queries +%d, sent +%d, failed +%d, refused +%d; a warning: %s; demoted now: %s",
            c1.queries - c0.queries, c1.upstream_sent - c0.upstream_sent, c1.upstream_failed - c0.upstream_failed,
            c1.refused - c0.refused, tostring(emfile), table.concat(rstatus().scopes[1].demoted or {}, ",")))
        -- PEI-1344: resolvd sets no LimitNOFILE, so at ~1 024 descriptors
        -- every new transaction fails with EMFILE ("Too many open files"),
        -- failing its attempts at once and demoting a healthy server; the
        -- held count never gets near 1 500, let alone 4 096.
        t:assert(max - rest >= 1500, string.format("1 500 transactions held at once (held %d)", max - rest))
    end)

local raised = false

test("at 4 096 outstanding transactions a question's first attempt is refused: unavailable, and counted",
    { spec = "resolvd *engine-servers.in-flight-ceiling-value resolvd *engine-servers.in-flight-ceiling-refuses-first-attempts" },
    function(t)
        local limit = string.pack("<I8I8", 16384, 16384)
        local r = sut:syscall(302, { args = { pid, 7, 0, 0 }, bufs = { limit }, ptrs = { 2 } })
        t:log("prlimit64: ret " .. tostring(r.ret) .. " errno " .. tostring(r.errno) .. "; "
            .. sut:read_file("/proc/" .. pid .. "/limits"):match("Max open files[^\n]*"))
        t:assert_eq(r.ret, 0, "resolvd's descriptor limit raised to 16 384")
        raised = true
        -- Wait out the demotions the last test caused (not needed for the
        -- ceiling, but they keep the log quiet).
        local c0 = rstatus().counters
        local p = flood("b", 4600, 200)
        local max = sample(p, 0.5)
        p:wait(10)
        local c1 = rstatus().counters
        t:log(string.format("most held %d (rest %d); queries +%d, sent +%d, refused +%d", max, rest,
            c1.queries - c0.queries, c1.upstream_sent - c0.upstream_sent, c1.refused - c0.refused))
        t:assert_eq(max - rest, CEILING, "exactly 4 096 transactions were held at once")
        local asked = c1.queries - c0.queries
        t:assert(asked > CEILING, "more than 4 096 questions arrived (" .. asked .. ")")
        t:assert_eq(c1.refused - c0.refused, asked - CEILING, "every question beyond the 4 096th was refused")
        t:assert_eq(c1.upstream_sent - c0.upstream_sent, CEILING, "and sent nothing")
        drain(t, rest)
    end)

test("at the ceiling, synthetic names and cache hits are answered as usual, and a new question is refused",
    { spec = "resolvd *engine-servers.local-answers-unaffected-by-ceiling" }, function(t)
        t:assert(raised, "the descriptor limit was raised")
        local p0 = sut:run_async("sh", { args = { "-c", "resolv query held.example.test A" } })
        gw:serve({ timeout = 15, until_ = function() return p0:status() == "exited" end })
        t:assert(p0:wait(5).stdout:match("^found%s+dns"), "held.example.test is cached")
        dns.stop(gw)
        local p = flood("c", 4400, 200)
        p:wait(15)
        t:assert(fds() - rest >= CEILING, "4 096 transactions are held")
        local c0 = rstatus().counters
        local r = sut:run("resolv query localhost A; resolv query held.example.test A; resolv query new.example.test A; echo rc=$?")
        t:log(r.stdout)
        local c1 = rstatus().counters
        t:assert(r.stdout:match("^found%s+synthetic"), "localhost answered synthetic")
        t:assert(r.stdout:find("\nfound  cache", 1, true), "held.example.test answered from the cache")
        t:assert(r.stdout:find("\nunavailable  local", 1, true) and r.stdout:find("rc=3", 1, true),
            "the new question is unavailable at once")
        t:assert_eq(c1.refused - c0.refused, 1, "and counted as refused; the other two were not")
        t:assert(fds() - rest <= CEILING, "still at the ceiling")
        drain(t, rest)
    end)

test("later attempts are not checked against the ceiling, so the count can pass 4 096",
    { spec = "resolvd *engine-servers.retries-not-checked-against-ceiling", tags = { "known-bug" } }, function(t)
        t:assert(raised, "the descriptor limit was raised")
        local c0 = rstatus().counters
        local p = flood("d", 4300, 200)
        -- Sample through the second and third attempts (6 s in all).
        local max = sample(p, 6.5)
        p:wait(10)
        local c1 = rstatus().counters
        local sent = c1.upstream_sent - c0.upstream_sent
        t:log(string.format("sent +%d (first attempts %d), refused +%d; most held %d", sent, CEILING,
            c1.refused - c0.refused, max - rest))
        t:assert(sent >= 3 * CEILING - 50,
            "the held questions' second and third attempts went out at the ceiling (" .. sent .. " sent)")
        -- TRM-inflight-cannot-pass: every retry is sent after its own
        -- transaction is removed (a timeout's or a truncated reply's), so
        -- the count never rises above 4 096; the most held was 4 096.
        t:assert(max - rest > CEILING, "more than 4 096 transactions were in flight at some moment (" .. (max - rest) .. ")")
        drain(t, rest)
    end)
