-- resolvd TRM §4.6: three attempts per question across search candidates,
-- spent only by failures and TCP retries; a `notfound` answer that moves
-- the question to its next candidate is not charged. The resolver must
-- answer before the NSS shim's ten-second timeout.
--
-- Harness: the scripted gateway (helpers.gateway) is the one DNS server
-- (helpers.dns, 10.77.0.1 from the lease). `ExtraSearchDomains` gives
-- two search domains, one.test and two.test, so a single label has two
-- candidates. The gateway's hook counts the UDP attempts at each name
-- and type: under one.test the first two attempts get no reply and the
-- third gets NXDOMAIN (no SOA, so nothing is cached) 1.5 s late; under
-- two.test nothing is ever answered. The first candidate therefore makes
-- three transactions: two timeouts (charged) and an NXDOMAIN (refunded).
-- The second candidate gets the one attempt left, which times out.
--
-- Each test asks a different single label, so the counts are its own.
--
-- Own VMs: search domains in the registry, and long silent questions.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")

peinit.claim(2)

local SOCK = "/run/resolvd/resolv.sock"

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })

local attempts = {}
dns.serve(gw, {
    on = function(q, default, ctx)
        local qn = q.questions[1]
        local n = qn and qn.name:lower() or ""
        local domain = n:match("^%a+%.(%a+)%.test$")
        if domain ~= "one" and domain ~= "two" then return nil end
        if ctx.transport ~= "udp" then return false end
        local key = n .. "/" .. qn.type
        attempts[key] = (attempts[key] or 0) + 1
        if domain == "one" and attempts[key] == 3 then
            default.rcode, default.answers, default.authority = dns.RCODE.NXDOMAIN, {}, {}
            default.delay = 1.5
            return default
        end
        return false
    end,
})

local files = {}
files = network.test_binary("resolvd", files)
local sut = network.boot({ bridges = { lan }, gateway = gw, files = files })

local function rstatus()
    local s, err = network.call(sut, { query = "status" }, { path = SOCK })
    assert(s and s.ok ~= false, "resolvd status: " .. tostring(err or (s and s.error)))
    return s
end

local ready = false
local function setup(t)
    if ready then return end
    t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound a lease")
    t:assert(gw:serve({ timeout = 20, until_ = function()
        local s = rstatus().scopes or {}
        return s[1] ~= nil and (s[1].servers or {})[1] == "10.77.0.1"
    end }), "resolvd has the lease's server")
    network.write(sut, "Dns", { ExtraSearchDomains = "multi:one.test,two.test" })
    gw:serve({ timeout = 2 })
    ready = true
end

--- Run `cmd` in the guest, timed by /proc/uptime, while the gateway pumps.
local function timed(t, cmd)
    local p = sut:run_async("sh", { args = { "-c", "cat /proc/uptime; " .. cmd .. "; echo rc=$?; cat /proc/uptime" } })
    gw:serve({ timeout = 40, until_ = function() return p:status() == "exited" end })
    local out = p:wait(5).stdout
    local u = {}
    for a in out:gmatch("(%d+%.%d+) %d+%.%d+") do u[#u + 1] = tonumber(a) end
    t:log(cmd .. ": " .. out:gsub("\n", " | "))
    return out, (u[2] or 0) - (u[1] or 0)
end

local function udp(name, rtype)
    return dns.queries(gw, function(e)
        local q = e.msg and e.msg.questions[1]
        return q and e.transport == "udp" and dns.same_name(q.name, name) and q.type == dns.TYPE[rtype or "A"]
    end)
end

test("the attempt limit spans search candidates; a notfound answer does not spend it",
    { spec = "resolvd *engine-servers.limit-is-per-candidate" }, function(t)
        setup(t)
        local out, elapsed = timed(t, "resolv query pc A")
        t:assert(out:find("\nunavailable", 1, true), "the question is unavailable")
        local one, two = udp("pc.one.test"), udp("pc.two.test")
        t:assert_eq(#one, 3, "three transactions at the first candidate, the third answered NXDOMAIN")
        t:assert_eq(#two, 1, "the second candidate gets the one attempt the two timeouts left")
        t:assert(two[1].at > one[3].at, "the second candidate was asked after the first's NXDOMAIN")
        t:log(string.format("four transactions, three charged, in %.2f s", elapsed))
    end)

test("a question gets three attempts",
    { spec = "PSPU *nri-limits.attempts-per-question" }, function(t)
        setup(t)
        local out = timed(t, "resolv query pq A")
        t:assert(out:find("\nunavailable", 1, true), "the question is unavailable")
        local n = #udp("pq.one.test") + #udp("pq.two.test")
        -- PEI-1361: the budget applies to the entire question. One of the
        -- transactions was answered NXDOMAIN, which is not a failed attempt.
        t:assert(n - 1 <= 3, "at most three failed attempts for the question (made " .. n .. " transactions)")
    end)

test("a slow upstream is reported by the resolver as unavailable before the shim's own timeout",
    { spec = "PSPU *nri-limits.shim-timeout-exceeds-attempts-times-server-timeout" },
    function(t)
        setup(t)
        local out, elapsed = timed(t, "getent ahosts sh")
        t:assert(not out:find("rc=0", 1, true), "getent found nothing")
        gw:serve({ timeout = 4 })
        local n = #udp("sh.one.test", "A") + #udp("sh.two.test", "A")
        t:log(string.format("getent returned after %.2f s; resolvd made %d A attempts", elapsed, n))
        t:assert(n - 1 <= 3, "the A question stayed within three failed attempts")
        t:assert(elapsed < 9.8, string.format("resolvd answered within the shim's 10 s (getent took %.2f s)", elapsed))
    end)
