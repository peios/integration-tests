-- resolvd TRM §4.5 "The Cache": the key, what is stored and for how
-- long, hits, bypassing, lingering entries, and a reply that lands after
-- a flush; PSPU §6.7 "The cache" and §6.B's positive-TTL cap.
--
-- Harness: the scripted gateway (helpers.gateway) is the network and its
-- DNS server (helpers.dns), offered by DHCP option 6 as 10.77.0.1; the
-- gateway also carries 10.77.0.2 (the fallback server, from the
-- registry) and 10.77.0.3 (a replacement server for the lease). Answers
-- come from the zone below, and from a hook for the names whose replies
-- are bent (SERVFAIL, truncated, held back). Questions are asked with
-- `resolv query` while the gateway pumps, and `source` in its output
-- tells a hit (`cache`) from a question that went upstream (`dns`); the
-- gateway's query log says what reached a server.
--
-- Names outside example.test (the image's background NTP names) are
-- answered NXDOMAIN without an SOA, a zero lifetime, so they never take
-- a cache entry and `cache_entries` moves only for the test's names.
-- Negative answers under example.test carry an SOA (TTL and MINIMUM 30)
-- except for the `nosoa-` names.
--
-- A held reply is a UDP reply given a long `delay`, which parks it in
-- the gateway's pending list; the test releases it by making it due.
-- resolvd's transaction lives for 2 s, so whatever must happen before
-- the reply lands (a flush, a change of servers) has that long.
--
-- The scope tests come last: they move the lease's servers with DHCP
-- renewals, and the fallback scope stands in when the lease has none.
--
-- Own VMs: the lease's DNS servers are changed.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")
local rtnl = require("helpers.rtnl")

peinit.claim(2)

local SOCK = "/run/resolvd/resolv.sock"

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
-- rtnl, not ntfe.if_addr: on eth0 the latter replaces the primary address.
assert(rtnl.add_address(gw.vm, gw.ifindex, "10.77.0.2", { prefix = 24 }), "gateway address 10.77.0.2")
assert(rtnl.add_address(gw.vm, gw.ifindex, "10.77.0.3", { prefix = 24 }), "gateway address 10.77.0.3")
local dhcp = gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })

local function A(addr, ttl) return { type = "A", ttl = ttl or 60, data = addr } end
local zone = {
    ["mixed.example.test"] = { A("10.77.0.80"), { type = "AAAA", ttl = 60, data = "fd77::80" } },
    ["key.example.test"] = { A("10.77.0.81"), { type = "AAAA", ttl = 60, data = "fd77::81" } },
    ["short.example.test"] = { A("10.77.0.82") },
    ["other.example.test"] = { A("10.77.0.83") },
    ["two.example.test"] = { A("10.77.1.1", 8), A("10.77.1.2", 4) },
    ["big.example.test"] = { A("10.77.1.3", 100000) },
    ["ttl.example.test"] = { A("10.77.1.4", 60) },
    ["zero.example.test"] = { A("10.77.1.5", 0) },
    ["nosoa-nodata.example.test"] = { { type = "AAAA", ttl = 60, data = "fd77::85" } },
    ["nc.example.test"] = { A("10.77.1.6") },
    ["doors.example.test"] = { A("10.77.1.9"), { type = "AAAA", ttl = 60, data = "fd77::1:9" } },
    ["9.1.77.10.in-addr.arpa"] = { { type = "PTR", ttl = 60, data = "doors.example.test" } },
    ["linger.example.test"] = { A("10.77.1.7", 2) },
    ["late.example.test"] = { A("10.77.1.8") },
    ["pre.example.test"] = { A("10.77.1.10") },
    ["inflight.example.test"] = { A("10.77.1.11") },
    ["servfail.example.test"] = { A("10.77.1.12") },
    ["tcfail.example.test"] = { A("10.77.1.13") },
}

local hold = {}   -- lower-case names whose UDP replies are held back

dns.serve(gw, {
    zone = zone,
    on = function(q, default, ctx)
        local qn = q.questions[1]
        local n = qn and qn.name:lower() or ""
        if not n:match("example%.test$") and not n:match("in%-addr%.arpa$") then
            return nil                                  -- NXDOMAIN, no SOA: never stored
        end
        if n == "servfail.example.test" then
            default.rcode, default.answers = dns.RCODE.SERVFAIL, {}
            return default
        end
        if n == "tcfail.example.test" then
            if ctx.transport == "tcp" then return false end   -- close: the retry fails
            default.tc, default.no_truncate = true, true      -- TC, with the A record in it
            return default
        end
        if (default.rcode == dns.RCODE.NXDOMAIN or #default.answers == 0) and not n:match("^nosoa%-") then
            default.authority = { { name = "example.test", type = "SOA", ttl = 30, data = { minimum = 30 } } }
        end
        if hold[n] and ctx.transport == "udp" then default.delay = 1000 end
        return default
    end,
})

local sut = network.boot({ bridges = { lan }, gateway = gw })

local function rstatus()
    local s, err = network.call(sut, { query = "status" }, { path = SOCK })
    assert(s and s.ok ~= false, "resolvd status: " .. tostring(err or (s and s.error)))
    return s
end
local function entries() return rstatus().cache_entries end

--- Run a shell command in the guest while the gateway pumps.
local function served(cmd, timeout)
    local p = sut:run_async("sh", { args = { "-c", cmd } })
    gw:serve({ timeout = timeout or 20, until_ = function() return p:status() == "exited" end })
    return p:wait(5)
end

--- Parse `resolv query` output (TRM §8.1): the summary line, then records.
local function parse(text)
    local out = { records = {} }
    local first = text:match("^[^\n]*")
    out.outcome, out.source = first:match("^(%S+)%s+(%S+)")
    out.server = first:match(" via (%S+)")
    out.iface = first:match(" on (%S+)")
    for line in text:gmatch("[^\n]+") do
        local n, ttl, ty, data = line:match("^(%S+)\t(%d+)\t(%S+)\t(.*)$")
        if n then out.records[#out.records + 1] = { name = n, ttl = tonumber(ttl), type = ty, text = data } end
    end
    return out
end

local function query(t, name, rtype, extra)
    local r = served("resolv query " .. name .. " " .. (rtype or "A") .. (extra and (" " .. extra) or ""))
    local out = parse(r.stdout)
    out.exit = r.exit_code
    t:log(string.format("resolv query %s %s%s -> %s", name, rtype or "A", extra and (" " .. extra) or "",
        (r.stdout .. r.stderr):gsub("\n", " | ")))
    return out
end

--- The questions for `name` (any case) and `rtype` that reached a server.
local function asked(name, rtype)
    return dns.queries(gw, function(e)
        local q = e.msg and e.msg.questions[1]
        return q and dns.same_name(q.name, name) and (not rtype or q.type == dns.TYPE[rtype])
    end)
end

local function list(xs) return table.concat(xs or {}, ",") end

--- Pump until resolvd's first scope has exactly `servers`.
local function servers_become(t, servers, what)
    local last
    local ok = gw:serve({ timeout = 30, until_ = function()
        local s = rstatus().scopes or {}
        last = s[1] and list(s[1].servers) or "(no scope)"
        return last == list(servers)
    end })
    t:assert(ok, what .. ": the scope's servers are [" .. list(servers) .. "] (have [" .. tostring(last) .. "])")
end

--- Give the lease `servers` (false: none) and renew it.
local function lease_servers(t, servers)
    dhcp.dns = servers
    local r = network.call(sut, { query = "renew", interface = "eth0" })
    t:assert(r and r.ok, "netd accepted the renewal")
    servers_become(t, servers or {}, "after the renewal")
end

--- Release every held UDP reply now.
local function release()
    local n = 0
    for _, p in ipairs(gw.dns_pending or {}) do
        if p.due > gw.vm:clock():get() + 100 then p.due = 0; n = n + 1 end
    end
    return n
end

local function uptimes(text)
    local out = {}
    for a in text:gmatch("(%d+%.%d+) %d+%.%d+") do out[#out + 1] = tonumber(a) end
    return out
end

test("a name asked in any case through an expansion is cached under the expanded name, and the reverse",
    { spec = "resolvd *engine-cache.expansions-cached-under-expanded-name" }, function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound a lease")
        servers_become(t, { "10.77.0.1" }, "the lease's server")
        network.write(sut, "Dns", { ExtraSearchDomains = "multi:example.test" })
        t:assert(gw:serve({ timeout = 10, until_ = function()
            return query(t, "short", "A").outcome == "found"
        end }), "the search domain is in use")
        t:assert_eq(#asked("short", "A"), 0, "the single label was never sent bare")
        t:assert_eq(#asked("short.example.test", "A"), 1, "its expansion was asked once")
        local r = query(t, "short.example.test", "A")
        t:assert_eq(r.source, "cache", "the expanded name, asked as itself, is a hit")
        t:assert_eq(#asked("short.example.test", "A"), 1, "and was not asked again")

        r = query(t, "other.example.test", "A")
        t:assert_eq(r.source, "dns", "other.example.test asked as itself goes upstream")
        r = query(t, "other", "A")
        t:assert_eq(r.source, "cache", "the single label's expansion finds it in the cache")
        t:assert_eq(#asked("other.example.test", "A"), 1, "other.example.test was asked once")
        network.delete(sut, "Dns")
    end)

test("positive answers live for their least TTL, capped at 86 400 s; the records keep the TTLs the server sent",
    { spec = "resolvd *engine-cache.positive-lifetime resolvd *engine-cache.record-ttls-kept-entry-lifetime-capped PSPU *nri-resolution.positive-ttl-least-capped PSPU *nri-limits.positive-ttl-cap" },
    function(t)
        local r = served("resolv query two.example.test A; resolv query two.example.test A; sleep 5; resolv query two.example.test A")
        -- Split the output at each summary line.
        local parts, cur = {}, nil
        for line in r.stdout:gmatch("[^\n]+") do
            if not line:find("\t", 1, true) then cur = { line }; parts[#parts + 1] = cur else cur[#cur + 1] = line end
        end
        t:log(r.stdout)
        t:assert_eq(#parts, 3, "three answers")
        local first, hit, later = parse(table.concat(parts[1], "\n")), parse(table.concat(parts[2], "\n")),
            parse(table.concat(parts[3], "\n"))
        local function ttls(a)
            local m = {}
            for _, rec in ipairs(a.records) do m[rec.text] = rec.ttl end
            return m
        end
        t:assert_eq(first.source, "dns", "the first answer is the server's")
        t:assert(ttls(first)["10.77.1.1"] == 8 and ttls(first)["10.77.1.2"] == 4, "with the TTLs it sent (8 and 4)")
        t:assert_eq(hit.source, "cache", "asked again at once: a hit")
        t:assert(ttls(hit)["10.77.1.1"] <= 3 and ttls(hit)["10.77.1.2"] <= 3,
            "both records are lowered to what is left of a 4-second lifetime, the least TTL")
        t:assert_eq(later.source, "dns", "five seconds on, the entry has expired: the 8-second record did not keep it")

        local big = query(t, "big.example.test", "A")
        t:assert_eq(big.source, "dns", "big.example.test from the server")
        t:assert_eq(big.records[1] and big.records[1].ttl, 100000, "as sent: 100 000, the record is not capped")
        local again = query(t, "big.example.test", "A")
        t:assert_eq(again.source, "cache", "a hit")
        local ttl = again.records[1] and again.records[1].ttl
        t:assert(ttl and ttl >= 86395 and ttl <= 86400,
            "the entry lives 86 400 s, not 100 000: the hit reports " .. tostring(ttl))
    end)

test("a hit reports each TTL lowered to the whole seconds the entry has left",
    { spec = "resolvd *engine-cache.hit-ttl-lowered-to-remaining-seconds PSPU *nri-resolution.cache-hit-ttl-reduced" },
    function(t)
        local r = served("cat /proc/uptime; resolv query ttl.example.test A; cat /proc/uptime; sleep 3; "
            .. "cat /proc/uptime; resolv query ttl.example.test A; cat /proc/uptime")
        t:log(r.stdout)
        local u = uptimes(r.stdout)
        t:assert_eq(#u, 4, "four uptime readings")
        local a, b = {}, {}
        local which = a
        for line in r.stdout:gmatch("[^\n]+") do
            if line:match("^found") and #a > 0 then which = b end
            if not line:match("^%d+%.%d+ %d") then which[#which + 1] = line end
        end
        local first, hit = parse(table.concat(a, "\n")), parse(table.concat(b, "\n"))
        t:assert_eq(first.source, "dns", "stored from the server")
        t:assert_eq(first.records[1].ttl, 60, "the server's TTL, 60")
        t:assert_eq(hit.source, "cache", "a hit")
        -- The entry was stored between readings 1 and 2 and read between
        -- 3 and 4, so its age at the hit lies within these bounds.
        local lo, hi = math.floor(60 - (u[4] - u[1])), math.floor(60 - (u[3] - u[2]))
        local ttl = hit.records[1].ttl
        t:assert(ttl >= lo and ttl <= hi, string.format("TTL %d is 60 less the time in cache, rounded down: within [%d, %d]",
            ttl, lo, hi))
        t:assert(ttl < 60, "lowered")
    end)

test("an answer with a zero lifetime is not stored: a zero TTL, and a negative answer with no SOA",
    { spec = "resolvd *engine-cache.zero-lifetime-not-stored resolvd *engine-cache.no-soa-negative-lifetime-zero" },
    function(t)
        local before = entries()
        for _, c in ipairs({ { "zero.example.test", "found" }, { "nosoa-nx.example.test", "notfound" },
                             { "nosoa-nodata.example.test", "found" } }) do
            local r1 = query(t, c[1], "A")
            local r2 = query(t, c[1], "A")
            t:assert(r1.outcome == c[2] and r2.outcome == c[2], c[1] .. " is " .. c[2])
            t:assert(r1.source == "dns" and r2.source == "dns", c[1] .. ": asked twice, both from the server")
            t:assert_eq(#asked(c[1], "A"), 2, c[1] .. " reached the server twice")
        end
        t:assert_eq(entries(), before, "nothing was stored")
    end)

test("never stored: synthetic answers, unavailable, a transport failure, a truncated UDP reply, other response codes",
    { spec = "resolvd *engine-cache.never-stored" }, function(t)
        network.write(sut, "Dns", {})
        network.write(sut, "Dns\\Hosts", { ["static.example.test"] = "sz:10.77.9.9" })
        t:assert(gw:serve({ timeout = 10, until_ = function()
            return query(t, "static.example.test", "A").source == "hosts"
        end }), "the static name is in use")
        local before = entries()
        t:assert_eq(query(t, "localhost", "A").source, "synthetic", "localhost is synthetic")
        t:assert_eq(query(t, "static.example.test", "A").source, "hosts", "the static name answers from hosts")
        t:assert_eq(entries(), before, "neither was stored")

        -- SERVFAIL three times: unavailable, and asked afresh next time.
        local s1 = query(t, "servfail.example.test", "A")
        t:assert_eq(s1.outcome, "unavailable", "three SERVFAILs: unavailable")
        local n = #asked("servfail.example.test")
        t:assert_eq(n, 3, "three attempts")
        local s2 = query(t, "servfail.example.test", "A")
        t:assert_eq(s2.outcome, "unavailable", "unavailable again")
        t:assert_eq(#asked("servfail.example.test"), 6, "asked afresh: neither SERVFAIL nor unavailable was stored")

        -- A truncated UDP reply carrying a record, whose TCP retry fails:
        -- a transport failure each time, unavailable after three.
        local c1 = query(t, "tcfail.example.test", "A")
        t:assert_eq(c1.outcome, "unavailable", "every TCP retry fails: unavailable")
        local udp = #asked("tcfail.example.test")
        local c2 = query(t, "tcfail.example.test", "A")
        t:assert_eq(c2.outcome, "unavailable", "unavailable again, not the truncated reply's record")
        t:assert(#asked("tcfail.example.test") > udp, "asked afresh: the TC reply was not stored")
        t:assert_eq(entries(), before, "the cache did not grow")
        network.delete(sut, "Dns")
    end)

test("--no-cache skips the lookup, and the reply it gets is still stored",
    { spec = "resolvd *engine-cache.no-cache-skips-lookup-still-stores" }, function(t)
        t:assert_eq(query(t, "nc.example.test", "A").source, "dns", "first asked upstream")
        t:assert_eq(query(t, "nc.example.test", "A").source, "cache", "then held")
        zone["nc.example.test"][1].data = "10.77.1.66"
        local r = query(t, "nc.example.test", "A", "--no-cache")
        t:assert_eq(r.source, "dns", "--no-cache goes upstream although an entry is held")
        t:assert_eq(r.records[1] and r.records[1].text, "10.77.1.66", "and gets the new answer")
        t:assert_eq(#asked("nc.example.test", "A"), 2, "two questions reached the server")
        r = query(t, "nc.example.test", "A")
        t:assert_eq(r.source, "cache", "the next question is a hit")
        t:assert_eq(r.records[1] and r.records[1].text, "10.77.1.66", "on the entry --no-cache stored")
    end)

test("stub queries, lookup and reverse consult the cache",
    { spec = "resolvd *engine-cache.other-doors-always-consult-cache" }, function(t)
        t:assert_eq(query(t, "doors.example.test", "A").source, "dns", "the A record stored")
        t:assert_eq(query(t, "9.1.77.10.in-addr.arpa", "PTR").source, "dns", "the PTR record stored")
        local hits = rstatus().counters.cache_hits

        local fd = assert(ntfe.udp_connect(sut, "127.0.0.53", 53))
        ntfe.send(sut, fd, dns.encode(dns.query("doors.example.test", "A", { id = 777 })))
        local got
        gw:serve({ timeout = 5, until_ = function() got = ntfe.recv(sut, fd, 50, 4096); return got ~= nil end })
        sys.close(sut, fd)
        local m = got and dns.decode(got)
        t:assert(m and m.id == 777 and #m.answers == 1, "the stub door answered")

        local l = served("resolv lookup doors.example.test")
        t:log("lookup: " .. l.stdout)
        t:assert(l.stdout:find("10.77.1.9", 1, true), "lookup found the address")
        local v = served("resolv reverse 10.77.1.9")
        t:log("reverse: " .. v.stdout)
        t:assert(v.stdout:match("^found%s+cache"), "reverse answered from the cache")
        t:assert(v.stdout:find("doors.example.test", 1, true), "with the cached PTR")
        t:assert_eq(#asked("doors.example.test", "A"), 1, "the A record was asked upstream only once")
        t:assert_eq(#asked("9.1.77.10.in-addr.arpa", "PTR"), 1, "the PTR only once")
        t:assert_eq(#asked("doors.example.test", "AAAA"), 1, "lookup's AAAA half, never cached, went upstream")
        t:assert_eq(rstatus().counters.cache_hits, hits + 3, "three cache hits: stub, lookup's A, reverse")
    end)

test("expired entries stay, counted, until something replaces them",
    { spec = "resolvd *engine-cache.expired-entries-linger-and-are-counted" }, function(t)
        local before = entries()
        t:assert_eq(query(t, "linger.example.test", "A").source, "dns", "a 2-second answer stored")
        t:assert_eq(entries(), before + 1, "one entry more")
        gw:serve({ timeout = 4 })
        t:assert_eq(entries(), before + 1, "four seconds on, the expired entry is still counted")
        local r = query(t, "linger.example.test", "A")
        t:assert_eq(r.source, "dns", "but it is not served: the question goes upstream")
        t:assert_eq(entries(), before + 1, "the fresh answer replaced it")
    end)

test("a reply that arrives after a flush is stored, under the same scope",
    { spec = "resolvd *engine-cache.late-reply-stored-after-flush" }, function(t)
        hold["late.example.test"] = true
        local p = sut:run_async("sh", { args = { "-c", "resolv query late.example.test A" } })
        t:assert(gw:serve({ timeout = 10, until_ = function() return #asked("late.example.test") > 0 end }),
            "the question reached the server, whose reply is held")
        local f = sut:run("resolv flush")
        t:assert_eq(f.exit_code, 0, "flushed")
        t:assert_eq(entries(), 0, "the cache is empty")
        t:assert_eq(release(), 1, "the held reply is released")
        hold["late.example.test"] = nil
        gw:serve({ timeout = 10, until_ = function() return p:status() == "exited" end })
        local r = parse(p:wait(5).stdout)
        t:assert(r.source == "dns" and r.server == "10.77.0.1", "the late reply answered the question")
        t:assert_eq(#asked("late.example.test"), 1, "on the first attempt (it landed in time)")
        t:assert_eq(entries(), 1, "and it was stored after the flush")
        local again = query(t, "late.example.test", "A")
        t:assert_eq(again.source, "cache", "the next question is a hit")
        t:assert_eq(again.iface, "eth0", "under the scope it was asked through")
    end)

test("an entry's key is the candidate in lower case, the record type and the scope; the class is not in it",
    { spec = "resolvd *engine-cache.key-is-lowercase-candidate-type-scope PSPU *nri-resolution.cache-keyed-by-name-type-scope" },
    function(t)
        -- The lease loses its server: the fallback scope takes questions.
        network.write(sut, "Dns", { FallbackServers = "multi:10.77.0.2" })
        lease_servers(t, false)
        local r = query(t, "Key.Example.TEST", "A")
        t:assert(r.source == "dns" and r.server == "10.77.0.2", "asked through the fallback scope")
        r = query(t, "key.example.test", "A")
        t:assert(r.source == "cache" and r.server == "10.77.0.2", "another case of the name is the same entry")
        r = query(t, "KEY.example.test", "AAAA")
        t:assert_eq(r.source, "dns", "another type is another entry")
        for _, q in ipairs(asked("key.example.test")) do
            t:assert_eq(q.msg.questions[1].class, dns.CLASS.IN, "every question upstream is class IN")
        end
        -- A stub question of class CH finds the IN entry.
        local hits = rstatus().counters.cache_hits
        local fd = assert(ntfe.udp_connect(sut, "127.0.0.53", 53))
        ntfe.send(sut, fd, dns.encode(dns.query("key.example.test", "A", { id = 778, class = dns.CLASS.CH })))
        local got
        gw:serve({ timeout = 5, until_ = function() got = ntfe.recv(sut, fd, 50, 4096); return got ~= nil end })
        sys.close(sut, fd)
        t:assert(got ~= nil, "the stub door answered the CH question")
        t:assert_eq(rstatus().counters.cache_hits, hits + 1, "from the class-IN entry")
        t:assert_eq(#asked("key.example.test", "A"), 1, "nothing more went upstream")

        -- The lease's server returns: the same name and type, another scope.
        lease_servers(t, { "10.77.0.1" })
        r = query(t, "key.example.test", "A")
        t:assert(r.source == "dns" and r.server == "10.77.0.1" and r.iface == "eth0",
            "through eth0's scope it is asked upstream: the fallback scope's entry is not its")
        -- The lease's server goes again: the fallback scope's entry is still there.
        lease_servers(t, false)
        r = query(t, "key.example.test", "A")
        t:assert(r.source == "cache" and r.server == "10.77.0.2",
            "back on the fallback scope, its own entry is a hit")
        t:assert_eq(#asked("key.example.test", "A"), 2, "two questions upstream in all, one per scope")
        lease_servers(t, { "10.77.0.1" })
        network.delete(sut, "Dns")
    end)

test("when a scope's servers change, every answer learned through it is discarded, a reply still in flight included",
    { spec = "PSPU *nri-resolution.cache-discarded-with-scope", tags = { "known-bug" } }, function(t)
        servers_become(t, { "10.77.0.1" }, "eth0 has its lease's server")
        t:assert_eq(query(t, "pre.example.test", "A").source, "dns", "an answer learned through eth0")
        t:assert_eq(query(t, "pre.example.test", "A").source, "cache", "held")

        hold["inflight.example.test"] = true
        local p = sut:run_async("sh", { args = { "-c", "resolv query inflight.example.test A" } })
        t:assert(gw:serve({ timeout = 10, until_ = function() return #asked("inflight.example.test") > 0 end }),
            "a question is in flight to 10.77.0.1, its reply held")
        local sent = asked("inflight.example.test")[1].at
        dhcp.dns = { "10.77.0.3" }
        t:assert((network.call(sut, { query = "renew", interface = "eth0" }) or {}).ok, "renewal accepted")
        servers_become(t, { "10.77.0.3" }, "the lease's servers change")
        local changed = gw.vm:clock():get()
        t:log(string.format("servers changed %.2f s after the question was sent", changed - sent))
        t:assert(changed - sent < 1.8, "the change landed inside the transaction's 2 s (else the test proves nothing)")
        t:assert_eq(release(), 1, "the old server's reply is released")
        hold["inflight.example.test"] = nil
        gw:serve({ timeout = 10, until_ = function() return p:status() == "exited" end })
        local r = parse(p:wait(5).stdout)
        t:assert(r.source == "dns" and r.server == "10.77.0.1", "the old server's late reply answered the asker")

        local pre = query(t, "pre.example.test", "A")
        t:assert(pre.source == "dns" and pre.server == "10.77.0.3", "what was learned before the change is discarded")
        local late = query(t, "inflight.example.test", "A")
        -- PEI-1339: resolvd stores the old server's late reply under the
        -- scope after the change, and serves it: `found cache via 10.77.0.1`.
        t:assert(late.source == "dns" and late.server == "10.77.0.3",
            "the reply learned from the old server is not served after the change (got "
            .. tostring(late.source) .. " via " .. tostring(late.server) .. ")")
    end)
