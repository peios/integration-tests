-- resolvd TRM §4.5 "Capacity and eviction" and the negative lifetime's
-- cap; PSPU §6.B's cache-entries and negative-TTL-cap rows.
--
-- Harness: the scripted gateway (helpers.gateway) runs the machine's
-- only DNS server (helpers.dns, offered by DHCP option 6), and a whole
-- Peios (helpers.network). The cache is filled through the stub door:
-- the agent sends queries to 127.0.0.53 from one UDP socket in batches
-- of 200 (well under resolvd's 1 024 descriptors) and never reads the
-- replies; the gateway answers each from a hook, so the TTL of every
-- entry is chosen by its name. `status`'s `cache_entries` is the count.
--
-- Every name the test does not own (the image's background NTP names)
-- is answered NXDOMAIN with no SOA, a zero lifetime that is never
-- stored, so every entry in the cache is the test's.
--
-- Names are `<letter><ttl>-<n>.fill.test`, an A record with that TTL:
--   e1750  the designated earliest entry
--   s1800  "short" fillers        l7200  "long" fillers
--   o<ttl> overflow entries, each a little shorter than the last
--   p320, m3600, d86400, t295, t310  single entries for the sweep steps
-- and three negative names with an SOA whose TTL and MINIMUM are set:
--   nxcap  NXDOMAIN, SOA TTL 100 000, MINIMUM 100 000 (capped to 300)
--   nxttl  NXDOMAIN, SOA TTL 290, MINIMUM 100 000 (290, the lesser)
--   nxmin  NODATA,   SOA TTL 100 000, MINIMUM 285 (285, the lesser)
--
-- A full cache is fragile: storing any new key at 8 192 sweeps every
-- entry due to expire a second or more before the new one. So the steps
-- are ordered, each starts from the state the last one left, and every
-- check that must not store anything is asked in "verify" mode, in
-- which the gateway answers with TTL 0 (a zero lifetime is not stored):
-- `source` then tells a hit (`cache`) from a miss (`dns`).
--
-- The 300-second negative cap cannot be waited out in a test, so the
-- sweep is the instrument: negative entries stored next to positive
-- entries of known lifetime, then a positive entry of a chosen TTL
-- stored at a full cache. Which of them it sweeps brackets their
-- lifetimes.
--
-- Own VMs: two whole fills of the cache.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local ntfe = require("helpers.ntfe")

peinit.claim(2)

local CAP = 8192
local SOCK = "/run/resolvd/resolv.sock"

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })

local verify = false   -- answer every owned name with TTL 0
local answered = 0     -- owned questions the gateway has answered

local function soa(ttl, minimum)
    return { { name = "fill.test", type = "SOA", ttl = ttl, data = { minimum = minimum } } }
end

dns.serve(gw, {
    on = function(q, default)
        local qn = q.questions[1]
        local label = qn and qn.name:lower():match("^([^.]+)%.fill%.test$")
        if not label then return nil end   -- NXDOMAIN, no SOA: never stored
        answered = answered + 1
        default.answers, default.authority = {}, {}
        local function negative(rcode, ttl, minimum)
            -- In verify mode without the SOA: a zero lifetime, not stored.
            default.rcode, default.authority = rcode, verify and {} or soa(ttl, minimum)
        end
        if label == "nxcap" then
            negative(dns.RCODE.NXDOMAIN, 100000, 100000)
        elseif label == "nxttl" then
            negative(dns.RCODE.NXDOMAIN, 290, 100000)
        elseif label == "nxmin" then
            negative(dns.RCODE.NOERROR, 100000, 285)
        else
            local ttl = assert(tonumber(label:match("^%a+(%d+)")), "a fill name carries its TTL")
            default.rcode = dns.RCODE.NOERROR
            default.answers = { { name = qn.name, type = "A", ttl = verify and 0 or ttl, data = "10.77.1.1" } }
        end
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

--- `resolv query`'s output, parsed (TRM §8.1).
local function query(name, opts)
    local r = served("resolv query " .. name .. " A" .. ((opts and opts.no_cache) and " --no-cache" or ""))
    local out = { exit = r.exit_code, raw = r.stdout .. r.stderr, records = {} }
    local first = r.stdout:match("^[^\n]*")
    out.outcome, out.source = first:match("^(%S+)%s+(%S+)")
    out.server = first:match(" via (%S+)")
    for line in r.stdout:gmatch("[^\n]+") do
        local n, ttl, ty, text = line:match("^(%S+)\t(%d+)\t(%S+)\t(.*)$")
        if n then out.records[#out.records + 1] = { name = n, ttl = tonumber(ttl), type = ty, text = text } end
    end
    return out
end

local function name(prefix, n) return string.format("%s-%d.fill.test", prefix, n) end

--- Whether `name` is answered from the cache, asked without storing.
local function cached(t, nm)
    verify = true
    local r = query(nm)
    verify = false
    t:log(string.format("%s: %s %s", nm, tostring(r.outcome), tostring(r.source)))
    return r.source == "cache", r
end

local stub = assert(ntfe.udp_connect(sut, "127.0.0.53", 53))
local next_id = 0

--- Store `n` new entries named `prefix-<from..from+n-1>` through the stub
--- door, 200 at a time, and wait until every one is in the cache. Only
--- for a cache with room for them all: nothing here may evict.
local function fill(t, prefix, from, n)
    local target = entries() + n
    t:assert(target <= CAP, string.format("fill %s: %d more fit (%d)", prefix, n, target))
    local i, last = from, from + n - 1
    while i <= last do
        local batch = math.min(200, last - i + 1)
        local before = entries()
        for k = i, i + batch - 1 do
            next_id = (next_id + 1) % 65536
            ntfe.send(sut, stub, dns.encode(dns.query(name(prefix, k), "A", { id = next_id })))
        end
        i = i + batch
        local ok = gw:serve({ timeout = 30, until_ = function() return entries() >= before + batch end })
        t:assert(ok, string.format("fill %s: batch of %d stored (cache %d)", prefix, batch, entries()))
    end
    t:assert_eq(entries(), target, "fill " .. prefix .. ": the cache holds exactly what was stored")
end

-- What the steps share.
local S, L = 4096, 0   -- short and long fillers stored

test("the cache holds 8 192 entries; a new key at a full cache with nothing to sweep evicts the one earliest-expiring entry",
    { spec = "resolvd *engine-cache.capacity resolvd *engine-cache.eviction-then-earliest-expiry PSPU *nri-limits.cache-entries" },
    function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound a lease")
        t:assert(gw:serve({ timeout = 20, until_ = function()
            local s = rstatus().scopes or {}
            return s[1] ~= nil and (s[1].servers or {})[1] == "10.77.0.1"
        end }), "resolvd has the lease's server")
        t:assert_eq(entries(), 0, "the cache starts empty (background names are never stored)")

        -- The designated earliest, then the fill: shorts, then longs to 8 192.
        local r = query(name("e1750", 0))
        t:assert_eq(r.source, "dns", "the designated earliest entry is asked upstream")
        local c0 = os.time()
        fill(t, "s1800", 1, S)
        L = CAP - entries()
        fill(t, "l7200", 1, L)
        t:log(string.format("filled %d entries (%d short, %d long) in ~%d s", CAP, S, L, os.time() - c0))
        t:assert_eq(entries(), CAP, "full at 8 192")

        -- Five more keys, one at a time, each expiring before everything
        -- held: the sweep finds nothing, so each evicts the earliest.
        for k = 1, 5 do
            local o = query(name("o" .. (1700 - 2 * k), 0))
            t:assert_eq(o.source, "dns", "overflow " .. k .. " asked upstream")
            t:assert_eq(entries(), CAP, "after overflow " .. k .. " the cache still holds 8 192")
        end
        local hit
        hit = cached(t, name("e1750", 0))
        t:assert(not hit, "the designated earliest entry was evicted by the first overflow")
        for k = 1, 4 do
            hit = cached(t, name("o" .. (1700 - 2 * k), 0))
            t:assert(not hit, "overflow " .. k .. " was the earliest when overflow " .. (k + 1) .. " came, and was evicted")
        end
        t:assert((cached(t, name("o1690", 0))), "the last overflow entry is held")
        t:assert((cached(t, name("s1800", 1))), "the first short filler is held")
        t:assert((cached(t, name("l7200", 1))), "the first long filler is held")
        t:assert_eq(entries(), CAP, "verification stored nothing")
    end)

test("storing under a key the full cache already holds replaces it and evicts nothing",
    { spec = "resolvd *engine-cache.overwrite-evicts-nothing" }, function(t)
        t:assert_eq(entries(), CAP, "the cache is full")
        local _, before = cached(t, name("s1800", 2))
        local old_ttl = before.records[1] and before.records[1].ttl
        t:assert(old_ttl and old_ttl < 1795, "the held entry has aged: TTL " .. tostring(old_ttl))
        local r = query(name("s1800", 2), { no_cache = true })
        t:assert_eq(r.source, "dns", "--no-cache asks upstream")
        t:assert_eq(entries(), CAP, "the cache still holds 8 192")
        local hit, after = cached(t, name("s1800", 2))
        t:assert(hit, "the overwritten key is held")
        local new_ttl = after.records[1] and after.records[1].ttl
        t:assert(new_ttl and new_ttl >= 1795 and new_ttl > old_ttl,
            string.format("its entry is the new one: TTL %s, was %s", tostring(new_ttl), tostring(old_ttl)))
        t:assert((cached(t, name("o1690", 0))), "the earliest-expiring entry was not evicted")
    end)

test("a new key at a full cache sweeps every entry expiring a second or more before it, live or not",
    { spec = "resolvd *engine-cache.eviction-sweeps-against-new-expiry" }, function(t)
        t:assert_eq(entries(), CAP, "the cache is full")
        t:assert((cached(t, name("s1800", 3))), "a short filler is live before the sweep")
        local r = query(name("m3600", 0))
        t:assert_eq(r.source, "dns", "the new key is asked upstream")
        -- Swept: the 4 096 shorts and the overflow entry (all due before
        -- now + 3 599 s, all live); kept: the longs; then the new key.
        t:assert_eq(entries(), L + 1, string.format("only the %d long fillers and the new entry are left", L))
        t:assert(not (cached(t, name("s1800", 3))), "the live short filler was swept")
        t:assert(not (cached(t, name("o1690", 0))), "the overflow entry was swept")
        t:assert((cached(t, name("l7200", 3))), "a long filler, due after the new entry, is kept")
        t:assert((cached(t, name("m3600", 0))), "the new entry is held")
    end)

test("negative answers live for the lesser of the SOA's TTL and MINIMUM, capped at 300 s, for NXDOMAIN and NODATA alike",
    { spec = "resolvd *engine-cache.negative-lifetime-from-soa resolvd *engine-cache.nxdomain-uses-negative-lifetime resolvd *engine-cache.nodata-uses-negative-lifetime PSPU *nri-resolution.negative-ttl-soa-minimum-capped PSPU *nri-limits.negative-ttl-cap" },
    function(t)
        -- Room for exactly four: the three negative entries and p320.
        fill(t, "l7200", L + 1, CAP - 4 - entries())
        local nxcap = query("nxcap.fill.test")
        local nxttl = query("nxttl.fill.test")
        local nxmin = query("nxmin.fill.test")
        local p = query(name("p320", 0))
        t:log(string.format("nxcap %s/%s exit %s; nxttl %s/%s; nxmin %s/%s records %d",
            tostring(nxcap.outcome), tostring(nxcap.source), tostring(nxcap.exit), tostring(nxttl.outcome),
            tostring(nxttl.source), tostring(nxmin.outcome), tostring(nxmin.source), #nxmin.records))
        t:assert(nxcap.outcome == "notfound" and nxttl.outcome == "notfound", "NXDOMAIN is notfound")
        t:assert(nxmin.outcome == "found" and #nxmin.records == 0, "NODATA is found with no records")
        t:assert_eq(p.source, "dns", "p320 asked upstream")
        t:assert_eq(entries(), CAP, "all four stored: the cache is full")
        for _, n in ipairs({ "nxcap", "nxttl", "nxmin" }) do
            t:assert((cached(t, n .. ".fill.test")), n .. " is held")
        end

        -- A 295-second entry sweeps what is due before now + 294 s. A
        -- lifetime of 100 000 would survive it; so would one of 300.
        t:assert_eq(query(name("t295", 0)).source, "dns", "t295 asked upstream")
        t:assert_eq(entries(), CAP - 1, "exactly two entries swept, then one stored")
        t:assert(not (cached(t, "nxttl.fill.test")), "nxttl (SOA TTL 290 < MINIMUM 100 000) lived less than 295 s")
        t:assert(not (cached(t, "nxmin.fill.test")), "nxmin, NODATA (MINIMUM 285 < SOA TTL 100 000) lived less than 295 s")
        t:assert((cached(t, "nxcap.fill.test")), "nxcap (both 100 000) outlives a 295-second entry")
        t:assert((cached(t, name("p320", 0))), "p320 outlives it too")

        -- Full again, then a 310-second entry sweeps what is due before
        -- now + 309 s: nxcap and t295, but not p320.
        fill(t, "l7200", 10000, 1)
        t:assert_eq(query(name("t310", 0)).source, "dns", "t310 asked upstream")
        t:assert_eq(entries(), CAP - 1, "exactly two entries swept (nxcap, t295), then one stored")
        t:assert(not (cached(t, "nxcap.fill.test")), "nxcap is gone: its lifetime was capped below 310 s")
        t:assert((cached(t, name("p320", 0))), "p320 is kept: the sweep reached no further than it should")
        t:assert((cached(t, name("l7200", 1))), "the long fillers are kept")
    end)

test("a day-long answer arriving at a full cache of shorter-lived answers empties it",
    { spec = "resolvd *engine-cache.long-lived-entry-empties-full-cache" }, function(t)
        local room = CAP - entries()
        if room > 0 then fill(t, "l7200", 20000, room) end
        t:assert_eq(entries(), CAP, "the cache is full of shorter-lived answers")
        t:assert_eq(query(name("d86400", 0)).source, "dns", "the day-long answer is asked upstream")
        t:assert_eq(entries(), 1, "every other entry was swept")
        t:assert((cached(t, name("d86400", 0))), "the day-long answer is held")
        t:assert(not (cached(t, name("l7200", 2))), "a long filler is gone")
    end)
