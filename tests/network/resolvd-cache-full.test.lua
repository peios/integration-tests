-- resolvd TRM §4.5 "Capacity and eviction" and the negative lifetime's
-- cap; PSPU §6.B's cache-entries and negative-TTL-cap rows.
--
-- Harness: the scripted gateway (helpers.gateway) runs the machine's
-- only DNS server (helpers.dns, offered by DHCP option 6), and a whole
-- Peios (helpers.network). The cache is filled through the stub door:
-- the agent sends queries to 127.0.0.53 from one UDP socket in batches
-- of 16 (within the per-endpoint pending budget) and never reads the
-- replies; the gateway answers each from a hook, so the TTL of every
-- entry is chosen by its name. `status`'s `cache_entries` is the count.
--
-- Every name the test does not own (the image's background NTP names)
-- is answered NXDOMAIN with no SOA, a zero lifetime that is never
-- stored, so every entry in the cache is the test's.
--
-- Names normally carry their positive TTL: <letter><ttl>-<n>.fill.test.
-- Selected held keys are overwritten with short positive or negative
-- replies to test expiry and compare lifetimes without refilling the cache.
-- New keys at capacity remove expired entries, then only the earliest
-- live entry if still full. The incoming answer's lifetime is irrelevant.
--
-- In "verify" mode the gateway answers with a zero lifetime, so a cache
-- miss cannot insert a replacement and perturb subsequent observations.
-- The negative-lifetime test observes eviction order against positive
-- controls. It bounds the 300-second cap between 270 and 330 seconds
-- without a five-minute wait. Exact cap/expiry arithmetic is also covered
-- by engine host tests expanded_nodata_cname_uses_the_negative_lifetime_and_ages_with_the_cache
-- and hostile_ttls_and_missing_soa_are_bounded.
--
-- Own VMs: one whole fill of the cache.

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
local overrides = {}  -- alternate replies under already-held keys

local function soa(ttl, minimum)
    return { { name = "fill.test", type = "SOA", ttl = ttl, data = { minimum = minimum } } }
end

dns.serve(gw, {
    on = function(q, default)
        local qn = q.questions[1]
        local label = qn and qn.name:lower():match("^([^.]+)%.fill%.test$")
        if not label then return nil end   -- NXDOMAIN, no SOA: never stored
        default.answers, default.authority = {}, {}
        local function negative(rcode, ttl, minimum)
            -- In verify mode without the SOA: a zero lifetime, not stored.
            default.rcode, default.authority = rcode, verify and {} or soa(ttl, minimum)
        end
        local reply = overrides[label]
        if reply and reply.rcode then
            negative(reply.rcode, reply.ttl, reply.minimum)
        else
            local ttl = reply and reply.ttl or assert(tonumber(label:match("^%a+(%d+)")), "a fill name carries its TTL")
            default.rcode = dns.RCODE.NOERROR
            default.answers = { { name = qn.name, type = "A", ttl = verify and 0 or ttl, data = "10.77.1.1" } }
        end
        return default
    end,
})

local sut = network.boot({ bridges = { lan }, gateway = gw, files = network.test_binary("resolvd", {}) })

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
--- door, 16 at a time, and wait until every one is in the cache. Only
--- for a cache with room for them all: nothing here may evict.
local function fill(t, prefix, from, n)
    local target = entries() + n
    t:assert(target <= CAP, string.format("fill %s: %d more fit (%d)", prefix, n, target))
    local i, last = from, from + n - 1
    while i <= last do
        local batch = math.min(16, last - i + 1)
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
        t:assert(os.time() - c0 < 600, "fill completed before the overflow TTL can overtake a filler")

        -- Five more keys, one at a time, each expiring before everything
        -- held: the sweep finds nothing, so each evicts the earliest.
        for k = 1, 5 do
            local o = query(name("o" .. (900 - 2 * k), 0))
            t:assert_eq(o.source, "dns", "overflow " .. k .. " asked upstream")
            t:assert_eq(entries(), CAP, "after overflow " .. k .. " the cache still holds 8 192")
        end
        local hit
        hit = cached(t, name("e1750", 0))
        t:assert(not hit, "the designated earliest entry was evicted by the first overflow")
        for k = 1, 4 do
            hit = cached(t, name("o" .. (900 - 2 * k), 0))
            t:assert(not hit, "overflow " .. k .. " was the earliest when overflow " .. (k + 1) .. " came, and was evicted")
        end
        t:assert((cached(t, name("o890", 0))), "the last overflow entry is held")
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
        t:assert((cached(t, name("o890", 0))), "the earliest-expiring entry was not evicted")
    end)

test("a new key at a full cache removes expired entries without evicting a live entry when that makes room",
    { spec = "resolvd *engine-cache.eviction-sweeps-against-new-expiry" }, function(t)
        t:assert_eq(entries(), CAP, "the cache is full")
        -- Overwrite two existing keys: no capacity eviction happens here.
        for _, k in ipairs({ 4, 5 }) do
            overrides["s1800-" .. k] = { ttl = 2 }
            t:assert_eq(query(name("s1800", k), { no_cache = true }).source, "dns", "a held key now expires in two seconds")
        end
        gw:serve({ timeout = 4 })
        t:assert_eq(entries(), CAP, "untouched expired entries still count")
        t:assert((cached(t, name("o890", 0))), "the earliest live entry is still held")
        local r = query(name("m3600", 0))
        t:assert_eq(r.source, "dns", "the new key is asked upstream")
        t:assert_eq(entries(), CAP - 1, "two expired entries removed, one inserted")
        for _, k in ipairs({ 4, 5 }) do
            t:assert(not (cached(t, name("s1800", k))), "the expired entry was removed")
        end
        t:assert((cached(t, name("o890", 0))), "no extra live victim was needed")
        t:assert((cached(t, name("s1800", 3))), "the live short filler was not swept")
        t:assert((cached(t, name("l7200", 3))), "the long filler was not swept")
        t:assert((cached(t, name("m3600", 0))), "the new entry is held")
        t:assert_eq(entries(), CAP - 1, "verification stored nothing")
    end)

test("NXDOMAIN and NODATA use the lesser SOA TTL or MINIMUM and cap long negative lifetimes",
    { spec = "resolvd *engine-cache.negative-lifetime-from-soa resolvd *engine-cache.nxdomain-uses-negative-lifetime resolvd *engine-cache.nodata-uses-negative-lifetime PSPU *nri-resolution.negative-ttl-soa-minimum-capped PSPU *nri-limits.negative-ttl-cap" },
    function(t)
        fill(t, "l7200", 10000, CAP - entries())
        -- All nine keys already exist. Replacing them avoids an admission
        -- eviction until all the comparison lifetimes have been installed.
        local cases = {
            { k = 10, rcode = dns.RCODE.NXDOMAIN, ttl = 190, minimum = 100000 },
            { k = 11, rcode = dns.RCODE.NXDOMAIN, ttl = 100000, minimum = 190 },
            { k = 12, rcode = dns.RCODE.NOERROR, ttl = 190, minimum = 100000 },
            { k = 13, rcode = dns.RCODE.NOERROR, ttl = 100000, minimum = 190 },
            { k = 14, rcode = dns.RCODE.NXDOMAIN, ttl = 100000, minimum = 100000 },
            { k = 15, rcode = dns.RCODE.NOERROR, ttl = 100000, minimum = 100000 },
            { k = 16, ttl = 160 }, { k = 17, ttl = 270 }, { k = 18, ttl = 330 },
        }
        local started = os.time()
        for _, c in ipairs(cases) do
            overrides["s1800-" .. c.k] = c
            local r = query(name("s1800", c.k), { no_cache = true })
            t:assert_eq(r.source, "dns", "the held key was overwritten upstream")
            if c.rcode == dns.RCODE.NXDOMAIN then
                t:assert_eq(r.outcome, "notfound", "NXDOMAIN is notfound")
            elseif c.rcode then
                t:assert(r.outcome == "found" and #r.records == 0, "NODATA is found with no records")
            end
            t:assert((cached(t, name("s1800", c.k))), "the replacement is cached")
            t:assert_eq(entries(), CAP, "overwriting did not evict a neighbour")
        end
        local overflow = 0
        local function evict(n)
            for _ = 1, n do
                overflow = overflow + 1
                t:assert_eq(query(name("v1000", overflow)).source, "dns", "overflow asked upstream")
                t:assert_eq(entries(), CAP, "one live victim per new key")
            end
        end
        local function held(k) return cached(t, name("s1800", k)) end
        evict(1)
        t:assert(not held(16), "the 160-second control expires before the negative answers")
        for k = 10, 15 do t:assert(held(k), "negative answer outlives the 160-second control") end
        evict(4)
        for k = 10, 13 do t:assert(not held(k), "the lesser SOA field bounds both NXDOMAIN and NODATA") end
        t:assert(held(17), "the 270-second control outlives the 190-second negative answers")
        t:assert(held(14) and held(15), "both capped answers outlive the shorter negatives")
        evict(1)
        t:assert(not held(17), "the 270-second control expires before the capped answers")
        t:assert(held(14) and held(15), "both capped answers outlive 270 seconds")
        evict(2)
        t:assert(not held(14) and not held(15), "both capped answers expire before the 330-second control")
        t:assert(held(18), "the 330-second control was kept")
        evict(1)
        t:assert(not held(18), "the last control was the next earliest entry")
        -- Minimum separation is 30 seconds; reject a stalled run rather
        -- than interpreting clock drift as evidence about lifetime order.
        t:assert(os.time() - started < 20, "comparisons completed within their TTL separation margin")
        t:assert((cached(t, name("s1800", 1))), "other live short fillers are retained")
        t:assert((cached(t, name("l7200", 1))), "other live long fillers are retained")
    end)

test("a day-long answer at capacity evicts only the earliest live entry",
    { spec = "resolvd *engine-cache.long-lived-entry-empties-full-cache" }, function(t)
        t:assert_eq(entries(), CAP, "the cache is full of shorter-lived answers")
        t:assert_eq(query(name("d86400", 0)).source, "dns", "the day-long answer is asked upstream")
        t:assert_eq(entries(), CAP, "one entry was replaced, not the whole cache")
        t:assert((cached(t, name("d86400", 0))), "the day-long answer is held")
        t:assert(not (cached(t, name("o890", 0))), "the earliest overflow entry was evicted")
        for k = 1, 9 do t:assert((cached(t, name("v1000", k))), "later overflow entries survive") end
        t:assert((cached(t, name("s1800", 1))), "a short filler survives")
        t:assert((cached(t, name("l7200", 2))), "a long filler survives")
        t:assert_eq(entries(), CAP, "verification stored nothing")
    end)
