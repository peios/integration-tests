-- resolvd §4.2 — the machine's own addresses, which answer the hostname:
-- every address of every scope at `addressed` or better, with or without
-- servers, in snapshot order, link-local included and loopback excluded,
-- with only adjacent repeats removed.
--
-- Two interfaces need two networks, and a file may have only two VMs, so
-- the gateway VM is attached to both bridges and a second gateway object
-- drives its second NIC (the pattern of hostname-order.test.lua). The
-- first network leases 10.77.0.50 with no DNS server, so its scope has
-- none; the second network never answers DHCP, and the default profile
-- is edited at once to turn off IPv4 link-local fallback, so that
-- interface stays at `link`: up, with only the kernel's fe80:: address,
-- in the snapshot but below `addressed`.
--
-- The expected answer is computed from resolvd's own `status` (each
-- scope's `subnets`, in snapshot order) and netd's levels, so the test
-- does not depend on the order the NICs enumerate in or the kernel lists
-- addresses in; it then checks that the case it meant to build was
-- built. `Address.Static` puts the same addresses on both interfaces to
-- make repeats, adjacent within a scope and apart across the two.
--
-- The loopback address is added last: if netd were to refuse it, the
-- profile would stop applying and nothing after it could be trusted.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local ntfe = require("helpers.ntfe")
local dns = require("helpers.dns")

peinit.claim(2)

local lan = network.bridge("lan")
local lan2 = network.bridge("wan")
local gw = gateway.boot({ bridges = { lan, lan2 } })

--- A second gateway object for the gateway VM's second NIC.
local function second_gateway(g, ifname, addr)
    assert(ntfe.if_addr(g.vm, ifname, addr, 24))
    local o = setmetatable({
        vm = g.vm, ifname = ifname, addr = addr, prefix = 24, addr6 = "fd78::1",
        seen = {}, handlers = {}, t0 = g.t0,
    }, getmetatable(g))
    o.ifindex = assert(ntfe.if_index(g.vm, ifname))
    o.mac = assert(ntfe.if_hwaddr(g.vm, ifname))
    o.ll = gateway.link_local(o.mac)
    o.ps = assert(ntfe.packet_socket(g.vm, ifname))
    return o
end

local gw2 = second_gateway(gw, "eth1", "10.78.0.1")
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600, dns = false })
gw2:dhcp({ pool = { "10.78.0.50" }, silent = true })
local sut = network.boot({ bridges = { lan, lan2 }, gateways = { gw, gw2 } })
-- Before the silent network's client falls back to 169.254 (about 28 s).
network.write(sut, [[Profiles\default]], { ["Address.LinkLocal"] = "dword:0" })
network.write(sut, network.KEY, { Hostname = "sz:peibox" })

local SOCK = "/run/resolvd/resolv.sock"
local PROFILE = [[Profiles\default]]
local LEVELS = { absent = 0, link = 1, addressed = 2, routed = 3 }

local function serve_both(timeout, pred)
    local deadline = os.time() + timeout
    repeat
        gw:pump(50)
        gw2:pump(50)
        if pred() then return true end
    until os.time() > deadline
    return pred() and true or false
end

local function rcall(req)
    local r, err = network.call(sut, req, { path = SOCK })
    assert(r and r.ok, "resolvd " .. req.query .. ": " .. tostring(err or (r and r.error)))
    return r
end

--- netd's level for each interface name.
local function levels()
    local out = {}
    for _, i in ipairs(network.status(sut).interfaces or {}) do out[i.name] = i.level end
    return out
end

--- What resolvd's status says, flattened: each scope with its level (from
--- netd) and addresses; and every address of every scope in order.
local function picture()
    local s, lv = rcall({ query = "status" }), levels()
    local scopes, all = {}, {}
    for _, sc in ipairs(s.scopes or {}) do
        local addrs = {}
        for _, a in ipairs(sc.subnets or {}) do addrs[#addrs + 1] = a:match("^([^/]+)") end
        scopes[#scopes + 1] = { name = sc.interface, level = lv[sc.interface], addrs = addrs, servers = sc.servers }
    end
    return s, scopes
end

local function is_loopback(a) return a:match("^127%.") ~= nil or a == "::1" end

--- The own-address list the TRM describes, from the scopes.
local function expected(scopes)
    local list = {}
    for _, sc in ipairs(scopes) do
        if (LEVELS[sc.level] or 0) >= LEVELS.addressed then
            for _, a in ipairs(sc.addrs) do
                if not is_loopback(a) then list[#list + 1] = a end
            end
        end
    end
    local out = {}
    for _, a in ipairs(list) do
        if out[#out] ~= a then out[#out + 1] = a end
    end
    return out, list
end

local function answer_addrs(r)
    local out = {}
    for _, rec in ipairs(r.records or {}) do out[#out + 1] = rec.text end
    return out
end

local function describe(scopes)
    local parts = {}
    for _, sc in ipairs(scopes) do
        parts[#parts + 1] = string.format("%s(%s, %d servers): %s", sc.name, tostring(sc.level),
            #(sc.servers or {}), table.concat(sc.addrs, " "))
    end
    return table.concat(parts, "; ")
end

local function count(list, x)
    local n = 0
    for _, v in ipairs(list) do if v == x then n = n + 1 end end
    return n
end

local function hostname_answer(t)
    local r = rcall({ query = "resolve", name = "peibox", type = dns.TYPE.ANY })
    t:assert_eq(r.source, "synthetic", "the hostname is answered synthetically")
    for _, rec in ipairs(r.records or {}) do t:assert_eq(rec.ttl, 0, "TTL 0") end
    return answer_addrs(r)
end

-- ---------------------------------------------------------------------------

test("the hostname's addresses are every address of every scope at addressed or better, servers or not, in snapshot order, link-local included",
    { spec = "resolvd *engine-synthetic.own-addresses-from-every-addressed-scope" }, function(t)
        local ok = serve_both(60, function()
            local n_bound, n_link = 0, 0
            for _, i in ipairs(network.status(sut).interfaces or {}) do
                if network.bound(i) then n_bound = n_bound + 1 end
                if i.level == "link" then n_link = n_link + 1 end
            end
            local s = rcall({ query = "status" })
            return n_bound == 1 and n_link == 1 and #s.scopes == 2 and s.hostname == "peibox"
        end)
        local _, scopes = picture()
        t:log("scopes: " .. describe(scopes))
        t:assert(ok, "one interface bound, the other at link, both scopes in resolvd, hostname peibox")
        local addressed, below
        for _, sc in ipairs(scopes) do
            if sc.level == "link" then below = sc else addressed = sc end
        end
        t:assert(addressed and below, "one scope at addressed or better, one at link")
        t:assert_eq(#addressed.servers, 0, "the addressed scope has no servers")
        t:assert(#below.addrs >= 1, "the link-level scope holds an address (its fe80::)")
        local want = expected(scopes)
        local got = hostname_answer(t)
        t:log("hostname answer: " .. table.concat(got, " ") .. "; expected " .. table.concat(want, " "))
        t:assert_eq(table.concat(got, " "), table.concat(want, " "), "the answer is the addressed scope's addresses, in order")
        local has_ll = false
        for _, a in ipairs(got) do if a:match("^fe80:") then has_ll = true end end
        t:assert(has_ll, "the addressed scope's link-local address is included")
        for _, a in ipairs(below.addrs) do
            t:assert_eq(count(got, a), 0, "the link-level scope's " .. a .. " is not")
        end

        -- Static addresses lift the second interface to addressed: now both count.
        network.write(sut, PROFILE, { ["Address.Static"] = "multi:10.88.0.5/24" })
        ok = serve_both(30, function()
            local _, sc = picture()
            local n = 0
            for _, x in ipairs(sc) do if (LEVELS[x.level] or 0) >= LEVELS.addressed then n = n + 1 end end
            return n == 2
        end)
        _, scopes = picture()
        t:log("scopes: " .. describe(scopes))
        t:assert(ok, "both interfaces are at addressed or better")
        want = expected(scopes)
        got = hostname_answer(t)
        t:log("hostname answer: " .. table.concat(got, " "))
        t:assert_eq(table.concat(got, " "), table.concat(want, " "), "both scopes' addresses, in snapshot order")
        t:assert_eq(count(got, "10.88.0.5"), 2, "the static address once for each interface")
    end)

test("repeated addresses are removed only when adjacent: the same address twice in one scope is once, across two scopes twice",
    { spec = "resolvd *engine-synthetic.only-adjacent-duplicates-removed" }, function(t)
        network.write(sut, PROFILE, { ["Address.Static"] = "multi:10.88.0.5/24,10.88.0.5/16" })
        local scopes
        local ok = serve_both(30, function()
            _, scopes = picture()
            local n = 0
            for _, sc in ipairs(scopes) do n = n + count(sc.addrs, "10.88.0.5") end
            return n == 4
        end)
        t:log("scopes: " .. describe(scopes))
        t:assert(ok, "10.88.0.5 is held twice on each interface (/24 and /16)")
        local want, list = expected(scopes)
        local got = hostname_answer(t)
        t:log("all: " .. table.concat(list, " "))
        t:log("hostname answer: " .. table.concat(got, " "))
        t:assert_eq(table.concat(got, " "), table.concat(want, " "), "the list with adjacent repeats removed")
        -- The case built: each interface holds its two side by side, and
        -- something lies between the two interfaces' copies.
        local adjacent, apart = 0, 0
        for i = 2, #list do if list[i] == list[i - 1] then adjacent = adjacent + 1 end end
        t:assert(adjacent >= 1, "the list had adjacent repeats to remove")
        t:assert(#want < #list, "and they were removed")
        t:assert_eq(count(got, "10.88.0.5"), 2, "10.88.0.5 is left once per interface: the copies apart are both kept")
        for i = 1, #got do
            for j = i + 2, #got do if got[i] == got[j] then apart = apart + 1 end end
        end
        t:assert(apart >= 1, "a repeat that was not adjacent stayed")
    end)

test("loopback addresses held by an interface are not among the machine's own addresses",
    { spec = "resolvd *engine-synthetic.own-addresses-from-every-addressed-scope" }, function(t)
        network.write(sut, PROFILE, { ["Address.Static"] = "multi:10.88.0.5/24,127.0.0.9/8" })
        local scopes
        local ok = serve_both(30, function()
            _, scopes = picture()
            for _, sc in ipairs(scopes) do if count(sc.addrs, "127.0.0.9") > 0 then return true end end
            return false
        end)
        t:log("scopes: " .. describe(scopes))
        if not ok then
            for _, l in ipairs(network.logs(sut)) do
                if l:find("Static", 1, true) or l:find("refus", 1, true) then t:log("netd: " .. l) end
            end
        end
        t:assert(ok, "an interface holds 127.0.0.9 and the snapshot carries it")
        local got = hostname_answer(t)
        t:log("hostname answer: " .. table.concat(got, " "))
        t:assert_eq(count(got, "127.0.0.9"), 0, "127.0.0.9 is not among them")
        t:assert_eq(table.concat(got, " "), table.concat(expected(scopes), " "), "the rest are")
    end)
