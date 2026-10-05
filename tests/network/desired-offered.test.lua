-- netd TRM §4.2 "Desired state", the offered half: what a joined
-- interface takes from its network — the lease's MTU, address,
-- broadcast, routers and classless routes, the routers' MTU, SLAAC
-- addresses and default router — and how the profile's switches and its
-- own Route.Gateway decide between them. (The configured half, on links
-- the test makes, is desired.test.lua.)
--
-- Harness: the scripted gateway as DHCPv4 server and router, one whole
-- Peios machine. The machine boots into a seeded profile, so the first
-- exchange already happens under it:
--
--   Profiles\ptoff   Address.Offered, Route.Offered, Dns.Offered,
--                    Mtu.Offered, Address.Temporary = 1, and a static
--                    10.88.0.5/24;
--   Rules\Interface\ptc-off   wired -> JOIN(ptoff), priority 20.
--
-- The gateway's lease carries an MTU (26 = 1400), a broadcast address
-- (28 = 10.77.0.191), two routers (3 = 10.77.0.3, 10.77.0.1) and
-- classless routes (121: 10.1.0.0/16 via .9, 0.0.0.0/0 via .7); its
-- router advertisement an MTU of 1300, an on-link autonomous fd77::/64
-- and an off-link autonomous fd78::/64. A case changes the lease by
-- re-arming the server and asking netd to `renew`, and changes the
-- profile by writing it (which restarts the clients, §3.3).
--
-- What landed is read from the kernel (helpers.rtnl), never from logs.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local rtnl = require("helpers.rtnl")
local sha1 = require("helpers.sha1")

peinit.claim(2)

local N = [[Machine\System\Network]]
local function k(path, values) return { path = path, values = values } end
local function dword(name, v) return { name = name, type = "dword", data = v } end
local function sz(name, v) return { name = name, type = "sz", data = v } end
local function multi(name, v) return { name = name, type = "multi", data = v } end

local seeds = peinit.seed("pt-desired-offered", {
    k([[Machine\System]]), k(N), k(N .. [[\Profiles]]),
    k(N .. [[\Profiles\ptoff]], {
        dword("Address.Offered", 1), dword("Route.Offered", 1), dword("Dns.Offered", 1),
        dword("Mtu.Offered", 1), dword("Address.Temporary", 1),
        multi("Address.Static", { "10.88.0.5/24" }),
    }),
    k(N .. [[\Rules]]), k(N .. [[\Rules\Interface]]),
    k(N .. [[\Rules\Interface\ptc-off]], {
        sz("Interface.Kind.Equal", "wired"), dword("Priority", 20),
        multi("Actions", { "JOIN(ptoff)" }),
    }),
})

local O = gateway.opt
local OPT_MTU = { 26, O.u16(1400) }
local OPT_BCAST = { 28, O.ip("10.77.0.191") }
local OPT_CLASSLESS = { 121, O.classless({ { "10.1.0.0", 16, "10.77.0.9" }, { "0.0.0.0", 0, "10.77.0.7" } }) }
local ROUTERS = { "10.77.0.3", "10.77.0.1" }

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
local function arm(options)
    gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600, router = ROUTERS, options = options })
end
arm({ OPT_MTU, OPT_BCAST, OPT_CLASSLESS })
local RA = { lifetime = 1800, mtu = 1300, prefixes = {
    { prefix = "fd77::", len = 64 },
    { prefix = "fd78::", len = 64, L = false },
} }
gw:router(RA)
local sut = network.boot({ bridges = { lan }, gateway = gw, files = seeds })

local LEASED = "10.77.0.50"
local index -- eth0's

local function mtu() return tonumber(sut:read_file("/sys/class/net/eth0/mtu"):match("%d+")) end

local function v4(addr)
    for _, a in ipairs(rtnl.addresses_of(sut, index, 4)) do
        if a.address == addr then return a end
    end
end

--- netd's routes (protocol 200) on eth0 of family `fam`, as
--- "dst/len via gw metric N".
local function netd_routes(fam)
    local out = {}
    for _, r in ipairs(rtnl.routes_of(sut, index)) do
        if r.family == fam and r.protocol == rtnl.RTPROT.NETD then
            out[#out + 1] = string.format("%s/%d via %s metric %d", r.dst, r.prefix, tostring(r.gateway), r.metric)
        end
    end
    table.sort(out)
    return table.concat(out, "; ")
end

--- Pump the gateway until `pred()` holds; raise with `what` if it never does.
local function until_(pred, what, timeout)
    local ok = gw:serve({ timeout = timeout or 30, until_ = pred })
    if not ok then error("never: " .. what, 2) end
end

local function renew()
    local r, err = network.call(sut, { query = "renew", interface = "eth0" })
    assert(r and r.ok, "renew: " .. tostring(err or (r and r.error)))
end

local function profile(name, data)
    local key = N .. [[\Profiles\ptoff]]
    if data == nil then
        network.reg(sut, { "del", key, name })
    else
        network.reg(sut, { "set", key, name, data }):assert_ok()
    end
end

local function bound_with_v6(i) return network.bound(i) and #network.ipv6(i) > 0 end

-- ---------------------------------------------------------------------------

test("the MTU: with Mtu.Offered, the lease's (option 26), else the routers' advertised MTU; without it nothing is desired and the link's MTU is left",
    { spec = "netd *desired.mtu" }, function(t)
    local s = network.serve_until(gw, sut, bound_with_v6, { iface = true, timeout = 90 })
    t:assert(s, "eth0 bound and autoconfigured")
    index = network.iface(s, "eth0").index
    until_(function() return mtu() == 1400 end, "the lease's MTU, 1400")
    t:assert_eq(mtu(), 1400, "the lease's MTU wins over the routers' 1300")

    arm({ OPT_BCAST, OPT_CLASSLESS })
    renew()
    until_(function() return mtu() == 1300 end, "the routers' MTU once the lease has none")
    t:assert_eq(mtu(), 1300, "no option 26: the router advertisement's MTU")

    -- Without Mtu.Offered no MTU is desired, so whatever the link has stays.
    profile("Mtu.Offered", "dword:0")
    local again = network.serve_until(gw, sut, bound_with_v6, { iface = true, timeout = 30 })
    t:assert(again, "rebound under the edited profile")
    arm({ OPT_MTU, OPT_BCAST, OPT_CLASSLESS })
    renew()
    gw:serve({ timeout = 3 })
    t:assert_eq(mtu(), 1300, "neither the lease's 1400 nor anything else is applied")
end)

test("IPv4 addresses: the profile's static and the lease's address at the lease's prefix, with the lease's broadcast (option 28); no link-local while a lease is held",
    { spec = "netd *desired.ipv4-addresses" }, function(t)
    t:assert(index, "the first test found eth0")
    until_(function() return v4(LEASED) ~= nil and v4("10.88.0.5") ~= nil end, "both addresses")
    local l, st = v4(LEASED), v4("10.88.0.5")
    t:log(string.format("lease %s/%d brd %s; static %s/%d brd %s", l.address, l.prefix,
        tostring(l.broadcast), st.address, st.prefix, tostring(st.broadcast)))
    t:assert_eq(l.prefix, 24, "the lease's prefix (option 1)")
    t:assert_eq(l.broadcast, "10.77.0.191", "the lease's broadcast address (option 28)")
    t:assert_eq(st.prefix, 24, "the static at its prefix")
    for _, a in ipairs(rtnl.addresses_of(sut, index, 4)) do
        t:assert(not a.address:match("^169%.254%."), "no link-local address beside a lease: " .. a.address)
    end
    t:assert_eq(#rtnl.addresses_of(sut, index, 4), 2, "exactly the static and the lease")
end)

test("IPv4 routes: with Route.Offered the default goes via the classless 0.0.0.0/0 gateway when option 121 came, else the first router of option 3, and classless routes are added; Route.Gateway beats the lease; without Route.Offered none of the lease's routes",
    { spec = "netd *desired.ipv4-routes" }, function(t)
    t:assert(index, "the first test found eth0")
    local classful = "0.0.0.0/0 via 10.77.0.7 metric 100; 10.1.0.0/16 via 10.77.0.9 metric 100"
    until_(function() return netd_routes(4) == classful end, "the classless routes")
    t:assert_eq(netd_routes(4), classful, "default via the classless 0/0 gateway, not option 3")

    arm({ OPT_BCAST })
    renew()
    until_(function() return netd_routes(4) == "0.0.0.0/0 via 10.77.0.3 metric 100" end,
        "the default via option 3's first router")
    t:assert_eq(netd_routes(4), "0.0.0.0/0 via 10.77.0.3 metric 100", "no 121: option 3's first router, no classless routes")

    arm({ OPT_BCAST, OPT_CLASSLESS })
    profile("Route.Offered", "dword:0")
    until_(function() local i = network.iface(network.status(sut), "eth0"); return i and network.bound(i) end,
        "rebound without Route.Offered")
    gw:serve({ timeout = 3 })
    t:assert_eq(netd_routes(4), "", "without Route.Offered: no default, no classless routes")
    t:assert_eq(netd_routes(6), "", "nor the routers' default")

    profile("Route.Offered", "dword:1")
    profile("Route.Gateway", "multi:10.77.0.254")
    local want = "0.0.0.0/0 via 10.77.0.254 metric 100; 10.1.0.0/16 via 10.77.0.9 metric 100"
    until_(function() return netd_routes(4) == want end, "Route.Gateway's default")
    t:assert_eq(netd_routes(4), want, "Route.Gateway beats the lease's gateway; classless routes stay")
end)

test("IPv6 addresses: the stable-privacy and temporary address router discovery wants for each prefix, deprecated or not, with a prefix route only when the prefix is on-link",
    { spec = "netd *desired.ipv6-addresses" }, function(t)
    t:assert(index, "the first test found eth0")
    local s = network.serve_until(gw, sut, bound_with_v6, { iface = true, timeout = 30 })
    local ifid = network.iface(s, "eth0").ifid
    local secret = sut:read_file("/var/state/netd/secret")
    t:assert_eq(#secret, 32, "netd's 32-byte secret")
    local function stable(prefix)
        local p8 = gateway.ip6(prefix):sub(1, 8)
        return gateway.ip6_text(p8 .. sha1.digest("peios-ndp-stable-iid|" .. secret .. p8 .. ifid .. "\0"):sub(1, 8))
    end
    local s77, s78 = stable("fd77::"), stable("fd78::")
    local function v6()
        local by = {}
        for _, a in ipairs(rtnl.addresses_of(sut, index, 6)) do
            if not a.address:match("^fe80:") then by[a.address] = a end
        end
        return by
    end
    local function in_prefix(by, p)
        local n = 0
        for a in pairs(by) do if a:sub(1, #p) == p then n = n + 1 end end
        return n
    end
    until_(function() local by = v6(); return by[s77] and by[s78] and in_prefix(by, "fd77:") >= 2
        and in_prefix(by, "fd78:") >= 2 end, "stable and temporary addresses in both prefixes")
    local by = v6()
    local list = {}
    for a, e in pairs(by) do
        list[#list + 1] = string.format("%s/%d%s%s", a, e.prefix, e.deprecated and " deprecated" or "",
            e.noprefixroute and " noprefixroute" or "")
    end
    table.sort(list)
    t:log("eth0 v6: " .. table.concat(list, ", "))
    for a, e in pairs(by) do
        local on_link = a:sub(1, 5) == "fd77:"
        t:assert_eq(e.prefix, 64, a .. " at /64")
        t:assert_eq(e.noprefixroute, not on_link, a .. ": no-prefix-route exactly when off-link")
        t:assert(not e.deprecated, a .. " preferred")
    end
    t:assert_eq(in_prefix(by, "fd77:"), 2, "one stable and one temporary in fd77::/64")
    t:assert_eq(in_prefix(by, "fd78:"), 2, "one stable and one temporary in fd78::/64")
    local prefix_routes = {}
    for _, r in ipairs(rtnl.routes_of(sut, index)) do
        if r.family == 6 and r.prefix == 64 then prefix_routes[r.dst] = r.protocol end
    end
    t:assert(prefix_routes["fd77::"] ~= nil, "the on-link prefix has a prefix route")
    t:assert_eq(prefix_routes["fd78::"], nil, "the off-link prefix has none")

    -- A router taking the preferred lifetime to zero: deprecated, kept.
    gw:send_ra({ lifetime = 1800, mtu = 1300, prefixes = {
        { prefix = "fd77::", len = 64, preferred = 0 }, { prefix = "fd78::", len = 64, L = false } } })
    until_(function() local e = v6()[s77]; return e and e.deprecated end, "fd77's stable address deprecated")
    t:assert(v6()[s77].deprecated, "the stable fd77 address is deprecated, not removed")
    t:assert(not v6()[s78].deprecated, "the other prefix's address is not")
    gw:send_ra(RA)
    until_(function() local e = v6()[s77]; return e and not e.deprecated end, "fd77 preferred again")
end)

test("IPv6 default route: via Route.Gateway's IPv6 entry when set, else (Route.Offered) the default router discovery chose; with neither, none",
    { spec = "netd *desired.ipv6-default-route" }, function(t)
    t:assert(index, "the first test found eth0")
    local ll = gateway.ip6_text(gw.ll)
    local via_router = "::/0 via " .. ll .. " metric 100"
    until_(function() return netd_routes(6) == via_router end, "the router's default")
    t:assert_eq(netd_routes(6), via_router, "Route.Gateway has no IPv6 entry: the chosen router")

    profile("Route.Gateway", "multi:10.77.0.254,fd77::fe")
    until_(function() return netd_routes(6) == "::/0 via fd77::fe metric 100" end, "Route.Gateway's v6 default")
    t:assert_eq(netd_routes(6), "::/0 via fd77::fe metric 100", "Route.Gateway's IPv6 entry beats the router")

    profile("Route.Gateway", nil)
    profile("Route.Offered", "dword:0")
    until_(function() local i = network.iface(network.status(sut), "eth0"); return i and bound_with_v6(i) end,
        "rebound with neither")
    gw:serve({ timeout = 3 })
    t:assert_eq(netd_routes(6), "", "neither Route.Gateway nor Route.Offered: no IPv6 default route")
end)
