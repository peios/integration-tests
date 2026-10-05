-- netd TRM §4.2 "Desired state", the configured half: what DOWN, IGNORE
-- and JOIN desire, the metric, the MTU, static addresses of both
-- families, the link-local fallback's conditions, and the default routes
-- a profile's own Route.Gateway makes. (What a network's offer adds —
-- the lease, classless routes, router discovery — is
-- desired-offered.test.lua.)
--
-- Harness: one whole Peios machine and no gateway. Every subject is a
-- link the test makes in the guest over rtnetlink (local functions
-- below; the image ships no `ip`): dummies, which are wired, and a
-- mac80211_hwsim station, which is wireless. A rule per link, naming it
-- by MAC at priority 20 (above the baseline's 10), stands it in a
-- profile the test writes, so each case changes exactly one thing in
-- the registry and reads the kernel back with helpers.rtnl.
--
-- The `reconcile` control request runs a full pass and answers only
-- when it is done, so it is the barrier before every assertion that
-- something did NOT change.
--
-- Its own VM because it needs no network at all, and the hwsim and dummy
-- modules it loads change the machine for the rest of its life.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local rtnl = require("helpers.rtnl")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")

peinit.claim(1)

local sut = network.boot({})

-- ---------------------------------------------------------------------------
-- rtnetlink, from the agent
-- ---------------------------------------------------------------------------

local RTM = { NEWLINK = 16, DELLINK = 17 }
local NLM_F = { REQUEST = 0x1, ACK = 0x4, EXCL = 0x200, CREATE = 0x400 }

local function nla(attr, payload)
    local len = 4 + #payload
    return string.pack("<I2I2", len, attr) .. payload .. string.rep("\0", (4 - len % 4) % 4)
end

local function nl_request(msg_type, flags, body)
    local s = sut:syscall(ntfe.NR.socket, 16, ntfe.SOCK_RAW, 0)
    assert(s.ret >= 0, "netlink socket: " .. sys.errname(s.errno))
    local fd = s.ret
    ntfe.send(sut, fd, string.pack("<I4I2I2I4I4", 16 + #body, msg_type,
        flags | NLM_F.REQUEST | NLM_F.ACK, 1, 0) .. body)
    local buf = ntfe.recv(sut, fd, 3000, 65536)
    sys.close(sut, fd)
    if not buf or #buf < 20 then return nil, "no ack" end
    local _, kind = string.unpack("<I4I2", buf)
    if kind ~= 2 then return nil, "reply type " .. kind end
    local err = string.unpack("<i4", buf, 17)
    if err ~= 0 then return nil, sys.errname(-err) end
    return true
end

--- A dummy link named `name` with MAC `mac` (text), created down.
local function dummy(name, mac)
    local body = string.pack("<I1I1I2i4I4I4", 0, 0, 0, 0, 0, 0)
        .. nla(3, name .. "\0") .. nla(1, gateway.mac(mac)) .. nla(18, nla(1, "dummy"))
    local ok, err = nl_request(RTM.NEWLINK, NLM_F.CREATE | NLM_F.EXCL, body)
    assert(ok, "dummy " .. name .. ": " .. tostring(err))
    return assert(ntfe.if_index(sut, name))
end

-- ---------------------------------------------------------------------------
-- The registry and the kernel
-- ---------------------------------------------------------------------------

--- Stand the link with MAC `mac` in `actions` (a JOIN, DOWN or IGNORE).
local function rule(name, mac, actions)
    return network.write(sut, "Rules\\Interface\\" .. name, {
        ["Interface.Mac.Equal"] = "sz:" .. mac, Priority = "dword:20",
        Actions = "multi:" .. actions,
    })
end

local function set(key, name, data)
    network.reg(sut, { "set", network.KEY .. "\\" .. key, name, data }):assert_ok()
end

local function unset(key, name)
    network.reg(sut, { "del", network.KEY .. "\\" .. key, name })
end

--- A full pass, finished when this returns.
local function pass()
    local r, err = network.call(sut, { query = "reconcile" })
    assert(r and r.ok, "reconcile: " .. tostring(err or (r and r.error)))
end

local function iface(name) return network.iface(network.status(sut), name) end

local function is_up(name)
    return (ntfe.if_flags(sut, name) or 0) & ntfe.IFF_UP ~= 0
end

local function mtu(name)
    return tonumber(sut:read_file("/sys/class/net/" .. name .. "/mtu"):match("%d+"))
end

--- Addresses on `index` by text (IPv6 link-locals left out).
local function addrs(index)
    local out = {}
    for _, a in ipairs(rtnl.addresses_of(sut, index)) do
        if not a.address:match("^fe80:") then out[a.address] = a end
    end
    return out
end

local function addr_list(index)
    local out = {}
    for a, e in pairs(addrs(index)) do out[#out + 1] = a .. "/" .. e.prefix end
    table.sort(out)
    return table.concat(out, " ")
end

--- Routes on `index` in the main table, as "dst/len via gw metric N proto P".
local function routes(index, fam)
    local out = {}
    for _, r in ipairs(rtnl.routes_of(sut, index)) do
        if not fam or r.family == fam then
            out[#out + 1] = string.format("%s/%d via %s metric %d proto %d",
                r.dst, r.prefix, tostring(r.gateway), r.metric, r.protocol)
        end
    end
    table.sort(out)
    return out
end

local function has(list, item)
    for _, x in ipairs(list) do if x == item then return true end end
    return false
end

local function netd_routes(index, fam)
    local out = {}
    for _, r in ipairs(routes(index, fam)) do
        if r:match("proto 200$") then out[#out + 1] = r end
    end
    return out
end

local MAC1, MAC2, MAC3 = "02:c0:00:00:02:01", "02:c0:00:00:02:02", "02:c0:00:00:02:03"
local d1 = dummy("ptd1", MAC1)

-- ---------------------------------------------------------------------------

test("DOWN desires the link down with no addresses or routes; IGNORE desires nothing, so netd plans nothing; JOIN desires the link up; loopback has no desired state",
    { spec = "netd *desired.by-verdict" }, function(t)
    -- DOWN: a foreign address is taken away and the link is kept down.
    rule("ptc-d1", MAC1, "DOWN")
    wait_until(function() local i = iface("ptd1"); return i and i.verdict == "DOWN" end,
        { timeout = 20, interval = 0.25, desc = "ptd1 judged DOWN" })
    t:assert(ntfe.if_up(sut, "ptd1"), "brought ptd1 up by hand")
    t:assert(rtnl.add_address(sut, d1, "10.44.0.9", { prefix = 24 }), "added an address by hand")
    wait_until(function() return not is_up("ptd1") and not addrs(d1)["10.44.0.9"] end,
        { timeout = 20, interval = 0.25, desc = "netd to take ptd1 down and its address away" })
    pass()
    t:assert(not is_up("ptd1"), "DOWN: the link is down")
    t:assert_eq(addr_list(d1), "", "DOWN: no addresses")
    t:assert_eq(#netd_routes(d1), 0, "DOWN: no routes")

    -- IGNORE: whatever is there stays there.
    rule("ptc-d1", MAC1, "IGNORE")
    wait_until(function() return iface("ptd1").verdict == "IGNORE" end,
        { timeout = 20, interval = 0.25, desc = "ptd1 judged IGNORE" })
    t:assert(ntfe.if_up(sut, "ptd1"), "brought ptd1 up by hand")
    t:assert(rtnl.add_address(sut, d1, "10.44.0.9", { prefix = 24 }), "added an address by hand")
    pass()
    pass()
    t:assert(is_up("ptd1"), "IGNORE: netd left the link up")
    t:assert(addrs(d1)["10.44.0.9"] ~= nil, "IGNORE: netd left the foreign address")
    t:assert(ntfe.if_down(sut, "ptd1"), "took ptd1 down by hand")
    pass()
    t:assert(not is_up("ptd1"), "IGNORE: netd left the link down too")

    -- JOIN in a bare profile: the link up, and only what the profile says.
    network.write(sut, "Profiles\\ptd-bare", {})
    rule("ptc-d1", MAC1, "JOIN(ptd-bare)")
    wait_until(function() return is_up("ptd1") and not addrs(d1)["10.44.0.9"] end,
        { timeout = 20, interval = 0.25, desc = "netd to bring ptd1 up and own its addresses" })
    pass()
    t:assert_eq(iface("ptd1").profile, "ptd-bare", "joined")
    t:assert(is_up("ptd1"), "JOIN: the link is up")
    t:assert_eq(addr_list(d1), "", "JOIN in a bare profile: no addresses")
    t:assert_eq(#netd_routes(d1), 0, "JOIN in a bare profile: no routes")

    -- Loopback: an extra address on lo is never planned away.
    local lo = assert(ntfe.if_index(sut, "lo"))
    local ok, err = rtnl.add_address(sut, lo, "192.0.2.77", { prefix = 32 })
    t:assert(ok, "added 192.0.2.77/32 to lo: " .. tostring(err))
    pass()
    pass()
    t:assert(rtnl.address(sut, lo, "192.0.2.77") ~= nil, "lo keeps an address netd did not add")
    t:assert(is_up("lo"), "lo stays up")
end)

test("every route netd adds carries the interface's metric: Route.Metric when set, else 600 for wireless and 100 for anything else",
    { spec = "netd *desired.metric" }, function(t)
    network.write(sut, "Profiles\\ptd-a", {
        ["Address.Static"] = "multi:10.55.0.2/24", ["Route.Gateway"] = "multi:10.55.0.1",
    })
    rule("ptc-d1", MAC1, "JOIN(ptd-a)")
    local want = "0.0.0.0/0 via 10.55.0.1 metric 100 proto 200"
    wait_until(function() return has(routes(d1, 4), want) end,
        { timeout = 20, interval = 0.25, desc = "the wired default route" })
    t:log("ptd1: " .. table.concat(routes(d1, 4), "; "))

    set("Profiles\\ptd-a", "Route.Metric", "dword:250")
    local want250 = "0.0.0.0/0 via 10.55.0.1 metric 250 proto 200"
    wait_until(function() return has(routes(d1, 4), want250) and not has(routes(d1, 4), want) end,
        { timeout = 20, interval = 0.25, desc = "the default route at metric 250" })
    t:assert_eq(#netd_routes(d1, 4), 1, "one netd route, at the profile's metric")
    unset("Profiles\\ptd-a", "Route.Metric")
    wait_until(function() return has(routes(d1, 4), want) end,
        { timeout = 20, interval = 0.25, desc = "back to metric 100" })

    -- Wireless: a hwsim station, joined by a rule on its kind.
    sut:run("modprobe mac80211_hwsim radios=1"):assert_ok()
    local wlan
    wait_until(function()
        for _, n in ipairs(network.links(sut)) do
            if sut:run("test -e /sys/class/net/" .. n .. "/phy80211").exit_code == 0 then wlan = n end
        end
        return wlan
    end, { timeout = 20, interval = 0.5, desc = "a hwsim station" })
    local w = assert(ntfe.if_index(sut, wlan))
    network.write(sut, "Profiles\\ptd-w", {
        ["Address.Static"] = "multi:10.66.0.2/24", ["Route.Gateway"] = "multi:10.66.0.1",
    })
    network.write(sut, "Rules\\Interface\\ptc-wl", {
        ["Interface.Kind.Equal"] = "sz:wireless", Priority = "dword:20", Actions = "multi:JOIN(ptd-w)",
    })
    local want600 = "0.0.0.0/0 via 10.66.0.1 metric 600 proto 200"
    local ok = pcall(wait_until, function() return has(routes(w, 4), want600) end,
        { timeout = 20, interval = 0.25, desc = "the wireless default route" })
    t:log(wlan .. ": " .. table.concat(routes(w, 4), "; ") .. "; addresses " .. addr_list(w))
    t:assert(ok, "the wireless station's default route is at metric 600")
    network.delete(sut, "Rules\\Interface\\ptc-wl")
end)

test("the MTU: Mtu.Value when set; otherwise (no offer) no MTU is desired and the link's is left as it is",
    { spec = "netd *desired.mtu" }, function(t)
    t:assert_eq(mtu("ptd1"), 1500, "ptd1 starts at 1500")
    set("Profiles\\ptd-a", "Mtu.Value", "dword:1400")
    wait_until(function() return mtu("ptd1") == 1400 end,
        { timeout = 20, interval = 0.25, desc = "the MTU at 1400" })
    unset("Profiles\\ptd-a", "Mtu.Value")
    pass()
    t:assert_eq(mtu("ptd1"), 1400, "nothing desired: netd does not put it back")
    sut:run("echo 1300 > /sys/class/net/ptd1/mtu"):assert_ok()
    pass()
    pass()
    t:assert_eq(mtu("ptd1"), 1300, "nothing desired: a hand-set MTU is left as it is")
    -- Mtu.Offered with nothing offered desires nothing either.
    set("Profiles\\ptd-a", "Mtu.Offered", "dword:1")
    pass()
    t:assert_eq(mtu("ptd1"), 1300, "Mtu.Offered with no lease and no router: left as it is")
    unset("Profiles\\ptd-a", "Mtu.Offered")
end)

test("IPv4 addresses: every static entry at its prefix; the link-local fallback at /16 only when the client fell back, holds no lease and the profile has no static address of either family",
    { spec = "netd *desired.ipv4-addresses" }, function(t)
    set("Profiles\\ptd-a", "Address.Static", "multi:10.55.0.2/24,10.57.0.2/16")
    wait_until(function() local a = addrs(d1); return a["10.55.0.2"] and a["10.57.0.2"] end,
        { timeout = 20, interval = 0.25, desc = "both static addresses" })
    t:assert_eq(addrs(d1)["10.55.0.2"].prefix, 24, "10.55.0.2 at /24")
    t:assert_eq(addrs(d1)["10.57.0.2"].prefix, 16, "10.57.0.2 at /16")
    -- Observation for the report, not a claim of the TRM: two statics in
    -- one subnet, written high then low; which does the kernel make primary?
    set("Profiles\\ptd-a", "Address.Static", "multi:10.58.0.9/24,10.58.0.3/24,10.55.0.2/24")
    wait_until(function() local a = addrs(d1); return a["10.58.0.9"] and a["10.58.0.3"] end,
        { timeout = 20, interval = 0.25, desc = "both 10.58 statics" })
    t:log(string.format("10.58.0.9 flags 0x%x, 10.58.0.3 flags 0x%x (0x1 = secondary)",
        addrs(d1)["10.58.0.9"].flags, addrs(d1)["10.58.0.3"].flags))
    set("Profiles\\ptd-a", "Address.Static", "multi:10.55.0.2/24")
    wait_until(function() local a = addrs(d1); return a["10.57.0.2"] == nil and a["10.58.0.9"] == nil
        and a["10.58.0.3"] == nil end,
        { timeout = 20, interval = 0.25, desc = "the dropped statics to go" })

    -- The fallback: DHCP on a dummy is never answered.
    local d2 = dummy("ptd2", MAC2)
    network.write(sut, "Profiles\\ptd-ll", { ["Address.Offered"] = "dword:1", ["Address.LinkLocal"] = "dword:1" })
    rule("ptc-d2", MAC2, "JOIN(ptd-ll)")
    -- netd's choice (RFC 3927 §2.1, seeded by the MAC's last four bytes).
    local m = gateway.mac(MAC2)
    local seed = string.unpack(">I4", m, 3)
    local host = 256 + seed % (65024 - 256)
    local ll = string.format("169.254.%d.%d", host >> 8, host & 0xff)
    wait_until(function() return addrs(d2)[ll] end,
        { timeout = 40, interval = 0.5, desc = "the link-local fallback " .. ll })
    t:assert_eq(addrs(d2)[ll].prefix, 16, "the link-local address is at /16")
    t:log("ptd2 fell back to " .. ll)

    -- A static address of the other family suppresses it. (The edit
    -- restarts the client; wait for it to fall back again.)
    local function fallbacks()
        local n = 0
        for _, l in ipairs(network.logs(sut, { take = 1000 })) do
            if l:find("interface ptd2: no DHCP offer; link-local", 1, true) then n = n + 1 end
        end
        return n
    end
    local before = fallbacks()
    set("Profiles\\ptd-ll", "Address.Static", "multi:fd55::22/64")
    wait_until(function() return fallbacks() > before end,
        { timeout = 40, interval = 1, desc = "the restarted client to fall back again" })
    pass()
    local a = addrs(d2)
    t:log("ptd2 after falling back with a v6 static: " .. addr_list(d2))
    t:assert_eq(a[ll], nil, "no link-local address with a static address of either family")
    t:assert(a["fd55::22"] ~= nil, "the v6 static is there")
end)

test("IPv4 default route: via Route.Gateway as written, with no check that it is on a subnet the link has; an unreachable gateway fails the add on every reconcile, logged each time; with no gateway there is no default route",
    { spec = "netd *desired.ipv4-routes" }, function(t)
    t:assert(has(routes(d1, 4), "0.0.0.0/0 via 10.55.0.1 metric 100 proto 200"), "via Route.Gateway")
    -- A gateway on no subnet ptd1 has.
    set("Profiles\\ptd-a", "Route.Gateway", "multi:192.0.2.1")
    local function failures()
        local n = 0
        for _, l in ipairs(network.logs(sut, { take = 1000 })) do
            if l:find("reconcile: AddRoute(", 1, true) and l:find("192.0.2.1", 1, true)
                and l:find("failed", 1, true) then n = n + 1 end
        end
        return n
    end
    wait_until(function() return failures() > 0 end,
        { timeout = 20, interval = 0.5, desc = "the failed add to be logged" })
    t:assert_eq(#netd_routes(d1, 4), 0, "no default route landed")
    t:assert(addrs(d1)["10.55.0.2"] ~= nil, "the address is still there")
    local n1 = failures()
    pass()
    local n2 = failures()
    pass()
    local n3 = failures()
    t:log(string.format("failure lines: %d, %d, %d", n1, n2, n3))
    t:assert(n2 > n1 and n3 > n2, "every reconcile tries again and logs the failure")
    -- No gateway: no default route.
    unset("Profiles\\ptd-a", "Route.Gateway")
    pass()
    t:assert_eq(#netd_routes(d1, 4), 0, "no Route.Gateway, no Route.Offered: no IPv4 default route")
end)

test("IPv6 static addresses land at their prefix, preferred, with a prefix route",
    { spec = "netd *desired.ipv6-addresses" }, function(t)
    set("Profiles\\ptd-a", "Address.Static", "multi:10.55.0.2/24,fd55::2/64")
    local e
    wait_until(function()
        for _, a in ipairs(rtnl.addresses_of(sut, d1, 6)) do
            if a.address == "fd55::2" and not a.tentative then e = a end
        end
        return e
    end, { timeout = 20, interval = 0.25, desc = "fd55::2 on ptd1" })
    t:assert_eq(e.prefix, 64, "at /64")
    t:assert(not e.deprecated, "preferred")
    t:assert_eq(e.preferred, rtnl.FOREVER, "preferred lifetime forever")
    t:assert(not e.noprefixroute, "with a prefix route")
    t:assert(has(routes(d1, 6), "fd55::/64 via nil metric 256 proto 2"),
        "the kernel's prefix route: " .. table.concat(routes(d1, 6), "; "))
end)

test("IPv6 default route: via Route.Gateway's IPv6 entry; with neither it nor Route.Offered there is none",
    { spec = "netd *desired.ipv6-default-route" }, function(t)
    t:assert_eq(#netd_routes(d1, 6), 0, "no IPv6 gateway yet: no IPv6 default route")
    set("Profiles\\ptd-a", "Route.Gateway", "multi:10.55.0.1,fd55::1")
    local want = "::/0 via fd55::1 metric 100 proto 200"
    wait_until(function() return has(routes(d1, 6), want) end,
        { timeout = 20, interval = 0.25, desc = "the IPv6 default route" })
    t:assert(has(routes(d1, 4), "0.0.0.0/0 via 10.55.0.1 metric 100 proto 200"),
        "the IPv4 entry is the IPv4 gateway")
    unset("Profiles\\ptd-a", "Route.Gateway")
    wait_until(function() return #netd_routes(d1, 6) == 0 end,
        { timeout = 20, interval = 0.25, desc = "the IPv6 default route to go" })
end)
