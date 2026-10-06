-- netd §6.2 — addresses (SLAAC): which prefixes form addresses, the
-- stable-privacy derivation, lifetimes and the two-hour rule,
-- deprecation and removal, and the prefix-route flag. Temporary addresses
-- are slaac-temporary.test.lua; the secret's own lifecycle is
-- slaac-secret.test.lua.
--
-- Harness: the scripted gateway (helpers.gateway) playing a router that
-- answers every solicitation with BASE (one prefix, fd77::/64), and
-- sending each test's own advertisements. One whole Peios machine joined
-- by the shipped baseline. Addresses are asserted EXACTLY: the expected
-- stable address is computed here from `/var/state/netd/secret`, the
-- prefix and the interface id (helpers.sha1), as §6.2 gives it. The
-- kernel's view (flags, prefix routes) comes from helpers.rtnl.
--
-- Lifetimes are monotonic, so they are short (seconds), and every timing
-- is asserted in whole gateway seconds with a second or two of slack.
-- The two-hour rule's rows 3 to 5 cannot be told apart from one another
-- in a test this length (each leaves the address alive well past the
-- short lifetime advertised); rows 1 and 2 are shown exactly.
--
-- Own VMs: the tests run in order on one pair; each uses its own
-- prefixes, so none disturbs another.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local rtnl = require("helpers.rtnl")
local sha1 = require("helpers.sha1")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })

local BASE = { lifetime = 1800,
    prefixes = { { prefix = "fd77::", len = 64, valid = 86400, preferred = 14400 } } }
gw:router(BASE)

local sut = network.boot({ bridges = { lan }, gateway = gw })
local nic = lan:nic(sut)

local INDEX = tonumber((sut:read_file("/sys/class/net/eth0/ifindex"):match("%d+")))
local MAC = gateway.mac(sut:read_file("/sys/class/net/eth0/address"))
local GW_LL = gateway.ip6_text(gw.ll)
local FOREVER = 0xFFFFFFFF

-- ---------------------------------------------------------------------------
-- Local helpers
-- ---------------------------------------------------------------------------

local function iface() return network.iface(network.status(sut), "eth0") end

--- network.serve_until, returning eth0's status (serve_until itself
--- returns the whole status reply).
local function serve_iface(pred, o)
    local s = network.serve_until(gw, sut, pred, o)
    return s and network.iface(s, "eth0")
end

local function in64(a, prefix)
    return gateway.ip6(a):sub(1, 8) == gateway.ip6(prefix):sub(1, 8)
end

local function kernel_in(prefix)
    local out = {}
    for _, a in ipairs(rtnl.addresses_of(sut, INDEX, 6)) do
        if in64(a.address, prefix) then out[#out + 1] = a end
    end
    return out
end

local function status_has(i, addr)
    return network.has_address(i, addr)
end

--- RFC 5453 reserved interface identifiers.
local function reserved(iid)
    if iid == string.rep("\0", 8) then return true end
    if iid:sub(1, 4) == "\2\0\x5e\xff" then return true end
    return iid:sub(1, 7) == "\xfd\xff\xff\xff\xff\xff\xff" and iid:byte(8) >= 0x80
end

--- §6.2's stable address for `prefix` (text), given the secret and the
--- interface id.
local function stable(prefix, secret, ifid)
    local p8 = gateway.ip6(prefix):sub(1, 8)
    for counter = 0, 7 do
        local iid = sha1.digest("peios-ndp-stable-iid|" .. secret .. p8 .. ifid .. string.char(counter)):sub(1, 8)
        if not reserved(iid) then return gateway.ip6_text(p8 .. iid) end
    end
    return gateway.ip6_text(p8 .. "\0\0\0\0\0\0\0\1")
end

local SECRET, IFID
local function expected(prefix)
    if not SECRET then
        SECRET = sut:read_file("/var/state/netd/secret")
        assert(SECRET and #SECRET == 32, "the secret file holds 32 bytes")
        IFID = assert(iface().ifid, "the interface has an id")
    end
    return stable(prefix, SECRET, IFID)
end

local function pio(prefix, len, flags, valid, preferred)
    return string.pack(">I1I1I1I1I4I4I4", 3, 4, len, flags, valid, preferred, 0) .. gateway.ip6(prefix)
end

--- An advertisement from the gateway's link-local, router lifetime
--- 1800, carrying `options` (raw).
local function advertise(options)
    local body = string.pack(">I1I1I2I1I1I2I4I4", 134, 0, 0, 64, 0, 1800, 0, 0) .. options
    gw:send_ip6(gateway.ALL_NODES, 58, gateway.icmp6(gw.ll, gateway.ALL_NODES, body))
end

local L, A = 0x80, 0x40

--- Pump until `pred()` holds; returns whether it did.
local function pump_until(pred, timeout)
    return gw:serve({ timeout = timeout or 15, until_ = pred })
end

local function present(addr) return rtnl.address(sut, INDEX, addr) end

--- netd's user+system CPU ticks (/proc/<pid>/stat) spent over `secs`
--- seconds of pumping.
local function netd_cpu_over(secs)
    local pid = assert(network.netd_pid(sut), "netd is running")
    local function ticks()
        local stat = sut:read_file("/proc/" .. pid .. "/stat")
        local rest = assert(stat:match("%) (.*)$"), "a /proc stat line")
        local f = {}
        for x in rest:gmatch("%S+") do f[#f + 1] = x end
        return tonumber(f[12]) + tonumber(f[13])
    end
    local before = ticks()
    gw:serve({ timeout = secs })
    return ticks() - before
end

local function prefix_route(prefix, plen)
    for _, r in ipairs(rtnl.routes_of(sut, INDEX)) do
        if r.family == 6 and r.dst == prefix and r.prefix == plen then return r end
    end
end

-- ---------------------------------------------------------------------------
-- The stable address
-- ---------------------------------------------------------------------------

test("each accepted prefix gets one stable address: the prefix, then the first 8 bytes of SHA-1 over the label, the secret, the prefix, the interface id and a counter",
    { spec = "netd *slaac.stable-privacy-derivation" }, function(t)
        local s = serve_iface(function(i)
            return network.bound(i) and i.gateway6 == GW_LL and #network.ipv6(i) > 0
        end, { iface = "eth0", timeout = 60 })
        t:assert(s, "netd took the router's prefix")
        local want = expected("fd77::")
        t:log("interface id " .. IFID .. "; expected " .. want .. "; status " .. table.concat(s.addresses, " "))
        t:assert(status_has(s, want), "the status carries the computed stable address " .. want)
        local k = kernel_in("fd77::")
        t:assert_eq(#k, 1, "exactly one address in the prefix (no temporary without Address.Temporary)")
        t:assert_eq(k[1] and k[1].address, want, "the kernel carries it")
        t:assert_eq(k[1] and k[1].prefix, 64, "…as a /64")
    end)

test("the same machine on the same network has the same address across a restart and a cable pull; another network an unrelated one; no MAC in it",
    { spec = "netd *slaac.same-machine-same-network-same-address" }, function(t)
        local want = expected("fd77::")
        network.restart_netd(sut)
        t:assert(serve_iface(function(i) return status_has(i, want) end,
            { iface = "eth0", timeout = 30 }), "after netd restarted, the same address " .. want)
        nic:disconnect()
        t:assert(serve_iface(function(i) return i.carrier == false end,
            { iface = "eth0", timeout = 20 }), "carrier dropped")
        nic:reconnect()
        local s = serve_iface(function(i) return status_has(i, want) end,
            { iface = "eth0", timeout = 30 })
        t:assert(s, "after a cable pull, the same address " .. want)
        t:assert_eq(#kernel_in("fd77::"), 1, "and only it")

        -- Another network: a different prefix, an unrelated identifier.
        advertise(pio("fd78::", 64, L | A, 3600, 3600))
        local other = expected("fd78::")
        t:assert(serve_iface(function(i) return status_has(i, other) end,
            { iface = "eth0", timeout = 15 }), "fd78::/64 gets " .. other)
        local iid1, iid2 = gateway.ip6(want):sub(9, 16), gateway.ip6(other):sub(9, 16)
        t:assert(iid1 ~= iid2, "the two networks see different interface identifiers")
        local b = { MAC:byte(1, 6) }
        local eui = string.char(b[1] ~ 2, b[2], b[3], 0xff, 0xfe, b[4], b[5], b[6])
        for _, iid in ipairs({ iid1, iid2 }) do
            t:assert(iid ~= eui, "the identifier is not the EUI-64 of the MAC")
            t:assert(not iid:find(MAC:sub(4, 6), 1, true), "the MAC's last three bytes do not appear in it")
        end
    end)

-- ---------------------------------------------------------------------------
-- Which prefixes
-- ---------------------------------------------------------------------------

test("only a prefix with A, length 64 and preferred ≤ valid forms an address, and a new one only with a valid lifetime; an L-only prefix gets neither address nor route",
    { spec = "netd *slaac.prefix-acceptance" }, function(t)
        advertise(pio("fd51::", 64, L, 3600, 3600)           -- L only
            .. pio("fd52::", 48, L | A, 3600, 3600)           -- /48
            .. pio("fd5e::", 80, L | A, 3600, 3600)           -- /80
            .. pio("fd53::", 64, L | A, 100, 200)             -- preferred > valid
            .. pio("fd54::", 64, L | A, 0, 0)                 -- new, valid 0
            .. pio("fd55::", 64, L | A, 3600, 3600))          -- the marker
        local marker = expected("fd55::")
        t:assert(pump_until(function() return present(marker) end), "the marker prefix formed " .. marker)
        for _, p in ipairs({ "fd51::", "fd52::", "fd5e::", "fd53::", "fd54::" }) do
            t:assert_eq(#kernel_in(p), 0, "no address from " .. p)
        end
        t:assert(not prefix_route("fd51::", 64), "no on-link route for the L-only prefix")
        t:assert(not prefix_route("fd52::", 48), "no route for the /48")
    end)

test("an off-link prefix's address is added with IFA_F_NOPREFIXROUTE and gets no prefix route; an on-link one gets the kernel's",
    { spec = "netd *slaac.off-link-gets-no-prefix-route" }, function(t)
        advertise(pio("fd56::", 64, A, 3600, 3600))
        local off = expected("fd56::")
        t:assert(pump_until(function() return present(off) end), "the off-link prefix formed " .. off)
        local a = present(off)
        t:assert(a.noprefixroute, "the off-link address carries IFA_F_NOPREFIXROUTE")
        t:assert(not prefix_route("fd56::", 64), "no fd56::/64 route")
        local on = present(expected("fd55::"))
        t:assert(on, "the on-link address from the last test is there")
        t:assert(not on.noprefixroute, "the on-link address has no IFA_F_NOPREFIXROUTE")
        local r = prefix_route("fd55::", 64)
        t:assert(r, "the kernel added the on-link prefix route fd55::/64")
        t:assert_eq(r and r.protocol, rtnl.RTPROT.KERNEL, "…as the kernel's own")
    end)

-- ---------------------------------------------------------------------------
-- Lifetimes
-- ---------------------------------------------------------------------------

test("0xffffffff is forever; an update takes the on-link flag and the preferred lifetime as advertised",
    { spec = "netd *slaac.lifetimes" }, function(t)
        local addr = expected("fd57::")
        advertise(pio("fd57::", 64, L | A, FOREVER, FOREVER))
        t:assert(pump_until(function() return present(addr) end), "fd57::/64 formed " .. addr)
        gw:serve({ timeout = 3 })
        local a = present(addr)
        t:assert(a and not a.deprecated, "a forever preferred lifetime: not deprecated")
        t:assert_eq(a and a.preferred, FOREVER, "netd gives the kernel a forever preferred lifetime")
        t:assert(prefix_route("fd57::", 64), "on-link: the prefix route is there")

        -- Preferred 0 is taken at once, shortening included.
        advertise(pio("fd57::", 64, L | A, FOREVER, 0))
        t:assert(pump_until(function() local x = present(addr); return x and x.deprecated end),
            "an advertised preferred lifetime of 0 deprecates it")
        t:assert_eq(present(addr).preferred, 0, "…preferred lifetime 0 in the kernel")

        -- On-link flag cleared, preferred forever again.
        advertise(pio("fd57::", 64, A, FOREVER, FOREVER))
        t:assert(pump_until(function()
            local x = present(addr)
            return x and x.noprefixroute and not x.deprecated
        end), "the update's L=0 and preferred forever are taken")
        t:assert(pump_until(function() return not prefix_route("fd57::", 64) end, 5),
            "the prefix route went with the on-link flag")
    end)

test("when the preferred lifetime runs out the address is deprecated and kept, with netd idle meanwhile; when the valid lifetime does, removed",
    { spec = "netd *slaac.deprecate-then-remove netd *loop.one-thread-one-poll" }, function(t)
        local addr = expected("fd58::")
        local quiet = netd_cpu_over(3)
        local t0 = gw:now()
        advertise(pio("fd58::", 64, L | A, 12, 5))
        t:assert(pump_until(function() local x = present(addr); return x and not x.deprecated end, 5),
            "fd58::/64 formed " .. addr .. ", preferred")
        t:assert(pump_until(function() local x = present(addr); return x and x.deprecated end, 15),
            "deprecated when its preferred lifetime ran out")
        local dep = gw:now() - t0
        t:log("deprecated at +" .. dep .. "s")
        t:assert(dep >= 4 and dep <= 7, "…5 s after the advertisement (+" .. dep .. "s)")
        t:assert(network.has_address(iface(), addr), "the deprecated address is still on the interface")
        t:assert_eq(present(addr).preferred, 0, "kept with a preferred lifetime of 0")
        -- The loop sleeps in poll until something is due (§2.2). The
        -- passed preferred lifetime is not due again: offered as a
        -- deadline it made the timeout zero, and netd spun a whole core
        -- until the address went, about 370 ticks in these 3 s (PEI-1367).
        local busy = netd_cpu_over(3)
        t:log(string.format("netd CPU ticks over 3 s: %d with nothing deprecated, %d with a deprecated address",
            quiet, busy))
        t:assert(busy <= quiet + 30, "netd stays idle while an address is deprecated (" .. busy
            .. " ticks in 3 s, against " .. quiet .. " with none)")
        t:assert(pump_until(function() return not present(addr) end, 15),
            "removed when its valid lifetime ran out")
        local gone = gw:now() - t0
        t:log("removed at +" .. gone .. "s")
        t:assert(gone >= 11 and gone <= 14, "…12 s after the advertisement (+" .. gone .. "s)")
        t:assert(not network.has_address(iface(), addr), "gone from the status too")
    end)

test("the two-hour rule: a longer or over-two-hours valid lifetime is taken; a short one never cuts the remaining lifetime",
    { spec = "netd *slaac.two-hour-rule" }, function(t)
        local a1, a2, a3, a4, a5 = expected("fd59::"), expected("fd5a::"), expected("fd5b::"),
            expected("fd5c::"), expected("fd5d::")
        local t0 = gw:now()
        advertise(pio("fd59::", 64, L | A, 10, 10)            -- row 1
            .. pio("fd5a::", 64, L | A, 14, 14)               -- row 2
            .. pio("fd5b::", 64, L | A, 86400, 3600)          -- row 3
            .. pio("fd5c::", 64, L | A, FOREVER, FOREVER)     -- row 4
            .. pio("fd5d::", 64, L | A, FOREVER, FOREVER))    -- row 5
        t:assert(pump_until(function()
            return present(a1) and present(a2) and present(a3) and present(a4) and present(a5)
        end, 10), "all five prefixes formed their addresses")
        gw:serve({ timeout = math.max(0, t0 + 3 - gw:now()) })
        local t1 = gw:now()
        advertise(pio("fd59::", 64, L | A, 30, 30)            -- above what remains: taken
            .. pio("fd5a::", 64, L | A, 4, 4)                 -- ≤ 2 h, not above, ≤ 2 h left: unchanged
            .. pio("fd5b::", 64, L | A, 3, 0)                 -- ≤ 2 h, > 2 h left: two hours
            .. pio("fd5c::", 64, L | A, 7300, 0)              -- > 2 h, forever: taken
            .. pio("fd5d::", 64, L | A, 3, 0))                -- ≤ 2 h, forever: forever (PEI-1335)
        t:log("re-advertised at +" .. (t1 - t0) .. "s")
        -- Row 2: the 4 s would have ended at t1+4; the original at t0+14.
        gw:serve({ timeout = math.max(0, t1 + 7 - gw:now()) })
        t:assert(present(a2), "row 2: a shorter lifetime did not cut the remaining one (alive at +"
            .. (gw:now() - t0) .. "s)")
        t:assert(pump_until(function() return not present(a2) end, 12), "row 2: removed at last")
        local gone2 = gw:now() - t0
        t:assert(gone2 >= 13 and gone2 <= 16, "row 2: at the original 14 s (+" .. gone2 .. "s)")
        -- Row 1: the original 10 s are past; it lives on.
        t:assert(gw:now() - t0 >= 12, "past the original 10 s")
        t:assert(present(a1), "row 1: the longer advertised lifetime was taken")
        -- Rows 3, 4 and 5: the advertised 3 s (or 7300) did not shorten
        -- the address to seconds. Row 5 is PEI-1335: an infinite remaining
        -- lifetime stays infinite under a short advertisement.
        t:assert(present(a3), "row 3: alive well past the advertised 3 s")
        t:assert(present(a4), "row 4: alive")
        t:assert(present(a5), "row 5: alive well past the advertised 3 s")
        t:assert(pump_until(function() return not present(a1) end, 25), "row 1: removed at last")
        local gone1 = gw:now() - t1
        t:log("row 1 removed at +" .. gone1 .. "s after the re-advertisement")
        t:assert(gone1 >= 29 and gone1 <= 32, "row 1: 30 s after the re-advertisement (+" .. gone1 .. "s)")
        t:assert(present(a3) and present(a4) and present(a5), "rows 3 to 5 still alive at +"
            .. (gw:now() - t0) .. "s")
    end)
