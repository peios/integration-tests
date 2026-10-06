-- netd §6.2 — temporary addresses (RFC 8981) beside the stable one, under
-- the profile's `Address.Temporary`.
--
-- Harness: the scripted gateway (helpers.gateway) playing a router that
-- answers every solicitation with BASE (fd77::/64), and sending each
-- step's own advertisements. One whole Peios machine joined by the
-- shipped baseline, with `Address.Temporary` written to
-- Profiles\default by the test (a profile edit, which restarts router
-- discovery, §3.3) and deleted again at the end. The stable address is
-- computed from the secret (helpers.sha1) so the temporaries can be told
-- from it exactly.
--
-- What cannot be seen: a temporary's own lifetimes (a day less up to
-- 599 s, two days) are netd's to keep; the kernel is told forever (or a
-- preferred lifetime of 0 once deprecated), so only the effect of a
-- prefix's shorter lifetimes, which cut them, is observable here.
--
-- Regeneration is driven by keeping the prefix's preferred lifetime a
-- few seconds ahead of the newest temporary's: each temporary is cut to
-- the prefix's preferred lifetime as it stood when it was formed, so
-- re-advertising every 1.5 s with a preferred lifetime of 3 s makes the
-- newest one lapse while the prefix is still preferred, and a new one is
-- formed each time.
--
-- Own VMs: the profile edit and the regeneration chain are this file's
-- alone.

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

local INDEX = tonumber((sut:read_file("/sys/class/net/eth0/ifindex"):match("%d+")))
local MAC = gateway.mac(sut:read_file("/sys/class/net/eth0/address"))
local GW_LL = gateway.ip6_text(gw.ll)
local PROFILE = "Profiles\\default"

-- ---------------------------------------------------------------------------
-- Local helpers
-- ---------------------------------------------------------------------------

local function iface() return network.iface(network.status(sut), "eth0") end

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

local function reserved(iid)
    if iid == string.rep("\0", 8) then return true end
    if iid:sub(1, 4) == "\2\0\x5e\xff" then return true end
    return iid:sub(1, 7) == "\xfd\xff\xff\xff\xff\xff\xff" and iid:byte(8) >= 0x80
end

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

--- The temporaries in `prefix`: every kernel address there but the
--- stable one.
local function temporaries(prefix)
    local st = expected(prefix)
    local out = {}
    for _, a in ipairs(kernel_in(prefix)) do
        if a.address ~= st then out[#out + 1] = a end
    end
    return out
end

local function pio(prefix, len, flags, valid, preferred)
    return string.pack(">I1I1I1I1I4I4I4", 3, 4, len, flags, valid, preferred, 0) .. gateway.ip6(prefix)
end

local function advertise(options)
    local body = string.pack(">I1I1I2I1I1I2I4I4", 134, 0, 0, 64, 0, 1800, 0, 0) .. options
    gw:send_ip6(gateway.ALL_NODES, 58, gateway.icmp6(gw.ll, gateway.ALL_NODES, body))
end

local function pump_until(pred, timeout)
    return gw:serve({ timeout = timeout or 15, until_ = pred })
end

local function count_logged(text)
    local n = 0
    for _, l in ipairs(network.logs(sut, { since = "30m ago", take = 2000 })) do
        if l:find(text, 1, true) then n = n + 1 end
    end
    return n
end

local LA = 0xc0

-- ---------------------------------------------------------------------------

test("with Address.Temporary each prefix also carries random temporary addresses, cut to the prefix's lifetimes, regenerated when the newest lapses while the prefix is preferred, at most four kept",
    { spec = "netd *slaac.temporary-addresses" }, function(t)
        t:assert(serve_iface(function(i)
            return network.bound(i) and i.gateway6 == GW_LL and #network.ipv6(i) > 0
        end, { iface = "eth0", timeout = 60 }), "netd took the router's prefix")
        local st = expected("fd77::")
        t:assert_eq(#kernel_in("fd77::"), 1, "without Address.Temporary: the stable address alone")

        -- Address.Temporary is read when discovery starts: the edit
        -- restarts it, and the router's answer brings a temporary.
        local starts = count_logged("interface eth0: soliciting routers")
        network.write(sut, PROFILE, { ["Address.Temporary"] = "dword:1" })
        t:assert(pump_until(function() return #temporaries("fd77::") == 1 end, 20),
            "after the edit, fd77::/64 carries one temporary")
        t:assert(count_logged("interface eth0: soliciting routers") > starts,
            "the edit restarted discovery (`soliciting routers` again)")
        local tmp = temporaries("fd77::")[1]
        local iid = gateway.ip6(tmp.address):sub(9, 16)
        local b = { MAC:byte(1, 6) }
        t:log("stable " .. st .. ", temporary " .. tmp.address)
        t:assert(rtnl.address(sut, INDEX, st), "the stable address " .. st .. " stays beside it")
        t:assert(not reserved(iid), "the temporary's identifier is not reserved")
        t:assert(iid ~= string.char(b[1] ~ 2, b[2], b[3], 0xff, 0xfe, b[4], b[5], b[6]),
            "…and not the MAC's EUI-64")
        t:assert(not tmp.deprecated, "the new temporary is preferred")

        -- Cut to the prefix's own lifetimes.
        local t0 = gw:now()
        advertise(pio("fd81::", 64, LA, 10, 5))
        t:assert(pump_until(function() return #kernel_in("fd81::") == 2 end, 5),
            "a prefix arriving preferred brings its stable address and one temporary")
        t:assert(pump_until(function()
            local x = kernel_in("fd81::")
            return #x == 2 and x[1].deprecated and x[2].deprecated
        end, 20), "both deprecated with the prefix")
        -- The window is wide for a loaded host: the claim is the prefix's
        -- 5 s rather than a temporary's own day, not a precise moment.
        local dep = gw:now() - t0
        t:assert(dep >= 4 and dep <= 15, "…at the prefix's 5 s (+" .. dep .. "s), not a day")
        t:assert_eq(#kernel_in("fd81::"), 2, "no new temporary once the prefix itself is deprecated")
        t:assert(pump_until(function() return #kernel_in("fd81::") == 0 end, 10), "both removed with the prefix")
        local gone = gw:now() - t0
        t:assert(gone >= 9 and gone <= 12, "…at the prefix's 10 s (+" .. gone .. "s), not two days")

        -- A prefix arriving with preferred lifetime 0 forms no temporary.
        advertise(pio("fd82::", 64, LA, 600, 0))
        t:assert(pump_until(function() return #kernel_in("fd82::") >= 1 end, 5), "fd82::/64 formed its stable address")
        gw:serve({ timeout = 1 })
        t:assert_eq(#kernel_in("fd82::"), 1, "no temporary for a prefix arriving with preferred lifetime 0")

        -- Regeneration, and the cap.
        local seen, order = {}, {}
        local max_live = 0
        local function sample()
            local live = temporaries("fd83::")
            if #live > max_live then max_live = #live end
            for _, a in ipairs(live) do
                if not seen[a.address] then seen[a.address] = true; order[#order + 1] = a.address end
            end
            return live
        end
        local rounds = 0
        while #order < 4 and rounds < 12 do
            advertise(pio("fd83::", 64, LA, 600, 3))
            rounds = rounds + 1
            gw:serve({ timeout = 1.5, until_ = function() sample(); return false end })
        end
        t:log(rounds .. " advertisements; temporaries formed: " .. table.concat(order, " "))
        t:assert(#order >= 4, "a new temporary each time the newest lapsed with the prefix still preferred")
        -- Now keep the prefix preferred long: the newest lapses once more
        -- and a fifth is formed, with nothing due for 30 s after.
        advertise(pio("fd83::", 64, LA, 600, 30))
        gw:serve({ timeout = 6, until_ = function() sample(); return false end })
        local live = sample()
        local newest = 0
        for _, a in ipairs(live) do if not a.deprecated then newest = newest + 1 end end
        t:log("formed " .. #order .. "; live now " .. #live .. "; most live at once " .. max_live)
        for _, a in ipairs(live) do
            t:log(string.format("  %s%s", a.address, a.deprecated and " (deprecated)" or ""))
        end
        t:assert(#order >= 5, "a fifth temporary was formed")
        t:assert_eq(newest, 1, "exactly one temporary is preferred; the older ones stay, deprecated")
        local distinct = 0
        for _ in pairs(seen) do distinct = distinct + 1 end
        t:assert_eq(distinct, #order, "every temporary was a new address")
        -- The list is cut to four after the regenerated temporary is
        -- added. It was once cut before, and five reached the interface;
        -- only netd spinning on a past deadline (PEI-1367) hid that, by
        -- cutting again at once.
        t:assert(max_live <= 4, "at most four temporaries at once (saw " .. max_live .. ")")
        t:assert(not rtnl.address(sut, INDEX, order[1]), "the oldest (" .. order[1] .. ") was dropped")

        -- Without Address.Temporary again: discovery restarts, no temporaries.
        network.reg(sut, { "del", network.KEY .. "\\" .. PROFILE, "Address.Temporary" }):assert_ok()
        t:assert(pump_until(function()
            return #temporaries("fd77::") == 0 and rtnl.address(sut, INDEX, st) ~= nil
        end, 20), "Address.Temporary removed: the stable address alone again")
    end)
