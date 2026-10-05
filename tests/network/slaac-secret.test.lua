-- netd §6.2 — the stable-privacy secret: read from
-- /var/state/netd/secret the first time an interface starts router
-- discovery, replaced from /dev/urandom when the file does not hold
-- exactly 32 bytes, and used for the process's life when it cannot be
-- written. Losing it renumbers the machine and does nothing else.
--
-- Harness: the scripted gateway (helpers.gateway) playing a router that
-- answers every solicitation with BASE (fd77::/64). One whole Peios
-- machine joined by the shipped baseline. Each step edits the secret
-- file from the guest and restarts netd (a new process reads it afresh);
-- a cable pull restarts discovery inside one process. The address
-- expected from a given secret is computed here (helpers.sha1).
--
-- Own VMs: the test rewrites the machine's secret, which renumbers it.
-- It puts the original back at the end.

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
local GW_LL = gateway.ip6_text(gw.ll)
local SECRET_PATH = "/var/state/netd/secret"

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

--- The machine's addresses in fd77::/64, per the kernel.
local function addresses77()
    local out = {}
    for _, a in ipairs(rtnl.addresses_of(sut, INDEX, 6)) do
        if in64(a.address, "fd77::") then out[#out + 1] = a.address end
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

--- Wait until fd77::/64 holds exactly one address, and return it.
local function settled_address(timeout)
    local addr
    gw:serve({ timeout = timeout or 30, until_ = function()
        local a = addresses77()
        if #a == 1 then addr = a[1]; return true end
        return false
    end })
    return addr
end

--- Wait until fd77::/64 holds exactly `want`.
local function holds(want, timeout)
    return gw:serve({ timeout = timeout or 30, until_ = function()
        local a = addresses77()
        return #a == 1 and a[1] == want
    end })
end

local function cable_cycle()
    nic:disconnect()
    assert(serve_iface(function(i) return i.carrier == false end,
        { iface = "eth0", timeout = 20 }), "carrier did not drop")
    nic:reconnect()
    assert(serve_iface(function(i) return i.carrier and i.gateway6 == GW_LL end,
        { iface = "eth0", timeout = 30 }), "the router did not come back")
end

local function count_logged(text)
    local n = 0
    for _, l in ipairs(network.logs(sut, { since = "30m ago", take = 2000 })) do
        if l:find(text, 1, true) then n = n + 1 end
    end
    return n
end

-- ---------------------------------------------------------------------------

test("the secret is read when discovery first starts; a file not of 32 bytes is replaced from urandom and written; one that cannot be written is logged and used for the process's life; losing it renumbers and nothing else",
    { spec = "netd *slaac.secret" }, function(t)
        local s = serve_iface(function(i)
            return network.bound(i) and i.gateway6 == GW_LL and #network.ipv6(i) > 0
        end, { iface = "eth0", timeout = 60 })
        t:assert(s, "netd took the router's prefix")
        local ifid, lease, net = s.ifid, network.ipv4(s)[1], s.network
        local duid = network.get(sut, network.KEY, "Duid")
        local original = sut:read_file(SECRET_PATH)
        t:assert_eq(#original, 32, "the secret file holds 32 bytes")
        local a0 = stable("fd77::", original, ifid)
        t:assert(holds(a0, 10), "the address is the one the file's secret gives: " .. a0)

        -- Read once per process: a new file under a running netd changes
        -- nothing, even across a restart of discovery.
        local other = string.rep("\x5a", 32)
        sut:write_file(SECRET_PATH, other)
        t:assert_eq(sut:read_file(SECRET_PATH), other, "the file now holds another 32-byte secret")
        cable_cycle()
        t:assert(holds(a0, 20), "after a cable pull the in-memory secret still gives " .. a0)

        -- A file that does not hold 32 bytes: a new secret, written back.
        sut:write_file(SECRET_PATH, "short")
        network.restart_netd(sut)
        local a1 = settled_address(30)
        t:assert(a1, "an address after the restart")
        local fresh = sut:read_file(SECRET_PATH)
        t:assert_eq(#fresh, 32, "a 5-byte secret was replaced by 32 bytes")
        t:assert(fresh ~= original and fresh ~= other and fresh ~= "short", "…new ones")
        t:assert_eq(a1, stable("fd77::", fresh, ifid), "the address is the new secret's")
        t:assert(a1 ~= a0, "the machine was renumbered")
        -- …and nothing else.
        s = serve_iface(network.bound, { iface = "eth0", timeout = 30 })
        t:assert(s, "the lease is held")
        t:assert_eq(s.ifid, ifid, "the interface id is unchanged")
        t:assert_eq(network.ipv4(s)[1], lease, "the DHCPv4 address is unchanged")
        t:assert_eq(s.network, net, "the network id is unchanged")
        t:assert_eq(network.get(sut, network.KEY, "Duid"), duid, "the DUID is unchanged")

        -- A secret that cannot be written: logged, and used for the rest
        -- of the process's life.
        local warned = count_logged("could not persist the address secret at " .. SECRET_PATH)
        sut:run("rm -f " .. SECRET_PATH .. " && mkdir " .. SECRET_PATH):assert_ok()
        network.restart_netd(sut)
        local a2 = settled_address(30)
        t:assert(a2, "an address after the restart")
        t:assert(count_logged("could not persist the address secret at " .. SECRET_PATH) > warned,
            "netd logged `could not persist the address secret at " .. SECRET_PATH .. "`")
        t:log(string.format("addresses: original %s; after a 5-byte file %s; with an unwritable file %s",
            a0, tostring(a1), tostring(a2)))
        t:assert(a2 ~= a0 and a2 ~= a1, "a new secret again: " .. tostring(a2))
        cable_cycle()
        t:assert(holds(a2, 20), "the unwritten secret is used for the rest of the process's life")

        -- Put the original back.
        sut:run("rmdir " .. SECRET_PATH):assert_ok()
        sut:write_file(SECRET_PATH, original)
        network.restart_netd(sut)
        t:assert(holds(a0, 30), "with the original secret back, the original address " .. a0)
    end)
