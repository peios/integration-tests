-- netd TRM §4.1 "Identity and carrier", the carrier half: what losing
-- carrier stops and forgets, what the next reconcile then removes and
-- keeps, what returning carrier starts again; and a card that leaves the
-- kernel altogether.
--
-- Harness: the scripted gateway as DHCPv4 server and router (one /64,
-- fd77::/64, so the machine has SLAAC addresses and a v6 default route
-- to lose), and one whole Peios machine on the same bridge. The cable is
-- pulled with provium's NIC link switch (`lan:nic(sut)`); the virtio
-- driver sees the link go and clears IFF_LOWER_UP, which is exactly the
-- carrier netd watches.
--
-- Its own pair because the machine boots into a seeded interface layer
-- (registry seeds staged before netd starts), so the first exchange is
-- already the one these tests are about:
--
--   Profiles\ptcar        the baseline's four switches plus a static
--                         address, 10.88.0.5/24, which must survive;
--   Profiles\ptcar\net    inherits it, Route.Metric 150;
--   Rules\Interface\ptc-car  wired -> JOIN(ptcar), priority 20;
--   Rules\Interface\ptc-net  wired with Network.Id present ->
--                         JOIN(ptcar/net), priority 30.
--
-- So the profile an interface stands in says whether netd's judgement
-- currently has a Network.* fact for it: ptcar/net while a network is
-- identified, ptcar when it is not.
--
-- A cable pull can never show the RELEASE the stopping client sends: the
-- link is down, so the frame dies in the guest (dhcp4-loss.test.lua
-- shows the server never sees it). The release itself is §5.4's.
--
-- The last test unbinds the virtio driver, so eth0 leaves the kernel
-- (a card removed, not a cable pulled), then binds it back.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local rtnl = require("helpers.rtnl")

peinit.claim(2)

local N = [[Machine\System\Network]]
local function k(path, values) return { path = path, values = values } end
local function dword(name, v) return { name = name, type = "dword", data = v } end
local function sz(name, v) return { name = name, type = "sz", data = v } end
local function multi(name, v) return { name = name, type = "multi", data = v } end

local seeds = peinit.seed("pt-ifid-carrier", {
    k([[Machine\System]]), k(N), k(N .. [[\Profiles]]),
    k(N .. [[\Profiles\ptcar]], {
        dword("Address.Offered", 1), dword("Address.LinkLocal", 1),
        dword("Route.Offered", 1), dword("Dns.Offered", 1),
        multi("Address.Static", { "10.88.0.5/24" }),
    }),
    k(N .. [[\Profiles\ptcar\net]], { dword("Route.Metric", 150) }),
    k(N .. [[\Rules]]), k(N .. [[\Rules\Interface]]),
    k(N .. [[\Rules\Interface\ptc-car]], {
        sz("Interface.Kind.Equal", "wired"), dword("Priority", 20),
        multi("Actions", { "JOIN(ptcar)" }),
    }),
    k(N .. [[\Rules\Interface\ptc-net]], {
        sz("Interface.Kind.Equal", "wired"), dword("Network.Id.Present", 1),
        dword("Priority", 30), multi("Actions", { "JOIN(ptcar/net)" }),
    }),
})

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
gw:router({ lifetime = 1800, prefixes = { { prefix = "fd77::", len = 64 } } })
local sut = network.boot({ bridges = { lan }, gateway = gw, files = seeds })
local nic = lan:nic(sut)

local LEASED = "10.77.0.50"
local STATIC = "10.88.0.5"
local D = gateway.DHCP
local NETID = "^%x+%-%x+%-%x+%-%x+%-%x+$"

local function ready(i)
    return network.bound(i) and i.profile == "ptcar/net" and #network.ipv6(i) > 0
        and i.gateway6 ~= nil
end

local function record(id, value)
    return network.get(sut, "Interfaces\\" .. id .. "\\Status", value)
end

local function count_logged(text)
    local n = 0
    for _, l in ipairs(network.logs(sut, { take = 1000 })) do
        if l:find(text, 1, true) then n = n + 1 end
    end
    return n
end

--- The kernel's view of eth0 (`index`): addresses by text, and netd's
--- routes (protocol 200) as "dst/prefix via gw metric".
local function kernel(index)
    local addrs, routes = {}, {}
    for _, a in ipairs(rtnl.addresses_of(sut, index)) do addrs[a.address] = a end
    for _, r in ipairs(rtnl.routes_of(sut, index)) do
        if r.protocol == rtnl.RTPROT.NETD then
            routes[#routes + 1] = string.format("%s/%d via %s metric %d", r.dst, r.prefix,
                tostring(r.gateway), r.metric)
        end
    end
    table.sort(routes)
    return addrs, routes
end

-- What the machine looked like on its network, for the later tests.
local before = {}

test("losing carrier stops the clients and forgets the network: `carrier lost` is logged, the lease goes, Status Network and the Network.* facts go absent, LastNetwork stays",
    { spec = "netd *ifid.carrier-loss" }, function(t)
    local s = network.serve_until(gw, sut, ready, { iface = true, timeout = 90 })
    t:assert(s, "eth0 bound, identified its network (ptcar/net) and took a SLAAC address")
    local i = network.iface(s, "eth0")
    before.id, before.index, before.network = i.ifid, i.index, i.network
    before.v6 = network.ipv6(i)
    t:log("network " .. tostring(i.network) .. ", v6 " .. table.concat(before.v6, " "))
    t:assert(i.network and i.network:match(NETID), "a network is identified")
    t:assert_eq(record(i.ifid, "Network"), i.network, "Status Network names it")
    t:assert_eq(record(i.ifid, "LastNetwork"), i.network, "Status LastNetwork names it")
    t:assert_eq(i.profile, "ptcar/net", "judged with Network.Id present")

    local lost = count_logged("interface eth0: carrier lost")
    nic:disconnect()
    local off = network.serve_until(gw, sut, function(x)
        return x.carrier == false and x.lease == nil and x.network == nil
    end, { iface = true, timeout = 30 })
    t:assert(off, "netd saw the carrier go, dropped the lease and the network")
    local o = network.iface(off, "eth0")
    t:assert(count_logged("interface eth0: carrier lost") > lost, "`interface eth0: carrier lost` logged")
    t:assert_eq(o.ifid, before.id, "the same interface")
    t:assert(o.up, "still administratively up (only the carrier went)")
    t:assert_eq(o.lease, nil, "no lease")
    t:assert_eq(o.network, nil, "Status network cleared")
    t:assert_eq(o.network_name, nil, "no network name")
    -- The judgement no longer has Network.Id: the rule needing it is out.
    wait_until(function() return network.iface(network.status(sut), "eth0").profile == "ptcar" end,
        { timeout = 20, interval = 0.25, desc = "re-judged without a network" })
    t:assert_eq(network.iface(network.status(sut), "eth0").rule, "ptc-car", "the Network.Id rule no longer speaks")
    -- The kernel's packet layers read Status Network: it is gone.
    t:assert_eq(record(before.id, "Network"), nil, "Status Network removed")
    t:assert_eq(record(before.id, "LastNetwork"), before.network, "Status LastNetwork kept")
end)

test("the reconcile after carrier loss removes the leased and autoconfigured addresses and the routes that used them; a static address stays",
    { spec = "netd *ifid.carrier-loss-removes-offered-config" }, function(t)
    t:assert(before.index, "the first test recorded eth0")
    local addrs, routes
    wait_until(function()
        addrs, routes = kernel(before.index)
        if addrs[LEASED] or #routes > 0 then return false end
        for _, a in ipairs(before.v6) do
            if addrs[a:match("^[^/]+")] then return false end
        end
        return true
    end, { timeout = 20, interval = 0.25, desc = "the offered configuration to go" })
    local names = {}
    for a in pairs(addrs) do names[#names + 1] = a end
    table.sort(names)
    t:log("eth0 now holds: " .. table.concat(names, " ") .. "; netd routes: " .. table.concat(routes, ", "))
    t:assert_eq(addrs[LEASED], nil, "the leased address is gone")
    for _, a in ipairs(before.v6) do
        t:assert_eq(addrs[a:match("^[^/]+")], nil, "the SLAAC address " .. a .. " is gone")
    end
    t:assert_eq(#routes, 0, "no protocol-200 route is left (IPv4 and IPv6 defaults gone)")
    t:assert(addrs[STATIC] ~= nil, "the static address stays")
    t:assert_eq(addrs[STATIC].prefix, 24, "at its prefix")
    -- The kernel's own link-local is not netd's, and stays.
    local ll = false
    for a in pairs(addrs) do if a:match("^fe80:") then ll = true end end
    t:assert(ll, "the kernel's IPv6 link-local stays")
end)

test("when carrier returns the pass starts the clients from scratch: DHCPv4 first asks (INIT-REBOOT) for the address the network last gave, routers are solicited again",
    { spec = "netd *ifid.carrier-loss" }, function(t)
    gw:forget()
    nic:reconnect()
    local s = network.serve_until(gw, sut, ready, { iface = true, timeout = 60 })
    t:assert(s, "bound again, the network identified, SLAAC back")
    local msgs = gw:dhcp_messages()
    t:assert(#msgs > 0, "the client spoke")
    local first = msgs[1]
    t:log(string.format("first DHCP message after the return: %s ciaddr %s opt50 %s opt54 %s",
        tostring(gateway.DHCP_NAME[first.type]), first.ciaddr,
        first.opt[50] and gateway.ip4_text(first.opt[50]) or "-",
        first.opt[54] and gateway.ip4_text(first.opt[54]) or "-"))
    t:assert_eq(first.type, D.REQUEST, "the first message is a REQUEST")
    t:assert_eq(first.ciaddr, "0.0.0.0", "INIT-REBOOT: ciaddr is zero")
    t:assert(first.opt[50] ~= nil, "it requests an address")
    t:assert_eq(gateway.ip4_text(first.opt[50]), LEASED, "the address the network last gave")
    t:assert_eq(first.opt[54], nil, "no server identifier")
    t:assert(#gw:solicitations() > 0, "router discovery started again (a solicitation)")
    local i = network.iface(s, "eth0")
    t:assert_eq(i.network, before.network, "the same network is identified again")
    t:assert(network.has_address(i, LEASED), "the lease's address is back")
end)

test("a card that leaves the kernel is dropped with its clients, lease and network, nothing is sent, and its record stays; when it comes back it is a new sighting with the same id",
    { spec = "netd *ifid.appear-disappear" }, function(t)
    local s = network.serve_until(gw, sut, ready, { iface = true, timeout = 30 })
    t:assert(s, "bound before the card goes")
    local dev = sut:run("realpath /sys/class/net/eth0/device")
    dev:assert_ok()
    local virtio = dev.stdout:match("([^/\n]+)\n?$")
    t:log("eth0's virtio device: " .. virtio)
    local sightings = count_logged("interface eth0 (pci-0000:00:02.0) is " .. before.id)
    gw:forget()
    sut:run("echo " .. virtio .. " > /sys/bus/virtio/drivers/virtio_net/unbind"):assert_ok()
    local gone = network.serve_until(gw, sut, function(st) return network.iface(st, "eth0") == nil end,
        { timeout = 20 })
    t:assert(gone, "eth0 is gone from the status reply")
    -- Pump a little longer: nothing more may arrive from the machine.
    local seen_then = #gw.seen
    gw:serve({ timeout = 3 })
    t:assert_eq(#gw:dhcp_messages(D.RELEASE), 0, "no RELEASE was sent")
    t:assert_eq(#gw.seen, seen_then, "nothing more was sent once the card was gone")
    t:assert_eq(record(before.id, "Name"), "eth0", "the record stays")
    t:assert_eq(record(before.id, "Verdict"), "JOIN", "with what netd last wrote")
    t:assert_eq(record(before.id, "LastNetwork"), before.network, "and its LastNetwork")

    sut:run("echo " .. virtio .. " > /sys/bus/virtio/drivers/virtio_net/bind"):assert_ok()
    local back = network.serve_until(gw, sut, ready, { iface = true, timeout = 60 })
    t:assert(back, "the card came back, bound and identified its network")
    local i = network.iface(back, "eth0")
    t:log(string.format("back as index %d (was %d)", i.index, before.index))
    t:assert_eq(i.ifid, before.id, "the same id")
    t:assert(count_logged("interface eth0 (pci-0000:00:02.0) is " .. before.id) > sightings,
        "a new first-sight line")
    -- Its clients started from scratch: the first word is a fresh one.
    local first = gw:dhcp_messages()[1]
    t:assert(first ~= nil, "the client spoke")
    t:assert_eq(first.type, D.REQUEST, "an INIT-REBOOT REQUEST")
    t:assert_eq(first.ciaddr, "0.0.0.0", "with no ciaddr: no lease was carried over")
end)
