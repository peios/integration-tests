-- netd TRM §7.1 — network identification: the signals, the identity
-- derived from them, when identification runs, and what a newly
-- identified network does to the interface's judgement.
--
-- Every network id is computed here from the TRM's rule (a v5 UUID over
-- `peios-netd-network|<kind>|<basis>`, helpers.sha1) and compared with
-- the `network` netd reports in its status reply. The networks are
-- produced by re-arming the gateway between cable pulls: a returning
-- client asks for its old address with INIT-REBOOT, and the gateway's
-- pool decides whether it gets it (ACK) or discovers into the new pool
-- (NAK). A different server is the same gateway answering with another
-- server identifier, which an INIT-REBOOT client accepts because it has
-- not chosen a server yet.
--
-- IPv6 comes from the gateway's router advertisements, armed only once
-- the first lease is bound, so the first identity is the DHCPv4 one and
-- the advertisement's arrival is a change the tests can watch. The
-- signals themselves are read where netd records them, the record's
-- `Status` values (§7.2), since that is the only place netd shows them.
--
-- Two claims have no route here and are said so in the report rather
-- than tested: a different *kind* of interface (the machine has one NIC,
-- wired), and identification on an interface that is not joined (an
-- interface judged IGNORE or DOWN loses its clients, so it has no
-- signals either way; the carrier half of the condition is tested).
--
-- One pair; the tests run in order and each starts where the last left
-- the machine.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local sha1 = require("helpers.sha1")
local rtnl = require("helpers.rtnl")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50", "10.77.0.60" }, lease = 3600 })
local sut = network.boot({ bridges = { lan }, gateway = gw })

local function netid(basis) return sha1.uuid5("peios-netd-network|wired|" .. basis) end
local NETID = netid("dhcp:10.77.0.1|10.77.0.0/24")
local GW_LL = gateway.ip6_text(gw.ll)
local RA = {
    lifetime = 1800,
    prefixes = {
        { prefix = "fd77::", len = 64 },
        -- Preferred lifetime 0: its address is deprecated from the start.
        { prefix = "fd78::", len = 64, preferred = 0, valid = 3600 },
    },
    rdnss = { servers = { "fd77::53", GW_LL } },
}

local function iface() return network.iface(network.status(sut), "eth0") end

--- A record's `Status` values: name → { type, data }.
local function record_status(id)
    local r = network.reg(sut, { "get", network.KEY .. "\\Networks\\" .. id .. "\\Status", "--json" })
    if r.exit_code ~= 0 then return nil end
    local out = {}
    for _, v in ipairs(json.decode(r.stdout).values or {}) do out[v.name] = v end
    return out
end

local function list_text(l) return table.concat(l or {}, ", ") end

local function on_network(id)
    return function(i) return i.network == id end
end

--- Pull the cable, run `between` while it is out, plug it back and pump
--- until the interface stands on network `id` with a bound lease.
local function replug(t, id, between, what)
    local nic = lan:nic(sut)
    nic:disconnect()
    t:assert(network.serve_until(gw, sut, function(x) return x.carrier == false end,
        { iface = "eth0", timeout = 20 }), what .. ": carrier goes")
    if between then between() end
    nic:reconnect()
    local s = network.serve_until(gw, sut, function(i) return network.bound(i) and i.network == id end,
        { iface = "eth0", timeout = 45 })
    if not s then t:log(what .. ": status network " .. tostring(iface().network) .. ", wanted " .. id) end
    t:assert(s, what .. ": bound on network " .. id)
    return network.iface(s, "eth0")
end

local function count_logged(text)
    local n = 0
    for _, l in ipairs(network.logs(sut, { take = 400 })) do
        if l:find(text, 1, true) then n = n + 1 end
    end
    return n
end

test("a lease identifies its network as dhcp:<server>|<subnet>/<prefix> under the interface's kind",
    { spec = "netd *netid.derivation" }, function(t)
        local s = network.serve_until(gw, sut, network.bound, { iface = "eth0", timeout = 60 })
        t:assert(s, "netd bound a lease")
        s = network.serve_until(gw, sut, on_network(NETID), { iface = "eth0", timeout = 10 })
        t:assert(s, "the network is the SHA-1 v5 id of `peios-netd-network|wired|dhcp:10.77.0.1|10.77.0.0/24`: "
            .. NETID .. " (got " .. tostring(iface().network) .. ")")
        t:assert(network.logged(sut, "interface eth0: network " .. NETID), "netd logged the newly identified network")
    end)

test("the signals: kind, server, subnet, gateway, router, the non-deprecated prefixes once each, and the DNS servers of both",
    { spec = "netd *netid.signals" }, function(t)
        gw:router(RA)
        gw:send_ra(RA)
        local s = network.serve_until(gw, sut, function(i)
            for _, a in ipairs(network.ipv6(i)) do if a:match("^fd77:") then return true end end
            return false
        end, { iface = "eth0", timeout = 30 })
        t:assert(s, "the advertised prefix is autoconfigured")
        local st
        t:assert(wait_until(function()
            gw:serve({ timeout = 0 })
            st = record_status(NETID)
            return st and st.Router ~= nil
        end, { timeout = 15, interval = 0.5, desc = "the router to reach the record" }), "the record shows the router")
        for k, v in pairs(st) do t:log(k .. " = " .. (type(v.data) == "table" and "[" .. list_text(v.data) .. "]" or tostring(v.data))) end
        t:assert_eq(st.Kind.data, "wired", "kind: the interface's kind")
        t:assert_eq(st.Server.data, "10.77.0.1", "server: the lease's server identifier")
        t:assert_eq(st.Gateway.data, "10.77.0.1", "gateway: the lease's router")
        t:assert_eq(st.Router.data, GW_LL, "router: the default router discovery chose (its link-local address)")
        t:assert_eq(list_text(st.Prefixes.data), "10.77.0.0/24, fd77::/64",
            "prefixes: the subnet, then the autoconfigured prefix; the deprecated fd78::/64 is left out")
        t:assert_eq(list_text(st.DnsServers.data), "10.77.0.1, fd77::53, " .. GW_LL,
            "DNS servers: the lease's, then the routers' RDNSS servers, the link-local one included")
    end)

test("the same server and subnet are the same network whatever the address; another server or subnet is another network; IPv4 wins over IPv6",
    { spec = "netd *netid.same-server-and-subnet-same-network" }, function(t)
        t:assert_eq(iface().network, NETID,
            "with both a lease and an advertised prefix, the network is the DHCPv4 one")
        t:assert(record_status(netid("ra:" .. GW_LL .. "|fd77::/64")) == nil, "no RA-basis record was made beside it")

        -- Another address from the same server and subnet.
        gw:dhcp({ pool = { "10.77.0.60" }, lease = 3600 })
        local i = replug(t, NETID, nil, "another address, same server and subnet")
        t:assert(network.has_address(i, "10.77.0.60"), "the address changed to 10.77.0.60")

        -- Another server identifier, the same subnet.
        local id2 = netid("dhcp:10.77.0.2|10.77.0.0/24")
        gw:dhcp({ server = "10.77.0.2", pool = { "10.77.0.60" }, lease = 3600 })
        i = replug(t, id2, nil, "another server")
        t:assert(id2 ~= NETID, "a different id")

        -- The same server, another subnet.
        local id3 = netid("dhcp:10.77.0.1|10.88.0.0/24")
        gw:dhcp({ pool = { "10.88.0.50" }, router = false, lease = 3600 })
        i = replug(t, id3, nil, "another subnet")
        t:assert(network.has_address(i, "10.88.0.50"), "the lease is in 10.88.0.0/24")
    end)

test("identification runs on every full pass, and only while the interface has carrier",
    { spec = "netd *netid.when" }, function(t)
        local id = iface().network
        t:assert(id, "the interface stands on a network")
        local function last_seen() return tonumber(network.get(sut, "Networks\\" .. id .. "\\Status", "LastSeen")) end
        local function next_second(after) wait_until(function() return os.time() > after + 1 end,
            { timeout = 5, interval = 0.2, desc = "the clock to move on" }) end

        local v1 = last_seen()
        next_second(os.time())
        t:assert(network.call(sut, { query = "reconcile" }).ok, "a full pass on request")
        local v2 = last_seen()
        t:log("LastSeen " .. v1 .. " → " .. v2 .. " across one full pass")
        t:assert(v2 > v1, "the pass identified the network again and refreshed its record")

        local nic = lan:nic(sut)
        nic:disconnect()
        t:assert(network.serve_until(gw, sut, function(x) return x.carrier == false end,
            { iface = "eth0", timeout = 20 }), "carrier goes")
        local v3 = last_seen()
        next_second(os.time())
        t:assert(network.call(sut, { query = "reconcile" }).ok, "a full pass with the cable out")
        t:assert_eq(last_seen(), v3, "without carrier the pass does not identify: the record is untouched")
        t:assert_eq(iface().network, nil, "and the interface names no network")
        nic:reconnect()
        t:assert(network.serve_until(gw, sut, function(i) return network.bound(i) and i.network == id end,
            { iface = "eth0", timeout = 30 }), "back on the same network")
        t:assert(last_seen() > v3, "identified again once carrier is back")
    end)

test("without a lease, a default router and an autoconfigured prefix identify the network as ra:<router>|<prefix>; a static-only interface has no network",
    { spec = "netd *netid.derivation" }, function(t)
        local RA_ID = netid("ra:" .. GW_LL .. "|fd77::/64")
        -- IPv6 only: the DHCPv4 client stops and its lease goes.
        network.write(sut, [[Profiles\default]], { ["Address.Families"] = "sz:ipv6" })
        local s = network.serve_until(gw, sut, on_network(RA_ID), { iface = "eth0", timeout = 40 })
        t:assert(s, "the network becomes the RA-basis id " .. RA_ID .. " (got " .. tostring(iface().network) .. ")")
        t:assert_eq(network.iface(s, "eth0").lease, nil, "with no lease held")
        local st = record_status(RA_ID)
        t:assert(st, "the RA-basis network has its record")
        t:assert_eq(st.Server, nil, "with no server")
        t:assert_eq(st.Router.data, GW_LL, "and the router it was derived from")

        -- Static only: nothing offered is taken, so there is no identity.
        network.reg(sut, { "del", network.KEY .. [[\Profiles\default]], "Address.Families" }):assert_ok()
        network.write(sut, [[Profiles\default]], { ["Address.Offered"] = "dword:0", ["Address.Static"] = "sz:10.77.0.70/24" })
        local nic = lan:nic(sut)
        nic:disconnect()
        t:assert(network.serve_until(gw, sut, function(x) return x.carrier == false end,
            { iface = "eth0", timeout = 20 }), "carrier goes (the network is forgotten)")
        nic:reconnect()
        s = network.serve_until(gw, sut, function(i) return i.carrier and network.has_address(i, "10.77.0.70") end,
            { iface = "eth0", timeout = 30 })
        t:assert(s, "the static address is applied after the carrier returns")
        t:assert(network.call(sut, { query = "reconcile" }).ok, "one more full pass")
        gw:serve({ timeout = 2 })
        t:assert_eq(iface().network, nil, "a static-only interface stands on no identified network")

        network.reg(sut, { "del", network.KEY .. [[\Profiles\default]], "Address.Static" }):assert_ok()
        network.write(sut, [[Profiles\default]], { ["Address.Offered"] = "dword:1" })
        t:assert(network.serve_until(gw, sut, network.bound, { iface = "eth0", timeout = 40 }),
            "the baseline is back and binds")
    end)

local ID4 = netid("dhcp:10.77.0.3|10.77.0.0/24")

test("a newly identified network is logged with its name and trust, and the interface is judged again with the Network facts",
    { spec = "netd *netid.new-network-rejudges" }, function(t)
        -- A rule that speaks only on a network named `office`, and the
        -- profile it names.
        network.write(sut, [[Profiles\office]], {
            ["Address.Offered"] = "dword:1", ["Route.Offered"] = "dword:1",
            ["Dns.Offered"] = "dword:1", ["Route.Metric"] = "dword:50",
        })
        network.write(sut, [[Rules\Interface\office]], {
            ["Network.Name.Equal"] = "sz:office", Priority = "dword:20", Actions = "multi:JOIN(office)",
        })
        -- The record of a network not seen yet, named in advance.
        network.write(sut, "Networks\\" .. ID4, { Name = "sz:office", Trust = "sz:high" })
        t:assert_eq(iface().profile, "default", "the interface stands in default until then")

        gw:dhcp({ server = "10.77.0.3", pool = { "10.77.0.60" }, lease = 3600 })
        gw:forget()
        local starts = count_logged("interface eth0: dhcp starting")
        local i = replug(t, ID4, nil, "the office network")
        local s = network.serve_until(gw, sut, function(x) return x.profile == "office" and network.bound(x) end,
            { iface = "eth0", timeout = 30 })
        t:assert(s, "the interface moves to the office profile and binds there (profile "
            .. tostring(iface().profile) .. ")")
        i = network.iface(s, "eth0")
        t:assert_eq(i.network_name, "office", "the Network.Name fact")
        t:assert_eq(i.network_trust, "high", "the Network.Trust fact")
        t:assert(network.logged(sut, "interface eth0: network office (trust high)"),
            "netd logged `interface eth0: network office (trust high)`")
        t:assert(network.logged(sut, "interface eth0: JOIN(office) by office"), "and the new verdict by the office rule")
        -- One client started when the carrier came back (under default),
        -- and another when the verdict moved the interface to office.
        local now_starts = count_logged("interface eth0: dhcp starting")
        t:log("dhcp starting: " .. starts .. " → " .. now_starts)
        t:assert(now_starts >= starts + 2, "the switch restarted the client under the office profile")
        local metric
        for _, r in ipairs(rtnl.routes_of(sut, i.index)) do
            if r.family == 4 and r.dst == "0.0.0.0" and r.prefix == 0 then metric = r.metric end
        end
        t:assert_eq(metric, 50, "the default route now carries the office profile's metric")
    end)

test("the network is kept while carrier holds, through the profile switch it triggered; losing carrier forgets it",
    { spec = "netd *netid.sticky-while-carrier" }, function(t)
        local joins = count_logged("JOIN(office) by office")
        -- Several passes later the interface still stands on the office
        -- network in the office profile: the switch did not forget the
        -- network and switch back.
        for _ = 1, 3 do
            t:assert(network.call(sut, { query = "reconcile" }).ok, "a full pass")
            gw:serve({ timeout = 1 })
            local i = iface()
            t:assert_eq(i.network, ID4, "still on the office network")
            t:assert_eq(i.profile, "office", "still in the office profile")
        end
        t:assert_eq(count_logged("JOIN(office) by office"), joins, "with no further change of verdict")

        local nic = lan:nic(sut)
        nic:disconnect()
        local s = network.serve_until(gw, sut, function(x) return x.carrier == false end,
            { iface = "eth0", timeout = 20 })
        t:assert(s, "carrier goes")
        s = network.serve_until(gw, sut, function(x) return x.network == nil and x.profile == "default" end,
            { iface = "eth0", timeout = 10 })
        t:assert(s, "losing carrier forgets the network, and with it the office verdict (network "
            .. tostring(iface().network) .. ", profile " .. tostring(iface().profile) .. ")")
        nic:reconnect()
        t:assert(network.serve_until(gw, sut, function(x) return x.network == ID4 and x.profile == "office" end,
            { iface = "eth0", timeout = 40 }), "identified again on return, and judged into office again")
    end)
