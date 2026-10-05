-- netd §5.4 — losing a lease: expiry and a NAK (lost by the network),
-- Address.OnExpiry's Drop and Keep, the client being stopped (and when
-- that sends a RELEASE), and the operator's renew.
--
-- Harness: the scripted gateway and one whole Peios machine on a private
-- bridge. Leases are made short on demand: the gateway is re-armed with a
-- 20 s lease and the operator's `renew` takes it (an ACK in Renewing
-- starts the lease again), so expiry is about 20 s away without a fresh
-- boot. A silent gateway (`silent = true`) then lets the lease run out.
-- What netd did is read from the status reply, from the kernel (rtnl:
-- addresses and netd's protocol-200 routes) and from the wire.
--
-- Own VMs: the file edits `Profiles\default` (Address.OnExpiry) and
-- expires leases; nothing here can share a machine with another
-- article's tests. The tests run in order and each leaves the machine
-- bound to 10.77.0.50 on a long lease with the shipped profile.
--
-- Not covered: "a link that disappears from the kernel takes its client
-- with it and sends nothing". The machine's only NIC is the one the test
-- talks through, and with the link gone nothing could reach the gateway
-- whatever netd did, so no assertion on the wire could fail.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local rtnl = require("helpers.rtnl")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
local sut = network.boot({ bridges = { lan }, gateway = gw })
local nic = lan:nic(sut)

local D = gateway.DHCP
local PROFILE = "Profiles\\default"
local LEASED, OTHER = "10.77.0.50", "10.77.0.51"
local INDEX = tonumber((sut:read_file("/sys/class/net/eth0/ifindex"):match("%d+")))

-- ---------------------------------------------------------------------------
-- Local helpers
-- ---------------------------------------------------------------------------

local function iface() return network.iface(network.status(sut), "eth0") end

local function await(pred, timeout, desc)
    local found
    gw:serve({ timeout = timeout or 30, until_ = function()
        for _, m in ipairs(gw:dhcp_messages()) do
            if pred(m) then found = m; return true end
        end
        return false
    end })
    assert(found, "no message on the wire: " .. (desc or "?"))
    return found
end

local function bound(timeout)
    local s = network.serve_until(gw, sut, network.bound, { iface = true, timeout = timeout or 60 })
    assert(s, "netd did not bind a lease")
    return network.iface(s, "eth0")
end

local function renew()
    local r, err = network.call(sut, { query = "renew", interface = "eth0" })
    assert(r, "renew: " .. tostring(err))
    return r
end

local function unset(key, name)
    network.reg(sut, { "del", network.KEY .. "\\" .. key, name }):assert_ok()
end

local function count_logged(text)
    local n = 0
    for _, l in ipairs(network.logs(sut, { since = "30m ago", take = 2000 })) do
        if l:find(text, 1, true) then n = n + 1 end
    end
    return n
end

local function log_line(text)
    for _, l in ipairs(network.logs(sut, { since = "30m ago", take = 2000 })) do
        if l:find(text, 1, true) then return l end
    end
end

--- The kernel's IPv4 addresses on eth0, as a set of text addresses.
local function v4_addresses()
    local out = {}
    for _, a in ipairs(rtnl.addresses_of(sut, INDEX, 4)) do out[a.address] = a.prefix end
    return out
end

--- netd's IPv4 routes on eth0 (protocol 200): "dst/prefix via gw".
local function netd_routes()
    local out = {}
    for _, r in ipairs(rtnl.routes_of(sut, INDEX)) do
        if r.family == 4 and r.protocol == rtnl.RTPROT.NETD then
            out[#out + 1] = string.format("%s/%d via %s", r.dst, r.prefix, tostring(r.gateway))
        end
    end
    table.sort(out)
    return out
end

local function has(list, item)
    for _, x in ipairs(list) do if x == item then return true end end
    return false
end

local function nak(m)
    return { op = 2, xid = m.xid, flags = m.flags, chaddr = m.chaddr, yiaddr = "0.0.0.0",
             siaddr = gw.addr, options = { { 53, string.char(D.NAK) }, { 54, gateway.ip4(gw.addr) } } }
end

--- Re-arm the gateway with a 20 s lease and take it with a renew.
local function short_lease(extra)
    gw:dhcp({ pool = { LEASED }, lease = 20, options = extra })
    renew()
    assert(network.serve_until(gw, sut, function(i)
        return network.bound(i) and i.lease.expires_in <= 20 end, { iface = true, timeout = 20 }),
        "the 20 s lease was not taken")
end

local function long_lease(pool)
    gw:dhcp({ pool = pool or { LEASED }, lease = 3600 })
end

-- ---------------------------------------------------------------------------
-- The operator's renew
-- ---------------------------------------------------------------------------

test("renew moves a bound client into Renewing at once, without a release, keeping its address",
    { spec = "netd *dhcp4-loss.operator-renew" },
    function(t)
        local i = bound()
        t:assert_eq(i.lease.state, "bound", "bound before")
        local hold = true
        gw:dhcp({ pool = { LEASED }, lease = 3600, on = {
            renew = function() if hold then return false end end,
        } })
        gw:forget()
        local r = renew()
        t:assert(r.ok, "renew answers ok")
        local first = await(function(m) return m.type == D.REQUEST end, 5, "the renewing REQUEST")
        -- While the server is silent: renewing, address held, nothing released.
        local during = {}
        gw:serve({ timeout = 3, until_ = function()
            local s = iface()
            during[#during + 1] = (s.lease and s.lease.state or "none") .. "/" ..
                tostring(network.has_address(s, LEASED) and v4_addresses()[LEASED] ~= nil)
            return false
        end })
        t:log("while the server held its answer: " .. table.concat(during, " "))
        for _, x in ipairs(during) do
            t:assert_eq(x, "renewing/true", "renewing, with the address on the interface")
        end
        t:assert_eq(first.ciaddr, LEASED, "the REQUEST is for the lease")
        t:assert(not first.opt[50] and not first.opt[54], "a Renewing REQUEST (no 50, no 54)")
        t:assert_eq(first.frame.dst_ip, gw.addr, "unicast to the lease's server")
        t:assert_eq(first.frame.src_ip, LEASED, "from the lease address")
        -- A renew while already renewing starts Renewing again: a new xid.
        hold = false
        gw:forget()
        t:assert(renew().ok, "renew while renewing answers ok")
        local second = await(function(m) return m.type == D.REQUEST end, 5, "the second REQUEST")
        bound()
        t:assert(second.xid ~= first.xid, "a new transaction id")
        t:assert_eq(#gw:dhcp_messages(D.RELEASE), 0, "no RELEASE was sent")
        t:assert(v4_addresses()[LEASED], "the address stayed throughout")
    end)

-- ---------------------------------------------------------------------------
-- Lost by the network
-- ---------------------------------------------------------------------------

test("a lease that runs out is lost: logged, address and routes removed, Selecting with option 50",
    { spec = "netd *dhcp4-loss.lost netd *dhcp4-loss.drop-removes-the-address netd *dhcp4-client.messages" },
    function(t)
        bound()
        short_lease({ { 121, gateway.opt.classless({ { "10.9.0.0", 16, "10.77.0.9" }, { "0.0.0.0", 0, gw.addr } }) } })
        local routes = netd_routes()
        t:log("routes with the lease: " .. table.concat(routes, ", "))
        t:assert(has(routes, "10.9.0.0/16 via 10.77.0.9"), "the classless route is installed")
        t:assert(has(routes, "0.0.0.0/0 via " .. gw.addr), "the default route is installed")
        local lost_before = count_logged("interface eth0: lease lost")
        gw:dhcp({ silent = true })
        gw:forget()
        local s = network.serve_until(gw, sut, function(x) return x.lease == nil end, { iface = true, timeout = 30 })
        t:assert(s, "the lease ran out")
        local d = await(function(m) return m.type == D.DISCOVER end, 5, "the DISCOVER after the loss")
        -- Give the reconcile a moment, then read the kernel.
        local clean = network.serve_until(gw, sut, function(x)
            return not network.has_address(x, LEASED) end, { iface = true, timeout = 10 })
        t:assert(clean, "the address left the status reply")
        local addrs, after = v4_addresses(), netd_routes()
        t:log("routes after: " .. table.concat(after, ", "))
        t:assert_eq(addrs[LEASED], nil, "the kernel no longer has the lease address")
        t:assert_eq(#after, 0, "netd's IPv4 routes went with it")
        t:assert(count_logged("interface eth0: lease lost") > lost_before, "`lease lost` was logged")
        t:assert_eq(log_line("interface eth0: lease lost"):find("keeping", 1, true), nil,
            "the Drop line, not Keep's")
        t:assert(d.opt[50] and gateway.ip4_text(d.opt[50]) == LEASED,
            "the DISCOVER after an expiry carries option 50, the expired address")
        t:assert_eq(d.ciaddr, "0.0.0.0", "DISCOVER ciaddr 0")
        t:assert(d.broadcast, "DISCOVER broadcast flag")
    end)

test("renew on a client that holds no lease answers ok and leaves it as it is",
    { spec = "netd *dhcp4-loss.operator-renew" },
    function(t)
        -- Still Selecting from the previous test, with a silent server.
        local i = iface()
        t:assert_eq(i.lease, nil, "no lease")
        gw:forget()
        local r = renew()
        t:assert(r.ok, "renew answers ok: " .. tostring(r.error))
        gw:serve({ timeout = 5 })
        local kinds = {}
        for _, m in ipairs(gw:dhcp_messages()) do kinds[#kinds + 1] = gateway.DHCP_NAME[m.type] end
        t:log("sent after the renew: " .. table.concat(kinds, " "))
        t:assert_eq(#gw:dhcp_messages(D.REQUEST), 0, "no REQUEST: the client did not renew")
        t:assert_eq(iface().lease, nil, "still no lease")
        long_lease()
        bound()
    end)

test("a NAK while renewing loses the lease; the next DISCOVER has no option 50",
    { spec = "netd *dhcp4-loss.lost netd *dhcp4-loss.drop-removes-the-address" },
    function(t)
        bound()
        -- NAK the renewal, and offer nothing after it, so the loss stays visible.
        gw:dhcp({ pool = { LEASED }, lease = 3600, on = {
            renew = function(m) return nak(m) end,
            discover = function() return false end,
        } })
        gw:forget()
        local lost_before = count_logged("interface eth0: lease lost")
        renew()
        local d = await(function(m) return m.type == D.DISCOVER end, 10, "a DISCOVER after the NAK")
        local s = network.serve_until(gw, sut, function(x)
            return x.lease == nil and not network.has_address(x, LEASED) end, { iface = true, timeout = 10 })
        t:assert(s, "the lease and its address are gone")
        t:assert_eq(v4_addresses()[LEASED], nil, "the kernel no longer has the address")
        t:assert(count_logged("interface eth0: lease lost") > lost_before, "`lease lost` was logged")
        t:assert_eq(d.opt[50], nil, "a NAK forgets the address: no option 50")
        long_lease()
        bound()
    end)

-- ---------------------------------------------------------------------------
-- Keep
-- ---------------------------------------------------------------------------

test("with OnExpiry = Keep a lapsed lease keeps its address and routes until a new lease replaces it",
    { spec = "netd *dhcp4-loss.keep-holds-the-lease netd *dhcp4-loss.lost netd *dhcp4-loss.stop-releases" },
    function(t)
        bound()
        gw:forget()
        network.write(sut, PROFILE, { ["Address.OnExpiry"] = "sz:Keep" })
        -- A profile edit stops the client (with a RELEASE) and starts another.
        local rel = await(function(m) return m.type == D.RELEASE end, 20, "the RELEASE on the edit")
        t:assert_eq(rel.ciaddr, LEASED, "a bound client's stop releases its lease")
        bound()
        short_lease({ { 121, gateway.opt.classless({ { "10.9.0.0", 16, "10.77.0.9" }, { "0.0.0.0", 0, gw.addr } }) } })
        gw:dhcp({ silent = true })
        gw:forget()
        local s = network.serve_until(gw, sut, function(x) return x.lease == nil end, { iface = true, timeout = 30 })
        t:assert(s, "the client's lease ran out (status `lease` is nil)")
        await(function(m) return m.type == D.DISCOVER end, 5, "the client discovering again")
        gw:serve({ timeout = 2 })
        local line = log_line("lease lost; keeping the address (Address.OnExpiry = Keep)")
        t:log("log: " .. tostring(line))
        t:assert(line, "the Keep line was logged")
        t:assert(line and line:find("interface eth0: lease lost; keeping the address", 1, true),
            "naming the interface")
        t:assert(line and line:match("^netd: warn"), "at warning level")
        local i = iface()
        t:assert_eq(i.lease, nil, "status `lease` describes the client: nil")
        t:assert(network.has_address(i, LEASED), "the address stays on the interface")
        t:assert(v4_addresses()[LEASED] == 24, "in the kernel, at its prefix")
        local routes = netd_routes()
        t:log("routes while kept: " .. table.concat(routes, ", "))
        t:assert(has(routes, "0.0.0.0/0 via " .. gw.addr), "the default route stays")
        t:assert(has(routes, "10.9.0.0/16 via 10.77.0.9"), "the classless route stays")

        -- A new lease, for another address, replaces the kept one.
        long_lease({ OTHER })
        local b = bound()
        local gone = network.serve_until(gw, sut, function(x)
            return network.has_address(x, OTHER) and not network.has_address(x, LEASED) end,
            { iface = true, timeout = 15 })
        t:assert(gone, "the kept address was replaced by the new lease's")
        t:assert_eq(v4_addresses()[LEASED], nil, "the kernel dropped the kept address")
        t:assert(not has(netd_routes(), "10.9.0.0/16 via 10.77.0.9"), "and the kept lease's classless route")
        t:assert_eq(b.lease.state, "bound", "bound on the new lease")
    end)

test("a stop forgets a kept lease",
    { spec = "netd *dhcp4-loss.keep-holds-the-lease netd *dhcp4-loss.stop-releases" },
    function(t)
        bound()
        -- Let the OTHER lease lapse under Keep.
        gw:dhcp({ pool = { OTHER }, lease = 20 })
        renew()
        assert(network.serve_until(gw, sut, function(i)
            return network.bound(i) and i.lease.expires_in <= 20 end, { iface = true, timeout = 20 }))
        gw:dhcp({ silent = true })
        assert(network.serve_until(gw, sut, function(x) return x.lease == nil end, { iface = true, timeout = 30 }),
            "the lease lapsed")
        t:assert(network.has_address(iface(), OTHER), "kept")
        -- The stop: put OnExpiry back (a profile edit). The client is in
        -- Selecting, holding no lease, so it sends no RELEASE.
        gw:forget()
        network.write(sut, PROFILE, { ["Address.OnExpiry"] = "sz:Drop" })
        local s = network.serve_until(gw, sut, function(x) return not network.has_address(x, OTHER) end,
            { iface = true, timeout = 15 })
        t:assert(s, "the kept address went with the stop")
        t:assert_eq(v4_addresses()[OTHER], nil, "the kernel no longer has it")
        t:assert_eq(#gw:dhcp_messages(D.RELEASE), 0, "a client holding no lease sends no RELEASE")
        unset(PROFILE, "Address.OnExpiry")
        long_lease()
        bound()
    end)

-- ---------------------------------------------------------------------------
-- Stopped by netd
-- ---------------------------------------------------------------------------

test("a stop while renewing releases first, unicast from the lease address; the addresses go",
    { spec = "netd *dhcp4-loss.stop-releases" },
    function(t)
        bound()
        gw:dhcp({ pool = { LEASED }, lease = 3600, on = { renew = function() return false end } })
        renew()
        assert(network.serve_until(gw, sut, function(i) return i.lease and i.lease.state == "renewing" end,
            { iface = true, timeout = 10 }), "renewing")
        gw:forget()
        long_lease()
        network.write(sut, PROFILE, { ["Address.Families"] = "sz:ipv6" })
        local rel = await(function(m) return m.type == D.RELEASE end, 15, "the RELEASE")
        local s = network.serve_until(gw, sut, function(x)
            return x.lease == nil and not network.has_address(x, LEASED) end, { iface = true, timeout = 15 })
        t:assert(s, "the lease and its address are gone")
        t:assert_eq(rel.ciaddr, LEASED, "RELEASE ciaddr is the lease address")
        t:assert_eq(gateway.ip4_text(rel.opt[54]), gw.addr, "RELEASE names the server")
        t:assert_eq(rel.frame.src_ip, LEASED, "sent from the lease address")
        t:assert_eq(rel.frame.dst_ip, gw.addr, "unicast to the server")
        t:assert_eq(v4_addresses()[LEASED], nil, "the kernel no longer has the address")
        unset(PROFILE, "Address.Families")
        bound()
    end)

test("a carrier loss stops the client: its RELEASE never reaches the server, and the address goes",
    { spec = "netd *dhcp4-loss.stop-releases" },
    function(t)
        bound()
        local lost_before = count_logged("interface eth0: carrier lost")
        gw:forget()
        nic:disconnect()
        local s = network.serve_until(gw, sut, function(x)
            return x.carrier == false and x.lease == nil and not network.has_address(x, LEASED) end,
            { iface = true, timeout = 20 })
        t:assert(s, "carrier gone, lease and address forgotten")
        t:assert_eq(v4_addresses()[LEASED], nil, "the kernel no longer has the address")
        t:assert(count_logged("interface eth0: carrier lost") > lost_before, "`carrier lost` logged")
        gw:serve({ timeout = 2 })
        nic:reconnect()
        bound()
        t:assert_eq(#gw:dhcp_messages(D.RELEASE), 0, "the server never saw a RELEASE")
    end)
