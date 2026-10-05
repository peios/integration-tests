-- netd TRM §8.4 — which lease's name: the first joined interface, in
-- kernel index order, whose profile has `Hostname.Offered` and whose lease
-- carries a hostname.
--
-- Two interfaces need two networks, and a file may have only two VMs, so
-- the one gateway VM serves both: it is attached to two bridges, and a
-- second gateway object is made here for its second NIC (address
-- 10.78.0.1/24, its own packet socket) from the gateway helper's own
-- metatable, so `dhcp`, `pump` and the rest work on it unchanged. The
-- gateway VM's udp/67 absorber is bound to the wildcard address, so it
-- covers both NICs. Both gateway objects are pumped together.
--
-- Which machine interface sits on which bridge is read from the wire
-- (the chaddr each gateway sees), and the test is written in terms of
-- "the lower-index interface" and "the higher-index one", so it does not
-- depend on the order the NICs enumerate in.
--
-- The proof of order: the higher-index interface's lease offers a name
-- first and it is taken; then the lower-index one's lease offers one too
-- and it wins although the other is still on offer; when the lower one's
-- lease stops offering a name, the higher one's comes back.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local ntfe = require("helpers.ntfe")

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
local d1 = gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
local d2 = gw2:dhcp({ pool = { "10.78.0.50" }, lease = 3600 })
local sut = network.boot({ bridges = { lan, lan2 }, gateways = { gw, gw2 } })

local function kernel_name()
    return (sut:read_file("/proc/sys/kernel/hostname"):gsub("%s+$", ""))
end

--- Pump both gateways until `pred()` holds.
local function serve_both(timeout, pred)
    local deadline = os.time() + timeout
    repeat
        gw:pump(50)
        gw2:pump(50)
        if pred() then return true end
    until os.time() > deadline
    return pred() and true or false
end

local function both_bound()
    local s = network.call(sut, { query = "status" })
    if not (s and s.ok) then return false end
    local n = 0
    for _, i in ipairs(s.interfaces or {}) do
        if network.bound(i) then n = n + 1 end
    end
    return n == 2
end

--- The machine interface (status entry) whose MAC sent `g` its DHCP.
local function iface_on(g)
    local m = g:dhcp_messages()[1]
    if not m then return nil end
    for _, i in ipairs(network.status(sut).interfaces) do
        if gateway.mac(i.mac) == m.chaddr then return i end
    end
end

local function set_name(t, which, name)
    which.server.options = name and { { 12, name } } or {}
    local r = network.call(sut, { query = "renew", interface = which.iface.name })
    t:assert(r and r.ok, "renew " .. which.iface.name .. " accepted")
end

local function name_becomes(t, name, what)
    t:assert(serve_both(15, function() return kernel_name() == name end),
        what .. " (kernel has `" .. kernel_name() .. "`)")
end

test("of two leases offering a name, the lower-index joined interface's is taken",
    { spec = "netd *hostname.source" }, function(t)
        t:assert(serve_both(60, both_bound), "both interfaces bind a lease")
        network.write(sut, [[Profiles\default]], { ["Hostname.Offered"] = "dword:1" })
        -- The profile edit restarts both clients; wait for both to bind again.
        serve_both(3, function() return false end)
        t:assert(serve_both(40, both_bound), "both bind again under the edited profile")

        local a = { iface = iface_on(gw), server = d1 }
        local b = { iface = iface_on(gw2), server = d2 }
        t:assert(a.iface and b.iface and a.iface.index ~= b.iface.index, "each gateway serves one interface")
        local low, high = a, b
        if b.iface.index < a.iface.index then low, high = b, a end
        t:log(string.format("lower index: %s (%d); higher: %s (%d)",
            low.iface.name, low.iface.index, high.iface.name, high.iface.index))
        t:assert_eq(kernel_name(), "(none)", "no lease has offered a name yet")

        set_name(t, high, "high-name")
        name_becomes(t, "high-name", "the only name on offer, the higher-index interface's, is taken")
        set_name(t, low, "low-name")
        name_becomes(t, "low-name", "the lower-index interface's name wins once it is offered")
        -- Shorten the higher one's lease in the same renewal, so the moment
        -- its ACK has been taken is visible in the status reply.
        high.server.lease = 1800
        set_name(t, high, "high-name")
        t:assert(serve_both(15, function()
            local i = network.iface(network.status(sut), high.iface.name)
            return i and i.lease and i.lease.expires_in <= 1800
        end), "the higher interface's renewal is answered and taken")
        t:assert_eq(kernel_name(), "low-name", "a renewal on the higher one does not take it back")
        set_name(t, low, nil)
        name_becomes(t, "high-name", "when the lower one stops offering, the higher one's name is taken")
    end)
