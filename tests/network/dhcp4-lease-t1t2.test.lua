-- netd §5.3 "T1 and T2": how an ACK's options 58 and 59 are taken or
-- replaced by the defaults, so that T1 < T2 < the lease time.
--
-- Harness: the scripted gateway and one whole Peios machine on a private
-- bridge. For each case the operator's `renew` puts the client in
-- Renewing, the test answers it with an ACK carrying the case's lease
-- time, option 58 and option 59, and then times the client: its unicast
-- REQUEST is T1, its broadcast REQUEST is T2. The broadcast one is then
-- answered with a long lease, ready for the next case.
--
-- Timing: T1 and T2 are taken from the gateway's clock against the moment
-- it sent the ACK (±2 s, the gateway reads in whole seconds), and T2 − T1
-- from the client's own `secs` (±1 s), which is exact on the client side.
--
-- Own VMs: a sequence of short leases, each lasting until its T2.
--
-- Not covered: "capped at the lease time minus 1". T1 is always below
-- the lease time minus 2 (taken only so, else half the lease), so T1 + 1
-- is always below the lease time minus 1, and the 7/8 default is never
-- above it: no ACK can make the cap change the result.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
local sut = network.boot({ bridges = { lan }, gateway = gw })

local D = gateway.DHCP
local LEASED = "10.77.0.50"
local MAC = gateway.mac(sut:read_file("/sys/class/net/eth0/address"))

local function bound(timeout)
    local s = network.serve_until(gw, sut, network.bound, { iface = true, timeout = timeout or 60 })
    assert(s, "netd did not bind a lease")
    return network.iface(s, "eth0")
end

local function renew()
    local r, err = network.call(sut, { query = "renew", interface = "eth0" })
    assert(r and r.ok, "renew: " .. tostring(err or (r and r.error)))
end

local function ack(m, lease, t1, t2)
    local opts = { { 53, string.char(D.ACK) }, { 54, gateway.ip4(gw.addr) }, { 51, gateway.opt.u32(lease) } }
    if t1 then opts[#opts + 1] = { 58, gateway.opt.u32(t1) } end
    if t2 then opts[#opts + 1] = { 59, gateway.opt.u32(t2) } end
    opts[#opts + 1] = { 1, gateway.ip4("255.255.255.0") }
    opts[#opts + 1] = { 3, gateway.ip4(gw.addr) }
    return gateway.dhcp_encode({ op = 2, xid = m.xid, flags = m.flags, chaddr = MAC, yiaddr = LEASED,
        siaddr = gw.addr, options = opts })
end

--- Hand the client a lease of `lease` s with options 58/59 as given, and
--- return the observed T1 and T2 (gateway seconds after the ACK) and
--- T2 − T1 by the client's clock.
local function observe(lease, t1, t2)
    local caught = {}
    gw:dhcp({ pool = { LEASED }, lease = 3600, on = {
        renew = function(m)
            local f = gw.seen[#gw.seen]
            caught[#caught + 1] = { m = m, at = f.at, broadcast = f.dst_ip == "255.255.255.255" }
            return false
        end,
    } })
    renew()
    assert(gw:serve({ timeout = 10, until_ = function() return #caught >= 1 end }), "no renewing REQUEST")
    local sent = gw:now()
    gw:send_udp4(MAC, LEASED, 67, 68, ack(caught[1].m, lease, t1, t2))
    local ok = gw:serve({ timeout = lease + 5, until_ = function()
        return #caught >= 3 and caught[#caught].broadcast
    end })
    assert(ok, "no REQUEST at T2")
    local r1, r2 = caught[2], caught[#caught]
    -- Answer the rebinding REQUEST with a long lease.
    gw:send_udp4(MAC, LEASED, 67, 68, ack(r2.m, 3600))
    assert(network.serve_until(gw, sut, function(i)
        return network.bound(i) and i.lease.expires_in > 100 end, { iface = true, timeout = 10 }),
        "back on a long lease")
    return r1.at - sent, r2.at - sent, r2.m.secs - r1.m.secs, #caught, r1.broadcast
end

local function case(t, what, lease, t1, t2, want1, want2)
    local got1, got2, gap, n, first_broadcast = observe(lease, t1, t2)
    t:log(string.format("%s: lease %d, 58=%s, 59=%s → T1 %d, T2 %d (client gap %d)", what, lease,
        tostring(t1), tostring(t2), got1, got2, gap))
    t:assert(not first_broadcast, what .. ": the REQUEST at T1 is a unicast renewal")
    t:assert_eq(n, 3, what .. ": one renewal, then the rebinding")
    t:assert(math.abs(got1 - want1) <= 2, string.format("%s: T1 %d, expected %d ± 2", what, got1, want1))
    t:assert(math.abs(got2 - want2) <= 2, string.format("%s: T2 %d, expected %d ± 2", what, got2, want2))
    t:assert(math.abs(gap - (want2 - want1)) <= 1,
        string.format("%s: T2 − T1 by the client %d, expected %d ± 1", what, gap, want2 - want1))
end

test("options 58 and 59 are taken when 0 < T1 < lease − 2 and T1 < T2 < lease",
    { spec = "netd *dhcp4-lease.t1-t2" },
    function(t)
        bound()
        case(t, "both valid", 40, 4, 9, 4, 9)
    end)

test("T1 at or above the lease time minus 2, or zero, is replaced by half the lease; T2 then defaults to 7/8",
    { spec = "netd *dhcp4-lease.t1-t2" },
    function(t)
        bound()
        case(t, "T1 = lease − 2", 12, 10, nil, 6, 10)
        case(t, "T1 = 0", 16, 0, nil, 8, 14)
    end)

test("T2 not above T1, or not below the lease time, is replaced by 7/8 of the lease, raised to T1 + 1",
    { spec = "netd *dhcp4-lease.t1-t2" },
    function(t)
        bound()
        case(t, "T2 = T1", 16, 4, 4, 4, 14)
        case(t, "T2 = lease", 16, 4, 16, 4, 14)
        -- 7/8 of 24 is 21, not above T1 = 21: raised to 22.
        case(t, "7/8 below T1 + 1", 24, 21, nil, 21, 22)
    end)
