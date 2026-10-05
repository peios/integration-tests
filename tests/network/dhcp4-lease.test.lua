-- netd §5.3 — replies and leases: which replies the client looks at, the
-- server lock, what each state accepts, what makes an ACK a lease, and
-- how an ACK is read: the prefix, the routes, and the options kept.
--
-- Harness: the scripted gateway and one whole Peios machine on a private
-- bridge. The gateway *intercepts*: it records the client's message and
-- stays silent, and the test then sends hand-built replies (gateway.
-- dhcp_encode) itself, in the order and with the faults it wants. The
-- client stays where it is meanwhile, since its next retransmission is
-- seconds (acquiring) or a minute (renewing) away. Renewing is reached on
-- demand with the operator's `renew`; Rebooting with a cable pull;
-- Selecting and Requesting by NAKing a renewal.
--
-- An ignored reply is shown against one that would have been visible:
-- every faulty ACK grants a *different* address (10.77.0.77) on a short
-- lease, so had the client taken it, the status reply would show the
-- address, the state `bound`, or a short `expires_in`. Each check waits
-- 1.5 s for netd to have read the reply first.
--
-- How a lease is read is observed where netd puts it: the kernel's
-- addresses and netd's protocol-200 routes (rtnl), the status reply
-- (prefix, gateway, DNS, search, hostname), the link MTU (sysfs), and the
-- resolver snapshot (NTP). T1 and T2 are timing and have their own file,
-- dhcp4-lease-t1t2.
--
-- Own VMs: the file hands the machine a series of odd leases and edits
-- the shipped profile; the tests run in order and each leaves it bound to
-- 10.77.0.50/24 from 10.77.0.1.

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
local LEASED, OTHER, STRANGER = "10.77.0.50", "10.77.0.77", "10.77.0.9"
local BCAST_MAC = string.rep("\xff", 6)
local MAC = gateway.mac(sut:read_file("/sys/class/net/eth0/address"))
local INDEX = tonumber((sut:read_file("/sys/class/net/eth0/ifindex"):match("%d+")))

-- ---------------------------------------------------------------------------
-- Local helpers
-- ---------------------------------------------------------------------------

local function iface() return network.iface(network.status(sut), "eth0") end

local function bound(timeout)
    local s = network.serve_until(gw, sut, network.bound, { iface = true, timeout = timeout or 60 })
    assert(s, "netd did not bind a lease")
    return network.iface(s, "eth0")
end

local function renew()
    local r, err = network.call(sut, { query = "renew", interface = "eth0" })
    assert(r and r.ok, "renew: " .. tostring(err or (r and r.error)))
end

local function normal() gw:dhcp({ pool = { LEASED }, lease = 3600 }) end

--- Record every client message by kind and answer nothing.
local caught = {}
local function intercept()
    caught = { discover = {}, request = {}, renew = {}, reboot = {} }
    local function cap(kind) return function(m) table.insert(caught[kind], m); return false end end
    gw:dhcp({ pool = { LEASED }, lease = 3600, on = {
        discover = cap("discover"), request = cap("request"), renew = cap("renew"), reboot = cap("reboot"),
    } })
end

local function await_caught(kind, n, timeout)
    local ok = gw:serve({ timeout = timeout or 15, until_ = function() return #caught[kind] >= (n or 1) end })
    assert(ok, "the client sent no " .. kind .. " message")
    return caught[kind][#caught[kind]]
end

local function mask(bits)
    return string.pack(">I4", bits == 0 and 0 or ((0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF))
end

--- A reply to `m`. `o`: kind (ACK), yiaddr (LEASED), server (the
--- gateway; false for no option 54), lease (3600; a string is the raw
--- option), prefix (24; false for no mask; a string is the raw mask),
--- router (the gateway; false for none), extra (more options), xid,
--- chaddr, op, type (raw option 53 byte; false for none).
local function reply(m, o)
    o = o or {}
    local opts = {}
    local kind = o.kind or D.ACK
    if o.type ~= false then opts[#opts + 1] = { 53, string.char(o.type or kind) } end
    if o.server ~= false then opts[#opts + 1] = { 54, gateway.ip4(o.server or gw.addr) } end
    if kind ~= D.NAK then
        if o.lease ~= false then
            opts[#opts + 1] = { 51, type(o.lease) == "string" and o.lease or gateway.opt.u32(o.lease or 3600) }
        end
        if o.prefix ~= false then
            opts[#opts + 1] = { 1, type(o.prefix) == "string" and o.prefix or mask(o.prefix or 24) }
        end
        if o.router ~= false then opts[#opts + 1] = { 3, gateway.opt.ip(o.router or gw.addr) } end
    end
    for _, x in ipairs(o.extra or {}) do opts[#opts + 1] = x end
    return gateway.dhcp_encode({
        op = o.op or 2, xid = o.xid or m.xid, flags = m.flags, chaddr = o.chaddr or MAC,
        yiaddr = kind == D.NAK and "0.0.0.0" or (o.yiaddr or LEASED), siaddr = gw.addr, options = opts,
    })
end

--- Send a reply to a renewing client (unicast to the lease address), or
--- to an acquiring one (broadcast).
local function to_renewing(payload) gw:send_udp4(MAC, LEASED, 67, 68, payload) end
local function to_acquiring(payload) gw:send_udp4(BCAST_MAC, "255.255.255.255", 67, 68, payload) end

local function settle() gw:serve({ timeout = 1.5 }) end

--- After a faulty reply to a renewing client: still renewing, on the old
--- lease, with no trace of OTHER.
local function still_renewing(t, what)
    settle()
    local i = iface()
    t:log(string.format("%s: lease %s, addresses %s", what,
        i.lease and (i.lease.state .. " " .. i.lease.server .. " " .. i.lease.expires_in) or "nil",
        table.concat(network.ipv4(i), ",")))
    t:assert(i.lease and i.lease.state == "renewing", what .. ": ignored (still renewing)")
    t:assert(i.lease and i.lease.expires_in > 1000, what .. ": the old lease's clock")
    t:assert(not network.has_address(i, OTHER), what .. ": the offered address was not taken")
    t:assert(network.has_address(i, LEASED), what .. ": the lease address stays")
end

--- Put the machine back on the plain lease, from a renewing client.
local function restore_from_renewing()
    local m = caught.renew[#caught.renew]
    to_renewing(reply(m))
    assert(network.serve_until(gw, sut, function(i)
        return network.bound(i) and network.has_address(i, LEASED) and not network.has_address(i, OTHER)
    end, { iface = true, timeout = 10 }), "back on the plain lease")
end

local function renewing()
    intercept()
    renew()
    return await_caught("renew", 1, 10)
end

local function cable_cycle()
    nic:disconnect()
    assert(network.serve_until(gw, sut, function(i) return i.carrier == false end,
        { iface = true, timeout = 20 }), "carrier did not drop")
    gw:forget()
    nic:reconnect()
end

--- The kernel's IPv4 addresses on eth0: { [address] = prefix }.
local function v4()
    local out = {}
    for _, a in ipairs(rtnl.addresses_of(sut, INDEX, 4)) do out[a.address] = a end
    return out
end

local function netd_routes()
    local out = {}
    for _, r in ipairs(rtnl.routes_of(sut, INDEX)) do
        if r.family == 4 and r.protocol == rtnl.RTPROT.NETD then
            out[#out + 1] = string.format("%s/%d via %s", r.dst, r.prefix, tostring(r.gateway))
        end
    end
    table.sort(out)
    return table.concat(out, "; ")
end

-- ---------------------------------------------------------------------------
-- Which replies are looked at
-- ---------------------------------------------------------------------------

test("a reply is ignored unless it is a BOOTREPLY, on the current xid, to this chaddr, of a known type",
    { spec = "netd *dhcp4-lease.reply-filter" },
    function(t)
        bound()
        local m = renewing()
        local bad = { yiaddr = OTHER, lease = 99 }
        local function with(o)
            local x = {}
            for k, v in pairs(bad) do x[k] = v end
            for k, v in pairs(o) do x[k] = v end
            return x
        end
        to_renewing(reply(m, with({ op = 1 })))
        still_renewing(t, "a BOOTREQUEST")
        to_renewing(reply(m, with({ xid = (m.xid + 1) & 0xFFFFFFFF })))
        still_renewing(t, "another transaction id")
        to_renewing(reply(m, with({ chaddr = "\x02\0\0\0\0\x01" })))
        still_renewing(t, "another chaddr")
        to_renewing(reply(m, with({ type = 9 })))
        still_renewing(t, "message type 9")
        to_renewing(reply(m, with({ type = false })))
        still_renewing(t, "no option 53")
        -- The control: the same reply, well-formed, is taken.
        to_renewing(reply(m, { yiaddr = OTHER, lease = 99 }))
        local s = network.serve_until(gw, sut, function(i) return network.bound(i) and network.has_address(i, OTHER) end,
            { iface = true, timeout = 10 })
        t:assert(s, "the well-formed reply was taken")
        t:assert_eq(s and network.iface(s, "eth0").lease.expires_in <= 99, true, "with its 99 s lease")
        -- And back.
        m = renewing()
        restore_from_renewing()
    end)

-- ---------------------------------------------------------------------------
-- The server lock
-- ---------------------------------------------------------------------------

test("once a server is chosen, an ACK or NAK naming another is ignored (renewing, requesting)",
    { spec = "netd *dhcp4-lease.server-lock" },
    function(t)
        bound()
        local m = renewing()
        to_renewing(reply(m, { server = STRANGER, yiaddr = OTHER, lease = 99 }))
        still_renewing(t, "an ACK from a stranger while renewing")
        to_renewing(reply(m, { kind = D.NAK, server = STRANGER }))
        still_renewing(t, "a NAK from a stranger while renewing")
        to_renewing(reply(m, { kind = D.NAK, server = false }))
        still_renewing(t, "a NAK naming no server while renewing")

        -- Requesting: the offer's server is the chosen one.
        to_renewing(reply(m, { kind = D.NAK }))
        local d = await_caught("discover", 1, 10)
        to_acquiring(reply(d, { kind = D.OFFER }))
        local r = await_caught("request", 1, 10)
        to_acquiring(reply(r, { server = STRANGER }))
        settle()
        t:assert_eq(iface().lease, nil, "an ACK from a stranger while requesting is ignored")
        to_acquiring(reply(r, { kind = D.NAK, server = STRANGER }))
        settle()
        t:assert_eq(#caught.discover, 1, "a NAK from a stranger while requesting is ignored (no new DISCOVER)")
        to_acquiring(reply(r))
        local i = bound(10)
        t:assert_eq(i.lease.server, gw.addr, "the chosen server's ACK binds")
    end)

test("in Rebooting no server is chosen: an ACK from any server is taken",
    { spec = "netd *dhcp4-lease.server-lock netd *dhcp4-lease.state-table" },
    function(t)
        bound()
        intercept()
        cable_cycle()
        local r = await_caught("reboot", 1, 20)
        to_acquiring(reply(r, { server = STRANGER }))
        local i = bound(10)
        t:log("bound to " .. i.lease.server)
        t:assert_eq(i.lease.server, STRANGER, "the stranger's ACK made the lease")
        t:assert(network.has_address(i, LEASED), "for the requested address")
        -- Back to the gateway's lease.
        normal()
        cable_cycle()
        local back = bound(30)
        t:assert_eq(back.lease.server, gw.addr, "rebooted onto the gateway's lease")
    end)

-- ---------------------------------------------------------------------------
-- What each state accepts
-- ---------------------------------------------------------------------------

test("Selecting takes the first OFFER with an address and a server identifier and ignores the rest",
    { spec = "netd *dhcp4-lease.state-table" },
    function(t)
        bound()
        local m = renewing()
        gw:forget()
        to_renewing(reply(m, { kind = D.NAK }))
        local d = await_caught("discover", 1, 10)
        to_acquiring(reply(d, { kind = D.OFFER, yiaddr = "0.0.0.0" }))
        to_acquiring(reply(d, { kind = D.OFFER, yiaddr = "10.77.0.60", server = false }))
        settle()
        t:assert_eq(#caught.request, 0, "no REQUEST for an OFFER without an address or without option 54")
        to_acquiring(reply(d, { kind = D.OFFER, yiaddr = "10.77.0.60" }))
        to_acquiring(reply(d, { kind = D.OFFER, yiaddr = "10.77.0.61" }))
        local r = await_caught("request", 1, 10)
        settle()
        t:assert_eq(gateway.ip4_text(r.opt[50]), "10.77.0.60", "the first acceptable OFFER wins")
        t:assert_eq(#caught.request, 1, "the second OFFER is ignored")

        -- Requesting: an ACK that is not a lease is ignored and the
        -- REQUEST is retransmitted; a NAK returns to Selecting.
        to_acquiring(reply(r, { yiaddr = "10.77.0.60", lease = 2 }))
        local r2 = await_caught("request", 2, 10)
        t:assert_eq(iface().lease, nil, "an ACK with a 2 s lease is ignored")
        t:assert_eq(r2.xid, r.xid, "and the REQUEST retransmitted")
        to_acquiring(reply(r2, { kind = D.NAK }))
        local d2 = await_caught("discover", #caught.discover + 1, 10)
        t:assert(d2.xid ~= d.xid, "a NAK while requesting: Selecting again, new xid")
        t:assert_eq(d2.opt[50], nil, "with no requested address")
        normal()
        bound()
    end)

test("Rebooting: a NAK forgets the previous address and discovers afresh",
    { spec = "netd *dhcp4-lease.state-table" },
    function(t)
        bound()
        intercept()
        cable_cycle()
        local r = await_caught("reboot", 1, 20)
        t:assert_eq(gateway.ip4_text(r.opt[50]), LEASED, "rebooting for the previous address")
        to_acquiring(reply(r, { kind = D.NAK, server = false }))
        local d = await_caught("discover", 1, 10)
        t:assert(d.xid ~= r.xid, "Selecting, new xid")
        t:assert_eq(d.opt[50], nil, "the previous address is forgotten")
        normal()
        bound()
    end)

test("Renewing: an ACK for a different address replaces the lease; a NAK loses it",
    { spec = "netd *dhcp4-lease.state-table" },
    function(t)
        bound()
        local m = renewing()
        to_renewing(reply(m, { yiaddr = OTHER }))
        local s = network.serve_until(gw, sut, function(i)
            return network.bound(i) and network.has_address(i, OTHER) and not network.has_address(i, LEASED)
        end, { iface = true, timeout = 10 })
        t:assert(s, "the new address replaced the old")
        local k = v4()
        t:assert(k[OTHER] and not k[LEASED], "in the kernel too")
        -- Renew again (from OTHER) and NAK it.
        intercept()
        renew()
        local m2 = await_caught("renew", 1, 10)
        t:assert_eq(m2.ciaddr, OTHER, "renewing the new lease")
        gw:send_udp4(MAC, OTHER, 67, 68, reply(m2, { kind = D.NAK }))
        local d = await_caught("discover", 1, 10)
        local gone = network.serve_until(gw, sut, function(i)
            return i.lease == nil and not network.has_address(i, OTHER) end, { iface = true, timeout = 10 })
        t:assert(gone, "a NAK while renewing lost the lease")
        t:assert(d, "and the client is selecting")
        normal()
        bound()
    end)

-- ---------------------------------------------------------------------------
-- Reading an ACK
-- ---------------------------------------------------------------------------

test("an ACK is a lease only with an address, a server identifier, and a 4-byte lease time of at least 4 s",
    { spec = "netd *dhcp4-lease.ack-requirements netd *dhcp4-lease.state-table" },
    function(t)
        bound()
        local m = renewing()
        to_renewing(reply(m, { yiaddr = "0.0.0.0" }))
        still_renewing(t, "yiaddr 0")
        to_renewing(reply(m, { yiaddr = OTHER, lease = false }))
        still_renewing(t, "no lease time")
        to_renewing(reply(m, { yiaddr = OTHER, lease = "\0\0\x63" }))
        still_renewing(t, "a 3-byte lease time")
        to_renewing(reply(m, { yiaddr = OTHER, lease = "\0\0\0\0\x63" }))
        still_renewing(t, "a 5-byte lease time")
        to_renewing(reply(m, { yiaddr = OTHER, lease = 3 }))
        still_renewing(t, "a 3 s lease")
        -- 4 s is enough.
        to_renewing(reply(m, { yiaddr = OTHER, lease = 4 }))
        local s = network.serve_until(gw, sut, function(i) return network.has_address(i, OTHER) end,
            { iface = true, timeout = 5 })
        t:assert(s, "a 4 s lease is a lease")
        -- It runs out within seconds. NAK its renewal so the client
        -- discovers, and the gateway offers it the plain lease again.
        gw:dhcp({ pool = { LEASED }, lease = 3600, on = {
            renew = function(m) return reply(m, { kind = D.NAK }) end,
        } })
        assert(network.serve_until(gw, sut, function(i)
            return network.bound(i) and network.has_address(i, LEASED) and i.lease.expires_in > 100
                and not network.has_address(i, OTHER) end, { iface = true, timeout = 30 }), "back on the plain lease")

        -- With no server chosen (Rebooting) the lock does not apply, so an
        -- ACK without option 54 is refused for itself.
        intercept()
        cable_cycle()
        local r = await_caught("reboot", 1, 20)
        to_acquiring(reply(r, { server = false }))
        local r2 = await_caught("reboot", 2, 10)
        t:assert_eq(iface().lease, nil, "an ACK without a server identifier is not a lease")
        t:assert_eq(r2.xid, r.xid, "the REQUEST is retransmitted")
        to_acquiring(reply(r2))
        bound(10)
    end)

test("the prefix comes from a contiguous non-zero mask, otherwise from the address's class",
    { spec = "netd *dhcp4-lease.prefix" },
    function(t)
        bound()
        -- Masks on the gateway's subnet go through a renewal. An address
        -- off it could not renew by unicast (no route to the server), so
        -- each class case is handed out to a rebooting client instead (a
        -- cable pull; its REQUEST is a broadcast).
        local cases = {
            { LEASED, { prefix = 16 }, 16, "mask 255.255.0.0" },
            { LEASED, { prefix = gateway.ip4("255.0.255.0") }, 8, "a non-contiguous mask: class A" },
            { LEASED, { prefix = false }, 8, "no mask: class A" },
            { LEASED, { prefix = gateway.ip4("0.0.0.0") }, 8, "mask 0: class A" },
            { "126.1.0.5", { prefix = false, router = false }, 8, "no mask: first octet 126 is class A" },
            { "128.1.0.5", { prefix = false, router = false }, 16, "no mask: first octet 128 is class B" },
            { "191.255.0.5", { prefix = false, router = false }, 16, "no mask: first octet 191 is class B" },
            { "192.168.7.5", { prefix = false, router = false }, 24, "no mask: first octet 192 is class C" },
        }
        local held = LEASED
        for _, c in ipairs(cases) do
            local addr, o, want, what = c[1], c[2], c[3], c[4]
            o.yiaddr = addr
            intercept()
            if addr == LEASED then
                renew()
                local m = await_caught("renew", 1, 10)
                to_renewing(reply(m, o))
            else
                cable_cycle()
                local r = await_caught("reboot", 1, 20)
                to_acquiring(reply(r, o))
            end
            local s = network.serve_until(gw, sut, function(i)
                return network.bound(i) and network.has_address(i, addr)
                    and (addr == held or not network.has_address(i, held)) end, { iface = true, timeout = 10 })
            local k = v4()
            t:log(string.format("%s: %s/%s", what, addr, tostring(k[addr] and k[addr].prefix)))
            t:assert(s, what .. ": bound")
            t:assert_eq(k[addr] and k[addr].prefix, want, what .. ": /" .. want)
            held = addr
        end
        -- Back: the gateway refuses the off-subnet address and offers its own.
        normal()
        cable_cycle()
        assert(network.serve_until(gw, sut, function(i)
            return network.bound(i) and network.has_address(i, LEASED) and not network.has_address(i, held) end,
            { iface = true, timeout = 30 }), "back on the plain lease")
        t:assert_eq(v4()[LEASED].prefix, 24, "and /24 again")
    end)

-- PEI-1330: a malformed option 121 makes the whole ACK unusable (it is
-- ignored like any ACK that is not a lease). Asserted as it stands.
test("classless routes are installed and override option 3; a malformed option 121 rejects the ACK",
    { spec = "netd *dhcp4-lease.routes" },
    function(t)
        bound()
        local m = renewing()
        local routes = gateway.opt.classless({
            { "10.9.0.0", 16, "10.77.0.9" }, { "10.20.30.40", 32, "10.77.0.8" }, { "0.0.0.0", 0, gw.addr },
        })
        to_renewing(reply(m, { router = "10.77.0.254", extra = { { 121, routes } } }))
        local s = network.serve_until(gw, sut, function(i) return network.bound(i) end, { iface = true, timeout = 10 })
        t:assert(s, "bound")
        gw:serve({ timeout = 1 })
        local got = netd_routes()
        t:log("routes: " .. got)
        t:assert_eq(got, "0.0.0.0/0 via 10.77.0.1; 10.20.30.40/32 via 10.77.0.8; 10.9.0.0/16 via 10.77.0.9",
            "the classless routes, and the default from the /0 entry, not option 3")
        t:assert_eq(iface().gateway, gw.addr, "status gateway is the /0 route's")

        -- Without a /0 entry, option 3 is still ignored: no default route.
        m = renewing()
        to_renewing(reply(m, { router = "10.77.0.254", extra = { { 121, gateway.opt.classless({
            { "10.9.0.0", 16, "10.77.0.9" } }) } } }))
        assert(network.serve_until(gw, sut, function(i) return network.bound(i) end, { iface = true, timeout = 10 }))
        gw:serve({ timeout = 1 })
        got = netd_routes()
        t:log("routes without /0: " .. got)
        t:assert_eq(got, "10.9.0.0/16 via 10.77.0.9", "option 3 ignored beside classless routes")
        t:assert_eq(iface().gateway, nil, "no IPv4 gateway")

        -- Malformed: a prefix length of 33, and an entry cut short.
        m = renewing()
        to_renewing(reply(m, { yiaddr = OTHER, lease = 99, extra = { { 121, "\x21\x0a\x09\x00\x00\x00\x0a\x4d\x00\x09" } } }))
        still_renewing(t, "option 121 with prefix length 33")
        to_renewing(reply(m, { yiaddr = OTHER, lease = 99, extra = { { 121, "\x10\x0a\x09\x0a\x4d" } } }))
        still_renewing(t, "option 121 cut short")
        restore_from_renewing()
        gw:serve({ timeout = 1 })
        t:assert_eq(netd_routes(), "0.0.0.0/0 via 10.77.0.1", "the plain lease's default route only")
    end)

test("the options kept: DNS, domain, search list, hostname, MTU, broadcast and NTP, first occurrence winning",
    { spec = "netd *dhcp4-lease.options-kept" },
    function(t)
        bound()
        -- Let the profile use the MTU and the hostname (a profile edit
        -- restarts the client; it reboots onto the same lease).
        normal()
        network.write(sut, PROFILE, { ["Mtu.Offered"] = "dword:1", ["Hostname.Offered"] = "dword:1" })
        gw:serve({ timeout = 2 })
        bound()
        local m = renewing()
        -- For another address: the broadcast address is set when an
        -- address is added (§4.3), so a fresh address shows it.
        to_renewing(reply(m, { yiaddr = OTHER, extra = {
            { 6, gateway.opt.ip({ "10.77.0.53", "10.77.0.54" }) .. "\1\2" },
            { 6, gateway.opt.ip({ "10.77.0.99" }) },
            { 15, "corp.example\0junk" },
            { 12, "pt-leasehost\0x" },
            { 26, gateway.opt.u16(1400) },
            { 28, gateway.ip4("10.77.0.250") },
            { 42, gateway.opt.ip({ "10.77.0.123", "10.77.0.124" }) .. "\9" },
        } }))
        local s = network.serve_until(gw, sut, function(i) return network.bound(i) end, { iface = true, timeout = 10 })
        t:assert(s, "bound")
        gw:serve({ timeout = 1 })
        local st = network.status(sut)
        local i = network.iface(st, "eth0")
        local snap = network.call(sut, { query = "subscribe" })
        local ntp
        for _, sc in ipairs((snap and snap.scopes) or {}) do if sc.name == "eth0" then ntp = sc.ntp end end
        local mtu = tonumber((sut:read_file("/sys/class/net/eth0/mtu"):match("%d+")))
        local bc = v4()[OTHER] and v4()[OTHER].broadcast
        t:log(string.format("dns %s; search %s; hostname %s; mtu %s; broadcast %s; ntp %s",
            table.concat(i.dns, ","), table.concat(i.search, ","), st.hostname, tostring(mtu), tostring(bc),
            ntp and table.concat(ntp, ",") or "nil"))
        t:assert_eq(table.concat(i.dns, ","), "10.77.0.53,10.77.0.54",
            "option 6: every 4-byte entry of the first occurrence")
        t:assert_eq(table.concat(i.search, ","), "corp.example", "option 15 up to the NUL")
        t:assert_eq(st.hostname, "pt-leasehost", "option 12 up to the NUL")
        t:assert_eq(mtu, 1400, "option 26")
        t:assert_eq(bc, "10.77.0.250", "option 28")
        t:assert(ntp, "the resolver snapshot has the interface")
        t:assert_eq(ntp and table.concat(ntp, ","), "10.77.0.123,10.77.0.124", "option 42: every 4-byte entry")

        -- 119 wins over 15, with compression followed; and a pointer loop
        -- ends after 16 jumps without spoiling the lease.
        m = renewing()
        local search = "\7example\3com\0" .. "\3sub\xc0\x00" .. "\4loop\xc0\x13"
        to_renewing(reply(m, { extra = { { 15, "ignored.example" }, { 119, search }, { 12, "\xff\xfe" } } }))
        assert(network.serve_until(gw, sut, function(x) return network.bound(x) end, { iface = true, timeout = 10 }))
        gw:serve({ timeout = 1 })
        st = network.status(sut)
        i = network.iface(st, "eth0")
        t:log("search " .. table.concat(i.search, ",") .. "; hostname " .. st.hostname)
        t:assert_eq(table.concat(i.search, ","), "example.com,sub.example.com",
            "option 119 decoded with its pointer; the looping name dropped; option 15 unused")
        t:assert_eq(st.hostname, "pt-leasehost", "a hostname that is not UTF-8 is dropped")

        -- A domain that is not UTF-8 is dropped.
        m = renewing()
        to_renewing(reply(m, { extra = { { 15, "\xff\xfe" } } }))
        assert(network.serve_until(gw, sut, function(x) return network.bound(x) end, { iface = true, timeout = 10 }))
        gw:serve({ timeout = 1 })
        i = iface()
        t:assert_eq(#i.search, 0, "no search domain from a non-UTF-8 option 15")
        -- Put the profile back.
        network.write(sut, PROFILE, { ["Mtu.Offered"] = "dword:0", ["Hostname.Offered"] = "dword:0" })
        normal()
        gw:serve({ timeout = 2 })
        bound()
    end)
