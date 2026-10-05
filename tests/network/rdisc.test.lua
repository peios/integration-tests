-- netd §6.1 — router discovery, the half of it about netd itself: the
-- kernel's RA handling switched off, when discovery runs and stops, the
-- socket, and the solicitation schedule (when soliciting starts, backs
-- off, stops, and starts again). What an advertisement is accepted for
-- and what it does is rdisc-adverts.test.lua.
--
-- Harness: the scripted gateway (helpers.gateway) with NO router armed:
-- solicitations go unanswered unless a test sends an advertisement
-- itself (`gw:send_ra`), so the schedule is netd's alone. One whole
-- Peios machine joined by the shipped baseline. Solicitations are read
-- off the wire; their times are the gateway's, whole seconds, so each
-- interval is asserted with ±10% and a second of tolerance.
--
-- Own VMs: the schedule needs discovery to start while the test is
-- pumping, which a cable pull (`lan:nic(sut)`) gives: the carrier loss
-- stops discovery and, once the kernel's link-local address has been
-- through DAD again, it starts from the first interval. The tests run in
-- order on one pair.
--
-- Instruments of note: `/proc/sys/net/ipv6/conf/*/accept_ra`; sock_diag
-- (a local function: NETLINK_SOCK_DIAG dump of raw IPv6 sockets) for the
-- device the ICMPv6 socket is bound to; a local RTM_DELADDR and
-- RTM_NEWLINK/DELLINK, which helpers.rtnl lacks.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local rtnl = require("helpers.rtnl")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
local sut = network.boot({ bridges = { lan }, gateway = gw })
local nic = lan:nic(sut)

local INDEX = tonumber((sut:read_file("/sys/class/net/eth0/ifindex"):match("%d+")))
local MAC = gateway.mac(sut:read_file("/sys/class/net/eth0/address"))
local GW_LL = gateway.ip6_text(gw.ll)
local PROFILE = "Profiles\\default"

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

local function trim(s) return (tostring(s or ""):gsub("%s+$", "")) end

local function accept_ra(name)
    return trim(sut:read_file("/proc/sys/net/ipv6/conf/" .. name .. "/accept_ra"))
end

local function set_accept_ra(name, v)
    sut:run(string.format("echo %d > /proc/sys/net/ipv6/conf/%s/accept_ra", v, name)):assert_ok()
end

--- Whether text address `a` lies in the /64 `prefix` (text).
local function in64(a, prefix)
    return gateway.ip6(a):sub(1, 8) == gateway.ip6(prefix):sub(1, 8)
end

--- The status's addresses in `prefix`/64.
local function in_prefix(i, prefix)
    local out = {}
    for _, a in ipairs(network.ipv6(i)) do
        local addr = a:match("^([^/]+)")
        if in64(addr, prefix) then out[#out + 1] = addr end
    end
    return out
end

local function link_local()
    for _, a in ipairs(rtnl.addresses_of(sut, INDEX, 6)) do
        if a.address:match("^fe80:") then return a.address, a end
    end
end

local function count_logged(text)
    local n = 0
    for _, l in ipairs(network.logs(sut, { since = "30m ago", take = 2000 })) do
        if l:find(text, 1, true) then n = n + 1 end
    end
    return n
end

--- Solicitations seen after gateway time `since` (inclusive).
local function solicitations_since(since)
    local out = {}
    for _, f in ipairs(gw:solicitations()) do
        if f.at >= since then out[#out + 1] = f end
    end
    return out
end

local function await_solicitations(n, since, timeout)
    gw:serve({ timeout = timeout or 30, until_ = function()
        return #solicitations_since(since) >= n
    end })
    return solicitations_since(since)
end

--- An interval of `want` seconds (±10% jitter) measured in whole
--- gateway seconds.
local function interval_ok(got, want)
    return got >= math.floor(0.9 * want) - 1 and got <= math.ceil(1.1 * want) + 1
end

-- netlink, for what helpers.rtnl does not do.
local function nla(attr, payload)
    local len = 4 + #payload
    return string.pack("<I2I2", len, attr) .. payload .. string.rep("\0", (4 - len % 4) % 4)
end

local function nl_request(proto, msg_type, flags, body)
    local s = sut:syscall(ntfe.NR.socket, 16, ntfe.SOCK_RAW, proto)
    assert(s.ret >= 0, "netlink socket: " .. sys.errname(s.errno))
    local fd = s.ret
    ntfe.send(sut, fd, string.pack("<I4I2I2I4I4", 16 + #body, msg_type, flags | 0x1, 1, 0) .. body)
    local msgs, done = {}, false
    while not done do
        local buf = ntfe.recv(sut, fd, 3000, 65536)
        if not buf then break end
        local at = 1
        while at + 15 <= #buf do
            local len, kind = string.unpack("<I4I2", buf, at)
            if len < 16 then done = true; break end
            msgs[#msgs + 1] = { type = kind, body = buf:sub(at + 16, at + len - 1) }
            if kind == 2 or kind == 3 then done = true end
            at = at + ((len + 3) & ~3)
        end
    end
    sys.close(sut, fd)
    return msgs
end

local function nl_ack(msg_type, flags, body)
    for _, m in ipairs(nl_request(0, msg_type, flags | 0x4, body)) do
        if m.type == 2 then
            local err = string.unpack("<i4", m.body)
            if err ~= 0 then return nil, sys.errname(-err) end
            return true
        end
    end
    return nil, "no ack"
end

local function del_address6(addr, plen)
    local b = gateway.ip6(addr)
    return nl_ack(21, 0, string.pack("<I1I1I1I1i4", 10, plen, 0, 0, INDEX) .. nla(2, b) .. nla(1, b))
end

local function add_dummy(name)
    local body = string.pack("<I1I1I2i4I4I4", 0, 0, 0, 0, 0, 0)
        .. nla(3, name .. "\0") .. nla(18, nla(1, "dummy"))
    return nl_ack(16, 0x400 | 0x200, body)
end

local function del_link(index)
    return nl_ack(17, 0, string.pack("<I1I1I2i4I4I4", 0, 0, 0, index, 0, 0))
end

--- Raw IPv6 sockets of `protocol`, from sock_diag: { inode, bound_if,
--- protocol }. Raises when the dump is refused.
local function raw6_sockets(protocol)
    local req = string.pack("<I1I1I1I1I4", 10, 255, 0, protocol, 0xFFFFFFFF) .. string.rep("\0", 48)
    local out = {}
    for _, m in ipairs(nl_request(4, 20, 0x300, req)) do
        if m.type == 2 then
            local err = string.unpack("<i4", m.body)
            assert(err == 0, "sock_diag refused the raw dump: " .. sys.errname(-err))
        elseif m.type == 20 then
            -- The dump does not filter by protocol; a raw socket's
            -- protocol is its "source port" (inet_sport).
            local proto = string.unpack(">I2", m.body, 5)
            local bound_if = string.unpack("<I4", m.body, 41)
            local inode = string.unpack("<I4", m.body, 69)
            if proto == protocol then
                out[#out + 1] = { inode = inode, bound_if = bound_if }
            end
        end
    end
    return out
end

--- The socket inodes netd holds.
local function netd_socket_inodes()
    local pid = assert(network.netd_pid(sut), "netd is running")
    local r = sut:run("ls -l /proc/" .. pid .. "/fd")
    r:assert_ok()
    local set = {}
    for inode in r.stdout:gmatch("socket:%[(%d+)%]") do set[tonumber(inode)] = true end
    return set
end

local function cable_out()
    nic:disconnect()
    assert(serve_iface(function(i) return i.carrier == false end,
        { iface = "eth0", timeout = 20 }), "carrier did not drop")
end

-- ---------------------------------------------------------------------------
-- The kernel's RA handling
-- ---------------------------------------------------------------------------

test("accept_ra is 0 for all, default and every interface at startup, and for an interface seen for the first time; the kernel acts on no advertisement",
    { spec = "netd *rdisc.kernel-accept-ra-off" }, function(t)
        t:assert(serve_iface(network.bound, { iface = "eth0", timeout = 60 }),
            "netd bound a lease")
        for _, n in ipairs({ "all", "default", "lo", "eth0" }) do
            t:assert_eq(accept_ra(n), "0", "accept_ra for " .. n .. " after boot")
        end

        -- At startup, for all, default and every interface listed.
        for _, n in ipairs({ "all", "default", "lo", "eth0" }) do
            set_accept_ra(n, 1)
            t:assert_eq(accept_ra(n), "1", "accept_ra for " .. n .. " set back to 1 by the test")
        end
        network.restart_netd(sut)
        for _, n in ipairs({ "all", "default", "lo", "eth0" }) do
            t:assert_eq(accept_ra(n), "0", "accept_ra for " .. n .. " after netd restarted")
        end

        -- An interface netd sees for the first time: `default` is 1, so the
        -- new link is born with 1, and only netd's own write makes it 0.
        set_accept_ra("default", 1)
        local links_before = {}
        for _, l in ipairs(network.links(sut)) do links_before[l] = true end
        local ok, why = add_dummy("ptra0")
        t:assert(ok, "a dummy link was created: " .. tostring(why))
        local seen = serve_iface(function(s)
            return network.iface(s, "ptra0") ~= nil
        end, { timeout = 15 })
        t:assert(seen, "netd reports the new link")
        local born_with = accept_ra("ptra0")
        t:log("ptra0 accept_ra once netd reports it: " .. born_with)
        t:assert(wait_until(function() return accept_ra("ptra0") == "0" end,
            { timeout = 10, interval = 0.25, desc = "ptra0 accept_ra 0" }), "netd wrote 0 for ptra0")
        t:assert_eq(accept_ra("default"), "1", "netd did not touch `default` after startup (so ptra0's 0 is its own write)")
        set_accept_ra("default", 0)
        local idx = tonumber((sut:read_file("/sys/class/net/ptra0/ifindex"):match("%d+")))
        -- The baseline's wired rule joins a dummy (it is an Ethernet-type
        -- link), so netd runs its clients there too until it goes.
        t:assert(del_link(idx), "the dummy link was removed")
        local left = serve_iface(function(st) return network.iface(st, "ptra0") == nil end, { timeout = 15 })
        t:log("links after the removal: " .. table.concat(network.links(sut), " "))
        t:assert(left, "netd no longer reports the dummy link")
        -- Loading the dummy driver also made `dummy0`; take it away too.
        for _, l in ipairs(network.links(sut)) do
            if not links_before[l] then
                local li = tonumber((sut:read_file("/sys/class/net/" .. l .. "/ifindex"):match("%d+")))
                t:assert(del_link(li), "removed " .. l .. ", which the dummy driver made")
            end
        end
        t:assert(serve_iface(function(st) return #st.interfaces == 1 end, { timeout = 15 }),
            "netd is back to eth0 alone")

        -- The kernel configures nothing from an advertisement: no
        -- EUI-64 address, no RA-protocol route. netd's own stable address
        -- shows the advertisement did arrive.
        -- One unsolicited advertisement can be lost on a loaded host;
        -- repeat it, as a router would, until netd has taken it.
        local ra = { lifetime = 30,
            prefixes = { { prefix = "fd70::", len = 64, valid = 86400, preferred = 14400 } } }
        local s
        for _ = 1, 10 do
            gw:send_ra(ra)
            s = serve_iface(function(i)
                return #in_prefix(i, "fd70::") > 0 and i.gateway6 ~= nil
            end, { iface = "eth0", timeout = 3 })
            if s then break end
        end
        t:assert(s, "netd took the advertisement")
        local b = { MAC:byte(1, 6) }
        local eui = gateway.ip6_text(gateway.ip6("fd70::"):sub(1, 8)
            .. string.char(b[1] ~ 2, b[2], b[3], 0xff, 0xfe, b[4], b[5], b[6]))
        local mine = 0
        for _, a in ipairs(rtnl.addresses_of(sut, INDEX, 6)) do
            t:log(string.format("address %s/%d flags %#x", a.address, a.prefix, a.flags))
            t:assert(a.address ~= eui, "no kernel SLAAC (EUI-64) address " .. eui)
            if in64(a.address, "fd70::") then mine = mine + 1 end
        end
        t:assert_eq(mine, 1, "exactly one address in fd70::/64: netd's")
        for _, r in ipairs(rtnl.routes_of(sut, INDEX)) do
            t:assert(r.protocol ~= rtnl.RTPROT.RA, "no route of protocol ra (kernel RA handling): "
                .. r.dst .. "/" .. r.prefix)
            if r.family == 6 and r.prefix == 0 then
                t:assert_eq(r.protocol, rtnl.RTPROT.NETD, "the IPv6 default route is netd's")
            end
        end
    end)

-- ---------------------------------------------------------------------------
-- The solicitation schedule
-- ---------------------------------------------------------------------------

test("solicitations: type 133 with the MAC as source link-layer option, to ff02::2 at hop limit 255 from the link-local address, at 0, 4, 8, 16 and 32 s; the socket is raw ICMPv6 bound to the interface",
    { spec = "netd *rdisc.solicitation-schedule netd *rdisc.socket" }, function(t)
        cable_out()
        local ll = assert(link_local(), "a link-local address")
        gw:forget()
        local t0 = gw:now()
        nic:reconnect()
        local rs = await_solicitations(5, t0, 45)
        t:assert(#rs >= 5, "five solicitations within 45 s of the cable going back (saw " .. #rs .. ")")
        local ALL_ROUTERS_MAC = gateway.mcast_mac(gateway.ALL_ROUTERS)
        for k, f in ipairs(rs) do
            local b = f.icmp6_body
            local what = "solicitation " .. k
            t:log(string.format("%s at +%ds from %s hop %d", what, f.at - t0, f.src_ip, f.ip6.hop))
            t:assert_eq(f.dst, ALL_ROUTERS_MAC, what .. " to the all-routers MAC")
            t:assert_eq(f.dst_ip, "ff02::2", what .. " to ff02::2")
            t:assert_eq(f.ip6.hop, 255, what .. " at hop limit 255")
            t:assert_eq(f.src_ip, ll, what .. " from the link-local address")
            t:assert_eq(#b, 16, what .. " is 16 bytes")
            t:assert_eq(b:byte(1), 133, what .. " is type 133")
            t:assert_eq(b:byte(2), 0, what .. " code 0")
            t:assert_eq(b:sub(5, 8), "\0\0\0\0", what .. " reserved field zero")
            t:assert_eq(b:sub(9, 10), "\1\1", what .. " source link-layer option, length 1")
            t:assert_eq(b:sub(11, 16), MAC, what .. " carries the interface's MAC")
        end
        t:assert(rs[1].at - t0 <= 5, "the first goes once discovery starts (+" .. (rs[1].at - t0) .. "s)")
        local want = { 4, 4, 8, 16 }
        for k = 2, 5 do
            local gap = rs[k].at - rs[k - 1].at
            t:assert(interval_ok(gap, want[k - 1]),
                string.format("solicitation %d follows %d s after the last (gateway: %d s)", k, want[k - 1], gap))
        end

        -- The socket: a raw ICMPv6 socket of netd's, bound to eth0.
        local inodes = netd_socket_inodes()
        local bound = {}
        for _, s in ipairs(raw6_sockets(58)) do
            if inodes[s.inode] then bound[#bound + 1] = s.bound_if end
        end
        t:log("netd's raw ICMPv6 sockets bound to: " .. table.concat(bound, ",")
            .. "; links " .. table.concat(network.links(sut), " "))
        t:assert_eq(#bound, 1, "netd holds one raw ICMPv6 socket (one interface runs discovery)")
        t:assert_eq(bound[1], INDEX, "…bound to eth0 (SO_BINDTODEVICE)")
    end)

test("soliciting stops when an advertisement with a router lifetime arrives, and starts again from the first interval when every default router has expired",
    { spec = "netd *rdisc.solicit-again-when-routers-gone" }, function(t)
        -- Discovery is soliciting, backed off, from the last test.
        local t0 = gw:now()
        gw:send_ra({ lifetime = 8,
            prefixes = { { prefix = "fd71::", len = 64, valid = 600, preferred = 600 } } })
        local s = serve_iface(function(i) return i.gateway6 == GW_LL end,
            { iface = "eth0", timeout = 5 })
        t:assert(s, "the router became the default router")
        local rs = await_solicitations(3, t0 + 1, 30)
        t:assert(#rs >= 3, "solicitations again after the router expired (saw " .. #rs .. ")")
        for k, f in ipairs(rs) do t:log("solicitation at +" .. (f.at - t0) .. "s") end
        t:assert(rs[1].at - t0 >= 7, "none while the router was live (first at +" .. (rs[1].at - t0) .. "s)")
        t:assert(rs[1].at - t0 <= 10, "the first as soon as it expired, 8 s on (+" .. (rs[1].at - t0) .. "s)")
        t:assert(iface().gateway6 == nil, "no default router once it expired")
        t:assert(interval_ok(rs[2].at - rs[1].at, 4), "then 4 s (" .. (rs[2].at - rs[1].at) .. ")")
        t:assert(interval_ok(rs[3].at - rs[2].at, 4), "then 4 s (" .. (rs[3].at - rs[2].at) .. ")")

        -- A router lifetime of zero is no reason to stop.
        local t1 = gw:now()
        gw:send_ra({ lifetime = 0 })
        local more = await_solicitations(1, t1 + 1, 15)
        t:assert(#more >= 1, "still soliciting after an advertisement with router lifetime 0")
        t:log("next solicitation at +" .. ((more[1] and more[1].at or -1) - t1) .. "s after it")
    end)

-- ---------------------------------------------------------------------------
-- When discovery runs
-- ---------------------------------------------------------------------------

test("discovery runs while the profile wants IPv6 and the link is up with a finished link-local address; stopping removes its address and route and sends nothing",
    { spec = "netd *rdisc.start-stop" }, function(t)
        local function has_router()
            local s = serve_iface(function(i)
                return i.gateway6 == GW_LL and #in_prefix(i, "fd72::") > 0
            end, { iface = "eth0", timeout = 15 })
            return s
        end
        local function gone(i) return i.gateway6 == nil and #in_prefix(i, "fd72::") == 0 end
        local function kernel_clean(what)
            for _, a in ipairs(rtnl.addresses_of(sut, INDEX, 6)) do
                t:assert(not in64(a.address, "fd72::"), what .. ": no fd72::/64 address left (" .. a.address .. ")")
            end
            for _, r in ipairs(rtnl.routes_of(sut, INDEX)) do
                t:assert(not (r.family == 6 and r.prefix == 0 and r.protocol == rtnl.RTPROT.NETD),
                    what .. ": no IPv6 default route of netd's left")
            end
        end
        local function quiet_wire(what)
            for _, f in ipairs(gw.seen) do
                t:assert(not (f.icmp6_body and (f.icmp6_body:byte(1) == 133 or f.icmp6_body:byte(1) == 134)),
                    what .. ": no router discovery message on the wire")
                t:assert(not (f.udp and (f.udp.dport == 547 or f.udp.sport == 546)),
                    what .. ": no DHCPv6 on the wire")
            end
        end
        local RA = { lifetime = 1800, prefixes = { { prefix = "fd72::", len = 64, valid = 86400, preferred = 14400 } } }

        gw:send_ra(RA)
        t:assert(has_router(), "discovery is running: the router and its prefix are taken")

        -- Wants: the profile stops dealing in IPv6.
        local starts = count_logged("interface eth0: soliciting routers")
        gw:forget()
        network.write(sut, PROFILE, { ["Address.Families"] = "multi:ipv4" })
        t:assert(serve_iface(gone, { iface = "eth0", timeout = 15 }),
            "with Address.Families = ipv4 the address and the IPv6 default route go")
        kernel_clean("not wanted")
        gw:serve({ timeout = 6 })
        quiet_wire("not wanted")
        network.reg(sut, { "del", network.KEY .. "\\" .. PROFILE, "Address.Families" }):assert_ok()
        local back = gw:now()
        local rs = await_solicitations(1, back, 15)
        t:assert(#rs >= 1, "wanted again: a solicitation")
        t:assert(count_logged("interface eth0: soliciting routers") > starts, "…and `soliciting routers` logged")
        gw:send_ra(RA)
        t:assert(has_router(), "the router is taken again")

        -- Can: the kernel's link-local address goes away.
        local ll = assert(link_local(), "a link-local address")
        local stops = count_logged("interface eth0: ipv6 stopping")
        starts = count_logged("interface eth0: soliciting routers")
        gw:forget()
        local ok, why = del_address6(ll, 64)
        t:assert(ok, "removed the link-local address: " .. tostring(why))
        t:assert(serve_iface(gone, { iface = "eth0", timeout = 15 }),
            "without a link-local address discovery stops: address and route go")
        t:assert(count_logged("interface eth0: ipv6 stopping") > stops, "netd logged `ipv6 stopping`")
        kernel_clean("no link-local")
        gw:serve({ timeout = 5 })
        quiet_wire("no link-local")
        local readd = gw:now()
        t:assert(rtnl.add_address(sut, INDEX, ll, { prefix = 64 }), "the link-local address put back")
        rs = await_solicitations(1, readd, 15)
        t:assert(#rs >= 1, "a solicitation once the link-local address is usable")
        t:assert_eq(rs[1].src_ip, ll, "…from it (so not while it was tentative)")
        t:assert(count_logged("interface eth0: soliciting routers") > starts, "`soliciting routers` logged")
        t:assert_eq(count_logged("solicit: "), 0, "no solicitation failed to send")
        gw:send_ra(RA)
        t:assert(has_router(), "the router is taken again")

        -- Can: the carrier goes.
        gw:forget()
        cable_out()
        t:assert(serve_iface(gone, { iface = "eth0", timeout = 15 }),
            "without carrier discovery stops: address and route go")
        kernel_clean("no carrier")
        quiet_wire("no carrier")
        nic:reconnect()
        t:assert(serve_iface(network.bound, { iface = "eth0", timeout = 30 }),
            "bound again after the cable went back")
    end)
