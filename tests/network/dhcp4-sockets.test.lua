-- netd TRM §5.6 — the sockets behind the DHCPv4 client: the per-interface
-- packet socket, the broadcast path from 0.0.0.0, the unicast path from
-- the lease address, and the udp/68 absorber.
--
-- The gateway records every frame byte for byte, so the broadcast and
-- unicast paths are read straight off the wire: the Ethernet destination,
-- every IPv4 header field the TRM's table names, and the UDP ports and
-- checksum. Each kind of message is produced where netd sends it:
--
--   DISCOVER, REQUEST (Requesting)  the boot-time exchange;
--   REQUEST (Renewing)              the `renew` control request;
--   REQUEST (Rebinding)             a short lease whose renewal goes
--                                   unanswered until T2;
--   RELEASE                         a profile edit while bound (§3.3);
--   REQUEST (Rebooting)             a cable pull (INIT-REBOOT on return).
--
-- The packet socket and the absorber are read from the guest's /proc: the
-- agent (SYSTEM) can list netd's descriptors, and /proc/net/packet and
-- /proc/net/udp carry each socket's inode, type and binding.
--
-- The absorber's purpose (no ICMP port-unreachable for a unicast reply)
-- needs a datagram that reaches the machine's UDP layer. An unsolicited
-- one does not: the shipped baseline drops a new inbound flow silently,
-- so it draws no ICMP whatever is bound. The unicast ACK to a renewal is
-- inside the renewal's own flow, so that is the probe, and the control is
-- the same ACK with netd running without its absorber (§2.1's degraded
-- start, produced by holding udp/68 without SO_REUSEADDR while netd
-- starts). That test is last: it leaves netd without an absorber.
--
-- The BPF filter's behaviour needs a client in Selecting from the first
-- DISCOVER and a gateway that answers by hand, so it has its own file,
-- `dhcp4-sockets-filter`.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
local server = gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
local sut = network.boot({ bridges = { lan }, gateway = gw })

local BROADCAST_MAC = string.rep("\xff", 6)
local LEASE = "10.77.0.50"

--- The Ethernet, IPv4 and UDP headers of a recorded frame.
local function headers(f)
    local raw = f.raw
    local vihl, tos, total, id, flagfrag, ttl, proto = string.unpack(">I1I1I2I2I2I1I1", raw, 15)
    local ihl = (vihl & 0xF) * 4
    local sport, dport, ulen, ucsum = string.unpack(">I2I2I2I2", raw, 15 + ihl)
    return {
        eth_dst = raw:sub(1, 6), eth_src = raw:sub(7, 12),
        version = vihl >> 4, tos = tos, id = id, flags = flagfrag >> 13, frag = flagfrag & 0x1FFF,
        ttl = ttl, proto = proto, src = gateway.ip4_text(raw:sub(27, 30)),
        dst = gateway.ip4_text(raw:sub(31, 34)),
        sport = sport, dport = dport, udp_checksum = ucsum,
    }
end

local function describe(h)
    return string.format("eth %s→%s ip %s→%s tos=0x%02x id=%d flags=%d frag=%d ttl=%d udp %d→%d csum=0x%04x",
        gateway.mac_text(h.eth_src), gateway.mac_text(h.eth_dst), h.src, h.dst, h.tos, h.id,
        h.flags, h.frag, h.ttl, h.sport, h.dport, h.udp_checksum)
end

--- Assert the TRM's broadcast-frame table on one message.
local function assert_broadcast(t, m, what)
    local h = headers(m.frame)
    t:log(what .. ": " .. describe(h))
    t:assert_eq(h.eth_dst, BROADCAST_MAC, what .. ": Ethernet destination ff:ff:ff:ff:ff:ff")
    t:assert_eq(h.src, "0.0.0.0", what .. ": source 0.0.0.0")
    t:assert_eq(h.dst, "255.255.255.255", what .. ": destination 255.255.255.255")
    t:assert_eq(h.tos, 0x10, what .. ": TOS 0x10")
    t:assert_eq(h.id, 0, what .. ": identification 0")
    t:assert_eq(h.flags, 2, what .. ": flags don't-fragment only")
    t:assert_eq(h.frag, 0, what .. ": fragment offset 0")
    t:assert_eq(h.ttl, 64, what .. ": TTL 64")
    t:assert_eq(h.proto, 17, what .. ": UDP")
    t:assert_eq(h.sport, 68, what .. ": source port 68")
    t:assert_eq(h.dport, 67, what .. ": destination port 67")
    t:assert_eq(h.udp_checksum, 0, what .. ": UDP checksum 0")
end

--- Assert the unicast path on one message: from the lease address to the
--- server, the kernel having resolved the server's MAC.
local function assert_unicast(t, m, what, sut_mac)
    local h = headers(m.frame)
    t:log(what .. ": " .. describe(h))
    t:assert_eq(h.eth_dst, gw.mac, what .. ": Ethernet destination is the server's MAC (resolved by the kernel)")
    t:assert_eq(h.eth_src, sut_mac, what .. ": from the machine's MAC")
    t:assert_eq(h.src, LEASE, what .. ": source is the lease address")
    t:assert_eq(h.dst, "10.77.0.1", what .. ": destination is the server")
    t:assert_eq(h.sport, 68, what .. ": source port 68")
    t:assert_eq(h.dport, 67, what .. ": destination port 67")
end

local function requests()
    return gw:dhcp_messages(gateway.DHCP.REQUEST)
end

local function iface()
    return network.iface(network.status(sut), "eth0")
end

--- The socket inodes among netd's file descriptors.
local function netd_socket_inodes(t)
    local pid = network.netd_pid(sut)
    t:assert(pid, "netd is running")
    local r = sut:run("ls -l /proc/" .. pid .. "/fd")
    r:assert_ok()
    local set = {}
    for inode in r.stdout:gmatch("socket:%[(%d+)%]") do set[inode] = true end
    return set, pid
end

--- /proc/net/packet rows: { type, proto, iface, inode }.
local function packet_sockets()
    local out = {}
    for line in sut:read_file("/proc/net/packet"):gmatch("[^\n]+") do
        local _, _, ty, proto, ifc, _, _, _, inode =
            line:match("^(%x+)%s+(%d+)%s+(%d+)%s+(%x+)%s+(%d+)%s+(%d+)%s+(%d+)%s+(%d+)%s+(%d+)")
        if ty then
            out[#out + 1] = { type = tonumber(ty), proto = proto:lower(), iface = tonumber(ifc), inode = inode }
        end
    end
    return out
end

--- /proc/net/udp rows: { local_ip, local_port, inode }.
local function udp_sockets()
    local out = {}
    for line in sut:read_file("/proc/net/udp"):gmatch("[^\n]+") do
        local ip, port, inode = line:match("^%s*%d+:%s+(%x+):(%x+)%s+%x+:%x+%s+%x+%s+%x+:%x+%s+%x+:%x+%s+%x+%s+%d+%s+%d+%s+(%d+)")
        if ip then
            local n = tonumber(ip, 16)
            -- The kernel prints the address as a host-order (little-endian) word.
            local text = string.format("%d.%d.%d.%d", n & 0xFF, (n >> 8) & 0xFF, (n >> 16) & 0xFF, n >> 24)
            out[#out + 1] = { ip = text, port = tonumber(port, 16), inode = inode }
        end
    end
    return out
end

--- netd's AF_PACKET sockets: rows of /proc/net/packet whose inode is one
--- of netd's descriptors.
local function netd_packet_sockets(t)
    local mine = netd_socket_inodes(t)
    local out = {}
    for _, p in ipairs(packet_sockets()) do
        if mine[p.inode] then out[#out + 1] = p end
    end
    return out
end

--- ICMP destination-unreachable/port-unreachable frames the machine sent.
local function port_unreachables()
    local out = {}
    for _, f in ipairs(gw.seen) do
        if f.ethertype == ntfe.ETH_P.IP and f.ip and f.ip.protocol == 1 then
            local ihl = (f.raw:byte(15) & 0xF) * 4
            local ty, code = f.raw:byte(15 + ihl), f.raw:byte(16 + ihl)
            if ty == 3 and code == 3 then out[#out + 1] = f end
        end
    end
    return out
end

--- A UDP socket bound to 0.0.0.0:`port` WITHOUT SO_REUSEADDR (ntfe's
--- socket helper always sets it), so a later bind of the same port fails
--- even with SO_REUSEADDR. Returns fd, or nil and an errno name.
local function bind_exclusive(who, port)
    local r = who:syscall(ntfe.NR.socket, ntfe.AF_INET, ntfe.SOCK_DGRAM, 0)
    if r.ret < 0 then return nil, sys.errname(r.errno) end
    local sa = ntfe.sockaddr("0.0.0.0", port)
    local b = who:syscall(ntfe.NR.bind, { args = { r.ret, 0, #sa }, bufs = { sa }, ptrs = { 1 } })
    if b.ret ~= 0 then sys.close(who, r.ret); return nil, sys.errname(b.errno) end
    return r.ret
end

local sut_mac

test("DISCOVER and REQUEST in Requesting leave on the packet socket as broadcast frames from 0.0.0.0",
    { spec = "netd *dhcp4-sockets.broadcast-frame" }, function(t)
        local s = network.serve_until(gw, sut, network.bound, { iface = "eth0", timeout = 60 })
        t:assert(s, "netd bound a lease")
        sut_mac = gateway.mac(network.iface(s, "eth0").mac)
        local d = gw:dhcp_messages(gateway.DHCP.DISCOVER)
        t:assert(#d >= 1, "a DISCOVER was seen")
        assert_broadcast(t, d[1], "DISCOVER")
        local selecting = nil
        for _, m in ipairs(requests()) do
            if m.opt[54] and m.opt[50] and m.ciaddr == "0.0.0.0" then selecting = m end
        end
        t:assert(selecting, "a REQUEST in Requesting (options 50 and 54, no ciaddr) was seen")
        assert_broadcast(t, selecting, "REQUEST (Requesting)")
    end)

test("REQUEST in Renewing goes unicast from the lease address on a transient socket; its reply is read off the packet socket",
    { spec = "netd *dhcp4-sockets.unicast-renewal" }, function(t)
        t:assert(sut_mac, "the first test bound a lease")
        -- The renewal is answered with a short lease, which the next test
        -- uses to reach Rebinding: T1 4 s, T2 8 s.
        server.lease, server.t1, server.t2 = 30, 4, 8
        local renewals = 0
        server.on.renew = function(m, default)
            renewals = renewals + 1
            if renewals == 2 then
                -- The T1 renewal: unanswered, so the client rebinds at T2.
                -- The rebinding answer restores a long lease.
                server.lease, server.t1, server.t2 = 3600, nil, nil
                return false
            end
            return nil
        end
        gw:forget()
        local before = iface().lease.expires_in
        t:log("lease expires in " .. before .. " s before the renewal")
        local r = network.call(sut, { query = "renew", interface = "eth0" })
        t:assert(r and r.ok, "netd took the renew request: " .. tostring(r and r.error))
        t:assert(gw:serve({ timeout = 10, until_ = function() return #requests() >= 1 end }), "a renewal REQUEST arrives")
        local m = requests()[1]
        t:assert_eq(m.ciaddr, LEASE, "the renewal carries the lease address in ciaddr")
        assert_unicast(t, m, "REQUEST (Renewing)", sut_mac)

        -- The ACK went back unicast to ciaddr. netd took it (the lease is
        -- now 30 s long), so the packet socket saw a reply addressed to the
        -- lease address, not only broadcasts.
        local s = network.serve_until(gw, sut, function(x)
            return x.lease and x.lease.state == "bound" and x.lease.expires_in <= 30
        end, { iface = "eth0", timeout = 10 })
        t:assert(s, "the unicast ACK was read: the lease is now the 30 s one")

        -- The renewal's socket was closed: nothing is bound to the lease
        -- address's port 68, only the absorber's wildcard.
        local rows, wildcard = udp_sockets(), false
        for _, u in ipairs(rows) do
            if u.ip == "0.0.0.0" and u.port == 68 then wildcard = true end
        end
        t:assert(wildcard, "the /proc/net/udp read works: it shows the absorber's 0.0.0.0:68")
        for _, u in ipairs(rows) do
            t:assert(not (u.ip == LEASE and u.port == 68),
                "no socket stays bound to " .. LEASE .. ":68 after the send")
        end
    end)

test("REQUEST in Rebinding goes out as a broadcast frame from 0.0.0.0",
    { spec = "netd *dhcp4-sockets.broadcast-frame" }, function(t)
        local function rebinding()
            for _, m in ipairs(requests()) do
                if m.ciaddr == LEASE and m.frame.dst_ip == "255.255.255.255" then return m end
            end
        end
        t:assert(gw:serve({ timeout = 20, until_ = function() return rebinding() ~= nil end }),
            "after an unanswered T1 renewal, a rebinding REQUEST arrives at T2")
        local all = requests()
        t:assert(#all >= 2, "the renewal at T1 came first")
        t:assert_eq(all[2].frame.dst_ip, "10.77.0.1", "the T1 renewal was unicast")
        local m = rebinding()
        assert_broadcast(t, m, "REQUEST (Rebinding)")
        t:assert_eq(m.ciaddr, LEASE, "rebinding still names the lease address in ciaddr")
        local s = network.serve_until(gw, sut, function(x)
            return x.lease and x.lease.state == "bound" and x.lease.expires_in > 60
        end, { iface = "eth0", timeout = 10 })
        t:assert(s, "the rebinding ACK restores a long lease")
        server.on.renew = nil
    end)

test("RELEASE goes unicast from the lease address to the server",
    { spec = "netd *dhcp4-sockets.unicast-renewal" }, function(t)
        gw:forget()
        -- Any change to the profile's resolved values restarts the client,
        -- which releases first (§3.3). Route.Metric 100 is the default's
        -- effect but not its value, so it changes the outcome and nothing
        -- else.
        network.write(sut, [[Profiles\default]], { ["Route.Metric"] = "dword:100" })
        t:assert(gw:serve({ timeout = 15, until_ = function()
            return #gw:dhcp_messages(gateway.DHCP.RELEASE) >= 1
        end }), "a RELEASE arrives")
        local m = gw:dhcp_messages(gateway.DHCP.RELEASE)[1]
        t:assert_eq(m.ciaddr, LEASE, "the RELEASE names the lease address")
        assert_unicast(t, m, "RELEASE", sut_mac)
        network.reg(sut, { "del", network.KEY .. [[\Profiles\default]], "Route.Metric" }):assert_ok()
        t:assert(network.serve_until(gw, sut, network.bound, { iface = "eth0", timeout = 30 }),
            "the restarted client binds again")
    end)

test("REQUEST in Rebooting goes out as a broadcast frame from 0.0.0.0",
    { spec = "netd *dhcp4-sockets.broadcast-frame" }, function(t)
        local nic = lan:nic(sut)
        nic:disconnect()
        t:assert(network.serve_until(gw, sut, function(x) return x.carrier == false end,
            { iface = "eth0", timeout = 20 }), "carrier goes")
        gw:forget()
        nic:reconnect()
        local function reboot()
            for _, m in ipairs(requests()) do
                if m.ciaddr == "0.0.0.0" and m.opt[50] and not m.opt[54] then return m end
            end
        end
        t:assert(gw:serve({ timeout = 20, until_ = function() return reboot() ~= nil end }),
            "the returning client opens with an INIT-REBOOT REQUEST")
        local m = reboot()
        t:assert_eq(gateway.ip4_text(m.opt[50]), LEASE, "for the lease address")
        assert_broadcast(t, m, "REQUEST (Rebooting)")
        t:assert(network.serve_until(gw, sut, network.bound, { iface = "eth0", timeout = 30 }), "and binds again")
    end)

test("each running client has one AF_PACKET SOCK_DGRAM ETH_P_IP socket bound to its interface",
    { spec = "netd *dhcp4-sockets.packet-socket" }, function(t)
        local i = iface()
        local ps = netd_packet_sockets(t)
        for _, p in ipairs(ps) do
            t:log(string.format("netd packet socket inode %s type %d proto %s iface %d", p.inode, p.type, p.proto, p.iface))
        end
        t:assert_eq(#ps, 1, "netd holds exactly one packet socket while one client runs")
        t:assert_eq(ps[1].type, 2, "SOCK_DGRAM (cooked)")
        t:assert_eq(ps[1].proto, "0800", "protocol ETH_P_IP")
        t:assert_eq(ps[1].iface, i.index, "bound to eth0's index")

        -- No client, no socket.
        network.write(sut, [[Profiles\default]], { ["Address.Offered"] = "dword:0" })
        t:assert(wait_until(function()
            gw:serve({ timeout = 0 })
            return #netd_packet_sockets(t) == 0
        end, { timeout = 20, interval = 0.5, desc = "the packet socket to close with its client" }),
            "a stopped client's packet socket is closed")
        network.write(sut, [[Profiles\default]], { ["Address.Offered"] = "dword:1" })
        t:assert(network.serve_until(gw, sut, network.bound, { iface = "eth0", timeout = 30 }),
            "the restarted client binds")
        local again = netd_packet_sockets(t)
        t:assert_eq(#again, 1, "and has its own packet socket again")
        t:assert(again[1].inode ~= ps[1].inode, "a new socket, not the old one")
    end)

test("netd binds 0.0.0.0:68 so a server's unicast reply draws no port-unreachable, and runs without it when it cannot",
    { spec = "netd *dhcp4-sockets.absorber" }, function(t)
        local mine = netd_socket_inodes(t)
        local absorber
        for _, u in ipairs(udp_sockets()) do
            if u.ip == "0.0.0.0" and u.port == 68 then absorber = u end
        end
        t:assert(absorber, "a UDP socket is bound to 0.0.0.0:68")
        t:assert(mine[absorber.inode], "and it is netd's (inode " .. absorber.inode .. ")")

        -- With the absorber: a renewal's unicast ACK reaches the UDP layer
        -- and finds a bound port.
        gw:forget()
        local r = network.call(sut, { query = "renew", interface = "eth0" })
        t:assert(r and r.ok, "renew accepted")
        t:assert(gw:serve({ timeout = 10, until_ = function() return #requests() >= 1 end }), "a renewal arrives")
        gw:serve({ timeout = 3 })
        t:assert_eq(#port_unreachables(), 0, "the unicast ACK drew no ICMP port-unreachable")

        -- Without it: hold udp/68 (no SO_REUSEADDR, so netd's bind fails)
        -- across a netd start, then let go of it.
        sut:run("svctl stop netd"):assert_ok()
        wait_until(function() return network.netd_pid(sut) == nil end,
            { timeout = 20, interval = 0.25, desc = "netd to stop" })
        local fd, err = bind_exclusive(sut, 68)
        t:assert(fd, "the agent holds 0.0.0.0:68 without SO_REUSEADDR: " .. tostring(err))
        sut:run("svctl start netd"):assert_ok()
        wait_until(function()
            local s = network.call(sut, { query = "status" })
            return s ~= nil and s.ok == true
        end, { timeout = 30, interval = 0.25, desc = "the new netd answering" })
        sys.close(sut, fd)
        t:assert(wait_until(function() return network.logged(sut, "could not bind udp/68 (") end,
            { timeout = 10, interval = 0.5, desc = "the absorber warning in netd's log" }),
            "netd logged that it could not bind udp/68")
        local s = network.serve_until(gw, sut, network.bound, { iface = "eth0", timeout = 30 })
        t:assert(s, "netd runs on without the absorber and binds a lease")
        for _, u in ipairs(udp_sockets()) do
            t:assert(not (u.ip == "0.0.0.0" and u.port == 68), "nothing holds 0.0.0.0:68 now")
        end

        gw:forget()
        r = network.call(sut, { query = "renew", interface = "eth0" })
        t:assert(r and r.ok, "renew accepted")
        t:assert(gw:serve({ timeout = 10, until_ = function() return #port_unreachables() >= 1 end }),
            "with no absorber, the same unicast ACK draws an ICMP port-unreachable")
        local f = port_unreachables()[1]
        t:assert_eq(f.src_ip, LEASE, "from the lease address")
        t:assert_eq(f.dst_ip, "10.77.0.1", "to the server")
    end)
