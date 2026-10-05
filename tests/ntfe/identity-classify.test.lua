-- PKM §6.9 — what stands at each local end of a flow: `program`,
-- `kernel`, `shared` or `none`, decided by whether anyone answers.
-- Outbound it is the sending socket's stamp; inbound it is a transport
-- lookup for the receiver of the very packet being judged — by tuple
-- for TCP and UDP, through the SO_REUSEPORT hash, among raw sockets for
-- any other protocol — with multicast and broadcast UDP `shared` before
-- any lookup, and the stack's own handlers standing in when no socket
-- does.
--
-- The VM's veth peer is the remote host for every inbound case, and a
-- SYSTEM worker owns the VM's sockets: it can bind any port, and it
-- hands a socket to another identity by impersonating that identity and
-- restamping it (KACS_SO_RESTAMP), so each case can tell whose socket
-- the judgment found.
--
-- Own VM: the policy is machine-wide state, and the file opens ping
-- sockets to every group (net.ipv4.ping_group_range).

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local token = require("helpers.token")
local id = require("helpers.ntfe_identity")

local vm = provium:vm("vntfeidc", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local peer, net = ntfe.peer(vm)

local w = vm:spawn_worker()
id.set_comm(w, "pit-classify")
local W_PID = id.pid(w)

-- Ping sockets are closed to every group by default.
id.sysctl(vm, "/proc/sys/net/ipv4/ping_group_range", "0 2147483647")

local E = ntfe.engine(vm, id.policy())

local X = { user_sid = token.SID.TEST_USER }
local Y = { user_sid = token.SID.TEST_USER_2 }
local USER_3 = token.sid(5, 21, 1000, 2000, 3000, 1103)
local Z = { user_sid = USER_3 }

local SO_BROADCAST = 6

--- Hand `fd` (one of w's) to the identity `spec`.
local function stamp_as(fd, spec)
    id.as(w, spec, function() id.restamp(w, fd) end)
end

--- One datagram from the peer to `addr`:`port`, from a socket bound to
--- `sport` (0: ephemeral) with SO_BROADCAST set.
local function peer_datagram(addr, port, data, sport)
    local s = assert(ntfe.socket(peer, ntfe.AF_INET, ntfe.SOCK_DGRAM,
        { bind = { net.peer_addr, sport or 0 } }))
    ntfe.set_int_opt(peer, s, 1, SO_BROADCAST, 1)
    local r = ntfe.sendto(peer, s, data, addr, port)
    sys.close(peer, s)
    return r
end

--- An ICMP echo request from the peer to the VM, through a raw socket
--- there; returns whether a reply came back.
local function peer_ping(ident)
    local raw = assert(ntfe.socket(peer, ntfe.AF_INET, ntfe.SOCK_RAW, { protocol = ntfe.IPPROTO.ICMP }))
    ntfe.sendto(peer, raw, ntfe.icmp(8, 0, ident, "pit"), net.addr, 0)
    local reply = ntfe.recv(peer, raw, 500)
    sys.close(peer, raw)
    return reply ~= nil
end

-- ---- the four kinds --------------------------------------------------

test("Local names what stands at a flow's local end: program, kernel, shared or none",
    { spec = "PKM *ntfe-identity.local-fact-kinds" }, function(t)
        E:replace(id.policy({
            program = { ["Local.Equal"] = "program", Actions = { "PASS" } },
            kernel = { ["Local.Equal"] = "kernel", Actions = { "PASS" } },
            shared = { ["Local.Equal"] = "shared", Actions = { "PASS" } },
            none = { ["Local.Equal"] = "none", Actions = { "PASS" } },
        }))
        local bound = assert(ntfe.udp_bind(w, "0.0.0.0", 7101))
        local _, events = E:during(function()
            local c = assert(ntfe.udp_connect(w, net.peer_addr, 7100))
            ntfe.send(w, c, "program")
            sys.close(w, c)
            peer_ping(0x70000001)
            peer_datagram("255.255.255.255", 7101, "shared")
            ntfe.tcp_connect(peer, net.addr, 7102, 300)
        end)
        sys.close(w, bound)
        for _, c in ipairs({
            { "program", ntfe.LOCAL.PROGRAM, { dst_port = 7100 } },
            { "kernel", ntfe.LOCAL.KERNEL, { protocol = ntfe.IPPROTO.ICMP } },
            { "shared", ntfe.LOCAL.SHARED, { dst_port = 7101 } },
            { "none", ntfe.LOCAL.NONE, { dst_port = 7102 } },
        }) do
            local got = id.flow_events(events, c[3])
            t:assert(#got >= 1, c[1] .. ": the flow was judged: " .. ntfe.describe(events))
            t:assert_eq(got[1]["local"].kind, c[2], c[1] .. " is reported as its kind")
            t:assert_eq(got[1].attributed, "all/" .. c[1], "and `Local.Equal = " .. c[1] .. "` matched it")
        end
    end)

-- ---- outbound --------------------------------------------------------

test("outbound, a socket a program stamped makes the local end that program",
    { spec = "PKM *ntfe-identity.outbound-stamped-socket-program" }, function(t)
        E:replace(id.policy({ program = { ["Local.Equal"] = "program", Actions = { "PASS" } } }))
        local l = assert(ntfe.tcp_listen(peer, net.peer_addr, 7110))
        local _, events = E:during(function()
            local fd = assert(ntfe.tcp_connect(w, net.peer_addr, 7110))
            sys.close(w, fd)
            id.as(w, X, function()
                local fd2 = assert(ntfe.tcp_connect(w, net.peer_addr, 7110))
                sys.close(w, fd2)
            end)
        end)
        sys.close(peer, l)
        local out = id.flow_events(events, { seat = ntfe.SEAT.LOCAL_OUT, dst_port = 7110 })
        t:assert_eq(#out, 2, "each connection is judged at the outbound seat: " .. ntfe.describe(events))
        for i, want in ipairs({ token.SID.LOCAL_SYSTEM, token.SID.TEST_USER }) do
            local e = out[i]["local"]
            t:assert_eq(e.kind, ntfe.LOCAL.PROGRAM, "connection " .. i .. " is a program's")
            t:assert_eq(out[i].attributed, "all/program", "and reads `program` to the policy")
            t:assert_eq(e.pid, W_PID, "the sending process")
            t:assert_eq(e.comm, "pit-classify", "by its comm")
            t:assert_eq(e.user, want, "under the identity that stamped the socket: " .. id.describe_end(e))
        end
    end)

test("outbound, a packet no program sent is the kernel's",
    { spec = "PKM *ntfe-identity.outbound-kernel-or-no-socket-kernel" }, function(t)
        -- Joining a group makes the stack send IGMP membership reports
        -- of its own, from no socket at all, on a timer.
        E:replace(id.policy({ kernel = { ["Local.Equal"] = "kernel", Actions = { "PASS" } } }))
        local u = assert(ntfe.udp_bind(w, "0.0.0.0", 7111))
        E:drain()
        t:assert_eq(id.join(w, u, "239.7.7.1", net.addr).ret, 0, "the group is joined")
        local events = id.await(vm, E, function(list)
            return #id.flow_events(list, { protocol = 2 }) > 0
        end)
        sys.close(w, u)
        local igmp = id.flow_events(events, { protocol = 2 })
        t:assert(#igmp >= 1, "the membership report was judged: " .. ntfe.describe(events))
        t:assert_eq(igmp[1].seat, ntfe.SEAT.LOCAL_OUT, "at the outbound seat")
        local e = igmp[1]["local"]
        t:assert_eq(e.kind, ntfe.LOCAL.KERNEL, "as the kernel's: " .. id.describe_end(e))
        t:assert_eq(igmp[1].attributed, "all/kernel", "which is what the policy reads")
        t:assert_eq(e.pid, 0, "the joining program is nowhere in it")
        t:assert_eq(e.user, nil, "and there is no principal")
    end)

-- ---- inbound: shared -------------------------------------------------

test("inbound UDP to a broadcast or multicast address is shared, with no principal",
    { spec = "PKM *ntfe-identity.inbound-multicast-broadcast-udp-shared" }, function(t)
        E:replace(id.policy({
            ["shared-unowned"] = { ["Local.Equal"] = "shared", ["Local.User.Present"] = 0,
                                   Actions = { "PASS" } },
        }))
        -- Two programs bound to the port: one flow, many endpoints.
        local a = assert(ntfe.udp_bind(w, "0.0.0.0", 7120))
        local b = assert(ntfe.udp_bind(w, "0.0.0.0", 7120))
        stamp_as(b, X)
        t:assert_eq(id.join(w, a, "239.7.7.2", net.addr).ret, 0, "the group is joined")
        local _, events = E:during(function()
            peer_datagram("255.255.255.255", 7120, "limited")
            peer_datagram("10.9.0.255", 7120, "subnet")
            peer_datagram("239.7.7.2", 7120, "group")
        end)
        t:assert(ntfe.recv(w, a, 300), "the datagrams were delivered")
        sys.close(w, a); sys.close(w, b)
        for _, dst in ipairs({ "255.255.255.255", "10.9.0.255", "239.7.7.2" }) do
            local got = id.flow_events(events, { dst = dst, dst_port = 7120 })
            t:assert(#got >= 1, dst .. " was judged: " .. ntfe.describe(events))
            local e = got[1]["local"]
            t:assert_eq(e.kind, ntfe.LOCAL.SHARED, dst .. " is shared: " .. id.describe_end(e))
            t:assert_eq(e.pid, 0, "no one program stands at it")
            t:assert_eq(e.user, nil, "Local.User is absent")
            t:assert_eq(got[1].attributed, "all/shared-unowned", "to the policy as well")
        end
    end)

test("inbound UDP to a multicast group one socket receives is still shared",
    { spec = "PKM *ntfe-identity.inbound-multicast-broadcast-udp-shared",
      -- UDP's multicast early demux attaches the one socket a group
      -- datagram matches, and that socket was once taken as the receiver
      -- before the shared check, reading `program` (PEI-1305).
    }, function(t)
        E:replace(id.policy())
        local only = assert(ntfe.udp_bind(w, "0.0.0.0", 7121))
        t:assert_eq(id.join(w, only, "239.7.7.3", net.addr).ret, 0, "the group is joined")
        local _, events = E:during(function()
            peer_datagram("239.7.7.3", 7121, "group")
            t:assert(ntfe.recv(w, only, 300), "the one member receives it")
        end)
        sys.close(w, only)
        local got = id.flow_events(events, { dst = "239.7.7.3" })
        t:assert(#got >= 1, "the datagram was judged: " .. ntfe.describe(events))
        t:assert_eq(got[1]["local"].kind, ntfe.LOCAL.SHARED,
            "as shared, the per-program question being the join's: " .. id.describe_end(got[1]["local"]))
    end)

-- ---- inbound: by tuple -----------------------------------------------

test("inbound TCP and UDP find their receiver by tuple, the most specific socket first",
    { spec = "PKM *ntfe-identity.inbound-transport-lookup-by-tuple" }, function(t)
        E:replace(id.policy())
        -- A listener; a UDP port bound twice, to the address and to the
        -- wildcard; and a UDP socket connected to one peer port beside a
        -- wildcard one, which early demux finds for its own peer.
        local listener = assert(ntfe.tcp_listen(w, net.addr, 7130))
        stamp_as(listener, X)
        local specific = assert(ntfe.udp_bind(w, net.addr, 7131))
        local wildcard = assert(ntfe.udp_bind(w, "0.0.0.0", 7131))
        stamp_as(specific, X)
        stamp_as(wildcard, Y)
        local connected = assert(ntfe.udp_connect(w, net.peer_addr, 7134, { bind = { net.addr, 7132 } }))
        local other = assert(ntfe.udp_bind(w, "0.0.0.0", 7132))
        stamp_as(connected, Z)
        stamp_as(other, Y)
        local _, events = E:during(function()
            local fd = ntfe.tcp_connect(peer, net.addr, 7130)
            t:assert(fd, "the listener answers")
            if fd then sys.close(peer, fd) end
            peer_datagram(net.addr, 7131, "to-the-address")
            peer_datagram(net.addr, 7132, "from-the-connected-peer", 7134)
            peer_datagram(net.addr, 7132, "from-elsewhere", 7135)
        end)
        t:assert_eq(ntfe.recv(w, specific, 300), "to-the-address", "the specific socket receives")
        t:assert_eq(ntfe.recv(w, wildcard, 100), nil, "the wildcard does not")
        t:assert_eq(ntfe.recv(w, connected, 300), "from-the-connected-peer", "the connected socket gets its peer's")
        t:assert_eq(ntfe.recv(w, other, 300), "from-elsewhere", "and the wildcard everything else")
        for _, fd in ipairs({ listener, specific, wildcard, connected, other }) do sys.close(w, fd) end
        for _, c in ipairs({
            { "the listener", { dst_port = 7130 }, token.SID.TEST_USER },
            { "the specific UDP socket", { dst_port = 7131 }, token.SID.TEST_USER },
            { "the connected UDP socket", { dst_port = 7132, src_port = 7134 }, USER_3 },
            { "the wildcard beside it", { dst_port = 7132, src_port = 7135 }, token.SID.TEST_USER_2 },
        }) do
            local got = id.flow_events(events, c[2])
            t:assert(#got >= 1, c[1] .. "'s flow was judged: " .. ntfe.describe(events))
            local e = got[1]["local"]
            t:assert_eq(e.kind, ntfe.LOCAL.PROGRAM, c[1] .. " is found")
            t:assert_eq(e.user, c[3], "and named by its own stamp: " .. id.describe_end(e))
        end
    end)

test("a SO_REUSEPORT group is looked up through its own hash: the judgment names the member that receives",
    { spec = "PKM *ntfe-identity.inbound-transport-lookup-by-tuple" }, function(t)
        E:replace(id.policy())
        local a = id.reuseport_udp(w, net.addr, 7140)
        local b = id.reuseport_udp(w, net.addr, 7140)
        stamp_as(a, X)
        stamp_as(b, Y)
        local owner_of = { [a] = token.SID.TEST_USER, [b] = token.SID.TEST_USER_2 }
        local _, events = E:during(function()
            for i = 1, 12 do peer_datagram(net.addr, 7140, "d" .. i) end
        end)
        local receiver = {}
        for _, fd in ipairs({ a, b }) do
            while true do
                local data, sport = id.recvfrom(w, fd, 100)
                if not data then break end
                receiver[sport] = fd
            end
        end
        sys.close(w, a); sys.close(w, b)
        local flows, both = 0, {}
        for _, e in ipairs(id.flow_events(events, { dst_port = 7140 })) do
            local fd = receiver[e.src_port]
            t:assert(fd, "the datagram from port " .. e.src_port .. " was received")
            if fd then
                t:assert_eq(e["local"].user, owner_of[fd],
                    "the flow from port " .. e.src_port .. " names the member that received it")
                both[fd] = true
            end
            flows = flows + 1
        end
        t:assert_eq(flows, 12, "every datagram was its own flow")
        t:assert(both[a] and both[b], "and the hash spread them over both members")
    end)

test("a protocol other than TCP or UDP is looked up among the raw sockets bound to it",
    { spec = "PKM *ntfe-identity.inbound-other-protocol-raw-lookup" }, function(t)
        E:replace(id.policy())
        local raw = assert(ntfe.socket(w, ntfe.AF_INET, ntfe.SOCK_RAW, { protocol = 253 }))
        stamp_as(raw, X)
        local _, events = E:during(function()
            local s = assert(ntfe.socket(peer, ntfe.AF_INET, ntfe.SOCK_RAW, { protocol = 253 }))
            ntfe.sendto(peer, s, "experimental", net.addr, 0)
            sys.close(peer, s)
            t:assert(ntfe.recv(w, raw, 300), "the raw socket receives the packet")
        end)
        sys.close(w, raw)
        local got = id.flow_events(events, { protocol = 253 })
        t:assert(#got >= 1, "the packet was judged: " .. ntfe.describe(events))
        local e = got[1]["local"]
        t:assert_eq(e.kind, ntfe.LOCAL.PROGRAM, "the raw socket is found")
        t:assert_eq(e.user, token.SID.TEST_USER, "and named by its stamp: " .. id.describe_end(e))
        t:assert_eq(e.pid, W_PID, "its program's process")
    end)

-- ---- inbound: what was found -----------------------------------------

test("a request minisock stands for its listener",
    { spec = "PKM *ntfe-identity.inbound-found-socket-program" }, function(t)
        -- The flow's first judgment has to land on a packet the stack
        -- matches to a half-open connection: the handshake's ACK is
        -- dropped while no Flow forest exists, so the SYN went
        -- unjudged; then the Flow forest is published and the client's
        -- first data segment is the flow's first judgment.
        local listener = assert(ntfe.tcp_listen(w, net.addr, 7150))
        stamp_as(listener, X)
        E:replace({ RawPacket = id.PASS_ALL, Packet = {
            all = { Actions = { "PASS" } },
            ["no-handshake-ack"] = { ["DstPort.Equal"] = 7150, ["TcpFlags.Has"] = "ACK",
                                     ["TcpFlags.Hasnt"] = "SYN", Actions = { "DROP" } },
        } })
        local client = ntfe.tcp_connect(peer, net.addr, 7150)
        t:assert(client, "the client believes it connected")
        t:assert_eq(ntfe.tcp_accept(w, listener, 300), nil, "while the server has nothing to accept")
        E:replace(id.policy())
        local _, events = E:during(function()
            ntfe.send(peer, client, "first-data")
            local fd = ntfe.tcp_accept(w, listener, 2000)
            t:assert(fd, "the data completes the connection")
            if fd then sys.close(w, fd) end
        end)
        sys.close(peer, client); sys.close(w, listener)
        local got = id.flow_events(events, { dst_port = 7150 })
        t:assert(#got >= 1, "the flow was judged on the data: " .. ntfe.describe(events))
        local e = got[1]["local"]
        t:assert_eq(e.kind, ntfe.LOCAL.PROGRAM, "the half-open connection reads as a program")
        t:assert_eq(e.user, token.SID.TEST_USER, "the listener's: " .. id.describe_end(e))
    end)

test("a TIME_WAIT minisock is nobody's: kernel",
    { spec = "PKM *ntfe-identity.inbound-found-socket-program" }, function(t)
        E:replace(id.policy())
        local listener = assert(ntfe.tcp_listen(w, net.addr, 7151))
        local client = assert(ntfe.tcp_connect(peer, net.addr, 7151, 1000, { bind = { net.peer_addr, 45151 } }))
        local server = assert(ntfe.tcp_accept(w, listener))
        -- The VM closes first, so its end of the tuple lingers in
        -- TIME_WAIT once the peer closes too.
        sys.close(w, server)
        t:assert_eq(ntfe.recv(peer, client, 500), "", "the peer sees the VM's close")
        sys.close(peer, client)
        vm:clock():sleep("200ms")
        -- The same tuple again: conntrack starts a new flow, and the
        -- receiver lookup finds the TIME_WAIT minisock first.
        local _, events = E:during(function()
            local again = ntfe.tcp_connect(peer, net.addr, 7151, 1000, { bind = { net.peer_addr, 45151 } })
            if again then sys.close(peer, again) end
        end)
        sys.close(w, listener)
        local got = id.flow_events(events, { dst_port = 7151, src_port = 45151 })
        t:assert(#got >= 1, "the new flow was judged: " .. ntfe.describe(events))
        t:assert_eq(got[1]["local"].kind, ntfe.LOCAL.KERNEL,
            "as the kernel's, though a listener is on the port: " .. id.describe_end(got[1]["local"]))
    end)

test("with no socket, an end is kernel when the stack handles the protocol and none when it answers with a refusal",
    { spec = "PKM *ntfe-identity.inbound-nothing-found-kernel-or-none" }, function(t)
        E:replace(id.policy())
        local tcp_why, udp_err
        local _, events = E:during(function()
            t:assert(peer_ping(0x70000002), "the stack answers the echo request itself")
            _, tcp_why = ntfe.tcp_connect(peer, net.addr, 7160, 500)
            local u = assert(ntfe.udp_connect(peer, net.addr, 7161))
            ntfe.send(peer, u, "anyone?")
            _, udp_err = ntfe.recv(peer, u, 500)
            sys.close(peer, u)
            -- 254, not the raw-socket case's 253: a generic flow lives
            -- ten minutes, and that one is already judged.
            local s = assert(ntfe.socket(peer, ntfe.AF_INET, ntfe.SOCK_RAW, { protocol = 254 }))
            ntfe.sendto(peer, s, "nobody", net.addr, 0)
            sys.close(peer, s)
        end)
        t:assert_eq(tcp_why, sys.E.CONNREFUSED, "the closed TCP port is answered with a reset")
        t:assert_eq(udp_err, sys.E.CONNREFUSED, "the closed UDP port with an unreachable")
        for _, c in ipairs({
            { "ICMP", { protocol = ntfe.IPPROTO.ICMP }, ntfe.LOCAL.KERNEL },
            { "TCP to a closed port", { dst_port = 7160 }, ntfe.LOCAL.NONE },
            { "UDP to a closed port", { dst_port = 7161 }, ntfe.LOCAL.NONE },
            { "a protocol nothing handles", { protocol = 254 }, ntfe.LOCAL.NONE },
        }) do
            local got = id.flow_events(events, c[2])
            t:assert(#got >= 1, c[1] .. " was judged: " .. ntfe.describe(events))
            t:assert_eq(got[1].seat, ntfe.SEAT.LOCAL_IN, c[1] .. " at the inbound seat")
            t:assert_eq(got[1]["local"].kind, c[3], c[1] .. " reads " ..
                (c[3] == ntfe.LOCAL.KERNEL and "kernel" or "none"))
        end
    end)

test("SCTP reads kernel while its module is loaded",
    { spec = "PKM *ntfe-identity.sctp-reads-kernel",
      covered_by = "kunit:pkm_kunit_ntfe",
      skip = "the guest cannot load SCTP: CONFIG_IP_SCTP is a module and the " ..
             "kernel-only fixtures carry no sctp.ko, so no handler is ever " ..
             "registered for protocol 132 here (it reads `none`, by the same " ..
             "rule); runs under ntfe_kunit_identity_handler_reads_kernel, " ..
             "which shows the rule with protocol 253 rather than SCTP itself: " ..
             "with an inet_protos handler registered and no socket it reads " ..
             "PEIOS_NTFE_LOCAL_KERNEL, then `none` once it is unregistered" },
    function(t) end)

test("a ping socket's echo reply rides the outbound program sentence",
    { spec = "PKM *ntfe-identity.ping-reply-inherits-outbound-sentence" }, function(t)
        -- Were the reply looked up on its own it would find no socket —
        -- ping sockets are not raw sockets — and read `kernel`, which
        -- this policy drops.
        E:replace(id.policy({
            ["kernel-or-none"] = { ["Local.Equal"] = { "kernel", "none" }, Actions = { "DROP" } },
        }))
        local ping = assert(ntfe.socket(w, ntfe.AF_INET, ntfe.SOCK_DGRAM, { protocol = ntfe.IPPROTO.ICMP }))
        local reply
        local delta, events = E:during(function()
            ntfe.sendto(w, ping, ntfe.icmp(8, 0, 0, "pit-ping"), net.peer_addr, 0)
            reply = ntfe.recv(w, ping, 1000)
        end)
        sys.close(w, ping)
        t:assert(reply, "the echo reply reaches the ping socket")
        t:assert_eq(reply and reply:byte(1), 0, "as an echo reply")
        local judged = id.flow_events(events, { protocol = ntfe.IPPROTO.ICMP })
        t:assert_eq(#judged, 1, "the exchange is judged once: " .. ntfe.describe(events))
        t:assert_eq(judged[1].seat, ntfe.SEAT.LOCAL_OUT, "on the request, outbound")
        t:assert_eq(judged[1]["local"].kind, ntfe.LOCAL.PROGRAM, "as the program's")
        t:assert(delta.flow_cached >= 1, "and the reply answered to that sentence")
    end)
