-- PKM §6.9 — what the identities look like from outside: a Flow event
-- and a flow record carry both ends (kind, process GUID, pid, comm,
-- user SID, service SID); an end that could not be attributed is
-- confessed in the status, on the event and on the record's slot; and
-- PEIOS_NTFE_IOC_LISTENERS lists every socket prepared to receive, with
-- the identity that governs it, without a packet having to arrive.
--
-- The unattributable end is a loopback sender the inbound seat cannot
-- see: a loopback datagram injected on lo with AF_PACKET reaches the
-- inbound seat having passed no outbound one.
--
-- Own VM: the policy is machine-wide state, the listeners dump is the
-- whole machine's, and the file sets lo's route_localnet and
-- accept_local (for the injected packet).

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local token = require("helpers.token")
local id = require("helpers.ntfe_identity")

local vm = provium:vm("vntfeidr", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))

local w = vm:spawn_worker()
id.set_comm(w, "pit-stream")
local W_PID = id.pid(w)

id.sysctl(vm, "/proc/sys/net/ipv4/conf/lo/route_localnet", "1")
id.sysctl(vm, "/proc/sys/net/ipv4/conf/lo/accept_local", "1")

local E = ntfe.engine(vm, id.policy())

local RESOLVD_SID = id.sid("S-1-5-80-3864064249-1823296737-2008945602-1354971773-2894779966")
local SERVICE = { user_sid = token.sid(5, 19), groups = {
    { sid = token.SID.EVERYONE, attributes = id.ENABLED },
    { sid = RESOLVD_SID, attributes = id.ENABLED },
} }

local ENDPOINT_FIELDS = { "kind", "pid", "guid", "comm", "user", "service" }

--- Assert that an event's endpoint and a record's owner slot agree.
local function same_end(t, ev_end, rec_end, what)
    for _, f in ipairs(ENDPOINT_FIELDS) do
        t:assert_eq(ev_end[f], rec_end[f], what .. ": the event's " .. f .. " is the record's")
    end
end

--- A loopback datagram injected on lo, to a socket of w's on `port`.
--- Returns the status delta, the events and the flow's record.
local function inject(t, port)
    local s = assert(ntfe.udp_bind(w, "0.0.0.0", port))
    local p = assert(ntfe.packet_socket(vm, "lo"))
    local udp = ntfe.udp("127.0.0.1", "127.0.0.1", 40000 + port % 1000, port, "injected")
    local frame = ntfe.eth(string.rep("\0", 6), string.rep("\0", 6), ntfe.ETH_P.IP)
        .. ntfe.ipv4("127.0.0.1", "127.0.0.1", ntfe.IPPROTO.UDP, #udp) .. udp
    local delta, events = E:during(function()
        t:assert_eq(ntfe.send_frame(vm, p, frame).ret, #frame, "the frame is sent on lo")
        t:assert_eq(ntfe.recv(w, s, 500), "injected", "and delivered")
    end)
    sys.close(vm, p); sys.close(w, s)
    return delta, events, id.flow_record(E, ntfe.IPPROTO.UDP, port)
end

-- ---- the event and the record ----------------------------------------

test("a Flow event and the flow's record carry both ends: kind, process GUID, pid, comm, user and service",
    { spec = "PKM *ntfe-identity.event-and-record-carry-both-ends" }, function(t)
        E:replace(id.policy())
        local client, _, guid = id.principal(t, vm, SERVICE, "pit-client")
        local client_pid = id.pid(client)
        local ok, err = pcall(function()
            local server = assert(ntfe.udp_bind(w, "127.0.0.1", 7500))
            local _, events = E:during(function()
                local fd = assert(ntfe.udp_connect(client, "127.0.0.1", 7500))
                ntfe.send(client, fd, "both ends")
                t:assert(ntfe.recv(w, server, 300), "the datagram crosses lo")
                sys.close(client, fd)
            end)
            sys.close(w, server)
            local rec = id.flow_record(E, ntfe.IPPROTO.UDP, 7500)
            t:assert(rec, "the flow is in the dump")
            local out = id.flow_events(events, { seat = ntfe.SEAT.LOCAL_OUT, dst_port = 7500 })
            local inb = id.flow_events(events, { seat = ntfe.SEAT.LOCAL_IN, dst_port = 7500 })
            t:assert(#out == 1 and #inb == 1, "both seats judged it: " .. ntfe.describe(events))
            if not (rec and out[1] and inb[1]) then return end
            local l = out[1]["local"]
            t:assert_eq(l.kind, ntfe.LOCAL.PROGRAM, "the sending end is a program")
            t:assert_eq(l.pid, client_pid, "with its pid")
            t:assert_eq(l.guid, guid, "its process GUID")
            t:assert_eq(l.comm, "pit-client", "its comm")
            t:assert_eq(l.user, token.sid(5, 19), "its user SID")
            t:assert_eq(l.service, RESOLVD_SID, "and its service SID")
            t:assert(out[1].remote.kind ~= ntfe.LOCAL.ABSENT, "the event carries the other end too")
            same_end(t, l, rec.owners[0], "outbound Local and slot 0")
            same_end(t, out[1].remote, rec.owners[1], "outbound Remote and slot 1")
            same_end(t, inb[1]["local"], rec.owners[1], "inbound Local and slot 1")
            same_end(t, inb[1].remote, rec.owners[0], "inbound Remote and slot 0")
        end)
        client:kill(); client:join()
        if not ok then error(err, 0) end
    end)

test("an end that could not be attributed is confessed in the status and on the event",
    { spec = "PKM *ntfe-identity.unattributed-end-confessed" }, function(t)
        E:replace(id.policy())
        local delta, events = inject(t, 7510)
        local got = id.flow_events(events, { dst_port = 7510 })
        t:assert_eq(#got, 1, "the injected flow was judged: " .. ntfe.describe(events))
        t:assert(delta.identity_unresolved >= 1, "identity_unresolved counts it")
        t:assert(got[1] and got[1].identity_unresolved, "the event carries PEIOS_NTFE_EV_F_IDENTITY_UNRESOLVED")
        t:assert(got[1] and got[1].remote.unresolved, "on the end that could not be seen")
        t:assert(got[1] and not got[1]["local"].unresolved, "and not on the one that could")
    end)

test("an end that could not be attributed is confessed on the flow record's slot",
    { spec = "PKM *ntfe-identity.unattributed-end-confessed",
      -- The unseen loopback sender (ABSENT + unresolved) once left its
      -- slot all zero (PEI-1308). The other two causes the TRM names (no
      -- KACS state, an unstamped inet socket) no guest task can reach.
    }, function(t)
        E:replace(id.policy())
        local _, _, rec = inject(t, 7511)
        t:assert(rec, "the injected flow is in the dump")
        t:assert(rec and rec.loopback == 1, "as a loopback flow")
        t:assert(rec and rec.owners[0].unresolved, "its unseen sender's slot carries the flag")
    end)

-- ---- at rest ---------------------------------------------------------

test("the listeners dump lists every socket prepared to receive, with the identity that governs it",
    { spec = "PKM *ntfe-identity.listeners-dump-reports-receivers-with-identity" }, function(t)
        local x, _, x_guid = id.principal(t, vm, { user_sid = token.SID.TEST_USER }, "pit-listener")
        local ok, err = pcall(function()
            local x_listener = assert(ntfe.tcp_listen(x, "127.0.0.1", 0))
            local x_port = id.port_of(x, x_listener)
            local tcp4 = assert(ntfe.tcp_listen(w, "127.0.0.1", 7520))
            local tcp6 = assert(ntfe.tcp_listen(w, "::1", 7521))
            local udp = assert(ntfe.udp_bind(w, "0.0.0.0", 7522))
            id.as(w, SERVICE, function() id.restamp(w, udp) end)
            local lite = assert(ntfe.socket(w, ntfe.AF_INET, ntfe.SOCK_DGRAM,
                { protocol = 136, bind = { "127.0.0.1", 7523 } }))
            local connected_udp = assert(ntfe.udp_connect(w, "127.0.0.1", 9, { bind = { "127.0.0.1", 7524 } }))
            local rp = id.reuseport_udp(w, "127.0.0.1", 7525)
            local bound_tcp = assert(ntfe.socket(w, ntfe.AF_INET, ntfe.SOCK_STREAM, { bind = { "127.0.0.1", 7526 } }))
            local client = assert(ntfe.tcp_connect(w, "127.0.0.1", 7520))
            local client_port = id.port_of(w, client)

            local guid = id.process_guid(t, vm, w)
            local function check(what, protocol, port, want)
                local l = id.listener(E, protocol, port)
                t:assert(l, what .. " is listed")
                if not l then return {} end
                t:assert_eq(l.owner_kind, ntfe.LOCAL.PROGRAM, what .. " is a program's")
                for k, v in pairs(want) do
                    t:assert_eq(l[k], v, what .. ": " .. k)
                end
                return l
            end
            local l4 = check("a TCP listener", ntfe.IPPROTO.TCP, 7520, {
                family = 4, owner_pid = W_PID, owner_comm = "pit-stream", owner_guid = guid,
                owner_user = token.SID.LOCAL_SYSTEM })
            t:assert_eq(l4.owner_service, nil, "a TCP listener: no service SID for a non-service")
            check("an IPv6 TCP listener", ntfe.IPPROTO.TCP, 7521, { family = 6, owner_pid = W_PID })
            check("a bound UDP socket", ntfe.IPPROTO.UDP, 7522, {
                family = 4, connected = 0, owner_user = token.sid(5, 19), owner_service = RESOLVD_SID })
            check("a bound UDP-Lite socket", 136, 7523, { owner_pid = W_PID })
            check("a connected UDP socket", ntfe.IPPROTO.UDP, 7524, { connected = 1 })
            check("a SO_REUSEPORT member", ntfe.IPPROTO.UDP, 7525, { reuseport = 1 })
            check("another program's listener", ntfe.IPPROTO.TCP, x_port, {
                owner_pid = id.pid(x), owner_comm = "pit-listener", owner_guid = x_guid,
                owner_user = token.SID.TEST_USER })
            t:assert_eq(id.listener(E, ntfe.IPPROTO.TCP, 7526), nil, "a bound TCP socket that is not listening is not")
            t:assert_eq(id.listener(E, ntfe.IPPROTO.TCP, client_port), nil, "nor is a connected TCP socket")

            for _, fd in ipairs({ tcp4, tcp6, udp, lite, connected_udp, rp, bound_tcp, client }) do
                sys.close(w, fd)
            end
            sys.close(x, x_listener)
            t:assert_eq(id.listener(E, ntfe.IPPROTO.TCP, 7520), nil, "and a closed listener is gone")
        end)
        x:kill(); x:join()
        if not ok then error(err, 0) end
    end)
