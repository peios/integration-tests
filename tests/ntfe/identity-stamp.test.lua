-- PKM §6.9 — what KACS stamps on a socket, as the Flow layer reads it:
-- the effective token and the process facts of the moment of each act
-- that commits the socket to a role (creation, bind, listen, connect,
-- inheritance at accept, KACS_SO_RESTAMP), the last stamp governing; a
-- kernel socket stamped as the kernel's; and the stamp read through one
-- accessor that leaves the flow holding what it read after the socket
-- and its process are gone.
--
-- Every case stamps under one identity and acts under another, so the
-- verdict event can only show the identity if that act was the stamp:
-- a SYSTEM worker impersonates a minted token for exactly one act, and
-- a second worker takes a listener over by pidfd_getfd, the descriptor
-- passing this harness has.
--
-- Own VM: the policy is machine-wide state.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local token = require("helpers.token")
local hooks = require("helpers.hooks")
local id = require("helpers.ntfe_identity")

local vm = provium:vm("vntfeids", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local peer, net = ntfe.peer(vm)

local w = vm:spawn_worker()
id.set_comm(w, "pit-stamper")
local W_PID = id.pid(w)
local heir = vm:spawn_worker()
id.set_comm(heir, "pit-heir")
local HEIR_PID = id.pid(heir)

local E = ntfe.engine(vm, id.policy())

local Y = { user_sid = token.SID.TEST_USER_2 }

--- The single Flow event of `events` matching `want`, asserted.
local function judged(t, events, want, what)
    local got = id.flow_events(events, want)
    t:assert(#got >= 1, what .. " was judged: " .. ntfe.describe(events))
    return got[1] and got[1]["local"] or {}
end

-- ---- the stamp -------------------------------------------------------

test("a socket is governed by the effective token and the process facts of the moment it was stamped",
    { spec = "PKM *ntfe-identity.socket-stamp-effective-token-and-process-facts" }, function(t)
        local guid = id.process_guid(t, vm, w)
        id.set_comm(w, "pit-before")
        local own = assert(ntfe.udp_connect(w, net.peer_addr, 7200))
        -- A service thread acting for a client: the socket is the
        -- client's, as audit would say.
        local client
        id.as(w, Y, function() client = assert(ntfe.udp_connect(w, net.peer_addr, 7201)) end)
        -- The moment has passed: a later name is not the stamp's.
        id.set_comm(w, "pit-after")
        local _, events = E:during(function()
            ntfe.send(w, own, "own")
            ntfe.send(w, client, "client")
        end)
        id.set_comm(w, "pit-stamper")
        sys.close(w, own); sys.close(w, client)
        for _, c in ipairs({
            { "the worker's own socket", 7200, token.SID.LOCAL_SYSTEM },
            { "the socket made while impersonating", 7201, token.SID.TEST_USER_2 },
        }) do
            local e = judged(t, events, { dst_port = c[2] }, c[1])
            t:assert_eq(e.user, c[3], c[1] .. " carries the effective token's user: " .. id.describe_end(e))
            t:assert_eq(e.pid, W_PID, "the thread group it was made in")
            t:assert_eq(e.guid, guid, "that process's GUID")
            t:assert_eq(e.comm, "pit-before", "and the comm it had then, not now")
        end
    end)

test("each act that commits a socket to a role stamps it again",
    { spec = "PKM *ntfe-identity.stamp-taken-at-role-acts" }, function(t)
        E:replace(id.policy())
        -- Each socket is touched by Y for exactly one act; everything
        -- else it does, it does as SYSTEM. Sending is no act: an
        -- unconnected socket's autobind at sendto stamps nothing.
        local made = {}
        id.as(w, Y, function() made.creation = assert(ntfe.socket(w, ntfe.AF_INET, ntfe.SOCK_DGRAM)) end)

        made.bind = assert(ntfe.socket(w, ntfe.AF_INET, ntfe.SOCK_DGRAM))
        id.as(w, Y, function() t:assert_eq(id.bind(w, made.bind, net.addr, 0).ret, 0, "bind as Y") end)

        made.connect = assert(ntfe.socket(w, ntfe.AF_INET, ntfe.SOCK_DGRAM))
        id.as(w, Y, function()
            t:assert_eq(id.connect(w, made.connect, net.peer_addr, 7212).ret, 0, "connect as Y")
        end)

        made.restamp = assert(ntfe.udp_connect(w, net.peer_addr, 7213))
        id.as(w, Y, function() id.restamp(w, made.restamp) end)

        made.none = assert(ntfe.socket(w, ntfe.AF_INET, ntfe.SOCK_DGRAM))

        local listener = assert(ntfe.socket(w, ntfe.AF_INET, ntfe.SOCK_STREAM, { bind = { net.addr, 0 } }))
        id.as(w, Y, function() t:assert_eq(id.listen(w, listener).ret, 0, "listen as Y") end)
        local lport = id.port_of(w, listener)

        local _, events = E:during(function()
            ntfe.sendto(w, made.creation, "c", net.peer_addr, 7210)
            ntfe.sendto(w, made.bind, "b", net.peer_addr, 7211)
            ntfe.send(w, made.connect, "n")
            ntfe.send(w, made.restamp, "r")
            ntfe.sendto(w, made.none, "s", net.peer_addr, 7214)
            local c = ntfe.tcp_connect(peer, net.addr, lport)
            t:assert(c, "the listener answers")
            if c then sys.close(peer, c) end
        end)
        for _, fd in pairs(made) do sys.close(w, fd) end
        local first = ntfe.tcp_accept(w, listener, 300)
        if first then sys.close(w, first) end
        for _, c in ipairs({
            { "creation", { dst_port = 7210 }, token.SID.TEST_USER_2 },
            { "bind", { dst_port = 7211 }, token.SID.TEST_USER_2 },
            { "connect", { dst_port = 7212 }, token.SID.TEST_USER_2 },
            { "KACS_SO_RESTAMP", { dst_port = 7213 }, token.SID.TEST_USER_2 },
            { "listen", { dst_port = lport }, token.SID.TEST_USER_2 },
            { "no act as Y at all", { dst_port = 7214 }, token.SID.LOCAL_SYSTEM },
        }) do
            local e = judged(t, events, c[2], "the socket stamped at " .. c[1])
            t:assert_eq(e.user, c[3], "the socket Y touched only at " .. c[1] ..
                " is governed accordingly: " .. id.describe_end(e))
        end

        -- Inheritance at accept: the handshake completes while no Flow
        -- forest exists, so the first judgment is the server's first
        -- send — read from the accepted socket itself. The listener is
        -- restamped after the accept, so only a copy taken at accept can
        -- still say Y.
        E:replace(id.policy(nil, { no_flow = true }))
        local client = assert(ntfe.tcp_connect(peer, net.addr, lport))
        local accepted = assert(ntfe.tcp_accept(w, listener))
        id.restamp(w, listener)
        E:replace(id.policy())
        local _, later = E:during(function()
            ntfe.send(w, accepted, "from-the-accepted-socket")
            t:assert(ntfe.recv(peer, client, 300), "the data arrives")
        end)
        sys.close(peer, client); sys.close(w, accepted); sys.close(w, listener)
        local e = judged(t, later, { seat = ntfe.SEAT.LOCAL_OUT, dst_port = lport }, "the accepted socket's send")
        t:assert_eq(e.user, token.SID.TEST_USER_2,
            "the accepted socket inherited the listener's stamp at accept, though SYSTEM accepted it: " ..
            id.describe_end(e))
    end)

test("the last stamp governs: a listener handed to another program is that program's once it restamps",
    { spec = "PKM *ntfe-identity.last-stamp-governs" }, function(t)
        E:replace(id.policy())
        local heir_guid = id.process_guid(t, vm, heir)
        local listener = assert(ntfe.tcp_listen(w, net.addr, 7220))
        local function connect_once()
            local _, events = E:during(function()
                local c = ntfe.tcp_connect(peer, net.addr, 7220)
                t:assert(c, "the listener answers")
                if c then sys.close(peer, c) end
            end)
            return judged(t, events, { dst_port = 7220 }, "the connection")
        end
        t:assert_eq(connect_once().pid, W_PID, "the listener is its creator's")
        local held = id.take_fd(heir, W_PID, listener)
        sys.close(w, listener)
        t:assert_eq(connect_once().pid, W_PID,
            "holding the descriptor is not a stamp: still the creator's")
        id.restamp(heir, held)
        local e = connect_once()
        t:assert_eq(e.pid, HEIR_PID, "after the heir restamps, the heir's: " .. id.describe_end(e))
        t:assert_eq(e.comm, "pit-heir", "by its comm")
        t:assert_eq(e.guid, heir_guid, "and its process GUID")
        local l = id.listener(E, ntfe.IPPROTO.TCP, 7220)
        t:assert(l, "the listener is in the listeners dump")
        t:assert_eq(l and l.owner_pid, HEIR_PID, "under the heir there too")
        sys.close(heir, held)
    end)

test("a kernel socket is stamped as the kernel's",
    { spec = "PKM *ntfe-identity.kernel-socket-stamped-without-token" }, function(t)
        -- No subsystem in this profile opens a kernel inet socket in the
        -- root namespace that originates a flow (the control sockets
        -- only ever answer flows already judged), so the stamp is
        -- witnessed at the act: a new network namespace makes the
        -- kernel create its per-namespace control sockets, and each is
        -- stamped with owner kind 2, the kernel. That the kernel's stamp
        -- carries no token is held by pkm_kunit_ntfe's
        -- ntfe_kunit_identity_facts (a sock_create_kern socket resolves
        -- to `kernel` with a NULL token).
        local EVENT = "kacs/kacs_socket_token"
        local ns = vm:spawn_worker()
        t:assert(hooks.trace_start(vm, EVENT), "tracing starts")
        local r = ns:syscall(sys.NR.unshare, ntfe.CLONE_NEWNET)
        local lines = hooks.trace_stop(vm, EVENT)
        ns:kill(); ns:join()
        t:assert_eq(r.ret, 0, "unshare(CLONE_NEWNET): " .. sys.errname(r.errno))
        local stamps = {}
        for _, line in ipairs(lines or {}) do
            if line:match("reason=owner") then stamps[#stamps + 1] = line end
        end
        t:assert(#stamps > 0, "the kernel's sockets are stamped")
        for _, line in ipairs(stamps) do
            t:assert_eq(tonumber(line:match("max_imp=(%d+)")), 2, "as the kernel's: " .. line)
        end
    end)

test("the flow keeps the identity it read after the socket is closed and its process has exited",
    { spec = "PKM *ntfe-identity.owner-accessor-counted-ref-and-copy PKM *ntfe-identity.facts-outlive-process-and-socket" },
    function(t)
        E:replace(id.policy())
        local x, _, guid = id.principal(t, vm, { user_sid = token.SID.TEST_USER }, "pit-gone")
        local x_pid = id.pid(x)
        local fd = assert(ntfe.udp_connect(x, net.peer_addr, 7230, { bind = { net.addr, 0 } }))
        local sport = id.port_of(x, fd)
        ntfe.send(x, fd, "last words")
        sys.close(x, fd)
        x:kill(); x:join()

        local rec = id.flow_record(E, ntfe.IPPROTO.UDP, 7230, sport)
        t:assert(rec, "the flow outlives its socket")
        local o = rec and rec.owners[0] or {}
        t:assert_eq(o.kind, ntfe.LOCAL.PROGRAM, "its record still names a program")
        t:assert_eq(o.pid, x_pid, "the exited process's pid")
        t:assert_eq(o.comm, "pit-gone", "its comm")
        t:assert_eq(o.guid, guid, "its process GUID")
        t:assert_eq(o.user, token.SID.TEST_USER, "and, from the token the flow still holds, its user")

        -- A judgment after both are gone still asks the token: the same
        -- tuple, sent by someone else, re-judges the same flow.
        E:replace(id.policy({ ["by-user"] = { ["Local.User.Equal"] = token.sid_string(token.SID.TEST_USER),
                                              Actions = { "PASS" } } }))
        local _, events = E:during(function()
            local again = assert(ntfe.udp_connect(vm, net.peer_addr, 7230, { bind = { net.addr, sport } }))
            ntfe.send(vm, again, "same tuple")
            sys.close(vm, again)
        end)
        local got = id.flow_events(events, { dst_port = 7230, src_port = sport })
        t:assert(#got >= 1, "the flow is judged again: " .. ntfe.describe(events))
        t:assert(got[1] and got[1].rejudged, "as a re-judgment of the same flow")
        t:assert_eq(got[1] and got[1].attributed, "all/by-user", "and Local.User still answers from the token")
        t:assert_eq(got[1] and got[1]["local"].pid, x_pid, "naming the exited process")
    end)
