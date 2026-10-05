-- PKM §6.B — the listeners dump and "Listener records": which sockets
-- the dump lists (TCP in LISTEN, bound UDP and UDP-Lite, the root
-- namespace's only), what `count` and `total` say, and what each member
-- of `struct peios_ntfe_listener_rec` means — the wildcard address,
-- SO_BINDTODEVICE, SO_REUSEPORT groups, IPV6_V6ONLY, and the owner as
-- the socket's current stamp; with the 32-record copy-out.
--
-- Own VM: the sockets of the root namespace are machine-wide state, and
-- the dump lists all of them.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local raw = require("helpers.ntfe_abi_notes")
local token = require("helpers.token")

local vm = provium:vm("vntfeabilst", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local peer, net = ntfe.peer(vm)

local PASS_ALL = { all = { Actions = { "PASS" } } }
local E = ntfe.engine(vm, { RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = PASS_ALL })

local IPPROTO_UDPLITE = 136
local SOL_SOCKET, SO_REUSEPORT, SO_BINDTODEVICE = 1, 15, 25
local IPPROTO_IPV6, IPV6_V6ONLY = 41, 26

--- The listener records for `port`, optionally only of `protocol`.
local function listed(port, protocol)
    local out = {}
    for _, l in ipairs(assert(E:listeners(512))) do
        if l.port == port and (not protocol or l.protocol == protocol) then
            out[#out + 1] = l
        end
    end
    return out
end

--- A socket built step by step: `o.family`, `o.type`, `o.protocol`,
--- `o.opts` = { {level, name, int-or-string}, ... } set before the bind,
--- `o.bind` = { addr, port }, `o.listen`. Returns fd.
local function sock(who, o)
    local r = who:syscall(ntfe.NR.socket, o.family or ntfe.AF_INET,
        (o.type or ntfe.SOCK_STREAM) | ntfe.SOCK_NONBLOCK, o.protocol or 0)
    assert(r.ret >= 0, "socket: " .. sys.errname(r.errno))
    local fd = r.ret
    for _, opt in ipairs(o.opts or {}) do
        local v = type(opt[3]) == "string" and opt[3] or string.pack("<i4", opt[3])
        local s = who:syscall(ntfe.NR.setsockopt, {
            args = { fd, opt[1], opt[2], 0, #v }, bufs = { v }, ptrs = { 3 },
        })
        assert(s.ret == 0, "setsockopt " .. opt[2] .. ": " .. sys.errname(s.errno))
    end
    if o.bind then
        local sa = ntfe.sockaddr(o.bind[1], o.bind[2])
        local b = who:syscall(ntfe.NR.bind, { args = { fd, 0, #sa }, bufs = { sa }, ptrs = { 1 } })
        assert(b.ret == 0, "bind: " .. sys.errname(b.errno))
    end
    if o.listen then
        assert(who:syscall(ntfe.NR.listen, fd, 8).ret == 0, "listen")
    end
    return fd
end

local function close_all(who, fds) for _, fd in ipairs(fds) do sys.close(who, fd) end end

test("the listeners dump lists every listening TCP socket and bound UDP / UDP-Lite socket, with its owner, and counts them",
    { spec = "PKM *ntfe-abi-notes.listeners-ioctl-count-and-total" }, function(t)
        local fds = {
            sock(vm, { bind = { "127.0.0.1", 7900 }, listen = true }),
            sock(vm, { type = ntfe.SOCK_DGRAM, bind = { "127.0.0.1", 7901 } }),
            sock(vm, { type = ntfe.SOCK_DGRAM, protocol = IPPROTO_UDPLITE, bind = { "127.0.0.1", 7902 } }),
        }
        local all = raw.dump(vm, E.dev, "listeners", 512)
        t:assert_eq(all.ret, 0, "the dump succeeds")
        t:assert_eq(all.count, all.total, "with room for all, all are written")
        for _, want in ipairs({ { 7900, ntfe.IPPROTO.TCP, "TCP" }, { 7901, ntfe.IPPROTO.UDP, "UDP" },
                                { 7902, IPPROTO_UDPLITE, "UDP-Lite" } }) do
            local l = listed(want[1], want[2])
            t:assert_eq(#l, 1, "the " .. want[3] .. " socket is listed")
            t:assert_eq(l[1].owner_kind, ntfe.LOCAL.PROGRAM, "with the identity KACS stamped on it")
            t:assert_eq(l[1].owner_user, token.SID.LOCAL_SYSTEM, "its owner's user")
        end
        local short = raw.dump(vm, E.dev, "listeners", 1)
        t:assert_eq(short.ret, 0, "a short buffer is not an error")
        t:assert_eq(short.count, 1, "it holds what fits")
        t:assert_eq(short.total, all.total, "and `total` is how many the walk saw")
        close_all(vm, fds)
    end)

test("one record per socket prepared to receive; a UDP socket with a peer is `connected`",
    { spec = "PKM *ntfe-abi-notes.listener-rec-one-per-receiving-socket" }, function(t)
        local l = sock(vm, { bind = { "127.0.0.1", 7903 }, listen = true })
        local c = assert(ntfe.tcp_connect(vm, "127.0.0.1", 7903))
        local a = assert(ntfe.tcp_accept(vm, l))
        local tcp = listed(7903, ntfe.IPPROTO.TCP)
        t:assert_eq(#tcp, 1, "the listener is listed; the connected and accepted sockets are not")
        local cport = string.unpack(">I2", vm:syscall(ntfe.NR.getsockname, {
            args = { c, 0, 0 }, bufs = { string.rep("\0", 16), string.pack("<I4", 16) }, ptrs = { 1, 2 },
        }).out_bufs[1], 3)
        t:assert_eq(#listed(cport, ntfe.IPPROTO.TCP), 0, "the client's port is not a listener")
        close_all(vm, { c, a, l })

        local bound = sock(vm, { type = ntfe.SOCK_DGRAM, bind = { "127.0.0.1", 7904 } })
        local conn = assert(ntfe.udp_connect(vm, "127.0.0.1", 9, { bind = { "127.0.0.1", 7905 } }))
        local unbound = sock(vm, { type = ntfe.SOCK_DGRAM })
        local b = listed(7904, ntfe.IPPROTO.UDP)
        t:assert_eq(#b, 1, "a bound UDP socket is listed")
        t:assert_eq(b[1].connected, 0, "as receiving from anyone")
        local cn = listed(7905, ntfe.IPPROTO.UDP)
        t:assert_eq(#cn, 1, "a connected UDP socket is listed")
        t:assert_eq(cn[1].connected, 1, "as `connected`: it receives from one address only")
        local before = #assert(E:listeners(512))
        close_all(vm, { unbound })
        t:assert_eq(#assert(E:listeners(512)), before, "an unbound UDP socket was never listed")
        close_all(vm, { bound, conn })
    end)

test("`addr` all zero is the wildcard",
    { spec = "PKM *ntfe-abi-notes.listener-rec-zero-addr-wildcard" }, function(t)
        local any = sock(vm, { bind = { "0.0.0.0", 7906 }, listen = true })
        local one = sock(vm, { bind = { "127.0.0.1", 7907 }, listen = true })
        local any6 = sock(vm, { family = ntfe.AF_INET6, bind = { "::", 7908 }, listen = true })
        t:assert_eq(listed(7906)[1].addr, string.rep("\0", 16), "a socket bound to 0.0.0.0 lists all zero")
        t:assert_eq(listed(7908)[1].addr, string.rep("\0", 16), "so does one bound to ::")
        t:assert_eq(listed(7907)[1].addr:sub(1, 4), ntfe.ip4("127.0.0.1"),
            "and one bound to an address lists it")
        close_all(vm, { any, one, any6 })
    end)

test("`ifindex` is SO_BINDTODEVICE's interface, 0 for any",
    { spec = "PKM *ntfe-abi-notes.listener-rec-ifindex-bindtodevice" }, function(t)
        local tied = sock(vm, { opts = { { SOL_SOCKET, SO_BINDTODEVICE, net.name .. "\0" } },
                                bind = { "0.0.0.0", 7909 }, listen = true })
        local free = sock(vm, { bind = { "0.0.0.0", 7910 }, listen = true })
        t:assert_eq(listed(7909)[1].ifindex, net.ifindex, "a socket bound to a device names it")
        t:assert_eq(listed(7910)[1].ifindex, 0, "one bound to none says 0")
        close_all(vm, { tied, free })
    end)

test("`reuseport` marks a member of an SO_REUSEPORT group, and each member is listed",
    { spec = "PKM *ntfe-abi-notes.listener-rec-reuseport-each-member-listed" }, function(t)
        local o = { opts = { { SOL_SOCKET, SO_REUSEPORT, 1 } }, bind = { "127.0.0.1", 7911 }, listen = true }
        local a, b = sock(vm, o), sock(vm, o)
        local solo = sock(vm, { bind = { "127.0.0.1", 7912 }, listen = true })
        local group = listed(7911)
        t:assert_eq(#group, 2, "both members of the group are listed")
        for _, l in ipairs(group) do t:assert_eq(l.reuseport, 1, "each marked `reuseport`") end
        t:assert_eq(listed(7912)[1].reuseport, 0, "a socket in no group is not")
        close_all(vm, { a, b, solo })
    end)

test("`v6only` says an IPv6 socket refuses v4-mapped traffic; without it, it answers on both families",
    { spec = "PKM *ntfe-abi-notes.listener-rec-v6only" }, function(t)
        local only = sock(vm, { family = ntfe.AF_INET6, opts = { { IPPROTO_IPV6, IPV6_V6ONLY, 1 } },
                                bind = { "::", 7913 }, listen = true })
        local dual = sock(vm, { family = ntfe.AF_INET6, opts = { { IPPROTO_IPV6, IPV6_V6ONLY, 0 } },
                                bind = { "::", 7914 }, listen = true })
        local o, d = listed(7913)[1], listed(7914)[1]
        t:assert_eq(o.family, 6, "an IPv6 socket")
        t:assert_eq(o.v6only, 1, "with IPV6_V6ONLY is `v6only`")
        t:assert_eq(d.v6only, 0, "without it is not")
        local c4, why = ntfe.tcp_connect(vm, "127.0.0.1", 7914)
        t:assert(c4, "and the latter answers an IPv4 connection: " .. tostring(why))
        if c4 then sys.close(vm, c4) end
        local _, refused = ntfe.tcp_connect(vm, "127.0.0.1", 7913)
        t:assert_eq(refused, sys.E.CONNREFUSED, "while the `v6only` one does not")
        close_all(vm, { only, dual })
    end)

test("the owner fields are the socket's current stamp, as a flow's slot would carry it",
    { spec = "PKM *ntfe-abi-notes.listener-rec-owner-current-stamp" }, function(t)
        local w = vm:spawn_worker()
        local wpid = w:syscall(sys.NR.getpid).ret
        local rx = assert(ntfe.udp_bind(w, "127.0.0.1", 7915))
        local first = listed(7915)[1]
        t:assert_eq(first.owner_kind, ntfe.LOCAL.PROGRAM, "a program's socket is PROGRAM")
        t:assert_eq(first.owner_user, token.SID.LOCAL_SYSTEM, "stamped by the binder, SYSTEM")
        t:assert_eq(first.owner_pid, wpid, "with the binder's pid")
        t:assert_eq(first.owner_comm, raw.comm(vm, wpid), "and comm")
        local tok = assert(token.mint(w, {}))
        t:assert_eq(token.install(w, tok).ret, 0, "the worker becomes an ordinary user")
        t:assert_eq(raw.restamp(w, rx).ret, 0, "and restamps the socket")
        local now = listed(7915)[1]
        t:assert_eq(now.owner_user, token.SID.TEST_USER, "the record follows the current stamp")
        t:assert_eq(now.owner_unresolved, 0, "resolved")
        -- A flow to the socket records the same identity in its slot.
        raw.inject_lo_udp(vm, 7916, 7915, "who listens")
        local f
        for _, x in ipairs(assert(E:flows(512))) do if x.dst_port == 7915 then f = x end end
        t:assert(f, "a flow to the socket is listed")
        local slot = f.owners[1]
        t:assert_eq(slot.kind, now.owner_kind, "its receiving slot has the listener's kind")
        t:assert_eq(slot.pid, now.owner_pid, "pid")
        t:assert_eq(slot.guid, now.owner_guid, "GUID")
        t:assert_eq(slot.comm, now.owner_comm, "comm")
        t:assert_eq(slot.user, now.owner_user, "and user SID")
        sys.close(w, rx)
    end)

test("a socket nobody stamped reads KERNEL with `owner_unresolved` set",
    { spec = "PKM *ntfe-abi-notes.listener-rec-owner-current-stamp", covered_by = "kunit:pkm_kunit_ntfe",
      skip = "KACS leaves an inet socket unstamped only when the task that made " ..
             "it has no token (pkm_kacs_socket_stamp_owner); every guest process " ..
             "carries one and kernel sockets are stamped KERNEL, so no guest " ..
             "socket is unstamped; runs under ntfe_kunit_identity_unresolved, " ..
             "whose never-stamped socket's listener record reads owner_kind " ..
             "KERNEL with owner_unresolved set" },
    function(t) end)

test("the walk is of the root namespace's tables only",
    { spec = "PKM *ntfe-abi-notes.listener-dump-root-ns-best-effort" }, function(t)
        local pt = sock(peer, { bind = { net.peer_addr, 7917 }, listen = true })
        local pu = sock(peer, { type = ntfe.SOCK_DGRAM, bind = { net.peer_addr, 7918 } })
        local mine = sock(vm, { bind = { "0.0.0.0", 7919 }, listen = true })
        t:assert_eq(#listed(7917), 0, "a listener in another namespace is not listed")
        t:assert_eq(#listed(7918), 0, "nor a bound UDP socket there")
        t:assert_eq(#listed(7919), 1, "while the root namespace's are")
        close_all(peer, { pt, pu })
        close_all(vm, { mine })
    end)

test("listeners are copied out 32 at a time, and a dump of more is whole",
    { spec = "PKM *ntfe-abi-notes.bound-listener-batch-32" }, function(t)
        local fds = {}
        for port = 7930, 7999 do fds[#fds + 1] = assert(ntfe.udp_bind(vm, "127.0.0.1", port)) end
        local d = raw.dump(vm, E.dev, "listeners", 512)
        t:assert_eq(d.ret, 0, "the dump succeeds")
        t:assert(d.total >= 70, "seventy sockets and more are live: " .. d.total)
        t:assert_eq(d.count, d.total, "every one is written, across more than two batches")
        local seen = {}
        for i = 1, d.count do
            local port = string.unpack("<I2", raw.record(d, "listeners", i), 9)
            if port >= 7930 and port <= 7999 then
                t:assert(not seen[port], "no record is written twice")
                seen[port] = true
            end
        end
        local n = 0
        for _ in pairs(seen) do n = n + 1 end
        t:assert_eq(n, 70, "and none is missing")
        local cut = raw.dump(vm, E.dev, "listeners", 33)
        t:assert_eq(cut.count, 33, "a buffer one past a batch holds 33")
        close_all(vm, fds)
    end)

test("forty sockets in one hash bucket, more than a batch, are all written",
    { spec = "PKM *ntfe-abi-notes.bound-listener-batch-32", tags = { "known-bug" } }, function(t)
        -- PEI-1377: a bucket was walked once, so past the 32nd socket in
        -- one bucket the rest were counted in `total` but never written:
        -- `count < total` with room to spare. One SO_REUSEPORT group on
        -- one port shares one bucket.
        local fds = {}
        for _ = 1, 40 do
            fds[#fds + 1] = sock(vm, { type = ntfe.SOCK_DGRAM, opts = { { SOL_SOCKET, SO_REUSEPORT, 1 } },
                bind = { "0.0.0.0", 7920 } })
        end
        local d = raw.dump(vm, E.dev, "listeners", 512)
        t:assert_eq(d.ret, 0, "the dump succeeds")
        t:assert_eq(d.count, d.total, "with room for all, all are written")
        t:assert_eq(#listed(7920, ntfe.IPPROTO.UDP), 40, "every member of the group is listed")
        close_all(vm, fds)
    end)
