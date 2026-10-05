-- The identity facts of NTFE (PKM §6.9), on top of helpers/ntfe: making
-- sockets under chosen identities, reading who a judgment saw, and the
-- handful of syscalls the identity cases need that helpers/ntfe does
-- not carry (getsockname, recvfrom, prctl, pidfd_getfd, sysctl writes).
--
-- Two ways to stand behind a socket as someone else:
--
-- - `as(who, spec, fn)`: a SYSTEM worker impersonates a freshly minted
--   token for the length of `fn`. Every stamp `fn` causes carries that
--   token, and the worker's own process facts (pid, comm, GUID). This is
--   how one process commits one socket to roles under different
--   identities, act by act.
-- - `principal(vm, spec)`: a new worker whose *primary* token is the
--   minted one, for the cases that need a whole process to be someone
--   else (or to die and leave its socket's flow behind).
--
-- A SYSTEM worker binds any port; a minted principal binds port 0 only
-- (no port-reservation table is served, so the compiled-in fallback
-- admits SYSTEM alone, §3.12.1). Fixed ports are therefore bound as
-- SYSTEM and handed to another identity with KACS_SO_RESTAMP.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local token = require("helpers.token")
local kmes = require("helpers.kmes")
local netobj = require("helpers.netobj")

local M = {}

M.PASS_ALL = { all = { Actions = { "PASS" } } }

--- A policy that passes everything, with `children` as exceptions of
--- the Flow layer's one root, `all`. A child that matches is attributed
--- `all/<name>`; when none does, `all` is. `o.no_flow` publishes no Flow
--- forest at all.
function M.policy(children, o)
    o = o or {}
    local p = { RawPacket = M.PASS_ALL, Packet = M.PASS_ALL }
    if not o.no_flow then
        p.Flow = { all = { Actions = { "PASS" }, children = children } }
    end
    return p
end

--- The Flow-layer events of `events` that also match `want`.
function M.flow_events(events, want)
    local w = { layer = ntfe.LAYER.FLOW }
    for k, v in pairs(want or {}) do w[k] = v end
    return ntfe.matching(events, w)
end

-- ---- identities ------------------------------------------------------

--- Mint an impersonation token in `who` (a SYSTEM worker) from a
--- helpers/token spec and impersonate it. Returns the token fd and its
--- logon session.
function M.impersonate(who, spec)
    local s = {}
    for k, v in pairs(spec or {}) do s[k] = v end
    s.token_type = token.TYPE.IMPERSONATION
    s.impersonation_level = token.LEVEL.IMPERSONATION
    local fd, session = token.mint(who, s)
    assert(fd, "mint: " .. sys.errname(session or 0))
    local r = token.impersonate(who, fd)
    assert(r.ret == 0, "impersonate: " .. sys.errname(r.errno))
    return fd, session
end

--- Run `fn()` in `who` while it impersonates `spec`; revert after.
function M.as(who, spec, fn)
    local fd = M.impersonate(who, spec)
    local ok, err = pcall(fn)
    token.revert(who)
    sys.close(who, fd)
    if not ok then error(err, 0) end
end

--- A new worker running as `spec` (its primary token), optionally
--- renamed to `comm`. Returns the worker, the token's logon session and
--- the process GUID (read while the worker is still SYSTEM, so a minted
--- principal's KMES rights do not matter). The caller kills it
--- (`w:kill(); w:join()`) or lets the test end.
function M.principal(t, vm, spec, comm)
    local w = vm:spawn_worker()
    local guid = M.process_guid(t, vm, w)
    -- token.mint writes the session into the spec; keep the caller's clean.
    local s = {}
    for k, v in pairs(spec or {}) do s[k] = v end
    local fd, session = token.mint(w, s)
    assert(fd, "mint: " .. sys.errname(session or 0))
    local r = token.install(w, fd)
    assert(r.ret == 0, "KACS_IOC_INSTALL: " .. sys.errname(r.errno))
    sys.close(w, fd)
    if comm then M.set_comm(w, comm) end
    return w, session, guid
end

--- A policy generation that differs from the last one in a rule that
--- never matches, so a replace always publishes and every flow's next
--- packet is re-judged.
local generation_bump = 0
function M.bump()
    generation_bump = generation_bump + 1
    return { ["DstPort.Equal"] = 1, ["SrcPort.Equal"] = generation_bump, Actions = { "PASS" } }
end

M.ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED

--- A binary SID from "S-1-5-21-..." text.
function M.sid(text)
    local parts = {}
    for n in text:gmatch("%d+") do parts[#parts + 1] = tonumber(n) end
    -- parts[1] is the revision.
    return token.sid(parts[2], table.unpack(parts, 3))
end

--- "S-1-..." or "nil", for messages.
function M.sid_text(bin)
    return bin and token.sid_string(bin) or "nil"
end

-- ---- process facts ---------------------------------------------------

--- The caller's pid as the kernel's tgid.
function M.pid(who)
    return who:syscall(sys.NR.getpid).ret
end

--- prctl(PR_SET_NAME): the task's `comm`.
function M.set_comm(who, name)
    local r = who:syscall(157, { args = { 15, 0 }, bufs = { name .. "\0" }, ptrs = { 1 } })
    assert(r.ret == 0, "prctl(PR_SET_NAME): " .. sys.errname(r.errno))
end

--- The process GUID of `who`, as the 16 raw bytes KMES stamps on an
--- event it emits (§2.A) — the same bytes the stamp records.
function M.process_guid(t, vm, who)
    local tag = string.format("PIT_NTFEID_%d", M.pid(who))
    local events = kmes.recording(t, vm, function()
        local r = kmes.emit(who, tag, kmes.PAYLOAD)
        assert(r.ret == 0, "kmes_emit: " .. sys.errname(r.errno))
    end)
    for _, ev in ipairs(events) do
        if ev.type == tag then return ev.process_guid end
    end
    error("no KMES event came back for " .. tag)
end

--- The GUID text of 16 raw bytes in the PCDS canonical form, unbraced:
--- Data1, Data2 and Data3 as numbers (little-endian in storage), Data4
--- in byte order, lowercase.
function M.guid_pcds(b)
    local d1, d2, d3 = string.unpack("<I4I2I2", b)
    local tail = {}
    for i = 9, 16 do tail[#tail + 1] = string.format("%02x", b:byte(i)) end
    return string.format("%08x-%04x-%04x-%s-%s", d1, d2, d3,
        table.concat(tail, "", 1, 2), table.concat(tail, "", 3, 8))
end

--- The same 16 bytes hex-encoded in storage order with 8-4-4-4-12
--- hyphens: what the kernel's bridge rendered before PEI-1309, kept to
--- show that text no longer names the process.
function M.guid_storage_order(b)
    local h = (b:gsub(".", function(c) return string.format("%02x", c:byte()) end))
    return h:sub(1, 8) .. "-" .. h:sub(9, 12) .. "-" .. h:sub(13, 16) .. "-"
        .. h:sub(17, 20) .. "-" .. h:sub(21, 32)
end

-- ---- sockets ---------------------------------------------------------

--- bind(2) an existing inet socket. Returns the raw result.
function M.bind(who, fd, addr, port)
    local sa = ntfe.sockaddr(addr, port)
    return who:syscall(ntfe.NR.bind, { args = { fd, 0, #sa }, bufs = { sa }, ptrs = { 1 } })
end

--- connect(2) an existing inet socket. Returns the raw result.
function M.connect(who, fd, addr, port)
    local sa = ntfe.sockaddr(addr, port)
    return who:syscall(ntfe.NR.connect, { args = { fd, 0, #sa }, bufs = { sa }, ptrs = { 1 } })
end

--- listen(2).
function M.listen(who, fd)
    return who:syscall(ntfe.NR.listen, fd, 16)
end

--- The local port of a bound inet socket.
function M.port_of(who, fd)
    local r = who:syscall(ntfe.NR.getsockname, { args = { fd, 0, 0 },
        bufs = { string.rep("\0", 28), string.pack("<I4", 28) }, ptrs = { 1, 2 } })
    assert(r.ret == 0, "getsockname: " .. sys.errname(r.errno))
    return (string.unpack(">I2", r.out_bufs[1], 3))
end

--- A UDP socket with SO_REUSEPORT set, bound to `addr`:`port`.
function M.reuseport_udp(who, addr, port)
    local fd = assert(ntfe.socket(who, ntfe.AF_INET, ntfe.SOCK_DGRAM))
    ntfe.set_int_opt(who, fd, 1, netobj.SO_REUSEPORT, 1)
    local r = M.bind(who, fd, addr, port)
    assert(r.ret == 0, "bind: " .. sys.errname(r.errno))
    return fd
end

--- KACS_SO_RESTAMP: `who`'s effective identity replaces the stamp.
function M.restamp(who, fd)
    local r = netobj.restamp(who, fd)
    assert(r.ret == 0, "KACS_SO_RESTAMP: " .. sys.errname(r.errno))
end

--- recvfrom(2) within `timeout_ms` (default 300). Returns the data and
--- the sender's port, or nil, "timeout".
function M.recvfrom(who, fd, timeout_ms)
    if ntfe.poll(who, fd, ntfe.POLLIN, timeout_ms or 300) & ntfe.POLLIN == 0 then
        return nil, "timeout"
    end
    local r = who:syscall(ntfe.NR.recvfrom, { args = { fd, 0, 2048, 0, 0, 0 },
        bufs = { string.rep("\0", 2048), string.rep("\0", 16), string.pack("<I4", 16) },
        ptrs = { 1, 4, 5 } })
    if r.ret < 0 then return nil, r.errno end
    return r.out_bufs[1]:sub(1, r.ret), (string.unpack(">I2", r.out_bufs[2], 3))
end

--- IP_ADD_MEMBERSHIP for `group` on the interface holding `ifaddr`.
function M.join(who, fd, group, ifaddr)
    local mreq = ntfe.ip4(group) .. ntfe.ip4(ifaddr)
    return who:syscall(ntfe.NR.setsockopt, { args = { fd, 0, 35, 0, #mreq },
        bufs = { mreq }, ptrs = { 3 } })
end

--- pidfd_getfd(2): `who` takes a duplicate of `pid`'s descriptor `fd`.
function M.take_fd(who, pid, fd)
    local pidfd = assert(token.pidfd_open(who, pid))
    local r = who:syscall(438, pidfd, fd, 0)
    sys.close(who, pidfd)
    assert(r.ret >= 0, "pidfd_getfd: " .. sys.errname(r.errno))
    return r.ret
end

-- ---- the machine -----------------------------------------------------

--- Write a sysctl (or any /proc file) as `vm`.
function M.sysctl(vm, path, value)
    local fd, e = sys.open(vm, path, sys.O.WRONLY)
    assert(fd, "open " .. path .. ": " .. sys.errname(e or 0))
    local r = sys.write(vm, fd, value .. "\n")
    sys.close(vm, fd)
    assert(r.ret > 0, "write " .. path .. ": " .. sys.errname(r.errno))
end

--- Collect events from `E` until `pred(list)` is true or `timeout_ms`
--- (default 3000) passes, for what the kernel sends on a timer (an
--- IGMP report). Returns the events collected.
function M.await(vm, E, pred, timeout_ms)
    local seen = {}
    local waited = 0
    while true do
        for _, e in ipairs(E:events()) do seen[#seen + 1] = e end
        if pred(seen) or waited >= (timeout_ms or 3000) then return seen end
        sys.nanosleep(vm, 0, 50000000)
        waited = waited + 50
    end
end

--- The record of the flow to `dst_port` over `protocol` in the flows
--- dump, or nil.
function M.flow_record(E, protocol, dst_port, src_port)
    for _, f in ipairs(assert(E:flows())) do
        if f.protocol == protocol and f.dst_port == dst_port
            and (src_port == nil or f.src_port == src_port) then
            return f
        end
    end
    return nil
end

--- The listener record for `protocol` on `port`, or nil.
function M.listener(E, protocol, port)
    for _, l in ipairs(assert(E:listeners())) do
        if l.protocol == protocol and l.port == port then return l end
    end
    return nil
end

--- One line describing an endpoint, for messages.
function M.describe_end(e)
    return string.format("kind %d pid %d comm %q user %s service %s%s",
        e.kind, e.pid, e.comm, M.sid_text(e.user), M.sid_text(e.service),
        e.unresolved and " unresolved" or "")
end

return M
