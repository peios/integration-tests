-- The NTFE ABI notes (PKM §6.B) at the level of raw bytes and raw errnos.
--
-- helpers/ntfe decodes records into tables and turns the stream's EAGAIN
-- into an empty batch, which is what a test of the engine wants and what
-- a test of the ABI cannot use: the appendix is about which errno comes
-- back for which argument, how many bytes one read() copies, and where a
-- field sits in a record. This module issues the calls itself and hands
-- back what the kernel returned, untouched.
--
-- It also carries the volume tools the bounds need — thousands of
-- datagrams in a handful of sendmmsg(2) calls — and a few probes of the
-- guest (its files, a worker's blocked thread, a process's GUID).

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local kmes = require("helpers.kmes")

local M = {}

M.NR = { sendmmsg = 307, tgkill = 234, fcntl = 72 }
M.F_GETFL, M.F_SETFL = 3, 4
M.O_NONBLOCK = 0x800
M.SIGBUS = 7
M.POLLRDNORM = 0x40

-- An address no process maps: the bottom page is never mapped, so a
-- copy to or from it faults.
M.BAD_ADDR = 0x10

local function zeros(n) return string.rep("\0", n) end

-- ---- the device, raw ---------------------------------------------------

--- A file on the device, non-blocking unless `blocking`. Returns fd.
function M.open(who, blocking)
    return assert(ntfe.open(who, sys.O.RDONLY | (blocking and 0 or M.O_NONBLOCK)))
end

--- read(2) of `len` bytes. `o.addr` replaces the buffer with a raw
--- address (for EFAULT). Returns ret, errno, and the bytes read.
function M.read(who, fd, len, o)
    o = o or {}
    if o.addr then
        local r = who:syscall(sys.NR.read, fd, o.addr, len)
        return r.ret, r.errno
    end
    local r = who:syscall(sys.NR.read, {
        args = { fd, 0, len }, bufs = { zeros(len) }, ptrs = { 1 },
    })
    if r.ret < 0 then return r.ret, r.errno end
    return r.ret, 0, r.out_bufs[1]:sub(1, r.ret)
end

--- Every record a read returned, decoded, plus each record's raw bytes.
function M.records(bytes)
    local out = {}
    for at = 1, #bytes, ntfe.EVENT_SIZE do
        local e = ntfe.decode_event(bytes, at)
        e.raw = bytes:sub(at, at + ntfe.EVENT_SIZE - 1)
        out[#out + 1] = e
    end
    return out
end

--- Read the stream on `fd` until it is empty (non-blocking fd).
--- Returns the decoded records, oldest first.
function M.drain(who, fd)
    local out = {}
    while true do
        local ret, errno, bytes = M.read(who, fd, ntfe.READ_MAX * ntfe.EVENT_SIZE)
        if ret < 0 then
            assert(errno == sys.E.AGAIN, "stream read: " .. sys.errname(errno))
            return out
        end
        for _, e in ipairs(M.records(bytes)) do out[#out + 1] = e end
    end
end

--- Set or clear O_NONBLOCK on an open file.
function M.set_nonblock(who, fd, on)
    local flags = who:syscall(M.NR.fcntl, fd, M.F_GETFL, 0).ret
    flags = on and (flags | M.O_NONBLOCK) or (flags & ~M.O_NONBLOCK)
    return who:syscall(M.NR.fcntl, fd, M.F_SETFL, flags)
end

--- The STATUS ioctl with a raw argument: `o.addr` a raw address in
--- place of the buffer, `o.size` the size encoded in the command.
function M.status_raw(who, fd, o)
    o = o or {}
    local size = o.size or ntfe.STATUS_SIZE
    local cmd = ntfe.ioc(2, 1, size)
    if o.addr then
        local r = who:syscall(sys.NR.ioctl, fd, cmd, o.addr)
        return r.ret, r.errno
    end
    local r = who:syscall(sys.NR.ioctl, {
        args = { fd, cmd, 0 }, bufs = { zeros(size) }, ptrs = { 2 },
    })
    return r.ret, r.errno, r.out_bufs[1]
end

M.DUMP = {
    counters = { cmd = ntfe.IOC.COUNTERS, size = ntfe.COUNTER_REC_SIZE },
    flows = { cmd = ntfe.IOC.FLOWS, size = ntfe.FLOW_REC_SIZE },
    listeners = { cmd = ntfe.IOC.LISTENERS, size = ntfe.LISTENER_REC_SIZE },
}

--- One dump ioctl (`kind` = "counters" | "flows" | "listeners") with
--- room for `capacity` records. `o.buf_addr` puts a raw address in the
--- query's `buf`; `o.query_addr` passes a raw address for the query
--- itself; `o.buf_len` overrides the byte length.
---
--- Returns a table: ret, errno, count, total, and `buf` (the raw
--- records, `count` × record size bytes).
function M.dump(who, fd, kind, capacity, o)
    o = o or {}
    local d = M.DUMP[kind]
    local len = o.buf_len or capacity * d.size
    if o.query_addr then
        local r = who:syscall(sys.NR.ioctl, fd, d.cmd, o.query_addr)
        return { ret = r.ret, errno = r.errno }
    end
    local r
    if o.buf_addr then
        r = who:syscall(sys.NR.ioctl, {
            args = { fd, d.cmd, 0 },
            bufs = { string.pack("<I8I4I4I4I4", o.buf_addr, len, 0, 0, 0) },
            ptrs = { 2 },
        })
    else
        r = who:syscall(sys.NR.ioctl, {
            args = { fd, d.cmd, 0 },
            bufs = { string.pack("<I8I4I4I4I4", 0, len, 0, 0, 0), zeros(math.max(len, 1)) },
            ptrs = { 2 },
            nested = { { parent = 1, child = 2, offset = 0 } },
        })
    end
    local out = { ret = r.ret, errno = r.errno }
    if r.ret == 0 then
        out.count, out.total = string.unpack("<I4I4", r.out_bufs[1], 13)
        if r.out_bufs[2] then
            out.buf = r.out_bufs[2]:sub(1, out.count * d.size)
        end
    end
    return out
end

--- The raw bytes of record `i` (1-based) of a dump.
function M.record(d, kind, i)
    local size = M.DUMP[kind].size
    return d.buf:sub((i - 1) * size + 1, i * size)
end

--- The raw flow record whose conntrack id (its first u32) is `id`.
function M.flow_record(d, id)
    for i = 1, d.count do
        local rec = M.record(d, "flows", i)
        if string.unpack("<I4", rec, 1) == id then return rec end
    end
    return nil
end

-- ---- traffic in bulk ---------------------------------------------------

local MMSG = 64 -- struct mmsghdr: msghdr (56) + msg_len, padded

local function mmsghdr(name_len)
    -- msg_name (filled by a nested pointer), msg_namelen, msg_iov
    -- (nested), msg_iovlen = 1, no control, flags 0.
    return string.pack("<I8I4I4I8I8I8I8I4I4I4I4", 0, name_len or 0, 0, 0, 1,
        0, 0, 0, 0, 0, 0)
end

--- `n` copies of `data` on the connected datagram socket `fd`, in as few
--- sendmmsg(2) calls as the kernel allows (1024 a call): every message
--- shares one iovec and one payload. Returns how many were sent.
function M.flood(who, fd, n, data)
    data = data or "x"
    local sent = 0
    while sent < n do
        local k = math.min(1024, n - sent)
        local nested = {}
        for i = 0, k - 1 do
            nested[#nested + 1] = { parent = 1, child = 2, offset = MMSG * i + 16 }
        end
        nested[#nested + 1] = { parent = 2, child = 3, offset = 0 }
        local r = who:syscall(M.NR.sendmmsg, {
            args = { fd, 0, k, 0 },
            bufs = { string.rep(mmsghdr(0), k), string.pack("<I8I8", 0, #data), data },
            ptrs = { 1 }, nested = nested,
        })
        assert(r.ret > 0, "sendmmsg: " .. sys.errname(r.errno))
        sent = sent + r.ret
    end
    return sent
end

--- One datagram of `data` to each IPv4 destination in `dests` (a list of
--- dotted addresses) at `port`, on the unconnected socket `fd`: up to
--- 250 destinations a call, each message naming its own sockaddr.
--- Returns how many were sent.
function M.spray(who, fd, dests, port, data)
    data = data or "x"
    local sent, i = 0, 1
    while i <= #dests do
        local k = math.min(250, #dests - i + 1)
        local bufs = { string.rep(mmsghdr(16), k), string.pack("<I8I8", 0, #data), data }
        local nested = { { parent = 2, child = 3, offset = 0 } }
        for j = 0, k - 1 do
            bufs[#bufs + 1] = (ntfe.sockaddr(dests[i + j], port))
            nested[#nested + 1] = { parent = 1, child = #bufs, offset = MMSG * j }
            nested[#nested + 1] = { parent = 1, child = 2, offset = MMSG * j + 16 }
        end
        local r = who:syscall(M.NR.sendmmsg, {
            args = { fd, 0, k, 0 }, bufs = bufs, ptrs = { 1 }, nested = nested,
        })
        assert(r.ret > 0, "sendmmsg: " .. sys.errname(r.errno))
        sent = sent + r.ret
        i = i + r.ret
    end
    return sent
end

--- How many events the engine emitted between two statuses: every
--- verdict it counts and every fail-closed drop is exactly one event,
--- and nothing else emits.
function M.emitted(before, after)
    local function sum(s)
        return s.verdict_pass + s.verdict_drop + s.verdict_reject + s.fail_closed
    end
    return sum(after) - sum(before)
end

-- ---- the policy --------------------------------------------------------

-- Entries seeded after registration must resolve at the sequence the
-- kernel already knows (helpers/ntfe's seed_pinned, which is local there).
local function seed_pinned(src, fn)
    local saved, real = src.seq, src.next_seq
    src.next_seq = function() return 1 end
    local ok, err = pcall(fn)
    src.next_seq = real
    src.seq = saved
    if not ok then error(err, 0) end
end

--- `E:replace` with a settle timeout of the caller's choosing, for a
--- policy so large that its walk outlasts the default five seconds.
function M.replace(E, policy, timeout_ms)
    local src = E.src
    local rules = assert(src:lookup(ntfe.RULES_KEY), "no Rules key")
    src.store.entries[rules] = nil
    src.store.values[rules] = nil
    seed_pinned(src, function() ntfe.seed(src, policy) end)
    local r = E:poke()
    assert(r.ret == 0, "poke: " .. sys.errname(r.errno))
    return E:settle(timeout_ms)
end

-- ---- the guest ---------------------------------------------------------

--- A small file's contents, or nil, errno.
function M.readfile(who, path)
    local fd, errno = sys.open(who, path)
    if not fd then return nil, errno end
    local s = sys.read(who, fd, 4096)
    sys.close(who, fd)
    return s
end

--- Write a small file (a sysctl). Returns true, or nil, errno.
function M.writefile(who, path, text)
    local fd, errno = sys.open(who, path, sys.O.WRONLY)
    if not fd then return nil, errno end
    local r = sys.write(who, fd, text)
    sys.close(who, fd)
    if r.ret < 0 then return nil, r.errno end
    return true
end

--- The raw `st_rdev` of a path.
function M.rdev(vm, path)
    local r = vm:syscall(sys.NR.newfstatat, {
        args = { sys.AT_FDCWD, 0, 0, 0 },
        bufs = { sys.cstr(path), zeros(144) }, ptrs = { 1, 2 },
    })
    if r.ret ~= 0 then return nil, r.errno end
    return (string.unpack("<I8", r.out_bufs[2], 41))
end

--- The tid of a thread of process `pid` that is blocked in syscall
--- `nr`, waiting at most about a second for one to get there. A
--- worker's `syscall_async` runs on a thread of its own; this finds it.
function M.blocked_thread(vm, pid, nr)
    for _ = 1, 200 do
        local dir = assert(sys.open(vm, "/proc/" .. pid .. "/task", sys.O.DIRECTORY))
        local entries = sys.getdents_all(vm, dir)
        sys.close(vm, dir)
        for _, e in ipairs(entries) do
            local tid = tonumber(e.name)
            if tid and tid ~= pid then
                local sc = M.readfile(vm, "/proc/" .. pid .. "/task/" .. tid .. "/syscall")
                local state = M.readfile(vm, "/proc/" .. pid .. "/task/" .. tid .. "/stat")
                if sc and sc:match("^" .. nr .. " ") and state
                    and state:match("%) S ") then
                    return tid
                end
            end
        end
        sys.nanosleep(vm, 0, 5000000)
    end
    return nil
end

--- The process GUID KACS knows `who` by, as KMES stamps it on an event
--- `who` emits. `who` must hold the audit privilege.
function M.process_guid(vm, who)
    local rings = {}
    for cpu = 0, 63 do
        local ring = kmes.attach(vm, cpu)
        if not ring then break end
        rings[#rings + 1] = ring
    end
    local marker = string.format("ntfe-guid-probe-%d", math.random(1, 1 << 30))
    local r = kmes.emit(who, marker, "\x81\xa1k\x01")
    local guid
    for _, ring in ipairs(rings) do
        for _, e in ipairs(kmes.of_type(kmes.drain(ring), marker)) do
            guid = e.process_guid
        end
        kmes.detach(ring)
    end
    if not guid then return nil, r.errno end
    return guid
end

--- Put one UDP datagram 127.0.0.1:`sport` → 127.0.0.1:`dport` straight
--- onto the loopback through a packet socket: it never crosses the
--- outbound seats, so the inbound seat meets a loopback flow nobody
--- recorded a sender for. The stack routes such a frame only while lo
--- accepts a loopback source from outside its own output path, so the
--- two sysctls are raised for the send and put back after.
function M.inject_lo_udp(vm, sport, dport, data)
    local conf = "/proc/sys/net/ipv4/conf/lo/"
    assert(M.writefile(vm, conf .. "route_localnet", "1"))
    assert(M.writefile(vm, conf .. "accept_local", "1"))
    local pfd = assert(ntfe.packet_socket(vm, "lo"))
    local udp = ntfe.udp("127.0.0.1", "127.0.0.1", sport, dport, data)
    local frame = ntfe.eth(zeros(6), zeros(6), ntfe.ETH_P.IP)
        .. ntfe.ipv4("127.0.0.1", "127.0.0.1", ntfe.IPPROTO.UDP, #udp) .. udp
    local r = ntfe.send_frame(vm, pfd, frame)
    sys.close(vm, pfd)
    assert(M.writefile(vm, conf .. "route_localnet", "0"))
    assert(M.writefile(vm, conf .. "accept_local", "0"))
    return r
end

--- KACS_SO_RESTAMP (SOL_KACS 4096, option 4): make the caller the
--- socket's governing identity. Returns the raw result.
function M.restamp(who, fd)
    return who:syscall(ntfe.NR.setsockopt, {
        args = { fd, 4096, 4, 0, 4 }, bufs = { string.pack("<i4", 1) }, ptrs = { 3 },
    })
end

--- The comm of process `pid`.
function M.comm(vm, pid)
    local s = M.readfile(vm, "/proc/" .. pid .. "/comm")
    return s and s:match("^[^\n]*")
end

return M
