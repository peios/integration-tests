-- The verdict stream at the syscall level (PKM §6.7), for the tests that
-- need more than helpers/ntfe's one reader on the main agent: raw reads
-- of a chosen length on any file, a drain that never blocks, a burst of
-- judged traffic big enough to wrap the ring, and the guest's clock.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")

local M = {}

M.RING = 4096
M.POLLRDNORM = 0x40

--- CLOCK_REALTIME in nanoseconds, as the kernel stamps `t_ns`.
function M.now_ns(who)
    local r = who:syscall(228, { -- clock_gettime
        args = { 0, 0 }, bufs = { string.rep("\0", 16) }, ptrs = { 1 },
    })
    local s, ns = string.unpack("<i8i8", r.out_bufs[1])
    return s * 1000000000 + ns
end

--- read(2) `len` bytes from a device file: the raw result, its bytes
--- (`r.out_bufs[1]`) as they came back from the guest.
function M.read_raw(who, fd, len, fill)
    return who:syscall(sys.NR.read, {
        args = { fd, 0, len }, bufs = { string.rep(fill or "\0", len) }, ptrs = { 1 },
    })
end

--- Every event waiting for `fd`, oldest first, reading only while poll
--- says one waits — so a blocking file is drained without blocking.
--- Returns the events, or nil, errno when a read failed.
function M.drain(who, fd)
    local out = {}
    while ntfe.poll(who, fd, ntfe.POLLIN, 0) & ntfe.POLLIN ~= 0 do
        local batch, errno = ntfe.read_events(who, fd)
        if not batch then return nil, errno end
        if #batch == 0 then break end
        for _, e in ipairs(batch) do out[#out + 1] = e end
    end
    return out
end

--- A UDP sender connected to a bound receiver on loopback, port `port`.
--- Returns the sender fd and the receiver fd.
function M.udp_pair(who, port)
    local rx = assert(ntfe.udp_bind(who, "127.0.0.1", port))
    local tx = assert(ntfe.udp_connect(who, "127.0.0.1", port))
    return tx, rx
end

--- `n` empty datagrams on a connected UDP socket in one round trip
--- (sendto with no buffer: integer arguments only, which is what a
--- batch carries). Each is judged at four seats on loopback.
function M.burst(vm, tx, n)
    local res = vm:batch(function(b)
        for _ = 1, n do b:syscall(ntfe.NR.sendto, tx, 0, 0, 0, 0, 0) end
    end)
    return #res
end

-- An IEEE "local experimental" ethertype: no protocol handler claims it.
M.ETH_EXPERIMENTAL = 0x88B5

--- One Ethernet frame sent through loopback by AF_PACKET: out of the
--- egress seat and back in at the ingress seat, never near an IP seat
--- unless it says IP. `ethertype` defaults to ETH_EXPERIMENTAL; the
--- payload to 46 zero bytes. Returns the raw send result.
function M.lo_frame(who, ethertype, payload)
    ethertype = ethertype or M.ETH_EXPERIMENTAL
    local fd = assert(ntfe.packet_socket(who, "lo", ethertype))
    local zero = string.rep("\0", 6)
    local r = ntfe.send_frame(who, fd, ntfe.eth(zero, zero, ethertype)
        .. (payload or string.rep("\0", 46)))
    sys.close(who, fd)
    return r
end

--- A frame that says IPv4 and is not (version 0): a parse error at both
--- device seats.
function M.garbage_ipv4(who)
    return M.lo_frame(who, ntfe.ETH_P.IP, string.rep("\0", 30))
end

--- The status as raw bytes from a buffer of `size` bytes prefilled with
--- `fill`, with the request number `req` (default the published one).
function M.status_raw(who, fd, size, fill, req)
    return who:syscall(sys.NR.ioctl, {
        args = { fd, req or ntfe.IOC.STATUS, 0 },
        bufs = { string.rep(fill or "\0", size) }, ptrs = { 2 },
    })
end

--- One dump ioctl with a record buffer of `buf_len` bytes, the query in
--- a buffer of `query_size` bytes (default 24) prefilled after the first
--- 24 with `fill`. Returns the raw result; `count` and `total` decoded.
function M.dump_raw(who, fd, req, buf_len, o)
    o = o or {}
    local qsize = o.query_size or 24
    local query = string.pack("<I8I4I4I4I4", 0, buf_len, 0, 0, 0)
        .. string.rep(o.fill or "\0", qsize - 24)
    local r = who:syscall(sys.NR.ioctl, {
        args = { fd, req, 0 },
        bufs = { query, string.rep(o.rec_fill or "\0", math.max(buf_len, 1)) },
        ptrs = { 2 },
        nested = { { parent = 1, child = 2, offset = 0 } },
    })
    if r.ret == 0 then
        r.count, r.total = string.unpack("<I4I4", r.out_bufs[1], 13)
    end
    return r
end

--- Events of `list` for which `pred` holds.
function M.where(list, pred)
    local out = {}
    for _, e in ipairs(list) do
        if pred(e) then out[#out + 1] = e end
    end
    return out
end

return M
