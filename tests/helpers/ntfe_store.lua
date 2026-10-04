-- The three stores of PKM §6.6, from the outside: flow tags in table
-- order, counter cells with the hash the store files them under, and
-- the `network-report` events NTFE writes into KMES.
--
-- helpers/ntfe decodes the dumps for the common case; what is here is
-- what only the store tests need: the tag slots in the order the table
-- holds them, Linux's jhash (to say which of the 1024 buckets a cell is
-- in), a msgpack reader that knows map16 (the report payload's header),
-- a KMES reader over every CPU's ring, and senders that put many
-- datagrams on the wire in one syscall.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local kmes = require("helpers.kmes")

local M = {}

-- ---- the flows dump, keeping the tag order ---------------------------

--- Every flow's tags as an ordered list of `{ hash, value }`, in the
--- order the flow's table holds them (the dump walks the table by
--- index and skips cleared slots). Returns a list of `{ id, src_port,
--- dst_port, protocol, n_tags, tags }`.
function M.flow_tag_order(vm, dev)
    local capacity = 256
    local size = capacity * ntfe.FLOW_REC_SIZE
    local r = vm:syscall(sys.NR.ioctl, {
        args = { dev, ntfe.IOC.FLOWS, 0 },
        bufs = { string.pack("<I8I4I4I4I4", 0, size, 0, 0, 0), string.rep("\0", size) },
        ptrs = { 2 },
        nested = { { parent = 1, child = 2, offset = 0 } },
    })
    assert(r.ret == 0, "flows dump: " .. sys.errname(r.errno))
    local count = string.unpack("<I4", r.out_bufs[1], 13)
    local buf, out = r.out_bufs[2], {}
    for i = 0, count - 1 do
        local at = i * ntfe.FLOW_REC_SIZE + 1
        local f = { id = string.unpack("<I4", buf, at), protocol = buf:byte(at + 5) }
        f.src_port, f.dst_port = string.unpack("<I2I2", buf, at + 52)
        f.n_tags = buf:byte(at + 58)
        f.tags = {}
        for n = 0, math.min(f.n_tags, 8) - 1 do
            f.tags[#f.tags + 1] = {
                hash = string.unpack("<I8", buf, at + 160 + n * 8),
                value = string.unpack("<I8", buf, at + 224 + n * 8),
            }
        end
        out[#out + 1] = f
    end
    return out
end

-- ---- counter cells -----------------------------------------------------

--- The cells of a counters dump belonging to stream `name` with
--- key-spec `keyspec` (nil: any).
function M.cells(list, name, keyspec)
    local out = {}
    for _, c in ipairs(list) do
        if c.name == name and (keyspec == nil or c.keyspec == keyspec) then
            out[#out + 1] = c
        end
    end
    return out
end

--- The cell of `cells` whose source address is `src` (dotted v4).
function M.cell_from(cells, src)
    for _, c in ipairs(cells) do
        if c.src == src then return c end
    end
end

local function rol32(x, k)
    return ((x << k) | (x >> (32 - k))) & 0xFFFFFFFF
end

--- Linux's `jhash(key, #key, initval)` (include/linux/jhash.h, lookup3),
--- little-endian words.
function M.jhash(key, initval)
    local length = #key
    local a = (0xdeadbeef + length + initval) & 0xFFFFFFFF
    local b, c = a, a
    local k = 1
    local function mix()
        a = (a - c) & 0xFFFFFFFF; a = a ~ rol32(c, 4);  c = (c + b) & 0xFFFFFFFF
        b = (b - a) & 0xFFFFFFFF; b = b ~ rol32(a, 6);  a = (a + c) & 0xFFFFFFFF
        c = (c - b) & 0xFFFFFFFF; c = c ~ rol32(b, 8);  b = (b + a) & 0xFFFFFFFF
        a = (a - c) & 0xFFFFFFFF; a = a ~ rol32(c, 16); c = (c + b) & 0xFFFFFFFF
        b = (b - a) & 0xFFFFFFFF; b = b ~ rol32(a, 19); a = (a + c) & 0xFFFFFFFF
        c = (c - b) & 0xFFFFFFFF; c = c ~ rol32(b, 4);  b = (b + a) & 0xFFFFFFFF
    end
    local function final()
        c = c ~ b; c = (c - rol32(b, 14)) & 0xFFFFFFFF
        a = a ~ c; a = (a - rol32(c, 11)) & 0xFFFFFFFF
        b = b ~ a; b = (b - rol32(a, 25)) & 0xFFFFFFFF
        c = c ~ b; c = (c - rol32(b, 16)) & 0xFFFFFFFF
        a = a ~ c; a = (a - rol32(c, 4)) & 0xFFFFFFFF
        b = b ~ a; b = (b - rol32(a, 14)) & 0xFFFFFFFF
        c = c ~ b; c = (c - rol32(b, 24)) & 0xFFFFFFFF
    end
    while length > 12 do
        local x, y, z = string.unpack("<I4I4I4", key, k)
        a = (a + x) & 0xFFFFFFFF; b = (b + y) & 0xFFFFFFFF; c = (c + z) & 0xFFFFFFFF
        mix()
        length = length - 12
        k = k + 12
    end
    if length == 0 then return c end
    local tail = key:sub(k) .. string.rep("\0", 12 - length)
    local x, y, z = string.unpack("<I4I4I4", tail)
    a = (a + x) & 0xFFFFFFFF; b = (b + y) & 0xFFFFFFFF; c = (c + z) & 0xFFFFFFFF
    final()
    return c
end

M.COUNTER_BUCKETS = 1024
M.COUNTER_JHASH_INIT = 0x504e5043

--- The bucket a dumped cell lives in: jhash over the store's 40-byte
--- cell key (family, pad, ifindex, source, destination).
function M.bucket_of(cell)
    local function addr(a)
        if a == nil then return string.rep("\0", 16) end
        return ntfe.ip4(a) .. string.rep("\0", 12)
    end
    local key = string.pack("<I1xxxi4", cell.family, cell.ifindex)
        .. addr(cell.src) .. addr(cell.dst)
    return M.jhash(key, M.COUNTER_JHASH_INIT) & (M.COUNTER_BUCKETS - 1)
end

-- ---- msgpack, with map16 ------------------------------------------------

local function unpack_value(b, at)
    local tag = b:byte(at)
    if not tag then error("msgpack: ran off the end") end
    if tag < 0x80 then return tag, at + 1 end
    if tag >= 0xe0 then return tag - 0x100, at + 1 end
    local function map(n, from)
        local out, keys = {}, {}
        for _ = 1, n do
            local k, v
            k, from = unpack_value(b, from)
            v, from = unpack_value(b, from)
            out[k] = v
            keys[#keys + 1] = k
        end
        return out, from, keys
    end
    if tag >= 0x80 and tag <= 0x8f then return map(tag - 0x80, at + 1) end
    if tag == 0xde then return map(string.unpack(">I2", b, at + 1), at + 3) end
    if tag >= 0xa0 and tag <= 0xbf then
        local n = tag - 0xa0
        return b:sub(at + 1, at + n), at + 1 + n
    end
    if tag == 0xd9 then
        local n = b:byte(at + 1)
        return b:sub(at + 2, at + 1 + n), at + 2 + n
    end
    if tag == 0xc0 then return nil, at + 1 end
    if tag == 0xcc then return string.unpack(">I1", b, at + 1), at + 2 end
    if tag == 0xcd then return string.unpack(">I2", b, at + 1), at + 3 end
    if tag == 0xce then return string.unpack(">I4", b, at + 1), at + 5 end
    if tag == 0xcf then return string.unpack(">I8", b, at + 1), at + 9 end
    error(string.format("msgpack: unhandled tag 0x%02x at %d", tag, at))
end

--- Decode a report's payload bytes: the map, the keys in wire order,
--- and the number of bytes the map occupied.
function M.decode_payload(bytes)
    local map, after, keys = unpack_value(bytes, 1)
    return map, keys, after - 1
end

-- ---- KMES, every CPU ---------------------------------------------------

M.ORIGIN_NTFE = 4
M.REPORT_TYPE = "network-report"

--- Attach to every CPU's ring. Returns a recorder: `rec:drain()` gives
--- every event since the last drain across all rings, each with its
--- raw payload bytes as `payload_bytes`.
function M.recorder(vm)
    local q = vm:syscall(kmes.SYS.ATTACH, {
        args = { kmes.ATTACH_QUERY_SLOTS, 0 },
        bufs = { string.rep("\0", 8) }, ptrs = { 1 },
    })
    assert(q.ret == 0, "KMES slot query: " .. sys.errname(q.errno))
    local slots = string.unpack("<I8", q.out_bufs[1])
    local rec = { rings = {} }
    for cpu = 0, slots - 1 do
        local ring = kmes.attach(vm, cpu)
        if ring then rec.rings[#rec.rings + 1] = ring end
    end
    assert(#rec.rings > 0, "no KMES ring attached")
    function rec:drain()
        local out = {}
        for _, ring in ipairs(self.rings) do
            for _, e in ipairs(kmes.drain(ring)) do
                e.payload_bytes = e.raw:sub(e.header_size + 1)
                out[#out + 1] = e
            end
        end
        table.sort(out, function(x, y) return x.timestamp < y.timestamp end)
        return out
    end
    return rec
end

--- The NTFE reports of a drain, payloads decoded (`report`, `keys`).
function M.reports(events)
    local out = {}
    for _, e in ipairs(events) do
        if e.type == M.REPORT_TYPE then
            local ok, map, keys = pcall(M.decode_payload, e.payload_bytes)
            e.report = ok and map or nil
            e.keys = ok and keys or nil
            out[#out + 1] = e
        end
    end
    return out
end

-- ---- hand-built IPv6 ---------------------------------------------------

--- An IPv6 header for `payload_len` bytes of `next_header`. Addresses
--- are text.
function M.ipv6(src, dst, next_header, payload_len, hop)
    return string.pack(">I4I2I1I1", 0x60000000, payload_len, next_header, hop or 64)
        .. ntfe.ip6(src) .. ntfe.ip6(dst)
end

--- A UDP datagram for IPv6, checksummed over the v6 pseudo-header.
function M.udp6(src, dst, sport, dport, data)
    local len = 8 + #data
    local pseudo = ntfe.ip6(src) .. ntfe.ip6(dst) .. string.pack(">I4I3I1", len, 0, 17)
    local function seg(csum)
        return string.pack(">I2I2I2I2", sport, dport, len, csum) .. data
    end
    local csum = ntfe.checksum(pseudo .. seg(0))
    if csum == 0 then csum = 0xFFFF end
    return seg(csum)
end

-- ---- many frames in one syscall ----------------------------------------

M.NR_SENDMMSG = 307
local MMSGHDR = 64 -- struct mmsghdr: msghdr (56) + msg_len, padded
local IOVEC = 16

--- An anonymous mapping in `who` big enough for `n` messages of up to
--- `frame_max` bytes, with their iovecs and mmsghdrs, so one sendmmsg(2)
--- can carry a thousand distinct frames: the syscall bridge can only
--- point a buffer at another buffer's start, never into it. Returns a
--- sender: `s:load(frames)` writes the frames into the mapping (through
--- a pipe, the only write path into a worker), `s:fire(fd)` starts a
--- sendmmsg of them without waiting, and `s:send(fd, frames)` does both
--- and waits.
function M.batch_sender(who, n, frame_max)
    local data_len = n * frame_max
    local total = data_len + n * IOVEC + n * MMSGHDR
    local m = who:syscall(sys.NR.mmap, 0, total, sys.PROT.READ | sys.PROT.WRITE,
        sys.MAP.PRIVATE | sys.MAP.ANONYMOUS, -1, 0)
    assert(m.ret > 0, "mmap: " .. sys.errname(m.errno))
    local s = { who = who, base = m.ret, n = n, frame_max = frame_max }
    s.iov_at = s.base + data_len
    s.msg_at = s.iov_at + n * IOVEC
    local p = who:syscall(sys.NR.pipe2, {
        args = { 0, 0 }, bufs = { string.rep("\0", 8) }, ptrs = { 0 },
    })
    assert(p.ret == 0, "pipe2: " .. sys.errname(p.errno))
    s.rd, s.wr = string.unpack("<i4i4", p.out_bufs[1])
    -- F_SETPIPE_SZ: one write per region, however large the batch.
    who:syscall(72, s.wr, 1031, 1 << 20)

    local function poke(addr, bytes)
        local at = 1
        while at <= #bytes do
            local chunk = bytes:sub(at, at + 65535)
            local w = who:syscall(sys.NR.write, {
                args = { s.wr, 0, #chunk }, bufs = { chunk }, ptrs = { 1 },
            })
            assert(w.ret == #chunk, "pipe fill: " .. sys.errname(w.errno))
            local r = who:syscall(sys.NR.read, s.rd, addr + at - 1, #chunk)
            assert(r.ret == #chunk, "pipe drain: " .. sys.errname(r.errno))
            at = at + #chunk
        end
    end

    --- Write `frames` into the mapping, ready for `fire`.
    function s:load(frames)
        assert(#frames <= self.n, "more frames than the sender was built for")
        local data, iov, msgs = {}, {}, {}
        for i, f in ipairs(frames) do
            assert(#f <= self.frame_max, "frame too long")
            data[i] = f .. string.rep("\0", self.frame_max - #f)
            iov[i] = string.pack("<I8I8", self.base + (i - 1) * self.frame_max, #f)
            msgs[i] = string.pack("<I8I4I4I8I8I8I8I4I4I4I4", 0, 0, 0,
                self.iov_at + (i - 1) * IOVEC, 1, 0, 0, 0, 0, 0, 0)
        end
        poke(self.base, table.concat(data))
        poke(self.iov_at, table.concat(iov))
        poke(self.msg_at, table.concat(msgs))
        self.loaded = #frames
    end

    --- sendmmsg(2) the loaded frames on `fd` without waiting: returns
    --- the pending syscall (`:await()` gives the result).
    function s:fire(fd)
        return self.who:syscall_async(M.NR_SENDMMSG, fd, self.msg_at, self.loaded, 0)
    end

    --- Load `frames` and send them all in one sendmmsg(2). Returns the
    --- number the kernel took, and the errno.
    function s:send(fd, frames)
        self:load(frames)
        local r = self.who:syscall(M.NR_SENDMMSG, fd, self.msg_at, #frames, 0)
        return r.ret, r.errno
    end

    return s
end

--- An Ethernet frame carrying a UDP datagram from `src` to `dst` (v4).
function M.udp_frame(net, src, dst, sport, dport, data)
    data = data or "x"
    local udp = ntfe.udp(src, dst, sport, dport, data)
    return ntfe.eth(net.mac, net.peer_mac, ntfe.ETH_P.IP)
        .. ntfe.ipv4(src, dst, ntfe.IPPROTO.UDP, #udp) .. udp
end

return M
