-- Reading the KMES event ring, for the cases whose subject is an audit
-- record.
--
-- stratafs's audit events are emitted through KACS's kernel-only
-- emitter into a KMES ring, and never reach the filesystem interface
-- the rest of these tests drive. `revstrm` reads them on a real system;
-- there is no userspace here, so this drives the syscall and the shared
-- mapping directly.
--
-- Every number is from PKM §2.A, generated from `uapi/pkm/kmes.h`.

local sys = require("helpers.sys")

local M = {}

M.SYS = { EMIT = 1090, ATTACH = 1091, EMIT_BATCH = 1092 }

-- The privilege bits the three syscalls check (PKM §2.B): the emit
-- gate, the attach gate, and the rate-limit exemption.
M.PRIV = { AUDIT = 1 << 21, SECURITY = 1 << 8, TCB = 1 << 7 }

-- The compiled-in configuration defaults (PKM §2.A). The kernel-only
-- profile has no registry source, so these are always the live values
-- — which is itself the §2.6 bootstrap contract.
M.DEFAULT = {
    BUFFER_CAPACITY = 4194304,
    MAX_EVENT_SIZE = 65536,
    MAX_NESTING_DEPTH = 32,
    MAX_EMIT_RATE = 10000,
}

M.BATCH_MAX_ENTRIES = 256
M.HEADER_BASE = 77

--- Ask for the slot count rather than probing upwards: slots are
--- indexed by logical CPU id, so counting until EINVAL stops at the
--- first hole and misses every ring above it.
M.ATTACH_QUERY_SLOTS = 0xFFFFFFFF

M.ORIGIN = { USERSPACE = 0, KMES = 1, KACS = 2, LCS = 3 }

-- The mapping: producer page, consumer page, then the data mapped twice
-- back to back so an event that wraps is still contiguous.
local METADATA_TOTAL = 8192
local DATA_OFFSET = 8192

-- Producer metadata field offsets, 1-based for string.unpack.
local P = { magic = 1, version = 9, cpu_id = 13, capacity = 17,
            data_offset = 25, generation = 33, write_pos = 65, tail_pos = 73 }

-- On-wire event header, 77 bytes, 1-based.
local E = { size = 1, header_size = 5, timestamp = 9, sequence = 17,
            cpu_id = 25, origin_class = 27, effective_token = 28,
            true_token = 44, process_guid = 60, type_len = 76 }
local HEADER_BASE = 77
local GUID_SIZE = 16
local NULL_GUID = string.rep("\0", GUID_SIZE)

--- Just enough msgpack for the payloads KACS emits: fixmap, the three
--- string encodings, int32 and the small scalars. Anything else raises,
--- which is the right outcome — a payload shape this cannot read is a
--- payload the test has no business guessing at.
local function unpack_value(b, at)
    local tag = b:byte(at)
    if not tag then error("msgpack: ran off the end") end
    if tag < 0x80 then return tag, at + 1 end                    -- positive fixint
    if tag >= 0xe0 then return tag - 0x100, at + 1 end           -- negative fixint
    if tag >= 0x80 and tag <= 0x8f then                          -- fixmap
        local n, out = tag - 0x80, {}
        at = at + 1
        for _ = 1, n do
            local k, v
            k, at = unpack_value(b, at)
            v, at = unpack_value(b, at)
            out[k] = v
        end
        return out, at
    end
    if tag >= 0xa0 and tag <= 0xbf then                          -- fixstr
        local n = tag - 0xa0
        return b:sub(at + 1, at + n), at + 1 + n
    end
    if tag == 0xc0 then return nil, at + 1 end                   -- nil
    if tag == 0xc2 then return false, at + 1 end
    if tag == 0xc3 then return true, at + 1 end
    if tag == 0xd9 then                                          -- str8
        local n = b:byte(at + 1)
        return b:sub(at + 2, at + 1 + n), at + 2 + n
    end
    if tag == 0xda then                                          -- str16
        local n = string.unpack(">I2", b, at + 1)
        return b:sub(at + 3, at + 2 + n), at + 3 + n
    end
    if tag == 0xcc then return string.unpack(">I1", b, at + 1), at + 2 end
    if tag == 0xcd then return string.unpack(">I2", b, at + 1), at + 3 end
    if tag == 0xce then return string.unpack(">I4", b, at + 1), at + 5 end
    if tag == 0xcf then return string.unpack(">I8", b, at + 1), at + 9 end
    if tag == 0xd0 then return string.unpack("<i1", b, at + 1), at + 2 end
    if tag == 0xd1 then return string.unpack(">i2", b, at + 1), at + 3 end
    if tag == 0xd2 then return string.unpack(">i4", b, at + 1), at + 5 end
    if tag == 0xd3 then return string.unpack(">i8", b, at + 1), at + 9 end
    error(string.format("msgpack: unhandled tag 0x%02x at %d", tag, at))
end

--- A minimal msgpack map payload, for the many cases whose subject is
--- not the payload: {"k": 1}.
M.PAYLOAD = "\x81\xa1k\x01"

--- A msgpack value nested exactly `depth` containers deep: arrays of
--- one element ending in an empty array. Depth counts from 1 at the
--- top-level value (§2.2), so nested(1) is the bare empty array.
function M.nested(depth)
    return string.rep("\x91", depth - 1) .. "\x90"
end

--- kmes_emit. `opts` overrides the declared lengths (for the cases
--- about arithmetic on lengths) or replaces a pointer with a raw
--- address (for the EFAULT cases).
function M.emit(who, event_type, payload, opts)
    opts = opts or {}
    local args = { opts.type_ptr or 0, opts.type_len or #event_type,
                   opts.payload_ptr or 0,
                   opts.payload_len or (payload and #payload or 0) }
    local bufs, ptrs = {}, {}
    if not opts.type_ptr then
        bufs[#bufs + 1] = event_type
        ptrs[#ptrs + 1] = 0
    end
    if payload and #payload > 0 and not opts.payload_ptr then
        bufs[#bufs + 1] = payload
        ptrs[#ptrs + 1] = 2
    end
    return who:syscall(M.SYS.EMIT, { args = args, bufs = bufs, ptrs = ptrs })
end

--- kmes_emit_batch. `entries` is a list of `{type=, payload=}`, each
--- optionally overriding `type_len`, `payload_len`, `pad0`, `pad1`.
--- `opts.count` overrides the count argument;
--- `opts.emitted_ptr` replaces the emitted_out pointer with a raw
--- address. Returns the syscall result with `r.emitted` decoded.
function M.emit_batch(who, entries, opts)
    opts = opts or {}
    local desc, bufs, nested = {}, { "", string.rep("\0", 4) }, {}
    -- Identical strings share one buffer: the wire protocol indexes
    -- buffers with a byte, and a 256-entry batch of distinct buffers
    -- would overflow it.
    local interned = {}
    local function buf_index(s)
        if not interned[s] then
            bufs[#bufs + 1] = s
            interned[s] = #bufs
        end
        return interned[s]
    end
    for i, e in ipairs(entries) do
        local base = (i - 1) * 32
        desc[i] = string.pack("<I8I2c6I8I4c4",
            0, e.type_len or #e.type,
            e.pad0 or string.rep("\0", 6),
            0, e.payload_len or (e.payload and #e.payload or 0),
            e.pad1 or string.rep("\0", 4))
        nested[#nested + 1] = { parent = 1, child = buf_index(e.type),
                                offset = base }
        if e.payload and #e.payload > 0 then
            nested[#nested + 1] = { parent = 1, child = buf_index(e.payload),
                                    offset = base + 16 }
        end
    end
    bufs[1] = table.concat(desc)
    local args = { 0, opts.count or #entries, opts.emitted_ptr or 0 }
    local ptrs = opts.emitted_ptr and { 0 } or { 0, 2 }
    local r = who:syscall(M.SYS.EMIT_BATCH,
        { args = args, bufs = bufs, ptrs = ptrs, nested = nested })
    if r.out_bufs and r.out_bufs[2] then
        r.emitted = string.unpack("<I4", r.out_bufs[2])
    end
    return r
end

--- Write guest memory: read() from a pipe deposits bytes at any
--- address in the target process — there is no write_mem primitive.
function M.poke(who, addr, bytes)
    local p = who:syscall(sys.NR.pipe2, {
        args = { 0, 0 }, bufs = { string.rep("\0", 8) }, ptrs = { 0 },
    })
    assert(p.ret == 0, "pipe2: " .. sys.errname(p.errno))
    local rd, wr = string.unpack("<i4i4", p.out_bufs[1])
    local w = who:syscall(sys.NR.write, {
        args = { wr, 0, #bytes }, bufs = { bytes }, ptrs = { 1 },
    })
    assert(w.ret == #bytes, "pipe fill")
    local r = who:syscall(sys.NR.read, rd, addr, #bytes)
    sys.close(who, rd); sys.close(who, wr)
    return r.ret == #bytes
end

--- Read guest memory through the same pipe trick — works in a
--- worker, which has no read_mem.
function M.peek(who, addr, len)
    local p = who:syscall(sys.NR.pipe2, {
        args = { 0, 0 }, bufs = { string.rep("\0", 8) }, ptrs = { 0 },
    })
    assert(p.ret == 0, "pipe2: " .. sys.errname(p.errno))
    local rd, wr = string.unpack("<i4i4", p.out_bufs[1])
    assert(who:syscall(sys.NR.write, wr, addr, len).ret == len, "pipe fill")
    local r = who:syscall(sys.NR.read, {
        args = { rd, 0, len }, bufs = { string.rep("\0", len) }, ptrs = { 1 },
    })
    sys.close(who, rd); sys.close(who, wr)
    return r.out_bufs[1]
end

local IOC_ADJUST_PRIVS = 0x40184B01
local ATTR_ENABLED = 0x2

--- Enable or disable one privilege on the caller's own token, in
--- place. The §2.4 gates require "held, enabled" — this is how a test
--- makes the held-but-disabled caller.
function M.adjust_priv(who, kacs_helper, bit_value, enable)
    local luid = math.floor(math.log(bit_value, 2) + 0.5)
    local token = who:syscall(kacs_helper.SYS.OPEN_SELF_TOKEN, 0,
        kacs_helper.TOKEN_ALL_ACCESS)
    if token.ret < 0 then return nil, token.errno end
    local r = who:syscall(sys.NR.ioctl, {
        args = { token.ret, IOC_ADJUST_PRIVS, 0 },
        bufs = {
            string.pack("<I4I4I8I8", 1, 0, 0, 0),
            string.pack("<I4I4", luid, enable and ATTR_ENABLED or 0),
        },
        ptrs = { 2 },
        nested = { { parent = 1, child = 2, offset = 8 } },
    })
    sys.close(who, token.ret)
    if r.ret ~= 0 then return nil, r.errno end
    return true
end

--- Attach to a CPU's ring and map it.
---
--- The cursor starts at the current write position, so a reader sees
--- only what happens after it attached — which is what a test wants.
--- Returns the ring, or `nil, errno`.
function M.attach(vm, cpu)
    local r = vm:syscall(M.SYS.ATTACH, {
        args = { cpu or 0, 0 },
        bufs = { string.rep("\0", 8) },
        ptrs = { 1 },
    })
    if r.ret < 0 then return nil, r.errno end
    local capacity = string.unpack("<I8", r.out_bufs[1])
    local length = METADATA_TOTAL + 2 * capacity
    local addr, errno = sys.mmap(vm, r.ret, length,
        sys.PROT.READ | sys.PROT.WRITE, sys.MAP.SHARED)
    if not addr then
        sys.close(vm, r.ret)
        return nil, errno
    end
    local ring = { vm = vm, fd = r.ret, addr = addr,
                   capacity = capacity, length = length }
    local head = vm:read_mem(addr, 256)
    ring.magic = head:sub(P.magic, P.magic + 7)
    ring.version = string.unpack("<I4", head, P.version)
    ring.cursor = string.unpack("<I8", head, P.write_pos)
    return ring
end

--- The producer's current write and tail positions.
function M.positions(ring)
    local head = ring.vm:read_mem(ring.addr, 256)
    return string.unpack("<I8", head, P.write_pos),
           string.unpack("<I8", head, P.tail_pos)
end

--- Every event written since the last drain, oldest first.
---
--- Each is `{type, payload, sequence, timestamp, origin, cpu,
--- effective_token, true_token, process_guid}`, with the payload
--- decoded from msgpack.
function M.drain(ring)
    local write_pos, tail_pos = M.positions(ring)
    local from = math.max(ring.cursor, tail_pos)
    ring.cursor = write_pos
    if write_pos <= from then return {} end

    local bytes = ring.vm:read_mem(
        ring.addr + DATA_OFFSET + (from % ring.capacity), write_pos - from)
    if not bytes then return {} end

    local out, at = {}, 1
    while at + HEADER_BASE <= #bytes + 1 do
        local size = string.unpack("<I4", bytes, at + E.size - 1)
        if size == 0 or at + size - 1 > #bytes then break end
        local header_size = string.unpack("<I4", bytes, at + E.header_size - 1)
        local type_len = string.unpack("<I2", bytes, at + E.type_len - 1)
        local event = {
            size = size,
            timestamp = string.unpack("<I8", bytes, at + E.timestamp - 1),
            sequence = string.unpack("<I8", bytes, at + E.sequence - 1),
            cpu = string.unpack("<I2", bytes, at + E.cpu_id - 1),
            origin = string.unpack("<I1", bytes, at + E.origin_class - 1),
            effective_token = bytes:sub(at + E.effective_token - 1,
                at + E.effective_token - 2 + GUID_SIZE),
            true_token = bytes:sub(at + E.true_token - 1,
                at + E.true_token - 2 + GUID_SIZE),
            process_guid = bytes:sub(at + E.process_guid - 1,
                at + E.process_guid - 2 + GUID_SIZE),
            type = bytes:sub(at + HEADER_BASE, at + HEADER_BASE + type_len - 1),
            header_size = header_size,
            raw = bytes:sub(at, at + size - 1),
        }
        -- header_size locates the payload; a future revision may grow
        -- the header, so this must not count from the type string's end.
        local payload_at = at + header_size
        if payload_at <= at + size - 1 then
            local ok, value = pcall(unpack_value,
                bytes:sub(payload_at, at + size - 1), 1)
            event.payload = ok and value or nil
            event.payload_error = (not ok) and value or nil
        end
        out[#out + 1] = event
        at = at + size
    end
    return out
end

--- Every event of one type from a drain.
function M.of_type(events, event_type)
    local out = {}
    for _, e in ipairs(events) do
        if e.type == event_type then out[#out + 1] = e end
    end
    return out
end

--- Release a ring.
function M.detach(ring)
    sys.munmap(ring.vm, ring.addr, ring.length)
    sys.close(ring.vm, ring.fd)
end

M.NULL_GUID = NULL_GUID

--- Run `fn` with a ring attached, and return what it emitted.
---
--- Attaching first and draining after is the shape every audit case
--- wants: the ring is a stream, and a test cares about the window its
--- own operation occupied.
function M.recording(t, vm, fn)
    local ring, errno = M.attach(vm, 0)
    t:assert(ring, "a KMES ring attaches: " .. sys.errname(errno or 0))
    t:assert_eq(ring.magic, "KMESRING", "and carries the ring magic")
    local ok, err = pcall(fn)
    local events = M.drain(ring)
    M.detach(ring)
    if not ok then error(err, 0) end
    return events
end

return M
