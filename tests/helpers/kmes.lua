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
