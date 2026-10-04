-- eventd TRM §3.2 "Synthetic Event Payloads"
-- (3--event-storage/2--synthetic-event-payloads.md): the MessagePack map
-- each of the five synthetic event types carries, field by field.
--
-- One VM with two vCPUs: `resume_points` and `last_sequences` hold one
-- entry per logical CPU in cpu_id order, and on one vCPU that order is a
-- list of one. Its eventd is restarted and stopped as the cases need —
-- each synthetic type is produced by the event that causes it:
--
--   * synthetic.startup: the boot's first start, then every restart;
--   * synthetic.shutdown: every stop;
--   * synthetic.config_change: a live `reg set` / `reg del`;
--   * synthetic.gap: KMES events emitted while eventd is stopped, enough
--     to overrun the 4 MiB ring, so the next start finds sequences gone;
--   * synthetic.storage_error: a shard and the log store overwritten with
--     garbage while eventd is stopped, so the next start quarantines them.
--
-- Payloads are read as stored — the blob out of shard-0000.db (eventd
-- commits every synthetic record to shard 0) decoded here — because a
-- query does not show a nil field, a nested array's inner shape, or a
-- payload key that collides with a header column. The cases run in file
-- order; the storage_error case overwrites shard-0000 and comes last but
-- one, and the all-five-types case reads what the others left.
--
-- Between a stop and a start the shard is copied to the host and edited
-- with the host's sqlite3 (`rewrite`), which is how a shutdown payload is
-- falsified and a gap record with mismatched cpu_id is planted.

local eventd = require("helpers.eventd")
local peinit = require("helpers.peinit")
local kmes = require("helpers.kmes")
peinit.claim(1, { cpus = 2 }) -- one VM, two vCPUs

-- Two vCPUs: the per-CPU arrays are the subject (see above).
local vm = eventd.boot({ name = "ev-payload", cpus = 2 })

local SHARD0 = eventd.STORE.events .. "/shard-0000.db"

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

local function unhex(h)
    return (h:gsub("%x%x", function(b) return string.char(tonumber(b, 16)) end))
end

local NIL = setmetatable({}, { __tostring = function() return "nil" end })

--- Decode one MessagePack value (the whole of what eventd writes). Maps
--- come back as {map = {k = v}, keys = {k1, k2, ...}} so key order and
--- duplicates are visible; arrays as {array = {...}}; nil as NIL.
local function decode(b)
    local at = 1
    local value
    local function n(fmt, len)
        local v = string.unpack(fmt, b, at)
        at = at + len
        return v
    end
    local function str(len)
        local s = b:sub(at, at + len - 1)
        at = at + len
        return s
    end
    value = function()
        local tag = b:byte(at)
        assert(tag, "msgpack: ran off the end")
        at = at + 1
        if tag < 0x80 then return tag end
        if tag >= 0xe0 then return tag - 0x100 end
        local count
        if tag >= 0x80 and tag <= 0x8f then count = tag - 0x80
        elseif tag == 0xde then count = n(">I2", 2)
        elseif tag == 0xdf then count = n(">I4", 4) end
        if count then
            local m = { map = {}, keys = {} }
            for _ = 1, count do
                local k = value()
                local v = value()
                m.keys[#m.keys + 1] = k
                m.map[k] = v
            end
            return m
        end
        if tag >= 0x90 and tag <= 0x9f then count = tag - 0x90
        elseif tag == 0xdc then count = n(">I2", 2)
        elseif tag == 0xdd then count = n(">I4", 4) end
        if count then
            local a = { array = {} }
            for i = 1, count do a.array[i] = value() end
            return a
        end
        if tag >= 0xa0 and tag <= 0xbf then return str(tag - 0xa0) end
        if tag == 0xd9 then return str(n(">I1", 1)) end
        if tag == 0xda then return str(n(">I2", 2)) end
        if tag == 0xdb then return str(n(">I4", 4)) end
        if tag == 0xc4 then return { bin = str(n(">I1", 1)) } end
        if tag == 0xc5 then return { bin = str(n(">I2", 2)) } end
        if tag == 0xc0 then return NIL end
        if tag == 0xc2 then return false end
        if tag == 0xc3 then return true end
        if tag == 0xcc then return n(">I1", 1) end
        if tag == 0xcd then return n(">I2", 2) end
        if tag == 0xce then return n(">I4", 4) end
        if tag == 0xcf then return n(">I8", 8) end
        if tag == 0xd0 then return n(">i1", 1) end
        if tag == 0xd1 then return n(">i2", 2) end
        if tag == 0xd2 then return n(">i4", 4) end
        if tag == 0xd3 then return n(">i8", 8) end
        error(string.format("msgpack: unhandled tag 0x%02x", tag))
    end
    local v = value()
    assert(at == #b + 1, "msgpack: trailing bytes")
    return v
end

--- The newest stored record of a synthetic type in any shard (a gap goes
--- to the shard its CPU writes to; the rest to shard 0): {payload =
--- decoded, cpu_id = column, id = rowid, db = shard path}.
local function newest(event_type)
    local best
    for _, db in ipairs(eventd.shards(vm)) do
        local rows = eventd.sql(vm, db, "SELECT id, hex(payload), cpu_id, timestamp FROM events WHERE event_type = '" ..
            event_type .. "' ORDER BY timestamp DESC, id DESC LIMIT 1")
        if rows[1] and (not best or rows[1][4] > best.timestamp) then
            best = { id = rows[1][1], payload = decode(unhex(rows[1][2])), cpu_id = rows[1][3],
                     timestamp = rows[1][4], db = db }
        end
    end
    assert(best, "a stored " .. event_type .. " record")
    return best
end

local function count_of(event_type)
    local n = 0
    for _, db in ipairs(eventd.shards(vm)) do
        n = n + eventd.sql(vm, db, "SELECT count(*) FROM events WHERE event_type = '" .. event_type .. "'")[1][1]
    end
    return n
end

local function sorted_keys(m)
    local ks = {}
    for _, k in ipairs(m.keys) do ks[#ks + 1] = k end
    table.sort(ks)
    return table.concat(ks, ",")
end

local function boot_canonical()
    return vm:run("cat /proc/sys/kernel/random/boot_id").stdout:gsub("%s", "")
end

--- PCDS binary layout of the boot ID, uppercase hex (sqlite's hex()).
local function boot_pcds_hex()
    local c = boot_canonical():gsub("-", "")
    local function rev(h)
        local out = {}
        for i = #h - 1, 1, -2 do out[#out + 1] = h:sub(i, i + 1) end
        return table.concat(out)
    end
    return (rev(c:sub(1, 8)) .. rev(c:sub(9, 12)) .. rev(c:sub(13, 16)) .. c:sub(17)):upper()
end

--- Highest sequence contiguously covered from 1 by this boot's receipts
--- for `cpu`, across every shard file present.
local function highest_contiguous(cpu)
    local ranges = {}
    for _, s in ipairs(eventd.shards(vm)) do
        for _, r in ipairs(eventd.sql(vm, s, "SELECT first_sequence, last_sequence FROM receipt_ranges " ..
            "WHERE hex(boot_id) = '" .. boot_pcds_hex() .. "' AND cpu_id = " .. cpu)) do
            ranges[#ranges + 1] = r
        end
    end
    table.sort(ranges, function(a, b) return a[1] < b[1] end)
    local high = 0
    for _, r in ipairs(ranges) do
        if r[1] > high + 1 then break end
        if r[2] > high then high = r[2] end
    end
    return high
end

local function host_tmpdir()
    local p = assert(io.popen("mktemp -d", "r"))
    local dir = p:read("l")
    p:close()
    return dir
end

local function host_write(path, bytes)
    local f = assert(io.open(path, "wb"))
    f:write(bytes)
    f:close()
end

--- Copy guest database `src` to the host, run `script` against it there,
--- and write it back. eventd must be stopped (it has then checkpointed and
--- removed the WAL, so the main file is the whole database).
local function rewrite(src, script)
    local dir = host_tmpdir()
    host_write(dir .. "/db", vm:read_file(src))
    host_write(dir .. "/q.sql", script)
    host_write(dir .. "/run.py", [[
import sqlite3, sys
d = sys.argv[1]
c = sqlite3.connect(d + "/db")
c.executescript(open(d + "/q.sql").read())
c.commit()
c.close()
]])
    local p = assert(io.popen("python3 " .. dir .. "/run.py " .. dir .. " 2>&1", "r"))
    local out = p:read("a")
    local ok = p:close()
    local f = assert(io.open(dir .. "/db", "rb"))
    local bytes = f:read("a")
    f:close()
    os.execute("rm -rf '" .. dir .. "'")
    assert(ok, "host sqlite rewrite failed: " .. out)
    vm:write_file(src, bytes)
end

local function hex(s)
    return (s:gsub(".", function(ch) return string.format("%02X", ch:byte()) end))
end

local function stop()
    vm:run("svctl stop eventd"):assert_ok()
    wait_until(function() return eventd.pid(vm) == nil end,
        { timeout = 30, interval = 0.25, desc = "eventd to stop" })
end

local function start()
    vm:run("svctl start eventd")
    eventd.ready(vm)
end

--- Wait for the config_change record about `key` committed after `after_id`.
local function config_change_after(key, after_id)
    local rec
    wait_until(function()
        local rows = eventd.sql(vm, SHARD0, "SELECT id, hex(payload) FROM events WHERE event_type = '" ..
            eventd.T.config_change .. "' AND id > " .. after_id .. " ORDER BY id")
        for _, r in ipairs(rows) do
            local p = decode(unhex(r[2]))
            if p.map.key == key then rec = { id = r[1], payload = p } return true end
        end
        return false
    end, { timeout = 30, interval = 0.25, desc = "a config_change record for " .. key })
    return rec
end

local function max_id()
    return eventd.sql(vm, SHARD0, "SELECT COALESCE(max(id), 0) FROM events")[1][1]
end

-- ---------------------------------------------------------------------------
-- synthetic.startup
-- ---------------------------------------------------------------------------

test("synthetic.startup carries boot_id, restart, shard_count and resume_points", {
    spec = "eventd *payload.the-synthetic-startup-payload-schema",
}, function(t)
    local s = newest(eventd.T.startup)
    t:assert(s.payload.map, "the payload is a map")
    t:assert_eq(sorted_keys(s.payload), "boot_id,restart,resume_points,shard_count", "exactly the four fields")
    t:assert_eq(type(s.payload.map.boot_id), "string", "boot_id is a string")
    t:assert_eq(type(s.payload.map.restart), "boolean", "restart is a bool")
    t:assert(math.type(s.payload.map.shard_count) == "integer" and s.payload.map.shard_count >= 0,
        "shard_count is an unsigned integer")
    t:assert(s.payload.map.resume_points.array, "resume_points is an array")
end)

test("startup boot_id is the current boot in PCDS canonical (braced, lowercase) form", {
    spec = "eventd *payload.startup-boot-id-is-the-current-boot-in-canonical-guid-form",
    tags = { "known-bug" },
}, function(t)
    -- PEI-TBD-startup-boot-id-unbraced: BootId::canonical (boot_id.rs:40-60)
    -- formats the 8-4-4-4-12 digits with no braces, but PCDS's canonical
    -- GUID string is the 38-character braced form (PCDS GUID string
    -- format) — the form eventd itself uses when it renders the boot_id
    -- column.
    local s = newest(eventd.T.startup)
    t:assert_eq(s.payload.map.boot_id, "{" .. boot_canonical():lower() .. "}",
        "the kernel boot ID, braced and lowercase")
end)

test("startup resume_points: one {cpu_id, sequence} per CPU in cpu_id order, the highest contiguously accounted sequence", {
    spec = "eventd *payload.startup-resume-points-give-each-cpus-highest-contiguous-sequence-in-cpu-order",
}, function(t)
    -- Bracket the value: at least what the receipts held while eventd was
    -- down, at most what they hold once it has started.
    stop()
    local before = { [0] = highest_contiguous(0), [1] = highest_contiguous(1) }
    start()
    local after = { [0] = highest_contiguous(0), [1] = highest_contiguous(1) }
    local rp = newest(eventd.T.startup).payload.map.resume_points.array
    t:assert_eq(#rp, 2, "one entry per logical CPU")
    for i, e in ipairs(rp) do
        t:assert_eq(sorted_keys(e), "cpu_id,sequence", "each entry is {cpu_id, sequence}")
        t:assert_eq(e.map.cpu_id, i - 1, "ordered by cpu_id ascending")
        local c = e.map.cpu_id
        t:assert(e.map.sequence >= before[c] and e.map.sequence <= after[c],
            "cpu " .. c .. ": " .. before[c] .. " <= " .. e.map.sequence .. " <= " .. after[c])
    end
end)

test("startup restart is false on the boot's first start and true once the boot has committed rows", {
    spec = "eventd *payload.startup-restart-is-true-when-the-boot-already-had-committed-rows-or-receipts",
}, function(t)
    local rows = eventd.sql(vm, SHARD0, "SELECT hex(payload) FROM events WHERE event_type = '" ..
        eventd.T.startup .. "' AND hex(boot_id) = '" .. boot_pcds_hex() .. "' ORDER BY id")
    t:assert(#rows >= 2, "the boot's first start and the restart above: " .. #rows)
    t:assert_eq(decode(unhex(rows[1][1])).map.restart, false, "the first start of the boot: false")
    for i = 2, #rows do
        t:assert_eq(decode(unhex(rows[i][1])).map.restart, true, "every later start: true")
    end
end)

test("startup shard_count is the active shard count after StorageShards is resolved", {
    spec = "eventd *payload.startup-shard-count-is-the-resolved-active-shard-count",
}, function(t)
    t:assert_eq(newest(eventd.T.startup).payload.map.shard_count, 2,
        "StorageShards 0 resolves to the two attached buffers")
    eventd.set(vm, "StorageShards", "dword:3"):assert_ok()
    eventd.restart(vm)
    local three = newest(eventd.T.startup).payload.map.shard_count
    eventd.unset(vm, "StorageShards")
    eventd.restart(vm)
    t:assert_eq(three, 3, "StorageShards 3: three")
    t:assert_eq(newest(eventd.T.startup).payload.map.shard_count, 2, "and back to two")
end)

-- ---------------------------------------------------------------------------
-- synthetic.config_change
-- ---------------------------------------------------------------------------

test("synthetic.config_change carries key, old/new value types and values", {
    spec = "eventd *payload.the-synthetic-config-change-payload-schema"
        .. " eventd *payload.config-change-key-is-relative-to-the-eventd-configuration-key"
        .. " eventd *payload.config-change-old-value-type-is-absent-or-one-of-four-registry-types"
        .. " eventd *payload.config-change-old-value-is-nil-when-absent"
        .. " eventd *payload.config-change-new-value-type-uses-the-same-five-names"
        .. " eventd *payload.config-change-new-value-is-nil-when-absent",
}, function(t)
    local TYPES = { absent = true, REG_SZ = true, REG_DWORD = true, REG_QWORD = true, REG_BINARY = true }
    local id0 = max_id()
    eventd.set(vm, "LogRetentionDays", "dword:13"):assert_ok()
    local add = config_change_after("LogRetentionDays", id0)
    eventd.unset(vm, "LogRetentionDays"):assert_ok()
    local del = config_change_after("LogRetentionDays", add.id)
    local p = add.payload
    t:assert_eq(sorted_keys(p), "key,new_value,new_value_type,old_value,old_value_type", "exactly the five fields")
    t:assert_eq(p.map.key, "LogRetentionDays", "key is the value name under Machine\\System\\eventd")
    t:assert_eq(p.map.old_value_type, "absent", "it was absent")
    t:assert_eq(p.map.old_value, NIL, "so old_value is nil")
    t:assert_eq(p.map.new_value_type, "REG_DWORD", "and is now a REG_DWORD")
    t:assert_eq(p.map.new_value, "13", "with the new value")
    local q = del.payload
    t:assert_eq(q.map.old_value_type, "REG_DWORD", "deleted: it was a REG_DWORD")
    t:assert_eq(q.map.old_value, "13", "of 13")
    t:assert_eq(q.map.new_value_type, "absent", "and is now absent")
    t:assert_eq(q.map.new_value, NIL, "so new_value is nil")
    for _, r in ipairs({ p, q }) do
        t:assert(TYPES[r.map.old_value_type] and TYPES[r.map.new_value_type], "types are among the five names")
    end
end)

test("config values render as unpadded decimal, as strings, even for numeric types", {
    spec = "eventd *payload.config-values-render-as-utf8-unpadded-decimal-or-lowercase-hex"
        .. " eventd *payload.config-change-values-are-strings-even-for-numeric-types",
}, function(t)
    -- Only DWORD and QWORD keys are live (config.rs:676-813 lists no
    -- REG_SZ or REG_BINARY key), so those two renderings are what a
    -- change can show.
    local id0 = max_id()
    eventd.set(vm, "LogRetentionDays", "dword:7"):assert_ok()
    local d = config_change_after("LogRetentionDays", id0)
    eventd.set(vm, "EventRetentionMaxBytes", "qword:4294967306"):assert_ok()
    local q = config_change_after("EventRetentionMaxBytes", d.id)
    eventd.unset(vm, "LogRetentionDays")
    eventd.unset(vm, "EventRetentionMaxBytes")
    t:assert_eq(d.payload.map.new_value, "7", "a DWORD 7 is \"7\", no leading zeroes")
    t:assert_eq(q.payload.map.new_value_type, "REG_QWORD", "a QWORD key")
    t:assert_eq(q.payload.map.new_value, "4294967306", "renders as unsigned decimal past 32 bits")
    t:assert_eq(type(q.payload.map.new_value), "string", "and is a string, not a number")
    local hit = eventd.rows(vm, "EVENTS " .. eventd.T.config_change ..
        ' WHERE key == "LogRetentionDays" WHERE new_value == "7" SINCE 10m ago')
    t:assert(#hit >= 1, "a string filter matches a numeric key's value")
end)

-- ---------------------------------------------------------------------------
-- synthetic.shutdown
-- ---------------------------------------------------------------------------

test("synthetic.shutdown carries last_sequences: each CPU's highest contiguous receipted sequence, in cpu order", {
    spec = "eventd *payload.the-synthetic-shutdown-payload-schema"
        .. " eventd *payload.shutdown-last-sequences-give-each-cpus-highest-contiguous-receipted-sequence",
}, function(t)
    stop()
    local s = newest(eventd.T.shutdown)
    local high = { [0] = highest_contiguous(0), [1] = highest_contiguous(1) }
    start()
    t:assert_eq(sorted_keys(s.payload), "last_sequences", "the one field")
    local ls = s.payload.map.last_sequences.array
    t:assert_eq(#ls, 2, "one entry per CPU")
    for i, e in ipairs(ls) do
        t:assert_eq(sorted_keys(e), "cpu_id,sequence", "each is {cpu_id, sequence}")
        t:assert_eq(e.map.cpu_id, i - 1, "in cpu_id order")
        t:assert_eq(e.map.sequence, high[e.map.cpu_id],
            "cpu " .. e.map.cpu_id .. ": the receipts' highest contiguous sequence at shutdown")
    end
end)

test("startup derives recovery coverage from receipts, never from the shutdown payload", {
    spec = "eventd *payload.startup-never-derives-recovery-coverage-from-the-shutdown-payload",
}, function(t)
    stop()
    local s = newest(eventd.T.shutdown)
    local lie = eventd.msgpack({ last_sequences = eventd.array({
        eventd.map({ cpu_id = 0, sequence = 900000000 }), eventd.map({ cpu_id = 1, sequence = 900000000 }) }) })
    rewrite(s.db, "UPDATE events SET payload = X'" .. hex(lie) .. "' WHERE id = " .. s.id .. ";")
    start()
    local after = { [0] = highest_contiguous(0), [1] = highest_contiguous(1) }
    for _, e in ipairs(newest(eventd.T.startup).payload.map.resume_points.array) do
        t:assert(e.map.sequence <= after[e.map.cpu_id],
            "cpu " .. e.map.cpu_id .. " resumes from its receipts (" .. e.map.sequence .. "), not the falsified 900000000")
    end
end)

-- ---------------------------------------------------------------------------
-- synthetic.gap
-- ---------------------------------------------------------------------------

--- Stop eventd, overrun its ring with ~6 MB of events (a 4 MiB ring that
--- nothing is draining), start it, and return the gap record that start
--- wrote. Once per file; later calls return the same record.
local GAP
local function make_gap()
    if GAP then return GAP end
    local before = count_of(eventd.T.gap)
    stop()
    local big = eventd.msgpack({ blob = eventd.bin(string.rep("g", 60000)) })
    local entries = {}
    for i = 1, 100 do entries[i] = { type = "pt.flood", payload = big } end
    local fr = kmes.emit_batch(vm, entries)
    assert(fr.emitted == 100, "the flood was emitted")
    start()
    assert(count_of(eventd.T.gap) > before, "the restart recorded a gap")
    GAP = newest(eventd.T.gap)
    return GAP
end

--- Plant (once) a gap record whose column says CPU 1 and payload says 7.
local planted_gap = false
local function plant_gap()
    if planted_gap then return end
    stop()
    local planted = eventd.msgpack({ cpu_id = 7, first_sequence = 987654321, last_sequence = 987654321,
        count = 1, last_seen_timestamp = eventd.NIL, revealing_timestamp = 1 })
    rewrite(SHARD0, "INSERT INTO events (boot_id, timestamp, cpu_id, event_type, payload) " ..
        "SELECT boot_id, timestamp, 1, '" .. eventd.T.gap .. "', X'" .. hex(planted) .. "' FROM events " ..
        "WHERE event_type = '" .. eventd.T.shutdown .. "' ORDER BY id DESC LIMIT 1;")
    start()
    planted_gap = true
end

test("synthetic.gap carries cpu_id, first/last_sequence, count and both timestamps", {
    spec = "eventd *payload.the-synthetic-gap-payload-schema"
        .. " eventd *payload.gap-cpu-id-is-where-the-gap-was-detected"
        .. " eventd *payload.gap-first-sequence-is-the-first-missing-sequence"
        .. " eventd *payload.gap-last-sequence-is-the-last-missing-sequence"
        .. " eventd *payload.gap-count-is-how-many-sequences-are-missing"
        .. " eventd *payload.gap-last-seen-timestamp-is-the-last-event-before-the-gap-or-nil"
        .. " eventd *payload.gap-revealing-timestamp-is-what-revealed-the-gap"
        .. " eventd *payload.a-gap-carries-cpu-id-in-both-the-payload-and-the-column",
}, function(t)
    make_gap()
    local p = GAP.payload.map
    t:assert_eq(sorted_keys(GAP.payload),
        "count,cpu_id,first_sequence,last_seen_timestamp,last_sequence,revealing_timestamp", "exactly the six fields")
    t:assert_eq(p.cpu_id, GAP.cpu_id, "cpu_id in the payload is the column's")
    t:assert(p.cpu_id == 0 or p.cpu_id == 1, "and a CPU of this machine")
    t:assert_eq(p.count, p.last_sequence - p.first_sequence + 1, "count is the size of the inclusive range")
    local boot = boot_pcds_hex()
    local inside = 0
    for _, s in ipairs(eventd.shards(vm)) do
        inside = inside + eventd.sql(vm, s, "SELECT count(*) FROM events WHERE hex(boot_id) = '" .. boot ..
            "' AND cpu_id = " .. p.cpu_id .. " AND sequence BETWEEN " .. p.first_sequence .. " AND " ..
            p.last_sequence)[1][1]
    end
    t:assert_eq(inside, 0, "no event in first..last was stored: they are the missing ones")
    local edge_before, edge_after
    for _, s in ipairs(eventd.shards(vm)) do
        local r = eventd.sql(vm, s, "SELECT sequence, timestamp FROM events WHERE hex(boot_id) = '" .. boot ..
            "' AND cpu_id = " .. p.cpu_id .. " AND sequence IN (" .. (p.first_sequence - 1) .. ", " ..
            (p.last_sequence + 1) .. ")")
        for _, row in ipairs(r) do
            if row[1] == p.first_sequence - 1 then edge_before = row[2] else edge_after = row[2] end
        end
    end
    t:assert(p.first_sequence == 1 or highest_contiguous(p.cpu_id) >= p.first_sequence - 1,
        "the sequence before first_sequence was accounted for")
    t:assert(edge_after, "the event after last_sequence is stored: it revealed the gap")
    t:assert(math.type(p.revealing_timestamp) == "integer", "revealing_timestamp is a timestamp")
    t:assert_eq(p.revealing_timestamp, edge_after, "the revealing event's timestamp")
    if p.last_seen_timestamp ~= NIL then
        t:assert_eq(p.last_seen_timestamp, edge_before, "last_seen_timestamp is the event before the gap")
    end
end)

test("a cpu_id predicate matches a gap record's column, not its payload field", {
    spec = "eventd *payload.a-cpu-id-predicate-matches-the-gap-column-not-the-payload-field",
}, function(t)
    plant_gap()
    local q = "EVENTS " .. eventd.T.gap .. " WHERE first_sequence == 987654321"
    t:assert_eq(#eventd.rows(vm, q .. " WHERE cpu_id == 1 SINCE 1h ago"), 1, "cpu_id == 1 (the column) matches")
    t:assert_eq(#eventd.rows(vm, q .. " WHERE cpu_id == 7 SINCE 1h ago"), 0, "cpu_id == 7 (the payload) does not")
end)

test("every synthetic payload field name is a query field, unless its value is nested", {
    spec = "eventd *payload.synthetic-field-names-are-stable-query-fields-except-nested-values",
    tags = { "known-bug" },
}, function(t)
    -- TRM-synthetic-fields-collide: startup's boot_id and gap's cpu_id are
    -- top-level payload keys that collide with header columns, and eventd
    -- suppresses a colliding key from the query surface (the flattening
    -- rule §3.1 and §3.4 also state); the book's own §3.2 table then
    -- describes the column, not the field. This case reads each scalar
    -- top-level field back through a query and finds those two replaced.
    make_gap()
    plant_gap()
    local id0 = max_id()
    eventd.set(vm, "LogRetentionDays", "dword:11"):assert_ok()
    config_change_after("LogRetentionDays", id0)
    eventd.unset(vm, "LogRetentionDays")
    --- Find `stored`'s record among a query's results by its non-colliding
    --- scalar fields, then require every scalar field to read back as
    --- itself.
    local function check(event_type, stored)
        local rows = eventd.rows(vm, "EVENTS " .. event_type .. " SINCE 1h ago")
        local rec
        for _, r in ipairs(rows) do
            local all = true
            for k, v in pairs(stored.payload.map) do
                if type(v) ~= "table" and v ~= NIL and k ~= "boot_id" and k ~= "cpu_id" and r[k] ~= v then
                    all = false
                end
            end
            if all then rec = r break end
        end
        t:assert(rec, event_type .. ": its record comes back through a query")
        for k, v in pairs(stored.payload.map) do
            if type(v) ~= "table" and v ~= NIL then
                t:assert_eq(rec[k], v, event_type .. ": payload field " .. k .. " is queryable as itself")
            end
        end
    end
    -- The planted gap record: column cpu_id 1, payload cpu_id 7. The
    -- payload field is the one §3.2 names.
    local planted = eventd.rows(vm, "EVENTS " .. eventd.T.gap .. " WHERE first_sequence == 987654321 SINCE 1h ago")
    t:assert_eq(#planted, 1, "the planted gap record is found")
    t:assert_eq(planted[1].cpu_id, 7, "the gap payload's cpu_id is what a query presents as cpu_id")
    check(eventd.T.config_change, newest(eventd.T.config_change))
    check(eventd.T.shutdown, newest(eventd.T.shutdown))
    check(eventd.T.startup, newest(eventd.T.startup))
    check(eventd.T.gap, GAP)
end)

-- ---------------------------------------------------------------------------
-- synthetic.storage_error, then all five
-- ---------------------------------------------------------------------------

test("synthetic.storage_error carries store, shard_index (event store only) and a description", {
    spec = "eventd *payload.the-synthetic-storage-error-payload-schema"
        .. " eventd *payload.storage-error-store-is-event-log-metric-or-metadata"
        .. " eventd *payload.storage-error-shard-index-is-set-only-for-event-store-errors"
        .. " eventd *payload.storage-error-error-is-a-human-readable-description",
}, function(t)
    stop()
    local garbage = string.rep("this is not a database. ", 400)
    vm:write_file(SHARD0, garbage)
    vm:write_file(eventd.DB.logs, garbage)
    start()
    local rows = eventd.sql(vm, SHARD0, "SELECT hex(payload) FROM events WHERE event_type = '" ..
        eventd.T.storage_error .. "' ORDER BY id")
    local by_store = {}
    for _, r in ipairs(rows) do
        local p = decode(unhex(r[1]))
        t:assert_eq(sorted_keys(p), "error,shard_index,store", "exactly the three fields")
        by_store[p.map.store] = p.map
    end
    local STORES = { event = true, log = true, metric = true, metadata = true }
    for s in pairs(by_store) do t:assert(STORES[s], "store is one of the four names: " .. s) end
    t:assert(by_store.event, "the event shard's corruption was recorded: " .. json.encode(rows))
    t:assert(by_store.log, "and the log store's")
    t:assert_eq(by_store.event.shard_index, 0, "an event-store error names its shard")
    t:assert_eq(by_store.log.shard_index, NIL, "a log-store error has none")
    for s, p in pairs(by_store) do
        t:assert(type(p.error) == "string" and #p.error > 0 and p.error:find("%a"), s .. ": the error is text: " .. tostring(p.error))
    end
end)

test("every synthetic event carries a MessagePack map", {
    spec = "eventd *payload.every-synthetic-event-carries-a-messagepack-map",
}, function(t)
    -- shard-0000 was replaced above; restart to have a startup, a shutdown
    -- and a config change in it alongside the storage_error, and flood for
    -- a gap.
    eventd.set(vm, "LogRetentionDays", "dword:9"):assert_ok()
    eventd.unset(vm, "LogRetentionDays")
    stop()
    local big = eventd.msgpack({ blob = eventd.bin(string.rep("g", 60000)) })
    local entries = {}
    for i = 1, 100 do entries[i] = { type = "pt.flood", payload = big } end
    kmes.emit_batch(vm, entries)
    start()
    for _, ty in ipairs({ eventd.T.startup, eventd.T.shutdown, eventd.T.gap, eventd.T.config_change,
                          eventd.T.storage_error }) do
        local rows = {}
        for _, db in ipairs(eventd.shards(vm)) do
            for _, r in ipairs(eventd.sql(vm, db, "SELECT hex(payload) FROM events WHERE event_type = '" .. ty .. "'")) do
                rows[#rows + 1] = r
            end
        end
        t:assert(#rows >= 1, ty .. " is present")
        for _, r in ipairs(rows) do
            t:assert(decode(unhex(r[1])).map, ty .. ": the payload is one MessagePack map")
        end
    end
end)
