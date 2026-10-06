-- eventd TRM §2.5 — gap detection: a per-CPU sequence jump becomes a
-- `synthetic.gap` record saying what was lost, written through the normal
-- write path and accounted for by a receipt so a restart never repeats it.
--
-- One file-scope VM on one vCPU with the KMES ring seeded down to its
-- 64 KiB minimum (`Machine\System\KMES\BufferCapacity`, applied before
-- Phase 2), so a few hundred events overrun it. Losses are made three
-- ways, all against the real system sink:
--
--   * live overrun: SIGSTOP eventd, emit more than the ring holds,
--     SIGCONT — eventd's drain thread has been lapped and the next event
--     it reads is far beyond the one it expected;
--   * downtime: `svctl stop eventd`, flood, `svctl start eventd` — the
--     restart reconciliation finds sequences neither receipted nor in
--     the ring;
--   * no receipts at all: the shard files are removed while eventd is
--     stopped, so its coverage for this boot starts before sequence 1.
--     This one is last: it empties the store.
--
-- What a gap record holds is read two ways: through evctl (the header
-- fields and the payload fields) and straight out
-- of the shard with the host-side sqlite copy (the raw MessagePack payload
-- and the null header columns). The agent also attaches its own KMES ring
-- (it runs as SYSTEM, which holds SeSecurityPrivilege) to read the oldest
-- survivor while eventd is stopped and to watch what eventd emits.
--
-- Structural drops have no VM route (see the stub) and are homed on the
-- reconciler's unit test.

local eventd = require("helpers.eventd")
local peinit = require("helpers.peinit")
local kmes = require("helpers.kmes")
peinit.claim(1)

local RING = 65536

local vm = eventd.boot({
    name = "ev-gap",
    config = {},
    config_keys = { {
        path = [[Machine\System\KMES]],
        values = { { name = "BufferCapacity", type = "qword", data = RING } },
    } },
})

-- ---------------------------------------------------------------------------
-- Local helpers
-- ---------------------------------------------------------------------------

--- Emit `n` events of `event_type` from the agent in 256-entry batches.
local function flood(event_type, n)
    local entries = {}
    for i = 1, 256 do entries[i] = { type = event_type, payload = kmes.PAYLOAD } end
    local sent = 0
    while sent < n do
        local k = math.min(256, n - sent)
        local batch = entries
        if k < 256 then
            batch = {}
            for i = 1, k do batch[i] = entries[i] end
        end
        local r = kmes.emit_batch(vm, batch)
        assert(r.ret == 0 and r.emitted == k,
            "emit_batch: ret " .. tostring(r.ret) .. " emitted " .. tostring(r.emitted))
        sent = sent + k
    end
end

--- Emit one event and wait until eventd has stored it; returns its row.
local function stored_marker(stem)
    local event_type = "pt.gap." .. eventd.marker(stem)
    local r = eventd.emit(vm, event_type, { n = 1 })
    assert(r.ret == 0, "kmes_emit: errno " .. tostring(r.errno))
    local rows = eventd.wait_rows(vm, "EVENTS " .. event_type .. " SINCE 10m ago",
        function(rs) return #rs == 1 end)
    return rows[1]
end

--- Decode a gap payload: a MessagePack map of string keys to unsigned
--- integers or nil. Returns the map and its keys in wire order. Anything
--- else raises, which is the right outcome for a payload of the wrong
--- shape.
local function decode_gap_payload(hex)
    local b = eventd.unhex(hex)
    local at = 1
    local function str()
        local tag = b:byte(at)
        local n
        if tag >= 0xa0 and tag <= 0xbf then n = tag - 0xa0; at = at + 1
        elseif tag == 0xd9 then n = b:byte(at + 1); at = at + 2
        else error(string.format("gap payload: key tag 0x%02x", tag)) end
        local s = b:sub(at, at + n - 1)
        at = at + n
        return s
    end
    local function value()
        local tag = b:byte(at)
        if tag < 0x80 then at = at + 1; return tag end
        if tag == 0xc0 then at = at + 1; return nil end
        local fmt = ({ [0xcc] = ">I1", [0xcd] = ">I2", [0xce] = ">I4", [0xcf] = ">I8" })[tag]
        assert(fmt, string.format("gap payload: value tag 0x%02x", tag))
        local v, nxt = string.unpack(fmt, b, at + 1)
        at = nxt
        return v
    end
    local tag = b:byte(at)
    assert(tag >= 0x80 and tag <= 0x8f, string.format("gap payload is not a fixmap: 0x%02x", tag))
    at = at + 1
    local out, keys = {}, {}
    for _ = 1, tag - 0x80 do
        local k = str()
        keys[#keys + 1] = k
        out[k] = value()
    end
    assert(at == #b + 1, "gap payload has trailing bytes")
    return out, keys
end

--- Every gap row in the store, read straight from the shard files.
local function gap_rows()
    local out = {}
    for _, shard in ipairs(eventd.shards(vm)) do
        local rows = eventd.sql(vm, shard,
            "SELECT id, cpu_id, sequence, origin_class, effective_token_guid, " ..
            "true_token_guid, process_guid, hex(payload), timestamp " ..
            "FROM events WHERE event_type = 'synthetic.gap' ORDER BY id")
        for _, r in ipairs(rows) do
            local p, keys = decode_gap_payload(r[8])
            out[#out + 1] = {
                shard = shard, id = r[1], cpu_id = r[2], sequence = r[3],
                origin_class = r[4], effective_token_guid = r[5],
                true_token_guid = r[6], process_guid = r[7],
                timestamp = r[9], payload = p, keys = keys,
            }
        end
    end
    return out
end

--- The gap whose first missing sequence is at or beyond `after`.
local function gap_after(after)
    for _, g in ipairs(gap_rows()) do
        if g.payload.first_sequence >= after then return g end
    end
end

--- Wait until a gap starting at or after `after` has been committed.
local function wait_gap(after)
    local g
    wait_until(function()
        g = gap_after(after)
        return g ~= nil
    end, { timeout = 30, interval = 0.5, desc = "a gap record past sequence " .. after })
    return g
end

--- {sequence = {id, timestamp, shard}} for every CPU-0 event row in the
--- store with a sequence in [lo, hi].
local function rows_by_sequence(lo, hi)
    local out = {}
    for _, shard in ipairs(eventd.shards(vm)) do
        local rows = eventd.sql(vm, shard, string.format(
            "SELECT sequence, id, timestamp, event_type FROM events " ..
            "WHERE cpu_id = 0 AND sequence BETWEEN %d AND %d", lo, hi))
        for _, r in ipairs(rows) do
            out[r[1]] = { id = r[2], timestamp = r[3], event_type = r[4], shard = shard }
        end
    end
    return out
end

--- Receipt intervals for CPU 0, merged, from every shard.
local function receipts()
    local all = {}
    for _, shard in ipairs(eventd.shards(vm)) do
        for _, r in ipairs(eventd.sql(vm, shard,
            "SELECT first_sequence, last_sequence FROM receipt_ranges WHERE cpu_id = 0")) do
            all[#all + 1] = { r[1], r[2], shard = shard }
        end
    end
    table.sort(all, function(a, b) return a[1] < b[1] end)
    return all
end

local function covered(rs, seq)
    for _, r in ipairs(rs) do
        if seq >= r[1] and seq <= r[2] then return true end
    end
    return false
end

--- The oldest event still in CPU 0's ring, read through the agent's own
--- attachment from the ring's tail.
local function oldest_survivor()
    local ring = assert(kmes.attach(vm, 0))
    ring.cursor = 0
    local events = kmes.drain(ring)
    kmes.detach(ring)
    assert(#events > 0, "the ring holds events")
    return events[1], events[#events], events
end

-- ---------------------------------------------------------------------------
-- Live overrun
-- ---------------------------------------------------------------------------

test("an overrun ring becomes one gap record naming exactly the lost sequences", {
    spec = "eventd *gap.a-sequence-beyond-the-expected-next-one-reveals-a-gap"
        .. " eventd *gap.a-ring-buffer-overrun-is-recorded-as-a-gap"
        .. " eventd *gap.a-gap-record-carries-the-cpu-identifier"
        .. " eventd *gap.the-first-missing-sequence-is-the-last-seen-plus-one"
        .. " eventd *gap.the-last-missing-sequence-is-the-revealing-events-minus-one"
        .. " eventd *gap.a-gap-record-carries-the-count-of-missing-events"
        .. " eventd *gap.a-gap-record-carries-the-last-processed-timestamp-where-known"
        .. " eventd *gap.a-gap-record-carries-the-revealing-events-timestamp"
        .. " eventd *synthetic.lost-events-on-a-cpu-emit-synthetic-gap"
        .. " eventd *synthetic.the-timestamp-records-when-eventd-noticed-not-when-it-occurred",
}, function(t)
    local before = stored_marker("before")
    local flood_type = "pt.gap." .. eventd.marker("ovr")

    eventd.freeze(vm)
    -- Twice what the ring holds: whatever eventd had not read is lapped.
    flood(flood_type, 1500)
    -- The newest event: emitted after every lost one, before eventd runs.
    local last_emit = eventd.emit(vm, "pt.gap.resume", { n = 1 })
    t:assert_eq(last_emit.ret, 0, "the resume marker emitted")
    local resume = select(2, oldest_survivor())
    eventd.thaw(vm)

    local g = wait_gap(before["event.sequence"] + 1)
    local p = g.payload
    t:assert_eq(g.cpu_id, 0, "the record names CPU 0, the only CPU")
    t:assert_eq(p.cpu_id, 0, "in the payload too")

    -- The last event eventd saw before the jump, and the one that revealed it.
    local around = rows_by_sequence(p.first_sequence - 1, p.last_sequence + 1)
    local last_seen = around[p.first_sequence - 1]
    local revealing = around[p.last_sequence + 1]
    t:assert(last_seen, "the sequence before the gap was stored: it is the last one eventd saw")
    t:assert(revealing, "the sequence after the gap was stored: it is the event that revealed it")
    t:assert(p.first_sequence >= before["event.sequence"] + 1,
        "the loss began after the marker eventd had already stored")
    t:assert_eq(p.count, p.last_sequence - p.first_sequence + 1,
        "count is the number of sequences in [first, last]: " .. json.encode(p))
    t:assert(p.count > 0, "and something was lost")
    for s = p.first_sequence, p.last_sequence do
        if around[s] then
            t:assert(false, "no row exists for lost sequence " .. s)
            break
        end
    end
    t:assert_eq(p.last_seen_timestamp, last_seen.timestamp,
        "last_seen_timestamp is the timestamp of the last event processed before the gap")
    t:assert_eq(p.revealing_timestamp, revealing.timestamp,
        "revealing_timestamp is the timestamp of the event that revealed it")

    -- Stamped when eventd noticed: after every lost event was emitted, and
    -- after even the newest event, which was emitted before eventd resumed.
    t:assert(g.timestamp > p.revealing_timestamp,
        "the record's timestamp is later than the revealing event's")
    t:assert(g.timestamp > resume.timestamp,
        "and later than the last event emitted before eventd was resumed: " ..
        g.timestamp .. " vs " .. resume.timestamp)
end)

test("a lapped drain thread resumes at the oldest survivor and the lap is an ordinary gap", {
    spec = "eventd *gap.a-lapped-reader-is-advanced-to-tail-pos"
        .. " eventd *gap.lapping-is-recorded-by-ordinary-gap-detection"
        .. " eventd *gap.a-gap-record-is-never-emitted-through-kmes",
}, function(t)
    local before = stored_marker("lap")
    eventd.freeze(vm)
    flood("pt.gap." .. eventd.marker("lap"), 1500)
    -- Read the ring as eventd will find it: everything up to the tail has
    -- been overwritten, and the tail is the oldest survivor.
    local oldest = oldest_survivor()
    t:assert(oldest.sequence > before["event.sequence"] + 1,
        "eventd has been lapped: the oldest survivor " .. oldest.sequence ..
        " is past the next sequence it expects, " .. (before["event.sequence"] + 1))

    -- A second consumer, attached across the resume, sees whatever eventd
    -- puts into KMES from here on.
    local watch = assert(kmes.attach(vm, 0))
    eventd.thaw(vm)
    local g = wait_gap(before["event.sequence"] + 1)
    vm:run("sleep 1")
    local seen = kmes.drain(watch)
    kmes.detach(watch)

    t:assert_eq(g.payload.last_sequence + 1, oldest.sequence,
        "the first event read after the lap is the oldest survivor at tail_pos")
    local stored = rows_by_sequence(oldest.sequence, oldest.sequence)[oldest.sequence]
    t:assert(stored, "and that survivor was stored")
    t:assert_eq(g.payload.count, oldest.sequence - g.payload.first_sequence,
        "the lap is recorded as one ordinary gap up to it")

    for _, e in ipairs(seen) do
        t:assert(not e.type:find("^synthetic%."),
            "eventd emitted no synthetic event into KMES: saw " .. e.type)
    end
    t:assert(g.origin_class == nil and g.sequence == nil,
        "and the stored gap carries no KMES origin or sequence: it never passed through KMES")
end)

-- ---------------------------------------------------------------------------
-- The record itself
-- ---------------------------------------------------------------------------

test("a gap is stored like any event: same shard, same transaction, its own receipt", {
    spec = "eventd *gap.a-gap-record-is-committed-through-the-normal-write-path"
        .. " eventd *gap.a-gaps-receipt-range-covers-the-missing-interval-so-a-restart-never-repeats-it"
        .. " eventd *gap.gap-details-are-a-messagepack-payload-and-gaps-are-queryable-like-any-event"
        .. " eventd *gap.a-gap-record-says-what-was-lost-not-why"
        .. " eventd *batch.events-gaps-and-their-receipts-commit-in-the-same-transaction",
}, function(t)
    local before = stored_marker("path")
    eventd.freeze(vm)
    flood("pt.gap." .. eventd.marker("path"), 1500)
    eventd.thaw(vm)
    local g = wait_gap(before["event.sequence"] + 1)
    local p = g.payload

    -- Normal write path: the gap row went into the shard holding CPU 0's
    -- events, inserted immediately before the event that revealed it.
    local revealing = rows_by_sequence(p.last_sequence + 1, p.last_sequence + 1)[p.last_sequence + 1]
    t:assert(revealing, "the revealing event is stored")
    t:assert_eq(g.shard, revealing.shard, "the gap is in the same shard as its CPU's events")
    t:assert_eq(revealing.id, g.id + 1,
        "and was inserted directly ahead of the revealing event, in the same batch")

    -- One receipt row spans the missing interval and the revealing event:
    -- receipts are merged only within one transaction.
    local spanning
    for _, r in ipairs(receipts()) do
        if r[1] <= p.first_sequence and r[2] >= p.last_sequence + 1 then spanning = r end
    end
    t:assert(spanning, "a single receipt covers [first_sequence, revealing sequence]: " ..
        json.encode(receipts()))
    t:assert_eq(spanning.shard, g.shard, "in the gap's own shard")

    -- MessagePack in the payload column, saying what and never why.
    t:assert_eq(json.encode(g.keys), json.encode({ "cpu_id", "first_sequence",
        "last_sequence", "count", "last_seen_timestamp", "revealing_timestamp" }),
        "the payload is a MessagePack map of exactly the six loss fields")

    -- Queryable like any event, by its payload fields.
    local rows = eventd.rows(vm, string.format(
        "EVENTS %s WHERE first_sequence == %d SINCE 10m ago", eventd.T.gap, p.first_sequence))
    t:assert_eq(#rows, 1, "the gap is found by a query on its payload field")
    t:assert_eq(rows[1].last_sequence, p.last_sequence, "with its fields decoded")
    local by_cpu = eventd.rows(vm, string.format(
        "EVENTS %s WHERE event.cpu == 0 SINCE 10m ago TAKE 1000", eventd.T.gap))
    local found = false
    for _, r in ipairs(by_cpu) do
        if r.first_sequence == p.first_sequence then found = true end
    end
    t:assert(found, "and by event.cpu, like any event from that CPU")

    -- The receipt is why a restart does not rediscover the same loss.
    eventd.restart(vm)
    local again = 0
    for _, other in ipairs(gap_rows()) do
        if other.payload.first_sequence <= p.last_sequence
            and other.payload.last_sequence >= p.first_sequence then
            again = again + 1
        end
    end
    t:assert_eq(again, 1, "after a restart the interval is still recorded exactly once")
end)

test("a gap row fills cpu_id and no other header column, unlike every other synthetic event", {
    spec = "eventd *gap.a-gap-record-sets-cpu-id-and-leaves-the-other-header-columns-null"
        .. " eventd *gap.gap-records-are-the-only-synthetic-events-with-a-header-field",
}, function(t)
    local gaps = gap_rows()
    t:assert(#gaps >= 1, "earlier tests left gap rows")
    for _, g in ipairs(gaps) do
        t:assert(g.cpu_id ~= nil, "gap " .. g.id .. " has cpu_id")
        t:assert(g.sequence == nil and g.origin_class == nil and g.effective_token_guid == nil
            and g.true_token_guid == nil and g.process_guid == nil,
            "gap " .. g.id .. " leaves sequence, origin_class and the identity GUIDs null")
    end
    local others = 0
    for _, shard in ipairs(eventd.shards(vm)) do
        for _, r in ipairs(eventd.sql(vm, shard,
            "SELECT event_type, cpu_id, sequence, origin_class, effective_token_guid, " ..
            "true_token_guid, process_guid FROM events " ..
            "WHERE event_type LIKE 'synthetic.%' AND event_type <> 'synthetic.gap'")) do
            others = others + 1
            for i = 2, 7 do
                t:assert(r[i] == nil, r[1] .. " carries no KMES header column (column " .. i .. ")")
            end
        end
    end
    t:assert(others >= 2, "startup and shutdown records were checked too: " .. others)
end)

-- ---------------------------------------------------------------------------
-- Downtime and restart reconciliation
-- ---------------------------------------------------------------------------

test("events lost while eventd was stopped become a restart gap, survivors are stored", {
    spec = "eventd *gap.events-lost-while-eventd-was-not-running-are-recorded-as-a-gap"
        .. " eventd *kmes.restart-emits-a-gap-only-for-sequences-neither-receipted-nor-surviving",
}, function(t)
    local before = stored_marker("down")
    eventd.stop(vm)
    local flood_type = "pt.gap." .. eventd.marker("down")
    flood(flood_type, 1500)
    local oldest, newest = oldest_survivor()
    -- What eventd committed before it stopped, from its own receipts.
    local rs = receipts()
    local highest = 0
    for _, r in ipairs(rs) do
        if r[1] <= highest + 1 then highest = math.max(highest, r[2]) end
    end
    eventd.start(vm)

    t:assert(highest >= before["event.sequence"], "the marker was receipted before the stop")
    local g = wait_gap(highest + 1)
    t:assert_eq(g.payload.first_sequence, highest + 1,
        "the gap begins right after the receipted sequences")
    -- The ring is full, so the events peinit emits for the start itself
    -- overwrite a few more of the oldest survivors before eventd attaches:
    -- the survivor eventd found is at or past the one read above.
    local first_survivor = g.payload.last_sequence + 1
    t:assert(first_survivor >= oldest.sequence,
        "the gap stops at a ring survivor (" .. first_survivor .. ", oldest read while stopped " ..
        oldest.sequence .. ")")
    local stored = rows_by_sequence(first_survivor, newest.sequence)
    local missing = 0
    for s = first_survivor, newest.sequence do
        if not stored[s] then missing = missing + 1 end
    end
    t:assert(stored[first_survivor], "the event right after the gap is stored: survivors are not a gap")
    t:assert_eq(missing, 0, "every survivor from the downtime was ingested at restart")
    local overlapping = 0
    for _, other in ipairs(gap_rows()) do
        if other.payload.last_sequence >= highest + 1 then overlapping = overlapping + 1 end
    end
    t:assert_eq(overlapping, 1, "and the downtime produced exactly one gap")
end)

-- Last: removes every shard, so the store this boot starts over.
test("with no receipt for the CPU, an overwritten prefix is a gap from sequence 1", {
    spec = "eventd *kmes.with-no-receipt-for-a-cpu-coverage-begins-before-sequence-1",
}, function(t)
    eventd.stop(vm)
    local oldest = oldest_survivor()
    t:assert(oldest.sequence > 1, "the ring has wrapped since boot: oldest survivor " .. oldest.sequence)
    vm:run("rm -f /var/state/eventd/events/shard-*"):assert_ok()
    t:assert_eq(#eventd.shards(vm), 0, "no shard, so no receipt, is left")
    eventd.start(vm)

    local g
    wait_until(function()
        for _, x in ipairs(gap_rows()) do
            if x.payload.first_sequence == 1 then g = x end
        end
        return g ~= nil
    end, { timeout = 30, interval = 0.5, desc = "a gap from sequence 1" })
    -- As above, the start's own events may overwrite a few more survivors.
    local first_survivor = g.payload.last_sequence + 1
    t:assert(first_survivor >= oldest.sequence,
        "it runs from sequence 1 up to a ring survivor: " .. first_survivor)
    t:assert(rows_by_sequence(first_survivor, first_survivor)[first_survivor],
        "which was ingested, so the gap is exactly the overwritten prefix")
end)

-- ---------------------------------------------------------------------------
-- Structural drops
-- ---------------------------------------------------------------------------

-- Route closed: only a kernel emitter consumes a sequence number and then
-- drops the event (PKM §2.7 "Event drop": syscall emitters are validated
-- before a sequence is taken, so their drops leave no gap). The only
-- kernel limit a payload could trip is half the ring, 32 KiB at the 64 KiB
-- minimum, and every kernel emitter builds a bounded payload (KACS file
-- audit: a path of at most PATH_MAX; LCS audit: a fixed caller summary;
-- KMES self-reports: a 768-byte buffer), so nothing a guest can do makes
-- KMES drop a sequenced event. eventd cannot tell a drop from an overrun
-- anyway: both are a jump, and the jump is what the unit test drives.
test("any sequence jump, whatever caused it, becomes one gap", {
    spec = "eventd *gap.a-structural-drop-is-recorded-as-a-gap",
    skip = true,
    covered_by = "cargo:eventd eventd-core reconcile::tests::live_jump_becomes_one_gap",
}, function() end)
