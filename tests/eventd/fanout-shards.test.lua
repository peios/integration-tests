-- eventd TRM §6.4 — cross-shard fan-out: every database in the event
-- store answers every event query, results merge across them, aggregates
-- fold across them, and each database costs a read-only connection.
-- Also §6.6's statement that an event-store wake re-examines every shard.
--
-- One file-scope VM with two vCPUs, so the event store starts with two
-- active shards, one per KMES buffer. Events go to a chosen shard by
-- emitting from a worker pinned to that shard's CPU; which CPU feeds
-- which shard is read back from the shard files, not assumed. The memory
-- and timing side of fan-out (what a merge holds, when it stops, the
-- unbounded case) needs a large dataset and lives in account-memory.
--
-- Late in the file the shard count is lowered to one and eventd
-- restarted, which turns shard-0001 into a historical shard: the tests
-- after that point read across an active and a historical database. The
-- count is restored at the end.

local eventd = require("helpers.eventd")
local peinit = require("helpers.peinit")
local kmes = require("helpers.kmes")
local sys = require("helpers.sys")
local us = require("helpers.unixsock")
local pc = require("helpers.peinit_client")
peinit.claim(1, { cpus = 2 })

-- Two vCPUs: two active shards by default.
local vm = eventd.boot({ name = "ev-fanout", cpus = 2 })

-- ---------------------------------------------------------------------------
-- A raw query-channel client, for what evctl hides: where one response
-- frame ends and the next begins, the order frames arrive in, a caller
-- other than SYSTEM, and a reader that stops reading. A frame is a u32
-- little-endian length and a MessagePack map (PSPU §3.15–§3.16).
-- ---------------------------------------------------------------------------

local function mp_decode(s, i)
    i = i or 1
    local b = s:byte(i)
    assert(b, "msgpack: ran off the end")
    local function list(count, at)
        local out = {}
        for k = 1, count do out[k], at = mp_decode(s, at) end
        return out, at
    end
    local function dict(count, at)
        local out = {}
        for _ = 1, count do
            local k, v
            k, at = mp_decode(s, at)
            v, at = mp_decode(s, at)
            out[k] = v
        end
        return out, at
    end
    local function bytes(len, at) return s:sub(at, at + len - 1), at + len end
    local function num(fmt, size) return (string.unpack(fmt, s, i + 1)), i + 1 + size end
    if b <= 0x7f then return b, i + 1 end
    if b >= 0xe0 then return b - 0x100, i + 1 end
    if b <= 0x8f then return dict(b - 0x80, i + 1) end
    if b <= 0x9f then return list(b - 0x90, i + 1) end
    if b <= 0xbf then return bytes(b - 0xa0, i + 1) end
    if b == 0xc0 then return eventd.NIL, i + 1 end
    if b == 0xc2 then return false, i + 1 end
    if b == 0xc3 then return true, i + 1 end
    if b == 0xc4 or b == 0xd9 then return bytes(s:byte(i + 1), i + 2) end
    if b == 0xc5 or b == 0xda then return bytes((string.unpack(">I2", s, i + 1)), i + 3) end
    if b == 0xc6 or b == 0xdb then return bytes((string.unpack(">I4", s, i + 1)), i + 5) end
    if b == 0xca then return num(">f", 4) end
    if b == 0xcb then return num(">d", 8) end
    if b == 0xcc then return num(">I1", 1) end
    if b == 0xcd then return num(">I2", 2) end
    if b == 0xce then return num(">I4", 4) end
    if b == 0xcf then return num(">i8", 8) end
    if b == 0xd0 then return num(">i1", 1) end
    if b == 0xd1 then return num(">i2", 2) end
    if b == 0xd2 then return num(">i4", 4) end
    if b == 0xd3 then return num(">i8", 8) end
    if b == 0xdc then return list((string.unpack(">I2", s, i + 1)), i + 3) end
    if b == 0xdd then return list((string.unpack(">I4", s, i + 1)), i + 5) end
    if b == 0xde then return dict((string.unpack(">I2", s, i + 1)), i + 3) end
    if b == 0xdf then return dict((string.unpack(">I4", s, i + 1)), i + 5) end
    error(string.format("msgpack: unsupported tag 0x%02x", b))
end

local rq = {}

function rq.open(w, tok)
    local fd, err = pc.connect_as(w, eventd.SOCKET.query, us.SOCK.STREAM, tok)
    assert(fd, "connect to the query socket: " .. tostring(err))
    return { w = w, fd = fd, buf = "" }
end

function rq.timeout(c, seconds)
    c.w:syscall(us.NR.setsockopt, {
        args = { c.fd, 1, 20, 0, 16 },
        bufs = { string.pack("<i8i8", math.floor(seconds), math.floor((seconds % 1) * 1e6)) },
        ptrs = { 3 },
    })
end

function rq.send(c, text)
    local body = eventd.msgpack({ query = text })
    local r = us.sendmsg(c.w, c.fd, string.pack("<I4", #body) .. body)
    assert(r.ret == 4 + #body, "sending the request: ret " .. tostring(r.ret))
end

local function fill(c, n)
    while #c.buf < n do
        local r = us.recvmsg(c.w, c.fd, 65536, { cmsg = 0 })
        if r.ret < 0 then return false, us.errname(r.errno) end
        if r.ret == 0 then return false, "eof" end
        c.buf = c.buf .. r.data
    end
    return true
end

function rq.frame(c)
    local ok, why = fill(c, 4)
    if not ok then return nil, why end
    local len = string.unpack("<I4", c.buf)
    ok, why = fill(c, 4 + len)
    if not ok then return nil, why end
    local msg = mp_decode(c.buf:sub(5, 4 + len))
    c.buf = c.buf:sub(5 + len)
    msg.size = len
    return msg
end

function rq.close(c) sys.close(c.w, c.fd) end

-- ---------------------------------------------------------------------------
-- Local helpers
-- ---------------------------------------------------------------------------

--- Emit `entries` ({type, payload} with payload a Lua value) from a worker
--- pinned to `cpu`, in one batch.
local function pinned(cpu, etype, payloads)
    local w = vm:spawn_worker()
    local ok, err = pcall(function()
        local r = w:syscall(sys.NR.sched_setaffinity, {
            args = { 0, 8, 0 }, bufs = { string.pack("<I8", 1 << cpu) }, ptrs = { 2 },
        })
        assert(r.ret == 0, "pin to cpu " .. cpu .. ": errno " .. tostring(r.errno))
        local entries = {}
        for i, p in ipairs(payloads) do entries[i] = { type = etype, payload = eventd.msgpack(p) } end
        local e = kmes.emit_batch(w, entries)
        assert(e.ret == 0 and e.emitted == #entries, "pinned batch: errno " .. tostring(e.errno))
    end)
    w:kill(); w:join()
    if not ok then error(err, 0) end
end

--- shard number -> CPU that feeds it, worked out once from two probes.
local SHARD_OF_CPU = {}
do
    local tag = eventd.marker("probe")
    pinned(0, "pt.fan.probe", { { tag = tag .. "c0" } })
    pinned(1, "pt.fan.probe", { { tag = tag .. "c1" } })
    eventd.wait_rows(vm, "EVENTS pt.fan.probe", function(rs) return #rs >= 2 end)
    for _, path in ipairs(eventd.shards(vm)) do
        local n = tonumber(path:match("shard%-(%d+)%.db$"))
        for cpu = 0, 1 do
            local c = eventd.sql(vm, path, "SELECT count(*) FROM events WHERE instr(payload, '"
                .. tag .. "c" .. cpu .. "') > 0")
            if c[1][1] > 0 then SHARD_OF_CPU[cpu] = n end
        end
    end
    assert(SHARD_OF_CPU[0] and SHARD_OF_CPU[1] and SHARD_OF_CPU[0] ~= SHARD_OF_CPU[1],
        "the two CPUs feed two shards: " .. json.encode(SHARD_OF_CPU))
end

local function field(rows, name)
    local out = {}
    for i, r in ipairs(rows) do out[i] = r[name] end
    return out
end

local function eventd_fds()
    local pid = eventd.pid(vm)
    local out = {}
    for _, name in ipairs(vm:listdir("/proc/" .. pid .. "/fd")) do
        local n = type(name) == "table" and name.name or name
        local path = sys.readlink(vm, "/proc/" .. pid .. "/fd/" .. n)
        local okf, info = pcall(vm.read_file, vm, "/proc/" .. pid .. "/fdinfo/" .. n)
        if path and okf then
            out[tonumber(n)] = { path = path, mode = tonumber(info:match("flags:%s*(%d+)"), 8) & 3 }
        end
    end
    return out
end

--- fd numbers open on `path` with access mode `mode`, sorted.
local function fds_on(fds, path, mode)
    local list = {}
    for fd, d in pairs(fds) do
        if d.path == path and d.mode == mode then list[#list + 1] = fd end
    end
    table.sort(list)
    return list
end

local SHARD0 = eventd.STORE.events .. "/shard-0000.db"
local SHARD1 = eventd.STORE.events .. "/shard-0001.db"
-- The writers' descriptors as first seen, for the lifetime test at the end.
local FIRST_FDS = eventd_fds()

-- ---------------------------------------------------------------------------
-- Merging
-- ---------------------------------------------------------------------------

-- "A non-aggregating query with no SORT reads every shard at once ... and
--  the coordinator takes whichever shard's next row comes first under the
--  tiebreakers of §6.2: an N-way merge of the sorted streams."
test("events alternating between two shards come back in one newest-first sequence", {
    spec = "eventd *fanout.non-aggregating-results-are-an-n-way-merge-of-sorted-shard-streams",
}, function(t)
    local tag = eventd.marker("merge")
    for i = 1, 6 do
        pinned((i - 1) % 2, "pt.fan.merge", { { tag = tag, i = i } })
        os.execute("sleep 0.1")
    end
    local rows = eventd.wait_rows(vm, 'EVENTS pt.fan.merge WHERE tag == "' .. tag .. '"',
        function(rs) return #rs == 6 end)
    t:assert_eq(json.encode(field(rows, "i")), "[6,5,4,3,2,1]", "newest first across both shards")
    local cpus = {}
    for _, r in ipairs(rows) do cpus[r.cpu_id] = true end
    t:assert(cpus[0] and cpus[1], "and the rows did come from both CPUs' shards")
    for k = 2, #rows do
        t:assert(rows[k - 1].timestamp >= rows[k].timestamp, "timestamps never rise down the result")
    end
    local page = eventd.rows(vm, 'EVENTS pt.fan.merge WHERE tag == "' .. tag .. '" SKIP 2 TAKE 3')
    t:assert_eq(json.encode(field(page, "i")), "[4,3,2]", "and a page of the merge is a slice of it")
end)

-- PEI-TBD-group-count-unsorted: Groups::finish emits GROUP results "in
-- the order its groups appeared" (HEAD executor.rs:2048-2089) and
-- emit_aggregate sorts only on an explicit SORT (400-408); only COUNT BY
-- and TOP N BY go through `counted` (2105-2128). v0.1.5 behaves the same.
-- "COUNT BY, TOP N BY, GROUP … COUNT: a count; at the end the groups are
--  sorted by count descending and TAKE applies."
test("counted groups come back by count descending, then TAKE", {
    spec = "eventd *fanout.grouped-counts-are-sorted-descending-then-taken",
    tags = { "known-bug" },
}, function(t)
    local tag = eventd.marker("cnt")
    -- a once, b three times, c twice; a appears first, across both shards.
    pinned(0, "pt.fan.cnt", { { tag = tag, v = "a" }, { tag = tag, v = "b" } })
    pinned(1, "pt.fan.cnt", { { tag = tag, v = "b" }, { tag = tag, v = "c" } })
    pinned(0, "pt.fan.cnt", { { tag = tag, v = "c" }, { tag = tag, v = "b" } })
    local base = 'EVENTS pt.fan.cnt WHERE tag == "' .. tag .. '"'
    eventd.wait_rows(vm, base, function(rs) return #rs == 6 end)
    t:assert_eq(json.encode(field(eventd.rows(vm, base .. " COUNT BY v"), "v")), '["b","c","a"]', "COUNT BY")
    t:assert_eq(json.encode(field(eventd.rows(vm, base .. " TOP 2 BY v"), "v")), '["b","c"]', "TOP 2 BY")
    t:assert_eq(json.encode(field(eventd.rows(vm, base .. " COUNT BY v TAKE 2"), "count")), "[3,2]",
        "COUNT BY with TAKE")
    t:assert_eq(json.encode(field(eventd.rows(vm, base .. " GROUP v COUNT"), "v")), '["b","c","a"]',
        "GROUP … COUNT, by count descending")
    t:assert_eq(json.encode(field(eventd.rows(vm, base .. " GROUP v COUNT TAKE 2"), "count")), "[3,2]",
        "GROUP … COUNT with TAKE keeps the two largest")
end)

-- "GROUP … SUM: the exact integer sum while every value is an integer and
--  it fits, and the binary64 sum."
test("a group sum across shards is exact for integers and binary64 once a float joins", {
    spec = "eventd *fanout.group-sum-keeps-the-exact-and-binary64-sums",
}, function(t)
    local tag = eventd.marker("sum")
    -- 2^53 + 1 and 2: binary64 cannot hold either sum exactly.
    pinned(0, "pt.fan.sum", { { tag = tag, g = "exact", n = 9007199254740993 },
                              { tag = tag, g = "wide", n = 9223372036854775807 },
                              { tag = tag, g = "mixed", n = 2 } })
    pinned(1, "pt.fan.sum", { { tag = tag, g = "exact", n = 2 },
                              { tag = tag, g = "wide", n = 1 },
                              { tag = tag, g = "mixed", n = eventd.float(0.5) } })
    local base = 'EVENTS pt.fan.sum WHERE tag == "' .. tag .. '"'
    eventd.wait_rows(vm, base, function(rs) return #rs == 6 end)
    local r = eventd.query(vm, base .. " GROUP g SUM n SORT g")
    t:assert(r.ok, r.stderr)
    t:assert(r.stdout:find('"g":"exact","sum":9007199254740995', 1, true)
        or r.stdout:find('"sum":9007199254740995', 1, true), "the exact integer sum: " .. r.stdout)
    t:assert(r.stdout:find("9223372036854775808", 1, true), "past i64 it stays exact as an unsigned: " .. r.stdout)
    local mixed
    for _, row in ipairs(r.rows) do if row.g == "mixed" then mixed = row.sum end end
    t:assert_eq(mixed, 2.5, "with a float in the group the sum is binary64")
end)

-- "GROUP … AVG: the binary64 sum and count, divided once at the end."
test("an average across unevenly filled shards is the sum over the count", {
    spec = "eventd *fanout.group-avg-divides-the-whole-sum-by-the-whole-count",
}, function(t)
    local tag = eventd.marker("avg")
    pinned(0, "pt.fan.avg", { { tag = tag, n = 1 } })
    pinned(1, "pt.fan.avg", { { tag = tag, n = 2 }, { tag = tag, n = 3 } })
    local base = 'EVENTS pt.fan.avg WHERE tag == "' .. tag .. '"'
    eventd.wait_rows(vm, base, function(rs) return #rs == 3 end)
    local rows = eventd.rows(vm, base .. " GROUP tag AVG n")
    -- Averaging the shards' averages would give (1 + 2.5) / 2 = 1.75.
    t:assert_eq(rows[1] and rows[1].avg, 2.0, "six over three")
end)

-- "GROUP … MIN / MAX: the extreme so far."
test("the extremes across shards are the extremes of the whole group", {
    spec = "eventd *fanout.group-min-and-max-keep-the-extreme-so-far",
}, function(t)
    local tag = eventd.marker("ext")
    pinned(0, "pt.fan.ext", { { tag = tag, n = 4 }, { tag = tag, n = eventd.float(7.5) }, { tag = tag, n = "text" } })
    pinned(1, "pt.fan.ext", { { tag = tag, n = -5 }, { tag = tag, n = 3 }, { tag = tag } })
    local base = 'EVENTS pt.fan.ext WHERE tag == "' .. tag .. '"'
    eventd.wait_rows(vm, base, function(rs) return #rs == 6 end)
    t:assert_eq(eventd.rows(vm, base .. " GROUP tag MIN n")[1].min, -5, "the minimum, from the other shard")
    t:assert_eq(eventd.rows(vm, base .. " GROUP tag MAX n")[1].max, 7.5, "the maximum, a float")
end)

-- "DISTINCT: the value."
test("DISTINCT across shards gives each value once, in value order", {
    spec = "eventd *fanout.distinct-keeps-each-value",
}, function(t)
    local tag = eventd.marker("dis")
    pinned(0, "pt.fan.dis", { { tag = tag, v = "m" }, { tag = tag, v = "a" }, { tag = tag, v = "z" } })
    pinned(1, "pt.fan.dis", { { tag = tag, v = "a" }, { tag = tag, v = "m" }, { tag = tag, v = "b" } })
    local base = 'EVENTS pt.fan.dis WHERE tag == "' .. tag .. '"'
    eventd.wait_rows(vm, base, function(rs) return #rs == 6 end)
    t:assert_eq(json.encode(field(eventd.rows(vm, base .. " DISTINCT v"), "v")), '["a","b","m","z"]',
        "four values, once each")
end)

-- "A group is found by hashing a key that every pair of language-equal
--  values shares — numbers by their nearest binary64, text with ASCII
--  case folded — and then by the language's own equality."
test("equal values share a group, and values that only share a binary64 do not", {
    spec = "eventd *fanout.groups-are-found-by-a-hash-that-equal-values-share",
}, function(t)
    local tag = eventd.marker("hash")
    pinned(0, "pt.fan.hash", { { tag = tag, v = 1 }, { tag = tag, v = "A" }, { tag = tag, v = 9007199254740992 } })
    pinned(1, "pt.fan.hash", { { tag = tag, v = eventd.float(1.0) }, { tag = tag, v = "a" },
                               { tag = tag, v = 9007199254740993 } })
    local base = 'EVENTS pt.fan.hash WHERE tag == "' .. tag .. '"'
    eventd.wait_rows(vm, base, function(rs) return #rs == 6 end)
    local r = eventd.query(vm, base .. " GROUP v COUNT")
    t:assert(r.ok, r.stderr)
    t:assert_eq(#r.rows, 4, "1 with 1.0, A with a, and the two big integers apart: " .. r.stdout)
    local counts = field(r.rows, "count")
    table.sort(counts)
    t:assert_eq(json.encode(counts), "[1,1,2,2]", "two pairs and two singles")
    t:assert(r.stdout:find("9007199254740992", 1, true) and r.stdout:find("9007199254740993", 1, true),
        "both big integers survive as their own groups: " .. r.stdout)
end)

-- §6.6: "a wake is 'something committed somewhere' and a handler
--  re-examines every shard it cares about."
test("one stream receives events committed to either shard", {
    spec = "eventd *stream.an-event-store-wake-makes-a-handler-re-examine-every-shard",
}, function(t)
    local tag = eventd.marker("wake")
    local etype = "pt.fan.wake" .. tag
    local w = vm:spawn_worker()
    local ok, err = pcall(function()
        local c = rq.open(w)
        rq.timeout(c, 10)
        rq.send(c, "EVENTS " .. etype .. " STREAM")
        rq.frame(c)
        local watch = rq.frame(c)
        t:assert_eq(watch and watch.status, "watch", "the stream is established")
        pinned(0, etype, { { i = 1 } })
        pinned(1, etype, { { i = 2 } })
        pinned(0, etype, { { i = 3 } })
        local got = {}
        while #got < 3 do
            local f = rq.frame(c)
            if not f then break end
            for _, r in ipairs(f.records or {}) do got[#got + 1] = r end
        end
        rq.close(c)
        local cpus = {}
        for _, r in ipairs(got) do cpus[r.cpu_id] = true end
        t:assert_eq(#got, 3, "all three events streamed: " .. json.encode(got))
        t:assert(cpus[0] and cpus[1], "from both shards")
    end)
    w:kill(); w:join()
    if not ok then error(err, 0) end
end)

-- "Active shard writer connections stay open for the process lifetime."
test("each active shard's writer keeps the one read-write descriptor it started with", {
    spec = "eventd *fanout.active-shard-writer-connections-stay-open-for-the-process-lifetime",
}, function(t)
    for i = 1, 20 do eventd.rows(vm, "EVENTS pt.fan.merge TAKE " .. i .. " SELECT i") end
    eventd.rows(vm, "EVENTS COUNT BY event_type")
    pinned(0, "pt.fan.life", { { n = 1 } })
    pinned(1, "pt.fan.life", { { n = 2 } })
    eventd.wait_rows(vm, "EVENTS pt.fan.life", function(rs) return #rs >= 2 end)
    local now = eventd_fds()
    for _, path in ipairs({ SHARD0, SHARD1 }) do
        local first = fds_on(FIRST_FDS, path, 2)
        t:assert_eq(#first, 1, path .. ": one read-write descriptor at the start")
        t:assert_eq(json.encode(fds_on(now, path, 2)), json.encode(first),
            path .. ": the same descriptor after every test so far")
    end
end)

-- ---------------------------------------------------------------------------
-- Active and historical shards
-- ---------------------------------------------------------------------------

local HIST_TAG = eventd.marker("hist")
-- 600 events, 2 KB apiece, across both shards: enough results that a
-- client which stops reading leaves eventd blocked mid-answer.
pinned(SHARD_OF_CPU[0] == 1 and 0 or 1, "pt.fan.hist", (function()
    local p = {}
    for i = 1, 100 do p[i] = { tag = HIST_TAG, i = i, pad = string.rep("h", 2000) } end
    return p
end)())

-- "Event queries execute against every database in the event store
--  directory — active shards and historical ones alike." / "There is no
--  shard a query can skip on the basis of its contents, and a predicate
--  on cpu_id scans all of them."
test("after the shard count drops, the retired shard is still read, cpu_id predicates included", {
    spec = "eventd *fanout.an-event-query-runs-against-every-active-and-historical-shard"
        .. " eventd *fanout.no-shard-is-skipped-even-for-a-cpu-id-predicate",
}, function(t)
    -- The CPU feeding shard 1 now, whose events will outlive its shard.
    local cpu1 = SHARD_OF_CPU[0] == 1 and 0 or 1
    pinned(cpu1, "pt.fan.old", { { tag = HIST_TAG } })
    eventd.wait_rows(vm, 'EVENTS pt.fan.old WHERE tag == "' .. HIST_TAG .. '"', function(rs) return #rs == 1 end)
    eventd.set(vm, "StorageShards", "dword:1"):assert_ok()
    eventd.restart(vm)
    t:assert_eq(#eventd.shards(vm), 2, "shard-0001 is still in the directory")
    -- The same CPU now writes to the one active shard.
    pinned(cpu1, "pt.fan.old", { { tag = HIST_TAG, after = true } })
    local rows = eventd.wait_rows(vm, 'EVENTS pt.fan.old WHERE tag == "' .. HIST_TAG .. '"',
        function(rs) return #rs == 2 end)
    t:assert_eq(#rows, 2, "the event in the historical shard and the new one in the active shard")
    t:assert_eq(eventd.sql(vm, SHARD1,
        "SELECT count(*) FROM events WHERE event_type = 'pt.fan.old'")[1][1], 1,
        "control: one of them is in shard-0001, now historical")
    t:assert_eq(eventd.sql(vm, SHARD0,
        "SELECT count(*) FROM events WHERE event_type = 'pt.fan.old'")[1][1], 1,
        "and the other in shard-0000")
    local by_cpu = eventd.rows(vm, 'EVENTS pt.fan.old WHERE tag == "' .. HIST_TAG .. '" WHERE cpu_id == ' .. cpu1)
    t:assert_eq(#by_cpu, 2, "a cpu_id predicate finds that CPU's events in both shards")
    local hist = eventd.rows(vm, 'EVENTS pt.fan.hist WHERE tag == "' .. HIST_TAG .. '" COUNT BY event_type')
    t:assert_eq(hist[1] and hist[1].count, 100, "the bulk set in the historical shard is read")
end)

-- "An event query opens a read-only connection per database, and each
--  SQLite connection holds one or two descriptors for the database and
--  its write-ahead log."
test("a held event query reads each database, active and historical, through one read-only descriptor", {
    spec = "eventd *fanout.an-event-query-opens-a-read-only-connection-per-database",
}, function(t)
    -- Bulk in the active shard as well.
    pinned(0, "pt.fan.hist", (function()
        local p = {}
        for i = 101, 200 do p[#p + 1] = { tag = HIST_TAG, i = i, pad = string.rep("h", 2000) } end
        return p
    end)())
    eventd.wait_rows(vm, 'EVENTS pt.fan.hist WHERE tag == "' .. HIST_TAG .. '" COUNT BY event_type',
        function(rs) return rs[1] and rs[1].count == 200 end)
    local w = vm:spawn_worker()
    local c = rq.open(w)
    rq.send(c, "EVENTS pt.fan.hist")
    local first = rq.frame(c)
    local during = eventd_fds()
    rq.close(c)
    w:kill(); w:join()
    t:assert_eq(first and first.status, "ok", "the query was answering when held")
    -- Descriptors that SQLite parks after a connection closes are reused
    -- by the next connection to the same file (unix VFS), so what is
    -- counted is the read-only descriptors open at once: one per
    -- database the held query reads.
    for _, path in ipairs({ SHARD0, SHARD1 }) do
        t:assert_eq(#fds_on(during, path, 0), 1, path .. ": one read-only descriptor: " .. json.encode(during))
    end
    t:assert_eq(#fds_on(during, SHARD0, 1), 0, "nothing write-only")
    eventd.unset(vm, "StorageShards")
    eventd.restart(vm)
end)
