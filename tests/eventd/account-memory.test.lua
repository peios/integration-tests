-- eventd TRM §6.5 "Memory" and "Timeouts", with the parts of §6.3 and
-- §6.4 that are only visible through a query's cost: what a query holds
-- against MaxQueryHeldBytes, what the default order holds at all, when
-- the merge stops, what the timeout bounds, and the SQL push-downs whose
-- presence or absence shows up as time.
--
-- One VM with two vCPUs, so the event store has two active shards and
-- "one row per shard" means two. It carries three datasets, built once at
-- file scope:
--
--   pt.mem.wide  3000 events with an 8 KB string apiece. eventd's own
--                estimate of a held row (executor.rs row_size) is about
--                10 KiB for these, so all of them are ~30 MiB, past the
--                16 MiB minimum budget, while the 1024 rows a sorted
--                TAKE keeps before trimming are ~10 MiB, inside it.
--   pt.mem.mid   1000 of the same: ~10 MiB, so one query holding them
--                fits the budget and two do not.
--   pt.mem.slow  900 000 tiny events, about three seconds to read through,
--                for anything that has to outlast QueryTimeoutMs's one
--                second minimum. Every query over it runs with that
--                minimum in force, so none can run long.
--   pt.mem.med   100 000 tiny events, for timing one query precisely.
--
-- A query is "held open" by a raw client that reads its first frame and
-- then stops reading: eventd blocks writing the rest, with whatever the
-- query holds still held.

local eventd = require("helpers.eventd")
local peinit = require("helpers.peinit")
local kmes = require("helpers.kmes")
local sys = require("helpers.sys")
local token = require("helpers.token")
local us = require("helpers.unixsock")
local pc = require("helpers.peinit_client")
peinit.claim(1, { cpus = 2, memory_mib = 2048 })

-- Two vCPUs: two active event shards. 2 GiB: the datasets live on the
-- tmpfs-backed live root.
local vm = eventd.boot({ name = "ev-memory", cpus = 2, memory = "2G" })

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

function rq.collect(c)
    local out = { frames = {}, records = {} }
    while true do
        local m, why = rq.frame(c)
        if not m then out.status = why; return out end
        out.frames[#out.frames + 1] = m
        if m.status == "ok" then
            for _, r in ipairs(m.records) do out.records[#out.records + 1] = r end
        else
            out.status, out.error = m.status, m.error
            return out
        end
    end
end

function rq.close(c) sys.close(c.w, c.fd) end

-- ---------------------------------------------------------------------------
-- Local helpers and the datasets
-- ---------------------------------------------------------------------------

local function now_ns()
    return math.tointeger(tonumber(vm:run("date +%s%N").stdout:match("%d+")))
end

local BUDGET = 16777216 -- MaxQueryHeldBytes's minimum, 16 MiB

local function with_config(values, fn)
    for name, v in pairs(values) do eventd.set(vm, name, "dword:" .. v):assert_ok() end
    os.execute("sleep 1")
    local ok, err = pcall(fn)
    for name in pairs(values) do eventd.unset(vm, name) end
    os.execute("sleep 1")
    if not ok then error(err, 0) end
end

--- Run `text` through evctl, discarding the output, and time it on the
--- guest's clock. Returns exit code, stderr, seconds.
local function timed(text)
    local q = eventd.guest_tmp(vm, text, "q")
    local r = vm:run("a=$(date +%s%N); evctl --format msgpack --file " .. q
        .. " >/dev/null 2>/tmp/pt-mem-err; e=$?; b=$(date +%s%N); echo \"$e $a $b\"; cat /tmp/pt-mem-err")
    local e, a, b = r.stdout:match("^(%d+) (%d+) (%d+)")
    return tonumber(e), r.stdout:gsub("^[^\n]*\n", ""), (tonumber(b) - tonumber(a)) / 1e9
end

local function count_of(etype)
    local r = eventd.query(vm, "EVENTS " .. etype .. " COUNT BY event_type")
    if not r.ok or not r.rows[1] then return 0 end
    return r.rows[1].count
end

--- `n` events of `etype`, `per` to a batch, payload from `make(i)`.
local function emit_many(etype, n, per, make)
    local done = 0
    while done < n do
        local entries = {}
        for k = 1, math.min(per, n - done) do
            entries[k] = { type = etype, payload = make(done + k) }
        end
        local r = kmes.emit_batch(vm, entries)
        assert(r.ret == 0, "kmes_emit_batch: errno " .. tostring(r.errno))
        done = done + #entries
    end
end

local function wide(i) return eventd.msgpack({ n = i, pad = string.rep("w", 8000) .. i }) end

emit_many("pt.mem.wide", 3000, 50, wide)
emit_many("pt.mem.mid", 1000, 50, wide)
local TINY = eventd.msgpack({ k = 1 })
local MED0 = now_ns()
emit_many("pt.mem.med", 100000, 250, function() return TINY end)
local SLOW0 = now_ns()
emit_many("pt.mem.slow", 900000, 250, function() return TINY end)
wait_until(function()
    return count_of("pt.mem.wide") == 3000 and count_of("pt.mem.mid") == 1000
end, { timeout = 120, interval = 2, desc = "the wide datasets" })
-- Counting the tiny sets reads them through, so do it under the default
-- timeout once, with the store settled.
wait_until(function()
    return count_of("pt.mem.med") >= 99000 and count_of("pt.mem.slow") >= 890000
end, { timeout = 180, interval = 5, desc = "the tiny datasets" })

local function rss_kib()
    local status = vm:read_file("/proc/" .. eventd.pid(vm) .. "/status")
    return tonumber(status:match("VmRSS:%s*(%d+)"))
end

--- Start `text` raw, read its first frame, stop reading.
local function stall(text)
    local w = vm:spawn_worker()
    local c = rq.open(w)
    rq.send(c, text)
    local first = rq.frame(c)
    assert(first and first.status == "ok", "the held query started: " .. json.encode(first))
    return c, w, first
end

local function unstall(c, w)
    rq.close(c)
    w:kill(); w:join()
end

-- ---------------------------------------------------------------------------
-- Memory
-- ---------------------------------------------------------------------------

-- "A query in the default order holds one row per shard and nothing more,
--  and is never refused for the size of its result." / "A
--  non-aggregating query without TAKE has no implicit row limit."
test("a default-order query over thirty budgets' worth of rows answers every row", {
    spec = "eventd *account.a-default-order-query-is-never-refused-for-its-size"
        .. " eventd *fanout.a-non-aggregating-query-without-take-has-no-implicit-row-limit",
}, function(t)
    with_config({ MaxQueryHeldBytes = BUDGET }, function()
        local r = eventd.query(vm, "EVENTS pt.mem.wide SELECT n")
        t:assert(r.ok, "not refused: " .. r.stderr)
        t:assert_eq(#r.rows, 3000, "and every row came back")
    end)
end)

-- "A query that would take more than is left fails with an error, rather
--  than being truncated or answered from part of the data."
test("a sorted query that must hold more than the budget fails with an error", {
    spec = "eventd *account.a-query-past-the-held-budget-fails-with-an-error",
}, function(t)
    with_config({ MaxQueryHeldBytes = BUDGET }, function()
        local r = eventd.query(vm, "EVENTS pt.mem.wide SORT n SELECT n")
        t:assert_eq(r.exit_code, 1, "refused rather than answered: " .. #r.rows .. " rows")
        t:assert(r.stderr:find("MaxQueryHeldBytes", 1, true), "for the held budget: " .. r.stderr)
    end)
end)

-- "With TAKE it keeps only the best SKIP + TAKE of them, trimming to that
--  whenever it holds twice as many or a thousand, whichever is more."
test("a sorted query with TAKE over more than the budget answers its best rows", {
    spec = "eventd *fanout.a-sorted-query-with-take-keeps-only-its-best-skip-plus-take-rows",
}, function(t)
    with_config({ MaxQueryHeldBytes = BUDGET }, function()
        local top = eventd.rows(vm, "EVENTS pt.mem.wide SORT n DESC TAKE 5 SELECT n")
        local got = {}
        for i, r in ipairs(top) do got[i] = r.n end
        t:assert_eq(json.encode(got), "[3000,2999,2998,2997,2996]", "the five largest")
        local page = eventd.rows(vm, "EVENTS pt.mem.wide SORT n SKIP 300 TAKE 3 SELECT n")
        got = {}
        for i, r in ipairs(page) do got[i] = r.n end
        t:assert_eq(json.encode(got), "[301,302,303]", "a page from the middle")
    end)
end)

-- "Rows from every shard fold into one set of groups as they are read,
--  and no row is kept."
test("aggregations over more than the budget in rows succeed when their groups are few", {
    spec = "eventd *fanout.aggregating-queries-fold-rows-into-groups-as-they-are-read",
}, function(t)
    with_config({ MaxQueryHeldBytes = BUDGET }, function()
        local c = eventd.rows(vm, "EVENTS pt.mem.wide COUNT BY event_type")
        t:assert_eq(c[1] and c[1].count, 3000, "COUNT BY over every row")
        local g = eventd.rows(vm, "EVENTS pt.mem.wide GROUP event_type MAX n")
        t:assert_eq(g[1] and g[1].max, 3000, "GROUP MAX over every row")
        local s = eventd.rows(vm, "EVENTS pt.mem.wide GROUP event_type SUM n")
        t:assert_eq(s[1] and s[1].sum, 4501500, "GROUP SUM over every row")
    end)
end)

-- "What an aggregation holds is bounded by the number of its groups
--  rather than by its rows, within MaxQueryHeldBytes."
test("the same rows aggregated into thousands of large groups pass the budget and fail", {
    spec = "eventd *fanout.aggregation-memory-is-bounded-by-group-cardinality",
}, function(t)
    with_config({ MaxQueryHeldBytes = BUDGET }, function()
        local few = eventd.query(vm, "EVENTS pt.mem.wide COUNT BY event_type")
        t:assert(few.ok, "one group over 3000 rows fits: " .. few.stderr)
        local many = eventd.query(vm, "EVENTS pt.mem.wide DISTINCT pad")
        t:assert_eq(many.exit_code, 1, "3000 groups of 8 KB each do not")
        t:assert(many.stderr:find("MaxQueryHeldBytes", 1, true), many.stderr)
    end)
end)

-- "Everything else a query must hold ... counts against
--  MaxQueryHeldBytes, one budget for every running query together." / "A
--  query takes from it in 64 KiB granules as it grows ... and gives back
--  all of it when it ends."
test("a held sorted query's reservation refuses a second like it, until the first ends", {
    spec = "eventd *account.max-query-held-bytes-bounds-what-all-running-queries-hold-together"
        .. " eventd *account.held-memory-is-reserved-in-granules-and-given-back",
}, function(t)
    with_config({ MaxQueryHeldBytes = BUDGET }, function()
        local alone = eventd.query(vm, "EVENTS pt.mem.mid SORT n SELECT n")
        t:assert(alone.ok and #alone.rows == 1000, "alone, the mid set fits the budget: " .. alone.stderr)
        -- Unprojected, its result is ~8 MB, so eventd blocks sending it.
        local c, w = stall("EVENTS pt.mem.mid SORT n")
        local second = eventd.query(vm, "EVENTS pt.mem.mid SORT n SELECT n")
        unstall(c, w)
        t:assert_eq(second.exit_code, 1, "while the first holds its rows, a second is refused")
        t:assert(second.stderr:find("MaxQueryHeldBytes", 1, true), second.stderr)
        local ok = pcall(wait_until, function()
            return eventd.query(vm, "EVENTS pt.mem.mid SORT n SELECT n").ok
        end, { timeout = 30, interval = 1, desc = "the budget to come back" })
        t:assert(ok, "once the first has ended its reservation is given back")
    end)
end)

-- "What the query holds is one row per shard, the merge frontier,
--  whatever the size of its result." / "Each row that passes access
--  control and every predicate is sent as soon as it is taken."
test("a held default-order query over 30 MB of rows holds almost none of it, and starts sending at once", {
    spec = "eventd *fanout.a-default-order-query-holds-one-row-per-shard"
        .. " eventd *fanout.merged-results-are-streamed-incrementally-not-materialised",
}, function(t)
    with_config({ MaxQueryHeldBytes = BUDGET }, function()
        local before = rss_kib()
        local w0 = os.time()
        local c, w, first = stall("EVENTS pt.mem.wide")
        local waited = os.time() - w0
        os.execute("sleep 1")
        local during = rss_kib()
        -- The held query takes nothing from the budget either.
        local sorted = eventd.query(vm, "EVENTS pt.mem.mid SORT n SELECT n")
        unstall(c, w)
        t:assert(#first.records >= 1, "the first frame carried records")
        t:assert(waited <= 2, "the first frame came at once: " .. waited .. " s")
        t:assert(during - before < 10240,
            "eventd grew by " .. (during - before) .. " KiB while holding the query: far less than its 30 MB result")
        t:assert(sorted.ok, "a 10 MB sorted query runs beside it: " .. sorted.stderr)
    end)
end)

-- "A metric query reads each series' samples in order and holds none of
--  them: a transform keeps only the sample before, and an aggregation
--  folds each sample into its window, or its series, as it is read."
local METRIC = "ptmem" .. eventd.marker()
do
    local base = now_ns() - 1800 * 1000000000
    for b = 0, 39 do
        local samples = {}
        for i = 1, 1000 do
            local k = b * 1000 + i
            samples[i] = { name = METRIC, type = "counter", value = k, timestamp = base + k * 10000000,
                           labels = { host = "h1", pad = string.rep("l", 60) } }
        end
        local r = eventd.send_metric(vm, samples)
        assert(r.ret and r.ret > 0, "metric sendto: errno " .. tostring(r.errno))
        os.execute("sleep 0.1")
    end
end

test("aggregations over forty thousand samples fold within the budget", {
    spec = "eventd *account.a-metric-query-folds-samples-as-it-reads-them",
}, function(t)
    eventd.wait_rows(vm, "METRIC " .. METRIC .. " SINCE 1h ago MAX",
        function(rs) return rs[1] and rs[1].value == 40000 end, { timeout = 60 })
    with_config({ MaxQueryHeldBytes = BUDGET }, function()
        local max = eventd.query(vm, "METRIC " .. METRIC .. " SINCE 1h ago MAX")
        t:assert(max.ok, "a scalar aggregation: " .. max.stderr)
        t:assert_eq(max.rows[1] and max.rows[1].value, 40000, "folded every sample")
        local win = eventd.query(vm, "METRIC " .. METRIC .. " RATE SINCE 1h ago AVG_OVER 1m")
        t:assert(win.ok, "a transform and a window aggregation: " .. win.stderr)
        t:assert(#win.rows >= 6 and #win.rows <= 62, "one row per window: " .. #win.rows)
    end)
end)

-- "A query whose result is the samples themselves — a range without an
--  aggregation — holds them all, and is refused when they pass the budget
--  like a sorted query."
test("the raw range of forty thousand samples is refused once it passes the budget", {
    spec = "eventd *account.a-metric-querys-held-series-folds-and-rows-count-against-the-budget",
}, function(t)
    eventd.wait_rows(vm, "METRIC " .. METRIC .. " SINCE 1h ago MAX",
        function(rs) return rs[1] and rs[1].value == 40000 end, { timeout = 60 })
    with_config({ MaxQueryHeldBytes = BUDGET }, function()
        local raw = eventd.query(vm, "METRIC " .. METRIC .. " SINCE 1h ago")
        t:assert_eq(raw.exit_code, 1, "refused rather than answered: " .. #raw.rows .. " rows")
        t:assert(raw.stderr:find("MaxQueryHeldBytes", 1, true), raw.stderr)
    end)
end)

-- ---------------------------------------------------------------------------
-- Timeouts
-- ---------------------------------------------------------------------------

-- "Every query has a maximum execution time, QueryTimeoutMs." / "On
--  expiry eventd cancels the query and sends an error." / "Non-SQL work —
--  MessagePack flattening, the cross-shard merge — checks the same
--  deadline periodically."
test("a scan that would take seconds ends at the one-second timeout with an error", {
    spec = "eventd *account.every-query-is-bounded-by-query-timeout-ms"
        .. " eventd *account.on-expiry-the-query-is-cancelled-and-an-error-is-sent"
        .. " eventd *account.non-sql-query-work-checks-the-deadline-periodically",
}, function(t)
    with_config({ QueryTimeoutMs = 1000 }, function()
        -- Time goes on decoding and testing each row in eventd, not in
        -- SQLite: no SQL constraint covers a payload field without an
        -- index.
        local code, err, secs = timed("EVENTS pt.mem.slow WHERE nomatch == 1")
        t:assert_eq(code, 1, "the query failed")
        t:assert(err:find("query timed out", 1, true), "with the timeout error: " .. err)
        t:assert(secs < 2.5, "promptly after the deadline: " .. secs .. " s")
        local after = eventd.query(vm, "EVENTS pt.mem.mid TAKE 1")
        t:assert(after.ok, "the cancelled query freed its slot; eventd answers: " .. after.stderr)
    end)
end)

-- "Every query has a maximum execution time": the clock "starts once the
--  request has been decoded and the caller's token obtained, and covers
--  everything after", sending included.
test("time before the request is not charged, and time spent sending is", {
    spec = "eventd *account.the-timeout-starts-after-decoding-and-token-acquisition-and-covers-the-rest",
}, function(t)
    -- How long one scan of the medium set takes here.
    local code, err, d = timed("EVENTS pt.mem.med WHERE nomatch == 1")
    t:assert_eq(code, 0, "the measuring scan ran: " .. err)
    t:assert(d > 0.2, "the medium scan takes measurable time: " .. d .. " s")
    -- A timeout comfortably above that scan, and a pause before the
    -- request that, added to the scan, overruns it.
    local timeout = math.max(1000, math.ceil(d * 1600))
    -- Half a scan short of the timeout: inside the read timeout eventd
    -- puts on a request, and half a scan past the timeout once the scan
    -- is added.
    local pause = timeout / 1000 - d / 2
    t:log(string.format("scan %.2fs, timeout %dms, pause %.2fs", d, timeout, pause))
    local w = vm:spawn_worker()
    local ok, e2 = pcall(with_config, { QueryTimeoutMs = timeout }, function()
        local c = rq.open(w)
        rq.timeout(c, 30)
        os.execute(string.format("sleep %.2f", pause))
        rq.send(c, "EVENTS pt.mem.med WHERE nomatch == 1")
        local res = rq.collect(c)
        rq.close(c)
        t:assert_eq(res.status, "end", "the scan completed, the pause not counted: " .. tostring(res.error))
        -- Sending is covered: a reader that stops for longer than the
        -- timeout never gets to the end.
        local slow = rq.open(w)
        rq.timeout(slow, 30)
        rq.send(slow, "EVENTS pt.mem.wide")
        local first = rq.frame(slow)
        t:assert(first and first.status == "ok", "the result began")
        os.execute(string.format("sleep %.2f", timeout / 1000 + 1.5))
        local rest = rq.collect(slow)
        rq.close(slow)
        t:assert(rest.status ~= "end", "a reader that stalled past the timeout gets no end: "
            .. tostring(rest.status) .. " after " .. #rest.records .. " more records")
    end)
    w:kill(); w:join()
    if not ok then error(e2, 0) end
end)

-- "In the default order that costs time and no memory, so the query
--  timeout is the only backstop."
test("an unbounded query over a large store ends at the timeout, not at a size limit", {
    spec = "eventd *fanout.the-query-timeout-is-the-only-backstop-for-an-unbounded-query",
}, function(t)
    with_config({ QueryTimeoutMs = 1000, MaxQueryHeldBytes = BUDGET }, function()
        local code, err = timed("EVENTS pt.mem.slow")
        t:assert_eq(code, 1, "the unbounded query did not complete within a second")
        t:assert(not err:find("MaxQueryHeldBytes", 1, true), "it was not refused for its size: " .. err)
    end)
end)

-- "Once SKIP + TAKE rows have passed, the merge stops."
test("TAKE over a store too large to read within the timeout still answers", {
    spec = "eventd *fanout.with-take-the-merge-stops-once-skip-plus-take-rows-have-passed",
}, function(t)
    with_config({ QueryTimeoutMs = 1000 }, function()
        local code, err = timed("EVENTS pt.mem.slow TAKE 5")
        t:assert_eq(code, 0, "TAKE 5 answered within the second: " .. err)
        code, err = timed("EVENTS pt.mem.slow SKIP 1000 TAKE 5")
        t:assert_eq(code, 0, "and so did SKIP 1000 TAKE 5: " .. err)
    end)
end)

-- "A top-level comparison of timestamp with an integer narrows that range
--  further ... One inside an OR does not narrow, since it need not hold."
test("a top-level timestamp bound skips the rows it excludes, and one inside OR does not", {
    spec = "eventd *sql.a-top-level-timestamp-comparison-narrows-the-range-read",
}, function(t)
    with_config({ QueryTimeoutMs = 1000 }, function()
        -- Every slow event is newer than SLOW0. Bounded above by it, the
        -- read covers none of them.
        local code, err = timed("EVENTS pt.mem.slow WHERE timestamp < " .. SLOW0 .. " WHERE nomatch == 1")
        t:assert_eq(code, 0, "the narrowed read finishes inside the second: " .. err)
        code, err = timed("EVENTS pt.mem.slow WHERE (timestamp < " .. SLOW0 .. " OR nomatch == 1)")
        t:assert_eq(code, 1, "inside OR the bound narrows nothing, and the full read times out")
    end)
end)

-- TRM-aggregation-pushdown: eventd never sends an aggregation to SQL. It
-- folds every row in Rust (HEAD executor.rs:294-297, 1997-2046; v0.1.5
-- aggregate_records over the materialised rows), which is exactly what
-- the TRM's own §6.4 describes ("Rows from every shard fold into one set
-- of groups as they are read"); §6.3's push-down was never built.
-- "Aggregation is pushed into SQL wherever the storage engine can express
--  it, which is most of the time for simple grouping over columns."
test("counting by a header column answers as fast as SQL can count", {
    spec = "eventd *sql.aggregation-is-pushed-into-sql-except-where-sql-cannot-reproduce-the-comparison",
    tags = { "known-bug" },
}, function(t)
    with_config({ QueryTimeoutMs = 1000 }, function()
        -- A SQL GROUP BY over 900 000 rows of one column is a fraction of
        -- a second; reading and decoding each row is several seconds.
        local code, err = timed("EVENTS pt.mem.slow COUNT BY event_type")
        t:assert_eq(code, 0, "COUNT BY event_type over 900 000 rows answered within a second: " .. err)
    end)
end)

-- "SQLite work is interrupted through sqlite3_interrupt or an equivalent
--  progress-handler check."
-- Route closed: no eventd query spends its time inside one SQLite step.
-- Every read is a row-at-a-time scan whose rows come back to Rust, and
-- the aggregation and sorting happen in Rust (see the push-down test
-- above), so a query that runs out of time does so between rows, where
-- the Rust-side check fires first. Making SQLite itself run long would
-- need a statement eventd does not issue. The unit test registers the
-- same progress handler eventd installs (executor.rs open_read_only) on
-- a long recursive query and proves the interruption surfaces as the
-- query timeout.
test("an interrupted SQLite statement is reported as the query timing out", {
    spec = "eventd *account.cancellation-interrupts-in-progress-sqlite-work",
    skip = true,
    covered_by = "cargo:eventd eventd query::executor::tests::sqlite_progress_interrupt_is_reported_as_query_timeout",
}, function() end)
