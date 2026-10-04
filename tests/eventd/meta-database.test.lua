-- eventd TRM §3.5 — the metadata database: `eventd-meta.db`, its four
-- tables, who writes it, and what startup does with it.
--
-- One file-scope VM. The chapter is mostly about a file eventd keeps to
-- itself, so most of it is read straight out of the store with
-- `eventd.sql` (a host-side copy of the database and its WAL). The rest
-- is driven three ways:
--
--   * queries, which move the in-memory frequency counters the policy
--     thread later flushes into `index_counters`;
--   * a live registry change, which (config.rs:1031-1032) makes the
--     policy thread recompute and write the database at once, so a test
--     need not wait out the sixty-minute minimum policy interval;
--   * a stop, an offline edit and a start. eventd is stopped through the
--     service manager (an explicit stop is not a failure, so the
--     Critical policy is not involved), the database is copied to the
--     host, edited with the host's sqlite, written back with its -wal and
--     -shm removed, and eventd is started again. That is how a test plants
--     counters, a desired index set, a malformed schema or a bogus
--     sequence checkpoint before startup reads them.
--
-- The shard-reconfiguration test changes StorageShards and runs last,
-- because it leaves a historical shard behind.

local eventd = require("helpers.eventd")
local peinit = require("helpers.peinit")
peinit.claim(1)

local vm = eventd.boot({ name = "ev-meta" })

-- ---------------------------------------------------------------------------
-- Local helpers
-- ---------------------------------------------------------------------------

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

local function host_read(path)
    local f = assert(io.open(path, "rb"))
    local s = f:read("a")
    f:close()
    return s
end

--- Run `script` against a guest database while eventd is stopped: copy
--- it (and its WAL) to the host, apply the SQL there, fold the WAL back
--- into the main file, and write the result over the guest's copy with
--- the stale -wal and -shm removed.
local function host_edit(db, script)
    local dir = host_tmpdir()
    host_write(dir .. "/db", vm:read_file(db))
    local okw, wal = pcall(vm.read_file, vm, db .. "-wal")
    if okw and wal and #wal > 0 then host_write(dir .. "/db-wal", wal) end
    host_write(dir .. "/edit.sql", script)
    host_write(dir .. "/run.py", [[
import sqlite3, sys
d = sys.argv[1]
c = sqlite3.connect(d + "/db")
c.executescript(open(d + "/edit.sql").read())
c.commit()
c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
c.close()
]])
    local p = assert(io.popen("python3 " .. dir .. "/run.py " .. dir .. " 2>&1", "r"))
    local out = p:read("a")
    local ok = p:close()
    assert(ok, "host sqlite edit failed: " .. out)
    local bytes = host_read(dir .. "/db")
    os.execute("rm -rf '" .. dir .. "'")
    vm:run("rm -f '" .. db .. "-wal' '" .. db .. "-shm'"):assert_ok()
    vm:write_file(db, bytes)
end

local function stop_eventd()
    vm:run("svctl stop eventd"):assert_ok()
    wait_until(function() return eventd.pid(vm) == nil end,
        { timeout = 60, interval = 0.25, desc = "eventd to stop" })
end

local function start_eventd()
    vm:run("svctl start eventd"):assert_ok()
    eventd.ready(vm)
end

local function guest_now_ns()
    return math.tointeger(tonumber((vm:run("date +%s%N").stdout:gsub("%s", ""))))
end

--- The kernel boot ID in the PCDS byte layout eventd stores, as the
--- uppercase hex SQLite's hex() prints.
local function boot_pcds_hex()
    local u = vm:run("cat /proc/sys/kernel/random/boot_id").stdout:gsub("%s", ""):gsub("-", "")
    local b = {}
    for i = 1, 32, 2 do b[#b + 1] = u:sub(i, i + 1) end
    local out = {}
    for _, i in ipairs({ 4, 3, 2, 1, 6, 5, 8, 7, 9, 10, 11, 12, 13, 14, 15, 16 }) do
        out[#out + 1] = b[i]
    end
    return table.concat(out):upper()
end

local function startups()
    local rows = eventd.rows(vm, "EVENTS " .. eventd.T.startup .. " SINCE 1d ago")
    table.sort(rows, function(a, b) return a.timestamp < b.timestamp end)
    return rows
end

--- Run `n` event queries that each filter on `field`.
local function query_on(field, n)
    for _ = 1, n do
        eventd.rows(vm, "EVENTS pt.meta.none WHERE " .. field .. " == 1 SINCE 1m ago")
    end
end

--- Make an applied configuration change, which makes the policy thread
--- recompute and write the database now (config.rs:1031-1032), and put
--- the value back. RetentionDeleteBatchRows is chosen because nothing in
--- this file depends on it.
local bump = 0
local function nudge_policy()
    bump = bump + 1
    eventd.set(vm, "RetentionDeleteBatchRows", "dword:" .. (2000 + bump)):assert_ok()
    vm:clock():sleep("2s")
end

local function counter(field)
    local rows = eventd.sql(vm, eventd.DB.meta,
        "SELECT query_count, window_start FROM index_counters WHERE field_path = '" .. field .. "'")
    return rows[1]
end

local function columns(db, tbl)
    local out = {}
    for _, r in ipairs(eventd.sql(vm, db,
        "SELECT name, type, \"notnull\", pk FROM pragma_table_info('" .. tbl .. "') ORDER BY cid")) do
        out[#out + 1] = { name = r[1], type = r[2], notnull = r[3], pk = r[4] }
    end
    return out
end

--- Every file descriptor eventd holds on `path` itself (not its sidecars),
--- with its open flags' access mode: 0 read-only, 2 read-write.
local function fds_on(path)
    local pid = assert(eventd.pid(vm), "eventd is running")
    local r = vm:run("for f in /proc/" .. pid .. "/fd/*; do l=$(readlink $f); "
        .. "echo \"$l $(sed -n 's/^flags:[[:space:]]*//p' /proc/" .. pid .. "/fdinfo/${f##*/})\"; done")
    local out = {}
    for line in r.stdout:gmatch("[^\n]+") do
        local target, flags = line:match("^(%S+) (%d+)$")
        if target == path then out[#out + 1] = tonumber(flags, 8) & 3 end
    end
    return out
end

-- ---------------------------------------------------------------------------
-- What it is
-- ---------------------------------------------------------------------------

test("eventd-meta.db is the one database in the event store that is not a shard, and queries pass it by", {
    spec = "eventd *meta.eventd-meta-db-is-the-one-non-shard-database-in-the-event-store-directory"
        .. " eventd *meta.the-query-path-excludes-the-metadata-database",
}, function(t)
    local metas, others = 0, {}
    for _, e in ipairs(vm:listdir(eventd.STORE.events)) do
        local n = type(e) == "table" and e.name or e
        if n:match("%.db$") then
            if n == "eventd-meta.db" then
                metas = metas + 1
            elseif not n:match("^shard%-%d%d%d%d%.db$") then
                others[#others + 1] = n
            end
        end
    end
    t:assert_eq(metas, 1, "exactly one eventd-meta.db in the event store directory")
    t:assert_eq(#others, 0, "every other database there is a shard: " .. table.concat(others, ", "))
    -- The metadata database has no events table: a fan-out that opened it
    -- as a shard would fail, not merely return nothing.
    local r = eventd.query(vm, "EVENTS SINCE 1d ago TAKE 50")
    t:assert(r.ok, "an all-shards event query succeeds beside it: " .. tostring(r.stderr))
    t:assert(#r.rows >= 1, "and returns the shards' events")
end)

test("the metadata database holds exactly its four tables, and no access-control state", {
    spec = "eventd *meta.the-index-counters-table-holds-query-frequency-per-field"
        .. " eventd *meta.index-counters-field-path-is-a-text-primary-key-naming-a-field-or-payload-path"
        .. " eventd *meta.desired-indexes-field-path-is-a-text-primary-key"
        .. " eventd *meta.sequence-checkpoints-primary-key-is-boot-id-and-cpu-id"
        .. " eventd *meta.the-meta-table-is-a-key-value-store"
        .. " eventd *meta.meta-key-is-a-text-primary-key"
        .. " eventd *meta.no-access-control-state-is-stored-in-the-metadata-database",
}, function(t)
    local tables = {}
    for _, r in ipairs(eventd.sql(vm, eventd.DB.meta,
        "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")) do
        tables[#tables + 1] = r[1]
    end
    t:assert_eq(table.concat(tables, ","), "desired_indexes,index_counters,meta,sequence_checkpoints",
        "the four tables and nothing else")

    local function shape(tbl)
        local parts = {}
        for _, c in ipairs(columns(eventd.DB.meta, tbl)) do
            parts[#parts + 1] = string.format("%s %s%s%s", c.name, c.type,
                -- A WITHOUT ROWID primary key is implicitly NOT NULL;
                -- the chapter writes it as plain PRIMARY KEY.
                (c.notnull == 1 and c.pk == 0) and " NOT NULL" or "", c.pk > 0 and (" PK" .. c.pk) or "")
        end
        return table.concat(parts, ", ")
    end
    t:assert_eq(shape("index_counters"),
        "field_path TEXT PK1, query_count INTEGER NOT NULL, window_start INTEGER NOT NULL",
        "index_counters columns")
    t:assert_eq(shape("desired_indexes"),
        "field_path TEXT PK1, priority INTEGER NOT NULL, is_expression INTEGER NOT NULL",
        "desired_indexes columns")
    t:assert_eq(shape("sequence_checkpoints"),
        "boot_id BLOB PK1, cpu_id INTEGER PK2, sequence INTEGER NOT NULL, updated_at INTEGER NOT NULL",
        "sequence_checkpoints columns, keyed on (boot_id, cpu_id)")
    t:assert_eq(shape("meta"), "key TEXT PK1, value BLOB NOT NULL", "meta is a key-value table")

    local keys = {}
    for _, r in ipairs(eventd.sql(vm, eventd.DB.meta, "SELECT key FROM meta ORDER BY key")) do
        keys[#keys + 1] = r[1]
    end
    t:assert_eq(table.concat(keys, ","), "created_at,schema_version",
        "the meta table carries only its two required entries — no descriptor")
end)

test("the meta entries are UTF-8 bytes: schema_version and a UTC created_at", {
    spec = "eventd *meta.meta-values-store-strings-as-utf-8-and-binary-as-raw-bytes"
        .. " eventd *meta.meta-requires-schema-version-and-a-utc-created-at-string",
}, function(t)
    local rows = eventd.sql(vm, eventd.DB.meta,
        "SELECT key, typeof(value), CAST(value AS TEXT) FROM meta ORDER BY key")
    local by = {}
    for _, r in ipairs(rows) do by[r[1]] = { ty = r[2], text = r[3] } end
    t:assert_eq(by.schema_version and by.schema_version.ty, "blob", "schema_version is stored as bytes")
    t:assert_eq(by.schema_version and by.schema_version.text, "1", "and those bytes are the UTF-8 text 1")
    t:assert_eq(by.created_at and by.created_at.ty, "blob", "created_at is stored as bytes")
    t:assert(by.created_at and by.created_at.text:match("^%d%d%d%d%-%d%d%-%d%dT%d%d:%d%d:%d%dZ$"),
        "created_at is a UTC YYYY-MM-DDTHH:MM:SSZ string: " .. tostring(by.created_at and by.created_at.text))
end)

-- ---------------------------------------------------------------------------
-- Writing it
-- ---------------------------------------------------------------------------

test("query counts stay in memory until the policy thread flushes them", {
    spec = "eventd *meta.query-handlers-update-in-memory-counters-and-the-policy-thread-flushes-them-each-interval"
        .. " eventd *meta.index-counters-query-count-is-queries-filtering-on-the-field-in-the-current-window"
        .. " eventd *meta.index-counters-window-start-is-nanoseconds-since-the-epoch",
}, function(t)
    local field = eventd.marker("f")
    local before = guest_now_ns()
    query_on(field, 3)
    -- Several seconds with no policy activity: a query handler that wrote
    -- the database itself would have done so by now.
    vm:clock():sleep("4s")
    t:assert_eq(counter(field), nil, "the counts are not in the database before the policy runs")
    nudge_policy()
    local c = counter(field)
    t:assert(c, "the policy thread flushed the counter")
    t:assert_eq(c and c[1], 3, "query_count is the three queries that filtered on it")
    t:assert(c and c[2] >= before - 2 * 10 ^ 9 and c[2] <= guest_now_ns(),
        "window_start is nanoseconds since the epoch, at the first query: " .. tostring(c and c[2]))
    -- A payload path and a header field are recorded by their names.
    query_on("cpu_id", 1)
    nudge_policy()
    t:assert(counter("cpu_id"), "a header field is recorded as its column name")
end)

-- TRM-config-change-recomputes-index-policy: the book has the database
-- written once per policy interval (a1: at least sixty minutes). eventd
-- also recomputes and writes it on every applied configuration change
-- (config.rs:1031-1032, `index_policy.try_send(PolicyMessage::Recompute)`)
-- and once more at shutdown (pipeline.rs:686, PolicyMessage::Stop runs a
-- final recompute). The extra writes are deliberate — a threshold change
-- should take effect without an hour's wait — and the book never says so.
test("the metadata database is written only once per policy interval", {
    spec = "eventd *meta.written-once-per-policy-interval-and-read-at-startup",
    tags = { "known-bug" },
}, function(t)
    local field = eventd.marker("g")
    query_on(field, 2)
    -- A configuration change unrelated to adaptive indexing, well inside
    -- the sixty-minute minimum interval.
    nudge_policy()
    vm:clock():sleep("2s")
    t:assert_eq(counter(field), nil,
        "no policy interval has elapsed, so the counters are not yet in the database")
end)

test("the desired set ranks the most queried field first and marks payload expressions", {
    spec = "eventd *meta.the-desired-indexes-table-holds-the-computed-desired-index-set"
        .. " eventd *meta.desired-indexes-priority-ranks-lower-values-as-higher-priority"
        .. " eventd *meta.desired-indexes-is-expression-is-1-for-a-payload-expression-index-and-0-for-a-column-index",
}, function(t)
    -- 11, not the minimum 10: the create threshold must stay above the
    -- drop threshold (default 10) or the change is ignored.
    eventd.set(vm, "AdaptiveIndexCreateThreshold", "dword:11"):assert_ok()
    vm:clock():sleep("2s")
    local a, b = eventd.marker("pa"), eventd.marker("pb")
    query_on(a, 14)
    query_on("origin_class", 13)
    query_on(b, 12)
    nudge_policy()
    local rows = eventd.sql(vm, eventd.DB.meta,
        "SELECT field_path, priority, is_expression FROM desired_indexes ORDER BY priority")
    eventd.unset(vm, "AdaptiveIndexCreateThreshold")
    local got = {}
    for _, r in ipairs(rows) do got[r[1]] = { prio = r[2], expr = r[3] } end
    t:assert(got[a] and got.origin_class and got[b],
        "all three fields crossed the threshold into the desired set: " .. json.encode(rows))
    if not (got[a] and got.origin_class and got[b]) then return end
    t:assert(got[a].prio < got.origin_class.prio and got.origin_class.prio < got[b].prio,
        "the most queried field has the lowest priority value: " .. json.encode(rows))
    t:assert_eq(got[a].expr, 1, "a payload path is an expression index")
    t:assert_eq(got.origin_class.expr, 0, "a header column is a column index")
end)

test("graceful shutdown writes each CPU's last committed sequence to sequence_checkpoints", {
    spec = "eventd *meta.graceful-shutdown-writes-sequence-checkpoints-after-policy-activity-stops"
        .. " eventd *meta.sequence-checkpoints-boot-id-is-the-boot-the-checkpoint-applies-to"
        .. " eventd *meta.sequence-checkpoints-cpu-id-is-the-cpu-identifier"
        .. " eventd *meta.sequence-checkpoints-sequence-is-the-last-committed-sequence-when-written"
        .. " eventd *meta.sequence-checkpoints-updated-at-is-when-the-checkpoint-was-written",
}, function(t)
    -- The ordering against the final policy flush is not observable from
    -- outside: both land in the same database at shutdown and the WAL is
    -- folded in on close. What is observable is that the write happens at
    -- a graceful stop and what it holds.
    local before = guest_now_ns()
    eventd.restart(vm)
    local after = guest_now_ns()
    local boot = boot_pcds_hex()
    local rows = eventd.sql(vm, eventd.DB.meta,
        "SELECT hex(boot_id), cpu_id, sequence, updated_at FROM sequence_checkpoints "
        .. "WHERE hex(boot_id) = '" .. boot .. "'")
    t:assert_eq(#rows, 1, "one checkpoint for this boot on the one CPU: " .. json.encode(rows))
    local row = rows[1]
    if not row then return end
    t:assert_eq(row[2], 0, "cpu_id names the CPU")
    t:assert(row[4] >= before and row[4] <= after,
        "updated_at is when it was written, within the restart: " .. row[4])
    local shutdowns = eventd.rows(vm, "EVENTS " .. eventd.T.shutdown .. " SINCE 1h ago")
    table.sort(shutdowns, function(x, y) return x.timestamp < y.timestamp end)
    local last = shutdowns[#shutdowns]
    t:assert(last, "the stop recorded a shutdown event")
    local seq
    for _, p in ipairs(last and last.last_sequences or {}) do
        if p.cpu_id == 0 then seq = p.sequence end
    end
    t:assert_eq(row[3], seq,
        "the checkpoint is the last committed sequence the shutdown event also reports")
    local cover = eventd.sql(vm, eventd.shards(vm)[1],
        "SELECT max(last_sequence) FROM receipt_ranges WHERE cpu_id = 0 AND hex(boot_id) = '" .. boot
        .. "' AND last_sequence <= " .. row[3])
    t:assert_eq(cover[1][1], row[3], "and a committed receipt range ends exactly there")
end)

test("startup recovery ignores a sequence checkpoint that disagrees with the receipts", {
    spec = "eventd *meta.startup-recovery-never-uses-sequence-checkpoints"
        .. " eventd *meta.the-sequence-checkpoints-table-is-diagnostic-only",
}, function(t)
    local boot = boot_pcds_hex()
    stop_eventd()
    host_edit(eventd.DB.meta,
        "UPDATE sequence_checkpoints SET sequence = 999999999 WHERE hex(boot_id) = '" .. boot .. "';")
    start_eventd()
    local s = startups()
    local last = s[#s]
    t:assert_eq(last.restart, true, "the start was a restart")
    local resume
    for _, p in ipairs(last.resume_points or {}) do
        if p.cpu_id == 0 then resume = p.sequence end
    end
    t:assert(resume and resume < 999999999,
        "the resume point comes from receipt coverage, not the checkpoint: " .. tostring(resume))
end)

-- ---------------------------------------------------------------------------
-- Startup
-- ---------------------------------------------------------------------------

test("startup loads the persisted counters and desired set and converges the shards to it", {
    spec = "eventd *meta.startup-loads-index-counters-into-memory"
        .. " eventd *meta.startup-loads-desired-indexes-into-memory"
        .. " eventd *meta.startup-discovers-each-shards-material-indexes-and-compares-them-with-the-desired-set",
}, function(t)
    local seed = eventd.marker("seed")
    local now = guest_now_ns()
    stop_eventd()
    host_edit(eventd.DB.meta, string.format([[
INSERT OR REPLACE INTO index_counters VALUES ('%s', 777, %d);
INSERT OR REPLACE INTO index_counters VALUES ('process_guid', 5000, %d);
DELETE FROM desired_indexes;
INSERT INTO desired_indexes VALUES ('process_guid', 0, 0);
]], seed, now, now))
    start_eventd()
    local shard = eventd.shards(vm)[1]
    local made = pcall(wait_until, function()
        return eventd.schema(vm, shard).idx_events_process_guid ~= nil
    end, { timeout = 60, interval = 1, desc = "the seeded desired index to be materialised" })
    t:assert(made, "the writer converged the shard to the desired set it loaded at startup")
    nudge_policy()
    local c = counter(seed)
    t:assert(c and c[1] >= 777,
        "the policy's next write carries the counter it loaded at startup: " .. json.encode(c))
end)

test("a restart neither drops nor rebuilds a materialised index", {
    spec = "eventd *meta.no-index-is-dropped-or-rebuilt-at-startup"
        .. " eventd *meta.index-convergence-resumes-from-each-shards-current-state",
}, function(t)
    local shard = eventd.shards(vm)[1]
    local function rootpage()
        local r = eventd.sql(vm, shard,
            "SELECT rootpage FROM sqlite_master WHERE name = 'idx_events_process_guid'")
        return r[1] and r[1][1]
    end
    local before = rootpage()
    t:assert(before, "precondition: the index from the previous test is material")
    eventd.restart(vm)
    t:assert_eq(rootpage(), before,
        "the same b-tree is still there: the index was neither dropped nor rebuilt")
end)

test("a malformed metadata database is replaced by a fresh one at startup", {
    spec = "eventd *meta.startup-verifies-the-schema-version-and-required-meta-entries",
}, function(t)
    local cases = {
        { "schema_version missing", "DELETE FROM meta WHERE key = 'schema_version';" },
        { "schema_version unrecognised", "UPDATE meta SET value = CAST('2' AS BLOB) WHERE key = 'schema_version';" },
        { "created_at missing", "DELETE FROM meta WHERE key = 'created_at';" },
        { "a required table missing", "DROP TABLE desired_indexes;" },
    }
    for _, case in ipairs(cases) do
        local mark = eventd.marker("bad")
        stop_eventd()
        host_edit(eventd.DB.meta, "INSERT OR REPLACE INTO index_counters VALUES ('" .. mark
            .. "', 1, 1);\n" .. case[2])
        start_eventd()
        local meta = eventd.sql(vm, eventd.DB.meta,
            "SELECT CAST(value AS TEXT) FROM meta WHERE key = 'schema_version'")
        t:assert_eq(meta[1] and meta[1][1], "1", case[1] .. ": the database is valid again")
        local tables = eventd.sql(vm, eventd.DB.meta,
            "SELECT count(*) FROM sqlite_master WHERE type = 'table'")
        t:assert_eq(tables[1][1], 4, case[1] .. ": all four tables are back")
        nudge_policy()
        t:assert_eq(counter(mark), nil, case[1] .. ": and it was recreated, not repaired")
    end
end)

-- PEI-TBD-meta-recreate-silent: the book has eventd log an error when it
-- throws an invalid metadata database away. MetaStore::open
-- (meta_store.rs:80-85) drops and recreates it without a word, and
-- pipeline.rs:64-67 prints nothing either, so the loss of the accumulated
-- adaptation leaves no trace an operator could find.
test("an invalid metadata database is logged as an error and recreated", {
    spec = "eventd *meta.an-invalid-metadata-database-is-logged-and-recreated-from-defaults",
    tags = { "known-bug" },
}, function(t)
    stop_eventd()
    local from = guest_now_ns()
    host_edit(eventd.DB.meta, "DELETE FROM meta WHERE key = 'schema_version';")
    start_eventd()
    local meta = eventd.sql(vm, eventd.DB.meta,
        "SELECT CAST(value AS TEXT) FROM meta WHERE key = 'schema_version'")
    t:assert_eq(meta[1] and meta[1][1], "1", "the database was recreated")
    local logged = false
    pcall(eventd.wait_rows, vm, "LOGS FROM eventd SINCE 5m ago", function(rs)
        for _, r in ipairs(rs) do
            if r.timestamp >= from and r.is_error and r.message:lower():find("meta", 1, true) then
                logged = true
            end
        end
        return logged
    end, { timeout = 15 })
    t:assert(logged, "eventd logged an error naming the metadata database")
end)

test("a missing metadata database is created in WAL mode", {
    spec = "eventd *meta.startup-opens-eventd-meta-db-creating-it-if-absent"
        .. " eventd *meta.created-if-absent-and-opened-in-wal-mode-with-synchronous-normal",
}, function(t)
    -- synchronous=NORMAL is a per-connection setting held in eventd's
    -- memory and leaves no mark in the file; WAL mode is persistent and is
    -- in the header (bytes 18 and 19 are 2 for WAL).
    stop_eventd()
    local db = eventd.DB.meta
    vm:run("rm -f '" .. db .. "' '" .. db .. "-wal' '" .. db .. "-shm'"):assert_ok()
    start_eventd()
    local st = vm:stat(db)
    t:assert(st and st.entry_type == "file", "eventd created eventd-meta.db")
    local header = vm:read_file(db)
    t:assert(#header >= 20, "the file has a database header")
    t:assert_eq(header:byte(19) .. "," .. header:byte(20), "2,2", "the database is in WAL mode")
    t:assert_eq(#eventd.sql(vm, db, "SELECT 1 FROM meta WHERE key = 'created_at'"), 1,
        "and it was initialised with its entries")
end)

-- ---------------------------------------------------------------------------
-- Concurrency
-- ---------------------------------------------------------------------------

test("the metadata database has one connection, read-write, and no reader", {
    spec = "eventd *meta.only-the-index-policy-thread-opens-the-database-read-write"
        .. " eventd *meta.writers-and-query-handlers-read-desired-sets-from-memory-not-the-database",
}, function(t)
    -- A descriptor on the main database file is a SQLite connection. One,
    -- read-write, while writers ingest and queries run, is the policy
    -- thread's alone: a writer or query handler that read the desired set
    -- from the database would need a connection of its own.
    local pid = eventd.pid(vm)
    local threads = vm:run("cat /proc/" .. pid .. "/task/*/comm").stdout
    t:assert(threads:find("eventd-index-po", 1, true), "there is an index policy thread")
    eventd.emit(vm, "pt.meta.load", { n = 1 })
    for _ = 1, 3 do eventd.rows(vm, "EVENTS SINCE 1h ago TAKE 20") end
    local fds = fds_on(eventd.DB.meta)
    t:assert_eq(#fds, 1, "one descriptor on eventd-meta.db: " .. json.encode(fds))
    t:assert_eq(fds[1], 2, "and it is read-write")
end)

test("the policy thread checkpoints the metadata WAL once it reaches WalCheckpointPages", {
    spec = "eventd *meta.the-policy-thread-checkpoints-passively-at-walcheckpointpages-without-blocking",
}, function(t)
    -- Fill index_counters with long field names so each policy write is
    -- dozens of pages, lower the threshold to its minimum, and watch the
    -- WAL: a checkpoint lets the next write start the log over, which
    -- changes its salt.
    local function salt()
        local ok, wal = pcall(vm.read_file, vm, eventd.DB.meta .. "-wal")
        if not ok or #wal < 32 then return nil, 0 end
        local pagesize, _, s1 = string.unpack(">I4I4I4", wal, 9)
        return s1, #wal // (pagesize + 24)
    end
    local prefix = eventd.marker("w") .. string.rep("x", 60)
    for q = 1, 15 do
        local parts = {}
        for i = 1, 100 do parts[#parts + 1] = "WHERE " .. prefix .. q .. "_" .. i .. " == 1" end
        eventd.rows(vm, "EVENTS pt.meta.none " .. table.concat(parts, " ") .. " SINCE 1m ago")
    end
    eventd.set(vm, "WalCheckpointPages", "dword:100"):assert_ok()
    vm:clock():sleep("2s")
    local s0 = salt()
    local changed = false
    for _ = 1, 8 do
        nudge_policy()
        local s = salt()
        if s ~= s0 then changed = true; break end
    end
    eventd.unset(vm, "WalCheckpointPages")
    t:assert(changed, "the metadata WAL was checkpointed and restarted after crossing the threshold")
end)

-- No VM route and no unit test: eventd does not load sequence_checkpoints
-- at all (pipeline.rs:64-68 loads only the index state), and nothing it
-- exposes — queries, the diagnostic dump — reports them, so whether a
-- startup reads the table "for diagnostics" has no observable effect.
test("startup loads sequence_checkpoints for diagnostics only", {
    spec = "eventd *meta.startup-loads-sequence-checkpoints-for-diagnostics-only",
    skip = true,
}, function() end)

-- ---------------------------------------------------------------------------
-- Shard reconfiguration (last: it leaves a historical shard behind)
-- ---------------------------------------------------------------------------

test("the metadata database survives a shard reconfiguration untouched", {
    spec = "eventd *meta.the-metadata-database-survives-shard-reconfiguration-untouched",
}, function(t)
    local mark = eventd.marker("keep")
    query_on(mark, 2)
    nudge_policy()
    local created = eventd.sql(vm, eventd.DB.meta,
        "SELECT CAST(value AS TEXT) FROM meta WHERE key = 'created_at'")[1][1]
    eventd.set(vm, "StorageShards", "dword:2"):assert_ok()
    eventd.restart(vm)
    t:assert_eq(#eventd.shards(vm), 2, "eventd now runs two shards")
    t:assert_eq(eventd.sql(vm, eventd.DB.meta,
        "SELECT CAST(value AS TEXT) FROM meta WHERE key = 'created_at'")[1][1], created,
        "the metadata database is the same one")
    local c = counter(mark)
    t:assert(c and c[1] >= 2, "and its counters came through: " .. json.encode(c))
    eventd.unset(vm, "StorageShards")
    eventd.unset(vm, "RetentionDeleteBatchRows")
    eventd.restart(vm)
end)
