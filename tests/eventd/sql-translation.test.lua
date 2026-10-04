-- eventd TRM §6.3 — SQL translation: what becomes SQL, what is decided
-- after loading, where access control sits, and aggregation.
--
-- The translation is internal, so most statements here are observed as
-- answers: a predicate the TRM says becomes SQL must give exactly the
-- query language's answer, with and without the adaptive index that
-- lets SQL narrow it. An index is made material on demand with `EVENTS
-- INDEX <field>` (SYSTEM holds EVENTD_ADMINISTER), and its presence is
-- read back from the shard's schema before the comparison is trusted.
--
-- Filtering-first is observed from a second caller: an ordinary user (in
-- Administrators, the only non-system principals the query socket's
-- directory admits) for whom one log origin is made unreadable by its
-- own descriptor. Its answers — counts, order, pages — must be exactly
-- what the readable rows alone would give.
--
-- The aggregation push-down and the timestamp narrowing are observed by
-- their cost, against a dataset large enough to need it, and live in
-- account-memory.test.lua beside that dataset.
--
-- One file-scope VM, one vCPU.

local eventd = require("helpers.eventd")
local peinit = require("helpers.peinit")
local sys = require("helpers.sys")
local token = require("helpers.token")
local us = require("helpers.unixsock")
local pc = require("helpers.peinit_client")
peinit.claim(1)

local vm = eventd.boot({ name = "ev-sql" })

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

--- A token for an ordinary user, `rid` naming which one. In
--- Administrators because /run/eventd admits SYSTEM, Administrators and
--- eventd's own service SID and nothing else.
function rq.user(w, rid)
    local tok = pc.mint_admin(w, token.sid(5, 21, 1278, 6, 6, rid))
    assert(tok, "minting user " .. rid)
    return tok
end

function rq.open(w, tok)
    local fd, err = pc.connect_as(w, eventd.SOCKET.query, us.SOCK.STREAM, tok)
    assert(fd, "connect to the query socket: " .. tostring(err))
    return { w = w, fd = fd, buf = "" }
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

--- Run one query as user `rid` on a fresh connection.
local function as_user(rid, text)
    local w = vm:spawn_worker()
    local ok, res = pcall(function()
        local c = rq.open(w, rq.user(w, rid))
        rq.send(c, text)
        local out = rq.collect(c)
        rq.close(c)
        return out
    end)
    w:kill(); w:join()
    if not ok then error(res, 0) end
    return res
end

-- ---------------------------------------------------------------------------
-- Local helpers
-- ---------------------------------------------------------------------------

local function now_ns()
    return math.tointeger(tonumber(vm:run("date +%s%N").stdout:match("%d+")))
end

local function emit(etype, payload)
    local r = eventd.emit(vm, etype, payload)
    assert(r.ret == 0, "kmes_emit: errno " .. tostring(r.errno))
end

local function logs(records)
    local r = eventd.send_log(vm, records)
    assert(r.ret and r.ret > 0, "log sendto: errno " .. tostring(r.errno))
end

local function field(rows, name)
    local out = {}
    for i, r in ipairs(rows) do out[i] = r[name] end
    return out
end

--- Make the adaptive payload index on `path` material, and wait until
--- every shard has it.
local function materialise_index(t, path)
    local r = eventd.query(vm, "EVENTS INDEX " .. path)
    t:assert(r.ok, "INDEX " .. path .. ": " .. r.stderr)
    local ok = pcall(wait_until, function()
        for _, shard in ipairs(eventd.shards(vm)) do
            local found = eventd.sql(vm, shard,
                "SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_events_payload_%' AND sql LIKE '%"
                .. path .. "%'")
            if found[1][1] == 0 then return false end
        end
        return true
    end, { timeout = 90, interval = 1, desc = "the payload index on " .. path })
    t:assert(ok, "the payload index on " .. path .. " became material in every shard")
end

-- ---------------------------------------------------------------------------
-- The translation is internal
-- ---------------------------------------------------------------------------

-- "Clients never see any of it — the translation is entirely internal
--  and carries no guarantees."
test("no record or error a client receives carries SQL, and SQL syntax in a literal is only text", {
    spec = "eventd *sql.clients-never-see-the-generated-sql",
}, function(t)
    local tag = eventd.marker("inj")
    local hostile = "x' OR '1'='1"
    emit("pt.sql.inj", { tag = tag, s = hostile })
    emit("pt.sql.inj", { tag = tag, s = "other" })
    eventd.wait_rows(vm, 'EVENTS pt.sql.inj WHERE tag == "' .. tag .. '"', function(rs) return #rs == 2 end)
    local rows = eventd.rows(vm, 'EVENTS pt.sql.inj WHERE tag == "' .. tag .. '" WHERE s == "' .. hostile .. '"')
    t:assert_eq(#rows, 1, "the quote-laden literal matched as plain text")
    local none = eventd.rows(vm, 'EVENTS pt.sql.inj WHERE event_type == "pt.sql.inj\' OR \'1\'=\'1"')
    t:assert_eq(#none, 0, "and in a header comparison it selects nothing")

    local seen = {}
    local function keep(r) seen[#seen + 1] = r.stdout .. r.stderr end
    keep(eventd.query(vm, 'EVENTS pt.sql.inj WHERE tag == "' .. tag .. '"'))
    keep(eventd.query(vm, "EVENTS pt.sql.inj WHERE cpu_id > \"x\""))
    keep(eventd.query(vm, "METRIC pt.sql.none RATE SINCE 1h ago"))
    keep(eventd.query(vm, "EVENTS SINCE 30d ago WHERE LOG pt-none EXISTS"))
    vm:rename(eventd.DB.logs, eventd.DB.logs .. ".pt-aside")
    keep(eventd.query(vm, "LOGS TAKE 1"))
    vm:rename(eventd.DB.logs .. ".pt-aside", eventd.DB.logs)
    for _, text in ipairs(seen) do
        for _, sql in ipairs({ "SELECT ", "FROM events", "FROM logs", "sqlite_master", "COLLATE", "?1" }) do
            t:assert(not text:find(sql, 1, true), "no '" .. sql .. "' in: " .. text)
        end
    end
end)

-- ---------------------------------------------------------------------------
-- What translates directly
-- ---------------------------------------------------------------------------

-- "Event header fields are columns, so a predicate on one can become a
--  SQL WHERE comparison over an indexable column."
test("header predicates answer exactly as the query language says", {
    spec = "eventd *sql.an-event-header-predicate-becomes-a-sql-where-comparison",
}, function(t)
    local tag = eventd.marker("hdr")
    emit("pt.sql.hdr", { tag = tag })
    local base = 'EVENTS SINCE 10m ago WHERE tag == "' .. tag .. '"'
    local rows = eventd.wait_rows(vm, base, function(rs) return #rs == 1 end)
    local ev = rows[1]
    local function n(extra) return #eventd.rows(vm, base .. " WHERE " .. extra) end
    t:assert_eq(n('event_type == "PT.SQL.HDR"'), 1, "event_type folds ASCII case")
    t:assert_eq(n('event_type == "pt.sql.hdr2"'), 0, "and is not a prefix match")
    t:assert_eq(n("cpu_id == " .. ev.cpu_id), 1, "cpu_id ==")
    t:assert_eq(n("cpu_id != " .. ev.cpu_id), 0, "cpu_id !=")
    t:assert_eq(n("cpu_id >= " .. ev.cpu_id), 1, "cpu_id >=")
    t:assert_eq(n("cpu_id < " .. ev.cpu_id), 0, "cpu_id <")
    t:assert_eq(n("origin_class == userspace"), 1, "origin_class by its alias")
    t:assert_eq(n("origin_class == USERSPACE"), 1, "the alias folds case")
    t:assert_eq(n("origin_class == 0"), 1, "origin_class by number")
    t:assert_eq(n("origin_class > 0"), 0, "origin_class ordering")
    local guid = ev.process_guid
    t:assert_eq(n('process_guid == "' .. guid .. '"'), 1, "process_guid, applied after loading")
    local bare = guid:gsub("[{}]", ""):upper()
    t:assert_eq(n('process_guid == "' .. bare .. '"'), 1, "in its brace-free upper-case form too")
    t:assert_eq(n("cpu_id == 0.5"), 0, "a non-integer literal is compared, not truncated")
end)

-- "Log fields are all columns; log mode has no payload and its field set
--  is closed."
test("a log record is exactly its six fields, each one queryable, and no other name is a field", {
    spec = "eventd *sql.every-log-field-is-a-column",
}, function(t)
    local o = eventd.marker("cols")
    local job = string.rep("\x11", 16)
    local ts = now_ns() - 30 * 1000000000
    logs({ origin = o, is_error = true, message = "the line", timestamp = ts, job_id = eventd.bin(job) })
    local rows = eventd.wait_rows(vm, "LOGS FROM " .. o, function(rs) return #rs == 1 end)
    local keys = {}
    for k in pairs(rows[1]) do keys[#keys + 1] = k end
    table.sort(keys)
    t:assert_eq(table.concat(keys, ","), "boot_id,is_error,job_id,message,origin,timestamp",
        "the record's fields")
    local function n(pred) return #eventd.rows(vm, "LOGS FROM " .. o .. " WHERE " .. pred) end
    t:assert_eq(n("timestamp == " .. ts), 1, "timestamp")
    t:assert_eq(n('origin == "' .. o:upper() .. '"'), 1, "origin")
    t:assert_eq(n("is_error == true"), 1, "is_error")
    t:assert_eq(n('message CONTAINS "LINE"'), 1, "message")
    t:assert_eq(n('boot_id == "' .. rows[1].boot_id .. '"'), 1, "boot_id")
    t:assert_eq(n('job_id == "11111111-1111-1111-1111-111111111111"'), 1, "job_id")
    local r = eventd.query(vm, "LOGS FROM " .. o .. " WHERE payload IS NULL")
    t:assert_eq(r.exit_code, 1, "a name outside the six is refused")
    t:assert(r.stderr:find("unknown log field payload", 1, true), r.stderr)
end)

-- "Metric selection resolves names and labels through series ... and
--  reads samples for the range, ordered by the composite index that
--  already provides (timestamp, id)."
test("a selector's series are read for the range, each in timestamp order", {
    spec = "eventd *sql.metric-selection-resolves-through-series-and-reads-samples-in-index-order",
}, function(t)
    local name = "pt" .. eventd.marker("sel")
    local ts = now_ns() - 300 * 1000000000
    -- Two series, each written newest first, and one sample outside the
    -- range.
    for _, s in ipairs({ { "a", 3 }, { "b", 4 }, { "a", 1 }, { "b", 2 } }) do
        local r = eventd.send_metric(vm, { name = name, type = "gauge", value = s[2],
            labels = { host = s[1] }, timestamp = ts + s[2] * 1000000000 })
        assert(r.ret > 0)
        os.execute("sleep 0.2")
    end
    eventd.send_metric(vm, { name = name, type = "gauge", value = 99, labels = { host = "a" },
        timestamp = ts - 7200 * 1000000000 })
    local rows = eventd.wait_rows(vm, "METRIC " .. name .. "[] SINCE 1h ago",
        function(rs) return #rs == 4 end)
    t:assert_eq(json.encode(field(rows, "value")), "[1,2,3,4]", "both series, in timestamp order")
    local a = eventd.rows(vm, "METRIC " .. name .. '[host="a"] SINCE 1h ago')
    t:assert_eq(json.encode(field(a, "value")), "[1,3]", "the label resolves one series, its samples ascending")
    local all = eventd.rows(vm, "METRIC " .. name .. '[host="a"]  SINCE 4h ago')
    t:assert_eq(json.encode(field(all, "value")), "[99,1,3]", "the range decides which samples are read")
end)

-- ---------------------------------------------------------------------------
-- What does not
-- ---------------------------------------------------------------------------

-- "Event payload predicates have no column. They become eventd-internal
--  payload extraction predicates, and may use an adaptive payload
--  expression index to narrow candidates."
test("payload predicates over nested paths answer the same with and without an index", {
    spec = "eventd *sql.a-payload-predicate-becomes-an-internal-extraction-predicate",
}, function(t)
    local tag = eventd.marker("pl")
    local f = "pf" .. tag
    emit("pt.sql.pl", { tag = tag, [f] = { inner = "deep", n = 2 } })
    emit("pt.sql.pl", { tag = tag, [f] = { inner = "DEEP", n = 3 } })
    emit("pt.sql.pl", { tag = tag, [f] = { n = 4 } })
    emit("pt.sql.pl", { tag = tag })
    local base = 'EVENTS pt.sql.pl WHERE tag == "' .. tag .. '"'
    eventd.wait_rows(vm, base, function(rs) return #rs == 4 end)
    local queries = {
        { f .. '.inner == "deep"', 2 },
        { f .. ".n >= 3", 2 },
        { f .. ".inner IS NULL", 2 },
        { f .. ".n IS NOT NULL", 3 },
        { f .. '.inner IN ("Deep", "none")', 2 },
    }
    local function check(label)
        for _, q in ipairs(queries) do
            t:assert_eq(#eventd.rows(vm, base .. " WHERE " .. q[1]), q[2], label .. ": " .. q[1])
        end
    end
    check("without an index")
    materialise_index(t, f .. ".inner")
    check("with the index on " .. f .. ".inner material")
end)

-- "HAS, array containment, narrows nothing ... a HAS predicate is
--  answered by decoding each candidate row and testing its array in
--  full."
test("HAS finds the value anywhere in the array, and nowhere else", {
    spec = "eventd *sql.has-uses-no-index-and-tests-each-candidates-array-in-full",
}, function(t)
    local tag = eventd.marker("has")
    local f = "groups" .. tag
    local wanted = "S-1-5-32-544"
    emit("pt.sql.has", { tag = tag, i = 1, [f] = eventd.array({ "S-1-1-0", "S-1-5-11", wanted }) })
    emit("pt.sql.has", { tag = tag, i = 2, [f] = eventd.array({ "S-1-1-0" }) })
    emit("pt.sql.has", { tag = tag, i = 3, [f] = wanted })
    emit("pt.sql.has", { tag = tag, i = 4, [f] = eventd.array({ "s-1-5-32-544" }) })
    local base = 'EVENTS pt.sql.has WHERE tag == "' .. tag .. '"'
    eventd.wait_rows(vm, base, function(rs) return #rs == 4 end)
    local function which()
        local got = field(eventd.rows(vm, base .. ' WHERE ' .. f .. ' HAS "' .. wanted .. '" SORT i'), "i")
        return json.encode(got)
    end
    t:assert_eq(which(), "[1,4]", "the last element, and a case variant, are found; a scalar is not an array")
    materialise_index(t, f)
    t:assert_eq(which(), "[1,4]", "an index on the field changes nothing")
end)

-- "SQL narrows, the query language decides."
test("with an index material, equality still folds case and still tells text from bytes", {
    spec = "eventd *sql.sql-only-narrows-candidates-and-the-real-predicate-is-applied-after-loading",
}, function(t)
    local tag = eventd.marker("nar")
    local f = "who" .. tag
    local rows = {
        { i = 1, [f] = "Alice" }, { i = 2, [f] = "alice" }, { i = 3, [f] = "alice " },
        { i = 4, [f] = eventd.bin("alice") }, { i = 5, [f] = eventd.array({ "alice" }) },
        { i = 6, [f] = 7 }, { i = 7, [f] = eventd.float(7.0) }, { i = 8 },
    }
    for _, p in ipairs(rows) do
        p.tag = tag
        emit("pt.sql.nar", p)
    end
    local base = 'EVENTS pt.sql.nar WHERE tag == "' .. tag .. '"'
    eventd.wait_rows(vm, base, function(rs) return #rs == #rows end)
    local function which(pred)
        return json.encode(field(eventd.rows(vm, base .. " WHERE " .. pred .. " SORT i"), "i"))
    end
    local cases = {
        { f .. ' == "ALICE"', "[1,2]" },
        { f .. ' == x"616c696365"', "[4]" },
        { f .. " == 7", "[6,7]" },
        { f .. " IS NULL", "[8]" },
        { f .. ' != "alice"', "[3,4,5,6,7]" },
    }
    for _, c in ipairs(cases) do t:assert_eq(which(c[1]), c[2], "unindexed: " .. c[1]) end
    materialise_index(t, f)
    for _, c in ipairs(cases) do t:assert_eq(which(c[1]), c[2], "indexed: " .. c[1]) end
end)

-- ---------------------------------------------------------------------------
-- Where access control sits
-- ---------------------------------------------------------------------------

--- eventd's identity for a field (eventd-core field.rs field_guid): the
--- UUIDv5 of the field path under eventd's namespace, in PCDS byte
--- order — which is Python's uuid5(...).bytes_le.
local function field_guid(path)
    local p = assert(io.popen("python3 -c \"import uuid,sys; print(uuid.uuid5(uuid.UUID("
        .. "'e7d3a1b0-5c2f-4e8a-9b1d-0a6f3c8e2d4b'), sys.argv[1]).bytes_le.hex())\" '" .. path .. "'", "r"))
    local hex = p:read("l")
    p:close()
    return (hex:gsub("..", function(h) return string.char(tonumber(h, 16)) end))
end

--- A self-relative descriptor owned by SYSTEM whose DACL is `aces`, each
--- already packed; hex for `reg set … hex:`.
local function descriptor_hex(aces)
    local owner = token.SID.LOCAL_SYSTEM
    local body = table.concat(aces)
    -- ACL revision 4: the DACL carries object ACEs.
    local acl = string.pack("<BBI2I2I2", 4, 0, 8 + #body, #aces, 0) .. body
    local header = string.pack("<BBI2I4I4I4I4", 1, 0, 0x8004, 20, 20 + #owner, 0, 20 + 2 * #owner)
    return ((header .. owner .. owner .. acl):gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local function allow_ace(sid, mask)
    return string.pack("<BBI2I4", 0, 0, 8 + #sid, mask) .. sid
end

--- ACCESS_DENIED_OBJECT_ACE (MS-DTYP 2.4.4.4) denying `mask` on one
--- object type, the field `guid`.
local function deny_field_ace(sid, mask, guid)
    return string.pack("<BBI2I4I4", 6, 0, 28 + #sid, mask, 1) .. guid .. sid
end

-- "Which fields the query references, for both authorization and
--  frequency accounting."
test("a field the query names must be readable for a record to count, and is counted for indexing", {
    spec = "eventd *plan.planning-collects-referenced-fields-for-authorization-and-accounting",
}, function(t)
    local o = eventd.marker("ref")
    local key = eventd.SECURITY .. [[\Logs\]] .. o
    local user = token.sid(5, 21, 1278, 6, 6, 1101)
    -- The user may read these records, except their is_error field.
    local sd = descriptor_hex({
        deny_field_ace(user, 1, field_guid("is_error")),
        allow_ace(token.SID.LOCAL_SYSTEM, 1),
        allow_ace(user, 1),
    })
    logs({ { origin = o, is_error = false, message = "fine" }, { origin = o, is_error = true, message = "bad" } })
    eventd.wait_rows(vm, "LOGS FROM " .. o, function(rs) return #rs == 2 end)
    vm:run("reg set -p '" .. key .. "' @ hex:" .. sd):assert_ok()
    local ok, err = pcall(function()
        local plain = as_user(1101, "LOGS FROM " .. o)
        t:assert_eq(#plain.records, 2, "the user reads both records: " .. tostring(plain.error))
        for _, r in ipairs(plain.records) do
            t:assert(r.is_error == nil, "without the denied field: " .. json.encode(r))
            t:assert(r.message ~= nil, "with the others")
        end
        local named = as_user(1101, "LOGS FROM " .. o .. " WHERE is_error == true")
        t:assert_eq(named.status, "end", "the query runs: " .. tostring(named.error))
        t:assert_eq(#named.records, 0, "naming the unreadable field makes the records invisible to it")
        t:assert_eq(#eventd.rows(vm, "LOGS FROM " .. o .. " WHERE is_error == true"), 1,
            "control: SYSTEM, who may read the field, gets the record")
        local grouped = as_user(1101, "LOGS FROM " .. o .. " COUNT BY is_error")
        t:assert_eq(#grouped.records, 0, "grouping by it reveals nothing either")
        local other = as_user(1101, "LOGS FROM " .. o .. ' WHERE message == "bad"')
        t:assert_eq(#other.records, 1, "a predicate on a readable field works")
    end)
    vm:run("reg del '" .. key .. "'")
    if not ok then error(err, 0) end

    -- The same collected fields feed the frequency counters.
    local f = "rf" .. eventd.marker()
    eventd.rows(vm, "EVENTS pt.sql.ref WHERE " .. f .. ".x == 1")
    local throwaway = "flush" .. eventd.marker()
    t:assert(eventd.query(vm, "EVENTS INDEX " .. throwaway).ok, "a policy pass requested")
    local counted = pcall(wait_until, function()
        for _, row in ipairs(eventd.sql(vm, eventd.DB.meta, "SELECT field_path, query_count FROM index_counters")) do
            if row[1] == f .. ".x" and row[2] == 1 then return true end
        end
        return false
    end, { timeout = 30, interval = 0.5, desc = "the counter for " .. f .. ".x" })
    t:assert(counted, "the referenced payload path was counted once")
end)

-- "The externally visible result is identical to the one filtering-first
--  would produce — aggregates, ordering and pagination included."
test("a caller who may not read an origin gets counts, order and pages computed without it", {
    spec = "eventd *sql.results-equal-filtering-first-including-aggregates-ordering-and-pagination",
}, function(t)
    local m = eventd.marker("ff")
    local pub, secret = m .. "pub", m .. "sec"
    local key = eventd.SECURITY .. [[\Logs\]] .. secret
    -- Only SYSTEM may read the secret origin.
    local sd = pc.descriptor_hex(token.SID.LOCAL_SYSTEM, { { sid = token.SID.LOCAL_SYSTEM, mask = 1 } })
    vm:run("reg set -p '" .. key .. "' @ hex:" .. sd):assert_ok()
    local ok, err = pcall(function()
        local ts = now_ns() - 60 * 1000000000
        local batch = {}
        for i = 1, 10 do
            -- Interleaved in time: secret lines sit between public ones.
            batch[#batch + 1] = { origin = pub, is_error = false, message = m .. " p" .. i, timestamp = ts + i * 2000 }
            batch[#batch + 1] = { origin = secret, is_error = i % 2 == 0, message = m .. " s" .. i, timestamp = ts + i * 2000 + 1000 }
        end
        logs(batch)
        eventd.wait_rows(vm, "LOGS FROM " .. pub .. ", " .. secret, function(rs) return #rs == 20 end)
        local where = 'LOGS SINCE 10m ago WHERE message STARTS_WITH "' .. m .. '"'

        -- What filtering first gives: the public rows alone, read by SYSTEM.
        local want_page = field(eventd.rows(vm, "LOGS FROM " .. pub .. " SKIP 3 TAKE 4"), "message")
        local want_sorted = field(eventd.rows(vm, "LOGS FROM " .. pub .. " SORT message DESC TAKE 3"), "message")

        local all = as_user(1001, where)
        t:assert_eq(all.status, "end", "the user's query ran: " .. tostring(all.error))
        t:assert_eq(#all.records, 10, "the user sees the ten public lines only")
        local count = as_user(1001, where .. " COUNT BY origin")
        t:assert_eq(#count.records, 1, "one group: the secret origin is not a group")
        t:assert_eq(count.records[1] and count.records[1].count, 10, "counting ten, not twenty")
        local errs = as_user(1001, where .. " COUNT BY is_error")
        t:assert_eq(#errs.records, 1, "is_error has one value among the public lines")
        local page = as_user(1001, where .. " SKIP 3 TAKE 4")
        t:assert_eq(json.encode(field(page.records, "message")), json.encode(want_page),
            "a page is the same page the public rows alone give")
        local sorted = as_user(1001, where .. " SORT message DESC TAKE 3")
        t:assert_eq(json.encode(field(sorted.records, "message")), json.encode(want_sorted),
            "and so is a sorted page")
        local distinct = as_user(1001, where .. " DISTINCT origin")
        t:assert_eq(#distinct.records, 1, "DISTINCT does not leak the secret origin")
    end)
    vm:run("reg del '" .. key .. "'")
    if not ok then error(err, 0) end
end)
