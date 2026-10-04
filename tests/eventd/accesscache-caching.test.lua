-- eventd TRM §7.5 — caching: record-level and field-level verdict caches,
-- descriptor resolution cached across queries and invalidated by the
-- registry watch, what a stream reuses, and the metric publication cache's
-- hot path.
--
-- Access checks are counted, not inferred. A descriptor carrying a SACL
-- success/failure audit ACE for Everyone makes every AccessCheck eventd
-- runs against it emit one KACS `access-audit` event naming the check's
-- audit context ("events:<pattern>"), and eventd stores those events like
-- any other, so the number of checks a query cost is the number of new
-- such records. Registry reads are counted the same way, through LCS: a
-- SACL on a descriptor's own key makes each open of it emit
-- `LCS_KEY_OPEN_AUDIT` with the opener's user SID.
--
-- One file-scope eventd serves every test; each test has its own
-- marker-named pattern, so no test's checks are counted in another's.
-- Streams are spoken on the query channel directly (PSPU §3.15–§3.17),
-- since a test has to emit records and change descriptors while one is
-- open.

local eventd = require("helpers.eventd")
local peinit = require("helpers.peinit")
local token = require("helpers.token")
local access = require("helpers.access")
local us = require("helpers.unixsock")
local sys = require("helpers.sys")
peinit.claim(1)

local vm = eventd.boot({ name = "ev-cache" })

local SY, BA, AU = token.SID.LOCAL_SYSTEM, token.SID.ADMINISTRATORS, token.SID.AUTHENTICATED_USERS
local EVERYONE = token.SID.EVERYONE
local GROUP = token.SID.TEST_GROUP
local NOBODY = token.SID.TEST_GROUP_2
local READ, PUBLISH = 0x1, 0x8

local function hex(s) return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end)) end
local function unhex(h) return (h:gsub("%s", ""):gsub("..", function(x) return string.char(tonumber(x, 16)) end)) end

local function field_guid(name)
    local p = assert(io.popen("python3 -c 'import uuid; print(uuid.uuid5(uuid.UUID("
        .. "\"e7d3a1b0-5c2f-4e8a-9b1d-0a6f3c8e2d4b\"), \"" .. name .. "\").bytes_le.hex())'"))
    local g = unhex(p:read("l"))
    p:close()
    return g
end

local function allow(mask, sid) return access.ace(access.ACE.ALLOWED, mask, sid or SY) end
local AUDIT = access.acl({ access.ace(access.ACE.AUDIT, 0xf, EVERYONE,
    access.ACE_FLAG.SUCCESSFUL_ACCESS | access.ACE_FLAG.FAILED_ACCESS) })
--- A descriptor whose every check is audited.
local function audited(aces) return access.simple(aces, { sacl = AUDIT }) end
local DENY_ALL = access.simple({ allow(READ | PUBLISH, NOBODY) })

local function key_of(ns, pattern) return eventd.SECURITY .. "\\" .. ns .. "\\" .. pattern end
local function put(ns, pattern, sd)
    vm:run("reg set -p '" .. key_of(ns, pattern) .. "' @ hex:" .. hex(sd)):assert_ok()
end

local function emit(ty, payload)
    local r = eventd.emit(vm, ty, payload or { n = 1 })
    assert(r.ret == 0, "kmes_emit " .. ty .. ": errno " .. tostring(r.errno))
end

local function rows(text)
    local r = eventd.query(vm, text)
    assert(r.ok, "query `" .. text .. "` failed: " .. tostring(r.stderr))
    return r.rows
end

--- Events of `ty` committed to the store, read from the shards (a query
--- would itself be an access check).
local function stored(ty)
    local n = 0
    for _, shard in ipairs(eventd.shards(vm)) do
        n = n + eventd.sql(vm, shard, "SELECT count(*) FROM events WHERE event_type = '" .. ty .. "'")[1][1]
    end
    return n
end
local function wait_stored(ty, n)
    wait_until(function() return stored(ty) == n end, { timeout = 15, desc = n .. " of " .. ty .. " stored" })
end

-- ---------------------------------------------------------------------------
-- Counting checks
-- ---------------------------------------------------------------------------

--- access-audit records naming `ctx`.
local function audits(ctx)
    return #rows('EVENTS access-audit WHERE object_context == x"' .. hex(ctx)
        .. '" SINCE 1h ago TAKE 100000 SELECT sequence')
end

--- The audit count for `ctx` once it has stopped moving: KACS emits
--- during the check, eventd stores asynchronously.
local function settled(ctx)
    local last, steady = -1, 0
    wait_until(function()
        local n = audits(ctx)
        if n == last then steady = steady + 1 else steady, last = 0, n end
        return steady >= 3
    end, { timeout = 30, interval = 0.5, desc = "the audit count for " .. ctx .. " to settle" })
    return last
end

--- How many access checks running `text` once cost, against `ctx`.
local function checks(ctx, text)
    local before = settled(ctx)
    rows(text)
    return settled(ctx) - before
end

--- Put an audited descriptor and wait until a query is checked against
--- it (the query's own checks are then part of the baseline).
local function audit_pattern(ns, pattern, aces, probe)
    put(ns, pattern, audited(aces))
    local ctx = ns:lower() .. ":" .. pattern
    wait_until(function()
        rows(probe)
        return audits(ctx) > 0
    end, { timeout = 20, desc = "the audited descriptor on " .. pattern .. " to be in force" })
    return ctx
end

-- ---------------------------------------------------------------------------
-- Record-level and field-level
-- ---------------------------------------------------------------------------

test("verdicts are keyed by identifier, not pattern: more records cost nothing, another type under the pattern does", {
    spec = "eventd *accesscache.verdicts-are-cached-per-query-and-keyed-by-identifier-not-pattern",
}, function(t)
    local p = eventd.marker("ptroot")
    for _, s in ipairs({ "a", "b", "c" }) do
        for i = 1, 5 do emit(p .. "." .. s, { i = i }) end
    end
    for _, s in ipairs({ "a", "b", "c" }) do wait_stored(p .. "." .. s, 5) end
    local q = "EVENTS " .. p .. ".* SINCE 1h ago TAKE 10000"
    local ctx = audit_pattern("Events", p, { allow(READ) }, q)

    local three = checks(ctx, q)
    for _, s in ipairs({ "a", "b", "c" }) do
        for i = 6, 10 do emit(p .. "." .. s, { i = i }) end
    end
    for _, s in ipairs({ "a", "b", "c" }) do wait_stored(p .. "." .. s, 10) end
    t:assert_eq(checks(ctx, q), three, "twice the records cost no more checks")

    emit(p .. ".d")
    wait_stored(p .. ".d", 1)
    local four = checks(ctx, q)
    t:assert(three >= 3 and three % 3 == 0, "three types under one pattern cost the same each: " .. three .. " checks")
    t:assert_eq(four, three + three // 3, "a fourth type under the same pattern costs one type's checks more")
end)

test("events of uniform types take two checks per type: the pre-check and one result check", {
    spec = "eventd *accesscache.ten-thousand-events-of-twenty-uniform-types-take-at-most-forty-checks",
}, function(t)
    local p = eventd.marker("pttwenty")
    local types = 4
    for k = 1, types do for i = 1, 10 do emit(p .. ".t" .. k, { i = i }) end end
    for k = 1, types do wait_stored(p .. ".t" .. k, 10) end
    local q = "EVENTS " .. p .. ".* SINCE 1h ago TAKE 10000"
    local ctx = audit_pattern("Events", p, { allow(READ) }, q)
    local n = checks(ctx, q)
    t:assert_eq(n, 2 * types, n .. " checks for " .. (types * 10) .. " events of " .. types .. " types")
end)

test("with object ACEs, one verdict per field set: more records of known shapes cost nothing", {
    spec = "eventd *accesscache.a-result-verdict-is-cached-per-identifier-and-field-set",
}, function(t)
    local ty = eventd.marker("ptshapes")
    local shapes = { { a = 1 }, { b = 1 }, { a = 1, b = 1 } }
    for _, s in ipairs(shapes) do for _ = 1, 4 do emit(ty, s) end end
    wait_stored(ty, 12)
    local q = "EVENTS " .. ty .. " SINCE 1h ago TAKE 10000"
    local ctx = audit_pattern("Events", ty, {
        access.ace(access.ACE.DENIED_OBJECT, READ, SY, 0, { object_type = field_guid("z") }),
        allow(READ) }, q)
    local before = checks(ctx, q)
    for _, s in ipairs(shapes) do for _ = 1, 4 do emit(ty, s) end end
    wait_stored(ty, 24)
    t:assert_eq(checks(ctx, q), before, "twelve more records of the same three shapes cost no more checks")
end)

test("each distinct field set costs its own cache entry and check", {
    spec = "eventd *accesscache.each-distinct-field-set-costs-its-own-cache-entry-and-check",
}, function(t)
    local ty = eventd.marker("ptnewshape")
    for _ = 1, 3 do emit(ty, { a = 1 }) end
    wait_stored(ty, 3)
    local q = "EVENTS " .. ty .. " SINCE 1h ago TAKE 10000"
    local ctx = audit_pattern("Events", ty, {
        access.ace(access.ACE.DENIED_OBJECT, READ, SY, 0, { object_type = field_guid("z") }),
        allow(READ) }, q)
    local one = checks(ctx, q)
    emit(ty, { b = 1 }); emit(ty, { c = 1 })
    wait_stored(ty, 5)
    t:assert_eq(checks(ctx, q), one + 2, "two records of two new shapes cost two more checks")
end)

test("a log query takes two checks per origin", {
    spec = "eventd *accesscache.a-log-query-takes-two-checks-per-origin",
}, function(t)
    local origin = eventd.marker("ptlogone")
    for i = 1, 10 do eventd.send_log(vm, { origin = origin, is_error = false, message = "m" .. i }) end
    wait_until(function()
        return eventd.sql(vm, eventd.DB.logs, "SELECT count(*) FROM logs WHERE origin = '" .. origin .. "'")[1][1] == 10
    end, { timeout = 15, desc = "the ten log records" })
    local q = "LOGS FROM " .. origin .. " SINCE 1h ago TAKE 10000"
    local ctx = audit_pattern("Logs", origin, { allow(READ) }, q)
    local n = checks(ctx, q)
    t:assert_eq(n, 2, "ten log records of one origin cost two checks: the pre-check and one result check")
end)

-- ---------------------------------------------------------------------------
-- Descriptor resolution
-- ---------------------------------------------------------------------------

--- eventd's own user SID, read as the owner of the sockets it creates.
local function eventd_sid()
    local r = vm:run("sd show --sddl " .. eventd.SOCKET.query)
    r:assert_ok()
    local s = assert(r.stdout:match("O:(S%-[%d%-]+)G:"), "socket owner: " .. r.stdout)
    local parts = {}
    for n in s:gmatch("%d+") do parts[#parts + 1] = tonumber(n) end
    -- S-1-<authority>-<subs…>
    return token.sid(parts[2], table.unpack(parts, 3))
end

--- Opens of a key with a SACL, by eventd, as LCS audited them.
local function opens(sid)
    return #rows('EVENTS LCS_KEY_OPEN_AUDIT WHERE caller.user_sid == x"' .. hex(sid)
        .. '" SINCE 1h ago TAKE 100000 SELECT sequence')
end

local function settled_opens(sid)
    local last, steady = -1, 0
    wait_until(function()
        local n = opens(sid)
        if n == last then steady = steady + 1 else steady, last = 0, n end
        return steady >= 3
    end, { timeout = 30, interval = 0.5, desc = "eventd's audited key opens to settle" })
    return last
end

test("resolving a pattern is cached across queries until a descriptor changes", {
    spec = "eventd *accesscache.descriptor-resolution-is-cached-across-queries"
        .. " eventd *accesscache.a-descriptor-change-invalidates-cached-resolutions-and-verdicts",
}, function(t)
    local p = eventd.marker("ptresolve")
    emit(p .. ".a")
    wait_stored(p .. ".a", 1)
    put("Events", p, access.simple({ allow(READ) }))
    -- Audit every successful read-access open of the descriptor's key.
    vm:run("reg sd '" .. key_of("Events", p) .. "' --sacl --set 'S:(AU;SA;KR;;;WD)'"):assert_ok()
    local sid = eventd_sid()
    local q = "EVENTS " .. p .. ".* SINCE 1h ago"
    wait_until(function()
        rows(q)
        return opens(sid) > 0
    end, { timeout = 20, desc = "eventd's open of the audited key" })

    local base = settled_opens(sid)
    for _ = 1, 3 do t:assert_eq(#rows(q), 1, "the event is readable") end
    t:assert_eq(settled_opens(sid), base, "three more queries open the descriptor's key no more")

    -- A change under the Security subtree throws the resolution away.
    put("Events", p, access.simple({ allow(READ), allow(READ, GROUP) }))
    local changed = false
    wait_until(function()
        rows(q)
        changed = settled_opens(sid) > base
        return changed
    end, { timeout = 30, desc = "the changed descriptor to be read again" })
    t:assert(changed, "after the change the key is opened again")
end)

test("a revocation takes effect on the next query", {
    spec = "eventd *accesscache.a-revocation-takes-effect-on-the-next-query",
}, function(t)
    local ty = eventd.marker("ptrevoke")
    emit(ty)
    wait_stored(ty, 1)
    local q = "EVENTS " .. ty .. " SINCE 1h ago"
    for _ = 1, 3 do t:assert_eq(#rows(q), 1, "readable, and its verdict cached") end
    put("Events", ty, DENY_ALL)
    -- The registry watch is asynchronous; the revocation must land within
    -- moments, not at a restart.
    local ok = wait_until(function() return #rows(q) == 0 end,
        { timeout = 5, interval = 0.1, desc = "the revocation" })
    t:assert(ok, "the next queries after the change no longer return the event")
end)

-- Route closed: nothing a test can do makes the registry watch fail.
-- Deleting the whole Security subtree, recreating it with a descriptor that
-- denies eventd's SID KEY_NOTIFY, and writing descriptors under it left
-- eventd's watch healthy (no "watch degraded" line, queries still served
-- from the new keys): a deleted key does not error the notify fd, and the
-- watch is only re-opened after an error. The registry provider is not a
-- service a test can restart.
test("a failed registry watch discards the descriptor cache and fails closed for new resolutions", {
    spec = "eventd *accesscache.a-failed-registry-watch-discards-the-cache-and-fails-closed-for-new-resolutions",
    skip = true,
    covered_by = "cargo:eventd eventd query::security::tests::a_failed_watch_discards_the_cache_and_fails_closed_without_reading_the_registry",
}, function() end)

-- Route closed: as above. The unit test shows a descriptor resolved
-- before the failure no longer resolves after it.
test("a failed watch degrades: ingestion continues, and queries see no records until it recovers", {
    spec = "eventd *accesscache.a-failed-watch-degrades-ingestion-continues-and-queries-see-no-records-until-it-recovers",
    skip = true,
    covered_by = "cargo:eventd eventd query::security::tests::a_failed_watch_discards_the_cache_and_fails_closed_without_reading_the_registry",
}, function() end)

-- ---------------------------------------------------------------------------
-- Streams
-- ---------------------------------------------------------------------------

local NIL = setmetatable({}, { __tostring = function() return "nil" end })

local function decode(b, at)
    local tag = b:byte(at)
    if tag < 0x80 then return tag, at + 1 end
    if tag >= 0xe0 then return tag - 0x100, at + 1 end
    local function map(n, p)
        local out = {}
        for _ = 1, n do local k, v; k, p = decode(b, p); v, p = decode(b, p); out[k] = v end
        return out, p
    end
    local function arr(n, p)
        local out = {}
        for i = 1, n do out[i], p = decode(b, p) end
        return out, p
    end
    local function bytes(n, p) return b:sub(p, p + n - 1), p + n end
    if tag <= 0x8f then return map(tag - 0x80, at + 1) end
    if tag <= 0x9f then return arr(tag - 0x90, at + 1) end
    if tag <= 0xbf then return bytes(tag - 0xa0, at + 1) end
    if tag == 0xc0 then return NIL, at + 1 end
    if tag == 0xc2 then return false, at + 1 end
    if tag == 0xc3 then return true, at + 1 end
    if tag == 0xc4 or tag == 0xd9 then return bytes(b:byte(at + 1), at + 2) end
    if tag == 0xc5 or tag == 0xda then return bytes(string.unpack(">I2", b, at + 1), at + 3) end
    if tag == 0xc6 or tag == 0xdb then return bytes(string.unpack(">I4", b, at + 1), at + 5) end
    if tag == 0xca then return string.unpack(">f", b, at + 1), at + 5 end
    if tag == 0xcb then return string.unpack(">d", b, at + 1), at + 9 end
    if tag == 0xcc then return string.unpack(">I1", b, at + 1), at + 2 end
    if tag == 0xcd then return string.unpack(">I2", b, at + 1), at + 3 end
    if tag == 0xce then return string.unpack(">I4", b, at + 1), at + 5 end
    if tag == 0xcf or tag == 0xd3 then return string.unpack(">i8", b, at + 1), at + 9 end
    if tag == 0xd0 then return string.unpack(">i1", b, at + 1), at + 2 end
    if tag == 0xd1 then return string.unpack(">i2", b, at + 1), at + 3 end
    if tag == 0xd2 then return string.unpack(">i4", b, at + 1), at + 5 end
    if tag == 0xdc then return arr(string.unpack(">I2", b, at + 1), at + 3) end
    if tag == 0xdd then return arr(string.unpack(">I4", b, at + 1), at + 5) end
    if tag == 0xde then return map(string.unpack(">I2", b, at + 1), at + 3) end
    if tag == 0xdf then return map(string.unpack(">I4", b, at + 1), at + 5) end
    error(string.format("msgpack: unhandled tag 0x%02x", tag))
end

--- Open `text` on the query channel from `who`, connected while
--- impersonating `as` (or as itself). Returns the connection.
local function open(who, text, as)
    local fd = assert(us.socket(who, us.AF_UNIX, us.SOCK.STREAM))
    who:syscall(us.NR.setsockopt, { args = { fd, 1, 20, 0, 16 },
        bufs = { string.pack("<i8i8", 20, 0) }, ptrs = { 3 } })
    if as then assert(token.impersonate(who, as).ret == 0, "impersonate") end
    local r = us.connect(who, fd, eventd.SOCKET.query)
    if as then token.revert(who) end
    assert(r.ret == 0, "connect: " .. us.errname(r.errno))
    local body = eventd.msgpack({ query = text })
    us.sendmsg(who, fd, string.pack("<I4", #body) .. body)
    return { who = who, fd = fd, buf = "" }
end

local function next_message(c)
    while true do
        if #c.buf >= 4 then
            local n = string.unpack("<I4", c.buf)
            if #c.buf >= 4 + n then
                local m = decode(c.buf:sub(5, 4 + n), 1)
                c.buf = c.buf:sub(5 + n)
                return m
            end
        end
        local r = us.recvmsg(c.who, c.fd, 65536, { cmsg = 0 })
        if r.ret <= 0 then return nil, r.ret == 0 and "eof" or us.errname(r.errno) end
        c.buf = c.buf .. r.data
    end
end

--- Read the initial result set up to `watch`; returns its records.
local function initial(c)
    local out = {}
    while true do
        local m, why = next_message(c)
        assert(m, "the stream ended before watch: " .. tostring(why))
        if m.status == "watch" then return out end
        assert(m.status == "ok", "stream answered " .. tostring(m.status) .. ": " .. tostring(m.error))
        for _, r in ipairs(m.records) do out[#out + 1] = r end
    end
end

--- Read live records until one of type `until_type` arrives; returns
--- every record read.
local function live_until(c, until_type)
    local out = {}
    while true do
        local m, why = next_message(c)
        assert(m, "the stream gave no " .. until_type .. ": " .. tostring(why))
        assert(m.status == "ok", "stream answered " .. tostring(m.status) .. ": " .. tostring(m.error))
        local done = false
        for _, r in ipairs(m.records) do
            out[#out + 1] = r
            if r.event_type == until_type then done = true end
        end
        if done then return out end
    end
end

local function types_of(recs)
    local seen = {}
    for _, r in ipairs(recs) do seen[#seen + 1] = r.event_type end
    table.sort(seen)
    return table.concat(seen, ",")
end

test("a stream reuses its initial verdicts, checks a new identifier first, and re-checks after a change", {
    spec = "eventd *accesscache.initial-stream-verdicts-are-reused-through-the-watch-phase"
        .. " eventd *accesscache.a-new-identifier-in-a-stream-is-checked-before-it-is-used"
        .. " eventd *accesscache.after-a-descriptor-change-stream-batches-are-rechecked",
}, function(t)
    local p = eventd.marker("ptstream")
    emit(p .. ".a")
    wait_stored(p .. ".a", 1)
    local q = "EVENTS " .. p .. ".* SINCE 1h ago STREAM"
    local ctx = audit_pattern("Events", p, { allow(READ) }, "EVENTS " .. p .. ".* SINCE 1h ago")
    -- A sibling the console may not read, under its own pattern.
    put("Events", p .. ".denied", DENY_ALL)

    local c = open(vm, q)
    t:assert_eq(types_of(initial(c)), p .. ".a", "the initial result set")
    local before = settled(ctx)

    -- More of the identifier already authorized: no new check.
    emit(p .. ".a", { n = 2 })
    local got = live_until(c, p .. ".a")
    t:assert_eq(#got, 1, "the live record arrives")
    t:assert_eq(settled(ctx), before, "and was not checked again")

    -- A new identifier the console may not read, then one it may.
    emit(p .. ".denied"); emit(p .. ".new")
    got = live_until(c, p .. ".new")
    t:assert_eq(types_of(got), p .. ".new", "the unreadable new type was never delivered")
    t:assert(settled(ctx) > before, "and the readable new type was checked before it was")

    -- A change to an identifier already authorized in this stream.
    put("Events", p .. ".a", DENY_ALL)
    -- The descriptor generation moves when eventd's watch sees the change;
    -- wait until a fresh query sees it, then emit.
    wait_until(function() return #rows("EVENTS " .. p .. ".a SINCE 1h ago") == 0 end,
        { timeout = 15, desc = "the revocation of " .. p .. ".a" })
    emit(p .. ".a", { n = 3 }); emit(p .. ".after")
    got = live_until(c, p .. ".after")
    t:assert_eq(types_of(got), p .. ".after", "the revoked type is no longer delivered on the open stream")
    sys.close(vm, c.fd)
end)

test("a stream keeps the identity it connected with until it disconnects", {
    spec = "eventd *accesscache.a-streams-token-is-never-re-examined"
        .. " eventd *accesscache.a-stream-keeps-its-connection-time-identity-until-disconnect",
}, function(t)
    local p = eventd.marker("ptsnap")
    emit(p .. ".a")
    wait_stored(p .. ".a", 1)
    put("Events", p, access.simple({ allow(READ, GROUP) }))
    local w = vm:spawn_worker()
    local ok, err = pcall(function()
        local notify = token.bit(token.PRIV.CHANGE_NOTIFY)
        local on = token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED
        local fixed = token.GROUP.MANDATORY | on
        -- GROUP is enabled but not mandatory, so it can be switched off.
        local member = assert(token.mint(w, {
            user_sid = token.SID.TEST_USER,
            token_type = token.TYPE.IMPERSONATION,
            impersonation_level = token.LEVEL.IMPERSONATION,
            groups = {
                { sid = EVERYONE, attributes = fixed }, { sid = AU, attributes = fixed },
                { sid = BA, attributes = fixed }, { sid = GROUP, attributes = on },
            },
            privs_present = notify, privs_enabled = notify,
        }))
        local c = open(w, "EVENTS " .. p .. ".* SINCE 1h ago STREAM", member)
        t:assert_eq(types_of(initial(c)), p .. ".a", "the member's stream reads the GROUP-only pattern")

        -- Take the member out of GROUP.
        local groups = assert(token.groups(w, member))
        local _, index = token.find_group(groups, GROUP)
        t:assert(index, "the token lists GROUP")
        local r = token.adjust_groups(w, member, { { index - 1, 0 } })
        t:assert_eq(r.ret, 0, "GROUP is disabled on the token: errno " .. tostring(r.errno))
        local now = token.find_group(assert(token.groups(w, member)), GROUP)
        t:assert(now.attributes & token.GROUP.ENABLED == 0, "and reads back disabled")

        -- A new connection as the changed token is refused the pattern...
        local fresh = open(w, "EVENTS " .. p .. ".* SINCE 1h ago", member)
        local first = assert(next_message(fresh))
        local n = 0
        while first and first.status == "ok" do n = n + #first.records; first = next_message(fresh) end
        sys.close(w, fresh.fd)
        t:assert_eq(n, 0, "a connection made after the change reads nothing")

        -- ...while the open stream, a new identifier included, carries on.
        emit(p .. ".new")
        local got = live_until(c, p .. ".new")
        t:assert_eq(types_of(got), p .. ".new",
            "the stream opened before the change still receives, and authorizes a new type, as it connected")
        sys.close(w, c.fd)
    end)
    w:kill(); w:join()
    if not ok then error(err, 0) end
end)

-- ---------------------------------------------------------------------------
-- Metric publication
-- ---------------------------------------------------------------------------

-- Route closed: what this claims is the absence of a lock, an allocation
-- and an AccessCheck on a hit. The AccessCheck half is counted in
-- writepath-ingest.test.lua (a recurring name is checked once); taking no
-- lock and allocating nothing are not observable from outside the process.
test("a recurring metric name is answered from the thread-local cache without a check", {
    spec = "eventd *accesscache.a-recurring-metric-needs-no-lock-and-only-stats-the-token-fd",
    skip = true,
    covered_by = "cargo:eventd eventd write_security::tests::recurring_name_reuses_cached_allow_and_deny_verdicts",
}, function() end)
