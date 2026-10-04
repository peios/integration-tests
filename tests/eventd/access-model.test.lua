-- eventd TRM §7.1 — the access model: enforcement on the read path at
-- query time, the caller's identity, and the four rights.
--
-- One file-scope eventd serves every test. Each test names its own event
-- types with a `marker()` prefix and writes a descriptor for exactly that
-- prefix under `Machine\System\eventd\Security\Events\…`, so the defaults
-- every other test relies on are never touched (the Admin descriptor is
-- the one exception, and is put back byte for byte).
--
-- A denial does not need a second principal: the agent is SYSTEM and an
-- Administrator, and a descriptor that grants only a group nobody holds
-- refuses it as readily as anyone. Where a test is about *which* identity
-- eventd evaluates, a worker mints one, connects while impersonating it,
-- and speaks the query channel itself (PSPU §3.15–§3.17), because evctl
-- can only ever be the console's own identity.

local eventd = require("helpers.eventd")
local peinit = require("helpers.peinit")
local token = require("helpers.token")
local access = require("helpers.access")
local us = require("helpers.unixsock")
local sys = require("helpers.sys")
peinit.claim(1)

local vm = eventd.boot({ name = "ev-access" })

-- ---------------------------------------------------------------------------
-- Descriptors
-- ---------------------------------------------------------------------------

local SY, BA, AU = token.SID.LOCAL_SYSTEM, token.SID.ADMINISTRATORS, token.SID.AUTHENTICATED_USERS
local EVERYONE, ANONYMOUS = token.SID.EVERYONE, token.SID.ANONYMOUS
--- A group the test principals hold and SYSTEM does not.
local GROUP = token.SID.TEST_GROUP
--- A group nobody holds: a descriptor granting only it refuses everyone.
local NOBODY = token.SID.TEST_GROUP_2
local READ, CLEAR, ADMINISTER, PUBLISH = 0x1, 0x2, 0x4, 0x8
local GENERIC_READ, GENERIC_WRITE = 0x80000000, 0x40000000

local function hex(s) return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end)) end

local function allow(mask, sid) return access.ace(access.ACE.ALLOWED, mask, sid) end
local function descriptor(aces, opts) return access.simple(aces, opts) end

local function key_of(ns, pattern)
    return eventd.SECURITY .. (ns and ("\\" .. ns) or "") .. "\\" .. pattern
end

--- Write `sd` as the descriptor for `pattern` in namespace `ns` (nil for
--- the Admin key itself).
local function put(ns, pattern, sd)
    vm:run("reg set -p '" .. key_of(ns, pattern) .. "' @ hex:" .. hex(sd)):assert_ok()
end

local function get_hex(ns, pattern)
    local r = vm:run("reg get '" .. key_of(ns, pattern) .. "' @")
    if r.exit_code ~= 0 then return nil end
    return (r.stdout:gsub("%s", ""))
end

-- ---------------------------------------------------------------------------
-- The query channel, spoken directly (PSPU §3.15–§3.17)
--
-- A request is a little-endian u32 length and a MessagePack map
-- {query = text}; every answer is the same framing around a map whose
-- `status` is ok (with `records`), end, watch or error.
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

--- Connect `who` to the query socket. `opts.as` is a token fd impersonated
--- around connect() only; `opts.level` is KACS_SO_IMPERSONATION_LEVEL,
--- set before connecting. Returns a connection, or nil and why.
local function connect(who, opts)
    opts = opts or {}
    local fd, e = us.socket(who, us.AF_UNIX, us.SOCK.STREAM)
    if not fd then return nil, "socket: " .. us.errname(e) end
    -- SO_RCVTIMEO, so an answer that never comes fails the read.
    who:syscall(us.NR.setsockopt, { args = { fd, 1, 20, 0, 16 },
        bufs = { string.pack("<i8i8", opts.timeout or 20, 0) }, ptrs = { 3 } })
    if opts.level then us.set_level(who, fd, opts.level) end
    if opts.as then
        local r = token.impersonate(who, opts.as)
        assert(r.ret == 0, "impersonate: " .. us.errname(r.errno))
    end
    local r = us.connect(who, fd, eventd.SOCKET.query)
    if opts.as then token.revert(who) end
    if r.ret ~= 0 then
        sys.close(who, fd)
        return nil, "connect: " .. us.errname(r.errno)
    end
    return { who = who, fd = fd, buf = "" }
end

local function send_query(c, text)
    local body = eventd.msgpack({ query = text })
    local r = us.sendmsg(c.who, c.fd, string.pack("<I4", #body) .. body)
    assert(r.ret == 4 + #body, "send: " .. us.errname(r.errno or 0))
end

--- The next message, or nil and why (eof, or the receive timing out).
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
        if r.ret < 0 then return nil, "recv: " .. us.errname(r.errno) end
        if r.ret == 0 then return nil, "eof" end
        c.buf = c.buf .. r.data
    end
end

local function close(c) sys.close(c.who, c.fd) end

--- One whole query as `who`: {records, status, error, closed, connect_error}.
local function ask(who, text, opts)
    local c, why = connect(who, opts)
    if not c then return { records = {}, connect_error = why } end
    send_query(c, text)
    local out = { records = {} }
    while true do
        local m, reason = next_message(c)
        if not m then out.closed = reason; break end
        if m.status == "ok" then
            for _, r in ipairs(m.records) do out.records[#out.records + 1] = r end
        else
            out.status, out.error = m.status, m.error
            break
        end
    end
    close(c)
    return out
end

local function describe(out)
    return string.format("status=%s error=%s closed=%s connect=%s records=%d",
        tostring(out.status), tostring(out.error), tostring(out.closed),
        tostring(out.connect_error), #out.records)
end

local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED
local NOTIFY = token.bit(token.PRIV.CHANGE_NOTIFY)

--- An impersonation token for TEST_USER in `groups` (each a binary SID),
--- holding only SeChangeNotifyPrivilege, without which the walk to
--- /run/eventd fails on traverse before the socket is reached.
local function mint(who, groups, spec)
    local list = {}
    for i, sid in ipairs(groups) do list[i] = { sid = sid, attributes = ENABLED } end
    local s = {
        user_sid = token.SID.TEST_USER,
        token_type = token.TYPE.IMPERSONATION,
        impersonation_level = token.LEVEL.IMPERSONATION,
        groups = list, privs_present = NOTIFY, privs_enabled = NOTIFY,
    }
    for k, v in pairs(spec or {}) do s[k] = v end
    local fd, e = token.mint(who, s)
    assert(fd, "mint: " .. sys.errname(e or 0))
    return fd
end

local function with_worker(fn)
    local w = vm:spawn_worker()
    local ok, err = pcall(fn, w)
    w:kill(); w:join()
    if not ok then error(err, 0) end
end

-- ---------------------------------------------------------------------------
-- Records
-- ---------------------------------------------------------------------------

--- Events of `ty` in the store, counted in the shard files themselves.
local function stored(ty)
    local n = 0
    for _, shard in ipairs(eventd.shards(vm)) do
        n = n + eventd.sql(vm, shard, "SELECT count(*) FROM events WHERE event_type = '"
            .. ty .. "'")[1][1]
    end
    return n
end

local function emit(ty, payload)
    local r = eventd.emit(vm, ty, payload)
    assert(r.ret == 0, "kmes_emit " .. ty .. ": errno " .. tostring(r.errno))
end

local function events(ty) return "EVENTS " .. ty .. " SINCE 1h ago TAKE 1000" end

--- Wait until the console sees exactly `n` events of `ty`.
local function wait_seen(ty, n, desc)
    return eventd.wait_rows(vm, events(ty), function(rs) return #rs == n end,
        { timeout = 15, desc = desc })
end

-- ---------------------------------------------------------------------------
-- Enforcement at query time
-- ---------------------------------------------------------------------------

test("a record nobody may read is stored, and a later grant or revocation applies to it", {
    spec = "eventd *access.access-is-enforced-at-query-time"
        .. " eventd *access.every-record-is-stored-regardless-of-who-may-read-it"
        .. " eventd *access.a-grant-or-revocation-applies-retroactively-to-stored-records",
}, function(t)
    local ty = eventd.marker("ptacc")
    -- The descriptor is in place before the event exists: storage-time
    -- filtering would have to drop it here.
    put("Events", ty, descriptor({ allow(READ, NOBODY) }))
    emit(ty, { n = 1 })
    wait_until(function() return stored(ty) == 1 end,
        { timeout = 15, desc = "the unreadable event to be committed" })
    t:assert_eq(stored(ty), 1, "the event is in the store although nobody may read it")
    t:assert_eq(#eventd.rows(vm, events(ty)), 0, "and the console's query does not return it")

    -- A grant made after the fact reaches the record already stored.
    put("Events", ty, descriptor({ allow(READ, SY) }))
    local rows = wait_seen(ty, 1, "the later grant to reach the stored event")
    t:assert_eq(rows[1].n, 1, "the stored event is returned once SYSTEM is granted")

    -- Two callers, one copy: an Administrator who is not SYSTEM asks the
    -- same store the same question and is answered differently.
    with_worker(function(w)
        local admin = mint(w, { EVERYONE, AU, BA })
        local out = ask(w, events(ty), { as = admin })
        t:assert_eq(out.status, "end", "the administrator's query succeeds: " .. describe(out))
        t:assert_eq(#out.records, 0, "and returns nothing, where SYSTEM's returned the event")
    end)

    -- And a revocation takes it away again.
    put("Events", ty, descriptor({ allow(READ, NOBODY) }))
    wait_seen(ty, 0, "the revocation to hide the stored event")
    t:assert_eq(stored(ty), 1, "while it stays in the store")
end)

-- ---------------------------------------------------------------------------
-- Who may connect, and who the caller is
-- ---------------------------------------------------------------------------

test("every authenticated caller may connect to the query socket", {
    spec = "eventd *access.every-authenticated-caller-may-connect-to-the-query-socket",
}, function(t)
    local shown = vm:run("sd show --sddl " .. eventd.SOCKET.query)
    shown:assert_ok()
    local dacl = shown.stdout:match("(D:[^\n]*)")
    t:assert_eq(dacl, "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)(A;;FW;;;AU)",
        "the query socket's DACL is the one §7.1 gives: " .. shown.stdout)

    with_worker(function(w)
        -- An ordinary signed-in user: no Administrators, no SYSTEM.
        local user = mint(w, { EVERYONE, AU })
        local out = ask(w, "LOGS SINCE 1h ago TAKE 1", { as = user })
        t:assert_eq(out.connect_error, nil, "an Authenticated User connects: " .. describe(out))
        t:assert_eq(out.status, "end", "and is answered: " .. describe(out))
    end)
end)

test("the query is evaluated as the identity captured at connect(), not the sender's", {
    spec = "eventd *access.the-caller-token-is-read-from-the-peer-token-socket-option"
        .. " eventd *access.the-caller-token-is-captured-at-connection-time",
}, function(t)
    local ty = eventd.marker("ptwho")
    emit(ty, { n = 1 })
    wait_seen(ty, 1, "the event")
    -- Readable by GROUP only: the minted principal, not SYSTEM (which is
    -- what the worker is whenever it is not impersonating).
    put("Events", ty, descriptor({ allow(READ, GROUP) }))
    wait_seen(ty, 0, "SYSTEM to lose the event")

    with_worker(function(w)
        -- Administrators as well, so the image's socket admits it; the
        -- descriptor above grants Administrators nothing.
        local member = mint(w, { EVERYONE, AU, BA, GROUP })

        -- Connect as the member, then send and read as SYSTEM.
        local c = assert(connect(w, { as = member }))
        send_query(c, events(ty))
        local got = {}
        while true do
            local m = assert(next_message(c))
            if m.status ~= "ok" then t:assert_eq(m.status, "end", tostring(m.error)); break end
            for _, r in ipairs(m.records) do got[#got + 1] = r end
        end
        close(c)
        t:assert_eq(#got, 1, "the member's connection reads the event, though SYSTEM sent the query")

        -- Connect as SYSTEM, then send and read while impersonating the member.
        c = assert(connect(w))
        assert(token.impersonate(w, member).ret == 0)
        send_query(c, events(ty))
        local m = assert(next_message(c))
        local records = 0
        while m and m.status == "ok" do records = records + #m.records; m = next_message(c) end
        token.revert(w)
        close(c)
        t:assert_eq(records, 0, "and SYSTEM's connection does not, whoever sends on it")
    end)
end)

-- Route closed: KACS captures an identity on every connect(), so no
-- client can make eventd's KACS_SO_PEER_TOKEN read fail. Tried here: a
-- client at Anonymous level conveys the anonymous token, one at
-- Identification level conveys an Identification token (the read
-- succeeds; AccessCheck then refuses it), and a token whose own
-- descriptor admits only its user is still conveyed and evaluated. The
-- refusal branch is `Authorizer::from_peer(...)?` in `handle`
-- (eventd/src/query/mod.rs:269-271), which drops the connection.
test("a failed peer-token read ends the connection without evaluating a query", {
    spec = "eventd *access.a-failed-peer-token-read-denies-the-query",
    skip = true,
    covered_by = "cargo:eventd TODO a query connection whose Authorizer::from_peer fails is closed with no records and no evaluation (query::handle)",
}, function() end)

test("a connection whose identity cannot be evaluated is refused, never served as someone else", {
    spec = "eventd *access.there-is-no-fallback-identification-or-anonymous-mode",
    tags = { "known-bug" },
}, function(t)
    -- PEI-TBD-anonymous-peer-served: a client that connects at Anonymous
    -- impersonation level conveys the anonymous token, and eventd
    -- evaluates it like any other (Authorizer::from_peer, query/mod.rs:269;
    -- no check of the token's level or user), so a descriptor granting
    -- Everyone or Anonymous serves records to a caller who declined to say
    -- who it is. Unsure: the book may mean only that eventd never invents
    -- an identity of its own.
    local ty = eventd.marker("ptanon")
    emit(ty, { n = 1 })
    wait_seen(ty, 1, "the event")
    put("Events", ty, descriptor({ allow(READ, SY), allow(READ, EVERYONE), allow(READ, ANONYMOUS) }))
    wait_seen(ty, 1, "the widened descriptor")

    -- Identification level: an identity eventd may look at but not act
    -- as. AccessCheck refuses it, and eventd answers with the failure
    -- rather than falling back to anything.
    local ident = ask(vm, events(ty), { level = token.LEVEL.IDENTIFICATION })
    t:assert_eq(#ident.records, 0, "an Identification-level caller gets nothing: " .. describe(ident))
    t:assert_eq(ident.status, "error", "and is refused: " .. describe(ident))

    -- Anonymous level: the caller conveys no identity of its own.
    local anon = ask(vm, events(ty), { level = token.LEVEL.ANONYMOUS })
    t:assert_eq(#anon.records, 0,
        "an anonymous caller is not served, even where Everyone may read: " .. describe(anon))
end)

-- ---------------------------------------------------------------------------
-- Rights
-- ---------------------------------------------------------------------------

test("EVENTD_READ is 0x0001: that bit alone reads records, and no other bit does", {
    spec = "eventd *access.eventd-read-is-bit-0-value-0x0001",
}, function(t)
    local ty = eventd.marker("ptread")
    emit(ty, { n = 1 })
    wait_seen(ty, 1, "the event")
    put("Events", ty, descriptor({ allow(CLEAR | ADMINISTER | PUBLISH, SY) }))
    wait_seen(ty, 0, "every right but read to leave the event unreadable")
    put("Events", ty, descriptor({ allow(READ, SY) }))
    wait_seen(ty, 1, "0x0001 alone to read it")
end)

local ADMIN_DEFAULT = get_hex(nil, "Admin")

--- INDEX as the console; true when eventd accepted it.
local function index(field)
    local r = eventd.query(vm, "EVENTS INDEX " .. field)
    return r.ok, r.stderr
end

--- Put the Admin descriptor, then wait until INDEX answers `expect`.
local function admin_is(sd, expect, what)
    put(nil, "Admin", sd)
    local ok = wait_until(function() return (index("ptadminprobe")) == expect end,
        { timeout = 15, desc = what })
    return ok
end

test("EVENTD_ADMINISTER is 0x0004, and EVENTD_READ alone does not grant it", {
    spec = "eventd *access.eventd-administer-is-bit-2-value-0x0004"
        .. " eventd *access.eventd-read-alone-does-not-grant-eventd-administer",
}, function(t)
    admin_is(descriptor({ allow(ADMINISTER, SY) }), true, "0x0004 to permit INDEX")
    t:assert((index("ptadminfield")), "an Admin descriptor granting 0x0004 permits INDEX")

    -- Read, as a bit and as GENERIC_READ (EVENTD_READ | READ_CONTROL).
    admin_is(descriptor({ allow(READ, SY) }), false, "0x0001 to refuse INDEX")
    local ok, err = index("ptadminfield")
    t:assert(not ok, "EVENTD_READ alone does not permit INDEX")
    t:assert(err:find("EVENTD_ADMINISTER", 1, true), "refused for want of administer: " .. err)
    admin_is(descriptor({ allow(GENERIC_READ, SY) }), false, "GENERIC_READ to refuse INDEX")
    t:assert(not (index("ptadminfield")), "nor does GENERIC_READ")

    -- Every other right together still is not 0x0004.
    admin_is(descriptor({ allow(READ | CLEAR | PUBLISH, SY) }), false, "the other bits to refuse INDEX")
    t:assert(not (index("ptadminfield")), "read, clear and publish together do not permit INDEX")

    vm:run("reg set '" .. key_of(nil, "Admin") .. "' @ hex:" .. ADMIN_DEFAULT):assert_ok()
    wait_until(function() return (index("ptadminprobe")) end,
        { timeout = 15, desc = "the default Admin descriptor to be back" })
end)

--- Metric series by name, read out of the store itself, so the test does
--- not depend on being allowed to read what it is testing publication of.
local function series(name)
    return eventd.sql(vm, eventd.DB.metrics, "SELECT count(*) FROM series WHERE name = '"
        .. name .. "'")[1][1]
end

test("EVENTD_PUBLISH is 0x0008: that bit alone publishes a metric name, and no other bit does", {
    spec = "eventd *access.eventd-publish-is-bit-3-value-0x0008",
}, function(t)
    local p = eventd.marker("ptpub")
    local witness = eventd.marker("ptpubw")
    put("Metrics", p, descriptor({ allow(PUBLISH, SY) }))
    -- A sample under the default wildcard rides in the same datagram,
    -- after the one under test: once it is stored, the one before it has
    -- been decided.
    local function publish(name, w)
        local r = eventd.send_metric(vm, eventd.array({
            { name = name, type = "gauge", value = 1 },
            { name = w, type = "gauge", value = 1 },
        }))
        assert(r.ret and r.ret > 0, "sendto: errno " .. tostring(r.errno))
        wait_until(function() return series(w) == 1 end,
            { timeout = 15, desc = "the witness " .. w })
    end
    wait_until(function()
        publish(p .. ".one", eventd.marker("ptpubw"))
        return series(p .. ".one") == 1
    end, { timeout = 20, desc = "0x0008 to publish" })
    t:assert_eq(series(p .. ".one"), 1, "a name whose descriptor grants only 0x0008 is published")

    put("Metrics", p, descriptor({ allow(READ | CLEAR | ADMINISTER, SY) }))
    -- The change reaches the metric thread through the descriptor
    -- generation; give it the same settling a query would need.
    wait_until(function()
        local probe = p .. "." .. eventd.marker("probe")
        publish(probe, eventd.marker("ptpubw"))
        return series(probe) == 0
    end, { timeout = 20, desc = "the narrower descriptor to apply" })
    publish(p .. ".two", witness)
    t:assert_eq(series(p .. ".two"), 0, "every other right together does not publish")
end)

-- Route closed: EVENTD_CLEAR is reserved and nothing uses it (§7.1), so no
-- operation turns on whether a caller holds bit 1, and no VM test can
-- tell 0x0002 from any other unused bit.
test("EVENTD_CLEAR is bit 1, value 0x0002", {
    spec = "eventd *access.eventd-clear-is-bit-1-value-0x0002",
    skip = true,
    covered_by = "cargo:eventd-client TODO access::EVENTD_CLEAR == 0x0002 and RIGHTS names it as bit 1",
}, function() end)

-- Route closed: the only right GENERIC_WRITE could be seen to grant through
-- EVENTD_CLEAR is a right nothing checks; what is observable of the
-- mapping (administer and publish from GENERIC_WRITE) is the a2 constant
-- chapter's.
test("GENERIC_WRITE maps to a mask that includes EVENTD_CLEAR", {
    spec = "eventd *access.generic-write-already-grants-eventd-clear",
    skip = true,
    covered_by = "cargo:eventd-client TODO access::GENERIC_WRITE & EVENTD_CLEAR != 0",
}, function() end)

test("no operation deletes records on a caller's behalf", {
    spec = "eventd *access.no-operation-uses-eventd-clear",
}, function(t)
    local ty = eventd.marker("ptclear")
    emit(ty, { n = 1 })
    wait_seen(ty, 1, "the event")
    -- Every right there is, so a deleting operation, if there were one,
    -- would be permitted.
    put("Events", ty, descriptor({ allow(0x000F000F, SY) }))
    for _, text in ipairs({ "CLEAR EVENTS " .. ty, "DELETE EVENTS " .. ty,
                            "EVENTS " .. ty .. " CLEAR", "EVENTS " .. ty .. " DELETE" }) do
        local r = eventd.query(vm, text)
        t:assert(not r.ok, "`" .. text .. "` is not an operation eventd performs: " .. r.stdout)
    end
    t:assert_eq(stored(ty), 1, "and the record is still stored")
    t:assert_eq(#eventd.rows(vm, events(ty)), 1, "and still read")
end)

-- ---------------------------------------------------------------------------
-- KACS decides
-- ---------------------------------------------------------------------------

test("every verdict is KACS AccessCheck's: its audit walk, integrity and restricted-SID passes all apply", {
    spec = "eventd *access.eventd-delegates-every-decision-to-kacs-accesscheck",
}, function(t)
    local ty = eventd.marker("ptkacs")
    emit(ty, { n = 1 })
    wait_seen(ty, 1, "the event")

    -- The SACL audit walk: a success-audit ACE makes AccessCheck itself
    -- emit access-audit, from inside eventd's query thread.
    local sacl = access.acl({ access.ace(access.ACE.AUDIT, READ, EVERYONE,
        access.ACE_FLAG.SUCCESSFUL_ACCESS) })
    put("Events", ty, descriptor({ allow(READ, SY), allow(READ, GROUP) }, { sacl = sacl }))
    wait_seen(ty, 1, "the audited descriptor")
    local context = "events:" .. ty
    local audits = eventd.wait_rows(vm,
        'EVENTS access-audit WHERE object_context == x"' .. hex(context) .. '" SINCE 1h ago TAKE 100',
        function(rs) return #rs >= 1 end, { timeout = 15, desc = "an access-audit record" })
    t:assert_eq(audits[1]["process.executable_path"], "/usr/sbin/eventd",
        "the audit record was emitted by eventd's own AccessCheck call")
    t:assert_eq(audits[1].requested_access, READ, "asking for EVENTD_READ")

    with_worker(function(w)
        -- Restricted SIDs: a second pass that only the restricting SIDs
        -- may satisfy. Restricted to Administrators, the token still
        -- reaches the socket but not the GROUP-only grant.
        local member = mint(w, { EVERYONE, AU, BA, GROUP })
        local plain = ask(w, events(ty), { as = member })
        t:assert_eq(#plain.records, 1, "the member reads the event: " .. describe(plain))
        local restricted, e = token.restrict(w, member, { restrict_sids = { BA } })
        t:assert(restricted, "restrict: " .. tostring(e))
        local out = ask(w, events(ty), { as = restricted })
        t:assert_eq(out.status, "end", "the restricted member is answered: " .. describe(out))
        t:assert_eq(#out.records, 0, "and the restricted pass hides the event")

        -- Integrity: a High mandatory label with no-read-up refuses a
        -- Medium caller whatever the DACL grants it.
        local label = access.acl({ access.label_ace(token.INTEGRITY.HIGH, access.LABEL.NO_READ_UP) })
        put("Events", ty, descriptor({ allow(READ, SY), allow(READ, GROUP) }, { sacl = label }))
        wait_until(function() return #ask(w, events(ty), { as = member }).records == 0 end,
            { timeout = 15, desc = "the label to refuse the Medium member" })
        t:assert_eq(#ask(w, events(ty), { as = member }).records, 0,
            "a Medium caller does not read up past a High no-read-up label")
        t:assert_eq(#eventd.rows(vm, events(ty)), 1, "while SYSTEM, at System integrity, still does")
    end)
end)
