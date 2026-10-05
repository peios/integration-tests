-- eventd TRM §7.3 — per-field control: object ACEs over a two-level object
-- type list, field GUIDs derived by UUID v5 from the field's name, the
-- names each kind of field goes by, and the list built for each record.
--
-- One file-scope eventd serves every test; each writes descriptors only
-- for its own marker-named identifiers. Every field GUID here is computed
-- on the host by Python's `uuid` module from the namespace §B gives —
-- never by eventd's code — so a test that hides a field by its GUID also
-- proves the derivation a third party has to reproduce.
--
-- Records are read through the query channel directly (PSPU §3.15–§3.17)
-- rather than through evctl's JSON, because a JSON decoder drops a key
-- whose value is nil, and "which keys does the record carry" is the
-- question most of these tests ask.
--
-- Two shapes of descriptor recur: a field deny (deny one field's GUID,
-- then allow the whole record) and a field-only grant (allow object ACEs
-- naming fields, nothing for the root — §7.3's MonitoringTeam). KACS
-- propagates a node's denial to its ancestors, as MS-DTYP does, so a
-- record whose list holds a denied field has its root denied too, and
-- what is shown of it is only ever its granted fields. Some tests assert
-- only "no shown record carries the denied field, and a record without
-- it is shown unchanged", which fails if the GUID named the wrong field
-- without depending on how the denied record is shaped.

local eventd = require("helpers.eventd")
local peinit = require("helpers.peinit")
local token = require("helpers.token")
local access = require("helpers.access")
peinit.claim(1)

local vm = eventd.boot({ name = "ev-fields" })

-- ---------------------------------------------------------------------------
-- Descriptors
-- ---------------------------------------------------------------------------

local SY = token.SID.LOCAL_SYSTEM
local READ, PUBLISH = 0x1, 0x8

--- A GUID in the byte order an ACE carries it (PCDS: the first three
--- fields little-endian), computed by the host's Python.
local function python_guid(expr)
    local p = assert(io.popen("python3 -c 'import uuid; print((" .. expr .. ").bytes_le.hex())'"))
    local h = p:read("l")
    p:close()
    assert(h and #h == 32, "python uuid: " .. tostring(h))
    return eventd.unhex(h)
end

--- The data type root GUIDs, from §B.
local ROOT = {
    events = python_guid('uuid.UUID("a1b2c3d4-0001-4000-8000-000000000001")'),
    logs = python_guid('uuid.UUID("a1b2c3d4-0001-4000-8000-000000000002")'),
}

local function allow(mask) return access.ace(access.ACE.ALLOWED, mask, SY) end
--- An allowing object ACE for SYSTEM naming `guid` (nil: no object type).
local function allow_object(mask, guid)
    return access.ace(access.ACE.ALLOWED_OBJECT, mask, SY, 0, { object_type = guid })
end
local function allow_field(field) return allow_object(READ, eventd.field_guid(field)) end
local function deny_field(field)
    return access.ace(access.ACE.DENIED_OBJECT, READ, SY, 0, { object_type = eventd.field_guid(field) })
end

--- Deny each of `fields`, then allow the record: a readable record
--- without those fields.
local function hiding(fields, mask)
    local aces = {}
    for _, f in ipairs(fields) do aces[#aces + 1] = deny_field(f) end
    aces[#aces + 1] = allow(mask or READ)
    return access.simple(aces)
end

--- Allow exactly `fields` and not the root.
local function only(fields)
    local aces = {}
    for _, f in ipairs(fields) do aces[#aces + 1] = allow_field(f) end
    return access.simple(aces)
end

-- ---------------------------------------------------------------------------
-- Reading records with their nil-valued keys intact (PSPU §3.15–§3.17)
-- ---------------------------------------------------------------------------

--- The records a query returns to the console, decoded from the wire.
local function records(text)
    local out = eventd.rq.ask(vm, text, { timeout = 20 })
    assert(out.status == "end", "query `" .. text .. "` ended " .. tostring(out.status or out.closed)
        .. ": " .. tostring(out.error))
    return out.records
end

--- A record's keys, sorted, as one string.
local function keys(rec)
    local ks = {}
    for k in pairs(rec) do ks[#ks + 1] = k end
    table.sort(ks)
    return table.concat(ks, ",")
end

local function keyset(list)
    local copy = {}
    for i, k in ipairs(list) do copy[i] = k end
    table.sort(copy)
    return table.concat(copy, ",")
end

--- Wait until `text` returns records satisfying `pred`; returns them.
local function settle(text, pred, desc)
    local last
    wait_until(function()
        last = records(text)
        return pred(last)
    end, { timeout = 15, interval = 0.25, desc = desc or text })
    return last
end

local function count(n) return function(rs) return #rs == n end end

--- The record whose field `f` is `v`.
local function where(rs, f, v)
    for _, r in ipairs(rs) do if r[f] == v then return r end end
    return nil
end

local function emit(ty, payload)
    local r = eventd.emit(vm, ty, payload)
    assert(r.ret == 0, "kmes_emit " .. ty .. ": errno " .. tostring(r.errno))
end

local function ev(ty) return "EVENTS " .. ty .. " SINCE 1h ago TAKE 1000" end

local HEADERS = { "timestamp", "cpu_id", "sequence", "origin_class", "event_type",
    "effective_token_guid", "true_token_guid", "process_guid", "boot_id" }

-- ---------------------------------------------------------------------------
-- Granting some fields and not others
-- ---------------------------------------------------------------------------

--- No shown record carries `field`, and the record whose `k` is `v` is
--- shown: true of a field deny before and after 92d4dbd.
local function denied_everywhere(field, k, v)
    return function(rs)
        for _, r in ipairs(rs) do if r[field] ~= nil then return false end end
        return where(rs, k, v) ~= nil
    end
end

test("a field the caller may not read is absent, exactly as if the record never carried it", {
    spec = "eventd *fieldaccess.a-descriptor-can-grant-some-fields-of-a-record-and-not-others"
        .. " eventd *fieldaccess.an-unauthorized-field-is-absent-as-if-never-carried"
        .. " eventd *fieldaccess.each-field-is-included-or-excluded-by-its-node-verdict",
}, function(t)
    -- The deny on `secret` denies the record's root as well (KACS
    -- propagates a denial to ancestors); the record is shown with the
    -- fields still granted (Authorizer::check, security.rs:147-171).
    local ty = eventd.marker("ptfield")
    emit(ty, { n = 1, secret = "s" })
    emit(ty, { n = 2 })
    settle(ev(ty), count(2))
    eventd.put_descriptor(vm, "Events", ty, hiding({ "secret" }))
    local rs = settle(ev(ty), function(r)
        return #r == 2 and where(r, "n", 1) and where(r, "n", 1).secret == nil
    end, "the field deny to apply")
    local carried, never = where(rs, "n", 1), where(rs, "n", 2)
    t:assert_eq(keys(carried), keys(never),
        "the record that carried `secret` has the same keys as the one that never did")
    t:assert_eq(carried.n, 1, "the rest of the record is there")
    for _, h in ipairs(HEADERS) do
        t:assert(carried[h] ~= nil, "header field " .. h .. " is still there")
    end
end)

test("an object ACE with no GUID applies to every field, and one with a field's GUID to that field", {
    spec = "eventd *fieldaccess.an-object-ace-without-a-guid-applies-to-every-field"
        .. " eventd *fieldaccess.an-object-ace-with-a-field-guid-applies-to-that-field",
}, function(t)
    local ty = eventd.marker("ptobj")
    emit(ty, { n = 1, extra = "x" })
    emit(ty, { n = 2 })
    local full = settle(ev(ty), count(2))
    local with, without = keys(where(full, "n", 1)), keys(where(full, "n", 2))

    -- An object ACE with no object type applies to the whole tree.
    eventd.put_descriptor(vm, "Events", ty, access.simple({ allow_object(READ, nil) }))
    local rs = settle(ev(ty), count(2), "an object ACE with no GUID to grant the records")
    t:assert_eq(keys(where(rs, "n", 1)), with, "an object ACE without a GUID grants every field")

    -- A field GUID names a level-1 node, and only in the list of a record
    -- that carries the field.
    eventd.put_descriptor(vm, "Events", ty, access.simple({
        access.ace(access.ACE.DENIED_OBJECT, READ, SY, 0, { object_type = eventd.field_guid("extra") }),
        allow_object(READ, nil) }))
    rs = settle(ev(ty), denied_everywhere("extra", "n", 2), "a deny on extra's GUID")
    for _, r in ipairs(rs) do t:assert_eq(r.extra, nil, "no record shows extra") end
    t:assert_eq(keys(where(rs, "n", 2)), without,
        "and the record without extra, whose list has no such node, is shown whole")
end)

test("the object type list has the type's root at level 0 and its fields at level 1", {
    spec = "eventd *fieldaccess.the-object-type-list-is-the-type-root-at-level-0-and-one-field-per-level-1-node",
}, function(t)
    local ty = eventd.marker("ptroot")
    emit(ty, { n = 1, extra = "x" })
    emit(ty, { n = 2 })
    local full = settle(ev(ty), count(2))
    local with, without = keys(where(full, "n", 1)), keys(where(full, "n", 2))

    -- Another data type's root is not in an event's list at all.
    eventd.put_descriptor(vm, "Events", ty, access.simple({ allow_object(READ, ROOT.logs) }))
    settle(ev(ty), count(0), "the Logs root GUID to grant nothing on an event")
    t:assert_eq(#records(ev(ty)), 0, "the Logs root GUID names no node of an event's list")

    -- Naming the Events root GUID grants the level-0 node, and with it
    -- every field below.
    eventd.put_descriptor(vm, "Events", ty, access.simple({ allow_object(READ, ROOT.events) }))
    local rs = settle(ev(ty), count(2), "the Events root GUID to grant the records")
    t:assert_eq(keys(where(rs, "n", 1)), with, "the Events root GUID is the list's level-0 node")

    -- And a field GUID is a level-1 node below it.
    eventd.put_descriptor(vm, "Events", ty, access.simple({
        access.ace(access.ACE.DENIED_OBJECT, READ, SY, 0, { object_type = eventd.field_guid("extra") }),
        allow_object(READ, ROOT.events) }))
    rs = settle(ev(ty), denied_everywhere("extra", "n", 2), "a deny on extra's GUID")
    for _, r in ipairs(rs) do t:assert_eq(r.extra, nil, "no record shows extra") end
    t:assert_eq(keys(where(rs, "n", 2)), without,
        "and the record without extra, whose list has no such node, is shown whole")
end)

test("a field's GUID is UUID v5 of its name, so a name never seen before can be named", {
    spec = "eventd *fieldaccess.field-guids-are-derived-not-registered"
        .. " eventd *fieldaccess.a-field-guid-is-uuid-v5-of-the-utf-8-field-name-in-the-eventd-namespace"
        .. " eventd *fieldaccess.the-same-field-name-always-yields-the-same-guid"
        .. " eventd *fieldaccess.a-field-guid-does-not-depend-on-the-event-type-carrying-it",
}, function(t)
    -- A field name minted for this run, and so registered nowhere.
    local fresh = eventd.marker("fld")
    local base = eventd.marker("ptguid")
    local a, b = base .. ".a", base .. "." .. eventd.marker("other")
    for _, ty in ipairs({ a, b }) do
        emit(ty, { [fresh] = "hidden", n = 1 })
        emit(ty, { [fresh .. "x"] = "kept", n = 2 })
    end
    settle(ev(base .. ".*"), count(4))
    eventd.put_descriptor(vm, "Events", base, hiding({ fresh }))
    local rs = settle(ev(base .. ".*"), function(r)
        local kept = 0
        for _, x in ipairs(r) do
            if x[fresh] ~= nil then return false end
            if x.n == 2 then kept = kept + 1 end
        end
        return kept == 2
    end, "the host-computed GUID to hide " .. fresh)
    for _, r in ipairs(rs) do
        t:assert_eq(r[fresh], nil, r.event_type .. ": " .. fresh .. " is denied by its derived GUID")
        if r.n == 2 then
            t:assert_eq(r[fresh .. "x"], "kept", r.event_type .. ": a different name is a different GUID")
        end
    end
    local types = {}
    for _, r in ipairs(rs) do if r.n == 2 then types[r.event_type] = true end end
    t:assert(types[a] and types[b], "both types' records without the field are shown")
end)

test("an event header field is named by its column name", {
    spec = "eventd *fieldaccess.an-event-header-field-is-named-by-its-column-name",
}, function(t)
    local ty = eventd.marker("pthdr")
    emit(ty, { n = 1 })
    settle(ev(ty), count(1))
    eventd.put_descriptor(vm, "Events", ty, hiding({ "cpu_id", "process_guid", "sequence" }))
    local r = settle(ev(ty), function(rs) return #rs == 1 and rs[1].cpu_id == nil end)[1]
    for _, gone in ipairs({ "cpu_id", "process_guid", "sequence" }) do
        t:assert_eq(r[gone], nil, gone .. " is hidden by GUID(\"" .. gone .. "\")")
    end
    for _, kept in ipairs({ "timestamp", "event_type", "origin_class", "effective_token_guid",
                            "true_token_guid", "boot_id", "n" }) do
        t:assert(r[kept] ~= nil, kept .. " is untouched")
    end
end)

test("an event payload field is named by its flattened dot path", {
    spec = "eventd *fieldaccess.an-event-payload-field-is-named-by-its-flattened-dot-path",
}, function(t)
    local ty = eventd.marker("ptdot")
    emit(ty, { source = { name = "n", kind = "k" }, granted_access = 7, i = 1 })
    emit(ty, { source = { kind = "k2" }, i = 2 })
    settle(ev(ty), count(2))
    eventd.put_descriptor(vm, "Events", ty, hiding({ "source.name", "granted_access" }))
    local rs = settle(ev(ty), function(r)
        for _, x in ipairs(r) do
            if x["source.name"] ~= nil or x.granted_access ~= nil then return false end
        end
        return where(r, "i", 2) ~= nil
    end, "the dot-path deny")
    for _, r in ipairs(rs) do
        t:assert_eq(r["source.name"], nil, "source.name is denied by GUID(\"source.name\")")
        t:assert_eq(r.granted_access, nil, "a top-level payload field by its own name")
    end
    t:assert_eq(where(rs, "i", 2)["source.kind"], "k2",
        "and the sibling path source.kind is its own field, untouched")
end)

local function lg(origin) return "LOGS FROM " .. origin .. " SINCE 1h ago TAKE 1000" end

test("a log field is named by its column name", {
    spec = "eventd *fieldaccess.a-log-field-is-named-by-its-column-name",
}, function(t)
    local origin = eventd.marker("ptlogf")
    eventd.send_log(vm, { origin = origin, is_error = true, message = "m" })
    settle(lg(origin), count(1))
    eventd.put_descriptor(vm, "Logs", origin, hiding({ "message", "is_error" }))
    local r = settle(lg(origin), function(rs) return #rs == 1 and rs[1].message == nil end)[1]
    t:assert_eq(r.message, nil, "message is hidden by GUID(\"message\")")
    t:assert_eq(r.is_error, nil, "is_error by GUID(\"is_error\")")
    t:assert_eq(r.origin, origin, "origin is untouched")
    t:assert(r.timestamp ~= nil and r.boot_id ~= nil, "and so are timestamp and boot_id")
end)

local function mq(name) return "METRIC " .. name .. " SINCE 1h ago" end

test("the fixed metric fields are named timestamp, boot_id, name, type and value", {
    spec = "eventd *fieldaccess.the-fixed-metric-field-names",
}, function(t)
    -- A sample whose timestamp is hidden is still placed by its time, and
    -- returned without the field.
    local one, two = eventd.marker("ptmf"), eventd.marker("ptmf")
    for _, n in ipairs({ one, two }) do
        eventd.send_metric(vm, { name = n, type = "gauge", value = 5, labels = { device = "d" } })
        settle(mq(n), count(1))
    end
    eventd.put_descriptor(vm, "Metrics", one, hiding({ "boot_id", "type" }, READ | PUBLISH))
    eventd.put_descriptor(vm, "Metrics", two, hiding({ "timestamp", "name", "value" }, READ | PUBLISH))
    local r1 = settle(mq(one), function(rs) return #rs == 1 and rs[1].type == nil end)[1]
    local r2 = settle(mq(two), function(rs) return #rs == 1 and rs[1].value == nil end)[1]
    t:assert_eq(keys(r1), keyset({ "timestamp", "name", "value", "device" }),
        "boot_id and type are hidden by their names' GUIDs")
    t:assert_eq(keys(r2), keyset({ "boot_id", "type", "device" }),
        "and timestamp, name and value by theirs")
end)

test("a metric label is named by its label key", {
    spec = "eventd *fieldaccess.a-metric-label-is-named-by-its-label-key",
}, function(t)
    local base = eventd.marker("ptmlabel")
    local with, without = base .. ".core", base .. ".other"
    eventd.send_metric(vm, { name = with, type = "gauge", value = 1, labels = { core = "1" } })
    eventd.send_metric(vm, { name = without, type = "gauge", value = 2, labels = { corex = "1" } })
    settle(mq(with), count(1)); settle(mq(without), count(1))
    eventd.put_descriptor(vm, "Metrics", base, hiding({ "core" }, READ | PUBLISH))
    settle(mq(without .. " "), count(1))
    local ok = wait_until(function()
        for _, r in ipairs(records(mq(with))) do if r.core ~= nil then return false end end
        return true
    end, { timeout = 15, desc = "the label deny" })
    t:assert(ok, "no sample of " .. with .. " shows the label core")
    local other = records(mq(without))
    t:assert_eq(#other, 1, "the series without core is shown")
    t:assert_eq(other[1].corex, "1", "with its own label corex, a different name and GUID")
end)

test("a suppressed payload path has no GUID: a grant naming it never exposes its value", {
    spec = "eventd *fieldaccess.suppressed-payload-fields-get-no-guid",
}, function(t)
    local ty = eventd.marker("ptsup")
    -- cpu_id collides with a header; a.b is not a valid path segment.
    emit(ty, { cpu_id = 99, ["a.b"] = 5 })
    eventd.wait_rows(vm, ev(ty), function(rs) return #rs == 1 end)
    eventd.put_descriptor(vm, "Events", ty, only({ "cpu_id", "a.b" }))
    local rs = settle(ev(ty), count(1), "the field-only grant to show the record")
    t:assert_eq(keys(rs[1]), "cpu_id", "only the header cpu_id is granted")
    t:assert(rs[1].cpu_id ~= 99, "and it is the header's value, never the payload's: "
        .. tostring(rs[1].cpu_id))
end)

test("a field ACE applies to the fields of the pattern whose descriptor holds it", {
    spec = "eventd *fieldaccess.a-field-ace-is-scoped-by-the-pattern-descriptor-holding-it",
}, function(t)
    local scoped, other = eventd.marker("ptscope"), eventd.marker("ptscope")
    emit(scoped .. ".x", { secret = "s", n = 1 })
    emit(scoped .. ".x", { n = 2 })
    emit(other .. ".x", { secret = "s" })
    settle(ev(scoped .. ".x"), count(2)); settle(ev(other .. ".x"), count(1))
    eventd.put_descriptor(vm, "Events", scoped, hiding({ "secret" }))
    settle(ev(scoped .. ".x"), denied_everywhere("secret", "n", 2), "the deny in " .. scoped)
    for _, r in ipairs(records(ev(scoped .. ".x"))) do
        t:assert_eq(r.secret, nil, "the ACE in " .. scoped .. "'s descriptor governs "
            .. scoped .. ".x's secret")
    end
    t:assert_eq(records(ev(other .. ".x"))[1].secret, "s",
        "and the same field of another pattern's records is untouched")
end)

test("granting three field GUIDs and no root yields records of exactly those three keys", {
    spec = "eventd *fieldaccess.a-grant-of-three-field-guids-yields-records-with-exactly-those-three-keys",
}, function(t)
    local ty = eventd.marker("ptthree")
    emit(ty, { granted_access = 1, target_sid = "x" })
    eventd.wait_rows(vm, ev(ty), function(rs) return #rs == 1 end)
    eventd.put_descriptor(vm, "Events", ty, only({ "timestamp", "event_type", "cpu_id" }))
    local rs = settle(ev(ty), count(1), "the monitoring grant to show the record")
    t:assert_eq(keys(rs[1]), keyset({ "timestamp", "event_type", "cpu_id" }),
        "the record carries exactly the three granted keys")
end)

test("each event's list is its own header fields and present payload fields", {
    spec = "eventd *fieldaccess.the-list-is-built-from-the-fields-present-in-the-record"
        .. " eventd *fieldaccess.an-event-list-has-every-header-field-and-every-present-unsuppressed-payload-field"
        .. " eventd *fieldaccess.two-events-of-the-same-type-can-produce-different-lists",
}, function(t)
    local ty = eventd.marker("ptlist")
    emit(ty, { k = 1, a = 1, b = 1 })
    emit(ty, { k = 2, b = 2 })
    emit(ty, { k = 3, a = 3 })
    eventd.wait_rows(vm, ev(ty), function(rs) return #rs == 3 end)

    -- Every header, plus a and k: each record shows its own headers and
    -- whichever of a and k it carries.
    local granted = { "a", "k" }
    for _, h in ipairs(HEADERS) do granted[#granted + 1] = h end
    eventd.put_descriptor(vm, "Events", ty, only(granted))
    local rs = settle(ev(ty), count(3), "the header-and-payload grant to show all three")
    local headers = {}
    for i, h in ipairs(HEADERS) do headers[i] = h end
    local function with(...)
        local l = { table.unpack(headers) }
        for _, f in ipairs({ ... }) do l[#l + 1] = f end
        return keyset(l)
    end
    t:assert_eq(keys(where(rs, "k", 1)), with("a", "k"), "{k, a, b}: every header, k and a")
    t:assert_eq(keys(where(rs, "k", 2)), with("k"), "{k, b}: every header and k")
    t:assert_eq(keys(where(rs, "k", 3)), with("a", "k"), "{k, a}: every header, k and a")

    -- Granting only a: the record without a has nothing in its list the
    -- descriptor grants, and is not shown at all.
    eventd.put_descriptor(vm, "Events", ty, only({ "a" }))
    rs = settle(ev(ty), count(2), "the a-only grant")
    for _, r in ipairs(rs) do t:assert_eq(keys(r), "a", "a record of type " .. ty .. " shows only a") end
end)

test("every log record's list is the same six fields", {
    spec = "eventd *fieldaccess.every-log-record-has-the-same-six-field-list",
}, function(t)
    local origin = eventd.marker("ptsix")
    eventd.send_log(vm, { origin = origin, is_error = false, message = "a" })
    eventd.send_log(vm, { origin = origin, is_error = true, message = "b" })
    eventd.wait_rows(vm, lg(origin), function(rs) return #rs == 2 end)
    local six = { "timestamp", "origin", "is_error", "message", "job_id", "boot_id" }
    eventd.put_descriptor(vm, "Logs", origin, only(six))
    local rs = settle(lg(origin), count(2), "the six-field grant to show the logs")
    for _, r in ipairs(rs) do
        t:assert_eq(keys(r), keyset(six), "a log record is exactly the six fields")
    end
end)

test("a metric's list is the five fixed fields and its series' label keys", {
    spec = "eventd *fieldaccess.a-metric-list-has-the-five-fixed-fields-and-the-series-label-keys",
}, function(t)
    local base = eventd.marker("ptml")
    local a, b = base .. ".a", base .. ".b"
    eventd.send_metric(vm, { name = a, type = "gauge", value = 1, labels = { core = "0" } })
    eventd.send_metric(vm, { name = b, type = "gauge", value = 2, labels = { device = "d" } })
    eventd.wait_rows(vm, mq(a), function(rs) return #rs == 1 end)
    eventd.wait_rows(vm, mq(b), function(rs) return #rs == 1 end)
    local five = { "timestamp", "boot_id", "name", "type", "value" }
    local granted = { "core" }
    for _, f in ipairs(five) do granted[#granted + 1] = f end
    eventd.put_descriptor(vm, "Metrics", base, only(granted))
    local with_core = settle(mq(a), count(1), "the fixed-field grant to show the core series")[1]
    local with_device = settle(mq(b), count(1), "and the device series")[1]
    t:assert_eq(keys(with_core), keyset(granted), "the core series shows the five and core")
    t:assert_eq(keys(with_device), keyset(five), "the device series shows the five; device is not granted")
end)

test("aggregate outputs have no GUID, and show when their sources may be read", {
    spec = "eventd *fieldaccess.aggregate-outputs-are-omitted-from-the-list"
        .. " eventd *fieldaccess.an-aggregate-is-visible-when-its-source-records-and-fields-are-authorized",
}, function(t)
    local ty = eventd.marker("ptagg")
    for i = 1, 3 do emit(ty, { num = i }) end
    settle(ev(ty), count(3))
    local by = "EVENTS " .. ty .. " SINCE 1h ago COUNT BY event_type"
    local sum = "EVENTS " .. ty .. " SINCE 1h ago GROUP event_type SUM num"
    -- Deny GUIDs with the aggregates' own names: if they were nodes of
    -- the list, these would remove them.
    eventd.put_descriptor(vm, "Events", ty, hiding({ "count", "sum", "avg", "min", "max" }))
    local counted = settle(by, count(1), "COUNT BY under the deny")
    t:assert_eq(counted[1].count, 3, "count is shown though GUID(\"count\") is denied")
    local summed = records(sum)
    t:assert_eq(#summed, 1, "the group is shown")
    t:assert_eq(summed[1].sum, 6, "sum is shown though GUID(\"sum\") is denied")

    -- Take away the source field: the sum's input is no longer readable.
    eventd.put_descriptor(vm, "Events", ty, hiding({ "num" }))
    settle(sum, count(0), "SUM num to disappear with num")
    t:assert_eq(#records(sum), 0, "an aggregate over a field that may not be read is not shown")
end)
