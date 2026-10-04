-- eventd TRM §10.2 — The eventd-client Library.
--
-- eventd-client is a Rust library with no binary of its own. Nothing in the
-- image calls `query`, `Tail`, `text` or `access` except evctl, which uses
-- only its wire framing and output types (evctl/src/main.rs), and
-- whatever evctl does is §10.1's to prove. So the library's own guarantees
-- — whole results or none, how a tail reports, how text is quoted, what
-- `access` and `readable` compute — are proved by its unit tests, cited
-- below and run under ptcargo, or listed as TODO where none exists yet.
--
-- Two anchors are about eventd's behaviour as much as the library's, and
-- those run in a VM: that text a person typed must be quoted because a bare
-- keyword is read as the clause, and that a field-only grant shows records.

local eventd = require("helpers.eventd")
local peinit = require("helpers.peinit")
local token = require("helpers.token")
local access = require("helpers.access")
peinit.claim(1)

local vm = eventd.boot({ name = "ev-client" })

-- ---------------------------------------------------------------------------
-- Unit homes
-- ---------------------------------------------------------------------------

-- Route closed: eventd-client is a library with no binary; the only program
-- in the image that links it is evctl, whose behaviour §10.1 covers.
test("eventd-client speaks the query channel: it frames the normative query request", {
    spec = "eventd *client.eventd-client-is-the-library-for-programs-that-query-eventd",
    skip = true,
    covered_by = "cargo:eventd eventd-client wire::tests::sends_the_normative_query_request",
}, function() end)

-- Route closed: no program in the image calls eventd_client::query; evctl
-- drives the wire itself (evctl/src/main.rs execute_query).
test("query() returns every record at end, or the error and no records", {
    spec = "eventd *client.query-returns-a-whole-result-or-none",
    skip = true,
    covered_by = "cargo:eventd eventd-client tests::a_query_that_fails_part_way_gives_nothing",
}, function() end)

-- Route closed: no program in the image uses Tail.
test("a Tail reports the initial result once, whole, at watch, then each live batch", {
    spec = "eventd *client.a-tail-reports-its-initial-result-once-complete",
    skip = true,
    covered_by = "cargo:eventd eventd-client tests::a_tail_reports_its_initial_result_whole_then_live_batches",
}, function() end)

-- Route closed: no program in the image uses Tail.
test("a Tail reads its socket on a thread of its own, through a channel of at most capacity reports", {
    spec = "eventd *client.a-tail-reads-its-socket-on-its-own-thread",
    skip = true,
    covered_by = "cargo:eventd TODO a Tail whose caller never calls updates() still drains the socket " ..
        "until `capacity` reports are queued (the far end's writes complete), then stops reading",
}, function() end)

-- Route closed: no program in the image uses Tail.
test("a Tail its program stops reading is ended by eventd, and reports that it ended", {
    spec = "eventd *client.a-tail-a-program-stops-reading-is-ended-by-eventd",
    skip = true,
    covered_by = "cargo:eventd TODO with capacity 1 and no reader, a stand-in eventd that closes the " ..
        "stream once its write would block leads to Tailed::Ended as the next report, with bounded memory",
}, function() end)

-- Route closed: text::string is a pure function no image program calls.
test("text::string escapes the quote, the backslash and every control character", {
    spec = "eventd *client.text-string-escapes-quotes-backslashes-and-controls",
    skip = true,
    covered_by = "cargo:eventd eventd-client text::tests::strings_escape_quotes_backslashes_and_controls",
}, function() end)

-- Route closed: the access module runs in the calling program; no image
-- program calls it.
test("access resolves the descriptors eventd checks, at eventd's registry paths", {
    spec = "eventd *client.access-checks-the-descriptors-eventd-checks",
    skip = true,
    covered_by = "cargo:eventd eventd-client access::tests::descriptor_paths_sit_under_the_namespace_key",
}, function() end)

-- Route closed: which code eventd links is not observable from outside;
-- eventd's query/security.rs:17-19 imports the rights, generic mapping and
-- `candidates` walk from eventd_client::access, and the cited test pins the walk.
test("eventd and its clients share the rights, the generic mapping and the pattern walk", {
    spec = "eventd *client.eventd-and-its-clients-share-the-rights-mapping-and-pattern-walk",
    skip = true,
    covered_by = "cargo:eventd eventd-client access::tests::candidates_walk_from_the_identifier_to_the_wildcard",
}, function() end)

-- Route closed: field_grants runs in the calling program; eventd's own use
-- of it is the field-only grant, which the VM test below shows.
test("field_grants lists the object GUIDs of a descriptor's allowing object ACEs", {
    spec = "eventd *client.field-grants-are-the-object-guids-of-allowing-object-aces",
    skip = true,
    covered_by = "cargo:eventd eventd-client " ..
        "access::tests::a_descriptor_grants_by_name_the_fields_its_allowing_object_aces_name",
}, function() end)

-- Route closed: readable() runs in the calling program; no image program calls it.
test("readable() weighs every pattern: a specific grant under a denying * is Some, not Nothing", {
    spec = "eventd *client.readable-considers-every-pattern",
    skip = true,
    covered_by = "cargo:eventd TODO readable(Namespace::Logs) with `*` denying and `Logs\\x` granting the " ..
        "caller returns Some { hidden: [\"*\"] }, and with `*` granting and `x` denying, Some { hidden: [\"x\"] }",
}, function() end)

-- Route closed: readable() runs in the calling program; no image program calls it.
test("readable() says Unknown, with the reason, when the policy cannot be read", {
    spec = "eventd *client.unreadable-policy-is-unknown-not-denied",
    skip = true,
    covered_by = "cargo:eventd TODO readable() for a caller denied ENUMERATE_SUB_KEYS on " ..
        "Security\\Logs returns Readable::Unknown(reason), never Nothing",
}, function() end)

-- ---------------------------------------------------------------------------
-- What eventd does with the text and the grants
-- ---------------------------------------------------------------------------

-- PEI-1298 (TRM-bare-keyword-origin): a bare origin named WHERE or STREAM after FROM is read as the origin, not the clause.
-- FROM takes a comma list of identifiers and never
-- looks for a clause keyword there (query_language.rs:779-791), so an origin
-- called WHERE or STREAM written bare is read as the origin, not the clause.
-- The advice to quote holds (an event pattern written bare *is* read as a
-- clause: `EVENTS WHERE`), but the book's example does not.
test("text a person typed must be quoted: bare, an origin called STREAM or WHERE is read as the clause", {
    spec = "eventd *client.text-a-person-typed-is-always-quoted",
    tags = { "known-bug" },
}, function(t)
    for _, origin in ipairs({ "WHERE", "STREAM" }) do
        eventd.send_log(vm, { origin = origin, is_error = false, message = "origin " .. origin })
    end
    eventd.wait_rows(vm, 'LOGS FROM "STREAM" SINCE 10m ago', function(rs) return #rs >= 1 end)
    t:assert(#eventd.rows(vm, 'LOGS FROM "WHERE" SINCE 10m ago') >= 1, "quoted, WHERE is an origin")
    t:assert(#eventd.rows(vm, 'LOGS FROM "STREAM" SINCE 10m ago') >= 1, "quoted, STREAM is an origin")
    local bare = eventd.query(vm, "LOGS FROM WHERE SINCE 10m ago")
    t:assert(not (bare.ok and #bare.rows >= 1 and bare.rows[1].origin == "WHERE"),
        "bare, WHERE is read as the clause, not as the origin: " .. json.encode(bare.rows[1]))
    local p = vm:run_async("/usr/bin/evctl", { args = { "--format", "jsonl", "LOGS FROM STREAM" } })
    local r = p:wait("3s")
    t:assert(r.exit_code ~= 0 or not tostring(r.stdout):find('"origin":"STREAM"', 1, true),
        "bare, STREAM is read as the clause and streams, rather than naming the origin: " .. tostring(r.stdout))
end)

test("records are visible with EVENTD_READ on the root, or on any field alone", {
    spec = "eventd *client.records-are-visible-with-read-on-the-root-or-any-field",
}, function(t)
    local origin = eventd.marker("fo")
    eventd.send_log(vm, { origin = origin, is_error = false, message = "only this" })
    eventd.wait_rows(vm, "LOGS FROM " .. origin .. " SINCE 10m ago", function(rs) return #rs == 1 end)
    local p = assert(io.popen("python3 -c 'import uuid; print(uuid.uuid5(uuid.UUID(" ..
        "\"e7d3a1b0-5c2f-4e8a-9b1d-0a6f3c8e2d4b\"), \"message\").bytes_le.hex())'", "r"))
    local guid = (p:read("a"):gsub("%s+$", "")):gsub("%x%x", function(h) return string.char(tonumber(h, 16)) end)
    p:close()
    local key = eventd.SECURITY .. [[\Logs\]] .. origin
    local sd = access.simple({
        access.ace(access.ACE.ALLOWED, 0x1, token.SID.LOCAL_SYSTEM),
        access.ace(access.ACE.ALLOWED_OBJECT, 0x1, token.SID.TEST_USER, 0, { object_type = guid }) })
    vm:run("reg new '" .. key .. "'")
    eventd.set(vm, "@", "hex:" .. (sd:gsub(".", function(c) return string.format("%02x", c:byte()) end)),
        { key = key }):assert_ok()
    vm:run("sleep 0.5")
    local NOTIFY = token.bit(token.PRIV.CHANGE_NOTIFY)
    local out
    token.as_principal(t, vm, { privs_present = NOTIFY, privs_enabled = NOTIFY }, function(w)
        out = w:run("/usr/bin/evctl", { args = { "--format", "jsonl", "LOGS FROM " .. origin .. " SINCE 10m ago" } })
    end)
    vm:run("reg del '" .. key .. "'")
    local line = out.stdout:match("[^\n]+")
    local row = line and json.decode(line)
    t:assert(row, "a grant on the message field alone shows the record: " .. tostring(out.stderr))
    t:assert_eq(row and row.message, "only this", "with the granted field")
    t:assert(row and row.origin == nil, "and not the ungranted ones: " .. tostring(line))
end)
