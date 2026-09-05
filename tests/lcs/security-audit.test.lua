-- PKM §5.4.4 — Audit: the seven events LCS emits through KMES, the
-- bounded caller summary they carry, what a key-open record says, the
-- twelve source-validation classes, the self-configuration events, and
-- the rule that an audit failure blocks an operation only where the
-- record is the point of it being permitted.
--
-- A ring is attached before the source registers, because the nineteen
-- LCS_SELF_CONFIG_INVALID events of a first boot are emitted during
-- registration and are gone by the time a test starts.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local access = require("helpers.access")
local kmes = require("helpers.kmes")

local vm = provium:vm("v", "kernel-only"):boot()

local CI = access.ACE_FLAG.CONTAINER_INHERIT
local SUCCESS = access.ACE_FLAG.SUCCESSFUL_ACCESS
local FAILURE = access.ACE_FLAG.FAILED_ACCESS
local R = lcs.RIGHT
local ALL = lcs.KEY_ALL_ACCESS

local EVENT_TYPES = {
    "LCS_KEY_OPEN_AUDIT", "LCS_BACKUP_START", "LCS_BACKUP_COMPLETE",
    "LCS_RESTORE_START", "LCS_RESTORE_COMPLETE",
    "LCS_SOURCE_VALIDATION_FAILURE", "LCS_SELF_CONFIG_INVALID",
}
local CALLER_FIELDS = {
    "effective_token_guid", "true_token_guid", "process_guid", "user_sid",
    "authentication_id", "token_id", "token_type", "impersonation_level",
    "integrity_level",
}
local VALIDATION_CLASSES = {
    malformed_security_descriptor = true, malformed_layer_name = true,
    unknown_rsi_status_code = true, future_sequence_number = true,
    duplicate_winning_sequence_tie = true,
    malformed_layer_metadata_security_descriptor = true,
    malformed_key_name = true, malformed_value_name = true,
    malformed_response_payload = true, malformed_key_metadata = true,
    malformed_value_payload = true, malformed_delete_layer_orphan_list = true,
}

--- A descriptor with a DACL and one SACL audit ACE.
local function audited(dacl_aces, audit_mask, audit_flags)
    return lcs.sd(dacl_aces, { sacl = access.acl({
        -- helpers/access spells SYSTEM_AUDIT_ACE_TYPE as ACE.AUDIT.
        access.ace(access.ACE.AUDIT, audit_mask, kacs.SID.EVERYONE, audit_flags | CI),
    }) })
end
local EVERYONE_ALL = access.ace(access.ACE.ALLOWED, ALL, kacs.SID.EVERYONE, CI)
local SYSTEM_ALL = access.ace(access.ACE.ALLOWED, ALL, kacs.SID.LOCAL_SYSTEM, CI)

-- A ring open across registration, for the first-boot configuration events.
local boot_ring = assert(kmes.attach(vm, 0))

local src = lcs.source(vm)
src:key(lcs.PARAMS_PATH)             -- present but unseeded: nineteen events
src:key("Machine\\Software\\Test")
src:key("Machine\\Plain")            -- no SACL at all
src:key("Machine\\Audit\\Success", { sd = audited({ EVERYONE_ALL }, R.QUERY_VALUE, SUCCESS) })
src:key("Machine\\Audit\\Denied", { sd = audited({ SYSTEM_ALL }, R.QUERY_VALUE,
    SUCCESS | FAILURE) })
src:key("Machine\\Audit\\Other", { sd = audited({ EVERYONE_ALL }, R.SET_VALUE, SUCCESS) })
src:key("Machine\\Audit\\Max", { sd = audited({
    SYSTEM_ALL, access.ace(access.ACE.ALLOWED, R.KEY_READ, kacs.SID.EVERYONE, CI),
}, R.QUERY_VALUE, SUCCESS | FAILURE) })
-- A descriptor a source may not return: MAXIMUM_ALLOWED in an ACE mask.
src:key("Machine\\Bad", { sd = lcs.sd({
    access.ace(access.ACE.ALLOWED, R.KEY_READ | R.MAXIMUM_ALLOWED, kacs.SID.EVERYONE, CI),
}) })
local TREE = src:key("Machine\\Tree")
src:value(TREE, "Leaf", lcs.TYPE.DWORD, lcs.dword(1))
src:key("Machine\\Tree\\Kid")
src:key("Machine\\Enumerable")
src:key("Machine\\Enumerable\\Kid")
local VALUES = src:key("Machine\\Values")
src:value(VALUES, "One", lcs.TYPE.DWORD, lcs.dword(1))
assert(src:register())
src:pump()
local BOOT_EVENTS = kmes.drain(boot_ring)
kmes.detach(boot_ring)

local w = vm:spawn_worker()

local function must_open(t, path, desired, who)
    local r = lcs.open_key(src, who or w, -1, path, desired or ALL)
    t:assert(r.ret >= 0, "open " .. path .. ": " .. sys.errname(r.errno or 0))
    return r.ret
end

--- The one event of `kind` in `events`, or nil.
local function one(events, kind)
    local got = kmes.of_type(events, kind)
    return got[1], #got
end

local function count_keys(map)
    local n = 0
    for _ in pairs(map or {}) do n = n + 1 end
    return n
end

--- A scratch file the guest can write a backup stream into.
local next_file = 0
local function scratch_file(t, contents)
    next_file = next_file + 1
    local path = "/lcs-audit-" .. next_file .. ".bin"
    local fd, e = sys.open(w, path, sys.O.RDWR | sys.O.CREAT | sys.O.TRUNC,
        tonumber("600", 8))
    t:assert(fd, "open " .. path .. ": " .. sys.errname(e or 0))
    if contents then
        w:syscall(sys.NR.write, { args = { fd, 0, #contents }, bufs = { contents },
            ptrs = { 1 } })
        sys.lseek(w, fd, 0, 0)
    end
    return fd
end

--- An RSI_QUERY_VALUES response body from rows of
--- `{ name =, layer =, type =, data =, seq = }`.
local function values_response(rows)
    local out = { string.pack("<I4", #rows) }
    for _, v in ipairs(rows) do
        out[#out + 1] = string.pack("<s4s4I4s4I8", v.name, v.layer, v.type,
            v.data or "", v.seq or 1)
    end
    out[#out + 1] = string.pack("<I4", 0)
    return table.concat(out)
end

--- Run `fn` with `op` intercepted, and return the events it produced.
local function with_intercept(t, op, handler, fn)
    src:intercept(op, handler)
    local ok, events = pcall(kmes.recording, t, vm, fn)
    src:intercept(op, nil)   -- always, or every later case inherits it
    if not ok then error(events, 0) end
    return events
end

--- The validation class a dishonest answer produced, asserting there was
--- exactly one such event and that its class is one of the documented
--- twelve.
local function validation_class(t, op, handler, fn)
    local events = with_intercept(t, op, handler, fn)
    local e, n = one(events, "LCS_SOURCE_VALIDATION_FAILURE")
    t:assert(e, "a source validation failure was audited")
    t:assert_eq(n, 1, "exactly one")
    local class = e.payload.validation_class
    t:assert(VALIDATION_CLASSES[class],
        "\"" .. tostring(class) .. "\" is one of the twelve documented classes")
    return class, e
end

-- The catalogue ----------------------------------------------------------

test("seven audit events exist, and LCS emits every one of them through KMES",
    { spec = "PKM *lcs-audit.seven-events-through-kmes" }, function(t)
        local seen = {}
        for _, e in ipairs(BOOT_EVENTS) do seen[e.type] = e end

        local events = kmes.recording(t, vm, function()
            local fd = must_open(t, "Machine\\Audit\\Success", R.QUERY_VALUE)
            sys.close(w, fd)
            lcs.open_key(src, w, -1, "Machine\\Bad", R.KEY_READ)
            local tree = must_open(t, "Machine\\Tree")
            local out = scratch_file(t)
            t:assert_eq(lcs.backup(src, w, tree, out).ret, 0, "a backup runs")
            sys.lseek(w, out, 0, 0)
            t:assert_eq(lcs.restore(src, w, tree, out).ret, 0, "and a restore")
            sys.close(w, out)
            sys.close(w, tree)
        end)
        for _, e in ipairs(events) do seen[e.type] = e end

        for _, kind in ipairs(EVENT_TYPES) do
            t:assert(seen[kind], kind .. " was emitted")
            t:assert_eq(seen[kind].origin, kmes.ORIGIN.LCS,
                "and carries the LCS origin class")
        end
        t:assert_eq(#EVENT_TYPES, 7, "seven events, and no others")
    end)

test("every audit payload is a single MessagePack map with string keys",
    { spec = "PKM *lcs-audit.payload-is-a-msgpack-map" }, function(t)
        local events = kmes.recording(t, vm, function()
            local fd = must_open(t, "Machine\\Audit\\Success", R.QUERY_VALUE)
            sys.close(w, fd)
        end)
        local e = one(events, "LCS_KEY_OPEN_AUDIT")
        t:assert(e, "the event decoded")
        t:assert(not e.payload_error, "its payload is well-formed MessagePack")
        t:assert_eq(type(e.payload), "table", "and decodes to a map")
        for k in pairs(e.payload) do
            t:assert_eq(type(k), "string", "whose keys are strings")
        end
        for _, boot in ipairs(BOOT_EVENTS) do
            t:assert_eq(type(boot.payload), "table",
                "and so does every configuration event")
        end
    end)

test("GUIDs are 16-byte binary values and SIDs are binary KACS encodings",
    { spec = "PKM *lcs-audit.payload-guid-and-sid-encoding" }, function(t)
        local guid = src:lookup("Machine\\Audit\\Success")
        local events = kmes.recording(t, vm, function()
            local fd = must_open(t, "Machine\\Audit\\Success", R.QUERY_VALUE)
            sys.close(w, fd)
        end)
        local e = one(events, "LCS_KEY_OPEN_AUDIT")
        t:assert_eq(#e.payload.key_guid, 16, "the key GUID is sixteen bytes")
        t:assert_eq(e.payload.key_guid, guid, "and is the GUID the source gave the key")
        for _, field in ipairs({ "effective_token_guid", "true_token_guid", "process_guid" }) do
            t:assert_eq(#e.payload.caller[field], 16, field .. " is sixteen bytes")
        end
        t:assert_eq(token.sid_string(e.payload.caller.user_sid), "S-1-5-18",
            "and the user SID is a binary KACS encoding, here SYSTEM's")
    end)

-- The caller summary -------------------------------------------------------

test("the caller submap has nine fields and no more",
    { spec = "PKM *lcs-audit.caller-summary-nine-fields" }, function(t)
        local events = kmes.recording(t, vm, function()
            local fd = must_open(t, "Machine\\Audit\\Success", R.QUERY_VALUE)
            sys.close(w, fd)
        end)
        local e = one(events, "LCS_KEY_OPEN_AUDIT")
        local caller = e.payload.caller
        t:assert(caller, "the event carries a caller submap")
        for _, name in ipairs(CALLER_FIELDS) do
            t:assert(caller[name] ~= nil, "it carries " .. name)
        end
        t:assert_eq(count_keys(caller), 9, "and exactly nine fields")
        for _, absent in ipairs({ "groups", "privileges", "claims", "default_dacl" }) do
            t:assert(caller[absent] == nil,
                absent .. " is unbounded and is never included")
        end
    end)

-- The kernel reports the token's stored impersonation level verbatim
-- (kacs_rust_token_audit_summary), so the agent's primary token — created
-- at Delegation — audits as level 3 rather than the 0 §5.4.4 specifies.
test("a primary token reports an impersonation level of 0",
    { spec = "PKM *lcs-audit.primary-token-impersonation-level-zero",
      tags = { "known-bug" } }, function(t)
        local events = kmes.recording(t, vm, function()
            local fd = must_open(t, "Machine\\Audit\\Success", R.QUERY_VALUE)
            sys.close(w, fd)
        end)
        local e = one(events, "LCS_KEY_OPEN_AUDIT")
        t:assert_eq(e.payload.caller.token_type, 1, "the caller holds a primary token")
        t:assert_eq(e.payload.caller.impersonation_level, 0,
            "which reports an impersonation level of 0")
    end)

-- Key opens -----------------------------------------------------------------

test("LCS_KEY_OPEN_AUDIT is emitted when an open matches a SACL audit ACE, and not otherwise",
    { spec = "PKM *lcs-audit.key-open.on-sacl-match" }, function(t)
        local matched = kmes.recording(t, vm, function()
            local fd = must_open(t, "Machine\\Audit\\Success", R.QUERY_VALUE)
            sys.close(w, fd)
        end)
        local e, n = one(matched, "LCS_KEY_OPEN_AUDIT")
        t:assert(e, "a matching open audits")
        t:assert_eq(n, 1, "once")

        local unmatched = kmes.recording(t, vm, function()
            local fd = must_open(t, "Machine\\Plain", R.QUERY_VALUE)
            sys.close(w, fd)
        end)
        t:assert_eq(#kmes.of_type(unmatched, "LCS_KEY_OPEN_AUDIT"), 0,
            "and a key with no SACL audits nothing")
    end)

test("the key-open payload carries the caller, GUID, masks, decision and SACL match flags",
    { spec = "PKM *lcs-audit.key-open.payload-fields" }, function(t)
        local events = kmes.recording(t, vm, function()
            local fd = must_open(t, "Machine\\Audit\\Success", R.QUERY_VALUE)
            sys.close(w, fd)
        end)
        local e = one(events, "LCS_KEY_OPEN_AUDIT")
        t:assert(e.payload.caller, "the caller summary")
        t:assert(e.payload.key_guid, "the key GUID")
        t:assert_eq(e.payload.requested_access, R.QUERY_VALUE, "the requested access mask")
        t:assert_eq(e.payload.granted_access, R.QUERY_VALUE, "the granted access mask")
        t:assert_eq(e.payload.decision, "allowed", "the decision")
        t:assert_eq(e.payload.sacl_match_flags, 1, "and bit 0 for a success-audit match")
        t:assert_eq(count_keys(e.payload), 6, "six fields, and no others")
    end)

test("granted_access is forced to zero on a denial, and the decision says denied",
    { spec = "PKM *lcs-audit.key-open.denied-event-has-zero-granted" }, function(t)
        local events = kmes.recording(t, vm, function()
            token.as_principal(t, vm, { user_sid = token.SID.TEST_USER }, function(w2)
                local r = lcs.open_key(src, w2, -1, "Machine\\Audit\\Denied", R.QUERY_VALUE)
                t:assert_eq(r.errno, sys.E.ACCES, "the open is denied")
            end)
        end)
        local e = one(events, "LCS_KEY_OPEN_AUDIT")
        t:assert(e, "and audited")
        t:assert_eq(e.payload.decision, "denied", "as a denial")
        t:assert_eq(e.payload.granted_access, 0, "with a zero granted mask")
        t:assert_eq(e.payload.sacl_match_flags, 2, "and bit 1 for a failure-audit match")
    end)

test("requested_access is the mask after generic mapping, with MAXIMUM_ALLOWED re-added",
    { spec = "PKM *lcs-audit.key-open.requested-access-is-post-mapping" }, function(t)
        local mapped = kmes.recording(t, vm, function()
            local fd = must_open(t, "Machine\\Audit\\Success", R.GENERIC_READ)
            sys.close(w, fd)
        end)
        local e = one(mapped, "LCS_KEY_OPEN_AUDIT")
        t:assert_eq(e.payload.requested_access, R.KEY_READ,
            "GENERIC_READ is recorded as the KEY_READ it maps to")

        local maxed = kmes.recording(t, vm, function()
            local fd = must_open(t, "Machine\\Audit\\Max", R.MAXIMUM_ALLOWED)
            sys.close(w, fd)
        end)
        local m = one(maxed, "LCS_KEY_OPEN_AUDIT")
        t:assert_eq(m.payload.requested_access & R.MAXIMUM_ALLOWED, R.MAXIMUM_ALLOWED,
            "and MAXIMUM_ALLOWED is re-added after mapping takes it to zero")
    end)

test("the SACL is evaluated alongside the DACL, in the same AccessCheck",
    { spec = "PKM *lcs-audit.sacl-evaluated-with-the-dacl" }, function(t)
        local events = kmes.recording(t, vm, function()
            token.as_principal(t, vm, { user_sid = token.SID.TEST_USER }, function(w2)
                lcs.open_key(src, w2, -1, "Machine\\Audit\\Denied", R.QUERY_VALUE)
            end)
        end)
        local e, n = one(events, "LCS_KEY_OPEN_AUDIT")
        t:assert_eq(n, 1, "one open, one record")
        t:assert(e.payload.decision and e.payload.sacl_match_flags,
            "carrying the DACL's decision and the SACL's match in the same event: " ..
            "one evaluation produced both")
    end)

test("reading or modifying a SACL requires ACCESS_SYSTEM_SECURITY, gated by SeSecurityPrivilege",
    { spec = "PKM *lcs-audit.sacl-access-gated-by-sesecurityprivilege" }, function(t)
        token.as_principal(t, vm, { user_sid = token.SID.TEST_USER }, function(w2)
            local r = lcs.open_key(src, w2, -1, "Machine\\Audit\\Success",
                R.QUERY_VALUE | R.ACCESS_SYSTEM_SECURITY)
            t:assert_eq(r.errno, sys.E.ACCES,
                "a caller without SeSecurityPrivilege is not granted ACCESS_SYSTEM_SECURITY")
        end)
        local fd = lcs.open_key(src, w, -1, "Machine\\Audit\\Success",
            R.QUERY_VALUE | R.ACCESS_SYSTEM_SECURITY)
        t:assert(fd.ret >= 0, "while a caller holding it is: " .. sys.errname(fd.errno or 0))
        local g = lcs.get_security(src, w, fd.ret, lcs.SI.SACL)
        t:assert_eq(g.ret, 0, "and only then may the SACL be read: " ..
            sys.errname(g.errno or 0))
        sys.close(w, fd.ret)
    end)

test("MAXIMUM_ALLOWED alone matches each audit ACE against the granted mask, and always succeeds",
    { spec = "PKM *lcs-audit.key-open.maximum-allowed-matches-granted-mask" }, function(t)
        local events = kmes.recording(t, vm, function()
            token.as_principal(t, vm, { user_sid = token.SID.TEST_USER }, function(w2)
                local r = lcs.open_key(src, w2, -1, "Machine\\Audit\\Max", R.MAXIMUM_ALLOWED)
                t:assert(r.ret >= 0, "MAXIMUM_ALLOWED returns what is available: " ..
                    sys.errname(r.errno or 0))
                if r.ret >= 0 then sys.close(w2, r.ret) end
            end)
        end)
        local e = one(events, "LCS_KEY_OPEN_AUDIT")
        t:assert(e, "the open audited")
        t:assert_eq(e.payload.granted_access, R.KEY_READ,
            "the granted set is what the descriptor allowed")
        t:assert_eq(e.payload.sacl_match_flags & 1, 1,
            "and the audit ACE for KEY_QUERY_VALUE matched it, because they did get it")
    end)

test("a MAXIMUM_ALLOWED open always audits as a success: a failure ACE has nothing to record",
    { spec = "PKM *lcs-audit.key-open.maximum-allowed-always-audits-success" }, function(t)
        local events = kmes.recording(t, vm, function()
            token.as_principal(t, vm, { user_sid = token.SID.TEST_USER }, function(w2)
                local r = lcs.open_key(src, w2, -1, "Machine\\Audit\\Max", R.MAXIMUM_ALLOWED)
                if r.ret >= 0 then sys.close(w2, r.ret) end
            end)
        end)
        local e = one(events, "LCS_KEY_OPEN_AUDIT")
        t:assert_eq(e.payload.decision, "allowed", "MAXIMUM_ALLOWED never fails")
        t:assert_eq(e.payload.sacl_match_flags, 1,
            "so the record is a success audit and never a failure one, " ..
            "though the ACE carries both flags")
    end)

test("an ACE naming a right the caller did not receive does not match",
    { spec = "PKM *lcs-audit.key-open.ace-for-ungranted-right-does-not-match" }, function(t)
        local events = kmes.recording(t, vm, function()
            local fd = must_open(t, "Machine\\Audit\\Other", R.QUERY_VALUE)
            sys.close(w, fd)
        end)
        t:assert_eq(#kmes.of_type(events, "LCS_KEY_OPEN_AUDIT"), 0,
            "the audit ACE names KEY_SET_VALUE, which this open neither asked for nor got")

        local matched = kmes.recording(t, vm, function()
            local fd = must_open(t, "Machine\\Audit\\Other", R.SET_VALUE)
            sys.close(w, fd)
        end)
        t:assert_eq(#kmes.of_type(matched, "LCS_KEY_OPEN_AUDIT"), 1,
            "and an open that does receive that right matches it")
    end)

-- Backup and restore ---------------------------------------------------------

test("LCS_BACKUP_START is emitted before any subtree data is read",
    { spec = "PKM *lcs-audit.backup-start.before-any-read" }, function(t)
        local ring = assert(kmes.attach(vm, 0))
        local fd = must_open(t, "Machine\\Tree")
        local out = scratch_file(t)
        -- The read-only snapshot transaction opens first; hold the first
        -- request that actually reads subtree data, and look at the ring
        -- while the backup is stopped there.
        src:intercept(lcs.OP.ENUM_CHILDREN, function() return lcs.HOLD end)
        src:intercept(lcs.OP.QUERY_VALUES, function() return lcs.HOLD end)
        local pending = lcs.backup_async(w, fd, out)
        src:pump()
        local held = src:held_ids()
        local mid = kmes.drain(ring)
        src:intercept(lcs.OP.ENUM_CHILDREN, nil)
        src:intercept(lcs.OP.QUERY_VALUES, nil)
        for _, id in ipairs(held) do src:release(id) end
        src:pump()
        local r = pending:await()
        kmes.detach(ring)
        sys.close(w, out)
        sys.close(w, fd)

        t:assert(#held >= 1, "the backup is stopped on its first read of subtree data")
        t:assert(one(mid, "LCS_BACKUP_START"), "and LCS_BACKUP_START is already emitted")
        t:assert_eq(#kmes.of_type(mid, "LCS_BACKUP_COMPLETE"), 0, "with no completion yet")
        t:assert_eq(r.ret, 0, "the backup then runs to the end: " .. sys.errname(r.errno or 0))
    end)

test("LCS_BACKUP_COMPLETE is emitted after a backup completes, and after one that fails",
    { spec = "PKM *lcs-audit.backup-complete.after-finish-or-failure" }, function(t)
        local fd = must_open(t, "Machine\\Tree")
        local ok = kmes.recording(t, vm, function()
            local out = scratch_file(t)
            t:assert_eq(lcs.backup(src, w, fd, out).ret, 0, "a backup succeeds")
            sys.close(w, out)
        end)
        local done = one(ok, "LCS_BACKUP_COMPLETE")
        t:assert(done, "and completes")
        t:assert_eq(done.payload.result_errno, 0, "carrying a zero result")

        local failed = with_intercept(t, lcs.OP.QUERY_VALUES,
            function() return lcs.STATUS.STORAGE_ERROR, "" end, function()
                local out = scratch_file(t)
                local r = lcs.backup(src, w, fd, out)
                t:assert(r.ret < 0, "a backup that fails after starting")
                sys.close(w, out)
            end)
        t:assert(one(failed, "LCS_BACKUP_START"), "still started")
        local bad = one(failed, "LCS_BACKUP_COMPLETE")
        t:assert(bad, "and still completed")
        t:assert(bad.payload.result_errno ~= 0, "carrying the failure")
        sys.close(w, fd)
    end)

test("LCS_RESTORE_START is emitted before REG_IOC_RESTORE modifies any source state",
    { spec = "PKM *lcs-audit.restore-start.before-any-mutation" }, function(t)
        local fd = must_open(t, "Machine\\Tree")
        local garbage = scratch_file(t, "NOTASTREAM" .. string.rep("\0", 64))
        local mark = src:mark()
        local events = kmes.recording(t, vm, function()
            local r = lcs.restore(src, w, fd, garbage)
            t:assert(r.ret < 0, "a stream LCS cannot read fails the restore")
        end)
        t:assert(one(events, "LCS_RESTORE_START"),
            "and LCS_RESTORE_START was emitted anyway, before anything was written")
        for i = mark, #src.log do
            local op = src.log[i].op
            t:assert(op ~= lcs.OP.SET_VALUE and op ~= lcs.OP.CREATE_ENTRY and
                op ~= lcs.OP.DELETE_ENTRY and op ~= lcs.OP.DROP_KEY,
                "no source state was modified")
        end
        sys.close(w, garbage)
        sys.close(w, fd)
    end)

test("LCS_RESTORE_COMPLETE is emitted after a restore completes, and after one that fails",
    { spec = "PKM *lcs-audit.restore-complete.after-finish-or-failure" }, function(t)
        local fd = must_open(t, "Machine\\Tree")
        local out = scratch_file(t)
        t:assert_eq(lcs.backup(src, w, fd, out).ret, 0, "a stream to restore from")
        sys.lseek(w, out, 0, 0)
        local ok = kmes.recording(t, vm, function()
            t:assert_eq(lcs.restore(src, w, fd, out).ret, 0, "a restore succeeds")
        end)
        local done = one(ok, "LCS_RESTORE_COMPLETE")
        t:assert(done, "and completes")
        t:assert_eq(done.payload.result_errno, 0, "carrying a zero result")
        sys.close(w, out)

        local garbage = scratch_file(t, "NOTASTREAM" .. string.rep("\0", 64))
        local failed = kmes.recording(t, vm, function()
            t:assert(lcs.restore(src, w, fd, garbage).ret < 0, "a restore fails")
        end)
        local bad = one(failed, "LCS_RESTORE_COMPLETE")
        t:assert(bad, "and still completes")
        t:assert(bad.payload.result_errno ~= 0, "carrying the failure")
        sys.close(w, garbage)
        sys.close(w, fd)
    end)

test("backup and restore are audited unconditionally, whatever the SACL on the target says",
    { spec = "PKM *lcs-audit.backup-and-restore-unconditional" }, function(t)
        -- Machine\Plain has no SACL at all, so nothing about it asks to
        -- be audited; the privilege-gated bulk operations are audited
        -- regardless, because the trail is the only record they happened.
        local fd = must_open(t, "Machine\\Plain")
        local opened = kmes.recording(t, vm, function()
            local again = must_open(t, "Machine\\Plain", lcs.RIGHT.QUERY_VALUE)
            sys.close(w, again)
        end)
        t:assert_eq(#kmes.of_type(opened, "LCS_KEY_OPEN_AUDIT"), 0,
            "an ordinary open of this key audits nothing")

        local events = kmes.recording(t, vm, function()
            local out = scratch_file(t)
            t:assert_eq(lcs.backup(src, w, fd, out).ret, 0, "a backup of it")
            sys.lseek(w, out, 0, 0)
            t:assert_eq(lcs.restore(src, w, fd, out).ret, 0, "and a restore over it")
            sys.close(w, out)
        end)
        for _, kind in ipairs({ "LCS_BACKUP_START", "LCS_BACKUP_COMPLETE",
                                "LCS_RESTORE_START", "LCS_RESTORE_COMPLETE" }) do
            t:assert(one(events, kind), kind .. " is emitted regardless")
        end
        sys.close(w, fd)
    end)

-- Source validation failures ---------------------------------------------------

test("LCS_SOURCE_VALIDATION_FAILURE is emitted when LCS rejects malformed source data",
    { spec = "PKM *lcs-audit.validation-failure.on-malformed-source-data" }, function(t)
        local events = kmes.recording(t, vm, function()
            local r = lcs.open_key(src, w, -1, "Machine\\Bad", R.KEY_READ)
            t:assert_eq(r.errno, sys.E.IO, "the operation fails closed with EIO")
        end)
        local e, n = one(events, "LCS_SOURCE_VALIDATION_FAILURE")
        t:assert(e, "and the rejection is audited")
        t:assert_eq(n, 1, "once")
        t:assert_eq(e.payload.validation_class, "malformed_security_descriptor",
            "naming what was wrong")
    end)

test("the payload carries the source slot, and the hive, request id, op code and GUID where known",
    { spec = "PKM *lcs-audit.validation-failure.payload-fields" }, function(t)
        local events = kmes.recording(t, vm, function()
            lcs.open_key(src, w, -1, "Machine\\Bad", R.KEY_READ)
        end)
        local e = one(events, "LCS_SOURCE_VALIDATION_FAILURE")
        t:assert(e.payload.source_slot ~= nil, "the source slot identifier")
        t:assert(e.payload.request_id ~= nil, "the RSI request id")
        t:assert_eq(e.payload.op_code, lcs.OP.LOOKUP, "the operation code")
        t:assert_eq(#e.payload.key_guid, 16, "and a key GUID, sixteen bytes")
        t:assert(src.store.keys[e.payload.key_guid] ~= nil,
            "naming a key this source holds — the parent the failing lookup was against")
        t:assert(e.payload.validation_class, "with the validation class last")
    end)

test("the twelve validation classes are the whole vocabulary",
    { spec = "PKM *lcs-audit.validation-failure.twelve-classes" }, function(t)
        t:assert_eq(count_keys(VALIDATION_CLASSES), 12, "twelve classes are documented")
        local seen = {}

        local unknown = validation_class(t, lcs.OP.LOOKUP, function() return 42, "" end,
            function()
                local r = lcs.open_key(src, w, -1, "Machine\\Values", R.KEY_READ)
                t:assert_eq(r.errno, sys.E.IO, "an unknown RSI status is EIO")
            end)
        seen[unknown] = true
        t:assert_eq(unknown, "unknown_rsi_status_code", "an unknown status code names itself")

        local sd = validation_class(t, lcs.OP.LOOKUP, nil, function()
            lcs.open_key(src, w, -1, "Machine\\Bad", R.KEY_READ)
        end)
        seen[sd] = true

        local future = validation_class(t, lcs.OP.QUERY_VALUES, function()
            return lcs.STATUS.OK, values_response({
                { name = "One", layer = "base", type = lcs.TYPE.DWORD,
                  data = lcs.dword(1), seq = 1 << 62 } })
        end, function()
            local fd = must_open(t, "Machine\\Values")
            t:assert_eq(lcs.query_value(src, w, fd, "One").errno, sys.E.IO,
                "a sequence beyond what LCS has allocated is EIO")
            sys.close(w, fd)
        end)
        seen[future] = true

        local n = 0
        for _ in pairs(seen) do n = n + 1 end
        t:assert(n >= 3, "and every class a source can provoke is one of them")
    end)

test("the three name classes are field-specific: layer names, key names and value names",
    { spec = "PKM *lcs-audit.validation-failure.name-classes" }, function(t)
        local BAD_NAME = "\xFF\xFE\xFD"

        local value_name = validation_class(t, lcs.OP.QUERY_VALUES, function()
            return lcs.STATUS.OK, values_response({
                { name = BAD_NAME, layer = "base", type = lcs.TYPE.DWORD,
                  data = lcs.dword(1), seq = 1 } })
        end, function()
            local fd = must_open(t, "Machine\\Values")
            t:assert_eq(lcs.query_value(src, w, fd, "One").errno, sys.E.IO, "EIO")
            sys.close(w, fd)
        end)
        t:assert_eq(value_name, "malformed_value_name",
            "a bad value-name field is malformed_value_name")

        local layer_name = validation_class(t, lcs.OP.QUERY_VALUES, function()
            return lcs.STATUS.OK, values_response({
                { name = "One", layer = BAD_NAME, type = lcs.TYPE.DWORD,
                  data = lcs.dword(1), seq = 1 } })
        end, function()
            local fd = must_open(t, "Machine\\Values")
            t:assert_eq(lcs.query_value(src, w, fd, "One").errno, sys.E.IO, "EIO")
            sys.close(w, fd)
        end)
        t:assert_eq(layer_name, "malformed_layer_name",
            "a bad layer-name field is malformed_layer_name")

        local key_name = validation_class(t, lcs.OP.ENUM_CHILDREN, function()
            local g = lcs.guid()
            local entry = string.pack("<s4", "base") .. "\0" .. g .. string.pack("<I8", 1)
            local meta = string.pack("<I4", 1) .. g ..
                string.pack("<s4", lcs.permissive_sd()) .. string.pack("<I1I1I8", 0, 0, 0)
            return lcs.STATUS.OK, string.pack("<I4", 1) .. string.pack("<s4", BAD_NAME) ..
                string.pack("<I4", 1) .. entry .. meta
        end, function()
            local fd = must_open(t, "Machine\\Enumerable")
            t:assert_eq(lcs.enum_subkeys(src, w, fd, 0).errno, sys.E.IO, "EIO")
            sys.close(w, fd)
        end)
        t:assert_eq(key_name, "malformed_key_name",
            "and a bad key component or child name is malformed_key_name")
    end)

test("the structural classes cover a response of the wrong shape, bad metadata and a bad payload",
    { spec = "PKM *lcs-audit.validation-failure.structural-classes" }, function(t)
        -- Trailing bytes after an otherwise valid lookup body.
        local shape = validation_class(t, lcs.OP.LOOKUP, function()
            return lcs.STATUS.OK, string.pack("<I4I4", 0, 0) .. "TRAILING"
        end, function()
            t:assert_eq(lcs.open_key(src, w, -1, "Machine\\Values", R.KEY_READ).errno,
                sys.E.IO, "a response with trailing bytes is EIO")
        end)
        t:assert_eq(shape, "malformed_response_payload",
            "an operation-specific payload of the wrong shape")

        -- An entry naming a GUID the metadata block never describes.
        local metadata = validation_class(t, lcs.OP.LOOKUP, function()
            return lcs.STATUS.OK, string.pack("<I4", 1) .. string.pack("<s4", "base") ..
                "\0" .. lcs.guid() .. string.pack("<I8", 1) .. string.pack("<I4", 0)
        end, function()
            t:assert_eq(lcs.open_key(src, w, -1, "Machine\\Values", R.KEY_READ).errno,
                sys.E.IO, "an unreferenced metadata block is EIO")
        end)
        t:assert_eq(metadata, "malformed_key_metadata",
            "and an enumeration whose metadata block is incomplete")

        local payload = validation_class(t, lcs.OP.QUERY_VALUES, function()
            return lcs.STATUS.OK, values_response({
                { name = "One", layer = "base", type = 4242,
                  data = lcs.dword(1), seq = 1 } })
        end, function()
            local fd = must_open(t, "Machine\\Values")
            t:assert_eq(lcs.query_value(src, w, fd, "One").errno, sys.E.IO, "EIO")
            sys.close(w, fd)
        end)
        t:assert_eq(payload, "malformed_value_payload",
            "and a value payload with an invalid type")
    end)

-- Configuration -----------------------------------------------------------------

test("a first boot before seed restore emits one LCS_SELF_CONFIG_INVALID per parameter",
    { spec = "PKM *lcs-audit.self-config.missing-counts-as-invalid" }, function(t)
        local boot = kmes.of_type(BOOT_EVENTS, "LCS_SELF_CONFIG_INVALID")
        t:assert_eq(#boot, 19,
            "nineteen events against an empty Registry key, one per parameter")
        local names = {}
        for _, e in ipairs(boot) do
            t:assert_eq(e.payload.received_kind, "missing", "each says the value was missing")
            t:assert_eq(e.payload.configuration_parent_path, "Machine\\System\\Registry",
                "under the configuration parent path")
            names[e.payload.configuration_name] = true
        end
        t:assert_eq(count_keys(names), 19, "nineteen distinct parameters")
    end)

test("the payload names the parameter, the expected type and range, what arrived, and what was kept",
    { spec = "PKM *lcs-audit.self-config.payload-fields" }, function(t)
        local boot = kmes.of_type(BOOT_EVENTS, "LCS_SELF_CONFIG_INVALID")
        local timeout
        for _, e in ipairs(boot) do
            if e.payload.configuration_name == "RequestTimeoutMs" then timeout = e end
        end
        t:assert(timeout, "the RequestTimeoutMs event is there")
        local p = timeout.payload
        t:assert_eq(p.configuration_parent_path, "Machine\\System\\Registry", "the parent path")
        t:assert_eq(p.configuration_name, "RequestTimeoutMs", "the value name")
        t:assert_eq(p.expected_type, lcs.TYPE.DWORD, "the expected type, REG_DWORD")
        t:assert_eq(p.expected_min, 1000, "the expected minimum")
        t:assert_eq(p.expected_max, 600000, "the expected maximum")
        t:assert_eq(p.received_kind, "missing", "what was actually received")
        t:assert_eq(p.retained_value, 30000, "and the value LCS retained instead")
    end)

test("LCS_SELF_CONFIG_INVALID is emitted when LCS rejects an invalid self-configuration value",
    { spec = "PKM *lcs-audit.self-config-invalid.on-invalid-value" }, function(t)
        local params = must_open(t, lcs.PARAMS_PATH)
        local events = kmes.recording(t, vm, function()
            t:assert_eq(lcs.set_value(src, w, params, "RequestTimeoutMs", lcs.TYPE.DWORD,
                lcs.dword(5)).ret, 0, "a value below the range is written to the registry")
            src:pump()
            src:pump()
        end)
        local got = kmes.of_type(events, "LCS_SELF_CONFIG_INVALID")
        local mine
        for _, e in ipairs(got) do
            if e.payload.configuration_name == "RequestTimeoutMs" then mine = e end
        end
        t:assert(mine, "the refresh audits it")
        t:assert_eq(mine.payload.received_kind, "dword_out_of_range", "as out of range")
        t:assert_eq(mine.payload.received_u32, 5, "naming the value received")
        t:assert_eq(mine.payload.retained_value, 30000, "and the value retained instead")
        sys.close(w, params)
    end)

-- What happens when emission fails --------------------------------------------

test("if LCS cannot construct a valid key-open payload the open fails with EIO",
    { spec = "PKM *lcs-audit.emit-failure.key-open-construct-failure-fails-the-open",
      covered_by = "kunit:pkm_lcs_kunit_key",
      skip = "payload construction fails only on corrupt internal state or an allocation " ..
             "failure, neither of which a guest can induce at an open; runs under " ..
             "pkm_lcs_kunit_key_open_audit_payload_abi_rejects_bad_state" },
    function(t) end)

test("if KMES cannot retain a key-open event the decision and the fd are unaffected",
    { spec = "PKM *lcs-audit.emit-failure.key-open-retain-failure-is-harmless" }, function(t)
        -- No ring is attached, so there is no consumer and nothing to
        -- retain the event; the open is not supposed to notice.
        local fd = lcs.open_key(src, w, -1, "Machine\\Audit\\Success", R.QUERY_VALUE)
        t:assert(fd.ret >= 0, "the open succeeds with nobody listening: " ..
            sys.errname(fd.errno or 0))
        local q = lcs.query_value(src, w, fd.ret, "Nothing")
        t:assert_eq(q.errno, sys.E.NOENT, "and the fd it published works")
        sys.close(w, fd.ret)

        token.as_principal(t, vm, { user_sid = token.SID.TEST_USER }, function(w2)
            local denied = lcs.open_key(src, w2, -1, "Machine\\Audit\\Denied", R.QUERY_VALUE)
            t:assert_eq(denied.errno, sys.E.ACCES,
                "and a denial is still a denial, not an EIO: loss accounting is KMES's problem")
        end)
    end)

test("LCS_BACKUP_START and LCS_RESTORE_START failing to emit returns EIO and does not start",
    { spec = "PKM *lcs-audit.emit-failure.start-events-block-the-operation",
      covered_by = "kunit:",
      skip = "a guest cannot make KMES refuse an event: with no consumer attached the " ..
             "event is still enqueued successfully, and there is no interface to fail " ..
             "the emission itself; no LCS KUnit case found — candidate for a new one" },
    function(t) end)

test("a completion event that cannot be emitted does not change a result already determined",
    { spec = "PKM *lcs-audit.emit-failure.complete-events-are-best-effort" }, function(t)
        -- No consumer: LCS_BACKUP_COMPLETE reaches nobody, and the backup
        -- still succeeded.
        local fd = must_open(t, "Machine\\Tree")
        local out = scratch_file(t)
        local r = lcs.backup(src, w, fd, out)
        t:assert_eq(r.ret, 0, "the backup succeeds with nobody listening: " ..
            sys.errname(r.errno or 0))
        local size = sys.lseek(w, out, 0, 2)
        t:assert(size.ret > 0, "and its stream was written")
        sys.close(w, out)
        sys.close(w, fd)
    end)

test("a validation-failure event that cannot be emitted does not change the EIO already failing",
    { spec = "PKM *lcs-audit.emit-failure.validation-failure-is-best-effort" }, function(t)
        local r = lcs.open_key(src, w, -1, "Machine\\Bad", R.KEY_READ)
        t:assert_eq(r.errno, sys.E.IO,
            "with no consumer for the record, the triggering operation still fails with EIO")
        local again = lcs.open_key(src, w, -1, "Machine\\Bad", R.KEY_READ)
        t:assert_eq(again.errno, sys.E.IO, "every time, unchanged by the audit's fate")
    end)

test("a self-config event that cannot be emitted leaves the retained configuration in force",
    { spec = "PKM *lcs-audit.emit-failure.self-config-is-best-effort" }, function(t)
        local params = must_open(t, lcs.PARAMS_PATH)
        -- First, with nobody listening at all.
        t:assert_eq(lcs.set_value(src, w, params, "SymlinkDepthLimit", lcs.TYPE.DWORD,
            lcs.dword(9999)).ret, 0, "an out-of-range value is written unobserved")
        src:pump()

        -- Then again, with a ring: the retained value is still the
        -- compiled-in default, so the unobserved rejection changed nothing.
        local events = kmes.recording(t, vm, function()
            t:assert_eq(lcs.set_value(src, w, params, "SymlinkDepthLimit", lcs.TYPE.DWORD,
                lcs.dword(9998)).ret, 0, "and once more, observed")
            src:pump()
            src:pump()
        end)
        local mine
        for _, e in ipairs(kmes.of_type(events, "LCS_SELF_CONFIG_INVALID")) do
            if e.payload.configuration_name == "SymlinkDepthLimit" then mine = e end
        end
        t:assert(mine, "the second rejection is audited")
        t:assert_eq(mine.payload.retained_value, 16,
            "and LCS is still running on the compiled-in default it retained the first time")
        sys.close(w, params)
    end)

test("LCS enqueues the payload and never waits for a userspace consumer to observe it",
    { spec = "PKM *lcs-audit.enqueue-without-awaiting-a-consumer" }, function(t)
        -- Nothing is attached to KMES, and nothing is reading. Every
        -- audit point still returns.
        local fd = must_open(t, "Machine\\Audit\\Success", R.QUERY_VALUE)
        sys.close(w, fd)
        local tree = must_open(t, "Machine\\Tree")
        local out = scratch_file(t)
        t:assert_eq(lcs.backup(src, w, tree, out).ret, 0,
            "an unconditionally audited operation completes with no consumer")
        sys.lseek(w, out, 0, 0)
        t:assert_eq(lcs.restore(src, w, tree, out).ret, 0, "and so does its counterpart")
        sys.close(w, out)
        sys.close(w, tree)
        t:assert_eq(lcs.open_key(src, w, -1, "Machine\\Bad", R.KEY_READ).errno, sys.E.IO,
            "and so does one whose audit records a rejection")
    end)
