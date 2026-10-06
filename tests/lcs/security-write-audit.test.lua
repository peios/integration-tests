-- PKM §5.4.4 — Audit of registry writes: the continuous-audit mask a key
-- handle takes from the key's SYSTEM_ALARM ACEs at open, the write records
-- it gates (lcs.audit.value.set, .value.deleted, .key.deleted and the
-- rest), the descriptor-change record a SACL change always writes, key
-- creation gated on the parent's SACL, and the one record that says how a
-- transaction holding recorded writes ended (PEI-617).
--
-- RequestTimeoutMs is seeded at its minimum, so a write the source holds
-- times out inside a test's lifetime.
--
-- Payload field paths are nested maps (PGSS §6.4): `object.key.value.name`
-- is `payload.object.key.value.name`, and a hyphenated segment needs
-- brackets, as in `payload.access["audit-mask"]`.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local access = require("helpers.access")
local kmes = require("helpers.kmes")

local vm = provium:vm("v", "kernel-only"):boot()

local CI = access.ACE_FLAG.CONTAINER_INHERIT
local SUCCESS = access.ACE_FLAG.SUCCESSFUL_ACCESS
local R = lcs.RIGHT
local ALL = lcs.KEY_ALL_ACCESS
local ETIMEDOUT = 110

local EVERYONE_ALL = access.ace(access.ACE.ALLOWED, ALL, kacs.SID.EVERYONE, CI)

-- The eight records this file covers; security-audit.test.lua covers the
-- other seven.
local WRITE_EVENT_TYPES = {
    "lcs.audit.value.set", "lcs.audit.value.deleted", "lcs.audit.key.tombstoned",
    "lcs.audit.key.deleted", "lcs.audit.key.hidden", "lcs.audit.key.created",
    "lcs.audit.key.descriptor.changed", "lcs.audit.transaction.committed",
}

--- A descriptor whose SACL holds one SYSTEM_ALARM ACE for Everyone over
--- `mask`, with a DACL granting Everyone everything.
local function alarmed(mask)
    return lcs.sd({ EVERYONE_ALL }, { sacl = access.acl({
        access.ace(access.ACE.ALARM, mask, kacs.SID.EVERYONE, 0),
    }) })
end

local WRITE_SD = alarmed(R.SET_VALUE)
local SACL_SD = lcs.permissive_sd()

local src = lcs.source(vm)
src:seed_param("RequestTimeoutMs", 1000)
local WRITE = src:key("Machine\\Alarm\\Write", { sd = WRITE_SD })
src:value(WRITE, "Old", lcs.TYPE.SZ, lcs.sz("before"))
src:key("Machine\\Alarm\\Refused", { sd = alarmed(R.SET_VALUE) })
src:key("Machine\\Alarm\\Doomed", { sd = alarmed(R.DELETE) })
src:key("Machine\\Alarm\\DeleteOnly", { sd = alarmed(R.DELETE) })
src:key("Machine\\Alarm\\Fixed", { sd = alarmed(R.SET_VALUE) })
src:key("Machine\\Alarm\\Late", { sd = alarmed(R.SET_VALUE) })
src:key("Machine\\Alarm\\Txn", { sd = alarmed(R.SET_VALUE) })
src:key("Machine\\Alarm\\Dacl", { sd = alarmed(R.WRITE_DAC) })
src:key("Machine\\Alarm\\Sacl", { sd = SACL_SD })
src:key("Machine\\Alarm\\Plain", { sd = lcs.permissive_sd() })
src:key("Machine\\Audited", { sd = lcs.sd({ EVERYONE_ALL }, { sacl = access.acl({
    access.ace(access.ACE.AUDIT, R.CREATE_SUB_KEY, kacs.SID.EVERYONE, SUCCESS),
}) }) })
assert(src:register())
src:pump()

local w = vm:spawn_worker()

local function must_open(t, path, desired)
    local r = lcs.open_key(src, w, -1, path, desired)
    t:assert(r.ret >= 0, "open " .. path .. ": " .. sys.errname(r.errno or 0))
    return r.ret
end

--- The one event of `kind` in `events`, and how many there were.
local function one(events, kind)
    local got = kmes.of_type(events, kind)
    return got[1], #got
end

local function count_keys(map)
    local n = 0
    for _ in pairs(map or {}) do n = n + 1 end
    return n
end

-- Writes ---------------------------------------------------------------------

test("an alarm ACE on a key makes a value write through its handle a record",
    { spec = {
        "PKM *lcs-audit.write.alarm-mask-cached-at-open",
        "PKM *lcs-audit.write.recorded-when-right-overlaps-mask",
        "PKM *lcs-audit.write.payload-fields",
        "PKM *lcs-audit.write.data-recorded-as-sha256-digest",
        "PKM *lcs-audit.write.previous-value-recorded",
        "PKM *lcs-audit.events-through-kmes",
    } }, function(t)
        local events = kmes.recording(t, vm, function()
            local fd = must_open(t, "Machine\\Alarm\\Write", R.SET_VALUE | R.QUERY_VALUE)
            local r = lcs.set_value(src, w, fd, "Old", lcs.TYPE.DWORD, lcs.dword(7))
            t:assert_eq(r.ret, 0, "the write succeeds: " .. sys.errname(r.errno or 0))
            sys.close(w, fd)
        end)
        local e, n = one(events, "lcs.audit.value.set")
        t:assert(e, "the write is recorded")
        t:assert_eq(n, 1, "once")
        t:assert_eq(e.origin, kmes.ORIGIN.LCS, "through KMES, with the LCS origin")

        local p = e.payload
        t:assert_eq(count_keys(p), 5,
            "subject, object, access, mutation and outcome, and no others")
        t:assert_eq(token.sid_string(p.subject.token.sid), "S-1-5-18",
            "the caller summary names SYSTEM")
        t:assert_eq(p.object.kind, "key", "object.kind is key")
        t:assert_eq(p.object.key.guid, WRITE, "object.key.guid is the handle's key")
        t:assert_eq(p.object.key.path, "Machine\\Alarm\\Write", "object.key.path its path")
        t:assert_eq(p.object.key.layer.name, "base", "and the layer written is base")

        local v = p.object.key.value
        t:assert_eq(count_keys(v), 7, "the value: name, three fields new, three previous")
        t:assert_eq(v.name, "Old", "object.key.value.name")
        t:assert_eq(v.type, lcs.TYPE.DWORD, "the type written")
        t:assert_eq(v.length, 4, "its length")
        t:assert_eq(v.digest, lcs.sha256(lcs.dword(7)),
            "and the SHA-256 digest of its data, never the data")
        t:assert_eq(v["type-previous"], lcs.TYPE.SZ, "the value it replaced: its type")
        t:assert_eq(v["length-previous"], #lcs.sz("before"), "its length")
        t:assert_eq(v["digest-previous"], lcs.sha256(lcs.sz("before")), "and its digest")

        t:assert_eq(p.access.requested, R.SET_VALUE, "access.requested is KEY_SET_VALUE")
        t:assert_eq(p.access.granted, R.SET_VALUE | R.QUERY_VALUE,
            "access.granted is the handle's grant")
        t:assert_eq(p.access.matched, R.SET_VALUE, "access.matched the overlap")
        t:assert_eq(p.access["audit-mask"], R.SET_VALUE, "access.audit-mask the alarm's mask")
        t:assert_eq(type(p.mutation.sequence), "number", "mutation.sequence is stamped")
        t:assert_eq(p.outcome.success, true, "outcome.success is true")
        t:assert_eq(count_keys(p.outcome), 1, "with no errno")
    end)

test("a value delete records the value it removed",
    { spec = "PKM *lcs-audit.write.previous-value-recorded" }, function(t)
        local fd = must_open(t, "Machine\\Alarm\\Write", R.SET_VALUE | R.QUERY_VALUE)
        local r = lcs.set_value(src, w, fd, "Gone", lcs.TYPE.BINARY, "\1\2\3")
        t:assert_eq(r.ret, 0, "a value to delete: " .. sys.errname(r.errno or 0))
        local events = kmes.recording(t, vm, function()
            local d = lcs.delete_value(src, w, fd, "Gone")
            t:assert_eq(d.ret, 0, "the delete succeeds: " .. sys.errname(d.errno or 0))
        end)
        sys.close(w, fd)
        local e, n = one(events, "lcs.audit.value.deleted")
        t:assert(e, "the delete is recorded")
        t:assert_eq(n, 1, "once")
        local v = e.payload.object.key.value
        t:assert_eq(v.name, "Gone", "naming the value")
        t:assert_eq(v["type-previous"], lcs.TYPE.BINARY, "with the type it had")
        t:assert_eq(v["length-previous"], 3, "its length")
        t:assert_eq(v["digest-previous"], lcs.sha256("\1\2\3"), "and its digest")
        t:assert(v.digest == nil, "and nothing of a new value")
    end)

test("no alarm ACE, or one whose mask misses the right, means no record",
    { spec = "PKM *lcs-audit.write.recorded-when-right-overlaps-mask" }, function(t)
        local events = kmes.recording(t, vm, function()
            local plain = must_open(t, "Machine\\Alarm\\Plain", R.SET_VALUE)
            t:assert_eq(lcs.set_value(src, w, plain, "V", lcs.TYPE.DWORD, lcs.dword(1)).ret, 0,
                "a write to a key with no SACL succeeds")
            sys.close(w, plain)
            local other = must_open(t, "Machine\\Alarm\\DeleteOnly", R.SET_VALUE)
            t:assert_eq(lcs.set_value(src, w, other, "V", lcs.TYPE.DWORD, lcs.dword(1)).ret, 0,
                "and so does one to a key whose alarm covers only DELETE")
            sys.close(w, other)
        end)
        t:assert_eq(#kmes.of_type(events, "lcs.audit.value.set"), 0, "neither is recorded")
    end)

test("each write is gated on the right its handle's gate checks",
    { spec = "PKM *lcs-audit.write.rights-per-event" }, function(t)
        local doomed = src:lookup("Machine\\Alarm\\Doomed")
        local events = kmes.recording(t, vm, function()
            local fd = must_open(t, "Machine\\Alarm\\Doomed", R.DELETE)
            local d = lcs.delete_key(src, w, fd)
            t:assert_eq(d.ret, 0, "the key is deleted: " .. sys.errname(d.errno or 0))
            sys.close(w, fd)
        end)
        local e, n = one(events, "lcs.audit.key.deleted")
        t:assert(e, "a delete through a DELETE-alarmed handle is recorded")
        t:assert_eq(n, 1, "once")
        local p = e.payload
        t:assert_eq(count_keys(p), 4, "subject, object, access and outcome")
        t:assert_eq(p.object.key.guid, doomed, "naming the deleted key")
        t:assert_eq(p.object.key.path, "Machine\\Alarm\\Doomed", "by its full path")
        t:assert_eq(p.access.requested, R.DELETE, "and the right it needed, DELETE")
        t:assert_eq(p.access.matched, R.DELETE, "which the mask covered")
        t:assert_eq(p.outcome.success, true, "successfully")
    end)

test("a write the handle's gate refuses is recorded as a failure",
    { spec = "PKM *lcs-audit.write.failures-recorded" }, function(t)
        local events = kmes.recording(t, vm, function()
            local fd = must_open(t, "Machine\\Alarm\\Refused", R.QUERY_VALUE)
            local r = lcs.set_value(src, w, fd, "V", lcs.TYPE.DWORD, lcs.dword(1))
            t:assert_eq(r.errno, sys.E.ACCES, "a handle without KEY_SET_VALUE is refused")
            sys.close(w, fd)
        end)
        local e, n = one(events, "lcs.audit.value.set")
        t:assert(e, "the refusal is recorded: the mask covers rights the grant lacks")
        t:assert_eq(n, 1, "once")
        local p = e.payload
        t:assert_eq(p.outcome.success, false, "as a failure")
        t:assert_eq(p.outcome.errno, -sys.E.ACCES, "with the negative errno the caller got")
        t:assert_eq(p.request["timed-out"], false, "which was not a timeout")
        t:assert_eq(p.access.granted, R.QUERY_VALUE, "the handle's grant")
        t:assert_eq(count_keys(p.object.key), 2,
            "and only the key's GUID and path: the request was refused before it read more")
    end)

test("the mask is fixed when the key is opened, and a SACL change is recorded",
    { spec = {
        "PKM *lcs-audit.write.mask-fixed-for-handle-life",
        "PKM *lcs-audit.descriptor-changed.sacl-change-always-recorded",
    } }, function(t)
        local before = must_open(t, "Machine\\Alarm\\Fixed", R.SET_VALUE)
        local events = kmes.recording(t, vm, function()
            local sec = must_open(t, "Machine\\Alarm\\Fixed",
                R.ACCESS_SYSTEM_SECURITY | R.READ_CONTROL)
            local s = lcs.set_security(src, w, sec, lcs.SI.SACL,
                lcs.sd({ EVERYONE_ALL }, { sacl = access.acl({}) }))
            t:assert_eq(s.ret, 0, "the alarm ACE is removed: " .. sys.errname(s.errno or 0))
            sys.close(w, sec)
            t:assert_eq(lcs.set_value(src, w, before, "V", lcs.TYPE.DWORD, lcs.dword(2)).ret, 0,
                "a handle opened before still writes")
        end)
        t:assert_eq(#kmes.of_type(events, "lcs.audit.key.descriptor.changed"), 1,
            "the SACL change itself is recorded")
        t:assert_eq(#kmes.of_type(events, "lcs.audit.value.set"), 1,
            "and the old handle is still audited after its alarm ACE is gone")
        sys.close(w, before)

        local after = kmes.recording(t, vm, function()
            local fd = must_open(t, "Machine\\Alarm\\Fixed", R.SET_VALUE)
            t:assert_eq(lcs.set_value(src, w, fd, "V", lcs.TYPE.DWORD, lcs.dword(3)).ret, 0,
                "a handle opened after writes too")
            sys.close(w, fd)
        end)
        t:assert_eq(#kmes.of_type(after, "lcs.audit.value.set"), 0,
            "but is not audited: its open saw no alarm ACE")
    end)

test("a write the source does not answer in time is recorded as possibly applied",
    { spec = "PKM *lcs-audit.write.timed-out-may-apply-later" }, function(t)
        local fd = must_open(t, "Machine\\Alarm\\Late", R.SET_VALUE | R.QUERY_VALUE)
        local events = kmes.recording(t, vm, function()
            src:intercept(lcs.OP.SET_VALUE, function() return lcs.HOLD end)
            local ok, err = pcall(function()
                local p = lcs.set_value_async(w, fd, "Late", lcs.TYPE.DWORD, lcs.dword(9))
                src:pump()
                local r = p:await()
                t:assert_eq(r.errno, ETIMEDOUT,
                    "the caller is told ETIMEDOUT: " .. sys.errname(r.errno or 0))
            end)
            src:intercept(lcs.OP.SET_VALUE, nil)
            if not ok then error(err, 0) end
            -- The source answers after all, and the write lands.
            for _, id in ipairs(src:held_ids()) do src:release(id) end
            src:pump()
        end)
        local q = lcs.query_value(src, w, fd, "Late")
        t:assert_eq(q.ret, 0, "the value is there: " .. sys.errname(q.errno or 0))
        t:assert_eq(q.data, lcs.dword(9), "the write was applied later")
        sys.close(w, fd)

        local e, n = one(events, "lcs.audit.value.set")
        t:assert(e, "the write was recorded")
        t:assert_eq(n, 1, "once: the late reply adds no second record")
        local p = e.payload
        t:assert_eq(p.outcome.success, false, "as a failure")
        t:assert_eq(p.outcome.errno, -ETIMEDOUT, "with ETIMEDOUT")
        t:assert_eq(p.request["timed-out"], true, "and request.timed-out true")
        t:assert_eq(p.object.key.value.digest, lcs.sha256(lcs.dword(9)),
            "describing the write that landed")
    end)

-- Transactions -----------------------------------------------------------------

test("a transacted write is recorded when staged, and its transaction's end once",
    { spec = {
        "PKM *lcs-audit.write.transacted-recorded-when-staged",
        "PKM *lcs-audit.txn-committed.once-per-recorded-transaction",
        "PKM *lcs-audit.txn-committed.payload-fields",
        "PKM *lcs-audit.txn-committed.subject",
    } }, function(t)
        local events = kmes.recording(t, vm, function()
            local txn = assert(lcs.begin_transaction(w))
            local fd = must_open(t, "Machine\\Alarm\\Txn", R.SET_VALUE)
            local r = lcs.set_value(src, w, fd, "Staged", lcs.TYPE.DWORD, lcs.dword(1),
                { txn_fd = txn })
            t:assert_eq(r.ret, 0, "the write is staged: " .. sys.errname(r.errno or 0))
            local c = lcs.commit(src, w, txn)
            t:assert_eq(c.ret, 0, "and committed: " .. sys.errname(c.errno or 0))
            sys.close(w, txn)
            sys.close(w, fd)
        end)
        local staged = one(events, "lcs.audit.value.set")
        t:assert(staged, "the staged write is recorded")
        local id = staged.payload.transaction and staged.payload.transaction.id
        t:assert_eq(type(id), "number", "with transaction.id")
        t:assert_eq(staged.payload.outcome.success, true, "as accepted into the transaction")
        t:assert(staged.payload.object.key.value["type-previous"] == nil,
            "and no previous value: a transacted write does not read one")

        local ended, n = one(events, "lcs.audit.transaction.committed")
        t:assert(ended, "the transaction's end is recorded")
        t:assert_eq(n, 1, "exactly once")
        local p = ended.payload
        t:assert_eq(count_keys(p), 3, "subject, transaction and outcome")
        t:assert_eq(p.transaction.id, id, "joined to the write on transaction.id")
        t:assert_eq(p.transaction.state, "committed", "it committed")
        t:assert_eq(count_keys(p.transaction), 2, "id and state alone on success")
        t:assert_eq(p.outcome.success, true, "successfully")
        t:assert_eq(token.sid_string(p.subject.token.sid), "S-1-5-18",
            "and the subject is the committer")

        local closed = kmes.recording(t, vm, function()
            local txn = assert(lcs.begin_transaction(w))
            local fd = must_open(t, "Machine\\Alarm\\Txn", R.SET_VALUE)
            t:assert_eq(lcs.set_value(src, w, fd, "Dropped", lcs.TYPE.DWORD, lcs.dword(2),
                { txn_fd = txn }).ret, 0, "a second transaction stages a write")
            sys.close(w, fd)
            sys.close(w, txn)
            src:pump()
        end)
        local aborted, m = one(closed, "lcs.audit.transaction.committed")
        t:assert(aborted, "closing it without a commit is recorded")
        t:assert_eq(m, 1, "once")
        t:assert_eq(aborted.payload.transaction.state, "aborted", "as aborted")
        t:assert_eq(aborted.payload.outcome.success, false, "a failure")
        t:assert_eq(aborted.payload.outcome.reason, "aborted", "for that reason")
        t:assert(aborted.payload.outcome.errno == nil, "with no errno: no commit call failed")
        t:assert_eq(aborted.payload.transaction["commit-outstanding"], false,
            "and no commit outstanding")

        local unrecorded = kmes.recording(t, vm, function()
            local txn = assert(lcs.begin_transaction(w))
            local fd = must_open(t, "Machine\\Alarm\\Plain", R.SET_VALUE)
            t:assert_eq(lcs.set_value(src, w, fd, "Quiet", lcs.TYPE.DWORD, lcs.dword(3),
                { txn_fd = txn }).ret, 0, "a transaction stages an unrecorded write")
            t:assert_eq(lcs.commit(src, w, txn).ret, 0, "and commits")
            sys.close(w, fd)
            sys.close(w, txn)
        end)
        t:assert_eq(#kmes.of_type(unrecorded, "lcs.audit.transaction.committed"), 0,
            "a transaction with no recorded write owes no record")
    end)

-- Key creation ----------------------------------------------------------------------

test("a key made under a parent whose SACL audits KEY_CREATE_SUB_KEY is recorded",
    { spec = {
        "PKM *lcs-audit.key-created.on-parent-sacl-match",
        "PKM *lcs-audit.key-created.only-made-keys",
        "PKM *lcs-audit.key-created.payload-fields",
    } }, function(t)
        local events = kmes.recording(t, vm, function()
            local made = lcs.create_key(src, w, { path = "Machine\\Audited\\Child" })
            t:assert(made.ret >= 0, "the key is created: " .. sys.errname(made.errno or 0))
            t:assert_eq(made.disposition, lcs.CREATED_NEW, "as new")
            sys.close(w, made.ret)
        end)
        local e, n = one(events, "lcs.audit.key.created")
        t:assert(e, "the creation is recorded")
        t:assert_eq(n, 1, "once")
        local p = e.payload
        t:assert_eq(count_keys(p), 4, "subject, object, access and outcome")
        t:assert_eq(p.object.key.path, "Machine\\Audited\\Child", "naming the new key's path")
        t:assert_eq(p.object.key.guid, src:lookup("Machine\\Audited\\Child"),
            "and its GUID")
        t:assert_eq(p.object.key.created, true, "object.key.created")
        t:assert_eq(p.object.key.volatile, false, "object.key.volatile")
        t:assert_eq(p.object.key.symlink, false, "object.key.symlink")
        t:assert_eq(type(p.object.sd.length), "number", "the new descriptor's length")
        t:assert_eq(type(p.object.sd.owner), "string", "and owner")
        t:assert_eq(p.access.requested, R.CREATE_SUB_KEY,
            "access.requested is the parent check's KEY_CREATE_SUB_KEY")
        t:assert_eq(p.outcome.success, true, "and it succeeded")

        local again = kmes.recording(t, vm, function()
            local opened = lcs.create_key(src, w, { path = "Machine\\Audited\\Child" })
            t:assert(opened.ret >= 0, "a second create opens it")
            t:assert_eq(opened.disposition, lcs.OPENED_EXISTING, "as existing")
            sys.close(w, opened.ret)
            local plain = lcs.create_key(src, w, { path = "Machine\\Alarm\\Plain\\Child" })
            t:assert(plain.ret >= 0, "a key under an unaudited parent is made")
            sys.close(w, plain.ret)
        end)
        t:assert_eq(#kmes.of_type(again, "lcs.audit.key.created"), 0,
            "neither opening an existing key nor creating under an unaudited parent records")
    end)

-- Descriptor changes ---------------------------------------------------------------------

test("a SACL change is recorded whatever the handle's mask says",
    { spec = {
        "PKM *lcs-audit.descriptor-changed.sacl-change-always-recorded",
        "PKM *lcs-audit.descriptor-changed.payload-fields",
        "PKM *lcs-audit.write.data-recorded-as-sha256-digest",
    } }, function(t)
        local events = kmes.recording(t, vm, function()
            local fd = must_open(t, "Machine\\Alarm\\Sacl",
                R.ACCESS_SYSTEM_SECURITY | R.READ_CONTROL)
            local s = lcs.set_security(src, w, fd, lcs.SI.SACL, lcs.sd({ EVERYONE_ALL },
                { sacl = access.acl({
                    access.ace(access.ACE.AUDIT, R.QUERY_VALUE, kacs.SID.EVERYONE, SUCCESS),
                }) }))
            t:assert_eq(s.ret, 0, "a SACL is set on a key with none: " ..
                sys.errname(s.errno or 0))
            sys.close(w, fd)
        end)
        local e, n = one(events, "lcs.audit.key.descriptor.changed")
        t:assert(e, "the change is recorded, though the key had no alarm ACE")
        t:assert_eq(n, 1, "once")
        local p = e.payload
        t:assert_eq(p.object.kind, "key", "object.kind is key")
        t:assert_eq(p.object.key.path, "Machine\\Alarm\\Sacl", "naming the key")
        local sd = p.object.sd
        t:assert_eq(sd.components, lcs.SI.SACL, "object.sd.components says the SACL changed")
        t:assert_eq(count_keys(sd), 7,
            "with both descriptors' lengths, digests and owners")
        t:assert_eq(sd["length-previous"], #SACL_SD, "the old descriptor's length")
        t:assert_eq(sd["digest-previous"], lcs.sha256(SACL_SD), "its SHA-256 digest")
        t:assert_eq(#sd.digest, 32, "the new one's digest is SHA-256 too")
        t:assert(sd.digest ~= sd["digest-previous"], "and differs")
        t:assert_eq(token.sid_string(sd.owner), "S-1-5-18", "the owner")
        t:assert_eq(token.sid_string(sd["owner-previous"]), "S-1-5-18", "and the owner before")
        t:assert_eq(p.access.requested, R.ACCESS_SYSTEM_SECURITY,
            "access.requested is ACCESS_SYSTEM_SECURITY")
        t:assert_eq(p.access.matched, 0, "and nothing matched: the SACL alone decided")
        t:assert_eq(p.outcome.success, true, "successfully")
    end)

test("owner, group and DACL changes follow the handle's mask",
    { spec = "PKM *lcs-audit.descriptor-changed.other-changes-follow-mask" }, function(t)
        local events = kmes.recording(t, vm, function()
            local fd = must_open(t, "Machine\\Alarm\\Dacl", R.WRITE_DAC)
            t:assert_eq(lcs.set_security(src, w, fd, lcs.SI.DACL,
                lcs.sd({ EVERYONE_ALL })).ret, 0, "a DACL change under a WRITE_DAC alarm")
            sys.close(w, fd)
        end)
        local e, n = one(events, "lcs.audit.key.descriptor.changed")
        t:assert(e, "is recorded")
        t:assert_eq(n, 1, "once")
        t:assert_eq(e.payload.object.sd.components, lcs.SI.DACL, "as a DACL change")
        t:assert_eq(e.payload.access.matched, R.WRITE_DAC, "matched on WRITE_DAC")

        local quiet = kmes.recording(t, vm, function()
            local fd = must_open(t, "Machine\\Alarm\\Plain", R.WRITE_DAC)
            t:assert_eq(lcs.set_security(src, w, fd, lcs.SI.DACL,
                lcs.sd({ EVERYONE_ALL })).ret, 0, "a DACL change with no alarm ACE")
            sys.close(w, fd)
        end)
        t:assert_eq(#kmes.of_type(quiet, "lcs.audit.key.descriptor.changed"), 0,
            "is not")
    end)

-- What the guest cannot reach ------------------------------------------------------------

test("a registry open a privilege contributed to is recorded as kacs.audit.privilege.used",
    { spec = "PKM *lcs-audit.open.privilege-use-recorded",
      covered_by = "kunit:pkm_lcs_kunit_audit",
      skip = "the record needs a token whose audit policy asks for privilege use, which " ..
             "nothing a test can mint sets; runs under " ..
             "pkm_lcs_kunit_audit_open_records_privilege_use" },
    function(t) end)

test("a write record that cannot be emitted leaves the operation's result",
    { spec = "PKM *lcs-audit.emit-failure.write-records-preserve-result",
      covered_by = "cargo:lcs-core registry::lcs_audit_event_vocabulary::" ..
                   "lcs_write_audit_failure_policy_preserves_the_result",
      skip = "a guest cannot make KMES or the payload builder fail on demand; the " ..
             "policy runs under cargo test -p lcs-core --test registry " ..
             "lcs_write_audit_failure_policy_preserves_the_result" },
    function(t) end)

test("the eight write records are LCS events",
    { spec = "PKM *lcs-audit.events-through-kmes" }, function(t)
        t:assert_eq(#WRITE_EVENT_TYPES, 8, "eight write, creation, descriptor and " ..
            "transaction records, beside security-audit's seven")
        for _, kind in ipairs(WRITE_EVENT_TYPES) do
            t:assert(kind:sub(1, 10) == "lcs.audit.", kind .. " is under lcs.audit")
        end
    end)
