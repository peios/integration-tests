-- PKM §3.8.9 — auditing inside AccessCheck: the three mechanisms that
-- observe a decision without changing it — the SACL walk's access
-- auditing, the alarm ACEs that arm per-operation continuous auditing,
-- and privilege-use accounting — plus the per-token policy that forces
-- events and what an event carries.
--
-- Events are witnessed on the KMES ring: the public AccessCheck
-- syscalls install no event sink, so their audit records go straight to
-- KMES. Continuous auditing is per-operation and is witnessed on a real
-- FACS file.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local access = require("helpers.access")
local kmes = require("helpers.kmes")
local facs = require("helpers.facs")

local vm = provium:vm("v", "kernel-only"):boot()

local STD = access.STD
local E, USER = token.SID.EVERYONE, token.SID.TEST_USER
local G2 = token.SID.TEST_GROUP_2
local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED
local ALLOW = access.ACE.ALLOWED
local SUCCESS_FLAG, FAILURE_FLAG = access.ACE_FLAG.SUCCESSFUL_ACCESS, access.ACE_FLAG.FAILED_ACCESS
--- Conditional audit and alarm ACE types (§3.A); helpers/access names
--- the unconditional ones only.
local AUDIT_CALLBACK, ALARM_CALLBACK = 0x0D, 0x0E
local CONF = token.sid(15, 2, 1, 2, 3, 4, 5, 6, 7)
--- F_GETPIPE_SZ, one of the fcntl commands KACS classifies as needing
--- FILE_READ_ATTRIBUTES.
local F_GETPIPE_SZ = 1032
local BACKUP = token.bit(token.PRIV.BACKUP)
local TAKE_OWNERSHIP = token.bit(token.PRIV.TAKE_OWNERSHIP)
local POLICY = token.AUDIT

--- A synthetic object type whose read, write and execute rights are three
--- disjoint bits.
local OBJ = { read = 0x1, write = 0x2, execute = 0x4,
    all = 0x7 | STD.DELETE | STD.READ_CONTROL | STD.WRITE_DAC | STD.WRITE_OWNER | STD.SYNCHRONIZE }
local READ, WRITE, EXEC = 0x1, 0x2, 0x4

local function grant(mask, sid) return access.ace(ALLOW, mask, sid) end
local function audit_ace(mask, sid, flags) return access.ace(access.ACE.AUDIT, mask, sid, flags) end
local function alarm_ace(mask, sid, flags) return access.ace(access.ACE.ALARM, mask, sid, flags) end

--- `Exists(<literal>)` — UNKNOWN, since a literal has no attribute to
--- answer for. Padded so the containing ACE stays a multiple of four.
local UNKNOWN_EXPR = (function()
    local e = "artx" .. string.pack("<I1i8I1I1", 0x04, 1, 0x01, 0x02) .. string.pack("<I1", 0x87)
    return e .. string.rep("\0", (-#e) % 4)
end)()

--- Mint a subject from `spec` (copied, because `token.mint` stamps its
--- session into it) and run `fn(fd)`.
local function with_subject(spec, fn)
    local fresh = { groups = { { sid = E, attributes = ENABLED } } }
    for k, v in pairs(spec or {}) do fresh[k] = v end
    local fd, e = token.mint(vm, fresh)
    assert(fd, "mint: " .. sys.errname(e or 0))
    local ok, err = pcall(fn, fd)
    sys.close(vm, fd)
    if not ok then error(err, 0) end
end

local function as_subject(spec, sd, desired, opts)
    opts = opts or {}
    local out
    with_subject(spec, function(fd)
        out = access.check(vm, { token_fd = fd, sd = sd, desired = desired,
            mapping = opts.mapping or OBJ, intent = opts.intent, tree = opts.tree,
            audit_context = opts.audit_context })
    end)
    return out
end

--- Attach to CPU 0's ring, drain it, run `fn`, and return everything
--- emitted while it ran.
local function recording(fn)
    local ring = assert(kmes.attach(vm, 0))
    kmes.drain(ring)
    local ok, err = pcall(fn)
    local events = kmes.drain(ring)
    kmes.detach(ring)
    if not ok then error(err, 0) end
    return events
end
local function of(events, ty) return kmes.of_type(events, ty) end

-- Observational ------------------------------------------------------------------------

test("no audit rule changes the decision",
    { spec = "PKM *check.auditing.observational" }, function(t)
        local dacl = { grant(READ, E) }
        local bare = access.simple(dacl)
        -- A failure-audit ACE covering everything, an alarm ACE, and a
        -- success-audit ACE: none of them may move a bit.
        local audited = access.simple(dacl, { sacl = access.acl({
            audit_ace(STD.GENERIC_ALL, E, SUCCESS_FLAG | FAILURE_FLAG),
            alarm_ace(STD.GENERIC_ALL, E, SUCCESS_FLAG | FAILURE_FLAG),
            audit_ace(WRITE, G2, FAILURE_FLAG) }) })
        for _, desired in ipairs({ READ, WRITE, STD.MAXIMUM_ALLOWED }) do
            local a = as_subject({}, bare, desired)
            local b = as_subject({}, audited, desired)
            t:log(string.format("desired=0x%x: bare ret=%d/0x%x, audited ret=%d/0x%x",
                desired, a.ret, a.granted, b.ret, b.granted))
            t:assert_eq(b.ret, a.ret, string.format(
                "the verdict for 0x%x is the same with a SACL as without one", desired))
            t:assert_eq(b.granted, a.granted, "and so is the granted mask")
        end
    end)

test("the pipeline emits access-audit for object access and privilege-use for privilege use",
    { spec = "PKM *check.auditing.event-families" }, function(t)
        local events = recording(function()
            with_subject({ privs_present = BACKUP, privs_enabled = BACKUP,
                audit_policy = POLICY.OBJECT_ACCESS_SUCCESS | POLICY.PRIVILEGE_USE_SUCCESS },
                function(fd)
                    local sd = access.simple({}, { sacl = access.acl({
                        audit_ace(READ, E, SUCCESS_FLAG) }) })
                    local r = access.check(vm, { token_fd = fd, sd = sd, desired = READ,
                        mapping = OBJ, intent = access.INTENT.BACKUP })
                    t:assert(r.ok, "SeBackupPrivilege grants read: " .. sys.errname(r.errno or 0))
                end)
        end)
        t:log(string.format("access-audit=%d privilege-use=%d", #of(events, "access-audit"),
            #of(events, "privilege-use")))
        t:assert(#of(events, "access-audit") >= 1,
            "the SACL walk and the token policy produce access-audit records")
        t:assert_eq(#of(events, "privilege-use"), 1,
            "and the privilege-use step produces its own family")
    end)

test("the CAAP conditions of §3.8.8 emit a third family, caap-policy-diagnostic",
    { spec = "PKM *check.auditing.caap-diagnostic-family" }, function(t)
        local sid = token.sid(5, 21, 1000, 2000, 3000, 9301)
        local r0 = access.set_caap(vm, sid, access.caap_spec({
            { effective_dacl = access.acl({ grant(READ | WRITE, E) }),
              staged_dacl = access.acl({ grant(READ, E) }) } }))
        t:assert_eq(r0.ret, 0, "kacs_set_caap: " .. sys.errname(r0.errno or 0))
        local sd = access.simple({ grant(READ | WRITE, E) }, { sacl = access.acl({
            access.ace(access.ACE.SCOPED_POLICY_ID, 0, sid) }) })
        local r
        local events = recording(function() r = as_subject({}, sd, READ | WRITE) end)
        access.set_caap(vm, sid, nil)
        local diags = of(events, "caap-policy-diagnostic")
        t:log(string.format("ret=%d sm=%d diagnostics=%d", r.ret, r.staging_mismatch, #diags))
        t:assert_eq(r.staging_mismatch, 1, "the staged result differs")
        t:assert_eq(#diags, 1, "and one caap-policy-diagnostic event is emitted for it")
        t:assert_eq(diags[1].payload.kind, "staging-mismatch", "naming the condition")
    end)

test("audit delivery happens before any writeback, so a bad output pointer cannot suppress it",
    { spec = "PKM *check.auditing.delivery-before-result" }, function(t)
        -- The args block is built by hand so granted_out can name an
        -- address the kernel cannot write.
        local sd = access.simple({ grant(READ, E) })
        local BAD = 0xdeadbeef000
        local r, events
        with_subject({ audit_policy = POLICY.OBJECT_ACCESS_SUCCESS }, function(fd)
            local args = string.pack("<I4i4I8I4I4I4I4I4I4I8I4I4I8I4I4I8I4I4I8I4I4I8I4I4I8I8",
                access.ARGS_SIZE, fd, 0, #sd, READ,
                OBJ.read, OBJ.write, OBJ.execute, OBJ.all,
                0, 0, 0, 0, 0, 0, 0, 0, 0,
                BAD, 0, 0, 0, 0, 0, 0, 0)
            events = recording(function()
                r = vm:syscall(access.SYS.ACCESS_CHECK, {
                    args = { 0 }, bufs = { args, sd }, ptrs = { 0 },
                    nested = { { parent = 1, child = 2, offset = 8 } },
                })
            end)
        end)
        local ev = of(events, "access-audit")
        t:log(string.format("ret=%d %s, access-audit=%d", r.ret, sys.errname(r.errno or 0), #ev))
        t:assert_eq(r.errno, sys.E.FAULT, "the writeback fails: " .. sys.errname(r.errno or 0))
        t:assert_eq(#ev, 1, "and the event was already delivered before it was attempted")
    end)

-- Access auditing ----------------------------------------------------------------------

test("an audit event needs a SID match, a mask overlap and a matching outcome flag",
    { spec = "PKM *check.auditing.audit-ace-conditions" }, function(t)
        local dacl = { grant(READ, E) }
        local function count(sacl_ace, desired)
            local n
            local events = recording(function()
                as_subject({}, access.simple(dacl, { sacl = access.acl({ sacl_ace }) }),
                    desired)
            end)
            n = #of(events, "access-audit")
            return n
        end
        local all_three = count(audit_ace(READ, E, SUCCESS_FLAG), READ)
        local wrong_sid = count(audit_ace(READ, G2, SUCCESS_FLAG), READ)
        local no_overlap = count(audit_ace(EXEC, E, SUCCESS_FLAG), READ)
        local wrong_flag = count(audit_ace(READ, E, FAILURE_FLAG), READ)
        t:log(string.format("all three=%d, wrong SID=%d, no overlap=%d, wrong flag=%d",
            all_three, wrong_sid, no_overlap, wrong_flag))
        t:assert_eq(all_three, 1, "SID, mask and flag all matching emits one event")
        t:assert_eq(wrong_sid, 0, "an ACE on a SID the caller does not hold emits nothing")
        t:assert_eq(no_overlap, 0, "nor does one whose mask does not overlap the request")
        t:assert_eq(wrong_flag, 0, "nor a failure ACE on a request that succeeded")
    end)

test("the audit SID match uses deny polarity, so a deny-only group is still audited",
    { spec = "PKM *check.auditing.deny-polarity-matching" }, function(t)
        local deny_only = { groups = { { sid = E, attributes = ENABLED },
            { sid = G2, attributes = token.GROUP.USE_FOR_DENY_ONLY } } }
        local sd = access.simple({ grant(READ, E) },
            { sacl = access.acl({ audit_ace(READ, G2, SUCCESS_FLAG) }) })
        local held, absent
        local events = recording(function() held = as_subject(deny_only, sd, READ) end)
        local other = recording(function()
            absent = as_subject({}, sd, READ)   -- no G2 on the token at all
        end)
        t:log(string.format("deny-only group events=%d, group absent events=%d",
            #of(events, "access-audit"), #of(other, "access-audit")))
        t:assert(held.ok and absent.ok, "both requests succeed")
        t:assert_eq(#of(events, "access-audit"), 1,
            "a deny-only group matches the audit ACE — the broadest identity view")
        t:assert_eq(#of(other, "access-audit"), 0,
            "while a group the token does not carry at all does not")
    end)

test("the mask overlap is tested against the requested mask, not the granted one",
    { spec = "PKM *check.auditing.overlap-against-requested" }, function(t)
        -- The DACL grants read alone, so a request for read and write
        -- fails and the write bit is never granted. An audit ACE naming
        -- write must still fire on the failure.
        local sd = access.simple({ grant(READ, E) },
            { sacl = access.acl({ audit_ace(WRITE, E, FAILURE_FLAG) }) })
        local r
        local events = recording(function() r = as_subject({}, sd, READ | WRITE) end)
        local ev = of(events, "access-audit")
        t:log(string.format("ret=%d granted=0x%x events=%d", r.ret, r.granted, #ev))
        t:assert(r.denied, "the request fails: ret=" .. r.ret .. " " .. sys.errname(r.errno or 0))
        t:assert_eq(r.granted, READ, "with only the read bit granted")
        t:assert_eq(#ev, 1, "and the write-only audit ACE still fires for the right asked for")
        t:assert_eq(ev[1].payload.requested_access, READ | WRITE, "the record carries the request")
        t:assert_eq(ev[1].payload.granted_access, READ, "beside what was actually granted")
    end)

test("a conditional audit ACE whose expression is UNKNOWN emits the event",
    { spec = "PKM *check.auditing.unknown-condition-emits" }, function(t)
        local sd = access.simple({ grant(READ, E) }, { sacl = access.acl({
            access.ace(AUDIT_CALLBACK, READ, E, SUCCESS_FLAG, { condition = UNKNOWN_EXPR }) }) })
        local r
        local events = recording(function() r = as_subject({}, sd, READ) end)
        local ev = of(events, "access-audit")
        t:log(string.format("ret=%d events=%d", r.ret, #ev))
        t:assert(r.ok, "the request succeeds: " .. sys.errname(r.errno or 0))
        t:assert_eq(#ev, 1, "when in doubt, audit")
    end)

-- Continuous auditing ------------------------------------------------------------------

test("an alarm ACE accumulates its mask into the continuous audit mask returned to the caller",
    { spec = "PKM *check.auditing.alarm-accumulates-mask" }, function(t)
        local none = as_subject({}, access.simple({ grant(STD.GENERIC_ALL, E) }), READ)
        local one = as_subject({}, access.simple({ grant(STD.GENERIC_ALL, E) },
            { sacl = access.acl({ alarm_ace(READ | WRITE, E, SUCCESS_FLAG) }) }), READ)
        local two = as_subject({}, access.simple({ grant(STD.GENERIC_ALL, E) },
            { sacl = access.acl({ alarm_ace(READ, E, 0), alarm_ace(EXEC, E, 0) }) }), READ)
        local other = as_subject({}, access.simple({ grant(STD.GENERIC_ALL, E) },
            { sacl = access.acl({ alarm_ace(READ, G2, 0) }) }), READ)
        t:log(string.format("no alarm=0x%x, one=0x%x, two=0x%x, other SID=0x%x",
            none.continuous_audit, one.continuous_audit, two.continuous_audit,
            other.continuous_audit))
        t:assert_eq(none.continuous_audit, 0, "no alarm ACE leaves the mask empty")
        t:assert_eq(one.continuous_audit, READ | WRITE, "one contributes its whole mask")
        t:assert_eq(two.continuous_audit, READ | EXEC, "and two accumulate")
        t:assert_eq(other.continuous_audit, 0, "an alarm ACE needs its SID to match")
    end)

test("the alarm branch performs no overlap test against the requested mask",
    { spec = "PKM *check.auditing.alarm-no-overlap-test" }, function(t)
        -- The alarm ACE names execute; the request is for read alone.
        local sd = access.simple({ grant(STD.GENERIC_ALL, E) },
            { sacl = access.acl({ alarm_ace(EXEC, E, 0), audit_ace(EXEC, E, SUCCESS_FLAG) }) })
        local r
        local events = recording(function() r = as_subject({}, sd, READ) end)
        t:log(string.format("continuous=0x%x access-audit=%d", r.continuous_audit,
            #of(events, "access-audit")))
        t:assert_eq(r.continuous_audit, EXEC,
            "the alarm ACE contributes on a SID match alone, with no overlap with the request")
        t:assert_eq(#of(events, "access-audit"), 0,
            "while the audit ACE carrying the same mask is skipped for want of overlap")
    end)

--- A FACS file whose SACL arms continuous auditing for `alarm_mask`,
--- with a DACL granting everything. Returns the path.
local function armed_file(name, alarm_mask)
    local dir = facs.workspace(vm, "audit")
    local path = dir .. "/" .. name
    facs.file(vm, path, "hello world")
    local sd = access.sd({ owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
        dacl = access.acl({ grant(STD.GENERIC_ALL, E) }),
        sacl = access.acl({ alarm_ace(alarm_mask, E, 0) }) })
    assert(kacs.set_sd(vm, path, sd, kacs.SI.DACL | kacs.SI.SACL).ret == 0, "set_sd")
    return path
end

test("a later operation emits a continuous-audit event when its required mask overlaps the stored one",
    { spec = "PKM *check.auditing.continuous-event-on-overlap" }, function(t)
        local watched = armed_file("watched", kacs.RIGHT.READ_DATA)
        local unwatched = armed_file("unwatched", kacs.RIGHT.WRITE_DATA)
        local a, b
        local events = recording(function()
            local fd = facs.handle(t, vm, watched, kacs.RIGHT.READ_DATA | kacs.RIGHT.SYNCHRONIZE)
            a = sys.read(vm, fd, 5)
            sys.close(vm, fd)
            local fd2 = facs.handle(t, vm, unwatched, kacs.RIGHT.READ_DATA | kacs.RIGHT.SYNCHRONIZE)
            b = sys.read(vm, fd2, 5)
            sys.close(vm, fd2)
        end)
        local ev = of(events, "continuous-audit")
        t:log(string.format("read=%s/%s continuous-audit=%d", tostring(a), tostring(b), #ev))
        t:assert_eq(a, "hello", "the watched file reads")
        t:assert_eq(b, "hello", "and so does the unwatched one")
        t:assert(#ev >= 1, "the read whose required access overlaps the armed mask is recorded")
        for _, e in ipairs(ev) do
            t:assert_eq(e.payload.matched_access & kacs.RIGHT.READ_DATA, kacs.RIGHT.READ_DATA,
                "every event names the overlapping right")
        end
    end)

test("the event records the subset of the required mask that overlapped",
    { spec = "PKM *check.auditing.continuous-records-overlapping-subset" }, function(t)
        -- An append write authorizes on either FILE_WRITE_DATA or
        -- FILE_APPEND_DATA, so the required mask holds the accepted set;
        -- the armed mask names only one of the two.
        local path = armed_file("append", kacs.RIGHT.APPEND_DATA)
        local r, fd, errno
        local events = recording(function()
            fd, errno = sys.open(vm, path, sys.O.WRONLY | sys.O.APPEND)
            assert(fd, "open for append: " .. sys.errname(errno or 0))
            r = vm:syscall(sys.NR.write, { args = { fd, 0, 3 }, bufs = { "abc" }, ptrs = { 1 } })
            sys.close(vm, fd)
        end)
        local ev = of(events, "continuous-audit")
        t:log(string.format("write ret=%d, continuous-audit=%d", r.ret, #ev))
        t:assert_eq(r.ret, 3, "the append succeeds: " .. sys.errname(r.errno or 0))
        t:assert(#ev >= 1, "and is audited")
        local last = ev[#ev]
        t:log(string.format("required=0x%x matched=0x%x", last.payload.requested_access,
            last.payload.matched_access))
        t:assert_eq(last.payload.requested_access & (kacs.RIGHT.WRITE_DATA | kacs.RIGHT.APPEND_DATA),
            kacs.RIGHT.WRITE_DATA | kacs.RIGHT.APPEND_DATA,
            "the required mask holds the whole accepted set")
        t:assert_eq(last.payload.matched_access, kacs.RIGHT.APPEND_DATA,
            "and the event records only the subset the armed mask overlapped")
    end)

test("continuous-audit events are emitted for denied operations as well as successful ones",
    { spec = "PKM *check.auditing.continuous-both-outcomes" }, function(t)
        local path = armed_file("outcomes",
            kacs.RIGHT.READ_DATA | kacs.RIGHT.READ_ATTRIBUTES)
        local ok_read, denied
        local events = recording(function()
            -- Opened for read data alone: an fcntl needing
            -- FILE_READ_ATTRIBUTES fails the use-time check against the
            -- mask the open stamped.
            local fd = facs.handle(t, vm, path, kacs.RIGHT.READ_DATA | kacs.RIGHT.SYNCHRONIZE)
            ok_read = sys.read(vm, fd, 5)
            denied = facs.fcntl(vm, fd, F_GETPIPE_SZ, 0)
            sys.close(vm, fd)
        end)
        local ev = of(events, "continuous-audit")
        local successes, failures = 0, 0
        for _, e in ipairs(ev) do
            if e.payload.success then successes = successes + 1 else failures = failures + 1 end
        end
        t:log(string.format("read=%s fcntl ret=%d %s; events=%d success=%d failure=%d",
            tostring(ok_read), denied.ret, sys.errname(denied.errno or 0),
            #ev, successes, failures))
        t:assert_eq(ok_read, "hello", "the read succeeds")
        t:assert_eq(denied.errno, sys.E.ACCES, "and the fcntl is refused: "
            .. sys.errname(denied.errno or 0))
        t:assert(successes >= 1, "a successful operation is recorded")
        t:assert(failures >= 1, "and so is a denied one")
    end)

test("the subject recorded is the operation-time effective token, not the one that opened the handle",
    { spec = "PKM *check.auditing.continuous-operation-time-subject" }, function(t)
        local path = armed_file("passed", kacs.RIGHT.READ_DATA)
        -- The agent opens the handle as SYSTEM; a worker sharing the same
        -- file table reads it under a minted token.
        local fd = facs.handle(t, vm, path, kacs.RIGHT.READ_DATA | kacs.RIGHT.SYNCHRONIZE)
        local events = recording(function()
            token.as_principal(t, vm, {}, function(w)
                local got = sys.read(w, fd, 5)
                t:assert_eq(got, "hello", "the installed principal reads through the handle")
            end)
        end)
        sys.close(vm, fd)
        local ev = of(events, "continuous-audit")
        t:log(string.format("continuous-audit=%d", #ev))
        t:assert(#ev >= 1, "the read is audited")
        t:assert_eq(ev[#ev].payload.subject.user_sid, USER,
            "and attributed to the token in force when the operation ran")
    end)

test("an enforcement point that cannot construct a required continuous-audit event fails closed",
    { spec = "PKM *check.auditing.continuous-fails-closed",
      covered_by = "kunit:pkm_kunit_file",
      skip = "the emit helper only refuses a malformed record — a zero " ..
             "required or matched mask, or a matched mask outside the " ..
             "required one — and every guest-reachable enforcement point " ..
             "computes both from the same masks, so no syscall can " ..
             "produce one; runs under " ..
             "pkm_kunit_file_continuous_audit_emit_malformed_fails_closed" },
    function(t) end)

-- Privilege-use auditing ----------------------------------------------------------------

test("privilege-use accounting runs after the whole pipeline, CAAP included",
    { spec = "PKM *check.auditing.privilege-use-after-pipeline" }, function(t)
        -- The privilege's bits are in the result until step 12 removes
        -- them, so a step-13 that ran earlier would have called this a
        -- success.
        local sid = token.sid(5, 21, 1000, 2000, 3000, 9302)
        local r0 = access.set_caap(vm, sid, access.caap_spec({
            { effective_dacl = access.acl({}) } }))
        t:assert_eq(r0.ret, 0, "kacs_set_caap: " .. sys.errname(r0.errno or 0))
        local sd = access.sd({ owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
            dacl = access.acl({}),
            sacl = access.acl({ access.ace(access.ACE.SCOPED_POLICY_ID, 0, sid) }) })
        local r
        local events = recording(function()
            r = as_subject({ privs_present = BACKUP, privs_enabled = BACKUP,
                audit_policy = POLICY.PRIVILEGE_USE_FAILURE | POLICY.PRIVILEGE_USE_SUCCESS },
                sd, READ, { intent = access.INTENT.BACKUP })
        end)
        access.set_caap(vm, sid, nil)
        local ev = of(events, "privilege-use")
        t:log(string.format("ret=%d %s, privilege-use=%d", r.ret, sys.errname(r.errno or 0), #ev))
        t:assert(r.denied, "CAAP takes the privilege-granted bits away: ret=" .. r.ret
            .. " " .. sys.errname(r.errno or 0))
        t:assert_eq(#ev, 1, "one privilege-use event")
        t:assert_eq(ev[1].payload.success, false,
            "reporting failure, because it reflects the result after CAAP")
    end)

test("a privilege whose bits survive is marked used and audited under PRIVILEGE_USE_SUCCESS",
    { spec = "PKM *check.auditing.privilege-use-success" }, function(t)
        local r, before, after
        local events = recording(function()
            with_subject({ privs_present = BACKUP, privs_enabled = BACKUP,
                audit_policy = POLICY.PRIVILEGE_USE_SUCCESS }, function(fd)
                before = token.privileges(vm, fd)
                r = access.check(vm, { token_fd = fd, sd = access.simple({}), desired = READ,
                    mapping = OBJ, intent = access.INTENT.BACKUP })
                after = token.privileges(vm, fd)
            end)
        end)
        local ev = of(events, "privilege-use")
        t:log(string.format("ret=%d used 0x%x -> 0x%x, events=%d", r.ret, before.used,
            after.used, #ev))
        t:assert(r.ok, "the privilege grants the right: " .. sys.errname(r.errno or 0))
        t:assert_eq(before.used & BACKUP, 0, "SeBackupPrivilege starts unused")
        t:assert_eq(after.used & BACKUP, BACKUP, "and is marked used")
        t:assert_eq(#ev, 1, "one privilege-use event")
        t:assert_eq(ev[1].payload.success, true, "reporting success")
        t:assert_eq(ev[1].payload.privilege, "SeBackupPrivilege", "and naming the privilege")
    end)

test("a privilege whose bits do not survive is not marked used and is audited under PRIVILEGE_USE_FAILURE",
    { spec = "PKM *check.auditing.privilege-use-failure" }, function(t)
        -- Confinement revokes what the privilege granted (§3.8.6).
        local r, after
        local events = recording(function()
            with_subject({ privs_present = BACKUP, privs_enabled = BACKUP,
                confinement_sid = CONF, audit_policy = POLICY.PRIVILEGE_USE_FAILURE },
                function(fd)
                    r = access.check(vm, { token_fd = fd, sd = access.simple({}), desired = READ,
                        mapping = OBJ, intent = access.INTENT.BACKUP })
                    after = token.privileges(vm, fd)
                end)
        end)
        local ev = of(events, "privilege-use")
        t:log(string.format("ret=%d %s, used=0x%x, events=%d", r.ret, sys.errname(r.errno or 0),
            after.used, #ev))
        t:assert(r.denied, "the confinement pass removes the bits: ret=" .. r.ret
            .. " " .. sys.errname(r.errno or 0))
        t:assert_eq(after.used & BACKUP, 0, "the privilege is not marked used")
        t:assert_eq(#ev, 1, "one privilege-use event")
        t:assert_eq(ev[1].payload.success, false, "reporting failure")
    end)

test("a privilege that contributed nothing to the requested access produces no event either way",
    { spec = "PKM *check.auditing.privilege-use-no-contribution" }, function(t)
        -- SeBackupPrivilege seeds the read bits; the request names write
        -- alone, which the DACL grants.
        local r
        local events = recording(function()
            r = as_subject({ privs_present = BACKUP, privs_enabled = BACKUP,
                audit_policy = POLICY.PRIVILEGE_USE_SUCCESS | POLICY.PRIVILEGE_USE_FAILURE },
                access.simple({ grant(WRITE, E) }), WRITE, { intent = access.INTENT.BACKUP })
        end)
        local ev = of(events, "privilege-use")
        t:log(string.format("ret=%d events=%d", r.ret, #ev))
        t:assert(r.ok, "the DACL grants the write bit: " .. sys.errname(r.errno or 0))
        t:assert_eq(#ev, 0, "and the privilege contributed no requested bit, so nothing is recorded")
    end)

test("with an object type list a privilege counts as used if its bits survive on any node",
    { spec = "PKM *check.auditing.privilege-use-per-node" }, function(t)
        local function guid(n) return string.rep(string.char(n), 16) end
        local ROOT, A, B = guid(1), guid(2), guid(3)
        local tree = { { level = 0, guid = ROOT }, { level = 1, guid = A }, { level = 1, guid = B } }
        -- A confined token: the confinement pass reaches an object ACE on
        -- child A alone, so the privilege-granted read bit survives there
        -- and nowhere else.
        local function run(dacl)
            local out, events
            events = recording(function()
                with_subject({ privs_present = BACKUP, privs_enabled = BACKUP,
                    confinement_sid = CONF,
                    audit_policy = POLICY.PRIVILEGE_USE_SUCCESS | POLICY.PRIVILEGE_USE_FAILURE },
                    function(fd)
                        out = access.check_list(vm, { token_fd = fd, sd = access.simple(dacl),
                            desired = READ, mapping = OBJ, tree = tree,
                            intent = access.INTENT.BACKUP })
                    end)
            end)
            return out, of(events, "privilege-use")
        end
        local on_a, ev_a = run({ access.ace(access.ACE.ALLOWED_OBJECT, READ, CONF, 0,
            { object_type = A }) })
        local nowhere, ev_n = run({ grant(READ, E) })
        t:log(string.format("scoped to A: nodes 0x%x/0x%x/0x%x events=%d success=%s",
            on_a.nodes[1].granted, on_a.nodes[2].granted, on_a.nodes[3].granted, #ev_a,
            tostring(ev_a[1] and ev_a[1].payload.success)))
        t:log(string.format("nowhere: nodes 0x%x/0x%x/0x%x events=%d success=%s",
            nowhere.nodes[1].granted, nowhere.nodes[2].granted, nowhere.nodes[3].granted, #ev_n,
            tostring(ev_n[1] and ev_n[1].payload.success)))
        t:assert_eq(on_a.nodes[2].granted, READ, "the bit survives on the one scoped node")
        t:assert_eq(on_a.nodes[1].granted, 0, "and on neither the root")
        t:assert_eq(on_a.nodes[3].granted, 0, "nor the sibling")
        t:assert_eq(#ev_a, 1, "one privilege-use event")
        t:assert_eq(ev_a[1].payload.success, true, "recording success on the strength of one node")
        t:assert_eq(#ev_n, 1, "and where it survives on no node, one event too")
        t:assert_eq(ev_n[1].payload.success, false, "recording failure")
    end)

test("a MAXIMUM_ALLOWED request marks nothing used and emits no privilege-use event",
    { spec = "PKM *check.auditing.max-allowed-skips-privilege-use" }, function(t)
        local r, after
        local events = recording(function()
            with_subject({ privs_present = BACKUP, privs_enabled = BACKUP,
                audit_policy = POLICY.PRIVILEGE_USE_SUCCESS | POLICY.PRIVILEGE_USE_FAILURE },
                function(fd)
                    r = access.check(vm, { token_fd = fd, sd = access.simple({}),
                        desired = STD.MAXIMUM_ALLOWED, mapping = OBJ,
                        intent = access.INTENT.BACKUP })
                    after = token.privileges(vm, fd)
                end)
        end)
        t:log(string.format("granted=0x%x used=0x%x events=%d", r.granted, after.used,
            #of(events, "privilege-use")))
        t:assert_eq(r.granted, OBJ.read, "the privilege still contributed to the result")
        t:assert_eq(after.used & BACKUP, 0, "yet nothing is marked used")
        t:assert_eq(#of(events, "privilege-use"), 0, "and the whole step emits nothing")
    end)

test("backup and restore report use even where the DACL alone would have permitted the access",
    { spec = "PKM *check.auditing.backup-restore-overreport" }, function(t)
        -- The DACL already grants read to Everyone, so the privilege was
        -- not load-bearing; backup seeds its bits unconditionally and is
        -- reported used anyway. SeTakeOwnershipPrivilege, which only
        -- contributes where the DACL had not already granted the right,
        -- is the contrast.
        local backup_ev, take_ev, r1, r2, used1, used2
        local a = recording(function()
            with_subject({ privs_present = BACKUP, privs_enabled = BACKUP,
                audit_policy = POLICY.PRIVILEGE_USE_SUCCESS }, function(fd)
                r1 = access.check(vm, { token_fd = fd, sd = access.simple({ grant(READ, E) }),
                    desired = READ, mapping = OBJ, intent = access.INTENT.BACKUP })
                used1 = token.privileges(vm, fd).used
            end)
        end)
        local b = recording(function()
            with_subject({ privs_present = TAKE_OWNERSHIP, privs_enabled = TAKE_OWNERSHIP,
                audit_policy = POLICY.PRIVILEGE_USE_SUCCESS }, function(fd)
                r2 = access.check(vm, { token_fd = fd,
                    sd = access.simple({ grant(STD.WRITE_OWNER, E) }),
                    desired = STD.WRITE_OWNER, mapping = OBJ })
                used2 = token.privileges(vm, fd).used
            end)
        end)
        backup_ev, take_ev = of(a, "privilege-use"), of(b, "privilege-use")
        t:log(string.format("backup: ret=%d used=0x%x events=%d; take-ownership: ret=%d used=0x%x events=%d",
            r1.ret, used1, #backup_ev, r2.ret, used2, #take_ev))
        t:assert(r1.ok and r2.ok, "both requests succeed on the DACL's own terms")
        t:assert_eq(#backup_ev, 1,
            "SeBackupPrivilege reports use for an access the DACL alone would have permitted")
        t:assert_eq(used1 & BACKUP, BACKUP, "and is marked used")
        t:assert_eq(#take_ev, 0,
            "while SeTakeOwnershipPrivilege, which contributes only where the DACL did not, reports nothing")
        t:assert_eq(used2 & TAKE_OWNERSHIP, 0, "and is not marked used")
    end)

-- Per-token audit policy ------------------------------------------------------------------

test("the token's audit policy forces success and failure events regardless of SACL content",
    { spec = "PKM *check.auditing.forced-events" }, function(t)
        local granting, denying = access.simple({ grant(READ, E) }), access.simple({})
        local function run(policy, sd, desired)
            local n, r
            local events = recording(function()
                r = as_subject({ audit_policy = policy }, sd, desired)
            end)
            n = #of(events, "access-audit")
            return r, n
        end
        local _, none_ok = run(0, granting, READ)
        local _, none_fail = run(0, denying, READ)
        local ok_r, success = run(POLICY.OBJECT_ACCESS_SUCCESS, granting, READ)
        local _, success_on_fail = run(POLICY.OBJECT_ACCESS_SUCCESS, denying, READ)
        local fail_r, failure = run(POLICY.OBJECT_ACCESS_FAILURE, denying, READ)
        local _, failure_on_ok = run(POLICY.OBJECT_ACCESS_FAILURE, granting, READ)
        t:log(string.format("policy 0: %d/%d; SUCCESS: %d on grant, %d on denial; FAILURE: %d on denial, %d on grant",
            none_ok, none_fail, success, success_on_fail, failure, failure_on_ok))
        t:assert(ok_r.ok and fail_r.denied, "one request succeeds and one is denied")
        t:assert_eq(none_ok + none_fail, 0, "a zero policy forces nothing")
        t:assert_eq(success, 1, "OBJECT_ACCESS_SUCCESS forces an event on a successful check")
        t:assert_eq(success_on_fail, 0, "and not on a failed one")
        t:assert_eq(failure, 1, "OBJECT_ACCESS_FAILURE forces an event on a failed check")
        t:assert_eq(failure_on_ok, 0, "and not on a successful one")
    end)

test("forced success means every requested bit granted, or nothing requested at all",
    { spec = "PKM *check.auditing.forced-success-definition" }, function(t)
        local sd = access.simple({ grant(READ, E) })
        local spec = { audit_policy = POLICY.OBJECT_ACCESS_SUCCESS | POLICY.OBJECT_ACCESS_FAILURE }
        local function run(desired)
            local r
            local events = recording(function() r = as_subject(spec, sd, desired) end)
            local ev = of(events, "access-audit")
            return r, ev
        end
        local all_granted, e1 = run(READ)
        local partly, e2 = run(READ | WRITE)
        local nothing, e3 = run(0)
        t:log(string.format("READ ret=%d success=%s; READ|WRITE ret=%d success=%s; 0 ret=%d success=%s",
            all_granted.ret, tostring(e1[1] and e1[1].payload.success),
            partly.ret, tostring(e2[1] and e2[1].payload.success),
            nothing.ret, tostring(e3[1] and e3[1].payload.success)))
        t:assert_eq(#e1, 1, "one event for the fully granted request")
        t:assert_eq(e1[1].payload.success, true, "classed a success")
        t:assert_eq(#e2, 1, "one for the partly granted request")
        t:assert_eq(e2[1].payload.success, false, "classed a failure — not every bit was granted")
        t:assert_eq(#e3, 1, "one for the request naming nothing")
        t:assert_eq(e3[1].payload.success, true, "classed a success, because nothing was asked for")
    end)

test("forced events are additive and carry the caller-supplied object audit context",
    { spec = "PKM *check.auditing.forced-additive" }, function(t)
        -- No SACL at all, so nothing could have matched.
        local sd = access.simple({ grant(READ, E) })
        local context = "object:/some/path"
        local r
        local events = recording(function()
            r = as_subject({ audit_policy = POLICY.OBJECT_ACCESS_SUCCESS }, sd, READ,
                { audit_context = context })
        end)
        local ev = of(events, "access-audit")
        t:log(string.format("ret=%d events=%d", r.ret, #ev))
        t:assert_eq(#ev, 1, "the event fires with no SACL ACE to have matched it")
        t:assert_eq(ev[1].payload.trigger.kind, "policy", "recorded as policy-forced")
        t:assert_eq(ev[1].payload.object_context, context,
            "and carrying the object audit context the caller supplied")
    end)

test("the audit policy is read from the effective token, so impersonation carries it",
    { spec = "PKM *check.auditing.policy-from-effective-token" }, function(t)
        local sd = access.simple({ grant(READ, E) })
        local audited, plain = 0, 0
        recording(function()
            token.as_principal(t, vm, { audit_policy = POLICY.OBJECT_ACCESS_SUCCESS },
                function(w)
                    local r = access.check(w, { sd = sd, desired = READ, mapping = OBJ })
                    t:assert(r.ok, "the installed principal is granted: "
                        .. sys.errname(r.errno or 0))
                end)
        end)
        local a = recording(function()
            token.as_principal(t, vm, { audit_policy = POLICY.OBJECT_ACCESS_SUCCESS },
                function(w) access.check(w, { sd = sd, desired = READ, mapping = OBJ }) end)
        end)
        local b = recording(function()
            token.as_principal(t, vm, {}, function(w)
                access.check(w, { sd = sd, desired = READ, mapping = OBJ })
            end)
        end)
        audited, plain = #of(a, "access-audit"), #of(b, "access-audit")
        t:log(string.format("policy on the effective token=%d, without it=%d", audited, plain))
        t:assert_eq(audited, 1,
            "a check with no token_fd reads the policy off whatever token is effective")
        t:assert_eq(plain, 0, "and a principal whose policy is zero forces nothing")
    end)

test("an event carries the subject, the object context, the access, the trigger and the process",
    { spec = "PKM *check.auditing.event-contents" }, function(t)
        local ace = audit_ace(READ, E, SUCCESS_FLAG)
        local sd = access.simple({ grant(READ, E) }, { sacl = access.acl({ ace }) })
        local r
        local events = recording(function()
            r = as_subject({ integrity_level = token.INTEGRITY.LOW }, sd, READ,
                { audit_context = "ctx" })
        end)
        local ev = of(events, "access-audit")
        t:assert_eq(#ev, 1, "one event from the SACL")
        local p = ev[1].payload
        t:log(string.format("user=%s groups=%d il=%d pip=(%d,%d) req=0x%x granted=0x%x pid=%d name=%s",
            token.sid_string(p.subject.user_sid), #p.subject.group_sids,
            p.subject.integrity_level, p.subject.pip_type, p.subject.pip_trust,
            p.requested_access, p.granted_access, p.process.pid, p.process.name))
        t:assert_eq(p.subject.user_sid, USER, "the subject's user SID")
        t:assert(#p.subject.group_sids >= 1, "its group SIDs")
        t:assert_eq(p.subject.integrity_level, token.INTEGRITY.LOW, "its integrity level")
        t:assert_eq(p.subject.pip_type, 0, "its PIP type")
        t:assert_eq(p.subject.pip_trust, 0, "and PIP trust")
        t:assert_eq(p.object_context, "ctx", "the object, as the caller-provided context")
        t:assert_eq(p.requested_access, READ, "what was requested")
        t:assert_eq(p.granted_access, READ, "what was granted")
        t:assert_eq(p.success, true, "whether it succeeded")
        t:assert_eq(p.trigger.kind, "sacl", "the trigger's kind")
        t:assert_eq(p.trigger.ace, ace, "and the matched ACE's own bytes")
        t:assert(p.process.pid > 0, "the process's pid")
        t:assert(#p.process.name > 0, "its name")
        t:assert(#p.process.executable_path > 0, "and its executable path")
    end)
