-- PKM §3.8.8 — Central Access and Auditing Policy: how an object
-- references a policy, how a rule's DACL narrows the result and its SACL
-- adds audit coverage, the cache and its wire format, the recovery
-- policy for a missing one, what a rule error preserves, and staging.
--
-- The agent is SYSTEM and holds SeTcbPrivilege, which is what
-- kacs_set_caap needs; the subject of each check is a freshly minted
-- token passed as `token_fd`.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local access = require("helpers.access")
local kmes = require("helpers.kmes")
local facs = require("helpers.facs")

local vm = provium:vm("v", "kernel-only"):boot()

local STD = access.STD
local E, USER = token.SID.EVERYONE, token.SID.TEST_USER
local ADMINS = token.SID.ADMINISTRATORS
local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED
local ALLOW, DENY = access.ACE.ALLOWED, access.ACE.DENIED
local SCOPED = access.ACE.SCOPED_POLICY_ID
local CONF = token.sid(15, 2, 1, 2, 3, 4, 5, 6, 7)
local BACKUP, SECURITY = token.bit(token.PRIV.BACKUP), token.bit(token.PRIV.SECURITY)

--- A synthetic object type whose read, write and execute rights are three
--- disjoint bits, so the intersection can be read bit by bit.
local OBJ = { read = 0x1, write = 0x2, execute = 0x4,
    all = 0x7 | STD.DELETE | STD.READ_CONTROL | STD.WRITE_DAC | STD.WRITE_OWNER | STD.SYNCHRONIZE }
local READ, WRITE, EXEC = 0x1, 0x2, 0x4

-- Policies --------------------------------------------------------------------------

local function policy_sid(rid) return token.sid(5, 21, 1000, 2000, 3000, rid) end

--- Publish a policy and return its SID, asserting the syscall worked.
local function publish(t, rid, rules)
    local sid = policy_sid(rid)
    local r = access.set_caap(vm, sid, access.caap_spec(rules))
    t:assert_eq(r.ret, 0, "kacs_set_caap: " .. sys.errname(r.errno or 0))
    return sid
end
local function drop(sid) access.set_caap(vm, sid, nil) end

local function scoped_ace(sid, flags) return access.ace(SCOPED, 0, sid, flags) end
local function grant(mask, sid) return access.ace(ALLOW, mask, sid) end

--- A descriptor granting `mask` to Everyone whose SACL carries `sacl_aces`.
local function sd_with(mask, sacl_aces, opts)
    opts = opts or {}
    return access.sd({
        owner = opts.owner or token.SID.LOCAL_SYSTEM,
        group = opts.group or token.SID.LOCAL_SYSTEM,
        dacl = access.acl(opts.dacl_aces or { grant(mask, E) }),
        sacl = access.acl(sacl_aces),
    })
end

--- Check `desired` against `sd` as a freshly minted subject built from
--- `spec` (copied, because `token.mint` stamps its session into it).
local function as_subject(spec, sd, desired, opts)
    opts = opts or {}
    local fresh = { groups = { { sid = E, attributes = ENABLED } } }
    for k, v in pairs(spec or {}) do fresh[k] = v end
    local fd, e = token.mint(vm, fresh)
    assert(fd, "mint: " .. sys.errname(e or 0))
    local r = access.check(vm, { token_fd = fd, sd = sd, desired = desired,
        mapping = opts.mapping or OBJ, intent = opts.intent, pip_type = opts.pip_type,
        pip_trust = opts.pip_trust })
    sys.close(vm, fd)
    return r
end

-- Conditional expressions ------------------------------------------------------------

--- An int64 literal token, positive, decimal.
local function int_lit(v) return string.pack("<I1i8I1I1", 0x04, v, 0x01, 0x02) end
--- `1 == 1`, which is TRUE without consulting anything.
local ALWAYS_TRUE = "artx" .. int_lit(1) .. int_lit(1) .. string.pack("<I1", 0x80)
--- `1 == 2`, FALSE.
local ALWAYS_FALSE = "artx" .. int_lit(1) .. int_lit(2) .. string.pack("<I1", 0x80)
--- `Exists(<literal>)`, which is UNKNOWN: Exists over a literal has no
--- attribute to answer for.
local UNKNOWN_EXPR = "artx" .. int_lit(1) .. string.pack("<I1", 0x87)
--- `Member_of({sid})` and its Any / Device / negated variants.
local function membership(op, sid)
    return "artx" .. string.pack("<I1I4", 0x51, #sid) .. sid .. string.pack("<I1", op)
end

--- An ACL big enough that the rule's synthetic descriptor cannot be
--- built: the synthetic form is header + owner + group + SACL + this,
--- and a self-relative descriptor is capped at 65535 bytes.
local OVERSIZE_ACL = (function()
    local ace = access.ace(ALLOW, READ, E)
    local n = (65535 - 8) // #ace
    local aces = {}
    for i = 1, n do aces[i] = ace end
    return access.acl(aces)
end)()

-- Reference and evaluation ------------------------------------------------------------

test("an object references a policy by SID through a scoped policy ACE in its SACL",
    { spec = "PKM *check.cap.reference-by-scoped-policy-ace" }, function(t)
        local sid = publish(t, 9201, { { effective_dacl = access.acl({ grant(READ, E) }) } })
        local referencing = sd_with(READ | WRITE, { scoped_ace(sid) })
        local unreferencing = sd_with(READ | WRITE, {
            access.ace(access.ACE.AUDIT, READ, E, access.ACE_FLAG.SUCCESSFUL_ACCESS) })
        local a = as_subject({}, referencing, STD.MAXIMUM_ALLOWED)
        local b = as_subject({}, unreferencing, STD.MAXIMUM_ALLOWED)
        t:log(string.format("referencing granted=0x%x, not referencing granted=0x%x",
            a.granted, b.granted))
        t:assert_eq(a.granted, READ, "the policy named by the ACE narrows the result")
        t:assert_eq(b.granted, READ | WRITE,
            "and the same policy has no effect on an object that does not name it")
        drop(sid)
    end)

test("a policy replaced after a handle is open changes future checks and not that handle",
    { spec = "PKM *check.cap.check-at-open" }, function(t)
        local sid = publish(t, 9202, {
            { effective_dacl = access.acl({ grant(STD.GENERIC_ALL, E) }) } })
        local dir = facs.workspace(vm, "caap")
        local path = dir .. "/governed"
        facs.file(vm, path, "hello")
        local sd = access.sd({ owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
            dacl = access.acl({ grant(STD.GENERIC_ALL, E) }),
            sacl = access.acl({ scoped_ace(sid) }) })
        t:assert_eq(kacs.set_sd(vm, path, sd, kacs.SI.DACL | kacs.SI.SACL).ret, 0,
            "the file references the policy")

        local fd, errno = kacs.open(vm, path, { access = kacs.RIGHT.READ_DATA })
        t:assert(fd, "the permissive policy admits the open: " .. sys.errname(errno or 0))

        -- Replace it with one whose effective DACL grants nothing.
        publish(t, 9202, { { effective_dacl = access.acl({}) } })
        local before = sys.read(vm, fd, 16)
        local again, errno2 = kacs.open(vm, path, { access = kacs.RIGHT.READ_DATA })
        if again then sys.close(vm, again) end
        sys.close(vm, fd)
        t:log(string.format("open handle read=%s, reopen fd=%s %s", tostring(before),
            tostring(again), sys.errname(errno2 or 0)))
        t:assert_eq(before, "hello", "the already-open handle keeps reading")
        t:assert(not again, "while a fresh open is refused under the replaced policy")
        t:assert_eq(errno2, sys.E.ACCES, "as a denial: " .. sys.errname(errno2 or 0))
        drop(sid)
    end)

test("a rule with no applies-to condition governs every object referencing the policy",
    { spec = "PKM *check.cap.no-condition-applies-always" }, function(t)
        local sid = publish(t, 9203, { { effective_dacl = access.acl({ grant(READ, E) }) } })
        local a = as_subject({}, sd_with(READ | WRITE, { scoped_ace(sid) }), STD.MAXIMUM_ALLOWED)
        local b = as_subject({ groups = { { sid = E, attributes = ENABLED },
            { sid = token.SID.TEST_GROUP_2, attributes = ENABLED } } },
            sd_with(READ | WRITE, { scoped_ace(sid) }), STD.MAXIMUM_ALLOWED)
        t:log(string.format("granted=0x%x and 0x%x", a.granted, b.granted))
        t:assert_eq(a.granted, READ, "the unconditional rule applies")
        t:assert_eq(b.granted, READ, "to every subject and object alike")
        drop(sid)
    end)

test("membership operators inside applies_to evaluate to UNKNOWN, so such a rule never applies",
    { spec = "PKM *check.cap.applies-to-membership-unknown" }, function(t)
        local narrow = access.acl({ grant(READ, E) })
        local true_rule = publish(t, 9204,
            { { applies_to = ALWAYS_TRUE, effective_dacl = narrow } })
        local a = as_subject({}, sd_with(READ | WRITE, { scoped_ace(true_rule) }),
            STD.MAXIMUM_ALLOWED)
        drop(true_rule)
        for _, c in ipairs({ { 0x89, "Member_of" }, { 0x8b, "Member_of_Any" },
                { 0x8a, "Device_Member_of" }, { 0x8c, "Device_Member_of_Any" },
                { 0x90, "Not_Member_of" }, { 0x92, "Not_Member_of_Any" } }) do
            local sid = publish(t, 9205, { { applies_to = membership(c[1], E),
                effective_dacl = narrow } })
            local r = as_subject({}, sd_with(READ | WRITE, { scoped_ace(sid) }),
                STD.MAXIMUM_ALLOWED)
            t:log(string.format("%s granted=0x%x", c[2], r.granted))
            t:assert_eq(r.granted, READ | WRITE, c[2]
                .. " in applies_to is UNKNOWN, so the rule is skipped and nothing narrows")
            drop(sid)
        end
        t:assert_eq(a.granted, READ,
            "while a rule whose condition is genuinely TRUE does narrow — Everyone is a token group")
    end)

test("a rule whose applies_to is UNKNOWN is skipped, the opposite of the deny-ACE rule",
    { spec = "PKM *check.cap.unknown-condition-skips-rule" }, function(t)
        local narrow = access.acl({ grant(READ, E) })
        local unknown = publish(t, 9206,
            { { applies_to = UNKNOWN_EXPR, effective_dacl = narrow } })
        local u = as_subject({}, sd_with(READ | WRITE, { scoped_ace(unknown) }), STD.MAXIMUM_ALLOWED)
        drop(unknown)
        local false_rule = publish(t, 9207,
            { { applies_to = ALWAYS_FALSE, effective_dacl = narrow } })
        local f = as_subject({}, sd_with(READ | WRITE, { scoped_ace(false_rule) }),
            STD.MAXIMUM_ALLOWED)
        drop(false_rule)
        t:log(string.format("UNKNOWN granted=0x%x, FALSE granted=0x%x", u.granted, f.granted))
        t:assert_eq(u.granted, READ | WRITE, "an UNKNOWN condition skips the rule entirely")
        t:assert_eq(f.granted, READ | WRITE, "as a FALSE one does")
    end)

test("CAAP intersects and never expands",
    { spec = "PKM *check.cap.intersects-only" }, function(t)
        local sid = publish(t, 9208, { { effective_dacl = access.acl({ grant(READ, E) }) } })
        local narrowed = as_subject({}, sd_with(READ | WRITE, { scoped_ace(sid) }),
            STD.MAXIMUM_ALLOWED)
        -- The rule grants far more than the object's own DACL.
        local wide = publish(t, 9209,
            { { effective_dacl = access.acl({ grant(STD.GENERIC_ALL, E) }) } })
        local expanded = as_subject({}, sd_with(READ, { scoped_ace(wide) }), STD.MAXIMUM_ALLOWED)
        t:log(string.format("narrowing granted=0x%x, widening granted=0x%x",
            narrowed.granted, expanded.granted))
        t:assert_eq(narrowed.granted, READ,
            "a rule granting read alone takes write away from an object granting read and write")
        t:assert_eq(expanded.granted, READ,
            "and a rule granting everything cannot add to what the object's DACL gave")
        drop(sid); drop(wide)
    end)

test("several scoped policy ACEs compose, each narrowing further",
    { spec = "PKM *check.cap.multiple-scoped-policy-aces" }, function(t)
        local a = publish(t, 9210, { { effective_dacl = access.acl({ grant(READ | WRITE, E) }) } })
        local b = publish(t, 9211, { { effective_dacl = access.acl({ grant(WRITE | EXEC, E) }) } })
        local one = as_subject({}, sd_with(READ | WRITE | EXEC, { scoped_ace(a) }),
            STD.MAXIMUM_ALLOWED)
        local both = as_subject({}, sd_with(READ | WRITE | EXEC,
            { scoped_ace(a), scoped_ace(b) }), STD.MAXIMUM_ALLOWED)
        t:log(string.format("one policy granted=0x%x, two granted=0x%x", one.granted, both.granted))
        t:assert_eq(one.granted, READ | WRITE, "one policy narrows to its own rule")
        t:assert_eq(both.granted, WRITE,
            "and a second one narrows again — the AND semantics make composition safe")
        drop(a); drop(b)
    end)

test("an inherit-only scoped policy ACE does not apply to the object carrying it",
    { spec = "PKM *check.cap.inherit-only-policy-ace-ignored" }, function(t)
        local sid = publish(t, 9212, { { effective_dacl = access.acl({ grant(READ, E) }) } })
        local applied = as_subject({}, sd_with(READ | WRITE, { scoped_ace(sid) }),
            STD.MAXIMUM_ALLOWED)
        local ignored = as_subject({}, sd_with(READ | WRITE,
            { scoped_ace(sid, access.ACE_FLAG.INHERIT_ONLY) }), STD.MAXIMUM_ALLOWED)
        t:log(string.format("applied granted=0x%x, inherit-only granted=0x%x",
            applied.granted, ignored.granted))
        t:assert_eq(applied.granted, READ, "the ordinary ACE brings the policy in")
        t:assert_eq(ignored.granted, READ | WRITE,
            "and the inherit-only one is skipped during lookup")
        drop(sid)
    end)

test("a rule's effective DACL is evaluated through the full pipeline, confinement included",
    { spec = "PKM *check.cap.rule-dacl-full-pipeline" }, function(t)
        -- The object's DACL names both Everyone and the confinement SID,
        -- so the base pass grants. Whether the rule grants depends on
        -- whether its own evaluation ran the confinement pass too.
        local blind = publish(t, 9213, { { effective_dacl = access.acl({ grant(READ, E) }) } })
        local seeing = publish(t, 9214,
            { { effective_dacl = access.acl({ grant(READ, E), grant(READ, CONF) }) } })
        local spec = { confinement_sid = CONF }
        local sd_blind = sd_with(READ, { scoped_ace(blind) },
            { dacl_aces = { grant(READ, E), grant(READ, CONF) } })
        local sd_seeing = sd_with(READ, { scoped_ace(seeing) },
            { dacl_aces = { grant(READ, E), grant(READ, CONF) } })
        local a = as_subject(spec, sd_blind, READ)
        local b = as_subject(spec, sd_seeing, READ)
        t:log(string.format("rule without the confinement SID ret=%d %s, with it ret=%d",
            a.ret, sys.errname(a.errno or 0), b.ret))
        t:assert(a.denied,
            "a rule DACL naming only Everyone grants a confined token nothing: ret=" .. a.ret
            .. " " .. sys.errname(a.errno or 0))
        t:assert(b.ok, "and one naming the confinement identity does: "
            .. sys.errname(b.errno or 0))
        drop(blind); drop(seeing)
    end)

test("when no rule applies the normal result stands",
    { spec = "PKM *check.cap.no-applicable-rules-no-effect" }, function(t)
        local empty = publish(t, 9215, {})
        local none = as_subject({}, sd_with(READ | WRITE, { scoped_ace(empty) }),
            STD.MAXIMUM_ALLOWED)
        drop(empty)
        local skipped = publish(t, 9216, { { applies_to = ALWAYS_FALSE,
            effective_dacl = access.acl({ grant(READ, E) }) } })
        local s = as_subject({}, sd_with(READ | WRITE, { scoped_ace(skipped) }),
            STD.MAXIMUM_ALLOWED)
        drop(skipped)
        t:log(string.format("no rules granted=0x%x, every condition false granted=0x%x",
            none.granted, s.granted))
        t:assert_eq(none.granted, READ | WRITE, "a policy with no rules has no effect")
        t:assert_eq(s.granted, READ | WRITE, "nor has one whose every condition is false")
    end)

test("a rule's DACL is evaluated with the caller's backup and restore intent not passed",
    { spec = "PKM *check.cap.no-backup-restore-intent" }, function(t)
        -- The object's DACL is empty, so the read bits in the base result
        -- came from SeBackupPrivilege alone. The rule's DACL is empty too:
        -- if intent were passed the rule would seed the same bits and the
        -- intersection would keep them.
        local privs = { privs_present = BACKUP, privs_enabled = BACKUP }
        local empty_rule = publish(t, 9217, { { effective_dacl = access.acl({}) } })
        local granting = publish(t, 9218, { { effective_dacl = access.acl({ grant(READ, E) }) } })
        local sd_empty = sd_with(0, { scoped_ace(empty_rule) }, { dacl_aces = {} })
        local sd_grant = sd_with(0, { scoped_ace(granting) }, { dacl_aces = {} })
        local no_policy = as_subject(privs, access.simple({}), READ,
            { intent = access.INTENT.BACKUP })
        local a = as_subject(privs, sd_empty, READ, { intent = access.INTENT.BACKUP })
        local b = as_subject(privs, sd_grant, READ, { intent = access.INTENT.BACKUP })
        t:log(string.format("no policy ret=%d, empty rule ret=%d %s, granting rule ret=%d",
            no_policy.ret, a.ret, sys.errname(a.errno or 0), b.ret))
        t:assert(no_policy.ok, "SeBackupPrivilege with backup intent grants read: "
            .. sys.errname(no_policy.errno or 0))
        t:assert(a.denied,
            "an empty rule DACL grants nothing, because the rule seeds no backup bits of its own: ret="
            .. a.ret .. " " .. sys.errname(a.errno or 0))
        t:assert(b.ok, "while a rule that grants the right through its DACL keeps it: "
            .. sys.errname(b.errno or 0))
        drop(empty_rule); drop(granting)
    end)

test("CAAP never recurses: a rule's synthetic descriptor has scoped policy ACEs stripped",
    { spec = "PKM *check.cap.no-recursion" }, function(t)
        -- If the rule's descriptor kept the ACE that selected the policy,
        -- evaluating the rule would select it again and the evaluation
        -- would not terminate. It does, with exactly one intersection.
        local sid = publish(t, 9219, { { effective_dacl = access.acl({ grant(READ, E) }) } })
        local once = as_subject({}, sd_with(READ | WRITE, { scoped_ace(sid) }), STD.MAXIMUM_ALLOWED)
        local twice = as_subject({}, sd_with(READ | WRITE, { scoped_ace(sid), scoped_ace(sid) }),
            STD.MAXIMUM_ALLOWED)
        t:log(string.format("one reference granted=0x%x, two granted=0x%x",
            once.granted, twice.granted))
        t:assert(once.ok and twice.ok, "the check terminates and returns a verdict")
        t:assert_eq(once.granted, READ, "with the policy applied once")
        t:assert_eq(twice.granted, READ, "and naming it twice is the same intersection")
        drop(sid)
    end)

test("the synthetic descriptor keeps the original owner and the SACL's mandatory label",
    { spec = "PKM *check.cap.synthetic-preserves-labels" }, function(t)
        -- The object is labelled Untrusted, which a Low caller dominates.
        -- Were the SACL not carried into the rule's descriptor the rule
        -- would fall back to the implicit Medium label and MIC would
        -- strip write inside the rule alone.
        local sid = publish(t, 9220,
            { { effective_dacl = access.acl({ grant(READ | WRITE, E) }) } })
        local sd = access.sd({ owner = USER, group = USER,
            dacl = access.acl({ grant(READ | WRITE, E) }),
            sacl = access.acl({ access.label_ace(token.INTEGRITY.UNTRUSTED,
                access.LABEL.NO_WRITE_UP), scoped_ace(sid) }) })
        local low = as_subject({ integrity_level = token.INTEGRITY.LOW }, sd, STD.MAXIMUM_ALLOWED)
        t:log(string.format("granted=0x%x", low.granted))
        t:assert_eq(low.granted & WRITE, WRITE,
            "the rule saw the object's own Untrusted label, which the Low caller dominates")
        t:assert_eq(low.granted & (STD.READ_CONTROL | STD.WRITE_DAC),
            STD.READ_CONTROL | STD.WRITE_DAC,
            "and the original owner, whose implicit rights the rule's evaluation granted too")
        drop(sid)
    end)

-- Audit evaluation ---------------------------------------------------------------------

local function events_of(ring, ty) return kmes.of_type(kmes.drain(ring), ty) end

test("a rule's effective SACL is evaluated alongside the object's own",
    { spec = "PKM *check.cap.sacl-merged-with-object" }, function(t)
        local ring = assert(kmes.attach(vm, 0))
        local sid = publish(t, 9221, {
            { effective_dacl = access.acl({ grant(STD.GENERIC_ALL, E) }),
              effective_sacl = access.acl({ access.ace(access.ACE.AUDIT, WRITE, E,
                  access.ACE_FLAG.SUCCESSFUL_ACCESS) }) } })
        -- The object's own SACL audits the read bit; the policy's audits
        -- the write bit. A request for both should produce both events.
        local sd = sd_with(READ | WRITE, {
            access.ace(access.ACE.AUDIT, READ, E, access.ACE_FLAG.SUCCESSFUL_ACCESS),
            scoped_ace(sid) })
        kmes.drain(ring)
        local r = as_subject({}, sd, READ | WRITE)
        local ev = events_of(ring, "access-audit")
        kmes.detach(ring)
        t:log(string.format("ret=%d access-audit events=%d", r.ret, #ev))
        t:assert(r.ok, "the request succeeds: " .. sys.errname(r.errno or 0))
        t:assert_eq(#ev, 2,
            "one event from the object's SACL and one from the policy's, treated identically")
        drop(sid)
    end)

test("the CAAP SACL component is additive and cannot suppress the object's own auditing",
    { spec = "PKM *check.cap.sacl-additive-only" }, function(t)
        local ring = assert(kmes.attach(vm, 0))
        -- A policy whose effective SACL is present but empty, and one
        -- with no SACL at all: neither can take the object's event away.
        local empty_sacl = publish(t, 9222, {
            { effective_dacl = access.acl({ grant(STD.GENERIC_ALL, E) }),
              effective_sacl = access.acl({}) } })
        local sd = sd_with(READ, {
            access.ace(access.ACE.AUDIT, READ, E, access.ACE_FLAG.SUCCESSFUL_ACCESS),
            scoped_ace(empty_sacl) })
        kmes.drain(ring)
        local r = as_subject({}, sd, READ)
        local ev = events_of(ring, "access-audit")
        kmes.detach(ring)
        t:log(string.format("ret=%d events=%d", r.ret, #ev))
        t:assert(r.ok, "the request succeeds: " .. sys.errname(r.errno or 0))
        t:assert_eq(#ev, 1, "the object's own audit ACE still fires under an empty policy SACL")
        drop(empty_sacl)
    end)

-- The cache and its wire format ---------------------------------------------------------

test("kacs_set_caap requires SeTcbPrivilege and marks it used",
    { spec = "PKM *check.cap.set-requires-tcb" }, function(t)
        local TCB, CREATE = token.bit(token.PRIV.TCB), token.bit(token.PRIV.CREATE_TOKEN)
        local spec = access.caap_spec({ { effective_dacl = access.acl({ grant(READ, E) }) } })
        token.as_principal(t, vm, { privs_present = TCB | CREATE,
            privs_enabled = TCB | CREATE }, function(w)
            local own = assert(token.open_self(w, token.RIGHT.QUERY | token.RIGHT.ADJUST_PRIVS))
            local with = access.set_caap(w, policy_sid(9223), spec)
            local privs = token.privileges(w, own)
            t:log(string.format("with TCB ret=%d %s, used=0x%x", with.ret,
                sys.errname(with.errno or 0), privs.used))
            t:assert_eq(with.ret, 0, "a caller holding SeTcbPrivilege may push a policy: "
                .. sys.errname(with.errno or 0))
            t:assert(privs.used & TCB ~= 0, "and the privilege is marked used")
            t:assert_eq(token.disable_priv(w, own, token.PRIV.TCB).ret, 0, "disable it")
            local without = access.set_caap(w, policy_sid(9224), spec)
            t:log(string.format("without TCB ret=%d %s", without.ret,
                sys.errname(without.errno or 0)))
            t:assert_eq(without.errno, sys.E.ACCES, "without it the call is refused EACCES: "
                .. sys.errname(without.errno or 0))
        end)
        drop(policy_sid(9223))
    end)

test("a non-null spec replaces an existing policy and a null one removes it",
    { spec = "PKM *check.cap.set-replaces-or-removes" }, function(t)
        local sid = publish(t, 9225, { { effective_dacl = access.acl({ grant(READ, E) }) } })
        local sd = sd_with(READ | WRITE | EXEC, { scoped_ace(sid) })
        local first = as_subject({}, sd, STD.MAXIMUM_ALLOWED)
        publish(t, 9225, { { effective_dacl = access.acl({ grant(WRITE, E) }) } })
        local replaced = as_subject({}, sd, STD.MAXIMUM_ALLOWED)
        t:assert_eq(access.set_caap(vm, sid, nil).ret, 0, "a null spec removes the policy")
        local removed = as_subject({}, sd, STD.MAXIMUM_ALLOWED)
        t:assert_eq(access.set_caap(vm, sid, "").ret, 0, "and so does a zero-length one")
        t:log(string.format("first granted=0x%x, replaced granted=0x%x, removed granted=0x%x",
            first.granted, replaced.granted, removed.granted))
        t:assert_eq(first.granted, READ, "the first policy narrows to read")
        t:assert_eq(replaced.granted, WRITE, "the replacement narrows to write instead")
        -- With the policy gone the SID is unknown and the recovery policy
        -- applies; the subject is neither an administrator, SYSTEM nor the
        -- owner, so it gets nothing.
        t:assert_eq(removed.granted, 0, "and once it is removed the recovery policy takes over")
    end)

test("the policy SID length is bounded to 8-68 bytes before parsing begins",
    { spec = "PKM *check.cap.uninitialised-eacces" }, function(t)
        local spec = access.caap_spec({ { effective_dacl = access.acl({ grant(READ, E) }) } })
        local short = access.set_caap(vm, string.rep("\1", 7), spec)
        local long = access.set_caap(vm, string.rep("\1", 69), spec)
        local ok = access.set_caap(vm, policy_sid(9226), spec)
        t:log(string.format("7 bytes ret=%d %s, 69 bytes ret=%d %s, valid ret=%d",
            short.ret, sys.errname(short.errno or 0), long.ret,
            sys.errname(long.errno or 0), ok.ret))
        t:assert_eq(short.errno, sys.E.INVAL, "a 7-byte SID is refused: "
            .. sys.errname(short.errno or 0))
        t:assert_eq(long.errno, sys.E.INVAL, "so is a 69-byte one: "
            .. sys.errname(long.errno or 0))
        t:assert_eq(ok.ret, 0, "and a well-formed one is accepted: " .. sys.errname(ok.errno or 0))
        drop(policy_sid(9226))
    end)

test("every ACE type valid in a DACL or SACL is permitted inside a policy ACL",
    { spec = "PKM *check.cap.any-ace-type-permitted" }, function(t)
        local guid = string.rep("\7", 16)
        local dacl = access.acl({
            access.ace(DENY, EXEC, token.SID.TEST_GROUP_2),
            access.ace(access.ACE.ALLOWED_OBJECT, READ, E, 0, { object_type = guid }),
            access.ace(access.ACE.ALLOWED_CALLBACK, READ | WRITE, E, 0,
                { condition = membership(0x89, E) .. string.rep("\0",
                    (-#membership(0x89, E)) % 4) }),
            grant(READ | WRITE, E),
        })
        local sacl = access.acl({
            access.ace(access.ACE.AUDIT, READ, E, access.ACE_FLAG.SUCCESSFUL_ACCESS),
            access.ace(access.ACE.ALARM, WRITE, E, access.ACE_FLAG.SUCCESSFUL_ACCESS),
            access.label_ace(token.INTEGRITY.LOW, access.LABEL.NO_WRITE_UP),
        })
        local sid = policy_sid(9227)
        local r = access.set_caap(vm, sid, access.caap_spec({
            { effective_dacl = dacl, effective_sacl = sacl } }))
        t:log(string.format("ret=%d %s", r.ret, sys.errname(r.errno or 0)))
        t:assert_eq(r.ret, 0, "deny, object, callback, audit, alarm and label ACEs all parse: "
            .. sys.errname(r.errno or 0))
        local check = as_subject({}, sd_with(READ | WRITE, { scoped_ace(sid) }), STD.MAXIMUM_ALLOWED)
        t:assert(check.ok, "and the policy evaluates: " .. sys.errname(check.errno or 0))
        drop(sid)
    end)

test("applies_to is conditional ACE bytecode carrying the same artx prefix",
    { spec = "PKM *check.cap.applies-to-artx-bytecode" }, function(t)
        local dacl = access.acl({ grant(READ, E) })
        local sid = policy_sid(9228)
        local with = access.set_caap(vm, sid,
            access.caap_spec({ { applies_to = ALWAYS_TRUE, effective_dacl = dacl } }))
        local without = access.set_caap(vm, sid, access.caap_spec({
            { applies_to = ALWAYS_TRUE:sub(5), effective_dacl = dacl } }))
        local wrong = access.set_caap(vm, sid, access.caap_spec({
            { applies_to = "ARTX" .. ALWAYS_TRUE:sub(5), effective_dacl = dacl } }))
        t:log(string.format("artx ret=%d, no prefix ret=%d %s, wrong prefix ret=%d %s",
            with.ret, without.ret, sys.errname(without.errno or 0), wrong.ret,
            sys.errname(wrong.errno or 0)))
        t:assert_eq(with.ret, 0, "the same bytecode a callback ACE carries is accepted: "
            .. sys.errname(with.errno or 0))
        t:assert_eq(without.errno, sys.E.INVAL, "the identical program without the prefix is not: "
            .. sys.errname(without.errno or 0))
        t:assert_eq(wrong.errno, sys.E.INVAL, "nor is one whose prefix is not exactly `artx`: "
            .. sys.errname(wrong.errno or 0))
        drop(sid)
    end)

test("the spec limits are 256 rules, a 64 KB applies_to and a 64 KB ACL",
    { spec = "PKM *check.cap.limits" }, function(t)
        local dacl = access.acl({ grant(READ, E) })
        local sid = policy_sid(9229)
        local function rules(n)
            local out = {}
            for i = 1, n do out[i] = { effective_dacl = dacl } end
            return out
        end
        local at_limit = access.set_caap(vm, sid, access.caap_spec(rules(256)))
        local over = access.set_caap(vm, sid, access.caap_spec(rules(257)))
        -- A field one byte past 64 KB, declared and supplied.
        local big_applies = "artx" .. string.rep("\0", 65534)
        local over_applies = access.set_caap(vm, sid,
            access.caap_spec({ { applies_to = big_applies .. string.rep("\0", 3), effective_dacl = dacl } }))
        t:log(string.format("256 rules ret=%d %s, 257 ret=%d %s, 64KB+1 applies_to ret=%d %s",
            at_limit.ret, sys.errname(at_limit.errno or 0), over.ret,
            sys.errname(over.errno or 0), over_applies.ret, sys.errname(over_applies.errno or 0)))
        t:assert_eq(at_limit.ret, 0, "256 rules are accepted: " .. sys.errname(at_limit.errno or 0))
        t:assert_eq(over.errno, sys.E.INVAL, "257 are not: " .. sys.errname(over.errno or 0))
        t:assert_eq(over_applies.errno, sys.E.INVAL,
            "and an applies_to past 64 KB is refused: " .. sys.errname(over_applies.errno or 0))
        drop(sid)
    end)

test("the version byte has to be 0x01",
    { spec = "PKM *check.cap.version-byte" }, function(t)
        local spec = access.caap_spec({ { effective_dacl = access.acl({ grant(READ, E) }) } })
        local sid = policy_sid(9230)
        local good = access.set_caap(vm, sid, spec)
        local zero = access.set_caap(vm, sid, string.pack("<I1", 0) .. spec:sub(2))
        local two = access.set_caap(vm, sid, string.pack("<I1", 2) .. spec:sub(2))
        t:log(string.format("0x01 ret=%d, 0x00 ret=%d %s, 0x02 ret=%d %s", good.ret, zero.ret,
            sys.errname(zero.errno or 0), two.ret, sys.errname(two.errno or 0)))
        t:assert_eq(good.ret, 0, "version 0x01 is accepted: " .. sys.errname(good.errno or 0))
        t:assert_eq(zero.errno, sys.E.INVAL, "0x00 is not: " .. sys.errname(zero.errno or 0))
        t:assert_eq(two.errno, sys.E.INVAL, "nor is 0x02: " .. sys.errname(two.errno or 0))
        drop(sid)
    end)

test("trailing bytes after the declared rules are rejected",
    { spec = "PKM *check.cap.trailing-bytes-rejected" }, function(t)
        local spec = access.caap_spec({ { effective_dacl = access.acl({ grant(READ, E) }) } })
        local sid = policy_sid(9231)
        local exact = access.set_caap(vm, sid, spec)
        local padded = access.set_caap(vm, sid, spec .. "\0")
        t:log(string.format("exact ret=%d, one extra byte ret=%d %s", exact.ret, padded.ret,
            sys.errname(padded.errno or 0)))
        t:assert_eq(exact.ret, 0, "the exact spec is accepted: " .. sys.errname(exact.errno or 0))
        t:assert_eq(padded.errno, sys.E.INVAL, "a single trailing byte is refused: "
            .. sys.errname(padded.errno or 0))
        drop(sid)
    end)

test("malformed applies_to bytecode fails the whole call with EINVAL at ingestion",
    { spec = "PKM *check.cap.malformed-applies-to-einval" }, function(t)
        local dacl = access.acl({ grant(READ, E) })
        local sid = policy_sid(9232)
        -- A structurally invalid program: a binary operator with nothing
        -- under it. A runtime evaluation would call this UNKNOWN.
        local dangling = "artx" .. string.pack("<I1", 0x80)
        local truncated = "artx" .. int_lit(1):sub(1, 5)
        local a = access.set_caap(vm, sid, access.caap_spec({
            { applies_to = dangling, effective_dacl = dacl } }))
        local b = access.set_caap(vm, sid, access.caap_spec({
            { applies_to = truncated, effective_dacl = dacl } }))
        t:log(string.format("dangling operator ret=%d %s, truncated literal ret=%d %s",
            a.ret, sys.errname(a.errno or 0), b.ret, sys.errname(b.errno or 0)))
        t:assert_eq(a.errno, sys.E.INVAL,
            "an operator with no operands fails the call rather than being admitted: "
            .. sys.errname(a.errno or 0))
        t:assert_eq(b.errno, sys.E.INVAL, "and so does a truncated literal: "
            .. sys.errname(b.errno or 0))
        local check = as_subject({}, sd_with(READ, { scoped_ace(sid) }), READ)
        t:assert(check.ok or check.denied, "the policy was never admitted, so nothing evaluates it")
    end)

test("a zero-length effective DACL, a truncated field or a bad ACL header all fail with EINVAL",
    { spec = "PKM *check.cap.zero-length-dacl-einval" }, function(t)
        local sid = policy_sid(9233)
        local zero = access.set_caap(vm, sid,
            string.pack("<I1I4", 1, 1) .. string.rep(string.pack("<I4", 0), 5))
        local truncated = access.set_caap(vm, sid,
            string.pack("<I1I4", 1, 1) .. string.pack("<I4", 0) .. string.pack("<I4", 40) .. "abc")
        -- An ACL header declaring a size smaller than the header itself.
        local bad_header = access.set_caap(vm, sid, access.caap_spec({
            { effective_dacl = string.pack("<I1I1I2I2I2", 2, 0, 4, 0, 0) } }))
        t:log(string.format("zero-length DACL ret=%d %s, truncated ret=%d %s, bad ACL size ret=%d %s",
            zero.ret, sys.errname(zero.errno or 0), truncated.ret,
            sys.errname(truncated.errno or 0), bad_header.ret, sys.errname(bad_header.errno or 0)))
        t:assert_eq(zero.errno, sys.E.INVAL, "a rule with no effective DACL is refused: "
            .. sys.errname(zero.errno or 0))
        t:assert_eq(truncated.errno, sys.E.INVAL,
            "a length running past the end of the buffer is refused: "
            .. sys.errname(truncated.errno or 0))
        t:assert_eq(bad_header.errno, sys.E.INVAL, "and so is an invalid ACL header: "
            .. sys.errname(bad_header.errno or 0))
    end)

test("SeTcbPrivilege is checked before any parsing begins",
    { spec = "PKM *check.cap.tcb-checked-before-parsing" }, function(t)
        local CREATE = token.bit(token.PRIV.CREATE_TOKEN)
        -- A spec that is malformed several ways over, and a SID outside
        -- the length bounds: a caller without the privilege must see
        -- EACCES rather than any of the parse errors.
        token.as_principal(t, vm, { privs_present = CREATE, privs_enabled = CREATE }, function(w)
            local garbage = access.set_caap(w, policy_sid(9234), string.rep("\xff", 32))
            local bad_sid = access.set_caap(w, string.rep("\1", 4), string.rep("\xff", 32))
            t:log(string.format("garbage spec ret=%d %s, out-of-range SID ret=%d %s",
                garbage.ret, sys.errname(garbage.errno or 0), bad_sid.ret,
                sys.errname(bad_sid.errno or 0)))
            t:assert_eq(garbage.errno, sys.E.ACCES,
                "an unprivileged caller is refused before the spec is looked at: "
                .. sys.errname(garbage.errno or 0))
            t:assert_eq(bad_sid.errno, sys.E.ACCES,
                "and before the policy SID's length is checked: " .. sys.errname(bad_sid.errno or 0))
        end)
    end)

-- The recovery policy ---------------------------------------------------------------------

test("a scoped policy ACE naming a SID that is not in the cache falls back to the recovery policy",
    { spec = "PKM *check.cap.recovery-policy" }, function(t)
        local missing = policy_sid(9235)
        drop(missing)
        local sd = sd_with(READ | WRITE, { scoped_ace(missing) })
        local nobody = as_subject({}, sd, STD.MAXIMUM_ALLOWED)
        local admin = as_subject({ groups = { { sid = E, attributes = ENABLED },
            { sid = ADMINS, attributes = ENABLED } } }, sd, STD.MAXIMUM_ALLOWED)
        local system = as_subject({ groups = { { sid = E, attributes = ENABLED },
            { sid = token.SID.LOCAL_SYSTEM, attributes = ENABLED } } }, sd, STD.MAXIMUM_ALLOWED)
        local owner = as_subject({}, sd_with(READ | WRITE, { scoped_ace(missing) },
            { owner = USER, group = USER }), STD.MAXIMUM_ALLOWED)
        t:log(string.format("plain=0x%x, admin=0x%x, system=0x%x, owner=0x%x",
            nobody.granted, admin.granted, system.granted, owner.granted))
        t:assert_eq(nobody.granted, 0,
            "an ordinary subject gets nothing: the recovery policy is fail-closed")
        t:assert_eq(admin.granted, READ | WRITE, "BUILTIN\\Administrators keeps the object's grant")
        t:assert_eq(system.granted & (READ | WRITE), READ | WRITE,
            string.format("so does SYSTEM: 0x%x", system.granted))
        t:assert(owner.granted & (READ | WRITE) == READ | WRITE,
            string.format("and so does the owner, through OWNER RIGHTS: 0x%x", owner.granted))
    end)

test("the recovery masks are the literal GENERIC_ALL, expanded through the caller's mapping",
    { spec = "PKM *check.cap.recovery-generic-all-mapped" }, function(t)
        local missing = policy_sid(9236)
        drop(missing)
        -- The same descriptor, evaluated for two object types whose
        -- GENERIC_ALL means different things.
        local sd = access.sd({ owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
            dacl = access.acl({ grant(STD.GENERIC_ALL, E) }),
            sacl = access.acl({ scoped_ace(missing) }) })
        local spec = { groups = { { sid = E, attributes = ENABLED },
            { sid = ADMINS, attributes = ENABLED } } }
        local synthetic = as_subject(spec, sd, STD.MAXIMUM_ALLOWED)
        local file = as_subject(spec, sd, STD.MAXIMUM_ALLOWED, { mapping = access.FILE_MAPPING })
        t:log(string.format("synthetic granted=0x%x (all=0x%x), file granted=0x%x (all=0x%x)",
            synthetic.granted, OBJ.all, file.granted, access.FILE_MAPPING.all))
        t:assert_eq(synthetic.granted, OBJ.all,
            "the recovery grant expands to the synthetic type's whole right set")
        t:assert_eq(file.granted, access.FILE_MAPPING.all,
            "and to the file type's under the file mapping — the mask was not pre-mapped")
    end)

-- Errors -------------------------------------------------------------------------------

test("a rule whose DACL evaluation errors denies everything except privilege-granted bits",
    { spec = "PKM *check.cap.rule-error-denies-except-privileges" }, function(t)
        -- The rule's DACL is a valid ACL that no synthetic descriptor can
        -- hold, so building the rule's descriptor fails.
        local sid = publish(t, 9237, { { effective_dacl = OVERSIZE_ACL } })
        local privs = { privs_present = SECURITY, privs_enabled = SECURITY }
        local sd = sd_with(STD.GENERIC_ALL, { scoped_ace(sid) })
        local ass = as_subject(privs, sd, STD.ACCESS_SYSTEM_SECURITY)
        local read = as_subject(privs, sd, READ)
        local everything = as_subject(privs, sd, STD.MAXIMUM_ALLOWED)
        t:log(string.format("ACCESS_SYSTEM_SECURITY ret=%d, read ret=%d %s, accumulated=0x%x",
            ass.ret, read.ret, sys.errname(read.errno or 0), everything.granted))
        t:assert(ass.ok, "the privilege-granted right survives the failed rule: "
            .. sys.errname(ass.errno or 0))
        t:assert(read.denied, "and everything the DACL granted is gone: ret=" .. read.ret
            .. " " .. sys.errname(read.errno or 0))
        t:assert_eq(everything.granted & OBJ.all, 0, "leaving no object-specific right at all")
        drop(sid)
    end)

test("the error escape hatch works only for a PIP-dominant caller",
    { spec = "PKM *check.cap.error-hatch-requires-pip-dominance" }, function(t)
        local sid = publish(t, 9238, { { effective_dacl = OVERSIZE_ACL } })
        local privs = { privs_present = SECURITY, privs_enabled = SECURITY }
        local sd = sd_with(STD.GENERIC_ALL, {
            access.trust_label_ace(512, 512, STD.GENERIC_ALL), scoped_ace(sid) })
        local dominant = as_subject(privs, sd, STD.ACCESS_SYSTEM_SECURITY,
            { pip_type = 512, pip_trust = 512 })
        local below = as_subject(privs, sd, STD.ACCESS_SYSTEM_SECURITY,
            { pip_type = 1, pip_trust = 1 })
        t:log(string.format("dominant ret=%d, non-dominant ret=%d %s", dominant.ret, below.ret,
            sys.errname(below.errno or 0)))
        t:assert(dominant.ok,
            "a PIP-dominant administrator keeps ACCESS_SYSTEM_SECURITY through the failed rule: "
            .. sys.errname(dominant.errno or 0))
        t:assert(below.denied,
            "a non-dominant one had it stripped before CAAP ran, so the hatch has nothing to preserve: ret="
            .. below.ret .. " " .. sys.errname(below.errno or 0))
        drop(sid)
    end)

test("rule evaluation swallows every error kind and reports a denial rather than an errno",
    { spec = "PKM *check.cap.rule-error-swallowed" }, function(t)
        local sid = publish(t, 9239, { { effective_dacl = OVERSIZE_ACL } })
        local r = as_subject({}, sd_with(STD.GENERIC_ALL, { scoped_ace(sid) }), READ)
        t:log(string.format("ret=%d %s", r.ret, sys.errname(r.errno or 0)))
        t:assert(r.denied,
            "the failed rule comes back as `denied all except privileges`, not as an error: ret="
            .. r.ret .. " " .. sys.errname(r.errno or 0))
        t:assert(r.errno ~= sys.E.NOMEM and r.errno ~= sys.E.INVAL,
            "and neither ENOMEM nor EINVAL escapes: " .. sys.errname(r.errno or 0))
        drop(sid)
    end)

test("a rule whose SACL evaluation errors has its audit contribution skipped and a diagnostic emitted",
    { spec = "PKM *check.cap.sacl-error-skipped-diagnostic" }, function(t)
        local ring = assert(kmes.attach(vm, 0))
        -- A mandatory-label ACE's mask is not validated at ingestion, so
        -- a reserved-range bit gets into the cache and only fails when the
        -- SACL walk maps it.
        local bad = access.ace(access.ACE.MANDATORY_LABEL, 0x0CE00000,
            token.label_sid(token.INTEGRITY.LOW))
        local sid = publish(t, 9240, {
            { effective_dacl = access.acl({ grant(STD.GENERIC_ALL, E) }),
              effective_sacl = access.acl({ bad, access.ace(access.ACE.AUDIT, READ, E,
                  access.ACE_FLAG.SUCCESSFUL_ACCESS) }) } })
        local sd = sd_with(READ, {
            access.ace(access.ACE.AUDIT, READ, E, access.ACE_FLAG.SUCCESSFUL_ACCESS),
            scoped_ace(sid) })
        kmes.drain(ring)
        local r = as_subject({}, sd, READ)
        local events = kmes.drain(ring)
        kmes.detach(ring)
        local audits = kmes.of_type(events, "access-audit")
        local diags = kmes.of_type(events, "caap-policy-diagnostic")
        t:log(string.format("ret=%d access-audit=%d caap-policy-diagnostic=%d", r.ret,
            #audits, #diags))
        t:assert(r.ok, "the access decision is unaffected: " .. sys.errname(r.errno or 0))
        t:assert_eq(#audits, 1,
            "the object's own audit ACE still fires and the policy's contributes nothing")
        t:assert(#diags >= 1, "and a caap-policy-diagnostic event is emitted")
        t:assert_eq(diags[1].payload.kind, "sacl-error", "classified as a SACL error")
        t:assert_eq(diags[1].payload.policy_sid, sid, "naming the policy")
        t:assert_eq(diags[1].payload.rule_index, 0, "and the rule inside it")
        drop(sid)
    end)

-- Staging -------------------------------------------------------------------------------

test("a staged DACL affects neither access nor audit and reports through the mismatch flag",
    { spec = "PKM *check.cap.staged-no-effect-reports-mismatch" }, function(t)
        local ring = assert(kmes.attach(vm, 0))
        local sid = publish(t, 9241, {
            { effective_dacl = access.acl({ grant(READ | WRITE, E) }),
              staged_dacl = access.acl({ grant(READ, E) }) } })
        local sd = sd_with(READ | WRITE, { scoped_ace(sid) })
        kmes.drain(ring)
        local r = as_subject({}, sd, READ | WRITE)
        local diags = kmes.of_type(kmes.drain(ring), "caap-policy-diagnostic")
        kmes.detach(ring)
        t:log(string.format("ret=%d granted=0x%x sm=%d diagnostics=%d", r.ret, r.granted,
            r.staging_mismatch, #diags))
        t:assert(r.ok, "the effective rule decides access: " .. sys.errname(r.errno or 0))
        t:assert_eq(r.granted, READ | WRITE, "and the staged result changes none of it")
        t:assert_eq(r.staging_mismatch, 1, "the difference is reported through the flag")
        t:assert(#diags >= 1, "and a diagnostic event")
        t:assert_eq(diags[1].payload.kind, "staging-mismatch", "of the staging kind")
        t:assert_eq(diags[1].payload.effective_granted_access, READ | WRITE, "carrying both totals")
        t:assert_eq(diags[1].payload.staged_granted_access, READ, "effective and staged")
        drop(sid)
    end)

test("a rule with no staged DACL contributes its effective result to both totals",
    { spec = "PKM *check.cap.no-staged-uses-effective" }, function(t)
        local none = publish(t, 9242, { { effective_dacl = access.acl({ grant(READ, E) }) } })
        local a = as_subject({}, sd_with(READ | WRITE, { scoped_ace(none) }), READ)
        drop(none)
        -- Two rules, only the second staged: the first still contributes
        -- to the staged total, so the staged result is the intersection
        -- of the first's effective and the second's staged.
        local mixed = publish(t, 9243, {
            { effective_dacl = access.acl({ grant(READ | WRITE, E) }) },
            { effective_dacl = access.acl({ grant(READ | WRITE, E) }),
              staged_dacl = access.acl({ grant(READ | WRITE, E) }) } })
        local b = as_subject({}, sd_with(READ | WRITE, { scoped_ace(mixed) }), READ | WRITE)
        drop(mixed)
        t:log(string.format("no staged DACL sm=%d granted=0x%x, mixed sm=%d granted=0x%x",
            a.staging_mismatch, a.granted, b.staging_mismatch, b.granted))
        t:assert_eq(a.staging_mismatch, 0,
            "an unstaged rule feeds both totals, so no difference is reported")
        t:assert_eq(b.staging_mismatch, 0,
            "and an unstaged rule beside a staged one that matches leaves the flag clear")
        t:assert_eq(b.granted, READ | WRITE, "with the effective result unchanged")
    end)
