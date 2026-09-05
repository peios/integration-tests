-- PKM §3.8.10 — the algorithm: how the layers compose. The order of the
-- fifteen steps, the two checks that can fail the call before the
-- pipeline starts, the wrappers' arithmetic, the shared helpers, and the
-- five privilege provenance masks.
--
-- The agent is SYSTEM with every privilege, so each case mints its own
-- subject and passes it as `token_fd`.

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
local G3 = token.sid(5, 21, 1000, 2000, 3000, 5003)
local PRINCIPAL_SELF = token.sid(5, 10)
local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED
local ALLOW, DENY = access.ACE.ALLOWED, access.ACE.DENIED
local SUCCESS_FLAG, FAILURE_FLAG = access.ACE_FLAG.SUCCESSFUL_ACCESS, access.ACE_FLAG.FAILED_ACCESS
local AUDIT_CALLBACK = 0x0D
local CONF = token.sid(15, 2, 1, 2, 3, 4, 5, 6, 7)
local POLICY = token.AUDIT
local RESERVED_BITS = 0x0CE00000

local SECURITY = token.bit(token.PRIV.SECURITY)
local TAKE_OWNERSHIP = token.bit(token.PRIV.TAKE_OWNERSHIP)
local BACKUP, RESTORE = token.bit(token.PRIV.BACKUP), token.bit(token.PRIV.RESTORE)
local RELABEL = token.bit(token.PRIV.RELABEL)

--- A synthetic object type whose read, write and execute rights are three
--- disjoint bits. ACCESS_SYSTEM_SECURITY is deliberately outside `all`.
local OBJ = { read = 0x1, write = 0x2, execute = 0x4,
    all = 0x7 | STD.DELETE | STD.READ_CONTROL | STD.WRITE_DAC | STD.WRITE_OWNER | STD.SYNCHRONIZE }
local READ, WRITE, EXEC = 0x1, 0x2, 0x4

local function guid(n) return string.rep(string.char(n), 16) end
local ROOT, A, B = guid(1), guid(2), guid(3)
local FLAT = { { level = 0, guid = ROOT }, { level = 1, guid = A }, { level = 1, guid = B } }

local function grant(mask, sid, flags, extra) return access.ace(ALLOW, mask, sid, flags, extra) end
local function audit_ace(mask, sid, flags) return access.ace(access.ACE.AUDIT, mask, sid, flags) end
local function alarm_ace(mask, sid, flags) return access.ace(access.ACE.ALARM, mask, sid, flags) end

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
            self_sid = opts.self_sid, pip_type = opts.pip_type, pip_trust = opts.pip_trust,
            audit_context = opts.audit_context })
    end)
    return out
end

local function as_subject_list(spec, sd, desired, tree, opts)
    opts = opts or {}
    local out
    with_subject(spec, function(fd)
        out = access.check_list(vm, { token_fd = fd, sd = sd, desired = desired,
            mapping = opts.mapping or OBJ, tree = tree, intent = opts.intent })
    end)
    return out
end

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

local function policy_sid(rid) return token.sid(5, 21, 1000, 2000, 3000, rid) end
local function scoped_ace(sid) return access.ace(access.ACE.SCOPED_POLICY_ID, 0, sid) end
local function set_policy(t, rid, rules)
    local sid = policy_sid(rid)
    local r = access.set_caap(vm, sid, rules and access.caap_spec(rules) or nil)
    t:assert_eq(r.ret, 0, "kacs_set_caap: " .. sys.errname(r.errno or 0))
    return sid
end
local function drop(sid) access.set_caap(vm, sid, nil) end

--- An ACL too big for any synthetic descriptor to hold, which is how a
--- case makes a CAAP rule's evaluation fail.
local OVERSIZE_ACL = (function()
    local ace = grant(READ, E)
    local aces = {}
    for i = 1, (65535 - 8) // #ace do aces[i] = ace end
    return access.acl(aces)
end)()

local function pad4(s) return s .. string.rep("\0", (-#s) % 4) end
local function int_lit(v) return string.pack("<I1i8I1I1", 0x04, v, 0x01, 0x02) end
local function utf16(s)
    local out = {}
    for i = 1, #s do out[i] = string.pack("<I2", s:byte(i)) end
    return table.concat(out)
end
--- `Member_of({sid})`.
local function member_of(sid)
    return pad4("artx" .. string.pack("<I1I4", 0x51, #sid) .. sid .. string.pack("<I1", 0x89))
end
--- `@Resource.<name> == <value>`.
local function resource_eq(name, value)
    return pad4("artx" .. string.pack("<I1I4", 0xfa, #utf16(name)) .. utf16(name)
        .. int_lit(value) .. string.pack("<I1", 0x80))
end
--- A SYSTEM_RESOURCE_ATTRIBUTE ACE carrying one INT64-valued attribute.
--- The trustee must be Everyone; the payload is the MS-DTYP
--- CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 layout.
local function resource_attribute(name, value)
    local name_bytes = utf16(name) .. string.pack("<I2", 0)
    local body = string.pack("<I4I2I2I4I4", 20, 0x0001, 0, 0, 1)
        .. string.pack("<I4", 20 + #name_bytes) .. name_bytes .. string.pack("<i8", value)
    return access.ace(access.ACE.RESOURCE_ATTRIBUTE, 0, E, 0, { condition = pad4(body) })
end

-- Before the pipeline -------------------------------------------------------------------

test("the pipeline composes privileges, MIC, the DACL, the restricted merge and confinement in order",
    { spec = "PKM *check.algorithm.pipeline-order" }, function(t)
        -- Every layer touches the same bit, and only this order produces
        -- the observed sequence of results: step 4 seeds the read bit,
        -- step 5's MIC never revokes it, step 8's deny ACE cannot reopen
        -- it, step 10 intersects it away and restores it, and step 11
        -- takes it for good.
        local label = access.acl({ access.label_ace(token.INTEGRITY.HIGH,
            access.LABEL.NO_READ_UP | access.LABEL.NO_WRITE_UP) })
        local sd = access.simple({ access.ace(DENY, READ, E) }, { sacl = label })
        local base = { integrity_level = token.INTEGRITY.LOW,
            privs_present = BACKUP, privs_enabled = BACKUP }
        local function spec(extra)
            local s = {}
            for k, v in pairs(base) do s[k] = v end
            for k, v in pairs(extra or {}) do s[k] = v end
            return s
        end
        local intent = { intent = access.INTENT.BACKUP }
        local privileged = as_subject(spec(), sd, READ, intent)
        local no_intent = as_subject(spec(), sd, READ, {})
        local restricted = as_subject(spec({ restricted_sids = { { sid = G3, attributes = 0 } } }),
            sd, READ, intent)
        local confined = as_subject(spec({ confinement_sid = CONF }), sd, READ, intent)
        t:log(string.format("privileged ret=%d, no intent ret=%d, restricted ret=%d, confined ret=%d",
            privileged.ret, no_intent.ret, restricted.ret, confined.ret))
        t:assert(privileged.ok,
            "the read bit is seeded at step 4, survives MIC at step 5 and the deny ACE at step 8: "
            .. sys.errname(privileged.errno or 0))
        t:assert(no_intent.denied,
            "without backup intent step 3 clears the privilege and the deny ACE decides: ret="
            .. no_intent.ret .. " " .. sys.errname(no_intent.errno or 0))
        t:assert(restricted.ok,
            "step 10 intersects the bit away and restores it, because privileges bypass that pass: "
            .. sys.errname(restricted.errno or 0))
        t:assert(confined.denied,
            "and step 11, running after the restoration, takes it for good: ret=" .. confined.ret
            .. " " .. sys.errname(confined.errno or 0))
    end)

test("a write_restricted token without user_deny_only is rejected as invalid",
    { spec = "PKM *check.algorithm.write-restricted-needs-deny-only",
      covered_by = "kunit:pkm_kunit_token",
      skip = "no such token can be presented from the guest: " ..
             "kacs_create_token refuses the pair outright (EINVAL) and " ..
             "KACS_IOC_RESTRICT sets user_deny_only whenever it sets " ..
             "write_restricted, so AccessCheck's own re-check of the " ..
             "invariant is unreachable; the creation-time half runs " ..
             "under pkm_kunit_create_token_write_restricted_requires_" ..
             "user_deny_only" },
    function(t) end)

test("the orchestrator rejects a null descriptor and requires the result list to have a tree",
    { spec = "PKM *check.algorithm.null-descriptor-rejected" }, function(t)
        local sd = access.simple({ grant(READ, E) })
        local null_args = string.pack("<I4i4I8I4I4I4I4I4I4I8I4I4I8I4I4I8I4I4I8I4I4I8I4I4I8I8",
            access.ARGS_SIZE, -1, 0, 0, READ,
            OBJ.read, OBJ.write, OBJ.execute, OBJ.all,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        local null_sd = vm:syscall(access.SYS.ACCESS_CHECK, {
            args = { 0 }, bufs = { null_args }, ptrs = { 0 } })
        local tree_args = string.pack("<I4i4I8I4I4I4I4I4I4I8I4I4I8I4I4I8I4I4I8I4I4I8I4I4I8I8",
            access.ARGS_SIZE, -1, 0, #sd, READ,
            OBJ.read, OBJ.write, OBJ.execute, OBJ.all,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        local nested = { { parent = 1, child = 2, offset = 8 } }
        local no_tree = vm:syscall(access.SYS.ACCESS_CHECK_LIST, {
            args = { 0, 0, 0 }, bufs = { tree_args, sd }, ptrs = { 0 }, nested = nested })
        t:log(string.format("null descriptor ret=%d %s, list with no tree ret=%d %s",
            null_sd.ret, sys.errname(null_sd.errno or 0), no_tree.ret,
            sys.errname(no_tree.errno or 0)))
        t:assert_eq(null_sd.errno, sys.E.INVAL, "a null descriptor fails the call: "
            .. sys.errname(null_sd.errno or 0))
        t:assert(no_tree.ret < 0, "and the result-list variant refuses a request with no list")
        t:assert(no_tree.errno ~= sys.E.ACCES, "as an invalid request: "
            .. sys.errname(no_tree.errno or 0))
    end)

test("a null descriptor presented by an Identification token fails as invalid, not as denied",
    { spec = "PKM *check.algorithm.null-check-runs-first" }, function(t)
        local ident = { token_type = token.TYPE.IMPERSONATION,
            impersonation_level = token.LEVEL.IDENTIFICATION }
        local denied, invalid
        with_subject(ident, function(fd)
            -- With a real descriptor the impersonation gate refuses it.
            denied = access.check(vm, { token_fd = fd, sd = access.simple({ grant(READ, E) }),
                desired = READ, mapping = OBJ })
            local args = string.pack("<I4i4I8I4I4I4I4I4I4I8I4I4I8I4I4I8I4I4I8I4I4I8I4I4I8I8",
                access.ARGS_SIZE, fd, 0, 0, READ,
                OBJ.read, OBJ.write, OBJ.execute, OBJ.all,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
            invalid = vm:syscall(access.SYS.ACCESS_CHECK, {
                args = { 0 }, bufs = { args }, ptrs = { 0 } })
        end)
        t:log(string.format("with a descriptor ret=%d %s, with none ret=%d %s",
            denied.ret, sys.errname(denied.errno or 0), invalid.ret,
            sys.errname(invalid.errno or 0)))
        t:assert(denied.denied, "an Identification token is denied outright: ret=" .. denied.ret
            .. " " .. sys.errname(denied.errno or 0))
        t:assert_eq(invalid.errno, sys.E.INVAL,
            "while the same token with a null descriptor fails as an invalid parameter: "
            .. sys.errname(invalid.errno or 0))
    end)

-- The pipeline --------------------------------------------------------------------------

test("an impersonation token at Identification level is denied immediately",
    { spec = "PKM *check.algorithm.identification-denied" }, function(t)
        -- The DACL grants everything, so nothing but step 0 can refuse it.
        local sd = access.simple({ grant(STD.GENERIC_ALL, E) })
        local ident = as_subject({ token_type = token.TYPE.IMPERSONATION,
            impersonation_level = token.LEVEL.IDENTIFICATION }, sd, STD.MAXIMUM_ALLOWED)
        local higher = as_subject({ token_type = token.TYPE.IMPERSONATION,
            impersonation_level = token.LEVEL.IMPERSONATION }, sd, STD.MAXIMUM_ALLOWED)
        t:log(string.format("Identification ret=%d %s, Impersonation granted=0x%x",
            ident.ret, sys.errname(ident.errno or 0), higher.granted))
        t:assert(ident.denied, "even a MAXIMUM_ALLOWED request, which never fails otherwise: ret="
            .. ident.ret .. " " .. sys.errname(ident.errno or 0))
        t:assert_eq(higher.granted, OBJ.all, "while the next level up runs the pipeline")
    end)

test("an Anonymous-level token proceeds through the full pipeline",
    { spec = "PKM *check.algorithm.anonymous-allowed" }, function(t)
        local anon = { token_type = token.TYPE.IMPERSONATION,
            impersonation_level = token.LEVEL.ANONYMOUS }
        local granted = as_subject(anon, access.simple({ grant(READ, E) }), READ)
        local refused = as_subject(anon, access.simple({}), READ)
        t:log(string.format("granting DACL ret=%d %s, empty DACL ret=%d %s", granted.ret,
            sys.errname(granted.errno or 0), refused.ret, sys.errname(refused.errno or 0)))
        t:assert(granted.ok, "the DACL decides, so an Everyone grant comes through: "
            .. sys.errname(granted.errno or 0))
        t:assert(refused.denied, "and an empty DACL denies — not the impersonation gate: ret="
            .. refused.ret .. " " .. sys.errname(refused.errno or 0))
    end)

test("step 1 rejects a descriptor with no owner",
    { spec = "PKM *check.algorithm.no-owner-rejected" }, function(t)
        local ownerless = access.sd({ group = token.SID.LOCAL_SYSTEM,
            dacl = access.acl({ grant(READ, E) }) })
        local owned = access.sd({ owner = token.SID.LOCAL_SYSTEM,
            group = token.SID.LOCAL_SYSTEM, dacl = access.acl({ grant(READ, E) }) })
        local a = as_subject({}, ownerless, READ)
        local b = as_subject({}, owned, READ)
        t:log(string.format("no owner ret=%d %s, owner ret=%d", a.ret, sys.errname(a.errno or 0),
            b.ret))
        t:assert(a.ret < 0, "the check fails")
        t:assert_eq(a.errno, sys.E.INVAL, "as an invalid descriptor, not as a denial: "
            .. sys.errname(a.errno or 0))
        t:assert(b.ok, "and the same descriptor with an owner evaluates: "
            .. sys.errname(b.errno or 0))
    end)

test("a null group SID is valid and has no direct effect on the decision",
    { spec = "PKM *check.algorithm.null-group-valid" }, function(t)
        local dacl = access.acl({ grant(READ, E) })
        local grouped = access.sd({ owner = token.SID.LOCAL_SYSTEM,
            group = token.SID.LOCAL_SYSTEM, dacl = dacl })
        local groupless = access.sd({ owner = token.SID.LOCAL_SYSTEM, dacl = dacl })
        local a = as_subject({}, grouped, STD.MAXIMUM_ALLOWED)
        local b = as_subject({}, groupless, STD.MAXIMUM_ALLOWED)
        t:log(string.format("with a group granted=0x%x, without granted=0x%x", a.granted, b.granted))
        t:assert(b.ok, "a descriptor with no group is accepted: " .. sys.errname(b.errno or 0))
        t:assert_eq(b.granted, a.granted, "and decides exactly as one with a group does")
    end)

test("step 2 maps the generic bits in the desired mask and strips MAXIMUM_ALLOWED",
    { spec = "PKM *check.algorithm.desired-mask-mapped" }, function(t)
        -- The DACL grants the synthetic type's read right and nothing else.
        local sd = access.simple({ grant(READ, E) })
        local generic = as_subject({}, sd, STD.GENERIC_READ)
        local specific = as_subject({}, sd, READ)
        local wrong = as_subject({}, sd, STD.GENERIC_WRITE)
        local stripped = as_subject({}, sd, STD.MAXIMUM_ALLOWED | READ)
        t:log(string.format("GENERIC_READ ret=%d, read ret=%d, GENERIC_WRITE ret=%d %s, max|read granted=0x%x",
            generic.ret, specific.ret, wrong.ret, sys.errname(wrong.errno or 0), stripped.granted))
        t:assert(generic.ok, "GENERIC_READ becomes the object type's read right: "
            .. sys.errname(generic.errno or 0))
        t:assert_eq(generic.ret, specific.ret, "which is the same request as naming it outright")
        t:assert(wrong.denied, "GENERIC_WRITE becomes the write right, which is not granted: ret="
            .. wrong.ret .. " " .. sys.errname(wrong.errno or 0))
        t:assert(stripped.ok, "and MAXIMUM_ALLOWED is stripped rather than demanded: "
            .. sys.errname(stripped.errno or 0))
        t:assert_eq(stripped.granted & STD.MAXIMUM_ALLOWED, 0, "so it never reaches the result")
    end)

test("step 3 clears the backup and restore bits when the matching intent flag is absent",
    { spec = "PKM *check.algorithm.intent-gates-backup-restore" }, function(t)
        local sd = access.simple({})
        local both = { privs_present = BACKUP | RESTORE, privs_enabled = BACKUP | RESTORE }
        local none = as_subject(both, sd, STD.MAXIMUM_ALLOWED)
        local backup = as_subject(both, sd, STD.MAXIMUM_ALLOWED, { intent = access.INTENT.BACKUP })
        local restore = as_subject(both, sd, STD.MAXIMUM_ALLOWED, { intent = access.INTENT.RESTORE })
        local all = as_subject(both, sd, STD.MAXIMUM_ALLOWED,
            { intent = access.INTENT.BACKUP | access.INTENT.RESTORE })
        t:log(string.format("no intent=0x%x, backup=0x%x, restore=0x%x, both=0x%x",
            none.granted, backup.granted, restore.granted, all.granted))
        t:assert_eq(none.granted, 0, "neither privilege contributes without its intent flag")
        t:assert_eq(backup.granted, OBJ.read, "backup intent brings the read bits in")
        t:assert_eq(restore.granted & OBJ.write, OBJ.write, "restore intent brings the write bits in")
        t:assert_eq(all.granted & (OBJ.read | OBJ.write), OBJ.read | OBJ.write,
            "and naming both brings in both")
    end)

test("step 4 seeds decided, granted and privilege_granted from the three privileges",
    { spec = "PKM *check.algorithm.privilege-seeding" }, function(t)
        -- An empty DACL: everything in the result came from the seeding.
        local sd = access.simple({})
        local plain = as_subject({}, sd, STD.MAXIMUM_ALLOWED)
        local ass = as_subject({}, sd, STD.ACCESS_SYSTEM_SECURITY)
        local security = as_subject({ privs_present = SECURITY, privs_enabled = SECURITY },
            sd, STD.MAXIMUM_ALLOWED)
        local backup = as_subject({ privs_present = BACKUP, privs_enabled = BACKUP },
            sd, STD.MAXIMUM_ALLOWED, { intent = access.INTENT.BACKUP })
        local restore = as_subject({ privs_present = RESTORE, privs_enabled = RESTORE },
            sd, STD.MAXIMUM_ALLOWED, { intent = access.INTENT.RESTORE })
        local restore_bits = OBJ.write | STD.WRITE_DAC | STD.WRITE_OWNER | STD.DELETE
            | STD.ACCESS_SYSTEM_SECURITY
        t:log(string.format("none=0x%x, security=0x%x, backup=0x%x, restore=0x%x (expected 0x%x)",
            plain.granted, security.granted, backup.granted, restore.granted, restore_bits))
        t:assert_eq(plain.granted, 0, "an unprivileged caller seeds nothing")
        t:assert(ass.denied,
            "and ACCESS_SYSTEM_SECURITY is decided by privilege, so without one it is refused: ret="
            .. ass.ret .. " " .. sys.errname(ass.errno or 0))
        t:assert_eq(security.granted, STD.ACCESS_SYSTEM_SECURITY,
            "SeSecurityPrivilege seeds exactly ACCESS_SYSTEM_SECURITY")
        t:assert_eq(backup.granted, OBJ.read, "SeBackupPrivilege seeds MapGenericBits(GENERIC_READ)")
        t:assert_eq(restore.granted, restore_bits,
            "and SeRestorePrivilege seeds the write bits with WRITE_DAC, WRITE_OWNER, DELETE and ACCESS_SYSTEM_SECURITY")
    end)

test("step 5 extracts the label, the trust label, resource attributes and policy SIDs, then enforces MIC and PIP",
    { spec = "PKM *check.algorithm.pre-sacl-walk" }, function(t)
        local sid = set_policy(t, 9401,
            { { effective_dacl = access.acl({ grant(READ | WRITE, E) }) } })
        -- One SACL carrying all four kinds of entry. The DACL grants
        -- through a condition that only a resource attribute can satisfy.
        local sacl = access.acl({
            access.label_ace(token.INTEGRITY.HIGH, access.LABEL.NO_WRITE_UP),
            access.trust_label_ace(512, 512, 0),
            resource_attribute("Dept", 7),
            scoped_ace(sid),
        })
        local dacl = access.acl({
            access.ace(access.ACE.ALLOWED_CALLBACK, READ | WRITE | EXEC, E, 0,
                { condition = resource_eq("Dept", 7) }) })
        local sd = access.sd({ owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
            dacl = dacl, sacl = sacl })
        local low = { integrity_level = token.INTEGRITY.LOW }
        local dominant = as_subject(low, sd, STD.MAXIMUM_ALLOWED,
            { pip_type = 512, pip_trust = 512 })
        local non_dominant = as_subject(low, sd, READ, { pip_type = 1, pip_trust = 1 })
        local wrong_attribute = as_subject(low, access.sd({
            owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM, dacl = dacl,
            sacl = access.acl({ resource_attribute("Dept", 9) }) }), READ)
        drop(sid)
        t:log(string.format("dominant granted=0x%x, non-dominant ret=%d %s, wrong attribute ret=%d %s",
            dominant.granted, non_dominant.ret, sys.errname(non_dominant.errno or 0),
            wrong_attribute.ret, sys.errname(wrong_attribute.errno or 0)))
        t:assert_eq(dominant.granted & READ, READ,
            "the resource attribute was extracted, so the conditional ACE granted read")
        t:assert_eq(dominant.granted & WRITE, 0,
            "the mandatory label was extracted, and MIC denied write to a Low caller")
        t:assert_eq(dominant.granted & EXEC, 0,
            "the scoped policy SID was extracted, and the policy's rule granted no execute")
        t:assert(non_dominant.denied,
            "the trust label was extracted, and PIP denies a non-dominant caller: ret="
            .. non_dominant.ret .. " " .. sys.errname(non_dominant.errno or 0))
        t:assert(wrong_attribute.denied,
            "and an attribute whose value does not match leaves the condition false: ret="
            .. wrong_attribute.ret .. " " .. sys.errname(wrong_attribute.errno or 0))
    end)

test("step 7 seeds every tree node from the already-augmented scalar state",
    { spec = "PKM *check.algorithm.tree-seeded-from-scalar" }, function(t)
        -- The read bits come from step 4 alone; the DACL is empty. Every
        -- node must start life holding them.
        local r = as_subject_list({ privs_present = BACKUP, privs_enabled = BACKUP },
            access.simple({}), OBJ.read, FLAT, { intent = access.INTENT.BACKUP })
        t:log(string.format("nodes 0x%x/%d 0x%x/%d 0x%x/%d",
            r.nodes[1].granted, r.nodes[1].status, r.nodes[2].granted, r.nodes[2].status,
            r.nodes[3].granted, r.nodes[3].status))
        for i = 1, 3 do
            t:assert_eq(r.nodes[i].granted, OBJ.read,
                "node " .. i .. " carries the scalar state's privilege-seeded bits")
            t:assert_eq(r.nodes[i].status, 0, "and passes on them alone")
        end
    end)

test("step 9 grants WRITE_OWNER from SeTakeOwnershipPrivilege unless a mandatory mechanism blocked it",
    { spec = "PKM *check.algorithm.take-ownership-override" }, function(t)
        local privs = { privs_present = TAKE_OWNERSHIP, privs_enabled = TAKE_OWNERSHIP }
        local empty = access.simple({})
        local without = as_subject({}, empty, STD.WRITE_OWNER)
        local with = as_subject(privs, empty, STD.WRITE_OWNER)
        -- MIC decides WRITE_OWNER for a caller below the object's label,
        -- and step 9 checks mandatory_decided before granting.
        local labelled = access.simple({}, { sacl = access.acl({
            access.label_ace(token.INTEGRITY.HIGH, access.LABEL.NO_WRITE_UP) }) })
        local blocked = as_subject({ integrity_level = token.INTEGRITY.LOW,
            privs_present = TAKE_OWNERSHIP, privs_enabled = TAKE_OWNERSHIP }, labelled,
            STD.WRITE_OWNER)
        t:log(string.format("no privilege ret=%d %s, with it ret=%d, blocked by MIC ret=%d %s",
            without.ret, sys.errname(without.errno or 0), with.ret, blocked.ret,
            sys.errname(blocked.errno or 0)))
        t:assert(without.denied, "an empty DACL grants no WRITE_OWNER: ret=" .. without.ret
            .. " " .. sys.errname(without.errno or 0))
        t:assert(with.ok, "SeTakeOwnershipPrivilege supplies it: " .. sys.errname(with.errno or 0))
        t:assert(blocked.denied, "and cannot where MIC has already decided the bit: ret="
            .. blocked.ret .. " " .. sys.errname(blocked.errno or 0))
    end)

test("an object type list is validated at parse time, before the pipeline runs",
    { spec = "PKM *check.algorithm.list-validated-before-pipeline" }, function(t)
        local sd = access.simple({ grant(READ, E) })
        -- An Identification token would be denied at step 0; a malformed
        -- list must fail earlier than that, as an invalid parameter.
        local ident = { token_type = token.TYPE.IMPERSONATION,
            impersonation_level = token.LEVEL.IDENTIFICATION }
        local cases = {
            { { { level = 1, guid = ROOT } }, "a list whose first node is not at level 0" },
            { { { level = 0, guid = ROOT }, { level = 2, guid = A } }, "a level gap" },
            { { { level = 0, guid = ROOT }, { level = 1, guid = ROOT } }, "a duplicate GUID" },
            { { { level = 0, guid = ROOT }, { level = 0, guid = A } }, "a second root" },
        }
        for _, c in ipairs(cases) do
            local r = as_subject_list(ident, sd, READ, c[1])
            t:log(string.format("%s: ret=%d %s", c[2], r.ret, sys.errname(r.errno or 0)))
            t:assert(r.ret < 0, c[2] .. " is refused")
            t:assert_eq(r.errno, sys.E.INVAL,
                c[2] .. " never reaches the impersonation gate: " .. sys.errname(r.errno or 0))
        end
        local good = as_subject_list(ident, sd, READ, FLAT)
        t:assert_eq(good.errno, sys.E.ACCES,
            "while a well-formed list does reach it: " .. sys.errname(good.errno or 0))
    end)

test("reserved access-mask bits are rejected in the caller's desired mask",
    { spec = "PKM *check.algorithm.reserved-bits-rejected" }, function(t)
        local sd = access.simple({ grant(STD.GENERIC_ALL, E) })
        local clean = as_subject({}, sd, READ)
        local reserved = as_subject({}, sd, READ | RESERVED_BITS)
        local one_bit = as_subject({}, sd, READ | 0x00200000)
        t:log(string.format("clean ret=%d, 0x0CE00000 ret=%d %s, one reserved bit ret=%d %s",
            clean.ret, reserved.ret, sys.errname(reserved.errno or 0), one_bit.ret,
            sys.errname(one_bit.errno or 0)))
        t:assert(clean.ok, "the request without them succeeds: " .. sys.errname(clean.errno or 0))
        t:assert_eq(reserved.errno, sys.E.INVAL, "the whole reserved range is refused: "
            .. sys.errname(reserved.errno or 0))
        t:assert_eq(one_bit.errno, sys.E.INVAL, "and so is a single bit from it: "
            .. sys.errname(one_bit.errno or 0))
    end)

test("a single ACE carrying a reserved bit aborts the whole check rather than being skipped",
    { spec = "PKM *check.algorithm.reserved-bit-ace-aborts-check" }, function(t)
        -- The first ACE grants the request outright, so a skipped second
        -- ACE would leave the call succeeding.
        local sd = access.simple({ grant(READ, E), grant(RESERVED_BITS, G2) })
        local clean = as_subject({}, access.simple({ grant(READ, E), grant(WRITE, G2) }), READ)
        local r = as_subject({}, sd, READ)
        t:log(string.format("clean ret=%d, reserved-bit ACE ret=%d %s", clean.ret, r.ret,
            sys.errname(r.errno or 0)))
        t:assert(clean.ok, "the same shape without the reserved bit succeeds: "
            .. sys.errname(clean.errno or 0))
        t:assert(r.ret < 0, "the reserved bit in an ACE mask fails the call")
        t:assert_eq(r.errno, sys.E.INVAL, "as an invalid descriptor: " .. sys.errname(r.errno or 0))
    end)

test("a reserved bit in a mandatory-label ACE mask aborts the check like any other ACE mask",
    { spec = "PKM *check.algorithm.reserved-bit-ace-aborts-check" }, function(t)
        -- Ace::parse_mandatory_label is the one parse path that does not
        -- call validate_ace_mask, and MIC only ever tests the label mask
        -- against the three SYSTEM_MANDATORY_LABEL_NO_*_UP bits, so the
        -- reserved range survives both. It still aborts the call, in the
        -- SACL walk, which maps every ACE mask it meets. The caller here
        -- dominates the Low label, so MIC returns before touching the
        -- mask and only the walk can be the source.
        local sacl = access.acl({ access.ace(access.ACE.MANDATORY_LABEL,
            RESERVED_BITS | access.LABEL.NO_WRITE_UP, token.label_sid(token.INTEGRITY.LOW)) })
        local sd = access.simple({ grant(READ, E) }, { sacl = sacl })
        local clean = as_subject({}, access.simple({ grant(READ, E) }, { sacl = access.acl({
            access.label_ace(token.INTEGRITY.LOW, access.LABEL.NO_WRITE_UP) }) }), READ)
        local r = as_subject({}, sd, READ)
        t:log(string.format("clean ret=%d, reserved-bit label ret=%d %s granted=0x%x", clean.ret,
            r.ret, sys.errname(r.errno or 0), r.granted))
        t:assert(clean.ok, "the same label without the reserved bit evaluates: "
            .. sys.errname(clean.errno or 0))
        t:assert(r.ret < 0, "the check is aborted")
        t:assert_eq(r.errno, sys.E.INVAL, "as an invalid descriptor: " .. sys.errname(r.errno or 0))
    end)

test("privilege_granted is narrowed by what survived, so confinement shrinks the CAAP error hatch",
    { spec = "PKM *check.algorithm.privilege-granted-narrowed" }, function(t)
        -- The hatch preserves the *narrowed* privilege-granted set. A
        -- confined caller had ACCESS_SYSTEM_SECURITY taken out of it by
        -- step 11, so there is nothing left for step 12 to preserve.
        local sid = set_policy(t, 9402, { { effective_dacl = OVERSIZE_ACL } })
        local privs = { privs_present = SECURITY, privs_enabled = SECURITY }
        local sd = access.simple({ grant(STD.GENERIC_ALL, E) },
            { sacl = access.acl({ scoped_ace(sid) }) })
        local plain = as_subject(privs, sd, STD.ACCESS_SYSTEM_SECURITY)
        local confined = as_subject({ privs_present = SECURITY, privs_enabled = SECURITY,
            confinement_sid = CONF }, sd, STD.ACCESS_SYSTEM_SECURITY)
        drop(sid)
        t:log(string.format("unconfined ret=%d %s, confined ret=%d %s", plain.ret,
            sys.errname(plain.errno or 0), confined.ret, sys.errname(confined.errno or 0)))
        t:assert(plain.ok, "the failed rule preserves the privilege-granted right: "
            .. sys.errname(plain.errno or 0))
        t:assert(confined.denied,
            "and a bit the confinement intersection removed is no longer part of the set: ret="
            .. confined.ret .. " " .. sys.errname(confined.errno or 0))
    end)

test("in result-list mode a scalar staged delta sets the mismatch flag even when no node differs",
    { spec = "PKM *check.algorithm.scalar-delta-sets-flag" }, function(t)
        -- Both the effective and the staged rule DACL fail to evaluate.
        -- The effective error path contributes privilege_granted to both
        -- the scalar total and every node; the staged one contributes
        -- zero to the scalar total and privilege_granted to every node.
        -- The per-node lists therefore agree and the scalar totals do not.
        local sid = set_policy(t, 9403,
            { { effective_dacl = OVERSIZE_ACL, staged_dacl = OVERSIZE_ACL } })
        local sd = access.simple({ grant(STD.GENERIC_ALL, E) },
            { sacl = access.acl({ scoped_ace(sid) }) })
        local r
        local events = recording(function()
            r = as_subject_list({ privs_present = SECURITY, privs_enabled = SECURITY },
                sd, STD.ACCESS_SYSTEM_SECURITY, FLAT)
        end)
        drop(sid)
        local diags = of(events, "caap-policy-diagnostic")
        t:log(string.format("ret=%d sm=%d nodes 0x%x/0x%x/0x%x diagnostics=%d",
            r.ret, r.staging_mismatch, r.nodes[1].granted, r.nodes[2].granted,
            r.nodes[3].granted, #diags))
        for i = 1, 3 do
            t:assert_eq(r.nodes[i].granted, STD.ACCESS_SYSTEM_SECURITY,
                "node " .. i .. " keeps the privilege-granted right")
        end
        t:assert_eq(#diags, 1, "one staging diagnostic")
        t:assert_eq(diags[1].payload.object_results_differ, false,
            "reporting that no per-node result differs")
        t:assert_eq(diags[1].payload.effective_granted_access, STD.ACCESS_SYSTEM_SECURITY,
            "while the effective scalar total holds the right")
        t:assert_eq(diags[1].payload.staged_granted_access, 0, "and the staged scalar total is empty")
        t:assert_eq(r.staging_mismatch, 1,
            "the comparison is not mode-branched, so the scalar delta alone sets the flag")
    end)

test("privilege-use folds across nodes: success on any node, failure only on none",
    { spec = "PKM *check.algorithm.privilege-use-folds-across-nodes" }, function(t)
        -- A confined token whose confinement pass reaches an object ACE
        -- scoped to child A alone.
        local function run(dacl)
            local out, events
            events = recording(function()
                out = as_subject_list({ privs_present = BACKUP, privs_enabled = BACKUP,
                    confinement_sid = CONF,
                    audit_policy = POLICY.PRIVILEGE_USE_SUCCESS | POLICY.PRIVILEGE_USE_FAILURE },
                    access.simple(dacl), READ, FLAT, { intent = access.INTENT.BACKUP })
            end)
            return out, of(events, "privilege-use")
        end
        local some, ev_some = run({ access.ace(access.ACE.ALLOWED_OBJECT, READ, CONF, 0,
            { object_type = A }) })
        local none, ev_none = run({ grant(READ, E) })
        t:log(string.format("one node: 0x%x/0x%x/0x%x success=%s; no node: 0x%x/0x%x/0x%x success=%s",
            some.nodes[1].granted, some.nodes[2].granted, some.nodes[3].granted,
            tostring(ev_some[1] and ev_some[1].payload.success),
            none.nodes[1].granted, none.nodes[2].granted, none.nodes[3].granted,
            tostring(ev_none[1] and ev_none[1].payload.success)))
        t:assert_eq(some.nodes[2].granted, READ, "the bits survive on one node")
        t:assert_eq(some.nodes[1].granted, 0, "and on no other")
        t:assert_eq(#ev_some, 1, "one privilege-use event")
        t:assert_eq(ev_some[1].payload.success, true, "folded to success across the nodes")
        t:assert_eq(#ev_none, 1, "one event where they survive nowhere")
        t:assert_eq(ev_none[1].payload.success, false, "folded to failure")
    end)

test("step 14 walks the object's SACL and then each CAAP effective SACL",
    { spec = "PKM *check.algorithm.sacl-walk-order" }, function(t)
        local object_ace = audit_ace(READ, E, SUCCESS_FLAG)
        local policy_ace = audit_ace(WRITE, E, SUCCESS_FLAG)
        local sid = set_policy(t, 9404, {
            { effective_dacl = access.acl({ grant(STD.GENERIC_ALL, E) }),
              effective_sacl = access.acl({ policy_ace, alarm_ace(EXEC, E, 0) }) } })
        local sd = access.simple({ grant(STD.GENERIC_ALL, E) }, { sacl = access.acl({
            object_ace, alarm_ace(READ, E, 0), scoped_ace(sid) }) })
        local r
        local events = recording(function() r = as_subject({}, sd, READ | WRITE) end)
        drop(sid)
        local ev = of(events, "access-audit")
        t:log(string.format("ret=%d continuous=0x%x events=%d", r.ret, r.continuous_audit, #ev))
        t:assert(r.ok, "the request succeeds: " .. sys.errname(r.errno or 0))
        t:assert_eq(#ev, 2, "one event from each SACL")
        t:assert_eq(ev[1].payload.trigger.ace, object_ace, "the object's SACL is walked first")
        t:assert_eq(ev[2].payload.trigger.ace, policy_ace, "and the CAAP SACL after it")
        t:assert_eq(r.continuous_audit, READ | EXEC,
            "with the alarm masks from both ORed into the continuous audit mask")
    end)

test("the staged audit walk is driven by the staged granted total",
    { spec = "PKM *check.algorithm.staged-audit-walk-uses-staged-grant" }, function(t)
        -- The object's SACL carries a failure-audit ACE only. The
        -- effective result grants the request, so the effective walk
        -- emits nothing; the staged result does not, so the second walk
        -- classifies the same ACE as a failure.
        local sid = set_policy(t, 9405, {
            { effective_dacl = access.acl({ grant(READ | WRITE, E) }),
              staged_dacl = access.acl({ grant(READ, E) }),
              effective_sacl = access.acl({ alarm_ace(READ, E, 0) }) } })
        local sd = access.simple({ grant(READ | WRITE, E) }, { sacl = access.acl({
            audit_ace(READ | WRITE, E, FAILURE_FLAG), scoped_ace(sid) }) })
        local r
        local events = recording(function() r = as_subject({}, sd, READ | WRITE) end)
        drop(sid)
        local ev = of(events, "access-audit")
        t:log(string.format("ret=%d granted=0x%x sm=%d access-audit=%d", r.ret, r.granted,
            r.staging_mismatch, #ev))
        t:assert(r.ok, "the effective result grants the whole request: "
            .. sys.errname(r.errno or 0))
        t:assert_eq(#ev, 0,
            "so the effective SACL walk classes it a success and the failure ACE emits nothing")
        t:assert_eq(r.staging_mismatch, 1,
            "while the staged walk, run against the staged grant, classes it a failure")
    end)

-- The wrappers ---------------------------------------------------------------------------

test("AccessCheck allows the request when nothing was asked for or every requested bit is granted",
    { spec = "PKM *check.algorithm.allowed-computation" }, function(t)
        local sd = access.simple({ grant(READ, E) })
        local nothing = as_subject({}, sd, 0)
        local all_of_it = as_subject({}, sd, READ)
        local partly = as_subject({}, sd, READ | WRITE)
        -- With a tree present the wrapper takes the root node's mask.
        local tree_sd = access.simple({
            access.ace(access.ACE.DENIED_OBJECT, READ, E, 0, { object_type = B }),
            grant(READ, E) })
        local scalar = as_subject({}, tree_sd, READ, { tree = FLAT })
        local list = as_subject_list({}, tree_sd, READ, FLAT)
        t:log(string.format("nothing ret=%d granted=0x%x, all ret=%d, partial ret=%d %s; scalar ret=%d, root=0x%x",
            nothing.ret, nothing.granted, all_of_it.ret, partly.ret,
            sys.errname(partly.errno or 0), scalar.ret, list.nodes[1].granted))
        t:assert(nothing.ok, "a request naming nothing is allowed: "
            .. sys.errname(nothing.errno or 0))
        t:assert_eq(nothing.granted, 0, "with an empty granted mask")
        t:assert(all_of_it.ok, "so is one whose every bit is granted: "
            .. sys.errname(all_of_it.errno or 0))
        t:assert(partly.denied, "and one with a bit missing is not: ret=" .. partly.ret
            .. " " .. sys.errname(partly.errno or 0))
        t:assert_eq(scalar.granted, list.nodes[1].granted,
            "with a tree present the scalar wrapper returns the root node's mask")
        t:assert(scalar.denied, "which a descendant's denial has propagated into: ret="
            .. scalar.ret .. " " .. sys.errname(scalar.errno or 0))
    end)

test("neither wrapper filters the returned granted mask to what was requested",
    { spec = "PKM *check.algorithm.granted-not-filtered" }, function(t)
        -- Under the file mapping SeBackupPrivilege seeds a whole family of
        -- read rights; the caller asks for READ_CONTROL alone.
        local r = as_subject({ privs_present = BACKUP, privs_enabled = BACKUP },
            access.simple({}), STD.READ_CONTROL,
            { mapping = access.FILE_MAPPING, intent = access.INTENT.BACKUP })
        t:log(string.format("ret=%d granted=0x%x (requested 0x%x)", r.ret, r.granted,
            STD.READ_CONTROL))
        t:assert(r.ok, "the request succeeds: " .. sys.errname(r.errno or 0))
        t:assert_eq(r.granted, access.FILE_MAPPING.read,
            "and the caller sees every read bit the privilege seeded, not just the one it asked for")
    end)

test("the file enforcement path filters its result while the generic query path does not",
    { spec = "PKM *check.algorithm.file-path-filters-result" }, function(t)
        local dir = facs.workspace(vm, "algorithm")
        local path = dir .. "/filtered"
        facs.file(vm, path, "hello")
        local sd = access.sd({ owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
            dacl = access.acl({ grant(STD.GENERIC_ALL, E) }) })
        t:assert_eq(kacs.set_sd(vm, path, sd, kacs.SI.DACL).ret, 0, "the file grants everything")
        -- Opened natively for read data alone: the stamped mask is the
        -- filtered result, so a write is refused at use time.
        local fd = facs.handle(t, vm, path, kacs.RIGHT.READ_DATA | kacs.RIGHT.SYNCHRONIZE)
        local read = sys.read(vm, fd, 5)
        local write = vm:syscall(sys.NR.write, { args = { fd, 0, 3 }, bufs = { "abc" }, ptrs = { 1 } })
        sys.close(vm, fd)
        local query = access.check(vm, { sd = sd, desired = kacs.RIGHT.READ_DATA,
            mapping = access.FILE_MAPPING })
        t:log(string.format("read=%s write ret=%d %s; query granted=0x%x", tostring(read),
            write.ret, sys.errname(write.errno or 0), query.granted))
        t:assert_eq(read, "hello", "the right the open asked for works")
        t:assert(write.ret < 0, "and one it did not ask for does not: "
            .. sys.errname(write.errno or 0))
        t:assert(query.granted & ~kacs.RIGHT.READ_DATA ~= 0,
            string.format("while the query returns the unfiltered mask: 0x%x", query.granted))
    end)

-- Helpers -----------------------------------------------------------------------------

test("all four generic bits are cleared before any is expanded, so every one maps",
    { spec = "PKM *check.algorithm.all-generics-expand" }, function(t)
        local both = as_subject({}, access.simple({
            grant(STD.GENERIC_READ | STD.GENERIC_WRITE, E) }), STD.MAXIMUM_ALLOWED)
        local three = as_subject({}, access.simple({
            grant(STD.GENERIC_READ | STD.GENERIC_WRITE | STD.GENERIC_EXECUTE, E) }),
            STD.MAXIMUM_ALLOWED)
        local with_all = as_subject({}, access.simple({
            grant(STD.GENERIC_ALL | STD.GENERIC_READ, E) }), STD.MAXIMUM_ALLOWED)
        t:log(string.format("read|write=0x%x, read|write|execute=0x%x, all|read=0x%x",
            both.granted, three.granted, with_all.granted))
        t:assert_eq(both.granted, OBJ.read | OBJ.write, "two generics expand to both right sets")
        t:assert_eq(three.granted, OBJ.read | OBJ.write | OBJ.execute, "three to all three")
        t:assert_eq(with_all.granted, OBJ.all, "and GENERIC_ALL beside another is not swallowed")
    end)

test("S-1-5-10 is resolved per lookup, in the DACL walk, the SACL walk and conditional membership alike",
    { spec = "PKM *check.algorithm.virtual-groups-per-lookup" }, function(t)
        local sd = access.simple({
            grant(READ, PRINCIPAL_SELF),
            access.ace(access.ACE.ALLOWED_CALLBACK, WRITE, E, 0,
                { condition = member_of(PRINCIPAL_SELF) }),
        }, { sacl = access.acl({ audit_ace(READ, PRINCIPAL_SELF, SUCCESS_FLAG) }) })
        local matching, other
        local a = recording(function()
            matching = as_subject({}, sd, STD.MAXIMUM_ALLOWED, { self_sid = USER })
        end)
        local b = recording(function()
            other = as_subject({}, sd, STD.MAXIMUM_ALLOWED, { self_sid = G3 })
        end)
        t:log(string.format("self=USER granted=0x%x events=%d, self=G3 granted=0x%x events=%d",
            matching.granted, #of(a, "access-audit"), other.granted, #of(b, "access-audit")))
        t:assert_eq(matching.granted & READ, READ, "the DACL walk resolves it against self_sid")
        t:assert_eq(matching.granted & WRITE, WRITE, "so does conditional membership")
        t:assert_eq(#of(a, "access-audit"), 1, "and so does the SACL walk")
        t:assert_eq(other.granted, 0, "a self_sid the token does not match answers no everywhere")
        t:assert_eq(#of(b, "access-audit"), 0, "including in the SACL walk")
    end)

test("EvaluateSACL checks SID, object-type scoping, condition and mask overlap in that order",
    { spec = "PKM *check.algorithm.sacl-ace-check-order" }, function(t)
        local FALSE_COND = pad4("artx" .. int_lit(1) .. int_lit(2) .. string.pack("<I1", 0x80))
        local dacl = { grant(STD.GENERIC_ALL, E) }
        local function count(sacl_ace, tree)
            local n
            local events = recording(function()
                as_subject({}, access.simple(dacl, { sacl = access.acl({ sacl_ace }) }),
                    READ, { tree = tree })
            end)
            n = #of(events, "access-audit")
            return n
        end
        local passes = count(audit_ace(READ, E, SUCCESS_FLAG))
        local bad_sid = count(audit_ace(READ, G3, SUCCESS_FLAG))
        local bad_scope = count(access.ace(access.ACE.AUDIT_OBJECT, READ, E, SUCCESS_FLAG,
            { object_type = guid(9) }), FLAT)
        local good_scope = count(access.ace(access.ACE.AUDIT_OBJECT, READ, E, SUCCESS_FLAG,
            { object_type = A }), FLAT)
        local bad_condition = count(access.ace(AUDIT_CALLBACK, READ, E, SUCCESS_FLAG,
            { condition = FALSE_COND }))
        local no_overlap = count(audit_ace(EXEC, E, SUCCESS_FLAG))
        -- The alarm branch stops before the fourth check, which is what
        -- makes the overlap test a separable final step.
        local alarm
        local events = recording(function()
            alarm = as_subject({}, access.simple(dacl,
                { sacl = access.acl({ alarm_ace(EXEC, E, 0) }) }), READ)
        end)
        t:log(string.format("all four=%d, SID=%d, scope=%d/%d, condition=%d, overlap=%d, alarm mask=0x%x",
            passes, bad_sid, bad_scope, good_scope, bad_condition, no_overlap,
            alarm.continuous_audit))
        t:assert_eq(passes, 1, "an ACE passing all four checks emits")
        t:assert_eq(bad_sid, 0, "the SID match is the first gate")
        t:assert_eq(bad_scope, 0, "object-type scoping against the tree is the second")
        t:assert_eq(good_scope, 1, "which the same ACE naming a listed GUID passes")
        t:assert_eq(bad_condition, 0, "the condition is the third")
        t:assert_eq(no_overlap, 0, "and the mask overlap the fourth")
        t:assert_eq(alarm.continuous_audit, EXEC,
            "an alarm ACE deliberately skips that fourth check")
    end)

test("inherit-only ACEs are skipped throughout the SACL walk",
    { spec = "PKM *check.algorithm.sacl-inherit-only-skipped" }, function(t)
        local INHERIT_ONLY = access.ACE_FLAG.INHERIT_ONLY
        local dacl = { grant(STD.GENERIC_ALL, E) }
        local applied, skipped
        local a = recording(function()
            applied = as_subject({}, access.simple(dacl, { sacl = access.acl({
                audit_ace(READ, E, SUCCESS_FLAG), alarm_ace(WRITE, E, 0) }) }), READ)
        end)
        local b = recording(function()
            skipped = as_subject({}, access.simple(dacl, { sacl = access.acl({
                audit_ace(READ, E, SUCCESS_FLAG | INHERIT_ONLY),
                alarm_ace(WRITE, E, INHERIT_ONLY) }) }), READ)
        end)
        t:log(string.format("ordinary events=%d mask=0x%x, inherit-only events=%d mask=0x%x",
            #of(a, "access-audit"), applied.continuous_audit,
            #of(b, "access-audit"), skipped.continuous_audit))
        t:assert_eq(#of(a, "access-audit"), 1, "the ordinary audit ACE emits")
        t:assert_eq(applied.continuous_audit, WRITE, "and the ordinary alarm ACE contributes")
        t:assert_eq(#of(b, "access-audit"), 0, "the inherit-only audit ACE does not")
        t:assert_eq(skipped.continuous_audit, 0, "nor does the inherit-only alarm ACE")
    end)

test("a CAAP rule's synthetic descriptor recomputes its control bits rather than copying them",
    { spec = "PKM *check.algorithm.synthetic-recomputes-control-bits" }, function(t)
        -- The object has no DACL at all, so SE_DACL_PRESENT is clear on
        -- the original. If the rule's descriptor inherited that bit the
        -- rule's substituted DACL would read as absent, which grants
        -- everything, and the intersection would not narrow.
        local sid = set_policy(t, 9406, { { effective_dacl = access.acl({ grant(READ, E) }) } })
        local sd = access.sd({ owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
            sacl = access.acl({ scoped_ace(sid) }) })
        local governed = as_subject({}, sd, STD.MAXIMUM_ALLOWED)
        drop(sid)
        local ungoverned = as_subject({}, access.sd({ owner = token.SID.LOCAL_SYSTEM,
            group = token.SID.LOCAL_SYSTEM }), STD.MAXIMUM_ALLOWED)
        t:log(string.format("with the policy granted=0x%x, without granted=0x%x",
            governed.granted, ungoverned.granted))
        t:assert_eq(ungoverned.granted, OBJ.all, "a null DACL on its own grants every valid right")
        t:assert_eq(governed.granted, READ,
            "and the rule's DACL is evaluated as present, narrowing the result to what it grants")
    end)

-- Provenance -----------------------------------------------------------------------------

--- Run one privilege-use accounting case and return its single event.
local function provenance_event(t, spec, sd, desired, opts)
    opts = opts or {}
    local fresh = { audit_policy = POLICY.PRIVILEGE_USE_SUCCESS | POLICY.PRIVILEGE_USE_FAILURE }
    for k, v in pairs(spec) do fresh[k] = v end
    local r
    local events = recording(function() r = as_subject(fresh, sd, desired, opts) end)
    local ev = of(events, "privilege-use")
    t:assert_eq(#ev, 1, "one privilege-use event")
    return r, ev[1].payload
end

test("security_granted records the ACCESS_SYSTEM_SECURITY that SeSecurityPrivilege granted",
    { spec = "PKM *check.algorithm.provenance.security" }, function(t)
        local r, p = provenance_event(t, { privs_present = SECURITY, privs_enabled = SECURITY },
            access.simple({}), STD.ACCESS_SYSTEM_SECURITY)
        t:log(string.format("ret=%d privilege=%s requested=0x%x surviving=0x%x", r.ret,
            p.privilege, p.requested_access, p.surviving_access))
        t:assert(r.ok, "the privilege grants the right: " .. sys.errname(r.errno or 0))
        t:assert_eq(p.privilege, "SeSecurityPrivilege", "the event names the privilege")
        t:assert_eq(p.requested_access, STD.ACCESS_SYSTEM_SECURITY,
            "and the provenance mask meeting the request is ACCESS_SYSTEM_SECURITY")
        t:assert_eq(p.success, true, "which survived into the result")
    end)

test("backup_granted records the read bits SeBackupPrivilege granted",
    { spec = "PKM *check.algorithm.provenance.backup" }, function(t)
        local r, p = provenance_event(t, { privs_present = BACKUP, privs_enabled = BACKUP },
            access.simple({}), OBJ.read, { intent = access.INTENT.BACKUP })
        t:log(string.format("ret=%d privilege=%s requested=0x%x", r.ret, p.privilege,
            p.requested_access))
        t:assert(r.ok, "the privilege grants the read right: " .. sys.errname(r.errno or 0))
        t:assert_eq(p.privilege, "SeBackupPrivilege", "the event names the privilege")
        t:assert_eq(p.requested_access, OBJ.read,
            "and the provenance mask is MapGenericBits(GENERIC_READ)")
    end)

test("restore_granted records the write and metadata bits SeRestorePrivilege granted",
    { spec = "PKM *check.algorithm.provenance.restore" }, function(t)
        local wanted = OBJ.write | STD.WRITE_DAC | STD.WRITE_OWNER | STD.DELETE
        local r, p = provenance_event(t, { privs_present = RESTORE, privs_enabled = RESTORE },
            access.simple({}), wanted, { intent = access.INTENT.RESTORE })
        t:log(string.format("ret=%d privilege=%s requested=0x%x", r.ret, p.privilege,
            p.requested_access))
        t:assert(r.ok, "the privilege grants them: " .. sys.errname(r.errno or 0))
        t:assert_eq(p.privilege, "SeRestorePrivilege", "the event names the privilege")
        t:assert_eq(p.requested_access, wanted,
            "and the provenance covers the write bits together with WRITE_DAC, WRITE_OWNER and DELETE")
    end)

test("take_ownership_granted records the WRITE_OWNER step 9 supplied",
    { spec = "PKM *check.algorithm.provenance.take-ownership" }, function(t)
        local r, p = provenance_event(t,
            { privs_present = TAKE_OWNERSHIP, privs_enabled = TAKE_OWNERSHIP },
            access.simple({}), STD.WRITE_OWNER)
        t:log(string.format("ret=%d privilege=%s requested=0x%x", r.ret, p.privilege,
            p.requested_access))
        t:assert(r.ok, "the privilege grants WRITE_OWNER: " .. sys.errname(r.errno or 0))
        t:assert_eq(p.privilege, "SeTakeOwnershipPrivilege", "the event names the privilege")
        t:assert_eq(p.requested_access, STD.WRITE_OWNER, "and the provenance is that one bit")
    end)

test("relabel_granted records the WRITE_OWNER SeRelabelPrivilege added to the MIC allowed set",
    { spec = "PKM *check.algorithm.provenance.relabel" }, function(t)
        -- A Low caller against a High object: MIC would decide WRITE_OWNER
        -- denied, so the DACL's grant could not take effect.
        local sd = access.simple({ grant(STD.WRITE_OWNER, E) }, { sacl = access.acl({
            access.label_ace(token.INTEGRITY.HIGH, access.LABEL.NO_WRITE_UP) }) })
        local low = { integrity_level = token.INTEGRITY.LOW }
        local without = as_subject(low, sd, STD.WRITE_OWNER)
        local r, p = provenance_event(t, { integrity_level = token.INTEGRITY.LOW,
            privs_present = RELABEL, privs_enabled = RELABEL }, sd, STD.WRITE_OWNER)
        t:log(string.format("without ret=%d %s, with ret=%d privilege=%s requested=0x%x",
            without.ret, sys.errname(without.errno or 0), r.ret, p.privilege, p.requested_access))
        t:assert(without.denied, "without the privilege MIC decides WRITE_OWNER: ret="
            .. without.ret .. " " .. sys.errname(without.errno or 0))
        t:assert(r.ok, "with it the DACL's grant takes effect: " .. sys.errname(r.errno or 0))
        t:assert_eq(p.privilege, "SeRelabelPrivilege", "the event names the privilege")
        t:assert_eq(p.requested_access, STD.WRITE_OWNER,
            "and the provenance is the WRITE_OWNER it loosened")
    end)
