-- PKM §3.8.7 — PIP inside AccessCheck: the trust label ACE an object
-- opts in with, the dominance test, the ACE mask as the whole allowed
-- set for a non-dominant caller, the privilege revocation that makes it
-- an absolute boundary, and where the two axes come from.
--
-- The agent's own PSB carries pip_type 0 and pip_trust 0 — nothing in
-- the profile is signed — so a case that wants a dominant caller
-- supplies the axes through the query's arguments.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local access = require("helpers.access")
local kmes = require("helpers.kmes")
local facs = require("helpers.facs")

local vm = provium:vm("v", "kernel-only"):boot()

local STD = access.STD
local E = token.SID.EVERYONE
local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED

--- A synthetic object type whose read, write and execute rights are three
--- disjoint bits. `all` is the whole valid right set, and
--- ACCESS_SYSTEM_SECURITY is deliberately outside it.
local OBJ = { read = 0x1, write = 0x2, execute = 0x4,
    all = 0x7 | STD.DELETE | STD.READ_CONTROL | STD.WRITE_DAC | STD.WRITE_OWNER | STD.SYNCHRONIZE }
local READ, WRITE = 0x1, 0x2
local ALLOW = access.ACE.ALLOWED
local BACKUP, SECURITY = token.bit(token.PRIV.BACKUP), token.bit(token.PRIV.SECURITY)

--- Check `desired` against `sd` as a freshly minted subject built from
--- `spec`. The spec is copied because `token.mint` stamps the session it
--- creates into it, and a reused spec would name a session that has gone.
local function as_subject(spec, sd, desired, opts)
    opts = opts or {}
    local fresh = { groups = { { sid = E, attributes = ENABLED } } }
    for k, v in pairs(spec or {}) do fresh[k] = v end
    local fd, e = token.mint(vm, fresh)
    assert(fd, "mint: " .. sys.errname(e or 0))
    local r = access.check(vm, { token_fd = fd, sd = sd, desired = desired, mapping = OBJ,
        pip_type = opts.pip_type, pip_trust = opts.pip_trust, intent = opts.intent,
        audit_context = opts.audit_context })
    sys.close(vm, fd)
    return r
end

--- A descriptor whose DACL grants everything to Everyone, carrying
--- `sacl` (or none). Whatever PIP blocks, the DACL was willing to give.
local function open_sd(sacl)
    return access.simple({ access.ace(ALLOW, STD.GENERIC_ALL, E) }, { sacl = sacl })
end
--- The same, labelled with one trust label ACE.
local function labelled(pip_type, pip_trust, mask, flags)
    return open_sd(access.acl({ access.trust_label_ace(pip_type, pip_trust, mask, flags) }))
end

test("an object opts in to PIP by carrying a trust label ACE in its SACL",
    { spec = "PKM *check.pip.opt-in-via-sacl-ace" }, function(t)
        local bare = as_subject({}, open_sd(nil), READ)
        local other_sacl = as_subject({}, open_sd(access.acl({
            access.ace(access.ACE.AUDIT, READ, E, access.ACE_FLAG.SUCCESSFUL_ACCESS) })), READ)
        local opted_in = as_subject({}, labelled(512, 512, 0), READ)
        t:log(string.format("no SACL ret=%d, SACL without a label ret=%d, labelled ret=%d %s",
            bare.ret, other_sacl.ret, opted_in.ret, sys.errname(opted_in.errno or 0)))
        t:assert(bare.ok, "an object with no SACL is unconstrained: " .. sys.errname(bare.errno or 0))
        t:assert(other_sacl.ok, "and so is one whose SACL carries no trust label: "
            .. sys.errname(other_sacl.errno or 0))
        t:assert(opted_in.denied, "the label ACE is what turns PIP on: ret=" .. opted_in.ret
            .. " " .. sys.errname(opted_in.errno or 0))
    end)

test("a caller dominates only when both axes are greater than or equal to the ACE's",
    { spec = "PKM *check.pip.ace-dominance-test" }, function(t)
        -- The label requires type 512 and trust 512; the mask is empty,
        -- so a non-dominant caller gets nothing at all.
        local sd = labelled(512, 512, 0)
        local corners = {
            { 512, 512, true, "equal on both axes" },
            { 1024, 1024, true, "greater on both axes" },
            { 1024, 256, false, "greater type, lower trust" },
            { 256, 1024, false, "lower type, greater trust" },
            { 256, 256, false, "lower on both axes" },
        }
        for _, c in ipairs(corners) do
            local r = as_subject({}, sd, READ, { pip_type = c[1], pip_trust = c[2] })
            t:log(string.format("(%d,%d) ret=%d %s", c[1], c[2], r.ret, sys.errname(r.errno or 0)))
            if c[3] then
                t:assert(r.ok, c[4] .. " dominates: " .. sys.errname(r.errno or 0))
            else
                t:assert(r.denied, c[4] .. " does not dominate: ret=" .. r.ret .. " "
                    .. sys.errname(r.errno or 0))
            end
        end
    end)

test("a non-dominant caller is limited to the ACE's mask and denied everything else",
    { spec = "PKM *check.pip.non-dominant-limited-to-ace-mask" }, function(t)
        -- The DACL grants everything; the label allows the read bit alone.
        local sd = labelled(512, 512, READ)
        local max = as_subject({}, sd, STD.MAXIMUM_ALLOWED, { pip_type = 1, pip_trust = 1 })
        local r = as_subject({}, sd, READ, { pip_type = 1, pip_trust = 1 })
        local w = as_subject({}, sd, WRITE, { pip_type = 1, pip_trust = 1 })
        local dominant = as_subject({}, sd, STD.MAXIMUM_ALLOWED, { pip_type = 512, pip_trust = 512 })
        t:log(string.format("non-dominant granted=0x%x (read ret=%d, write ret=%d %s), dominant granted=0x%x",
            max.granted, r.ret, w.ret, sys.errname(w.errno or 0), dominant.granted))
        t:assert_eq(max.granted, READ, "the ACE mask is the whole allowed set")
        t:assert(r.ok, "the right it names is still available: " .. sys.errname(r.errno or 0))
        t:assert(w.denied, "and everything else is denied: ret=" .. w.ret .. " "
            .. sys.errname(w.errno or 0))
        t:assert_eq(dominant.granted, OBJ.all, "while a dominant caller is unrestricted")
    end)

test("PIP has no default: an unlabelled object is reachable whatever the caller's PIP identity",
    { spec = "PKM *check.pip.no-default" }, function(t)
        -- Unlike MIC, which treats an unlabelled object as Medium.
        local sd = open_sd(nil)
        for _, axes in ipairs({ { 0, 0 }, { 1, 1 }, { 1024, 1024 } }) do
            local r = as_subject({}, sd, STD.MAXIMUM_ALLOWED,
                { pip_type = axes[1], pip_trust = axes[2] })
            t:log(string.format("(%d,%d) granted=0x%x", axes[1], axes[2], r.granted))
            t:assert_eq(r.granted, OBJ.all, string.format(
                "a caller at (%d,%d) is unrestricted by an object with no trust label",
                axes[1], axes[2]))
        end
    end)

test("the label SID is S-1-19-{type}-{trust}: the first sub-authority is the type, the second the trust",
    { spec = "PKM *check.pip.label-sid-shape" }, function(t)
        -- Asymmetric axes, so swapping the caller's two values flips the
        -- verdict and pins which sub-authority is which.
        local sd = labelled(5, 9, 0)
        local right_way = as_subject({}, sd, READ, { pip_type = 5, pip_trust = 9 })
        local swapped = as_subject({}, sd, READ, { pip_type = 9, pip_trust = 5 })
        t:log(string.format("(5,9) ret=%d, (9,5) ret=%d %s", right_way.ret, swapped.ret,
            sys.errname(swapped.errno or 0)))
        t:assert(right_way.ok, "type 5 and trust 9 dominate S-1-19-5-9: "
            .. sys.errname(right_way.errno or 0))
        t:assert(swapped.denied,
            "and exchanging the two values does not, so the order of the sub-authorities is load-bearing: ret="
            .. swapped.ret .. " " .. sys.errname(swapped.errno or 0))
    end)

test("a non-standard numeric type is valid and compared by the same dominance rule",
    { spec = "PKM *check.pip.nonstandard-type-accepted" }, function(t)
        -- 7777 is none of None (0), Protected (512) or Isolated (1024).
        local sd = labelled(7777, 3, 0)
        local below = as_subject({}, sd, READ, { pip_type = 7776, pip_trust = 3 })
        local equal = as_subject({}, sd, READ, { pip_type = 7777, pip_trust = 3 })
        local above = as_subject({}, sd, READ, { pip_type = 7778, pip_trust = 3 })
        t:log(string.format("7776 ret=%d %s, 7777 ret=%d, 7778 ret=%d", below.ret,
            sys.errname(below.errno or 0), equal.ret, above.ret))
        t:assert(below.denied, "type 7776 does not dominate type 7777: ret=" .. below.ret
            .. " " .. sys.errname(below.errno or 0))
        t:assert(equal.ok and above.ok,
            "while 7777 and 7778 do — the axis is numeric, not a closed enum")
    end)

test("a trust label SID of the wrong shape makes the descriptor malformed and aborts the check",
    { spec = "PKM *check.pip.malformed-label-rejects-descriptor" }, function(t)
        local function labelled_with(sid)
            return open_sd(access.acl({ access.ace(access.ACE.PROCESS_TRUST_LABEL, 0, sid) }))
        end
        local three = as_subject({}, labelled_with(token.sid(19, 512, 512, 1)), READ)
        local one = as_subject({}, labelled_with(token.sid(19, 512)), READ)
        local wrong_authority = as_subject({}, labelled_with(token.sid(5, 512, 512)), READ)
        t:log(string.format("three sub-authorities ret=%d %s, one ret=%d %s, authority 5 ret=%d %s",
            three.ret, sys.errname(three.errno or 0), one.ret, sys.errname(one.errno or 0),
            wrong_authority.ret, sys.errname(wrong_authority.errno or 0)))
        for _, c in ipairs({ { three, "three sub-authorities" }, { one, "one sub-authority" },
                { wrong_authority, "the wrong identifier authority" } }) do
            t:assert(c[1].ret < 0, c[2] .. " is refused")
            t:assert(c[1].errno ~= sys.E.ACCES, c[2]
                .. " is rejected as a malformed descriptor rather than as a denial: "
                .. sys.errname(c[1].errno or 0))
        end
    end)

test("only the first non-inherit-only trust label applies to the object carrying it",
    { spec = "PKM *check.pip.first-non-inherit-only-label" }, function(t)
        local INHERIT_ONLY = access.ACE_FLAG.INHERIT_ONLY
        -- Two labels: a strict one and a permissive one. Which applies is
        -- the whole question.
        local strict_first = open_sd(access.acl({
            access.trust_label_ace(512, 512, 0),
            access.trust_label_ace(0, 0, STD.GENERIC_ALL) }))
        local strict_inherit_only = open_sd(access.acl({
            access.trust_label_ace(512, 512, 0, INHERIT_ONLY),
            access.trust_label_ace(0, 0, STD.GENERIC_ALL) }))
        local a = as_subject({}, strict_first, READ, { pip_type = 1, pip_trust = 1 })
        local b = as_subject({}, strict_inherit_only, READ, { pip_type = 1, pip_trust = 1 })
        t:log(string.format("strict first ret=%d %s, strict inherit-only ret=%d", a.ret,
            sys.errname(a.errno or 0), b.ret))
        t:assert(a.denied, "the first label in the SACL is the one used: ret=" .. a.ret
            .. " " .. sys.errname(a.errno or 0))
        t:assert(b.ok,
            "marking it inherit-only takes it out of play and the next label applies: "
            .. sys.errname(b.errno or 0))
    end)

test("PIP revokes rights a privilege had already granted",
    { spec = "PKM *check.pip.revokes-privilege-granted" }, function(t)
        -- An empty DACL, so the read bits can only have come from
        -- SeBackupPrivilege's seeding at step 4.
        local privs = { privs_present = BACKUP, privs_enabled = BACKUP }
        local unlabelled = access.simple({})
        local sd = access.simple({}, { sacl = access.acl({ access.trust_label_ace(512, 512, 0) }) })
        local plain = as_subject(privs, unlabelled, READ, { intent = access.INTENT.BACKUP })
        local dominant = as_subject(privs, sd, READ,
            { intent = access.INTENT.BACKUP, pip_type = 512, pip_trust = 512 })
        local stripped = as_subject(privs, sd, READ,
            { intent = access.INTENT.BACKUP, pip_type = 1, pip_trust = 1 })
        t:log(string.format("no label ret=%d, dominant ret=%d, non-dominant ret=%d %s",
            plain.ret, dominant.ret, stripped.ret, sys.errname(stripped.errno or 0)))
        t:assert(plain.ok, "SeBackupPrivilege grants read against an empty DACL: "
            .. sys.errname(plain.errno or 0))
        t:assert(dominant.ok, "and keeps it for a dominant caller: "
            .. sys.errname(dominant.errno or 0))
        t:assert(stripped.denied,
            "while a non-dominant caller has the privilege-granted bits taken back: ret="
            .. stripped.ret .. " " .. sys.errname(stripped.errno or 0))
    end)

test("the enforcement step ORs ACCESS_SYSTEM_SECURITY into what it can take away",
    { spec = "PKM *check.pip.revokes-access-system-security" }, function(t)
        -- The ACE mask is GENERIC_ALL, which maps to every right the
        -- object type defines — and ACCESS_SYSTEM_SECURITY is outside the
        -- mapping, so only the explicit OR removes it.
        local privs = { privs_present = SECURITY, privs_enabled = SECURITY }
        local sd = open_sd(access.acl({ access.trust_label_ace(512, 512, STD.GENERIC_ALL) }))
        local dominant = as_subject(privs, sd, STD.ACCESS_SYSTEM_SECURITY,
            { pip_type = 512, pip_trust = 512 })
        local non_dominant = as_subject(privs, sd, STD.ACCESS_SYSTEM_SECURITY,
            { pip_type = 1, pip_trust = 1 })
        local rest = as_subject(privs, sd, STD.MAXIMUM_ALLOWED, { pip_type = 1, pip_trust = 1 })
        t:log(string.format("dominant ret=%d, non-dominant ret=%d %s, accumulated=0x%x",
            dominant.ret, non_dominant.ret, sys.errname(non_dominant.errno or 0), rest.granted))
        t:assert(dominant.ok, "SeSecurityPrivilege reaches the SACL when the caller dominates: "
            .. sys.errname(dominant.errno or 0))
        t:assert(non_dominant.denied,
            "a GENERIC_ALL label mask still leaves ACCESS_SYSTEM_SECURITY denied: ret="
            .. non_dominant.ret .. " " .. sys.errname(non_dominant.errno or 0))
        t:assert_eq(rest.granted & STD.ACCESS_SYSTEM_SECURITY, 0,
            "and it is absent from the accumulated mask")
        t:assert_eq(rest.granted, OBJ.all, "while every mapped right the ACE named survives")
    end)

test("EnforcePIP maps the ACE mask through the caller's GenericMapping to build the allowed set",
    { spec = "PKM *check.pip.algorithm" }, function(t)
        -- One label ACE carrying GENERIC_READ, evaluated under two
        -- different mappings: the allowed set is whatever that mapping
        -- makes of the generic bit.
        local sd = labelled(512, 512, STD.GENERIC_READ)
        local fd = assert(token.mint(vm, { groups = { { sid = E, attributes = ENABLED } } }))
        local synthetic = access.check(vm, { token_fd = fd, sd = sd, desired = STD.MAXIMUM_ALLOWED,
            mapping = OBJ, pip_type = 1, pip_trust = 1 })
        local file = access.check(vm, { token_fd = fd, sd = sd, desired = STD.MAXIMUM_ALLOWED,
            mapping = access.FILE_MAPPING, pip_type = 1, pip_trust = 1 })
        t:log(string.format("synthetic granted=0x%x (read=0x%x), file granted=0x%x (read=0x%x)",
            synthetic.granted, OBJ.read, file.granted, access.FILE_MAPPING.read))
        t:assert_eq(synthetic.granted, OBJ.read,
            "the non-dominant caller keeps exactly the synthetic type's read rights")
        t:assert_eq(file.granted, access.FILE_MAPPING.read,
            "and the file type's read rights under the file mapping")
        sys.close(vm, fd)
    end)

test("the two axes are parameters, not a token field: one token gives two verdicts",
    { spec = "PKM *check.pip.values-are-parameters" }, function(t)
        local fd = assert(token.mint(vm, { groups = { { sid = E, attributes = ENABLED } } }))
        local sd = labelled(512, 512, 0)
        local low = access.check(vm, { token_fd = fd, sd = sd, desired = READ, mapping = OBJ,
            pip_type = 1, pip_trust = 1 })
        local high = access.check(vm, { token_fd = fd, sd = sd, desired = READ, mapping = OBJ,
            pip_type = 512, pip_trust = 512 })
        t:log(string.format("same token: (1,1) ret=%d %s, (512,512) ret=%d", low.ret,
            sys.errname(low.errno or 0), high.ret))
        t:assert(low.denied, "the very same token is non-dominant at (1,1): ret=" .. low.ret
            .. " " .. sys.errname(low.errno or 0))
        t:assert(high.ok, "and dominant at (512,512): " .. sys.errname(high.errno or 0))
        sys.close(vm, fd)
    end)

test("the enforcement path takes the axes from the subject's PSB, not from anything a caller supplies",
    { spec = "PKM *check.pip.enforcement-uses-psb" }, function(t)
        -- Nothing in the profile is signed, so the agent's PSB carries
        -- pip_type 0 and pip_trust 0 and it dominates nothing above zero.
        local dir = facs.workspace(vm, "pip")
        local path = dir .. "/labelled"
        facs.file(vm, path, "x")
        local sd = access.sd({
            owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
            dacl = access.acl({ access.ace(ALLOW, STD.GENERIC_ALL, E) }),
            sacl = access.acl({ access.trust_label_ace(512, 512, 0) }) })
        local set = kacs.set_sd(vm, path, sd, kacs.SI.DACL | kacs.SI.SACL)
        t:assert_eq(set.ret, 0, "the trust label is written onto the file: "
            .. sys.errname(set.errno or 0))
        local fd, errno = kacs.open(vm, path, { access = kacs.RIGHT.READ_DATA })
        if fd then sys.close(vm, fd) end
        t:log(string.format("native open fd=%s %s", tostring(fd), sys.errname(errno or 0)))
        t:assert(not fd, "opening it is refused: the enforcement point evaluated the PSB's zero axes")
        t:assert_eq(errno, sys.E.ACCES, "as a denial: " .. sys.errname(errno or 0))
        -- The same descriptor through the advisory query, where the
        -- caller may name a context, grants.
        local q = access.check(vm, { sd = sd, desired = access.FILE_MAPPING.read,
            mapping = access.FILE_MAPPING, pip_type = 512, pip_trust = 512 })
        t:assert(q.ok, "while the query, told to evaluate at (512,512), grants: "
            .. sys.errname(q.errno or 0))
    end)

test("the query takes each axis from its argument when non-zero and from the PSB when zero",
    { spec = "PKM *check.pip.query-supplies-values-per-axis" }, function(t)
        -- The agent's PSB is (0,0), so a zero argument on either axis
        -- falls back to a value that dominates nothing.
        local sd = labelled(512, 512, 0)
        local both = as_subject({}, sd, READ, { pip_type = 512, pip_trust = 512 })
        local type_only = as_subject({}, sd, READ, { pip_type = 512, pip_trust = 0 })
        local trust_only = as_subject({}, sd, READ, { pip_type = 0, pip_trust = 512 })
        t:log(string.format("both ret=%d, type only ret=%d %s, trust only ret=%d %s",
            both.ret, type_only.ret, sys.errname(type_only.errno or 0),
            trust_only.ret, sys.errname(trust_only.errno or 0)))
        t:assert(both.ok, "supplying both axes evaluates against the supplied context: "
            .. sys.errname(both.errno or 0))
        t:assert(type_only.denied,
            "leaving the trust axis zero falls back to the PSB's zero and loses dominance: ret="
            .. type_only.ret .. " " .. sys.errname(type_only.errno or 0))
        t:assert(trust_only.denied, "and so does leaving the type axis zero: ret="
            .. trust_only.ret .. " " .. sys.errname(trust_only.errno or 0))
    end)

test("the effective axes used for the verdict are the ones recorded in the event",
    { spec = "PKM *check.pip.same-values-for-verdict-and-event" }, function(t)
        local ring = assert(kmes.attach(vm, 0))
        local policy = token.AUDIT.OBJECT_ACCESS_SUCCESS | token.AUDIT.OBJECT_ACCESS_FAILURE
        local sd = labelled(1024, 1024, 0)
        kmes.drain(ring)
        local denied = as_subject({ audit_policy = policy }, sd, READ,
            { pip_type = 512, pip_trust = 512 })
        local a = kmes.of_type(kmes.drain(ring), "access-audit")
        local granted = as_subject({ audit_policy = policy }, sd, READ,
            { pip_type = 2048, pip_trust = 2048 })
        local b = kmes.of_type(kmes.drain(ring), "access-audit")
        kmes.detach(ring)
        t:log(string.format("denied ret=%d events=%d, granted ret=%d events=%d",
            denied.ret, #a, granted.ret, #b))
        t:assert(denied.denied, "(512,512) does not dominate a S-1-19-1024-1024 label: ret="
            .. denied.ret .. " " .. sys.errname(denied.errno or 0))
        t:assert_eq(#a, 1, "one forced access-audit event")
        t:assert_eq(a[1].payload.subject.pip_type, 512, "carrying the type used for the verdict")
        t:assert_eq(a[1].payload.subject.pip_trust, 512, "and the trust used for it")
        t:assert_eq(a[1].payload.success, false, "and the verdict it describes")
        t:assert(granted.ok, "(2048,2048) dominates: " .. sys.errname(granted.errno or 0))
        t:assert_eq(#b, 1, "one forced access-audit event")
        t:assert_eq(b[1].payload.subject.pip_type, 2048, "recording the other context")
        t:assert_eq(b[1].payload.subject.pip_trust, 2048, "on both axes")
        t:assert_eq(b[1].payload.success, true, "agreeing with the verdict again")
    end)

test("the record of which bits PIP decided is threaded through and exported but never read",
    { spec = "PKM *check.pip.decided-record-unconsumed",
      skip = "no coverage anywhere: this is a claim about the absence of " ..
             "a consumer. The value is carried in PipEnforcementState, " ..
             "PreSaclWalkState.pip_decided and AccessCheckCoreState." ..
             "pip_decided, and no ABI writeback, KMES payload field or " ..
             "enforcement branch reads it — which no guest syscall and " ..
             "no KUnit assertion can witness, only a source audit" },
    function(t) end)
