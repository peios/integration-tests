-- PKM §3.8.2 — the DACL walk: first-writer-wins, which SIDs an ACE
-- matches at each polarity, ACE-mask mapping, absent and empty DACLs,
-- the owner's implicit rights and their OWNER RIGHTS suppression, and
-- MAXIMUM_ALLOWED.
--
-- The agent is SYSTEM and would pass everything, so each case mints its
-- own subject with helpers/token and passes it as `token_fd`.

local sys = require("helpers.sys")
local token = require("helpers.token")
local access = require("helpers.access")

local vm = provium:vm("v", "kernel-only"):boot()

local STD = access.STD
local E, USER = token.SID.EVERYONE, token.SID.TEST_USER
local G2 = token.SID.TEST_GROUP_2
local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED

--- A synthetic object type whose read, write and execute rights are three
--- disjoint bits, so a case can tell which category a granted bit came
--- from. The standard rights live in `all` and in none of the three.
local OBJ = { read = 0x1, write = 0x2, execute = 0x4,
    all = 0x7 | STD.DELETE | STD.READ_CONTROL | STD.WRITE_DAC | STD.WRITE_OWNER | STD.SYNCHRONIZE }
local READ, WRITE, OUTSIDE = 0x1, 0x2, 0x8

local ALLOW, DENY = access.ACE.ALLOWED, access.ACE.DENIED

--- The one-SID `Member_of({sid})` conditional expression, padded so the
--- containing ACE keeps a size that is a multiple of four.
local function member_of(sid)
    local expr = "artx" .. string.pack("<I1I4", 0x51, #sid) .. sid .. string.pack("<I1", 0x89)
    return expr .. string.rep("\0", (-#expr) % 4)
end

--- Check `desired` against `sd` as a freshly minted subject built from
--- `spec`, under the synthetic mapping. Returns the result table. The
--- spec is copied because `token.mint` stamps the session it creates
--- into it, and a reused spec would name a session that has gone.
local function as_subject(spec, sd, desired, mapping)
    local fresh = {}
    for k, v in pairs(spec or {}) do fresh[k] = v end
    local fd, e = token.mint(vm, fresh)
    assert(fd, "mint: " .. sys.errname(e or 0))
    local r = access.check(vm, { token_fd = fd, sd = sd, desired = desired,
        mapping = mapping or OBJ })
    sys.close(vm, fd)
    return r
end

--- A descriptor owned by the minted subject (TEST_USER).
local function owned(dacl)
    return access.sd({ owner = USER, group = USER, dacl = dacl })
end

test("first-writer-wins: the first ACE to decide a bit fixes its outcome",
    { spec = "PKM *check.dacl.first-writer-wins" }, function(t)
        local allow_first = access.simple({ access.ace(ALLOW, READ, E), access.ace(DENY, READ, E) })
        local deny_first = access.simple({ access.ace(DENY, READ, E), access.ace(ALLOW, READ, E) })
        local a = as_subject({}, allow_first, READ)
        local d = as_subject({}, deny_first, READ)
        t:log(string.format("allow-then-deny ret=%d, deny-then-allow ret=%d %s", a.ret, d.ret,
            sys.errname(d.errno or 0)))
        t:assert(a.ok, "allow before deny grants: " .. sys.errname(a.errno or 0))
        t:assert_eq(a.ret, READ, "returning the right")
        t:assert(d.denied, "deny before allow refuses the same right: ret=" .. d.ret
            .. " " .. sys.errname(d.errno or 0))
    end)

test("an allow ACE grants only the rights not yet decided",
    { spec = "PKM *check.dacl.allow-grants-undecided" }, function(t)
        -- The read bit is decided by the deny ACE; the allow ACE that
        -- follows carries read and write and may only contribute write.
        local sd = access.simple({ access.ace(DENY, READ, E), access.ace(ALLOW, READ | WRITE, E) })
        local r = as_subject({}, sd, STD.MAXIMUM_ALLOWED)
        t:log(string.format("granted=0x%x", r.granted))
        t:assert_eq(r.granted & WRITE, WRITE, "the undecided bit is granted")
        t:assert_eq(r.granted & READ, 0, "and the already-decided bit is left alone")
    end)

test("a deny ACE marks its rights decided but not granted",
    { spec = "PKM *check.dacl.deny-marks-decided" }, function(t)
        -- If deny only refused rather than deciding, the allow ACE behind
        -- it would grant the bit back.
        local sd = access.simple({ access.ace(DENY, READ, E), access.ace(ALLOW, READ, E) })
        local max = as_subject({}, sd, STD.MAXIMUM_ALLOWED)
        t:log(string.format("granted=0x%x", max.granted))
        t:assert_eq(max.granted & READ, 0, "the denied bit is not granted by the later allow ACE")
        local r = as_subject({}, sd, READ)
        t:assert(r.denied, "and asking for it fails: ret=" .. r.ret .. " " .. sys.errname(r.errno or 0))
    end)

test("an allow ACE matches a group only when it is enabled and not deny-only",
    { spec = "PKM *check.dacl.allow-enabled-groups-only" }, function(t)
        local sd = access.simple({ access.ace(ALLOW, READ, G2) })
        local enabled = as_subject({ groups = { { sid = E, attributes = ENABLED },
            { sid = G2, attributes = ENABLED } } }, sd, READ)
        local deny_only = as_subject({ groups = { { sid = E, attributes = ENABLED },
            { sid = G2, attributes = token.GROUP.USE_FOR_DENY_ONLY } } }, sd, READ)
        t:log(string.format("enabled ret=%d, deny-only ret=%d %s", enabled.ret, deny_only.ret,
            sys.errname(deny_only.errno or 0)))
        t:assert(enabled.ok, "an enabled group matches the allow ACE: " .. sys.errname(enabled.errno or 0))
        t:assert(deny_only.denied, "a deny-only group does not: ret=" .. deny_only.ret
            .. " " .. sys.errname(deny_only.errno or 0))
    end)

test("a deny ACE matches a deny-only group whatever its enabled state",
    { spec = "PKM *check.dacl.deny-matches-deny-only" }, function(t)
        local sd = access.simple({ access.ace(DENY, READ, G2), access.ace(ALLOW, READ, E) })
        local r = as_subject({ groups = { { sid = E, attributes = ENABLED },
            { sid = G2, attributes = token.GROUP.USE_FOR_DENY_ONLY } } }, sd, READ)
        t:log(string.format("ret=%d %s", r.ret, sys.errname(r.errno or 0)))
        t:assert(r.denied, "the deny ACE matches through a deny-only, not-enabled group: ret="
            .. r.ret .. " " .. sys.errname(r.errno or 0))
    end)

test("a group that is neither enabled nor deny-only matches nothing",
    { spec = "PKM *check.dacl.inert-group" }, function(t)
        local inert = { groups = { { sid = E, attributes = ENABLED }, { sid = G2, attributes = 0 } } }
        local allowed = as_subject(inert, access.simple({ access.ace(ALLOW, READ, G2) }), READ)
        local denied = as_subject(inert, access.simple({ access.ace(DENY, READ, G2),
            access.ace(ALLOW, READ, E) }), READ)
        t:log(string.format("allow ret=%d %s, deny ret=%d", allowed.ret,
            sys.errname(allowed.errno or 0), denied.ret))
        t:assert(allowed.denied, "an inert group does not match an allow ACE: ret=" .. allowed.ret
            .. " " .. sys.errname(allowed.errno or 0))
        t:assert(denied.ok, "nor a deny ACE, so the later allow still grants: "
            .. sys.errname(denied.errno or 0))
    end)

test("a user_deny_only token's user SID matches deny ACEs and not allow ACEs",
    { spec = "PKM *check.dacl.user-deny-only" }, function(t)
        local udo = { groups = { { sid = E, attributes = ENABLED } }, user_deny_only = true }
        local allowed = as_subject(udo, access.simple({ access.ace(ALLOW, READ, USER) }), READ)
        local denied = as_subject(udo, access.simple({ access.ace(DENY, READ, USER),
            access.ace(ALLOW, READ, E) }), READ)
        local ordinary = as_subject({ groups = { { sid = E, attributes = ENABLED } } },
            access.simple({ access.ace(ALLOW, READ, USER) }), READ)
        t:log(string.format("deny-only allow ret=%d, deny ret=%d, ordinary allow ret=%d",
            allowed.ret, denied.ret, ordinary.ret))
        t:assert(ordinary.ok, "an ordinary token matches an allow ACE on its user SID: "
            .. sys.errname(ordinary.errno or 0))
        t:assert(allowed.denied, "a user_deny_only token does not: ret=" .. allowed.ret
            .. " " .. sys.errname(allowed.errno or 0))
        t:assert(denied.denied, "but still matches a deny ACE on it: ret=" .. denied.ret
            .. " " .. sys.errname(denied.errno or 0))
    end)

test("INHERIT_ONLY ACEs are skipped by the walk",
    { spec = "PKM *check.dacl.inherit-only-skipped" }, function(t)
        local sd = access.simple({
            access.ace(DENY, READ, E, access.ACE_FLAG.INHERIT_ONLY),
            access.ace(ALLOW, READ, E),
        })
        local r = as_subject({}, sd, READ)
        t:log(string.format("ret=%d %s", r.ret, sys.errname(r.errno or 0)))
        t:assert(r.ok, "the inherit-only deny does not decide the bit: " .. sys.errname(r.errno or 0))
        t:assert_eq(r.ret, READ, "so the allow ACE behind it grants the right")
    end)

test("each ACE's mask is mapped through the caller's GenericMapping",
    { spec = "PKM *check.dacl.ace-mask-mapped" }, function(t)
        local sd = access.simple({ access.ace(ALLOW, STD.GENERIC_READ, E) })
        local synthetic = as_subject({}, sd, STD.MAXIMUM_ALLOWED)
        local file = as_subject({}, sd, STD.MAXIMUM_ALLOWED, access.FILE_MAPPING)
        t:log(string.format("synthetic=0x%x file=0x%x", synthetic.granted, file.granted))
        t:assert_eq(synthetic.granted, OBJ.read,
            "GENERIC_READ in the ACE grants the synthetic type's read rights")
        t:assert_eq(file.granted, access.FILE_MAPPING.read,
            "and the same ACE grants the file type's read rights under the file mapping")
    end)

test("a descriptor with no DACL grants every valid right not already decided",
    { spec = "PKM *check.dacl.absent-grants-valid-rights" }, function(t)
        local sd = access.sd({ owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM })
        local r = as_subject({}, sd, STD.MAXIMUM_ALLOWED)
        t:log(string.format("granted=0x%x (all=0x%x)", r.granted, OBJ.all))
        t:assert_eq(r.granted, OBJ.all, "an absent DACL grants the object type's whole right set")
        local one = as_subject({}, sd, OBJ.write)
        t:assert(one.ok, "and a targeted request for one of them succeeds: "
            .. sys.errname(one.errno or 0))
    end)

test("the absent-DACL grant is bounded by MapGenericBits(GENERIC_ALL) rather than 0xFFFFFFFF",
    { spec = "PKM *check.dacl.absent-bounded-by-generic-all" }, function(t)
        local sd = access.sd({ owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM })
        local r = as_subject({}, sd, STD.MAXIMUM_ALLOWED)
        t:log(string.format("granted=0x%x outside=0x%x", r.granted, r.granted & ~OBJ.all))
        t:assert_eq(r.granted & ~OBJ.all, 0, "no bit outside the object type's valid rights is granted")
        local outside = as_subject({}, sd, OUTSIDE)
        t:assert(outside.denied, "and a right outside them is refused: ret=" .. outside.ret
            .. " " .. sys.errname(outside.errno or 0))
    end)

test("a present but empty DACL grants nothing",
    { spec = "PKM *check.dacl.empty-grants-nothing" }, function(t)
        -- Owned by SYSTEM, which the subject is not, so the owner implicit
        -- rights do not muddy the result.
        local sd = access.simple({})
        local r = as_subject({}, sd, STD.MAXIMUM_ALLOWED)
        t:log(string.format("ret=%d granted=0x%x", r.ret, r.granted))
        t:assert(r.ok, "a pure MAXIMUM_ALLOWED request still succeeds: " .. sys.errname(r.errno or 0))
        t:assert_eq(r.granted, 0, "with an empty granted mask")
    end)

test("the owner receives READ_CONTROL and WRITE_DAC whatever the DACL says",
    { spec = "PKM *check.dacl.owner-implicit-rights" }, function(t)
        local r = as_subject({}, owned(access.acl({})), STD.READ_CONTROL | STD.WRITE_DAC)
        t:log(string.format("ret=%d granted=0x%x", r.ret, r.granted))
        t:assert(r.ok, "the owner gets them from an empty DACL: " .. sys.errname(r.errno or 0))
        t:assert_eq(r.granted, STD.READ_CONTROL | STD.WRITE_DAC, "and gets exactly those two")
    end)

test("the owner implicit grant happens before the walk, so no deny ACE overrides it",
    { spec = "PKM *check.dacl.owner-implicit-before-walk" }, function(t)
        local sd = owned(access.acl({ access.ace(DENY, STD.READ_CONTROL | STD.WRITE_DAC, E) }))
        local r = as_subject({}, sd, STD.READ_CONTROL | STD.WRITE_DAC)
        t:log(string.format("ret=%d granted=0x%x", r.ret, r.granted))
        t:assert(r.ok, "a deny ACE for both rights does not take them away: "
            .. sys.errname(r.errno or 0))
        t:assert_eq(r.granted, STD.READ_CONTROL | STD.WRITE_DAC, "they are granted before the walk starts")
    end)

test("an OWNER RIGHTS ACE anywhere in the DACL suppresses the implicit grant",
    { spec = "PKM *check.dacl.owner-rights-suppresses-implicit" }, function(t)
        local suppressed = owned(access.acl({ access.ace(ALLOW, READ, token.SID.OWNER_RIGHTS) }))
        local plain = owned(access.acl({ access.ace(ALLOW, READ, E) }))
        local a = as_subject({}, suppressed, STD.READ_CONTROL)
        local b = as_subject({}, plain, STD.READ_CONTROL)
        t:log(string.format("with S-1-3-4 ret=%d %s, without ret=%d", a.ret,
            sys.errname(a.errno or 0), b.ret))
        t:assert(a.denied, "the owner loses READ_CONTROL once S-1-3-4 appears: ret=" .. a.ret
            .. " " .. sys.errname(a.errno or 0))
        t:assert(b.ok, "and keeps it in the same DACL without that SID: " .. sys.errname(b.errno or 0))
    end)

test("the OWNER RIGHTS pre-scan tests only for the SID, not for any condition on the ACE",
    { spec = "PKM *check.dacl.owner-rights-prescan-presence-only" }, function(t)
        -- A conditional allow ACE on S-1-3-4 whose Member_of condition is
        -- false for this subject: the ACE itself grants nothing, yet the
        -- pre-scan still suppresses the implicit owner grant.
        local sd = owned(access.acl({ access.ace(access.ACE.ALLOWED_CALLBACK, READ,
            token.SID.OWNER_RIGHTS, 0, { condition = member_of(token.SID.ADMINISTRATORS) }) }))
        local rc = as_subject({}, sd, STD.READ_CONTROL)
        local read = as_subject({}, sd, READ)
        t:log(string.format("READ_CONTROL ret=%d %s, conditional right ret=%d %s", rc.ret,
            sys.errname(rc.errno or 0), read.ret, sys.errname(read.errno or 0)))
        t:assert(read.denied, "the false condition stops the ACE granting anything: ret="
            .. read.ret .. " " .. sys.errname(read.errno or 0))
        t:assert(rc.denied, "yet its mere presence suppresses the implicit owner grant: ret="
            .. rc.ret .. " " .. sys.errname(rc.errno or 0))
    end)

test("during the walk S-1-3-4 is an ordinary SID matching the owner at both polarities",
    { spec = "PKM *check.dacl.owner-rights-ordinary-sid" }, function(t)
        local allowed = as_subject({},
            owned(access.acl({ access.ace(ALLOW, READ, token.SID.OWNER_RIGHTS) })), READ)
        local denied = as_subject({},
            owned(access.acl({ access.ace(DENY, READ, token.SID.OWNER_RIGHTS),
                access.ace(ALLOW, READ, E) })), READ)
        local deny_only_user = as_subject({ groups = { { sid = E, attributes = ENABLED } },
            user_deny_only = true },
            owned(access.acl({ access.ace(ALLOW, READ, token.SID.OWNER_RIGHTS) })), READ)
        t:log(string.format("allow ret=%d, deny ret=%d, user_deny_only allow ret=%d",
            allowed.ret, denied.ret, deny_only_user.ret))
        t:assert(allowed.ok, "an allow ACE on S-1-3-4 grants to the owner: "
            .. sys.errname(allowed.errno or 0))
        t:assert(denied.denied, "a deny ACE on it denies the owner: ret=" .. denied.ret
            .. " " .. sys.errname(denied.errno or 0))
        t:assert(deny_only_user.denied,
            "and it does not match an allow ACE through a user_deny_only token's user SID: ret="
            .. deny_only_user.ret .. " " .. sys.errname(deny_only_user.errno or 0))
    end)

test("a pre-decision from MIC bounds the owner implicit grant",
    { spec = "PKM *check.dacl.owner-implicit-bounded-by-decided" }, function(t)
        -- The subject owns the object but is below its integrity label, so
        -- MIC has already decided WRITE_DAC before EvaluateDACL runs.
        local sd = access.sd({ owner = USER, group = USER, dacl = access.acl({}),
            sacl = access.acl({ access.label_ace(token.INTEGRITY.HIGH, access.LABEL.NO_WRITE_UP) }) })
        local max = as_subject({}, sd, STD.MAXIMUM_ALLOWED)
        local wd = as_subject({}, sd, STD.WRITE_DAC)
        local rc = as_subject({}, sd, STD.READ_CONTROL)
        t:log(string.format("max granted=0x%x, WRITE_DAC ret=%d %s, READ_CONTROL ret=%d",
            max.granted, wd.ret, sys.errname(wd.errno or 0), rc.ret))
        t:assert(wd.denied, "a non-dominant owner does not receive WRITE_DAC: ret=" .. wd.ret
            .. " " .. sys.errname(wd.errno or 0))
        t:assert(rc.ok, "while READ_CONTROL, which MIC leaves undecided, is still granted: "
            .. sys.errname(rc.errno or 0))
        t:assert_eq(max.granted & STD.WRITE_DAC, 0, "and it is absent from the accumulated mask")
    end)

test("MAXIMUM_ALLOWED is stripped from the desired mask before evaluation",
    { spec = "PKM *check.dacl.max-allowed-stripped" }, function(t)
        -- No ACE grants bit 25, so an unstripped desired mask would fail.
        local sd = access.simple({ access.ace(ALLOW, READ, E) })
        local r = as_subject({}, sd, STD.MAXIMUM_ALLOWED | READ)
        t:log(string.format("ret=%d granted=0x%x", r.ret, r.granted))
        t:assert(r.ok, "MAXIMUM_ALLOWED | READ succeeds against a DACL granting only read: "
            .. sys.errname(r.errno or 0))
        t:assert_eq(r.granted & STD.MAXIMUM_ALLOWED, 0, "and bit 25 is not part of the granted mask")
    end)

test("MAXIMUM_ALLOWED runs the walk to completion and returns the accumulated mask",
    { spec = "PKM *check.dacl.max-allowed-returns-accumulated" }, function(t)
        local sd = access.simple({ access.ace(ALLOW, READ, E), access.ace(ALLOW, WRITE, E) })
        local r = as_subject({}, sd, STD.MAXIMUM_ALLOWED | READ)
        t:log(string.format("granted=0x%x", r.granted))
        t:assert_eq(r.granted, READ | WRITE,
            "the walk does not stop once the requested bit is decided, and the mask is not filtered to it")
    end)

test("a MAXIMUM_ALLOWED request carrying no specific rights always succeeds",
    { spec = "PKM *check.dacl.max-allowed-alone-succeeds" }, function(t)
        local r = as_subject({}, access.simple({}), STD.MAXIMUM_ALLOWED)
        t:log(string.format("ret=%d granted=0x%x", r.ret, r.granted))
        t:assert(r.ok, "against a DACL that grants nothing at all: " .. sys.errname(r.errno or 0))
        t:assert_eq(r.granted, 0, "returning an empty mask")
    end)

test("first-writer-wins applies to MAXIMUM_ALLOWED requests too",
    { spec = "PKM *check.dacl.max-allowed-first-writer-wins" }, function(t)
        -- MS-DTYP would let the later allow contribute here; KACS does not.
        local sd = access.simple({ access.ace(DENY, READ, E), access.ace(ALLOW, READ | WRITE, E) })
        local r = as_subject({}, sd, STD.MAXIMUM_ALLOWED)
        t:log(string.format("granted=0x%x", r.granted))
        t:assert_eq(r.granted & READ, 0, "the earlier deny still binds under MAXIMUM_ALLOWED")
        t:assert_eq(r.granted & WRITE, WRITE, "and the undecided bit is accumulated")
    end)
