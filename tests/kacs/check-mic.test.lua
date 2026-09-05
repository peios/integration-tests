-- PKM §3.8.3 — Mandatory Integrity Control: the pre-DACL constraint a
-- caller below the object's label runs into, what it does and does not
-- touch, how the label ACE is read, and the three policy bits.
--
-- Every case mints its own subject: the agent is SYSTEM at System
-- integrity and dominates everything.

local sys = require("helpers.sys")
local token = require("helpers.token")
local access = require("helpers.access")

local vm = provium:vm("v", "kernel-only"):boot()

local STD = access.STD
local E = token.SID.EVERYONE
local LOW, MEDIUM, HIGH = token.INTEGRITY.LOW, token.INTEGRITY.MEDIUM, token.INTEGRITY.HIGH
local LABEL = access.LABEL

--- A synthetic object type whose read, write and execute rights are three
--- disjoint bits.
local OBJ = { read = 0x1, write = 0x2, execute = 0x4,
    all = 0x7 | STD.DELETE | STD.READ_CONTROL | STD.WRITE_DAC | STD.WRITE_OWNER | STD.SYNCHRONIZE }
local READ, WRITE, EXEC = 0x1, 0x2, 0x4

--- A second synthetic type whose categories deliberately overlap, so
--- each label policy bit can be isolated: 0x1 is read-only, 0x2 is
--- read+write, 0x4 is write+execute, 0x8 is execute-only. MIC's starting
--- allowed set is read|execute, so a bit reachable through read or
--- execute disappears only when the matching policy bit strips it.
local LAYERED = { read = 0x3, write = 0x6, execute = 0xC,
    all = 0xF | STD.READ_CONTROL | STD.WRITE_DAC }
local READ_ONLY, READ_WRITE, WRITE_EXEC, EXEC_ONLY = 0x1, 0x2, 0x4, 0x8

--- Check `desired` against `sd` as a freshly minted subject. The spec is
--- copied because `token.mint` stamps the session it creates into it.
local function as_subject(spec, sd, desired, mapping, intent)
    local fresh = {}
    for k, v in pairs(spec or {}) do fresh[k] = v end
    local fd, e = token.mint(vm, fresh)
    assert(fd, "mint: " .. sys.errname(e or 0))
    local r = access.check(vm, { token_fd = fd, sd = sd, desired = desired,
        mapping = mapping or OBJ, intent = intent })
    sys.close(vm, fd)
    return r
end

--- A descriptor whose DACL grants GENERIC_ALL to Everyone, carrying
--- `sacl` (or none). Whatever MIC blocks, the DACL was willing to give.
local function open_sd(sacl)
    return access.simple({ access.ace(access.ACE.ALLOWED, STD.GENERIC_ALL, E) }, { sacl = sacl })
end
local function labelled(level, policy, flags)
    return open_sd(access.acl({ access.label_ace(level, policy, flags) }))
end

test("MIC is enforced before the DACL walk, so an allow ACE cannot undo it",
    { spec = "PKM *check.mic.before-dacl" }, function(t)
        -- The very first ACE in the DACL allows everything.
        local sd = labelled(HIGH, LABEL.NO_WRITE_UP)
        local w = as_subject({ integrity_level = LOW }, sd, WRITE)
        local max = as_subject({ integrity_level = LOW }, sd, STD.MAXIMUM_ALLOWED)
        t:log(string.format("write ret=%d %s, accumulated=0x%x", w.ret, sys.errname(w.errno or 0),
            max.granted))
        t:assert(w.denied, "the write right is refused despite the leading GENERIC_ALL ACE: ret="
            .. w.ret .. " " .. sys.errname(w.errno or 0))
        t:assert_eq(max.granted & WRITE, 0,
            "MIC decided the bit before the walk, so no ACE could grant it")
    end)

test("the default is no-write-up: a lower-integrity caller reads and executes but does not write",
    { spec = "PKM *check.mic.default-no-write-up" }, function(t)
        local sd = labelled(HIGH, LABEL.NO_WRITE_UP)
        local r = as_subject({ integrity_level = LOW }, sd, READ)
        local x = as_subject({ integrity_level = LOW }, sd, EXEC)
        local w = as_subject({ integrity_level = LOW }, sd, WRITE)
        t:log(string.format("read ret=%d execute ret=%d write ret=%d %s", r.ret, x.ret, w.ret,
            sys.errname(w.errno or 0)))
        t:assert(r.ok, "read is allowed up: " .. sys.errname(r.errno or 0))
        t:assert(x.ok, "execute is allowed up: " .. sys.errname(x.errno or 0))
        t:assert(w.denied, "write is not: ret=" .. w.ret .. " " .. sys.errname(w.errno or 0))
    end)

test("an object with no mandatory label is treated as Medium with no-write-up",
    { spec = "PKM *check.mic.unlabelled-is-medium" }, function(t)
        local no_sacl = open_sd(nil)
        -- A SACL that carries no mandatory label ACE at all.
        local no_label = open_sd(access.acl({ access.ace(access.ACE.AUDIT, READ, E,
            access.ACE_FLAG.SUCCESSFUL_ACCESS) }))
        local low_a = as_subject({ integrity_level = LOW }, no_sacl, WRITE)
        local low_b = as_subject({ integrity_level = LOW }, no_label, WRITE)
        local med = as_subject({ integrity_level = MEDIUM }, no_sacl, WRITE)
        t:log(string.format("low/no-sacl ret=%d, low/no-label ret=%d, medium ret=%d",
            low_a.ret, low_b.ret, med.ret))
        t:assert(low_a.denied, "a Low caller cannot write an unlabelled object: ret=" .. low_a.ret
            .. " " .. sys.errname(low_a.errno or 0))
        t:assert(low_b.denied, "nor one whose SACL carries no label ACE: ret=" .. low_b.ret
            .. " " .. sys.errname(low_b.errno or 0))
        t:assert(med.ok, "while a Medium caller dominates the implied Medium label: "
            .. sys.errname(med.errno or 0))
    end)

test("a caller at or above the object's level dominates it and MIC decides nothing",
    { spec = "PKM *check.mic.dominant-no-effect" }, function(t)
        local sd = labelled(HIGH, LABEL.NO_WRITE_UP | LABEL.NO_READ_UP | LABEL.NO_EXECUTE_UP)
        local equal = as_subject({ integrity_level = HIGH }, sd, STD.MAXIMUM_ALLOWED)
        local above = as_subject({ integrity_level = token.INTEGRITY.SYSTEM }, sd, STD.MAXIMUM_ALLOWED)
        t:log(string.format("equal granted=0x%x, above granted=0x%x", equal.granted, above.granted))
        t:assert_eq(equal.granted, OBJ.all,
            "an equal level dominates, so the DACL's GENERIC_ALL comes through untouched")
        t:assert_eq(above.granted, OBJ.all, "and so does a higher one")
    end)

test("MIC never revokes what a privilege already granted",
    { spec = "PKM *check.mic.never-revokes-privileges" }, function(t)
        -- SeRestorePrivilege seeds the write bits into `granted` at step 4;
        -- MIC only ever adds to `decided`. The DACL is empty, so nothing
        -- else can be the source.
        local strip = access.acl({ access.label_ace(HIGH,
            LABEL.NO_READ_UP | LABEL.NO_WRITE_UP | LABEL.NO_EXECUTE_UP) })
        local sd = access.simple({}, { sacl = strip })
        local spec = { integrity_level = LOW,
            privs_present = token.bit(token.PRIV.RESTORE),
            privs_enabled = token.bit(token.PRIV.RESTORE) }
        local r = as_subject(spec, sd, WRITE, OBJ, access.INTENT.RESTORE)
        t:log(string.format("restore ret=%d granted=0x%x", r.ret, r.granted))
        t:assert(r.ok, "the restore-granted write right survives MIC: " .. sys.errname(r.errno or 0))
        t:assert_eq(r.granted & (STD.WRITE_DAC | STD.WRITE_OWNER | STD.DELETE),
            STD.WRITE_DAC | STD.WRITE_OWNER | STD.DELETE,
            "along with the rest of the restore set")
    end)

test("ACCESS_SYSTEM_SECURITY is outside the set of bits MIC can decide",
    { spec = "PKM *check.mic.access-system-security-untouched" }, function(t)
        local sd = labelled(HIGH, LABEL.NO_READ_UP | LABEL.NO_WRITE_UP | LABEL.NO_EXECUTE_UP)
        local with = as_subject({ integrity_level = LOW,
            privs_present = token.bit(token.PRIV.SECURITY),
            privs_enabled = token.bit(token.PRIV.SECURITY) }, sd, STD.ACCESS_SYSTEM_SECURITY)
        local without = as_subject({ integrity_level = LOW }, sd, STD.ACCESS_SYSTEM_SECURITY)
        t:log(string.format("with SeSecurity ret=%d, without ret=%d %s", with.ret, without.ret,
            sys.errname(without.errno or 0)))
        t:assert(with.ok, "a non-dominant caller holding SeSecurityPrivilege still gets it: "
            .. sys.errname(with.errno or 0))
        t:assert_eq(with.granted & STD.ACCESS_SYSTEM_SECURITY, STD.ACCESS_SYSTEM_SECURITY,
            "MIC's reach stops at MapGenericBits(GENERIC_ALL), which does not include the bit")
        t:assert(without.denied, "the right is privilege-granted, not DACL-granted: ret="
            .. without.ret .. " " .. sys.errname(without.errno or 0))
    end)

test("SeRelabelPrivilege lets the DACL grant WRITE_OWNER through an integrity mismatch",
    { spec = "PKM *check.mic.relabel-allows-write-owner" }, function(t)
        local sd = access.simple({ access.ace(access.ACE.ALLOWED, STD.WRITE_OWNER, E) },
            { sacl = access.acl({ access.label_ace(HIGH, LABEL.NO_WRITE_UP) }) })
        local with = as_subject({ integrity_level = LOW,
            privs_present = token.bit(token.PRIV.RELABEL),
            privs_enabled = token.bit(token.PRIV.RELABEL) }, sd, STD.WRITE_OWNER)
        local without = as_subject({ integrity_level = LOW }, sd, STD.WRITE_OWNER)
        t:log(string.format("with relabel ret=%d, without ret=%d %s", with.ret, without.ret,
            sys.errname(without.errno or 0)))
        t:assert(with.ok, "the DACL's WRITE_OWNER comes through: " .. sys.errname(with.errno or 0))
        t:assert(without.denied, "and without the privilege MIC blocks it: ret=" .. without.ret
            .. " " .. sys.errname(without.errno or 0))
    end)

test("a relabel-loosened WRITE_OWNER is not privilege-granted, so the restricted merge drops it",
    { spec = "PKM *check.mic.relabel-not-privilege-granted" }, function(t)
        -- The subject holds SeRelabelPrivilege and SeSecurityPrivilege and
        -- is restricted to a SID no ACE names. ACCESS_SYSTEM_SECURITY is
        -- privilege-granted and is restored after the intersection;
        -- WRITE_OWNER, loosened only through the relabel provenance, is not.
        local sd = access.simple({ access.ace(access.ACE.ALLOWED, STD.WRITE_OWNER, E) },
            { sacl = access.acl({ access.label_ace(HIGH, LABEL.NO_WRITE_UP) }) })
        local privs = token.bit(token.PRIV.RELABEL) | token.bit(token.PRIV.SECURITY)
        local unrestricted = as_subject({ integrity_level = LOW,
            privs_present = privs, privs_enabled = privs }, sd, STD.MAXIMUM_ALLOWED)
        local restricted = as_subject({ integrity_level = LOW,
            privs_present = privs, privs_enabled = privs,
            restricted_sids = { { sid = token.SID.TEST_GROUP_2, attributes = 0 } } },
            sd, STD.MAXIMUM_ALLOWED)
        t:log(string.format("unrestricted=0x%x restricted=0x%x", unrestricted.granted,
            restricted.granted))
        t:assert_eq(unrestricted.granted & STD.WRITE_OWNER, STD.WRITE_OWNER,
            "unrestricted, the relabel-loosened right is granted")
        t:assert_eq(restricted.granted & STD.WRITE_OWNER, 0,
            "restricted, it is not restored after the intersection")
        t:assert_eq(restricted.granted & STD.ACCESS_SYSTEM_SECURITY, STD.ACCESS_SYSTEM_SECURITY,
            "while a genuinely privilege-granted bit is")
    end)

test("MIC enforcement is gated on the token's NO_WRITE_UP mandatory policy",
    { spec = "PKM *check.mic.mandatory-policy-gate" }, function(t)
        local sd = labelled(HIGH, LABEL.NO_WRITE_UP)
        local on = as_subject({ integrity_level = LOW,
            mandatory_policy = token.MANDATORY.NO_WRITE_UP }, sd, WRITE)
        local off = as_subject({ integrity_level = LOW, mandatory_policy = 0 }, sd, WRITE)
        t:log(string.format("policy on ret=%d %s, policy clear ret=%d", on.ret,
            sys.errname(on.errno or 0), off.ret))
        t:assert(on.denied, "with NO_WRITE_UP set the rule applies: ret=" .. on.ret
            .. " " .. sys.errname(on.errno or 0))
        t:assert(off.ok, "with it clear MIC is disabled for that token: " .. sys.errname(off.errno or 0))
    end)

test("only the first non-inherit-only mandatory label ACE is used",
    { spec = "PKM *check.mic.first-non-inherit-only-label" }, function(t)
        -- An inherit-only High label ahead of an effective Low one: the Low
        -- label is what applies, and a Medium caller dominates it.
        local skipped = open_sd(access.acl({
            access.label_ace(HIGH, LABEL.NO_WRITE_UP, access.ACE_FLAG.INHERIT_ONLY),
            access.label_ace(LOW, LABEL.NO_WRITE_UP),
        }))
        -- Two effective labels: the first one wins.
        local first_wins = open_sd(access.acl({
            access.label_ace(HIGH, LABEL.NO_WRITE_UP),
            access.label_ace(LOW, LABEL.NO_WRITE_UP),
        }))
        local a = as_subject({ integrity_level = MEDIUM }, skipped, WRITE)
        local b = as_subject({ integrity_level = MEDIUM }, first_wins, WRITE)
        t:log(string.format("inherit-only first ret=%d, both effective ret=%d %s", a.ret, b.ret,
            sys.errname(b.errno or 0)))
        t:assert(a.ok, "an inherit-only label does not apply to the object carrying it: "
            .. sys.errname(a.errno or 0))
        t:assert(b.denied, "and of two effective labels the first is the one used: ret=" .. b.ret
            .. " " .. sys.errname(b.errno or 0))
    end)

test("the label SID's single sub-authority is the integrity level, compared as an unsigned integer",
    { spec = "PKM *check.mic.label-sid-shape" }, function(t)
        local equal = as_subject({ integrity_level = MEDIUM },
            labelled(8192, LABEL.NO_WRITE_UP), WRITE)
        local one_above = as_subject({ integrity_level = MEDIUM },
            labelled(8193, LABEL.NO_WRITE_UP), WRITE)
        local one_below = as_subject({ integrity_level = MEDIUM },
            labelled(8191, LABEL.NO_WRITE_UP), WRITE)
        t:log(string.format("S-1-16-8192 ret=%d, S-1-16-8193 ret=%d, S-1-16-8191 ret=%d",
            equal.ret, one_above.ret, one_below.ret))
        t:assert(equal.ok, "a caller at S-1-16-8192 dominates the same value: "
            .. sys.errname(equal.errno or 0))
        t:assert(one_above.denied, "one unit above it does not: ret=" .. one_above.ret
            .. " " .. sys.errname(one_above.errno or 0))
        t:assert(one_below.ok, "and one unit below it does: " .. sys.errname(one_below.errno or 0))
    end)

test("intermediate S-1-16-X levels are valid and compared numerically",
    { spec = "PKM *check.mic.nonstandard-levels-accepted" }, function(t)
        local below = as_subject({ integrity_level = LOW },
            labelled(2048, LABEL.NO_WRITE_UP), WRITE)
        local above = as_subject({ integrity_level = MEDIUM },
            labelled(8448, LABEL.NO_WRITE_UP), WRITE)
        t:log(string.format("Low vs S-1-16-2048 ret=%d, Medium vs S-1-16-8448 ret=%d %s",
            below.ret, above.ret, sys.errname(above.errno or 0)))
        t:assert(below.ok, "a Low caller dominates the non-standard level 2048: "
            .. sys.errname(below.errno or 0))
        t:assert(above.denied, "and a Medium caller is below the non-standard level 8448: ret="
            .. above.ret .. " " .. sys.errname(above.errno or 0))
    end)

test("a malformed mandatory label ACE rejects the whole descriptor rather than being ignored",
    { spec = "PKM *check.mic.malformed-label-rejects-descriptor" }, function(t)
        local wrong_authority = open_sd(access.acl({
            access.ace(access.ACE.MANDATORY_LABEL, LABEL.NO_WRITE_UP, token.SID.LOCAL_SYSTEM) }))
        local two_sub_authorities = open_sd(access.acl({
            access.ace(access.ACE.MANDATORY_LABEL, LABEL.NO_WRITE_UP, token.sid(16, 8192, 1)) }))
        local a = as_subject({ integrity_level = LOW }, wrong_authority, READ)
        local b = as_subject({ integrity_level = LOW }, two_sub_authorities, READ)
        t:log(string.format("wrong authority ret=%d %s, two sub-authorities ret=%d %s",
            a.ret, sys.errname(a.errno or 0), b.ret, sys.errname(b.errno or 0)))
        t:assert(a.ret < 0 and not a.denied,
            "a label SID outside S-1-16 fails the check as an error: " .. sys.errname(a.errno or 0))
        t:assert(b.ret < 0 and not b.denied,
            "and so does one with the wrong sub-authority count: " .. sys.errname(b.errno or 0))
    end)

test("SYSTEM_MANDATORY_LABEL_NO_READ_UP removes the read-mapped rights",
    { spec = "PKM *check.mic.policy.no-read-up" }, function(t)
        local none = labelled(HIGH, 0)
        local strip = labelled(HIGH, LABEL.NO_READ_UP)
        local low = { integrity_level = LOW }
        local base = as_subject(low, none, READ_ONLY, LAYERED)
        local stripped = as_subject(low, strip, READ_ONLY, LAYERED)
        local other = as_subject(low, strip, EXEC_ONLY, LAYERED)
        t:log(string.format("read-only bit: no policy ret=%d, NO_READ_UP ret=%d; execute-only ret=%d",
            base.ret, stripped.ret, other.ret))
        t:assert(base.ok, "the read-mapped bit is allowed up by default: " .. sys.errname(base.errno or 0))
        t:assert(stripped.denied, "NO_READ_UP takes it away: ret=" .. stripped.ret
            .. " " .. sys.errname(stripped.errno or 0))
        t:assert(other.ok, "and leaves the execute-mapped bit alone: " .. sys.errname(other.errno or 0))
    end)

test("SYSTEM_MANDATORY_LABEL_NO_WRITE_UP removes the write-mapped rights",
    { spec = "PKM *check.mic.policy.no-write-up" }, function(t)
        local none = labelled(HIGH, 0)
        local strip = labelled(HIGH, LABEL.NO_WRITE_UP)
        local low = { integrity_level = LOW }
        local base = as_subject(low, none, READ_WRITE, LAYERED)
        local stripped = as_subject(low, strip, READ_WRITE, LAYERED)
        local other = as_subject(low, strip, READ_ONLY, LAYERED)
        t:log(string.format("read+write bit: no policy ret=%d, NO_WRITE_UP ret=%d; read-only ret=%d",
            base.ret, stripped.ret, other.ret))
        t:assert(base.ok, "a bit reachable through GENERIC_READ is allowed up by default: "
            .. sys.errname(base.errno or 0))
        t:assert(stripped.denied, "NO_WRITE_UP takes it away because GENERIC_WRITE also maps it: ret="
            .. stripped.ret .. " " .. sys.errname(stripped.errno or 0))
        t:assert(other.ok, "and leaves the purely read-mapped bit alone: " .. sys.errname(other.errno or 0))
    end)

test("SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP removes the execute-mapped rights",
    { spec = "PKM *check.mic.policy.no-execute-up" }, function(t)
        local none = labelled(HIGH, 0)
        local strip = labelled(HIGH, LABEL.NO_EXECUTE_UP)
        local low = { integrity_level = LOW }
        local base = as_subject(low, none, EXEC_ONLY, LAYERED)
        local stripped = as_subject(low, strip, EXEC_ONLY, LAYERED)
        local other = as_subject(low, strip, READ_ONLY, LAYERED)
        t:log(string.format("execute-only bit: no policy ret=%d, NO_EXECUTE_UP ret=%d; read-only ret=%d",
            base.ret, stripped.ret, other.ret))
        t:assert(base.ok, "the execute-mapped bit is allowed up by default: " .. sys.errname(base.errno or 0))
        t:assert(stripped.denied, "NO_EXECUTE_UP takes it away: ret=" .. stripped.ret
            .. " " .. sys.errname(stripped.errno or 0))
        t:assert(other.ok, "and leaves the read-mapped bit alone: " .. sys.errname(other.errno or 0))
    end)

test("unknown bits in a label mask are ignored",
    { spec = "PKM *check.mic.unknown-policy-bits-ignored" }, function(t)
        local low = { integrity_level = LOW }
        local none = labelled(HIGH, 0)
        local unknown = labelled(HIGH, 0x40000000)
        for _, bit in ipairs({ READ_ONLY, READ_WRITE, WRITE_EXEC, EXEC_ONLY }) do
            local a = as_subject(low, none, bit, LAYERED)
            local b = as_subject(low, unknown, bit, LAYERED)
            t:log(string.format("bit 0x%x: no policy ret=%d, unknown-bit policy ret=%d",
                bit, a.ret, b.ret))
            t:assert_eq(b.ok, a.ok, string.format(
                "an unrecognised policy bit changes nothing for right 0x%x", bit))
            t:assert_eq(b.granted, a.granted, "and grants exactly the same mask")
        end
    end)

test("EnforceMIC leaves a fully stripped non-dominant caller with READ_CONTROL and SYNCHRONIZE",
    { spec = "PKM *check.mic.algorithm" }, function(t)
        -- Every up-strip set, the file mapping (whose GENERIC_READ folds in
        -- READ_CONTROL and SYNCHRONIZE), no privileges, an owner the caller
        -- is not: what survives is exactly the pair the algorithm ORs back
        -- in after the strips.
        local sd = labelled(HIGH, LABEL.NO_READ_UP | LABEL.NO_WRITE_UP | LABEL.NO_EXECUTE_UP)
        local r = as_subject({ integrity_level = LOW }, sd, STD.MAXIMUM_ALLOWED,
            access.FILE_MAPPING)
        t:log(string.format("granted=0x%x", r.granted))
        t:assert_eq(r.granted, STD.READ_CONTROL | STD.SYNCHRONIZE,
            "READ_CONTROL and SYNCHRONIZE are added after the strips and nothing else survives")
    end)
