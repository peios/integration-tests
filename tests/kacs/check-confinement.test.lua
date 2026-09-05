-- PKM §3.8.6 — application confinement: the second intersection, run
-- after the restricted merge, that limits a confined token to what its
-- confinement identity can justify on its own — the SID set, the two
-- confinement-scoped virtual groups, what privileges cannot do about
-- it, and strict confinement.
--
-- The agent is SYSTEM and unconfined, so every case mints its own
-- subject and passes it as `token_fd`.

local sys = require("helpers.sys")
local token = require("helpers.token")
local access = require("helpers.access")

local vm = provium:vm("v", "kernel-only"):boot()

local STD = access.STD
local E, USER = token.SID.EVERYONE, token.SID.TEST_USER
local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED

--- The confinement identity every case uses, plus a capability SID and a
--- SID that appears nowhere unless a case puts it there.
local CONF = token.sid(15, 2, 1, 2, 3, 4, 5, 6, 7)
local CAP = token.sid(15, 3, 4001)
local ALL_APP_PACKAGES = token.sid(15, 2, 1)
local ALL_RESTRICTED_APP_PACKAGES = token.sid(15, 2, 2)
local OWNER_RIGHTS, PRINCIPAL_SELF = token.SID.OWNER_RIGHTS, token.sid(5, 10)

--- A synthetic object type whose read, write and execute rights are three
--- disjoint bits, so a case can say which category a surviving bit came
--- from. The standard rights live in `all` and in none of the three.
local OBJ = { read = 0x1, write = 0x2, execute = 0x4,
    all = 0x7 | STD.DELETE | STD.READ_CONTROL | STD.WRITE_DAC | STD.WRITE_OWNER | STD.SYNCHRONIZE }
local READ, WRITE = 0x1, 0x2
local ALLOW = access.ACE.ALLOWED
local BACKUP = token.bit(token.PRIV.BACKUP)
local SECURITY = token.bit(token.PRIV.SECURITY)

--- A one-SID membership conditional expression, padded so the containing
--- ACE keeps a size that is a multiple of four. `op` is 0x89 for
--- `Member_of`.
local function member_of(sid)
    local expr = "artx" .. string.pack("<I1I4", 0x51, #sid) .. sid .. string.pack("<I1", 0x89)
    return expr .. string.rep("\0", (-#expr) % 4)
end

--- Check `desired` against `sd` as a freshly minted subject built from
--- `spec`, under the synthetic mapping. The spec is copied because
--- `token.mint` stamps the session it creates into it, and a reused spec
--- would name a session that has gone.
local function as_subject(spec, sd, desired, opts)
    opts = opts or {}
    local fresh = {}
    for k, v in pairs(spec or {}) do fresh[k] = v end
    local fd, e = token.mint(vm, fresh)
    assert(fd, "mint: " .. sys.errname(e or 0))
    local r = access.check(vm, { token_fd = fd, sd = sd, desired = desired,
        mapping = OBJ, self_sid = opts.self_sid, intent = opts.intent })
    sys.close(vm, fd)
    return r
end

--- The ordinary identity every case starts from: TEST_USER in Everyone.
local function identity(extra)
    local spec = { groups = { { sid = E, attributes = ENABLED } } }
    for k, v in pairs(extra or {}) do spec[k] = v end
    return spec
end
--- The same identity, confined to CONF.
local function confined(extra)
    local spec = { confinement_sid = CONF }
    for k, v in pairs(extra or {}) do spec[k] = v end
    return identity(spec)
end

local function grant(mask, sid, flags, extra) return access.ace(ALLOW, mask, sid, flags, extra) end

test("the confinement pass intersects the DACL result with what the confinement identity earns alone",
    { spec = "PKM *check.confinement.intersects-confinement-identity" }, function(t)
        -- Everyone grants read and write; the confinement identity is
        -- named by an ACE carrying read alone.
        local sd = access.simple({ grant(READ | WRITE, E), grant(READ, CONF) })
        local plain = as_subject(identity(), sd, STD.MAXIMUM_ALLOWED)
        local conf = as_subject(confined(), sd, STD.MAXIMUM_ALLOWED)
        local w = as_subject(confined(), sd, WRITE)
        t:log(string.format("unconfined granted=0x%x, confined granted=0x%x, write ret=%d %s",
            plain.granted, conf.granted, w.ret, sys.errname(w.errno or 0)))
        t:assert_eq(plain.granted, READ | WRITE, "an unconfined token keeps both rights")
        t:assert_eq(conf.granted, READ,
            "the confined one keeps only the right its confinement identity was granted")
        t:assert(w.denied, "and the right that came through Everyone alone is revoked: ret="
            .. w.ret .. " " .. sys.errname(w.errno or 0))
    end)

test("confinement_exempt skips the pass entirely",
    { spec = "PKM *check.confinement.exempt-skips-evaluation" }, function(t)
        local sd = access.simple({ grant(READ, E) })
        local strict = as_subject(confined(), sd, READ)
        local exempt = as_subject(confined({ confinement_exempt = true }), sd, READ)
        t:log(string.format("confined ret=%d %s, exempt ret=%d", strict.ret,
            sys.errname(strict.errno or 0), exempt.ret))
        t:assert(strict.denied, "a confined token is refused a right granted only through Everyone: ret="
            .. strict.ret .. " " .. sys.errname(strict.errno or 0))
        t:assert(exempt.ok, "and the same token marked exempt is granted it: "
            .. sys.errname(exempt.errno or 0))
    end)

test("the confinement SID set is the confinement SID together with every capability SID",
    { spec = "PKM *check.confinement.sid-set" }, function(t)
        -- Everyone carries both rights, so the normal pass grants both;
        -- the confinement pass reaches read through the confinement SID
        -- and write only through the capability.
        local sd = access.simple({ grant(READ | WRITE, E), grant(READ, CONF), grant(WRITE, CAP) })
        local without = as_subject(confined(), sd, STD.MAXIMUM_ALLOWED)
        local with = as_subject(confined({
            confinement_capabilities = { { sid = CAP, attributes = ENABLED } } }), sd, STD.MAXIMUM_ALLOWED)
        t:log(string.format("no capability granted=0x%x, with capability granted=0x%x",
            without.granted, with.granted))
        t:assert_eq(without.granted, READ, "the confinement SID alone reaches only its own ACE")
        t:assert_eq(with.granted, READ | WRITE,
            "and adding the capability to the set brings its ACE into the pass")
    end)

test("capability SIDs are presence-based: disabling one or marking it deny-only changes nothing",
    { spec = "PKM *check.confinement.capabilities-presence-based" }, function(t)
        local sd = access.simple({ grant(READ, E), grant(READ, CAP) })
        for _, attrs in ipairs({ 0, ENABLED, token.GROUP.USE_FOR_DENY_ONLY,
                token.GROUP.ENABLED_BY_DEFAULT }) do
            local r = as_subject(confined({
                confinement_capabilities = { { sid = CAP, attributes = attrs } } }), sd, READ)
            t:log(string.format("attributes 0x%x: ret=%d %s", attrs, r.ret, sys.errname(r.errno or 0)))
            t:assert(r.ok, string.format(
                "a capability with attributes 0x%x still participates: %s", attrs,
                sys.errname(r.errno or 0)))
        end
    end)

test("PRINCIPAL_SELF is injected into the confinement pass only when self_sid is a confinement SID",
    { spec = "PKM *check.confinement.virtual-groups" }, function(t)
        -- Everyone carries the normal pass; S-1-5-10 is the only ACE the
        -- confinement pass can reach.
        local sd = access.simple({ grant(READ, E), grant(READ, PRINCIPAL_SELF) })
        local as_conf = as_subject(confined(), sd, READ, { self_sid = CONF })
        local as_cap = as_subject(confined({
            confinement_capabilities = { { sid = CAP, attributes = ENABLED } } }), sd, READ,
            { self_sid = CAP })
        local as_user = as_subject(confined(), sd, READ, { self_sid = USER })
        t:log(string.format("self=CONF ret=%d, self=CAP ret=%d, self=USER ret=%d %s",
            as_conf.ret, as_cap.ret, as_user.ret, sys.errname(as_user.errno or 0)))
        t:assert(as_conf.ok, "self_sid equal to the confinement SID injects S-1-5-10: "
            .. sys.errname(as_conf.errno or 0))
        t:assert(as_cap.ok, "and so does self_sid equal to a capability SID: "
            .. sys.errname(as_cap.errno or 0))
        t:assert(as_user.denied,
            "while self_sid equal to the token's own user SID does not: ret=" .. as_user.ret
            .. " " .. sys.errname(as_user.errno or 0))
    end)

test("OWNER RIGHTS is injected into the confinement pass only when the owner is a confinement SID",
    { spec = "PKM *check.confinement.virtual-groups" }, function(t)
        local dacl = access.acl({ grant(READ, E), grant(READ, OWNER_RIGHTS) })
        local owned_by_conf = access.sd({ owner = CONF, group = CONF, dacl = dacl })
        local owned_by_user = access.sd({ owner = USER, group = USER, dacl = dacl })
        local a = as_subject(confined(), owned_by_conf, READ)
        local b = as_subject(confined(), owned_by_user, READ)
        t:log(string.format("owner=CONF ret=%d, owner=USER ret=%d %s", a.ret, b.ret,
            sys.errname(b.errno or 0)))
        t:assert(a.ok, "an object owned by the confinement SID makes S-1-3-4 match: "
            .. sys.errname(a.errno or 0))
        t:assert(b.denied,
            "while an object owned by the token's own user SID does not: ret=" .. b.ret
            .. " " .. sys.errname(b.errno or 0))
    end)

test("the two virtual groups follow the confinement rules inside conditional membership operators",
    { spec = "PKM *check.confinement.virtual-groups-in-conditionals" }, function(t)
        -- The conditional ACE's own SID is the confinement SID, so it is
        -- reached in the confinement pass; only its Member_of(S-1-5-10)
        -- condition decides whether it grants.
        local sd = access.simple({ grant(READ, E),
            access.ace(access.ACE.ALLOWED_CALLBACK, READ, CONF, 0,
                { condition = member_of(PRINCIPAL_SELF) }) })
        local as_conf = as_subject(confined(), sd, READ, { self_sid = CONF })
        local as_user = as_subject(confined(), sd, READ, { self_sid = USER })
        t:log(string.format("Member_of(S-1-5-10) self=CONF ret=%d, self=USER ret=%d %s",
            as_conf.ret, as_user.ret, sys.errname(as_user.errno or 0)))
        t:assert(as_conf.ok, "S-1-5-10 is a member when self_sid is the confinement SID: "
            .. sys.errname(as_conf.errno or 0))
        t:assert(as_user.denied,
            "and is not when self_sid is only the token's user SID: ret=" .. as_user.ret
            .. " " .. sys.errname(as_user.errno or 0))
    end)

test("Member_of(OWNER RIGHTS) inside the confinement pass answers for the confinement identity",
    { spec = "PKM *check.confinement.virtual-groups-in-conditionals" }, function(t)
        local dacl = access.acl({ grant(READ, E),
            access.ace(access.ACE.ALLOWED_CALLBACK, READ, CONF, 0,
                { condition = member_of(OWNER_RIGHTS) }) })
        local a = as_subject(confined(), access.sd({ owner = CONF, group = CONF, dacl = dacl }), READ)
        local b = as_subject(confined(), access.sd({ owner = USER, group = USER, dacl = dacl }), READ)
        t:log(string.format("owner=CONF ret=%d, owner=USER ret=%d %s", a.ret, b.ret,
            sys.errname(b.errno or 0)))
        t:assert(a.ok, "the owner is a member of S-1-3-4 when it is in the confinement set: "
            .. sys.errname(a.errno or 0))
        t:assert(b.denied, "and is not when it is only the token's user SID: ret=" .. b.ret
            .. " " .. sys.errname(b.errno or 0))
    end)

test("conditional expressions in the confinement pass still see the token's real groups",
    { spec = "PKM *check.confinement.conditionals-see-full-token" }, function(t)
        -- Both ACEs are on the confinement SID, so both are reached by
        -- the confinement pass; only the condition differs. Everyone is a
        -- token group and never a confinement SID.
        local function sd_for(condition)
            return access.simple({ grant(READ, E),
                access.ace(access.ACE.ALLOWED_CALLBACK, READ, CONF, 0, { condition = condition }) })
        end
        local real = as_subject(confined(), sd_for(member_of(E)), READ)
        local absent = as_subject(confined(), sd_for(member_of(token.SID.TEST_GROUP_2)), READ)
        t:log(string.format("Member_of(Everyone) ret=%d, Member_of(unheld group) ret=%d %s",
            real.ret, absent.ret, sys.errname(absent.errno or 0)))
        t:assert(real.ok,
            "Member_of sees a token group that is not part of the confinement identity: "
            .. sys.errname(real.errno or 0))
        t:assert(absent.denied, "and still answers false for a group the token does not hold: ret="
            .. absent.ret .. " " .. sys.errname(absent.errno or 0))
    end)

test("privileges do not bypass confinement: backup-granted read is revoked",
    { spec = "PKM *check.confinement.privileges-do-not-bypass" }, function(t)
        -- An empty DACL, so the read bit can only have come from the
        -- privilege seeding at step 4.
        local sd = access.simple({})
        local plain = as_subject(identity({ privs_present = BACKUP, privs_enabled = BACKUP }),
            sd, READ, { intent = access.INTENT.BACKUP })
        local conf = as_subject(confined({ privs_present = BACKUP, privs_enabled = BACKUP }),
            sd, READ, { intent = access.INTENT.BACKUP })
        t:log(string.format("unconfined ret=%d, confined ret=%d %s", plain.ret, conf.ret,
            sys.errname(conf.errno or 0)))
        t:assert(plain.ok, "SeBackupPrivilege grants read against an empty DACL: "
            .. sys.errname(plain.errno or 0))
        t:assert(conf.denied, "and the confinement intersection takes it straight back: ret="
            .. conf.ret .. " " .. sys.errname(conf.errno or 0))
    end)

test("the confinement merge takes no privilege-granted input, so take-ownership cannot get through",
    { spec = "PKM *check.confinement.privileges-do-not-bypass" }, function(t)
        local TAKE = token.bit(token.PRIV.TAKE_OWNERSHIP)
        local sd = access.simple({})
        local plain = as_subject(identity({ privs_present = TAKE, privs_enabled = TAKE }),
            sd, STD.WRITE_OWNER)
        local conf = as_subject(confined({ privs_present = TAKE, privs_enabled = TAKE }),
            sd, STD.WRITE_OWNER)
        t:log(string.format("unconfined ret=%d, confined ret=%d %s", plain.ret, conf.ret,
            sys.errname(conf.errno or 0)))
        t:assert(plain.ok, "SeTakeOwnershipPrivilege grants WRITE_OWNER: "
            .. sys.errname(plain.errno or 0))
        t:assert(conf.denied, "confinement revokes it: ret=" .. conf.ret .. " "
            .. sys.errname(conf.errno or 0))
    end)

test("the confinement pass runs with skip_owner_implicit, so a confined owner gets no implicit rights",
    { spec = "PKM *check.confinement.skips-owner-implicit" }, function(t)
        -- CONF is both the object's owner and a token group, so the
        -- normal pass grants the owner's implicit READ_CONTROL and
        -- WRITE_DAC; only the confinement pass can take them away.
        local spec = { groups = { { sid = E, attributes = ENABLED },
            { sid = CONF, attributes = ENABLED } }, confinement_sid = CONF }
        local sd = access.sd({ owner = CONF, group = CONF,
            dacl = access.acl({ grant(READ, CONF) }) })
        local max = as_subject(spec, sd, STD.MAXIMUM_ALLOWED)
        local rc = as_subject(spec, sd, STD.READ_CONTROL)
        t:log(string.format("granted=0x%x, READ_CONTROL ret=%d %s", max.granted, rc.ret,
            sys.errname(rc.errno or 0)))
        t:assert_eq(max.granted & (STD.READ_CONTROL | STD.WRITE_DAC), 0,
            "the implicit owner rights do not survive the confinement intersection")
        t:assert_eq(max.granted & READ, READ, "while the right an explicit ACE granted does")
        t:assert(rc.denied, "and asking for READ_CONTROL outright fails: ret=" .. rc.ret
            .. " " .. sys.errname(rc.errno or 0))
    end)

test("a null DACL grants in the confinement pass exactly as it does in the normal one",
    { spec = "PKM *check.confinement.null-dacl-grants" }, function(t)
        local sd = access.sd({ owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM })
        local plain = as_subject(identity(), sd, STD.MAXIMUM_ALLOWED)
        local conf = as_subject(confined(), sd, STD.MAXIMUM_ALLOWED)
        local one = as_subject(confined(), sd, WRITE)
        t:log(string.format("unconfined granted=0x%x, confined granted=0x%x, write ret=%d",
            plain.granted, conf.granted, one.ret))
        t:assert_eq(conf.granted, OBJ.all, "the confined token receives the whole valid right set")
        t:assert_eq(conf.granted, plain.granted, "which is what an unconfined token receives")
        t:assert(one.ok, "and a targeted request against a null DACL succeeds: "
            .. sys.errname(one.errno or 0))
    end)

test("strict confinement is the same evaluation over a SID set that omits ALL_APPLICATION_PACKAGES",
    { spec = "PKM *check.confinement.strict-omits-all-app-packages" }, function(t)
        -- One object grants to ALL_APPLICATION_PACKAGES and one to
        -- ALL_RESTRICTED_APPLICATION_PACKAGES: the strict token reaches
        -- only the second, which is what makes its surface narrower.
        local normal = confined({ confinement_capabilities = {
            { sid = ALL_APP_PACKAGES, attributes = ENABLED },
            { sid = ALL_RESTRICTED_APP_PACKAGES, attributes = ENABLED } } })
        local strict = confined({ confinement_capabilities = {
            { sid = ALL_RESTRICTED_APP_PACKAGES, attributes = ENABLED } } })
        local wide = access.simple({ grant(READ, E), grant(READ, ALL_APP_PACKAGES) })
        local narrow = access.simple({ grant(READ, E), grant(READ, ALL_RESTRICTED_APP_PACKAGES) })
        local a, b = as_subject(normal, wide, READ), as_subject(strict, wide, READ)
        local c, d = as_subject(normal, narrow, READ), as_subject(strict, narrow, READ)
        t:log(string.format("ALL_APP: normal ret=%d strict ret=%d %s; ALL_RESTRICTED: normal ret=%d strict ret=%d",
            a.ret, b.ret, sys.errname(b.errno or 0), c.ret, d.ret))
        t:assert(a.ok, "a normal confined token reaches an ALL_APPLICATION_PACKAGES grant: "
            .. sys.errname(a.errno or 0))
        t:assert(b.denied, "a strict one does not: ret=" .. b.ret .. " "
            .. sys.errname(b.errno or 0))
        t:assert(c.ok and d.ok,
            "both reach an ALL_RESTRICTED_APPLICATION_PACKAGES grant, which is the narrower surface")
    end)

test("strict confinement is derived from the SID set: never synthesised, never rejected",
    { spec = "PKM *check.confinement.strict-never-rejected" }, function(t)
        local strict, e1 = token.mint(vm, { confinement_sid = CONF })
        t:assert(strict, "a confined token with no capabilities at all is accepted: "
            .. sys.errname(e1 or 0))
        local loose, e2 = token.mint(vm, { confinement_sid = CONF, confinement_capabilities = {
            { sid = ALL_APP_PACKAGES, attributes = ENABLED } } })
        t:assert(loose, "and so is one carrying ALL_APPLICATION_PACKAGES: " .. sys.errname(e2 or 0))
        -- Nothing is added to the set the token was created with.
        local sd = access.simple({ grant(READ, E), grant(READ, ALL_APP_PACKAGES) })
        local s = access.check(vm, { token_fd = strict, sd = sd, desired = READ, mapping = OBJ })
        local l = access.check(vm, { token_fd = loose, sd = sd, desired = READ, mapping = OBJ })
        t:log(string.format("strict ret=%d %s, with the package SID ret=%d", s.ret,
            sys.errname(s.errno or 0), l.ret))
        t:assert(s.denied, "the kernel never synthesises ALL_APPLICATION_PACKAGES: ret=" .. s.ret
            .. " " .. sys.errname(s.errno or 0))
        t:assert(l.ok, "only the token that was given it matches: " .. sys.errname(l.errno or 0))
        sys.close(vm, strict); sys.close(vm, loose)
    end)

test("SACL access is unreachable for a confined token unless a confinement ACE grants it",
    { spec = "PKM *check.confinement.sacl-unreachable" }, function(t)
        -- ACCESS_SYSTEM_SECURITY is only ever privilege-granted, and the
        -- confinement merge takes no privilege-granted input.
        local privs = { privs_present = SECURITY, privs_enabled = SECURITY }
        local open_dacl = access.simple({ grant(STD.GENERIC_ALL, E) })
        local plain = as_subject(identity(privs), open_dacl, STD.ACCESS_SYSTEM_SECURITY)
        local conf = as_subject(confined(privs), open_dacl, STD.ACCESS_SYSTEM_SECURITY)
        local granted = as_subject(confined(privs),
            access.simple({ grant(STD.GENERIC_ALL, E),
                grant(STD.ACCESS_SYSTEM_SECURITY, CONF) }), STD.ACCESS_SYSTEM_SECURITY)
        t:log(string.format("unconfined ret=%d, confined ret=%d %s, with a confinement ACE ret=%d",
            plain.ret, conf.ret, sys.errname(conf.errno or 0), granted.ret))
        t:assert(plain.ok, "SeSecurityPrivilege reaches the SACL when nothing is confining: "
            .. sys.errname(plain.errno or 0))
        t:assert(conf.denied,
            "a confined caller cannot, even holding the privilege and a GENERIC_ALL DACL: ret="
            .. conf.ret .. " " .. sys.errname(conf.errno or 0))
        t:assert(granted.ok,
            "and only an ACE granting the right outright to the confinement identity gets it back: "
            .. sys.errname(granted.errno or 0))
    end)

test("confinement runs after the restricted merge, so the restored privilege bits are still revoked",
    { spec = "PKM *check.confinement.after-restricted-merge" }, function(t)
        -- The restricting SID list matches no ACE, so the restricted pass
        -- grants nothing and the read bit survives it only because
        -- privilege-granted bits are restored afterwards. Confinement
        -- runs next and removes it: if the two ran the other way round
        -- the restoration would put it back.
        local G3 = token.sid(5, 21, 1000, 2000, 3000, 5003)
        local privs = { privs_present = BACKUP, privs_enabled = BACKUP,
            restricted_sids = { { sid = G3, attributes = 0 } } }
        local sd = access.simple({})
        local restricted = as_subject(identity(privs), sd, READ, { intent = access.INTENT.BACKUP })
        local both = as_subject(confined(privs), sd, READ, { intent = access.INTENT.BACKUP })
        t:log(string.format("restricted only ret=%d, restricted and confined ret=%d %s",
            restricted.ret, both.ret, sys.errname(both.errno or 0)))
        t:assert(restricted.ok,
            "the restricted merge restores the privilege-granted read bit: "
            .. sys.errname(restricted.errno or 0))
        t:assert(both.denied,
            "and the confinement pass, running after it, takes the restored bit away: ret="
            .. both.ret .. " " .. sys.errname(both.errno or 0))
    end)
