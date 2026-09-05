-- PKM §3.8.4 — restricted tokens: when the second DACL pass runs, what
-- it can see, how its result is merged, and how owner rights, virtual
-- groups and device groups behave inside it.
--
-- Every case mints its own subject; the agent is SYSTEM and unrestricted.

local sys = require("helpers.sys")
local token = require("helpers.token")
local access = require("helpers.access")

local vm = provium:vm("v", "kernel-only"):boot()

local STD = access.STD
local E, USER = token.SID.EVERYONE, token.SID.TEST_USER
local G2 = token.SID.TEST_GROUP_2
--- A SID that is on no token and in no ACE unless a case puts it there.
local G3 = token.sid(5, 21, 1000, 2000, 3000, 5003)
local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED

--- A synthetic object type whose read, write and execute rights are three
--- disjoint bits, so the write-restricted merge can be seen bit by bit.
local OBJ = { read = 0x1, write = 0x2, execute = 0x4,
    all = 0x7 | STD.DELETE | STD.READ_CONTROL | STD.WRITE_DAC | STD.WRITE_OWNER | STD.SYNCHRONIZE }
local READ, WRITE, EXEC = 0x1, 0x2, 0x4
local ALLOW = access.ACE.ALLOWED

--- A conditional expression, padded so the containing ACE keeps a size
--- that is a multiple of four. `op` is 0x89 for `Member_of` and 0x8a for
--- `Device_Member_of`.
local function membership(op, sid)
    local expr = "artx" .. string.pack("<I1I4", 0x51, #sid) .. sid .. string.pack("<I1", op)
    return expr .. string.rep("\0", (-#expr) % 4)
end
local function member_of(sid) return membership(0x89, sid) end
local function device_member_of(sid) return membership(0x8a, sid) end

--- Check `desired` against `sd` as a freshly minted subject. The spec is
--- copied because `token.mint` stamps the session it creates into it.
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

--- The ordinary identity every case starts from: TEST_USER in Everyone
--- and TEST_GROUP_2, both enabled.
local function identity(extra)
    local spec = { groups = { { sid = E, attributes = ENABLED }, { sid = G2, attributes = ENABLED } } }
    for k, v in pairs(extra or {}) do spec[k] = v end
    return spec
end
local function restricting(sids, extra)
    local list = {}
    for i, sid in ipairs(sids) do list[i] = { sid = sid, attributes = 0 } end
    return identity(extra and (function()
        local e = { restricted_sids = list }
        for k, v in pairs(extra) do e[k] = v end
        return e
    end)() or { restricted_sids = list })
end

test("the second pass runs whenever the restricting SID list or the restricted device group list is non-empty",
    { spec = "PKM *check.restricted.second-pass-trigger" }, function(t)
        local sd = access.simple({ access.ace(ALLOW, READ, E) })
        local plain = as_subject(identity(), sd, READ)
        local sids = as_subject(restricting({ G3 }), sd, READ)
        -- No restricting SIDs at all, only restricted device groups: the
        -- pass still runs, and with an empty restricting list it grants
        -- nothing for the intersection to keep.
        local devices = as_subject(identity({
            device_groups = { { sid = G3, attributes = ENABLED } },
            restricted_device_groups = { { sid = G3, attributes = ENABLED } } }), sd, READ)
        t:log(string.format("unrestricted ret=%d, restricting SIDs ret=%d, device groups only ret=%d",
            plain.ret, sids.ret, devices.ret))
        t:assert(plain.ok, "an unrestricted token gets the right: " .. sys.errname(plain.errno or 0))
        t:assert(sids.denied, "a non-empty restricting SID list forces the second pass: ret="
            .. sids.ret .. " " .. sys.errname(sids.errno or 0))
        t:assert(devices.denied, "and so does a non-empty restricted device group list: ret="
            .. devices.ret .. " " .. sys.errname(devices.errno or 0))
    end)

test("the restricted pass matches SIDs only from the restricting list, not the token's groups",
    { spec = "PKM *check.restricted.only-restricting-sids-match" }, function(t)
        -- Both ACEs match the token's ordinary identity, so the normal pass
        -- grants read and write. Only the TEST_GROUP_2 ACE is visible to
        -- the restricted pass.
        local sd = access.simple({ access.ace(ALLOW, READ, E), access.ace(ALLOW, WRITE, G2) })
        local r = as_subject(restricting({ G2 }), sd, STD.MAXIMUM_ALLOWED)
        t:log(string.format("granted=0x%x", r.granted))
        t:assert_eq(r.granted & WRITE, WRITE, "the right an ACE on the restricting SID carries survives")
        t:assert_eq(r.granted & READ, 0,
            "while the one that came through Everyone does not — the normal groups are invisible")
    end)

test("conditional membership operators take the restricted view of the identity",
    { spec = "PKM *check.restricted.conditional-membership-restricted" }, function(t)
        -- The ACE's SID is Everyone, which is in the restricting list both
        -- times; only the Member_of condition differs in what it can see.
        local sd = access.simple({ access.ace(access.ACE.ALLOWED_CALLBACK, READ, E, 0,
            { condition = member_of(G2) }) })
        local hidden = as_subject(restricting({ E }), sd, READ)
        local visible = as_subject(restricting({ E, G2 }), sd, READ)
        t:log(string.format("G2 not restricting ret=%d %s, G2 restricting ret=%d", hidden.ret,
            sys.errname(hidden.errno or 0), visible.ret))
        t:assert(hidden.denied,
            "Member_of does not see a token group that is not a restricting SID: ret=" .. hidden.ret
            .. " " .. sys.errname(hidden.errno or 0))
        t:assert(visible.ok, "and does see it once it is one: " .. sys.errname(visible.errno or 0))
    end)

test("the restricting SID list is presence-based: its entries' attributes are ignored",
    { spec = "PKM *check.restricted.presence-based" }, function(t)
        local sd = access.simple({ access.ace(ALLOW, READ, G2) })
        for _, attrs in ipairs({ 0, ENABLED, token.GROUP.USE_FOR_DENY_ONLY }) do
            local r = as_subject(identity({
                restricted_sids = { { sid = G2, attributes = attrs } } }), sd, READ)
            t:log(string.format("restricting entry attributes 0x%x: ret=%d %s", attrs, r.ret,
                sys.errname(r.errno or 0)))
            t:assert(r.ok, string.format(
                "a restricting SID carrying attributes 0x%x still matches the allow ACE: %s",
                attrs, sys.errname(r.errno or 0)))
        end
    end)

test("access is the intersection of the two passes, so the restricting SIDs act as a ceiling",
    { spec = "PKM *check.restricted.intersection" }, function(t)
        -- TEST_GROUP_2 is not on the token, so the normal pass grants only
        -- read+write; the restricted pass grants only write+execute.
        local sd = access.simple({ access.ace(ALLOW, READ | WRITE, E),
            access.ace(ALLOW, WRITE | EXEC, G2) })
        local spec = { groups = { { sid = E, attributes = ENABLED } },
            restricted_sids = { { sid = G2, attributes = 0 } } }
        local r = as_subject(spec, sd, STD.MAXIMUM_ALLOWED)
        t:log(string.format("granted=0x%x", r.granted))
        t:assert_eq(r.granted, WRITE, "only the right both passes agree on is granted")
    end)

test("a write-restricted token intersects only the write-category bits",
    { spec = "PKM *check.restricted.write-restricted" }, function(t)
        -- The restricting SID matches no ACE, so the restricted pass grants
        -- nothing at all; read and execute come from the normal pass alone.
        local sd = access.simple({ access.ace(ALLOW, READ | WRITE | EXEC, E) })
        local r = as_subject(identity({ write_restricted = true, user_deny_only = true,
            restricted_sids = { { sid = G3, attributes = 0 } } }), sd, STD.MAXIMUM_ALLOWED)
        t:log(string.format("granted=0x%x", r.granted))
        t:assert_eq(r.granted & WRITE, 0, "the write-mapped bit is intersected away")
        t:assert_eq(r.granted & (READ | EXEC), READ | EXEC,
            "while read and execute come from the normal pass alone")
    end)

test("privilege-granted rights bypass the restricted intersection",
    { spec = "PKM *check.restricted.privileges-bypass" }, function(t)
        local sd = access.simple({})
        local spec = identity({ restricted_sids = { { sid = G3, attributes = 0 } },
            privs_present = token.bit(token.PRIV.SECURITY),
            privs_enabled = token.bit(token.PRIV.SECURITY) })
        local r = as_subject(spec, sd, STD.ACCESS_SYSTEM_SECURITY)
        t:log(string.format("ret=%d granted=0x%x", r.ret, r.granted))
        t:assert(r.ok, "SeSecurityPrivilege's grant survives a pass that granted nothing: "
            .. sys.errname(r.errno or 0))
        t:assert_eq(r.granted & STD.ACCESS_SYSTEM_SECURITY, STD.ACCESS_SYSTEM_SECURITY,
            "it is added back after the intersection")
    end)

test("the restored set includes the take-ownership grant",
    { spec = "PKM *check.restricted.restored-set" }, function(t)
        -- SeTakeOwnershipPrivilege grants WRITE_OWNER at step 9, after the
        -- DACL and before the restricted merge; it is restored with the
        -- rest of the privilege-granted set.
        local sd = access.simple({})
        local spec = identity({ restricted_sids = { { sid = G3, attributes = 0 } },
            privs_present = token.bit(token.PRIV.TAKE_OWNERSHIP),
            privs_enabled = token.bit(token.PRIV.TAKE_OWNERSHIP) })
        local r = as_subject(spec, sd, STD.WRITE_OWNER)
        local without = as_subject(identity({
            restricted_sids = { { sid = G3, attributes = 0 } } }), sd, STD.WRITE_OWNER)
        t:log(string.format("with take-ownership ret=%d, without ret=%d %s", r.ret, without.ret,
            sys.errname(without.errno or 0)))
        t:assert(r.ok, "WRITE_OWNER is restored after the intersection: " .. sys.errname(r.errno or 0))
        t:assert(without.denied, "and without the privilege there is nothing to restore: ret="
            .. without.ret .. " " .. sys.errname(without.errno or 0))
    end)

test("the restricted pass grants owner implicit rights only when the owner is a restricting SID",
    { spec = "PKM *check.restricted.owner-implicit" }, function(t)
        -- The object is owned by TEST_GROUP_2, which the subject is in, so
        -- the normal pass always grants the implicit pair.
        local sd = access.sd({ owner = G2, group = G2, dacl = access.acl({}) })
        local want = STD.READ_CONTROL | STD.WRITE_DAC
        local owner_restricting = as_subject(restricting({ G2 }), sd, want)
        local owner_absent = as_subject(restricting({ G3 }), sd, want)
        t:log(string.format("owner restricting ret=%d, owner absent ret=%d %s",
            owner_restricting.ret, owner_absent.ret, sys.errname(owner_absent.errno or 0)))
        t:assert(owner_restricting.ok,
            "the pass grants READ_CONTROL and WRITE_DAC when the owner SID is restricting: "
            .. sys.errname(owner_restricting.errno or 0))
        t:assert_eq(owner_restricting.granted, want, "and exactly those two")
        t:assert(owner_absent.denied, "and grants neither when it is not: ret=" .. owner_absent.ret
            .. " " .. sys.errname(owner_absent.errno or 0))
    end)

test("S-1-3-4 and S-1-5-10 are injected into the restricted pass only on the same basis",
    { spec = "PKM *check.restricted.virtual-groups" }, function(t)
        local owner_rights = access.sd({ owner = G2, group = G2,
            dacl = access.acl({ access.ace(ALLOW, READ, token.SID.OWNER_RIGHTS) }) })
        local a = as_subject(restricting({ G2 }), owner_rights, READ)
        local b = as_subject(restricting({ G3 }), owner_rights, READ)
        t:log(string.format("S-1-3-4: owner restricting ret=%d, owner absent ret=%d %s",
            a.ret, b.ret, sys.errname(b.errno or 0)))
        t:assert(a.ok, "OWNER RIGHTS matches when the object's owner is a restricting SID: "
            .. sys.errname(a.errno or 0))
        t:assert(b.denied, "and matches nothing when it is not: ret=" .. b.ret
            .. " " .. sys.errname(b.errno or 0))

        local principal_self = access.simple({ access.ace(ALLOW, READ, token.sid(5, 10)) })
        local c = as_subject(restricting({ G2 }), principal_self, READ, { self_sid = G2 })
        local d = as_subject(restricting({ G3 }), principal_self, READ, { self_sid = G2 })
        t:log(string.format("S-1-5-10: self restricting ret=%d, self absent ret=%d %s",
            c.ret, d.ret, sys.errname(d.errno or 0)))
        t:assert(c.ok, "PRINCIPAL_SELF matches when self_sid is a restricting SID: "
            .. sys.errname(c.errno or 0))
        t:assert(d.denied, "and matches nothing when it is not: ret=" .. d.ret
            .. " " .. sys.errname(d.errno or 0))
    end)

test("restricted device groups are swapped in for the restricted pass",
    { spec = "PKM *check.restricted.device-groups-swapped" }, function(t)
        -- The token's real device group is G3 both times, so the normal
        -- pass always grants; only the restricted device group list moves.
        local sd = access.simple({ access.ace(access.ACE.ALLOWED_CALLBACK, READ, E, 0,
            { condition = device_member_of(G3) }) })
        local base = { device_groups = { { sid = G3, attributes = ENABLED } },
            restricted_sids = { { sid = E, attributes = 0 } } }
        local same = as_subject(identity({ device_groups = base.device_groups,
            restricted_sids = base.restricted_sids,
            restricted_device_groups = { { sid = G3, attributes = ENABLED } } }), sd, READ)
        local other = as_subject(identity({ device_groups = base.device_groups,
            restricted_sids = base.restricted_sids,
            restricted_device_groups = { { sid = G2, attributes = ENABLED } } }), sd, READ)
        t:log(string.format("restricted devices {G3} ret=%d, {G2} ret=%d %s", same.ret, other.ret,
            sys.errname(other.errno or 0)))
        t:assert(same.ok,
            "Device_Member_of sees the restricted device group list in the restricted pass: "
            .. sys.errname(same.errno or 0))
        t:assert(other.denied,
            "so a different restricted device list fails it even though the token's own list matches: ret="
            .. other.ret .. " " .. sys.errname(other.errno or 0))
    end)
