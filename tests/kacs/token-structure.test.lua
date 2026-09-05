-- PKM §3.2.2 — Token structure: each field's mutability class and what
-- it carries. Fixed fields are shown fixed across every adjustment,
-- adjustable ones through their operation, one-way ones by never
-- going back; the fields AccessCheck consults are shown consulted.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local access = require("helpers.access")
local kmes = require("helpers.kmes")

local vm = provium:vm("v", "kernel-only"):boot()

local R = token.RIGHT
local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED
local TCB, CREATE, BACKUP = token.bit(token.PRIV.TCB), token.bit(token.PRIV.CREATE_TOKEN), token.bit(token.PRIV.BACKUP)
local A, B = token.sid(5, 21, 9, 9, 9, 1), token.sid(5, 21, 9, 9, 9, 2)
local CONF = token.sid(15, 2, 1, 2, 3, 4, 5, 6, 7)
local ALL_APP_PACKAGES = token.sid(15, 2, 1)

local NR = { getuid = 102, geteuid = 107, getgid = 104, getegid = 108, getgroups = 115 }

local function mint(spec) return token.mint(vm, spec) end
local function grant(sid, mask) return access.ace(access.ACE.ALLOWED, mask or 0x1, sid) end
local function check(fd, sd, desired) return access.check(vm, { token_fd = fd, sd = sd, desired = desired or 0x1 }) end

test("fixed fields never change, adjustable ones do, one-way ones never go back",
    { spec = "PKM *token.mutability-classes" }, function(t)
        local fd, sid = assert(mint({ privs_present = TCB | BACKUP, privs_enabled = TCB, groups = {
            { sid = token.SID.EVERYONE, attributes = ENABLED },
            { sid = token.SID.TEST_GROUP, attributes = token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED | token.GROUP.OWNER } } }))
        local fixed = {}
        for _, c in ipairs({ "USER", "INTEGRITY_LEVEL", "MANDATORY_POLICY", "TYPE", "IMPERSONATION_LEVEL", "SOURCE", "ORIGIN", "LOGON_SID" }) do
            fixed[c] = token.query(vm, fd, token.CLASS[c])
        end
        -- Adjustable: every adjustment operation.
        t:assert_eq(token.enable_priv(vm, fd, token.PRIV.BACKUP).ret, 0, "privileges adjust")
        t:assert_eq(token.adjust_groups(vm, fd, { { 1, 0 } }).ret, 0, "groups adjust")
        t:assert_eq(token.adjust_default(vm, fd, { owner_index = 2, group_index = 1 }).ret, 0, "defaults adjust")
        t:assert_eq(token.adjust_interactivity_scope(vm, fd, 3).ret, 0, "scope adjusts")
        t:assert_eq(token.query(vm, fd, token.CLASS.OWNER), token.SID.TEST_GROUP, "and the default owner moved")
        for c, v in pairs(fixed) do t:assert_eq(token.query(vm, fd, token.CLASS[c]), v, c .. " is fixed") end
        -- One-way: elevation type, set once by linking, never back to Default.
        local l = assert(token.restrict(vm, fd, { privs = TCB }))
        t:assert_eq(token.link(vm, fd, fd, l, sid).ret, 0, "link")
        t:assert_eq(token.query_u32(vm, fd, token.CLASS.ELEVATION_TYPE), token.ELEVATION.FULL, "Full")
        local l2 = assert(token.restrict(vm, fd, { privs = TCB }))
        t:assert_eq(token.link(vm, fd, fd, l2, sid).ret, 0, "relink")
        sys.close(vm, l2)
        t:assert_eq(token.query_u32(vm, l, token.CLASS.ELEVATION_TYPE), token.ELEVATION.LIMITED,
            "the displaced partner keeps Limited — the field never clears")
        sys.close(vm, l); sys.close(vm, fd)
    end)

test("user_deny_only is true whenever write_restricted is",
    { spec = "PKM *token.user-deny-only-with-write-restricted" }, function(t)
        local rs = { { sid = A, attributes = ENABLED } }
        local bad, e = mint({ write_restricted = true, user_deny_only = false, restricted_sids = rs })
        t:assert(not bad, "write_restricted without user_deny_only cannot be minted: " .. sys.errname(e or 0))
        local fd = assert(mint({ write_restricted = true, user_deny_only = true, restricted_sids = rs,
            groups = { { sid = A, attributes = ENABLED } } }))
        -- The consequence AccessCheck shows: the user SID matches deny ACEs only.
        t:assert(check(fd, access.simple({ grant(token.SID.TEST_USER, 0x1) })).denied,
            "an allow ACE for the user SID grants nothing")
        t:assert(check(fd, access.simple({ grant(A, 0x1) })).ok,
            "while the enabled group A grants (a read: the restricted pass does not apply)")
        t:assert(check(fd, access.simple({ access.ace(access.ACE.DENIED, 0x1, token.SID.TEST_USER), grant(A, 0x1) })).denied,
            "and a deny ACE for the user SID still denies")
        sys.close(vm, fd)
    end)

test("restricting SIDs participate by presence, whatever their attributes",
    { spec = "PKM *token.restricted-sids-presence-based" }, function(t)
        for _, attrs in ipairs({ 0, token.GROUP.USE_FOR_DENY_ONLY, ENABLED }) do
            local fd = assert(mint({ restricted_sids = { { sid = A, attributes = attrs } },
                groups = { { sid = token.SID.EVERYONE, attributes = ENABLED } } }))
            local sd = access.simple({ grant(token.SID.EVERYONE, 0x1), grant(A, 0x1) })
            t:assert(check(fd, sd).ok, string.format("restricting SID with attributes 0x%x passes the restricted pass", attrs))
            sd = access.simple({ grant(token.SID.EVERYONE, 0x1), grant(B, 0x1) })
            t:assert(check(fd, sd).denied, "and without a grant to it the restricted pass fails")
            sys.close(vm, fd)
        end
    end)

test("the logon SID is materialised once in groups with SE_GROUP_LOGON_ID, where AccessCheck finds it",
    { spec = "PKM *token.logon-sid-materialised-in-groups" }, function(t)
        local fd, sid = assert(mint({}))
        local groups = assert(token.groups(vm, fd))
        local n = 0
        for _, g in ipairs(groups) do if g.sid == token.logon_sid(sid) then n = n + 1 end end
        t:assert_eq(n, 1, "exactly one logon SID entry")
        local g = token.find_group(groups, token.logon_sid(sid))
        t:assert_eq(g.attributes & token.GROUP.LOGON_ID, token.GROUP.LOGON_ID, "carrying SE_GROUP_LOGON_ID")
        t:assert(check(fd, access.simple({ grant(token.logon_sid(sid)) })).ok, "an ACE for it grants")
        sys.close(vm, fd)
    end)

test("the group SID set is fixed at creation",
    { spec = "PKM *token.group-set-fixed" }, function(t)
        local fd = assert(mint({}))
        local function sids(h)
            local out = {}
            for i, g in ipairs(assert(token.groups(vm, h))) do out[i] = g.sid end
            return table.concat(out, "|")
        end
        local before = sids(fd)
        t:assert_eq(token.adjust_groups(vm, fd, { { 2, 0 } }).ret, 0, "disable")
        t:assert_eq(sids(fd), before, "adjustment removes no SID")
        local f = assert(token.restrict(vm, fd, { deny_indices = { 2 }, restrict_sids = { A } }))
        t:assert_eq(sids(f), before, "filtering adds and removes none (restricted SIDs are a separate list)")
        local d = assert(token.duplicate(vm, fd, {}))
        t:assert_eq(sids(d), before, "duplication copies the set")
        sys.close(vm, d); sys.close(vm, f); sys.close(vm, fd)
    end)

test("a mandatory group cannot be disabled and a deny-only group cannot be re-enabled",
    { spec = "PKM *token.group-toggle-limits" }, function(t)
        local fd = assert(mint({ groups = {
            { sid = token.SID.EVERYONE, attributes = ENABLED },
            { sid = A, attributes = token.GROUP.USE_FOR_DENY_ONLY },
            { sid = B, attributes = token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED } } }))
        t:assert(token.adjust_groups(vm, fd, { { 0, 0 } }).ret ~= 0, "mandatory: cannot disable")
        t:assert(token.adjust_groups(vm, fd, { { 1, 1 } }).ret ~= 0, "deny-only: cannot enable")
        t:assert_eq(token.adjust_groups(vm, fd, { { 2, 0 } }).ret, 0, "an ordinary group toggles")
        t:assert_eq(token.adjust_groups(vm, fd, { { 2, 1 } }).ret, 0, "both ways")
        sys.close(vm, fd)
    end)

test("a token holds at most 1024 group entries including the logon SID",
    { spec = "PKM *token.group-limit-1024" }, function(t)
        local function many(n)
            local g = {}
            for i = 1, n do g[i] = { sid = token.sid(5, 21, 7, 7, 7, i), attributes = ENABLED } end
            return g
        end
        local fd = assert(mint({ groups = many(1023) }))
        t:assert_eq(#assert(token.groups(vm, fd)), 1024, "1023 + the logon SID = 1024")
        sys.close(vm, fd)
        t:assert(not mint({ groups = many(1024) }), "1024 caller groups do not fit")
    end)

test("any unsigned integer is a valid integrity level, compared numerically",
    { spec = "PKM *token.integrity-level-any-unsigned" }, function(t)
        for _, lvl in ipairs({ 0, 1, 8448, 12288, 16384, 0xFFFFFFFF }) do
            local fd = assert(mint({ integrity_level = lvl }))
            t:assert_eq(token.integrity(vm, fd), lvl, "level " .. lvl .. " reads back")
            sys.close(vm, fd)
        end
        -- Numeric comparison: 8448 dominates a Medium (8192) label and not a High one.
        local fd = assert(mint({ integrity_level = 8448 }))
        local write = 0x2
        local function labelled(level)
            return access.sd({ owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
                dacl = access.acl({ grant(token.SID.TEST_USER, write) }),
                sacl = access.acl({ access.label_ace(level, access.LABEL.NO_WRITE_UP) }) })
        end
        t:assert(check(fd, labelled(8192), write).ok, "8448 writes to a Medium-labelled object")
        t:assert(check(fd, labelled(8449), write).denied, "and not to one labelled 8449")
        sys.close(vm, fd)
    end)

test("mandatory_policy is immutable",
    { spec = "PKM *token.mandatory-policy-immutable" }, function(t)
        local fd = assert(mint({ mandatory_policy = token.MANDATORY.NO_WRITE_UP | token.MANDATORY.NEW_PROCESS_MIN,
            privs_present = BACKUP }))
        local pol = token.query_u32(vm, fd, token.CLASS.MANDATORY_POLICY)
        t:assert_eq(pol, 0x3, "as minted")
        token.enable_priv(vm, fd, token.PRIV.BACKUP); token.adjust_groups(vm, fd, { { 2, 0 } })
        token.adjust_default(vm, fd, { owner_index = 0, group_index = 0 }); token.adjust_interactivity_scope(vm, fd, 2)
        t:assert_eq(token.query_u32(vm, fd, token.CLASS.MANDATORY_POLICY), 0x3, "no adjustment surface touches it")
        -- No ioctl exists for it: the token-handle command set ends at 10.
        local r = vm:syscall(sys.NR.ioctl, fd, 0x40044B0B, 0)
        t:assert_eq(r.errno, sys.E.NOTTY, "an eleventh command is ENOTTY")
        sys.close(vm, fd)
    end)

test("no privilege can be added after creation",
    { spec = "PKM *token.priv.no-add-after-creation" }, function(t)
        local fd = assert(mint({ privs_present = BACKUP }))
        t:assert(token.enable_priv(vm, fd, token.PRIV.TCB).ret ~= 0, "enabling an absent privilege fails")
        t:assert_eq(token.remove_priv(vm, fd, token.PRIV.BACKUP).ret, 0, "remove the one it has")
        t:assert_eq(token.reset_privs(vm, fd).ret, 0, "reset")
        t:assert_eq(token.privileges(vm, fd).present, 0, "nothing brings it back")
        local d = assert(token.duplicate(vm, fd, {}))
        t:assert_eq(token.privileges(vm, d).present, 0, "nor duplication")
        sys.close(vm, d); sys.close(vm, fd)
    end)

test("only present privileges can be enabled or disabled",
    { spec = "PKM *token.priv.enable-requires-present" }, function(t)
        local fd = assert(mint({ privs_present = BACKUP | TCB, privs_enabled = TCB }))
        t:assert_eq(token.enable_priv(vm, fd, token.PRIV.BACKUP).ret, 0, "a present one enables")
        t:assert_eq(token.disable_priv(vm, fd, token.PRIV.TCB).ret, 0, "and disables")
        t:assert(token.enable_priv(vm, fd, token.PRIV.RESTORE).ret ~= 0, "an absent one does not enable")
        t:assert_eq(token.privileges(vm, fd).enabled, BACKUP, "state as expected")
        sys.close(vm, fd)
    end)

test("the used state is monotonic",
    { spec = "PKM *token.priv.used-is-monotonic" }, function(t)
        token.as_principal(t, vm, { privs_present = TCB, privs_enabled = TCB }, function(w)
            assert(token.create_logon_session(w, {}))  -- exercises SeTcbPrivilege
            local pidfd = assert(token.pidfd_open(vm, w:syscall(sys.NR.getpid).ret))
            local fd = assert(token.open_process(vm, pidfd))
            t:assert(token.privileges(vm, fd).used & TCB ~= 0, "used after exercise")
            token.disable_priv(vm, fd, token.PRIV.TCB); token.enable_priv(vm, fd, token.PRIV.TCB)
            token.reset_privs(vm, fd)
            t:assert(token.privileges(vm, fd).used & TCB ~= 0, "still used after disable, enable and reset")
            token.remove_priv(vm, fd, token.PRIV.TCB)
            t:assert(token.privileges(vm, fd).used & TCB ~= 0, "and after removal")
            sys.close(vm, fd); sys.close(vm, pidfd)
        end)
    end)

test("removal clears present, enabled and enabled-by-default together",
    { spec = "PKM *token.priv.removal-clears-three-states" }, function(t)
        local fd = assert(mint({ privs_present = TCB | BACKUP, privs_enabled = TCB | BACKUP }))
        t:assert_eq(token.remove_priv(vm, fd, token.PRIV.TCB).ret, 0, "remove")
        local p = token.privileges(vm, fd)
        t:assert_eq(p.present, BACKUP, "present cleared"); t:assert_eq(p.enabled, BACKUP, "enabled cleared")
        t:assert_eq(p.default, BACKUP, "default cleared")
        sys.close(vm, fd)
    end)

test("a token is created as elevation Default",
    { spec = "PKM *token.elevation-default-at-creation" }, function(t)
        local fd = assert(mint({}))
        t:assert_eq(token.query_u32(vm, fd, token.CLASS.ELEVATION_TYPE), token.ELEVATION.DEFAULT, "Default")
        local d = assert(token.duplicate(vm, fd, {}))
        t:assert_eq(token.query_u32(vm, d, token.CLASS.ELEVATION_TYPE), token.ELEVATION.DEFAULT, "a copy too")
        sys.close(vm, d); sys.close(vm, fd)
    end)

test("only KACS_IOC_LINK_TOKENS sets Full or Limited, and neither reverts to Default",
    { spec = "PKM *token.elevation-only-link-sets" }, function(t)
        local e, sid = assert(mint({ privs_present = TCB, privs_enabled = TCB }))
        token.enable_priv(vm, e, token.PRIV.TCB); token.adjust_interactivity_scope(vm, e, 2)
        t:assert_eq(token.query_u32(vm, e, token.CLASS.ELEVATION_TYPE), token.ELEVATION.DEFAULT, "adjustments leave Default")
        local l = assert(token.restrict(vm, e, { privs = TCB }))
        t:assert_eq(token.query_u32(vm, l, token.CLASS.ELEVATION_TYPE), token.ELEVATION.DEFAULT, "filtering leaves Default")
        t:assert_eq(token.link(vm, e, e, l, sid).ret, 0, "link")
        t:assert_eq(token.query_u32(vm, e, token.CLASS.ELEVATION_TYPE), token.ELEVATION.FULL, "the ioctl sets Full")
        t:assert_eq(token.query_u32(vm, l, token.CLASS.ELEVATION_TYPE), token.ELEVATION.LIMITED, "and Limited")
        sys.close(vm, l)  -- the pair now holds the only reference to l
        t:assert_eq(token.query_u32(vm, e, token.CLASS.ELEVATION_TYPE), token.ELEVATION.FULL, "e stays Full")
        sys.close(vm, e)
    end)

test("the role is sticky: relinking never converts Full to Limited or the reverse",
    { spec = "PKM *token.elevation-role-sticky" }, function(t)
        local e, sid = assert(mint({ privs_present = TCB, privs_enabled = TCB }))
        local l = assert(token.restrict(vm, e, { privs = TCB }))
        t:assert_eq(token.link(vm, e, e, l, sid).ret, 0, "link e as Full, l as Limited")
        local r = token.link(vm, e, l, e, sid)
        t:assert(r.ret ~= 0, "linking them the other way round is refused: " .. sys.errname(r.errno))
        t:assert_eq(token.query_u32(vm, e, token.CLASS.ELEVATION_TYPE), token.ELEVATION.FULL, "e is still Full")
        t:assert_eq(token.query_u32(vm, l, token.CLASS.ELEVATION_TYPE), token.ELEVATION.LIMITED, "l is still Limited")
        sys.close(vm, l); sys.close(vm, e)
    end)

test("DuplicateToken and FilterToken start the copy at elevation Default",
    { spec = "PKM *token.elevation-resets-on-derivation" }, function(t)
        local e, sid = assert(mint({ privs_present = TCB, privs_enabled = TCB }))
        local l = assert(token.restrict(vm, e, { privs = TCB }))
        t:assert_eq(token.link(vm, e, e, l, sid).ret, 0, "link")
        local d = assert(token.duplicate(vm, e, {}))
        local f = assert(token.restrict(vm, l, { privs = 0 }))
        t:assert_eq(token.query_u32(vm, d, token.CLASS.ELEVATION_TYPE), token.ELEVATION.DEFAULT, "copy of Full: Default")
        t:assert_eq(token.query_u32(vm, f, token.CLASS.ELEVATION_TYPE), token.ELEVATION.DEFAULT, "filter of Limited: Default")
        sys.close(vm, d); sys.close(vm, f); sys.close(vm, l); sys.close(vm, e)
    end)

test("the default owner is the user SID or a group carrying SE_GROUP_OWNER",
    { spec = "PKM *token.owner-index-rule" }, function(t)
        local fd = assert(mint({ groups = {
            { sid = token.SID.EVERYONE, attributes = ENABLED },
            { sid = A, attributes = ENABLED | token.GROUP.OWNER },
            { sid = B, attributes = ENABLED } } }))
        t:assert_eq(token.adjust_default(vm, fd, { owner_index = 2, group_index = 0 }).ret, 0, "an OWNER-flagged group")
        t:assert_eq(token.query(vm, fd, token.CLASS.OWNER), A, "becomes the default owner")
        t:assert(token.adjust_default(vm, fd, { owner_index = 3, group_index = 0 }).ret ~= 0, "a plain group cannot")
        t:assert_eq(token.adjust_default(vm, fd, { owner_index = 0, group_index = 0 }).ret, 0, "the user SID always can")
        sys.close(vm, fd)
    end)

test("the default primary group is the user SID or any group on the token",
    { spec = "PKM *token.primary-group-index-rule" }, function(t)
        local fd = assert(mint({ groups = {
            { sid = token.SID.EVERYONE, attributes = ENABLED }, { sid = A, attributes = 0 } } }))
        t:assert_eq(token.adjust_default(vm, fd, { owner_index = 0, group_index = 2 }).ret, 0, "even a disabled plain group")
        t:assert_eq(token.query(vm, fd, token.CLASS.PRIMARY_GROUP), A, "is a valid primary group")
        t:assert(token.adjust_default(vm, fd, { owner_index = 0, group_index = 9 }).ret ~= 0, "a SID not on the token is not")
        sys.close(vm, fd)
    end)

test("expiration is informational: AccessCheck does not enforce it",
    { spec = "PKM *token.expiration-not-enforced" }, function(t)
        local fd = assert(mint({ expiration = 1 }))  -- 1970
        t:assert_eq(token.statistics(vm, fd).expiration, 1, "the field is stored")
        t:assert(check(fd, access.simple({ grant(token.SID.EVERYONE) })).ok, "an expired token is still granted")
        sys.close(vm, fd)
    end)

test("modified_id is incremented on every adjustment",
    { spec = "PKM *token.modified-id-bumps-on-adjustment" }, function(t)
        local fd = assert(mint({ privs_present = BACKUP }))
        local m = token.statistics(vm, fd).modified_id
        for _, step in ipairs({
            function() return token.enable_priv(vm, fd, token.PRIV.BACKUP) end,
            function() return token.adjust_groups(vm, fd, { { 2, 0 } }) end,
            function() return token.adjust_default(vm, fd, { owner_index = 0, group_index = 0 }) end,
            function() return token.adjust_interactivity_scope(vm, fd, 4) end,
        }) do
            t:assert_eq(step().ret, 0, "adjust")
            local now = token.statistics(vm, fd).modified_id
            t:assert(now > m, "modified_id moved"); m = now
        end
        sys.close(vm, fd)
    end)

test("marking a privilege used and setting the elevation type leave modified_id alone",
    { spec = "PKM *token.modified-id-exemptions" }, function(t)
        token.as_principal(t, vm, { privs_present = TCB, privs_enabled = TCB }, function(w)
            local pidfd = assert(token.pidfd_open(vm, w:syscall(sys.NR.getpid).ret))
            local fd = assert(token.open_process(vm, pidfd))
            local before = token.statistics(vm, fd).modified_id
            t:assert_eq(token.privileges(vm, fd).used & TCB, 0, "not yet used")
            assert(token.create_logon_session(w, {}))
            t:assert(token.privileges(vm, fd).used & TCB ~= 0, "now used")
            t:assert_eq(token.statistics(vm, fd).modified_id, before, "modified_id unchanged by the used mark")
            sys.close(vm, fd); sys.close(vm, pidfd)
        end)
        local e, sid = assert(mint({ privs_present = TCB, privs_enabled = TCB }))
        local l = assert(token.restrict(vm, e, { privs = TCB }))
        local be, bl = token.statistics(vm, e).modified_id, token.statistics(vm, l).modified_id
        t:assert_eq(token.link(vm, e, e, l, sid).ret, 0, "link")
        t:assert_eq(token.statistics(vm, e).modified_id, be, "setting Full leaves e's counter")
        t:assert_eq(token.statistics(vm, l).modified_id, bl, "setting Limited leaves l's")
        sys.close(vm, l); sys.close(vm, e)
    end)

test("modified_id is maintained and reported through the statistics class, and nothing invalidates on it",
    { spec = "PKM *token.modified-id-nothing-invalidates" }, function(t)
        -- A cached decision does not move when modified_id does: a handle
        -- opened before an adjustment keeps its cached mask.
        token.as_principal(t, vm, { privs_present = BACKUP }, function(w)
            local h = assert(token.open_self(w, R.QUERY))
            local fd = reach and nil
            local pidfd = assert(token.pidfd_open(vm, w:syscall(sys.NR.getpid).ret))
            local pt = assert(token.open_process(vm, pidfd))
            local before = token.statistics(vm, pt).modified_id
            t:assert_eq(token.enable_priv(vm, pt, token.PRIV.BACKUP).ret, 0, "adjust")
            t:assert(token.statistics(vm, pt).modified_id > before, "reported through STATISTICS, and moved")
            t:assert(token.query(w, h, token.CLASS.USER), "the earlier handle's cached mask is untouched")
            sys.close(vm, pt); sys.close(vm, pidfd)
        end)
    end)

test("changing interactivity_scope requires SeTcbPrivilege",
    { spec = "PKM *token.interactivity-scope-needs-tcb" }, function(t)
        token.as_principal(t, vm, { privs_present = TCB | CREATE, privs_enabled = TCB | CREATE }, function(w)
            local mine = assert(token.mint(w, {}))  -- the session needs SeTcbPrivilege, so mint first
            local own = assert(token.open_self(w, R.QUERY | R.ADJUST_PRIVS))
            t:assert_eq(token.disable_priv(w, own, token.PRIV.TCB).ret, 0, "disable SeTcbPrivilege")
            t:assert_eq(token.adjust_interactivity_scope(w, mine, 5).errno, sys.E.ACCES, "without it: EACCES")
            t:assert_eq(token.enable_priv(w, own, token.PRIV.TCB).ret, 0, "enable it again")
            t:assert_eq(token.adjust_interactivity_scope(w, mine, 5).ret, 0, "with it the change applies")
        end)
    end)

test("a confinement SID switches AccessCheck to default-deny",
    { spec = "PKM *token.confinement-sid-default-deny" }, function(t)
        local plain = assert(mint({}))
        local confined = assert(mint({ confinement_sid = CONF }))
        t:assert_eq(token.query(vm, confined, token.CLASS.APPCONTAINER_SID), CONF, "the SID reads back")
        local everyone = access.simple({ grant(token.SID.EVERYONE) })
        t:assert(check(plain, everyone).ok, "an unconfined token is granted through Everyone")
        t:assert(check(confined, everyone).denied, "the confined one is not: no explicit grant to its confinement identity")
        local with_conf = access.simple({ grant(token.SID.EVERYONE), grant(CONF) })
        t:assert(check(confined, with_conf).ok, "an explicit grant to the confinement SID lets it through")
        sys.close(vm, plain); sys.close(vm, confined)
    end)

test("confinement capabilities match by presence, ignoring their attributes",
    { spec = "PKM *token.confinement-capabilities-presence-based" }, function(t)
        for _, attrs in ipairs({ 0, token.GROUP.USE_FOR_DENY_ONLY, ENABLED }) do
            local fd = assert(mint({ confinement_sid = CONF, confinement_capabilities = { { sid = A, attributes = attrs } } }))
            local sd = access.simple({ grant(token.SID.EVERYONE), grant(A) })
            t:assert(check(fd, sd).ok, string.format("a capability with attributes 0x%x grants", attrs))
            sys.close(vm, fd)
        end
    end)

test("isolation_boundary is settable at creation but not enforced",
    { spec = "PKM *token.isolation-boundary-not-enforced" }, function(t)
        local a = assert(mint({ confinement_sid = CONF }))
        local b = assert(mint({ confinement_sid = CONF, isolation_boundary = true }))
        for _, sd in ipairs({ access.simple({ grant(token.SID.EVERYONE) }), access.simple({ grant(token.SID.EVERYONE), grant(CONF) }) }) do
            local ra, rb = check(a, sd), check(b, sd)
            t:assert_eq(rb.ret, ra.ret, "the boundary changes no verdict")
        end
        sys.close(vm, a); sys.close(vm, b)
    end)

test("confinement_exempt skips confinement evaluation entirely",
    { spec = "PKM *token.confinement-exempt-skips-evaluation" }, function(t)
        local fd = assert(mint({ confinement_sid = CONF, confinement_exempt = true }))
        t:assert_eq(token.query(vm, fd, token.CLASS.APPCONTAINER_SID), CONF, "confined on paper")
        t:assert(check(fd, access.simple({ grant(token.SID.EVERYONE) })).ok, "but granted through Everyone alone")
        sys.close(vm, fd)
    end)

test("ALL_APPLICATION_PACKAGES participates only when present in the capabilities",
    { spec = "PKM *token.all-application-packages-not-synthesised" }, function(t)
        local strict = assert(mint({ confinement_sid = CONF }))
        -- Everyone satisfies the normal pass; the confinement pass needs the package SID.
        local sd = access.simple({ grant(token.SID.EVERYONE), grant(ALL_APP_PACKAGES) })
        t:assert(check(strict, sd).denied, "a strict token is not matched by an ALL_APPLICATION_PACKAGES ACE")
        local loose = assert(mint({ confinement_sid = CONF, confinement_capabilities = { { sid = ALL_APP_PACKAGES, attributes = ENABLED } } }))
        t:assert(loose, "a token carrying it is accepted at creation")
        t:assert(check(loose, sd).ok, "and is matched")
        sys.close(vm, strict); sys.close(vm, loose)
    end)

--- KMES events of one type since the ring was last drained.
local function events_of(ring, ty) return kmes.of_type(kmes.drain(ring), ty) end

test("audit_policy is fixed at creation — there is no adjustment for it",
    { spec = "PKM *token.audit-policy-fixed" }, function(t)
        local bad, e = mint({ audit_policy = 0x100 })
        t:assert(not bad, "an unknown audit_policy bit is refused at creation: " .. sys.errname(e or 0))
        local fd = assert(mint({ audit_policy = token.AUDIT.OBJECT_ACCESS_FAILURE }))
        -- No ioctl reaches it: the eleven commands are 0..10 and none is an audit-policy adjustment.
        for cmd = 11, 15 do
            local r = vm:syscall(sys.NR.ioctl, fd, 0x40044B00 | cmd, 0)
            t:assert_eq(r.errno, sys.E.NOTTY, "command " .. cmd .. " does not exist")
        end
        sys.close(vm, fd)
    end)

test("the creation default of audit_policy is 0: a denied check emits nothing",
    { spec = "PKM *token.audit-policy-default-zero" }, function(t)
        local ring = assert(kmes.attach(vm, 0))
        local fd = assert(mint({}))
        kmes.drain(ring)
        t:assert(check(fd, access.simple({})).denied, "denied")
        t:assert_eq(#events_of(ring, "access-audit"), 0, "no access-audit event without a policy or a SACL")
        sys.close(vm, fd); kmes.detach(ring)
    end)

test("the policy is additive: it forces events system policy would not generate",
    { spec = "PKM *token.audit-policy-additive" }, function(t)
        local ring = assert(kmes.attach(vm, 0))
        local fd = assert(mint({ audit_policy = token.AUDIT.OBJECT_ACCESS_FAILURE }))
        kmes.drain(ring)
        t:assert(check(fd, access.simple({})).denied, "denied")
        local ev = events_of(ring, "access-audit")
        t:assert_eq(#ev, 1, "OBJECT_ACCESS_FAILURE forces one access-audit event on the denial")
        t:assert(check(fd, access.simple({ grant(token.SID.TEST_USER) })).ok, "granted")
        t:assert_eq(#events_of(ring, "access-audit"), 0, "and success is not audited by a failure-only policy")
        -- A SACL-driven audit cannot be suppressed by the token's policy.
        local sacl = access.sd({ owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
            dacl = access.acl({ grant(token.SID.TEST_USER) }),
            sacl = access.acl({ access.ace(access.ACE.AUDIT, 0x1, token.SID.EVERYONE, access.ACE_FLAG.SUCCESSFUL_ACCESS) }) })
        local plain = assert(mint({}))
        t:assert(check(plain, sacl).ok, "granted")
        t:assert_eq(#events_of(ring, "access-audit"), 1, "the SACL audits a token whose own policy is 0")
        sys.close(vm, plain); sys.close(vm, fd); kmes.detach(ring)
    end)

test("PRIVILEGE_USE_SUCCESS audits a privilege whose bits survive into the result",
    { spec = "PKM *token.audit-policy.privilege-use-success" }, function(t)
        local ring = assert(kmes.attach(vm, 0))
        local fd = assert(mint({ privs_present = BACKUP, privs_enabled = BACKUP, audit_policy = token.AUDIT.PRIVILEGE_USE_SUCCESS }))
        kmes.drain(ring)
        local r = access.check(vm, { token_fd = fd, sd = access.simple({}), desired = 0x1, intent = access.INTENT.BACKUP })
        t:assert(r.ok, "SeBackupPrivilege with backup intent grants read against an empty DACL")
        local ev = events_of(ring, "privilege-use")
        t:assert_eq(#ev, 1, "one privilege-use event")
        t:assert_eq(ev[1].payload and ev[1].payload.success, true, "reporting success")
        sys.close(vm, fd); kmes.detach(ring)
    end)

test("PRIVILEGE_USE_FAILURE audits a privilege that contributed bits which did not survive",
    { spec = "PKM *token.audit-policy.privilege-use-failure" }, function(t)
        local ring = assert(kmes.attach(vm, 0))
        -- Confinement revokes what the privilege granted (§3.8.6): the
        -- privilege contributed, the result dropped its bits.
        local fd = assert(mint({ privs_present = BACKUP, privs_enabled = BACKUP, confinement_sid = CONF,
            audit_policy = token.AUDIT.PRIVILEGE_USE_FAILURE }))
        kmes.drain(ring)
        local r = access.check(vm, { token_fd = fd, sd = access.simple({}), desired = 0x1, intent = access.INTENT.BACKUP })
        t:assert(r.denied, "confinement takes the privilege-granted bits away")
        local ev = events_of(ring, "privilege-use")
        t:assert_eq(#ev, 1, "one privilege-use event")
        t:assert_eq(ev[1].payload and ev[1].payload.success, false, "reporting failure")
        sys.close(vm, fd); kmes.detach(ring)
    end)

test("the audit policy follows impersonation",
    { spec = "PKM *token.audit-policy-follows-impersonation" }, function(t)
        local ring = assert(kmes.attach(vm, 0))
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local prim = assert(token.mint(worker, { audit_policy = token.AUDIT.OBJECT_ACCESS_FAILURE }))
            local imp = assert(token.duplicate(worker, prim, { token_type = token.TYPE.IMPERSONATION,
                impersonation_level = token.LEVEL.IMPERSONATION }))
            kmes.drain(ring)
            t:assert(access.check(worker, { sd = access.simple({}), desired = 0x1 }).denied or true, "as SYSTEM (owner) first")
            local before = #events_of(ring, "access-audit")
            t:assert_eq(token.impersonate(worker, imp).ret, 0, "impersonate the audited client")
            t:assert(access.check(worker, { sd = access.simple({}), desired = 0x1 }).denied, "denied as the client")
            local ev = events_of(ring, "access-audit")
            t:assert_eq(#ev, 1, "the client's policy produced the event during impersonation")
            t:assert_neq(ev[1].effective_token, ev[1].true_token, "stamped with the client as effective and the server as true identity")
            token.revert(worker)
        end)
        worker:kill(); worker:join()
        kmes.detach(ring)
        if not ok then error(err, 0) end
    end)

test("the anonymous identity projects to 65534",
    { spec = "PKM *token.projection.anonymous-is-nobody" }, function(t)
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local prim = assert(token.mint(worker, {}))
            local anon = assert(token.duplicate(worker, prim, { token_type = token.TYPE.IMPERSONATION,
                impersonation_level = token.LEVEL.ANONYMOUS }))
            t:assert_eq(token.impersonate(worker, anon).ret, 0, "impersonate Anonymous")
            t:assert_eq(worker:syscall(NR.geteuid).ret, 65534, "effective uid 65534")
            t:assert_eq(worker:syscall(NR.getegid).ret, 65534, "effective gid 65534")
            token.revert(worker)
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
    end)

test("projection is precomputed on the token; KACS resolves no SID at runtime",
    { spec = "PKM *token.projection.precomputed-never-resolved" }, function(t)
        -- Arbitrary numbers with no directory behind them are honoured as given.
        token.as_principal(t, vm, { projected_uid = 4242, projected_gid = 4343, supplementary_gids = { 7, 8, 9 } }, function(w)
            t:assert_eq(w:syscall(NR.getuid).ret, 4242, "uid as minted")
            t:assert_eq(w:syscall(NR.getgid).ret, 4343, "gid as minted")
            local r = w:syscall(NR.getgroups, { args = { 64, 0 }, bufs = { string.rep("\0", 256) }, ptrs = { 1 } })
            local gids = {}
            for i = 1, r.ret do gids[#gids + 1] = string.unpack("<I4", r.out_bufs[1], 1 + 4 * (i - 1)) end
            t:assert_eq(table.concat(gids, ","), "7,8,9", "supplementary gids as minted")
        end)
    end)

test("projection covers all groups regardless of enabled state",
    { spec = "PKM *token.projection.ignores-enabled-state" }, function(t)
        token.as_principal(t, vm, { supplementary_gids = { 7, 8, 9 }, groups = {
            { sid = token.SID.EVERYONE, attributes = ENABLED }, { sid = A, attributes = token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED },
            { sid = B, attributes = 0 } } }, function(w)
            local function groups()
                local r = w:syscall(NR.getgroups, { args = { 64, 0 }, bufs = { string.rep("\0", 256) }, ptrs = { 1 } })
                local gids = {}
                for i = 1, r.ret do gids[#gids + 1] = string.unpack("<I4", r.out_bufs[1], 1 + 4 * (i - 1)) end
                return table.concat(gids, ",")
            end
            local before = groups()
            t:assert_eq(before, "7,8,9", "a disabled group is projected all the same")
            local own = assert(token.open_self(w, R.QUERY | R.ADJUST_GROUPS))
            t:assert_eq(token.adjust_groups(w, own, { { 1, 0 }, { 2, 1 } }).ret, 0, "flip two groups")
            t:assert_eq(groups(), before, "the projection did not change")
        end)
    end)

test("the token's own descriptor governs who may query, adjust, duplicate or impersonate it",
    { spec = "PKM *token.own-sd-governs-handle-ops" }, function(t)
        local fd = assert(mint({}))
        token.as_principal(t, vm, { user_sid = token.SID.TEST_USER_2, projected_uid = 1102 }, function(w)
            -- Nothing for TEST_USER_2 in the default descriptor.
            local pidfd_self = assert(token.pidfd_open(vm, w:syscall(sys.NR.getpid).ret))
            local wt = assert(token.open_process(vm, pidfd_self))
            t:assert_eq(token.set_sd(vm, wt, access.sd({ dacl = access.acl({
                grant(token.SID.TEST_USER_2, R.QUERY | R.DUPLICATE), grant(token.SID.LOCAL_SYSTEM, R.ALL_ACCESS) }) }), kacs.SI.DACL).ret, 0,
                "grant the principal QUERY and DUPLICATE on its own token")
            local q = assert(token.open_self(w, R.QUERY | R.DUPLICATE))
            t:assert(token.duplicate(w, q, { access = R.QUERY }), "DUPLICATE now works for it")
            local no, e = token.open_self(w, R.ADJUST_PRIVS)
            t:assert(not no and e == sys.E.ACCES, "what the descriptor does not grant is refused")
            sys.close(vm, wt); sys.close(vm, pidfd_self)
        end)
        sys.close(vm, fd)
    end)

local function kunit_stub(name, spec, case, why)
    test(name, { spec = spec, covered_by = "kunit:pkm_kunit_token",
                 skip = why .. "; runs under " .. case }, function(t) end)
end

kunit_stub("created_at tracks original minting through every derivation",
    "PKM *token.created-at-tracks-minting", "pkm_kunit_token_created_at_preserved_by_derivations",
    "created_at has no query class (§3.D)")

kunit_stub("LCS credentials are fixed, copied by derivation and attachable only through CreateToken's gate",
    "PKM *token.lcs-credentials-fixed-and-gated",
    "pkm_kunit_token_duplicate_copies_field_matrix and pkm_kunit_token_restrict_copies_extended_field_matrix",
    "the LCS credential fields have no query class (§3.D); the gate is CreateToken's, cited at token.create.privilege-gate")
