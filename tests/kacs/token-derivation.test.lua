-- PKM §3.2.4 — DuplicateToken and FilterToken: what a derived token
-- shares with its source, what is fresh, and what filtering may only
-- ever weaken. The KUnit suite pkm_kunit_token drives the same paths
-- from inside the kernel; here they are driven through the ioctls a
-- program uses, from a minted principal where the source's own state
-- matters.

local sys = require("helpers.sys")
local token = require("helpers.token")

local vm = provium:vm("v", "kernel-only"):boot()

local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED
local TCB, CREATE = token.bit(token.PRIV.TCB), token.bit(token.PRIV.CREATE_TOKEN)
local A, B, C = token.sid(5, 21, 9, 9, 9, 1), token.sid(5, 21, 9, 9, 9, 2), token.sid(5, 21, 9, 9, 9, 3)

--- A rich source token, so field-by-field copying has something to copy.
local function rich_spec(extra)
    local spec = {
        groups = {
            { sid = token.SID.EVERYONE, attributes = ENABLED },
            { sid = token.SID.TEST_GROUP, attributes = ENABLED | token.GROUP.OWNER },
            { sid = token.SID.TEST_GROUP_2, attributes = token.GROUP.USE_FOR_DENY_ONLY },
        },
        privs_present = TCB | CREATE | token.bit(token.PRIV.BACKUP),
        privs_enabled = TCB | token.bit(token.PRIV.BACKUP),
        integrity_level = token.INTEGRITY.HIGH,
        mandatory_policy = token.MANDATORY.NO_WRITE_UP | token.MANDATORY.NEW_PROCESS_MIN,
        owner_sid_index = 2, primary_group_index = 3,
        default_dacl = require("helpers.kacs").acl({
            require("helpers.kacs").ace(0, 0x1F01FF, token.SID.TEST_USER, 0) }),
        expiration = 0x5F5E1000, origin = 0x123456789, interactivity_scope = 3,
        source_name = "PITRich\0", source_id = 0xABCDEF,
        device_groups = { { sid = A, attributes = ENABLED } },
        supplementary_gids = { 100, 200, 300 },
        audit_policy = token.AUDIT.OBJECT_ACCESS_FAILURE,
    }
    for k, v in pairs(extra or {}) do spec[k] = v end
    return spec
end

--- Every queryable class compared between two handles. Returns the list
--- of class names that differ.
local COPIED = { "USER", "GROUPS", "PRIVILEGES", "INTEGRITY_LEVEL", "OWNER", "PRIMARY_GROUP",
    "INTERACTIVITY_SCOPE", "RESTRICTED_SIDS", "SOURCE", "ORIGIN", "DEVICE_GROUPS",
    "APPCONTAINER_SID", "CAPABILITIES", "MANDATORY_POLICY", "LOGON_TYPE", "LOGON_SID",
    "DEFAULT_DACL", "USER_CLAIMS", "DEVICE_CLAIMS", "PROJECTED_SUPPLEMENTARY_GIDS" }
local function differing_classes(who, a, b, except)
    local diff = {}
    for _, name in ipairs(COPIED) do
        if not (except and except[name]) then
            local pa, pb = token.query(who, a, token.CLASS[name]), token.query(who, b, token.CLASS[name])
            if pa ~= pb then diff[#diff + 1] = name end
        end
    end
    return diff
end

--- Run `fn(worker, pidfd_token)` where the worker runs as a freshly
--- minted principal that has exercised SeTcbPrivilege (so its token
--- carries a used bit) and the agent holds an ALL_ACCESS handle on the
--- worker's primary token, opened through a pidfd.
local function with_used_principal(t, spec, fn)
    token.as_principal(t, vm, spec, function(w)
        -- Exercise SeTcbPrivilege: creating a LogonSession requires it.
        assert(token.create_logon_session(w, {}))
        local pid = w:syscall(sys.NR.getpid).ret
        local pidfd = assert(token.pidfd_open(vm, pid))
        local tf, errno = token.open_process(vm, pidfd)
        assert(tf, "open_process_token: " .. sys.errname(errno or 0))
        local privs = assert(token.privileges(vm, tf))
        t:assert(privs.used & TCB ~= 0, "the source token has a used bit to carry")
        fn(w, tf)
        sys.close(vm, tf); sys.close(vm, pidfd)
    end)
end

-- DuplicateToken ---------------------------------------------------------------

test("DuplicateToken requires TOKEN_DUPLICATE on the source handle",
    { spec = "PKM *token.duplicate.requires-token-duplicate" }, function(t)
        local fd = assert(token.mint(vm, {}))
        -- Re-open the same token with a narrower mask by duplicating it
        -- to a QUERY-only handle first.
        local narrow = assert(token.duplicate(vm, fd, { access = token.RIGHT.QUERY }))
        local dup, errno = token.duplicate(vm, narrow, {})
        t:assert(not dup, "a QUERY-only handle cannot duplicate")
        t:assert_eq(errno, sys.E.ACCES, "EACCES")
        t:assert(token.query(vm, narrow, token.CLASS.USER), "though it can still query")
        sys.close(vm, narrow); sys.close(vm, fd)
    end)

test("the token type may change in either direction",
    { spec = "PKM *token.duplicate.type-may-change" }, function(t)
        local prim = assert(token.mint(vm, {}))
        local imp = assert(token.duplicate(vm, prim, { token_type = token.TYPE.IMPERSONATION,
            impersonation_level = token.LEVEL.IMPERSONATION }))
        t:assert_eq(token.query_u32(vm, imp, token.CLASS.TYPE), token.TYPE.IMPERSONATION, "primary → impersonation")
        local back = assert(token.duplicate(vm, imp, { token_type = token.TYPE.PRIMARY,
            impersonation_level = token.LEVEL.IMPERSONATION }))
        t:assert_eq(token.query_u32(vm, back, token.CLASS.TYPE), token.TYPE.PRIMARY, "impersonation → primary")
        t:assert_eq(token.statistics(vm, back).token_type, token.TYPE.PRIMARY, "statistics agree")
        sys.close(vm, prim); sys.close(vm, imp); sys.close(vm, back)
    end)

test("the impersonation level is a ratchet: equal or lower, never higher",
    { spec = "PKM *token.duplicate.level-ratchet" }, function(t)
        local deleg = assert(token.mint(vm, { impersonation_level = token.LEVEL.DELEGATION }))
        for _, lvl in ipairs({ token.LEVEL.DELEGATION, token.LEVEL.IMPERSONATION,
            token.LEVEL.IDENTIFICATION, token.LEVEL.ANONYMOUS }) do
            local d = token.duplicate(vm, deleg, { token_type = token.TYPE.IMPERSONATION,
                impersonation_level = lvl })
            t:assert(d, "a Delegation primary duplicates to an impersonation token at " .. lvl)
            t:assert_eq(token.query_u32(vm, d, token.CLASS.IMPERSONATION_LEVEL), lvl, "at that level")
            sys.close(vm, d)
        end
        local imp = assert(token.mint(vm, { impersonation_level = token.LEVEL.IMPERSONATION }))
        local up, errno = token.duplicate(vm, imp, { token_type = token.TYPE.IMPERSONATION,
            impersonation_level = token.LEVEL.DELEGATION })
        t:assert(not up, "an Impersonation primary cannot yield Delegation")
        t:assert_eq(errno, sys.E.INVAL, "EINVAL")
        local ident = assert(token.duplicate(vm, imp, { token_type = token.TYPE.IMPERSONATION,
            impersonation_level = token.LEVEL.IDENTIFICATION }))
        for _, lvl in ipairs({ token.LEVEL.IMPERSONATION, token.LEVEL.DELEGATION }) do
            local up2, e2 = token.duplicate(vm, ident, { token_type = token.TYPE.IMPERSONATION,
                impersonation_level = lvl })
            t:assert(not up2 and e2 == sys.E.INVAL, "Identification cannot go back up to " .. lvl)
        end
        sys.close(vm, deleg); sys.close(vm, imp); sys.close(vm, ident)
    end)

test("a Primary result below Impersonation is refused",
    { spec = "PKM *token.duplicate.primary-result-floor" }, function(t)
        local src = assert(token.mint(vm, {}))
        for _, lvl in ipairs({ token.LEVEL.IDENTIFICATION, token.LEVEL.ANONYMOUS }) do
            local p, errno = token.duplicate(vm, src, { token_type = token.TYPE.PRIMARY,
                impersonation_level = lvl })
            t:assert(not p, "primary at " .. lvl .. " refused: " .. sys.errname(errno or 0))
        end
        local ok = assert(token.duplicate(vm, src, { token_type = token.TYPE.PRIMARY,
            impersonation_level = token.LEVEL.IMPERSONATION }))
        t:assert_eq(token.query_u32(vm, ok, token.CLASS.IMPERSONATION_LEVEL), token.LEVEL.IMPERSONATION,
            "a primary at Impersonation is the floor")
        sys.close(vm, ok); sys.close(vm, src)
    end)

test("the copy has fresh identity fields and starts at elevation Default",
    { spec = "PKM *token.duplicate.fresh-fields" }, function(t)
        -- A linked Full token, so the reset to Default is visible.
        local elevated, sid = assert(token.mint(vm, { privs_present = TCB, privs_enabled = TCB }))
        local filtered = assert(token.restrict(vm, elevated, { privs = TCB }))
        local link = token.link(vm, elevated, elevated, filtered, sid)
        t:assert_eq(link.ret, 0, "the pair links: " .. sys.errname(link.errno))
        t:assert_eq(token.query_u32(vm, elevated, token.CLASS.ELEVATION_TYPE), token.ELEVATION.FULL,
            "the source is Full")
        local ss = assert(token.statistics(vm, elevated))
        local dup = assert(token.duplicate(vm, elevated, {}))
        local ds = assert(token.statistics(vm, dup))
        t:assert_neq(ds.token_id, ss.token_id, "fresh token_id")
        t:assert_eq(ds.modified_id, ds.token_id, "modified_id initialised to the new token_id")
        t:assert_eq(token.query_u32(vm, dup, token.CLASS.ELEVATION_TYPE), token.ELEVATION.DEFAULT,
            "elevation resets to Default on the copy")
        t:assert_eq(token.query_u32(vm, elevated, token.CLASS.ELEVATION_TYPE), token.ELEVATION.FULL,
            "and stays Full on the source")
        sys.close(vm, dup); sys.close(vm, filtered); sys.close(vm, elevated)
    end)

test("the copy's own descriptor is a fresh default, not the source's",
    { spec = "PKM *token.duplicate.fresh-default-sd" }, function(t)
        local kacs = require("helpers.kacs")
        local src = assert(token.mint(vm, {}))
        local default_sd = assert(token.get_sd(vm, src, kacs.SI.DACL))
        -- Customise the source's DACL: grant Everyone everything.
        local custom = kacs.descriptor(kacs.acl({ kacs.ace(0, token.RIGHT.ALL_ACCESS, token.SID.EVERYONE, 0) }))
        local set = token.set_sd(vm, src, custom, kacs.SI.DACL)
        t:assert_eq(set.ret, 0, "the source's DACL is replaced: " .. sys.errname(set.errno))
        local src_now = assert(token.get_sd(vm, src, kacs.SI.DACL))
        t:assert_neq(src_now, default_sd, "and reads back changed")
        local dup = assert(token.duplicate(vm, src, {}))
        local dup_sd = assert(token.get_sd(vm, dup, kacs.SI.DACL))
        t:assert_eq(dup_sd, default_sd, "the copy carries the default descriptor, not the customised one")
        sys.close(vm, dup); sys.close(vm, src)
    end)

test("everything else is copied — the used privilege state included",
    { spec = "PKM *token.duplicate.copies-everything-else" }, function(t)
        with_used_principal(t, rich_spec(), function(w, src)
            local dup = assert(token.duplicate(vm, src, { token_type = token.TYPE.IMPERSONATION,
                impersonation_level = token.LEVEL.DELEGATION }))
            local diff = differing_classes(vm, src, dup)
            t:assert_eq(#diff, 0, "no queryable class differs: " .. table.concat(diff, ","))
            local sp, dp = assert(token.privileges(vm, src)), assert(token.privileges(vm, dup))
            t:assert_eq(dp.used, sp.used, "the used state is carried across by duplication")
            t:assert(dp.used ~= 0, "and it is non-zero")
            local ss, ds = token.statistics(vm, src), token.statistics(vm, dup)
            t:assert_eq(ds.auth_id, ss.auth_id, "auth_id copied")
            t:assert_eq(ds.expiration, ss.expiration, "expiration copied")
            sys.close(vm, dup)
        end)
    end)

test("duplicating to Impersonation at Anonymous yields the boot Anonymous shape",
    { spec = "PKM *token.duplicate.anonymous-is-fresh-shape" }, function(t)
        local src = assert(token.mint(vm, rich_spec()))
        local anon = assert(token.duplicate(vm, src, { token_type = token.TYPE.IMPERSONATION,
            impersonation_level = token.LEVEL.ANONYMOUS }))
        t:assert_eq(token.sid_string(token.query(vm, anon, token.CLASS.USER)), "S-1-5-7", "user is Anonymous")
        local groups = assert(token.groups(vm, anon))
        t:assert_eq(#groups, 1, "one group")
        t:assert_eq(groups[1].sid, token.SID.EVERYONE, "Everyone")
        local privs = assert(token.privileges(vm, anon))
        t:assert_eq(privs.present, 0, "no privileges")
        t:assert_eq(token.integrity(vm, anon), token.INTEGRITY.UNTRUSTED, "Untrusted integrity")
        t:assert_eq(token.statistics(vm, anon).auth_id, token.ANONYMOUS_LOGON_LUID,
            "LogonSession 998, not the source's")
        t:assert_eq(token.query_u32(vm, anon, token.CLASS.LOGON_TYPE), token.LOGON_TYPE.NETWORK, "logon type Network")
        t:assert_eq(token.query_u32(vm, anon, token.CLASS.TYPE), token.TYPE.IMPERSONATION, "type Impersonation")
        t:assert_eq(token.query_u32(vm, anon, token.CLASS.IMPERSONATION_LEVEL), token.LEVEL.ANONYMOUS, "level Anonymous")
        sys.close(vm, anon); sys.close(vm, src)
    end)

test("the source token is unaffected by duplication",
    { spec = "PKM *token.duplicate.source-unaffected" }, function(t)
        local src = assert(token.mint(vm, rich_spec()))
        local before = {}
        for _, name in ipairs(COPIED) do before[name] = token.query(vm, src, token.CLASS[name]) end
        local bs = token.statistics(vm, src)
        local dup = assert(token.duplicate(vm, src, { token_type = token.TYPE.IMPERSONATION,
            impersonation_level = token.LEVEL.IDENTIFICATION }))
        local anon = assert(token.duplicate(vm, src, { token_type = token.TYPE.IMPERSONATION,
            impersonation_level = token.LEVEL.ANONYMOUS }))
        for _, name in ipairs(COPIED) do
            t:assert_eq(token.query(vm, src, token.CLASS[name]), before[name], name .. " unchanged")
        end
        local as = token.statistics(vm, src)
        t:assert_eq(as.modified_id, bs.modified_id, "modified_id did not move")
        t:assert_eq(token.query_u32(vm, src, token.CLASS.TYPE), token.TYPE.PRIMARY, "still primary")
        sys.close(vm, dup); sys.close(vm, anon); sys.close(vm, src)
    end)

-- FilterToken --------------------------------------------------------------------

test("FilterToken requires TOKEN_DUPLICATE on the source handle",
    { spec = "PKM *token.filter.requires-token-duplicate" }, function(t)
        local fd = assert(token.mint(vm, {}))
        local narrow = assert(token.duplicate(vm, fd, { access = token.RIGHT.QUERY | token.RIGHT.ADJUST_PRIVS }))
        local f, errno = token.restrict(vm, narrow, { privs = 0 })
        t:assert(not f, "a handle without TOKEN_DUPLICATE cannot filter")
        t:assert_eq(errno, sys.E.ACCES, "EACCES")
        sys.close(vm, narrow); sys.close(vm, fd)
    end)

test("filtering removes privileges from all three states at once",
    { spec = "PKM *token.filter.remove-privileges" }, function(t)
        local src = assert(token.mint(vm, { privs_present = TCB | CREATE | token.bit(token.PRIV.BACKUP),
            privs_enabled = TCB | CREATE }))
        local f = assert(token.restrict(vm, src, { privs = TCB | token.bit(token.PRIV.BACKUP) }))
        local p = assert(token.privileges(vm, f))
        t:assert_eq(p.present, CREATE, "present: only SeCreateTokenPrivilege remains")
        t:assert_eq(p.enabled, CREATE, "enabled likewise")
        t:assert_eq(p.default, CREATE, "and enabled-by-default")
        local sp = assert(token.privileges(vm, src))
        t:assert_eq(sp.present, TCB | CREATE | token.bit(token.PRIV.BACKUP), "the source keeps its privileges")
        -- Permanently: nothing re-adds a removed privilege.
        t:assert_neq(token.enable_priv(vm, f, token.PRIV.TCB).ret, 0, "the removed privilege cannot be enabled")
        t:assert_eq(token.reset_privs(vm, f).ret, 0, "reset-to-defaults succeeds")
        t:assert_eq(token.privileges(vm, f).present, CREATE, "and does not bring it back")
        sys.close(vm, f); sys.close(vm, src)
    end)

test("filtering sets groups to deny-only, permanently",
    { spec = "PKM *token.filter.deny-only-groups" }, function(t)
        local src = assert(token.mint(vm, {}))
        local groups = assert(token.groups(vm, src))
        -- Index 2 is TEST_GROUP (Everyone, Authenticated Users, TEST_GROUP, logon).
        local f = assert(token.restrict(vm, src, { deny_indices = { 2 } }))
        local fg = assert(token.groups(vm, f))
        t:assert_eq(fg[3].sid, token.SID.TEST_GROUP, "same SID at index 2")
        t:assert_eq(fg[3].attributes & token.GROUP.USE_FOR_DENY_ONLY, token.GROUP.USE_FOR_DENY_ONLY,
            "marked SE_GROUP_USE_FOR_DENY_ONLY")
        t:assert_eq(groups[3].attributes & token.GROUP.USE_FOR_DENY_ONLY, 0, "the source is not")
        -- No way back: neither an enable nor a reset clears it.
        t:assert_neq(token.adjust_groups(vm, f, { { 2, 1 } }).ret, 0, "it cannot be re-enabled")
        t:assert_eq(token.adjust_groups(vm, f, { { token.GROUP_RESET_INDEX, 0 } }).ret, 0, "reset succeeds")
        t:assert_eq(token.groups(vm, f)[3].attributes & token.GROUP.USE_FOR_DENY_ONLY,
            token.GROUP.USE_FOR_DENY_ONLY, "and leaves it deny-only")
        sys.close(vm, f); sys.close(vm, src)
    end)

test("filtering adds a restricted SID list",
    { spec = "PKM *token.filter.restricted-sids-double-evaluation" }, function(t)
        local src = assert(token.mint(vm, {}))
        t:assert_eq(#token.parse_sid_array(token.query(vm, src, token.CLASS.RESTRICTED_SIDS)), 0,
            "the source is unrestricted")
        local f = assert(token.restrict(vm, src, { restrict_sids = { A, B } }))
        local rs = token.parse_sid_array(assert(token.query(vm, f, token.CLASS.RESTRICTED_SIDS)))
        t:assert_eq(#rs, 2, "two restricting SIDs")
        t:assert(rs[1].sid == A and rs[2].sid == B, "the supplied ones, in order")
        sys.close(vm, f); sys.close(vm, src)
    end)

test("input validation is all-or-nothing",
    { spec = "PKM *token.filter.validation-all-or-nothing" }, function(t)
        local src = assert(token.mint(vm, { privs_present = TCB, privs_enabled = TCB }))
        local bs = token.statistics(vm, src)
        -- One good deny index, one out of range, plus a privilege removal:
        -- nothing happens.
        local f, errno = token.restrict(vm, src, { privs = TCB, deny_indices = { 2, 99 } })
        t:assert(not f, "a single bad entry refuses the call: " .. sys.errname(errno or 0))
        t:assert_eq(token.privileges(vm, src).present, TCB, "the source's privilege is untouched")
        t:assert_eq(token.groups(vm, src)[3].attributes & token.GROUP.USE_FOR_DENY_ONLY, 0,
            "and its good index was not applied either")
        t:assert_eq(token.statistics(vm, src).modified_id, bs.modified_id, "modified_id did not move")
        sys.close(vm, src)
    end)

test("deny-only indices are zero-based, unique and in range",
    { spec = "PKM *token.filter.deny-only-index-rule" }, function(t)
        local src = assert(token.mint(vm, {}))  -- four groups: indices 0..3
        local f = assert(token.restrict(vm, src, { deny_indices = { 0 } }))
        t:assert_eq(token.groups(vm, f)[1].attributes & token.GROUP.USE_FOR_DENY_ONLY,
            token.GROUP.USE_FOR_DENY_ONLY, "index 0 is the first group")
        sys.close(vm, f)
        local bad, errno = token.restrict(vm, src, { deny_indices = { 4 } })
        t:assert(not bad, "index 4 (one past the end) is invalid: " .. sys.errname(errno or 0))
        bad, errno = token.restrict(vm, src, { deny_indices = { 1, 1 } })
        t:assert(not bad, "a duplicate index is invalid: " .. sys.errname(errno or 0))
        sys.close(vm, src)
    end)

test("the restricting SID blob has to parse exactly",
    { spec = "PKM *token.filter.sid-blob-exact" }, function(t)
        local src = assert(token.mint(vm, {}))
        local bad, errno = token.restrict(vm, src, { restrict_sids = { A },
            raw_data = A .. "\0\0\0\0", data_len = #A + 4 })
        t:assert(not bad, "trailing bytes are refused: " .. sys.errname(errno or 0))
        bad, errno = token.restrict(vm, src, { restrict_sids = { A },
            raw_data = A:sub(1, #A - 2), data_len = #A - 2 })
        t:assert(not bad, "a truncated SID is refused: " .. sys.errname(errno or 0))
        bad, errno = token.restrict(vm, src, { restrict_sids = { A, B }, raw_data = A, data_len = #A })
        t:assert(not bad, "fewer SIDs than declared is refused: " .. sys.errname(errno or 0))
        sys.close(vm, src)
    end)

test("an empty intersection with an already-restricted source is invalid",
    { spec = "PKM *token.filter.empty-intersection-invalid" }, function(t)
        local src = assert(token.mint(vm, { restricted_sids = { { sid = A, attributes = ENABLED } } }))
        local bad, errno = token.restrict(vm, src, { restrict_sids = { B } })
        t:assert(not bad, "{A} ∩ {B} = ∅ is refused: " .. sys.errname(errno or 0))
        local ok = token.restrict(vm, src, { restrict_sids = { A, B } })
        t:assert(ok, "{A} ∩ {A,B} is not empty")
        sys.close(vm, ok); sys.close(vm, src)
    end)

test("the filtered token has fresh identity fields and elevation Default",
    { spec = "PKM *token.filter.fresh-fields" }, function(t)
        local elevated, sid = assert(token.mint(vm, { privs_present = TCB, privs_enabled = TCB }))
        local limited = assert(token.restrict(vm, elevated, { privs = TCB }))
        t:assert_eq(token.link(vm, elevated, elevated, limited, sid).ret, 0, "linked")
        t:assert_eq(token.query_u32(vm, elevated, token.CLASS.ELEVATION_TYPE), token.ELEVATION.FULL, "Full")
        local f = assert(token.restrict(vm, elevated, { privs = 0 }))
        local es, fs = token.statistics(vm, elevated), token.statistics(vm, f)
        t:assert_neq(fs.token_id, es.token_id, "fresh token_id")
        t:assert_eq(fs.modified_id, fs.token_id, "modified_id initialised to it")
        t:assert_eq(token.query_u32(vm, f, token.CLASS.ELEVATION_TYPE), token.ELEVATION.DEFAULT,
            "elevation Default on the filtered copy")
        sys.close(vm, f); sys.close(vm, limited); sys.close(vm, elevated)
    end)

test("filtering resets the used state to zero, unlike duplication",
    { spec = "PKM *token.filter.used-resets" }, function(t)
        with_used_principal(t, rich_spec(), function(w, src)
            local f = assert(token.restrict(vm, src, { privs = 0 }))
            local sp, fp = assert(token.privileges(vm, src)), assert(token.privileges(vm, f))
            t:assert(sp.used ~= 0, "the source has used bits")
            t:assert_eq(fp.used, 0, "the filtered copy has none")
            t:assert_eq(fp.present, sp.present, "while present is copied")
            t:assert_eq(fp.enabled, sp.enabled, "and enabled")
            sys.close(vm, f)
        end)
    end)

test("filtering keeps the group SIDs, changing only attributes",
    { spec = "PKM *token.filter.groups-unchanged-except-attributes" }, function(t)
        local src = assert(token.mint(vm, rich_spec()))
        local sg = assert(token.groups(vm, src))
        local f = assert(token.restrict(vm, src, { deny_indices = { 0 } }))
        local fg = assert(token.groups(vm, f))
        t:assert_eq(#fg, #sg, "same count")
        for i = 1, #sg do
            t:assert_eq(fg[i].sid, sg[i].sid, "same SID at " .. i)
            if i ~= 1 then t:assert_eq(fg[i].attributes, sg[i].attributes, "same attributes at " .. i) end
        end
        t:assert_eq(fg[1].attributes, sg[1].attributes | token.GROUP.USE_FOR_DENY_ONLY,
            "only the named index gained deny-only")
        sys.close(vm, f); sys.close(vm, src)
    end)

test("restricted SIDs intersect with an already-restricted source's list",
    { spec = "PKM *token.filter.restricted-sids-intersection" }, function(t)
        local src = assert(token.mint(vm, { restricted_sids = {
            { sid = A, attributes = ENABLED }, { sid = B, attributes = ENABLED } } }))
        local f = assert(token.restrict(vm, src, { restrict_sids = { B, C } }))
        local rs = token.parse_sid_array(assert(token.query(vm, f, token.CLASS.RESTRICTED_SIDS)))
        t:assert_eq(#rs, 1, "{A,B} ∩ {B,C} has one member")
        t:assert_eq(rs[1].sid, B, "B")
        sys.close(vm, f); sys.close(vm, src)
    end)

test("everything else is copied by filtering",
    { spec = "PKM *token.filter.copies-everything-else" }, function(t)
        local src = assert(token.mint(vm, rich_spec()))
        local f = assert(token.restrict(vm, src, { privs = 0 }))
        local diff = differing_classes(vm, src, f)
        t:assert_eq(#diff, 0, "no queryable class differs: " .. table.concat(diff, ","))
        local ss, fs = token.statistics(vm, src), token.statistics(vm, f)
        t:assert_eq(fs.auth_id, ss.auth_id, "auth_id copied")
        t:assert_eq(fs.expiration, ss.expiration, "expiration copied")
        t:assert_eq(fs.token_type, ss.token_type, "type copied")
        t:assert_eq(token.query_u32(vm, f, token.CLASS.IMPERSONATION_LEVEL),
            token.query_u32(vm, src, token.CLASS.IMPERSONATION_LEVEL), "level copied")
        sys.close(vm, f); sys.close(vm, src)
    end)

-- What no query class exposes runs under KUnit.
local function kunit_stub(name, spec, case, why)
    test(name, { spec = spec, covered_by = "kunit:pkm_kunit_token",
                 skip = why .. "; runs under " .. case }, function(t) end)
end

kunit_stub("write-restricted mode forces user_deny_only on the new token",
    "PKM *token.filter.write-restricted-forces-deny-only",
    "pkm_kunit_token_restrict_write_restricted_sets_user_deny_only",
    "neither write_restricted nor user_deny_only has a query class (§3.D)")

kunit_stub("write_restricted is sticky from the source",
    "PKM *token.filter.write-restricted-sticky",
    "pkm_kunit_token_restrict_write_restricted_sticky_from_source",
    "write_restricted has no query class (§3.D)")
