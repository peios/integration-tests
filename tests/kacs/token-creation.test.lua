-- PKM §3.2.4 — CreateToken: what the caller supplies, what the kernel
-- generates, and every structural invariant the spec is validated
-- against. The agent is SYSTEM and holds SeCreateTokenPrivilege, so the
-- privilege gate itself is tested from a minted principal that lacks it.

local sys = require("helpers.sys")
local token = require("helpers.token")

local vm = provium:vm("v", "kernel-only"):boot()

local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED

--- A distinct local-account SID for group i.
local function group_sid(i) return token.sid(5, 21, 1000, 2000, 3000, 10000 + i) end

--- Mint in a fresh session with the given spec overrides; returns fd (or
--- nil, errno) and the session id.
local function mint(spec) return token.mint(vm, spec) end

test("CreateToken is gated by SeCreateTokenPrivilege, held and enabled",
    { spec = "PKM *token.create.privilege-gate" }, function(t)
        -- A principal with SeTcbPrivilege (to create the session) and
        -- SeCreateTokenPrivilege present but disabled.
        token.as_principal(t, vm, {
            privs_present = token.bit(token.PRIV.TCB) | token.bit(token.PRIV.CREATE_TOKEN),
            privs_enabled = token.bit(token.PRIV.TCB),
        }, function(w)
            local sid = assert(token.create_logon_session(w, {}))
            local fd, errno = token.create(w, { auth_id = sid })
            t:assert(not fd, "held-but-disabled SeCreateTokenPrivilege is refused")
            -- §3.2.4 names no errno for the gate; the kernel says EPERM.
            t:assert_eq(errno, sys.E.PERM, "with EPERM")
            local own = assert(token.open_self(w, token.RIGHT.ADJUST_PRIVS | token.RIGHT.QUERY))
            t:assert_eq(token.enable_priv(w, own, token.PRIV.CREATE_TOKEN).ret, 0,
                "the principal enables it on its own token")
            fd, errno = token.create(w, { auth_id = sid })
            t:assert(fd, "and CreateToken now succeeds: " .. sys.errname(errno or 0))
            local privs = assert(token.privileges(w, own))
            t:assert(privs.used & token.bit(token.PRIV.CREATE_TOKEN) ~= 0,
                "the exercise is recorded in the used state")
        end)
        -- And a principal that does not hold it at all.
        token.as_principal(t, vm, { privs_present = token.bit(token.PRIV.TCB),
            privs_enabled = token.bit(token.PRIV.TCB) }, function(w)
            local sid = assert(token.create_logon_session(w, {}))
            local fd, errno = token.create(w, { auth_id = sid })
            t:assert(not fd, "a token without the privilege cannot mint")
            t:assert_eq(errno, sys.E.PERM, "EPERM")
        end)
    end)

test("the kernel injects no implicit groups — the logon SID is the only one it adds",
    { spec = "PKM *token.create.no-implicit-groups" }, function(t)
        local fd, sid = mint({ groups = {} })
        t:assert(fd, "a token with no caller groups mints: " .. sys.errname(sid or 0))
        local groups = assert(token.groups(vm, fd))
        t:assert_eq(#groups, 1, "exactly one group")
        t:assert_eq(groups[1].sid, token.logon_sid(sid), "and it is the logon SID")
        t:assert(not token.find_group(groups, token.SID.EVERYONE), "no Everyone")
        t:assert(not token.find_group(groups, token.SID.AUTHENTICATED_USERS), "no Authenticated Users")
        sys.close(vm, fd)
    end)

test("the kernel generates the bookkeeping fields",
    { spec = "PKM *token.create.kernel-generated-fields" }, function(t)
        local a, sid = mint({})
        local b = assert(mint({ auth_id = sid }))
        local sa, sb = assert(token.statistics(vm, a)), assert(token.statistics(vm, b))
        t:assert(sa.token_id ~= 0 and sb.token_id ~= 0, "token ids are non-zero LUIDs")
        t:assert_neq(sa.token_id, sb.token_id, "and distinct per token")
        t:assert_eq(sa.modified_id, sa.token_id, "modified_id initialised to token_id")
        t:assert_eq(sa.auth_id, sid, "auth_id is the session")
        t:assert_eq(token.query_u32(vm, a, token.CLASS.ELEVATION_TYPE), token.ELEVATION.DEFAULT,
            "elevation_type is always Default")
        t:assert_eq(token.query(vm, a, token.CLASS.LOGON_SID),
            token.sid(5, 5, sid >> 32, sid & 0xFFFFFFFF),
            "logon SID is S-1-5-5-{id>>32}-{id&0xFFFFFFFF}")
        sys.close(vm, a); sys.close(vm, b)
    end)

test("the logon SID is appended after the caller's groups with the fixed attributes",
    { spec = "PKM *token.create.logon-sid-appended" }, function(t)
        local fd, sid = assert(mint({}))
        local groups = assert(token.groups(vm, fd))
        local last = groups[#groups]
        t:assert_eq(last.sid, token.logon_sid(sid), "the logon SID is the last entry")
        t:assert_eq(last.attributes, ENABLED | token.GROUP.LOGON_ID,
            "MANDATORY | ENABLED_BY_DEFAULT | ENABLED | LOGON_ID")
        t:assert_eq(groups[1].sid, token.SID.EVERYONE, "caller groups keep their order before it")
        sys.close(vm, fd)
    end)

test("owner and primary-group indices count the caller's groups, not the injected logon SID",
    { spec = "PKM *token.create.indices-relative-to-caller-groups" }, function(t)
        local groups = {
            { sid = token.SID.EVERYONE, attributes = ENABLED },
            { sid = token.SID.TEST_GROUP, attributes = ENABLED | token.GROUP.OWNER },
            { sid = token.SID.TEST_GROUP_2, attributes = ENABLED },
        }
        local fd = assert(mint({ groups = groups, owner_sid_index = 2, primary_group_index = 3 }))
        t:assert_eq(token.query(vm, fd, token.CLASS.OWNER), token.SID.TEST_GROUP,
            "owner index 2 is the caller's second group")
        t:assert_eq(token.query(vm, fd, token.CLASS.PRIMARY_GROUP), token.SID.TEST_GROUP_2,
            "primary group index 3 is the caller's third")
        sys.close(vm, fd)
        -- Index 4 would be the logon SID's slot in the stored array; it is
        -- not addressable at creation.
        local bad, errno = mint({ groups = groups, primary_group_index = 4 })
        t:assert(not bad, "an index past the caller's groups is refused: " .. sys.errname(errno or 0))
        local zero = assert(mint({ groups = groups, owner_sid_index = 0, primary_group_index = 0 }))
        t:assert_eq(token.query(vm, zero, token.CLASS.OWNER), token.SID.TEST_USER, "index 0 is the user SID")
        sys.close(vm, zero)
    end)

test("every SID has to be structurally well-formed",
    { spec = "PKM *token.create.validate.sids-well-formed" }, function(t)
        -- sub_authority_count 20 exceeds the 15-sub-authority maximum.
        local bad_user = string.pack("<I1I1", 1, 20) .. string.pack(">I2I4", 0, 5) .. string.rep("\0", 80)
        local fd, errno = mint({ user_sid = bad_user })
        t:assert(not fd, "an over-long user SID is refused: " .. sys.errname(errno or 0))
        -- A group SID whose declared length runs past its bytes.
        local truncated = token.SID.TEST_GROUP:sub(1, 10)
        fd, errno = mint({ groups = { { sid = truncated, attributes = ENABLED } } })
        t:assert(not fd, "a truncated group SID is refused: " .. sys.errname(errno or 0))
        -- Revision 2 does not exist.
        local rev2 = "\2" .. token.SID.TEST_USER:sub(2)
        fd, errno = mint({ user_sid = rev2 })
        t:assert(not fd, "revision 2 is refused: " .. sys.errname(errno or 0))
    end)

test("the owner SID has to be the user SID or a group carrying SE_GROUP_OWNER",
    { spec = "PKM *token.create.validate.owner-sid" }, function(t)
        local fd, errno = mint({ owner_sid_index = 3 })  -- TEST_GROUP, no OWNER attribute
        t:assert(not fd, "a group without SE_GROUP_OWNER cannot be the owner: " .. sys.errname(errno or 0))
        fd = assert(mint({ groups = {
            { sid = token.SID.EVERYONE, attributes = ENABLED },
            { sid = token.SID.TEST_GROUP, attributes = ENABLED | token.GROUP.OWNER },
        }, owner_sid_index = 2 }))
        t:assert_eq(token.query(vm, fd, token.CLASS.OWNER), token.SID.TEST_GROUP, "with the attribute it can")
        sys.close(vm, fd)
    end)

test("the primary group has to be the user SID or a group on the token",
    { spec = "PKM *token.create.validate.primary-group-sid" }, function(t)
        local fd = assert(mint({ primary_group_index = 3 }))  -- any group qualifies
        t:assert_eq(token.query(vm, fd, token.CLASS.PRIMARY_GROUP), token.SID.TEST_GROUP,
            "an ordinary group is a valid primary group")
        sys.close(vm, fd)
        local bad, errno = mint({ primary_group_index = 9 })
        t:assert(not bad, "an index beyond the groups is refused: " .. sys.errname(errno or 0))
    end)

test("auth_id has to name an existing LogonSession",
    { spec = "PKM *token.create.validate.auth-id-exists" }, function(t)
        local fd, errno = token.create(vm, { auth_id = 0x7FFFFFFF00001234 })
        t:assert(not fd, "an unknown session id is refused: " .. sys.errname(errno or 0))
        fd, errno = token.create(vm, { auth_id = 0 })
        t:assert(not fd, "and so is zero: " .. sys.errname(errno or 0))
    end)

test("a Primary token has to carry impersonation level Impersonation or Delegation",
    { spec = "PKM *token.create.validate.primary-level-floor" }, function(t)
        for _, lvl in ipairs({ token.LEVEL.IDENTIFICATION, token.LEVEL.ANONYMOUS }) do
            local fd, errno = mint({ impersonation_level = lvl })
            t:assert(not fd, "primary at level " .. lvl .. " refused: " .. sys.errname(errno or 0))
        end
        local imp = assert(mint({ impersonation_level = token.LEVEL.IMPERSONATION }))
        t:assert_eq(token.query_u32(vm, imp, token.CLASS.IMPERSONATION_LEVEL), token.LEVEL.IMPERSONATION,
            "a primary at Impersonation mints")
        sys.close(vm, imp)
        local ident = assert(mint({ token_type = token.TYPE.IMPERSONATION,
            impersonation_level = token.LEVEL.IDENTIFICATION }))
        t:assert_eq(token.query_u32(vm, ident, token.CLASS.IMPERSONATION_LEVEL), token.LEVEL.IDENTIFICATION,
            "an impersonation token may be minted at Identification")
        sys.close(vm, ident)
    end)

test("write_restricted requires user_deny_only",
    { spec = "PKM *token.create.validate.deny-only-with-write-restricted" }, function(t)
        local restricted = { { sid = token.SID.TEST_GROUP, attributes = ENABLED } }
        local fd, errno = mint({ write_restricted = true, restricted_sids = restricted })
        t:assert(not fd, "write_restricted without user_deny_only is refused: " .. sys.errname(errno or 0))
        fd = mint({ write_restricted = true, user_deny_only = true, restricted_sids = restricted })
        t:assert(fd, "with user_deny_only it mints")
        sys.close(vm, fd)
    end)

test("isolation_boundary requires a confinement SID",
    { spec = "PKM *token.create.validate.isolation-needs-confinement" }, function(t)
        local fd, errno = mint({ isolation_boundary = true })
        t:assert(not fd, "isolation without confinement is refused: " .. sys.errname(errno or 0))
        fd = mint({ isolation_boundary = true, confinement_sid = token.sid(15, 2, 1, 2, 3, 4, 5, 6, 7) })
        t:assert(fd, "with a confinement SID it mints")
        t:assert_eq(token.query(vm, fd, token.CLASS.APPCONTAINER_SID), token.sid(15, 2, 1, 2, 3, 4, 5, 6, 7),
            "and the confinement SID reads back")
        sys.close(vm, fd)
    end)

test("the wire format's elevation_type slot has to be zero",
    { spec = "PKM *token.create.validate.elevation-type-zero" }, function(t)
        for _, v in ipairs({ token.ELEVATION.DEFAULT, token.ELEVATION.FULL, token.ELEVATION.LIMITED }) do
            local fd, errno = mint({ reserved1 = v })
            t:assert(not fd, "reserved elevation slot " .. v .. " refused: " .. sys.errname(errno or 0))
        end
    end)

test("1023 caller groups fit; 1024 do not",
    { spec = "PKM *token.create.validate.group-limit" }, function(t)
        local function many(n)
            local g = {}
            for i = 1, n do g[i] = { sid = group_sid(i), attributes = ENABLED } end
            return g
        end
        local fd, sid = mint({ groups = many(1023) })
        t:assert(fd, "1023 caller groups mint: " .. sys.errname(sid or 0))
        t:assert_eq(#assert(token.groups(vm, fd)), 1024, "the array holds 1024 with the logon SID")
        sys.close(vm, fd)
        local bad, errno = mint({ groups = many(1024) })
        t:assert(not bad, "1024 caller groups are refused: " .. sys.errname(errno or 0))
    end)

--- The LCS extension: header + GUIDs + name lengths + names.
local function lcs_ext(guids, names, opts)
    opts = opts or {}
    local out = { string.pack("<I4I4I4I4", opts.version or 1, opts.reserved or 0, #guids, #names) }
    for _, g in ipairs(guids) do out[#out + 1] = g end
    for _, n in ipairs(names) do out[#out + 1] = string.pack("<I4", #n) end
    for _, n in ipairs(names) do out[#out + 1] = n end
    return table.concat(out) .. (opts.trailing or "")
end
local function guid(i) return string.pack("<I8I8", 0x1111222233334444, i) end

test("the LCS credential extension is bounded and de-duplicated",
    { spec = "PKM *token.create.lcs-extension-limits" }, function(t)
        local fd = mint({ lcs_credentials = lcs_ext({ guid(1), guid(2) }, { "Audit", "Policy" }) })
        t:assert(fd, "two scopes and two layers mint")
        sys.close(vm, fd)
        local cases = {
            { "257 scope GUIDs", (function()
                local g = {}; for i = 1, 257 do g[i] = guid(i) end; return lcs_ext(g, {}) end)() },
            { "a nil scope GUID", lcs_ext({ string.rep("\0", 16) }, {}) },
            { "a duplicate scope GUID", lcs_ext({ guid(1), guid(1) }, {}) },
            { "an empty layer name", lcs_ext({}, { "" }) },
            { "an overlong layer name", lcs_ext({}, { string.rep("x", 256) }) },
            { "case-insensitive duplicate layer names", lcs_ext({}, { "Audit", "audit" }) },
            { "a layer name with a slash", lcs_ext({}, { "a/b" }) },
            { "257 layer names", (function()
                local n = {}; for i = 1, 257 do n[i] = "layer" .. i end; return lcs_ext({}, n) end)() },
            { "the wrong extension version", lcs_ext({ guid(1) }, {}, { version = 2 }) },
        }
        for _, c in ipairs(cases) do
            local bad, errno = mint({ lcs_credentials = c[2] })
            t:assert(not bad, c[1] .. " is refused: " .. sys.errname(errno or 0))
        end
        -- Exactly at the limits is fine.
        local g, n = {}, {}
        for i = 1, 256 do g[i] = guid(i); n[i] = "layer" .. i end
        fd = mint({ lcs_credentials = lcs_ext(g, n) })
        t:assert(fd, "256 of each mint")
        sys.close(vm, fd)
    end)

test("malformed LCS credentials fail the whole call",
    { spec = "PKM *token.create.lcs-malformed-fails-closed" }, function(t)
        -- Trailing bytes after the extension: the section has to be
        -- consumed exactly. No token is created.
        local before = token.create_logon_session(vm, {})
        local fd, errno = token.create(vm, { auth_id = before,
            lcs_credentials = lcs_ext({ guid(1) }, { "Audit" }, { trailing = "\0\0\0\0" }) })
        t:assert(not fd, "trailing bytes are refused: " .. sys.errname(errno or 0))
        -- The session never acquired a live token, so the rollback path
        -- still applies — evidence that nothing was created.
        t:assert_eq(token.destroy_empty_logon_session(vm, before).ret, 0,
            "the session is still empty: no token was minted")
    end)

test("CreateToken returns a handle carrying TOKEN_ALL_ACCESS",
    { spec = "PKM *token.create.returns-all-access" }, function(t)
        local fd = assert(mint({}))
        -- Rights the default descriptor would not grant the subject, so
        -- only a cached ALL_ACCESS explains their working.
        local dup = token.duplicate(vm, fd, { token_type = token.TYPE.IMPERSONATION,
            impersonation_level = token.LEVEL.IDENTIFICATION })
        t:assert(dup, "TOKEN_DUPLICATE is on the handle")
        sys.close(vm, dup)
        t:assert_eq(token.adjust_interactivity_scope(vm, fd, 7).ret, 0,
            "TOKEN_ADJUST_INTERACTIVITY_SCOPE is on the handle")
        t:assert_eq(token.query_u32(vm, fd, token.CLASS.INTERACTIVITY_SCOPE), 7, "and took effect")
        sys.close(vm, fd)
        -- TOKEN_ASSIGN_PRIMARY: a worker installs a token it just minted.
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local wfd = assert(token.mint(worker, {}))
            local r = token.install(worker, wfd)
            t:assert_eq(r.ret, 0, "TOKEN_ASSIGN_PRIMARY is on the handle: " .. sys.errname(r.errno))
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
    end)
