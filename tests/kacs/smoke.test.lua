-- The KACS chapter's smoke test: the token helper can reach every
-- surface the rest of the suite depends on — open, query, mint,
-- derive, install — before any conformance case asks a real question.

local sys = require("helpers.sys")
local token = require("helpers.token")

local vm = provium:vm("v", "kernel-only"):boot()

test("the agent runs as SYSTEM and can read its own token back",
    { spec = "PKM *token.bootstrap.system-token" }, function(t)
        local fd = assert(token.open_self(vm))
        local user = assert(token.query(vm, fd, token.CLASS.USER))
        t:assert_eq(token.sid_string(user), "S-1-5-18", "user SID is Local System")
        t:assert_eq(token.query_u32(vm, fd, token.CLASS.TYPE), token.TYPE.PRIMARY, "primary")
        t:assert_eq(token.query_u32(vm, fd, token.CLASS.IMPERSONATION_LEVEL),
            token.LEVEL.DELEGATION, "at Delegation")
        t:assert_eq(token.query_u32(vm, fd, token.CLASS.ELEVATION_TYPE),
            token.ELEVATION.DEFAULT, "elevation Default")
        t:assert_eq(token.integrity(vm, fd), token.INTEGRITY.SYSTEM, "System integrity")
        local st = assert(token.statistics(vm, fd))
        t:assert_eq(st.auth_id, token.SYSTEM_LUID, "auth_id is SYSTEM_LUID")
        local src = assert(token.source(vm, fd))
        t:assert_eq(src.name, "PeiosKrn", "source PeiosKrn")
        local groups = assert(token.groups(vm, fd))
        t:assert(token.find_group(groups, token.SID.ADMINISTRATORS), "Administrators present")
        t:assert(token.find_group(groups, token.SID.EVERYONE), "Everyone present")
        t:assert(token.find_group(groups, token.SID.AUTHENTICATED_USERS), "Authenticated Users present")
        local privs = assert(token.privileges(vm, fd))
        t:assert(privs.present & token.bit(token.PRIV.TCB) ~= 0, "SeTcbPrivilege present")
        t:assert(privs.enabled & token.bit(token.PRIV.CREATE_TOKEN) ~= 0, "SeCreateTokenPrivilege enabled")
        sys.close(vm, fd)
    end)

test("a LogonSession and a token can be minted and read back",
    { spec = "PKM *token.create.kernel-generated-fields" }, function(t)
        local fd, sid = token.mint(vm, {})
        t:assert(fd, "mint: " .. sys.errname(sid or 0))
        t:assert(sid >= 1000, "dynamic session ids start at 1000: " .. tostring(sid))
        local user = assert(token.query(vm, fd, token.CLASS.USER))
        t:assert_eq(user, token.SID.TEST_USER, "user SID as supplied")
        local st = assert(token.statistics(vm, fd))
        t:assert_eq(st.auth_id, sid, "auth_id is the session")
        t:assert_eq(st.modified_id, st.token_id, "modified_id starts at token_id")
        local groups = assert(token.groups(vm, fd))
        t:assert_eq(#groups, 4, "three caller groups plus the logon SID")
        local logon = token.find_group(groups, token.logon_sid(sid))
        t:assert(logon, "logon SID materialised in groups")
        t:assert_eq(logon.attributes & token.GROUP.LOGON_ID, token.GROUP.LOGON_ID, "carrying SE_GROUP_LOGON_ID")
        t:assert_eq(token.query(vm, fd, token.CLASS.LOGON_SID), token.logon_sid(sid), "LOGON_SID class agrees")
        t:assert_eq(token.query_u32(vm, fd, token.CLASS.ELEVATION_TYPE), token.ELEVATION.DEFAULT, "Default elevation")

        local dup = token.duplicate(vm, fd, { token_type = token.TYPE.IMPERSONATION,
            impersonation_level = token.LEVEL.IMPERSONATION })
        t:assert(dup, "duplicate")
        t:assert_eq(token.query_u32(vm, dup, token.CLASS.TYPE), token.TYPE.IMPERSONATION, "type changed")
        local filtered = token.restrict(vm, fd, { deny_indices = { 2 } })
        t:assert(filtered, "restrict")
        local fg = assert(token.groups(vm, filtered))
        t:assert_eq(fg[3].attributes & token.GROUP.USE_FOR_DENY_ONLY, token.GROUP.USE_FOR_DENY_ONLY,
            "group index 2 is deny-only on the copy")
        sys.close(vm, dup); sys.close(vm, filtered); sys.close(vm, fd)
    end)

test("a minted token can be installed in a worker",
    { spec = "PKM *token.install.process-wide" }, function(t)
        token.as_principal(t, vm, {}, function(w)
            -- The minted token's own descriptor grants its subject
            -- TOKEN_QUERY and the adjust rights, not ALL_ACCESS (§3.2.8).
            local fd, errno = token.open_self(w, token.RIGHT.QUERY)
            t:assert(fd, "open_self as TEST_USER: " .. sys.errname(errno or 0))
            t:assert_eq(token.query(w, fd, token.CLASS.USER), token.SID.TEST_USER, "worker is TEST_USER")
            sys.close(w, fd)
        end)
        local fd = assert(token.open_self(vm))
        t:assert_eq(token.sid_string(assert(token.query(vm, fd, token.CLASS.USER))), "S-1-5-18",
            "the agent itself is unchanged")
        sys.close(vm, fd)
    end)
