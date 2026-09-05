-- PKM §3.A — the generated ABI appendix, token / socket / System V IPC
-- constants. Each table is checked by driving the syscall the constant
-- governs with the published value and, where the kernel can tell,
-- showing that a value outside the table is refused.
--
-- A constant is testable because the kernel disagrees with a wrong one:
-- an ioctl whose type byte is not KACS_IOC_MAGIC is ENOTTY, an
-- information class outside the enumeration is EINVAL, an option under
-- a level other than SOL_KACS never reaches KACS at all. The struct
-- layouts of the same appendix are in abi-structs.test.lua, the
-- AccessCheck / file / SD / SID constants in abi-constants.test.lua,
-- and the tracepoint vocabularies in abi-tracepoints.test.lua.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local access = require("helpers.access")
local kmes = require("helpers.kmes")
local unix = require("helpers.unixsock")

local vm = provium:vm("v", "kernel-only"):boot()

local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT
    | token.GROUP.ENABLED

local function fresh(spec)
    local fd, e = token.mint(vm, spec or {})
    assert(fd, "mint: " .. sys.errname(e or 0))
    return fd
end

--- The LCS credential extension section: header, GUIDs, name lengths,
--- names — laid out at the KACS_TOKEN_LCS_EXT_OFF_* offsets.
local function lcs_ext(guids, names, opts)
    opts = opts or {}
    local out = { string.pack("<I4I4I4I4", opts.version or 1,
        opts.reserved or 0, #guids, #names) }
    for _, g in ipairs(guids) do out[#out + 1] = g end
    for _, n in ipairs(names) do out[#out + 1] = string.pack("<I4", #n) end
    for _, n in ipairs(names) do out[#out + 1] = n end
    return table.concat(out)
end
local function guid(i) return string.pack("<I8I8", 0x1111222233334444, i) end

--- A create-logon-session spec laid out field by field at the published
--- offsets, so a case can put a wrong value in one of them.
local function session_spec(logon_type, pkg, user_sid, pkg_len_override)
    return string.pack("<I1I2", logon_type, pkg_len_override or #pkg) .. pkg
        .. string.pack("<I4", #user_sid) .. user_sid
end

test("KACS_TOKEN_OPEN_REAL selects the primary token behind an impersonation",
    { spec = "PKM *kacs-abi.open-self-token-flags" }, function(t)
        -- The flag is only visible while the two differ, so the worker
        -- installs a primary and impersonates a token derived from it:
        -- flags 0 is the impersonation token, 0x01 the primary.
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local prim = assert(token.mint(worker, {}))
            local imp = assert(token.duplicate(worker, prim, {
                token_type = token.TYPE.IMPERSONATION,
                impersonation_level = token.LEVEL.IMPERSONATION }))
            t:assert_eq(token.install(worker, prim).ret, 0, "a primary is installed")
            t:assert_eq(token.impersonate(worker, imp).ret, 0, "and impersonated over")
            local eff, e1 = token.open_self(worker, token.RIGHT.QUERY, 0)
            t:assert(eff, "flags 0 opens: " .. sys.errname(e1 or 0))
            t:assert_eq(token.query_u32(worker, eff, token.CLASS.TYPE),
                token.TYPE.IMPERSONATION, "and is the effective token")
            local real, e2 = token.open_self(worker, token.RIGHT.QUERY,
                token.OPEN_REAL)
            t:assert(real, "KACS_TOKEN_OPEN_REAL opens: " .. sys.errname(e2 or 0))
            t:assert_eq(token.query_u32(worker, real, token.CLASS.TYPE),
                token.TYPE.PRIMARY, "and is the primary behind it")
            token.revert(worker)
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
    end)

test("each per-handle token right gates exactly its own operation",
    { spec = "PKM *kacs-abi.token-access-rights" }, function(t)
        local R = token.RIGHT
        -- SeBackupPrivilege is present so that the adjustment case turns
        -- on the access right rather than on the privilege being absent.
        local source = fresh({ privs_present = token.bit(token.PRIV.BACKUP),
            groups = {
                { sid = token.SID.EVERYONE,
                  attributes = ENABLED | token.GROUP.OWNER },
                -- Not mandatory: a mandatory group cannot be adjusted at
                -- all, which would mask the access-right question.
                { sid = token.SID.TEST_GROUP,
                  attributes = token.GROUP.ENABLED_BY_DEFAULT
                      | token.GROUP.ENABLED },
            } })
        local dacl = access.acl({ access.ace(access.ACE.ALLOWED, R.QUERY,
            token.SID.EVERYONE) })
        local ops = {
            { "KACS_TOKEN_ASSIGN_PRIMARY", R.ASSIGN_PRIMARY, function(fd)
                return token.install(vm, fd).errno end },
            { "KACS_TOKEN_DUPLICATE", R.DUPLICATE, function(fd)
                local h, e = token.duplicate(vm, fd, { access = R.QUERY })
                if h then sys.close(vm, h); return 0 end
                return e end },
            { "KACS_TOKEN_IMPERSONATE", R.IMPERSONATE, function(fd)
                return token.impersonate(vm, fd).errno end },
            { "KACS_TOKEN_QUERY", R.QUERY, function(fd)
                local p, e = token.query(vm, fd, token.CLASS.TYPE)
                return p and 0 or e end },
            { "KACS_TOKEN_ADJUST_PRIVS", R.ADJUST_PRIVS, function(fd)
                return token.enable_priv(vm, fd, token.PRIV.BACKUP).errno end },
            { "KACS_TOKEN_ADJUST_GROUPS", R.ADJUST_GROUPS, function(fd)
                return token.adjust_groups(vm, fd, { { 1, 1 } }).errno end },
            { "KACS_TOKEN_ADJUST_DEFAULT", R.ADJUST_DEFAULT, function(fd)
                return token.adjust_default(vm, fd,
                    { dacl = dacl, owner_index = 0, group_index = 0 }).errno end },
            { "KACS_TOKEN_ADJUST_INTERACTIVITY_SCOPE",
              R.ADJUST_INTERACTIVITY_SCOPE, function(fd)
                return token.adjust_interactivity_scope(vm, fd, 2).errno end },
        }
        for _, op in ipairs(ops) do
            -- Every right but this one: the operation is refused.
            local without = assert(token.duplicate(vm, source,
                { access = R.ALL_ACCESS & ~op[2] }))
            t:assert_eq(op[3](without), sys.E.ACCES,
                op[1] .. " is required for its operation")
            sys.close(vm, without)
        end
        -- KACS_TOKEN_QUERY_SOURCE is 0x0010, its own bit: a handle
        -- carrying only it is not a query handle.
        local qs = assert(token.duplicate(vm, source,
            { access = R.QUERY_SOURCE }))
        local p, e = token.query(vm, qs, token.CLASS.TYPE)
        t:assert(not p, "0x0010 alone is not KACS_TOKEN_QUERY (0x0008)")
        t:assert_eq(e, sys.E.ACCES, "and a query through it is refused")
        sys.close(vm, qs)
        -- KACS_TOKEN_ALL_ACCESS is 0x000F01FF exactly: it carries every
        -- one of the rights above, and one bit more is not a right.
        local all = assert(token.duplicate(vm, source, { access = R.ALL_ACCESS }))
        for _, op in ipairs(ops) do
            if op[2] ~= R.ASSIGN_PRIMARY and op[2] ~= R.IMPERSONATE then
                t:assert_eq(op[3](all), 0,
                    op[1] .. " is granted by KACS_TOKEN_ALL_ACCESS")
            end
        end
        local over, e2 = token.duplicate(vm, source,
            { access = R.ALL_ACCESS | 0x0200 })
        t:assert(not over, "0x0200 is outside the mask: " ..
            sys.errname(e2 or 0))
        t:assert_eq(e2, sys.E.INVAL, "and the duplicate is refused EINVAL")
        sys.close(vm, all); sys.close(vm, source)
    end)

test("KACS_IOC_MAGIC is 0x4B: no other interface identifier reaches a token",
    { spec = "PKM *kacs-abi.token-ioctl-magic" }, function(t)
        local fd = fresh()
        local args = { fd, token.IOC.QUERY, 0 }
        t:assert_eq(vm:syscall(sys.NR.ioctl, {
            args = args, bufs = { string.pack("<I4I4I8", token.CLASS.TYPE, 0, 0) },
            ptrs = { 2 },
        }).ret, 0, "type 0x4B, command 0, is KACS_IOC_QUERY")
        for _, magic in ipairs({ 0x4A, 0x4C, 0x00 }) do
            local cmd = (3 << 30) | (16 << 16) | (magic << 8) | 0x00
            t:assert_eq(vm:syscall(sys.NR.ioctl, {
                args = { fd, cmd, 0 }, bufs = { string.rep("\0", 16) }, ptrs = { 2 },
            }).errno, sys.E.NOTTY,
                ("type 0x%02X is not a KACS token ioctl"):format(magic))
        end
        sys.close(vm, fd)
    end)

test("the privilege-entry attribute bits are ENABLED 2 and REMOVED 4",
    { spec = "PKM *kacs-abi.privilege-attributes" }, function(t)
        local BACKUP = token.bit(token.PRIV.BACKUP)
        local fd = fresh({ privs_present = BACKUP, privs_enabled = 0 })
        t:assert_eq(token.adjust_privs(vm, fd,
            { { token.PRIV.BACKUP, token.PRIV_ATTR.ENABLED } }).ret, 0, "0x2")
        t:assert_eq(assert(token.privileges(vm, fd)).enabled, BACKUP,
            "KACS_PRIVILEGE_ATTR_ENABLED enables it")
        t:assert_eq(token.adjust_privs(vm, fd,
            { { token.PRIV.BACKUP, token.PRIV_ATTR.REMOVED } }).ret, 0, "0x4")
        local privs = assert(token.privileges(vm, fd))
        t:assert_eq(privs.present, 0,
            "KACS_PRIVILEGE_ATTR_REMOVED takes it out of the present set")
        t:assert_eq(privs.enabled, 0, "and out of the enabled set with it")
        sys.close(vm, fd)
    end)

test("KACS_PRIVILEGE_RESET_ALL_DEFAULTS is a bulk flag, not a per-entry attribute",
    { spec = "PKM *kacs-abi.privilege-reset-all-defaults" }, function(t)
        local BACKUP, RESTORE =
            token.bit(token.PRIV.BACKUP), token.bit(token.PRIV.RESTORE)
        local fd = fresh({ privs_present = BACKUP | RESTORE,
            privs_enabled = BACKUP })
        t:assert_eq(token.disable_priv(vm, fd, token.PRIV.BACKUP).ret, 0,
            "the default-enabled one is switched off")
        t:assert_eq(token.enable_priv(vm, fd, token.PRIV.RESTORE).ret, 0,
            "and the other on")
        t:assert_eq(assert(token.privileges(vm, fd)).enabled, RESTORE,
            "the enabled set is now the inverse of the defaults")
        t:assert_eq(token.adjust_privs(vm, fd,
            { { 0, token.PRIV_ATTR.RESET_ALL_DEFAULTS } }).ret, 0,
            "0x80000000 with luid 0 is accepted")
        t:assert_eq(assert(token.privileges(vm, fd)).enabled, BACKUP,
            "and restores the enabled-by-default set wholesale")
        sys.close(vm, fd)
    end)

test("KACS_TOKEN_RESTRICT_WRITE_RESTRICTED is the only kacs_restrict_args flag",
    { spec = "PKM *kacs-abi.restrict-flags" }, function(t)
        local fd = fresh()
        local ok, e = token.restrict(vm, fd,
            { flags = token.RESTRICT_WRITE_RESTRICTED })
        t:assert(ok, "0x1 is accepted: " .. sys.errname(e or 0))
        sys.close(vm, ok)
        local bad, e2 = token.restrict(vm, fd, { flags = 0x2 })
        t:assert(not bad, "0x2 is not a defined flag: " .. sys.errname(e2 or 0))
        t:assert_eq(e2, sys.E.INVAL, "and is refused EINVAL")
        sys.close(vm, fd)
    end)

test("the token types are PRIMARY 1 and IMPERSONATION 2, and nothing else",
    { spec = "PKM *kacs-abi.token-types" }, function(t)
        local fd = fresh()
        t:assert_eq(token.query_u32(vm, fd, token.CLASS.TYPE),
            token.TYPE.PRIMARY, "a minted token reports 1")
        local imp = assert(token.duplicate(vm, fd, {
            token_type = token.TYPE.IMPERSONATION,
            impersonation_level = token.LEVEL.IMPERSONATION }))
        t:assert_eq(token.query_u32(vm, imp, token.CLASS.TYPE),
            token.TYPE.IMPERSONATION, "its impersonation duplicate reports 2")
        local bad, e = token.duplicate(vm, fd, { token_type = 3 })
        t:assert(not bad, "3 is not a token type: " .. sys.errname(e or 0))
        local zero, e2 = token.duplicate(vm, fd, { token_type = 0 })
        t:assert(not zero, "nor is 0: " .. sys.errname(e2 or 0))
        sys.close(vm, imp); sys.close(vm, fd)
    end)

test("the impersonation levels are 0 to 3 in the published order",
    { spec = "PKM *kacs-abi.impersonation-levels" }, function(t)
        local fd = fresh()
        for _, level in ipairs({ token.LEVEL.ANONYMOUS,
                                 token.LEVEL.IDENTIFICATION,
                                 token.LEVEL.IMPERSONATION,
                                 token.LEVEL.DELEGATION }) do
            local h, e = token.duplicate(vm, fd, {
                access = token.RIGHT.QUERY,
                token_type = token.TYPE.IMPERSONATION,
                impersonation_level = level })
            t:assert(h, "level " .. level .. " duplicates: " .. sys.errname(e or 0))
            t:assert_eq(token.query_u32(vm, h, token.CLASS.IMPERSONATION_LEVEL),
                level, "and reads back as itself")
            sys.close(vm, h)
        end
        local bad, e = token.duplicate(vm, fd, {
            token_type = token.TYPE.IMPERSONATION, impersonation_level = 4 })
        t:assert(not bad, "4 is past KACS_IMLEVEL_DELEGATION: " ..
            sys.errname(e or 0))
        sys.close(vm, fd)
    end)

test("the elevation types are Default 1, Full 2 and Limited 3",
    { spec = "PKM *kacs-abi.elevation-types" }, function(t)
        local TCB = token.bit(token.PRIV.TCB)
        local elevated, sid = token.mint(vm,
            { privs_present = TCB, privs_enabled = TCB })
        t:assert(elevated, "an elevated token: " .. sys.errname(sid or 0))
        t:assert_eq(token.query_u32(vm, elevated, token.CLASS.ELEVATION_TYPE),
            token.ELEVATION.DEFAULT, "unlinked, it is Default (1)")
        local filtered = assert(token.create(vm, { auth_id = sid }))
        t:assert_eq(token.link(vm, elevated, elevated, filtered, sid).ret, 0,
            "the pair is linked")
        t:assert_eq(token.query_u32(vm, elevated, token.CLASS.ELEVATION_TYPE),
            token.ELEVATION.FULL, "the elevated half becomes Full (2)")
        t:assert_eq(token.query_u32(vm, filtered, token.CLASS.ELEVATION_TYPE),
            token.ELEVATION.LIMITED, "and the filtered half Limited (3)")
        sys.close(vm, elevated); sys.close(vm, filtered)
    end)

test("the mandatory-policy bits are NO_WRITE_UP 1 and NEW_PROCESS_MIN 2",
    { spec = "PKM *kacs-abi.mandatory-policy-bits" }, function(t)
        for _, policy in ipairs({ 0, token.MANDATORY.NO_WRITE_UP,
                                  token.MANDATORY.NEW_PROCESS_MIN,
                                  token.MANDATORY.NO_WRITE_UP
                                      | token.MANDATORY.NEW_PROCESS_MIN }) do
            local fd, e = token.mint(vm, { mandatory_policy = policy })
            t:assert(fd, "policy " .. policy .. " mints: " .. sys.errname(e or 0))
            t:assert_eq(token.query_u32(vm, fd, token.CLASS.MANDATORY_POLICY),
                policy, "and reads back unchanged")
            sys.close(vm, fd)
        end
        local bad, e = token.mint(vm, { mandatory_policy = 0x4 })
        t:assert(not bad, "0x4 is not a mandatory-policy bit: " ..
            sys.errname(e or 0))
        t:assert_eq(e, sys.E.INVAL, "and the token is refused EINVAL")
    end)

test("the four audit-policy bits select the four audited outcomes",
    { spec = "PKM *kacs-abi.audit-policy-bits" }, function(t)
        local A = token.AUDIT
        local ring = assert(kmes.attach(vm, 0))
        local sd_denied = access.simple({})
        local sd_granted = access.simple({ access.ace(access.ACE.ALLOWED, 0x1,
            token.SID.TEST_USER) })
        local function audits(policy, sd)
            local fd = fresh({ audit_policy = policy })
            kmes.drain(ring)
            access.check(vm, { token_fd = fd, sd = sd, desired = 0x1 })
            local n = #kmes.of_type(kmes.drain(ring), "access-audit")
            sys.close(vm, fd)
            return n
        end
        t:assert_eq(audits(A.OBJECT_ACCESS_SUCCESS, sd_granted), 1,
            "0x1 audits a granted access")
        t:assert_eq(audits(A.OBJECT_ACCESS_SUCCESS, sd_denied), 0,
            "and only that")
        t:assert_eq(audits(A.OBJECT_ACCESS_FAILURE, sd_denied), 1,
            "0x2 audits a denied access")
        t:assert_eq(audits(A.OBJECT_ACCESS_FAILURE, sd_granted), 0,
            "and only that")
        kmes.detach(ring)
        for _, policy in ipairs({ A.PRIVILEGE_USE_SUCCESS,
                                  A.PRIVILEGE_USE_FAILURE, 0xF }) do
            local fd, e = token.mint(vm, { audit_policy = policy })
            t:assert(fd, "policy 0x" .. string.format("%x", policy) ..
                " is accepted: " .. sys.errname(e or 0))
            if fd then sys.close(vm, fd) end
        end
        local bad, e = token.mint(vm, { audit_policy = 0x10 })
        t:assert(not bad, "0x10 is outside the four bits: " ..
            sys.errname(e or 0))
    end)

test("the logon types are the six published values and no others",
    { spec = "PKM *kacs-abi.logon-types" }, function(t)
        for name, value in pairs(token.LOGON_TYPE) do
            local sid, e = token.create_logon_session(vm, { logon_type = value })
            t:assert(sid, name .. " (" .. value .. ") is a logon type: " ..
                sys.errname(e or 0))
            local fd = assert(token.create(vm, { auth_id = sid }))
            t:assert_eq(token.query_u32(vm, fd, token.CLASS.LOGON_TYPE), value,
                "and a token in the session reports it")
            sys.close(vm, fd)
        end
        for _, value in ipairs({ 0, 1, 6, 7, 10, 255 }) do
            local sid, e = token.create_logon_session(vm, { logon_type = value })
            t:assert(not sid, value .. " is not a logon type: " ..
                sys.errname(e or 0))
        end
    end)

test("KACS_TOKEN_MAX_GROUPS is 1024, counting the injected logon SID",
    { spec = "PKM *kacs-abi.token-max-groups" }, function(t)
        local function many(n)
            local out = {}
            for i = 1, n do
                out[i] = { sid = token.sid(5, 21, 1000, 2000, 3000, 30000 + i),
                           attributes = 0 }
            end
            return out
        end
        local fd, e = token.mint(vm, { groups = many(1023) })
        t:assert(fd, "1023 caller groups mint: " .. sys.errname(e or 0))
        t:assert_eq(#assert(token.groups(vm, fd)), 1024,
            "and the array holds exactly 1024 with the logon SID")
        sys.close(vm, fd)
        local bad, e2 = token.mint(vm, { groups = many(1024) })
        t:assert(not bad, "one more is refused: " .. sys.errname(e2 or 0))
    end)

test("KACS_TOKEN_GROUP_MASK_WORDS is 16 — 1024 groups in sixteen u64 words",
    { spec = "PKM *kacs-abi.token-group-mask-words" }, function(t)
        local groups = {}
        for i = 1, 1023 do
            groups[i] = { sid = token.sid(5, 21, 1000, 2000, 3000, 40000 + i),
                          attributes = 0 }
        end
        local fd = fresh({ groups = groups })
        t:assert_eq(token.adjust_groups(vm, fd, { { 1022, 1 } }).ret, 0,
            "the highest caller group enables")
        local _, words = token.adjust_groups(vm, fd, { { 1022, 0 } })
        t:assert_eq(#words, 16, "the previous-state mask is sixteen words")
        t:assert(words[16] & (1 << 62) ~= 0,
            "group 1022 lives in word 15, bit 62 — 64 groups to a word")
        t:assert_eq(words[1], 0, "and the low word is untouched")
        t:assert_eq(token.adjust_groups(vm, fd, { { 1024, 1 } }).errno,
            sys.E.INVAL, "index 1024 is past the sixteen words")
        sys.close(vm, fd)
    end)

test("the create-token spec is a 192-byte header, version 2, within 64 KiB",
    { spec = "PKM *kacs-abi.token-spec-wire-format" }, function(t)
        local sid = assert(token.create_logon_session(vm, {}))
        local blob = token.build_spec({ auth_id = sid })
        t:assert_eq(#blob >= token.SPEC_HEADER_BYTES, true,
            "the header is 192 bytes")
        local fd = assert(token.create(vm, blob))
        sys.close(vm, fd)
        -- KACS_TOKEN_SPEC_VERSION is 2.
        local bad, e = token.create(vm, token.build_spec(
            { auth_id = sid, version = 3 }))
        t:assert(not bad, "version 3 is refused: " .. sys.errname(e or 0))
        -- KACS_TOKEN_SPEC_MIN_BYTES is 192.
        t:assert_eq(vm:syscall(token.SYS.CREATE_TOKEN, {
            args = { 0, 191 }, bufs = { blob }, ptrs = { 0 },
        }).errno, sys.E.INVAL, "a spec_len of 191 cannot hold the header")
        -- KACS_TOKEN_SPEC_MAX_BYTES is 65536.
        local huge = blob .. string.rep("\0", 65537 - #blob)
        t:assert_eq(vm:syscall(token.SYS.CREATE_TOKEN, {
            args = { 0, #huge }, bufs = { huge }, ptrs = { 0 },
        }).errno, sys.E.INVAL, "65537 bytes is past the maximum")
        -- Every offset+length is validated to fall inside the buffer.
        local outside = token.build_spec({ auth_id = sid,
            raw = { { 100, string.pack("<I4I4", 0x7000, 64) } } })
        local ob, e3 = token.create(vm, outside)
        t:assert(not ob,
            "a section offset past the buffer is refused: " ..
            sys.errname(e3 or 0))
    end)

test("the spec header's fields are read at their published byte offsets",
    { spec = "PKM *kacs-abi.token-spec-offsets" }, function(t)
        -- A session per call: closing a token frees the last reference
        -- to its LogonSession, and the next spec must name a live one.
        local function at(patches, spec)
            spec = spec or {}
            spec.auth_id = assert(token.create_logon_session(vm, {}))
            spec.raw = patches
            return token.create(vm, spec)
        end
        -- integrity_rid at 8.
        local fd = assert(at({ { 8, string.pack("<I4", token.INTEGRITY.LOW) } }))
        t:assert_eq(token.integrity(vm, fd), token.INTEGRITY.LOW,
            "the u32 at 8 is the integrity RID")
        sys.close(vm, fd)
        -- owner_sid_index at 64 and primary_group_index at 68.
        fd = assert(at({ { 64, string.pack("<I4I4", 1, 2) } }, { groups = {
            { sid = token.SID.EVERYONE, attributes = ENABLED | token.GROUP.OWNER },
            { sid = token.SID.TEST_GROUP, attributes = ENABLED },
        } }))
        t:assert_eq(token.query(vm, fd, token.CLASS.OWNER), token.SID.EVERYONE,
            "the u32 at 64 is the owner index")
        t:assert_eq(token.query(vm, fd, token.CLASS.PRIMARY_GROUP),
            token.SID.TEST_GROUP, "and the u32 at 68 the primary-group index")
        sys.close(vm, fd)
        -- source_name at 72 and source_id at 80.
        fd = assert(at({ { 72, "ZZTOPZZT" .. string.pack("<I8", 0x0102030405060708) } }))
        local src = assert(token.source(vm, fd))
        t:assert_eq(src.name, "ZZTOPZZT", "the eight bytes at 72 are the name")
        t:assert_eq(src.luid, 0x0102030405060708, "and the u64 at 80 the LUID")
        sys.close(vm, fd)
        -- interactivity_scope at 184.
        fd = assert(at({ { 184, string.pack("<I4", 7) } }))
        t:assert_eq(token.query_u32(vm, fd, token.CLASS.INTERACTIVITY_SCOPE), 7,
            "the u32 at 184 is the interactivity scope")
        sys.close(vm, fd)
        -- The two reserved fields, at 6 and 32, must be zero.
        local r0, e0 = at({ { 6, string.pack("<I2", 1) } })
        t:assert(not r0, "a non-zero _reserved0 at 6 is refused: " ..
            sys.errname(e0 or 0))
        local r1, e1 = at({ { 32, string.pack("<I4", 1) } })
        t:assert(not r1, "and a non-zero _reserved1 at 32: " ..
            sys.errname(e1 or 0))
    end)

test("KACS_TOKEN_SPEC_SOURCE_NAME_BYTES is 8 — a fixed field, not a string",
    { spec = "PKM *kacs-abi.token-source-name-bytes" }, function(t)
        local fd = fresh({ source_name = "ABCDEFGH",
            source_id = 0x1122334455667788 })
        local payload = assert(token.query(vm, fd, token.CLASS.SOURCE))
        t:assert_eq(#payload, 16, "the SOURCE payload is 8 name bytes plus a LUID")
        t:assert_eq(payload:sub(1, 8), "ABCDEFGH",
            "all eight bytes are carried, with no terminator")
        t:assert_eq(string.unpack("<I8", payload, 9), 0x1122334455667788,
            "and the LUID begins at byte 8")
        sys.close(vm, fd)
        -- A shorter name occupies the same eight bytes, NUL-padded.
        local short = fresh({ source_name = "AB" })
        t:assert_eq(assert(token.query(vm, short, token.CLASS.SOURCE)):sub(1, 8),
            "AB\0\0\0\0\0\0", "a shorter name is padded into the field")
        sys.close(vm, short)
    end)

test("the LCS extension is a versioned, bounded, de-duplicated section",
    { spec = "PKM *kacs-abi.token-lcs-extension" }, function(t)
        local fd = fresh({ lcs_credentials =
            lcs_ext({ guid(1), guid(2) }, { "Audit", "Policy" }) })
        t:assert(fd, "two scopes and two layers are accepted")
        sys.close(vm, fd)
        -- KACS_TOKEN_LCS_MAX_SCOPE_GUIDS / _MAX_PRIVATE_LAYERS are 256.
        local g, n = {}, {}
        for i = 1, 256 do g[i] = guid(i); n[i] = "layer" .. i end
        local at_limit = fresh({ lcs_credentials = lcs_ext(g, n) })
        t:assert(at_limit, "256 of each is inside the limits")
        sys.close(vm, at_limit)
        g[257] = guid(257)
        local over, e = token.mint(vm, { lcs_credentials = lcs_ext(g, {}) })
        t:assert(not over, "257 scope GUIDs is refused: " .. sys.errname(e or 0))
        -- KACS_TOKEN_LCS_MAX_LAYER_NAME_BYTES is 255.
        local ok255 = fresh({ lcs_credentials =
            lcs_ext({}, { string.rep("x", 255) }) })
        t:assert(ok255, "a 255-byte layer name is the longest accepted")
        sys.close(vm, ok255)
        local long, e2 = token.mint(vm, { lcs_credentials =
            lcs_ext({}, { string.rep("x", 256) }) })
        t:assert(not long, "256 bytes is refused: " .. sys.errname(e2 or 0))
        -- KACS_TOKEN_LCS_SCOPE_GUID_BYTES is 16, and a GUID must be
        -- non-nil and unique.
        local nil_guid, e3 = token.mint(vm,
            { lcs_credentials = lcs_ext({ string.rep("\0", 16) }, {}) })
        t:assert(not nil_guid, "a nil GUID is refused: " .. sys.errname(e3 or 0))
        local dup, e4 = token.mint(vm,
            { lcs_credentials = lcs_ext({ guid(1), guid(1) }, {}) })
        t:assert(not dup, "a duplicate GUID is refused: " .. sys.errname(e4 or 0))
    end)

test("the LCS extension header's four fields sit at 0, 4, 8 and 12",
    { spec = "PKM *kacs-abi.token-lcs-extension-offsets" }, function(t)
        local body = guid(1) .. string.pack("<I4", 5) .. "Audit"
        local function ext(version, reserved, scopes, layers)
            return string.pack("<I4I4I4I4", version, reserved, scopes, layers)
                .. body
        end
        -- The documented header, correctly filled: one scope, one layer.
        local fd = fresh({ lcs_credentials = ext(1, 0, 1, 1) })
        t:assert(fd, "version 1 at 0, reserved 0 at 4, counts at 8 and 12")
        sys.close(vm, fd)
        local v, e = token.mint(vm, { lcs_credentials = ext(2, 0, 1, 1) })
        t:assert(not v, "the u32 at 0 is the version: " .. sys.errname(e or 0))
        local r, e2 = token.mint(vm, { lcs_credentials = ext(1, 1, 1, 1) })
        t:assert(not r, "the u32 at 4 is a must-be-zero reserved: " ..
            sys.errname(e2 or 0))
        -- Counts at 8 and 12: a scope count that does not match the
        -- payload leaves the section not exactly consumed.
        local sc, e3 = token.mint(vm, { lcs_credentials = ext(1, 0, 2, 1) })
        t:assert(not sc, "the u32 at 8 is the scope count: " ..
            sys.errname(e3 or 0))
        local lc, e4 = token.mint(vm, { lcs_credentials = ext(1, 0, 1, 2) })
        t:assert(not lc, "and the u32 at 12 the private-layer count: " ..
            sys.errname(e4 or 0))
    end)

test("the logon-session spec is consumed exactly, between 15 and 4096 bytes",
    { spec = "PKM *kacs-abi.logon-session-spec-wire-format" }, function(t)
        local pkg, user = "Negotiate", token.SID.TEST_USER
        local blob = session_spec(token.LOGON_TYPE.INTERACTIVE, pkg, user)
        local r = vm:syscall(token.SYS.CREATE_LOGON_SESSION, {
            args = { 0, #blob }, bufs = { blob }, ptrs = { 0 },
        })
        t:assert(r.ret >= 1000, "the documented layout creates a session")
        -- 7 + auth_pkg_len + user_sid_len must equal len.
        t:assert_eq(vm:syscall(token.SYS.CREATE_LOGON_SESSION, {
            args = { 0, #blob + 1 }, bufs = { blob .. "\0" }, ptrs = { 0 },
        }).errno, sys.E.INVAL, "one trailing byte is not consumed")
        t:assert_eq(vm:syscall(token.SYS.CREATE_LOGON_SESSION, {
            args = { 0, #blob - 1 }, bufs = { blob }, ptrs = { 0 },
        }).errno, sys.E.INVAL, "and one byte short is a length mismatch")
        -- KACS_LOGON_SESSION_SPEC_MIN_BYTES is 15.
        t:assert_eq(vm:syscall(token.SYS.CREATE_LOGON_SESSION, {
            args = { 0, 14 }, bufs = { blob }, ptrs = { 0 },
        }).errno, sys.E.INVAL, "14 bytes cannot hold the fixed fields")
        -- KACS_LOGON_SESSION_SPEC_MAX_BYTES is 4096.
        local big = session_spec(token.LOGON_TYPE.INTERACTIVE,
            string.rep("N", 4096), user)
        t:assert_eq(vm:syscall(token.SYS.CREATE_LOGON_SESSION, {
            args = { 0, #big }, bufs = { big }, ptrs = { 0 },
        }).errno, sys.E.INVAL, "and " .. #big .. " bytes is past the maximum")
    end)

test("the session spec's fixed fields sit at 0, 1 and 3",
    { spec = "PKM *kacs-abi.logon-session-spec-offsets" }, function(t)
        local pkg, user = "Kerberos", token.SID.TEST_USER
        -- logon_type is the byte at 0.
        local blob = session_spec(token.LOGON_TYPE.SERVICE, pkg, user)
        local r = vm:syscall(token.SYS.CREATE_LOGON_SESSION, {
            args = { 0, #blob }, bufs = { blob }, ptrs = { 0 },
        })
        t:assert(r.ret >= 1000, "a session is created: " .. sys.errname(r.errno))
        local fd = assert(token.create(vm, { auth_id = r.ret }))
        t:assert_eq(token.query_u32(vm, fd, token.CLASS.LOGON_TYPE),
            token.LOGON_TYPE.SERVICE, "the byte at 0 is the logon type")
        sys.close(vm, fd)
        -- auth_pkg_len is the __le16 at 1, and the name begins at 3: a
        -- length that disagrees with the name makes the total wrong.
        local wrong = session_spec(token.LOGON_TYPE.SERVICE, pkg, user, #pkg - 1)
        t:assert_eq(vm:syscall(token.SYS.CREATE_LOGON_SESSION, {
            args = { 0, #wrong }, bufs = { wrong }, ptrs = { 0 },
        }).errno, sys.E.INVAL,
            "the __le16 at 1 is the package length, and the name follows at 3")
    end)

test("the eleven token-handle ioctl commands are the published values",
    { spec = "PKM *kacs-abi.token-ioctls" }, function(t)
        -- A handle carrying only TOKEN_QUERY: every verb is recognised
        -- (whatever it then answers), and only an unlisted command
        -- number is ENOTTY.
        local source = fresh()
        local fd = assert(token.duplicate(vm, source,
            { access = token.RIGHT.QUERY }))
        local commands = {
            { "KACS_IOC_QUERY", 0xC0104B00, 16 },
            { "KACS_IOC_ADJUST_PRIVS", 0x40184B01, 24 },
            { "KACS_IOC_DUPLICATE", 0xC0104B02, 16 },
            { "KACS_IOC_INSTALL", 0x00004B03, 0 },
            { "KACS_IOC_RESTRICT", 0xC0284B04, 40 },
            { "KACS_IOC_LINK_TOKENS", 0x40104B05, 16 },
            { "KACS_IOC_GET_LINKED_TOKEN", 0xC0044B06, 4 },
            { "KACS_IOC_ADJUST_GROUPS", 0x40904B07, 144 },
            { "KACS_IOC_IMPERSONATE", 0x00004B08, 0 },
            { "KACS_IOC_ADJUST_DEFAULT", 0x40104B09, 16 },
            { "KACS_IOC_ADJUST_INTERACTIVITY_SCOPE", 0x40044B0A, 4 },
        }
        for _, c in ipairs(commands) do
            local r
            if c[3] == 0 then
                r = vm:syscall(sys.NR.ioctl, c[1] and fd or fd, c[2], 0)
            else
                r = vm:syscall(sys.NR.ioctl, {
                    args = { fd, c[2], 0 }, bufs = { string.rep("\0", c[3]) },
                    ptrs = { 2 },
                })
            end
            t:assert_neq(r.errno, sys.E.NOTTY,
                c[1] .. " is a recognised verb: " .. sys.errname(r.errno))
        end
        -- 0x0B is one past KACS_IOC_ADJUST_INTERACTIVITY_SCOPE.
        for _, nr in ipairs({ 0x0B, 0x0C, 0x7F }) do
            t:assert_eq(vm:syscall(sys.NR.ioctl, {
                args = { fd, 0x40044B00 | nr, 0 }, bufs = { string.rep("\0", 4) },
                ptrs = { 2 },
            }).errno, sys.E.NOTTY,
                ("command 0x%02X is not a token ioctl"):format(nr))
        end
        sys.close(vm, fd); sys.close(vm, source)
    end)

test("the twenty-four token information classes are 0x01 through 0x18",
    { spec = "PKM *kacs-abi.token-information-classes" }, function(t)
        local fd = assert(token.open_self(vm))
        local seen = 0
        for name, class in pairs(token.CLASS) do
            local payload, e = token.query(vm, fd, class)
            t:assert(payload, ("KACS_TOKEN_CLASS_%s (0x%02X) answers: %s")
                :format(name, class, sys.errname(e or 0)))
            seen = seen + 1
        end
        t:assert_eq(seen, 24, "twenty-four classes are defined")
        for _, class in ipairs({ 0x00, 0x19, 0x20, 0xFF }) do
            local p, e = token.query(vm, fd, class)
            t:assert(not p, ("0x%02X is outside the enumeration"):format(class))
            t:assert_eq(e, sys.E.INVAL, "and is refused EINVAL")
        end
        sys.close(vm, fd)
    end)

test("each privilege is the single bit the table names",
    { spec = "PKM *kacs-abi.privilege-bits" }, function(t)
        local all = 0
        for _, index in pairs(token.PRIV) do all = all | token.bit(index) end
        local fd = fresh({ privs_present = all, privs_enabled = all })
        local privs = assert(token.privileges(vm, fd))
        t:assert_eq(privs.present, all,
            "every named privilege survives creation as its own bit")
        t:assert_eq(privs.enabled, all, "and can be enabled")
        sys.close(vm, fd)
        -- One at a time: a token holding only SeRelabelPrivilege
        -- (1 << 32) holds nothing else, which is only true if the bit
        -- index is what the table says.
        for name, index in pairs(token.PRIV) do
            local one = token.bit(index)
            local h = fresh({ privs_present = one, privs_enabled = one })
            t:assert_eq(assert(token.privileges(vm, h)).present, one,
                ("KACS_SE_%s_PRIVILEGE is bit %d alone"):format(name, index))
            sys.close(vm, h)
        end
    end)

test("SOL_KACS is 4096 and the options live under that level alone",
    { spec = "PKM *kacs-abi.sol-kacs" }, function(t)
        local srv, acc, cli = unix.connected(vm, "/abi-sol.sock")
        t:assert(srv, "a connected pair: " .. tostring(acc))
        t:assert_eq(unix.level(vm, acc), token.LEVEL.IMPERSONATION,
            "getsockopt at 4096 reaches KACS")
        for _, level in ipairs({ 4095, 4097 }) do
            local r = vm:syscall(unix.NR.getsockopt, {
                args = { acc, level, unix.SO.IMPERSONATION_LEVEL, 0, 0 },
                bufs = { string.pack("<i4", -1), string.pack("<i4", 4) },
                ptrs = { 3, 4 },
            })
            t:assert_neq(r.ret, 0, "level " .. level ..
                " is not SOL_KACS: " .. unix.errname(r.errno))
        end
        -- An option number this level does not define is ENOPROTOOPT.
        local r = vm:syscall(unix.NR.getsockopt, {
            args = { acc, unix.SOL_KACS, 5, 0, 0 },
            bufs = { string.pack("<i4", -1), string.pack("<i4", 4) },
            ptrs = { 3, 4 },
        })
        t:assert_eq(r.errno, unix.E.NOPROTOOPT,
            "option 5 is undefined at SOL_KACS: " .. unix.errname(r.errno))
        sys.close(vm, cli); sys.close(vm, acc); sys.close(vm, srv)
    end)

test("KACS_SO_PEER_TOKEN is option 1, and getsockopt only",
    { spec = "PKM *kacs-abi.so-peer-token" }, function(t)
        local srv, acc, cli = unix.connected(vm, "/abi-peer.sock")
        t:assert(srv, "a connected pair: " .. tostring(acc))
        local fd, e = unix.peer_token(vm, acc)
        t:assert(fd, "option 1 hands back a token fd: " ..
            unix.errname(e or 0))
        t:assert_eq(token.query_u32(vm, fd, token.CLASS.TYPE),
            token.TYPE.IMPERSONATION,
            "carrying the peer's identity as an impersonation token")
        t:assert_eq(unix.setopt(vm, acc, unix.SO.PEER_TOKEN, 0).errno,
            unix.E.NOPROTOOPT, "and setsockopt of it is refused")
        local lone = assert(unix.socket(vm, unix.AF_UNIX, unix.SOCK.STREAM))
        local _, e2 = unix.peer_token(vm, lone)
        t:assert_eq(e2, unix.E.NOTCONN,
            "an unconnected socket has no register: " .. unix.errname(e2 or 0))
        sys.close(vm, lone); sys.close(vm, fd)
        sys.close(vm, cli); sys.close(vm, acc); sys.close(vm, srv)
    end)

test("KACS_SO_IMPERSONATION_LEVEL is option 2, read and written",
    { spec = "PKM *kacs-abi.so-impersonation-level" }, function(t)
        local srv, acc, cli = unix.connected(vm, "/abi-level.sock")
        t:assert(srv, "a connected pair: " .. tostring(acc))
        t:assert_eq(unix.level(vm, cli), token.LEVEL.IMPERSONATION,
            "the default is KACS_IMLEVEL_IMPERSONATION")
        t:assert_eq(unix.set_level(vm, cli,
            token.LEVEL.IDENTIFICATION).ret, 0, "it may be lowered")
        t:assert_eq(unix.level(vm, cli), token.LEVEL.IDENTIFICATION,
            "and reads back as what was written")
        t:assert_neq(unix.set_level(vm, cli, 4).ret, 0,
            "a level past KACS_IMLEVEL_DELEGATION is out of range")
        sys.close(vm, cli); sys.close(vm, acc); sys.close(vm, srv)
    end)

test("KACS_SO_PASS_TOKEN is option 3, a 0/1 sender-side switch",
    { spec = "PKM *kacs-abi.so-pass-token" }, function(t)
        local srv, acc, cli = unix.connected(vm, "/abi-pass.sock")
        t:assert(srv, "a connected pair: " .. tostring(acc))
        t:assert_eq(unix.pass_token(vm, cli), 0, "the default is 0")
        t:assert_eq(unix.set_pass_token(vm, cli, true).ret, 0, "it is settable")
        t:assert_eq(unix.pass_token(vm, cli), 1, "and reads back set")
        local snd = unix.sendmsg(vm, cli, "passed")
        t:assert_eq(snd.ret, 6, "a send carries identity while it is set")
        local rcv = unix.recvmsg(vm, acc, 16)
        t:assert_eq(#rcv.tokens, 1,
            "and the receiver is handed one identity message")
        for _, fd in ipairs(rcv.tokens) do sys.close(vm, fd) end
        sys.close(vm, cli); sys.close(vm, acc); sys.close(vm, srv)
    end)

test("KACS_SO_RESTAMP is option 4, and setsockopt only",
    { spec = "PKM *kacs-abi.so-restamp" }, function(t)
        local srv, acc, cli = unix.connected(vm, "/abi-restamp.sock")
        t:assert(srv, "a connected pair: " .. tostring(acc))
        t:assert_eq(unix.restamp(vm, srv).ret, 0,
            "a listening socket restamps its conveyed identity")
        t:assert_eq(unix.restamp(vm, acc).errno, sys.E.INVAL,
            "a socket that is not listening is EINVAL")
        local _, e = unix.getopt(vm, srv, unix.SO.RESTAMP)
        t:assert_eq(e, unix.E.NOPROTOOPT,
            "and there is nothing to read back: " .. unix.errname(e or 0))
        sys.close(vm, cli); sys.close(vm, acc); sys.close(vm, srv)
    end)

test("KACS_SCM_TOKEN is ancillary type 1 at cmsg_level SOL_KACS",
    { spec = "PKM *kacs-abi.scm-token" }, function(t)
        local srv, acc, cli = unix.connected(vm, "/abi-scm.sock")
        t:assert(srv, "a connected pair: " .. tostring(acc))
        local source = fresh()
        local imp = assert(token.duplicate(vm, source, {
            access = token.RIGHT.QUERY | token.RIGHT.IMPERSONATE,
            token_type = token.TYPE.IMPERSONATION,
            impersonation_level = token.LEVEL.IMPERSONATION }))
        local snd = unix.sendmsg(vm, cli, "attach", { token_fd = imp })
        t:assert_eq(snd.ret, 6, "a token attaches to a send: " ..
            unix.errname(snd.errno))
        local rcv = unix.recvmsg(vm, acc, 16)
        t:assert_eq(#rcv.cmsgs, 1, "one ancillary message arrives")
        t:assert_eq(rcv.cmsgs[1].level, unix.SOL_KACS,
            "at cmsg_level SOL_KACS")
        t:assert_eq(rcv.cmsgs[1].type, unix.SCM_TOKEN, "with type 1")
        t:assert_eq(#rcv.tokens, 1, "carrying one int — a token fd")
        t:assert_eq(token.query(vm, rcv.tokens[1], token.CLASS.USER),
            token.SID.TEST_USER, "for the identity the sender attested")
        for _, fd in ipairs(rcv.tokens) do sys.close(vm, fd) end
        sys.close(vm, imp); sys.close(vm, source)
        sys.close(vm, cli); sys.close(vm, acc); sys.close(vm, srv)
    end)

test("the System V IPC rights gate the operations the table names",
    { spec = "PKM *kacs-abi.ipc-access-rights" }, function(t)
        local NR = { shmget = 29, shmat = 30, shmctl = 31 }
        local IPC_CREAT, SHM_RDONLY = 0x200, 0x1000
        local IPC_STAT, SHM_LOCK, SHM_UNLOCK, IPC_RMID = 2, 11, 12, 0
        local LOCK_MEMORY = token.bit(token.PRIV.LOCK_MEMORY)
        local ids = {}
        for i = 1, 3 do
            ids[i] = vm:syscall(NR.shmget, 0xA100 + i, 4096,
                IPC_CREAT | 0x1B6).ret
        end
        local shm = ids[3]
        t:assert(shm >= 0, "a shared-memory segment exists")
        local function grant(mask)
            local sd = kacs.descriptor(kacs.acl({
                kacs.ace(kacs.ACE_ALLOWED, mask, token.SID.TEST_USER) }))
            return vm:syscall(kacs.SYS.SET_SD, {
                args = { shm, 0, kacs.SI.DACL, 0, #sd, 0x01000000 },
                bufs = { sd }, ptrs = { 3 },
            }).ret
        end
        local function as(mask, privs, fn)
            t:assert_eq(grant(mask), 0, "the descriptor grants 0x" ..
                string.format("%x", mask))
            token.as_principal(t, vm, { privs_present = privs or 0,
                privs_enabled = privs or 0 }, fn)
        end
        -- KACS_IPC_READ (1): a read-only attach and nothing more.
        as(1, nil, function(w)
            t:assert(w:syscall(NR.shmat, shm, 0, SHM_RDONLY).ret > 0,
                "KACS_IPC_READ admits a read-only shmat")
            t:assert_eq(w:syscall(NR.shmat, shm, 0, 0).errno, sys.E.ACCES,
                "but not a read-write one")
        end)
        -- KACS_IPC_WRITE (2) is what a read-write attach adds.
        as(1 | 2, nil, function(w)
            t:assert(w:syscall(NR.shmat, shm, 0, 0).ret > 0,
                "KACS_IPC_WRITE admits a read-write shmat")
        end)
        -- KACS_IPC_QUERY_INFORMATION (4) is IPC_STAT.
        as(1, nil, function(w)
            t:assert_eq(w:syscall(NR.shmctl, { args = { shm, IPC_STAT, 0 },
                bufs = { string.rep("\0", 112) }, ptrs = { 2 } }).errno,
                sys.E.ACCES, "IPC_STAT is refused without it")
        end)
        as(1 | 4, nil, function(w)
            t:assert_eq(w:syscall(NR.shmctl, { args = { shm, IPC_STAT, 0 },
                bufs = { string.rep("\0", 112) }, ptrs = { 2 } }).ret, 0,
                "KACS_IPC_QUERY_INFORMATION admits IPC_STAT")
        end)
        -- KACS_IPC_SET_INFORMATION (8) is SHM_LOCK / SHM_UNLOCK.
        as(1, LOCK_MEMORY, function(w)
            t:assert_eq(w:syscall(NR.shmctl, shm, SHM_LOCK, 0).errno,
                sys.E.ACCES, "SHM_LOCK is refused without it")
        end)
        as(1 | 8, LOCK_MEMORY, function(w)
            t:assert_eq(w:syscall(NR.shmctl, shm, SHM_LOCK, 0).ret, 0,
                "KACS_IPC_SET_INFORMATION admits SHM_LOCK")
            w:syscall(NR.shmctl, shm, SHM_UNLOCK, 0)
        end)
        -- KACS_IPC_ALL_ACCESS is 983055: the four bits plus the four
        -- standard rights, and it admits every one of them.
        as(983055, LOCK_MEMORY, function(w)
            t:assert(w:syscall(NR.shmat, shm, 0, 0).ret > 0,
                "ALL_ACCESS admits the attach")
            t:assert_eq(w:syscall(NR.shmctl, { args = { shm, IPC_STAT, 0 },
                bufs = { string.rep("\0", 112) }, ptrs = { 2 } }).ret, 0,
                "the query")
            t:assert_eq(w:syscall(NR.shmctl, shm, SHM_LOCK, 0).ret, 0,
                "and the lock")
            w:syscall(NR.shmctl, shm, SHM_UNLOCK, 0)
        end)
        for _, id in ipairs(ids) do vm:syscall(NR.shmctl, id, IPC_RMID, 0) end
    end)

test("the KACS_SD_AT_SYSV_* selectors address an object by kind and id",
    { spec = "PKM *kacs-abi.sysv-sd-selectors" }, function(t)
        local NR = { shmget = 29, shmctl = 31, msgget = 68, msgctl = 71,
                     semget = 64, semctl = 66 }
        local IPC_CREAT, IPC_RMID = 0x200, 0
        local SHM, MSG, SEM = 0x01000000, 0x02000000, 0x04000000
        -- Three segments so the shm ids climb past the message-queue
        -- and semaphore id spaces: a selector naming the wrong kind
        -- must then find no object at all.
        local shms = {}
        for i = 1, 3 do
            shms[i] = vm:syscall(NR.shmget, 0xA200 + i, 4096,
                IPC_CREAT | 0x1B6).ret
        end
        local shm = shms[3]
        local msg = vm:syscall(NR.msgget, 0xA210, IPC_CREAT | 0x1B6).ret
        local sem = vm:syscall(NR.semget, 0xA211, 1, IPC_CREAT | 0x1B6).ret
        t:assert(shm >= 0 and msg >= 0 and sem >= 0, "one object of each kind")
        local function get(id, selector)
            return vm:syscall(kacs.SYS.GET_SD, {
                args = { id, 0, kacs.SI.DACL, 0, 4096, selector },
                bufs = { string.rep("\0", 4096) }, ptrs = { 3 },
            })
        end
        for _, c in ipairs({ { "KACS_SD_AT_SYSV_SHM", shm, SHM },
                             { "KACS_SD_AT_SYSV_MSG", msg, MSG },
                             { "KACS_SD_AT_SYSV_SEM", sem, SEM } }) do
            local r = get(c[2], c[3])
            t:assert(r.ret > 0, c[1] .. " reads the object's descriptor: " ..
                sys.errname(r.errno))
        end
        t:assert_eq(get(shm, MSG).errno, sys.E.INVAL,
            "the message-queue selector finds no queue with the shm id")
        t:assert_eq(get(shm, SEM).errno, sys.E.INVAL,
            "nor the semaphore selector a semaphore array")
        -- The selector lives in `flags`, and the path must be NULL: with
        -- no selector the same call is an ordinary path lookup.
        t:assert_eq(get(shm, 0).errno, sys.E.FAULT,
            "without a selector the NULL path is taken as a path")
        -- KACS_SD_AT_SYSV_MASK is 0x07000000: more than one kind at once
        -- names no object.
        t:assert_eq(get(shm, 0x07000000).errno, sys.E.INVAL,
            "the whole mask is not a kind")
        vm:syscall(NR.msgctl, msg, IPC_RMID, 0)
        vm:syscall(NR.semctl, sem, IPC_RMID, 0)
        for _, id in ipairs(shms) do vm:syscall(NR.shmctl, id, IPC_RMID, 0) end
    end)
