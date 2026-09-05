-- PKM §3.2.5 — Token adjustment: privileges, groups, interactivity scope
-- and object-creation defaults, each with its access right and its
-- constraint model. Adjustments mutate the token in place, so a case
-- reads the same token back — sometimes from another thread group that
-- shares it.

local sys = require("helpers.sys")
local token = require("helpers.token")

local vm = provium:vm("v", "kernel-only"):boot()

local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED
local TCB, CREATE, BACKUP = token.bit(token.PRIV.TCB), token.bit(token.PRIV.CREATE_TOKEN), token.bit(token.PRIV.BACKUP)
local RESTORE = token.bit(token.PRIV.RESTORE)

--- Groups with one of each kind: plain, mandatory, deny-only, plus the
--- user SID itself as a plain group.
local function kinds()
    return {
        { sid = token.SID.EVERYONE, attributes = ENABLED },                              -- 0 mandatory
        { sid = token.SID.TEST_GROUP, attributes = token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED }, -- 1 plain, enabled
        { sid = token.SID.TEST_GROUP_2, attributes = token.GROUP.USE_FOR_DENY_ONLY },   -- 2 deny-only
        { sid = token.SID.TEST_USER, attributes = token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED }, -- 3 the user SID
        { sid = token.SID.USERS, attributes = 0 },                                       -- 4 plain, disabled
        -- 5 is the injected logon SID
    }
end

local function mint(spec) return token.mint(vm, spec) end

--- A handle on the same token with fewer rights.
local function narrow(fd, access) return assert(token.duplicate(vm, fd, { access = access })) end

test("adjustments mutate the shared token in place and bump modified_id",
    { spec = "PKM *token.adjust.in-place-visible-bumps-modified-id" }, function(t)
        -- A worker installs a minted token; the agent, holding the
        -- worker's primary token through a pidfd, adjusts it. The worker
        -- sees each change on its own effective token.
        token.as_principal(t, vm, { privs_present = TCB | BACKUP, privs_enabled = TCB,
            groups = kinds() }, function(w)
            local pidfd = assert(token.pidfd_open(vm, w:syscall(sys.NR.getpid).ret))
            local fd = assert(token.open_process(vm, pidfd))
            local own = assert(token.open_self(w, token.RIGHT.QUERY))
            local before = assert(token.statistics(vm, fd)).modified_id
            t:assert_eq(token.enable_priv(vm, fd, token.PRIV.BACKUP).ret, 0, "enable a privilege")
            t:assert(token.privileges(w, own).enabled & BACKUP ~= 0, "the worker sees it enabled at once")
            local m1 = token.statistics(vm, fd).modified_id
            t:assert(m1 > before, "modified_id bumped by AdjustPrivileges")
            t:assert_eq(token.adjust_groups(vm, fd, { { 1, 0 } }).ret, 0, "disable a group")
            t:assert_eq(token.groups(w, own)[2].attributes & token.GROUP.ENABLED, 0, "the worker sees it disabled")
            local m2 = token.statistics(vm, fd).modified_id
            t:assert(m2 > m1, "bumped by AdjustGroups")
            t:assert_eq(token.adjust_default(vm, fd, { owner_index = 0, group_index = 2 }).ret, 0, "change a default")
            t:assert_eq(token.query(w, own, token.CLASS.PRIMARY_GROUP), token.SID.TEST_GROUP, "the worker sees the new primary group")
            local m3 = token.statistics(vm, fd).modified_id
            t:assert(m3 > m2, "bumped by AdjustDefault")
            t:assert_eq(token.adjust_interactivity_scope(vm, fd, 9).ret, 0, "change the scope")
            t:assert_eq(token.query_u32(w, own, token.CLASS.INTERACTIVITY_SCOPE), 9, "the worker sees the scope")
            t:assert(token.statistics(vm, fd).modified_id > m3, "bumped by AdjustInteractivityScope")
            sys.close(vm, fd); sys.close(vm, pidfd)
        end)
    end)

-- AdjustPrivileges ---------------------------------------------------------------

test("AdjustPrivileges requires TOKEN_ADJUST_PRIVILEGES",
    { spec = "PKM *token.adjust.privs.requires-right" }, function(t)
        local fd = assert(mint({ privs_present = BACKUP }))
        local h = narrow(fd, token.RIGHT.ALL_ACCESS & ~token.RIGHT.ADJUST_PRIVS)
        local r = token.enable_priv(vm, h, token.PRIV.BACKUP)
        t:assert_eq(r.errno, sys.E.ACCES, "refused EACCES without the right")
        t:assert_eq(token.privileges(vm, fd).enabled, 0, "and nothing changed")
        t:assert_eq(token.enable_priv(vm, fd, token.PRIV.BACKUP).ret, 0, "the full handle can")
        sys.close(vm, h); sys.close(vm, fd)
    end)

test("an absent privilege cannot be enabled; disabling one is a no-op",
    { spec = "PKM *token.adjust.privs.absent-enable-fails-disable-noop" }, function(t)
        local fd = assert(mint({ privs_present = BACKUP, privs_enabled = BACKUP }))
        local before = token.statistics(vm, fd).modified_id
        local r = token.enable_priv(vm, fd, token.PRIV.RESTORE)
        t:assert(r.ret ~= 0, "enabling an absent privilege fails: " .. sys.errname(r.errno))
        t:assert_eq(token.disable_priv(vm, fd, token.PRIV.RESTORE).ret, 0, "disabling an absent one is a no-op")
        local p = token.privileges(vm, fd)
        t:assert_eq(p.present, BACKUP, "present unchanged")
        t:assert_eq(p.enabled, BACKUP, "enabled unchanged — nothing was granted")
        sys.close(vm, fd)
    end)

test("reset-to-defaults is one entry with luid 0 and the RESET_ALL_DEFAULTS attribute",
    { spec = "PKM *token.adjust.privs.reset-encoding" }, function(t)
        local fd = assert(mint({ privs_present = TCB | BACKUP | RESTORE, privs_enabled = TCB }))
        t:assert_eq(token.disable_priv(vm, fd, token.PRIV.TCB).ret, 0, "disable a default-enabled one")
        t:assert_eq(token.enable_priv(vm, fd, token.PRIV.BACKUP).ret, 0, "enable a default-disabled one")
        t:assert_eq(token.privileges(vm, fd).enabled, BACKUP, "state is now inverted")
        t:assert_eq(token.reset_privs(vm, fd).ret, 0, "reset")
        local p = token.privileges(vm, fd)
        t:assert_eq(p.enabled, p.default, "enabled matches enabled-by-default")
        t:assert_eq(p.enabled, TCB, "which is the creation-time state")
        sys.close(vm, fd)
    end)

test("reset restores enabled state only — a removed privilege stays removed",
    { spec = "PKM *token.adjust.privs.reset-does-not-restore-removed" }, function(t)
        local fd = assert(mint({ privs_present = TCB | BACKUP, privs_enabled = TCB | BACKUP }))
        t:assert_eq(token.remove_priv(vm, fd, token.PRIV.TCB).ret, 0, "remove")
        t:assert_eq(token.reset_privs(vm, fd).ret, 0, "reset")
        local p = token.privileges(vm, fd)
        t:assert_eq(p.present, BACKUP, "still absent")
        t:assert_eq(p.enabled, BACKUP, "not re-enabled")
        t:assert_eq(p.default, BACKUP, "and its default was cleared by the removal")
        sys.close(vm, fd)
    end)

test("removing an already-absent privilege is a no-op",
    { spec = "PKM *token.adjust.privs.remove-absent-noop" }, function(t)
        local fd = assert(mint({ privs_present = BACKUP, privs_enabled = BACKUP }))
        t:assert_eq(token.remove_priv(vm, fd, token.PRIV.RESTORE).ret, 0, "returns success")
        t:assert_eq(token.privileges(vm, fd).present, BACKUP, "and changes nothing")
        sys.close(vm, fd)
    end)

test("duplicate privilege indices in one request are invalid",
    { spec = "PKM *token.adjust.privs.duplicate-indices-invalid" }, function(t)
        local fd = assert(mint({ privs_present = BACKUP }))
        local r = token.adjust_privs(vm, fd, { { token.PRIV.BACKUP, token.PRIV_ATTR.ENABLED },
            { token.PRIV.BACKUP, token.PRIV_ATTR.ENABLED } })
        t:assert(r.ret ~= 0, "refused: " .. sys.errname(r.errno))
        t:assert_eq(token.privileges(vm, fd).enabled, 0, "nothing applied")
        sys.close(vm, fd)
    end)

test("an invalid entry fails the whole request with no state change",
    { spec = "PKM *token.adjust.privs.all-or-nothing" }, function(t)
        local fd = assert(mint({ privs_present = BACKUP | RESTORE }))
        local before = token.statistics(vm, fd).modified_id
        -- A valid enable of BACKUP, then an enable of an absent privilege.
        local r = token.adjust_privs(vm, fd, { { token.PRIV.BACKUP, token.PRIV_ATTR.ENABLED },
            { token.PRIV.TCB, token.PRIV_ATTR.ENABLED } })
        t:assert(r.ret ~= 0, "refused: " .. sys.errname(r.errno))
        t:assert_eq(token.privileges(vm, fd).enabled, 0, "the valid entry was not applied either")
        t:assert_eq(token.statistics(vm, fd).modified_id, before, "modified_id did not move")
        sys.close(vm, fd)
    end)

test("the caller receives each adjusted privilege's previous state",
    { spec = "PKM *token.adjust.privs.reports-previous-state" }, function(t)
        local fd = assert(mint({ privs_present = BACKUP | RESTORE, privs_enabled = BACKUP }))
        local r, prev = token.adjust_privs(vm, fd, { { token.PRIV.BACKUP, 0 },
            { token.PRIV.RESTORE, token.PRIV_ATTR.ENABLED } })
        t:assert_eq(r.ret, 0, "disable BACKUP, enable RESTORE")
        t:assert(prev & BACKUP ~= 0, "previous state: BACKUP was enabled")
        t:assert_eq(prev & RESTORE, 0, "previous state: RESTORE was not")
        t:assert_eq(token.privileges(vm, fd).enabled, RESTORE, "and the new state is the inverse")
        sys.close(vm, fd)
    end)

-- AdjustGroups --------------------------------------------------------------------

test("AdjustGroups requires TOKEN_ADJUST_GROUPS",
    { spec = "PKM *token.adjust.groups.requires-right" }, function(t)
        local fd = assert(mint({ groups = kinds() }))
        local h = narrow(fd, token.RIGHT.ALL_ACCESS & ~token.RIGHT.ADJUST_GROUPS)
        local r = token.adjust_groups(vm, h, { { 1, 0 } })
        t:assert_eq(r.errno, sys.E.ACCES, "refused EACCES without the right")
        t:assert(token.groups(vm, fd)[2].attributes & token.GROUP.ENABLED ~= 0, "group still enabled")
        sys.close(vm, h); sys.close(vm, fd)
    end)

test("mandatory, deny-only and logon-id groups cannot be adjusted in either direction",
    { spec = "PKM *token.adjust.groups.protected-attributes-either-direction" }, function(t)
        local fd = assert(mint({ groups = kinds() }))
        local cases = {
            { 0, 0, "disabling the mandatory group" }, { 0, 1, "enabling the (already enabled) mandatory group" },
            { 2, 1, "enabling the deny-only group" }, { 2, 0, "disabling the deny-only group" },
            { 5, 0, "disabling the logon SID" }, { 5, 1, "enabling the logon SID" },
        }
        local before = token.groups(vm, fd)
        for _, c in ipairs(cases) do
            local r = token.adjust_groups(vm, fd, { { c[1], c[2] } })
            t:assert(r.ret ~= 0, c[3] .. " fails: " .. sys.errname(r.errno))
        end
        -- Naming one alongside a valid entry fails the whole call.
        local r = token.adjust_groups(vm, fd, { { 1, 0 }, { 0, 0 } })
        t:assert(r.ret ~= 0, "a valid entry beside a protected one fails the call")
        local after = token.groups(vm, fd)
        for i = 1, #before do t:assert_eq(after[i].attributes, before[i].attributes, "group " .. i .. " unchanged") end
        sys.close(vm, fd)
    end)

test("the user SID, when it appears as a group, cannot be disabled",
    { spec = "PKM *token.adjust.groups.user-sid-cannot-disable" }, function(t)
        local fd = assert(mint({ groups = kinds() }))
        local r = token.adjust_groups(vm, fd, { { 3, 0 } })
        t:assert(r.ret ~= 0, "disabling the user SID fails: " .. sys.errname(r.errno))
        t:assert_eq(token.adjust_groups(vm, fd, { { 3, 1 } }).ret, 0, "enabling it (the other direction) is fine")
        t:assert_eq(token.adjust_groups(vm, fd, { { 4, 1 } }).ret, 0, "an ordinary disabled group enables")
        t:assert(token.groups(vm, fd)[5].attributes & token.GROUP.ENABLED ~= 0, "and reads back enabled")
        t:assert_eq(token.adjust_groups(vm, fd, { { 4, 0 } }).ret, 0, "and disables again")
        sys.close(vm, fd)
    end)

test("reset restores enabled state and does not clear a later deny-only mark",
    { spec = "PKM *token.adjust.groups.reset-keeps-deny-only" }, function(t)
        local fd = assert(mint({ groups = kinds() }))
        t:assert_eq(token.adjust_groups(vm, fd, { { 1, 0 }, { 4, 1 } }).ret, 0, "invert two groups")
        t:assert_eq(token.adjust_groups(vm, fd, { { token.GROUP_RESET_INDEX, 0 } }).ret, 0, "reset the source")
        local g = token.groups(vm, fd)
        t:assert(g[2].attributes & token.GROUP.ENABLED ~= 0, "the disabled group is enabled again")
        t:assert_eq(g[5].attributes & token.GROUP.ENABLED, 0, "the enabled group is disabled again")
        -- Mark a group deny-only after creation, then reset the copy.
        local f = assert(token.restrict(vm, fd, { deny_indices = { 1 } }))
        t:assert_eq(token.adjust_groups(vm, f, { { token.GROUP_RESET_INDEX, 0 } }).ret, 0, "reset the copy")
        local fg = token.groups(vm, f)
        t:assert_eq(fg[2].attributes & token.GROUP.USE_FOR_DENY_ONLY, token.GROUP.USE_FOR_DENY_ONLY,
            "the deny-only mark survives reset")
        t:log(string.format("copy attributes after reset: idx1=0x%x idx4=0x%x", fg[2].attributes, fg[5].attributes))
        sys.close(vm, f); sys.close(vm, fd)
    end)

test("a count of 0, a count above 1024, or duplicate indices are invalid",
    { spec = "PKM *token.adjust.groups.count-and-duplicate-limits" }, function(t)
        local fd = assert(mint({ groups = kinds() }))
        local r = token.adjust_groups(vm, fd, {}, 0)
        t:assert(r.ret ~= 0, "count 0 fails: " .. sys.errname(r.errno))
        r = token.adjust_groups(vm, fd, { { 1, 0 } }, 1025)
        t:assert(r.ret ~= 0, "count 1025 fails: " .. sys.errname(r.errno))
        r = token.adjust_groups(vm, fd, { { 1, 0 }, { 1, 1 } })
        t:assert(r.ret ~= 0, "duplicate indices fail: " .. sys.errname(r.errno))
        r = token.adjust_groups(vm, fd, { { 6, 0 } })
        t:assert(r.ret ~= 0, "an out-of-range index fails: " .. sys.errname(r.errno))
        t:assert(token.groups(vm, fd)[2].attributes & token.GROUP.ENABLED ~= 0, "nothing applied")
        sys.close(vm, fd)
    end)

test("reset is one entry of { index = 0xFFFFFFFF, enable = 0 }",
    { spec = "PKM *token.adjust.groups.reset-encoding" }, function(t)
        local fd = assert(mint({ groups = kinds() }))
        t:assert_eq(token.adjust_groups(vm, fd, { { 1, 0 } }).ret, 0, "disable")
        t:assert_eq(token.adjust_groups(vm, fd, { { token.GROUP_RESET_INDEX, 0 } }).ret, 0, "reset")
        t:assert(token.groups(vm, fd)[2].attributes & token.GROUP.ENABLED ~= 0, "restored")
        local r = token.adjust_groups(vm, fd, { { token.GROUP_RESET_INDEX, 1 } })
        t:assert(r.ret ~= 0, "the reset index with enable = 1 is not a valid encoding: " .. sys.errname(r.errno))
        sys.close(vm, fd)
    end)

test("the previous enabled state comes back as a 1024-bit mask in sixteen words",
    { spec = "PKM *token.adjust.groups.previous-state-mask" }, function(t)
        local fd = assert(mint({ groups = kinds() }))
        -- Enabled at creation: 0 (mandatory), 1, 3, 5 (logon). Not: 2, 4.
        local r, words = token.adjust_groups(vm, fd, { { 1, 0 }, { 4, 1 } })
        t:assert_eq(r.ret, 0, "adjust")
        t:assert_eq(words[1], (1 << 0) | (1 << 1) | (1 << 3) | (1 << 5), "word 0 is the previous enabled bits")
        for i = 2, 16 do t:assert_eq(words[i], 0, "word " .. (i - 1) .. " is clear") end
        r, words = token.adjust_groups(vm, fd, { { 1, 1 } })
        t:assert_eq(words[1], (1 << 0) | (1 << 3) | (1 << 4) | (1 << 5), "and reflects the change on the next call")
        sys.close(vm, fd)
    end)

-- AdjustInteractivityScope --------------------------------------------------------------

test("AdjustInteractivityScope requires the right on the handle and SeTcbPrivilege on the caller's real token",
    { spec = "PKM *token.adjust.interactivity-scope.gates" }, function(t)
        local fd = assert(mint({}))
        local h = narrow(fd, token.RIGHT.ALL_ACCESS & ~token.RIGHT.ADJUST_INTERACTIVITY_SCOPE)
        t:assert_eq(token.adjust_interactivity_scope(vm, h, 5).errno, sys.E.ACCES, "without the right: EACCES")
        sys.close(vm, h); sys.close(vm, fd)
        -- A principal holding SeTcbPrivilege disabled: it mints a token
        -- (ALL_ACCESS handle) and then cannot change its scope.
        token.as_principal(t, vm, { privs_present = TCB | CREATE, privs_enabled = TCB | CREATE }, function(w)
            local mine = assert(token.mint(w, {}))
            t:assert_eq(token.adjust_interactivity_scope(w, mine, 5).ret, 0, "with SeTcbPrivilege enabled it works")
            local own = assert(token.open_self(w, token.RIGHT.ADJUST_PRIVS | token.RIGHT.QUERY))
            t:assert_eq(token.disable_priv(w, own, token.PRIV.TCB).ret, 0, "disable SeTcbPrivilege on itself")
            local r = token.adjust_interactivity_scope(w, mine, 6)
            t:assert_eq(r.errno, sys.E.ACCES, "held-but-disabled SeTcbPrivilege: EACCES")
            t:assert_eq(token.query_u32(w, mine, token.CLASS.INTERACTIVITY_SCOPE), 5, "unchanged")
        end)
    end)

test("changing the scope changes nothing else on the token",
    { spec = "PKM *token.adjust.interactivity-scope.metadata-only" }, function(t)
        local fd = assert(mint({ privs_present = TCB | BACKUP, privs_enabled = TCB, groups = kinds() }))
        local classes = { "USER", "GROUPS", "PRIVILEGES", "INTEGRITY_LEVEL", "OWNER", "PRIMARY_GROUP",
            "RESTRICTED_SIDS", "SOURCE", "ORIGIN", "ELEVATION_TYPE", "MANDATORY_POLICY", "LOGON_SID",
            "DEFAULT_DACL", "IMPERSONATION_LEVEL", "USER_CLAIMS", "APPCONTAINER_SID", "CAPABILITIES" }
        local before = {}
        for _, c in ipairs(classes) do before[c] = token.query(vm, fd, token.CLASS[c]) end
        t:assert_eq(token.adjust_interactivity_scope(vm, fd, 42).ret, 0, "set scope 42")
        t:assert_eq(token.query_u32(vm, fd, token.CLASS.INTERACTIVITY_SCOPE), 42, "it took")
        for _, c in ipairs(classes) do
            t:assert_eq(token.query(vm, fd, token.CLASS[c]), before[c], c .. " unchanged")
        end
        sys.close(vm, fd)
    end)

-- AdjustDefault -------------------------------------------------------------------------

test("AdjustDefault requires TOKEN_ADJUST_DEFAULT",
    { spec = "PKM *token.adjust.default.requires-right" }, function(t)
        local fd = assert(mint({ groups = kinds() }))
        local h = narrow(fd, token.RIGHT.ALL_ACCESS & ~token.RIGHT.ADJUST_DEFAULT)
        t:assert_eq(token.adjust_default(vm, h, { owner_index = 0, group_index = 2 }).errno, sys.E.ACCES,
            "without the right: EACCES")
        t:assert_eq(token.query(vm, fd, token.CLASS.PRIMARY_GROUP), token.SID.TEST_USER, "unchanged")
        t:assert_eq(token.adjust_default(vm, fd, { owner_index = 0, group_index = 2 }).ret, 0, "the full handle can")
        t:assert_eq(token.query(vm, fd, token.CLASS.PRIMARY_GROUP), token.SID.TEST_GROUP, "and it took")
        sys.close(vm, h); sys.close(vm, fd)
    end)

test("the defaults govern future object creation only",
    { spec = "PKM *token.adjust.default.future-objects-only" }, function(t)
        local kacs = require("helpers.kacs")
        local mount = "/mnt/pit-defaults"
        assert(kacs.new_mount(vm, "tmpfs", mount, kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL))
        -- Anyone may create here.
        assert(kacs.set_sd(vm, mount, kacs.grant(kacs.ALL_RIGHTS)).ret == 0)
        -- SeChangeNotifyPrivilege, as every principal has it (§3.4.2), so
        -- the walk to the mount is not the thing being tested.
        local CN = token.bit(token.PRIV.CHANGE_NOTIFY)
        token.as_principal(t, vm, { privs_present = CN, privs_enabled = CN, groups = {
            { sid = token.SID.EVERYONE, attributes = ENABLED },
            { sid = token.SID.TEST_GROUP, attributes = ENABLED | token.GROUP.OWNER },
        } }, function(w)
            local own, e = token.open_self(w, token.RIGHT.QUERY | token.RIGHT.ADJUST_DEFAULT)
            assert(own, "open_self: " .. sys.errname(e or 0))
            local a, ea = kacs.open(w, mount .. "/a", { disposition = kacs.DISPOSITION.CREATE,
                access = kacs.RIGHT.READ_DATA | kacs.RIGHT.WRITE_DATA | kacs.RIGHT.READ_CONTROL })
            assert(a, "create a: " .. sys.errname(ea or 0))
            sys.close(w, a)
            local sd_a = token.parse_sd(assert(kacs.get_sd(vm, mount .. "/a", kacs.SI.OWNER)))
            t:assert_eq(sd_a.owner, token.SID.TEST_USER, "object a is owned by the default owner, the user SID")
            t:assert_eq(token.adjust_default(w, own, { owner_index = 2, group_index = 0 }).ret, 0,
                "switch the default owner to the OWNER-flagged group")
            local b, eb = kacs.open(w, mount .. "/b", { disposition = kacs.DISPOSITION.CREATE,
                access = kacs.RIGHT.READ_DATA | kacs.RIGHT.WRITE_DATA | kacs.RIGHT.READ_CONTROL })
            assert(b, "create b: " .. sys.errname(eb or 0))
            sys.close(w, b)
            local sd_b = token.parse_sd(assert(kacs.get_sd(vm, mount .. "/b", kacs.SI.OWNER)))
            t:assert_eq(sd_b.owner, token.SID.TEST_GROUP, "object b takes the new default owner")
            sd_a = token.parse_sd(assert(kacs.get_sd(vm, mount .. "/a", kacs.SI.OWNER)))
            t:assert_eq(sd_a.owner, token.SID.TEST_USER, "object a is untouched")
        end)
    end)
