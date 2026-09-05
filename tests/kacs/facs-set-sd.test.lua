-- PKM §3.9.6 — `kacs_set_sd`: which right each component costs, how a
-- subset merges into the existing descriptor, the ownership and
-- integrity-label rules, and where SeRestorePrivilege does and does not
-- fire.
--
-- Every rule here is a *denial* rule, and the agent is SYSTEM holding
-- every privilege, so almost every case runs from a minted principal:
-- `token.as_principal` installs the token in a worker, and
-- SeChangeNotifyPrivilege is present throughout only so the principal
-- can traverse `/`, whose DACL grants nothing but SYSTEM. The rights
-- under test are granted or withheld by the *file's* DACL.
--
-- Objects live on the root tmpfs, which is FACS-managed and stores
-- descriptors natively, so a merge really is read-modify-write against
-- stored bytes rather than against a synthesised value.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local facs = require("helpers.facs")
local access = require("helpers.access")
local token = require("helpers.token")
local kmes = require("helpers.kmes")

local vm = provium:vm("v", "kernel-only"):boot()

local SI = kacs.SI
local LABEL = 0x10                       -- KACS_SECINFO_LABEL
local OWNER_GROUP_DACL = SI.OWNER | SI.GROUP | SI.DACL
local B = facs.workspace(vm, "setsd")
local CHANGE_NOTIFY = token.bit(token.PRIV.CHANGE_NOTIFY)

--- A file whose DACL grants `mask` to Everyone, owned by SYSTEM.
local function file_granting(name, mask, opts)
    opts = opts or {}
    local path = B .. "/" .. name
    vm:write_file(path, "content")
    local sd = access.sd({
        owner = opts.owner or token.SID.LOCAL_SYSTEM,
        group = opts.group or token.SID.LOCAL_SYSTEM,
        dacl = access.acl({ access.ace(access.ACE.ALLOWED, mask, token.SID.EVERYONE) }),
        sacl = opts.sacl,
    })
    local info = OWNER_GROUP_DACL | (opts.sacl and SI.SACL or 0)
    assert(kacs.set_sd(vm, path, sd, info).ret == 0, "authoring " .. path)
    return path
end

--- Run `fn(worker)` as a minted TEST_USER holding `privs` (plus
--- SeChangeNotifyPrivilege) at `integrity`.
local function as_user(t, privs, fn, opts)
    opts = opts or {}
    local bits = CHANGE_NOTIFY | (privs or 0)
    token.as_principal(t, vm, {
        privs_present = bits, privs_enabled = bits,
        integrity_level = opts.integrity,
        groups = opts.groups,
    }, fn)
end

--- A descriptor subset naming just an owner.
local function owner_only(sid)
    return access.sd({ owner = sid })
end

local ALL_BUT = function(bits) return kacs.ALL_RIGHTS & ~bits end

-- ---- the component table --------------------------------------------------

test("changing the owner needs WRITE_OWNER",
    { spec = "PKM *facs.set-sd.owner-requires-write-owner" }, function(t)
        local denied = file_granting("owner-denied", ALL_BUT(kacs.RIGHT.WRITE_OWNER))
        local allowed = file_granting("owner-allowed", kacs.ALL_RIGHTS)
        as_user(t, 0, function(w)
            local r = kacs.set_sd(w, denied, owner_only(token.SID.TEST_USER), SI.OWNER)
            t:assert_eq(r.ret, -1, "every right but WRITE_OWNER is not enough")
            t:assert_eq(r.errno, sys.E.ACCES, "EACCES")
            local ok = kacs.set_sd(w, allowed, owner_only(token.SID.TEST_USER), SI.OWNER)
            t:assert_eq(ok.ret, 0, "with WRITE_OWNER it succeeds: " .. sys.errname(ok.errno))
        end)
        t:assert_eq(access.parse_sd(assert(kacs.get_sd(vm, allowed, SI.OWNER))).owner,
            token.SID.TEST_USER, "and the owner changed")
    end)

test("changing the DACL needs WRITE_DAC",
    { spec = "PKM *facs.set-sd.dacl-requires-write-dac" }, function(t)
        local denied = file_granting("dacl-denied", ALL_BUT(kacs.RIGHT.WRITE_DAC))
        local allowed = file_granting("dacl-allowed", kacs.ALL_RIGHTS)
        local new_dacl = access.sd({
            dacl = access.acl({ access.ace(access.ACE.ALLOWED, kacs.RIGHT.READ_DATA,
                token.SID.TEST_USER) }),
        })
        as_user(t, 0, function(w)
            local r = kacs.set_sd(w, denied, new_dacl, SI.DACL)
            t:assert_eq(r.ret, -1, "every right but WRITE_DAC is not enough")
            t:assert_eq(r.errno, sys.E.ACCES, "EACCES")
            local ok = kacs.set_sd(w, allowed, new_dacl, SI.DACL)
            t:assert_eq(ok.ret, 0, "with WRITE_DAC it succeeds: " .. sys.errname(ok.errno))
        end)
    end)

test("changing the SACL needs ACCESS_SYSTEM_SECURITY, which only SeSecurityPrivilege grants",
    { spec = "PKM *facs.set-sd.sacl-requires-access-system-security" }, function(t)
        local path = file_granting("sacl", kacs.ALL_RIGHTS)
        local sacl = access.sd({
            sacl = access.acl({ access.ace(access.ACE.AUDIT, kacs.RIGHT.READ_DATA,
                token.SID.EVERYONE, access.ACE_FLAG.SUCCESSFUL_ACCESS) }),
        })
        -- A DACL granting every object right still cannot reach the SACL:
        -- ACCESS_SYSTEM_SECURITY is not a bit a DACL can hand out.
        as_user(t, 0, function(w)
            local r = kacs.set_sd(w, path, sacl, SI.SACL)
            t:assert_eq(r.ret, -1, "a principal without SeSecurityPrivilege is refused")
            t:assert_eq(r.errno, sys.E.ACCES, "EACCES")
        end)
        as_user(t, token.bit(token.PRIV.SECURITY), function(w)
            local r = kacs.set_sd(w, path, sacl, SI.SACL)
            t:assert_eq(r.ret, 0, "and succeeds with it: " .. sys.errname(r.errno))
        end)
        t:assert(access.parse_sd(assert(kacs.get_sd(vm, path, SI.SACL))).sacl,
            "the SACL is there")
    end)

test("setting the integrity label needs WRITE_OWNER",
    { spec = "PKM *facs.set-sd.label-requires-write-owner" }, function(t)
        local denied = file_granting("label-denied", ALL_BUT(kacs.RIGHT.WRITE_OWNER))
        local allowed = file_granting("label-allowed", kacs.ALL_RIGHTS)
        local low = access.sd({
            sacl = access.acl({ access.label_ace(token.INTEGRITY.LOW) }),
        })
        as_user(t, 0, function(w)
            local r = kacs.set_sd(w, denied, low, LABEL)
            t:assert_eq(r.ret, -1, "without WRITE_OWNER the label cannot be set")
            t:assert_eq(r.errno, sys.E.ACCES, "EACCES")
            local ok = kacs.set_sd(w, allowed, low, LABEL)
            t:assert_eq(ok.ret, 0, "with it, a label at or below the caller's own lands: " ..
                sys.errname(ok.errno))
        end)
    end)

test("only the indicated components change; the rest are preserved",
    { spec = "PKM *facs.set-sd.merge-preserves-unindicated" }, function(t)
        local path = file_granting("merge", kacs.ALL_RIGHTS,
            { group = token.SID.ADMINISTRATORS })
        local before = access.parse_sd(assert(kacs.get_sd(vm, path, OWNER_GROUP_DACL)))
        -- A subset naming an owner only, with no group and no DACL.
        local r = kacs.set_sd(vm, path, owner_only(token.SID.TEST_USER), SI.OWNER)
        t:assert_eq(r.ret, 0, "the owner alone is written: " .. sys.errname(r.errno))
        local after = access.parse_sd(assert(kacs.get_sd(vm, path, OWNER_GROUP_DACL)))
        t:assert_eq(after.owner, token.SID.TEST_USER, "the owner changed")
        t:assert_eq(after.group, before.group, "the group did not")
        t:assert_eq(after.dacl.count, before.dacl.count, "nor the DACL's ACE count")
        t:assert_eq(after.dacl.aces[1].mask, before.dacl.aces[1].mask, "nor its mask")
        t:assert_eq(after.dacl.aces[1].sid, before.dacl.aces[1].sid, "nor its trustee")
    end)

test("SACL and LABEL cannot be combined in one call",
    { spec = "PKM *facs.set-sd.sacl-label-exclusive" }, function(t)
        local path = file_granting("exclusive", kacs.ALL_RIGHTS)
        local sd = access.sd({
            sacl = access.acl({ access.label_ace(token.INTEGRITY.MEDIUM) }),
        })
        local r = kacs.set_sd(vm, path, sd, SI.SACL | LABEL)
        t:assert_eq(r.ret, -1, "both bits together are refused")
        t:assert_eq(r.errno, sys.E.INVAL, "EINVAL — they mean incompatible things")
        t:assert_eq(kacs.set_sd(vm, path, sd, LABEL).ret, 0, "either one alone is fine")
        t:assert_eq(kacs.set_sd(vm, path, access.sd({ sacl = access.acl({}) }),
            SI.SACL).ret, 0, "as is the other")
    end)

test("a SACL write replaces the object's entire SACL",
    { spec = "PKM *facs.set-sd.sacl-write-replaces-all" }, function(t)
        local path = file_granting("sacl-replace", kacs.ALL_RIGHTS, {
            sacl = access.acl({
                access.ace(access.ACE.AUDIT, kacs.RIGHT.READ_DATA, token.SID.EVERYONE,
                    access.ACE_FLAG.SUCCESSFUL_ACCESS),
                access.ace(access.ACE.AUDIT, kacs.RIGHT.WRITE_DATA,
                    token.SID.ADMINISTRATORS, access.ACE_FLAG.FAILED_ACCESS),
            }),
        })
        local before = access.parse_sd(assert(kacs.get_sd(vm, path, SI.SACL)))
        t:assert_eq(before.sacl.count, 2, "two audit ACEs to start with")
        local one = access.sd({
            sacl = access.acl({ access.ace(access.ACE.AUDIT, kacs.RIGHT.EXECUTE,
                token.SID.TEST_USER, access.ACE_FLAG.FAILED_ACCESS) }),
        })
        t:assert_eq(kacs.set_sd(vm, path, one, SI.SACL).ret, 0, "a one-ACE SACL is written")
        local after = access.parse_sd(assert(kacs.get_sd(vm, path, SI.SACL)))
        t:assert_eq(after.sacl.count, 1, "and it replaced both, rather than merging")
        t:assert_eq(after.sacl.aces[1].sid, token.SID.TEST_USER, "leaving only the new one")
    end)

test("a LABEL write touches the label subset only",
    { spec = "PKM *facs.set-sd.label-write-subset" }, function(t)
        local audit = access.ace(access.ACE.AUDIT, kacs.RIGHT.READ_DATA,
            token.SID.EVERYONE, access.ACE_FLAG.SUCCESSFUL_ACCESS)
        local path = file_granting("label-subset", kacs.ALL_RIGHTS,
            { sacl = access.acl({ audit }) })
        -- A present SACL holding exactly one non-inherit-only label ACE.
        local set = access.sd({
            sacl = access.acl({ access.label_ace(token.INTEGRITY.LOW) }),
        })
        t:assert_eq(kacs.set_sd(vm, path, set, LABEL).ret, 0, "the label is set")
        local labelled = access.parse_sd(assert(kacs.get_sd(vm, path, LABEL)))
        t:assert(labelled.sacl, "the label subset reads back as a SACL")
        t:assert_eq(labelled.sacl.count, 1, "with one ACE")
        t:assert_eq(labelled.sacl.aces[1].type, access.ACE.MANDATORY_LABEL,
            "a SYSTEM_MANDATORY_LABEL_ACE")
        t:assert_eq(labelled.sacl.aces[1].sid, token.label_sid(token.INTEGRITY.LOW),
            "naming the level asked for")
        local full = access.parse_sd(assert(kacs.get_sd(vm, path, SI.SACL)))
        local kinds = {}
        for _, a in ipairs(full.sacl.aces) do kinds[a.type] = true end
        t:assert(kinds[access.ACE.AUDIT], "the object's non-label SACL ACEs are preserved")

        -- No SACL component removes the explicit label.
        t:assert_eq(kacs.set_sd(vm, path, access.sd({ owner = token.SID.LOCAL_SYSTEM }),
            LABEL).ret, 0, "a subset with no SACL removes it")
        local cleared = access.parse_sd(assert(kacs.get_sd(vm, path, LABEL)))
        t:assert(not cleared.sacl, "the object is back to unlabelled")
        local still = access.parse_sd(assert(kacs.get_sd(vm, path, SI.SACL)))
        t:assert(still.sacl, "and the audit ACEs survived that too")
    end)

test("a merge that would leave the object with no owner fails",
    { spec = "PKM *facs.set-sd.owner-must-remain" }, function(t)
        local path = file_granting("ownerless", kacs.ALL_RIGHTS)
        -- OWNER indicated, but the input carries no owner SID.
        local r = kacs.set_sd(vm, path, access.sd({ group = token.SID.LOCAL_SYSTEM }),
            SI.OWNER)
        t:assert_eq(r.ret, -1, "an owner-less result is refused")
        t:assert_eq(r.errno, sys.E.INVAL, "EINVAL")
        t:assert(access.parse_sd(assert(kacs.get_sd(vm, path, SI.OWNER))).owner,
            "and the object still has one")
        -- The group SID, by contrast, may be null.
        local ok = kacs.set_sd(vm, path, access.sd({ owner = token.SID.LOCAL_SYSTEM }),
            SI.OWNER | SI.GROUP)
        t:assert_eq(ok.ret, 0, "a null group is accepted: " .. sys.errname(ok.errno))
        t:assert(not access.parse_sd(assert(kacs.get_sd(vm, path, SI.GROUP))).group,
            "and the group is gone")
    end)

test("MIC applies to these checks — a low-integrity caller cannot rewrite a high one",
    { spec = "PKM *facs.set-sd.mic-pip-apply" }, function(t)
        local path = file_granting("mic", kacs.ALL_RIGHTS)
        -- The agent runs at System integrity, so it may label at High.
        t:assert_eq(kacs.set_sd(vm, path, access.sd({
            sacl = access.acl({ access.label_ace(token.INTEGRITY.HIGH) }) }), LABEL).ret, 0,
            "the file is labelled High")
        as_user(t, 0, function(w)
            -- The DACL grants WRITE_OWNER and WRITE_DAC to Everyone; only
            -- the mandatory policy stands in the way.
            local r = kacs.set_sd(w, path, owner_only(token.SID.TEST_USER), SI.OWNER)
            t:assert_eq(r.ret, -1, "a Medium caller cannot write up to a High object")
            t:assert_eq(r.errno, sys.E.ACCES, "EACCES")
            local d = kacs.set_sd(w, path, access.sd({
                dacl = access.acl({ access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS,
                    token.SID.TEST_USER) }) }), SI.DACL)
            t:assert_eq(d.ret, -1, "nor its DACL, even though the DACL grants WRITE_DAC")
            t:assert_eq(d.errno, sys.E.ACCES, "EACCES")
        end, { integrity = token.INTEGRITY.MEDIUM })
    end)

-- ---- ownership ------------------------------------------------------------

test("a new owner may only be the caller's own SID, or a group carrying SE_GROUP_OWNER",
    { spec = "PKM *facs.set-sd.ownership" }, function(t)
        local path = file_granting("ownership", kacs.ALL_RIGHTS)
        as_user(t, 0, function(w)
            local own = kacs.set_sd(w, path, owner_only(token.SID.TEST_USER), SI.OWNER)
            t:assert_eq(own.ret, 0, "the caller's own SID is accepted: " ..
                sys.errname(own.errno))
            local foreign = kacs.set_sd(w, path, owner_only(token.SID.TEST_USER_2), SI.OWNER)
            t:assert_eq(foreign.ret, -1, "an arbitrary other SID is not")
            t:assert_eq(foreign.errno, sys.E.ACCES, "EACCES")
            local group = kacs.set_sd(w, path, owner_only(token.SID.TEST_GROUP), SI.OWNER)
            t:assert_eq(group.ret, -1,
                "nor a group SID the token does not flag SE_GROUP_OWNER")
            t:assert_eq(group.errno, sys.E.ACCES, "EACCES")
        end)
        -- The same group, this time carrying the owner attribute.
        local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT
            | token.GROUP.ENABLED
        as_user(t, 0, function(w)
            local r = kacs.set_sd(w, path, owner_only(token.SID.TEST_GROUP), SI.OWNER)
            t:assert_eq(r.ret, 0, "a group flagged SE_GROUP_OWNER is accepted: " ..
                sys.errname(r.errno))
            t:assert_eq(access.parse_sd(assert(kacs.get_sd(w, path, SI.OWNER))).owner,
                token.SID.TEST_GROUP, "and becomes the owner")
        end, { groups = {
            { sid = token.SID.EVERYONE, attributes = ENABLED },
            { sid = token.SID.TEST_GROUP, attributes = ENABLED | token.GROUP.OWNER },
        } })
    end)

test("SeTakeOwnershipPrivilege reaches the caller's own SID, SeRestorePrivilege any SID",
    { spec = "PKM *facs.set-sd.take-ownership-and-restore" }, function(t)
        -- A descriptor that grants nothing at all, so only a privilege can
        -- get past it.
        local path = B .. "/takeown"
        vm:write_file(path, "content")
        assert(kacs.set_sd(vm, path, access.sd({
            owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
            dacl = access.acl({}) }), OWNER_GROUP_DACL).ret == 0, "an empty DACL")

        as_user(t, 0, function(w)
            local r = kacs.set_sd(w, path, owner_only(token.SID.TEST_USER), SI.OWNER)
            t:assert_eq(r.ret, -1, "with no privilege the empty DACL denies")
            t:assert_eq(r.errno, sys.E.ACCES, "EACCES")
        end)
        as_user(t, token.bit(token.PRIV.TAKE_OWNERSHIP), function(w)
            local own = kacs.set_sd(w, path, owner_only(token.SID.TEST_USER), SI.OWNER)
            t:assert_eq(own.ret, 0,
                "SeTakeOwnershipPrivilege sets ownership to the caller's own SID: " ..
                sys.errname(own.errno))
            local foreign = kacs.set_sd(w, path, owner_only(token.SID.TEST_USER_2), SI.OWNER)
            t:assert_eq(foreign.ret, -1, "but not to somebody else's")
            t:assert_eq(foreign.errno, sys.E.ACCES, "EACCES")
        end)
        as_user(t, token.bit(token.PRIV.RESTORE), function(w)
            local r = kacs.set_sd(w, path, owner_only(token.SID.TEST_USER_2), SI.OWNER)
            t:assert_eq(r.ret, 0, "SeRestorePrivilege allows an arbitrary SID: " ..
                sys.errname(r.errno))
        end)
        -- Reading the owner back needs READ_CONTROL, which the empty DACL
        -- grants nobody and which SeBackupPrivilege only supplies under a
        -- backup intent kacs_get_sd does not take — so widen the DACL
        -- first, which the agent's own SeRestorePrivilege does allow.
        t:assert_eq(kacs.set_sd(vm, path, access.sd({
            dacl = access.acl({ access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS,
                token.SID.EVERYONE) }) }), SI.DACL).ret, 0, "the DACL is widened")
        t:assert_eq(access.parse_sd(assert(kacs.get_sd(vm, path, SI.OWNER))).owner,
            token.SID.TEST_USER_2, "and the arbitrary owner landed")
    end)

-- ---- integrity labels -----------------------------------------------------

test("without SeRelabelPrivilege a label may be set only at or below the caller's level",
    { spec = "PKM *facs.set-sd.label-level-constraint" }, function(t)
        local path = file_granting("relabel", kacs.ALL_RIGHTS)
        local function label(level)
            return access.sd({ sacl = access.acl({ access.label_ace(level) }) })
        end
        as_user(t, 0, function(w)
            t:assert_eq(kacs.set_sd(w, path, label(token.INTEGRITY.LOW), LABEL).ret, 0,
                "a Medium caller may label Low")
            t:assert_eq(kacs.set_sd(w, path, label(token.INTEGRITY.MEDIUM), LABEL).ret, 0,
                "and Medium")
            local up = kacs.set_sd(w, path, label(token.INTEGRITY.HIGH), LABEL)
            t:assert_eq(up.ret, -1, "but not High")
            t:assert_eq(up.errno, sys.E.ACCES, "EACCES")
        end, { integrity = token.INTEGRITY.MEDIUM })
        as_user(t, token.bit(token.PRIV.RELABEL), function(w)
            local up = kacs.set_sd(w, path, label(token.INTEGRITY.HIGH), LABEL)
            t:assert_eq(up.ret, 0, "with SeRelabelPrivilege any level is allowed: " ..
                sys.errname(up.errno))
        end, { integrity = token.INTEGRITY.MEDIUM })
        t:assert_eq(access.parse_sd(assert(kacs.get_sd(vm, path, LABEL))).sacl.aces[1].sid,
            token.label_sid(token.INTEGRITY.HIGH), "and the object is now High")
    end)

test("the level constraint applies to a label ACE embedded in a full SACL write too",
    { spec = "PKM *facs.set-sd.label-constraint-via-sacl" }, function(t)
        local path = file_granting("relabel-sacl", kacs.ALL_RIGHTS)
        local raising = access.sd({
            sacl = access.acl({ access.label_ace(token.INTEGRITY.HIGH) }),
        })
        -- SeSecurityPrivilege alone satisfies the SACL component's own
        -- gate; the label ACE inside it still needs SeRelabelPrivilege.
        as_user(t, token.bit(token.PRIV.SECURITY), function(w)
            local r = kacs.set_sd(w, path, raising, SI.SACL)
            t:assert_eq(r.ret, -1,
                "a SACL raising integrity above the caller is refused")
            t:assert_eq(r.errno, sys.E.ACCES, "EACCES")
        end, { integrity = token.INTEGRITY.MEDIUM })
        as_user(t, token.bit(token.PRIV.SECURITY) | token.bit(token.PRIV.RELABEL),
            function(w)
                local r = kacs.set_sd(w, path, raising, SI.SACL)
                t:assert_eq(r.ret, 0, "with SeRelabelPrivilege it is allowed: " ..
                    sys.errname(r.errno))
            end, { integrity = token.INTEGRITY.MEDIUM })
    end)

-- ---- the SeRestorePrivilege bypass ----------------------------------------

test("SeRestorePrivilege fires only where set-security runs a live AccessCheck",
    { spec = "PKM *facs.set-sd.restore-bypass-live-only" }, function(t)
        -- A pathname is one of the live routes, so the privilege grants
        -- every requested right against a descriptor that grants none.
        local path = B .. "/restore-live"
        vm:write_file(path, "content")
        assert(kacs.set_sd(vm, path, access.sd({
            owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
            dacl = access.acl({}) }), OWNER_GROUP_DACL).ret == 0, "an empty DACL")
        as_user(t, 0, function(w)
            local r = kacs.set_sd(w, path, access.sd({
                dacl = access.acl({ access.ace(access.ACE.ALLOWED,
                    kacs.RIGHT.READ_DATA, token.SID.TEST_USER) }) }), SI.DACL)
            t:assert_eq(r.ret, -1, "without the privilege the empty DACL denies")
            t:assert_eq(r.errno, sys.E.ACCES, "EACCES")
        end)
        as_user(t, token.bit(token.PRIV.RESTORE), function(w)
            local r = kacs.set_sd(w, path, access.sd({
                dacl = access.acl({ access.ace(access.ACE.ALLOWED,
                    kacs.RIGHT.READ_DATA, token.SID.TEST_USER) }) }), SI.DACL)
            t:assert_eq(r.ret, 0, "with it, WRITE_DAC is granted on the live path: " ..
                sys.errname(r.errno))
            -- And ACCESS_SYSTEM_SECURITY with it, on the same route.
            local sacl = kacs.set_sd(w, path, access.sd({
                sacl = access.acl({ access.ace(access.ACE.AUDIT, kacs.RIGHT.READ_DATA,
                    token.SID.EVERYONE, access.ACE_FLAG.SUCCESSFUL_ACCESS) }) }), SI.SACL)
            t:assert_eq(sacl.ret, 0, "and the SACL too: " .. sys.errname(sacl.errno))
        end)
    end)

test("on an ordinary file descriptor the privilege has no effect at all",
    { spec = "PKM *facs.set-sd.restore-no-effect-on-fd" }, function(t)
        -- The agent is SYSTEM and holds SeRestorePrivilege; the only thing
        -- consulted here is the mask the descriptor was opened with.
        local path = file_granting("restore-fd", kacs.ALL_RIGHTS)
        local base = kacs.RIGHT.READ_DATA | kacs.RIGHT.READ_ATTRIBUTES
            | kacs.RIGHT.SYNCHRONIZE
        local new_dacl = access.sd({
            dacl = access.acl({ access.ace(access.ACE.ALLOWED, kacs.RIGHT.READ_DATA,
                token.SID.TEST_USER) }),
        })
        local without = facs.handle(t, vm, path, base | kacs.RIGHT.READ_CONTROL)
        local r = kacs.set_sd_fd(vm, without, new_dacl, SI.DACL)
        t:assert_eq(r.ret, -1, "a descriptor whose cached mask lacks WRITE_DAC is refused")
        t:assert_eq(r.errno, sys.E.ACCES,
            "EACCES — no AccessCheck runs, so the privilege never fires")
        sys.close(vm, without)

        local with = facs.handle(t, vm, path,
            base | kacs.RIGHT.READ_CONTROL | kacs.RIGHT.WRITE_DAC)
        local ok = kacs.set_sd_fd(vm, with, new_dacl, SI.DACL)
        t:assert_eq(ok.ret, 0, "the same call on a descriptor that has it succeeds: " ..
            sys.errname(ok.errno))
        sys.close(vm, with)
    end)

-- ---- mandatory resource attributes ----------------------------------------

test("a mandatory resource attribute cannot be dropped or changed without SeTcbPrivilege",
    { spec = "PKM *facs.set-sd.mandatory-attribute-requires-tcb" }, function(t)
        local mandatory = access.resource_attribute_ace("Mandatory", 7,
            access.CLAIM_FLAG.MANDATORY)
        local audit = access.ace(access.ACE.AUDIT, kacs.RIGHT.READ_DATA,
            token.SID.EVERYONE, access.ACE_FLAG.SUCCESSFUL_ACCESS)
        local path = file_granting("mandatory-attr", kacs.ALL_RIGHTS,
            { sacl = access.acl({ mandatory, audit }) })
        local stored = access.parse_sd(assert(kacs.get_sd(vm, path, SI.SACL)))
        t:assert_eq(stored.sacl.count, 2, "the SACL carries the attribute and an audit ACE")

        local dropped = access.sd({ sacl = access.acl({ audit }) })
        local modified = access.sd({ sacl = access.acl({
            access.resource_attribute_ace("Mandatory", 9, access.CLAIM_FLAG.MANDATORY),
            audit }) })
        as_user(t, token.bit(token.PRIV.SECURITY), function(w)
            local r = kacs.set_sd(w, path, dropped, SI.SACL)
            t:assert_eq(r.ret, -1, "removing it without SeTcbPrivilege fails the whole call")
            local m = kacs.set_sd(w, path, modified, SI.SACL)
            t:assert_eq(m.ret, -1, "and so does changing its values: " ..
                sys.errname(m.errno))
        end)
        local after = access.parse_sd(assert(kacs.get_sd(vm, path, SI.SACL)))
        t:assert_eq(after.sacl.count, 2, "nothing was silently dropped")
        -- The agent holds SeTcbPrivilege, so the same call goes through.
        t:assert_eq(kacs.set_sd(vm, path, dropped, SI.SACL).ret, 0,
            "SeTcbPrivilege permits the removal")
        t:assert_eq(access.parse_sd(assert(kacs.get_sd(vm, path, SI.SACL))).sacl.count, 1,
            "and the attribute is gone")
    end)

-- ---- write mechanics ------------------------------------------------------

test("the write goes to the xattr through a path the denial hook does not gate",
    { spec = "PKM *facs.set-sd.write-bypasses-denial-hook" }, function(t)
        -- A fresh deny-missing mount root: no descriptor, and therefore no
        -- canonical xattr, before the call.
        local at = "/setsd-write"
        t:assert(kacs.new_mount(vm, "tmpfs", at, nil, nil), "a fresh mount")
        t:assert_eq(#(sys.listxattr(vm, at) or {}), 0, "whose root stores nothing")
        local sd = access.sd({
            owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
            dacl = access.acl({ access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS,
                token.SID.EVERYONE, access.ACE_FLAG.OBJECT_INHERIT
                    | access.ACE_FLAG.CONTAINER_INHERIT) }),
        })
        -- The same bytes through the ordinary xattr surface are refused.
        local raw = sys.setxattr(vm, at, "security.peios.sd", sd)
        t:assert_eq(raw.errno, sys.E.ACCES, "a raw write of these bytes is denied")
        t:assert_eq(kacs.set_sd(vm, at, sd, OWNER_GROUP_DACL).ret, 0,
            "set-security writes them")
        local names = sys.listxattr(vm, at) or {}
        t:assert_eq(#names, 1, "and the medium now stores exactly one xattr")
        t:assert_eq(names[1], "security.peios.sd", "the canonical name")
        t:assert_eq(kacs.get_sd(vm, at, OWNER_GROUP_DACL), sd,
            "and the in-memory cache agrees with it")
    end)

test("an audit event is emitted when the file's SACL carries a matching audit ACE",
    { spec = "PKM *facs.set-sd.audit-on-matching-ace" }, function(t)
        -- The audit ACE has to match the *result* of the merge, since that
        -- is the descriptor the emitter evaluates, and it has to name the
        -- rights the call required — WRITE_DAC for a DACL write.
        local matching = access.acl({
            access.ace(access.ACE.AUDIT, kacs.ALL_RIGHTS, token.SID.EVERYONE,
                access.ACE_FLAG.SUCCESSFUL_ACCESS | access.ACE_FLAG.FAILED_ACCESS),
        })
        local path = file_granting("audit-on", kacs.ALL_RIGHTS, { sacl = matching })
        local new_dacl = access.sd({
            dacl = access.acl({ access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS,
                token.SID.EVERYONE) }),
        })
        local events = kmes.recording(t, vm, function()
            t:assert_eq(kacs.set_sd(vm, path, new_dacl, SI.DACL).ret, 0, "the DACL is set")
        end)
        t:assert(#kmes.of_type(events, "access-audit") > 0,
            "a matching audit ACE produced an access-audit event")

        -- And an object with no SACL produces none.
        local quiet = file_granting("audit-off", kacs.ALL_RIGHTS)
        local silent = kmes.recording(t, vm, function()
            t:assert_eq(kacs.set_sd(vm, quiet, new_dacl, SI.DACL).ret, 0, "the same write")
        end)
        t:assert_eq(#kmes.of_type(silent, "access-audit"), 0,
            "with no SACL there is nothing to match and no event")
    end)
