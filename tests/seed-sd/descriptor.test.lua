-- The descriptor seed-sd writes: claims B1–B8 of the seed-sd inventory.
--
-- `build_seed_sd` is the only definition of the bootstrap descriptor
-- left in-tree, and because every ACE in it is inheritable it is not
-- one file's policy but the access policy of every tree seeded with it
-- — prelude's `/dev`, an installer's target root, the tmpfs a
-- root-mount hook pivots into. Changing it changes all of them, so the
-- bytes are pinned here field by field rather than as a blob: owner,
-- group, the three ACEs, their order, their masks and their
-- inheritance flags. A failure then names the part that moved.
--
-- Everything is read back from a node seed-sd actually stamped, with
-- `kacs_get_sd` and `access.parse_sd`, rather than rebuilt from the
-- source's constants — the point is what lands on the inode.
--
-- The two `--sddl` cases are the other half of the contract. It
-- replaces the built-in outright rather than adding to it, and a
-- descriptor that does not parse is fatal with no fall back to the
-- default, because a fall back would stamp a *narrower* policy than
-- the caller asked for and the symptom would surface far away.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local access = require("helpers.access")
local token = require("helpers.token")

local vm = provium:vm("sd", "prelude"):boot()

local SEED = "/bin/seed-sd"
local ALL = kacs.SI.OWNER | kacs.SI.GROUP | kacs.SI.DACL

-- The flags and mask the built-in is made of, from the helpers rather
-- than from literals: OI|CI on the two principal ACEs, and IO as well
-- on CREATOR OWNER.
local OI, CI = access.ACE_FLAG.OBJECT_INHERIT, access.ACE_FLAG.CONTAINER_INHERIT
local IO = access.ACE_FLAG.INHERIT_ONLY
local GENERIC_ALL = access.STD.GENERIC_ALL

-- `WellKnownSid` has no CREATOR OWNER variant and neither SDDL
-- vocabulary has a `CO` alias, so seed-sd spells it as a literal SID.
local CREATOR_OWNER = token.sid(3, 0)

--- A directory on the root a hook mounted and seeded. Not `/tmp`: the
--- agent mounts a tmpfs of its own there as PID 1, and that one is
--- DENY_MISSING with no descriptor on its root.
local function workspace(name)
    local at = "/run/seed-sd-desc/" .. name
    vm:mkdir(at, { parents = true })
    return at
end

--- Seed a fresh file with the built-in descriptor and return the
--- descriptor that landed on it, parsed.
local function stamped(name)
    local path = workspace(name) .. "/f"
    vm:write_file(path, "x")
    local r = vm:run(SEED, { path })
    assert(r.exit_code == 0, "seeding " .. path .. ": " .. r.stderr)
    return access.parse_sd(assert(kacs.get_sd(vm, path, ALL))), path
end

-- ---- the built-in descriptor ----------------------------------------------

test("the built-in default is owned by SYSTEM, with SYSTEM as group",
    { spec = "seed-sd sd.default-is-owned-by-system" }, function(t)
        local sd = stamped("owner")
        t:assert_eq(sd.owner, token.SID.LOCAL_SYSTEM,
            "owner is SYSTEM (" .. token.sid_string(sd.owner) .. ")")
        t:assert_eq(sd.group, token.SID.LOCAL_SYSTEM,
            "group is SYSTEM (" .. token.sid_string(sd.group) .. ")")
    end)

test("its DACL is exactly three ACEs: Allow SYSTEM, Allow BUILTIN\\Administrators, Allow CREATOR OWNER",
    { spec = "seed-sd sd.default-dacl-has-three-aces" }, function(t)
        local sd = stamped("three-aces")
        t:assert(sd.dacl, "the descriptor carries a DACL")
        t:assert_eq(sd.dacl.count, 3, "three ACEs, and no more")
        t:assert_eq(#sd.dacl.aces, 3, "three ACEs are actually present")

        local trustees = {}
        for _, ace in ipairs(sd.dacl.aces) do
            t:assert_eq(ace.type, access.ACE.ALLOWED,
                token.sid_string(ace.sid) .. "'s ACE allows rather than denies")
            trustees[token.sid_string(ace.sid)] = true
        end
        t:assert(trustees["S-1-5-18"], "SYSTEM is one of them")
        t:assert(trustees["S-1-5-32-544"], "BUILTIN\\Administrators is another")
        t:assert(trustees["S-1-3-0"], "CREATOR OWNER is the third")
    end)

test("in that order",
    { spec = "seed-sd sd.default-ace-order" }, function(t)
        local sd = stamped("ace-order")
        t:assert_eq(sd.dacl.aces[1].sid, token.SID.LOCAL_SYSTEM,
            "SYSTEM first (got " .. token.sid_string(sd.dacl.aces[1].sid) .. ")")
        t:assert_eq(sd.dacl.aces[2].sid, token.SID.ADMINISTRATORS,
            "BUILTIN\\Administrators second (got " .. token.sid_string(sd.dacl.aces[2].sid) .. ")")
        t:assert_eq(sd.dacl.aces[3].sid, CREATOR_OWNER,
            "CREATOR OWNER third (got " .. token.sid_string(sd.dacl.aces[3].sid) .. ")")
    end)

test("SYSTEM and Administrators are GENERIC_ALL with OBJECT_INHERIT and CONTAINER_INHERIT",
    { spec = "seed-sd sd.system-and-administrators-are-inheritable-generic-all" }, function(t)
        local sd = stamped("inheritable")
        for i, who in ipairs({ "SYSTEM", "BUILTIN\\Administrators" }) do
            local ace = sd.dacl.aces[i]
            t:assert_eq(ace.mask, GENERIC_ALL,
                who .. " is GENERIC_ALL (mask 0x" .. string.format("%08x", ace.mask) .. ")")
            t:assert_eq(ace.flags, OI | CI,
                who .. " carries OBJECT_INHERIT and CONTAINER_INHERIT and nothing else " ..
                "(flags 0x" .. string.format("%02x", ace.flags) .. "), so the template propagates")
        end
    end)

test("CREATOR OWNER carries INHERIT_ONLY as well",
    { spec = "seed-sd sd.creator-owner-is-inherit-only" }, function(t)
        local sd = stamped("creator-owner")
        local ace = sd.dacl.aces[3]
        t:assert_eq(ace.sid, CREATOR_OWNER,
            "the third ACE names S-1-3-0 (got " .. token.sid_string(ace.sid) .. ")")
        t:assert_eq(ace.mask, GENERIC_ALL, "granting GENERIC_ALL: whoever creates an object " ..
            "gets full control of it")
        t:assert_eq(ace.flags & IO, IO,
            "INHERIT_ONLY is set (flags 0x" .. string.format("%02x", ace.flags) .. ")")
        t:assert_eq(ace.flags, OI | CI | IO,
            "alongside OBJECT_INHERIT and CONTAINER_INHERIT, so KACS carries the rule " ..
            "onward down each container")
    end)

-- ---- --sddl ---------------------------------------------------------------

test("--sddl replaces the built-in entirely rather than adding to it",
    { spec = "seed-sd sddl.replaces-the-built-in-entirely" }, function(t)
        -- Nothing about this descriptor resembles the built-in: a
        -- different owner, a different trustee, one ACE, no inheritance.
        local path = workspace("sddl-replaces") .. "/f"
        vm:write_file(path, "x")
        local r = vm:run(SEED, { "--sddl", "O:BAG:BAD:(A;;GA;;;AU)", path })
        t:assert_eq(r.exit_code, 0, "the run succeeded: " .. r.stderr)

        local sd = access.parse_sd(assert(kacs.get_sd(vm, path, ALL)))
        t:assert_eq(sd.owner, token.SID.ADMINISTRATORS, "the owner is the one given")
        t:assert_eq(sd.group, token.SID.ADMINISTRATORS, "and so is the group")
        t:assert_eq(sd.dacl.count, 1, "the DACL is exactly the one ACE asked for")
        t:assert_eq(sd.dacl.aces[1].sid, token.SID.AUTHENTICATED_USERS,
            "naming the trustee asked for")

        for _, ace in ipairs(sd.dacl.aces) do
            local who = token.sid_string(ace.sid)
            t:assert(who ~= "S-1-5-18" and who ~= "S-1-5-32-544" and who ~= "S-1-3-0",
                "no trace of the built-in three: " .. who .. " is not among them")
        end
    end)

test("an SDDL string that does not parse is a hard failure with no fallback to the default",
    { spec = "seed-sd sddl.unparseable-is-a-hard-failure" }, function(t)
        -- A filesystem mounted at runtime is DENY_MISSING and its root
        -- has no descriptor at all, so "unchanged" is observable: the
        -- read is refused before the seed and must still be refused
        -- after it.
        local at = "/run/seed-sd-desc/unparseable"
        assert(kacs.new_mount(vm, "tmpfs", at, kacs.MOUNT_POLICY.DENY_MISSING))
        local before, before_errno = kacs.get_sd(vm, at, ALL)
        t:assert(before == nil, "the fresh mount's root has no descriptor to read")
        t:assert_eq(before_errno, sys.E.ACCES, "DENY_MISSING refuses it: EACCES")

        local r = vm:run(SEED, { "--sddl", "not a descriptor", at })
        t:assert_eq(r.exit_code, 1, "an unparseable descriptor exits 1: " .. r.stderr)
        t:assert_eq(r.stderr:sub(1, 19), "seed-sd: build SD: ",
            "reporting the descriptor it could not build: " .. r.stderr)

        local after, after_errno = kacs.get_sd(vm, at, ALL)
        t:assert(after == nil,
            "and stamped nothing: falling back to the default would stamp a narrower " ..
            "policy than asked for")
        t:assert_eq(after_errno, sys.E.ACCES, "the root is still MISSING")

        -- The control: the same call without the bad descriptor does
        -- seed it, so the check above is reading a real difference.
        local ok = vm:run(SEED, { at })
        t:assert_eq(ok.exit_code, 0, "the same target seeds cleanly without --sddl: " .. ok.stderr)
        t:assert(kacs.get_sd(vm, at, ALL), "and its descriptor reads back")
    end)

-- ---- what is left alone ---------------------------------------------------

test("only owner, group and DACL are written; the SACL is untouched",
    { spec = "seed-sd sd.only-owner-group-and-dacl-are-written" }, function(t)
        local path = workspace("sacl") .. "/f"
        vm:write_file(path, "x")

        -- An audit ACE nothing in seed-sd would ever write. The agent is
        -- SYSTEM and holds SeSecurityPrivilege, so it can author and
        -- read one back.
        local audit = access.ace(access.ACE.AUDIT, kacs.RIGHT.READ_DATA,
            token.SID.TEST_USER, access.ACE_FLAG.SUCCESSFUL_ACCESS)
        assert(kacs.set_sd(vm, path, access.sd({ sacl = access.acl({ audit }) }),
            kacs.SI.SACL).ret == 0, "authoring a SACL on " .. path)

        local r = vm:run(SEED, { path })
        t:assert_eq(r.exit_code, 0, "the seed succeeded: " .. r.stderr)

        -- It really ran: the DACL is the built-in one now.
        local dacl = access.parse_sd(assert(kacs.get_sd(vm, path, ALL))).dacl
        t:assert_eq(dacl.count, 3, "the DACL was replaced with the built-in three")

        local sacl = access.parse_sd(assert(kacs.get_sd(vm, path, kacs.SI.SACL))).sacl
        t:assert(sacl, "the SACL is still there")
        t:assert_eq(sacl.count, 1, "with the one audit ACE it had")
        t:assert_eq(sacl.aces[1].type, access.ACE.AUDIT, "still an audit ACE")
        t:assert_eq(sacl.aces[1].sid, token.SID.TEST_USER, "still naming the same trustee")
        t:assert_eq(sacl.aces[1].mask, kacs.RIGHT.READ_DATA, "with the same mask")
        t:assert_eq(sacl.aces[1].flags, access.ACE_FLAG.SUCCESSFUL_ACCESS,
            "and the same flags: seed-sd asks for owner, group and DACL only")
    end)
