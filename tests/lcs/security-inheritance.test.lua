-- PKM §5.4.3 — Inheritance and hive roots: what KACS computes and LCS
-- persists at creation, why only CONTAINER_INHERIT_ACE matters, the
-- token-default-DACL fallback, where a hive root's descriptor comes
-- from, and the merge REG_IOC_SET_SECURITY performs.
--
-- Two hives: Machine, whose root carries the descriptor §5.4.3 gives as
-- loregd's convention, and Users, holding one user root written the
-- same way.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local access = require("helpers.access")

local vm = provium:vm("v", "kernel-only"):boot()

local CI = access.ACE_FLAG.CONTAINER_INHERIT
local OI = access.ACE_FLAG.OBJECT_INHERIT
local NP = access.ACE_FLAG.NO_PROPAGATE
local INHERITED = access.ACE_FLAG.INHERITED
local ALL = lcs.KEY_ALL_ACCESS
local R = lcs.RIGHT
local SACL_PRESENT = access.CONTROL.SACL_PRESENT

local USER_SID = token.SID.TEST_USER
local OTHER_SID = token.SID.TEST_USER_2
local USER_ROOT_NAME = token.sid_string(USER_SID)

--- The descriptor §5.4.3 gives for `Users\<SID>\`: the user, SYSTEM and
--- Administrators, all KEY_ALL_ACCESS, all container-inherit.
local USER_ROOT_SD = lcs.sd({
    access.ace(access.ACE.ALLOWED, ALL, USER_SID, CI),
    access.ace(access.ACE.ALLOWED, ALL, kacs.SID.LOCAL_SYSTEM, CI),
    access.ace(access.ACE.ALLOWED, ALL, kacs.SID.ADMINISTRATORS, CI),
})
local MACHINE_ROOT_SD = lcs.machine_root_sd()

local src = lcs.source(vm, { hives = {
    { name = "Machine", sd = MACHINE_ROOT_SD }, { name = "Users" },
} })
src:key("Machine\\Software\\Test")
src:key("Users\\" .. USER_ROOT_NAME, { sd = USER_ROOT_SD, root = src.hives[2].root })

-- Inheritance fixtures. Every one grants Everyone KEY_ALL_ACCESS with no
-- inherit flags so the creating caller can create under it; the marker
-- ACEs are what the child does or does not receive.
local EVERYONE_HERE = access.ace(access.ACE.ALLOWED, ALL, kacs.SID.EVERYONE, 0)
-- And a container-inheritable grant for the creator, so the descriptor
-- the child inherits still passes the re-check of §5.5.2 step 7.
local SYSTEM_DOWN = access.ace(access.ACE.ALLOWED, ALL, kacs.SID.LOCAL_SYSTEM, CI)
src:key("Machine\\Inherit\\Selecting", { sd = lcs.sd({
    EVERYONE_HERE, SYSTEM_DOWN,
    access.ace(access.ACE.ALLOWED, ALL, USER_SID, CI),
    access.ace(access.ACE.ALLOWED, ALL, OTHER_SID, OI),
}) })
src:key("Machine\\Inherit\\NoPropagate", { sd = lcs.sd({
    EVERYONE_HERE, SYSTEM_DOWN,
    access.ace(access.ACE.ALLOWED, ALL, USER_SID, CI | OI | NP),
}) })
src:key("Machine\\Inherit\\Plain", { sd = lcs.sd({ EVERYONE_HERE }) })
src:key("Machine\\Inherit\\Static", { sd = lcs.sd({
    EVERYONE_HERE, SYSTEM_DOWN,
    access.ace(access.ACE.ALLOWED, ALL, USER_SID, CI),
}) })
src:key("Machine\\Sec")
local VALUES = src:key("Machine\\Sec\\Values")
src:value(VALUES, "First", lcs.TYPE.DWORD, lcs.dword(1))
src:value(VALUES, "Second", lcs.TYPE.SZ, lcs.sz("two"))
for i = 1, 8 do src:key("Machine\\Sec\\S" .. i) end
assert(src:register())
src:pump()

local w = vm:spawn_worker()

local function open_key(t, who, path, desired)
    local r = lcs.open_key(src, who or w, -1, path, desired or lcs.KEY_ALL_ACCESS)
    return r
end

local function must_open(t, path, desired, who)
    local r = open_key(t, who, path, desired)
    t:assert(r.ret >= 0, "open " .. path .. ": " .. sys.errname(r.errno or 0))
    return r.ret
end

--- The parsed descriptor of `path`, read as SYSTEM.
local function descriptor_of(t, path, info)
    local fd = must_open(t, path, R.READ_CONTROL | R.ACCESS_SYSTEM_SECURITY)
    local g = lcs.get_security(src, w, fd, info or (lcs.SI.OWNER | lcs.SI.GROUP | lcs.SI.DACL))
    t:assert_eq(g.ret, 0, "get security on " .. path .. ": " .. sys.errname(g.errno or 0))
    sys.close(w, fd)
    return token.parse_sd(g.sd), g.sd
end

--- The ACE in `dacl` naming `sid`, or nil.
local function ace_for(dacl, sid)
    for _, a in ipairs(dacl or {}) do if a.sid == sid then return a end end
    return nil
end

-- Inheritance at creation ------------------------------------------------

test("KACS computes a new key's descriptor and LCS hands the result to the source to persist",
    { spec = "PKM *inherit.kacs-computes-lcs-persists" }, function(t)
        local mark = src:mark()
        local made = lcs.create_key(src, w, { path = "Machine\\Inherit\\Selecting\\Fresh" })
        t:assert(made.ret >= 0, "create: " .. sys.errname(made.errno or 0))
        sys.close(w, made.ret)

        local creates = src:served(lcs.OP.CREATE_KEY, mark)
        t:assert_eq(#creates, 1, "one RSI_CREATE_KEY was issued")
        -- guid(16), name, parent(16), sd, volatile, symlink
        local p = creates[1].payload
        local at = 17
        local _, next_at = string.unpack("<s4", p, at); at = next_at + 16
        local sd = string.unpack("<s4", p, at)
        t:assert(#sd > 20, "carrying a computed descriptor for the source to persist")
        local parsed = token.parse_sd(sd)
        local inherited = ace_for(parsed.dacl, USER_SID)
        t:assert(inherited, "with the parent's container-inheritable ACE in it")
        t:assert_eq(inherited.flags & INHERITED, INHERITED,
            "marked INHERITED, as the KACS inheritance algorithm marks it")

        -- And what the source was told is what the key now has.
        local live = select(2, descriptor_of(t, "Machine\\Inherit\\Selecting\\Fresh"))
        t:assert(ace_for(token.parse_sd(live).dacl, USER_SID),
            "and reading it back finds the same grant")
    end)

test("inheritance is static: a later change to the parent does not propagate to existing children",
    { spec = "PKM *inherit.static-no-repropagation" }, function(t)
        local made = lcs.create_key(src, w, { path = "Machine\\Inherit\\Static\\Child" })
        t:assert(made.ret >= 0, "create: " .. sys.errname(made.errno or 0))
        sys.close(w, made.ret)
        local before = descriptor_of(t, "Machine\\Inherit\\Static\\Child")
        t:assert(ace_for(before.dacl, USER_SID), "the child inherited the parent's ACE")

        -- Rewrite the parent's DACL, dropping that ACE entirely.
        local parent = must_open(t, "Machine\\Inherit\\Static", lcs.KEY_ALL_ACCESS)
        local mark = src:mark()
        t:assert_eq(lcs.set_security(src, w, parent, lcs.SI.DACL, lcs.sd({
            EVERYONE_HERE, SYSTEM_DOWN,
            access.ace(access.ACE.ALLOWED, ALL, OTHER_SID, CI),
        })).ret, 0, "the parent's DACL is replaced")
        sys.close(w, parent)

        local writes = src:served(lcs.OP.WRITE_KEY, mark)
        t:assert_eq(#writes, 1, "exactly one key was written: no tree walk followed")
        local after = descriptor_of(t, "Machine\\Inherit\\Static\\Child")
        t:assert(ace_for(after.dacl, USER_SID),
            "and the child still carries what it inherited at creation")
        t:assert(not ace_for(after.dacl, OTHER_SID),
            "and did not acquire what the parent gained afterwards")
    end)

test("values are not independent security objects: they inherit their key's access control",
    { spec = "PKM *inherit.values-have-no-descriptor-of-their-own" }, function(t)
        token.as_principal(t, vm, { user_sid = USER_SID }, function(w2)
            local fd = open_key(t, w2, "Machine\\Sec\\Values", R.QUERY_VALUE)
            t:assert(fd.ret >= 0, "one right on the key: " .. sys.errname(fd.errno or 0))
            local b = lcs.query_values_batch(src, w2, fd.ret)
            t:assert_eq(b.ret, 0, "and every value on it reads: " .. sys.errname(b.errno or 0))
            t:assert_eq(b.count, 2, "both of them, with no per-value decision to make")
            sys.close(w2, fd.ret)
        end)
        -- There is no ioctl that reads or writes a value's descriptor:
        -- REG_IOC_GET_SECURITY and SET_SECURITY take a key fd, and §5.5.3
        -- has no value-scoped pair.
        local fd = must_open(t, "Machine\\Sec\\Values", R.READ_CONTROL)
        local g = lcs.get_security(src, w, fd, lcs.SI.DACL)
        t:assert_eq(g.ret, 0, "the only descriptor in reach is the key's")
        sys.close(w, fd)
    end)

test("OBJECT_INHERIT_ACE never selects an ACE for inheritance; only CONTAINER_INHERIT_ACE does",
    { spec = "PKM *inherit.object-inherit-ace-never-selects" }, function(t)
        local made = lcs.create_key(src, w, { path = "Machine\\Inherit\\Selecting\\Selected" })
        t:assert(made.ret >= 0, "create: " .. sys.errname(made.errno or 0))
        sys.close(w, made.ret)
        local child = descriptor_of(t, "Machine\\Inherit\\Selecting\\Selected")
        t:assert(ace_for(child.dacl, USER_SID),
            "the container-inheritable ACE reached the child")
        t:assert(not ace_for(child.dacl, OTHER_SID),
            "the object-inherit-only ACE did not: every registry object is a container")
    end)

test("NO_PROPAGATE_INHERIT_ACE clears OBJECT_INHERIT_ACE on the child copy",
    { spec = "PKM *inherit.no-propagate-clears-object-inherit" }, function(t)
        local made = lcs.create_key(src, w, { path = "Machine\\Inherit\\NoPropagate\\Child" })
        t:assert(made.ret >= 0, "create: " .. sys.errname(made.errno or 0))
        sys.close(w, made.ret)
        local child = descriptor_of(t, "Machine\\Inherit\\NoPropagate\\Child")
        local a = ace_for(child.dacl, USER_SID)
        t:assert(a, "the ACE was inherited")
        t:assert_eq(a.flags & OI, 0, "with OBJECT_INHERIT_ACE cleared on the child's copy")
        t:assert_eq(a.flags & CI, 0, "and CONTAINER_INHERIT_ACE too: it propagates no further")
    end)

test("a parent with no inheritable ACEs falls back to the creating token's default DACL",
    { spec = "PKM *inherit.no-inheritable-aces-uses-token-default-dacl" }, function(t)
        local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED
        -- A default DACL with a marker nothing else in this file grants:
        -- if it turns up on the child, it came from the token.
        local marker = access.acl({
            access.ace(access.ACE.ALLOWED, ALL, USER_SID, 0),
            access.ace(access.ACE.ALLOWED, ALL, OTHER_SID, 0),
            access.ace(access.ACE.ALLOWED, ALL, kacs.SID.LOCAL_SYSTEM, 0),
        })
        token.as_principal(t, vm, {
            user_sid = USER_SID, default_dacl = marker,
            groups = {
                { sid = kacs.SID.EVERYONE, attributes = ENABLED },
                { sid = kacs.SID.AUTHENTICATED_USERS, attributes = ENABLED },
                -- Base-layer writes want SYSTEM or Administrators (§5.3.4).
                { sid = kacs.SID.ADMINISTRATORS, attributes = ENABLED },
            },
        }, function(w2)
            local made = lcs.create_key(src, w2, { path = "Machine\\Inherit\\Plain\\Fallback" })
            t:assert(made.ret >= 0, "the principal creates a child: " ..
                sys.errname(made.errno or 0))
            sys.close(w2, made.ret)
        end)
        local child = descriptor_of(t, "Machine\\Inherit\\Plain\\Fallback")
        t:assert(ace_for(child.dacl, OTHER_SID),
            "the child's DACL is the creating token's default DACL")
    end)

test("the token-default fallback covers the DACL only: there is no default SACL",
    { spec = "PKM *inherit.no-default-sacl" }, function(t)
        local parsed = descriptor_of(t, "Machine\\Inherit\\Plain\\Fallback", lcs.SI.ALL)
        t:assert_eq(parsed.control & SACL_PRESENT, 0,
            "a key created under a parent with no inheritable ACEs carries no SACL")
    end)

-- Hive roots --------------------------------------------------------------

test("a hive root has no parent, so it inherits nothing and its descriptor is the source's",
    { spec = "PKM *inherit.hive-root-inherits-nothing" }, function(t)
        local fd = must_open(t, "Machine", R.READ_CONTROL)
        local g = lcs.get_security(src, w, fd, lcs.SI.OWNER | lcs.SI.GROUP | lcs.SI.DACL)
        t:assert_eq(g.ret, 0, "the root's descriptor reads: " .. sys.errname(g.errno or 0))
        sys.close(w, fd)
        t:assert_eq(g.sd, MACHINE_ROOT_SD,
            "and is byte for byte what the source stored: nothing was computed into it")
        local mark = src:mark()
        local up = lcs.open_key(nil, w, -1, "Machine\\..", R.KEY_READ)
        t:assert(up.ret < 0, "there is nothing above it to inherit from either")
        t:assert_eq(#src.log, mark - 1, "and no walk was attempted")
    end)

test("LCS holds no hive root template: it enforces whatever descriptor the source stored",
    { spec = "PKM *inherit.hive-root-descriptor-comes-from-the-source" }, function(t)
        local users = must_open(t, "Users", R.READ_CONTROL)
        local g = lcs.get_security(src, w, users, lcs.SI.OWNER | lcs.SI.GROUP | lcs.SI.DACL)
        t:assert_eq(g.ret, 0, "the second hive's root reads too")
        sys.close(w, users)
        t:assert_eq(g.sd, lcs.permissive_sd(),
            "and carries this source's own choice, not a kernel default")
        t:assert(g.sd ~= MACHINE_ROOT_SD,
            "two roots in one kernel, two different descriptors, both the source's")
    end)

test("the Machine root descriptor loregd writes: SYSTEM and Administrators all, Authenticated Users read",
    { spec = "PKM *inherit.machine-root-default-descriptor" }, function(t)
        local parsed = descriptor_of(t, "Machine")
        local system = ace_for(parsed.dacl, kacs.SID.LOCAL_SYSTEM)
        local admins = ace_for(parsed.dacl, kacs.SID.ADMINISTRATORS)
        local auth = ace_for(parsed.dacl, kacs.SID.AUTHENTICATED_USERS)
        t:assert(system and system.mask == ALL, "SYSTEM holds KEY_ALL_ACCESS")
        t:assert(admins and admins.mask == ALL, "Administrators holds KEY_ALL_ACCESS")
        t:assert(auth and auth.mask == R.KEY_READ, "Authenticated Users holds KEY_READ")
        for _, a in ipairs({ system, admins, auth }) do
            t:assert_eq(a.flags & CI, CI, "and every one of them is container-inherit")
        end
        token.as_principal(t, vm, { user_sid = USER_SID }, function(w2)
            local read = open_key(t, w2, "Machine", R.KEY_READ)
            t:assert(read.ret >= 0, "so an authenticated user may read the root: " ..
                sys.errname(read.errno or 0))
            if read.ret >= 0 then sys.close(w2, read.ret) end
            local write = open_key(t, w2, "Machine", R.KEY_WRITE)
            t:assert_eq(write.errno, sys.E.ACCES, "and no more than read it")
        end)
    end)

test("the Users\\<SID> root descriptor loregd writes: the user, SYSTEM and Administrators",
    { spec = "PKM *inherit.user-root-default-descriptor" }, function(t)
        local path = "Users\\" .. USER_ROOT_NAME
        local parsed = descriptor_of(t, path)
        t:assert(ace_for(parsed.dacl, USER_SID), "the user's own SID is named")
        t:assert(ace_for(parsed.dacl, kacs.SID.LOCAL_SYSTEM), "SYSTEM is named")
        t:assert(ace_for(parsed.dacl, kacs.SID.ADMINISTRATORS), "Administrators is named")
        token.as_principal(t, vm, { user_sid = USER_SID }, function(w2)
            local mine = open_key(t, w2, path, lcs.KEY_ALL_ACCESS)
            t:assert(mine.ret >= 0, "the user holds KEY_ALL_ACCESS over their own root: " ..
                sys.errname(mine.errno or 0))
            if mine.ret >= 0 then sys.close(w2, mine.ret) end
        end)
        token.as_principal(t, vm, { user_sid = OTHER_SID }, function(w3)
            local theirs = open_key(t, w3, path, R.KEY_READ)
            t:assert_eq(theirs.errno, sys.E.ACCES, "and another user holds nothing over it")
        end)
    end)

-- Reading and writing descriptors -----------------------------------------

test("security_info selects which components REG_IOC_GET_SECURITY and SET_SECURITY act on",
    { spec = "PKM *inherit.security-info-selects-components" }, function(t)
        local fd = must_open(t, "Machine\\Sec\\S1", R.READ_CONTROL)
        local owner = lcs.get_security(src, w, fd, lcs.SI.OWNER)
        t:assert_eq(owner.ret, 0, "owner only: " .. sys.errname(owner.errno or 0))
        local o = token.parse_sd(owner.sd)
        t:assert(o.owner, "an owner comes back")
        t:assert(not o.dacl, "and no DACL")

        local dacl = lcs.get_security(src, w, fd, lcs.SI.DACL)
        t:assert_eq(dacl.ret, 0, "DACL only: " .. sys.errname(dacl.errno or 0))
        local d = token.parse_sd(dacl.sd)
        t:assert(d.dacl, "a DACL comes back")
        t:assert(not d.owner, "and no owner")
        sys.close(w, fd)
    end)

test("a zero or unknown security_info is EINVAL, rejected before the source is contacted",
    { spec = "PKM *inherit.security-info-zero-or-unknown-is-einval" }, function(t)
        local fd = must_open(t, "Machine\\Sec\\S2", lcs.KEY_ALL_ACCESS)
        local sd = lcs.permissive_sd()
        local probes = {
            { "GET_SECURITY with zero", function() return lcs.get_security(nil, w, fd, 0) end },
            { "GET_SECURITY with an unknown flag",
              function() return lcs.get_security(nil, w, fd, 0x10) end },
            { "SET_SECURITY with zero",
              function() return lcs.set_security(nil, w, fd, 0, sd) end },
            { "SET_SECURITY with an unknown flag",
              function() return lcs.set_security(nil, w, fd, lcs.SI.DACL | 0x20, sd) end },
        }
        for _, p in ipairs(probes) do
            local mark = src:mark()
            local r = p[2]()
            t:assert_eq(r.errno, sys.E.INVAL, p[1] .. " is EINVAL")
            t:assert_eq(#src.log, mark - 1,
                "before the source is contacted and before any mutation")
        end
        sys.close(w, fd)
    end)

test("a set is a merge: only the components security_info names are taken",
    { spec = "PKM *inherit.set-security-is-a-merge" }, function(t)
        local fd = must_open(t, "Machine\\Sec\\S3", lcs.KEY_ALL_ACCESS)
        local before = select(1, descriptor_of(t, "Machine\\Sec\\S3"))
        -- A supplied descriptor whose owner differs from the key's, set
        -- with DACL only.
        local supplied = access.sd({
            owner = OTHER_SID, group = OTHER_SID,
            dacl = access.acl({ access.ace(access.ACE.ALLOWED, ALL, USER_SID, 0) }),
        })
        t:assert_eq(lcs.set_security(src, w, fd, lcs.SI.DACL, supplied).ret, 0,
            "the DACL alone is written")
        sys.close(w, fd)
        local after = descriptor_of(t, "Machine\\Sec\\S3")
        t:assert(ace_for(after.dacl, USER_SID), "the new DACL took")
        t:assert_eq(after.owner, before.owner,
            "and the owner the request did not name was preserved")
        t:assert_eq(after.group, before.group, "and so was the group")
    end)

test("a merge that would leave the descriptor ownerless is EINVAL",
    { spec = "PKM *inherit.merge-must-leave-an-owner" }, function(t)
        local fd = must_open(t, "Machine\\Sec\\S4", lcs.KEY_ALL_ACCESS)
        local ownerless = access.sd({
            group = kacs.SID.LOCAL_SYSTEM,
            dacl = access.acl({ access.ace(access.ACE.ALLOWED, ALL, kacs.SID.EVERYONE, 0) }),
        })
        local r = lcs.set_security(src, w, fd, lcs.SI.OWNER, ownerless)
        t:assert_eq(r.errno, sys.E.INVAL, "the result must still have an owner")
        sys.close(w, fd)
        local still = descriptor_of(t, "Machine\\Sec\\S4")
        t:assert(still.owner, "and the key kept the one it had")
    end)

test("a null group SID stays valid",
    { spec = "PKM *inherit.null-group-sid-is-valid" }, function(t)
        local fd = must_open(t, "Machine\\Sec\\S5", lcs.KEY_ALL_ACCESS)
        local no_group = access.sd({
            owner = kacs.SID.LOCAL_SYSTEM,
            dacl = access.acl({ access.ace(access.ACE.ALLOWED, ALL, kacs.SID.EVERYONE, 0) }),
        })
        local r = lcs.set_security(src, w, fd, lcs.SI.GROUP, no_group)
        t:assert_eq(r.ret, 0, "merging a null group is accepted: " .. sys.errname(r.errno or 0))
        sys.close(w, fd)
        local after = descriptor_of(t, "Machine\\Sec\\S5")
        t:assert(after.owner, "the descriptor still has its owner")
        t:assert(after.group == nil, "and a null group SID, which is valid")
    end)

test("a descriptor change in a transaction is atomic with it and still not layer-qualified",
    { spec = "PKM *inherit.descriptor-change-in-a-transaction" }, function(t)
        local sd = lcs.sd({ access.ace(access.ACE.ALLOWED, ALL, OTHER_SID, 0) })

        -- Aborted: closing the transaction fd leaves the key untouched.
        local aborted = assert(lcs.begin_transaction(w))
        local fd = must_open(t, "Machine\\Sec\\S6", lcs.KEY_ALL_ACCESS)
        t:assert_eq(lcs.set_security(src, w, fd, lcs.SI.DACL, sd, { txn_fd = aborted }).ret, 0,
            "the change enlists")
        sys.close(w, aborted)
        local unchanged = descriptor_of(t, "Machine\\Sec\\S6")
        t:assert(not ace_for(unchanged.dacl, OTHER_SID),
            "and an aborted transaction simply does not apply it")

        -- Committed: it lands, and it is a direct mutation on the key —
        -- REG_IOC_SET_SECURITY names no layer at all.
        local txn = assert(lcs.begin_transaction(w))
        t:assert_eq(lcs.set_security(src, w, fd, lcs.SI.DACL, sd, { txn_fd = txn }).ret, 0,
            "a second attempt enlists")
        t:assert_eq(lcs.commit(src, w, txn).ret, 0, "and commits")
        sys.close(w, txn)
        sys.close(w, fd)
        local applied = descriptor_of(t, "Machine\\Sec\\S6")
        t:assert(ace_for(applied.dacl, OTHER_SID),
            "the descriptor change is applied with the rest of the transaction")
    end)
