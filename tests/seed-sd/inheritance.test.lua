-- What the seed descriptor buys — inventory E1–E3.
--
-- These are not claims about seed-sd. They are claims about KACS
-- honouring what seed-sd wrote, and they are the reason the tool exists:
-- one call on the root of a fresh mount has to leave a tree that is
-- usable throughout, administrable by a principal who is not SYSTEM, and
-- usable by whoever creates something in it.
--
-- All three follow from the shape of the built-in descriptor. SYSTEM and
-- BUILTIN\Administrators are GENERIC_ALL with OBJECT_INHERIT and
-- CONTAINER_INHERIT, so the template propagates to everything created
-- beneath the seeded root; CREATOR OWNER carries INHERIT_ONLY as well,
-- so it grants nothing where it sits and resolves to the creator on each
-- object made below it.
--
-- The Administrators ACE is the one with a story. While SYSTEM was the
-- only principal that could exist, a lone Allow-SYSTEM ACE was a
-- complete answer. It stopped being one the moment authd could mint a
-- non-SYSTEM token: an administrator signing on receives
-- BUILTIN\Administrators and can traverse to a file with
-- SeChangeNotifyPrivilege and even execute it — but nothing bypasses
-- FILE_LIST_DIRECTORY, so they could not enumerate a single directory.
-- E3 is that case.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local access = require("helpers.access")
local token = require("helpers.token")

local vm = provium:vm("v", "prelude"):boot()

local SEED_SD = "/bin/seed-sd"
local ALL_INFO = kacs.SI.OWNER | kacs.SI.GROUP | kacs.SI.DACL
local OI_CI = access.ACE_FLAG.OBJECT_INHERIT | access.ACE_FLAG.CONTAINER_INHERIT
local INHERIT_ONLY = access.ACE_FLAG.INHERIT_ONLY
local INHERITED = access.ACE_FLAG.INHERITED
local FILE_ALL = kacs.ALL_RIGHTS
local CREATOR_OWNER = token.sid(3, 0)

local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT
    | token.GROUP.ENABLED
local CHANGE_NOTIFY = token.bit(token.PRIV.CHANGE_NOTIFY)

--- An administrator: BUILTIN\Administrators and SeChangeNotifyPrivilege,
--- which is what authd hands a signed-on administrator and nothing more.
--- Notably not SYSTEM — the whole point of the Administrators ACE is the
--- principal who is not.
---
--- A fresh table per call: `token.mint` records the logon session it
--- created in the spec it was handed, so a shared one would carry a dead
--- session into the next mint.
local function administrator()
    return {
        groups = {
            { sid = token.SID.EVERYONE, attributes = ENABLED },
            { sid = token.SID.AUTHENTICATED_USERS, attributes = ENABLED },
            { sid = token.SID.ADMINISTRATORS, attributes = ENABLED },
        },
        privs_present = CHANGE_NOTIFY,
        privs_enabled = CHANGE_NOTIFY,
        integrity_level = token.INTEGRITY.HIGH,
    }
end

--- An ordinary principal: Everyone and Authenticated Users, neither of
--- which the seed descriptor names.
local function ordinary()
    return {
        groups = {
            { sid = token.SID.EVERYONE, attributes = ENABLED },
            { sid = token.SID.AUTHENTICATED_USERS, attributes = ENABLED },
        },
        privs_present = CHANGE_NOTIFY,
        privs_enabled = CHANGE_NOTIFY,
    }
end

--- Seed a fresh deny-missing tmpfs at `at` and hand it back.
local function seeded_mount(t, at, args)
    local ok, stage, errno = kacs.new_mount(vm, "tmpfs", at, nil)
    t:assert(ok, "a fresh deny-missing tmpfs at " .. at .. ": " ..
        tostring(stage) .. " " .. sys.errname(errno or 0))
    local r = vm:run(SEED_SD, args or { at })
    t:assert_eq(r.exit_code, 0, "seed-sd seeds it: " .. r.stderr)
    return at
end

local function dacl_of(t, path)
    local sd, errno = kacs.get_sd(vm, path, ALL_INFO)
    t:assert(sd, "reading " .. path .. "'s descriptor: " .. sys.errname(errno or 0))
    local d = access.parse_sd(sd)
    t:assert(d.dacl, path .. " has a DACL")
    return d
end

-- ---- the template propagates -----------------------------------------------

test("a file created under a seeded directory inherits the template",
    { spec = "seed-sd inherit.a-created-file-takes-the-template" }, function(t)
        seeded_mount(t, "/e1")
        vm:write_file("/e1/file", "contents")

        local d = dacl_of(t, "/e1/file")
        t:assert_eq(d.dacl.count, 3, "the created file arrives with three ACEs")

        local want = { token.SID.LOCAL_SYSTEM, token.SID.ADMINISTRATORS }
        for i, sid in ipairs(want) do
            local ace = d.dacl.aces[i]
            t:assert_eq(ace.type, access.ACE.ALLOWED, "ACE " .. i .. " allows")
            t:assert_eq(ace.sid, sid, "ACE " .. i .. "'s trustee came from the template")
            t:assert_eq(ace.mask, FILE_ALL,
                "GENERIC_ALL mapped to every right the file object defines")
            t:assert(ace.flags & INHERITED ~= 0,
                "flagged INHERITED, so it came down from the seeded root")
            t:assert(ace.flags & OI_CI == OI_CI,
                "and stays inheritable, so the template keeps propagating")
        end

        -- And the tree is usable throughout, not just at the root: a
        -- file two levels down is created, written and read back.
        vm:mkdir("/e1/a/b", { parents = true })
        vm:write_file("/e1/a/b/deep", "deep")
        t:assert_eq(vm:read_file("/e1/a/b/deep"), "deep",
            "a file two levels below the seeded root is usable")
        local deep = dacl_of(t, "/e1/a/b/deep")
        t:assert_eq(deep.dacl.aces[1].sid, token.SID.LOCAL_SYSTEM,
            "and carries the same template")
        t:assert_eq(deep.dacl.aces[2].sid, token.SID.ADMINISTRATORS,
            "including the Administrators ACE")
    end)

test("CREATOR OWNER grants nothing where it sits and resolves per created object",
    { spec = "seed-sd inherit.creator-owner-resolves-per-object" }, function(t)
        seeded_mount(t, "/e2")

        -- On the seeded directory itself the ACE is inherit-only, so an
        -- access check never consults it.
        local root = dacl_of(t, "/e2")
        local co = root.dacl.aces[3]
        t:assert_eq(co.sid, CREATOR_OWNER, "the third ACE is CREATOR OWNER, S-1-3-0")
        t:assert(co.flags & INHERIT_ONLY ~= 0,
            "carrying INHERIT_ONLY, so it grants nothing on the node it sits on")

        -- A principal that is not SYSTEM creates a file beneath it and
        -- reads back what it wrote.
        token.as_principal(t, vm, administrator(), function(w)
            local fd, e = sys.open(w, "/e2/mine",
                sys.O.RDWR | sys.O.CREAT | sys.O.EXCL, tonumber("644", 8))
            t:assert(fd, "the principal creates a file: " .. sys.errname(e or 0))
            t:assert_eq(sys.write(w, fd, "mine").ret, 4, "and writes to it")
            sys.close(w, fd)

            local rfd, re = sys.open(w, "/e2/mine", sys.O.RDONLY)
            t:assert(rfd, "and can open it again: " .. sys.errname(re or 0))
            t:assert_eq(sys.read(w, rfd, 16), "mine",
                "reading back exactly what it just wrote")
            sys.close(w, rfd)

            t:assert_eq(sys.mkdir(w, "/e2/mine.d").ret, 0,
                "and makes a directory beside it")
        end)

        local mine = dacl_of(t, "/e2/mine")
        t:assert_eq(mine.owner, token.SID.TEST_USER, "the creator owns the file")
        t:assert_eq(mine.dacl.count, 3, "which has three ACEs")
        local resolved = mine.dacl.aces[3]
        t:assert_eq(resolved.sid, token.SID.TEST_USER,
            "and CREATOR OWNER resolved to the creator's own SID")
        t:assert_eq(resolved.flags & INHERIT_ONLY, 0,
            "with INHERIT_ONLY gone, so it grants on this object")
        t:assert_eq(resolved.mask, FILE_ALL, "full control of what it created")

        -- On a container the rule is carried onward as well as resolved,
        -- so the same thing happens again one level down.
        local made = dacl_of(t, "/e2/mine.d")
        t:assert_eq(made.dacl.count, 4, "a created directory has four ACEs")
        t:assert_eq(made.dacl.aces[3].sid, token.SID.TEST_USER,
            "the resolved one for this object")
        t:assert_eq(made.dacl.aces[4].sid, CREATOR_OWNER,
            "and CREATOR OWNER itself, carried onward")
        t:assert(made.dacl.aces[4].flags & INHERIT_ONLY ~= 0,
            "still inherit-only, so it will resolve again for whatever is created below")
    end)

-- ---- who can use a seeded tree ---------------------------------------------

test("an administrator can enumerate a seeded tree",
    { spec = "seed-sd inherit.an-administrator-can-enumerate" }, function(t)
        seeded_mount(t, "/e3")
        vm:mkdir("/e3/sub/deeper", { parents = true })
        vm:write_file("/e3/sub/file", "x")
        local r = vm:run(SEED_SD, { "-r", "/e3" })
        t:assert_eq(r.exit_code, 0, "the whole tree is seeded: " .. r.stderr)

        token.as_principal(t, vm, administrator(), function(w)
            for _, p in ipairs({ "/e3", "/e3/sub", "/e3/sub/deeper" }) do
                local fd, e = sys.open(w, p, sys.O.RDONLY | sys.O.DIRECTORY)
                t:assert(fd, "an administrator opens " .. p .. ": " ..
                    sys.errname(e or 0))
                local entries, de = sys.getdents_all(w, fd)
                t:assert(entries, "and enumerates it: " .. sys.errname(de or 0))
                sys.close(w, fd)
            end
            local names = {}
            local fd = sys.open(w, "/e3/sub", sys.O.RDONLY | sys.O.DIRECTORY)
            for _, e in ipairs(sys.getdents_all(w, fd) or {}) do
                names[e.name] = true
            end
            sys.close(w, fd)
            t:assert(names["file"] and names["deeper"],
                "seeing what is actually in it")
            t:assert(sys.stat(w, "/e3/sub/file"), "and reaching the file inside")
        end)

        -- The control: without the Administrators ACE there would be
        -- nothing here for a non-SYSTEM principal at all, which is what
        -- the ACE was added to fix.
        token.as_principal(t, vm, ordinary(), function(w)
            local fd, e = sys.open(w, "/e3", sys.O.RDONLY | sys.O.DIRECTORY)
            t:assert(not fd, "a principal the descriptor does not name cannot")
            t:assert_eq(e, sys.E.ACCES, "EACCES — the seed grants Everyone nothing")
        end)
    end)
