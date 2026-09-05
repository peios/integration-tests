-- PKM §3.9.5 — what a missing descriptor means: denial under
-- `facs_deny_missing`, synthesis under the two synthesise classes, and
-- the deferred write-back that gives a persistent mount durable
-- descriptors.
--
-- Two filesystems carry the weight here. **ramfs** declares no xattr
-- support at all, so every inode on it has a missing descriptor for
-- ever — which is what makes the inheritance walk, its depth bound and
-- the best-effort write-back reachable. **cgroup2** is the other:
-- kernfs never calls `security_inode_init_security`, so a created cgroup
-- directory is never stamped either, but kernfs *does* store xattrs — so
-- it is the one filesystem here where a persistent write-back of a
-- non-root object can actually land.
--
-- Everything else on a tmpfs is stamped at creation, so a tmpfs shows
-- the missing case only at its mount root, which the kernel never
-- created through the LSM.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local access = require("helpers.access")
local token = require("helpers.token")

local vm = provium:vm("v", "kernel-only"):boot()

local ALL_INFO = kacs.SI.OWNER | kacs.SI.GROUP | kacs.SI.DACL
local OI_CI = access.ACE_FLAG.OBJECT_INHERIT | access.ACE_FLAG.CONTAINER_INHERIT
local INHERITED = access.ACE_FLAG.INHERITED
local MP = kacs.MOUNT_POLICY
local GENERIC_ALL, GENERIC_READ, GENERIC_EXECUTE = 0x10000000, 0x80000000, 0x20000000

--- A fresh mount in `class`, plus an O_PATH fd on its superblock.
local function mounted(t, name, class, fstype)
    local at = "/syn-" .. name
    local ok, stage, errno = kacs.new_mount(vm, fstype or "tmpfs", at, class, nil)
    t:assert(ok, "mount " .. (fstype or "tmpfs") .. " at " .. at .. ": " ..
        tostring(stage) .. " " .. sys.errname(errno or 0))
    local fd = sys.open(vm, at, sys.O.PATH)
    t:assert(fd, "an O_PATH fd on " .. at)
    return at, fd
end

local function xattrs(path) return sys.listxattr(vm, path) or {} end
local function has_canonical(path)
    for _, n in ipairs(xattrs(path)) do
        if n == "security.peios.sd" then return true end
    end
    return false
end

--- A complete descriptor usable as a mount template.
local function template(aces)
    return access.sd({
        owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
        dacl = access.acl(aces),
    })
end

-- ---- deny-missing ---------------------------------------------------------

test("under deny-missing a missing descriptor denies everything",
    { spec = "PKM *facs.storage.deny-missing-denies" }, function(t)
        local at = mounted(t, "deny", nil)
        t:assert_eq(#xattrs(at), 0, "the mount root stores no descriptor")
        local sd, errno = kacs.get_sd(vm, at, ALL_INFO)
        t:assert(not sd, "its descriptor cannot be read")
        t:assert_eq(errno, sys.E.ACCES, "EACCES")
        local mk = sys.mkdir(vm, at .. "/child")
        t:assert_eq(mk.ret, -1, "nothing can be created in it")
        t:assert_eq(mk.errno, sys.E.ACCES, "EACCES")
        local fd, oerr = sys.open(vm, at, sys.O.RDONLY | sys.O.DIRECTORY)
        t:assert(not fd, "and it cannot be opened for reading")
        t:assert_eq(oerr, sys.E.ACCES, "EACCES — the agent is SYSTEM and is still denied")
    end)

test("an O_PATH open plus set_sd with AT_EMPTY_PATH is the repair route",
    { spec = "PKM *facs.storage.missing-repair-route", tags = { "known-bug" } },
    function(t)
        -- §3.9.5: "open(path, O_PATH) then kacs_set_sd with AT_EMPTY_PATH
        -- under SeRestorePrivilege". The O_PATH open works — the open hook
        -- is bypassed entirely — but kacs_set_sd refuses the descriptor:
        -- its first resolution step is the token-descriptor one, which
        -- calls fdget(), and fdget() rejects FMODE_PATH files, so the
        -- syscall returns EBADF before the file target is ever tried. The
        -- documented repair route is therefore unreachable.
        local at = mounted(t, "repair", nil)
        local pfd = sys.open(vm, at, sys.O.PATH)
        t:assert(pfd, "O_PATH opens a descriptor-less object")
        local full = access.sd({
            owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
            dacl = access.acl({ access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS,
                token.SID.EVERYONE, OI_CI) }),
        })
        local r = kacs.set_sd_fd(vm, pfd, full, ALL_INFO)
        t:assert_eq(r.ret, 0, "the agent holds SeRestorePrivilege and repairs it: " ..
            sys.errname(r.errno))
        sys.close(vm, pfd)
    end)

test("the same repair works when the object is named by path",
    { spec = "PKM *facs.storage.missing-repair-route" }, function(t)
        -- The path form is the other live-AccessCheck route §3.9.6 lists,
        -- so SeRestorePrivilege fires there too. This is the only spelling
        -- of the repair that currently works.
        local at = mounted(t, "repair-path", nil)
        local full = access.sd({
            owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
            dacl = access.acl({ access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS,
                token.SID.EVERYONE, OI_CI) }),
        })
        local r = kacs.set_sd(vm, at, full, ALL_INFO)
        t:assert_eq(r.ret, 0, "set_sd by path repairs the root: " .. sys.errname(r.errno))
        t:assert_eq(kacs.get_sd(vm, at, ALL_INFO), full, "the descriptor is now readable")
        t:assert_eq(sys.mkdir(vm, at .. "/child").ret, 0, "and the mount is usable")
    end)

-- ---- synthesis ------------------------------------------------------------

test("synthesis takes the parent's descriptor first and the template only without one",
    { spec = "PKM *facs.storage.synthesis-order" }, function(t)
        -- cgroup2 has a single superblock per namespace, so every mount
        -- of it in this file shares one; the cgroup names are unique per
        -- test for that reason.
        local at, fd = mounted(t, "order", nil, "cgroup2")
        t:assert_eq(sys.mkdir(vm, at .. "/ord").ret, 0, "a cgroup below the root")
        -- Two ACEs: one that inherits and one that does not. A child built
        -- by inheritance carries only the first, flagged INHERITED; a
        -- child built from the template would carry both, unflagged.
        local tpl = template({
            access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS, token.SID.EVERYONE, OI_CI),
            access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS, token.SID.TEST_USER_2, 0),
        })
        t:assert_eq(kacs.set_mount_policy_ex(vm, fd, MP.SYNTHESIZE_EPHEMERAL,
            { template = tpl }).ret, 0, "the template is installed")

        local root = assert(kacs.get_sd(vm, at, ALL_INFO))
        t:assert_eq(root, tpl,
            "the mount root has no parent, so it is the template verbatim")

        local child = access.parse_sd(assert(kacs.get_sd(vm, at .. "/ord", ALL_INFO)))
        t:assert_eq(child.dacl.count, 1, "the child took inheritance, not the template")
        t:assert_eq(child.dacl.aces[1].sid, token.SID.EVERYONE, "the inheritable ACE")
        t:assert(child.dacl.aces[1].flags & INHERITED ~= 0, "flagged INHERITED")
        sys.close(vm, fd)
    end)

test("with no template the fallback grants SYSTEM and Administrators all, Everyone read and execute",
    { spec = "PKM *facs.storage.synthesis-fallback-descriptor" }, function(t)
        local at = mounted(t, "fallback", MP.SYNTHESIZE_EPHEMERAL)
        local d = access.parse_sd(assert(kacs.get_sd(vm, at, ALL_INFO)))
        t:assert_eq(d.owner, token.SID.LOCAL_SYSTEM, "owned by SYSTEM")
        t:assert_eq(d.group, token.SID.LOCAL_SYSTEM, "with SYSTEM as group")
        t:assert_eq(d.dacl.count, 3, "three ACEs")
        local want = {
            { token.SID.LOCAL_SYSTEM, GENERIC_ALL },
            { token.SID.ADMINISTRATORS, GENERIC_ALL },
            { token.SID.EVERYONE, GENERIC_READ | GENERIC_EXECUTE },
        }
        for i, w in ipairs(want) do
            t:assert_eq(d.dacl.aces[i].sid, w[1], "ACE " .. i .. "'s trustee")
            t:assert_eq(d.dacl.aces[i].mask, w[2], "ACE " .. i .. "'s mask")
            t:assert_eq(d.dacl.aces[i].type, access.ACE.ALLOWED, "ACE " .. i .. " allows")
        end
    end)

test("the accessor's token has no effect on what is synthesised",
    { spec = "PKM *facs.storage.synthesis-ignores-accessor" }, function(t)
        local at = mounted(t, "accessor", MP.SYNTHESIZE_EPHEMERAL, "ramfs")
        t:assert_eq(sys.mkdir(vm, at .. "/d").ret, 0, "a directory on the mount")
        local as_system = assert(kacs.get_sd(vm, at .. "/d", ALL_INFO))
        local bits = token.bit(token.PRIV.CHANGE_NOTIFY)
        token.as_principal(t, vm, { privs_present = bits, privs_enabled = bits },
            function(w)
                -- The fallback grants Everyone GENERIC_READ, which maps to
                -- READ_CONTROL, so the principal may read the descriptor.
                local sd, errno = kacs.get_sd(w, at .. "/d", ALL_INFO)
                t:assert(sd, "a minted principal reads it: " .. sys.errname(errno or 0))
                t:assert_eq(sd, as_system,
                    "and gets the same bytes SYSTEM does")
            end)
        local d = access.parse_sd(as_system)
        t:assert_eq(d.owner, token.SID.LOCAL_SYSTEM,
            "the synthetic system-policy creator supplies the owner, not the accessor")
        t:assert_neq(d.owner, token.SID.TEST_USER, "which is not the principal's SID")
    end)

test("a parent whose own descriptor is missing is synthesised first",
    { spec = "PKM *facs.storage.synthesis-recursive" }, function(t)
        local at, fd = mounted(t, "recursive", nil, "ramfs")
        local tpl = template({
            access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS, token.SID.EVERYONE, OI_CI),
        })
        t:assert_eq(kacs.set_mount_policy_ex(vm, fd, MP.SYNTHESIZE_EPHEMERAL,
            { template = tpl }).ret, 0, "a template terminates the walk at the root")
        local deep = at
        for i = 1, 5 do
            deep = deep .. "/l" .. i
            t:assert_eq(sys.mkdir(vm, deep).ret, 0, "level " .. i)
        end
        -- Nothing between the root and `deep` has ever been resolved, and
        -- ramfs stores nothing, so answering for `deep` means synthesising
        -- all five ancestors on the way.
        local d = access.parse_sd(assert(kacs.get_sd(vm, deep, ALL_INFO),
            "the deepest object resolves"))
        t:assert_eq(d.dacl.count, 1, "by inheritance")
        t:assert(d.dacl.aces[1].flags & INHERITED ~= 0,
            "its ACE is INHERITED, so it came down the chain rather than from the template")
        sys.close(vm, fd)
    end)

test("the inheritance walk is bounded at 32 ancestor levels and fails closed past it",
    { spec = "PKM *facs.storage.synthesis-depth-limit" }, function(t)
        local at, fd = mounted(t, "depth", MP.SYNTHESIZE_EPHEMERAL, "ramfs")
        local path = at
        for i = 1, 40 do
            path = path .. "/d" .. i
            t:assert_eq(sys.mkdir(vm, path).ret, 0, "level " .. i .. " exists")
        end
        -- Building the tree resolved every level on the way, so bump the
        -- generation: that discards every synthetic entry and puts the
        -- walk back to starting at the mount root.
        t:assert_eq(kacs.set_mount_policy_ex(vm, fd, MP.SYNTHESIZE_EPHEMERAL, {}).ret, 0,
            "the generation moves, discarding the synthetic caches")
        sys.close(vm, fd)

        local function at_depth(n)
            local p = at
            for i = 1, n do p = p .. "/d" .. i end
            return p
        end
        -- Deepest first, so no shallower resolution seeds the walk.
        for _, n in ipairs({ 40, 33, 32 }) do
            local sd, errno = kacs.get_sd(vm, at_depth(n), ALL_INFO)
            t:assert(not sd, "depth " .. n .. " is past the bound")
            t:assert_eq(errno, sys.E.ACCES, "and fails closed with EACCES")
        end
        t:assert(kacs.get_sd(vm, at_depth(31), ALL_INFO),
            "31 ancestors below the nearest resolvable one still synthesises")
    end)

-- ---- write-back -----------------------------------------------------------

test("an ephemeral synthesis is cached only and never reaches the filesystem",
    { spec = "PKM *facs.storage.ephemeral-not-written-back" }, function(t)
        local at = mounted(t, "eph", MP.SYNTHESIZE_EPHEMERAL)
        -- tmpfs stores xattrs perfectly well, so an absent canonical name
        -- here is a decision, not an inability.
        t:assert_eq(#xattrs(at), 0, "nothing stored before")
        t:assert(kacs.get_sd(vm, at, ALL_INFO), "the descriptor synthesises")
        t:assert(not has_canonical(at), "and nothing was written to the medium")
        t:assert_eq(sys.mkdir(vm, at .. "/d").ret, 0, "the mount is usable")
        t:assert(not has_canonical(at), "still nothing")
    end)

test("a persistent synthesis is additionally written to the xattr",
    { spec = "PKM *facs.storage.persistent-written-back" }, function(t)
        local at = mounted(t, "pers", MP.SYNTHESIZE_PERSISTENT)
        t:assert_eq(#xattrs(at), 0, "nothing stored before")
        local sd = assert(kacs.get_sd(vm, at, ALL_INFO), "the descriptor synthesises")
        t:assert(has_canonical(at), "and the medium acquired security.peios.sd")
        t:assert_eq(kacs.get_sd(vm, at, ALL_INFO), sd, "reading it back is unchanged")
    end)

test("the write-back never runs inline under the FACS lock",
    { spec = "PKM *facs.storage.write-back-deferred" }, function(t)
        -- Reaching synthesis from a metadata operation is the case that
        -- would self-deadlock if the xattr write ran inline: setxattr
        -- already holds i_rwsem when the LSM hook resolves the descriptor.
        local at = mounted(t, "deferred", MP.SYNTHESIZE_PERSISTENT)
        t:assert_eq(#xattrs(at), 0, "nothing stored before")
        local w = sys.setxattr(vm, at, "user.probe", "v")
        t:assert_eq(w.ret, 0, "a metadata operation drives the synthesis: " ..
            sys.errname(w.errno))
        t:assert(has_canonical(at), "and the deferred write-back still lands")
        local names = xattrs(at)
        t:assert_eq(#names, 2, "beside the caller's own xattr")
    end)

test("synthesis is decisive at once — the access does not wait for the disk",
    { spec = "PKM *facs.storage.synthesis-marks-pending" }, function(t)
        local at = mounted(t, "pending", MP.SYNTHESIZE_PERSISTENT)
        t:assert_eq(#xattrs(at), 0, "the root has no stored descriptor")
        -- The very first operation needing a decision on this inode gets a
        -- correct one, from the cached synthetic entry, before anything
        -- could have been persisted.
        local mk = sys.mkdir(vm, at .. "/first")
        t:assert_eq(mk.ret, 0, "the first access is authorised: " .. sys.errname(mk.errno))
        t:assert(kacs.get_sd(vm, at, ALL_INFO), "and the descriptor is readable")
    end)

test("the write-back runs from task work, so it has landed by the next syscall",
    { spec = "PKM *facs.storage.write-back-task-work" }, function(t)
        local at = mounted(t, "taskwork", MP.SYNTHESIZE_PERSISTENT)
        t:assert(not has_canonical(at), "before the triggering operation")
        assert(kacs.get_sd(vm, at, ALL_INFO))
        -- No wait, no retry loop: the callback fires as the triggering
        -- syscall returns to userspace, so the very next one sees it.
        t:assert(has_canonical(at),
            "the xattr is present on the syscall immediately after")
    end)

test("a write-back that cannot happen does not fail the operation that triggered it",
    { spec = "PKM *facs.storage.write-back-best-effort" }, function(t)
        -- ramfs declares no xattr support, so the persistent class owes a
        -- write-back it can never perform.
        local at = mounted(t, "besteffort", MP.SYNTHESIZE_PERSISTENT, "ramfs")
        local sd = assert(kacs.get_sd(vm, at, ALL_INFO),
            "the descriptor resolves anyway")
        t:assert_eq(#xattrs(at), 0, "nothing was stored")
        t:assert_eq(sys.mkdir(vm, at .. "/d").ret, 0,
            "and the operations it authorises all succeed")
        t:assert_eq(kacs.get_sd(vm, at, ALL_INFO), sd,
            "a later access re-synthesises the identical descriptor")
    end)

test("once written back the descriptor is ordinary and no longer generation-tagged",
    { spec = "PKM *facs.storage.written-back-becomes-ordinary" }, function(t)
        local at, fd = mounted(t, "ordinary", MP.SYNTHESIZE_PERSISTENT)
        local written = assert(kacs.get_sd(vm, at, ALL_INFO))
        t:assert(has_canonical(at), "the fallback was written back")
        -- A template change bumps the generation, which would discard a
        -- synthetic entry and re-synthesise from the new template. This
        -- one is xattr-backed now, so the stored bytes win.
        local tpl = template({
            access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS, token.SID.TEST_USER, OI_CI),
        })
        t:assert_eq(kacs.set_mount_policy_ex(vm, fd, MP.SYNTHESIZE_PERSISTENT,
            { template = tpl }).ret, 0, "a new template is installed")
        t:assert_eq(kacs.get_sd(vm, at, ALL_INFO), written,
            "the durable descriptor is not re-synthesised")
        sys.close(vm, fd)
    end)

test("an ancestor synthesised for a descendant persists when it is next accessed itself",
    { spec = "PKM *facs.storage.ancestor-also-persists", tags = { "known-bug" } },
    function(t)
        -- cgroup2 is the reachable case: kernfs never stamps an inode, so
        -- `a` and `a/b` below are genuinely missing, and kernfs stores
        -- xattrs, so a persistent write-back can land.
        --
        -- Resolving `anc/b/c` synthesises `anc` and `anc/b` on the way and
        -- marks them pending — the write-back is queued only for the
        -- object the syscall named. Accessing `anc` in its own right
        -- afterwards finds a *current* cache entry, so
        -- pkm_kacs_inode_ensure_effective_cache returns before the
        -- pending-source branch that queues the persist, and the ancestor
        -- stays pending for ever.
        local at, fd = mounted(t, "ancestor", nil, "cgroup2")
        for _, p in ipairs({ "/anc", "/anc/b", "/anc/b/c" }) do
            t:assert_eq(sys.mkdir(vm, at .. p).ret, 0, "mkdir " .. p)
        end
        t:assert_eq(kacs.set_mount_policy_ex(vm, fd, MP.SYNTHESIZE_PERSISTENT, {}).ret, 0,
            "the mount becomes synthesise-persistent")
        sys.close(vm, fd)

        t:assert(kacs.get_sd(vm, at .. "/anc/b/c", ALL_INFO), "the descendant resolves")
        t:assert(has_canonical(at .. "/anc/b/c"), "and persists")
        t:assert(not has_canonical(at .. "/anc"),
            "its ancestor is still only pending at this point")

        t:assert(kacs.get_sd(vm, at .. "/anc", ALL_INFO),
            "the ancestor is now accessed in its own right")
        t:assert(has_canonical(at .. "/anc"),
            "so it persists under the same rules")
    end)
