-- PKM §3.9.5 — the mount-policy classifier and the two mounts the kernel
-- establishes before any userspace exists.
--
-- Which class a superblock lands in is decided from its filesystem magic
-- and is observable directly: `kacs_get_mount_policy` on any object of
-- the mount reports it, and the class decides what a missing descriptor
-- means there. `helpers/kacs.new_mount` builds a filesystem through the
-- fsopen/fsmount API, which is the only way to name a mount before it is
-- attached — so a class can be read on a freshly created superblock
-- rather than only on the ones the agent inherited.
--
-- The seeding half is read out of the running guest: `/` and `/dev` were
-- stamped by the kernel inside `init_mount_tree` and `devtmpfs_init`,
-- long before this test could run, so the descriptors those two carry at
-- the first syscall of the first userspace process *are* the seed.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local access = require("helpers.access")
local token = require("helpers.token")
local stratafs = require("helpers.stratafs")
local fx = require("helpers.fixtures")

local vm = provium:vm("v", "kernel-only"):boot()

local ALL_INFO = kacs.SI.OWNER | kacs.SI.GROUP | kacs.SI.DACL
local GENERIC_ALL = 0x10000000
local GENERIC_READ, GENERIC_EXECUTE = 0x80000000, 0x20000000
local OI_CI = access.ACE_FLAG.OBJECT_INHERIT | access.ACE_FLAG.CONTAINER_INHERIT

--- The mount policy class of the superblock `path` lives on.
local function policy_of(path)
    local fd = sys.open(vm, path, sys.O.PATH)
    if not fd then return nil, "no O_PATH fd on " .. path end
    local p, errno = kacs.get_mount_policy(vm, fd)
    sys.close(vm, fd)
    return p, errno
end

--- Mount `fstype` at a fresh point and report its default class.
local function default_class(t, fstype)
    local at = "/cls-" .. fstype
    local ok, stage, errno = kacs.new_mount(vm, fstype, at, nil, nil)
    t:assert(ok, "mount " .. fstype .. ": " .. tostring(stage) .. " " ..
        sys.errname(errno or 0))
    return (policy_of(at))
end

-- ---- the classifier -------------------------------------------------------

test("procfs and sysfs are unmanaged — FACS holds no descriptor for them at all",
    { spec = "PKM *facs.storage.proc-sysfs-unmanaged" }, function(t)
        for _, at in ipairs({ "/proc", "/sys" }) do
            t:assert_eq(policy_of(at), kacs.MOUNT_POLICY.UNMANAGED,
                at .. " is unmanaged")
            local sd, errno = kacs.get_sd(vm, at, ALL_INFO)
            t:assert(not sd, "and has no descriptor to read")
            t:assert_eq(errno, sys.E.OPNOTSUPP,
                "get_sd on an unmanaged mount is EOPNOTSUPP")
        end
        -- The classifier assigns unmanaged; the ABI will not.
        local fd = sys.open(vm, "/proc", sys.O.PATH)
        local r = kacs.set_mount_policy_ex(vm, fd, kacs.MOUNT_POLICY.DENY_MISSING, {})
        t:assert_eq(r.ret, -1, "an unmanaged superblock cannot be adopted")
        t:assert_eq(r.errno, sys.E.OPNOTSUPP, "EOPNOTSUPP")
        sys.close(vm, fd)
        t:assert_eq(default_class(t, "proc"), kacs.MOUNT_POLICY.UNMANAGED,
            "a freshly mounted procfs classifies the same way")
        t:assert_eq(default_class(t, "sysfs"), kacs.MOUNT_POLICY.UNMANAGED,
            "and so does a freshly mounted sysfs")
    end)

test("nullfs is unmanaged",
    { spec = "PKM *facs.storage.nullfs-unmanaged",
      covered_by = "kunit:pkm_kunit_file",
      skip = "nullfs is SB_NOUSER and absent from /proc/filesystems, and the " ..
             "one instance — the mount-namespace root — is permanently covered " ..
             "by the rootfs mounted on top of it, so no path in the guest " ..
             "resolves to it; runs under " ..
             "pkm_kunit_nullfs_root_is_unmanaged_and_unseeded, which steps up " ..
             "from the root mount to it" }, function(t) end)

test("StrataFS is fixed at deny-missing for the superblock's lifetime",
    { spec = "PKM *facs.storage.stratafs-fixed-deny-missing" }, function(t)
        stratafs.with(vm, "policy", {
            { name = "up", flags = { "create" } },
            { name = "lo", flags = { "ro" }, entries = { f = "lower" } },
        }, function(s)
            local fd = sys.open(vm, s.at, sys.O.PATH)
            t:assert_eq(kacs.get_mount_policy(vm, fd), kacs.MOUNT_POLICY.DENY_MISSING,
                "a stratafs mount is deny-missing")
            for _, class in ipairs({ kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL,
                                     kacs.MOUNT_POLICY.SYNTHESIZE_PERSISTENT,
                                     kacs.MOUNT_POLICY.DENY_MISSING }) do
                local r = kacs.set_mount_policy_ex(vm, fd, class, {})
                t:assert_eq(r.ret, -1, "class " .. class .. " is refused")
                t:assert_eq(r.errno, sys.E.OPNOTSUPP, "with EOPNOTSUPP")
            end
            t:assert_eq(kacs.get_mount_policy(vm, fd), kacs.MOUNT_POLICY.DENY_MISSING,
                "and the class is unchanged")
            sys.close(vm, fd)
        end)
    end)

test("the storage-less magics default to synthesise-ephemeral",
    { spec = "PKM *facs.storage.ephemeral-magics" }, function(t)
        -- RAMFS_MAGIC and CGROUP2_SUPER_MAGIC are the two of the six the
        -- kernel-only guest can mount: NFS needs a server, and
        -- msdos/exfat/iso9660 all need a block device.
        t:assert_eq(default_class(t, "ramfs"), kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL,
            "RAMFS_MAGIC is facs_synthesize_ephemeral")
        t:assert_eq(default_class(t, "cgroup2"), kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL,
            "CGROUP2_SUPER_MAGIC is facs_synthesize_ephemeral")
    end)

test("everything else, tmpfs included, defaults to deny-missing",
    { spec = "PKM *facs.storage.default-deny-missing" }, function(t)
        t:assert_eq(default_class(t, "tmpfs"), kacs.MOUNT_POLICY.DENY_MISSING,
            "TMPFS_MAGIC is facs_deny_missing")
        -- The rootfs and /tmp the agent inherited are both tmpfs and land
        -- in the same class; squashfs, ext4 and btrfs are the other three
        -- §3.9.5 names, and none of them mounts without a block device.
        t:assert_eq(policy_of("/"), kacs.MOUNT_POLICY.DENY_MISSING,
            "and so does the root filesystem")
        t:assert_eq(policy_of("/tmp"), kacs.MOUNT_POLICY.DENY_MISSING, "and /tmp")
    end)

test("an NTFS volume is deny-missing too, and an inode with no descriptor there is refused as missing",
    { spec = "PKM *facs.storage.default-deny-missing", tags = { "known-bug" } }, function(t)
        -- ntfs3 is a block-device filesystem with no magic of its own in
        -- the classifier, so it lands with everything else. Its
        -- descriptors are `system.ntfs_security`, and on a volume made
        -- by mkntfs the root has none ntfs3 can read (its descriptor is
        -- an inline attribute, security id 0), so deny-missing's answer
        -- for the root is the same as for a descriptor-less tmpfs file:
        -- EACCES.
        --
        -- known-bug PEI-715: ntfs3 reports that inode as ENOENT rather
        -- than ENODATA and KACS hands the errno up as the verdict, so
        -- today every path on the volume is ENOENT.
        if not fx.present(vm, fx.NTFS_IMAGE) then
            t:skip("the profile was built without mkntfs, so there is no NTFS image")
        end
        assert(fx.load_module(vm, "ntfs3"))
        local dev, loopfd, e = fx.loop_attach(vm, fx.NTFS_IMAGE)
        assert(dev, "loop: " .. tostring(loopfd) .. ": " .. sys.errname(e or 0))
        local at = "/cls-ntfs3"
        local ok, stage, errno = kacs.new_mount(vm, "ntfs3", at, nil, { source = dev })
        t:assert(ok, "mount ntfs3: " .. tostring(stage) .. " " .. sys.errname(errno or 0))
        t:assert_eq(policy_of(at), kacs.MOUNT_POLICY.DENY_MISSING,
            "ntfs3 classifies deny-missing")
        local st, se = sys.stat(vm, at)
        t:assert(not st, "the descriptor-less root is not reachable")
        t:assert_eq(se, sys.E.ACCES, "and the refusal is deny-missing's EACCES, not the driver's errno: " ..
            sys.errname(se or 0))
        sys.umount(vm, at, 0)
        fx.loop_detach(vm, loopfd)
    end)

-- ---- the two kernel-internal mounts ---------------------------------------

test("both mounts the kernel makes before userspace are managed and carry a descriptor",
    { spec = "PKM *facs.storage.kernel-internal-mounts" }, function(t)
        local mounts = vm:read_file("/proc/self/mounts")
        t:assert(mounts:match("rootfs / rootfs"), "the root is the rootfs tmpfs")
        t:assert(mounts:match("devtmpfs /dev devtmpfs"), "and devtmpfs is on /dev")
        for _, at in ipairs({ "/", "/dev" }) do
            t:assert_eq(policy_of(at), kacs.MOUNT_POLICY.DENY_MISSING,
                at .. " is TMPFS_MAGIC and therefore deny-missing")
            local sd, errno = kacs.get_sd(vm, at, ALL_INFO)
            t:assert(sd, at .. " carries a descriptor: " .. sys.errname(errno or 0))
        end
    end)

--- The descriptor §3.9.5 says both roots are seeded with.
local function assert_seeded(t, path)
    local sd = assert(kacs.get_sd(vm, path, ALL_INFO), path .. " has a descriptor")
    local d = access.parse_sd(sd)
    t:assert_eq(d.owner, token.SID.LOCAL_SYSTEM, path .. ": owner is SYSTEM (S-1-5-18)")
    t:assert_eq(d.group, token.SID.LOCAL_SYSTEM, path .. ": group is SYSTEM")
    t:assert(d.dacl, path .. ": a DACL is present")
    t:assert_eq(d.dacl.count, 1, path .. ": exactly one ACE")
    local ace = d.dacl.aces[1]
    t:assert_eq(ace.type, access.ACE.ALLOWED, path .. ": ACCESS_ALLOWED")
    t:assert_eq(ace.mask, GENERIC_ALL, path .. ": granting GENERIC_ALL")
    t:assert_eq(ace.sid, token.SID.LOCAL_SYSTEM, path .. ": to SYSTEM")
    t:assert_eq(ace.flags, OI_CI,
        path .. ": OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE")
    local sacl = kacs.get_sd(vm, path, kacs.SI.SACL)
    t:assert(sacl, path .. ": the SACL subset reads back")
    t:assert(not access.parse_sd(sacl).sacl, path .. ": and there is no SACL")
    return sd
end

test("the rootfs root is seeded before the mount is published, so it is usable at once",
    { spec = "PKM *facs.storage.rootfs-seed-timing" }, function(t)
        -- Nothing in the guest ran before init_mount_tree, so a descriptor
        -- on / at the agent's first syscall can only have been written
        -- there by the kernel, under i_rwsem, before / became reachable.
        assert_seeded(t, "/")
        -- And the class is viable: a deny-missing root with no descriptor
        -- would refuse every lookup through it.
        local fd, errno = sys.open(vm, "/", sys.O.RDONLY | sys.O.DIRECTORY)
        t:assert(fd, "the root opens: " .. sys.errname(errno or 0))
        sys.close(vm, fd)
    end)

test("the devtmpfs root is seeded before kdevtmpfs starts",
    { spec = "PKM *facs.storage.devtmpfs-seed-timing" }, function(t)
        assert_seeded(t, "/dev")
        -- kdevtmpfs populated /dev after the seed, and every node it made
        -- inherited from it — which is only possible if the seed was
        -- already there.
        local console = sys.stat(vm, "/dev/console")
        t:assert(console, "/dev is populated")
        local sd = kacs.get_sd(vm, "/dev/console", ALL_INFO)
        t:assert(sd, "and a node kdevtmpfs created carries a descriptor")
    end)

test("the nullfs root is not seeded",
    { spec = "PKM *facs.storage.nullfs-not-seeded",
      covered_by = "kunit:pkm_kunit_file",
      skip = "the nullfs namespace root is covered by the rootfs mounted over " ..
             "it and is unreachable by path or fd from the guest; runs under " ..
             "pkm_kunit_nullfs_root_is_unmanaged_and_unseeded, which finds no " ..
             "descriptor on it and one on the rootfs root above" },
    function(t) end)

test("the seed is byte-for-byte identical on both mounts",
    { spec = "PKM *facs.storage.seeded-descriptor-contents" }, function(t)
        local root = assert_seeded(t, "/")
        local dev = assert_seeded(t, "/dev")
        t:assert_eq(root, dev,
            "the rootfs and devtmpfs roots carry the same descriptor bytes")
    end)

test("the seed reached the xattr although no caller may write it",
    { spec = "PKM *facs.storage.seed-writes-bypass-hooks" }, function(t)
        local names = sys.listxattr(vm, "/")
        t:assert(names, "the root's xattr names list")
        local found = false
        for _, n in ipairs(names) do if n == "security.peios.sd" then found = true end end
        t:assert(found, "security.peios.sd is stored on the root inode")
        -- The same name is unwritable and unreadable through the ordinary
        -- surface, for the agent, which is SYSTEM and holds every
        -- privilege — so the seed cannot have come through it.
        local w = sys.setxattr(vm, "/", "security.peios.sd", "x")
        t:assert_eq(w.ret, -1, "and a caller cannot write it")
        t:assert_eq(w.errno, sys.E.ACCES, "EACCES")
        local _, gerr = sys.getxattr(vm, "/", "security.peios.sd")
        t:assert_eq(gerr, sys.E.ACCES, "nor read it")
    end)

test("a seeded mount is still fully manageable afterwards",
    { spec = "PKM *facs.storage.seeded-mounts-still-manageable" }, function(t)
        local original = assert(kacs.get_sd(vm, "/dev", ALL_INFO))
        local replacement = access.sd({
            owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
            dacl = access.acl({ access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS,
                token.SID.EVERYONE, OI_CI) }),
        })
        local w = kacs.set_sd(vm, "/dev", replacement, ALL_INFO)
        t:assert_eq(w.ret, 0, "trusted userspace overwrites the seeded descriptor: " ..
            sys.errname(w.errno))
        t:assert_neq(kacs.get_sd(vm, "/dev", ALL_INFO), original,
            "and the per-inode descriptor changed")

        local fd = sys.open(vm, "/dev", sys.O.PATH)
        local before = kacs.get_mount_policy_ex(vm, fd)
        local r = kacs.set_mount_policy_ex(vm, fd,
            kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL, {})
        t:assert_eq(r.ret, 0, "and the superblock's class changes: " ..
            sys.errname(r.errno))
        t:assert_eq(kacs.get_mount_policy(vm, fd), kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL,
            "to synthesise-ephemeral")
        t:assert(kacs.get_mount_policy_ex(vm, fd).generation > before.generation,
            "bumping the generation")
        -- Put both back: the rest of the file reads /dev as the kernel left it.
        kacs.set_mount_policy_ex(vm, fd, kacs.MOUNT_POLICY.DENY_MISSING, {})
        sys.close(vm, fd)
        kacs.set_sd(vm, "/dev", original, ALL_INFO)
        t:assert_eq(kacs.get_sd(vm, "/dev", ALL_INFO), original, "restored")
    end)

test("a filesystem mounted after boot is not seeded — the obligation is the artifact's",
    { spec = "PKM *facs.storage.boot-artifacts-not-seeded" }, function(t)
        -- The two mounts above are the only ones the kernel seeds. A
        -- deny-missing filesystem attached afterwards gets nothing, which
        -- is exactly the position a squashfs artifact whose build pipeline
        -- omitted `security.peios.sd` would be in. (A real boot artifact
        -- cannot be mounted here: squashfs, ext4 and vfat all need a block
        -- device the kernel-only profile does not provide.)
        local at = "/artifact"
        t:assert(kacs.new_mount(vm, "tmpfs", at, nil, nil), "a deny-missing mount")
        t:assert_eq(policy_of(at), kacs.MOUNT_POLICY.DENY_MISSING, "in the default class")
        local names = sys.listxattr(vm, at)
        t:assert_eq(#(names or { 1 }), 0, "whose root carries no stored xattr")
        local sd, errno = kacs.get_sd(vm, at, ALL_INFO)
        t:assert(not sd, "and no descriptor")
        t:assert_eq(errno, sys.E.ACCES,
            "so FACS treats the missing descriptor as corruption and denies")
        local mk = sys.mkdir(vm, at .. "/anything")
        t:assert_eq(mk.ret, -1, "nothing can be created under it")
        t:assert_eq(mk.errno, sys.E.ACCES, "EACCES")
    end)
