-- PKM §3.9.5 — the mutable root filesystem is a tmpfs whatever the
-- command line says. Upstream Linux makes it a ramfs when the command
-- line carries `root=`, or a `rootfstype=` that does not name tmpfs, and
-- ramfs stores no extended attributes, so the rootfs seed would have
-- nowhere to go.
--
-- `/proc/self/mounts` names the root `rootfs` either way; the filesystem
-- magic is what tells tmpfs (0x01021994) from ramfs (0x858458f6). The
-- second guest boots with both of the upstream triggers on its command
-- line — an installed system's `root=` and a `rootfstype=` naming
-- something else — and its initramfs still runs, because a kernel that
-- finds /init in the archive never mounts root= itself.
--
-- `facs.storage.rootfs-seed-failure-is-fatal` has no case here: the
-- panic needs the seed's xattr write to fail on a tmpfs root, which a
-- correctly built kernel never does, and no KUnit case covers it.
--
-- Belongs in facs-storage-mounts.test.lua beside "the rootfs root is
-- seeded before the mount is published".

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")

local TMPFS_MAGIC = 0x01021994
local RAMFS_MAGIC = 0x858458f6
local ALL_INFO = kacs.SI.OWNER | kacs.SI.GROUP | kacs.SI.DACL

local vm = provium:vm("v", "kernel-only"):boot()
local rooted = provium:vm("vroot", "kernel-only")
    :boot({ kernel_cmdline_append = "root=/dev/vda rootfstype=ext4" })

--- The root's magic, and whether it carries a descriptor.
local function root_of(t, guest, label)
    local st, errno = sys.statfs(guest, "/")
    t:assert(st, label .. ": statfs / : " .. sys.errname(errno or 0))
    local sd, serr = kacs.get_sd(guest, "/", ALL_INFO)
    return st and st.type, sd, serr
end

test("the rootfs is a tmpfs on a plain boot",
    { spec = "PKM *facs.storage.rootfs-always-tmpfs" }, function(t)
        local magic, sd, serr = root_of(t, vm, "plain")
        t:assert_eq(magic, TMPFS_MAGIC,
            string.format("/ is TMPFS_MAGIC, not 0x%x", magic or 0))
        t:assert(sd, "and carries the seeded descriptor: " .. sys.errname(serr or 0))
    end)

test("the rootfs is a tmpfs even when the command line carries root= and rootfstype=",
    { spec = "PKM *facs.storage.rootfs-always-tmpfs" }, function(t)
        local cmdline = rooted:read_file("/proc/cmdline")
        t:assert(cmdline:find("root=/dev/vda", 1, true),
            "the guest booted with root= on its command line: " .. cmdline)
        t:assert(cmdline:find("rootfstype=ext4", 1, true),
            "and a rootfstype= that does not name tmpfs")
        t:assert(rooted:read_file("/proc/self/mounts"):match("rootfs / rootfs"),
            "/ is still the initramfs root")

        local magic, sd, serr = root_of(t, rooted, "root=")
        t:assert(magic ~= RAMFS_MAGIC, "it is not the ramfs upstream would have made")
        t:assert_eq(magic, TMPFS_MAGIC,
            string.format("/ is TMPFS_MAGIC: 0x%x", magic or 0))
        -- Which is what makes the seed possible: the root carries it,
        -- and what the archive unpacked inherited from it.
        t:assert(sd, "the root carries the seeded descriptor: " .. sys.errname(serr or 0))
        local names = sys.listxattr(rooted, "/") or {}
        local stored = false
        for _, n in ipairs(names) do if n == "security.peios.sd" then stored = true end end
        t:assert(stored, "stored as an xattr on the root inode")
        local child, cerr = kacs.get_sd(rooted, "/fixtures", ALL_INFO)
        t:assert(child, "and a directory the archive unpacked carries one too: "
            .. sys.errname(cerr or 0))
    end)
