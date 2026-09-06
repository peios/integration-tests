-- seed-sd, stamping one node — inventory C1–C5.
--
-- `seed-sd <path>` writes owner, group and DACL onto exactly one inode.
-- Everything the recursive walk does is built on this call, so the cases
-- here are about the single stamp: what it says when it works, what it
-- says when it does not, which inode it lands on when the path names a
-- symlink, and the one case the tool exists for — an inode whose
-- descriptor is MISSING, which under KACS is denied to everyone
-- including SYSTEM.
--
-- The guest is the prelude profile: prelude boots, its root-mount hook
-- mounts and seeds a tmpfs, and the provium agent is what prelude execs
-- on the far side of the handoff. The agent runs as SYSTEM with every
-- privilege, so `vm:run` starts seed-sd with exactly the token prelude
-- and its hooks give it. There is no shell in that root — every call is
-- the direct-exec form.
--
-- Two substrates recur:
--
--   * a fresh `tmpfs` in the deny-missing class, whose root inode was
--     never created through the LSM and therefore has no descriptor at
--     all. That is the MISSING state, and it is what a mount looks like
--     the moment it is attached.
--   * a fresh `ramfs`, which declares no xattr support, so no descriptor
--     can ever be stored on it. `kacs_set_sd` fails there with
--     EOPNOTSUPP, which is how a stamp failure is produced without
--     contriving anything about seed-sd itself.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local access = require("helpers.access")
local token = require("helpers.token")

local vm = provium:vm("v", "prelude"):boot()

local SEED_SD = "/bin/seed-sd"
local ALL_INFO = kacs.SI.OWNER | kacs.SI.GROUP | kacs.SI.DACL
local OI_CI = access.ACE_FLAG.OBJECT_INHERIT | access.ACE_FLAG.CONTAINER_INHERIT
local INHERIT_ONLY = access.ACE_FLAG.INHERIT_ONLY
local GENERIC_ALL = 0x10000000
local CREATOR_OWNER = token.sid(3, 0)

--- The descriptor `build_seed_sd` produces: SYSTEM-owned, SYSTEM group,
--- and three allow ACEs — SYSTEM, BUILTIN\Administrators and CREATOR
--- OWNER, all GENERIC_ALL and inheritable, the last inherit-only.
---
--- Composed here rather than read back from a known-good node so that a
--- case asserting "this node was stamped" is asserting against the
--- descriptor the tool is documented to write, not against whatever it
--- happened to write elsewhere in the same run.
local TEMPLATE = access.sd({
    owner = token.SID.LOCAL_SYSTEM,
    group = token.SID.LOCAL_SYSTEM,
    dacl = access.acl({
        access.ace(access.ACE.ALLOWED, GENERIC_ALL, token.SID.LOCAL_SYSTEM, OI_CI),
        access.ace(access.ACE.ALLOWED, GENERIC_ALL, token.SID.ADMINISTRATORS, OI_CI),
        access.ace(access.ACE.ALLOWED, GENERIC_ALL, CREATOR_OWNER, OI_CI | INHERIT_ONLY),
    }),
})

--- A descriptor nothing else in this file writes, for "this node was
--- left alone". Everyone, every right, inheritable — so a node wearing
--- it stays reachable and the test can still read it back.
local MARKER = access.sd({
    owner = token.SID.LOCAL_SYSTEM,
    group = token.SID.LOCAL_SYSTEM,
    dacl = access.acl({
        access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS, token.SID.EVERYONE, OI_CI),
    }),
})

--- kacs_get_sd against the named inode itself, never the symlink target.
local function get_sd_nofollow(path)
    local r = vm:syscall(kacs.SYS.GET_SD, {
        args = { sys.AT_FDCWD, 0, ALL_INFO, 0, 4096, sys.AT_SYMLINK_NOFOLLOW },
        bufs = { sys.cstr(path), string.rep("\0", 4096) },
        ptrs = { 1, 3 },
    })
    if r.ret < 0 then return nil, r.errno end
    return r.out_bufs[2]:sub(1, r.ret)
end

local function mark(t, path)
    local r = kacs.set_sd(vm, path, MARKER, ALL_INFO)
    t:assert_eq(r.ret, 0, "marking " .. path .. ": " .. sys.errname(r.errno))
end

local function stamped(t, path, why)
    local sd, errno = kacs.get_sd(vm, path, ALL_INFO)
    t:assert(sd, "reading " .. path .. "'s descriptor: " .. sys.errname(errno or 0))
    t:assert_eq(sd, TEMPLATE, why or (path .. " carries the seed descriptor"))
end

local function untouched(t, path, why)
    local sd, errno = kacs.get_sd(vm, path, ALL_INFO)
    t:assert(sd, "reading " .. path .. "'s descriptor: " .. sys.errname(errno or 0))
    t:assert_eq(sd, MARKER, why or (path .. " still wears the mark it was given"))
end

-- ---- success ---------------------------------------------------------------

test("a stamp that works exits 0 and prints nothing",
    { spec = "seed-sd stamp.success-is-silent-and-exits-zero" }, function(t)
        vm:mkdir("/c1", { parents = true })
        mark(t, "/c1")

        local r = vm:run(SEED_SD, { "/c1" })
        t:assert_eq(r.exit_code, 0, "success is exit 0")
        t:assert_eq(r.stdout, "", "and no output on stdout")
        t:assert_eq(r.stderr, "", "and none on stderr either")
        stamped(t, "/c1", "the descriptor did land, so the silence is not inaction")
    end)

test("it replaces a MISSING descriptor, which is the whole point",
    { spec = "seed-sd stamp.replaces-a-missing-descriptor" }, function(t)
        -- A filesystem attached at runtime lands in the deny-missing
        -- class, and its root inode was never created through
        -- inode_init_security, so it has no stored descriptor. KACS
        -- denies every access to such an inode — to the agent too, which
        -- is SYSTEM and holds every privilege.
        local ok, stage, errno = kacs.new_mount(vm, "tmpfs", "/c5", nil)
        t:assert(ok, "a fresh deny-missing tmpfs: " ..
            tostring(stage) .. " " .. sys.errname(errno or 0))

        local before, ge = kacs.get_sd(vm, "/c5", ALL_INFO)
        t:assert(not before, "its root has no descriptor to read back")
        t:assert_eq(ge, sys.E.ACCES, "the read is refused with EACCES")
        t:assert_eq(sys.mkdir(vm, "/c5/before").errno, sys.E.ACCES,
            "and nothing can be created in it")

        -- Replacing a MISSING descriptor is the one write KACS gates on
        -- SeRestorePrivilege; the token seed-sd inherits has it.
        local r = vm:run(SEED_SD, { "/c5" })
        t:assert_eq(r.exit_code, 0, "seed-sd stamps it anyway: " .. r.stderr)
        stamped(t, "/c5", "the mount root now carries the seed descriptor")
        t:assert_eq(sys.mkdir(vm, "/c5/after").ret, 0,
            "and the filesystem is usable, which it was not a moment ago")
    end)

-- ---- what one stamp reaches ------------------------------------------------

test("without -r the named directory is stamped and nothing inside it is",
    { spec = "seed-sd stamp.without-r-touches-only-the-named-path" }, function(t)
        vm:mkdir("/c3/inner", { parents = true })
        vm:write_file("/c3/inner/file", "x")
        mark(t, "/c3/inner")
        mark(t, "/c3/inner/file")

        local r = vm:run(SEED_SD, { "/c3" })
        t:assert_eq(r.exit_code, 0, "the stamp succeeds: " .. r.stderr)
        stamped(t, "/c3", "the named directory got the descriptor")
        untouched(t, "/c3/inner", "the directory inside it did not")
        untouched(t, "/c3/inner/file", "nor did the file below that")
    end)

test("a symlink is stamped as itself and never followed",
    { spec = "seed-sd stamp.a-symlink-is-stamped-as-itself" }, function(t)
        -- prelude depends on this against /dev, where /dev/core points at
        -- /proc/kcore: /proc is UNMANAGED, so following the link would
        -- fail — while the link inode is what `ls -l` has to stat, and it
        -- needs the seed as much as anything else in the tree.
        vm:mkdir("/c2", { parents = true })
        vm:write_file("/c2/target", "x")
        mark(t, "/c2/target")
        t:assert_eq(sys.symlink(vm, "/c2/target", "/c2/link").ret, 0,
            "a symlink beside its target")

        local before = get_sd_nofollow("/c2/link")
        t:assert(before, "the link inode has a descriptor of its own")
        t:assert_neq(before, TEMPLATE, "which is not yet the seed descriptor")

        local r = vm:run(SEED_SD, { "/c2/link" })
        t:assert_eq(r.exit_code, 0, "seeding the link succeeds: " .. r.stderr)
        t:assert_eq(get_sd_nofollow("/c2/link"), TEMPLATE,
            "the link inode itself was stamped")
        untouched(t, "/c2/target", "and what it points at was not touched")
    end)

-- ---- failure ---------------------------------------------------------------

test("a stamp that fails exits 1 and names the path it could not write",
    { spec = "seed-sd stamp.a-failure-exits-one-and-names-the-path" }, function(t)
        -- ramfs declares no xattr support, so the canonical descriptor
        -- can never be stored on it and kacs_set_sd fails. The
        -- synthesising class is what keeps the mount otherwise reachable,
        -- so the only thing that goes wrong is the write seed-sd came to
        -- make.
        local ok, stage, errno = kacs.new_mount(vm, "ramfs", "/c4",
            kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL)
        t:assert(ok, "a ramfs that can hold no descriptor: " ..
            tostring(stage) .. " " .. sys.errname(errno or 0))

        local r = vm:run(SEED_SD, { "/c4" })
        t:assert_eq(r.exit_code, 1,
            "an operational failure is exit 1, distinct from 2 for a usage error")
        t:assert_eq(r.stdout, "", "nothing goes to stdout")

        local detail = r.stderr:match("^seed%-sd: set_sd /c4: (.-)\n$")
        t:assert(detail, "stderr is `seed-sd: set_sd <path>: <error>`, got " ..
            string.format("%q", r.stderr))
        t:assert(#detail > 0, "with the underlying error after the path")
        -- The synthesising class still answers for the inode, so the
        -- evidence that nothing landed is that what it answers with is
        -- not what seed-sd tried to write.
        t:assert_neq(kacs.get_sd(vm, "/c4", ALL_INFO), TEMPLATE,
            "and the descriptor did not land, which is what it was reporting")
    end)
