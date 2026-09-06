-- seed-sd, the recursive walk — inventory D1–D9.
--
-- `-r` seeds the named path and then every existing descendant. The
-- order is the load-bearing part: a node is stamped *before* it is read,
-- so a directory that was inaccessible for want of a descriptor becomes
-- readable the instant it is seeded and the walk can enter it. That is
-- what makes one call after mkfs+mount enough, and it is what prelude
-- relies on against /dev.
--
-- The walk is best-effort by design: a node that cannot be stamped is
-- reported and counted and the walk goes on, because one odd inode is no
-- reason to leave the rest of a tree locked. The exit status still says
-- whether everything succeeded, so the failure cases below assert the
-- count as well as the text — a walk that miscounts is a walk that lied
-- about what it left behind.
--
-- Three mechanisms produce failures no guest can talk seed-sd out of:
--
--   * `ramfs` declares no xattr support, so no descriptor can be stored
--     on it and `kacs_set_sd` fails with EOPNOTSUPP. One ramfs mounted
--     inside an otherwise ordinary tree is one unstampable node; a ramfs
--     with N children in it is N+1.
--   * `--sddl` with a descriptor that grants no FILE_LIST_DIRECTORY.
--     seed-sd stamps it and then cannot read the directory it just
--     stamped — which is the unreadable-directory case, reached without
--     anything false about the walk.
--   * `--sddl` with a descriptor that grants no FILE_READ_ATTRIBUTES,
--     which is the same trick one step earlier: the stat that follows
--     the stamp is what fails.
--
-- The last two use `--sddl` only as a way to make an access check fail.
-- What the flag itself does is `sddl.*` in descriptor.test.lua; nothing
-- here asserts anything about it.

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

-- Every file right except FILE_LIST_DIRECTORY (0x1), and except
-- FILE_READ_ATTRIBUTES (0x80), as SDDL hex masks.
local NO_LIST = "O:SYG:SYD:(A;;0x001F01FE;;;SY)"
local NO_ATTRIBUTES = "O:SYG:SYD:(A;;0x001F017F;;;SY)"

local TEMPLATE = access.sd({
    owner = token.SID.LOCAL_SYSTEM,
    group = token.SID.LOCAL_SYSTEM,
    dacl = access.acl({
        access.ace(access.ACE.ALLOWED, GENERIC_ALL, token.SID.LOCAL_SYSTEM, OI_CI),
        access.ace(access.ACE.ALLOWED, GENERIC_ALL, token.SID.ADMINISTRATORS, OI_CI),
        access.ace(access.ACE.ALLOWED, GENERIC_ALL, CREATOR_OWNER, OI_CI | INHERIT_ONLY),
    }),
})

--- A descriptor nothing here writes, so a node still wearing it is a
--- node the walk never reached.
local MARKER = access.sd({
    owner = token.SID.LOCAL_SYSTEM,
    group = token.SID.LOCAL_SYSTEM,
    dacl = access.acl({
        access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS, token.SID.EVERYONE, OI_CI),
    }),
})

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
    t:assert_eq(sd, MARKER, why or (path .. " was never reached"))
end

--- How many nodes seed-sd named on stderr, counting the per-node lines
--- rather than trusting the summary the count is asserted against.
local function reported(stderr)
    local n = 0
    for line in stderr:gmatch("[^\n]+") do
        if line:find("^seed%-sd: ") and not line:find("node%(s%) under ") then
            n = n + 1
        end
    end
    return n
end

-- ---- entering what was locked ----------------------------------------------

test("a directory is seeded before it is read, so the walk can enter one that was inaccessible",
    { spec = "seed-sd walk.a-directory-is-seeded-before-it-is-read" }, function(t)
        -- Build the tree while the mount still synthesises descriptors,
        -- then move it into the deny-missing class. The mount root is the
        -- one inode the kernel never created through the LSM, so it alone
        -- has no stored descriptor — and with it MISSING, everything
        -- underneath is unreachable, however good its own descriptor is.
        local ok, stage, errno = kacs.new_mount(vm, "tmpfs", "/d1",
            kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL)
        t:assert(ok, "a tmpfs that is usable for now: " ..
            tostring(stage) .. " " .. sys.errname(errno or 0))
        t:assert_eq(sys.mkdir(vm, "/d1/a").ret, 0, "a directory on it")
        t:assert_eq(sys.mkdir(vm, "/d1/a/b").ret, 0, "and one below that")
        vm:write_file("/d1/a/b/leaf", "x")

        local fd = sys.open(vm, "/d1", sys.O.PATH)
        t:assert(fd, "an O_PATH handle on the mount")
        t:assert_eq(kacs.set_mount_policy(vm, fd,
            kacs.MOUNT_POLICY.DENY_MISSING).ret, 0, "moved to deny-missing")
        sys.close(vm, fd)

        local dirfd, oe = sys.open(vm, "/d1", sys.O.RDONLY | sys.O.DIRECTORY)
        t:assert(not dirfd, "the root can no longer be listed at all")
        t:assert_eq(oe, sys.E.ACCES, "EACCES — its descriptor is MISSING")

        local r = vm:run(SEED_SD, { "-r", "/d1" })
        t:assert_eq(r.exit_code, 0,
            "the walk seeds the root first and then reads it: " .. r.stderr)
        t:assert_eq(r.stderr, "", "with nothing reported")
        for _, p in ipairs({ "/d1", "/d1/a", "/d1/a/b", "/d1/a/b/leaf" }) do
            stamped(t, p, p .. " came out stamped")
        end
    end)

test("every directory is descended, to any depth",
    { spec = "seed-sd walk.descends-to-any-depth" }, function(t)
        local levels, p = {}, "/d2"
        for i = 1, 20 do
            p = p .. "/l" .. i
            levels[#levels + 1] = p
        end
        vm:mkdir(p, { parents = true })
        vm:write_file(p .. "/leaf", "x")
        for _, level in ipairs(levels) do mark(t, level) end
        mark(t, p .. "/leaf")

        local r = vm:run(SEED_SD, { "-r", "/d2" })
        t:assert_eq(r.exit_code, 0, "the walk succeeds: " .. r.stderr)
        for i, level in ipairs(levels) do
            stamped(t, level, "level " .. i .. " was descended into and stamped")
        end
        stamped(t, p .. "/leaf", "and the file twenty levels down was stamped")
    end)

test("symlinks are stamped but never followed, so the walk cannot leave the tree",
    { spec = "seed-sd walk.symlinks-are-stamped-never-followed" }, function(t)
        -- Not merely tidiness: /dev/core points at /proc/kcore and
        -- /dev/stdin at /proc/self/fd/0, and /proc is UNMANAGED, so
        -- following would fail every such link — while the link inode
        -- itself needs the seed as much as anything else in the tree.
        vm:mkdir("/d3", { parents = true })
        vm:mkdir("/d3-outside/deep", { parents = true })
        vm:write_file("/d3-outside/deep/file", "x")
        for _, p in ipairs({ "/d3-outside", "/d3-outside/deep",
                             "/d3-outside/deep/file" }) do
            mark(t, p)
        end
        t:assert_eq(sys.symlink(vm, "/d3-outside", "/d3/link").ret, 0,
            "a symlink out of the tree, at a directory")
        t:assert_eq(sys.symlink(vm, "/d3-outside/absent", "/d3/dangling").ret, 0,
            "and one at nothing at all")

        local before = get_sd_nofollow("/d3/link")
        t:assert(before, "the link inode has a descriptor of its own")
        t:assert_neq(before, TEMPLATE, "which is not yet the seed descriptor")

        local r = vm:run(SEED_SD, { "-r", "/d3" })
        t:assert_eq(r.exit_code, 0, "the walk succeeds: " .. r.stderr)
        t:assert_eq(r.stderr, "", "and reports nothing — the dangling link " ..
            "would have failed had it been followed")
        t:assert_eq(get_sd_nofollow("/d3/link"), TEMPLATE,
            "the link inode itself was stamped")
        t:assert_eq(get_sd_nofollow("/d3/dangling"), TEMPLATE,
            "and so was the dangling one")
        untouched(t, "/d3-outside", "what the link points at was not entered")
        untouched(t, "/d3-outside/deep", "nor was anything below it")
        untouched(t, "/d3-outside/deep/file", "nor the file inside that")
    end)

test("a wholly successful walk exits 0 and says nothing",
    { spec = "seed-sd walk.a-clean-walk-exits-zero" }, function(t)
        vm:mkdir("/d8/a/b", { parents = true })
        vm:mkdir("/d8/c", { parents = true })
        vm:write_file("/d8/a/file", "x")
        vm:write_file("/d8/a/b/file", "x")
        t:assert_eq(sys.symlink(vm, "file", "/d8/a/link").ret, 0, "and a symlink")

        local r = vm:run(SEED_SD, { "-r", "/d8" })
        t:assert_eq(r.exit_code, 0, "a walk with no failure exits 0")
        t:assert_eq(r.stdout, "", "nothing on stdout")
        t:assert_eq(r.stderr, "", "nothing on stderr")
        for _, p in ipairs({ "/d8", "/d8/a", "/d8/a/b", "/d8/c",
                             "/d8/a/file", "/d8/a/b/file" }) do
            stamped(t, p)
        end
    end)

test("-r on a non-directory stamps it and stops, with no error",
    { spec = "seed-sd walk.a-non-directory-target-is-one-node" }, function(t)
        vm:mkdir("/d9", { parents = true })
        vm:write_file("/d9/file", "x")
        vm:mkdir("/d9/sibling", { parents = true })
        mark(t, "/d9")
        mark(t, "/d9/sibling")

        local r = vm:run(SEED_SD, { "-r", "/d9/file" })
        t:assert_eq(r.exit_code, 0, "recursing over one file is not an error")
        t:assert_eq(r.stderr, "", "and nothing is reported")
        stamped(t, "/d9/file", "the file was stamped")
        untouched(t, "/d9", "its directory was not")
        untouched(t, "/d9/sibling", "and neither was anything beside it")
    end)

-- ---- best effort -----------------------------------------------------------

test("a node that cannot be stamped is reported and the walk carries on",
    { spec = "seed-sd walk.is-best-effort" }, function(t)
        -- One unstampable inode in the middle of an ordinary tree: a
        -- ramfs mount, which can store no descriptor at all.
        vm:mkdir("/d4", { parents = true })
        local siblings = { "a", "b", "c", "d" }
        for _, name in ipairs(siblings) do
            vm:mkdir("/d4/" .. name .. "/nested", { parents = true })
            vm:write_file("/d4/" .. name .. "/nested/file", "x")
        end
        local ok, stage, errno = kacs.new_mount(vm, "ramfs", "/d4/blocked",
            kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL)
        t:assert(ok, "a ramfs that can hold no descriptor: " ..
            tostring(stage) .. " " .. sys.errname(errno or 0))

        local r = vm:run(SEED_SD, { "-r", "/d4" })
        t:assert_eq(r.exit_code, 1, "the walk finishes and reports the failure")
        t:assert(r.stderr:find("seed%-sd: set_sd /d4/blocked: "),
            "naming the node it could not stamp, got " .. string.format("%q", r.stderr))
        t:assert_eq(reported(r.stderr), 1,
            "and exactly one node was named, so nothing else was disturbed")

        stamped(t, "/d4", "the root was still seeded")
        for _, name in ipairs(siblings) do
            stamped(t, "/d4/" .. name, "/d4/" .. name .. " was seeded either side of the failure")
            stamped(t, "/d4/" .. name .. "/nested", "and so was what is under it")
            stamped(t, "/d4/" .. name .. "/nested/file", "down to the file")
        end
    end)

test("a walk with any failure exits 1 after printing how many nodes it left",
    { spec = "seed-sd walk.failure-count-is-reported-and-exits-one" }, function(t)
        -- Four unstampable nodes: a ramfs mount and the three directories
        -- made inside it. The count is asserted, not just the shape of
        -- the line — a walk that miscounts is a walk that misreports what
        -- it left locked.
        vm:mkdir("/d5", { parents = true })
        vm:write_file("/d5/ordinary", "x")
        local ok, stage, errno = kacs.new_mount(vm, "ramfs", "/d5/rf",
            kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL)
        t:assert(ok, "a ramfs inside the tree: " ..
            tostring(stage) .. " " .. sys.errname(errno or 0))
        for _, name in ipairs({ "x", "y", "z" }) do
            t:assert_eq(sys.mkdir(vm, "/d5/rf/" .. name).ret, 0,
                "a directory on the ramfs")
        end

        local r = vm:run(SEED_SD, { "-r", "/d5" })
        t:assert_eq(r.exit_code, 1, "any failure at all is exit 1")
        t:assert_eq(r.stdout, "", "the summary is not stdout's business")
        t:assert(r.stderr:find(
            "seed%-sd: 4 node%(s%) under /d5 could not be seeded\n$"),
            "`seed-sd: N node(s) under <path> could not be seeded`, last, " ..
            "got " .. string.format("%q", r.stderr))
        for _, p in ipairs({ "/d5/rf", "/d5/rf/x", "/d5/rf/y", "/d5/rf/z" }) do
            t:assert(r.stderr:find("seed%-sd: set_sd " .. p .. ": "),
                p .. " is one of the four")
        end
        t:assert_eq(reported(r.stderr), 4,
            "four nodes were named, so the summary counts what it reported")
        stamped(t, "/d5/ordinary", "and the rest of the tree was still seeded")
    end)

test("a directory that cannot be read counts one failure and is not descended into",
    { spec = "seed-sd walk.an-unreadable-directory-counts-once" }, function(t)
        -- Seeding a directory with a descriptor that grants no
        -- FILE_LIST_DIRECTORY makes the read that follows the stamp fail:
        -- seed-sd locks itself out of the directory it has just stamped.
        -- Nothing bypasses FILE_LIST_DIRECTORY, so being SYSTEM with
        -- every privilege does not help.
        vm:mkdir("/d6/child/grandchild", { parents = true })
        vm:write_file("/d6/child/file", "x")
        mark(t, "/d6/child")

        local r = vm:run(SEED_SD, { "-r", "--sddl", NO_LIST, "/d6" })
        t:assert_eq(r.exit_code, 1, "the walk reports a failure")
        t:assert(r.stderr:find("seed%-sd: read_dir /d6: "),
            "naming the directory it could not read, got " ..
            string.format("%q", r.stderr))
        t:assert(not r.stderr:find("seed%-sd: set_sd /d6:"),
            "the stamp itself succeeded — the read is what failed")
        t:assert(r.stderr:find(
            "seed%-sd: 1 node%(s%) under /d6 could not be seeded\n$"),
            "and it counts once, not once per node it never saw")
        t:assert_eq(reported(r.stderr), 1, "one node was named, and only one")
        t:assert(not r.stderr:find("child", 1, true),
            "nothing below it is mentioned")
        untouched(t, "/d6/child", "because the walk never entered the directory")
    end)

test("a node that cannot be stat'd counts one failure and ends that branch",
    { spec = "seed-sd walk.a-stat-failure-ends-that-branch" }, function(t)
        -- Same trick one step earlier: a descriptor granting no
        -- FILE_READ_ATTRIBUTES, so the symlink_metadata that decides
        -- whether to descend is what is refused. The branch stops there
        -- — the walk cannot tell a directory from a file without it.
        vm:mkdir("/d7/child", { parents = true })
        mark(t, "/d7/child")

        local r = vm:run(SEED_SD, { "-r", "--sddl", NO_ATTRIBUTES, "/d7" })
        t:assert_eq(r.exit_code, 1, "the walk reports a failure")
        t:assert(r.stderr:find("seed%-sd: stat /d7: "),
            "naming the node it could not stat, got " ..
            string.format("%q", r.stderr))
        t:assert(r.stderr:find(
            "seed%-sd: 1 node%(s%) under /d7 could not be seeded\n$"),
            "counted once")
        t:assert_eq(reported(r.stderr), 1, "one node was named, and only one")
        untouched(t, "/d7/child", "and the branch ended there")
    end)
