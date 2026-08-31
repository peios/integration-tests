-- PKM §4.1 — the model stratafs presents, before any of its detail.
--
-- Four claims: the merged view tracks its strata without a remount,
-- every object in it is a real object on a real stratum, the mount has
-- a superblock identity of its own, and a stratum is named by its path
-- rather than by whatever that path pointed at when it was mounted.

local sys = require("helpers.sys")
local stratafs = require("helpers.stratafs")

local vm = provium:vm("v", "kernel-only"):boot()

-- §4.A: the superblock magic, ASCII `STRA`.
local STRATAFS_MAGIC = 0x53545241

test("a change to a stratum shows through without a remount",
    { spec = "PKM *mount.reflects-stratum-changes" }, function(t)
        stratafs.with(vm, "reflects", {
            { name = "upper", flags = { "create" } },
            { name = "lower", flags = { "ro" }, entries = { present = "p" } },
        }, function(s)
            t:assert_eq(vm:read_file(s:join("present")), "p",
                "the name the stratum was populated with is there")
            t:assert(sys.stat(vm, s:join("added")) == nil,
                "and one it was not is not")

            -- Written straight into the stratum, behind stratafs's
            -- back: no mount, no remount, no notification.
            vm:write_file(s:in_stratum("lower", "added"), "a")
            vm:mkdir(s:in_stratum("lower", "dir"))
            vm:unlink(s:in_stratum("lower", "present"))

            t:assert_eq(vm:read_file(s:join("added")), "a",
                "a name that appeared in a stratum appears in the view")
            local dir = sys.stat(vm, s:join("dir"))
            t:assert(dir and dir.is_dir,
                "including a directory")
            t:assert(sys.stat(vm, s:join("present")) == nil,
                "and one that went away is gone from it")
        end)
    end)

test("everything the view holds is a real object on a stratum",
    { spec = "PKM *model.every-object-is-real" }, function(t)
        -- stratafs stores nothing itself, so the whole of what a test
        -- writes through it must survive the mount going away.
        local s = stratafs.scenario(vm, "every-object-real", {
            { name = "upper", flags = { "create" } },
            { name = "lower", flags = { "ro" }, entries = { ["d/lower-file"] = "l" } },
        })
        local ok, err = pcall(function()
            vm:write_file(s:join("created"), "written through the view")
            vm:mkdir(s:join("d", "made"))
            vm:write_file(s:join("d", "made", "nested"), "n")

            -- Each one is visible at its stratum path *while* mounted:
            -- the view did not buffer it somewhere of its own.
            t:assert_eq(vm:read_file(s:in_stratum("upper", "created")),
                "written through the view",
                "a file created through the view is a file on the create stratum")
            t:assert_eq(vm:read_file(s:in_stratum("upper", "d/made/nested")), "n",
                "and so is one under a directory made through it")
        end)
        s.release()
        if not ok then error(err, 0) end

        -- And with no stratafs left in the picture at all.
        t:assert_eq(vm:read_file(s:in_stratum("upper", "created")),
            "written through the view",
            "the object outlives the mount, because it was never the mount's")
        t:assert_eq(vm:read_file(s:in_stratum("lower", "d/lower-file")), "l",
            "and the stratum that only ever provided is untouched")
    end)

test("the mount has a superblock identity of its own",
    { spec = "PKM *mount.superblock-identity" }, function(t)
        local filesystems = vm:read_file("/proc/filesystems")
        t:assert_contains(filesystems, "stratafs",
            "the filesystem type is registered")
        t:assert_contains(filesystems, "nodev\tstratafs",
            "and takes no device — get_tree_nodev")

        stratafs.with(vm, "superblock", {
            { name = "upper", flags = { "create" } },
        }, function(s)
            local fs = sys.statfs(vm, s.at)
            t:assert(fs ~= nil, "statfs on the mount succeeds")
            t:assert_eq(fs.type, STRATAFS_MAGIC,
                "statfs reports STRATAFS_MAGIC")

            -- The device identifier belongs to the mount, not to any
            -- stratum: the same directory reached the two ways reports
            -- two different st_dev.
            local through = sys.stat(vm, s.at)
            local direct = sys.stat(vm, s:in_stratum("upper"))
            t:assert(through and direct, "both paths stat")
            t:assert_neq(through.dev, direct.dev,
                "the view's device is the mount's, not the stratum's")

            -- And it is per-mount, not per-filesystem-type: a second
            -- mount of the same stack is a second superblock.
            local second = s.root .. "/mnt2"
            stratafs.mount(vm, { at = second, strata = s.strata })
            local other = sys.stat(vm, second)
            stratafs.umount(vm, second)
            t:assert(other, "the second mount stats")
            t:assert_neq(through.dev, other.dev,
                "each mount gets an anonymous device of its own")
        end)
    end)

test("a stratum is the path, not the directory it resolved to",
    { spec = "PKM *strata.identified-by-path" }, function(t)
        -- The package-transaction case: swap a whole tree in underneath
        -- a live mount by renaming, and the view follows the path.
        stratafs.with(vm, "identified-by-path", {
            { name = "upper", flags = { "create" } },
            { name = "lower", flags = { "ro" }, entries = { which = "first" } },
        }, function(s)
            t:assert_eq(vm:read_file(s:join("which")), "first",
                "the directory mounted is the one providing")

            local replacement = s.root .. "/replacement"
            stratafs.populate(vm, replacement, { which = "second", extra = "e" })
            local retired = s.root .. "/retired"
            vm:rename(s:in_stratum("lower"), retired)
            vm:rename(replacement, s:in_stratum("lower"))

            t:assert_eq(vm:read_file(s:join("which")), "second",
                "the path now resolves elsewhere, and the view follows it")
            t:assert_eq(vm:read_file(s:join("extra")), "e",
                "the whole tree was replaced, not merged with the old one")
        end)
    end)
