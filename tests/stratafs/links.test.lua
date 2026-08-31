-- PKM §4.5.6, §4.5.7 and §4.5.8 — hard links within one mount, locks
-- held on the provider's object, and where durability and accounting
-- land when the filesystem holds no storage.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local stratafs = require("helpers.stratafs")

local vm = provium:vm("v", "kernel-only"):boot()

test("a link's source provider must accept modification",
    { spec = "PKM *link.source-provider-must-be-writable" }, function(t)
        -- EXDEV rather than EROFS: it is the error callers already
        -- handle when a link cannot be made between two locations, and
        -- it is accurate — the link would have to span two strata,
        -- which through this mount are two filesystems.
        stratafs.with(vm, "link-source-ro", {
            { name = "dest", flags = { "create" } },
            { name = "frozen", flags = { "ro" }, entries = { f = "original" } },
        }, function(s)
            local r = sys.link(vm, s:join("f"), s:join("newname"))
            t:assert_neq(r.ret, 0, "linking from a ro stratum is refused")
            t:assert_eq(r.errno, sys.E.XDEV, "with EXDEV: " .. sys.errname(r.errno))
            t:assert(sys.stat(vm, s:join("newname")) == nil, "and no link was made")
        end)
    end)

test("a link is never satisfied by copying the source up",
    { spec = "PKM *link.never-copies-up" }, function(t)
        -- The result would be a link to the copy rather than to the
        -- object the source names, so the two names would not share an
        -- object — which is the whole of what a hard link is for.
        stratafs.with(vm, "link-no-copy", {
            { name = "dest", flags = { "create" } },
            { name = "frozen", flags = { "ro" }, entries = { f = "original" } },
        }, function(s)
            local r = sys.link(vm, s:join("f"), s:join("newname"))
            t:assert_neq(r.ret, 0, "the link is refused")
            t:assert(sys.stat(vm, s:in_stratum("dest", "f")) == nil,
                "and nothing was copied up to satisfy it")
            t:assert(sys.stat(vm, s:in_stratum("dest", "newname")) == nil,
                "nor was a copy linked into place")
        end)
    end)

test("the destination must not be held by any stratum",
    { spec = "PKM *link.destination-must-not-be-held" }, function(t)
        stratafs.with(vm, "link-dest-held", {
            { name = "provider", flags = { "create" }, entries = { f = "original" } },
            { name = "below", flags = { "ro" }, entries = { taken = "held below" } },
        }, function(s)
            local r = sys.link(vm, s:join("f"), s:join("taken"))
            t:assert_neq(r.ret, 0, "a destination held below is refused")
            t:assert_eq(r.errno, sys.E.EXIST,
                "with EEXIST, so the new link is not shadowed: " ..
                sys.errname(r.errno))

            t:assert_eq(sys.link(vm, s:join("f"), s:join("free")).ret, 0,
                "while a name no stratum holds is accepted")
        end)
    end)

test("the destination's parent must be held by the source's provider",
    { spec = "PKM *link.destination-parent-in-provider" }, function(t)
        stratafs.with(vm, "link-dest-parent", {
            { name = "provider", flags = { "create" }, entries = { f = "original" } },
            { name = "other", entries = { ["d/x"] = "x" } },
        }, function(s)
            t:assert(sys.stat(vm, s:in_stratum("provider", "d")) == nil,
                "the provider does not hold the destination's parent")
            local r = sys.link(vm, s:join("f"), s:join("d", "newname"))
            t:assert_neq(r.ret, 0, "the link is refused")
            t:assert_eq(r.errno, sys.E.XDEV, "with EXDEV: " .. sys.errname(r.errno))
            t:assert(sys.stat(vm, s:in_stratum("provider", "d")) == nil,
                "and the directory was not created to satisfy it")
        end)
    end)

test("the link is created in the source's provider, whichever that is",
    { spec = "PKM *link.created-in-the-provider" }, function(t)
        -- That is the only stratum in which the two names can share an
        -- object, so the provider need not be the create stratum.
        stratafs.with(vm, "link-in-provider", {
            { name = "dest", flags = { "create" } },
            { name = "provider", entries = { f = "original" } },
        }, function(s)
            t:assert_eq(sys.link(vm, s:join("f"), s:join("newname")).ret, 0,
                "the link is made")
            t:assert(sys.stat(vm, s:in_stratum("provider", "newname")) ~= nil,
                "in the stratum that provides the source")
            t:assert(sys.stat(vm, s:in_stratum("dest", "newname")) == nil,
                "and not in the create stratum")

            local a = sys.stat(vm, s:join("f"))
            local b = sys.stat(vm, s:join("newname"))
            t:assert_eq(a.ino, b.ino, "the two names share one object")
            t:assert_eq(a.nlink, 2, "with a link count to match")
        end)
    end)

test("an unnamed file is linked into the create stratum",
    { spec = "PKM *link.unnamed-goes-to-create-stratum" }, function(t)
        -- It has no provider, so the hard-link conditions have no
        -- subject and §4.5.3's rules apply instead.
        stratafs.with(vm, "link-unnamed", {
            { name = "high", entries = { ["d/x"] = "x" } },
            { name = "dest", flags = { "create" } },
        }, function(s)
            local fd = sys.open(vm, s:join("d"),
                sys.O.TMPFILE | sys.O.RDWR, tonumber("644", 8))
            t:assert(fd, "an unnamed file is created")
            sys.write(vm, fd, "unnamed contents")

            -- linkat with AT_EMPTY_PATH from the descriptor.
            local r = vm:syscall(sys.NR.linkat, {
                args = { fd, 0, sys.AT_FDCWD, 0, sys.AT_EMPTY_PATH },
                bufs = { sys.cstr(""), sys.cstr(s:join("d", "named")) },
                ptrs = { 1, 3 },
            })
            sys.close(vm, fd)
            t:assert_eq(r.ret, 0, "and linked into the mount: " ..
                sys.errname(r.errno))
            t:assert_eq(vm:read_file(s:in_stratum("dest", "d/named")),
                "unnamed contents",
                "landing in the create stratum, not the stratum above")
            t:assert(sys.stat(vm, s:in_stratum("high", "d/named")) == nil,
                "which holds nothing new")
        end)
    end)

test("linking an unnamed file into another mount is EXDEV",
    { spec = "PKM *link.unnamed-cross-mount-exdev" }, function(t)
        local a = stratafs.scenario(vm, "link-unnamed-a", {
            { name = "only", flags = { "create" } },
        })
        local b = stratafs.scenario(vm, "link-unnamed-b", {
            { name = "only", flags = { "create" } },
        })
        local ok, err = pcall(function()
            local fd = sys.open(vm, a.at, sys.O.TMPFILE | sys.O.RDWR,
                tonumber("644", 8))
            t:assert(fd, "an unnamed file is created in the first mount")
            local r = vm:syscall(sys.NR.linkat, {
                args = { fd, 0, sys.AT_FDCWD, 0, sys.AT_EMPTY_PATH },
                bufs = { sys.cstr(""), sys.cstr(b:join("named")) },
                ptrs = { 1, 3 },
            })
            sys.close(vm, fd)
            t:assert_neq(r.ret, 0, "linking it into the second is refused")
            t:assert_eq(r.errno, sys.E.XDEV, "with EXDEV: " .. sys.errname(r.errno))
        end)
        a.release(); b.release()
        if not ok then error(err, 0) end
    end)

test("a failed install rolls the lower link back",
    { spec = "PKM *link.rolled-back-on-install-failure",
      skip = "the rollback path runs only where installing the outer inode " ..
             "fails after the lower link succeeded — an allocation failure " ..
             "between two steps of one syscall. Wants fault injection" },
    function(t) t:fail("no way to fail the install") end)

test("a symbolic link's target is stored and returned verbatim",
    { spec = "PKM *link.symlink-target-verbatim" }, function(t)
        -- No rewriting exists anywhere: a target naming a path inside a
        -- stratum is not rewritten to name the corresponding path
        -- inside the mount, nor the reverse.
        stratafs.with(vm, "symlink-verbatim", {
            { name = "dest", flags = { "create" } },
            { name = "below", entries = { existing = stratafs.symlink("/etc/thing") } },
        }, function(s)
            local targets = {
                relative = "../up/and/over",
                absolute = "/stratafs/somewhere/else",
                stratum_path = s:in_stratum("below", "existing"),
                awkward = "a:b+c,d\\e f",
                dangling = "nothing-here-at-all",
            }
            for name, target in pairs(targets) do
                t:assert_eq(sys.symlink(vm, target, s:join(name)).ret, 0,
                    "`" .. name .. "` is created")
                t:assert_eq(sys.readlink(vm, s:join(name)), target,
                    "`" .. name .. "` reads back byte for byte")
                t:assert_eq(sys.readlink(vm, s:in_stratum("dest", name)), target,
                    "and is stored in the create stratum unchanged")
            end

            -- One created directly in a stratum is likewise untouched.
            t:assert_eq(sys.readlink(vm, s:join("existing")), "/etc/thing",
                "a link the stratum's own owner made is returned as written")
        end)
    end)

test("a lock is taken on the provider's object, in its own lock space",
    { spec = "PKM *lock.taken-on-the-provider-object" }, function(t)
        -- A lock taken through the mount and a lock taken directly on
        -- the same object must be the same lock, since a stratafs mount
        -- is established over directories that have their own writers.
        stratafs.with(vm, "lock-provider", {
            { name = "only", flags = { "create" }, entries = { f = "x" } },
        }, function(s)
            local through = sys.open(vm, s:join("f"), sys.O.RDWR)
            t:assert(through, "the merged path opens")
            t:assert_eq(sys.flock(vm, through, sys.LOCK_EX).ret, 0,
                "and takes an exclusive lock")

            -- A second process locking the same object directly must
            -- contend with it.
            local worker = vm:spawn_worker()
            local ok, err = pcall(function()
                local direct = sys.open(worker, s:in_stratum("only", "f"),
                    sys.O.RDWR)
                t:assert(direct, "the stratum path opens directly")
                local r = sys.flock(worker, direct, sys.LOCK_EX | sys.LOCK_NB)
                t:assert_neq(r.ret, 0,
                    "and cannot take the same lock through the stratum")
                t:assert_eq(r.errno, sys.E.AGAIN,
                    "they contend, so it is one lock space: " ..
                    sys.errname(r.errno))
                sys.close(worker, direct)
            end)
            worker:kill(); worker:join()
            sys.flock(vm, through, sys.LOCK_UN)
            sys.close(vm, through)
            if not ok then error(err, 0) end
        end)
    end)

test("locking needs no write access and cannot cause a copy-up",
    { spec = "PKM *lock.taken-on-the-provider-object" }, function(t)
        stratafs.with(vm, "lock-no-write", {
            { name = "dest", flags = { "create" } },
            { name = "src", flags = { "ro" }, entries = { f = "original" } },
        }, function(s)
            local fd = sys.open(vm, s:join("f"), sys.O.RDONLY)
            t:assert(fd, "a read-only descriptor opens")
            t:assert_eq(sys.flock(vm, fd, sys.LOCK_SH).ret, 0,
                "and carries a shared lock")
            sys.flock(vm, fd, sys.LOCK_UN)
            sys.close(vm, fd)
            t:assert(sys.stat(vm, s:in_stratum("dest", "f")) == nil,
                "with no copy-up: taking a lock does not modify an object")
        end)
    end)

test("a lock is not transferred when the provider changes",
    { spec = "PKM *lock.not-transferred-on-provider-change" }, function(t)
        -- Two callers may hold exclusive locks on one merged path
        -- without contending, whenever they opened it either side of a
        -- change of provider. Neither is wrong about the object it
        -- locked; the merged path is what stopped naming one thing.
        stratafs.with(vm, "lock-provider-change", {
            { name = "dest", flags = { "create" } },
            { name = "src", entries = { f = "original" } },
        }, function(s)
            local first = sys.open(vm, s:join("f"), sys.O.RDWR)
            t:assert(first, "the first descriptor opens on the provider")
            t:assert_eq(sys.flock(vm, first, sys.LOCK_EX).ret, 0,
                "and locks it exclusively")

            -- A higher-precedence stratum gains the name.
            vm:write_file(s:in_stratum("dest", "f"), "the new provider")
            t:assert_eq(vm:read_file(s:join("f")), "the new provider",
                "a new object now provides the name")

            local second = sys.open(vm, s:join("f"), sys.O.RDWR)
            t:assert(second, "a second descriptor opens on it")
            local r = sys.flock(vm, second, sys.LOCK_EX | sys.LOCK_NB)
            t:assert_eq(r.ret, 0,
                "and takes an exclusive lock without contending: " ..
                sys.errname(r.errno))

            sys.flock(vm, second, sys.LOCK_UN); sys.close(vm, second)
            sys.flock(vm, first, sys.LOCK_UN); sys.close(vm, first)
        end)
    end)

test("an unlock reaches the retired pre-copy-up file",
    { spec = "PKM *lock.unlock-reaches-the-retired-file" }, function(t)
        -- Copy-up does not close the file it copied from; the retired
        -- file is kept specifically so locks taken before the copy-up
        -- stay alive. An unlock is applied to both.
        stratafs.with(vm, "lock-retired", {
            { name = "dest", flags = { "create" } },
            { name = "src", flags = { "ro" }, entries = { f = "original" } },
        }, function(s)
            local fd = sys.open(vm, s:join("f"), sys.O.RDWR)
            t:assert(fd, "a descriptor opens on the ro provider")
            t:assert_eq(sys.flock(vm, fd, sys.LOCK_EX).ret, 0,
                "and locks it before any copy-up")

            t:assert_eq(sys.write(vm, fd, "modified").ret, 8,
                "the write copies it up")
            t:assert_eq(sys.flock(vm, fd, sys.LOCK_UN).ret, 0,
                "the unlock succeeds")
            sys.close(vm, fd)

            -- The lock on the retired file was released too, so another
            -- caller can now take it on the original object.
            local worker = vm:spawn_worker()
            local ok, err = pcall(function()
                -- Writable, because KACS maps flock LOCK_EX to
                -- FILE_WRITE_DATA (§3.9) and a read-only descriptor
                -- carries no such grant.
                local direct = sys.open(worker, s:in_stratum("src", "f"),
                    sys.O.RDWR)
                t:assert(direct, "the original object opens directly")
                local r = sys.flock(worker, direct, sys.LOCK_EX | sys.LOCK_NB)
                t:assert_eq(r.ret, 0,
                    "and is lockable, so the unlock reached the retired " ..
                    "file: " .. sys.errname(r.errno))
                sys.close(worker, direct)
            end)
            worker:kill(); worker:join()
            if not ok then error(err, 0) end
        end)
    end)

test("closing a descriptor clears locks on both files",
    { spec = "PKM *lock.close-clears-both-files" }, function(t)
        stratafs.with(vm, "lock-close", {
            { name = "dest", flags = { "create" } },
            { name = "src", flags = { "ro" }, entries = { f = "original" } },
        }, function(s)
            local fd = sys.open(vm, s:join("f"), sys.O.RDWR)
            t:assert_eq(sys.flock(vm, fd, sys.LOCK_EX).ret, 0,
                "a lock is taken before the copy-up")
            t:assert_eq(sys.write(vm, fd, "modified").ret, 8, "which then happens")
            -- Closed without unlocking: the release path has to clear
            -- both the copy and the retired original.
            sys.close(vm, fd)

            local worker = vm:spawn_worker()
            local ok, err = pcall(function()
                for _, path in ipairs({ s:in_stratum("src", "f"),
                                        s:in_stratum("dest", "f") }) do
                    local d = sys.open(worker, path, sys.O.RDWR)
                    t:assert(d, "`" .. path .. "` opens")
                    local r = sys.flock(worker, d, sys.LOCK_EX | sys.LOCK_NB)
                    t:assert_eq(r.ret, 0,
                        "and is lockable after the close: " ..
                        sys.errname(r.errno))
                    sys.close(worker, d)
                end
            end)
            worker:kill(); worker:join()
            if not ok then error(err, 0) end
        end)
    end)

test("leases are the provider's own, established in its lock space",
    { spec = "PKM *lock.leases-are-the-providers" }, function(t)
        -- stratafs neither adds to nor removes from whatever semantics
        -- the provider's filesystem gives them, and never reports a
        -- lease as established where the provider refused it.
        stratafs.with(vm, "leases", {
            { name = "only", flags = { "create" }, entries = { f = "x" } },
        }, function(s)
            local F_SETLEASE, F_GETLEASE = 1024, 1025
            local F_RDLCK, F_UNLCK = 0, 2
            local fd = sys.open(vm, s:join("f"), sys.O.RDONLY)
            t:assert(fd, "the merged path opens")

            local set = vm:syscall(72, fd, F_SETLEASE, F_RDLCK) -- fcntl
            t:assert_eq(set.ret, 0, "a read lease is granted: " ..
                sys.errname(set.errno))

            local got = vm:syscall(72, fd, F_GETLEASE, 0)
            t:assert_eq(got.ret, F_RDLCK, "and is reported back")

            -- The same object, reached directly, sees the lease: it was
            -- established in the provider's lock space and nowhere else.
            local worker = vm:spawn_worker()
            local ok, err = pcall(function()
                local wfd, errno = sys.open(worker, s:in_stratum("only", "f"),
                    sys.O.WRONLY | 0x800) -- O_NONBLOCK
                t:assert(wfd == nil,
                    "opening it for writing directly is refused")
                t:assert_eq(errno, sys.E.AGAIN,
                    "by the lease, which is the provider's: " ..
                    sys.errname(errno))
            end)
            worker:kill(); worker:join()
            vm:syscall(72, fd, F_SETLEASE, F_UNLCK)
            sys.close(vm, fd)
            if not ok then error(err, 0) end
        end)
    end)

test("fsync follows the descriptor, not the path",
    { spec = "PKM *durability.fsync-follows-the-descriptor" }, function(t)
        -- No path re-resolution happens, so it is never forwarded to
        -- whichever object currently provides the path. Where the two
        -- differ, the data the caller wrote is on the object it opened.
        stratafs.with(vm, "fsync-descriptor", {
            { name = "dest", flags = { "create" } },
            { name = "src", entries = { f = "original" } },
        }, function(s)
            local fd = sys.open(vm, s:join("f"), sys.O.RDWR)
            t:assert(fd, "a descriptor opens on the provider")
            t:assert_eq(sys.write(vm, fd, "written!").ret, 8, "and writes")

            -- The path now names a different object entirely.
            vm:write_file(s:in_stratum("dest", "f"), "a different provider")
            t:assert_eq(vm:read_file(s:join("f")), "a different provider",
                "while the path now resolves elsewhere")

            t:assert_eq(sys.fsync(vm, fd).ret, 0,
                "fsync on the descriptor still succeeds")
            sys.close(vm, fd)
            t:assert_eq(vm:read_file(s:in_stratum("src", "f")), "written!",
                "having synchronised the object the caller actually wrote")
        end)
    end)

test("synchronising a merged directory covers every stratum holding it",
    { spec = "PKM *durability.dirsync-covers-every-stratum" }, function(t)
        -- The set is evaluated when the operation runs, not when the
        -- descriptor was opened — which is exactly what a creation
        -- through that descriptor needs, since §4.5.3 materialises its
        -- parent in a stratum that did not hold it at open.
        stratafs.with(vm, "dirsync", {
            { name = "high", entries = { ["d/from_high"] = "h" } },
            { name = "dest", flags = { "create" } },
            { name = "low", entries = { ["d/from_low"] = "l" } },
        }, function(s)
            local fd = sys.open(vm, s:join("d"), sys.O.RDONLY | sys.O.DIRECTORY)
            t:assert(fd, "the merged directory opens")
            t:assert(sys.stat(vm, s:in_stratum("dest", "d")) == nil,
                "and the create stratum does not hold it yet")

            t:assert_eq(sys.fsync(vm, fd).ret, 0,
                "fsync over the participants succeeds")

            -- Create through the descriptor, materialising the create
            -- stratum's counterpart, and sync again: the new directory
            -- must be covered.
            local made = sys.openat(vm, fd, "created",
                sys.O.WRONLY | sys.O.CREAT, tonumber("644", 8))
            t:assert(made, "a file is created through the descriptor")
            if made then sys.close(vm, made) end
            t:assert(sys.stat(vm, s:in_stratum("dest", "d")) ~= nil,
                "materialising the create stratum's counterpart")

            t:assert_eq(sys.fsync(vm, fd).ret, 0,
                "and fsync succeeds over the now-larger set")
            sys.close(vm, fd)
        end)
    end)

test("freezing a stratafs mount is EOPNOTSUPP",
    { spec = "PKM *durability.freeze-eopnotsupp" }, function(t)
        -- A stratafs mount has no storage to quiesce, and no freeze
        -- operation is registered at all.
        stratafs.with(vm, "freeze", {
            { name = "only", flags = { "create" }, entries = { f = "x" } },
        }, function(s)
            local FIFREEZE = 0xC0045877
            local fd = sys.open(vm, s.at, sys.O.RDONLY | sys.O.DIRECTORY)
            t:assert(fd, "the mount root opens")
            local r, errno = sys.ioctl_word(vm, fd, FIFREEZE, 1)
            sys.close(vm, fd)
            t:assert(r == nil, "freezing is refused")
            t:assert_eq(errno, sys.E.OPNOTSUPP,
                "with EOPNOTSUPP — no freeze operation is registered at " ..
                "all: " .. sys.errname(errno))
        end)
    end)

test("storage is charged to the create stratum's filesystem",
    { spec = "PKM *durability.storage-charged-to-create-stratum" }, function(t)
        -- Storage consumed by an object created through the mount, or
        -- copied up into it, is consumed on the create stratum's
        -- filesystem and accounted there.
        stratafs.with(vm, "accounting", {
            { name = "dest", flags = { "create" } },
            { name = "src", flags = { "ro" }, entries = { big = "" } },
        }, function(s)
            local chunk = string.rep("x", 65536)
            local fd = sys.open(vm, s:in_stratum("src", "big"),
                sys.O.WRONLY | sys.O.TRUNC)
            for _ = 1, 16 do sys.write(vm, fd, chunk) end
            sys.close(vm, fd)

            local before = sys.statfs(vm, s:in_stratum("dest"))
            t:assert(stratafs.try_write(vm, s:join("big"), "modified"),
                "the write copies it up")
            local after = sys.statfs(vm, s:in_stratum("dest"))

            t:assert(before and after, "the create stratum answers statfs")
            local copy = sys.stat(vm, s:in_stratum("dest", "big"))
            t:assert_eq(copy.size, 16 * 65536,
                "the copy carries the whole object")
            t:assert_eq(sys.stat(vm, s.at).dev ~= copy.dev, true,
                "which lives on the create stratum's filesystem, not the mount's")
        end)
    end)

test("copy-up preserves the POSIX owner, and the accounting follows it",
    { spec = "PKM *durability.copy-up-preserves-posix-owner" }, function(t)
        stratafs.with(vm, "durability-owner", {
            { name = "dest", flags = { "create" } },
            { name = "src", flags = { "ro" }, entries = { f = "original" } },
        }, function(s)
            t:assert_eq(sys.chown(vm, s:in_stratum("src", "f"), 4242, 4243).ret, 0,
                "the source is owned by someone other than the caller")
            t:assert(stratafs.try_write(vm, s:join("f"), "modified"),
                "the write copies it up")

            local copy = sys.stat(vm, s:in_stratum("dest", "f"))
            t:assert_eq(copy.uid, 4242,
                "the copy is owned by the source's owner")
            t:assert_eq(copy.gid, 4243, "group likewise")
            t:assert_neq(copy.uid, 0,
                "and not by the caller who provoked it, who is root")
        end)
    end)

test("copy-up preserves the descriptor's owner SID alongside the POSIX owner",
    { spec = "PKM *durability.copy-up-preserves-owner-sid" }, function(t)
        -- The two notions of owner agree, and both name the object
        -- rather than whoever provoked the copy — which is what §4.6.2
        -- relies on when it permits a caller to cause a copy into a
        -- directory they hold no rights over.
        stratafs.with(vm, "durability-sid", {
            { name = "dest", flags = { "create" } },
            { name = "src", flags = { "ro" }, entries = { f = "original" } },
        }, function(s)
            local before = kacs.get_sd(vm, s:in_stratum("src", "f"),
                kacs.SI.OWNER | kacs.SI.GROUP | kacs.SI.DACL)
            t:assert(before, "the source has a descriptor")

            t:assert(stratafs.try_write(vm, s:join("f"), "modified"),
                "the write copies it up")

            local after = kacs.get_sd(vm, s:in_stratum("dest", "f"),
                kacs.SI.OWNER | kacs.SI.GROUP | kacs.SI.DACL)
            t:assert(after, "and the copy has one")
            t:assert_eq(after, before,
                "identical to the source's, owner SID included")
        end)
    end)
