-- PKM §4.5.3 and §4.5.4 — creating a name no stratum holds, the
-- dispositions that delete, and removal, which without whiteouts can
-- only remove an entry that is really there.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local stratafs = require("helpers.stratafs")

local vm = provium:vm("v", "kernel-only"):boot()

test("a name no stratum holds is created in the create stratum",
    { spec = "PKM *create.lands-in-create-stratum" }, function(t)
        -- All six kinds go through one helper and one path.
        stratafs.with(vm, "lands", {
            { name = "high", entries = { ["d/existing"] = "h" } },
            { name = "dest", flags = { "create" } },
            { name = "low", entries = { ["d/also"] = "l" } },
        }, function(s)
            t:assert(stratafs.try_create(vm, s:join("d", "file"), "x"),
                "a regular file is created")
            t:assert_eq(sys.mkdir(vm, s:join("d", "dir")).ret, 0, "a directory")
            t:assert_eq(sys.symlink(vm, "target", s:join("d", "link")).ret, 0,
                "a symbolic link")
            t:assert_eq(sys.mknod(vm, s:join("d", "fifo"),
                sys.S_IFIFO | tonumber("644", 8)).ret, 0, "a FIFO")
            t:assert_eq(sys.mknod(vm, s:join("d", "sock"),
                sys.S_IFSOCK | tonumber("644", 8)).ret, 0, "a socket")

            for _, name in ipairs({ "file", "dir", "link", "fifo", "sock" }) do
                t:assert(sys.stat(vm, s:in_stratum("dest", "d/" .. name),
                    { follow = false }) ~= nil,
                    "`" .. name .. "` landed in the create stratum")
                t:assert(sys.stat(vm, s:in_stratum("high", "d/" .. name),
                    { follow = false }) == nil,
                    "and not in the stratum above it")
            end
        end)
    end)

test("creation without a create stratum is EROFS",
    { spec = "PKM *create.erofs-without-create-stratum" }, function(t)
        stratafs.with(vm, "no-create-stratum", {
            { name = "a", entries = { ["d/x"] = "x" } },
            { name = "b", flags = { "ro" } },
        }, function(s)
            local ok, errno = stratafs.try_create(vm, s:join("d", "new"), "n")
            t:assert(not ok, "a file is refused")
            t:assert_eq(errno, sys.E.ROFS, sys.errname(errno))
            t:assert_eq(sys.mkdir(vm, s:join("d", "dir")).errno, sys.E.ROFS,
                "and a directory")
            t:assert_eq(sys.symlink(vm, "t", s:join("d", "link")).errno, sys.E.ROFS,
                "and a symlink")
        end)

        -- The same when it exists but is absent.
        stratafs.with(vm, "create-stratum-absent", {
            { name = "dest", flags = { "create" } },
            { name = "src", entries = { ["d/x"] = "x" } },
        }, function(s)
            vm:rename(s:in_stratum("dest"), s.root .. "/dest-away")
            local ok, errno = stratafs.try_create(vm, s:join("d", "new"), "n")
            t:assert(not ok, "an absent create stratum refuses too")
            t:assert_eq(errno, sys.E.ROFS, sys.errname(errno))
        end)
    end)

test("a non-directory blocking the create stratum's path is ENOTDIR",
    { spec = "PKM *create.parent-conflict-enotdir" }, function(t)
        -- Creation routes positionally, into the create stratum's
        -- subdirectory at the same path whether or not it exists. Where
        -- the create stratum holds that path as a file and a
        -- higher-precedence stratum provides it as a directory, the
        -- merged directory is reachable while its counterpart is
        -- blocked.
        stratafs.with(vm, "parent-conflict", {
            { name = "high", entries = { ["d/existing"] = "h" } },
            { name = "dest", flags = { "create" }, entries = { d = "in the way" } },
        }, function(s)
            t:assert_eq(vm:read_file(s:join("d", "existing")), "h",
                "the merged directory is reachable")

            local ok, errno = stratafs.try_create(vm, s:join("d", "new"), "n")
            t:assert(not ok, "but creating into it is refused")
            t:assert_eq(errno, sys.E.NOTDIR, "with ENOTDIR: " .. sys.errname(errno))
            t:assert_eq(vm:read_file(s:in_stratum("dest", "d")), "in the way",
                "and the blocking entry is neither removed nor replaced")
        end)
    end)

test("a created object's descriptor is inherited from the create-stratum parent",
    { spec = "PKM *create.descriptor-inherited-from-parent" }, function(t)
        -- A created object has no provider to inherit from, so its
        -- descriptor comes from the directory it is created in, exactly
        -- as if it had been created there directly. Ordinary creation
        -- in a create stratum inherits; copy-up preserves.
        stratafs.with(vm, "inherit-descriptor", {
            { name = "high", entries = { ["d/existing"] = "h" } },
            { name = "dest", flags = { "create" }, entries = { ["d/anchor"] = "a" } },
        }, function(s)
            -- Give the create-stratum parent a descriptor of its own,
            -- inheritable, so that what a created object inherits is
            -- distinguishable from whatever it started with.
            --
            -- The provider directory is left alone: the create *right*
            -- is checked against it (§4.6.2), so closing it down would
            -- refuse the creation before the question here arises.
            local r1 = kacs.set_sd(vm, s:in_stratum("dest", "d"),
                kacs.grant(kacs.ALL_RIGHTS))
            t:assert_eq(r1.ret, 0, "the create-stratum parent is marked: " ..
                sys.errname(r1.errno))

            t:assert(stratafs.try_create(vm, s:join("d", "through_mount"), "x"),
                "a file is created through the merged directory")
            -- ...and one created directly in the create-stratum parent,
            -- which is the thing it must be equivalent to.
            vm:write_file(s:in_stratum("dest", "d/directly"), "x")

            local through = kacs.get_sd(vm, s:in_stratum("dest", "d/through_mount"))
            local directly = kacs.get_sd(vm, s:in_stratum("dest", "d/directly"))
            t:assert(through and directly, "both have descriptors")
            t:assert_eq(through, directly,
                "creation through the mount inherits exactly as direct " ..
                "creation in the create-stratum parent does")
        end)
    end)

test("supersede is validated as a removal and then a creation",
    { spec = "PKM *create.supersede-is-removal-then-creation" }, function(t)
        -- Before anything is created the removal is validated: the
        -- target's provider must accept modification, or EROFS.
        stratafs.with(vm, "supersede-ro", {
            { name = "dest", flags = { "create" } },
            { name = "src", flags = { "ro" }, entries = { f = "original" } },
        }, function(s)
            local fd, errno = kacs.open(vm, s:join("f"),
                { disposition = kacs.DISPOSITION.SUPERSEDE })
            if fd then sys.close(vm, fd) end
            t:assert(fd == nil, "superseding a ro provider is refused")
            t:assert_eq(errno, sys.E.ROFS, "with EROFS: " .. sys.errname(errno))
            t:assert_eq(vm:read_file(s:in_stratum("src", "f")), "original",
                "and the provider is untouched")
            t:assert(sys.stat(vm, s:in_stratum("dest", "f")) == nil,
                "with nothing created either")
        end)

        -- Before anything is removed, the replacement is checked for
        -- reachability: a stratum strictly above the create stratum
        -- that also holds the name would outrank it.
        stratafs.with(vm, "supersede-shadowed", {
            { name = "above", entries = { f = "would shadow" } },
            { name = "dest", flags = { "create" }, entries = { f = "the provider" } },
        }, function(s)
            local fd, errno = kacs.open(vm, s:join("f"),
                { disposition = kacs.DISPOSITION.SUPERSEDE })
            if fd then sys.close(vm, fd) end
            t:assert(fd == nil,
                "superseding is refused where the replacement would be shadowed")
            t:assert_eq(errno, sys.E.ROFS, "with EROFS: " .. sys.errname(errno))
            t:assert_eq(vm:read_file(s:in_stratum("dest", "f")), "the provider",
                "and nothing was removed")
        end)

        -- Where both halves are sound it works, and the result is a new
        -- object rather than a modification of the old one.
        stratafs.with(vm, "supersede-ok", {
            { name = "dest", flags = { "create" }, entries = { f = "original" } },
        }, function(s)
            local before = sys.stat(vm, s:join("f"))
            local fd, status = kacs.open(vm, s:join("f"),
                { disposition = kacs.DISPOSITION.SUPERSEDE })
            t:assert(fd, "superseding succeeds: " .. sys.errname(status or 0))
            if fd then
                sys.write(vm, fd, "replacement")
                sys.close(vm, fd)
            end
            t:assert_eq(vm:read_file(s:join("f")), "replacement",
                "the name now holds the new object")
            t:assert_neq(sys.stat(vm, s:join("f")).ino, before.ino,
                "which is a different object, not the old one modified")
        end)

        -- Supersede applies to regular files only.
        stratafs.with(vm, "supersede-directory", {
            { name = "dest", flags = { "create" }, entries = { ["d/x"] = "x" } },
        }, function(s)
            local fd, errno = kacs.open(vm, s:join("d"),
                { disposition = kacs.DISPOSITION.SUPERSEDE })
            if fd then sys.close(vm, fd) end
            t:assert(fd == nil, "superseding a directory is refused")
            t:assert_eq(errno, sys.E.OPNOTSUPP,
                "with EOPNOTSUPP: " .. sys.errname(errno))
        end)
    end)

test("a deferred deletion targets the object the descriptor resolved to",
    { spec = "PKM *create.deferred-delete-targets-resolved-object" }, function(t)
        -- Not whatever provides that name at close time. Where another
        -- caller's copy-up has published a new object at that name in a
        -- higher stratum, that object is not the one being deleted.
        stratafs.with(vm, "deferred-target", {
            { name = "dest", flags = { "create" } },
            { name = "src", entries = { f = "the resolved object" } },
        }, function(s)
            local fd = kacs.open(vm, s:join("f"),
                { options = kacs.CREATE_OPT.DELETE_ON_CLOSE })
            t:assert(fd, "the descriptor is armed against the provider")

            -- A new object appears at the same name, higher up.
            vm:write_file(s:in_stratum("dest", "f"), "published later")
            t:assert_eq(vm:read_file(s:join("f")), "published later",
                "and now provides the name")

            sys.close(vm, fd)

            t:assert_eq(vm:read_file(s:in_stratum("dest", "f")), "published later",
                "the later object is left alone")
            t:assert(sys.stat(vm, s:in_stratum("src", "f")) == nil,
                "while the entry the descriptor resolved to is the one removed")
        end)
    end)

test("a deferred deletion is checked against the stratum the entry lives in",
    { spec = "PKM *create.deferred-delete-checked-against-the-providing-stratum" },
    function(t)
        -- And at deletion time rather than only at arm: arm time could
        -- not do it, because which stratum provides the entry is
        -- stratafs-internal and not visible to KACS there.
        stratafs.with(vm, "deferred-check", {
            { name = "dest", flags = { "create" } },
            { name = "src", entries = { f = "original" } },
        }, function(s)
            local fd = kacs.open(vm, s:join("f"),
                { options = kacs.CREATE_OPT.DELETE_ON_CLOSE })
            t:assert(fd, "the descriptor is armed while the stratum accepts")

            -- The providing stratum stops accepting modification after
            -- the arm. If the check were made at arm time this would
            -- not matter; it is made at deletion time, so it does.
            t:assert(sys.set_immutable(vm, s:in_stratum("src", "f"), true),
                "the entry becomes immutable under the armed descriptor")
            sys.close(vm, fd)

            local still = sys.stat(vm, s:in_stratum("src", "f"))
            sys.set_immutable(vm, s:in_stratum("src", "f"), false)
            t:assert(still ~= nil,
                "the deletion fails at close and the object is left in place")
        end)

        -- The same from the rights side, and against the directory of
        -- the stratum the entry lives in rather than the merged parent.
        stratafs.with(vm, "deferred-check-rights", {
            { name = "dest", flags = { "create" }, entries = { ["d/f"] = "x" } },
        }, function(s)
            local fd = kacs.open(vm, s:join("d", "f"),
                { options = kacs.CREATE_OPT.DELETE_ON_CLOSE })
            t:assert(fd, "the descriptor is armed while the directory permits")

            local r = kacs.set_sd(vm, s:in_stratum("dest", "d"), kacs.deny_all())
            t:assert_eq(r.ret, 0, "the stratum's directory is closed after the " ..
                "arm: " .. sys.errname(r.errno))
            sys.close(vm, fd)

            t:assert(sys.stat(vm, s:in_stratum("dest", "d/f")) ~= nil,
                "the deletion is refused, so the check was made at deletion " ..
                "time and not only at arm")
        end)
    end)

test("the arming token outlives the arm",
    { spec = "PKM *create.deferred-delete-token-outlives-the-arm" }, function(t)
        -- The token is the one that requested the deferred deletion,
        -- not the credentials of whoever closes the descriptor. The
        -- file's blob takes a reference when armed and releases it in
        -- file_release, because arm and close may be far apart and in
        -- different tasks.
        --
        -- Two observations together carry it. The sibling case below
        -- shows the check is genuinely made at deletion time — deny the
        -- directory after the arm and the deletion does not happen — so
        -- the deletion here is not succeeding because nothing was
        -- checked. And here the process drops every privilege that
        -- carries a caller past an access check between the arm and the
        -- close, and the deletion still happens.
        --
        -- Fully airtight would want the arming and closing tokens to be
        -- *different principals*, so that one is granted by the DACL
        -- and the other denied. That needs a token restricted by a SID
        -- the DACL does not name, and the layout of the restricted-SID
        -- payload is not in §3.A.
        stratafs.with(vm, "deferred-token", {
            { name = "dest", flags = { "create" }, entries = { ["d/f"] = "x" } },
        }, function(s)
            local worker = vm:spawn_worker()
            local ok, err = pcall(function()
                local fd = kacs.open(worker, s:join("d", "f"),
                    { options = kacs.CREATE_OPT.DELETE_ON_CLOSE })
                t:assert(fd, "the descriptor is armed by a privileged caller")

                -- Drop, in the same process, every privilege that lets
                -- a holder past an access check.
                local tok = worker:syscall(kacs.SYS.OPEN_SELF_TOKEN, 0,
                    kacs.TOKEN_ALL_ACCESS)
                t:assert(tok.ret >= 0, "its token opens")
                local res = worker:syscall(sys.NR.ioctl, {
                    args = { tok.ret, kacs.IOC.RESTRICT, 0 },
                    bufs = { string.pack("<I8I4I4I4I4I8i4I4",
                        kacs.BYPASS_PRIVILEGES, 0, 0, 0, 0, 0, -1, 0) },
                    ptrs = { 2 },
                })
                t:assert_eq(res.ret, 0, "a filtered token is made: " ..
                    sys.errname(res.errno))
                local filtered = string.unpack("<i4", res.out_bufs[1], 33)
                t:assert_eq(worker:syscall(sys.NR.ioctl, filtered,
                    kacs.IOC.INSTALL, 0).ret, 0,
                    "and installed process-wide before the close")

                sys.close(worker, fd)
            end)
            worker:kill(); worker:join()
            if not ok then error(err, 0) end

            t:assert(sys.stat(vm, s:in_stratum("dest", "d/f")) == nil,
                "the deletion happened under the token that armed it")
        end)
    end)

test("exclusive creation is EEXIST when any stratum holds the name",
    { spec = "PKM *create.exclusive-eexist-from-any-stratum" }, function(t)
        -- Exclusive creation asks whether the name is free, and through
        -- this mount it is not: a caller that created it anyway would
        -- find their object shadowing a file they did not know was
        -- there, or masking a whole subtree.
        stratafs.with(vm, "exclusive", {
            { name = "dest", flags = { "create" } },
            { name = "mid", entries = { from_mid = "m" } },
            { name = "low", flags = { "ro" }, entries = { from_low = "l",
                                                          shadowed_dir = stratafs.DIR } },
        }, function(s)
            for _, name in ipairs({ "from_mid", "from_low", "shadowed_dir" }) do
                local ok, errno = stratafs.try_create(vm, s:join(name), "x")
                t:assert(not ok, "`" .. name .. "` is refused exclusively")
                t:assert_eq(errno, sys.E.EXIST,
                    "with EEXIST though the create stratum does not hold it: " ..
                    sys.errname(errno))
            end

            -- And a name genuinely held by nobody is created.
            t:assert(stratafs.try_create(vm, s:join("free"), "x"),
                "a free name is created exclusively")
        end)
    end)

test("non-exclusive creation over a shadowed name is an open",
    { spec = "PKM *create.shadowed-non-exclusive-is-open" }, function(t)
        -- The merged dentry is positive, so the VFS never calls the
        -- create path: the operation is an open, and §4.5.1 routes it.
        stratafs.with(vm, "shadowed-create", {
            { name = "dest", flags = { "create" } },
            { name = "src", flags = { "ro" }, entries = { f = "original" } },
        }, function(s)
            local fd = sys.open(vm, s:join("f"),
                sys.O.RDWR | sys.O.CREAT | sys.O.TRUNC, tonumber("644", 8))
            t:assert(fd, "O_CREAT over a shadowed name opens it")
            if fd then
                t:assert_eq(sys.write(vm, fd, "written").ret, 7, "and writes")
                sys.close(vm, fd)
            end

            -- O_TRUNC is stripped from the backing open on a
            -- non-in-place route precisely so the copy-up source is not
            -- destroyed before it is read.
            t:assert_eq(vm:read_file(s:in_stratum("src", "f")), "original",
                "without destroying the copy-up source")
            t:assert_eq(vm:read_file(s:in_stratum("dest", "f")), "written",
                "and the truncation landed on the copy")
        end)

        -- A special-file provider is forwarded, with no copy-up, and
        -- opens whether or not the provider accepts modification.
        stratafs.with(vm, "shadowed-fifo", {
            { name = "dest", flags = { "create" } },
            { name = "src", flags = { "ro" } },
        }, function(s)
            t:assert_eq(sys.mknod(vm, s:in_stratum("src", "fifo"),
                sys.S_IFIFO | tonumber("666", 8)).ret, 0, "a FIFO in a ro stratum")
            local fd = sys.open(vm, s:join("fifo"),
                sys.O.RDONLY | sys.O.CREAT | 0x800, tonumber("644", 8))
            t:assert(fd, "opens with O_CREAT over it")
            if fd then sys.close(vm, fd) end
            t:assert(sys.stat(vm, s:in_stratum("dest", "fifo")) == nil,
                "with no copy-up")
        end)
    end)

test("an unnamed file is created on the create stratum",
    { spec = "PKM *create.unnamed-file-in-create-stratum" }, function(t)
        stratafs.with(vm, "unnamed", {
            { name = "high", entries = { ["d/x"] = "x" } },
            { name = "dest", flags = { "create" } },
        }, function(s)
            -- Parent materialisation applies as for a named creation.
            t:assert(sys.stat(vm, s:in_stratum("dest", "d")) == nil,
                "the create stratum holds no part of the path")

            local fd, errno = sys.open(vm, s:join("d"),
                sys.O.TMPFILE | sys.O.RDWR, tonumber("644", 8))
            t:assert(fd, "an unnamed file is created: " .. sys.errname(errno or 0))
            if fd then
                t:assert_eq(sys.write(vm, fd, "unnamed").ret, 7, "and is writable")
                local st = sys.fstat(vm, fd)
                t:assert(st and st.nlink == 0, "with no link to it")
                sys.close(vm, fd)
            end
            local dir = sys.stat(vm, s:in_stratum("dest", "d"))
            t:assert(dir and dir.is_dir,
                "and the create stratum's counterpart was materialised for it")
        end)

        stratafs.with(vm, "unnamed-erofs", {
            { name = "only", flags = { "ro" }, entries = { ["d/x"] = "x" } },
        }, function(s)
            local fd, errno = sys.open(vm, s:join("d"),
                sys.O.TMPFILE | sys.O.RDWR, tonumber("644", 8))
            if fd then sys.close(vm, fd) end
            t:assert(fd == nil, "with no create stratum it is refused")
            t:assert_eq(errno, sys.E.ROFS, "with EROFS: " .. sys.errname(errno))
        end)
    end)

test("unlinking removes the entry from the provider, or refuses",
    { spec = "PKM *remove.unlink-in-provider" }, function(t)
        stratafs.with(vm, "unlink", {
            { name = "plain", entries = { accepts = "a", shared = "high" } },
            { name = "frozen", flags = { "ro" }, entries = { refuses = "r" } },
            { name = "below", flags = { "create" }, entries = { shared = "low" } },
        }, function(s)
            -- Any stratum that accepts modification may have an entry
            -- removed from it; it need not be the create stratum.
            t:assert_eq(sys.unlink(vm, s:join("accepts")).ret, 0,
                "an entry in an accepting stratum is removed")
            t:assert(sys.stat(vm, s:in_stratum("plain", "accepts")) == nil,
                "from that stratum")

            local r = sys.unlink(vm, s:join("refuses"))
            t:assert_neq(r.ret, 0, "one in a ro stratum is not")
            t:assert_eq(r.errno, sys.E.ROFS, "with EROFS: " .. sys.errname(r.errno))

            -- Where a lower stratum also holds the name, it becomes the
            -- provider and the name remains visible. That is how a
            -- modification is undone.
            t:assert_eq(vm:read_file(s:join("shared")), "high", "the higher provides")
            t:assert_eq(sys.unlink(vm, s:join("shared")).ret, 0,
                "removing it succeeds")
            t:assert_eq(vm:read_file(s:join("shared")), "low",
                "and the name remains visible, resolving to the lower object")
        end)

        -- An immutable provider is EPERM rather than EROFS: the outer
        -- inode carries the provider's inode flags, so the VFS refuses
        -- before stratafs's own test is reached.
        stratafs.with(vm, "unlink-immutable", {
            { name = "only", flags = { "create" }, entries = { f = "x" } },
        }, function(s)
            t:assert(sys.set_immutable(vm, s:in_stratum("only", "f"), true),
                "the entry is made immutable")
            local r = sys.unlink(vm, s:join("f"))
            sys.set_immutable(vm, s:in_stratum("only", "f"), false)
            t:assert_neq(r.ret, 0, "removing it is refused")
            t:assert_eq(r.errno, sys.E.PERM,
                "with EPERM, as every filesystem returns for an immutable " ..
                "file: " .. sys.errname(r.errno))
        end)
    end)

test("rmdir requires the merged directory to be empty",
    { spec = "PKM *remove.rmdir-merged-emptiness" }, function(t)
        stratafs.with(vm, "rmdir", {
            { name = "top", flags = { "create" }, entries = { d = stratafs.DIR } },
            { name = "bot", entries = { ["d/from_bot"] = "b" } },
        }, function(s)
            -- Empty in the provider, not in another participant.
            t:assert_eq(#vm:listdir(s:in_stratum("top", "d")), 0,
                "the provider's directory is empty")
            local r = sys.unlink(vm, s:join("d"), sys.AT_REMOVEDIR)
            t:assert_neq(r.ret, 0, "but rmdir is refused")
            t:assert_eq(r.errno, sys.E.NOTEMPTY,
                "because the merged directory is not: " .. sys.errname(r.errno))

            -- With the other participant emptied too, it succeeds — and
            -- the name remains visible as a merged directory of what is
            -- left, which by the emptiness condition is empty.
            vm:unlink(s:in_stratum("bot", "d/from_bot"))
            t:assert_eq(sys.unlink(vm, s:join("d"), sys.AT_REMOVEDIR).ret, 0,
                "once every participant is empty, rmdir succeeds")
            local st = sys.stat(vm, s:join("d"))
            t:assert(st and st.is_dir,
                "and the name remains as a merged directory of the rest")
            t:assert_eq(#vm:listdir(s:join("d")), 0, "which is empty")
        end)
    end)

test("the emptiness check completes before any participant is enumerated",
    { spec = "PKM *remove.rmdir-merged-emptiness" }, function(t)
        -- Otherwise the emptiness test would be a disclosure channel: a
        -- caller who may not enumerate a protected participant could
        -- learn whether it holds anything by attempting rmdir and
        -- distinguishing ENOTEMPTY from success.
        stratafs.with(vm, "rmdir-disclosure", {
            { name = "open", flags = { "create" }, entries = { d = stratafs.DIR } },
            { name = "shut", entries = { ["d/secret"] = "s" } },
        }, function(s)
            local r = kacs.set_sd(vm, s:in_stratum("shut", "d"), kacs.deny_all())
            t:assert_eq(r.ret, 0, "one participant is closed: " ..
                sys.errname(r.errno))

            kacs.as_dacl_bound(t, vm, function(worker)
                local got = sys.unlink(worker, s:join("d"), sys.AT_REMOVEDIR)
                t:assert_neq(got.ret, 0, "rmdir is refused")
                t:assert_eq(got.errno, sys.E.ACCES,
                    "with EACCES rather than ENOTEMPTY, disclosing nothing " ..
                    "about the closed participant: " .. sys.errname(got.errno))
            end)
        end)
    end)

test("removal touches only the provider, and writes no marker anywhere",
    { spec = "PKM *remove.touches-only-the-provider" }, function(t)
        -- No entry, marker, or object is created in any stratum to
        -- suppress a lower entry; no whiteout machinery exists.
        stratafs.with(vm, "touches-provider", {
            { name = "top", flags = { "create" }, entries = { f = "top", keep = "k" } },
            { name = "mid", entries = { f = "mid" } },
            { name = "bot", entries = { f = "bot" } },
        }, function(s)
            local function snapshot(layer)
                local names = {}
                for _, e in ipairs(vm:listdir(s:in_stratum(layer))) do
                    names[#names + 1] = e.name
                end
                table.sort(names)
                return table.concat(names, ",")
            end
            local mid_before, bot_before = snapshot("mid"), snapshot("bot")

            t:assert_eq(sys.unlink(vm, s:join("f")).ret, 0, "the name is removed")

            t:assert_eq(snapshot("top"), "keep",
                "the provider lost exactly the entry removed")
            t:assert_eq(snapshot("mid"), mid_before,
                "and no other stratum gained or lost anything")
            t:assert_eq(snapshot("bot"), bot_before, "nor the one below that")
            t:assert_eq(vm:read_file(s:join("f")), "mid",
                "with the name now provided by the next stratum down")
        end)
    end)
