-- PKM §4.5.2 — replicating an object into the create stratum: parents,
-- what is replicated, staleness, staging and atomicity.
--
-- The two ownership cases already have a file of their own
-- (copy-up.test.lua); this covers the rest of the section.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local stratafs = require("helpers.stratafs")

local vm = provium:vm("v", "kernel-only"):boot()

-- §4.A: the staging attribute and its marker.
local STAGING_XATTR = "security.peios.stratafs_staging"
local STAGE_MAGIC, STAGE_VERSION, STAGE_SIZE = 0x53544731, 1, 24

local function marker(magic, version, size, boot_cookie, mount_cookie)
    return string.pack("<I4I2I2I8I8", magic or STAGE_MAGIC,
        version or STAGE_VERSION, size or STAGE_SIZE,
        boot_cookie or 0xDEADBEEFCAFEF00D, mount_cookie or 0x0123456789ABCDEF)
end

--- A provider that will not accept modification, and a create stratum
--- that outranks it.
local function copying(t, name, body, entries)
    stratafs.with(vm, name, {
        { name = "dest", flags = { "create" } },
        { name = "src", flags = { "ro" }, entries = entries or { f = "original" } },
    }, body)
end

test("copy-up replicates into the create stratum at the same relative path",
    { spec = "PKM *copy-up.replicates-into-create-stratum" }, function(t)
        copying(t, "replicates", function(s)
            t:assert(stratafs.try_write(vm, s:join("deep", "nested", "f"), "modified"),
                "a write deep in the tree succeeds")
            t:assert_eq(vm:read_file(s:in_stratum("dest", "deep/nested/f")),
                "modified",
                "and the copy is at the same path relative to the mount root")
            t:assert_eq(vm:read_file(s:in_stratum("src", "deep/nested/f")),
                "original",
                "with the provider unmodified")
        end, { ["deep/nested/f"] = "original" })
    end)

test("missing parent directories are materialised, empty",
    { spec = "PKM *copy-up.materialises-missing-parents" }, function(t)
        copying(t, "parents", function(s)
            -- Give the provider's directories distinguishable modes, so
            -- the materialised ones can be checked against them.
            sys.chmod(vm, s:in_stratum("src", "a"), tonumber("711", 8))
            sys.chmod(vm, s:in_stratum("src", "a/b"), tonumber("750", 8))

            t:assert(sys.stat(vm, s:in_stratum("dest", "a")) == nil,
                "the create stratum holds none of the path")
            t:assert(stratafs.try_write(vm, s:join("a", "b", "f"), "modified"),
                "the write succeeds")

            for path, mode in pairs({ a = "711", ["a/b"] = "750" }) do
                local st = sys.stat(vm, s:in_stratum("dest", path))
                t:assert(st and st.is_dir, "`" .. path .. "` was materialised")
                t:assert_eq(st.perm, tonumber(mode, 8),
                    "with the merged provider directory's mode")
            end

            -- Contents are not copied: the directories exist to hold
            -- the copied object, and what the lower strata hold is
            -- still reached by merging.
            local names = {}
            for _, e in ipairs(vm:listdir(s:in_stratum("dest", "a/b"))) do
                names[e.name] = true
            end
            t:assert(names.f, "the copied object is there")
            t:assert(not names.sibling,
                "and nothing else from the provider was copied with it")
            t:assert_eq(vm:read_file(s:join("a", "b", "sibling")), "untouched",
                "while the sibling is still reached by merging")
        end, { ["a/b/f"] = "original", ["a/b/sibling"] = "untouched" })
    end)

test("a non-directory blocking a parent path is ENOTDIR, and is not removed",
    { spec = "PKM *copy-up.materialises-missing-parents" }, function(t)
        copying(t, "parent-blocked", function(s)
            -- The create stratum holds `a` as a regular file, where the
            -- copy-up needs a directory.
            vm:write_file(s:in_stratum("dest", "a"), "in the way")

            local wrote, errno = stratafs.try_write(vm, s:join("a", "f"), "modified")
            t:assert(not wrote, "the write is refused")
            t:assert_eq(errno, sys.E.NOTDIR, "with ENOTDIR: " .. sys.errname(errno))
            t:assert_eq(vm:read_file(s:in_stratum("dest", "a")), "in the way",
                "and the blocking entry is neither removed nor replaced")
        end, { ["a/f"] = "original" })
    end)

test("a regular file is copied with its contents and mode",
    { spec = "PKM *copy-up.result.regular-file" }, function(t)
        copying(t, "result-regular", function(s)
            sys.chmod(vm, s:in_stratum("src", "f"), tonumber("640", 8))
            t:assert(stratafs.try_write(vm, s:join("f"), "MODIFIED"),
                "the write succeeds")
            local copy = sys.stat(vm, s:in_stratum("dest", "f"))
            t:assert(copy and copy.is_file, "a regular file appears")
            t:assert_eq(copy.perm, tonumber("640", 8), "with the same mode")
            t:assert_eq(vm:read_file(s:in_stratum("dest", "f")), "MODIFIED",
                "and the contents, as modified")
        end, { f = "original" })
    end)

test("a symbolic link is copied with the same target",
    { spec = "PKM *copy-up.result.symlink" }, function(t)
        copying(t, "result-symlink", function(s)
            -- Setting an attribute on the link is a modification of the
            -- object itself, which routes and copies it up.
            local r = sys.chown(vm, s:join("link"), 4242, 4243, { follow = false })
            t:assert_eq(r.ret, 0, "a chown on the link succeeds: " ..
                sys.errname(r.errno))

            local copy = sys.stat(vm, s:in_stratum("dest", "link"),
                { follow = false })
            t:assert(copy and copy.is_symlink, "a symlink appears in the copy")
            t:assert_eq(sys.readlink(vm, s:in_stratum("dest", "link")),
                "../somewhere/else", "with the same target, verbatim")
        end, { link = stratafs.symlink("../somewhere/else") })
    end)

test("a directory is copied empty, with the same mode",
    { spec = "PKM *copy-up.result.directory" }, function(t)
        copying(t, "result-directory", function(s)
            sys.chmod(vm, s:in_stratum("src", "d"), tonumber("751", 8))
            local r = sys.chown(vm, s:join("d"), 4242, 4243)
            t:assert_eq(r.ret, 0, "a chown on the directory succeeds: " ..
                sys.errname(r.errno))

            local copy = sys.stat(vm, s:in_stratum("dest", "d"))
            t:assert(copy and copy.is_dir, "a directory appears in the copy")
            t:assert_eq(copy.perm, tonumber("751", 8), "with the same mode")
            t:assert_eq(#vm:listdir(s:in_stratum("dest", "d")), 0,
                "and empty — contents are not copied")
            t:assert_eq(vm:read_file(s:join("d", "inside")), "still merged",
                "while its contents are still reached by merging")
        end, { ["d/inside"] = "still merged" })
    end)

test("anything not a regular file, directory or symlink is refused",
    { spec = "PKM *copy-up.non-copyable-refused" }, function(t)
        copying(t, "non-copyable", function(s)
            local r = sys.mknod(vm, s:in_stratum("src", "fifo"),
                sys.S_IFIFO | tonumber("666", 8))
            t:assert_eq(r.ret, 0, "a FIFO is made in the provider: " ..
                sys.errname(r.errno))

            local ch = sys.chmod(vm, s:join("fifo"), tonumber("600", 8))
            t:assert_neq(ch.ret, 0, "modifying it is refused")
            t:assert_eq(ch.errno, sys.E.ROFS,
                "with EROFS, before a copy-up begins: " .. sys.errname(ch.errno))
            t:assert(sys.stat(vm, s:in_stratum("dest", "fifo")) == nil,
                "and nothing was copied")
        end, { placeholder = "x" })
    end)

test("extended attributes are copied, with the documented exclusions",
    { spec = "PKM *copy-up.xattrs-copied-with-exclusions" }, function(t)
        copying(t, "xattrs", function(s)
            local set = sys.setxattr(vm, s:in_stratum("src", "f"),
                "user.carried", "value")
            t:assert_eq(set.ret, 0, "the provider carries an attribute: " ..
                sys.errname(set.errno))

            t:assert(stratafs.try_write(vm, s:join("f"), "modified"),
                "the write copies it up")
            t:assert_eq(sys.getxattr(vm, s:in_stratum("dest", "f"), "user.carried"),
                "value", "and the attribute came with it")

            -- The staging marker attribute is one of the exclusions,
            -- and is removed after publication in any case.
            local staging = sys.getxattr(vm, s:in_stratum("dest", "f"),
                STAGING_XATTR)
            t:assert(staging == nil,
                "while the staging marker is not on the published copy")
        end)
    end)

test("modification times are preserved, access and change times are not",
    { spec = "PKM *copy-up.mtime-preserved" }, function(t)
        copying(t, "mtime", function(s)
            sys.utimes(vm, s:in_stratum("src", "f"), 1000000)
            local before = sys.stat(vm, s:in_stratum("src", "f"))

            -- A chown routes without touching the contents, so the
            -- mtime that survives is the source's and not the copy's.
            local r = sys.chown(vm, s:join("f"), 4242, 4243)
            t:assert_eq(r.ret, 0, "the chown succeeds: " .. sys.errname(r.errno))

            local after = sys.stat(vm, s:in_stratum("dest", "f"))
            t:assert_eq(after.mtime, before.mtime,
                "the copy carries the source's modification time")
        end)

        -- Symbolic links included. Everything here has to avoid
        -- following the link: its target does not exist.
        copying(t, "mtime-symlink", function(s)
            sys.utimes(vm, s:in_stratum("src", "link"), 1000000,
                { follow = false })
            local before = sys.stat(vm, s:in_stratum("src", "link"),
                { follow = false })
            local r = sys.chown(vm, s:join("link"), 4242, 4243, { follow = false })
            t:assert_eq(r.ret, 0, "the chown succeeds: " .. sys.errname(r.errno))
            local copy = sys.stat(vm, s:in_stratum("dest", "link"),
                { follow = false })
            t:assert(copy, "the link is copied")
            t:assert_eq(copy.mtime, before.mtime,
                "a symlink's modification time is preserved too")
        end, { link = stratafs.symlink("target") })
    end)

test("the mode is carried across, except for a symbolic link",
    { spec = "PKM *copy-up.mode-preserved-except-symlinks" }, function(t)
        copying(t, "mode-preserved", function(s)
            for name, mode in pairs({ f = "705", d = "751" }) do
                sys.chmod(vm, s:in_stratum("src", name), tonumber(mode, 8))
            end
            t:assert(stratafs.try_write(vm, s:join("f"), "modified"),
                "the file is copied up")
            sys.chown(vm, s:join("d"), 4242, 4243)

            t:assert_eq(sys.stat(vm, s:in_stratum("dest", "f")).perm,
                tonumber("705", 8), "a regular file keeps its mode")
            t:assert_eq(sys.stat(vm, s:in_stratum("dest", "d")).perm,
                tonumber("751", 8), "and so does a directory")

            -- A symlink's mode is fixed by the VFS and not the
            -- caller's to set, so it is whatever the VFS makes it.
            sys.chown(vm, s:join("link"), 4242, 4243, { follow = false })
            local copy = sys.stat(vm, s:in_stratum("dest", "link"),
                { follow = false })
            t:assert(copy and copy.is_symlink, "the link is copied")
            t:assert_eq(copy.perm, tonumber("777", 8),
                "with the mode the VFS gives every symlink")
        end, { f = "original", ["d/x"] = "x", link = stratafs.symlink("t") })
    end)

test("access and change times are not preserved",
    { spec = "PKM *copy-up.atime-ctime-not-preserved" }, function(t)
        copying(t, "atime-ctime", function(s)
            -- Push the source's times well into the past. The copy-up
            -- is provoked by a chown rather than a write, so nothing
            -- about the operation itself sets a timestamp on the copy.
            sys.utimes(vm, s:in_stratum("src", "f"), 1000000)
            local source = sys.stat(vm, s:in_stratum("src", "f"))
            t:assert_eq(source.mtime, 1000000, "the source's times are old")

            local r = sys.chown(vm, s:join("f"), 4242, 4243)
            t:assert_eq(r.ret, 0, "the chown copies it up: " ..
                sys.errname(r.errno))

            local copy = sys.stat(vm, s:in_stratum("dest", "f"))
            t:assert(copy, "the copy exists")
            t:assert_eq(copy.mtime, source.mtime,
                "the modification time is preserved")
            -- Neither of the others was carried across: both stand at
            -- the moment the copy was made, far past the preserved
            -- modification time. (utimensat moves ctime to now as a
            -- side effect, so the source's own ctime is no baseline.)
            t:assert(copy.atime > copy.mtime,
                "the access time is not preserved (" .. copy.atime ..
                " against a preserved mtime of " .. copy.mtime .. ")")
            t:assert(copy.ctime > copy.mtime,
                "and neither is the change time (" .. copy.ctime .. ")")
        end)
    end)

test("the chown runs under the mount's credential, not the caller's",
    { spec = "PKM *copy-up.ownership-chown-runs-under-resolution-credential" },
    function(t)
        -- Setting another uid needs authority the caller does not have,
        -- so the chown that preserves ownership runs under the same
        -- resolution context stratafs uses to reach providers. A caller
        -- with no privileges at all must still produce a copy owned by
        -- the source's owner.
        copying(t, "chown-credential", function(s)
            local ch = sys.chown(vm, s:in_stratum("src", "f"), 4242, 4243)
            t:assert_eq(ch.ret, 0, "the source is owned by someone else: " ..
                sys.errname(ch.errno))
            local r = kacs.set_sd(vm, s:in_stratum("src", "f"),
                kacs.grant(kacs.ALL_RIGHTS))
            t:assert_eq(r.ret, 0, "and grants the caller access: " ..
                sys.errname(r.errno))

            kacs.as_dacl_bound(t, vm, function(worker)
                local fd = sys.open(worker, s:join("f"), sys.O.RDWR)
                t:assert(fd, "the unprivileged caller opens it")
                local w = sys.write(worker, fd, "modified")
                sys.close(worker, fd)
                t:assert_eq(w.ret, 8, "and writes, copying up: " ..
                    sys.errname(w.errno))
            end)

            local copy = sys.stat(vm, s:in_stratum("dest", "f"))
            t:assert(copy, "the copy exists")
            t:assert_eq(copy.uid, 4242,
                "owned by the source's owner, not by whoever provoked it")
            t:assert_eq(copy.gid, 4243, "group likewise")
        end)
    end)

test("hard links are not preserved",
    { spec = "PKM *copy-up.hard-links-not-preserved" }, function(t)
        copying(t, "hard-links", function(s)
            local r = sys.link(vm, s:in_stratum("src", "f"),
                s:in_stratum("src", "other_name"))
            t:assert_eq(r.ret, 0, "the provider has two links: " ..
                sys.errname(r.errno))
            t:assert_eq(sys.stat(vm, s:in_stratum("src", "f")).nlink, 2,
                "confirmed by its link count")

            t:assert(stratafs.try_write(vm, s:join("f"), "modified"),
                "one of them is written through the mount")

            local copy = sys.stat(vm, s:in_stratum("dest", "f"))
            t:assert_eq(copy.nlink, 1,
                "the copy is a single independent object")
            t:assert_eq(vm:read_file(s:join("other_name")), "original",
                "and the other link still refers to the original")
            t:assert_eq(vm:read_file(s:in_stratum("src", "f")), "original",
                "which is unmodified")
        end)
    end)

test("a descriptor whose object is no longer the provider fails ESTALE",
    { spec = "PKM *copy-up.source-must-still-be-provider" }, function(t)
        -- Every descriptor other than the one that caused a copy-up
        -- still refers to the original object, so a second descriptor
        -- opened before the copy-up meets this rule the first time it
        -- writes. A caller has to be prepared for a write to fail
        -- ESTALE on a descriptor that was valid when it was opened and
        -- has done nothing wrong (§4.8).
        copying(t, "estale", function(s)
            local first = sys.open(vm, s:join("f"), sys.O.RDWR)
            local second = sys.open(vm, s:join("f"), sys.O.RDWR)
            t:assert(first and second, "two descriptors on the original")

            t:assert_eq(sys.write(vm, first, "modified").ret, 8,
                "the first writes, copying up")

            local w = sys.write(vm, second, "second!!")
            sys.close(vm, first)
            sys.close(vm, second)
            t:assert_neq(w.ret, 8, "the second's write does not succeed")
            t:assert_eq(w.errno, sys.E.STALE,
                "its object is no longer the provider: " .. sys.errname(w.errno))
        end)
    end)

test("orphan recovery leaves alone what it cannot prove is an orphan",
    { spec = "PKM *copy-up.orphan-recovery-checks-marker" }, function(t)
        -- Two mounts may share a create stratum, so an unqualified
        -- cleanup would have each new mount destroy the other's
        -- copy-up in flight. A staged name alone is not proof of
        -- ownership: an entry whose marker is missing, short, or
        -- carries the wrong magic, version or size is left alone.
        --
        -- Only the leave-alone half is reachable from userspace. The
        -- marker lives in `security.peios.stratafs_staging`, which is
        -- reserved (§4.7) and refuses a write with EPERM, so a *valid*
        -- marker naming a dead mount cannot be forged and the
        -- removal half cannot be provoked.
        local s = stratafs.scenario(vm, "orphans", {
            { name = "dest", flags = { "create" } },
            { name = "src", flags = { "ro" }, entries = { f = "original" } },
        }, { mount = false })

        -- Confirm the reservation rather than assuming it, since it is
        -- the reason the other half is missing.
        vm:write_file(s:in_stratum("dest", ".stratafs-stage-probe"), "partial")
        local reserved = sys.setxattr(vm, s:in_stratum("dest", ".stratafs-stage-probe"),
            STAGING_XATTR, marker())
        t:assert_neq(reserved.ret, 0, "the staging attribute refuses a write")
        t:assert_eq(reserved.errno, sys.E.PERM,
            "with EPERM: " .. sys.errname(reserved.errno))

        local kept = { ".stratafs-stage-probe", ".stratafs-stage-nomarker" }
        vm:write_file(s:in_stratum("dest", ".stratafs-stage-nomarker"), "partial")

        -- Mounting, opening a directory and looking a staging-prefixed
        -- name up are three of the five triggers for the scan.
        stratafs.mount(vm, { at = s.at, strata = s.strata })
        local ok, err = pcall(function()
            local fd = sys.open(vm, s.at, sys.O.RDONLY | sys.O.DIRECTORY)
            if fd then sys.close(vm, fd) end
            for _, name in ipairs(kept) do sys.stat(vm, s:join(name)) end

            for _, name in ipairs(kept) do
                t:assert(sys.stat(vm, s:in_stratum("dest", name)) ~= nil,
                    "`" .. name .. "` carries no valid marker and is left alone")
            end

            -- And none of them is reachable through the mount, whatever
            -- recovery made of them.
            for _, name in ipairs(kept) do
                local st = sys.stat(vm, s:join(name))
                t:assert(st ~= nil,
                    "an entry recovery declined to remove resolves normally, " ..
                    "since it is not on this mount's staging list")
            end
        end)
        stratafs.umount(vm, s.at)
        if not ok then error(err, 0) end
    end)

test("a published copy is independent of its source",
    { spec = "PKM *copy-up.no-source-snapshot" }, function(t)
        -- Nothing blocks waiting for a quiescent source and nothing
        -- fails a copy-up merely because the source is being written.
        -- Once published, later modifications to the source are not
        -- reflected in the copy and are not visible through the mount
        -- for as long as the copy provides the name.
        copying(t, "independent", function(s)
            t:assert(stratafs.try_write(vm, s:join("f"), "modified"),
                "the write copies it up")
            t:assert_eq(vm:read_file(s:join("f")), "modified",
                "and the copy now provides the name")

            vm:write_file(s:in_stratum("src", "f"), "the source moved on")
            t:assert_eq(vm:read_file(s:join("f")), "modified",
                "a later change to the source is not reflected in the copy")
            t:assert_eq(vm:read_file(s:in_stratum("dest", "f")), "modified",
                "nor visible through the mount while the copy provides")
        end)
    end)

-- Two of §4.5.2's claims need a copy-up held open or an attribute write
-- made to fail from outside, and neither is reachable from userspace.
test("a copy-up is never observable in a partial state",
    { spec = "PKM *copy-up.never-partially-observable",
      skip = "needs a copy-up held open mid-flight. A regular file stages " ..
             "as an anonymous tmpfile with no directory entry, and the " ..
             "named path publishes within microseconds; see the note in " ..
             "lookup.test.lua. Wants a kernel-side delay hook" },
    function(t) t:fail("no way to hold a copy-up open") end)

test("any extended-attribute failure aborts the copy-up with EIO",
    { spec = "PKM *copy-up.xattr-failure-aborts-with-eio" }, function(t)
        -- No attribute is silently discarded. Any per-attribute failure
        -- aborts the copy-up, as does a listing that fails or exceeds
        -- XATTR_LIST_MAX; in every case the error reported is EIO,
        -- whatever the underlying one was.
        --
        -- The reachable half is the listing bound: XATTR_LIST_MAX is
        -- 64 KiB, and enough attributes with long enough names put the
        -- source's listing past it.
        copying(t, "xattr-failure", function(s)
            local provider = s:in_stratum("src", "f")
            local long = string.rep("k", 200)
            for i = 1, 400 do
                local r = sys.setxattr(vm, provider,
                    "user." .. long .. string.format("%03d", i), "v")
                t:assert_eq(r.ret, 0, "attribute " .. i .. " is set: " ..
                    sys.errname(r.errno))
            end

            local size = vm:syscall(sys.NR.listxattr, {
                args = { 0, 0, 0 }, bufs = { sys.cstr(provider) }, ptrs = { 0 },
            })
            t:assert(size.ret > 65536,
                "the source's attribute listing exceeds XATTR_LIST_MAX (" ..
                size.ret .. " bytes)")

            local ok, errno = stratafs.try_write(vm, s:join("f"), "modified")
            t:assert(not ok, "the copy-up is aborted")
            t:assert_eq(errno, sys.E.IO,
                "and reported as EIO, whatever the underlying error was: " ..
                sys.errname(errno))

            -- Nothing published: an object whose attributes could not
            -- be preserved is never published.
            t:assert(sys.stat(vm, s:in_stratum("dest", "f")) == nil,
                "with no partial copy left in the create stratum")
            t:assert_eq(vm:read_file(s:in_stratum("src", "f")), "original",
                "and the source untouched")
        end)
    end)

test("a copy is accounted to the owner it preserved",
    { spec = "PKM *copy-up.accounted-to-preserved-owner",
      skip = "quota accounting keys on the POSIX owner, and tmpfs in this " ..
             "VM has no quota support to observe it through. The ownership " ..
             "half is covered by copy-up.posix-ownership-preserved" },
    function(t) t:fail("no quota accounting available") end)
