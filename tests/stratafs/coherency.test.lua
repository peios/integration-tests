-- PKM §4.4 — how uncoordinated change is observed (§4.4.1), what is
-- cached (§4.4.2: nothing), and the inode identity presented over it
-- (§4.4.3).

local sys = require("helpers.sys")
local stratafs = require("helpers.stratafs")

local vm = provium:vm("v", "kernel-only"):boot()

test("a writer that does not know stratafs exists needs no protocol",
    { spec = "PKM *coherency.no-notification-protocol" }, function(t)
        -- There is no notification machinery anywhere in the
        -- filesystem: no writer announces a change, quiesces, or
        -- participates in anything. A separate process that has never
        -- touched the mount changes a stratum and the mount follows.
        stratafs.with(vm, "no-protocol", {
            { name = "top", entries = { start = "s" } },
            { name = "bot", flags = { "create" } },
        }, function(s)
            local worker = vm:spawn_worker()
            local ok, err = pcall(function()
                local fd = sys.open(worker, s:in_stratum("top", "added"),
                    sys.O.WRONLY | sys.O.CREAT, tonumber("644", 8))
                t:assert(fd, "the other process writes into the stratum")
                sys.write(worker, fd, "from a stranger")
                sys.close(worker, fd)

                t:assert_eq(vm:read_file(s:join("added")), "from a stranger",
                    "and the mount sees it, having been told nothing")
            end)
            worker:kill(); worker:join()
            if not ok then error(err, 0) end
        end)
    end)

test("resolution depends on names and types, never on contents",
    { spec = "PKM *coherency.resolution-depends-on-names-not-contents" },
    function(t)
        stratafs.with(vm, "names-not-contents", {
            { name = "top", entries = { f = "original" } },
            { name = "bot", entries = { f = "the stratum below" } },
        }, function(s)
            -- A change to contents requires no action at all: there is
            -- no second page cache, and every data operation is
            -- forwarded to a backing file on the provider.
            vm:write_file(s:in_stratum("top", "f"), "rewritten")
            t:assert_eq(vm:read_file(s:join("f")), "rewritten",
                "a content change is observed immediately and by construction")

            -- And it does not change which stratum provides.
            local st = sys.stat(vm, s:join("f"))
            vm:write_file(s:in_stratum("top", "f"), "rewritten again")
            t:assert_eq(sys.stat(vm, s:join("f")).ino, st.ino,
                "the provider is unchanged by it")

            -- Even through a descriptor opened before the change, since
            -- the read is forwarded to the provider's own object.
            local fd = sys.open(vm, s:join("f"), sys.O.RDONLY)
            vm:write_file(s:in_stratum("top", "f"), "changed under the fd!")
            local r = vm:syscall(sys.NR.read, {
                args = { fd, 0, 64 }, bufs = { string.rep("\0", 64) }, ptrs = { 1 },
            })
            sys.close(vm, fd)
            t:assert_eq(r.out_bufs[1]:sub(1, r.ret), "changed under the fd!",
                "a descriptor reads the provider's current contents")

            -- A change to structure is the one that can move a name.
            vm:unlink(s:in_stratum("top", "f"))
            t:assert_eq(vm:read_file(s:join("f")), "the stratum below",
                "removing the entry moves the name to the next stratum")
        end)
    end)

test("a structural change is visible to the next resolution and no sooner",
    { spec = "PKM *coherency.structural-change-visible-to-next-resolution" },
    function(t)
        stratafs.with(vm, "structural", {
            { name = "top", entries = { f = "top" } },
            { name = "bot", entries = { f = "bot" } },
        }, function(s)
            -- Resolutions already completed are not revisited. Every
            -- regular-file open is detached onto a descriptor-private
            -- dentry and inode holding their own provider reference, so
            -- later masking or removal cannot reach that descriptor. It
            -- is not re-pointed and it does not fail.
            local fd = sys.open(vm, s:join("f"), sys.O.RDONLY)
            t:assert(fd, "a descriptor is open on the provider")

            vm:unlink(s:in_stratum("top", "f"))
            t:assert_eq(vm:read_file(s:join("f")), "bot",
                "a fresh resolution sees the change at once")

            local r = vm:syscall(sys.NR.read, {
                args = { fd, 0, 64 }, bufs = { string.rep("\0", 64) }, ptrs = { 1 },
            })
            sys.close(vm, fd)
            t:assert_eq(r.ret, 3, "the open descriptor still reads")
            t:assert_eq(r.out_bufs[1]:sub(1, r.ret), "top",
                "from the file it was opened on — a configuration file " ..
                "held across a package upgrade is the file it opened")
        end)
    end)

test("a stratum's directory may be replaced wholesale under a live mount",
    { spec = "PKM *coherency.stratum-replaceable-while-mounted" }, function(t)
        -- The requirement the filesystem exists to satisfy: a package
        -- transaction renames a whole tree into place with no remount
        -- and no interruption to callers.
        stratafs.with(vm, "replaceable", {
            { name = "pkg", entries = { conf = "version 1", v1only = "gone soon" } },
            { name = "base", flags = { "create" }, entries = { steady = "s" } },
        }, function(s)
            local fd = sys.open(vm, s:join("conf"), sys.O.RDONLY)
            t:assert(fd, "a caller holds the old file open")

            stratafs.populate(vm, s.root .. "/incoming",
                { conf = "version 2", v2only = "new" })
            vm:rename(s:in_stratum("pkg"), s.root .. "/outgoing")
            vm:rename(s.root .. "/incoming", s:in_stratum("pkg"))

            t:assert_eq(vm:read_file(s:join("conf")), "version 2",
                "the new tree is live immediately")
            t:assert_eq(vm:read_file(s:join("v2only")), "new",
                "in its entirety")
            t:assert(sys.stat(vm, s:join("v1only")) == nil,
                "and the old one is gone")
            t:assert_eq(vm:read_file(s:join("steady")), "s",
                "while the other strata are undisturbed")

            local r = vm:syscall(sys.NR.read, {
                args = { fd, 0, 64 }, bufs = { string.rep("\0", 64) }, ptrs = { 1 },
            })
            sys.close(vm, fd)
            t:assert_eq(r.out_bufs[1]:sub(1, r.ret), "version 1",
                "and the caller holding the old file is not interrupted")
        end)
    end)

test("every dentry but the root is invalidated on every walk",
    { spec = "PKM *coherency.revalidate.always-invalidates" }, function(t)
        -- Nothing is memoised: no version value, no directory identity,
        -- no i_version. The VFS discards the dentry and re-enters
        -- lookup on every path walk.
        stratafs.with(vm, "always-invalidate", {
            { name = "top", entries = { ["a/b/c"] = "top" } },
            { name = "bot", entries = { ["a/b/c"] = "bot" } },
        }, function(s)
            -- Walk it once so anything that could be cached, is.
            for _ = 1, 3 do
                t:assert_eq(vm:read_file(s:join("a", "b", "c")), "top",
                    "the deep path resolves")
            end

            -- Change a component at every level and check each is
            -- re-resolved, not served from a cached dentry.
            vm:unlink(s:in_stratum("top", "a/b/c"))
            t:assert_eq(vm:read_file(s:join("a", "b", "c")), "bot",
                "the leaf is re-resolved")

            vm:rename(s:in_stratum("top", "a/b"), s.root .. "/b-away")
            t:assert_eq(vm:read_file(s:join("a", "b", "c")), "bot",
                "and an intermediate directory")

            vm:rename(s:in_stratum("top", "a"), s.root .. "/a-away")
            t:assert_eq(vm:read_file(s:join("a", "b", "c")), "bot",
                "and the top one")

            -- The root dentry is the exception, and is never replaced:
            -- the mount point keeps working throughout.
            local st = sys.stat(vm, s.at)
            t:assert(st and st.is_dir, "the root is still the root")
        end)
    end)

-- Refusing RCU-walk is a property of `d_revalidate` returning -ECHILD
-- in LOOKUP_RCU, which the VFS handles by silently retrying in
-- ref-walk mode. The retry is invisible to the caller by design: the
-- syscall succeeds either way and returns nothing that distinguishes
-- them. Confirming it wants a kernel-side counter — a tracepoint or a
-- debugfs statistic — not a bigger VM.
test("RCU-walk is refused unconditionally",
    { spec = "PKM *coherency.revalidate.rcu-walk-refused",
      skip = "the ref-walk fallback is invisible to userspace: the syscall " ..
             "succeeds either way and reports nothing that distinguishes " ..
             "them. Wants a tracepoint or a counter" },
    function(t) t:fail("no userspace-visible signal") end)

test("inode numbers are allocated, not derived from the provider's",
    { spec = "PKM *inode.number-allocated-not-derived" }, function(t)
        stratafs.with(vm, "allocated-inodes", {
            { name = "top", flags = { "create" }, entries = { f = "f", d = stratafs.DIR } },
            { name = "bot", entries = { g = "g" } },
        }, function(s)
            -- The number is the mount's, and so is the device.
            local through = sys.stat(vm, s:join("f"))
            local direct = sys.stat(vm, s:in_stratum("top", "f"))
            t:assert_neq(through.ino, direct.ino,
                "the reported number is not the provider's")
            t:assert_neq(through.dev, direct.dev,
                "nor the reported device")

            -- The counter is per-mount, monotone and pre-incremented,
            -- so the first number handed out is 2 — the root's.
            t:assert_eq(sys.stat(vm, s.at).ino, 2,
                "the first number allocated is 2, and the root has it")

            -- Two names resolving to one provider object compare equal,
            -- because the map is keyed on the object and not on the
            -- path or stratum that reached it.
            local link = s:in_stratum("top", "hardlink")
            local r = vm:syscall(265, { -- linkat
                args = { sys.AT_FDCWD, 0, sys.AT_FDCWD, 0, 0 },
                bufs = { sys.cstr(s:in_stratum("top", "f")), sys.cstr(link) },
                ptrs = { 1, 3 },
            })
            t:assert_eq(r.ret, 0, "a hard link is made in the stratum: " ..
                sys.errname(r.errno))
            t:assert_eq(sys.stat(vm, s:join("hardlink")).ino, through.ino,
                "and both names report one number through the mount")
        end)
    end)

test("one directory reached through two strata compares equal",
    { spec = "PKM *inode.number-allocated-not-derived" }, function(t)
        -- The map is keyed on the provider inode object, so a directory
        -- reachable two ways is one object and gets one number.
        local s = stratafs.scenario(vm, "one-object-two-paths", {
            { name = "top", entries = { real = stratafs.DIR, ["real/x"] = "x" } },
            { name = "bot" },
        }, { mount = false })

        -- Bind the same directory in under a second name in the other
        -- stratum: two merged paths, one underlying object.
        vm:mkdir(s:in_stratum("bot", "alias"), { parents = true })
        local m = sys.mount(vm, { source = s:in_stratum("top", "real"),
            target = s:in_stratum("bot", "alias"), flags = sys.MS_BIND })
        t:assert_eq(m.ret, 0, "bind mount: " .. sys.errname(m.errno))

        stratafs.mount(vm, { at = s.at, strata = s.strata })
        local ok, err = pcall(function()
            local a = sys.stat(vm, s:join("real"))
            local b = sys.stat(vm, s:join("alias"))
            t:assert(a and b, "both paths resolve")
            t:assert_eq(a.ino, b.ino,
                "two paths to one provider object report one number")
        end)
        stratafs.umount(vm, s.at)
        sys.umount(vm, s:in_stratum("bot", "alias"))
        if not ok then error(err, 0) end
    end)

test("the mount root's number follows its live provider",
    { spec = "PKM *inode.root.follows-live-provider" }, function(t)
        -- The root inode is created once and the root dentry never
        -- replaced — `d_revalidate` returns 1 for it — but its provider
        -- is re-resolved on every use and the number follows.
        --
        -- The higher stratum has to be absent *at mount*, so it is
        -- built, moved aside, and only then mounted.
        local s = stratafs.scenario(vm, "root-follows", {
            { name = "top", flags = { "am" }, entries = { other = "t" } },
            { name = "bot", entries = { marker = "b" } },
        }, { mount = false })
        vm:rename(s:in_stratum("top"), s.root .. "/top-waiting")
        stratafs.mount(vm, { at = s.at, strata = s.strata })

        local ok, err = pcall(function()
            local first = sys.stat(vm, s.at)
            t:assert(first, "the root stats while `bot` provides it")
            t:assert_eq(sys.stat(vm, s:in_stratum("bot")).ino ~= first.ino, true,
                "with a number of the mount's own")

            -- The higher-precedence stratum root appears: the provider
            -- changes, and the number must follow it.
            vm:rename(s.root .. "/top-waiting", s:in_stratum("top"))
            t:assert_eq(vm:read_file(s:join("other")), "t",
                "the higher stratum is live")
            local second = sys.stat(vm, s.at)
            t:assert(second, "and the root stats again")
            t:assert_neq(second.ino, first.ino,
                "the root's number follows the new provider")

            -- And back again when it goes.
            vm:rename(s:in_stratum("top"), s.root .. "/top-gone")
            t:assert_eq(sys.stat(vm, s.at).ino, first.ino,
                "and follows it back to the stratum below")
        end)
        stratafs.umount(vm, s.at)
        if not ok then error(err, 0) end
    end)

test("the root's number agrees with other paths to the same provider",
    { spec = "PKM *inode.root.agrees-with-other-paths-to-its-provider" },
    function(t)
        -- Without this a root whose provider is also reachable
        -- elsewhere would report a different number from that other
        -- path: two paths naming one object, unequal — the direction
        -- that breaks hard-link detection.
        local s = stratafs.scenario(vm, "root-agrees", {
            { name = "top", entries = { x = "x" } },
            { name = "bot" },
        }, { mount = false })

        -- Reach the top stratum's root a second time, as a
        -- subdirectory of the other stratum.
        vm:mkdir(s:in_stratum("bot", "alias"), { parents = true })
        local m = sys.mount(vm, { source = s:in_stratum("top"),
            target = s:in_stratum("bot", "alias"), flags = sys.MS_BIND })
        t:assert_eq(m.ret, 0, "bind mount: " .. sys.errname(m.errno))

        stratafs.mount(vm, { at = s.at, strata = s.strata })
        local ok, err = pcall(function()
            local root = sys.stat(vm, s.at)
            local alias = sys.stat(vm, s:join("alias"))
            t:assert(root and alias, "both paths resolve")
            t:assert_eq(root.ino, alias.ino,
                "the root reports the number every other path to its " ..
                "provider reports")
        end)
        stratafs.umount(vm, s.at)
        sys.umount(vm, s:in_stratum("bot", "alias"))
        if not ok then error(err, 0) end
    end)

-- PEI-575. The root of an all-absent stack cannot be stat'd at all
-- until some stratum root has existed, so the bare counter value it is
-- supposed to keep cannot be read.
test("a root with no provider keeps the bare counter value",
    { spec = "PKM *inode.root.bare-counter-without-a-provider",
      tags = { "known-bug" } }, function(t)
        local s = stratafs.scenario(vm, "bare-counter", {
            { name = "gone", flags = { "am" } },
        }, { mount = false })
        vm:rename(s:in_stratum("gone"), s.root .. "/moved")
        stratafs.mount(vm, { at = s.at, strata = s.strata })
        local ok, err = pcall(function()
            local st, errno = sys.stat(vm, s.at)
            t:assert(st, "the root stats: " .. sys.errname(errno or 0))
            t:assert_eq(st.ino, 2,
                "and keeps the counter value allocated for it")
        end)
        stratafs.umount(vm, s.at)
        if not ok then error(err, 0) end
    end)

test("a merged directory takes its attributes from its provider",
    { spec = "PKM *inode.merged-dir.attributes-from-provider" }, function(t)
        stratafs.with(vm, "merged-attrs", {
            { name = "top", entries = { ["d/from_top"] = "t" } },
            { name = "bot", entries = { ["d/from_bot"] = "b" } },
        }, function(s)
            -- Give the two participants distinguishable attributes.
            sys.chmod(vm, s:in_stratum("top", "d"), tonumber("750", 8))
            sys.chown(vm, s:in_stratum("top", "d"), 4242, 4243)
            sys.chmod(vm, s:in_stratum("bot", "d"), tonumber("705", 8))
            sys.chown(vm, s:in_stratum("bot", "d"), 5252, 5253)

            local merged = sys.stat(vm, s:join("d"))
            local provider = sys.stat(vm, s:in_stratum("top", "d"))
            t:assert_eq(merged.perm, provider.perm,
                "the mode is the provider's, not a composite")
            t:assert_eq(merged.uid, provider.uid, "and the owner")
            t:assert_eq(merged.gid, provider.gid, "and the group")
            t:assert_eq(merged.perm, tonumber("750", 8),
                "specifically the highest-precedence participant's")
        end)
    end)

test("a merged directory's link count is forced to 1",
    { spec = "PKM *inode.merged-dir.nlink-forced-to-1" }, function(t)
        -- The true count of subdirectories spans strata and cannot be
        -- maintained, so the value carries no meaning beyond indicating
        -- that the object is a directory.
        stratafs.with(vm, "nlink", {
            { name = "top", entries = { d = stratafs.DIR, ["d/a"] = stratafs.DIR,
                                        ["d/b"] = stratafs.DIR } },
            { name = "bot", entries = { ["d/c"] = stratafs.DIR,
                                        ["d/e"] = stratafs.DIR } },
        }, function(s)
            local provider = sys.stat(vm, s:in_stratum("top", "d"))
            t:assert(provider.nlink > 1,
                "the provider's own count reflects its subdirectories (" ..
                provider.nlink .. ")")

            local merged = sys.stat(vm, s:join("d"))
            t:assert_eq(merged.nlink, 1,
                "while the merged directory reports 1")
            t:assert(merged.is_dir, "and is still recognisably a directory")

            -- The root is a merged directory too.
            t:assert_eq(sys.stat(vm, s.at).nlink, 1,
                "including the mount root")
        end)
    end)

test("a resolution never rebinds an inode to a new provider",
    { spec = "PKM *inode.never-rebound-by-resolution" }, function(t)
        -- When the provider for a path changes, a resolution of that
        -- path yields a *new* inode. Per-inode state is populated from
        -- the provider it was resolved against — including the security
        -- descriptor KACS caches on it — and is not re-derivable.
        stratafs.with(vm, "never-rebound", {
            { name = "top", flags = { "am" } },
            { name = "bot", entries = { f = "bot" } },
        }, function(s)
            local first = sys.stat(vm, s:join("f"))

            -- A higher-precedence stratum gains the name.
            stratafs.populate(vm, s:in_stratum("top"), { f = "top" })
            local second = sys.stat(vm, s:join("f"))
            t:assert_eq(vm:read_file(s:join("f")), "top", "the provider changed")
            t:assert_neq(second.ino, first.ino,
                "and the number changed with it — a new inode, not a rebind")

            -- The previous provider's entry is removed.
            vm:unlink(s:in_stratum("top", "f"))
            t:assert_eq(sys.stat(vm, s:join("f")).ino, first.ino,
                "and back to the first object's number when it goes")
        end)
    end)

test("a descriptor keeps its inode across its own copy-up",
    { spec = "PKM *inode.copy-up.descriptor-keeps-inode" }, function(t)
        -- The one case in which an inode's backing object changes. It
        -- is safe because copy-up preserves the source's security
        -- descriptor exactly, so the descriptor cached on that inode
        -- remains correct for the copy.
        stratafs.with(vm, "descriptor-keeps-inode", {
            { name = "dest", flags = { "create" } },
            { name = "src", flags = { "ro" }, entries = { f = "original" } },
        }, function(s)
            local fd = sys.open(vm, s:join("f"), sys.O.RDWR)
            t:assert(fd, "the name opens")

            local before_fd = sys.fstat(vm, fd)
            local before_path = sys.stat(vm, s:join("f"))
            t:assert_eq(before_fd.ino, before_path.ino,
                "before any copy-up, fstat and stat agree")

            local w = sys.write(vm, fd, "modified")
            t:assert_eq(w.ret, 8, "the write copies it up: " ..
                sys.errname(w.errno))

            local after_fd = sys.fstat(vm, fd)
            local after_path = sys.stat(vm, s:join("f"))
            sys.close(vm, fd)

            t:assert_eq(after_fd.ino, before_fd.ino,
                "the descriptor keeps the inode it was opened against")
            t:assert_neq(after_path.ino, after_fd.ino,
                "while a fresh resolution allocates one for the copy — " ..
                "both name the copy, and the numbers disagree (§4.8)")
            t:assert_eq(vm:read_file(s:in_stratum("dest", "f")), "modified",
                "and the copy carries the write")
            t:assert_eq(vm:read_file(s:in_stratum("src", "f")), "original",
                "leaving the source alone")
        end)
    end)

test("the identity map pins a provider for the life of the mount",
    { spec = "PKM *inode.pins-provider-until-unmount" }, function(t)
        -- The map holds a reference on every provider inode ever
        -- reached, so the object cannot be freed and its address reused
        -- while the mount lives — which is what makes the number stable
        -- across a name coming and going.
        stratafs.with(vm, "pins-provider", {
            { name = "top", entries = { f = "top" } },
            { name = "bot", flags = { "create" } },
        }, function(s)
            local first = sys.stat(vm, s:join("f"))

            -- Take the name away entirely, so nothing in the mount
            -- refers to that object any more, and give the kernel work
            -- to do that might reuse the memory.
            vm:rename(s:in_stratum("top", "f"), s.root .. "/f-aside")
            t:assert(sys.stat(vm, s:join("f")) == nil, "the name is gone")
            for i = 1, 200 do
                vm:write_file(s:in_stratum("bot", "churn" .. i), "x")
            end

            vm:rename(s.root .. "/f-aside", s:in_stratum("top", "f"))
            t:assert_eq(sys.stat(vm, s:join("f")).ino, first.ino,
                "the same provider object is still mapped to its number")
        end)
    end)
