-- PKM §4.2.1 — the stratum stack: what it is, what fixes it, and what
-- each of the three flags means.

local sys = require("helpers.sys")
local stratafs = require("helpers.stratafs")

local vm = provium:vm("v", "kernel-only"):boot()

test("precedence varies by neither path nor operation",
    { spec = "PKM *strata.stack-fixed-and-ordered" }, function(t)
        -- The same three strata, each holding the same three names at
        -- three depths. Index 0 must win at all of them.
        local function tree(mark)
            return {
                f = mark, ["d/f"] = mark, ["d/e/f"] = mark,
                ["d"] = stratafs.DIR, ["d/e"] = stratafs.DIR,
            }
        end
        stratafs.with(vm, "fixed-order", {
            { name = "top", flags = { "create" }, entries = tree("top") },
            { name = "mid", entries = tree("mid") },
            { name = "bot", flags = { "ro" }, entries = tree("bot") },
        }, function(s)
            for _, at in ipairs({ "f", "d/f", "d/e/f" }) do
                t:assert_eq(vm:read_file(s:join(at)), "top",
                    "index 0 provides `" .. at .. "` — precedence does not vary by path")
            end

            -- Nor by which operation asks. A read, a stat and an
            -- enumeration must all be answering about the same object.
            local st = sys.stat(vm, s:join("f"))
            t:assert_eq(st.size, 3, "stat sees the provider's file")
            local via_dir = sys.stat(vm, s:join("d", "f"))
            t:assert_eq(via_dir.size, 3, "and so does one inside a merged directory")
        end)
    end)

test("the stack's order is the order it was declared in",
    { spec = "PKM *strata.stack-fixed-and-ordered" }, function(t)
        -- Nothing sorts or reorders the stack: the same directories in
        -- the other order give the other answer.
        local s = stratafs.scenario(vm, "declared-order", {
            { name = "a", flags = { "create" }, entries = { f = "a" } },
            { name = "b", entries = { f = "b" } },
        }, { mount = false })

        stratafs.mount(vm, { at = s.at, strata = s.strata })
        t:assert_eq(vm:read_file(s:join("f")), "a", "declared first, provides")
        stratafs.umount(vm, s.at)

        local reversed = { s.strata[2], s.strata[1] }
        local other = s.root .. "/mnt-reversed"
        stratafs.mount(vm, { at = other, strata = reversed })
        local got = vm:read_file(other .. "/f")
        stratafs.umount(vm, other)
        t:assert_eq(got, "b", "declared first the other way round, provides instead")
    end)

test("sixteen strata are a stack and seventeen are not",
    { spec = "PKM *strata.max-sixteen" }, function(t)
        -- STRATAFS_MAX_STRATA is 16, and the refusal is at parse time.
        local layers = {}
        for i = 1, 17 do
            local name = string.format("s%02d", i)
            layers[i] = { name = name, entries = { [name] = tostring(i) } }
        end
        layers[1].flags = { "create" }

        local s = stratafs.scenario(vm, "max-strata", layers, { mount = false })

        local sixteen = {}
        for i = 1, 16 do sixteen[i] = s.strata[i] end
        stratafs.mount(vm, { at = s.at, strata = sixteen })
        for i = 1, 16 do
            local name = string.format("s%02d", i)
            t:assert_eq(vm:read_file(s:join(name)), tostring(i),
                "all sixteen strata contribute")
        end
        stratafs.umount(vm, s.at)

        local r = stratafs.try_mount(vm, { at = s.root .. "/mnt17", strata = s.strata })
        t:assert_neq(r.ret, 0, "a seventeenth is refused")
        t:assert_eq(r.errno, sys.E.INVAL,
            "with EINVAL: " .. sys.errname(r.errno))
    end)

test("no resolution is retained between operations",
    { spec = "PKM *strata.no-cached-resolution" }, function(t)
        stratafs.with(vm, "no-cache", {
            { name = "top", flags = { "create" }, entries = { f = "top" } },
            { name = "bot", entries = { f = "bot", ["d/deep"] = "old" } },
        }, function(s)
            t:assert_eq(vm:read_file(s:join("f")), "top", "resolved once")

            -- Take the name away from its provider. Nothing told
            -- stratafs; the next lookup has to walk again to find out.
            vm:unlink(s:in_stratum("top", "f"))
            t:assert_eq(vm:read_file(s:join("f")), "bot",
                "the next lookup finds the next stratum down")

            -- The same for a directory along the path rather than the
            -- leaf: the walk is redone from the stratum's path string,
            -- so an intermediate replaced wholesale is followed too.
            t:assert_eq(vm:read_file(s:join("d", "deep")), "old", "resolved once")
            stratafs.populate(vm, s.root .. "/new-d", { deep = "new" })
            vm:rename(s:in_stratum("bot", "d"), s.root .. "/old-d")
            vm:rename(s.root .. "/new-d", s:in_stratum("bot", "d"))
            t:assert_eq(vm:read_file(s:join("d", "deep")), "new",
                "an intermediate directory replaced underneath is followed")
        end)
    end)

test("a mount inside a stratum is part of that stratum's tree",
    { spec = "PKM *mount.resolution-context-pinned" }, function(t)
        -- The stratum path is walked by an ordinary filename_lookup
        -- with no restricting flags, so mounts along it are traversed
        -- and one stratum can span several filesystems.
        stratafs.with(vm, "spans-mounts", {
            { name = "top", flags = { "create" } },
            { name = "bot", entries = { ["sub/inner"] = "direct", elsewhere = "e" } },
        }, function(s)
            t:assert_eq(vm:read_file(s:join("sub", "inner")), "direct",
                "before anything is mounted over it")

            -- Bind another directory over `sub`. Its contents are a
            -- different tree reached through the same stratum path.
            stratafs.populate(vm, s.root .. "/other", { inner = "through the bind" })
            local r = sys.mount(vm, {
                source = s.root .. "/other",
                target = s:in_stratum("bot", "sub"),
                flags = sys.MS_BIND,
            })
            t:assert_eq(r.ret, 0, "bind mounts: " .. sys.errname(r.errno))

            local ok, err = pcall(function()
                t:assert_eq(vm:read_file(s:join("sub", "inner")), "through the bind",
                    "the walk crosses the mount, so the stratum spans two filesystems")
                t:assert_eq(vm:read_file(s:join("elsewhere")), "e",
                    "and the rest of the stratum is unaffected")
            end)
            sys.umount(vm, s:in_stratum("bot", "sub"))
            if not ok then error(err, 0) end
        end)
    end)

test("nothing about a stratum's filesystem is probed at mount time",
    { spec = "PKM *strata.mount-time-checks" }, function(t)
        -- The mount-time checks are path-resolves, is-a-directory,
        -- not-a-duplicate and stacking depth (§4.2.3) — and nothing
        -- else. In particular no capability of the stratum's
        -- filesystem is examined, not even whether the create stratum
        -- can be written to.
        local s = stratafs.scenario(vm, "no-probe", {
            { name = "create", flags = { "create" } },
            { name = "lower", entries = { f = "l" } },
        }, { mount = false })

        -- A create stratum reached through a read-only mount. Mounting
        -- would have to probe it to notice.
        local frozen = s.root .. "/frozen"
        vm:mkdir(frozen, { parents = true })
        local r = sys.bind_ro(vm, s:in_stratum("create"), frozen)
        t:assert_eq(r.ret, 0, "read-only bind: " .. sys.errname(r.errno))

        local strata = { { path = frozen, flags = { "create" } }, s.strata[2] }
        local mounted = stratafs.try_mount(vm, { at = s.at, strata = strata })
        local ok, err = pcall(function()
            t:assert_eq(mounted.ret, 0,
                "the mount is admitted: " .. sys.errname(mounted.errno))
            t:assert_eq(vm:read_file(s:join("f")), "l",
                "and the stack works for everything that does not create")

            -- The unwritability is discovered when something is
            -- actually created, not before.
            local created, errno = stratafs.try_create(vm, s:join("new"), "n")
            t:assert(not created, "creating into it fails")
            t:assert_eq(errno, sys.E.ROFS,
                "at that point and not at mount: " .. sys.errname(errno))
        end)
        if mounted.ret == 0 then stratafs.umount(vm, s.at) end
        sys.umount(vm, frozen)
        if not ok then error(err, 0) end
    end)

test("every stack-wide rule collapses to EINVAL",
    { spec = "PKM *strata.stack-errors-are-einval" }, function(t)
        -- stratafs-core distinguishes five cases; the C boundary does
        -- not, and a caller cannot tell them apart.
        local s = stratafs.scenario(vm, "stack-errors", {
            { name = "a" }, { name = "b" },
        }, { mount = false })
        local a, b = s:in_stratum("a"), s:in_stratum("b")

        local cases = {
            { "an empty stack", "strata=" },
            { "more than sixteen strata", nil, 17 },
            { "an unrecognised flag", "strata=" .. a .. "+nosuchflag" },
            { "create twice", "strata=" .. a .. "+create:" .. b .. "+create" },
            { "create and ro together", "strata=" .. a .. "+create+ro" },
        }
        for i, case in ipairs(cases) do
            local data = case[2]
            if case[3] then
                local parts = {}
                for n = 1, case[3] do parts[n] = a end
                data = "strata=" .. table.concat(parts, ":")
            end
            local r = stratafs.try_mount(vm,
                { at = s.root .. "/mnt-e" .. i, data = data })
            t:assert_neq(r.ret, 0, case[1] .. " is refused")
            t:assert_eq(r.errno, sys.E.INVAL,
                case[1] .. " gives EINVAL, not " .. sys.errname(r.errno))
        end
    end)

test("without a create stratum nothing is created and nothing copied up",
    { spec = "PKM *strata.create-designates-creation-and-copy-up-destination" },
    function(t)
        stratafs.with(vm, "no-create", {
            { name = "plain", entries = { modifiable = "before" } },
            { name = "frozen", flags = { "ro" }, entries = { immutable = "before" } },
        }, function(s)
            local ok, errno = stratafs.try_create(vm, s:join("new"), "n")
            t:assert(not ok, "creation is refused")
            t:assert_eq(errno, sys.E.ROFS, "with EROFS: " .. sys.errname(errno))

            -- A modification whose provider will not take it needs a
            -- copy-up destination, and there is none.
            local wrote, werr = stratafs.try_write(vm, s:join("immutable"), "after")
            t:assert(not wrote, "a write that would need copy-up is refused")
            t:assert_eq(werr, sys.E.ROFS, "with EROFS: " .. sys.errname(werr))
            t:assert_eq(vm:read_file(s:in_stratum("frozen", "immutable")), "before",
                "and the ro stratum is untouched")

            -- But a provider that accepts modification is written in
            -- place: routing tests the provider before it looks for a
            -- create stratum at all.
            local inplace = stratafs.try_write(vm, s:join("modifiable"), "after!")
            t:assert(inplace, "a modification the provider accepts still happens")
            t:assert_eq(vm:read_file(s:in_stratum("plain", "modifiable")), "after!",
                "in place, on the providing stratum")
        end)
    end)

test("the create stratum takes creations and copy-ups wherever it sits",
    { spec = "PKM *strata.create-designates-creation-and-copy-up-destination" },
    function(t)
        -- `create` is not "the top stratum" and not "the writable one":
        -- it is where objects that exist nowhere go, and where copy-up
        -- lands. Put it below a stratum stratafs writes in place.
        stratafs.with(vm, "create-below", {
            { name = "plain", entries = { own = "p" } },
            { name = "dest", flags = { "create" } },
            { name = "source", flags = { "ro" }, entries = { copied = "original" } },
        }, function(s)
            t:assert(stratafs.try_create(vm, s:join("new"), "n"),
                "creation succeeds")
            t:assert_eq(vm:read_file(s:in_stratum("dest", "new")), "n",
                "into the create stratum, though it is not the highest")
            t:assert(sys.stat(vm, s:in_stratum("plain", "new")) == nil,
                "and not into the stratum above it")

            t:assert(stratafs.try_write(vm, s:join("copied"), "modified"),
                "a write against a ro provider succeeds")
            t:assert_eq(vm:read_file(s:in_stratum("dest", "copied")), "modified",
                "by copy-up into the create stratum")
            t:assert_eq(vm:read_file(s:in_stratum("source", "copied")), "original",
                "leaving the provider alone")
        end)
    end)

-- `known-bug` marks a case that states the specified behaviour and
-- currently fails against the kernel, with the ticket named beside it.
-- CI runs `--no-tag known-bug`; a local run leaves it red so it stays
-- visible to whoever is working in the area.
test("each term of the accepts-modification predicate refuses on its own",
    { spec = "PKM *strata.ro-is-independent-of-filesystem",
      tags = { "known-bug" } }, function(t) -- PEI-574
        -- Three terms: the `ro` flag, the provider's mount being
        -- read-only, and the provider's inode being immutable. Any one
        -- of them makes the stratum decline the modification, which
        -- with a create stratum present means a copy-up.
        local s = stratafs.scenario(vm, "accepts-modification", {
            { name = "dest", flags = { "create" } },
            { name = "flagged", flags = { "ro" }, entries = { by_flag = "original" } },
            { name = "readonly", entries = { by_mount = "original" } },
            { name = "plain", entries = { by_inode = "original", by_mode = "original" } },
        }, { mount = false })

        -- Term two: an ordinary stratum, no `ro`, reached through a
        -- read-only bind. The filesystem underneath is writable.
        local frozen = s.root .. "/frozen-mount"
        vm:mkdir(frozen, { parents = true })
        local r = sys.bind_ro(vm, s:in_stratum("readonly"), frozen)
        t:assert_eq(r.ret, 0, "read-only bind: " .. sys.errname(r.errno))

        -- The note: unwritable mode bits are *not* one of the terms.
        vm:syscall(268, { -- fchmodat
            args = { sys.AT_FDCWD, 0, tonumber("444", 8), 0 },
            bufs = { sys.cstr(s:in_stratum("plain", "by_mode")) },
            ptrs = { 1 },
        })

        local strata = {
            s.strata[1], s.strata[2],
            { path = frozen }, s.strata[4],
        }
        stratafs.mount(vm, { at = s.at, strata = strata })
        local ok, err = pcall(function()
            local function copies_up(name, stratum, why)
                t:assert(stratafs.try_write(vm, s:join(name), "modified"),
                    why .. ": the write succeeds")
                t:assert_eq(vm:read_file(s:in_stratum("dest", name)), "modified",
                    why .. ": by copy-up into the create stratum")
                t:assert_eq(vm:read_file(stratum), "original",
                    why .. ": leaving the provider unmodified")
            end
            copies_up("by_flag", s:in_stratum("flagged", "by_flag"),
                "the ro flag")
            copies_up("by_mount", s:in_stratum("readonly", "by_mount"),
                "a read-only provider mount")

            -- Term three has to be reached with the file already open.
            -- A stratafs inode carries its provider's inode flags, so
            -- the VFS refuses to open an immutable name for writing
            -- before stratafs is asked anything. Routing is decided at
            -- each write and not at the open (§4.5.1), so setting the
            -- flag in between is what puts the term in play.
            local provider = s:in_stratum("plain", "by_inode")
            local fd = sys.open(vm, s:join("by_inode"), sys.O.WRONLY)
            t:assert(fd, "the name opens for writing while it is mutable")
            t:assert(sys.set_immutable(vm, provider, true),
                "the provider inode is made immutable under the open file")
            local wrote = sys.write(vm, fd, "modified")
            sys.close(vm, fd)
            t:assert_eq(wrote.ret, 8,
                "an immutable provider inode: the write succeeds: " ..
                sys.errname(wrote.errno))
            t:assert_eq(vm:read_file(s:in_stratum("dest", "by_inode")), "modified",
                "an immutable provider inode: by copy-up into the create stratum")
            t:assert_eq(vm:read_file(provider), "original",
                "an immutable provider inode: leaving the provider unmodified")

            -- The note again, from the other end: mode bits route
            -- nothing. The open is refused for want of write
            -- permission, and nothing is copied up.
            local ok2, errno, stage = stratafs.try_write(vm, s:join("by_mode"), "modified")
            t:assert(not ok2, "an unwritable mode is refused")
            t:assert_eq(errno, sys.E.ACCES,
                "for want of permission at " .. stage .. ", not " .. sys.errname(errno))
            t:assert(sys.stat(vm, s:in_stratum("dest", "by_mode")) == nil,
                "so nothing was copied up on its account")
        end)
        stratafs.umount(vm, s.at)
        sys.set_immutable(vm, s:in_stratum("plain", "by_inode"), false)
        sys.umount(vm, frozen)
        if not ok then error(err, 0) end
    end)

test("am decides whether an absent stratum may be mounted, and nothing else",
    { spec = "PKM *strata.am-governs-mount-time-only" }, function(t)
        local s = stratafs.scenario(vm, "am-flag", {
            { name = "present", flags = { "create" }, entries = { p = "p" } },
        }, { mount = false })
        local missing = s.root .. "/not-there"

        local without = stratafs.try_mount(vm, {
            at = s.root .. "/mnt-noam",
            strata = { s.strata[1], { path = missing } },
        })
        t:assert_neq(without.ret, 0, "an absent stratum without am is refused")
        t:assert_eq(without.errno, sys.E.NOENT,
            "with ENOENT: " .. sys.errname(without.errno))

        local with = stratafs.try_mount(vm, {
            at = s.at,
            strata = { s.strata[1], { path = missing, flags = { "am" } } },
        })
        t:assert_eq(with.ret, 0,
            "with am it is admitted: " .. sys.errname(with.errno))
        stratafs.umount(vm, s.at)
    end)

test("a stratum that goes away is skipped the same with or without am",
    { spec = "PKM *strata.am-governs-mount-time-only" }, function(t)
        -- The flag governs mount time only; the resolver never reads
        -- it. Two identical stacks differing only in `am`, both with
        -- their lower stratum removed after mounting, must behave
        -- identically.
        local function build(name, flags)
            local s = stratafs.scenario(vm, name, {
                { name = "top", flags = { "create" }, entries = { shared = "top" } },
                { name = "bot", flags = flags,
                  entries = { shared = "bot", only_bot = "b" } },
            })
            return s
        end
        local without, with = build("am-runtime-no", nil), build("am-runtime-yes", { "am" })

        local ok, err = pcall(function()
            for _, s in ipairs({ without, with }) do
                t:assert_eq(vm:read_file(s:join("only_bot")), "b",
                    "the lower stratum contributes while it is there")
                vm:rename(s:in_stratum("bot"), s.root .. "/moved-away")

                t:assert(sys.stat(vm, s:join("only_bot")) == nil,
                    "once gone, what only it held is gone")
                t:assert_eq(vm:read_file(s:join("shared")), "top",
                    "and the rest of the stack carries on")
                local created, errno = stratafs.try_create(vm, s:join("still-works"), "y")
                t:assert(created, "with the mount fully usable: " .. sys.errname(errno or 0))
            end
        end)
        without.release()
        with.release()
        if not ok then error(err, 0) end
    end)
