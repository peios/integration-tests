-- PKM §4.3.1 — resolving one name in one directory: the provider, what
-- ancestors contribute, independence from the caller, reaching the
-- object, staged names and recursion.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local stratafs = require("helpers.stratafs")

local vm = provium:vm("v", "kernel-only"):boot()

test("the provider is the highest-precedence stratum holding the name",
    { spec = "PKM *resolution.provider-is-highest-stratum" }, function(t)
        stratafs.with(vm, "provider", {
            { name = "s0", entries = { all = "s0" } },
            { name = "s1", entries = { all = "s1", from1 = "s1", lower = "s1" } },
            { name = "s2", entries = { all = "s2", from1 = "s2", lower = "s2" } },
        }, function(s)
            t:assert_eq(vm:read_file(s:join("all")), "s0",
                "the first stratum holding it provides")
            t:assert_eq(vm:read_file(s:join("from1")), "s1",
                "and where it does not, the next one down does")

            -- No stratum holds it: a negative dentry, and ENOENT.
            local st, errno = sys.stat(vm, s:join("nowhere"))
            t:assert(st == nil, "a name no stratum holds does not resolve")
            t:assert_eq(errno, sys.E.NOENT, "with ENOENT: " .. sys.errname(errno))
        end)
    end)

test("a stratum whose walk fails ENOENT or ENOTDIR is passed over",
    { spec = "PKM *resolution.provider-is-highest-stratum" }, function(t)
        -- The presence bitmap is set by a full walk of the joined path
        -- per stratum, so a stratum whose intermediate component is a
        -- regular file is skipped exactly like one that lacks the name.
        stratafs.with(vm, "walk-failures", {
            { name = "top", entries = { d = "a regular file, not a directory" } },
            { name = "mid" },
            { name = "bot", entries = { ["d/f"] = "bot" } },
        }, function(s)
            -- `top` holds `d` as a file, so `d` is masked entirely
            -- (§4.3.3) — the walk of `d/f` in `top` gives ENOTDIR, but
            -- the ancestor test fires first.
            local st, errno = sys.stat(vm, s:join("d", "f"))
            t:assert(st == nil, "a masked ancestor stops the resolution")
            t:assert_eq(errno, sys.E.NOTDIR, "with ENOTDIR: " .. sys.errname(errno))

            -- With the masking file gone, `mid` lacks `d` entirely and
            -- is skipped, and `bot` provides.
            vm:unlink(s:in_stratum("top", "d"))
            t:assert_eq(vm:read_file(s:join("d", "f")), "bot",
                "a stratum that simply lacks the name is passed over")
        end)
    end)

test("a child's provider is chosen afresh, not inherited from its parent",
    { spec = "PKM *resolution.provider-chosen-per-component" }, function(t)
        -- If /a is provided by a lower stratum, /a/b may still be
        -- provided by a higher one — provided the higher also holds /a
        -- as a directory, so the two merge.
        stratafs.with(vm, "per-component", {
            { name = "high", entries = { ["a/b"] = "high" } },
            { name = "low", entries = { ["a/b"] = "low", ["a/only_low"] = "l" } },
        }, function(s)
            -- `a` merges; its provider is `high`. Its children are
            -- resolved independently across the whole stack.
            t:assert_eq(vm:read_file(s:join("a", "b")), "high",
                "the child's provider is the highest holding the child")
            t:assert_eq(vm:read_file(s:join("a", "only_low")), "l",
                "and a sibling's may be a different stratum entirely")

            -- Removing the child from the higher stratum moves only
            -- that child, not the directory.
            vm:unlink(s:in_stratum("high", "a/b"))
            t:assert_eq(vm:read_file(s:join("a", "b")), "low",
                "one component moving does not move the others")
            t:assert_eq(vm:read_file(s:join("a", "only_low")), "l",
                "nor the directory they are in")
        end)
    end)

test("every proper prefix is resolved before the final component",
    { spec = "PKM *resolution.provider-chosen-per-component" }, function(t)
        -- A prefix whose merged provider is not a directory aborts the
        -- whole resolution with ENOTDIR. That is what makes masking
        -- total, at any depth.
        stratafs.with(vm, "prefixes", {
            { name = "top", entries = { ["x/y"] = "a file where a dir should be" } },
            { name = "bot", entries = { ["x/y/z/deep"] = "bot" } },
        }, function(s)
            t:assert_eq(vm:read_file(s:join("x", "y")), "a file where a dir should be",
                "the prefix itself resolves to the masking file")
            for _, path in ipairs({ "x/y/z", "x/y/z/deep" }) do
                local st, errno = sys.stat(vm, s.at .. "/" .. path)
                t:assert(st == nil, "`" .. path .. "` does not resolve")
                t:assert_eq(errno, sys.E.NOTDIR,
                    "because a prefix is not a directory: " .. sys.errname(errno))
            end
        end)
    end)

test("a provider the caller may not reach is refused, not fallen past",
    { spec = "PKM *resolution.independent-of-caller" }, function(t)
        -- Resolution takes no operation argument and does not consult
        -- the calling token. A name whose provider the caller may not
        -- access resolves normally and is then refused — it does not
        -- fall through to a lower stratum, which would let a caller's
        -- rights decide which file they read.
        stratafs.with(vm, "independent", {
            { name = "top", entries = { f = "the one that provides" } },
            { name = "bot", entries = { f = "the one that must not be reached" } },
        }, function(s)
            local r = kacs.set_sd(vm, s:in_stratum("top", "f"), kacs.deny_all())
            t:assert_eq(r.ret, 0, "the provider is closed: " .. sys.errname(r.errno))

            kacs.as_dacl_bound(t, vm, function(worker)
                local fd, errno = sys.open(worker, s:join("f"), sys.O.RDONLY)
                t:assert(fd == nil, "the caller cannot open the name")
                t:assert_eq(errno, sys.E.ACCES,
                    "it is refused: " .. sys.errname(errno))
                if fd then sys.close(worker, fd) end

                -- The lower stratum's file is perfectly readable, and
                -- that is exactly why this matters.
                t:assert_eq(vm:read_file(s:in_stratum("bot", "f")),
                    "the one that must not be reached",
                    "while the stratum below holds a readable file of that name")
            end)
        end)
    end)

test("a non-directory is the provider's object, forwarded",
    { spec = "PKM *resolution.non-directory-forwarded" }, function(t)
        stratafs.with(vm, "forwarded", {
            { name = "top", flags = { "create" }, entries = {
                link = stratafs.symlink("../outside/target"),
                absolute = stratafs.symlink("/stratafs/forwarded/elsewhere"),
                weird = stratafs.symlink("a:b+c,d\\e"),
            } },
            { name = "bot", entries = { plain = "content from the provider" } },
        }, function(s)
            t:assert_eq(vm:read_file(s:join("plain")), "content from the provider",
                "a read is forwarded to the provider's object")

            -- get_link returns the raw target verbatim: stratafs does
            -- not rewrite it, and does not follow it itself.
            for name, target in pairs({
                link = "../outside/target",
                absolute = "/stratafs/forwarded/elsewhere",
                weird = "a:b+c,d\\e",
            }) do
                local got, errno = sys.readlink(vm, s:join(name))
                t:assert_eq(got, target,
                    "`" .. name .. "` reads back verbatim: " ..
                    tostring(got or sys.errname(errno)))
            end

            -- The outer inode takes the provider's mode, so a symlink
            -- is a symlink and a file is a file through the view.
            local ln = sys.stat(vm, s:join("link"), { follow = false })
            t:assert(ln and ln.is_symlink, "the symlink presents as one")
            local pl = sys.stat(vm, s:join("plain"))
            t:assert(pl and pl.is_file, "and the regular file as one")

            -- The VFS interprets the target in the caller's namespace,
            -- so an absolute target resolves from the process root and
            -- can land outside the mount entirely.
            vm:mkdir(s.root, { parents = true })
            vm:write_file(s.root .. "/elsewhere", "outside the mount")
            t:assert_eq(vm:read_file(s:join("absolute")), "outside the mount",
                "an absolute target resolves from the process's own root")
        end)
    end)

-- Not reachable from userspace, and not for want of privilege.
--
-- Suppression is keyed on the staged name in a per-superblock list of
-- what *this* mount has in flight (`stratafs_is_staging`), so a
-- hand-made `.stratafs-stage-` file is not suppressed and proves
-- nothing. Catching a real one needs the copy-up to be in flight while
-- something else looks, and neither path allows it:
--
--   * a regular file stages into an anonymous O_TMPFILE inode and has
--     no directory entry at all until it is published, so there is
--     never a name to be hidden;
--   * a directory or symlink does take a `.stratafs-stage-` name, but
--     that path is create, set attributes, copy xattrs, rename — it
--     holds the name for microseconds.
--
-- Tried and rejected: a 96 MB source through the merged view with the
-- write in flight (`vm:syscall_async`) and a 1 ms poll of the create
-- stratum for 10 s. Nothing ever appears, because that is the
-- anonymous path.
--
-- Covering this wants a kernel-side hook that holds a copy-up open —
-- fault injection or a debugfs delay — not a bigger VM.
test("a staging name is invisible through the mount that owns it",
    { spec = "PKM *resolution.staged-names-hidden",
      skip = "needs a copy-up held open mid-flight: regular files stage " ..
             "anonymously (no name to hide) and the named path holds its " ..
             "name for microseconds. Wants a kernel-side delay hook" },
    function(t) t:fail("no way to hold a copy-up open") end)

test("re-entering a superblock during resolution is ELOOP",
    { spec = "PKM *resolution.reentrant-superblock-eloop" }, function(t)
        -- The guard is a per-task, per-superblock re-entrancy list, not
        -- a depth counter, so a cycle formed *after* the mount — which
        -- mount-time loop detection cannot catch — terminates the
        -- moment resolution returns to a mount it is already inside.
        local s = stratafs.scenario(vm, "reentrant", {
            { name = "only", flags = { "create" }, entries = { f = "f", loop = stratafs.DIR } },
        })
        local ok, err = pcall(function()
            t:assert_eq(vm:read_file(s:join("f")), "f", "the mount works")

            -- Bind the mount into its own stratum. Nothing at mount
            -- time could have seen this coming.
            local r = sys.mount(vm, {
                source = s.at,
                target = s:in_stratum("only", "loop"),
                flags = sys.MS_BIND,
            })
            t:assert_eq(r.ret, 0, "the cycle is formed: " .. sys.errname(r.errno))

            local st, errno = sys.stat(vm, s:join("loop", "f"))
            t:assert(st == nil, "resolving into the cycle fails")
            t:assert_eq(errno, sys.E.LOOP,
                "with ELOOP: " .. sys.errname(errno))

            sys.umount(vm, s:in_stratum("only", "loop"))
        end)
        s.release()
        if not ok then error(err, 0) end
    end)
