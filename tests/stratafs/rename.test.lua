-- PKM §4.5.5 — rename removes a name and creates one, so the source is
-- bound by the removal constraint and the destination by the
-- read-after-write direction of routing.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local stratafs = require("helpers.stratafs")
local hooks = require("helpers.hooks")

local vm = provium:vm("v", "kernel-only"):boot()

test("the source's provider must accept modification",
    { spec = "PKM *rename.source-provider-must-be-writable" }, function(t)
        -- Otherwise the source cannot be removed, and the rename would
        -- leave it still visible and amount to a copy.
        stratafs.with(vm, "rename-source-ro", {
            { name = "dest", flags = { "create" } },
            { name = "frozen", flags = { "ro" }, entries = { f = "original" } },
        }, function(s)
            local r = sys.rename(vm, s:join("f"), s:join("moved"))
            t:assert_neq(r.ret, 0, "renaming out of a ro stratum is refused")
            t:assert_eq(r.errno, sys.E.ROFS, "with EROFS: " .. sys.errname(r.errno))
            t:assert_eq(vm:read_file(s:join("f")), "original",
                "and the source is still there")
        end)
    end)

test("an immutable source is EPERM rather than EROFS",
    { spec = "PKM *rename.immutable-source-eperm" }, function(t)
        stratafs.with(vm, "rename-immutable", {
            { name = "only", flags = { "create" }, entries = { f = "original" } },
        }, function(s)
            t:assert(sys.set_immutable(vm, s:in_stratum("only", "f"), true),
                "the source is made immutable")
            local r = sys.rename(vm, s:join("f"), s:join("moved"))
            sys.set_immutable(vm, s:in_stratum("only", "f"), false)
            t:assert_neq(r.ret, 0, "renaming it is refused")
            t:assert_eq(r.errno, sys.E.PERM,
                "by the VFS, before stratafs's own test: " .. sys.errname(r.errno))
        end)
    end)

test("the destination must not be provided by a higher stratum",
    { spec = "PKM *rename.destination-not-higher-precedence" }, function(t)
        -- Otherwise the renamed object would be shadowed at its
        -- destination and unreadable through the path it was renamed to.
        stratafs.with(vm, "rename-dest-higher", {
            { name = "above", entries = { taken = "shadows" } },
            { name = "provider", flags = { "create" }, entries = { f = "original" } },
        }, function(s)
            local r = sys.rename(vm, s:join("f"), s:join("taken"))
            t:assert_neq(r.ret, 0, "renaming onto it is refused")
            t:assert_eq(r.errno, sys.E.ROFS, "with EROFS: " .. sys.errname(r.errno))
            t:assert_eq(vm:read_file(s:join("f")), "original", "and nothing moved")
        end)
    end)

test("the destination's parent must be held by the source's provider",
    { spec = "PKM *rename.destination-parent-in-provider" }, function(t)
        -- That directory is not created to satisfy the condition, even
        -- where the provider is the create stratum: parent
        -- materialisation exists to receive a copy-up, and a rename is
        -- not one.
        stratafs.with(vm, "rename-dest-parent", {
            { name = "provider", flags = { "create" }, entries = { f = "original" } },
            { name = "other", entries = { ["d/x"] = "x" } },
        }, function(s)
            t:assert(sys.stat(vm, s:join("d")) ~= nil,
                "the destination's parent exists as a merged directory")
            t:assert(sys.stat(vm, s:in_stratum("provider", "d")) == nil,
                "but the source's provider does not hold it")

            local r = sys.rename(vm, s:join("f"), s:join("d", "moved"))
            t:assert_neq(r.ret, 0, "the rename is refused")
            t:assert_eq(r.errno, sys.E.XDEV, "with EXDEV: " .. sys.errname(r.errno))
            t:assert(sys.stat(vm, s:in_stratum("provider", "d")) == nil,
                "and the directory was not created to satisfy it")
        end)
    end)

test("a directory source may not strand entries in other strata",
    { spec = "PKM *rename.directory-source-must-not-strand-entries" }, function(t)
        stratafs.with(vm, "rename-strand", {
            { name = "provider", flags = { "create" },
              entries = { ["d/mine"] = "m" } },
            { name = "other", entries = { ["d/theirs"] = "t" } },
        }, function(s)
            local r = sys.rename(vm, s:join("d"), s:join("moved"))
            t:assert_neq(r.ret, 0, "renaming the merged directory is refused")
            t:assert_eq(r.errno, sys.E.XDEV,
                "with EXDEV, since those entries cannot move with it: " ..
                sys.errname(r.errno))

            -- With nothing stranded, it moves.
            vm:unlink(s:in_stratum("other", "d/theirs"))
            t:assert_eq(sys.rename(vm, s:join("d"), s:join("moved")).ret, 0,
                "once no other stratum contributes, it succeeds")
            t:assert(sys.stat(vm, s:in_stratum("provider", "moved")) ~= nil,
                "in the providing stratum")
        end)
    end)

test("the stranded-entries scan needs rights on every participant",
    { spec = "PKM *rename.directory-source-must-not-strand-entries" }, function(t)
        -- Checked before any enumeration begins, so a refusal does not
        -- disclose whether other strata contributed.
        stratafs.with(vm, "rename-strand-rights", {
            { name = "provider", flags = { "create" },
              entries = { ["d/mine"] = "m" } },
            { name = "shut", entries = { ["d/secret"] = "s" } },
        }, function(s)
            local r = kacs.set_sd(vm, s:in_stratum("shut", "d"), kacs.deny_all())
            t:assert_eq(r.ret, 0, "one participant is closed: " ..
                sys.errname(r.errno))

            kacs.as_dacl_bound(t, vm, function(worker)
                local got = sys.rename(worker, s:join("d"), s:join("moved"))
                t:assert_neq(got.ret, 0, "the rename is refused")
                t:assert_eq(got.errno, sys.E.ACCES,
                    "with EACCES rather than EXDEV, disclosing nothing: " ..
                    sys.errname(got.errno))
            end)
        end)
    end)

test("the destination's type must match the source's",
    { spec = "PKM *rename.destination-type-must-match" }, function(t)
        -- Only the provider's type is compared: a lower stratum's entry
        -- of a different type is masked and contributes no inode.
        stratafs.with(vm, "rename-types", {
            { name = "only", flags = { "create" }, entries = {
                file = "f", other_file = "o",
                ["dir/x"] = "x", ["empty_dir"] = stratafs.DIR,
            } },
        }, function(s)
            local a = sys.rename(vm, s:join("file"), s:join("dir"))
            t:assert_neq(a.ret, 0, "a non-directory onto a directory is refused")
            t:assert_eq(a.errno, sys.E.ISDIR, "with EISDIR: " .. sys.errname(a.errno))

            local b = sys.rename(vm, s:join("dir"), s:join("other_file"))
            t:assert_neq(b.ret, 0, "a directory onto a non-directory is refused")
            t:assert_eq(b.errno, sys.E.NOTDIR, "with ENOTDIR: " .. sys.errname(b.errno))

            -- Matching types are fine.
            t:assert_eq(sys.rename(vm, s:join("file"), s:join("other_file")).ret, 0,
                "a file onto a file succeeds")
        end)
    end)

test("a directory destination must be empty across every stratum",
    { spec = "PKM *rename.destination-directory-must-be-empty" }, function(t)
        stratafs.with(vm, "rename-dest-empty", {
            { name = "provider", flags = { "create" }, entries = {
                ["source_dir/x"] = "x", ["target"] = stratafs.DIR } },
            { name = "other", entries = { ["target/theirs"] = "t" } },
        }, function(s)
            t:assert_eq(#vm:listdir(s:in_stratum("provider", "target")), 0,
                "the destination is empty in the provider")
            local r = sys.rename(vm, s:join("source_dir"), s:join("target"))
            t:assert_neq(r.ret, 0, "the rename is refused")
            t:assert_eq(r.errno, sys.E.NOTEMPTY,
                "because the merged destination is not empty: " ..
                sys.errname(r.errno))
        end)
    end)

test("the rename is performed within the source's provider",
    { spec = "PKM *rename.performed-within-the-provider" }, function(t)
        -- Both parents are resolved at the provider's index and a
        -- single vfs_rename is issued there. The provider need not be
        -- the create stratum.
        stratafs.with(vm, "rename-within", {
            { name = "dest", flags = { "create" } },
            { name = "provider", entries = { ["a/f"] = "original", b = stratafs.DIR } },
        }, function(s)
            t:assert_eq(sys.rename(vm, s:join("a", "f"), s:join("b", "moved")).ret, 0,
                "the rename succeeds")
            t:assert_eq(vm:read_file(s:in_stratum("provider", "b/moved")), "original",
                "in the stratum that provided the source")
            t:assert(sys.stat(vm, s:in_stratum("provider", "a/f")) == nil,
                "with the source gone from it")
            t:assert_eq(#vm:listdir(s:in_stratum("dest")), 0,
                "and the create stratum untouched")
        end)
    end)

test("a destination in a lower stratum is shadowed, not replaced",
    { spec = "PKM *rename.lower-destination-is-shadowed" }, function(t)
        stratafs.with(vm, "rename-shadow", {
            { name = "provider", flags = { "create" },
              entries = { f = "the renamed object" } },
            { name = "below", entries = { target = "the shadowed one" } },
        }, function(s)
            t:assert_eq(sys.rename(vm, s:join("f"), s:join("target")).ret, 0,
                "the rename succeeds")
            t:assert_eq(vm:read_file(s:join("target")), "the renamed object",
                "and the renamed object provides the destination")
            t:assert_eq(vm:read_file(s:in_stratum("below", "target")),
                "the shadowed one",
                "while the lower entry is shadowed, not removed")

            -- Where the destination is held by the provider itself, it
            -- is replaced, as on any filesystem.
            vm:write_file(s:in_stratum("provider", "g"), "another")
            t:assert_eq(sys.rename(vm, s:join("g"), s:join("target")).ret, 0,
                "renaming onto the provider's own entry succeeds")
            t:assert_eq(vm:read_file(s:join("target")), "another",
                "replacing it")
        end)
    end)

test("a directory renamed onto a directory merges with the strata below",
    { spec = "PKM *rename.directory-destination-merges" }, function(t)
        -- Not a shadowing: by §4.3.2 the renamed directory merges. The
        -- emptiness condition is what keeps that tolerable — those
        -- directories are empty, so the merged result is the renamed
        -- directory's own contents.
        stratafs.with(vm, "rename-dir-merge", {
            { name = "provider", flags = { "create" }, entries = {
                ["source/mine"] = "m", target = stratafs.DIR } },
            { name = "below", entries = { target = stratafs.DIR } },
        }, function(s)
            t:assert_eq(sys.rename(vm, s:join("source"), s:join("target")).ret, 0,
                "the rename succeeds")
            local names = {}
            for _, e in ipairs(vm:listdir(s:join("target"))) do names[e.name] = true end
            t:assert(names.mine, "the renamed directory's contents are there")
            t:assert(sys.stat(vm, s:in_stratum("below", "target")) ~= nil,
                "and the lower directory still exists, merged with it")
        end)
    end)

test("a rename across mounts is EXDEV",
    { spec = "PKM *rename.cross-mount-exdev" }, function(t)
        local a = stratafs.scenario(vm, "rename-xdev-a", {
            { name = "only", flags = { "create" }, entries = { f = "a" } },
        })
        local b = stratafs.scenario(vm, "rename-xdev-b", {
            { name = "only", flags = { "create" } },
        })
        local ok, err = pcall(function()
            local r = sys.rename(vm, a:join("f"), b:join("moved"))
            t:assert_neq(r.ret, 0, "renaming between two mounts is refused")
            t:assert_eq(r.errno, sys.E.XDEV, "with EXDEV: " .. sys.errname(r.errno))
            t:assert_eq(vm:read_file(a:join("f")), "a", "and nothing moved")
        end)
        a.release(); b.release()
        if not ok then error(err, 0) end
    end)

test("the atomic-replace pattern works through a mount",
    { spec = "PKM *rename.replace-is-atomic" }, function(t)
        -- The operation by which most software replaces a file safely:
        -- write a temporary beside it, then rename over. §4.5.3 places
        -- the temporary in the create stratum, which never carries
        -- `ro`, so conditions 1 and 3 are satisfied.
        stratafs.with(vm, "rename-atomic", {
            { name = "dest", flags = { "create" } },
            { name = "base", flags = { "ro" }, entries = { conf = "version 1" } },
        }, function(s)
            t:assert(stratafs.try_create(vm, s:join("conf.tmp"), "version 2"),
                "the temporary is created")
            t:assert(sys.stat(vm, s:in_stratum("dest", "conf.tmp")) ~= nil,
                "in the create stratum")

            t:assert_eq(sys.rename(vm, s:join("conf.tmp"), s:join("conf")).ret, 0,
                "and renamed over the read-only original")
            t:assert_eq(vm:read_file(s:join("conf")), "version 2",
                "the new contents provide the name")
            t:assert_eq(vm:read_file(s:in_stratum("base", "conf")), "version 1",
                "the original is shadowed rather than removed — no whiteout " ..
                "was needed")
        end)
    end)

test("RENAME_NOREPLACE checks every stratum",
    { spec = "PKM *rename.noreplace-checks-every-stratum" }, function(t)
        stratafs.with(vm, "rename-noreplace", {
            { name = "provider", flags = { "create" }, entries = { f = "original" } },
            { name = "below", flags = { "ro" }, entries = { taken = "held below" } },
        }, function(s)
            local r = sys.rename(vm, s:join("f"), s:join("taken"),
                sys.RENAME_NOREPLACE)
            t:assert_neq(r.ret, 0, "a destination held below is refused")
            t:assert_eq(r.errno, sys.E.EXIST,
                "with EEXIST, not merely where the provider holds it: " ..
                sys.errname(r.errno))

            t:assert_eq(sys.rename(vm, s:join("f"), s:join("free"),
                sys.RENAME_NOREPLACE).ret, 0,
                "while a name no stratum holds is accepted")
        end)
    end)

test("RENAME_NOREPLACE's EEXIST takes precedence over the other conditions",
    { spec = "PKM *rename.noreplace-eexist-takes-precedence" }, function(t)
        -- The VFS looks the destination up with LOOKUP_EXCL and returns
        -- EEXIST for a positive dentry before vfs_rename runs, and
        -- stratafs's merged lookup makes it positive whenever any
        -- stratum holds the name. So a caller should not expect EROFS,
        -- EXDEV or EACCES from a NOREPLACE whose destination existed.
        stratafs.with(vm, "rename-noreplace-order", {
            { name = "frozen", flags = { "ro" }, entries = { f = "original" } },
            { name = "below", entries = { taken = "held" } },
        }, function(s)
            -- Condition 1 would give EROFS: the source is in a ro
            -- stratum. EEXIST wins.
            local r = sys.rename(vm, s:join("f"), s:join("taken"),
                sys.RENAME_NOREPLACE)
            t:assert_neq(r.ret, 0, "the rename is refused")
            t:assert_eq(r.errno, sys.E.EXIST,
                "with EEXIST rather than the EROFS condition 1 would give: " ..
                sys.errname(r.errno))
        end)
    end)

test("RENAME_EXCHANGE needs both names in one stratum",
    { spec = "PKM *rename.exchange-needs-one-stratum" }, function(t)
        stratafs.with(vm, "rename-exchange", {
            { name = "provider", flags = { "create" },
              entries = { a = "A", b = "B" } },
            { name = "other", entries = { elsewhere = "E" } },
        }, function(s)
            -- Both in the providing stratum: an ordinary exchange.
            t:assert_eq(sys.rename(vm, s:join("a"), s:join("b"),
                sys.RENAME_EXCHANGE).ret, 0, "an exchange within one stratum works")
            t:assert_eq(vm:read_file(s:join("a")), "B", "the names are swapped")
            t:assert_eq(vm:read_file(s:join("b")), "A", "both ways")

            -- Names provided by different strata cannot be exchanged.
            local r = sys.rename(vm, s:join("a"), s:join("elsewhere"),
                sys.RENAME_EXCHANGE)
            t:assert_neq(r.ret, 0, "an exchange across strata is refused")
            t:assert_eq(r.errno, sys.E.ROFS, "with EROFS: " .. sys.errname(r.errno))

            -- Conditions 5 and 6 are not evaluated: an exchange swaps
            -- two names that both exist, so neither type matching nor
            -- emptiness is required of either.
            vm:mkdir(s:in_stratum("provider", "populated"), { parents = true })
            vm:write_file(s:in_stratum("provider", "populated/inside"), "x")
            t:assert_eq(sys.rename(vm, s:join("a"), s:join("populated"),
                sys.RENAME_EXCHANGE).ret, 0,
                "a file and a populated directory exchange, differing in type " ..
                "and neither being empty")
        end)
    end)

test("RENAME_WHITEOUT is refused before anything else",
    { spec = "PKM *rename.whiteout-flag-einval" }, function(t)
        -- stratafs has no whiteouts and cannot represent one.
        stratafs.with(vm, "rename-whiteout", {
            { name = "frozen", flags = { "ro" }, entries = { f = "original" } },
        }, function(s)
            -- The source is in a ro stratum, so condition 1 would give
            -- EROFS — but the flag is checked before everything else.
            local r = sys.rename(vm, s:join("f"), s:join("moved"),
                sys.RENAME_WHITEOUT)
            t:assert_neq(r.ret, 0, "the rename is refused")
            t:assert_eq(r.errno, sys.E.INVAL,
                "with EINVAL, checked before condition 1: " ..
                sys.errname(r.errno))
        end)
    end)

test("unknown flag bits pass through to the VFS",
    { spec = "PKM *rename.unknown-flags-pass-through" }, function(t)
        -- Neither rejected nor masked by stratafs.
        stratafs.with(vm, "rename-unknown-flags", {
            { name = "only", flags = { "create" }, entries = { f = "original" } },
        }, function(s)
            local r = sys.rename(vm, s:join("f"), s:join("moved"), 0x1000)
            t:assert_neq(r.ret, 0, "an unknown flag bit is refused")
            t:assert_eq(r.errno, sys.E.INVAL,
                "by the VFS, which knows no such flag: " .. sys.errname(r.errno))
            t:assert_eq(vm:read_file(s:join("f")), "original", "and nothing moved")
        end)
    end)

test("a rename whose names resolve to one inode is a no-op",
    { spec = "PKM *rename.same-inode-is-a-noop" }, function(t)
        stratafs.with(vm, "rename-same-inode", {
            { name = "only", flags = { "create" }, entries = { f = "original" } },
        }, function(s)
            -- Two names for one object in the providing stratum.
            t:assert_eq(sys.link(vm, s:in_stratum("only", "f"),
                s:in_stratum("only", "hardlink")).ret, 0, "a second link is made")

            local r = sys.rename(vm, s:join("f"), s:join("hardlink"))
            t:assert_eq(r.ret, 0, "renaming one onto the other succeeds: " ..
                sys.errname(r.errno))
            t:assert_eq(vm:read_file(s:join("f")), "original",
                "and both names are still there")
            t:assert_eq(vm:read_file(s:join("hardlink")), "original", "unchanged")

            -- The trivial case too.
            t:assert_eq(sys.rename(vm, s:join("f"), s:join("f")).ret, 0,
                "renaming a name onto itself succeeds")
        end)
    end)

-- A race backstop: the dentry stratafs receives in `->rename` was
-- built moments earlier by the same syscall, so the mismatch needs the
-- provider to change between that walk and the locked re-lookup —
-- inside one syscall. The rename-provider rendezvous (§4.A.2) holds
-- exactly that window open.
--
-- The refusal is per attempt and the VFS heals it: ESTALE from a
-- rename retries the whole syscall once with a fresh walk, whose
-- rebuilt dentry carries the current identity, so the caller sees the
-- retry's outcome. The refusal itself is recorded at the
-- stratafs:stratafs_rename_stale tracepoint (§4.5.5), which is where
-- this test observes it.
test("a dentry whose provider identity no longer matches is ESTALE",
    { spec = "PKM *rename.stale-dentry-estale" }, function(t)
        stratafs.with(vm, "stale-rename", {
            { name = "only", flags = { "create" }, entries = { f = "first" } },
        }, function(s)
            t:assert(hooks.hold(vm, "rename-provider"), "the rendezvous arms")
            -- In a worker: a held syscall on the agent's main
            -- connection would wedge every later call.
            local worker = vm:spawn_worker()
            local ok, err = pcall(function()
                local pending = worker:syscall_async(sys.NR.renameat2, {
                    args = { sys.AT_FDCWD, 0, sys.AT_FDCWD, 0, 0 },
                    bufs = { sys.cstr(s:join("f")), sys.cstr(s:join("g")) },
                    ptrs = { 1, 3 },
                })
                t:assert(hooks.await_waiting(vm, "rename-provider"),
                    "the rename holds with its walk-time provider captured")

                -- Replace the provider under it, directly in the
                -- stratum: same name, different object.
                t:assert_eq(sys.unlink(vm, s:in_stratum("only", "f")).ret, 0,
                    "the provider entry is removed behind the rename")
                vm:write_file(s:in_stratum("only", "f"), "second")

                t:assert(hooks.trace_start(vm, "stratafs"), "tracing starts")
                t:assert(hooks.clear(vm, "rename-provider"), "released")
                local r = pending:await()
                local lines = hooks.trace_stop(vm, "stratafs")

                -- Attempt one hit the backstop; the trace records it.
                local stale = false
                for _, line in ipairs(lines or {}) do
                    if line:match("stratafs_rename_stale:") then stale = true end
                end
                t:assert(stale, "the stale identity was detected and refused")

                -- The retry then acted on the current identity: what
                -- moved to the destination is the replacement object,
                -- not the one the first walk resolved.
                t:assert_eq(r.ret, 0, "the healed retry succeeds: " ..
                    sys.errname(r.errno))
                t:assert_eq(vm:read_file(s:join("g")), "second",
                    "and renamed the object now at the name")
                t:assert(sys.stat(vm, s:join("f")) == nil,
                    "which no longer provides the source name")
            end)
            hooks.clear(vm, "rename-provider")
            worker:kill(); worker:join()
            if not ok then error(err, 0) end
        end)
    end)
