-- PKM §4.3.2 and §4.3.3 — merged directories: who participates, where
-- their creations go, and what happens when two strata hold one name
-- with different types.

local sys = require("helpers.sys")
local stratafs = require("helpers.stratafs")

local vm = provium:vm("v", "kernel-only"):boot()

local function names_in(dir)
    local out = {}
    for _, e in ipairs(vm:listdir(dir)) do out[e.name] = e.entry_type or true end
    return out
end

test("the participants are the strata holding the name as a directory",
    { spec = "PKM *resolution.merge-participants" }, function(t)
        stratafs.with(vm, "participants", {
            { name = "s0", entries = { ["d/from0"] = "0" } },
            { name = "s1", entries = { d = "a regular file" } },
            { name = "s2", entries = { ["d/from2"] = "2" } },
            { name = "s3" },
            { name = "s4", entries = { ["d/from4"] = "4" } },
        }, function(s)
            local got = names_in(s:join("d"))
            t:assert(got.from0, "the provider participates")
            t:assert(got.from2, "and a lower stratum holding it as a directory")
            t:assert(got.from4, "however far down")

            -- A stratum holding the name as a non-directory does not
            -- participate — and does not stop those below it from
            -- doing so, because it is not the provider.
            t:assert_eq(vm:read_file(s:in_stratum("s1", "d")), "a regular file",
                "the non-directory is still there in its own stratum")

            -- Nothing compacts or re-sorts: precedence inside the
            -- merged directory is precedence in the stack.
            stratafs.populate(vm, s:in_stratum("s2", "d"), { shared = "2" })
            stratafs.populate(vm, s:in_stratum("s4", "d"), { shared = "4" })
            t:assert_eq(vm:read_file(s:join("d", "shared")), "2",
                "the higher participant provides a name they share")
        end)
    end)

test("merging is recursive and recomputed, never cached",
    { spec = "PKM *resolution.merge-participants" }, function(t)
        stratafs.with(vm, "recursive-merge", {
            { name = "top", entries = { ["a/b/c/from_top"] = "t" } },
            { name = "bot", entries = { ["a/b/c/from_bot"] = "b" } },
        }, function(s)
            local got = names_in(s:join("a", "b", "c"))
            t:assert(got.from_top and got.from_bot,
                "a child that is a directory in both merges at its own level")

            -- Rebuilt from the path string on every lookup, so a
            -- directory appearing deep in a stratum merges immediately.
            stratafs.populate(vm, s:in_stratum("bot", "a/b/c/new"), { deep = "d" })
            stratafs.populate(vm, s:in_stratum("top", "a/b/c/new"), { other = "o" })
            local deeper = names_in(s:join("a", "b", "c", "new"))
            t:assert(deeper.deep and deeper.other,
                "with no remount and nothing invalidated")
        end)
    end)

test("the mount root is a merged directory of the stratum roots",
    { spec = "PKM *resolution.merge-participants" }, function(t)
        -- And it has one special case: where the ordinary provider rule
        -- would pick a stratum root that is present but not a
        -- directory, the root takes the first that is both present and
        -- a directory, so the synthetic root cannot change type.
        local s = stratafs.scenario(vm, "root-merge", {
            { name = "s0" },
            { name = "s1", entries = { from1 = "1" } },
            { name = "s2", entries = { from2 = "2" } },
        }, { mount = false })

        -- Make the highest stratum root a regular file.
        vm:rename(s:in_stratum("s0"), s.root .. "/s0-away")
        vm:write_file(s:in_stratum("s0"), "not a directory")

        local r = stratafs.try_mount(vm, { at = s.at, strata = s.strata })
        t:assert_neq(r.ret, 0,
            "a non-directory stratum root is refused at mount (§4.2.3)")
        t:assert_eq(r.errno, sys.E.NOTDIR, sys.errname(r.errno))

        -- So reach the case the other way: mount with it a directory,
        -- then replace it underneath.
        vm:unlink(s:in_stratum("s0"))
        vm:rename(s.root .. "/s0-away", s:in_stratum("s0"))
        stratafs.mount(vm, { at = s.at, strata = s.strata })
        local ok, err = pcall(function()
            vm:rename(s:in_stratum("s0"), s.root .. "/s0-gone")
            vm:write_file(s:in_stratum("s0"), "not a directory any more")

            local st = sys.stat(vm, s.at)
            t:assert(st and st.is_dir,
                "the mount root is still a directory")
            local got = names_in(s.at)
            t:assert(got.from1 and got.from2,
                "and still merges the stratum roots that are directories")
        end)
        stratafs.umount(vm, s.at)
        if not ok then error(err, 0) end
    end)

test("a merged directory's create stratum is positional",
    { spec = "PKM *resolution.merge-create-stratum-is-positional" }, function(t)
        -- It is the correspondingly-named subdirectory of the mount's
        -- create stratum, at the same relative path, whether or not
        -- that subdirectory exists — not the highest-precedence
        -- participating writable directory.
        stratafs.with(vm, "positional-create", {
            { name = "high", entries = { ["d/from_high"] = "h", ["e/x"] = "x" } },
            { name = "dest", flags = { "create" } },
            { name = "low", entries = { ["d/from_low"] = "l" } },
        }, function(s)
            -- The create stratum holds no part of `d` at all, and the
            -- highest participant is a perfectly writable directory.
            t:assert(sys.stat(vm, s:in_stratum("dest", "d")) == nil,
                "the create stratum holds no part of the path")

            t:assert(stratafs.try_create(vm, s:join("d", "new"), "n"),
                "a creation in the merged directory succeeds")
            t:assert_eq(vm:read_file(s:in_stratum("dest", "d/new")), "n",
                "landing in the create stratum's counterpart, materialised on demand")
            t:assert(sys.stat(vm, s:in_stratum("high", "d/new")) == nil,
                "and not in the highest participating writable directory")

            -- Two sibling directories must route to the same stratum,
            -- which is the whole point of the derivation being
            -- positional rather than by participation.
            t:assert(stratafs.try_create(vm, s:join("e", "new"), "n"),
                "a creation in a sibling merged directory succeeds")
            t:assert_eq(vm:read_file(s:in_stratum("dest", "e/new")), "n",
                "and lands in the same stratum, not a different one")
        end)
    end)

test("every consumer of the participant set resolves the final component alike",
    { spec = "PKM *resolution.merge-participant-set-resolves-like-lookup" },
    function(t)
        -- Ordinary lookup resolves without following the final
        -- component. Every site that builds the participant set does
        -- the same — the set itself, the emptiness scan, the permission
        -- check, directory fsync — so a stratum holding the name as a
        -- symlink is a non-participant to all of them.
        --
        -- The two agreeing is what closes a confused-deputy shape: were
        -- the set to follow the link while lookup did not, a stratum
        -- owner replacing a directory with a symlink would change which
        -- real directory contributed entries to another stratum's view.
        stratafs.with(vm, "participant-set-alike", {
            { name = "top", flags = { "create" }, entries = { ["d/only_top"] = "t" } },
            { name = "bot", entries = {
                d = stratafs.symlink("elsewhere"),
                elsewhere = stratafs.DIR,
                ["elsewhere/would_be_merged"] = "e",
            } },
        }, function(s)
            -- The set: the symlink stratum contributes nothing, and
            -- nothing from the directory it points at appears.
            local got = names_in(s:join("d"))
            t:assert(got.only_top, "the participating stratum contributes")
            t:assert(not got.would_be_merged,
                "and the symlink's target is not merged in")

            -- The permission check and the open agree with that: the
            -- merged directory opens against one participant.
            local fd = sys.open(vm, s:join("d"), sys.O.RDONLY | sys.O.DIRECTORY)
            t:assert(fd, "the merged directory opens")
            if fd then
                -- Directory fsync walks the same set.
                local sync = sys.fsync(vm, fd)
                t:assert_eq(sync.ret, 0,
                    "and fsyncs over it: " .. sys.errname(sync.errno))
                sys.close(vm, fd)
            end

            -- The emptiness scan: with the one participant emptied, the
            -- merged directory is empty, because the symlink stratum
            -- never counted and neither did its target's contents.
            vm:unlink(s:in_stratum("top", "d/only_top"))
            t:assert_eq(#vm:listdir(s:join("d")), 0,
                "the merged directory is empty once its one participant is")
            local r = sys.mkdir(vm, s:join("d", "probe"))
            t:assert_eq(r.ret, 0,
                "and still works as a directory: " .. sys.errname(r.errno))

            -- The target is untouched throughout, and still reachable
            -- by its own name.
            t:assert(names_in(s:join("elsewhere")).would_be_merged,
                "the symlink's target is reachable under its own name")
        end)
    end)

test("a symlink masks a directory below exactly as any non-directory does",
    { spec = "PKM *resolution.symlink-masks-like-any-non-directory" }, function(t)
        -- The participant set resolves the final component the way
        -- lookup does — without following it — so a symlink at a name
        -- is a non-directory there too and masks whatever the strata
        -- below hold. Were the two to disagree, a stratum owner who
        -- replaced a directory with a symlink would change which real
        -- directory contributed entries to another stratum's view.
        --
        -- What the caller then sees through the name is the VFS's
        -- doing, not stratafs's: it follows the link and resolves the
        -- rest of the path against the target. The masking shows up as
        -- the lower directory's entries being absent from that.
        stratafs.with(vm, "symlink-masks", {
            { name = "top", entries = {
                link = stratafs.symlink("target"),
                dangling = stratafs.symlink("nothing-here"),
                target = stratafs.DIR,
                ["target/alpha"] = "from the link's target",
            } },
            { name = "bot", entries = {
                ["link/beta"] = "from the stratum below",
                ["dangling/beta"] = "from the stratum below",
                ["target/gamma"] = "merged normally",
            } },
        }, function(s)
            for _, name in ipairs({ "link", "dangling" }) do
                local st = sys.stat(vm, s:join(name), { follow = false })
                t:assert(st and st.is_symlink,
                    "`" .. name .. "` resolves to the link itself")

                -- The lower stratum's directory of that name did not
                -- participate, so nothing it holds is reachable here.
                local child, errno = sys.stat(vm, s:join(name, "beta"))
                t:assert(child == nil,
                    "`" .. name .. "/beta` is not reachable")
                t:assert_eq(errno, sys.E.NOENT,
                    "the path is resolved against the link's target, not a " ..
                    "merge with the masked directory: " .. sys.errname(errno))

                -- And it is still there in its own stratum, untouched.
                t:assert_eq(vm:read_file(s:in_stratum("bot", name .. "/beta")),
                    "from the stratum below",
                    "while the masked directory is unchanged where it lives")
            end

            -- The link's target resolves as itself and merges by the
            -- ordinary rule, which is what makes the contrast sharp:
            -- the same two strata merge under `target` and do not
            -- under `link`, though `link` points at `target`.
            t:assert_eq(vm:read_file(s:join("link", "alpha")),
                "from the link's target",
                "the link leads to its target's contents")
            local merged = names_in(s:join("target"))
            t:assert(merged.alpha and merged.gamma,
                "and `target` itself merges both strata as usual")
            t:assert(not names_in(s:join("link")).beta,
                "while nothing reached through the link shows the masked entries")
        end)
    end)

test("the provider's type is the resolved object's type",
    { spec = "PKM *resolution.conflict-provider-type-wins" }, function(t)
        stratafs.with(vm, "type-wins", {
            { name = "top", entries = {
                as_file = "a file up here", as_dir = stratafs.DIR,
                ["as_dir/x"] = "x",
            } },
            { name = "bot", entries = {
                ["as_file/inside"] = "hidden", as_dir = "a file down there",
            } },
        }, function(s)
            local file = sys.stat(vm, s:join("as_file"))
            t:assert(file and file.is_file,
                "a file over a directory resolves as a file")
            local dir = sys.stat(vm, s:join("as_dir"))
            t:assert(dir and dir.is_dir,
                "and a directory over a file as a directory")

            -- The outer inode gets the operations tables that follow
            -- from the provider's mode, so the wrong-type operation
            -- fails against the provider.
            local st, errno = sys.stat(vm, s:join("as_file", "inside"))
            t:assert(st == nil, "the masked directory's child does not resolve")
            t:assert_eq(errno, sys.E.NOTDIR, sys.errname(errno))
        end)
    end)

test("a directory provider merges only the directories below it",
    { spec = "PKM *resolution.conflict-directory-merges-only-directories" },
    function(t)
        stratafs.with(vm, "merges-only-dirs", {
            { name = "s0", entries = { ["d/from0"] = "0" } },
            { name = "s1", entries = { d = "a file" } },
            { name = "s2", entries = { ["d/from2"] = "2" } },
        }, function(s)
            local got = names_in(s:join("d"))
            t:assert(got.from0, "the provider contributes")
            t:assert(got.from2,
                "and so does a lower stratum holding the name as a directory")
            t:assert_eq(vm:read_file(s:in_stratum("s1", "d")), "a file",
                "while the one holding it as a file is masked, not merged")
        end)
    end)

test("a non-directory provider masks every lower entry of that name",
    { spec = "PKM *resolution.non-directory-masks-lower" }, function(t)
        stratafs.with(vm, "masks-lower", {
            { name = "s0", entries = { n = "the provider" } },
            { name = "s1", entries = { ["n/a_directory"] = "d" } },
            { name = "s2", entries = { n = "another file" } },
            { name = "s3", entries = { n = stratafs.symlink("elsewhere") } },
        }, function(s)
            t:assert_eq(vm:read_file(s:join("n")), "the provider",
                "the provider provides")
            local st = sys.stat(vm, s:join("n"), { follow = false })
            t:assert(st and st.is_file,
                "as a regular file, whatever the strata below hold")
            local child, errno = sys.stat(vm, s:join("n", "a_directory"))
            t:assert(child == nil and errno == sys.E.NOTDIR,
                "and nothing below that name is reachable: " ..
                sys.errname(errno))
        end)
    end)

test("masking hides the whole subtree, and modifies nothing",
    { spec = "PKM *resolution.masking-hides-whole-subtree" }, function(t)
        stratafs.with(vm, "masking-total", {
            { name = "top", flags = { "create" }, entries = { x = "a file at x" } },
            { name = "mid", entries = { ["x/y/z/deep"] = "m", ["x/shallow"] = "m" } },
            { name = "bot", entries = { ["x/y/other"] = "b" } },
        }, function(s)
            -- No path beneath the masked name resolves, regardless of
            -- what the masked directory holds and regardless of another
            -- stratum holding part of the subtree.
            for _, path in ipairs({ "x/shallow", "x/y", "x/y/z", "x/y/z/deep",
                                    "x/y/other" }) do
                local st, errno = sys.stat(vm, s.at .. "/" .. path)
                t:assert(st == nil, "`" .. path .. "` is unreachable")
                t:assert_eq(errno, sys.E.NOTDIR,
                    "`" .. path .. "`: " .. sys.errname(errno))
            end

            -- Masking modifies nothing: no marker is written, and the
            -- masked entries are unchanged in their own strata.
            t:assert_eq(vm:read_file(s:in_stratum("mid", "x/y/z/deep")), "m",
                "the masked tree is untouched in its own stratum")
            t:assert_eq(vm:read_file(s:in_stratum("bot", "x/y/other")), "b",
                "and so is the one below it")
            local top_entries = names_in(s:in_stratum("top"))
            t:assert_eq(top_entries.x, "file",
                "and nothing was written into the masking stratum")
        end)
    end)

test("an operation valid only against the masked type fails against the provider",
    { spec = "PKM *resolution.conflict-operation-fails-against-provider" },
    function(t)
        -- Provider selection is a pure function of the presence bitmap
        -- and consults neither the caller nor the operation, so asking
        -- for the masked type does not summon it.
        stratafs.with(vm, "operation-fails", {
            { name = "top", flags = { "create" }, entries = {
                file_over_dir = "a file",
                dir_over_file = stratafs.DIR,
                ["dir_over_file/x"] = "x",
            } },
            { name = "bot", entries = {
                ["file_over_dir/inside"] = "hidden",
                dir_over_file = "a file down there",
            } },
        }, function(s)
            -- Opening the file-over-directory as a directory: ENOTDIR
            -- against the provider, not a promotion of the masked one.
            local fd, errno = sys.open(vm, s:join("file_over_dir"),
                sys.O.RDONLY | sys.O.DIRECTORY)
            t:assert(fd == nil, "opening the provider as a directory fails")
            t:assert_eq(errno, sys.E.NOTDIR, sys.errname(errno))

            -- And reading the directory-over-file as a file: EISDIR,
            -- raised by the generic VFS against the provider's mode.
            local rfd, rerr = sys.open(vm, s:join("dir_over_file"), sys.O.RDONLY)
            if rfd then sys.close(vm, rfd) end
            local wfd, werr = sys.open(vm, s:join("dir_over_file"), sys.O.WRONLY)
            t:assert(wfd == nil, "opening the provider for writing fails")
            t:assert_eq(werr, sys.E.ISDIR,
                "as a directory: " .. sys.errname(werr))

            t:assert_eq(vm:read_file(s:in_stratum("bot", "dir_over_file")),
                "a file down there",
                "while the masked file is untouched in its own stratum")
        end)
    end)
