-- PKM §4.2.4 — a stratum's directory may not exist. What that means
-- while it is gone, and what appearing, disappearing and reappearing do.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local stratafs = require("helpers.stratafs")

local vm = provium:vm("v", "kernel-only"):boot()

test("an absent stratum contributes nothing but keeps its place",
    { spec = "PKM *strata.absent-contributes-nothing" }, function(t)
        stratafs.with(vm, "absent-nothing", {
            { name = "top", entries = { shared = "top", d = stratafs.DIR,
                                        ["d/from_top"] = "t" } },
            { name = "mid", flags = { "am" }, entries = { shared = "mid",
                                        only_mid = "m", ["d/from_mid"] = "m" } },
            { name = "bot", flags = { "create" }, entries = { shared = "bot",
                                        ["d/from_bot"] = "b" } },
        }, function(s)
            t:assert_eq(vm:read_file(s:join("only_mid")), "m",
                "the middle stratum contributes while it is there")

            vm:rename(s:in_stratum("mid"), s.root .. "/mid-away")
            t:assert(sys.stat(vm, s:join("only_mid")) == nil,
                "absent, it holds no names")

            -- It participates in no merged directory and contributes no
            -- entries to an enumeration...
            local names = {}
            for _, e in ipairs(vm:listdir(s:join("d"))) do names[e.name] = true end
            t:assert(names.from_top and names.from_bot,
                "the present strata still merge")
            t:assert(not names.from_mid,
                "and the absent one contributes no entries")

            -- ...but keeps its position, so the stratum below it does
            -- not get promoted past the one above.
            t:assert_eq(vm:read_file(s:join("shared")), "top",
                "precedence is unchanged by the gap")
        end)
    end)

test("only ENOENT and ENOTDIR count as absence",
    { spec = "PKM *strata.absent-contributes-nothing" }, function(t)
        -- A stratum that is unreadable for a reason other than not
        -- being there masks the name for every stratum, rather than
        -- being passed over — otherwise a stratum going unreadable
        -- would silently change which file a caller reads.
        local s = stratafs.scenario(vm, "absence-errnos", {
            { name = "top" },
            { name = "bot", entries = { f = "bot" } },
        }, { mount = false })

        -- ENOTDIR: the stratum path becomes a regular file. Skipped,
        -- exactly like an absent directory.
        stratafs.mount(vm, { at = s.at, strata = s.strata })
        local ok, err = pcall(function()
            vm:rename(s:in_stratum("top"), s.root .. "/top-away")
            vm:write_file(s:in_stratum("top"), "now a regular file")
            t:assert_eq(vm:read_file(s:join("f")), "bot",
                "a stratum path that is not a directory is skipped")
        end)
        stratafs.umount(vm, s.at)
        if not ok then error(err, 0) end

        -- EACCES: not absence. The whole resolution fails.
        --
        -- Resolution runs under the credentials captured at mount
        -- (§4.2.1), not the caller's, so the barrier has to deny the
        -- *mounter*. Hence the worker mounts: a stack the agent could
        -- walk right past would prove nothing. And the barrier goes up
        -- after the mount, because admission stats every stratum and
        -- would refuse the mount outright.
        local shut = stratafs.scenario(vm, "absence-eacces", {
            { name = "top", entries = { f = "top" } },
            { name = "bot", entries = { f = "bot" } },
        }, { mount = false })

        kacs.as_dacl_bound(t, vm, function(worker)
            local m = stratafs.try_mount(worker,
                { at = shut.at, strata = shut.strata })
            t:assert_eq(m.ret, 0, "the caller mounts: " .. sys.errname(m.errno))
            t:assert_eq(vm:read_file(shut:in_stratum("top", "f")), "top",
                "and the higher stratum holds the name")

            local r2 = kacs.set_sd(vm, shut:in_stratum("top"), kacs.deny_all())
            t:assert_eq(r2.ret, 0, "the barrier goes up: " .. sys.errname(r2.errno))

            local st, errno = sys.stat(worker, shut:join("f"))
            t:assert(st == nil,
                "the name does not resolve past the unreadable stratum")
            t:assert_eq(errno, sys.E.ACCES,
                "an unreadable stratum masks the name rather than being " ..
                "passed over: " .. sys.errname(errno))
        end)
    end)

test("an absent create stratum refuses creation and copy-up with EROFS",
    { spec = "PKM *strata.absent-contributes-nothing" }, function(t)
        -- The create stratum's root is re-resolved at the point of use
        -- and its ENOENT mapped to EROFS. stratafs does not mint the
        -- directory: choosing its security descriptor is not a mount's
        -- to do.
        stratafs.with(vm, "absent-create", {
            { name = "dest", flags = { "create" } },
            { name = "src", flags = { "ro" }, entries = { f = "original" } },
        }, function(s)
            t:assert(stratafs.try_create(vm, s:join("before"), "b"),
                "creation works while the create stratum is there")

            vm:rename(s:in_stratum("dest"), s.root .. "/dest-away")

            local made, cerr = stratafs.try_create(vm, s:join("after"), "a")
            t:assert(not made, "creation is refused once it is gone")
            t:assert_eq(cerr, sys.E.ROFS, "with EROFS: " .. sys.errname(cerr))

            local wrote, werr = stratafs.try_write(vm, s:join("f"), "modified")
            t:assert(not wrote, "and so is a write that would need copy-up")
            t:assert_eq(werr, sys.E.ROFS, "with EROFS: " .. sys.errname(werr))

            t:assert(sys.stat(vm, s.root .. "/dest") == nil,
                "and the directory was not minted to satisfy them")
        end)
    end)

test("a stratum appearing or going is observed by the next lookup",
    { spec = "PKM *strata.appearance-observed-on-next-lookup" }, function(t)
        -- Neither event is detected; both are simply observed, because
        -- only the path string is held and every resolution walks it
        -- afresh.
        stratafs.with(vm, "appearance", {
            { name = "top", flags = { "am" } },
            { name = "bot", flags = { "create" }, entries = { shared = "bot" } },
        }, function(s)
            t:assert_eq(vm:read_file(s:join("shared")), "bot",
                "while the higher stratum is absent, the lower provides")

            -- Appearing.
            stratafs.populate(vm, s:in_stratum("top"), { shared = "top" })
            t:assert_eq(vm:read_file(s:join("shared")), "top",
                "a directory that comes into existence is picked up at once")

            -- Replaced by another directory.
            stratafs.populate(vm, s.root .. "/replacement", { shared = "other" })
            vm:rename(s:in_stratum("top"), s.root .. "/top-aside")
            vm:rename(s.root .. "/replacement", s:in_stratum("top"))
            t:assert_eq(vm:read_file(s:join("shared")), "other",
                "and so is one that replaces it")

            -- Going away.
            vm:rename(s:in_stratum("top"), s.root .. "/top-gone")
            t:assert_eq(vm:read_file(s:join("shared")), "bot",
                "and one that is removed")
        end)
    end)

test("a stratum renamed away and back keeps its inode numbers",
    { spec = "PKM *strata.reappearance-preserves-inode-number" }, function(t)
        -- The identity map is keyed on the provider inode and pins it
        -- for the life of the mount, so the same underlying inode
        -- reached again gets the number it had before. A different
        -- directory in the same place does not.
        stratafs.with(vm, "reappearance", {
            { name = "top", entries = { f = "top" } },
            { name = "bot", flags = { "create" }, entries = { f = "bot" } },
        }, function(s)
            local before = sys.stat(vm, s:join("f"))
            t:assert(before, "the name resolves")

            vm:rename(s:in_stratum("top"), s.root .. "/aside")
            local while_gone = sys.stat(vm, s:join("f"))
            t:assert(while_gone, "the lower stratum provides while it is away")
            t:assert_neq(while_gone.ino, before.ino,
                "as a different object, with a different number")

            vm:rename(s.root .. "/aside", s:in_stratum("top"))
            local after = sys.stat(vm, s:join("f"))
            t:assert(after, "the name resolves again")
            t:assert_eq(after.ino, before.ino,
                "and the same provider inode has the same number as before")

            -- A different directory in the same place is a different
            -- provider, and gets a number of its own.
            stratafs.populate(vm, s.root .. "/other", { f = "other" })
            vm:rename(s:in_stratum("top"), s.root .. "/aside2")
            vm:rename(s.root .. "/other", s:in_stratum("top"))
            local replaced = sys.stat(vm, s:join("f"))
            t:assert_eq(vm:read_file(s:join("f")), "other", "the replacement provides")
            t:assert_neq(replaced.ino, before.ino,
                "and is not given the number the old provider had")
        end)
    end)
