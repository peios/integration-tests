-- PKM §4.6.1 and §4.6.2 — who performs which access check, and what
-- right each operation on a merged directory needs.
--
-- Every case here runs as a caller bound by the DACL (helpers/kacs),
-- because the agent is SYSTEM and carries privileges that go straight
-- past an access check. The shape is always the same: grant everything
-- except the one right under test, show the operation is refused, then
-- grant it and show the operation is the only thing that changed.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local stratafs = require("helpers.stratafs")

local vm = provium:vm("v", "kernel-only"):boot()

local R = kacs.RIGHT
local SEARCH = R.TRAVERSE
local ENUMERATE = R.TRAVERSE | R.LIST_DIRECTORY

--- Grant every right except `missing` on `path`.
local function grant_all_but(t, path, missing, why)
    local r = kacs.set_sd(vm, path, kacs.grant_all_but(missing))
    t:assert_eq(r.ret, 0, (why or path) .. ": " .. sys.errname(r.errno))
end

--- Grant every right except `missing` on `path` and on `also`.
---
--- Deletion is permitted by DELETE on the object *or* DELETE_CHILD on
--- its parent, so a case about the parent right has to close the
--- object's own route as well, or the operation succeeds by the other
--- door and proves nothing.
local function close_delete_route(t, object)
    local r = kacs.set_sd(vm, object, kacs.grant_all_but(kacs.RIGHT.DELETE))
    t:assert_eq(r.ret, 0, "the object's own delete right is withdrawn: " ..
        sys.errname(r.errno))
end

--- Grant every right on `path`.
local function grant_all(t, path, why)
    local r = kacs.set_sd(vm, path, kacs.grant(kacs.ALL_RIGHTS))
    t:assert_eq(r.ret, 0, (why or path) .. ": " .. sys.errname(r.errno))
end

test("an object's descriptor lives on its own stratum",
    { spec = "PKM *security.descriptor-on-provider-stratum" }, function(t)
        -- stratafs stores no descriptors and has nowhere to put one.
        -- Every object reachable through a mount has its descriptor on
        -- its own stratum, and that is what governs access to it.
        stratafs.with(vm, "sd-on-stratum", {
            { name = "top", flags = { "create" }, entries = { f = "x" } },
            { name = "bot", entries = { g = "y" } },
        }, function(s)
            for name, layer in pairs({ f = "top", g = "bot" }) do
                local through = kacs.get_sd(vm, s:join(name))
                local direct = kacs.get_sd(vm, s:in_stratum(layer, name))
                t:assert(through and direct, "`" .. name .. "` has a descriptor")
                t:assert_eq(through, direct,
                    "and the mount reports the provider's own, unchanged")
            end

            -- Changing it on the stratum changes what the mount says,
            -- because there is no second copy anywhere.
            local before = kacs.get_sd(vm, s:join("f"))
            grant_all_but(t, s:in_stratum("top", "f"), R.WRITE_DATA,
                "the provider's descriptor is changed")
            local after = kacs.get_sd(vm, s:join("f"))
            t:assert_neq(after, before,
                "and the mount reports the new one")
            t:assert_eq(after, kacs.get_sd(vm, s:in_stratum("top", "f")),
                "still identical to the provider's")
        end)
    end)

test("a mount cannot grant access the provider's stratum would refuse",
    { spec = "PKM *security.check-evaluates-target-descriptor" }, function(t)
        -- Structural rather than a matter of care: there is no
        -- descriptor for stratafs to get wrong, because it holds none.
        stratafs.with(vm, "sd-cannot-widen", {
            { name = "only", flags = { "create" },
              entries = { open = "readable", shut = "not readable" } },
        }, function(s)
            grant_all(t, s:in_stratum("only", "open"), "one object is open")
            local r = kacs.set_sd(vm, s:in_stratum("only", "shut"), kacs.deny_all())
            t:assert_eq(r.ret, 0, "the other is closed: " .. sys.errname(r.errno))

            kacs.as_dacl_bound(t, vm, function(worker)
                local ok = sys.open(worker, s:join("open"), sys.O.RDONLY)
                t:assert(ok, "the open object is readable through the mount")
                if ok then sys.close(worker, ok) end

                local no, errno = sys.open(worker, s:join("shut"), sys.O.RDONLY)
                t:assert(no == nil, "and the closed one is not")
                t:assert_eq(errno, sys.E.ACCES,
                    "the mount cannot widen what the stratum refuses: " ..
                    sys.errname(errno))
            end)
        end)
    end)

test("merged-directory checks are stratafs's own, over every participant",
    { spec = "PKM *security.merged-checks-are-stratafs-own" }, function(t)
        -- Forwarding would yield only the provider's descriptor, so
        -- stratafs walks every present participant and evaluates each,
        -- failing on the first refusal. Nothing degrades the operation
        -- to the subset of strata the caller may reach.
        stratafs.with(vm, "merged-own-checks", {
            { name = "top", flags = { "create" }, entries = { ["d/from_top"] = "t" } },
            { name = "bot", entries = { ["d/from_bot"] = "b" } },
        }, function(s)
            grant_all(t, s:in_stratum("top", "d"), "the provider is open")
            grant_all(t, s:in_stratum("bot", "d"), "and so is the participant")

            kacs.as_dacl_bound(t, vm, function(worker)
                local fd = sys.open(worker, s:join("d"),
                    sys.O.RDONLY | sys.O.DIRECTORY)
                t:assert(fd, "the merged directory opens while both permit")
                if fd then sys.close(worker, fd) end
            end)

            -- Close the *non-provider* participant. Forwarding would
            -- never have consulted it.
            local r = kacs.set_sd(vm, s:in_stratum("bot", "d"), kacs.deny_all())
            t:assert_eq(r.ret, 0, "the non-provider is closed: " ..
                sys.errname(r.errno))

            kacs.as_dacl_bound(t, vm, function(worker)
                local fd, errno = sys.open(worker, s:join("d"),
                    sys.O.RDONLY | sys.O.DIRECTORY)
                t:assert(fd == nil,
                    "and the merged directory no longer opens")
                t:assert_eq(errno, sys.E.ACCES,
                    "though the provider still permits it: " ..
                    sys.errname(errno))
                -- The provider's own directory is still openable
                -- directly, so the refusal is about the merged set.
                local direct = sys.open(worker, s:in_stratum("top", "d"),
                    sys.O.RDONLY | sys.O.DIRECTORY)
                t:assert(direct, "while the provider's directory opens on its own")
                if direct then sys.close(worker, direct) end
            end)
        end)
    end)

test("the open-time grant is frozen into the descriptor",
    { spec = "PKM *security.open-grant-frozen" }, function(t)
        -- The check-at-open principle applies unchanged: a descriptor
        -- keeps the grant it was opened with.
        stratafs.with(vm, "grant-frozen", {
            { name = "only", flags = { "create" }, entries = { f = "contents" } },
        }, function(s)
            grant_all(t, s:in_stratum("only", "f"), "the object is open")

            kacs.as_dacl_bound(t, vm, function(worker)
                local fd = sys.open(worker, s:join("f"), sys.O.RDONLY)
                t:assert(fd, "the caller opens it for reading")

                -- Now close it down entirely, under the open descriptor.
                local r = kacs.set_sd(vm, s:in_stratum("only", "f"),
                    kacs.deny_all())
                t:assert_eq(r.ret, 0, "the descriptor is revoked: " ..
                    sys.errname(r.errno))

                local read = worker:syscall(sys.NR.read, {
                    args = { fd, 0, 64 }, bufs = { string.rep("\0", 64) },
                    ptrs = { 1 },
                })
                sys.close(worker, fd)
                t:assert_eq(read.out_bufs[1]:sub(1, read.ret), "contents",
                    "the open descriptor still reads: its grant was frozen")

                -- A fresh open is refused, so the revocation did land.
                local again, errno = sys.open(worker, s:join("f"), sys.O.RDONLY)
                t:assert(again == nil, "while a fresh open is refused")
                t:assert_eq(errno, sys.E.ACCES, sys.errname(errno))
            end)
        end)
    end)

test("resolving a name needs traverse on every participant",
    { spec = "PKM *security.rights.resolve" }, function(t)
        stratafs.with(vm, "right-resolve", {
            { name = "top", flags = { "create" }, entries = { ["d/f"] = "x" } },
            { name = "bot", entries = { ["d/g"] = "y" } },
        }, function(s)
            grant_all(t, s:in_stratum("top", "d"))
            grant_all_but(t, s:in_stratum("bot", "d"), SEARCH,
                "one participant loses traverse")

            kacs.as_dacl_bound(t, vm, function(worker)
                local st, errno = sys.stat(worker, s:join("d", "f"))
                t:assert(st == nil, "resolving a name inside is refused")
                t:assert_eq(errno, sys.E.ACCES,
                    "though the name is provided by the participant that " ..
                    "still permits: " .. sys.errname(errno))
            end)

            grant_all(t, s:in_stratum("bot", "d"), "traverse is restored")
            kacs.as_dacl_bound(t, vm, function(worker)
                t:assert(sys.stat(worker, s:join("d", "f")) ~= nil,
                    "and the name resolves again")
            end)
        end)
    end)

test("the search right is traverse on every participating directory",
    { spec = "PKM *security.merged-search-right" }, function(t)
        -- The permission hook maps the kernel's execute intent onto it.
        stratafs.with(vm, "merged-search", {
            { name = "a", flags = { "create" }, entries = { ["d/x"] = "x" } },
            { name = "b", entries = { ["d/y"] = "y" } },
            { name = "c", entries = { ["d/z"] = "z" } },
        }, function(s)
            for _, layer in ipairs({ "a", "b", "c" }) do
                grant_all(t, s:in_stratum(layer, "d"))
            end

            -- Each participant in turn: losing traverse anywhere is
            -- enough to refuse.
            for _, layer in ipairs({ "a", "b", "c" }) do
                grant_all_but(t, s:in_stratum(layer, "d"), SEARCH,
                    "`" .. layer .. "` loses traverse")
                kacs.as_dacl_bound(t, vm, function(worker)
                    local st, errno = sys.stat(worker, s:join("d", "x"))
                    t:assert(st == nil,
                        "with `" .. layer .. "` closed, resolution is refused")
                    t:assert_eq(errno, sys.E.ACCES, sys.errname(errno))
                end)
                grant_all(t, s:in_stratum(layer, "d"))
            end
        end)
    end)

test("enumerating needs traverse and list on every participant",
    { spec = "PKM *security.merged-enumerate-right" }, function(t)
        -- Directory open demands both together, and the check is made
        -- before the listing is captured.
        stratafs.with(vm, "merged-enumerate", {
            { name = "a", flags = { "create" }, entries = { ["d/x"] = "x" } },
            { name = "b", entries = { ["d/y"] = "y" } },
        }, function(s)
            grant_all(t, s:in_stratum("a", "d"))
            grant_all_but(t, s:in_stratum("b", "d"), R.LIST_DIRECTORY,
                "one participant keeps traverse but loses list")

            kacs.as_dacl_bound(t, vm, function(worker)
                -- Traverse alone is enough to resolve through it...
                t:assert(sys.stat(worker, s:join("d", "x")) ~= nil,
                    "resolution still works with traverse alone")
                -- ...but not to enumerate.
                local fd, errno = sys.open(worker, s:join("d"),
                    sys.O.RDONLY | sys.O.DIRECTORY)
                t:assert(fd == nil, "while enumerating is refused")
                t:assert_eq(errno, sys.E.ACCES, sys.errname(errno))
            end)
        end)
    end)

test("enumerating is checked before the listing is captured",
    { spec = "PKM *security.rights.enumerate" }, function(t)
        stratafs.with(vm, "right-enumerate", {
            { name = "open", flags = { "create" }, entries = { ["d/visible"] = "v" } },
            { name = "shut", entries = { ["d/secret"] = "s" } },
        }, function(s)
            grant_all(t, s:in_stratum("open", "d"))
            local r = kacs.set_sd(vm, s:in_stratum("shut", "d"), kacs.deny_all())
            t:assert_eq(r.ret, 0, "one participant is closed: " ..
                sys.errname(r.errno))

            kacs.as_dacl_bound(t, vm, function(worker)
                local fd, errno = sys.open(worker, s:join("d"),
                    sys.O.RDONLY | sys.O.DIRECTORY)
                t:assert(fd == nil,
                    "the open is refused rather than serving a partial listing")
                t:assert_eq(errno, sys.E.ACCES, sys.errname(errno))
            end)
        end)
    end)

test("reading attributes needs search, plus the object's own right",
    { spec = "PKM *security.rights.read-attributes" }, function(t)
        stratafs.with(vm, "right-read-attrs", {
            { name = "only", flags = { "create" }, entries = { ["d/f"] = "x" } },
        }, function(s)
            grant_all(t, s:in_stratum("only", "d"))
            grant_all_but(t, s:in_stratum("only", "d/f"), R.READ_ATTRIBUTES,
                "the object loses read-attributes")

            kacs.as_dacl_bound(t, vm, function(worker)
                local st, errno = sys.stat(worker, s:join("d", "f"))
                t:assert(st == nil, "stat is refused")
                t:assert_eq(errno, sys.E.ACCES,
                    "by the object's own descriptor: " .. sys.errname(errno))
            end)

            -- And the directory half: search is needed too.
            grant_all(t, s:in_stratum("only", "d/f"), "the object is reopened")
            grant_all_but(t, s:in_stratum("only", "d"), SEARCH,
                "and the directory loses traverse")
            kacs.as_dacl_bound(t, vm, function(worker)
                local st, errno = sys.stat(worker, s:join("d", "f"))
                t:assert(st == nil, "stat is refused again")
                t:assert_eq(errno, sys.E.ACCES,
                    "this time by the directory: " .. sys.errname(errno))
            end)
        end)
    end)

test("creating needs add-file on the create stratum's directory",
    { spec = "PKM *security.rights.create" }, function(t)
        -- The mutating right lands on the directory that actually
        -- changes, which for a creation is the create stratum's.
        stratafs.with(vm, "right-create", {
            { name = "high", entries = { ["d/existing"] = "h" } },
            { name = "dest", flags = { "create" }, entries = { ["d/anchor"] = "a" } },
        }, function(s)
            grant_all(t, s:in_stratum("high", "d"))
            grant_all_but(t, s:in_stratum("dest", "d"), R.ADD_FILE,
                "the create stratum's directory loses add-file")

            kacs.as_dacl_bound(t, vm, function(worker)
                local fd, errno = sys.open(worker, s:join("d", "new"),
                    sys.O.WRONLY | sys.O.CREAT | sys.O.EXCL, tonumber("644", 8))
                if fd then sys.close(worker, fd) end
                t:assert(fd == nil, "creation is refused")
                t:assert_eq(errno, sys.E.ACCES,
                    "by the create stratum's directory, not the provider's: " ..
                    sys.errname(errno))
            end)

            grant_all(t, s:in_stratum("dest", "d"), "add-file is restored")
            kacs.as_dacl_bound(t, vm, function(worker)
                local fd = sys.open(worker, s:join("d", "new"),
                    sys.O.WRONLY | sys.O.CREAT | sys.O.EXCL, tonumber("644", 8))
                t:assert(fd, "and creation succeeds")
                if fd then sys.close(worker, fd) end
            end)
            t:assert(sys.stat(vm, s:in_stratum("dest", "d/new")) ~= nil,
                "landing in the create stratum")
        end)
    end)

test("creating a directory needs add-subdirectory",
    { spec = "PKM *security.rights.create" }, function(t)
        stratafs.with(vm, "right-mkdir", {
            { name = "dest", flags = { "create" }, entries = { ["d/anchor"] = "a" } },
        }, function(s)
            grant_all_but(t, s:in_stratum("dest", "d"), R.ADD_SUBDIRECTORY,
                "the directory loses add-subdirectory")
            kacs.as_dacl_bound(t, vm, function(worker)
                local r = sys.mkdir(worker, s:join("d", "sub"))
                t:assert_neq(r.ret, 0, "mkdir is refused")
                t:assert_eq(r.errno, sys.E.ACCES, sys.errname(r.errno))
            end)

            grant_all(t, s:in_stratum("dest", "d"), "and regains it")
            kacs.as_dacl_bound(t, vm, function(worker)
                t:assert_eq(sys.mkdir(worker, s:join("d", "sub")).ret, 0,
                    "mkdir succeeds")
            end)
        end)
    end)

test("the create check falls back to the provider directory",
    { spec = "PKM *security.create-check-falls-back-to-provider-directory" },
    function(t)
        -- A merged directory has a create stratum whether or not that
        -- subdirectory exists, so the check is evaluated against the
        -- descriptor the directory will carry once materialised — the
        -- corresponding provider directory's. Never skipped, and never
        -- substituted with an ancestor's.
        stratafs.with(vm, "create-fallback", {
            { name = "provider", entries = { ["d/existing"] = "p" } },
            { name = "dest", flags = { "create" } },
        }, function(s)
            t:assert(sys.stat(vm, s:in_stratum("dest", "d")) == nil,
                "the create stratum holds no part of the path")
            grant_all_but(t, s:in_stratum("provider", "d"), R.ADD_FILE,
                "the provider directory loses add-file")

            kacs.as_dacl_bound(t, vm, function(worker)
                local fd, errno = sys.open(worker, s:join("d", "new"),
                    sys.O.WRONLY | sys.O.CREAT | sys.O.EXCL, tonumber("644", 8))
                if fd then sys.close(worker, fd) end
                t:assert(fd == nil,
                    "creation is refused against the descriptor the " ..
                    "directory would carry")
                t:assert_eq(errno, sys.E.ACCES, sys.errname(errno))
            end)

            -- The check precedes materialisation, so nothing was left
            -- behind by the refusal.
            t:assert(sys.stat(vm, s:in_stratum("dest", "d")) == nil,
                "and the create stratum is left exactly as it was")

            grant_all(t, s:in_stratum("provider", "d"), "add-file is restored")
            kacs.as_dacl_bound(t, vm, function(worker)
                local fd = sys.open(worker, s:join("d", "new"),
                    sys.O.WRONLY | sys.O.CREAT | sys.O.EXCL, tonumber("644", 8))
                t:assert(fd, "and now creation succeeds")
                if fd then sys.close(worker, fd) end
            end)
            t:assert(sys.stat(vm, s:in_stratum("dest", "d")) ~= nil,
                "materialising the path as part of the operation")
        end)
    end)

test("removing a name needs delete-child on the provider's directory",
    { spec = "PKM *security.rights.remove" }, function(t)
        stratafs.with(vm, "right-remove", {
            { name = "provider", entries = { ["d/f"] = "x" } },
            { name = "dest", flags = { "create" }, entries = { ["d/other"] = "o" } },
        }, function(s)
            grant_all(t, s:in_stratum("dest", "d"))
            close_delete_route(t, s:in_stratum("provider", "d/f"))
            grant_all_but(t, s:in_stratum("provider", "d"), R.DELETE_CHILD,
                "the provider's directory loses delete-child")

            kacs.as_dacl_bound(t, vm, function(worker)
                local r = sys.unlink(worker, s:join("d", "f"))
                t:assert_neq(r.ret, 0, "removal is refused")
                t:assert_eq(r.errno, sys.E.ACCES,
                    "by the provider's directory, which is the one that " ..
                    "would change: " .. sys.errname(r.errno))
            end)

            grant_all(t, s:in_stratum("provider", "d"), "delete-child is restored")
            kacs.as_dacl_bound(t, vm, function(worker)
                t:assert_eq(sys.unlink(worker, s:join("d", "f")).ret, 0,
                    "and removal succeeds")
            end)
        end)
    end)

test("removing a directory needs enumerate as well as delete-child",
    { spec = "PKM *security.rights.rmdir" }, function(t)
        -- Emptiness is judged across every participant, so the caller
        -- must be able to enumerate them all.
        stratafs.with(vm, "right-rmdir", {
            { name = "provider", flags = { "create" },
              entries = { ["d/victim"] = stratafs.DIR } },
            { name = "other", entries = { ["d/victim"] = stratafs.DIR } },
        }, function(s)
            grant_all(t, s:in_stratum("provider", "d"))
            grant_all(t, s:in_stratum("provider", "d/victim"))
            grant_all_but(t, s:in_stratum("other", "d/victim"), R.LIST_DIRECTORY,
                "a participant of the victim loses list")

            kacs.as_dacl_bound(t, vm, function(worker)
                local r = sys.unlink(worker, s:join("d", "victim"),
                    sys.AT_REMOVEDIR)
                t:assert_neq(r.ret, 0, "rmdir is refused")
                t:assert_eq(r.errno, sys.E.ACCES,
                    "because emptiness cannot be judged: " ..
                    sys.errname(r.errno))
            end)

            grant_all(t, s:in_stratum("other", "d/victim"), "list is restored")
            close_delete_route(t, s:in_stratum("provider", "d/victim"))
            grant_all_but(t, s:in_stratum("provider", "d"), R.DELETE_CHILD,
                "and the provider's parent loses delete-child")
            kacs.as_dacl_bound(t, vm, function(worker)
                local r = sys.unlink(worker, s:join("d", "victim"),
                    sys.AT_REMOVEDIR)
                t:assert_neq(r.ret, 0, "rmdir is refused again")
                t:assert_eq(r.errno, sys.E.ACCES,
                    "this time for the removal itself: " .. sys.errname(r.errno))
            end)

            grant_all(t, s:in_stratum("provider", "d"), "and regains it")
            kacs.as_dacl_bound(t, vm, function(worker)
                t:assert_eq(sys.unlink(worker, s:join("d", "victim"),
                    sys.AT_REMOVEDIR).ret, 0, "rmdir succeeds")
            end)
        end)
    end)

test("a rename needs delete-child on the source provider's directory",
    { spec = "PKM *security.rights.rename-source" }, function(t)
        stratafs.with(vm, "right-rename-source", {
            { name = "provider", flags = { "create" },
              entries = { ["d/f"] = "x" } },
        }, function(s)
            close_delete_route(t, s:in_stratum("provider", "d/f"))
            grant_all_but(t, s:in_stratum("provider", "d"), R.DELETE_CHILD,
                "the source's directory loses delete-child")
            kacs.as_dacl_bound(t, vm, function(worker)
                local r = sys.rename(worker, s:join("d", "f"), s:join("d", "moved"))
                t:assert_neq(r.ret, 0, "the rename is refused")
                t:assert_eq(r.errno, sys.E.ACCES, sys.errname(r.errno))
            end)

            grant_all(t, s:in_stratum("provider", "d"), "delete-child is restored")
            kacs.as_dacl_bound(t, vm, function(worker)
                t:assert_eq(sys.rename(worker, s:join("d", "f"),
                    s:join("d", "moved")).ret, 0, "and the rename succeeds")
            end)
        end)
    end)

test("a rename needs add-entry on the destination's directory",
    { spec = "PKM *security.rights.rename-destination" }, function(t)
        -- §4.5.5 requires the source provider to hold the destination's
        -- directory, so it is that directory's descriptor that decides.
        stratafs.with(vm, "right-rename-dest", {
            { name = "provider", flags = { "create" },
              entries = { ["from/f"] = "x", ["to/anchor"] = "a" } },
        }, function(s)
            grant_all(t, s:in_stratum("provider", "from"))
            grant_all_but(t, s:in_stratum("provider", "to"), R.ADD_FILE,
                "the destination's directory loses add-file")

            kacs.as_dacl_bound(t, vm, function(worker)
                local r = sys.rename(worker, s:join("from", "f"),
                    s:join("to", "moved"))
                t:assert_neq(r.ret, 0, "the rename is refused")
                t:assert_eq(r.errno, sys.E.ACCES, sys.errname(r.errno))
            end)

            grant_all(t, s:in_stratum("provider", "to"), "add-file is restored")
            kacs.as_dacl_bound(t, vm, function(worker)
                t:assert_eq(sys.rename(worker, s:join("from", "f"),
                    s:join("to", "moved")).ret, 0, "and it succeeds")
            end)
        end)
    end)

test("renaming a directory needs enumerate on the object being renamed",
    { spec = "PKM *security.rights.rename-directory" }, function(t)
        stratafs.with(vm, "right-rename-dir", {
            { name = "provider", flags = { "create" },
              entries = { ["d/subject/inside"] = "i" } },
        }, function(s)
            grant_all(t, s:in_stratum("provider", "d"))
            grant_all_but(t, s:in_stratum("provider", "d/subject"),
                R.LIST_DIRECTORY, "the directory being renamed loses list")

            kacs.as_dacl_bound(t, vm, function(worker)
                local r = sys.rename(worker, s:join("d", "subject"),
                    s:join("d", "moved"))
                t:assert_neq(r.ret, 0, "the rename is refused")
                t:assert_eq(r.errno, sys.E.ACCES,
                    "the stranded-entries scan needs to enumerate it: " ..
                    sys.errname(r.errno))
            end)

            grant_all(t, s:in_stratum("provider", "d/subject"), "list is restored")
            kacs.as_dacl_bound(t, vm, function(worker)
                t:assert_eq(sys.rename(worker, s:join("d", "subject"),
                    s:join("d", "moved")).ret, 0, "and it succeeds")
            end)
        end)
    end)

test("RENAME_EXCHANGE needs add-entry and delete-child on the one directory",
    { spec = "PKM *security.rights.rename-exchange" }, function(t)
        stratafs.with(vm, "right-exchange", {
            { name = "provider", flags = { "create" },
              entries = { ["d/a"] = "A", ["d/b"] = "B" } },
        }, function(s)
            close_delete_route(t, s:in_stratum("provider", "d/a"))
            close_delete_route(t, s:in_stratum("provider", "d/b"))
            grant_all_but(t, s:in_stratum("provider", "d"), R.DELETE_CHILD,
                "the directory loses delete-child")
            kacs.as_dacl_bound(t, vm, function(worker)
                local r = sys.rename(worker, s:join("d", "a"), s:join("d", "b"),
                    sys.RENAME_EXCHANGE)
                t:assert_neq(r.ret, 0, "the exchange is refused")
                t:assert_eq(r.errno, sys.E.ACCES, sys.errname(r.errno))
            end)

            grant_all(t, s:in_stratum("provider", "d"), "and regains it")
            kacs.as_dacl_bound(t, vm, function(worker)
                t:assert_eq(sys.rename(worker, s:join("d", "a"), s:join("d", "b"),
                    sys.RENAME_EXCHANGE).ret, 0, "and the exchange succeeds")
            end)
            t:assert_eq(vm:read_file(s:join("d", "a")), "B", "with the names swapped")
        end)
    end)

test("a link needs add-file on the source provider's directory",
    { spec = "PKM *security.rights.link" }, function(t)
        stratafs.with(vm, "right-link", {
            { name = "provider", flags = { "create" }, entries = { ["d/f"] = "x" } },
        }, function(s)
            grant_all(t, s:in_stratum("provider", "d/f"))
            grant_all_but(t, s:in_stratum("provider", "d"), R.ADD_FILE,
                "the directory loses add-file")
            kacs.as_dacl_bound(t, vm, function(worker)
                local r = sys.link(worker, s:join("d", "f"), s:join("d", "linked"))
                t:assert_neq(r.ret, 0, "the link is refused")
                t:assert_eq(r.errno, sys.E.ACCES, sys.errname(r.errno))
            end)

            grant_all(t, s:in_stratum("provider", "d"), "add-file is restored")
            kacs.as_dacl_bound(t, vm, function(worker)
                t:assert_eq(sys.link(worker, s:join("d", "f"),
                    s:join("d", "linked")).ret, 0, "and the link is made")
            end)
        end)
    end)

test("a link additionally needs write-attributes on the source object",
    { spec = "PKM *security.link-requires-write-attributes-on-source" }, function(t)
        -- One right the table does not name is required anyway: the
        -- underlying vfs_link makes KACS demand it, and it is an
        -- object-descriptor right rather than a directory one.
        stratafs.with(vm, "right-link-source", {
            { name = "provider", flags = { "create" }, entries = { ["d/f"] = "x" } },
        }, function(s)
            grant_all(t, s:in_stratum("provider", "d"))
            grant_all_but(t, s:in_stratum("provider", "d/f"), R.WRITE_ATTRIBUTES,
                "the source object loses write-attributes")

            kacs.as_dacl_bound(t, vm, function(worker)
                local r = sys.link(worker, s:join("d", "f"), s:join("d", "linked"))
                t:assert_neq(r.ret, 0, "the link is refused")
                t:assert_eq(r.errno, sys.E.ACCES,
                    "by the source object's own descriptor: " ..
                    sys.errname(r.errno))
            end)

            grant_all(t, s:in_stratum("provider", "d/f"), "and it is restored")
            kacs.as_dacl_bound(t, vm, function(worker)
                t:assert_eq(sys.link(worker, s:join("d", "f"),
                    s:join("d", "linked")).ret, 0, "and the link is made")
            end)
        end)
    end)

test("creating or linking an unnamed file needs add-file on the create stratum",
    { spec = "PKM *security.rights.unnamed-file" }, function(t)
        stratafs.with(vm, "right-unnamed", {
            { name = "high", entries = { ["d/x"] = "x" } },
            { name = "dest", flags = { "create" }, entries = { ["d/anchor"] = "a" } },
        }, function(s)
            grant_all(t, s:in_stratum("high", "d"))
            grant_all_but(t, s:in_stratum("dest", "d"), R.ADD_FILE,
                "the create stratum's directory loses add-file")

            kacs.as_dacl_bound(t, vm, function(worker)
                local fd, errno = sys.open(worker, s:join("d"),
                    sys.O.TMPFILE | sys.O.RDWR, tonumber("644", 8))
                if fd then sys.close(worker, fd) end
                t:assert(fd == nil, "creating an unnamed file is refused")
                t:assert_eq(errno, sys.E.ACCES, sys.errname(errno))
            end)

            grant_all(t, s:in_stratum("dest", "d"), "add-file is restored")
            kacs.as_dacl_bound(t, vm, function(worker)
                local fd = sys.open(worker, s:join("d"),
                    sys.O.TMPFILE | sys.O.RDWR, tonumber("644", 8))
                t:assert(fd, "and it succeeds")
                if fd then sys.close(worker, fd) end
            end)
        end)
    end)

test("linking an unnamed file is exempt from the source-object check",
    { spec = "PKM *security.unnamed-link-exempt-from-source-check" }, function(t)
        -- stratafs marks the source for that purpose. An unnamed file
        -- has no descriptor a caller could have been granted rights on
        -- before it existed.
        stratafs.with(vm, "unnamed-exempt", {
            { name = "dest", flags = { "create" }, entries = { ["d/anchor"] = "a" } },
        }, function(s)
            grant_all(t, s:in_stratum("dest", "d"))
            kacs.as_dacl_bound(t, vm, function(worker)
                local fd = sys.open(worker, s:join("d"),
                    sys.O.TMPFILE | sys.O.RDWR, tonumber("644", 8))
                t:assert(fd, "an unnamed file is created")
                sys.write(worker, fd, "contents")

                -- Deny everything on it, then link it: the source check
                -- that a named link would face does not apply.
                local r = worker:syscall(sys.NR.linkat, {
                    args = { fd, 0, sys.AT_FDCWD, 0, sys.AT_EMPTY_PATH },
                    bufs = { sys.cstr(""), sys.cstr(s:join("d", "named")) },
                    ptrs = { 1, 3 },
                })
                sys.close(worker, fd)
                t:assert_eq(r.ret, 0, "and links into place: " ..
                    sys.errname(r.errno))
            end)
            t:assert_eq(vm:read_file(s:in_stratum("dest", "d/named")), "contents",
                "landing in the create stratum")
        end)
    end)

test("copy-up carries no separate authority of its own",
    { spec = "PKM *security.copy-up-requires-no-extra-right" }, function(t)
        -- The same fixture as the rights-table row, stated as the
        -- section's own claim: the caller obtains nothing they did not
        -- already have — the same content, under the same descriptor,
        -- at the same path — and gains no space either, because §4.5.8
        -- accounts the copy to the preserved owner.
        stratafs.with(vm, "copy-up-no-authority", {
            { name = "dest", flags = { "create" } },
            { name = "src", flags = { "ro" }, entries = { f = "original" } },
        }, function(s)
            grant_all(t, s:in_stratum("src", "f"), "the object is writable")
            grant_all_but(t, s:in_stratum("dest"),
                R.ADD_FILE | R.ADD_SUBDIRECTORY,
                "the create stratum grants no right to add an entry")
            local source_sd = kacs.get_sd(vm, s:in_stratum("src", "f"),
                kacs.SI.OWNER | kacs.SI.GROUP | kacs.SI.DACL)

            kacs.as_dacl_bound(t, vm, function(worker)
                local fd = sys.open(worker, s:join("f"), sys.O.RDWR)
                t:assert(fd, "the caller opens the object for writing")
                t:assert_eq(sys.write(worker, fd, "modified").ret, 8,
                    "and the write succeeds")
                sys.close(worker, fd)
            end)

            t:assert_eq(kacs.get_sd(vm, s:in_stratum("dest", "f"),
                kacs.SI.OWNER | kacs.SI.GROUP | kacs.SI.DACL), source_sd,
                "and the copy carries the source's descriptor, so the " ..
                "caller reaches exactly what they already could")
        end)
    end)

test("copy-up requires no right beyond the operation it serves",
    { spec = "PKM *security.rights.copy-up" }, function(t)
        -- It does not require the caller to hold the right to read the
        -- provider's object, nor to add an entry to the create
        -- stratum's directory. Neither copy-up path takes any
        -- authorisation at all.
        stratafs.with(vm, "right-copy-up", {
            { name = "dest", flags = { "create" } },
            { name = "src", flags = { "ro" }, entries = { f = "original" } },
        }, function(s)
            -- The caller may write the object, and nothing else: the
            -- create stratum's root is closed to them entirely.
            grant_all(t, s:in_stratum("src", "f"), "the object is writable")
            -- Only the right to *add an entry* is withdrawn. Traverse
            -- has to stay: the merged directory's search check runs over
            -- every participant and would refuse before copy-up arose.
            grant_all_but(t, s:in_stratum("dest"),
                R.ADD_FILE | R.ADD_SUBDIRECTORY,
                "the create stratum grants no right to add an entry")

            kacs.as_dacl_bound(t, vm, function(worker)
                local fd = sys.open(worker, s:join("f"), sys.O.RDWR)
                t:assert(fd, "the caller opens the object for writing")
                local w = sys.write(worker, fd, "modified")
                sys.close(worker, fd)
                t:assert_eq(w.ret, 8,
                    "and the write succeeds, copying up into a directory " ..
                    "they hold no rights over: " .. sys.errname(w.errno))
            end)

            t:assert_eq(vm:read_file(s:in_stratum("dest", "f")), "modified",
                "the copy is there")
            t:assert_eq(vm:read_file(s:in_stratum("src", "f")), "original",
                "and the source is untouched")
        end)
    end)

test("the mutating right lands on the directory that actually changes",
    { spec = "PKM *security.mutating-right-on-modified-directory" }, function(t)
        -- An entry appears in the create stratum's directory and
        -- disappears from the provider's, so in each case it is that
        -- directory's descriptor that decides. The two coincide only
        -- where the create stratum is also the provider.
        stratafs.with(vm, "mutating-right", {
            { name = "provider", entries = { ["d/existing"] = "p" } },
            { name = "dest", flags = { "create" }, entries = { ["d/anchor"] = "a" } },
        }, function(s)
            -- Creation is governed by the create stratum's directory:
            -- closing the provider's makes no difference to it.
            grant_all(t, s:in_stratum("dest", "d"))
            grant_all_but(t, s:in_stratum("provider", "d"), R.ADD_FILE,
                "the provider's directory loses add-file")
            kacs.as_dacl_bound(t, vm, function(worker)
                local fd = sys.open(worker, s:join("d", "created"),
                    sys.O.WRONLY | sys.O.CREAT | sys.O.EXCL, tonumber("644", 8))
                t:assert(fd, "creation still succeeds")
                if fd then sys.close(worker, fd) end
            end)

            -- Removal is governed by the provider's: closing the create
            -- stratum's makes no difference to it.
            grant_all(t, s:in_stratum("provider", "d"), "the provider is reopened")
            grant_all_but(t, s:in_stratum("dest", "d"), R.DELETE_CHILD,
                "and the create stratum's loses delete-child")
            kacs.as_dacl_bound(t, vm, function(worker)
                t:assert_eq(sys.unlink(worker, s:join("d", "existing")).ret, 0,
                    "removing the provider's entry still succeeds")
            end)
        end)
    end)
