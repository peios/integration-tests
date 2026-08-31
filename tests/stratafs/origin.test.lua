-- PKM §4.7 — the one synthetic extended attribute, which reveals which
-- stratum provided a merged path.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local stratafs = require("helpers.stratafs")

local vm = provium:vm("v", "kernel-only"):boot()

local ORIGIN = "system.stratafs.origin"
local STAGING = "security.peios.stratafs_staging"

test("for a non-directory the origin is the provider's path in its stratum",
    { spec = "PKM *origin.value.non-directory" }, function(t)
        stratafs.with(vm, "origin-file", {
            { name = "top", flags = { "create" }, entries = { f = "t" } },
            { name = "bot", entries = { f = "b", ["only_bot"] = "b",
                                        link = stratafs.symlink("f") } },
        }, function(s)
            t:assert_eq(sys.getxattr(vm, s:join("f"), ORIGIN),
                s:in_stratum("top", "f"),
                "the provider's path, not the lower stratum's")
            t:assert_eq(sys.getxattr(vm, s:join("only_bot"), ORIGIN),
                s:in_stratum("bot", "only_bot"),
                "and for a name only the lower stratum holds, that one")

            -- One element only: a non-directory has one provider.
            local value = sys.getxattr(vm, s:join("f"), ORIGIN)
            t:assert(not value:find("\n"),
                "a non-directory's origin names exactly one path")
        end)
    end)

test("for a merged directory the origin names every participant in order",
    { spec = "PKM *origin.value.merged-directory" }, function(t)
        stratafs.with(vm, "origin-dir", {
            { name = "a", flags = { "create" }, entries = { ["d/x"] = "x" } },
            { name = "b", entries = { unrelated = "u" } },
            { name = "c", entries = { ["d/z"] = "z" } },
            { name = "e", entries = { ["d/w"] = "w" } },
        }, function(s)
            local value = sys.getxattr(vm, s:join("d"), ORIGIN)
            t:assert(value, "the merged directory has an origin")

            local lines = {}
            for line in value:gmatch("[^\n]+") do lines[#lines + 1] = line end
            t:assert_eq(#lines, 3,
                "one element per participating directory, and no more")
            t:assert_eq(lines[1], s:in_stratum("a", "d"), "in precedence order")
            t:assert_eq(lines[2], s:in_stratum("c", "d"), "skipping non-participants")
            t:assert_eq(lines[3], s:in_stratum("e", "d"), "to the last")

            -- The mount root is a merged directory of the stratum roots.
            local root = sys.getxattr(vm, s.at, ORIGIN)
            local root_lines = {}
            for line in root:gmatch("[^\n]+") do root_lines[#root_lines + 1] = line end
            t:assert_eq(#root_lines, 4, "the root names every stratum root")
            t:assert_eq(root_lines[1], s:in_stratum("a"), "starting with the first")
        end)
    end)

test("each element is the stratum path, a slash, and the relative path",
    { spec = "PKM *origin.value.element-format" }, function(t)
        stratafs.with(vm, "origin-format", {
            { name = "only", flags = { "create" },
              entries = { ["a/b/c/deep"] = "d" } },
        }, function(s)
            t:assert_eq(sys.getxattr(vm, s:join("a", "b", "c", "deep"), ORIGIN),
                s:in_stratum("only") .. "/a/b/c/deep",
                "the stratum's own path, then a slash, then the relative path")

            -- Where the relative part is empty, no slash is added: the
            -- stratum root's own path stands alone.
            t:assert_eq(sys.getxattr(vm, s.at, ORIGIN), s:in_stratum("only"),
                "and a mount root element is the stratum path unadorned")
        end)
    end)

test("a newline or backslash in a path is escaped, and the inserted slash is not",
    { spec = "PKM *origin.value.escaping" }, function(t)
        -- Those two are the whole escape set.
        stratafs.with(vm, "origin-escaping", {
            { name = "only", flags = { "create" } },
        }, function(s)
            local awkward = "back\\slash"
            vm:mkdir(s:in_stratum("only", awkward), { parents = true })
            vm:write_file(s:in_stratum("only", awkward .. "/f"), "x")

            local value = sys.getxattr(vm, s:join(awkward, "f"), ORIGIN)
            t:assert(value, "the origin reads")
            t:assert(value:find("back\\\\slash", 1, true),
                "a backslash in the path is escaped: " .. value)
            t:assert(value:find("/f", 1, true),
                "while the separator stratafs inserts is not escaped")

            -- A colon, plus or comma is not in the escape set here —
            -- that is the mount-option grammar (§4.2.2), not this one.
            local punctuated = "has:plus+comma,here"
            vm:mkdir(s:in_stratum("only", punctuated), { parents = true })
            local dir_value = sys.getxattr(vm, s:join(punctuated), ORIGIN)
            t:assert(dir_value:find(punctuated, 1, true),
                "and the mount-option escape set does not apply: " .. dir_value)
        end)
    end)

test("there is no trailing newline and no trailing NUL",
    { spec = "PKM *origin.value.no-trailing-terminator" }, function(t)
        stratafs.with(vm, "origin-terminator", {
            { name = "a", flags = { "create" }, entries = { ["d/x"] = "x", f = "f" } },
            { name = "b", entries = { ["d/y"] = "y" } },
        }, function(s)
            for _, path in ipairs({ s:join("f"), s:join("d"), s.at }) do
                local value = sys.getxattr(vm, path, ORIGIN)
                t:assert(value:sub(-1) ~= "\n",
                    "`" .. path .. "` has no trailing newline")
                t:assert(value:sub(-1) ~= "\0",
                    "`" .. path .. "` has no trailing NUL")
            end

            -- And the size reported matches the bytes returned exactly.
            local size = sys.getxattr_size(vm, s:join("d"), ORIGIN)
            t:assert_eq(size, #sys.getxattr(vm, s:join("d"), ORIGIN),
                "the reported size is the value's length, terminator-free")
        end)
    end)

test("a null buffer returns the length, an undersized one ERANGE",
    { spec = "PKM *origin.value.sizing" }, function(t)
        stratafs.with(vm, "origin-sizing", {
            { name = "a", flags = { "create" }, entries = { ["d/x"] = "x" } },
            { name = "b", entries = { ["d/y"] = "y" } },
        }, function(s)
            local needed = sys.getxattr_size(vm, s:join("d"), ORIGIN)
            t:assert(needed and needed > 0,
                "a null buffer returns the length required: " .. tostring(needed))

            local exact = sys.getxattr(vm, s:join("d"), ORIGIN, needed)
            t:assert(exact and #exact == needed,
                "a buffer of exactly that size is enough")

            local short, errno = sys.getxattr(vm, s:join("d"), ORIGIN, needed - 1)
            t:assert(short == nil, "one byte less is refused")
            t:assert_eq(errno, sys.E.RANGE, "with ERANGE: " .. sys.errname(errno))
        end)
    end)

test("the value is synthesised at each read from the current resolution",
    { spec = "PKM *origin.value.synthesised-per-read" }, function(t)
        -- Not stored, and not the value of any attribute on any stratum.
        stratafs.with(vm, "origin-synthesised", {
            { name = "top", flags = { "am" } },
            { name = "bot", entries = { f = "b" } },
        }, function(s)
            t:assert_eq(sys.getxattr(vm, s:join("f"), ORIGIN),
                s:in_stratum("bot", "f"), "the lower stratum provides")

            -- The provider changes; the next read follows it, with
            -- nothing invalidated and no remount.
            vm:write_file(s:in_stratum("top", "f"), "t")
            t:assert_eq(sys.getxattr(vm, s:join("f"), ORIGIN),
                s:in_stratum("top", "f"),
                "and a fresh read names the new provider")

            -- No stratum carries such an attribute of its own.
            t:assert(sys.getxattr(vm, s:in_stratum("top", "f"), ORIGIN) == nil,
                "while the provider object holds no such attribute")
        end)
    end)

test("the attribute is not settable, and neither is anything reserved",
    { spec = "PKM *origin.not-settable" }, function(t)
        -- Any set or removal in the reserved namespace fails with
        -- EPERM, before the provider is reached at all.
        stratafs.with(vm, "origin-not-settable", {
            { name = "only", flags = { "create" }, entries = { f = "x" } },
        }, function(s)
            local set = sys.setxattr(vm, s:join("f"), ORIGIN, "/somewhere")
            t:assert_neq(set.ret, 0, "setting the origin is refused")
            t:assert_eq(set.errno, sys.E.PERM, "with EPERM: " ..
                sys.errname(set.errno))

            local rm = sys.removexattr(vm, s:join("f"), ORIGIN)
            t:assert_neq(rm.ret, 0, "removing it is refused")
            t:assert_eq(rm.errno, sys.E.PERM, "with EPERM: " ..
                sys.errname(rm.errno))

            -- Before the provider is reached: nothing landed there.
            t:assert(sys.getxattr(vm, s:in_stratum("only", "f"), ORIGIN) == nil,
                "and nothing was written to the provider")
        end)
    end)

test("the attribute is hidden from listings",
    { spec = "PKM *origin.hidden-from-listing" }, function(t)
        -- Hiding it keeps archivers, copy tools and backup software
        -- from discovering it, attempting to preserve it, and failing.
        stratafs.with(vm, "origin-hidden", {
            { name = "only", flags = { "create" }, entries = { f = "x" } },
        }, function(s)
            t:assert(sys.getxattr(vm, s:join("f"), ORIGIN) ~= nil,
                "the attribute is readable")
            t:assert_eq(sys.setxattr(vm, s:join("f"), "user.ordinary", "v").ret, 0,
                "and an ordinary one is set beside it")

            local names = sys.listxattr(vm, s:join("f"))
            t:assert(names, "the listing succeeds")
            local seen = {}
            for _, n in ipairs(names) do seen[n] = true end
            t:assert(seen["user.ordinary"], "the ordinary attribute is listed")
            t:assert(not seen[ORIGIN], "and the origin is not")
            t:assert(not seen[STAGING], "nor the staging marker")
        end)
    end)

test("the whole system.stratafs namespace is reserved",
    { spec = "PKM *origin.namespace-reserved" }, function(t)
        stratafs.with(vm, "origin-namespace", {
            { name = "only", flags = { "create" }, entries = { f = "x" } },
        }, function(s)
            for _, name in ipairs({ "system.stratafs.other",
                                    "system.stratafs.anything.at.all",
                                    "system.stratafs." }) do
                local got, errno = sys.getxattr(vm, s:join("f"), name)
                t:assert(got == nil, "reading `" .. name .. "` fails")
                t:assert_eq(errno, sys.E.NODATA,
                    "with ENODATA: " .. sys.errname(errno))

                local set = sys.setxattr(vm, s:join("f"), name, "v")
                t:assert_neq(set.ret, 0, "writing `" .. name .. "` fails")
                t:assert_eq(set.errno, sys.E.PERM,
                    "with EPERM: " .. sys.errname(set.errno))

                local rm = sys.removexattr(vm, s:join("f"), name)
                t:assert_eq(rm.errno, sys.E.PERM,
                    "and removing it likewise: " .. sys.errname(rm.errno))
            end
        end)
    end)

-- Reachable only with a provider that actually carries an attribute of
-- a reserved name, and nothing in this VM can be made to. tmpfs refuses
-- `system.*` names outside the handful it implements (EOPNOTSUPP), and
-- `security.peios.stratafs_staging` is refused by FACS on every path,
-- stratum included. A provider filesystem with a permissive `system.*`
-- namespace would do it.
test("a provider's real attribute of a reserved name is masked",
    { spec = "PKM *origin.masks-provider-attribute",
      skip = "needs a provider carrying a real attribute of a reserved " ..
             "name: tmpfs refuses arbitrary system.* names with EOPNOTSUPP, " ..
             "and the staging attribute is refused by FACS everywhere" },
    function(t) t:fail("no provider can carry one") end)

test("the bare name system.stratafs is not reserved",
    { spec = "PKM *origin.bare-name-not-reserved" }, function(t)
        -- The namespace test is a fixed-length prefix comparison
        -- including the trailing dot, so the bare name falls outside it
        -- and is forwarded to the provider.
        stratafs.with(vm, "origin-bare-name", {
            { name = "only", flags = { "create" }, entries = { f = "x" } },
        }, function(s)
            local got, errno = sys.getxattr(vm, s:join("f"), "system.stratafs")
            t:assert(got == nil, "reading it finds nothing")
            t:assert_neq(errno, sys.E.PERM,
                "but not because it is reserved: " .. sys.errname(errno))
            t:assert_eq(errno, sys.E.NODATA,
                "it is forwarded to the provider, which has no such " ..
                "attribute: " .. sys.errname(errno))
        end)
    end)

test("the staging marker attribute gets the same treatment",
    { spec = "PKM *origin.staging-marker-reserved" }, function(t)
        -- One name wider than the namespace suggests, despite lying
        -- outside system.stratafs.
        stratafs.with(vm, "origin-staging", {
            { name = "only", flags = { "create" }, entries = { f = "x" } },
        }, function(s)
            local got, errno = sys.getxattr(vm, s:join("f"), STAGING)
            t:assert(got == nil, "reading it fails")
            t:assert_eq(errno, sys.E.NODATA, "with ENODATA: " ..
                sys.errname(errno))

            local set = sys.setxattr(vm, s:join("f"), STAGING, "x")
            t:assert_neq(set.ret, 0, "writing it fails")
            t:assert_eq(set.errno, sys.E.PERM, "with EPERM: " ..
                sys.errname(set.errno))

            t:assert_eq(sys.removexattr(vm, s:join("f"), STAGING).errno,
                sys.E.PERM, "and removing it likewise")

            -- Masked from the provider too.
            sys.setxattr(vm, s:in_stratum("only", "f"), STAGING, "real")
            local _, e2 = sys.getxattr(vm, s:join("f"), STAGING)
            t:assert_eq(e2, sys.E.NODATA,
                "a provider's real one is masked, not forwarded")
        end)
    end)

test("reading the origin needs the read-EA right, not merely stat",
    { spec = "PKM *origin.requires-read-ea" }, function(t)
        stratafs.with(vm, "origin-read-ea", {
            { name = "only", flags = { "create" }, entries = { ["d/f"] = "x" } },
        }, function(s)
            local r = kacs.set_sd(vm, s:in_stratum("only", "d/f"),
                kacs.grant_all_but(kacs.RIGHT.READ_EA))
            t:assert_eq(r.ret, 0, "the object loses read-EA: " ..
                sys.errname(r.errno))

            kacs.as_dacl_bound(t, vm, function(worker)
                -- The right to read stat attributes is not sufficient.
                t:assert(sys.stat(worker, s:join("d", "f")) ~= nil,
                    "the caller may still stat it")
                local got, errno = sys.getxattr(worker, s:join("d", "f"), ORIGIN)
                t:assert(got == nil, "but not read the origin")
                t:assert_eq(errno, sys.E.ACCES, "with EACCES: " ..
                    sys.errname(errno))
            end)
        end)
    end)

test("a merged directory's origin needs read-EA on every participant",
    { spec = "PKM *origin.merged-requires-all-participants" }, function(t)
        -- The value names every participating directory, so it
        -- discloses more than any one of them: a caller who may not
        -- know a restricted directory participates must not learn it
        -- from this attribute.
        stratafs.with(vm, "origin-participants", {
            { name = "open", flags = { "create" }, entries = { ["d/x"] = "x" } },
            { name = "shut", entries = { ["d/y"] = "y" } },
        }, function(s)
            local a = kacs.set_sd(vm, s:in_stratum("open", "d"),
                kacs.grant(kacs.ALL_RIGHTS))
            local b = kacs.set_sd(vm, s:in_stratum("shut", "d"),
                kacs.grant_all_but(kacs.RIGHT.READ_EA))
            t:assert_eq(a.ret + b.ret, 0, "the participants are marked")

            kacs.as_dacl_bound(t, vm, function(worker)
                local got, errno = sys.getxattr(worker, s:join("d"), ORIGIN)
                t:assert(got == nil,
                    "the origin is refused where one participant refuses")
                t:assert_eq(errno, sys.E.ACCES, "with EACCES: " ..
                    sys.errname(errno))
            end)

            local c = kacs.set_sd(vm, s:in_stratum("shut", "d"),
                kacs.grant(kacs.ALL_RIGHTS))
            t:assert_eq(c.ret, 0, "read-EA is restored")
            kacs.as_dacl_bound(t, vm, function(worker)
                local got = sys.getxattr(worker, s:join("d"), ORIGIN)
                t:assert(got, "and the origin reads")
                t:assert(got:find(s:in_stratum("shut", "d"), 1, true),
                    "naming the participant that was hidden")
            end)
        end)
    end)

test("reading the origin needs search plus read-EA on every participant",
    { spec = "PKM *security.rights.read-origin" }, function(t)
        -- The read-EA half is what this path gates on directly; the
        -- search half is the ordinary merged-directory search right,
        -- exercised by `security.merged-search-right`, which every
        -- resolution of the directory already goes through.
        stratafs.with(vm, "origin-rights", {
            { name = "a", flags = { "create" }, entries = { ["d/x"] = "x" } },
            { name = "b", entries = { ["d/y"] = "y" } },
            { name = "c", entries = { ["d/z"] = "z" } },
        }, function(s)
            for _, layer in ipairs({ "a", "b", "c" }) do
                kacs.set_sd(vm, s:in_stratum(layer, "d"), kacs.grant(kacs.ALL_RIGHTS))
            end

            -- Each participant in turn: losing read-EA anywhere refuses.
            for _, layer in ipairs({ "a", "b", "c" }) do
                local r = kacs.set_sd(vm, s:in_stratum(layer, "d"),
                    kacs.grant_all_but(kacs.RIGHT.READ_EA))
                t:assert_eq(r.ret, 0, "`" .. layer .. "` loses read-EA: " ..
                    sys.errname(r.errno))
                kacs.as_dacl_bound(t, vm, function(worker)
                    local got, errno = sys.getxattr(worker, s:join("d"), ORIGIN)
                    t:assert(got == nil,
                        "with `" .. layer .. "` closed, the origin is refused")
                    t:assert_eq(errno, sys.E.ACCES, sys.errname(errno))
                end)
                kacs.set_sd(vm, s:in_stratum(layer, "d"),
                    kacs.grant(kacs.ALL_RIGHTS))
            end

            kacs.as_dacl_bound(t, vm, function(worker)
                t:assert(sys.getxattr(worker, s:join("d"), ORIGIN),
                    "and with all three granting, it reads")
            end)
        end)
    end)

test("through a descriptor the origin names the settled participant set",
    { spec = "PKM *origin.fd.settled-participant-set" }, function(t)
        -- A stratum that has joined since is not disclosed, because the
        -- check that would have covered it was never run; a settled
        -- participant that has since ceased to hold the directory is
        -- still named, for the same reason.
        stratafs.with(vm, "origin-fd-settled", {
            { name = "a", flags = { "create" }, entries = { ["d/x"] = "x" } },
            { name = "b", flags = { "am" } },
            { name = "c", entries = { ["d/z"] = "z" } },
        }, function(s)
            local fd = sys.open(vm, s:join("d"), sys.O.RDONLY | sys.O.DIRECTORY)
            t:assert(fd, "the merged directory opens")
            local at_open = sys.fgetxattr(vm, fd, ORIGIN)
            t:assert(at_open, "and the origin reads through it")
            t:assert(not at_open:find(s:in_stratum("b", "d"), 1, true),
                "naming only the participants settled at open")

            -- A stratum joins, and another leaves.
            stratafs.populate(vm, s:in_stratum("b", "d"), { joined = "j" })
            vm:rename(s:in_stratum("c", "d"), s.root .. "/c-d-away")

            local later = sys.fgetxattr(vm, fd, ORIGIN)
            sys.close(vm, fd)
            t:assert_eq(later, at_open,
                "the descriptor still names the set settled at open: " ..
                "the joiner is not disclosed, and the leaver is still named")
        end)
    end)

test("by path the origin names the current participant set",
    { spec = "PKM *origin.by-path.current-participant-set" }, function(t)
        stratafs.with(vm, "origin-by-path", {
            { name = "a", flags = { "create" }, entries = { ["d/x"] = "x" } },
            { name = "b", flags = { "am" } },
        }, function(s)
            local before = sys.getxattr(vm, s:join("d"), ORIGIN)
            t:assert(not before:find(s:in_stratum("b", "d"), 1, true),
                "the absent stratum is not named")

            stratafs.populate(vm, s:in_stratum("b", "d"), { joined = "j" })
            local after = sys.getxattr(vm, s:join("d"), ORIGIN)
            t:assert(after:find(s:in_stratum("b", "d"), 1, true),
                "and once it holds the directory, a fresh read names it")
            t:assert_neq(after, before, "resolved afresh each time")
        end)
    end)

test("through a descriptor the access decision is the one made at open",
    { spec = "PKM *origin.fd.access-decided-at-open" }, function(t)
        -- The read consults a stored verdict rather than re-checking.
        stratafs.with(vm, "origin-fd-access", {
            { name = "a", flags = { "create" }, entries = { ["d/x"] = "x" } },
            { name = "b", entries = { ["d/y"] = "y" } },
        }, function(s)
            kacs.set_sd(vm, s:in_stratum("a", "d"), kacs.grant(kacs.ALL_RIGHTS))
            kacs.set_sd(vm, s:in_stratum("b", "d"), kacs.grant(kacs.ALL_RIGHTS))

            kacs.as_dacl_bound(t, vm, function(worker)
                local fd = sys.open(worker, s:join("d"),
                    sys.O.RDONLY | sys.O.DIRECTORY)
                t:assert(fd, "the caller opens the merged directory")
                t:assert(sys.fgetxattr(worker, fd, ORIGIN),
                    "and reads the origin through it")

                -- Withdraw read-EA from a participant, under the open
                -- descriptor.
                local r = kacs.set_sd(vm, s:in_stratum("b", "d"),
                    kacs.grant_all_but(kacs.RIGHT.READ_EA))
                t:assert_eq(r.ret, 0, "a participant withdraws read-EA: " ..
                    sys.errname(r.errno))

                local again = sys.fgetxattr(worker, fd, ORIGIN)
                t:assert(again,
                    "the descriptor still reads it, on the verdict recorded " ..
                    "at open")
                sys.close(worker, fd)

                -- While a fresh read by path is refused, so the
                -- withdrawal did take effect.
                local byte, errno = sys.getxattr(worker, s:join("d"), ORIGIN)
                t:assert(byte == nil, "while a read by path is refused")
                t:assert_eq(errno, sys.E.ACCES, sys.errname(errno))
            end)
        end)
    end)
