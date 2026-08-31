-- PKM §4.2.2 — the one filesystem-specific mount parameter: its
-- grammar, its escaping, every way it can be malformed, the generic
-- flags around it, remount, and how it is reported back.

local sys = require("helpers.sys")
local stratafs = require("helpers.stratafs")

local vm = provium:vm("v", "kernel-only"):boot()

-- A stack that parses and mounts, for the cases whose subject is
-- something other than the stack itself.
local function fixture(name, layers)
    return stratafs.scenario(vm, name, layers or {
        { name = "upper", flags = { "create" }, entries = { u = "u" } },
        { name = "lower", flags = { "ro" }, entries = { l = "l" } },
    }, { mount = false })
end

test("strata is the only filesystem option, and every other name is refused",
    { spec = "PKM *mount.only-strata-option" }, function(t)
        local s = fixture("only-strata")
        local valid = stratafs.options(s.strata)

        local rejected = {
            ["an option of its own"] = "sddl=O:SY",
            ["a caching mode"] = valid .. ",cache=none",
            ["an inode-numbering scheme"] = valid .. ",inode=derived",
            ["anything at all beside it"] = valid .. ",verbose",
        }
        for why, data in pairs(rejected) do
            local r = stratafs.try_mount(vm, { at = s.root .. "/mnt-x", data = data })
            t:assert_neq(r.ret, 0, why .. " is refused")
            t:assert_eq(r.errno, sys.E.INVAL,
                why .. ": " .. sys.errname(r.errno))
        end

        -- And the valid one on its own is accepted, so the refusals
        -- above are about the option name and nothing else.
        local ok = stratafs.try_mount(vm, { at = s.at, data = valid })
        t:assert_eq(ok.ret, 0, "strata alone: " .. sys.errname(ok.errno))
        stratafs.umount(vm, s.at)
    end)

test("the grammar is colon-separated strata, each a path with plus-flags",
    { spec = "PKM *mount.strata-option-syntax" }, function(t)
        local s = fixture("syntax", {
            { name = "a", entries = { a = "a" } },
            { name = "b", flags = { "create" }, entries = { b = "b" } },
            { name = "c", flags = { "ro" }, entries = { c = "c" } },
            { name = "d", flags = { "ro", "am" }, entries = { d = "d" } },
        })
        -- Written out longhand, exactly as §4.2.2 spells it, rather
        -- than through the builder — this case is about the string.
        local data = "strata=" .. s:in_stratum("a") ..
            ":" .. s:in_stratum("b") .. "+create" ..
            ":" .. s:in_stratum("c") .. "+ro" ..
            ":" .. s:in_stratum("d") .. "+ro+am"
        local r = stratafs.try_mount(vm, { at = s.at, data = data })
        t:assert_eq(r.ret, 0, "the stack mounts: " .. sys.errname(r.errno))
        for _, name in ipairs({ "a", "b", "c", "d" }) do
            t:assert_eq(vm:read_file(s:join(name)), name,
                "every stratum in the list contributes")
        end
        stratafs.umount(vm, s.at)
    end)

test("a path may carry any of the four escapable bytes",
    { spec = "PKM *mount.escape-set" }, function(t)
        -- The escaped byte is stored literally and the backslash is
        -- consumed, so a stratum directory whose name contains one of
        -- them is reachable.
        local s = stratafs.scenario(vm, "escapes", {
            { name = "plain", flags = { "create" } },
        }, { mount = false })

        local awkward = { colon = ":", plus = "+", comma = ",", backslash = "\\" }
        local strata = { { path = s:in_stratum("plain"), flags = { "create" } } }
        local names = {}
        for name, char in pairs(awkward) do
            local dir = s.root .. "/has" .. char .. "char-" .. name
            stratafs.populate(vm, dir, { [name] = char })
            strata[#strata + 1] = { path = dir }
            names[#names + 1] = name
        end

        -- The builder escapes; that is the point of it living in one
        -- place. Check it produced what §4.2.2 describes before
        -- trusting the mount that follows.
        local data = stratafs.options(strata)
        t:assert_contains(data, "has\\:char", "a colon is escaped")
        t:assert_contains(data, "has\\+char", "a plus is escaped")
        t:assert_contains(data, "has\\,char", "a comma is escaped")
        t:assert_contains(data, "has\\\\char", "a backslash is escaped")

        local r = stratafs.try_mount(vm, { at = s.at, strata = strata })
        t:assert_eq(r.ret, 0, "the stack mounts: " .. sys.errname(r.errno))
        for _, name in ipairs(names) do
            t:assert_eq(vm:read_file(s:join(name)), awkward[name],
                "the stratum whose path holds a literal `" .. awkward[name] ..
                "` is reachable")
        end
        stratafs.umount(vm, s.at)
    end)

test("every malformed value is EINVAL, and none is partly honoured",
    { spec = "PKM *mount.parse-failure-einval" }, function(t)
        -- The parser consumes the whole string and errors on any byte
        -- it cannot classify: there is no skip-and-continue, so a
        -- valid stack followed by rubbish does not mount.
        local s = fixture("parse-whole-string")
        local valid = stratafs.options(s.strata)

        local r = stratafs.try_mount(vm,
            { at = s.at, data = valid .. ",;-not-an-option" })
        t:assert_neq(r.ret, 0, "trailing rubbish is not ignored")
        t:assert_eq(r.errno, sys.E.INVAL, sys.errname(r.errno))
        t:assert(sys.stat(vm, s:join("u")) == nil,
            "and nothing was mounted")
    end)

-- §4.2.2's parse-failure table, one case per row. The fixture and the
-- assertion are identical throughout and only the option string
-- varies, so the shape is factored out — but each row keeps its own
-- test and its own citation, because each is a separate promise.
local parse_fixture = fixture("parse-table")
local A, B = parse_fixture:in_stratum("upper"), parse_fixture:in_stratum("lower")

local refusal_seq = 0
local function refuses(t, why, data)
    refusal_seq = refusal_seq + 1
    local at = parse_fixture.root .. "/mnt-p" .. refusal_seq
    local r = stratafs.try_mount(vm, { at = at, data = data })
    t:assert_neq(r.ret, 0, why .. " is refused")
    t:assert_eq(r.errno, sys.E.INVAL,
        why .. " gives EINVAL, not " .. sys.errname(r.errno))
end

test("the strata option is absent",
    { spec = "PKM *mount.parse.strata-absent" }, function(t)
        -- There is no default stack.
        refuses(t, "no strata= at all", "")
        refuses(t, "an option string naming something else", "ro")
    end)

test("the strata value is empty",
    { spec = "PKM *mount.parse.empty-value" }, function(t)
        refuses(t, "an empty value", "strata=")
    end)

test("an element of the strata value is empty",
    { spec = "PKM *mount.parse.empty-element" }, function(t)
        refuses(t, "an element between two separators", "strata=" .. A .. "::" .. B)
        refuses(t, "a value beginning with a separator", "strata=:" .. A)
        refuses(t, "a value ending with a separator", "strata=" .. A .. ":")
    end)

test("a stratum path is not absolute",
    { spec = "PKM *mount.parse.path-must-be-absolute" }, function(t)
        -- Tested on the raw first byte, which is exact because `/` is
        -- not escapable.
        refuses(t, "a relative path", "strata=relative/path")
        refuses(t, "a relative path after a valid one", "strata=" .. A .. ":also/relative")
        refuses(t, "a path whose first byte is an escape", "strata=\\" .. A)
    end)

test("a stratum path is empty after unescaping",
    { spec = "PKM *mount.parse.empty-after-unescape",
      skip = "defensive branch with no reachable input: the absolute-path " ..
             "test runs first and guarantees at least one byte, so every " ..
             "value that would unescape to nothing is refused before it" },
    function(t)
        t:fail("unreachable")
    end)

test("an unescaped comma appears in a path or a flag",
    { spec = "PKM *mount.parse.unescaped-comma" }, function(t)
        -- The option string is comma-separated at the outer level, so
        -- an unescaped comma ends the value and what follows is read
        -- as another option.
        refuses(t, "a comma inside a path", "strata=" .. A .. ",b")
        refuses(t, "a comma inside a flag token", "strata=" .. A .. "+cre,ate")
    end)

test("an escape is dangling or meaningless",
    { spec = "PKM *mount.parse.invalid-escape" }, function(t)
        refuses(t, "a backslash ending the value", "strata=" .. A .. "\\")
        refuses(t, "a backslash before an unescapable byte", "strata=" .. A .. "\\q")
        refuses(t, "a backslash before a slash", "strata=" .. A .. "\\/sub")
    end)

test("a plus introduces no flag or an unrecognised one",
    { spec = "PKM *mount.parse.unknown-flag" }, function(t)
        -- Flag names are matched by exact length and content, so
        -- neither a prefix nor an extension of a real one is accepted.
        refuses(t, "a plus followed by nothing", "strata=" .. A .. "+")
        refuses(t, "a plus followed by a separator", "strata=" .. A .. "+:" .. B)
        refuses(t, "an unknown flag", "strata=" .. A .. "+rw")
        refuses(t, "a prefix of a real flag", "strata=" .. A .. "+cr")
        refuses(t, "an extension of a real flag", "strata=" .. A .. "+created")
        refuses(t, "a real flag in the wrong case", "strata=" .. A .. "+RO")
    end)

test("a flag is repeated on one stratum",
    { spec = "PKM *mount.parse.duplicate-flag" }, function(t)
        refuses(t, "ro twice", "strata=" .. A .. "+ro+ro")
        refuses(t, "am twice with another flag between", "strata=" .. A .. "+am+ro+am")
    end)

test("there are more than sixteen strata",
    { spec = "PKM *mount.parse.too-many-strata" }, function(t)
        -- The array bound is reached mid-parse.
        local seventeen = {}
        for i = 1, 17 do seventeen[i] = A end
        refuses(t, "a seventeenth stratum", "strata=" .. table.concat(seventeen, ":"))
    end)

test("the strata option appears twice",
    { spec = "PKM *mount.parse.duplicate-strata-option" }, function(t)
        refuses(t, "two strata= options", "strata=" .. A .. ",strata=" .. B)
        refuses(t, "the same strata= option twice", "strata=" .. A .. ",strata=" .. A)
    end)

test("an over-long path is accepted at parse and fails at resolution",
    { spec = "PKM *mount.overlong-path-enametoolong" }, function(t)
        -- Nothing bounds a stratum path at parse time. The failure
        -- comes later, when the stratum path joined with a relative
        -- name exceeds PATH_MAX.
        --
        -- The window is narrow at both ends: mount(2) copies its data
        -- argument into a single page, so the whole option string must
        -- fit in 4096 bytes, while the stratum path plus a name must
        -- not. One stratum, a path just under 4KiB, and a long name.
        local s = fixture("overlong")
        local deep = s.root .. "/deep"
        vm:mkdir(deep, { parents = true })

        local target = 4070
        local component = string.rep("d", 200)
        local path = deep
        while #path + #component + 1 <= target do
            path = path .. "/" .. component
            vm:mkdir(path)
        end
        if #path + 2 <= target then
            path = path .. "/" .. string.rep("t", target - #path - 1)
            vm:mkdir(path)
        end
        t:assert(#path > 4064 and #path < 4089,
            "the stratum path is long but both resolvable and passable (" ..
            #path .. " bytes)")

        local strata = { { path = path } }
        local r = stratafs.try_mount(vm, { at = s.at, strata = strata })
        t:assert_eq(r.ret, 0,
            "the mount is accepted, over-long path and all: " ..
            sys.errname(r.errno))

        local ok, err = pcall(function()
            -- A name long enough that joining it to the stratum path
            -- passes PATH_MAX. It resolves against the mount point
            -- perfectly well; it is the join that cannot be done.
            local name = string.rep("n", 40)
            local st, errno = sys.stat(vm, s:join(name))
            t:assert(st == nil, "the name does not resolve")
            t:assert_eq(errno, sys.E.NAMETOOLONG,
                "because the joined path is too long, not because the name " ..
                "is absent: " .. sys.errname(errno))

            -- A short name in the same mount still resolves the whole
            -- way, so the refusal is about the length and not the
            -- mount being broken.
            local short, serr = sys.stat(vm, s:join("f"))
            t:assert(short == nil and serr == sys.E.NOENT,
                "while a short absent name is a plain ENOENT: " ..
                sys.errname(serr))
        end)
        stratafs.umount(vm, s.at)
        if not ok then error(err, 0) end
    end)

test("a read-only mount refuses every mutation regardless of the stack",
    { spec = "PKM *mount.read-only-refuses-all-mutation" }, function(t)
        -- The superblock's read-only state is the first term of the
        -- routing decision, short-circuiting before the provider or
        -- the create stratum is looked at. So a stack that would
        -- otherwise accept everything still refuses everything.
        local s = fixture("read-only", {
            { name = "upper", flags = { "create" }, entries = { existing = "original" } },
            { name = "lower", entries = { alsohere = "original" } },
        })
        stratafs.mount(vm, { at = s.at, strata = s.strata, flags = sys.MS_RDONLY })
        local ok, err = pcall(function()
            local created, cerr = stratafs.try_create(vm, s:join("new"), "n")
            t:assert(not created, "creation is refused")
            t:assert_eq(cerr, sys.E.ROFS, "with EROFS: " .. sys.errname(cerr))

            -- Both a name provided by the create stratum and one
            -- provided by an ordinary stratum below it: neither is
            -- consulted, because the superblock decided first.
            for _, name in ipairs({ "existing", "alsohere" }) do
                local wrote, werr = stratafs.try_write(vm, s:join(name), "modified")
                t:assert(not wrote, "writing `" .. name .. "` is refused")
                t:assert_eq(werr, sys.E.ROFS,
                    "with EROFS: " .. sys.errname(werr))
            end
            t:assert_eq(vm:read_file(s:in_stratum("upper", "existing")), "original",
                "and nothing reached the strata")

            -- Reads are unaffected.
            t:assert_eq(vm:read_file(s:join("alsohere")), "original",
                "reading still works")
        end)
        stratafs.umount(vm, s.at)
        if not ok then error(err, 0) end
    end)

test("locking and syncing work on a read-only mount",
    { spec = "PKM *mount.locking-unaffected-by-read-only" }, function(t)
        -- Neither modifies an object and neither consults the
        -- superblock's read-only state; a reader of a merged tree may
        -- need both.
        local s = fixture("ro-locking", {
            { name = "only", entries = { f = "content" } },
        })
        stratafs.mount(vm, { at = s.at, strata = s.strata, flags = sys.MS_RDONLY })
        local ok, err = pcall(function()
            local fd = sys.open(vm, s:join("f"), sys.O.RDONLY)
            t:assert(fd, "the file opens for reading")

            -- A shared lock is what a reader of a merged tree wants,
            -- and it is what a read-only mount can be asked for: KACS
            -- maps `flock LOCK_EX` to FILE_WRITE_DATA (§3.9), which no
            -- descriptor on a read-only mount carries. That refusal is
            -- KACS's, not the routing decision's.
            local sh = sys.flock(vm, fd, sys.LOCK_SH)
            t:assert_eq(sh.ret, 0,
                "a shared lock is granted: " .. sys.errname(sh.errno))
            local un = sys.flock(vm, fd, sys.LOCK_UN)
            t:assert_eq(un.ret, 0, "and released: " .. sys.errname(un.errno))

            local sync = sys.fsync(vm, fd)
            t:assert_eq(sync.ret, 0,
                "fsync is not refused: " .. sys.errname(sync.errno))
            sys.close(vm, fd)
        end)
        stratafs.umount(vm, s.at)
        if not ok then error(err, 0) end
    end)

test("a remount may not change the stack",
    { spec = "PKM *mount.remount-rejects-a-changed-stack" }, function(t)
        local s = fixture("remount-change", {
            { name = "a", flags = { "create" }, entries = { a = "a" } },
            { name = "b", entries = { b = "b" } },
            { name = "c", entries = { c = "c" } },
        })
        local stack = { s.strata[1], s.strata[2] }
        stratafs.mount(vm, { at = s.at, strata = stack })

        local function remount(strata)
            return sys.mount(vm, {
                target = s.at,
                flags = sys.MS_REMOUNT,
                data = stratafs.options(strata),
            })
        end

        local ok, err = pcall(function()
            local changes = {
                ["adding a stratum"] = { s.strata[1], s.strata[2], s.strata[3] },
                ["removing one"] = { s.strata[1] },
                ["reordering them"] = { s.strata[2], s.strata[1] },
                ["re-flagging one"] = {
                    { path = s:in_stratum("a"), flags = { "create", "am" } },
                    s.strata[2],
                },
                ["substituting one"] = { s.strata[1], s.strata[3] },
            }
            for why, strata in pairs(changes) do
                local r = remount(strata)
                t:assert_neq(r.ret, 0, why .. " is refused")
                t:assert_eq(r.errno, sys.E.INVAL,
                    why .. ": " .. sys.errname(r.errno))
            end
            t:assert_eq(vm:read_file(s:join("b")), "b",
                "and the mounted stack is untouched by the attempts")
        end)
        stratafs.umount(vm, s.at)
        if not ok then error(err, 0) end
    end)

test("a remount replaying the same stack byte-for-byte is accepted",
    { spec = "PKM *mount.remount-accepts-an-identical-stack" }, function(t)
        -- The test is on the value, not on the presence of the
        -- parameter, so option-string replay works — which is what
        -- lets a tool flip a stratafs mount read-only.
        local s = fixture("remount-replay", {
            { name = "a", flags = { "create" }, entries = { f = "original" } },
        })
        local data = stratafs.options(s.strata)
        stratafs.mount(vm, { at = s.at, strata = s.strata })

        local ok, err = pcall(function()
            local same = sys.mount(vm,
                { target = s.at, flags = sys.MS_REMOUNT, data = data })
            t:assert_eq(same.ret, 0,
                "an identical stack is accepted: " .. sys.errname(same.errno))
            t:assert(stratafs.try_write(vm, s:join("f"), "modified"),
                "and the mount is still writable")

            -- The same replay, plus a generic flag change.
            local ro = sys.mount(vm, {
                target = s.at,
                flags = sys.MS_REMOUNT | sys.MS_RDONLY,
                data = data,
            })
            t:assert_eq(ro.ret, 0,
                "replaying it while going read-only is accepted: " ..
                sys.errname(ro.errno))
            local wrote, werr = stratafs.try_write(vm, s:join("f"), "again!!!")
            t:assert(not wrote, "and the mount is now read-only")
            t:assert_eq(werr, sys.E.ROFS, sys.errname(werr))

            -- A remount naming no stack at all is likewise fine: the
            -- test is on a value, and there is none to compare.
            local bare = sys.mount(vm, { target = s.at, flags = sys.MS_REMOUNT })
            t:assert_eq(bare.ret, 0,
                "a remount naming no stack is accepted: " .. sys.errname(bare.errno))
        end)
        stratafs.umount(vm, s.at)
        if not ok then error(err, 0) end
    end)

test("the mount table reports the option string as it was given",
    { spec = "PKM *mount.options-reported-verbatim" }, function(t)
        -- Nothing abbreviated, no stratum omitted, no path
        -- canonicalised, and an absent stratum reported like any
        -- other. Ordinary paths carry none of `: + , \` or
        -- whitespace, so the reported value is byte-identical.
        local s = fixture("mount-table", {
            { name = "a", flags = { "create" }, entries = { f = "f" } },
            { name = "b", flags = { "ro" } },
        })
        local absent = s.root .. "/never-existed"
        local strata = { s.strata[1], s.strata[2], { path = absent, flags = { "am" } } }
        local data = stratafs.options(strata)
        stratafs.mount(vm, { at = s.at, strata = strata })

        local ok, err = pcall(function()
            local mounts = vm:read_file("/proc/self/mounts")
            local line
            for entry in mounts:gmatch("[^\n]+") do
                local target = entry:match("^%S+ (%S+) ")
                if target == s.at then line = entry end
            end
            t:assert(line, "the mount appears in the mount table")
            t:assert_contains(line, " stratafs ",
                "reported with the filesystem type `stratafs`")
            t:assert_contains(line, data,
                "and the option string verbatim: " .. line)
            t:assert_contains(line, absent,
                "including the stratum that does not exist")
        end)
        stratafs.umount(vm, s.at)
        if not ok then error(err, 0) end
    end)
