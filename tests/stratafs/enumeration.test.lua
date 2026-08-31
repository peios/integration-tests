-- PKM §4.3.4 — enumerating a merged directory: the union, the capture
-- taken at open, what survives deduplication, ordering, offsets, and
-- the rights it needs.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local stratafs = require("helpers.stratafs")

local vm = provium:vm("v", "kernel-only"):boot()

--- Open a directory and read the whole capture. Returns the entries
--- and the still-open fd, which the capture cases need to keep.
local function open_dir(t, path)
    local fd, errno = sys.open(vm, path, sys.O.RDONLY | sys.O.DIRECTORY)
    t:assert(fd, "opening `" .. path .. "`: " .. sys.errname(errno or 0))
    return fd
end

local function entries(t, fd)
    local all, errno = sys.getdents_all(vm, fd)
    t:assert(all, "getdents64: " .. sys.errname(errno or 0))
    return all
end

local function by_name(list)
    local out = {}
    for _, e in ipairs(list) do out[e.name] = e end
    return out
end

local function listing(t, path)
    local fd = open_dir(t, path)
    local all = entries(t, fd)
    sys.close(vm, fd)
    return all
end

test("a merged directory enumerates the union, each name once",
    { spec = "PKM *resolution.merged-directory-is-union" }, function(t)
        stratafs.with(vm, "union", {
            { name = "s0", entries = { only0 = "0", shared = "0", all = "0" } },
            { name = "s1", entries = { only1 = "1", shared = "1", all = "1" } },
            { name = "s2", entries = { only2 = "2", all = "2" } },
        }, function(s)
            local got = by_name(listing(t, s.at))
            for _, name in ipairs({ "only0", "only1", "only2", "shared", "all" }) do
                t:assert(got[name], "`" .. name .. "` is in the union")
            end

            local count = {}
            for _, e in ipairs(listing(t, s.at)) do
                count[e.name] = (count[e.name] or 0) + 1
            end
            for name, n in pairs(count) do
                t:assert_eq(n, 1, "`" .. name .. "` appears exactly once")
            end
        end)
    end)

test("the listing is captured at open and served for the descriptor's life",
    { spec = "PKM *enumerate.captured-at-open" }, function(t)
        stratafs.with(vm, "captured", {
            { name = "top", flags = { "create" }, entries = { at_open = "a" } },
            { name = "bot", entries = { also = "b" } },
        }, function(s)
            local fd = open_dir(t, s.at)

            -- Everything changes underneath, in both strata, after the
            -- open and before a single entry has been read.
            vm:write_file(s:in_stratum("top", "added_after"), "x")
            vm:unlink(s:in_stratum("top", "at_open"))
            vm:write_file(s:in_stratum("bot", "also_after"), "y")

            local got = by_name(entries(t, fd))
            sys.close(vm, fd)
            t:assert(got.at_open,
                "a name removed after the open is still listed")
            t:assert(got.also, "and one that was there stays")
            t:assert(not got.added_after,
                "a name added after the open is not listed")
            t:assert(not got.also_after, "in any stratum")

            -- A descriptor opened now sees the current state, so the
            -- staleness is the capture's and not the filesystem's.
            local fresh = by_name(listing(t, s.at))
            t:assert(fresh.added_after and fresh.also_after,
                "a fresh open sees the changes")
            t:assert(not fresh.at_open, "and not the removed name")
        end)
    end)

test("a duplicated name is reported as the provider's entry",
    { spec = "PKM *enumerate.duplicate-name-resolves-to-provider" }, function(t)
        -- Deduplication is global and participants are visited
        -- highest-precedence first, so the entry that survives is
        -- always the provider's — including its type and inode.
        stratafs.with(vm, "dedup", {
            { name = "top", entries = { conflict = stratafs.DIR,
                                        ["conflict/x"] = "x" } },
            { name = "mid", entries = { conflict = "a regular file" } },
            { name = "bot", entries = { conflict = stratafs.symlink("somewhere") } },
        }, function(s)
            local got = by_name(listing(t, s.at))
            t:assert(got.conflict, "the name is listed")
            t:assert_eq(got.conflict.type, sys.DT.DIR,
                "with the provider's type, not a lower stratum's")

            local st = sys.stat(vm, s:join("conflict"), { follow = false })
            t:assert_eq(got.conflict.ino, st.ino,
                "and the provider's inode number")
        end)
    end)

test("dot and dot-dot are synthesised once, however many participants",
    { spec = "PKM *enumerate.dot-entries-synthesised-once" }, function(t)
        stratafs.with(vm, "dots", {
            { name = "s0", entries = { ["d/a"] = "a" } },
            { name = "s1", entries = { ["d/b"] = "b" } },
            { name = "s2", entries = { ["d/c"] = "c" } },
            { name = "s3", entries = { ["d/e"] = "e" } },
        }, function(s)
            local dots, dotdots = 0, 0
            for _, e in ipairs(listing(t, s:join("d"))) do
                if e.name == "." then dots = dots + 1 end
                if e.name == ".." then dotdots = dotdots + 1 end
            end
            t:assert_eq(dots, 1, "one `.` across four participants")
            t:assert_eq(dotdots, 1, "and one `..`")
        end)
    end)

test("an entry's inode number is the one stat reports",
    { spec = "PKM *enumerate.entry-inode-matches-stat" }, function(t)
        -- The number comes from looking the child up in the providing
        -- participant and mapping it through the identity table, so
        -- getdents and stat agree.
        stratafs.with(vm, "ino-agrees", {
            { name = "top", entries = { file = "f", dir = stratafs.DIR,
                                        ["dir/x"] = "x" } },
            { name = "bot", entries = { lower = "l", dir = stratafs.DIR,
                                        ["dir/y"] = "y" } },
        }, function(s)
            for _, e in ipairs(listing(t, s.at)) do
                if e.name ~= "." and e.name ~= ".." then
                    local st = sys.stat(vm, s:join(e.name), { follow = false })
                    t:assert(st, "`" .. e.name .. "` stats")
                    t:assert_eq(e.ino, st.ino,
                        "`" .. e.name .. "`: getdents and stat agree on the inode")
                end
            end
        end)
    end)

test("a symlink entry reports its own identity, not its target's",
    { spec = "PKM *enumerate.symlink-entry-reports-itself" }, function(t)
        -- The final component is not followed during the follow-up
        -- lookup that gets the inode number.
        stratafs.with(vm, "symlink-entry", {
            { name = "only", entries = {
                target = "the thing pointed at",
                link = stratafs.symlink("target"),
                broken = stratafs.symlink("nothing-here"),
            } },
        }, function(s)
            local got = by_name(listing(t, s.at))
            t:assert_eq(got.link.type, sys.DT.LNK, "the link is reported as a link")
            t:assert_eq(got.broken.type, sys.DT.LNK, "and so is a dangling one")

            local link = sys.stat(vm, s:join("link"), { follow = false })
            local target = sys.stat(vm, s:join("target"))
            t:assert_eq(got.link.ino, link.ino, "with its own inode number")
            t:assert_neq(got.link.ino, target.ino, "and not its target's")

            -- A dangling link is listed at all, which is the same point
            -- from the other side: nothing followed it.
            t:assert(got.broken, "a dangling link is listed")
        end)
    end)

-- Not reachable: every filesystem available in a kernel-only VM
-- reports a real d_type. tmpfs fills it in from the inode mode, so
-- there is no participant that can supply DT_UNKNOWN for stratafs to
-- pass through. Reaching it wants a participant filesystem that
-- reports DT_UNKNOWN — which is a property of the stratum's
-- filesystem, not of the VM's size.
test("a participant reporting DT_UNKNOWN has it propagated unchanged",
    { spec = "PKM *enumerate.dt-unknown-propagated",
      skip = "needs a participant filesystem that reports DT_UNKNOWN; tmpfs " ..
             "and rootfs both fill d_type in from the inode mode" },
    function(t) t:fail("no participant supplies DT_UNKNOWN") end)

test("shadowed entries leave no trace in the listing",
    { spec = "PKM *enumerate.shadowed-entries-invisible" }, function(t)
        -- No second record is ever allocated, so the entry count
        -- reflects distinct names only.
        stratafs.with(vm, "shadowed", {
            { name = "s0", entries = { a = "0", b = "0", c = "0" } },
            { name = "s1", entries = { a = "1", b = "1", c = "1" } },
            { name = "s2", entries = { a = "2", b = "2", c = "2", d = "2" } },
        }, function(s)
            local all = listing(t, s.at)
            local names = {}
            for _, e in ipairs(all) do
                if e.name ~= "." and e.name ~= ".." then names[#names + 1] = e.name end
            end
            table.sort(names)
            t:assert_eq(table.concat(names, ","), "a,b,c,d",
                "four distinct names from ten entries across three strata")
            t:assert_eq(#all, 6, "and six records including the dot entries")
        end)
    end)

test("entries are ordered stratum-ascending, then by each stratum's readdir",
    { spec = "PKM *enumerate.order-stratum-then-readdir" }, function(t)
        stratafs.with(vm, "order", {
            { name = "s0", entries = { a0 = "x", b0 = "x", c0 = "x" } },
            { name = "s1", entries = { a1 = "x", b1 = "x", a0 = "shadowed" } },
            { name = "s2", entries = { a2 = "x" } },
        }, function(s)
            local all = listing(t, s.at)
            local seen = {}
            for i, e in ipairs(all) do
                if e.name ~= "." and e.name ~= ".." then
                    seen[#seen + 1] = { name = e.name,
                                        stratum = tonumber(e.name:sub(-1)) }
                end
            end
            local highest = -1
            for _, e in ipairs(seen) do
                t:assert(e.stratum >= highest,
                    "`" .. e.name .. "` does not appear before a later stratum's")
                highest = math.max(highest, e.stratum)
            end

            -- Deterministic for one capture: reading it again gives
            -- the same order.
            local again = listing(t, s.at)
            local first, second = {}, {}
            for i, e in ipairs(all) do first[i] = e.name end
            for i, e in ipairs(again) do second[i] = e.name end
            t:assert_eq(table.concat(first, ","), table.concat(second, ","),
                "and the order is stable between captures of the same state")
        end)
    end)

test("a rewind replays the original capture",
    { spec = "PKM *enumerate.changes-after-open-invisible" }, function(t)
        stratafs.with(vm, "rewind", {
            { name = "only", flags = { "create" }, entries = { a = "a", b = "b" } },
        }, function(s)
            local fd = open_dir(t, s.at)
            local first = entries(t, fd)

            vm:write_file(s:in_stratum("only", "added"), "x")

            -- Generic llseek: rewinding replays the capture rather
            -- than rebuilding it.
            local r = sys.lseek(vm, fd, 0, 0)
            t:assert_eq(r.ret, 0, "rewind: " .. sys.errname(r.errno))
            local second = entries(t, fd)
            sys.close(vm, fd)

            local a, b = {}, {}
            for i, e in ipairs(first) do a[i] = e.name end
            for i, e in ipairs(second) do b[i] = e.name end
            t:assert_eq(table.concat(b, ","), table.concat(a, ","),
                "the replay is the original capture, name for name")
            t:assert(not by_name(second).added,
                "and does not pick up what changed in between")
        end)
    end)

test("the participant set is settled at open, by object and not by position",
    { spec = "PKM *enumerate.participant-set-settled-at-open" }, function(t)
        -- The descriptor pins a path reference on each participant.
        -- A participant removed and replaced by another directory at
        -- the same path is a different object and contributes nothing.
        stratafs.with(vm, "settled", {
            { name = "top", entries = { ["d/from_top"] = "t" } },
            { name = "bot", entries = { ["d/from_bot"] = "b" } },
        }, function(s)
            local fd = open_dir(t, s:join("d"))

            stratafs.populate(vm, s.root .. "/replacement",
                { from_replacement = "r" })
            vm:rename(s:in_stratum("bot", "d"), s.root .. "/bot-d-away")
            vm:rename(s.root .. "/replacement", s:in_stratum("bot", "d"))

            local got = by_name(entries(t, fd))
            t:assert(got.from_top, "the surviving participant still lists")
            t:assert(got.from_bot,
                "and the replaced one lists what the pinned object held")
            t:assert(not got.from_replacement,
                "the directory now at that path is a different object")

            -- But resolving a name *through* the same descriptor is an
            -- ordinary live resolution and does see it. The two answers
            -- differ deliberately.
            local live, errno = sys.openat(vm, fd, "from_replacement",
                sys.O.RDONLY)
            t:assert(live,
                "openat through the descriptor resolves the current strata: " ..
                sys.errname(errno or 0))
            if live then sys.close(vm, live) end
            sys.close(vm, fd)
        end)
    end)

test("offsets are plain ordinals with the dot entries first",
    { spec = "PKM *enumerate.offsets-are-plain-ordinals" }, function(t)
        -- No provider cookie, no stratum index, no name hash: the
        -- offset each participant supplied is discarded.
        stratafs.with(vm, "offsets", {
            { name = "s0", entries = { a = "a", b = "b" } },
            { name = "s1", entries = { c = "c" } },
        }, function(s)
            local all = listing(t, s.at)
            t:assert_eq(all[1].name, ".", "offset 0 is `.`")
            t:assert_eq(all[2].name, "..", "offset 1 is `..`")
            for i, e in ipairs(all) do
                t:assert_eq(e.off, i,
                    "entry " .. (i - 1) .. " is followed by ordinal " .. i)
            end
        end)
    end)

test("enumeration needs rights on every participant, or none at all",
    { spec = "PKM *enumerate.requires-rights-on-every-participant" }, function(t)
        -- Checked before the capture is built, and a refusal aborts the
        -- open entirely — so no partial listing covering only the
        -- readable strata can be produced.
        stratafs.with(vm, "enum-rights", {
            { name = "open", entries = { ["d/readable"] = "r" } },
            { name = "shut", entries = { ["d/hidden"] = "h" } },
        }, function(s)
            -- Everything is readable to begin with.
            local before = by_name(listing(t, s:join("d")))
            t:assert(before.readable and before.hidden,
                "both participants contribute while both are readable")

            local r = kacs.set_sd(vm, s:in_stratum("shut", "d"), kacs.deny_all())
            t:assert_eq(r.ret, 0, "one participant is closed: " ..
                sys.errname(r.errno))

            kacs.as_dacl_bound(t, vm, function(worker)
                local fd, errno = sys.open(worker, s:join("d"),
                    sys.O.RDONLY | sys.O.DIRECTORY)
                t:assert(fd == nil,
                    "the open is refused, not served without that stratum")
                t:assert_eq(errno, sys.E.ACCES, sys.errname(errno))

                -- The readable participant's own directory is still
                -- perfectly openable, so the refusal is about the
                -- merged set and not about the caller generally.
                local ok = sys.open(worker, s:in_stratum("open", "d"),
                    sys.O.RDONLY | sys.O.DIRECTORY)
                t:assert(ok, "while the readable stratum opens on its own")
                if ok then sys.close(worker, ok) end
            end)
        end)
    end)
