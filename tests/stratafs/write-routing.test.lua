-- PKM §4.5.1 — which single stratum a modification is performed
-- against, when that is decided, and what each operation does about it.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local stratafs = require("helpers.stratafs")

local vm = provium:vm("v", "kernel-only"):boot()

-- The routing fixture: a `ro` provider that will not accept a
-- modification, and a create stratum that strictly outranks it. Any
-- operation that routes leaves a copy in `dest`; any that does not
-- leaves `dest` empty. That single observation is what the whole
-- routing table reduces to.
local function routed(t, name, body, entries)
    stratafs.with(vm, name, {
        { name = "dest", flags = { "create" } },
        { name = "src", flags = { "ro" },
          entries = entries or { f = "original contents" } },
    }, function(s)
        --- Has `name` been copied into the create stratum?
        function s.copied(n)
            return sys.stat(vm, s:in_stratum("dest", n or "f")) ~= nil
        end
        body(s)
    end)
end

test("the predicate reads no credentials, so a refused caller cannot copy up",
    { spec = "PKM *write.accepts-modification" }, function(t)
        -- Load-bearing: were the predicate to consider the caller's
        -- rights, a caller *refused* write access could still provoke a
        -- copy-up. The write would fail, but the copy would have been
        -- published, and the merged path would resolve to a snapshot
        -- the provider's legitimate writer could no longer update. A
        -- caller with no write access at all could freeze any file.
        routed(t, "no-credentials", function(s)
            local r = kacs.set_sd(vm, s:in_stratum("src", "f"),
                kacs.grant(kacs.RIGHT.READ_DATA | kacs.RIGHT.READ_ATTRIBUTES
                    | kacs.RIGHT.READ_CONTROL | kacs.RIGHT.SYNCHRONIZE))
            t:assert_eq(r.ret, 0, "the provider grants read only: " ..
                sys.errname(r.errno))

            kacs.as_dacl_bound(t, vm, function(worker)
                -- Reading is fine.
                local rd = sys.open(worker, s:join("f"), sys.O.RDONLY)
                t:assert(rd, "the caller may read it")
                if rd then sys.close(worker, rd) end

                -- Writing is refused, at the open, by KACS.
                local wr, errno = sys.open(worker, s:join("f"), sys.O.WRONLY)
                t:assert(wr == nil, "and may not write it")
                t:assert_eq(errno, sys.E.ACCES, sys.errname(errno))
            end)

            t:assert(not s.copied(),
                "and nothing was copied up on their account")
        end)
    end)

test("a read-only mount short-circuits every other term",
    { spec = "PKM *write.read-only-mount-short-circuits" }, function(t)
        -- The first term of the routing decision, decided before the
        -- provider or the create stratum is looked at — so it refuses
        -- even a write the provider would have taken in place.
        local s = stratafs.scenario(vm, "ro-short-circuit", {
            { name = "dest", flags = { "create" } },
            { name = "plain", entries = { in_place = "original" } },
            { name = "src", flags = { "ro" }, entries = { would_copy = "original" } },
        }, { mount = false })
        stratafs.mount(vm, { at = s.at, strata = s.strata, flags = sys.MS_RDONLY })
        local ok, err = pcall(function()
            for _, name in ipairs({ "in_place", "would_copy" }) do
                local wrote, errno = stratafs.try_write(vm, s:join(name), "modified")
                t:assert(not wrote, "`" .. name .. "` is refused")
                t:assert_eq(errno, sys.E.ROFS, sys.errname(errno))
            end
            t:assert(sys.stat(vm, s:in_stratum("dest", "would_copy")) == nil,
                "and nothing reached the create stratum")
            t:assert_eq(vm:read_file(s:in_stratum("plain", "in_place")), "original",
                "nor the stratum that would have taken it in place")
        end)
        stratafs.umount(vm, s.at)
        if not ok then error(err, 0) end
    end)

test("a provider that accepts modification takes it in place",
    { spec = "PKM *write.in-place-when-provider-accepts" }, function(t)
        stratafs.with(vm, "in-place", {
            { name = "dest", flags = { "create" } },
            { name = "plain", entries = { f = "original" } },
        }, function(s)
            t:assert(stratafs.try_write(vm, s:join("f"), "modified"),
                "the write succeeds")
            t:assert_eq(vm:read_file(s:in_stratum("plain", "f")), "modified",
                "against the provider's own object")
            t:assert(sys.stat(vm, s:in_stratum("dest", "f")) == nil,
                "with no copy made, though a create stratum outranks it")
        end)
    end)

test("copy-up needs the create stratum to strictly outrank the provider",
    { spec = "PKM *write.copy-up-when-create-outranks" }, function(t)
        -- Where a high-precedence stratum provides a name it will not
        -- accept a write for, no lower stratum can take the write
        -- without the result vanishing behind the provider, so EROFS is
        -- the honest answer.
        stratafs.with(vm, "outranks", {
            { name = "dest", flags = { "create" } },
            { name = "src", flags = { "ro" }, entries = { above = "original" } },
        }, function(s)
            t:assert(stratafs.try_write(vm, s:join("above"), "modified"),
                "with the create stratum above, the write copies up")
            t:assert_eq(vm:read_file(s:in_stratum("dest", "above")), "modified",
                "into the create stratum")
        end)

        stratafs.with(vm, "outranked", {
            { name = "src", flags = { "ro" }, entries = { below = "original" } },
            { name = "dest", flags = { "create" } },
        }, function(s)
            local wrote, errno = stratafs.try_write(vm, s:join("below"), "modified")
            t:assert(not wrote,
                "with the create stratum below the provider, it is refused")
            t:assert_eq(errno, sys.E.ROFS, "with EROFS: " .. sys.errname(errno))
            t:assert(sys.stat(vm, s:in_stratum("dest", "below")) == nil,
                "and nothing is written where the provider would shadow it")
        end)
    end)

test("with no writable stratum at all the route is read-only",
    { spec = "PKM *write.erofs-when-no-writable-stratum" }, function(t)
        stratafs.with(vm, "no-writable", {
            { name = "a", flags = { "ro" }, entries = { f = "original" } },
            { name = "b", flags = { "ro" }, entries = { g = "original" } },
        }, function(s)
            for _, name in ipairs({ "f", "g" }) do
                local wrote, errno = stratafs.try_write(vm, s:join(name), "modified")
                t:assert(not wrote, "`" .. name .. "` is refused")
                t:assert_eq(errno, sys.E.ROFS, sys.errname(errno))
            end
        end)
    end)

test("the route is recomputed for every operation, never cached",
    { spec = "PKM *write.routed-per-operation" }, function(t)
        -- Every mutating entry point calls the rule afresh against the
        -- provider it currently holds, and a descriptor opened before
        -- the predicate changed is not revisited.
        routed(t, "per-operation", function(s)
            -- Open while the provider still accepts, on a plain
            -- stratum, and write in place.
            local plain = s:in_stratum("dest")
            vm:write_file(plain .. "/g", "original")
            local fd = sys.open(vm, s:join("g"), sys.O.RDWR)
            t:assert(fd, "a descriptor is open on a writable provider")
            t:assert_eq(sys.write(vm, fd, "first!!!").ret, 8, "the first write lands")
            t:assert_eq(vm:read_file(plain .. "/g"), "first!!!",
                "in place")

            -- Now make that provider refuse, under the open descriptor.
            t:assert(sys.set_immutable(vm, plain .. "/g", true),
                "the provider stops accepting modification")
            local again = sys.write(vm, fd, "second!!")
            sys.close(vm, fd)
            sys.set_immutable(vm, plain .. "/g", false)

            -- The second write re-routes rather than reusing the first
            -- decision. With the create stratum *being* that provider
            -- there is nowhere to copy to, so it is EROFS — which is
            -- still proof the route was recomputed.
            t:assert_neq(again.ret, 8,
                "the second write does not simply reuse the first route")
            t:assert_eq(again.errno, sys.E.ROFS,
                "it is re-decided and refused: " .. sys.errname(again.errno))
        end)
    end)

-- The routing table, §4.5.1. Every case is the same observation — did
-- a copy appear in the create stratum — so the fixture and the check
-- are shared and only the operation varies. Each row keeps its own
-- citation, because each is a separate promise.

local function routes(t, name, spec_name, op)
    routed(t, name, function(s)
        local fd = sys.open(vm, s:join("f"), sys.O.RDWR)
        t:assert(fd, "the name opens")
        t:assert(not s.copied(),
            "opening alone has not copied anything up")
        local outcome = op(s, fd)
        if fd then sys.close(vm, fd) end
        t:assert(s.copied(), (outcome or "the operation") ..
            " routed, and the copy is in the create stratum")
        t:assert_eq(vm:read_file(s:in_stratum("src", "f")), "original contents",
            "leaving the provider unmodified")
    end)
end

test("writing routes", { spec = "PKM *write.routes.write" }, function(t)
    routes(t, "routes-write", nil, function(s, fd)
        local r = sys.write(vm, fd, "modified")
        t:assert_eq(r.ret, 8, "the write succeeds: " .. sys.errname(r.errno))
        return "a write"
    end)
end)

test("truncating and other setattr route",
    { spec = "PKM *write.routes.setattr" }, function(t)
    routes(t, "routes-setattr", nil, function(s, fd)
        local r = sys.ftruncate(vm, fd, 4)
        t:assert_eq(r.ret, 0, "the truncate succeeds: " .. sys.errname(r.errno))
        return "a truncate"
    end)
end)

test("changing mode, owner or timestamps routes",
    { spec = "PKM *write.routes.metadata" }, function(t)
        for _, case in ipairs({
            { "a chmod", function(s) return sys.chmod(vm, s:join("f"), tonumber("600", 8)) end },
            { "a chown", function(s) return sys.chown(vm, s:join("f"), 4242, 4243) end },
            { "a utimes", function(s) return sys.utimes(vm, s:join("f"), 1000000) end },
        }) do
            routed(t, "routes-metadata-" .. #case[1], function(s)
                local r = case[2](s)
                t:assert_eq(r.ret, 0, case[1] .. " succeeds: " .. sys.errname(r.errno))
                t:assert(s.copied(), case[1] .. " routed into the create stratum")
            end)
        end
    end)

test("setting or removing an extended attribute routes",
    { spec = "PKM *write.routes.xattr" }, function(t)
        routed(t, "routes-setxattr", function(s)
            local r = sys.setxattr(vm, s:join("f"), "user.probe", "value")
            t:assert_eq(r.ret, 0, "setxattr succeeds: " .. sys.errname(r.errno))
            t:assert(s.copied(), "and routed into the create stratum")
            t:assert_eq(sys.getxattr(vm, s:in_stratum("dest", "f"), "user.probe"),
                "value", "with the attribute on the copy")
        end)

        routed(t, "routes-removexattr", function(s)
            -- The attribute has to be on the provider first, which
            -- means putting it there directly.
            local set = sys.setxattr(vm, s:in_stratum("src", "f"), "user.probe", "v")
            t:assert_eq(set.ret, 0, "the provider carries one: " ..
                sys.errname(set.errno))
            local r = sys.removexattr(vm, s:join("f"), "user.probe")
            t:assert_eq(r.ret, 0, "removexattr succeeds: " .. sys.errname(r.errno))
            t:assert(s.copied(), "and routed into the create stratum")
        end)
    end)

test("fallocate routes", { spec = "PKM *write.routes.fallocate" }, function(t)
    routes(t, "routes-fallocate", nil, function(s, fd)
        local r = sys.fallocate(vm, fd, 0, 0, 8192)
        t:assert_eq(r.ret, 0, "fallocate succeeds: " .. sys.errname(r.errno))
        return "a fallocate"
    end)
end)

test("splice into the file routes",
    { spec = "PKM *write.routes.splice" }, function(t)
    routes(t, "routes-splice", nil, function(s, fd)
        local rd, wr = sys.pipe(vm)
        t:assert(rd, "a pipe is available")
        sys.write(vm, wr, "spliced!")
        sys.close(vm, wr)
        local r = sys.splice(vm, rd, fd, 8)
        sys.close(vm, rd)
        t:assert_eq(r.ret, 8, "the splice succeeds: " .. sys.errname(r.errno))
        return "a splice"
    end)
end)

test("copy_file_range routes",
    { spec = "PKM *write.routes.copy-range" }, function(t)
    -- Source and destination both inside the mount: copy_file_range
    -- across superblocks is EXDEV before stratafs sees it.
    routed(t, "routes-copy-range", function(s)
        local fd = sys.open(vm, s:join("f"), sys.O.RDWR)
        local src = sys.open(vm, s:join("donor"), sys.O.RDONLY)
        t:assert(fd and src, "both names open inside the mount")
        t:assert(not s.copied(), "opening alone has copied nothing up")

        local r = sys.copy_file_range(vm, src, fd, 8)
        sys.close(vm, src)
        sys.close(vm, fd)
        t:assert(r.ret > 0, "the copy succeeds: " .. sys.errname(r.errno))
        t:assert(s.copied(),
            "a copy_file_range routed, and the copy is in the create stratum")
        t:assert_eq(vm:read_file(s:in_stratum("src", "f")), "original contents",
            "leaving the provider unmodified")
    end, { f = "original contents", donor = "donated" })
end)

test("establishing a shared writable mapping routes",
    { spec = "PKM *write.routes.shared-mapping" }, function(t)
    routes(t, "routes-mmap", nil, function(s, fd)
        local addr = sys.mmap(vm, fd, 4096,
            sys.PROT.READ | sys.PROT.WRITE, sys.MAP.SHARED)
        t:assert(addr, "the mapping is established")
        if addr then sys.munmap(vm, addr, 4096) end
        return "a shared writable mapping"
    end)
end)

test("reading does not route", { spec = "PKM *write.routes.read-does-not" },
    function(t)
        routed(t, "read-no-route", function(s)
            local fd = sys.open(vm, s:join("f"), sys.O.RDONLY)
            local r = vm:syscall(sys.NR.read, {
                args = { fd, 0, 64 }, bufs = { string.rep("\0", 64) }, ptrs = { 1 },
            })
            t:assert_eq(r.out_bufs[1]:sub(1, r.ret), "original contents",
                "the read is served from the provider")
            local st = sys.stat(vm, s:join("f"))
            local xattr = sys.getxattr(vm, s:join("f"), "user.absent")
            sys.close(vm, fd)
            t:assert(st, "and attributes are readable")
            t:assert(not s.copied(),
                "none of which copied anything up")
        end)
    end)

test("opening does not route", { spec = "PKM *write.routes.open-does-not" },
    function(t)
        routed(t, "open-no-route", function(s)
            for _, flags in ipairs({ sys.O.RDONLY, sys.O.WRONLY, sys.O.RDWR,
                                     sys.O.WRONLY | sys.O.APPEND }) do
                local fd, errno = sys.open(vm, s:join("f"), flags)
                t:assert(fd, "the name opens for access " .. flags .. ": " ..
                    sys.errname(errno or 0))
                if fd then sys.close(vm, fd) end
                t:assert(not s.copied(),
                    "and opening for access " .. flags .. " copied nothing up")
            end
        end)
    end)

test("locking does not route", { spec = "PKM *write.routes.lock-does-not" },
    function(t)
        routed(t, "lock-no-route", function(s)
            local fd = sys.open(vm, s:join("f"), sys.O.RDWR)
            t:assert(fd, "the name opens")
            local ex = sys.flock(vm, fd, sys.LOCK_EX)
            t:assert_eq(ex.ret, 0, "an exclusive lock is taken: " ..
                sys.errname(ex.errno))
            t:assert(not s.copied(), "and did not route")
            local un = sys.flock(vm, fd, sys.LOCK_UN)
            t:assert_eq(un.ret, 0, "and released")
            t:assert(not s.copied(), "which did not route either")
            sys.close(vm, fd)
        end)
    end)

test("the security descriptor routes as an extended attribute",
    { spec = "PKM *write.descriptor-routes-as-xattr" }, function(t)
        -- Both the descriptor and the SACL are reached as extended
        -- attributes, so both route through setxattr like any other.
        -- There is no descriptor-specific code in stratafs at all.
        routed(t, "descriptor-as-xattr", function(s)
            local before = kacs.get_sd(vm, s:in_stratum("src", "f"))
            t:assert(before, "the provider has a descriptor")

            local r = kacs.set_sd(vm, s:join("f"),
                kacs.grant(kacs.RIGHT.GENERIC_ALL))
            t:assert_eq(r.ret, 0, "setting one through the mount succeeds: " ..
                sys.errname(r.errno))
            t:assert(s.copied(),
                "and routed, like any other attribute write")

            local provider_now = kacs.get_sd(vm, s:in_stratum("src", "f"))
            t:assert_eq(provider_now, before,
                "leaving the provider's descriptor untouched")
        end)
    end)

test("an open computes a route but defers acting on it",
    { spec = "PKM *write.open-defers-routing" }, function(t)
        -- A non-in-place route downgrades the provider open to
        -- read-only and strips O_TRUNC, deferring rather than deciding.
        routed(t, "defers", function(s)
            local fd = sys.open(vm, s:join("f"), sys.O.RDWR)
            t:assert(fd, "the name opens read-write")
            t:assert(not s.copied(),
                "and nothing has been copied up by the open alone")

            local w = sys.write(vm, fd, "modified")
            sys.close(vm, fd)
            t:assert_eq(w.ret, 8, "the write succeeds: " .. sys.errname(w.errno))
            t:assert(s.copied(), "and it is the write that copies up")
        end)
    end)

test("O_TRUNC routes at the open",
    { spec = "PKM *write.o-trunc-routes-at-open" }, function(t)
        -- The one case in which an open acts: O_TRUNC on a regular file
        -- is a modification, so it routes, and copies up or fails with
        -- EROFS there and then.
        routed(t, "o-trunc", function(s)
            local fd = sys.open(vm, s:join("f"), sys.O.RDWR | sys.O.TRUNC)
            t:assert(fd, "the open succeeds")
            t:assert(s.copied(),
                "and has already copied up, before any write")
            if fd then sys.close(vm, fd) end
            t:assert_eq(sys.stat(vm, s:in_stratum("dest", "f")).size, 0,
                "with the truncation applied to the copy")
            t:assert_eq(vm:read_file(s:in_stratum("src", "f")), "original contents",
                "and the provider untouched")
        end)

        -- With nowhere to copy to, the refusal is at the open.
        stratafs.with(vm, "o-trunc-erofs", {
            { name = "src", flags = { "ro" }, entries = { f = "original" } },
        }, function(s)
            local fd, errno = sys.open(vm, s:join("f"), sys.O.RDWR | sys.O.TRUNC)
            t:assert(fd == nil, "the open is refused")
            t:assert_eq(errno, sys.E.ROFS,
                "with EROFS at the open: " .. sys.errname(errno))
            t:assert_eq(vm:read_file(s:in_stratum("src", "f")), "original",
                "and nothing was truncated")
        end)
    end)

test("a shared mapping routes on MAYWRITE, not on WRITE",
    { spec = "PKM *write.mmap-routes-on-maywrite" }, function(t)
        -- The test is on VM_SHARED with VM_MAYWRITE — the "could become
        -- writable" bit — because a PROT_READ shared mapping from a
        -- writable descriptor can acquire write access later through
        -- mprotect with no filesystem operation in between.
        routed(t, "maywrite", function(s)
            local fd = sys.open(vm, s:join("f"), sys.O.RDWR)
            local addr = sys.mmap(vm, fd, 4096, sys.PROT.READ, sys.MAP.SHARED)
            t:assert(addr, "a PROT_READ shared mapping from a writable fd")
            if addr then sys.munmap(vm, addr, 4096) end
            sys.close(vm, fd)
            t:assert(s.copied(),
                "routes, because it could become writable through mprotect")
        end)

        routed(t, "private-map", function(s)
            local fd = sys.open(vm, s:join("f"), sys.O.RDWR)
            local addr = sys.mmap(vm, fd, 4096,
                sys.PROT.READ | sys.PROT.WRITE, sys.MAP.PRIVATE)
            t:assert(addr, "a private mapping is established")
            if addr then sys.munmap(vm, addr, 4096) end
            sys.close(vm, fd)
            t:assert(not s.copied(),
                "and does not route: its stores never reach the object")
        end)

        -- A shared mapping that cannot acquire write access does not
        -- route either, so it is allowed even with nowhere to copy to.
        stratafs.with(vm, "map-erofs", {
            { name = "src", flags = { "ro" }, entries = { f = "original" } },
        }, function(s)
            local ro = sys.open(vm, s:join("f"), sys.O.RDONLY)
            local addr = sys.mmap(vm, ro, 4096, sys.PROT.READ, sys.MAP.SHARED)
            t:assert(addr,
                "a shared mapping from a read-only descriptor has no " ..
                "MAYWRITE, so it does not route and is not refused")
            if addr then sys.munmap(vm, addr, 4096) end
            sys.close(vm, ro)

            -- One that can acquire write access does route, and with
            -- nowhere to copy to the mapping is refused.
            local rw = sys.open(vm, s:join("f"), sys.O.RDWR)
            t:assert(rw, "the name still opens read-write on a ro stratum")
            local denied, errno = sys.mmap(vm, rw, 4096,
                sys.PROT.READ, sys.MAP.SHARED)
            if denied then sys.munmap(vm, denied, 4096) end
            sys.close(vm, rw)
            t:assert(denied == nil, "with nowhere to copy to it is refused")
            t:assert_eq(errno, sys.E.ROFS, "with EROFS: " .. sys.errname(errno))
        end)
    end)

test("the copying descriptor follows the copy, and no other does",
    { spec = "PKM *write.copying-descriptor-follows-copy" }, function(t)
        routed(t, "follows-copy", function(s)
            local mine = sys.open(vm, s:join("f"), sys.O.RDWR)
            local other = sys.open(vm, s:join("f"), sys.O.RDONLY)
            t:assert(mine and other, "two descriptors on the original")

            t:assert_eq(sys.write(vm, mine, "modified").ret, 8,
                "one of them writes, copying up")

            -- The copying descriptor refers to the copy from then on.
            sys.lseek(vm, mine, 0, 0)
            local a = vm:syscall(sys.NR.read, {
                args = { mine, 0, 64 }, bufs = { string.rep("\0", 64) }, ptrs = { 1 },
            })
            t:assert_eq(a.out_bufs[1]:sub(1, 8), "modified",
                "and reads the copy through it")

            -- Every other descriptor still refers to the original.
            local b = vm:syscall(sys.NR.read, {
                args = { other, 0, 64 }, bufs = { string.rep("\0", 64) }, ptrs = { 1 },
            })
            t:assert_eq(b.out_bufs[1]:sub(1, b.ret), "original contents",
                "while the other still refers to the original")

            -- And a fresh resolution yields the copy.
            t:assert_eq(vm:read_file(s:join("f")):sub(1, 8), "modified",
                "a fresh resolution of the path yields the copy")
            sys.close(vm, mine)
            sys.close(vm, other)
        end)
    end)

test("a special file is written without routing and is never copied up",
    { spec = "PKM *write.special-files-never-copied-up" }, function(t)
        -- What is written to a FIFO passes to a pipe, not to the
        -- object's contents, so writing does not route. Copying one up
        -- would sever it: a reader holding the original and a writer
        -- that arrived after the copy would hold two unrelated pipes.
        stratafs.with(vm, "special-files", {
            { name = "dest", flags = { "create" } },
            { name = "src", flags = { "ro" } },
        }, function(s)
            local r = sys.mknod(vm, s:in_stratum("src", "fifo"),
                sys.S_IFIFO | tonumber("666", 8))
            t:assert_eq(r.ret, 0, "a FIFO is made in the provider: " ..
                sys.errname(r.errno))

            local st = sys.stat(vm, s:join("fifo"))
            t:assert(st, "it resolves through the mount")
            t:assert_eq(st.mode & 0xF000, sys.S_IFIFO, "as a FIFO")

            -- Opening and writing it does not route: there is nothing
            -- to copy and nothing is copied.
            local rd = sys.open(vm, s:join("fifo"), sys.O.RDONLY | 0x800) -- O_NONBLOCK
            t:assert(rd, "it opens for reading without blocking")
            local wr = sys.open(vm, s:join("fifo"), sys.O.WRONLY)
            t:assert(wr, "and for writing")
            if wr then
                t:assert_eq(sys.write(vm, wr, "through the pipe").ret, 16,
                    "the write goes to the pipe")
                sys.close(vm, wr)
            end
            if rd then sys.close(vm, rd) end
            t:assert(sys.stat(vm, s:in_stratum("dest", "fifo")) == nil,
                "and the FIFO was never copied up")

            -- But an operation that modifies the object itself routes,
            -- and cannot copy up, so it is EROFS.
            local ch = sys.chmod(vm, s:join("fifo"), tonumber("600", 8))
            t:assert_neq(ch.ret, 0, "changing its mode is refused")
            t:assert_eq(ch.errno, sys.E.ROFS,
                "with EROFS, since the copy-up branch cannot apply: " ..
                sys.errname(ch.errno))
            t:assert(sys.stat(vm, s:in_stratum("dest", "fifo")) == nil,
                "and still nothing was copied")
        end)
    end)

test("ioctl on a regular file is refused, and forwarded on anything else",
    { spec = "PKM *write.ioctl-regular-file-refused" }, function(t)
        -- Stored-file ioctls can mutate data and would need
        -- command-by-command routing, which is not implemented;
        -- refusing is the conservative stand-in.
        stratafs.with(vm, "ioctl", {
            { name = "only", flags = { "create" }, entries = { f = "regular" } },
        }, function(s)
            local fd = sys.open(vm, s:join("f"), sys.O.RDONLY)
            t:assert(fd, "the regular file opens")
            local got, errno = sys.ioctl_word(vm, fd, sys.FS_IOC_GETFLAGS, 0)
            sys.close(vm, fd)
            t:assert(got == nil, "an ioctl on it is refused")
            t:assert_eq(errno, sys.E.NOTTY,
                "unconditionally, with ENOTTY: " .. sys.errname(errno))

            -- The same ioctl against the provider directly works, so
            -- the refusal is stratafs's and not the filesystem's.
            local direct = sys.open(vm, s:in_stratum("only", "f"), sys.O.RDONLY)
            local ok = sys.ioctl_word(vm, direct, sys.FS_IOC_GETFLAGS, 0)
            sys.close(vm, direct)
            t:assert(ok ~= nil,
                "while the provider answers it directly")
        end)
    end)
