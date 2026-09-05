-- PKM §3.9.4 — use-time data operations: the right each read, write,
-- lock, mapping, truncation and allocation needs, and what an
-- append-only handle may and may not do.
--
-- Every case here is two native opens of the same file. `kacs_open` is
-- strict, so a descriptor opened with a desired mask carries exactly
-- that mask, and a use-time check is `(granted & required) == required`
-- against that cached mask with no token consulted. The agent is SYSTEM
-- and its privileges are irrelevant to a mask comparison — so "the
-- operation with the right, and the same operation without it" needs no
-- bounded caller, only two handles.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local facs = require("helpers.facs")

local vm = provium:vm("v", "kernel-only"):boot()

local R = kacs.RIGHT
local B = facs.workspace(vm, "use-data")

--- A fresh file granting every right, with `content`.
local function file(name, content)
    local p = B .. "/" .. name
    kacs.set_sd(vm, B, kacs.grant(kacs.ALL_RIGHTS))
    vm:write_file(p, content or string.rep("x", 128))
    kacs.set_sd(vm, p, kacs.grant(kacs.ALL_RIGHTS))
    return p
end

--- Run `fn(fd)` against a handle carrying exactly `mask`.
local function with(t, path, mask, fn)
    local fd = facs.handle(t, vm, path, mask)
    local ok, err = pcall(fn, fd)
    sys.close(vm, fd)
    if not ok then error(err, 0) end
end

test("every operation on an open descriptor is a check against the cached mask",
    { spec = "PKM *facs.use.mask-check-per-operation" }, function(t)
        local p = file("percall")
        -- The DACL grants everything; only the mask the handle asked
        -- for decides, and it decides again on every operation.
        with(t, p, R.READ_DATA, function(fd)
            t:assert_eq(sys.read(vm, fd, 4), "xxxx", "the first read is allowed")
            sys.lseek(vm, fd, 0, 0)
            t:assert_eq(sys.read(vm, fd, 4), "xxxx", "and so is the second")
            local w = sys.write(vm, fd, "y")
            t:assert(w.ret < 0, "a write through the same handle is not: " ..
                sys.errname(w.errno))
        end)
        -- Widening the object's DACL changes nothing for the handle.
        with(t, p, R.READ_DATA, function(fd)
            kacs.set_sd(vm, p, kacs.grant(kacs.ALL_RIGHTS))
            local w = sys.write(vm, fd, "y")
            t:assert(w.ret < 0, "even after the DACL is rewritten to grant everything: " ..
                sys.errname(w.errno))
        end)
    end)

test("each data operation takes the right the table names",
    { spec = "PKM *facs.use.data-operations" }, function(t)
        local p = file("dataops")

        -- Read: FILE_READ_DATA.
        with(t, p, R.READ_DATA, function(fd)
            t:assert_eq(sys.read(vm, fd, 4), "xxxx", "a read handle reads")
        end)

        -- Sequential write with no append intent: FILE_WRITE_DATA.
        with(t, p, R.WRITE_DATA, function(fd)
            t:assert_eq(sys.write(vm, fd, "abc").ret, 3, "a write handle writes")
        end)
        with(t, p, R.READ_DATA | R.APPEND_DATA, function(fd)
            -- Append-only. A no-append override removes the effective
            -- append intent the descriptor's O_APPEND supplies, and the
            -- write then needs FILE_WRITE_DATA.
            local w = facs.pwritev2(vm, fd, "abc", 0, facs.RWF.NOAPPEND)
            t:assert_eq(w.errno, sys.E.ACCES,
                "a no-append override needs FILE_WRITE_DATA: " .. sys.errname(w.errno))
        end)

        -- Directory listing: FILE_LIST_DIRECTORY.
        local d = B .. "/dataops-dir"
        vm:mkdir(d, { parents = true })
        vm:write_file(d .. "/child", "c")
        kacs.set_sd(vm, d, kacs.grant(kacs.ALL_RIGHTS))
        with(t, d, R.LIST_DIRECTORY, function(fd)
            t:assert(sys.getdents(vm, fd), "a listing handle lists")
        end)
        with(t, d, R.TRAVERSE, function(fd)
            local e, errno = sys.getdents(vm, fd)
            t:assert(not e, "one without FILE_LIST_DIRECTORY does not")
            t:assert_eq(errno, sys.E.ACCES, "EACCES: " .. sys.errname(errno or 0))
        end)

        -- ftruncate: FILE_WRITE_DATA. FILE_APPEND_DATA gives the
        -- descriptor FMODE_WRITE, so Linux lets the call reach KACS.
        with(t, p, R.READ_DATA | R.APPEND_DATA, function(fd)
            t:assert_eq(sys.ftruncate(vm, fd, 0).errno, sys.E.ACCES,
                "ftruncate needs FILE_WRITE_DATA")
        end)
        with(t, p, R.WRITE_DATA, function(fd)
            t:assert_eq(sys.ftruncate(vm, fd, 0).ret, 0, "and has it here")
        end)

        -- mmap PROT_READ: FILE_READ_DATA. FILE_EXECUTE alone is a valid
        -- native mask but grants no read.
        file("dataops")
        with(t, p, R.READ_DATA, function(fd)
            local addr = sys.mmap(vm, fd, 4096, sys.PROT.READ, sys.MAP.PRIVATE)
            t:assert(addr, "a read handle maps PROT_READ")
            if addr then sys.munmap(vm, addr, 4096) end
        end)

        -- mmap PROT_EXEC: FILE_EXECUTE.
        with(t, p, R.READ_DATA, function(fd)
            local a, e = sys.mmap(vm, fd, 4096, sys.PROT.READ | facs.PROT_EXEC, sys.MAP.PRIVATE)
            t:assert(not a, "an execute mapping needs FILE_EXECUTE")
            t:assert_eq(e, sys.E.ACCES, "EACCES: " .. sys.errname(e or 0))
        end)
        with(t, p, R.READ_DATA | R.EXECUTE, function(fd)
            local a = sys.mmap(vm, fd, 4096, sys.PROT.READ | facs.PROT_EXEC, sys.MAP.PRIVATE)
            t:assert(a, "and is installed with it")
            if a then sys.munmap(vm, a, 4096) end
        end)

        -- flock LOCK_SH: FILE_READ_DATA. LOCK_EX: write or append.
        with(t, p, R.WRITE_DATA, function(fd)
            t:assert_eq(sys.flock(vm, fd, sys.LOCK_SH | sys.LOCK_NB).errno, sys.E.ACCES,
                "a shared lock needs FILE_READ_DATA")
            t:assert_eq(sys.flock(vm, fd, sys.LOCK_EX | sys.LOCK_NB).ret, 0,
                "an exclusive lock takes FILE_WRITE_DATA")
        end)
        with(t, p, R.READ_DATA, function(fd)
            t:assert_eq(sys.flock(vm, fd, sys.LOCK_SH | sys.LOCK_NB).ret, 0,
                "and a read handle may take a shared one")
            t:assert_eq(sys.flock(vm, fd, sys.LOCK_EX | sys.LOCK_NB).errno, sys.E.ACCES,
                "but not an exclusive one")
        end)
        with(t, p, R.READ_DATA | R.APPEND_DATA, function(fd)
            t:assert_eq(sys.flock(vm, fd, sys.LOCK_EX | sys.LOCK_NB).ret, 0,
                "FILE_APPEND_DATA satisfies the exclusive lock too")
        end)

        -- fallocate allocation: append or write. Mutation: write.
        with(t, p, R.READ_DATA | R.APPEND_DATA, function(fd)
            t:assert_eq(sys.fallocate(vm, fd, facs.FALLOC.ALLOCATE_RANGE, 0, 4096).ret, 0,
                "an allocation takes FILE_APPEND_DATA")
            local m = sys.fallocate(vm, fd,
                facs.FALLOC.PUNCH_HOLE | facs.FALLOC.KEEP_SIZE, 0, 4096)
            t:assert_eq(m.errno, sys.E.ACCES,
                "a mutation needs FILE_WRITE_DATA: " .. sys.errname(m.errno))
        end)
        with(t, p, R.READ_DATA | R.WRITE_DATA, function(fd)
            t:assert_eq(sys.fallocate(vm, fd,
                facs.FALLOC.PUNCH_HOLE | facs.FALLOC.KEEP_SIZE, 0, 4096).ret, 0,
                "and has it here")
        end)
    end)

test("a shared writable mapping needs FILE_WRITE_DATA, not FILE_APPEND_DATA",
    { spec = "PKM *facs.use.mmap-shared-write-needs-write-data" }, function(t)
        local p = file("mmap-shared")
        with(t, p, R.READ_DATA | R.APPEND_DATA, function(fd)
            local a, e = sys.mmap(vm, fd, 4096,
                sys.PROT.READ | sys.PROT.WRITE, sys.MAP.SHARED)
            t:assert(not a, "FILE_APPEND_DATA alone is insufficient")
            t:assert_eq(e, sys.E.ACCES, "EACCES: " .. sys.errname(e or 0))
        end)
        with(t, p, R.READ_DATA | R.WRITE_DATA, function(fd)
            local a = sys.mmap(vm, fd, 4096,
                sys.PROT.READ | sys.PROT.WRITE, sys.MAP.SHARED)
            t:assert(a, "FILE_WRITE_DATA installs it")
            if a then sys.munmap(vm, a, 4096) end
        end)
    end)

test("a private writable mapping needs only FILE_READ_DATA",
    { spec = "PKM *facs.use.mmap-private-needs-read" }, function(t)
        local p = file("mmap-private")
        with(t, p, R.READ_DATA, function(fd)
            local a = sys.mmap(vm, fd, 4096,
                sys.PROT.READ | sys.PROT.WRITE, sys.MAP.PRIVATE)
            t:assert(a, "copy-on-write writes nothing to the file, so read suffices")
            if a then sys.munmap(vm, a, 4096) end
        end)
        -- And an execute-only handle, which grants no read, cannot.
        with(t, p, R.EXECUTE, function(fd)
            local a, e = sys.mmap(vm, fd, 4096,
                sys.PROT.READ | sys.PROT.WRITE, sys.MAP.PRIVATE)
            t:assert(not a, "a handle with no read right cannot: " .. sys.errname(e or 0))
        end)
    end)

test("fsync and fdatasync require SYNCHRONIZE",
    { spec = "PKM *facs.use.fsync-requires-synchronize" }, function(t)
        local p = file("fsync")
        with(t, p, R.READ_DATA | R.WRITE_DATA, function(fd)
            t:assert_eq(sys.fsync(vm, fd).errno, sys.E.ACCES,
                "a handle without SYNCHRONIZE cannot fsync")
            t:assert_eq(vm:syscall(facs.NR.fdatasync, fd).errno, sys.E.ACCES,
                "nor fdatasync")
        end)
        with(t, p, R.READ_DATA | R.WRITE_DATA | R.SYNCHRONIZE, function(fd)
            t:assert_eq(sys.fsync(vm, fd).ret, 0, "and with it, both succeed")
            t:assert_eq(vm:syscall(facs.NR.fdatasync, fd).ret, 0, "fdatasync too")
        end)
    end)

test("a fallocate mode outside the supported set fails closed",
    { spec = "PKM *facs.use.fallocate-unsupported-mode-fails" }, function(t)
        local p = file("falloc-mode")
        with(t, p, R.READ_DATA | R.WRITE_DATA, function(fd)
            -- §3.9.4 names no errno here, only "fails closed". The VFS
            -- validates the mode before reaching the KACS gate and its
            -- supported set is the same one, so what the guest sees is
            -- EOPNOTSUPP rather than the EACCES the KACS classifier
            -- would return on its own (pkm_kunit_file_fallocate_
            -- snapshot_unsupported_fail_closed covers that layer).
            local r = sys.fallocate(vm, fd, facs.FALLOC.NO_HIDE_STALE, 0, 4096)
            t:assert(r.ret ~= 0, "FALLOC_FL_NO_HIDE_STALE is not a supported mode: " ..
                sys.errname(r.errno))
            local b = sys.fallocate(vm, fd, 0x4000, 0, 4096)
            t:assert(b.ret ~= 0, "and neither is an undefined bit: " ..
                sys.errname(b.errno))
            local c = sys.fallocate(vm, fd,
                facs.FALLOC.COLLAPSE_RANGE | facs.FALLOC.KEEP_SIZE, 0, 4096)
            t:assert(c.ret ~= 0, "nor COLLAPSE_RANGE with KEEP_SIZE: " ..
                sys.errname(c.errno))

            -- PUNCH_HOLE additionally requires KEEP_SIZE.
            local ph = sys.fallocate(vm, fd, facs.FALLOC.PUNCH_HOLE, 0, 4096)
            t:assert(ph.ret ~= 0, "PUNCH_HOLE without KEEP_SIZE is refused: " ..
                sys.errname(ph.errno))
            t:assert_eq(sys.fallocate(vm, fd,
                facs.FALLOC.PUNCH_HOLE | facs.FALLOC.KEEP_SIZE, 0, 4096).ret, 0,
                "and with it the same call is allowed")
        end)
    end)

test("an append-only handle allows only true append-intent writes",
    { spec = "PKM *facs.use.append-only-enforcement" }, function(t)
        local p = file("appendonly", "seed")
        with(t, p, R.READ_DATA | R.APPEND_DATA, function(fd)
            -- The descriptor carries O_APPEND, so an ordinary write(2)
            -- is append intent and is allowed.
            t:assert_eq(sys.write(vm, fd, "more").ret, 4,
                "a sequential write on an O_APPEND descriptor is append intent")
            -- A write that overrides that intent is not.
            local w = facs.pwritev2(vm, fd, "no", 0, facs.RWF.NOAPPEND)
            t:assert_eq(w.errno, sys.E.ACCES,
                "one without effective append intent is denied: " .. sys.errname(w.errno))
        end)
        t:assert_eq(sys.stat(vm, p).size, 8, "and the appended bytes landed at the end")
    end)

test("append intent is O_APPEND or RWF_APPEND, and is negated by RWF_NOAPPEND",
    { spec = "PKM *facs.use.append-intent-definition" }, function(t)
        local p = file("appendintent", "seed")
        -- A handle with FILE_APPEND_DATA and no FILE_WRITE_DATA, opened
        -- through the append-only mask, so O_APPEND is set.
        with(t, p, R.READ_DATA | R.APPEND_DATA, function(fd)
            local a = facs.pwritev2(vm, fd, "A", -1, facs.RWF.APPEND)
            t:assert_eq(a.ret, 1, "RWF_APPEND is append intent: " .. sys.errname(a.errno))
            -- RWF_NOAPPEND on the same operation negates the O_APPEND
            -- the descriptor carries, so the write is no longer append
            -- intent and needs FILE_WRITE_DATA.
            local n = facs.pwritev2(vm, fd, "N", -1, facs.RWF.NOAPPEND)
            t:assert(n.ret < 0, "RWF_NOAPPEND negates it")
            t:assert_eq(n.errno, sys.E.ACCES, "EACCES: " .. sys.errname(n.errno))
        end)
        -- With FILE_WRITE_DATA the same RWF_NOAPPEND write is allowed.
        with(t, p, R.READ_DATA | R.WRITE_DATA, function(fd)
            local n = facs.pwritev2(vm, fd, "N", -1, facs.RWF.NOAPPEND)
            t:assert_eq(n.ret, 1, "and FILE_WRITE_DATA permits it: " .. sys.errname(n.errno))
        end)
    end)

test("RWF_APPEND and RWF_NOAPPEND together fail with EACCES",
    { spec = "PKM *facs.use.append-noappend-conflict-eacces" }, function(t)
        local p = file("appendconflict", "seed")
        with(t, p, R.READ_DATA | R.WRITE_DATA | R.APPEND_DATA, function(fd)
            local r = facs.pwritev2(vm, fd, "X", -1, facs.RWF.APPEND | facs.RWF.NOAPPEND)
            t:assert(r.ret < 0, "the pair is contradictory")
            t:assert_eq(r.errno, sys.E.ACCES, "and fails with EACCES: " ..
                sys.errname(r.errno))
        end)
    end)

test("the operations denied on an append-only handle",
    { spec = "PKM *facs.use.append-only-denied-set" }, function(t)
        local p = file("appenddenied", string.rep("s", 4096))
        with(t, p, R.READ_DATA | R.APPEND_DATA, function(fd)
            -- Positioned writes *without effective append intent*. An
            -- append-only handle always carries O_APPEND — kacs_open
            -- sets it whenever FILE_APPEND_DATA is requested without
            -- FILE_WRITE_DATA, and a legacy open cannot produce the
            -- combination any other way — so the way to strip the
            -- intent from a positioned write is RWF_NOAPPEND.
            t:assert_eq(facs.pwritev2(vm, fd, "x", 0, facs.RWF.NOAPPEND).errno,
                sys.E.ACCES, "pwritev2 with an explicit offset and no append intent")
            -- Any write using RWF_NOAPPEND, positioned or not.
            t:assert_eq(facs.pwritev2(vm, fd, "x", -1, facs.RWF.NOAPPEND).errno,
                sys.E.ACCES, "a write using RWF_NOAPPEND")
            -- Shared writable mmap.
            local _, me = sys.mmap(vm, fd, 4096,
                sys.PROT.READ | sys.PROT.WRITE, sys.MAP.SHARED)
            t:assert_eq(me, sys.E.ACCES, "a shared writable mapping")
            -- mprotect upgrade to PROT_WRITE over a shared mapping.
            local addr = sys.mmap(vm, fd, 4096, sys.PROT.READ, sys.MAP.SHARED)
            t:assert(addr, "a shared read mapping is installed")
            t:assert_eq(facs.mprotect(vm, addr, 4096,
                sys.PROT.READ | sys.PROT.WRITE).errno, sys.E.ACCES,
                "an mprotect upgrade to PROT_WRITE")
            sys.munmap(vm, addr, 4096)
            -- The fallocate mutation modes.
            for _, m in ipairs({ { "PUNCH_HOLE", facs.FALLOC.PUNCH_HOLE | facs.FALLOC.KEEP_SIZE },
                                 { "ZERO_RANGE", facs.FALLOC.ZERO_RANGE },
                                 { "UNSHARE_RANGE", facs.FALLOC.UNSHARE_RANGE } }) do
                t:assert_eq(sys.fallocate(vm, fd, m[2], 0, 4096).errno, sys.E.ACCES,
                    "the fallocate mutation mode " .. m[1])
            end
        end)
    end)
