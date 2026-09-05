-- PKM §3.9.4 — fcntl: which commands are descriptor-local and need
-- nothing, which are object-state queries checked against the cached
-- mask, what F_SETFL evaluates, how the lock commands are passed
-- through to the file-lock hook, and what F_NOTIFY takes.
--
-- Two handle shapes carry most of this. A file handle opened with
-- exactly one mask is the ordinary case. A *directory* handle opened
-- with FILE_TRAVERSE alone is the interesting one: kacs_open does not
-- narrow a directory's f_mode, so the descriptor keeps FMODE_READ while
-- its cached mask carries no FILE_READ_DATA — which is the only way to
-- reach a lock or notify check that Linux's own fmode test would
-- otherwise refuse first.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local facs = require("helpers.facs")

local vm = provium:vm("v", "kernel-only"):boot()

local R = kacs.RIGHT
local B = facs.workspace(vm, "use-fcntl")

local function file(name, content)
    local p = B .. "/" .. name
    kacs.set_sd(vm, B, kacs.grant(kacs.ALL_RIGHTS))
    vm:write_file(p, content or "fcntl")
    kacs.set_sd(vm, p, kacs.grant(kacs.ALL_RIGHTS))
    return p
end

local function dir(name)
    local d = B .. "/" .. name
    vm:mkdir(d, { parents = true })
    vm:write_file(d .. "/child", "c")
    kacs.set_sd(vm, d, kacs.grant(kacs.ALL_RIGHTS))
    return d
end

local function with(t, path, mask, fn)
    local fd = facs.handle(t, vm, path, mask)
    local ok, err = pcall(fn, fd)
    sys.close(vm, fd)
    if not ok then error(err, 0) end
end

-- Status flags F_SETFL may change.
local O_NOATIME = 0x40000

test("the object-state fcntl commands are checked against the cached mask",
    { spec = "PKM *facs.use.fcntl" }, function(t)
        local p = file("state")
        local lock = facs.flock_struct(facs.LOCK.RDLCK, 0, 0, 0)

        -- F_GETLK: any data right. An execute-only handle has none.
        with(t, p, R.EXECUTE, function(fd)
            t:assert_eq(facs.fcntl_buf(vm, fd, facs.F.GETLK, lock).errno, sys.E.ACCES,
                "F_GETLK needs a data right")
            t:assert_eq(facs.fcntl_buf(vm, fd, facs.F.OFD_GETLK, lock).errno, sys.E.ACCES,
                "and so does F_OFD_GETLK")
        end)
        with(t, p, R.READ_DATA, function(fd)
            t:assert_eq(facs.fcntl_buf(vm, fd, facs.F.GETLK, lock).ret, 0,
                "FILE_READ_DATA satisfies it")
        end)
        with(t, p, R.APPEND_DATA, function(fd)
            t:assert_eq(facs.fcntl_buf(vm, fd, facs.F.GETLK, lock).ret, 0,
                "and so does FILE_APPEND_DATA — any data right will do")
        end)

        -- FILE_READ_ATTRIBUTES commands.
        with(t, p, R.READ_DATA, function(fd)
            for _, c in ipairs({ { "F_GETLEASE", facs.F.GETLEASE },
                                 { "F_GETPIPE_SZ", facs.F.GETPIPE_SZ },
                                 { "F_GET_SEALS", facs.F.GET_SEALS },
                                 { "F_GET_RW_HINT", facs.F.GET_RW_HINT },
                                 { "F_GET_FILE_RW_HINT", facs.F.GET_FILE_RW_HINT } }) do
                t:assert_eq(facs.fcntl(vm, fd, c[2], 0).errno, sys.E.ACCES,
                    c[1] .. " needs FILE_READ_ATTRIBUTES")
            end
        end)
        with(t, p, R.READ_DATA | R.READ_ATTRIBUTES, function(fd)
            -- Past the KACS check, Linux answers for itself (a regular
            -- file has no pipe size and no seals), which is exactly the
            -- point: the mask check is no longer what refuses them.
            for _, c in ipairs({ { "F_GETLEASE", facs.F.GETLEASE },
                                 { "F_GETPIPE_SZ", facs.F.GETPIPE_SZ },
                                 { "F_GET_SEALS", facs.F.GET_SEALS },
                                 { "F_GET_RW_HINT", facs.F.GET_RW_HINT } }) do
                t:assert_neq(facs.fcntl(vm, fd, c[2], 0).errno, sys.E.ACCES,
                    c[1] .. " is no longer refused by KACS")
            end
        end)

        -- FILE_WRITE_ATTRIBUTES commands.
        with(t, p, R.READ_DATA | R.READ_ATTRIBUTES, function(fd)
            for _, c in ipairs({ { "F_SETPIPE_SZ", facs.F.SETPIPE_SZ, 4096 },
                                 { "F_ADD_SEALS", facs.F.ADD_SEALS, 1 },
                                 { "F_SET_RW_HINT", facs.F.SET_RW_HINT, 0 } }) do
                t:assert_eq(facs.fcntl(vm, fd, c[2], c[3]).errno, sys.E.ACCES,
                    c[1] .. " needs FILE_WRITE_ATTRIBUTES")
            end
        end)
        with(t, p, R.READ_DATA | R.WRITE_ATTRIBUTES, function(fd)
            for _, c in ipairs({ { "F_SETPIPE_SZ", facs.F.SETPIPE_SZ, 4096 },
                                 { "F_ADD_SEALS", facs.F.ADD_SEALS, 1 } }) do
                t:assert_neq(facs.fcntl(vm, fd, c[2], c[3]).errno, sys.E.ACCES,
                    c[1] .. " is no longer refused by KACS")
            end
        end)
    end)

test("F_SETFL cannot clear O_APPEND on an append-only handle",
    { spec = "PKM *facs.use.setfl-clear-append-denied" }, function(t)
        local p = file("setfl-append")
        with(t, p, R.READ_DATA | R.APPEND_DATA, function(fd)
            local flags = facs.fcntl(vm, fd, facs.F.GETFL, 0).ret
            t:assert(flags & sys.O.APPEND ~= 0,
                "an append-only handle carries O_APPEND")
            local r = facs.fcntl(vm, fd, facs.F.SETFL, flags & ~sys.O.APPEND)
            t:assert(r.ret ~= 0, "clearing it is refused")
            t:assert_eq(r.errno, sys.E.ACCES, "EACCES: " .. sys.errname(r.errno))
            -- Setting it is a privilege reduction and always allowed.
            t:assert_eq(facs.fcntl(vm, fd, facs.F.SETFL, flags | sys.O.APPEND).ret, 0,
                "setting it is always allowed")
        end)
        -- A handle carrying FILE_WRITE_DATA may clear it.
        with(t, p, R.READ_DATA | R.WRITE_DATA, function(fd)
            local flags = facs.fcntl(vm, fd, facs.F.GETFL, 0).ret
            t:assert_eq(facs.fcntl(vm, fd, facs.F.SETFL, flags | sys.O.APPEND).ret, 0,
                "O_APPEND is set on a writable handle")
            t:assert_eq(facs.fcntl(vm, fd, facs.F.SETFL, flags & ~sys.O.APPEND).ret, 0,
                "and cleared again, because FILE_WRITE_DATA is granted")
        end)
    end)

test("adding O_NOATIME requires FILE_WRITE_ATTRIBUTES and clearing it does not",
    { spec = "PKM *facs.use.setfl-noatime" }, function(t)
        local p = file("setfl-noatime")
        with(t, p, R.READ_DATA, function(fd)
            local flags = facs.fcntl(vm, fd, facs.F.GETFL, 0).ret
            local r = facs.fcntl(vm, fd, facs.F.SETFL, flags | O_NOATIME)
            t:assert(r.ret ~= 0, "adding O_NOATIME without FILE_WRITE_ATTRIBUTES is refused")
            t:assert_eq(r.errno, sys.E.ACCES, "EACCES: " .. sys.errname(r.errno))
        end)
        with(t, p, R.READ_DATA | R.WRITE_ATTRIBUTES, function(fd)
            local flags = facs.fcntl(vm, fd, facs.F.GETFL, 0).ret
            t:assert_eq(facs.fcntl(vm, fd, facs.F.SETFL, flags | O_NOATIME).ret, 0,
                "with it, O_NOATIME goes on")
            local now = facs.fcntl(vm, fd, facs.F.GETFL, 0).ret
            t:assert(now & O_NOATIME ~= 0, "and is observable through F_GETFL")
        end)
        -- Clearing it is always allowed, even on a handle that could
        -- not have set it.
        with(t, p, R.READ_DATA | R.WRITE_ATTRIBUTES, function(fd)
            local flags = facs.fcntl(vm, fd, facs.F.GETFL, 0).ret
            t:assert_eq(facs.fcntl(vm, fd, facs.F.SETFL, flags | O_NOATIME).ret, 0,
                "O_NOATIME is set")
        end)
        with(t, p, R.READ_DATA, function(fd)
            local flags = facs.fcntl(vm, fd, facs.F.GETFL, 0).ret
            t:assert_eq(facs.fcntl(vm, fd, facs.F.SETFL, flags & ~O_NOATIME).ret, 0,
                "and clearing it needs no right")
        end)
    end)

test("changing only O_NONBLOCK or O_NDELAY needs no KACS right",
    { spec = "PKM *facs.use.setfl-flags-need-no-right" }, function(t)
        local p = file("setfl-flags")
        -- An execute-only handle carries no data right and no attribute
        -- right; the status flags that are neither append nor noatime
        -- are still hers to change.
        with(t, p, R.EXECUTE, function(fd)
            local flags = facs.fcntl(vm, fd, facs.F.GETFL, 0).ret
            t:assert(flags >= 0, "F_GETFL works: " .. flags)
            t:assert_eq(facs.fcntl(vm, fd, facs.F.SETFL, flags | 0x800).ret, 0,
                "O_NONBLOCK goes on")
            t:assert_eq(facs.fcntl(vm, fd, facs.F.SETFL, flags & ~0x800).ret, 0,
                "and comes off again")
        end)
    end)

test("the descriptor-local commands require nothing and do not widen the mask",
    { spec = "PKM *facs.use.fcntl-descriptor-local" }, function(t)
        local p = file("fdlocal")
        with(t, p, R.EXECUTE, function(fd)
            for _, c in ipairs({ { "F_GETFD", facs.F.GETFD, 0 },
                                 { "F_SETFD", facs.F.SETFD, 0 },
                                 { "F_GETFL", facs.F.GETFL, 0 },
                                 { "F_CREATED_QUERY", facs.F.CREATED_QUERY, 0 },
                                 { "F_DUPFD_QUERY", facs.F.DUPFD_QUERY, fd },
                                 { "F_GETOWN", facs.F.GETOWN, 0 },
                                 { "F_SETOWN", facs.F.SETOWN, 0 },
                                 { "F_GETSIG", facs.F.GETSIG, 0 },
                                 { "F_SETSIG", facs.F.SETSIG, 0 } }) do
                t:assert_neq(facs.fcntl(vm, fd, c[2], c[3]).errno, sys.E.ACCES,
                    c[1] .. " is descriptor-local: no KACS right")
            end

            -- F_DUPFD and F_DUPFD_CLOEXEC preserve the same open file
            -- description, so the duplicate carries the same mask —
            -- neither widens it.
            local d = facs.fcntl(vm, fd, facs.F.DUPFD, 0)
            t:assert(d.ret >= 0, "F_DUPFD: " .. sys.errname(d.errno))
            local r = vm:syscall(sys.NR.read, { args = { d.ret, 0, 4 },
                bufs = { string.rep("\0", 4) }, ptrs = { 1 } })
            t:assert_eq(r.errno, sys.E.BADF,
                "the duplicate is as unreadable as the original")
            sys.close(vm, d.ret)

            local c = facs.fcntl(vm, fd, facs.F.DUPFD_CLOEXEC, 0)
            t:assert(c.ret >= 0, "F_DUPFD_CLOEXEC: " .. sys.errname(c.errno))
            t:assert_eq(facs.fcntl(vm, c.ret, facs.F.UNKNOWN, 0).errno, sys.E.ACCES,
                "and is still a managed descriptor")
            sys.close(vm, c.ret)
        end)
    end)

test("the lock commands pass through fcntl to the file-lock hook",
    { spec = "PKM *facs.use.fcntl-lock-passthrough" }, function(t)
        -- A directory handle keeps FMODE_READ whatever its mask says,
        -- so Linux's own fmode test for F_SETLK passes and the decision
        -- is left to the file-lock hook, against the normalised type.
        local d = dir("locks")
        with(t, d, R.TRAVERSE, function(fd)
            -- F_UNLCK is allowed unconditionally there.
            t:assert_eq(facs.fcntl_buf(vm, fd, facs.F.SETLK,
                facs.flock_struct(facs.LOCK.UNLCK, 0, 0, 0)).ret, 0,
                "F_UNLCK needs nothing")
            -- F_RDLCK is normalised to a read and needs FILE_READ_DATA,
            -- which FILE_TRAVERSE is not.
            local rd = facs.fcntl_buf(vm, fd, facs.F.SETLK,
                facs.flock_struct(facs.LOCK.RDLCK, 0, 0, 0))
            t:assert(rd.ret ~= 0, "F_RDLCK is refused")
            t:assert_eq(rd.errno, sys.E.ACCES, "EACCES: " .. sys.errname(rd.errno))
        end)
        with(t, d, R.LIST_DIRECTORY, function(fd)
            t:assert_eq(facs.fcntl_buf(vm, fd, facs.F.SETLK,
                facs.flock_struct(facs.LOCK.RDLCK, 0, 0, 0)).ret, 0,
                "and granted where FILE_LIST_DIRECTORY is")
            t:assert_eq(facs.fcntl_buf(vm, fd, facs.F.SETLK,
                facs.flock_struct(facs.LOCK.UNLCK, 0, 0, 0)).ret, 0,
                "then released")
        end)
        -- F_SETLEASE reaches the lease code rather than being refused
        -- by the fcntl hook: a directory is not leasable, and Linux
        -- says so itself.
        with(t, d, R.TRAVERSE, function(fd)
            t:assert_neq(facs.fcntl(vm, fd, facs.F.SETLEASE, facs.LOCK.UNLCK).errno,
                sys.E.ACCES, "F_SETLEASE is not refused by the fcntl hook")
        end)
    end)

test("installing an F_NOTIFY watch requires FILE_LIST_DIRECTORY",
    { spec = "PKM *facs.use.fcntl-notify-install" }, function(t)
        local d = dir("notify")
        with(t, d, R.TRAVERSE, function(fd)
            -- Removing a watch is a zero event mask and requires nothing.
            t:assert_eq(facs.fcntl(vm, fd, facs.F.NOTIFY, 0).ret, 0,
                "a zero event mask needs nothing")
            t:assert_eq(facs.fcntl(vm, fd, facs.F.NOTIFY, facs.DN.MULTISHOT).ret, 0,
                "and DN_MULTISHOT alone is still a removal")

            for _, e in ipairs({ { "DN_ACCESS", facs.DN.ACCESS },
                                 { "DN_MODIFY", facs.DN.MODIFY },
                                 { "DN_CREATE", facs.DN.CREATE },
                                 { "DN_DELETE", facs.DN.DELETE },
                                 { "DN_RENAME", facs.DN.RENAME },
                                 { "DN_ATTRIB", facs.DN.ATTRIB } }) do
                local r = facs.fcntl(vm, fd, facs.F.NOTIFY, e[2])
                t:assert(r.ret ~= 0, "installing " .. e[1] .. " is refused")
                t:assert_eq(r.errno, sys.E.ACCES, "EACCES: " .. sys.errname(r.errno))
            end
        end)
        with(t, d, R.LIST_DIRECTORY, function(fd)
            t:assert_eq(facs.fcntl(vm, fd, facs.F.NOTIFY,
                facs.DN.MODIFY | facs.DN.MULTISHOT).ret, 0,
                "and granted where FILE_LIST_DIRECTORY is")
            facs.fcntl(vm, fd, facs.F.NOTIFY, 0)
        end)
    end)

test("an unknown DN_ bit on a managed descriptor fails closed",
    { spec = "PKM *facs.use.fcntl-notify-unknown-bits" }, function(t)
        local d = dir("notify-bits")
        -- FILE_LIST_DIRECTORY is granted, so nothing but the unknown
        -- bit can be the reason.
        with(t, d, R.LIST_DIRECTORY, function(fd)
            for _, bit in ipairs({ 0x40, 0x80, 0x1000, 0x40000000 }) do
                local r = facs.fcntl(vm, fd, facs.F.NOTIFY, facs.DN.MODIFY | bit)
                t:assert(r.ret ~= 0, string.format("DN bit 0x%x is not known", bit))
                t:assert_eq(r.errno, sys.E.ACCES, "it fails closed: " ..
                    sys.errname(r.errno))
            end
            facs.fcntl(vm, fd, facs.F.NOTIFY, 0)
        end)
    end)

test("an unknown fcntl command on a managed descriptor fails closed",
    { spec = "PKM *facs.use.unknown-fcntl-fails-closed" }, function(t)
        local p = file("unknown")
        with(t, p, R.READ_DATA | R.WRITE_DATA | R.READ_ATTRIBUTES |
                   R.WRITE_ATTRIBUTES | R.READ_EA | R.WRITE_EA |
                   R.READ_CONTROL | R.SYNCHRONIZE, function(fd)
            -- Every right the handle could carry, and the command is
            -- still refused: it is unknown, not unauthorized.
            for _, cmd in ipairs({ facs.F.UNKNOWN, 4242, 1050 }) do
                local r = facs.fcntl(vm, fd, cmd, 0)
                t:assert(r.ret ~= 0, "fcntl command " .. cmd .. " is unknown")
                t:assert_eq(r.errno, sys.E.ACCES, "it fails closed: " ..
                    sys.errname(r.errno))
            end
        end)

        -- An unmanaged descriptor sits outside the handle check
        -- entirely, so Linux answers instead.
        local pfd = assert(sys.open(vm, "/proc/self/stat", sys.O.RDONLY))
        local r = facs.fcntl(vm, pfd, facs.F.UNKNOWN, 0)
        t:assert_neq(r.errno, sys.E.ACCES,
            "an unmanaged descriptor is not judged at all: " .. sys.errname(r.errno))
        sys.close(vm, pfd)
    end)
