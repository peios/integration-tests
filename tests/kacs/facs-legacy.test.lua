-- PKM §3.9.3 — legacy open compatibility: the core rights an open(2)
-- flag combination requires, the compat rights it asks for and does
-- without, the subset success criterion, and what an O_PATH descriptor
-- is and is not.
--
-- Every denial case runs in a caller stripped of the DACL-bypassing
-- privileges (helpers/kacs.as_dacl_bound): the agent is SYSTEM and
-- would otherwise be granted everything before the DACL is consulted.
-- The *stamped mask* cases need no such caller — a use-time check is a
-- comparison against the cached mask with no token involved — but the
-- mask a legacy open stamps is the subset AccessCheck returned, so the
-- descriptor has to be acquired by the bounded caller too.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local facs = require("helpers.facs")

local vm = provium:vm("v", "kernel-only"):boot()

local R = kacs.RIGHT
local B = facs.workspace(vm, "legacy")

local function at(name) return B .. "/" .. name end

--- (Re)write `path` after restoring a descriptor that grants everything.
---
--- A case that narrowed the DACL leaves the object unwritable by the
--- agent as well: the legacy open path passes no backup or restore
--- intent, so SYSTEM's privileges do not carry it past a DACL either.
local function rewrite(path, content)
    kacs.set_sd(vm, path, kacs.grant(kacs.ALL_RIGHTS))
    vm:write_file(path, content)
end

--- Grant exactly `mask` on `path`, then legacy-open it with `flags` in a
--- DACL-bound worker. Returns `{fd, errno}` with the descriptor closed.
local function legacy(t, path, mask, flags)
    t:assert_eq(kacs.set_sd(vm, path, kacs.grant(mask)).ret, 0, "descriptor written")
    local out
    kacs.as_dacl_bound(t, vm, function(w)
        local fd, errno = sys.open(w, path, flags)
        if fd then sys.close(w, fd) end
        out = { fd = fd, errno = errno }
    end)
    return out
end

test("O_RDONLY, O_WRONLY and O_RDWR each name their own core set",
    { spec = "PKM *facs.legacy.core-rights" }, function(t)
        local p = at("core")
        vm:write_file(p, "core")
        local ALL = kacs.ALL_RIGHTS

        -- O_RDONLY: FILE_READ_DATA | FILE_READ_ATTRIBUTES.
        t:assert(legacy(t, p, ALL, sys.O.RDONLY).fd, "O_RDONLY opens with every right granted")
        t:assert(not legacy(t, p, ALL & ~R.READ_DATA, sys.O.RDONLY).fd,
            "and is refused without FILE_READ_DATA")
        t:assert(not legacy(t, p, ALL & ~R.READ_ATTRIBUTES, sys.O.RDONLY).fd,
            "or without FILE_READ_ATTRIBUTES")
        t:assert(legacy(t, p, ALL & ~R.WRITE_DATA, sys.O.RDONLY).fd,
            "FILE_WRITE_DATA is no part of its core")

        -- O_WRONLY: FILE_WRITE_DATA | FILE_READ_ATTRIBUTES.
        t:assert(legacy(t, p, ALL, sys.O.WRONLY).fd, "O_WRONLY opens with every right granted")
        t:assert(not legacy(t, p, ALL & ~R.WRITE_DATA, sys.O.WRONLY).fd,
            "and is refused without FILE_WRITE_DATA")
        t:assert(legacy(t, p, ALL & ~R.READ_DATA, sys.O.WRONLY).fd,
            "FILE_READ_DATA is no part of its core")

        -- O_RDWR: both data rights and FILE_READ_ATTRIBUTES.
        t:assert(legacy(t, p, ALL, sys.O.RDWR).fd, "O_RDWR opens with every right granted")
        t:assert(not legacy(t, p, ALL & ~R.READ_DATA, sys.O.RDWR).fd,
            "and is refused without FILE_READ_DATA")
        t:assert(not legacy(t, p, ALL & ~R.WRITE_DATA, sys.O.RDWR).fd,
            "or without FILE_WRITE_DATA")
    end)

test("a directory's core set excludes FILE_LIST_DIRECTORY",
    { spec = "PKM *facs.legacy.directory-core-excludes-list" }, function(t)
        local d = at("dircore")
        vm:mkdir(d, { parents = true })
        vm:write_file(d .. "/child", "c")
        local ALL = kacs.ALL_RIGHTS

        -- Core is FILE_READ_ATTRIBUTES | FILE_TRAVERSE.
        t:assert(not legacy(t, d, ALL & ~R.TRAVERSE, sys.O.RDONLY | sys.O.DIRECTORY).fd,
            "a directory without FILE_TRAVERSE cannot be opened O_RDONLY")
        t:assert(not legacy(t, d, ALL & ~R.READ_ATTRIBUTES, sys.O.RDONLY | sys.O.DIRECTORY).fd,
            "nor one without FILE_READ_ATTRIBUTES")

        -- Listing is compat, so the open succeeds without it and the
        -- descriptor is usable for the operations that do not list.
        t:assert_eq(kacs.set_sd(vm, d, kacs.grant(ALL & ~R.LIST_DIRECTORY)).ret, 0,
            "listing permission is withdrawn")
        kacs.as_dacl_bound(t, vm, function(w)
            local fd, errno = sys.open(w, d, sys.O.RDONLY | sys.O.DIRECTORY)
            t:assert(fd, "the directory still opens O_RDONLY: " .. sys.errname(errno or 0))
            t:assert(sys.fstat(w, fd), "and fstat() works on the descriptor")
            t:assert_eq(facs.fchdir(w, fd).ret, 0, "and so does fchdir()")
            local entries, e = sys.getdents(w, fd)
            t:assert(not entries, "while listing it is refused")
            t:assert_eq(e, sys.E.ACCES, "with EACCES: " .. sys.errname(e or 0))
            sys.close(w, fd)
        end)
    end)

test("O_APPEND replaces FILE_WRITE_DATA in core and O_TRUNC re-adds it",
    { spec = "PKM *facs.legacy.append-trunc-order" }, function(t)
        local p = at("appendtrunc")
        local ALL = kacs.ALL_RIGHTS

        -- O_APPEND alone: the replacement means FILE_WRITE_DATA is not
        -- core, and FILE_APPEND_DATA is.
        rewrite(p, "appendtrunc")
        t:assert(legacy(t, p, ALL & ~R.WRITE_DATA, sys.O.WRONLY | sys.O.APPEND).fd,
            "O_WRONLY|O_APPEND opens without FILE_WRITE_DATA")
        rewrite(p, "appendtrunc")
        t:assert(not legacy(t, p, ALL & ~R.APPEND_DATA, sys.O.WRONLY | sys.O.APPEND).fd,
            "and is refused without FILE_APPEND_DATA")

        -- O_TRUNC alone: FILE_WRITE_DATA is core.
        rewrite(p, "appendtrunc")
        t:assert(not legacy(t, p, ALL & ~R.WRITE_DATA, sys.O.WRONLY | sys.O.TRUNC).fd,
            "O_WRONLY|O_TRUNC needs FILE_WRITE_DATA")

        -- Both: the replacement happens first and the re-addition
        -- second, so core carries *both* rights and each is required.
        rewrite(p, "appendtrunc")
        t:assert(not legacy(t, p, ALL & ~R.APPEND_DATA,
            sys.O.WRONLY | sys.O.APPEND | sys.O.TRUNC).fd,
            "O_APPEND|O_TRUNC still needs FILE_APPEND_DATA")
        rewrite(p, "appendtrunc")
        t:assert(not legacy(t, p, ALL & ~R.WRITE_DATA,
            sys.O.WRONLY | sys.O.APPEND | sys.O.TRUNC).fd,
            "and needs FILE_WRITE_DATA as well")
        rewrite(p, "appendtrunc")
        t:assert(legacy(t, p, ALL, sys.O.WRONLY | sys.O.APPEND | sys.O.TRUNC).fd,
            "with both granted it opens")
    end)

test("FILE_READ_ATTRIBUTES is core for every legacy open",
    { spec = "PKM *facs.legacy.read-attributes-always-core" }, function(t)
        local p = at("readattr")
        local ALL = kacs.ALL_RIGHTS & ~R.READ_ATTRIBUTES
        for _, f in ipairs({ { "O_RDONLY", sys.O.RDONLY },
                             { "O_WRONLY", sys.O.WRONLY },
                             { "O_RDWR", sys.O.RDWR },
                             { "O_WRONLY|O_APPEND", sys.O.WRONLY | sys.O.APPEND } }) do
            rewrite(p, "readattr")
            local r = legacy(t, p, ALL, f[2])
            t:assert(not r.fd, f[1] .. " is not openable without FILE_READ_ATTRIBUTES")
            t:assert_eq(r.errno, sys.E.ACCES, "EACCES: " .. sys.errname(r.errno or 0))
        end
    end)

test("compat rights are requested alongside core and silently omitted where denied",
    { spec = "PKM *facs.legacy.compat-rights" }, function(t)
        local p = at("compat")
        vm:write_file(p, "compat")
        local CORE = R.READ_DATA | R.WRITE_DATA | R.READ_ATTRIBUTES

        -- With only core granted, the open succeeds and the compat
        -- rights simply are not on the descriptor.
        t:assert_eq(kacs.set_sd(vm, p, kacs.grant(CORE)).ret, 0, "only core is granted")
        kacs.as_dacl_bound(t, vm, function(w)
            local fd, errno = sys.open(w, p, sys.O.RDWR)
            t:assert(fd, "the open succeeds with no compat right granted: " ..
                sys.errname(errno or 0))
            -- Not fchmod: WRITE_DAC (like READ_CONTROL) is granted to
            -- an object's owner whatever the DACL says, so it cannot
            -- stand for a compat right that was denied.
            t:assert_eq(facs.futimens(w, fd, 5).errno, sys.E.ACCES,
                "FILE_WRITE_ATTRIBUTES is absent, so futimens() is refused")
            t:assert_eq(sys.fsync(w, fd).errno, sys.E.ACCES,
                "SYNCHRONIZE is absent, so fsync() is refused")
            sys.close(w, fd)
        end)

        -- Grant the compat rights and the same open picks them up.
        t:assert_eq(kacs.set_sd(vm, p, kacs.grant(CORE | R.WRITE_DAC |
            R.WRITE_ATTRIBUTES | R.SYNCHRONIZE | R.READ_EA | R.WRITE_EA |
            R.READ_CONTROL | R.WRITE_OWNER | R.EXECUTE)).ret, 0, "compat is granted too")
        kacs.as_dacl_bound(t, vm, function(w)
            local fd = assert(sys.open(w, p, sys.O.RDWR))
            t:assert_eq(facs.fchmod(w, fd).ret, 0, "fchmod() now works")
            t:assert_eq(facs.futimens(w, fd, 5).ret, 0, "futimens() now works")
            t:assert_eq(sys.fsync(w, fd).ret, 0, "fsync() now works")
            sys.close(w, fd)
        end)
    end)

test("the open fails with EACCES only where a core right is missing",
    { spec = "PKM *facs.legacy.core-missing-eacces" }, function(t)
        local p = at("subset")
        vm:write_file(p, "subset")
        -- Every compat right denied, every core right granted: the
        -- subset criterion admits it.
        local CORE = R.READ_DATA | R.READ_ATTRIBUTES
        t:assert_eq(kacs.set_sd(vm, p, kacs.grant(CORE)).ret, 0, "core only")
        kacs.as_dacl_bound(t, vm, function(w)
            local fd, errno = sys.open(w, p, sys.O.RDONLY)
            t:assert(fd, "core alone is enough: " .. sys.errname(errno or 0))
            if fd then sys.close(w, fd) end
        end)
        -- One core right removed and the whole open fails.
        t:assert_eq(kacs.set_sd(vm, p, kacs.grant(kacs.ALL_RIGHTS & ~R.READ_DATA)).ret, 0,
            "one core right is withdrawn")
        kacs.as_dacl_bound(t, vm, function(w)
            local fd, errno = sys.open(w, p, sys.O.RDONLY)
            t:assert(not fd, "and the open fails")
            t:assert_eq(errno, sys.E.ACCES, "with EACCES: " .. sys.errname(errno or 0))
        end)
    end)

test("an O_PATH descriptor is left unmanaged and carries no granted mask",
    { spec = "PKM *facs.legacy.o-path-unmanaged" }, function(t)
        local p = at("opath")
        vm:write_file(p, "opath")
        t:assert_eq(kacs.set_sd(vm, p, kacs.deny_all()).ret, 0,
            "the object's DACL grants nobody anything")
        kacs.as_dacl_bound(t, vm, function(w)
            local fd, errno = sys.open(w, p, sys.O.PATH)
            t:assert(fd, "O_PATH opens regardless: the hook evaluates nothing: " ..
                sys.errname(errno or 0))
            local no, e = sys.open(w, p, sys.O.RDONLY)
            t:assert(not no, "while an ordinary open of the same object is refused")
            t:assert_eq(e, sys.E.ACCES, "EACCES: " .. sys.errname(e or 0))
            if fd then sys.close(w, fd) end
        end)
    end)

test("fstat and fstatfs on an O_PATH descriptor are allowed unconditionally",
    { spec = "PKM *facs.legacy.o-path-fstat-unconditional" }, function(t)
        local p = at("opath-stat")
        vm:write_file(p, "1234567890")
        t:assert_eq(kacs.set_sd(vm, p, kacs.deny_all()).ret, 0, "nothing is granted")
        kacs.as_dacl_bound(t, vm, function(w)
            local fd = assert(sys.open(w, p, sys.O.PATH))
            local st = sys.fstat(w, fd)
            t:assert(st, "fstat() succeeds on an O_PATH handle over a denied object")
            t:assert_eq(st.size, 10, "and reports the file's size")
            t:assert_eq(facs.fstatfs(w, fd).ret, 0, "fstatfs() succeeds too")
            sys.close(w, fd)
        end)
    end)

test("fchdir on an O_PATH descriptor runs a live FILE_TRAVERSE check",
    { spec = "PKM *facs.legacy.o-path-fchdir-live" }, function(t)
        local d = at("opath-chdir")
        vm:mkdir(d, { parents = true })
        t:assert_eq(kacs.set_sd(vm, d, kacs.grant(kacs.ALL_RIGHTS)).ret, 0,
            "the directory grants everything")
        kacs.as_dacl_bound(t, vm, function(w)
            local fd = assert(sys.open(w, d, sys.O.PATH))
            t:assert_eq(facs.fchdir(w, fd).ret, 0, "fchdir succeeds while traverse is granted")
            sys.close(w, fd)
        end)

        -- The check is live, so withdrawing the right between the open
        -- and the fchdir changes the answer — an ordinary descriptor's
        -- cached mask would not.
        kacs.as_dacl_bound(t, vm, function(w)
            local fd = assert(sys.open(w, d, sys.O.PATH))
            t:assert_eq(kacs.set_sd(vm, d, kacs.grant_all_but(R.TRAVERSE)).ret, 0,
                "FILE_TRAVERSE is withdrawn under the open handle")
            local r = facs.fchdir(w, fd)
            t:assert(r.ret ~= 0, "and the fchdir is now refused")
            t:assert_eq(r.errno, sys.E.ACCES, "EACCES: " .. sys.errname(r.errno))
            sys.close(w, fd)
        end)
        kacs.set_sd(vm, d, kacs.grant(kacs.ALL_RIGHTS))
    end)

test("fchmod, fchown, the xattr calls, ioctl and mmap on an O_PATH handle are EBADF",
    { spec = "PKM *facs.legacy.o-path-ebadf" }, function(t)
        local p = at("opath-ebadf")
        facs.file(vm, p, "opath")
        local fd = assert(sys.open(vm, p, sys.O.PATH))

        t:assert_eq(facs.fchmod(vm, fd).errno, sys.E.BADF, "fchmod")
        t:assert_eq(facs.fchown(vm, fd, 0, 0).errno, sys.E.BADF, "fchown")
        local g = vm:syscall(sys.NR.fgetxattr, {
            args = { fd, 0, 0, 64 },
            bufs = { sys.cstr("user.x"), string.rep("\0", 64) }, ptrs = { 1, 2 } })
        t:assert_eq(g.errno, sys.E.BADF, "fgetxattr")
        t:assert_eq(facs.fsetxattr(vm, fd, "user.x", "v").errno, sys.E.BADF, "fsetxattr")
        t:assert_eq(facs.ioctl(vm, fd, facs.IOC.FS_IOC_GETFLAGS,
            string.rep("\0", 8)).errno, sys.E.BADF, "ioctl")
        local _, merr = sys.mmap(vm, fd, 4096, sys.PROT.READ, sys.MAP.SHARED)
        t:assert_eq(merr, sys.E.BADF, "mmap")

        -- §3.9.3 notes that futimens() has no such guard of its own.
        -- What the guest sees is Linux's own refusal, which is the same
        -- errno, so there is nothing here to distinguish.
        sys.close(vm, fd)
    end)

test("execveat on an O_PATH handle is enforced live in the bprm hook",
    { spec = "PKM *facs.legacy.o-path-live-checks" }, function(t)
        local p = at("opath-exec")
        facs.file(vm, p, "#!/nothing\n")
        sys.chmod(vm, p, tonumber("755", 8))

        kacs.as_dacl_bound(t, vm, function(w)
            local fd = assert(sys.open(w, p, sys.O.PATH))
            -- The handle carries no mask at all, so anything that
            -- happens here is a live decision against the object as it
            -- stands at the moment of the exec.
            t:assert_eq(kacs.set_sd(vm, p, kacs.grant_all_but(R.EXECUTE)).ret, 0,
                "FILE_EXECUTE is withdrawn")
            local denied = facs.execveat_fd(w, fd)
            t:assert_eq(denied.errno, sys.E.ACCES,
                "execveat(AT_EMPTY_PATH) is refused: " .. sys.errname(denied.errno))

            t:assert_eq(kacs.set_sd(vm, p, kacs.grant(kacs.ALL_RIGHTS)).ret, 0,
                "and granted again, with no reopen in between")
            local allowed = facs.execveat_fd(w, fd)
            t:assert_neq(allowed.errno, sys.E.ACCES,
                "after which the same handle passes and Linux rejects the format: " ..
                sys.errname(allowed.errno))
            sys.close(w, fd)
        end)
    end)

test("kacs_get_sd and kacs_set_sd with AT_EMPTY_PATH run live on an O_PATH anchor",
    { spec = "PKM *facs.legacy.o-path-live-checks", tags = { "known-bug" } }, function(t)
        -- §3.9.3: "kacs_get_sd and kacs_set_sd with AT_EMPTY_PATH
        -- likewise run live", and "the descriptor itself *is*
        -- protected: kacs_get_sd on an O_PATH handle performs a live
        -- check". The kernel refuses the call outright instead.
        local p = at("opath-sd")
        facs.file(vm, p, "anchored")
        local function get_sd(who, fd)
            return who:syscall(kacs.SYS.GET_SD, {
                args = { fd, 0, kacs.SI.DACL, 0, 4096, sys.AT_EMPTY_PATH },
                bufs = { sys.cstr(""), string.rep("\0", 4096) }, ptrs = { 1, 3 } })
        end

        -- An ordinary descriptor is accepted as an anchor, so the flag
        -- and the argument shape are right.
        local ordinary = facs.handle(t, vm, p, R.READ_DATA | R.READ_CONTROL)
        t:assert(get_sd(vm, ordinary).ret > 0,
            "an ordinary descriptor anchors kacs_get_sd through AT_EMPTY_PATH")
        sys.close(vm, ordinary)

        local anchor = assert(sys.open(vm, p, sys.O.PATH))
        local got = get_sd(vm, anchor)
        t:assert(got.ret > 0, "and so does an O_PATH one: " .. sys.errname(got.errno))

        local sd = kacs.grant(kacs.ALL_RIGHTS)
        local set = vm:syscall(kacs.SYS.SET_SD, {
            args = { anchor, 0, kacs.SI.DACL, 0, #sd, sys.AT_EMPTY_PATH },
            bufs = { sys.cstr(""), sd }, ptrs = { 1, 3 } })
        t:assert_eq(set.ret, 0, "kacs_set_sd accepts the same anchor: " ..
            sys.errname(set.errno))
        sys.close(vm, anchor)
    end)
