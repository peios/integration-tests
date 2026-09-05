-- PKM §3.9.2 — kacs_open: the strict all-or-nothing desired mask, the
-- required data right, directories and special nodes, the six create
-- dispositions, delete-on-close, and caller-supplied descriptors.
--
-- The workspace lives under `/`, which is a FACS-managed tmpfs whose
-- objects carry stored descriptors. Cases about a *denial* run in a
-- caller stripped of the DACL-bypassing privileges (helpers/kacs) or,
-- where the subject is a privilege the agent holds, in a freshly minted
-- principal that does not (helpers/token).

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local access = require("helpers.access")
local facs = require("helpers.facs")
local fx = require("helpers.fixtures")

local vm = provium:vm("v", "kernel-only"):boot()

local R = kacs.RIGHT
local D = kacs.DISPOSITION
local B = facs.workspace(vm, "open")
local MAXIMUM_ALLOWED = access.STD.MAXIMUM_ALLOWED

--- A path under the workspace with a fresh name per case.
local function at(name) return B .. "/" .. name end

test("a native open grants the whole requested mask or nothing",
    { spec = "PKM *facs.open.strict-all-or-nothing" }, function(t)
        local p = at("strict")
        vm:write_file(p, "strict")
        -- WRITE_OWNER, not WRITE_DAC: an object's owner is implicitly
        -- granted READ_CONTROL and WRITE_DAC whatever the DACL says, so
        -- neither can serve as the one withheld right.
        t:assert_eq(kacs.set_sd(vm, p, kacs.grant_all_but(R.WRITE_OWNER)).ret, 0,
            "every right but WRITE_OWNER is granted")

        kacs.as_dacl_bound(t, vm, function(w)
            local ok, e1 = facs.open(w, p, { access = R.READ_DATA | R.WRITE_DATA })
            t:assert(ok, "a mask entirely within the DACL opens: " .. sys.errname(e1 or 0))
            if ok then sys.close(w, ok) end

            local no, e2 = facs.open(w, p, { access = R.READ_DATA | R.WRITE_OWNER })
            t:assert(not no, "adding one denied right fails the whole open")
            t:assert_eq(e2, sys.E.ACCES, "with EACCES: " .. sys.errname(e2 or 0))
        end)
    end)

test("MAXIMUM_ALLOWED caches the computed maximum rather than the requested set",
    { spec = "PKM *facs.open.maximum-allowed-computes-max" }, function(t)
        local p = at("maxallowed")
        vm:write_file(p, "max")
        t:assert_eq(kacs.set_sd(vm, p, kacs.grant(R.READ_DATA | R.READ_ATTRIBUTES |
            R.WRITE_ATTRIBUTES | R.SYNCHRONIZE)).ret, 0, "the DACL grants four rights")

        -- FILE_WRITE_ATTRIBUTES is granted by the DACL but not
        -- requested, so a strict open does not cache it.
        local plain = facs.handle(t, vm, p, R.READ_DATA)
        local denied = facs.futimens(vm, plain, 1000)
        t:assert_eq(denied.errno, sys.E.ACCES,
            "a strict handle cannot set times it never asked for: " ..
            sys.errname(denied.errno))
        sys.close(vm, plain)

        -- The same concrete data right plus MAXIMUM_ALLOWED caches the
        -- whole computed maximum, which includes it.
        local maxed = facs.handle(t, vm, p, R.READ_DATA | MAXIMUM_ALLOWED)
        local ok = facs.futimens(vm, maxed, 1000)
        t:assert_eq(ok.ret, 0, "MAXIMUM_ALLOWED caches every granted right: " ..
            sys.errname(ok.errno))
        t:assert_eq(sys.read(vm, maxed, 3), "max",
            "and the concrete data right still defines the descriptor's mode")
        sys.close(vm, maxed)
    end)

test("MAXIMUM_ALLOWED alone defines no file mode and is invalid",
    { spec = "PKM *facs.open.maximum-allowed-alone-einval" }, function(t)
        local p = facs.file(vm, at("maxalone"), "x")
        local fd, errno = facs.open(vm, p, { access = MAXIMUM_ALLOWED })
        t:assert(not fd, "MAXIMUM_ALLOWED on its own is refused")
        t:assert_eq(errno, sys.E.INVAL, "with EINVAL: " .. sys.errname(errno or 0))
    end)

test("every native open names a data right or FILE_EXECUTE",
    { spec = "PKM *facs.open.required-data-right" }, function(t)
        local p = facs.file(vm, at("dataright"), "x")
        for _, m in ipairs({ { "READ_CONTROL", R.READ_CONTROL },
                             { "WRITE_DAC", R.WRITE_DAC },
                             { "READ_ATTRIBUTES", R.READ_ATTRIBUTES },
                             { "SYNCHRONIZE", R.SYNCHRONIZE },
                             { "DELETE", R.DELETE } }) do
            local fd, errno = facs.open(vm, p, { access = m[2] })
            t:assert(not fd, m[1] .. " alone defines no file mode and is refused")
            t:assert_eq(errno, sys.E.INVAL, "with EINVAL: " .. sys.errname(errno or 0))
        end
        for _, m in ipairs({ { "FILE_READ_DATA", R.READ_DATA },
                             { "FILE_WRITE_DATA", R.WRITE_DATA },
                             { "FILE_APPEND_DATA", R.APPEND_DATA },
                             { "FILE_EXECUTE", R.EXECUTE } }) do
            local fd, errno = facs.open(vm, p, { access = m[2] })
            t:assert(fd, m[1] .. " satisfies the requirement: " .. sys.errname(errno or 0))
            if fd then sys.close(vm, fd) end
        end
    end)

test("FILE_EXECUTE alone yields a handle that can neither read nor write",
    { spec = "PKM *facs.open.execute-only-handle" }, function(t)
        local p = facs.file(vm, at("execonly"), "#!/nothing\n")
        local fd = facs.handle(t, vm, p, R.EXECUTE)
        local r = vm:syscall(sys.NR.read, { args = { fd, 0, 4 },
            bufs = { string.rep("\0", 4) }, ptrs = { 1 } })
        t:assert_eq(r.errno, sys.E.BADF,
            "reading an execute-only handle is refused by its mode: " .. sys.errname(r.errno))
        local w = sys.write(vm, fd, "x")
        t:assert_eq(w.errno, sys.E.BADF,
            "and so is writing: " .. sys.errname(w.errno))

        -- FMODE_EXEC is what the mask bit sets, and it is what
        -- execveat(AT_EMPTY_PATH) needs. The file is not a program, so
        -- Linux answers ENOEXEC — which it only reaches once KACS and
        -- the mode bit have both allowed the exec.
        sys.chmod(vm, p, tonumber("755", 8))
        local x = facs.execveat_fd(vm, fd)
        t:assert_neq(x.errno, sys.E.ACCES,
            "the handle is executable: " .. sys.errname(x.errno))
        sys.close(vm, fd)
    end)

test("FILE_LIST_DIRECTORY satisfies the data-right requirement on a directory",
    { spec = "PKM *facs.open.dir-list-satisfies-data-right" }, function(t)
        local d = at("listdir")
        vm:mkdir(d, { parents = true })
        vm:write_file(d .. "/child", "c")
        kacs.set_sd(vm, d, kacs.grant(kacs.ALL_RIGHTS))

        local fd = facs.handle(t, vm, d, R.LIST_DIRECTORY | R.READ_ATTRIBUTES)
        local entries = sys.getdents_all(vm, fd)
        t:assert(entries, "the handle maps to FMODE_READ and lists")
        local names = {}
        for _, e in ipairs(entries or {}) do names[e.name] = true end
        t:assert(names.child, "and reports the directory's contents")
        sys.close(vm, fd)
    end)

test("the directory write aliases are not cacheable handle rights",
    { spec = "PKM *facs.open.dir-write-aliases-eopnotsupp" }, function(t)
        local d = at("dirwrite")
        vm:mkdir(d, { parents = true })
        kacs.set_sd(vm, d, kacs.grant(kacs.ALL_RIGHTS))
        for _, m in ipairs({ { "FILE_ADD_FILE", R.ADD_FILE },
                             { "FILE_ADD_SUBDIRECTORY", R.ADD_SUBDIRECTORY },
                             { "FILE_DELETE_CHILD", R.DELETE_CHILD } }) do
            local fd, errno = facs.open(vm, d, { access = R.LIST_DIRECTORY | m[2] })
            t:assert(not fd, m[1] .. " is not a right a directory handle may carry")
            t:assert_eq(errno, sys.E.OPNOTSUPP, "EOPNOTSUPP: " .. sys.errname(errno or 0))
        end
    end)

test("FIFOs, socket nodes and device nodes are ordinary file objects",
    { spec = "PKM *facs.open.special-nodes-are-file-objects" }, function(t)
        local nodes = {
            { "fifo", sys.S_IFIFO, 0 },
            { "sock", sys.S_IFSOCK, 0 },
            { "chr", sys.S_IFCHR, (1 << 8) | 3 },   -- /dev/null
        }
        for _, n in ipairs(nodes) do
            local p = at("node-" .. n[1])
            t:assert_eq(sys.mknod(vm, p, n[2] | tonumber("600", 8), n[3]).ret, 0,
                "mknod " .. n[1])
            t:assert_eq(kacs.set_sd(vm, p, kacs.grant(kacs.ALL_RIGHTS)).ret, 0,
                n[1] .. " carries a file descriptor")

            -- Authorized: the file GenericMapping and the file right
            -- mapping apply, so the open reaches the Linux object
            -- implementation (which refuses a socket node with ENXIO of
            -- its own accord).
            local fd, errno = facs.open(vm, p, { access = R.READ_DATA | R.WRITE_DATA })
            if n[1] == "sock" then
                t:assert(not fd, "a socket node is not openable by Linux")
                t:assert_eq(errno, 6, "ENXIO from the object implementation, not KACS: " ..
                    sys.errname(errno or 0))
            else
                t:assert(fd, n[1] .. " opens as a file object: " .. sys.errname(errno or 0))
                sys.close(vm, fd)
            end

            -- And the descriptor is authoritative: withdraw the data
            -- right and KACS refuses before Linux is consulted.
            t:assert_eq(kacs.set_sd(vm, p, kacs.grant_all_but(R.READ_DATA)).ret, 0,
                "the read right is withdrawn")
            kacs.as_dacl_bound(t, vm, function(w)
                local no, e = facs.open(w, p, { access = R.READ_DATA })
                t:assert(not no, n[1] .. " is judged on its own descriptor")
                t:assert_eq(e, sys.E.ACCES, "EACCES: " .. sys.errname(e or 0))
            end)
        end
    end)

test("FILE_EXECUTE is not a data substitute on a special node",
    { spec = "PKM *facs.open.execute-not-valid-on-special-nodes" }, function(t)
        for _, n in ipairs({ { "xfifo", sys.S_IFIFO, 0 },
                             { "xsock", sys.S_IFSOCK, 0 },
                             { "xchr", sys.S_IFCHR, (1 << 8) | 3 } }) do
            local p = at(n[1])
            t:assert_eq(sys.mknod(vm, p, n[2] | tonumber("600", 8), n[3]).ret, 0, "mknod " .. n[1])
            kacs.set_sd(vm, p, kacs.grant(kacs.ALL_RIGHTS))
            local fd, errno = facs.open(vm, p, { access = R.EXECUTE })
            t:assert(not fd, n[1] .. " cannot be opened for execute")
            t:assert_eq(errno, sys.E.ACCES, "it fails closed: " .. sys.errname(errno or 0))
        end
    end)

test("a symlink is not a terminal object for kacs_open",
    { spec = "PKM *facs.open.symlink-nofollow-eloop" }, function(t)
        local target = facs.file(vm, at("linktarget"), "pointed-at")
        local link = at("link")
        t:assert_eq(sys.symlink(vm, target, link).ret, 0, "the symlink is created")

        -- Following is the default resolution behaviour.
        local fd, errno = facs.open(vm, link, { access = R.READ_DATA })
        t:assert(fd, "the default follows to the target: " .. sys.errname(errno or 0))
        if fd then
            t:assert_eq(sys.read(vm, fd, 7), "pointed", "and opens what it points at")
            sys.close(vm, fd)
        end

        local no, e = facs.open(vm, link, { access = R.READ_DATA,
            flags = sys.AT_SYMLINK_NOFOLLOW })
        t:assert(not no, "AT_SYMLINK_NOFOLLOW does not open the link object itself")
        t:assert_eq(e, sys.E.LOOP, "with ELOOP: " .. sys.errname(e or 0))

        -- kacs_get_sd resolves the link object under the same flag,
        -- which is the difference §3.9.2 draws.
        local sd = kacs.get_sd(vm, link)
        t:assert(sd, "kacs_get_sd reaches a descriptor through the link")
    end)

test("the six create dispositions behave as the table says",
    { spec = "PKM *facs.open.create-dispositions" }, function(t)
        local rw = R.READ_DATA | R.WRITE_DATA | R.READ_ATTRIBUTES
        local function fresh(name, content)
            local p = at(name)
            if content then facs.file(vm, p, content) else sys.unlink(vm, p) end
            return p
        end

        -- FILE_OPEN: opens what exists, fails where nothing does.
        local p = fresh("d-open", "hello")
        local fd, st = facs.open(vm, p, { access = rw, disposition = D.OPEN })
        t:assert(fd, "FILE_OPEN opens an existing file: " .. sys.errname(st or 0))
        t:assert_eq(st, facs.STATUS.OPENED, "reporting OPENED")
        sys.close(vm, fd)
        local no, e = facs.open(vm, fresh("d-open-missing"), { access = rw, disposition = D.OPEN })
        t:assert(not no, "and fails where the file does not exist")
        t:assert_eq(e, sys.E.NOENT, "ENOENT: " .. sys.errname(e or 0))

        -- FILE_CREATE: creates, fails where something exists.
        fd, st = facs.open(vm, fresh("d-create"), { access = rw, disposition = D.CREATE })
        t:assert(fd, "FILE_CREATE creates: " .. sys.errname(st or 0))
        t:assert_eq(st, facs.STATUS.CREATED, "reporting CREATED")
        sys.close(vm, fd)
        no, e = facs.open(vm, at("d-create"), { access = rw, disposition = D.CREATE })
        t:assert(not no, "and fails where the name is taken")
        t:assert_eq(e, sys.E.EXIST, "EEXIST: " .. sys.errname(e or 0))

        -- FILE_OPEN_IF: opens or creates.
        fd, st = facs.open(vm, fresh("d-openif", "here"), { access = rw, disposition = D.OPEN_IF })
        t:assert_eq(st, facs.STATUS.OPENED, "FILE_OPEN_IF opens what exists")
        sys.close(vm, fd)
        fd, st = facs.open(vm, fresh("d-openif2"), { access = rw, disposition = D.OPEN_IF })
        t:assert_eq(st, facs.STATUS.CREATED, "and creates what does not")
        sys.close(vm, fd)

        -- FILE_OVERWRITE: truncates what exists, fails where nothing does.
        p = fresh("d-overwrite", "0123456789")
        fd, st = facs.open(vm, p, { access = rw, disposition = D.OVERWRITE })
        t:assert(fd, "FILE_OVERWRITE opens: " .. sys.errname(st or 0))
        t:assert_eq(st, facs.STATUS.OVERWRITTEN, "reporting OVERWRITTEN")
        t:assert_eq(sys.stat(vm, p).size, 0, "and the file is truncated to zero")
        sys.close(vm, fd)
        no, e = facs.open(vm, fresh("d-overwrite-missing"), { access = rw, disposition = D.OVERWRITE })
        t:assert(not no, "and it fails where the file does not exist: " .. sys.errname(e or 0))

        -- FILE_OVERWRITE_IF: truncates or creates.
        p = fresh("d-owif", "0123456789")
        fd, st = facs.open(vm, p, { access = rw, disposition = D.OVERWRITE_IF })
        t:assert_eq(st, facs.STATUS.OVERWRITTEN, "FILE_OVERWRITE_IF truncates what exists")
        t:assert_eq(sys.stat(vm, p).size, 0, "to zero")
        sys.close(vm, fd)
        fd, st = facs.open(vm, fresh("d-owif2"), { access = rw, disposition = D.OVERWRITE_IF })
        t:assert_eq(st, facs.STATUS.CREATED, "and creates what does not")
        sys.close(vm, fd)

        -- FILE_SUPERSEDE: deletes and recreates, or creates.
        p = fresh("d-supersede", "0123456789")
        fd, st = facs.open(vm, p, { access = rw, disposition = D.SUPERSEDE })
        t:assert_eq(st, facs.STATUS.SUPERSEDED, "FILE_SUPERSEDE replaces what exists")
        t:assert_eq(sys.stat(vm, p).size, 0, "with an empty file")
        sys.close(vm, fd)
        fd, st = facs.open(vm, fresh("d-supersede2"), { access = rw, disposition = D.SUPERSEDE })
        t:assert_eq(st, facs.STATUS.CREATED, "and creates where nothing does")
        sys.close(vm, fd)

        -- A value past the table is not a disposition at all.
        no, e = facs.open(vm, at("d-open"), { access = rw, disposition = 6 })
        t:assert(not no, "disposition 6 is not defined")
        t:assert_eq(e, sys.E.INVAL, "EINVAL: " .. sys.errname(e or 0))
    end)

test("FILE_SUPERSEDE needs DELETE on the file and FILE_ADD_FILE on the parent",
    { spec = "PKM *facs.open.supersede-rights" }, function(t)
        local d = at("sup-rights")
        vm:mkdir(d, { parents = true })
        local p = d .. "/victim"
        local rw = R.READ_DATA | R.WRITE_DATA

        local function attempt(parent_mask, file_mask)
            vm:write_file(p, "victim")
            kacs.set_sd(vm, d, kacs.grant(parent_mask))
            kacs.set_sd(vm, p, kacs.grant(file_mask))
            local out
            kacs.as_dacl_bound(t, vm, function(w)
                local fd, errno = facs.open(w, p, { access = rw, disposition = D.SUPERSEDE })
                if fd then sys.close(w, fd) end
                out = { fd = fd, errno = errno }
            end)
            return out
        end

        local ok = attempt(kacs.ALL_RIGHTS, kacs.ALL_RIGHTS)
        t:assert(ok.fd, "with every right on both, supersede succeeds: " ..
            sys.errname(ok.errno or 0))

        local no_delete = attempt(kacs.ALL_RIGHTS & ~R.DELETE_CHILD,
                                  kacs.ALL_RIGHTS & ~R.DELETE)
        t:assert(not no_delete.fd,
            "without DELETE on the file or FILE_DELETE_CHILD on the parent it fails")
        t:assert_eq(no_delete.errno, sys.E.ACCES, "EACCES: " ..
            sys.errname(no_delete.errno or 0))

        local no_add = attempt(kacs.ALL_RIGHTS & ~R.ADD_FILE, kacs.ALL_RIGHTS)
        t:assert(not no_add.fd, "and without FILE_ADD_FILE on the parent it fails")
        t:assert_eq(no_add.errno, sys.E.ACCES, "EACCES: " ..
            sys.errname(no_add.errno or 0))
    end)

test("a superseded pathname names a new inode and leaves the old hardlink set",
    { spec = "PKM *facs.open.supersede-new-inode" }, function(t)
        local p = facs.file(vm, at("sup-inode"), "original")
        local other = at("sup-inode-link")
        sys.unlink(vm, other)
        t:assert_eq(sys.link(vm, p, other).ret, 0, "a second hardlink names the same inode")
        local before = sys.stat(vm, p)
        t:assert_eq(sys.stat(vm, other).ino, before.ino, "as it must, to start with")

        local held = facs.handle(t, vm, p, R.READ_DATA)
        local fd, st = facs.open(vm, p, { access = R.READ_DATA | R.WRITE_DATA,
            disposition = D.SUPERSEDE })
        t:assert_eq(st, facs.STATUS.SUPERSEDED, "the file is superseded")
        sys.close(vm, fd)

        local after = sys.stat(vm, p)
        t:assert_neq(after.ino, before.ino, "the pathname names a new inode")
        t:assert_eq(sys.stat(vm, other).ino, before.ino,
            "the other hardlink still names the old one")
        t:assert_eq(sys.read(vm, held, 8), "original",
            "and a descriptor opened before still reads the old inode")
        sys.close(vm, held)
    end)

test("FILE_OVERWRITE truncates in place and requires FILE_WRITE_DATA",
    { spec = "PKM *facs.open.overwrite-in-place" }, function(t)
        local p = facs.file(vm, at("ow-inplace"), "0123456789")
        local other = at("ow-inplace-link")
        sys.unlink(vm, other)
        t:assert_eq(sys.link(vm, p, other).ret, 0, "the file has a second hardlink")
        local before = sys.stat(vm, p)

        local fd, st = facs.open(vm, p, { access = R.READ_DATA | R.WRITE_DATA,
            disposition = D.OVERWRITE })
        t:assert_eq(st, facs.STATUS.OVERWRITTEN, "the file is overwritten")
        sys.close(vm, fd)
        local after = sys.stat(vm, p)
        t:assert_eq(after.ino, before.ino, "the inode is the same one")
        t:assert_eq(after.size, 0, "truncated to zero")
        t:assert_eq(sys.stat(vm, other).ino, before.ino, "and the hardlink is preserved")
        t:assert_eq(after.nlink, 2, "with the link count unchanged")

        local no, e = facs.open(vm, p, { access = R.READ_DATA, disposition = D.OVERWRITE })
        t:assert(not no, "an overwrite that does not request FILE_WRITE_DATA is refused")
        t:assert_eq(e, sys.E.INVAL, "as invalid input: " .. sys.errname(e or 0))
    end)

test("on an unmanaged mount the creating dispositions fail and the opening ones do not",
    { spec = "PKM *facs.open.unmanaged-create-eopnotsupp" }, function(t)
        local rw = R.READ_DATA | R.WRITE_DATA
        for _, d in ipairs({ { "FILE_SUPERSEDE", D.SUPERSEDE },
                             { "FILE_OVERWRITE", D.OVERWRITE },
                             { "FILE_OVERWRITE_IF", D.OVERWRITE_IF } }) do
            local fd, errno = facs.open(vm, "/proc/version", { access = rw, disposition = d[2] })
            t:assert(not fd, d[1] .. " is refused on /proc")
            t:assert_eq(errno, sys.E.OPNOTSUPP, "EOPNOTSUPP: " .. sys.errname(errno or 0))
        end
        for _, d in ipairs({ { "FILE_OPEN", D.OPEN }, { "FILE_OPEN_IF", D.OPEN_IF } }) do
            local fd, st = facs.open(vm, "/proc/version",
                { access = R.READ_DATA | R.READ_ATTRIBUTES, disposition = d[2] })
            t:assert(fd, d[1] .. " succeeds and returns an unmanaged descriptor: " ..
                sys.errname(st or 0))
            t:assert_eq(st, facs.STATUS.OPENED, "reporting OPENED")
            sys.close(vm, fd)
        end
    end)

test("the DELETE fallback is a two-descriptor check inside the open path",
    { spec = "PKM *facs.open.delete-fallback" }, function(t)
        local d = at("fallback")
        vm:mkdir(d, { parents = true })
        local p = d .. "/target"
        local rw = R.READ_DATA | R.WRITE_DATA

        local function supersede(parent_mask, file_mask)
            vm:write_file(p, "target")
            kacs.set_sd(vm, d, kacs.grant(parent_mask))
            kacs.set_sd(vm, p, kacs.grant(file_mask))
            local out
            kacs.as_dacl_bound(t, vm, function(w)
                local fd, errno = facs.open(w, p, { access = rw, disposition = D.SUPERSEDE })
                if fd then sys.close(w, fd) end
                out = { fd = fd, errno = errno }
            end)
            return out
        end

        -- DELETE on the file alone is enough, even with
        -- FILE_DELETE_CHILD withdrawn from the parent.
        local by_file = supersede(kacs.ALL_RIGHTS & ~R.DELETE_CHILD, kacs.ALL_RIGHTS)
        t:assert(by_file.fd, "DELETE on the file satisfies it: " ..
            sys.errname(by_file.errno or 0))

        -- FILE_DELETE_CHILD on the parent alone is enough too: the
        -- check runs a second time against the parent.
        local by_parent = supersede(kacs.ALL_RIGHTS, kacs.ALL_RIGHTS & ~R.DELETE)
        t:assert(by_parent.fd, "FILE_DELETE_CHILD on the parent satisfies it: " ..
            sys.errname(by_parent.errno or 0))

        -- Neither, and the open fails.
        local neither = supersede(kacs.ALL_RIGHTS & ~R.DELETE_CHILD,
                                  kacs.ALL_RIGHTS & ~R.DELETE)
        t:assert(not neither.fd, "with neither, the open fails")
        t:assert_eq(neither.errno, sys.E.ACCES, "EACCES: " ..
            sys.errname(neither.errno or 0))
    end)

test("KACS_CREATE_OPT_DIRECTORY requires the target to be a directory",
    { spec = "PKM *facs.open.create-opt-directory" }, function(t)
        local d = at("optdir")
        sys.unlink(vm, d, sys.AT_REMOVEDIR)
        local fd, st = facs.open(vm, d, { access = R.LIST_DIRECTORY,
            disposition = D.CREATE, options = kacs.CREATE_OPT.DIRECTORY })
        t:assert(fd, "creating with the option makes a directory: " .. sys.errname(st or 0))
        t:assert_eq(st, facs.STATUS.CREATED, "reporting CREATED")
        sys.close(vm, fd)
        t:assert(sys.stat(vm, d).is_dir, "and the object is a directory")

        -- Opening an existing non-directory with it fails.
        local f = facs.file(vm, at("optdir-file"), "regular")
        local no, e = facs.open(vm, f, { access = R.READ_DATA,
            disposition = D.OPEN, options = kacs.CREATE_OPT.DIRECTORY })
        t:assert(not no, "opening a regular file with the option fails")
        t:assert_eq(e, sys.E.NOTDIR, "with ENOTDIR: " .. sys.errname(e or 0))
    end)

test("a nonzero reserved create-option bit is invalid",
    { spec = "PKM *facs.open.reserved-create-option-einval" }, function(t)
        local p = facs.file(vm, at("reserved"), "x")
        for _, bit in ipairs({ 0x0004, 0x0008, 0x0100, 0x80000000 }) do
            local fd, errno = facs.open(vm, p, { access = R.READ_DATA, options = bit })
            t:assert(not fd, string.format("create option 0x%x is reserved", bit))
            t:assert_eq(errno, sys.E.INVAL, "EINVAL: " .. sys.errname(errno or 0))
        end
    end)

test("delete-on-close attaches to one file-description lineage, which dup preserves",
    { spec = "PKM *facs.open.delete-on-close-lineage" }, function(t)
        local p = facs.file(vm, at("doc-lineage"), "doomed")
        local fd, st = facs.open(vm, p, { access = R.READ_DATA | R.WRITE_DATA | R.DELETE,
            options = kacs.CREATE_OPT.DELETE_ON_CLOSE })
        t:assert(fd, "the handle is armed: " .. sys.errname(st or 0))

        local d = facs.dup(vm, fd)
        t:assert(d.ret >= 0, "dup: " .. sys.errname(d.errno))
        sys.close(vm, fd)
        t:assert(sys.stat(vm, p), "closing one member of the lineage does not unlink")
        sys.close(vm, d.ret)
        t:assert(not sys.stat(vm, p), "closing the last one does")
    end)

test("delete-on-close is no-share: later opens of the object fail closed",
    { spec = "PKM *facs.open.delete-on-close-no-share" }, function(t)
        local p = facs.file(vm, at("doc-noshare"), "doomed")
        local fd = facs.handle(t, vm, p, R.READ_DATA | R.WRITE_DATA | R.DELETE,
            { options = kacs.CREATE_OPT.DELETE_ON_CLOSE })

        local no, e = facs.open(vm, p, { access = R.READ_DATA })
        t:assert(not no, "a second native open of the object is refused")
        t:assert_eq(e, sys.E.ACCES, "EACCES: " .. sys.errname(e or 0))
        local legacy, e2 = sys.open(vm, p, sys.O.RDONLY)
        t:assert(not legacy, "and so is a legacy one")
        t:assert_eq(e2, sys.E.ACCES, "EACCES: " .. sys.errname(e2 or 0))
        sys.close(vm, fd)
    end)

test("the unlink happens at final close, not at open",
    { spec = "PKM *facs.open.delete-on-close-final-close" }, function(t)
        local p = facs.file(vm, at("doc-final"), "doomed")
        local fd = facs.handle(t, vm, p, R.READ_DATA | R.WRITE_DATA | R.DELETE,
            { options = kacs.CREATE_OPT.DELETE_ON_CLOSE })
        t:assert(sys.stat(vm, p), "the file is still there while the handle is open")
        sys.close(vm, fd)
        t:assert(not sys.stat(vm, p), "and gone once it closes")
    end)

test("a pathname already gone at final close is a no-op, not a new error",
    { spec = "PKM *facs.open.delete-on-close-final-close",
      tags = { "known-bug" },
      skip = "known-bug: running this oopses the guest kernel (NULL deref in " ..
             "ihold via d_delete_notify <- vfs_unlink <- " ..
             "pkm_kacs_unlink_delete_on_close_file <- security_file_release), " ..
             "which wedges the whole file, so the body is left unexecuted. " ..
             "See the report." },
    function(t)
        -- §3.9.2: the unlink happens at final close, "and if the
        -- pathname is already gone by then the close path treats it as
        -- a no-op rather than a new error".
        local q = facs.file(vm, at("doc-gone"), "doomed")
        local fd = facs.handle(t, vm, q, R.READ_DATA | R.WRITE_DATA | R.DELETE,
            { options = kacs.CREATE_OPT.DELETE_ON_CLOSE })
        t:assert_eq(sys.unlink(vm, q).ret, 0, "the pathname is removed first")
        local closed = sys.close(vm, fd)
        t:assert_eq(closed.ret, 0, "and the close still succeeds: " ..
            sys.errname(closed.errno))
    end)

test("delete-on-close is for regular files only",
    { spec = "PKM *facs.open.delete-on-close-regular-only" }, function(t)
        local d = at("doc-dir")
        vm:mkdir(d, { parents = true })
        kacs.set_sd(vm, d, kacs.grant(kacs.ALL_RIGHTS))
        local fd, errno = facs.open(vm, d, { access = R.LIST_DIRECTORY | R.DELETE,
            options = kacs.CREATE_OPT.DELETE_ON_CLOSE })
        t:assert(not fd, "a directory cannot be armed")
        t:assert_eq(errno, sys.E.OPNOTSUPP, "it fails closed: " .. sys.errname(errno or 0))
        t:assert(sys.stat(vm, d), "and the directory is still there")
    end)

test("a new file with no supplied descriptor inherits one from its parent",
    { spec = "PKM *facs.open.null-descriptor-inherits" }, function(t)
        local d = at("inherit")
        vm:mkdir(d, { parents = true })
        -- A distinctive trustee, inheritable onto objects, so the
        -- child's descriptor can be told from a default.
        local marker = token.SID.TEST_GROUP_2
        local sd = access.sd({
            owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
            dacl = access.acl({
                access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS, token.SID.EVERYONE,
                    access.ACE_FLAG.OBJECT_INHERIT | access.ACE_FLAG.CONTAINER_INHERIT),
                access.ace(access.ACE.ALLOWED, R.READ_DATA, marker,
                    access.ACE_FLAG.OBJECT_INHERIT | access.ACE_FLAG.CONTAINER_INHERIT),
            }),
        })
        t:assert_eq(kacs.set_sd(vm, d, sd).ret, 0, "the parent carries an inheritable ACE")

        local child = d .. "/inherited"
        sys.unlink(vm, child)
        local fd, st = facs.open(vm, child, { access = R.READ_DATA | R.WRITE_DATA,
            disposition = D.CREATE })
        t:assert(fd, "the child is created with a null descriptor pointer: " ..
            sys.errname(st or 0))
        sys.close(vm, fd)

        local got = kacs.get_sd(vm, child)
        t:assert(got, "and has a descriptor of its own")
        local parsed = token.parse_sd(got)
        local ace = token.find_ace(parsed.dacl, marker, kacs.ACE_ALLOWED)
        t:assert(ace, "carrying the parent's inheritable ACE")
        t:assert_eq(ace.flags & access.ACE_FLAG.INHERITED, access.ACE_FLAG.INHERITED,
            "marked inherited")
    end)

test("supplying a descriptor on a branch that opens an existing object is invalid",
    { spec = "PKM *facs.open.supplied-on-existing-einval" }, function(t)
        local p = facs.file(vm, at("supplied-existing"), "here")
        local sd = kacs.grant(kacs.ALL_RIGHTS)
        local rw = R.READ_DATA | R.WRITE_DATA
        for _, d in ipairs({ { "FILE_OPEN_IF resolving to an existing object", D.OPEN_IF },
                             { "FILE_OVERWRITE", D.OVERWRITE },
                             { "the existing-object branch of FILE_OVERWRITE_IF", D.OVERWRITE_IF } }) do
            local fd, errno = facs.open(vm, p, { access = rw, disposition = d[2], sd = sd })
            t:assert(not fd, d[1] .. " with a supplied descriptor is refused")
            t:assert_eq(errno, sys.E.INVAL, "EINVAL: " .. sys.errname(errno or 0))
        end
    end)

test("FILE_OPEN with a descriptor supplied is unsupported",
    { spec = "PKM *facs.open.supplied-with-file-open-eopnotsupp" }, function(t)
        local p = facs.file(vm, at("supplied-open"), "here")
        local fd, errno = facs.open(vm, p, { access = R.READ_DATA,
            disposition = D.OPEN, sd = kacs.grant(kacs.ALL_RIGHTS) })
        t:assert(not fd, "FILE_OPEN never creates, so a descriptor makes no sense")
        t:assert_eq(errno, sys.E.OPNOTSUPP, "EOPNOTSUPP: " .. sys.errname(errno or 0))
    end)

test("the strict check runs against the newly computed descriptor",
    { spec = "PKM *facs.open.check-against-new-descriptor" }, function(t)
        local d = at("newsd")
        vm:mkdir(d, { parents = true })
        kacs.set_sd(vm, d, kacs.grant(kacs.ALL_RIGHTS))
        local child = d .. "/refused"
        sys.unlink(vm, child)

        -- Parent create rights are held in full; the *new* object's
        -- descriptor grants read only, so a write handle is refused.
        local readonly = access.sd({
            owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
            dacl = access.acl({ access.ace(access.ACE.ALLOWED,
                R.READ_DATA | R.READ_ATTRIBUTES, token.SID.EVERYONE) }),
        })
        kacs.as_dacl_bound(t, vm, function(w)
            local no, e = facs.open(w, child, { access = R.READ_DATA | R.WRITE_DATA,
                disposition = D.CREATE, sd = readonly })
            t:assert(not no, "parent create rights do not authorize the returned handle")
            t:assert_eq(e, sys.E.ACCES, "EACCES: " .. sys.errname(e or 0))

            local ok, e2 = facs.open(w, child, { access = R.READ_DATA,
                disposition = D.CREATE, sd = readonly })
            t:assert(ok, "a handle the new descriptor grants is created: " ..
                sys.errname(e2 or 0))
            if ok then sys.close(w, ok) end
        end)
    end)

test("a failed strict check rolls the creation back",
    { spec = "PKM *facs.open.failed-check-rolls-back" }, function(t)
        local d = at("rollback")
        vm:mkdir(d, { parents = true })
        kacs.set_sd(vm, d, kacs.grant(kacs.ALL_RIGHTS))
        local child = d .. "/never"
        sys.unlink(vm, child)
        local readonly = access.sd({
            owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
            dacl = access.acl({ access.ace(access.ACE.ALLOWED, R.READ_DATA, token.SID.EVERYONE) }),
        })
        kacs.as_dacl_bound(t, vm, function(w)
            local no, e = facs.open(w, child, { access = R.READ_DATA | R.WRITE_DATA,
                disposition = D.CREATE, sd = readonly })
            t:assert(not no, "the open fails: " .. sys.errname(e or 0))
        end)
        t:assert(not sys.stat(vm, child), "and the file it created is removed again")

        -- A directory creation rolls back the same way.
        local dir = d .. "/neverdir"
        sys.unlink(vm, dir, sys.AT_REMOVEDIR)
        kacs.as_dacl_bound(t, vm, function(w)
            local no = facs.open(w, dir, { access = R.LIST_DIRECTORY | R.ADD_FILE,
                disposition = D.CREATE, options = kacs.CREATE_OPT.DIRECTORY, sd = readonly })
            t:assert(not no, "a directory creation whose check fails is refused")
        end)
        t:assert(not sys.stat(vm, dir), "and the directory is removed again")
    end)

test("a supplied owner has to be the caller's own or a group marked SE_GROUP_OWNER",
    { spec = "PKM *facs.open.supplied-owner-constraint" }, function(t)
        kacs.set_sd(vm, "/", kacs.grant(kacs.ALL_RIGHTS))
        local d = at("owner")
        vm:mkdir(d, { parents = true })
        kacs.set_sd(vm, d, kacs.grant(kacs.ALL_RIGHTS))

        local function creating(owner)
            return access.sd({ owner = owner, group = token.SID.LOCAL_SYSTEM,
                dacl = access.acl({ access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS,
                    token.SID.EVERYONE) }) })
        end
        local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED
        local groups = {
            { sid = token.SID.EVERYONE, attributes = ENABLED },
            { sid = token.SID.TEST_GROUP, attributes = ENABLED | token.GROUP.OWNER },
            { sid = token.SID.TEST_GROUP_2, attributes = ENABLED },
        }

        token.as_principal(t, vm, { groups = groups }, function(w)
            local own = d .. "/own"
            sys.unlink(w, own)
            local a, e1 = facs.open(w, own, { access = R.READ_DATA | R.WRITE_DATA,
                disposition = D.CREATE, sd = creating(token.SID.TEST_USER) })
            t:assert(a, "the caller's own user SID is accepted: " .. sys.errname(e1 or 0))
            if a then sys.close(w, a) end

            local grp = d .. "/group"
            sys.unlink(w, grp)
            local b, e2 = facs.open(w, grp, { access = R.READ_DATA | R.WRITE_DATA,
                disposition = D.CREATE, sd = creating(token.SID.TEST_GROUP) })
            t:assert(b, "a group marked SE_GROUP_OWNER is accepted: " .. sys.errname(e2 or 0))
            if b then sys.close(w, b) end

            local no = d .. "/foreign"
            sys.unlink(w, no)
            local c, e3 = facs.open(w, no, { access = R.READ_DATA | R.WRITE_DATA,
                disposition = D.CREATE, sd = creating(token.SID.TEST_GROUP_2) })
            t:assert(not c, "a group without the attribute is not: " .. sys.errname(e3 or 0))
        end)

        -- SeRestorePrivilege lifts the constraint entirely.
        token.as_principal(t, vm, { groups = groups,
            privs_present = token.bit(token.PRIV.RESTORE),
            privs_enabled = token.bit(token.PRIV.RESTORE) }, function(w)
            local p = d .. "/restored"
            sys.unlink(w, p)
            local fd, e = facs.open(w, p, { access = R.READ_DATA | R.WRITE_DATA,
                disposition = D.CREATE, sd = creating(token.SID.TEST_GROUP_2) })
            t:assert(fd, "with SeRestorePrivilege any owner is allowed: " ..
                sys.errname(e or 0))
            if fd then sys.close(w, fd) end
        end)
    end)

test("a supplied SACL is a full SACL input and requires SeSecurityPrivilege",
    { spec = "PKM *facs.open.supplied-sacl-requires-privilege" }, function(t)
        kacs.set_sd(vm, "/", kacs.grant(kacs.ALL_RIGHTS))
        local d = at("sacl")
        vm:mkdir(d, { parents = true })
        kacs.set_sd(vm, d, kacs.grant(kacs.ALL_RIGHTS))
        local with_sacl = access.sd({
            owner = token.SID.TEST_USER, group = token.SID.LOCAL_SYSTEM,
            dacl = access.acl({ access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS, token.SID.EVERYONE) }),
            sacl = access.acl({ access.ace(access.ACE.AUDIT, R.READ_DATA, token.SID.EVERYONE,
                access.ACE_FLAG.SUCCESSFUL_ACCESS) }),
        })

        token.as_principal(t, vm, {}, function(w)
            local p = d .. "/nosacl"
            sys.unlink(w, p)
            local fd, e = facs.open(w, p, { access = R.READ_DATA | R.WRITE_DATA,
                disposition = D.CREATE, sd = with_sacl })
            t:assert(not fd, "a caller without SeSecurityPrivilege cannot supply a SACL: " ..
                sys.errname(e or 0))
        end)

        token.as_principal(t, vm, { privs_present = token.bit(token.PRIV.SECURITY),
            privs_enabled = token.bit(token.PRIV.SECURITY) }, function(w)
            local p = d .. "/withsacl"
            sys.unlink(w, p)
            local fd, e = facs.open(w, p, { access = R.READ_DATA | R.WRITE_DATA,
                disposition = D.CREATE, sd = with_sacl })
            t:assert(fd, "and a caller holding it can: " .. sys.errname(e or 0))
            if fd then sys.close(w, fd) end
        end)
    end)

test("a supplied mandatory label has to satisfy the label-write constraint",
    { spec = "PKM *facs.open.supplied-label-constraint" }, function(t)
        kacs.set_sd(vm, "/", kacs.grant(kacs.ALL_RIGHTS))
        local d = at("label")
        vm:mkdir(d, { parents = true })
        kacs.set_sd(vm, d, kacs.grant(kacs.ALL_RIGHTS))
        local function labelled(level)
            return access.sd({
                owner = token.SID.TEST_USER, group = token.SID.LOCAL_SYSTEM,
                dacl = access.acl({ access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS,
                    token.SID.EVERYONE) }),
                sacl = access.acl({ access.label_ace(level, access.LABEL.NO_WRITE_UP) }),
            })
        end
        -- SeSecurityPrivilege is needed for any SACL at all, so the
        -- label constraint is the only variable left.
        local sec = { privs_present = token.bit(token.PRIV.SECURITY),
                      privs_enabled = token.bit(token.PRIV.SECURITY),
                      integrity_level = token.INTEGRITY.MEDIUM }

        -- Read access only: the strict check runs against the *new*
        -- descriptor (§3.9.2), and a Medium caller asking for write on a
        -- High-labelled object would be refused by NO_WRITE_UP rather
        -- than by the label-write constraint under test.
        token.as_principal(t, vm, sec, function(w)
            local low = d .. "/atorbelow"
            sys.unlink(w, low)
            local fd, e = facs.open(w, low, { access = R.READ_DATA,
                disposition = D.CREATE, sd = labelled(token.INTEGRITY.LOW) })
            t:assert(fd, "a label below the caller's own level is allowed: " ..
                sys.errname(e or 0))
            if fd then sys.close(w, fd) end

            local high = d .. "/above"
            sys.unlink(w, high)
            local no, e2 = facs.open(w, high, { access = R.READ_DATA,
                disposition = D.CREATE, sd = labelled(token.INTEGRITY.HIGH) })
            t:assert(not no, "one above it is refused: " .. sys.errname(e2 or 0))
        end)

        local relabel = { privs_present = token.bit(token.PRIV.SECURITY) | token.bit(token.PRIV.RELABEL),
                          privs_enabled = token.bit(token.PRIV.SECURITY) | token.bit(token.PRIV.RELABEL),
                          integrity_level = token.INTEGRITY.MEDIUM }
        token.as_principal(t, vm, relabel, function(w)
            local p = d .. "/relabelled"
            sys.unlink(w, p)
            local fd, e = facs.open(w, p, { access = R.READ_DATA,
                disposition = D.CREATE, sd = labelled(token.INTEGRITY.HIGH) })
            t:assert(fd, "unless SeRelabelPrivilege is held: " .. sys.errname(e or 0))
            if fd then sys.close(w, fd) end
        end)
    end)

test("native creation uses fixed Linux inode modes",
    { spec = "PKM *facs.open.fixed-create-modes" }, function(t)
        local f = at("mode-file")
        sys.unlink(vm, f)
        local fd = facs.handle(t, vm, f, R.READ_DATA | R.WRITE_DATA, { disposition = D.CREATE })
        sys.close(vm, fd)
        t:assert_eq(sys.stat(vm, f).perm, tonumber("600", 8), "a regular file is 0600")

        local d = at("mode-dir")
        sys.unlink(vm, d, sys.AT_REMOVEDIR)
        local dfd = facs.handle(t, vm, d, R.LIST_DIRECTORY,
            { disposition = D.CREATE, options = kacs.CREATE_OPT.DIRECTORY })
        sys.close(vm, dfd)
        t:assert_eq(sys.stat(vm, d).perm, tonumber("700", 8), "a directory is 0700")
    end)

test("native creation makes regular files and directories, and nothing else",
    { spec = "PKM *facs.open.no-native-special-creation" }, function(t)
        -- `kacs_open_how` has no way to ask for a FIFO, a socket node, a
        -- device node or a symlink: the only create option that shapes
        -- the object is KACS_CREATE_OPT_DIRECTORY, and every other bit
        -- is reserved.
        local f = at("nospecial")
        sys.unlink(vm, f)
        local fd = facs.handle(t, vm, f, R.READ_DATA | R.WRITE_DATA, { disposition = D.CREATE })
        sys.close(vm, fd)
        t:assert(sys.stat(vm, f).is_file, "a native creation is always a regular file")

        -- Those objects stay on the Linux namespace APIs, which do
        -- create them.
        local fifo = at("nospecial-fifo")
        t:assert_eq(sys.mknod(vm, fifo, sys.S_IFIFO | tonumber("600", 8), 0).ret, 0,
            "mknod creates a FIFO")
        t:assert(not sys.stat(vm, fifo).is_file, "which is not a regular file")
        local link = at("nospecial-link")
        sys.unlink(vm, link)
        t:assert_eq(sys.symlink(vm, f, link).ret, 0, "and symlink(2) creates a symlink")
        t:assert(sys.stat(vm, link, { follow = false }).is_symlink, "which is one")
    end)

test("NTFS is excluded from native creation",
    { spec = "PKM *facs.open.ntfs-excluded" }, function(t)
        -- An NTFS volume from the profile's fixtures, loop-mounted with
        -- the ntfs3 driver under a synthesising policy so the mount is
        -- managed (an unmanaged one is refused native creation for that
        -- reason first). The exclusion is the ntfs branch of building
        -- the created file's descriptor, and it answers EOPNOTSUPP —
        -- before anything about the volume's own descriptors is
        -- consulted, which is why this is reachable while PEI-715
        -- (the volume's paths are ENOENT through the Linux API) is not
        -- fixed; facs-storage-mounts carries that case.
        if not fx.present(vm, fx.NTFS_IMAGE) then
            t:skip("the profile was built without mkntfs, so there is no NTFS image")
        end
        local ok, e = fx.load_module(vm, "ntfs3")
        assert(ok, "loading ntfs3: " .. sys.errname(e or 0))
        local dev, loopfd, e2 = fx.loop_attach(vm, fx.NTFS_IMAGE)
        assert(dev, "loop: " .. tostring(loopfd) .. ": " .. sys.errname(e2 or 0))
        local NTFS = "/ntfs"
        local okm, stage, e3 = kacs.new_mount(vm, "ntfs3", NTFS,
            kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL, { source = dev })
        assert(okm, "mounting ntfs3: " .. tostring(stage) .. ": " .. sys.errname(e3 or 0))

        local fd, status = facs.open(vm, NTFS .. "/native",
            { access = R.READ_DATA | R.WRITE_DATA, disposition = D.CREATE })
        t:assert(not fd, "native creation on NTFS is refused")
        if fd then sys.close(vm, fd) end
        t:assert_eq(status, sys.E.OPNOTSUPP,
            "with EOPNOTSUPP, the exclusion's answer: " .. sys.errname(status or 0))
        -- Not for want of a right: the same request one directory up,
        -- on the managed tmpfs, is what the exclusion is measured
        -- against.
        local ok2, s2 = facs.open(vm, at("not-ntfs"),
            { access = R.READ_DATA | R.WRITE_DATA, disposition = D.CREATE })
        t:assert(ok2, "the same creation elsewhere succeeds: " .. sys.errname(s2 or 0))
        if ok2 then sys.close(vm, ok2) end

        sys.umount(vm, NTFS, 0)
        fx.loop_detach(vm, loopfd)
    end)

test("KACS_STATUS_SUPERSEDED is reported only when something was replaced",
    { spec = "PKM *facs.open.status-superseded-only-if-replaced" }, function(t)
        local rw = R.READ_DATA | R.WRITE_DATA
        local existing = facs.file(vm, at("status-existing"), "replace me")
        local fd, st = facs.open(vm, existing, { access = rw, disposition = D.SUPERSEDE })
        t:assert(fd, "supersede over an existing file: " .. sys.errname(st or 0))
        t:assert_eq(st, facs.STATUS.SUPERSEDED, "reports SUPERSEDED")
        sys.close(vm, fd)

        local absent = at("status-absent")
        sys.unlink(vm, absent)
        local fd2, st2 = facs.open(vm, absent, { access = rw, disposition = D.SUPERSEDE })
        t:assert(fd2, "supersede that finds no target: " .. sys.errname(st2 or 0))
        t:assert_eq(st2, facs.STATUS.CREATED, "reports CREATED, not SUPERSEDED")
        sys.close(vm, fd2)
    end)
