-- PKM §3.9.4 — ioctl classification and execution: the right each known
-- ioctl takes, what the 32-bit compat aliases inherit, which commands
-- are descriptor-local, where Linux's own capability checks still sit on
-- top, and the two layers an exec passes through.
--
-- Where a command is allowed by KACS the filesystem usually answers for
-- itself (tmpfs implements few of these), so the positive half of a case
-- asserts "no longer EACCES" rather than success: the subject is which
-- layer refuses, not whether tmpfs implements FITRIM.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local facs = require("helpers.facs")

local vm = provium:vm("v", "kernel-only"):boot()

local R = kacs.RIGHT
local B = facs.workspace(vm, "use-ioctl")

local function file(name, content)
    local p = B .. "/" .. name
    kacs.set_sd(vm, B, kacs.grant(kacs.ALL_RIGHTS))
    vm:write_file(p, content or string.rep("i", 64))
    kacs.set_sd(vm, p, kacs.grant(kacs.ALL_RIGHTS))
    return p
end

local function with(t, path, mask, fn)
    local fd = facs.handle(t, vm, path, mask)
    local ok, err = pcall(fn, fd)
    sys.close(vm, fd)
    if not ok then error(err, 0) end
end

local WORD = string.rep("\0", 8)
local BIG = string.rep("\0", 256)

test("known ioctls are classified by the right they require",
    { spec = "PKM *facs.use.ioctl-classification" }, function(t)
        local p = file("classify")

        -- FILE_READ_ATTRIBUTES readers.
        local readers = {
            { "FIGETBSZ", facs.IOC.FIGETBSZ, WORD },
            { "FIOQSIZE", facs.IOC.FIOQSIZE, WORD },
            { "FS_IOC_GETFLAGS", facs.IOC.FS_IOC_GETFLAGS, WORD },
            { "FS_IOC_GETVERSION", facs.IOC.FS_IOC_GETVERSION, WORD },
            { "FS_IOC_FSGETXATTR", facs.IOC.FS_IOC_FSGETXATTR, BIG },
            { "FS_IOC_GETFSUUID", facs.IOC.FS_IOC_GETFSUUID, BIG },
            { "FS_IOC_GET_ENCRYPTION_POLICY", facs.IOC.FS_IOC_GET_ENCRYPTION_POLICY, BIG },
        }
        with(t, p, R.READ_DATA, function(fd)
            for _, c in ipairs(readers) do
                t:assert_eq(facs.ioctl(vm, fd, c[2], c[3]).errno, sys.E.ACCES,
                    c[1] .. " needs FILE_READ_ATTRIBUTES")
            end
        end)
        with(t, p, R.READ_DATA | R.READ_ATTRIBUTES, function(fd)
            for _, c in ipairs(readers) do
                t:assert_neq(facs.ioctl(vm, fd, c[2], c[3]).errno, sys.E.ACCES,
                    c[1] .. " is no longer refused by KACS")
            end
        end)

        -- FILE_WRITE_ATTRIBUTES writers.
        local writers = {
            { "FS_IOC_SETFLAGS", facs.IOC.FS_IOC_SETFLAGS, WORD },
            { "FS_IOC_SETVERSION", facs.IOC.FS_IOC_SETVERSION, WORD },
            { "FS_IOC_FSSETXATTR", facs.IOC.FS_IOC_FSSETXATTR, BIG },
            { "FS_IOC_SETFSLABEL", facs.IOC.FS_IOC_SETFSLABEL, BIG },
            { "FS_IOC_SET_ENCRYPTION_POLICY", facs.IOC.FS_IOC_SET_ENCRYPTION_POLICY, BIG },
        }
        with(t, p, R.READ_DATA | R.READ_ATTRIBUTES, function(fd)
            for _, c in ipairs(writers) do
                t:assert_eq(facs.ioctl(vm, fd, c[2], c[3]).errno, sys.E.ACCES,
                    c[1] .. " needs FILE_WRITE_ATTRIBUTES")
            end
        end)
        with(t, p, R.READ_DATA | R.WRITE_ATTRIBUTES, function(fd)
            for _, c in ipairs(writers) do
                t:assert_neq(facs.ioctl(vm, fd, c[2], c[3]).errno, sys.E.ACCES,
                    c[1] .. " is no longer refused by KACS")
            end
        end)

        -- FILE_READ_DATA.
        with(t, p, R.WRITE_DATA, function(fd)
            t:assert_eq(facs.ioctl(vm, fd, facs.IOC.FIONREAD, WORD).errno, sys.E.ACCES,
                "FIONREAD on a regular file needs FILE_READ_DATA")
            t:assert_eq(facs.ioctl(vm, fd, facs.IOC.FS_IOC_FIEMAP, BIG).errno, sys.E.ACCES,
                "and so does FS_IOC_FIEMAP")
        end)
        with(t, p, R.READ_DATA, function(fd)
            t:assert_eq(facs.ioctl(vm, fd, facs.IOC.FIONREAD, WORD).ret, 0,
                "with it, FIONREAD answers")
        end)

        -- FILE_WRITE_DATA.
        local mutators = {
            { "FS_IOC_UNRESVSP", facs.IOC.FS_IOC_UNRESVSP, BIG },
            { "FS_IOC_ZERO_RANGE", facs.IOC.FS_IOC_ZERO_RANGE, BIG },
            { "FICLONERANGE", facs.IOC.FICLONERANGE, BIG },
            { "FIDEDUPERANGE", facs.IOC.FIDEDUPERANGE, BIG },
        }
        with(t, p, R.READ_DATA | R.APPEND_DATA, function(fd)
            for _, c in ipairs(mutators) do
                t:assert_eq(facs.ioctl(vm, fd, c[2], c[3]).errno, sys.E.ACCES,
                    c[1] .. " needs FILE_WRITE_DATA")
            end
            -- The preallocation commands take append or write.
            t:assert_neq(facs.ioctl(vm, fd, facs.IOC.FS_IOC_RESVSP, BIG).errno, sys.E.ACCES,
                "while FS_IOC_RESVSP takes FILE_APPEND_DATA")
        end)
        with(t, p, R.READ_DATA | R.WRITE_DATA, function(fd)
            for _, c in ipairs(mutators) do
                t:assert_neq(facs.ioctl(vm, fd, c[2], c[3]).errno, sys.E.ACCES,
                    c[1] .. " is no longer refused by KACS")
            end
        end)

        -- Anything unclassified is allowed on any data right, and
        -- refused without one.
        with(t, p, R.READ_DATA, function(fd)
            t:assert_neq(facs.ioctl(vm, fd, facs.IOC.UNCLASSIFIED, WORD).errno, sys.E.ACCES,
                "an unclassified command passes on a data right")
        end)
        with(t, p, R.EXECUTE, function(fd)
            t:assert_eq(facs.ioctl(vm, fd, facs.IOC.UNCLASSIFIED, WORD).errno, sys.E.ACCES,
                "and is refused on a handle carrying none")
        end)
    end)

test("the 32-bit compat aliases take their native command's right",
    { spec = "PKM *facs.use.ioctl-compat-aliases" }, function(t)
        local p = file("compat")
        local pairs_ = {
            { "FS_IOC32_GETFLAGS", facs.IOC.FS_IOC32_GETFLAGS, R.READ_ATTRIBUTES },
            { "FS_IOC32_GETVERSION", facs.IOC.FS_IOC32_GETVERSION, R.READ_ATTRIBUTES },
            { "FS_IOC32_SETFLAGS", facs.IOC.FS_IOC32_SETFLAGS, R.WRITE_ATTRIBUTES },
            { "FS_IOC32_SETVERSION", facs.IOC.FS_IOC32_SETVERSION, R.WRITE_ATTRIBUTES },
        }
        for _, c in ipairs(pairs_) do
            with(t, p, R.READ_DATA, function(fd)
                t:assert_eq(facs.ioctl(vm, fd, c[2], WORD).errno, sys.E.ACCES,
                    c[1] .. " is refused without its native command's right")
            end)
            with(t, p, R.READ_DATA | c[3], function(fd)
                t:assert_neq(facs.ioctl(vm, fd, c[2], WORD).errno, sys.E.ACCES,
                    c[1] .. " passes with it")
            end)
        end
        -- The compat preallocation commands normalise the same way.
        with(t, p, R.READ_DATA, function(fd)
            t:assert_eq(facs.ioctl(vm, fd, facs.IOC.FS_IOC_ZERO_RANGE_32, BIG).errno,
                sys.E.ACCES, "the compat FS_IOC_ZERO_RANGE needs FILE_WRITE_DATA")
        end)
        with(t, p, R.READ_DATA | R.APPEND_DATA, function(fd)
            t:assert_neq(facs.ioctl(vm, fd, facs.IOC.FS_IOC_RESVSP_32, BIG).errno,
                sys.E.ACCES, "and the compat FS_IOC_RESVSP takes FILE_APPEND_DATA")
        end)
    end)

test("FIOCLEX, FIONCLEX, FIONBIO and FIOASYNC are descriptor-local",
    { spec = "PKM *facs.use.ioctl-descriptor-local" }, function(t)
        local p = file("fdlocal")
        -- An execute-only handle carries no data right and no attribute
        -- right, so anything requiring one would be refused.
        with(t, p, R.EXECUTE, function(fd)
            t:assert_eq(facs.ioctl(vm, fd, facs.IOC.FIOCLEX).ret, 0,
                "FIOCLEX sets close-on-exec")
            t:assert_eq(facs.fcntl(vm, fd, facs.F.GETFD, 0).ret, 1, "and it took effect")
            t:assert_eq(facs.ioctl(vm, fd, facs.IOC.FIONCLEX).ret, 0, "FIONCLEX clears it")
            t:assert_eq(facs.fcntl(vm, fd, facs.F.GETFD, 0).ret, 0, "and that took effect too")
            t:assert_neq(facs.ioctl(vm, fd, facs.IOC.FIONBIO, string.pack("<i4", 1)).errno,
                sys.E.ACCES, "FIONBIO requires no KACS right")
            t:assert_neq(facs.ioctl(vm, fd, facs.IOC.FIOASYNC, string.pack("<i4", 0)).errno,
                sys.E.ACCES, "and neither does FIOASYNC")
        end)
    end)

test("the freeze ioctls keep Linux's CAP_SYS_ADMIN check on top of the KACS right",
    { spec = "PKM *facs.use.ioctl-freeze-cap-sys-admin" }, function(t)
        kacs.set_sd(vm, "/", kacs.grant(kacs.ALL_RIGHTS))
        local p = file("freeze")
        local RANGE = string.rep("\0", 24)

        -- KACS refuses first, on the mask.
        with(t, p, R.READ_DATA | R.READ_ATTRIBUTES, function(fd)
            for _, c in ipairs({ { "FIFREEZE", facs.IOC.FIFREEZE },
                                 { "FITHAW", facs.IOC.FITHAW },
                                 { "FITRIM", facs.IOC.FITRIM } }) do
                t:assert_eq(facs.ioctl(vm, fd, c[2], RANGE).errno, sys.E.ACCES,
                    c[1] .. " needs FILE_WRITE_ATTRIBUTES")
            end
        end)

        -- Past that, an ordinary user meets CAP_SYS_ADMIN, which the
        -- capability switchboard resolves to SeTcbPrivilege. tmpfs
        -- implements no freeze operation, so a caller that clears the
        -- capability gets EOPNOTSUPP and never freezes anything.
        token.as_principal(t, vm, {}, function(w)
            local fd, e = facs.open(w, p, { access = R.READ_DATA | R.WRITE_ATTRIBUTES })
            t:assert(fd, "the principal opens a handle carrying the right: " ..
                sys.errname(e or 0))
            if fd then
                local r = facs.ioctl(w, fd, facs.IOC.FIFREEZE, RANGE)
                t:assert(r.ret ~= 0, "and FIFREEZE is still refused")
                t:assert_eq(r.errno, sys.E.PERM,
                    "by Linux's CAP_SYS_ADMIN check rather than by KACS: " ..
                    sys.errname(r.errno))
                sys.close(w, fd)
            end
        end)

        -- SYSTEM holds SeTcbPrivilege and gets past both, to the
        -- filesystem's own answer.
        with(t, p, R.READ_DATA | R.WRITE_ATTRIBUTES, function(fd)
            local r = facs.ioctl(vm, fd, facs.IOC.FIFREEZE, RANGE)
            t:assert_neq(r.errno, sys.E.ACCES, "a TCB holder is past KACS")
            t:assert_neq(r.errno, sys.E.PERM, "and past CAP_SYS_ADMIN")
            t:assert_eq(r.errno, sys.E.OPNOTSUPP,
                "reaching tmpfs, which supports no freeze: " .. sys.errname(r.errno))
        end)
    end)

test("FS_IOC_GETFLAGS and FS_IOC_SETFLAGS take the same rights on a directory",
    { spec = "PKM *facs.use.ioctl-flags-on-directories" }, function(t)
        local d = B .. "/flags-dir"
        vm:mkdir(d, { parents = true })
        kacs.set_sd(vm, d, kacs.grant(kacs.ALL_RIGHTS))

        with(t, d, R.LIST_DIRECTORY, function(fd)
            t:assert_eq(facs.ioctl(vm, fd, facs.IOC.FS_IOC_GETFLAGS, WORD).errno,
                sys.E.ACCES, "FS_IOC_GETFLAGS on a directory needs FILE_READ_ATTRIBUTES")
        end)
        with(t, d, R.LIST_DIRECTORY | R.READ_ATTRIBUTES, function(fd)
            local got = sys.ioctl_word(vm, fd, facs.IOC.FS_IOC_GETFLAGS, 0)
            t:assert(got, "with it the flags read back")
            t:assert_eq(facs.ioctl(vm, fd, facs.IOC.FS_IOC_SETFLAGS,
                string.pack("<I8", got)).errno, sys.E.ACCES,
                "FS_IOC_SETFLAGS still needs FILE_WRITE_ATTRIBUTES")
        end)
        with(t, d, R.LIST_DIRECTORY | R.READ_ATTRIBUTES | R.WRITE_ATTRIBUTES, function(fd)
            local got = assert(sys.ioctl_word(vm, fd, facs.IOC.FS_IOC_GETFLAGS, 0))
            t:assert_neq(facs.ioctl(vm, fd, facs.IOC.FS_IOC_SETFLAGS,
                string.pack("<I8", got)).errno, sys.E.ACCES,
                "and with that it is no longer refused by KACS")
        end)
    end)

test("a device node's own descriptor is the boundary, and the device may still deny",
    { spec = "PKM *facs.use.ioctl-device-semantics-out-of-scope" }, function(t)
        local node = B .. "/null"
        sys.unlink(vm, node)
        t:assert_eq(sys.mknod(vm, node, sys.S_IFCHR | tonumber("600", 8),
            (1 << 8) | 3).ret, 0, "a character device node is created")
        kacs.set_sd(vm, node, kacs.grant(kacs.ALL_RIGHTS))

        -- The node's descriptor governs: an attribute ioctl is refused
        -- on a handle whose mask lacks the right, exactly as on a file.
        with(t, node, R.READ_DATA | R.WRITE_DATA, function(fd)
            t:assert_eq(facs.ioctl(vm, fd, facs.IOC.FS_IOC_GETFLAGS, WORD).errno,
                sys.E.ACCES, "FS_IOC_GETFLAGS is refused on the node's mask")
        end)

        -- Past the boundary, the device decides. /dev/null implements
        -- none of these, and answers for itself.
        with(t, node, R.READ_DATA | R.WRITE_DATA | R.READ_ATTRIBUTES, function(fd)
            local r = facs.ioctl(vm, fd, facs.IOC.UNCLASSIFIED, WORD)
            t:assert(r.ret ~= 0, "an unclassified command reaches the device")
            t:assert_neq(r.errno, sys.E.ACCES,
                "and is refused by it, not by KACS: " .. sys.errname(r.errno))
            t:assert_eq(r.errno, sys.E.NOTTY, "ENOTTY from the device")
        end)

        -- A pipe behaves the same way: FIONREAD is a data-right check
        -- for KACS and the pipe implements it.
        local rd, wr = sys.pipe(vm)
        t:assert(rd, "a pipe is created")
        t:assert_eq(facs.ioctl(vm, rd, facs.IOC.FIONREAD, WORD).ret, 0,
            "FIONREAD on a pipe is answered by the pipe")
        sys.close(vm, rd); sys.close(vm, wr)
    end)

test("execution is two layers, and KACS enforces only FILE_EXECUTE",
    { spec = "PKM *facs.use.execution" }, function(t)
        local p = file("exec-layers", "#!/nothing\n")
        sys.chmod(vm, p, tonumber("644", 8))

        -- The mode execute bit is a prerequisite for execve and
        -- execveat, and applies to neither mmap(PROT_EXEC) nor the
        -- descriptor's mask. A handle carrying FILE_EXECUTE maps
        -- PROT_EXEC over a file with no +x bit.
        with(t, p, R.READ_DATA | R.EXECUTE, function(fd)
            local addr = sys.mmap(vm, fd, 4096, sys.PROT.READ | facs.PROT_EXEC,
                sys.MAP.PRIVATE)
            t:assert(addr, "mmap(PROT_EXEC) is granted by FILE_EXECUTE alone")
            if addr then sys.munmap(vm, addr, 4096) end
        end)

        -- And FILE_EXECUTE is what KACS itself gates: withdraw it and
        -- the same mapping is refused, +x or not.
        t:assert_eq(kacs.set_sd(vm, p, kacs.grant_all_but(R.EXECUTE)).ret, 0,
            "FILE_EXECUTE is withdrawn from the object")
        kacs.as_dacl_bound(t, vm, function(w)
            local no, e = facs.open(w, p, { access = R.READ_DATA | R.EXECUTE })
            t:assert(not no, "and a handle naming it can no longer be opened")
            t:assert_eq(e, sys.E.ACCES, "EACCES: " .. sys.errname(e or 0))
        end)
        kacs.set_sd(vm, p, kacs.grant(kacs.ALL_RIGHTS))
    end)

test("the execute mode bit is Linux's rule, which KACS inherits",
    { spec = "PKM *facs.use.exec-mode-bit-from-linux" }, function(t)
        local p = file("exec-modebit", "not a program at all\n")
        sys.chmod(vm, p, tonumber("644", 8))

        with(t, p, R.EXECUTE, function(fd)
            local r = facs.execveat_fd(vm, fd)
            t:assert(r.ret ~= 0, "an exec of a file with no +x bit fails")
            t:assert_eq(r.errno, sys.E.ACCES,
                "with EACCES from Linux's own generic_permission: " ..
                sys.errname(r.errno))
        end)

        -- Nothing about the descriptor changed; only the mode bit did.
        sys.chmod(vm, p, tonumber("755", 8))
        with(t, p, R.EXECUTE, function(fd)
            local r = facs.execveat_fd(vm, fd)
            t:assert_neq(r.errno, sys.E.ACCES,
                "and with +x set the exec is no longer refused: " ..
                sys.errname(r.errno))
            t:assert_eq(r.errno, 8,
                "reaching ENOEXEC, which is the format check and nothing to do with access")
        end)
    end)

test("descriptor-based exec runs a live AccessCheck, not the cached mask",
    { spec = "PKM *facs.use.execveat-live-check" }, function(t)
        local p = file("exec-live", "#!/nothing\n")
        sys.chmod(vm, p, tonumber("755", 8))

        local fd = facs.handle(t, vm, p, R.EXECUTE)
        -- The cached mask carries FILE_EXECUTE and always will. The
        -- object's descriptor is what the bprm hook consults.
        t:assert_neq(facs.execveat_fd(vm, fd).errno, sys.E.ACCES,
            "the exec passes while the object grants FILE_EXECUTE")

        t:assert_eq(kacs.set_sd(vm, p, kacs.grant_all_but(R.EXECUTE)).ret, 0,
            "FILE_EXECUTE is withdrawn under the open handle")
        kacs.as_dacl_bound(t, vm, function(w)
            -- The bounded caller is judged on the object as it stands,
            -- through a descriptor whose cached mask says otherwise.
            local r = facs.execveat_fd(w, fd)
            t:assert(r.ret ~= 0, "and the exec is now refused")
            t:assert_eq(r.errno, sys.E.ACCES, "EACCES: " .. sys.errname(r.errno))
        end)

        t:assert_eq(kacs.set_sd(vm, p, kacs.grant(kacs.ALL_RIGHTS)).ret, 0,
            "granted again")
        t:assert_neq(facs.execveat_fd(vm, fd).errno, sys.E.ACCES,
            "and the same handle passes once more")
        sys.close(vm, fd)
    end)
