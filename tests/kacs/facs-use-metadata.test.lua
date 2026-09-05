-- PKM §3.9.4 — use-time metadata, directory traversal and watch
-- placement: the right each attribute, ownership, xattr and access
-- query takes, what FILE_TRAVERSE governs and where
-- SeChangeNotifyPrivilege does and does not carry a caller past it.
--
-- Descriptor-based rows are pure mask checks, so they are two native
-- opens of one file and need no bounded caller. The *path*-based rows —
-- stat by name, chdir, faccessat, watch placement — are live
-- AccessChecks against the object's own descriptor, so those run in a
-- caller stripped of the DACL-bypassing privileges, or in a freshly
-- minted principal where the subject is a privilege the agent holds.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local facs = require("helpers.facs")

local vm = provium:vm("v", "kernel-only"):boot()

local R = kacs.RIGHT
local B = facs.workspace(vm, "use-meta")

--- Everything except SeChangeNotifyPrivilege, so a bounded caller that
--- still holds the traverse bypass can be built.
local KEEP_CHANGE_NOTIFY = kacs.PRIV.SECURITY | kacs.PRIV.TAKE_OWNERSHIP
    | kacs.PRIV.BACKUP | kacs.PRIV.RESTORE

local function file(name, content)
    local p = B .. "/" .. name
    kacs.set_sd(vm, B, kacs.grant(kacs.ALL_RIGHTS))
    vm:write_file(p, content or "metadata")
    kacs.set_sd(vm, p, kacs.grant(kacs.ALL_RIGHTS))
    return p
end

local function with(t, path, mask, fn)
    local fd = facs.handle(t, vm, path, mask)
    local ok, err = pcall(fn, fd)
    sys.close(vm, fd)
    if not ok then error(err, 0) end
end

test("each metadata operation takes the right the table names",
    { spec = "PKM *facs.use.metadata-operations" }, function(t)
        local p = file("meta")

        -- fstat / descriptor statx / fstatfs: FILE_READ_ATTRIBUTES.
        with(t, p, R.READ_DATA, function(fd)
            t:assert(not sys.fstat(vm, fd), "fstat needs FILE_READ_ATTRIBUTES")
            t:assert_eq(facs.statx_fd(vm, fd).errno, sys.E.ACCES, "and so does statx")
            t:assert_eq(facs.fstatfs(vm, fd).errno, sys.E.ACCES, "and fstatfs")
        end)
        with(t, p, R.READ_DATA | R.READ_ATTRIBUTES, function(fd)
            t:assert(sys.fstat(vm, fd), "with it, fstat succeeds")
            t:assert_eq(facs.statx_fd(vm, fd).ret, 0, "statx too")
            t:assert_eq(facs.fstatfs(vm, fd).ret, 0, "and fstatfs")
        end)

        -- futimens: FILE_WRITE_ATTRIBUTES.
        with(t, p, R.READ_DATA, function(fd)
            t:assert_eq(facs.futimens(vm, fd, 100).errno, sys.E.ACCES,
                "futimens needs FILE_WRITE_ATTRIBUTES")
        end)
        with(t, p, R.READ_DATA | R.WRITE_ATTRIBUTES, function(fd)
            t:assert_eq(facs.futimens(vm, fd, 100).ret, 0, "and has it here")
        end)

        -- fgetxattr: FILE_READ_EA. fsetxattr / fremovexattr: FILE_WRITE_EA.
        with(t, p, R.READ_DATA | R.WRITE_EA, function(fd)
            t:assert_eq(facs.fsetxattr(vm, fd, "user.k", "v").ret, 0,
                "fsetxattr takes FILE_WRITE_EA")
            local _, e = sys.fgetxattr(vm, fd, "user.k")
            t:assert_eq(e, sys.E.ACCES, "while fgetxattr needs FILE_READ_EA")
        end)
        with(t, p, R.READ_DATA | R.READ_EA, function(fd)
            t:assert_eq(sys.fgetxattr(vm, fd, "user.k"), "v", "which it has here")
            t:assert_eq(facs.fsetxattr(vm, fd, "user.k", "w").errno, sys.E.ACCES,
                "and fsetxattr is now the one refused")
            t:assert_eq(facs.fremovexattr(vm, fd, "user.k").errno, sys.E.ACCES,
                "as is fremovexattr")
        end)

        -- Path-based rows are live checks against the object's own
        -- descriptor, so they need a caller the DACL binds.
        local q = file("meta-path")
        -- faccessat X_OK also passes through Linux's own MAY_EXEC rule,
        -- which refuses a file with no execute mode bit (§3.9.4's
        -- "the +x requirement is a Linux DAC property KACS inherits").
        sys.chmod(vm, q, tonumber("755", 8))
        kacs.as_dacl_bound(t, vm, function(w)
            t:assert_eq(kacs.set_sd(vm, q, kacs.grant_all_but(R.READ_ATTRIBUTES)).ret, 0,
                "FILE_READ_ATTRIBUTES is withdrawn")
            local _, e = sys.stat(w, q)
            t:assert_eq(e, sys.E.ACCES, "stat by pathname needs it: " .. sys.errname(e or 0))
            t:assert_eq(facs.faccessat(w, q, facs.F_OK).errno, sys.E.ACCES,
                "and so does faccessat F_OK")

            kacs.set_sd(vm, q, kacs.grant(kacs.ALL_RIGHTS))
            t:assert(sys.stat(w, q), "with it, stat succeeds")
            t:assert_eq(facs.faccessat(w, q, facs.F_OK).ret, 0, "and faccessat F_OK")

            -- access(2) R_OK / W_OK / X_OK map to the data rights.
            for _, c in ipairs({ { "R_OK", facs.R_OK, R.READ_DATA },
                                 { "W_OK", facs.W_OK, R.WRITE_DATA },
                                 { "X_OK", facs.X_OK, R.EXECUTE } }) do
                kacs.set_sd(vm, q, kacs.grant_all_but(c[3]))
                t:assert_eq(facs.faccessat(w, q, c[2]).errno, sys.E.ACCES,
                    "faccessat " .. c[1] .. " needs its own right")
                kacs.set_sd(vm, q, kacs.grant(kacs.ALL_RIGHTS))
                t:assert_eq(facs.faccessat(w, q, c[2]).ret, 0,
                    "and passes with it: " .. c[1])
            end

            -- truncate by pathname: FILE_WRITE_DATA.
            kacs.set_sd(vm, q, kacs.grant_all_but(R.WRITE_DATA))
            t:assert_eq(facs.truncate(w, q, 0).errno, sys.E.ACCES,
                "truncate by pathname needs FILE_WRITE_DATA")
            kacs.set_sd(vm, q, kacs.grant(kacs.ALL_RIGHTS))
            t:assert_eq(facs.truncate(w, q, 0).ret, 0, "and has it here")
        end)
    end)

test("chmod requires WRITE_DAC",
    { spec = "PKM *facs.use.chmod-requires-write-dac" }, function(t)
        local p = file("chmod")
        with(t, p, R.READ_DATA, function(fd)
            t:assert_eq(facs.fchmod(vm, fd, tonumber("640", 8)).errno, sys.E.ACCES,
                "a handle without WRITE_DAC cannot fchmod")
        end)
        with(t, p, R.READ_DATA | R.WRITE_DAC, function(fd)
            t:assert_eq(facs.fchmod(vm, fd, tonumber("640", 8)).ret, 0,
                "and with it the same call succeeds")
        end)
        -- The pathname forms take the same right. They are not
        -- demonstrated by withdrawing it from the DACL, because an
        -- object's owner is granted WRITE_DAC implicitly and the
        -- bounded caller here is the owner — the cached-mask case above
        -- is the one that isolates the right.
    end)

test("chown requires WRITE_OWNER",
    { spec = "PKM *facs.use.chown-requires-write-owner" }, function(t)
        local p = file("chown")
        with(t, p, R.READ_DATA, function(fd)
            t:assert_eq(facs.fchown(vm, fd, 0, 0).errno, sys.E.ACCES,
                "a handle without WRITE_OWNER cannot fchown")
        end)
        with(t, p, R.READ_DATA | R.WRITE_OWNER, function(fd)
            t:assert_eq(facs.fchown(vm, fd, 0, 0).ret, 0,
                "and with it the same call succeeds")
        end)
        kacs.as_dacl_bound(t, vm, function(w)
            kacs.set_sd(vm, p, kacs.grant_all_but(R.WRITE_OWNER))
            t:assert_eq(sys.chown(w, p, 0, 0).errno, sys.E.ACCES,
                "chown by pathname needs WRITE_OWNER too")
        end)
        kacs.set_sd(vm, p, kacs.grant(kacs.ALL_RIGHTS))
    end)

test("listxattr needs no right at all",
    { spec = "PKM *facs.use.listxattr-needs-no-right" }, function(t)
        local p = file("listxattr")
        local fd = facs.handle(t, vm, p, R.READ_DATA | R.WRITE_EA)
        t:assert_eq(facs.fsetxattr(vm, fd, "user.listed", "v").ret, 0, "an xattr is set")
        sys.close(vm, fd)

        -- An execute-only handle carries no data right, no
        -- FILE_READ_EA and no FILE_READ_ATTRIBUTES.
        with(t, p, R.EXECUTE, function(x)
            local r = facs.flistxattr(vm, x)
            t:assert(r.ret >= 0, "flistxattr succeeds on a handle granting nothing else: " ..
                sys.errname(r.errno))
            t:assert(r.out_bufs[1]:sub(1, r.ret):find("user.listed", 1, true),
                "and lists the name")
        end)

        -- The pathname form likewise, against a descriptor granting
        -- nothing.
        kacs.as_dacl_bound(t, vm, function(w)
            kacs.set_sd(vm, p, kacs.deny_all())
            local names = sys.listxattr(w, p)
            t:assert(names, "listxattr by pathname needs nothing either")
        end)
        kacs.set_sd(vm, p, kacs.grant(kacs.ALL_RIGHTS))
    end)

--- A minimal POSIX ACL blob. The call never gets far enough for its
--- contents to matter.
local POSIX_ACL = string.pack("<I4", 2) ..
    string.pack("<I2I2I4", 1, 6, 0xFFFFFFFF) ..    -- user_obj  rw-
    string.pack("<I2I2I4", 4, 4, 0xFFFFFFFF) ..    -- group_obj r--
    string.pack("<I2I2I4", 32, 4, 0xFFFFFFFF)      -- other     r--

test("a POSIX ACL xattr write by pathname is denied with EOPNOTSUPP",
    { spec = "PKM *facs.use.posix-acl-write-eopnotsupp" }, function(t)
        local p = file("posixacl")
        for _, name in ipairs({ "system.posix_acl_access", "system.posix_acl_default" }) do
            local set = sys.setxattr(vm, p, name, POSIX_ACL)
            t:assert(set.ret ~= 0, "setxattr of " .. name .. " is refused")
            t:assert_eq(set.errno, sys.E.OPNOTSUPP,
                "with EOPNOTSUPP so probe-then-tolerate callers behave: " ..
                sys.errname(set.errno))
            local rm = sys.removexattr(vm, p, name)
            t:assert(rm.ret ~= 0, "and so is removexattr")
            t:assert_eq(rm.errno, sys.E.OPNOTSUPP, "EOPNOTSUPP: " .. sys.errname(rm.errno))
        end
        -- Unconditional: the caller here is SYSTEM and the object
        -- grants every right, so nothing about the mask is involved.
    end)

test("a POSIX ACL xattr write through a descriptor is denied with EOPNOTSUPP",
    { spec = "PKM *facs.use.posix-acl-write-eopnotsupp", tags = { "known-bug" } },
    function(t)
        -- §3.9.4 names fsetxattr and fremovexattr in the same row as the
        -- pathname forms and says the POSIX ACL refusal is EOPNOTSUPP
        -- "rather than EACCES so that probe-then-tolerate callers behave
        -- sensibly". The descriptor hook answers EACCES.
        local p = file("posixacl-fd")
        with(t, p, R.READ_DATA | R.WRITE_DATA | R.WRITE_EA | R.READ_EA, function(fd)
            local set = facs.fsetxattr(vm, fd, "system.posix_acl_access", POSIX_ACL)
            t:assert(set.ret ~= 0, "fsetxattr of a POSIX ACL is refused")
            t:assert_eq(set.errno, sys.E.OPNOTSUPP, "with EOPNOTSUPP: " ..
                sys.errname(set.errno))
            local rm = facs.fremovexattr(vm, fd, "system.posix_acl_access")
            t:assert(rm.ret ~= 0, "and so is fremovexattr")
            t:assert_eq(rm.errno, sys.E.OPNOTSUPP, "EOPNOTSUPP: " .. sys.errname(rm.errno))
        end)
    end)

test("path resolution checks FILE_TRAVERSE on managed directory components",
    { spec = "PKM *facs.use.directory-traversal" }, function(t)
        local outer = B .. "/walk"
        local inner = outer .. "/inner"
        vm:mkdir(inner, { parents = true })
        local leaf = inner .. "/leaf"
        vm:write_file(leaf, "leaf")
        for _, d in ipairs({ outer, inner, leaf }) do
            kacs.set_sd(vm, d, kacs.grant(kacs.ALL_RIGHTS))
        end

        kacs.as_dacl_bound(t, vm, function(w)
            local fd = sys.open(w, leaf, sys.O.RDONLY)
            t:assert(fd, "the leaf opens while every component permits traversal")
            if fd then sys.close(w, fd) end

            -- Withdraw FILE_TRAVERSE from the intermediate component
            -- only; the leaf's own descriptor is untouched.
            t:assert_eq(kacs.set_sd(vm, inner, kacs.grant_all_but(R.TRAVERSE)).ret, 0,
                "the intermediate directory loses FILE_TRAVERSE")
            local no, e = sys.open(w, leaf, sys.O.RDONLY)
            t:assert(not no, "and the leaf is no longer reachable")
            t:assert_eq(e, sys.E.ACCES, "EACCES: " .. sys.errname(e or 0))
        end, { privs = KEEP_CHANGE_NOTIFY | kacs.PRIV.CHANGE_NOTIFY })
        kacs.set_sd(vm, inner, kacs.grant(kacs.ALL_RIGHTS))
    end)

test("SeChangeNotifyPrivilege bypasses the intermediate traverse checks",
    { spec = "PKM *facs.use.change-notify-bypasses-traverse" }, function(t)
        local outer = B .. "/cn"
        local inner = outer .. "/inner"
        vm:mkdir(inner, { parents = true })
        local leaf = inner .. "/leaf"
        vm:write_file(leaf, "leaf")
        for _, d in ipairs({ outer, leaf }) do
            kacs.set_sd(vm, d, kacs.grant(kacs.ALL_RIGHTS))
        end
        t:assert_eq(kacs.set_sd(vm, inner, kacs.grant_all_but(R.TRAVERSE)).ret, 0,
            "the intermediate directory denies FILE_TRAVERSE")

        -- A caller whose SeChangeNotifyPrivilege has been deleted is
        -- stopped by it.
        kacs.as_dacl_bound(t, vm, function(w)
            local no, e = sys.open(w, leaf, sys.O.RDONLY)
            t:assert(not no, "without the privilege the walk is refused")
            t:assert_eq(e, sys.E.ACCES, "EACCES: " .. sys.errname(e or 0))
        end, { privs = KEEP_CHANGE_NOTIFY | kacs.PRIV.CHANGE_NOTIFY })

        -- One that still holds it walks straight through.
        kacs.as_dacl_bound(t, vm, function(w)
            local fd, e = sys.open(w, leaf, sys.O.RDONLY)
            t:assert(fd, "with it the same walk succeeds: " .. sys.errname(e or 0))
            if fd then sys.close(w, fd) end
        end, { privs = KEEP_CHANGE_NOTIFY })

        -- And it reaches a directory with no descriptor at all: an
        -- unmanaged mount below the same tree behaves the same way.
        kacs.set_sd(vm, inner, kacs.grant(kacs.ALL_RIGHTS))
    end)

test("chdir and chroot take a live FILE_TRAVERSE check the privilege does not bypass",
    { spec = "PKM *facs.use.chdir-chroot-live-check" }, function(t)
        local d = B .. "/explicit"
        vm:mkdir(d, { parents = true })
        kacs.set_sd(vm, d, kacs.grant(kacs.ALL_RIGHTS))

        kacs.as_dacl_bound(t, vm, function(w)
            t:assert_eq(facs.chdir(w, d).ret, 0, "chdir succeeds while traverse is granted")
            t:assert_eq(kacs.set_sd(vm, d, kacs.grant_all_but(R.TRAVERSE)).ret, 0,
                "FILE_TRAVERSE is withdrawn")
            local r = facs.chdir(w, d)
            t:assert(r.ret ~= 0, "and the very next chdir is refused — the check is live")
            t:assert_eq(r.errno, sys.E.ACCES, "EACCES: " .. sys.errname(r.errno))
        end, { privs = KEEP_CHANGE_NOTIFY })

        -- The privilege bypass does not apply: an explicit change of
        -- directory is not intermediate resolution.
        kacs.as_dacl_bound(t, vm, function(w)
            local r = facs.chdir(w, d)
            t:assert(r.ret ~= 0, "a holder of SeChangeNotifyPrivilege is refused too")
            t:assert_eq(r.errno, sys.E.ACCES, "EACCES: " .. sys.errname(r.errno))
            local c = facs.chroot(w, d)
            t:assert(c.ret ~= 0, "and so is chroot")
            t:assert_eq(c.errno, sys.E.ACCES, "EACCES: " .. sys.errname(c.errno))
        end, { privs = KEEP_CHANGE_NOTIFY })

        kacs.set_sd(vm, d, kacs.grant(kacs.ALL_RIGHTS))
        kacs.as_dacl_bound(t, vm, function(w)
            t:assert_eq(facs.chroot(w, d).ret, 0,
                "with FILE_TRAVERSE granted, chroot succeeds")
        end, { privs = KEEP_CHANGE_NOTIFY })
    end)

test("an ordinary fchdir checks the descriptor's cached mask",
    { spec = "PKM *facs.use.fchdir-cached-mask" }, function(t)
        local d = B .. "/fchdir"
        vm:mkdir(d, { parents = true })
        kacs.set_sd(vm, d, kacs.grant(kacs.ALL_RIGHTS))

        -- A handle that did not ask for FILE_TRAVERSE cannot fchdir,
        -- however permissive the object's descriptor is.
        with(t, d, R.LIST_DIRECTORY, function(fd)
            local r = facs.fchdir(vm, fd)
            t:assert(r.ret ~= 0, "a directory handle without FILE_TRAVERSE cannot fchdir")
            t:assert_eq(r.errno, sys.E.ACCES, "EACCES: " .. sys.errname(r.errno))
        end)

        -- One that did can, and goes on being able to after the right
        -- is withdrawn from the object: the mask is cached, not live.
        with(t, d, R.LIST_DIRECTORY | R.TRAVERSE, function(fd)
            t:assert_eq(facs.fchdir(vm, fd).ret, 0, "with it, fchdir succeeds")
            t:assert_eq(kacs.set_sd(vm, d, kacs.grant_all_but(R.TRAVERSE)).ret, 0,
                "FILE_TRAVERSE is withdrawn from the object")
            t:assert_eq(facs.fchdir(vm, fd).ret, 0,
                "and the cached mask still carries the descriptor through")
        end)
        kacs.set_sd(vm, d, kacs.grant(kacs.ALL_RIGHTS))
    end)

test("placing a watch is a read of the object, checked live",
    { spec = "PKM *facs.use.watch-placement" }, function(t)
        local f = file("watched")
        local d = B .. "/watched-dir"
        vm:mkdir(d, { parents = true })
        kacs.set_sd(vm, d, kacs.grant(kacs.ALL_RIGHTS))

        kacs.as_dacl_bound(t, vm, function(w)
            local ifd = facs.inotify_init(w, 0)
            t:assert(ifd, "inotify_init succeeds")

            -- A watch on a file is FILE_READ_DATA.
            t:assert(facs.inotify_add_watch(w, ifd, f), "a file watch is placed")
            t:assert_eq(kacs.set_sd(vm, f, kacs.grant_all_but(R.READ_DATA)).ret, 0,
                "FILE_READ_DATA is withdrawn")
            local no, e = facs.inotify_add_watch(w, ifd, f)
            t:assert(not no, "and the same watch is now refused")
            t:assert_eq(e, sys.E.ACCES, "EACCES: " .. sys.errname(e or 0))

            -- A watch on a directory is FILE_LIST_DIRECTORY.
            t:assert(facs.inotify_add_watch(w, ifd, d), "a directory watch is placed")
            t:assert_eq(kacs.set_sd(vm, d, kacs.grant_all_but(R.LIST_DIRECTORY)).ret, 0,
                "FILE_LIST_DIRECTORY is withdrawn")
            local nd, e2 = facs.inotify_add_watch(w, ifd, d)
            t:assert(not nd, "and the directory watch is refused")
            t:assert_eq(e2, sys.E.ACCES, "EACCES: " .. sys.errname(e2 or 0))
            sys.close(w, ifd)
        end, { privs = KEEP_CHANGE_NOTIFY })

        kacs.set_sd(vm, f, kacs.grant(kacs.ALL_RIGHTS))
        kacs.set_sd(vm, d, kacs.grant(kacs.ALL_RIGHTS))
    end)

test("SeChangeNotifyPrivilege does not bypass the watch-placement check",
    { spec = "PKM *facs.use.watch-change-notify-no-bypass" }, function(t)
        local f = file("watch-priv")
        t:assert_eq(kacs.set_sd(vm, f, kacs.grant_all_but(R.READ_DATA)).ret, 0,
            "FILE_READ_DATA is withdrawn from the object")

        -- The caller holds SeChangeNotifyPrivilege, which carries it
        -- past every intermediate traverse check on the way there.
        kacs.as_dacl_bound(t, vm, function(w)
            local ifd = facs.inotify_init(w, 0)
            t:assert(ifd, "inotify_init succeeds")
            local no, e = facs.inotify_add_watch(w, ifd, f)
            t:assert(not no, "the watch is still refused: the privilege covers " ..
                "traversal, not reading")
            t:assert_eq(e, sys.E.ACCES, "EACCES: " .. sys.errname(e or 0))
            sys.close(w, ifd)
        end, { privs = KEEP_CHANGE_NOTIFY })
        kacs.set_sd(vm, f, kacs.grant(kacs.ALL_RIGHTS))
    end)

test("mount marks and the fanotify permission classes are TCB-only",
    { spec = "PKM *facs.use.fanotify-mount-marks-tcb" }, function(t)
        kacs.set_sd(vm, "/", kacs.grant(kacs.ALL_RIGHTS))
        local d = B .. "/fan"
        vm:mkdir(d, { parents = true })
        kacs.set_sd(vm, d, kacs.grant(kacs.ALL_RIGHTS))

        -- SYSTEM holds SeTcbPrivilege and may do both.
        local content = facs.fanotify_init(vm, facs.FAN.CLASS_CONTENT, 0)
        t:assert(content, "SYSTEM may open a permission-class group")
        if content then sys.close(vm, content) end

        token.as_principal(t, vm, {}, function(w)
            -- The notification class is not a permission class and is
            -- not TCB-gated.
            local notif, ne = facs.fanotify_init(w, facs.FAN.CLASS_NOTIF | facs.FAN.REPORT_FID, 0)
            t:assert(notif, "an ordinary user may open a notification group: " ..
                sys.errname(ne or 0))

            -- The permission classes are.
            for _, c in ipairs({ { "FAN_CLASS_CONTENT", facs.FAN.CLASS_CONTENT },
                                 { "FAN_CLASS_PRE_CONTENT", facs.FAN.CLASS_PRE_CONTENT } }) do
                local no, e = facs.fanotify_init(w, c[2], 0)
                t:assert(not no, c[1] .. " is refused without SeTcbPrivilege")
                t:assert_eq(e, sys.E.PERM, "EPERM: " .. sys.errname(e or 0))
            end

            -- A mount mark is not an object watch and is TCB-only too.
            if notif then
                local m = facs.fanotify_mark(w, notif,
                    facs.FAN.MARK_ADD | facs.FAN.MARK_MOUNT, facs.FAN.MODIFY,
                    sys.AT_FDCWD, d)
                t:assert(m.ret ~= 0, "a mount mark is refused")
                t:assert_eq(m.errno, sys.E.PERM, "EPERM: " .. sys.errname(m.errno))
                local fs = facs.fanotify_mark(w, notif,
                    facs.FAN.MARK_ADD | facs.FAN.MARK_FILESYSTEM, facs.FAN.MODIFY,
                    sys.AT_FDCWD, d)
                t:assert(fs.ret ~= 0, "and so is a filesystem mark")
                t:assert_eq(fs.errno, sys.E.PERM, "EPERM: " .. sys.errname(fs.errno))
                sys.close(w, notif)
            end
        end)

        -- With SeTcbPrivilege the same calls go through.
        token.as_principal(t, vm, { privs_present = token.bit(token.PRIV.TCB),
            privs_enabled = token.bit(token.PRIV.TCB) }, function(w)
            local fd, e = facs.fanotify_init(w, facs.FAN.CLASS_CONTENT, 0)
            t:assert(fd, "a TCB holder may open a permission-class group: " ..
                sys.errname(e or 0))
            if fd then
                local m = facs.fanotify_mark(w, fd,
                    facs.FAN.MARK_ADD | facs.FAN.MARK_MOUNT, facs.FAN.MODIFY,
                    sys.AT_FDCWD, d)
                t:assert_eq(m.ret, 0, "and place a mount mark: " .. sys.errname(m.errno))
                sys.close(w, fd)
            end
        end)
    end)
