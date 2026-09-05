-- PKM §3.4.2 — the enforcement point each privilege in the catalogue
-- names. Every case drives the operation the catalogue says the
-- privilege governs, from a principal that holds exactly that privilege
-- and from one that does not.
--
-- The agent is SYSTEM and passes every gate, so the shape throughout is
-- `as(t, {bits}, fn)`: a minted token installed in a worker. The
-- capability-mapped gates (§3.10.2 owns the mapping table itself) are
-- driven through the syscall the capability guards.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local access = require("helpers.access")
local kmes = require("helpers.kmes")
local hooks = require("helpers.hooks")

local vm = provium:vm("v", "kernel-only"):boot()

local P = token.PRIV
local NR = {
    reboot = 169, settimeofday = 164, setpriority = 141, sched_setaffinity = 203,
    perf_event_open = 298, mlock = 149, init_module = 175, prlimit64 = 302,
    setrlimit = 160, open_by_handle_at = 304, chdir = 80,
}
local REBOOT_MAGIC1, REBOOT_MAGIC2, CAD_OFF = 0xfee1dead, 672274793, 0
local RLIMIT_NOFILE, RLIMIT_MEMLOCK = 7, 8
-- A software CPU-clock event that excludes kernel and hypervisor modes,
-- so perf's own paranoia ceiling is not what decides the case.
local PERF_ATTR = string.pack("<I4I4I8I8I8I8I8", 1, 128, 0, 0, 0, 0, 0x60)
    .. string.rep("\0", 72)
local BAD_HANDLE = string.pack("<I4i4", 8, 1) .. string.rep("\0", 8)

local function mask(bits)
    local m = 0
    for _, b in ipairs(bits) do m = m | token.bit(b) end
    return m
end

--- Run `fn(worker)` as a principal holding exactly `bits`.
local function as(t, bits, fn, spec)
    local s = { privs_present = mask(bits), privs_enabled = mask(bits) }
    for k, v in pairs(spec or {}) do s[k] = v end
    token.as_principal(t, vm, s, fn)
end

local function words(w)
    local fd = assert(token.open_self(w, token.RIGHT.QUERY))
    local p = assert(token.privileges(w, fd))
    sys.close(w, fd)
    return p
end

-- A world-writable corner of the guest root for the cases that need one.
-- Reaching any path costs FILE_TRAVERSE on every directory above it
-- unless the caller holds SeChangeNotifyPrivilege, and most principals
-- here deliberately hold nothing — so the guest root is opened too, and
-- every case that is about a descriptor sets one on its own object.
local WORK = "/priv-gates"
sys.mkdir_p(vm, WORK)
kacs.set_sd(vm, WORK, kacs.grant(kacs.ALL_RIGHTS))
kacs.set_sd(vm, "/", kacs.grant(kacs.ALL_RIGHTS))

-- Identity and token management ------------------------------------------------

test("SeCreateTokenPrivilege mints tokens from scratch",
    { spec = "PKM *priv.catalogue.se-create-token" }, function(t)
        as(t, { P.TCB }, function(w)
            local session = assert(token.create_logon_session(w, {}))
            local fd, errno = token.create(w, { auth_id = session })
            t:assert(not fd, "without it nothing can be minted")
            t:assert_eq(errno, sys.E.PERM, "EPERM")
        end)
        as(t, { P.TCB, P.CREATE_TOKEN }, function(w)
            local session = assert(token.create_logon_session(w, {}))
            local fd, errno = token.create(w, { auth_id = session })
            t:assert(fd, "with it a token is minted: " .. sys.errname(errno or 0))
            t:assert_eq(words(w).used & token.bit(P.CREATE_TOKEN), token.bit(P.CREATE_TOKEN),
                "and the exercise is recorded")
            sys.close(w, fd)
        end)
    end)

test("SeImpersonatePrivilege is what lets a service impersonate a principal other than itself",
    { spec = "PKM *priv.catalogue.se-impersonate" }, function(t)
        local MINT = mask({ P.TCB, P.CREATE_TOKEN })
        local function reach_other(bits)
            local level
            token.as_principal(t, vm, { privs_present = MINT | mask(bits),
                privs_enabled = MINT | mask(bits) }, function(w)
                local other = assert(token.mint(w, { user_sid = token.SID.TEST_USER_2,
                    token_type = token.TYPE.IMPERSONATION,
                    impersonation_level = token.LEVEL.IMPERSONATION }))
                t:assert_eq(token.impersonate(w, other).ret, 0, "the call itself succeeds")
                level = assert(token.effective(vm, w)).level
                token.revert(w)
                sys.close(w, other)
            end)
            return level
        end
        t:assert_eq(reach_other({}), token.LEVEL.IDENTIFICATION,
            "without it the level is capped to Identification")
        t:assert_eq(reach_other({ P.IMPERSONATE }), token.LEVEL.IMPERSONATION,
            "with it the service acts as the other principal")
    end)

test("SeAssignPrimaryTokenPrivilege gates installing a token as the process's primary identity",
    { spec = "PKM *priv.catalogue.se-assign-primary-token" }, function(t)
        as(t, { P.CREATE_TOKEN }, function(w)
            local self_fd = assert(token.open_self(w, token.RIGHT.QUERY))
            local session = assert(token.statistics(w, self_fd)).auth_id
            sys.close(w, self_fd)
            local mine = assert(token.create(w, { auth_id = session }))
            local r = token.install(w, mine)
            t:assert(r.ret ~= 0, "installation without the privilege is refused")
            t:assert_eq(r.errno, sys.E.ACCES, "EACCES")
            sys.close(w, mine)
        end)
        local KEEP = mask({ P.CREATE_TOKEN, P.ASSIGN_PRIMARY_TOKEN })
        as(t, { P.CREATE_TOKEN, P.ASSIGN_PRIMARY_TOKEN }, function(w)
            local self_fd = assert(token.open_self(w, token.RIGHT.QUERY))
            local session = assert(token.statistics(w, self_fd)).auth_id
            sys.close(w, self_fd)
            -- Installation is self-directed and replaces the caller's own
            -- identity, so the replacement carries the same privileges or
            -- the rest of the case would run as a principal with none.
            local mine = assert(token.create(w, { auth_id = session,
                privs_present = KEEP, privs_enabled = KEEP }))
            t:assert_eq(token.install(w, mine).ret, 0, "with it the token installs")
            sys.close(w, mine)
            -- Same user SID and same LogonSession, unless SeTcbPrivilege.
            local other_session = token.create_logon_session(w, {})
            t:assert(not other_session, "a non-TCB holder cannot open a new LogonSession")
            local stranger = assert(token.create(w, { auth_id = session,
                user_sid = token.SID.TEST_USER_2 }))
            t:assert_eq(token.install(w, stranger).errno, sys.E.PERM,
                "and cannot install another user's token: EPERM")
            sys.close(w, stranger)
        end)
    end)

-- Access control ------------------------------------------------------------------

test("SeSecurityPrivilege reaches the SACL and the KMES ring",
    { spec = "PKM *priv.catalogue.se-security" }, function(t)
        local path = WORK .. "/sacl-target"
        vm:write_file(path, "x")
        kacs.set_sd(vm, path, kacs.grant(kacs.ALL_RIGHTS))
        as(t, {}, function(w)
            local sd, errno = kacs.get_sd(w, path, kacs.SI.SACL)
            t:assert(not sd, "without it the SACL cannot be read: " .. sys.errname(errno or 0))
            local r = w:syscall(kmes.SYS.ATTACH,
                { args = { 0, 0 }, bufs = { string.rep("\0", 8) }, ptrs = { 1 } })
            t:assert(r.ret < 0, "and the KMES ring cannot be attached")
            t:assert_eq(r.errno, sys.E.PERM, "EPERM")
        end)
        as(t, { P.SECURITY }, function(w)
            local sd, errno = kacs.get_sd(w, path, kacs.SI.SACL)
            t:assert(sd, "with it the SACL is readable: " .. sys.errname(errno or 0))
            local r = w:syscall(kmes.SYS.ATTACH,
                { args = { 0, 0 }, bufs = { string.rep("\0", 8) }, ptrs = { 1 } })
            t:assert(r.ret >= 0, "and the ring attaches: " .. sys.errname(r.errno))
            sys.close(w, r.ret)
            t:assert_eq(words(w).used & token.bit(P.SECURITY), token.bit(P.SECURITY),
                "both exercises are recorded")
        end)
    end)

test("SeTakeOwnershipPrivilege exists purely inside AccessCheck and has no standalone gate",
    { spec = "PKM *priv.catalogue.se-take-ownership" }, function(t)
        local nothing = access.simple({}, { owner = token.SID.TEST_USER_2,
            group = token.SID.TEST_USER_2 })
        local function granted(bits, desired)
            local fd = assert(token.mint(vm, { privs_present = mask(bits),
                privs_enabled = mask(bits), token_type = token.TYPE.IMPERSONATION,
                impersonation_level = token.LEVEL.IMPERSONATION }))
            local r = access.check(vm, { token_fd = fd, sd = nothing, desired = desired })
            sys.close(vm, fd)
            return r
        end
        local WRITE_OWNER = access.STD.WRITE_OWNER
        t:assert(granted({}, WRITE_OWNER).denied, "the descriptor grants WRITE_OWNER to nobody")
        t:assert(granted({ P.TAKE_OWNERSHIP }, WRITE_OWNER).ok,
            "the privilege grants it inside the pipeline")
        -- And nothing else: it opens no operation gate of its own.
        as(t, { P.TAKE_OWNERSHIP }, function(w)
            t:assert_eq(w:syscall(NR.reboot, REBOOT_MAGIC1, REBOOT_MAGIC2, CAD_OFF, 0).errno,
                sys.E.PERM, "no standalone gate answers to it")
            t:assert(not token.create_logon_session(w, {}), "not the TCB paths")
            local r = w:syscall(kmes.SYS.ATTACH,
                { args = { 0, 0 }, bufs = { string.rep("\0", 8) }, ptrs = { 1 } })
            t:assert_eq(r.errno, sys.E.PERM, "not the KMES ring")
            t:assert_eq(words(w).used, 0, "and no standalone path ever marks it")
        end)
    end)

test("SeRestorePrivilege is also a plain standalone gate on owner assignment",
    { spec = "PKM *priv.catalogue.backup-restore-standalone-gates" }, function(t)
        local path = WORK .. "/owner-target"
        vm:write_file(path, "x")
        kacs.set_sd(vm, path, kacs.grant(kacs.ALL_RIGHTS))
        -- A SID the subject neither is nor holds as an owner-capable group.
        local foreign = token.sid(5, 21, 1000, 2000, 3000, 4242)
        local descriptor = access.sd({ owner = foreign })
        as(t, { P.CHANGE_NOTIFY }, function(w)
            local r = kacs.set_sd(w, path, descriptor, kacs.SI.OWNER)
            t:assert(r.ret ~= 0, "assigning an owner the subject does not hold is refused")
            t:assert_eq(r.errno, sys.E.ACCES, "EACCES")
        end)
        as(t, { P.CHANGE_NOTIFY, P.RESTORE }, function(w)
            local r = kacs.set_sd(w, path, descriptor, kacs.SI.OWNER)
            t:assert_eq(r.ret, 0, "SeRestorePrivilege opens the assignment: "
                .. sys.errname(r.errno))
            t:assert_eq(words(w).used & token.bit(P.RESTORE), token.bit(P.RESTORE),
                "and is recorded as used outside AccessCheck")
        end)
    end)

test("SeRelabelPrivilege is what writes a label above the caller's own level",
    { spec = "PKM *priv.catalogue.se-relabel" }, function(t)
        local path = WORK .. "/label-target"
        vm:write_file(path, "x")
        kacs.set_sd(vm, path, kacs.grant(kacs.ALL_RIGHTS))
        local LABEL_INFO = 0x10
        local high = access.sd({ sacl = access.acl({
            access.label_ace(token.INTEGRITY.HIGH, access.LABEL.NO_WRITE_UP) }) })
        local low = access.sd({ sacl = access.acl({
            access.label_ace(token.INTEGRITY.LOW, access.LABEL.NO_WRITE_UP) }) })
        as(t, { P.CHANGE_NOTIFY }, function(w)
            t:assert_eq(kacs.set_sd(w, path, low, LABEL_INFO).ret, 0,
                "a Medium caller may write a Low label")
            local r = kacs.set_sd(w, path, high, LABEL_INFO)
            t:assert(r.ret ~= 0, "but not one above its own level")
            t:assert_eq(r.errno, sys.E.ACCES, "EACCES")
        end)
        as(t, { P.CHANGE_NOTIFY, P.RELABEL }, function(w)
            local r = kacs.set_sd(w, path, high, LABEL_INFO)
            t:assert_eq(r.ret, 0, "SeRelabelPrivilege removes the at-or-below restriction: "
                .. sys.errname(r.errno))
            t:assert_eq(words(w).used & token.bit(P.RELABEL), token.bit(P.RELABEL),
                "and is recorded")
        end)
    end)

test("SeChangeNotifyPrivilege bypasses traverse checking on intermediate directories",
    { spec = "PKM *priv.catalogue.se-change-notify" }, function(t)
        local root = WORK .. "/notrav"
        sys.mkdir_p(vm, root .. "/sub")
        vm:write_file(root .. "/sub/f", "hello")
        kacs.set_sd(vm, root, kacs.grant_all_but(kacs.RIGHT.TRAVERSE))
        kacs.set_sd(vm, root .. "/sub", kacs.grant(kacs.ALL_RIGHTS))
        kacs.set_sd(vm, root .. "/sub/f", kacs.grant(kacs.ALL_RIGHTS))
        as(t, {}, function(w)
            local fd, errno = sys.open(w, root .. "/sub/f")
            t:assert(not fd, "an intermediate directory without FILE_TRAVERSE stops the walk")
            t:assert_eq(errno, sys.E.ACCES, "EACCES")
        end)
        as(t, { P.CHANGE_NOTIFY }, function(w)
            local fd, errno = sys.open(w, root .. "/sub/f")
            t:assert(fd, "the privilege reaches the file anyway: " .. sys.errname(errno or 0))
            sys.close(w, fd)
            t:assert_eq(words(w).used & token.bit(P.CHANGE_NOTIFY), token.bit(P.CHANGE_NOTIFY),
                "and the bypass is recorded")
        end)
    end)

test("the traverse bypass is suppressed for an explicit chdir",
    { spec = "PKM *priv.change-notify.chdir-exception" }, function(t)
        local root = WORK .. "/chdir"
        sys.mkdir_p(vm, root .. "/sub")
        kacs.set_sd(vm, root, kacs.grant_all_but(kacs.RIGHT.TRAVERSE))
        kacs.set_sd(vm, root .. "/sub", kacs.grant(kacs.ALL_RIGHTS))
        as(t, { P.CHANGE_NOTIFY }, function(w)
            local r = w:syscall(NR.chdir, { args = { 0 }, bufs = { sys.cstr(root) }, ptrs = { 0 } })
            t:assert(r.ret ~= 0, "chdir into the traverse-denying directory is refused")
            t:assert_eq(r.errno, sys.E.ACCES, "EACCES, privilege or no privilege")
            local ok = w:syscall(NR.chdir,
                { args = { 0 }, bufs = { sys.cstr(root .. "/sub") }, ptrs = { 0 } })
            t:assert_eq(ok.ret, 0,
                "while the same walk through it, ending on a directory that does grant "
                .. "FILE_TRAVERSE, succeeds: " .. sys.errname(ok.errno))
        end)
    end)

test("SeChangeNotifyPrivilege additionally gates open_by_handle_at",
    { spec = "PKM *priv.change-notify.open-by-handle-at" }, function(t)
        local call = { args = { sys.AT_FDCWD, 0, 0 }, bufs = { BAD_HANDLE }, ptrs = { 1 } }
        as(t, {}, function(w)
            local r = w:syscall(NR.open_by_handle_at, call)
            t:assert(r.ret < 0, "without the privilege the call never looks at the handle")
            t:assert_eq(r.errno, sys.E.PERM, "EPERM")
        end)
        as(t, { P.CHANGE_NOTIFY }, function(w)
            local r = w:syscall(NR.open_by_handle_at, call)
            t:assert(r.ret < 0, "with it the handle itself is what fails")
            t:assert_eq(r.errno, sys.E.STALE, "ESTALE, from past the gate")
        end)
    end)

test("the traverse check is made once per intermediate directory on every path walk",
    { spec = "PKM *priv.change-notify.checked-per-directory" }, function(t)
        local root = WORK .. "/deep"
        sys.mkdir_p(vm, root .. "/a/b/c")
        vm:write_file(root .. "/a/b/c/f", "x")
        local chain = { root, root .. "/a", root .. "/a/b", root .. "/a/b/c" }
        for _, dir in ipairs(chain) do
            kacs.set_sd(vm, dir, kacs.grant_all_but(kacs.RIGHT.TRAVERSE))
        end
        kacs.set_sd(vm, root .. "/a/b/c/f", kacs.grant(kacs.ALL_RIGHTS))
        local want = {}
        for _, dir in ipairs(chain) do
            want[assert(sys.stat(vm, dir), "stat " .. dir).ino] = dir
        end
        as(t, { P.CHANGE_NOTIFY }, function(w)
            t:assert(hooks.trace_start(vm, "kacs/kacs_inode_permission"), "tracing starts")
            local fd, errno = sys.open(w, root .. "/a/b/c/f")
            t:assert(fd, "the walk completes on the privilege: " .. sys.errname(errno or 0))
            if fd then sys.close(w, fd) end
            local lines = hooks.trace_stop(vm, "kacs/kacs_inode_permission")
            local seen = {}
            for _, line in ipairs(lines) do
                if line:find("reason=change-notify-priv ", 1, true) then
                    local ino = tonumber(line:match("ino=(%d+)"))
                    if ino and want[ino] then seen[ino] = true end
                end
            end
            for ino, dir in pairs(want) do
                t:assert(seen[ino], "the bypass was taken for " .. dir .. " (inode " .. ino .. ")")
            end
        end)
    end)

test("SeCreateSymbolicLinkPrivilege is required in addition to FILE_ADD_FILE",
    { spec = "PKM *priv.catalogue.se-create-symbolic-link" }, function(t)
        local open_dir = WORK .. "/links"
        local closed_dir = WORK .. "/links-closed"
        sys.mkdir_p(vm, open_dir); sys.mkdir_p(vm, closed_dir)
        kacs.set_sd(vm, open_dir, kacs.grant(kacs.ALL_RIGHTS))
        kacs.set_sd(vm, closed_dir, kacs.grant_all_but(kacs.RIGHT.ADD_FILE))
        as(t, { P.CHANGE_NOTIFY }, function(w)
            local r = sys.symlink(w, "target", open_dir .. "/a")
            t:assert(r.ret ~= 0, "FILE_ADD_FILE alone does not create a symlink")
            t:assert_eq(r.errno, sys.E.PERM, "EPERM")
        end)
        as(t, { P.CHANGE_NOTIFY, P.CREATE_SYMBOLIC_LINK }, function(w)
            local r = sys.symlink(w, "target", closed_dir .. "/b")
            t:assert(r.ret ~= 0, "and the privilege alone does not either")
            t:assert_eq(r.errno, sys.E.ACCES, "EACCES without FILE_ADD_FILE on the parent")
            local ok = sys.symlink(w, "target", open_dir .. "/c")
            t:assert_eq(ok.ret, 0, "with both, the link is made: " .. sys.errname(ok.errno))
            t:assert_eq(words(w).used & token.bit(P.CREATE_SYMBOLIC_LINK),
                token.bit(P.CREATE_SYMBOLIC_LINK), "and the privilege is recorded")
        end)
    end)

-- System operations ---------------------------------------------------------------

test("SeManageVolumePrivilege is what admits a mount",
    { spec = "PKM *priv.catalogue.se-manage-volume" }, function(t)
        local at = WORK .. "/mnt"
        sys.mkdir_p(vm, at)
        kacs.set_sd(vm, at, kacs.grant(kacs.ALL_RIGHTS))
        as(t, { P.CHANGE_NOTIFY }, function(w)
            local r = sys.mount(w, { source = "none", target = at, fstype = "tmpfs" })
            t:assert(r.ret ~= 0, "an ordinary principal cannot reshape the mount tree")
            t:assert_eq(r.errno, sys.E.PERM, "EPERM")
        end)
        as(t, { P.CHANGE_NOTIFY, P.MANAGE_VOLUME }, function(w)
            local r = sys.mount(w, { source = "none", target = at, fstype = "tmpfs" })
            t:assert_eq(r.ret, 0, "the privilege admits it: " .. sys.errname(r.errno))
            t:assert_eq(words(w).used & token.bit(P.MANAGE_VOLUME), token.bit(P.MANAGE_VOLUME),
                "and is recorded")
            sys.umount(w, at)
        end)
    end)

test("SeTcbPrivilege is the catch-all for system operations with no more specific privilege",
    { spec = "PKM *priv.catalogue.se-tcb" }, function(t)
        as(t, {}, function(w)
            local sid, errno = token.create_logon_session(w, {})
            t:assert(not sid, "LogonSession creation is one of its paths")
            t:assert_eq(errno, sys.E.PERM, "EPERM")
        end)
        as(t, { P.TCB }, function(w)
            local sid, errno = token.create_logon_session(w, {})
            t:assert(sid, "with it a LogonSession is created: " .. sys.errname(errno or 0))
            t:assert_eq(token.destroy_empty_logon_session(w, sid).ret, 0,
                "and destroyed, which is another of them")
            -- The mount policy paths take it too (§3.4.2).
            local at = WORK .. "/tcb-mnt"
            sys.mkdir_p(w, at)
            t:assert_eq(sys.mount(w, { source = "none", target = at, fstype = "tmpfs" }).ret, 0,
                "the TCB may do anything a volume manager may")
            sys.umount(w, at)
            t:assert_eq(words(w).used & token.bit(P.TCB), token.bit(P.TCB), "and it is recorded")
        end)
    end)

test("SeShutdownPrivilege shuts down or reboots the machine through CAP_SYS_BOOT",
    { spec = "PKM *priv.catalogue.se-shutdown" }, function(t)
        as(t, {}, function(w)
            local r = w:syscall(NR.reboot, REBOOT_MAGIC1, REBOOT_MAGIC2, CAD_OFF, 0)
            t:assert(r.ret ~= 0, "reboot(2) is refused without it")
            t:assert_eq(r.errno, sys.E.PERM, "EPERM")
        end)
        as(t, { P.SHUTDOWN }, function(w)
            local r = w:syscall(NR.reboot, REBOOT_MAGIC1, REBOOT_MAGIC2, CAD_OFF, 0)
            t:assert_eq(r.ret, 0, "and accepted with it: " .. sys.errname(r.errno))
            t:assert_eq(words(w).used & token.bit(P.SHUTDOWN), token.bit(P.SHUTDOWN), "recorded")
        end)
    end)

test("SeRemoteShutdownPrivilege is required in addition for a Network-class logon",
    { spec = "PKM *priv.catalogue.se-remote-shutdown" }, function(t)
        for _, logon in ipairs({ token.LOGON_TYPE.NETWORK, token.LOGON_TYPE.NETWORK_CLEARTEXT,
            token.LOGON_TYPE.NEW_CREDENTIALS }) do
            as(t, { P.SHUTDOWN }, function(w)
                t:assert_eq(w:syscall(NR.reboot, REBOOT_MAGIC1, REBOOT_MAGIC2, CAD_OFF, 0).errno,
                    sys.E.PERM, "logon type " .. logon .. " needs more than SeShutdownPrivilege")
            end, { logon_type = logon })
            as(t, { P.SHUTDOWN, P.REMOTE_SHUTDOWN }, function(w)
                t:assert_eq(w:syscall(NR.reboot, REBOOT_MAGIC1, REBOOT_MAGIC2, CAD_OFF, 0).ret, 0,
                    "and passes with both")
                t:assert_eq(words(w).used & token.bit(P.REMOTE_SHUTDOWN),
                    token.bit(P.REMOTE_SHUTDOWN), "recording SeRemoteShutdownPrivilege")
            end, { logon_type = logon })
        end
        -- An Interactive logon is not a remote request and needs neither.
        as(t, { P.REMOTE_SHUTDOWN }, function(w)
            t:assert_eq(w:syscall(NR.reboot, REBOOT_MAGIC1, REBOOT_MAGIC2, CAD_OFF, 0).errno,
                sys.E.PERM, "and SeRemoteShutdownPrivilege alone is never enough")
        end, { logon_type = token.LOGON_TYPE.INTERACTIVE })
    end)

test("SeLoadDriverPrivilege loads and unloads kernel modules through CAP_SYS_MODULE",
    { spec = "PKM *priv.catalogue.se-load-driver" }, function(t)
        local call = { args = { 0, 4, 0 }, bufs = { "abcd", sys.cstr("") }, ptrs = { 0, 2 } }
        as(t, {}, function(w)
            local r = w:syscall(NR.init_module, call)
            t:assert(r.ret ~= 0, "init_module(2) is refused without it")
            t:assert_eq(r.errno, sys.E.PERM, "EPERM")
        end)
        as(t, { P.LOAD_DRIVER }, function(w)
            local r = w:syscall(NR.init_module, call)
            t:assert(r.ret ~= 0, "with it the four bytes are rejected as a module, not as a caller")
            t:assert_neq(r.errno, sys.E.PERM,
                "past the capability gate: " .. sys.errname(r.errno))
            t:assert_eq(words(w).used & token.bit(P.LOAD_DRIVER), token.bit(P.LOAD_DRIVER),
                "and the privilege is recorded")
        end)
    end)

test("SeDebugPrivilege inspects any process regardless of its descriptor",
    { spec = "PKM *priv.catalogue.se-debug" }, function(t)
        local victim = vm:spawn_worker()
        local ok, err = pcall(function()
            local vpid = victim:syscall(sys.NR.getpid).ret
            local vfd = assert(token.mint(victim, { user_sid = token.SID.TEST_USER_2 }))
            assert(token.install(victim, vfd).ret == 0, "the victim runs as another user")
            local read_limits = { args = { vpid, RLIMIT_NOFILE, 0, 0 },
                bufs = { string.rep("\0", 16) }, ptrs = { 3 } }
            as(t, {}, function(w)
                local r = w:syscall(NR.prlimit64, read_limits)
                t:assert(r.ret ~= 0, "the target's process descriptor keeps a stranger out")
                t:assert_eq(r.errno, sys.E.ACCES, "EACCES")
            end)
            as(t, { P.DEBUG }, function(w)
                local r = w:syscall(NR.prlimit64, read_limits)
                t:assert_eq(r.ret, 0, "SeDebugPrivilege reaches it anyway: " .. sys.errname(r.errno))
                t:assert_eq(words(w).used & token.bit(P.DEBUG), token.bit(P.DEBUG), "recorded")
            end)
        end)
        victim:kill(); victim:join()
        if not ok then error(err, 0) end
    end)

test("SeSystemtimePrivilege changes the clock",
    { spec = "PKM *priv.catalogue.se-systemtime" }, function(t)
        local call = { args = { 0, 0 }, bufs = { string.pack("<i8i8", 1800000000, 0) }, ptrs = { 0 } }
        as(t, {}, function(w)
            local r = w:syscall(NR.settimeofday, call)
            t:assert(r.ret ~= 0, "settimeofday(2) is refused without it")
            t:assert_eq(r.errno, sys.E.PERM, "EPERM")
        end)
        as(t, { P.SYSTEMTIME }, function(w)
            local r = w:syscall(NR.settimeofday, call)
            t:assert_eq(r.ret, 0, "and accepted with it: " .. sys.errname(r.errno))
            t:assert_eq(words(w).used & token.bit(P.SYSTEMTIME), token.bit(P.SYSTEMTIME), "recorded")
        end)
    end)

test("SeIncreaseBasePriorityPrivilege raises scheduling priority and sets other processes' affinity",
    { spec = "PKM *priv.catalogue.se-increase-base-priority" }, function(t)
        local victim = vm:spawn_worker()
        local ok, err = pcall(function()
            local vpid = victim:syscall(sys.NR.getpid).ret
            assert(token.install(victim, assert(token.mint(victim, {}))).ret == 0)
            local affinity = { args = { vpid, 8, 0 }, bufs = { string.pack("<I8", 1) }, ptrs = { 2 } }
            as(t, {}, function(w)
                -- PRIO_PROCESS, self, nice -1: raising priority.
                t:assert_eq(w:syscall(NR.setpriority, 0, 0, -1).errno, sys.E.ACCES,
                    "raising priority is refused without it")
                t:assert_eq(w:syscall(NR.sched_setaffinity, affinity).errno, sys.E.ACCES,
                    "and so is another process's affinity")
            end)
            as(t, { P.INCREASE_BASE_PRIORITY }, function(w)
                t:assert_eq(w:syscall(NR.setpriority, 0, 0, -1).ret, 0,
                    "with it the priority is raised")
                local r = w:syscall(NR.sched_setaffinity, affinity)
                t:assert_eq(r.ret, 0, "and the affinity is set: " .. sys.errname(r.errno))
                t:assert_eq(words(w).used & token.bit(P.INCREASE_BASE_PRIORITY),
                    token.bit(P.INCREASE_BASE_PRIORITY), "recorded")
            end)
        end)
        victim:kill(); victim:join()
        if not ok then error(err, 0) end
    end)

test("SeIncreaseQuotaPrivilege overrides resource limits",
    { spec = "PKM *priv.catalogue.se-increase-quota" }, function(t)
        -- Raising a *hard* limit is the privileged half of prlimit64.
        local raise = { args = { 0, RLIMIT_NOFILE, 0, 0 },
            bufs = { string.pack("<I8I8", 1024, 1048576) }, ptrs = { 2 } }
        as(t, {}, function(w)
            local r = w:syscall(NR.prlimit64, raise)
            t:assert(r.ret ~= 0, "raising a hard limit is refused without it")
            t:assert_eq(r.errno, sys.E.PERM, "EPERM")
        end)
        as(t, { P.INCREASE_QUOTA }, function(w)
            local r = w:syscall(NR.prlimit64, raise)
            t:assert_eq(r.ret, 0, "and permitted with it: " .. sys.errname(r.errno))
            t:assert_eq(words(w).used & token.bit(P.INCREASE_QUOTA), token.bit(P.INCREASE_QUOTA),
                "recorded")
        end)
    end)

test("SeLockMemoryPrivilege locks pages in physical memory",
    { spec = "PKM *priv.catalogue.se-lock-memory" }, function(t)
        local function lock(w)
            -- RLIMIT_MEMLOCK 0 removes the unprivileged allowance, so the
            -- privilege is the only thing that can carry the mlock.
            w:syscall(NR.setrlimit, { args = { RLIMIT_MEMLOCK, 0 },
                bufs = { string.pack("<I8I8", 0, 0) }, ptrs = { 1 } })
            local addr = sys.mmap(w, -1, 8192, sys.PROT.READ | sys.PROT.WRITE,
                sys.MAP.PRIVATE | sys.MAP.ANONYMOUS, 0)
            assert(addr, "anonymous mapping")
            return w:syscall(NR.mlock, addr, 8192)
        end
        as(t, {}, function(w)
            local r = lock(w)
            t:assert(r.ret ~= 0, "mlock(2) past the rlimit is refused without it")
            t:assert_eq(r.errno, sys.E.PERM, "EPERM")
        end)
        as(t, { P.LOCK_MEMORY }, function(w)
            local r = lock(w)
            t:assert_eq(r.ret, 0, "and permitted with it: " .. sys.errname(r.errno))
            t:assert_eq(words(w).used & token.bit(P.LOCK_MEMORY), token.bit(P.LOCK_MEMORY),
                "recorded")
        end)
    end)

test("SeAuditPrivilege is what KMES requires for userspace event emission",
    { spec = "PKM *priv.catalogue.se-audit" }, function(t)
        as(t, {}, function(w)
            local r = kmes.emit(w, "PIT_PRIV", kmes.PAYLOAD)
            t:assert(r.ret ~= 0, "an emit without it is refused")
            t:assert_eq(r.errno, sys.E.PERM, "EPERM")
        end)
        as(t, { P.AUDIT }, function(w)
            local r = kmes.emit(w, "PIT_PRIV", kmes.PAYLOAD)
            t:assert_eq(r.ret, 0, "and accepted with it: " .. sys.errname(r.errno))
            t:assert_eq(words(w).used & token.bit(P.AUDIT), token.bit(P.AUDIT), "recorded")
        end)
    end)

test("SeProfileSingleProcessPrivilege attaches perf_event_open to a specific other process",
    { spec = "PKM *priv.catalogue.se-profile-single-process" }, function(t)
        local victim = vm:spawn_worker()
        local ok, err = pcall(function()
            local vpid = victim:syscall(sys.NR.getpid).ret
            assert(token.install(victim, assert(token.mint(victim, {}))).ret == 0)
            local cross = { args = { 0, vpid, -1, -1, 0 }, bufs = { PERF_ATTR }, ptrs = { 0 } }
            as(t, {}, function(w)
                local r = w:syscall(NR.perf_event_open, cross)
                t:assert(r.ret < 0, "cross-task profiling is refused without it")
            end)
            as(t, { P.PROFILE_SINGLE_PROCESS }, function(w)
                local r = w:syscall(NR.perf_event_open, cross)
                t:assert(r.ret >= 0, "and permitted with it: " .. sys.errname(r.errno))
                sys.close(w, r.ret)
                t:assert_eq(words(w).used & token.bit(P.PROFILE_SINGLE_PROCESS),
                    token.bit(P.PROFILE_SINGLE_PROCESS), "recorded")
            end)
        end)
        victim:kill(); victim:join()
        if not ok then error(err, 0) end
    end)

test("own-task profiling requires nothing, and cross-task profiling still meets the process boundary",
    { spec = "PKM *priv.profile.pip-dominance-and-own-task" }, function(t)
        local own = { args = { 0, 0, -1, -1, 0 }, bufs = { PERF_ATTR }, ptrs = { 0 } }
        as(t, {}, function(w)
            local r = w:syscall(NR.perf_event_open, own)
            t:assert(r.ret >= 0, "a principal with no privileges profiles itself: "
                .. sys.errname(r.errno))
            sys.close(w, r.ret)
            t:assert_eq(words(w).used, 0, "and nothing is consulted to let it")
        end)
        -- Cross-task does not skip the boundary check: the privilege gets
        -- the caller as far as the target's own access decision.
        local victim = vm:spawn_worker()
        local ok, err = pcall(function()
            local vpid = victim:syscall(sys.NR.getpid).ret
            local vfd = assert(token.mint(victim, { user_sid = token.SID.TEST_USER_2 }))
            assert(token.install(victim, vfd).ret == 0)
            as(t, { P.PROFILE_SINGLE_PROCESS }, function(w)
                local r = w:syscall(NR.perf_event_open,
                    { args = { 0, vpid, -1, -1, 0 }, bufs = { PERF_ATTR }, ptrs = { 0 } })
                t:assert(r.ret < 0, "the privilege does not bypass the target's own decision")
                t:assert_eq(r.errno, sys.E.ACCES, "EACCES")
            end)
        end)
        victim:kill(); victim:join()
        if not ok then error(err, 0) end
    end)

test("SeSystemProfilePrivilege is what covers system-wide profiling",
    { spec = "PKM *priv.catalogue.se-system-profile" }, function(t)
        local system_wide = { args = { 0, -1, 0, -1, 0 }, bufs = { PERF_ATTR }, ptrs = { 0 } }
        as(t, {}, function(w)
            t:assert(w:syscall(NR.perf_event_open, system_wide).ret < 0,
                "a system-wide event is refused without it")
        end)
        as(t, { P.PROFILE_SINGLE_PROCESS }, function(w)
            local r = w:syscall(NR.perf_event_open, system_wide)
            t:assert(r.ret < 0, "the per-target tier does not reach it either")
            t:assert_eq(r.errno, sys.E.PERM, "EPERM — the two tiers are disjoint")
        end)
        as(t, { P.SYSTEM_PROFILE }, function(w)
            local r = w:syscall(NR.perf_event_open, system_wide)
            t:assert(r.ret >= 0, "the operator-class privilege opens it: " .. sys.errname(r.errno))
            sys.close(w, r.ret)
            t:assert_eq(words(w).used & token.bit(P.SYSTEM_PROFILE), token.bit(P.SYSTEM_PROFILE),
                "recorded")
        end)
    end)

test("CAP_PERFMON is satisfied by any of the three, and every one held is marked used",
    { spec = "PKM *priv.perfmon.satisfied-by-any-of-three" }, function(t)
        -- An own-task event that does *not* exclude kernel mode: KACS's own
        -- perf gates permit it outright (own-task profiling requires
        -- nothing), so what is left deciding it is perf's CAP_PERFMON
        -- ceiling and nothing else.
        local kernel_attr = string.pack("<I4I4I8I8I8I8I8", 1, 128, 0, 0, 0, 0, 0)
            .. string.rep("\0", 72)
        local own_task = { args = { 0, 0, -1, -1, 0 }, bufs = { kernel_attr }, ptrs = { 0 } }
        as(t, {}, function(w)
            local r = w:syscall(NR.perf_event_open, own_task)
            t:assert(r.ret < 0, "with none of the three, CAP_PERFMON is unsatisfied")
            t:assert_eq(r.errno, sys.E.ACCES, "EACCES")
        end)
        for _, bit in ipairs({ P.SYSTEM_PROFILE, P.PROFILE_SINGLE_PROCESS, P.LOAD_DRIVER }) do
            as(t, { bit }, function(w)
                local r = w:syscall(NR.perf_event_open, own_task)
                t:assert(r.ret >= 0, "bit " .. bit .. " alone satisfies CAP_PERFMON: "
                    .. sys.errname(r.errno))
                sys.close(w, r.ret)
                t:assert_eq(words(w).used & token.bit(bit), token.bit(bit),
                    "and is marked used for it")
            end)
        end
        as(t, { P.LOAD_DRIVER, P.SYSTEM_PROFILE, P.PROFILE_SINGLE_PROCESS }, function(w)
            local r = w:syscall(NR.perf_event_open, own_task)
            t:assert(r.ret >= 0, "holding all three, the event opens: " .. sys.errname(r.errno))
            sys.close(w, r.ret)
            local used = words(w).used
            for _, bit in ipairs({ P.LOAD_DRIVER, P.SYSTEM_PROFILE, P.PROFILE_SINGLE_PROCESS }) do
                t:assert_eq(used & token.bit(bit), token.bit(bit),
                    "and every one the caller holds is marked used, including bit " .. bit)
            end
        end)
    end)
