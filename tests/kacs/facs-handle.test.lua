-- PKM §3.9.1 — the FACS handle model: the granted mask is decided once
-- at open and never changes, mount policy is a property of the
-- superblock, unmanaged filesystems carry no mask at all, and every
-- acquisition path (dup, fork, SCM_RIGHTS, pidfd_getfd) carries the
-- mask through unchanged.
--
-- The root filesystem is a FACS-managed tmpfs (`facs_deny_missing`) and
-- its objects carry stored descriptors, so a workspace under `/` is the
-- ordinary managed case. `/proc` and `/sys` are the unmanaged ones.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local access = require("helpers.access")
local facs = require("helpers.facs")
local kmes = require("helpers.kmes")

local vm = provium:vm("v", "kernel-only"):boot()

local R = kacs.RIGHT
local B = facs.workspace(vm, "handle")

test("the granted mask is set once and survives a rewrite of the DACL",
    { spec = "PKM *facs.handle.mask-immutable" }, function(t)
        local p = facs.file(vm, B .. "/immutable", "0123456789")
        local fd = facs.handle(t, vm, p, R.READ_DATA | R.WRITE_DATA)

        -- Withdraw every right on the object while the handle is open.
        t:assert_eq(kacs.set_sd(vm, p, kacs.deny_all()).ret, 0,
            "the object's DACL is emptied under the open descriptor")

        local w = sys.write(vm, fd, "xy")
        t:assert_eq(w.ret, 2, "the descriptor still writes: " .. sys.errname(w.errno))
        sys.lseek(vm, fd, 0, 0)
        t:assert_eq(sys.read(vm, fd, 2), "xy", "and still reads")

        -- A fresh open of the same object is refused, so the rewrite did
        -- take effect — the descriptor is what is immune to it.
        local again, errno = facs.open(vm, p, { access = R.READ_DATA })
        t:assert(not again, "a new open of the same object is refused")
        t:assert_eq(errno, sys.E.ACCES, "with EACCES: " .. sys.errname(errno or 0))
        sys.close(vm, fd)
    end)

test("a continuous audit mask is stamped alongside the granted mask at open",
    { spec = "PKM *facs.handle.audit-mask-stamped" }, function(t)
        -- The mask comes from the object's SACL and is consulted at
        -- every use-time enforcement point (§3.8.9): an operation on a
        -- handle whose stamped mask covers the right it needs emits a
        -- `continuous-audit` event. A descriptor with no audit ACE is
        -- the control — same operation, no event.
        local audited = B .. "/audited"
        local quiet = B .. "/quiet"
        vm:write_file(audited, "abcdefgh")
        vm:write_file(quiet, "abcdefgh")
        local dacl = access.acl({ access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS, token.SID.EVERYONE) })
        -- The continuous mask is the union of the SACL's alarm ACEs
        -- (§3.8.9); an ordinary audit ACE feeds the open-time
        -- access-audit record instead.
        local sacl = access.acl({ access.ace(access.ACE.ALARM, R.READ_DATA, token.SID.EVERYONE) })
        t:assert_eq(kacs.set_sd(vm, audited, access.sd({ dacl = dacl, sacl = sacl }),
            kacs.SI.DACL | kacs.SI.SACL).ret, 0, "the audited object carries a SACL")
        t:assert_eq(kacs.set_sd(vm, quiet, access.sd({ dacl = dacl })).ret, 0,
            "the control object carries none")

        local function read_once(path)
            local fd = facs.handle(t, vm, path, R.READ_DATA)
            sys.read(vm, fd, 4)
            sys.close(vm, fd)
        end

        local with = kmes.recording(t, vm, function() read_once(audited) end)
        local without = kmes.recording(t, vm, function() read_once(quiet) end)
        local a = kmes.of_type(with, "continuous-audit")
        local b = kmes.of_type(without, "continuous-audit")
        t:assert(#a > 0, "a read through the audited handle emits continuous-audit")
        t:assert_eq(#b, 0, "and the same read through an unaudited one emits none")
    end)

test("mount policy is a property of the superblock, not of a path",
    { spec = "PKM *facs.handle.policy-per-superblock" }, function(t)
        local at, bind = B .. "/sb-a", B .. "/sb-b"
        vm:mkdir(at, { parents = true })
        vm:mkdir(bind, { parents = true })
        local ok, stage, errno = kacs.new_mount(vm, "tmpfs", at,
            kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL)
        t:assert(ok, "a tmpfs mounts: " .. tostring(stage) .. " " ..
            sys.errname(errno or 0))
        t:assert_eq(sys.mount(vm, { source = at, target = bind, flags = sys.MS_BIND }).ret, 0,
            "and is bind-mounted at a second path")

        local function policy(path)
            local fd = assert(sys.open(vm, path, sys.O.RDONLY | sys.O.DIRECTORY))
            local p = kacs.get_mount_policy(vm, fd)
            sys.close(vm, fd)
            return p
        end
        t:assert_eq(policy(at), kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL,
            "the first path reports the class it was given")
        t:assert_eq(policy(bind), kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL,
            "and so does the bind mount over the same superblock")

        -- Changing it through one path changes it for the other: there
        -- is one class per superblock, not one per mount.
        local fd = assert(sys.open(vm, bind, sys.O.RDONLY | sys.O.DIRECTORY))
        local set = kacs.set_mount_policy(vm, fd, kacs.MOUNT_POLICY.SYNTHESIZE_PERSISTENT)
        sys.close(vm, fd)
        t:assert_eq(set.ret, 0, "the class is changed through the bind mount: " ..
            sys.errname(set.errno))
        t:assert_eq(policy(at), kacs.MOUNT_POLICY.SYNTHESIZE_PERSISTENT,
            "and the original path observes the change")
        sys.umount(vm, bind)
        sys.umount(vm, at)
    end)

test("an unmanaged mount stamps no granted mask on its file descriptions",
    { spec = "PKM *facs.handle.unmanaged-no-mask" }, function(t)
        -- The witness is an operation KACS refuses on any managed
        -- descriptor whatever its mask: an unknown fcntl command fails
        -- closed (§3.9.4). On an unmanaged descriptor the handle check
        -- does not run at all, so Linux answers instead.
        local p = facs.file(vm, B .. "/managed-fcntl", "x")
        local fd = facs.handle(t, vm, p, R.READ_DATA | R.WRITE_DATA |
            R.READ_ATTRIBUTES | R.WRITE_ATTRIBUTES)
        local managed = facs.fcntl(vm, fd, facs.F.UNKNOWN, 0)
        t:assert_eq(managed.errno, sys.E.ACCES,
            "a managed descriptor refuses the unknown command: " .. sys.errname(managed.errno))
        sys.close(vm, fd)

        local pfd = assert(sys.open(vm, "/proc/self/stat", sys.O.RDONLY))
        local unmanaged = facs.fcntl(vm, pfd, facs.F.UNKNOWN, 0)
        t:assert_neq(unmanaged.errno, sys.E.ACCES,
            "a /proc descriptor is not judged on a mask at all: " ..
            sys.errname(unmanaged.errno))
        t:assert_eq(unmanaged.errno, sys.E.INVAL, "Linux answers EINVAL instead")
        sys.close(vm, pfd)
    end)

test("a magic-derived unmanaged superblock cannot be given a policy",
    { spec = "PKM *facs.handle.unmanaged-not-settable" }, function(t)
        for _, path in ipairs({ "/proc", "/sys" }) do
            local fd = assert(sys.open(vm, path, sys.O.RDONLY | sys.O.DIRECTORY))
            t:assert_eq(kacs.get_mount_policy(vm, fd), kacs.MOUNT_POLICY.UNMANAGED,
                path .. " is unmanaged")
            local set = kacs.set_mount_policy(vm, fd, kacs.MOUNT_POLICY.DENY_MISSING)
            t:assert_eq(set.ret, -1, "and setting a policy on it fails")
            t:assert_eq(set.errno, sys.E.OPNOTSUPP,
                "with EOPNOTSUPP: " .. sys.errname(set.errno))
            sys.close(vm, fd)
        end
    end)

test("writes to /sys are gated by a built-in descriptor naming Administrators and SYSTEM",
    { spec = "PKM *facs.handle.sysfs-write-builtin-descriptor" }, function(t)
        local knob = "/sys/kernel/profiling"
        t:assert(sys.stat(vm, knob), "the guest exposes a writable sysfs attribute")
        -- The root is managed, so a minted user needs FILE_TRAVERSE
        -- there before it can reach an unmanaged mount below it.
        kacs.set_sd(vm, "/", kacs.grant(kacs.ALL_RIGHTS))

        -- The agent is SYSTEM, which the built-in descriptor names.
        local fd, errno = sys.open(vm, knob, sys.O.WRONLY)
        t:assert(fd, "SYSTEM opens it for writing: " .. sys.errname(errno or 0))
        if fd then sys.close(vm, fd) end

        -- A minted local user is in neither group. /sys is unmanaged, so
        -- nothing but the hardcoded rule can be denying this.
        token.as_principal(t, vm, {}, function(worker)
            local no, e = sys.open(worker, knob, sys.O.WRONLY)
            t:assert(not no, "an ordinary user cannot")
            t:assert_eq(e, sys.E.ACCES, "with EACCES: " .. sys.errname(e or 0))
            local ro, e2 = sys.open(worker, knob, sys.O.RDONLY)
            t:assert(ro, "and reading the same attribute is untouched: " ..
                sys.errname(e2 or 0))
            if ro then sys.close(worker, ro) end
        end)
    end)

test("a pidfd bypasses FACS at open",
    { spec = "PKM *facs.handle.pidfd-bypasses-open" }, function(t)
        local pid = vm:syscall(sys.NR.getpid).ret
        local r = vm:syscall(sys.NR.pidfd_open, pid, 0)
        t:assert(r.ret >= 0, "pidfd_open: " .. sys.errname(r.errno))
        -- Same witness as the unmanaged case: a managed descriptor fails
        -- an unknown fcntl closed. A pidfd never entered the handle
        -- model, so it does not.
        local u = facs.fcntl(vm, r.ret, facs.F.UNKNOWN, 0)
        t:assert_neq(u.errno, sys.E.ACCES,
            "a pidfd carries no granted mask to judge: " .. sys.errname(u.errno))
        sys.close(vm, r.ret)
    end)

test("dup and fork produce the same open file description and the same rights",
    { spec = "PKM *facs.handle.dup-fork-same-rights" }, function(t)
        local p = facs.file(vm, B .. "/dup", "0123456789abcdef")
        -- Append-only: FMODE_WRITE is set (so Linux lets ftruncate
        -- reach KACS) but FILE_WRITE_DATA is not granted, which is what
        -- ftruncate needs.
        local fd = facs.handle(t, vm, p, R.READ_DATA | R.APPEND_DATA)

        local d = facs.dup(vm, fd)
        t:assert(d.ret >= 0, "dup: " .. sys.errname(d.errno))
        t:assert_eq(sys.read(vm, d.ret, 4), "0123", "the duplicate reads, as the original may")
        local trunc = sys.ftruncate(vm, d.ret, 0)
        t:assert_eq(trunc.errno, sys.E.ACCES,
            "and is refused exactly what the original is refused: " .. sys.errname(trunc.errno))
        sys.close(vm, d.ret)

        -- A worker is a forked child of the agent, so the descriptor
        -- number names the same open file description there.
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            sys.lseek(vm, fd, 0, 0)
            t:assert_eq(sys.read(worker, fd, 4), "0123",
                "the forked child reads through the inherited descriptor")
            local ftr = sys.ftruncate(worker, fd, 0)
            t:assert_eq(ftr.errno, sys.E.ACCES,
                "and inherits the same refusal: " .. sys.errname(ftr.errno))
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
        sys.close(vm, fd)
    end)

test("a descriptor without FD_CLOEXEC survives exec with its mask unchanged",
    { spec = "PKM *facs.handle.exec-preserves-mask",
      skip = "no coverage anywhere: the kernel-only guest has no second program to " ..
             "exec (the sole binary is the provium agent, and exec'ing it ends the " ..
             "connection the assertion would have to travel back over), and no KUnit " ..
             "case covers exec's effect on a stamped file blob" },
    function(t) end)

test("SCM_RIGHTS transfers the descriptor as a capability, with no re-check",
    { spec = "PKM *facs.handle.scm-rights-capability" }, function(t)
        -- Possession is the authorization: the descriptor is sent over a
        -- unix socket after every right on the object has been
        -- withdrawn, and the receiver still holds what was granted at
        -- open. A re-check of any kind at receive would refuse it.
        local p = facs.file(vm, B .. "/scm", "capability")
        local fd = facs.handle(t, vm, p, R.READ_DATA)

        local pair = vm:syscall(facs.NR.socketpair, {
            args = { 1, 1, 0, 0 }, bufs = { string.rep("\0", 8) }, ptrs = { 3 },
        })
        t:assert_eq(pair.ret, 0, "socketpair: " .. sys.errname(pair.errno))
        local send_fd, recv_fd = string.unpack("<i4i4", pair.out_bufs[1])

        t:assert_eq(kacs.set_sd(vm, p, kacs.deny_all()).ret, 0,
            "every right on the object is withdrawn before the transfer")

        -- struct msghdr (56 bytes): name, namelen, iov, iovlen, control,
        -- controllen, flags. The control buffer is one cmsghdr
        -- (len, SOL_SOCKET=1, SCM_RIGHTS=1) followed by the fd.
        local cmsg = string.pack("<I8I4I4i4i4", 20, 1, 1, fd, 0)
        local iov = string.pack("<I8I8", 0, 1)
        local msg = string.pack("<I8I4I4I8I8I8I8i4I4", 0, 0, 0, 0, 1, 0, 20, 0, 0)
        local sent = vm:syscall(facs.NR.sendmsg, {
            args = { send_fd, 0, 0 },
            bufs = { msg, iov, "!", cmsg },
            ptrs = { 1 },
            nested = { { parent = 1, child = 2, offset = 16 },
                       { parent = 2, child = 3, offset = 0 },
                       { parent = 1, child = 4, offset = 32 } },
        })
        t:assert_eq(sent.ret, 1, "the descriptor is sent: " .. sys.errname(sent.errno))

        local rcmsg = string.rep("\0", 32)
        local riov = string.pack("<I8I8", 0, 1)
        local rmsg = string.pack("<I8I4I4I8I8I8I8i4I4", 0, 0, 0, 0, 1, 0, 32, 0, 0)
        local got = vm:syscall(facs.NR.recvmsg, {
            args = { recv_fd, 0, 0 },
            bufs = { rmsg, riov, "\0", rcmsg },
            ptrs = { 1 },
            nested = { { parent = 1, child = 2, offset = 16 },
                       { parent = 2, child = 3, offset = 0 },
                       { parent = 1, child = 4, offset = 32 } },
        })
        t:assert_eq(got.ret, 1, "and received: " .. sys.errname(got.errno))
        local received = string.unpack("<i4", got.out_bufs[4], 17)
        t:assert(received >= 0, "the receiver got a descriptor: " .. received)

        sys.lseek(vm, received, 0, 0)
        t:assert_eq(sys.read(vm, received, 4), "capa",
            "which still carries the rights it was opened with")
        local reopen, errno = facs.open(vm, p, { access = R.READ_DATA })
        t:assert(not reopen, "while a fresh open of the object is refused: " ..
            sys.errname(errno or 0))

        sys.close(vm, received); sys.close(vm, send_fd)
        sys.close(vm, recv_fd); sys.close(vm, fd)
    end)

test("pidfd_getfd is gated by an AccessCheck for PROCESS_DUP_HANDLE",
    { spec = "PKM *facs.handle.pidfd-getfd-gate" }, function(t)
        local pid = vm:syscall(sys.NR.getpid).ret
        -- SYSTEM is granted it against its own process and receives the
        -- descriptor with its full mask.
        local p = facs.file(vm, B .. "/getfd", "target")
        local fd = facs.handle(t, vm, p, R.READ_DATA)
        local mine = vm:syscall(sys.NR.pidfd_open, pid, 0)
        t:assert(mine.ret >= 0, "pidfd_open: " .. sys.errname(mine.errno))
        local got = facs.pidfd_getfd(vm, mine.ret, fd)
        t:assert(got.ret >= 0, "SYSTEM may duplicate a handle out of the process: " ..
            sys.errname(got.errno))
        if got.ret >= 0 then
            t:assert_eq(sys.read(vm, got.ret, 6), "target",
                "and the descriptor arrives with its mask intact")
            sys.close(vm, got.ret)
        end
        sys.close(vm, mine.ret); sys.close(vm, fd)

        -- An ordinary user is not, and the gate is the process
        -- descriptor rather than anything about the file.
        kacs.set_sd(vm, "/", kacs.grant(kacs.ALL_RIGHTS))
        token.as_principal(t, vm, {}, function(worker)
            local target = worker:syscall(sys.NR.pidfd_open, pid, 0)
            t:assert(target.ret >= 0, "an ordinary user may name the process: " ..
                sys.errname(target.errno))
            -- Descriptor 0 exists in the target; only PROCESS_DUP_HANDLE
            -- is missing, so the refusal is the gate and not a bad fd.
            local no = facs.pidfd_getfd(worker, target.ret, 0)
            -- PROCESS_QUERY_LIMITED is granted (pidfd_open worked) and
            -- PROCESS_DUP_HANDLE is not, which is the gate. §3.9.1 names
            -- no errno; Linux reports the refused ptrace-mode check as
            -- EPERM.
            t:assert(no.ret < 0, "and cannot duplicate a handle out of it: " ..
                sys.errname(no.errno))
            sys.close(worker, target.ret)
        end)
    end)

test("mandatory subject policy is evaluated once, at open, against the opener",
    { spec = "PKM *facs.handle.mic-pip-at-open" }, function(t)
        -- Everyone needs to reach the object for the label to be the
        -- only thing deciding.
        kacs.set_sd(vm, "/", kacs.grant(kacs.ALL_RIGHTS))
        kacs.set_sd(vm, B, kacs.grant(kacs.ALL_RIGHTS))
        local p = B .. "/mic"
        vm:write_file(p, "labelled")
        local dacl = access.acl({ access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS, token.SID.EVERYONE) })
        local high = access.sd({
            dacl = dacl,
            sacl = access.acl({ access.label_ace(token.INTEGRITY.HIGH, access.LABEL.NO_WRITE_UP) }),
        })
        t:assert_eq(kacs.set_sd(vm, p, high, kacs.SI.DACL | kacs.SI.SACL).ret, 0,
            "the object is labelled High with NO_WRITE_UP")

        token.as_principal(t, vm, { integrity_level = token.INTEGRITY.MEDIUM,
            mandatory_policy = token.MANDATORY.NO_WRITE_UP }, function(worker)
            local ro, e1 = facs.open(worker, p, { access = R.READ_DATA })
            t:assert(ro, "a Medium opener may read a High object: " .. sys.errname(e1 or 0))
            local rw, e2 = facs.open(worker, p, { access = R.WRITE_DATA })
            t:assert(not rw, "and is refused a write handle by the label alone")
            t:assert_eq(e2, sys.E.ACCES, "EACCES: " .. sys.errname(e2 or 0))
            -- The read handle is unaffected by anything that happens to
            -- the label afterwards, because the decision was taken at
            -- open against the opener.
            if ro then
                t:assert_eq(sys.read(worker, ro, 5), "label",
                    "the handle opened before is still usable")
                sys.close(worker, ro)
            end
        end)
    end)

-- Stacked backing files -----------------------------------------------------
--
-- A backing file is a kernel-private file a stacking filesystem
-- allocates for a managed user-visible one. Overlayfs is the reachable
-- producer: an mmap through an overlay installs the *provider's* file in
-- the VMA, so a later mprotect is enforced against the backing file's
-- own blob — which is where the outer descriptor's snapshot has to have
-- landed for the refusal to happen at all.

local OVL = B .. "/ovl"

--- Mount an overlay whose lower layer holds `name` with `content`, and
--- run `fn(merged_path)`.
local function with_overlay(t, name, content, fn)
    for _, d in ipairs({ "lower", "upper", "work", "merged" }) do
        vm:mkdir(OVL .. "-" .. d, { parents = true })
        kacs.set_sd(vm, OVL .. "-" .. d, kacs.grant(kacs.ALL_RIGHTS))
    end
    facs.file(vm, OVL .. "-lower/" .. name, content)
    local m = sys.mount(vm, { source = "overlay", target = OVL .. "-merged",
        fstype = "overlay",
        data = "lowerdir=" .. OVL .. "-lower,upperdir=" .. OVL ..
               "-upper,workdir=" .. OVL .. "-work" })
    t:assert_eq(m.ret, 0, "the overlay mounts: " .. sys.errname(m.errno))
    local ok, err = pcall(fn, OVL .. "-merged/" .. name)
    sys.umount(vm, OVL .. "-merged")
    if not ok then error(err, 0) end
end

test("the outer handle's snapshot is captured into the backing file",
    { spec = "PKM *facs.handle.backing-snapshot-captured" }, function(t)
        with_overlay(t, "snap", string.rep("a", 64), function(merged)
            -- Read-only outer handle. The mapping is installed against
            -- the provider's backing file; upgrading it to PROT_WRITE
            -- is judged on that file's blob.
            local ro = facs.handle(t, vm, merged, R.READ_DATA)
            local addr = sys.mmap(vm, ro, 4096, sys.PROT.READ, sys.MAP.SHARED)
            t:assert(addr, "a shared read mapping through the overlay succeeds")
            local up = facs.mprotect(vm, addr, 4096, sys.PROT.READ | sys.PROT.WRITE)
            t:assert_eq(up.errno, sys.E.ACCES,
                "and the backing file refuses the write upgrade the outer mask never granted: "
                .. sys.errname(up.errno))
            sys.munmap(vm, addr, 4096)
            sys.close(vm, ro)

            -- With FILE_WRITE_DATA on the outer handle the same upgrade
            -- is allowed: the backing file carries the outer values, not
            -- a mask of its own.
            local rw = facs.handle(t, vm, merged, R.READ_DATA | R.WRITE_DATA)
            local waddr = sys.mmap(vm, rw, 4096, sys.PROT.READ, sys.MAP.SHARED)
            t:assert(waddr, "a shared read mapping through a writable handle succeeds")
            local ok = facs.mprotect(vm, waddr, 4096, sys.PROT.READ | sys.PROT.WRITE)
            t:assert_eq(ok.ret, 0, "and the write upgrade is granted: " ..
                sys.errname(ok.errno))
            sys.munmap(vm, waddr, 4096)
            sys.close(vm, rw)
        end)
    end)

test("no new AccessCheck runs against the task executing the stacking filesystem",
    { spec = "PKM *facs.handle.backing-no-new-accesscheck",
      covered_by = "kunit:pkm_kunit_file",
      skip = "the backing-file allocation path is kernel-private — the guest can " ..
             "observe the resulting mask but not the absence of a second check; " ..
             "runs under pkm_kunit_backing_file_inherits_exact_outer_snapshot" },
    function(t) end)

test("the inheritance is admitted only through the typed backing-file path",
    { spec = "PKM *facs.handle.backing-admission-narrow",
      covered_by = "kunit:pkm_kunit_file",
      skip = "admission is decided inside backing_file_alloc, which userspace " ..
             "cannot reach with a non-conforming outer file; runs under " ..
             "pkm_kunit_backing_file_rejects_unsettled_outer_handles" },
    function(t) end)

test("an active copy-up context takes precedence over inherited authority",
    { spec = "PKM *facs.handle.copy-up-context-precedence",
      covered_by = "kunit:pkm_kunit_file",
      skip = "the copy-up context exists only for the duration of a kernel-internal " ..
             "copy-up and cannot be observed mid-flight from the guest; runs under " ..
             "pkm_kunit_copy_up_backing_file_requires_explicit_adoption" },
    function(t) end)

test("immediate provider re-entry does not repeat the caller authorization",
    { spec = "PKM *facs.handle.no-duplicate-provider-check" }, function(t)
        -- One user-visible read through the overlay, one caller audit
        -- event. A second authorization of the provider file would emit
        -- a second one against the same continuous audit mask.
        for _, d in ipairs({ "lower", "upper", "work", "merged" }) do
            vm:mkdir(OVL .. "2-" .. d, { parents = true })
            kacs.set_sd(vm, OVL .. "2-" .. d, kacs.grant(kacs.ALL_RIGHTS))
        end
        local lower = OVL .. "2-lower/dup"
        vm:write_file(lower, "abcdefgh")
        local dacl = access.acl({ access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS, token.SID.EVERYONE) })
        local sacl = access.acl({ access.ace(access.ACE.ALARM, R.READ_DATA, token.SID.EVERYONE) })
        t:assert_eq(kacs.set_sd(vm, lower, access.sd({ dacl = dacl, sacl = sacl }),
            kacs.SI.DACL | kacs.SI.SACL).ret, 0, "the object is continuously audited")
        local m = sys.mount(vm, { source = "overlay", target = OVL .. "2-merged",
            fstype = "overlay",
            data = "lowerdir=" .. OVL .. "2-lower,upperdir=" .. OVL ..
                   "2-upper,workdir=" .. OVL .. "2-work" })
        t:assert_eq(m.ret, 0, "the overlay mounts: " .. sys.errname(m.errno))

        local events = kmes.recording(t, vm, function()
            local fd = facs.handle(t, vm, OVL .. "2-merged/dup", R.READ_DATA)
            sys.read(vm, fd, 4)
            sys.close(vm, fd)
        end)
        sys.umount(vm, OVL .. "2-merged")
        local reads = {}
        for _, e in ipairs(kmes.of_type(events, "continuous-audit")) do
            if e.payload and e.payload.operation == "file.permission" then
                reads[#reads + 1] = e
            end
        end
        t:assert_eq(#reads, 1,
            "one user-visible read is authorized and audited once, not once per layer")
    end)

test("the mmap handoff verifies the outer, backing and captured snapshots agree",
    { spec = "PKM *facs.handle.mmap-backing-verifies-agreement" }, function(t)
        with_overlay(t, "agree", string.rep("b", 64), function(merged)
            -- An execute mapping is installed only if all three views
            -- carry FILE_EXECUTE. A handle without it is refused at the
            -- handoff rather than at mprotect.
            local ro = facs.handle(t, vm, merged, R.READ_DATA)
            local no = sys.mmap(vm, ro, 4096, sys.PROT.READ | facs.PROT_EXEC, sys.MAP.PRIVATE)
            t:assert(not no, "an execute mapping is refused where the outer mask lacks it")
            sys.close(vm, ro)

            local x = facs.handle(t, vm, merged, R.READ_DATA | R.EXECUTE)
            local addr = sys.mmap(vm, x, 4096, sys.PROT.READ | facs.PROT_EXEC, sys.MAP.PRIVATE)
            t:assert(addr, "and installed where every view agrees it is granted")
            if addr then sys.munmap(vm, addr, 4096) end
            sys.close(vm, x)
        end)
    end)

test("suppression covers KACS authorization only, not filesystem refusals",
    { spec = "PKM *facs.handle.backing-suppresses-kacs-only" }, function(t)
        -- A read-only overlay (two lower layers, no upper) refuses a
        -- write handle on its own account. KACS grants the mask; the
        -- refusal is EROFS, which is not a KACS decision and which the
        -- backing-file suppression does not touch.
        for _, d in ipairs({ "l1", "l2", "m" }) do
            vm:mkdir(OVL .. "3-" .. d, { parents = true })
            kacs.set_sd(vm, OVL .. "3-" .. d, kacs.grant(kacs.ALL_RIGHTS))
        end
        facs.file(vm, OVL .. "3-l1/ro", "immutable content")
        local m = sys.mount(vm, { source = "overlay", target = OVL .. "3-m",
            fstype = "overlay",
            data = "lowerdir=" .. OVL .. "3-l1:" .. OVL .. "3-l2" })
        t:assert_eq(m.ret, 0, "a read-only overlay mounts: " .. sys.errname(m.errno))

        local ro, e1 = facs.open(vm, OVL .. "3-m/ro", { access = R.READ_DATA })
        t:assert(ro, "a read handle through it opens: " .. sys.errname(e1 or 0))
        if ro then
            t:assert_eq(sys.read(vm, ro, 9), "immutable", "and reads")
            sys.close(vm, ro)
        end

        local rw, e2 = facs.open(vm, OVL .. "3-m/ro", { access = R.READ_DATA | R.WRITE_DATA })
        t:assert(not rw, "a write handle is refused")
        t:assert_eq(e2, sys.E.ROFS,
            "by the read-only mount rather than by KACS: " .. sys.errname(e2 or 0))
        sys.umount(vm, OVL .. "3-m")
    end)
