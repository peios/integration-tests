-- PKM §3.7 — where dominance is enforced: ptrace in every mode, signal
-- delivery, the pidfd calls, and /proc metadata.
--
-- Each of these claims is of the form "operation X needs right R plus
-- dominance". Both halves are witnessed:
--
--   * the right, from the `kacs:kacs_process_access` tracepoint's
--     `desired=` field, which is the mask the enforcement point asked
--     the descriptor for — and by withholding exactly that bit;
--   * the PIP half, from a process-trust-label ACE on the target's
--     descriptor. No process in this guest can be made protected (§3.6
--     confers PIP only through a signature and there is no signing key),
--     so that ACE is the only way to put a live process behind a PIP
--     refusal. It runs the same two-axis comparison and, as §3.7's
--     SeDebugPrivilege paragraph says, short-circuits before the debug
--     rescue.
--
-- The caller throughout is the agent's own principal minus the
-- privileges that reach past a descriptor, SeDebugPrivilege included —
-- otherwise every denial would be rescued. It keeps SYSTEM's user SID
-- and full Linux capabilities, which is what makes the ptrace case mean
-- something: the caller is root and is refused anyway.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local psb = require("helpers.psb")
local pip = require("helpers.pip")
local signing = require("helpers.signing")

local vm = provium:vm("v", "kernel-only"):boot()

-- Yama's default ptrace scope restricts attach to descendants, which
-- would mask KACS's answer with EPERM before the LSM is consulted. The
-- cases below are about KACS's answer, so the native restriction is
-- lifted for the file.
vm:write_file("/proc/sys/kernel/yama/ptrace_scope", "0")

local EV = "kacs/kacs_process_access"

--- The `desired=` masks the tracepoint recorded across `fn`, as a set.
local function desired(fn)
    local seen = {}
    for _, e in ipairs(signing.of(signing.trace(vm, { EV }, fn),
                                  "kacs_process_access")) do
        seen[e.desired] = (seen[e.desired] or 0) + 1
    end
    return seen
end

--- Assert that `fn` asked the descriptor for exactly `mask`.
local function asked_for(t, mask, what, fn)
    local seen = desired(fn)
    local want = string.format("0x%x", mask)
    local names = {}
    for k in pairs(seen) do names[#names + 1] = k end
    table.sort(names)
    t:assert(seen[want], what .. " asks the descriptor for " .. want ..
        " (saw " .. (next(names) and table.concat(names, ",") or "nothing") .. ")")
end

--- Run `fn(caller, pid)` against a target whose descriptor grants
--- Everyone exactly `mask`.
local function granting(t, mask, fn)
    pip.with_target(vm, function(target, pidfd, pid)
        pip.protect(vm, pidfd, pip.grant(mask))
        pip.bound(t, vm, function(w) fn(w, pid, pidfd, target) end)
    end)
end

--- Run `fn(caller, pid)` against a target whose DACL grants every
--- process right and whose trust label the caller cannot satisfy.
local function pip_denied(t, fn)
    pip.with_target(vm, function(target, pidfd, pid)
        pip.protect(vm, pidfd, pip.pip())
        pip.bound(t, vm, function(w) fn(w, pid, pidfd, target) end)
    end)
end

-- ptrace ---------------------------------------------------------------------

test("a caller PIP refuses is denied ptrace in the attach, pidfd and query modes",
    { spec = "PKM *pip.ptrace.all-modes" }, function(t)
        pip_denied(t, function(w, pid, pidfd)
            -- Attach mode.
            t:assert_eq(w:syscall(pip.NR.ptrace, pip.PTRACE.ATTACH, pid, 0, 0).errno,
                sys.E.ACCES, "PTRACE_ATTACH is refused")
            t:assert_eq(w:syscall(pip.NR.ptrace, pip.PTRACE.SEIZE, pid, 0, 0).errno,
                sys.E.ACCES, "PTRACE_SEIZE is refused")
            -- PIDFD_OPEN mode.
            t:assert_eq(select(2, token.pidfd_open(w, pid)), sys.E.ACCES,
                "PTRACE_MODE_PIDFD_OPEN is refused")
            -- PROC_QUERY modes.
            t:assert_eq(pip.proc_read(w, pid, "stat"),
                "read:" .. sys.errname(sys.E.ACCES),
                "the limited metadata query is refused")
            t:assert_eq(pip.proc_read(w, pid, "status"),
                "read:" .. sys.errname(sys.E.ACCES),
                "and so is the detailed one")
        end)
    end)

test("a caller PIP refuses is denied ptrace in read mode too",
    { spec = "PKM *pip.ptrace.all-modes", tags = { "known-bug" } }, function(t)
        -- The remaining mode. §3.7 says a non-dominant caller is refused
        -- "whatever the mode". The hook *is* reached on this path and it
        -- *does* deny — `kacs_process_access` records
        -- `reason=debug-denied desired=0x10 ret=-13` for each of these
        -- opens — but the syscall proceeds anyway, so the LSM's answer is
        -- computed and discarded. Same divergence
        -- tests/kacs/psb-rights.test.lua records for *psb.right.vm-read.
        pip_denied(t, function(w, pid)
            t:assert_eq(pip.proc_read(w, pid, "maps"),
                "open:" .. sys.errname(sys.E.ACCES),
                "/proc/<pid>/maps is refused")
            t:assert_eq(pip.proc_read(w, pid, "environ"),
                "open:" .. sys.errname(sys.E.ACCES),
                "and so is /proc/<pid>/environ")
        end)
    end)

test("the LSM's answer is final: a root caller with every capability is still refused",
    { spec = "PKM *pip.ptrace.lsm-answer-final" }, function(t)
        -- The caller keeps SYSTEM's user SID and the whole Linux
        -- capability set — the only thing it has lost is the KACS
        -- privileges that reach past a descriptor. Native UID and
        -- capability rules would grant; `__ptrace_may_access` returns
        -- the LSM's answer instead.
        granting(t, pip.ALL_RIGHTS & ~pip.RIGHT.VM_WRITE, function(w, pid)
            t:assert_eq(w:syscall(sys.NR.getuid).ret, 0,
                "the caller is root")
            t:assert_eq(w:syscall(pip.NR.ptrace, pip.PTRACE.ATTACH, pid, 0, 0).errno,
                sys.E.ACCES,
                "and is refused the attach the descriptor withholds")
        end)
        granting(t, pip.ALL_RIGHTS, function(w, pid)
            local r = w:syscall(pip.NR.ptrace, pip.PTRACE.ATTACH, pid, 0, 0)
            t:assert_eq(r.ret, 0, "with PROCESS_VM_WRITE granted it attaches: "
                .. sys.errname(r.errno))
            w:syscall(pip.NR.ptrace, pip.PTRACE.DETACH, pid, 0, 0)
        end)
    end)

test("the direct memory-access vectors route through the same check",
    { spec = "PKM *pip.ptrace.covers-memory-vectors", tags = { "known-bug" } },
    function(t)
        -- §3.7: "/proc/<pid>/mem, process_vm_readv and process_vm_writev
        -- route through the same check, so one hook covers every
        -- memory-access vector." Against a descriptor granting nothing
        -- the hook runs and denies — one `kacs_process_access` verdict
        -- per call, `reason=debug-denied desired=0x10 ret=-13` — and the
        -- calls succeed regardless: process_vm_readv returns the bytes
        -- and /proc/<pid>/mem opens. The answer is reached and then
        -- ignored, which is the same divergence
        -- tests/kacs/psb-rights.test.lua records for *psb.right.vm-read.
        granting(t, 0, function(w, pid, _, target)
            local remote = assert(psb.anon(target, psb.PROT.READ | psb.PROT.WRITE),
                "the target has a page to read")
            local r = pip.vm_readv(w, pid, remote)
            t:assert_eq(r.errno, sys.E.ACCES,
                "process_vm_readv is refused by a descriptor granting " ..
                "nothing (it read " .. r.ret .. " bytes)")
            local fd, errno = sys.open(w, "/proc/" .. pid .. "/mem", sys.O.RDONLY)
            if fd then sys.close(w, fd) end
            t:assert(not fd,
                "/proc/<pid>/mem is refused without PROCESS_VM_READ")
            t:assert_eq(errno, sys.E.ACCES, "with EACCES")
        end)
    end)

test("PTRACE_TRACEME inverts the roles: the caller is the target",
    { spec = "PKM *pip.ptrace.traceme-inverted" }, function(t)
        -- The nominated tracer is the worker's parent, the agent, which
        -- is SYSTEM and holds SeDebugPrivilege — so an ordinary
        -- descriptor denial on the caller's own process would be
        -- rescued. A trust label on it is not, and it is the caller's
        -- own descriptor that decides.
        -- A TRACEME that succeeds cannot be undone from the tracee, so
        -- the two verdicts need a worker each.
        local function traceme(descriptor, body)
            local worker = vm:spawn_worker()
            local ok, err = pcall(function()
                local pid = worker:syscall(sys.NR.getpid).ret
                local pidfd = assert(token.pidfd_open(vm, pid))
                pip.protect(vm, pidfd, descriptor)
                sys.close(vm, pidfd)
                body(worker)
            end)
            worker:kill(); worker:join()
            if not ok then error(err, 0) end
        end

        traceme(pip.pip(), function(worker)
            t:assert_eq(worker:syscall(pip.NR.ptrace, pip.PTRACE.TRACEME,
                0, 0, 0).errno, sys.E.ACCES,
                "TRACEME is refused when the nominated tracer does not " ..
                "dominate the caller")
        end)
        traceme(pip.grant(pip.ALL_RIGHTS), function(worker)
            local seen = desired(function()
                t:assert_eq(worker:syscall(pip.NR.ptrace, pip.PTRACE.TRACEME,
                    0, 0, 0).ret, 0,
                    "and accepted when the caller's own descriptor permits it")
            end)
            t:assert(seen[string.format("0x%x", pip.RIGHT.VM_WRITE)],
                "asking the caller's own descriptor for PROCESS_VM_WRITE")
        end)
    end)

test("mutually exclusive ptrace modes, and a request that is neither read nor attach, are malformed",
    { spec = "PKM *pip.ptrace.mode-combinations-rejected",
      covered_by = "kunit:pkm_kunit_process",
      skip = "PTRACE_MODE_* is an in-kernel argument to the LSM hook, " ..
             "assembled by the caller inside the kernel; no syscall lets " ..
             "userspace present a combination of them; runs under " ..
             "pkm_kunit_ptrace_unknown_mode_fails_closed and " ..
             "pkm_kunit_proc_metadata_query_mode_combo_fails_closed" },
    function(t) end)

-- Signals ---------------------------------------------------------------------

test("signal delivery is gated uniformly, whatever the signal's type",
    { spec = "PKM *pip.signal.uniform-all-types" }, function(t)
        pip_denied(t, function(w, pid)
            local sigs = { 1, 2, 6, 9, 15, 17, 18, 19, 23, 28, 31, 32, 64 }
            for _, sig in ipairs(sigs) do
                t:assert_eq(w:syscall(pip.NR.kill, pid, sig).errno, sys.E.ACCES,
                    psb.signame(sig) .. " is refused")
            end
            t:assert_eq(w:syscall(pip.NR.kill, pid, 0).errno, sys.E.ACCES,
                "and so is the zero-signal existence probe")
        end)
    end)

test("signalling within one process security state is exempt structurally",
    { spec = "PKM *pip.signal.same-security-state-exempt" }, function(t)
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local pid = worker:syscall(sys.NR.getpid).ret
            local pidfd = assert(token.pidfd_open(vm, pid))
            -- Nothing could pass this descriptor: it grants nothing and
            -- carries a trust label the worker cannot satisfy.
            pip.protect(vm, pidfd, pip.pip(pip.PROTECTED, pip.PEIOS_TCB, 0))
            sys.close(vm, pidfd)
            local seen = desired(function()
                t:assert_eq(worker:syscall(pip.NR.kill, pid, 28).ret, 0,
                    "a self-directed signal is delivered")
                t:assert_eq(worker:syscall(pip.NR.tkill, pid, 28).ret, 0,
                    "and so is a thread-directed one")
            end)
            t:assert(next(seen) == nil,
                "the exemption is a pointer comparison ahead of both " ..
                "checks: no descriptor or dominance evaluation ran at all")
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
    end)

test("raise() and abort() work for a restricted token whose own descriptor would refuse it",
    { spec = "PKM *pip.signal.self-signals-work-for-restricted" }, function(t)
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local pid = worker:syscall(sys.NR.getpid).ret
            local pidfd = assert(token.pidfd_open(vm, pid))
            -- A present, empty DACL: an AccessCheck of any token
            -- against this descriptor fails, self ACE or not.
            pip.protect(vm, pidfd, psb.deny_all())
            sys.close(vm, pidfd)

            local self_token = worker:syscall(kacs.SYS.OPEN_SELF_TOKEN, 0,
                kacs.TOKEN_ALL_ACCESS)
            assert(self_token.ret >= 0, "open_self_token")
            local restrict = worker:syscall(sys.NR.ioctl, {
                args = { self_token.ret, kacs.IOC.RESTRICT, 0 },
                bufs = { string.pack("<I8I4I4I4I4I8i4I4",
                    kacs.BYPASS_PRIVILEGES | pip.SE_DEBUG,
                    0, 0, 0, 0, 0, -1, 0) },
                ptrs = { 2 },
            })
            assert(restrict.ret == 0, "KACS_IOC_RESTRICT")
            local filtered = string.unpack("<i4", restrict.out_bufs[1], 33)
            assert(worker:syscall(sys.NR.ioctl, filtered,
                kacs.IOC.INSTALL, 0).ret == 0, "KACS_IOC_INSTALL")

            -- raise(SIGURG) / pthread_kill(SIGWINCH): both ignorable, so
            -- the process survives to answer.
            t:assert_eq(worker:syscall(pip.NR.kill, pid, 23).ret, 0,
                "raise() works for a restricted token")
            t:assert_eq(worker:syscall(pip.NR.tgkill, pid, pid, 28).ret, 0,
                "and so does pthread_kill()")
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
    end)

test("a multi-target send reaches the permitted subset and succeeds",
    { spec = "PKM *pip.signal.multi-target-partial-success" }, function(t)
        pip.with_target(vm, function(target, pidfd, pid)
            -- The target is in the caller's process group (both are
            -- children of the agent) and is individually unreachable.
            pip.protect(vm, pidfd, psb.deny_all())
            pip.bound(t, vm, function(w)
                t:assert_eq(w:syscall(pip.NR.kill, pid, 28).errno, sys.E.ACCES,
                    "the target refuses a directed send")
                local r = w:syscall(pip.NR.kill, 0, 28)
                t:assert_eq(r.ret, 0,
                    "but a send to the whole process group succeeds, " ..
                    "because at least one delivery happened: "
                    .. sys.errname(r.errno))
            end)
        end)
    end)

test("SIGCONT has no same-session exception and needs PROCESS_SUSPEND_RESUME",
    { spec = "PKM *pip.signal.sigcont-no-session-exception" }, function(t)
        -- POSIX exempts SIGCONT to a process in the sender's own
        -- session. Caller and target are both children of the agent, so
        -- they share one session; the exemption is absent anyway.
        granting(t, pip.ALL_RIGHTS & ~pip.RIGHT.SUSPEND_RESUME, function(w, pid)
            t:assert_eq(w:syscall(pip.NR.getsid, 0).ret,
                vm:syscall(pip.NR.getsid, pid).ret,
                "caller and target are in the same session")
            t:assert_eq(w:syscall(pip.NR.kill, pid, 18).errno, sys.E.ACCES,
                "SIGCONT is refused without PROCESS_SUSPEND_RESUME")
        end)
        granting(t, pip.RIGHT.SUSPEND_RESUME, function(w, pid)
            asked_for(t, pip.RIGHT.SUSPEND_RESUME, "SIGCONT", function()
                t:assert_eq(w:syscall(pip.NR.kill, pid, 18).ret, 0,
                    "and accepted with it, like every other job-control signal")
            end)
        end)
    end)

-- pidfd ------------------------------------------------------------------------

test("pidfd_open() needs PROCESS_QUERY_LIMITED plus dominance",
    { spec = "PKM *pip.pidfd-open.query-limited" }, function(t)
        granting(t, pip.RIGHT.QUERY_LIMITED, function(w, pid)
            asked_for(t, pip.RIGHT.QUERY_LIMITED, "pidfd_open()", function()
                local fd, errno = token.pidfd_open(w, pid)
                t:assert(fd, "it succeeds on that right alone: "
                    .. sys.errname(errno or 0))
                if fd then sys.close(w, fd) end
            end)
        end)
        granting(t, pip.ALL_RIGHTS & ~pip.RIGHT.QUERY_LIMITED, function(w, pid)
            t:assert_eq(select(2, token.pidfd_open(w, pid)), sys.E.ACCES,
                "and is refused when that right is the one withheld")
        end)
        pip_denied(t, function(w, pid)
            t:assert_eq(select(2, token.pidfd_open(w, pid)), sys.E.ACCES,
                "dominance is required on top of the right")
        end)
    end)

test("pidfd_getfd() maps to PROCESS_DUP_HANDLE plus dominance",
    { spec = "PKM *pip.pidfd-getfd.dup-handle" }, function(t)
        pip.with_target(vm, function(target, pidfd, pid)
            local victim = sys.pipe(target)
            t:assert(victim, "the target holds a descriptor to extract")
            pip.protect(vm, pidfd, pip.grant(pip.ALL_RIGHTS))
            pip.bound(t, vm, function(w)
                local pf = assert(token.pidfd_open(w, pid))
                asked_for(t, pip.RIGHT.DUP_HANDLE, "pidfd_getfd()", function()
                    local r = w:syscall(pip.NR.pidfd_getfd, pf, victim, 0)
                    if r.ret >= 0 then sys.close(w, r.ret) end
                end)
                sys.close(w, pf)
            end)
            pip.protect(vm, pidfd, pip.pip())
            pip.bound(t, vm, function(w)
                t:assert_eq(select(2, token.pidfd_open(w, pid)), sys.E.ACCES,
                    "a caller PIP refuses cannot even open the pidfd it " ..
                    "would extract through")
            end)
        end)
    end)

-- /proc --------------------------------------------------------------------------

test("the non-ptrace-gated /proc entries carry their own descriptor requirement",
    { spec = "PKM *pip.proc.metadata-needs-descriptor-and-dominance" }, function(t)
        granting(t, pip.RIGHT.QUERY_LIMITED, function(w, pid)
            asked_for(t, pip.RIGHT.QUERY_LIMITED, "/proc/<pid>/stat", function()
                t:assert_eq(pip.proc_read(w, pid, "stat"), "ok",
                    "a limited metadata entry reads on QUERY_LIMITED")
            end)
            t:assert_eq(pip.proc_read(w, pid, "status"),
                "read:" .. sys.errname(sys.E.ACCES),
                "a detailed one needs more")
        end)
        granting(t, pip.RIGHT.QUERY_INFORMATION, function(w, pid)
            asked_for(t, pip.RIGHT.QUERY_INFORMATION, "/proc/<pid>/status",
                function()
                    t:assert_eq(pip.proc_read(w, pid, "status"), "ok",
                        "the detailed entry reads on QUERY_INFORMATION")
                end)
        end)
        pip_denied(t, function(w, pid)
            t:assert_eq(pip.proc_read(w, pid, "stat"),
                "read:" .. sys.errname(sys.E.ACCES),
                "and dominance is required on top of either right")
        end)
    end)

test("entries stricter than a metadata query keep their native hardening",
    { spec = "PKM *pip.proc.stricter-entries-keep-native" }, function(t)
        local METADATA = pip.RIGHT.QUERY_LIMITED | pip.RIGHT.QUERY_INFORMATION
        granting(t, METADATA, function(w, pid)
            -- Both metadata rights granted, so every entry the metadata
            -- rule covers is readable; /proc/<pid>/stack is refused
            -- anyway, and with EPERM rather than the EACCES that rule
            -- produces, because it keeps its own attach-class gate.
            t:assert_eq(pip.proc_read(w, pid, "stat"), "ok",
                "the limited metadata entries are readable")
            t:assert_eq(pip.proc_read(w, pid, "status"), "ok",
                "and so are the detailed ones")
            t:assert_eq(pip.proc_read(w, pid, "stack"),
                "read:" .. sys.errname(sys.E.PERM),
                "/proc/<pid>/stack is not brought under the metadata rule")
        end)
        granting(t, pip.ALL_RIGHTS, function(w, pid)
            t:assert_eq(pip.proc_read(w, pid, "stack"), "ok",
                "it takes the stricter, attach-class grant instead")
        end)
    end)

test("denying access does not hide the pid from /proc",
    { spec = "PKM *pip.proc.pid-visible-not-hidden" }, function(t)
        pip_denied(t, function(w, pid)
            t:assert_eq(pip.proc_read(w, pid, "stat"),
                "read:" .. sys.errname(sys.E.ACCES),
                "nothing inside /proc/<pid>/ is readable")
            local fd = assert(sys.open(w, "/proc",
                sys.O.RDONLY | sys.O.DIRECTORY))
            local entries = assert(sys.getdents_all(w, fd))
            sys.close(w, fd)
            local seen = false
            for _, e in ipairs(entries) do
                if e.name == tostring(pid) then seen = true end
            end
            t:assert(seen, "but the directory name is still enumerated: " ..
                "visible-but-inaccessible is the accepted position")
        end)
    end)
