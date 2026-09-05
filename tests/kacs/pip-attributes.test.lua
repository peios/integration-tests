-- PKM §3.7 — the attribute surface: capability metadata, resource
-- limits, the scheduler and placement calls, CPU affinity, token opens
-- and performance monitoring.
--
-- Every claim here names a process right and adds "plus dominance", and
-- a few add a privilege that is checked *before* the descriptor so the
-- SeDebugPrivilege rescue cannot substitute for it.
--
-- Three witnesses, used throughout:
--
--   * the right: the `kacs:kacs_process_access` tracepoint's `desired=`
--     field is the mask the enforcement point handed the descriptor, and
--     withholding exactly that bit refuses the operation;
--   * dominance: a process-trust-label ACE on the target's descriptor,
--     which is the only way to put a live process behind a PIP refusal
--     in a guest where nothing can be signed (§3.6);
--   * a privilege that comes first: a caller that holds SeDebugPrivilege
--     and not the named privilege is refused against a descriptor that
--     grants everything, and no descriptor verdict is recorded at all —
--     the privilege gate returned before the descriptor call.
--
-- perf_event_open needs one concession to Linux's own model:
-- `perf_event_paranoid` defaults to 2, which refuses an unprivileged
-- caller before KACS is consulted. The file relaxes it so that what a
-- case observes is KACS's answer and not the native one.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local psb = require("helpers.psb")
local pip = require("helpers.pip")
local signing = require("helpers.signing")

local vm = provium:vm("v", "kernel-only"):boot()

vm:write_file("/proc/sys/kernel/perf_event_paranoid", "-1")

local EV = "kacs/kacs_process_access"

--- The `desired=` masks the tracepoint recorded across `fn`.
local function desired(fn)
    local seen = {}
    for _, e in ipairs(signing.of(signing.trace(vm, { EV }, fn),
                                  "kacs_process_access")) do
        seen[e.desired] = true
    end
    return seen
end

local function asked_for(t, mask, what, fn)
    local seen = desired(fn)
    local want = string.format("0x%x", mask)
    local names = {}
    for k in pairs(seen) do names[#names + 1] = k end
    table.sort(names)
    t:assert(seen[want], what .. " asks the descriptor for " .. want ..
        " (saw " .. (next(names) and table.concat(names, ",") or "nothing") .. ")")
end

--- `fn(caller, pid, target)` against a target granting exactly `mask`.
local function granting(t, mask, fn, opts)
    pip.with_target(vm, function(target, pidfd, pid)
        pip.protect(vm, pidfd, pip.grant(mask))
        pip.bound(t, vm, function(w) fn(w, pid, target, pidfd) end, opts)
    end)
end

--- `fn(caller, pid)` against a target whose trust label the caller
--- cannot satisfy, with every process right granted by the DACL.
local function pip_denied(t, fn, opts)
    pip.with_target(vm, function(target, pidfd, pid)
        pip.protect(vm, pidfd, pip.pip())
        pip.bound(t, vm, function(w) fn(w, pid, target, pidfd) end, opts)
    end)
end

--- The standard three-part case: the right is what the enforcement
--- point asks for, withholding it refuses, and PIP refuses on top.
local function needs(t, mask, what, run)
    granting(t, mask, function(w, pid, target)
        asked_for(t, mask, what, function() run(w, pid, target) end)
        t:assert_eq(run(w, pid, target).errno, 0,
            what .. " succeeds on that right alone")
    end)
    granting(t, pip.ALL_RIGHTS & ~mask, function(w, pid, target)
        t:assert_eq(run(w, pid, target).errno, sys.E.ACCES,
            what .. " is refused when that right is withheld")
    end)
    pip_denied(t, function(w, pid, target)
        t:assert_eq(run(w, pid, target).errno, sys.E.ACCES,
            what .. " is refused when PIP does not permit it")
    end)
end

-- Capability metadata ---------------------------------------------------------

test("capget on the current process, or a thread sharing its state, is not a boundary operation",
    { spec = "PKM *pip.capget.self-and-sibling-exempt" }, function(t)
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local pid = worker:syscall(sys.NR.getpid).ret
            local pidfd = assert(token.pidfd_open(vm, pid))
            pip.protect(vm, pidfd, pip.pip(pip.PROTECTED, pip.PEIOS_TCB, 0))
            sys.close(vm, pidfd)
            local seen = desired(function()
                t:assert_eq(pip.capget(worker, 0).ret, 0,
                    "capget(pid 0) on itself succeeds against a descriptor " ..
                    "that grants nothing and a label it cannot satisfy")
                t:assert_eq(pip.capget(worker, pid).ret, 0,
                    "and so does naming its own pid")
            end)
            t:assert(next(seen) == nil,
                "neither check ran: it is not a boundary operation")
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
    end)

test("capget against another process needs PROCESS_QUERY_INFORMATION plus dominance",
    { spec = "PKM *pip.capget.cross-process-query-information" }, function(t)
        needs(t, pip.RIGHT.QUERY_INFORMATION, "capget(<other pid>)",
            function(w, pid) return pip.capget(w, pid) end)
    end)

-- Resource limits ----------------------------------------------------------------

test("a prlimit read needs QUERY_INFORMATION and a change needs SET_INFORMATION",
    { spec = "PKM *pip.prlimit.read-and-change" }, function(t)
        granting(t, pip.RIGHT.QUERY_INFORMATION, function(w, pid)
            asked_for(t, pip.RIGHT.QUERY_INFORMATION, "a read-only prlimit",
                function()
                    t:assert_eq(pip.prlimit_read(w, pid).ret, 0,
                        "the read succeeds on QUERY_INFORMATION")
                end)
            t:assert_eq(pip.prlimit_write(w, pid).errno, sys.E.ACCES,
                "but a change is refused on it")
        end)
        granting(t, pip.RIGHT.SET_INFORMATION, function(w, pid)
            asked_for(t, pip.RIGHT.SET_INFORMATION, "a limit change", function()
                t:assert_eq(pip.prlimit_write(w, pid).ret, 0,
                    "the change succeeds on SET_INFORMATION")
            end)
            t:assert_eq(pip.prlimit_read(w, pid).errno, sys.E.ACCES,
                "and a read is refused on it")
        end)
        pip_denied(t, function(w, pid)
            t:assert_eq(pip.prlimit_read(w, pid).errno, sys.E.ACCES,
                "PIP refuses the read")
            t:assert_eq(pip.prlimit_write(w, pid).errno, sys.E.ACCES,
                "and the change")
        end)
    end)

test("setpgid() needs PROCESS_SET_INFORMATION",
    { spec = "PKM *pip.setpgid.set-information",
      covered_by = "kunit:pkm_kunit_process",
      skip = "sys_setpgid() checks PF_FORKNOEXEC before the LSM hook, so " ..
             "the hook is unreachable for any target that has exec'd — " ..
             "and every process a test can name here has (the agent's " ..
             "workers are exec'd children, and a worker cannot fork, " ..
             "PEI-688); a non-parent caller can only name itself, which " ..
             "is the self-target exemption; runs under " ..
             "pkm_kunit_process_setinfo_denied_by_process_sd" },
    function(t) end)

test("getpgid() and getsid() need PROCESS_QUERY_LIMITED",
    { spec = "PKM *pip.getpgid-getsid.query-limited" }, function(t)
        needs(t, pip.RIGHT.QUERY_LIMITED, "getpgid()",
            function(w, pid) return w:syscall(pip.NR.getpgid, pid) end)
        needs(t, pip.RIGHT.QUERY_LIMITED, "getsid()",
            function(w, pid) return w:syscall(pip.NR.getsid, pid) end)
    end)

test("the scheduler, affinity and I/O priority queries need PROCESS_QUERY_INFORMATION",
    { spec = "PKM *pip.sched-queries.query-information" }, function(t)
        needs(t, pip.RIGHT.QUERY_INFORMATION, "sched_getscheduler()",
            function(w, pid) return w:syscall(pip.NR.sched_getscheduler, pid) end)
        needs(t, pip.RIGHT.QUERY_INFORMATION, "ioprio_get()",
            function(w, pid) return w:syscall(pip.NR.ioprio_get, 1, pid) end)
    end)

test("the memory-placement mutations need PROCESS_SET_INFORMATION",
    { spec = "PKM *pip.movememory.set-information" }, function(t)
        needs(t, pip.RIGHT.SET_INFORMATION, "migrate_pages()",
            function(w, pid) return w:syscall(pip.NR.migrate_pages, pid, 0, 0, 0) end)
    end)

test("setting nice, scheduler parameters and I/O priority need PROCESS_SET_INFORMATION",
    { spec = "PKM *pip.sched-set.set-information" }, function(t)
        needs(t, pip.RIGHT.SET_INFORMATION, "setpriority()",
            function(w, pid) return w:syscall(pip.NR.setpriority, 0, pid, 5) end)
        needs(t, pip.RIGHT.SET_INFORMATION, "ioprio_set()",
            function(w, pid)
                return w:syscall(pip.NR.ioprio_set, 1, pid, (2 << 13) | 4)
            end)
    end)

-- CPU affinity ---------------------------------------------------------------------

test("changing the caller's own thread's affinity is not a boundary operation",
    { spec = "PKM *pip.affinity.same-process-not-boundary" }, function(t)
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local pid = worker:syscall(sys.NR.getpid).ret
            local pidfd = assert(token.pidfd_open(vm, pid))
            pip.protect(vm, pidfd, pip.pip(pip.PROTECTED, pip.PEIOS_TCB, 0))
            sys.close(vm, pidfd)
            -- Nothing is granted and the label denies, and the caller
            -- does not hold SeIncreaseBasePriorityPrivilege either.
            local self_token = worker:syscall(kacs.SYS.OPEN_SELF_TOKEN, 0,
                kacs.TOKEN_ALL_ACCESS)
            assert(self_token.ret >= 0, "open_self_token")
            local restrict = worker:syscall(sys.NR.ioctl, {
                args = { self_token.ret, kacs.IOC.RESTRICT, 0 },
                bufs = { string.pack("<I8I4I4I4I4I8i4I4",
                    kacs.BYPASS_PRIVILEGES | pip.SE_DEBUG
                        | pip.SE_INCREASE_BASE_PRIORITY,
                    0, 0, 0, 0, 0, -1, 0) },
                ptrs = { 2 },
            })
            assert(restrict.ret == 0, "KACS_IOC_RESTRICT")
            local filtered = string.unpack("<i4", restrict.out_bufs[1], 33)
            assert(worker:syscall(sys.NR.ioctl, filtered,
                kacs.IOC.INSTALL, 0).ret == 0, "KACS_IOC_INSTALL")

            local seen = desired(function()
                t:assert_eq(pip.setaffinity(worker, 0, 1).ret, 0,
                    "the caller's own thread accepts an affinity change")
                t:assert_eq(pip.setaffinity(worker, pid, 1).ret, 0,
                    "and so does naming its own pid")
            end)
            t:assert(next(seen) == nil,
                "affinity is per-thread, so neither check ran")
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
    end)

test("a cross-process affinity change checks SeIncreaseBasePriorityPrivilege first",
    { spec = "PKM *pip.affinity.cross-process-privilege-first" }, function(t)
        -- The caller keeps SeDebugPrivilege and loses only
        -- SeIncreaseBasePriorityPrivilege. If the rescue could stand in
        -- for the privilege, a descriptor granting everything would let
        -- the call through; it does not, and the errno is the privilege
        -- gate's EPERM rather than the descriptor's EACCES.
        granting(t, pip.ALL_RIGHTS, function(w, pid)
            -- The descriptor grants every right and the caller holds
            -- SeDebugPrivilege, so nothing downstream could refuse
            -- this. It is refused anyway, and the descriptor was never
            -- evaluated: no verdict was recorded for it at all.
            local seen = desired(function()
                t:assert_eq(pip.setaffinity(w, pid, 1).errno, sys.E.ACCES,
                    "without SeIncreaseBasePriorityPrivilege the change " ..
                    "is refused")
            end)
            t:assert(not seen[string.format("0x%x", pip.RIGHT.SET_INFORMATION)],
                "and the privilege was checked before the descriptor and " ..
                "dominance call, which never ran")
        end, { keep = pip.SE_DEBUG, drop = pip.SE_INCREASE_BASE_PRIORITY })
        granting(t, pip.RIGHT.SET_INFORMATION, function(w, pid)
            asked_for(t, pip.RIGHT.SET_INFORMATION,
                "a cross-process affinity change", function()
                    t:assert_eq(pip.setaffinity(w, pid, 1).ret, 0,
                        "with the privilege it reaches the descriptor and " ..
                        "asks for PROCESS_SET_INFORMATION")
                end)
        end)
        granting(t, pip.ALL_RIGHTS & ~pip.RIGHT.SET_INFORMATION, function(w, pid)
            t:assert_eq(pip.setaffinity(w, pid, 1).errno, sys.E.ACCES,
                "and is refused there when the right is withheld")
        end)
        pip_denied(t, function(w, pid)
            t:assert_eq(pip.setaffinity(w, pid, 1).errno, sys.E.ACCES,
                "and PIP refuses it on top of both")
        end)
    end)

test("KACS does not relax the kernel's own affinity validity rules",
    { spec = "PKM *pip.affinity.native-validity-preserved" }, function(t)
        granting(t, pip.ALL_RIGHTS, function(w, pid)
            t:assert_eq(pip.setaffinity(w, pid, 1).ret, 0,
                "a valid mask is accepted with every right granted")
            t:assert_eq(pip.setaffinity(w, pid, 0).errno, sys.E.INVAL,
                "an empty mask still fails EINVAL")
            t:assert_eq(pip.setaffinity(w, pid, 1 << 63).errno, sys.E.INVAL,
                "and so does a mask naming no CPU the machine has")
        end)
    end)

-- Token opens ---------------------------------------------------------------------

test("opening a process or thread token needs PROCESS_QUERY_INFORMATION plus dominance",
    { spec = "PKM *pip.token-open.query-information" }, function(t)
        pip.with_target(vm, function(target, pidfd, pid)
            pip.protect(vm, pidfd, pip.grant(pip.RIGHT.QUERY_INFORMATION
                | pip.RIGHT.QUERY_LIMITED))
            pip.bound(t, vm, function(w)
                local pf = assert(token.pidfd_open(w, pid))
                asked_for(t, pip.RIGHT.QUERY_INFORMATION,
                    "kacs_open_process_token", function()
                        local fd, errno = token.open_process(w, pf,
                            token.RIGHT.QUERY)
                        t:assert(fd, "it succeeds on QUERY_INFORMATION: "
                            .. sys.errname(errno or 0))
                        if fd then sys.close(w, fd) end
                    end)
                local tfd, terrno = token.open_thread(w, pf, pid,
                    token.RIGHT.QUERY)
                t:assert(tfd or terrno == sys.E.NOENT,
                    "kacs_open_thread_token is reached on the same right: "
                    .. sys.errname(terrno or 0))
                if tfd then sys.close(w, tfd) end
                sys.close(w, pf)
            end)

            pip.protect(vm, pidfd, pip.grant(pip.ALL_RIGHTS
                & ~pip.RIGHT.QUERY_INFORMATION))
            pip.bound(t, vm, function(w)
                local pf = assert(token.pidfd_open(w, pid))
                t:assert_eq(select(2, token.open_process(w, pf,
                    token.RIGHT.QUERY)), sys.E.ACCES,
                    "and is refused when QUERY_INFORMATION is withheld")
                sys.close(w, pf)
            end)
        end)
    end)

-- Performance monitoring -------------------------------------------------------------

test("target-specific perf needs SeProfileSingleProcessPrivilege, then the right, then dominance",
    { spec = "PKM *pip.perf.target-specific-requirements" }, function(t)
        -- The privilege is checked and marked used before the
        -- descriptor call, so a caller holding SeDebugPrivilege and not
        -- it is refused with the privilege gate's EPERM.
        granting(t, pip.ALL_RIGHTS, function(w, pid)
            t:assert_eq(pip.perf(w, pid, -1).errno, sys.E.PERM,
                "without SeProfileSingleProcessPrivilege it is refused " ..
                "with EPERM, and SeDebugPrivilege does not stand in for it")
        end, { keep = pip.SE_DEBUG, drop = pip.SE_PROFILE_SINGLE_PROCESS })
        granting(t, pip.RIGHT.QUERY_INFORMATION, function(w, pid)
            asked_for(t, pip.RIGHT.QUERY_INFORMATION,
                "target-specific perf_event_open()", function()
                    local r = pip.perf(w, pid, -1)
                    t:assert(r.ret >= 0, "with the privilege it reaches the " ..
                        "descriptor and asks for QUERY_INFORMATION: "
                        .. sys.errname(r.errno))
                    if r.ret >= 0 then sys.close(w, r.ret) end
                end)
        end)
        granting(t, pip.ALL_RIGHTS & ~pip.RIGHT.QUERY_INFORMATION, function(w, pid)
            t:assert_eq(pip.perf(w, pid, -1).errno, sys.E.ACCES,
                "and is refused when the right is withheld")
        end)
        pip_denied(t, function(w, pid)
            t:assert_eq(pip.perf(w, pid, -1).errno, sys.E.ACCES,
                "and PIP refuses it on top of both")
        end)
    end)

test("own-task profiling is not a boundary operation and needs no privilege",
    { spec = "PKM *pip.perf.own-task-exempt" }, function(t)
        -- A freshly minted principal with no privileges at all.
        token.as_principal(t, vm, {}, function(w)
            local seen = desired(function()
                local r = pip.perf(w, 0, -1)
                t:assert(r.ret >= 0, "perf_event_open on its own task " ..
                    "succeeds with no privilege: " .. sys.errname(r.errno))
                if r.ret >= 0 then sys.close(w, r.ret) end
            end)
            t:assert(next(seen) == nil,
                "and neither process check ran")
            t:assert_eq(pip.perf(w, -1, 0).errno, sys.E.PERM,
                "while the system-wide form is refused to the same caller")
        end)
    end)

test("system-wide profiling needs the operator-class SeSystemProfilePrivilege",
    { spec = "PKM *pip.perf.system-wide-privilege" }, function(t)
        local WITH = token.bit(token.PRIV.PROFILE_SINGLE_PROCESS)
        token.as_principal(t, vm, {
            privs_present = WITH, privs_enabled = WITH,
        }, function(w)
            t:assert_eq(pip.perf(w, -1, 0).errno, sys.E.PERM,
                "SeProfileSingleProcessPrivilege does not carry pid == -1")
        end)
        local SYS = token.bit(token.PRIV.SYSTEM_PROFILE)
        token.as_principal(t, vm, {
            privs_present = SYS, privs_enabled = SYS,
        }, function(w)
            local r = pip.perf(w, -1, 0)
            t:assert(r.ret >= 0,
                "SeSystemProfilePrivilege does: " .. sys.errname(r.errno))
            if r.ret >= 0 then sys.close(w, r.ret) end
        end)
    end)

test("cgroup perf mode stays under Linux's native model",
    { spec = "PKM *pip.perf.cgroup-native",
      skip = "no coverage anywhere: PERF_FLAG_PID_CGROUP needs a cgroup " ..
             "directory descriptor and no cgroup filesystem is mounted in " ..
             "a kernel-only guest; pkm_kunit_process's perf cases drive " ..
             "pkm_kacs_perf_event_open with a task, so none of them " ..
             "exercises the cgroup branch either" },
    function(t) end)
