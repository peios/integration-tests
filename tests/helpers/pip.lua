-- Process Integrity Protection (PKM §3.7): the process-boundary
-- surface, and the one thing that is hard about testing it here.
--
-- PIP is conferred only by a binary signature (§3.6), the kernel holds
-- no signing key, and the guest has no signed binary — so **every**
-- process in this VM carries `pip_type` None and `pip_trust` 0. That
-- makes the target side of the dominance test unreachable: nothing can
-- be made protected, so nothing can be non-dominant against it.
--
-- Two things are reachable, and between them they cover most of §3.7.
--
-- The first is the *caller* side. `kacs_access_check` takes `pip_type`
-- and `pip_trust` directly, so the dominance arithmetic can be driven
-- against a descriptor carrying a process-trust-label ACE with any
-- values a case likes. §3.8.7 owns the AccessCheck-side claims; §3.7
-- uses the syscall only as a witness for the comparison itself.
--
-- The second is the *descriptor* side. A process descriptor may carry a
-- process-trust-label ACE of its own, and a caller that fails it is
-- refused inside the descriptor evaluation — before the SeDebugPrivilege
-- rescue, which is exactly what §3.7 says about that privilege. `M.pip`
-- below builds such a descriptor. Where a case says "operation X needs
-- right R plus dominance", the right is witnessed by the
-- `kacs:kacs_process_access` tracepoint's `desired=` field, which is the
-- mask the enforcement point asked for, and the PIP half by that
-- descriptor.
--
-- The tracepoint is also what shows the two checks are two: a permitted
-- cross-process operation emits `reason=allow` twice — once from the
-- descriptor evaluation, once from the standalone dominance test that
-- follows it.
--
-- Syscall numbers are x86_64 and are carried here rather than in
-- helpers/psb so that §3.7 does not depend on another section's module
-- growing entries.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local access = require("helpers.access")

local M = {}

-- The process-boundary syscalls §3.7 names.
M.NR = {
    kill = 62, tkill = 200, tgkill = 234, ptrace = 101, prctl = 157,
    capget = 125, getpgid = 121, getsid = 124, setpgid = 109,
    sched_getscheduler = 145, sched_setscheduler = 144,
    setpriority = 141, getpriority = 140,
    ioprio_get = 252, ioprio_set = 251,
    sched_setaffinity = 203, sched_getaffinity = 204,
    migrate_pages = 256, move_pages = 279,
    prlimit64 = 302, perf_event_open = 298,
    pidfd_open = 434, pidfd_getfd = 438,
    process_vm_readv = 310, process_vm_writev = 311,
    socket = 41, mount = 165,
}

-- Process access rights (§3.3.3). Repeated here so a §3.7 case names the
-- right the TRM names without reaching into another section's module.
M.RIGHT = {
    TERMINATE = 0x0001, SIGNAL = 0x0002, VM_READ = 0x0010, VM_WRITE = 0x0020,
    DUP_HANDLE = 0x0040, SET_INFORMATION = 0x0200,
    QUERY_INFORMATION = 0x0400, SUSPEND_RESUME = 0x0800,
    QUERY_LIMITED = 0x1000,
    READ_CONTROL = 0x20000, WRITE_DAC = 0x40000, WRITE_OWNER = 0x80000,
}
M.ALL_RIGHTS = M.RIGHT.TERMINATE | M.RIGHT.SIGNAL | M.RIGHT.VM_READ
    | M.RIGHT.VM_WRITE | M.RIGHT.DUP_HANDLE | M.RIGHT.SET_INFORMATION
    | M.RIGHT.QUERY_INFORMATION | M.RIGHT.SUSPEND_RESUME
    | M.RIGHT.QUERY_LIMITED | M.RIGHT.READ_CONTROL | M.RIGHT.WRITE_DAC
    | M.RIGHT.WRITE_OWNER

-- ptrace requests.
M.PTRACE = { TRACEME = 0, PEEKDATA = 2, ATTACH = 16, DETACH = 17, SEIZE = 0x4206 }

-- prctl options.
M.PR = { SET_DUMPABLE = 4, GET_DUMPABLE = 3, SET_NO_NEW_PRIVS = 38 }

-- The tier a §3.7 case uses to stand for "protected": the only tier the
-- signing layer can currently produce (§3.6).
M.PROTECTED, M.PEIOS_TCB = 512, 8192

--- SeDebugPrivilege, which §3.7 says bypasses the descriptor check and
--- never the dominance check.
M.SE_DEBUG = token.bit(token.PRIV.DEBUG)
M.SE_INCREASE_BASE_PRIORITY = token.bit(token.PRIV.INCREASE_BASE_PRIORITY)
M.SE_PROFILE_SINGLE_PROCESS = token.bit(token.PRIV.PROFILE_SINGLE_PROCESS)
M.SE_SYSTEM_PROFILE = token.bit(token.PRIV.SYSTEM_PROFILE)

-- Descriptors ---------------------------------------------------------------

--- A process descriptor granting `mask` to Everyone.
function M.grant(mask)
    return access.sd({ dacl = access.acl({
        access.ace(access.ACE.ALLOWED, mask, token.SID.EVERYONE) }) })
end

--- A process descriptor that grants everything through its DACL and then
--- carries a process-trust-label ACE requiring `type`/`trust`.
---
--- Against a caller whose PSB is None/0 — which every process here is —
--- the label denies, and it denies *inside* the descriptor evaluation,
--- before the SeDebugPrivilege rescue. That is the only PIP refusal a
--- guest can provoke, since no process's own PSB can be raised.
function M.pip(pip_type, pip_trust, mask)
    return access.sd({
        dacl = access.acl({
            access.ace(access.ACE.ALLOWED, mask or M.ALL_RIGHTS,
                       token.SID.EVERYONE) }),
        sacl = access.acl({
            access.trust_label_ace(pip_type or M.PROTECTED,
                                   pip_trust or M.PEIOS_TCB, 0) }),
    })
end

--- A file/object descriptor carrying only a process-trust-label ACE over
--- a permissive DACL, for the AccessCheck-side dominance arithmetic.
function M.labelled(pip_type, pip_trust, mask)
    return access.sd({
        owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
        dacl = access.acl({
            access.ace(access.ACE.ALLOWED, access.FILE_MAPPING.all,
                       token.SID.EVERYONE) }),
        sacl = access.acl({
            access.trust_label_ace(pip_type, pip_trust, mask or 0) }),
    })
end

-- Targets --------------------------------------------------------------------

--- kacs_set_sd against a pidfd, replacing DACL and SACL together.
function M.set_process_sd(vm, pidfd, descriptor)
    return token.set_sd(vm, pidfd, descriptor, kacs.SI.DACL | kacs.SI.SACL)
end

--- Replace a target's process descriptor, raising if the setup did not
--- take — a case whose subject is the operation afterwards has nothing
--- to say if it did not.
function M.protect(vm, pidfd, descriptor)
    local r = M.set_process_sd(vm, pidfd, descriptor)
    assert(r.ret == 0, "set_sd on the target: " .. sys.errname(r.errno))
end

--- Run `fn(target, pidfd, pid)` with a fresh worker as the target and an
--- open pidfd on it, tearing both down afterwards.
function M.with_target(vm, fn)
    local target = vm:spawn_worker()
    local pid = target:syscall(sys.NR.getpid).ret
    local pidfd = assert(token.pidfd_open(vm, pid), "pidfd_open on the target")
    local ok, err = pcall(fn, target, pidfd, pid)
    sys.close(vm, pidfd)
    target:kill(); target:join()
    if not ok then error(err, 0) end
end

--- Run `fn(worker)` as a caller stripped of the privileges that reach
--- past a descriptor. `opts.keep` is a mask of privileges to *keep*
--- that would otherwise be dropped (SeDebugPrivilege, for the rescue
--- cases); `opts.drop` names extra ones to remove.
function M.bound(t, vm, fn, opts)
    opts = opts or {}
    local privs = kacs.BYPASS_PRIVILEGES | M.SE_DEBUG | (opts.drop or 0)
    privs = privs & ~(opts.keep or 0)
    return kacs.as_dacl_bound(t, vm, fn, { privs = privs })
end

-- perf_event_open ------------------------------------------------------------

-- struct perf_event_attr, 128 bytes: type PERF_TYPE_SOFTWARE (1), size,
-- config PERF_COUNT_SW_CPU_CLOCK (0). Everything else zero.
function M.perf_attr()
    return string.pack("<I4I4I8I8", 1, 128, 0, 0) .. string.rep("\0", 104)
end

--- perf_event_open(attr, pid, cpu, -1, flags). Returns the raw result.
function M.perf(who, pid, cpu, flags)
    return who:syscall(M.NR.perf_event_open, {
        args = { 0, pid, cpu, -1, flags or 0 },
        bufs = { M.perf_attr() },
        ptrs = { 0 },
    })
end

-- perf_event_open flags.
M.PERF_FLAG_PID_CGROUP = 0x4

-- Assorted call shapes -------------------------------------------------------

--- capget(header{version, pid}, data). Returns the raw result.
function M.capget(who, pid)
    return who:syscall(M.NR.capget, {
        args = { 0, 0 },
        bufs = { string.pack("<I4i4", 0x20080522, pid), string.rep("\0", 24) },
        ptrs = { 0, 1 },
    })
end

--- prlimit64(pid, RLIMIT_CPU, new, old). Passing `new` makes it a
--- change, `old` alone makes it a read — §3.7 gives them different
--- rights.
function M.prlimit_read(who, pid)
    return who:syscall(M.NR.prlimit64, {
        args = { pid, 0, 0, 0 },
        bufs = { string.rep("\0", 16) },
        ptrs = { 3 },
    })
end

function M.prlimit_write(who, pid, value)
    value = value or (1 << 30)
    return who:syscall(M.NR.prlimit64, {
        args = { pid, 0, 0, 0 },
        bufs = { string.pack("<I8I8", value, value) },
        ptrs = { 2 },
    })
end

--- sched_setaffinity(pid, len, mask).
function M.setaffinity(who, pid, mask)
    return who:syscall(M.NR.sched_setaffinity, {
        args = { pid, 8 },
        bufs = { string.pack("<I8", mask == nil and 1 or mask) },
        ptrs = { 2 },
    })
end

--- process_vm_readv against `pid`, reading `len` bytes from `remote`.
function M.vm_readv(who, pid, remote, len)
    len = len or 8
    local local_iov = string.pack("<I8I8", 0, len)
    local remote_iov = string.pack("<I8I8", remote, len)
    return who:syscall(M.NR.process_vm_readv, {
        args = { pid, 0, 1, 0, 1, 0 },
        bufs = { local_iov, remote_iov, string.rep("\0", len) },
        ptrs = { 1, 3 },
        nested = { { parent = 1, child = 3, offset = 0 } },
    })
end

--- Open one of a process's /proc entries and read from it. Returns
--- "ok", or `open:`/`read:` plus the errno name.
function M.proc_read(who, pid, name, flags)
    local fd, errno = sys.open(who, "/proc/" .. pid .. "/" .. name,
        flags or sys.O.RDONLY)
    if not fd then return "open:" .. sys.errname(errno or 0) end
    local data, rerrno = sys.read(who, fd, 64)
    sys.close(who, fd)
    if not data then return "read:" .. sys.errname(rerrno or 0) end
    return "ok"
end

return M
