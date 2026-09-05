-- The Process Security Block, for the §3.3 cases.
--
-- Three surfaces, and one thing that is awkward about each.
--
-- `kacs_set_psb(pidfd, mitigations)` is the only writer of the PSB's
-- mitigation word. It is write-only: nothing reads the bits back, so a
-- case proves a bit committed by provoking its enforcement point —
-- a W+X mapping for `wxp`, a speculation prctl for `sml`, an exec for
-- `pie`, a fork for `no_child_process`. `-1` names the caller's own
-- process; any other value is a pidfd.
--
-- The process security descriptor is reached through `kacs_get_sd` /
-- `kacs_set_sd` with an empty path, AT_EMPTY_PATH, and a pidfd in the
-- dirfd slot (`pkm_kacs_resolve_pidfd_process_target_checked`). The
-- syscall tries a token fd, then a file, then a pidfd, so the same call
-- shape helpers/token uses for a token handle works here unchanged.
--
-- Producing a caller a process descriptor can deny is the awkward part.
-- The agent is SYSTEM with every privilege and the default DACL grants
-- SYSTEM GENERIC_ALL, so it passes everything twice over. `bound`
-- below runs a body in a worker whose token is the agent's minus the
-- privileges that reach past a descriptor — SeDebugPrivilege included,
-- since §3.3.3 says it rescues a descriptor denial outright. The
-- worker keeps SYSTEM's user SID, which matters: Linux's own
-- credential comparisons sit in front of several of these paths, and a
-- caller that differs from its target in projected uid as well as in
-- descriptor rights cannot tell the two apart.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local access = require("helpers.access")

local M = {}

M.SYS = { SET_PSB = 1005 }

-- Mitigation bits, from uapi/pkm/psb.h.
M.MIT = {
    WXP = 0x001, TLP = 0x002, LSV = 0x004, CFI = 0x008, UI_ACCESS = 0x010,
    NO_CHILD = 0x020, CFIF = 0x040, CFIB = 0x080, PIE = 0x100, SML = 0x200,
}
M.MIT_ALL = 0x3FF

-- Process access rights (§3.3.3), from uapi/pkm/process.h plus the
-- standard bits every object type shares.
M.RIGHT = {
    TERMINATE = 0x0001, SIGNAL = 0x0002, VM_READ = 0x0010, VM_WRITE = 0x0020,
    DUP_HANDLE = 0x0040, SET_INFORMATION = 0x0200,
    QUERY_INFORMATION = 0x0400, SUSPEND_RESUME = 0x0800,
    QUERY_LIMITED = 0x1000,
    READ_CONTROL = 0x20000, WRITE_DAC = 0x40000, WRITE_OWNER = 0x80000,
}

--- Every process right §3.3.3 names, which is what GENERIC_ALL maps to.
M.ALL_RIGHTS = M.RIGHT.TERMINATE | M.RIGHT.SIGNAL | M.RIGHT.VM_READ
    | M.RIGHT.VM_WRITE | M.RIGHT.DUP_HANDLE | M.RIGHT.SET_INFORMATION
    | M.RIGHT.QUERY_INFORMATION | M.RIGHT.SUSPEND_RESUME
    | M.RIGHT.QUERY_LIMITED | M.RIGHT.READ_CONTROL | M.RIGHT.WRITE_DAC
    | M.RIGHT.WRITE_OWNER

-- The signal classification, exactly as §3.3.3 tabulates it.
M.SIGNAL = {
    TERMINATE = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                  24, 25, 26, 27, 29, 30, 31 },
    SUSPEND_RESUME = { 18, 19, 20, 21, 22 },
    IGNORE = { 17, 23, 28 },
}
M.SIGRTMIN, M.SIGRTMAX = 32, 64
M.SIGNAME = {
    [1] = "SIGHUP", [2] = "SIGINT", [3] = "SIGQUIT", [4] = "SIGILL",
    [5] = "SIGTRAP", [6] = "SIGABRT", [7] = "SIGBUS", [8] = "SIGFPE",
    [9] = "SIGKILL", [10] = "SIGUSR1", [11] = "SIGSEGV", [12] = "SIGUSR2",
    [13] = "SIGPIPE", [14] = "SIGALRM", [15] = "SIGTERM", [16] = "SIGSTKFLT",
    [17] = "SIGCHLD", [18] = "SIGCONT", [19] = "SIGSTOP", [20] = "SIGTSTP",
    [21] = "SIGTTIN", [22] = "SIGTTOU", [23] = "SIGURG", [24] = "SIGXCPU",
    [25] = "SIGXFSZ", [26] = "SIGVTALRM", [27] = "SIGPROF", [28] = "SIGWINCH",
    [29] = "SIGIO", [30] = "SIGPWR", [31] = "SIGSYS",
}
function M.signame(sig) return M.SIGNAME[sig] or ("signal " .. sig) end

-- Syscalls the enforcement points sit on. helpers/sys carries the
-- filesystem half; these are the process ones.
M.NR = {
    kill = 62, tgkill = 234, ptrace = 101, prctl = 157, execve = 59,
    pidfd_getfd = 438, capget = 125,
    sched_getscheduler = 145, setpriority = 141, getpgid = 121,
    rt_sigprocmask = 14, rt_sigtimedwait = 128,
}

-- mmap(2) protections, including the exec bit helpers/sys has no need of.
M.PROT = { NONE = 0, READ = 1, WRITE = 2, EXEC = 4 }

-- prctl(2) options the mitigations lock down.
M.PR = {
    SET_DUMPABLE = 4,
    GET_SPECULATION_CTRL = 52, SET_SPECULATION_CTRL = 53,
}
M.PR_SPEC = {
    STORE_BYPASS = 0, INDIRECT_BRANCH = 1, L1D_FLUSH = 2,
    NOT_AFFECTED = 0, PRCTL = 1, ENABLE = 2, DISABLE = 4,
    FORCE_DISABLE = 8, DISABLE_NOEXEC = 16,
}
M.SUID_DUMP_USER = 1

-- SeDebugPrivilege, which §3.3.3 says rescues a descriptor denial.
M.SE_DEBUG = token.bit(token.PRIV.DEBUG)

--- The privileges a caller must not hold for a descriptor denial to be
--- the thing under test: the DACL-bypassing set helpers/kacs names, plus
--- SeDebugPrivilege.
M.NO_BYPASS_PRIVILEGES = kacs.BYPASS_PRIVILEGES | M.SE_DEBUG

-- kacs_set_psb -----------------------------------------------------------

--- kacs_set_psb(2). `pidfd` defaults to -1, the caller's own process.
--- Returns the raw syscall result.
function M.set_psb(who, mitigations, pidfd)
    return who:syscall(M.SYS.SET_PSB, pidfd or -1, mitigations)
end

--- kacs_set_psb on the caller, returning nil on success or the errno.
function M.commit(who, mitigations)
    local r = M.set_psb(who, mitigations)
    if r.ret == 0 then return nil end
    return r.errno
end

-- Enforcement-point probes ------------------------------------------------

--- Map an anonymous page with `prot`. Returns the address, or nil, errno.
function M.anon(who, prot, length)
    return sys.mmap(who, -1, length or 4096, prot,
        sys.MAP.PRIVATE | sys.MAP.ANONYMOUS, 0)
end

--- Is a simultaneously writable and executable anonymous mapping
--- refused? Returns nil when it is allowed, the errno when it is not.
---
--- This is how a case reads the `wxp` bit back: nothing else does.
function M.wx_refused(who)
    local addr, errno = M.anon(who, M.PROT.READ | M.PROT.WRITE | M.PROT.EXEC)
    if not addr then return errno end
    sys.munmap(who, addr, 4096)
    return nil
end

--- mprotect(2).
function M.mprotect(who, addr, length, prot)
    return who:syscall(sys.NR.mprotect, addr, length or 4096, prot)
end

--- execve(2) with no argv and no envp, which every binary here fails at
--- some later stage: what a case reads is *which* stage. Returns the
--- errno.
---
--- The call is safe from a worker precisely because it never succeeds —
--- a successful exec would replace the agent's child with something
--- that cannot answer.
function M.execve(who, path)
    local r = who:syscall(M.NR.execve, {
        args = { 0, 0, 0 }, bufs = { sys.cstr(path) }, ptrs = { 0 },
    })
    return r.errno
end

--- Write a bare 64-bit x86 ELF header of the given `e_type` at `path`
--- and make it executable. ET_EXEC is 2, ET_DYN is 3.
---
--- Nothing here is loadable — there are no program headers — so exec
--- reaches the ELF loader and fails ENOEXEC. That is the point: a
--- mitigation that rejects the binary earlier is visible as a different
--- errno.
function M.write_elf(vm, path, e_type)
    vm:write_file(path, "\x7fELF\2\1\1\0" .. string.rep("\0", 8)
        .. string.pack("<I2I2", e_type, 0x3e) .. string.rep("\0", 200))
    return sys.chmod(vm, path, tonumber("755", 8))
end
M.ET_EXEC, M.ET_DYN = 2, 3

-- The process security descriptor ----------------------------------------

--- pidfd_open(2) on a pid. Returns the fd, or nil, errno.
function M.pidfd(who, pid) return token.pidfd_open(who, pid) end

--- A worker's pid.
function M.pid(who) return who:syscall(sys.NR.getpid).ret end

--- kacs_get_sd against a pidfd. Returns the descriptor bytes, or
--- nil, errno.
function M.get_sd(who, pidfd, info)
    return token.get_sd(who, pidfd,
        info or (kacs.SI.OWNER | kacs.SI.GROUP | kacs.SI.DACL))
end

--- kacs_set_sd against a pidfd. Returns the raw syscall result.
function M.set_sd(who, pidfd, descriptor, info)
    return token.set_sd(who, pidfd, descriptor, info)
end

--- A descriptor whose DACL grants `mask` to Everyone and nothing to
--- anyone else — the shape a rights case wants, since it decides
--- exactly what an arbitrary caller gets.
function M.grant(mask)
    return access.sd({ dacl = access.acl({
        access.ace(access.ACE.ALLOWED, mask, token.SID.EVERYONE) }) })
end

--- The descriptor that denies everyone: a present, empty DACL.
function M.deny_all() return access.sd({ dacl = access.acl({}) }) end

--- Replace a target process's DACL, from the agent. Raises on failure —
--- a case whose subject is the operation afterwards has nothing to say
--- if the setup did not take.
function M.set_dacl(vm, pidfd, mask)
    local r = M.set_sd(vm, pidfd, M.grant(mask), kacs.SI.DACL)
    assert(r.ret == 0, "set_sd on the target: " .. sys.errname(r.errno))
end

-- Callers ------------------------------------------------------------------

--- Run `fn(worker)` as a caller the target's descriptor decides.
---
--- The worker is the agent's principal minus the privileges that reach
--- past a descriptor, SeDebugPrivilege included. `opts.keep_debug`
--- leaves SeDebugPrivilege in place, which is how the §3.3.3 rescue
--- case gets a caller that holds it.
function M.bound(t, vm, fn, opts)
    opts = opts or {}
    local privs = opts.keep_debug and kacs.BYPASS_PRIVILEGES
        or M.NO_BYPASS_PRIVILEGES
    return kacs.as_dacl_bound(t, vm, fn, { privs = privs })
end

--- Run `fn(target, pidfd)` with a plain worker as the target and an open
--- pidfd on it, tearing both down afterwards.
function M.with_target(vm, fn)
    local target = vm:spawn_worker()
    local pidfd = assert(M.pidfd(vm, M.pid(target)), "pidfd_open on the target")
    local ok, err = pcall(fn, target, pidfd)
    sys.close(vm, pidfd)
    target:kill(); target:join()
    if not ok then error(err, 0) end
end

--- `fn(caller)` against a target whose DACL grants Everyone exactly
--- `mask`. The target lives for the call and no longer.
function M.against(t, vm, mask, fn, opts)
    M.with_target(vm, function(target, pidfd)
        M.set_dacl(vm, pidfd, mask)
        M.bound(t, vm, function(caller)
            fn(caller, M.pid(target), target)
        end, opts)
    end)
end

-- siginfo ------------------------------------------------------------------

--- Block `sig` in `who`, so a later delivery queues rather than being
--- taken by the default action.
function M.block_signal(who, sig)
    local set = string.pack("<I8", 1 << (sig - 1))
    return who:syscall(M.NR.rt_sigprocmask, {
        args = { 0, 0, 0, 8 },                 -- SIG_BLOCK
        bufs = { set, string.rep("\0", 8) },
        ptrs = { 1, 2 },
    })
end

--- Dequeue a pending blocked `sig` and decode the siginfo the sender
--- was stamped with. Returns `{signo, code, pid, uid}`, or nil, errno.
---
--- x86_64 siginfo_t: si_signo, si_errno, si_code, four bytes of
--- padding, then the kill union — si_pid at 16, si_uid at 20.
function M.await_signal(who, sig, seconds)
    local set = string.pack("<I8", 1 << (sig - 1))
    local r = who:syscall(M.NR.rt_sigtimedwait, {
        args = { 0, 0, 0, 8 },
        bufs = { set, string.rep("\0", 128),
                 string.pack("<i8i8", seconds or 1, 0) },
        ptrs = { 0, 1, 2 },
    })
    if r.ret < 0 then return nil, r.errno end
    local info = r.out_bufs[2]
    local signo, _, code = string.unpack("<i4i4i4", info)
    local pid, uid = string.unpack("<i4I4", info, 17)
    return { signo = signo, code = code, pid = pid, uid = uid }
end

-- The KMES process GUID ----------------------------------------------------

--- The process GUID a KMES event was stamped with, as hex.
function M.guid_hex(guid)
    return (guid:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

return M
