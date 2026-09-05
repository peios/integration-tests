-- PKM §3.3.3 — the process access rights: which operation each one
-- gates, and the three /proc entries that are not where their names
-- suggest.
--
-- Each case narrows a target process's DACL to a single Everyone ACE
-- and then drives the operation from a caller the DACL decides — the
-- agent's own principal minus the privileges that reach past a
-- descriptor, SeDebugPrivilege included (§3.3.3 says it rescues a
-- descriptor denial, so a caller holding it proves nothing about a
-- right). Caller and target share SYSTEM's user SID, so nothing Linux
-- decides on credential comparison can be mistaken for the descriptor
-- deciding.
--
-- Four cases here are tagged known-bug: the rights that gate the
-- ptrace-mode surfaces do not gate them from the guest. See the report.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local psb = require("helpers.psb")

local vm = provium:vm("v", "kernel-only"):boot()

local R = psb.RIGHT

--- Open one of the target's /proc entries and read from it. Returns
--- "ok", or the errno name of whichever of the two failed.
local function proc_read(who, pid, name, flags)
    local fd, errno = sys.open(who, "/proc/" .. pid .. "/" .. name,
        flags or sys.O.RDONLY)
    if not fd then return "open:" .. sys.errname(errno or 0) end
    local data, rerrno = sys.read(who, fd, 64)
    sys.close(who, fd)
    if not data then return "read:" .. sys.errname(rerrno or 0) end
    return "ok"
end

--- Run `fn(caller, pid)` against a target whose DACL grants Everyone
--- exactly `mask`.
local function against(t, mask, fn)
    psb.against(t, vm, mask, function(caller, pid) fn(caller, pid) end)
end

-- Signal-carrying rights ---------------------------------------------------

test("PROCESS_TERMINATE carries the signals whose default action is termination",
    { spec = "PKM *psb.right.terminate" }, function(t)
        against(t, psb.ALL_RIGHTS & ~R.TERMINATE, function(w, pid)
            t:assert_eq(w:syscall(psb.NR.kill, pid, 15).errno, sys.E.ACCES,
                "without it SIGTERM is refused")
            t:assert_eq(w:syscall(psb.NR.kill, pid, 9).errno, sys.E.ACCES,
                "and so is SIGKILL, which no handler could have caught")
            t:assert_eq(w:syscall(psb.NR.kill, pid, 28).ret, 0,
                "while an informational signal still goes through")
        end)
        against(t, R.TERMINATE, function(w, pid)
            t:assert_eq(w:syscall(psb.NR.kill, pid, 30).ret, 0,
                "with it alone a terminate-class signal is accepted")
            t:assert_eq(w:syscall(psb.NR.kill, pid, 28).errno, sys.E.ACCES,
                "but an informational one is not")
        end)
    end)

test("PROCESS_SIGNAL carries exactly the signals whose default action is to ignore",
    { spec = "PKM *psb.right.signal" }, function(t)
        against(t, R.SIGNAL, function(w, pid)
            for _, sig in ipairs(psb.SIGNAL.IGNORE) do
                t:assert_eq(w:syscall(psb.NR.kill, pid, sig).ret, 0,
                    psb.signame(sig) .. " goes through on PROCESS_SIGNAL alone")
            end
            t:assert_eq(w:syscall(psb.NR.kill, pid, 15).errno, sys.E.ACCES,
                "and it carries nothing that terminates")
        end)
        against(t, psb.ALL_RIGHTS & ~R.SIGNAL, function(w, pid)
            for _, sig in ipairs(psb.SIGNAL.IGNORE) do
                t:assert_eq(w:syscall(psb.NR.kill, pid, sig).errno, sys.E.ACCES,
                    psb.signame(sig) .. " is refused without it")
            end
        end)
    end)

test("PROCESS_SUSPEND_RESUME carries the signals whose default action stops or continues",
    { spec = "PKM *psb.right.suspend-resume" }, function(t)
        against(t, psb.ALL_RIGHTS & ~R.SUSPEND_RESUME, function(w, pid)
            t:assert_eq(w:syscall(psb.NR.kill, pid, 19).errno, sys.E.ACCES,
                "without it SIGSTOP is refused")
            t:assert_eq(w:syscall(psb.NR.kill, pid, 18).errno, sys.E.ACCES,
                "and so is SIGCONT")
        end)
        against(t, R.SUSPEND_RESUME, function(w, pid)
            t:assert_eq(w:syscall(psb.NR.kill, pid, 18).ret, 0,
                "with it alone SIGCONT is accepted")
            t:assert_eq(w:syscall(psb.NR.kill, pid, 15).errno, sys.E.ACCES,
                "and it carries nothing that terminates")
        end)
    end)

-- Inspection and mutation --------------------------------------------------

test("PROCESS_QUERY_LIMITED is what basic process information needs",
    { spec = "PKM *psb.right.query-limited" }, function(t)
        against(t, R.QUERY_LIMITED, function(w, pid)
            t:assert_eq(w:syscall(psb.NR.kill, pid, 0).ret, 0,
                "an existence probe succeeds")
            t:assert(psb.pidfd(w, pid), "pidfd_open() succeeds")
            t:assert_eq(w:syscall(psb.NR.getpgid, pid).ret >= 0, true,
                "the process group id is readable")
            t:assert_eq(proc_read(w, pid, "stat"), "ok", "/proc/<pid>/stat is readable")
        end)
        against(t, psb.ALL_RIGHTS & ~R.QUERY_LIMITED, function(w, pid)
            t:assert_eq(w:syscall(psb.NR.kill, pid, 0).errno, sys.E.ACCES,
                "without it the existence probe is refused")
            local fd, errno = psb.pidfd(w, pid)
            t:assert(not fd, "pidfd_open() is refused")
            t:assert_eq(errno, sys.E.ACCES, "with EACCES")
            t:assert_eq(w:syscall(psb.NR.getpgid, pid).errno, sys.E.ACCES,
                "the process group id is not readable")
            t:assert_eq(proc_read(w, pid, "stat"), "read:EACCES (13)",
                "and neither is /proc/<pid>/stat")
        end)
    end)

test("PROCESS_QUERY_INFORMATION is what detailed inspection needs",
    { spec = "PKM *psb.right.query-information" }, function(t)
        local function capget(w, pid)
            return w:syscall(psb.NR.capget, {
                args = { 0, 0 },
                bufs = { string.pack("<I4i4", 0x20080522, pid), string.rep("\0", 24) },
                ptrs = { 0, 1 },
            })
        end
        against(t, R.QUERY_INFORMATION, function(w, pid)
            t:assert_eq(w:syscall(psb.NR.sched_getscheduler, pid).ret >= 0, true,
                "detailed scheduler state is readable")
            t:assert_eq(capget(w, pid).ret, 0,
                "compatibility capability state is readable through capget(pid)")
            for _, name in ipairs({ "cmdline", "status", "limits" }) do
                t:assert_eq(proc_read(w, pid, name), "ok",
                    "/proc/<pid>/" .. name .. " is readable")
            end
        end)
        against(t, psb.ALL_RIGHTS & ~R.QUERY_INFORMATION, function(w, pid)
            t:assert_eq(w:syscall(psb.NR.sched_getscheduler, pid).errno, sys.E.ACCES,
                "without it the scheduler state is refused")
            t:assert_eq(capget(w, pid).errno, sys.E.ACCES, "capget(pid) is refused")
            for _, name in ipairs({ "cmdline", "status", "limits" }) do
                t:assert_eq(proc_read(w, pid, name), "read:EACCES (13)",
                    "/proc/<pid>/" .. name .. " is refused")
            end
        end)
    end)

test("PROCESS_SET_INFORMATION is what changing a process's attributes needs",
    { spec = "PKM *psb.right.set-information" }, function(t)
        against(t, R.SET_INFORMATION, function(w, pid)
            t:assert_eq(w:syscall(psb.NR.setpriority, 0, pid, 5).ret, 0,
                "with it the target's scheduling priority may be changed")
        end)
        against(t, psb.ALL_RIGHTS & ~R.SET_INFORMATION, function(w, pid)
            t:assert_eq(w:syscall(psb.NR.setpriority, 0, pid, 5).errno, sys.E.ACCES,
                "without it the change is refused")
        end)
    end)

test("cgroup sits in the PROCESS_QUERY_LIMITED set, not the detailed one",
    { spec = "PKM *psb.proc.cgroup-in-query-limited" }, function(t)
        against(t, R.QUERY_LIMITED, function(w, pid)
            t:assert_eq(proc_read(w, pid, "cgroup"), "ok",
                "cgroup reads on PROCESS_QUERY_LIMITED alone")
            t:assert_eq(proc_read(w, pid, "cmdline"), "read:EACCES (13)",
                "while a genuinely detailed entry does not")
        end)
        against(t, psb.ALL_RIGHTS & ~R.QUERY_LIMITED, function(w, pid)
            t:assert_eq(proc_read(w, pid, "cgroup"), "read:EACCES (13)",
                "and it is refused when that right is the one withheld")
        end)
        against(t, psb.ALL_RIGHTS & ~R.QUERY_INFORMATION, function(w, pid)
            t:assert_eq(proc_read(w, pid, "cgroup"), "ok",
                "withholding PROCESS_QUERY_INFORMATION does not reach it")
        end)
    end)

-- The ptrace-mode surfaces -------------------------------------------------

test("PROCESS_VM_READ is what reading another process's memory needs",
    { spec = "PKM *psb.right.vm-read", tags = { "known-bug" } }, function(t)
        against(t, R.VM_READ, function(w, pid)
            local fd, errno = sys.open(w, "/proc/" .. pid .. "/mem", sys.O.RDONLY)
            t:assert(fd, "with it /proc/<pid>/mem opens for reading: "
                .. sys.errname(errno or 0))
            if fd then sys.close(w, fd) end
        end)
        against(t, psb.ALL_RIGHTS & ~R.VM_READ, function(w, pid)
            local fd, errno = sys.open(w, "/proc/" .. pid .. "/mem", sys.O.RDONLY)
            if fd then sys.close(w, fd) end
            t:assert(not fd, "without it the read-only open is refused")
            t:assert_eq(errno, sys.E.ACCES, "with EACCES")
        end)
    end)

test("PROCESS_VM_WRITE is what writing another process's memory needs",
    { spec = "PKM *psb.right.vm-write", tags = { "known-bug" } }, function(t)
        against(t, psb.ALL_RIGHTS, function(w, pid)
            local fd, errno = sys.open(w, "/proc/" .. pid .. "/mem", sys.O.RDWR)
            t:assert(fd, "with every process right granted /proc/<pid>/mem "
                .. "opens for writing: " .. sys.errname(errno or 0))
            if fd then sys.close(w, fd) end
        end)
        against(t, psb.ALL_RIGHTS & ~R.VM_WRITE, function(w, pid)
            local fd, errno = sys.open(w, "/proc/" .. pid .. "/mem", sys.O.RDWR)
            if fd then sys.close(w, fd) end
            t:assert(not fd, "without it the writable open is refused")
            t:assert_eq(errno, sys.E.ACCES, "with EACCES")
        end)
    end)

test("PROCESS_DUP_HANDLE is what extracting a descriptor through pidfd_getfd needs",
    { spec = "PKM *psb.right.dup-handle", tags = { "known-bug" } }, function(t)
        psb.with_target(vm, function(target, pidfd)
            local victim = sys.pipe(target)
            t:assert(victim, "the target holds a descriptor to extract")
            psb.set_dacl(vm, pidfd, psb.ALL_RIGHTS)
            psb.bound(t, vm, function(w)
                local pf = assert(psb.pidfd(w, psb.pid(target)))
                local r = w:syscall(psb.NR.pidfd_getfd, pf, victim, 0)
                t:assert(r.ret >= 0, "with PROCESS_DUP_HANDLE granted the "
                    .. "descriptor is extracted: " .. sys.errname(r.errno))
                if r.ret >= 0 then sys.close(w, r.ret) end
                sys.close(w, pf)
            end)
            psb.set_dacl(vm, pidfd, psb.ALL_RIGHTS & ~psb.RIGHT.DUP_HANDLE)
            psb.bound(t, vm, function(w)
                local pf = assert(psb.pidfd(w, psb.pid(target)))
                local r = w:syscall(psb.NR.pidfd_getfd, pf, victim, 0)
                t:assert(r.ret < 0, "and without it the extraction is refused")
                t:assert_eq(r.errno, sys.E.PERM,
                    "with " .. sys.errname(r.errno))
                sys.close(w, pf)
            end)
        end)
    end)

test("maps, fd and environ keep their PTRACE_MODE_READ gating, which is PROCESS_VM_READ",
    { spec = "PKM *psb.proc.maps-fd-environ-are-vm-read", tags = { "known-bug" } },
    function(t)
        against(t, psb.ALL_RIGHTS & ~R.VM_READ, function(w, pid)
            for _, name in ipairs({ "maps", "environ" }) do
                t:assert_eq(proc_read(w, pid, name), "open:EACCES (13)",
                    "/proc/<pid>/" .. name .. " is refused without PROCESS_VM_READ")
            end
            local fd, errno = sys.open(w, "/proc/" .. pid .. "/fd",
                sys.O.RDONLY | sys.O.DIRECTORY)
            if fd then sys.close(w, fd) end
            t:assert(not fd, "and so is /proc/<pid>/fd")
            t:assert_eq(errno, sys.E.ACCES, "with EACCES")
        end)
        against(t, R.VM_READ, function(w, pid)
            t:assert_eq(proc_read(w, pid, "maps"), "ok",
                "PROCESS_VM_READ alone is enough for maps")
            t:assert_eq(proc_read(w, pid, "cmdline"), "read:EACCES (13)",
                "and it is not PROCESS_QUERY_INFORMATION that carries them")
        end)
    end)
