-- PKM §3.3.3 — signal classification: each Linux signal maps to a
-- process access right by its default action, signal 0 is a probe
-- rather than a delivery, and kernel-originated delivery bypasses the
-- classification entirely.
--
-- Membership is established by withholding one right and watching the
-- whole class fail: that names every signal in the class without
-- delivering any of them, which matters when the class contains
-- SIGKILL. The one delivery these cases do perform is a SIGWINCH,
-- whose default action is to ignore, so that the siginfo the receiver
-- dequeues can be inspected.

local sys = require("helpers.sys")
local token = require("helpers.token")
local psb = require("helpers.psb")

local vm = provium:vm("v", "kernel-only"):boot()

local R = psb.RIGHT
local SIGWINCH, SIGCONT = 28, 18

-- Signals these cases may actually deliver. A membership case
-- establishes a class by withholding its right and watching every
-- member fail, so nothing in the terminate class is ever sent; and of
-- the suspend class only SIGCONT is, because a delivered SIGSTOP would
-- leave the target stopped and unreapable.
local DELIVERABLE_SUSPEND = { SIGCONT }

--- Run `fn(caller, pid)` against a target granting Everyone `mask`.
local function against(t, mask, fn)
    psb.against(t, vm, mask, function(caller, pid) fn(caller, pid) end)
end

--- Every signal in the three classes, plus the real-time range.
local function realtime()
    local out = {}
    for sig = psb.SIGRTMIN, psb.SIGRTMAX do out[#out + 1] = sig end
    return out
end

--- Assert that each signal in `sigs` is refused for `w` against `pid`.
local function all_refused(t, w, pid, sigs, why)
    for _, sig in ipairs(sigs) do
        t:assert_eq(w:syscall(psb.NR.kill, pid, sig).errno, sys.E.ACCES,
            psb.signame(sig) .. " " .. why)
    end
end

--- Assert that each signal in `sigs` is *not* refused for `w`.
local function none_refused(t, w, pid, sigs, why)
    for _, sig in ipairs(sigs) do
        t:assert_eq(w:syscall(psb.NR.kill, pid, sig).ret, 0,
            psb.signame(sig) .. " " .. why)
    end
end

test("a signal's required right follows its default action, not its number",
    { spec = "PKM *psb.signal.by-default-action" }, function(t)
        -- One representative per class, against each right in turn: the
        -- right that carries a signal is the one matching what the
        -- signal would do by default.
        local rep = { terminate = 15, suspend = 18, ignore = 28 }
        against(t, R.TERMINATE, function(w, pid)
            t:assert_eq(w:syscall(psb.NR.kill, pid, rep.suspend).errno, sys.E.ACCES,
                "SIGCONT does not travel on PROCESS_TERMINATE")
            t:assert_eq(w:syscall(psb.NR.kill, pid, rep.ignore).errno, sys.E.ACCES,
                "nor does SIGWINCH")
        end)
        against(t, R.SUSPEND_RESUME, function(w, pid)
            t:assert_eq(w:syscall(psb.NR.kill, pid, rep.terminate).errno, sys.E.ACCES,
                "SIGTERM does not travel on PROCESS_SUSPEND_RESUME")
            t:assert_eq(w:syscall(psb.NR.kill, pid, rep.ignore).errno, sys.E.ACCES,
                "nor does SIGWINCH")
            t:assert_eq(w:syscall(psb.NR.kill, pid, rep.suspend).ret, 0,
                "SIGCONT does")
        end)
        against(t, R.SIGNAL, function(w, pid)
            t:assert_eq(w:syscall(psb.NR.kill, pid, rep.terminate).errno, sys.E.ACCES,
                "SIGTERM does not travel on PROCESS_SIGNAL")
            t:assert_eq(w:syscall(psb.NR.kill, pid, rep.suspend).errno, sys.E.ACCES,
                "nor does SIGCONT")
            t:assert_eq(w:syscall(psb.NR.kill, pid, rep.ignore).ret, 0, "SIGWINCH does")
        end)
    end)

test("signal 0 is an existence and permission probe requiring PROCESS_QUERY_LIMITED",
    { spec = "PKM *psb.signal.zero-is-probe" }, function(t)
        against(t, R.QUERY_LIMITED, function(w, pid)
            t:assert_eq(w:syscall(psb.NR.kill, pid, 0).ret, 0,
                "kill(pid, 0) succeeds on PROCESS_QUERY_LIMITED alone")
            t:assert_eq(w:syscall(psb.NR.tgkill, pid, pid, 0).ret, 0,
                "and so does tgkill(tgid, tid, 0)")
            -- The right that carries the probe carries no delivery.
            t:assert_eq(w:syscall(psb.NR.kill, pid, 15).errno, sys.E.ACCES,
                "while nothing deliverable goes with it")
            t:assert_eq(w:syscall(psb.NR.kill, pid, 28).errno, sys.E.ACCES,
                "not even a signal whose default action is to ignore")
        end)
        against(t, psb.ALL_RIGHTS & ~R.QUERY_LIMITED, function(w, pid)
            t:assert_eq(w:syscall(psb.NR.kill, pid, 0).errno, sys.E.ACCES,
                "and withholding it refuses the probe")
            t:assert_eq(w:syscall(psb.NR.tgkill, pid, pid, 0).errno, sys.E.ACCES,
                "through tgkill too")
            t:assert_eq(w:syscall(psb.NR.kill, pid, 28).ret, 0,
                "even though every deliverable signal is still permitted")
        end)
    end)

test("PROCESS_TERMINATE's set is exactly the signals that terminate by default",
    { spec = "PKM *psb.signal.terminate-set" }, function(t)
        against(t, psb.ALL_RIGHTS & ~R.TERMINATE, function(w, pid)
            all_refused(t, w, pid, psb.SIGNAL.TERMINATE,
                "is refused when PROCESS_TERMINATE is the only right withheld")
            none_refused(t, w, pid, DELIVERABLE_SUSPEND, "is not in that set")
            none_refused(t, w, pid, psb.SIGNAL.IGNORE, "is not in that set either")
        end)
    end)

test("PROCESS_SUSPEND_RESUME's set is exactly the signals that stop or continue",
    { spec = "PKM *psb.signal.suspend-resume-set" }, function(t)
        against(t, psb.ALL_RIGHTS & ~R.SUSPEND_RESUME, function(w, pid)
            all_refused(t, w, pid, psb.SIGNAL.SUSPEND_RESUME,
                "is refused when PROCESS_SUSPEND_RESUME is the only right withheld")
            none_refused(t, w, pid, psb.SIGNAL.IGNORE, "is not in that set")
        end)
    end)

test("PROCESS_SIGNAL's set is exactly the three signals ignored by default",
    { spec = "PKM *psb.signal.ignore-set" }, function(t)
        against(t, psb.ALL_RIGHTS & ~R.SIGNAL, function(w, pid)
            all_refused(t, w, pid, psb.SIGNAL.IGNORE,
                "is refused when PROCESS_SIGNAL is the only right withheld")
            none_refused(t, w, pid, DELIVERABLE_SUSPEND, "is not in that set")
        end)
        against(t, R.SIGNAL, function(w, pid)
            none_refused(t, w, pid, psb.SIGNAL.IGNORE,
                "goes through on PROCESS_SIGNAL alone")
        end)
    end)

test("the real-time signals default to terminate and so require PROCESS_TERMINATE",
    { spec = "PKM *psb.signal.realtime-terminate" }, function(t)
        local rt = realtime()
        t:assert_eq(#rt, 33, "SIGRTMIN..SIGRTMAX is 32..64")
        against(t, psb.ALL_RIGHTS & ~R.TERMINATE, function(w, pid)
            all_refused(t, w, pid, rt,
                "is refused when PROCESS_TERMINATE is the only right withheld")
        end)
        against(t, R.TERMINATE, function(w, pid)
            -- One is enough to show the class travels on that right; the
            -- target is torn down straight afterwards either way.
            t:assert_eq(w:syscall(psb.NR.kill, pid, psb.SIGRTMIN).ret, 0,
                "and SIGRTMIN is accepted on PROCESS_TERMINATE alone")
        end)
    end)

test("si_uid in a delivered signal is the sender's projected UID, captured at send time",
    { spec = "PKM *psb.signal.si-uid-projected" }, function(t)
        local SENDER_UID = 4242
        psb.with_target(vm, function(target, pidfd)
            psb.set_dacl(vm, pidfd, R.SIGNAL | R.QUERY_LIMITED)
            -- Block it first, so the delivery queues rather than being
            -- taken by SIGWINCH's default action of ignoring it.
            t:assert_eq(psb.block_signal(target, SIGWINCH).ret, 0,
                "the receiver blocks SIGWINCH")
            local sender_pid
            token.as_principal(t, vm, {
                user_sid = token.SID.TEST_USER, projected_uid = SENDER_UID,
            }, function(sender)
                sender_pid = psb.pid(sender)
                t:assert_eq(sender:syscall(psb.NR.kill, psb.pid(target), SIGWINCH).ret, 0,
                    "a minted principal sends it")
            end)
            local info, errno = psb.await_signal(target, SIGWINCH)
            t:assert(info, "the receiver dequeues it: " .. sys.errname(errno or 0))
            t:assert_eq(info.signo, SIGWINCH, "the signal is the one that was sent")
            t:assert_eq(info.uid, SENDER_UID,
                "si_uid is the sender's projected UID, not the receiver's")
            t:assert_eq(info.pid, sender_pid, "and si_pid is the sender's pid")
        end)
    end)

-- ---- kernel-originated delivery, deferred to the KUnit suite ---------

test("kernel-generated signals bypass the process descriptor check",
    { spec = "PKM *psb.signal.kernel-generated-bypass",
      covered_by = "kunit:pkm_kunit_process",
      skip = "a kernel-originated delivery to another process cannot be " ..
             "provoked from the guest — every fault, SIGCHLD and SIGPIPE " ..
             "a test can cause is delivered to the process that caused " ..
             "it, where the same-process exemption decides first; runs " ..
             "under pkm_kunit_signal_kernel_originated_bypasses_checks " ..
             "and pkm_kunit_signal_origin_classification" },
    function(t) end)

test("terminal job-control signals are kernel-originated and bypass the check the same way",
    { spec = "PKM *psb.signal.tty-isig-bypass",
      covered_by = "kunit:pkm_kunit_process",
      skip = "the kernel-only profile has no controlling terminal and no " ..
             "pty to allocate, so the tty driver's isig path is " ..
             "unreachable; its SEND_SIG_PRIV origin is classified under " ..
             "pkm_kunit_signal_origin_classification" },
    function(t) end)
