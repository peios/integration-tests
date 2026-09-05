-- PKM §3.3.3 — the process security descriptor itself: the generic
-- mapping, the template every process is created with, what modifying
-- it costs, and the one privilege that rescues a denial.
--
-- The descriptor is read and written through kacs_get_sd / kacs_set_sd
-- with an empty path, AT_EMPTY_PATH and a pidfd in the dirfd slot.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local access = require("helpers.access")
local token = require("helpers.token")
local psb = require("helpers.psb")

local vm = provium:vm("v", "kernel-only"):boot()

local R = psb.RIGHT
local GENERIC_ALL = 0x10000000

--- The parsed descriptor of the process behind `pidfd`.
local function descriptor_of(t, pidfd)
    local bytes, errno = psb.get_sd(vm, pidfd)
    t:assert(bytes, "the process descriptor reads back: " .. sys.errname(errno or 0))
    return token.parse_sd(bytes)
end

test("the process generic mapping folds each generic right onto the documented set",
    { spec = "PKM *psb.generic-mapping" }, function(t)
        local function against(mask, fn)
            psb.against(t, vm, mask, function(caller, pid) fn(caller, pid) end)
        end
        -- GENERIC_EXECUTE = TERMINATE | SUSPEND_RESUME | QUERY_LIMITED.
        against(access.STD.GENERIC_EXECUTE, function(w, pid)
            t:assert_eq(w:syscall(psb.NR.kill, pid, 0).ret, 0,
                "GENERIC_EXECUTE carries PROCESS_QUERY_LIMITED")
            t:assert_eq(w:syscall(psb.NR.kill, pid, 18).ret, 0,
                "and PROCESS_SUSPEND_RESUME")
            t:assert_eq(w:syscall(psb.NR.kill, pid, 30).ret, 0, "and PROCESS_TERMINATE")
            t:assert_eq(w:syscall(psb.NR.kill, pid, 28).errno, sys.E.ACCES,
                "but not PROCESS_SIGNAL")
            t:assert_eq(w:syscall(psb.NR.sched_getscheduler, pid).errno, sys.E.ACCES,
                "nor PROCESS_QUERY_INFORMATION")
            t:assert_eq(w:syscall(psb.NR.setpriority, 0, pid, 5).errno, sys.E.ACCES,
                "nor PROCESS_SET_INFORMATION")
        end)
        -- GENERIC_READ = QUERY_INFORMATION | VM_READ | READ_CONTROL.
        against(access.STD.GENERIC_READ, function(w, pid)
            t:assert_eq(w:syscall(psb.NR.sched_getscheduler, pid).ret >= 0, true,
                "GENERIC_READ carries PROCESS_QUERY_INFORMATION")
            t:assert_eq(w:syscall(psb.NR.kill, pid, 0).errno, sys.E.ACCES,
                "but not PROCESS_QUERY_LIMITED")
            t:assert_eq(w:syscall(psb.NR.setpriority, 0, pid, 5).errno, sys.E.ACCES,
                "nor PROCESS_SET_INFORMATION")
        end)
        -- GENERIC_WRITE = SET_INFORMATION | VM_WRITE | WRITE_DAC.
        against(access.STD.GENERIC_WRITE, function(w, pid)
            t:assert_eq(w:syscall(psb.NR.setpriority, 0, pid, 5).ret, 0,
                "GENERIC_WRITE carries PROCESS_SET_INFORMATION")
            t:assert_eq(w:syscall(psb.NR.sched_getscheduler, pid).errno, sys.E.ACCES,
                "but not PROCESS_QUERY_INFORMATION")
            t:assert_eq(w:syscall(psb.NR.kill, pid, 15).errno, sys.E.ACCES,
                "nor PROCESS_TERMINATE")
        end)
        -- GENERIC_ALL = every process right above.
        against(access.STD.GENERIC_ALL, function(w, pid)
            t:assert_eq(w:syscall(psb.NR.kill, pid, 0).ret, 0, "GENERIC_ALL carries the probe")
            t:assert_eq(w:syscall(psb.NR.kill, pid, 28).ret, 0, "PROCESS_SIGNAL")
            t:assert_eq(w:syscall(psb.NR.sched_getscheduler, pid).ret >= 0, true,
                "PROCESS_QUERY_INFORMATION")
            t:assert_eq(w:syscall(psb.NR.setpriority, 0, pid, 5).ret, 0,
                "and PROCESS_SET_INFORMATION")
        end)
    end)

test("every process is created with the default descriptor template",
    { spec = "PKM *psb.sd.default-template" }, function(t)
        psb.with_target(vm, function(target, pidfd)
            local sd = descriptor_of(t, pidfd)
            -- Owner and group come from the creating thread's primary
            -- token; the agent is SYSTEM in Administrators.
            t:assert_eq(sd.owner, token.SID.LOCAL_SYSTEM,
                "the owner is the creator's primary token user SID")
            t:assert_eq(sd.group, token.SID.ADMINISTRATORS,
                "the group is that token's primary group SID")
            t:assert_eq(#sd.dacl, 4, "the DACL holds four ACEs")
            for i, ace in ipairs(sd.dacl) do
                t:assert_eq(ace.type, kacs.ACE_ALLOWED, "ACE " .. i .. " is an allow ACE")
            end
            t:assert_eq(sd.dacl[1].sid, token.SID.LOCAL_SYSTEM,
                "the first names the process's own user SID")
            t:assert_eq(sd.dacl[1].mask, GENERIC_ALL, "at GENERIC_ALL")
            t:assert_eq(sd.dacl[2].sid, token.SID.ADMINISTRATORS, "then Administrators")
            t:assert_eq(sd.dacl[2].mask, GENERIC_ALL, "at GENERIC_ALL")
            t:assert_eq(sd.dacl[3].sid, token.SID.LOCAL_SYSTEM, "then SYSTEM")
            t:assert_eq(sd.dacl[3].mask, GENERIC_ALL, "at GENERIC_ALL")
            t:assert_eq(sd.dacl[4].sid, token.SID.EVERYONE, "and finally Everyone")
            t:assert_eq(sd.dacl[4].mask, R.QUERY_LIMITED, "at PROCESS_QUERY_LIMITED only")

            -- What the template means for an unrelated principal: basic
            -- information yes, detailed inspection no.
            token.as_principal(t, vm, { user_sid = token.SID.TEST_USER }, function(other)
                local pid = psb.pid(target)
                t:assert_eq(other:syscall(psb.NR.kill, pid, 0).ret, 0,
                    "any principal can see that the process exists")
                t:assert(psb.pidfd(other, pid), "and open a pidfd on it")
                t:assert_eq(other:syscall(psb.NR.sched_getscheduler, pid).errno,
                    sys.E.ACCES, "but not inspect it in detail")
                t:assert_eq(other:syscall(psb.NR.kill, pid, 15).errno, sys.E.ACCES,
                    "and not terminate it")
            end)
        end)
    end)

test("a custom descriptor cannot be requested at launch: creation always builds the template",
    { spec = "PKM *psb.sd.no-custom-at-launch" }, function(t)
        psb.with_target(vm, function(first, first_pidfd)
            local a = descriptor_of(t, first_pidfd)
            t:assert_eq(#a.dacl, 4, "the first process starts from the template")
            -- Replace it with something a launcher might have wanted.
            psb.set_dacl(vm, first_pidfd, R.QUERY_LIMITED)
            t:assert_eq(#descriptor_of(t, first_pidfd).dacl, 1,
                "and a subsequent write replaces it")
            -- The next process created by the same creator is unaffected:
            -- creation has no descriptor input to carry the deviation.
            psb.with_target(vm, function(second, second_pidfd)
                local b = descriptor_of(t, second_pidfd)
                t:assert_eq(#b.dacl, 4, "the next process still starts from the template")
                t:assert_eq(b.owner, a.owner, "with the same owner")
                t:assert_eq(b.dacl[4].sid, token.SID.EVERYONE, "and the same trailing ACE")
                t:assert_eq(b.dacl[4].mask, R.QUERY_LIMITED, "at the same mask")
            end)
        end)
    end)

test("kacs_set_sd on a process descriptor requires WRITE_DAC",
    { spec = "PKM *psb.sd.set-sd-requires-write-dac" }, function(t)
        -- A target owned by someone else, so the caller gets nothing but
        -- what the DACL says.
        token.as_principal(t, vm, { user_sid = token.SID.TEST_USER }, function(target)
            local pid = psb.pid(target)
            local pidfd = assert(psb.pidfd(vm, pid))
            local ok, err = pcall(function()
                -- The process itself holds WRITE_DAC through the default
                -- template's own-user ACE, which is what §3.3.3 says makes
                -- a service able to narrow itself at runtime.
                t:assert_eq(psb.set_sd(target, assert(psb.pidfd(target, pid)),
                    psb.grant(psb.ALL_RIGHTS), kacs.SI.DACL).ret, 0,
                    "the process can rewrite its own descriptor")

                psb.set_dacl(vm, pidfd, psb.ALL_RIGHTS & ~R.WRITE_DAC)
                psb.bound(t, vm, function(w)
                    local pf = assert(psb.pidfd(w, pid))
                    local r = psb.set_sd(w, pf, psb.grant(psb.ALL_RIGHTS), kacs.SI.DACL)
                    t:assert(r.ret ~= 0, "a caller without WRITE_DAC cannot rewrite it")
                    t:assert_eq(r.errno, sys.E.ACCES, "with EACCES")
                    sys.close(w, pf)
                end)

                psb.set_dacl(vm, pidfd, psb.ALL_RIGHTS)
                psb.bound(t, vm, function(w)
                    local pf = assert(psb.pidfd(w, pid))
                    local r = psb.set_sd(w, pf, psb.grant(psb.ALL_RIGHTS), kacs.SI.DACL)
                    t:assert_eq(r.ret, 0, "and with it granted the write succeeds: "
                        .. sys.errname(r.errno))
                    sys.close(w, pf)
                end)
            end)
            sys.close(vm, pidfd)
            if not ok then error(err, 0) end
        end)
    end)

test("an enabled SeDebugPrivilege rescues a descriptor denial and is marked used",
    { spec = "PKM *psb.sd.sedebug-overrides-denial" }, function(t)
        psb.with_target(vm, function(target, pidfd)
            local pid = psb.pid(target)
            -- A descriptor that is present and empty denies everyone.
            local r = psb.set_sd(vm, pidfd, psb.deny_all(), kacs.SI.DACL)
            t:assert_eq(r.ret, 0, "the target denies everyone: " .. sys.errname(r.errno))

            psb.bound(t, vm, function(w)
                t:assert_eq(w:syscall(psb.NR.kill, pid, 0).errno, sys.E.ACCES,
                    "a caller without the privilege is refused")
                t:assert_eq(w:syscall(psb.NR.sched_getscheduler, pid).errno, sys.E.ACCES,
                    "on every right the descriptor withholds")
            end)

            psb.bound(t, vm, function(w)
                t:assert_eq(w:syscall(psb.NR.kill, pid, 0).ret, 0,
                    "a caller holding SeDebugPrivilege is granted the access anyway")
                t:assert_eq(w:syscall(psb.NR.sched_getscheduler, pid).ret >= 0, true,
                    "and the detailed inspection too")
                local own = assert(token.open_self(w, token.RIGHT.QUERY))
                local privs = assert(token.privileges(w, own))
                t:assert(privs.used & psb.SE_DEBUG ~= 0,
                    "the rescue is recorded in the token's used state")
                sys.close(w, own)
            end, { keep_debug = true })
        end)
    end)

-- ---- PIP-dependent, deferred to the KUnit suite ----------------------

test("the descriptor check and the PIP check both have to pass",
    { spec = "PKM *psb.pip.both-checks-must-pass",
      covered_by = "kunit:pkm_kunit_process",
      skip = "showing the two are independent needs a target with a " ..
             "non-zero pip_type, which requires a signed binary the " ..
             "profile does not carry; runs under " ..
             "pkm_kunit_signal_debug_still_fails_on_pip and " ..
             "pkm_kunit_process_pip_dominance_matrix" },
    function(t) end)
