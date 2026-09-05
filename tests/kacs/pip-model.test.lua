-- PKM §3.7 — the PIP model: two independent checks, the dominance
-- arithmetic, what SeDebugPrivilege reaches, and what a self-directed
-- operation skips.
--
-- The fixture's one constraint, and it shapes every case here: PIP is
-- conferred only by a binary signature, the kernel holds no signing key
-- and the guest has no signed binary, so every process in this VM is
-- None/0. The *target* side of the dominance test is therefore
-- unreachable — nothing can be made protected.
--
-- Two things are reachable and between them they carry the model.
--
-- `kacs_access_check` takes `pip_type` and `pip_trust` as parameters, so
-- the comparison itself can be driven against a descriptor carrying a
-- process-trust-label ACE with any values a case likes. §3.8.7 owns the
-- AccessCheck-side claims; §3.7 uses the syscall purely as a witness for
-- the arithmetic.
--
-- A *process* descriptor may carry a process-trust-label ACE too, and a
-- caller that fails it is refused inside the descriptor evaluation —
-- which §3.7's SeDebugPrivilege paragraph names explicitly as the first
-- of the two structural places PIP short-circuits. That is the only PIP
-- refusal a guest can provoke against a live process, and it is what the
-- all-or-nothing and rescue cases use.
--
-- The `kacs:kacs_process_access` tracepoint is what makes the two checks
-- visible as two: a permitted cross-process operation emits
-- `reason=allow` twice, once from the descriptor evaluation and once
-- from the standalone dominance test that runs after it.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local access = require("helpers.access")
local psb = require("helpers.psb")
local pip = require("helpers.pip")
local signing = require("helpers.signing")

local vm = provium:vm("v", "kernel-only"):boot()

local EV = "kacs/kacs_process_access"

--- Every `kacs_process_access` verdict recorded across `fn`.
local function verdicts(fn)
    return signing.of(signing.trace(vm, { EV }, fn), "kacs_process_access")
end

--- The verdicts whose `desired` is exactly `mask`.
local function about(events, mask)
    local want = string.format("0x%x", mask)
    local out = {}
    for _, e in ipairs(events) do
        if e.desired == want then out[#out + 1] = e end
    end
    return out
end

--- The reasons of `events`, joined, for an assertion message.
local function reasons(events)
    local out = {}
    for _, e in ipairs(events) do out[#out + 1] = e.reason end
    return table.concat(out, ",")
end

-- Two checks -----------------------------------------------------------------

test("a process-to-process operation passes two independent checks, and both run",
    { spec = "PKM *pip.two-checks-both-required" }, function(t)
        pip.with_target(vm, function(target, pidfd, pid)
            pip.protect(vm, pidfd, pip.grant(pip.ALL_RIGHTS))
            -- A permitted existence probe. The descriptor evaluation
            -- reports allow, and the standalone dominance test that
            -- follows reports allow separately: two verdicts, one
            -- operation.
            local seen
            pip.bound(t, vm, function(w)
                seen = verdicts(function()
                    t:assert_eq(w:syscall(pip.NR.kill, pid, 0).ret, 0,
                        "the probe is permitted")
                end)
            end)
            local mine = about(seen, pip.RIGHT.QUERY_LIMITED)
            t:assert_eq(#mine, 2,
                "the operation produced two verdicts, not one: " ..
                reasons(mine))
            t:assert_eq(reasons(mine), "allow,allow",
                "the descriptor check and the dominance check both allowed")

            -- With the descriptor withholding the right, the operation
            -- is refused even though the target is unprotected and the
            -- dominance half would have passed.
            pip.protect(vm, pidfd,
                pip.grant(pip.ALL_RIGHTS & ~pip.RIGHT.QUERY_LIMITED))
            pip.bound(t, vm, function(w)
                t:assert_eq(w:syscall(pip.NR.kill, pid, 0).errno, sys.E.ACCES,
                    "the descriptor check alone failing refuses the operation")
            end)
        end)
    end)

test("the dominance test reads the PSBs and never the descriptor",
    { spec = "PKM *pip.dominance-independent-of-descriptor" }, function(t)
        pip.with_target(vm, function(target, pidfd, pid)
            -- A descriptor that grants nothing at all. A caller holding
            -- SeDebugPrivilege is rescued past it — and the operation
            -- then *succeeds*, which it could only do if the standalone
            -- dominance test that runs afterwards had a source of its
            -- own: the two PSBs. It had no descriptor left to consult.
            pip.protect(vm, pidfd, psb.deny_all())
            local seen
            pip.bound(t, vm, function(w)
                seen = verdicts(function()
                    t:assert_eq(w:syscall(pip.NR.kill, pid, 0).ret, 0,
                        "a caller with SeDebugPrivilege gets past the " ..
                        "empty descriptor")
                end)
            end, { keep = pip.SE_DEBUG })
            local mine = about(seen, pip.RIGHT.QUERY_LIMITED)
            t:assert_eq(reasons(mine), "debug-rescue,allow",
                "the descriptor granted nothing and was rescued; the " ..
                "dominance test allowed on its own")
            local dominance = mine[#mine]
            local ctype, ctrust = dominance:pair("caller_pip")
            local ttype, ttrust = dominance:pair("target_pip")
            t:assert_eq(ctype .. ":" .. ctrust, "0:0",
                "and it compared the caller's PSB fields")
            t:assert_eq(ttype .. ":" .. ttrust, "0:0",
                "against the target's PSB fields")
        end)
    end)

test("dominance compares both axes numerically, and needs both",
    { spec = "PKM *pip.dominance-both-axes" }, function(t)
        -- The dominance arithmetic is `caller.type >= label.type AND
        -- caller.trust >= label.trust`. No process here can be made
        -- protected, so the comparison is driven through AccessCheck's
        -- explicit pip parameters against a process-trust-label ACE —
        -- the same two-axis test, with values a guest can choose.
        local sd = pip.labelled(pip.PROTECTED, pip.PEIOS_TCB, 0)
        local cases = {
            { 0, 0, false, "None/0 dominates neither axis" },
            { pip.PROTECTED, pip.PEIOS_TCB, true, "equality on both axes dominates" },
            { pip.PROTECTED, pip.PEIOS_TCB - 1, false,
              "the type axis alone is not enough" },
            { pip.PROTECTED - 1, pip.PEIOS_TCB, false,
              "the trust axis alone is not enough" },
            { pip.PROTECTED + 1, pip.PEIOS_TCB + 1, true,
              "strictly greater on both axes dominates" },
            { 0xFFFFFFFF, pip.PEIOS_TCB, true,
              "the axes are plain unsigned integers, not closed enumerations" },
        }
        for _, c in ipairs(cases) do
            local r = access.check(vm, {
                sd = sd, desired = access.FILE_MAPPING.read,
                pip_type = c[1], pip_trust = c[2],
            })
            if c[3] then
                t:assert(r.ok, c[4] .. ": " .. sys.errname(r.errno))
            else
                t:assert(r.denied, c[4] .. " (got " .. sys.errname(r.errno) ..
                    ", granted " .. tostring(r.granted) .. ")")
            end
        end
    end)

test("an unprotected target is dominated by any caller",
    { spec = "PKM *pip.unprotected-target-always-dominated" }, function(t)
        pip.with_target(vm, function(target, pidfd, pid)
            pip.protect(vm, pidfd, pip.grant(pip.ALL_RIGHTS))
            local seen
            pip.bound(t, vm, function(w)
                seen = verdicts(function()
                    t:assert_eq(w:syscall(pip.NR.kill, pid, 0).ret, 0,
                        "the caller reaches the unprotected target")
                end)
            end)
            local mine = about(seen, pip.RIGHT.QUERY_LIMITED)
            local dominance = mine[#mine]
            t:assert(dominance, "a dominance verdict was recorded")
            local ttype, ttrust = dominance:pair("target_pip")
            t:assert_eq(ttype, 0, "the target's pip_type is None")
            local ctype, ctrust = dominance:pair("caller_pip")
            t:assert_eq(ctype, 0, "and the caller carries no trust of its own")
            t:assert_eq(ctrust, 0, "on either axis")
            t:assert_eq(dominance.reason, "allow",
                "yet the target is dominated: an unprotected target is " ..
                "universally accessible whatever the caller carries")
            t:assert_eq(ttrust, 0, "target pip_trust is 0")
        end)
    end)

test("a caller PIP refuses has no process access at all, whichever operation it tried",
    { spec = "PKM *pip.dominance-is-all-or-nothing" }, function(t)
        pip.with_target(vm, function(target, pidfd, pid)
            -- The DACL grants every process right; the trust label
            -- denies. Granularity lives in the descriptor and PIP is the
            -- all-or-nothing gate above it, so nothing at all gets
            -- through — not a signal, not a query, not metadata.
            pip.protect(vm, pidfd, pip.pip())
            pip.bound(t, vm, function(w)
                local ops = {
                    { "an existence probe", function() return w:syscall(pip.NR.kill, pid, 0) end },
                    { "a terminating signal", function() return w:syscall(pip.NR.kill, pid, 15) end },
                    { "an ignorable signal", function() return w:syscall(pip.NR.kill, pid, 28) end },
                    { "a job-control signal", function() return w:syscall(pip.NR.kill, pid, 18) end },
                    { "a scheduler query", function() return w:syscall(pip.NR.sched_getscheduler, pid) end },
                    { "a priority change", function() return w:syscall(pip.NR.setpriority, 0, pid, 5) end },
                    { "a capability query", function() return pip.capget(w, pid) end },
                    { "a resource-limit read", function() return pip.prlimit_read(w, pid) end },
                    { "a process-group query", function() return w:syscall(pip.NR.getpgid, pid) end },
                }
                for _, op in ipairs(ops) do
                    t:assert_eq(op[2]().errno, sys.E.ACCES,
                        op[1] .. " is refused")
                end
                t:assert_eq(select(2, token.pidfd_open(w, pid)), sys.E.ACCES,
                    "and so is opening a pidfd on it")
            end)
        end)
    end)

test("SeDebugPrivilege bypasses the descriptor check and never the PIP one",
    { spec = "PKM *pip.sedebug-bypasses-descriptor-only" }, function(t)
        pip.with_target(vm, function(target, pidfd, pid)
            -- A descriptor granting nothing: the privilege rescues it.
            pip.protect(vm, pidfd, psb.deny_all())
            pip.bound(t, vm, function(w)
                t:assert_eq(w:syscall(pip.NR.kill, pid, 0).errno, sys.E.ACCES,
                    "without the privilege an empty descriptor refuses")
            end)
            pip.bound(t, vm, function(w)
                t:assert_eq(w:syscall(pip.NR.kill, pid, 0).ret, 0,
                    "with it the descriptor denial is rescued")
            end, { keep = pip.SE_DEBUG })

            -- The same privilege against a PIP-label denial: the
            -- short-circuit is reached first and there is no rescue.
            pip.protect(vm, pidfd, pip.pip())
            local seen
            pip.bound(t, vm, function(w)
                seen = verdicts(function()
                    t:assert_eq(w:syscall(pip.NR.kill, pid, 0).errno,
                        sys.E.ACCES,
                        "a PIP-label denial is not rescued by the privilege")
                end)
            end, { keep = pip.SE_DEBUG })
            local mine = about(seen, pip.RIGHT.QUERY_LIMITED)
            t:assert_eq(reasons(mine), "pip-denied",
                "the PIP denial short-circuits before the debug rescue " ..
                "is reached")
            -- Even the agent, which is SYSTEM and holds every privilege
            -- there is, does not get past it.
            t:assert_eq(vm:syscall(pip.NR.kill, pid, 0).errno, sys.E.ACCES,
                "and neither does a caller holding every privilege")
        end)
    end)

test("PIP reads the PSB, never the effective token",
    { spec = "PKM *pip.impersonation.reads-psb-not-token",
      covered_by = "kunit:pkm_kunit_process",
      skip = "every process here carries None/0, so a token impersonated " ..
             "across a process boundary cannot differ from the PSB in any " ..
             "PIP dimension — there is no protected PSB to read instead " ..
             "of, and no token that carries PIP at all; runs under " ..
             "pkm_kunit_process_boundary_under_impersonation_uses_psb_pip " ..
             "and pkm_kunit_access_check_psb_pip_unchanged_by_impersonation" },
    function(t) end)

-- Self-directed operations -------------------------------------------------

test("a self-directed operation is not a boundary crossing and skips both checks",
    { spec = "PKM *pip.self-directed-skips-checks" }, function(t)
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local pid = worker:syscall(sys.NR.getpid).ret
            local pidfd = assert(token.pidfd_open(vm, pid))
            -- The worker's own process descriptor grants nothing and
            -- carries a trust label it cannot satisfy; its token is the
            -- agent's minus every privilege that reaches past a
            -- descriptor. Nothing it does to itself is affected.
            pip.protect(vm, pidfd, pip.pip(pip.PROTECTED, pip.PEIOS_TCB, 0))
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

            local ops = {
                { "signalling itself", function() return worker:syscall(pip.NR.kill, pid, 28) end },
                { "probing its own existence", function() return worker:syscall(pip.NR.kill, pid, 0) end },
                { "reading its own capabilities", function() return pip.capget(worker, 0) end },
                { "reading its own resource limits", function() return pip.prlimit_read(worker, pid) end },
                { "changing its own priority", function() return worker:syscall(pip.NR.setpriority, 0, pid, 3) end },
                { "changing its own affinity", function() return pip.setaffinity(worker, 0, 1) end },
                { "reading its own process group", function() return worker:syscall(pip.NR.getpgid, 0) end },
            }
            for _, op in ipairs(ops) do
                t:assert_eq(op[2]().ret, 0, op[1] .. " is not a boundary " ..
                    "operation and is unaffected")
            end
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
    end)
