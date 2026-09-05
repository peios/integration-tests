-- PKM §3.7 — the PeiosTcb floor on kernel-initiated execs, trust
-- raising under a tracer or supervisor, the build-time hardening the
-- LSM refuses to start without, and coredumps.
--
-- The usermodehelper floor is the one part of §3.7 that gates execution
-- rather than labelling it, and it is fully reachable: `modprobe_path`
-- is a writable sysctl, so a case points it at a binary it authored and
-- provokes a `request_module()` — `mount()` with an unknown filesystem
-- type, or `socket()` with an unknown protocol family. The helper child
-- is exec'd at the kernel's own authority, the exec is refused, and the
-- `kacs:kacs_exec` tracepoint records `reason=umh-not-tcb` with the tier
-- it derived.
--
-- The trust-raising cases are the other side: a raise needs a signature,
-- and there is none, so only the non-raising arm is live. It is driven
-- under a genuine `LSM_UNSAFE_NO_NEW_PRIVS` exec — `prctl(PR_SET_NO_NEW_PRIVS)`
-- in a worker, then an exec from that worker — so the unsafe branch is
-- actually entered and is seen to leave the label alone.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local hooks = require("helpers.hooks")
local psb = require("helpers.psb")
local pip = require("helpers.pip")
local signing = require("helpers.signing")

local vm = provium:vm("v", "kernel-only"):boot()

local B = signing.workspace(vm, "umh")

--- The default `modprobe_path`, restored after every case that moves it.
local MODPROBE = "/proc/sys/kernel/modprobe"
local DEFAULT_MODPROBE = vm:read_file(MODPROBE):gsub("\n$", "")

--- Point `modprobe_path` at `path`, provoke a `request_module()`, and
--- return the `kacs_exec` events the helper's exec produced.
---
--- Two triggers, because a kernel that already knows the filesystem or
--- the protocol family would not ask: an unknown fstype
--- (`get_fs_type()`) and an unknown protocol family (`socket()`).
local function usermodehelper(path)
    vm:write_file(MODPROBE, path)
    local ok, events = pcall(signing.trace, vm, { signing.EV_EXEC }, function()
        sys.mount(vm, { source = "none", target = B, fstype = "nosuchfs" })
        vm:syscall(pip.NR.socket, 5, 2, 0)      -- AF_APPLETALK, unbuilt
        -- The helper runs on a kernel workqueue thread; give it a
        -- moment to be scheduled and reach the exec.
        sys.nanosleep(vm, 0, 300 * 1000 * 1000)
    end)
    -- Restore first: a raise inside the recording would otherwise leave
    -- the whole VM's module loader pointed at a test binary.
    vm:write_file(MODPROBE, DEFAULT_MODPROBE)
    if not ok then error(events, 0) end
    return signing.of(events, "kacs_exec")
end

--- The events of `list` whose reason is `reason`.
local function with_reason(list, reason)
    local out = {}
    for _, e in ipairs(list) do
        if e.reason == reason then out[#out + 1] = e end
    end
    return out
end

-- The PeiosTcb floor -----------------------------------------------------------

test("a binary the kernel execs on its own behalf must carry PeiosTcb trust",
    { spec = "PKM *pip.umh.peiostcb-floor" }, function(t)
        local helper = signing.place(vm, B .. "/helper",
            signing.craft({ no_sections = true }))
        -- The same binary, exec'd by a process rather than by the
        -- kernel, runs perfectly well: the floor is about who is behind
        -- the exec, not about the binary.
        t:assert_eq(vm:run(helper, {}).exit_code, 0,
            "an ordinary exec of the helper succeeds")

        local events = usermodehelper(helper)
        local refused = with_reason(events, "umh-not-tcb")
        t:assert(#refused > 0,
            "the kernel-initiated exec of the same binary was refused (saw " ..
            signing.reasons(events, "kacs_exec") .. ")")
        t:assert_eq(refused[1]:num("ret"), -13,
            "with EACCES")
        t:assert_eq(refused[1].verdict, "deny", "as a denial")
    end)

test("the floor refuses when no tier could be derived at all, not only when one graded too low",
    { spec = "PKM *pip.umh.refuses-underivable-tier" }, function(t)
        -- An unsigned helper: nothing was derived, so the trust value
        -- the floor compares is 0 because there was no answer, not
        -- because the answer was low. §3.7 says both reach the same
        -- refusal, and this is the "no answer" arm.
        local helper = signing.place(vm, B .. "/underivable",
            signing.craft({ no_sections = true }))
        local refused = with_reason(usermodehelper(helper), "umh-not-tcb")
        t:assert(#refused > 0, "the exec was refused")
        local ptype, ptrust = refused[1]:pair("exec_pip")
        t:assert_eq(ptype, 0, "no pip_type was established")
        t:assert_eq(ptrust, 0, "and no pip_trust: nothing was derived")

        -- The same with signing material present but unusable, so the
        -- lookup ran and still produced no tier.
        local bad = signing.place(vm, B .. "/underivable2",
            signing.craft({ no_sections = true }),
            { xattr = signing.blob({ fill = "\xBB" }) })
        local refused2 = with_reason(usermodehelper(bad), "umh-not-tcb")
        t:assert(#refused2 > 0,
            "a helper whose signature matches no key is refused too")
    end)

test("the usermodehelper mark is never cleared, so a #! helper stays under the floor",
    { spec = "PKM *pip.umh.mark-never-cleared" }, function(t)
        -- binfmt_script hands the interpreter to the next binfmt
        -- iteration without ever reaching bprm_creds_from_file, so the
        -- only exec the hook sees is the interpreter's — the *second*
        -- exec of the helper task. It is still refused.
        local interp = signing.place(vm, B .. "/interp",
            signing.craft({ no_sections = true }))
        local script = signing.place(vm, B .. "/script", "#!" .. interp .. "\n")
        local events = usermodehelper(script)
        local refused = with_reason(events, "umh-not-tcb")
        t:assert(#refused > 0,
            "the interpreter's exec is refused under the floor (saw " ..
            signing.reasons(events, "kacs_exec") .. ")")
        t:assert_eq(refused[1]:num("ret"), -13, "with EACCES")
    end)

test("a refusal emits kacs_exec with reason umh-not-tcb",
    { spec = "PKM *pip.umh.audit-reason" }, function(t)
        local helper = signing.place(vm, B .. "/audited",
            signing.craft({ no_sections = true }))
        local events = usermodehelper(helper)
        t:assert_contains(signing.reasons(events, "kacs_exec"), "umh-not-tcb",
            "the refusal is named rather than presenting as an " ..
            "unexplained module-load failure")
        -- And an ordinary exec of the same binary is not tagged that way.
        local ordinary = signing.exec_traced(vm, { signing.EV_EXEC }, helper)
        t:assert(not signing.reasons(ordinary, "kacs_exec"):find("umh-not-tcb",
            1, true),
            "an exec with a process behind it carries no such reason")
    end)

-- Trust raising under a tracer or supervisor -----------------------------------

test("dominance is tested when a tracer attaches and when a seccomp filter is installed, and not again",
    { spec = "PKM *pip.unsafe.dominance-tested-at-attach-only",
      covered_by = "kunit:pkm_kunit_process",
      skip = "the claim is about a process whose label rises after the " ..
             "attach, and a rise needs a signature that verifies — the " ..
             "kernel holds no signing key; runs under " ..
             "pkm_kunit_exec_pip_signed_material_sets_tcb_trust with " ..
             "pkm_kunit_ptrace_attach_success" },
    function(t) end)

test("under LSM_UNSAFE the staged label is capped at the process's current one",
    { spec = "PKM *pip.unsafe.label-capped",
      covered_by = "kunit:pkm_kunit_process",
      skip = "capping is only observable when the new label would be " ..
             "higher than the current one, which needs a binary that " ..
             "verifies; runs under pkm_kunit_exec_pip_signed_material_sets_tcb_trust " ..
             "(the cap arm of pkm_kacs_exec_pip_cap_for_unsafe)" },
    function(t) end)

test("an exec that does not raise the label is untouched by the unsafe rule",
    { spec = "PKM *pip.unsafe.non-raising-exec-untouched" }, function(t)
        -- A worker under no_new_privs, which is exactly the flag Linux
        -- marks as LSM_UNSAFE_NO_NEW_PRIVS, exec'ing an unsigned
        -- binary. The unsafe branch is entered and finds the new label
        -- dominated by the current one, so nothing is capped.
        local helper = signing.place(vm, B .. "/nnp",
            signing.craft({ no_sections = true }))
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            t:assert_eq(worker:syscall(pip.NR.prctl,
                pip.PR.SET_NO_NEW_PRIVS, 1, 0, 0, 0).ret, 0,
                "the worker sets no_new_privs")
            local events = signing.trace(vm, { signing.EV_EXEC }, function()
                t:assert_eq(worker:run(helper, {}).exit_code, 0,
                    "and execs an unsigned binary under it")
            end)
            local reasons = signing.reasons(events, "kacs_exec")
            t:assert_contains(reasons, "pip-committed",
                "the exec completed: " .. reasons)
            t:assert(not reasons:find("pip-capped-unsafe", 1, true),
                "and nothing was capped — the common case is untouched")
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
    end)

test("a cap emits kacs_exec with reason pip-capped-unsafe",
    { spec = "PKM *pip.unsafe.audit-reason",
      covered_by = "kunit:pkm_kunit_process",
      skip = "the event is emitted only when a cap happens, and a cap " ..
             "needs a label that would rise — which needs a verified " ..
             "signature; runs under the cap arm of " ..
             "pkm_kunit_exec_pip_signed_material_sets_tcb_trust" },
    function(t) end)

-- Raw physical memory and the init gate ----------------------------------------

test("KACS refuses to initialise without STRICT_DEVMEM and MODULE_SIG_FORCE",
    { spec = "PKM *pip.devmem.required-configs" }, function(t)
        -- `pkm_init()` returns -EINVAL before `security_add_hooks()`
        -- unless both are enabled, so KACS being *present* is the
        -- witness: the hooks could not be there otherwise.
        local path, err = hooks.hook_path(vm, "unused")
        t:assert(path, "securityfs is available: " .. tostring(err))
        local lsms = vm:read_file(hooks.SECURITYFS_AT .. "/lsm"):gsub("%s+$", "")
        t:assert_contains(lsms, "pkm",
            "pkm is in the active LSM list (" .. lsms .. "), so pkm_init() " ..
            "passed the build-hardening gate")
        -- And the hooks are live, not merely registered.
        t:assert(vm:syscall(kacs.SYS.OPEN_SELF_TOKEN, 0,
            kacs.TOKEN_ALL_ACCESS).ret >= 0,
            "and KACS is answering")
        -- /dev/mem exists, so the restriction is CONFIG_STRICT_DEVMEM's
        -- and not the node's absence.
        local st = sys.stat(vm, "/dev/mem")
        t:assert(st, "/dev/mem is present")
        t:assert(st.is_file == false, "as a device node")
    end)

test("the same gate refuses to coexist with another MAC or the BPF LSM",
    { spec = "PKM *pip.init.refuses-other-lsms" }, function(t)
        local path, err = hooks.hook_path(vm, "unused")
        t:assert(path, "securityfs is available: " .. tostring(err))
        local lsms = vm:read_file(hooks.SECURITYFS_AT .. "/lsm"):gsub("%s+$", "")
        t:assert_contains(lsms, "pkm", "pkm initialised (" .. lsms .. ")")
        for _, other in ipairs({ "selinux", "apparmor", "smack", "tomoyo", "bpf" }) do
            t:assert(not lsms:find(other, 1, true),
                other .. " is not present: pkm_init() would have refused " ..
                "to start beside it")
        end
    end)

test("nothing places a restrictive descriptor on /dev/mem or /dev/kmem",
    { spec = "PKM *pip.devmem.no-descriptor-protection" }, function(t)
        -- §3.7 says the secondary defence is not implemented and
        -- nothing handles those paths specially. They carry exactly the
        -- descriptor every other device node in the same directory has.
        local info = kacs.SI.OWNER | kacs.SI.GROUP | kacs.SI.DACL
        local mem = kacs.get_sd(vm, "/dev/mem", info)
        t:assert(mem, "/dev/mem has a descriptor")
        for _, peer in ipairs({ "/dev/null", "/dev/zero", "/dev/port" }) do
            local other = kacs.get_sd(vm, peer, info)
            t:assert(other, peer .. " has a descriptor")
            t:assert_eq(mem, other,
                "/dev/mem's descriptor is byte-identical to " .. peer ..
                "'s: it is not special-cased")
        end
        t:assert(not sys.stat(vm, "/dev/kmem"),
            "and /dev/kmem does not exist to be protected")
    end)

-- Coredumps -----------------------------------------------------------------------

test("a PIP-protected process has its dumpable flag cleared and cannot re-enable it",
    { spec = "PKM *pip.coredump.disabled-for-protected",
      covered_by = "kunit:pkm_kunit_process",
      skip = "the gate is `a process with a nonzero pip_type`, and no " ..
             "process in a keyless guest has one — every process here is " ..
             "None/0, for which prctl(PR_SET_DUMPABLE, 1) is correctly " ..
             "allowed; runs under pkm_kunit_task_prctl_pip_blocks_dumpable_reenable " ..
             "and pkm_kunit_exec_dumpable_signed_material_clears_if_mm" },
    function(t) end)

test("requests that keep or make a process non-dumpable are allowed",
    { spec = "PKM *pip.coredump.non-dumpable-requests-allowed",
      covered_by = "kunit:pkm_kunit_process",
      skip = "the allow-list only bites on a protected process; on an " ..
             "unprotected one every dumpable request is allowed anyway, " ..
             "so the distinction is not observable here; runs under " ..
             "pkm_kunit_task_prctl_pip_blocks_dumpable_reenable" },
    function(t) end)

test("a later exec assigning None/0 restores the normal Linux dumpability rules",
    { spec = "PKM *pip.coredump.unprotected-exec-restores-rules",
      covered_by = "kunit:pkm_kunit_process",
      skip = "the transition needs a process that was protected before " ..
             "the exec, which needs a verified signature; runs under " ..
             "pkm_kunit_exec_dumpable_decision_tracks_pip" },
    function(t) end)

test("no signed high-trust crash handler is implemented",
    { spec = "PKM *pip.coredump.no-crash-handler" }, function(t)
        -- §3.7 records the alternative as not implemented. Nothing in
        -- KACS's surface offers one: securityfs carries the token and
        -- session endpoints and nothing else, and core_pattern is
        -- Linux's own default, untouched by KACS.
        local path, err = hooks.hook_path(vm, "unused")
        t:assert(path, "securityfs is available: " .. tostring(err))
        local names = {}
        for _, e in ipairs(vm:listdir(hooks.SECURITYFS_AT .. "/kacs")) do
            names[#names + 1] = e.name
        end
        table.sort(names)
        t:assert_eq(table.concat(names, ","), "self,sessions",
            "KACS's securityfs surface offers no crash-handler endpoint")
        t:assert_eq(vm:read_file("/proc/sys/kernel/core_pattern"), "core\n",
            "and core_pattern is Linux's default: KACS installs no handler")
    end)
