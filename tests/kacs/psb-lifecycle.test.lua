-- PKM §3.3.4 — what the PSB does across fork, exec and CLONE_THREAD,
-- and how it feeds AccessCheck.
--
-- The fork half is reachable: a worker is a process whose token a test
-- controls, and `worker:run_async` forks and execs a child from it. The
-- exec half is not. Witnessing it needs a process that survives its own
-- exec and can still be questioned, and the kernel-only profile carries
-- exactly one binary — the agent itself, which a worker-spawned child
-- runs with no connection back to the host. CLONE_THREAD is not in the
-- agent's protocol at all. Those cases name the KUnit case that drives
-- them instead.
--
-- The last case commits `pie` on the agent, which every worker created
-- afterwards inherits. It is deliberately the final case in the file.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local kmes = require("helpers.kmes")
local psb = require("helpers.psb")
local token = require("helpers.token")
local access = require("helpers.access")

local vm = provium:vm("v", "kernel-only"):boot()

local ENOEXEC = 8
local AGENT = "/sbin/provium-agent"
local ELF_DIR = "/mnt/psb-life-elf"
assert(kacs.new_mount(vm, "tmpfs", ELF_DIR, kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL))
assert(psb.write_elf(vm, ELF_DIR .. "/et-exec", psb.ET_EXEC).ret == 0)
assert(psb.write_elf(vm, ELF_DIR .. "/et-dyn", psb.ET_DYN).ret == 0)

test("the child's process GUID is kernel-generated, not copied from the parent",
    { spec = "PKM *psb.fork.new-guid" }, function(t)
        local child = vm:spawn_worker()
        local ok, err = pcall(function()
            local events = kmes.recording(t, vm, function()
                assert(kmes.emit(vm, "PIT_PSBF_P", kmes.PAYLOAD).ret == 0)
                assert(kmes.emit(child, "PIT_PSBF_C", kmes.PAYLOAD).ret == 0)
            end)
            local parent, kid
            for _, e in ipairs(events) do
                if e.type == "PIT_PSBF_P" then parent = e.process_guid end
                if e.type == "PIT_PSBF_C" then kid = e.process_guid end
            end
            t:assert(parent and kid, "the forking parent and its child each stamped an event")
            t:assert_neq(kid, parent, "the child's GUID is not the parent's: "
                .. psb.guid_hex(kid) .. " vs " .. psb.guid_hex(parent))
            t:assert_neq(kid, kmes.NULL_GUID, "and it is not the null GUID")
            t:assert_eq((kid:byte(7) & 0xF0) >> 4, 4, "it is a fresh version-4 UUID")
        end)
        child:kill(); child:join()
        if not ok then error(err, 0) end
    end)

-- ---- exec, threads and AccessCheck: deferred to the KUnit suite ------

test("the child's descriptor owner is the forking thread's primary token, not its impersonation token",
    { spec = "PKM *psb.fork.sd-owner-primary-token" }, function(t)
        -- A minted principal reaches the agent image only if its
        -- descriptor lets it, and SeChangeNotifyPrivilege carries it
        -- past traverse checking on the way.
        assert(kacs.set_sd(vm, AGENT, kacs.grant(kacs.ALL_RIGHTS)).ret == 0,
            "the agent image is reachable by a minted principal")
        local port = 7900

        --- Spawn from `worker` and read the child's process descriptor.
        --- Returns the parsed descriptor and the process, which the
        --- caller reaps — a `kill` is relayed through the worker, so it
        --- has to happen with the worker's credentials in a state that
        --- allows it.
        local function child_sd(worker)
            port = port + 1
            local proc = worker:run_async(AGENT, { "--port", tostring(port) })
            local pidfd = assert(psb.pidfd(vm, proc:pid()), "pidfd_open on the child")
            local bytes = assert(psb.get_sd(vm, pidfd, kacs.SI.OWNER | kacs.SI.DACL),
                "the child's process descriptor")
            sys.close(vm, pidfd)
            return access.parse_sd(bytes), proc
        end

        -- SeTcbPrivilege is what lets the principal open the
        -- LogonSession the second identity lives in; SeCreateTokenPrivilege
        -- and SeImpersonatePrivilege let it mint that identity and wear
        -- it; SeChangeNotifyPrivilege is for the walk to the image.
        local privs = token.bit(token.PRIV.TCB) | token.bit(token.PRIV.CREATE_TOKEN)
            | token.bit(token.PRIV.IMPERSONATE) | token.bit(token.PRIV.CHANGE_NOTIFY)
        token.as_principal(t, vm, { privs_present = privs, privs_enabled = privs }, function(w)
            -- Not impersonating: the owner is the principal's own SID.
            local plain, p1 = child_sd(w)
            p1:kill(); p1:wait("5s")
            t:assert_eq(plain.owner, token.SID.TEST_USER, "a plain fork's child is owned by the forker")
            t:assert(plain.dacl and plain.dacl.count > 0, "with a DACL from the default template")

            -- Impersonating another user at the moment of the fork.
            local client = assert(token.mint(w, { user_sid = token.SID.TEST_USER_2, projected_uid = 1102 }))
            local imp = assert(token.duplicate(w, client, { token_type = token.TYPE.IMPERSONATION,
                impersonation_level = token.LEVEL.IMPERSONATION }))
            t:assert_eq(token.impersonate(w, imp).ret, 0, "the forking thread impersonates TEST_USER_2")
            t:assert_eq(assert(token.effective(vm, w)).user, token.SID.TEST_USER_2,
                "and is running as it at the moment of the fork")
            local under, p2 = child_sd(w)
            token.revert(w)
            p2:kill(); p2:wait("5s")
            t:assert_eq(under.owner, token.SID.TEST_USER,
                "the child is still owned by the forking thread's primary token")
            t:assert_neq(under.owner, token.SID.TEST_USER_2, "not by the impersonation token")
            t:assert(under.dacl and under.dacl.count > 0, "and the DACL still follows the default template")
        end)
    end)

test("exec resets the PIP fields from the new binary's signature",
    { spec = "PKM *psb.exec.pip-reset-from-binary",
      covered_by = "kunit:pkm_kunit_process",
      skip = "the profile carries no signed binary, so no guest exec can " ..
             "move pip_type in either direction; runs under " ..
             "pkm_kunit_exec_pip_unsigned_commit_clears_existing_pip and " ..
             "pkm_kunit_exec_pip_signed_material_sets_tcb_trust" },
    function(t) end)

test("the mitigation flags are not reset at exec",
    { spec = "PKM *psb.exec.mitigations-persist",
      covered_by = "kunit:pkm_kunit_process",
      skip = "witnessing persistence needs a process that survives its " ..
             "own exec and can still be questioned, and the only " ..
             "executable image here is the agent itself; runs under " ..
             "pkm_kunit_exec_commit_preserves_mitigations_and_no_child" },
    function(t) end)

test("no_child_process persists across exec",
    { spec = "PKM *psb.exec.no-child-process-persists",
      covered_by = "kunit:pkm_kunit_process",
      skip = "same reach as the mitigations: nothing the guest can exec " ..
             "answers afterwards; runs under " ..
             "pkm_kunit_exec_commit_preserves_mitigations_and_no_child" },
    function(t) end)

test("the process GUID is not reset at exec: it identifies the process, not the binary",
    { spec = "PKM *psb.exec.guid-preserved",
      skip = "no coverage anywhere: process_guid is exposed nowhere but the " ..
             "stamp on a KMES event a process emits itself — the KACS " ..
             "syscall range (§3.A) carries no PSB query, so a pidfd cannot " ..
             "be asked for one — and no process here can be questioned " ..
             "either side of its own exec: a worker has already exec'd by " ..
             "the time the harness can speak to it, and the child a worker " ..
             "spawns is a fresh agent with no connection back. " ..
             "pkm_kunit_exec_commit_preserves_mitigations_and_no_child " ..
             "compares the process_sd and rate-bucket pointers across the " ..
             "exec commit without comparing process_guid — a " ..
             "pkm_kunit_expect_guid_eq on that case would close it" },
    function(t) end)

test("the process descriptor is preserved unchanged across exec",
    { spec = "PKM *psb.exec.sd-preserved",
      covered_by = "kunit:pkm_kunit_process",
      skip = "the exec commit is only observable from inside the kernel " ..
             "here; runs under " ..
             "pkm_kunit_exec_commit_preserves_mitigations_and_no_child, " ..
             "which asserts the descriptor pointer is the same object " ..
             "before and after" },
    function(t) end)

test("threads created with CLONE_THREAD share the process's PSB",
    { spec = "PKM *psb.clone-thread.shares-psb",
      covered_by = "kunit:pkm_kunit_process",
      skip = "the agent protocol offers no thread-creation primitive and " ..
             "no way to address one thread of a worker, so a shared-PSB " ..
             "observation cannot be attributed to a thread rather than " ..
             "the process; runs under " ..
             "pkm_kunit_process_state_clone_thread_shares_live_object" },
    function(t) end)

test("AccessCheck's PIP step reads pip_type and pip_trust from the PSB, not from a token",
    { spec = "PKM *psb.accesscheck.pip-from-psb",
      covered_by = "kunit:pkm_kunit_process",
      skip = "telling the PSB apart from the effective token as the " ..
             "source needs a non-zero pip_type together with an " ..
             "impersonation, and pip_type is unreachable without a signed " ..
             "binary; runs under " ..
             "pkm_kunit_process_boundary_under_impersonation_uses_psb_pip" },
    function(t) end)

-- ---- last: this commits a mitigation on the agent ---------------------

test("the child inherits everything but the GUID: a mitigation set in the parent is already in force",
    { spec = "PKM *psb.fork.inherits-rest" }, function(t)
        -- Before: a freshly forked child rejects nothing at exec.
        local before = vm:spawn_worker()
        local ok, err = pcall(function()
            t:assert_eq(psb.execve(before, ELF_DIR .. "/et-exec"), ENOEXEC,
                "a child forked before the parent commits pie reaches the loader")
        end)
        before:kill(); before:join()
        if not ok then error(err, 0) end

        -- The parent commits a mitigation, and forks again.
        t:assert_eq(psb.commit(vm, psb.MIT.PIE), nil, "the parent commits pie")
        local after = vm:spawn_worker()
        ok, err = pcall(function()
            t:assert_eq(psb.execve(after, ELF_DIR .. "/et-exec"), sys.E.ACCES,
                "and the child it forks afterwards is born with it enforced")
            t:assert_eq(psb.execve(after, ELF_DIR .. "/et-dyn"), ENOEXEC,
                "with the mitigation doing exactly what it does in the parent")
            -- Inheritance is a copy, not a share: the child may add to it.
            t:assert_eq(psb.commit(after, psb.MIT.WXP), nil,
                "the child can commit a further mitigation of its own")
            t:assert_eq(psb.wx_refused(after), sys.E.ACCES, "which binds the child")
            t:assert_eq(psb.wx_refused(vm), nil, "and not the parent")
        end)
        after:kill(); after:join()
        if not ok then error(err, 0) end
    end)
