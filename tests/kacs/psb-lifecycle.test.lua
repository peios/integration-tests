-- PKM §3.3.4 — what the PSB does across fork, exec and CLONE_THREAD,
-- and how it feeds AccessCheck.
--
-- Only the fork half is reachable from here. The exec half needs a
-- process that survives its exec and can be questioned afterwards, and
-- the kernel-only profile carries exactly one binary — the agent
-- itself, which cannot be re-exec'd without losing the connection that
-- would ask the question. CLONE_THREAD is not in the agent's protocol
-- at all. Those cases name the KUnit case that drives them instead.
--
-- The last case commits `pie` on the agent, which every worker created
-- afterwards inherits. It is deliberately the final case in the file.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local kmes = require("helpers.kmes")
local psb = require("helpers.psb")

local vm = provium:vm("v", "kernel-only"):boot()

local ENOEXEC = 8
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
    { spec = "PKM *psb.fork.sd-owner-primary-token",
      covered_by = "kunit:pkm_kunit_process",
      skip = "the impersonating half needs a process that impersonates " ..
             "and then forks; the agent cannot install a token on itself " ..
             "and a worker has no way to fork with the impersonation " ..
             "still in place; runs under " ..
             "pkm_kunit_process_state_fork_under_impersonation_uses_primary_sd" },
    function(t) end)

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
      skip = "no coverage anywhere: the guest cannot exec anything that " ..
             "survives to stamp a second KMES event, and " ..
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
