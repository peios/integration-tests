-- PKM §3.3.2 — the PSB's fields: the process GUID fixed at fork, the
-- PIP identity the binary decides, what each mitigation means at its
-- own enforcement point, and the one-way process restriction.
--
-- Nothing reads the mitigation word back, so every case here proves a
-- bit by provoking what it governs: a W+X mapping for wxp, a
-- speculation prctl for sml, an exec for pie, a fork for
-- no_child_process. The GUID is readable, through the process_guid
-- KMES stamps on every event (PKM §2.A).
--
-- §3.3.2's activation rules are the neighbouring file,
-- psb-mitigations.test.lua.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local kmes = require("helpers.kmes")
local psb = require("helpers.psb")

local vm = provium:vm("v", "kernel-only"):boot()

local WRITE_EXEC = psb.PROT.READ | psb.PROT.WRITE | psb.PROT.EXEC
-- ENOEXEC: helpers/sys names the errnos the TRM names, and this one is
-- only ever the *absence* of a refusal — what exec reports once a
-- mitigation has let a header-only ELF through to the loader.
local ENOEXEC = 8

--- The GUID KMES stamps on an event emitted by `who`, as raw bytes.
--- Emits `count` events and returns the list of GUIDs it saw for `type`.
local function guids_of(t, tag, emitters)
    local events = kmes.recording(t, vm, function()
        for _, e in ipairs(emitters) do
            local r = kmes.emit(e.who, e.type, kmes.PAYLOAD)
            assert(r.ret == 0, "kmes_emit: " .. sys.errname(r.errno))
        end
    end)
    local out = {}
    for _, ev in ipairs(events) do
        if ev.type:sub(1, #tag) == tag then
            out[#out + 1] = { type = ev.type, guid = ev.process_guid }
        end
    end
    return out
end

--- The exec-time discriminator: /mnt/psb-elf holds a bare ELF header of
--- each type. Neither is loadable, so an exec that reaches the loader
--- fails ENOEXEC; a mitigation that rejects the binary first shows a
--- different errno.
local ELF_DIR = "/mnt/psb-fields-elf"
assert(kacs.new_mount(vm, "tmpfs", ELF_DIR, kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL))
assert(psb.write_elf(vm, ELF_DIR .. "/et-exec", psb.ET_EXEC).ret == 0)
assert(psb.write_elf(vm, ELF_DIR .. "/et-dyn", psb.ET_DYN).ret == 0)

--- Run `fn(worker)` in a fresh worker, tearing it down afterwards.
local function in_worker(fn)
    local w = vm:spawn_worker()
    local ok, err = pcall(fn, w)
    w:kill(); w:join()
    if not ok then error(err, 0) end
end

--- The errno a fork out of `w` fails with, or 0 when the fork itself
--- succeeded.
---
--- There is no fork primitive in the agent protocol, so this asks the
--- worker to run a binary that does not exist: the fork happens, the
--- exec then fails ENOENT. A fork the kernel refuses never reaches the
--- exec, and the errno is the refusal's.
local function fork_errno(w)
    local ok, err = pcall(function() w:run("/nonexistent-peios-binary") end)
    if ok then return 0 end
    local errno = tostring(err):match("errno (%d+)")
    assert(errno, "unrecognised run() failure: " .. tostring(err))
    errno = tonumber(errno)
    return errno == sys.E.NOENT and 0 or errno
end

-- Process identity ---------------------------------------------------------

test("every process gets a fresh process GUID at fork; it is not copied and never changes",
    { spec = "PKM *psb.guid.new-and-immutable" }, function(t)
        local a, b = vm:spawn_worker(), vm:spawn_worker()
        local ok, err = pcall(function()
            local seen = guids_of(t, "PIT_PSBG", {
                { who = vm, type = "PIT_PSBG_AGENT" },
                { who = a, type = "PIT_PSBG_A" },
                { who = b, type = "PIT_PSBG_B" },
                { who = a, type = "PIT_PSBG_A" },
            })
            t:assert_eq(#seen, 4, "four stamped events came back")
            local agent, a1, bb, a2 = seen[1].guid, seen[2].guid, seen[3].guid, seen[4].guid
            t:assert_neq(a1, kmes.NULL_GUID, "a process GUID is not the null GUID")
            t:assert_neq(a1, agent, "the child's GUID is not the forking parent's")
            t:assert_neq(bb, agent, "nor is its sibling's")
            t:assert_neq(a1, bb, "and the two children differ from each other")
            t:assert_eq(a1, a2, "a process keeps one GUID for its lifetime")
            -- UUID v4: version nibble 4, variant 10xx (PKM §3.A).
            t:assert_eq((a1:byte(7) & 0xF0) >> 4, 4,
                "the GUID is a version-4 UUID: " .. psb.guid_hex(a1))
            t:assert_eq((a1:byte(9) & 0xC0), 0x80, "carrying the RFC 4122 variant")
        end)
        a:kill(); a:join(); b:kill(); b:join()
        if not ok then error(err, 0) end
    end)

test("process GUIDs are unique within a boot, unlike the PIDs they outlive",
    { spec = "PKM *psb.guid.unique-within-boot" }, function(t)
        local emitters, workers = {}, {}
        for i = 1, 8 do
            workers[i] = vm:spawn_worker()
            emitters[i] = { who = workers[i], type = "PIT_PSBU_" .. i }
        end
        local ok, err = pcall(function()
            local seen = guids_of(t, "PIT_PSBU", emitters)
            t:assert_eq(#seen, 8, "eight processes stamped an event each")
            local by_guid = {}
            for _, e in ipairs(seen) do
                t:assert(not by_guid[e.guid],
                    "no two live processes share a GUID (" .. psb.guid_hex(e.guid) .. ")")
                by_guid[e.guid] = e.type
            end
        end)
        for _, w in ipairs(workers) do w:kill(); w:join() end
        if not ok then error(err, 0) end
    end)

-- Protection ---------------------------------------------------------------

test("the parent cannot influence the child's PIP: nothing in the ABI sets it",
    { spec = "PKM *psb.pip.parent-cannot-influence" }, function(t)
        -- The agent is SYSTEM with every privilege — a compromised
        -- peinit — and kacs_set_psb is the only writer of a child's PSB
        -- it has. Its whole accepted vocabulary is KACS_MIT_ALL, and no
        -- bit in it names pip_type or pip_trust.
        in_worker(function(w)
            local pid = psb.pid(w)
            local pidfd = assert(psb.pidfd(vm, pid))
            for bit = 10, 31 do
                local r = psb.set_psb(vm, 1 << bit, pidfd)
                t:assert_eq(r.errno, sys.E.INVAL,
                    string.format("bit 0x%x is not a PSB field the parent may set", 1 << bit))
            end
            -- Everything the parent *is* allowed to set, set at once.
            local settable = psb.MIT.UI_ACCESS | psb.MIT.PIE
            t:assert_eq(psb.set_psb(vm, settable, pidfd).ret, 0,
                "the parent sets every mitigation it can on the child")
            -- The child is still unprotected: a PIP-protected process
            -- may not re-enable core dumps, and this one may.
            local r = w:syscall(psb.NR.prctl, psb.PR.SET_DUMPABLE, psb.SUID_DUMP_USER, 0, 0, 0)
            t:assert_eq(r.ret, 0,
                "the child still behaves as pip_type 0: " .. sys.errname(r.errno))
            sys.close(vm, pidfd)
        end)
    end)

test("write-XOR-execute rejects W+X mappings and both transitions between them",
    { spec = "PKM *psb.wxp.no-write-and-execute" }, function(t)
        in_worker(function(w)
            local rw = assert(psb.anon(w, psb.PROT.READ | psb.PROT.WRITE))
            local rx = assert(psb.anon(w, psb.PROT.READ | psb.PROT.EXEC))
            t:assert_eq(psb.commit(w, psb.MIT.WXP), nil, "wxp commits")

            t:assert_eq(psb.wx_refused(w), sys.E.ACCES,
                "a mapping asking for write and execute at once is refused")
            t:assert_eq(psb.mprotect(w, rw, 4096, psb.PROT.READ | psb.PROT.EXEC).errno,
                sys.E.ACCES, "a writable mapping cannot become executable")
            t:assert_eq(psb.mprotect(w, rx, 4096, psb.PROT.READ | psb.PROT.WRITE).errno,
                sys.E.ACCES, "an executable mapping cannot become writable")
            t:assert_eq(psb.mprotect(w, rw, 4096, WRITE_EXEC).errno, sys.E.ACCES,
                "and neither can become both")
            t:assert_eq(psb.mprotect(w, rw, 4096, psb.PROT.READ).ret, 0,
                "dropping write is still allowed")
            local rx2, errno = psb.anon(w, psb.PROT.READ | psb.PROT.EXEC)
            t:assert(rx2, "so is an execute-only-plus-read mapping: "
                .. sys.errname(errno or 0))
        end)
    end)

test("speculation mitigations are locked on and the process cannot relax them",
    { spec = "PKM *psb.sml.speculation-locked" }, function(t)
        in_worker(function(w)
            local function spec_ctrl(which, ctrl)
                return w:syscall(psb.NR.prctl, psb.PR.SET_SPECULATION_CTRL,
                    which, ctrl, 0, 0)
            end
            t:assert_eq(spec_ctrl(psb.PR_SPEC.STORE_BYPASS, psb.PR_SPEC.ENABLE).ret, 0,
                "before sml the process may enable speculative store bypass")
            t:assert_eq(psb.commit(w, psb.MIT.SML), nil, "sml commits")

            t:assert_eq(spec_ctrl(psb.PR_SPEC.STORE_BYPASS, psb.PR_SPEC.ENABLE).errno,
                sys.E.ACCES, "afterwards it cannot re-enable store bypass")
            t:assert_eq(spec_ctrl(psb.PR_SPEC.INDIRECT_BRANCH, psb.PR_SPEC.ENABLE).errno,
                sys.E.ACCES, "nor indirect-branch speculation")
            t:assert_eq(spec_ctrl(psb.PR_SPEC.L1D_FLUSH, psb.PR_SPEC.DISABLE).errno,
                sys.E.ACCES, "nor turn the L1D flush off")
            t:assert_eq(spec_ctrl(psb.PR_SPEC.STORE_BYPASS, psb.PR_SPEC.DISABLE).ret, 0,
                "tightening further is still permitted")
        end)
    end)

test("with pie set, a non-PIE binary is rejected at exec",
    { spec = "PKM *psb.pie.non-pie-rejected-at-exec" }, function(t)
        in_worker(function(w)
            t:assert_eq(psb.execve(w, ELF_DIR .. "/et-exec"), ENOEXEC,
                "without pie an ET_EXEC image reaches the ELF loader (ENOEXEC)")
            t:assert_eq(psb.execve(w, ELF_DIR .. "/et-dyn"), ENOEXEC,
                "as does an ET_DYN one")
            t:assert_eq(psb.commit(w, psb.MIT.PIE), nil, "pie commits")
            t:assert_eq(psb.execve(w, ELF_DIR .. "/et-exec"), sys.E.ACCES,
                "afterwards the ET_EXEC image is refused before the loader sees it")
            t:assert_eq(psb.execve(w, ELF_DIR .. "/et-dyn"), ENOEXEC,
                "and the position-independent one still reaches it")
        end)
    end)

test("mitigations are one-way: nothing a later request says clears a committed bit",
    { spec = "PKM *psb.mitigations.one-way" }, function(t)
        in_worker(function(w)
            t:assert_eq(psb.commit(w, psb.MIT.WXP), nil, "wxp commits")
            t:assert_eq(psb.wx_refused(w), sys.E.ACCES, "and is enforced")
            t:assert_eq(psb.commit(w, 0), nil, "an empty request is accepted")
            t:assert_eq(psb.wx_refused(w), sys.E.ACCES, "and clears nothing")
            t:assert_eq(psb.commit(w, psb.MIT.UI_ACCESS), nil,
                "a request naming a different mitigation is accepted")
            t:assert_eq(psb.wx_refused(w), sys.E.ACCES,
                "and leaves the committed one where it was")
        end)
    end)

test("ui_access is set by syscall and fixed thereafter",
    { spec = "PKM *psb.ui-access.set-once-fixed" }, function(t)
        in_worker(function(w)
            t:assert_eq(psb.commit(w, psb.MIT.UI_ACCESS), nil,
                "ui_access commits with nothing to activate")
            t:assert_eq(psb.commit(w, psb.MIT.UI_ACCESS), nil,
                "and re-requesting it is a no-op rather than an error")
            -- kacs_set_psb's argument is a set-mask: the only accepted
            -- values are the mitigation bits themselves, so no call can
            -- ask for a clear. Requesting every other valid bit at once
            -- must not be read as a request to drop this one.
            t:assert_eq(psb.commit(w, psb.MIT_ALL & ~psb.MIT.UI_ACCESS
                & ~psb.MIT.CFI & ~psb.MIT.CFIF & ~psb.MIT.CFIB
                & ~psb.MIT.TLP & ~psb.MIT.LSV), nil,
                "a request naming every other settable mitigation is accepted")
            t:assert_eq(psb.commit(w, psb.MIT.UI_ACCESS), nil,
                "and ui_access is still a settable no-op afterwards")
        end)
    end)

-- Process restrictions -----------------------------------------------------

test("no_child_process blocks fork while leaving the process running",
    { spec = "PKM *psb.no-child-process.blocks-fork" }, function(t)
        in_worker(function(w)
            t:assert_eq(fork_errno(w), 0, "the worker can create a process to begin with")
            t:assert_eq(psb.commit(w, psb.MIT.NO_CHILD), nil, "no_child_process commits")
            local errno = fork_errno(w)
            t:assert_neq(errno, 0, "afterwards process creation is refused")
            t:assert_eq(errno, sys.E.ACCES, "with " .. sys.errname(errno))
            t:assert_eq(w:syscall(sys.NR.getpid).ret > 0, true,
                "and the restricted process itself keeps running")
        end)
    end)

test("no_child_process can be set in the freshly forked child or later in life",
    { spec = "PKM *psb.no-child-process.two-set-points" }, function(t)
        -- Point one: a worker is a forked child that has not exec'd —
        -- exactly where a launcher's code runs between fork and exec.
        in_worker(function(w)
            t:assert_eq(psb.commit(w, psb.MIT.NO_CHILD), nil,
                "the freshly forked child restricts itself before exec'ing anything")
            t:assert_eq(fork_errno(w), sys.E.ACCES, "and creates no processes")
        end)
        -- Point two: a process that has already spawned its workers
        -- restricts itself afterwards, and only later creations fail.
        in_worker(function(w)
            t:assert_eq(fork_errno(w), 0, "a process spawns freely first")
            t:assert_eq(fork_errno(w), 0, "and again")
            t:assert_eq(psb.commit(w, psb.MIT.NO_CHILD), nil,
                "then restricts itself part way through its life")
            t:assert_eq(fork_errno(w), sys.E.ACCES, "and creates nothing more")
        end)
    end)

test("identity virtualization is reserved: the ABI carries no field for it",
    { spec = "PKM *psb.virtualization.reserved" }, function(t)
        in_worker(function(w)
            -- KACS_MIT_ALL is the whole accepted vocabulary, and each of
            -- its ten bits is one of §3.3.2's named mitigations. There
            -- is no virtualization bit, and no other syscall takes one.
            local named = 0
            for _, bit in pairs(psb.MIT) do named = named | bit end
            t:assert_eq(named, psb.MIT_ALL,
                "the named mitigations account for every bit of KACS_MIT_ALL")
            for bit = 10, 31 do
                t:assert_eq(psb.set_psb(w, 1 << bit).errno, sys.E.INVAL,
                    string.format("no PSB field answers to bit 0x%x", 1 << bit))
            end
            t:assert_eq(psb.set_psb(w, psb.MIT_ALL + 1).errno, sys.E.INVAL,
                "and a request straying past KACS_MIT_ALL is refused outright")
        end)
    end)

-- ---- binary-signature dependent, deferred to the KUnit suite ---------

test("only Protected at PeiosTcb trust is producible; Isolated is unreachable",
    { spec = "PKM *psb.pip.only-protected-tcb",
      covered_by = "kunit:pkm_kunit_process",
      skip = "the profile carries no signed binary and the kernel only " ..
             "ever verifies, so no guest exec can produce a non-zero " ..
             "pip_type; runs under pkm_kunit_exec_pip_signed_material_" ..
             "sets_tcb_trust and pkm_kunit_exec_pip_bad_signature_resets_none" },
    function(t) end)

test("neither None nor Isolated is a named constant in the public ABI",
    { spec = "PKM *psb.pip.none-isolated-absent-from-abi",
      covered_by = "pekit:pkm test.uapi",
      skip = "this is an assertion about which constants uapi/pkm/*.h " ..
             "defines, which neither a guest syscall nor a KUnit case can " ..
             "observe; pkm's uapi/check-userspace-clean.sh fails the UAPI " ..
             "check if any header defines a None or Isolated PIP constant" },
    function(t) end)

test("library signature verification enforces a trust floor at the process's PIP trust",
    { spec = "PKM *psb.lsv.trust-floor",
      covered_by = "kunit:pkm_kunit_process",
      skip = "comparing a library's signer trust against the process's " ..
             "requires a signed shared library, and the profile has " ..
             "none; runs under pkm_kunit_lsv_signed_tcb_allows_none_and_" ..
             "tcb_pip and pkm_kunit_lsv_insufficient_trust_denies" },
    function(t) end)

test("trusted library paths admit shared libraries only from approved prefixes",
    { spec = "PKM *psb.tlp.approved-prefixes-only",
      covered_by = "kunit:pkm_kunit_process",
      skip = "tlp cannot be committed on any live process here: the " ..
             "prefix cache has no production writer, so the agent's own " ..
             "file-backed text mapping is already denied and the enable " ..
             "fails; runs under pkm_kunit_tlp_executable_mapping_enforcement" },
    function(t) end)

test("backward-edge CFI locks the hardware shadow stack on",
    { spec = "PKM *psb.cfib.shadow-stack-locked",
      covered_by = "kunit:pkm_kunit_process",
      skip = "the profile's vCPU reports no X86_FEATURE_USER_SHSTK, so " ..
             "cfib fails ENODEV before any shadow stack is enabled and " ..
             "the lock is unreachable; runs under pkm_kunit_task_prctl_" ..
             "sml_and_cfib_block_disable_paths" },
    function(t) end)
