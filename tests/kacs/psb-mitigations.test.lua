-- PKM §3.3.2 — activation: what has to be true before a mitigation bit
-- moves from clear to set, what a failed request must not leave behind,
-- and the TLP prefix cache the `tlp` bit is evaluated against.
--
-- The profile's vCPU offers neither userspace IBT nor a user shadow
-- stack, so the two architecture-backed bits fail closed here; that is
-- what §3.3.2 says they must do, and it is what makes the fail-closed
-- and all-or-nothing cases witnessable at all.
--
-- Every process in this VM is the provium agent, whose text is a
-- file-backed executable mapping of an unsigned binary at a path no
-- approved prefix covers — so `tlp` and `lsv` can never be committed
-- on a live process here, and the cases that would need a committed
-- one are deferred to KUnit.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local psb = require("helpers.psb")

local vm = provium:vm("v", "kernel-only"):boot()

local ELF_DIR = "/mnt/psb-mit-elf"
assert(kacs.new_mount(vm, "tmpfs", ELF_DIR, kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL))
assert(psb.write_elf(vm, ELF_DIR .. "/et-exec", psb.ET_EXEC).ret == 0)
local ENOEXEC = 8

local function in_worker(fn)
    local w = vm:spawn_worker()
    local ok, err = pcall(fn, w)
    w:kill(); w:join()
    if not ok then error(err, 0) end
end

--- The errno a fork out of `w` fails with, or 0 when the fork succeeded.
--- See psb-fields.test.lua for why this is shaped as a failed exec.
local function fork_errno(w)
    local ok, err = pcall(function() w:run("/nonexistent-peios-binary") end)
    if ok then return 0 end
    local errno = tonumber(tostring(err):match("errno (%d+)"))
    assert(errno, "unrecognised run() failure: " .. tostring(err))
    return errno == sys.E.NOENT and 0 or errno
end

-- Activation ---------------------------------------------------------------

test("setting a bit is activation-backed: KACS activates the protection or verifies it holds",
    { spec = "PKM *psb.mitigations.activation-backed" }, function(t)
        in_worker(function(w)
            -- The verification route: wxp is refused while the process
            -- violates the invariant and accepted once it does not, so
            -- the bit is not simply recorded on request.
            local wx = assert(psb.anon(w, psb.PROT.READ | psb.PROT.WRITE | psb.PROT.EXEC))
            t:assert_eq(psb.commit(w, psb.MIT.WXP), sys.E.ACCES,
                "wxp is refused while the process already violates it")
            sys.munmap(w, wx, 4096)
            t:assert_eq(psb.commit(w, psb.MIT.WXP), nil,
                "and accepted once KACS can verify the invariant holds")
            -- The activation route: an architecture-backed bit whose
            -- protection the platform cannot be placed in is refused
            -- rather than recorded.
            t:assert_eq(psb.commit(w, psb.MIT.CFIB), sys.E.NODEV,
                "an arch bit KACS cannot activate is refused, not recorded")
        end)
    end)

test("a request that cannot be satisfied mutates no bit from that request",
    { spec = "PKM *psb.mitigations.all-or-nothing" }, function(t)
        in_worker(function(w)
            -- wxp alone would be accepted; asked for alongside cfif,
            -- which fails closed, neither may be committed.
            t:assert_eq(psb.commit(w, psb.MIT.WXP | psb.MIT.CFIF), sys.E.NODEV,
                "the whole request fails on the bit that cannot be activated")
            t:assert_eq(psb.wx_refused(w), nil,
                "and wxp was not committed on the way past")
            t:assert_eq(psb.commit(w, psb.MIT.WXP | psb.MIT.LSV), sys.E.ACCES,
                "the same holds when the unsatisfiable bit is a memory one")
            t:assert_eq(psb.wx_refused(w), nil, "wxp is still not committed")
            t:assert_eq(psb.commit(w, psb.MIT.WXP), nil, "asked for on its own it commits")
            t:assert_eq(psb.wx_refused(w), sys.E.ACCES, "and is enforced")
        end)
    end)

test("re-requesting a committed mitigation never weakens what is already committed",
    { spec = "PKM *psb.mitigations.recommit-never-weakens" }, function(t)
        in_worker(function(w)
            t:assert_eq(psb.commit(w, psb.MIT.WXP), nil, "wxp commits")
            t:assert_eq(psb.commit(w, psb.MIT.WXP), nil, "and re-requesting it is accepted")
            t:assert_eq(psb.wx_refused(w), sys.E.ACCES, "with the protection unchanged")
            t:assert_eq(psb.commit(w, psb.MIT.WXP | psb.MIT.UI_ACCESS), nil,
                "re-requesting it alongside a new bit is accepted")
            t:assert_eq(psb.wx_refused(w), sys.E.ACCES, "and still changes nothing")
            -- A request that fails leaves it alone too.
            t:assert_eq(psb.commit(w, psb.MIT.WXP | psb.MIT.CFIF), sys.E.NODEV,
                "a failing request naming it is refused")
            t:assert_eq(psb.wx_refused(w), sys.E.ACCES, "and does not disturb it")
        end)
    end)

test("enabling wxp fails when the process already holds a writable executable mapping",
    { spec = "PKM *psb.wxp.enable-fails-on-existing-wx" }, function(t)
        in_worker(function(w)
            local wx = assert(psb.anon(w, psb.PROT.READ | psb.PROT.WRITE | psb.PROT.EXEC),
                "a W+X mapping is available before wxp")
            t:assert_eq(psb.commit(w, psb.MIT.WXP), sys.E.ACCES,
                "wxp is refused while it exists")
            -- A second, innocent mapping does not change the answer:
            -- one violating VMA anywhere in the address space is enough.
            local ro = assert(psb.anon(w, psb.PROT.READ))
            t:assert_eq(psb.commit(w, psb.MIT.WXP), sys.E.ACCES, "still refused")
            sys.munmap(w, ro, 4096)
            sys.munmap(w, wx, 4096)
            t:assert_eq(psb.commit(w, psb.MIT.WXP), nil,
                "and accepted once the violating mapping is gone")
        end)
    end)

test("enabling tlp fails when a file-backed executable mapping is already TLP-denied",
    { spec = "PKM *psb.tlp.enable-fails-on-denied-mapping" }, function(t)
        in_worker(function(w)
            -- The process's own text is file-backed, executable, and at
            -- a path no approved prefix covers — the cache is empty.
            t:assert_eq(psb.commit(w, psb.MIT.TLP), sys.E.ACCES,
                "tlp is refused on a process whose text no prefix covers")
            -- Mapping the same file executable again does not help, and
            -- neither does having only anonymous mappings besides.
            local f = assert(sys.open(w, "/sbin/provium-agent", sys.O.RDONLY))
            local m, errno = sys.mmap(w, f, 4096, psb.PROT.READ | psb.PROT.EXEC,
                sys.MAP.PRIVATE, 0)
            t:assert(m, "a second file-backed executable mapping is made: "
                .. sys.errname(errno or 0))
            t:assert_eq(psb.commit(w, psb.MIT.TLP), sys.E.ACCES, "tlp is still refused")
            sys.munmap(w, m, 4096); sys.close(w, f)
        end)
    end)

test("enabling lsv fails when a file-backed executable mapping carries no valid signature",
    { spec = "PKM *psb.lsv.enable-fails-on-untrusted-mapping" }, function(t)
        in_worker(function(w)
            t:assert_eq(psb.commit(w, psb.MIT.LSV), sys.E.ACCES,
                "lsv is refused on a process whose text is unsigned")
            local f = assert(sys.open(w, "/sbin/provium-agent", sys.O.RDONLY))
            local m = assert(sys.mmap(w, f, 4096, psb.PROT.READ, sys.MAP.PRIVATE, 0))
            t:assert_eq(psb.commit(w, psb.MIT.LSV), sys.E.ACCES,
                "a non-executable mapping of the same file changes nothing")
            sys.munmap(w, m, 4096); sys.close(w, f)
        end)
    end)

test("an architecture-backed mitigation the platform cannot make true fails closed",
    { spec = "PKM *psb.mitigations.arch-fails-closed" }, function(t)
        in_worker(function(w)
            -- This vCPU offers no user shadow stack, so KACS cannot place
            -- the task in the protected state.
            t:assert_eq(psb.commit(w, psb.MIT.CFIB), sys.E.NODEV,
                "cfib is refused rather than recorded")
            t:assert_eq(psb.commit(w, psb.MIT.CFI), sys.E.NODEV,
                "and so is the legacy alias that expands to both CFI bits")
            -- Failing closed means failing: nothing was half-applied.
            t:assert_eq(psb.commit(w, psb.MIT.CFIB), sys.E.NODEV,
                "the refusal is stable across repeats")
            t:assert_eq(psb.commit(w, psb.MIT.WXP), nil,
                "and an unrelated mitigation is still settable afterwards")
        end)
    end)

test("cfif cannot be committed at all: activation against a live task is ENODEV",
    { spec = "PKM *psb.cfif.enodev-always" }, function(t)
        in_worker(function(w)
            t:assert_eq(psb.commit(w, psb.MIT.CFIF), sys.E.NODEV,
                "cfif on the caller's own process")
            t:assert_eq(psb.commit(w, psb.MIT.CFIF | psb.MIT.UI_ACCESS), sys.E.NODEV,
                "cfif alongside a mitigation that would otherwise succeed")
            local pidfd = assert(psb.pidfd(vm, psb.pid(w)))
            t:assert_eq(psb.set_psb(vm, psb.MIT.CFIF, pidfd).errno, sys.E.NODEV,
                "cfif requested on another process by a fully privileged caller")
            sys.close(vm, pidfd)
            t:assert_eq(psb.commit(w, psb.MIT.UI_ACCESS), nil,
                "the process is otherwise perfectly able to commit a mitigation")
        end)
    end)

test("enabling cfib on a task other than the caller fails",
    { spec = "PKM *psb.cfib.self-only" }, function(t)
        in_worker(function(w)
            local pidfd = assert(psb.pidfd(vm, psb.pid(w)))
            local errno = psb.set_psb(vm, psb.MIT.CFIB, pidfd).errno
            t:assert_neq(errno, 0,
                "the agent cannot enable cfib on another process: " .. sys.errname(errno))
            sys.close(vm, pidfd)
        end)
    end)

test("pie and no_child_process are event-gated: they constrain what happens next, not what has happened",
    { spec = "PKM *psb.mitigations.event-gated" }, function(t)
        in_worker(function(w)
            -- Both events happen freely before the bit is set...
            t:assert_eq(psb.execve(w, ELF_DIR .. "/et-exec"), ENOEXEC,
                "an ET_EXEC image reaches the loader before pie is set")
            t:assert_eq(fork_errno(w), 0, "and a process is created before no_child is set")
            t:assert_eq(psb.commit(w, psb.MIT.PIE | psb.MIT.NO_CHILD), nil,
                "both bits commit with nothing retroactive to do")
            -- ...and are constrained from the next occurrence onwards.
            t:assert_eq(psb.execve(w, ELF_DIR .. "/et-exec"), sys.E.ACCES,
                "the next exec of that image is refused")
            t:assert_eq(fork_errno(w), sys.E.ACCES, "and the next process creation is too")
        end)
    end)

-- The TLP cache ------------------------------------------------------------

test("the TLP prefix cache has no production writer",
    { spec = "PKM *psb.tlp.no-production-writer" }, function(t)
        -- Three places a writer could be, and is not.
        --
        -- The syscall: kacs_set_psb's only arguments are a pidfd and a
        -- u32 mitigation bitmask, so there is no shape in which a prefix
        -- could be passed. Nothing else in the §3.A syscall table takes
        -- one either.
        in_worker(function(w)
            t:assert_eq(psb.set_psb(w, psb.MIT_ALL + 1).errno, sys.E.INVAL,
                "the mitigation argument accepts only KACS_MIT_ALL — no prefix travels with it")
        end)
        -- securityfs: KACS publishes no node for it.
        local SEC = "/mnt/psb-securityfs"
        local ok = kacs.new_mount(vm, "securityfs", SEC,
            kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL)
        t:assert(ok, "securityfs mounts")
        local fd = assert(sys.open(vm, SEC, sys.O.RDONLY | sys.O.DIRECTORY))
        local names = {}
        for _, e in ipairs(assert(sys.getdents_all(vm, fd))) do
            if e.name ~= "." and e.name ~= ".." then names[#names + 1] = e.name end
        end
        sys.close(vm, fd)
        for _, name in ipairs(names) do
            t:assert(not name:lower():find("tlp"),
                "no securityfs node names the prefix cache (saw " .. name .. ")")
        end
        -- And the consequence: with nothing having written it, the cache
        -- is empty, so no process can commit tlp at all.
        in_worker(function(w)
            t:assert_eq(psb.commit(w, psb.MIT.TLP), sys.E.ACCES,
                "an unwritten cache leaves tlp uncommittable")
        end)
    end)

-- ---- KUnit-only: the cache's writer is compiled in under KUnit -------

test("the cache holds at most 64 prefixes of at most 4096 bytes each",
    { spec = "PKM *psb.tlp.cache-bounds",
      covered_by = "kunit:pkm_kunit_process",
      skip = "the only writer of the prefix cache is compiled in under " ..
             "CONFIG_SECURITY_PKM_KUNIT, so no guest call can present a " ..
             "prefix; runs under pkm_kunit_tlp_cache_validation" },
    function(t) end)

test("an approved prefix is absolute and slash-terminated, with no embedded NUL",
    { spec = "PKM *psb.tlp.prefix-slash-terminated",
      covered_by = "kunit:pkm_kunit_process",
      skip = "prefix syntax is only checkable at the cache writer, which " ..
             "exists solely under KUnit; runs under pkm_kunit_tlp_cache_validation" },
    function(t) end)

test("an invalid prefix is rejected without mutating the existing cache",
    { spec = "PKM *psb.tlp.invalid-prefix-rejected-atomically",
      covered_by = "kunit:pkm_kunit_process",
      skip = "the staged-and-swapped update is only reachable through the " ..
             "KUnit-only writer; runs under pkm_kunit_tlp_cache_validation" },
    function(t) end)

test("an empty cache matches no path, so tlp denies every file-backed executable mapping",
    { spec = "PKM *psb.tlp.empty-cache-denies-all",
      covered_by = "kunit:pkm_kunit_process",
      skip = "committing tlp on a live process is impossible here — the " ..
             "enable is refused by the process's own text — so the " ..
             "subsequent mappings the claim is about never happen; runs " ..
             "under pkm_kunit_tlp_executable_mapping_enforcement" },
    function(t) end)

test("mmap(PROT_EXEC) is rejected when the backing path matches no approved prefix",
    { spec = "PKM *psb.tlp.mmap-rejects-unmatched",
      covered_by = "kunit:pkm_kunit_process",
      skip = "reaching the mmap-time check needs a process with tlp " ..
             "committed, which no guest process can become; runs under " ..
             "pkm_kunit_tlp_executable_mapping_enforcement and " ..
             "pkm_kunit_tlp_mprotect_checks_new_exec_only" },
    function(t) end)

test("anonymous executable mappings are governed by wxp alone",
    { spec = "PKM *psb.mitigations.anonymous-exec-is-wxp-only",
      covered_by = "kunit:pkm_kunit_process",
      skip = "separating an anonymous mapping's treatment from a " ..
             "file-backed one's needs tlp or lsv committed, and every " ..
             "process here is refused both by its own text; runs under " ..
             "pkm_kunit_lsv_bypasses_non_exec_and_anonymous" },
    function(t) end)

test("a platform reporting speculation as not-affected satisfies sml activation by that fact",
    { spec = "PKM *psb.sml.not-affected-satisfies",
      covered_by = "kunit:pkm_kunit_process",
      skip = "this vCPU reports PR_SPEC_PRCTL | PR_SPEC_ENABLE for store " ..
             "bypass and indirect branch, not PR_SPEC_NOT_AFFECTED, so sml " ..
             "takes the force-disable route; runs under " ..
             "pkm_kunit_sml_not_affected_satisfies_activation" },
    function(t) end)
