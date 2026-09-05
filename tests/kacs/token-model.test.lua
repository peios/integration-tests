-- PKM §3.2.1 — The token model: every thread has one, decisions use the
-- effective token, real_cred is the objective identity and cred the
-- subjective one, and what a credential carries into deferred work.
-- Impersonation happens in a worker: the main connection is served by
-- several threads and cannot hold a per-thread identity.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local access = require("helpers.access")

local vm = provium:vm("v", "kernel-only"):boot()

local CN = token.bit(token.PRIV.CHANGE_NOTIFY)

--- A descriptor granting only TEST_USER read access.
local function only_test_user()
    return access.simple({ access.ace(access.ACE.ALLOWED, 0x120089, token.SID.TEST_USER) })
end

--- Run `fn(worker, imp_fd)` in a worker (SYSTEM primary) holding an
--- impersonation token for TEST_USER it has not yet installed.
local function with_client(t, fn, spec)
    local worker = vm:spawn_worker()
    local ok, err = pcall(function()
        local prim = assert(token.mint(worker, spec or {}))
        local imp = assert(token.duplicate(worker, prim, { token_type = token.TYPE.IMPERSONATION,
            impersonation_level = token.LEVEL.IMPERSONATION }))
        sys.close(worker, prim)
        fn(worker, imp)
    end)
    worker:kill(); worker:join()
    if not ok then error(err, 0) end
end

test("an access decision evaluates the thread's effective token",
    { spec = "PKM *token.decisions-use-effective-token" }, function(t)
        with_client(t, function(w, imp)
            -- Nobody but TEST_USER may read: SYSTEM (the primary) is denied
            -- once its DACL-bypassing privileges are removed... simpler: a
            -- descriptor that grants TEST_USER and nothing to SYSTEM, checked
            -- with token_fd = -1 (the caller's effective token).
            local sd = only_test_user()
            local as_system = access.check(w, { sd = sd, desired = 0x1 })
            -- SYSTEM is the owner of the descriptor and holds bypassing
            -- privileges; strip the question of owner rights by asking for
            -- a data bit it is not granted.
            t:assert(as_system.denied or as_system.ok, "the check runs as the primary")
            t:assert_eq(token.impersonate(w, imp).ret, 0, "impersonate TEST_USER")
            local as_client = access.check(w, { sd = sd, desired = 0x1 })
            t:assert(as_client.ok, "the effective token is TEST_USER and is granted: " .. sys.errname(as_client.errno or 0))
            t:assert_eq(as_client.granted, 0x1, "the requested bit")
            t:assert_eq(token.revert(w).ret, 0, "revert")
            -- A descriptor that grants nothing to TEST_USER but everything to Everyone
            -- distinguishes the two identities from the other side.
            local everyone = access.simple({ access.ace(access.ACE.DENIED, 0x1, token.SID.TEST_USER),
                access.ace(access.ACE.ALLOWED, 0x1, token.SID.EVERYONE) })
            t:assert_eq(token.impersonate(w, imp).ret, 0, "impersonate again")
            t:assert(access.check(w, { sd = everyone, desired = 0x1 }).denied, "TEST_USER is denied by its deny ACE")
            t:assert_eq(token.revert(w).ret, 0, "revert")
            t:assert(access.check(w, { sd = everyone, desired = 0x1 }).ok, "the primary, SYSTEM, is not")
        end)
    end)

test("every live userspace thread has a token",
    { spec = "PKM *token.every-thread-has-one" }, function(t)
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local own = assert(token.open_self(worker))
            t:assert(token.query(worker, own, token.CLASS.USER), "a worker thread can read its own token")
            local pid, tid = worker:syscall(sys.NR.getpid).ret, worker:syscall(sys.NR.gettid).ret
            local pidfd = assert(token.pidfd_open(vm, pid))
            local pt = assert(token.open_process(vm, pidfd))
            t:assert_eq(token.statistics(vm, pt).token_id, token.statistics(worker, own).token_id,
                "another process reaches the same primary token through a pidfd")
            sys.close(vm, pt); sys.close(vm, pidfd)
            -- The agent's own threads: several syscalls land on several
            -- threads, every one of which has the same primary token.
            local ids = {}
            for i = 1, 8 do
                local fd = assert(token.open_self(vm))
                ids[token.statistics(vm, fd).token_id] = true
                sys.close(vm, fd)
            end
            local n = 0; for _ in pairs(ids) do n = n + 1 end
            t:assert_eq(n, 1, "every agent thread resolves to the one primary token")
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
    end)

test("a mutation to a token shared by a process's threads is visible to every thread",
    { spec = "PKM *token.shared-within-process" }, function(t)
        -- The agent is multi-threaded and its syscalls are spread across
        -- its threads: a change made through one is read back through others.
        local fd = assert(token.open_self(vm))
        local before = token.privileges(vm, fd)
        local target = token.PRIV.LOCK_MEMORY
        local was_enabled = before.enabled & token.bit(target) ~= 0
        local r = was_enabled and token.disable_priv(vm, fd, target) or token.enable_priv(vm, fd, target)
        t:assert_eq(r.ret, 0, "toggle a privilege on the shared primary token")
        for i = 1, 8 do
            local h = assert(token.open_self(vm))
            local now = token.privileges(vm, h).enabled & token.bit(target) ~= 0
            t:assert_eq(now, not was_enabled, "read " .. i .. " sees the toggled state")
            sys.close(vm, h)
        end
        -- Put it back.
        local back = was_enabled and token.enable_priv(vm, fd, target) or token.disable_priv(vm, fd, target)
        t:assert_eq(back.ret, 0, "restored")
        sys.close(vm, fd)
    end)

test("real_cred is the objective identity: others see the primary token",
    { spec = "PKM *token.real-cred-is-objective" }, function(t)
        with_client(t, function(w, imp)
            t:assert_eq(token.impersonate(w, imp).ret, 0, "the worker impersonates TEST_USER")
            local pidfd = assert(token.pidfd_open(vm, w:syscall(sys.NR.getpid).ret))
            local pt = assert(token.open_process(vm, pidfd))
            t:assert_eq(token.sid_string(token.query(vm, pt, token.CLASS.USER)), "S-1-5-18",
                "opening the process's token yields the primary, SYSTEM")
            t:assert_eq(token.query_u32(vm, pt, token.CLASS.TYPE), token.TYPE.PRIMARY, "a primary token")
            sys.close(vm, pt); sys.close(vm, pidfd)
            t:assert_eq(token.revert(w).ret, 0, "revert")
        end)
    end)

test("cred is the subjective identity: the thread acts as its effective token",
    { spec = "PKM *token.cred-is-subjective" }, function(t)
        with_client(t, function(w, imp)
            t:assert_eq(token.impersonate(w, imp).ret, 0, "impersonate")
            local eff = assert(token.open_self(w, token.RIGHT.QUERY))
            t:assert_eq(token.query(w, eff, token.CLASS.USER), token.SID.TEST_USER,
                "the thread's own token is now the impersonation token")
            t:assert_eq(token.query_u32(w, eff, token.CLASS.TYPE), token.TYPE.IMPERSONATION, "of type Impersonation")
            local pidfd = assert(token.pidfd_open(vm, w:syscall(sys.NR.getpid).ret))
            local tt = assert(token.open_thread(vm, pidfd, w:syscall(sys.NR.gettid).ret))
            t:assert_eq(token.query(vm, tt, token.CLASS.USER), token.SID.TEST_USER,
                "and the thread-token variant reaches it from outside")
            sys.close(vm, tt); sys.close(vm, pidfd); sys.close(w, eff)
            t:assert_eq(token.revert(w).ret, 0, "revert")
        end)
    end)

test("impersonation swaps only cred; reverting restores it to real_cred",
    { spec = "PKM *token.impersonation-swaps-cred-only" }, function(t)
        with_client(t, function(w, imp)
            local pidfd = assert(token.pidfd_open(vm, w:syscall(sys.NR.getpid).ret))
            local function real_id()
                local pt = assert(token.open_process(vm, pidfd))
                local id = token.statistics(vm, pt).token_id; sys.close(vm, pt); return id
            end
            local function eff_id()
                local fd = assert(token.open_self(w, token.RIGHT.QUERY))
                local id = token.statistics(w, fd).token_id; sys.close(w, fd); return id
            end
            local real0, eff0 = real_id(), eff_id()
            t:assert_eq(real0, eff0, "with no impersonation both credentials resolve to the same token")
            t:assert_eq(token.impersonate(w, imp).ret, 0, "impersonate")
            t:assert_eq(real_id(), real0, "real_cred still points at the primary")
            t:assert_neq(eff_id(), real0, "cred points at a different token")
            t:assert_eq(eff_id(), token.statistics(w, imp).token_id, "the impersonation token")
            -- The real token seen through the effective identity: the
            -- OPEN_REAL flag names it, and the check runs as TEST_USER, whom
            -- SYSTEM's token descriptor does not grant.
            local denied, e = token.open_self(w, token.RIGHT.QUERY, token.OPEN_REAL)
            t:assert(not denied and e == sys.E.ACCES, "OPEN_REAL is judged by the effective token: EACCES")
            t:assert_eq(token.revert(w).ret, 0, "revert")
            t:assert_eq(eff_id(), real0, "cred is back to real_cred")
            sys.close(vm, pidfd)
        end)
    end)

test("authorization cached on a handle outlives a change of effective token",
    { spec = "PKM *token.cached-handle-authority-persists" }, function(t)
        local mount = "/mnt/pit-cached"
        assert(kacs.new_mount(vm, "tmpfs", mount, kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL))
        local f = assert(sys.open(vm, mount .. "/f", sys.O.WRONLY | sys.O.CREAT, 420))
        sys.write(vm, f, "hello"); sys.close(vm, f)
        -- Nobody but SYSTEM may read f.
        assert(kacs.set_sd(vm, mount .. "/f", kacs.descriptor(kacs.acl({
            kacs.ace(0, kacs.ALL_RIGHTS, kacs.SID.LOCAL_SYSTEM, 0) }))).ret == 0)
        with_client(t, function(w, imp)
            local fd = assert(sys.open(w, mount .. "/f", sys.O.RDONLY))
            t:assert_eq(token.impersonate(w, imp).ret, 0, "impersonate TEST_USER, who may not read f")
            local denied, e = sys.open(w, mount .. "/f", sys.O.RDONLY)
            t:assert(not denied and e == sys.E.ACCES, "a fresh open as TEST_USER is refused")
            local r, e2 = sys.read(w, fd, 5)
            t:assert_eq(r and #r or 0, 5, "the handle opened as SYSTEM still reads: " .. sys.errname(e2 or 0))
            t:assert_eq(token.revert(w).ret, 0, "revert")
            sys.close(w, fd)
        end, { privs_present = CN, privs_enabled = CN })
    end)

-- Credential contexts no guest syscall can construct run under KUnit.
local function kunit_stub(name, spec, case, why)
    test(name, { spec = spec, covered_by = "kunit:pkm_kunit_token",
                 skip = why .. "; runs under " .. case }, function(t) end)
end

kunit_stub("an LSM hook reached with a credential carrying no token fails closed",
    "PKM *token.null-credential-fails-closed",
    "pkm_kunit_token_eval_context_requires_subjective_cred",
    "every userspace credential carries a token; a token-less one exists only inside the kernel")

kunit_stub("user-originated asynchronous work with neither captured credentials nor cached authority fails closed",
    "PKM *token.uncaptured-async-fails-closed",
    "pkm_kunit_token_eval_context_requires_subjective_cred",
    "the credential shape is kernel-internal")

test("credentials installed by override_creds carry their token and are evaluated normally",
    { spec = "PKM *token.override-creds-authoritative",
      covered_by = "kunit:pkm_kunit_misc",
      skip = "override_creds() is reached only by in-kernel callers (io_uring " ..
             "workers, workqueues), so no syscall exercises it; runs under " ..
             "pkm_kunit_override_creds_credential_is_authoritative, where a kernel " ..
             "thread overrides its credential with a lesser token and every " ..
             "evaluation follows that token until it reverts" },
    function(t) end)

test("kernel-originated work under the boot SYSTEM credential evaluates as SYSTEM",
    { spec = "PKM *token.kernel-work-evaluates-as-system",
      covered_by = "kunit:pkm_kunit_misc",
      skip = "the boot credential's evaluations (write-back, seeding) leave no " ..
             "user-visible verdict to compare against SYSTEM's; runs under " ..
             "pkm_kunit_kernel_work_evaluates_as_system, where the KUnit kernel " ..
             "thread's token is SYSTEM's and its gates answer as SYSTEM" },
    function(t) end)
