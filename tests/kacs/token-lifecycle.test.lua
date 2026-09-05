-- PKM §3.2.3 — Token lifecycle: fork, clone, exec, NEW_PROCESS_MIN,
-- self-installation, the bootstrap tokens. A provium worker is a fork
-- and exec of the agent, and `worker:run_async` forks and execs a child
-- whose pid the test can reach — the only executable in the guest is
-- the agent itself, which run with `--port N` listens forever.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local access = require("helpers.access")

local vm = provium:vm("v", "kernel-only"):boot()

local R = token.RIGHT
local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED
local TCB, BACKUP, RESTORE = token.bit(token.PRIV.TCB), token.bit(token.PRIV.BACKUP), token.bit(token.PRIV.RESTORE)
local CN = token.bit(token.PRIV.CHANGE_NOTIFY)
local AGENT = "/sbin/provium-agent"
local next_port = 7100

--- Spawn a long-lived exec'd child from `who`; returns proc, pidfd.
local function child_of(who, binary)
    next_port = next_port + 1
    -- Direct exec (program, argv): there is no shell in the guest.
    local proc = who:run_async(binary or AGENT, { "--port", tostring(next_port) })
    local pidfd = assert(token.pidfd_open(vm, proc:pid()))
    return proc, pidfd
end

local function primary_of(pidfd) return assert(token.open_process(vm, pidfd)) end
local function id_of(fd, who) return assert(token.statistics(who or vm, fd)).token_id end

--- Every queryable class, for "same content, different object".
local CLASSES = { "USER", "GROUPS", "PRIVILEGES", "INTEGRITY_LEVEL", "OWNER", "PRIMARY_GROUP",
    "INTERACTIVITY_SCOPE", "SOURCE", "ORIGIN", "ELEVATION_TYPE", "MANDATORY_POLICY", "LOGON_SID",
    "DEFAULT_DACL", "IMPERSONATION_LEVEL", "TYPE" }
--- The classes on which `a` and `b` disagree, skipping any named in
--- `skip`. A case that expects one field to differ names it there and
--- asserts on it separately.
local function same_content(a, b, skip)
    local diff = {}
    for _, c in ipairs(CLASSES) do
        if not (skip and skip[c])
            and token.query(vm, a, token.CLASS[c]) ~= token.query(vm, b, token.CLASS[c]) then
            diff[#diff + 1] = c
        end
    end
    return diff
end

--- Start a syscall on a *second* thread of `worker`: a nanosleep long
--- enough that the thread is still blocked in the kernel while the case
--- looks at it. `worker:syscall` runs on one thread; `syscall_async`
--- adds one for the duration of the call.
local function sleeping_thread(worker, seconds)
    return worker:syscall_async(sys.NR.nanosleep, {
        args = { 0, 0 }, bufs = { string.pack("<i8i8", seconds, 0) }, ptrs = { 0 },
    })
end

--- The tid of `pid`'s other thread, once the kernel has published it
--- under /proc/<pid>/task. Returns nil if none appears.
local function sibling_tid(pid)
    for _ = 1, 200 do
        for _, e in ipairs(vm:listdir("/proc/" .. pid .. "/task")) do
            local tid = tonumber(e.name)
            if tid and tid ~= pid then return tid end
        end
        sys.nanosleep(vm, 0, 5 * 1000 * 1000)
    end
    return nil
end

-- Fork ----------------------------------------------------------------------------

test("a forked child receives an independent deep copy of the primary token",
    { spec = "PKM *token.fork.independent-copy" }, function(t)
        local worker = vm:spawn_worker()  -- a fork (and exec) of the agent
        local ok, err = pcall(function()
            local mine = assert(token.open_self(vm))
            local pidfd = assert(token.pidfd_open(vm, worker:syscall(sys.NR.getpid).ret))
            local theirs = primary_of(pidfd)
            t:assert_neq(id_of(theirs), id_of(mine), "a different token object")
            t:assert_eq(#same_content(mine, theirs), 0, "with the same content: " .. table.concat(same_content(mine, theirs), ","))
            t:assert_eq(token.statistics(vm, theirs).auth_id, token.SYSTEM_LUID, "in the same session")
            sys.close(vm, theirs); sys.close(vm, pidfd); sys.close(vm, mine)
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
    end)

test("a child forked by an impersonating parent starts on the primary token",
    { spec = "PKM *token.fork.impersonation-not-inherited", covered_by = "kunit:pkm_kunit_process",
      skip = "a worker can spawn now, but every spawn is a fork *and* an exec, and exec reverts " ..
             "impersonation on its own account (token.exec.reverts-impersonation below), so the fork " ..
             "half cannot be isolated from the guest; runs under " ..
             "pkm_kunit_clone_process_impersonation_uses_primary_copy" },
    function(t) end)

test("after a fork, mutations to either token are invisible to the other",
    { spec = "PKM *token.fork.mutations-invisible-after" }, function(t)
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local mine = assert(token.open_self(vm))
            local pidfd = assert(token.pidfd_open(vm, worker:syscall(sys.NR.getpid).ret))
            local theirs = primary_of(pidfd)
            local target = token.PRIV.LOCK_MEMORY
            local before_theirs = token.privileges(vm, theirs).enabled
            t:assert_eq(token.disable_priv(vm, mine, target).ret, 0, "disable a privilege on the agent's token")
            t:assert_eq(token.privileges(vm, theirs).enabled, before_theirs, "the worker's copy is unchanged")
            t:assert_eq(token.enable_priv(vm, mine, target).ret, 0, "restore")
            local before_mine = token.privileges(vm, mine).enabled
            t:assert_eq(token.disable_priv(vm, theirs, target).ret, 0, "disable it on the worker's copy")
            t:assert_eq(token.privileges(vm, mine).enabled, before_mine, "the agent's token is unchanged")
            sys.close(vm, theirs); sys.close(vm, pidfd); sys.close(vm, mine)
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
    end)

-- Threads ----------------------------------------------------------------------------

test("threads share one primary token, so an adjustment is visible to every thread",
    { spec = "PKM *token.thread.shared-primary" }, function(t)
        -- The agent's syscalls land on different threads of one thread group.
        local fd = assert(token.open_self(vm))
        local target = token.PRIV.LOCK_MEMORY
        t:assert_eq(token.disable_priv(vm, fd, target).ret, 0, "disable on one thread")
        for i = 1, 8 do
            local h = assert(token.open_self(vm))
            t:assert_eq(token.privileges(vm, h).enabled & token.bit(target), 0, "thread read " .. i .. " sees it disabled")
            t:assert_eq(id_of(h), id_of(fd), "and the same token object")
            sys.close(vm, h)
        end
        t:assert_eq(token.enable_priv(vm, fd, target).ret, 0, "restore")
        sys.close(vm, fd)
    end)

test("a new thread cloned by an impersonating thread starts on the shared primary",
    { spec = "PKM *token.thread.clone-starts-on-primary" }, function(t)
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local pid = worker:syscall(sys.NR.getpid).ret
            local pidfd = assert(token.pidfd_open(vm, pid))
            local primary = primary_of(pidfd)
            -- The worker's only thread puts on an impersonation token.
            local client = assert(token.mint(worker, { user_sid = token.SID.TEST_USER_2, projected_uid = 1102 }))
            local imp = assert(token.duplicate(worker, client, { token_type = token.TYPE.IMPERSONATION,
                impersonation_level = token.LEVEL.IMPERSONATION }))
            t:assert_eq(token.impersonate(worker, imp).ret, 0, "the worker's thread impersonates")
            local before = assert(token.effective(vm, worker))
            t:assert_eq(before.user, token.SID.TEST_USER_2, "and is running as TEST_USER_2")
            t:assert_eq(before.type, token.TYPE.IMPERSONATION, "on an impersonation token")

            -- ... and then clones one, while still wearing it.
            local sleeping = sleeping_thread(worker, 3)
            local tid = sibling_tid(pid)
            t:assert(tid, "a second thread of the same thread group appears")
            local fd = assert(token.open_thread(vm, pidfd, tid, R.QUERY))
            t:assert_eq(token.query(vm, fd, token.CLASS.USER), token.SID.LOCAL_SYSTEM,
                "the new thread's effective identity is the shared primary, not the cloner's impersonation token")
            t:assert_eq(token.query_u32(vm, fd, token.CLASS.TYPE), token.TYPE.PRIMARY, "a primary token")
            t:assert_eq(id_of(fd), id_of(primary), "and the very object the process's primary is")
            t:assert_eq(assert(token.effective(vm, worker)).user, token.SID.TEST_USER_2,
                "while the cloning thread goes on impersonating")
            sys.close(vm, fd)
            t:assert_eq(sleeping:await().ret, 0, "the new thread was blocked in the kernel throughout")
            token.revert(worker)
            sys.close(vm, primary); sys.close(vm, pidfd)
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
    end)

-- Exec ----------------------------------------------------------------------------------

test("the primary token survives execve unchanged",
    { spec = "PKM *token.exec.primary-survives" }, function(t)
        -- The agent forks and execs a long-lived copy of itself; the child's
        -- token has the parent's content (and, the image being unlabelled,
        -- its integrity level).
        local mine = assert(token.open_self(vm))
        local proc, pidfd = child_of(vm)
        local child = primary_of(pidfd)
        local diff = same_content(mine, child)
        t:assert_eq(#diff, 0, "the exec'd child's token has the parent's content: " .. table.concat(diff, ","))
        t:assert_eq(token.integrity(vm, child), token.INTEGRITY.SYSTEM, "at the parent's integrity level")
        t:assert_neq(id_of(child), id_of(mine), "as the fork's independent copy")
        proc:kill(); sys.close(vm, child); sys.close(vm, pidfd); sys.close(vm, mine)
    end)

test("a new program always starts with the primary token as its effective identity",
    { spec = "PKM *token.exec.reverts-impersonation" }, function(t)
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local pid = worker:syscall(sys.NR.getpid).ret
            local pidfd = assert(token.pidfd_open(vm, pid))
            local parent = primary_of(pidfd)
            local client = assert(token.mint(worker, { user_sid = token.SID.TEST_USER_2, projected_uid = 1102 }))
            local imp = assert(token.duplicate(worker, client, { token_type = token.TYPE.IMPERSONATION,
                impersonation_level = token.LEVEL.IMPERSONATION }))
            t:assert_eq(token.impersonate(worker, imp).ret, 0, "the spawning thread impersonates TEST_USER_2")
            t:assert_eq(assert(token.effective(vm, worker)).user, token.SID.TEST_USER_2,
                "and is running as it at the moment of the fork")

            -- run_async forks and execs from that very thread.
            local proc, cpidfd = child_of(worker)
            local effective = assert(token.open_thread(vm, cpidfd, proc:pid(), R.QUERY))
            t:assert_eq(token.query(vm, effective, token.CLASS.USER), token.SID.LOCAL_SYSTEM,
                "the new program runs as the primary token's user, not the impersonated one")
            t:assert_eq(token.query_u32(vm, effective, token.CLASS.TYPE), token.TYPE.PRIMARY,
                "on a primary token")
            local child = primary_of(cpidfd)
            t:assert_eq(id_of(effective), id_of(child), "which is its own primary token object")
            t:assert_eq(#same_content(child, parent, { PRIVILEGES = true }), 0,
                "the parent's primary, copied: " .. table.concat(same_content(child, parent, { PRIVILEGES = true }), ","))
            -- The revert is the child's; the caller keeps what it wore.
            t:assert_eq(assert(token.effective(vm, worker)).user, token.SID.TEST_USER_2,
                "and the spawning thread's own impersonation is untouched")
            token.revert(worker)
            proc:kill(); proc:wait("5s")
            sys.close(vm, effective); sys.close(vm, child); sys.close(vm, cpidfd)
            sys.close(vm, parent); sys.close(vm, pidfd)
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
    end)

-- NEW_PROCESS_MIN --------------------------------------------------------------------------
--
-- NEW_PROCESS_MIN needs a principal that execs, and something to exec.
-- The images are the agent as it ships — whose descriptor carries no
-- SACL, so it is unlabelled — and copies of it on a synthesising tmpfs
-- whose SACLs carry a mandatory label ACE. Every image's DACL grants
-- every right to everyone and the principal holds
-- SeChangeNotifyPrivilege (traverse checking is what would otherwise
-- stop it at `/`), so the label is the only thing left deciding
-- anything.

local NPM_AT = "/mnt/pit-npm"
local NPM = token.MANDATORY.NO_WRITE_UP | token.MANDATORY.NEW_PROCESS_MIN
assert(kacs.set_sd(vm, AGENT, kacs.grant(kacs.ALL_RIGHTS)).ret == 0,
    "the shipped agent is reachable by a minted user")
assert(kacs.new_mount(vm, "tmpfs", NPM_AT, kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL))
local AGENT_IMAGE = vm:read_file(AGENT)

--- A copy of the agent at `name`, executable by everyone, whose SACL
--- carries a mandatory label at `level` — or no SACL at all when
--- `level` is nil, which is what §3.2.3 means by unlabelled.
local function image(name, level)
    local p = NPM_AT .. "/" .. name
    vm:write_file(p, AGENT_IMAGE)
    assert(sys.chmod(vm, p, tonumber("755", 8)).ret == 0, "chmod " .. p)
    local sd = access.sd({
        owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
        dacl = access.acl({ access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS, token.SID.EVERYONE) }),
        sacl = level and access.acl({ access.label_ace(level, access.LABEL.NO_WRITE_UP) }) or nil,
    })
    assert(kacs.set_sd(vm, p, sd, kacs.SI.DACL | (level and kacs.SI.SACL or 0)).ret == 0,
        "descriptor on " .. p)
    return p
end

local UNLABELLED = image("unlabelled", nil)
local LOW_IMAGE = image("low", token.INTEGRITY.LOW)
local MEDIUM_IMAGE = image("medium", token.INTEGRITY.MEDIUM)
local HIGH_IMAGE = image("high", token.INTEGRITY.HIGH)

--- Mint a principal from `spec`, have it exec `binary`, and run
--- `fn(parent, child)` on handles to the principal's primary token and
--- to the primary token of the program it started.
local function exec_as(t, spec, binary, fn)
    spec.privs_present, spec.privs_enabled = CN, CN
    token.as_principal(t, vm, spec, function(w)
        local wpidfd = assert(token.pidfd_open(vm, w:syscall(sys.NR.getpid).ret))
        local parent = primary_of(wpidfd)
        local proc, pidfd = child_of(w, binary)
        local child = primary_of(pidfd)
        local ok, err = pcall(fn, parent, child)
        proc:kill(); proc:wait("5s")
        sys.close(vm, child); sys.close(vm, pidfd)
        sys.close(vm, parent); sys.close(vm, wpidfd)
        if not ok then error(err, 0) end
    end)
end

test("NEW_PROCESS_MIN replaces the primary token at exec when the image carries a lower label",
    { spec = "PKM *token.new-process-min" }, function(t)
        exec_as(t, { mandatory_policy = NPM }, LOW_IMAGE, function(parent, child)
            t:assert_eq(token.integrity(vm, parent), token.INTEGRITY.MEDIUM, "the principal is Medium")
            t:assert_eq(token.integrity(vm, child), token.INTEGRITY.LOW,
                "and the Low-labelled image it execs runs at the image's level")
            t:assert_neq(id_of(child), id_of(parent), "on a replacement token")
            t:assert_eq(token.query_u32(vm, child, token.CLASS.MANDATORY_POLICY), NPM,
                "which carries the flag on, so the mechanism applies to the whole subtree")
        end)
        -- The same principal and the same image, without the flag: the
        -- label is not consulted at all.
        exec_as(t, { mandatory_policy = token.MANDATORY.NO_WRITE_UP }, LOW_IMAGE, function(parent, child)
            t:assert_eq(token.integrity(vm, child), token.INTEGRITY.MEDIUM,
                "without NEW_PROCESS_MIN the same image leaves the token where it was")
        end)
    end)

test("an unlabelled image leaves the token unchanged",
    { spec = "PKM *token.new-process-min.unlabelled-unchanged" }, function(t)
        -- Two shapes of unlabelled: no SACL at all, and a descriptor
        -- authored by a case that names a DACL and no label ACE.
        for _, binary in ipairs({ AGENT, UNLABELLED }) do
            exec_as(t, { mandatory_policy = NPM }, binary, function(parent, child)
                t:assert_eq(token.integrity(vm, child), token.integrity(vm, parent),
                    binary .. " is unlabelled, so the token survives exec unchanged")
            end)
        end
        -- Deliberately not the access-check rule, under which an
        -- unlabelled object counts as Medium (§3.8.3) — that rule would
        -- demote every process on an unlabelled image, this one first.
        exec_as(t, { mandatory_policy = NPM, integrity_level = token.INTEGRITY.HIGH }, AGENT,
            function(parent, child)
                t:assert_eq(token.integrity(vm, parent), token.INTEGRITY.HIGH, "a High principal")
                t:assert_eq(token.integrity(vm, child), token.INTEGRITY.HIGH,
                    "stays High across an unlabelled image rather than being taken for Medium")
            end)
    end)

test("a lower label yields a DuplicateToken-shaped copy at the file's level",
    { spec = "PKM *token.new-process-min.lowers-to-file-label" }, function(t)
        exec_as(t, { mandatory_policy = NPM }, LOW_IMAGE, function(parent, child)
            local ps, cs = token.statistics(vm, parent), token.statistics(vm, child)
            t:assert_eq(token.integrity(vm, child), token.INTEGRITY.LOW, "integrity_level is the file's label")
            t:assert_neq(cs.token_id, ps.token_id, "a new token id")
            t:assert_eq(cs.modified_id, cs.token_id, "modified_id initialised to it")
            t:assert_eq(token.query_u32(vm, child, token.CLASS.ELEVATION_TYPE), token.ELEVATION.DEFAULT,
                "elevation_type reset to Default")
            local diff = same_content(parent, child, { INTEGRITY_LEVEL = true, PRIVILEGES = true })
            t:assert_eq(#diff, 0, "every other field copied from the source: " .. table.concat(diff, ","))
            local pp, cp = token.privileges(vm, parent), token.privileges(vm, child)
            t:assert_eq(cp.present, pp.present, "the privilege set with them")
            t:assert_eq(cp.enabled, pp.enabled, "enabled as it was")
            t:assert_eq(cp.default, pp.default, "and defaulting as it did")
            t:assert_eq(cs.auth_id, ps.auth_id, "in the source's LogonSession")
        end)
    end)

test("a label at or above the token's level leaves the token unchanged",
    { spec = "PKM *token.new-process-min.higher-label-unchanged" }, function(t)
        exec_as(t, { mandatory_policy = NPM }, HIGH_IMAGE, function(parent, child)
            t:assert_eq(token.integrity(vm, child), token.INTEGRITY.MEDIUM,
                "a High-labelled image does not raise a Medium token: the mechanism only lowers")
        end)
        exec_as(t, { mandatory_policy = NPM }, MEDIUM_IMAGE, function(parent, child)
            t:assert_eq(token.integrity(vm, child), token.INTEGRITY.MEDIUM,
                "and a label equal to the token's is a no-op")
            local diff = same_content(parent, child, { PRIVILEGES = true })
            t:assert_eq(#diff, 0, "the token crosses the exec as it was: " .. table.concat(diff, ","))
        end)
    end)

-- Self-installation ------------------------------------------------------------------------

test("KACS_IOC_INSTALL replaces the primary token of the calling process",
    { spec = "PKM *token.install.process-wide" }, function(t)
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local pidfd = assert(token.pidfd_open(vm, worker:syscall(sys.NR.getpid).ret))
            local before = primary_of(pidfd)
            t:assert_eq(token.sid_string(token.query(vm, before, token.CLASS.USER)), "S-1-5-18", "SYSTEM before")
            local new, e = token.mint(worker, {})
            assert(new, "mint: " .. sys.errname(e or 0))
            t:assert_eq(token.install(worker, new).ret, 0, "install")
            local after = primary_of(pidfd)
            t:assert_eq(token.query(vm, after, token.CLASS.USER), token.SID.TEST_USER, "the process's primary is now TEST_USER")
            t:assert_neq(id_of(after), id_of(before), "a different token from the one before")
            t:assert_eq(token.statistics(vm, after).auth_id, token.statistics(worker, new).auth_id,
                "in the installed token's session")
            local eff, e2 = token.open_self(worker, R.QUERY)
            assert(eff, "open_self after install: " .. sys.errname(e2 or 0))
            t:assert_eq(id_of(eff, worker), id_of(after), "and the calling thread's effective token is that primary")
            sys.close(vm, before); sys.close(vm, after); sys.close(vm, pidfd)
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
    end)

test("an impersonating thread keeps its impersonation across an install; reverting lands on the new primary",
    { spec = "PKM *token.install.impersonating-thread-keeps-cred" }, function(t)
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local client = assert(token.mint(worker, { user_sid = token.SID.TEST_USER_2, projected_uid = 1102 }))
            local imp = assert(token.duplicate(worker, client, { token_type = token.TYPE.IMPERSONATION,
                impersonation_level = token.LEVEL.IMPERSONATION }))
            assert(token.impersonate(worker, imp).ret == 0)
            local new = assert(token.mint(worker, {}))  -- minted as SYSTEM? no: as the effective TEST_USER_2
            t:assert(new, "minting while impersonating uses the effective token's privileges")
        end)
        worker:kill(); worker:join()
        -- Redo with the primary holding what the install needs.
        worker = vm:spawn_worker()
        ok, err = pcall(function()
            local pidfd = assert(token.pidfd_open(vm, worker:syscall(sys.NR.getpid).ret))
            local new = assert(token.mint(worker, {}))
            local client = assert(token.mint(worker, { user_sid = token.SID.TEST_USER_2, projected_uid = 1102 }))
            local imp = assert(token.duplicate(worker, client, { token_type = token.TYPE.IMPERSONATION,
                impersonation_level = token.LEVEL.IMPERSONATION }))
            assert(token.impersonate(worker, imp).ret == 0)
            -- The install is judged on the real token (SYSTEM), and replaces real_cred only.
            local r = token.install(worker, new)
            t:assert_eq(r.ret, 0, "install while impersonating: " .. sys.errname(r.errno or 0))
            local installed = primary_of(pidfd)
            t:assert_eq(token.query(vm, installed, token.CLASS.USER), token.SID.TEST_USER, "real_cred is the new primary, TEST_USER")
            local eff = assert(token.open_self(worker, R.QUERY))
            t:assert_eq(token.query(worker, eff, token.CLASS.USER), token.SID.TEST_USER_2, "cred still holds the impersonation token")
            t:assert_eq(token.revert(worker).ret, 0, "revert")
            eff = assert(token.open_self(worker, R.QUERY))
            t:assert_eq(id_of(eff, worker), id_of(installed), "reverting lands on the new primary, not the old one")
            sys.close(vm, pidfd)
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
    end)

test("installing needs TOKEN_ASSIGN_PRIMARY, a primary token, and SeAssignPrimaryTokenPrivilege on the real token",
    { spec = "PKM *token.install.gates" }, function(t)
        local ASSIGN, CREATE = token.bit(token.PRIV.ASSIGN_PRIMARY_TOKEN), token.bit(token.PRIV.CREATE_TOKEN)
        -- Handle without the right; an impersonation-type token.
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local new = assert(token.mint(worker, {}))
            local narrow = assert(token.duplicate(worker, new, { access = R.ALL_ACCESS & ~R.ASSIGN_PRIMARY }))
            t:assert_eq(token.install(worker, narrow).errno, sys.E.ACCES, "without TOKEN_ASSIGN_PRIMARY: EACCES")
            local imp = assert(token.duplicate(worker, new, { token_type = token.TYPE.IMPERSONATION,
                impersonation_level = token.LEVEL.IMPERSONATION }))
            t:assert_eq(token.install(worker, imp).errno, sys.E.INVAL, "an impersonation token cannot be a primary: EINVAL")
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
        -- The privilege is judged on the real token, and marked used.
        local IMP = token.bit(token.PRIV.IMPERSONATE)
        token.as_principal(t, vm, { privs_present = TCB | CREATE | ASSIGN | IMP, privs_enabled = TCB | CREATE | IMP }, function(w)
            local own = assert(token.open_self(w, R.QUERY | R.ADJUST_PRIVS))
            local mine = assert(token.mint(w, {}))
            t:assert_eq(token.install(w, mine).errno, sys.E.ACCES, "SeAssignPrimaryTokenPrivilege held but disabled: EACCES")
            -- An impersonated token carrying it enabled does not help. The
            -- donor is another user (a self-minted token's descriptor would
            -- not grant its creator TOKEN_IMPERSONATE), so SeImpersonatePrivilege
            -- is what lets the principal wear it.
            local donor = assert(token.mint(w, { user_sid = token.SID.TEST_USER_2, projected_uid = 1102,
                privs_present = ASSIGN, privs_enabled = ASSIGN }))
            local dimp, de = token.duplicate(w, donor, { access = R.QUERY | R.IMPERSONATE,
                token_type = token.TYPE.IMPERSONATION, impersonation_level = token.LEVEL.IMPERSONATION })
            assert(dimp, "duplicate the donor: " .. sys.errname(de or 0))
            assert(token.impersonate(w, dimp).ret == 0, "impersonate the donor")
            t:assert_eq(token.install(w, mine).errno, sys.E.ACCES, "the effective token's privilege does not satisfy the gate")
            assert(token.revert(w).ret == 0)
            t:assert_eq(token.enable_priv(w, own, token.PRIV.ASSIGN_PRIMARY_TOKEN).ret, 0, "enable it on the real token")
            t:assert_eq(token.privileges(w, own).used & ASSIGN, 0, "not yet used")
            t:assert_eq(token.install(w, mine).ret, 0, "now the install succeeds")
            -- `own` still names the outgoing token object; the used mark landed there.
            t:assert(token.privileges(w, own).used & ASSIGN ~= 0, "and the privilege is marked used")
        end)
    end)

test("without SeTcbPrivilege the installed token has to share the caller's user SID and LogonSession",
    { spec = "PKM *token.install.same-user-same-session-unless-tcb" }, function(t)
        local ASSIGN, CREATE = token.bit(token.PRIV.ASSIGN_PRIMARY_TOKEN), token.bit(token.PRIV.CREATE_TOKEN)
        token.as_principal(t, vm, { privs_present = TCB | CREATE | ASSIGN, privs_enabled = TCB | CREATE | ASSIGN }, function(w)
            local own = assert(token.open_self(w, R.QUERY | R.ADJUST_PRIVS))
            local my_session = token.statistics(w, own).auth_id
            -- Candidates, minted while SeTcbPrivilege is still enabled.
            local other_user = assert(token.mint(w, { user_sid = token.SID.TEST_USER_2, projected_uid = 1102 }))
            local other_session = assert(token.mint(w, {}))
            -- Same identity, same session; keeps SeTcbPrivilege (disabled) and
            -- SeAssignPrimaryTokenPrivilege so the second install can follow.
            local same = assert(token.create(w, { auth_id = my_session, privs_present = TCB | ASSIGN, privs_enabled = ASSIGN }))
            t:assert_eq(token.disable_priv(w, own, token.PRIV.TCB).ret, 0, "drop SeTcbPrivilege")
            t:assert_eq(token.install(w, other_user).errno, sys.E.PERM, "another user SID: EPERM")
            t:assert_eq(token.install(w, other_session).errno, sys.E.PERM, "same user, another LogonSession: EPERM")
            t:assert_eq(token.install(w, same).ret, 0, "same user and session: installs")
            -- Now as the new primary (same identity), re-enable SeTcbPrivilege
            -- on it and install a token of another user and session.
            local own2 = assert(token.open_self(w, R.QUERY | R.ADJUST_PRIVS))
            t:assert(token.privileges(w, own2).present & TCB ~= 0, "the same-identity token was minted with SeTcbPrivilege")
            t:assert_eq(token.enable_priv(w, own2, token.PRIV.TCB).ret, 0, "enable it")
            t:assert_eq(token.install(w, other_user).ret, 0, "with SeTcbPrivilege the identity constraints are bypassed")
            local eff = assert(token.open_self(w, R.QUERY))
            t:assert_eq(token.query(w, eff, token.CLASS.USER), token.SID.TEST_USER_2, "the caller is now TEST_USER_2")
        end)
    end)

test("sibling threads converge through queued credential work with no completion barrier",
    { spec = "PKM *token.install.siblings-converge-asynchronously" }, function(t)
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local pid = worker:syscall(sys.NR.getpid).ret
            local pidfd = assert(token.pidfd_open(vm, pid))
            -- A sibling that is blocked in the kernel for the whole
            -- transition, so nothing it does can be mistaken for a
            -- credential switch it performed itself.
            local sleeping = sleeping_thread(worker, 3)
            local sibling = sibling_tid(pid)
            t:assert(sibling, "the worker has a second thread")
            local function sibling_user()
                local fd, e = token.open_thread(vm, pidfd, sibling, R.QUERY)
                assert(fd, "open_thread on the sibling: " .. sys.errname(e or 0))
                local u = token.query(vm, fd, token.CLASS.USER)
                sys.close(vm, fd)
                return u
            end
            t:assert_eq(sibling_user(), token.SID.LOCAL_SYSTEM, "which starts on the shared SYSTEM primary")

            local new = assert(token.mint(worker, {}))
            t:assert_eq(token.install(worker, new).ret, 0, "the main thread installs a TEST_USER primary")
            local eff = assert(token.open_self(worker, R.QUERY))
            t:assert_eq(token.query(worker, eff, token.CLASS.USER), token.SID.TEST_USER,
                "the installing thread is on it immediately")

            -- No barrier is exposed, so the sibling is polled: the claim
            -- is that its own queued credential work converges, not when.
            local polls, converged = 0, false
            for i = 1, 300 do
                polls = i
                if sibling_user() == token.SID.TEST_USER then converged = true; break end
                sys.nanosleep(vm, 0, 10 * 1000 * 1000)
            end
            t:assert(converged, "the sibling converges on the new primary without one")
            t:log("the sibling was observed on the new primary after " .. polls .. " poll(s)")
            t:assert_eq(sleeping:await().ret, 0, "having stayed blocked in the kernel across the switch")
            sys.close(vm, pidfd)
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
    end)

test("the process descriptor is regenerated when the installed token's user SID differs, else preserved",
    { spec = "PKM *token.install.process-sd-regenerated-on-sid-change" }, function(t)
        local function process_sd(pidfd)
            local r = vm:syscall(kacs.SYS.GET_SD, {
                args = { pidfd, 0, kacs.SI.OWNER | kacs.SI.DACL, 0, 4096, sys.AT_EMPTY_PATH },
                bufs = { sys.cstr(""), string.rep("\0", 4096) }, ptrs = { 1, 3 } })
            assert(r.ret >= 0, "process get_sd: " .. sys.errname(r.errno or 0))
            return token.parse_sd(r.out_bufs[2]:sub(1, r.ret))
        end
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local pidfd = assert(token.pidfd_open(vm, worker:syscall(sys.NR.getpid).ret))
            t:assert_eq(process_sd(pidfd).owner, token.SID.LOCAL_SYSTEM, "owned by SYSTEM before")
            local a = assert(token.mint(worker, {}))
            t:assert_eq(token.install(worker, a).ret, 0, "install TEST_USER")
            t:assert_eq(process_sd(pidfd).owner, token.SID.TEST_USER, "regenerated: owned by TEST_USER")
            -- Customise the process DACL, then install another TEST_USER token.
            local custom = access.sd({ dacl = access.acl({
                access.ace(access.ACE.ALLOWED, 0x1FFFFF, token.SID.LOCAL_SYSTEM),
                access.ace(access.ACE.ALLOWED, 0x1000, token.SID.EVERYONE) }) })
            local set = vm:syscall(kacs.SYS.SET_SD, { args = { pidfd, 0, kacs.SI.DACL, 0, #custom, sys.AT_EMPTY_PATH },
                bufs = { sys.cstr(""), custom }, ptrs = { 1, 3 } })
            t:assert_eq(set.ret, 0, "customise the process DACL: " .. sys.errname(set.errno or 0))
            local marker = token.find_ace(process_sd(pidfd).dacl, token.SID.EVERYONE, 0)
            t:assert(marker and marker.mask == 0x1000, "the custom ACE is there")
            -- The worker is now TEST_USER without SeAssignPrimaryTokenPrivilege; the agent
            -- cannot install for it, so give it what the install needs.
            local b = assert(token.mint(vm, { auth_id = token.statistics(worker, a).auth_id }))
            sys.close(vm, b)
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
        -- Same-SID reinstall, from a principal that keeps SeAssignPrimaryTokenPrivilege.
        local ASSIGN, CREATE = token.bit(token.PRIV.ASSIGN_PRIMARY_TOKEN), token.bit(token.PRIV.CREATE_TOKEN)
        token.as_principal(t, vm, { privs_present = ASSIGN | CREATE | TCB, privs_enabled = ASSIGN | CREATE | TCB }, function(w)
            local pidfd = assert(token.pidfd_open(vm, w:syscall(sys.NR.getpid).ret))
            t:assert_eq(process_sd(pidfd).owner, token.SID.TEST_USER, "installed at spawn: owned by TEST_USER")
            local custom = access.sd({ dacl = access.acl({
                access.ace(access.ACE.ALLOWED, 0x1FFFFF, token.SID.LOCAL_SYSTEM),
                access.ace(access.ACE.ALLOWED, 0x1000, token.SID.EVERYONE) }) })
            assert(vm:syscall(kacs.SYS.SET_SD, { args = { pidfd, 0, kacs.SI.DACL, 0, #custom, sys.AT_EMPTY_PATH },
                bufs = { sys.cstr(""), custom }, ptrs = { 1, 3 } }).ret == 0)
            local same = assert(token.mint(w, {}))  -- TEST_USER again, another session
            local r = token.install(w, same)
            t:assert_eq(r.ret, 0, "reinstall a same-SID token: " .. sys.errname(r.errno or 0))
            local sd = process_sd(pidfd)
            t:assert_eq(sd.owner, token.SID.TEST_USER, "owner unchanged")
            local marker = token.find_ace(sd.dacl, token.SID.EVERYONE, 0)
            t:assert(marker and marker.mask == 0x1000, "the custom DACL is preserved")
            sys.close(vm, pidfd)
        end)
    end)

-- Bootstrap tokens ----------------------------------------------------------------------------

test("the SYSTEM token is hardcoded at kernel init and inherited by PID 1",
    { spec = "PKM *token.bootstrap.system-token" }, function(t)
        local fd = assert(token.open_self(vm))
        t:assert_eq(token.sid_string(token.query(vm, fd, token.CLASS.USER)), "S-1-5-18", "S-1-5-18")
        local groups = assert(token.groups(vm, fd))
        for _, s in ipairs({ token.SID.ADMINISTRATORS, token.SID.EVERYONE, token.SID.AUTHENTICATED_USERS }) do
            t:assert(token.find_group(groups, s), token.sid_string(s) .. " present")
        end
        local p = assert(token.privileges(vm, fd))
        local all = 0
        for _, bit in pairs(token.PRIV) do all = all | token.bit(bit) end
        t:assert_eq(p.present & all, all, "every defined privilege present")
        t:assert_eq(p.enabled & all, all, "and enabled")
        t:assert_eq(token.integrity(vm, fd), token.INTEGRITY.SYSTEM, "integrity System")
        t:assert_eq(token.query_u32(vm, fd, token.CLASS.TYPE), token.TYPE.PRIMARY, "Primary")
        t:assert_eq(token.query_u32(vm, fd, token.CLASS.IMPERSONATION_LEVEL), token.LEVEL.DELEGATION, "Delegation")
        t:assert_eq(token.query_u32(vm, fd, token.CLASS.ELEVATION_TYPE), token.ELEVATION.DEFAULT, "elevation Default")
        t:assert_eq(token.source(vm, fd).name, "PeiosKrn", "source PeiosKrn")
        t:assert_eq(vm:syscall(102).ret, 0, "projected UID 0")
        t:assert_eq(token.statistics(vm, fd).auth_id, token.SYSTEM_LUID, "auth_id SYSTEM_LUID")
        -- PID 1 carries it too.
        local pidfd1 = assert(token.pidfd_open(vm, 1))
        local pid1 = assert(token.open_process(vm, pidfd1))
        t:assert_eq(token.sid_string(token.query(vm, pid1, token.CLASS.USER)), "S-1-5-18", "PID 1 is SYSTEM")
        sys.close(vm, pid1); sys.close(vm, pidfd1); sys.close(vm, fd)
    end)

test("the Anonymous token has the fixed boot shape",
    { spec = "PKM *token.bootstrap.anonymous-token" }, function(t)
        local src = assert(token.mint(vm, {}))
        local anon = assert(token.duplicate(vm, src, { token_type = token.TYPE.IMPERSONATION,
            impersonation_level = token.LEVEL.ANONYMOUS }))
        t:assert_eq(token.sid_string(token.query(vm, anon, token.CLASS.USER)), "S-1-5-7", "S-1-5-7")
        local groups = assert(token.groups(vm, anon))
        t:assert(#groups == 1 and groups[1].sid == token.SID.EVERYONE, "Everyone as the only group")
        t:assert_eq(token.privileges(vm, anon).present, 0, "no privileges")
        t:assert_eq(token.integrity(vm, anon), token.INTEGRITY.UNTRUSTED, "Untrusted")
        t:assert_eq(token.query_u32(vm, anon, token.CLASS.LOGON_TYPE), token.LOGON_TYPE.NETWORK, "logon type Network")
        t:assert_eq(token.query_u32(vm, anon, token.CLASS.TYPE), token.TYPE.IMPERSONATION, "Impersonation")
        t:assert_eq(token.query_u32(vm, anon, token.CLASS.IMPERSONATION_LEVEL), token.LEVEL.ANONYMOUS, "level Anonymous")
        t:assert_eq(token.query_u32(vm, anon, token.CLASS.ELEVATION_TYPE), token.ELEVATION.DEFAULT, "elevation Default")
        t:assert_eq(token.source(vm, anon).name, "PeiosKrn", "source PeiosKrn")
        t:assert_eq(token.statistics(vm, anon).auth_id, token.ANONYMOUS_LOGON_LUID, "auth_id ANONYMOUS_LOGON_LUID")
        -- Effectively immutable: nothing to adjust.
        t:assert(token.enable_priv(vm, anon, token.PRIV.TCB).ret ~= 0, "no privilege to enable")
        t:assert(token.adjust_groups(vm, anon, { { 0, 0 } }).ret ~= 0, "Everyone is mandatory: cannot disable")
        sys.close(vm, anon); sys.close(vm, src)
    end)

test("DuplicateToken to Anonymous mints a fresh object each time",
    { spec = "PKM *token.bootstrap.anonymous-singleton-vs-duplicate" }, function(t)
        local src = assert(token.mint(vm, {}))
        local a = assert(token.duplicate(vm, src, { token_type = token.TYPE.IMPERSONATION, impersonation_level = token.LEVEL.ANONYMOUS }))
        local b = assert(token.duplicate(vm, src, { token_type = token.TYPE.IMPERSONATION, impersonation_level = token.LEVEL.ANONYMOUS }))
        t:assert_neq(id_of(a), id_of(b), "two duplicates are two objects, not the global singleton")
        t:assert_eq(token.statistics(vm, a).auth_id, token.ANONYMOUS_LOGON_LUID, "both in the Anonymous session")
        -- (A peer token captured at Anonymous level references the singleton: imp-*.test.lua.)
        sys.close(vm, a); sys.close(vm, b); sys.close(vm, src)
    end)

test("dynamic LogonSessions start at 1000; 999 and 998 are the kernel's",
    { spec = "PKM *token.bootstrap.reserved-luids" }, function(t)
        local ids = {}
        for i = 1, 5 do ids[i] = assert(token.create_logon_session(vm, {})) end
        for i, id in ipairs(ids) do
            t:assert(id >= 1000, "session " .. i .. " is " .. id)
            if i > 1 then t:assert(id > ids[i - 1], "and ids increase") end
        end
        t:assert_eq(token.statistics(vm, assert(token.open_self(vm))).auth_id, 999, "SYSTEM is 999")
        local src = assert(token.mint(vm, {}))
        local anon = assert(token.duplicate(vm, src, { token_type = token.TYPE.IMPERSONATION, impersonation_level = token.LEVEL.ANONYMOUS }))
        t:assert_eq(token.statistics(vm, anon).auth_id, 998, "Anonymous is 998")
        for _, id in ipairs(ids) do token.destroy_empty_logon_session(vm, id) end
        sys.close(vm, anon); sys.close(vm, src)
    end)

test("SYSTEM carries SeBackupPrivilege and SeRestorePrivilege present and enabled at boot",
    { spec = "PKM *token.bootstrap.system-backup-restore-present" }, function(t)
        local p = assert(token.privileges(vm, assert(token.open_self(vm))))
        t:assert_eq(p.present & (BACKUP | RESTORE), BACKUP | RESTORE, "present")
        t:assert_eq(p.enabled & (BACKUP | RESTORE), BACKUP | RESTORE, "enabled")
    end)

test("backup and restore intent grant read and write regardless of the DACL",
    { spec = "PKM *token.bootstrap.backup-restore-intent-bypasses-dacl" }, function(t)
        local me = assert(token.open_self(vm))
        local deny_all = access.simple({})
        t:assert(access.check(vm, { token_fd = me, sd = deny_all, desired = 0x1 }).denied, "no intent: read denied")
        t:assert(access.check(vm, { token_fd = me, sd = deny_all, desired = 0x1, intent = access.INTENT.BACKUP }).ok,
            "backup intent: read granted")
        t:assert(access.check(vm, { token_fd = me, sd = deny_all, desired = 0x2, intent = access.INTENT.RESTORE }).ok,
            "restore intent: write granted")
        t:assert(access.check(vm, { token_fd = me, sd = deny_all, desired = 0x2, intent = access.INTENT.BACKUP }).denied,
            "backup intent does not grant write")
        sys.close(vm, me)
    end)

test("FACS passes the backup intent of a native open into AccessCheck",
    { spec = "PKM *token.bootstrap.backup-restore-intent-bypasses-dacl", tags = { "known-bug" } }, function(t)
        -- <pkm/file.h> defines KACS_BACKUP_INTENT / KACS_RESTORE_INTENT for
        -- kacs_open_how.flags, and §3.2.3 says FACS passes the intent into
        -- AccessCheck. kacs_open accepts only the AT_* bits in flags and
        -- refuses the intent bits with EINVAL; the open path passes no
        -- intent at all.
        local mount = "/mnt/pit-intent"
        assert(kacs.new_mount(vm, "tmpfs", mount, kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL))
        local f = assert(sys.open(vm, mount .. "/f", sys.O.WRONLY | sys.O.CREAT, 420)); sys.close(vm, f)
        assert(kacs.set_sd(vm, mount .. "/f", kacs.deny_all()).ret == 0)
        local plain, e = kacs.open(vm, mount .. "/f", { access = kacs.RIGHT.READ_DATA })
        t:assert(not plain and e == sys.E.ACCES, "a plain native open is denied")
        local fd, e2 = kacs.open(vm, mount .. "/f", { access = kacs.RIGHT.READ_DATA, flags = 0x1 })
        t:assert(fd, "with KACS_BACKUP_INTENT it opens: " .. sys.errname(e2 or 0))
        if fd then sys.close(vm, fd) end
    end)

test("external token replacement is not built: INSTALL only ever targets the caller",
    { spec = "PKM *token.external-replacement-not-built" }, function(t)
        -- No syscall or ioctl names a target process. Installing a token
        -- opened from another process's pidfd changes the caller, not the target.
        token.as_principal(t, vm, {}, function(a)
            local a_pidfd_in_b
            local b = vm:spawn_worker()
            local ok, err = pcall(function()
                local a_pid = a:syscall(sys.NR.getpid).ret
                a_pidfd_in_b = assert(token.pidfd_open(b, a_pid))
                local a_tok = assert(token.open_process(b, a_pidfd_in_b))
                t:assert_eq(token.install(b, a_tok).ret, 0, "B installs A's token")
                local b_eff = assert(token.open_self(b, R.QUERY))
                t:assert_eq(token.query(b, b_eff, token.CLASS.USER), token.SID.TEST_USER, "B became TEST_USER")
                local a_pidfd = assert(token.pidfd_open(vm, a_pid))
                local a_now = primary_of(a_pidfd)
                t:assert_eq(token.query(vm, a_now, token.CLASS.USER), token.SID.TEST_USER, "A is what it was")
                sys.close(vm, a_now); sys.close(vm, a_pidfd)
            end)
            b:kill(); b:join()
            if not ok then error(err, 0) end
        end)
        -- And the retired syscall numbers around the token range stay holes.
        for _, nr in ipairs({ 1007, 1008, 1009, 1010, 1011, 1013 }) do
            t:assert_eq(vm:syscall(nr, 0, 0, 0).errno, sys.E.NOSYS, "syscall " .. nr .. " is ENOSYS")
        end
    end)

-- Last: this leaves one agent thread impersonating for the rest of the VM.
test("each thread keeps independent impersonation state",
    { spec = "PKM *token.thread.independent-impersonation" }, function(t)
        -- The agent's connection is served by several threads. Impersonating
        -- on it affects exactly the thread that ran the ioctl; the next
        -- syscalls, landing on other threads, still see the primary.
        local prim = assert(token.mint(vm, {}))
        local imp = assert(token.duplicate(vm, prim, { token_type = token.TYPE.IMPERSONATION,
            impersonation_level = token.LEVEL.IMPERSONATION }))
        t:assert_eq(token.impersonate(vm, imp).ret, 0, "impersonate on one agent thread")
        local seen_system, seen_user = false, false
        for _ = 1, 24 do
            local fd = token.open_self(vm, R.QUERY)
            if fd then
                local u = token.query(vm, fd, token.CLASS.USER)
                if u == token.SID.TEST_USER then seen_user = true else seen_system = true end
                sys.close(vm, fd)
            end
        end
        t:assert(seen_system, "other threads of the process still run on the primary")
        t:log("the impersonating thread was observed: " .. tostring(seen_user))
    end)
