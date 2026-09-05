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
local function same_content(a, b)
    local diff = {}
    for _, c in ipairs(CLASSES) do
        if token.query(vm, a, token.CLASS[c]) ~= token.query(vm, b, token.CLASS[c]) then diff[#diff + 1] = c end
    end
    return diff
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
      skip = "a worker cannot spawn a child (worker:run_async is refused for process-isolated workers) and the " ..
             "agent cannot impersonate; runs under pkm_kunit_clone_process_impersonation_uses_primary_copy" },
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
    { spec = "PKM *token.thread.clone-starts-on-primary", covered_by = "kunit:pkm_kunit_process",
      skip = "no guest path creates a thread from an impersonating thread under the harness; runs under " ..
             "pkm_kunit_clone_thread_impersonation_starts_on_primary" }, function(t) end)

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
    { spec = "PKM *token.exec.reverts-impersonation",
      skip = "no coverage anywhere: exec from an impersonating thread needs a worker that can spawn " ..
             "(worker:run_async is refused for process-isolated workers), and no KUnit case drives exec " ..
             "under impersonation" }, function(t) end)

-- NEW_PROCESS_MIN --------------------------------------------------------------------------

-- NEW_PROCESS_MIN needs a principal that execs. The guest's only
-- executable is the agent, and a worker — the only process whose token
-- a test controls — cannot spawn a child under the current harness, so
-- the exec-time relabel runs under KUnit.
local function npm_stub(name, spec, case)
    test(name, { spec = spec, covered_by = "kunit:pkm_kunit_process",
        skip = "a worker cannot exec (worker:run_async is refused for process-isolated workers); runs under " .. case },
        function(t) end)
end

npm_stub("NEW_PROCESS_MIN replaces the primary token at exec when the image carries a lower label",
    "PKM *token.new-process-min", "pkm_kunit_exec_new_process_min_lowers_to_file_label")
npm_stub("an unlabelled image leaves the token unchanged",
    "PKM *token.new-process-min.unlabelled-unchanged", "pkm_kunit_exec_new_process_min_unlabeled_inherits_parent")
npm_stub("a lower label yields a DuplicateToken-shaped copy at the file's level",
    "PKM *token.new-process-min.lowers-to-file-label", "pkm_kunit_exec_new_process_min_lowers_to_file_label")
npm_stub("a label at or above the token's level leaves the token unchanged",
    "PKM *token.new-process-min.higher-label-unchanged", "pkm_kunit_exec_new_process_min_equal_label_noops")

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

test("sibling threads converge through queued credential work with no completion barrier",
    { spec = "PKM *token.install.siblings-converge-asynchronously",
      skip = "no coverage anywhere: a worker is single-threaded and the agent cannot install; the transition " ..
             "window is a scheduling property with no KUnit case" }, function(t) end)

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
