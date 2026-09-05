-- PKM §3.4.1 — the privilege model: the lifecycle of a privilege on a
-- token, the two enforcement categories, intent gating, and the used-bit
-- accounting every gate performs (immediately for the shared helper,
-- late for the three gates that mark after a further check).
--
-- The agent is SYSTEM and holds every privilege enabled, so it passes
-- every gate. Each case here therefore mints a principal that holds
-- exactly the privileges the claim is about and installs it in a worker.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local access = require("helpers.access")
local kmes = require("helpers.kmes")
local hooks = require("helpers.hooks")

local vm = provium:vm("v", "kernel-only"):boot()

local P = token.PRIV
local NR = { reboot = 169, settimeofday = 164, sched_setaffinity = 203,
             open_by_handle_at = 304 }
-- reboot(2)'s harmless command: LINUX_REBOOT_CMD_CAD_OFF takes the same
-- CAP_SYS_BOOT gate as a real shutdown and does nothing observable.
local REBOOT_MAGIC1, REBOOT_MAGIC2, CAD_OFF = 0xfee1dead, 672274793, 0

--- The mask for a list of privilege bit indices.
local function mask(bits)
    local m = 0
    for _, b in ipairs(bits) do m = m | token.bit(b) end
    return m
end

--- Run `fn(worker)` as a principal holding exactly `bits`, present and
--- enabled. `spec` overrides anything else about the token.
local function as(t, bits, fn, spec)
    local s = { privs_present = mask(bits), privs_enabled = mask(bits) }
    for k, v in pairs(spec or {}) do s[k] = v end
    token.as_principal(t, vm, s, fn)
end

--- The worker's own four privilege words, through its own handle.
local function words(w)
    local fd, errno = token.open_self(w, token.RIGHT.QUERY)
    assert(fd, "open_self: " .. sys.errname(errno or 0))
    local p = assert(token.privileges(w, fd))
    sys.close(w, fd)
    return p
end

local function hex(v) return ("0x%X"):format(v) end

-- Lifecycle ------------------------------------------------------------------

test("a privilege absent at creation can never be added later",
    { spec = "PKM *priv.lifecycle.no-runtime-grants" }, function(t)
        as(t, { P.TCB }, function(w)
            local fd = assert(token.open_self(w, token.RIGHT.QUERY | token.RIGHT.ADJUST_PRIVS))
            local before = assert(token.privileges(w, fd))
            t:assert_eq(before.present & token.bit(P.SHUTDOWN), 0,
                "SeShutdownPrivilege is not present to begin with")
            local r = token.enable_priv(w, fd, P.SHUTDOWN)
            t:assert(r.ret ~= 0, "enabling an absent privilege is refused")
            -- §3.4.1 names no errno for the refusal; the kernel says EINVAL.
            t:assert_eq(r.errno, sys.E.INVAL, "with EINVAL")
            local after = assert(token.privileges(w, fd))
            t:assert_eq(after.present, before.present, "the present set is unchanged")
            t:assert_eq(after.enabled, before.enabled, "and so is the enabled set")
            sys.close(w, fd)
            -- And the gate it would have opened stays shut.
            t:assert_eq(w:syscall(NR.reboot, REBOOT_MAGIC1, REBOOT_MAGIC2, CAD_OFF, 0).errno,
                sys.E.PERM, "reboot is still EPERM")
        end)
    end)

test("the enabled set has to be a subset of the present set at creation",
    { spec = "PKM *priv.enabled-subset-of-present" }, function(t)
        local fd, errno = token.mint(vm, { privs_present = mask({ P.TCB }),
            privs_enabled = mask({ P.TCB, P.SHUTDOWN }) })
        t:assert(not fd, "an enabled bit outside the present set is refused")
        t:assert_eq(errno, sys.E.INVAL, "EINVAL")
        local ok = assert(token.mint(vm, { privs_present = mask({ P.TCB, P.SHUTDOWN }),
            privs_enabled = mask({ P.TCB }) }))
        local p = assert(token.privileges(vm, ok))
        t:assert_eq(p.present, mask({ P.TCB, P.SHUTDOWN }), "a proper subset mints")
        t:assert_eq(p.enabled, mask({ P.TCB }), "with the enabled set as supplied")
        t:assert_eq(p.default, mask({ P.TCB }),
            "and the creation-time enabled set is the enabled-by-default set")
        sys.close(vm, ok)
    end)

test("a gate checks that the privilege is enabled, not merely present",
    { spec = "PKM *priv.check.enabled-not-just-present" }, function(t)
        -- SeSystemtimePrivilege present but disabled: settimeofday is a
        -- standalone gate through CAP_SYS_TIME (§3.4.2).
        local clock = string.pack("<i8i8", 1800000000, 0)
        as(t, {}, function(w)
            local fd = assert(token.open_self(w, token.RIGHT.QUERY | token.RIGHT.ADJUST_PRIVS))
            local p = assert(token.privileges(w, fd))
            t:assert_eq(p.present & token.bit(P.SYSTEMTIME), token.bit(P.SYSTEMTIME),
                "SeSystemtimePrivilege is present")
            t:assert_eq(p.enabled & token.bit(P.SYSTEMTIME), 0, "and disabled")
            local r = w:syscall(NR.settimeofday, { args = { 0, 0 }, bufs = { clock }, ptrs = { 0 } })
            t:assert(r.ret ~= 0, "present-but-disabled does not open the gate")
            t:assert_eq(r.errno, sys.E.PERM, "EPERM")
            t:assert_eq(assert(token.privileges(w, fd)).used & token.bit(P.SYSTEMTIME), 0,
                "and nothing is recorded as used")
            t:assert_eq(token.enable_priv(w, fd, P.SYSTEMTIME).ret, 0, "the holder enables it")
            r = w:syscall(NR.settimeofday, { args = { 0, 0 }, bufs = { clock }, ptrs = { 0 } })
            t:assert_eq(r.ret, 0, "and the same call now passes: " .. sys.errname(r.errno))
            t:assert_eq(assert(token.privileges(w, fd)).used & token.bit(P.SYSTEMTIME),
                token.bit(P.SYSTEMTIME), "the exercise is recorded")
            sys.close(w, fd)
        end, { privs_present = mask({ P.SYSTEMTIME }), privs_enabled = 0 })
    end)

test("removing a privilege clears present, enabled and default but keeps the used bit",
    { spec = "PKM *priv.remove.preserves-used-bit" }, function(t)
        as(t, { P.TCB }, function(w)
            -- Exercise it: creating a LogonSession takes SeTcbPrivilege.
            assert(token.create_logon_session(w, {}), "the principal exercises SeTcbPrivilege")
            local fd = assert(token.open_self(w, token.RIGHT.QUERY | token.RIGHT.ADJUST_PRIVS))
            local before = assert(token.privileges(w, fd))
            t:assert_eq(before.used & token.bit(P.TCB), token.bit(P.TCB), "the used bit is set")
            t:assert_eq(token.remove_priv(w, fd, P.TCB).ret, 0, "the privilege is removed")
            local after = assert(token.privileges(w, fd))
            t:assert_eq(after.present & token.bit(P.TCB), 0, "present is cleared")
            t:assert_eq(after.enabled & token.bit(P.TCB), 0, "enabled is cleared")
            t:assert_eq(after.default & token.bit(P.TCB), 0, "enabled-by-default is cleared")
            t:assert_eq(after.used & token.bit(P.TCB), token.bit(P.TCB),
                "and the used bit survives for audit")
            sys.close(w, fd)
        end)
    end)

-- Used-bit accounting --------------------------------------------------------

test("the shared privilege helper marks the bit as soon as the gate accepts it",
    { spec = "PKM *priv.used.helper-marks-immediately" }, function(t)
        -- open_by_handle_at goes through pkm_kacs_require_enabled_privilege
        -- for SeChangeNotifyPrivilege and nothing else; a garbage handle
        -- then fails the syscall well after the gate has passed.
        local handle = string.pack("<I4i4", 8, 1) .. string.rep("\0", 8)
        as(t, { P.CHANGE_NOTIFY }, function(w)
            t:assert_eq(words(w).used & token.bit(P.CHANGE_NOTIFY), 0,
                "the fresh principal has not exercised SeChangeNotifyPrivilege")
            local r = w:syscall(NR.open_by_handle_at,
                { args = { sys.AT_FDCWD, 0, 0 }, bufs = { handle }, ptrs = { 1 } })
            t:assert(r.ret < 0, "the call fails on the handle itself")
            t:assert_eq(r.errno, sys.E.STALE, "ESTALE, which is past the privilege gate")
            t:assert_eq(words(w).used & token.bit(P.CHANGE_NOTIFY), token.bit(P.CHANGE_NOTIFY),
                "and the bit was marked the moment the gate accepted it")
        end)
        -- Without the privilege the same call stops at the gate.
        as(t, {}, function(w)
            local r = w:syscall(NR.open_by_handle_at,
                { args = { sys.AT_FDCWD, 0, 0 }, bufs = { handle }, ptrs = { 1 } })
            t:assert_eq(r.errno, sys.E.PERM, "EPERM without SeChangeNotifyPrivilege")
        end)
    end)

test("a used bit is recorded even when a later independent check denies the operation",
    { spec = "PKM *priv.used.recorded-despite-later-denial" }, function(t)
        -- sched_setaffinity on another process takes
        -- SeIncreaseBasePriorityPrivilege as a standalone gate and *then*
        -- an access check against the target's process descriptor.
        local victim = vm:spawn_worker()
        local ok, err = pcall(function()
            local vpid = victim:syscall(sys.NR.getpid).ret
            local vfd = assert(token.mint(victim, { user_sid = token.SID.TEST_USER_2 }))
            assert(token.install(victim, vfd).ret == 0, "the victim runs as another user")
            local affinity = { args = { vpid, 8, 0 }, bufs = { string.pack("<I8", 1) }, ptrs = { 2 } }
            as(t, { P.INCREASE_BASE_PRIORITY }, function(w)
                local r = w:syscall(NR.sched_setaffinity, affinity)
                t:assert(r.ret ~= 0, "the target's process descriptor denies the caller")
                t:assert_eq(r.errno, sys.E.ACCES, "EACCES")
                t:assert_eq(words(w).used & token.bit(P.INCREASE_BASE_PRIORITY),
                    token.bit(P.INCREASE_BASE_PRIORITY),
                    "and the privilege the gate accepted is still recorded as used")
            end)
            as(t, {}, function(w)
                local r = w:syscall(NR.sched_setaffinity, affinity)
                t:assert(r.ret ~= 0, "without the privilege the gate itself refuses")
                t:assert_eq(words(w).used, 0, "and nothing is recorded")
            end)
        end)
        victim:kill(); victim:join()
        if not ok then error(err, 0) end
    end)

test("token creation marks SeCreateTokenPrivilege only after the specification is accepted",
    { spec = "PKM *priv.used.create-token-marks-late" }, function(t)
        as(t, { P.TCB, P.CREATE_TOKEN }, function(w)
            local session = assert(token.create_logon_session(w, {}))
            -- A malformed specification: the version field is not the ABI's.
            local bad, errno = token.create(w, { auth_id = session, version = 0xFFFF })
            t:assert(not bad, "a malformed specification is refused: " .. sys.errname(errno or 0))
            t:assert_eq(words(w).used & token.bit(P.CREATE_TOKEN), 0,
                "and leaves SeCreateTokenPrivilege unmarked — the gate marks after construction")
            local good = assert(token.create(w, { auth_id = session }))
            t:assert_eq(words(w).used & token.bit(P.CREATE_TOKEN), token.bit(P.CREATE_TOKEN),
                "a token that is actually built marks it")
            sys.close(w, good)
        end)
    end)

test("primary installation marks SeAssignPrimaryTokenPrivilege only after the same-user gate",
    { spec = "PKM *priv.used.install-marks-late" }, function(t)
        -- A principal with SeCreateTokenPrivilege and
        -- SeAssignPrimaryTokenPrivilege but no SeTcbPrivilege: §3.4.2 says
        -- installation then requires the same user SID and LogonSession.
        as(t, { P.CREATE_TOKEN, P.ASSIGN_PRIMARY_TOKEN }, function(w)
            local self_fd = assert(token.open_self(w, token.RIGHT.QUERY))
            local session = assert(token.statistics(w, self_fd)).auth_id
            sys.close(w, self_fd)
            -- The gate marks the *caller's* primary token, which a
            -- successful install then replaces, so hold a handle on it.
            local before = assert(token.open_self(w, token.RIGHT.QUERY))
            local stranger = assert(token.create(w, { auth_id = session,
                user_sid = token.SID.TEST_USER_2 }))
            local r = token.install(w, stranger)
            t:assert(r.ret ~= 0, "installing another user's token is refused")
            t:assert_eq(r.errno, sys.E.PERM, "EPERM")
            t:assert_eq(assert(token.privileges(w, before)).used & token.bit(P.ASSIGN_PRIMARY_TOKEN),
                0, "and the privilege is not marked — the gate marks after that check")
            sys.close(w, stranger)
            local mine = assert(token.create(w, { auth_id = session }))
            t:assert_eq(token.install(w, mine).ret, 0, "the same user in the same session installs")
            t:assert_eq(assert(token.privileges(w, before)).used & token.bit(P.ASSIGN_PRIMARY_TOKEN),
                token.bit(P.ASSIGN_PRIMARY_TOKEN), "and that marks it")
            sys.close(w, before); sys.close(w, mine)
        end)
    end)

test("the CAP_SYS_BOOT mapping marks SeShutdownPrivilege only after the remote-origin gate",
    { spec = "PKM *priv.used.cap-sys-boot-marks-late" }, function(t)
        as(t, { P.SHUTDOWN }, function(w)
            local r = w:syscall(NR.reboot, REBOOT_MAGIC1, REBOOT_MAGIC2, CAD_OFF, 0)
            t:assert(r.ret ~= 0, "a Network-logon caller without SeRemoteShutdownPrivilege is refused")
            t:assert_eq(r.errno, sys.E.PERM, "EPERM")
            t:assert_eq(words(w).used & token.bit(P.SHUTDOWN), 0,
                "and SeShutdownPrivilege is unmarked — the mapping marks after the origin gate")
        end, { logon_type = token.LOGON_TYPE.NETWORK })
        as(t, { P.SHUTDOWN, P.REMOTE_SHUTDOWN }, function(w)
            local r = w:syscall(NR.reboot, REBOOT_MAGIC1, REBOOT_MAGIC2, CAD_OFF, 0)
            t:assert_eq(r.ret, 0, "with both, the reboot request is accepted: " .. sys.errname(r.errno))
            t:assert_eq(words(w).used & token.bit(P.SHUTDOWN), token.bit(P.SHUTDOWN),
                "and only then is SeShutdownPrivilege marked")
        end, { logon_type = token.LOGON_TYPE.NETWORK })
    end)

test("a gate whose used-bit record fails returns EPERM or EACCES rather than proceeding",
    { spec = "PKM *priv.used.record-failure-fails-operation",
      covered_by = "kunit:pkm_kunit_misc",
      skip = "kacs_rust_token_mark_privileges_used is an atomic fetch_or that " ..
             "fails only for a NULL token pointer, which no gate can reach with a " ..
             "live credential; runs under " ..
             "pkm_kunit_privilege_use_record_failure_fails_the_gate, which makes " ..
             "the recorder fail and watches the capability and manage-volume gates " ..
             "refuse what they had just admitted" },
    function(t) end)

-- The two enforcement categories ---------------------------------------------

test("exactly five privileges alter the outcome of AccessCheck",
    { spec = "PKM *priv.accesscheck.five-privileges" }, function(t)
        -- A descriptor whose DACL is present and empty grants nobody
        -- anything, so every grant below is the privilege's doing.
        local nothing = access.simple({}, { owner = token.SID.TEST_USER,
            group = token.SID.TEST_USER })
        local function granted_with(bits, desired, intent, sd)
            local fd = assert(token.mint(vm, { privs_present = mask(bits),
                privs_enabled = mask(bits), token_type = token.TYPE.IMPERSONATION,
                impersonation_level = token.LEVEL.IMPERSONATION }))
            local r = access.check(vm, { token_fd = fd, sd = sd or nothing,
                desired = desired, intent = intent })
            sys.close(vm, fd)
            return r
        end
        local ASS, WRITE_OWNER = 0x01000000, 0x00080000
        t:assert(granted_with({ P.SECURITY }, ASS).ok,
            "SeSecurityPrivilege grants ACCESS_SYSTEM_SECURITY")
        t:assert(granted_with({ P.TAKE_OWNERSHIP }, WRITE_OWNER).ok,
            "SeTakeOwnershipPrivilege grants WRITE_OWNER")
        t:assert(granted_with({ P.BACKUP }, access.STD.READ_CONTROL | 0x1,
            access.INTENT.BACKUP).ok, "SeBackupPrivilege grants read access")
        local restore = granted_with({ P.RESTORE }, 0x2 | access.STD.WRITE_DAC
            | WRITE_OWNER | access.STD.DELETE | ASS, access.INTENT.RESTORE)
        t:assert(restore.ok, "SeRestorePrivilege grants write, WRITE_DAC, WRITE_OWNER, DELETE and "
            .. "ACCESS_SYSTEM_SECURITY")
        -- SeRelabelPrivilege does not grant WRITE_OWNER; it loosens MIC's
        -- constraint on it, so the object needs a label the caller does
        -- not dominate and a DACL that would otherwise have granted it.
        local high_label = access.sd({
            owner = token.SID.TEST_USER, group = token.SID.TEST_USER,
            sacl = access.acl({ access.label_ace(token.INTEGRITY.HIGH,
                access.LABEL.NO_WRITE_UP) }),
            dacl = access.acl({ access.ace(access.ACE.ALLOWED, WRITE_OWNER,
                token.SID.EVERYONE) }) })
        t:assert(granted_with({}, WRITE_OWNER, nil, high_label).denied,
            "MIC blocks WRITE_OWNER for a Medium caller against a High label")
        t:assert(granted_with({ P.RELABEL }, WRITE_OWNER, nil, high_label).ok,
            "SeRelabelPrivilege loosens that constraint")
        -- And a standalone-only privilege changes nothing in the pipeline.
        local tcb = granted_with({ P.TCB, P.SHUTDOWN, P.DEBUG, P.CHANGE_NOTIFY }, 0x1)
        t:assert(tcb.denied, "SeTcbPrivilege and its standalone peers grant nothing: "
            .. sys.errname(tcb.errno))
    end)

test("backup and restore are evaluated only when the matching intent flag is set",
    { spec = "PKM *priv.intent-gating" }, function(t)
        local nothing = access.simple({}, { owner = token.SID.TEST_USER,
            group = token.SID.TEST_USER })
        local fd = assert(token.mint(vm, {
            privs_present = mask({ P.BACKUP, P.RESTORE }),
            privs_enabled = mask({ P.BACKUP, P.RESTORE }),
            token_type = token.TYPE.IMPERSONATION,
            impersonation_level = token.LEVEL.IMPERSONATION }))
        local bare = access.check(vm, { token_fd = fd, sd = nothing, desired = 0x1 })
        t:assert(bare.denied, "without BACKUP_INTENT the privilege is invisible: "
            .. sys.errname(bare.errno))
        t:assert_eq(assert(token.privileges(vm, fd)).used & mask({ P.BACKUP, P.RESTORE }), 0,
            "and neither privilege is recorded as used")
        local backed = access.check(vm, { token_fd = fd, sd = nothing, desired = 0x1,
            intent = access.INTENT.BACKUP })
        t:assert(backed.ok, "with BACKUP_INTENT it grants read: " .. sys.errname(backed.errno))
        local written = access.check(vm, { token_fd = fd, sd = nothing, desired = 0x2,
            intent = access.INTENT.RESTORE })
        t:assert(written.ok, "and RESTORE_INTENT grants write: " .. sys.errname(written.errno))
        local wrong = access.check(vm, { token_fd = fd, sd = nothing, desired = 0x2,
            intent = access.INTENT.BACKUP })
        t:assert(wrong.denied, "backup intent does not carry restore's grant: "
            .. sys.errname(wrong.errno))
        sys.close(vm, fd)
    end)

-- Auditing --------------------------------------------------------------------

test("every standalone gate emits an ftrace event",
    { spec = "PKM *priv.audit.ftrace-per-standalone-gate" }, function(t)
        -- The shared helper's gate, reached through open_by_handle_at.
        local handle = string.pack("<I4i4", 8, 1) .. string.rep("\0", 8)
        t:assert(hooks.trace_start(vm, "kacs/kacs_privilege"), "kacs_privilege tracing starts")
        as(t, {}, function(w)
            w:syscall(NR.open_by_handle_at,
                { args = { sys.AT_FDCWD, 0, 0 }, bufs = { handle }, ptrs = { 1 } })
        end)
        local lines = hooks.trace_stop(vm, "kacs/kacs_privilege")
        local want = ("privilege=0x%x"):format(token.bit(P.CHANGE_NOTIFY))
        local seen = false
        for _, line in ipairs(lines) do
            if line:find(want, 1, true) and line:find("verdict=deny", 1, true) then seen = true end
        end
        t:assert(seen, "the refused SeChangeNotifyPrivilege gate is on the ring ("
            .. #lines .. " kacs_privilege lines)")

        -- And the capability-mapped gate, reached through reboot(2).
        t:assert(hooks.trace_start(vm, "kacs/kacs_capability"), "kacs_capability tracing starts")
        as(t, {}, function(w)
            w:syscall(NR.reboot, REBOOT_MAGIC1, REBOOT_MAGIC2, CAD_OFF, 0)
        end)
        local caps = hooks.trace_stop(vm, "kacs/kacs_capability")
        local shutdown = ("privilege=0x%x"):format(token.bit(P.SHUTDOWN))
        seen = false
        for _, line in ipairs(caps) do
            if line:find(shutdown, 1, true) then seen = true end
        end
        t:assert(seen, "the refused CAP_SYS_BOOT gate names SeShutdownPrivilege ("
            .. #caps .. " kacs_capability lines)")
    end)

test("a privilege-use event for SeSecurity or SeTakeOwnership means the privilege was load-bearing",
    { spec = "PKM *priv.audit.security-takeownership-counterfactual" }, function(t)
        local WRITE_OWNER = 0x00080000
        local nothing = access.simple({}, { owner = token.SID.TEST_USER,
            group = token.SID.TEST_USER })
        local already = access.simple(
            { access.ace(access.ACE.ALLOWED, WRITE_OWNER, token.SID.EVERYONE) },
            { owner = token.SID.TEST_USER, group = token.SID.TEST_USER })
        local fd = assert(token.mint(vm, {
            privs_present = mask({ P.TAKE_OWNERSHIP, P.SECURITY }),
            privs_enabled = mask({ P.TAKE_OWNERSHIP, P.SECURITY }),
            audit_policy = token.AUDIT.PRIVILEGE_USE_SUCCESS,
            token_type = token.TYPE.IMPERSONATION,
            impersonation_level = token.LEVEL.IMPERSONATION }))
        local quiet = kmes.recording(t, vm, function()
            local r = access.check(vm, { token_fd = fd, sd = already, desired = WRITE_OWNER })
            t:assert(r.ok, "the DACL grants WRITE_OWNER on its own: " .. sys.errname(r.errno))
        end)
        t:assert_eq(#kmes.of_type(quiet, "privilege-use"), 0,
            "no privilege-use event where take-ownership contributed nothing")
        local loud = kmes.recording(t, vm, function()
            local r = access.check(vm, { token_fd = fd, sd = nothing, desired = WRITE_OWNER })
            t:assert(r.ok, "the privilege alone grants it: " .. sys.errname(r.errno))
        end)
        local events = kmes.of_type(loud, "privilege-use")
        t:assert_eq(#events, 1, "and that fires exactly one privilege-use event")
        t:assert_eq(events[1].payload.privilege, "SeTakeOwnershipPrivilege", "naming the privilege")
        local sacl = kmes.recording(t, vm, function()
            local r = access.check(vm, { token_fd = fd, sd = nothing, desired = 0x01000000 })
            t:assert(r.ok, "SeSecurityPrivilege pre-decides ACCESS_SYSTEM_SECURITY: "
                .. sys.errname(r.errno))
        end)
        local sec = kmes.of_type(sacl, "privilege-use")
        t:assert_eq(#sec, 1, "which is itself counterfactual and fires one event")
        t:assert_eq(sec[1].payload.privilege, "SeSecurityPrivilege", "naming SeSecurityPrivilege")
        sys.close(vm, fd)
    end)

test("backup and restore fire privilege-use events even where the DACL would have granted the access",
    { spec = "PKM *priv.audit.backup-restore-not-counterfactual" }, function(t)
        local already = access.simple(
            { access.ace(access.ACE.ALLOWED, 0x1 | 0x2, token.SID.EVERYONE) },
            { owner = token.SID.TEST_USER, group = token.SID.TEST_USER })
        local fd = assert(token.mint(vm, {
            privs_present = mask({ P.BACKUP, P.RESTORE }),
            privs_enabled = mask({ P.BACKUP, P.RESTORE }),
            audit_policy = token.AUDIT.PRIVILEGE_USE_SUCCESS,
            token_type = token.TYPE.IMPERSONATION,
            impersonation_level = token.LEVEL.IMPERSONATION }))
        local events = kmes.recording(t, vm, function()
            local r = access.check(vm, { token_fd = fd, sd = already, desired = 0x1,
                intent = access.INTENT.BACKUP })
            t:assert(r.ok, "the DACL grants FILE_READ_DATA to Everyone: " .. sys.errname(r.errno))
        end)
        local uses = kmes.of_type(events, "privilege-use")
        t:assert_eq(#uses, 1, "and the event fires anyway — backup seeds its bits unconditionally")
        t:assert_eq(uses[1].payload.privilege, "SeBackupPrivilege", "naming SeBackupPrivilege")
        local restore = kmes.recording(t, vm, function()
            local r = access.check(vm, { token_fd = fd, sd = already, desired = 0x2,
                intent = access.INTENT.RESTORE })
            t:assert(r.ok, "and FILE_WRITE_DATA likewise: " .. sys.errname(r.errno))
        end)
        local ruses = kmes.of_type(restore, "privilege-use")
        t:assert_eq(#ruses, 1, "restore fires its event on an access the DACL already permitted")
        t:assert_eq(ruses[1].payload.privilege, "SeRestorePrivilege", "naming SeRestorePrivilege")
        sys.close(vm, fd)
    end)
