-- PKM §3.C — the audit records KACS emits through KMES: which event
-- each family produces, the fields the appendix pins down, and the
-- delivery contract.
--
-- Every record is read from the KMES ring directly (helpers/kmes):
-- there is no userspace here to run a consumer. A case attaches, drives
-- the operation, and drains the window its own operation occupied.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local access = require("helpers.access")
local facs = require("helpers.facs")
local kmes = require("helpers.kmes")
local stratafs = require("helpers.stratafs")

local vm = provium:vm("v", "kernel-only"):boot()

local B = facs.workspace(vm, "auditev")
local A, STD, AUDIT = access.ACE, access.STD, token.AUDIT
local U = token.SID.TEST_USER
local MAP = { read = 0x1, write = 0x2, execute = 0x4,
    all = 0x7 | STD.WRITE_OWNER | STD.READ_CONTROL
        | STD.ACCESS_SYSTEM_SECURITY }

--- Every right kacs_open accepts in a desired mask: FILE_DELETE_CHILD
--- is a parent-directory right the native open refuses outright.
local OPENABLE = kacs.ALL_RIGHTS & ~kacs.RIGHT.DELETE_CHILD

local function mint(spec)
    local fd, e = token.mint(vm, spec or {})
    assert(fd, "mint: " .. sys.errname(e or 0))
    return fd
end

--- Attach, run, drain: the shape every case here wants.
local function recorded(t, fn)
    local ring, errno = kmes.attach(vm, 0)
    t:assert(ring, "a KMES ring attaches: " .. sys.errname(errno or 0))
    local ok, err = pcall(fn, ring)
    local events = kmes.drain(ring)
    kmes.detach(ring)
    if not ok then error(err, 0) end
    return events
end

--- kacs_access_check with the argument block written field by field, so
--- a case can hand the call an output pointer that cannot be written.
local function raw_check(opts)
    local blob = string.rep("\0", access.ARGS_SIZE)
    local function put(off, fmt, v)
        local p = string.pack(fmt, v)
        blob = blob:sub(1, off) .. p .. blob:sub(off + #p + 1)
    end
    local m = opts.mapping or MAP
    put(0, "<I4", access.ARGS_SIZE)
    put(4, "<i4", opts.token_fd or -1)
    put(20, "<I4", opts.desired or 0)
    put(24, "<I4", m.read); put(28, "<I4", m.write)
    put(32, "<I4", m.execute); put(36, "<I4", m.all)
    for _, f in ipairs(opts.fields or {}) do put(f[1], f[2], f[3]) end
    local bufs, nested = { "" }, {}
    for _, c in ipairs(opts.children or {}) do
        bufs[#bufs + 1] = c.bytes
        nested[#nested + 1] = { parent = 1, child = #bufs, offset = c.at }
    end
    bufs[1] = blob
    return vm:syscall(access.SYS.ACCESS_CHECK, {
        args = { 0 }, bufs = bufs, ptrs = { 0 }, nested = nested,
    })
end

--- A descriptor with a SACL that audits `flags` outcomes for `mask`.
local function audited(mask, flags, dacl)
    return access.sd({ owner = token.SID.LOCAL_SYSTEM,
        group = token.SID.LOCAL_SYSTEM,
        dacl = dacl or access.acl({ access.ace(A.ALLOWED, MAP.all, U) }),
        sacl = access.acl({ access.ace(A.AUDIT, mask, U, flags) }) })
end

test("every KACS record carries origin class 2",
    { spec = "PKM *audit-events.origin-class-two" }, function(t)
        local seen = {}
        local events = recorded(t, function()
            -- One record from each of the three families a single
            -- process can drive without a filesystem: an audited access,
            -- a privilege use, and a session teardown.
            local BACKUP = token.bit(token.PRIV.BACKUP)
            local fd = mint({ audit_policy = AUDIT.OBJECT_ACCESS_SUCCESS
                | AUDIT.PRIVILEGE_USE_SUCCESS,
                privs_present = BACKUP, privs_enabled = BACKUP })
            access.check(vm, { token_fd = fd, sd = access.simple({}),
                desired = 0x1, intent = access.INTENT.BACKUP, mapping = MAP })
            local doomed = mint({})
            sys.close(vm, doomed)
            sys.close(vm, fd)
        end)
        for _, e in ipairs(events) do
            if e.type == "access-audit" or e.type == "privilege-use"
                or e.type == "logon-session-destroyed" then
                seen[e.type] = true
                t:assert_eq(e.origin, kmes.ORIGIN.KACS,
                    e.type .. " is stamped KMES_ORIGIN_KACS (2)")
            end
        end
        t:assert(seen["access-audit"], "an access-audit record was produced")
        t:assert(seen["privilege-use"], "a privilege-use record too")
        t:assert(seen["logon-session-destroyed"],
            "and a logon-session-destroyed record")
    end)

test("access-audit comes from the SACL walk and from token audit policy",
    { spec = "PKM *audit-events.access-audit-record" }, function(t)
        -- The SACL walk: the token's own policy is zero, and the
        -- descriptor asks for the record.
        local from_sacl = recorded(t, function()
            local fd = mint({})
            access.check(vm, { token_fd = fd,
                sd = audited(0x1, access.ACE_FLAG.SUCCESSFUL_ACCESS),
                desired = 0x1, mapping = MAP })
            sys.close(vm, fd)
        end)
        local walk = kmes.of_type(from_sacl, "access-audit")
        t:assert_eq(#walk, 1, "the SACL walk emits one access-audit record")
        t:assert_eq(walk[1].payload.success, true,
            "reporting the outcome it audited")
        t:assert(walk[1].payload.subject,
            "with the resolved subject attached at emission")
        t:assert(walk[1].payload.process,
            "and the calling process")
        -- Token audit-policy forcing: the descriptor has no SACL at all.
        local from_policy = recorded(t, function()
            local fd = mint({ audit_policy = AUDIT.OBJECT_ACCESS_FAILURE })
            access.check(vm, { token_fd = fd, sd = access.simple({}),
                desired = 0x1, mapping = MAP })
            sys.close(vm, fd)
        end)
        local forced = kmes.of_type(from_policy, "access-audit")
        t:assert_eq(#forced, 1,
            "the token's own audit policy forces one without a SACL")
        t:assert_eq(forced[1].payload.success, false,
            "for the failure it was asked to audit")
    end)

test("continuous-audit comes from an enforcement point, per operation",
    { spec = "PKM *audit-events.continuous-audit-record" }, function(t)
        local p = B .. "/continuous"
        vm:write_file(p, "hello")
        local sd = access.sd({ owner = token.SID.LOCAL_SYSTEM,
            group = token.SID.LOCAL_SYSTEM,
            dacl = access.acl({ access.ace(A.ALLOWED, kacs.ALL_RIGHTS,
                kacs.SID.EVERYONE) }),
            sacl = access.acl({ access.ace(A.ALARM, kacs.ALL_RIGHTS,
                kacs.SID.EVERYONE, access.ACE_FLAG.SUCCESSFUL_ACCESS
                    | access.ACE_FLAG.FAILED_ACCESS) }) })
        t:assert_eq(kacs.set_sd(vm, p, sd, kacs.SI.OWNER | kacs.SI.GROUP
            | kacs.SI.DACL | kacs.SI.SACL).ret, 0,
            "the file carries a continuous-audit mask")
        local events = recorded(t, function()
            local fd = facs.open(vm, p, { access = OPENABLE })
            t:assert(fd, "a handle with the whole mask")
            sys.read(vm, fd, 3)
            sys.flock(vm, fd, sys.LOCK_SH)
            sys.close(vm, fd)
        end)
        local records = kmes.of_type(events, "continuous-audit")
        t:assert(#records >= 2,
            "one record per operation, not one per handle: " .. #records)
        local payload = records[1].payload
        t:assert(payload.operation, "each names its enforcement point")
        t:assert(payload.matched_access and payload.matched_access ~= 0,
            "and the part of the handle's continuous mask it matched")
        t:assert(payload.granted_access, "alongside the granted mask")
        t:assert(payload.subject and payload.process,
            "with the shared subject and process sub-maps")
    end)

test("privilege-use comes from privilege-use auditing on a check",
    { spec = "PKM *audit-events.privilege-use-record" }, function(t)
        local BACKUP = token.bit(token.PRIV.BACKUP)
        local events = recorded(t, function()
            local fd = mint({ privs_present = BACKUP, privs_enabled = BACKUP,
                audit_policy = AUDIT.PRIVILEGE_USE_SUCCESS })
            local r = access.check(vm, { token_fd = fd,
                sd = access.simple({}), desired = 0x1,
                intent = access.INTENT.BACKUP, mapping = MAP })
            t:assert(r.ok, "SeBackupPrivilege grants read against an empty DACL")
            sys.close(vm, fd)
        end)
        local records = kmes.of_type(events, "privilege-use")
        t:assert_eq(#records, 1, "one privilege-use record")
        local p = records[1].payload
        t:assert_eq(p.privilege, "SeBackupPrivilege",
            "naming the privilege that influenced the check")
        t:assert_eq(p.success, true, "and whether its bits survived")
        t:assert(p.requested_access and p.granted_access
            and p.surviving_access, "with the three masks the record carries")
    end)

test("caap-policy-diagnostic comes from a staged-versus-effective mismatch",
    { spec = "PKM *audit-events.caap-policy-diagnostic-record" }, function(t)
        local policy = token.sid(5, 21, 1000, 2000, 3000, 9101)
        local effective = access.acl({ access.ace(A.ALLOWED, 0x1, U) })
        local staged = access.acl({ access.ace(A.ALLOWED, 0x3, U) })
        t:assert_eq(access.set_caap(vm, policy, access.caap_spec({
            { effective_dacl = effective, staged_dacl = staged } })).ret, 0,
            "a policy whose staged rules differ from its effective ones")
        local events = recorded(t, function()
            local fd = mint({})
            local sd = access.sd({ owner = U, group = U,
                dacl = access.acl({ access.ace(A.ALLOWED, 0x7,
                    kacs.SID.EVERYONE) }),
                sacl = access.acl({
                    access.ace(A.SCOPED_POLICY_ID, 0, policy) }) })
            local r = access.check(vm, { token_fd = fd, sd = sd,
                desired = 0x3, mapping = MAP })
            t:assert_eq(r.staging_mismatch, 1,
                "the check reports the mismatch to its caller")
            sys.close(vm, fd)
        end)
        local records = kmes.of_type(events, "caap-policy-diagnostic")
        t:assert_eq(#records, 1, "and emits one diagnostic record")
        local p = records[1].payload
        t:assert_eq(p.kind, "staging-mismatch", "of the mismatch kind")
        t:assert_eq(p.effective_granted_access & 0x3, 0x1,
            "carrying what the effective rules granted")
        t:assert_eq(p.staged_granted_access & 0x3, 0x3,
            "and what the staged rules would have")
        t:assert_neq(p.effective_granted_access, p.staged_granted_access,
            "which is the mismatch the record exists to report")
        access.set_caap(vm, policy, nil)
    end)

test("logon-session-destroyed comes from LogonSession teardown",
    { spec = "PKM *audit-events.logon-session-destroyed-record" }, function(t)
        local session
        local events = recorded(t, function()
            local fd, sid = token.mint(vm,
                { logon_type = token.LOGON_TYPE.SERVICE,
                  auth_package = "Kerberos" })
            t:assert(fd, "a session with one token: " .. sys.errname(sid or 0))
            session = sid
            sys.close(vm, fd)
        end)
        local records = {}
        for _, e in ipairs(kmes.of_type(events, "logon-session-destroyed")) do
            if e.payload and e.payload.session_id == session then
                records[#records + 1] = e
            end
        end
        t:assert_eq(#records, 1,
            "the last token going emits one teardown record")
        local p = records[1].payload
        t:assert_eq(p.logon_type, token.LOGON_TYPE.SERVICE,
            "carrying the session's logon type")
        t:assert_eq(p.auth_package, "Kerberos", "its authentication package")
        t:assert(p.user_sid, "the authenticated user's SID")
        t:assert(p.created_at, "and when the session was created")
    end)

test("corrupt-sd comes from a descriptor xattr that fails validation",
    { spec = "PKM *audit-events.corrupt-sd-record",
      covered_by = "kunit:pkm_kunit_file",
      skip = "the canonical descriptor xattr cannot be written through " ..
             "the xattr surface — the metadata hook refuses it as " ..
             "KACS_META_CANONICAL_SD even for SYSTEM — so a guest " ..
             "cannot author the corrupt stored SD this record reports; " ..
             "it runs under " ..
             "pkm_kunit_file_sd_cache_population_corrupt_emits_once" },
    function(t) end)

test("STRATAFS_COPY_UP comes from the copy-up lifecycle",
    { spec = "PKM *audit-events.stratafs-copy-up-record" }, function(t)
        stratafs.with(vm, "auditev-copy-up", {
            { name = "dest", flags = { "create" } },
            { name = "src", flags = { "ro" }, entries = { f = "original" } },
        }, function(s)
            local events = kmes.recording(t, vm, function()
                t:assert(stratafs.try_write(vm, s:join("f"), "modified"),
                    "a write to a read-only stratum copies up")
            end)
            local records = kmes.of_type(events, "STRATAFS_COPY_UP")
            t:assert_eq(#records, 1, "which emits one STRATAFS_COPY_UP record")
            t:assert_eq(records[1].origin, kmes.ORIGIN.KACS,
                "through KACS's kernel-only emitter")
            t:assert(records[1].payload.path,
                "naming the object that was copied")
            t:assert_eq(records[1].payload.result_errno, 0,
                "and the outcome of the copy")
        end)
    end)

test("STRATAFS_MUTATION_REFUSED comes from an arrangement refusal",
    { spec = "PKM *audit-events.stratafs-mutation-refused-record" }, function(t)
        stratafs.with(vm, "auditev-refused", {
            { name = "only", flags = { "ro" }, entries = { f = "x" } },
        }, function(s)
            local events = kmes.recording(t, vm, function()
                local ok, errno = stratafs.try_create(vm, s:join("new"), "x")
                t:assert(not ok and errno == sys.E.ROFS,
                    "a create with no create stratum is refused")
            end)
            local records = kmes.of_type(events, "STRATAFS_MUTATION_REFUSED")
            t:assert_eq(#records, 1,
                "which emits one STRATAFS_MUTATION_REFUSED record")
            t:assert_eq(records[1].origin, kmes.ORIGIN.KACS,
                "through KACS's kernel-only emitter")
            t:assert(records[1].payload.operation,
                "naming the arrangement that was refused")
            t:assert_eq(records[1].payload.result_errno, -sys.E.ROFS,
                "and the errno it was refused with")
        end)
    end)

test("only five privilege names are representable in a privilege-use record",
    { spec = "PKM *audit-events.privilege-five-canonical-names" }, function(t)
        local P = token.PRIV
        local POLICY = AUDIT.PRIVILEGE_USE_SUCCESS | AUDIT.PRIVILEGE_USE_FAILURE
        local label_sd = access.sd({ owner = token.SID.LOCAL_SYSTEM,
            group = token.SID.LOCAL_SYSTEM,
            dacl = access.acl({ access.ace(A.ALLOWED, MAP.all,
                kacs.SID.EVERYONE) }),
            sacl = access.acl({ access.label_ace(token.INTEGRITY.MEDIUM,
                access.LABEL.NO_WRITE_UP) }) })
        local cases = {
            { "SeBackupPrivilege", P.BACKUP, 0x1,
              { intent = access.INTENT.BACKUP } },
            { "SeRestorePrivilege", P.RESTORE, 0x2,
              { intent = access.INTENT.RESTORE } },
            { "SeSecurityPrivilege", P.SECURITY, STD.ACCESS_SYSTEM_SECURITY, {} },
            { "SeTakeOwnershipPrivilege", P.TAKE_OWNERSHIP, STD.WRITE_OWNER, {} },
            -- SeRelabelPrivilege restores WRITE_OWNER to a caller the
            -- mandatory label would otherwise strip it from.
            { "SeRelabelPrivilege", P.RELABEL, STD.WRITE_OWNER,
              { sd = label_sd, integrity_level = token.INTEGRITY.LOW } },
        }
        for _, c in ipairs(cases) do
            local bit = token.bit(c[2])
            local events = recorded(t, function()
                local fd = mint({ privs_present = bit, privs_enabled = bit,
                    audit_policy = POLICY,
                    integrity_level = c[4].integrity_level })
                access.check(vm, { token_fd = fd,
                    sd = c[4].sd or access.simple({}), desired = c[3],
                    intent = c[4].intent, mapping = MAP })
                sys.close(vm, fd)
            end)
            local records = kmes.of_type(events, "privilege-use")
            t:assert_eq(#records, 1, c[1] .. " produces one record")
            t:assert_eq(records[1].payload.privilege, c[1],
                "under its canonical name")
        end
    end)

test("no other privilege ever appears in a privilege-use record",
    { spec = "PKM *audit-events.privilege-encoder-fails-closed" }, function(t)
        -- The encoder has a name for five privileges and refuses
        -- anything else rather than emitting an unnamed one, which is
        -- consistent with those being the only five that can influence a
        -- check at all: a token full of the others audits nothing.
        local POLICY = AUDIT.PRIVILEGE_USE_SUCCESS | AUDIT.PRIVILEGE_USE_FAILURE
        local FIVE = token.bit(token.PRIV.SECURITY)
            | token.bit(token.PRIV.TAKE_OWNERSHIP)
            | token.bit(token.PRIV.BACKUP) | token.bit(token.PRIV.RESTORE)
            | token.bit(token.PRIV.RELABEL)
        local others = 0
        for _, index in pairs(token.PRIV) do
            local bit = token.bit(index)
            if bit & FIVE == 0 then others = others | bit end
        end
        local events = recorded(t, function()
            local fd = mint({ privs_present = others, privs_enabled = others,
                audit_policy = POLICY })
            t:assert(access.check(vm, { token_fd = fd,
                sd = access.simple({ access.ace(A.ALLOWED, 0x1, U) }),
                desired = 0x1, mapping = MAP }).ok, "a granted check")
            t:assert(access.check(vm, { token_fd = fd,
                sd = access.simple({}), desired = 0x1, mapping = MAP }).denied,
                "and a denied one")
            sys.close(vm, fd)
        end)
        t:assert_eq(#kmes.of_type(events, "privilege-use"), 0,
            "every other privilege enabled at once, and no record at all")
        -- And nothing that does emit carries a name outside the five.
        local NAMED = { SeSecurityPrivilege = true,
            SeTakeOwnershipPrivilege = true, SeBackupPrivilege = true,
            SeRestorePrivilege = true, SeRelabelPrivilege = true }
        local BACKUP = token.bit(token.PRIV.BACKUP)
        local emitted = recorded(t, function()
            local fd = mint({ privs_present = BACKUP | others,
                privs_enabled = BACKUP | others, audit_policy = POLICY })
            access.check(vm, { token_fd = fd, sd = access.simple({}),
                desired = 0x1, intent = access.INTENT.BACKUP, mapping = MAP })
            sys.close(vm, fd)
        end)
        local records = kmes.of_type(emitted, "privilege-use")
        t:assert(#records > 0, "a token holding one of the five does emit")
        for _, e in ipairs(records) do
            t:assert(NAMED[e.payload.privilege],
                "and never an unnamed privilege: " ..
                tostring(e.payload.privilege))
        end
    end)

test("continuous-audit names its enforcement point from a fixed vocabulary",
    { spec = "PKM *audit-events.continuous-operation-names" }, function(t)
        local NAMES = { ["file.access"] = true, ["file.mmap"] = true,
            ["file.mprotect"] = true, ["file.permission"] = true,
            ["file.write"] = true, ["file.ioctl"] = true,
            ["file.lock"] = true, ["file.fcntl"] = true,
            ["file.truncate"] = true, ["file.fallocate"] = true }
        local p = B .. "/opnames"
        vm:write_file(p, "hello")
        local sd = access.sd({ owner = token.SID.LOCAL_SYSTEM,
            group = token.SID.LOCAL_SYSTEM,
            dacl = access.acl({ access.ace(A.ALLOWED, kacs.ALL_RIGHTS,
                kacs.SID.EVERYONE) }),
            sacl = access.acl({ access.ace(A.ALARM, kacs.ALL_RIGHTS,
                kacs.SID.EVERYONE, access.ACE_FLAG.SUCCESSFUL_ACCESS
                    | access.ACE_FLAG.FAILED_ACCESS) }) })
        t:assert_eq(kacs.set_sd(vm, p, sd, kacs.SI.OWNER | kacs.SI.GROUP
            | kacs.SI.DACL | kacs.SI.SACL).ret, 0, "a fully audited file")
        local events = recorded(t, function()
            local fd = facs.open(vm, p, { access = OPENABLE })
            t:assert(fd, "a handle with the whole mask")
            sys.read(vm, fd, 3)
            sys.flock(vm, fd, sys.LOCK_SH)
            sys.ftruncate(vm, fd, 2)
            sys.fallocate(vm, fd, 0, 0, 4096)
            local addr = sys.mmap(vm, fd, 4096, sys.PROT.READ, sys.MAP.SHARED)
            if addr then
                vm:syscall(sys.NR.mprotect, addr, 4096, sys.PROT.READ)
                sys.munmap(vm, addr, 4096)
            end
            facs.ioctl(vm, fd, sys.FS_IOC_GETFLAGS, string.pack("<I8", 0))
            sys.close(vm, fd)
        end)
        local seen = {}
        for _, e in ipairs(kmes.of_type(events, "continuous-audit")) do
            local op = e.payload and e.payload.operation
            t:assert(NAMES[op], "an operation outside the ten: " ..
                tostring(op))
            seen[op] = true
        end
        for _, want in ipairs({ "file.access", "file.permission",
                                "file.lock", "file.truncate",
                                "file.fallocate", "file.mmap",
                                "file.mprotect", "file.ioctl" }) do
            t:assert(seen[want], "the vocabulary's `" .. want ..
                "` enforcement point is named")
        end
    end)

test("a continuous-audit record's object_context is always nil",
    { spec = "PKM *audit-events.continuous-object-context-nil" }, function(t)
        local p = B .. "/objctx"
        vm:write_file(p, "hello")
        local sd = access.sd({ owner = token.SID.LOCAL_SYSTEM,
            group = token.SID.LOCAL_SYSTEM,
            dacl = access.acl({ access.ace(A.ALLOWED, kacs.ALL_RIGHTS,
                kacs.SID.EVERYONE) }),
            sacl = access.acl({ access.ace(A.ALARM, kacs.ALL_RIGHTS,
                kacs.SID.EVERYONE, access.ACE_FLAG.SUCCESSFUL_ACCESS) }) })
        t:assert_eq(kacs.set_sd(vm, p, sd, kacs.SI.OWNER | kacs.SI.GROUP
            | kacs.SI.DACL | kacs.SI.SACL).ret, 0, "an audited file")
        local events = recorded(t, function()
            local fd = facs.open(vm, p, { access = OPENABLE })
            t:assert(fd, "a handle")
            sys.read(vm, fd, 3)
            sys.flock(vm, fd, sys.LOCK_SH)
            sys.close(vm, fd)
        end)
        local records = kmes.of_type(events, "continuous-audit")
        t:assert(#records > 0, "records were produced")
        for _, e in ipairs(records) do
            t:assert_eq(e.payload.object_context, nil,
                "object_context is nil on every one — the field exists in " ..
                "the schema and is never filled at this point")
            t:assert(e.payload.operation,
                "while the operation beside it always is")
        end
    end)

test("an audit event cannot be suppressed by a bad output pointer",
    { spec = "PKM *audit-events.delivered-before-result" }, function(t)
        local sd = access.simple({ access.ace(A.ALLOWED, 0x1, U) })
        local events = recorded(t, function()
            local fd = mint({ audit_policy = AUDIT.OBJECT_ACCESS_SUCCESS })
            -- granted_out_ptr names a page that cannot be written; the
            -- record is delivered before the result is.
            local r = raw_check({ token_fd = fd, desired = 0x1,
                fields = { { 16, "<I4", #sd }, { 88, "<I8", 0xdead0000 } },
                children = { { bytes = sd, at = 8 } } })
            t:assert(r.ret < 0, "the syscall fails on the write-back")
            t:assert_eq(r.errno, sys.E.FAULT,
                "with EFAULT: " .. sys.errname(r.errno))
            sys.close(vm, fd)
        end)
        t:assert_eq(#kmes.of_type(events, "access-audit"), 1,
            "and the audit record is on the ring regardless")
    end)

test("a logon-session-destroyed with an invalid UTF-8 package drops silently",
    { spec = "PKM *audit-events.best-effort-logon-session-utf8",
      covered_by = "kunit:pkm_kunit_misc",
      skip = "kacs_create_logon_session validates the auth-package name as " ..
             "UTF-8 and refuses anything else " ..
             "(pkm_kunit_create_logon_session_non_utf8_auth_package_fails_closed), " ..
             "so no live session can hand the encoder anything else; runs under " ..
             "pkm_kunit_logon_session_destroyed_encoder_drops_non_utf8, which " ..
             "probes the encoder directly and sees the refusal the emitter drops on" },
    function(t) end)

test("the two StrataFS records drop rather than failing the operation",
    { spec = "PKM *audit-events.best-effort-stratafs",
      covered_by = "kunit:pkm_kunit_misc",
      skip = "the two drop conditions are an allocation failure and an " ..
             "over-long operation string; the operation strings are " ..
             "compile-time constants, and the stratafs test-hook points cannot " ..
             "fail the emitter's allocation. Runs under " ..
             "pkm_kunit_stratafs_audit_emission_is_best_effort for the over-long " ..
             "operation and path; the allocation failure has no witness" },
    function(t) end)

test("a self-emitted payload that would overflow its buffer is dropped",
    { spec = "PKM *audit-events.best-effort-oversize-payload",
      skip = "no coverage anywhere: the msgpack writer grows its buffer, " ..
             "so the only overflow is an allocation failure, which a " ..
             "guest cannot provoke and no KUnit case injects" },
    function(t) end)
