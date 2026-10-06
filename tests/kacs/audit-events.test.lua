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
    -- kacs.session.destroyed is written by a kernel work item after the
    -- teardown, not by the call that ended the session: give it a moment.
    sys.nanosleep(vm, 0, 50 * 1000 * 1000)
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
            if e.type == "kacs.audit.access.checked"
                or e.type == "kacs.audit.privilege.used"
                or e.type == "kacs.session.destroyed" then
                seen[e.type] = true
                t:assert_eq(e.origin, kmes.ORIGIN.KACS,
                    e.type .. " is stamped KMES_ORIGIN_KACS (2)")
            end
        end
        t:assert(seen["kacs.audit.access.checked"],
            "a kacs.audit.access.checked record was produced")
        t:assert(seen["kacs.audit.privilege.used"],
            "a kacs.audit.privilege.used record too")
        t:assert(seen["kacs.session.destroyed"],
            "and a kacs.session.destroyed record")
    end)

test("kacs.audit.access.checked comes from the SACL walk and from token audit policy",
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
        local walk = kmes.of_type(from_sacl, "kacs.audit.access.checked")
        t:assert_eq(#walk, 1,
            "the SACL walk emits one kacs.audit.access.checked record")
        t:assert_eq(walk[1].payload.outcome.success, true,
            "reporting the outcome it audited")
        t:assert_eq(walk[1].payload.trigger.kind, "sacl",
            "triggered by the SACL")
        t:assert(walk[1].payload.subject and walk[1].payload.subject.token,
            "with the resolved subject attached at emission")
        t:assert(walk[1].payload.emitter and walk[1].payload.emitter.process,
            "and the calling process")
        -- Token audit-policy forcing: the descriptor has no SACL at all.
        local from_policy = recorded(t, function()
            local fd = mint({ audit_policy = AUDIT.OBJECT_ACCESS_FAILURE })
            access.check(vm, { token_fd = fd, sd = access.simple({}),
                desired = 0x1, mapping = MAP })
            sys.close(vm, fd)
        end)
        local forced = kmes.of_type(from_policy, "kacs.audit.access.checked")
        t:assert_eq(#forced, 1,
            "the token's own audit policy forces one without a SACL")
        t:assert_eq(forced[1].payload.outcome.success, false,
            "for the failure it was asked to audit")
        t:assert_eq(forced[1].payload.trigger.kind, "policy",
            "triggered by the token's policy")
        t:assert_eq(forced[1].payload.trigger.ace, nil,
            "which names no ACE")
    end)

test("kacs.audit.handle.used comes from an enforcement point, per operation",
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
        local records = kmes.of_type(events, "kacs.audit.handle.used")
        t:assert(#records >= 2,
            "one record per operation, not one per handle: " .. #records)
        local payload = records[1].payload
        t:assert(payload.operation and payload.operation.name,
            "each names its enforcement point")
        t:assert(payload.access.matched and payload.access.matched ~= 0,
            "and the part of the handle's continuous mask it matched")
        t:assert(payload.access.granted, "alongside the granted mask")
        local audit_mask = payload.access["audit-mask"]
        t:assert(audit_mask
            and audit_mask & payload.access.matched == payload.access.matched,
            "and the whole continuous mask cached on the handle")
        t:assert_eq(payload.object.kind, "file", "on a file")
        t:assert_eq(payload.object.file.path, p, "named by its path")
        t:assert(payload.subject and payload.emitter
            and payload.emitter.process,
            "with the shared subject and emitter process sub-maps")
    end)

test("kacs.audit.privilege.used comes from privilege-use auditing on a check",
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
        local records = kmes.privilege_uses(events)
        t:assert_eq(#records, 1, "one kacs.audit.privilege.used record")
        local p = records[1].payload
        t:assert_eq(p.privilege.name, "SeBackupPrivilege",
            "naming the privilege that influenced the check")
        t:assert_eq(p.outcome.success, true, "and whether its bits survived")
        t:assert(p.privilege.contributed and p.privilege.surviving
            and p.access.requested and p.access.granted,
            "with the masks the record carries")
        t:assert_eq(p.privilege.contributed, 0x1,
            "the privilege contributed the read it was asked for")
        t:assert_eq(p.privilege.surviving, 0x1, "and all of it survived")
        t:assert_eq(p.access.requested, 0x1,
            "beside the whole check's requested mask")
        t:assert_eq(p.access.granted & 0x1, 0x1,
            "and its final granted mask")
    end)

test("CAAP staging divergence comes from a staged-versus-effective mismatch",
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
        local records = kmes.of_type(events, "kacs.caap.staging.diverged")
        t:assert_eq(#records, 1, "and emits one diagnostic record")
        t:assert_eq(#kmes.of_type(events, "kacs.caap.sacl.skipped"), 0,
            "of the divergence type, not the skipped-SACL one")
        local p = records[1].payload
        t:assert_eq(p.access["granted"] & 0x3, 0x1,
            "carrying what the effective rules granted")
        t:assert_eq(p.access["granted-staged"] & 0x3, 0x3,
            "and what the staged rules would have")
        t:assert_neq(p.access["granted"], p.access["granted-staged"],
            "which is the mismatch the record exists to report")
        access.set_caap(vm, policy, nil)
    end)

test("kacs.session.destroyed comes from LogonSession teardown",
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
        for _, e in ipairs(kmes.of_type(events, "kacs.session.destroyed")) do
            if e.payload and e.payload.object.session.id == session then
                records[#records + 1] = e
            end
        end
        t:assert_eq(#records, 1,
            "the last token going emits one teardown record")
        local s = records[1].payload.object.session
        t:assert_eq(s["logon-type"], "service",
            "carrying the session's logon type, by name")
        t:assert_eq(s["auth-package"], "Kerberos", "its authentication package")
        t:assert(s.user and s.user.sid, "the authenticated user's SID")
        t:assert(s["logon-time"], "and when the session was created")
        -- Nanoseconds since the epoch, converted from whole seconds: a
        -- seconds value would sit near 1.8e9, a nanosecond one near 1.8e18.
        t:assert(s["logon-time"] > 1000000000000000,
            "in realtime nanoseconds, not seconds: " .. s["logon-time"])
        t:assert_eq(s["logon-time"] % 1000000000, 0,
            "of whole-second resolution")
    end)

test("kacs.descriptor.rejected comes from a descriptor xattr that fails validation",
    { spec = "PKM *audit-events.corrupt-sd-record",
      covered_by = "kunit:pkm_kunit_file",
      skip = "the canonical descriptor xattr cannot be written through " ..
             "the xattr surface — the metadata hook refuses it as " ..
             "KACS_META_CANONICAL_SD even for SYSTEM — so a guest " ..
             "cannot author the corrupt stored SD this record reports; " ..
             "it runs under " ..
             "pkm_kunit_file_sd_cache_population_corrupt_emits_once" },
    function(t) end)

test("kacs.descriptor.rejected names the file by inode and device, its length and its reader",
    { spec = "PKM *audit-events.corrupt-sd-identifies-file",
      covered_by = "kunit:pkm_kunit_file",
      skip = "a guest cannot author the corrupt stored descriptor this " ..
             "record reports (see the case above); the payload runs under " ..
             "pkm_kunit_file_sd_cache_population_corrupt_emits_once" },
    function(t) end)

test("stratafs.file.copied-up comes from the copy-up lifecycle",
    { spec = "PKM *audit-events.stratafs-copy-up-record" }, function(t)
        stratafs.with(vm, "auditev-copy-up", {
            { name = "dest", flags = { "create" } },
            { name = "src", flags = { "ro" }, entries = { f = "original" } },
        }, function(s)
            local events = kmes.recording(t, vm, function()
                t:assert(stratafs.try_write(vm, s:join("f"), "modified"),
                    "a write to a read-only stratum copies up")
            end)
            local records = kmes.of_type(events, "stratafs.file.copied-up")
            t:assert_eq(#records, 1,
                "which emits one stratafs.file.copied-up record")
            t:assert_eq(records[1].origin, kmes.ORIGIN.KACS,
                "through KACS's kernel-only emitter")
            local p = records[1].payload
            t:assert_eq(p.object.file["path-relative"], "/f",
                "naming the object that was copied")
            t:assert_eq(p.outcome.success, true,
                "and the outcome of the copy")
            t:assert_eq(p.outcome.errno, nil,
                "with no errno on success")
        end)
    end)

test("stratafs.mutation.refused comes from an arrangement refusal",
    { spec = "PKM *audit-events.stratafs-mutation-refused-record" }, function(t)
        stratafs.with(vm, "auditev-refused", {
            { name = "only", flags = { "ro" }, entries = { f = "x" } },
        }, function(s)
            local events = kmes.recording(t, vm, function()
                local ok, errno = stratafs.try_create(vm, s:join("new"), "x")
                t:assert(not ok and errno == sys.E.ROFS,
                    "a create with no create stratum is refused")
            end)
            local records = kmes.of_type(events, "stratafs.mutation.refused")
            t:assert_eq(#records, 1,
                "which emits one stratafs.mutation.refused record")
            t:assert_eq(records[1].origin, kmes.ORIGIN.KACS,
                "through KACS's kernel-only emitter")
            t:assert(records[1].payload.operation.name,
                "naming the arrangement that was refused")
            t:assert_eq(records[1].payload.outcome.errno, -sys.E.ROFS,
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
            local records = kmes.privilege_uses(events)
            t:assert_eq(#records, 1, c[1] .. " produces one record")
            t:assert_eq(records[1].payload.privilege.name, c[1],
                "under its canonical name")
        end
    end)

test("no other privilege ever appears in a privilege-use record",
    { spec = "PKM *audit-events.privilege-encoder-fails-closed" }, function(t)
        -- Only five privileges can influence a check, so a token full of
        -- the others produces no access-check privilege record at all.
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
        t:assert_eq(#kmes.privilege_uses(events), 0,
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
        local records = kmes.privilege_uses(emitted)
        t:assert(#records > 0, "a token holding one of the five does emit")
        for _, e in ipairs(records) do
            t:assert(NAMED[e.payload.privilege.name],
                "and never an unnamed privilege: " ..
                tostring(e.payload.privilege.name))
        end
    end)

test("kacs.audit.handle.used names its enforcement point from a fixed vocabulary",
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
        for _, e in ipairs(kmes.of_type(events, "kacs.audit.handle.used")) do
            local op = e.payload and e.payload.operation
                and e.payload.operation.name
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

test("a kacs.audit.handle.used record names its file and carries no opaque context",
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
        local records = kmes.of_type(events, "kacs.audit.handle.used")
        t:assert(#records > 0, "records were produced")
        for _, e in ipairs(records) do
            t:assert_eq(e.payload.object_context, nil,
                "no opaque object_context key on any of them")
            t:assert_eq(e.payload.fields, nil,
                "and nothing userspace asserted: the kernel observed it all")
            t:assert_eq(e.payload.object.kind, "file",
                "the object is always a file at this enforcement point")
            t:assert_eq(e.payload.object.file.path, p,
                "named by its absolute path")
            t:assert(e.payload.operation and e.payload.operation.name,
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
        t:assert_eq(#kmes.of_type(events, "kacs.audit.access.checked"), 1,
            "and the audit record is on the ring regardless")
    end)

test("a kacs.session.destroyed with an invalid UTF-8 package drops silently",
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

-- kacs.audit.descriptor.changed ---------------------------------------------------

local DESCRIPTOR_CHANGED = "kacs.audit.descriptor.changed"

--- An audited descriptor: owner and group SYSTEM, a DACL granting `mask`
--- to Everyone, and `sacl` (an ACL) when given.
local function owned_sd(mask, sacl)
    return access.sd({ owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
        dacl = access.acl({ access.ace(A.ALLOWED, mask, kacs.SID.EVERYONE) }),
        sacl = sacl })
end

local function audit_sacl()
    return access.acl({ access.ace(A.AUDIT, kacs.ALL_RIGHTS, kacs.SID.EVERYONE,
        access.ACE_FLAG.SUCCESSFUL_ACCESS | access.ACE_FLAG.FAILED_ACCESS) })
end

test("removing a file's SACL is recorded as kacs.audit.descriptor.changed",
    { spec = "PKM *audit-events.descriptor-changed-sacl-always" }, function(t)
        local p = B .. "/sacl-removed"
        vm:write_file(p, "watched")
        local ALL = kacs.SI.OWNER | kacs.SI.GROUP | kacs.SI.DACL | kacs.SI.SACL
        t:assert_eq(kacs.set_sd(vm, p, owned_sd(kacs.ALL_RIGHTS, audit_sacl()), ALL).ret, 0,
            "the file is audited")
        local events = recorded(t, function()
            t:assert_eq(kacs.set_sd(vm, p, owned_sd(kacs.ALL_RIGHTS, access.acl({})),
                kacs.SI.SACL).ret, 0, "its SACL is emptied")
        end)
        local rec = kmes.of_type(events, DESCRIPTOR_CHANGED)
        t:assert_eq(#rec, 1, "and that change is recorded, though the new SACL audits nothing")
        local p1 = rec[1].payload
        t:assert_eq(p1.object.kind, "file", "about a file")
        t:assert_eq(p1.object.sd.components & kacs.SI.SACL, kacs.SI.SACL, "a SACL change")
        t:assert(p1.object.sd["digest-previous"] and p1.object.sd.digest,
            "with the replaced and the written descriptor's digests")
        t:assert(p1.object.sd["digest-previous"] ~= p1.object.sd.digest, "which differ")
        t:assert_eq(#p1.object.sd.digest, 32, "SHA-256")
        t:assert_eq(p1.object.sd.owner, token.SID.LOCAL_SYSTEM, "naming the owner")
        t:assert_eq(p1.access.requested & STD.ACCESS_SYSTEM_SECURITY,
            STD.ACCESS_SYSTEM_SECURITY, "the change needed ACCESS_SYSTEM_SECURITY")
        t:assert_eq(p1.outcome.success, true, "and was made")
        t:assert_eq(p1.subject.token.sid, token.SID.LOCAL_SYSTEM, "by SYSTEM")
    end)

test("a DACL change through a path, with no handle alarm mask, is not recorded",
    { spec = "PKM *audit-events.descriptor-changed-dacl-by-handle-mask" }, function(t)
        local p = B .. "/dacl-only"
        vm:write_file(p, "plain")
        t:assert_eq(kacs.set_sd(vm, p, owned_sd(kacs.ALL_RIGHTS), kacs.SI.OWNER | kacs.SI.GROUP
            | kacs.SI.DACL).ret, 0, "a descriptor")
        local events = recorded(t, function()
            t:assert_eq(kacs.set_sd(vm, p, owned_sd(kacs.ALL_RIGHTS & ~kacs.RIGHT.DELETE_CHILD),
                kacs.SI.DACL).ret, 0, "its DACL changes")
        end)
        t:assert_eq(#kmes.of_type(events, DESCRIPTOR_CHANGED), 0,
            "with no SACL in the change and no alarm mask on a handle, nothing is recorded")
    end)

test("a SACL change to a token, a process or an IPC object is recorded too",
    { spec = "PKM *audit-events.descriptor-changed-object-kinds" }, function(t)
        local netobj = require("helpers.netobj")
        local psb = require("helpers.psb")
        local SI = kacs.SI.OWNER | kacs.SI.GROUP | kacs.SI.DACL | kacs.SI.SACL
        local tfd = mint({})
        local sem = assert(netobj.semget(vm, 0x5d0001, 1))
        local child = vm:spawn_worker()
        local pidfd = assert(psb.pidfd(vm, psb.pid(child)))
        local events = recorded(t, function()
            t:assert_eq(token.set_sd(vm, tfd, owned_sd(kacs.ALL_RIGHTS, audit_sacl()), SI).ret, 0,
                "a token's SACL is set")
            t:assert_eq(psb.set_sd(vm, pidfd, owned_sd(kacs.ALL_RIGHTS, audit_sacl()), SI).ret, 0,
                "a process's")
            t:assert_eq(netobj.ipc_set_sd(vm, netobj.SD_AT.SEM, sem,
                owned_sd(kacs.ALL_RIGHTS, audit_sacl()), SI).ret, 0, "and a semaphore set's")
        end)
        local kinds = {}
        for _, e in ipairs(kmes.of_type(events, DESCRIPTOR_CHANGED)) do
            kinds[e.payload.object.kind] = e.payload
        end
        t:assert(kinds.token, "the token's change is recorded")
        t:assert_eq(kinds.token.object.token.id, assert(token.statistics(vm, tfd)).token_id,
            "naming the token")
        t:assert(kinds.process, "the process's")
        t:assert_eq(#kinds.process.object.process.guid, 16, "naming the process by GUID")
        t:assert(kinds.ipc, "and the semaphore set's")
        t:assert_eq(kinds.ipc.object.ipc.type, "sem", "a semaphore set")
        t:assert_eq(kinds.ipc.object.ipc.id, sem, "by its identifier")
        for kind, p in pairs(kinds) do
            t:assert_eq(p.access.granted, nil, kind .. ": made without a handle mask")
            t:assert(p.object.sd.digest, kind .. ": with the written descriptor's digest")
        end
        sys.close(vm, tfd); sys.close(vm, pidfd)
        child:kill(); child:join()
        vm:syscall(netobj.NR.semctl, sem, 0, 0, 0)
    end)
