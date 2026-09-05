-- PKM §3.10.3 — setuid behaviour: the syscall family is a silent no-op
-- without SeAssignPrimaryTokenPrivilege and EOPNOTSUPP with it, the
-- setuid bit on exec is cosmetic without it and refused with it, and
-- `current_fsuid()` is redefined to read the effective token's
-- projection rather than `cred->fsuid`.
--
-- File ownership is the visible face of the fsuid patch, so the cases
-- create files on a synthesising tmpfs and stat them back as the agent.
--
-- The exec cases need a real ELF: the setid hook runs from
-- `begin_new_exec()`, which only a recognised binary format reaches, so
-- a garbage file fails ENOEXEC before the hook. /sbin/provium-agent is
-- the one binary in a kernel-only guest; `--help` makes it exit 0
-- immediately, which is what the permitted case needs.

local sys = require("helpers.sys")
local token = require("helpers.token")
local kacs = require("helpers.kacs")
local creds = require("helpers.creds")

local vm = provium:vm("vcredsetuid", "kernel-only"):boot()

local ASSIGN = token.bit(token.PRIV.ASSIGN_PRIMARY_TOKEN)
local CREATE = token.bit(token.PRIV.CREATE_TOKEN)
local IMPERSONATE = token.bit(token.PRIV.IMPERSONATE)

assert(kacs.new_mount(vm, "tmpfs", "/mt", kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL))
assert(kacs.set_sd(vm, "/mt", kacs.grant(kacs.ALL_RIGHTS)).ret == 0)
assert(kacs.set_sd(vm, "/", kacs.grant(kacs.ALL_RIGHTS)).ret == 0)

-- The one executable a kernel-only guest has, reachable by a principal
-- and carrying the setuid bit with owner uid 0.
local AGENT = "/sbin/provium-agent"
assert(kacs.set_sd(vm, "/sbin", kacs.grant(kacs.ALL_RIGHTS)).ret == 0)
assert(kacs.set_sd(vm, AGENT, kacs.grant(kacs.ALL_RIGHTS)).ret == 0)
assert(sys.chmod(vm, AGENT, tonumber("4755", 8)).ret == 0)
assert(sys.stat(vm, AGENT).uid == 0, "the setuid binary is owned by uid 0")

local function create_as(who, path)
    local fd, errno = sys.open(who, path, sys.O.CREAT | sys.O.RDWR,
        tonumber("644", 8))
    if not fd then return nil, errno end
    sys.close(who, fd)
    return sys.stat(vm, path)
end

--- Run `fn(worker)` in a worker whose primary token is `spec`, keeping
--- the worker alive across an exec attempt (as_principal's worker is
--- fine for this because a refused exec leaves the process intact).
local function as_principal(t, spec, fn) token.as_principal(t, vm, spec, fn) end

-- ---- the setuid syscalls --------------------------------------------

test("without SeAssignPrimaryTokenPrivilege the setuid family is a silent no-op",
    { spec = "PKM *cred.setuid.unprivileged-noop" }, function(t)
        as_principal(t, { projected_uid = 6001, projected_gid = 6002,
                          supplementary_gids = { 500, 501 } }, function(w)
            local caps_before = assert(creds.capget(w))
            local calls = {
                { "setuid(0)", function() return creds.setuid(w, 0) end },
                { "setgid(0)", function() return creds.setgid(w, 0) end },
                { "setresuid(1,2,3)", function() return creds.setresuid(w, 1, 2, 3) end },
                { "setresgid(1,2,3)", function() return creds.setresgid(w, 1, 2, 3) end },
                { "setgroups([77])", function() return creds.setgroups(w, { 77 }) end },
            }
            for _, call in ipairs(calls) do
                local r = call[2]()
                t:assert_eq(r.ret, 0, call[1] .. " returns success: " .. sys.errname(r.errno))
            end
            t:assert_eq(creds.getuid(w), 6001, "the uid is restored from the old credential")
            t:assert_eq(creds.geteuid(w), 6001, "and so is the euid")
            t:assert_eq(creds.getgid(w), 6002, "and the gid")
            t:assert_eq(creds.getegid(w), 6002, "and the egid")
            t:assert_eq(creds.groups_string(creds.getgroups(w)), "[500,501]",
                "and the supplementary groups")
            local caps_after = assert(creds.capget(w))
            t:assert_eq(caps_after.effective, caps_before.effective,
                "and the capability sets")
            t:assert_eq(caps_after.permitted, caps_before.permitted, "all three of them")
        end)
    end)

test("with SeAssignPrimaryTokenPrivilege the setuid family fails with EOPNOTSUPP",
    { spec = "PKM *cred.setuid.privileged-eopnotsupp" }, function(t)
        as_principal(t, { projected_uid = 6101, projected_gid = 6102,
                          privs_present = ASSIGN, privs_enabled = ASSIGN }, function(w)
            for _, call in ipairs({
                { "setuid(0)", function() return creds.setuid(w, 0) end },
                { "setgid(0)", function() return creds.setgid(w, 0) end },
                { "setresuid(1,2,3)", function() return creds.setresuid(w, 1, 2, 3) end },
                { "setgroups([77])", function() return creds.setgroups(w, { 77 }) end },
            }) do
                local r = call[2]()
                t:assert_eq(r.ret, -1, call[1] .. " fails")
                t:assert_eq(r.errno, sys.E.OPNOTSUPP,
                    "with EOPNOTSUPP: there is no authd redirect in the LSM")
            end
            t:assert_eq(creds.getuid(w), 6101, "and nothing changed")
        end)
    end)

-- ---- the setuid bit on exec -----------------------------------------

test("without the privilege a setuid-bit exec is permitted and merely cosmetic",
    { spec = "PKM *cred.setuid.exec-bit-cosmetic" }, function(t)
        as_principal(t, { projected_uid = 6201, projected_gid = 6202 }, function(w)
            -- The principal's fsuid (6201) differs from the file's owner
            -- (0), so bprm_fill_uid arms the euid change and the KACS
            -- setid hook is asked about it. It permits: the exec runs.
            local r = w:run(AGENT, { args = { "--help" }, timeout = "20s" })
            t:assert_eq(r.status, "exited",
                "the exec of a setuid binary proceeds: " .. tostring(r.stderr))
            t:assert_eq(r.exit_code, 0, "and the program ran")
        end)
    end)

test("the cosmetic exec sets uid and suid from euid and carries fsuid over",
    { spec = "PKM *cred.setuid.exec-bit-slot-values",
      covered_by = "kunit:pkm_kunit_process",
      skip = "the slot values live on a credential that only the exec'd " ..
             "program could read, and a kernel-only guest has no program " ..
             "that reports them; runs under " ..
             "pkm_kunit_exec_setid_compat_rewrites_visible_uid_and_gid_only" },
    function(t) end)

test("with the privilege an id-changing exec fails with EOPNOTSUPP",
    { spec = "PKM *cred.setuid.exec-privileged-eopnotsupp" }, function(t)
        as_principal(t, { projected_uid = 6301, projected_gid = 6302,
                          privs_present = ASSIGN, privs_enabled = ASSIGN }, function(w)
            local ok, err = pcall(function()
                return w:run(AGENT, { args = { "--help" }, timeout = "20s" })
            end)
            t:assert(not ok, "the exec fails outright")
            t:assert_contains(tostring(err), "os error 95",
                "with EOPNOTSUPP: " .. tostring(err))
        end)
        -- The refusal is about the id change, not about exec: a token
        -- holding the privilege execs a binary that changes no id.
        as_principal(t, { projected_uid = 0, user_sid = token.SID.LOCAL_SYSTEM,
                          privs_present = ASSIGN, privs_enabled = ASSIGN }, function(w)
            local r = w:run(AGENT, { args = { "--help" }, timeout = "20s" })
            t:assert_eq(r.exit_code, 0,
                "an exec that would change no uid is untouched by the gate")
        end)
    end)

-- ---- the current_fsuid patch ----------------------------------------

test("current_fsuid returns the effective token's projected uid, not cred->fsuid",
    { spec = "PKM *cred.setuid.fsuid-patch" }, function(t)
        token.as_principal(t, vm, {
            privs_present = CREATE | IMPERSONATE, privs_enabled = CREATE | IMPERSONATE,
            projected_uid = 6401, projected_gid = 6402,
        }, function(w, session)
            local client = assert(token.create(w, {
                auth_id = session, token_type = token.TYPE.IMPERSONATION,
                impersonation_level = token.LEVEL.IMPERSONATION,
                projected_uid = 6501, projected_gid = 6502,
            }))
            t:assert_eq(token.impersonate(w, client).ret, 0, "impersonating a second token")
            -- cred->fsuid on the primary credential is still 6401 —
            -- getuid(2) reads that credential and says so.
            t:assert_eq(creds.getuid(w), 6401, "the primary credential still reads 6401")
            local st = create_as(w, "/mt/fsuid-patch")
            t:assert(st, "a file is created")
            t:assert_eq(st.uid, 6501,
                "and current_fsuid() answered with the effective token's projection")
            t:assert_eq(st.gid, 6502, "current_fsgid() likewise")
            token.revert(w)
            sys.close(w, client)
        end)
    end)

test("files are created owned by the projected UID",
    { spec = "PKM *cred.setuid.fsuid-consequences" }, function(t)
        as_principal(t, { projected_uid = 6601, projected_gid = 6602 }, function(w)
            local st = create_as(w, "/mt/consequences")
            t:assert(st, "the principal creates a file")
            t:assert_eq(st.uid, 6601, "owned by its projected uid, not uid 0")
            t:assert_eq(st.gid, 6602, "and its projected gid")
        end)
        -- A different principal on the same filesystem lands differently:
        -- the number is the token's, not the mount's or the agent's.
        as_principal(t, { projected_uid = 6701, projected_gid = 6702 }, function(w)
            local st = create_as(w, "/mt/consequences-2")
            t:assert_eq(st.uid, 6701, "a second principal owns its own files")
        end)
    end)

test("setfsuid is a no-op for filesystem purposes",
    { spec = "PKM *cred.setuid.setfsuid-noop" }, function(t)
        as_principal(t, { projected_uid = 6801, projected_gid = 6802 }, function(w)
            local prev = creds.setfsuid(w, 0).ret
            t:assert_eq(prev, 6801, "setfsuid reports the previous fsuid")
            creds.setfsgid(w, 0)
            local st = create_as(w, "/mt/setfsuid")
            t:assert(st, "a file created after setfsuid(0)")
            t:assert_eq(st.uid, 6801, "is still owned by the projected uid")
            t:assert_eq(st.gid, 6802, "and the projected gid")
        end)
    end)

test("access(2) uses the effective token rather than a real credential",
    { spec = "PKM *cred.setuid.access-uses-effective-token" }, function(t)
        -- Two directories, each granting exactly one user SID. The
        -- process's *real* identity never changes; only the effective
        -- token does, and access(2) follows it.
        t:assert_eq(sys.mkdir(vm, "/mt/for-one").ret, 0, "a directory for TEST_USER")
        t:assert_eq(sys.mkdir(vm, "/mt/for-two").ret, 0, "and one for TEST_USER_2")
        t:assert_eq(kacs.set_sd(vm, "/mt/for-one", kacs.descriptor(kacs.acl({
            kacs.ace(kacs.ACE_ALLOWED, kacs.ALL_RIGHTS, token.SID.TEST_USER, 3) }))).ret, 0,
            "its DACL names TEST_USER only")
        t:assert_eq(kacs.set_sd(vm, "/mt/for-two", kacs.descriptor(kacs.acl({
            kacs.ace(kacs.ACE_ALLOWED, kacs.ALL_RIGHTS, token.SID.TEST_USER_2, 3) }))).ret, 0,
            "and the other names TEST_USER_2 only")

        token.as_principal(t, vm, {
            user_sid = token.SID.TEST_USER,
            privs_present = CREATE | IMPERSONATE, privs_enabled = CREATE | IMPERSONATE,
        }, function(w, session)
            local other = assert(token.create(w, {
                auth_id = session, user_sid = token.SID.TEST_USER_2,
                token_type = token.TYPE.IMPERSONATION,
                impersonation_level = token.LEVEL.IMPERSONATION,
            }))
            t:assert_eq(creds.faccessat(w, "/mt/for-one", creds.R_OK).ret, 0,
                "as itself the caller reaches its own directory")
            local denied = creds.faccessat(w, "/mt/for-two", creds.R_OK)
            t:assert_eq(denied.ret, -1, "and not the other's")
            t:assert_eq(denied.errno, sys.E.ACCES, "EACCES")

            t:assert_eq(token.impersonate(w, other).ret, 0, "it impersonates TEST_USER_2")
            t:assert_eq(creds.faccessat(w, "/mt/for-two", creds.R_OK).ret, 0,
                "access(2) now answers for the impersonated token")
            local flipped = creds.faccessat(w, "/mt/for-one", creds.R_OK)
            t:assert_eq(flipped.ret, -1,
                "and refuses what the real identity could reach")
            t:assert_eq(flipped.errno, sys.E.ACCES,
                "EACCES: there is no 'real identity' separate from the acting one")
            token.revert(w)
            sys.close(w, other)
        end)
    end)

test("SO_PEERCRED reports projected UIDs, not token information",
    { spec = "PKM *cred.setuid.so-peercred-projected" }, function(t)
        as_principal(t, { projected_uid = 5150, projected_gid = 5151 }, function(w)
            local a, b = creds.socketpair(w)
            t:assert(a, "a connected AF_UNIX pair: " .. sys.errname(b or 0))
            local peer = assert(creds.peercred(w, a))
            t:assert_eq(peer.uid, 5150, "the peer's uid is the projected uid")
            t:assert_eq(peer.gid, 5151, "and the gid the projected gid")
            t:assert(peer.pid > 0, "with the peer's pid alongside")
            sys.close(w, a); sys.close(w, b)
        end)
    end)

test("cosmetic UID forgery in SCM_CREDENTIALS is possible, because CAP_SETUID is allowed",
    { spec = "PKM *cred.setuid.so-peercred-projected" }, function(t)
        as_principal(t, { projected_uid = 5250, projected_gid = 5251 }, function(w)
            local a, b = creds.socketpair(w)
            t:assert(a, "a connected AF_UNIX pair")
            t:assert_eq(creds.set_passcred(w, b).ret, 0, "the reader asks for SO_PASSCRED")
            local pid = w:syscall(creds.NR.getpid).ret
            local r = creds.sendmsg_with_creds(w, a, "hello",
                { pid = pid, uid = 4242, gid = 4243 })
            t:assert_eq(r.ret, 5,
                "a uid the sender does not hold is accepted: " .. sys.errname(r.errno))
            local got = assert(creds.recvmsg_with_cmsg(w, b))
            t:assert_eq(got.cmsg_type, creds.SCM_CREDENTIALS, "SCM_CREDENTIALS is delivered")
            t:assert(got.creds, "carrying a struct ucred")
            t:assert_eq(got.creds.uid, 4242, "with the forged uid, not the projected one")
            t:assert_eq(got.creds.gid, 4243, "and the forged gid")
            sys.close(w, a); sys.close(w, b)
        end)
    end)

test("a uid0 utility could not change what current_fsuid answers",
    { spec = "PKM *cred.setuid.uid0-utility-absent" }, function(t)
        -- The utility does not exist in the tree; the guarantee it would
        -- rely on is that `current_fsuid()` ignores `cred->uid`. Under
        -- impersonation the two are different numbers, and filesystem
        -- operations follow the projection rather than the credential.
        token.as_principal(t, vm, {
            privs_present = CREATE | IMPERSONATE, privs_enabled = CREATE | IMPERSONATE,
            projected_uid = 0, user_sid = token.SID.LOCAL_SYSTEM,
        }, function(w, session)
            local other = assert(token.create(w, {
                auth_id = session, token_type = token.TYPE.IMPERSONATION,
                impersonation_level = token.LEVEL.IMPERSONATION,
                projected_uid = 7301, projected_gid = 7302,
            }))
            t:assert_eq(creds.getuid(w), 0, "cred->uid is 0 — what such a utility would force")
            t:assert_eq(token.impersonate(w, other).ret, 0, "acting for a real user")
            t:assert_eq(creds.getuid(w), 0, "cred->uid is still 0")
            local st = create_as(w, "/mt/uid0")
            t:assert(st, "a file is created")
            t:assert_eq(st.uid, 7301,
                "and is owned by the real user: current_fsuid() ignores cred->uid entirely")
            token.revert(w)
            sys.close(w, other)
        end)
    end)
