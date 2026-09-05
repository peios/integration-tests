-- PKM §3.10.2 — DAC neutralisation and the capability switchboard: the
-- ALLOW substrate every process carries so DAC never denies before a
-- KACS hook fires, the PRIVILEGE capabilities that map to a KACS
-- privilege, the DENY set, and the compatibility-only nature of
-- capget/capset/prctl.
--
-- The switchboard is only visible from a caller that lacks the
-- privilege under test, so every gate case runs in a worker holding a
-- minted principal. The agent is SYSTEM and holds everything, which is
-- exactly what makes it the right subject for the DENY cases: a
-- capability refused to SYSTEM is refused unconditionally.
--
-- The gates chosen here are the cheapest reachable ones: reboot(2) with
-- a CAD toggle for CAP_SYS_BOOT (it changes nothing), setpriority(2)
-- for CAP_SYS_NICE, perf_event_open(2) for CAP_PERFMON, mount(2) for
-- the may_mount() question, and setxattr on a `security.*` name for the
-- xattr prechecks.

local sys = require("helpers.sys")
local token = require("helpers.token")
local kacs = require("helpers.kacs")
local hooks = require("helpers.hooks")
local creds = require("helpers.creds")

local vm = provium:vm("vcreddac", "kernel-only"):boot()

local PRIV = token.PRIV
local function bits(...)
    local mask = 0
    for _, p in ipairs({ ... }) do mask = mask | token.bit(p) end
    return mask
end

-- A filesystem a principal can reach, for the mount and xattr cases.
assert(kacs.new_mount(vm, "tmpfs", "/mt", kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL))
assert(kacs.set_sd(vm, "/mt", kacs.grant(kacs.ALL_RIGHTS)).ret == 0)
assert(kacs.set_sd(vm, "/", kacs.grant(kacs.ALL_RIGHTS)).ret == 0)

--- Run `fn(worker)` as a principal holding exactly `privs`.
local function as_holder(t, privs, fn)
    token.as_principal(t, vm, { privs_present = privs, privs_enabled = privs }, fn)
end

--- A principal's own token's privilege-use word.
local function used_privileges(w)
    local own = assert(token.open_self(w, token.RIGHT.QUERY))
    local p = assert(token.privileges(w, own))
    sys.close(w, own)
    return p.used
end

-- ---- the substrate ---------------------------------------------------

test("every process carries the ALLOW capabilities, mandatory substrate rather than a grant",
    { spec = "PKM *cred.dac.every-process-gets-allow" }, function(t)
        -- A principal with no privileges at all still has them.
        token.as_principal(t, vm, {}, function(w)
            local caps = assert(creds.capget(w))
            for _, cap in ipairs(creds.ALLOW_CAPS) do
                t:assert(caps.effective & (1 << cap) ~= 0,
                    creds.cap_names(1 << cap) .. " is effective for an unprivileged principal")
                t:assert(caps.permitted & (1 << cap) ~= 0, "and permitted")
            end
        end)
        -- And so does the agent, which is SYSTEM: it is substrate, not policy.
        local mine = assert(creds.capget(vm))
        t:assert_eq(mine.effective & creds.ALLOW_MASK, creds.ALLOW_MASK,
            "SYSTEM carries the same substrate")
    end)

test("the ALLOW set is exactly the twelve capabilities the table names",
    { spec = "PKM *cred.dac.allow-set" }, function(t)
        token.as_principal(t, vm, {}, function(w)
            local caps = assert(creds.capget(w))
            t:assert_eq(caps.effective, creds.ALLOW_MASK,
                "effective is the ALLOW set and nothing else: got "
                .. creds.cap_names(caps.effective))
            t:assert_eq(caps.permitted, creds.ALLOW_MASK, "permitted likewise")
            t:assert_eq(caps.inheritable, creds.ALLOW_MASK, "inheritable likewise")
        end)
        -- CAP_NET_BIND_SERVICE is in the set: the port's reservation
        -- decides at socket_bind, and the privileged-port floor never
        -- refuses first (§3.12.1).
        t:assert(creds.ALLOW_MASK & (1 << creds.CAP.NET_BIND_SERVICE) ~= 0,
            "CAP_NET_BIND_SERVICE is an ALLOW capability")
        t:assert(creds.ALLOW_MASK & (1 << creds.CAP.IPC_OWNER) ~= 0,
            "and so is CAP_IPC_OWNER, which is what makes the SysV mode inert (§3.11)")
    end)

test("security_capable is authoritative and the raw capability sets answer nothing",
    { spec = "PKM *cred.dac.security-capable-authoritative" }, function(t)
        -- CAP_SYS_BOOT is absent from every credential's effective set,
        -- yet reboot(2) succeeds for a holder of SeShutdownPrivilege and
        -- fails for one without: the sets are not consulted.
        as_holder(t, bits(PRIV.SHUTDOWN), function(w)
            local caps = assert(creds.capget(w))
            t:assert_eq(caps.effective & (1 << creds.CAP.SYS_BOOT), 0,
                "CAP_SYS_BOOT is not in the credential's effective set")
            t:assert_eq(creds.reboot(w).ret, 0,
                "yet the CAP_SYS_BOOT-gated call succeeds on the privilege alone")
        end)
        as_holder(t, bits(PRIV.BACKUP), function(w)
            local caps = assert(creds.capget(w))
            t:assert_eq(caps.effective & (1 << creds.CAP.SYS_BOOT), 0,
                "the same credential state")
            local r = creds.reboot(w)
            t:assert_eq(r.ret, -1, "and the same call is refused without the privilege")
            t:assert_eq(r.errno, sys.E.PERM, "EPERM")
        end)
    end)

test("a PRIVILEGE capability is answered by the KACS privilege it maps to",
    { spec = "PKM *cred.dac.privilege-mapped" }, function(t)
        -- CAP_SYS_NICE -> SeIncreaseBasePriorityPrivilege, through
        -- setpriority(2)'s can_nice() gate.
        local function renice(w) return w:syscall(creds.NR.setpriority, 0, 0, -5) end
        as_holder(t, 0, function(w)
            local r = renice(w)
            t:assert_eq(r.ret, -1, "lowering the nice value is refused without the privilege")
            t:assert_eq(r.errno, sys.E.ACCES, "EACCES")
        end)
        as_holder(t, bits(PRIV.INCREASE_BASE_PRIORITY), function(w)
            t:assert_eq(renice(w).ret, 0,
                "SeIncreaseBasePriorityPrivilege is what CAP_SYS_NICE asks for")
        end)
        -- A different privilege does not answer for it.
        as_holder(t, bits(PRIV.TCB), function(w)
            t:assert_eq(renice(w).errno, sys.E.ACCES,
                "SeTcbPrivilege is not a master key for a mapped capability")
        end)
    end)

test("CAP_PERFMON OR-maps, and every privilege the caller holds is marked used",
    { spec = "PKM *cred.dac.perfmon-or-mapped" }, function(t)
        -- A system-wide perf_event_open: perfmon_capable() decides, and
        -- refuses with EACCES when it says no. Anything past that gate
        -- is a different question and a different errno.
        local function perf(w)
            local attr = string.pack("<I4I4I8", 1, 128, 0) .. string.rep("\0", 112)
            return w:syscall(creds.NR.perf_event_open, {
                args = { 0, -1, 0, -1, 0 }, bufs = { attr }, ptrs = { 0 },
            })
        end
        for _, priv in ipairs({ PRIV.SYSTEM_PROFILE, PRIV.PROFILE_SINGLE_PROCESS,
                                PRIV.LOAD_DRIVER }) do
            as_holder(t, bits(priv), function(w)
                perf(w)
                t:assert_eq(used_privileges(w) & token.bit(priv), token.bit(priv),
                    "privilege bit " .. priv .. " alone satisfies the CAP_PERFMON ceiling")
            end)
        end
        as_holder(t, bits(PRIV.SYSTEM_PROFILE, PRIV.PROFILE_SINGLE_PROCESS,
                          PRIV.LOAD_DRIVER), function(w)
            perf(w)
            local want = bits(PRIV.SYSTEM_PROFILE, PRIV.PROFILE_SINGLE_PROCESS,
                              PRIV.LOAD_DRIVER)
            t:assert_eq(used_privileges(w) & want, want,
                "holding all three marks all three used")
        end)
        as_holder(t, bits(PRIV.BACKUP), function(w)
            local r = perf(w)
            t:assert_eq(r.ret, -1, "an unrelated privilege does not satisfy it")
            t:assert_eq(r.errno, sys.E.ACCES, "EACCES from the perfmon gate")
            t:assert_eq(used_privileges(w) & token.bit(PRIV.BACKUP), 0,
                "and nothing is marked used")
        end)
    end)

test("mounting is asked outside the capability table: SeManageVolumePrivilege or SeTcbPrivilege",
    { spec = "PKM *cred.dac.may-mount-manage-volume" }, function(t)
        for i, at in ipairs({ "/mt/mp1", "/mt/mp2", "/mt/mp3" }) do
            t:assert(sys.mkdir(vm, at).ret == 0, "mount point " .. i)
        end
        local function mount_at(w, at)
            return sys.mount(w, { target = at, fstype = "tmpfs" })
        end
        as_holder(t, 0, function(w)
            local r = mount_at(w, "/mt/mp1")
            t:assert_eq(r.ret, -1, "a principal with neither privilege cannot mount")
            t:assert_eq(r.errno, sys.E.PERM, "EPERM, from may_mount()")
        end)
        as_holder(t, bits(PRIV.MANAGE_VOLUME), function(w)
            t:assert_eq(mount_at(w, "/mt/mp2").ret, 0,
                "SeManageVolumePrivilege is accepted")
        end)
        as_holder(t, bits(PRIV.TCB), function(w)
            t:assert_eq(mount_at(w, "/mt/mp3").ret, 0,
                "and so is SeTcbPrivilege")
        end)
    end)

test("CAP_SYS_BOOT from a remote logon session additionally needs SeRemoteShutdownPrivilege",
    { spec = "PKM *cred.dac.sys-boot-remote-shutdown" }, function(t)
        local SHUT = bits(PRIV.SHUTDOWN)
        local BOTH = bits(PRIV.SHUTDOWN, PRIV.REMOTE_SHUTDOWN)
        token.as_principal(t, vm, { privs_present = SHUT, privs_enabled = SHUT,
            logon_type = token.LOGON_TYPE.INTERACTIVE }, function(w)
            t:assert_eq(creds.reboot(w).ret, 0,
                "an interactive session needs only SeShutdownPrivilege")
        end)
        for _, remote in ipairs({ token.LOGON_TYPE.NETWORK,
                                  token.LOGON_TYPE.NETWORK_CLEARTEXT,
                                  token.LOGON_TYPE.NEW_CREDENTIALS }) do
            token.as_principal(t, vm, { privs_present = SHUT, privs_enabled = SHUT,
                logon_type = remote }, function(w)
                local r = creds.reboot(w)
                t:assert_eq(r.ret, -1,
                    "logon type " .. remote .. " needs more than SeShutdownPrivilege")
                t:assert_eq(r.errno, sys.E.PERM, "EPERM")
            end)
            token.as_principal(t, vm, { privs_present = BOTH, privs_enabled = BOTH,
                logon_type = remote }, function(w)
                t:assert_eq(creds.reboot(w).ret, 0,
                    "with SeRemoteShutdownPrivilege it is allowed at logon type " .. remote)
            end)
        end
    end)

test("the DENY capabilities are refused whatever privilege the caller holds",
    { spec = "PKM *cred.dac.deny-set" }, function(t)
        -- The agent is SYSTEM and holds every privilege, which is what
        -- makes it the right subject: these refusals are unconditional.
        -- CAP_SETPCAP gates PR_CAPBSET_DROP.
        local r = vm:syscall(creds.NR.prctl, creds.PR.CAPBSET_DROP,
            creds.CAP.SYS_ADMIN, 0, 0, 0)
        t:assert_eq(r.ret, -1, "SYSTEM cannot drop a bounding-set capability")
        t:assert_eq(r.errno, sys.E.PERM, "EPERM: CAP_SETPCAP is dead")
        -- CAP_SETFCAP gates installing file capability data.
        local fd = assert(sys.open(vm, "/mt/denyset", sys.O.CREAT | sys.O.RDWR,
            tonumber("644", 8)))
        sys.close(vm, fd)
        local caps = string.pack("<I4I4I4I4I4", 0x02000000, 1, 0, 0, 0)
        local x = sys.setxattr(vm, "/mt/denyset", "security.capability", caps)
        t:assert_eq(x.ret, -1, "SYSTEM cannot install file capabilities")
        t:assert_eq(x.errno, sys.E.PERM, "EPERM: CAP_SETFCAP is dead")
        -- CAP_MAC_OVERRIDE has no reachable gate here: KACS is the only
        -- MAC LSM and nothing else asks for it. It shares the refusal.
    end)

test("an unmapped or unknown capability is denied by default",
    { spec = "PKM *cred.dac.unmapped-denied",
      covered_by = "kunit:pkm_kunit_process",
      skip = "every capability this kernel defines is in the ALLOW, " ..
             "PRIVILEGE or DENY class, so no syscall can present an " ..
             "unmapped one; runs under pkm_kunit_capability_switchboard_full_matrix" },
    function(t) end)

-- ---- compatibility state --------------------------------------------

test("capget and /proc/<pid>/status report the ALLOW substrate",
    { spec = "PKM *cred.dac.capget-reports-allow" }, function(t)
        local status = assert(creds.proc_status(vm))
        for _, field in ipairs({ "CapEff", "CapPrm", "CapInh", "CapBnd" }) do
            local reported = creds.status_caps(status, field)
            t:assert(reported, field .. " is reported by the proc interface")
            t:assert_eq(reported & creds.ALLOW_MASK, creds.ALLOW_MASK,
                field .. " carries the whole ALLOW substrate: "
                .. creds.cap_names(reported))
        end
        t:assert(creds.status_caps(status, "CapAmb"),
            "CapAmb is reported too — raw Linux ambient state")
        t:assert_eq(creds.status_caps(status, "CapAmb") & creds.ALLOW_MASK, 0,
            "and the substrate does not depend on ambient capabilities")
        local caps = assert(creds.capget(vm))
        t:assert_eq(caps.effective, creds.status_caps(status, "CapEff"),
            "capget() agrees with CapEff")
        t:assert_eq(caps.permitted, creds.status_caps(status, "CapPrm"),
            "and with CapPrm")
        t:assert_eq(caps.inheritable, creds.status_caps(status, "CapInh"),
            "and with CapInh")
    end)

test("capset rejects any request clearing an ALLOW capability",
    { spec = "PKM *cred.dac.allow-set-undroppable" }, function(t)
        token.as_principal(t, vm, {}, function(w)
            local caps = assert(creds.capget(w))
            t:assert_eq(creds.capset(w, caps).ret, 0,
                "re-writing the sets unchanged is accepted")
            for _, cap in ipairs(creds.ALLOW_CAPS) do
                for _, set in ipairs({ "effective", "permitted", "inheritable" }) do
                    local req = { effective = caps.effective,
                                  permitted = caps.permitted,
                                  inheritable = caps.inheritable }
                    req[set] = req[set] & ~(1 << cap)
                    local r = creds.capset(w, req)
                    t:assert_eq(r.ret, -1, "clearing " .. creds.cap_names(1 << cap)
                        .. " from " .. set .. " is refused")
                    t:assert_eq(r.errno, sys.E.PERM, "EPERM")
                end
            end
            t:assert_eq(assert(creds.capget(w)).effective, creds.ALLOW_MASK,
                "and the substrate survived every attempt")
            -- Bounding-set drops reject an ALLOW capability too.
            local drop = w:syscall(creds.NR.prctl, creds.PR.CAPBSET_DROP,
                creds.CAP.CHOWN, 0, 0, 0)
            t:assert_eq(drop.ret, -1, "PR_CAPBSET_DROP of an ALLOW capability is refused")
            t:assert_eq(drop.errno, sys.E.PERM, "EPERM")
        end)
    end)

test("an ambient raise of an ALLOW capability is refused, not only a clear",
    { spec = "PKM *cred.dac.ambient-raise-refused" }, function(t)
        token.as_principal(t, vm, {}, function(w)
            for _, cap in ipairs({ creds.CAP.CHOWN, creds.CAP.NET_BIND_SERVICE }) do
                local raise = w:syscall(creds.NR.prctl, creds.PR.CAP_AMBIENT,
                    creds.PR_CAP_AMBIENT.RAISE, cap, 0, 0)
                t:assert_eq(raise.ret, -1,
                    "raising " .. creds.cap_names(1 << cap) .. " into ambient is refused")
                t:assert_eq(raise.errno, sys.E.PERM, "EPERM — stricter than the invariant needs")
                local lower = w:syscall(creds.NR.prctl, creds.PR.CAP_AMBIENT,
                    creds.PR_CAP_AMBIENT.LOWER, cap, 0, 0)
                t:assert_eq(lower.errno, sys.E.PERM, "and lowering it is refused as well")
            end
            -- A non-ALLOW capability is not the switchboard's business:
            -- ordinary Linux ambient rules apply and refuse it for their
            -- own reason.
            local other = w:syscall(creds.NR.prctl, creds.PR.CAP_AMBIENT,
                creds.PR_CAP_AMBIENT.RAISE, creds.CAP.SYS_ADMIN, 0, 0)
            t:assert_eq(other.ret, -1, "a non-ALLOW ambient raise fails too")
        end)
    end)

-- ---- neutralised native paths ---------------------------------------

test("the commoncap subset gates before a KACS hook are neutralised",
    { spec = "PKM *cred.dac.commoncap-neutralised",
      covered_by = "kunit:pkm_kunit_process",
      skip = "every credential carries the identical ALLOW set, so the " ..
             "native cap_issubset() gates would pass anyway and their " ..
             "removal is not observable from the guest; runs under " ..
             "pkm_kunit_ptrace_traceme_success and pkm_kunit_setnice_success" },
    function(t) end)

test("the native security-xattr capability precheck is skipped, leaving FACS authoritative",
    { spec = "PKM *cred.dac.xattr-precheck-skipped" }, function(t)
        -- Natively `security.*` xattr writes need CAP_SYS_ADMIN, which
        -- maps to SeTcbPrivilege. A principal holding no privilege at
        -- all writes one, because only the FACS metadata hook is asked.
        token.as_principal(t, vm, {}, function(w)
            local fd, errno = sys.open(w, "/mt/xattr-precheck",
                sys.O.CREAT | sys.O.RDWR, tonumber("644", 8))
            t:assert(fd, "the principal creates a file: " .. sys.errname(errno or 0))
            sys.close(w, fd)
            local caps = assert(creds.capget(w))
            t:assert_eq(caps.effective & (1 << creds.CAP.SYS_ADMIN), 0,
                "it holds no CAP_SYS_ADMIN")
            local r = sys.setxattr(w, "/mt/xattr-precheck", "security.pit", "v")
            t:assert_eq(r.ret, 0,
                "and still writes a security.* xattr: " .. sys.errname(r.errno))
            t:assert_eq(sys.getxattr(w, "/mt/xattr-precheck", "security.pit"), "v",
                "which reads back")
        end)
    end)

test("Linux file capabilities stay dead: non-empty security.capability is refused",
    { spec = "PKM *cred.dac.file-caps-dead" }, function(t)
        local fd = assert(sys.open(vm, "/mt/filecaps", sys.O.CREAT | sys.O.RDWR,
            tonumber("644", 8)))
        sys.close(vm, fd)
        local v2 = string.pack("<I4I4I4I4I4", 0x02000000, 1, 0, 0, 0)
        local v3 = string.pack("<I4I4I4I4I4I4", 0x03000000, 1, 0, 0, 0, 0)
        for name, data in pairs({ ["revision 2"] = v2, ["revision 3"] = v3 }) do
            local r = sys.setxattr(vm, "/mt/filecaps", "security.capability", data)
            t:assert_eq(r.ret, -1, "installing " .. name .. " file capabilities is refused")
            t:assert_eq(r.errno, sys.E.PERM, "EPERM: the dead CAP_SETFCAP policy")
        end
        -- Removing stale metadata is the ordinary FILE_WRITE_EA path, so
        -- it is not refused by that policy — there is simply nothing there.
        local rm = sys.removexattr(vm, "/mt/filecaps", "security.capability")
        t:assert_eq(rm.errno, sys.E.NODATA,
            "removal is not blocked by the dead-capability policy: "
            .. sys.errname(rm.errno))
    end)

test("a privilege consulted through security_capable is marked used twice",
    { spec = "PKM *cred.dac.privilege-use-double-counted",
      covered_by = "kunit:pkm_kunit_misc",
      skip = "privilege use is recorded as a bitmask with no counter and no " ..
             "per-use audit event, so a double count has no witness from the " ..
             "guest; runs under pkm_kunit_security_capable_marks_privilege_use_twice, " ..
             "which counts the recorder's calls across one security_capable()" },
    function(t) end)

-- ---- the LSM stack ---------------------------------------------------

--- The registered LSM list, from securityfs.
local function registered_lsms()
    assert(hooks.hook_path(vm, "unused"))   -- mounts securityfs once
    local fd, errno = sys.open(vm, hooks.SECURITYFS_AT .. "/lsm", sys.O.RDONLY)
    assert(fd, "open securityfs/lsm: " .. sys.errname(errno or 0))
    local data = sys.read(vm, fd, 512)
    sys.close(vm, fd)
    local out = {}
    for name in (data or ""):gmatch("[%w_]+") do out[#out + 1] = name end
    return out, data
end

test("the MAC LSMs and the BPF LSM are not in the stack",
    { spec = "PKM *cred.dac.mac-lsms-disabled" }, function(t)
        local names, raw = registered_lsms()
        local present = {}
        for _, n in ipairs(names) do present[n] = true end
        for _, banned in ipairs({ "selinux", "apparmor", "smack", "tomoyo", "bpf" }) do
            t:assert(not present[banned],
                banned .. " must not be registered; the stack is " .. tostring(raw))
        end
        t:assert(present.pkm, "and KACS itself did activate: " .. tostring(raw))
    end)

test("non-MAC LSMs stack safely alongside KACS",
    { spec = "PKM *cred.dac.non-mac-lsms-allowed" }, function(t)
        local names, raw = registered_lsms()
        local present = {}
        for _, n in ipairs(names) do present[n] = true end
        local allowed = { capability = true, pkm = true, landlock = true,
                          lockdown = true, yama = true, integrity = true,
                          ima = true, evm = true, safesetid = true,
                          loadpin = true }
        local found = 0
        for _, n in ipairs(names) do
            t:assert(allowed[n], n .. " is not a permitted non-MAC LSM: " .. tostring(raw))
            if n == "landlock" or n == "lockdown" or n == "yama" then found = found + 1 end
        end
        t:assert(found > 0,
            "at least one of landlock/lockdown/yama stacks with KACS: " .. tostring(raw))
    end)

