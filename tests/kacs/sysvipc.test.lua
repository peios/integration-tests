-- PKM §3.11 — System V IPC objects: every message queue, shared memory
-- segment and semaphore array carries a security descriptor stamped
-- from its creator's token, the nine-bit `ipc_perm` mode is inert, and
-- the descriptor is addressed by kind and id rather than by a path.
--
-- The agent is SYSTEM and the default descriptor grants SYSTEM
-- GENERIC_ALL, so it passes everything: the subject of a rights case is
-- always a minted principal, and the agent's part is to create the
-- object and author the DACL the principal is judged on.
--
-- SysV objects outlive their creator, so every test removes what it
-- made; the keys are drawn from a per-test counter so a leaked object
-- cannot make a later test claim the wrong id.

local sys = require("helpers.sys")
local token = require("helpers.token")
local kacs = require("helpers.kacs")
local access = require("helpers.access")
local netobj = require("helpers.netobj")

local vm = provium:vm("vsysvipc", "kernel-only"):boot()

local IPC = netobj.IPC
local CTL = netobj.CTL
local SD_AT = netobj.SD_AT
local TCB = token.bit(token.PRIV.TCB)
local LOCK_MEMORY = token.bit(token.PRIV.LOCK_MEMORY)

local next_key = 0x50000
local function key() next_key = next_key + 1; return next_key end

--- A message queue holding one message, plus a shm segment and a
--- semaphore array, all created by the agent with `mode`. Returns the
--- three ids; the caller must remove them.
local function make_objects(t, mode)
    local msg = assert(netobj.msgget(vm, key(), netobj.IPC_CREAT | (mode or netobj.MODE_0666)))
    local shm = assert(netobj.shmget(vm, key(), 4096,
        netobj.IPC_CREAT | (mode or netobj.MODE_0666)))
    local sem = assert(netobj.semget(vm, key(), 2,
        netobj.IPC_CREAT | (mode or netobj.MODE_0666)))
    t:assert_eq(netobj.msgsnd(vm, msg).ret, 0, "a message is queued for msgrcv to find")
    return msg, shm, sem
end

local function drop(msg, shm, sem)
    if msg then netobj.msgctl(vm, msg, CTL.RMID) end
    if shm then netobj.shmctl(vm, shm, CTL.RMID) end
    if sem then netobj.semctl(vm, sem, 0, CTL.RMID) end
end

--- Author a DACL granting exactly `mask` to TEST_USER on all three,
--- keeping SYSTEM at GENERIC_ALL so the agent can still re-seed the
--- queue between cases. Only TEST_USER's verdicts are asserted on.
local function grant_all_three(msg, shm, sem, mask)
    local sd = kacs.descriptor(kacs.acl({
        kacs.ace(kacs.ACE_ALLOWED, mask, token.SID.TEST_USER),
        kacs.ace(kacs.ACE_ALLOWED, IPC.GENERIC_ALL, token.SID.LOCAL_SYSTEM),
    }))
    netobj.ipc_set_sd(vm, SD_AT.MSG, msg, sd)
    netobj.ipc_set_sd(vm, SD_AT.SHM, shm, sd)
    netobj.ipc_set_sd(vm, SD_AT.SEM, sem, sd)
end

--- The verdicts a principal gets on one object of each kind, as a table
--- of operation name → true (allowed) / errno (refused).
local function verdicts(w, msg, shm, sem)
    local function v(r) return r.ret >= 0 or r.errno end
    local out = {}
    out.msgrcv = v(netobj.msgrcv(w, msg))
    out.msgsnd = v(netobj.msgsnd(w, msg, "wxyz"))
    out.shmat_ro = v(netobj.shmat(w, shm, netobj.SHM_RDONLY))
    out.shmat_rw = v(netobj.shmat(w, shm, 0))
    out.getval = v(netobj.semctl(w, sem, 0, CTL.SEM_GETVAL))
    out.setval = v(netobj.semctl(w, sem, 0, CTL.SEM_SETVAL, 1))
    out.ipc_stat = v(netobj.ctl_buf(w, netobj.NR.shmctl, shm, CTL.STAT))
    out.read_control = v({ ret = netobj.ipc_get_sd(w, SD_AT.SHM, shm, kacs.SI.DACL)
        and 0 or -1, errno = select(2, netobj.ipc_get_sd(w, SD_AT.SHM, shm, kacs.SI.DACL)) or 0 })
    return out
end

-- ---- the mode is inert ----------------------------------------------

test("the nine-bit ipc_perm mode never decides: the descriptor does",
    { spec = "PKM *sysvipc.mode-inert" }, function(t)
        -- Mode 0000 would refuse everyone under ipcperms(); the DACL
        -- grants the principal everything and it works anyway.
        local open_msg = assert(netobj.msgget(vm, key(), netobj.IPC_CREAT | 0))
        netobj.ipc_set_sd(vm, SD_AT.MSG, open_msg,
            netobj.only(token.SID.TEST_USER, IPC.GENERIC_ALL))
        -- Mode 0666 would admit everyone; the DACL grants nothing.
        local shut_msg = assert(netobj.msgget(vm, key(),
            netobj.IPC_CREAT | netobj.MODE_0666))
        netobj.ipc_set_sd(vm, SD_AT.MSG, shut_msg, kacs.deny_all())
        token.as_principal(t, vm, {}, function(w)
            t:assert_eq(netobj.msgsnd(w, open_msg).ret, 0,
                "mode 0000 with a granting DACL is usable")
            local refused = netobj.msgsnd(w, shut_msg)
            t:assert_eq(refused.ret, -1, "mode 0666 with an empty DACL is not")
            t:assert_eq(refused.errno, sys.E.ACCES, "EACCES from KACS, not from the mode")
        end)
        drop(open_msg); drop(shut_msg)
    end)

-- ---- the descriptor --------------------------------------------------

test("an object's descriptor is built from its creator's effective token",
    { spec = "PKM *sysvipc.default-descriptor" }, function(t)
        local created
        token.as_principal(t, vm, {}, function(w)
            created = assert(netobj.shmget(w, key(), 4096))
        end)
        local sd = assert(netobj.ipc_get_sd(vm, SD_AT.SHM, created))
        local parsed = token.parse_sd(sd)
        t:assert_eq(parsed.owner, token.SID.TEST_USER,
            "owner is the creator's user SID: " .. token.sid_string(parsed.owner))
        t:assert(parsed.group, "a group is present too")
        t:assert_eq(#parsed.dacl, 3, "three ACEs")
        for _, want in ipairs({ token.SID.TEST_USER, token.SID.ADMINISTRATORS,
                                token.SID.LOCAL_SYSTEM }) do
            local ace = token.find_ace(parsed.dacl, want, kacs.ACE_ALLOWED)
            t:assert(ace, token.sid_string(want) .. " has an allow ACE")
            t:assert_eq(ace.mask, IPC.GENERIC_ALL, "at GENERIC_ALL")
        end
        drop(nil, created)
    end)

test("the descriptor lives as long as the object, not as long as its creator",
    { spec = "PKM *sysvipc.descriptor-lifetime" }, function(t)
        local created
        token.as_principal(t, vm, { projected_uid = 6060 }, function(w)
            created = assert(netobj.shmget(w, key(), 4096))
        end)
        -- The creator's worker is gone; the object and its descriptor are not.
        local sd = netobj.ipc_get_sd(vm, SD_AT.SHM, created)
        t:assert(sd, "the descriptor still reads back after the creator exited")
        t:assert_eq(token.parse_sd(sd).owner, token.SID.TEST_USER,
            "still naming the creator")
        t:assert_eq(netobj.shmctl(vm, created, CTL.RMID).ret, 0, "the object is removed")
        local gone, errno = netobj.ipc_get_sd(vm, SD_AT.SHM, created)
        t:assert(not gone, "and the descriptor goes with it: " .. sys.errname(errno or 0))
    end)

test("the generic rights map as the table says",
    { spec = "PKM *sysvipc.generic-mapping" }, function(t)
        local msg, shm, sem = make_objects(t)
        -- GENERIC_READ: read plus query plus READ_CONTROL.
        grant_all_three(msg, shm, sem, IPC.GENERIC_READ)
        token.as_principal(t, vm, {}, function(w)
            local v = verdicts(w, msg, shm, sem)
            t:assert_eq(v.msgrcv, true, "GENERIC_READ grants msgrcv")
            t:assert_eq(v.ipc_stat, true, "and IPC_STAT")
            t:assert_eq(v.read_control, true, "and READ_CONTROL")
            t:assert_eq(v.msgsnd, sys.E.ACCES, "but not msgsnd")
            t:assert_eq(v.setval, sys.E.ACCES, "and not SETVAL")
        end)
        netobj.msgsnd(vm, msg)
        -- GENERIC_WRITE: write plus set-information plus READ_CONTROL.
        grant_all_three(msg, shm, sem, IPC.GENERIC_WRITE)
        token.as_principal(t, vm, {}, function(w)
            local v = verdicts(w, msg, shm, sem)
            t:assert_eq(v.msgsnd, true, "GENERIC_WRITE grants msgsnd")
            t:assert_eq(v.setval, true, "and SETVAL")
            t:assert_eq(v.read_control, true, "and READ_CONTROL")
            t:assert_eq(v.msgrcv, sys.E.ACCES, "but not msgrcv")
            t:assert_eq(v.ipc_stat, sys.E.ACCES, "and not IPC_STAT")
        end)
        -- GENERIC_EXECUTE: query plus READ_CONTROL, and nothing else.
        grant_all_three(msg, shm, sem, IPC.GENERIC_EXECUTE)
        token.as_principal(t, vm, {}, function(w)
            local v = verdicts(w, msg, shm, sem)
            t:assert_eq(v.read_control, true, "GENERIC_EXECUTE grants READ_CONTROL")
            t:assert_eq(v.msgrcv, sys.E.ACCES, "and no read")
            t:assert_eq(v.msgsnd, sys.E.ACCES, "and no write")
        end)
        -- The query half of GENERIC_EXECUTE, isolated: IPC_STAT needs
        -- KACS_IPC_READ (ipcperms) and KACS_IPC_QUERY_INFORMATION (the
        -- ctl hook), so READ alone is not enough and READ plus
        -- GENERIC_EXECUTE is.
        grant_all_three(msg, shm, sem, IPC.READ)
        token.as_principal(t, vm, {}, function(w)
            t:assert_eq(verdicts(w, msg, shm, sem).ipc_stat, sys.E.ACCES,
                "KACS_IPC_READ alone does not answer IPC_STAT")
        end)
        grant_all_three(msg, shm, sem, IPC.READ | IPC.GENERIC_EXECUTE)
        token.as_principal(t, vm, {}, function(w)
            t:assert_eq(verdicts(w, msg, shm, sem).ipc_stat, true,
                "GENERIC_EXECUTE supplies the query right")
        end)
        -- GENERIC_ALL is everything above.
        netobj.msgsnd(vm, msg)
        grant_all_three(msg, shm, sem, IPC.GENERIC_ALL)
        token.as_principal(t, vm, {}, function(w)
            local v = verdicts(w, msg, shm, sem)
            for _, op in ipairs({ "msgrcv", "msgsnd", "shmat_ro", "shmat_rw",
                                  "getval", "setval", "ipc_stat", "read_control" }) do
                t:assert_eq(v[op], true, "GENERIC_ALL grants " .. op)
            end
        end)
        drop(msg, shm, sem)
    end)

-- ---- where the checks run -------------------------------------------

test("every data operation is an AccessCheck for the right its mode bits imply",
    { spec = "PKM *sysvipc.data-ops-access-check" }, function(t)
        local msg, shm, sem = make_objects(t)
        grant_all_three(msg, shm, sem, IPC.READ)
        token.as_principal(t, vm, {}, function(w)
            local v = verdicts(w, msg, shm, sem)
            t:assert_eq(v.msgrcv, true, "KACS_IPC_READ grants msgrcv")
            t:assert_eq(v.shmat_ro, true, "and a read-only shmat")
            t:assert_eq(v.getval, true, "and GETVAL")
            t:assert_eq(v.msgsnd, sys.E.ACCES, "and refuses msgsnd")
            t:assert_eq(v.shmat_rw, sys.E.ACCES, "and a read-write shmat")
            t:assert_eq(v.setval, sys.E.ACCES, "and SETVAL")
        end)
        netobj.msgsnd(vm, msg)
        grant_all_three(msg, shm, sem, IPC.WRITE)
        token.as_principal(t, vm, {}, function(w)
            local v = verdicts(w, msg, shm, sem)
            t:assert_eq(v.msgsnd, true, "KACS_IPC_WRITE grants msgsnd")
            t:assert_eq(v.setval, true, "and SETVAL")
            t:assert_eq(v.msgrcv, sys.E.ACCES, "and refuses msgrcv")
            t:assert_eq(v.shmat_ro, sys.E.ACCES, "and a read-only shmat")
            t:assert_eq(v.getval, sys.E.ACCES, "and GETVAL")
        end)
        -- SHM_LOCK is the set-information right (and Linux's own
        -- CAP_IPC_LOCK gate, which is SeLockMemoryPrivilege).
        netobj.ipc_set_sd(vm, SD_AT.SHM, shm,
            netobj.only(token.SID.TEST_USER, IPC.SET_INFORMATION))
        token.as_principal(t, vm, { privs_present = LOCK_MEMORY,
            privs_enabled = LOCK_MEMORY }, function(w)
            t:assert_eq(netobj.shmctl(w, shm, CTL.SHM_LOCK).ret, 0,
                "KACS_IPC_SET_INFORMATION grants SHM_LOCK")
            t:assert_eq(netobj.shmctl(w, shm, CTL.SHM_UNLOCK).ret, 0, "and SHM_UNLOCK")
        end)
        netobj.ipc_set_sd(vm, SD_AT.SHM, shm, netobj.only(token.SID.TEST_USER, IPC.READ))
        token.as_principal(t, vm, { privs_present = LOCK_MEMORY,
            privs_enabled = LOCK_MEMORY }, function(w)
            local r = netobj.shmctl(w, shm, CTL.SHM_LOCK)
            t:assert_eq(r.ret, -1, "and without it SHM_LOCK is refused")
            t:assert_eq(r.errno, sys.E.ACCES, "EACCES")
        end)
        drop(msg, shm, sem)
    end)

test("a *get on an existing key goes through the same check with the requested mode",
    { spec = "PKM *sysvipc.get-existing-key-checked" }, function(t)
        local k = key()
        local shm = assert(netobj.shmget(vm, k, 4096))
        netobj.ipc_set_sd(vm, SD_AT.SHM, shm, kacs.deny_all())
        token.as_principal(t, vm, {}, function(w)
            local r = w:syscall(netobj.NR.shmget, k, 4096, netobj.MODE_0666)
            t:assert_eq(r.ret, -1, "looking the key up is refused by the descriptor")
            t:assert_eq(r.errno, sys.E.ACCES, "EACCES")
        end)
        netobj.ipc_set_sd(vm, SD_AT.SHM, shm,
            netobj.only(token.SID.TEST_USER, IPC.GENERIC_READ))
        token.as_principal(t, vm, {}, function(w)
            local r = w:syscall(netobj.NR.shmget, k, 4096, tonumber("444", 8))
            t:assert_eq(r.ret, shm, "a read-only lookup is granted by KACS_IPC_READ")
            local rw = w:syscall(netobj.NR.shmget, k, 4096, netobj.MODE_0666)
            t:assert_eq(rw.ret, -1, "and a read-write one is not")
            t:assert_eq(rw.errno, sys.E.ACCES, "EACCES")
        end)
        drop(nil, shm)
    end)

test("the commands that address no object need nothing",
    { spec = "PKM *sysvipc.info-commands-unchecked" }, function(t)
        token.as_principal(t, vm, {}, function(w)
            for _, c in ipairs({ { "shmctl IPC_INFO", netobj.NR.shmctl, CTL.INFO },
                                 { "shmctl SHM_INFO", netobj.NR.shmctl, CTL.SHM_INFO },
                                 { "msgctl IPC_INFO", netobj.NR.msgctl, CTL.INFO },
                                 { "msgctl MSG_INFO", netobj.NR.msgctl, CTL.MSG_INFO },
                                 { "semctl IPC_INFO", netobj.NR.semctl, CTL.INFO },
                                 { "semctl SEM_INFO", netobj.NR.semctl, CTL.SEM_INFO } }) do
                local r
                if c[2] == netobj.NR.semctl then
                    r = w:syscall(c[2], { args = { 0, 0, c[3], 0 },
                        bufs = { string.rep("\0", 128) }, ptrs = { 3 } })
                else
                    r = netobj.ctl_buf(w, c[2], 0, c[3])
                end
                t:assert(r.ret >= 0,
                    c[1] .. " is answered for a principal holding nothing: "
                    .. sys.errname(r.errno))
            end
        end)
    end)

test("Linux's own ownership check on IPC_SET and IPC_RMID still runs first",
    { spec = "PKM *sysvipc.linux-owner-check-first" }, function(t)
        -- The agent creates, so the object's cuid is 0 and the
        -- principal's projected uid is not. The descriptor grants
        -- DELETE, which the hook is happy with; Linux is not.
        local m1 = assert(netobj.msgget(vm, key()))
        netobj.ipc_set_sd(vm, SD_AT.MSG, m1, netobj.only(token.SID.TEST_USER,
            IPC.DELETE | IPC.READ_CONTROL))
        token.as_principal(t, vm, {}, function(w)
            local r = netobj.msgctl(w, m1, CTL.RMID)
            t:assert_eq(r.ret, -1, "DELETE alone does not remove another creator's object")
            t:assert_eq(r.errno, sys.E.PERM,
                "EPERM: Linux compared the projected uid and refused first")
        end)
        -- SeTcbPrivilege is what CAP_SYS_ADMIN maps to, and satisfies
        -- Linux's half. The descriptor still has to grant DELETE.
        local m2 = assert(netobj.msgget(vm, key()))
        netobj.ipc_set_sd(vm, SD_AT.MSG, m2, netobj.only(token.SID.TEST_USER,
            IPC.READ | IPC.READ_CONTROL))
        token.as_principal(t, vm, { privs_present = TCB, privs_enabled = TCB },
            function(w)
                local r = netobj.msgctl(w, m2, CTL.RMID)
                t:assert_eq(r.ret, -1, "SeTcbPrivilege alone does not either")
                t:assert_eq(r.errno, sys.E.ACCES, "EACCES: the hook only further restricts")
            end)
        local m3 = assert(netobj.msgget(vm, key()))
        netobj.ipc_set_sd(vm, SD_AT.MSG, m3, netobj.only(token.SID.TEST_USER,
            IPC.DELETE | IPC.READ_CONTROL))
        token.as_principal(t, vm, { privs_present = TCB, privs_enabled = TCB },
            function(w)
                t:assert_eq(netobj.msgctl(w, m3, CTL.RMID).ret, 0,
                    "an administrator who is not the creator needs both")
            end)
        drop(m1); drop(m2)
    end)

-- ---- reading and changing a descriptor ------------------------------

test("kacs_get_sd and kacs_set_sd address a SysV object by kind and id with a NULL path",
    { spec = "PKM *sysvipc.sd-addressing" }, function(t)
        local msg = assert(netobj.msgget(vm, key()))
        local shm = assert(netobj.shmget(vm, key(), 4096))
        local sem = assert(netobj.semget(vm, key(), 1))
        for _, c in ipairs({ { "KACS_SD_AT_SYSV_MSG", SD_AT.MSG, msg },
                             { "KACS_SD_AT_SYSV_SHM", SD_AT.SHM, shm },
                             { "KACS_SD_AT_SYSV_SEM", SD_AT.SEM, sem } }) do
            local sd, errno = netobj.ipc_get_sd(vm, c[2], c[3])
            t:assert(sd, c[1] .. " with the id in dirfd reads the descriptor: "
                .. sys.errname(errno or 0))
            t:assert(token.parse_sd(sd).dacl, "and it carries a DACL")
        end
        -- A path may not accompany the kind bits.
        local with_path = vm:syscall(kacs.SYS.GET_SD, {
            args = { shm, 0, kacs.SI.DACL, 0, 4096, SD_AT.SHM },
            bufs = { sys.cstr("/"), string.rep("\0", 4096) },
            ptrs = { 1, 3 },
        })
        t:assert_eq(with_path.ret, -1, "a non-NULL path is refused")
        t:assert_eq(with_path.errno, sys.E.INVAL, "EINVAL")
        -- Exactly one kind bit, and no other flag alongside.
        for _, bad in ipairs({ { "two kinds", SD_AT.SHM | SD_AT.MSG },
                               { "a kind plus another flag",
                                 SD_AT.SHM | sys.AT_EMPTY_PATH } }) do
            local r = vm:syscall(kacs.SYS.GET_SD, {
                args = { shm, 0, kacs.SI.DACL, 0, 4096, bad[2] },
                bufs = { string.rep("\0", 4096) }, ptrs = { 3 },
            })
            t:assert_eq(r.ret, -1, bad[1] .. " is refused")
            t:assert_eq(r.errno, sys.E.INVAL, "EINVAL")
        end
        -- Changing needs WRITE_DAC, and merges component by component.
        local replacement = netobj.only(token.SID.TEST_USER_2, IPC.GENERIC_READ)
        t:assert_eq(netobj.ipc_set_sd(vm, SD_AT.SHM, shm, replacement).ret, 0,
            "the agent writes a new DACL")
        local after = token.parse_sd(assert(netobj.ipc_get_sd(vm, SD_AT.SHM, shm)))
        t:assert_eq(#after.dacl, 1, "which replaced the DACL")
        t:assert_eq(after.dacl[1].sid, token.SID.TEST_USER_2, "with the one ACE written")
        t:assert(after.owner, "while owner and group survived the merge")
        -- Reading the SACL asks for ACCESS_SYSTEM_SECURITY, which a
        -- principal holding only READ_CONTROL does not have.
        netobj.ipc_set_sd(vm, SD_AT.SHM, shm,
            netobj.only(token.SID.TEST_USER, IPC.READ_CONTROL))
        token.as_principal(t, vm, {}, function(w)
            t:assert(netobj.ipc_get_sd(w, SD_AT.SHM, shm, kacs.SI.DACL),
                "READ_CONTROL reads the DACL")
            local sacl, errno = netobj.ipc_get_sd(w, SD_AT.SHM, shm, kacs.SI.SACL)
            t:assert(not sacl, "but not the SACL: " .. sys.errname(errno or 0))
        end)
        drop(msg, shm, sem)
    end)

test("an unknown id is EINVAL",
    { spec = "PKM *sysvipc.sd-lookup-errors" }, function(t)
        for _, kind in ipairs({ SD_AT.SHM, SD_AT.MSG, SD_AT.SEM }) do
            local sd, errno = netobj.ipc_get_sd(vm, kind, 0x7FFFFFF0)
            t:assert(not sd, "an id no object holds is refused")
            t:assert_eq(errno, sys.E.INVAL, "EINVAL")
        end
        local set = netobj.ipc_set_sd(vm, SD_AT.SHM, 0x7FFFFFF0,
            netobj.only(token.SID.TEST_USER, IPC.GENERIC_ALL))
        t:assert_eq(set.ret, -1, "and so is a write to one")
        t:assert_eq(set.errno, sys.E.INVAL, "EINVAL")
    end)

test("a removed id is EINVAL like an unknown one",
    { spec = "PKM *sysvipc.sd-lookup-errors" }, function(t)
        -- IPC_RMID drops the id from the namespace in the step that marks
        -- the object deleted, so a later lookup cannot see the removal;
        -- EIDRM is the racing case only.
        local shm = assert(netobj.shmget(vm, key(), 4096))
        t:assert(netobj.ipc_get_sd(vm, SD_AT.SHM, shm),
            "the descriptor reads while the object is live")
        t:assert_eq(netobj.shmctl(vm, shm, CTL.RMID).ret, 0, "the object is removed")
        local sd, errno = netobj.ipc_get_sd(vm, SD_AT.SHM, shm)
        t:assert(not sd, "its descriptor is no longer readable")
        t:assert_eq(errno, sys.E.INVAL, "a removed id is EINVAL: " .. sys.errname(errno or 0))
    end)

-- ---- names -----------------------------------------------------------

test("the key namespace is claim-on-create and the descriptor cannot protect a name",
    { spec = "PKM *sysvipc.key-claim-on-create" }, function(t)
        local k = key()
        local claimed
        token.as_principal(t, vm, {}, function(w)
            claimed = assert(netobj.shmget(w, k, 4096))
            t:assert(claimed >= 0, "the first caller to ask owns the key")
        end)
        local sd = assert(netobj.ipc_get_sd(vm, SD_AT.SHM, claimed))
        t:assert_eq(token.parse_sd(sd).owner, token.SID.TEST_USER,
            "and the object it created is protected by its own descriptor")
        token.as_principal(t, vm, { user_sid = token.SID.TEST_USER_2 }, function(w)
            -- IPC_EXCL is how a program that needs a specific key learns
            -- it did not get it.
            local excl, errno = netobj.shmget(w, k, 4096,
                netobj.IPC_CREAT | netobj.IPC_EXCL | netobj.MODE_0666)
            t:assert(not excl,
                "a second program's IPC_EXCL create fails: " .. sys.errname(errno or 0))
            -- Nothing stops it claiming a key nobody has taken yet.
            local free = key()
            local mine = netobj.shmget(w, free, 4096)
            t:assert(mine, "and a free key is anyone's to claim")
            local other_sd = assert(netobj.ipc_get_sd(vm, SD_AT.SHM, mine))
            t:assert_eq(token.parse_sd(other_sd).owner, token.SID.TEST_USER_2,
                "with the claimant's own descriptor on it")
            netobj.shmctl(vm, mine, CTL.RMID)
        end)
        drop(nil, claimed)
    end)
