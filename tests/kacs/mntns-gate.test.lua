-- PKM §3.13 — the mount gate: the three rungs `pkm_kacs_may_mount_op()`
-- asks in order (privilege, no descriptor, descriptor), the operations
-- and filesystem types a descriptor can admit, the tmpfs a namespace
-- descriptor admits being stamped for its creator, and the
-- `kacs:kacs_mntns` event that records all of it.
--
-- Which rung decided is read from the event rather than guessed from
-- the errno: every refusal the gate makes is EPERM, so "the descriptor
-- refused" and "the descriptor was never asked" look the same from the
-- syscall. A worker issues every syscall on one thread, so its records
-- carry its pid and the agent's own mounting does not get mixed in.
--
-- Second identities in a namespace come from impersonation, as in
-- mntns-object.test.lua: the gate asks the caller's effective token, and
-- installing another user's primary would need SeTcbPrivilege. Where a
-- case needs the *same* user to drop the mount privilege mid-test (to
-- hold a detached-tree fd only a privileged caller can make), it
-- installs a privilege-free token minted in the same logon session,
-- which SeAssignPrimaryTokenPrivilege allows.
--
-- Every namespace change happens on a worker: the agent is PID 1 and
-- its own table is the initial one.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local facs = require("helpers.facs")
local hooks = require("helpers.hooks")
local stratafs = require("helpers.stratafs")

local vm = provium:vm("vmntnsgate", "kernel-only"):boot()

-- A minted principal holds no SeChangeNotifyPrivilege; `/` grants
-- traverse instead, so no case hands one a privilege to walk.
kacs.set_sd(vm, "/", kacs.grant(kacs.ALL_RIGHTS))
local B = facs.workspace(vm, "mntns-gate")
for _, d in ipairs({ "src", "dst", "dst2", "held", "fs", "lo", "up", "agentmnt" }) do
    vm:mkdir(B .. "/" .. d, { parents = true })
end
vm:write_file(B .. "/src/marker", "src")
vm:write_file(B .. "/lo/lower-file", "from the lower stratum")

local P = token.PRIV
local MANAGE_VOLUME = token.bit(P.MANAGE_VOLUME)
local TCB = token.bit(P.TCB)
local IMPERSONATE = token.bit(P.IMPERSONATE)
local ASSIGN = token.bit(P.ASSIGN_PRIMARY_TOKEN)
local MOUNT_PRIVS = MANAGE_VOLUME | TCB

local NR = { unshare = 272, chdir = 80, pivot_root = 155, open_tree = 428,
             move_mount = 429, fsopen = 430, fsconfig = 431, fsmount = 432,
             mount_setattr = 442 }
local CLONE_NEWNS = 0x00020000
local MS = { RDONLY = 1, REMOUNT = 32, BIND = 4096, MOVE = 8192, REC = 16384,
             UNBINDABLE = 1 << 17, PRIVATE = 1 << 18, SLAVE = 1 << 19,
             SHARED = 1 << 20 }
local MNT_FORCE, MNT_DETACH = 1, 2
local OPEN_TREE_CLONE = 1
local MOVE_MOUNT_F_EMPTY_PATH = 4
local MOUNT_ATTR_RDONLY = 1
local MP = kacs.MOUNT_POLICY
local GENERIC_ALL = 0x10000000

-- Principals ------------------------------------------------------------------

local function principal(privs, over)
    local s = { privs_present = privs or 0, privs_enabled = privs or 0 }
    for k, v in pairs(over or {}) do s[k] = v end
    return s
end

local function impersonation(spec)
    spec.token_type = token.TYPE.IMPERSONATION
    spec.impersonation_level = token.LEVEL.IMPERSONATION
    return spec
end

local function become(w, fd)
    local r = token.install(w, fd)
    assert(r.ret == 0, "KACS_IOC_INSTALL: " .. sys.errname(r.errno))
    sys.close(w, fd)
end

--- A worker that mints every spec in `specs` while it is still SYSTEM,
--- installs the first, and hands `fn` the worker and the rest's fds.
local function as(t, specs, fn)
    local w = vm:spawn_worker()
    local ok, err = pcall(function()
        local fds = {}
        for i, s in ipairs(specs) do
            local fd, e = token.mint(w, s)
            assert(fd, "mint: " .. sys.errname(e or 0))
            fds[i] = fd
        end
        become(w, fds[1])
        fn(w, table.unpack(fds, 2))
    end)
    w:kill(); w:join()
    if not ok then error(err, 0) end
end

local function pid_of(w) return w:syscall(sys.NR.getpid).ret end

-- Operations ------------------------------------------------------------------

local function unshare(w) return w:syscall(NR.unshare, CLONE_NEWNS) end
local function bind(w, from, to, extra)
    return sys.mount(w, { source = from, target = to, flags = MS.BIND | (extra or 0) })
end
local function new_fs(w, fstype, at, data)
    return sys.mount(w, { source = "none", target = at, fstype = fstype, data = data })
end
local function chdir(w, path)
    return w:syscall(NR.chdir, { args = { 0 }, bufs = { sys.cstr(path) }, ptrs = { 0 } })
end
local function pivot_dot(w)
    return w:syscall(NR.pivot_root, { args = { 0, 0 },
        bufs = { sys.cstr("."), sys.cstr(".") }, ptrs = { 0, 1 } })
end
local function open_tree(w, path)
    return w:syscall(NR.open_tree, { args = { sys.AT_FDCWD, 0, OPEN_TREE_CLONE },
        bufs = { sys.cstr(path) }, ptrs = { 1 } })
end
local function fsopen(w, fstype)
    return w:syscall(NR.fsopen, { args = { 0, 0 }, bufs = { sys.cstr(fstype) }, ptrs = { 0 } })
end

local function ok(t, r, what)
    t:assert_eq(r.ret, 0, what .. ": " .. sys.errname(r.errno or 0))
end
local function refused(t, r, what)
    t:assert_eq(r.ret, -1, what .. " is refused")
    t:assert_eq(r.errno, sys.E.PERM, what .. ": " .. sys.errname(r.errno or 0))
end

-- Tracing ---------------------------------------------------------------------

--- Run `fn` with the given kacs: events enabled; return their records
--- as { pid, event, reason, verdict, op, desired, privilege, ret, line }.
local function traced(t, events, fn)
    for _, ev in ipairs(events) do
        local started, err = hooks.trace_start(vm, "kacs/" .. ev)
        t:assert(started, "tracing starts on " .. ev .. ": " .. tostring(err))
    end
    local ran, raised = pcall(fn)
    local lines
    for _, ev in ipairs(events) do
        local got = hooks.trace_stop(vm, "kacs/" .. ev)
        lines = lines or got
    end
    if not ran then error(raised, 0) end
    local out = {}
    for _, l in ipairs(lines or {}) do
        local event, body = l:match(":%s+(kacs_[%w_]+):%s+(.*)$")
        if event then
            out[#out + 1] = {
                pid = tonumber(l:match("^%s*.-%-(%d+)%s+%[")),
                event = event,
                reason = body:match("reason=(%S+)"),
                verdict = body:match("verdict=(%S+)"),
                op = tonumber(body:match(" op=(%d+)")),
                desired = body:match("desired=(%S+)"),
                privilege = tonumber((body:match("privilege=0x(%x+)") or ""), 16),
                ret = tonumber(body:match("ret=(%-?%d+)")),
                line = body,
            }
        end
    end
    return out
end

local function select_(records, pid, event)
    local out = {}
    for _, r in ipairs(records) do
        if (pid == nil or r.pid == pid) and r.event == (event or "kacs_mntns") then
            out[#out + 1] = r
        end
    end
    return out
end

local function summary(records)
    local out = {}
    for _, r in ipairs(records) do
        out[#out + 1] = (r.reason or "?") .. "/" .. (r.verdict or "?") .. "@" .. tostring(r.op)
    end
    return "[" .. table.concat(out, " ") .. "]"
end

local function with_reason(records, reason)
    local out = {}
    for _, r in ipairs(records) do if r.reason == reason then out[#out + 1] = r end end
    return out
end

--- Trace one operation by worker `w` and return its kacs_mntns records.
local function gate_of(t, w, fn)
    local pid = pid_of(w)
    local result
    local records = traced(t, { "kacs_mntns" }, function() result = fn() end)
    return result, select_(records, pid)
end

-- The rungs -------------------------------------------------------------------

test("the gate asks privilege, then whether a descriptor exists, then the descriptor",
    { spec = "PKM *mntns.gate-rungs" }, function(t)
        local pids = {}
        local records = traced(t, { "kacs_mntns" }, function()
            -- Rung 1 answers before rung 2 is reached: a privileged
            -- caller is admitted in the initial table, which has no
            -- descriptor at all.
            as(t, { principal(MANAGE_VOLUME) }, function(w)
                pids.privileged = pid_of(w)
                ok(t, bind(w, B .. "/src", B .. "/dst"), "a privileged bind in the initial table")
                ok(t, sys.umount(w, B .. "/dst"), "and its unmount")
            end)
            -- Rung 2 answers before rung 3: an operation no descriptor
            -- could ever admit is refused in the initial table as
            -- "no descriptor", not as "operation not admitted".
            as(t, { principal() }, function(w)
                pids.initial = pid_of(w)
                refused(t, sys.mount(w, { target = B .. "/dst",
                    flags = MS.REMOUNT | MS.BIND | MS.RDONLY }), "a remount in the initial table")
                refused(t, bind(w, B .. "/src", B .. "/dst"), "a bind in the initial table")
            end)
            -- Rung 3, in the caller's own table.
            as(t, { principal() }, function(w)
                pids.own = pid_of(w)
                ok(t, unshare(w), "unshare")
                ok(t, bind(w, B .. "/src", B .. "/dst"), "a bind in the caller's own table")
                refused(t, sys.mount(w, { target = B .. "/dst",
                    flags = MS.REMOUNT | MS.BIND | MS.RDONLY }), "a remount there")
                ok(t, sys.umount(w, B .. "/dst"), "an unmount there")
            end)
        end)

        local priv = select_(records, pids.privileged)
        t:assert_eq(#priv, 2, "the privileged caller left two gate records: " .. summary(priv))
        for _, r in ipairs(priv) do
            t:assert_eq(r.reason, "gate-privilege", "each answered by the privilege rung: " .. summary(priv))
            t:assert_eq(r.verdict, "allow", "and admitted")
        end

        local initial = select_(records, pids.initial)
        t:assert_eq(#initial, 2, "two records in the initial table: " .. summary(initial))
        for _, r in ipairs(initial) do
            t:assert_eq(r.reason, "gate-no-sd",
                "each stopped at the no-descriptor rung, the remount too: " .. summary(initial))
            t:assert_eq(r.verdict, "deny", "and refused")
        end

        local own = select_(records, pids.own)
        local gates = {}
        for _, r in ipairs(own) do if r.reason ~= "sd-alloc" then gates[#gates + 1] = r end end
        t:assert_eq(#gates, 3, "three gate records in the caller's own table: " .. summary(own))
        t:assert_eq(gates[1] and gates[1].reason, "gate-sd-decision",
            "the bind went to the descriptor: " .. summary(own))
        t:assert_eq(gates[1] and gates[1].verdict, "allow", "which admitted it")
        t:assert_eq(gates[2] and gates[2].reason, "gate-op-not-admitted",
            "the remount was turned away before the descriptor: " .. summary(own))
        t:assert_eq(gates[3] and gates[3].reason, "gate-sd-decision",
            "the unmount went to the descriptor: " .. summary(own))
    end)

test("the privilege rung is decided first and alone, and marks the privilege used",
    { spec = "PKM *mntns.gate-privilege-first" }, function(t)
        -- A privileged identity in a table whose descriptor does not name
        -- it is admitted — which only the privilege rung can do — and the
        -- descriptor is never consulted. TEST_USER creates the table and
        -- then acts as TEST_USER_2 holding SeManageVolumePrivilege.
        local holder = impersonation(principal(MANAGE_VOLUME, { user_sid = token.SID.TEST_USER_2 }))
        local pid
        local records = traced(t, { "kacs_mntns" }, function()
            as(t, { principal(IMPERSONATE), holder }, function(w, imp)
                ok(t, unshare(w), "TEST_USER makes a table")
                pid = pid_of(w)
                ok(t, token.impersonate(w, imp), "and acts as a privileged TEST_USER_2")
                ok(t, bind(w, B .. "/src", B .. "/dst"),
                    "a bind by an identity the descriptor does not name")
                local privs = assert(token.privileges(w, imp))
                t:assert_eq(privs.used & MANAGE_VOLUME, MANAGE_VOLUME,
                    "SeManageVolumePrivilege is marked used")
            end)
        end)
        local mine = select_(records, pid)
        local gate = {}
        for _, r in ipairs(mine) do if r.reason ~= "sd-alloc" then gate[#gate + 1] = r end end
        t:assert_eq(#gate, 1, "one gate record: " .. summary(mine))
        t:assert_eq(gate[1] and gate[1].reason, "gate-privilege", "from the privilege rung")
        t:assert_eq(#with_reason(mine, "gate-sd-decision"), 0, "the descriptor was never asked")

        -- An unprivileged caller is never asked the privilege question,
        -- so its routine bind records no privilege refusal; a privilege
        -- that is held but not enabled is not the privilege.
        local cases = {
            { "a principal holding nothing", principal() },
            { "a principal holding SeManageVolumePrivilege disabled",
              principal(0, { privs_present = MANAGE_VOLUME }) },
        }
        for _, c in ipairs(cases) do
            local wpid
            local recs = traced(t, { "kacs_mntns", "kacs_privilege" }, function()
                as(t, { c[2] }, function(w)
                    wpid = pid_of(w)
                    ok(t, unshare(w), c[1] .. " makes a table")
                    ok(t, bind(w, B .. "/src", B .. "/dst"), c[1] .. ": a bind there")
                    local self = assert(token.open_self(w, token.RIGHT.QUERY))
                    t:assert_eq(assert(token.privileges(w, self)).used & MOUNT_PRIVS, 0,
                        c[1] .. ": no mount privilege is marked used")
                end)
            end)
            local mntns = select_(recs, wpid)
            t:assert_eq(#with_reason(mntns, "gate-privilege"), 0,
                c[1] .. ": the privilege rung did not answer: " .. summary(mntns))
            t:assert_eq(#with_reason(mntns, "gate-sd-decision"), 1,
                c[1] .. ": the descriptor did: " .. summary(mntns))
            local asked = {}
            for _, r in ipairs(select_(recs, wpid, "kacs_privilege")) do
                if r.privilege and (r.privilege & MOUNT_PRIVS) ~= 0 then
                    asked[#asked + 1] = r.line
                end
            end
            t:assert_eq(#asked, 0, c[1] .. ": no mount-privilege check was recorded: " ..
                table.concat(asked, " | "))
        end
    end)

test("without the privilege, nothing changes the initial table",
    { spec = "PKM *mntns.root-table-privilege-only" }, function(t)
        -- A mount of the agent's, for the unmount case to aim at.
        ok(t, bind(vm, B .. "/src", B .. "/held"), "the agent holds a bind in the initial table")
        local ran, err = pcall(function()
            as(t, { principal() }, function(w)
                refused(t, bind(w, B .. "/src", B .. "/dst"), "a principal's bind")
                refused(t, bind(w, B .. "/src", B .. "/dst", MS.REC), "its recursive bind")
                refused(t, sys.umount(w, B .. "/held"), "its unmount of an existing mount")
                refused(t, sys.umount(w, B .. "/held", MNT_DETACH), "its lazy unmount")
                refused(t, new_fs(w, "tmpfs", B .. "/dst"), "its tmpfs")
                ok(t, chdir(w, B .. "/src"), "chdir")
                refused(t, pivot_dot(w), "its pivot_root")
            end)
            -- Either mount privilege, enabled, is the way in.
            for _, p in ipairs({ { "SeManageVolumePrivilege", MANAGE_VOLUME },
                                 { "SeTcbPrivilege", TCB } }) do
                as(t, { principal(p[2]) }, function(w)
                    ok(t, bind(w, B .. "/src", B .. "/dst"), p[1] .. ": a bind in the initial table")
                    ok(t, sys.umount(w, B .. "/dst"), p[1] .. ": and its unmount")
                end)
            end
        end)
        sys.umount(vm, B .. "/held", MNT_DETACH)
        if not ran then error(err, 0) end
    end)

test("the descriptor rung is AccessCheck for KACS_MNTNS_MOUNT against the caller's table",
    { spec = "PKM *mntns.gate-descriptor-check" }, function(t)
        local other = impersonation(principal(0, { user_sid = token.SID.TEST_USER_2 }))
        as(t, { principal(IMPERSONATE), other }, function(w, imp)
            ok(t, unshare(w), "TEST_USER makes a table")
            local r, recs = gate_of(t, w, function() return bind(w, B .. "/src", B .. "/dst") end)
            ok(t, r, "the creator's bind")
            local d = with_reason(recs, "gate-sd-decision")[1]
            t:assert(d, "reached the descriptor: " .. summary(recs))
            t:assert_eq(d and d.desired, "0x1", "asking for KACS_MNTNS_MOUNT")
            t:assert_eq(d and d.verdict, "allow", "and granted")
            ok(t, sys.umount(w, B .. "/dst"), "unmount")

            ok(t, token.impersonate(w, imp), "now acting as TEST_USER_2")
            r, recs = gate_of(t, w, function() return bind(w, B .. "/src", B .. "/dst") end)
            refused(t, r, "TEST_USER_2's bind")
            d = with_reason(recs, "gate-sd-decision")[1]
            t:assert(d, "reached the descriptor: " .. summary(recs))
            t:assert_eq(d and d.desired, "0x1", "asking for the same right")
            t:assert_eq(d and d.verdict, "deny", "which the descriptor withholds")
            t:assert_eq(d and d.ret, -sys.E.ACCES, "an AccessCheck denial (EACCES), reported as EPERM")
        end)
    end)

-- What a descriptor can admit ----------------------------------------------------

test("a descriptor admits bind, unmount, pivot_root and allowlisted new filesystems, and nothing else",
    { spec = "PKM *mntns.admissible-operations" }, function(t)
        -- The yes rows.
        as(t, { principal() }, function(w)
            ok(t, unshare(w), "unshare")
            ok(t, bind(w, B .. "/src", B .. "/dst"), "MS_BIND")
            ok(t, sys.umount(w, B .. "/dst"), "umount2 without MNT_FORCE")
            ok(t, bind(w, B .. "/src", B .. "/dst", MS.REC), "MS_BIND|MS_REC")
            ok(t, sys.umount(w, B .. "/dst", MNT_DETACH), "umount2(MNT_DETACH)")
            ok(t, new_fs(w, "tmpfs", B .. "/fs"), "a new tmpfs")
            ok(t, sys.umount(w, B .. "/fs"), "and its unmount")
        end)
        as(t, { principal() }, function(w)
            ok(t, unshare(w), "unshare")
            ok(t, bind(w, B .. "/src", B .. "/src"), "the new root becomes a mount point")
            ok(t, chdir(w, B .. "/src"), "chdir")
            ok(t, pivot_dot(w), "pivot_root")
        end)

        -- The no rows. The worker starts privileged so it can hold the
        -- two detached-tree fds only a privileged caller can make, then
        -- installs a privilege-free token of the same user and session
        -- and is asked for everything again. Its table's descriptor
        -- names TEST_USER, so whatever it refuses, it refuses by
        -- operation rather than by identity.
        local w = vm:spawn_worker()
        local ran, err = pcall(function()
            local mv, session = token.mint(w, principal(MANAGE_VOLUME | ASSIGN))
            assert(mv, "mint: " .. sys.errname(session or 0))
            local plain = assert(token.create(w, principal(0, { auth_id = session })))
            become(w, mv)
            ok(t, unshare(w), "unshare")
            ok(t, bind(w, B .. "/src", B .. "/dst"), "a bind for the per-mount cases to aim at")
            local tree = open_tree(w, B .. "/src")
            t:assert(tree.ret >= 0, "privileged open_tree(OPEN_TREE_CLONE): " .. sys.errname(tree.errno))
            local fsfd = fsopen(w, "tmpfs")
            t:assert(fsfd.ret >= 0, "privileged fsopen: " .. sys.errname(fsfd.errno))
            ok(t, w:syscall(NR.fsconfig, fsfd.ret, kacs.FSCONFIG_CMD_CREATE, 0, 0, 0),
                "privileged fsconfig(FSCONFIG_CMD_CREATE)")
            become(w, plain)

            local r, recs = gate_of(t, w, function()
                return bind(w, B .. "/src", B .. "/dst2") end)
            ok(t, r, "a bind, now unprivileged")
            t:assert_eq(#with_reason(recs, "gate-sd-decision"), 1,
                "the descriptor is what admits the now-unprivileged caller: " .. summary(recs))

            local attr = string.pack("<I8I8I8I8", MOUNT_ATTR_RDONLY, 0, 0, 0)
            local cases = {
                { "MS_REMOUNT", function() return sys.mount(w, { target = B .. "/dst",
                    flags = MS.REMOUNT | MS.RDONLY }) end },
                { "MS_REMOUNT|MS_BIND", function() return sys.mount(w, { target = B .. "/dst",
                    flags = MS.REMOUNT | MS.BIND | MS.RDONLY }) end },
                { "MS_MOVE", function() return sys.mount(w, { source = B .. "/dst2",
                    target = B .. "/fs", flags = MS.MOVE }) end },
                { "MS_SHARED", function() return sys.mount(w, { target = B .. "/dst", flags = MS.SHARED }) end },
                { "MS_PRIVATE", function() return sys.mount(w, { target = B .. "/dst", flags = MS.PRIVATE }) end },
                { "MS_SLAVE", function() return sys.mount(w, { target = B .. "/dst", flags = MS.SLAVE }) end },
                { "MS_UNBINDABLE", function() return sys.mount(w, { target = B .. "/dst", flags = MS.UNBINDABLE }) end },
                { "open_tree(OPEN_TREE_CLONE)", function() return open_tree(w, B .. "/src") end },
                { "fsmount", function() return w:syscall(NR.fsmount, fsfd.ret, 0, 0) end },
                { "fsopen", function() return fsopen(w, "tmpfs") end },
                { "move_mount", function() return w:syscall(NR.move_mount, {
                    args = { tree.ret, 0, sys.AT_FDCWD, 0, MOVE_MOUNT_F_EMPTY_PATH },
                    bufs = { sys.cstr(""), sys.cstr(B .. "/fs") }, ptrs = { 1, 3 } }) end },
                { "mount_setattr", function() return w:syscall(NR.mount_setattr, {
                    args = { sys.AT_FDCWD, 0, 0, 0, #attr },
                    bufs = { sys.cstr(B .. "/dst"), attr }, ptrs = { 1, 3 } }) end },
            }
            for _, c in ipairs(cases) do
                local r, recs = gate_of(t, w, c[2])
                refused(t, r, c[1])
                t:assert(#with_reason(recs, "gate-op-not-admitted") >= 1,
                    c[1] .. " is turned away as an operation the descriptor cannot admit: " ..
                    summary(recs))
                t:assert_eq(#with_reason(recs, "gate-sd-decision"), 0,
                    c[1] .. " never reaches the descriptor")
            end

            -- MNT_FORCE is the one "no" that is not a gate operation of
            -- its own: the gate sees an unmount and the descriptor admits
            -- it, and then the CAP_SYS_ADMIN test MNT_FORCE keeps on the
            -- superblock's user namespace (SeTcbPrivilege, through the
            -- switchboard) refuses it — so it still needs the privilege
            -- whatever the descriptor grants.
            r, recs = gate_of(t, w, function() return sys.umount(w, B .. "/dst", MNT_FORCE) end)
            refused(t, r, "umount2(MNT_FORCE)")
            local d = with_reason(recs, "gate-sd-decision")[1]
            t:assert(d and d.verdict == "allow" and d.op == 2,
                "the descriptor admitted the unmount, and MNT_FORCE's own test refused it: " ..
                summary(recs))
        end)
        w:kill(); w:join()
        if not ran then error(err, 0) end
    end)

test("the filesystem types a descriptor can admit are exactly tmpfs, proc and stratafs",
    { spec = "PKM *mntns.fs-type-allowlist" }, function(t)
        as(t, { principal() }, function(w)
            ok(t, unshare(w), "unshare")
            local admitted = {
                { "tmpfs", nil },
                { "proc", nil },
                { "stratafs", stratafs.options({ { B .. "/lo", "ro" } }) },
            }
            for _, a in ipairs(admitted) do
                local r, recs = gate_of(t, w, function() return new_fs(w, a[1], B .. "/fs", a[2]) end)
                ok(t, r, "a new " .. a[1])
                t:assert(#with_reason(recs, "gate-sd-decision") >= 1,
                    a[1] .. " is admitted by the descriptor: " .. summary(recs))
                ok(t, sys.umount(w, B .. "/fs"), a[1] .. " comes off again")
            end
            -- Image parsers, kernel views outside the allowlist, and a
            -- type that does not exist at all: the gate refuses all of
            -- them before the type is looked up, so the last is EPERM
            -- and not ENODEV, and an ext4 with no device is EPERM and not
            -- ENOTBLK.
            for _, fstype in ipairs({ "ext4", "squashfs", "iso9660", "ntfs3", "ramfs",
                                      "sysfs", "nosuchfs" }) do
                local r, recs = gate_of(t, w, function() return new_fs(w, fstype, B .. "/fs") end)
                refused(t, r, "a new " .. fstype)
                local d = with_reason(recs, "gate-fs-not-admitted")[1]
                t:assert(d, fstype .. " is refused as a type the descriptor cannot admit: " ..
                    summary(recs))
                t:assert_eq(#with_reason(recs, "gate-sd-decision"), 0,
                    fstype .. " never reaches the descriptor")
            end
        end)
    end)

test("an unprivileged stratafs stack is read-only or absent-tolerant; a create stratum is refused by stratafs",
    { spec = "PKM *mntns.stratafs-read-only-only" }, function(t)
        local with_create = stratafs.options({ { B .. "/up", "create" }, { B .. "/lo", "ro" } })
        -- The same option string is a good stack: the agent, in the
        -- initial namespace with SeTcbPrivilege, mounts it.
        ok(t, new_fs(vm, "stratafs", B .. "/agentmnt", with_create), "the agent mounts the create stack")
        sys.umount(vm, B .. "/agentmnt")

        as(t, { principal() }, function(w)
            ok(t, unshare(w), "unshare")
            local r, recs = gate_of(t, w, function()
                return new_fs(w, "stratafs", B .. "/fs", with_create) end)
            refused(t, r, "an unprivileged stack with a create stratum")
            local decisions = with_reason(recs, "gate-sd-decision")
            t:assert(#decisions >= 1, "the gate was passed: " .. summary(recs))
            for _, d in ipairs(decisions) do
                t:assert_eq(d.verdict, "allow",
                    "the descriptor admitted the type; stratafs's own admission refused: " ..
                    summary(recs))
            end

            ok(t, new_fs(w, "stratafs", B .. "/fs",
                stratafs.options({ { B .. "/lo", "ro" } })), "a read-only stack")
            local fd = assert(sys.open(w, B .. "/fs/lower-file", sys.O.RDONLY))
            t:assert_eq(sys.read(w, fd, 64), "from the lower stratum", "reads through")
            sys.close(w, fd)
            ok(t, sys.umount(w, B .. "/fs"), "unmount")

            ok(t, new_fs(w, "stratafs", B .. "/fs", stratafs.options({
                { B .. "/absent", "am" }, { B .. "/lo", "ro" } })),
                "an absent-tolerant stack over a stratum that does not exist")
            ok(t, sys.umount(w, B .. "/fs"), "unmount")
        end)
    end)

-- The tmpfs stamp -------------------------------------------------------------------

--- The policy of a mount inside worker `w`'s table, read by the agent
--- through /proc/<pid>/root (kacs_get_mount_policy needs the privilege).
local function policy_in(t, w, path)
    local fd, e = sys.open(vm, "/proc/" .. pid_of(w) .. "/root" .. path,
        sys.O.PATH | sys.O.DIRECTORY)
    t:assert(fd, "the agent opens the worker's mount: " .. sys.errname(e or 0))
    local got = kacs.get_mount_policy_ex(vm, fd)
    sys.close(vm, fd)
    return got
end

test("a tmpfs an unprivileged token brings into being is stamped synthesize-ephemeral for its creator",
    { spec = "PKM *mntns.unprivileged-tmpfs-stamped" }, function(t)
        local pid
        local records = traced(t, { "kacs_mntns" }, function()
            as(t, { principal() }, function(w)
                pid = pid_of(w)
                ok(t, unshare(w), "unshare")
                ok(t, new_fs(w, "tmpfs", B .. "/fs"), "an unprivileged tmpfs")
                local got = assert(policy_in(t, w, B .. "/fs"))
                t:assert_eq(got.policy, MP.SYNTHESIZE_EPHEMERAL, "synthesize-ephemeral")
                t:assert_eq(got.generation, 1, "at generation 1")
                t:assert(got.template, "with a template")
                local tpl = token.parse_sd(got.template)
                t:assert_eq(tpl.owner, token.SID.TEST_USER, "owned by the mounter's user")
                t:assert(tpl.group, "with a group from the token")
                t:assert_eq(tpl.dacl and #tpl.dacl, 1, "and one ACE")
                local ace = tpl.dacl and tpl.dacl[1]
                t:assert_eq(ace and ace.type, kacs.ACE_ALLOWED, "an allow")
                t:assert_eq(ace and ace.sid, token.SID.TEST_USER, "for the mounter's user")
                t:assert_eq(ace and ace.mask, GENERIC_ALL, "of GENERIC_ALL")

                -- So the one identity that can reach the table can use it.
                local fd, e = sys.open(w, B .. "/fs/mine", sys.O.WRONLY | sys.O.CREAT,
                    tonumber("644", 8))
                t:assert(fd, "the mounter creates a file on it: " .. sys.errname(e or 0))
                if fd then
                    t:assert_eq(sys.write(w, fd, "kept").ret, 4, "and writes it")
                    sys.close(w, fd)
                end
                fd = assert(sys.open(w, B .. "/fs/mine", sys.O.RDONLY))
                t:assert_eq(sys.read(w, fd, 16), "kept", "and reads it back")
                sys.close(w, fd)
            end)
        end)
        t:assert_eq(#with_reason(select_(records, pid), "sb-stamp"), 1,
            "the stamp is recorded: " .. summary(select_(records, pid)))
    end)

test("a privileged mounter's tmpfs keeps the deny-missing default",
    { spec = "PKM *mntns.privileged-tmpfs-untouched" }, function(t)
        local pid
        local records = traced(t, { "kacs_mntns" }, function()
            as(t, { principal(MANAGE_VOLUME) }, function(w)
                pid = pid_of(w)
                ok(t, unshare(w), "unshare")
                ok(t, new_fs(w, "tmpfs", B .. "/fs"), "a privileged tmpfs")
                local got = assert(policy_in(t, w, B .. "/fs"))
                t:assert_eq(got.policy, MP.DENY_MISSING, "deny-missing")
                t:assert_eq(got.generation, 0, "at generation 0: nobody has spoken for it")
                t:assert_eq(got.template_len, 0, "and no template")
                local fd, e = sys.open(w, B .. "/fs/mine", sys.O.WRONLY | sys.O.CREAT,
                    tonumber("644", 8))
                t:assert(not fd, "so not even its mounter can create on it until it is seeded")
                t:assert_eq(e, sys.E.ACCES, "EACCES: " .. sys.errname(e or 0))
                if fd then sys.close(w, fd) end
            end)
        end)
        t:assert_eq(#with_reason(select_(records, pid), "sb-stamp"), 0,
            "and no stamp is recorded: " .. summary(select_(records, pid)))
    end)

-- Tracing -----------------------------------------------------------------------------

test("kacs:kacs_mntns records minting, each rung of the gate, and the tmpfs stamp",
    { spec = "PKM *mntns.trace-event" }, function(t)
        local DOCUMENTED = {
            ["sd-alloc"] = true, ["sd-alloc-fail"] = true, ["gate-privilege"] = true,
            ["gate-no-sd"] = true, ["gate-op-not-admitted"] = true,
            ["gate-sd-decision"] = true, ["gate-pip-context"] = true,
            ["gate-fs-not-admitted"] = true, ["sb-stamp"] = true, ["sb-stamp-fail"] = true,
        }
        local records = traced(t, { "kacs_mntns" }, function()
            as(t, { principal() }, function(w)
                refused(t, bind(w, B .. "/src", B .. "/dst"), "a bind in the initial table")
                ok(t, unshare(w), "unshare")
                ok(t, bind(w, B .. "/src", B .. "/dst"), "a bind")
                refused(t, sys.mount(w, { target = B .. "/dst", flags = MS.PRIVATE }),
                    "a propagation change")
                refused(t, new_fs(w, "ext4", B .. "/fs"), "an ext4")
                ok(t, new_fs(w, "tmpfs", B .. "/fs"), "a tmpfs")
            end)
            as(t, { principal(MANAGE_VOLUME) }, function(w)
                ok(t, unshare(w), "a privileged unshare")
                ok(t, bind(w, B .. "/src", B .. "/dst"), "a privileged bind")
            end)
        end)
        local mntns = select_(records, nil)
        local seen = {}
        for _, r in ipairs(mntns) do
            t:assert(DOCUMENTED[r.reason or "?"], "a documented reason: " .. r.line)
            t:assert(r.verdict == "allow" or r.verdict == "deny", "a verdict: " .. r.line)
            t:assert(r.op ~= nil, "an operation code: " .. r.line)
            t:assert(r.desired ~= nil, "the right asked: " .. r.line)
            seen[r.reason] = seen[r.reason] or r
        end
        for _, want in ipairs({ { "sd-alloc", "allow" }, { "gate-no-sd", "deny" },
                                { "gate-sd-decision", "allow" },
                                { "gate-op-not-admitted", "deny" },
                                { "gate-fs-not-admitted", "deny" }, { "sb-stamp", "allow" },
                                { "gate-privilege", "allow" } }) do
            local r = seen[want[1]]
            t:assert(r, want[1] .. " was recorded: " .. summary(mntns))
            t:assert_eq(r and r.verdict, want[2], want[1] .. " is an " .. want[2])
        end
        -- The right asked of the descriptor appears only where a rung
        -- reached it.
        t:assert_eq(seen["gate-sd-decision"] and seen["gate-sd-decision"].desired, "0x1",
            "the descriptor rung records KACS_MNTNS_MOUNT")
        t:assert_eq(seen["gate-no-sd"] and seen["gate-no-sd"].desired, "0x0",
            "a rung that did not reach a descriptor records no right")
        t:assert_eq(seen["gate-privilege"] and seen["gate-privilege"].desired, "0x0",
            "nor does the privilege rung")
    end)
