-- PKM §3.13 — a mount namespace as a KACS object: who may create one,
-- which namespaces carry a descriptor, what the minted descriptor names,
-- and the rights it is written in. The gate that reads the descriptor is
-- mntns-gate.test.lua; the private table seen from inside is
-- mntns-private-root.test.lua.
--
-- Nothing exposes a namespace's descriptor to kacs_get_sd (§3.13 says so
-- itself), so the descriptor is read by what it admits: a bind mount in
-- the namespace is AccessCheck for KACS_MNTNS_MOUNT against it. Getting
-- a *second* identity into a namespace somebody else created takes one
-- worker and two tokens: the worker mints both while it is still SYSTEM,
-- installs the creator, unshares, and then impersonates the other — the
-- gate asks the caller's *effective* token, and the namespace belongs to
-- the process, so it stays put while the identity asking changes.
-- (Installing another user's primary would need SeTcbPrivilege, which
-- would make the creator privileged.) The creator carries
-- SeImpersonatePrivilege so the impersonation is not capped to
-- Identification (§3.5.2); the mount gate asks only
-- SeManageVolumePrivilege and SeTcbPrivilege, so an unrelated privilege
-- does not move it.
--
-- Every namespace change happens on a worker: the agent is PID 1 and
-- its own table is the initial one.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local facs = require("helpers.facs")
local hooks = require("helpers.hooks")

local vm = provium:vm("vmntnsobj", "kernel-only"):boot()

-- A minted principal holds no SeChangeNotifyPrivilege, so the walk to
-- the workspace needs `/` itself to grant traverse (the imp-levels
-- precedent). Nothing here hands a principal a privilege to get there.
kacs.set_sd(vm, "/", kacs.grant(kacs.ALL_RIGHTS))
local B = facs.workspace(vm, "mntns-obj")
vm:mkdir(B .. "/src", { parents = true })
vm:write_file(B .. "/src/marker", "src")
vm:mkdir(B .. "/dst", { parents = true })

local P = token.PRIV
local NR = { unshare = 272, clone = 56, open_tree = 428, fsopen = 430,
             fsconfig = 431, fsmount = 432 }
local CLONE = {
    NEWNS = 0x00020000, NEWUTS = 0x04000000, NEWIPC = 0x08000000,
    NEWPID = 0x20000000, NEWNET = 0x40000000, NEWCGROUP = 0x02000000,
    NEWTIME = 0x00000080, NEWUSER = 0x10000000,
}
local MS = { BIND = 4096, REMOUNT = 32, PRIVATE = 1 << 18, RDONLY = 1 }
local MNT_DETACH = 2
local OPEN_TREE_CLONE = 1
local IMPERSONATE = token.bit(P.IMPERSONATE)
local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT
    | token.GROUP.ENABLED

-- Principals ------------------------------------------------------------------

--- A build_spec table holding exactly `privs`, enabled, plus `over`.
--- A fresh table every call: token.mint writes the session into it.
local function principal(privs, over)
    local s = { privs_present = privs or 0, privs_enabled = privs or 0 }
    for k, v in pairs(over or {}) do s[k] = v end
    return s
end

--- Install the token `fd` as the worker's primary, and drop the fd.
local function become(w, fd)
    local r = token.install(w, fd)
    assert(r.ret == 0, "KACS_IOC_INSTALL: " .. sys.errname(r.errno))
    sys.close(w, fd)
end

--- `spec` as an Impersonation-level impersonation token.
local function impersonation(spec)
    spec.token_type = token.TYPE.IMPERSONATION
    spec.impersonation_level = token.LEVEL.IMPERSONATION
    return spec
end

--- A worker that mints every spec in `specs` while it is still SYSTEM,
--- installs the first, and hands `fn` the fds of the rest.
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

-- Operations ------------------------------------------------------------------

local function unshare(w, flags) return w:syscall(NR.unshare, flags or CLONE.NEWNS) end
local function bind(w, from, to)
    return sys.mount(w, { source = from, target = to, flags = MS.BIND })
end
local function ns_of(w) return sys.readlink(w, "/proc/self/ns/mnt") end

local function ok(t, r, what)
    t:assert_eq(r.ret, 0, what .. ": " .. sys.errname(r.errno or 0))
end
local function refused(t, r, errno, what)
    t:assert_eq(r.ret, -1, what .. " is refused")
    t:assert_eq(r.errno, errno, what .. ": " .. sys.errname(r.errno or 0))
end

--- Bind src onto dst and take it straight back off, asserting both.
local function bind_and_drop(t, w, what)
    ok(t, bind(w, B .. "/src", B .. "/dst"), what)
    ok(t, sys.umount(w, B .. "/dst", MNT_DETACH), what .. ", and the bind comes off")
end

-- The helper ------------------------------------------------------------------

--- tests/tools/pt-mntns, staged into the workspace and executable by
--- everyone. A real program run under a minted token, for the clone(2)
--- cases a worker's own syscall channel cannot fork through.
local HELPER = (function()
    local pipe = assert(io.popen("sh tests/tools/build.sh pt-mntns", "r"))
    local path = pipe:read("*l")
    assert(pipe:close() and path and path ~= "", "could not build pt-mntns")
    local f = assert(io.open(path, "rb"))
    local bytes = f:read("*a")
    f:close()
    local at = B .. "/pt-mntns"
    vm:write_file(at, bytes)
    sys.chmod(vm, at, tonumber("755", 8))
    kacs.set_sd(vm, at, kacs.grant(kacs.ALL_RIGHTS))
    return at
end)()

local function helper(w, ...)
    return w:run(HELPER, { args = { ... }, timeout = "20s" })
end

-- Tracing ---------------------------------------------------------------------

--- Run `fn` with kacs:kacs_mntns enabled; return its records as
--- { pid, reason, verdict, op, desired, ret }. A worker issues every
--- syscall on one thread, so its records carry its pid.
local function traced(t, fn)
    local started, err = hooks.trace_start(vm, "kacs/kacs_mntns")
    t:assert(started, "tracing starts: " .. tostring(err))
    local ran, raised = pcall(fn)
    local lines = hooks.trace_stop(vm, "kacs/kacs_mntns") or {}
    if not ran then error(raised, 0) end
    local out = {}
    for _, l in ipairs(lines) do
        local pid = l:match("^%s*.-%-(%d+)%s+%[")
        local body = l:match("kacs_mntns:%s+(.*)$")
        if body then
            out[#out + 1] = {
                pid = tonumber(pid),
                reason = body:match("reason=(%S+)"),
                verdict = body:match("verdict=(%S+)"),
                op = tonumber(body:match("op=(%d+)")),
                desired = body:match("desired=(%S+)"),
                ret = tonumber(body:match("ret=(%-?%d+)")),
            }
        end
    end
    return out
end

local function of_pid(records, pid)
    local out = {}
    for _, r in ipairs(records) do if r.pid == pid then out[#out + 1] = r end end
    return out
end

local function reasons(records)
    local out = {}
    for _, r in ipairs(records) do out[#out + 1] = r.reason .. "/" .. r.verdict end
    return table.concat(out, " ")
end

local function pid_of(w) return w:syscall(sys.NR.getpid).ret end

-- The object -------------------------------------------------------------------

test("changing a mount table is an access check against the table's descriptor, not a capability",
    { spec = "PKM *mntns.object-model" }, function(t)
        as(t, { principal() }, function(w)
            refused(t, bind(w, B .. "/src", B .. "/dst"), sys.E.PERM,
                "an ordinary principal's bind in the initial table")
            ok(t, unshare(w), "it creates a table of its own")
            bind_and_drop(t, w, "and the same bind there is admitted")
        end)

        -- The Linux route — root in a fresh user namespace that owns the
        -- mount namespace — confers nothing. Upstream, user-namespace
        -- root may change propagation, remount and mount ramfs in a
        -- table its namespace owns; here each of those still needs the
        -- privilege, and only what the descriptor admits is admitted.
        as(t, { principal() }, function(w)
            ok(t, unshare(w, CLONE.NEWUSER | CLONE.NEWNS),
                "a user namespace is created alongside the mount namespace")
            ok(t, bind(w, B .. "/src", B .. "/dst"),
                "the descriptor admits a bind")
            refused(t, sys.mount(w, { target = B .. "/dst", flags = MS.PRIVATE }),
                sys.E.PERM, "a propagation change by user-namespace root")
            refused(t, sys.mount(w, { target = B .. "/dst",
                flags = MS.REMOUNT | MS.BIND | MS.RDONLY }),
                sys.E.PERM, "a remount by user-namespace root")
            refused(t, sys.mount(w, { source = "none", target = B .. "/dst",
                fstype = "ramfs" }), sys.E.PERM, "a ramfs mount by user-namespace root")
        end)
    end)

-- Creating one -----------------------------------------------------------------

test("unshare and clone with CLONE_NEWNS alone need no privilege",
    { spec = "PKM *mntns.create-unprivileged" }, function(t)
        as(t, { principal() }, function(w)
            local before = assert(ns_of(w))
            ok(t, unshare(w), "unshare(CLONE_NEWNS) by a principal holding no privilege")
            local after = assert(ns_of(w))
            t:assert(after ~= before,
                "and the caller is in a new mount namespace: " .. before .. " -> " .. after)

            local run = helper(w, "clone", string.format("%x", CLONE.NEWNS))
            t:assert_eq(run.exit_code, 0, "pt-mntns clone runs: " .. tostring(run.stdout))
            local parent = run.stdout:match("parent ns=(%S+)")
            local child = run.stdout:match("child ns=(%S+)")
            t:assert(run.stdout:find("clone ok status=0", 1, true),
                "clone(CLONE_NEWNS) succeeds unprivileged: " .. run.stdout)
            t:assert(child and parent and child ~= parent,
                "and the child starts in a mount namespace of its own: " .. run.stdout)
        end)
    end)

--- Every namespace type the nsproxy gate covers, other than the mount one.
local OTHERS = {
    { "CLONE_NEWUTS", CLONE.NEWUTS }, { "CLONE_NEWIPC", CLONE.NEWIPC },
    { "CLONE_NEWPID", CLONE.NEWPID }, { "CLONE_NEWNET", CLONE.NEWNET },
    { "CLONE_NEWCGROUP", CLONE.NEWCGROUP }, { "CLONE_NEWTIME", CLONE.NEWTIME },
}

test("every other namespace type, alone or with the mount namespace, keeps the SeTcbPrivilege gate",
    { spec = "PKM *mntns.other-types-stay-gated" }, function(t)
        as(t, { principal() }, function(w)
            local home = assert(ns_of(w))
            for _, o in ipairs(OTHERS) do
                refused(t, unshare(w, o[2]), sys.E.PERM, "unshare(" .. o[1] .. ")")
                refused(t, unshare(w, CLONE.NEWNS | o[2]), sys.E.PERM,
                    "unshare(CLONE_NEWNS|" .. o[1] .. ")")
            end
            t:assert_eq(ns_of(w), home,
                "a refused combination did not half-create the mount namespace")

            local run = helper(w, "clone", string.format("%x", CLONE.NEWNS | CLONE.NEWUTS))
            t:assert(run.stdout:find("clone fail errno=1", 1, true),
                "clone(CLONE_NEWNS|CLONE_NEWUTS) is refused with EPERM: " .. run.stdout)

            -- A user namespace is not on the gate's list: upstream lets
            -- anyone make one, and so does Peios.
            ok(t, unshare(w, CLONE.NEWUSER | CLONE.NEWNS),
                "a user namespace may still come alongside")
        end)
        -- The gate is the switchboard's: SeTcbPrivilege answers it.
        as(t, { principal(token.bit(P.TCB)) }, function(w)
            ok(t, unshare(w, CLONE.NEWUTS), "with SeTcbPrivilege, unshare(CLONE_NEWUTS)")
            ok(t, unshare(w, CLONE.NEWNS | CLONE.NEWIPC),
                "and unshare(CLONE_NEWNS|CLONE_NEWIPC)")
        end)
    end)

test("the nsproxy gate's one carve-out is a mount namespace requested alone",
    { spec = "PKM *cred.dac.mount-namespace-ungated" }, function(t)
        as(t, { principal() }, function(w)
            ok(t, unshare(w, CLONE.NEWNS), "CLONE_NEWNS alone passes without a capability")
            refused(t, unshare(w, CLONE.NEWNS | CLONE.NEWNET), sys.E.PERM,
                "CLONE_NEWNS|CLONE_NEWNET")
            refused(t, unshare(w, CLONE.NEWNS | CLONE.NEWUTS | CLONE.NEWIPC), sys.E.PERM,
                "CLONE_NEWNS|CLONE_NEWUTS|CLONE_NEWIPC")
            refused(t, unshare(w, CLONE.NEWPID), sys.E.PERM, "CLONE_NEWPID alone")
        end)
        as(t, { principal(token.bit(P.TCB)) }, function(w)
            ok(t, unshare(w, CLONE.NEWNS | CLONE.NEWNET),
                "the TCB passes the combination")
        end)
    end)

-- Which namespaces carry a descriptor ------------------------------------------

test("the initial namespace and anonymous detached trees carry no descriptor",
    { spec = "PKM *mntns.initial-has-no-descriptor" }, function(t)
        local wpid, upid
        local records = traced(t, function()
            -- The initial table: the gate finds no descriptor to ask.
            as(t, { principal() }, function(w)
                wpid = pid_of(w)
                refused(t, bind(w, B .. "/src", B .. "/dst"), sys.E.PERM,
                    "a principal's bind in the initial table")
            end)
            -- Anonymous namespaces, made by the agent (which holds the
            -- privilege): a cloned tree and a fresh fsmount.
            local tree = vm:syscall(NR.open_tree, {
                args = { sys.AT_FDCWD, 0, OPEN_TREE_CLONE },
                bufs = { sys.cstr(B .. "/src") }, ptrs = { 1 },
            })
            t:assert(tree.ret >= 0, "open_tree(OPEN_TREE_CLONE): " .. sys.errname(tree.errno))
            local fs = vm:syscall(NR.fsopen, { args = { 0, 0 },
                bufs = { sys.cstr("tmpfs") }, ptrs = { 0 } })
            t:assert(fs.ret >= 0, "fsopen(tmpfs): " .. sys.errname(fs.errno))
            ok(t, vm:syscall(NR.fsconfig, fs.ret, kacs.FSCONFIG_CMD_CREATE, 0, 0, 0),
                "fsconfig(FSCONFIG_CMD_CREATE)")
            local mnt = vm:syscall(NR.fsmount, fs.ret, 0, 0)
            t:assert(mnt.ret >= 0, "fsmount: " .. sys.errname(mnt.errno))
            for _, fd in ipairs({ tree.ret, fs.ret, mnt.ret }) do
                if fd >= 0 then sys.close(vm, fd) end
            end
            -- And for contrast, one namespace that does get one.
            as(t, { principal() }, function(w)
                upid = pid_of(w)
                ok(t, unshare(w), "a principal's unshare")
            end)
        end)

        local mine = of_pid(records, wpid)
        t:assert(#mine >= 1, "the refused bind left a gate record")
        t:assert_eq(mine[1].reason, "gate-no-sd",
            "the gate found no descriptor on the initial table: " .. reasons(mine))
        t:assert_eq(mine[1].verdict, "deny", "and denied")

        local minted = {}
        for _, r in ipairs(records) do
            if r.reason == "sd-alloc" then minted[#minted + 1] = r end
        end
        t:assert_eq(#minted, 1,
            "exactly one descriptor was minted — the unshare's, none for " ..
            "open_tree or fsmount: " .. reasons(records))
        t:assert_eq(minted[1] and minted[1].pid, upid, "and it was the unsharing worker's")
    end)

-- The minted descriptor ---------------------------------------------------------

--- The identities that must find a creator's namespace closed: another
--- user; another user in BUILTIN\Administrators; and SYSTEM itself with
--- no privileges. The SysV and socket defaults name the last two.
local INTRUDERS = {
    { "another user", function() return principal(0, { user_sid = token.SID.TEST_USER_2 }) end },
    { "a member of BUILTIN\\Administrators", function()
        return principal(0, { user_sid = token.SID.TEST_USER_2, groups = {
            { sid = token.SID.EVERYONE, attributes = ENABLED },
            { sid = token.SID.AUTHENTICATED_USERS, attributes = ENABLED },
            { sid = token.SID.ADMINISTRATORS, attributes = ENABLED },
        } })
    end },
    { "SYSTEM without its privileges", function()
        return principal(0, { user_sid = token.SID.LOCAL_SYSTEM })
    end },
}

test("a minted descriptor names its creator's user and nobody else",
    { spec = "PKM *mntns.default-descriptor" }, function(t)
        -- The descriptor's DACL is read here by whom it admits. Its
        -- bytes — owner and group from the token, one GENERIC_ALL ACE —
        -- are read in mntns-gate.test.lua's tmpfs-stamp case: the stamp
        -- template is built by the same kacs_rust_create_default_mnt_ns_sd
        -- the namespace descriptor is, and unlike it can be read back.
        for _, who in ipairs(INTRUDERS) do
            local pid
            local records = traced(t, function()
                as(t, { principal(IMPERSONATE), impersonation(who[2]()) }, function(w, intruder)
                    pid = pid_of(w)
                    ok(t, unshare(w), "the creator makes a table")
                    bind_and_drop(t, w, "the creator's bind is admitted")
                    ok(t, token.impersonate(w, intruder),
                        "the creator's thread acts as " .. who[1])
                    refused(t, bind(w, B .. "/src", B .. "/dst"), sys.E.PERM,
                        who[1] .. "'s bind in the creator's table")
                end)
            end)
            -- The refusal is the descriptor's, not some earlier rung's.
            local last = of_pid(records, pid)
            last = last[#last]
            t:assert(last and last.reason == "gate-sd-decision" and last.verdict == "deny",
                who[1] .. " was refused by the descriptor: " .. reasons(of_pid(records, pid)))
        end
        -- It is the user SID the ACE names, not the token: a second,
        -- unrelated token for the same user, in another logon session,
        -- is let in.
        as(t, { principal(IMPERSONATE), impersonation(principal()) }, function(w, same_user)
            ok(t, unshare(w), "the creator makes a table")
            ok(t, token.impersonate(w, same_user), "the creator acts as another TEST_USER token")
            bind_and_drop(t, w, "another token of the creator's user is admitted")
        end)
    end)

test("a namespace's descriptor is minted from the creating task's effective token",
    { spec = "PKM *mntns.descriptor-lifetime" }, function(t)
        -- The creator's primary is TEST_USER; it creates the table while
        -- impersonating TEST_USER_2. SeImpersonatePrivilege keeps the
        -- impersonation at Impersonation level rather than capped to
        -- Identification (§3.5.2).
        local client = impersonation(principal(0, { user_sid = token.SID.TEST_USER_2 }))
        as(t, { principal(IMPERSONATE), client }, function(w, imp)
            ok(t, token.impersonate(w, imp), "the creator impersonates TEST_USER_2")
            ok(t, unshare(w), "and creates a table while impersonating")
            bind_and_drop(t, w, "TEST_USER_2 is admitted")
            ok(t, token.revert(w), "the creator reverts to its own primary")
            refused(t, bind(w, B .. "/src", B .. "/dst"), sys.E.PERM,
                "the primary's user — the process's own — in that table")
            ok(t, token.impersonate(w, imp), "impersonating again")
            bind_and_drop(t, w, "TEST_USER_2 is admitted again")
        end)
    end)

test("the generic rights map onto the mount-namespace rights as the table says",
    { spec = "PKM *mntns.generic-mapping",
      covered_by = "cargo:kacs-core access_mask::mount_namespace_mapping_matches_the_header",
      skip = "nothing exposes a namespace's descriptor to kacs_get_sd or " ..
             "kacs_set_sd (§3.13), so no guest can write an ACE in a generic " ..
             "right and watch it map; the kernel's check passes " ..
             "MNTNS_GENERIC_MAPPING (token_runtime.rs, mnt_ns_sd_access_check_errno); " ..
             "runs under kacs-core's mount_namespace_mapping_matches_the_header" },
    function(t) end)

-- The rights ---------------------------------------------------------------------

test("changing the table asks the descriptor for KACS_MNTNS_MOUNT, 0x1",
    { spec = "PKM *kacs-abi.mntns-access-rights" }, function(t)
        -- KACS_MNTNS_MOUNT is the one right a guest can watch being
        -- asked for: the gate's descriptor rung records the mask it
        -- requested. KACS_MNTNS_ENTER (0x2) and KACS_MNTNS_ALL_ACCESS
        -- (917507) have no consumer yet — setns still needs the
        -- privilege and no syscall reads or writes a namespace's
        -- descriptor — so their values are checked only by kacs-core's
        -- mount_namespace_mapping_matches_the_header.
        local pid
        local records = traced(t, function()
            as(t, { principal() }, function(w)
                pid = pid_of(w)
                ok(t, unshare(w), "unshare")
                bind_and_drop(t, w, "a bind in the principal's own table")
            end)
        end)
        local asked
        for _, r in ipairs(of_pid(records, pid)) do
            if r.reason == "gate-sd-decision" then asked = r; break end
        end
        t:assert(asked, "the bind reached the descriptor rung: " .. reasons(of_pid(records, pid)))
        t:assert_eq(asked and asked.desired, "0x1", "asking for 0x1, KACS_MNTNS_MOUNT")
        t:assert_eq(asked and asked.verdict, "allow", "which the creator holds")
    end)
