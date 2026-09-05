-- PKM §3.A — the `kacs:` tracepoint diagnostic codes, observed from
-- tracefs while the machinery they describe is driven.
--
-- Each table in the appendix is a vocabulary: a tool reading the kacs:
-- system decodes a record's reason against §3.A without knowing the
-- kernel build. So each case here drives one path, expects the symbol
-- the appendix names for it, and then checks that *every* symbol the
-- run produced is one the appendix documents — which is the property
-- the published table actually asserts.
--
-- The values render through their symbolic names (the sole exception is
-- kacs_ipc, whose reason prints as a number). tracefs mounts with a
-- synthesize-ephemeral policy exactly as the KMES tracepoint suite does
-- (helpers/hooks).

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local access = require("helpers.access")
local facs = require("helpers.facs")
local hooks = require("helpers.hooks")
local psb = require("helpers.psb")
local unix = require("helpers.unixsock")

local vm = provium:vm("v", "kernel-only"):boot()

local B = facs.workspace(vm, "abitrace")
local R = kacs.RIGHT

--- Enable one kacs: event, run `fn`, and return the buffer's lines.
local function traced(t, event, fn)
    local ok, err = hooks.trace_start(vm, event)
    t:assert(ok, "tracing starts on " .. event .. ": " .. tostring(err))
    local ran, raised = pcall(fn)
    local lines = hooks.trace_stop(vm, event)
    if not ran then error(raised, 0) end
    t:assert(lines, "the buffer reads back")
    return lines
end

--- Every value of one field across the traced lines, in order.
local function values(lines, field)
    local out = {}
    for _, l in ipairs(lines) do
        local v = l:match("[ :]" .. field .. "=([%w%-_]+)")
        if v then out[#out + 1] = v end
    end
    return out
end

local function has(list, want)
    for _, v in ipairs(list) do if v == want then return true end end
    return false
end

--- A set from a list of symbol names.
local function vocab(...)
    local set = {}
    for _, name in ipairs({ ... }) do set[name] = true end
    return set
end

--- The property the published table asserts: the field never carries a
--- symbol outside the documented set, and the run produced at least one.
local function decodes(t, lines, field, allowed, what)
    local seen = values(lines, field)
    t:assert(#seen > 0, what .. " produced at least one record")
    for _, v in ipairs(seen) do
        t:assert(allowed[v], "undocumented " .. field .. " symbol: " .. v)
    end
    return seen
end

test("kacs_access_decision reasons decode against the published table",
    { spec = "PKM *kacs-abi.trace.access-decision-reasons" }, function(t)
        local V = vocab("decision", "bad-args", "no-i_security", "unmanaged",
            "pip-context", "no-token", "no-dentry-alias",
            "delete-on-close-pending", "native-stamp", "native-arm", "stamp",
            "lazy-dentry-relookup", "negative-after-create",
            "change-notify-priv", "change-notify-priv-exhausted")
        local p = facs.file(vm, B .. "/decision", "hello")
        local lines = traced(t, "kacs/kacs_file_access", function()
            kacs.as_dacl_bound(t, vm, function(w)
                local fd = facs.open(w, p, { access = R.READ_DATA })
                if fd then sys.read(w, fd, 3); sys.close(w, fd) end
            end)
        end)
        local seen = decodes(t, lines, "reason", V, "the live file-access core")
        t:assert(has(seen, "decision"),
            "a resolved allow/deny is KACS_TR_DECISION")
        t:assert(#values(lines, "verdict") > 0,
            "and the verdict is a separate field, read from ret")
    end)

test("kacs_sd_cache reasons decode against the published table",
    { spec = "PKM *kacs-abi.trace.sd-cache-reasons" }, function(t)
        local V = vocab("hit", "miss-none", "miss-stale-gen",
            "miss-needs-synth", "corrupt-empty-or-oversize",
            "corrupt-validate-fail")
        local lines = traced(t, "kacs/kacs_sd_cache_lookup", function()
            -- A stored descriptor is a hit; a filesystem attached at
            -- runtime has objects with no cache at all.
            sys.stat(vm, B .. "/decision")
            kacs.new_mount(vm, "tmpfs", "/trc-syn",
                kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL)
            sys.mkdir(vm, "/trc-syn/d")
            sys.stat(vm, "/trc-syn/d")
        end)
        local seen = decodes(t, lines, "reason", V, "the inode SD cache")
        t:assert(has(seen, "hit"), "a current cache is KACS_SDC_HIT")
        t:assert(has(seen, "miss-none"),
            "and an inode with none is KACS_SDC_MISS_NONE")
    end)

test("kacs_process_access reasons decode against the published table",
    { spec = "PKM *kacs-abi.trace.process-access-reasons" }, function(t)
        local V = vocab("allow", "bad-args", "no-target", "no-sd", "sd-error",
            "pip-denied", "debug-rescue", "debug-denied", "pip-dominance")
        local lines = traced(t, "kacs/kacs_process_access", function()
            psb.against(t, vm, 0, function(w, pid)
                w:syscall(psb.NR.kill, pid, 15)
            end)
        end)
        local seen = decodes(t, lines, "reason", V,
            "a cross-process access decision")
        t:assert(has(seen, "debug-denied") or has(seen, "allow"),
            "the SeDebugPrivilege rung is named apart from a plain allow")
    end)

test("kacs_exec reasons decode against the published table",
    { spec = "PKM *kacs-abi.trace.exec-reasons" }, function(t)
        local V = vocab("creds-allow", "bad-args", "id-change-no-token",
            "id-change-priv-unsupported", "token-npm-derived", "token-clone",
            "npm-no-file", "npm-derive-fail", "token-install-fail",
            "token-clone-fail", "integrity-no-i_security",
            "integrity-no-cache", "integrity-invalid-sd",
            "impersonation-revert-fail", "pip-committed", "umh-not-tcb",
            "signature-unverifiable", "pip-capped-unsafe")
        local lines = traced(t, "kacs/kacs_exec", function()
            local proc = vm:run_async("/sbin/provium-agent", { "--port", "9931" })
            sys.nanosleep(vm, 0, 200 * 1000 * 1000)
            vm:syscall(62, proc:pid(), 9)
        end)
        local seen = decodes(t, lines, "reason", V, "an exec")
        t:assert(has(seen, "creds-allow"),
            "the cred transition is KACS_EXEC_CREDS_ALLOW")
        t:assert(has(seen, "pip-committed"),
            "and the commit-time PIP transition KACS_EXEC_PIP_COMMITTED")
    end)

test("kacs_signing reasons decode against the published table",
    { spec = "PKM *kacs-abi.trace.signing-reasons" }, function(t)
        local V = vocab("unsigned", "bad-key-table", "no-key-match",
            "verified", "crypto-unavailable", "crypto-mismatch",
            "found", "elf-magic-read", "elf-short-ehdr", "elf-ehdr-read",
            "elf-bad-ident", "elf-bad-shtable", "elf-shdrs-range",
            "elf-shstr-read", "elf-strtab-range", "elf-shdr-read",
            "elf-name-read", "elf-bad-sig-section", "elf-bad-blob",
            "elf-hash-fail", "xattr-bad-blob", "xattr-hash-fail",
            "size-changed")
        local lines = traced(t, "kacs/kacs_signing_verify", function()
            local proc = vm:run_async("/sbin/provium-agent", { "--port", "9932" })
            sys.nanosleep(vm, 0, 200 * 1000 * 1000)
            vm:syscall(62, proc:pid(), 9)
        end)
        local seen = decodes(t, lines, "reason", V, "a signature verification")
        t:assert(has(seen, "unsigned"),
            "a binary with no signature material is KACS_SIG_UNSIGNED")
        t:assert(#values(lines, "source") > 0,
            "and the material source is recorded as an enum, never bytes")
    end)

test("kacs_firmware reasons decode against the published table",
    { spec = "PKM *kacs-abi.trace.firmware-reasons",
      covered_by = "kunit:pkm_kunit_signing",
      skip = "a kernel-only guest loads no firmware: nothing in it can " ..
             "reach request_firmware, so the kacs:kacs_firmware_load " ..
             "event never fires; the verdict logic runs under " ..
             "pkm_kunit_firmware_verdict_requires_tcb" }, function(t)
    end)

test("kacs_socket reasons decode against the published table",
    { spec = "PKM *kacs-abi.trace.socket-reasons" }, function(t)
        local V = vocab("bad-args", "not-unix", "no-security", "no-token",
            "bad-level", "wrong-state", "no-peer-token", "pip-context",
            "sd-decision", "no-sd", "have-sd", "already-bound", "bind",
            "connect", "level-set", "open-token", "attach", "gate",
            "register", "deliver", "listen", "restamp", "port-bind",
            "port-table", "owner")
        local lines = traced(t, "kacs/kacs_socket_token", function()
            local srv, acc, cli = unix.connected(vm, "/trc-sock.sock")
            t:assert(srv, "a connected pair: " .. tostring(acc))
            unix.set_pass_token(vm, cli, true)
            unix.sendmsg(vm, cli, "x")
            local rcv = unix.recvmsg(vm, acc, 8)
            for _, fd in ipairs(rcv.tokens) do sys.close(vm, fd) end
            sys.close(vm, cli); sys.close(vm, acc); sys.close(vm, srv)
        end)
        local seen = decodes(t, lines, "reason", V, "the AF_UNIX identity path")
        t:assert(has(seen, "listen"),
            "the listener capture is KACS_SOCK_LISTEN")
        t:assert(has(seen, "attach"), "an attached identity KACS_SOCK_ATTACH")
        t:assert(has(seen, "deliver"),
            "and its delivery KACS_SOCK_DELIVER")
    end)

test("reason 16 is a hole in the kacs_socket table, never reused",
    { spec = "PKM *kacs-abi.trace.socket-reason-16-retired" }, function(t)
        -- 16 was KACS_SOCK_IMPERSONATE, for the retired
        -- kacs_impersonate_peer syscall. Nothing emits it, so the value
        -- has no symbol and would render as a bare number.
        local lines = traced(t, "kacs/kacs_socket_token", function()
            local srv, acc, cli = unix.connected(vm, "/trc-sock16.sock")
            t:assert(srv, "a connected pair: " .. tostring(acc))
            unix.set_pass_token(vm, cli, true)
            unix.sendmsg(vm, cli, "x")
            local rcv = unix.recvmsg(vm, acc, 8)
            for _, fd in ipairs(rcv.tokens) do sys.close(vm, fd) end
            unix.peer_token(vm, acc)
            unix.set_level(vm, cli, token.LEVEL.IDENTIFICATION)
            unix.restamp(vm, srv)
            sys.close(vm, cli); sys.close(vm, acc); sys.close(vm, srv)
        end)
        t:assert(#lines > 0, "the socket path is traced")
        for _, v in ipairs(values(lines, "reason")) do
            t:assert(v ~= "16", "no record carries the retired value 16")
        end
        -- And the syscall it belonged to is a permanent hole.
        t:assert_eq(vm:syscall(1011, 0, 0).errno, sys.E.NOSYS,
            "kacs_impersonate_peer (1011) is gone: " ..
            sys.errname(sys.E.NOSYS))
    end)

test("kacs_ipc reasons are the six numeric codes the table names",
    { spec = "PKM *kacs-abi.trace.ipc-reasons" }, function(t)
        -- kacs_ipc prints its reason as a number rather than a symbol,
        -- so the table is checked against the range it defines.
        local NR = { shmget = 29, shmat = 30, shmctl = 31 }
        local lines = traced(t, "kacs/kacs_ipc", function()
            local shm = vm:syscall(NR.shmget, 0xC101, 4096,
                0x200 | 0x1B6).ret
            vm:syscall(NR.shmat, shm, 0, 4096)
            vm:syscall(NR.shmctl, { args = { shm, 2, 0 },
                bufs = { string.rep("\0", 112) }, ptrs = { 2 } })
            vm:syscall(kacs.SYS.GET_SD, {
                args = { shm, 0, kacs.SI.DACL, 0, 4096, 0x01000000 },
                bufs = { string.rep("\0", 4096) }, ptrs = { 3 } })
            vm:syscall(NR.shmctl, shm, 0, 0)
        end)
        local seen = values(lines, "reason")
        t:assert(#seen > 0, "the System V IPC hooks are traced")
        local saw_alloc, saw_permission = false, false
        for _, v in ipairs(seen) do
            local n = tonumber(v)
            t:assert(n and n >= 0 and n <= 5,
                "every reason is one of KACS_IPC_ALLOC..KACS_IPC_NO_SD: " .. v)
            if n == 0 then saw_alloc = true end
            if n == 1 then saw_permission = true end
        end
        t:assert(saw_alloc, "creation stamps a default SD (0)")
        t:assert(saw_permission, "and an attach is an ipc_permission (1)")
    end)

test("kacs_namespace stages decode against the published table",
    { spec = "PKM *kacs-abi.trace.namespace-stages" }, function(t)
        local V = vocab("primary", "parent-fallback", "source", "dest",
            "delete-existing")
        local lines = traced(t, "kacs/kacs_inode_rename", function()
            vm:write_file(B .. "/ns-a", "a")
            sys.rename(vm, B .. "/ns-a", B .. "/ns-b")
        end)
        local seen = decodes(t, lines, "stage", V, "a rename")
        t:assert(has(seen, "source"), "the source side is KACS_NS_SOURCE")
        t:assert(has(seen, "dest"),
            "and the destination parent KACS_NS_DEST — a multi-stage op " ..
            "tags each verdict")
        local single = traced(t, "kacs/kacs_inode_create", function()
            vm:write_file(B .. "/ns-c", "c")
        end)
        local one = decodes(t, single, "stage", V, "a create")
        t:assert(has(one, "primary"),
            "while a single-decision op reports KACS_NS_PRIMARY")
    end)

test("kacs_psb reasons decode against the published table",
    { spec = "PKM *kacs-abi.trace.psb-reasons" }, function(t)
        local V = vocab("apply-ok", "apply-normalize", "apply-mm-acquire",
            "apply-cfif", "apply-sml", "apply-cfib", "wxp-mmap",
            "wxp-mprotect", "wxp-existing-vma", "lsv-probe", "lsv-verify",
            "lsv-pip-dominance", "pie-et-exec", "prctl-sml", "prctl-cfib",
            "prctl-pip")
        local lines = traced(t, "kacs/kacs_psb_apply", function()
            local worker = vm:spawn_worker()
            local ok, err = pcall(function()
                local pidfd = assert(token.pidfd_open(vm, psb.pid(worker)))
                psb.set_psb(vm, psb.MIT.WXP, pidfd)
                psb.set_psb(vm, 0x400, pidfd)
                sys.close(vm, pidfd)
            end)
            worker:kill(); worker:join()
            if not ok then error(err, 0) end
        end)
        local seen = decodes(t, lines, "reason", V, "a mitigation apply")
        t:assert(has(seen, "apply-ok"),
            "a committed mitigation is KACS_PSB_APPLY_OK")
        t:assert(has(seen, "apply-normalize"),
            "and an unsupported request KACS_PSB_APPLY_NORMALIZE")
    end)

test("kacs_token_ioctl cmds decode against the published table",
    { spec = "PKM *kacs-abi.trace.token-ioctl-cmds" }, function(t)
        local V = vocab("query", "adjust-privs", "adjust-groups", "duplicate",
            "install", "restrict", "link", "get-linked", "impersonate",
            "adjust-default", "adjust-sessionid", "unknown")
        local TCB = token.bit(token.PRIV.TCB)
        local lines = traced(t, "kacs/kacs_token_ioctl", function()
            -- A handle carrying only TOKEN_QUERY: every verb is reached
            -- and named, and the ones it may not perform surface as
            -- -EACCES rather than as an unrecognised command.
            local source = assert(token.mint(vm, {}))
            local fd = assert(token.duplicate(vm, source,
                { access = token.RIGHT.QUERY }))
            local sized = { { 0xC0104B00, 16 }, { 0x40184B01, 24 },
                { 0xC0104B02, 16 }, { 0x00004B03, 0 }, { 0xC0284B04, 40 },
                { 0xC0044B06, 4 }, { 0x40904B07, 144 }, { 0x00004B08, 0 },
                { 0x40104B09, 16 }, { 0x40044B0A, 4 }, { 0x40044B0B, 4 } }
            for _, c in ipairs(sized) do
                if c[2] == 0 then
                    vm:syscall(sys.NR.ioctl, fd, c[1], 0)
                else
                    vm:syscall(sys.NR.ioctl, { args = { fd, c[1], 0 },
                        bufs = { string.rep("\0", c[2]) }, ptrs = { 2 } })
                end
            end
            sys.close(vm, fd); sys.close(vm, source)
            -- The pair verbs need real descriptors to be reached.
            local elevated, sid = token.mint(vm,
                { privs_present = TCB, privs_enabled = TCB })
            local filtered = assert(token.create(vm, { auth_id = sid }))
            token.link(vm, elevated, elevated, filtered, sid)
            local linked = token.get_linked(vm, elevated)
            if linked then sys.close(vm, linked) end
            sys.close(vm, elevated); sys.close(vm, filtered)
        end)
        local seen = decodes(t, lines, "cmd", V, "the token-handle ioctls")
        for _, want in ipairs({ "query", "adjust-privs", "adjust-groups",
                                "duplicate", "install", "restrict", "link",
                                "get-linked", "impersonate", "adjust-default",
                                "adjust-sessionid", "unknown" }) do
            t:assert(has(seen, want), "the table's `" .. want ..
                "` verb is reached and named")
        end
    end)

test("kacs_token_ref reasons decode against the published table",
    { spec = "PKM *kacs-abi.trace.token-ref-reasons" }, function(t)
        local V = vocab("to-fd", "release", "bind", "open")
        local lines = traced(t, "kacs/kacs_token_ref", function()
            local fd = assert(token.mint(vm, {}))
            local own = token.open_self(vm, token.RIGHT.QUERY)
            if own then sys.close(vm, own) end
            sys.close(vm, fd)
        end)
        local seen = decodes(t, lines, "reason", V, "the token-fd lifecycle")
        t:assert(has(seen, "to-fd"),
            "a token installed into a fresh handle is KACS_TREF_TO_FD")
        t:assert(has(seen, "release"),
            "and the handle teardown KACS_TREF_RELEASE")
        t:assert(has(seen, "open"),
            "while the checked-access open path is KACS_TREF_OPEN")
    end)

test("kacs_logon_session reasons decode against the published table",
    { spec = "PKM *kacs-abi.trace.logon-session-reasons" }, function(t)
        local V = vocab("create", "create-priv-denied", "destroy",
            "destroy-priv-denied", "create-token", "create-token-priv-denied")
        local lines = traced(t, "kacs/kacs_logon_session", function()
            local sid = assert(token.create_logon_session(vm, {}))
            local fd = assert(token.create(vm, { auth_id = sid }))
            sys.close(vm, fd)
            local empty = assert(token.create_logon_session(vm, {}))
            token.destroy_empty_logon_session(vm, empty)
            -- A principal with no SeTcbPrivilege reaches the gate.
            token.as_principal(t, vm, {}, function(w)
                token.create_logon_session(w, {})
            end)
        end)
        local seen = decodes(t, lines, "reason", V,
            "the session and token creation surface")
        t:assert(has(seen, "create"), "a published session is KACS_SES_CREATE")
        t:assert(has(seen, "create-token"),
            "an issued token KACS_SES_CREATE_TOKEN")
        t:assert(has(seen, "destroy"), "a teardown KACS_SES_DESTROY")
        t:assert(has(seen, "create-priv-denied"),
            "and the TCB gate KACS_SES_CREATE_PRIV_DENIED")
    end)

test("kacs_cred reasons decode against the published table",
    { spec = "PKM *kacs-abi.trace.cred-reasons" }, function(t)
        local V = vocab("prepare", "transfer", "alloc-blank", "free",
            "install-token-ref", "clone-thread-share", "clone-fork-copy",
            "project-uid0-blocked", "project-groups-alloc-fail",
            "project-e2big")
        local lines = traced(t, "kacs/kacs_cred", function()
            token.as_principal(t, vm, {}, function(w)
                w:syscall(sys.NR.getuid)
            end)
        end)
        local seen = decodes(t, lines, "reason", V,
            "the credential lifecycle")
        t:assert(has(seen, "prepare"),
            "a cred_prepare token clone is KACS_CRED_PREPARE")
        t:assert(has(seen, "install-token-ref"),
            "an explicit install KACS_CRED_INSTALL_TOKEN_REF")
        t:assert(has(seen, "clone-fork-copy") or has(seen, "clone-thread-share"),
            "and the clone-time split is named either way")
    end)

test("kacs_setid reasons decode against the published table",
    { spec = "PKM *kacs-abi.trace.setid-reasons" }, function(t)
        local V = vocab("setuid-no-token", "setuid-priv-gate",
            "setgid-no-token", "setgid-priv-gate", "setgroups-no-token",
            "setgroups-priv-gate")
        local AP = token.bit(token.PRIV.ASSIGN_PRIMARY_TOKEN)
        local lines = traced(t, "kacs/kacs_setid", function()
            token.as_principal(t, vm,
                { privs_present = AP, privs_enabled = AP }, function(w)
                    w:syscall(sys.NR.setresuid, 1234, -1, -1)
                    w:syscall(sys.NR.setresgid, 1234, -1, -1)
                end)
        end)
        local seen = decodes(t, lines, "reason", V, "the setid gate")
        t:assert(has(seen, "setuid-priv-gate"),
            "a holder of SeAssignPrimaryTokenPrivilege hits " ..
            "KACS_SETID_SETUID_PRIV_GATE")
        t:assert(has(seen, "setgid-priv-gate"),
            "and the gid form its own code")
    end)

test("kacs_task reasons decode against the published table",
    { spec = "PKM *kacs-abi.trace.task-reasons" }, function(t)
        local V = vocab("alloc-no-child-blocked", "alloc-inherit-enomem",
            "alloc", "free")
        local lines = traced(t, "kacs/kacs_task", function()
            local worker = vm:spawn_worker()
            worker:syscall(sys.NR.getpid)
            worker:kill(); worker:join()
        end)
        local seen = decodes(t, lines, "reason", V,
            "the task-security lifecycle")
        t:assert(has(seen, "alloc"), "task_alloc is KACS_TASK_ALLOC")
    end)

test("kacs_primary_install reasons decode against the published table",
    { spec = "PKM *kacs-abi.trace.primary-install-reasons" }, function(t)
        local V = vocab("install-ok", "sd-realloc", "sd-alloc-fail",
            "apply-commit", "impersonate-install", "impersonate-revert",
            "sibling-requeue", "sibling-failed")
        local lines = traced(t, "kacs/kacs_primary_install", function()
            local worker = vm:spawn_worker()
            local ok, err = pcall(function()
                local prim = assert(token.mint(worker, {}))
                local imp = assert(token.duplicate(worker, prim, {
                    token_type = token.TYPE.IMPERSONATION,
                    impersonation_level = token.LEVEL.IMPERSONATION }))
                assert(token.install(worker, prim).ret == 0, "install")
                assert(token.impersonate(worker, imp).ret == 0, "impersonate")
                token.revert(worker)
            end)
            worker:kill(); worker:join()
            if not ok then error(err, 0) end
        end)
        local seen = decodes(t, lines, "reason", V,
            "the primary-token transitions")
        t:assert(has(seen, "install-ok"),
            "the install commit is KACS_PRIM_INSTALL_OK")
        t:assert(has(seen, "impersonate-install"),
            "an override_creds KACS_PRIM_IMPERSONATE_INSTALL")
        t:assert(has(seen, "impersonate-revert"),
            "and the revert KACS_PRIM_IMPERSONATE_REVERT")
    end)

test("kacs_process_token_open reasons decode against the published table",
    { spec = "PKM *kacs-abi.trace.process-token-open-reasons" }, function(t)
        local V = vocab("open-ok", "bad-args", "no-target", "bad-access",
            "access-denied", "self", "cross")
        local lines = traced(t, "kacs/kacs_process_token_open", function()
            local own = token.open_self(vm, token.RIGHT.QUERY)
            if own then sys.close(vm, own) end
            local worker = vm:spawn_worker()
            local ok, err = pcall(function()
                local pidfd = assert(token.pidfd_open(vm, psb.pid(worker)))
                local fd = token.open_process(vm, pidfd, token.RIGHT.QUERY)
                if fd then sys.close(vm, fd) end
                sys.close(vm, pidfd)
            end)
            worker:kill(); worker:join()
            if not ok then error(err, 0) end
        end)
        local seen = decodes(t, lines, "reason", V,
            "opening a process or thread token")
        t:assert(has(seen, "open-ok"),
            "a successful open is KACS_PTO_OPEN_OK")
    end)

test("kacs_process_state reasons decode against the published table",
    { spec = "PKM *kacs-abi.trace.process-state-reasons" }, function(t)
        local V = vocab("alloc", "alloc-fail", "free", "inherit-share",
            "inherit-fork", "exec-pip-stage", "exec-pip-commit", "dumpable",
            "clone-blocked-nochild", "sd-alloc", "sd-alloc-fail",
            "sd-wrap-fail", "sd-replace", "socket-sd-alloc")
        local lines = traced(t, "kacs/kacs_process_state", function()
            local worker = vm:spawn_worker()
            worker:syscall(sys.NR.getpid)
            worker:kill(); worker:join()
        end)
        local seen = decodes(t, lines, "reason", V,
            "the process-state lifecycle")
        t:assert(has(seen, "alloc"), "an allocation is KACS_PST_ALLOC")
        t:assert(has(seen, "inherit-fork") or has(seen, "inherit-share"),
            "and the CLONE_THREAD-versus-fork split is named")
    end)

test("kacs_mount_policy reasons decode against the published table",
    { spec = "PKM *kacs-abi.trace.mount-policy-reasons" }, function(t)
        local V = vocab("set-ok", "bad-args", "no-security", "unmanaged",
            "validate", "template-invalid", "tcb-denied", "get-ok",
            "get-no-security", "fixed-policy")
        local set_lines = traced(t, "kacs/kacs_mount_policy_set", function()
            kacs.new_mount(vm, "tmpfs", "/trc-mp",
                kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL)
        end)
        local seen = decodes(t, set_lines, "reason", V, "a policy set")
        t:assert(has(seen, "set-ok"),
            "a committed change is KACS_MP_SET_OK")
        local get_lines = traced(t, "kacs/kacs_mount_policy_get", function()
            local fd = assert(sys.open(vm, "/trc-mp",
                sys.O.RDONLY | sys.O.DIRECTORY))
            kacs.get_mount_policy(vm, fd)
            sys.close(vm, fd)
        end)
        local got = decodes(t, get_lines, "reason", V, "a policy get")
        t:assert(has(got, "get-ok"), "and a snapshot KACS_MP_GET_OK")
    end)

test("kacs_sd_syscall target kinds decode against the published table",
    { spec = "PKM *kacs-abi.trace.sd-syscall-target-kinds" }, function(t)
        local V = vocab("token", "file", "process", "path", "access-check")
        local lines = traced(t, "kacs/kacs_sd_query", function()
            kacs.get_sd(vm, B .. "/decision")
            local fd = assert(token.mint(vm, {}))
            token.get_sd(vm, fd, kacs.SI.DACL)
            sys.close(vm, fd)
            local worker = vm:spawn_worker()
            local ok, err = pcall(function()
                local pidfd = assert(token.pidfd_open(vm, psb.pid(worker)))
                psb.get_sd(vm, pidfd, kacs.SI.DACL)
                sys.close(vm, pidfd)
            end)
            worker:kill(); worker:join()
            if not ok then error(err, 0) end
        end)
        local seen = decodes(t, lines, "kind", V, "the SD query core")
        t:assert(has(seen, "file"), "an inode target is KACS_SDS_KIND_FILE")
        t:assert(has(seen, "token"), "a token fd KACS_SDS_KIND_TOKEN")
        t:assert(has(seen, "process"), "and a pidfd KACS_SDS_KIND_PROCESS")
        -- KACS_SDS_KIND_ACCESS_CHECK tags the AccessCheck ingress, on
        -- the kacs_access_check event rather than on an SD get or set.
        local ingress = traced(t, "kacs/kacs_access_check", function()
            local fd = assert(token.mint(vm, {}))
            access.check(vm, { token_fd = fd, sd = access.simple({}),
                desired = 0x1 })
            sys.close(vm, fd)
        end)
        local kinds = decodes(t, ingress, "kind", V, "the AccessCheck ingress")
        t:assert(has(kinds, "access-check"),
            "which is tagged KACS_SDS_KIND_ACCESS_CHECK")
    end)

test("kacs_sd_syscall reasons decode against the published table",
    { spec = "PKM *kacs-abi.trace.sd-syscall-reasons" }, function(t)
        local V = vocab("query-ok", "set-ok", "bad-args", "unmanaged",
            "access-denied", "no-sd", "restore-bypass", "query-fail")
        local p = facs.file(vm, B .. "/sdsys", "s")
        -- Owned by someone else, with an empty DACL: the bound caller
        -- has neither READ_CONTROL nor the owner's implicit rights.
        local closed = access.sd({ owner = token.SID.TEST_USER,
            group = token.SID.TEST_USER, dacl = access.acl({}) })
        local q = traced(t, "kacs/kacs_sd_query", function()
            kacs.get_sd(vm, p)
            t:assert_eq(kacs.set_sd(vm, p, closed,
                kacs.SI.OWNER | kacs.SI.GROUP | kacs.SI.DACL).ret, 0,
                "the descriptor is closed to everyone but its owner")
            kacs.as_dacl_bound(t, vm, function(w) kacs.get_sd(w, p) end)
            -- An unmanaged superblock answers neither way.
            kacs.get_sd(vm, "/proc/self/stat")
        end)
        local seen = decodes(t, q, "reason", V, "an SD query")
        t:assert(has(seen, "query-ok"),
            "a returned subset is KACS_SDS_QUERY_OK")
        t:assert(has(seen, "access-denied"),
            "a refused one KACS_SDS_ACCESS_DENIED")
        t:assert(has(seen, "unmanaged"),
            "and an unmanaged superblock KACS_SDS_UNMANAGED")
        kacs.set_sd(vm, p, kacs.grant(kacs.ALL_RIGHTS))
        local s = traced(t, "kacs/kacs_sd_set", function()
            kacs.set_sd(vm, p, kacs.grant(kacs.ALL_RIGHTS))
        end)
        local set = decodes(t, s, "reason", V, "an SD set")
        t:assert(has(set, "set-ok"), "a merged descriptor is KACS_SDS_SET_OK")
    end)

test("kacs_access_check reasons decode against the published table",
    { spec = "PKM *kacs-abi.trace.access-check-reasons" }, function(t)
        local V = vocab("ok", "eval-context", "token-resolve", "caap-lock-fail")
        local lines = traced(t, "kacs/kacs_access_check", function()
            local fd = assert(token.mint(vm, {}))
            access.check(vm, { token_fd = fd, sd = access.simple({}),
                desired = 0x1 })
            -- A descriptor that names no live token: the ingress cannot
            -- resolve it.
            access.check(vm, { token_fd = 4242, sd = access.simple({}),
                desired = 0x1 })
            sys.close(vm, fd)
        end)
        local seen = decodes(t, lines, "reason", V, "the AccessCheck ingress")
        t:assert(has(seen, "ok"),
            "a dispatched ingress is KACS_ACK_OK")
        t:assert(has(seen, "token-resolve"),
            "and an unresolvable token KACS_ACK_TOKEN_RESOLVE")
    end)

test("kacs_file_snapshot ops decode against the published table",
    { spec = "PKM *kacs-abi.trace.file-snapshot-ops" }, function(t)
        local V = vocab("access", "permission", "ioctl", "lock", "fcntl",
            "truncate", "fallocate", "mmap", "mprotect", "write-intent",
            "sysfs-write-gate")
        local p = facs.file(vm, B .. "/snapop", "hello")
        local lines = traced(t, "kacs/kacs_file_snapshot", function()
            local fd = facs.open(vm, p, { access = R.READ_DATA | R.WRITE_DATA
                | R.READ_ATTRIBUTES | R.WRITE_ATTRIBUTES })
            t:assert(fd, "a native handle")
            sys.flock(vm, fd, sys.LOCK_SH)
            sys.ftruncate(vm, fd, 2)
            sys.fallocate(vm, fd, 0, 0, 4096)
            sys.mmap(vm, fd, 4096, sys.PROT.READ, sys.MAP.SHARED)
            facs.ioctl(vm, fd, sys.FS_IOC_GETFLAGS, string.pack("<I8", 0))
            sys.write(vm, fd, "z")
            sys.close(vm, fd)
        end)
        local seen = decodes(t, lines, "op", V, "the snapshot-grant hooks")
        for _, want in ipairs({ "lock", "truncate", "fallocate", "mmap",
                                "ioctl", "permission" }) do
            t:assert(has(seen, want),
                "the table's `" .. want .. "` enforcement point is named")
        end
    end)

test("kacs_file_snapshot reasons decode against the published table",
    { spec = "PKM *kacs-abi.trace.file-snapshot-reasons" }, function(t)
        local V = vocab("decision", "signed-exec", "grant-deny",
            "append-deny", "unmanaged-sysfs", "audit-emit-fail")
        local p = facs.file(vm, B .. "/snapreason", "hello")
        local lines = traced(t, "kacs/kacs_file_snapshot", function()
            -- A handle opened for reading only: the operations its
            -- cached mask covers resolve, and one it does not is a
            -- grant-deny.
            local fd = facs.open(vm, p, { access = R.READ_DATA })
            t:assert(fd, "a read-only native handle")
            sys.read(vm, fd, 3)
            facs.ioctl(vm, fd, sys.FS_IOC_GETFLAGS, string.pack("<I8", 0))
            sys.write(vm, fd, "nope")
            sys.close(vm, fd)
        end)
        local seen = decodes(t, lines, "reason", V,
            "the snapshot-grant verdicts")
        t:assert(has(seen, "decision"),
            "a resolved compare is KACS_FSR_DECISION")
        t:assert(has(seen, "grant-deny"),
            "and a mask that lacks the required right KACS_FSR_GRANT_DENY")
    end)

test("kacs_metadata reasons decode against the published table",
    { spec = "PKM *kacs-abi.trace.metadata-reasons" }, function(t)
        local V = vocab("decision", "consume-hit", "begin-busy",
            "canonical-sd", "caps-xattr", "acl", "signed-exec", "bad-args",
            "internal-sd", "getsecurity")
        local p = facs.file(vm, B .. "/meta", "m")
        local lines = traced(t, "kacs/kacs_metadata", function()
            -- The canonical descriptor xattr is not writable through the
            -- xattr surface: that refusal is the metadata hook speaking.
            sys.setxattr(vm, p, "security.peios.sd", "junk", 0)
            sys.setxattr(vm, p, "security.capability", "junk", 0)
        end)
        local seen = decodes(t, lines, "reason", V,
            "the file-metadata hooks")
        t:assert(has(seen, "canonical-sd"),
            "a canonical-SD xattr mutation is KACS_META_CANONICAL_SD")
    end)

test("kacs_native_open_ext reasons decode against the published table",
    { spec = "PKM *kacs-abi.trace.native-open-ext-reasons" }, function(t)
        local V = vocab("prepare-ok", "prepare-bad-flags",
            "prepare-bad-sd-args", "prepare-bad-disposition",
            "prepare-bad-access", "prepare-unsupported", "resolve",
            "build-created-sd", "delete-on-close-arm")
        local p = facs.file(vm, B .. "/nox", "n")
        local lines = traced(t, "kacs/kacs_native_open_ext", function()
            facs.open(vm, p, { access = R.READ_DATA, flags = 0x40 })
            facs.open(vm, p, { access = R.READ_DATA, disposition = 9 })
            facs.open(vm, p, { access = 0 })
            local fd = facs.open(vm, B .. "/nox-new",
                { access = R.READ_DATA | R.WRITE_DATA,
                  disposition = kacs.DISPOSITION.CREATE })
            if fd then sys.close(vm, fd) end
        end)
        local seen = decodes(t, lines, "reason", V,
            "the native-open preparation")
        t:assert(has(seen, "prepare-ok"),
            "an accepted request is KACS_NOX_PREPARE_OK")
        t:assert(has(seen, "prepare-bad-flags"),
            "a bad flags word KACS_NOX_PREPARE_BAD_FLAGS")
        t:assert(has(seen, "prepare-bad-disposition"),
            "a disposition out of range KACS_NOX_PREPARE_BAD_DISPOSITION")
        t:assert(has(seen, "build-created-sd"),
            "and building a created file's descriptor " ..
            "KACS_NOX_BUILD_CREATED_SD")
    end)

test("kacs_object reasons decode against the published table",
    { spec = "PKM *kacs-abi.trace.object-reasons" }, function(t)
        local V = vocab("delete-on-close-unlink", "signed-exec-pin",
            "signed-exec-mutation-blocked")
        local lines = traced(t, "kacs/kacs_object", function()
            local fd = facs.open(vm, B .. "/obj",
                { access = R.READ_DATA | R.WRITE_DATA | R.DELETE,
                  disposition = kacs.DISPOSITION.CREATE,
                  options = kacs.CREATE_OPT.DELETE_ON_CLOSE })
            t:assert(fd, "a delete-on-close handle")
            sys.close(vm, fd)
        end)
        local seen = decodes(t, lines, "reason", V,
            "the object-lifecycle transitions")
        t:assert(has(seen, "delete-on-close-unlink"),
            "the release-time unlink is KACS_OBJ_DELETE_ON_CLOSE_UNLINK")
    end)

test("kacs_securityfs reasons decode against the published table",
    { spec = "PKM *kacs-abi.trace.securityfs-reasons" }, function(t)
        local V = vocab("sessions-no-token", "sessions-pip-context",
            "sessions-access-check", "open-self", "init")
        -- securityfs is unclassified by FACS, so it is mounted with a
        -- synthesising policy before anything under it can be read.
        local path, err = hooks.hook_path(vm, "unused")
        t:assert(path, "securityfs mounts: " .. tostring(err))
        local lines = traced(t, "kacs/kacs_securityfs", function()
            local fd = sys.open(vm, hooks.SECURITYFS_AT .. "/kacs/self",
                sys.O.RDONLY)
            if fd then sys.close(vm, fd) end
            local sessions = sys.open(vm,
                hooks.SECURITYFS_AT .. "/kacs/sessions", sys.O.RDONLY)
            if sessions then
                sys.read(vm, sessions, 256); sys.close(vm, sessions)
            end
        end)
        local seen = decodes(t, lines, "reason", V,
            "the securityfs endpoints")
        t:assert(has(seen, "open-self"),
            "opening kacs/self is KACS_SFS_OPEN_SELF")
    end)

test("kacs_caap reasons decode against the published table",
    { spec = "PKM *kacs-abi.trace.caap-reasons" }, function(t)
        local V = vocab("tcb-gate", "set", "init", "destroy")
        local policy = token.sid(5, 21, 1000, 2000, 3000, 7100)
        local dacl = access.acl({ access.ace(access.ACE.ALLOWED, 0x1,
            token.SID.TEST_USER) })
        local lines = traced(t, "kacs/kacs_caap", function()
            access.set_caap(vm, policy,
                access.caap_spec({ { effective_dacl = dacl } }))
            access.set_caap(vm, policy, nil)
            token.as_principal(t, vm, {}, function(w)
                access.set_caap(w, policy, nil)
            end)
        end)
        local seen = decodes(t, lines, "reason", V, "the CAAP policy cache")
        t:assert(has(seen, "set"), "a cache set is KACS_CAAP_SET")
        t:assert(has(seen, "tcb-gate"),
            "and the SeTcbPrivilege gate KACS_CAAP_TCB_GATE")
    end)

test("kacs_capability reasons decode against the published table",
    { spec = "PKM *kacs-abi.trace.capability-reasons" }, function(t)
        local V = vocab("allow-grant", "hard-deny", "priv-not-enabled",
            "use-mark-fail", "capset", "prctl-guard", "capable", "capget")
        local lines = traced(t, "kacs/kacs_capability", function()
            token.as_principal(t, vm, {}, function(w)
                -- capset: the hard-denied SETPCAP family.
                w:syscall(125, { args = { 0, 0 },
                    bufs = { string.rep("\0", 8), string.rep("\0", 24) },
                    ptrs = { 0, 1 } })
                -- A device node needs CAP_MKNOD, which maps to a
                -- privilege this principal does not hold.
                w:syscall(sys.NR.mknodat, { args = { sys.AT_FDCWD, 0,
                    sys.S_IFCHR | 420, 0 },
                    bufs = { sys.cstr("/trc-dev") }, ptrs = { 1 } })
                -- capget for a task, which is its own hook outcome.
                w:syscall(126, { args = { 0, 0 },
                    bufs = { string.pack("<I4i4", 0x20080522, 0),
                             string.rep("\0", 24) }, ptrs = { 0, 1 } })
            end)
        end)
        local seen = decodes(t, lines, "reason", V,
            "the capability-to-privilege gate")
        t:assert(has(seen, "capset"), "the capset core is KACS_CAP_CAPSET")
        t:assert(has(seen, "hard-deny"),
            "and the SETPCAP family a KACS_CAP_HARD_DENY")
        t:assert(has(seen, "prctl-guard"),
            "while the prctl guard reports its own outcome")
    end)

test("kacs_privilege reasons decode against the published table",
    { spec = "PKM *kacs-abi.trace.privilege-reasons" }, function(t)
        local V = vocab("null-or-zero", "not-enabled", "use-mark-fail",
            "change-notify", "rcu-enomem-fallback")
        local p = facs.file(vm, B .. "/priv", "p")
        local lines = traced(t, "kacs/kacs_privilege", function()
            -- Reading a SACL needs SeSecurityPrivilege, held and enabled.
            token.as_principal(t, vm, {}, function(w)
                kacs.get_sd(w, p, kacs.SI.SACL)
                -- open_by_handle_at is the SeChangeNotifyPrivilege gate.
                w:syscall(304, { args = { sys.AT_FDCWD, 0, 0 },
                    bufs = { string.rep("\0", 128) }, ptrs = { 1 } })
            end)
        end)
        local seen = decodes(t, lines, "reason", V,
            "the require-enabled-privilege gate")
        t:assert(has(seen, "not-enabled"),
            "a privilege the token lacks is KACS_PRIV_NOT_ENABLED")
        t:assert(has(seen, "change-notify"),
            "and the open_by_handle_at check KACS_PRIV_CHANGE_NOTIFY")
    end)

test("kacs_tlp reasons decode against the published table",
    { spec = "PKM *kacs-abi.trace.tlp-reasons" }, function(t)
        local V = vocab("check-path", "replace")
        local lines = traced(t, "kacs/kacs_tlp", function()
            -- Enabling the trusted-launch-path mitigation evaluates the
            -- process's existing executable mappings against the prefix
            -- table, which is empty: no prefix matches.
            kacs.as_dacl_bound(t, vm, function(w)
                t:assert_eq(psb.commit(w, psb.MIT.TLP), sys.E.ACCES,
                    "tlp is refused against an unlisted mapping")
            end)
        end)
        local seen = decodes(t, lines, "reason", V,
            "the trusted-launch-path decisions")
        t:assert(has(seen, "check-path"),
            "a no-prefix-match denial is KACS_TLP_CHECK_PATH")
        for _, l in ipairs(lines) do
            t:assert(l:match("path_len=%d+"),
                "the record carries the path length, never the path")
            t:assert(not l:match("/sbin"), "and no path bytes at all")
        end
    end)
