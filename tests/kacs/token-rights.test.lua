-- PKM §3.2.8 — Token access rights: obtaining a handle, the
-- token-specific rights and their generic mapping, the default token
-- descriptor, and check-at-open against the standard rights' live check.
-- The socket-borne handles (peer token, SCM tokens, SCM_RIGHTS) are in
-- imp-*.test.lua's territory and cited from there.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local access = require("helpers.access")

local vm = provium:vm("v", "kernel-only"):boot()

local R = token.RIGHT
local TCB, CREATE, ASSIGN = token.bit(token.PRIV.TCB), token.bit(token.PRIV.CREATE_TOKEN), token.bit(token.PRIV.ASSIGN_PRIMARY_TOKEN)
local SELF_RIGHTS = R.QUERY | R.ADJUST_PRIVS | R.ADJUST_GROUPS | R.ADJUST_DEFAULT
local PROCESS_QUERY_INFORMATION = 0x0400

--- The worker's primary token as seen by the agent, plus its pidfd.
local function reach(w)
    local pidfd = assert(token.pidfd_open(vm, w:syscall(sys.NR.getpid).ret))
    local fd = assert(token.open_process(vm, pidfd))
    return fd, pidfd
end

--- Replace a token's DACL (through the agent, which holds WRITE_DAC).
local function set_dacl(fd, aces)
    return token.set_sd(vm, fd, access.sd({ dacl = access.acl(aces) }), kacs.SI.DACL)
end

test("tokens are securable objects: reaching one is an AccessCheck against its descriptor",
    { spec = "PKM *token.rights.access-checked-object" }, function(t)
        token.as_principal(t, vm, {}, function(a)
            local a_pid = a:syscall(sys.NR.getpid).ret
            -- A second principal, a different user, tries to reach A's token.
            token.as_principal(t, vm, { user_sid = token.SID.TEST_USER_2, projected_uid = 1102 }, function(b)
                local pidfd = assert(token.pidfd_open(b, a_pid))
                local fd, errno = token.open_process(b, pidfd, R.QUERY)
                t:assert(not fd and errno == sys.E.ACCES, "B is not in A's token descriptor: EACCES")
            end)
            local own, e = token.open_self(a, R.QUERY)
            t:assert(own, "A reaches its own token for what the descriptor grants: " .. sys.errname(e or 0))
        end)
    end)

test("opening directly takes a pidfd and a desired mask, and caches the granted mask",
    { spec = "PKM *token.rights.open-by-pidfd" }, function(t)
        token.as_principal(t, vm, {}, function(w)
            local pid = w:syscall(sys.NR.getpid).ret
            local by_pid = vm:syscall(token.SYS.OPEN_PROCESS_TOKEN, pid, R.QUERY)
            t:assert(by_pid.ret < 0 and by_pid.errno == sys.E.BADF, "a raw PID is not a pidfd: EBADF")
            local pidfd = assert(token.pidfd_open(vm, pid))
            local fd = assert(token.open_process(vm, pidfd, R.QUERY | R.DUPLICATE))
            t:assert(token.query(vm, fd, token.CLASS.USER), "TOKEN_QUERY is cached")
            local d = token.duplicate(vm, fd, {})
            t:assert(d, "TOKEN_DUPLICATE is cached")
            sys.close(vm, d)
            t:assert_eq(token.enable_priv(vm, fd, token.PRIV.TCB).errno, sys.E.ACCES,
                "a right not requested is not on the handle, whoever the caller is")
            sys.close(vm, fd); sys.close(vm, pidfd)
        end)
    end)

test("a separate variant opens a thread's impersonation token",
    { spec = "PKM *token.rights.open-thread-token" }, function(t)
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local pid, tid = worker:syscall(sys.NR.getpid).ret, worker:syscall(sys.NR.gettid).ret
            local pidfd = assert(token.pidfd_open(vm, pid))
            local plain = assert(token.open_thread(vm, pidfd, tid))
            local pt0 = assert(token.open_process(vm, pidfd))
            t:assert_eq(token.statistics(vm, plain).token_id, token.statistics(vm, pt0).token_id,
                "a thread that is not impersonating resolves to the primary")
            sys.close(vm, plain); sys.close(vm, pt0)
            local prim = assert(token.mint(worker, {}))
            local imp = assert(token.duplicate(worker, prim, { token_type = token.TYPE.IMPERSONATION,
                impersonation_level = token.LEVEL.IMPERSONATION }))
            assert(token.impersonate(worker, imp).ret == 0)
            local tt = assert(token.open_thread(vm, pidfd, tid))
            t:assert_eq(token.statistics(vm, tt).token_id, token.statistics(worker, imp).token_id,
                "the thread variant returns the impersonation token")
            t:assert_eq(token.query_u32(vm, tt, token.CLASS.TYPE), token.TYPE.IMPERSONATION, "of type Impersonation")
            local pt = assert(token.open_process(vm, pidfd))
            t:assert_eq(token.query_u32(vm, pt, token.CLASS.TYPE), token.TYPE.PRIMARY, "while the process variant returns the primary")
            token.revert(worker)
            sys.close(vm, tt); sys.close(vm, pt); sys.close(vm, pidfd)
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
    end)

test("opening another process's token also needs PROCESS_QUERY_INFORMATION on the process",
    { spec = "PKM *token.rights.open-other-needs-process-query" }, function(t)
        token.as_principal(t, vm, {}, function(a)
            local a_pid = a:syscall(sys.NR.getpid).ret
            local a_tok, a_pidfd = reach(a)
            -- Grant Everyone TOKEN_QUERY on A's token, so the token descriptor
            -- is not the obstacle.
            t:assert_eq(set_dacl(a_tok, {
                access.ace(access.ACE.ALLOWED, R.QUERY, token.SID.EVERYONE),
                access.ace(access.ACE.ALLOWED, R.ALL_ACCESS, token.SID.LOCAL_SYSTEM) }).ret, 0, "token DACL opened up")
            token.as_principal(t, vm, { user_sid = token.SID.TEST_USER_2, projected_uid = 1102 }, function(b)
                local pidfd = assert(token.pidfd_open(b, a_pid))
                local fd, errno = token.open_process(b, pidfd, R.QUERY)
                t:assert(not fd and errno == sys.E.ACCES, "without PROCESS_QUERY_INFORMATION on A's process: EACCES")
                -- Now grant B PROCESS_QUERY_INFORMATION on A's process descriptor.
                local psd = access.sd({ dacl = access.acl({
                    access.ace(access.ACE.ALLOWED, PROCESS_QUERY_INFORMATION, token.SID.TEST_USER_2),
                    access.ace(access.ACE.ALLOWED, 0x1FFFFF, token.SID.LOCAL_SYSTEM) }) })
                local set = vm:syscall(kacs.SYS.SET_SD, {
                    args = { a_pidfd, 0, kacs.SI.DACL, 0, #psd, sys.AT_EMPTY_PATH },
                    bufs = { sys.cstr(""), psd }, ptrs = { 1, 3 } })
                t:assert_eq(set.ret, 0, "A's process DACL now grants B QUERY_INFORMATION: " .. sys.errname(set.errno or 0))
                fd, errno = token.open_process(b, pidfd, R.QUERY)
                t:assert(fd, "and B reaches the token: " .. sys.errname(errno or 0))
                t:assert_eq(token.query(b, fd, token.CLASS.USER), token.SID.TEST_USER, "it is A's")
            end)
            sys.close(vm, a_tok); sys.close(vm, a_pidfd)
        end)
    end)

test("self-query follows from the default descriptor and can be revoked by rewriting it",
    { spec = "PKM *token.rights.self-query-revocable" }, function(t)
        token.as_principal(t, vm, {}, function(w)
            local own = assert(token.open_self(w, R.QUERY))
            sys.close(w, own)
            local fd = reach(w)
            t:assert_eq(set_dacl(fd, { access.ace(access.ACE.ALLOWED, R.ALL_ACCESS, token.SID.LOCAL_SYSTEM) }).ret, 0,
                "the self grant is removed from the token's DACL")
            local again, errno = token.open_self(w, R.QUERY)
            t:assert(not again and errno == sys.E.ACCES, "self-query is now refused: the AccessCheck really runs")
            sys.close(vm, fd)
        end)
    end)

test("TOKEN_ASSIGN_PRIMARY on the handle is not enough: SeAssignPrimaryTokenPrivilege is required too",
    { spec = "PKM *token.rights.assign-primary-needs-privilege" }, function(t)
        -- A principal able to mint (and so holding ALL_ACCESS on what it
        -- mints) but lacking SeAssignPrimaryTokenPrivilege.
        token.as_principal(t, vm, { privs_present = TCB | CREATE | ASSIGN, privs_enabled = TCB | CREATE }, function(w)
            local own = assert(token.open_self(w, R.QUERY | R.ADJUST_PRIVS))
            local mine, sid = assert(token.mint(w, {}))
            local r = token.install(w, mine)
            t:assert_eq(r.errno, sys.E.ACCES, "held-but-disabled SeAssignPrimaryTokenPrivilege: EACCES")
            t:assert_eq(token.enable_priv(w, own, token.PRIV.ASSIGN_PRIMARY_TOKEN).ret, 0, "enable it")
            r = token.install(w, mine)
            t:assert_eq(r.ret, 0, "with the privilege the ALL_ACCESS handle installs: " .. sys.errname(r.errno or 0))
        end)
    end)

test("TOKEN_QUERY_SOURCE is subsumed by TOKEN_QUERY and grants nothing alone",
    { spec = "PKM *token.rights.query-source-subsumed" }, function(t)
        local fd = assert(token.mint(vm, {}))
        local q = assert(token.duplicate(vm, fd, { access = R.QUERY }))
        local src = token.source(vm, q)
        t:assert(src and src.name == "PITTest\0", "a TOKEN_QUERY holder reads the source")
        local qs, e = token.duplicate(vm, fd, { access = R.QUERY_SOURCE })
        if qs then
            local s2, e2 = token.query(vm, qs, token.CLASS.SOURCE)
            t:assert(not s2 and e2 == sys.E.ACCES, "a TOKEN_QUERY_SOURCE-only handle cannot query: EACCES")
            sys.close(vm, qs)
        else
            t:log("a handle with only 0x0010 is not even granted: " .. sys.errname(e))
        end
        sys.close(vm, q); sys.close(vm, fd)
    end)

test("TOKEN_ALL_ACCESS is 0x000F01FF",
    { spec = "PKM *token.rights.all-access-value" }, function(t)
        t:assert_eq(R.ALL_ACCESS, 0x000F01FF, "the constant")
        t:assert_eq(SELF_RIGHTS | R.ASSIGN_PRIMARY | R.DUPLICATE | R.IMPERSONATE | R.ADJUST_INTERACTIVITY_SCOPE, 0x01EF,
            "the named rights OR to 0x01EF")
        local fd = assert(token.mint(vm, {}))
        local all = assert(token.duplicate(vm, fd, { access = 0x000F01FF }))
        t:assert(all, "SYSTEM is granted the full mask on a token it created")
        local bad, e = token.duplicate(vm, fd, { access = 0x0200 })
        t:assert(not bad, "an undefined token-specific bit is not grantable: " .. sys.errname(e or 0))
        sys.close(vm, all); sys.close(vm, fd)
    end)

test("the generic rights map onto the token-specific ones",
    { spec = "PKM *token.rights.generic-mapping" }, function(t)
        local fd = assert(token.mint(vm, { privs_present = TCB }))
        local read = assert(token.duplicate(vm, fd, { access = R.GENERIC_READ }))
        t:assert(token.query(vm, read, token.CLASS.USER), "GENERIC_READ: TOKEN_QUERY")
        t:assert(token.get_sd(vm, read), "GENERIC_READ: READ_CONTROL")
        t:assert_eq(token.enable_priv(vm, read, token.PRIV.TCB).errno, sys.E.ACCES, "GENERIC_READ: no adjust")
        local write = assert(token.duplicate(vm, fd, { access = R.GENERIC_WRITE }))
        t:assert_eq(token.enable_priv(vm, write, token.PRIV.TCB).ret, 0, "GENERIC_WRITE: ADJUST_PRIVILEGES")
        t:assert_eq(token.adjust_groups(vm, write, { { 2, 0 } }).ret, 0, "GENERIC_WRITE: ADJUST_GROUPS")
        t:assert_eq(token.adjust_default(vm, write, { owner_index = 0, group_index = 0 }).ret, 0, "GENERIC_WRITE: ADJUST_DEFAULT")
        t:assert_eq(set_dacl(write, { access.ace(access.ACE.ALLOWED, R.ALL_ACCESS, token.SID.LOCAL_SYSTEM) }).ret, 0,
            "GENERIC_WRITE: WRITE_DAC")
        local _, eq = token.query(vm, write, token.CLASS.USER)
        t:assert_eq(eq, sys.E.ACCES, "GENERIC_WRITE: no TOKEN_QUERY")
        local exec = assert(token.duplicate(vm, fd, { access = R.GENERIC_EXECUTE }))
        local _, ee = token.query(vm, exec, token.CLASS.USER)
        t:assert_eq(ee, sys.E.ACCES, "GENERIC_EXECUTE: no TOKEN_QUERY")
        local all = assert(token.duplicate(vm, fd, { access = R.GENERIC_ALL }))
        t:assert(token.query(vm, all, token.CLASS.USER) and token.duplicate(vm, all, {}), "GENERIC_ALL: everything")
        -- GENERIC_EXECUTE = TOKEN_IMPERSONATE: only a worker can show it.
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local p = assert(token.mint(worker, {}))
            local imp = assert(token.duplicate(worker, p, { token_type = token.TYPE.IMPERSONATION,
                impersonation_level = token.LEVEL.IMPERSONATION }))
            local x = assert(token.duplicate(worker, imp, { access = R.GENERIC_EXECUTE,
                token_type = token.TYPE.IMPERSONATION, impersonation_level = token.LEVEL.IMPERSONATION }))
            t:assert_eq(token.impersonate(worker, x).ret, 0, "GENERIC_EXECUTE: TOKEN_IMPERSONATE")
            token.revert(worker)
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
        sys.close(vm, read); sys.close(vm, write); sys.close(vm, exec); sys.close(vm, all); sys.close(vm, fd)
    end)

test("DELETE has no effect on a token",
    { spec = "PKM *token.rights.delete-inert" }, function(t)
        local fd = assert(token.mint(vm, {}))
        local d = assert(token.duplicate(vm, fd, { access = R.DELETE | R.QUERY }))
        t:assert(d, "DELETE is grantable")
        sys.close(vm, d)
        t:assert(token.query(vm, fd, token.CLASS.USER), "and the token is still there afterwards")
        sys.close(vm, fd)
    end)

test("a new token's descriptor is owned by the creator with the three-ACE default DACL",
    { spec = "PKM *token.rights.default-descriptor" }, function(t)
        local fd = assert(token.mint(vm, {}))
        local sd = token.parse_sd(assert(token.get_sd(vm, fd)))
        t:assert_eq(sd.owner, token.SID.LOCAL_SYSTEM, "owned by the creating process's user SID, SYSTEM")
        local self_ace = token.find_ace(sd.dacl, token.SID.TEST_USER, 0)
        t:assert(self_ace, "an ACE for the token's own user SID")
        t:assert_eq(self_ace.mask, SELF_RIGHTS, "QUERY | ADJUST_PRIVILEGES | ADJUST_GROUPS | ADJUST_DEFAULT")
        local sys_aces = {}
        for _, a in ipairs(sd.dacl) do if a.sid == token.SID.LOCAL_SYSTEM then sys_aces[#sys_aces + 1] = a end end
        t:assert(#sys_aces >= 1, "SYSTEM has an ACE (creator and SYSTEM are the same principal here)")
        for _, a in ipairs(sys_aces) do t:assert_eq(a.mask, R.ALL_ACCESS, "granting TOKEN_ALL_ACCESS") end
        -- A creator who is not SYSTEM shows both the creator and SYSTEM ACEs.
        token.as_principal(t, vm, { user_sid = token.SID.TEST_USER_2, projected_uid = 1102,
            privs_present = TCB | CREATE, privs_enabled = TCB | CREATE }, function(w)
            local minted = assert(token.mint(w, {}))
            local msd = token.parse_sd(assert(token.get_sd(w, minted)))
            t:assert_eq(msd.owner, token.SID.TEST_USER_2, "owner is the creator's user SID")
            t:assert_eq(token.find_ace(msd.dacl, token.SID.TEST_USER, 0).mask, SELF_RIGHTS, "subject: the adjust set")
            t:assert_eq(token.find_ace(msd.dacl, token.SID.TEST_USER_2, 0).mask, R.ALL_ACCESS, "creator: ALL_ACCESS")
            t:assert_eq(token.find_ace(msd.dacl, token.SID.LOCAL_SYSTEM, 0).mask, R.ALL_ACCESS, "SYSTEM: ALL_ACCESS")
            t:assert_eq(#msd.dacl, 3, "and nothing else")
        end)
        sys.close(vm, fd)
    end)

test("the subject is not granted TOKEN_DUPLICATE, TOKEN_IMPERSONATE or WRITE_DAC on its own token",
    { spec = "PKM *token.rights.default-sd-no-self-escalation" }, function(t)
        token.as_principal(t, vm, {}, function(w)
            for _, want in ipairs({ R.DUPLICATE, R.IMPERSONATE, R.WRITE_DAC, R.ASSIGN_PRIMARY }) do
                local fd, e = token.open_self(w, want)
                t:assert(not fd and e == sys.E.ACCES, string.format("0x%x is refused to the subject: %s", want, sys.errname(e or 0)))
            end
            local ok = assert(token.open_self(w, SELF_RIGHTS))
            t:assert(ok, "the adjustment set is granted")
        end)
    end)

test("when creator and subject coincide the creator ACE is omitted and OWNER RIGHTS suppresses the implicit grant",
    { spec = "PKM *token.rights.default-sd-self-created-owner-rights" }, function(t)
        token.as_principal(t, vm, { privs_present = TCB | CREATE, privs_enabled = TCB | CREATE }, function(w)
            -- TEST_USER mints a token for TEST_USER.
            local minted = assert(token.mint(w, {}))
            local sd = token.parse_sd(assert(token.get_sd(w, minted)))
            t:assert_eq(sd.owner, token.SID.TEST_USER, "owned by the creator, who is also the subject")
            local self_aces = {}
            for _, a in ipairs(sd.dacl) do if a.sid == token.SID.TEST_USER then self_aces[#self_aces + 1] = a end end
            t:assert_eq(#self_aces, 1, "one ACE for the shared SID")
            t:assert_eq(self_aces[1].mask, SELF_RIGHTS, "the limited self set, not the creator's ALL_ACCESS")
            local owner_rights = token.find_ace(sd.dacl, token.SID.OWNER_RIGHTS, 0)
            t:assert(owner_rights, "an OWNER RIGHTS (S-1-3-4) ACE is present")
            t:assert_eq(owner_rights.mask, R.READ_CONTROL, "granting READ_CONTROL only")
            t:assert_eq(owner_rights.flags & access.ACE_FLAG.INHERIT_ONLY, 0, "and not inherit-only")
            -- The consequence: the owner cannot rewrite the DACL.
            local r = token.set_sd(w, minted, access.sd({ dacl = access.acl({
                access.ace(access.ACE.ALLOWED, R.ALL_ACCESS, token.SID.TEST_USER) }) }), kacs.SI.DACL)
            t:assert_eq(r.errno, sys.E.ACCES, "owner-implicit WRITE_DAC is suppressed: EACCES")
            t:assert(token.get_sd(w, minted), "while READ_CONTROL is preserved")
        end)
    end)

test("token-specific rights are checked at open and cached; later descriptor changes do not reach open handles",
    { spec = "PKM *token.rights.check-at-open" }, function(t)
        token.as_principal(t, vm, {}, function(w)
            local h = assert(token.open_self(w, R.QUERY))
            local fd = reach(w)
            t:assert_eq(set_dacl(fd, { access.ace(access.ACE.ALLOWED, R.ALL_ACCESS, token.SID.LOCAL_SYSTEM) }).ret, 0,
                "the subject's grant is removed")
            t:assert(token.query(w, h, token.CLASS.USER), "the open handle still queries from its cached mask")
            local fresh, e = token.open_self(w, R.QUERY)
            t:assert(not fresh and e == sys.E.ACCES, "a fresh open is judged by the new descriptor")
            sys.close(vm, fd)
        end)
    end)

test("the standard rights on a token's own descriptor are re-evaluated live on every call",
    { spec = "PKM *token.rights.standard-rights-live-check" }, function(t)
        token.as_principal(t, vm, {}, function(w)
            local fd = reach(w)
            t:assert_eq(set_dacl(fd, {
                access.ace(access.ACE.ALLOWED, R.QUERY | R.READ_CONTROL, token.SID.TEST_USER),
                access.ace(access.ACE.ALLOWED, R.ALL_ACCESS, token.SID.LOCAL_SYSTEM) }).ret, 0,
                "grant the subject READ_CONTROL")
            local h = assert(token.open_self(w, R.QUERY | R.READ_CONTROL))
            t:assert(token.get_sd(w, h), "the handle reads the descriptor")
            t:assert_eq(set_dacl(fd, {
                access.ace(access.ACE.ALLOWED, R.QUERY, token.SID.TEST_USER),
                access.ace(access.ACE.ALLOWED, R.ALL_ACCESS, token.SID.LOCAL_SYSTEM) }).ret, 0,
                "take READ_CONTROL away again")
            local sd, e = token.get_sd(w, h)
            t:assert(not sd and e == sys.E.ACCES, "the same handle can no longer read it: a live check")
            t:assert(token.query(w, h, token.CLASS.USER), "while its cached TOKEN_QUERY still works")
            sys.close(vm, fd)
        end)
    end)

-- Socket-borne handles --------------------------------------------------------------

local unixsock = require("helpers.unixsock")
local SOL_SOCKET, SCM_RIGHTS = 1, 1

-- A directory the sockets can be bound in: the rootfs is deny-missing,
-- so give it and its root a descriptor everyone can create under.
local SOCKS = "/pit-rights-socks"
sys.mkdir_p(vm, SOCKS)
kacs.set_sd(vm, SOCKS, kacs.grant(kacs.ALL_RIGHTS))
kacs.set_sd(vm, "/", kacs.grant(kacs.ALL_RIGHTS))

--- What a handle can do, by trying: QUERY, DUPLICATE, IMPERSONATE, ADJUST_PRIVS.
local function rights_of(who, fd)
    local out = {}
    out.query = token.query(who, fd, token.CLASS.USER) ~= nil
    -- A downward duplicate, so the level ratchet cannot be what refuses.
    local d, de = token.duplicate(who, fd, { access = R.QUERY, token_type = token.TYPE.IMPERSONATION,
        impersonation_level = token.LEVEL.IDENTIFICATION })
    out.duplicate = d ~= nil or de ~= sys.E.ACCES
    if d then sys.close(who, d) end
    out.adjust = token.disable_priv(who, fd, token.PRIV.LOCK_MEMORY).errno ~= sys.E.ACCES
    return out
end

test("a peer token carries the fixed rights TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE",
    { spec = "PKM *token.rights.peer-token-fixed-rights" }, function(t)
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local srv, acc, cli = assert(unixsock.connected(worker, SOCKS .. "/peer.sock"))
            local peer, e = unixsock.peer_token(worker, acc)
            t:assert(peer, "the server reads the client's peer token: " .. unixsock.errname(e or 0))
            local can = rights_of(worker, peer)
            t:assert(can.query, "TOKEN_QUERY")
            t:assert(can.duplicate, "TOKEN_DUPLICATE")
            t:assert(not can.adjust, "no TOKEN_ADJUST_PRIVILEGES")
            t:assert_eq(token.impersonate(worker, peer).ret, 0, "TOKEN_IMPERSONATE: the server can wear it")
            token.revert(worker)
            sys.close(worker, srv); sys.close(worker, acc); sys.close(worker, cli)
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
    end)

test("a token delivered in KACS_SCM_TOKEN carries the same three rights",
    { spec = "PKM *token.rights.scm-token-fixed-rights" }, function(t)
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local srv, acc, cli = assert(unixsock.connected(worker, SOCKS .. "/scm.sock"))
            local prim = assert(token.mint(worker, {}))
            local imp = assert(token.duplicate(worker, prim, { token_type = token.TYPE.IMPERSONATION,
                impersonation_level = token.LEVEL.IMPERSONATION }))
            local s = unixsock.sendmsg(worker, cli, "hello", { token_fd = imp })
            t:assert_eq(s.ret, 5, "send with a token attached: " .. unixsock.errname(s.errno or 0))
            local r = unixsock.recvmsg(worker, acc, 64)
            t:assert_eq(#r.tokens, 1, "one token cmsg arrives")
            local got = r.tokens[1]
            t:assert_eq(token.query(worker, got, token.CLASS.USER), token.SID.TEST_USER, "it is the sent identity")
            local can = rights_of(worker, got)
            t:assert(can.query and can.duplicate and not can.adjust, "QUERY and DUPLICATE, no adjust")
            t:assert_eq(token.impersonate(worker, got).ret, 0, "TOKEN_IMPERSONATE")
            token.revert(worker)
            sys.close(worker, srv); sys.close(worker, acc); sys.close(worker, cli)
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
    end)

test("a token fd passed over SCM_RIGHTS keeps the mask cached at its open, whoever receives it",
    { spec = "PKM *token.rights.passed-fd-keeps-cached-mask" }, function(t)
        local path = SOCKS .. "/rights.sock"
        local a = vm:spawn_worker()  -- SYSTEM: opens the token and sends it
        local ok, err = pcall(function()
            local srv = assert(unixsock.socket(a, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
            assert(unixsock.bind(a, srv, path).ret == 0); assert(unixsock.listen(a, srv).ret == 0)
            token.as_principal(t, vm, { user_sid = token.SID.TEST_USER_2, projected_uid = 1102 }, function(b)
                local cli = assert(unixsock.socket(b, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
                assert(unixsock.connect(b, cli, path).ret == 0, "connect")
                local acc = assert(unixsock.accept(a, srv))
                -- A's own token, opened QUERY-only. Its descriptor grants B nothing.
                local qfd = assert(token.open_self(a, R.QUERY))
                local control = string.pack("<I8I4I4i4", 16 + 4, SOL_SOCKET, SCM_RIGHTS, qfd) .. "\0\0\0\0"
                local s = unixsock.sendmsg(a, acc, "x", { raw_control = control })
                t:assert_eq(s.ret, 1, "A passes the fd: " .. unixsock.errname(s.errno or 0))
                local r = unixsock.recvmsg(b, cli, 8, { cmsg = unixsock.cmsg_space(4) })
                local rights_cmsg
                for _, c in ipairs(r.cmsgs) do if c.level == SOL_SOCKET and c.type == SCM_RIGHTS then rights_cmsg = c end end
                t:assert(rights_cmsg, "B receives an SCM_RIGHTS cmsg")
                local recv_fd = string.unpack("<i4", rights_cmsg.data)
                t:assert_eq(token.sid_string(assert(token.query(b, recv_fd, token.CLASS.USER))), "S-1-5-18",
                    "B, whom the descriptor grants nothing, queries SYSTEM's token through the cached TOKEN_QUERY")
                local d, de = token.duplicate(b, recv_fd, { access = R.QUERY })
                t:assert(not d and de == sys.E.ACCES, "but not beyond the mask cached at A's open: no TOKEN_DUPLICATE")
                local fresh, fe = token.open_self(b, R.QUERY)
                t:assert(fresh, "B's own token opens on its own descriptor: " .. sys.errname(fe or 0))
                sys.close(a, acc)
            end)
            sys.close(a, srv)
        end)
        a:kill(); a:join()
        if not ok then error(err, 0) end
    end)
