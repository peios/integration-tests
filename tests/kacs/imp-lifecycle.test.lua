-- PKM §3.5.3 — the impersonation lifecycle: what a connect captures on
-- each end, restamping a listener, Anonymous, double impersonation,
-- reverting, how MIC and PIP read the result, and which transports
-- carry an identity register at all.
--
-- The per-message half of §3.5.3 — the conveyed-identity register,
-- KACS_SO_PASS_TOKEN and KACS_SCM_TOKEN — is in
-- imp-permessage.test.lua.
--
-- Sockets are pathname sockets: an abstract bind installs a socket
-- descriptor (§3.12) whose default DACL admits only the binder,
-- Administrators and SYSTEM, which would decide a cross-principal
-- connect before the identity question is reached.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local access = require("helpers.access")
local us = require("helpers.unixsock")

local vm = provium:vm("v", "kernel-only"):boot()

local P = token.PRIV
local L = token.LEVEL
local MINTER = token.bit(P.TCB) | token.bit(P.CREATE_TOKEN)
local IMPERSONATE = token.bit(P.IMPERSONATE)
local LABEL_INFO = 0x10

local SOCKS = "/imp-life"
sys.mkdir_p(vm, SOCKS)
kacs.set_sd(vm, SOCKS, kacs.grant(kacs.ALL_RIGHTS))
kacs.set_sd(vm, "/", kacs.grant(kacs.ALL_RIGHTS))

local next_name = 0
local function sock_path()
    next_name = next_name + 1
    return SOCKS .. "/s" .. next_name
end

--- A listening socket at `path` in `who`.
local function listener(t, who, path, stype)
    local fd = assert(us.socket(who, us.AF_UNIX, stype))
    t:assert_eq(us.bind(who, fd, path).ret, 0, "bind " .. path)
    t:assert_eq(us.listen(who, fd).ret, 0, "listen")
    return fd
end

--- Connect to `path` from `who`, optionally at `level`. Returns the
--- connecting fd.
local function connect(t, who, path, level, stype)
    local fd = assert(us.socket(who, us.AF_UNIX, stype))
    if level then t:assert_eq(us.set_level(who, fd, level).ret, 0, "set level") end
    t:assert_eq(us.connect(who, fd, path).ret, 0, "connect " .. path)
    return fd
end

local function level_of(who, fd) return token.query_u32(who, fd, token.CLASS.IMPERSONATION_LEVEL) end
local function user_of(who, fd) return token.query(who, fd, token.CLASS.USER) end

-- The sequence -----------------------------------------------------------------

test("the impersonation level may be changed at any time and bounds every later capture",
    { spec = "PKM *imp.capture.level-changeable-bounds-later-captures" }, function(t)
        local path = sock_path()
        local srv = listener(t, vm, path)
        local cli = assert(us.socket(vm))
        t:assert_eq(us.set_level(vm, cli, L.DELEGATION).ret, 0, "the client asks for Delegation")
        t:assert_eq(us.set_pass_token(vm, cli, true).ret, 0, "and conveys on every send")
        t:assert_eq(us.connect(vm, cli, path).ret, 0, "connect")
        local acc = assert(us.accept(vm, srv))
        local first = assert(us.peer_token(vm, acc))
        t:assert_eq(level_of(vm, first), L.DELEGATION, "the connect capture is at Delegation")

        -- Change it after the fact.
        t:assert_eq(us.set_level(vm, cli, L.IDENTIFICATION).ret, 0, "the level is lowered")
        t:assert_eq(us.level(vm, cli), L.IDENTIFICATION, "and reads back lowered")
        t:assert_eq(us.sendmsg(vm, cli, "after").ret, 5, "a send after the change")
        local got = us.recvmsg(vm, acc, 16)
        t:assert_eq(#got.tokens, 1, "conveys a fresh identity")
        t:assert_eq(level_of(vm, got.tokens[1]), L.IDENTIFICATION,
            "bounded by the new level")
        t:assert_eq(level_of(vm, first), L.DELEGATION,
            "and the capture already made is not rewritten")
        sys.close(vm, first); sys.close(vm, got.tokens[1])
        sys.close(vm, srv); sys.close(vm, acc); sys.close(vm, cli)
    end)

test("the connecting end learns the identity the listener captured at listen()",
    { spec = "PKM *imp.capture.listener-identity-to-connecting-end" }, function(t)
        local server = vm:spawn_worker()
        local client = vm:spawn_worker()
        local ok, err = pcall(function()
            assert(token.install(server, assert(token.mint(server,
                { user_sid = token.SID.TEST_USER }))).ret == 0)
            assert(token.install(client, assert(token.mint(client,
                { user_sid = token.SID.TEST_USER_2 }))).ret == 0)
            local path = sock_path()
            local srv = listener(t, server, path)
            local cli = connect(t, client, path)
            local peer, e = us.peer_token(client, cli)
            t:assert(peer, "the client reads KACS_SO_PEER_TOKEN on its own socket: "
                .. us.errname(e or 0))
            t:assert_eq(user_of(client, peer), token.SID.TEST_USER,
                "and sees who it reached")
            t:assert_eq(level_of(client, peer), L.IDENTIFICATION,
                "at Identification, the default for a listener that set no level")
            sys.close(client, peer); sys.close(client, cli); sys.close(server, srv)

            -- A listener that does set its own level conveys at that level.
            local path2 = sock_path()
            local srv2 = assert(us.socket(server))
            t:assert_eq(us.set_level(server, srv2, L.IMPERSONATION).ret, 0,
                "the listener chooses Impersonation")
            t:assert_eq(us.bind(server, srv2, path2).ret, 0, "bind")
            t:assert_eq(us.listen(server, srv2).ret, 0, "listen")
            local cli2 = connect(t, client, path2)
            local peer2 = assert(us.peer_token(client, cli2))
            t:assert_eq(level_of(client, peer2), L.IMPERSONATION, "and the client sees that")
            sys.close(client, peer2); sys.close(client, cli2); sys.close(server, srv2)
        end)
        server:kill(); server:join(); client:kill(); client:join()
        if not ok then error(err, 0) end
    end)

test("KACS_SO_RESTAMP works only on a listening socket",
    { spec = "PKM *imp.restamp.listening-socket-only" }, function(t)
        local fresh = assert(us.socket(vm))
        local r = us.restamp(vm, fresh)
        t:assert(r.ret ~= 0, "an unbound socket is not listening")
        t:assert_eq(r.errno, sys.E.INVAL, "EINVAL")
        local path = sock_path()
        t:assert_eq(us.bind(vm, fresh, path).ret, 0, "bind")
        r = us.restamp(vm, fresh)
        t:assert(r.ret ~= 0, "a bound but not listening socket is refused too")
        t:assert_eq(r.errno, sys.E.INVAL, "EINVAL")
        t:assert_eq(us.listen(vm, fresh).ret, 0, "listen")
        t:assert_eq(us.restamp(vm, fresh).ret, 0, "and a listening one is restamped")
        -- A connected end is not a listening socket either.
        local cli = connect(t, vm, path)
        local acc = assert(us.accept(vm, fresh))
        t:assert_eq(us.restamp(vm, acc).errno, sys.E.INVAL, "nor is an accepted end")
        t:assert_eq(us.restamp(vm, cli).errno, sys.E.INVAL, "nor a connected one")
        sys.close(vm, fresh); sys.close(vm, cli); sys.close(vm, acc)
    end)

test("a restamp is not retroactive: clients that connected before it see the previous holder",
    { spec = "PKM *imp.restamp.not-retroactive" }, function(t)
        token.as_principal(t, vm, { privs_present = MINTER | IMPERSONATE,
            privs_enabled = MINTER | IMPERSONATE }, function(w)
            local path = sock_path()
            local srv = listener(t, w, path)
            -- One client connects before the restamp.
            local early = connect(t, w, path)
            local early_peer = assert(us.peer_token(w, early))
            t:assert_eq(user_of(w, early_peer), token.SID.TEST_USER,
                "the early client sees who was listening")
            -- The listener is handed on: a new holder stamps itself.
            local successor = assert(token.mint(w, { user_sid = token.SID.TEST_USER_2,
                token_type = token.TYPE.IMPERSONATION, impersonation_level = L.IMPERSONATION }))
            t:assert_eq(token.impersonate(w, successor).ret, 0, "the successor takes over")
            t:assert_eq(us.restamp(w, srv).ret, 0, "and restamps the listener")
            token.revert(w)
            local late = connect(t, w, path)
            local late_peer = assert(us.peer_token(w, late))
            t:assert_eq(user_of(w, late_peer), token.SID.TEST_USER_2,
                "a client connecting after sees the new holder")
            t:assert_eq(user_of(w, early_peer), token.SID.TEST_USER,
                "and the earlier client's capture is untouched — that is who was listening")
            sys.close(w, early_peer); sys.close(w, late_peer)
            sys.close(w, srv); sys.close(w, early); sys.close(w, late); sys.close(w, successor)
        end)
    end)

test("an Anonymous capture never records the client's real identity",
    { spec = "PKM *imp.capture.anonymous-records-no-real-identity" }, function(t)
        token.as_principal(t, vm, { user_sid = token.SID.TEST_USER,
            privs_present = MINTER, privs_enabled = MINTER }, function(w)
            local path = sock_path()
            local srv = listener(t, w, path)
            local cli = connect(t, w, path, L.ANONYMOUS)
            local acc = assert(us.accept(w, srv))
            local peer = assert(us.peer_token(w, acc))
            t:assert_eq(user_of(w, peer), token.SID.ANONYMOUS, "the stored user SID is S-1-5-7")
            local groups = assert(token.groups(w, peer))
            for _, g in ipairs(groups) do
                t:assert_neq(g.sid, token.SID.TEST_USER,
                    "the caller's own SID appears nowhere in the stored token")
            end
            t:assert(token.find_group(groups, token.SID.EVERYONE), "Everyone is carried")
            t:assert(not token.find_group(groups, token.SID.AUTHENTICATED_USERS),
                "Authenticated Users is not")
            sys.close(w, peer); sys.close(w, srv); sys.close(w, acc); sys.close(w, cli)
        end)
    end)

test("at Impersonation the thread's effective token is what is stored",
    { spec = "PKM *imp.capture.stores-effective-token" }, function(t)
        token.as_principal(t, vm, { privs_present = MINTER | IMPERSONATE,
            privs_enabled = MINTER | IMPERSONATE }, function(w)
            local path = sock_path()
            local srv = listener(t, w, path)
            -- Not impersonating: the primary is the effective token.
            local plain = connect(t, w, path)
            local acc1 = assert(us.accept(w, srv))
            local peer1 = assert(us.peer_token(w, acc1))
            t:assert_eq(user_of(w, peer1), token.SID.TEST_USER, "the process's own identity")
            -- Impersonating: the impersonated identity is what flows.
            local client = assert(token.mint(w, { user_sid = token.SID.TEST_USER_2,
                token_type = token.TYPE.IMPERSONATION, impersonation_level = L.IMPERSONATION }))
            t:assert_eq(token.impersonate(w, client).ret, 0, "the thread impersonates a client")
            local under = connect(t, w, path)
            local acc2 = assert(us.accept(w, srv))
            local peer2 = assert(us.peer_token(w, acc2))
            t:assert_eq(user_of(w, peer2), token.SID.TEST_USER_2,
                "the impersonated identity is what is stored, not the primary")
            token.revert(w)
            for _, fd in ipairs({ peer1, peer2, srv, acc1, acc2, plain, under, client }) do
                sys.close(w, fd)
            end
        end)
    end)

test("the peer-token fd carries TOKEN_QUERY, TOKEN_IMPERSONATE and TOKEN_DUPLICATE",
    { spec = "PKM *imp.peer-token.fd-access-mask" }, function(t)
        local path = sock_path()
        local srv = listener(t, vm, path)
        local cli = connect(t, vm, path)
        local acc = assert(us.accept(vm, srv))
        local peer = assert(us.peer_token(vm, acc))
        t:assert(token.query(vm, peer, token.CLASS.USER), "TOKEN_QUERY: the classes read")
        local dup, de = token.duplicate(vm, peer, { access = token.RIGHT.QUERY,
            token_type = token.TYPE.IMPERSONATION, impersonation_level = L.IMPERSONATION })
        t:assert(dup, "TOKEN_DUPLICATE: the handle duplicates: " .. sys.errname(de or 0))
        sys.close(vm, dup)
        -- TOKEN_IMPERSONATE: proved in a worker, since installing an
        -- impersonation token on the agent's own connection is not safe.
        token.as_principal(t, vm, {}, function(w)
            local wpath = sock_path()
            local wsrv = listener(t, w, wpath)
            local wcli = connect(t, w, wpath)
            local wacc = assert(us.accept(w, wsrv))
            local wpeer = assert(us.peer_token(w, wacc))
            t:assert_eq(token.impersonate(w, wpeer).ret, 0, "TOKEN_IMPERSONATE: the fd installs")
            token.revert(w)
            sys.close(w, wpeer); sys.close(w, wsrv); sys.close(w, wcli); sys.close(w, wacc)
        end)
        -- And nothing beyond those three: the adjust rights are absent.
        local adjusted = token.adjust_privs(vm, peer, { { P.TCB, 0 } })
        t:assert(adjusted.ret ~= 0, "TOKEN_ADJUST_PRIVS is not in the mask")
        t:assert_eq(adjusted.errno, sys.E.ACCES, "EACCES")
        local groups = token.adjust_groups(vm, peer, { { 0, 0 } })
        t:assert(groups.ret ~= 0, "and neither is TOKEN_ADJUST_GROUPS: "
            .. sys.errname(groups.errno))
        sys.close(vm, peer); sys.close(vm, srv); sys.close(vm, cli); sys.close(vm, acc)
    end)

test("kacs_revert restores the thread's credential to its real one",
    { spec = "PKM *imp.revert.restores-real-cred" }, function(t)
        token.as_principal(t, vm, { privs_present = MINTER | IMPERSONATE,
            privs_enabled = MINTER | IMPERSONATE }, function(w)
            local before = assert(token.effective(vm, w))
            t:assert_eq(before.type, token.TYPE.PRIMARY, "the thread starts on its primary token")
            local client = assert(token.mint(w, { user_sid = token.SID.TEST_USER_2,
                token_type = token.TYPE.IMPERSONATION, impersonation_level = L.IMPERSONATION }))
            t:assert_eq(token.impersonate(w, client).ret, 0, "it impersonates")
            local during = assert(token.effective(vm, w))
            t:assert_eq(during.user, token.SID.TEST_USER_2, "and is the client for a while")
            t:assert_eq(token.revert(w).ret, 0, "kacs_revert succeeds")
            local after = assert(token.effective(vm, w))
            t:assert_eq(after.type, token.TYPE.PRIMARY, "the credential is the real one again")
            t:assert_eq(after.user, token.SID.TEST_USER, "with the service identity back")
            t:assert_eq(after.level, before.level, "at the primary's own level")
            sys.close(w, client)
        end)
    end)

-- Anonymous ---------------------------------------------------------------------

test("any thread may impersonate Anonymous without passing either gate",
    { spec = "PKM *imp.anonymous.no-gates" }, function(t)
        -- A server that would fail both gates outright: restricted, Low
        -- integrity, no privileges. Against an unrestricted token of its
        -- own user the identity gate hard-denies (§3.5.2); at Anonymous
        -- level the same token is accepted.
        local RESTRICTION = { { sid = token.SID.TEST_GROUP_2, attributes = 0 } }
        token.as_principal(t, vm, { privs_present = MINTER, privs_enabled = MINTER,
            integrity_level = token.INTEGRITY.LOW, restricted_sids = RESTRICTION }, function(w)
            local hard = assert(token.mint(w, { user_sid = token.SID.TEST_USER,
                integrity_level = token.INTEGRITY.HIGH,
                token_type = token.TYPE.IMPERSONATION, impersonation_level = L.IMPERSONATION }))
            local denied = token.impersonate(w, hard)
            t:assert(denied.ret ~= 0, "at Impersonation the gates deny it outright")
            t:assert_eq(denied.errno, sys.E.PERM, "EPERM")
            local anon = assert(token.mint(w, { user_sid = token.SID.TEST_USER,
                integrity_level = token.INTEGRITY.HIGH,
                token_type = token.TYPE.IMPERSONATION, impersonation_level = L.ANONYMOUS }))
            t:assert_eq(token.impersonate(w, anon).ret, 0,
                "the same shape at Anonymous level passes with no gate at all")
            t:assert_eq(assert(token.effective(vm, w)).level, L.ANONYMOUS, "at Anonymous")
            token.revert(w)
            sys.close(w, hard); sys.close(w, anon)
        end)
    end)

test("the socket path builds Anonymous as a minimal shape rather than preserving anything",
    { spec = "PKM *imp.anonymous.socket-constructs-minimal-shape" }, function(t)
        -- The caller is SYSTEM: every privilege, System integrity, a rich
        -- group list. None of it survives.
        local path = sock_path()
        local srv = listener(t, vm, path)
        local cli = connect(t, vm, path, L.ANONYMOUS)
        local acc = assert(us.accept(vm, srv))
        local peer = assert(us.peer_token(vm, acc))
        t:assert_eq(user_of(vm, peer), token.SID.ANONYMOUS, "the Anonymous SID is the user SID")
        local privs = assert(token.privileges(vm, peer))
        t:assert_eq(privs.present, 0, "no privileges are present")
        t:assert_eq(privs.enabled, 0, "none enabled")
        t:assert_eq(token.integrity(vm, peer), token.INTEGRITY.UNTRUSTED, "Untrusted integrity")
        sys.close(vm, peer); sys.close(vm, srv); sys.close(vm, cli); sys.close(vm, acc)
    end)

-- Double impersonation ------------------------------------------------------------

test("impersonating while already impersonating reverts internally and re-impersonates",
    { spec = "PKM *imp.double.revert-then-reimpersonate" }, function(t)
        token.as_principal(t, vm, { privs_present = MINTER | IMPERSONATE,
            privs_enabled = MINTER | IMPERSONATE }, function(w)
            local a = assert(token.mint(w, { user_sid = token.SID.TEST_USER_2,
                token_type = token.TYPE.IMPERSONATION, impersonation_level = L.IMPERSONATION }))
            local b = assert(token.mint(w, { user_sid = token.sid(5, 21, 1000, 2000, 3000, 1109),
                token_type = token.TYPE.IMPERSONATION, impersonation_level = L.IMPERSONATION }))
            t:assert_eq(token.impersonate(w, a).ret, 0, "the thread impersonates A")
            t:assert_eq(assert(token.effective(vm, w)).user, token.SID.TEST_USER_2, "and is A")
            t:assert_eq(token.impersonate(w, b).ret, 0,
                "installing B while impersonating A succeeds rather than erroring")
            t:assert_eq(assert(token.effective(vm, w)).user,
                token.sid(5, 21, 1000, 2000, 3000, 1109), "and the thread is now B")
            -- One revert lands on the primary, not back on A: the kernel
            -- reverted internally before re-impersonating.
            t:assert_eq(token.revert(w).ret, 0, "a single revert")
            local after = assert(token.effective(vm, w))
            t:assert_eq(after.type, token.TYPE.PRIMARY, "lands on the real credential")
            t:assert_eq(after.user, token.SID.TEST_USER, "the service's own identity")
            sys.close(w, a); sys.close(w, b)
        end)
    end)

-- MIC and PIP ---------------------------------------------------------------------

test("MIC evaluates the effective token's integrity level",
    { spec = "PKM *imp.mic.reads-effective-token" }, function(t)
        -- An object labelled Medium with NO_WRITE_UP, open to Everyone.
        local path = SOCKS .. "/labelled"
        vm:write_file(path, "x")
        kacs.set_sd(vm, path, kacs.grant(kacs.ALL_RIGHTS))
        local label = access.sd({ sacl = access.acl({
            access.label_ace(token.INTEGRITY.MEDIUM, access.LABEL.NO_WRITE_UP) }) })
        t:assert_eq(kacs.set_sd(vm, path, label, LABEL_INFO).ret, 0, "the label is written")
        token.as_principal(t, vm, { privs_present = MINTER, privs_enabled = MINTER,
            integrity_level = token.INTEGRITY.HIGH }, function(w)
            local fd, errno = sys.open(w, path, sys.O.WRONLY)
            t:assert(fd, "a High-integrity server writes to a Medium object: "
                .. sys.errname(errno or 0))
            sys.close(w, fd)
            -- Impersonating a Low client of the same user: MIC now reads
            -- Low, and NO_WRITE_UP strips write access.
            local low = assert(token.mint(w, { user_sid = token.SID.TEST_USER,
                integrity_level = token.INTEGRITY.LOW,
                token_type = token.TYPE.IMPERSONATION, impersonation_level = L.IMPERSONATION }))
            t:assert_eq(token.impersonate(w, low).ret, 0, "it impersonates the Low client")
            t:assert_eq(assert(token.effective(vm, w)).level, L.IMPERSONATION,
                "at Impersonation — the ceiling permits assuming a lower label")
            local got, e2 = sys.open(w, path, sys.O.WRONLY)
            t:assert(not got, "and the same write is refused: " .. sys.errname(e2 or 0))
            t:assert_eq(e2, sys.E.ACCES, "EACCES")
            local readable = sys.open(w, path, sys.O.RDONLY)
            t:assert(readable, "while reading up is still permitted")
            sys.close(w, readable)
            token.revert(w)
            local again = sys.open(w, path, sys.O.WRONLY)
            t:assert(again, "and the server's own integrity returns with the revert")
            sys.close(w, again); sys.close(w, low)
        end)
    end)

test("PIP reads the PSB rather than the effective token",
    { spec = "PKM *imp.pip.reads-psb-not-effective-token",
      covered_by = "kunit:pkm_kunit_process",
      skip = "pip_type and pip_trust are set by signature verification at exec " ..
             "and carried on the PSB, which a guest cannot author; runs under " ..
             "pkm_kunit_process_boundary_under_impersonation_uses_psb_pip and " ..
             "pkm_kunit_access_check_psb_pip_unchanged_by_impersonation" },
    function(t) end)

-- Supported transports ----------------------------------------------------------

test("peer-token capture works on SOCK_STREAM and on SOCK_SEQPACKET",
    { spec = "PKM *imp.transport.stream-and-seqpacket" }, function(t)
        for _, stype in ipairs({ us.SOCK.STREAM, us.SOCK.SEQPACKET }) do
            local path = sock_path()
            local srv = listener(t, vm, path, stype)
            local cli = connect(t, vm, path, nil, stype)
            local acc = assert(us.accept(vm, srv))
            local peer, e = us.peer_token(vm, acc)
            t:assert(peer, "type " .. stype .. " captures at connect: " .. us.errname(e or 0))
            t:assert_eq(user_of(vm, peer), token.SID.LOCAL_SYSTEM, "carrying the client's identity")
            t:assert_eq(level_of(vm, peer), L.IMPERSONATION, "at the socket's level")
            -- The same lifecycle: read, impersonate, revert.
            t:assert(token.duplicate(vm, peer, { access = token.RIGHT.QUERY,
                token_type = token.TYPE.IMPERSONATION, impersonation_level = L.IMPERSONATION }),
                "and the token behaves the same on both")
            sys.close(vm, peer); sys.close(vm, srv); sys.close(vm, cli); sys.close(vm, acc)
        end
    end)

test("a SOCK_DGRAM socket carries no conveyed-identity register",
    { spec = "PKM *imp.dgram.no-register" }, function(t)
        local path = sock_path()
        local rx = assert(us.socket(vm, us.AF_UNIX, us.SOCK.DGRAM))
        t:assert_eq(us.bind(vm, rx, path).ret, 0, "bind the receiving end")
        local tx = assert(us.socket(vm, us.AF_UNIX, us.SOCK.DGRAM))
        t:assert_eq(us.set_pass_token(vm, tx, true).ret, 0, "the sender conveys identity")
        local _, errno = us.peer_token(vm, rx)
        t:assert_eq(errno, sys.E.OPNOTSUPP, "the register option is EOPNOTSUPP on a datagram socket")
        -- Every datagram that carries a token delivers it, because there
        -- is no register to compare it against and none is retained.
        for i = 1, 3 do
            t:assert_eq(us.sendto(vm, tx, "d" .. i, path).ret, 2, "datagram " .. i)
        end
        for i = 1, 3 do
            local got = us.recvmsg(vm, rx, 16)
            t:assert_eq(got.data, "d" .. i, "datagram " .. i .. " arrives")
            t:assert_eq(#got.tokens, 1,
                "and carries its own token, even though the identity never changed")
            sys.close(vm, got.tokens[1])
        end
        local _, again = us.peer_token(vm, rx)
        t:assert_eq(again, sys.E.OPNOTSUPP, "and nothing was retained")
        sys.close(vm, rx); sys.close(vm, tx)
    end)

test("SOCK_DGRAM supports per-message identity only, bounded by the socket's level",
    { spec = "PKM *imp.dgram.per-message-identity-only" }, function(t)
        local path = sock_path()
        local rx = assert(us.socket(vm, us.AF_UNIX, us.SOCK.DGRAM))
        t:assert_eq(us.bind(vm, rx, path).ret, 0, "bind")
        local tx = assert(us.socket(vm, us.AF_UNIX, us.SOCK.DGRAM))
        t:assert_eq(us.level(vm, tx), L.IMPERSONATION, "the level option works on a datagram socket")
        t:assert_eq(us.set_level(vm, tx, L.IDENTIFICATION).ret, 0, "and can be set")
        t:assert_eq(us.set_pass_token(vm, tx, true).ret, 0, "KACS_SO_PASS_TOKEN works too")
        t:assert_eq(us.sendto(vm, tx, "auto", path).ret, 4, "a datagram is sent")
        local got = us.recvmsg(vm, rx, 16)
        t:assert_eq(#got.tokens, 1, "carrying an identity")
        t:assert_eq(level_of(vm, got.tokens[1]), L.IDENTIFICATION,
            "bounded by KACS_SO_IMPERSONATION_LEVEL as on any socket")
        sys.close(vm, got.tokens[1])
        -- An explicit KACS_SCM_TOKEN attach works on a datagram too.
        t:assert_eq(us.set_pass_token(vm, tx, false).ret, 0, "turn the automatic path off")
        local explicit = assert(token.mint(vm, { user_sid = token.SID.TEST_USER_2,
            token_type = token.TYPE.IMPERSONATION, impersonation_level = L.IDENTIFICATION }))
        local sent = us.sendmsg(vm, tx, "expl", { token_fd = explicit, to = path })
        t:assert_eq(sent.ret, 4, "an explicit attach sends: " .. sys.errname(sent.errno))
        local explicit_got = us.recvmsg(vm, rx, 16)
        t:assert_eq(#explicit_got.tokens, 1, "and is delivered with the datagram")
        t:assert_eq(user_of(vm, explicit_got.tokens[1]), token.SID.TEST_USER_2,
            "carrying the attached identity")
        sys.close(vm, explicit_got.tokens[1]); sys.close(vm, explicit)
        sys.close(vm, rx); sys.close(vm, tx)
    end)

-- Where the register does not apply -----------------------------------------------

test("KACS_SO_PEER_TOKEN is EOPNOTSUPP on a datagram socket and on any non-Unix family",
    { spec = "PKM *imp.peer-token.eopnotsupp-non-unix" }, function(t)
        local dgram = assert(us.socket(vm, us.AF_UNIX, us.SOCK.DGRAM))
        local _, e1 = us.peer_token(vm, dgram)
        t:assert_eq(e1, sys.E.OPNOTSUPP, "EOPNOTSUPP on AF_UNIX SOCK_DGRAM")
        local inet = assert(us.socket(vm, us.AF_INET, us.SOCK.STREAM))
        local _, e2 = us.peer_token(vm, inet)
        t:assert_eq(e2, sys.E.OPNOTSUPP, "EOPNOTSUPP on AF_INET")
        sys.close(vm, dgram); sys.close(vm, inet)
    end)

test("a socketpair end starts with an empty register and reports ENODATA",
    { spec = "PKM *imp.peer-token.socketpair-enodata" }, function(t)
        local a, b = us.socketpair(vm)
        t:assert(a, "socketpair: " .. us.errname(b or 0))
        local _, errno = us.peer_token(vm, a)
        t:assert_eq(errno, sys.E.NODATA, "ENODATA: connected, but nothing was ever captured")
        local _, errno2 = us.peer_token(vm, b)
        t:assert_eq(errno2, sys.E.NODATA, "on both ends")
        -- Once the peer conveys an identity, the register works as usual.
        t:assert_eq(us.set_pass_token(vm, b, true).ret, 0, "the peer turns on KACS_SO_PASS_TOKEN")
        t:assert_eq(us.sendmsg(vm, b, "hi").ret, 2, "and sends")
        local got = us.recvmsg(vm, a, 8)
        t:assert_eq(got.data, "hi", "the read arrives")
        local peer, pe = us.peer_token(vm, a)
        t:assert(peer, "after which the register answers: " .. us.errname(pe or 0))
        t:assert_eq(user_of(vm, peer), token.SID.LOCAL_SYSTEM, "with the sender's identity")
        sys.close(vm, peer)
        if got.tokens[1] then sys.close(vm, got.tokens[1]) end
        sys.close(vm, a); sys.close(vm, b)
    end)

test("a socket that is not yet connected reports ENOTCONN",
    { spec = "PKM *imp.peer-token.enotconn" }, function(t)
        local fresh = assert(us.socket(vm))
        local _, e1 = us.peer_token(vm, fresh)
        t:assert_eq(e1, us.E.NOTCONN, "ENOTCONN on a fresh socket")
        local path = sock_path()
        t:assert_eq(us.bind(vm, fresh, path).ret, 0, "bind")
        local _, e2 = us.peer_token(vm, fresh)
        t:assert_eq(e2, us.E.NOTCONN, "still ENOTCONN once bound")
        t:assert_eq(us.listen(vm, fresh).ret, 0, "listen")
        local _, e3 = us.peer_token(vm, fresh)
        t:assert_eq(e3, us.E.NOTCONN, "and on a listening socket, which is not a connection")
        sys.close(vm, fresh)
    end)

test("a pipe is not a socket, so getsockopt fails before KACS is reached",
    { spec = "PKM *imp.peer-token.enotsock-pipes" }, function(t)
        local rd, wr = sys.pipe(vm)
        t:assert(rd, "pipe2: " .. sys.errname(wr or 0))
        local _, e1 = us.peer_token(vm, rd)
        t:assert_eq(e1, us.E.NOTSOCK, "ENOTSOCK on the read end")
        local _, e2 = us.peer_token(vm, wr)
        t:assert_eq(e2, us.E.NOTSOCK, "and on the write end")
        -- A FIFO is the same story.
        local fifo = SOCKS .. "/fifo"
        t:assert_eq(sys.mknod(vm, fifo, sys.S_IFIFO | tonumber("666", 8)).ret, 0, "mkfifo")
        local fd = assert(sys.open(vm, fifo, sys.O.RDONLY | 0x800))  -- O_NONBLOCK
        local _, e3 = us.peer_token(vm, fd)
        t:assert_eq(e3, us.E.NOTSOCK, "and on a FIFO")
        sys.close(vm, rd); sys.close(vm, wr); sys.close(vm, fd)
    end)

test("KACS_IOC_IMPERSONATE works on a token fd however it was obtained",
    { spec = "PKM *imp.impersonate.any-token-fd" }, function(t)
        token.as_principal(t, vm, { privs_present = MINTER, privs_enabled = MINTER }, function(w)
            -- 1. A token fd from CreateToken.
            local minted = assert(token.mint(w, { user_sid = token.SID.TEST_USER,
                token_type = token.TYPE.IMPERSONATION, impersonation_level = L.IMPERSONATION }))
            t:assert_eq(token.impersonate(w, minted).ret, 0, "a minted fd impersonates")
            token.revert(w)
            -- 2. A token fd from KACS_SO_PEER_TOKEN.
            local path = sock_path()
            local srv = listener(t, w, path)
            local cli = connect(t, w, path)
            local acc = assert(us.accept(w, srv))
            local peer = assert(us.peer_token(w, acc))
            t:assert_eq(token.impersonate(w, peer).ret, 0, "so does a peer-token fd")
            token.revert(w)
            -- 3. A token fd carried across an SCM_RIGHTS transfer.
            local SOL_SOCKET, SCM_RIGHTS = 1, 1
            local control = string.pack("<I8I4I4i4", 20, SOL_SOCKET, SCM_RIGHTS, minted)
                .. "\0\0\0\0"
            t:assert_eq(us.sendmsg(w, cli, "fd", { raw_control = control }).ret, 2,
                "the fd is passed over the connection")
            local got = us.recvmsg(w, acc, 8, { cmsg = us.cmsg_space(4) })
            local passed
            for _, c in ipairs(got.cmsgs) do
                if c.level == SOL_SOCKET and c.type == SCM_RIGHTS then
                    passed = string.unpack("<i4", c.data)
                end
            end
            t:assert(passed, "and arrives as a descriptor")
            t:assert_eq(token.impersonate(w, passed).ret, 0,
                "which impersonates like any other token fd")
            t:assert_eq(assert(token.effective(vm, w)).user, token.SID.TEST_USER,
                "carrying the identity it was minted with")
            token.revert(w)
            for _, fd in ipairs({ minted, peer, passed, srv, cli, acc }) do sys.close(w, fd) end
        end)
    end)
