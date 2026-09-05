-- PKM §3.5.1 — the four impersonation levels and the ratchet that binds
-- them: what each level permits, where the level is set, and the fact
-- that every path a token can travel copies or lowers it and none
-- raises it.
--
-- The level lives on the token and on the socket, so the cases here mix
-- both surfaces: a client sets `KACS_SO_IMPERSONATION_LEVEL` before
-- connecting, the capture takes the lower of that and the token's own,
-- and what comes back through `KACS_SO_PEER_TOKEN` is what the server
-- may act at.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local access = require("helpers.access")
local us = require("helpers.unixsock")

local vm = provium:vm("v", "kernel-only"):boot()

local P = token.PRIV
local L = token.LEVEL
local MINTER = token.bit(P.TCB) | token.bit(P.CREATE_TOKEN)
-- A minted principal's own token descriptor grants it TOKEN_QUERY and
-- the adjust rights and nothing else (§3.2.8), so every derivation a
-- worker makes asks for exactly the rights it reads back with.
local QUERY_ONLY = token.RIGHT.QUERY

-- Pathname sockets, so the abstract namespace's socket descriptor
-- (§3.12) is not what decides a cross-principal connect. The guest root
-- is opened for the same reason the privilege files open it: a minted
-- principal holds no SeChangeNotifyPrivilege and would otherwise fail
-- the walk rather than the case.
local SOCKS = "/imp-levels"
sys.mkdir_p(vm, SOCKS)
kacs.set_sd(vm, SOCKS, kacs.grant(kacs.ALL_RIGHTS))
kacs.set_sd(vm, "/", kacs.grant(kacs.ALL_RIGHTS))

local next_name = 0
local function sock_path()
    next_name = next_name + 1
    return SOCKS .. "/s" .. next_name
end

--- Connect one end to another inside `who`, with `level` set on the
--- connecting socket beforehand. Returns the accepted end's peer token
--- fd plus the three sockets.
local function capture(t, who, level, stype)
    local path = sock_path()
    local srv = assert(us.socket(who, us.AF_UNIX, stype))
    t:assert_eq(us.bind(who, srv, path).ret, 0, "bind " .. path)
    t:assert_eq(us.listen(who, srv).ret, 0, "listen")
    local cli = assert(us.socket(who, us.AF_UNIX, stype))
    if level then
        t:assert_eq(us.set_level(who, cli, level).ret, 0, "the client sets its level")
    end
    t:assert_eq(us.connect(who, cli, path).ret, 0, "connect")
    local acc, e = us.accept(who, srv)
    t:assert(acc, "accept: " .. us.errname(e or 0))
    local peer, pe = us.peer_token(who, acc)
    t:assert(peer, "KACS_SO_PEER_TOKEN: " .. us.errname(pe or 0))
    return peer, srv, acc, cli
end

local function level_of(who, fd) return token.query_u32(who, fd, token.CLASS.IMPERSONATION_LEVEL) end

-- The four levels ------------------------------------------------------------

test("an Anonymous connection conveys no identity at all",
    { spec = "PKM *imp.anonymous.no-identity-conveyed" }, function(t)
        local peer = capture(t, vm, L.ANONYMOUS)
        t:assert_eq(token.query(vm, peer, token.CLASS.USER), token.SID.ANONYMOUS,
            "the user SID is Anonymous (S-1-5-7), not the caller's")
        local groups = assert(token.groups(vm, peer))
        local everyone = token.find_group(groups, token.SID.EVERYONE)
        t:assert(everyone, "Everyone is carried")
        t:assert_eq(everyone.attributes & token.GROUP.ENABLED, token.GROUP.ENABLED, "and enabled")
        t:assert(not token.find_group(groups, token.SID.AUTHENTICATED_USERS),
            "Authenticated Users is not")
        t:assert_eq(level_of(vm, peer), L.ANONYMOUS, "and the token is at Anonymous level")
        sys.close(vm, peer)
    end)

test("an Identification-level token is barred from AccessCheck",
    { spec = "PKM *imp.identification.barred-from-accesscheck" }, function(t)
        local open_to_all = access.simple(
            { access.ace(access.ACE.ALLOWED, 0x1F01FF, token.SID.EVERYONE) })
        local ident = assert(token.mint(vm, { token_type = token.TYPE.IMPERSONATION,
            impersonation_level = L.IDENTIFICATION }))
        local acting = assert(token.mint(vm, { token_type = token.TYPE.IMPERSONATION,
            impersonation_level = L.IMPERSONATION }))
        t:assert(access.check(vm, { token_fd = acting, sd = open_to_all, desired = 0x1 }).ok,
            "an Impersonation-level token passes a descriptor that grants Everyone everything")
        local r = access.check(vm, { token_fd = ident, sd = open_to_all, desired = 0x1 })
        t:assert(r.ret < 0, "the same descriptor refuses an Identification-level one: "
            .. sys.errname(r.errno))
        t:assert_eq(r.granted, 0, "and grants nothing")
        sys.close(vm, ident); sys.close(vm, acting)

        -- And a server thread impersonating one cannot open a file.
        local path = SOCKS .. "/readable"
        vm:write_file(path, "content")
        kacs.set_sd(vm, path, kacs.grant(kacs.ALL_RIGHTS))
        token.as_principal(t, vm, { privs_present = MINTER, privs_enabled = MINTER }, function(w)
            local fd = assert(sys.open(w, path, sys.O.RDONLY))
            sys.close(w, fd)
            local client = assert(token.mint(w, { user_sid = token.SID.TEST_USER,
                token_type = token.TYPE.IMPERSONATION,
                impersonation_level = L.IDENTIFICATION }))
            t:assert_eq(token.impersonate(w, client).ret, 0, "the server impersonates it")
            t:assert_eq(assert(token.effective(vm, w)).level, L.IDENTIFICATION, "at Identification")
            local got, errno = sys.open(w, path, sys.O.RDONLY)
            -- §3.5.1 names no errno for the bar, only that the check
            -- fails; the kernel reports it as EINVAL rather than EACCES.
            t:assert(not got, "and the open simply fails the check: " .. sys.errname(errno or 0))
            token.revert(w)
            t:assert(sys.open(w, path, sys.O.RDONLY), "the same open works again after reverting")
            sys.close(w, client)
        end)
    end)

test("identity cascades freely across local services at Impersonation level",
    { spec = "PKM *imp.impersonation.cascades-across-local-services" }, function(t)
        local IMPERSONATE = token.bit(P.IMPERSONATE)
        token.as_principal(t, vm, { privs_present = MINTER | IMPERSONATE,
            privs_enabled = MINTER | IMPERSONATE }, function(w)
            -- Service A impersonates client B ...
            local b = assert(token.mint(w, { user_sid = token.SID.TEST_USER_2,
                token_type = token.TYPE.IMPERSONATION, impersonation_level = L.IMPERSONATION }))
            t:assert_eq(token.impersonate(w, b).ret, 0, "A impersonates B")
            t:assert_eq(assert(token.effective(vm, w)).level, L.IMPERSONATION, "at Impersonation")
            -- ... and connects to local service C, which sees B.
            local peer = capture(t, w, nil)
            t:assert_eq(token.query(w, peer, token.CLASS.USER), token.SID.TEST_USER_2,
                "C sees B's identity, not A's")
            t:assert_eq(level_of(w, peer), L.IMPERSONATION, "at Impersonation")
            token.revert(w)
            -- After reverting, the next connection carries A again.
            local own = capture(t, w, nil)
            t:assert_eq(token.query(w, own, token.CLASS.USER), token.SID.TEST_USER,
                "and A's own identity once it reverts")
            sys.close(w, peer); sys.close(w, own); sys.close(w, b)
        end)
    end)

test("Delegation is locally identical to Impersonation and differs only at the network boundary",
    { spec = "PKM *imp.delegation.network-boundary-only" }, function(t)
        local open_to_all = access.simple(
            { access.ace(access.ACE.ALLOWED, 0x1F01FF, token.SID.EVERYONE) })
        local closed = access.simple({})
        local pair = {}
        for _, level in ipairs({ L.IMPERSONATION, L.DELEGATION }) do
            local fd = assert(token.mint(vm, { token_type = token.TYPE.IMPERSONATION,
                impersonation_level = level }))
            pair[level] = {
                open = access.check(vm, { token_fd = fd, sd = open_to_all, desired = 0x1 }),
                shut = access.check(vm, { token_fd = fd, sd = closed, desired = 0x1 }),
                level = level_of(vm, fd),
            }
            sys.close(vm, fd)
        end
        t:assert_eq(pair[L.DELEGATION].open.granted, pair[L.IMPERSONATION].open.granted,
            "the same descriptor grants the same access at either level")
        t:assert(pair[L.DELEGATION].shut.denied and pair[L.IMPERSONATION].shut.denied,
            "and refuses the same access at either level")
        -- What differs is the flag KACS carries for authd to read.
        t:assert_eq(pair[L.IMPERSONATION].level, L.IMPERSONATION, "the level is on the token")
        t:assert_eq(pair[L.DELEGATION].level, L.DELEGATION, "and distinguishes the two")
        -- The socket carries it too, and the capture keeps it distinct.
        local deleg = capture(t, vm, L.DELEGATION)
        local imp = capture(t, vm, L.IMPERSONATION)
        t:assert_eq(level_of(vm, deleg), L.DELEGATION, "a Delegation capture is flagged Delegation")
        t:assert_eq(level_of(vm, imp), L.IMPERSONATION, "an Impersonation capture is not")
        sys.close(vm, deleg); sys.close(vm, imp)
    end)

test("the level is set on the socket before connect and defaults to Impersonation",
    { spec = "PKM *imp.level.socket-default-impersonation" }, function(t)
        local fresh = assert(us.socket(vm))
        t:assert_eq(us.level(vm, fresh), L.IMPERSONATION, "a new socket starts at Impersonation")
        local peer = capture(t, vm, nil)
        t:assert_eq(level_of(vm, peer), L.IMPERSONATION,
            "and a connection made without setting it is captured there")
        sys.close(vm, peer)
        t:assert_eq(us.set_level(vm, fresh, L.IDENTIFICATION).ret, 0, "the client may set it")
        t:assert_eq(us.level(vm, fresh), L.IDENTIFICATION, "and read it back")
        local bad = us.set_level(vm, fresh, 9)
        t:assert(bad.ret ~= 0, "a value outside the four levels is refused")
        t:assert_eq(bad.errno, sys.E.INVAL, "EINVAL")
        sys.close(vm, fresh)
    end)

-- The ratchet ------------------------------------------------------------------

test("the impersonation level only ever goes down",
    { spec = "PKM *imp.level.ratchet-only-down" }, function(t)
        local deleg = assert(token.mint(vm, { impersonation_level = L.DELEGATION }))
        -- Down, one step at a time, is always allowed.
        local imp = assert(token.duplicate(vm, deleg, { token_type = token.TYPE.IMPERSONATION,
            impersonation_level = L.IMPERSONATION }))
        t:assert_eq(level_of(vm, imp), L.IMPERSONATION, "Delegation duplicates down to Impersonation")
        local ident = assert(token.duplicate(vm, imp, { token_type = token.TYPE.IMPERSONATION,
            impersonation_level = L.IDENTIFICATION }))
        t:assert_eq(level_of(vm, ident), L.IDENTIFICATION, "and on down to Identification")
        -- Up is refused from every rung.
        local up, errno = token.duplicate(vm, ident, { token_type = token.TYPE.IMPERSONATION,
            impersonation_level = L.IMPERSONATION })
        t:assert(not up, "an Identification token cannot be duplicated back up")
        t:assert_eq(errno, sys.E.INVAL, "EINVAL")
        t:assert(not token.duplicate(vm, imp, { token_type = token.TYPE.IMPERSONATION,
            impersonation_level = L.DELEGATION }), "nor an Impersonation one to Delegation")
        -- And an impersonation token acts at its level and no higher.
        local open_to_all = access.simple(
            { access.ace(access.ACE.ALLOWED, 0x1F01FF, token.SID.EVERYONE) })
        t:assert(access.check(vm, { token_fd = imp, sd = open_to_all, desired = 0x1 }).ok,
            "the Impersonation copy acts")
        t:assert(access.check(vm, { token_fd = ident, sd = open_to_all, desired = 0x1 }).ret < 0,
            "the Identification copy does not")
        sys.close(vm, deleg); sys.close(vm, imp); sys.close(vm, ident)
    end)

test("a primary token's level is the ceiling on everything the process carrying it can convey",
    { spec = "PKM *imp.level.primary-is-conveyance-ceiling" }, function(t)
        token.as_principal(t, vm, { impersonation_level = L.IMPERSONATION,
            privs_present = MINTER, privs_enabled = MINTER }, function(w)
            -- What a peer captures at connect.
            local peer = capture(t, w, L.DELEGATION)
            t:assert_eq(level_of(w, peer), L.IMPERSONATION,
                "a connect made at Delegation is captured at the primary's Impersonation")
            -- What KACS_SO_PASS_TOKEN attaches.
            local path = sock_path()
            local srv = assert(us.socket(w))
            t:assert_eq(us.bind(w, srv, path).ret, 0, "bind")
            t:assert_eq(us.listen(w, srv).ret, 0, "listen")
            local cli = assert(us.socket(w))
            t:assert_eq(us.set_level(w, cli, L.DELEGATION).ret, 0, "the sender asks for Delegation")
            t:assert_eq(us.set_pass_token(w, cli, true).ret, 0, "and turns on KACS_SO_PASS_TOKEN")
            t:assert_eq(us.connect(w, cli, path).ret, 0, "connect")
            local acc = assert(us.accept(w, srv))
            t:assert_eq(us.sendmsg(w, cli, "hop").ret, 3, "send")
            local got = us.recvmsg(w, acc, 16)
            t:assert_eq(#got.tokens, 1, "the receive carries a token")
            t:assert_eq(level_of(w, got.tokens[1]), L.IMPERSONATION,
                "attached at the primary's level, not the socket's")
            -- What DuplicateToken produces, in either direction.
            local own = assert(token.open_self(w, token.RIGHT.QUERY))
            t:assert_eq(level_of(w, own), L.IMPERSONATION, "the primary itself is at Impersonation")
            sys.close(w, own); sys.close(w, peer); sys.close(w, srv); sys.close(w, acc)
            sys.close(w, cli); sys.close(w, got.tokens[1])
        end)
    end)

test("a capture stores the lower of the socket's level and the source token's own",
    { spec = "PKM *imp.level.capture-takes-lower" }, function(t)
        -- The agent's own token is at Delegation, so the socket is what
        -- binds: each level asked for is the level captured.
        for _, level in ipairs({ L.IDENTIFICATION, L.IMPERSONATION, L.DELEGATION }) do
            local peer = capture(t, vm, level)
            t:assert_eq(level_of(vm, peer), level,
                "socket level " .. level .. " below a Delegation token captures at " .. level)
            sys.close(vm, peer)
        end
        -- With the token below the socket, the token is what binds.
        token.as_principal(t, vm, { impersonation_level = L.IMPERSONATION,
            privs_present = MINTER, privs_enabled = MINTER }, function(w)
            local peer = capture(t, w, L.DELEGATION)
            t:assert_eq(level_of(w, peer), L.IMPERSONATION,
                "an Impersonation token under a Delegation socket captures at Impersonation")
            local lower = capture(t, w, L.IDENTIFICATION)
            t:assert_eq(level_of(w, lower), L.IDENTIFICATION,
                "and the socket still binds when it is the lower of the two")
            sys.close(w, peer); sys.close(w, lower)
        end)
    end)

test("FilterToken and primary installation copy the level unchanged",
    { spec = "PKM *imp.level.derivation-copies-unchanged" }, function(t)
        local source = assert(token.mint(vm, { impersonation_level = L.IMPERSONATION,
            privs_present = token.bit(P.TCB), privs_enabled = token.bit(P.TCB) }))
        local filtered = assert(token.restrict(vm, source, { privs = token.bit(P.TCB) }))
        t:assert_eq(level_of(vm, filtered), L.IMPERSONATION,
            "FilterToken carries the level across unchanged")
        sys.close(vm, filtered); sys.close(vm, source)
        -- Primary installation likewise: the worker's primary reports the
        -- level the token was minted at.
        for _, level in ipairs({ L.IMPERSONATION, L.DELEGATION }) do
            token.as_principal(t, vm, { impersonation_level = level }, function(w)
                local own = assert(token.open_self(w, token.RIGHT.QUERY))
                t:assert_eq(level_of(w, own), level,
                    "an installed primary keeps its level (" .. level .. ")")
                sys.close(w, own)
            end)
        end
    end)

test("the one way to a higher level is a fresh token from CreateToken",
    { spec = "PKM *imp.level.raise-only-via-create-token" }, function(t)
        token.as_principal(t, vm, { impersonation_level = L.IMPERSONATION,
            privs_present = MINTER, privs_enabled = MINTER }, function(w)
            local own = assert(token.open_self(w, token.RIGHT.QUERY))
            t:assert_eq(level_of(w, own), L.IMPERSONATION, "the process is at Impersonation")
            -- A capture from this process cannot exceed it ...
            local captured = capture(t, w, L.DELEGATION)
            t:assert_eq(level_of(w, captured), L.IMPERSONATION, "a capture cannot raise it")
            -- ... and neither can duplicating what it captured.
            local up, upe = token.duplicate(w, captured, { access = QUERY_ONLY,
                token_type = token.TYPE.IMPERSONATION, impersonation_level = L.DELEGATION })
            t:assert(not up, "DuplicateToken cannot raise it either")
            t:assert_eq(upe, sys.E.INVAL, "EINVAL — refused on the level, not on the handle")
            -- CreateToken can, because it is a fresh token rather than a
            -- derivation — and it takes SeCreateTokenPrivilege.
            local fresh = assert(token.mint(w, { impersonation_level = L.DELEGATION }))
            t:assert_eq(level_of(w, fresh), L.DELEGATION, "CreateToken mints at Delegation")
            sys.close(w, own); sys.close(w, captured); sys.close(w, fresh)
        end)
        -- And without the privilege there is no such path at all.
        token.as_principal(t, vm, { impersonation_level = L.IMPERSONATION,
            privs_present = token.bit(P.TCB), privs_enabled = token.bit(P.TCB) }, function(w)
            local session = assert(token.create_logon_session(w, {}))
            local fd, errno = token.create(w, { auth_id = session,
                impersonation_level = L.DELEGATION })
            t:assert(not fd, "a principal without SeCreateTokenPrivilege cannot mint one")
            t:assert_eq(errno, sys.E.PERM, "EPERM")
        end)
    end)

test("the client's choice holds across any number of hops",
    { spec = "PKM *imp.level.holds-across-hops" }, function(t)
        -- Hop one: a client connects at Impersonation and the server
        -- captures it there.
        local peer = capture(t, vm, L.IMPERSONATION)
        t:assert_eq(level_of(vm, peer), L.IMPERSONATION, "the capture is at Impersonation")
        -- Hop two: the server converts that token to a primary and gives
        -- it to a process, which is capped at Impersonation.
        local primary = assert(token.duplicate(vm, peer, { token_type = token.TYPE.PRIMARY,
            impersonation_level = L.IMPERSONATION }))
        t:assert_eq(level_of(vm, primary), L.IMPERSONATION, "the primary it becomes is capped there")
        t:assert(not token.duplicate(vm, primary, { token_type = token.TYPE.PRIMARY,
            impersonation_level = L.DELEGATION }), "and cannot be duplicated back up")
        sys.close(vm, primary); sys.close(vm, peer)
        -- Hop three: nothing that process captures, conveys or duplicates
        -- can ever be Delegation.
        token.as_principal(t, vm, { impersonation_level = L.IMPERSONATION,
            privs_present = MINTER, privs_enabled = MINTER }, function(w)
            local hop = capture(t, w, L.DELEGATION)
            t:assert_eq(level_of(w, hop), L.IMPERSONATION,
                "a further hop asking for Delegation is still captured at Impersonation")
            local again, againe = token.duplicate(w, hop, { access = QUERY_ONLY,
                token_type = token.TYPE.PRIMARY, impersonation_level = L.IMPERSONATION })
            t:assert(again, "converting it again holds: " .. sys.errname(againe or 0))
            t:assert_eq(level_of(w, again), L.IMPERSONATION, "at Impersonation")
            local raised, raisede = token.duplicate(w, hop, { access = QUERY_ONLY,
                token_type = token.TYPE.IMPERSONATION, impersonation_level = L.DELEGATION })
            t:assert(not raised,
                "so authd is never shown a Delegation flag the client did not grant")
            t:assert_eq(raisede, sys.E.INVAL, "EINVAL")
            sys.close(w, hop); sys.close(w, again)
        end)
    end)
