-- PKM §3.2.6 — Linked tokens: pairing on the LogonSession, the gates on
-- establishing a pair, the Identification-level query copy an
-- unprivileged holder gets, and the pair's lifecycle.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local kmes = require("helpers.kmes")

local vm = provium:vm("v", "kernel-only"):boot()

local TCB = token.bit(token.PRIV.TCB)
local BACKUP = token.bit(token.PRIV.BACKUP)
local CN = token.bit(token.PRIV.CHANGE_NOTIFY)
local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED
local AGENT = "/sbin/provium-agent"
local next_port = 7200

--- A long-lived exec'd child of `who`. The guest's only executable is
--- the agent, which with `--port N` listens forever. Returns the
--- process and a pidfd on it.
local function child_of(who)
    next_port = next_port + 1
    local proc = who:run_async(AGENT, { "--port", tostring(next_port) })
    return proc, assert(token.pidfd_open(vm, proc:pid()))
end

local function id_of(who, fd) return assert(token.statistics(who, fd)).token_id end

--- An elevated token plus its filtered partner in a fresh session.
--- Returns elevated_fd, filtered_fd, session_id.
local function pair(who, spec)
    spec = spec or {}
    spec.privs_present = spec.privs_present or (TCB | token.bit(token.PRIV.BACKUP))
    spec.privs_enabled = spec.privs_enabled or spec.privs_present
    spec.groups = spec.groups or {
        { sid = token.SID.EVERYONE, attributes = ENABLED },
        { sid = token.SID.ADMINISTRATORS, attributes = token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED },
    }
    local e, sid = assert(token.mint(who, spec))
    local l = assert(token.restrict(who, e, { privs = TCB | token.bit(token.PRIV.BACKUP), deny_indices = { 1 } }))
    return e, l, sid
end

test("the two tokens of a pair share a LogonSession, are primary, and carry one user SID",
    { spec = "PKM *token.link.pair-invariants" }, function(t)
        local e, l, sid = pair(vm)
        t:assert_eq(token.link(vm, e, e, l, sid).ret, 0, "a well-formed pair links")
        -- Different user SID, same session.
        local other = assert(token.create(vm, { auth_id = sid, user_sid = token.SID.TEST_USER_2 }))
        local r = token.link(vm, e, e, other, sid)
        t:assert(r.ret ~= 0, "a partner with another user SID is refused: " .. sys.errname(r.errno))
        -- An impersonation token.
        local imp = assert(token.duplicate(vm, l, { token_type = token.TYPE.IMPERSONATION,
            impersonation_level = token.LEVEL.IMPERSONATION }))
        r = token.link(vm, e, e, imp, sid)
        t:assert(r.ret ~= 0, "a non-primary partner is refused: " .. sys.errname(r.errno))
        -- A token from a different session.
        local foreign = assert(token.mint(vm, {}))
        r = token.link(vm, e, e, foreign, sid)
        t:assert(r.ret ~= 0, "a partner from another session is refused: " .. sys.errname(r.errno))
        sys.close(vm, foreign); sys.close(vm, imp); sys.close(vm, other); sys.close(vm, e); sys.close(vm, l)
    end)

test("a token whose pair was replaced has no partner but keeps its elevation type",
    { spec = "PKM *token.link.stale-partner-errors-role-persists" }, function(t)
        local e, l, sid = pair(vm)
        t:assert_eq(token.link(vm, e, e, l, sid).ret, 0, "link e–l")
        t:assert_eq(token.query_u32(vm, l, token.CLASS.ELEVATION_TYPE), token.ELEVATION.LIMITED, "l is Limited")
        local partner = assert(token.get_linked(vm, l))
        t:assert_eq(token.statistics(vm, partner).token_id, token.statistics(vm, e).token_id, "its partner is e")
        sys.close(vm, partner)
        -- Replace the pair with e–l2.
        local l2 = assert(token.restrict(vm, e, { privs = TCB }))
        t:assert_eq(token.link(vm, e, e, l2, sid).ret, 0, "relink e–l2")
        local gone, errno = token.get_linked(vm, l)
        t:assert(not gone, "l has no active partner any more: " .. sys.errname(errno or 0))
        t:assert_eq(token.query_u32(vm, l, token.CLASS.ELEVATION_TYPE), token.ELEVATION.LIMITED,
            "but goes on reporting Limited")
        local p2 = assert(token.get_linked(vm, l2))
        t:assert_eq(token.statistics(vm, p2).token_id, token.statistics(vm, e).token_id, "l2's partner is e")
        sys.close(vm, p2); sys.close(vm, l2); sys.close(vm, l); sys.close(vm, e)
    end)

test("linking needs SeTcbPrivilege on the caller's primary token and TOKEN_DUPLICATE on both handles",
    { spec = "PKM *token.link.gates" }, function(t)
        local e, l, sid = pair(vm)
        -- A handle without TOKEN_DUPLICATE on either side.
        local narrow_e = assert(token.duplicate(vm, e, { access = token.RIGHT.ALL_ACCESS & ~token.RIGHT.DUPLICATE }))
        local r = token.link(vm, e, narrow_e, l, sid)
        t:assert_eq(r.errno, sys.E.ACCES, "elevated handle without TOKEN_DUPLICATE: EACCES")
        local narrow_l = assert(token.duplicate(vm, l, { access = token.RIGHT.QUERY }))
        r = token.link(vm, e, e, narrow_l, sid)
        t:assert_eq(r.errno, sys.E.ACCES, "filtered handle without TOKEN_DUPLICATE: EACCES")
        sys.close(vm, narrow_e); sys.close(vm, narrow_l); sys.close(vm, e); sys.close(vm, l)
        -- A caller whose primary lacks SeTcbPrivilege, even while
        -- impersonating a token that has it.
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local we, wl, wsid = pair(worker)
            local tcb_imp = assert(token.duplicate(worker, we, { token_type = token.TYPE.IMPERSONATION,
                impersonation_level = token.LEVEL.IMPERSONATION }))
            -- Become a TEST_USER primary without TCB, keeping the fds.
            local plain = assert(token.create(worker, { auth_id = wsid, privs_present = 0 }))
            assert(token.install(worker, plain).ret == 0, "install")
            local r2 = token.link(worker, we, we, wl, wsid)
            t:assert(r2.ret ~= 0, "a primary without SeTcbPrivilege cannot link: " .. sys.errname(r2.errno))
            t:assert_eq(token.impersonate(worker, tcb_imp).ret, 0, "impersonate a TCB-bearing token")
            r2 = token.link(worker, we, we, wl, wsid)
            t:assert(r2.ret ~= 0, "the effective token's SeTcbPrivilege does not satisfy the gate: " .. sys.errname(r2.errno))
            token.revert(worker)
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
    end)

test("the two handles name distinct tokens of the named, published session",
    { spec = "PKM *token.link.handles-distinct-same-published-session" }, function(t)
        local e, l, sid = pair(vm)
        local r = token.link(vm, e, e, e, sid)
        t:assert(r.ret ~= 0, "the same token on both sides is refused: " .. sys.errname(r.errno))
        local e2 = assert(token.duplicate(vm, e, {}))  -- a distinct object, same shape
        r = token.link(vm, e, e, e2, sid)
        t:assert_eq(r.ret, 0, "two distinct objects of the same session link (no reduction check)")
        local _, other_sid = assert(token.mint(vm, {}))
        r = token.link(vm, e, e, l, other_sid)
        t:assert(r.ret ~= 0, "naming a session neither token belongs to is refused: " .. sys.errname(r.errno))
        r = token.link(vm, e, e, l, 0x7FFF000000000042)
        t:assert(r.ret ~= 0, "a session that does not exist is refused: " .. sys.errname(r.errno))
        sys.close(vm, e2); sys.close(vm, e); sys.close(vm, l)
    end)

test("the handle the ioctl is issued on is ignored",
    { spec = "PKM *token.link.issuing-handle-ignored" }, function(t)
        local e, l, sid = pair(vm)
        local unrelated = assert(token.open_self(vm))
        t:assert_eq(token.link(vm, unrelated, e, l, sid).ret, 0, "issued on the agent's own token fd")
        t:assert_eq(token.query_u32(vm, e, token.CLASS.ELEVATION_TYPE), token.ELEVATION.FULL, "e is Full")
        t:assert_eq(token.query_u32(vm, l, token.CLASS.ELEVATION_TYPE), token.ELEVATION.LIMITED, "l is Limited")
        t:assert_eq(token.query_u32(vm, unrelated, token.CLASS.ELEVATION_TYPE), token.ELEVATION.DEFAULT,
            "the issuing handle's token is untouched")
        sys.close(vm, unrelated); sys.close(vm, e); sys.close(vm, l)
    end)

test("an unprivileged holder querying its partner gets an Identification-level copy through a QUERY-only handle",
    { spec = "PKM *token.link.query-returns-identification-clone" }, function(t)
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local e, l, sid = pair(worker)
            assert(token.link(worker, e, e, l, sid).ret == 0, "link")
            local e_stats = token.statistics(worker, e)
            assert(token.install(worker, l).ret == 0, "install the filtered token")
            sys.close(worker, e); sys.close(worker, l)
            -- The worker is now the Limited principal, without SeTcbPrivilege.
            local own = assert(token.open_self(worker, token.RIGHT.QUERY))
            t:assert_eq(token.query_u32(worker, own, token.CLASS.ELEVATION_TYPE), token.ELEVATION.LIMITED, "it is Limited")
            local copy, errno = token.get_linked(worker, own)
            t:assert(copy, "GET_LINKED_TOKEN succeeds: " .. sys.errname(errno or 0))
            t:assert_eq(token.query_u32(worker, copy, token.CLASS.IMPERSONATION_LEVEL), token.LEVEL.IDENTIFICATION,
                "the copy is at Identification")
            t:assert_eq(token.query_u32(worker, copy, token.CLASS.ELEVATION_TYPE), token.ELEVATION.FULL,
                "and preserves the partner's elevation type")
            local cs = token.statistics(worker, copy)
            t:assert_neq(cs.token_id, e_stats.token_id, "a new token object")
            t:assert_eq(cs.modified_id, cs.token_id, "modified_id initialised to it")
            local p = token.privileges(worker, copy)
            t:assert(p.present & TCB ~= 0, "the copy shows the elevated token's privileges")
            local dup, de = token.duplicate(worker, copy, {})
            t:assert(not dup and de == sys.E.ACCES, "the handle is QUERY-only: no TOKEN_DUPLICATE")
            local imp = token.impersonate(worker, copy)
            t:assert(imp.ret ~= 0, "and cannot be used for an access decision: " .. sys.errname(imp.errno))
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
    end)

test("a caller holding SeTcbPrivilege receives a full handle to the actual linked token",
    { spec = "PKM *token.link.tcb-gets-real-handle" }, function(t)
        local e, l, sid = pair(vm)
        t:assert_eq(token.link(vm, e, e, l, sid).ret, 0, "link")
        local partner = assert(token.get_linked(vm, l))
        t:assert_eq(token.statistics(vm, partner).token_id, token.statistics(vm, e).token_id,
            "the same token object as e")
        t:assert_eq(token.query_u32(vm, partner, token.CLASS.IMPERSONATION_LEVEL), token.LEVEL.DELEGATION,
            "at its real level")
        local dup = assert(token.duplicate(vm, partner, {}))
        t:assert(dup, "a full handle: TOKEN_DUPLICATE works")
        sys.close(vm, dup); sys.close(vm, partner); sys.close(vm, e); sys.close(vm, l)
    end)

test("KACS does not verify that the filtered token is a reduction of the elevated one",
    { spec = "PKM *token.link.no-reduction-check" }, function(t)
        local e, l, sid = pair(vm)
        -- A token in the same session that is not derived from e at all —
        -- and carries more than it, even.
        local unrelated = assert(token.create(vm, { auth_id = sid,
            privs_present = TCB | token.bit(token.PRIV.DEBUG), privs_enabled = TCB | token.bit(token.PRIV.DEBUG) }))
        t:assert_eq(token.link(vm, e, e, unrelated, sid).ret, 0, "an unrelated same-user primary links as the Limited side")
        t:assert_eq(token.query_u32(vm, unrelated, token.CLASS.ELEVATION_TYPE), token.ELEVATION.LIMITED, "and is Limited")
        sys.close(vm, unrelated); sys.close(vm, e); sys.close(vm, l)
    end)

test("the pair's own references do not keep the session alive",
    { spec = "PKM *token.link.pair-released-with-last-external-ref" }, function(t)
        local ring = assert(kmes.attach(vm, 0))
        local e, l, sid = pair(vm)
        t:assert_eq(token.link(vm, e, e, l, sid).ret, 0, "link")
        kmes.drain(ring)
        sys.close(vm, e)
        t:assert_eq(#kmes.of_type(kmes.drain(ring), "logon-session-destroyed"), 0, "l still held: session alive")
        sys.close(vm, l)
        local ev = kmes.of_type(kmes.drain(ring), "logon-session-destroyed")
        t:assert_eq(#ev, 1, "the last external reference gone: the session is destroyed despite the pair")
        local again, errno = token.create(vm, { auth_id = sid })
        t:assert(not again, "and the session id is dead: " .. sys.errname(errno or 0))
        kmes.detach(ring)
    end)

test("a forked child's deep copy preserves the parent's elevation type",
    { spec = "PKM *token.link.fork-preserves-elevation-type" }, function(t)
        -- A minted principal reaches the agent image only if its
        -- descriptor lets it; SeChangeNotifyPrivilege carries it past
        -- traverse checking on the way there.
        assert(kacs.set_sd(vm, AGENT, kacs.grant(kacs.ALL_RIGHTS)).ret == 0,
            "the agent image is reachable by a minted principal")

        --- Install one member of a linked pair as a worker's primary
        --- token, spawn from it, and inspect the child's copy.
        local function spawn_under(role, expected)
            local worker = vm:spawn_worker()
            local ok, err = pcall(function()
                local privs = TCB | BACKUP | CN
                local e, l, sid = pair(worker, { privs_present = privs, privs_enabled = privs })
                t:assert_eq(token.link(worker, e, e, l, sid).ret, 0, role .. ": the pair links")
                t:assert_eq(token.install(worker, role == "elevated" and e or l).ret, 0,
                    "and the " .. role .. " member is installed as the worker's primary")

                local wpidfd = assert(token.pidfd_open(vm, worker:syscall(sys.NR.getpid).ret))
                local parent = assert(token.open_process(vm, wpidfd))
                t:assert_eq(token.query_u32(vm, parent, token.CLASS.ELEVATION_TYPE), expected,
                    "the worker's primary reports the pair's role")
                local partner = assert(token.get_linked(vm, parent),
                    "and is the session's active member, so it has a partner")

                local proc, pidfd = child_of(worker)
                local child = assert(token.open_process(vm, pidfd))
                t:assert_eq(token.query_u32(vm, child, token.CLASS.ELEVATION_TYPE), expected,
                    "the child's deep copy reports the same elevation type")
                t:assert_neq(id_of(vm, child), id_of(vm, parent), "on a token object of its own")
                -- Sticky role, no partner: the copy was never the active
                -- member of the pair, so querying its linked token errors.
                local linked, errno = token.get_linked(vm, child)
                t:assert(not linked, "which was never linked to anything: " .. sys.errname(errno or 0))
                t:assert_eq(token.statistics(vm, child).auth_id, token.statistics(vm, parent).auth_id,
                    "though it sits in the pair's LogonSession")

                proc:kill(); proc:wait("5s")
                sys.close(vm, child); sys.close(vm, pidfd)
                sys.close(vm, partner); sys.close(vm, parent); sys.close(vm, wpidfd)
            end)
            worker:kill(); worker:join()
            if not ok then error(err, 0) end
        end

        spawn_under("elevated", token.ELEVATION.FULL)
        spawn_under("filtered", token.ELEVATION.LIMITED)
    end)
