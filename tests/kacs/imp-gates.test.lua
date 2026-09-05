-- PKM §3.5.2 — the two impersonation gates: the identity gate (same
-- user and same restriction status, or SeImpersonatePrivilege) and the
-- integrity ceiling, both judged against the server's *primary* token,
-- both capping to Identification rather than failing — with one hard
-- denial where a restricted server reaches for an unrestricted token of
-- its own user.
--
-- Every case is a worker whose primary token is a minted principal:
-- impersonation is per-thread and the agent spreads its syscalls across
-- threads, so the main connection is never the server here. The server
-- also carries SeTcbPrivilege and SeCreateTokenPrivilege so it can mint
-- the client tokens it then impersonates; neither participates in
-- either gate.
--
-- The effective level is read from outside, through
-- `token.effective`: a capped, Identification-level credential is
-- barred from AccessCheck, so the server cannot open its own effective
-- token to look.

local sys = require("helpers.sys")
local token = require("helpers.token")
local access = require("helpers.access")

local vm = provium:vm("v", "kernel-only"):boot()

local P = token.PRIV
local L = token.LEVEL
local MINTER = token.bit(P.TCB) | token.bit(P.CREATE_TOKEN)
local IMPERSONATE = token.bit(P.IMPERSONATE)
local RESTRICTION = { { sid = token.SID.TEST_GROUP_2, attributes = 0 } }

--- Run `fn(worker)` as a server principal. `spec` overrides the token
--- the worker installs; `MINTER` is always present so the body can mint
--- the clients it impersonates.
local function as_server(t, spec, fn)
    local s = { privs_present = MINTER, privs_enabled = MINTER,
        integrity_level = token.INTEGRITY.MEDIUM }
    for k, v in pairs(spec or {}) do s[k] = v end
    s.privs_present = s.privs_present | MINTER
    s.privs_enabled = s.privs_enabled | MINTER
    token.as_principal(t, vm, s, fn)
end

--- Mint an impersonation-level client token inside `w`. Defaults to
--- another user at Impersonation level and Medium integrity.
local function client(w, spec)
    local s = { user_sid = token.SID.TEST_USER_2,
        token_type = token.TYPE.IMPERSONATION,
        impersonation_level = L.IMPERSONATION,
        integrity_level = token.INTEGRITY.MEDIUM }
    for k, v in pairs(spec or {}) do s[k] = v end
    local fd, errno = token.mint(w, s)
    assert(fd, "mint client: " .. sys.errname(errno or 0))
    return fd
end

--- Impersonate `fd` and report the level the thread ends up acting at.
--- Returns the raw ioctl result and the effective-token view.
local function impersonate(t, vm_, w, fd)
    local r = token.impersonate(w, fd)
    if r.ret ~= 0 then return r, nil end
    local eff, errno = token.effective(vm_, w)
    t:assert(eff, "the agent reads the worker's effective token: " .. sys.errname(errno or 0))
    return r, eff
end

-- Which token the gates are judged against ------------------------------------

test("both gates are evaluated against the server's primary token, never its effective one",
    { spec = "PKM *imp.gate.evaluated-against-primary-token" }, function(t)
        as_server(t, { privs_present = IMPERSONATE, privs_enabled = IMPERSONATE }, function(w)
            -- Both clients are minted first: CreateToken is judged on the
            -- *effective* token, and the server is about to be one of
            -- these privilege-free principals.
            local first = client(w)
            local second = client(w, { user_sid = token.sid(5, 21, 1000, 2000, 3000, 1103) })
            local r, eff = impersonate(t, vm, w, first)
            t:assert_eq(r.ret, 0, "the server impersonates its first client")
            t:assert_eq(eff.level, L.IMPERSONATION,
                "at Impersonation, on its own SeImpersonatePrivilege")
            t:assert_eq(eff.user, token.SID.TEST_USER_2, "as that client")
            -- Still impersonating a principal that holds no privileges,
            -- the server reaches for a second, different client.
            local r2, eff2 = impersonate(t, vm, w, second)
            t:assert_eq(r2.ret, 0, "and impersonates a second one")
            t:assert_eq(eff2.level, L.IMPERSONATION,
                "still at Impersonation — the privilege on the primary token is what counts, "
                .. "not the privilege-free client it was already impersonating")
            token.revert(w)
            sys.close(w, first); sys.close(w, second)
        end)
    end)

-- The identity gate ------------------------------------------------------------

test("the same user, both unrestricted, needs no privilege",
    { spec = "PKM *imp.gate.same-user-same-restriction" }, function(t)
        as_server(t, {}, function(w)
            local same = client(w, { user_sid = token.SID.TEST_USER })
            local r, eff = impersonate(t, vm, w, same)
            t:assert_eq(r.ret, 0, "the impersonation succeeds")
            t:assert_eq(eff.level, L.IMPERSONATION,
                "at the level asked for, without SeImpersonatePrivilege")
            t:assert_eq(eff.user, token.SID.TEST_USER, "as the same user")
            token.revert(w)
            sys.close(w, same)
        end)
    end)

test("SeImpersonatePrivilege has to be present and enabled to reach another user",
    { spec = "PKM *imp.gate.impersonate-privilege-enabled" }, function(t)
        as_server(t, { privs_present = IMPERSONATE, privs_enabled = 0 }, function(w)
            local other = client(w)
            local r, eff = impersonate(t, vm, w, other)
            t:assert_eq(r.ret, 0, "held-but-disabled, the call still succeeds")
            t:assert_eq(eff.level, L.IDENTIFICATION, "but the level is capped to Identification")
            token.revert(w)
            local own = assert(token.open_self(w, token.RIGHT.QUERY | token.RIGHT.ADJUST_PRIVS))
            t:assert_eq(token.enable_priv(w, own, P.IMPERSONATE).ret, 0,
                "the server enables SeImpersonatePrivilege")
            local r2, eff2 = impersonate(t, vm, w, other)
            t:assert_eq(r2.ret, 0, "and impersonates again")
            t:assert_eq(eff2.level, L.IMPERSONATION, "this time at the level asked for")
            t:assert_eq(assert(token.privileges(w, own)).used & IMPERSONATE, IMPERSONATE,
                "the gate records the privilege as used")
            token.revert(w)
            sys.close(w, own); sys.close(w, other)
        end)
    end)

test("an identity-gate failure caps the level silently rather than returning an error",
    { spec = "PKM *imp.gate.identity-failure-caps-silently" }, function(t)
        as_server(t, {}, function(w)
            local other = client(w)
            local r, eff = impersonate(t, vm, w, other)
            t:assert_eq(r.ret, 0, "KACS_IOC_IMPERSONATE reports success")
            t:assert_eq(r.errno, 0, "with no errno")
            t:assert_eq(eff.level, L.IDENTIFICATION, "and the installed token is at Identification")
            t:assert_eq(eff.type, token.TYPE.IMPERSONATION, "an impersonation token all the same")
            t:assert_eq(eff.user, token.SID.TEST_USER_2, "carrying the client's user SID")
            token.revert(w)
            sys.close(w, other)
        end)
    end)

test("a restricted server reaching an unrestricted token of its own user is denied outright",
    { spec = "PKM *imp.gate.restricted-to-unrestricted-eperm" }, function(t)
        as_server(t, { restricted_sids = RESTRICTION }, function(w)
            local unrestricted = client(w, { user_sid = token.SID.TEST_USER })
            local r = token.impersonate(w, unrestricted)
            t:assert(r.ret ~= 0, "the sandbox cannot reach its parent's unrestricted token")
            t:assert_eq(r.errno, sys.E.PERM, "-EPERM, not a cap")
            local eff = assert(token.effective(vm, w))
            t:assert_eq(eff.type, token.TYPE.PRIMARY,
                "and the thread is still on its own primary token")
            sys.close(w, unrestricted)
        end)
    end)

test("an unrestricted server reaching a restricted token of its own user takes the ordinary cap",
    { spec = "PKM *imp.gate.unrestricted-to-restricted-caps" }, function(t)
        as_server(t, {}, function(w)
            local restricted = client(w, { user_sid = token.SID.TEST_USER,
                restricted_sids = RESTRICTION })
            local r, eff = impersonate(t, vm, w, restricted)
            t:assert_eq(r.ret, 0, "the downgrade is harmless and the call succeeds")
            t:assert_eq(eff.level, L.IDENTIFICATION,
                "capped to Identification, because the restriction status differs")
            token.revert(w)
            sys.close(w, restricted)
        end)
    end)

-- The integrity ceiling ---------------------------------------------------------

test("a client above the server's integrity level caps to Identification",
    { spec = "PKM *imp.gate.integrity-ceiling" }, function(t)
        as_server(t, { privs_present = IMPERSONATE, privs_enabled = IMPERSONATE,
            integrity_level = token.INTEGRITY.MEDIUM }, function(w)
            local low = client(w, { integrity_level = token.INTEGRITY.LOW })
            local _, eff_low = impersonate(t, vm, w, low)
            t:assert_eq(eff_low.level, L.IMPERSONATION, "a Low client is acted as")
            token.revert(w)
            local medium = client(w, { integrity_level = token.INTEGRITY.MEDIUM })
            local _, eff_mid = impersonate(t, vm, w, medium)
            t:assert_eq(eff_mid.level, L.IMPERSONATION, "and so is a Medium one")
            token.revert(w)
            local high = client(w, { integrity_level = token.INTEGRITY.HIGH })
            local r, eff_high = impersonate(t, vm, w, high)
            t:assert_eq(r.ret, 0, "a High client is accepted")
            t:assert_eq(eff_high.level, L.IDENTIFICATION, "but only at Identification")
            token.revert(w)
            sys.close(w, low); sys.close(w, medium); sys.close(w, high)
        end)
    end)

test("a token capped by the ceiling keeps the client's literal integrity label and authorizes nothing",
    { spec = "PKM *imp.gate.capped-token-keeps-label" }, function(t)
        as_server(t, { privs_present = IMPERSONATE, privs_enabled = IMPERSONATE,
            integrity_level = token.INTEGRITY.MEDIUM }, function(w)
            local high = client(w, { integrity_level = token.INTEGRITY.HIGH })
            local _, eff = impersonate(t, vm, w, high)
            t:assert_eq(eff.level, L.IDENTIFICATION, "the level is capped")
            t:assert_eq(eff.integrity, token.INTEGRITY.HIGH,
                "and the High label is preserved as identity metadata")
            -- The preserved label authorizes nothing: the thread cannot
            -- reach an object its own primary token would have reached.
            local fd = assert(token.effective_token(vm, w, token.RIGHT.QUERY))
            local everything = access.simple(
                { access.ace(access.ACE.ALLOWED, 0x1F01FF, token.SID.EVERYONE) })
            local r = access.check(vm, { token_fd = fd, sd = everything, desired = 0x1 })
            t:assert(r.ret < 0, "an Identification-level token is barred from AccessCheck: "
                .. sys.errname(r.errno))
            sys.close(vm, fd)
            token.revert(w)
            sys.close(w, high)
        end)
    end)

test("SeImpersonatePrivilege never bypasses the integrity ceiling",
    { spec = "PKM *imp.gate.privilege-never-bypasses-ceiling" }, function(t)
        as_server(t, { privs_present = IMPERSONATE, privs_enabled = IMPERSONATE,
            integrity_level = token.INTEGRITY.MEDIUM }, function(w)
            -- Same user, so the identity gate is satisfied without the
            -- privilege; the privilege is held and enabled regardless.
            local high = client(w, { user_sid = token.SID.TEST_USER,
                integrity_level = token.INTEGRITY.HIGH })
            local r, eff = impersonate(t, vm, w, high)
            t:assert_eq(r.ret, 0, "the call succeeds")
            t:assert_eq(eff.level, L.IDENTIFICATION,
                "and the ceiling still caps it, privilege or no privilege")
            token.revert(w)
            sys.close(w, high)
        end)
    end)

test("the effective level is the minimum of every constraint",
    { spec = "PKM *imp.gate.composition-minimum" }, function(t)
        as_server(t, { integrity_level = token.INTEGRITY.MEDIUM }, function(w)
            -- Both gates fail: another user without the privilege, above
            -- the server's integrity. Delegation requested.
            local both = client(w, { impersonation_level = L.DELEGATION,
                integrity_level = token.INTEGRITY.HIGH })
            local _, eff = impersonate(t, vm, w, both)
            t:assert_eq(eff.level, L.IDENTIFICATION, "two failed gates still land on Identification")
            token.revert(w)
            -- Neither gate fails, but the client asked for Identification:
            -- the level the client chose is the ceiling the composition
            -- starts from.
            local asked = client(w, { user_sid = token.SID.TEST_USER,
                impersonation_level = L.IDENTIFICATION })
            local _, eff2 = impersonate(t, vm, w, asked)
            t:assert_eq(eff2.level, L.IDENTIFICATION,
                "and a passing pair never raises the level the client set")
            token.revert(w)
            -- Neither gate fails and the client asked for Delegation.
            local full = client(w, { user_sid = token.SID.TEST_USER,
                impersonation_level = L.DELEGATION })
            local _, eff3 = impersonate(t, vm, w, full)
            t:assert_eq(eff3.level, L.DELEGATION, "with nothing constraining it the level stands")
            token.revert(w)
            sys.close(w, both); sys.close(w, asked); sys.close(w, full)
        end)
    end)
