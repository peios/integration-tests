-- PKM §3.2.7 and §3.5.3 — impersonation leaves no reference behind: a
-- token impersonated and reverted, or impersonated by a thread that
-- exits, is released like any other, and so is the impersonator's own
-- primary (PEI-1313).
--
-- A session dies with its last token, and kacs_destroy_empty_logon_session
-- then answers ENOENT; while any token in it lives the answer is EBUSY.
-- That errno is the token's reference count, seen from outside.

local sys = require("helpers.sys")
local token = require("helpers.token")

local vm = provium:vm("v", "kernel-only"):boot()

local IMP = { token_type = token.TYPE.IMPERSONATION, impersonation_level = token.LEVEL.IMPERSONATION }

local function imp_spec(extra)
    local s = {}
    for k, v in pairs(IMP) do s[k] = v end
    for k, v in pairs(extra or {}) do s[k] = v end
    return s
end

--- What the rollback says about `sid` right now: "ENOENT" (gone with its
--- last token), "EBUSY" (still referenced) or "OK" (it existed, empty).
local function state(sid)
    local r = token.destroy_empty_logon_session(vm, sid)
    if r.ret == 0 then return "OK" end
    return (sys.errname(r.errno):match("^%S+"))
end

--- `state` once it reads `want`, polling up to `ms`: task teardown is
--- asynchronous to the worker connection closing, and a cred's last put
--- frees it, and drops its token, from an RCU callback; the last reading
--- otherwise.
local function settle(sid, want, ms)
    local s
    for _ = 1, (ms or 2000) // 50 do
        s = state(sid)
        if s == want then return s end
        sys.nanosleep(vm, 0, 50000000)
    end
    return state(sid)
end

local function exit_worker(w) w:kill(); w:join() end

--- pidfd_getfd(2): `who` takes a duplicate of `pid`'s descriptor `fd`.
local function take_fd(who, pid, fd)
    local pidfd = assert(token.pidfd_open(who, pid))
    local r = who:syscall(438, pidfd, fd, 0)
    sys.close(who, pidfd)
    assert(r.ret >= 0, "pidfd_getfd: " .. sys.errname(r.errno))
    return r.ret
end

test("control: a token only minted releases its session when its fd closes",
    { spec = "PKM *token.session.lifetime-by-refcount" }, function(t)
        local w = vm:spawn_worker()
        local fd, sid = assert(token.mint(w, imp_spec()))
        sys.close(w, fd)
        local s = state(sid)
        t:log("mint-only, fd closed, worker alive: " .. s)
        t:assert_eq(s, "ENOENT", "released at once")
        exit_worker(w)
    end)

test("control: a token installed as primary releases its session when its process exits",
    { spec = "PKM *token.session.lifetime-by-refcount" }, function(t)
        local w = vm:spawn_worker()
        local fd, sid = assert(token.mint(w, {}))
        t:assert_eq(token.install(w, fd).ret, 0, "install")
        sys.close(w, fd)
        t:log("primary, worker alive: " .. state(sid))
        exit_worker(w)
        local s = settle(sid, "ENOENT")
        t:log("primary, worker exited: " .. s)
        t:assert_eq(s, "ENOENT", "released with the process")
    end)

-- override_creds() and revert_creds() take and drop no references; a
-- revert once discarded the cred revert_creds() handed back, leaking the
-- impersonation cred and its token on every revert (PEI-1313).

test("same worker: mint, impersonate, revert, close, then exit",
    { spec = "PKM *token.session.lifetime-by-refcount" }, function(t)
        local w = vm:spawn_worker()
        local fd, sid = assert(token.mint(w, imp_spec()))
        t:assert_eq(token.impersonate(w, fd).ret, 0, "impersonate")
        local during = token.effective(vm, w)
        t:assert_eq(during and during.user, token.SID.TEST_USER, "impersonating TEST_USER")
        t:assert_eq(token.revert(w).ret, 0, "revert")
        local after = token.effective(vm, w)
        t:assert_eq(after and after.user, token.SID.LOCAL_SYSTEM, "reverted: the thread acts as SYSTEM again")
        t:assert_eq(after and after.type, token.TYPE.PRIMARY, "on its primary token")
        sys.close(w, fd)
        local s1 = settle(sid, "ENOENT")
        t:log("same worker, reverted, fd closed, worker alive: " .. s1)
        exit_worker(w)
        local s2 = settle(sid, "ENOENT")
        t:log("same worker, after the worker exited: " .. s2)
        t:assert_eq(s1 .. "/" .. s2, "ENOENT/ENOENT",
            "released once reverted and closed / once the worker has exited")
    end)

test("other process: the agent mints, a worker impersonates and reverts, then exits",
    { spec = "PKM *token.session.lifetime-by-refcount" }, function(t)
        local fd, sid = assert(token.mint(vm, imp_spec()))
        local w = vm:spawn_worker()
        local wfd = take_fd(w, vm:syscall(sys.NR.getpid).ret, fd)
        sys.close(vm, fd)
        t:assert_eq(token.impersonate(w, wfd).ret, 0, "impersonate")
        t:assert_eq(token.revert(w).ret, 0, "revert")
        local after = token.effective(vm, w)
        t:assert_eq(after and after.user, token.SID.LOCAL_SYSTEM, "reverted")
        sys.close(w, wfd)
        local s1 = settle(sid, "ENOENT")
        t:log("cross-process, reverted, both fds closed, worker alive: " .. s1)
        exit_worker(w)
        local s2 = settle(sid, "ENOENT")
        t:log("cross-process, after the worker exited: " .. s2)
        t:assert_eq(s1 .. "/" .. s2, "ENOENT/ENOENT",
            "released once reverted and closed / once the worker has exited")
    end)

test("no revert: a worker that exits while impersonating",
    { spec = "PKM *token.session.lifetime-by-refcount" }, function(t)
        local w = vm:spawn_worker()
        local fd, sid = assert(token.mint(w, imp_spec()))
        t:assert_eq(token.impersonate(w, fd).ret, 0, "impersonate")
        sys.close(w, fd)
        t:log("no revert, impersonating, worker alive: " .. state(sid))
        exit_worker(w)
        local s = settle(sid, "ENOENT")
        t:log("no revert, after the worker exited: " .. s)
        t:assert_eq(s, "ENOENT", "released with the thread")
    end)

test("double impersonation: the first token is reverted internally",
    { spec = "PKM *imp.double.revert-then-reimpersonate" }, function(t)
        local w = vm:spawn_worker()
        local a, sa = assert(token.mint(w, imp_spec()))
        local b, sb = assert(token.mint(w, imp_spec({ user_sid = token.SID.TEST_USER_2 })))
        t:assert_eq(token.impersonate(w, a).ret, 0, "impersonate A")
        t:assert_eq(token.impersonate(w, b).ret, 0, "impersonate B over A")
        t:assert_eq(token.revert(w).ret, 0, "revert")
        sys.close(w, a); sys.close(w, b)
        local s_a, s_b = settle(sa, "ENOENT"), settle(sb, "ENOENT")
        t:log("double: A=" .. s_a .. " B=" .. s_b .. " (worker alive)")
        exit_worker(w)
        local e_a, e_b = settle(sa, "ENOENT"), settle(sb, "ENOENT")
        t:log("double, after exit: A=" .. e_a .. " B=" .. e_b)
        t:assert_eq(table.concat({ s_a, s_b, e_a, e_b }, "/"), "ENOENT/ENOENT/ENOENT/ENOENT",
            "A/B reverted and closed with the worker alive, then A/B after it exited")
    end)

--- A worker whose primary token is minted in its own session SB, holding
--- an impersonation token in session SA. Returns worker, A fd, SA, SB.
local function principal_with_imp(t)
    local w = vm:spawn_worker()
    local a, sa = assert(token.mint(w, imp_spec()))
    local IMPERSONATE = token.bit(token.PRIV.IMPERSONATE)
    local p, sb = assert(token.mint(w, { privs_present = IMPERSONATE, privs_enabled = IMPERSONATE }))
    t:assert_eq(token.install(w, p).ret, 0, "install P")
    sys.close(w, p)
    t:assert_eq(token.impersonate(w, a).ret, 0, "impersonate A")
    sys.close(w, a)
    return w, sa, sb
end

-- A thread exiting while impersonating once leaked its own cred's
-- reference parked in impersonation_saved_cred, which exit_creds() never
-- sees (PEI-1313).
test("principal exits while impersonating: the primary's session too",
    { spec = "PKM *token.session.lifetime-by-refcount" }, function(t)
        local w, sa, sb = principal_with_imp(t)
        exit_worker(w)
        local s_a, s_b = settle(sa, "ENOENT"), settle(sb, "ENOENT")
        t:log("principal, no revert, after exit: SA(imp)=" .. s_a .. " SB(primary)=" .. s_b)
        t:assert_eq(s_a .. "/" .. s_b, "ENOENT/ENOENT",
            "SA (impersonation) / SB (primary) released after the exit")
    end)

test("principal reverts, then exits",
    { spec = "PKM *token.session.lifetime-by-refcount" }, function(t)
        local w, sa, sb = principal_with_imp(t)
        t:assert_eq(token.revert(w).ret, 0, "revert")
        exit_worker(w)
        local s_a, s_b = settle(sa, "ENOENT"), settle(sb, "ENOENT")
        t:log("principal, reverted, after exit: SA(imp)=" .. s_a .. " SB(primary)=" .. s_b)
        t:assert_eq(s_a .. "/" .. s_b, "ENOENT/ENOENT",
            "SA (impersonation) / SB (primary) released after the exit")
    end)
