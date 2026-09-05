-- PKM §3.3.1 — the PSB model: a per-process structure that describes
-- what the process is, kept off the token so impersonation cannot move
-- it. The canonical reference lives on the task's LSM blob and the
-- credential mirrors are non-authoritative, which is a pointer identity
-- no guest operation can see; what a guest can see is the consequence,
-- so the two reachable cases drive a mitigation across an impersonation
-- boundary in both directions.

local sys = require("helpers.sys")
local token = require("helpers.token")
local psb = require("helpers.psb")

local vm = provium:vm("v", "kernel-only"):boot()

--- An impersonation token for TEST_USER, minted and impersonated inside
--- `w`. Returns the handle so the caller can close it.
local function impersonate_other(t, w)
    local fd, errno = token.mint(w, {
        user_sid = token.SID.TEST_USER,
        token_type = token.TYPE.IMPERSONATION,
        impersonation_level = token.LEVEL.IMPERSONATION,
    })
    t:assert(fd, "an impersonation token mints: " .. sys.errname(errno or 0))
    local r = token.impersonate(w, fd)
    t:assert_eq(r.ret, 0, "and the thread impersonates it: " .. sys.errname(r.errno))
    return fd
end

test("impersonation does not touch the PSB: a mitigation set before it stays enforced",
    { spec = "PKM *psb.impersonation-untouched" }, function(t)
        local w = vm:spawn_worker()
        local ok, err = pcall(function()
            t:assert_eq(psb.commit(w, psb.MIT.WXP), nil, "wxp commits on the process")
            t:assert_eq(psb.wx_refused(w), sys.E.ACCES, "and a W+X mapping is refused")

            local fd = impersonate_other(t, w)
            local own = assert(token.open_self(w, token.RIGHT.QUERY))
            t:assert_eq(token.query(w, own, token.CLASS.USER), token.SID.TEST_USER,
                "the effective token is now the client's")
            sys.close(w, own)

            t:assert_eq(psb.wx_refused(w), sys.E.ACCES,
                "and wxp is still enforced: what the process is did not change")
            t:assert_eq(token.revert(w).ret, 0, "reverting")
            t:assert_eq(psb.wx_refused(w), sys.E.ACCES, "leaves it enforced too")
            sys.close(w, fd)
        end)
        w:kill(); w:join()
        if not ok then error(err, 0) end
    end)

test("the credential swap impersonation performs leaves the same PSB in place",
    { spec = "PKM *psb.cred-swap-preserves-psb" }, function(t)
        -- Set the mitigation *while* a foreign token is installed in the
        -- credential. If the swap had moved the PSB with the credential
        -- the bit would leave with the revert; it does not, because the
        -- credential only ever mirrors the task's PSB.
        local w = vm:spawn_worker()
        local ok, err = pcall(function()
            local fd = impersonate_other(t, w)
            t:assert_eq(psb.commit(w, psb.MIT.WXP), nil,
                "wxp commits while impersonating")
            t:assert_eq(token.revert(w).ret, 0, "the credential is swapped back")
            t:assert_eq(psb.wx_refused(w), sys.E.ACCES,
                "and the process still carries the bit")
            sys.close(w, fd)
        end)
        w:kill(); w:join()
        if not ok then error(err, 0) end
    end)

-- ---- pointer identity, deferred to the KUnit suite -------------------

test("the canonical PSB reference lives on the task's LSM security blob",
    { spec = "PKM *psb.canonical-on-task-blob",
      covered_by = "kunit:pkm_kunit_process",
      skip = "which structure holds the reference is a kernel pointer " ..
             "identity, and no guest operation distinguishes it from the " ..
             "credential mirror; runs under " ..
             "pkm_kunit_process_state_impersonation_preserves_psb" },
    function(t) end)

test("a task-attached credential's PSB mirror refers to the task's own PSB",
    { spec = "PKM *psb.cred-mirror-same-psb",
      covered_by = "kunit:pkm_kunit_process",
      skip = "the mirror is only reachable as a pointer comparison " ..
             "between the credential and task security blobs; runs under " ..
             "pkm_kunit_process_state_impersonation_preserves_psb" },
    function(t) end)
