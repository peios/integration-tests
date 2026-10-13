-- PEI-745: process-wide installation order and thread enrollment.
-- Deterministic LIFO/ENOMEM scheduling is exercised by pkm_kunit_primary_epoch;
-- these cases exercise real concurrent ioctls and clones on the native kernel.
local sys = require("helpers.sys")
local token = require("helpers.token")
local vm = provium:vm("v", "kernel-only"):boot()
local R = token.RIGHT
local ASSIGN = token.bit(token.PRIV.ASSIGN_PRIMARY_TOKEN)
local TCB = token.bit(token.PRIV.TCB)
local BACKUP = token.bit(token.PRIV.BACKUP)

local function with_worker(fn)
    local w = vm:spawn_worker()
    local ok, err = pcall(fn, w)
    w:kill(); w:join()
    if not ok then error(err, 0) end
end

local function sleeper(w)
    return w:syscall_async(sys.NR.nanosleep, {
        args = { 0, 0 }, bufs = { string.pack("<i8i8", 20, 0) }, ptrs = { 0 },
    })
end

local function thread_ids(pid)
    local ids = {}
    for _, e in ipairs(vm:listdir("/proc/" .. pid .. "/task")) do
        local tid = tonumber(e.name)
        if tid then ids[#ids + 1] = tid end
    end
    return ids
end

local function assert_converged(t, pidfd, tids, expected)
    local pending = {}
    for _, tid in ipairs(tids) do pending[tid] = true end
    for _ = 1, 300 do
        for tid in pairs(pending) do
            local fd, e = token.open_thread(vm, pidfd, tid, R.QUERY)
            assert(fd, "thread disappeared before convergence: " .. sys.errname(e or 0))
            local id = assert(token.statistics(vm, fd)).token_id
            sys.close(vm, fd)
            if id == expected then pending[tid] = nil end
        end
        if next(pending) == nil then break end
        sys.nanosleep(vm, 0, 5 * 1000 * 1000)
    end
    t:assert(next(pending) == nil, "every surviving thread reaches the final primary token")
    -- Check again after more opportunities to service stale queued work.
    sys.nanosleep(vm, 0, 100 * 1000 * 1000)
    for _, tid in ipairs(tids) do
        local fd = assert(token.open_thread(vm, pidfd, tid, R.QUERY))
        t:assert_eq(token.statistics(vm, fd).token_id, expected,
            "later queued work cannot restore an older token")
        t:assert_eq(token.privileges(vm, fd).enabled & BACKUP, 0,
            "the final token's removed backup authority stays removed")
        sys.close(vm, fd)
    end
end

local function candidates(w)
    local a = assert(token.mint(w, { privs_present = ASSIGN | TCB | BACKUP,
        privs_enabled = ASSIGN | TCB | BACKUP }))
    local b = assert(token.mint(w, { privs_present = ASSIGN | TCB,
        privs_enabled = ASSIGN | TCB }))
    return a, b, assert(token.statistics(w, b)).token_id
end

test("successive installations converge to the newest token without restoring removed authority",
    { spec = "PKM *token.install.latest-successful-install-wins" }, function(t)
        with_worker(function(w)
            local pid = w:syscall(sys.NR.getpid).ret
            local pidfd = assert(token.pidfd_open(vm, pid))
            local a, b, final_id = candidates(w)
            local sleepers = { sleeper(w), sleeper(w), sleeper(w) }
            local tids = thread_ids(pid)
            t:assert(#tids >= 4, "three persistent sibling threads were published")
            for _ = 1, 32 do
                t:assert_eq(token.install(w, a).ret, 0, "install A")
                t:assert_eq(token.install(w, b).ret, 0, "install B")
            end
            assert_converged(t, pidfd, tids, final_id)
            sys.close(vm, pidfd)
        end)
    end)

test("concurrent installers and newly enrolled threads converge after a final installation",
    { spec = { "PKM *token.install.latest-successful-install-wins",
               "PKM *token.install.clone-enrollment" } }, function(t)
        with_worker(function(w)
            local pid = w:syscall(sys.NR.getpid).ret
            local pidfd = assert(token.pidfd_open(vm, pid))
            local a, b, final_id = candidates(w)
            local sleepers, installs = { sleeper(w) }, {}
            for i = 1, 16 do
                installs[#installs + 1] = w:syscall_async(sys.NR.ioctl, {
                    args = { i % 2 == 0 and a or b, token.IOC.INSTALL, 0 },
                })
                if i % 4 == 0 then sleepers[#sleepers + 1] = sleeper(w) end
            end
            local succeeded = 0
            for _, op in ipairs(installs) do
                local result = op:await()
                if result.ret == 0 then succeeded = succeeded + 1 end
                -- A changing thread-list snapshot may make an install retryable.
                t:assert(result.ret == 0 or result.errno == sys.E.AGAIN,
                    "concurrent install succeeds or returns its existing EAGAIN")
            end
            t:assert(succeeded >= 2, "multiple concurrent installers published an identity")
            t:assert_eq(token.install(w, b).ret, 0, "final installation after all installers return")
            local tids = thread_ids(pid)
            t:assert(#tids >= 6, "newly enrolled persistent siblings remain alive")
            assert_converged(t, pidfd, tids, final_id)
            sys.close(vm, pidfd)
        end)
    end)

test("LIFO callbacks and superseded ENOMEM retries cannot restore an obsolete primary token",
    { spec = "PKM *token.install.latest-successful-install-wins",
      skip = "Deterministic callback ordering and one-shot allocation failure are checked by " ..
             "pkm_kunit_primary_epoch: lifo, retry_current and retry_obsolete; native ioctls " ..
             "above exercise the real thread group without adding a userspace fault API." }, function() end)

test("a clone that missed prior snapshots catches up through its enrollment callback",
    { spec = "PKM *token.install.clone-enrollment",
      skip = "The exact missed-snapshot interleaving is checked by pkm_kunit_primary_epoch.enroll; " ..
             "the concurrent native case above exercises real successful clone publication." }, function() end)
