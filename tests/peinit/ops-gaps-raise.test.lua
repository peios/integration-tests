-- peinit TRM §8.2 — operations: a lifecycle deadline that raises. The
-- containment rule says an internal error about one service costs that
-- service and not the loop; these two sentences say it costs it once.
--
-- A deadline raises when peinit cannot do what it is due to do, and the
-- one thing every such deadline does is kill a cgroup. So the provocation
-- is a `cgroup.kill` peinit is not allowed to write: cgroupfs carries KACS
-- descriptors like any other file, and a DACL that denies SYSTEM
-- WRITE_DATA on it makes peinit's own open fail with EACCES — which
-- `kill_cgroup` reports as an error, unlike the ENOENT of a tree that is
-- already gone. The agent, which runs on peinit's token, is refused the
-- same open, and as the object's owner it can put the descriptor back.
--
-- Two deadlines, because the TRM has two cases. A readiness timeout is a
-- deadline containment can remove: it fails the service and the deadline
-- goes, announced once. A submitted job's stop-kill deadline belongs to
-- the submitted store and stays; it is held off and retried, and an
-- identical repeat is not announced again.
--
-- The ring is the oracle — `service.internal_error` is emitted for every
-- containment, job or service, and does not depend on who owns the
-- console. The console line is checked too, under `peios.quiet=0`.

local peinit = require("helpers.peinit")
local kacs = require("helpers.kacs")
local sys = require("helpers.sys")
peinit.claim(1)

local vm = peinit.boot({
    name = "ops-gaps-raise",
    append = "peios.quiet=0",
    files = peinit.seed("pt-ops-raise", {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
        { path = [[Machine\System\Services\pt-raise]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/sleep" },
            { name = "Arguments", type = "multi", data = { "100000" } },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 0 },
            { name = "StartTimeout", type = "dword", data = 6 },
            { name = "RestartPolicy", type = "dword", data = 0 },
        } },
    }),
})

local WRITE_DATA = 0x2
local FILE_ALL = 0x001F01FF

--- Deny SYSTEM the right to write `cgroup.kill` under `dir`.
local function deny_kill(dir)
    local sd = kacs.descriptor(kacs.acl({
        kacs.ace(1, WRITE_DATA, kacs.SID.LOCAL_SYSTEM, 0),
        kacs.ace(0, FILE_ALL, kacs.SID.EVERYONE, 0),
    }))
    local r = kacs.set_sd(vm, dir .. "/cgroup.kill", sd)
    assert(r.ret == 0, "deny " .. dir .. "/cgroup.kill: " .. sys.errname(r.errno or 0))
end

local function allow_kill(dir)
    local sd = kacs.descriptor(kacs.acl({ kacs.ace(0, FILE_ALL, kacs.SID.EVERYONE, 0) }))
    kacs.set_sd(vm, dir .. "/cgroup.kill", sd)
end

--- Whether the agent itself, on peinit's token, is refused the write.
local function refused(dir)
    local fd, err = sys.open(vm, dir .. "/cgroup.kill", sys.O.WRONLY, 0)
    if fd then sys.close(vm, fd) return false, "opened" end
    return err == sys.E.ACCES, sys.errname(err or 0)
end

--- The `service.internal_error` events on the ring whose payload names
--- `subject`, oldest first.
local function internal_errors(subject)
    local r = vm:run("revstrm --snapshot --pretty --type 'service.internal_error'",
        { timeout = 60 })
    r:assert_ok()
    local all, current = {}, nil
    for line in r.stdout:gmatch("[^\r\n]+") do
        if line:match("service%.internal_error%s*$") then
            current = { payload = "" }
            all[#all + 1] = current
        elseif current and line:match("^%s") then
            current.payload = current.payload .. line .. "\n"
        end
    end
    local out = {}
    for _, e in ipairs(all) do
        if e.payload:find(subject, 1, true) then out[#out + 1] = e end
    end
    return out, r.stdout
end

local function count(haystack, needle)
    local n, from = 0, 1
    while true do
        local at = haystack:find(needle, from, true)
        if not at then return n end
        n, from = n + 1, at + #needle
    end
end

--- PID 1's utime + stime, in clock ticks, read by the agent.
local function pid1_ticks()
    local stat = assert(peinit.proc(vm, 1, "stat"))
    local rest = stat:match("^%d+ %b() (.*)$")
    local f = {}
    for field in rest:gmatch("%S+") do f[#f + 1] = field end
    -- After pid and comm: state is f[1], so utime (14) and stime (15)
    -- are f[12] and f[13].
    return tonumber(f[12]) + tonumber(f[13])
end

local function pause(seconds)
    pcall(wait_until, function() return false end,
        { timeout = seconds, interval = 0.25, desc = "a fixed pause" })
end

test("a readiness deadline that raised is contained once, and does not come back",
    { spec = "peinit *op.a-deadline-that-raised-is-contained-once" },
    function(t)
        local ROOT = "/sys/fs/cgroup/peinit/pt-raise"
        vm:run("svctl --no-wait start pt-raise"):assert_ok()
        wait_until(function()
            local ok, procs = pcall(function() return vm:read_file(ROOT .. "/main/cgroup.procs") end)
            return ok and procs:match("%d") or nil
        end, { timeout = 30, interval = 0.2, desc = "pt-raise to launch" })

        -- Before its six-second readiness deadline: the kill it is due to
        -- do will be refused.
        deny_kill(ROOT)
        deny_kill(ROOT .. "/main")
        local denied, why = refused(ROOT)
        t:assert(denied, "premise: SYSTEM may not write the service's cgroup.kill (" .. why .. ")")

        local status = wait_until(function()
            local s = json.decode(vm:run("svctl --json status pt-raise").stdout)
            return s.state ~= "starting" and s or nil
        end, { timeout = 30, interval = 0.25, desc = "the readiness deadline to come due" })
        t:assert_eq(status.state, "failed", "the deadline that raised failed the service")
        t:assert_eq(status.cause, "internal_error", "under InternalError")

        local first = internal_errors("pt-raise")
        t:assert_eq(#first, 1, "and its containment was announced once")

        -- Ten more seconds of timer turns. Left in place, the deadline
        -- would be due again on every one of them, and announced again.
        pause(10)
        local later, raw = internal_errors("pt-raise")
        t:assert_eq(#later, 1, "it was not announced again: " .. raw)
        local console = vm:console():read_log()
        t:assert_eq(count(console, "peinit: service pt-raise: internal error at"), 1,
            "and the console carries the [FAILED] line once")

        allow_kill(ROOT .. "/main")
        allow_kill(ROOT)
        vm:run("echo 1 > " .. ROOT .. "/cgroup.kill")
    end)

test("a submitted job's deadline that keeps raising is retried at most once a second, and announced once",
    { spec = "peinit *op.a-deadline-that-keeps-raising-is-paced" },
    function(t)
        -- Ignores SIGTERM, so the timeout's stop has to escalate to the
        -- kill at its stop timeout. The kill is the deadline that raises,
        -- and it is the submitted store's, so containment cannot drop it.
        local r = vm:run("svctl --json job submit --timeout 3 --stop-timeout 2 " ..
            "/bin/sh -c 'trap \"\" TERM; while :; do /bin/sleep 1; done'")
        r:assert_ok()
        local id = r.stdout:match('"id":"([^"]+)"')
        t:assert(id, "the job was submitted: " .. r.stdout)
        local CG = "/sys/fs/cgroup/peinit/jobs/" .. id
        wait_until(function()
            local ok, procs = pcall(function() return vm:read_file(CG .. "/cgroup.procs") end)
            return ok and procs:match("%d") or nil
        end, { timeout = 30, interval = 0.2, desc = "the job to launch" })
        deny_kill(CG)
        local denied, why = refused(CG)
        t:assert(denied, "premise: SYSTEM may not write the job's cgroup.kill (" .. why .. ")")

        -- Three seconds to the timeout, two more to the kill.
        wait_until(function() return #internal_errors(id) > 0 or nil end,
            { timeout = 30, interval = 0.5, desc = "the kill deadline to raise" })

        -- Ten seconds of a deadline that cannot be removed and cannot be
        -- acted on. Re-armed in the past it would wake PID 1 at once,
        -- every turn, and each turn would announce it again.
        local before = pid1_ticks()
        local clock_before = os.time()
        pause(10)
        local spent = pid1_ticks() - before
        local elapsed = os.time() - clock_before

        local events, raw = internal_errors(id)
        t:assert_eq(#events, 1, "the identical repeat is not announced again: " .. raw)
        t:assert_eq(count(vm:console():read_log(), "peinit: job " .. id .. ": internal error at"),
            1, "and the console line appears once")
        -- USER_HZ is 100. A PID 1 retrying on every turn spins its vCPU:
        -- a whole second of ticks per second. Paced at once a second it
        -- uses next to nothing; a third of the window is far above that
        -- and far below a spin.
        t:assert(spent < elapsed * 100 / 3,
            "PID 1 was not spinning on the retry: " .. spent .. " ticks in " .. elapsed .. "s")
        -- The kill never landed: the job's processes are all still there.
        -- (The job record itself is retired by the containment, so `job
        -- status` no longer knows it; the deadline is the submitted
        -- store's, not the job's.)
        t:assert(vm:read_file(CG .. "/cgroup.procs"):match("%d"),
            "premise: the job's cgroup is still populated, so the kill is still owed")

        -- Retried, not dropped: once the write is allowed again, the next
        -- retry — within a second or so — lands the kill.
        allow_kill(CG)
        wait_until(function()
            local ok, procs = pcall(function() return vm:read_file(CG .. "/cgroup.procs") end)
            return (not ok or not procs:match("%d")) or nil
        end, { timeout = 20, interval = 0.5, desc = "the retried kill to land" })
    end)
