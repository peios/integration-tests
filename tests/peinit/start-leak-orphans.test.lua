-- peinit TRM §5.7 — leaked sub-cgroups, for the kinds §5.7 draws a
-- distinction around: a hook or health cgroup, and a pre-start check
-- helper's `checks/`. The chapter's own scenario is a process in
-- uninterruptible sleep, and nothing in a VM can be put into D-state on
-- demand. But the condition peinit actually tests is narrower: after
-- sending the kill it arms a post-kill deadline and asks `cgroup.events`
-- whether the sub-cgroup is still `populated` when the deadline fires.
-- That question can be answered honestly by making it true, which is what
-- `failure-unkillable.test.lua` does for a service's main process with a
-- keeper — a process that keeps injecting a fresh child into the doomed
-- cgroup across the post-kill window. This file does the same for the
-- other three cgroup kinds.
--
-- `PostKillTimeout` is seeded up so the keeper has a wide window to win;
-- at the five-second default this is a race against a shell loop.
--
-- Each leak is provoked once and the tests read the state it leaves: the
-- service's `warnings` array, the `peinit.cgroup.leaked` event on the
-- KMES ring,
-- and — for a hook/health leak — that the service goes on running.

local peinit = require("helpers.peinit")
local revstrm = require("helpers.revstrm")
peinit.claim(1)

local ROOT = "/sys/fs/cgroup/peinit/"

local FILES = {
    -- Keep <cgroup>/cgroup.procs populated across the post-kill window.
    -- Each iteration forks a fresh sleep and moves it into the target:
    -- whatever the kill took, the next iteration replaces. Long enough to
    -- outlast every provocation in the file.
    ["pt/keeper.sh"] = { [[
target=$1
N=0
while [ $N -lt 240 ] ; do
  /bin/sleep 300 &
  echo $! > "$target/cgroup.procs" 2>/dev/null || true
  N=$((N+1))
  /bin/sleep 0.25
done
]], exec = true },
}

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Boot]], values = {
        { name = "PostKillTimeout", type = "dword", data = 10 },
    } },
    { path = [[Machine\System\Services]] },
    -- A slow pre-hook, so hooks/ exists long enough to seed a keeper into
    -- it before peinit kills it (which it does once the hook succeeds,
    -- §5.3). The keeper then keeps it populated past the post-kill
    -- deadline, so the kill leaves a survivor.
    { path = [[Machine\System\Services\pt-hookleak]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "StartTimeout", type = "dword", data = 60 },
        { name = "ExecStartPre", type = "multi", data = { "/bin/sleep 6" } },
    } },
    -- A pre-start filesystem check on a path that exists, frozen so the
    -- helper misses its deadline; the keeper survives the kill of checks/.
    { path = [[Machine\System\Services\pt-chkleak]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "PreStartCheckTimeout", type = "dword", data = 3 },
        { name = "Conditions", type = "multi", data = { "path:/" } },
    } },
    -- A health check that always fails, so consecutive failures escalate.
    -- A keeper in hooks/ makes the escalation's kill of the *root* cgroup
    -- leave a survivor, which is how "escalation kills the root, not just
    -- main/" becomes visible: a main/-only kill would never reach hooks/.
    { path = [[Machine\System\Services\pt-esc]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "HealthCheck", type = "sz", data = "/bin/false" },
        { name = "HealthCheckInterval", type = "dword", data = 1 },
        { name = "HealthCheckRetries", type = "dword", data = 3 },
        { name = "RestartWindow", type = "dword", data = 60 },
    } },
}

local vm = peinit.boot({
    name = "leak-orphans",
    files = peinit.merge(FILES, peinit.seed("pt-leak-orphans", SERVICES)),
})

local function status(service)
    return json.decode(vm:run("svctl --json status " .. service).stdout)
end

--- Start a keeper against a cgroup, once it exists.
local function keep(cgroup)
    wait_until(function()
        return vm:run("test -d " .. cgroup .. " && echo y").stdout:find("y") or nil
    end, { timeout = 30, interval = 0.2, desc = cgroup .. " to exist" })
    vm:run("/pt/keeper.sh " .. cgroup .. " >/dev/null 2>&1 &")
end

--- Wait for a warning against `service` whose path ends with `suffix`, and
--- return it. A warning is the pull side of a leak record, so this is how
--- each provocation's outcome is read back.
local function leak_warning(service, suffix, timeout)
    return wait_until(function()
        for _, w in ipairs(status(service).warnings or {}) do
            if w.path and w.path:sub(-#suffix) == suffix then return w end
        end
        return nil
    end, { timeout = timeout or 45, interval = 0.5,
           desc = service .. " to record a leak of " .. suffix })
end

test("a leaked hook cgroup is orphaned: recorded, and the service goes on running",
    {
        spec = {
            "peinit *cgroup.a-leaked-hook-or-health-cgroup-is-orphaned",
            "peinit *cgroup.a-post-kill-deadline-detects-a-survivor",
        },
    },
    function(t)
        -- hooks/ is created at launch, so start the service and then seed the
        -- keeper into hooks/ while the pre-hook (sleep 6) is still running.
        -- When the hook succeeds peinit kills hooks/ before the main process
        -- and arms the post-kill deadline; the keeper keeps hooks/ populated
        -- until it fires.
        vm:run("svctl --no-wait start pt-hookleak"):assert_ok()
        keep(ROOT .. "pt-hookleak/hooks")

        local warning = leak_warning("pt-hookleak", "/hooks")
        t:assert_eq(warning.type, "hooks",
            "the survivor was recorded as a leaked hooks cgroup")
        t:assert(warning.detected_at, "with a detection time")

        -- Orphaned, not fatal: a hook holds no service resources, so a stuck
        -- one does not make the service unmanageable. peinit carries on
        -- supervising it -- the main process started and the service is
        -- Active despite the leak.
        local view = status("pt-hookleak")
        t:assert_eq(view.state, "active",
            "the service kept running past the leak: " .. view.state)
    end)

test("a leaked pre-start check helper is treated the same way",
    { spec = "peinit *cgroup.a-leaked-check-helper-is-treated-the-same-way" },
    function(t)
        -- Freeze the tree so the helper cannot report, seed a keeper into
        -- checks/ so the kill at PreStartCheckTimeout leaves a survivor.
        vm:run("mkdir -p " .. ROOT .. "pt-chkleak"):assert_ok()
        vm:run("echo 1 > " .. ROOT .. "pt-chkleak/cgroup.freeze"):assert_ok()
        vm:run("svctl --no-wait start pt-chkleak"):assert_ok()
        keep(ROOT .. "pt-chkleak/checks")

        local warning = leak_warning("pt-chkleak", "/checks")
        t:assert_eq(warning.type, "helper",
            "the check helper's checks/ was recorded, with its own `helper` kind")

        -- The generation is bumped, so the next start builds a fresh tree
        -- rather than one that still holds the stuck helper. Thaw first, or
        -- the frozen leftovers would block a rebuild.
        vm:run("echo 0 > " .. ROOT .. "pt-chkleak/cgroup.freeze")
        vm:run("svctl --no-wait start pt-chkleak")
        wait_until(function()
            return vm:run("ls -d " .. ROOT .. "pt-chkleak%gen1").exit_code == 0 or nil
        end, { timeout = 30, interval = 0.5,
               desc = "pt-chkleak to build a fresh generation" })
        t:assert(vm:run("ls -d " .. ROOT .. "pt-chkleak%gen1").exit_code == 0,
            "the next start built into pt-chkleak%gen1, not the leaked tree")
    end)

test("a leak is announced on the event stream, carrying the service, path and kind",
    { spec = "peinit *cgroup.the-leak-event" },
    function(t)
        -- The push side: a peinit.cgroup.leaked event on the KMES ring,
        -- one per leak detected, in the same vocabulary the status
        -- warnings use, written in kebab-case. Both provocations above are
        -- on the ring by now. When it was detected is the record's own
        -- time, in the header, not a field of the payload.
        local events, raw = revstrm.snapshot(vm, { "peinit.cgroup.leaked" })
        t:assert(#events >= 2, "both leaks reached the event stream: " .. raw)

        local by_service = {}
        for _, e in ipairs(events) do
            local service = revstrm.field(e, "object.service.name")
            if service then by_service[service] = e end
        end
        for service, kind in pairs({ ["pt-hookleak"] = "hooks", ["pt-chkleak"] = "helper" }) do
            local e = by_service[service]
            t:assert(e, "a peinit.cgroup.leaked event names " .. service)
            t:assert_eq(revstrm.field(e, "object.cgroup.type"), kind,
                service .. "'s event carries its kind")
            local path = revstrm.field(e, "object.cgroup.path")
            t:assert(path and path:find(service, 1, true),
                service .. "'s event names the sub-cgroup path: " .. tostring(path))
            t:assert(e.header:match("^%d%d:%d%d:%d%d"),
                service .. "'s record has the time it was written: " .. e.header)
            t:assert(not revstrm.has(e, "detected_at_ns"),
                "and carries no monotonic detection time of its own: " .. e.payload)
        end
    end)

test("health escalation kills the service's root cgroup, taking hooks with it",
    { spec = "peinit *health.escalation-kills-the-root-cgroup" },
    function(t)
        -- pt-esc's probe always fails; HealthCheckRetries consecutive
        -- failures escalate. Escalation kills the service's *root* cgroup
        -- rather than just main/. A keeper in hooks/ -- a sibling of main/ --
        -- makes that visible: a main/-only kill would never touch hooks/, so
        -- the tree would empty and no leak would arise. Because escalation
        -- reclaims the whole root, the keeper keeps the root populated past
        -- the post-kill deadline and the *root* is recorded as leaked.
        vm:run("svctl --no-wait start pt-esc"):assert_ok()
        keep(ROOT .. "pt-esc/hooks")
        wait_until(function() return status("pt-esc").state == "active" or nil end,
            { timeout = 30, interval = 0.3, desc = "pt-esc to start" })

        -- The escalation itself: consecutive failures take the service off
        -- Active with the health check named.
        local escalated = wait_until(function()
            local v = status("pt-esc")
            return (v.state == "failed" or v.state == "backoff") and v or nil
        end, { timeout = 30, interval = 0.3, desc = "pt-esc to escalate" })
        t:assert_eq(escalated.cause, "health_check_failure",
            "the escalation was driven by the failing health check")

        -- The signature of a *root* kill: the whole tree is what peinit
        -- tried to reclaim, so the keeper (in hooks/) keeps the service
        -- *root* populated, and the root is recorded as a service_tree leak.
        local root_suffix = "peinit/pt-esc"
        local warning = wait_until(function()
            for _, w in ipairs(status("pt-esc").warnings or {}) do
                if w.path and w.path:sub(-#root_suffix) == root_suffix then return w end
            end
            return nil
        end, { timeout = 30, interval = 0.5,
               desc = "pt-esc's root to be recorded as leaked" })
        t:assert_eq(warning.type, "service_tree",
            "the service root was reclaimed and leaked -- escalation killed the " ..
            "whole tree, not just main/")
    end)
