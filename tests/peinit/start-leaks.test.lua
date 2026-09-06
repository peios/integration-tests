-- peinit TRM §5.7 — leaked sub-cgroups, and §5.1's generations, which is
-- what a leak does to the next start.
--
-- The chapter's own scenario is a process in uninterruptible sleep, and
-- nothing in a VM can be put into D-state on demand. But §5.1 is
-- explicit that `populated` is not the only condition, and that the
-- second one is `rmdir` returning EBUSY — "the tree cannot be given up,
-- which covers that case *and* the ones where nothing is running but the
-- directory still will not go". That second condition is reachable:
-- cgroupfs refuses to remove a directory that has a child directory, so
-- creating one sub-cgroup inside a service's `main/` makes its tree
-- unreclaimable while leaving every process in it perfectly killable.
--
-- The service has to be stopped the hard way for any of this to run.
-- peinit reclaims a service's tree from the post-kill deadline it arms
-- when it escalates a stop to SIGKILL, so `pt-leak` traps SIGTERM and
-- carries a two-second StopTimeout: the graceful stop expires, peinit
-- kills the cgroup, and the cleanup that follows meets the directory it
-- cannot remove.

local peinit = require("helpers.peinit")

local FILES = {
    -- Ignores SIGTERM, so `svctl stop` has to escalate. The `sleep`
    -- children are ordinary processes and die with the cgroup kill --
    -- nothing here is unkillable, which is the point: what peinit finds
    -- at the deadline is an empty tree it still cannot remove.
    ["pt/stubborn.sh"] = [[
trap '' TERM
while : ; do /bin/sleep 1 ; done
]],
}

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },
    -- The console is one of the two places a leak is reported, and the
    -- image's own login-console takes /dev/console once the boot settles
    -- (§11.6), after which peinit's console output is no longer what a
    -- test reads back. Disabling it keeps the terminal peinit's for the
    -- length of this file.
    { path = [[Machine\System\Services\login-console]], values = {
        { name = "Disabled", type = "dword", data = 1 },
    } },
    { path = [[Machine\System\Services\pt-leak]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi", data = { "/pt/stubborn.sh" } },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "StopTimeout", type = "dword", data = 2 },
    } },
}

local vm = peinit.boot({
    name = "leaks",
    files = peinit.merge(FILES, peinit.seed("pt-leaks", SERVICES)),
})

local ROOT = "/sys/fs/cgroup/peinit/pt-leak"

--- Provoke the leak, once, for the whole file: plant a sub-cgroup inside
--- the service's `main/` and then stop the service.
---
--- Returns the `warnings` array from a status query, once peinit has
--- recorded them. Everything in this file is about the state that
--- leaves behind, so one VM and one provocation serve all of it.
local warnings = (function()
    -- A directory under main/ is itself a cgroup, and cgroupfs refuses
    -- `rmdir` on a cgroup with a child. It is created before the stop so
    -- that it is already in place when the cleanup runs.
    vm:run("mkdir " .. ROOT .. "/main/pt-planted"):assert_ok()

    -- The stop escalates and its operation times out, so the command
    -- reports a failure. That is the path being exercised, not a
    -- problem: what matters is the state afterwards.
    vm:run("svctl stop pt-leak")

    return wait_until(function()
        local status = json.decode(vm:run("svctl --json status pt-leak").stdout)
        return status.warnings and #status.warnings > 0 and status.warnings or nil
    end, { timeout = 40, interval = 0.5, desc = "peinit to record the leak" })
end)()

test("a cgroup that cannot be removed is recorded as a leak even with nothing running in it",
    { spec = "peinit *cgroup.rmdir-ebusy-also-records-a-leak" },
    function(t)
        -- Nothing survived the kill: the tree is unpopulated. The only
        -- thing wrong with it is that `rmdir` will not take it, which is
        -- the second of the two conditions and the one that a
        -- `populated`-only check would have missed.
        t:assert_eq(vm:read_file(ROOT .. "/cgroup.procs"), "",
            "the service root holds no processes")
        t:assert_eq(vm:read_file(ROOT .. "/main/cgroup.procs"), "",
            "and neither does main/, so nothing survived the kill")

        local paths = {}
        for _, warning in ipairs(warnings) do paths[warning.path] = warning.type end
        t:assert(paths[ROOT .. "/main"],
            "main/ was recorded as leaked: it holds the planted sub-cgroup")
        t:assert(paths[ROOT],
            "and so was the service root, which holds main/")
    end)

test("starting a service that has leaks returns a warning in the acknowledgement",
    { spec = "peinit *cgroup.a-start-on-a-service-with-leaks-warns" },
    function(t)
        -- The pull side survives the moment of detection: an operator who
        -- was not watching, and who is now simply starting the service,
        -- is told anyway. This is also the start the next test looks at,
        -- so the service is left running.
        --
        -- `--no-wait`, because the acknowledgement is what carries this.
        -- With the default wait svctl goes on to render the operation's
        -- final status instead, whose own `warnings` are the leak
        -- records of §5.7's status-query bullet rather than this one.
        local started = vm:run("svctl --no-wait start pt-leak")
        t:assert_contains(started.stdout, "warnings:",
            "the start acknowledgement carries a warnings section")
        t:assert_contains(started.stdout,
            "service has leaked sub-cgroups from a previous generation",
            "saying the service has leaked sub-cgroups from a previous generation")
        t:assert_contains(started.stdout, "I/O problem requiring investigation",
            "and that this indicates an I/O problem needing investigation")
    end)

test("a leak moves the service to a fresh tree, and the old one stays behind",
    { spec = "peinit *cgroup.a-leak-moves-the-service-to-a-fresh-tree" },
    function(t)
        wait_until(function()
            return vm:run("svctl status pt-leak").stdout:find("pt%-leak: active")
        end, { timeout = 30, interval = 0.5, desc = "pt-leak to start again" })

        -- The next start builds at <id>%gen<N>, with the separator the
        -- chapter names, rather than reusing a tree it could not empty.
        local fresh = vm:stat(ROOT .. "%gen1")
        t:assert_eq(fresh.entry_type, "directory",
            "the new generation's tree is at pt-leak%gen1")
        local procs = vm:read_file(ROOT .. "%gen1/main/cgroup.procs")
        t:assert(procs:match("^%d+"), "and the restarted process is in it: " .. procs)

        -- The old tree is not cleaned up behind it; it persists until
        -- the next reboot, still holding the directory that could not be
        -- removed.
        t:assert_eq(vm:stat(ROOT).entry_type, "directory",
            "the leaked tree is still in the hierarchy")
        t:assert_eq(vm:stat(ROOT .. "/main/pt-planted").entry_type, "directory",
            "with the sub-cgroup that made it unreclaimable still inside it")
    end)

test("two leaks against one tree advance the generation once",
    { spec = "peinit *cgroup.the-generation-advances-once-per-tree" },
    function(t)
        -- The cleanup reported `main/` and the service root separately,
        -- so two leaks were recorded. They are the same tree, so the
        -- first advances the generation and the second finds itself
        -- already behind it -- if each leak advanced it the next start
        -- would have built at %gen2.
        t:assert_eq(#warnings, 2, "two leaks were recorded against one tree")
        t:assert(vm:run("ls -d " .. ROOT .. "%gen1").exit_code == 0,
            "the generation advanced to 1")
        t:assert(vm:run("ls -d " .. ROOT .. "%gen2").exit_code ~= 0,
            "and not to 2, so it advanced once rather than once per leak")

        -- Deduplicated by path and kind, so neither leak was recorded
        -- twice by a later cleanup pass over the same tree.
        local seen = {}
        for _, warning in ipairs(warnings) do
            local key = warning.path .. "|" .. warning.type
            t:assert(not seen[key], "each leak appears once: " .. key)
            seen[key] = true
        end
    end)

test("a status query carries one warnings entry per leak, with path, type and time",
    {
        spec = {
            "peinit *cgroup.status-carries-a-warnings-entry-per-leak",
            "peinit *cgroup.the-leak-type-vocabulary",
        },
    },
    function(t)
        for _, warning in ipairs(warnings) do
            t:assert(warning.path and warning.path:find(ROOT, 1, true),
                "the entry names the sub-cgroup path: " .. tostring(warning.path))
            -- A leaked service root, and a `main/` that cannot be given
            -- up without giving up the tree, are both `service_tree` --
            -- the most serious of the four, since it means the whole
            -- tree including main/ could not be reclaimed.
            t:assert_eq(warning.type, "service_tree",
                "and its kind, in the shared vocabulary")
            t:assert(warning.detected_at and warning.detected_at:find("T"),
                "and the time it was detected: " .. tostring(warning.detected_at))
        end
    end)

test("a leak reaches the console once, in the same vocabulary the status query uses",
    {
        spec = {
            "peinit *cgroup.a-leak-is-both-pushed-and-queryable",
            "peinit *cgroup.the-leak-console-line",
            "peinit *cgroup.a-leak-is-announced-once",
        },
    },
    function(t)
        local log = vm:console():read_log()

        -- The push side. An operator who was not asking about pt-leak
        -- still learns that the machine is now missing a cgroup it can
        -- never reclaim, in the same `service_tree` spelling the status
        -- query uses.
        t:assert_contains(log,
            "peinit: service pt-leak leaked its service_tree cgroup " .. ROOT .. ";",
            "the console named the service, the kind and the path")

        -- Once, and only once. The tree has been through a restart and a
        -- second cleanup pass since it was first recorded; recording is
        -- idempotent, so it is not re-announced.
        local count = 0
        for _ in log:gmatch("service pt%-leak leaked its service_tree cgroup " ..
            ROOT:gsub("%p", "%%%0") .. ";") do
            count = count + 1
        end
        t:assert_eq(count, 1,
            "the service root's leak was announced exactly once, not on every pass")
    end)
