-- peinit TRM §5.7 — leaked sub-cgroups: the one case of a populated tree
-- at the post-kill deadline that is not a leak.
--
-- A readiness timeout kills the service's tree and arms the cleanup a
-- `PostKillTimeout` later (5 s by default). The restart that follows
-- comes after `RestartDelay` (1 s by default), into the same tree, since
-- nothing has leaked yet to move the generation on. So when the cleanup
-- comes due the tree is populated — by the relaunched instance, not by a
-- survivor of the killed one — and peinit must drop the check rather
-- than record a `service_tree` leak and advance the generation.
--
-- Both defaults are left alone on purpose: the TRM's own numbers are the
-- scenario. `pt-relaunch` is Notify and never says READY=1, with a
-- `StartTimeout` long enough that the relaunch is well inside the first
-- cleanup's window, and `OnFailure` so the readiness timeout restarts it.
--
-- Three oracles, because "no leak" is a negative and each alone could be
-- vacuous: the status `warnings` array, the `peinit.cgroup.leaked` event on the
-- KMES ring (neither depends on the console), and where the instance
-- after the cleanup lives — a recorded leak advances the generation, and
-- the next start would build `pt-relaunch%gen1`.

local peinit = require("helpers.peinit")
local revstrm = require("helpers.revstrm")
peinit.claim(1)

local SERVICE = "pt-relaunch"
local ROOT = "/sys/fs/cgroup/peinit/" .. SERVICE

local vm = peinit.boot({
    name = "cgroup-gaps",
    files = peinit.seed("pt-cgroup-gaps", {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
        { path = [[Machine\System\Services\]] .. SERVICE, values = {
            { name = "ImagePath", type = "sz", data = "/bin/sleep" },
            { name = "Arguments", type = "multi", data = { "3600" } },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            -- Notify, and it never notifies: every start ends in a
            -- readiness timeout, which is a tree kill and a cleanup.
            { name = "Readiness", type = "dword", data = 0 },
            { name = "StartTimeout", type = "dword", data = 12 },
            { name = "RestartPolicy", type = "dword", data = 1 },
            { name = "RestartDelay", type = "dword", data = 1 },
            { name = "RestartMaxRetries", type = "dword", data = 10 },
            { name = "RestartWindow", type = "dword", data = 600 },
        } },
    }),
})

--- The pid in the service's main/, or nil.
local function main_pid()
    local ok, procs = pcall(function() return vm:read_file(ROOT .. "/main/cgroup.procs") end)
    return ok and procs:match("^(%d+)") or nil
end

--- The `peinit.cgroup.leaked` events on the ring naming `service` in
--- `object.service.name`.
local function leak_events(service)
    local found = revstrm.snapshot(vm, { "peinit.cgroup.leaked" })
    local out = {}
    for _, e in ipairs(found) do
        if revstrm.field(e, "object.service.name") == service then out[#out + 1] = e end
    end
    return out
end

test("a relaunch running in the tree when its post-kill deadline fires is not recorded as a leak",
    { spec = "peinit *cgroup.a-tree-back-in-use-is-not-a-leak" },
    function(t)
        vm:run("svctl --no-wait start " .. SERVICE):assert_ok()
        local first = wait_until(main_pid, { timeout = 30, interval = 0.2,
            desc = SERVICE .. "'s first instance to launch" })

        -- The readiness timeout kills the first instance's tree: that is
        -- the moment the cleanup is armed, five seconds out.
        wait_until(function() return main_pid() ~= first or nil end,
            { timeout = 40, interval = 0.2, desc = "the first instance's readiness timeout" })
        local killed_at = os.time()

        -- The relaunch, a second later, into the same tree.
        local second = wait_until(function()
            local pid = main_pid()
            return pid and pid ~= first and pid or nil
        end, { timeout = 20, interval = 0.2, desc = "the restart to relaunch" })
        local relaunched_at = os.time()
        t:assert(relaunched_at - killed_at <= 3,
            "premise: the relaunch landed well inside the five-second cleanup window (" ..
            (relaunched_at - killed_at) .. "s after the kill)")
        t:assert_eq(vm:read_file("/proc/" .. second .. "/cgroup"):gsub("%s+$", ""),
            "0::/peinit/" .. SERVICE .. "/main",
            "and it is in the same tree the killed instance was")

        -- Past the cleanup's deadline, with margin for a loaded host, and
        -- still before the relaunch's own twelve-second readiness timeout.
        pcall(wait_until, function() return os.time() >= killed_at + 9 or nil end,
            { timeout = 15, interval = 0.25, desc = "the post-kill deadline to pass" })
        t:assert_eq(main_pid(), second,
            "premise: the relaunch was still the tree's occupant when the deadline fired")

        local status = json.decode(vm:run("svctl --json status " .. SERVICE).stdout)
        t:assert_eq(#(status.warnings or {}), 0,
            "no leak is recorded against the service: " ..
            vm:run("svctl --json status " .. SERVICE).stdout)
        t:assert_eq(#leak_events(SERVICE), 0,
            "and no peinit.cgroup.leaked event names it")

        -- The generation did not move. Stop it, start it again: a leak
        -- would have advanced it, and this start would build %gen1.
        vm:run("svctl stop " .. SERVICE, { timeout = 60 })
        vm:run("svctl --no-wait start " .. SERVICE):assert_ok()
        local third = wait_until(function()
            local pid = main_pid()
            return pid and pid ~= second and pid or nil
        end, { timeout = 30, interval = 0.2, desc = "the next start to launch" })
        t:assert_eq(vm:read_file("/proc/" .. third .. "/cgroup"):gsub("%s+$", ""),
            "0::/peinit/" .. SERVICE .. "/main",
            "the next start runs in the tree it always had, not a new generation")
        t:assert(vm:run("ls -d '" .. ROOT .. "%gen1'").exit_code ~= 0,
            "and no %gen1 tree was ever built")
        vm:run("svctl stop " .. SERVICE, { timeout = 60 })
    end)
