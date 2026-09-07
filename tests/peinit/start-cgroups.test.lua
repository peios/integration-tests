-- peinit TRM §5.1 — the cgroup tree peinit builds around every service.
--
-- The chapter's claims are all about directories on a real cgroup2
-- filesystem, which is the one part of starting a service that leaves a
-- durable trace: /sys/fs/cgroup/peinit is still there when the boot is
-- over, one subtree per service that was started, and a service that was
-- never started has no subtree at all.
--
-- Three staged definitions give the three shapes the chapter
-- distinguishes: one that runs (root, main, hooks, health), one that is
-- never triggered (nothing), and one whose start is abandoned during the
-- pre-start filesystem check (root and checks/ only, because the main
-- process never launched).

local peinit = require("helpers.peinit")
peinit.claim(1)

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },
    -- Runs and stays running: /bin/sleep with Readiness=Alive is Active
    -- the moment exec succeeds, so the tree is complete and stable for
    -- the whole test.
    { path = [[Machine\System\Services\pt-tree]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
    } },
    -- No Triggers, so Phase 2 never starts it. It exists in the registry
    -- and in `svctl list`, which is what makes its absence from the
    -- cgroup hierarchy evidence rather than a typo.
    { path = [[Machine\System\Services\pt-untriggered]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
    } },
    -- A condition on a path that is not there. The check runs in a
    -- forked helper (§5.2), so the service's tree is created for the
    -- helper and then abandoned before anything else in the launch.
    { path = [[Machine\System\Services\pt-skipped]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "Conditions", type = "multi", data = { "path:/pt-not-here" } },
    } },
}

local vm = peinit.boot({ name = "cgroups", files = peinit.seed("pt-cgroups", SERVICES) })

--- The names in a directory listing, as a set.
local function entries(path)
    local set = {}
    for _, entry in ipairs(vm:listdir(path)) do
        set[entry.name] = entry.entry_type
    end
    return set
end

test("a started service gets root, main, hooks and health, and its process is in main",
    {
        spec = {
            "peinit *cgroup.every-service-gets-a-tree",
            "peinit *preexec.the-child-is-cloned-straight-into-the-main-cgroup",
        },
    },
    function(t)
        local tree = entries("/sys/fs/cgroup/peinit/pt-tree")
        for _, child in ipairs({ "main", "hooks", "health" }) do
            t:assert_eq(tree[child], "directory",
                child .. "/ exists under the service root")
        end

        -- The tree is not just shaped right, it is populated the way the
        -- chapter says: knowing which processes belong to a service is
        -- one of the two things peinit uses cgroups for, and main/ is
        -- where the main process is.
        local procs = vm:read_file("/sys/fs/cgroup/peinit/pt-tree/main/cgroup.procs")
        local pid = procs:match("^(%d+)")
        t:assert(pid, "main/cgroup.procs names a process: " .. procs)

        -- And it has been there since it was created rather than having
        -- been moved in afterwards: clone3(CLONE_INTO_CGROUP) places the
        -- child in main/ at creation, so the process's own view of its
        -- cgroup is main/ and there is no window in which it was
        -- anywhere else. `/proc/<pid>/cgroup` is relative to the cgroup2
        -- root, so the /sys/fs/cgroup prefix is not in it.
        local own = vm:read_file("/proc/" .. pid .. "/cgroup"):gsub("%s+$", "")
        t:assert_eq(own, "0::/peinit/pt-tree/main",
            "the process's own cgroup is the service's main/")

        -- Nothing else joined it, and nothing is sitting in the service
        -- root, which is what the "no internal processes" split buys.
        t:assert_eq(vm:read_file("/sys/fs/cgroup/peinit/pt-tree/cgroup.procs"), "",
            "the service root holds no processes of its own")
    end)

test("the directory name under peinit/ is the service name unchanged",
    { spec = "peinit *cgroup.the-id-is-the-encoded-service-name" },
    function(t)
        -- Service names are already restricted to the encoder's safe set
        -- (§3.1), so every byte survives and the id equals the name. The
        -- observable form of that is that every subtree under
        -- /sys/fs/cgroup/peinit is named after a service peinit knows,
        -- with no escape sequence anywhere in the hierarchy.
        local known = {}
        for line in vm:run("svctl list").stdout:gmatch("[^\r\n]+") do
            local name = line:match("^([%w%-%._]+)%s")
            if name and name ~= "SERVICE" then known[name] = true end
        end
        t:assert(known["pt-tree"], "svctl list names the staged service")

        local seen = 0
        for name, kind in pairs(entries("/sys/fs/cgroup/peinit")) do
            -- cgroupfs puts its own interface files in the directory
            -- alongside the subtrees; only the directories are ids.
            if kind == "directory" and name ~= "jobs" then
                t:assert(known[name],
                    "the subtree `" .. name .. "` is named after a service")
                t:assert(not name:find("%%"),
                    "and carries no percent-escape: " .. name)
                seen = seen + 1
            end
        end
        t:assert(seen > 1, "there is more than one service subtree to check")
    end)

test("peinit enables no controllers and sets no limits on a service's cgroups",
    { spec = "peinit *cgroup.no-accounting-and-no-limits" },
    function(t)
        -- A controller has to be enabled in a parent's
        -- `cgroup.subtree_control` before it appears in the children.
        -- peinit enables none, so the accounting and limit files simply
        -- do not exist in a service's tree — which is a stronger
        -- statement than their holding default values.
        for _, dir in ipairs({ "/sys/fs/cgroup/peinit",
                               "/sys/fs/cgroup/peinit/pt-tree" }) do
            t:assert_eq(vm:read_file(dir .. "/cgroup.subtree_control"), "",
                dir .. " enables no controllers for its children")
        end

        local tree = entries("/sys/fs/cgroup/peinit/pt-tree/main")
        for _, limit in ipairs({ "memory.max", "pids.max", "cpu.max", "io.max" }) do
            t:assert(tree[limit] == nil,
                "main/ has no " .. limit .. ", so nothing is being limited")
        end
    end)

test("nothing is created for a service that never starts, and main/ only when the main process launches",
    { spec = "peinit *cgroup.sub-cgroups-are-created-on-demand" },
    function(t)
        -- pt-untriggered is in the registry and in the service table but
        -- has no trigger, so Phase 2 never starts it. No part of its
        -- tree exists, not even the root.
        local root = entries("/sys/fs/cgroup/peinit")
        t:assert(root["pt-untriggered"] == nil,
            "a service that never started has no cgroup at all")

        -- pt-skipped got as far as the pre-start filesystem check, which
        -- forks a helper into checks/ under the service root, and then
        -- abandoned the start. So the root and checks/ are there and
        -- main/ and health/ are not: they are created when the main
        -- process launches, and it never did.
        t:assert(root["pt-skipped"], "the skipped service's root was created")
        local skipped = entries("/sys/fs/cgroup/peinit/pt-skipped")
        t:assert_eq(skipped["checks"], "directory",
            "the check helper's checks/ sub-cgroup was created")
        t:assert(skipped["main"] == nil, "but main/ was not")
        t:assert(skipped["health"] == nil, "and neither was health/")

        t:assert_contains(vm:run("svctl status pt-skipped").stdout, "skipped",
            "the start really was abandoned rather than merely slow")
    end)
