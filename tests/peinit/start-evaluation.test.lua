-- peinit TRM §5.2 — the pre-start evaluation: the three gates a start
-- passes before anything is forked.
--
-- §3.5 owns what a condition and an assert mean; what §5.2 adds is the
-- order they are asked in, and the fact that the terminal question comes
-- first because answering it later would have forked a check helper for
-- a start that was never going to happen. That last claim is the one
-- with a physical trace: a filesystem check runs in a `checks/`
-- sub-cgroup under the service's tree, so the presence or absence of
-- that directory says whether the helper ever ran.
--
-- The terminal in question is /dev/console, and the machine has exactly
-- one. `pt-tty-first` takes it at boot; `pt-tty-second` is triggered on
-- `boot:settled`, so it is started afterwards and finds the terminal
-- held -- and it carries a filesystem condition that would have failed,
-- which is what makes the missing `checks/` directory mean something.

local peinit = require("helpers.peinit")

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },
    { path = [[Machine\System\Services\pt-tty-first]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "TTYPath", type = "sz", data = "/dev/console" },
    } },
    { path = [[Machine\System\Services\pt-tty-second]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
        -- `boot:settled` rather than `boot`, so that this one is
        -- started after pt-tty-first rather than racing it for the
        -- terminal. It is the trigger the image's own login-console
        -- uses for the same reason.
        { name = "Triggers", type = "multi", data = { "boot:settled" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "TTYPath", type = "sz", data = "/dev/console" },
        -- Would fail, if it were ever evaluated.
        { name = "Conditions", type = "multi", data = { "path:/pt-not-here" } },
    } },
    -- A fresh start from Inactive whose condition does not hold.
    { path = [[Machine\System\Services\pt-condition]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "Conditions", type = "multi", data = { "path:/pt-not-here" } },
    } },
    -- Filesystem entries in both lists: a condition that holds and an
    -- assert that does not. Both answers come back from one helper run.
    { path = [[Machine\System\Services\pt-both-lists]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "Conditions", type = "multi", data = { "directory:/run", "path:/run" } },
        { name = "Asserts", type = "multi", data = { "file:/pt-not-here" } },
    } },
}

local vm = peinit.boot({ name = "evaluation", files = peinit.seed("pt-eval", SERVICES) })

local function settled(service)
    return wait_until(function()
        local out = json.decode(vm:run("svctl --json status " .. service).stdout)
        if out.state == "starting" or out.state == "inactive" then return nil end
        return out
    end, { timeout = 60, interval = 0.5, desc = service .. " to settle" })
end

local function entries(path)
    local ok, listing = pcall(function() return vm:listdir(path) end)
    if not ok then return nil end
    local set = {}
    for _, entry in ipairs(listing) do set[entry.name] = entry.entry_type end
    return set
end

test("a service whose terminal is held is skipped before its conditions are evaluated",
    { spec = "peinit *start.a-held-terminal-skips-before-the-checks" },
    function(t)
        -- One terminal, two services that want it. The first one to be
        -- started gets it.
        local first = settled("pt-tty-first")
        t:assert_eq(first.state, "active",
            "the service that got there first holds /dev/console")

        local second = settled("pt-tty-second")
        t:assert_eq(second.state, "skipped", "the second is Skipped")
        t:assert_eq(second.cause, "tty_unavailable",
            "with the terminal named as the cause, not its condition")

        -- And the condition was never evaluated. pt-tty-second's
        -- condition is a filesystem check, which runs in a forked helper
        -- placed in a `checks/` sub-cgroup under the service's tree --
        -- so if the terminal question had been asked second, that
        -- directory would exist. It does not.
        local tree = entries("/sys/fs/cgroup/peinit/pt-tty-second")
        t:assert(tree == nil or tree["checks"] == nil,
            "no check helper was forked for a start that was never going to happen")

        -- The comparison that makes that argument: an identical
        -- condition on a service with no terminal contention did fork
        -- one.
        t:assert_eq((entries("/sys/fs/cgroup/peinit/pt-condition") or {})["checks"],
            "directory",
            "while the same condition on a service with no terminal did fork a helper")
    end)

test("a fresh start whose condition fails goes straight from Inactive to Skipped",
    { spec = "peinit *start.the-evaluation-gates-the-transition" },
    function(t)
        -- For a fresh start the evaluation gates the transition: the
        -- service becomes Starting only after the checks pass. This one
        -- never passed them, so it never had a main process at all --
        -- `main/` is created when the main process launches, and there
        -- is none.
        local status = settled("pt-condition")
        t:assert_eq(status.state, "skipped", "the service was skipped")
        t:assert_eq(status.cause, "condition_skipped", "by its condition")
        t:assert(status.current_job == nil,
            "and peinit never held a job for it")

        local tree = entries("/sys/fs/cgroup/peinit/pt-condition")
        t:assert(tree, "the tree exists, because the check helper needed it")
        t:assert(tree["main"] == nil,
            "but nothing was ever launched into main/")
        t:assert(tree["health"] == nil, "and health/ was never created either")
    end)

test("one helper run answers both the conditions and the asserts",
    { spec = "peinit *start.one-helper-run-covers-both-lists" },
    function(t)
        -- pt-both-lists names filesystem paths in both lists: two
        -- conditions that hold and one assert that does not. Its outcome
        -- is AssertionError, which is only reachable if the conditions
        -- were evaluated and passed *and* the assert was evaluated and
        -- failed -- so both lists were decided.
        local status = settled("pt-both-lists")
        t:assert_eq(status.state, "failed", "the service failed")
        t:assert_eq(status.cause, "assertion_error",
            "on its assert, which means its conditions were evaluated and held")

        -- And they were decided from one run. There is one `checks/`
        -- sub-cgroup in the service's tree, and peinit has no mechanism
        -- to ask for a second: the completion path evaluates both lists
        -- against the results it gets back.
        local tree = entries("/sys/fs/cgroup/peinit/pt-both-lists")
        t:assert_eq(tree["checks"], "directory", "the helper ran in checks/")
        local extra = 0
        for name, kind in pairs(tree) do
            if kind == "directory" and name ~= "checks" then extra = extra + 1 end
        end
        t:assert_eq(extra, 0,
            "and it is the only sub-cgroup in the tree: one run, not one per list")
    end)
