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
peinit.claim(1)

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
    -- Demand-only, with a filesystem condition on a path that *exists*, so
    -- the only thing that can skip it is the check failing to report. Its
    -- checks/ cgroup is frozen before the start, which is how the helper is
    -- made to miss its deadline.
    { path = [[Machine\System\Services\pt-chk-timeout]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "PreStartCheckTimeout", type = "dword", data = 3 },
        { name = "Conditions", type = "multi", data = { "path:/" } },
    } },
    -- Two services that want /dev/tty9, a virtual console nothing in the
    -- image claims. It used to be /dev/tty3, until the image's
    -- login-console.reg grew login-tty1..3 (PEI-1187): login-tty3 holds
    -- /dev/tty3 from boot:settled on, so the waiter was skipped at the
    -- cacheable pass with TtyUnavailable and never forked the helper this
    -- test freezes. The waiter carries a filesystem condition, so its
    -- start forks a helper; freezing the helper holds it pending while
    -- the holder takes the terminal.
    { path = [[Machine\System\Services\pt-tty-holder]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "TTYPath", type = "sz", data = "/dev/tty9" },
    } },
    { path = [[Machine\System\Services\pt-tty-waiter]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "TTYPath", type = "sz", data = "/dev/tty9" },
        { name = "PreStartCheckTimeout", type = "dword", data = 30 },
        { name = "Conditions", type = "multi", data = { "path:/" } },
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

--- Create a service's cgroup root and freeze it before the start, so that a
--- pre-start check helper cloned into its `checks/` sub-cgroup cannot run and
--- therefore cannot report. cgroup2 propagates the freeze to descendants, so
--- the helper is frozen the moment it lands. This is the only way to make a
--- `stat()` of an existing path miss `PreStartCheckTimeout` from a guest: the
--- helper never blocks on I/O here, so it is stopped rather than delayed.
local function freeze_root(service)
    local root = "/sys/fs/cgroup/peinit/" .. service
    vm:run("mkdir -p " .. root):assert_ok()
    vm:run("echo 1 > " .. root .. "/cgroup.freeze"):assert_ok()
    return root
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

test("a check that does not report in time is treated as not satisfied",
    { spec = "peinit *check.a-check-that-does-not-report-in-time-is-not-satisfied" },
    function(t)
        -- pt-chk-timeout's condition is `path:/`, which exists -- so a helper
        -- that reported would pass it and the service would start. The helper
        -- is frozen in its checks/ cgroup before the start, so it never
        -- reports, and PreStartCheckTimeout (3s) fires. The fail-safe
        -- direction is "not satisfied", so the condition fails and the
        -- service is Skipped -- the opposite of what a reported `path:/`
        -- would have produced.
        freeze_root("pt-chk-timeout")
        vm:run("svctl --no-wait start pt-chk-timeout"):assert_ok()

        -- The helper did land, and it is frozen: the timeout is a real
        -- deadline being missed, not a helper that never started.
        wait_until(function()
            local ok, events = pcall(function()
                return vm:read_file("/sys/fs/cgroup/peinit/pt-chk-timeout/checks/cgroup.events")
            end)
            return ok and events:find("populated 1") and events:find("frozen 1") or nil
        end, { timeout = 15, interval = 0.3, desc = "the check helper to be frozen in checks/" })

        local status = settled("pt-chk-timeout")
        t:assert_eq(status.state, "skipped",
            "the service was skipped, though the path it checked exists: " ..
            tostring(status.cause))
        t:assert_eq(status.cause, "condition_skipped",
            "because the unreported check was treated as not satisfied, and a " ..
            "failed condition skips")
    end)

test("the terminal is re-checked after the helper returns, not carried over from before it ran",
    { spec = "peinit *start.the-terminal-is-rechecked-after-the-helper" },
    function(t)
        -- The waiter has a filesystem condition, so its start forks a helper
        -- and the terminal question is asked twice: once in the cacheable
        -- pass before the fork, and again on the helper's completion. Freeze
        -- the waiter's helper so it stays pending -- during a fresh start
        -- from Inactive the service is not yet Starting, so it does not
        -- itself hold the terminal while it waits.
        freeze_root("pt-tty-waiter")
        vm:run("svctl --no-wait start pt-tty-waiter"):assert_ok()
        wait_until(function()
            local ok, events = pcall(function()
                return vm:read_file("/sys/fs/cgroup/peinit/pt-tty-waiter/checks/cgroup.events")
            end)
            return ok and events:find("populated 1") or nil
        end, { timeout = 15, interval = 0.3, desc = "the waiter's helper to be pending" })

        -- At the cacheable pass /dev/tty9 was free, so the waiter got past
        -- the terminal gate and into the helper. Now the holder takes the
        -- terminal while the helper is stuck.
        local holder = wait_until(function()
            vm:run("svctl start pt-tty-holder")
            local out = json.decode(vm:run("svctl --json status pt-tty-holder").stdout)
            return out.state == "active" and out or nil
        end, { timeout = 30, interval = 0.5, desc = "pt-tty-holder to take /dev/tty9" })
        t:assert_eq(holder.state, "active", "the holder now owns /dev/tty9")

        -- Thaw the helper. It reports `path:/` satisfied, so the condition
        -- passes -- the only thing that can stop the waiter now is the
        -- terminal, and only if peinit re-checks it. It does: the waiter is
        -- Skipped with TtyUnavailable rather than starting on a terminal
        -- another service holds.
        vm:run("echo 0 > /sys/fs/cgroup/peinit/pt-tty-waiter/cgroup.freeze"):assert_ok()
        local waiter = settled("pt-tty-waiter")
        t:assert_eq(waiter.state, "skipped",
            "the waiter was skipped rather than started onto a held terminal: " ..
            tostring(waiter.cause))
        t:assert_eq(waiter.cause, "tty_unavailable",
            "on the terminal, which was free when the helper was forked and taken " ..
            "while it ran -- so the answer came from a fresh re-check, not the cache")
    end)
