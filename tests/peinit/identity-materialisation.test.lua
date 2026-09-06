-- Peinit TRM §4.1 — token materialisation: every service process runs
-- with a KACS token peinit obtained or created for it, and which token
-- that is depends on where in the service's lifecycle the process sits.
--
-- All of it is observable on a booted machine, because a token is a
-- property of a live process: `token show --pid N` reads the one the
-- child was launched with, and `svctl status` reports the identity peinit
-- believes it handed over. Where the claim is about a process that has
-- already exited — a pre-exec hook, a health check, a reload command —
-- the test has that process write its own user SID somewhere the test can
-- read afterwards, which is the only record such a process leaves.

local peinit = require("helpers.peinit")

local vm = peinit.boot({
    name = "identity-materialisation",
    files = peinit.seed("pt-identity", {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
        -- No Identity value at all.
        { path = [[Machine\System\Services\pt-noident]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/sleep" },
            { name = "Arguments", type = "multi", data = { "900" } },
            { name = "Type", type = "dword", data = 0 },
            { name = "Readiness", type = "dword", data = 1 },
            { name = "Triggers", type = "multi", data = { "boot" } },
        } },
        -- A service whose hooks are meant to outrank it. Each of the four
        -- contexts §4.1 tabulates is exercised here at once, which is the
        -- point: they run within one service and still differ.
        { path = [[Machine\System\Services\pt-hooks]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/sleep" },
            { name = "Arguments", type = "multi", data = { "900" } },
            { name = "Type", type = "dword", data = 0 },
            { name = "Readiness", type = "dword", data = 1 },
            { name = "Triggers", type = "multi", data = { "boot" } },
            { name = "Identity", type = "sz", data = "LocalService" },
            { name = "HookIdentity", type = "sz", data = "SYSTEM" },
            { name = "RuntimeDirectories", type = "multi", data = { "pt-hooks" } },
            { name = "ExecStartPre", type = "multi",
              data = { [[/bin/sh -c "token user --raw > /run/pt-hooks-pre.out"]] } },
            { name = "HealthCheck", type = "sz",
              data = [[/bin/sh -c "token user --raw > /run/pt-hooks/health.out"]] },
            { name = "HealthCheckInterval", type = "dword", data = 2 },
            { name = "ExecReload", type = "sz",
              data = [[/bin/sh -c "token user --raw > /run/pt-hooks/reload.out"]] },
        } },
        -- An identity no principal source designates for a service logon,
        -- so no token can be materialised for it at all. Demand-only: a
        -- boot trigger would have it restart until its budget ran out,
        -- and the cause `svctl status` reports would then be the budget
        -- rather than the failure this test is about.
        { path = [[Machine\System\Services\pt-unknown-principal]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/true" },
            { name = "Type", type = "dword", data = 1 },
            { name = "Readiness", type = "dword", data = 1 },
            { name = "Identity", type = "sz", data = "pt-nobody" },
        } },
    }),
})

-- `token show --pid N --raw --all` prints three sections, each row a name
-- and its attributes separated by run of spaces.
local function token_of(vm_, pid)
    local shown = vm_:run("token show --pid " .. pid .. " --raw --all")
    shown:assert_ok()
    local out = { principal = {}, groups = {}, privileges = {} }
    local section
    for _, line in ipairs(peinit.lines(shown.stdout)) do
        local head = line:match("^%[(%a+)")
        if head then
            section = head
        elseif section and out[section] then
            local name, attrs = line:match("^%s+(.-)%s%s+(.*)$")
            if name then out[section][name] = attrs end
        end
    end
    return out
end

local function status_of(vm_, service)
    local status = vm_:run("svctl status " .. service)
    status:assert_ok()
    return status.stdout
end

-- A service is started by the boot graph, so a test that reads its state
-- immediately after `phase2 boot complete` can catch it mid-launch.
local function wait_active(vm_, service)
    for _ = 1, 40 do
        local status = status_of(vm_, service)
        if status:find("^" .. service .. ": active") then return status end
        vm_:run("sleep 1")
    end
    return status_of(vm_, service)
end

local function wait_for_file(vm_, path)
    for _ = 1, 40 do
        local read = vm_:run("cat " .. path)
        if read.exit_code == 0 and read.stdout:find("S%-1%-5%-") then return read.stdout end
        vm_:run("sleep 1")
    end
    return vm_:run("cat " .. path).stdout
end

test("a SYSTEM service gets a token of its own rather than peinit's",
    { spec = "peinit *identity.a-service-never-shares-peinits-token" },
    function(t)
        -- registryd is the strongest case available: it runs as SYSTEM,
        -- like peinit, so sharing would be invisible in the user SID. The
        -- two tokens are nevertheless distinguishable, because the one
        -- peinit materialised for registryd carries groups peinit's own
        -- does not.
        local pid = status_of(vm, "registryd"):match("pid: (%d+)")
        t:assert(pid, "registryd is running")
        local mine, theirs = token_of(vm, 1), token_of(vm, pid)

        t:assert_eq(theirs.principal.user, mine.principal.user,
            "both run as SYSTEM, which is what makes this worth checking")

        local extra = {}
        for sid in pairs(theirs.groups) do
            if mine.groups[sid] == nil then extra[#extra + 1] = sid end
        end
        table.sort(extra)
        t:assert(#extra > 0,
            "registryd's token carries groups peinit's does not, so it is not peinit's token: "
                .. table.concat(extra, " "))
    end)

test("a definition with no Identity value runs as LocalService",
    { spec = "peinit *identity.an-absent-identity-defaults-to-localservice" },
    function(t)
        local status = wait_active(vm, "pt-noident")
        t:assert(status:find("identity: LocalService", 1, true),
            "peinit reports the default identity: " .. status)

        -- And reports it because it is true: LocalService is S-1-5-19.
        local pid = status:match("pid: (%d+)")
        t:assert(pid, "pt-noident is running: " .. status)
        t:assert_eq(token_of(vm, pid).principal.user, "S-1-5-19",
            "the process really holds a LocalService token")
    end)

test("a hook and the main process of one service hold different tokens",
    {
        spec = {
            "peinit *identity.materialisation-is-per-launched-process",
            "peinit *identity.hooks-use-hookidentity-when-set",
        },
    },
    function(t)
        -- pt-hooks declares Identity=LocalService and HookIdentity=SYSTEM.
        -- If a token were materialised once per service the two would be
        -- the same one, and they are not.
        local status = wait_active(vm, "pt-hooks")
        local pid = status:match("pid: (%d+)")
        t:assert(pid, "pt-hooks is running: " .. status)
        t:assert_eq(token_of(vm, pid).principal.user, "S-1-5-19",
            "the main process took Identity")

        -- The pre-exec hook has long exited; what it left behind is the
        -- user SID it printed while it ran.
        t:assert(wait_for_file(vm, "/run/pt-hooks-pre.out"):find("S-1-5-18", 1, true),
            "ExecStartPre ran as SYSTEM, which is HookIdentity and not Identity")
    end)

test("a health check runs as the service's own identity, not as HookIdentity",
    { spec = "peinit *identity.health-checks-always-use-identity" },
    function(t)
        -- The distinction is deliberate rather than incidental: a health
        -- check reports on the service's own health and should see what
        -- the service sees. pt-hooks sets HookIdentity=SYSTEM, so a check
        -- that honoured it would print S-1-5-18 here.
        wait_active(vm, "pt-hooks")
        t:assert(wait_for_file(vm, "/run/pt-hooks/health.out"):find("S-1-5-19", 1, true),
            "the health check ran as LocalService")
    end)

test("an ExecReload command runs as the service's own identity too",
    { spec = "peinit *identity.execreload-always-uses-identity" },
    function(t)
        wait_active(vm, "pt-hooks")
        vm:run("svctl --wait reload pt-hooks"):assert_ok()
        t:assert(wait_for_file(vm, "/run/pt-hooks/reload.out"):find("S-1-5-19", 1, true),
            "the reload command ran as LocalService despite HookIdentity=SYSTEM")
    end)

test("a token that cannot be materialised fails the start with no child",
    { spec = "peinit *identity.a-materialisation-failure-fails-the-start" },
    function(t)
        -- pt-unknown-principal names an identity that cannot be resolved,
        -- so materialisation fails. The cause peinit records is the one
        -- reserved for a failure on the parent's side of the fork, which
        -- is the claim: there was no child to fail.
        vm:run("svctl start pt-unknown-principal")
        local status = status_of(vm, "pt-unknown-principal")
        t:assert(status:find("parent_setup_failure", 1, true),
            "the start failed as ParentSetupFailure: " .. status)
        t:assert(not status:find("pid:", 1, true),
            "and no process was ever launched: " .. status)
    end)
