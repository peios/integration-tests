-- peinit TRM §5.5 — the base environment: four layers, built from
-- scratch in the parent and handed to `execve`.
--
-- A process's environment is fixed at exec and readable for the rest of
-- its life at /proc/<pid>/environ, so the whole chapter is checkable
-- from one booted machine — provided the layers are stocked with values
-- that could only have come from one of them. That is what the seed
-- below does: `PT_GLOBAL` exists only in the global layer, `PT_OVERRIDE`
-- exists in the global layer *and* in the service's own `Environment`
-- with a different value, and the protocol names are set in both
-- configurable layers to something peinit must refuse to pass through.
--
-- The service is `/bin/sleep`, which reads no configuration and opens
-- nothing, so its environment is exactly what it was handed.

local peinit = require("helpers.peinit")

local FILES = {
    -- Reads the *initial* environment out of /proc rather than running
    -- `env`, so that nothing the shell itself sets or inherits can be
    -- mistaken for something peinit passed.
    ["pt/dump-env.sh"] = [[
cat /proc/self/environ > /run/pt-hook-environ
]],
}

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Init]] },
    { path = [[Machine\System\Init\EnvVars]], values = {
        { name = "PT_GLOBAL", type = "sz", data = "global" },
        { name = "PT_OVERRIDE", type = "sz", data = "from-global" },
        -- All four protocol names, set in the layer whose write access
        -- the chapter treats as equivalent to compromising every
        -- service. None of them may reach a service.
        { name = "NOTIFY_SOCKET", type = "sz", data = "/pt/bogus-notify.sock" },
        { name = "LISTEN_FDS", type = "sz", data = "9" },
        { name = "LISTEN_FDNAMES", type = "sz", data = "pt-bogus" },
        { name = "LISTEN_PID", type = "sz", data = "1" },
    } },
    { path = [[Machine\System\Services]] },
    { path = [[Machine\System\Services\pt-env]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "Environment", type = "multi",
          data = { "PT_OVERRIDE=from-service", "PT_SERVICE=own",
                   "NOTIFY_SOCKET=/pt/also-bogus.sock" } },
        { name = "ExecStartPre", type = "multi", data = { "/bin/sh /pt/dump-env.sh" } },
    } },
}

local vm = peinit.boot({
    name = "env",
    files = peinit.merge(FILES, peinit.seed("pt-env", SERVICES)),
})

--- A NUL-separated environment block, as a name -> value map.
local function parse_environ(block)
    local env = {}
    for entry in block:gmatch("[^%z]+") do
        local name, value = entry:match("^([^=]*)=(.*)$")
        if name then env[name] = value end
    end
    return env
end

local function service_environ(service)
    local pid = wait_until(function()
        local ok, procs = pcall(function()
            return vm:read_file("/sys/fs/cgroup/peinit/" .. service .. "/main/cgroup.procs")
        end)
        return ok and procs:match("^(%d+)") or nil
    end, { timeout = 60, interval = 0.5, desc = service .. " to have a main process" })
    return parse_environ(vm:read_file("/proc/" .. pid .. "/environ")), pid
end

test("the compiled-in layer supplies PATH, and the global layer adds to it",
    {
        spec = {
            "peinit *env.the-compiled-in-path",
            "peinit *env.global-envvars-become-variables",
        },
    },
    function(t)
        local env = service_environ("pt-env")
        t:assert_eq(env.PATH, "/sbin:/bin",
            "PATH is the compiled-in value: executables are addressed through " ..
            "the root-level StrataFS views, not through /usr")
        t:assert_eq(env.PT_GLOBAL, "global",
            "a value under Machine\\System\\Init\\EnvVars became a variable of that name")
    end)

test("the service's own Environment overrides the layers below it",
    { spec = "peinit *env.the-services-own-environment-overrides-the-layers-below" },
    function(t)
        -- PT_OVERRIDE is set in both configurable layers, to different
        -- values. Layer 3 wins.
        local env = service_environ("pt-env")
        t:assert_eq(env.PT_OVERRIDE, "from-service",
            "the definition's Environment beat the global layer")
        t:assert_eq(env.PT_SERVICE, "own",
            "and a name only it sets is present as well")
    end)

test("NOTIFY_SOCKET is always set, and cannot be overridden from either configurable layer",
    {
        spec = {
            "peinit *env.notify-socket-is-always-set",
            "peinit *env.the-protocol-names-are-filtered-out-of-the-configurable-layers",
        },
    },
    function(t)
        local env = service_environ("pt-env")
        -- The seed set NOTIFY_SOCKET in EnvVars *and* in the service's
        -- own Environment. Neither reached the service: the name is
        -- dropped from both layers before peinit inserts its own, so a
        -- service cannot break its own notification protocol.
        t:assert_eq(env.NOTIFY_SOCKET, "/run/services/peinit/notify.sock",
            "NOTIFY_SOCKET is peinit's socket")
        t:assert(not env.NOTIFY_SOCKET:find("bogus"),
            "and neither configured value survived: " .. env.NOTIFY_SOCKET)
    end)

test("the LISTEN_ variables are absent when no descriptors are injected, even when the global layer sets them",
    {
        spec = {
            "peinit *env.the-listen-variables-appear-only-with-injected-descriptors",
            "peinit *env.listen-pid-is-appended-by-the-child",
        },
    },
    function(t)
        -- pt-env has no fd store (FdStoreMax defaults to 0), so nothing
        -- is being injected and all three names must be absent. The
        -- global layer sets all three, which is the case the name filter
        -- exists for: without it an `EnvVars\LISTEN_FDS=9` would point
        -- an fd-store-less service's sd_listen_fds at whatever happened
        -- to sit at descriptor 3.
        local env = service_environ("pt-env")
        for _, name in ipairs({ "LISTEN_FDS", "LISTEN_FDNAMES", "LISTEN_PID" }) do
            t:assert(env[name] == nil,
                name .. " is absent, got " .. tostring(env[name]))
        end
    end)

test("peinit sets no HOME, USER, LOGNAME, SHELL or TERM, and passes nothing of its own through",
    {
        spec = {
            "peinit *env.no-home-user-logname-shell-or-term",
            "peinit *env.nothing-is-inherited-from-peinit",
        },
    },
    function(t)
        local env = service_environ("pt-env")
        for _, name in ipairs({ "HOME", "USER", "LOGNAME", "SHELL", "TERM" }) do
            t:assert(env[name] == nil,
                name .. " is not set: Peios identity is a token, not a passwd entry" ..
                " (got " .. tostring(env[name]) .. ")")
        end

        -- Nothing is inherited, which is a different claim from the one
        -- above: peinit's own startup environment is not empty, and none
        -- of what is in it is passed through.
        local own = parse_environ(vm:read_file("/proc/1/environ"))
        t:assert(own.TERM, "peinit's own environment holds TERM: " .. tostring(own.TERM))
        for name in pairs(own) do
            t:assert(env[name] == nil or name == "PATH",
                "peinit's " .. name .. " was not passed through to the service")
        end
    end)

test("a hook receives the identical environment to the main process, and no LISTEN_FDS",
    {
        spec = {
            "peinit *env.hooks-and-probes-receive-the-identical-environment",
            "peinit *env.hooks-never-receive-listen-fds",
        },
    },
    function(t)
        local main = service_environ("pt-env")
        local hook = parse_environ(wait_until(function()
            local ok, block = pcall(function() return vm:read_file("/run/pt-hook-environ") end)
            return ok and block ~= "" and block or nil
        end, { timeout = 30, interval = 0.5, desc = "pt-env's pre-hook to dump its environment" }))

        -- Built through the same path, so the same four layers and the
        -- same NOTIFY_SOCKET.
        for name, value in pairs(main) do
            t:assert_eq(hook[name], value,
                "the hook has the same " .. name .. " as the main process")
        end
        for name in pairs(hook) do
            -- `PWD` is the shell's own: the hook is `/bin/sh <script>`,
            -- and dash publishes its working directory into its
            -- environment before the script runs. peinit sets no such
            -- variable in any of the four layers, and the main process
            -- -- which is not a shell -- does not have it.
            t:assert(main[name] ~= nil or name == "PWD",
                "and nothing extra: the hook has " .. name .. " and the service does not")
        end

        -- Stored descriptors go to the main process alone, so a hook
        -- never sees the LISTEN_ set even where there is one.
        for _, name in ipairs({ "LISTEN_FDS", "LISTEN_FDNAMES" }) do
            t:assert(hook[name] == nil, "the hook has no " .. name)
        end
    end)

test("a change to the global layer reaches a service at its next start, not while it is running",
    { spec = "peinit *env.changes-take-effect-at-the-next-start" },
    function(t)
        local before, pid = service_environ("pt-env")
        t:assert_eq(before.PT_GLOBAL, "global", "the running process has the boot's snapshot")

        vm:run([[reg set 'Machine\System\Init\EnvVars' PT_GLOBAL sz:changed]]):assert_ok()
        vm:run("svctl reload-config"):assert_ok()

        -- The snapshot is refreshed on reload-config, and the running
        -- process is untouched by it: an environment is fixed at exec
        -- and peinit does not pretend otherwise.
        t:assert_eq(parse_environ(vm:read_file("/proc/" .. pid .. "/environ")).PT_GLOBAL,
            "global", "the running process still has the old value")

        vm:run("svctl restart pt-env"):assert_ok()
        local after = wait_until(function()
            local env = service_environ("pt-env")
            return env.PT_GLOBAL == "changed" and env or nil
        end, { timeout = 30, interval = 0.5, desc = "pt-env to restart with the new value" })
        t:assert_eq(after.PT_GLOBAL, "changed", "and the next start picks it up")
    end)

test("registryd alone is launched without the global layer",
    { spec = "peinit *env.registryd-does-not-receive-the-global-layer" },
    function(t)
        -- registryd is started in Phase 1, before EnvVars has been read
        -- at all, so the exemption is only observable on a restart --
        -- which is exactly the case it exists for. The exemption is a
        -- trust rule: write access to EnvVars would otherwise be write
        -- access into the daemon that enforces who may write EnvVars.
        vm:run("svctl restart registryd"):assert_ok()
        local registryd = wait_until(function()
            local ok, procs = pcall(function()
                return vm:read_file("/sys/fs/cgroup/peinit/registryd/main/cgroup.procs")
            end)
            local pid = ok and procs:match("^(%d+)")
            if not pid then return nil end
            local env = parse_environ(vm:read_file("/proc/" .. pid .. "/environ"))
            -- Wait for the restarted process rather than the one that
            -- Phase 1 started, which would pass for the wrong reason.
            return env.NOTIFY_SOCKET and env or nil
        end, { timeout = 30, interval = 0.5, desc = "registryd to restart" })

        t:assert(registryd.PT_GLOBAL == nil,
            "registryd did not receive the global layer: PT_GLOBAL is " ..
            tostring(registryd.PT_GLOBAL))
        t:assert_eq(registryd.PATH, "/sbin:/bin",
            "it has the compiled-in base")
        t:assert(registryd.NOTIFY_SOCKET, "and the protocol layer, which is not configurable")

        -- The layer was available at the time: another service started
        -- after the same reload has it.
        t:assert(service_environ("pt-env").PT_GLOBAL,
            "while an ordinary service started from the same snapshot does have it")
    end)

-- The last two claims each need a boot of their own, because they are
-- about the layer being built differently rather than about a service.

test("an EnvVars PATH replaces the compiled-in one rather than adding to it",
    { spec = "peinit *env.an-envvars-path-overrides-the-compiled-in-one" },
    function(t)
        local other = peinit.boot({
            name = "env-path",
            files = peinit.seed("pt-env-path", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Init]] },
                { path = [[Machine\System\Init\EnvVars]], values = {
                    { name = "PATH", type = "sz", data = "/pt-only/bin" },
                    { name = "PT_ADDS", type = "sz", data = "added" },
                } },
                { path = [[Machine\System\Services]] },
                { path = [[Machine\System\Services\pt-path]], values = {
                    { name = "ImagePath", type = "sz", data = "/bin/sleep" },
                    { name = "Arguments", type = "multi", data = { "3600" } },
                    { name = "Triggers", type = "multi", data = { "boot" } },
                    { name = "Identity", type = "sz", data = "SYSTEM" },
                    { name = "Readiness", type = "dword", data = 1 },
                } },
            }),
        })

        local pid = wait_until(function()
            local ok, procs = pcall(function()
                return other:read_file("/sys/fs/cgroup/peinit/pt-path/main/cgroup.procs")
            end)
            return ok and procs:match("^(%d+)") or nil
        end, { timeout = 60, interval = 0.5, desc = "pt-path to start" })
        local env = parse_environ(other:read_file("/proc/" .. pid .. "/environ"))

        -- PATH is the one name in the global layer that replaces
        -- something rather than adding: the compiled-in value is gone
        -- rather than prepended or appended to.
        t:assert_eq(env.PATH, "/pt-only/bin",
            "the global layer's PATH replaced the compiled-in /sbin:/bin")
        t:assert_eq(env.PT_ADDS, "added",
            "while every other name in the same layer still adds")
    end)

test("a malformed entry in the global layer fails the whole layer, which at boot is recovery",
    { spec = "peinit *env.a-malformed-envvars-entry-fails-the-layer" },
    function(t)
        -- A value name containing `=` cannot be an environment variable
        -- name, and peinit will not build a partial layer around it: it
        -- fails the layer, and a layer that cannot be built at boot
        -- leaves peinit with no environment to start services from.
        --
        -- `stage = false`, because this boot is not expected to reach
        -- Phase 2 at all.
        local other = peinit.boot({
            name = "env-bad",
            stage = false,
            files = peinit.seed("pt-env-bad", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Init]] },
                { path = [[Machine\System\Init\EnvVars]], values = {
                    { name = "PT=BAD", type = "sz", data = "malformed" },
                } },
            }),
        })

        other:console():expect("peinit: entering recovery", peinit.STAGE_TIMEOUT)
        local log = other:console():read_log()
        t:assert(not log:find("peinit: phase2 boot complete", 1, true),
            "the boot did not complete Phase 2")
    end)
