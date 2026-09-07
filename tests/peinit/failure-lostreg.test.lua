-- peinit TRM §14.1 — losing the registry: what registryd going away at
-- runtime does, and does not, cost.
--
-- The chapter's Phase 1 and Phase 2 halves are recovery-mode outcomes
-- and belong to §2.3 and §2.5, which anchor and test them. What is
-- peculiar to this chapter is the *runtime* half — the claim that peinit
-- holds a complete in-memory model and keeps supervising after the
-- registry has gone. Proving that needs a booted machine whose registry
-- is then taken away, which is what this file does: one VM, one
-- `svctl stop registryd` at file scope, and every test below reads the
-- state that leaves behind.
--
-- Two things are arranged for so that the machine survives long enough
-- to be asked. eventd is Critical in the shipped image and dies without
-- the registry, so a Critical budget exhaustion would sync and reboot
-- the VM out from under these tests; the seed downgrades it to
-- ErrorControl=Normal. That is the only reason for the override, and it
-- does not touch anything under test — the criticality of registryd
-- itself is read from a live process below, before the stop.
--
-- login-console is disabled for the length of the file because it takes
-- /dev/console once the boot settles (§11.6), after which peinit's own
-- console output is no longer what a test reads back — and one of the
-- claims here is a console warning.
--
-- `svctl stop registryd` rather than killing it: an explicit stop is not
-- a failure, so it takes registryd away without also setting the
-- Critical restart-and-reboot path running. What is being tested is life
-- without a registry, not what a Critical failure costs.

local peinit = require("helpers.peinit")
peinit.claim(1)

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },
    { path = [[Machine\System\Services\login-console]], values = {
        { name = "Disabled", type = "dword", data = 1 },
    } },
    { path = [[Machine\System\Services\eventd]], values = {
        { name = "ErrorControl", type = "dword", data = 0 },
    } },
    -- Resident, and started only when a test asks: the point is that a
    -- start still works with no registry to read a definition from.
    { path = [[Machine\System\Services\pt-live]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "100000" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
    } },
    -- Running from the boot, so there is something already supervised
    -- when the registry goes.
    { path = [[Machine\System\Services\pt-resident]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "100000" } },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
    } },
    -- Every ten seconds, so a firing lands inside a test's patience
    -- rather than at the top of the next minute. Persistent by default,
    -- so each firing also tries to write a last-run timestamp — which is
    -- the second claim this service carries.
    { path = [[Machine\System\Services\pt-timer]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/true" },
        { name = "Type", type = "dword", data = 1 },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Triggers", type = "multi", data = { "timer:*-*-* *:*:0/10" } },
    } },
}

local vm = peinit.boot({
    name = "lostreg",
    files = peinit.seed("pt-lostreg", SERVICES),
})

--- The main process peinit reports for a service, or nil.
local function main_pid(service)
    local status = json.decode(vm:run("svctl --json status " .. service).stdout)
    return status.current_job and status.current_job.pid
end

--- `/proc/<pid>/oom_score_adj`, as a string.
---
--- §5.4 sets it from ErrorControl and nothing else: -1000 for Critical
--- and the default for everything else. It is therefore the one place a
--- running system says out loud which services peinit considers
--- Critical, which is what two of the claims here turn on.
local function oom_score_adj(pid)
    return vm:read_file("/proc/" .. pid .. "/oom_score_adj"):gsub("%s+$", "")
end

-- Read while there is still a registryd to read from, and before the
-- stop below takes it away.
local registryd_oom = oom_score_adj(main_pid("registryd"))
local normal_oom = (function()
    vm:run("svctl start pt-live"):assert_ok()
    return oom_score_adj(main_pid("pt-live"))
end)()
local resident_pid_before = main_pid("pt-resident")

-- The provocation, once, for the whole file.
vm:run("svctl stop registryd"):assert_ok()
wait_until(function()
    return json.decode(vm:run("svctl --json status registryd").stdout).state == "inactive"
end, { timeout = 30, interval = 0.5, desc = "registryd to stop" })

test("registryd is a Critical service",
    { spec = "peinit *lostreg.registryd-is-a-critical-service" },
    function(t)
        -- ErrorControl is not exposed by a status query, so the oracle
        -- is what peinit did to the process: §5.4 marks a Critical
        -- service OOM-immune at -1000 and leaves everything else at the
        -- default. registryd carries no registry definition at all in
        -- this image — it is peinit's one compiled-in service — so this
        -- is peinit's own judgement rather than a seeded value.
        t:assert_eq(registryd_oom, "-1000",
            "registryd's main process was marked OOM-immune")
        t:assert_eq(normal_oom, "0",
            "while an ErrorControl=Normal service was left at the default, "
            .. "so -1000 means Critical rather than meaning nothing")
    end)

test("registryd going away does not stop peinit supervising anything",
    {
        spec = {
            "peinit *lostreg.registryd-going-away-does-not-stop-supervision",
            "peinit *lostreg.services-restarts-and-timers-keep-working-without-registryd",
        },
    },
    function(t)
        -- First, that the registry really is gone. Without this the rest
        -- of the test proves nothing: every assertion below would hold
        -- just as well on a machine whose registryd was still serving.
        local read = vm:run([[reg get 'Machine\System\Boot' MaxParallelStarts]])
        t:assert(read.exit_code ~= 0,
            "a registry read fails with no registryd: " .. read.stderr)

        -- Services keep running: the one that started at boot is the
        -- same process it was before the stop.
        t:assert_eq(main_pid("pt-resident"), resident_pid_before,
            "the service running before the stop is still the same process")

        -- The control socket keeps answering, for a query and for a
        -- bulk listing.
        local status = vm:run("svctl --json status pt-resident")
        status:assert_ok()
        t:assert(status.stdout:find('"state":"active"', 1, true),
            "and peinit still answers a status query about it: " .. status.stdout)
        vm:run("svctl list"):assert_ok()

        -- A start works, which is the sharpest form of the claim: the
        -- definition peinit launches from came out of the in-memory
        -- model, because there is nowhere else left for it to come from.
        vm:run("svctl stop pt-live"):assert_ok()
        vm:run("svctl start pt-live"):assert_ok()
        t:assert(main_pid("pt-live"), "a service started with no registry to read")

        -- And restarts keep working.
        local before = main_pid("pt-live")
        vm:run("svctl restart pt-live"):assert_ok()
        local after = main_pid("pt-live")
        t:assert(after and after ~= before,
            ("a restart replaced the process: %s -> %s"):format(
                tostring(before), tostring(after)))

        -- Timers keep firing. The started lines are the record: the
        -- service is a Oneshot, so each firing produces one.
        vm:console():expect("peinit: service pt-timer started", peinit.STAGE_TIMEOUT)
        local before_count = 0
        for _ in vm:console():read_log():gmatch("service pt%-timer started") do
            before_count = before_count + 1
        end
        wait_until(function()
            local count = 0
            for _ in vm:console():read_log():gmatch("service pt%-timer started") do
                count = count + 1
            end
            return count > before_count or nil
        end, { timeout = 40, interval = 1, desc = "another timer firing with no registryd" })
    end)

test("reload-config fails once there is no registryd to re-read",
    { spec = "peinit *lostreg.reload-config-fails-without-registryd" },
    function(t)
        -- The one command whose whole purpose is to go back to the
        -- registry. Everything else in this file answers from the model;
        -- this one cannot, and says so rather than quietly keeping the
        -- generation it has.
        local reload = vm:run("svctl reload-config")
        t:assert(reload.exit_code ~= 0,
            "reload-config was refused: " .. reload.stdout .. reload.stderr)
    end)

test("a timer firing cannot record its last run, and says the next boot will catch up",
    {
        spec =
        "peinit *lostreg.a-timer-last-run-timestamp-cannot-be-written-without-registryd",
    },
    function(t)
        -- The timestamp is a registry write (§9.3), so it is the one
        -- piece of supervision that does still need registryd. peinit
        -- neither drops the firing nor treats the failed write as fatal:
        -- it fires, fails the write, and names the consequence — a
        -- catch-up run after the next reboot that was not really missed.
        vm:console():expect(
            "peinit warning: recording the last run of timer *-*-* *:*:0/10 " ..
            "for service pt-timer failed; it will run catch-up again after a reboot",
            peinit.STAGE_TIMEOUT)
    end)
