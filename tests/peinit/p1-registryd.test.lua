-- Peinit TRM §2.3 step 6 — what Phase 2 does with the registryd it was
-- handed, and what a registry with no services at all boots into.
--
-- Both claims are about the seam between the two phases, so both need a
-- boot whose registry differs from the image's: one where the registry
-- defines registryd (which the shipped image does not, because registryd
-- bootstraps the registry and so can never be an ordinary entry), and
-- one where it defines nothing at all.
--
-- The second is reached by replacing the image's own seed-apply autorun
-- with a script that does nothing. Every service on this image comes
-- from `/lcl/policy/autoapply.d`, applied at Phase 1 step 7 by
-- `10-apply-seeds.sh`; a no-op in its place leaves peinit with the
-- registry it provisioned itself and nothing more, which is the
-- unprovisioned first boot §2.3 describes.

local peinit = require("helpers.peinit")
peinit.claim(1)

--- The compiled-in definition, as a registry entry — the same image path
--- and arguments peinit holds, plus a description nothing else would put
--- there so the merge is visible.
local REGISTRYD_DEFINITION = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },
    { path = [[Machine\System\Services\registryd]], values = {
        { name = "ImagePath", type = "sz", data = "/sbin/registryd" },
        { name = "Arguments", type = "multi", data = {
            "Machine=/var/state/loregd/Machine.hive",
            "Users=/var/state/loregd/Users.hive",
        } },
        { name = "Type", type = "dword", data = 0 },
        { name = "Readiness", type = "dword", data = 0 },
        { name = "ErrorControl", type = "dword", data = 1 },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Description", type = "sz", data = "pt-merged-description" },
    } },
}

local function starttime(vm, service)
    local pid
    for _ = 1, 40 do
        pid = vm:run("svctl status " .. service).stdout:match("pid: (%d+)")
        if pid then break end
        vm:run("sleep 1")
    end
    if not pid then error(service .. " never reported a pid") end
    -- Field 22 of /proc/pid/stat is the process's start time in clock
    -- ticks since boot. Read through `cut` rather than parsed in Lua
    -- because field 2 is a comm in parentheses and may hold spaces.
    local ticks = vm:run("cut -d' ' -f22 /proc/" .. pid .. "/stat").stdout:match("%d+")
    return tonumber(ticks), pid
end

test("a registry definition of registryd is merged onto the running one, not started again",
    { spec = "peinit *phase1.a-registry-definition-of-registryd-is-merged-not-restarted" },
    function(t)
        local vm = peinit.boot({
            name = "regd-merge",
            files = peinit.seed("pt-regd", REGISTRYD_DEFINITION),
        })

        -- The merge happened: the description is one only the seeded
        -- definition carries, and it is what svctl reports for the
        -- service that has been running since Phase 1.
        local status = vm:run("svctl --json status registryd")
        status:assert_ok()
        t:assert(status.stdout:find("pt-merged-description", 1, true),
            "the registry's definition reached the running service: " .. status.stdout)
        t:assert(status.stdout:find('"state":"active"', 1, true),
            "which is still active")

        -- And nothing restarted it. Three ways of saying so, because the
        -- claim is a negative: Phase 2 announced no registryd start, the
        -- process is older than the first service Phase 2 did start, and
        -- there is one of it.
        local log = vm:console():read_log()
        for _, name in ipairs(peinit.started_services(log)) do
            t:assert(name ~= "registryd",
                "Phase 2 announced no registryd start")
        end

        local registryd = starttime(vm, "registryd")
        local eventd = starttime(vm, "eventd")
        t:assert(registryd and eventd, "both processes reported a start time")
        t:assert(registryd < eventd,
            "registryd is the older process, so it is the Phase 1 one (" ..
                registryd .. " against " .. eventd .. ")")

        local count = vm:run(
            'n=0; for p in /proc/[0-9]*; do ' ..
            '[ "$(cat "$p/comm" 2>/dev/null)" = registryd ] && n=$((n+1)); ' ..
            'done; echo $n').stdout:match("%d+")
        t:assert_eq(count, "1", "and there is exactly one registryd process")
    end)

test("an empty service key boots into a Phase 2 with no services rather than into recovery",
    { spec = "peinit *phase1.an-empty-service-key-boots-with-no-services" },
    function(t)
        -- The self-healing half of the schema guard: an absent value
        -- reads as zero and passes, so a registry with nothing in it is
        -- a boot with nothing to start rather than a failed probe.
        local vm = peinit.boot({
            name = "regd-empty",
            files = {
                ["lcl/policy/autorun.d/10-apply-seeds.sh"] =
                    { "#!/bin/sh\necho pt-seeds-not-applied\nexit 0\n", exec = true },
            },
        })
        local log = vm:console():read_log()
        t:assert(log:find("pt-seeds-not-applied", 1, true),
            "the replacement autorun ran, so no seed was applied")

        local services = vm:run([[reg ls 'Machine\System\Services' --keys-only]])
        services:assert_ok()
        t:assert_eq(#peinit.lines(services.stdout), 0,
            "Machine\\System\\Services is empty: " .. services.stdout)

        -- Phase 2 ran and started nothing, which is the documented
        -- outcome rather than the recovery an unprovisioned system used
        -- to get.
        t:assert(log:find("peinit: phase2 boot complete", 1, true),
            "Phase 2 completed: " .. log:sub(-700))
        t:assert(not log:find("entering recovery", 1, true),
            "and no recovery was entered")
        t:assert_eq(#peinit.started_services(log), 0, "with no service started")

        -- registryd is still there: it is peinit's own, not the
        -- registry's, so an empty registry does not take it away.
        local list = vm:run("svctl list")
        list:assert_ok()
        t:assert(list.stdout:find("registryd", 1, true),
            "registryd is the one service a registry-less boot has: " .. list.stdout)
    end)
