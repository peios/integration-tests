-- peinit TRM §10.2 — `boot` passes the shutdown gate: it changes nothing,
-- so like the service queries it is answered while peinit shuts down.
--
-- Its own file because it spends its machine: the window it needs is a
-- shutdown in progress. The race is control-dispatch.test.lua's gate
-- test, with `boot` asked in place of `list`: a service that ignores
-- SIGTERM holds the shutdown open for its StopTimeout, the shutdown is
-- requested from inside a probe loop that is already hot, and the first
-- gated answer — a `start` refused as INVALID_STATE — proves the gate is
-- shut. `boot` is asked at that moment. The stubborn service keeps the
-- runtime, and its socket, alive for thirty seconds after, so this case
-- asserts a real answer rather than just the absence of a refusal.

local peinit = require("helpers.peinit")
peinit.claim(1)

local seed = peinit.seed("pt-bqs", {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },
    { path = [[Machine\System\Services\pt-bqs-stubborn]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        -- A loop rather than one long sleep: SIGTERM goes to the whole
        -- cgroup, and the shell, which ignores it, must outlive the child.
        { name = "Arguments", type = "multi",
          data = { "-c", "trap '' TERM; while :; do sleep 1; done" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "StopTimeout", type = "dword", data = 30 },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "Triggers", type = "multi", data = { "boot" } },
    } },
})

test("boot is answered during shutdown, when the lifecycle commands are refused",
    {
        spec = {
            "peinit *dispatch.boot-passes-the-shutdown-gate",
            "peinit *control.boot.is-checked-for-query-status",
        },
    },
    function(t)
        local probe, missed
        for attempt = 1, 3 do
            local vm = peinit.boot({ name = "bq-shutdown-" .. attempt, files = seed })
            t:assert(vm:run("svctl --json status pt-bqs-stubborn").stdout
                    :find('"state":"active"', 1, true),
                "the service that will hold the shutdown open is running")

            local run = vm:run(
                "i=0; while [ $i -lt 5000 ]; do " ..
                "  [ $i -eq 3 ] && { svctl shutdown poweroff >/dev/null 2>&1 & }; " ..
                "  out=$(svctl --json start pt-bqs-stubborn 2>&1); " ..
                "  case \"$out\" in " ..
                "    *INVALID_STATE*) " ..
                "      echo \"BOOT:$(svctl --json boot 2>&1)\"; " ..
                "      echo \"GATED:$out\"; " ..
                "      break;; " ..
                "    *'No such file'*) echo MISSED; break;; " ..
                "  esac; i=$((i+1)); done; echo END",
                { timeout = 120 })

            if run.stdout:find("GATED:", 1, true) then
                probe = run.stdout
                break
            end
            missed = run.stdout
            -- A machine that has begun shutting down cannot be asked twice;
            -- release it before the next attempt.
            vm:shutdown()
        end

        t:assert(probe,
            "a lifecycle command during shutdown was refused, in three attempts. " ..
            "Last: " .. tostring(missed))
        t:assert(probe:find('GATED:.*"code":"INVALID_STATE"'),
            "the gate was shut: a start was refused as invalid for the state: " .. probe)

        local boot = probe:match("BOOT:([^\r\n]*)") or ""
        t:assert(not boot:find("INVALID_STATE", 1, true),
            "boot was not refused by the gate: " .. boot)
        t:assert(boot:find('"status":"ok"', 1, true) and boot:find('"boot":{', 1, true),
            "it was answered, with the boot: " .. boot)
    end)
