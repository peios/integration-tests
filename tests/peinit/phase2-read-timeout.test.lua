-- Peinit TRM §2.5 — a registryd that hangs while Phase 2 is reading the
-- service graph costs peinit one LCS request timeout, and then recovery.
--
-- The hang has to start after Phase 1 is finished with the registry and
-- before Phase 2 is: registryd stopped any earlier would fail the Phase 1
-- probe or the step-8 provisioning read instead, both of which are other
-- claims with other recovery reasons. The seam between them is step 9,
-- which binds the control socket and then the jobs socket and then goes
-- straight on to Phase 2 — so the jobs socket appearing is the moment.
--
-- An autorun script (Phase 1 step 7) arms it. It finds registryd, leaves a
-- background watcher spinning on the jobs socket's path, and returns; when
-- step 9 binds the socket the watcher SIGSTOPs registryd, and peinit's
-- next registry request — the first of the Phase 2 reads — goes to a
-- source that will never answer. SIGSTOP rather than a kill: a dead source
-- is marked Down and fails its requests at once with EIO, which is a read
-- failure but not a hang. A stopped one keeps its slot and simply does not
-- reply, so the request waits out LCS's `RequestTimeoutMs` (30 seconds by
-- default) and comes back ETIMEDOUT.
--
-- The agent was started from the same autorun queue, so it is already up
-- when peinit gives up, and the console — watched as the boot goes — is
-- the record.

local peinit = require("helpers.peinit")
peinit.claim(1)

local FREEZE = table.concat({
    "#!/bin/sh",
    "pid=",
    "for d in /proc/[0-9]*; do",
    "  [ \"$(cat $d/comm 2>/dev/null)\" = registryd ] && pid=${d#/proc/}",
    "done",
    "[ -n \"$pid\" ] || { echo 'pt-freeze: no registryd to stop'; exit 0; }",
    "(",
    "  while [ ! -S /run/services/peinit/jobs.sock ]; do :; done",
    "  kill -STOP \"$pid\"",
    "  echo \"pt-freeze: registryd $pid stopped\" > /dev/console",
    ") </dev/null >/dev/null 2>&1 &",
    "echo \"pt-freeze: armed for registryd $pid\"",
    "",
}, "\n")

test("a registry read that times out during Phase 2 sends peinit to recovery",
    { spec = "peinit *phase2.a-registry-read-timeout-is-recovery" },
    function(t)
        local vm = peinit.boot({
            name = "phase2-timeout",
            stage = "autoruns",
            files = {
                ["lcl/policy/autorun.d/90-pt-freeze.sh"] = { FREEZE, exec = true },
            },
        })
        vm:console():expect("pt-freeze: registryd", peinit.STAGE_TIMEOUT)
        local frozen_at = os.time()
        vm:console():expect("entering recovery", 90)
        local waited = os.time() - frozen_at
        local log = vm:console():read_log()

        -- The hang landed where it was meant to: Phase 1 had finished
        -- with the registry, and Phase 2 had started reading.
        t:assert(log:find("pt-freeze: armed for registryd", 1, true),
            "the autorun found registryd: " .. log:sub(-1500))
        t:assert(log:find("peinit: phase2 boot starting", 1, true),
            "Phase 2 began before the hang took effect")

        -- The read came back ETIMEDOUT rather than hanging PID 1, and
        -- that is a Phase 2 recovery. The request that meets the stopped
        -- source is the first of the Phase 2 reads — in practice the open
        -- of Machine\System\Boot, just ahead of the service definitions —
        -- and the rule is the same for every one of them.
        local line = log:match("[^\r\n]*entering recovery[^\r\n]*")
        t:assert(line:find("entering recovery: Phase2", 1, true),
            "peinit named Phase 2 as the reason: " .. line)
        t:assert(line:find("RegistryRead", 1, true),
            "as a failed registry read: " .. line)
        t:assert(line:find("code: 110", 1, true) and line:find("TimedOut", 1, true),
            "that failed with ETIMEDOUT: " .. line)
        t:assert(not log:find("peinit: phase2 boot complete", 1, true),
            "no graph was booted")

        -- Bounded by the request timeout, not immediate: a source that
        -- failed its requests at once would have been back in a second.
        t:assert(waited >= 20,
            "peinit waited out the request timeout first (" .. waited .. "s)")
    end)
