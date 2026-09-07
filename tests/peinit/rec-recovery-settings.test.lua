-- Peinit TRM §2.8 — the registryd recovery starts is started with the
-- settings this boot parsed, not with defaults.
--
-- The observable is the daemon's own environment. `peios.notifysocket=`
-- moves where the sd_notify socket is bound, and peinit tells every service
-- it launches where to write through `NOTIFY_SOCKET` — so a recovery
-- registryd carrying the overridden path in its environment is a recovery
-- that used this boot's `SupervisorSettings` rather than a fresh default
-- set. A recovery that used defaults would point it at
-- /run/services/peinit/notify.sock, and the daemon would report readiness
-- into a socket nobody was listening on.
--
-- The override deliberately stays inside /run/services/peinit. The notify
-- bind is what creates that directory chain, and a path anywhere else takes
-- PID 1 to recovery for an unrelated reason (PEI-804) — which on this file
-- would be indistinguishable from the recovery being tested.
--
-- Entry is a boot attempt counter at the default threshold, because that is
-- the arm where recovery starts a registryd at all: Phase 1 has not reached
-- its own, so recovery must, and it is that launch whose settings are in
-- question.

local peinit = require("helpers.peinit")
peinit.claim(1)

local MOVED = "/run/services/peinit/pt-recovery.sock"

local REPORTER = table.concat({
    "#!/bin/sh",
    "pid=",
    "for d in /proc/[0-9]*; do",
    "  [ \"$(cat $d/comm 2>/dev/null)\" = registryd ] && pid=${d#/proc/}",
    "done",
    "notify=none",
    "if [ -n \"$pid\" ]; then",
    "  tr '\\0' '\\n' < /proc/$pid/environ > /tmp/pt-env",
    "  while read -r line; do",
    "    case $line in NOTIFY_SOCKET=*) notify=${line#NOTIFY_SOCKET=} ;; esac",
    "  done < /tmp/pt-env",
    "fi",
    "echo pt-rec: begin",
    "echo pt-rec: pid=$pid",
    "echo pt-rec: notify=$notify",
    "echo pt-rec: rundir=$(ls /run/services/peinit 2>&1 | tr '\\n' ',')",
    "echo pt-rec: end",
    "sleep 3600",
    "",
}, "\n")

test("a registryd started by recovery uses the settings this boot parsed",
    { spec = "peinit *recovery.a-recovery-registryd-uses-this-boots-settings" },
    function(t)
        local console = peinit.boot_to_recovery(t, {
            name = "recovery-settings",
            agent_timeout = 25,
            append = "peios.notifysocket=" .. MOVED,
            files = peinit.merge(
                { ["lcl/bin/recsh"] = { REPORTER, exec = true } },
                { [".peinit/boot-attempts"] = "3\n" }
            ),
        })
        t:assert(console:find("peinit: entering recovery: BootAttemptThresholdReached", 1, true),
            "this is the arm where recovery starts a registryd: " .. console:sub(-600))
        t:assert(console:match("pt%-rec: pid=(%d+)"),
            "recovery started a registryd: " .. console:sub(-600))
        t:assert_eq(console:match("pt%-rec: notify=([^\r\n]*)"), MOVED,
            "and pointed it at the socket this boot's command line named")
    end)
