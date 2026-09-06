#!/bin/sh
# Bring up provium's guest agent, so a test on the other end of the vsock
# can drive this VM.
#
# An autorun script, not a service. peinit runs everything in
# /lcl/policy/autorun.d on every boot, at phase 1.5 — after the registry
# is up and before the service graph starts. That is the right moment for
# this: a test wants to watch peinit bring services up, which it cannot do
# if the thing doing the watching is itself one of them. It also keeps the
# suite off the service definitions, so a test is free to add, break and
# remove them without the harness underneath it going away.
#
# peiso places this file and chmods it 0755; the binary beside it arrives
# as an ordinary injected file, which is why mkexec below is needed.
#
# peinit runs autorun scripts synchronously and relays their output, so
# this must return promptly. The agent is therefore backgrounded and
# reparented to peinit, which reaps it like any other orphan.
set -eu

agent=/usr/bin/provium-agent

if [ ! -f "$agent" ]; then
    echo "provium-agent: not at $agent; nothing to start" >&2
    exit 0
fi

# The execute bit is KACS's intrinsic "this is executable" flag rather
# than an advisory permission, and peiso's file injection writes 0644 —
# it has no way to know a payload is a program. mkexec sets it.
mkexec "$agent"

# Detached: no controlling terminal, and stdio pointed away from the
# console so the agent's own diagnostics cannot interleave with peinit's
# boot output, which several tests read as their only oracle.
"$agent" </dev/null >/run/provium-agent.log 2>&1 &

echo "provium-agent: started (pid $!)"
