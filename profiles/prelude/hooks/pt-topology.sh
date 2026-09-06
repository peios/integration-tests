#!/usr/bin/sh
# /// hook
# contributes = ["initramfs-ready"]
# ///
#
# The initramfs's own preparation, and the profile's stand-in for the
# packaged StrataFS topology hook that does this job in a shipped image.
#
# What it is really here for is the capability it names. `initramfs-ready`
# is the one capability with a rule: every hook that does not supply it is
# implicitly ordered after it, an edge no hook declares and mkirf
# materialises into the sequence. A profile whose hook set never supplies
# it would leave that rule untested in the one place it can be observed —
# an image being built and then booted.
#
# The work itself is deliberately small. /run/pt is where the scripted
# hooks keep their run counters, and it has to exist before the first one
# runs, which is exactly what being part of initramfs-ready buys.
set -eu
. /fixtures/pt-hook.sh

pt_gate topology

mkdir -p /run/pt

pt_mark topology outcome=satisfied
