#!/usr/bin/sh
# /// hook
# contributes = ["rootfs-strata-ready"]
# requires = ["rootfs-ready"]
# after = ["pt-nothing-supplies-this"]
# ///
#
# The hook that runs last, and the profile's stand-in for the packaged
# hook that assembles the real root's views once something has mounted it.
#
# It declares one of each kind of consumption, because between them they
# are the whole of prelude's scheduling:
#
#   requires   rootfs-ready must be ACHIEVED — every contributor finished
#              — so this hook cannot run before the root is mounted. It is
#              also what makes a declined or deferred mount hook
#              observable from here rather than only from prelude's own
#              refusal a phase later.
#   after      a capability nothing in this image supplies. Settled
#              vacuously, so it must not hold this hook back at all. That
#              is the property that lets a shared capability vocabulary
#              survive an image that implements none of it, and it is
#              silent when it breaks — the hook would simply never run.
set -eu
. /fixtures/pt-hook.sh

pt_gate late

# The root is mounted by now, so this hook can leave something in it that
# survives the pivot — which is how a test tells "the hook ran" apart from
# "the hook ran and prelude then threw the initramfs away".
mkdir -p /mnt/rootfs/run/pt
cp /run/pt/topology.n /mnt/rootfs/run/pt/topology.n 2>/dev/null || true
echo late > /mnt/rootfs/run/pt/late.ran

pt_mark late outcome=satisfied
