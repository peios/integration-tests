#!/usr/bin/sh
# /// hook
# requires = ["rootfs-ready"]
# ///
#
# Copy anything a test staged in the initramfs into the root, before
# prelude chroots into it.
#
# This is the suite's one lever on what peinit is handed. The image is
# built once per profile and every test boots the same medium, so a test
# that needs a different registry seed, a different autorun script or a
# different provisioned-path declaration cannot get one by rebuilding the
# image. What it can do is inject a file into the INITRAMFS —
# `vm:boot({files = …})` appends a cpio the kernel unpacks last — and let
# this hook carry it across the handoff.
#
# Paths under /fixtures/stage are root-relative, so a test writing
# /fixtures/stage/lcl/policy/autorun.d/50-x.sh puts a script in the
# autorun queue peinit reads at phase 1.5.
#
# `requires`, not `after`: this must run once the root is genuinely
# mounted, and `requires` is the edge that waits for a capability to be
# ACHIEVED rather than merely settled. Nothing declares this hook a
# provider of anything, so it never delays a boot that stages nothing.
set -eu

stage=/fixtures/stage

# The overwhelmingly common case, since only a handful of tests stage
# anything. Say nothing and get out of the way: this hook's own log lines
# would otherwise appear in every console a test reads as its oracle.
[ -d "$stage" ] || exit 0

. /usr/libexec/prelude/hook-log.sh
hook_log_init pt-stage

# The root is an overlay with a tmpfs upper, so these writes land in the
# upper and are gone at reboot — which is what a per-boot lever should
# do. A test that wants state to survive a reboot cannot get it here.
#
# `cp -a` preserves the execute bit, which under KACS is the intrinsic
# "this is executable" flag rather than an advisory permission: an
# autorun script copied without it is one peinit will refuse to spawn.
# The security descriptor is an extended attribute and is preserved too,
# but the files come from the initramfs and carry none, so what each one
# ends up with is inherited from the directory it lands in.
cp -a "$stage/." /mnt/rootfs/

log_ok "staged the test's files into the root"
