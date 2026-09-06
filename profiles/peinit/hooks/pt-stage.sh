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
# NOT `cp -a "$stage/." /mnt/rootfs/`, which is the obvious spelling and
# is wrong in a way that took three agents and a wrong bug report to
# find. The `.` entry IS the source directory, so `cp -a` copies its
# attributes onto the destination directory — and the security
# descriptor is an extended attribute. A stage directory unpacked from
# the initramfs carries none, so `/` came out of the copy with whatever
# KACS synthesises: a single SYSTEM ACE, losing the Everyone GRGX that
# live-boot stamps.
#
# The consequence was not subtle. Execute is traverse on Peios, and an
# explicit chdir gets no SeChangeNotifyPrivilege bypass, so every service
# whose identity is not SYSTEM failed its pre-exec `chdir("/")` with
# EACCES — including the image's own resolvd, trustd and timed. Any boot
# that staged a file lost them; any boot that staged nothing kept them,
# which is what made it look like a race in prelude (PEI-800).
#
# So: merge child by child, and never touch a directory that already
# exists. `cp -a` on each leaf still preserves the execute bit, which
# under KACS is the intrinsic "this is executable" flag rather than an
# advisory permission — an autorun script copied without it is one peinit
# refuses to spawn.
merge() {
    # $1 source directory, $2 destination directory (must exist).
    #
    # `local` is a dash extension rather than POSIX, and it is
    # load-bearing: without it `entry` and `name` are globals, and the
    # first recursion clobbers the loop variable of the call above it —
    # so a stage with any subdirectory copies part of itself and stops.
    local entry name
    for entry in "$1"/* "$1"/.[!.]*; do
        # An unmatched glob comes through as itself; the image has no
        # `find`, so this is the loop available.
        [ -e "$entry" ] || continue
        name=${entry##*/}
        if [ -d "$entry" ] && [ -d "$2/$name" ]; then
            merge "$entry" "$2/$name"
        else
            cp -a "$entry" "$2/$name"
        fi
    done
}
merge "$stage" /mnt/rootfs

log_ok "staged the test's files into the root"
