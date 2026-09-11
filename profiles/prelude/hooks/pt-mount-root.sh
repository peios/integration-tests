#!/usr/bin/sh
# /// hook
# contributes = ["rootfs-ready"]
# ///
#
# Mount the real root this suite hands prelude, from the payload the
# profile's build staged into the initramfs at /fixtures/rootfs.
#
# A tmpfs rather than a squashfs or a partition, because what prelude
# cares about is that /mnt/rootfs is on a different device from the
# initramfs and holds an executable init — not what kind of filesystem
# supplied it. Everything downstream of the mount (the mount-moves, the
# cleanup walk, the chroot, the exec) is identical either way, and a
# tmpfs needs no block device, no loop, and no image to keep in step
# with the tests.
#
# `contributes`, not `provides`: this hook is one part of getting a root
# ready, so anything ordered against rootfs-ready waits for every
# contributor rather than for whichever one finished first.
set -eu
. /fixtures/pt-hook.sh

# Report, and honour pt.mount-root= — a test that wants to see prelude's
# "no hook mounted a root filesystem" refusal sets `decline` here, and one
# testing the re-queue loop sets `defer:2`.
pt_gate mount-root

# prelude runs hooks with PATH=/usr/bin, so peiosutils (mount, mkdir, cp)
# and seed-sd resolve without this hook setting PATH itself.
mount -t tmpfs tmpfs /mnt/rootfs

# A freshly mounted tmpfs has no security descriptor, and KACS denies
# every access to an inode whose SD is MISSING. Without this the copy
# below fails, and so would the chroot and the exec after it. seed-sd's
# built-in descriptor (SYSTEM and Administrators, inheritable) is what a
# bootstrap tree wants and is enough here: everything in this guest runs
# as SYSTEM.
seed-sd /mnt/rootfs

# The payload becomes the root. Its /bin/peinit2 is the provium agent,
# which is what prelude execs at the handoff — so a test can ask the
# agent what prelude left behind.
#
# `--preserve=exec,timestamps`, not `-a`. On Peios `-a` is
# --preserve=all and "all" includes the security descriptor, which
# peiosutils' cp reads through kacs_get_sd — and that read is refused with
# EACCES on the initramfs payload, so `-a` failed every boot of this
# profile once peiosutils was productionised. The files do not want their
# initramfs descriptors anyway: they inherit from the seeded root they
# land in. `exec` is the one attribute that must come across — under KACS
# it is the intrinsic "this is executable" flag, and the agent at
# /bin/peinit2 is useless without it.
cp -R --preserve=exec,timestamps /fixtures/rootfs/. /mnt/rootfs/

# And seed it again. The `.` entry is the source directory itself, so the
# copy applies that directory's preserved attributes to /mnt/rootfs; the
# second stamp makes sure the new root ends up with the template whatever
# the copy did to it — the descriptor no longer comes across, but this is
# the step that guarantees it rather than an assumption about cp.
#
# Seeding twice rather than once after the copy, because the copy itself
# needs a stamped destination: an unseeded tmpfs denies everything, so
# there would be nothing to copy into.
seed-sd /mnt/rootfs

pt_mark mount-root outcome=satisfied
