#!/bin/sh
# Compose the prelude conformance VM: a root to take the kernel from, and
# a real initramfs to boot.
#
# Provium runs a profile's `build` on every invocation and holds no
# staleness logic of its own — it trusts the builder to be cheap when
# nothing changed. `peiso root` is not: it always composes from scratch
# and refuses a `--out` that already exists. So this script stamps its
# inputs and returns immediately when none of them has moved, exactly as
# the kernel-only profile's builder does.
#
# Three outputs:
#
#   {out}/root                  the composed root. provium boots the
#                               kernel out of it; the guest never sees
#                               the tree. Its boot/initramfs/ is the
#                               source for the next two.
#   {out}/irf/                  the initramfs source tree: the composed
#                               boot/initramfs plus this profile's test
#                               hooks and the payload that becomes the
#                               real root. Kept rather than deleted —
#                               a failing test is usually a question
#                               about what was in the initramfs, and
#                               this is the answer.
#   {out}/initramfs.cpio.gz     that tree, packed by the real mkirf.
#
# Packed with gzip, not mkirf's zstd default, because the kernel this
# suite boots sets CONFIG_RD_GZIP and no other decompressor: a zstd
# archive would leave the kernel with an empty rootfs and no /init.
#
# Run from this profile's own directory, with {out} as the only argument.
set -eu

out="$1"
root="$out/root"
irf="$out/irf"
initrd="$out/initramfs.cpio.gz"
stamp="$out/.build-stamp"

warn() { echo "prelude/build.sh: $*" >&2; }

# --- what this build needs from outside ------------------------------------
#
# mkirf: the shipped hook resolver and cpio writer, and half of what this
# suite tests. It must be the peiosutils applet — the one an image
# actually carries — rather than any other copy, so a repository build is
# preferred over whatever is on PATH.
mkirf=${PT_MKIRF:-}
if [ -z "$mkirf" ]; then
    for candidate in \
        ../../../peiosutils/target/release/mkirf \
        ../../../peiosutils/target/debug/mkirf
    do
        [ -x "$candidate" ] && { mkirf=$candidate; break; }
    done
fi
[ -n "$mkirf" ] || mkirf=$(command -v mkirf 2>/dev/null || true)
if [ -z "$mkirf" ]; then
    warn "no mkirf found (build peiosutils, or set PT_MKIRF)"
    exit 1
fi
mkirf=$(readlink -f "$mkirf")

# The provium agent. It becomes the real root's init, so prelude has
# something to hand off to and a test has something to ask about the
# state prelude left behind. Taken from the same overlay archive provium
# would inject into any other profile, so the agent in this guest is
# always the one the host on the other end of the vsock expects.
overlay=${PROVIUM_OVERLAY:-../../../provium/dist/agent-overlay.cpio.gz}
if [ ! -r "$overlay" ]; then
    warn "no provium agent overlay at $overlay (set PROVIUM_OVERLAY)"
    exit 1
fi
overlay=$(readlink -f "$overlay")

# --- staleness -------------------------------------------------------------
# Identity is name/size/mtime rather than content, as in the kernel-only
# profile: a rebuilt package always moves one of them, and hashing the
# kernel package on every test run would defeat the point.
fingerprint() {
    cat ../../peiso.toml peiso.toml build.sh
    cat hooks/* fixtures/*
    ls -lL ../../../pkgs/_pkgsOut_/ 2>/dev/null || true
    ls -lL "$mkirf" "$overlay" 2>/dev/null || true
}

current() {
    [ -d "$root" ] && [ -f "$initrd" ] && [ "$new" = "$(cat "$stamp" 2>/dev/null)" ]
}

new=$(fingerprint | sha256sum)
if current; then
    exit 0
fi

# Several provium processes may run at once (agents, a developer's shell
# and CI on one host), and every one of them runs this script. Only one
# may recompose: take the lock, then look at the stamp again — the winner
# has usually finished by the time the others get here. Without this, the
# losers would rm -rf the root the winner just composed, and a VM
# launching in that window fails to find its kernel.
mkdir -p "$out"
exec 9>"$out/.build-lock"
flock 9
if current; then
    exit 0
fi

# Remove the stamp first: a compose interrupted halfway must not leave a
# stamp claiming the tree beside it is current.
rm -f "$stamp" "$initrd"
rm -rf "$root" "$irf"
peiso root ../../peiso.toml peiso.toml --out "$root"

[ -d "$root/boot/initramfs" ] || {
    warn "the composed root has no boot/initramfs — no package landed in the initramfs root"
    exit 1
}

# --- the initramfs source tree ---------------------------------------------
# A copy, not the composed tree itself: what mkirf packs carries this
# suite's hooks and payload, and the composed root must stay exactly what
# peiso produced.
cp -a "$root/boot/initramfs" "$irf"

# The test hooks, into the packaged hook directory — the same place a
# feature peipkg would drop one. They are staged rather than packaged
# because a package would have to be published to be composed, and these
# change with the tests that use them.
mkdir -p "$irf/usr/libexec/prelude/hooks.d"
for h in hooks/*.sh; do
    cp "$h" "$irf/usr/libexec/prelude/hooks.d/$(basename "$h")"
    chmod 0755 "$irf/usr/libexec/prelude/hooks.d/$(basename "$h")"
done

# The scripted-hook library and anything else the hooks read, at
# /fixtures. A hook a test injects with `files` sources the same library,
# so an injected hook and a staged one report identically.
mkdir -p "$irf/fixtures"
cp fixtures/* "$irf/fixtures/"

# The payload that becomes the real root, at /fixtures/rootfs. The
# root-mount hook mounts a tmpfs on /mnt/rootfs, seeds it, and copies
# this in — so what prelude pivots into is an ordinary filesystem it
# found mounted, exactly as a squashfs or a disk partition would be.
#
#   bin/peinit2   the provium agent, under the first name in prelude's
#                 fallback chain. A test that wants the cmdline path
#                 appends its own init=.
#   proc sys dev  the mountpoints prelude mount-moves the kernel virtual
#                 filesystems onto. A root without them fails the handoff,
#                 which is itself a thing worth being able to test.
#   tmp run       the agent mounts a tmpfs on /tmp when it comes up as a
#                 standalone PID 1; /run is where a hook leaves anything
#                 it wants to survive the pivot.
payload="$irf/fixtures/rootfs"
rm -rf "$payload"
mkdir -p "$payload/bin" "$payload/proc" "$payload/sys" "$payload/dev" \
         "$payload/tmp" "$payload/run"

agent_tmp=$(mktemp -d "$out/agent.XXXXXX")
trap 'rm -rf "$agent_tmp"' EXIT
zcat "$overlay" | (cd "$agent_tmp" && cpio --quiet -idm 'sbin/provium-agent')
[ -f "$agent_tmp/sbin/provium-agent" ] || {
    warn "the agent overlay $overlay carries no sbin/provium-agent"
    exit 1
}
cp "$agent_tmp/sbin/provium-agent" "$payload/bin/peinit2"
# The execute bit is load-bearing under KACS — it is the intrinsic "this
# is executable" flag, not an advisory permission — and it has to survive
# the cpio, the copy the hook makes, and the SD the hook seeds.
chmod 0755 "$payload/bin/peinit2"

# --- pack -------------------------------------------------------------------
# mkirf resolves the hook DAG and writes the sequence files; this is the
# same call peiso makes when it builds an image, minus the compressor.
"$mkirf" --compress gzip "$irf" "$initrd"

printf '%s' "$new" > "$stamp"
