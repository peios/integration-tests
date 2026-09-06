#!/bin/sh
# Compose the peinit conformance VM: a live medium, and the initramfs that
# boots it.
#
# Unlike the other two profiles this one builds a whole Peios image,
# because peinit's contract (Peinit TRM §2.1) is that something has already
# assembled the root: chroot'd into it, mount-moved /proc, /sys and /dev in,
# and built the StrataFS /bin and /sbin views. Nothing short of a real
# initramfs running the real hooks delivers that, and the hook that
# assembles the root — live-boot's mount-root.sh — needs a real medium to
# find. So the build produces one.
#
# Provium runs a profile's `build` on every invocation and holds no
# staleness logic of its own. `peiso iso` composes from scratch and takes
# minutes, so this script stamps its inputs and returns immediately when
# none of them has moved, exactly as the other two profiles' builders do.
#
# Four outputs:
#
#   {out}/image/root            the composed root. provium takes the kernel
#                               from it and reads the command line live-boot
#                               ships in it; the guest never sees the tree
#                               itself — it gets the squashfs made from it.
#   {out}/medium.iso            the medium, under a fixed name. Attached as
#                               a virtio disk, and what live-boot's hook
#                               scans the bus for. A symlink, because peiso
#                               names the file after the edition and its
#                               version — both of which move with the
#                               packages, so the profile cannot state it.
#   {out}/irf/                  the initramfs source tree: the composed
#                               boot/initramfs plus this suite's staging
#                               hook. Kept rather than deleted — a failing
#                               test is usually a question about what was in
#                               the initramfs, and this is the answer.
#   {out}/initramfs.cpio.gz     that tree, packed by the real mkirf.
#
# The kernel and the initramfs are handed to QEMU directly rather than
# booted out of the medium's UKI, which holds the same two files built from
# the same tree. Only the loader differs, and the loader is not under test —
# whereas provium's control of the kernel command line is what every test
# that varies a boot depends on, and a UKI's command line is baked in.
#
# Packed with gzip, not mkirf's zstd default, because the kernel this suite
# boots sets CONFIG_RD_GZIP and no other decompressor: a zstd archive would
# leave the kernel with an empty rootfs and no /init.
#
# Run from this profile's own directory, with {out} as the only argument.
set -eu

out="$1"
image="$out/image"
root="$image/root"
irf="$out/irf"
initrd="$out/initramfs.cpio.gz"
medium="$out/medium.iso"
stamp="$out/.build-stamp"

warn() { echo "peinit/build.sh: $*" >&2; }

# --- what this build needs from outside ------------------------------------
#
# mkirf: the shipped hook resolver and cpio writer. It must be the
# peiosutils applet — the one an image actually carries — rather than any
# other copy, so a repository build is preferred over whatever is on PATH.
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

# peiso: the image composer. A repository build is preferred over
# whatever is on PATH for the same reason mkirf is — and for one more:
# an installed peiso lags the source tree, and a spec knob added since
# it was installed is reported as `unknown key`, which reads like a
# mistake in the spec rather than a stale binary.
#
# The build itself is deferred until after the staleness check below,
# and what the fingerprint hashes is peiso's SOURCE rather than the
# binary. `go build -o` rewrites the output file on every run even when
# the code has not moved, so a binary in the fingerprint would report
# itself stale every time and recompose the image on every test run.
peiso_src=
peiso=${PT_PEISO:-}
if [ -z "$peiso" ] && [ -d ../../../peiso ]; then
    peiso_src=$(readlink -f ../../../peiso)
    peiso="$out/peiso"
fi
if [ -z "$peiso_src" ]; then
    [ -n "$peiso" ] || peiso=$(command -v peiso 2>/dev/null || true)
    if [ -z "$peiso" ]; then
        warn "no peiso found (build it, or set PT_PEISO)"
        exit 1
    fi
    peiso=$(readlink -f "$peiso")
fi

# The provium agent. It is injected into the image and started by peinit's
# autorun, so a test has something to talk to once the boot completes.
# Taken from the same overlay archive provium would inject into any other
# profile, so the agent in this guest is always the one the host on the
# other end of the vsock expects.
overlay=${PROVIUM_OVERLAY:-../../../provium/dist/agent-overlay.cpio.gz}
if [ ! -r "$overlay" ]; then
    warn "no provium agent overlay at $overlay (set PROVIUM_OVERLAY)"
    exit 1
fi
overlay=$(readlink -f "$overlay")

# --- staleness -------------------------------------------------------------
# Identity is name/size/mtime rather than content, as in the other
# profiles: a rebuilt package always moves one of them, and hashing a
# gigabyte of packages on every test run would defeat the point.
fingerprint() {
    cat ../../peiso.toml peiso.toml build.sh
    cat payload/*
    # hooks/ is optional: this profile stages one only when a test needs
    # something the shipped hook set does not do.
    cat hooks/*.sh 2>/dev/null || true
    ls -lL ../../../pkgs/_pkgsOut_/ 2>/dev/null || true
    ls -lL "$mkirf" "$overlay" 2>/dev/null || true
    if [ -n "$peiso_src" ]; then
        find "$peiso_src" -name '*.go' -o -name 'go.*' | sort | xargs ls -lL
    else
        ls -lL "$peiso" 2>/dev/null || true
    fi
}

current() {
    [ -d "$root" ] && [ -f "$initrd" ] && [ -e "$medium" ] \
        && [ "$new" = "$(cat "$stamp" 2>/dev/null)" ]
}

new=$(fingerprint | sha256sum)
if current; then
    exit 0
fi

# Several provium processes may run at once (agents, a developer's shell
# and CI on one host), and every one of them runs this script. Only one may
# recompose: take the lock, then look at the stamp again — the winner has
# usually finished by the time the others get here. Without this the losers
# would rm -rf the image the winner just composed, and a VM launching in
# that window fails to find its kernel.
mkdir -p "$out"
exec 9>"$out/.build-lock"
flock 9
if current; then
    exit 0
fi

# Remove the stamp first: a compose interrupted halfway must not leave a
# stamp claiming the tree beside it is current.
rm -f "$stamp" "$initrd" "$medium"
rm -rf "$image" "$irf"

if [ -n "$peiso_src" ]; then
    (cd "$peiso_src" && go build -o "$peiso" .) || {
        warn "could not build peiso from $peiso_src"
        exit 1
    }
fi

# --- the agent's spec layer -------------------------------------------------
# peiso resolves a spec's relative paths against the LAST layer's directory,
# so this generated layer is where the agent's two files are named: the
# binary has to be extracted from the overlay archive first, and lands here
# rather than in the repository.
#
# The autorun script is what starts the agent. peiso chmods an autorun 0755;
# an injected [[file]] it writes 0644, having no way to know a payload is a
# program, which is why the script runs mkexec on the binary before exec'ing
# it.
agent_dir="$out/agent"
rm -rf "$agent_dir"
mkdir -p "$agent_dir"
zcat "$overlay" | (cd "$agent_dir" && cpio --quiet -idm 'sbin/provium-agent')
[ -f "$agent_dir/sbin/provium-agent" ] || {
    warn "the agent overlay $overlay carries no sbin/provium-agent"
    exit 1
}
mv "$agent_dir/sbin/provium-agent" "$agent_dir/provium-agent"
rmdir "$agent_dir/sbin"
cp payload/10-provium-agent.sh "$agent_dir/"

cat > "$agent_dir/agent.toml" <<'SPEC'
# Generated by profiles/peinit/build.sh — do not edit.
#
# The provium agent, injected into the image and started by peinit's
# phase-1.5 autorun. Injected rather than packaged because a package would
# have to be published to be composed, and this binary moves with provium.
[[file]]
src = "provium-agent"
dest = "usr/bin/provium-agent"

[[autorun]]
src = "10-provium-agent.sh"
name = "10-provium-agent.sh"
SPEC

# --- the image --------------------------------------------------------------
"$peiso" iso ../../peiso.toml peiso.toml "$agent_dir/agent.toml" --out "$image"

[ -d "$root/boot/initramfs" ] || {
    warn "the composed root has no boot/initramfs — no package landed in the initramfs root"
    exit 1
}
iso=$(ls "$image"/*.iso 2>/dev/null | head -1)
[ -n "$iso" ] || {
    warn "peiso wrote no .iso into $image"
    exit 1
}
# A relative symlink, so the whole {out} tree can be moved or shared.
ln -sfn "image/$(basename "$iso")" "$medium"

# --- the initramfs source tree ---------------------------------------------
# A copy, not the composed tree itself: what mkirf packs may carry this
# suite's own hooks, and the composed root must stay exactly what peiso
# produced.
cp -a "$root/boot/initramfs" "$irf"

# This suite's hooks, into the packaged hook directory — the same place a
# feature peipkg would drop one. They are staged rather than packaged
# because a package would have to be published to be composed, and these
# change with the tests that use them.
if [ -d hooks ] && [ -n "$(ls hooks 2>/dev/null)" ]; then
    mkdir -p "$irf/usr/libexec/prelude/hooks.d"
    for h in hooks/*.sh; do
        cp "$h" "$irf/usr/libexec/prelude/hooks.d/$(basename "$h")"
        chmod 0755 "$irf/usr/libexec/prelude/hooks.d/$(basename "$h")"
    done
fi

# --- pack -------------------------------------------------------------------
# mkirf resolves the hook DAG and writes the sequence files; this is the
# same call peiso makes when it builds the medium's UKI, minus the
# compressor.
"$mkirf" --compress gzip "$irf" "$initrd"

printf '%s' "$new" > "$stamp"
