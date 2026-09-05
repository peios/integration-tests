#!/bin/sh
# Compose the kernel-only root and the guest's fixture initramfs, and
# only when something they depend on has changed.
#
# Provium runs a profile's `build` on every invocation and holds no
# staleness logic of its own — it trusts the builder to be cheap when
# nothing changed. `peiso root` is not: it always composes from scratch
# and refuses a `--out` that already exists, so the obvious one-liner
# costs a full compose every run. That is 45 seconds against 1 second of
# actual tests.
#
# Two outputs:
#
#   {out}/root             the composed root. provium boots the kernel
#                          out of it; the guest never sees the tree.
#   {out}/extras.cpio.gz   the guest's initramfs, concatenated with the
#                          agent overlay at launch. It carries what the
#                          conformance tests need that a kernel alone
#                          cannot give them, under /fixtures:
#
#     modules/test_firmware.ko.zst   the firmware loader's self-test
#                                    device, to provoke firmware loads
#     modules/ntfs3.ko.zst           an NTFS driver, for the claims
#                                    about NTFS-backed files
#     firmware/*.bin, *.peios.sig    blobs signed with the TCB key the
#                                    kernel embeds, plus unsigned and
#                                    tampered ones, with the signature
#                                    beside each as a sidecar — the
#                                    tests stamp it into the xattr on
#                                    a filesystem that carries xattrs
#     ntfs.img                       a small empty NTFS volume, for a
#                                    loop mount
#
#   Both modules are copied out of the composed root, so they are the
#   modules of the kernel that boots. Signing needs the private half
#   of the TCB key the kernel was built with — the pkgs dev keyring's
#   by default, PIT_TCB_KEY to name another — and an OpenSSL with
#   ML-DSA-65 (3.5+). The NTFS image needs mkntfs (ntfs-3g). When one
#   of those is missing the build warns and leaves the fixture out, and
#   the tests that need it skip saying so.
#
# Run from this profile's own directory, with {out} as the only argument.
set -eu

out="$1"
root="$out/root"
extras="$out/extras.cpio.gz"
stamp="$out/.build-stamp"

# The TCB signing key. `pkgs/dev.keyring.pekit.toml` is what a local
# `pekit ... --keyring dev` embeds into the kernel, so its private half
# is what signs blobs that kernel will trust.
tcb_key=${PIT_TCB_KEY:-$(sed -n '/^\[tcb\]/,/^\[.*\]/{s/^priv *= *"\(.*\)".*/\1/p;}' \
    ../../../pkgs/dev.keyring.pekit.toml 2>/dev/null | head -n 1)}

# What the outputs depend on: the two spec layers, this script, the
# signing key, and the package repository they resolve against.
# Identity is name/size/mtime rather than content — a rebuilt package
# always moves one of them, and hashing the kernel package on every test
# run would defeat the point.
fingerprint() {
    cat ../../peiso.toml peiso.toml build.sh
    ls -lL ../../../pkgs/_pkgsOut_/ 2>/dev/null || true
    if [ -n "$tcb_key" ]; then ls -lL "$tcb_key" 2>/dev/null || true; fi
}

current() {
    [ -d "$root" ] && [ -f "$extras" ] && [ "$new" = "$(cat "$stamp" 2>/dev/null)" ]
}

new=$(fingerprint | sha256sum)
if current; then
    exit 0
fi

# Several provium processes may run at once (agents, a developer's shell
# and CI on one host), and every one of them runs this script. Only one
# may recompose: take the lock, then look at the stamp again — the
# winner has usually finished by the time the others get here. Without
# this, the losers would rm -rf the root the winner just composed, and a
# VM launching in that window fails to find its kernel.
mkdir -p "$out"
exec 9>"$out/.build-lock"
flock 9
if current; then
    exit 0
fi

# Remove the stamp first: a compose interrupted halfway must not leave a
# stamp claiming the tree beside it is current.
rm -f "$stamp" "$extras"
rm -rf "$root"
peiso root ../../peiso.toml peiso.toml --out "$root"

# --- the fixture initramfs ---------------------------------------------

warn() { echo "kernel-only/build.sh: $*" >&2; }

work=$(mktemp -d "$out/extras.XXXXXX")
trap 'rm -rf "$work"' EXIT
tree="$work/tree"
mkdir -p "$tree/fixtures/modules" "$tree/fixtures/firmware"

# The two modules, from the kernel the root carries.
moddir=$(find "$root/usr/lib/modules" -mindepth 1 -maxdepth 1 -type d | head -n 1)
[ -n "$moddir" ] || { warn "no module tree under $root/usr/lib/modules"; exit 1; }
for m in kernel/lib/test_firmware.ko.zst kernel/fs/ntfs3/ntfs3.ko.zst; do
    [ -f "$moddir/$m" ] || {
        warn "$m is not in the composed kernel-modules ($(basename "$moddir"))"
        exit 1
    }
    cp "$moddir/$m" "$tree/fixtures/modules/"
done

# Firmware blobs. Deterministic content, so the archive only changes
# when something real does.
fw="$tree/fixtures/firmware"
yes 'peios kernel-only firmware fixture: signed' | head -c 4096 > "$fw/signed.bin"
yes 'peios kernel-only firmware fixture: nobody vouches for these bytes' | head -c 4096 > "$fw/unsigned.bin"
yes 'peios kernel-only firmware fixture: sixteen KiB, for partial reads' | head -c 16384 > "$fw/large.bin"
yes 'peios kernel-only firmware fixture: compressed on disk' | head -c 8192 > "$work/plain.bin"
# Same bytes as signed.bin but one — it will carry signed.bin's signature.
cp "$fw/signed.bin" "$fw/tampered.bin"
printf '\377' | dd of="$fw/tampered.bin" bs=1 seek=2048 count=1 conv=notrunc status=none

# sign <file> <sidecar>: the PIP blob for the file's on-disk bytes —
# 0x01 then an ML-DSA-65 signature over their SHA-256 (PSPK ch.3).
sign() {
    openssl dgst -sha256 -binary "$1" > "$work/hash"
    openssl pkeyutl -sign -inkey "$tcb_key" -rawin -in "$work/hash" -out "$work/sig"
    { printf '\001'; cat "$work/sig"; } > "$2"
    size=$(stat -c %s "$2")
    [ "$size" -eq 3310 ] || { warn "signature blob is $size bytes, expected 3310"; exit 1; }
}

can_sign=1
if [ -z "$tcb_key" ] || [ ! -r "$tcb_key" ]; then
    warn "no TCB signing key (pkgs/dev.keyring.pekit.toml [tcb] priv, or PIT_TCB_KEY); firmware fixtures will be unsigned"
    can_sign=0
elif ! openssl list -signature-algorithms 2>/dev/null | grep -q 'ML-DSA-65'; then
    warn "this openssl cannot sign ML-DSA-65 (need 3.5+); firmware fixtures will be unsigned"
    can_sign=0
fi
if command -v zstd >/dev/null 2>&1; then
    # From a file, not a pipe: the kernel's zstd path needs the frame
    # to carry its content size, which zstd only writes when it knows
    # the input length.
    zstd -q -19 "$work/plain.bin" -o "$fw/compressed.bin.zst"
else
    warn "no zstd; the compressed firmware fixture will be missing"
fi
if [ "$can_sign" = 1 ]; then
    sign "$fw/signed.bin" "$fw/signed.bin.peios.sig"
    sign "$fw/large.bin" "$fw/large.bin.peios.sig"
    cp "$fw/signed.bin.peios.sig" "$fw/tampered.bin.peios.sig"
    if [ -f "$fw/compressed.bin.zst" ]; then
        # Over the compressed bytes, as the kernel hashes them — and,
        # for the contrast case, over the bytes they decompress to.
        sign "$fw/compressed.bin.zst" "$fw/compressed.bin.zst.peios.sig"
        sign "$work/plain.bin" "$fw/compressed.bin.zst.decompressed.peios.sig"
    fi
else
    : > "$fw/UNSIGNED"
fi

# An empty NTFS volume for a loop mount. 4 MiB is comfortably above
# mkntfs's floor and compresses to almost nothing.
if command -v mkntfs >/dev/null 2>&1; then
    truncate -s 4M "$tree/fixtures/ntfs.img"
    mkntfs -F -Q -q "$tree/fixtures/ntfs.img" >/dev/null 2>&1
else
    warn "no mkntfs (ntfs-3g); the NTFS fixture will be missing"
fi

# Pack. Sorted, epoch-dated, root-owned: the same archive for the same
# inputs (a fresh ML-DSA signature is randomised, so the firmware
# sidecars are the one thing that moves between builds).
find "$tree" -exec touch -d @0 {} +
( cd "$tree" && find . -mindepth 1 -print0 | LC_ALL=C sort -z \
    | cpio --quiet --null --create --format=newc --reproducible --owner 0:0 ) \
    | gzip -n -9 > "$extras.tmp"
mv "$extras.tmp" "$extras"

printf '%s' "$new" > "$stamp"
