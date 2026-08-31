#!/bin/sh
# Compose the kernel-only root, and only when something it depends on
# has changed.
#
# Provium runs a profile's `build` on every invocation and holds no
# staleness logic of its own — it trusts the builder to be cheap when
# nothing changed. `peiso root` is not: it always composes from scratch
# and refuses a `--out` that already exists, so the obvious one-liner
# costs a full compose every run. That is 45 seconds against 1 second of
# actual tests.
#
# Run from this profile's own directory, with {out} as the only argument.
set -eu

out="$1"
root="$out/root"
stamp="$out/.build-stamp"

# What the composition depends on: the two spec layers, and the package
# repository they resolve against. Identity is name/size/mtime rather
# than content — a rebuilt package always moves one of them, and hashing
# the kernel package on every test run would defeat the point.
fingerprint() {
    cat ../../peiso.toml peiso.toml
    ls -lL ../../../pkgs/_pkgsOut_/ 2>/dev/null || true
}

new=$(fingerprint | sha256sum)
if [ -d "$root" ] && [ "$new" = "$(cat "$stamp" 2>/dev/null)" ]; then
    exit 0
fi

# Remove the stamp first: a compose interrupted halfway must not leave a
# stamp claiming the tree beside it is current.
rm -f "$stamp"
rm -rf "$root"
peiso root ../../peiso.toml peiso.toml --out "$root"
printf '%s' "$new" > "$stamp"
