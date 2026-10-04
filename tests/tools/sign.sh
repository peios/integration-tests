#!/bin/sh
# PIP-sign one binary at the TCB tier with the development keyring.
#
#   sh tests/tools/sign.sh <input> <output>
#
# Used by profiles/peinit/build.sh for the provium agent and by
# helpers/peinit.lua's `tool(name, {signed = true})` for a guest tool that
# must signal or trace a TCB-signed process (PID 1, authd, eventd). The
# keyring is PEIOS_DEV_KEYRING, default pkgs/dev.keyring.pekit.toml beside
# this repository; pekit is PEKIT, default the one on PATH or ~/go/bin.
# Fails rather than produce an unsigned binary that quietly cannot reach
# what it was signed for.
set -eu

in=$1
out=$2
here=$(cd "$(dirname "$0")" && pwd)
keyring=$(readlink -f "${PEIOS_DEV_KEYRING:-$here/../../../pkgs/dev.keyring.pekit.toml}" 2>/dev/null || true)
[ -n "$keyring" ] && [ -r "$keyring" ] || {
    echo "tests/tools/sign.sh: no development keyring: set PEIOS_DEV_KEYRING" >&2
    exit 1
}
pekit=${PEKIT:-$(command -v pekit || echo "$HOME/go/bin/pekit")}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp "$here/sign.pekit.toml" "$work/pekit.toml"
cp "$in" "$work/payload"
(cd "$work" && "$pekit" --quiet build main --version 0.0.0 --keyring "$keyring") >&2 || {
    echo "tests/tools/sign.sh: pekit could not PIP-sign $in" >&2
    exit 1
}
# Several test files may sign the same tool at once: write a private name
# and rename over the target, as build.sh does.
cp "$work/out/build/main/bin/payload" "$out.$$"
chmod 0755 "$out.$$"
mv -f "$out.$$" "$out"
