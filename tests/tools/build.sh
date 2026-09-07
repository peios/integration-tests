#!/bin/sh
# Compile one of the suite's guest tools, if it is not already current.
#
# These are small C programs the suite stages into a guest to do something
# the image itself cannot. They are built on the host and statically
# linked: the guest has no compiler, and a dynamically linked binary would
# look for the host's loader and shared libraries, which are not the
# guest's. Static ELF plus plain syscalls is portable enough to run under
# any kernel the suite boots.
#
# Called from Lua by `helpers.peinit`'s `tool()` — not usually by hand.
# Prints the path of the finished binary and nothing else, so the caller
# can read it straight back.
#
#   sh tests/tools/build.sh pt-notify
#
# Run from the repository root. Set PT_CC to choose a compiler.
set -eu

name=$1
src="tests/tools/$name.c"
dir="tests/tools/.build"
out="$dir/$name"

[ -r "$src" ] || { echo "tests/tools/build.sh: no such tool: $src" >&2; exit 1; }

# Up to date? mtime rather than content: the source is a file in the
# repository, so anything that changes it moves its mtime, and hashing on
# every test run to save a sub-second compile is not worth it.
if [ -x "$out" ] && [ "$out" -nt "$src" ]; then
    echo "$out"
    exit 0
fi

mkdir -p "$dir"

cc=${PT_CC:-cc}
command -v "$cc" >/dev/null 2>&1 || {
    echo "tests/tools/build.sh: no C compiler ($cc); set PT_CC" >&2
    exit 1
}

# Several test files may reach here at once — provium dispatches one
# thread per file. Compile to a private name and rename over the target,
# so a concurrent reader sees either the old binary or the new one and
# never a half-written file.
tmp="$out.$$"
"$cc" -static -O2 -Wall -Wextra -o "$tmp" "$src" >&2
strip "$tmp" 2>/dev/null || true
mv -f "$tmp" "$out"

echo "$out"
