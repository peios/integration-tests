#!/usr/bin/env python3
"""The Kernel TRM's and the peinit TRM's anchors against the suite's citations.

    python3 tests/tools/trm-coverage.py [kernel|peinit ...]   (from the repository root)

For each book (both by default), prints each anchor no test cites (MISSING)
and each citation of an anchor the book no longer has (STALE), then a
one-line total, and exits 1 if any list is non-empty.

A citation is a `PKM *<anchor>` (kernel) or `peinit *<anchor>` token in any
tests/**/*.lua file. Some files build the token at run time, as
`"PKM *" .. spec` or `"PKM *param." .. row[5]`, so an anchor also counts as
cited when its slug, or the part after its first dot, appears as a quoted
string in the same suite's files. Those forms cannot be checked for
staleness. The books are read from the learn checkout beside this
repository.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
TRMS = (ROOT.parent / "learn/peios.product/3--advanced-peios.antho"
        / "300--trms.shelf")
BOOKS = {
    "kernel": ("PKM", "100--peios-kernel.book"),
    "peinit": ("peinit", "200--peinit.book"),
}

texts = {lua: lua.read_text() for lua in sorted((ROOT / "tests").rglob("*.lua"))}
quoted = set()
for text in texts.values():
    quoted.update(re.findall(r"[\"']([a-z0-9][a-z0-9.\-]*[a-z0-9])[\"']", text))

failed = False
for name in sys.argv[1:] or BOOKS:
    prefix, book = BOOKS[name]
    anchors = {}
    for md in sorted((TRMS / book).rglob("*.md")):
        for a in re.findall(r"\[\*([a-z0-9][a-z0-9.\-]*)\]", md.read_text()):
            anchors.setdefault(a, md.relative_to(TRMS / book))

    cited = {}
    # Every anchor in both books has a dot; requiring one keeps prose
    # emphasis such as "peinit *is* PID 1" from reading as a citation.
    pattern = re.escape(prefix) + r" \*([a-z0-9][a-z0-9\-]*\.[a-z0-9.\-]*[a-z0-9])"
    for lua, text in texts.items():
        for a in re.findall(pattern, text):
            cited.setdefault(a, lua.relative_to(ROOT))
    built = {a for a in anchors if a not in cited
             and (a in quoted or a.split(".", 1)[-1] in quoted)}

    missing = sorted(set(anchors) - set(cited) - built)
    # A token ending in a dot is the fixed half of a built citation.
    stale = sorted(a for a in set(cited) - set(anchors)
                   if not any(b.startswith(a + ".") for b in anchors))
    for a in missing:
        print(f"MISSING {name} {a}  ({anchors[a]})")
    for a in stale:
        print(f"STALE   {name} {a}  ({cited[a]})")
    print(f"TOTAL {name} anchors={len(anchors)} "
          f"cited={len(anchors) - len(missing)} "
          f"missing={len(missing)} stale={len(stale)}")
    failed = failed or bool(missing or stale)
sys.exit(1 if failed else 0)
