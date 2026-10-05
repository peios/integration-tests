#!/usr/bin/env python3
"""The network books' anchors against the tests/network suite's citations.

    python3 tests/tools/network-coverage.py [book ...]   (from the repository root)

Books: netd (the netd TRM), resolvd (the resolvd TRM), PSPU (PSPU book 6,
the name resolution interface, whose anchors all start `nri-`). With no
argument, every book.

For each book, prints each anchor no test cites (MISSING) and each
citation of an anchor the book no longer has (STALE), then a one-line
total, and exits 1 if any list is non-empty. A citation is a
`<book> *<anchor>` token anywhere in tests/network/*.lua: spec strings,
concatenated or not, and covered_by notes. The books are read from the
learn checkout beside this repository.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
ADV = ROOT.parent / "learn/peios.product/3--advanced-peios.antho"
BOOKS = {
    "netd": (ADV / "300--trms.shelf/700--netd.book", None),
    "resolvd": (ADV / "300--trms.shelf/800--resolvd.book", None),
    "PSPU": (ADV / "200--pcsa.shelf/400--pspu.book/6--name-resolution-interface", "nri-"),
}
TESTS = ROOT / "tests/network"

failed = False
for book in sys.argv[1:] or list(BOOKS):
    path, only = BOOKS[book]
    anchors = {}
    for md in sorted(path.rglob("*.md")):
        for a in re.findall(r"\[\*([a-z0-9][a-z0-9.\-]*)\]", md.read_text()):
            if only is None or a.startswith(only):
                anchors.setdefault(a, md.relative_to(path))

    cited = {}
    for lua in sorted(TESTS.glob("*.lua")):
        for a in re.findall(re.escape(book) + r" \*([a-z0-9][a-z0-9.\-]*[a-z0-9])", lua.read_text()):
            if only is None or a.startswith(only):
                cited.setdefault(a, lua.name)

    missing = sorted(set(anchors) - set(cited))
    stale = sorted(set(cited) - set(anchors))
    for a in missing:
        print(f"{book} MISSING {a}  ({anchors[a]})")
    for a in stale:
        print(f"{book} STALE   {a}  ({cited[a]})")
    print(f"{book} TOTAL anchors={len(anchors)} cited={len(set(anchors) & set(cited))} "
          f"missing={len(missing)} stale={len(stale)}")
    failed = failed or bool(missing or stale)
sys.exit(1 if failed else 0)
