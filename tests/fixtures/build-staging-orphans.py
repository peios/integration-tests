#!/usr/bin/env python3
"""Build the small offline filesystem used by staging-recovery.test.lua."""
import pathlib
import struct
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent
OUTPUT = ROOT / "staging-orphans.img"


def marker(magic=0x53544731, version=1, size=24):
    # Both zero cookies denote a dead owner: live boot/mount cookies are nonzero.
    return struct.pack("<IHHQQ", magic, version, size, 0, 0)


cases = {
    "orphan-file": (".stratafs-stage-dead", False, marker()),
    "orphan-dir": (".stratafs-stage-dead", True, marker()),
    "unmarked": (".stratafs-stage-unmarked", False, None),
    "short-marker": (".stratafs-stage-short", False, b"short"),
    "bad-magic": (".stratafs-stage-magic", False, marker(magic=0)),
    "bad-version": (".stratafs-stage-version", False, marker(version=2)),
    "bad-size": (".stratafs-stage-size", False, marker(size=23)),
    "published": ("ordinary", False, marker()),
}

with tempfile.TemporaryDirectory(prefix="staging-fixture-", dir=ROOT) as scratch:
    scratch = pathlib.Path(scratch)
    source = scratch / "source"
    for case, (name, directory, _) in cases.items():
        entry = source / "upper" / case / name
        entry.parent.mkdir(parents=True)
        if directory:
            entry.mkdir()
        else:
            entry.write_bytes(b"interrupted copy-up\n")
    image = scratch / "fixture.img"
    subprocess.run([
        "mke2fs", "-q", "-F", "-t", "ext2", "-b", "1024", "-N", "64",
        "-d", str(source), str(image), "1024",
    ], check=True)
    for case, (name, _, value) in cases.items():
        if value is None:
            continue
        data = scratch / "marker"
        data.write_bytes(value)
        inode = f"/upper/{case}/{name}"
        attr = "security.peios.stratafs_staging"
        subprocess.run([
            "debugfs", "-w", "-R", f"ea_set -f {data} {inode} {attr}", str(image),
        ], check=True, capture_output=True)
        readback = scratch / "readback"
        subprocess.run([
            "debugfs", "-R", f"ea_get -f {readback} {inode} {attr}", str(image),
        ], check=True, capture_output=True)
        assert readback.read_bytes() == value, f"marker mismatch: {case}"
    # Never run filesystem tools against the destination or an existing device.
    image.replace(OUTPUT)
print(OUTPUT)
