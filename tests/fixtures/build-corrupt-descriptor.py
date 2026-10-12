#!/usr/bin/env python3
"""Create an offline corrupt-SD fixture without relaxing runtime xattr policy."""
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent
CORRUPT = b"not a security descriptor"

with tempfile.TemporaryDirectory(prefix="corrupt-sd-fixture-", dir=ROOT) as scratch:
    scratch = pathlib.Path(scratch)
    source = scratch / "source" / "stratum"
    (source / "bad-dir").mkdir(parents=True)
    for name in ["bad-file", "good", "missing", "bad-dir/child"]:
        (source / name).write_bytes(b"fixture content\n")
    image = scratch / "fixture.img"
    subprocess.run([
        "mke2fs", "-q", "-F", "-t", "ext2", "-b", "1024", "-N", "64",
        "-d", str(source.parent), str(image), "1024",
    ], check=True)
    data = scratch / "descriptor"
    data.write_bytes(CORRUPT)
    for name in ["bad-file", "bad-dir"]:
        inode = "/stratum/" + name
        subprocess.run([
            "debugfs", "-w", "-R",
            f"ea_set -f {data} {inode} security.peios.sd", str(image),
        ], check=True, capture_output=True)
        readback = scratch / "readback"
        subprocess.run([
            "debugfs", "-R",
            f"ea_get -f {readback} {inode} security.peios.sd", str(image),
        ], check=True, capture_output=True)
        assert readback.read_bytes() == CORRUPT, name
    image.replace(ROOT / "corrupt-descriptor.img")
print(ROOT / "corrupt-descriptor.img")
