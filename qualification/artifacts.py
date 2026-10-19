"""Record and copy supplied inputs without invoking an image or signing builder."""

import hashlib
import json
import os
import re
import shutil
import stat
from pathlib import Path
from typing import BinaryIO

from qualification.sources import QualificationError, digest


def fingerprint(path: Path) -> str:
    """Hash regular file bytes or a canonical tree; reject special files and escaping links."""
    if path.is_symlink():
        raise QualificationError(f"Artifact root must not be a symlink: {path}")
    if path.is_file():
        with open_regular(path) as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise QualificationError(f"Not a regular input: {path}")
            hasher = hashlib.sha256()
            while chunk := stream.read(1024 * 1024):
                hasher.update(chunk)
            value = hasher.hexdigest()
            after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise QualificationError(f"Artifact changed while hashing: {path}")
        return value
    if not path.is_dir():
        raise QualificationError(f"Missing or special artifact: {path}")
    entries = []
    for item in sorted(path.rglob("*")):
        name = item.relative_to(path).as_posix()
        mode = item.lstat().st_mode
        if item.is_symlink():
            if Path(os.readlink(item)).is_absolute() or not item.resolve().is_relative_to(
                path.resolve()
            ):
                raise QualificationError(f"Artifact symlink escapes its tree: {item}")
            content = "link:" + os.readlink(item)
        elif stat.S_ISREG(mode):
            content = "file:" + fingerprint(item)
        elif stat.S_ISDIR(mode):
            content = "directory"
        else:
            raise QualificationError(f"Special artifact entry: {item}")
        entries.append([name, stat.S_IMODE(mode), content])
    return digest(json.dumps(entries, separators=(",", ":"), ensure_ascii=True).encode())


def stage_artifacts(spec: dict, base: Path, destination: Path) -> tuple:
    """Copy then verify every artifact, including packages, images, runner and tools."""
    destination.mkdir()
    paths = {}
    records = {}
    for name, item in spec["artifacts"].items():
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]*", name):
            raise QualificationError(f"Artifact IDs cannot contain directories: {name}")
        source = Path(item["path"])
        if not source.is_absolute():
            source = base / source
        expected = item["sha256"]
        actual = fingerprint(source)
        if actual != expected:
            raise QualificationError(f"Artifact hash mismatch: {name}")
        target = destination / name
        if source.is_dir():
            shutil.copytree(source, target, symlinks=True, copy_function=copy_regular)
        else:
            copy_regular(source, target)
        if fingerprint(target) != expected:
            raise QualificationError(f"Artifact changed during snapshot: {name}")
        paths[name] = target.resolve()
        records[name] = {
            "source": str(source.resolve()),
            "sha256": expected,
            "directory": source.is_dir(),
            "mode": stat.S_IMODE(target.stat().st_mode),
        }
    return paths, records


def artifact_path(reference: object, paths: dict[str, Path]) -> str:
    if not isinstance(reference, dict) or set(reference) != {"artifact"}:
        raise QualificationError("File inputs must use an explicit artifact reference")
    name = reference["artifact"]
    if name not in paths:
        raise QualificationError(f"Unknown artifact: {name}")
    return str(paths[name])


def open_regular(path: Path) -> BinaryIO:
    """Open without waiting on a pipe, then validate the actual open file."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise QualificationError(f"Not a regular input: {path}")
        return os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise


def copy_regular(source: str | Path, target: str | Path) -> None:
    """Copy a validated descriptor to a fresh file; preserve executable mode."""
    with open_regular(Path(source)) as incoming, open(target, "xb") as outgoing:
        shutil.copyfileobj(incoming, outgoing)
        os.fchmod(outgoing.fileno(), stat.S_IMODE(os.fstat(incoming.fileno()).st_mode))
