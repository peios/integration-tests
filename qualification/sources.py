"""Resolve owned test bundles from recorded Git objects, never sibling HEADs."""

import hashlib
import json
import re
import subprocess
from pathlib import Path, PurePosixPath


class QualificationError(Exception):
    """An input is missing, inconsistent, or unsuitable for qualification."""


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def relative_path(value: str) -> str:
    path = PurePosixPath(value)
    if not value or value == "." or path.is_absolute() or ".." in path.parts or "\\" in value:
        raise QualificationError(f"Expected a relative path without traversal: {value!r}")
    if str(path) != value or any(ord(c) < 32 for c in value):
        raise QualificationError(f"Noncanonical path: {value!r}")
    return value


def git(root: Path, *arguments: str) -> bytes:
    result = subprocess.run(["git", "-C", str(root), *arguments], capture_output=True, check=False)
    if result.returncode:
        raise QualificationError(result.stderr.decode(errors="replace").strip())
    return result.stdout


def read_object(root: Path, revision: str, path: str) -> bytes:
    relative_path(path)
    kind = git(root, "cat-file", "-t", f"{revision}:{path}").strip()
    if kind != b"blob":
        raise QualificationError(f"Not a file in the pinned source: {path}")
    mode = git(root, "ls-tree", revision, "--", path).split(None, 1)[0]
    if mode not in {b"100644", b"100755"}:
        raise QualificationError(f"Suite inputs must be regular Git files: {path}")
    return git(root, "show", f"{revision}:{path}")


def pin_catalog(catalog_path: Path) -> dict:
    catalog = json.loads(catalog_path.read_text())
    if catalog.get("format") != 1:
        raise QualificationError("Unsupported catalog format")
    locked: dict = {"format": 1, "components": []}
    seen = set()
    for entry in catalog["components"]:
        name = entry["id"]
        if not re.fullmatch(r"[a-z][a-z0-9-]*", name) or name in seen:
            raise QualificationError(f"Invalid or duplicate component: {name}")
        seen.add(name)
        root = (catalog_path.parent / entry["repository"]).resolve()
        revision = git(root, "rev-parse", "HEAD").decode().strip()
        contents = read_object(root, revision, entry["manifest"])
        locked["components"].append(
            {**entry, "revision": revision, "manifest_sha256": digest(contents)}
        )
    return locked


def resolve_sources(lock_path: Path, selected: list[str], candidates: dict[str, Path]) -> tuple:
    lock_bytes = lock_path.read_bytes()
    lock = json.loads(lock_bytes)
    if lock.get("format") != 1:
        raise QualificationError("Unsupported suite lock format")
    files = {}
    tests = []
    records = []
    owners = set()
    for entry in lock["components"]:
        owner = entry["id"]
        if owner in owners:
            raise QualificationError(f"Duplicate component {owner}")
        owners.add(owner)
        root = candidates.get(owner, (lock_path.parent / entry["repository"]).resolve())
        revision = entry["revision"]
        if owner in candidates:
            revision = git(root, "rev-parse", "HEAD").decode().strip()
            if git(root, "status", "--porcelain", "--untracked-files=normal").strip():
                raise QualificationError(f"Candidate {owner} has uncommitted changes")
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise QualificationError(f"An exact Git commit is required for {owner}")
        git(root, "cat-file", "-e", revision + "^{commit}")
        raw = read_object(root, revision, entry["manifest"])
        if owner not in candidates and digest(raw) != entry["manifest_sha256"]:
            raise QualificationError(f"Suite manifest mismatch for {owner}")
        manifest = json.loads(raw)
        if manifest.get("format") != 1 or manifest.get("component") != owner:
            raise QualificationError(f"Invalid suite manifest for {owner}")
        prefix = PurePosixPath(entry["manifest"]).parent
        declared_tests = set(manifest["tests"])
        if len(declared_tests) != len(manifest["tests"]):
            raise QualificationError(f"Duplicate test in {owner}")
        if not declared_tests.issubset(manifest["files"]):
            raise QualificationError(f"Undeclared test input in {owner}")
        if any(not p.endswith(".test.lua") for p in declared_tests):
            raise QualificationError(f"Invalid test filename in {owner}")
        tracked_tests = {
            name.decode()
            for name in git(
                root, "ls-tree", "-r", "--name-only", "-z", revision, "--", str(prefix)
            ).split(b"\0")
            if name.endswith(b".test.lua")
        }
        exported_tests = {str(prefix / manifest["files"][name]) for name in declared_tests}
        if tracked_tests != exported_tests:
            raise QualificationError(f"Suite test inventory differs from tracked files for {owner}")
        hashes = {}
        for destination, source in manifest["files"].items():
            relative_path(destination)
            if not destination.startswith(("tests/", "profiles/")):
                raise QualificationError(f"Export outside suite directories: {destination}")
            relative_path(source)
            if destination in files:
                raise QualificationError(f"Two owners export {destination}")
            data = read_object(root, revision, str(prefix / source))
            files[destination] = data
            hashes[destination] = digest(data)
            if destination in declared_tests and (not selected or owner in selected):
                tests.append(destination)
        records.append(
            {
                "component": owner,
                "harness_only": manifest.get("harness_only", False) is True,
                "repository": str(root),
                "revision": revision,
                "manifest_sha256": digest(raw),
                "candidate": owner in candidates,
                "files": hashes,
            }
        )
    unknown = (set(selected) | set(candidates)) - owners
    if unknown:
        raise QualificationError(f"Unknown components: {', '.join(sorted(unknown))}")
    if not tests:
        raise QualificationError("The selection contains no tests")
    return files, sorted(tests), {"lock_sha256": digest(lock_bytes), "sources": records}
