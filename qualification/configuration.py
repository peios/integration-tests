"""Build a Provium configuration from explicitly supplied boot artifacts."""

import json
import math
import re
import tomllib
from pathlib import Path

from qualification.artifacts import artifact_path, copy_regular
from qualification.sources import QualificationError, relative_path

PROFILE_FILES = {"kernel", "initrd", "root", "cmdline_file", "agent_overlay_path"}
PROFILE_VALUES = {"cmdline", "guest_os", "inject_agent", "agent_boot_timeout"}


def toml_value(value: object) -> str:
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, (float, int)):
        if not math.isfinite(value):
            raise QualificationError("TOML numbers must be finite")
        return str(value)
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(item) for item in value) + "]"
    if isinstance(value, dict):
        return (
            "{ " + ", ".join(json.dumps(k) + " = " + toml_value(v) for k, v in value.items()) + " }"
        )
    raise QualificationError(f"Unsupported TOML value: {value!r}")


def configuration(spec: dict, paths: dict[str, Path], run: Path) -> str:
    lines = ["[provium]", 'roots = ["tests"]', 'cache_dir = "cache/fixtures"', ""]
    for name, supplied in spec["profiles"].items():
        if not re.fullmatch(r"[a-z][a-z0-9-]*", name):
            raise QualificationError(f"Invalid profile name: {name}")
        unknown = set(supplied) - PROFILE_FILES - PROFILE_VALUES - {"disks"}
        if unknown:
            raise QualificationError(
                f"Unsupported profile fields: {sorted(unknown)}; builds are prohibited"
            )
        values: dict[str, object] = {}
        for key, value in supplied.items():
            if key in PROFILE_FILES:
                values[key] = artifact_path(value, paths)
            elif key == "disks":
                disks: list[dict] = []
                for disk in value:
                    if set(disk) - {"path", "id", "readonly", "mediated"}:
                        raise QualificationError("Unknown disk fields")
                    source = Path(artifact_path(disk["path"], paths))
                    target = source
                    if not disk.get("readonly", False):
                        working = run / "working-disks"
                        working.mkdir(exist_ok=True)
                        target = working / f"{name}-{len(disks)}.img"
                        copy_regular(source, target)
                    disks.append({**disk, "path": str(target)})
                values[key] = disks
            else:
                values[key] = value
        if "kernel" not in values and "root" not in values:
            raise QualificationError(f"Profile {name} needs a recorded kernel or root")
        if values.get("inject_agent", True) and "agent_overlay_path" not in values:
            raise QualificationError(f"Profile {name} needs an explicit recorded agent overlay")
        lines.append(f"[profiles.{name}]")
        lines.extend(f"{key} = {toml_value(value)}" for key, value in values.items())
        lines.append("")
    return "\n".join(lines)


def check_packages(spec: dict, paths: dict[str, Path]) -> list[dict]:
    records = []
    seen = set()
    for item in spec.get("packages", []):
        path = Path(artifact_path(item["manifest"], paths))
        manifest = tomllib.loads(path.read_text())
        identity = tuple(manifest[key] for key in ("name", "version", "arch"))
        if identity in seen:
            raise QualificationError(f"Duplicate package: {identity}")
        seen.add(identity)
        if any(item[key] != manifest[key] for key in ("name", "version", "arch")):
            raise QualificationError(f"Package identity differs from supplied manifest: {path}")
        records.append(item)
    return records


def host_environment(spec: dict, paths: dict[str, Path], run: Path) -> dict[str, str]:
    env = {
        "HOME": str(run / "home"),
        "TMPDIR": str(run / "tmp"),
        "PATH": str(run / "bin") + ":/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C.UTF-8",
        "PROVIUM_BUILD_DIR": str(run / "cache/build"),
        "PROVIUM_RERUN_STATE": str(run / "rerun.json"),
        "XDG_CACHE_HOME": str(run / "cache"),
    }
    for directory in ("home", "tmp", "cache", "bin"):
        (run / directory).mkdir(exist_ok=True)
    for name, reference in spec.get("environment", {}).items():
        if not re.fullmatch(
            r"PT_[A-Z0-9_]+|(PEINIT|TRUSTD|LOREGD|NETD|RESOLVD|NSS_NET|NSS_IDENTITY)_TEST_(BINARY|SERVICE)",
            name,
        ):
            raise QualificationError(f"Unsupported test environment setting: {name}")
        env[name] = artifact_path(reference, paths)
    for name, reference in spec.get("host_tools", {}).items():
        if "/" in relative_path(name):
            raise QualificationError("Host tool names cannot contain directories")
        (run / "bin" / name).symlink_to(artifact_path(reference, paths))
    return env
