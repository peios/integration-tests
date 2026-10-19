"""Stage pinned suites, run Provium, and preserve a complete result record."""

import json
import math
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from qualification.artifacts import artifact_path, copy_regular, fingerprint, stage_artifacts
from qualification.configuration import check_packages, configuration, host_environment
from qualification.sources import QualificationError, digest, resolve_sources


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=4, sort_keys=True) + "\n")


def fixture_tools(spec: dict, paths: dict[str, Path], run: Path) -> None:
    tools = {}
    for name, item in spec.get("guest_tools", {}).items():
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]*", name):
            raise QualificationError("Guest tool names cannot contain directories")
        tools[name] = {kind: artifact_path(reference, paths) for kind, reference in item.items()}
        if "unsigned" not in tools[name] or set(tools[name]) - {"unsigned", "signed"}:
            raise QualificationError(f"Invalid guest tool entry: {name}")
        if "signed" in tools[name]:
            copy_regular(Path(tools[name]["signed"]), Path(tools[name]["unsigned"] + ".signed"))
    write_json(run / "fixture-tools.json", tools)
    directory = run / "tests/tools"
    directory.mkdir(parents=True, exist_ok=True)
    for operation in ("build", "sign"):
        target = directory / (operation + ".sh")
        if target.exists():
            raise QualificationError(f"Suite attempts to replace fixture lookup: {target}")
        target.write_text(f'#!/bin/sh\nset -eu\nexec python3 fixture_tool.py {operation} "$@"\n')
    (run / "fixture_tool.py").write_bytes(Path(__file__).with_name("fixture_tool.py").read_bytes())


def prepare(
    lock: Path, composition: Path, output: Path, selected: list[str], candidates: dict
) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    output = output.resolve()
    if "'" in str(output) or any(ord(c) < 32 for c in str(output)):
        raise QualificationError(
            "The imported shell helpers require an output path without quotes or control characters"
        )
    record = {
        "format": 1,
        "status": "preparing",
        "qualification": False,
        "started_unix": time.time(),
        "host": platform.uname()._asdict(),
    }
    write_json(output / "run.json", record)
    try:
        files, tests, sources = resolve_sources(lock, selected, candidates)
        spec_bytes = composition.read_bytes()
        spec = json.loads(spec_bytes)
        if spec.get("format") != 1:
            raise QualificationError("Unsupported composition format")
        record.update(sources)
        record.update(composition_sha256=digest(spec_bytes), composition=spec, tests=tests)
        write_json(output / "run.json", record)
        paths, artifacts = stage_artifacts(spec, composition.parent, output / "artifacts")
        cfg = configuration(spec, paths, output)
        packages = check_packages(spec, paths)
        for name, data in files.items():
            target = output / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        fixture_tools(spec, paths, output)
        (output / "provium.toml").write_text(cfg)
        env = host_environment(spec, paths, output)
        command, mode = provium_command(spec, paths, tests)
        selected_sources = [
            entry for entry in sources["sources"] if not selected or entry["component"] in selected
        ]
        if mode == "harness" and any(
            not entry["harness_only"] and any(name in tests for name in entry["files"])
            for entry in selected_sources
        ):
            raise QualificationError(
                "Local harness runs require explicitly harness-only test suites"
            )
        record.update(sources)
        record.update(
            status="prepared",
            mode=mode,
            tests=tests,
            artifacts=artifacts,
            signed_fixtures={
                str(p.relative_to(output)): fingerprint(p)
                for p in (output / "artifacts").glob("*.signed")
                if p.is_file()
            },
            packages=packages,
            composition_sha256=digest(spec_bytes),
            composition=spec,
            environment=env,
            command=command,
            host_runtime=host_runtime(env),
            implementation={
                p.name: digest(p.read_bytes()) for p in Path(__file__).parent.glob("*.py")
            },
        )
        write_json(output / "run.json", record)
        return record
    except Exception as error:
        record.update(status="blocked", error=str(error))
        write_json(output / "run.json", record)
        raise


def summarize(stdout: str, tests: list[str], output: Path) -> dict:
    results = []
    for line in stdout.splitlines():
        if line.strip():
            results.append(json.loads(line))
    paths = []
    counts = {"passed": 0, "failed": 0, "skipped": 0}
    for result in results:
        path = Path(result["path"])
        paths.append(str(path.relative_to(output)) if path.is_absolute() else str(path))
        if (
            result.get("chunk_error")
            or result.get("timeout") != "in_time"
            or result.get("passed") is not True
        ):
            counts["failed"] += 1
        if not result.get("tests"):
            counts["failed"] += 1
        for case in result["tests"]:
            counts[case["status"]] += 1
    if sorted(paths) != sorted(tests):
        raise QualificationError("Provium did not report each selected test file exactly once")
    return counts


def execute(output: Path, record: dict, timeout: float) -> int:
    if not math.isfinite(timeout) or timeout <= 0:
        raise QualificationError("Run timeout must be positive and finite")
    record["status"] = "running"
    write_json(output / "run.json", record)
    code = 1
    try:
        with (
            (output / "stdout.jsonl").open("wb") as stdout,
            (output / "stderr.log").open("wb") as stderr,
        ):
            process = subprocess.Popen(
                record["command"],
                cwd=output,
                env=record["environment"],
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
            )
            try:
                code = process.wait(timeout=timeout)
            except BaseException:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
                raise
        counts = summarize((output / "stdout.jsonl").read_text(), record["tests"], output)
        record["counts"] = counts
        record["working_disks"] = {
            p.name: fingerprint(p) for p in (output / "working-disks").glob("*")
        }
        changed = []
        for name, artifact in record["artifacts"].items():
            if fingerprint(output / "artifacts" / name) != artifact["sha256"]:
                changed.append(name)
        for name, expected in record["signed_fixtures"].items():
            if fingerprint(output / name) != expected:
                changed.append(name)
        if changed:
            raise QualificationError(f"Input artifacts changed during the run: {changed}")
        record["status"] = (
            "failed"
            if code or counts["failed"]
            else "incomplete"
            if counts["skipped"]
            else "passed"
        )
        record["qualification"] = record["status"] == "passed" and record["mode"] == "system"
        code = 0 if record["status"] == "passed" else 3 if record["status"] == "incomplete" else 1
    except KeyboardInterrupt:
        record.update(status="interrupted", error="Interrupted by user")
        code = 130
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        IndexError,
        QualificationError,
        subprocess.TimeoutExpired,
    ) as error:
        record.update(status="failed", error=str(error))
        code = 1
    finally:
        record.update(finished_unix=time.time(), exit_code=code)
        write_json(output / "run.json", record)
    return code


def provium_command(spec: dict, paths: dict[str, Path], tests: list[str]) -> tuple[list[str], str]:
    """Validate run policy and produce the sole supported runner invocation."""
    runner = artifact_path(spec["runner"], paths)
    if not Path(runner).is_file() or not os.access(runner, os.X_OK):
        raise QualificationError("The recorded Provium runner must be executable")
    mode = spec.get("mode", "system")
    if mode not in {"system", "harness"}:
        raise QualificationError("Unknown run mode")
    if mode == "system" and (not spec["profiles"] or not spec.get("components")):
        raise QualificationError(
            "System runs require boot profiles and a declared component composition"
        )
    if mode == "system" and "qemu-system-x86_64" not in spec.get("host_tools", {}):
        raise QualificationError("System runs require a recorded QEMU executable")
    for component, revision in spec.get("components", {}).items():
        if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise QualificationError(f"Composition needs an exact source commit for {component}")
    file_timeout = spec.get("file_timeout_seconds", 300)
    if (
        not isinstance(file_timeout, (int, float))
        or not math.isfinite(file_timeout)
        or file_timeout <= 0
    ):
        raise QualificationError("File timeout must be positive and finite")
    command = [
        runner,
        "--config",
        "provium.toml",
        "--no-build",
        "--json",
        "--include-slow",
        "--save-events",
        "events.msgpack",
        "--timeout",
        str(file_timeout) + "s",
    ]
    if mode == "harness":
        command += ["--vmm", "local", "--no-preflight"]
    command += tests
    return command, mode


def host_runtime(environment: dict[str, str]) -> dict:
    """Record relevant host executables; this is not a hermetic dependency closure."""
    names = (
        "python3",
        "sh",
        "git",
        "cpio",
        "gzip",
        "mkdir",
        "chmod",
        "mktemp",
        "rm",
        "find",
        "sleep",
        "ip",
        "tc",
    )
    executables = {}
    for name in names:
        path = shutil.which(name, path=environment["PATH"])
        if path:
            resolved = Path(path).resolve()
            executables[name] = {"path": str(resolved), "sha256": fingerprint(resolved)}
    return {"python": sys.version, "executables": executables}
