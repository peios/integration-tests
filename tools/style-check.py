"""Check maintained code with the pinned PSC style tools."""

import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def tool(name: str, version: str) -> str:
    directory = os.environ.get("PEIOS_STYLE_BIN")
    path = str(Path(directory) / name) if directory else shutil.which(name)
    if path is None:
        raise SystemExit("Missing style tool: " + name)
    found = subprocess.check_output([path, "--version"], text=True)
    if version not in [line.strip() for line in found.splitlines()]:
        raise SystemExit("Unexpected " + name + " version: " + found.strip())
    return path


def run(*args: str) -> None:
    subprocess.run(args, cwd=ROOT, check=True)


def main() -> None:
    python = ["peios-qualify"] + [
        str(p.relative_to(ROOT))
        for folder in ["qualification", "checks", "tools"]
        for p in sorted((ROOT / folder).glob("*.py"))
    ]
    ruff = tool("ruff", "ruff 0.17.0")
    run(ruff, "check", "--no-cache", *python)
    run(ruff, "format", "--check", "--no-cache", *python)
    shell = ["tools/check"]
    run(tool("shellcheck", "version: 0.11.0"), *shell)
    run(tool("shfmt", "v3.14.1"), "-d", "-i", "4", *shell)
    data = [
        ".luarc.json",
        ".prettierrc.json",
        "suite.json",
        "suites.json",
        "suites.lock.json",
        "examples/composition.json",
    ] + [
        str(p.relative_to(ROOT))
        for folder in [".github", "tools"]
        for p in sorted((ROOT / folder).rglob("*"))
        if p.suffix in {".json", ".yml"}
    ]
    run(tool("prettier", "3.9.10"), "--check", *data)


if __name__ == "__main__":
    main()
