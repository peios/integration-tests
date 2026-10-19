"""Command-line entry point for recorded Peios conformance runs."""

import argparse
import json
import math
import sys
from pathlib import Path

from qualification.artifacts import fingerprint
from qualification.run import execute, prepare, write_json
from qualification.sources import QualificationError, pin_catalog, resolve_sources


def positive_seconds(value: str) -> float:
    """Reject timeouts that cannot impose a real deadline."""
    seconds = float(value)
    if not math.isfinite(seconds) or seconds <= 0:
        raise argparse.ArgumentTypeError("timeout must be positive and finite")
    return seconds


def parser() -> argparse.ArgumentParser:
    """Describe explicit inputs; never discover a sibling build implicitly."""
    cli = argparse.ArgumentParser(description="Run Peios suites against recorded artifacts.")
    commands = cli.add_subparsers(dest="command", required=True)
    hash_command = commands.add_parser("hash", help="hash a supplied file or tree")
    hash_command.add_argument("path", type=Path)
    pin = commands.add_parser("pin", help="record the committed revisions in a suite catalog")
    pin.add_argument("--catalog", type=Path, required=True)
    pin.add_argument("--output", type=Path, required=True)
    for operation in ("list", "prepare", "run"):
        command = commands.add_parser(operation)
        command.add_argument("--lock", type=Path, required=True)
        command.add_argument("--suite", action="append", default=[])
        command.add_argument("--candidate", action="append", default=[], metavar="COMPONENT=REPO")
        if operation != "list":
            command.add_argument("--composition", type=Path, required=True)
            command.add_argument("--output", type=Path, required=True)
        if operation == "run":
            command.add_argument("--timeout-seconds", type=positive_seconds, default=3600)
    return cli


def candidates(values: list[str]) -> dict[str, Path]:
    result = {}
    for value in values:
        name, separator, path = value.partition("=")
        if not separator or not path or name in result:
            raise QualificationError("Candidates must be unique COMPONENT=REPO pairs")
        result[name] = Path(path).resolve()
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "hash":
            print(fingerprint(args.path.absolute()))
        elif args.command == "pin":
            write_json(args.output, pin_catalog(args.catalog))
        elif args.command == "list":
            _, tests, provenance = resolve_sources(
                args.lock, args.suite, candidates(args.candidate)
            )
            print(json.dumps({"tests": tests, **provenance}, indent=4))
        else:
            record = prepare(
                args.lock.resolve(),
                args.composition.resolve(),
                args.output,
                args.suite,
                candidates(args.candidate),
            )
            if args.command == "run":
                return execute(args.output.resolve(), record, args.timeout_seconds)
            print(f"Prepared {len(record['tests'])} test files in {args.output}")
        return 0
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        IndexError,
        QualificationError,
    ) as error:
        print(f"peios-qualify: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
