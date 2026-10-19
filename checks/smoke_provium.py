"""Check the real Provium adapter without booting a VM."""

import argparse
import json
import shutil
from pathlib import Path

from test_qualification import QualificationTests

from qualification.artifacts import fingerprint
from qualification.run import execute, write_json
from qualification.sources import pin_catalog


def main() -> None:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--runner", type=Path, required=True)
    cli.add_argument("--evidence", type=Path, required=True)
    args = cli.parse_args()
    args.evidence.mkdir(parents=True, exist_ok=False)
    for mode, expected in (("pass", 0), ("skip", 3)):
        case = QualificationTests()
        case.setUp()
        try:
            if mode == "skip":
                case.test.write_text('test("skip", {skip="smoke"}, function(t) end)\n')
                case.commit()
                write_json(case.lock, pin_catalog(case.catalog))
            runner = args.runner.resolve()
            case.spec["artifacts"]["runner"] = {"path": str(runner), "sha256": fingerprint(runner)}
            record = case.prepare()
            result = execute(case.output, record, 30)
            target = args.evidence / mode
            target.mkdir()
            for name in ("run.json", "stdout.jsonl", "stderr.log", "events.msgpack"):
                if (case.output / name).exists():
                    shutil.copyfile(case.output / name, target / name)
            if result != expected or record["qualification"]:
                raise RuntimeError(json.dumps(record))
            print(f"{mode}: {record['status']}; qualification=false")
        finally:
            case.doCleanups()


if __name__ == "__main__":
    main()
