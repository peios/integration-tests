"""Resolve supplied guest tools; never compile or sign during qualification."""

import json
import sys
from pathlib import Path


def main() -> None:
    tools = json.loads(Path("fixture-tools.json").read_text())
    operation, *arguments = sys.argv[1:]
    if operation == "build" and len(arguments) == 1:
        print(tools[arguments[0]]["unsigned"])
    elif operation == "sign" and len(arguments) == 2:
        source, output = map(Path, arguments)
        entry = next(t for t in tools.values() if Path(t["unsigned"]) == source)
        # The existing Lua helper expects this exact adjacent output filename.
        if output != Path(str(source) + ".signed"):
            raise ValueError("Unexpected signed fixture destination")
        if "signed" not in entry or not output.is_file():
            raise ValueError("No supplied signed fixture")
        print(output)
    else:
        raise ValueError("Expected build NAME or sign INPUT OUTPUT")


if __name__ == "__main__":
    try:
        main()
    except (KeyError, StopIteration, ValueError, OSError) as error:
        print(f"Missing or invalid supplied fixture tool: {error}", file=sys.stderr)
        raise SystemExit(2) from None
