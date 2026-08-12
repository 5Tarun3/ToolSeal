"""Run Study 2 and write its results.

uv run python -m bench --out research/studies/s2
"""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

from bench.harness import run, to_dict, to_markdown, write


def main() -> int:
    parser = argparse.ArgumentParser(prog="bench", description="Run Study 2.")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("research/studies/s2"),
        help="Where to write results.json and RESULTS.md.",
    )
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="toolseal-bench-") as workspace:
        results = run(Path(workspace))

    write(results, args.out)
    print(to_markdown(to_dict(results)))
    print(f"written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
