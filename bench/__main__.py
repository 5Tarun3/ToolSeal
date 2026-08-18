"""Run Study 2 and write its results.

uv run python -m bench --out research/studies/s2
"""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

from bench import coverage, generated, overhead
from bench.harness import run, to_dict, to_markdown, write


def main() -> int:
    parser = argparse.ArgumentParser(prog="bench", description="Run an evaluation study.")
    parser.add_argument("study", choices=("s1", "s2", "s3", "s5"), help="Which study to run.")
    parser.add_argument(
        "--out", type=Path, default=None, help="Where to write results.json and RESULTS.md."
    )
    parser.add_argument(
        "--repeats", type=int, default=200, help="Repeats per measurement (s3 only)."
    )
    parser.add_argument("--model", default="qwen2.5:3b", help="Model to prompt (s1 only).")
    parser.add_argument("--samples", type=int, default=3, help="Samples per task (s1 only).")
    args = parser.parse_args()
    out = args.out or Path("research/studies") / args.study

    if args.study == "s1":
        with tempfile.TemporaryDirectory(prefix="toolseal-s1-") as workspace:
            completions = generated.run(Path(workspace), model=args.model, samples=args.samples)
        payload = generated.to_dict(completions, args.model)
        generated.write(payload, out)
        print(generated.to_markdown(payload))
    elif args.study == "s2":
        with tempfile.TemporaryDirectory(prefix="toolseal-bench-") as workspace:
            results = run(Path(workspace))
        write(results, out)
        print(to_markdown(to_dict(results)))
    elif args.study == "s5":
        payload = coverage.run()
        coverage.write(payload, out)
        print(coverage.to_markdown(payload))
    else:
        payload = overhead.run(args.repeats)
        overhead.write(payload, out)
        print(overhead.to_markdown(payload))

    print(f"written to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
