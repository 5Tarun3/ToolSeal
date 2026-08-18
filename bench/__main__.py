"""Run Study 2 and write its results.

uv run python -m bench --out research/studies/s2
"""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

from bench import (
    corpus,
    coverage,
    generated,
    mcp_servers,
    official_docs,
    overhead,
    s1_report,
    templates,
)
from bench.harness import run, to_dict, to_markdown, write

S1_SUB_STUDIES = (
    "s1",
    "s1-official-docs",
    "s1-mcp-servers",
    "s1-templates",
    "s1-combine",
)


def main() -> int:
    parser = argparse.ArgumentParser(prog="bench", description="Run an evaluation study.")
    parser.add_argument(
        "study", choices=(*S1_SUB_STUDIES, "s2", "s3", "s5"), help="Which study to run."
    )
    parser.add_argument(
        "--out", type=Path, default=None, help="Where to write results.json and RESULTS.md."
    )
    parser.add_argument(
        "--repeats", type=int, default=200, help="Repeats per measurement (s3 only)."
    )
    parser.add_argument("--model", default="qwen2.5:3b", help="Model to prompt (s1 only).")
    parser.add_argument("--samples", type=int, default=3, help="Samples per task (s1 only).")
    args = parser.parse_args()
    study_root = Path("research/studies/s1")
    out = args.out or Path("research/studies") / args.study.split("-", 1)[0]

    if args.study == "s1":
        out = args.out or study_root
        with tempfile.TemporaryDirectory(prefix="toolseal-s1-") as workspace:
            completions = generated.run(Path(workspace), model=args.model, samples=args.samples)
        payload = generated.to_dict(completions, args.model)
        generated.write(payload, out)
        print(generated.to_markdown(payload))
    elif args.study == "s1-official-docs":
        out = args.out or study_root / "official-docs"
        with tempfile.TemporaryDirectory(prefix="toolseal-s1-docs-") as workspace:
            artefacts = official_docs.run(Path(workspace))
        payload = corpus.to_dict("official-docs", official_docs.POPULATION_NOTE, artefacts)
        corpus.write(payload, artefacts, out)
        corpus.write_flat_index(payload, study_root, "official-docs")
        print(corpus.to_markdown(payload))
    elif args.study == "s1-mcp-servers":
        out = args.out or study_root / "mcp-servers"
        with tempfile.TemporaryDirectory(prefix="toolseal-s1-mcp-") as workspace:
            artefacts, skipped = mcp_servers.run(Path(workspace))
        payload = corpus.to_dict(
            "mcp-servers", mcp_servers.POPULATION_NOTE, artefacts, skipped=skipped
        )
        corpus.write(payload, artefacts, out)
        corpus.write_flat_index(payload, study_root, "mcp-servers")
        print(corpus.to_markdown(payload))
    elif args.study == "s1-templates":
        out = args.out or study_root / "templates"
        with tempfile.TemporaryDirectory(prefix="toolseal-s1-tmpl-") as workspace:
            artefacts, skipped = templates.run(Path(workspace))
        payload = corpus.to_dict("templates", templates.POPULATION_NOTE, artefacts, skipped=skipped)
        corpus.write(payload, artefacts, out)
        corpus.write_flat_index(payload, study_root, "templates")
        print(corpus.to_markdown(payload))
    elif args.study == "s1-combine":
        combined = s1_report.write(study_root)
        out = study_root
        print(s1_report.render_markdown(combined))
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
