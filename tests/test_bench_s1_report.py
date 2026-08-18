"""Combining the four Study 1 strata into one report.

The llm-generated stratum's own committed numbers must survive unchanged -
this is the "extend, do not replace" requirement - so that is what is
checked, alongside every stratum actually appearing in the combined output.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from bench import corpus
from bench.s1_report import combine, render_markdown, write

LLM_GENERATED_PAYLOAD = {
    "study": "S1 llm-generated stratum",
    "model": "qwen2.5:3b",
    "limitation": "a 3B-class open-weight model",
    "completions": [],
    "aggregate": {
        "completions_total": 12,
        "materialised": 0,
        "excluded": 12,
        "mean_score": None,
        "with_critical_finding": 0,
        "check_failure_counts": {},
    },
}


def _stratum_payload(stratum: str) -> dict[str, Any]:
    return corpus.to_dict(stratum, "note", [])


def test_combine_preserves_llm_generated_payload_unchanged() -> None:
    combined = combine(
        _stratum_payload("official-docs"),
        _stratum_payload("mcp-servers"),
        _stratum_payload("templates"),
        LLM_GENERATED_PAYLOAD,
    )

    assert combined["llm_generated"] == LLM_GENERATED_PAYLOAD


def test_render_markdown_includes_every_stratum() -> None:
    combined = combine(
        _stratum_payload("official-docs"),
        _stratum_payload("mcp-servers"),
        _stratum_payload("templates"),
        LLM_GENERATED_PAYLOAD,
    )

    text = render_markdown(combined)

    assert "official-docs" in text
    assert "mcp-servers" in text
    assert "templates" in text
    assert "llm-generated" in text
    assert "qwen2.5:3b" in text
    assert "Aggregate across strata" in text
    # Only one h1: the llm-generated stratum's own heading is demoted so it
    # sits alongside the other three sections rather than starting a new
    # top-level document.
    assert text.count("\n# ") + (1 if text.startswith("# ") else 0) == 1


def test_write_reads_every_strata_flat_file_and_writes_only_results_md(
    tmp_path: Path,
) -> None:
    s1_root = tmp_path / "s1"
    s1_root.mkdir(parents=True)
    (s1_root / "results.json").write_text(json.dumps(LLM_GENERATED_PAYLOAD), encoding="utf-8")
    for stratum in ("official-docs", "mcp-servers", "templates"):
        (s1_root / f"results.{stratum}.json").write_text(
            json.dumps(_stratum_payload(stratum)), encoding="utf-8"
        )

    combined = write(s1_root)

    assert combined["llm_generated"] == LLM_GENERATED_PAYLOAD
    assert (s1_root / "RESULTS.md").is_file()
    # research/studies/s1/results.json must keep meaning "the llm-generated
    # stratum's own result" for bench/coverage.py - write() must not touch it.
    untouched = json.loads((s1_root / "results.json").read_text(encoding="utf-8"))
    assert untouched == LLM_GENERATED_PAYLOAD
