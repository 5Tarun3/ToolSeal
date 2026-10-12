"""The Study 5 harness (P51): coverage analysis for C6, and the attempted
Study 1 re-cut by control.

Two failure modes matter more than the happy path here. First, the
complete-versus-curated distinction must survive into every rendered row -
losing it is exactly the overclaim §11 warns about. Second, the re-cut must
report its own infeasibility honestly against the real corpus this repository
ships, and must not be a function that only ever returns one answer - it is
exercised here against both a corpus with nothing to re-cut (the real one)
and synthetic per-check data that does support a re-cut, so "possible: True"
is proven reachable rather than dead code.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from bench import coverage as study5

from toolseal.core.policy.controls import load_catalogues


def test_coverage_analysis_reports_every_shipped_catalogue() -> None:
    payload = study5.coverage_analysis()

    ids = {entry["id"] for entry in payload["catalogues"]}
    assert ids == set(load_catalogues())


def test_coverage_analysis_carries_the_complete_enumeration_flag() -> None:
    payload = study5.coverage_analysis()
    by_id = {entry["id"]: entry for entry in payload["catalogues"]}

    assert by_id["owasp-llm-top10"]["complete_enumeration"] is True
    assert by_id["nist-ai-rmf"]["complete_enumeration"] is False
    assert by_id["iso-42001"]["complete_enumeration"] is False


def test_coverage_analysis_reports_uncovered_checkable_controls_by_name() -> None:
    # The unreachable remainder is a finding in its own right (spec §11), not
    # a shortfall to summarise away - each entry must name the control, not
    # just count it.
    payload = study5.coverage_analysis()
    by_id = {entry["id"]: entry for entry in payload["catalogues"]}

    nist = by_id["nist-ai-rmf"]
    assert nist["percentage"] < 100
    assert nist["uncovered"]
    assert all({"id", "title"} <= set(control) for control in nist["uncovered"])


def test_coverage_analysis_lists_checks_citing_no_control() -> None:
    payload = study5.coverage_analysis()

    assert isinstance(payload["unmapped_checks"], list)
    assert payload["checks_total"] >= len(payload["unmapped_checks"])


# --- part (b): the real corpus ----------------------------------------------


def test_recut_against_the_real_s1_corpus_is_delivered() -> None:
    # Asserted against the real file, not a fixture. Until 2026-10-09 this
    # asserted infeasibility: 0 of 12 completions had materialised. That zero
    # was a filename-recovery defect (bench/generated.py's docstring), and
    # with it fixed the corpus has per-check data to re-cut.
    result = study5.recut_study1_by_control()

    assert result["possible"] is True
    assert result["control_failure_counts"]
    # The llm-generated input is exploratory, so the re-cut built on it is too.
    assert result["status"].startswith("exploratory")


def test_recut_reports_no_missing_strata_now_all_four_are_collected() -> None:
    result = study5.recut_study1_by_control()

    assert result["missing_strata"] == []


def test_recut_is_reported_per_stratum() -> None:
    # Study 1 reports each stratum before any aggregate, because an aggregate
    # can hide a stratum the others do not resemble. The re-cut follows suit.
    strata = study5.recut_study1_by_control()["strata"]

    assert [s["stratum"] for s in strata] == [
        "llm-generated",
        "official-docs",
        "mcp-servers",
        "templates",
    ]
    assert all(s["control_failure_counts"] for s in strata if s["materialised"])


def test_recut_with_no_results_file_at_all_says_so(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(study5, "S1_RESULTS", tmp_path / "nowhere" / "results.json")

    result = study5.recut_study1_by_control()

    assert result["possible"] is False
    assert "does not exist" in result["reason"]


# --- part (b): proven reachable against synthetic data ----------------------


def test_recut_produces_a_per_control_table_when_the_corpus_supports_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A1 and A2 both cite owasp-llm-top10:LLM02 (tests/test_control_mapping.py
    # pins A1's citation; A2 shares it per reference/taxonomy.md). A synthetic
    # corpus where both fail must therefore show LLM02 failing on both
    # completions worth of count, proving the check -> control fan-in is
    # actually summed rather than merely passed through.
    fixture = tmp_path / "results.json"
    fixture.write_text(
        json.dumps(
            {
                "aggregate": {
                    "materialised": 2,
                    "completions_total": 2,
                    "check_failure_counts": {"A1": 2, "A2": 1},
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(study5, "S1_RESULTS", fixture)

    result = study5.recut_study1_by_control()

    assert result["possible"] is True
    assert result["control_failure_counts"]["owasp-llm-top10:LLM02"] == 3


# --- rendering ---------------------------------------------------------------


def test_markdown_marks_curated_catalogues_visibly() -> None:
    text = study5.to_markdown(study5.run())

    assert "curated subset" in text
    assert "`nist-ai-rmf`" in text
    assert "*" in text


def test_markdown_states_the_citation_not_adequacy_caveat() -> None:
    text = study5.to_markdown(study5.run())

    assert "not adequacy" in text or "not evidence the check discharges" in text


def test_markdown_delivers_the_recut_and_labels_it() -> None:
    text = study5.to_markdown(study5.run())

    assert "Not delivered" not in text
    assert "exploratory" in text
    # The counts are check failures summed per control, which can exceed the
    # number of completions; the header must not claim to count completions.
    assert "completions failing at least one check" not in text
    assert "check failures citing it" in text


def test_markdown_reports_the_recut_gap_honestly_when_infeasible(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(study5, "S1_RESULTS", tmp_path / "nowhere" / "results.json")

    text = study5.to_markdown(study5.run())

    assert "Not delivered" in text
    assert "honest gap beats a fabricated table" in text


def test_write_emits_both_artifacts(tmp_path: Path) -> None:
    study5.write(study5.run(), tmp_path)

    payload = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
    assert payload["study"].startswith("S5")
    assert (tmp_path / "RESULTS.md").read_text(encoding="utf-8").startswith("# Study 5")


def test_run_is_reproducible() -> None:
    first = study5.run()
    second = study5.run()

    assert first == second
