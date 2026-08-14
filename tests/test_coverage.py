"""The checks x controls matrix, and why both its margins are results.

A control with no check is a scope boundary: an honest statement of what a
configuration auditor cannot reach. A check with no control is either a gap the
standards have not caught up with, or an opinion in our taxonomy.

Reporting both is uncomfortable and deliberate. A coverage figure computed over
only the controls we happen to satisfy would be a marketing number.
"""

from __future__ import annotations

from toolseal.core.policy.coverage import coverage_for, unmapped_checks

FULL_PERCENT = 100


CHECKABLE_OWASP_LLM = 5  # LLM02, LLM03, LLM05, LLM06, LLM10
CHECKABLE_OWASP_AGENTIC_TOP10 = 5  # ASI02, ASI03, ASI04, ASI05, ASI07


def test_coverage_counts_only_checkable_controls() -> None:
    # Five of the ten OWASP LLM risks are not configuration properties. Scoring
    # against all ten would understate coverage by counting the unreachable.
    report = coverage_for("owasp-llm-top10")

    assert report.checkable_total == CHECKABLE_OWASP_LLM
    assert all(entry.control.checkable for entry in report.entries)


def test_covered_controls_name_the_checks_that_cover_them() -> None:
    report = coverage_for("owasp-llm-top10")
    by_id = {entry.control.id: entry for entry in report.entries}

    assert "A1" in by_id["LLM02"].check_ids
    assert "B1" in by_id["LLM06"].check_ids


def test_percentage_is_over_checkable_controls() -> None:
    report = coverage_for("owasp-llm-top10")

    assert report.percentage == round(100 * report.covered / report.checkable_total)


def test_owasp_llm_checkable_controls_are_fully_covered() -> None:
    # LLM02, LLM03, LLM05, LLM06 and LLM10 all have checks. If this ever fails,
    # a check was removed without its coverage being reconsidered.
    report = coverage_for("owasp-llm-top10")

    assert report.percentage == FULL_PERCENT


def test_owasp_agentic_top10_checkable_controls_are_fully_covered() -> None:
    # ASI02, ASI03, ASI04, ASI05 and ASI07 all have checks. Same shape as the
    # OWASP LLM test above, for the Top 10 for Agentic Applications catalogue
    # that did not exist when the LLM test was first written.
    report = coverage_for("owasp-agentic-top10")

    assert report.checkable_total == CHECKABLE_OWASP_AGENTIC_TOP10
    assert report.percentage == FULL_PERCENT


def test_complete_enumeration_is_carried_through_the_report() -> None:
    # A percentage travels into tables and papers without its provenance
    # unless the flag rides along on the report itself, not just a docstring.
    complete = coverage_for("owasp-llm-top10")
    curated = coverage_for("nist-ai-rmf")

    assert complete.complete_enumeration is True
    assert curated.complete_enumeration is False


def test_uncovered_controls_are_reported_not_hidden() -> None:
    # NIST is far broader than a config auditor reaches, and the report must
    # say so rather than quietly scoring only what it touches.
    report = coverage_for("nist-ai-rmf")
    uncovered = [entry.control.id for entry in report.entries if not entry.is_covered]

    assert report.percentage < FULL_PERCENT
    assert uncovered


def test_unmapped_checks_are_listed() -> None:
    # Empty today. Kept as a list rather than a boolean so that adding an
    # unmapped check is a visible diff in the report, not a silent state.
    assert unmapped_checks() == ()


def test_an_unknown_standard_is_refused() -> None:
    import pytest

    from toolseal.errors import ConfigError

    with pytest.raises(ConfigError, match="unknown standard"):
        coverage_for("not-a-standard")
