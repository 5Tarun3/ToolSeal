"""`toolseal policy` - the half of this feature an operator actually touches.

The control mapping exists so that a failing check can explain itself. A
developer who hits B3 should learn what the rule is, which obligations it
serves and what to run, without opening a standards document. These tests
assert that output, because an explanation nobody can read is not one.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from toolseal.cli import app, policy_command
from toolseal.core.policy import coverage as coverage_module
from toolseal.core.policy.controls import load_catalogues

runner = CliRunner()


def _catalogue_lines(stdout: str) -> dict[str, str]:
    """Map each catalogue id in `policy list` output to its full line.

    The legend below the table also starts with `*`, so it is excluded by
    skipping lines that do not open with an identifier.
    """
    lines: dict[str, str] = {}
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("*"):
            continue
        lines[stripped.split()[0]] = line
    return lines


def test_list_names_every_shipped_catalogue() -> None:
    result = runner.invoke(app, ["policy", "list"])

    assert result.exit_code == 0
    for standard in (
        "owasp-llm-top10",
        "nist-ai-rmf",
        "owasp-agentic-threats",
        "owasp-agentic-top10",
        "iso-42001",
    ):
        assert standard in result.stdout


def test_list_shows_coverage_of_each_standard() -> None:
    result = runner.invoke(app, ["policy", "list"])

    assert "%" in result.stdout


def test_list_marks_the_curated_subsets() -> None:
    # iso-42001 (4 of ~36 controls) and nist-ai-rmf (7 of ~70) are shortlists
    # drawn up before any check mapping existed. Their rows must carry a
    # visible marker so a reader never mistakes "100% of our selection" for
    # "100% of the standard".
    result = runner.invoke(app, ["policy", "list"])
    lines = _catalogue_lines(result.stdout)

    for partial in ("iso-42001", "nist-ai-rmf"):
        assert "*" in lines[partial]


def test_list_does_not_mark_the_fully_enumerated_catalogues() -> None:
    result = runner.invoke(app, ["policy", "list"])
    lines = _catalogue_lines(result.stdout)

    for complete in ("owasp-llm-top10", "owasp-agentic-threats", "owasp-agentic-top10"):
        assert "*" not in lines[complete]


def test_list_legend_names_the_limitation_when_a_catalogue_is_partial() -> None:
    result = runner.invoke(app, ["policy", "list"])

    assert "curated subset" in result.stdout
    assert "measures our selection" in result.stdout


def test_list_omits_the_legend_when_nothing_is_partial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Filter to only the fully-enumerated catalogues rather than deleting a
    # data file, so this does not depend on which catalogues happen to ship.
    complete_only = {
        key: catalogue
        for key, catalogue in load_catalogues().items()
        if catalogue.complete_enumeration
    }
    assert complete_only, "expected at least one fully-enumerated catalogue to filter to"

    monkeypatch.setattr(policy_command, "load_catalogues", lambda: complete_only)
    monkeypatch.setattr(coverage_module, "load_catalogues", lambda: complete_only)

    result = runner.invoke(app, ["policy", "list"])

    assert result.exit_code == 0
    assert "*" not in result.stdout
    assert "curated subset" not in result.stdout


def test_explain_a_check_states_the_rule_and_the_fix() -> None:
    result = runner.invoke(app, ["policy", "explain", "B3"])

    assert result.exit_code == 0
    assert "B3" in result.stdout
    assert "Filesystem" in result.stdout
    assert "workspace" in result.stdout.lower()  # the remediation


def test_explain_a_check_names_its_obligations() -> None:
    result = runner.invoke(app, ["policy", "explain", "B3"])

    assert "LLM06" in result.stdout
    assert "Excessive Agency" in result.stdout


def test_explain_is_case_insensitive() -> None:
    assert runner.invoke(app, ["policy", "explain", "b3"]).exit_code == 0


def test_explain_a_control_lists_the_checks_that_serve_it() -> None:
    result = runner.invoke(app, ["policy", "explain", "owasp-llm-top10:LLM02"])

    assert result.exit_code == 0
    assert "A1" in result.stdout


def test_explain_an_unknown_subject_fails_usefully() -> None:
    result = runner.invoke(app, ["policy", "explain", "Z99"])

    assert result.exit_code != 0
    assert "Z99" in result.output


def test_explain_a_control_nobody_checks_says_so() -> None:
    # LLM01 is not a configuration property. Saying "no checks" is the honest
    # answer; an empty list with no explanation would read as a bug.
    result = runner.invoke(app, ["policy", "explain", "owasp-llm-top10:LLM01"])

    assert result.exit_code == 0
    assert "not assessable" in result.stdout.lower()
