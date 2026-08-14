"""`toolseal policy` - the half of this feature an operator actually touches.

The control mapping exists so that a failing check can explain itself. A
developer who hits B3 should learn what the rule is, which obligations it
serves and what to run, without opening a standards document. These tests
assert that output, because an explanation nobody can read is not one.
"""

from __future__ import annotations

from typer.testing import CliRunner

from toolseal.cli import app

runner = CliRunner()


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
