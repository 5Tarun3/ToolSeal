"""The audit engine: scoring semantics, family A and C checks, and extraction.

Scoring is tested harder than detection, because a scoring bug is silent. A
missed pattern shows up as a finding nobody reported; a wrong denominator turns
every number the paper quotes into a wrong number.

No test here reaches the network. C2's OSV call is faked; the live behaviour is
covered by the check reporting `unknown` when the lookup fails.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

import pytest
from typer.testing import CliRunner

from toolseal.cli import app
from toolseal.core.adapters import ScaffoldSpec
from toolseal.core.audit import audit, extract
from toolseal.core.audit.engine import audit_model
from toolseal.core.model import Dependency, DependencySet, ProjectModel, RuntimeConfig
from toolseal.core.policy import all_checks, checks_in
from toolseal.core.policy.family_a import is_env_var_name, is_inert
from toolseal.core.policy.family_c import AdvisoryLookupError, query_osv
from toolseal.core.policy.model import (
    AuditReport,
    Check,
    CheckResult,
    Finding,
    Severity,
    Verdict,
)
from toolseal.core.policy.suppress import is_suppressed, suppression_for
from toolseal.core.report import to_sarif
from toolseal.core.scaffold import apply_plan, build_plan
from toolseal.errors import ExitCode

runner = CliRunner()


def check(check_id: str, severity: Severity) -> Check:
    return Check(
        id=check_id,
        family=check_id[0],
        title=check_id,
        severity=severity,
        remediation="",
        run=lambda _model: (),
    )


def result(check_id: str, severity: Severity, verdict: Verdict) -> CheckResult:
    return CheckResult(check(check_id, severity), verdict, ())


# --- scoring ---------------------------------------------------------------


def test_all_passing_scores_one_hundred() -> None:
    report = AuditReport(
        root=".",
        results=(
            result("A1", Severity.CRITICAL, Verdict.PASS),
            result("C1", Severity.HIGH, Verdict.PASS),
        ),
    )
    assert report.score == 100
    assert not report.blocking


def test_severity_weighting_is_applied() -> None:
    # critical=10, low=1: failing the low one costs 1/11 of the total.
    report = AuditReport(
        root=".",
        results=(
            result("A1", Severity.CRITICAL, Verdict.PASS),
            result("C5", Severity.LOW, Verdict.FAIL),
        ),
    )
    assert report.score == round(100 * (1 - 1 / 11))


def test_inapplicable_checks_leave_the_denominator() -> None:
    # Otherwise a project is penalised for a feature it never configured.
    scored = AuditReport(root=".", results=(result("A1", Severity.CRITICAL, Verdict.PASS),))
    with_na = AuditReport(
        root=".",
        results=(
            result("A1", Severity.CRITICAL, Verdict.PASS),
            result("D1", Severity.CRITICAL, Verdict.NOT_APPLICABLE),
        ),
    )
    assert scored.score == with_na.score == 100


def test_unknown_is_not_counted_as_a_pass() -> None:
    report = AuditReport(root=".", results=(result("C2", Severity.HIGH, Verdict.UNKNOWN),))

    # Nothing was actually evaluated, so no assurance is claimed either way.
    assert report.score == 100
    assert report.results[0].verdict is Verdict.UNKNOWN
    assert not report.results[0].counts_towards_score


def test_blocking_is_reported_apart_from_the_score() -> None:
    # One critical failure among many passes barely moves the average, which is
    # exactly why `blocking` exists.
    results = tuple(result(f"X{i}", Severity.LOW, Verdict.PASS) for i in range(40))
    report = AuditReport(
        root=".", results=(*results, result("A1", Severity.CRITICAL, Verdict.FAIL))
    )

    assert report.score > 75
    assert report.blocking


def test_findings_are_ordered_most_severe_first() -> None:
    model = ProjectModel(root=Path())
    report = audit_model(model)
    severities = [list(Severity).index(f.severity) for f in report.findings]
    assert severities == sorted(severities)


def test_a_raising_check_does_not_silence_the_others(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(_model: ProjectModel) -> Sequence[Finding]:
        message = "check is broken"
        raise RuntimeError(message)

    broken = Check(
        id="Z9", family="Z", title="broken", severity=Severity.LOW, remediation="", run=explode
    )
    monkeypatch.setattr("toolseal.core.audit.engine.all_checks", lambda: (broken, *all_checks()))

    report = audit_model(ProjectModel(root=Path()))

    assert any(r.check.id == "Z9" and r.verdict is Verdict.UNKNOWN for r in report.results)
    assert len(report.results) > 1


# --- suppression -----------------------------------------------------------


def test_suppression_requires_a_check_id_and_a_reason() -> None:
    assert is_suppressed('k = "x"  # toolseal:allow A1 - fixture', "A1")
    assert not is_suppressed('k = "x"  # toolseal:allow', "A1")
    assert not is_suppressed('k = "x"  # toolseal:allow A1', "A1")


def test_suppression_does_not_leak_to_other_checks() -> None:
    line = 'k = "x"  # toolseal:allow A1 - fixture'
    assert is_suppressed(line, "A1")
    assert not is_suppressed(line, "A2")


def test_suppression_reason_is_recoverable() -> None:
    assert suppression_for("# toolseal:allow A1 - test fixture", "A1") == "test fixture"


# --- family A --------------------------------------------------------------


def test_credential_literal_is_found(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        'OPENAI_API_KEY = "sk-abcdefghijklmnopqrst"\n',  # toolseal:allow A1 - detection under test
        encoding="utf-8",
    )

    findings = [f for f in audit(tmp_path).findings if f.check_id == "A1"]

    assert findings
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].line == 1


def test_suppressed_credential_is_not_reported(tmp_path: Path) -> None:
    (tmp_path / "conftest.py").write_text(
        'KEY = "sk-abcdefghijklmnopqrstuvwxyz01"  # toolseal:allow A1 - redaction fixture\n',
        encoding="utf-8",
    )

    assert not [f for f in audit(tmp_path).findings if f.check_id == "A1"]


def test_example_file_with_names_only_is_clean(tmp_path: Path) -> None:
    (tmp_path / ".env.example").write_text("ANTHROPIC_API_KEY=\n", encoding="utf-8")

    assert not [f for f in audit(tmp_path).findings if f.check_id == "A1"]


def test_example_file_with_a_real_value_is_reported(tmp_path: Path) -> None:
    (tmp_path / ".env.example").write_text(
        'ANTHROPIC_API_KEY="'
        'sk-ant-abcdefghijklmnopqrst"\n',  # toolseal:allow A1 - fake; a value (not name) is flagged
        encoding="utf-8",
    )

    assert [f for f in audit(tmp_path).findings if f.check_id == "A1"]


# --- is_env_var_name: naming a credential is not leaking it ----------------


def test_an_env_var_name_as_a_value_is_inert() -> None:
    # A1's own remediation is "reference the credential by name". A config
    # line that does exactly that must not itself be the thing A1 reports.
    assert is_env_var_name("FAKE_API_KEY")
    assert is_inert("FAKE_API_KEY")


def test_an_env_var_name_assignment_is_not_reported(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text('credential_env_var = "FAKE_API_KEY"\n', encoding="utf-8")

    assert not [f for f in audit(tmp_path).findings if f.check_id == "A1"]


def test_all_caps_without_an_underscore_is_not_an_env_var_name() -> None:
    # An AWS access key id is itself all-caps, so the underscore requirement
    # is what keeps that credential shape out of the exemption.
    assert not is_env_var_name("AKIAIOSFODNN7EXAMPLE")  # toolseal:allow A1 - fake AWS key shape
    assert not is_inert("AKIAIOSFODNN7EXAMPLE")  # toolseal:allow A1 - fake AWS key shape


def test_an_aws_shaped_assignment_is_still_reported(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        'API_KEY = "AKIAIOSFODNN7EXAMPLE"\n',  # toolseal:allow A1 - real shape must stay caught
        encoding="utf-8",
    )

    assert [f for f in audit(tmp_path).findings if f.check_id == "A1"]


def test_lowercase_values_are_unaffected_by_the_exemption() -> None:
    # The refinement is case-sensitive on purpose: it must not widen the hole
    # for an ordinary lowercase or mixed-case secret.
    assert not is_env_var_name("a-real-looking-secret-value")
    assert not is_inert("a-real-looking-secret-value")


def test_env_file_without_an_ignore_rule_is_reported(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("SOMETHING=1\n", encoding="utf-8")

    assert [f for f in audit(tmp_path).findings if f.check_id == "A2"]


def test_env_file_covered_by_gitignore_is_clean(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text(".env\n", encoding="utf-8")
    (tmp_path / ".env").write_text("SOMETHING=1\n", encoding="utf-8")

    assert not [f for f in audit(tmp_path).findings if f.check_id == "A2"]


def test_missing_redaction_is_reported(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("print('hello')\n", encoding="utf-8")

    assert [f for f in audit(tmp_path).findings if f.check_id == "A4"]


# --- family C --------------------------------------------------------------


def test_unpinned_dependency_and_missing_lockfile_are_reported(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests>=2.0\n", encoding="utf-8")

    findings = [f for f in audit(tmp_path).findings if f.check_id == "C1"]

    assert any("lockfile" in f.title.lower() for f in findings)
    assert any("Unpinned" in f.title for f in findings)


def test_pinned_dependency_with_a_lockfile_is_clean(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / "uv.lock").write_text("", encoding="utf-8")

    assert not [f for f in audit(tmp_path).findings if f.check_id == "C1"]


def test_osv_is_not_queried_for_unresolved_versions() -> None:
    # A range cannot be looked up, and guessing which version it would install
    # would produce findings about software the project may never run.
    assert query_osv([Dependency(name="requests", specifier=">=2.0")]) == {}


def test_advisory_lookup_failure_surfaces_as_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    def unreachable(*_args: object, **_kwargs: object) -> dict[str, list[str]]:
        message = "OSV was unreachable (URLError)"
        raise AdvisoryLookupError(message)

    monkeypatch.setattr("toolseal.core.policy.family_c.query_osv", unreachable)

    model = ProjectModel(
        root=Path(),
        dependencies=DependencySet(
            declared=(Dependency("requests", "==2.32.3", pinned=True, resolved_version="2.32.3"),)
        ),
        runtime=RuntimeConfig(redacts_credentials=True),
    )
    report = audit_model(model)

    c2 = next(r for r in report.results if r.check.id == "C2")
    assert c2.verdict is Verdict.UNKNOWN


# --- extraction ------------------------------------------------------------


def test_extraction_skips_vendored_directories(tmp_path: Path) -> None:
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "leaked.py").write_text(
        "sk-aaaaaaaaaaaaaaaaaaaaaa",  # toolseal:allow A1 - fake; proves .venv paths are skipped
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text("x = 1\n", encoding="utf-8")

    paths = {str(entry.path) for entry in extract(tmp_path).files}

    assert "main.py" in paths
    assert not any(".venv" in path for path in paths)


def test_shallow_ignore_rules_do_not_hide_findings(tmp_path: Path) -> None:
    # A pattern the parser does not understand must leave the file scanned.
    # Suppressing a finding is the worse failure direction.
    (tmp_path / ".gitignore").write_text("**/nested/**\n", encoding="utf-8")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "config.py").write_text(
        'API_KEY = "sk-abcdefghijklmnopqrst"\n',  # toolseal:allow A1 - fake; must reach the scanner
        encoding="utf-8",
    )

    assert [f for f in audit(tmp_path).findings if f.check_id == "A1"]


# --- the command -----------------------------------------------------------


def test_clean_project_exits_zero(tmp_path: Path) -> None:
    spec = ScaffoldSpec(
        project_name="demo",
        provider_id="ollama",
        framework_id="langgraph",
        workspace_root=tmp_path / "demo",
    )
    apply_plan(build_plan(spec))
    (tmp_path / "demo" / "uv.lock").write_text("", encoding="utf-8")

    result_ = runner.invoke(app, ["audit", str(tmp_path / "demo"), "--json"])
    payload = json.loads(result_.stdout)

    assert not payload["blocking"], payload["findings"]


def test_findings_produce_exit_code_one(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        'OPENAI_API_KEY = "sk-abcdefghijklmnopqrst"\n',  # toolseal:allow A1 - drives the exit code
        encoding="utf-8",
    )

    assert runner.invoke(app, ["audit", str(tmp_path)]).exit_code == ExitCode.FINDINGS


def test_json_output_carries_scores_and_families(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("x = 1\n", encoding="utf-8")

    payload = json.loads(runner.invoke(app, ["audit", str(tmp_path), "--json"]).stdout)

    assert "score" in payload
    assert "blocking" in payload
    assert {entry["family"] for entry in payload["families"]} >= {"A", "C"}


def test_min_severity_filters_the_report(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("x = 1\n", encoding="utf-8")

    payload = json.loads(
        runner.invoke(app, ["audit", str(tmp_path), "--json", "--min-severity", "critical"]).stdout
    )

    assert all(f["severity"] == "critical" for f in payload["findings"])


def test_every_registered_check_has_a_remediation() -> None:
    # A check with no automatic remediation is a feature request, not a check.
    assert all(item.remediation for item in all_checks())


def test_the_whole_taxonomy_is_registered() -> None:
    # The document in reference/taxonomy.md is normative; this is the drift
    # guard it asks for. Identifiers are permanent and never reused, so a
    # mismatch here is either an unimplemented check or an undocumented one.
    assert {c.id for c in checks_in("A")} == {"A1", "A2", "A3", "A4", "A5"}
    assert {c.id for c in checks_in("B")} == {"B1", "B2", "B3", "B4", "B5"}
    assert {c.id for c in checks_in("C")} == {"C1", "C2", "C4", "C5"}
    assert {c.id for c in checks_in("D")} == {"D1", "D2", "D3"}
    assert {c.id for c in checks_in("E")} == {"E1", "E2", "E3"}
    assert {c.id for c in checks_in("F")} == {"F1", "F2"}
    assert {c.id for c in checks_in("G")} == {"G1", "G2", "G3", "G4", "G5"}


# --- SARIF -----------------------------------------------------------------


def test_sarif_is_well_formed(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("x = 1\n", encoding="utf-8")

    log = to_sarif(audit(tmp_path))

    assert log["version"] == "2.1.0"
    assert len(log["runs"]) == 1
    assert log["runs"][0]["tool"]["driver"]["name"] == "toolseal"


def test_sarif_declares_every_rule_not_only_the_failing_ones(tmp_path: Path) -> None:
    # A consumer that can say "24 of 28 passed" is more useful than one that
    # only ever learns about failures.
    log = to_sarif(audit(tmp_path))

    declared = {rule["id"] for rule in log["runs"][0]["tool"]["driver"]["rules"]}
    assert declared == {item.id for item in all_checks()}


def test_sarif_locations_are_relative(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        'OPENAI_API_KEY = "sk-abcdefghijklmnopqrst"\n',  # toolseal:allow A1 - feeds SARIF location
        encoding="utf-8",
    )

    log = to_sarif(audit(tmp_path))
    located = [r for r in log["runs"][0]["results"] if "locations" in r]

    assert located
    for entry in located:
        uri = entry["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert not Path(uri).is_absolute()
        assert ":" not in uri  # no drive letter leaked from a build machine


def test_sarif_severity_narrowing_keeps_the_original(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        'OPENAI_API_KEY = "sk-abcdefghijklmnopqrst"\n',  # toolseal:allow A1 - feeds SARIF severity
        encoding="utf-8",
    )

    results = to_sarif(audit(tmp_path))["runs"][0]["results"]
    critical = [r for r in results if r["properties"]["severity"] == "critical"]

    assert critical
    assert all(r["level"] == "error" for r in critical)


def test_sarif_command_emits_valid_json(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("x = 1\n", encoding="utf-8")

    payload = json.loads(runner.invoke(app, ["audit", str(tmp_path), "--sarif"]).stdout)

    assert payload["version"] == "2.1.0"
