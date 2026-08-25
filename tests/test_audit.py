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


def test_relaxed_leaves_the_denominator() -> None:
    # Exactly like NOT_APPLICABLE: a waiver is not evidence the check passed.
    report = AuditReport(
        root=".",
        results=(
            result("A1", Severity.CRITICAL, Verdict.PASS),
            result("B2", Severity.CRITICAL, Verdict.RELAXED),
        ),
    )
    assert report.score == 100
    assert not report.results[1].counts_towards_score


def test_relaxed_critical_is_reported_apart_from_blocking_and_score() -> None:
    # A relaxed critical must never lower the score (RELAXED leaves the
    # denominator) and must never look like a live blocker (it is not a FAIL) -
    # but it must still be visible on its own, the way `blocking` is.
    results = tuple(result(f"X{i}", Severity.LOW, Verdict.PASS) for i in range(40))
    report = AuditReport(
        root=".", results=(*results, result("B2", Severity.CRITICAL, Verdict.RELAXED))
    )

    assert report.score == 100
    assert not report.blocking
    assert report.relaxed_critical


def test_relaxed_critical_is_false_when_nothing_critical_was_relaxed() -> None:
    report = AuditReport(
        root=".",
        results=(
            result("C5", Severity.LOW, Verdict.RELAXED),
            result("A1", Severity.CRITICAL, Verdict.FAIL),
        ),
    )
    assert report.blocking
    assert not report.relaxed_critical


def test_finding_subject_defaults_to_none() -> None:
    # Absence means "this finding names no single entity", not "unknown" -
    # the same absent-means-unset rule the rest of the model follows.
    finding = Finding(check_id="A1", severity=Severity.CRITICAL, title="t", detail="d")
    assert finding.subject is None
    assert finding.location is None


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


def test_lockfile_with_unpinned_specifiers_is_clean(tmp_path: Path) -> None:
    # A lockfile already delivers the reproducibility C1 exists to protect, so
    # an unpinned specifier in project metadata is no longer a finding once one
    # is present - refined 2026-08-18.
    (tmp_path / "requirements.txt").write_text("requests>=2.0\n", encoding="utf-8")
    (tmp_path / "uv.lock").write_text("", encoding="utf-8")

    assert not [f for f in audit(tmp_path).findings if f.check_id == "C1"]


def test_no_lockfile_and_no_pinning_is_still_reported(tmp_path: Path) -> None:
    # With neither a lockfile nor a fully pinned set, both findings still fire -
    # the lockfile refinement narrows the check, it does not remove it.
    (tmp_path / "requirements.txt").write_text("requests>=2.0\n", encoding="utf-8")

    findings = [f for f in audit(tmp_path).findings if f.check_id == "C1"]

    assert any("lockfile" in f.title.lower() for f in findings)
    assert any("Unpinned" in f.title for f in findings)


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


def test_c2_reports_an_indeterminate_status_to_the_installed_observer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # One network round trip with no meaningful sub-steps - `total` must be
    # `None`, an indeterminate status rather than a bar that can never move
    # meaningfully (spec §4).
    monkeypatch.setattr("toolseal.core.policy.family_c.query_osv", lambda *_a, **_k: {})

    calls: list[tuple[object, ...]] = []

    class Recorder:
        def start(self, phase: str, total: int | None) -> None:
            calls.append(("start", phase, total))

        def advance(self, phase: str, step: int = 1) -> None:
            calls.append(("advance", phase, step))

        def finish(self, phase: str) -> None:
            calls.append(("finish", phase))

    model = ProjectModel(
        root=Path(),
        dependencies=DependencySet(
            declared=(Dependency("requests", "==2.32.3", pinned=True, resolved_version="2.32.3"),)
        ),
        runtime=RuntimeConfig(redacts_credentials=True),
    )

    from toolseal.core.policy import progress

    with progress.observe(Recorder()):
        audit_model(model)

    assert ("start", "querying advisories", None) in calls
    assert ("finish", "querying advisories") in calls


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


# --- discoverability: a finding must name a path to `policy explain` --------


def test_audit_with_findings_points_at_policy_explain_by_real_id(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        'OPENAI_API_KEY = "sk-abcdefghijklmnopqrst"\n',  # toolseal:allow A1 - drives a finding
        encoding="utf-8",
    )

    result = runner.invoke(app, ["audit", str(tmp_path)])

    assert result.exit_code == ExitCode.FINDINGS
    assert "toolseal policy explain A1" in result.stdout


def test_clean_audit_says_nothing_about_policy_explain(tmp_path: Path) -> None:
    spec = ScaffoldSpec(
        project_name="demo",
        provider_id="ollama",
        framework_id="langgraph",
        workspace_root=tmp_path / "demo",
    )
    apply_plan(build_plan(spec))
    (tmp_path / "demo" / "uv.lock").write_text("", encoding="utf-8")

    result = runner.invoke(app, ["audit", str(tmp_path / "demo")])

    assert result.exit_code == ExitCode.OK
    assert "policy explain" not in result.stdout


def test_audit_json_is_unaffected_by_the_policy_explain_pointer(tmp_path: Path) -> None:
    # The pointer is human-report-only decoration; the machine contract must
    # not gain a field or a stray string because of it.
    (tmp_path / "config.py").write_text(
        'OPENAI_API_KEY = "sk-abcdefghijklmnopqrst"\n',  # toolseal:allow A1 - fixture
        encoding="utf-8",
    )

    result = runner.invoke(app, ["audit", str(tmp_path), "--json"])

    assert "policy explain" not in result.stdout
    json.loads(result.stdout)  # still valid, untouched JSON


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


def test_family_table_is_headed_and_aligned(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("x = 1\n", encoding="utf-8")

    result = runner.invoke(app, ["audit", str(tmp_path)])
    lines = result.stdout.splitlines()

    header_line = next(
        line for line in lines if line.split() == ["Family", "Score", "Pass", "Fail", "N/A"]
    )
    header_index = lines.index(header_line)
    # `rich.table`'s `box.SIMPLE` draws one rule line under the header (spec
    # §5: "rules under headers") before the data rows begin.
    rule_line = lines[header_index + 1]
    assert set(rule_line.strip()) == {"─"}
    trailer = lines[header_index + 2 :]
    family_rows = trailer[: trailer.index("")] if "" in trailer else trailer
    assert family_rows

    # A column boundary is a literal two-space separator between fixed-width
    # blocks; if a heading lost (or won unnecessarily) the width comparison
    # against its data, the separator would drift between the header and the
    # rows beneath it.
    score_column = header_line.index("Score")
    for row in family_rows:
        assert row[score_column - 2 : score_column] == "  "


# --- the redesigned report: verdict-first (spec §3) -------------------------


def test_summary_panel_precedes_the_findings(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        'OPENAI_API_KEY = "sk-abcdefghijklmnopqrst"\n',  # toolseal:allow A1 - drives a finding
        encoding="utf-8",
    )

    result = runner.invoke(app, ["audit", str(tmp_path)])

    score_line = next(i for i, line in enumerate(result.stdout.splitlines()) if "score" in line)
    finding_line = next(
        i for i, line in enumerate(result.stdout.splitlines()) if "CRITICAL" in line
    )
    assert score_line < finding_line


def test_blocking_appears_adjacent_to_the_score_not_as_a_trailing_line(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        'OPENAI_API_KEY = "sk-abcdefghijklmnopqrst"\n',  # toolseal:allow A1 - critical, so blocking
        encoding="utf-8",
    )

    result = runner.invoke(app, ["audit", str(tmp_path)])
    lines = result.stdout.splitlines()

    score_line = next(line for line in lines if line.strip().startswith("│ score"))
    assert "BLOCKING" in score_line


def test_summary_panel_counts_do_not_collide_with_the_panel_border(tmp_path: Path) -> None:
    # The severity-counts line used a `|` separator inside a panel whose own
    # side walls render as `|` in a plain-ASCII console (ASCII box-drawing
    # substitution, spec §8) - the two glyphs collided and the line read as
    # four badly-aligned cells rather than four counts. A project with more
    # than one severity present is enough to exercise the separator between
    # them.
    (tmp_path / "config.py").write_text(
        'OPENAI_API_KEY = "sk-abcdefghijklmnopqrst"\n',  # toolseal:allow A1 - fixture
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text("requests\n", encoding="utf-8")

    result = runner.invoke(app, ["audit", str(tmp_path)])
    # The score line also contains "critical" (via `BLOCKING: 1 critical
    # check failed`); the counts line is the one naming more than one
    # severity.
    counts_line = next(
        line for line in result.stdout.splitlines() if "critical" in line and "high" in line
    )

    assert " | " not in counts_line
    assert ", " in counts_line


def test_severity_is_spelled_out_as_text_not_only_by_colour(tmp_path: Path) -> None:
    # Piped output carries no colour at all - if severity were colour-only,
    # a log file would lose it entirely (spec §8).
    (tmp_path / "config.py").write_text(
        'OPENAI_API_KEY = "sk-abcdefghijklmnopqrst"\n',  # toolseal:allow A1 - fixture
        encoding="utf-8",
    )

    result = runner.invoke(app, ["audit", str(tmp_path)])

    assert "CRITICAL" in result.stdout


def test_piped_output_has_no_ansi_escape_codes(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        'OPENAI_API_KEY = "sk-abcdefghijklmnopqrst"\n',  # toolseal:allow A1 - fixture
        encoding="utf-8",
    )

    result = runner.invoke(app, ["audit", str(tmp_path)])

    assert "\x1b[" not in result.stdout


def test_progress_does_not_appear_when_stdout_is_not_a_tty(tmp_path: Path) -> None:
    # `CliRunner` captures through a stream that never reports as a TTY, so
    # this exercises the real suppression path, not a mocked one: a project
    # dependency drives C3's per-name resolution, and no spinner residue -
    # not even a stray carriage return - may reach either stream.
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / "uv.lock").write_text("", encoding="utf-8")

    result = runner.invoke(app, ["audit", str(tmp_path)])

    assert "resolving package names" not in result.stdout
    assert "resolving package names" not in result.output


def test_json_output_is_byte_identical_to_the_pinned_machine_contract(tmp_path: Path) -> None:
    # `--json` is a machine contract - SARIF, CI, and the study harnesses all
    # parse it - so the redesigned human report (a summary panel, rich
    # tables, colour) must change none of it. This computes the payload the
    # same way the command does internally and diffs the CLI's actual stdout
    # against it, byte for byte, catching any stray console formatting that
    # leaked into the machine path.
    from toolseal.cli.audit_command import _as_dict

    (tmp_path / "main.py").write_text("x = 1\n", encoding="utf-8")

    report = audit(tmp_path)
    expected = json.dumps(_as_dict(report, report.findings, ()), indent=2, sort_keys=True) + "\n"

    result = runner.invoke(app, ["audit", str(tmp_path), "--json"])

    assert result.stdout == expected


def test_every_registered_check_has_a_remediation() -> None:
    # A check with no automatic remediation is a feature request, not a check.
    assert all(item.remediation for item in all_checks())


def test_the_whole_taxonomy_is_registered() -> None:
    # The document in reference/taxonomy.md is normative; this is the drift
    # guard it asks for. Identifiers are permanent and never reused, so a
    # mismatch here is either an unimplemented check or an undocumented one.
    assert {c.id for c in checks_in("A")} == {"A1", "A2", "A3", "A4", "A5"}
    assert {c.id for c in checks_in("B")} == {"B1", "B2", "B3", "B4", "B5"}
    assert {c.id for c in checks_in("C")} == {"C1", "C2", "C3", "C4", "C5"}
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
