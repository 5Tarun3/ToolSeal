"""Relaxation: justified, expiring deviations from a check (§6 of the policy spec).

A relaxation is not a way to make a finding disappear - it is a way to make a
*known, justified, time-boxed* deviation visible instead of either failing
silently-ignored or being suppressed with no trace. Every test here pins one
piece of that discipline:

* `reason` and `expires` are both mandatory - a relaxation that never lapses is
  a permanent hole with a note attached;
* an expired relaxation stops applying, and is named rather than silently
  resuming as an ordinary failure with no explanation;
* a relaxation naming an unknown check id is refused, not ignored;
* `Verdict.RELAXED` leaves the score denominator and `relaxed_critical`
  surfaces independently of `blocking` and the score - re-verified here against
  the actual apply path, not just the bare dataclass (see also
  `tests/test_audit.py`'s direct `AuditReport` tests for that).
"""

from __future__ import annotations

from datetime import date

import pytest

from toolseal.core.policy.model import AuditReport, Check, CheckResult, Finding, Severity, Verdict
from toolseal.core.policy.relax import (
    Relaxation,
    apply_relaxations,
    parse_relaxations,
)
from toolseal.errors import ConfigError

KNOWN = frozenset({"B2", "A1", "F1"})


def _check(check_id: str, severity: Severity) -> Check:
    return Check(
        id=check_id,
        family=check_id[0],
        title=check_id,
        severity=severity,
        remediation="",
        run=lambda _model: (),
    )


def _fail(check_id: str, severity: Severity, *findings: Finding) -> CheckResult:
    return CheckResult(_check(check_id, severity), Verdict.FAIL, findings)


def _finding(check_id: str, severity: Severity, *, subject: str | None = None) -> Finding:
    return Finding(check_id=check_id, severity=severity, title="t", detail="d", subject=subject)


# --- parsing: reason and expires are mandatory --------------------------------


def test_a_relaxation_parses_with_reason_and_expiry() -> None:
    text = """
    [policy.relax.B2]
    reason = "CI runner needs shell; container-isolated, no network egress"
    expires = "2026-12-31"
    tools = ["ci_shell"]
    """
    (relaxation,) = parse_relaxations(text, known_check_ids=KNOWN)

    assert relaxation.check_id == "B2"
    assert relaxation.reason == "CI runner needs shell; container-isolated, no network egress"
    assert relaxation.expires == date(2026, 12, 31)
    assert relaxation.tools == ("ci_shell",)


def test_relaxation_without_reason_is_refused() -> None:
    text = '[policy.relax.B2]\nexpires = "2026-12-31"\n'
    with pytest.raises(ConfigError, match="reason"):
        parse_relaxations(text, known_check_ids=KNOWN)


def test_relaxation_with_blank_reason_is_refused() -> None:
    text = '[policy.relax.B2]\nreason = "   "\nexpires = "2026-12-31"\n'
    with pytest.raises(ConfigError, match="reason"):
        parse_relaxations(text, known_check_ids=KNOWN)


def test_relaxation_without_expires_is_refused() -> None:
    text = '[policy.relax.B2]\nreason = "needs shell"\n'
    with pytest.raises(ConfigError, match="expires"):
        parse_relaxations(text, known_check_ids=KNOWN)


def test_relaxation_with_an_unparseable_expiry_is_refused() -> None:
    text = '[policy.relax.B2]\nreason = "needs shell"\nexpires = "not-a-date"\n'
    with pytest.raises(ConfigError, match="expires"):
        parse_relaxations(text, known_check_ids=KNOWN)


def test_relaxation_naming_an_unknown_check_is_refused() -> None:
    text = '[policy.relax.ZZ9]\nreason = "whatever"\nexpires = "2026-12-31"\n'
    with pytest.raises(ConfigError, match="ZZ9"):
        parse_relaxations(text, known_check_ids=KNOWN)


def test_project_wide_relaxation_omits_tools() -> None:
    text = '[policy.relax.A1]\nreason = "known fixture pattern"\nexpires = "2026-12-31"\n'
    (relaxation,) = parse_relaxations(text, known_check_ids=KNOWN)

    assert relaxation.tools == ()


def test_no_relax_table_parses_to_nothing() -> None:
    assert parse_relaxations('[project]\nname = "x"\n', known_check_ids=KNOWN) == ()


# --- covers() / is_expired() ---------------------------------------------------


def test_project_wide_relaxation_covers_every_subject() -> None:
    relaxation = Relaxation(check_id="B2", reason="r", expires=date(2026, 12, 31))
    assert relaxation.covers("ci_shell")
    assert relaxation.covers(None)


def test_per_tool_relaxation_covers_only_named_tools() -> None:
    relaxation = Relaxation(
        check_id="B2", reason="r", expires=date(2026, 12, 31), tools=("ci_shell",)
    )
    assert relaxation.covers("ci_shell")
    assert not relaxation.covers("other_shell")
    assert not relaxation.covers(None)


def test_is_expired_compares_against_the_given_date() -> None:
    relaxation = Relaxation(check_id="B2", reason="r", expires=date(2026, 12, 31))
    assert not relaxation.is_expired(date(2026, 12, 31))
    assert relaxation.is_expired(date(2027, 1, 1))


# --- apply_relaxations: the semantics that matter ------------------------------


def test_relaxed_check_leaves_the_score_denominator() -> None:
    report = AuditReport(
        root=".",
        results=(_fail("B2", Severity.CRITICAL, _finding("B2", Severity.CRITICAL)),),
    )
    relaxation = Relaxation(check_id="B2", reason="needs shell", expires=date(2026, 12, 31))

    outcome = apply_relaxations(report, [relaxation], today=date(2026, 8, 18))

    (result,) = outcome.report.results
    assert result.verdict is Verdict.RELAXED
    assert not result.counts_towards_score
    assert outcome.report.score == 100
    assert relaxation in outcome.applied
    assert outcome.expired == ()


def test_relaxed_critical_surfaces_independently_of_blocking_and_score() -> None:
    report = AuditReport(
        root=".",
        results=(
            *(CheckResult(_check(f"X{i}", Severity.LOW), Verdict.PASS, ()) for i in range(20)),
            _fail("B2", Severity.CRITICAL, _finding("B2", Severity.CRITICAL)),
        ),
    )
    relaxation = Relaxation(check_id="B2", reason="needs shell", expires=date(2026, 12, 31))

    outcome = apply_relaxations(report, [relaxation], today=date(2026, 8, 18))

    assert outcome.report.score == 100
    assert not outcome.report.blocking
    assert outcome.report.relaxed_critical


def test_expired_relaxation_stops_applying_and_is_named() -> None:
    report = AuditReport(
        root=".",
        results=(_fail("B2", Severity.CRITICAL, _finding("B2", Severity.CRITICAL)),),
    )
    relaxation = Relaxation(check_id="B2", reason="needs shell", expires=date(2026, 1, 1))

    outcome = apply_relaxations(report, [relaxation], today=date(2026, 8, 18))

    (result,) = outcome.report.results
    assert result.verdict is Verdict.FAIL  # resumes failing, not silently
    assert outcome.applied == ()
    assert relaxation in outcome.expired  # and the report can name it


def test_per_tool_relaxation_only_relaxes_the_named_subject() -> None:
    covered = _finding("B2", Severity.CRITICAL, subject="ci_shell")
    uncovered = _finding("B2", Severity.CRITICAL, subject="build_shell")
    report = AuditReport(root=".", results=(_fail("B2", Severity.CRITICAL, covered, uncovered),))
    relaxation = Relaxation(
        check_id="B2", reason="ci needs shell", expires=date(2026, 12, 31), tools=("ci_shell",)
    )

    outcome = apply_relaxations(report, [relaxation], today=date(2026, 8, 18))

    (result,) = outcome.report.results
    # A finding remains against the tool the relaxation does not name, so the
    # check still fails - a per-tool waiver must not blanket-cover other tools.
    assert result.verdict is Verdict.FAIL
    assert result.findings == (uncovered,)


def test_per_tool_relaxation_covering_every_finding_relaxes_the_check() -> None:
    only = _finding("B2", Severity.CRITICAL, subject="ci_shell")
    report = AuditReport(root=".", results=(_fail("B2", Severity.CRITICAL, only),))
    relaxation = Relaxation(
        check_id="B2", reason="ci needs shell", expires=date(2026, 12, 31), tools=("ci_shell",)
    )

    outcome = apply_relaxations(report, [relaxation], today=date(2026, 8, 18))

    (result,) = outcome.report.results
    assert result.verdict is Verdict.RELAXED


def test_relaxation_never_touches_a_passing_check() -> None:
    report = AuditReport(
        root=".", results=(CheckResult(_check("B2", Severity.CRITICAL), Verdict.PASS, ()),)
    )
    relaxation = Relaxation(check_id="B2", reason="r", expires=date(2026, 12, 31))

    outcome = apply_relaxations(report, [relaxation], today=date(2026, 8, 18))

    (result,) = outcome.report.results
    assert result.verdict is Verdict.PASS
    assert outcome.applied == ()


def test_relaxation_naming_a_check_absent_from_the_report_is_a_no_op() -> None:
    report = AuditReport(
        root=".", results=(CheckResult(_check("A1", Severity.CRITICAL), Verdict.PASS, ()),)
    )
    relaxation = Relaxation(check_id="F1", reason="r", expires=date(2026, 12, 31))

    outcome = apply_relaxations(report, [relaxation], today=date(2026, 8, 18))

    assert outcome.report.results == report.results
    assert outcome.applied == ()
