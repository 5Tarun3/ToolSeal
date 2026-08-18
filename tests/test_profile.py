"""Policy profiles: the overlay model and its resolution.

A profile is data over the 28-check baseline (`docs/superpowers/specs/
2026-08-13-standards-compliance-policy-design.md` §5). Three rules are load
bearing and each gets its own test:

* a profile may not weaken a baseline severity - that is relaxation's job,
  because relaxation demands a justification and a profile file does not;
* two active profiles disagreeing on a severity resolve to the stricter one,
  and the report can always say which profile won;
* every profile's `not_assessed` scope list survives resolution so it can be
  printed with every report produced under it.
"""

from __future__ import annotations

import pytest

from toolseal.core.policy.model import AuditReport, Check, CheckResult, Severity, Verdict
from toolseal.core.policy.profile import (
    DATA_PACKAGE,
    Profile,
    apply_resolution,
    parse_profile,
    resolve,
)
from toolseal.errors import ConfigError

BASELINE = {
    "F1": Severity.MEDIUM,
    "D1": Severity.CRITICAL,
    "B2": Severity.CRITICAL,
    "C5": Severity.LOW,
}


def _check(check_id: str, severity: Severity) -> Check:
    return Check(
        id=check_id,
        family=check_id[0],
        title=check_id,
        severity=severity,
        remediation="",
        run=lambda _model: (),
    )


BASELINE_CHECKS = tuple(_check(check_id, severity) for check_id, severity in BASELINE.items())

HIPAA_LIKE = """
id = "hipaa"
kind = "regime"
name = "HIPAA Security Rule"
source = "45 CFR 164.302-318"
source_url = "https://www.ecfr.gov/current/title-45/part-164"
license = "public-domain"

[scope]
not_assessed = [
  "administrative safeguards (164.308)",
  "workforce training and sanction policy",
]

[severity]
F1 = "high"
D1 = "critical"

[require]
"policy.approval_required_for_destructive" = true
"""


# --- parsing -----------------------------------------------------------------


def test_profile_parses() -> None:
    profile = parse_profile(HIPAA_LIKE, baseline=BASELINE)

    assert profile.id == "hipaa"
    assert profile.kind == "regime"
    assert profile.name == "HIPAA Security Rule"
    assert profile.severity == {"F1": Severity.HIGH, "D1": Severity.CRITICAL}
    assert profile.not_assessed == (
        "administrative safeguards (164.308)",
        "workforce training and sanction policy",
    )
    assert profile.require == {"policy.approval_required_for_destructive": True}


def test_unknown_kind_is_refused() -> None:
    text = 'id = "x"\nkind = "nonsense"\nname = "X"\n'
    with pytest.raises(ConfigError, match="kind"):
        parse_profile(text, baseline=BASELINE)


def test_missing_required_fields_are_refused() -> None:
    with pytest.raises(ConfigError, match="id"):
        parse_profile('kind = "regime"\n', baseline=BASELINE)


# --- the "may not weaken" rule -------------------------------------------------


def test_a_profile_that_lowers_a_baseline_severity_is_rejected_at_load() -> None:
    # B2 is baseline critical; a profile that quietly downgrades it is exactly
    # the silent insecure path the spec forbids - weakening is relaxation's job.
    text = 'id = "loose"\nkind = "standard"\nname = "Loose"\n\n[severity]\nB2 = "high"\n'

    with pytest.raises(ConfigError) as excinfo:
        parse_profile(text, baseline=BASELINE)

    message = str(excinfo.value)
    assert "B2" in message
    assert "loose" in message


def test_a_profile_that_raises_a_baseline_severity_is_accepted() -> None:
    text = 'id = "strict"\nkind = "standard"\nname = "Strict"\n\n[severity]\nC5 = "high"\n'

    profile = parse_profile(text, baseline=BASELINE)

    assert profile.severity["C5"] is Severity.HIGH


def test_a_profile_that_restates_the_same_severity_is_accepted() -> None:
    text = 'id = "restate"\nkind = "standard"\nname = "Restate"\n\n[severity]\nD1 = "critical"\n'

    profile = parse_profile(text, baseline=BASELINE)

    assert profile.severity["D1"] is Severity.CRITICAL


def test_a_profile_naming_an_unknown_check_is_refused() -> None:
    text = 'id = "x"\nkind = "standard"\nname = "X"\n\n[severity]\nZZ9 = "high"\n'

    with pytest.raises(ConfigError, match="ZZ9"):
        parse_profile(text, baseline=BASELINE)


def test_an_invalid_severity_value_is_refused() -> None:
    text = 'id = "x"\nkind = "standard"\nname = "X"\n\n[severity]\nF1 = "urgent"\n'

    with pytest.raises(ConfigError, match="urgent"):
        parse_profile(text, baseline=BASELINE)


# --- conflict resolution: strictest wins, and the winner is named ------------


def test_two_agreeing_profiles_resolve_without_conflict() -> None:
    gdpr = Profile(id="gdpr", kind="regime", name="GDPR", severity={"F1": Severity.HIGH})
    hipaa = Profile(id="hipaa", kind="regime", name="HIPAA", severity={"F1": Severity.HIGH})

    resolution = resolve([gdpr, hipaa], baseline=BASELINE_CHECKS)

    (decision,) = [d for d in resolution.decisions if d.check_id == "F1"]
    assert decision.severity is Severity.HIGH


def test_two_disagreeing_profiles_resolve_to_the_stricter_and_name_the_winner() -> None:
    weaker = Profile(id="gdpr", kind="regime", name="GDPR", severity={"F1": Severity.HIGH})
    stronger = Profile(id="hipaa", kind="regime", name="HIPAA", severity={"F1": Severity.CRITICAL})

    resolution = resolve([weaker, stronger], baseline=BASELINE_CHECKS)

    (decision,) = [d for d in resolution.decisions if d.check_id == "F1"]
    assert decision.severity is Severity.CRITICAL
    assert decision.winner == "hipaa"

    resolved_f1 = next(c for c in resolution.checks if c.id == "F1")
    assert resolved_f1.severity is Severity.CRITICAL


def test_conflict_resolution_is_order_independent() -> None:
    weaker = Profile(id="gdpr", kind="regime", name="GDPR", severity={"F1": Severity.HIGH})
    stronger = Profile(id="hipaa", kind="regime", name="HIPAA", severity={"F1": Severity.CRITICAL})

    forward = resolve([weaker, stronger], baseline=BASELINE_CHECKS)
    backward = resolve([stronger, weaker], baseline=BASELINE_CHECKS)

    forward_f1 = next(c for c in forward.checks if c.id == "F1")
    backward_f1 = next(c for c in backward.checks if c.id == "F1")
    assert forward_f1.severity is backward_f1.severity is Severity.CRITICAL
    assert next(d for d in forward.decisions if d.check_id == "F1").winner == "hipaa"
    assert next(d for d in backward.decisions if d.check_id == "F1").winner == "hipaa"


def test_a_check_untouched_by_any_profile_keeps_its_baseline_severity() -> None:
    profile = Profile(id="hipaa", kind="regime", name="HIPAA", severity={"F1": Severity.HIGH})

    resolution = resolve([profile], baseline=BASELINE_CHECKS)

    d1 = next(c for c in resolution.checks if c.id == "D1")
    assert d1.severity is Severity.CRITICAL
    assert not any(d.check_id == "D1" for d in resolution.decisions)


def test_resolve_with_no_profiles_returns_the_baseline_unchanged() -> None:
    resolution = resolve([], baseline=BASELINE_CHECKS)

    assert resolution.checks == BASELINE_CHECKS
    assert resolution.decisions == ()


def test_resolve_refuses_a_profile_referencing_an_unknown_check() -> None:
    profile = Profile(id="x", kind="standard", name="X", severity={"ZZ9": Severity.HIGH})

    with pytest.raises(ConfigError, match="ZZ9"):
        resolve([profile], baseline=BASELINE_CHECKS)


# --- not_assessed carries through resolution ----------------------------------


def test_not_assessed_is_carried_through_resolution() -> None:
    gdpr = Profile(
        id="gdpr", kind="regime", name="GDPR", not_assessed=("breach notification procedures",)
    )
    hipaa = Profile(id="hipaa", kind="regime", name="HIPAA", not_assessed=("workforce training",))

    resolution = resolve([gdpr, hipaa], baseline=BASELINE_CHECKS)

    assert resolution.not_assessed == (
        "breach notification procedures",
        "workforce training",
    )


# --- shipped regimes -----------------------------------------------------------


def test_data_package_is_a_real_package() -> None:
    from importlib import resources

    # This only proves the package exists and is readable, the way
    # `load_catalogues()` needs `standards/` to. `tests/test_regimes.py`
    # covers the GDPR/HIPAA/DORA regime files P45 ships here in detail.
    assert resources.files(DATA_PACKAGE).is_dir()


def test_load_profiles_returns_every_shipped_regime() -> None:
    from toolseal.core.policy.profile import load_profiles

    profiles = load_profiles()

    assert set(profiles) == {"gdpr", "hipaa", "dora"}
    assert all(profile.kind == "regime" for profile in profiles.values())


def test_profile_is_frozen() -> None:
    profile = Profile(id="x", kind="standard", name="X")

    with pytest.raises(AttributeError):
        profile.id = "changed"  # type: ignore[misc]


# --- apply_resolution: overlaying a resolution onto an already-run report (P47) --


def test_apply_resolution_raises_the_severity_on_a_matching_result() -> None:
    # F1 fails at baseline MEDIUM; a profile resolution raises it to HIGH.
    # `apply_resolution` must be equivalent to having resolved *before* the
    # engine ran - the verdict and findings are untouched, only severity moves.
    report = AuditReport(
        root=".",
        results=(CheckResult(_check("F1", Severity.MEDIUM), Verdict.FAIL, ()),),
    )
    resolution = resolve(
        [Profile(id="hipaa", kind="regime", name="HIPAA", severity={"F1": Severity.HIGH})],
        baseline=BASELINE_CHECKS,
    )

    resolved_report = apply_resolution(report, resolution)

    (result,) = resolved_report.results
    assert result.check.severity is Severity.HIGH
    assert result.verdict is Verdict.FAIL  # unchanged - only severity moved


def test_apply_resolution_leaves_verdict_and_findings_untouched() -> None:
    report = AuditReport(
        root=".",
        results=(CheckResult(_check("D1", Severity.CRITICAL), Verdict.PASS, ()),),
    )
    resolution = resolve([], baseline=BASELINE_CHECKS)

    resolved_report = apply_resolution(report, resolution)

    (result,) = resolved_report.results
    assert result.verdict is Verdict.PASS
    assert result.findings == ()


def test_apply_resolution_changes_the_score_the_same_way_resolving_first_would() -> None:
    # F1 baseline MEDIUM (weight 3); raised to HIGH (weight 6) by a profile.
    # A failing MEDIUM costs less of the total than a failing HIGH - scoring
    # after the fact must reflect the *raised* weight, not the baseline one.
    report = AuditReport(
        root=".",
        results=(
            CheckResult(_check("F1", Severity.MEDIUM), Verdict.FAIL, ()),
            CheckResult(_check("D1", Severity.CRITICAL), Verdict.PASS, ()),
        ),
    )
    baseline_score = report.score

    resolution = resolve(
        [Profile(id="hipaa", kind="regime", name="HIPAA", severity={"F1": Severity.HIGH})],
        baseline=BASELINE_CHECKS,
    )
    resolved_report = apply_resolution(report, resolution)

    assert resolved_report.score < baseline_score


def test_apply_resolution_on_an_unresolved_check_id_leaves_it_untouched() -> None:
    # A result whose check id is not in the resolution (should not happen in
    # practice - `resolve()` always returns the full baseline) degrades
    # safely rather than dropping the result.
    report = AuditReport(
        root=".",
        results=(CheckResult(_check("ZZ9", Severity.LOW), Verdict.PASS, ()),),
    )
    resolution = resolve([], baseline=BASELINE_CHECKS)

    resolved_report = apply_resolution(report, resolution)

    (result,) = resolved_report.results
    assert result.check.id == "ZZ9"
    assert result.check.severity is Severity.LOW
