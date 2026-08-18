"""The three shipped regime profiles: GDPR, HIPAA, DORA (P45).

Per the spec (`docs/superpowers/specs/2026-08-13-standards-compliance-policy-
design.md` §5), a regime reports configuration evidence, never a verdict. Its
`not_assessed` list is the honesty mechanism, not a formality, so every regime
must declare one. Every severity it pins must be checkable against the live
taxonomy and must never be a lowering - `parse_profile` already refuses a
lowering at load time (`tests/test_profile.py` covers that rule generically),
this file asserts the invariant explicitly for each shipped regime rather than
trusting the loader alone.
"""

from __future__ import annotations

from toolseal.core.policy.model import Severity, all_checks
from toolseal.core.policy.profile import (
    Profile,
    derive_residency,
    load_profile,
    load_profiles,
    residency_table,
)
from toolseal.core.registry.utd import ComplianceEvidence

EXPECTED_REGIME_IDS = frozenset({"gdpr", "hipaa", "dora"})

_RANK = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


def _baseline_severities() -> dict[str, Severity]:
    return {check.id: check.severity for check in all_checks()}


# --- every regime file loads through P44's loader ----------------------------


def test_every_shipped_regime_loads() -> None:
    profiles = load_profiles()

    assert set(profiles) >= EXPECTED_REGIME_IDS
    for regime_id in EXPECTED_REGIME_IDS:
        assert profiles[regime_id].kind == "regime"


def test_gdpr_loads_by_id() -> None:
    profile = load_profile("gdpr")
    assert profile.id == "gdpr"
    assert profile.kind == "regime"


def test_hipaa_loads_by_id() -> None:
    profile = load_profile("hipaa")
    assert profile.id == "hipaa"
    assert profile.kind == "regime"


def test_dora_loads_by_id() -> None:
    profile = load_profile("dora")
    assert profile.id == "dora"
    assert profile.kind == "regime"


# --- every check id a regime's [severity] table names must exist -------------


def test_every_severity_entry_references_a_real_check_id() -> None:
    known_ids = set(_baseline_severities())

    for regime_id in EXPECTED_REGIME_IDS:
        profile = load_profile(regime_id)
        unknown = set(profile.severity) - known_ids
        assert not unknown, f"{regime_id} references unknown check id(s): {unknown}"


# --- no regime lowers a severity ----------------------------------------------


def test_no_regime_lowers_a_baseline_severity() -> None:
    baseline = _baseline_severities()

    for regime_id in EXPECTED_REGIME_IDS:
        profile = load_profile(regime_id)
        for check_id, wanted in profile.severity.items():
            current = baseline[check_id]
            assert _RANK[wanted] >= _RANK[current], (
                f"{regime_id} lowers {check_id} from {current} to {wanted}"
            )


# --- every regime declares a non-empty not_assessed ---------------------------


def test_every_regime_declares_a_non_empty_not_assessed() -> None:
    for regime_id in EXPECTED_REGIME_IDS:
        profile = load_profile(regime_id)
        assert len(profile.not_assessed) > 0, f"{regime_id} declares no not_assessed scope"
        assert all(isinstance(item, str) and item for item in profile.not_assessed)


# --- every regime carries a source_url and a licence --------------------------


def test_every_regime_declares_a_source_url_and_licence() -> None:
    for regime_id in EXPECTED_REGIME_IDS:
        profile = load_profile(regime_id)
        assert profile.source_url, f"{regime_id} has no source_url"
        assert profile.source_url.startswith("https://"), (
            f"{regime_id} source_url is not https: {profile.source_url!r}"
        )
        assert profile.license, f"{regime_id} has no license"
        assert profile.source, f"{regime_id} has no source citation"


# --- a regime never emits an overall verdict: Profile carries no such field --


def test_profile_shape_has_no_verdict_field() -> None:
    # A regime is data, not a report - it cannot even represent an overall
    # pass/fail, because Profile has no field for one. This is a structural
    # guarantee, not just a convention: nothing downstream can read a verdict
    # off a Profile that was never given one to read.
    profile = load_profile("hipaa")
    assert not hasattr(profile, "verdict")
    assert not hasattr(profile, "overall")
    assert not hasattr(profile, "pass_fail")


# --- specific, individually-justified severity raises -------------------------


def test_hipaa_raises_f1_for_required_audit_controls() -> None:
    # 164.312(b) "Audit controls" is a Required standard with no addressable
    # alternative.
    profile = load_profile("hipaa")
    assert profile.severity["F1"] is Severity.HIGH


def test_hipaa_raises_d2_for_required_authentication() -> None:
    # 164.312(d) "Person or entity authentication" is likewise Required.
    profile = load_profile("hipaa")
    assert profile.severity["D2"] is Severity.CRITICAL


def test_dora_raises_f1_for_mandatory_detection() -> None:
    # Art. 10(1)/(3): "shall have in place mechanisms to promptly detect
    # anomalous activities" and monitor user activity - unconditional, not
    # risk-qualified.
    profile = load_profile("dora")
    assert profile.severity["F1"] is Severity.HIGH


def test_dora_raises_d2_for_mandatory_strong_authentication() -> None:
    # Art. 9(4)(d): "shall implement policies and protocols for strong
    # authentication mechanisms" for critical/important ICT systems.
    profile = load_profile("dora")
    assert profile.severity["D2"] is Severity.CRITICAL


def test_gdpr_raises_no_severity() -> None:
    # GDPR's Art. 32 security obligation is qualified throughout by
    # "appropriate to the risk" - unlike HIPAA's Required standards or
    # DORA's unconditional "shall" provisions, it supports no flat raise.
    # D1 is restated (not raised) at its existing baseline for traceability.
    profile = load_profile("gdpr")
    baseline = _baseline_severities()
    for check_id, wanted in profile.severity.items():
        assert wanted is baseline[check_id], (
            f"gdpr restates {check_id} at {wanted}, which is not its baseline "
            f"{baseline[check_id]} - gdpr is expected to only restate, never raise"
        )


# --- require table -------------------------------------------------------------


def test_every_regime_pins_approval_on_destructive_operations() -> None:
    for regime_id in EXPECTED_REGIME_IDS:
        profile = load_profile(regime_id)
        assert profile.require.get("policy.approval_required_for_destructive") is True


# --- resolving multiple regimes together still behaves per P44 ---------------


def test_regimes_resolve_together_strictest_wins() -> None:
    from toolseal.core.policy.profile import resolve

    hipaa = load_profile("hipaa")
    dora = load_profile("dora")

    resolution = resolve([hipaa, dora])

    f1 = next(c for c in resolution.checks if c.id == "F1")
    assert f1.severity is Severity.HIGH
    d2 = next(c for c in resolution.checks if c.id == "D2")
    assert d2.severity is Severity.CRITICAL

    # not_assessed carries both regimes' scope forward.
    assert any("164.308" in item for item in resolution.not_assessed)
    assert any("Art. 28" in item or "Art. 5" in item for item in resolution.not_assessed)


# --- residency host-suffix table (P49) ----------------------------------------


def test_every_regime_declares_a_residency_table() -> None:
    for regime_id in EXPECTED_REGIME_IDS:
        profile = load_profile(regime_id)
        assert profile.residency, f"{regime_id} declares no [residency] table"


def test_gdpr_and_dora_map_the_eu_suffix() -> None:
    for regime_id in ("gdpr", "dora"):
        profile = load_profile(regime_id)
        assert profile.residency.get(".eu") == ("EU",)


def test_hipaa_maps_the_us_suffix() -> None:
    profile = load_profile("hipaa")
    assert profile.residency.get(".us") == ("US",)


def test_shipped_residency_tables_merge_without_conflict() -> None:
    table = residency_table()

    assert table[".eu"] == ("EU",)
    assert table[".us"] == ("US",)


def test_the_spec_worked_example_host_derives_to_us() -> None:
    # Spec §9's own worked example: "egress_hosts contains api.example.us" ->
    # region US. This exercises the shipped tables end to end, not a fixture.
    residency = derive_residency(("api.example.us",))

    assert residency.regions == ("US",)
    assert residency.evidence is ComplianceEvidence.DERIVED
    assert residency.derivation == "egress_hosts"


def test_a_host_matching_no_shipped_regime_suffix_is_unknown() -> None:
    residency = derive_residency(("api.example.jp",))

    assert residency.evidence is ComplianceEvidence.UNKNOWN
    assert residency.regions == ()


def test_profile_dataclass_still_frozen_for_shipped_regimes() -> None:
    profile = load_profile("gdpr")
    assert isinstance(profile, Profile)
    try:
        profile.id = "changed"  # type: ignore[misc]
    except AttributeError:
        pass
    else:
        raise AssertionError("shipped regime Profile should be frozen")
