"""Study 6's attack suite, validated before anything runs it.

The suite is the protection numerator. A malformed or favourable-only suite
would produce a number that means nothing, and it would do so silently - so
every rule the pre-registration states is enforced here.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from bench.attack_suite import (
    ATTACK_OUTCOMES,
    BENIGN_OUTCOMES,
    GUARDS,
    SuiteError,
    load,
    normalised_digest,
    registered_digest,
)

from toolseal.core.policy.controls import load_catalogues


def test_the_suite_is_non_empty() -> None:
    assert len(load()) >= len(GUARDS)


def test_every_guard_has_cases() -> None:
    covered = {case.guard for case in load()}
    assert covered == set(GUARDS), f"guards without cases: {sorted(set(GUARDS) - covered)}"


@pytest.mark.parametrize("guard", GUARDS)
def test_every_guard_has_an_expected_block_and_an_expected_miss(guard: str) -> None:
    # The adverse-case rule. A suite of cases the guards are expected to win
    # measures nothing - bench/harness.py refuses to report without adverse
    # tasks for the same reason.
    attacks = [c for c in load() if c.guard == guard and c.kind == "attack"]
    outcomes = {c.expected_decorator for c in attacks}
    assert "blocked" in outcomes, f"{guard} has no attack it is expected to block"
    assert "missed" in outcomes, f"{guard} has no attack it is expected to miss"


def test_case_ids_are_unique() -> None:
    ids = [case.id for case in load()]
    assert len(ids) == len(set(ids))


def test_outcomes_use_the_vocabulary_for_their_kind() -> None:
    for case in load():
        allowed = ATTACK_OUTCOMES if case.kind == "attack" else BENIGN_OUTCOMES
        assert case.expected_decorator in allowed, case.id
        assert case.expected_proxy in allowed, case.id


def test_every_attack_cites_a_checkable_atlas_technique() -> None:
    atlas = load_catalogues()["mitre-atlas"]
    for case in load():
        if case.kind != "attack":
            continue
        control = atlas.get(case.atlas or "")
        assert control is not None, f"{case.id} cites unknown technique {case.atlas!r}"
        assert control.checkable, f"{case.id} cites uncheckable {case.atlas}"


def test_benign_cases_exist() -> None:
    # Without them a guard that refuses everything scores perfect protection.
    assert any(case.kind == "benign" for case in load())


def test_every_case_states_its_basis() -> None:
    for case in load():
        assert case.basis.strip(), f"{case.id} gives no source for its expectation"


def test_the_suite_matches_its_registered_digest() -> None:
    # Pre-registration made enforceable: editing the suite after registration
    # fails here until a Deviations row is added and the digest re-recorded.
    recorded = registered_digest()
    assert recorded is not None, "protocol records no digest for the suite"
    assert normalised_digest() == recorded


def test_the_digest_ignores_line_endings(tmp_path: Path) -> None:
    # Git converts line endings on Windows. Without normalisation the pinned
    # digest would differ per platform and the pin would be unusable on CI.
    unix, windows = tmp_path / "u.toml", tmp_path / "w.toml"
    unix.write_bytes(b"a = 1\nb = 2\n")
    windows.write_bytes(b"a = 1\r\nb = 2\r\n")
    assert normalised_digest(unix) == normalised_digest(windows)


def test_an_unknown_outcome_is_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "bad.toml"
    bad.write_text(
        '[[case]]\nid = "X-01"\nguard = "redact"\nkind = "attack"\n'
        'atlas = "AML.T0055"\ndescription = "d"\nobservable = "log_content"\n'
        'input = "i"\nbasis = "b"\n'
        'expected = { decorator = "probably", proxy = "blocked" }\n',
        encoding="utf-8",
    )
    with pytest.raises(SuiteError, match="probably"):
        load(bad)
