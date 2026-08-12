"""The lattice turns P0's measurements into decisions, so the P0 rows are pinned.

If `langchain` or `crewai` expressiveness changes here, it must be because a
probe re-run said so - not because someone adjusted a set to make a test pass.
"""

from __future__ import annotations

import pytest

from toolseal.core.translate import (
    Evidence,
    GuardKind,
    SecurityProperty,
    plan_translation,
    profile,
)
from toolseal.errors import UsageError


def test_unknown_abstraction_lists_the_known_ones() -> None:
    with pytest.raises(UsageError) as caught:
        profile("autogen")

    message = str(caught.value)
    assert "autogen" in message
    assert "crewai" in message and "langchain" in message


def test_measured_rows_are_tagged_as_measured() -> None:
    assert profile("langchain").evidence is Evidence.MEASURED
    assert profile("crewai").evidence is Evidence.MEASURED


def test_unmeasured_rows_do_not_claim_measurement() -> None:
    assert profile("openai_fc").evidence is not Evidence.MEASURED
    assert profile("mcp").evidence is not Evidence.MEASURED


def test_langchain_preserves_annotations_as_p0_measured() -> None:
    langchain = profile("langchain")
    for prop in (
        SecurityProperty.READ_ONLY,
        SecurityProperty.DESTRUCTIVE,
        SecurityProperty.IDEMPOTENT,
        SecurityProperty.OPEN_WORLD,
    ):
        assert langchain.expresses(prop)


def test_crewai_expresses_only_constraints_as_p0_measured() -> None:
    crewai = profile("crewai")
    assert crewai.expresses(SecurityProperty.INPUT_CONSTRAINTS)
    assert not crewai.expresses(SecurityProperty.DESTRUCTIVE)
    assert not crewai.expresses(SecurityProperty.DESCRIPTION_INTEGRITY)


def test_destructive_into_langchain_is_lossless() -> None:
    plan = plan_translation(
        frozenset({SecurityProperty.DESTRUCTIVE}), source="mcp", target="langchain"
    )

    assert plan.is_lossless
    assert plan.status == "full"
    assert plan.preserved == frozenset({SecurityProperty.DESTRUCTIVE})
    assert plan.guards == ()


def test_destructive_into_crewai_is_compensated_by_approval() -> None:
    plan = plan_translation(
        frozenset({SecurityProperty.DESTRUCTIVE}), source="mcp", target="crewai"
    )

    assert not plan.is_lossless
    assert plan.status == "compensated"
    assert plan.compensated == frozenset({SecurityProperty.DESTRUCTIVE})
    assert [guard.kind for guard in plan.guards] == [GuardKind.REQUIRE_APPROVAL]
    assert plan.guards[0].compensates is SecurityProperty.DESTRUCTIVE


def test_description_integrity_into_crewai_gets_a_guard() -> None:
    plan = plan_translation(
        frozenset({SecurityProperty.DESCRIPTION_INTEGRITY}), source="mcp", target="crewai"
    )

    assert plan.status == "compensated"
    assert [guard.kind for guard in plan.guards] == [GuardKind.PRESERVE_DESCRIPTION]


def test_constraints_survive_into_both_targets() -> None:
    for target in ("langchain", "crewai"):
        plan = plan_translation(
            frozenset({SecurityProperty.INPUT_CONSTRAINTS}), source="mcp", target=target
        )
        assert plan.preserved == frozenset({SecurityProperty.INPUT_CONSTRAINTS})
        assert plan.is_lossless


def test_full_annotation_set_into_crewai_compensates_every_hint() -> None:
    declared = frozenset(
        {
            SecurityProperty.READ_ONLY,
            SecurityProperty.DESTRUCTIVE,
            SecurityProperty.IDEMPOTENT,
            SecurityProperty.OPEN_WORLD,
        }
    )

    plan = plan_translation(declared, source="mcp", target="crewai")

    assert plan.compensated == declared
    assert plan.preserved == frozenset()
    assert plan.unsupported == frozenset()
    assert len(plan.guards) == 4


def test_nothing_declared_is_trivially_lossless() -> None:
    plan = plan_translation(frozenset(), source="mcp", target="crewai")

    assert plan.is_lossless
    assert plan.status == "full"


def test_every_guard_names_the_property_it_replaces() -> None:
    declared = frozenset(SecurityProperty)
    plan = plan_translation(declared, source="mcp", target="crewai")

    for guard in plan.guards:
        assert guard.compensates in plan.compensated
    assert len(plan.guards) == len(plan.compensated)
