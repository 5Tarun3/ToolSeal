"""Lowering, guard synthesis, and the family G checks that police it.

The property under test is that nothing degrades silently. A dropped annotation
is either compensated by a guard or reported - never simply absent.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from toolseal.core.audit.engine import audit_model
from toolseal.core.model import ProjectModel, TranslationRecord
from toolseal.core.policy import checks_in
from toolseal.core.registry.utd import (
    SecurityAnnotations,
    ToolSource,
    UnifiedToolDescriptor,
)
from toolseal.core.translate.lattice import GuardKind, SecurityProperty
from toolseal.core.translate.lower import lower, ungeneratable_guard_kinds


def descriptor(**overrides: object) -> UnifiedToolDescriptor:
    defaults: dict[str, object] = {
        "id": "mcp/fs@1.0#delete",
        "name": "delete_records",
        "description": "Permanently delete rows. This cannot be undone.",
        "source": ToolSource("mcp", "npm", "@example/fs", "1.0.0"),
        "input_schema": {"properties": {"table": {"enum": ["users", "orders"]}}},
        "annotations": SecurityAnnotations(destructive=True, read_only=False),
    }
    return UnifiedToolDescriptor(**{**defaults, **overrides})  # type: ignore[arg-type]


def test_every_guard_the_lattice_promises_can_be_generated() -> None:
    # A promise the generator cannot keep would emit a binding with a missing
    # guard, which is worse than refusing to lower at all.
    assert ungeneratable_guard_kinds() == frozenset()


def test_lowering_into_langchain_is_lossless() -> None:
    result = lower(descriptor(), "langchain")

    assert result.is_lossless
    assert result.plan.status == "full"
    assert result.guards == ()


def test_lowering_into_crewai_compensates_destructive_with_approval() -> None:
    result = lower(descriptor(), "crewai")

    assert not result.is_lossless
    assert result.plan.status == "compensated"
    assert GuardKind.REQUIRE_APPROVAL in {guard.kind for guard in result.guards}
    assert "require_approval" in result.source


def test_generated_binding_is_valid_python() -> None:
    compile(lower(descriptor(), "crewai").source, "binding.py", "exec")


def test_generated_binding_preserves_the_authors_description() -> None:
    # crewai rewrites descriptions, so the original has to survive somewhere.
    result = lower(descriptor(), "crewai")

    assert "SOURCE_DESCRIPTION" in result.source
    assert "cannot be undone" in result.source


def test_manifest_entry_records_what_happened() -> None:
    entry = lower(descriptor(), "crewai").manifest_entry()

    assert entry["target"] == "crewai"
    assert entry["status"] == "compensated"
    assert str(SecurityProperty.DESTRUCTIVE) in entry["compensated"]
    assert entry["guards"]


def test_record_marks_compensated_properties_as_not_uncompensated() -> None:
    record = lower(descriptor(), "crewai").record

    assert str(SecurityProperty.DESTRUCTIVE) in record.dropped_properties
    assert str(SecurityProperty.DESTRUCTIVE) in record.guards_emitted
    assert str(SecurityProperty.DESTRUCTIVE) not in record.uncompensated


# --- family G --------------------------------------------------------------


def model_with(record: TranslationRecord) -> ProjectModel:
    return ProjectModel(root=Path(), translations=(record,))


def findings_for(check_id: str, record: TranslationRecord) -> list[object]:
    return [f for f in audit_model(model_with(record)).findings if f.check_id == check_id]


def test_family_g_is_registered() -> None:
    assert {c.id for c in checks_in("G")} == {"G1", "G2", "G3", "G4", "G5"}


def test_g_checks_do_not_apply_without_a_translation() -> None:
    report = audit_model(ProjectModel(root=Path()))
    g_results = [r for r in report.results if r.check.family == "G"]

    assert g_results
    assert all(r.verdict.value == "not_applicable" for r in g_results)


def test_g1_fires_only_on_an_uncompensated_annotation() -> None:
    compensated = TranslationRecord(
        tool_name="t",
        source_abstraction="mcp",
        target_abstraction="crewai",
        dropped_properties=frozenset({"destructiveHint"}),
        guards_emitted=frozenset({"destructiveHint"}),
    )
    uncompensated = TranslationRecord(
        tool_name="t",
        source_abstraction="mcp",
        target_abstraction="crewai",
        dropped_properties=frozenset({"destructiveHint"}),
    )

    assert not findings_for("G1", compensated)
    assert findings_for("G1", uncompensated)


def test_g2_fires_when_nothing_validates_before_dispatch() -> None:
    record = TranslationRecord(tool_name="t", source_abstraction="mcp", target_abstraction="crewai")
    assert findings_for("G2", record)

    validated = TranslationRecord(
        tool_name="t",
        source_abstraction="mcp",
        target_abstraction="crewai",
        validates_client_side=True,
    )
    assert not findings_for("G2", validated)


def test_g3_fires_when_errors_are_not_mapped() -> None:
    record = TranslationRecord(
        tool_name="t", source_abstraction="mcp", target_abstraction="langchain"
    )
    assert findings_for("G3", record)


def test_g4_reports_a_loss_with_no_guard() -> None:
    record = TranslationRecord(
        tool_name="t",
        source_abstraction="mcp",
        target_abstraction="crewai",
        dropped_properties=frozenset({"openWorldHint"}),
    )
    assert findings_for("G4", record)


def test_g5_fires_when_the_description_was_rewritten() -> None:
    record = TranslationRecord(
        tool_name="t",
        source_abstraction="mcp",
        target_abstraction="crewai",
        mutated_properties=frozenset({"descriptionIntegrity"}),
    )
    assert findings_for("G5", record)


@pytest.mark.parametrize("target", ["langchain", "crewai"])
def test_a_real_lowering_produces_no_uncompensated_loss(target: str) -> None:
    # The end-to-end property: lowering through this module never leaves G4
    # with anything to report.
    record = lower(descriptor(), target).record
    assert not findings_for("G4", record)
