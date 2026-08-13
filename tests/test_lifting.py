"""Lifting a framework-native tool into the descriptor.

The inverse of lowering, and the half that lets a registry be filled by
importing rather than only by crawling.

Lifting is lossless by construction - the descriptor is a superset - so the
tests that matter are not about what survives. They are about the distinction
between *the author declared nothing* and *this source could not carry it*.
Collapsing those two would let a lossy round trip launder a destructive tool
into a safe-looking one, which is the exact failure the translation layer exists
to prevent.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from toolseal.core.translate.lattice import SecurityProperty
from toolseal.core.translate.lift import from_framework_tool, from_mcp, round_trip_loss
from toolseal.core.translate.lower import lower
from toolseal.errors import RegistryError

MCP_TOOL: dict[str, Any] = {
    "name": "delete_records",
    "description": "Permanently delete rows. This cannot be undone.",
    "annotations": {
        "destructiveHint": True,
        "readOnlyHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
    "inputSchema": {"properties": {"table": {"enum": ["users", "orders"]}}},
}


class FakeLangChainTool:
    """Shaped like what P0 measured langchain-mcp-adapters to produce."""

    name = "delete_records"
    description = "Permanently delete rows. This cannot be undone."
    metadata = {"destructiveHint": True, "readOnlyHint": False}  # noqa: RUF012
    args_schema = {"properties": {"table": {"enum": ["users", "orders"]}}}  # noqa: RUF012


class FakeCrewAITool:
    """Shaped like what P0 measured crewai-tools to produce: no carrier at all."""

    name = "delete_records"
    description = "Tool Name: delete_records"
    args_schema = {"properties": {"table": {"enum": ["users", "orders"]}}}  # noqa: RUF012


# --- lifting from MCP ------------------------------------------------------


def test_mcp_annotations_survive() -> None:
    lifted = from_mcp(MCP_TOOL, package="@example/fs", registry="npm", version="1.0.0")

    assert lifted.descriptor.annotations.destructive is True
    assert SecurityProperty.DESTRUCTIVE in lifted.descriptor.declared_properties()


def test_mcp_schema_and_description_survive() -> None:
    descriptor = from_mcp(MCP_TOOL).descriptor

    assert descriptor.has_input_constraints()
    assert "cannot be undone" in descriptor.description


def test_mcp_is_the_most_complete_source() -> None:
    # Everything except client-side validation, which the protocol leaves to the
    # server and so genuinely cannot express.
    assert from_mcp(MCP_TOOL).unknowable == frozenset({SecurityProperty.CLIENT_VALIDATION})


def test_unnamed_mcp_tool_is_refused() -> None:
    with pytest.raises(RegistryError, match="no name"):
        from_mcp({"description": "nameless"})


def test_non_boolean_hint_is_not_treated_as_a_declaration() -> None:
    # A truthy string would turn "maybe" into an assertion the author never made.
    lifted = from_mcp({**MCP_TOOL, "annotations": {"destructiveHint": "yes"}})

    assert lifted.descriptor.annotations.destructive is None


# --- lifting from a live framework tool ------------------------------------


def test_langchain_tool_yields_its_annotations() -> None:
    lifted = from_framework_tool(FakeLangChainTool(), source_abstraction="langchain")

    assert lifted.descriptor.annotations.destructive is True


def test_crewai_tool_yields_no_annotations() -> None:
    # P0 measured that CrewAI drops them, so there is nothing to recover.
    lifted = from_framework_tool(FakeCrewAITool(), source_abstraction="crewai")

    assert lifted.descriptor.annotations.destructive is None


def test_a_missing_annotation_is_unknowable_not_absent() -> None:
    # The central distinction. CrewAI cannot carry destructiveHint, so its
    # absence says nothing about the tool - and the lift records that.
    lifted = from_framework_tool(FakeCrewAITool(), source_abstraction="crewai")

    assert SecurityProperty.DESTRUCTIVE not in lifted.descriptor.declared_properties()
    assert SecurityProperty.DESTRUCTIVE in lifted.unknowable
    assert SecurityProperty.DESTRUCTIVE in lifted.declared_or_unknown()


def test_langchain_can_carry_destructive_so_it_is_not_unknowable() -> None:
    lifted = from_framework_tool(FakeLangChainTool(), source_abstraction="langchain")

    assert SecurityProperty.DESTRUCTIVE not in lifted.unknowable


def test_completeness_reflects_the_source_not_the_tool() -> None:
    assert not from_framework_tool(FakeCrewAITool(), source_abstraction="crewai").is_complete
    assert not from_mcp(MCP_TOOL).is_complete  # client validation is never carried


def test_unnamed_framework_tool_is_refused() -> None:
    class Nameless:
        name = ""

    with pytest.raises(RegistryError, match="no name"):
        from_framework_tool(Nameless(), source_abstraction="crewai")


def test_lifting_does_not_import_the_frameworks() -> None:
    # Duck typing on purpose: this module must not drag LangChain into the
    # dependency set of a tool whose point is counting dependencies.
    source = Path("src/toolseal/core/translate/lift.py").read_text(encoding="utf-8")

    assert "import langchain" not in source
    assert "import crewai" not in source


# --- the round trip --------------------------------------------------------


def test_mcp_to_langchain_keeps_destructive() -> None:
    result = lower(from_mcp(MCP_TOOL).descriptor, "langchain")

    assert SecurityProperty.DESTRUCTIVE in result.plan.preserved


def test_mcp_to_crewai_compensates_rather_than_drops() -> None:
    result = lower(from_mcp(MCP_TOOL).descriptor, "crewai")

    assert result.plan.status == "compensated"
    assert SecurityProperty.DESTRUCTIVE in result.plan.compensated


def test_importing_from_crewai_cannot_recover_what_crewai_dropped() -> None:
    # The composite question a registry faces. No guard reinstates a property
    # that was never recovered, so the loss is reported rather than papered over.
    lifted = from_framework_tool(FakeCrewAITool(), source_abstraction="crewai")

    assert SecurityProperty.DESTRUCTIVE in round_trip_loss(lifted, "langchain")


def test_importing_from_mcp_loses_almost_nothing() -> None:
    assert SecurityProperty.DESTRUCTIVE not in round_trip_loss(from_mcp(MCP_TOOL), "langchain")


def test_claude_code_supplies_what_mcp_could_not() -> None:
    # Lifting from MCP cannot know about client-side validation, but lowering
    # into Claude Code supplies it: permission rules run before the tool does.
    assert SecurityProperty.CLIENT_VALIDATION not in round_trip_loss(
        from_mcp(MCP_TOOL), "claude-code"
    )
