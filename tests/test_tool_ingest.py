"""Turning a captured `tools/list` response into indexable tool descriptors.

The registry has always stored one entry per *server*, in a record whose own
docstring calls itself "one tool, normalised" - so `input_schema` and
`annotations` sat empty on all 113 entries and `tools_enumerated` was false
everywhere. This is the path that fills them, for servers an operator
authenticated to deliberately (see `research/probes/p1_remote_mcp_annotations`).
"""

from __future__ import annotations

import pytest

from toolseal.core.properties import SecurityProperty
from toolseal.core.registry.index import IndexEntry
from toolseal.core.registry.tools import ingest_capture
from toolseal.core.registry.utd import Provenance, ToolSource
from toolseal.errors import RegistryError

SOURCE = ToolSource(kind="mcp", registry="remote", package="mcp.example.com", version="")
PROVENANCE = Provenance(repository="https://example.test/repo", publisher="example")


def _capture(*tools: dict[str, object]) -> dict[str, object]:
    return {"tools": list(tools)}


def _ingest(*tools: dict[str, object]) -> tuple[IndexEntry, ...]:
    return ingest_capture(
        _capture(*tools), server_id="mcp/example/srv@1.0", source=SOURCE, provenance=PROVENANCE
    )


def test_tool_id_hangs_off_the_server_id() -> None:
    # The convention already used by the lowering tests: `<server>#<tool>`.
    (entry,) = _ingest({"name": "update_issue", "description": "Update it."})

    assert entry.id == "mcp/example/srv@1.0#update_issue"


def test_the_entry_is_marked_enumerated() -> None:
    # The whole point: this tool set is known, not merely unlisted.
    (entry,) = _ingest({"name": "x", "description": "d"})

    assert entry.tools_enumerated is True


def test_annotations_are_carried_across() -> None:
    (entry,) = _ingest(
        {
            "name": "update_issue",
            "description": "Update it.",
            "annotations": {
                "readOnlyHint": False,
                "destructiveHint": True,
                "idempotentHint": False,
                "openWorldHint": True,
            },
        }
    )
    annotations = entry.descriptor.annotations

    assert annotations.destructive is True
    assert annotations.read_only is False
    assert SecurityProperty.DESTRUCTIVE in annotations.declared()


def test_an_absent_hint_stays_undeclared_rather_than_false() -> None:
    # `None` means "never said"; `False` means "said no". Collapsing the two is
    # how an unannotated tool acquires a reassuring default.
    (entry,) = _ingest({"name": "x", "description": "d", "annotations": {"readOnlyHint": True}})
    annotations = entry.descriptor.annotations

    assert annotations.read_only is True
    assert annotations.destructive is None
    assert SecurityProperty.DESTRUCTIVE not in annotations.declared()


def test_a_capture_with_no_annotations_block_declares_nothing() -> None:
    (entry,) = _ingest({"name": "x", "description": "d"})

    assert entry.descriptor.annotations.declared() == frozenset()


def test_the_input_schema_is_preserved() -> None:
    schema = {"type": "object", "properties": {"table": {"enum": ["users"]}}}
    (entry,) = _ingest({"name": "x", "description": "d", "inputSchema": schema})

    assert entry.descriptor.input_schema == schema
    # And the constraint is therefore visible to translation.
    assert entry.descriptor.has_input_constraints()


def test_provenance_and_source_are_inherited_from_the_server() -> None:
    # A tool has no package of its own; it is only reachable through its server,
    # so the server's provenance is the only provenance it has.
    (entry,) = _ingest({"name": "x", "description": "d"})

    assert entry.descriptor.source == SOURCE
    assert entry.descriptor.provenance == PROVENANCE


def test_every_tool_in_the_capture_becomes_an_entry() -> None:
    entries = _ingest(
        {"name": "a", "description": "d"},
        {"name": "b", "description": "d"},
        {"name": "c", "description": "d"},
    )

    assert [e.descriptor.name for e in entries] == ["a", "b", "c"]


def test_a_tool_without_a_name_is_rejected() -> None:
    # This parses network-derived JSON; a malformed entry must fail loudly
    # rather than produce a descriptor with an empty identity.
    with pytest.raises(RegistryError):
        _ingest({"description": "no name"})


def test_a_capture_that_is_not_a_tools_list_is_rejected() -> None:
    with pytest.raises(RegistryError):
        ingest_capture(
            {"tools": "not a list"},
            server_id="s",
            source=SOURCE,
            provenance=PROVENANCE,
        )


def test_a_missing_description_is_empty_not_an_error() -> None:
    # A tool may genuinely ship without one. That is a metadata gap the audit
    # reports, not a parse failure.
    (entry,) = _ingest({"name": "x"})

    assert entry.descriptor.description == ""
    assert any("description" in finding for finding in entry.audit.findings)
