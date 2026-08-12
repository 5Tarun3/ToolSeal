"""Descriptor parsing is a trust boundary, so malformed input is tested harder
than well-formed input.

Index entries arrive over the network. Every rejection test here is a case where
a half-built descriptor would otherwise flow into translation and produce a tool
binding nobody declared.
"""

from __future__ import annotations

import pytest

from toolseal.core.registry import (
    SCHEMA_VERSION,
    Provenance,
    SecurityAnnotations,
    ToolSource,
    UnifiedToolDescriptor,
)
from toolseal.core.translate import SecurityProperty
from toolseal.errors import RegistryError

MINIMAL = {
    "id": "mcp/postgres@0.5.1#query",
    "name": "query_postgres",
    "description": "Run a read-only query.",
    "source": {
        "kind": "mcp",
        "registry": "npm",
        "package": "@modelcontextprotocol/server-postgres",
        "version": "0.5.1",
    },
}


def descriptor(**overrides: object) -> UnifiedToolDescriptor:
    data: dict[str, object] = {**MINIMAL, **overrides}
    return UnifiedToolDescriptor.from_dict(data)


def test_round_trip_preserves_every_field() -> None:
    original = UnifiedToolDescriptor(
        id="mcp/fs@1.0#delete",
        name="delete_file",
        description="Delete a file.",
        source=ToolSource("mcp", "npm", "@example/fs", "1.0.0"),
        input_schema={"properties": {"path": {"type": "string", "pattern": "^/docs/"}}},
        output_schema={"properties": {"ok": {"type": "boolean"}}},
        annotations=SecurityAnnotations(read_only=False, destructive=True),
        permissions=frozenset({"fs:write"}),
        egress_hosts=("example.test",),
        filesystem_scope="/docs",
        provenance=Provenance(repository="https://example.test/fs", signature="sigstore"),
    )

    restored = UnifiedToolDescriptor.from_dict(original.to_dict())

    assert restored == original


def test_serialised_form_carries_the_schema_version() -> None:
    assert descriptor().to_dict()["schema_version"] == SCHEMA_VERSION


def test_future_schema_version_is_refused() -> None:
    with pytest.raises(RegistryError, match="unsupported descriptor schema_version"):
        UnifiedToolDescriptor.from_dict({**MINIMAL, "schema_version": 99})


@pytest.mark.parametrize("missing", ["id", "name", "description", "source"])
def test_missing_required_field_names_the_field(missing: str) -> None:
    data = {key: value for key, value in MINIMAL.items() if key != missing}

    with pytest.raises(RegistryError, match=missing):
        UnifiedToolDescriptor.from_dict(data)


def test_wrong_type_reports_both_expected_and_found() -> None:
    with pytest.raises(RegistryError) as caught:
        UnifiedToolDescriptor.from_dict({**MINIMAL, "name": 42})

    message = str(caught.value)
    assert "str" in message and "int" in message


def test_non_boolean_annotation_is_refused() -> None:
    with pytest.raises(RegistryError, match="destructive"):
        descriptor(security={"annotations": {"destructive": "yes"}})


def test_malformed_interface_is_refused() -> None:
    with pytest.raises(RegistryError, match="interface"):
        descriptor(interface=["not", "an", "object"])


def test_malformed_input_schema_is_refused() -> None:
    with pytest.raises(RegistryError, match="input_schema"):
        descriptor(interface={"input_schema": "not an object"})


def test_malformed_egress_hosts_is_refused() -> None:
    with pytest.raises(RegistryError, match="egress_hosts"):
        descriptor(security={"egress_hosts": "example.test"})


def test_undeclared_annotation_is_not_a_false_declaration() -> None:
    annotations = SecurityAnnotations(destructive=True)

    assert annotations.declared() == frozenset({SecurityProperty.DESTRUCTIVE})
    assert annotations.read_only is None


def test_constraints_are_detected_only_when_a_keyword_narrows_a_field() -> None:
    constrained = descriptor(
        interface={"input_schema": {"properties": {"table": {"enum": ["a", "b"]}}}}
    )
    unconstrained = descriptor(
        interface={"input_schema": {"properties": {"table": {"type": "string"}}}}
    )

    assert constrained.has_input_constraints()
    assert not unconstrained.has_input_constraints()


def test_declared_properties_feed_the_lattice() -> None:
    tool = descriptor(
        security={"annotations": {"destructive": True}},
        interface={"input_schema": {"properties": {"n": {"maximum": 10}}}},
    )

    declared = tool.declared_properties()

    assert SecurityProperty.DESTRUCTIVE in declared
    assert SecurityProperty.INPUT_CONSTRAINTS in declared
    assert SecurityProperty.DESCRIPTION_INTEGRITY in declared
    assert SecurityProperty.READ_ONLY not in declared


def test_unsigned_provenance_is_the_default() -> None:
    assert not descriptor().provenance.is_signed
    assert Provenance(signature="sigstore").is_signed
