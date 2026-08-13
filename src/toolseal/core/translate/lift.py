"""Lifting a framework-native tool into the Unified Tool Descriptor.

The inverse of lowering, and the half that was missing: until this existed the
registry could only be filled by crawling, never by importing a tool a project
already has.

Lifting into the descriptor is lossless *by construction* - the descriptor is a
superset of every abstraction's expressive power, so anything a source carries
has somewhere to go. But that is not the same as the descriptor knowing
everything about the tool, and the distinction is the point of this module.

**An absent property has two very different causes.** A tool lifted from CrewAI
has no `destructiveHint`, and there is no way to tell from the tool itself
whether its author never declared one or whether CrewAI dropped it - P0 measured
that CrewAI drops all of them. Reporting both as "not declared" would let a
lossy round trip quietly launder a destructive tool into a safe-looking one.

So :func:`lift` returns the descriptor *and* the set of properties the source
abstraction is incapable of carrying, read from the same lattice that governs
lowering. A consumer can then distinguish "the author said nothing" from "we
cannot know".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from toolseal.core.properties import ANNOTATION_PROPERTIES, SecurityProperty
from toolseal.core.registry.utd import (
    Provenance,
    SecurityAnnotations,
    ToolSource,
    UnifiedToolDescriptor,
)
from toolseal.core.translate.lattice import profile
from toolseal.errors import RegistryError

# Attributes an adapter might hang annotations on. Same list the P0 probe used,
# because the question is identical: where did this framework put them?
_ANNOTATION_CARRIERS = ("metadata", "annotations", "extras", "meta")

# Two kinds of property behave differently on a round trip, and conflating
# them makes `round_trip_loss` wrong in one direction or the other.
#
# An *authored* property is a value only the tool's author knew. If the source
# abstraction dropped it, no target recovers it - a framework able to express
# destructiveHint still has nothing to express.
#
# A *provided* property is a capability rather than a value. Nobody declares
# client-side validation; a target either performs it or does not. Routing
# through a target that does supplies it outright.
_AUTHORED = ANNOTATION_PROPERTIES | {
    SecurityProperty.DESCRIPTION_INTEGRITY,
    SecurityProperty.INPUT_CONSTRAINTS,
}

_HINT_FIELDS = {
    "readOnlyHint": "read_only",
    "destructiveHint": "destructive",
    "idempotentHint": "idempotent",
    "openWorldHint": "open_world",
}


@dataclass(frozen=True)
class Lifted:
    """A descriptor, plus what could not be known from this source."""

    descriptor: UnifiedToolDescriptor
    source_abstraction: str

    unknowable: frozenset[SecurityProperty] = frozenset()
    """Properties the source abstraction cannot carry.

    Absent from the descriptor because the *source* could not express them, not
    because the author declined to. A consumer that treats these as "declared
    false" is reading a lossy round trip as an assertion.
    """

    @property
    def is_complete(self) -> bool:
        """Whether the source could have carried every property the model has."""
        return not self.unknowable

    def declared_or_unknown(self) -> frozenset[SecurityProperty]:
        """Everything the descriptor asserts, plus everything it cannot rule out."""
        return self.descriptor.declared_properties() | self.unknowable


def _unknowable_for(source: str) -> frozenset[SecurityProperty]:
    """Properties this abstraction is structurally incapable of carrying."""
    return frozenset(SecurityProperty) - profile(source).expressible


def _annotations_from(carrier: dict[str, Any]) -> SecurityAnnotations:
    values: dict[str, bool | None] = {}
    for hint, field in _HINT_FIELDS.items():
        raw = carrier.get(hint)
        # Only a real boolean counts. A truthy string would turn "maybe" into a
        # declaration the author never made.
        values[field] = raw if isinstance(raw, bool) else None
    return SecurityAnnotations(**values)


def _find_carrier(tool: object) -> dict[str, Any]:
    for name in _ANNOTATION_CARRIERS:
        value = getattr(tool, name, None)
        if isinstance(value, dict) and any(hint in value for hint in _HINT_FIELDS):
            return value
    return {}


def _schema_of(tool: object) -> dict[str, Any]:
    schema = getattr(tool, "args_schema", None)
    if isinstance(schema, dict):
        return schema
    model_schema = getattr(schema, "model_json_schema", None)
    if callable(model_schema):
        result = model_schema()
        if isinstance(result, dict):
            return result
    return {}


def from_mcp(
    tool: dict[str, Any],
    *,
    package: str = "",
    registry: str = "unknown",
    version: str = "0",
) -> Lifted:
    """Lift an MCP tool definition, as returned by ``tools/list``.

    The reference case: MCP carries everything except client-side validation, so
    almost nothing is unknowable and the descriptor is a faithful record.
    """
    name = str(tool.get("name") or "").strip()
    if not name:
        message = "MCP tool definition has no name"
        raise RegistryError(message)

    annotations = tool.get("annotations")
    schema = tool.get("inputSchema")

    descriptor = UnifiedToolDescriptor(
        id=f"mcp/{package or name}@{version}#{name}",
        name=name,
        description=str(tool.get("description") or ""),
        source=ToolSource(kind="mcp", registry=registry, package=package or name, version=version),
        input_schema=schema if isinstance(schema, dict) else {},
        output_schema=tool.get("outputSchema")
        if isinstance(tool.get("outputSchema"), dict)
        else None,
        annotations=(
            _annotations_from(annotations)
            if isinstance(annotations, dict)
            else SecurityAnnotations()
        ),
        provenance=Provenance(),
    )
    return Lifted(
        descriptor=descriptor,
        source_abstraction="mcp",
        unknowable=_unknowable_for("mcp"),
    )


def from_framework_tool(
    tool: object,
    *,
    source_abstraction: str,
    package: str = "",
    registry: str = "unknown",
    version: str = "0",
) -> Lifted:
    """Lift a live framework tool object - a LangChain or CrewAI tool.

    Works by duck typing rather than by importing either framework: this module
    must not drag LangChain into the dependency set of a tool whose whole point
    is counting dependencies.
    """
    name = str(getattr(tool, "name", "") or "").strip()
    if not name:
        message = f"{source_abstraction} tool object has no name"
        raise RegistryError(message)

    descriptor = UnifiedToolDescriptor(
        id=f"{source_abstraction}/{package or name}@{version}#{name}",
        name=name,
        description=str(getattr(tool, "description", "") or ""),
        source=ToolSource(
            kind=source_abstraction,
            registry=registry,
            package=package or name,
            version=version,
        ),
        input_schema=_schema_of(tool),
        annotations=_annotations_from(_find_carrier(tool)),
        provenance=Provenance(),
    )
    return Lifted(
        descriptor=descriptor,
        source_abstraction=source_abstraction,
        unknowable=_unknowable_for(source_abstraction),
    )


def round_trip_loss(lifted: Lifted, target: str) -> frozenset[SecurityProperty]:
    """Properties that would not survive lifting from one abstraction into another.

    The composite question a registry actually faces: importing a tool from
    CrewAI and lowering it into LangGraph loses whatever CrewAI already dropped,
    and no guard can restore what was never recovered. Reported so an import can
    be refused or annotated rather than silently degrading.

    An authored property that the source could not carry is lost for good. A
    provided one is recovered if the target performs it - which is why lowering
    an MCP tool into Claude Code supplies the client-side validation MCP itself
    has no way to express.
    """
    target_profile = profile(target)
    return frozenset(
        prop
        for prop in lifted.unknowable
        if prop in _AUTHORED or not target_profile.expresses(prop)
    )
