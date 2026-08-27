"""Indexing a server's actual tools, not just the server.

`UnifiedToolDescriptor`'s own docstring calls it "one tool, normalised - the
registry's storage unit", and it carries `input_schema`, `output_schema` and
`annotations`, all of which are per-*tool* facts. The registry nonetheless
filled it with per-*server* metadata, which is why all 113 shipped entries
report `tools_enumerated: false` with empty schemas and no annotations. This
module is the path that populates it as designed.

**The no-execute rule is narrowed here, not abandoned.** `crawl.py` still never
runs anything: it reads registry metadata and records `tools_enumerated: false`
precisely because enumerating a server's tools means running it. What this
module ingests is a `tools/list` response an operator obtained deliberately,
against a server they authenticated to themselves - see
`research/probes/p1_remote_mcp_annotations`. The distinction the project holds
is "we do not execute untrusted servers on a user's behalf", not "no tool
listing may ever enter the index". A capture arrives as data, from a file, and
is parsed at a trust boundary like any other network-derived input.

Tools inherit their server's `source` and `provenance` because they have none
of their own: a tool is not separately published, versioned, or signed, and is
only reachable through the server that offers it. Pretending otherwise would
invent provenance the ecosystem does not provide.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from toolseal.core.registry.index import IndexEntry
from toolseal.core.registry.utd import (
    Provenance,
    SecurityAnnotations,
    ToolSource,
    UnifiedToolDescriptor,
)
from toolseal.errors import RegistryError

# MCP spells its annotation hints in camelCase on the wire; the descriptor
# stores them under the vocabulary shared with the lattice and family G.
_HINTS: Mapping[str, str] = {
    "readOnlyHint": "read_only",
    "destructiveHint": "destructive",
    "idempotentHint": "idempotent",
    "openWorldHint": "open_world",
}


def _annotations(raw: Any) -> SecurityAnnotations:
    """Parse a tool's annotation block.

    An absent hint stays `None`. A tool that never said whether it is
    destructive is not a tool that said it is safe, and this is the boundary
    where that distinction would be easiest to lose - `dict.get(key, False)`
    would silently manufacture a reassuring answer for every unannotated tool
    in the corpus.
    """
    if raw is None:
        return SecurityAnnotations()
    if not isinstance(raw, dict):
        message = "tool field 'annotations' must be an object or absent"
        raise RegistryError(message)

    values: dict[str, bool | None] = {}
    for wire_name, field in _HINTS.items():
        value = raw.get(wire_name)
        if value is not None and not isinstance(value, bool):
            message = f"tool annotation {wire_name!r} must be a boolean or absent"
            raise RegistryError(message)
        values[field] = value
    return SecurityAnnotations(**values)


def tool_descriptor(
    tool: Any,
    *,
    server_id: str,
    source: ToolSource,
    provenance: Provenance,
) -> UnifiedToolDescriptor:
    """One tool from a `tools/list` response, as a descriptor.

    The id is `<server id>#<tool name>`, the convention already used elsewhere
    for a tool within a server, so a descriptor can always be traced back to
    what serves it.
    """
    if not isinstance(tool, dict):
        message = "each entry of 'tools' must be an object"
        raise RegistryError(message)

    name = tool.get("name")
    if not isinstance(name, str) or not name.strip():
        message = "tool is missing a usable 'name'"
        raise RegistryError(message)

    schema = tool.get("inputSchema") or {}
    if not isinstance(schema, dict):
        message = f"tool {name!r} field 'inputSchema' must be an object"
        raise RegistryError(message)

    description = tool.get("description")
    if description is not None and not isinstance(description, str):
        message = f"tool {name!r} field 'description' must be a string"
        raise RegistryError(message)

    return UnifiedToolDescriptor(
        id=f"{server_id}#{name}",
        name=name,
        description=description or "",
        source=source,
        input_schema=schema,
        annotations=_annotations(tool.get("annotations")),
        provenance=provenance,
        status="active",
    )


def ingest_capture(
    capture: Mapping[str, Any],
    *,
    server_id: str,
    source: ToolSource,
    provenance: Provenance,
) -> tuple[IndexEntry, ...]:
    """Every tool in a captured `tools/list` response, assessed and indexable.

    Assessment runs through `crawl.assess` rather than a second scorer, so a
    tool entry and a server entry are judged by the same rules and their
    scores are comparable. Imported here rather than at module scope because
    `crawl` imports this module's neighbours; the local import keeps the two
    from forming a cycle.
    """
    from toolseal.core.registry.crawl import assess

    raw = capture.get("tools")
    if not isinstance(raw, list):
        message = "capture field 'tools' must be a list"
        raise RegistryError(message)

    entries: list[IndexEntry] = []
    for tool in raw:
        descriptor = tool_descriptor(
            tool, server_id=server_id, source=source, provenance=provenance
        )
        entries.append(
            IndexEntry(
                descriptor=descriptor,
                audit=assess(descriptor),
                tools_enumerated=True,
            )
        )
    return tuple(entries)
