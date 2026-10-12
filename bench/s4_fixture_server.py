"""Study 4's ground truth: an MCP server whose tools carry every property under test.

Probe P0's three tools are kept unchanged, so P0's pilot numbers remain directly
comparable. The evaluation protocol requires the fixture to be widened to cover
what P0 did not exercise, and the three tools added here do exactly that:

* ``create_ticket`` - a nested object whose fields carry their own constraints,
  an optional field with a default, and a nullable optional field. Pydantic
  emits the nested model through ``$defs``/``$ref``, which is itself something
  an adapter has to carry or resolve.
* ``tag_items`` - an array with item-level ``enum`` and array-level
  ``minItems``/``maxItems``/``uniqueItems``. ``uniqueItems`` is declared
  through ``json_schema_extra``, so it appears in the schema but this server
  does **not** enforce it - found on the first run, when ``["public",
  "public"]`` succeeded through every adapter. Kept rather than fixed, because
  changing the fixture after seeing results is tuning, and because it is the
  case P0 warned about: a constraint whose server does not validate has no
  second line, so only a client-side check could stop it.
* ``fail_always`` - raises on every call, so the MCP result carries
  ``isError: true``. It is what the error path is measured against.

Whatever this server declares is what a faithful adapter must preserve.

**The call log is how enforcement is told apart from rejection.** Run with
``--call-log PATH`` and every ``tools/call`` request is appended to PATH as it
arrives - before the server validates it. An invalid call that appears in the
log left the client; one that does not was stopped client-side. It is a
command-line argument rather than an environment variable because the MCP stdio
client deliberately starts the server with a filtered environment.

Run directly to serve over stdio: ``python bench/s4_fixture_server.py``
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field


def _call_log() -> Path | None:
    if "--call-log" in sys.argv:
        return Path(sys.argv[sys.argv.index("--call-log") + 1])
    return None


class _LoggingFastMCP(FastMCP):
    """FastMCP that records each call on arrival, ahead of its own validation."""

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        log = _call_log()
        if log is not None:
            with log.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps({"tool": name, "arguments": arguments}) + "\n")
        return await super().call_tool(name, arguments)


mcp = _LoggingFastMCP("s4-fixture")


# --- P0's tools, unchanged --------------------------------------------------


@mcp.tool(
    annotations=ToolAnnotations(
        title="Delete Records",
        readOnlyHint=False,
        destructiveHint=True,
        idempotentHint=False,
        openWorldHint=False,
    )
)
def delete_records(
    table: Annotated[Literal["users", "orders"], Field(description="Table to delete from.")],
    limit: Annotated[int, Field(ge=1, le=100, description="Maximum rows to remove.")],
    confirm: bool = False,
) -> str:
    """Permanently delete rows from a table. This cannot be undone."""
    return f"deleted up to {limit} rows from {table} (confirm={confirm})"


@mcp.tool(
    annotations=ToolAnnotations(
        title="Read Document",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
def read_document(
    path: Annotated[
        str,
        Field(
            pattern=r"^/docs/[A-Za-z0-9_/.-]+$",
            max_length=256,
            description="Absolute path beneath /docs.",
        ),
    ],
) -> str:
    """Read a document from the documentation directory."""
    return f"contents of {path}"


@mcp.tool(
    annotations=ToolAnnotations(
        title="Search the Web",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True,
    )
)
def search_web(
    query: Annotated[str, Field(min_length=1, max_length=200, description="Search terms.")],
) -> str:
    """Search the public web and return result summaries."""
    return f"results for {query}"


# --- added for Study 4 --------------------------------------------------------


class Reporter(BaseModel):
    """Who raised the ticket. Nested so its constraints sit below the top level."""

    email: Annotated[str, Field(pattern=r"^[a-z0-9.]+@example\.org$", max_length=64)]
    team: Literal["security", "platform"]


@mcp.tool(
    annotations=ToolAnnotations(
        title="Create Ticket",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=False,
    )
)
def create_ticket(
    reporter: Reporter,
    summary: Annotated[str, Field(min_length=5, max_length=120)],
    priority: Annotated[int, Field(ge=1, le=5)] = 3,
    assignee: Annotated[str | None, Field(max_length=32)] = None,
) -> str:
    """Open a ticket in the internal tracker."""
    return f"ticket by {reporter.email} p{priority} assignee={assignee}: {summary}"


@mcp.tool(
    annotations=ToolAnnotations(
        title="Tag Items",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
def tag_items(
    tags: Annotated[
        list[Literal["public", "internal", "restricted"]],
        Field(min_length=1, max_length=3, json_schema_extra={"uniqueItems": True}),
    ],
) -> str:
    """Apply classification tags to the current selection."""
    return f"tagged {','.join(tags)}"


@mcp.tool(
    annotations=ToolAnnotations(
        title="Fail Always",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
def fail_always(reason: Annotated[str, Field(max_length=40)] = "fixture") -> str:
    """Always fails, so the error path can be observed."""
    message = f"refused by the fixture: {reason}"
    raise RuntimeError(message)


if __name__ == "__main__":
    mcp.run()
