"""An MCP server whose tools carry every security-relevant property under test.

This file is the ground truth for the P0 probe. Whatever this server declares is
what a faithful adapter must preserve; anything an adapter fails to carry across
is, by definition, translation loss.

The three tools are chosen to span the interesting cases:

* ``delete_records`` is destructive and non-idempotent, with a closed enum and a
  bounded integer. If ``destructiveHint`` is dropped, a consumer cannot tell it
  apart from a read-only tool.
* ``read_document`` is read-only and idempotent, and constrains its input with a
  regular expression. The pattern is the security control: it is what stops the
  tool reading outside ``/docs``.
* ``search_web`` reaches the public internet, which is what ``openWorldHint``
  exists to communicate.

Run directly to serve over stdio: ``python fixture_server.py``
"""

from __future__ import annotations

from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

mcp = FastMCP("p0-fixture")


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


if __name__ == "__main__":
    mcp.run()
