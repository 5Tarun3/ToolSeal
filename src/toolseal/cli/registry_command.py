"""`toolseal registry` - sync the index and search it."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from toolseal.core.registry.crawl import build_index, crawl_mcp_registry
from toolseal.core.registry.index import INDEX_FILENAME, RegistryIndex
from toolseal.errors import ExitCode

registry_app = typer.Typer(
    name="registry",
    help="Index of open-source tools and MCP servers.",
    no_args_is_help=True,
)


def default_index_path() -> Path:
    """Where the local index cache lives.

    Under the user's data directory rather than the project, so one crawl
    serves every project on the machine.
    """
    base = Path.home() / ".cache" / "toolseal"
    return base / INDEX_FILENAME


@registry_app.command("sync")
def sync(
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Where to write the index.")
    ] = None,
    max_pages: Annotated[
        int, typer.Option("--max-pages", help="Stop after this many registry pages.")
    ] = 20,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Crawl the MCP registry and rebuild the local index."""
    report = crawl_mcp_registry(max_pages=max_pages)
    index = build_index(report)

    path = output or default_index_path()
    index.write(path)

    if as_json:
        typer.echo(
            json.dumps(
                {
                    "path": str(path),
                    "entries": len(index),
                    "pages": report.pages_fetched,
                    "complete": report.complete,
                    "skipped": len(report.skipped),
                    "errors": report.errors,
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        typer.echo(f"{report.summary}\nwrote {path}")
        for error in report.errors:
            typer.secho(f"  {error}", fg=typer.colors.YELLOW)

    # A partial crawl is reported as findings, not success: the index is usable
    # but incomplete, and a scheduled job should be able to notice.
    raise typer.Exit(ExitCode.OK if report.complete else ExitCode.FINDINGS)


@registry_app.command("search")
def search(
    query: Annotated[str, typer.Argument(help="Text to look for.")] = "",
    index_path: Annotated[
        Path | None, typer.Option("--index", help="Index file to search.")
    ] = None,
    limit: Annotated[int, typer.Option("--limit", "-n", help="Maximum results.")] = 20,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Search the index, best-assessed first."""
    index = RegistryIndex.read(index_path or default_index_path())
    results = index.search(query, limit=limit)

    if as_json:
        typer.echo(json.dumps([entry.to_dict() for entry in results], indent=2, sort_keys=True))
        return

    if not results:
        typer.echo(f"nothing matching {query!r} in {len(index)} entries")
        return

    for entry in results:
        flag = "!" if entry.audit.blocking else " "
        typer.echo(f"{flag} {entry.audit.score:>3}  {entry.descriptor.name}")
        if entry.descriptor.description:
            typer.echo(f"        {entry.descriptor.description[:88]}")
        if not entry.tools_enumerated:
            typer.secho(
                "        tools not enumerated (would require running the server)",
                fg=typer.colors.BRIGHT_BLACK,
            )
