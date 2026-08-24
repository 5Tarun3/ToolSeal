"""`toolseal registry` - sync the index, search it, and inspect one entry."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.panel import Panel
from rich.text import Text

from toolseal.cli._ui import (
    accent_text,
    console,
    new_table,
    print_line,
    print_text,
    score_style,
)
from toolseal.cli.errors import command as error_boundary
from toolseal.core.registry.crawl import build_index, crawl_mcp_registry
from toolseal.core.registry.index import INDEX_FILENAME, IndexEntry, RegistryIndex
from toolseal.errors import ExitCode, UsageError

registry_app = typer.Typer(
    name="registry",
    help="Index of open-source tools and MCP servers.",
    no_args_is_help=True,
)

# Caps on the two free-text columns in `search`, so one long package name
# cannot blow the table past an 80-column terminal for every row. Narrower
# than the raw column count would suggest: `rich.table` adds its own
# between-column padding on top of these, and the fixed columns (`score`,
# `registry`, `tools`) must never be the ones a width shortage steals from -
# which is exactly what Rich does instead if these cap too high: it starts
# ellipsizing the header of whichever column it picks to shrink, rather
# than these two, once the surrounding frame eats into the terminal's 80
# columns. `_PACKAGE_WIDTH_MAX` is 4 narrower than the raw arithmetic would
# suggest for that reason - the panel search results now render inside
# (spec: every command's report is framed) costs exactly 4 columns of
# border and padding that a bare table never did.
_NAME_WIDTH_MAX = 20
_PACKAGE_WIDTH_MAX = 19


def default_index_path() -> Path:
    """Where the local index cache lives.

    Under the user's data directory rather than the project, so one crawl
    serves every project on the machine.
    """
    base = Path.home() / ".cache" / "toolseal"
    return base / INDEX_FILENAME


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
        typer.echo(report.summary)
        line = Text("wrote ")
        line.append_text(accent_text(str(path)))
        print_text(console, line)
        for error in report.errors:
            print_line(console, f"  {error}", style="verdict.warn")

    # A partial crawl is reported as findings, not success: the index is usable
    # but incomplete, and a scheduled job should be able to notice.
    raise typer.Exit(ExitCode.OK if report.complete else ExitCode.FINDINGS)


def _search_row(entry: IndexEntry) -> tuple[str, str, str, str, str, str]:
    flag = "!" if entry.audit.blocking else ""
    score = str(entry.audit.score)
    name = entry.descriptor.name
    package_version = f"{entry.descriptor.source.package}@{entry.descriptor.source.version}"
    registry = entry.descriptor.source.registry
    tools = "1" if entry.tools_enumerated else "-"
    return flag, score, name, package_version, registry, tools


def _print_search_results(results: tuple[IndexEntry, ...]) -> None:
    rows = [_search_row(entry) for entry in results]

    table = new_table()
    table.add_column("")  # the "!" blocking flag - unnamed, a single character wide
    table.add_column("score", justify="right")
    table.add_column("name", max_width=_NAME_WIDTH_MAX, overflow="ellipsis", no_wrap=True)
    table.add_column(
        "package@version", max_width=_PACKAGE_WIDTH_MAX, overflow="ellipsis", no_wrap=True
    )
    table.add_column("registry")
    table.add_column("tools", justify="right")
    for flag, score, name, package_version, registry, tools in rows:
        table.add_row(
            Text(flag, style="sev.critical") if flag else Text(""),
            Text(score, style=score_style(int(score))),
            accent_text(name),
            accent_text(package_version),
            registry,
            Text(tools, style="muted" if tools == "-" else ""),
        )
    # Framed like every other command's report (spec: audit's summary panel,
    # policy explain's panel), not a bare table with nothing marking where
    # the results start and end. `expand=False`: the box fits the table's
    # own content width rather than stretching to the terminal's.
    console.print(Panel(table, expand=False))

    blocking_seen = any(flag == "!" for flag, *_rest in rows)
    unenumerated_seen = any(tools == "-" for *_rest, tools in rows)
    if blocking_seen or unenumerated_seen:
        console.print()
    if blocking_seen:
        legend = Text("!", style="sev.critical")
        legend.append("  blocking: a critical check failed")
        print_text(console, legend)
    if unenumerated_seen:
        legend = Text("-", style="muted")
        legend.append("  tools not enumerated (would require running the server)")
        print_text(console, legend)


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
        line = Text("nothing matching ")
        line.append(repr(query), style="accent")
        line.append(f" in {len(index)} entries")
        print_text(console, line)
        return

    _print_search_results(results)


def _print_entry(entry: IndexEntry) -> None:
    descriptor = entry.descriptor
    provenance = descriptor.provenance
    source = descriptor.source

    print_text(console, accent_text(descriptor.id))
    print_line(console, descriptor.name, style="heading")
    console.print()
    typer.echo(descriptor.description or "(no description)")
    typer.echo("")

    fields = [
        ("package", source.package),
        ("version", source.version),
        ("registry", source.registry),
        ("repository", provenance.repository or "not declared"),
        ("license", provenance.license or "not declared"),
        ("publisher", provenance.publisher or "not declared"),
        ("signed", f"yes ({provenance.signature})" if provenance.is_signed else "no"),
    ]
    table = new_table()
    table.add_column("field")
    table.add_column("value")
    for label, value in fields:
        table.add_row(accent_text(label), value)
    console.print(Panel(table, expand=False))
    typer.echo("")

    print_line(console, f"score {entry.audit.score}/100", style=score_style(entry.audit.score))
    if entry.audit.blocking:
        # Severity drives weight identically everywhere (spec §1): the same
        # `sev.critical` treatment `audit` uses for `BLOCKING`.
        print_line(console, "BLOCKING: a critical check failed", style="sev.critical")
    if entry.audit.findings:
        print_line(console, "findings:", style="heading")
        for finding in entry.audit.findings:
            typer.echo(f"  - {finding}")
    typer.echo("")

    if entry.tools_enumerated:
        line = Text("tools: ")
        line.append_text(accent_text(descriptor.name))
        print_text(console, line)
    else:
        print_line(
            console, "tools not enumerated (would require running the server)", style="muted"
        )


def show(
    entry_id: Annotated[str, typer.Argument(help="Entry id, as printed by `registry search`.")],
    index_path: Annotated[Path | None, typer.Option("--index", help="Index file to read.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Show everything known about one registry entry."""
    index = RegistryIndex.read(index_path or default_index_path())
    entry = index.get(entry_id)
    if entry is None:
        message = f"no entry {entry_id!r} in the index; try `toolseal registry search`"
        raise UsageError(message)

    if as_json:
        typer.echo(json.dumps(entry.to_dict(), indent=2, sort_keys=True))
        return

    _print_entry(entry)


# Registered after definition, through the error boundary, so a domain error
# raised inside any of these becomes a message and an exit code rather than a
# traceback when the sub-app is invoked directly (a test harness, `python -m`,
# or anything else that does not go through `main()`). A bare
# `@registry_app.command(...)` decorator bypasses that boundary - this
# repository has fixed that exact regression twice, at P10 and P24.
registry_app.command("sync")(error_boundary(sync))
registry_app.command("search")(error_boundary(search))
registry_app.command("show")(error_boundary(show))
