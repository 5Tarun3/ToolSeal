"""`toolseal registry` - sync the index, search it, and inspect one entry."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Final

import typer
from rich.panel import Panel
from rich.text import Text

from toolseal.cli._ui import (
    accent_text,
    clip_ascii,
    console,
    new_progress_observer,
    new_table,
    print_line,
    print_text,
    score_style,
)
from toolseal.cli.errors import command as error_boundary
from toolseal.core.policy import progress as progress_hook
from toolseal.core.registry.crawl import build_index, crawl_mcp_registry
from toolseal.core.registry.index import (
    INDEX_FILENAME,
    IndexEntry,
    RegistryIndex,
    merge_indexes,
)
from toolseal.core.registry.tools import ingest_capture
from toolseal.core.registry.utd import Provenance, ToolSource
from toolseal.errors import ExitCode, UsageError

registry_app = typer.Typer(
    name="registry",
    help="Index of open-source tools and MCP servers.",
    epilog=(
        "Start with `toolseal registry search <term>` to find a server, then "
        "`toolseal registry show <id>` for what it declares about itself. "
        "`toolseal add tool` lowers one into your project."
    ),
    no_args_is_help=True,
)

# Caps on the two free-text columns in `search`, so one long package name
# cannot blow the table past an 80-column terminal for every row. Narrower
# than the raw column count would suggest: `rich.table` adds its own
# between-column padding on top of these, and the fixed columns (`score`,
# `registry`, `tools`) must never be the ones a width shortage steals from -
# which is exactly what Rich does instead if these cap too high: it starts
# folding whichever column it picks to shrink, rather than these two, once
# the surrounding frame eats into the terminal's 80 columns. `_PACKAGE_
# WIDTH_MAX` is 4 narrower than the raw arithmetic would suggest for that
# reason - the panel search results now render inside (spec: every
# command's report is framed) costs exactly 4 columns of border and
# padding that a bare table never did.
_NAME_WIDTH_MAX = 20
_PACKAGE_WIDTH_MAX = 19


def default_index_path() -> Path:
    """Where the local index cache lives.

    Under the user's data directory rather than the project, so one crawl
    serves every project on the machine.
    """
    base = Path.home() / ".cache" / "toolseal"
    return base / INDEX_FILENAME


def default_index() -> RegistryIndex:
    """Everything `search`/`show` can see when `--index` is not given.

    The union of the curated set shipped in the package and whatever the
    user's own `registry sync` produced, rather than one or the other.

    An earlier version preferred the cache and read the packaged set only when
    no cache existed. That was reasonable while the packaged set was a subset
    of the same crawl, and wrong as soon as it carried tools: a crawl reads
    registry metadata and can never enumerate a server's tools, since that
    means running the server. The two indexes differ in kind, not in freshness.

    The bug it caused was plain once seen. A user who had run `sync` had a
    2000-entry cache of bare server metadata, and `registry search aseprite`
    told them "nothing matching 'aseprite' in 2000 entries" while the shipped
    index contained exactly that server and its tools. Preferring the larger
    index made the better one invisible.
    """
    cached = default_index_path()
    packaged = RegistryIndex.read_packaged()
    if not cached.exists():
        return packaged
    return merge_indexes(RegistryIndex.read(cached), packaged)


def sync(
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Where to write the index.")
    ] = None,
    max_pages: Annotated[
        int, typer.Option("--max-pages", help="Stop after this many registry pages.")
    ] = 20,
    search: Annotated[
        str | None,
        typer.Option(
            "--search",
            help=(
                "Narrow the crawl to names matching this text. Default pagination is "
                "alphabetically biased, so a name known in advance is found reliably "
                "by searching for it rather than by raising --max-pages."
            ),
        ),
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Crawl the MCP registry and rebuild the local index."""
    # A several-page crawl against a live registry can run long enough to
    # look like a hang (spec S4/S1): `--max-pages` is always a known bound
    # by the time this runs, so `crawl_mcp_registry` reports it as a
    # determinate phase - the observer installed here is what turns that
    # into "fetching the index n/max_pages" on stderr, the same bridge
    # `audit` already uses for C2/C3.
    with progress_hook.observe(new_progress_observer()):
        report = crawl_mcp_registry(max_pages=max_pages, search=search)
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


# Severity drives weight identically everywhere (spec section 1): a declared
# destructive tool takes the same `sev.high` treatment `audit` gives a high
# finding. `?` is `caveat` rather than `muted` for the same reason
# `verdict.unknown` is magenta rather than grey - "the author said nothing"
# must not be rendered as though it read "fine".
_POSTURE_STYLES: Final[dict[str, str]] = {
    "D": "sev.high",
    "R": "verdict.good",
    "?": "caveat",
    "-": "muted",
}

_POSTURE_LEGEND: Final[dict[str, str]] = {
    "D": "the author declared this tool destructive",
    "R": "the author declared this tool read-only",
    "?": "tool known, but its author declared neither read-only nor destructive",
    "-": "tools not enumerated (would require running the server)",
}


def ingest(
    capture: Annotated[Path, typer.Argument(help="A captured tools/list response, as JSON.")],
    server: Annotated[
        str, typer.Option("--server", help="Entry id the tools belong to, e.g. mcp/acme/srv@1.0.")
    ],
    package: Annotated[
        str | None,
        typer.Option("--package", help="Package or URL the server is reached by."),
    ] = None,
    index_path: Annotated[
        Path | None, typer.Option("--index", help="Index to merge into. Defaults to the cache.")
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Add a server's tools to the index from a captured tools/list response.

    `sync` crawls registry *metadata* and never runs anything, which is why it
    records `tools_enumerated: false`: enumerating a server's tools means
    starting it. This command is the other half, and it does not run anything
    either - it reads a response you already obtained from a server you chose
    to authenticate to, as a file.

    The rule the project holds is "toolseal does not execute untrusted servers
    on your behalf", not "no tool listing may ever be indexed". Capturing the
    response is your decision and happens outside this tool; see
    `research/probes/p1_remote_mcp_annotations/README.md` for how the shipped
    entries were captured.
    """
    target = index_path or default_index_path()
    index = RegistryIndex.read(target) if target.exists() else RegistryIndex()

    try:
        payload = json.loads(capture.read_text(encoding="utf-8"))
    except FileNotFoundError:
        message = f"no capture at {capture}"
        raise UsageError(message) from None
    except json.JSONDecodeError as exc:
        message = f"{capture} is not valid JSON: {exc}"
        raise UsageError(message) from None

    existing = index.get(server)
    if existing is not None:
        source = existing.descriptor.source
        provenance = existing.descriptor.provenance
    elif package:
        # An unlisted server still gets an honest record: `unknown` for the
        # registry rather than a guess, so `assess` penalises the absence
        # instead of a fabricated provenance hiding it.
        source = ToolSource(kind="mcp", registry="unknown", package=package, version="")
        provenance = Provenance()
    else:
        message = (
            f"{server!r} is not in the index, so --package is required to record "
            "where its tools come from"
        )
        raise UsageError(message)

    tools = ingest_capture(payload, server_id=server, source=source, provenance=provenance)

    # Replacing rather than appending: re-ingesting a server must not leave a
    # second copy of every tool behind, and a tool the server has since dropped
    # should disappear rather than linger as a stale entry.
    prefix = f"{server}#"
    kept = tuple(entry for entry in index.entries if not entry.id.startswith(prefix))
    merged = RegistryIndex(entries=kept + tools, built_at=index.built_at)
    merged.write(target)

    declared = sum(1 for entry in tools if entry.descriptor.annotations.declared())
    destructive = sum(1 for entry in tools if entry.descriptor.annotations.destructive)

    if as_json:
        typer.echo(
            json.dumps(
                {
                    "server": server,
                    "tools": len(tools),
                    "annotated": declared,
                    "destructive": destructive,
                    "index": str(target),
                    "entries": len(merged),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return

    line = Text("Ingested ", style="verdict.good")
    line.append_text(accent_text(str(len(tools))))
    line.append(" tools from ", style="verdict.good")
    line.append_text(accent_text(server))
    print_text(console, line)
    summary = f"  {declared} annotated, {destructive} declared destructive"
    print_line(console, summary, style="muted")
    written = Text("  wrote ")
    written.append_text(accent_text(str(target)))
    print_text(console, written)


def _posture(entry: IndexEntry) -> str:
    """The one-character posture marker for an entry's `declares` column.

    Deliberately a single character with a spelled-out legend rather than a
    word: the table is held to 80 columns (there is a test), and the spec
    forbids colour as the only carrier of meaning, so the legend does the
    explaining that the width cannot.

    Order matters. `D` wins over `R` because a tool declaring itself
    destructive is the fact a reader must not miss, and the two are not
    mutually exclusive on the wire - a server may set both hints, and the
    reassuring one must never mask the alarming one.
    """
    if not entry.tools_enumerated:
        return "-"
    annotations = entry.descriptor.annotations
    if annotations.destructive:
        return "D"
    if annotations.read_only:
        return "R"
    # Enumerated, but the author declared neither. Not the same as "-", which
    # means nobody looked at all.
    return "?"


def _search_row(entry: IndexEntry) -> tuple[str, str, str, str, str, str]:
    flag = "!" if entry.audit.blocking else ""
    score = str(entry.audit.score)
    # Shortened here, in ASCII, before either value ever reaches `rich`
    # (spec §8) - not left to the column's own overflow handling, which
    # would otherwise reach for `rich`'s hardcoded U+2026 HORIZONTAL
    # ELLIPSIS the moment a name or package string is longer than its cap.
    name = clip_ascii(entry.descriptor.name, _NAME_WIDTH_MAX)
    package_version = clip_ascii(
        f"{entry.descriptor.source.package}@{entry.descriptor.source.version}",
        _PACKAGE_WIDTH_MAX,
    )
    registry = entry.descriptor.source.registry
    return flag, score, name, package_version, registry, _posture(entry)


def _print_search_results(results: tuple[IndexEntry, ...]) -> None:
    rows = [_search_row(entry) for entry in results]

    table = new_table()
    table.add_column("")  # the "!" blocking flag - unnamed, a single character wide
    table.add_column("score", justify="right")
    # `overflow="crop"` here is a backstop, not the truncation mechanism:
    # `_search_row` has already shortened `name`/`package_version` to fit
    # within these caps, marked with an ASCII "..." via `clip_ascii`. This
    # should never actually need to crop anything; if it ever does, that is
    # a bug in the cap arithmetic above, not a value this column is meant to
    # silently shorten on its own.
    table.add_column("name", max_width=_NAME_WIDTH_MAX, overflow="crop", no_wrap=True)
    table.add_column("package@version", max_width=_PACKAGE_WIDTH_MAX, overflow="crop", no_wrap=True)
    table.add_column("registry")
    # Was "tools" ("1" or "-" for whether the tool set was known). Once tools
    # are entries in their own right that answer is implied by the row itself,
    # so the column now carries what the row *declares* about its behaviour,
    # which is the fact a reader picking a tool actually needs.
    table.add_column("hints", justify="right")
    for flag, score, name, package_version, registry, declares in rows:
        table.add_row(
            Text(flag, style="sev.critical") if flag else Text(""),
            Text(score, style=score_style(int(score))),
            accent_text(name),
            accent_text(package_version),
            registry,
            Text(declares, style=_POSTURE_STYLES[declares]),
        )
    # Framed like every other command's report (spec: audit's summary panel,
    # policy explain's panel), not a bare table with nothing marking where
    # the results start and end. `expand=False`: the box fits the table's
    # own content width rather than stretching to the terminal's.
    console.print(Panel(table, expand=False))

    blocking_seen = any(flag == "!" for flag, *_rest in rows)
    seen_postures = {declares for *_rest, declares in rows}
    if blocking_seen or seen_postures:
        console.print()
    if blocking_seen:
        legend = Text("!", style="sev.critical")
        legend.append("  blocking: a critical check failed")
        print_text(console, legend)
    # Only the markers actually present get a legend line - a key explaining
    # symbols that are not on screen is noise, and the panel is already the
    # densest thing this command prints.
    for marker in ("D", "R", "?", "-"):
        if marker in seen_postures:
            legend = Text(marker, style=_POSTURE_STYLES[marker])
            legend.append(f"  {_POSTURE_LEGEND[marker]}")
            print_text(console, legend)


def _paging_is_useful() -> bool:
    """Whether sending output to a pager would help rather than corrupt it.

    A pager writes control sequences and waits for a keypress, so it is right
    for a person at a terminal and wrong for everything else. Redirected, piped
    or in CI, this returns False and the caller prints plainly - the spec's
    "degrade without apology" rule, which exists because a log file has to stay
    readable.

    Kept as a named function rather than an inline `console.is_terminal` so a
    test can state which of the two situations it is exercising.
    """
    return console.is_terminal


# What `--page` raises the row cap to. The default of 20 exists because roughly
# that many rows fit a screen; paging is precisely what removes that
# constraint, so leaving the cap in place would make the flag do half its job.
# A number rather than "unbounded" so a pathological index cannot fill memory.
_PAGED_LIMIT = 1000


def search(
    query: Annotated[str, typer.Argument(help="Text to look for.")] = "",
    index_path: Annotated[
        Path | None, typer.Option("--index", help="Index file to search.")
    ] = None,
    limit: Annotated[int | None, typer.Option("--limit", "-n", help="Maximum results.")] = None,
    page: Annotated[
        bool,
        typer.Option(
            # No `-p` alias: `-p` is `--provider` in `init` and `add framework`,
            # and one letter meaning two things is worse than one option having
            # no short form. Paging is typed once in a session; `--provider` is
            # typed constantly.
            "--page",
            help="Scroll results in a pager. Raises the row limit; ignored when not a terminal.",
        ),
    ] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Search the index for a tool or server, most relevant first."""
    index = RegistryIndex.read(index_path) if index_path is not None else default_index()
    # An explicit --limit always wins; --page only changes the *default*.
    effective_limit = limit if limit is not None else (_PAGED_LIMIT if page else 20)
    results = index.search(query, limit=effective_limit)

    if as_json:
        typer.echo(json.dumps([entry.to_dict() for entry in results], indent=2, sort_keys=True))
        return

    if not results:
        line = Text("nothing matching ")
        line.append(repr(query), style="accent")
        line.append(f" in {len(index)} entries")
        print_text(console, line)
        return

    # `--json` is checked above and has already returned: a machine contract
    # cannot be wrapped in a pager, which would add control sequences and block
    # on a keypress that a parsing caller will never send.
    if page and _paging_is_useful():
        # `styles=True` keeps the severity colours the spec assigns meaning to;
        # without it the `D` posture marker and a blocking `!` arrive as plain
        # text, which is exactly the information a reader is scrolling for.
        with console.pager(styles=True):
            _print_search_results(results)
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


def _resolve(index: RegistryIndex, term: str) -> IndexEntry:
    """The one entry *term* names, or a `UsageError` explaining the choice.

    `show` used to take an exact id and its help said "as printed by `registry
    search`", which was simply untrue: the search table prints a name, a
    package and a score, and never an id. Ids are long enough that showing them
    would either dominate an 80-column table or be clipped to uselessness -
    `mcp/io.github.upstash/context7@4.0.3#query-docs` is 46 characters - so the
    fix is for `show` to accept what a reader can actually see instead.

    Resolution order, most specific first:

    1. **Exact id**, so anything already scripted against ids is unaffected.
    2. **Exact name**, which is the column `search` actually prints.
    3. **Unique substring** of either.

    An exact name is tried before any substring pass because a short name is
    frequently a substring of longer ids - "upstash/context7" names one server
    and appears inside all three of its rows - and a name match is the more
    specific claim.
    """
    exact_id = index.get(term)
    if exact_id is not None:
        return exact_id

    by_name = [entry for entry in index.entries if entry.descriptor.name == term]
    if len(by_name) == 1:
        return by_name[0]

    needle = term.casefold()
    partial = by_name or [
        entry
        for entry in index.entries
        if needle in entry.id.casefold() or needle in entry.descriptor.name.casefold()
    ]
    if len(partial) == 1:
        return partial[0]

    if not partial:
        message = f"no entry matching {term!r}; try `toolseal registry search {term}`"
        raise UsageError(message)

    # The ambiguous case is where someone learns what the ids are, so it prints
    # them in full. Refusing without showing them would leave the reader in the
    # same position that made `show` unusable in the first place.
    shown = sorted(entry.id for entry in partial)[:10]
    listing = "\n  ".join(shown)
    more = f"\n  ... and {len(partial) - len(shown)} more" if len(partial) > len(shown) else ""
    message = f"{term!r} matches {len(partial)} entries:\n  {listing}{more}"
    raise UsageError(message)


def show(
    entry_id: Annotated[
        str,
        typer.Argument(
            help="Entry id, tool name, or a unique part of either, from `registry search`."
        ),
    ],
    index_path: Annotated[Path | None, typer.Option("--index", help="Index file to read.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Show everything known about one registry entry.

    Accepts an entry id, a tool or server name, or a unique part of either -
    see `_resolve`. The name is what `registry search` prints, so it is the
    string a reader has actually seen.
    """
    index = RegistryIndex.read(index_path) if index_path is not None else default_index()
    entry = _resolve(index, entry_id)

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
registry_app.command("ingest")(error_boundary(ingest))
registry_app.command("search")(error_boundary(search))
registry_app.command("show")(error_boundary(show))
