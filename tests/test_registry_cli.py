"""`toolseal registry search` and `toolseal registry show` at the CLI boundary.

Two things a plain search result cannot tell an operator - what a hit actually
*is* (its package, its registry, its provenance) and where to go for the rest
of the story - are what these commands exist to fix. The tests here pin the
headed table's shape, the escape hatch to full detail in `show`, and that
`--json` (a machine contract per the project's own rules) did not move.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from toolseal.cli import _ui, app, registry_command
from toolseal.core.policy import progress as progress_hook
from toolseal.core.registry.crawl import CrawlReport
from toolseal.core.registry.index import EntryAudit, IndexEntry, RegistryIndex
from toolseal.core.registry.utd import Provenance, ToolSource, UnifiedToolDescriptor
from toolseal.errors import ExitCode

runner = CliRunner()


def _descriptor(
    entry_id: str,
    name: str,
    *,
    description: str = "",
    package: str = "pkg",
    version: str = "1.0.0",
    registry: str = "npm",
    repository: str | None = "https://example.test/repo",
    license_: str | None = "MIT",
    publisher: str | None = "example",
    signature: str = "none",
) -> UnifiedToolDescriptor:
    return UnifiedToolDescriptor(
        id=entry_id,
        name=name,
        description=description,
        source=ToolSource(kind="mcp", registry=registry, package=package, version=version),
        provenance=Provenance(
            repository=repository, publisher=publisher, signature=signature, license=license_
        ),
    )


def _entry(
    entry_id: str,
    name: str,
    *,
    description: str = "",
    package: str = "pkg",
    version: str = "1.0.0",
    registry: str = "npm",
    repository: str | None = "https://example.test/repo",
    license_: str | None = "MIT",
    publisher: str | None = "example",
    signature: str = "none",
    score: int = 90,
    blocking: bool = False,
    findings: tuple[str, ...] = (),
    tools_enumerated: bool = False,
) -> IndexEntry:
    return IndexEntry(
        descriptor=_descriptor(
            entry_id,
            name,
            description=description,
            package=package,
            version=version,
            registry=registry,
            repository=repository,
            license_=license_,
            publisher=publisher,
            signature=signature,
        ),
        audit=EntryAudit(score=score, blocking=blocking, findings=findings),
        tools_enumerated=tools_enumerated,
    )


@pytest.fixture
def index_path(tmp_path: Path) -> Path:
    index = RegistryIndex(
        entries=(
            _entry(
                "mcp/postgres@1.0.0",
                "postgres-server",
                description="Query a PostgreSQL database over MCP.",
                package="@ex/postgres",
                version="1.0.0",
                score=92,
            ),
            _entry(
                "mcp/long@2.0.0",
                "a-tool-with-a-genuinely-long-descriptive-server-name",
                description="Matched only by this description's mention of xylophone.",
                package="@example/a-really-quite-long-package-identifier-indeed",
                version="2.0.0",
                score=40,
                blocking=True,
                findings=("C4: no signature or attestation",),
            ),
        ),
        built_at="fixed",
    )
    path = tmp_path / "index.json"
    index.write(path)
    return path


# --- sync (spec §4: "fetching the index") -----------------------------


class _ProgressRecorder:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def start(self, phase: str, total: int | None) -> None:
        self.calls.append(("start", phase, str(total)))

    def advance(self, phase: str, step: int = 1) -> None:
        self.calls.append(("advance", phase, str(step)))

    def finish(self, phase: str) -> None:
        self.calls.append(("finish", phase))


def test_sync_installs_an_observer_the_crawl_can_report_progress_through(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`registry sync` wires the CLI's rich-backed observer around the
    crawl (spec: "fetching the index"). `crawl_mcp_registry` is stubbed
    here - a real crawl needs the network - to isolate the wiring itself:
    does `sync()` install an observer the crawl's own progress calls
    reach, not whether `RichAuditProgress` renders correctly (already
    pinned in `test_cli_ui.py`).
    """
    recorder = _ProgressRecorder()
    monkeypatch.setattr(registry_command, "new_progress_observer", lambda: recorder)

    def fake_crawl(*, max_pages: int, **_kwargs: object) -> CrawlReport:
        hook = progress_hook.current()
        hook.start("fetching the index", max_pages)
        hook.advance("fetching the index")
        hook.finish("fetching the index")
        return CrawlReport(pages_fetched=1, complete=True)

    monkeypatch.setattr(registry_command, "crawl_mcp_registry", fake_crawl)

    output_path = tmp_path / "index.json"
    result = runner.invoke(
        app, ["registry", "sync", "--output", str(output_path), "--max-pages", "3"]
    )

    assert result.exit_code == ExitCode.OK
    assert recorder.calls == [
        ("start", "fetching the index", "3"),
        ("advance", "fetching the index", "1"),
        ("finish", "fetching the index"),
    ]
    assert output_path.is_file()


# --- search ------------------------------------------------------------

_SEARCH_HEADER = ["score", "name", "package@version", "registry", "hints"]


def _unbordered_tokens(line: str) -> list[str]:
    """*line*'s whitespace-split tokens, with a leading/trailing panel
    border token dropped if present.

    `registry search` frames its results in a `rich.panel.Panel` (spec:
    every command's report is framed, not a bare table), so the border can
    be either "|" (a console that cannot encode box-drawing - `rich`'s own
    ASCII fallback) or the unicode "|" it draws by default; either way it
    is its own token once split on whitespace, never fused onto a header
    word.
    """
    tokens = line.split()
    border_chars = {"|", "│"}
    if tokens and tokens[0] in border_chars:
        tokens = tokens[1:]
    if tokens and tokens[-1] in border_chars:
        tokens = tokens[:-1]
    return tokens


def _strip_frame(line: str) -> str:
    """*line* with a leading "border + one space" and trailing "space +
    border" removed, if the panel results are drawn in put them there."""
    for left, right in (("│ ", " │"), ("| ", " |")):
        if line.startswith(left) and line.endswith(right):
            return line[len(left) : -len(right)]
    return line


def _header_index(lines: list[str], expected: list[str]) -> int:
    """The line carrying *expected*'s header words, wherever it lands -
    not pinned to line zero, which would rule out ever framing the results
    in a panel the way every other command's report is framed (spec).
    """
    return next(i for i, line in enumerate(lines) if _unbordered_tokens(line) == expected)


def test_search_is_headed(index_path: Path) -> None:
    result = runner.invoke(app, ["registry", "search", "", "--index", str(index_path)])

    assert result.exit_code == ExitCode.OK
    lines = result.stdout.splitlines()
    assert any(_unbordered_tokens(line) == _SEARCH_HEADER for line in lines)


def test_search_rows_carry_identifying_detail(index_path: Path) -> None:
    result = runner.invoke(app, ["registry", "search", "postgres", "--index", str(index_path)])

    assert "@ex/postgres@1.0.0" in result.stdout
    assert "npm" in result.stdout


def test_search_stays_within_80_columns_even_with_long_values(index_path: Path) -> None:
    result = runner.invoke(app, ["registry", "search", "", "--index", str(index_path)])

    for line in result.stdout.splitlines():
        assert len(line) <= 80, line


def test_search_marks_a_blocking_entry_and_explains_the_marker(index_path: Path) -> None:
    result = runner.invoke(app, ["registry", "search", "", "--index", str(index_path)])

    lines = result.stdout.splitlines()
    header_index = _header_index(lines, _SEARCH_HEADER)
    # Sorted (blocking, -score): the clean, better-assessed "postgres-server"
    # entry (score 92) comes first; the blocking "long" entry (score 40) comes
    # second and must carry the "!" marker. `header_index + 1` is
    # `box.SIMPLE`'s header rule; the data rows follow it. `_strip_frame`
    # peels off the panel's own border and padding, so the marker check
    # below is against the row's actual content, not the frame around it.
    postgres_row = _strip_frame(lines[header_index + 2])
    long_row = _strip_frame(lines[header_index + 3])
    assert not postgres_row.startswith("!")
    assert long_row.startswith("!")
    assert long_row[1:].split()[0] == "40"
    assert "blocking" in result.stdout


def test_search_marks_unenumerated_tools_and_explains_the_marker(index_path: Path) -> None:
    result = runner.invoke(app, ["registry", "search", "", "--index", str(index_path)])

    assert "tools not enumerated" in result.stdout


def test_search_heading_survives_a_column_wider_than_the_heading(index_path: Path) -> None:
    # "package@version" (16 chars) is wider than every real package string
    # here is short, but the long-name fixture entry's package is far longer
    # than the header - the header must not end up narrower than that data.
    result = runner.invoke(app, ["registry", "search", "", "--index", str(index_path)])
    lines = result.stdout.splitlines()
    header_index = _header_index(lines, _SEARCH_HEADER)
    header = lines[header_index]

    registry_column = header.index("registry")
    # `header_index + 1` is `box.SIMPLE`'s header rule; the data rows follow
    # it. The panel frame around the whole table adds the same constant-width
    # prefix to every line, so `registry_column`'s offset still lines up.
    for line in lines[header_index + 2 : header_index + 4]:
        assert line[registry_column - 2 : registry_column] == "  "


def test_search_json_output_is_unchanged(index_path: Path) -> None:
    result = runner.invoke(app, ["registry", "search", "", "--index", str(index_path), "--json"])

    payload = json.loads(result.stdout)
    assert isinstance(payload, list)
    assert {"descriptor", "audit", "compat", "tools_enumerated"} <= payload[0].keys()
    # The JSON contract carries no table formatting - it is the same shape
    # `IndexEntry.to_dict()` has always produced.
    index = RegistryIndex.read(index_path)
    expected = [entry.to_dict() for entry in index.search("")]
    assert payload == expected


def test_search_ranks_exact_name_match_before_description_match(tmp_path: Path) -> None:
    index = RegistryIndex(
        entries=(
            _entry("a", "unrelated", description="mentions xylophone in passing", score=90),
            _entry("b", "xylophone", description="", score=90),
        )
    )
    path = tmp_path / "index.json"
    index.write(path)

    result = runner.invoke(app, ["registry", "search", "xylophone", "--index", str(path)])

    # Both entries score 90 and neither is blocking, so the tie is broken by
    # relevance: "xylophone" matches by name exactly and must appear first,
    # ahead of "unrelated" which only matches via its description text.
    assert result.stdout.index("xylophone") < result.stdout.index("unrelated")


def test_search_missing_index_fails_cleanly_not_with_a_traceback(tmp_path: Path) -> None:
    # Regression guard for the bug fixed twice before (P10, P24): a Typer
    # sub-app command registered with a bare decorator bypasses the error
    # boundary and leaks a raw traceback instead of a message and exit code.
    result = runner.invoke(
        app, ["registry", "search", "x", "--index", str(tmp_path / "absent.json")]
    )

    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert result.exit_code != 0
    assert "registry sync" in result.output


# --- default index resolution (P16: search works with no crawl yet) --------
#
# A user who just ran `pip install toolseal` has no `~/.cache/toolseal/`.
# `search`/`show` with no `--index` must still return something - the
# curated set shipped inside the package - rather than telling every new
# user to crawl the whole registry before they can look anything up. Once
# they *have* synced, their own cache takes priority: it is current as of
# their last crawl and reflects a choice they made.


def test_search_falls_back_to_the_packaged_curated_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(registry_command, "default_index_path", lambda: tmp_path / "absent.json")
    packaged = RegistryIndex(entries=(_entry("mcp/curated@1.0.0", "curated-only-tool"),))
    monkeypatch.setattr(RegistryIndex, "read_packaged", classmethod(lambda cls: packaged))

    result = runner.invoke(app, ["registry", "search", ""])

    assert result.exit_code == 0
    assert "curated-only-tool" in result.stdout


def test_search_covers_the_synced_cache_and_the_packaged_set_together(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # This asserted the opposite - that a cache suppressed the packaged set
    # entirely, with a `read_packaged` stub that failed the test if called.
    # That was right while the packaged set was a subset of the same crawl and
    # the cache was strictly newer and larger.
    #
    # It became wrong when the packaged set started carrying tools. A crawl
    # reads registry metadata and can never enumerate a server's tools, so the
    # two indexes differ in kind rather than freshness, and preferring the
    # larger one hid the better one: a user with a 2000-entry cache was told
    # "nothing matching 'aseprite' in 2000 entries" while the shipped index
    # held that server and its tools.
    cache_path = tmp_path / "index.json"
    RegistryIndex(entries=(_entry("mcp/synced@1.0.0", "synced-tool"),)).write(cache_path)
    monkeypatch.setattr(registry_command, "default_index_path", lambda: cache_path)
    packaged = RegistryIndex(entries=(_entry("mcp/curated@1.0.0", "curated-only-tool"),))
    monkeypatch.setattr(RegistryIndex, "read_packaged", classmethod(lambda cls: packaged))

    result = runner.invoke(app, ["registry", "search", ""])

    assert result.exit_code == 0
    assert "synced-tool" in result.stdout, "the user's own crawl must still be searchable"
    assert "curated-only-tool" in result.stdout, "the packaged set must not be suppressed"


def test_show_falls_back_to_the_packaged_curated_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(registry_command, "default_index_path", lambda: tmp_path / "absent.json")
    packaged = RegistryIndex(entries=(_entry("mcp/curated@1.0.0", "curated-only-tool"),))
    monkeypatch.setattr(RegistryIndex, "read_packaged", classmethod(lambda cls: packaged))

    result = runner.invoke(app, ["registry", "show", "mcp/curated@1.0.0"])

    assert result.exit_code == 0
    assert "curated-only-tool" in result.stdout


def test_explicit_index_flag_still_overrides_both_fallbacks(index_path: Path) -> None:
    # An explicit `--index` is never shadowed by either default: it fails
    # cleanly if absent (pinned above), and here it wins even though a
    # packaged fallback exists in the real, installed package.
    result = runner.invoke(app, ["registry", "search", "", "--index", str(index_path)])

    assert result.exit_code == 0
    assert "postgres-server" in result.stdout


# --- show ----------------------------------------------------------------


def test_show_prints_repository_and_package(index_path: Path) -> None:
    result = runner.invoke(
        app, ["registry", "show", "mcp/postgres@1.0.0", "--index", str(index_path)]
    )

    assert result.exit_code == ExitCode.OK
    assert "https://example.test/repo" in result.stdout
    assert "@ex/postgres" in result.stdout


def test_show_prints_the_full_description_not_truncated(index_path: Path) -> None:
    result = runner.invoke(
        app, ["registry", "show", "mcp/postgres@1.0.0", "--index", str(index_path)]
    )

    assert "Query a PostgreSQL database over MCP." in result.stdout


def test_show_reports_score_and_findings(index_path: Path) -> None:
    result = runner.invoke(app, ["registry", "show", "mcp/long@2.0.0", "--index", str(index_path)])

    assert "40/100" in result.stdout
    assert "BLOCKING" in result.stdout
    assert "no signature or attestation" in result.stdout


def test_show_reports_unenumerated_tools(index_path: Path) -> None:
    result = runner.invoke(
        app, ["registry", "show", "mcp/postgres@1.0.0", "--index", str(index_path)]
    )

    assert "tools not enumerated" in result.stdout


def test_show_unknown_id_is_a_usage_error(index_path: Path) -> None:
    result = runner.invoke(app, ["registry", "show", "no/such@0", "--index", str(index_path)])

    assert result.exit_code == ExitCode.USAGE
    assert "no/such@0" in result.output
    assert "registry search" in result.output


def test_show_json_matches_the_entry(index_path: Path) -> None:
    result = runner.invoke(
        app, ["registry", "show", "mcp/postgres@1.0.0", "--index", str(index_path), "--json"]
    )

    payload = json.loads(result.stdout)
    assert payload["descriptor"]["id"] == "mcp/postgres@1.0.0"
    assert payload["descriptor"]["provenance"]["repository"] == "https://example.test/repo"


# --- paging ----------------------------------------------------------------


def test_page_renders_results_through_a_pager(
    index_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    used: list[bool] = []

    class _Recording:
        def __enter__(self) -> None:
            used.append(True)

        def __exit__(self, *_: object) -> None:
            return None

    monkeypatch.setattr(_ui.console, "pager", lambda **_: _Recording())
    monkeypatch.setattr(registry_command, "_paging_is_useful", lambda: True)

    result = runner.invoke(app, ["registry", "search", "", "--index", str(index_path), "--page"])

    assert result.exit_code == ExitCode.OK
    assert used, "--page should render inside the pager"


def test_json_output_is_never_paged(index_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A machine contract: a pager would corrupt piped output, and --json is
    # parsed by the study harness.
    def _fail(**_: object) -> None:
        message = "--json must not be paged"
        raise AssertionError(message)

    monkeypatch.setattr(_ui.console, "pager", _fail)
    monkeypatch.setattr(registry_command, "_paging_is_useful", lambda: True)

    result = runner.invoke(
        app, ["registry", "search", "", "--index", str(index_path), "--page", "--json"]
    )

    assert result.exit_code == ExitCode.OK
    json.loads(result.stdout)


def test_page_is_ignored_when_output_is_not_a_terminal(
    index_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Redirected or in CI: plain text, no pager, same information (spec:
    # degrade without apology).
    def _fail(**_: object) -> None:
        message = "must not page a non-terminal"
        raise AssertionError(message)

    monkeypatch.setattr(_ui.console, "pager", _fail)
    monkeypatch.setattr(registry_command, "_paging_is_useful", lambda: False)

    result = runner.invoke(app, ["registry", "search", "", "--index", str(index_path), "--page"])

    assert result.exit_code == ExitCode.OK
    assert "postgres-server" in result.stdout


def test_page_lifts_the_default_row_limit(
    index_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The default limit of 20 exists because 20 rows is roughly a screen.
    # Paging is what removes that constraint, so keeping the cap would defeat
    # the flag. An explicit --limit still wins.
    seen: list[int] = []
    original = RegistryIndex.search

    def record(self: RegistryIndex, query: str, *, limit: int = 20) -> tuple[IndexEntry, ...]:
        seen.append(limit)
        return original(self, query, limit=limit)

    monkeypatch.setattr(RegistryIndex, "search", record)
    monkeypatch.setattr(registry_command, "_paging_is_useful", lambda: False)

    runner.invoke(app, ["registry", "search", "", "--index", str(index_path), "--page"])
    runner.invoke(
        app, ["registry", "search", "", "--index", str(index_path), "--page", "--limit", "5"]
    )

    assert seen[0] > 20, "--page should not stay capped at one screen"
    assert seen[1] == 5, "an explicit --limit must still win"
