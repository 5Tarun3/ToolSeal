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

from toolseal.cli import app
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


# --- search ------------------------------------------------------------


def test_search_is_headed(index_path: Path) -> None:
    result = runner.invoke(app, ["registry", "search", "", "--index", str(index_path)])

    assert result.exit_code == ExitCode.OK
    header = result.stdout.splitlines()[0]
    assert header.split() == ["score", "name", "package@version", "registry", "tools"]


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

    # Sorted (blocking, -score): the clean, better-assessed "postgres-server"
    # entry (score 92) comes first; the blocking "long" entry (score 40) comes
    # second and must carry the "!" marker.
    postgres_row, long_row = result.stdout.splitlines()[1:3]
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
    header = lines[0]

    registry_column = header.index("registry")
    for line in lines[1:3]:
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
