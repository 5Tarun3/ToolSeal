"""`toolseal add tool`: lowering a registry entry into a project, end to end.

Until this existed, `translate.lower.lower()` was a library function nothing
in the CLI ever called, and `ProjectModel.translations` was always empty, so
family G was implemented and unreachable - the same class of gap `add mcp`
closed for A5/B4/D1/D2 (test_mcp_wiring.py's own opening line). Half the tests
here are the command; the other half is `toolseal audit` reading the
compensation manifest this command writes and firing G1-G5 on a real project.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from toolseal.cli import app
from toolseal.core.audit import audit
from toolseal.core.registry.index import EntryAudit, IndexEntry, RegistryIndex
from toolseal.core.registry.utd import SecurityAnnotations, ToolSource, UnifiedToolDescriptor
from toolseal.errors import ExitCode

runner = CliRunner()


def _index_with(descriptor: UnifiedToolDescriptor, path: Path) -> Path:
    entry = IndexEntry(descriptor=descriptor, audit=EntryAudit(score=90, blocking=False))
    RegistryIndex(entries=(entry,)).write(path)
    return path


def _destructive_descriptor(entry_id: str = "mcp/e/delete@1.0") -> UnifiedToolDescriptor:
    return UnifiedToolDescriptor(
        id=entry_id,
        name="delete_records",
        description="Permanently delete rows. This cannot be undone.",
        source=ToolSource("mcp", "npm", "@example/fs", "1.0.0"),
        annotations=SecurityAnnotations(destructive=True, read_only=False),
    )


def _plain_descriptor(entry_id: str = "mcp/e/list@1.0") -> UnifiedToolDescriptor:
    return UnifiedToolDescriptor(
        id=entry_id,
        name="list_records",
        description="List rows.",
        source=ToolSource("mcp", "npm", "@example/fs", "1.0.0"),
    )


def test_unknown_entry_id_is_refused(tmp_path: Path) -> None:
    index_path = _index_with(_plain_descriptor(), tmp_path / "index.json")

    result = runner.invoke(
        app,
        ["add", "tool", "does/not/exist", "--index", str(index_path), "--directory", str(tmp_path)],
    )

    assert result.exit_code == ExitCode.USAGE
    assert "no entry" in result.output


def test_unknown_framework_is_refused(tmp_path: Path) -> None:
    index_path = _index_with(_plain_descriptor(), tmp_path / "index.json")

    result = runner.invoke(
        app,
        [
            "add",
            "tool",
            "mcp/e/list@1.0",
            "--index",
            str(index_path),
            "--framework",
            "not-a-real-framework",
            "--directory",
            str(tmp_path),
        ],
    )

    assert result.exit_code == ExitCode.USAGE
    assert "no translation target known" in result.output


def test_lossless_lowering_into_claude_code(tmp_path: Path) -> None:
    # claude-code expresses every property this descriptor declares (only
    # descriptionIntegrity, since nothing else is annotated), so nothing needs
    # compensating.
    index_path = _index_with(_plain_descriptor(), tmp_path / "index.json")

    result = runner.invoke(
        app,
        [
            "add",
            "tool",
            "mcp/e/list@1.0",
            "--index",
            str(index_path),
            "--framework",
            "claude-code",
            "--directory",
            str(tmp_path),
        ],
    )

    assert result.exit_code == ExitCode.OK, result.output
    assert "(full)" in result.output
    assert (tmp_path / "tools" / "list_records.py").is_file()


def test_destructive_annotation_is_compensated_into_crewai(tmp_path: Path) -> None:
    index_path = _index_with(_destructive_descriptor(), tmp_path / "index.json")

    result = runner.invoke(
        app,
        [
            "add",
            "tool",
            "mcp/e/delete@1.0",
            "--index",
            str(index_path),
            "--framework",
            "crewai",
            "--directory",
            str(tmp_path),
        ],
    )

    assert result.exit_code == ExitCode.OK, result.output
    assert "(compensated)" in result.output
    assert "require_approval" in result.output
    binding = (tmp_path / "tools" / "delete_records.py").read_text(encoding="utf-8")
    assert "require_approval" in binding


def test_compensation_manifest_accumulates_across_calls(tmp_path: Path) -> None:
    index_path = _index_with(_destructive_descriptor(), tmp_path / "index.json")
    other_path = _index_with(_plain_descriptor(), tmp_path / "index2.json")

    runner.invoke(
        app,
        [
            "add",
            "tool",
            "mcp/e/delete@1.0",
            "--index",
            str(index_path),
            "--framework",
            "crewai",
            "--directory",
            str(tmp_path),
        ],
    )
    runner.invoke(
        app,
        [
            "add",
            "tool",
            "mcp/e/list@1.0",
            "--index",
            str(other_path),
            "--framework",
            "crewai",
            "--directory",
            str(tmp_path),
        ],
    )

    manifest = json.loads((tmp_path / "compensation.json").read_text(encoding="utf-8"))
    tools = {row["tool"] for row in manifest["tools"]}
    assert tools == {"delete_records", "list_records"}


def test_json_output_is_structured(tmp_path: Path) -> None:
    index_path = _index_with(_destructive_descriptor(), tmp_path / "index.json")

    result = runner.invoke(
        app,
        [
            "add",
            "tool",
            "mcp/e/delete@1.0",
            "--index",
            str(index_path),
            "--framework",
            "crewai",
            "--directory",
            str(tmp_path),
            "--json",
        ],
    )

    payload = json.loads(result.output)
    assert payload["status"] == "compensated"
    assert "destructiveHint" in payload["compensated"]
    assert "require_approval" in payload["guards"]


def test_added_tool_is_revertible(tmp_path: Path) -> None:
    index_path = _index_with(_destructive_descriptor(), tmp_path / "index.json")
    runner.invoke(
        app,
        [
            "add",
            "tool",
            "mcp/e/delete@1.0",
            "--index",
            str(index_path),
            "--framework",
            "crewai",
            "--directory",
            str(tmp_path),
        ],
    )

    reverted = runner.invoke(app, ["revert", "--directory", str(tmp_path)])

    assert reverted.exit_code == ExitCode.OK
    assert not (tmp_path / "tools" / "delete_records.py").exists()
    assert not (tmp_path / "compensation.json").exists()


def test_audit_reports_family_g_findings_from_the_written_manifest(tmp_path: Path) -> None:
    # crewai drops destructiveHint's sibling readOnlyHint/idempotentHint/
    # openWorldHint with no guard (ANNOTATE_SIDECAR emits none) - but this
    # descriptor only declares destructive/read_only, and destructive is
    # compensated. What crewai genuinely cannot express and cannot compensate
    # is client-side validation, which G2 always checks for.
    index_path = _index_with(_destructive_descriptor(), tmp_path / "index.json")
    runner.invoke(
        app,
        [
            "add",
            "tool",
            "mcp/e/delete@1.0",
            "--index",
            str(index_path),
            "--framework",
            "crewai",
            "--directory",
            str(tmp_path),
        ],
    )

    report = audit(tmp_path)
    g_ids = {f.check_id for f in report.findings if f.check_id.startswith("G")}

    assert "G2" in g_ids
