"""Claude Code as a framework, and the reversible injection it needs.

Two things are being tested. The adapter, which is the first target able to
express `destructiveHint` natively and therefore the first case where lowering
correctly emits *no* guard. And the injection machinery, which exists because
configuring someone else's project is only acceptable if it can be undone
exactly.

The revert tests are the important half. A tool that writes into a directory it
did not create and cannot restore it is worse than one that refuses to write at
all.
"""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath

import pytest
from typer.testing import CliRunner

from toolseal.cli import app
from toolseal.core.adapters import RenderedFile, ScaffoldSpec, framework_registry
from toolseal.core.adapters.frameworks import ClaudeCodeFramework, LangGraphFramework
from toolseal.core.adapters.providers import GeminiProvider, OllamaProvider
from toolseal.core.injection import inject, load, plan_revert, revert
from toolseal.core.registry.utd import (
    SecurityAnnotations,
    ToolSource,
    UnifiedToolDescriptor,
)
from toolseal.core.translate.lattice import profile
from toolseal.core.translate.lower import lower
from toolseal.errors import ConfigError, ExitCode

runner = CliRunner()
FRAMEWORK = ClaudeCodeFramework()
PROVIDER = OllamaProvider()


def rendered(tmp_path: Path) -> dict[str, str]:
    spec = ScaffoldSpec(
        project_name="demo",
        provider_id="ollama",
        framework_id="claude-code",
        workspace_root=tmp_path,
    )
    return {str(f.path): f.content for f in FRAMEWORK.render(spec, PROVIDER)}


# --- the adapter -----------------------------------------------------------


def test_registered() -> None:
    assert "claude-code" in framework_registry.names()


def test_declares_that_it_configures_rather_than_creates() -> None:
    # The flag the CLI branches on. Without it `init` would happily produce a
    # directory containing only settings and no agent.
    assert FRAMEWORK.configures_in_place
    assert not getattr(LangGraphFramework(), "configures_in_place", False)


def test_needs_no_python_dependencies() -> None:
    # Claude Code is a runtime, not a library the project imports. An empty set
    # is the honest answer rather than a placeholder.
    assert FRAMEWORK.packages(PROVIDER) == ()


def test_emits_only_configuration(tmp_path: Path) -> None:
    files = rendered(tmp_path)

    assert set(files) == {".claude/settings.json", "CLAUDE.md"}
    assert not any(name.endswith(".py") for name in files)


def test_settings_are_valid_json_with_all_three_rule_sets(tmp_path: Path) -> None:
    settings = json.loads(rendered(tmp_path)[".claude/settings.json"])

    permissions = settings["permissions"]
    assert permissions["allow"] and permissions["ask"] and permissions["deny"]


def test_credential_paths_are_denied(tmp_path: Path) -> None:
    # A1/A2 expressed as configuration: the agent cannot read key material even
    # by accident.
    deny = json.loads(rendered(tmp_path)[".claude/settings.json"])["permissions"]["deny"]

    joined = " ".join(deny)
    for fragment in (".env", ".ssh", ".aws", "id_rsa"):
        assert fragment in joined


def test_no_wildcard_shell_permission(tmp_path: Path) -> None:
    # B2: only named, narrow commands are allowed.
    allow = json.loads(rendered(tmp_path)[".claude/settings.json"])["permissions"]["allow"]

    assert "Bash" not in allow
    assert "Bash(*)" not in allow


def test_writes_land_in_ask_not_allow(tmp_path: Path) -> None:
    # F2, and the reason this target needs no compensating guard.
    permissions = json.loads(rendered(tmp_path)[".claude/settings.json"])["permissions"]

    assert "Edit" in permissions["ask"]
    assert "Edit" not in permissions["allow"]


def test_instructions_explain_how_to_undo(tmp_path: Path) -> None:
    assert "toolseal revert" in rendered(tmp_path)["CLAUDE.md"]


# --- the lattice point -----------------------------------------------------


def test_expressible_set_comes_from_the_lattice() -> None:
    assert FRAMEWORK.expressible_properties() == frozenset(
        str(prop) for prop in profile("claude-code").expressible
    )


def test_it_is_the_widest_target() -> None:
    # The control condition the lattice previously lacked: with only LangGraph
    # and CrewAI, no real framework exercised the lossless path.
    assert len(FRAMEWORK.expressible_properties()) > len(
        LangGraphFramework().expressible_properties()
    )


def test_destructive_tool_lowers_losslessly() -> None:
    descriptor = UnifiedToolDescriptor(
        id="mcp/fs@1#delete",
        name="delete_records",
        description="Permanently delete rows.",
        source=ToolSource("mcp", "npm", "@example/fs", "1.0.0"),
        annotations=SecurityAnnotations(destructive=True),
    )

    result = lower(descriptor, "claude-code")

    assert result.plan.status == "full"
    assert result.guards == ()


def test_the_lattice_row_is_measured_and_says_how() -> None:
    # Promoted from `specified` after a live session confirmed the behaviour:
    # a read of .env was refused by the deny rule, and the agent declined to
    # reach the same file through another tool. The note carries that evidence
    # so the claim can be checked rather than taken on trust.
    row = profile("claude-code")

    assert row.evidence.value == "measured"
    assert "live session" in row.note
    assert ".env" in row.note


def test_three_rows_are_now_measured() -> None:
    # With one measured row the lattice is an assertion; with three it is a
    # comparison. claude-code is the row carrying the lossless control case.
    from toolseal.core.translate.lattice import PROFILES

    measured = {key for key, row in PROFILES.items() if row.evidence.value == "measured"}

    assert measured == {"langchain", "crewai", "claude-code"}


# --- injection and revert --------------------------------------------------


def files(*pairs: tuple[str, str]) -> tuple[RenderedFile, ...]:
    return tuple(RenderedFile(PurePosixPath(name), body) for name, body in pairs)


def test_injection_records_created_versus_modified(tmp_path: Path) -> None:
    (tmp_path / "CLAUDE.md").write_text("mine\n", encoding="utf-8")

    injection = inject(tmp_path, files(("CLAUDE.md", "new\n"), ("a/new.txt", "x\n")), label="t")

    by_path = {item.path: item for item in injection.files}
    assert not by_path["CLAUDE.md"].created
    assert by_path["CLAUDE.md"].backup == "mine\n"
    assert by_path["a/new.txt"].created
    assert by_path["a/new.txt"].backup is None


def test_revert_restores_prior_content_exactly(tmp_path: Path) -> None:
    original = "# mine\n\nnotes\n"
    (tmp_path / "CLAUDE.md").write_text(original, encoding="utf-8")
    inject(tmp_path, files(("CLAUDE.md", "replaced\n")), label="t")

    revert(tmp_path)

    assert (tmp_path / "CLAUDE.md").read_text(encoding="utf-8") == original


def test_revert_deletes_what_it_created(tmp_path: Path) -> None:
    inject(tmp_path, files((".claude/settings.json", "{}\n")), label="t")

    revert(tmp_path)

    assert not (tmp_path / ".claude" / "settings.json").exists()
    # An emptied directory goes too, but only if nothing else is in it.
    assert not (tmp_path / ".claude").exists()


def test_revert_leaves_a_directory_that_still_has_other_files(tmp_path: Path) -> None:
    inject(tmp_path, files((".claude/settings.json", "{}\n")), label="t")
    (tmp_path / ".claude" / "mine.json").write_text("{}\n", encoding="utf-8")

    revert(tmp_path)

    assert (tmp_path / ".claude").is_dir()
    assert (tmp_path / ".claude" / "mine.json").exists()


def test_revert_refuses_when_a_managed_file_was_edited(tmp_path: Path) -> None:
    # The guarantee that makes injection acceptable: a later edit is never
    # discarded without a second, explicit decision.
    inject(tmp_path, files(("CLAUDE.md", "written\n")), label="t")
    (tmp_path / "CLAUDE.md").write_text("written\n\nmy own addition\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="have changed since"):
        revert(tmp_path)

    assert "my own addition" in (tmp_path / "CLAUDE.md").read_text(encoding="utf-8")


def test_force_reverts_over_an_edit(tmp_path: Path) -> None:
    (tmp_path / "CLAUDE.md").write_text("original\n", encoding="utf-8")
    inject(tmp_path, files(("CLAUDE.md", "written\n")), label="t")
    (tmp_path / "CLAUDE.md").write_text("edited\n", encoding="utf-8")

    revert(tmp_path, force=True)

    assert (tmp_path / "CLAUDE.md").read_text(encoding="utf-8") == "original\n"


def test_plan_reports_edits_without_touching_anything(tmp_path: Path) -> None:
    inject(tmp_path, files(("CLAUDE.md", "written\n")), label="t")
    (tmp_path / "CLAUDE.md").write_text("edited\n", encoding="utf-8")

    plan = plan_revert(tmp_path, load(tmp_path) or pytest.fail("no manifest"))

    assert not plan.is_safe
    assert "CLAUDE.md" in plan.modified_since
    assert (tmp_path / "CLAUDE.md").read_text(encoding="utf-8") == "edited\n"


def test_a_deleted_managed_file_is_not_an_error(tmp_path: Path) -> None:
    inject(tmp_path, files(("gone.txt", "x\n")), label="t")
    (tmp_path / "gone.txt").unlink()

    plan = revert(tmp_path)

    assert "gone.txt" in plan.missing


def test_injection_cannot_escape_the_project(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="outside the project"):
        inject(tmp_path, files(("../escaped.txt", "x\n")), label="t")


def test_manifest_is_removed_after_a_full_revert(tmp_path: Path) -> None:
    inject(tmp_path, files(("a.txt", "x\n")), label="t")

    revert(tmp_path)

    assert load(tmp_path) is None


# --- the commands ----------------------------------------------------------


def test_add_then_revert_round_trip(tmp_path: Path) -> None:
    (tmp_path / "CLAUDE.md").write_text("# mine\n", encoding="utf-8")

    added = runner.invoke(app, ["add", "framework", "claude-code", "--directory", str(tmp_path)])
    assert added.exit_code == ExitCode.OK, added.output

    reverted = runner.invoke(app, ["revert", "--directory", str(tmp_path)])
    assert reverted.exit_code == ExitCode.OK, reverted.output
    assert (tmp_path / "CLAUDE.md").read_text(encoding="utf-8") == "# mine\n"


def test_add_refuses_a_framework_that_creates_projects(tmp_path: Path) -> None:
    result = runner.invoke(app, ["add", "framework", "langgraph", "--directory", str(tmp_path)])

    assert result.exit_code == ExitCode.USAGE
    assert "toolseal init" in result.output


def test_revert_with_nothing_to_undo_is_a_usage_error(tmp_path: Path) -> None:
    result = runner.invoke(app, ["revert", "--directory", str(tmp_path)])

    assert result.exit_code == ExitCode.USAGE


def test_dry_run_undoes_nothing(tmp_path: Path) -> None:
    runner.invoke(app, ["add", "framework", "claude-code", "--directory", str(tmp_path)])

    result = runner.invoke(app, ["revert", "--directory", str(tmp_path), "--dry-run"])

    assert result.exit_code == ExitCode.OK
    assert (tmp_path / ".claude" / "settings.json").exists()


# --- Gemini ----------------------------------------------------------------


def test_gemini_is_registered_and_needs_a_credential() -> None:
    provider = GeminiProvider()

    assert provider.credential_env_var == "GEMINI_API_KEY"
    assert provider.default_base_url.startswith("https://")
    assert all("==" in spec for spec in provider.packages())
