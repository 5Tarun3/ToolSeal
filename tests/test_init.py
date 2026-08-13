"""`toolseal init` end to end, and the safety properties of writing to disk.

The scaffolder is the only component that mutates a user's filesystem, so its
refusals matter more than its successes: not clobbering work, not escaping the
target directory, and not leaving a half-written tree behind.
"""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath

import pytest
from typer.testing import CliRunner

from toolseal.cli import app
from toolseal.core.adapters import RenderedFile, ScaffoldSpec
from toolseal.core.manifest import MANIFEST_NAME, Manifest
from toolseal.core.scaffold import ScaffoldPlan, apply_plan, build_plan
from toolseal.errors import ConfigError, ExitCode

runner = CliRunner()


def spec_for(tmp_path: Path) -> ScaffoldSpec:
    return ScaffoldSpec(
        project_name="demo",
        provider_id="ollama",
        framework_id="langgraph",
        workspace_root=tmp_path / "demo",
    )


# --- planning --------------------------------------------------------------


def test_plan_writes_nothing(tmp_path: Path) -> None:
    build_plan(spec_for(tmp_path))
    assert not (tmp_path / "demo").exists()


def test_plan_includes_hygiene_files(tmp_path: Path) -> None:
    paths = {str(item.path) for item in build_plan(spec_for(tmp_path)).files}

    assert ".gitignore" in paths
    assert ".pre-commit-config.yaml" in paths
    assert MANIFEST_NAME in paths


def test_plan_is_clean_on_an_empty_directory(tmp_path: Path) -> None:
    assert build_plan(spec_for(tmp_path)).is_applicable


def test_existing_file_becomes_a_conflict(tmp_path: Path) -> None:
    root = tmp_path / "demo"
    root.mkdir()
    (root / "agent.py").write_text("# my work\n", encoding="utf-8")

    plan = build_plan(spec_for(tmp_path))

    assert not plan.is_applicable
    assert PurePosixPath("agent.py") in plan.conflicts


def test_force_clears_conflicts(tmp_path: Path) -> None:
    root = tmp_path / "demo"
    root.mkdir()
    (root / "agent.py").write_text("# my work\n", encoding="utf-8")

    assert build_plan(spec_for(tmp_path), force=True).is_applicable


# --- applying --------------------------------------------------------------


def test_apply_refuses_rather_than_partially_writing(tmp_path: Path) -> None:
    root = tmp_path / "demo"
    root.mkdir()
    (root / "agent.py").write_text("# my work\n", encoding="utf-8")

    plan = build_plan(spec_for(tmp_path))
    with pytest.raises(ConfigError, match="--force"):
        apply_plan(plan)

    # Nothing else was written on the way to refusing.
    assert (root / "agent.py").read_text(encoding="utf-8") == "# my work\n"
    assert not (root / "tools.py").exists()


def test_apply_writes_every_planned_file(tmp_path: Path) -> None:
    plan = build_plan(spec_for(tmp_path))
    written = apply_plan(plan)

    assert len(written) == len(plan.files)
    for path in written:
        assert path.is_file() or path.name == ".gitkeep"


@pytest.mark.parametrize("escape", ["../outside.txt", "/etc/passwd", "a/../../outside.txt"])
def test_paths_cannot_escape_the_project(tmp_path: Path, escape: str) -> None:
    # Rendered paths are relative by construction, but a registry-supplied
    # descriptor is exactly the sort of thing that later makes them hostile.
    plan = ScaffoldPlan(
        root=tmp_path / "demo",
        files=(RenderedFile(PurePosixPath(escape), "pwned"),),
        conflicts=(),
    )

    with pytest.raises(ConfigError, match="outside the project"):
        apply_plan(plan)


def test_gitignore_merge_preserves_existing_rules(tmp_path: Path) -> None:
    root = tmp_path / "demo"
    root.mkdir()
    (root / ".gitignore").write_text("# mine\nbuild/\n", encoding="utf-8")

    apply_plan(build_plan(spec_for(tmp_path), force=True))

    content = (root / ".gitignore").read_text(encoding="utf-8")
    assert "build/" in content
    assert ".env" in content.splitlines()


def test_manifest_records_the_stack(tmp_path: Path) -> None:
    apply_plan(build_plan(spec_for(tmp_path)))

    manifest = Manifest.load(tmp_path / "demo")

    assert manifest is not None
    assert manifest.provider_id == "ollama"
    assert manifest.framework_id == "langgraph"
    assert manifest.approval_required_for_destructive


# --- the command -----------------------------------------------------------


def test_init_creates_a_runnable_looking_project(tmp_path: Path) -> None:
    result = runner.invoke(app, ["init", "demo", "--directory", str(tmp_path / "demo")])

    assert result.exit_code == ExitCode.OK, result.output
    assert (tmp_path / "demo" / "agent.py").is_file()
    assert (tmp_path / "demo" / MANIFEST_NAME).is_file()


def test_init_json_output_lists_what_it_wrote(tmp_path: Path) -> None:
    result = runner.invoke(app, ["init", "demo", "--directory", str(tmp_path / "demo"), "--json"])

    payload = json.loads(result.stdout)
    assert payload["action"] == "created"
    assert "agent.py" in payload["files"]


def test_dry_run_writes_nothing(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["init", "demo", "--directory", str(tmp_path / "demo"), "--dry-run"]
    )

    assert result.exit_code == ExitCode.OK
    assert not (tmp_path / "demo").exists()


def test_dry_run_reports_findings_exit_code_on_conflict(tmp_path: Path) -> None:
    root = tmp_path / "demo"
    root.mkdir()
    (root / "agent.py").write_text("# mine\n", encoding="utf-8")

    result = runner.invoke(app, ["init", "demo", "--directory", str(root), "--dry-run"])

    assert result.exit_code == ExitCode.FINDINGS


def test_unknown_provider_lists_the_known_ones(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["init", "demo", "--provider", "cohere", "--directory", str(tmp_path / "demo")]
    )

    assert result.exit_code == ExitCode.USAGE
    assert "ollama" in result.output


@pytest.mark.parametrize("name", ["", "   ", ".", "..", "a/b", "a\\b"])
def test_unsafe_project_names_are_refused(tmp_path: Path, name: str) -> None:
    result = runner.invoke(app, ["init", name, "--directory", str(tmp_path / "demo")])

    assert result.exit_code == ExitCode.USAGE
    assert not (tmp_path / "demo" / "agent.py").exists()


def test_second_init_refuses_without_force(tmp_path: Path) -> None:
    target = str(tmp_path / "demo")
    assert runner.invoke(app, ["init", "demo", "--directory", target]).exit_code == ExitCode.OK

    second = runner.invoke(app, ["init", "demo", "--directory", target])

    assert second.exit_code != ExitCode.OK
    assert "--force" in second.output
