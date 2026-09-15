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
from toolseal.core.credentials import KeyringStore
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


# --- the guided flow -------------------------------------------------------
#
# The wizard's own `--interactive`/`-i` (branch: interactive-init-wizard) and
# the credential prompt's original standalone `--interactive` (branch:
# init-api-key-credential) collided on the same flag name during the rebase
# of the latter onto the former. Resolved by folding credential collection
# into the guided flow as its last question (`wizard._ask_credential`) rather
# than keeping two different meanings for one flag - see wizard.py. Every
# wizard run below therefore answers one extra question whenever the chosen
# provider needs a credential; a trailing blank line means "skip it".


def test_interactive_scaffolds_from_the_answers(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["init", "--interactive", "--directory", str(tmp_path / "demo")],
        input="demo\n1\n1\n1\n\n",
    )
    assert result.exit_code == ExitCode.OK, result.output
    assert (tmp_path / "demo" / MANIFEST_NAME).exists()


def test_interactive_prints_the_equivalent_command(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["init", "--interactive", "--directory", str(tmp_path / "demo")],
        input="demo\n1\n1\n1\n\n",
    )
    assert "toolseal init demo --provider" in result.output


def test_a_missing_name_without_a_tty_is_a_usage_error(tmp_path: Path) -> None:
    result = runner.invoke(app, ["init", "--directory", str(tmp_path / "demo")])
    assert result.exit_code == ExitCode.USAGE
    assert "project name is required" in result.output


def test_json_and_interactive_cannot_share_stdout(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["init", "--interactive", "--json", "--directory", str(tmp_path / "demo")]
    )
    assert result.exit_code == ExitCode.USAGE


def test_a_named_init_is_still_non_interactive(tmp_path: Path) -> None:
    result = runner.invoke(app, ["init", "demo", "--directory", str(tmp_path / "demo")])
    assert result.exit_code == ExitCode.OK, result.output
    manifest = Manifest.load(tmp_path / "demo")
    assert manifest is not None
    assert manifest.provider_id == "ollama"
    assert manifest.framework_id == "langgraph"


def test_a_missing_name_on_a_tty_runs_the_wizard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The auto-trigger branch, which neither `CliRunner` nor a pipe reaches.

    `is_tty` is the only thing separating "prompt me" from "you forgot the
    argument", and every other test in this file runs without a terminal - so
    without this one, the condition that decides between a guided flow and a
    usage error is never executed.
    """
    monkeypatch.setattr("toolseal.cli.init_command.is_tty", lambda: True)
    result = runner.invoke(
        app,
        ["init", "--directory", str(tmp_path / "demo")],
        input="demo\n1\n1\n1\n\n",
    )
    assert result.exit_code == ExitCode.OK, result.output
    assert (tmp_path / "demo" / MANIFEST_NAME).exists()


# --- credential provisioning (check A1) -------------------------------------


def test_credential_free_provider_reports_nothing(tmp_path: Path) -> None:
    # Ollama needs no credential; nothing about one should appear.
    result = runner.invoke(app, ["init", "demo", "--directory", str(tmp_path / "demo")])

    assert result.exit_code == ExitCode.OK
    assert "Credential:" not in result.output


def test_api_key_flag_stores_into_the_keychain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stored: dict[str, str] = {}
    monkeypatch.setattr(
        KeyringStore,
        "set",
        lambda self, account, value: stored.__setitem__(account, value),
    )

    result = runner.invoke(
        app,
        [
            "init",
            "demo",
            "--provider",
            "openai",
            "--directory",
            str(tmp_path / "demo"),
            "--api-key",
            "sk-test-value",
        ],
    )

    assert result.exit_code == ExitCode.OK
    assert stored == {"openai": "sk-test-value"}
    assert "stored in the OS keychain" in result.output


def test_no_api_key_and_not_interactive_never_prompts(tmp_path: Path) -> None:
    # Regression: `isatty()` was tried as the gate for an automatic prompt and
    # dropped - it can report a terminal present with nobody there to answer,
    # which hung `init` inside an unattended harness. Without --interactive,
    # a credentialed provider must be handled without ever blocking on input.
    result = runner.invoke(
        app,
        ["init", "demo", "--provider", "openai", "--directory", str(tmp_path / "demo")],
        input="",
    )

    assert result.exit_code == ExitCode.OK
    assert "not provided" in result.output
    assert "--interactive" in result.output


def test_interactive_flag_prompts_and_stores(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # --provider and --framework are both given, so the only question the
    # wizard has left to ask is the regime (blank -> none) and then the
    # credential - it does not need to re-derive provider/framework here.
    stored: dict[str, str] = {}
    monkeypatch.setattr(
        KeyringStore,
        "set",
        lambda self, account, value: stored.__setitem__(account, value),
    )

    result = runner.invoke(
        app,
        [
            "init",
            "demo",
            "--provider",
            "openai",
            "--framework",
            "langgraph",
            "--directory",
            str(tmp_path / "demo"),
            "--interactive",
        ],
        input="\nsk-typed-at-the-prompt\n",
    )

    assert result.exit_code == ExitCode.OK, result.output
    assert stored == {"openai": "sk-typed-at-the-prompt"}


def test_interactive_flag_blank_answer_skips_storage(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "init",
            "demo",
            "--provider",
            "openai",
            "--framework",
            "langgraph",
            "--directory",
            str(tmp_path / "demo"),
            "--interactive",
        ],
        input="\n\n",
    )

    assert result.exit_code == ExitCode.OK, result.output
    assert "not provided" in result.output


def test_a_keychain_that_refuses_storage_does_not_fail_init(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _refuse(self: object, account: str, value: str) -> None:
        raise ConfigError("no OS keychain is available on this machine")

    monkeypatch.setattr(KeyringStore, "set", _refuse)

    result = runner.invoke(
        app,
        [
            "init",
            "demo",
            "--provider",
            "openai",
            "--directory",
            str(tmp_path / "demo"),
            "--api-key",
            "sk-test-value",
        ],
    )

    assert result.exit_code == ExitCode.OK
    assert (tmp_path / "demo" / "agent.py").exists()
    assert "not stored" in result.output
