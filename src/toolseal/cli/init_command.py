"""`toolseal init` - scaffold a project whose defaults already audit clean."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.text import Text

from toolseal.cli._ui import accent_text, choices_help, console, print_line, print_text
from toolseal.core.adapters import ScaffoldSpec, framework_registry, provider_registry
from toolseal.core.policy.profile import load_profile, profile_ids
from toolseal.core.scaffold import apply_plan, build_plan
from toolseal.errors import ConfigError, ExitCode, UsageError

DEFAULT_PROVIDER = "ollama"
DEFAULT_FRAMEWORK = "langgraph"


def _validate_project_name(name: str) -> str:
    """Reject a name that would produce an unusable or unsafe directory."""
    cleaned = name.strip()
    if not cleaned:
        message = "project name cannot be empty"
        raise UsageError(message)
    if cleaned in {".", ".."} or "/" in cleaned or "\\" in cleaned:
        message = f"project name must be a single directory name, not a path: {name!r}"
        raise UsageError(message)
    return cleaned


def _resolve_profile_or_usage_error(profile_id: str) -> None:
    """Validate a user-typed `--profile` id, translating the failure mode.

    `load_profile` raises `ConfigError` for both an unknown id (the caller's
    typo) and a malformed *shipped* profile file (a packaging fault). Only
    the former is this function's job to relabel - it is only ever called
    with a value the user typed at the CLI, so here every `ConfigError` is a
    usage mistake, matching the same boundary-only translation
    `policy_command._explain_control` already applies to a mistyped
    standard name.
    """
    try:
        load_profile(profile_id)
    except ConfigError as exc:
        raise UsageError(str(exc)) from None


def init(
    name: Annotated[str, typer.Argument(help="Project name; also the directory created.")],
    provider: Annotated[
        str,
        typer.Option(
            "--provider",
            "-p",
            help=choices_help("LLM provider to wire in.", provider_registry.names()),
        ),
    ] = DEFAULT_PROVIDER,
    framework: Annotated[
        str,
        typer.Option(
            "--framework",
            "-f",
            help=choices_help("Agent framework to scaffold.", framework_registry.names()),
        ),
    ] = DEFAULT_FRAMEWORK,
    model: Annotated[
        str | None, typer.Option("--model", "-m", help="Override the provider's default model.")
    ] = None,
    base_url: Annotated[
        str | None,
        typer.Option("--base-url", help="Override the provider endpoint (reported by check D3)."),
    ] = None,
    directory: Annotated[
        Path | None,
        typer.Option("--directory", "-d", help="Where to create it. Defaults to ./<name>."),
    ] = None,
    profile: Annotated[
        str | None,
        typer.Option(
            "--profile",
            help=choices_help("Scaffold under a regulatory regime from the start.", profile_ids()),
        ),
    ] = None,
    force: Annotated[bool, typer.Option("--force", help="Overwrite existing files.")] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show what would be written, and write nothing.")
    ] = False,
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable output on stdout.")
    ] = False,
) -> None:
    """Create a new agent project with secure defaults."""
    project_name = _validate_project_name(name)
    root = (directory or Path.cwd() / project_name).resolve()

    # Resolved before rendering so an unknown id fails with the list of valid
    # ones rather than part-way through writing a tree.
    provider_registry.get(provider)
    framework_registry.get(framework)
    if profile is not None:
        _resolve_profile_or_usage_error(profile)

    spec = ScaffoldSpec(
        project_name=project_name,
        provider_id=provider,
        framework_id=framework,
        workspace_root=root,
        model=model,
        base_url=base_url,
        profile_id=profile,
    )

    plan = build_plan(spec, force=force)
    paths = [str(item.path) for item in plan.files]

    if dry_run:
        _emit(
            as_json,
            {
                "action": "dry-run",
                "root": str(root),
                "files": paths,
                "conflicts": [str(path) for path in plan.conflicts],
            },
            lambda: _print_dry_run(root, plan.files, plan.conflicts),
        )
        raise typer.Exit(ExitCode.OK if plan.is_applicable else ExitCode.FINDINGS)

    apply_plan(plan)

    _emit(
        as_json,
        {"action": "created", "root": str(root), "files": paths},
        lambda: _print_created(root, project_name, paths),
    )


def _emit(as_json: bool, payload: dict[str, Any], human: Any) -> None:
    if as_json:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        human()


def _print_dry_run(root: Path, files: Any, conflicts: Any) -> None:
    header = Text("Would create ")
    header.append_text(accent_text(str(root)))
    print_text(console, header)
    for item in files:
        conflict = item.path in conflicts
        marker_style = "verdict.warn" if conflict else "verdict.good"
        marker = Text("!" if conflict else "+", style=marker_style)
        line = Text("  ")
        line.append_text(marker)
        line.append(f" {item.path}", style="muted")
        print_text(console, line)
    if conflicts:
        console.print()
        print_line(
            console,
            f"{len(conflicts)} file(s) already exist. Re-run with --force to replace them.",
            style="verdict.warn",
        )


def _print_created(root: Path, project_name: str, paths: list[str]) -> None:
    line = Text("Created ", style="verdict.good")
    line.append_text(accent_text(project_name))
    line.append(" in ", style="verdict.good")
    line.append_text(accent_text(str(root)))
    print_text(console, line)
    for path in sorted(paths):
        print_line(console, f"  {path}", style="muted")
    console.print()
    print_line(console, "Next:", style="heading")
    for command_example in ("cd " + root.name, "pip install -r requirements.txt", "toolseal audit"):
        line = Text("  ")
        line.append_text(accent_text(command_example))
        print_text(console, line)
