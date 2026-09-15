"""`toolseal init` - scaffold a project whose defaults already audit clean."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.text import Text

from toolseal.cli._ui import (
    accent_text,
    choices_help,
    console,
    is_tty,
    print_line,
    print_text,
)
from toolseal.cli.wizard import equivalent_command, run_wizard
from toolseal.core.adapters import ScaffoldSpec, framework_registry, provider_registry
from toolseal.core.credentials import KeyringStore
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
    name: Annotated[
        str | None,
        typer.Argument(help="Project name; also the directory created. Omit to be prompted."),
    ] = None,
    provider: Annotated[
        str | None,
        typer.Option(
            "--provider",
            "-p",
            help=choices_help("LLM provider to wire in.", provider_registry.names()),
        ),
    ] = None,
    framework: Annotated[
        str | None,
        typer.Option(
            "--framework",
            "-f",
            help=choices_help("Agent framework to scaffold.", framework_registry.names()),
        ),
    ] = None,
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
    interactive: Annotated[
        bool,
        typer.Option(
            "--interactive",
            "-i",
            help=(
                "Choose provider, framework, regime and credential from a guided "
                "prompt. Off by default even when a name is given: `isatty()` is not "
                "a reliable signal that a human is actually present to answer - some "
                "CI runners and agent harnesses attach a pty to an otherwise "
                "unattended process, and prompting there would hang the run rather "
                "than skip it."
            ),
        ),
    ] = False,
    force: Annotated[bool, typer.Option("--force", help="Overwrite existing files.")] = False,
    api_key: Annotated[
        str | None,
        typer.Option(
            "--api-key",
            help=(
                "Provider credential to store in the OS keychain (check A1) without "
                "the guided prompt - a value here can land in shell history, so "
                "prefer --interactive when running by hand."
            ),
        ),
    ] = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show what would be written, and write nothing.")
    ] = False,
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable output on stdout.")
    ] = False,
) -> None:
    """Create a new agent project with secure defaults."""
    # A missing name means "prompt me", but only where prompting can work. Off
    # a TTY it is a forgotten argument, and a CI job that hangs on a prompt
    # nobody can see is strictly worse than one that fails on the next line.
    wants_wizard = interactive or (name is None and is_tty())

    if wants_wizard and as_json:
        message = (
            "--json cannot be combined with --interactive; machine output and prompts share stdout"
        )
        raise UsageError(message)

    chosen = None
    if wants_wizard:
        # Validated before the flow rather than after, so an unknown value
        # passed alongside -i fails at the flag that carried it instead of
        # part-way through a sequence of questions.
        if provider is not None:
            provider_registry.get(provider)
        if framework is not None:
            framework_registry.get(framework)
        if profile is not None:
            _resolve_profile_or_usage_error(profile)

        chosen = run_wizard(
            name=None if name is None else _validate_project_name(name),
            provider=provider,
            framework=framework,
            profile=profile,
        )
        project_name = chosen.name
        provider = chosen.provider
        framework = chosen.framework
        profile = chosen.profile
        if api_key is None:
            api_key = chosen.api_key
    elif name is None:
        message = (
            "a project name is required when not running interactively; "
            "try `toolseal init <name>` or `toolseal init -i`"
        )
        raise UsageError(message)
    else:
        project_name = _validate_project_name(name)
        provider = provider if provider is not None else DEFAULT_PROVIDER
        framework = framework if framework is not None else DEFAULT_FRAMEWORK

    root = (directory or Path.cwd() / project_name).resolve()

    # Resolved before rendering so an unknown id fails with the list of valid
    # ones rather than part-way through writing a tree.
    provider_adapter = provider_registry.get(provider)
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

    if chosen is not None:
        console.print()
        replay = Text("  Next time: ")
        replay.append_text(accent_text(equivalent_command(chosen)))
        print_text(console, replay)

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

    credential_status = _provision_credential(provider_adapter, api_key)

    apply_plan(plan)

    payload: dict[str, Any] = {"action": "created", "root": str(root), "files": paths}
    if credential_status is not None:
        payload["credential"] = credential_status
    _emit(
        as_json,
        payload,
        lambda: _print_created(root, project_name, paths, credential_status),
    )


def _provision_credential(provider: Any, api_key: str | None) -> str | None:
    """Store a provider credential in the OS keychain (check A1's remediation).

    Runs before the scaffold is written but never blocks it: a provider that
    needs no credential (e.g. a local Ollama) reports nothing at all, and a
    keychain that refuses the write is reported rather than raised, so a
    project still gets created on a machine with no OS keychain - the caller
    just has to provide the credential another way.

    Never prompts itself: prompting only happens inside the guided flow
    (`wizard._ask_credential`, reached through `--interactive`), which is an
    explicit opt-in. `isatty()` was tried as an automatic gate here and
    dropped - it reported a terminal present, and `init` hung waiting for a
    human, inside a non-interactive harness that had attached a pty to an
    otherwise unattended process. A flag the caller must opt into cannot make
    that mistake regardless of what the platform reports.
    """
    env_var = provider.credential_env_var
    if env_var is None:
        return None

    if api_key is None:
        return "not provided - pass --api-key, or --interactive to be prompted"

    try:
        KeyringStore().set(provider.id, api_key)
    except ConfigError as exc:
        return f"not stored - {exc}"
    return "stored in the OS keychain"


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


def _print_created(
    root: Path, project_name: str, paths: list[str], credential_status: str | None
) -> None:
    line = Text("Created ", style="verdict.good")
    line.append_text(accent_text(project_name))
    line.append(" in ", style="verdict.good")
    line.append_text(accent_text(str(root)))
    print_text(console, line)
    for path in sorted(paths):
        print_line(console, f"  {path}", style="muted")
    if credential_status is not None:
        console.print()
        stored = credential_status == "stored in the OS keychain"
        style = "verdict.good" if stored else "verdict.warn"
        print_line(console, f"Credential: {credential_status}", style=style)
    console.print()
    print_line(console, "Next:", style="heading")
    for command_example in ("cd " + root.name, "pip install -r requirements.txt", "toolseal audit"):
        line = Text("  ")
        line.append_text(accent_text(command_example))
        print_text(console, line)
