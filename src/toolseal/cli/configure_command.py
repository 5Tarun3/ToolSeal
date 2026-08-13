"""`toolseal add framework` and `toolseal revert`.

Configuring a project that already exists is a different act from creating one,
and it gets a different command. `init` owns the directory it makes; `add`
writes into someone else's, which is why everything it does is recorded and
undoable.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from toolseal.cli import mcp_command
from toolseal.cli.errors import command as error_boundary
from toolseal.core.adapters import ScaffoldSpec, framework_registry, provider_registry
from toolseal.core.injection import inject, load, plan_revert
from toolseal.core.injection import revert as revert_injection
from toolseal.errors import ExitCode, UsageError

add_app = typer.Typer(name="add", help="Configure an existing project.", no_args_is_help=True)


def add_framework(
    framework: Annotated[str, typer.Argument(help="Framework to configure for.")],
    provider: Annotated[
        str, typer.Option("--provider", "-p", help="Provider to reference.")
    ] = "ollama",
    directory: Annotated[
        Path | None, typer.Option("--directory", "-d", help="Project to configure.")
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Write a framework's configuration into an existing project."""
    root = (directory or Path.cwd()).resolve()

    adapter = framework_registry.get(framework)
    provider_adapter = provider_registry.get(provider)

    if not getattr(adapter, "configures_in_place", False):
        message = (
            f"{framework!r} creates a project rather than configuring one. "
            f"Use `toolseal init <name> --framework {framework}` instead."
        )
        raise UsageError(message)

    files = adapter.render(
        ScaffoldSpec(
            project_name=root.name,
            provider_id=provider,
            framework_id=framework,
            workspace_root=root,
        ),
        provider_adapter,
    )
    injection = inject(root, files, label=f"{framework}@{provider}")

    if as_json:
        typer.echo(
            json.dumps(
                {
                    "action": "configured",
                    "root": str(root),
                    "framework": framework,
                    "files": [item.path for item in injection.files],
                    "created": [f.path for f in injection.files if f.created],
                    "backed_up": [f.path for f in injection.files if not f.created],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return

    typer.secho(f"Configured {root} for {adapter.display_name}", fg=typer.colors.GREEN)
    for item in injection.files:
        marker = "+" if item.created else "~"
        typer.echo(f"  {marker} {item.path}")
    typer.echo("\n  ~ means the previous content was backed up.")
    typer.echo("  Undo with: toolseal revert")


def revert(
    directory: Annotated[
        Path | None, typer.Option("--directory", "-d", help="Project to revert.")
    ] = None,
    force: Annotated[
        bool,
        typer.Option("--force", help="Revert even where a managed file has been edited."),
    ] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show what would be undone, and undo nothing.")
    ] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Undo what toolseal wrote into this project."""
    root = (directory or Path.cwd()).resolve()

    injection = load(root)
    if injection is None:
        message = f"nothing to revert: toolseal has not written to {root}"
        raise UsageError(message)

    if dry_run:
        plan = plan_revert(root, injection)
        if as_json:
            typer.echo(
                json.dumps(
                    {
                        "action": "dry-run",
                        "delete": list(plan.to_delete),
                        "restore": list(plan.to_restore),
                        "modified_since": list(plan.modified_since),
                        "missing": list(plan.missing),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            for path in plan.to_delete:
                typer.echo(f"  delete   {path}")
            for path in plan.to_restore:
                typer.echo(f"  restore  {path}")
            for path in plan.missing:
                typer.echo(f"  gone     {path}")
            for path in plan.modified_since:
                typer.secho(f"  edited   {path} (blocks revert)", fg=typer.colors.YELLOW)
        raise typer.Exit(ExitCode.OK if plan.is_safe else ExitCode.FINDINGS)

    plan = revert_injection(root, force=force)

    if as_json:
        typer.echo(
            json.dumps(
                {
                    "action": "reverted",
                    "deleted": list(plan.to_delete),
                    "restored": list(plan.to_restore),
                    "forced_over": list(plan.modified_since) if force else [],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return

    typer.secho(f"Reverted {root}", fg=typer.colors.GREEN)
    for path in plan.to_delete:
        typer.echo(f"  deleted   {path}")
    for path in plan.to_restore:
        typer.echo(f"  restored  {path}")
    if force and plan.modified_since:
        typer.secho(
            f"  discarded edits in: {', '.join(plan.modified_since)}",
            fg=typer.colors.YELLOW,
        )


# Registered after definition so the error boundary wraps it. A subcommand
# declared with a bare decorator bypasses it and leaks a raw exception with the
# wrong exit code - the same defect the top-level commands had at P10.
add_app.command("framework")(error_boundary(add_framework))
add_app.command("mcp")(error_boundary(mcp_command.add_mcp))
