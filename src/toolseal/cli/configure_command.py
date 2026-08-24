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
from rich.text import Text

from toolseal.cli import mcp_command
from toolseal.cli._ui import accent_text, console, print_line, print_text
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

    # Not every framework has a platform caveat to report - only claude-code
    # does today - so this is read off the adapter rather than assumed.
    warnings = adapter.scaffold_warnings() if hasattr(adapter, "scaffold_warnings") else ()

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
                    "warnings": list(warnings),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return

    line = Text("Configured ", style="verdict.good")
    line.append_text(accent_text(str(root)))
    line.append(" for ", style="verdict.good")
    line.append_text(accent_text(adapter.display_name))
    print_text(console, line)
    for item in injection.files:
        created = item.created
        marker = Text("+" if created else "~", style="verdict.good" if created else "muted")
        entry = Text("  ")
        entry.append_text(marker)
        entry.append(f" {item.path}", style="muted")
        print_text(console, entry)
    console.print()
    typer.echo("  ~ means the previous content was backed up.")
    undo = Text("  Undo with: ")
    undo.append_text(accent_text("toolseal revert"))
    print_text(console, undo)
    for message in warnings:
        console.print()
        print_line(console, f"  warning: {message}", style="verdict.warn")


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
                print_line(console, f"  delete   {path}", style="muted")
            for path in plan.to_restore:
                print_line(console, f"  restore  {path}", style="verdict.good")
            for path in plan.missing:
                print_line(console, f"  gone     {path}", style="verdict.warn")
            for path in plan.modified_since:
                print_line(console, f"  edited   {path} (blocks revert)", style="verdict.warn")
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

    line = Text("Reverted ", style="verdict.good")
    line.append_text(accent_text(str(root)))
    print_text(console, line)
    for path in plan.to_delete:
        print_line(console, f"  deleted   {path}", style="muted")
    for path in plan.to_restore:
        print_line(console, f"  restored  {path}", style="muted")
    if force and plan.modified_since:
        print_line(
            console,
            f"  discarded edits in: {', '.join(plan.modified_since)}",
            style="verdict.warn",
        )


# Registered after definition so the error boundary wraps it. A subcommand
# declared with a bare decorator bypasses it and leaks a raw exception with the
# wrong exit code - the same defect the top-level commands had at P10.
add_app.command("framework")(error_boundary(add_framework))
add_app.command("mcp")(error_boundary(mcp_command.add_mcp))
