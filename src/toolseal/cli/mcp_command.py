"""`toolseal add mcp` - wire an MCP server in, after verifying its name.

This is where check `C3` stops being a unit test. Adding a server means
resolving a name someone typed - or a model suggested - against the registries
that would actually serve it, and refusing a name that resolves nowhere.

The refusal is the point. A name that does not exist today is a name an attacker
can register tomorrow, and the install path is the last moment anyone looks.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from toolseal.core.adapters.mcp_targets import target_for
from toolseal.core.injection import inject
from toolseal.core.manifest import Manifest
from toolseal.core.model import MCPServerBinding, Transport
from toolseal.core.registry.resolve import Channel, Resolution, resolve
from toolseal.errors import ExitCode, ResolutionError, UsageError


def add_mcp(
    name: Annotated[str, typer.Argument(help="Package or server name to add.")],
    command: Annotated[
        str | None, typer.Option("--command", help="Launch command. Defaults to npx.")
    ] = None,
    url: Annotated[
        str | None, typer.Option("--url", help="Remote endpoint, instead of a command.")
    ] = None,
    framework: Annotated[
        str | None,
        typer.Option(
            "--framework",
            "-f",
            help="Which config file to write. Read from the manifest if omitted.",
        ),
    ] = None,
    directory: Annotated[
        Path | None, typer.Option("--directory", "-d", help="Project to configure.")
    ] = None,
    skip_verify: Annotated[
        bool,
        typer.Option(
            "--skip-verify",
            help="Add without checking the name resolves. Recorded as a finding.",
        ),
    ] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Add an MCP server, refusing a name that resolves nowhere."""
    root = (directory or Path.cwd()).resolve()

    manifest = Manifest.load(root)
    framework_id = framework or (manifest.framework_id if manifest else "generic")

    verified = False
    detail = "not checked"
    if not skip_verify:
        try:
            result = resolve(name, channels=(Channel.NPM, Channel.PYPI))
        except ResolutionError as exc:
            # An unreachable registry is not evidence of absence, so this stops
            # rather than guessing either way.
            raise UsageError(str(exc)) from None

        detail = result.detail
        if result.resolution is Resolution.PHANTOM:
            message = (
                f"{name!r} resolves in no registry checked. A name that does not exist "
                "today is one an attacker can register tomorrow. Re-run with "
                "--skip-verify if you are certain."
            )
            raise UsageError(message)
        if result.resolution is Resolution.LOOKALIKE:
            message = (
                f"{name!r} looks like a near-miss of {result.resembles!r}. "
                "Check the spelling, or re-run with --skip-verify."
            )
            raise UsageError(message)
        verified = True

    binding = MCPServerBinding(
        name=name.split("/")[-1],
        transport=Transport.STREAMABLE_HTTP if url else Transport.STDIO,
        command=None if url else (command or "npx"),
        args=() if url else ("-y", name),
        url=url,
        name_verified=verified,
    )

    target = target_for(framework_id)
    files = target.write(root, (binding,))
    injection = inject(root, files, label=f"mcp:{name}")

    if as_json:
        typer.echo(
            json.dumps(
                {
                    "action": "added",
                    "server": binding.name,
                    "verified": verified,
                    "detail": detail,
                    "config": str(target.config_path),
                    "files": [item.path for item in injection.files],
                },
                indent=2,
                sort_keys=True,
            )
        )
        raise typer.Exit(ExitCode.OK if verified else ExitCode.FINDINGS)

    mark = "verified" if verified else "UNVERIFIED"
    colour = typer.colors.GREEN if verified else typer.colors.YELLOW
    typer.secho(f"Added {binding.name} ({mark}) to {target.config_path}", fg=colour)
    typer.echo(f"  {detail}")
    typer.echo("  Undo with: toolseal revert")
    raise typer.Exit(ExitCode.OK if verified else ExitCode.FINDINGS)
