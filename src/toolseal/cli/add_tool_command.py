"""`toolseal add tool` - lower a registry entry into a project.

This is the mechanism behind contribution C5 made runnable: everywhere else in
`add`, a name is wired into a config file. Here, a descriptor's declared
security properties are carried into a target framework, and whatever the
target cannot express is either replaced by a generated guard or reported as
unsupported - never silently dropped. `toolseal audit` then reads back what
happened through family G, the same way it reads back an MCP server through
`A5`/`B4`/`D1`/`D2`.

`add mcp` and `add tool` are complementary, not alternatives: `add mcp` wires a
server so a client can reach it, `add tool` produces the guarded binding that
sits between a target framework and one of that server's tools. A project may
want either, both, or neither.
"""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Annotated, Final

import typer
from rich.text import Text

from toolseal.cli._ui import accent_text, choices_help, console, print_line, print_text
from toolseal.cli.registry_command import default_index
from toolseal.core.adapters.base import RenderedFile
from toolseal.core.injection import inject
from toolseal.core.manifest import Manifest
from toolseal.core.registry.index import RegistryIndex
from toolseal.core.translate.lower import (
    MANIFEST_NAME,
    identifier,
    lower,
    read_manifest,
    write_manifest,
)
from toolseal.errors import ExitCode, UsageError

# Which lattice profile a framework's tool abstraction corresponds to - the
# vocabulary `plan_translation` reasons in is the abstraction's shape
# (`langchain`, `crewai`, `claude-code`), not the scaffold that produced it,
# and LangGraph is the one place those two names differ (`core/adapters/
# frameworks/langgraph.py` makes the same substitution for the same reason).
# "generic" means no scaffold at all - the config `add mcp` writes for it is a
# bare MCP server entry, so nothing sits between the tool and the protocol it
# already speaks; there is no lossy client library to translate through, which
# is exactly what mapping it to "mcp" (the lossless reference profile) says.
_LATTICE_TARGET_BY_FRAMEWORK: Final[dict[str, str]] = {
    "langgraph": "langchain",
    "crewai": "crewai",
    "claude-code": "claude-code",
    "generic": "mcp",
}


def _lattice_target(framework_id: str) -> str:
    try:
        return _LATTICE_TARGET_BY_FRAMEWORK[framework_id]
    except KeyError:
        known = ", ".join(sorted(_LATTICE_TARGET_BY_FRAMEWORK))
        message = f"no translation target known for framework {framework_id!r}; available: {known}"
        raise UsageError(message) from None


def add_tool(
    entry_id: Annotated[str, typer.Argument(help="Entry id, as printed by `registry search`.")],
    framework: Annotated[
        str | None,
        typer.Option(
            "--framework",
            "-f",
            help=choices_help(
                "Target to lower into. Read from the manifest if omitted.",
                _LATTICE_TARGET_BY_FRAMEWORK,
            ),
        ),
    ] = None,
    directory: Annotated[
        Path | None, typer.Option("--directory", "-d", help="Project to configure.")
    ] = None,
    index_path: Annotated[
        Path | None, typer.Option("--index", help="Index file to read the entry from.")
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Lower one registry entry into the project, compensating what is lost."""
    root = (directory or Path.cwd()).resolve()

    manifest = Manifest.load(root)
    framework_id = framework or (manifest.framework_id if manifest else "generic")
    target = _lattice_target(framework_id)

    index = RegistryIndex.read(index_path) if index_path is not None else default_index()
    entry = index.get(entry_id)
    if entry is None:
        message = f"no entry {entry_id!r} in the index; try `toolseal registry search`"
        raise UsageError(message)

    tool_policy = manifest.policy_for(entry.descriptor.name) if manifest else None
    lowering = lower(entry.descriptor, target, tool_policy=tool_policy)

    binding_path = PurePosixPath("tools") / f"{identifier(entry.descriptor.name)}.py"
    manifest_entries = (*read_manifest(root), lowering.manifest_entry())
    files = (
        RenderedFile(binding_path, lowering.source),
        RenderedFile(PurePosixPath(MANIFEST_NAME), write_manifest(root, manifest_entries)),
    )
    injection = inject(root, files, label=f"tool:{entry_id}")

    plan = lowering.plan
    if as_json:
        typer.echo(
            json.dumps(
                {
                    "action": "lowered",
                    "id": entry_id,
                    "tool": entry.descriptor.name,
                    "framework": framework_id,
                    "target": target,
                    "status": plan.status,
                    "declared": sorted(str(p) for p in plan.declared),
                    "preserved": sorted(str(p) for p in plan.preserved),
                    "compensated": sorted(str(p) for p in plan.compensated),
                    "unsupported": sorted(str(p) for p in plan.unsupported),
                    "guards": [str(guard.kind) for guard in plan.guards],
                    "files": [item.path for item in injection.files],
                },
                indent=2,
                sort_keys=True,
            )
        )
        raise typer.Exit(ExitCode.OK if not plan.unsupported else ExitCode.FINDINGS)

    style = {"full": "verdict.good", "compensated": "verdict.warn", "unsupported": "verdict.bad"}[
        plan.status
    ]
    line = Text("Lowered ", style=style)
    line.append_text(accent_text(entry.descriptor.name))
    line.append(f" into {target} ", style=style)
    line.append(f"({plan.status})", style=style)
    print_text(console, line)
    for item in injection.files:
        marker = Text(
            "+" if item.created else "~", style="verdict.good" if item.created else "muted"
        )
        row = Text("  ")
        row.append_text(marker)
        row.append(f" {item.path}", style="muted")
        print_text(console, row)

    if plan.guards:
        console.print()
        print_line(console, "guards emitted:", style="heading")
        for guard in lowering.guards:
            typer.echo(f"  - {guard.kind}: {guard.comment}")

    if plan.unsupported:
        console.print()
        unsupported_line = Text("unsupported: ", style="sev.high")
        unsupported_line.append(", ".join(sorted(str(p) for p in plan.unsupported)))
        print_text(console, unsupported_line)
        typer.echo("  no guard exists yet to compensate this; the gap is recorded, not hidden.")

    console.print()
    undo = Text("  Undo with: ")
    undo.append_text(accent_text("toolseal revert"))
    print_text(console, undo)
    raise typer.Exit(ExitCode.OK if not plan.unsupported else ExitCode.FINDINGS)
