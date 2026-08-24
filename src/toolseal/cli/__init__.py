"""Command-line entry point.

This module owns the process boundary. It is the only place that converts an
exception into an exit code, and the only place that writes to stdout directly.

Commands are added alongside the features they expose; `doctor` exists now
because a skeleton that cannot be run cannot be tested.
"""

from __future__ import annotations

import json
import logging
import platform
import shutil
import sys
from typing import Annotated, Any

import typer
from rich.panel import Panel
from rich.text import Text

from toolseal import __version__
from toolseal.cli import (
    audit_command,
    configure_command,
    init_command,
    policy_command,
    registry_command,
)
from toolseal.cli._ui import accent_text, console, err_console, new_table, print_line
from toolseal.cli.errors import command as error_boundary
from toolseal.cli.errors import format_error_line
from toolseal.errors import ExitCode, ToolsealError
from toolseal.logging import configure_logging

log = logging.getLogger(__name__)

app = typer.Typer(
    name="toolseal",
    help="Secure-by-default scaffolding and cross-framework tool registry for agentic systems.",
    no_args_is_help=True,
    add_completion=False,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit(ExitCode.OK)


@app.callback()
def cli(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Enable debug logging on stderr."),
    ] = False,
) -> None:
    """Configure global state shared by every command."""
    configure_logging(verbose=verbose)


# Grouped by pillar (spec: the owner's complaint was "the --help has better
# UI than the tool itself" - nine subcommands rendered as one undifferentiated
# list). `rich_help_panel` is documented, public Typer API (both `.command()`
# and `.add_typer()` accept it) - grouping is the whole change here, nothing
# private is touched to get it.
#
# `init`/`add`/`revert` are a project's lifecycle - create it, configure it,
# undo what was configured - so they share "Scaffold" even though `add`'s own
# two subcommands split further (see `configure_command.py`) into Scaffold
# (`framework`) and Translate (`mcp`): the pillar most of `add` belongs to.
# `audit` and `policy` sit together under "Audit" on purpose - the spec calls
# audit a cross-cutting concern rather than a fourth pillar, and `policy` is
# entirely about the rules audit applies (what they are, why, and how they
# were sealed), so a reader looking for one finds the other beside it.
app.command(name="init", rich_help_panel="Scaffold")(error_boundary(init_command.init))
app.command(name="audit", rich_help_panel="Audit")(error_boundary(audit_command.audit))
app.add_typer(registry_command.registry_app, rich_help_panel="Registry")
app.add_typer(configure_command.add_app, rich_help_panel="Scaffold")
app.command(name="revert", rich_help_panel="Scaffold")(error_boundary(configure_command.revert))
app.add_typer(policy_command.policy_app, rich_help_panel="Audit")


def doctor(
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Emit machine-readable output on stdout."),
    ] = False,
) -> None:
    """Report environment information useful when diagnosing a problem."""
    report: dict[str, Any] = {
        "toolseal": __version__,
        "python": platform.python_version(),
        "platform": f"{platform.system()} {platform.release()}",
        "executable": sys.executable,
        "git": shutil.which("git"),
    }

    if as_json:
        typer.echo(json.dumps(report, indent=2, sort_keys=True))
        return

    table = new_table()
    table.add_column("field")
    table.add_column("value")
    for key, value in report.items():
        if value is None:
            cell = Text("not found", style="verdict.warn")
        else:
            cell = Text(str(value), style="muted")
        table.add_row(accent_text(key), cell)
    # Framed like every other command's report (spec: audit's summary,
    # policy explain's panel) rather than a bare table with nothing marking
    # where the report starts and ends. `expand=False`: the box fits the
    # table's own content width, the same choice those other panels make,
    # rather than stretching to the full terminal width for no reason.
    console.print(Panel(table, expand=False))


app.command(name="doctor", rich_help_panel="Diagnostics")(error_boundary(doctor))


def main() -> int:
    """Run the CLI and translate the outcome into an exit code.

    Returns an int rather than calling ``sys.exit`` so the boundary stays
    testable. The console-script wrapper passes the result to ``sys.exit``.
    """
    try:
        app()
    except SystemExit as exc:  # Click's normal completion path.
        code = exc.code
        if code is None:
            return int(ExitCode.OK)
        return code if isinstance(code, int) else int(ExitCode.USAGE)
    except ToolsealError as exc:
        log.debug("toolseal error", exc_info=exc)
        line = format_error_line("error", str(exc), exc.exit_code)
        print_line(err_console, line, style="verdict.bad")
        return int(exc.exit_code)
    except KeyboardInterrupt:
        print_line(err_console, "interrupted", style="verdict.warn")
        return int(ExitCode.INTERNAL)
    # Broad by design: the process boundary must not leak a traceback to the user.
    except Exception as exc:
        log.debug("unhandled error", exc_info=exc)
        # The traceback `log.debug` just captured is otherwise invisible -
        # it only reaches stderr once `--verbose` raises the root logger to
        # DEBUG (see `logging.configure_logging`) - so the one generic
        # pointer that earns its place here is the flag that would show it,
        # not a guess at which command caused an unexpected failure.
        line = format_error_line(
            "internal error",
            f"{type(exc).__name__}: {exc}",
            ExitCode.INTERNAL,
            hint="re-run with --verbose for a traceback",
        )
        print_line(err_console, line, style="verdict.bad")
        return int(ExitCode.INTERNAL)
    return int(ExitCode.OK)


if __name__ == "__main__":
    sys.exit(main())
