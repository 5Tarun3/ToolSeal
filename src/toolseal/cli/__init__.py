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

from toolseal import __version__
from toolseal.cli import audit_command, init_command, registry_command
from toolseal.cli.errors import command as error_boundary
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


app.command(name="init")(error_boundary(init_command.init))
app.command(name="audit")(error_boundary(audit_command.audit))
app.add_typer(registry_command.registry_app)


@app.command()
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

    width = max(len(key) for key in report)
    for key, value in report.items():
        typer.echo(f"{key.ljust(width)}  {value if value is not None else 'not found'}")


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
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        return int(exc.exit_code)
    except KeyboardInterrupt:
        typer.secho("interrupted", fg=typer.colors.YELLOW, err=True)
        return int(ExitCode.INTERNAL)
    # Broad by design: the process boundary must not leak a traceback to the user.
    except Exception as exc:
        log.debug("unhandled error", exc_info=exc)
        typer.secho(
            f"internal error: {type(exc).__name__}: {exc}",
            fg=typer.colors.RED,
            err=True,
        )
        return int(ExitCode.INTERNAL)
    return int(ExitCode.OK)


if __name__ == "__main__":
    sys.exit(main())
