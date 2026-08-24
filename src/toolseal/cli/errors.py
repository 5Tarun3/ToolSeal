"""Turning a domain error into CLI output, at the command boundary.

Doing this in ``main()`` alone was not enough. ``main`` is only involved when the
console script runs; a test harness, ``python -m``, or anything embedding the
Typer app calls the commands directly and would see a raw traceback instead of a
message and an exit code.

Wrapping each command keeps the behaviour identical however the app is reached,
and leaves ``main`` as a last-resort net for genuinely unexpected failures.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import Any, TypeVar

import typer

from toolseal.cli._ui import err_console, print_line
from toolseal.errors import ExitCode, ToolsealError

F = TypeVar("F", bound=Callable[..., Any])


def format_error_line(prefix: str, message: str, exit_code: ExitCode, *, hint: str = "") -> str:
    """One line: what happened, and the exit code a script can branch on -
    named as well as numbered, so a reader is not left to look up what `2`
    means (spec: colour is never the only carrier of meaning; the same
    discipline extends to a bare exit-code digit).

    *hint* is an optional trailing clause pointing at what would help - kept
    to an empty string for the common case, since most `ToolsealError`
    messages already carry their own specific pointer at the raise site
    (a "no entry found" `UsageError` already says to try `registry search`)
    and a second, generic one here would be chrome an error is not the
    place for.
    """
    line = f"{prefix}: {message} (exit {int(exit_code)}: {exit_code.name.lower()})"
    if hint:
        line = f"{line} - {hint}"
    return line


def command(function: F) -> F:
    """Convert :class:`ToolsealError` into a message on stderr and an exit code.

    ``functools.wraps`` preserves ``__wrapped__``, so Typer still reads the
    original signature and the command's options are unaffected.
    """

    @wraps(function)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return function(*args, **kwargs)
        except ToolsealError as exc:
            line = format_error_line("error", str(exc), exc.exit_code)
            print_line(err_console, line, style="verdict.bad")
            raise typer.Exit(int(exc.exit_code)) from None

    return wrapper  # type: ignore[return-value]
