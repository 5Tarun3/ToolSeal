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

from toolseal.errors import ToolsealError

F = TypeVar("F", bound=Callable[..., Any])


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
            typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
            raise typer.Exit(int(exc.exit_code)) from None

    return wrapper  # type: ignore[return-value]
