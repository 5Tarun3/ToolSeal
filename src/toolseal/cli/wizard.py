"""The guided `toolseal init` flow.

`init` has nine options and sensible defaults for all of them, which is a good
property for a script and a bad one for a first-time reader: the fastest path
through the command never shows that four providers and three frameworks
exist. This module is the slower path that does.

It reads answers and returns them. It does not touch the filesystem, does not
import `core.scaffold`, and does not decide anything `init` would not have
decided from flags - so every behaviour it can produce is reachable
non-interactively, and the summary it prints at the end says exactly how.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass

from rich.console import Console
from rich.text import Text

from toolseal.cli._ui import accent_text, print_text
from toolseal.cli._ui import console as default_console


@dataclass(frozen=True)
class Option:
    """One selectable answer: the value `init` takes, and why you would pick it."""

    value: str
    label: str
    summary: str


def _read(out: Console, answers: Iterator[str] | None) -> str:
    """One reply, from the injected sequence in tests or the console otherwise."""
    if answers is not None:
        return next(answers, "")
    return out.input("  > ")


def choose(
    prompt: str,
    options: Sequence[Option],
    *,
    default: str,
    out: Console | None = None,
    answers: Iterator[str] | None = None,
) -> str:
    """Render a numbered menu and return the chosen `Option.value`.

    Accepts the index or the value spelled out; empty input takes *default*.
    Anything else re-prompts rather than raising - a typo at a prompt is not a
    usage error, it is a typo.
    """
    target = out if out is not None else default_console
    by_index = {str(number): option.value for number, option in enumerate(options, start=1)}
    by_value = {option.value: option.value for option in options}

    target.print()
    print_text(target, Text(prompt, style="heading"))
    for number, option in enumerate(options, start=1):
        row = Text(f"  [{number}] ")
        row.append_text(accent_text(option.value))
        row.append(f"  {option.summary}", style="muted")
        if option.value == default:
            row.append("  (default)", style="verdict.good")
        print_text(target, row)

    while True:
        reply = _read(target, answers).strip()
        if not reply:
            return default
        chosen = by_index.get(reply) or by_value.get(reply)
        if chosen is not None:
            return chosen
        print_text(target, Text(f"  {reply!r} is not one of the options", style="verdict.warn"))
