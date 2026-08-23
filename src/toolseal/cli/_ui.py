"""The shared visual language for every toolseal command (spec: `docs/superpowers/
specs/2026-08-19-cli-visual-language.md`).

One `Theme`, one pair of `Console`s, one table factory, one progress bridge.
Nothing outside this module hard-codes a colour or writes its own column-width
arithmetic - a command that does either has drifted from the shared
vocabulary this module exists to be.

`rich` is a runtime dependency of this project, declared explicitly in
`pyproject.toml`. It reached the environment already, as a transitive
dependency of `typer` (`typer -> rich`) - so importing it here adds no new
supply-chain surface - but importing it directly rather than leaning on
someone else's transitive edge is what keeps a working install from breaking
on a `typer` minor release that changes what it pulls in.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from rich import box
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TaskID, TextColumn
from rich.status import Status
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from toolseal.core.policy.model import Severity
from toolseal.core.policy.progress import AuditProgress

# ---------------------------------------------------------------------------
# Palette (spec §2). Every token below is used somewhere in the CLI; nothing
# elsewhere in this codebase should reference a `typer.colors.*` constant or
# a raw colour name.
# ---------------------------------------------------------------------------

THEME = Theme(
    {
        "sev.critical": "bold red",
        "sev.high": "red",
        "sev.medium": "yellow",
        "sev.low": "cyan",
        "verdict.good": "green",
        "verdict.warn": "yellow",
        "verdict.bad": "red",
        # Deliberately magenta, not grey. `UNKNOWN` means "we could not
        # look" - the taxonomy spends real effort keeping that apart from
        # "we looked and it was fine". Grey would file it under "fine"
        # visually the moment someone "cleans up" this palette; magenta
        # can't be mistaken for a muted, harmless PASS. Do not soften this.
        "verdict.unknown": "magenta",
        "verdict.relaxed": "blue",
        "fix": "bold default",
        "muted": "dim",
        # Deliberately visible, not dim. The curated-subset mark on
        # `nist-ai-rmf`/`iso-42001` and the "not assessed" callouts exist so
        # a percentage or a score is never read outside the context that
        # qualifies it. A caveat nobody notices is exactly the defect this
        # token was written to prevent - resist the urge to mute it.
        "caveat": "italic yellow",
    }
)

console = Console(theme=THEME, highlight=False, markup=False)
"""Where every command prints its human-readable report. stdout.

`markup=False`: a project path or a finding's own text (a file path, a
detected literal) can legitimately contain a literal `[` - Rich's `[...]`
style markup would otherwise try to parse it. Styling goes through explicit
`rich.text.Text` objects instead, never through a markup string.
"""

err_console = Console(theme=THEME, stderr=True, highlight=False, markup=False)
"""Where progress and status indicators render (spec §4) - never stdout, so
`toolseal audit --json > out.json` is never touched by decoration."""

GOOD_SCORE = 80
WARN_SCORE = 50


def score_style(score: int) -> str:
    """The theme token for a numeric score, per spec §2's three thresholds."""
    if score >= GOOD_SCORE:
        return "verdict.good"
    if score >= WARN_SCORE:
        return "verdict.warn"
    return "verdict.bad"


def severity_style(severity: Severity) -> str:
    """The theme token for a severity. One severity, one colour, everywhere."""
    return f"sev.{severity.value}"


# ---------------------------------------------------------------------------
# Tables (spec §5). Replaces the hand-rolled width arithmetic in
# `cli/_columns.py` - Rich already computes "widest of heading or data"
# itself, which is the entire job that module did.
# ---------------------------------------------------------------------------


def new_table(*, box_style: box.Box = box.SIMPLE) -> Table:
    """A table in the shared visual language: rules under headers, no heavy
    borders around dense numeric data, no separate width-arithmetic module."""
    return Table(
        box=box_style,
        show_header=True,
        header_style="bold",
        pad_edge=False,
        show_edge=False,
    )


# ---------------------------------------------------------------------------
# Progress (spec §4). Determinate work gets a progress bar with `n/total`;
# indeterminate work gets a status line. Both are no-ops off a TTY, and both
# render to stderr only.
# ---------------------------------------------------------------------------


def is_tty() -> bool:
    """Whether decoration - colour, progress, status - should render at all.

    Checked against stdout specifically (spec §4): a user who redirects only
    stdout (`toolseal audit --json > out.json`) still gets a clean file, and
    a user who pipes the whole invocation (`toolseal audit . | cat`) gets
    plain text with no spinner residue either way.
    """
    return sys.stdout.isatty()


class RichAuditProgress:
    """Bridges `core.policy.progress.AuditProgress` - a plain Protocol with
    no rich import, so `core/` never has to know a terminal exists - to
    `rich.progress.Progress` for phases with a known count and
    `rich.status.Status` for phases that only know they are happening.

    `core/` calls `start`/`advance`/`finish` with plain strings and ints; this
    class is the only place those calls become an actual rendered indicator,
    and it is a no-op entirely when stdout is not a TTY.
    """

    def __init__(self, out: Console) -> None:
        self._console = out
        self._progress: Progress | None = None
        self._task_id: TaskID | None = None
        self._status: Status | None = None

    def start(self, phase: str, total: int | None) -> None:
        if not is_tty():
            return
        if total is None:
            self._status = self._console.status(phase)
            self._status.start()
            return
        self._progress = Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            console=self._console,
            transient=True,
        )
        self._progress.start()
        self._task_id = self._progress.add_task(phase, total=total)

    def advance(self, phase: str, step: int = 1) -> None:
        if self._progress is not None and self._task_id is not None:
            self._progress.advance(self._task_id, step)

    def finish(self, phase: str) -> None:
        if self._progress is not None:
            self._progress.stop()
            self._progress = None
            self._task_id = None
        if self._status is not None:
            self._status.stop()
            self._status = None


def new_progress_observer() -> AuditProgress:
    """The observer the CLI installs around a `core.audit.audit()` call."""
    return RichAuditProgress(err_console)


@contextmanager
def status(description: str) -> Iterator[None]:
    """An indeterminate status line for scaffolding-type work (spec §4:
    `init`, `add`). No-op off a TTY."""
    if not is_tty():
        yield
        return
    with err_console.status(description):
        yield


@contextmanager
def progress_bar(description: str, total: int) -> Iterator[Callable[[int], None]]:
    """A determinate progress indicator naming *description*, `n/total`
    (spec §4: `registry sync`'s index fetch, when the length is known).

    Yields a callable that advances the bar; a no-op callable when stdout is
    not a TTY, so callers never need their own branch on `is_tty()`.
    """
    if not is_tty():

        def noop(step: int = 1) -> None:
            pass

        yield noop
        return
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        console=err_console,
        transient=True,
    ) as progress:
        task_id = progress.add_task(description, total=total)

        def advance(step: int = 1) -> None:
            progress.advance(task_id, step)

        yield advance


# ---------------------------------------------------------------------------
# Small rendering helpers shared by more than one command.
# ---------------------------------------------------------------------------


def blocking_text(count: int) -> Text:
    """`BLOCKING`, styled `sev.critical` per spec §2's palette table, with the
    count of critical checks that failed - never as a bare trailing word."""
    plural = "check" if count == 1 else "checks"
    return Text(f"BLOCKING — {count} critical {plural} failed", style="sev.critical")
