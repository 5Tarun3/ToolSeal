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

from toolseal.core.policy.model import Severity, Verdict
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
        # Identifiers: check ids, catalogue ids, control ids, standard names,
        # file paths, command examples. Bold cyan rather than plain `sev.low`
        # cyan - the weight is what marks "this is a name you could type
        # back", not the hue alone, so a severity-low cell and an identifier
        # cell in the same row never read as the same kind of thing.
        "accent": "bold cyan",
        # Section headings and field labels ("How to fix it", "Obligations
        # this serves"). Named separately from `accent` even though both
        # currently render bold: a heading is a structural label, an accent
        # is a value the reader might copy - the two are allowed to diverge
        # later without every call site changing.
        "heading": "bold",
        # Table column headers. Coloured, not merely bold - the gap this
        # whole pass exists to close is a `--help` that is more legible than
        # the tool's own tables because typer colours its headers and we did
        # not (see spec's own opening complaint).
        "table.header": "bold cyan",
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


_VERDICT_STYLES: dict[Verdict, str] = {
    Verdict.PASS: "verdict.good",
    Verdict.FAIL: "verdict.bad",
    Verdict.UNKNOWN: "verdict.unknown",
    Verdict.RELAXED: "verdict.relaxed",
    # Neither a pass nor a fail - out of the check's reach entirely, which is
    # a different fact from either. `muted` is the same treatment a zero
    # count gets (see `count_style` below): a cell reporting "nothing to see
    # here" rather than a graded outcome.
    Verdict.NOT_APPLICABLE: "muted",
}


def verdict_style(verdict: Verdict) -> str:
    """The theme token for a verdict cell: PASS/FAIL/UNKNOWN/RELAXED/n-a each
    take their own token (spec §2), never a bare unstyled string."""
    return _VERDICT_STYLES[verdict]


def count_style(count: int) -> str:
    """The theme token for a numeric count cell: zero is muted, a non-zero
    count - a non-zero failure count in particular - keeps full weight
    rather than fading into the same grey as an empty column."""
    return "muted" if count == 0 else ""


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
        header_style="table.header",
        pad_edge=False,
        show_edge=False,
    )


def print_table(out: Console, table: Table) -> None:
    """Print `table`, with every rendered line right-trimmed.

    `rich.table.Table` pads every cell - including an unbordered last
    column's - out to its column's own computed width, so two rows whose
    last-column values differ in length otherwise differ in trailing
    whitespace too (spec: "stop padding"). There is no per-table switch for
    this: turning it off would mean abandoning column alignment, which is the
    entire point of a table.

    This does not hand-roll that layout - `Console.render_lines` still does
    every bit of the column sizing and cell wrapping. It only reassembles
    each already-rendered line into a `Text` (preserving every segment's
    style, so a coloured cell like the `caveat` marker survives intact) and
    trims the trailing whitespace `render_lines(..., pad=True)` would have
    added, the same boundary-level trim `print_wrapped` applies to wrapped
    prose.
    """
    for line in out.render_lines(table, out.options, pad=False):
        text = Text.assemble(
            *[(segment.text, segment.style or "") for segment in line if segment.text]
        )
        text.rstrip()
        out.print(text)


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
    return Text(f"BLOCKING: {count} critical {plural} failed", style="sev.critical")


def accent_text(value: str) -> Text:
    """An identifier - a check id, catalogue id, control id, standard name,
    package name, or a path/command meant to be read back and typed - styled
    `accent` (spec §2/§5a) so identifiers carry one consistent treatment
    everywhere they appear, table cell or inline."""
    return Text(value, style="accent")


def print_text(out: Console, text: Text) -> None:
    """Print a pre-built, possibly multi-styled `Text` as a single line that
    is never reflowed - `print_line`'s sibling for a caller that mixes more
    than one style into one line (an accent id followed by plain prose, for
    instance) and so cannot just hand `print_line` a single string.

    Without `soft_wrap=True`, `rich` word-wraps a line at the console width,
    which - for a long path or a long list of check ids - can split a word
    itself across two lines. A deeply nested temporary directory is exactly
    the case that surfaced this: wrapping mid-word broke a substring a test
    was searching for. `print_line` already guards against this for a single
    style; this closes the same gap for everything else.
    """
    out.print(text, soft_wrap=True)


def print_line(out: Console, text: str, *, style: str) -> None:
    """Print one already-composed line of status/confirmation text in a
    theme colour - the shared replacement for a bare `typer.secho(fg=...)`.

    `soft_wrap=True`: this is a single line, not prose to reflow. Without it,
    `rich`'s default word-wrap would break a long path or message across
    lines the way `typer.secho` never did - a real regression, since a
    project path on a CI runner or a Windows temp directory can easily
    exceed 80 columns.
    """
    out.print(Text(text, style=style), soft_wrap=True)


def print_wrapped(out: Console, body: str, *, indent: int, style: str, label: str = "") -> None:
    """Print `body` word-wrapped to `out`'s width, with a hanging indent: the
    first line starts with `label` at column `indent`, continuation lines
    align under the text (column `indent + len(label)`), never under `label`
    itself (spec: continuations must not read as a new field).

    No line is ever padded out to the container width - each line is only as
    long as its own content. `rich.padding.Padding` cannot do this: its
    `pad=True` fill-to-width is not configurable, which is what produced the
    trailing whitespace this function exists to avoid. Wrapping itself still
    comes entirely from `Console.render_lines` - rich's own line-splitting -
    so this is a thin adapter around a public rich API, not a hand-rolled
    wrapper.
    """
    if not body:
        if label:
            out.print(Text((" " * indent + label).rstrip(), style=style))
        return

    prefix_width = indent + len(label)
    available = max(out.size.width - prefix_width, 1)
    options = out.options.update_width(available)
    rendered = out.render_lines(Text(body), options, pad=False)

    first_prefix = " " * indent + label
    continuation_prefix = " " * prefix_width
    for index, line in enumerate(rendered):
        text = "".join(segment.text for segment in line).rstrip()
        prefix = first_prefix if index == 0 else continuation_prefix
        out.print(Text(prefix + text, style=style))
