"""An optional hook for reporting long-running network phases upward.

`family_c.py`'s per-name resolution loop (`C3`) and its advisory batch call
(`C2`) are the two phases in an audit that can run long enough that silence
reads as a hang - each `C3` name resolution costs roughly half a second over
the network, so a forty-dependency project spends on the order of twenty
seconds saying nothing.

`core/` has no business knowing whether a CLI, a test harness, or a library
caller is driving it - it must not import `rich`, and it must not import
anything from `cli/` (that boundary is deliberate: `cli/` is thin and `core/`
stays reusable on its own). So it cannot draw a progress bar itself. What it
can do is call back into whatever the caller installed, through a small
`Protocol` of plain method calls - no colour, no terminal control, nothing a
library consumer without a terminal would ever need to care about.

The default observer installed everywhere nothing was set up is a no-op, so
every caller that does not care about progress - every test in this suite
included - pays nothing for this seam existing.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Protocol


class AuditProgress(Protocol):
    """What a check may report about a long-running phase.

    Every method takes only strings and ints, so nothing that implements
    this protocol has to import anything beyond the standard library either
    - the CLI's `rich`-backed implementation lives entirely in `cli/_ui.py`.
    """

    def start(self, phase: str, total: int | None) -> None:
        """A phase named *phase* is beginning.

        *total* is the known step count for a determinate phase (name
        resolution, one step per name), or ``None`` for a phase where only
        "this is happening" can be said (the OSV advisory query, one network
        round trip with no meaningful sub-steps).
        """

    def advance(self, phase: str, step: int = 1) -> None:
        """*step* more units of *phase* completed."""

    def finish(self, phase: str) -> None:
        """The phase named *phase* is done."""


class _NullProgress:
    """Reports nothing. Installed by default, so nobody has to opt out."""

    def start(self, phase: str, total: int | None) -> None:
        pass

    def advance(self, phase: str, step: int = 1) -> None:
        pass

    def finish(self, phase: str) -> None:
        pass


_NULL: AuditProgress = _NullProgress()
_current: AuditProgress = _NULL


def current() -> AuditProgress:
    """The observer installed by the caller, or the no-op default."""
    return _current


@contextmanager
def observe(observer: AuditProgress) -> Iterator[None]:
    """Install *observer* as the current one for the duration of the block.

    A context manager rather than a bare setter, so a caller that raises -
    or simply forgets - never leaves a stale observer installed for the next
    audit run in the same process (the evaluation harness runs many in one
    process; a leaked observer there would report someone else's progress).
    """
    global _current
    previous = _current
    _current = observer
    try:
        yield
    finally:
        _current = previous
