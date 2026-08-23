"""`core.policy.progress` - the seam that lets a check report long-running
network phases without `core/` importing a CLI, or `rich`, or anything else
a library consumer of this package would not need.

The default observer is a no-op precisely so every check in this suite that
does not install one - which is almost all of them - pays nothing for this
existing.
"""

from __future__ import annotations

import pytest

from toolseal.core.policy import progress


class _Recorder:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def start(self, phase: str, total: int | None) -> None:
        self.calls.append(("start", phase, str(total)))

    def advance(self, phase: str, step: int = 1) -> None:
        self.calls.append(("advance", phase, str(step)))

    def finish(self, phase: str) -> None:
        self.calls.append(("finish", phase))


def test_default_observer_is_a_silent_noop() -> None:
    # Nothing installed - every call must be safe and produce no side effect.
    observer = progress.current()

    observer.start("some phase", 10)
    observer.advance("some phase")
    observer.finish("some phase")


def test_observe_installs_the_given_observer_for_the_block() -> None:
    recorder = _Recorder()

    with progress.observe(recorder):
        progress.current().start("resolving package names", 3)
        progress.current().advance("resolving package names")

    assert recorder.calls == [
        ("start", "resolving package names", "3"),
        ("advance", "resolving package names", "1"),
    ]


def test_observe_restores_the_previous_observer_on_exit() -> None:
    outer = _Recorder()
    inner = _Recorder()

    with progress.observe(outer):
        with progress.observe(inner):
            progress.current().start("x", None)
        # Back to `outer`, not the default - `observe` restores whatever was
        # active before it, not always the no-op.
        progress.current().start("y", None)

    assert inner.calls == [("start", "x", "None")]
    assert outer.calls == [("start", "y", "None")]


def test_observe_restores_even_when_the_block_raises() -> None:
    class BoomError(Exception):
        pass

    before = progress.current()

    with pytest.raises(BoomError), progress.observe(_Recorder()):
        raise BoomError

    assert progress.current() is before
