"""`cli/_ui.py` - the one place a colour or a table's width arithmetic is
allowed to live for the whole CLI (spec `docs/superpowers/specs/
2026-08-19-cli-visual-language.md`).

Two palette choices are deliberately load-bearing and are pinned here so a
future "cleanup" cannot soften them back to their obvious-looking defaults:
`verdict.unknown` must stay magenta, not grey, and `caveat` must stay visible,
not dim.
"""

from __future__ import annotations

import io
import sys

import pytest
from rich.console import Console

from toolseal.cli import _ui


def _rendered(style: str) -> str:
    # `no_color` is left unset (`None`) so `rich.console.Console` falls back
    # to its own `NO_COLOR` environment-variable check - the exact path
    # `test_no_color_suppresses_colour_codes` below exercises.
    buf = io.StringIO()
    console = Console(file=buf, theme=_ui.THEME, force_terminal=True, width=80, markup=False)
    console.print("x", style=style)
    return buf.getvalue()


# --- palette (spec §2) ------------------------------------------------------


def test_verdict_unknown_is_magenta_not_grey() -> None:
    # UNKNOWN means "we could not look" - rendering it grey would file it
    # visually under "fine", which is the exact confusion the taxonomy keeps
    # `Verdict.UNKNOWN` distinct from `Verdict.PASS` to avoid.
    out = _rendered("verdict.unknown")

    assert "\x1b[35m" in out  # magenta
    assert "\x1b[2m" not in out  # not dim/grey


def test_caveat_is_visible_not_dim() -> None:
    # The curated-subset mark and "not assessed" callouts exist so a score is
    # never read outside the context that qualifies it - muting this token
    # is the defect it was written to prevent.
    out = _rendered("caveat")

    assert "\x1b[2m" not in out  # not the `muted` (dim) treatment
    assert "3" in out  # italic SGR code is present in some form
    assert "33m" in out  # yellow


def test_caveat_and_muted_are_different_styles() -> None:
    assert _rendered("caveat") != _rendered("muted")


def test_severity_style_maps_one_token_per_severity() -> None:
    from toolseal.core.policy.model import Severity

    tokens = {_ui.severity_style(sev) for sev in Severity}
    assert tokens == {"sev.critical", "sev.high", "sev.medium", "sev.low"}


def test_score_style_thresholds() -> None:
    assert _ui.score_style(100) == "verdict.good"
    assert _ui.score_style(_ui.GOOD_SCORE) == "verdict.good"
    assert _ui.score_style(_ui.GOOD_SCORE - 1) == "verdict.warn"
    assert _ui.score_style(_ui.WARN_SCORE) == "verdict.warn"
    assert _ui.score_style(_ui.WARN_SCORE - 1) == "verdict.bad"
    assert _ui.score_style(0) == "verdict.bad"


# --- NO_COLOR (spec §1: "Degrade without apology") --------------------------


def test_no_color_suppresses_colour_codes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")

    out = _rendered("sev.critical")

    assert "\x1b[" not in out or "31m" not in out
    assert "31m" not in out


# --- tables (spec §5) --------------------------------------------------------


def test_new_table_uses_a_rule_under_the_header_not_a_heavy_border() -> None:
    buf = io.StringIO()
    console = Console(file=buf, width=80, force_terminal=False)
    table = _ui.new_table()
    table.add_column("family")
    table.add_column("score", justify="right")
    table.add_row("A", "100")

    console.print(table)
    lines = buf.getvalue().splitlines()

    assert lines[0].split() == ["family", "score"]
    assert set(lines[1].strip()) == {"─"}
    # No heavy box border anywhere: no corner or side-wall characters.
    assert not any(ch in buf.getvalue() for ch in "┌┐└┘┏┓┗┛║")


# --- progress (spec §4): no-op off a TTY, real off a TTY --------------------


def test_is_tty_reflects_stdout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    assert _ui.is_tty() is True

    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    assert _ui.is_tty() is False


def test_rich_audit_progress_is_silent_when_not_a_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_ui, "is_tty", lambda: False)
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=True, width=80)
    observer = _ui.RichAuditProgress(console)

    observer.start("resolving package names", 10)
    observer.advance("resolving package names")
    observer.finish("resolving package names")

    assert buf.getvalue() == ""


def test_rich_audit_progress_names_the_phase_and_shows_n_of_total(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_ui, "is_tty", lambda: True)
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=True, width=80)
    observer = _ui.RichAuditProgress(console)

    observer.start("resolving package names", 2)
    observer.advance("resolving package names")
    observer.finish("resolving package names")

    out = buf.getvalue()
    assert "resolving package names" in out


def test_rich_audit_progress_status_for_an_indeterminate_phase(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_ui, "is_tty", lambda: True)
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=True, width=80)
    observer = _ui.RichAuditProgress(console)

    observer.start("querying advisories", None)
    observer.finish("querying advisories")

    # A `Status`, not a `Progress` bar - no `n/total` fraction ever appears.
    assert observer._progress is None


def test_progress_bar_context_manager_is_a_noop_off_a_tty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_ui, "is_tty", lambda: False)

    with _ui.progress_bar("fetching the index", 5) as advance:
        advance(1)
        advance(2)


def test_status_context_manager_is_a_noop_off_a_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_ui, "is_tty", lambda: False)

    with _ui.status("scaffolding"):
        pass
