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
import pathlib
import sys

import pytest
from rich.console import Console
from rich.table import Table
from rich.text import Text

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


# --- defect 1: no non-ASCII punctuation anywhere outside this module --------
#
# A Windows console that cannot encode a literal "-" or "." in our own source
# renders it as U+FFFD ("?"), and that garbling survives being piped into a
# log, a CI job, or an incident ticket - none of which we control. Rich's own
# box-drawing characters are exempt: rich substitutes ASCII for those itself
# when the target encoding cannot represent them, which is a solved problem
# one layer down. It is only *our own literal strings* - an em dash, a middle
# dot used as a separator - that this test exists to keep out.
#
# "§" (SECTION SIGN, "§") is allow-listed: it is used exclusively in
# comments and docstrings to reference a section of the visual-language spec
# (e.g. "spec § 3"), never inside a string that reaches a user.


_ALLOWED_NON_ASCII = {"§"}
_CLI_SOURCE_ROOT = pathlib.Path(__file__).resolve().parents[1] / "src" / "toolseal"


def _cli_source_files() -> list[pathlib.Path]:
    return [
        path
        for path in sorted(_CLI_SOURCE_ROOT.rglob("*.py"))
        if path.name != "_ui.py" and "__pycache__" not in path.parts
    ]


def test_no_non_ascii_characters_outside_the_ui_module() -> None:
    offenders: list[str] = []
    for path in _cli_source_files():
        text = path.read_text(encoding="utf-8")
        for line_number, line in enumerate(text.splitlines(), start=1):
            stray = sorted({c for c in line if ord(c) > 127} - _ALLOWED_NON_ASCII)
            if stray:
                offenders.append(f"{path}:{line_number}: {stray!r}")

    assert not offenders, "non-ASCII character(s) found:\n" + "\n".join(offenders)


def test_source_files_were_actually_scanned() -> None:
    # A guard on the guard: if the glob above ever matched nothing (a moved
    # package, a typo'd root), the non-ASCII test above would pass vacuously
    # and silently stop meaning anything.
    assert len(_cli_source_files()) > 20


# --- defect 2 & 3: `print_wrapped`'s hanging indent, no padding -------------


def _wrapped_lines(body: str, *, width: int = 40, **kwargs: object) -> list[str]:
    # `print_wrapped` never consults `is_tty()` - it has no "off a TTY"
    # branch of its own (unlike `progress_bar`/`status`), so a plain
    # non-terminal `Console` is sufficient here.
    buf = io.StringIO()
    console = Console(file=buf, theme=_ui.THEME, force_terminal=False, width=width, markup=False)
    _ui.print_wrapped(console, body, **kwargs)  # type: ignore[arg-type]
    return buf.getvalue().splitlines()


def test_print_wrapped_continuation_lines_indent_under_the_text_not_the_label() -> None:
    lines = _wrapped_lines(
        "Move the value into the OS keychain and revoke the exposed credential.",
        indent=13,
        style="fix",
        label="fix  ",
    )

    assert len(lines) >= 2
    assert lines[0].startswith(" " * 13 + "fix  ")
    # The continuation must align under the text that follows "fix  " (column
    # 18), never under the "fix" label itself (column 13) - a continuation
    # starting at column 13 would read as a new field, which is defect 3.
    for continuation in lines[1:]:
        assert continuation.startswith(" " * 18)
        assert not continuation.startswith(" " * 18 + " ")  # exactly 18, not more
        assert "fix" not in continuation[:18]


def test_print_wrapped_with_no_label_still_indents_flat() -> None:
    lines = _wrapped_lines(
        "config.py:1 - OpenAI-style key found somewhere deep inside config.py",
        indent=13,
        style="muted",
    )

    assert len(lines) >= 2
    for line in lines:
        assert line.startswith(" " * 13)
        assert not line.startswith(" " * 14)


def test_print_wrapped_never_pads_a_line_to_the_container_width() -> None:
    lines = _wrapped_lines(
        "Move the value into the OS keychain and revoke the exposed credential; "
        "it must be treated as compromised.",
        indent=13,
        style="fix",
        label="fix  ",
        width=60,
    )

    assert len(lines) >= 2
    for line in lines:
        assert line == line.rstrip(), f"trailing whitespace on: {line!r}"
        # None of these lines legitimately need all 60 columns; padding to
        # the container width is exactly the defect this function prevents.
        assert len(line) < 60


def test_print_wrapped_on_an_empty_body_prints_only_the_label() -> None:
    lines = _wrapped_lines("", indent=13, style="fix", label="fix  ")

    assert lines == [" " * 13 + "fix"]


# --- table trailing whitespace (spec: "stop padding") -----------------------


def test_print_table_never_leaves_trailing_whitespace_on_a_short_row() -> None:
    # `rich.table.Table` pads every cell - including a left-justified last
    # column's - out to that column's own width, so a short value in the
    # widest column would otherwise trail whitespace up to the longest one.
    buf = io.StringIO()
    console = Console(file=buf, theme=_ui.THEME, force_terminal=False, width=80, markup=False)
    table = _ui.new_table()
    table.add_column("field")
    table.add_column("value")
    table.add_row("git", "not found")
    table.add_row("executable", "/a/very/long/path/that/is/much/longer/than/not/found")

    _ui.print_table(console, table)

    for line in buf.getvalue().splitlines():
        assert line == line.rstrip(), f"trailing whitespace on: {line!r}"


def test_print_table_preserves_per_cell_styling() -> None:
    # The rewrite that trims trailing whitespace must not flatten a styled
    # cell (e.g. the `caveat` marker in `policy list`) back to plain text.
    buf = io.StringIO()
    console = Console(
        file=buf, theme=_ui.THEME, force_terminal=True, width=80, markup=False, highlight=False
    )
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column()
    table.add_column()
    styled = Text("33%")
    styled.append("*", style="caveat")
    table.add_row("iso-42001", styled)

    _ui.print_table(console, table)

    out = buf.getvalue()
    assert "33m" in out  # the caveat token's yellow survived the rewrite
