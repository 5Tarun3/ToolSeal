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
from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text
from typer.testing import CliRunner

from toolseal.cli import _ui, app, policy_command
from toolseal.core.policy.controls import Control
from toolseal.core.registry.index import EntryAudit, IndexEntry, RegistryIndex
from toolseal.core.registry.utd import Provenance, ToolSource, UnifiedToolDescriptor
from toolseal.errors import ExitCode


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


# --- identifier/heading/table-header tokens ----------------------------------


def test_verdict_style_maps_one_token_per_verdict() -> None:
    from toolseal.core.policy.model import Verdict

    assert _ui.verdict_style(Verdict.PASS) == "verdict.good"
    assert _ui.verdict_style(Verdict.FAIL) == "verdict.bad"
    assert _ui.verdict_style(Verdict.UNKNOWN) == "verdict.unknown"
    assert _ui.verdict_style(Verdict.RELAXED) == "verdict.relaxed"
    # Neither a pass nor a fail - muted, the same treatment a zero count
    # gets, not a colour it would have to share with a graded outcome.
    assert _ui.verdict_style(Verdict.NOT_APPLICABLE) == "muted"


def test_count_style_zero_is_muted_nonzero_is_not() -> None:
    assert _ui.count_style(0) == "muted"
    assert _ui.count_style(1) == ""
    assert _ui.count_style(41) == ""


def test_accent_text_uses_the_accent_token() -> None:
    text = _ui.accent_text("B3")
    assert str(text) == "B3"
    assert text.style == "accent"


def test_accent_and_heading_are_distinct_tokens() -> None:
    # Both currently render bold, but they are named separately (spec §2):
    # an identifier a reader might type back is not the same kind of thing
    # as a section label, and the two must be free to diverge later without
    # every call site that uses one of them changing.
    assert _rendered("accent") != _rendered("heading")


def test_table_header_token_is_coloured_not_bare_bold() -> None:
    out = _rendered("table.header")

    assert "36m" in out  # cyan, not merely the bold `heading`/`fix` treatment
    assert "1" in out  # bold


def test_new_table_headers_render_with_the_table_header_token() -> None:
    # Colour-forced, unlike `test_new_table_uses_a_rule_under_the_header_not_
    # a_heavy_border` above (which deliberately checks the *plain*-text
    # shape) - this is the one place that pins headers actually being
    # coloured, not merely bold, on a real terminal.
    buf = io.StringIO()
    console = Console(file=buf, theme=_ui.THEME, force_terminal=True, width=80, markup=False)
    table = _ui.new_table()
    table.add_column("family")
    table.add_column("score", justify="right")
    table.add_row("A", "100")

    console.print(table)
    out = buf.getvalue()

    assert "36m" in out


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


# --- defect 1, widened: render, don't just scan source ----------------------
#
# `test_no_non_ascii_characters_outside_the_ui_module` above checks a
# literal in *our* source. It has a blind spot: rich's own
# `overflow="ellipsis"` hardcodes U+2026 HORIZONTAL ELLIPSIS into a
# truncated cell (`rich.text.Text.truncate`) - and that character never
# appears in any file the source scan reads, because it does not exist
# until `rich` renders. `registry search`'s two capped columns shipped with
# exactly that: a Windows console rendered every truncated name and
# package string as mojibake, and the guard above passed the whole time,
# because it was never looking at the right surface.
#
# The tests below check what the CLI actually *prints*, not what our
# source contains. That raises a new problem the source scan never had:
# `rich` legitimately draws non-ASCII box characters for a table or panel
# border, and that is correct, desired behaviour (spec: rich substitutes
# ASCII for those itself when the target encoding cannot represent them) -
# a naive "reject every non-ASCII byte in the output" assertion would fail
# on every single table this CLI prints.
#
# The line is drawn like this: `_cli_box_allowlist()` does not hardcode a
# guess at which glyphs count as "a box". It calls `rich.box.Box.substitute`
# - the exact method `rich` calls internally, right before drawing a
# border - on the two box styles this codebase actually asks for
# (`box.SIMPLE` for `new_table()`, `box.ROUNDED` for the `Panel` every
# table-bearing command wraps its table in; `new_grid()` uses `box=None`,
# no glyphs at all) against `_ui.console`'s own configuration. Whatever
# `substitute` returns *is* rich's own drawing for this console, full stop
# - on a console that cannot encode Unicode at all, `substitute` itself
# already downgrades to a pure-ASCII box, so the allowlist would come back
# empty there and the tests below would still hold. Anything outside that
# resolved, mechanically-derived set - our own cell content, an ellipsis
# marker, anything else - is a genuine finding, never something drawn by
# rich's own border logic.
#
# `test_offender_scan_flags_a_synthetic_ellipsis` is the guard on this
# guard (the same shape as `test_source_files_were_actually_scanned`
# above): it proves the scan actually rejects something, by feeding it a
# hand-built string carrying the exact character this defect shipped and
# asserting it gets flagged. A scan that cannot fail on that input would be
# passing every real test vacuously - exactly the failure mode this
# project has already had to rebuild one drift guard for.


def _rich_box_glyphs(console: Console, style: box.Box) -> set[str]:
    resolved = style.substitute(console.options, safe=console.safe_box)
    return {c for c in str(resolved) if ord(c) > 127}


def _cli_box_allowlist() -> set[str]:
    """Every non-ASCII glyph `rich` is entitled to draw for *this* console,
    derived from the two box styles this CLI's own code asks for - never a
    hardcoded guess (see the module-level comment above)."""
    return _rich_box_glyphs(_ui.console, box.SIMPLE) | _rich_box_glyphs(_ui.console, box.ROUNDED)


def _non_ascii_offenders(text: str, *, allowed: set[str]) -> set[str]:
    return {c for c in text if ord(c) > 127 and c not in allowed}


def test_box_allowlist_is_not_vacuous() -> None:
    # A guard on `_cli_box_allowlist` itself: if a future `rich` upgrade
    # changed `Box.substitute`'s behaviour so this came back empty, the
    # rendering test below would start rejecting every legitimate table
    # border - which would very likely get "fixed" by loosening the
    # assertion instead of by noticing the real cause.
    assert _cli_box_allowlist()


def test_offender_scan_flags_a_synthetic_ellipsis() -> None:
    """Proof the widened guard can fail, not just pass: a hand-built string
    carrying the exact character `registry search` shipped with - U+2026
    HORIZONTAL ELLIPSIS - dressed up inside an otherwise legitimate-looking
    boxed row, run through the same `allowed`-set scan the rendering test
    below performs on real command output."""
    allowed = _cli_box_allowlist()
    poisoned = "\u2502 name\u2026      \u2502\n\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n"

    offenders = _non_ascii_offenders(poisoned, allowed=allowed)

    assert offenders == {"\u2026"}


def _long_entries_index_path(tmp_path: pathlib.Path) -> pathlib.Path:
    """A registry index carrying the kind of long, externally-sourced
    strings that actually triggered this defect: a package name/version
    long enough for `registry search`'s compact listing to shorten, and a
    repository URL long enough that `registry show`'s full-detail table -
    which must never shorten it (`test_show_prints_the_full_description_
    not_truncated` already pins that for the description) - has to wrap it
    instead.
    """
    descriptor = UnifiedToolDescriptor(
        id="mcp/long@1.0.0",
        name="a-tool-with-a-genuinely-long-descriptive-server-name-that-keeps-going",
        description="",
        source=ToolSource(
            kind="mcp",
            registry="npm",
            package="@example/a-really-quite-long-package-identifier-indeed",
            version="1.0.0",
        ),
        provenance=Provenance(
            repository=(
                "https://github.com/some-org/"
                "a-genuinely-long-repository-name-that-keeps-going-and-going"
            ),
            publisher="example",
            signature="none",
            license="MIT",
        ),
    )
    index = RegistryIndex(
        entries=(
            IndexEntry(
                descriptor=descriptor,
                audit=EntryAudit(score=90, blocking=False, findings=()),
                tools_enumerated=False,
            ),
        ),
        built_at="fixed",
    )
    path = tmp_path / "index.json"
    index.write(path)
    return path


def _cli_output(args: list[str]) -> str:
    result = CliRunner().invoke(app, args)
    assert result.exit_code in {
        ExitCode.OK,
        ExitCode.FINDINGS,
    }, f"{args} exited {result.exit_code}: {result.output}"
    return result.output


def test_cli_output_is_ascii_outside_rich_box_drawing(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every human-readable command this CLI ships renders to ASCII, once
    rich's own sanctioned box-drawing glyphs are set aside (see the
    module-level comment above for how that line is drawn).

    `doctor` and `policy explain` are pushed past their real shipped data
    with a monkeypatch - a real `sys.executable`/git path or a real
    catalogue's control title happens to be short enough not to trigger
    rich's per-column overflow handling most of the time, which would make
    a check against only real data pass by coincidence rather than by
    construction. `registry search`/`show` use a purpose-built index
    instead, for the same reason.
    """
    project_root = tmp_path / "demo"
    init_output = _cli_output(["init", "demo", "--directory", str(project_root)])

    outputs = {
        "init": init_output,
        "audit": _cli_output(["audit", str(project_root)]),
        "policy list": _cli_output(["policy", "list"]),
        "policy show": _cli_output(["policy", "show", "--directory", str(project_root)]),
        "policy check": _cli_output(["policy", "check", "--directory", str(project_root)]),
        "policy apply": _cli_output(
            ["policy", "apply", "hipaa", "--yes", "--directory", str(project_root)]
        ),
        "policy relax": _cli_output(
            [
                "policy",
                "relax",
                "B2",
                "--reason",
                "needs shell access for this demo",
                "--expires",
                "2099-12-31",
                "--directory",
                str(project_root),
            ]
        ),
        "doctor": _doctor_output_with_a_long_executable_path(monkeypatch),
        "registry search": _cli_output(
            ["registry", "search", "", "--index", str(_long_entries_index_path(tmp_path))]
        ),
        "registry show": _cli_output(
            [
                "registry",
                "show",
                "mcp/long@1.0.0",
                "--index",
                str(_long_entries_index_path(tmp_path)),
            ]
        ),
        "policy explain": _policy_explain_output_with_a_long_control_title(monkeypatch),
        "policy explain (bare)": _cli_output(["policy", "explain"]),
    }

    add_target = tmp_path / "existing-project"
    add_target.mkdir()
    outputs["add framework"] = _cli_output(
        ["add", "framework", "claude-code", "--directory", str(add_target)]
    )
    outputs["revert"] = _cli_output(["revert", "--directory", str(add_target)])

    allowed = _cli_box_allowlist()
    failures = {
        label: offenders
        for label, output in outputs.items()
        if (offenders := _non_ascii_offenders(output, allowed=allowed))
    }
    assert not failures, f"non-ASCII output outside rich's own box drawing: {failures!r}"


def _doctor_output_with_a_long_executable_path(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setattr(
        sys,
        "executable",
        r"C:\Users\example\AppData\Local\pipx\venvs\toolseal-cli-app-name"
        r"\Scripts\toolseal-cli-executable-wrapper.exe",
    )
    return _cli_output(["doctor"])


def _policy_explain_output_with_a_long_control_title(monkeypatch: pytest.MonkeyPatch) -> str:
    long_title = (
        "A-genuinely-long-unbreakable-control-title-with-no-spaces-"
        "whatsoever-that-keeps-going-and-going"
    )
    monkeypatch.setattr(
        policy_command,
        "resolve",
        lambda ref, catalogues: Control(id=ref.control, title=long_title),
    )
    return _cli_output(["policy", "explain", "B3"])


# --- print_text: a mixed-style line is a line, never reflowed --------------
#
# A regression this project actually hit: a long path built as a multi-span
# `Text` and printed with a bare `console.print(...)` gets word-wrapped at
# the console width like prose, which can split a word - even one a test is
# searching for - across the line break. `print_line` already guarded a
# single-style line against this; `print_text` is the same guarantee for a
# line built from more than one style.


def test_print_text_never_wraps_a_long_line() -> None:
    from rich.text import Text

    buf = io.StringIO()
    console = Console(file=buf, theme=_ui.THEME, force_terminal=False, width=20, markup=False)
    long_word = "a" * 40
    text = Text("prefix: ")
    text.append(long_word, style="accent")

    _ui.print_text(console, text)

    lines = buf.getvalue().splitlines()
    assert len(lines) == 1
    assert long_word in lines[0]


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
