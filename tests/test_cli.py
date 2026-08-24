"""The CLI's public contract: version output, machine-readable mode, exit codes.

These are deliberately shallow. They pin the boundary behaviour that CI and the
evaluation harness depend on, and nothing else.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import toolseal.cli as cli_module
from toolseal import __version__
from toolseal.cli import app
from toolseal.cli.errors import format_error_line
from toolseal.errors import ExitCode

runner = CliRunner()


def test_version_reports_package_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == ExitCode.OK
    assert __version__ in result.stdout


def test_doctor_json_is_parseable() -> None:
    result = runner.invoke(app, ["doctor", "--json"])

    assert result.exit_code == ExitCode.OK
    report = json.loads(result.stdout)
    assert report["toolseal"] == __version__


def test_doctor_human_output_includes_python_version() -> None:
    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == ExitCode.OK
    assert "python" in result.stdout


def _unbordered_tokens(line: str) -> list[str]:
    """*line*'s whitespace-split tokens, with a leading/trailing panel
    border token dropped if present.

    `doctor` frames its table in a `rich.panel.Panel` (spec: every command's
    report is framed, not a bare table), so the border can be either "|" (a
    console that cannot encode box-drawing - see `rich`'s own ASCII
    fallback) or the unicode "|" it draws by default; either way it is its
    own token once split on whitespace, never fused onto "field" or "value".
    """
    tokens = line.split()
    border_chars = {"|", "│"}
    if tokens and tokens[0] in border_chars:
        tokens = tokens[1:]
    if tokens and tokens[-1] in border_chars:
        tokens = tokens[:-1]
    return tokens


def _strip_frame(line: str) -> str:
    """*line* with a leading "border + one space" and trailing "space +
    border" removed, if the panel `doctor` is drawn in put them there."""
    for left, right in (("│ ", " │"), ("| ", " |")):
        if line.startswith(left) and line.endswith(right):
            return line[len(left) : -len(right)]
    return line


def test_doctor_human_output_is_headed_and_aligned() -> None:
    result = runner.invoke(app, ["doctor"])

    lines = result.stdout.splitlines()

    # The header must exist somewhere in the output - not necessarily on
    # line zero, which would rule out ever framing this table in a panel
    # the way every other command's report is framed (spec).
    header_index = next(
        index
        for index, line in enumerate(lines)
        if _unbordered_tokens(line)[:2] == ["field", "value"]
    )
    header = lines[header_index]

    # `rich.table`'s `box.SIMPLE` draws one rule line under the header (spec
    # §5) before the data rows begin. `rich` substitutes an ASCII "-" for
    # the unicode "─" itself when the target console cannot encode it (a
    # degrading Windows console, for instance) - a real, expected rendering
    # this test must accept rather than pinning the unicode form and
    # breaking outside `CliRunner`'s own encoding.
    rule = set(_strip_frame(lines[header_index + 1]).strip())
    assert rule in ({"─"}, {"-"})

    # A column boundary is always a literal two-space separator between two
    # fixed-width blocks, regardless of which side is padded - so the
    # characters just before "value" must be that separator on every data
    # row, or the heading and the data have drifted out of alignment. Only
    # rows with actual content are checked, so a panel's closing border
    # line (all box-drawing characters, no alphanumerics) is not mistaken
    # for a mis-aligned row.
    value_column = header.index("value")
    data_lines = [line for line in lines[header_index + 2 :] if any(c.isalnum() for c in line)]
    assert data_lines
    for line in data_lines:
        assert line[value_column - 2 : value_column] == "  "


def test_unknown_option_is_a_usage_error() -> None:
    result = runner.invoke(app, ["--definitely-not-an-option"])

    assert result.exit_code == ExitCode.USAGE


# --- --help grouping (owner's remark: "the --help has better UI than the
# tool itself") -------------------------------------------------------------


def test_top_level_help_groups_commands_by_pillar() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == ExitCode.OK
    # Nine subcommands used to render as one undifferentiated list; grouped
    # by pillar now (`rich_help_panel`, public Typer API - see `cli/
    # __init__.py`'s registration block for which command lands where and
    # why).
    for panel_title in ("Scaffold", "Registry", "Audit", "Diagnostics"):
        assert panel_title in result.stdout


def test_add_help_splits_scaffold_from_translate() -> None:
    # `add`'s two subcommands sit on two different pillars even though both
    # live under the same top-level verb - `framework` extends scaffolding
    # in place, `mcp` is the Translate pillar (README: "make any indexed
    # tool usable from any supported framework"). That distinction is only
    # visible one level down, on `add`'s own help.
    result = runner.invoke(app, ["add", "--help"])

    assert result.exit_code == ExitCode.OK
    assert "Scaffold" in result.stdout
    assert "Translate" in result.stdout


# --- error output (errors.py) -----------------------------------------------


def test_format_error_line_names_the_exit_code_by_number_and_word() -> None:
    line = format_error_line("error", "something went wrong", ExitCode.USAGE)

    assert line == "error: something went wrong (exit 2: usage)"


def test_format_error_line_appends_a_hint_when_given_one() -> None:
    line = format_error_line(
        "internal error", "boom", ExitCode.INTERNAL, hint="re-run with --verbose for a traceback"
    )

    assert line == "internal error: boom (exit 3: internal) - re-run with --verbose for a traceback"


def test_usage_error_names_the_exit_code(tmp_path: Path) -> None:
    # `revert` with nothing to undo is the plainest `UsageError` in the CLI -
    # no fixture beyond an empty directory needed.
    result = runner.invoke(app, ["revert", "--directory", str(tmp_path)])

    assert result.exit_code == ExitCode.USAGE
    assert "error: nothing to revert" in result.output
    assert "(exit 2: usage)" in result.output


def test_main_reports_an_unexpected_exception_with_a_verbose_hint(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # An exception that is not a `ToolsealError` at all - a genuine bug, not
    # a recognised failure mode - reaches `main()`'s last-resort handler.
    # The traceback `log.debug` captures there is otherwise invisible unless
    # `--verbose` raises the root logger to DEBUG, so that flag is the one
    # generic pointer worth naming (errors.py: "a second, generic [pointer]
    # here would be chrome an error is not the place for" - except here,
    # where nothing more specific exists to point at).
    def boom() -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(cli_module, "app", boom)

    exit_code = cli_module.main()
    captured = capsys.readouterr()

    assert exit_code == int(ExitCode.INTERNAL)
    assert "internal error: RuntimeError: boom" in captured.err
    assert "(exit 3: internal)" in captured.err
    assert "--verbose" in captured.err
