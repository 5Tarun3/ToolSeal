"""The CLI's public contract: version output, machine-readable mode, exit codes.

These are deliberately shallow. They pin the boundary behaviour that CI and the
evaluation harness depend on, and nothing else.
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from toolseal import __version__
from toolseal.cli import app
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
