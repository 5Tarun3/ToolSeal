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


def test_doctor_human_output_is_headed_and_aligned() -> None:
    result = runner.invoke(app, ["doctor"])

    lines = result.stdout.splitlines()
    assert lines[0].split()[:2] == ["field", "value"]

    # A column boundary is always a literal two-space separator between two
    # fixed-width blocks, regardless of which side is padded - so the
    # characters just before "value" must be that separator on every row, or
    # the heading and the data have drifted out of alignment.
    value_column = lines[0].index("value")
    for line in lines[1:]:
        assert line[value_column - 2 : value_column] == "  "


def test_unknown_option_is_a_usage_error() -> None:
    result = runner.invoke(app, ["--definitely-not-an-option"])

    assert result.exit_code == ExitCode.USAGE
