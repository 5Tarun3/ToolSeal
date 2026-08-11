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


def test_unknown_option_is_a_usage_error() -> None:
    result = runner.invoke(app, ["--definitely-not-an-option"])

    assert result.exit_code == ExitCode.USAGE
