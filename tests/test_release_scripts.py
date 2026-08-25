"""The release-tag consistency check (scripts/check_release_tag.py).

This is the one guard between a typo in a tag and an unrecoverable PyPI
release: `pyproject.toml` is the declared source of truth for the version,
and the release workflow refuses to publish unless the tag agrees with it.
Exercised as a subprocess against its real command-line contract, the same
way the release workflow invokes it, rather than against its internals -
what matters is what the process prints and the exit code it returns.

`scripts/changelog_section.py` is covered too: it decides what becomes the
GitHub release body, and a missing section should fail loudly rather than
publish with an empty one.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT: Path = Path(__file__).resolve().parent.parent
CHECK_TAG: Path = ROOT / "scripts" / "check_release_tag.py"
CHANGELOG_SECTION: Path = ROOT / "scripts" / "changelog_section.py"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    # S603: literal argv and sys.executable, against scripts in this repo.
    return subprocess.run(  # noqa: S603
        [sys.executable, *args],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


@pytest.fixture
def pyproject(tmp_path: Path) -> Path:
    """A minimal pyproject.toml declaring a fixed, non-prerelease version."""
    path = tmp_path / "pyproject.toml"
    path.write_text('[project]\nname = "demo"\nversion = "1.2.3"\n', encoding="utf-8")
    return path


@pytest.fixture
def prerelease_pyproject(tmp_path: Path) -> Path:
    """A pyproject.toml declaring a PEP 440 release-candidate version."""
    path = tmp_path / "pyproject.toml"
    path.write_text('[project]\nname = "demo"\nversion = "1.2.3rc1"\n', encoding="utf-8")
    return path


def test_matching_tag_succeeds_and_reports_final(pyproject: Path) -> None:
    result = _run(str(CHECK_TAG), "v1.2.3", str(pyproject))

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ["version=1.2.3", "prerelease=false"]


def test_matching_prerelease_tag_is_routed_to_testpypi(prerelease_pyproject: Path) -> None:
    result = _run(str(CHECK_TAG), "v1.2.3rc1", str(prerelease_pyproject))

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ["version=1.2.3rc1", "prerelease=true"]


def test_mismatched_tag_fails_loudly(pyproject: Path) -> None:
    result = _run(str(CHECK_TAG), "v9.9.9", str(pyproject))

    assert result.returncode == 1
    assert "v9.9.9" in result.stderr
    assert "1.2.3" in result.stderr
    assert result.stdout == ""


def test_a_typo_in_the_prerelease_suffix_is_a_mismatch_not_a_match(pyproject: Path) -> None:
    # Guards against a check that only compares the release segment and
    # waves a stray suffix through.
    result = _run(str(CHECK_TAG), "v1.2.3rc1", str(pyproject))

    assert result.returncode == 1
    assert result.stdout == ""


def test_tag_without_leading_v_is_rejected(pyproject: Path) -> None:
    result = _run(str(CHECK_TAG), "1.2.3", str(pyproject))

    assert result.returncode == 1
    assert "does not start with 'v'" in result.stderr


def test_wrong_argument_count_is_a_usage_error(pyproject: Path) -> None:
    assert _run(str(CHECK_TAG)).returncode == 2
    assert _run(str(CHECK_TAG), "v1.2.3", str(pyproject), "extra").returncode == 2


def test_missing_pyproject_is_reported_not_traced(tmp_path: Path) -> None:
    result = _run(str(CHECK_TAG), "v1.2.3", str(tmp_path / "does-not-exist.toml"))

    assert result.returncode == 1
    assert "Traceback" not in result.stderr


def test_changelog_section_extracts_only_that_versions_body(tmp_path: Path) -> None:
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(
        "# Changelog\n\n"
        "## [Unreleased]\n\n### Added\n\n- next thing\n\n"
        "## [1.0.0] - 2026-01-01\n\n### Added\n\n- first thing\n\n"
        "## [0.9.0] - 2025-12-01\n\n### Added\n\n- older thing\n",
        encoding="utf-8",
    )

    result = _run(str(CHANGELOG_SECTION), "1.0.0", str(changelog))

    assert result.returncode == 0, result.stderr
    assert "first thing" in result.stdout
    assert "next thing" not in result.stdout
    assert "older thing" not in result.stdout


def test_changelog_section_missing_version_fails_loudly(tmp_path: Path) -> None:
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(
        "# Changelog\n\n## [Unreleased]\n\n### Added\n\n- a thing\n", encoding="utf-8"
    )

    result = _run(str(CHANGELOG_SECTION), "1.0.0", str(changelog))

    assert result.returncode == 1
    assert "1.0.0" in result.stderr
    assert result.stdout == ""


def test_real_changelog_has_no_1_2_3_section_yet() -> None:
    """Sanity check against the repository's actual, unreleased changelog."""
    result = _run(str(CHANGELOG_SECTION), "1.2.3")

    assert result.returncode == 1
