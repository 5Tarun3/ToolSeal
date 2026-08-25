"""The version-drift guard (P39 left half-closed).

`pyproject.toml` declares `[project].version`; `scripts/check_release_tag.py`
already asserts a release tag matches it. What P39 did not check is whether
the *package itself* - `toolseal.__version__`, and everything downstream of
it (`toolseal --version`, `doctor --json`) - agrees. `toolseal/__init__.py`
now derives `__version__` at import time instead of hand-duplicating the
literal, so the two can no longer drift apart; these tests are the proof.
"""

from __future__ import annotations

import tomllib
from importlib import metadata
from pathlib import Path

import pytest

import toolseal

ROOT: Path = Path(__file__).resolve().parent.parent


def _declared_pyproject_version() -> str:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def test_package_version_matches_pyproject_declared_version() -> None:
    # The one hand-maintained literal `pyproject.toml` still carries must be
    # exactly what `toolseal.__version__` reports - if these could ever
    # differ, `toolseal --version`/`doctor --json` could report a version
    # that a passing `check_release_tag.py` run never actually released.
    assert toolseal.__version__ == _declared_pyproject_version()


def test_installed_metadata_agrees_with_pyproject_too() -> None:
    # `uv run` performs an editable install before running anything in this
    # checkout, so `importlib.metadata` already resolves a real distribution
    # here - this pins that the metadata path (the one an installed wheel
    # always takes) is not silently disagreeing with `pyproject.toml` either.
    assert metadata.version("toolseal") == _declared_pyproject_version()


def test_falls_back_to_pyproject_when_no_distribution_is_installed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Simulates a source checkout with no install at all (no dist-info
    # anywhere on sys.path): `importlib.metadata.version` raises, and
    # `toolseal._read_version` must recover by reading `pyproject.toml`
    # directly rather than raising or reporting something wrong.
    def _raise(name: str) -> str:
        raise metadata.PackageNotFoundError(name)

    monkeypatch.setattr(metadata, "version", _raise)

    assert toolseal._read_version() == _declared_pyproject_version()
