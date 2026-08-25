"""Secure-by-default scaffolding and cross-framework tool registry for agentic systems."""

from __future__ import annotations

import tomllib
from importlib import metadata
from pathlib import Path

_DISTRIBUTION_NAME = "toolseal"


def _read_version() -> str:
    """The single source of truth is `pyproject.toml`'s `[project].version` -
    the same field `scripts/check_release_tag.py` already treats as
    canonical when it checks a release tag against it. Rather than keeping a
    second hand-maintained copy here (the drift P39 left open: the tag guard
    checks `pyproject.toml`, nothing checked this module), this reads it
    back at import time instead of re-declaring it.

    Two contexts both have to work, and they resolve the value differently:

    * An **installed wheel** always carries `*.dist-info/METADATA`, written
      from `pyproject.toml` at build time - `importlib.metadata.version`
      (stdlib, no new dependency) resolves it directly, with no filesystem
      layout assumptions at all.
    * A **source checkout** resolves the same way once *any* install has
      happened - including the editable install `uv run`/`uv sync` performs
      automatically, which writes the same dist-info into the project's own
      `.venv`. Only a checkout with no install whatsoever (no dist-info
      anywhere `importlib.metadata` looks) falls through to reading
      `pyproject.toml` straight off disk, exactly the way
      `check_release_tag.declared_version` already does - so this module
      never has to guess and never reports a version that does not exist
      somewhere on disk.
    """
    try:
        return metadata.version(_DISTRIBUTION_NAME)
    except metadata.PackageNotFoundError:
        pyproject = Path(__file__).resolve().parent.parent.parent / "pyproject.toml"
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        return str(data["project"]["version"])


__version__ = _read_version()

__all__ = ["__version__"]
