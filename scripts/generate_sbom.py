"""Regenerate toolseal's own SBOM (check `C5`).

`toolseal.core.sbom` already builds CycloneDX documents for projects the
scaffolder creates; this reuses the same `render` function for the project's
own runtime dependencies rather than writing a second generator.

Dependency names come from `[project.dependencies]` in `pyproject.toml`, and
each is pinned to the version actually installed in the current environment
(`importlib.metadata`) - which is whatever `uv sync` resolved from `uv.lock` -
so the document reflects what is really installed rather than a guess.

Run after `uv sync` following a dependency change:

    uv run python scripts/generate_sbom.py
"""

from __future__ import annotations

import re
import tomllib
from importlib.metadata import version
from pathlib import Path

from toolseal.core.sbom import SBOM_FILENAME, render

ROOT: Path = Path(__file__).resolve().parent.parent

# The leading package name in a PEP 508 dependency string - everything before
# the first specifier, extras marker, environment marker, or whitespace.
_NAME: re.Pattern[str] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")


def _pyproject() -> dict[str, object]:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _dependency_name(requirement: str) -> str:
    match = _NAME.match(requirement.strip())
    if match is None:
        message = f"cannot parse a package name out of dependency {requirement!r}"
        raise ValueError(message)
    return match.group(0)


def main() -> None:
    project = _pyproject()["project"]
    project_name = str(project["name"])  # type: ignore[index]
    names = [_dependency_name(str(item)) for item in project["dependencies"]]  # type: ignore[index]

    pinned = tuple(f"{name}=={version(name)}" for name in names)
    (ROOT / SBOM_FILENAME).write_text(render(project_name, pinned), encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
