"""Assert a release tag matches the version declared in `pyproject.toml`.

PyPI has no undo: a tag that races ahead of (or lags behind) the declared
version publishes an artefact nobody can recall. `pyproject.toml` is kept as
the single source of truth for the version rather than adding a versioning
plugin, which means the release workflow has to *check* the two agree instead
of deriving one from the other. This script is that check.

It also decides, from the tag alone, whether this is a pre-release: a tag
carrying a PEP 440 pre-release segment (`a`, `b`, `rc`, or `.dev`, e.g.
`v0.1.0rc1`) is routed to TestPyPI instead of the real index, so a pre-alpha
project can rehearse the whole release path without burning a version number
on PyPI.

Usage:

    uv run python scripts/check_release_tag.py <tag> [pyproject]

`[pyproject]` defaults to `pyproject.toml` at the repository root; the
argument exists so this can be exercised against a fixture file in tests
without touching the real one.

On a match, prints `prerelease=true` or `prerelease=false` to stdout and
exits 0. On a mismatch or a malformed tag, prints why to stderr and exits 1.
Exits 2 for a usage error (wrong number of arguments).
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT: Path = Path(__file__).resolve().parent.parent

# A tag is `v` followed by the exact string declared as `[project].version`.
_TAG: re.Pattern[str] = re.compile(r"^v(?P<version>.+)$")

# PEP 440's pre-release segment: `a`, `b`, or `rc` each optionally followed by
# a number, or a `.dev` segment - anywhere near the end of the version.
_PRERELEASE: re.Pattern[str] = re.compile(r"(?:(?:a|b|rc)\d*|\.dev\d*)$")


def declared_version(pyproject: Path = ROOT / "pyproject.toml") -> str:
    """The version declared in `[project].version`."""
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    project = data["project"]
    return str(project["version"])


def version_from_tag(tag: str) -> str:
    """The version a tag claims to release, stripped of its leading `v`."""
    match = _TAG.match(tag)
    if match is None:
        message = f"tag {tag!r} does not start with 'v'"
        raise ValueError(message)
    return match.group("version")


def is_prerelease(version: str) -> bool:
    """Whether a version string carries a PEP 440 pre-release segment."""
    return _PRERELEASE.search(version) is not None


def check(tag: str, declared: str) -> bool:
    """Return whether `tag` is a pre-release, after asserting it matches.

    Raises `ValueError` - with a message safe to print directly - if the tag
    is malformed or does not match the declared version.
    """
    tag_version = version_from_tag(tag)
    if tag_version != declared:
        message = (
            f"tag {tag!r} declares version {tag_version!r}, but pyproject.toml "
            f"declares {declared!r}. Refusing to release."
        )
        raise ValueError(message)
    return is_prerelease(declared)


def main(argv: list[str]) -> int:
    if len(argv) not in (1, 2):
        print("usage: check_release_tag.py <tag> [pyproject]", file=sys.stderr)
        return 2

    tag = argv[0]
    pyproject = Path(argv[1]) if len(argv) == 2 else ROOT / "pyproject.toml"

    try:
        prerelease = check(tag, declared_version(pyproject))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"prerelease={'true' if prerelease else 'false'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
