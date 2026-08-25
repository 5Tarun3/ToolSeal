"""Extract one version's section from `CHANGELOG.md`, for use as a release body.

Keep a Changelog puts unreleased work under an `## [Unreleased]` heading;
cutting a release means renaming that heading to `## [X.Y.Z] - YYYY-MM-DD`
before tagging. This script finds the section for a given version and prints
it, so the release workflow can use it verbatim as the GitHub release body
instead of duplicating the text or inventing one.

Failing to find the section is treated as an error, not an empty result: it
almost always means the changelog was not updated before the tag was cut, and
a release with no notes is a symptom worth stopping for.

Usage:

    uv run python scripts/changelog_section.py <version> [changelog]

`<version>` is the bare version (no leading `v`), matching `pyproject.toml`'s
`[project].version` - e.g. `0.1.0`, not `v0.1.0`. `[changelog]` defaults to
`CHANGELOG.md` at the repository root.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT: Path = Path(__file__).resolve().parent.parent

# A version heading, capturing everything after the version itself (a date,
# or nothing) so the heading line can be reproduced unchanged in the output.
_HEADING: re.Pattern[str] = re.compile(r"^##\s+\[(?P<version>[^\]]+)\]")


def extract(text: str, version: str) -> str:
    """The body of the `## [version]` section, excluding its own heading.

    Raises `ValueError` - with a message safe to print directly - if no
    heading matches `version` exactly.
    """
    lines = text.splitlines()
    start: int | None = None
    for index, line in enumerate(lines):
        match = _HEADING.match(line)
        if match is not None and match.group("version") == version:
            start = index + 1
            break

    if start is None:
        message = f"no '## [{version}]' section in the changelog"
        raise ValueError(message)

    end = len(lines)
    for index in range(start, len(lines)):
        if _HEADING.match(lines[index]) is not None:
            end = index
            break

    section = "\n".join(lines[start:end]).strip("\n")
    if not section:
        message = f"'## [{version}]' section in the changelog is empty"
        raise ValueError(message)
    return section


def main(argv: list[str]) -> int:
    if len(argv) not in (1, 2):
        print("usage: changelog_section.py <version> [changelog]", file=sys.stderr)
        return 2

    version = argv[0]
    changelog = Path(argv[1]) if len(argv) == 2 else ROOT / "CHANGELOG.md"

    try:
        section = extract(changelog.read_text(encoding="utf-8"), version)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(section)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
