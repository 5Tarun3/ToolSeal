"""P16 supplement: reach curated-worthy entries a paginated crawl never sees.

`registry_seed.py` selects mechanically from an already-crawled index, but the
crawl itself is alphabetically biased: `crawl_mcp_registry`'s own docstring
records that a bounded walk from the start of the registry's listing returned
1988 of 2000 entries under the `ai.*` prefix, with a single namespace
accounting for roughly a third of the total. A widely-used server like
`@upstash/context7-mcp` or `@sentry/mcp-server` can be genuinely registered
and still never surface within any `max_pages` a `sync` would practically run.

This module does not soften the criteria to compensate. It runs the exact
same `included()` predicate `registry_seed.py` uses, against entries reached
by a different route - the registry's own `?search=` filter rather than
pagination order - and merges only the survivors into the existing curated
set. A search term that turns up nothing `included()`-worthy contributes
nothing; the report says so rather than the module lowering the bar to fill a
slot.

`SEARCH_TARGETS` pairs a search term with the exact package identifier that
confirms a hit is the tool being looked for, not a same-named impostor - the
registry's `search` matches substrings of a server's own `name`, which turns
up plenty of both. Both were verified against npm directly before this list
was written; this module re-verifies the registry's own record of each at
every run rather than trusting that verification to stay true.

Usage::

    uv run python -m bench.registry_seed_search
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Final

from bench.registry_seed import included
from toolseal.core.registry.crawl import crawl_mcp_registry
from toolseal.core.registry.index import IndexEntry, RegistryIndex

SEARCH_TARGETS: Final[tuple[tuple[str, str], ...]] = (
    ("context7", "@upstash/context7-mcp"),
    ("playwright", "@playwright/mcp"),
    ("kubernetes", "kubernetes-mcp-server"),
    ("sentry", "@sentry/mcp-server"),
)


def find(term: str, expected_package: str, *, max_pages: int = 2) -> IndexEntry | None:
    """The latest entry from searching *term* whose package is *expected_package*.

    ``None`` when the search reaches no such entry - absence is a real,
    reportable outcome here, not an error: most of the well-known reference
    servers this project checked (`mcp-server-fetch`, `mcp-server-git`,
    `@modelcontextprotocol/server-filesystem`, among others) are simply not
    registered with this particular registry at all, and searching harder for
    them does not change that.
    """
    report = crawl_mcp_registry(search=term, max_pages=max_pages)
    matches = [
        entry
        for entry in report.entries
        if entry.descriptor.source.package == expected_package and entry.descriptor.is_latest
    ]
    return matches[0] if matches else None


def run(curated_path: Path) -> tuple[RegistryIndex, tuple[str, ...], tuple[str, ...]]:
    """Merge every qualifying search target into *curated_path*'s current contents."""
    curated = RegistryIndex.read(curated_path)
    by_id = {entry.id: entry for entry in curated.entries}
    added: list[str] = []
    skipped: list[str] = []

    for term, expected_package in SEARCH_TARGETS:
        found = find(term, expected_package)
        if found is None:
            skipped.append(f"{term} ({expected_package}): not found via search")
            continue
        if not included(found):
            skipped.append(f"{term} ({expected_package}): found but fails curation criteria")
            continue
        by_id[found.id] = found
        added.append(found.id)

    merged = RegistryIndex(
        entries=tuple(sorted(by_id.values(), key=lambda e: e.id)), built_at=curated.built_at
    )
    return merged, tuple(added), tuple(skipped)


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="registry_seed_search",
        description="Supplement the curated registry with entries a paginated crawl cannot reach.",
    )
    parser.add_argument(
        "--curated",
        type=Path,
        default=Path("src/toolseal/data/registry/curated.json"),
        help="The curated index to read and rewrite in place.",
    )
    args = parser.parse_args()

    merged, added, skipped = run(args.curated)
    merged.write(args.curated)

    print(f"added {len(added)}: {', '.join(added) or '(none)'}")
    for line in skipped:
        print(f"skipped: {line}")
    print(f"curated set now has {len(merged)} entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
