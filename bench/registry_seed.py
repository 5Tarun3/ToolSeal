"""P16: seed the registry from an already-crawled index, mechanically.

Criteria are fixed in `research/registry-curation-criteria.md`, committed
before this module existed and before any curated set was produced - see that
document's own note on why the ordering matters. This module is the
mechanical *application* of those criteria: a script decides membership, not
a person, so the result is reproducible and reviewable rather than
hand-picked.

Nothing here reads `entry.audit` (`EntryAudit.score`, `.blocking`,
`.findings`). `included()` only inspects `entry.descriptor` - the same
normalized record the crawl produces before any assessment runs - which is
what makes "the audit score played no part in selection" a checkable claim
about this code rather than an assertion about intent.

Usage, against a local crawl already produced by `toolseal registry sync`::

    uv run python -m bench.registry_seed ~/.cache/toolseal/index.json \\
        --out src/toolseal/data/registry/curated.json
"""

from __future__ import annotations

import argparse
import hashlib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from toolseal.core.registry.index import IndexEntry, RegistryIndex

VERIFIABLE_REGISTRIES: Final[frozenset[str]] = frozenset({"npm", "pypi"})
"""The two channels `core.registry.resolve.resolve()` checks by default for
check C3 (ToolGate) - the registries this project can independently
re-verify a package still resolves in, without adding a new verification
channel. Named once here so this module and the criteria document it
implements cannot drift apart silently."""

CAP: Final = 200
FLOOR: Final = 100


def included(entry: IndexEntry) -> bool:
    """Whether *entry* satisfies every inclusion rule in
    `research/registry-curation-criteria.md`.

    Reads only `entry.descriptor` fields - never `entry.audit` - by
    construction.
    """
    descriptor = entry.descriptor
    return (
        descriptor.source.registry in VERIFIABLE_REGISTRIES
        and bool(descriptor.provenance.repository)
        and bool(descriptor.description.strip())
        and descriptor.is_latest
        and descriptor.status == "active"
    )


def select(index: RegistryIndex) -> tuple[IndexEntry, ...]:
    """Apply the fixed criteria, then the cap, deterministically.

    Survivors are sorted by `id` alone - the index's own canonical sort key
    (`RegistryIndex.to_dict()` already orders entries this way) - and never
    by anything derived from `EntryAudit`. Calling this twice on the same
    *index* yields the same tuple, in the same order, every time.
    """
    survivors = sorted((entry for entry in index.entries if included(entry)), key=lambda e: e.id)
    return tuple(survivors[:CAP])


@dataclass(frozen=True)
class SelectionReport:
    """What a selection run produced, for the P16 report - never for the
    shipped `curated.json` itself, which stays in plain `RegistryIndex` shape
    so the exact same reader (`RegistryIndex.read`/`read_packaged`) that
    loads a synced cache also loads the curated set."""

    source_path: str
    source_sha256: str
    source_built_at: str
    source_count: int
    selected_count: int
    score_buckets: dict[str, int]
    with_repository: int
    is_latest_count: int
    registry_split: dict[str, int]

    def to_dict(self) -> dict[str, object]:
        return {
            "source_path": self.source_path,
            "source_sha256": self.source_sha256,
            "source_built_at": self.source_built_at,
            "source_count": self.source_count,
            "selected_count": self.selected_count,
            "score_buckets": dict(sorted(self.score_buckets.items())),
            "with_repository": self.with_repository,
            "is_latest_count": self.is_latest_count,
            "registry_split": dict(sorted(self.registry_split.items())),
        }

    def render(self) -> str:
        lines = [
            f"source: {self.source_path}",
            f"  sha256      {self.source_sha256}",
            f"  built_at    {self.source_built_at}",
            f"  entries     {self.source_count}",
            f"selected: {self.selected_count} "
            f"(floor {FLOOR}, cap {CAP}; not tuned to fall inside this range)",
            f"  with repository declared   {self.with_repository}/{self.selected_count}",
            f"  is_latest                  {self.is_latest_count}/{self.selected_count}",
            f"  registry split             {dict(sorted(self.registry_split.items()))}",
            f"  audit score buckets        {dict(sorted(self.score_buckets.items()))}",
            "  (score buckets are reported here, never used as a selection input)",
        ]
        return "\n".join(lines)


def _score_bucket(score: int) -> str:
    floor = (score // 20) * 20
    return f"{floor}-{floor + 19}"


def report_for(
    source_path: Path, source: RegistryIndex, selected: tuple[IndexEntry, ...]
) -> SelectionReport:
    raw = source_path.read_bytes()
    buckets = Counter(_score_bucket(entry.audit.score) for entry in selected)
    registries = Counter(entry.descriptor.source.registry for entry in selected)
    return SelectionReport(
        source_path=str(source_path),
        source_sha256=hashlib.sha256(raw).hexdigest(),
        source_built_at=source.built_at,
        source_count=len(source),
        selected_count=len(selected),
        score_buckets=dict(buckets),
        with_repository=sum(1 for e in selected if e.descriptor.provenance.repository),
        is_latest_count=sum(1 for e in selected if e.descriptor.is_latest),
        registry_split=dict(registries),
    )


def run(source_path: Path) -> tuple[RegistryIndex, SelectionReport]:
    """Read *source_path*, select, and build the curated index plus its report."""
    source = RegistryIndex.read(source_path)
    selected = select(source)
    curated = RegistryIndex(entries=selected, built_at=source.built_at)
    return curated, report_for(source_path, source, selected)


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="registry_seed",
        description="Apply the P16 curation criteria to an already-crawled registry index.",
    )
    parser.add_argument(
        "source",
        type=Path,
        help="Path to an index from `toolseal registry sync` (e.g. ~/.cache/toolseal/index.json).",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("src/toolseal/data/registry/curated.json"),
        help="Where to write the curated index (default: the shipped package location).",
    )
    args = parser.parse_args()

    curated, report = run(args.source)
    curated.write(args.out)

    print(report.render())
    print(f"wrote {len(curated)} entries to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
