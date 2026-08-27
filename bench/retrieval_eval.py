"""Measure retrieval quality against the pre-registered query set (P2).

Runs `research/probes/p2_retrieval/queries.md`'s twenty queries over the
92-tool corpus captured by P1, under two rankers:

* **baseline** - the substring matcher the registry shipped before this work,
  reimplemented here rather than imported. The original was deleted when
  `RegistryIndex.search` was replaced, and a comparison against a baseline
  nobody can run is not a comparison. The reimplementation is deliberately
  literal: `query.casefold() in haystack.casefold()` over the same fields the
  original joined, so the number it produces is what the shipped code would
  have produced.
* **bm25** - `toolseal.core.registry.retrieval.Ranker`, as wired into
  `RegistryIndex.search`.

Metrics are MRR over the `primary` answer and recall@5 over `relevant`, both
fixed in the queries document before either ranker was written.

Usage:

    uv run python bench/retrieval_eval.py [--json]
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from toolseal.core.registry.retrieval import Field, Ranker

ROOT = Path(__file__).resolve().parent.parent
CAPTURES = ROOT / "research" / "probes" / "p1_remote_mcp_annotations" / "results"
SERVERS = ("sentry", "notion", "linear")


@dataclass(frozen=True)
class Tool:
    """One captured tool, reduced to what retrieval sees."""

    id: str
    name: str
    description: str
    server: str


@dataclass(frozen=True)
class Query:
    """One pre-registered query and its fixed answers."""

    number: int
    text: str
    primary: str
    relevant: frozenset[str]
    ambiguous: bool


def load_tools() -> list[Tool]:
    tools: list[Tool] = []
    for server in SERVERS:
        payload = json.loads((CAPTURES / f"{server}-tools.json").read_text(encoding="utf-8"))
        for entry in payload["tools"]:
            tools.append(
                Tool(
                    id=f"{server}:{entry['name']}",
                    name=entry["name"],
                    description=entry.get("description") or "",
                    server=server,
                )
            )
    return tools


def load_queries(path: Path) -> list[Query]:
    """Parse the query table out of the pre-registered markdown.

    Read from the committed document rather than duplicated into this file, so
    the numbers can only ever be produced from the version-controlled
    judgments. A copy here would be a second source of truth, and the one that
    drifted would be the one generating the results.
    """
    queries: list[Query] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("| ") or line.startswith("| #") or set(line) <= set("| -"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 4 or not cells[0].isdigit():
            continue
        number, text, primary_cell, also_cell = cells[0], cells[1], cells[2], cells[3]
        notes = cells[4] if len(cells) > 4 else ""
        primary = primary_cell.strip("`")
        also = {item.strip().strip("`") for item in also_cell.split(",") if item.strip()}
        queries.append(
            Query(
                number=int(number),
                text=text,
                primary=primary,
                relevant=frozenset({primary, *also}),
                ambiguous="ambiguous" in notes.lower(),
            )
        )
    return queries


def baseline_rank(query: str, tools: list[Tool]) -> list[str]:
    """The shipped substring matcher: whole query as one contiguous needle."""
    needle = query.casefold().strip()
    return [
        tool.id
        for tool in tools
        if needle in " ".join([tool.id, tool.name, tool.description]).casefold()
    ]


def bm25_rank(query: str, tools: list[Tool], ranker: Ranker) -> list[str]:
    return [tools[index].id for index, _score in ranker.rank(query)]


def reciprocal_rank(ranking: list[str], target: str) -> float:
    return 1.0 / (ranking.index(target) + 1) if target in ranking else 0.0


def recall_at(ranking: list[str], relevant: frozenset[str], k: int) -> float:
    if not relevant:
        return 0.0
    return len(set(ranking[:k]) & relevant) / len(relevant)


def evaluate(queries: list[Query], tools: list[Tool]) -> dict[str, Any]:
    ranker = Ranker(
        [
            {
                Field.NAME: tool.name,
                Field.DESCRIPTION: tool.description,
                Field.SERVER: tool.server,
            }
            for tool in tools
        ]
    )

    rows: list[dict[str, Any]] = []
    for query in queries:
        base = baseline_rank(query.text, tools)
        bm25 = bm25_rank(query.text, tools, ranker)
        rows.append(
            {
                "n": query.number,
                "query": query.text,
                "primary": query.primary,
                "ambiguous": query.ambiguous,
                "baseline_rr": reciprocal_rank(base, query.primary),
                "bm25_rr": reciprocal_rank(bm25, query.primary),
                "baseline_recall5": recall_at(base, query.relevant, 5),
                "bm25_recall5": recall_at(bm25, query.relevant, 5),
                "bm25_top": bm25[0] if bm25 else None,
            }
        )

    def mean(key: str) -> float:
        return sum(float(row[key]) for row in rows) / len(rows) if rows else 0.0

    return {
        "corpus_tools": len(tools),
        "queries": len(rows),
        "baseline": {"mrr": mean("baseline_rr"), "recall@5": mean("baseline_recall5")},
        "bm25": {"mrr": mean("bm25_rr"), "recall@5": mean("bm25_recall5")},
        "rows": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable output.")
    args = parser.parse_args()

    tools = load_tools()
    queries = load_queries(ROOT / "research" / "probes" / "p2_retrieval" / "queries.md")
    if not queries:
        print("error: no queries parsed from the pre-registered document", file=sys.stderr)
        return 1

    report = evaluate(queries, tools)

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0

    print(f"corpus: {report['corpus_tools']} tools | queries: {report['queries']}")
    print()
    print(f"{'':3} {'query':34} {'base rr':>8} {'bm25 rr':>8}  top hit")
    for row in report["rows"]:
        mark = "*" if row["ambiguous"] else " "
        top = row["bm25_top"] or "-"
        print(
            f"{row['n']:>2}{mark} {row['query'][:34]:34} "
            f"{row['baseline_rr']:>8.2f} {row['bm25_rr']:>8.2f}  {top}"
        )
    print()
    for name in ("baseline", "bm25"):
        stats = report[name]
        print(f"{name:9} MRR {stats['mrr']:.3f}   recall@5 {stats['recall@5']:.3f}")
    print()
    print("* ambiguous: more than one defensible answer; see queries.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
