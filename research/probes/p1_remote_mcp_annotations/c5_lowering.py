"""C5 against real annotations: what survives lowering 92 production tools.

Probe P0 measured translation loss with a synthetic fixture server whose
annotations were ground truth by construction. This module runs the same
lattice over the *real* `tools/list` responses captured in `results/`, so the
question stops being "what would be lost, given a tool that declares
everything" and becomes "what is lost, given what these vendors actually
declare".

The difference matters because real declarations are uneven. A tool that never
set `idempotentHint` has nothing to preserve and nothing to compensate, so it
lowers losslessly into a target that cannot express idempotence at all - the
absence of a hint flatters the target. Counting that as a success would
overstate how much every framework carries, which is exactly the error this
probe exists to avoid.

Run:  .venv/Scripts/python.exe research/probes/p1_remote_mcp_annotations/c5_lowering.py
"""

from __future__ import annotations

import json
import pathlib
import sys
from collections import Counter
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3] / "src"))

from toolseal.core.properties import ANNOTATION_PROPERTIES
from toolseal.core.registry.utd import (
    SecurityAnnotations,
    ToolSource,
    UnifiedToolDescriptor,
)
from toolseal.core.translate.lattice import plan_translation

HERE = pathlib.Path(__file__).parent
RESULTS = HERE / "results"

SERVERS = {
    "sentry": "https://mcp.sentry.dev/mcp",
    "notion": "https://mcp.notion.com/mcp",
    "linear": "https://mcp.linear.app/mcp",
}

TARGETS = ("langchain", "crewai", "claude-code")


def descriptors(server: str, url: str) -> list[UnifiedToolDescriptor]:
    """Every captured tool for *server*, as registry descriptors.

    Annotation hints are carried across exactly as declared: a hint the server
    omitted stays `None`, never `False`, so `declared()` reports what the
    author asserted rather than a set of defaults.
    """
    payload = json.loads((RESULTS / f"{server}-tools.json").read_text(encoding="utf-8"))
    source = ToolSource(kind="mcp", registry="remote", package=url, version="captured")
    out = []
    for tool in payload["tools"]:
        raw: dict[str, Any] = tool.get("annotations") or {}
        out.append(
            UnifiedToolDescriptor(
                id=f"{server}/{tool['name']}",
                name=tool["name"],
                description=tool.get("description") or "",
                source=source,
                input_schema=tool.get("inputSchema") or {},
                annotations=SecurityAnnotations(
                    read_only=raw.get("readOnlyHint"),
                    destructive=raw.get("destructiveHint"),
                    idempotent=raw.get("idempotentHint"),
                    open_world=raw.get("openWorldHint"),
                ),
            )
        )
    return out


def main() -> int:
    all_tools = [d for s, u in SERVERS.items() for d in descriptors(s, u)]
    print(f"Loaded {len(all_tools)} captured tools\n")

    # What the sources actually declare, before any target is considered.
    declared_counts: Counter[str] = Counter()
    for d in all_tools:
        for prop in d.declared_properties():
            declared_counts[str(prop)] += 1
    print("--- declared properties across the corpus ---")
    for prop, n in declared_counts.most_common():
        print(f"  {prop:22} {n:3}/{len(all_tools)}")

    print("\n--- lowering outcomes per target ---")
    rows: dict[str, dict[str, Any]] = {}
    for target in TARGETS:
        lossless = 0
        guard_kinds: Counter[str] = Counter()
        prop_fate: dict[str, Counter[str]] = {}
        for d in all_tools:
            plan = plan_translation(
                d.declared_properties(), "mcp", target, values=d.annotation_values()
            )
            if plan.is_lossless:
                lossless += 1
            for g in plan.guards:
                guard_kinds[str(g.kind)] += 1
            for prop in d.declared_properties():
                fate = (
                    "preserved"
                    if prop in plan.preserved
                    else "compensated"
                    if prop in plan.compensated
                    else "unsupported"
                )
                prop_fate.setdefault(str(prop), Counter())[fate] += 1
        rows[target] = {
            "lossless": lossless,
            "guards": dict(guard_kinds),
            "prop_fate": {k: dict(v) for k, v in prop_fate.items()},
        }
        print(f"\n[{target}]")
        print(f"  lossless tools: {lossless}/{len(all_tools)}")
        print(f"  guards synthesised: {sum(guard_kinds.values())}")
        for kind, n in guard_kinds.most_common():
            print(f"      {kind:24} {n:3}")

    # The headline C5 claim: the same tool lowers differently per framework.
    print("\n--- per-property fate (preserved / compensated / unsupported) ---")
    props = sorted({p for r in rows.values() for p in r["prop_fate"]})
    header = f"{'property':22}" + "".join(f"{t:>34}" for t in TARGETS)
    print(header)
    for prop in props:
        line = f"{prop:22}"
        for target in TARGETS:
            f = rows[target]["prop_fate"].get(prop, {})
            cell = f"{f.get('preserved', 0)}/{f.get('compensated', 0)}/{f.get('unsupported', 0)}"
            line += f"{cell:>34}"
        print(line)

    # Absence is not preservation: how much of each target's "success" is
    # simply hints the vendors never declared.
    print("\n--- undeclared annotation hints (nothing to lose) ---")
    for name, url in SERVERS.items():
        ds = descriptors(name, url)
        missing = sum(
            1 for d in ds for p in ANNOTATION_PROPERTIES if p not in d.declared_properties()
        )
        total = len(ds) * len(ANNOTATION_PROPERTIES)
        print(f"  {name:7} {missing:3}/{total:3} annotation slots never declared")

    (RESULTS / "c5-lowering.json").write_text(
        json.dumps({"tool_count": len(all_tools), "targets": rows}, indent=2) + "\n",
        encoding="utf-8",
    )
    print("\nwrote results/c5-lowering.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
