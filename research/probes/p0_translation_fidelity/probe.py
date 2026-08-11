"""P0 - measure what cross-framework tool translation preserves and what it loses.

The plan (step P0) treats this as a falsification probe: contribution C5 and check
family G assume that popular MCP adapters silently drop security-relevant tool
metadata. This script decides that empirically instead of assuming it.

Method
------
`fixture_server.py` declares three MCP tools carrying every property under test:
the four MCP annotation hints, and JSON Schema constraints (enum, numeric
bounds, string pattern and length). Those declarations are the ground truth.

Each adapter under test loads the same server, and the resulting framework-native
tool is compared against ground truth property by property. Four verdicts are
possible:

* ``preserved``  - the property survived translation intact
* ``dropped``    - the property is not reachable on the translated tool
* ``mutated``    - the property survived but its value changed
* ``unknown``    - the adapter could not be evaluated

A second check calls each tool with arguments that violate its own schema, to
distinguish a constraint that is *present* from one that is *enforced*, and to
see whether an MCP error result stays distinguishable from a successful call.

Run
---
    uv sync --group research
    uv run python research/probes/p0_translation_fidelity/probe.py
"""

from __future__ import annotations

import asyncio
import importlib.metadata as metadata
import json
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "fixture_server.py"
RESULTS = HERE / "results"

ANNOTATION_HINTS = (
    "readOnlyHint",
    "destructiveHint",
    "idempotentHint",
    "openWorldHint",
    "title",
)

# JSON Schema keywords that carry a security meaning: each one narrows what a
# caller may pass, so losing one widens the tool's effective attack surface.
CONSTRAINT_KEYWORDS = (
    "enum",
    "minimum",
    "maximum",
    "minLength",
    "maxLength",
    "pattern",
)

# Attributes worth searching for annotation data. Adapters have no shared
# convention, so the probe looks everywhere plausible rather than assuming one.
ANNOTATION_CARRIERS = ("metadata", "annotations", "extras", "tags", "meta")

PRESERVED = "preserved"
DROPPED = "dropped"
MUTATED = "mutated"
UNKNOWN = "unknown"


@dataclass(frozen=True)
class Finding:
    """One property of one tool, as seen through one adapter."""

    adapter: str
    tool: str
    prop: str
    verdict: str
    expected: Any = None
    observed: Any = None
    note: str = ""


@dataclass
class TranslatedTool:
    """An adapter's output, normalised so adapters can be compared to each other."""

    name: str
    description: str
    input_schema: dict[str, Any]
    annotations: dict[str, Any]
    carrier: str = ""


# ---------------------------------------------------------------------------
# Ground truth
# ---------------------------------------------------------------------------


async def collect_ground_truth() -> dict[str, dict[str, Any]]:
    """Read the fixture server's own tool declarations."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(command=sys.executable, args=[str(FIXTURE)])
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        listed = await session.list_tools()
        return {tool.name: tool.model_dump(mode="json") for tool in listed.tools}


# ---------------------------------------------------------------------------
# Adapters under test
# ---------------------------------------------------------------------------


def _find_annotations(obj: object) -> tuple[dict[str, Any], str]:
    """Search an object's plausible carriers for MCP annotation hints.

    Returns the hints found and the attribute they were found on, so the report
    can state *where* an adapter chose to put them.
    """
    for carrier in ANNOTATION_CARRIERS:
        value = getattr(obj, carrier, None)
        if isinstance(value, dict) and any(hint in value for hint in ANNOTATION_HINTS):
            return value, carrier
    return {}, ""


def _as_json_schema(schema: object) -> dict[str, Any]:
    """Normalise an args schema to plain JSON Schema, whatever form it arrives in."""
    if isinstance(schema, dict):
        return schema
    model_schema = getattr(schema, "model_json_schema", None)
    if callable(model_schema):
        result = model_schema()
        if isinstance(result, dict):
            return result
    return {}


async def probe_langchain() -> tuple[list[TranslatedTool], list[Finding]]:
    """langchain-mcp-adapters: MCP session -> LangChain StructuredTool."""
    from langchain_mcp_adapters.tools import load_mcp_tools
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(command=sys.executable, args=[str(FIXTURE)])
    translated: list[TranslatedTool] = []
    findings: list[Finding] = []

    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        tools = await load_mcp_tools(session)

        for tool in tools:
            annotations, carrier = _find_annotations(tool)
            translated.append(
                TranslatedTool(
                    name=tool.name,
                    description=tool.description or "",
                    input_schema=_as_json_schema(getattr(tool, "args_schema", None)),
                    annotations=annotations,
                    carrier=carrier,
                )
            )

        findings.extend(await _langchain_enforcement(tools))

    return translated, findings


async def _langchain_enforcement(tools: list[Any]) -> list[Finding]:
    """Call tools with schema-violating arguments and record what happens."""
    findings: list[Finding] = []
    by_name = {tool.name: tool for tool in tools}

    violations = {
        "read_document": ({"path": "/etc/passwd"}, "pattern"),
        "delete_records": ({"table": "secrets", "limit": 5}, "enum"),
    }

    for name, (payload, keyword) in violations.items():
        tool = by_name.get(name)
        if tool is None:
            continue
        try:
            result = await tool.ainvoke(payload)
        # Broad by design: any rejection at all is the outcome under test.
        except Exception as exc:
            findings.append(
                Finding(
                    adapter="langchain-mcp-adapters",
                    tool=name,
                    prop=f"enforcement.{keyword}",
                    verdict=PRESERVED,
                    note=f"client raised {type(exc).__name__}",
                )
            )
            continue

        text = json.dumps(result, default=str)
        server_rejected = "validation error" in text or "Error executing tool" in text
        findings.append(
            Finding(
                adapter="langchain-mcp-adapters",
                tool=name,
                prop=f"enforcement.{keyword}",
                verdict=DROPPED if server_rejected else UNKNOWN,
                observed=text[:200],
                note=(
                    "no client-side rejection; the invalid call reached the server, "
                    "which rejected it and returned the error as ordinary tool content"
                    if server_rejected
                    else "invalid call was neither rejected nor flagged"
                ),
            )
        )

        findings.append(
            Finding(
                adapter="langchain-mcp-adapters",
                tool=name,
                prop="error_semantics.isError",
                verdict=MUTATED if server_rejected else UNKNOWN,
                observed=text[:200],
                note="MCP error result surfaced as tool content, not as an exception",
            )
        )

    return findings


def probe_crewai() -> tuple[list[TranslatedTool], list[Finding]]:
    """crewai-tools MCPServerAdapter: MCP stdio server -> CrewAI BaseTool."""
    from crewai_tools import MCPServerAdapter
    from mcp import StdioServerParameters

    params = StdioServerParameters(command=sys.executable, args=[str(FIXTURE)])
    translated: list[TranslatedTool] = []

    with MCPServerAdapter(params) as tools:
        for tool in tools:
            annotations, carrier = _find_annotations(tool)
            translated.append(
                TranslatedTool(
                    name=tool.name,
                    description=tool.description or "",
                    input_schema=_as_json_schema(getattr(tool, "args_schema", None)),
                    annotations=annotations,
                    carrier=carrier,
                )
            )

    return translated, []


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------


def _constraints_in(schema: dict[str, Any]) -> dict[str, Any]:
    """Flatten a schema's properties into ``field.keyword -> value`` pairs."""
    found: dict[str, Any] = {}
    for field, spec in (schema.get("properties") or {}).items():
        if not isinstance(spec, dict):
            continue
        for keyword in CONSTRAINT_KEYWORDS:
            if keyword in spec:
                found[f"{field}.{keyword}"] = spec[keyword]
    return found


def compare(
    adapter: str,
    truth: dict[str, dict[str, Any]],
    translated: list[TranslatedTool],
) -> list[Finding]:
    """Compare an adapter's output against ground truth, property by property."""
    findings: list[Finding] = []
    by_name = {tool.name: tool for tool in translated}

    for name, source in truth.items():
        actual = by_name.get(name)
        if actual is None:
            findings.append(
                Finding(
                    adapter=adapter,
                    tool=name,
                    prop="tool",
                    verdict=DROPPED,
                    note="tool absent after translation",
                )
            )
            continue

        # 1. Annotation hints.
        for hint in ANNOTATION_HINTS:
            expected = (source.get("annotations") or {}).get(hint)
            if expected is None:
                continue
            if hint not in actual.annotations:
                findings.append(
                    Finding(
                        adapter=adapter,
                        tool=name,
                        prop=f"annotation.{hint}",
                        verdict=DROPPED,
                        expected=expected,
                        note="no carrier on the translated tool holds this hint",
                    )
                )
            elif actual.annotations[hint] != expected:
                findings.append(
                    Finding(
                        adapter=adapter,
                        tool=name,
                        prop=f"annotation.{hint}",
                        verdict=MUTATED,
                        expected=expected,
                        observed=actual.annotations[hint],
                    )
                )
            else:
                findings.append(
                    Finding(
                        adapter=adapter,
                        tool=name,
                        prop=f"annotation.{hint}",
                        verdict=PRESERVED,
                        expected=expected,
                        observed=actual.annotations[hint],
                        note=f"carried on .{actual.carrier}",
                    )
                )

        # 2. Schema constraints.
        expected_constraints = _constraints_in(source.get("inputSchema") or {})
        observed_constraints = _constraints_in(actual.input_schema)
        for key, expected in expected_constraints.items():
            if key not in observed_constraints:
                findings.append(
                    Finding(
                        adapter=adapter,
                        tool=name,
                        prop=f"constraint.{key}",
                        verdict=DROPPED,
                        expected=expected,
                    )
                )
            elif observed_constraints[key] != expected:
                findings.append(
                    Finding(
                        adapter=adapter,
                        tool=name,
                        prop=f"constraint.{key}",
                        verdict=MUTATED,
                        expected=expected,
                        observed=observed_constraints[key],
                    )
                )
            else:
                findings.append(
                    Finding(
                        adapter=adapter,
                        tool=name,
                        prop=f"constraint.{key}",
                        verdict=PRESERVED,
                        expected=expected,
                    )
                )

        # 3. Description text. The description is what reaches the model's
        #    context, so an adapter rewriting it changes what the model reads.
        expected_description = source.get("description") or ""
        if actual.description == expected_description:
            verdict, note = PRESERVED, ""
        elif expected_description and expected_description in actual.description:
            verdict, note = MUTATED, "author's text retained but adapter added content around it"
        else:
            verdict, note = DROPPED, "author's text not present verbatim"
        findings.append(
            Finding(
                adapter=adapter,
                tool=name,
                prop="description",
                verdict=verdict,
                expected=expected_description,
                observed=actual.description[:200],
                note=note,
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def _versions() -> dict[str, str]:
    names = (
        "mcp",
        "langchain-mcp-adapters",
        "langchain-core",
        "crewai",
        "crewai-tools",
        "pydantic",
    )
    versions = {}
    for name in names:
        try:
            versions[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            versions[name] = "not installed"
    return versions


def summarise(findings: list[Finding]) -> dict[str, dict[str, int]]:
    """Count verdicts per adapter per property family."""
    table: dict[str, dict[str, int]] = {}
    for finding in findings:
        family = finding.prop.split(".")[0]
        key = f"{finding.adapter} / {family}"
        table.setdefault(key, {PRESERVED: 0, DROPPED: 0, MUTATED: 0, UNKNOWN: 0})
        table[key][finding.verdict] += 1
    return table


def write_markdown(report: dict[str, Any], path: Path) -> None:
    lines = [
        "# P0 - Translation fidelity probe",
        "",
        f"Generated: {report['generated']}",
        "",
        "## Versions under test",
        "",
        "| package | version |",
        "| --- | --- |",
    ]
    lines += [f"| `{k}` | {v} |" for k, v in report["versions"].items()]
    lines += [
        "",
        "## Verdict counts",
        "",
        "| adapter / family | preserved | dropped | mutated | unknown |",
        "| --- | --- | --- | --- | --- |",
    ]
    for key, counts in sorted(report["summary"].items()):
        lines.append(
            f"| {key} | {counts[PRESERVED]} | {counts[DROPPED]} | "
            f"{counts[MUTATED]} | {counts[UNKNOWN]} |"
        )

    lines += [
        "",
        "## Losses and mutations",
        "",
        "| adapter | tool | property | verdict | note |",
        "| --- | --- | --- | --- | --- |",
    ]
    for finding in report["findings"]:
        if finding["verdict"] == PRESERVED:
            continue
        note = finding["note"].replace("|", "/")
        lines.append(
            f"| {finding['adapter']} | `{finding['tool']}` | `{finding['prop']}` "
            f"| **{finding['verdict']}** | {note} |"
        )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)

    truth = asyncio.run(collect_ground_truth())
    findings: list[Finding] = []

    lc_tools, lc_findings = asyncio.run(probe_langchain())
    findings += compare("langchain-mcp-adapters", truth, lc_tools)
    findings += lc_findings

    try:
        crew_tools, crew_findings = probe_crewai()
        findings += compare("crewai-tools", truth, crew_tools)
        findings += crew_findings
    # Broad by design: an adapter that cannot be evaluated is itself a result.
    except Exception as exc:
        findings.append(
            Finding(
                adapter="crewai-tools",
                tool="*",
                prop="adapter",
                verdict=UNKNOWN,
                note=f"adapter could not be evaluated: {type(exc).__name__}: {exc}",
            )
        )

    report = {
        "generated": datetime.now(UTC).isoformat(timespec="seconds"),
        "versions": _versions(),
        "ground_truth": truth,
        "findings": [asdict(f) for f in findings],
        "summary": summarise(findings),
    }

    (RESULTS / "findings.json").write_text(
        json.dumps(report, indent=2, sort_keys=True), encoding="utf-8"
    )
    write_markdown(report, RESULTS / "findings.md")

    print(f"{len(findings)} findings written to {RESULTS}")
    for key, counts in sorted(report["summary"].items()):
        print(
            f"  {key:44s} preserved={counts[PRESERVED]:2d} dropped={counts[DROPPED]:2d} "
            f"mutated={counts[MUTATED]:2d} unknown={counts[UNKNOWN]:2d}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
