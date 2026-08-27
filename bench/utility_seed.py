"""Build the shipped registry from the utility-coverage manifest.

Replaces the alphabetically-sliced 113-entry set with one canonical server per
capability people actually use, plus the tool-level entries P1 captured. The
selection rule, the verification, and the capabilities the ecosystem cannot
fill are recorded in `research/registry-utility-coverage.md`; this script is
only the mechanism.

Entries are declared here rather than crawled because most of these servers
are **not in the MCP registry at all** - the protocol's own reference servers
among them. Each was fetched from npm or PyPI directly at selection time and
its version, license and deprecation status recorded. Declaring them is not a
shortcut around the crawl; it is the only route to a server the directory does
not list.

Usage:

    uv run python bench/utility_seed.py [--check]
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from toolseal.core.registry.crawl import assess
from toolseal.core.registry.index import IndexEntry, RegistryIndex
from toolseal.core.registry.tools import ingest_capture
from toolseal.core.registry.utd import (
    Provenance,
    ToolSource,
    UnifiedToolDescriptor,
)

ROOT = Path(__file__).resolve().parent.parent
CAPTURES = ROOT / "research" / "probes" / "p1_remote_mcp_annotations" / "results"
SWEEP = ROOT / "research" / "probes" / "p3_tool_sweep" / "results"
CURATED = ROOT / "src" / "toolseal" / "data" / "registry" / "curated.json"


@dataclass(frozen=True)
class Server:
    """One canonical server for one capability."""

    capability: str
    entry_id: str
    name: str
    description: str
    registry: str
    package: str
    version: str
    repository: str | None = None
    publisher: str | None = None
    license: str | None = None
    capture: str | None = None
    """Basename of a P1 capture whose tools belong to this server, if any."""


# Verified against npm/PyPI at selection time - see the manifest table in
# research/registry-utility-coverage.md. `license=None` where the package
# metadata declares no SPDX identifier, which for the reference servers is
# itself the finding rather than an omission here.
SERVERS: tuple[Server, ...] = (
    Server(
        "filesystem",
        "mcp/io.modelcontextprotocol/server-filesystem@2026.7.10",
        "modelcontextprotocol/server-filesystem",
        "Read, write and search files on the local filesystem, confined to directories "
        "granted at launch.",
        "npm",
        "@modelcontextprotocol/server-filesystem",
        "2026.7.10",
        repository="https://github.com/modelcontextprotocol/servers",
        publisher="modelcontextprotocol",
    ),
    Server(
        "git",
        "mcp/io.modelcontextprotocol/server-git@2026.8.18",
        "modelcontextprotocol/server-git",
        "Read a git repository, inspect history and diffs, stage and commit changes.",
        "pypi",
        "mcp-server-git",
        "2026.8.18",
        repository="https://github.com/modelcontextprotocol/servers",
        publisher="modelcontextprotocol",
        license="MIT",
    ),
    Server(
        "shell",
        "mcp/io.github.tumf/mcp-shell-server@1.1.9",
        "tumf/mcp-shell-server",
        "Execute allow-listed shell commands and return their output.",
        "pypi",
        "mcp-shell-server",
        "1.1.9",
        publisher="tumf",
        license="MIT",
    ),
    Server(
        "python-execution",
        "mcp/io.github.pydantic/mcp-run-python@0.0.22",
        "pydantic/mcp-run-python",
        "Run Python code in a sandboxed interpreter and return the result.",
        "pypi",
        "mcp-run-python",
        "0.0.22",
        repository="https://github.com/pydantic/mcp-run-python",
        publisher="pydantic",
        license="MIT",
    ),
    Server(
        "http-fetch",
        "mcp/io.modelcontextprotocol/server-fetch@2026.8.18",
        "modelcontextprotocol/server-fetch",
        "Fetch a URL and convert the response to markdown for a model to read.",
        "pypi",
        "mcp-server-fetch",
        "2026.8.18",
        repository="https://github.com/modelcontextprotocol/servers",
        publisher="modelcontextprotocol",
        license="MIT",
    ),
    Server(
        "time",
        "mcp/io.modelcontextprotocol/server-time@2026.8.18",
        "modelcontextprotocol/server-time",
        "Current time in any timezone, and conversion between timezones.",
        "pypi",
        "mcp-server-time",
        "2026.8.18",
        repository="https://github.com/modelcontextprotocol/servers",
        publisher="modelcontextprotocol",
        license="MIT",
    ),
    Server(
        "memory",
        "mcp/io.modelcontextprotocol/server-memory@2026.7.4",
        "modelcontextprotocol/server-memory",
        "A knowledge graph the agent can write to and read back across turns.",
        "npm",
        "@modelcontextprotocol/server-memory",
        "2026.7.4",
        repository="https://github.com/modelcontextprotocol/servers",
        publisher="modelcontextprotocol",
    ),
    Server(
        "reasoning",
        "mcp/io.modelcontextprotocol/server-sequential-thinking@2026.7.4",
        "modelcontextprotocol/server-sequential-thinking",
        "Structured step-by-step reasoning, revisable as the problem is understood.",
        "npm",
        "@modelcontextprotocol/server-sequential-thinking",
        "2026.7.4",
        repository="https://github.com/modelcontextprotocol/servers",
        publisher="modelcontextprotocol",
    ),
    Server(
        "postgresql",
        "mcp/io.github.crystaldba/postgres-mcp@0.3.0",
        "crystaldba/postgres-mcp",
        "Query a PostgreSQL database, inspect its schema, and analyse query plans.",
        "pypi",
        "postgres-mcp",
        "0.3.0",
        publisher="crystaldba",
        license="MIT",
    ),
    Server(
        "mongodb",
        "mcp/io.github.mongodb-js/mongodb-mcp-server@2.1.0",
        "mongodb-js/mongodb-mcp-server",
        "Query and administer MongoDB collections, indexes and aggregation pipelines.",
        "npm",
        "mongodb-mcp-server",
        "2.1.0",
        repository="https://github.com/mongodb-js/mongodb-mcp-server",
        publisher="mongodb-js",
        license="Apache-2.0",
    ),
    Server(
        "sqlite",
        "mcp/io.modelcontextprotocol/server-sqlite@2025.4.25",
        "modelcontextprotocol/server-sqlite",
        "Query a local SQLite database file and inspect its tables.",
        "pypi",
        "mcp-server-sqlite",
        "2025.4.25",
        repository="https://github.com/modelcontextprotocol/servers-archived",
        publisher="modelcontextprotocol",
    ),
    Server(
        "redis",
        "mcp/io.github.upstash/redis-mcp@0.1.1",
        "upstash/redis-mcp",
        "Read and write keys in a Redis database.",
        "npm",
        "@upstash/redis-mcp",
        "0.1.1",
        repository="https://github.com/upstash/mcp-server",
        publisher="upstash",
        license="MIT",
    ),
    Server(
        "vector-store",
        "mcp/io.github.chroma-core/chroma-mcp@0.2.6",
        "chroma-core/chroma-mcp",
        "Store and query embeddings in a Chroma vector database for retrieval.",
        "pypi",
        "chroma-mcp",
        "0.2.6",
        repository="https://github.com/chroma-core/chroma-mcp",
        publisher="chroma-core",
        license="Apache-2.0",
    ),
    Server(
        "browser",
        "mcp/io.github.microsoft/playwright-mcp@0.0.79",
        "microsoft/playwright-mcp",
        "Drive a real browser: navigate, click, fill forms, and capture screenshots.",
        "npm",
        "@playwright/mcp",
        "0.0.79",
        repository="https://github.com/microsoft/playwright-mcp",
        publisher="microsoft",
        license="Apache-2.0",
    ),
    Server(
        "documentation",
        "mcp/io.github.upstash/context7@4.0.3",
        "upstash/context7",
        "Fetch current, version-specific documentation for a library or framework.",
        "npm",
        "@upstash/context7-mcp",
        "4.0.3",
        repository="https://github.com/upstash/context7",
        publisher="upstash",
        license="MIT",
    ),
    Server(
        "containers",
        "mcp/io.github.quantgeekdev/docker-mcp@1.0.0",
        "quantgeekdev/docker-mcp",
        "Manage Docker containers, images and compose stacks.",
        "npm",
        "docker-mcp",
        "1.0.0",
        publisher="quantgeekdev",
        license="MIT",
    ),
    Server(
        "orchestration",
        "mcp/io.github.containers/kubernetes-mcp-server@0.0.66",
        "containers/kubernetes-mcp-server",
        "Inspect and manage Kubernetes resources across a cluster.",
        "npm",
        "kubernetes-mcp-server",
        "0.0.66",
        repository="https://github.com/containers/kubernetes-mcp-server",
        publisher="containers",
        license="Apache-2.0",
    ),
    Server(
        "pixel-art",
        "mcp/io.github.oaktreegames/aseprite-live-mcp@0.2.0",
        "oaktreegames/aseprite-live-mcp",
        "Draw, animate and export sprites in a running Aseprite instance.",
        "pypi",
        "aseprite-live-mcp",
        "0.2.0",
        publisher="oaktreegames",
        license="MIT",
    ),
    Server(
        "error-tracking",
        "mcp/io.github.getsentry/sentry-mcp@0.25.0",
        "getsentry/sentry-mcp",
        "Search Sentry issues and events, and analyse production errors.",
        "npm",
        "@sentry/mcp-server",
        "0.25.0",
        repository="https://github.com/getsentry/sentry-mcp",
        publisher="getsentry",
        license="FSL-1.1-ALv2",
        capture="sentry",
    ),
    Server(
        "documents",
        "mcp/com.notion/notion-mcp@2.5.1",
        "notion/notion-mcp-server",
        "Search, read and edit pages and databases in a Notion workspace.",
        "npm",
        "@notionhq/notion-mcp-server",
        "2.5.1",
        repository="https://github.com/makenotion/notion-mcp-server",
        publisher="makenotion",
        license="MIT",
        capture="notion",
    ),
    Server(
        "issue-tracking",
        "mcp/app.linear/linear-mcp@remote",
        "linear/linear-mcp",
        "Read and update Linear issues, projects, cycles and releases.",
        # Linear publishes no package: the server is remote-only. `unknown` is
        # the honest registry value and `assess` penalises it accordingly.
        "unknown",
        "https://mcp.linear.app/mcp",
        "",
        publisher="linear",
        capture="linear",
    ),
)


def _server_entry(server: Server) -> IndexEntry:
    descriptor = UnifiedToolDescriptor(
        id=server.entry_id,
        name=server.name,
        description=server.description,
        source=ToolSource(
            kind="mcp",
            registry=server.registry,
            package=server.package,
            version=server.version,
        ),
        provenance=Provenance(
            repository=server.repository,
            publisher=server.publisher,
            license=server.license,
        ),
        status="active",
    )
    return IndexEntry(descriptor=descriptor, audit=assess(descriptor))


def build() -> RegistryIndex:
    entries: list[IndexEntry] = []
    for server in SERVERS:
        entry = _server_entry(server)
        entries.append(entry)

        # Two capture sources, same shape. P1 holds the remote servers an
        # operator authenticated to; P3 holds the stdio servers enumerated by
        # `bench/sweep.py`. A server appears in at most one of them, and the
        # P1 name wins where both exist, since an authenticated capture of a
        # live service is the better evidence.
        capture = None
        if server.capture:
            capture = CAPTURES / f"{server.capture}-tools.json"
        elif (SWEEP / f"{server.capability}-tools.json").is_file():
            capture = SWEEP / f"{server.capability}-tools.json"

        if capture is not None and capture.is_file():
            payload = json.loads(capture.read_text(encoding="utf-8"))
            entries.extend(
                ingest_capture(
                    payload,
                    server_id=server.entry_id,
                    source=entry.descriptor.source,
                    provenance=entry.descriptor.provenance,
                )
            )
    return RegistryIndex(entries=tuple(entries))


def _preserve_scan_times(index: RegistryIndex, previous: RegistryIndex) -> RegistryIndex:
    """Keep each entry's earlier `scanned_at` when nothing else about it moved.

    `assess()` stamps the current time, so without this a rebuild that changed
    nothing would still rewrite every timestamp. `index.py` states that
    deterministic output is what makes a committed index reviewable, and a
    file whose every line churns on each regeneration is not reviewable.
    """
    kept: list[IndexEntry] = []
    for entry in index.entries:
        before = previous.get(entry.id)
        if before is not None and (
            before.audit.score == entry.audit.score
            and before.audit.findings == entry.audit.findings
            and before.descriptor == entry.descriptor
        ):
            kept.append(
                replace(entry, audit=replace(entry.audit, scanned_at=before.audit.scanned_at))
            )
        else:
            kept.append(entry)
    return RegistryIndex(entries=tuple(kept), built_at=index.built_at)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Report changes, write nothing.")
    args = parser.parse_args()

    index = build()
    if CURATED.exists():
        previous = RegistryIndex.read(CURATED)
        index = _preserve_scan_times(index, previous)
        index = RegistryIndex(entries=index.entries, built_at=previous.built_at)

    servers = [e for e in index.entries if "#" not in e.id]
    tools = [e for e in index.entries if "#" in e.id]
    print(f"servers: {len(servers)}   tools: {len(tools)}   total: {len(index)}")
    print(f"  capabilities covered: {len({s.capability for s in SERVERS})}")
    annotated = sum(1 for e in tools if e.descriptor.annotations.declared())
    destructive = sum(1 for e in tools if e.descriptor.annotations.destructive)
    print(f"  tools annotated: {annotated}/{len(tools)}")
    print(f"  tools declared destructive: {destructive}/{len(tools)}")

    if args.check:
        current = json.loads(CURATED.read_text(encoding="utf-8")) if CURATED.exists() else None
        if current == index.to_dict():
            print("curated.json is up to date")
            return 0
        print("curated.json is stale; re-run without --check")
        return 1

    index.write(CURATED)
    print(f"wrote {CURATED.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
