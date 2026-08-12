"""The scraper: crawling the MCP ecosystem into normalised descriptors.

Runs as a scheduled job, commits its output, and serves it as a static index.
Three constraints shape it, and each is a decision rather than an accident.

**It never executes what it finds.** Enumerating an MCP server's tools means
running the server, and this project decided against executing untrusted code.
So a crawled entry describes the *server*, and records
``tools_enumerated=False`` rather than implying the tool set is empty. A gap you
can see is worth more than a number you cannot trust.

**It is polite.** Registry operators are giving this away. Requests are paced,
identified by user agent, page-limited, and stop on the first hard failure
rather than hammering an endpoint that is already unhappy.

**Partial results are still results.** A crawl that reaches page nine of ten
returns nine pages and says so. Discarding the lot because the last request
timed out would make the job fail exactly when the ecosystem is largest.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final

from toolseal.core.net import HttpError, get_json
from toolseal.core.registry.index import EntryAudit, IndexEntry, RegistryIndex
from toolseal.core.registry.utd import (
    Provenance,
    SecurityAnnotations,
    ToolSource,
    UnifiedToolDescriptor,
)

MCP_REGISTRY_URL: Final = "https://registry.modelcontextprotocol.io/v0/servers"

DEFAULT_PAGE_SIZE: Final = 100
DEFAULT_MAX_PAGES: Final = 20
DEFAULT_DELAY_SECONDS: Final = 0.5

# Registry identifiers as the MCP registry reports them, mapped to the names
# used in a descriptor's source.
REGISTRY_META_KEY: Final = "io.modelcontextprotocol.registry/official"

_REGISTRY_NAMES: Final[dict[str, str]] = {
    "npm": "npm",
    "pypi": "pypi",
    "oci": "oci",
    "nuget": "nuget",
    "mcpb": "mcpb",
}


@dataclass
class CrawlReport:
    """What a crawl produced, including what it could not."""

    entries: list[IndexEntry] = field(default_factory=list)
    pages_fetched: int = 0
    skipped: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    complete: bool = False

    @property
    def summary(self) -> str:
        state = "complete" if self.complete else "partial"
        return (
            f"{len(self.entries)} entries from {self.pages_fetched} page(s), {state}; "
            f"{len(self.skipped)} skipped, {len(self.errors)} error(s)"
        )


def _first_package(server: dict[str, Any]) -> dict[str, Any] | None:
    """The first distributable package, preferring registries we can verify."""
    packages = server.get("packages")
    if not isinstance(packages, list):
        return None

    ranked = sorted(
        (p for p in packages if isinstance(p, dict)),
        key=lambda p: (
            0 if str(p.get("registryType") or p.get("registry_name")) in ("npm", "pypi") else 1
        ),
    )
    return ranked[0] if ranked else None


def _permissions(server: dict[str, Any]) -> frozenset[str]:
    """Capabilities inferable from the registry record alone.

    Coarse on purpose. Anything finer needs the server's code or its running
    tool list, and the crawl has neither.
    """
    permissions: set[str] = set()
    if server.get("remotes"):
        permissions.add("network:remote-endpoint")
    package = _first_package(server) or {}
    if package.get("environmentVariables") or package.get("environment_variables"):
        permissions.add("env:read")
    return frozenset(permissions)


def unwrap(record: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Split a registry item into its server object and its registry metadata.

    The live API returns ``{"server": {...}, "_meta": {...}}``. The flat shape is
    still accepted because fixtures and older snapshots use it, and because a
    normaliser that only understands one wire format silently drops everything
    the day that format changes - which is exactly what happened here: the first
    live run skipped all 200 records without a single error.
    """
    server = record.get("server")
    if isinstance(server, dict):
        meta = record.get("_meta")
        official = (meta or {}).get(REGISTRY_META_KEY) if isinstance(meta, dict) else None
        return server, official if isinstance(official, dict) else {}
    return record, {}


def to_descriptor(record: dict[str, Any]) -> UnifiedToolDescriptor | None:
    """Normalise one registry record into a descriptor, or ``None`` if unusable."""
    server, official = unwrap(record)

    name = str(server.get("name") or "").strip()
    if not name:
        return None

    version = str(
        server.get("version") or (server.get("version_detail") or {}).get("version") or "0"
    )
    package = _first_package(server) or {}
    registry = _REGISTRY_NAMES.get(
        str(package.get("registryType") or package.get("registry_name") or ""), "unknown"
    )
    package_name = str(package.get("identifier") or package.get("name") or name)

    repository = server.get("repository")
    repository_url = repository.get("url") if isinstance(repository, dict) else None

    return UnifiedToolDescriptor(
        id=f"mcp/{name}@{version}",
        name=name,
        description=str(server.get("description") or ""),
        source=ToolSource(kind="mcp", registry=registry, package=package_name, version=version),
        # Left empty rather than guessed. The registry record does not carry a
        # tool schema, and inventing one would put a fiction into the index.
        input_schema={},
        annotations=SecurityAnnotations(),
        permissions=_permissions(server),
        provenance=Provenance(
            repository=str(repository_url) if repository_url else None,
            # The registry namespaces server names by publisher domain, which is
            # the only publisher signal available without leaving the record.
            publisher=name.split("/")[0] if "/" in name else None,
            signature="none",
            license=str(server.get("license")) if server.get("license") else None,
        ),
        status=str(official.get("status") or "unknown"),
        is_latest=bool(official.get("isLatest", True)),
    )


def assess(descriptor: UnifiedToolDescriptor) -> EntryAudit:
    """A provisional assessment from the metadata a crawl can see.

    Not a substitute for auditing an installed project. It scores what is
    knowable without execution - provenance, an identifiable registry, a
    described purpose - and the findings name what could not be established so
    the entry never looks more assured than it is.
    """
    findings: list[str] = []
    score = 100

    if descriptor.source.registry == "unknown":
        findings.append("C4: no verifiable package registry for this server")
        score -= 30
    if not descriptor.provenance.repository:
        findings.append("C4: no source repository declared")
        score -= 20
    if not descriptor.provenance.is_signed:
        findings.append("C4: no signature or attestation")
        score -= 10
    if not descriptor.description.strip():
        findings.append("metadata: no description, so purpose cannot be reviewed")
        score -= 10
    if descriptor.status not in ("active", "unknown"):
        findings.append(f"registry: server status is {descriptor.status!r}")
        score -= 25
    if not descriptor.is_latest:
        findings.append("registry: a newer version of this server exists")
        score -= 15

    return EntryAudit(
        score=max(score, 0),
        blocking=False,
        findings=tuple(findings),
        scanned_at=datetime.now(UTC).isoformat(timespec="seconds"),
    )


def crawl_mcp_registry(
    *,
    max_pages: int = DEFAULT_MAX_PAGES,
    page_size: int = DEFAULT_PAGE_SIZE,
    delay_seconds: float = DEFAULT_DELAY_SECONDS,
    fetch: Any = get_json,
) -> CrawlReport:
    """Page through the official MCP registry, normalising as it goes.

    *fetch* is injected so the crawl can be tested without a network, and so a
    caller can substitute a cache.
    """
    report = CrawlReport()
    cursor: str | None = None

    for page in range(max_pages):
        url = f"{MCP_REGISTRY_URL}?limit={page_size}"
        if cursor:
            url = f"{url}&cursor={cursor}"

        try:
            payload = fetch(url)
        except HttpError as exc:
            # Stop rather than retry into an endpoint that is already unhappy;
            # what was collected so far is still worth returning.
            report.errors.append(f"page {page + 1}: {exc}")
            break

        servers = payload.get("servers") if isinstance(payload, dict) else None
        if not isinstance(servers, list):
            report.errors.append(f"page {page + 1}: response had no server list")
            break

        report.pages_fetched += 1
        for server in servers:
            if not isinstance(server, dict):
                report.skipped.append("non-object entry")
                continue
            descriptor = to_descriptor(server)
            if descriptor is None:
                report.skipped.append(str(server.get("name") or "<unnamed>"))
                continue
            report.entries.append(
                IndexEntry(
                    descriptor=descriptor,
                    audit=assess(descriptor),
                    compat={},
                    # Enumerating tools means running the server, which this
                    # project does not do. Recorded, not implied.
                    tools_enumerated=False,
                )
            )

        metadata = payload.get("metadata") if isinstance(payload, dict) else {}
        cursor = (metadata or {}).get("nextCursor") or (metadata or {}).get("next_cursor")
        if not cursor:
            report.complete = True
            break

        if delay_seconds:
            time.sleep(delay_seconds)

    return report


def build_index(report: CrawlReport) -> RegistryIndex:
    """Turn a crawl into an index, keeping the best-assessed entry per id."""
    best: dict[str, IndexEntry] = {}
    for entry in report.entries:
        current = best.get(entry.id)
        if current is None or entry.audit.score > current.audit.score:
            best[entry.id] = entry

    return RegistryIndex(
        entries=tuple(sorted(best.values(), key=lambda item: item.id)),
        built_at=datetime.now(UTC).isoformat(timespec="seconds"),
    )
