"""The registry index: what the crawl produces and what the CLI reads.

Deliberately a **static JSON file**, not a service. The whole index is built by a
scheduled job, committed to the repository, and served from a CDN, which buys
three things a server would not: it costs nothing to run, it is reproducible
because the artifact is in version control, and a consumer can pin or diff it.
An index you can `git log` is a supply-chain artifact; an index behind an API is
a trust assumption.

Entries are JSON rather than the YAML the plan sketched, because JSON needs no
dependency to read or write. A tool that exists to count other people's
dependencies should be able to justify each of its own.

Every entry carries its audit result. The index is not a catalogue with security
bolted on; the security assessment *is* the entry, and a tool that has not been
assessed is visibly unassessed rather than quietly listed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from toolseal.core.registry.utd import UnifiedToolDescriptor
from toolseal.errors import RegistryError

INDEX_VERSION: Final = 1
INDEX_FILENAME: Final = "index.json"


@dataclass(frozen=True)
class EntryAudit:
    """The security assessment attached to an entry."""

    score: int
    blocking: bool
    findings: tuple[str, ...] = ()
    scanned_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "blocking": self.blocking,
            "findings": list(self.findings),
            "scanned_at": self.scanned_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EntryAudit:
        return cls(
            score=int(data.get("score", 0)),
            blocking=bool(data.get("blocking", False)),
            findings=tuple(str(item) for item in data.get("findings") or []),
            scanned_at=str(data.get("scanned_at", "")),
        )


@dataclass(frozen=True)
class IndexEntry:
    """One indexed tool or server, with its assessment and compatibility."""

    descriptor: UnifiedToolDescriptor
    audit: EntryAudit
    compat: dict[str, str] = field(default_factory=dict)
    tools_enumerated: bool = False
    """Whether the tool set is known.

    False for a crawled MCP server: enumerating its tools means running it, and
    this project decided not to execute untrusted code. Recorded rather than
    implied, so a consumer knows the difference between "no tools" and "we did
    not look".
    """

    @property
    def id(self) -> str:
        return self.descriptor.id

    def matches(self, query: str) -> bool:
        """Whether *query* appears in the fields a human would search."""
        needle = query.casefold().strip()
        if not needle:
            return True
        haystack = " ".join(
            [
                self.descriptor.id,
                self.descriptor.name,
                self.descriptor.description,
                self.descriptor.source.package,
                *sorted(self.descriptor.permissions),
            ]
        ).casefold()
        return needle in haystack

    def name_relevance(self, needle: str) -> int:
        """How closely *needle* (already casefolded) matches this entry's name.

        Lower is more relevant. This only breaks ties among entries that
        already satisfy :meth:`matches`; it exists so a query that names a
        tool exactly is not outranked, at equal score, by an entry that only
        mentions the query in its description or permissions.
        """
        if not needle:
            return 0
        name = self.descriptor.name.casefold()
        if name == needle:
            return 0
        if name.startswith(needle):
            return 1
        if needle in name:
            return 2
        return 3

    def to_dict(self) -> dict[str, Any]:
        return {
            "descriptor": self.descriptor.to_dict(),
            "audit": self.audit.to_dict(),
            "compat": dict(sorted(self.compat.items())),
            "tools_enumerated": self.tools_enumerated,
        }

    @classmethod
    def from_dict(cls, data: object) -> IndexEntry:
        # Typed as `object` because this parses untrusted JSON: an entry that is
        # not an object must be rejected, not assumed away by an annotation.
        if not isinstance(data, dict):
            message = "index entry must be an object"
            raise RegistryError(message)
        return cls(
            descriptor=UnifiedToolDescriptor.from_dict(data.get("descriptor") or {}),
            audit=EntryAudit.from_dict(data.get("audit") or {}),
            compat={str(k): str(v) for k, v in (data.get("compat") or {}).items()},
            tools_enumerated=bool(data.get("tools_enumerated", False)),
        )


@dataclass(frozen=True)
class RegistryIndex:
    """A whole index, in memory."""

    entries: tuple[IndexEntry, ...] = ()
    built_at: str = ""

    def __len__(self) -> int:
        return len(self.entries)

    def get(self, entry_id: str) -> IndexEntry | None:
        return next((entry for entry in self.entries if entry.id == entry_id), None)

    def search(self, query: str, *, limit: int = 20) -> tuple[IndexEntry, ...]:
        """Matching entries, best-assessed first, most relevant among ties.

        Ordering by audit score rather than by popularity is a deliberate
        editorial choice: a registry that surfaces the most-downloaded tool
        first teaches people to install the most-downloaded tool. That
        discipline is the outer sort key and does not change. Name relevance
        only breaks ties *within* a given (blocking, score) bracket, so an
        exact or prefix name match outranks a description-only match without
        ever letting relevance override the security-first ordering.
        """
        needle = query.casefold().strip()
        matched = [entry for entry in self.entries if entry.matches(query)]
        matched.sort(
            key=lambda entry: (
                entry.audit.blocking,
                -entry.audit.score,
                entry.name_relevance(needle),
                entry.id,
            )
        )
        return tuple(matched[:limit])

    def names(self) -> frozenset[str]:
        """Every indexed package name - the reference set for lookalike detection."""
        return frozenset(entry.descriptor.source.package for entry in self.entries)

    def to_dict(self) -> dict[str, Any]:
        return {
            "index_version": INDEX_VERSION,
            "built_at": self.built_at or datetime.now(UTC).isoformat(timespec="seconds"),
            "count": len(self.entries),
            "entries": [entry.to_dict() for entry in sorted(self.entries, key=lambda e: e.id)],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RegistryIndex:
        version = data.get("index_version")
        if version != INDEX_VERSION:
            message = f"unsupported index_version {version!r}; expected {INDEX_VERSION}"
            raise RegistryError(message)

        raw = data.get("entries")
        if not isinstance(raw, list):
            message = "index field 'entries' must be a list"
            raise RegistryError(message)

        return cls(
            entries=tuple(IndexEntry.from_dict(item) for item in raw),
            built_at=str(data.get("built_at", "")),
        )

    def write(self, path: Path) -> None:
        """Write the index, sorted and newline-terminated.

        Deterministic output means a rebuild that changed nothing produces an
        empty diff, which is what makes a committed index reviewable.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.to_dict(), indent=2, sort_keys=True)
        path.write_text(payload + "\n", encoding="utf-8", newline="\n")

    @classmethod
    def read(cls, path: Path) -> RegistryIndex:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            message = f"no index at {path}; run `toolseal registry sync` first"
            raise RegistryError(message) from None
        except json.JSONDecodeError as exc:
            message = f"index at {path} is not valid JSON: {exc}"
            raise RegistryError(message) from None
        return cls.from_dict(data)
