"""The crawler and the index it produces.

The behaviours worth pinning are the honest ones: a partial crawl returns what
it got rather than nothing, an unenumerable tool set is recorded rather than
implied, and the index round-trips deterministically so a committed rebuild
diffs empty.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from toolseal.core.net import HttpError
from toolseal.core.registry.crawl import (
    CrawlReport,
    assess,
    build_index,
    crawl_mcp_registry,
    to_descriptor,
)
from toolseal.core.registry.index import (
    INDEX_VERSION,
    EntryAudit,
    IndexEntry,
    RegistryIndex,
)
from toolseal.errors import RegistryError

SERVER: dict[str, Any] = {
    "name": "io.example/postgres",
    "description": "Query a PostgreSQL database.",
    "version": "0.5.1",
    "repository": {"url": "https://example.test/postgres"},
    "packages": [{"registryType": "npm", "identifier": "@example/server-postgres"}],
}


def pages(*payloads: dict[str, Any]) -> Any:
    remaining = list(payloads)

    def fetch(_url: str) -> dict[str, Any]:
        if not remaining:
            message = "no more pages"
            raise HttpError(message)
        return remaining.pop(0)

    return fetch


# --- normalisation ---------------------------------------------------------


def test_registry_record_becomes_a_descriptor() -> None:
    descriptor = to_descriptor(SERVER)

    assert descriptor is not None
    assert descriptor.name == "io.example/postgres"
    assert descriptor.source.registry == "npm"
    assert descriptor.source.package == "@example/server-postgres"
    assert descriptor.provenance.repository == "https://example.test/postgres"


def test_unnamed_record_is_skipped_not_invented() -> None:
    assert to_descriptor({"description": "no name"}) is None


def test_input_schema_is_left_empty_rather_than_guessed() -> None:
    # The registry record carries no tool schema. Inventing one would put a
    # fiction into the index that later checks would treat as fact.
    descriptor = to_descriptor(SERVER)
    assert descriptor is not None
    assert descriptor.input_schema == {}


def test_remote_servers_gain_a_network_permission() -> None:
    descriptor = to_descriptor({**SERVER, "remotes": [{"url": "https://x"}]})
    assert descriptor is not None
    assert "network:remote-endpoint" in descriptor.permissions


def test_assessment_names_what_it_could_not_establish() -> None:
    descriptor = to_descriptor({"name": "bare", "packages": []})
    assert descriptor is not None

    audit = assess(descriptor)

    assert audit.score < 100
    assert any("registry" in finding for finding in audit.findings)
    assert any("repository" in finding for finding in audit.findings)


# --- crawling --------------------------------------------------------------


def test_crawl_stops_when_there_is_no_cursor() -> None:
    report = crawl_mcp_registry(fetch=pages({"servers": [SERVER], "metadata": {}}), delay_seconds=0)

    assert report.complete
    assert report.pages_fetched == 1
    assert len(report.entries) == 1


def test_crawl_follows_the_cursor() -> None:
    report = crawl_mcp_registry(
        fetch=pages(
            {"servers": [SERVER], "metadata": {"nextCursor": "abc"}},
            {"servers": [{**SERVER, "name": "io.example/second"}], "metadata": {}},
        ),
        delay_seconds=0,
    )

    assert report.complete
    assert len(report.entries) == 2


def test_partial_crawl_keeps_what_it_collected() -> None:
    # Discarding nine good pages because the tenth timed out would make the job
    # fail exactly when the ecosystem is largest.
    report = crawl_mcp_registry(
        fetch=pages({"servers": [SERVER], "metadata": {"nextCursor": "abc"}}),
        delay_seconds=0,
    )

    assert not report.complete
    assert len(report.entries) == 1
    assert report.errors


def test_malformed_page_is_reported_not_swallowed() -> None:
    report = crawl_mcp_registry(fetch=pages({"unexpected": True}), delay_seconds=0)

    assert not report.complete
    assert report.errors


def test_crawled_entries_record_that_tools_were_not_enumerated() -> None:
    # "No tools" and "we did not look" must not render the same way.
    report = crawl_mcp_registry(fetch=pages({"servers": [SERVER], "metadata": {}}), delay_seconds=0)

    assert all(not item.tools_enumerated for item in report.entries)


def test_max_pages_is_respected() -> None:
    def endless(_url: str) -> dict[str, Any]:
        return {"servers": [SERVER], "metadata": {"nextCursor": "more"}}

    report = crawl_mcp_registry(fetch=endless, max_pages=3, delay_seconds=0)

    assert report.pages_fetched == 3
    assert not report.complete


# --- index -----------------------------------------------------------------


def entry(name: str, score: int, *, blocking: bool = False) -> IndexEntry:
    descriptor = to_descriptor({**SERVER, "name": name})
    assert descriptor is not None
    return IndexEntry(descriptor=descriptor, audit=EntryAudit(score=score, blocking=blocking))


def test_index_round_trips(tmp_path: Path) -> None:
    index = build_index(
        crawl_mcp_registry(fetch=pages({"servers": [SERVER], "metadata": {}}), delay_seconds=0)
    )
    path = tmp_path / "index.json"
    index.write(path)

    restored = RegistryIndex.read(path)

    assert len(restored) == len(index)
    assert restored.entries[0].descriptor == index.entries[0].descriptor


def test_index_output_is_deterministic(tmp_path: Path) -> None:
    # A rebuild that changed nothing must diff empty, or a committed index is
    # unreviewable.
    first, second = tmp_path / "a.json", tmp_path / "b.json"
    RegistryIndex(entries=(entry("b", 90), entry("a", 80)), built_at="fixed").write(first)
    RegistryIndex(entries=(entry("a", 80), entry("b", 90)), built_at="fixed").write(second)

    assert first.read_text(encoding="utf-8") == second.read_text(encoding="utf-8")


def test_search_puts_the_best_assessed_first() -> None:
    index = RegistryIndex(entries=(entry("low", 20), entry("high", 95)))

    assert index.search("")[0].descriptor.name == "high"


def test_blocking_entries_sort_last() -> None:
    index = RegistryIndex(entries=(entry("blocked", 99, blocking=True), entry("clean", 50)))

    assert index.search("")[0].descriptor.name == "clean"


def test_search_matches_description_as_well_as_name() -> None:
    index = RegistryIndex(entries=(entry("io.example/x", 90),))

    assert index.search("postgresql")
    assert not index.search("nothing-like-this")


def test_search_ranks_an_exact_name_match_above_a_description_only_match() -> None:
    # Both entries score equally and neither is blocking, so the tie is broken
    # by relevance: "unrelated-name" only matches because SERVER's fixed
    # description mentions PostgreSQL, while "postgresql" matches its name
    # exactly and must come first.
    index = RegistryIndex(entries=(entry("unrelated-name", 90), entry("postgresql", 90)))

    results = index.search("postgresql")

    assert [r.descriptor.name for r in results] == ["postgresql", "unrelated-name"]


def test_search_relevance_never_outranks_the_security_ordering() -> None:
    # Relevance is a tiebreaker within a (blocking, score) bracket, not a
    # replacement for it: a worse-assessed exact name match still sorts after
    # a better-assessed entry that only matched on description.
    index = RegistryIndex(entries=(entry("postgresql", 20), entry("unrelated-name", 90)))

    assert index.search("postgresql")[0].descriptor.name == "unrelated-name"


def test_names_provides_the_lookalike_reference_set() -> None:
    index = RegistryIndex(entries=(entry("a", 90),))

    assert index.names() == frozenset({"@example/server-postgres"})


def test_unknown_index_version_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "index.json"
    path.write_text(json.dumps({"index_version": 99, "entries": []}), encoding="utf-8")

    with pytest.raises(RegistryError, match="unsupported index_version"):
        RegistryIndex.read(path)


def test_missing_index_tells_you_how_to_make_one(tmp_path: Path) -> None:
    with pytest.raises(RegistryError, match="registry sync"):
        RegistryIndex.read(tmp_path / "absent.json")


def test_non_object_entry_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "index.json"
    path.write_text(
        json.dumps({"index_version": INDEX_VERSION, "entries": ["not an object"]}),
        encoding="utf-8",
    )

    with pytest.raises(RegistryError, match="must be an object"):
        RegistryIndex.read(path)


def test_build_index_keeps_the_best_assessed_duplicate() -> None:
    report = CrawlReport(entries=[entry("dup", 40), entry("dup", 88)])

    index = build_index(report)

    assert len(index) == 1
    assert index.entries[0].audit.score == 88


# --- the live wire format --------------------------------------------------

# Regression: the first live run skipped all 200 records without raising a
# single error, because the API nests the record under a "server" key and the
# normaliser only understood the flat shape. Silent total loss is the worst
# possible failure for a crawler, so both shapes are now pinned.

WRAPPED: dict[str, Any] = {
    "server": {
        "name": "ac.example/mcp",
        "description": "A real-shaped record.",
        "version": "1.0.0",
        "remotes": [{"type": "streamable-http", "url": "https://example.test/mcp"}],
    },
    "_meta": {
        "io.modelcontextprotocol.registry/official": {
            "status": "active",
            "isLatest": True,
        }
    },
}


def test_wrapped_registry_record_is_understood() -> None:
    descriptor = to_descriptor(WRAPPED)

    assert descriptor is not None
    assert descriptor.name == "ac.example/mcp"
    assert descriptor.status == "active"
    assert descriptor.is_latest


def test_flat_record_is_still_understood() -> None:
    # Fixtures and older snapshots use the flat shape.
    assert to_descriptor(SERVER) is not None


def test_superseded_version_is_scored_down() -> None:
    superseded = {
        **WRAPPED,
        "_meta": {
            "io.modelcontextprotocol.registry/official": {
                "status": "active",
                "isLatest": False,
            }
        },
    }
    descriptor = to_descriptor(superseded)
    assert descriptor is not None

    assert not descriptor.is_latest
    assert any("newer version" in finding for finding in assess(descriptor).findings)


def test_inactive_server_is_scored_down() -> None:
    deleted = {
        **WRAPPED,
        "_meta": {
            "io.modelcontextprotocol.registry/official": {
                "status": "deleted",
                "isLatest": True,
            }
        },
    }
    descriptor = to_descriptor(deleted)
    assert descriptor is not None

    assert any("status" in finding for finding in assess(descriptor).findings)


def test_a_crawl_of_wrapped_records_skips_nothing() -> None:
    report = crawl_mcp_registry(
        fetch=pages({"servers": [WRAPPED, WRAPPED], "metadata": {}}), delay_seconds=0
    )

    assert report.skipped == []
    assert len(report.entries) == 2
