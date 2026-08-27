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
from toolseal.core.policy import progress
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


def test_search_narrows_every_page_url() -> None:
    # Default pagination is alphabetically biased (crawl_mcp_registry's own
    # docstring: one crawl measured 1988/2000 entries under `ai.*`). `search`
    # is the escape hatch - it has to actually reach the registry's own
    # `?search=` filter, not just exist as a parameter nothing uses.
    seen_urls: list[str] = []

    def fetch(url: str) -> dict[str, Any]:
        seen_urls.append(url)
        return {"servers": [SERVER], "metadata": {}}

    crawl_mcp_registry(fetch=fetch, search="context7", delay_seconds=0)

    assert seen_urls
    assert "search=context7" in seen_urls[0]


def test_search_term_is_url_encoded() -> None:
    seen_urls: list[str] = []

    def fetch(url: str) -> dict[str, Any]:
        seen_urls.append(url)
        return {"servers": [], "metadata": {}}

    crawl_mcp_registry(fetch=fetch, search="a b/c", delay_seconds=0)

    assert "search=a%20b%2Fc" in seen_urls[0]


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


# --- progress (spec §4: "fetching the index") -------------------------------
#
# `max_pages` is always a known bound by the time a crawl runs - `registry
# sync`'s CLI option always supplies one - so this is reported as a
# determinate phase through the same generic observer `family_c.py` already
# uses for C2/C3 (`core.policy.progress`), rather than leaving a multi-page
# crawl against a live registry silent.


class _Recorder:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def start(self, phase: str, total: int | None) -> None:
        self.calls.append(("start", phase, str(total)))

    def advance(self, phase: str, step: int = 1) -> None:
        self.calls.append(("advance", phase, str(step)))

    def finish(self, phase: str) -> None:
        self.calls.append(("finish", phase))


def test_crawl_reports_fetching_the_index_as_a_determinate_phase() -> None:
    recorder = _Recorder()

    with progress.observe(recorder):
        crawl_mcp_registry(
            fetch=pages({"servers": [SERVER], "metadata": {}}), delay_seconds=0, max_pages=5
        )

    assert recorder.calls[0] == ("start", "fetching the index", "5")
    assert ("advance", "fetching the index", "1") in recorder.calls
    assert recorder.calls[-1] == ("finish", "fetching the index")


def test_crawl_still_finishes_the_phase_when_a_page_fails() -> None:
    # `finish` must run even on the error-and-break path (a `try`/`finally`
    # in the crawl, not a call at the bottom of the function) - an observer
    # left "started" forever is exactly the kind of stuck spinner the
    # anti-silence principle this progress reporting serves is meant to
    # prevent, not cause.
    recorder = _Recorder()

    with progress.observe(recorder):
        crawl_mcp_registry(fetch=pages({"unexpected": True}), delay_seconds=0)

    assert recorder.calls[-1] == ("finish", "fetching the index")


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


def test_relevance_ranks_ahead_of_a_better_assessed_weaker_match() -> None:
    # Deliberate reversal of the earlier policy, which made relevance a
    # tiebreaker *within* a (blocking, score) bracket. That ordering answered
    # "what is safest" when the user asked "what does what I want", and it
    # could bury an exact match under an unrelated entry that merely scored
    # better. Search now ranks by relevance and reports posture alongside each
    # result; the score decides nothing about position except through the
    # blocking floor below.
    index = RegistryIndex(entries=(entry("postgresql", 20), entry("unrelated-name", 90)))

    assert index.search("postgresql")[0].descriptor.name == "postgresql"


def test_a_blocking_entry_still_sorts_below_every_non_blocking_match() -> None:
    # The one place posture does override relevance. A blocking entry failed a
    # critical check, so it is floored beneath everything that did not, however
    # well it matches - but it is still returned, because silently hiding a
    # result the user asked for teaches them the search is lying to them.
    index = RegistryIndex(
        entries=(entry("postgresql", 95, blocking=True), entry("unrelated-name", 20))
    )

    results = index.search("postgresql")

    assert [r.descriptor.name for r in results] == ["unrelated-name", "postgresql"]


def test_search_finds_terms_that_are_not_adjacent() -> None:
    # The substring matcher required a contiguous, correctly ordered phrase, so
    # this returned nothing at all.
    index = RegistryIndex(entries=(entry("io.example/x", 90),))

    assert index.search("postgresql server")
    assert index.search("server postgresql")


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


# --- the packaged curated set (P16) -----------------------------------------


def test_packaged_curated_servers_are_within_the_v1_cap() -> None:
    # Reads through `importlib.resources`, so this exercises the same path an
    # installed wheel uses - no filesystem path relative to this module.
    #
    # The cap is restated against *servers* rather than raised. It was written
    # when an entry could only be a server, and it bounds how large a set was
    # curated by hand-fixed criteria - a question tools do not participate in,
    # since they are not selected at all: a server's tools are taken wholesale
    # or not at all. Relaxing the number to fit the new total would have been
    # the easy edit and the wrong one.
    index = RegistryIndex.read_packaged()
    servers = [entry for entry in index.entries if not entry.tools_enumerated]

    assert 0 < len(servers) <= 200


def test_a_packaged_entry_reports_enumeration_honestly_either_way() -> None:
    # Was: no entry may claim its tools are enumerated, because enumerating a
    # server means running it and this project does not. That is still true of
    # every *server* entry. It is not true of a tool entry, which exists only
    # because someone captured a tools/list from a server they authenticated
    # to themselves (see core/registry/tools.py).
    #
    # The invariant that actually matters survives intact: the flag never
    # lies. A server entry says the tool set is unknown; a tool entry is the
    # evidence that one is known.
    index = RegistryIndex.read_packaged()
    servers = [entry for entry in index.entries if "#" not in entry.id]
    tools = [entry for entry in index.entries if "#" in entry.id]

    assert servers, "the packaged index should still carry server entries"
    assert tools, "the packaged index should now also carry tool entries"
    assert all(not entry.tools_enumerated for entry in servers)
    assert all(entry.tools_enumerated for entry in tools)


def test_every_packaged_tool_entry_carries_what_its_author_declared() -> None:
    # The reason tool entries were worth shipping at all: server metadata
    # carried no annotations and no schemas, so both fields sat empty on every
    # entry and neither family G nor guard synthesis had real input.
    index = RegistryIndex.read_packaged()
    tools = [entry for entry in index.entries if "#" in entry.id]

    annotated = [entry for entry in tools if entry.descriptor.annotations.declared()]
    assert len(annotated) == len(tools), "every captured tool declared at least one hint"


def test_a_crawl_of_wrapped_records_skips_nothing() -> None:
    report = crawl_mcp_registry(
        fetch=pages({"servers": [WRAPPED, WRAPPED], "metadata": {}}), delay_seconds=0
    )

    assert report.skipped == []
    assert len(report.entries) == 2
