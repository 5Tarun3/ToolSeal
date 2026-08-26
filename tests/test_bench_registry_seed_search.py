"""P16 supplement: search-reached entries, mechanically filtered the same way.

`bench.registry_seed.included()` is reused verbatim here, so the only new
behaviour worth pinning is `find`'s exact-package match (a search hit is not
proof it is the tool being looked for - the registry's `search` matches
substrings of a server's own `name`, and turns up plenty of same-named
impostors) and `run`'s merge (existing curated entries survive, a search
result that fails `included()` contributes nothing, and a term with no live
match is reported rather than silently dropped).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from bench.registry_seed_search import SEARCH_TARGETS, find, run

from toolseal.core.registry.index import EntryAudit, IndexEntry, RegistryIndex
from toolseal.core.registry.utd import Provenance, ToolSource, UnifiedToolDescriptor


def descriptor(
    entry_id: str,
    package: str,
    *,
    repository: str | None = "https://example.test/repo",
    description: str = "does a thing",
    is_latest: bool = True,
    registry: str = "npm",
) -> UnifiedToolDescriptor:
    return UnifiedToolDescriptor(
        id=entry_id,
        name=entry_id.split("/")[-1].split("@")[0],
        description=description,
        source=ToolSource(kind="mcp", registry=registry, package=package, version="1.0.0"),
        provenance=Provenance(repository=repository),
        status="active",
        is_latest=is_latest,
    )


def entry(entry_id: str, package: str, **kwargs: object) -> IndexEntry:
    return IndexEntry(
        descriptor=descriptor(entry_id, package, **kwargs),  # type: ignore[arg-type]
        audit=EntryAudit(score=90, blocking=False),
    )


def fake_report(*entries: IndexEntry) -> object:
    class _Report:
        def __init__(self) -> None:
            self.entries = list(entries)

    return _Report()


# --- find(): exact-package matching -----------------------------------------


def test_find_matches_the_exact_package_not_a_same_named_impostor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real = entry("mcp/io.github.upstash/context7@1.0.31", "@upstash/context7-mcp")
    impostor = entry("mcp/ai.smithery/context7fork@1.0.0", "@renCosta2025/context7fork")

    monkeypatch.setattr(
        "bench.registry_seed_search.crawl_mcp_registry",
        lambda **_kwargs: fake_report(impostor, real),
    )

    found = find("context7", "@upstash/context7-mcp")

    assert found is not None
    assert found.id == real.id


def test_find_returns_none_when_nothing_matches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "bench.registry_seed_search.crawl_mcp_registry", lambda **_kwargs: fake_report()
    )

    assert find("mcp-server-fetch", "mcp-server-fetch") is None


def test_find_ignores_a_superseded_version(monkeypatch: pytest.MonkeyPatch) -> None:
    stale = entry("mcp/x/y@0.1.0", "@x/y", is_latest=False)
    monkeypatch.setattr(
        "bench.registry_seed_search.crawl_mcp_registry", lambda **_kwargs: fake_report(stale)
    )

    assert find("y", "@x/y") is None


# --- run(): merging into the curated set ------------------------------------


def test_run_merges_a_qualifying_find_into_the_curated_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    existing = entry("mcp/existing@1.0.0", "existing")
    curated_path = tmp_path / "curated.json"
    RegistryIndex(entries=(existing,)).write(curated_path)

    found = entry("mcp/io.github.upstash/context7@1.0.31", "@upstash/context7-mcp")
    monkeypatch.setattr("bench.registry_seed_search.find", lambda term, pkg: found)

    merged, added, skipped = run(curated_path)

    ids = {e.id for e in merged.entries}
    assert existing.id in ids
    assert found.id in ids
    assert len(added) == len(SEARCH_TARGETS)
    assert skipped == ()


def test_run_reports_a_target_that_fails_curation_criteria_without_adding_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    curated_path = tmp_path / "curated.json"
    RegistryIndex(entries=()).write(curated_path)

    # Fails `included()`: no repository declared.
    disqualified = entry("mcp/x@1.0.0", "x", repository=None)
    monkeypatch.setattr("bench.registry_seed_search.find", lambda term, pkg: disqualified)

    merged, added, skipped = run(curated_path)

    assert added == ()
    assert len(skipped) == len(SEARCH_TARGETS)
    assert all("fails curation criteria" in line for line in skipped)
    assert merged.entries == ()


def test_run_reports_an_unfound_target_without_raising(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    curated_path = tmp_path / "curated.json"
    RegistryIndex(entries=()).write(curated_path)

    monkeypatch.setattr("bench.registry_seed_search.find", lambda term, pkg: None)

    merged, added, skipped = run(curated_path)

    assert added == ()
    assert len(skipped) == len(SEARCH_TARGETS)
    assert all("not found via search" in line for line in skipped)
    assert merged.entries == ()


def test_run_is_idempotent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    curated_path = tmp_path / "curated.json"
    RegistryIndex(entries=()).write(curated_path)

    found = entry("mcp/io.github.upstash/context7@1.0.31", "@upstash/context7-mcp")
    monkeypatch.setattr("bench.registry_seed_search.find", lambda term, pkg: found)

    first, _added, _skipped = run(curated_path)
    first.write(curated_path)
    second, _added2, _skipped2 = run(curated_path)

    assert [e.id for e in first.entries] == [e.id for e in second.entries]
