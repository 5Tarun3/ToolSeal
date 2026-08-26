"""P16 selection: applying `research/registry-curation-criteria.md` mechanically.

The behaviours worth pinning: each inclusion rule actually gates membership,
the audit score has no say in who gets in even when it disagrees loudly with
the fixed criteria, the cap is enforced by a score-blind tie-break, and the
whole thing is idempotent - the reproducibility property the criteria
document promises and a curated set that goes into a paper cannot do without.
"""

from __future__ import annotations

from pathlib import Path

from bench.registry_seed import CAP, included, report_for, run, select

from toolseal.core.registry.index import EntryAudit, IndexEntry, RegistryIndex
from toolseal.core.registry.utd import Provenance, ToolSource, UnifiedToolDescriptor


def descriptor(
    entry_id: str,
    *,
    registry: str = "npm",
    repository: str | None = "https://example.test/repo",
    description: str = "does a thing",
    is_latest: bool = True,
    status: str = "active",
) -> UnifiedToolDescriptor:
    return UnifiedToolDescriptor(
        id=entry_id,
        name=entry_id.split("/")[-1].split("@")[0],
        description=description,
        source=ToolSource(kind="mcp", registry=registry, package=entry_id, version="1.0.0"),
        provenance=Provenance(repository=repository),
        status=status,
        is_latest=is_latest,
    )


def entry(
    entry_id: str,
    *,
    registry: str = "npm",
    repository: str | None = "https://example.test/repo",
    description: str = "does a thing",
    is_latest: bool = True,
    status: str = "active",
    score: int = 50,
    blocking: bool = False,
) -> IndexEntry:
    return IndexEntry(
        descriptor=descriptor(
            entry_id,
            registry=registry,
            repository=repository,
            description=description,
            is_latest=is_latest,
            status=status,
        ),
        audit=EntryAudit(score=score, blocking=blocking),
    )


# --- each inclusion rule, in isolation --------------------------------------


def test_qualifying_entry_is_included() -> None:
    assert included(entry("mcp/a@1.0.0"))


def test_unverifiable_registry_is_excluded() -> None:
    for registry in ("oci", "nuget", "mcpb", "unknown"):
        assert not included(entry("mcp/a@1.0.0", registry=registry)), registry


def test_missing_repository_is_excluded() -> None:
    assert not included(entry("mcp/a@1.0.0", repository=None))


def test_empty_description_is_excluded() -> None:
    assert not included(entry("mcp/a@1.0.0", description=""))
    assert not included(entry("mcp/a@1.0.0", description="   "))


def test_superseded_version_is_excluded() -> None:
    assert not included(entry("mcp/a@1.0.0", is_latest=False))


def test_inactive_status_is_excluded() -> None:
    for status in ("deprecated", "deleted", "unknown"):
        assert not included(entry("mcp/a@1.0.0", status=status)), status


def test_pypi_is_also_a_verifiable_registry() -> None:
    assert included(entry("mcp/a@1.0.0", registry="pypi"))


# --- the score plays no part -------------------------------------------------


def test_selection_ignores_the_audit_score_entirely() -> None:
    # A qualifying entry with the worst possible score is kept; a
    # disqualified entry with the best possible score is not. If selection
    # ever started reading `entry.audit`, this is the test that would catch
    # it - the two entries are constructed to disagree with each other on
    # score while agreeing with the fixed criteria on inclusion.
    should_be_in = entry("mcp/qualifies@1.0.0", score=0, blocking=True)
    should_be_out = entry("mcp/fails@1.0.0", registry="oci", score=100, blocking=False)

    index = RegistryIndex(entries=(should_be_in, should_be_out))
    selected = select(index)

    ids = {e.id for e in selected}
    assert should_be_in.id in ids
    assert should_be_out.id not in ids


# --- ordering, the cap, and reproducibility ---------------------------------


def test_selection_sorts_survivors_by_id() -> None:
    index = RegistryIndex(entries=(entry("mcp/zebra@1.0.0"), entry("mcp/alpha@1.0.0")))

    selected = select(index)

    assert [e.id for e in selected] == ["mcp/alpha@1.0.0", "mcp/zebra@1.0.0"]


def test_cap_is_enforced_by_id_order_not_by_score() -> None:
    # More qualifying entries than the cap allows. The kept ones must be
    # exactly the lexicographically-first CAP ids - never the highest-scored
    # ones, which is what this test would catch if the tie-break secretly
    # preferred score.
    entries = tuple(entry(f"mcp/item-{i:04d}@1.0.0", score=i % 100) for i in range(CAP + 25))
    index = RegistryIndex(entries=entries)

    selected = select(index)

    assert len(selected) == CAP
    expected_ids = sorted(e.id for e in entries)[:CAP]
    assert [e.id for e in selected] == expected_ids


def test_selection_is_idempotent() -> None:
    # A selection that is not reproducible cannot be cited: the same input
    # must yield the same set, in the same order, every time.
    entries = tuple(
        entry(f"mcp/item-{i}@1.0.0", registry="npm" if i % 2 else "oci") for i in range(30)
    )
    index = RegistryIndex(entries=entries)

    first = select(index)
    second = select(index)

    assert first == second
    assert [e.id for e in first] == [e.id for e in second]


def test_below_the_floor_is_reported_as_is() -> None:
    # No entry qualifies here. `select` must not invent a looser rule to
    # reach the 100-entry floor - it reports the true (empty) result.
    index = RegistryIndex(entries=(entry("mcp/a@1.0.0", repository=None),))

    assert select(index) == ()


# --- the end-to-end run, against a file on disk -----------------------------


def test_run_reads_selects_and_reports(tmp_path: Path) -> None:
    source = RegistryIndex(
        entries=(
            entry("mcp/keep@1.0.0", score=90),
            entry("mcp/drop@1.0.0", registry="oci", score=95),
        ),
        built_at="2026-08-17T18:16:54+00:00",
    )
    source_path = tmp_path / "source.json"
    source.write(source_path)

    curated, report = run(source_path)

    assert [e.id for e in curated.entries] == ["mcp/keep@1.0.0"]
    assert curated.built_at == "2026-08-17T18:16:54+00:00"
    assert report.source_count == 2
    assert report.selected_count == 1
    assert report.with_repository == 1
    assert report.is_latest_count == 1
    assert report.registry_split == {"npm": 1}
    assert len(report.source_sha256) == 64  # a hex sha256 digest


def test_curated_output_round_trips_through_the_standard_reader(tmp_path: Path) -> None:
    # The shipped file has to be loadable by the exact same `RegistryIndex.read`
    # a synced cache is loaded by - it is not a special format.
    source = RegistryIndex(entries=(entry("mcp/keep@1.0.0"),))
    source_path = tmp_path / "source.json"
    source.write(source_path)

    curated, _report = run(source_path)
    out_path = tmp_path / "curated.json"
    curated.write(out_path)

    restored = RegistryIndex.read(out_path)
    assert [e.id for e in restored.entries] == ["mcp/keep@1.0.0"]


def test_report_describes_the_selection_without_influencing_it() -> None:
    # The report is a *description* of who survived (score buckets among
    # other fields), built after selection - not an input to it. The
    # excluded entry's score (100) must not appear in the report at all,
    # even though it is the higher of the two: it never made it into the
    # selected set for `report_for` to describe.
    source = RegistryIndex(
        entries=(entry("mcp/a@1.0.0", score=0), entry("mcp/b@1.0.0", score=100, registry="oci")),
    )
    selected = select(source)
    report = report_for(Path(__file__), source, selected)

    assert report.selected_count == 1
    assert report.score_buckets == {"0-19": 1}
