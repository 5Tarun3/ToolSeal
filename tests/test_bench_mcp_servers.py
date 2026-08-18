"""The mcp-servers harness: fetch is faked, ranking/filtering/parsing are real."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from bench.mcp_servers import fetch_readme_text, run, select

from toolseal.core.net import HttpError

NOW = datetime(2026, 8, 19, tzinfo=UTC)


def _item(
    name: str,
    stars: int,
    *,
    fork: bool = False,
    archived: bool = False,
    pushed_at: str = "2026-06-01T00:00:00Z",
) -> dict[str, Any]:
    return {
        "full_name": name,
        "html_url": f"https://github.com/{name}",
        "stargazers_count": stars,
        "fork": fork,
        "archived": archived,
        "pushed_at": pushed_at,
    }


def test_forks_are_mechanically_excluded() -> None:
    payload = {"items": [_item("a/one", 100, fork=True), _item("a/two", 50)]}

    kept, skipped = select(payload, now=NOW)

    assert [c.full_name for c in kept] == ["a/two"]
    assert skipped[0][0].full_name == "a/one"
    assert "fork" in skipped[0][1]


def test_archived_repositories_are_mechanically_excluded() -> None:
    payload = {"items": [_item("a/one", 100, archived=True)]}

    kept, skipped = select(payload, now=NOW)

    assert kept == []
    assert "archived" in skipped[0][1]


def test_stale_repositories_are_mechanically_excluded() -> None:
    payload = {"items": [_item("a/one", 100, pushed_at="2023-01-01T00:00:00Z")]}

    kept, skipped = select(payload, now=NOW)

    assert kept == []
    assert "18 months" in skipped[0][1]


def test_own_repository_is_excluded() -> None:
    payload = {"items": [_item("5Tarun3/ToolSeal", 1)]}

    kept, skipped = select(payload, now=NOW)

    assert kept == []
    assert "this project" in skipped[0][1]


def test_ranking_beyond_the_sample_size_is_skipped_and_counted() -> None:
    payload = {"items": [_item(f"a/repo{i}", 100 - i) for i in range(8)]}

    kept, skipped = select(payload, limit=6, now=NOW)

    assert len(kept) == 6
    assert len(skipped) == 2
    assert all("sample size" in reason for _c, reason in skipped)


def test_missing_pushed_at_is_treated_as_stale_not_fresh() -> None:
    # Absence of evidence is not evidence of freshness - the safer default
    # for an inclusion criterion is to exclude, not to assume.
    payload = {"items": [_item("a/one", 1, pushed_at="")]}

    kept, _skipped = select(payload, now=NOW)

    assert kept == []


def test_run_materialises_a_kept_candidate_from_its_readme(tmp_path: Path) -> None:
    readme_b64 = "IyBleGFtcGxlLXNlcnZlcgoKYGBgbWNwLmpzb24KeyJtY3BTZXJ2ZXJzIjoge319CmBgYAo="
    calls: list[str] = []

    def fetch_json(url: str) -> Any:
        calls.append(url)
        if "search/repositories" in url:
            return {"items": [_item("acme/example-server", 42)]}
        return {"content": readme_b64}

    artefacts, skipped = run(tmp_path, fetch_json=fetch_json)

    assert skipped == []
    assert len(artefacts) == 1
    assert artefacts[0].materialised
    assert artefacts[0].popularity == 42
    assert set(artefacts[0].files) == {"mcp.json"}


def test_unreachable_readme_is_excluded_and_counted(tmp_path: Path) -> None:
    def fetch_json(url: str) -> Any:
        if "search/repositories" in url:
            return {"items": [_item("acme/example-server", 42)]}
        raise HttpError("boom")

    artefacts, _skipped = run(tmp_path, fetch_json=fetch_json)

    assert len(artefacts) == 1
    assert not artefacts[0].materialised
    assert "unreachable" in artefacts[0].excluded


def test_fetch_readme_text_decodes_base64_content() -> None:
    from bench.mcp_servers import Candidate

    candidate = Candidate(
        full_name="acme/example",
        html_url="https://github.com/acme/example",
        stargazers_count=1,
        fork=False,
        archived=False,
        pushed_at="2026-01-01T00:00:00Z",
    )

    def fetch_json(url: str) -> Any:
        assert url == "https://api.github.com/repos/acme/example/readme"
        return {"content": "aGVsbG8="}  # "hello"

    assert fetch_readme_text(candidate, fetch_json=fetch_json) == "hello"
