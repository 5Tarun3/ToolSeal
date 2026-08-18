"""The official-docs harness: fetch is faked, parsing and exclusion are real."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from bench.official_docs import POPULATION, DocPage, run

from toolseal.core.net import HttpError

PAGE_WITH_CREDENTIAL_AND_BINDING = """
<p>Set ANTHROPIC_API_KEY, then add this to your <code>.mcp.json</code>:</p>
<pre><code>{"mcpServers": {"example": {"command": "npx"}}}</code></pre>
"""

PAGE_WITHOUT_CREDENTIAL = """
<p>Use MultiServerMCPClient to connect to a server.</p>
<pre><code>client = MultiServerMCPClient()</code></pre>
"""

FIXTURE_POPULATION = (
    DocPage("with-both", "https://example.test/with-both"),
    DocPage("credential-only-page", "https://example.test/credential-only"),
)


def _fetch(pages: dict[str, str]) -> Callable[[str], str]:
    def fetch(url: str) -> str:
        for page in FIXTURE_POPULATION:
            if page.url == url and page.framework_id in pages:
                return pages[page.framework_id]
        raise HttpError(f"no fixture for {url}")

    return fetch


def test_page_with_credential_and_binding_is_materialised(tmp_path: Path) -> None:
    results = run(
        tmp_path,
        fetch_text=_fetch({"with-both": PAGE_WITH_CREDENTIAL_AND_BINDING}),
        population=(FIXTURE_POPULATION[0],),
    )

    assert len(results) == 1
    assert results[0].materialised
    assert results[0].audit_score is not None
    assert set(results[0].files) == {".mcp.json"}


def test_page_without_credential_step_is_excluded(tmp_path: Path) -> None:
    results = run(
        tmp_path,
        fetch_text=_fetch({"credential-only-page": PAGE_WITHOUT_CREDENTIAL}),
        population=(FIXTURE_POPULATION[1],),
    )

    assert len(results) == 1
    assert not results[0].materialised
    assert "credential step" in results[0].excluded


def test_unreachable_page_is_excluded_and_counted(tmp_path: Path) -> None:
    def always_fails(url: str) -> str:
        raise HttpError("boom")

    results = run(tmp_path, fetch_text=always_fails, population=FIXTURE_POPULATION)

    assert len(results) == len(FIXTURE_POPULATION)
    assert all(not r.materialised for r in results)
    assert all("unreachable" in r.excluded for r in results)


def test_every_page_in_the_default_population_is_reported() -> None:
    # The default population is the census fixed in selection-criteria.md;
    # this pins its size so a change there is visible in a test diff.
    assert {p.framework_id for p in POPULATION} == {
        "claude-code",
        "langgraph",
        "crewai",
    }
