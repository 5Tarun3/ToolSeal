"""Study 1: the `mcp-servers` stratum.

Population, query and *N* are fixed in
`research/studies/s1/selection-criteria.md`, committed before this module
existed: the top 6 repositories tagged `mcp-server` on GitHub, ranked by
stars, that survive the mechanical fork/archived/staleness filter below.

**Mechanical exclusions only, at ranking time.** `fork`, `archived` and
`pushed_at` come straight from the GitHub API response, so skipping a
candidate here exercises no judgement. Inclusion rule 1 ("presents itself as
a way to get an agent running, not as an API reference") is not mechanically
decidable from API metadata - the protocol calls materialisation "the only
judgement-laden step" for exactly this reason - so a candidate that survives
ranking is still materialised and audited; a reviewer applying rule 1 by hand
against the materialised result is a separate, recorded step, not something
this module guesses at.

Every candidate the search returned - kept, mechanically skipped, or attempted
and excluded - is accounted for in :func:`run`'s return value, per the
protocol's count-exclusions rule.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final

from bench.corpus import Artefact, extract_fenced_files, materialise, now_iso, sha256_hex
from toolseal.core.net import HttpError, get_json

SEARCH_URL: Final = (
    "https://api.github.com/search/repositories"
    "?q=topic:mcp-server&sort=stars&order=desc&per_page=25"
)
SAMPLE_SIZE: Final = 6
STALE_AFTER_DAYS: Final = 548  # ~18 months, per selection-criteria.md
OWN_REPOSITORY: Final = "5tarun3/toolseal"

POPULATION_NOTE: Final = (
    "Top 6 GitHub repositories tagged mcp-server, ranked by stars, that "
    "survive the fork/archived/18-month-staleness filter in "
    "research/studies/s1/selection-criteria.md."
)


@dataclass(frozen=True)
class Candidate:
    full_name: str
    html_url: str
    stargazers_count: int
    fork: bool
    archived: bool
    pushed_at: str


def _candidates(payload: dict[str, Any]) -> list[Candidate]:
    return [
        Candidate(
            full_name=item["full_name"],
            html_url=item["html_url"],
            stargazers_count=int(item.get("stargazers_count") or 0),
            fork=bool(item.get("fork", False)),
            archived=bool(item.get("archived", False)),
            pushed_at=str(item.get("pushed_at") or ""),
        )
        for item in payload.get("items", [])
    ]


def _stale(pushed_at: str, *, now: datetime) -> bool:
    if not pushed_at:
        return True
    try:
        pushed = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
    except ValueError:
        return True
    return (now - pushed) > timedelta(days=STALE_AFTER_DAYS)


def select(
    payload: dict[str, Any],
    *,
    limit: int = SAMPLE_SIZE,
    now: datetime | None = None,
) -> tuple[list[Candidate], list[tuple[Candidate, str]]]:
    """Rank and mechanically filter; return (kept, skipped-with-reason)."""
    now = now or datetime.now(UTC)
    kept: list[Candidate] = []
    skipped: list[tuple[Candidate, str]] = []
    for candidate in _candidates(payload):
        if candidate.full_name.lower() == OWN_REPOSITORY:
            skipped.append((candidate, "authored by this project (exclusion rule 3)"))
        elif candidate.fork:
            skipped.append((candidate, "fork of another entry (exclusion rule 2)"))
        elif candidate.archived:
            skipped.append((candidate, "archived: no longer maintained guidance"))
        elif _stale(candidate.pushed_at, now=now):
            skipped.append((candidate, "not updated within 18 months of the snapshot"))
        elif len(kept) < limit:
            kept.append(candidate)
        else:
            skipped.append((candidate, "ranked outside the fixed sample size N=6"))
    return kept, skipped


def fetch_readme_text(candidate: Candidate, *, fetch_json: Callable[[str], Any]) -> str:
    """The README's decoded text via the Contents API, which returns base64."""
    url = f"https://api.github.com/repos/{candidate.full_name}/readme"
    payload = fetch_json(url)
    encoded = str(payload.get("content", ""))
    return base64.b64decode(encoded).decode("utf-8", errors="replace")


def run(
    workspace: Path,
    *,
    fetch_json: Callable[[str], Any] = get_json,
    limit: int = SAMPLE_SIZE,
) -> tuple[list[Artefact], list[tuple[str, str]]]:
    """Collect, materialise and audit the mcp-servers stratum.

    Returns every materialisation attempt plus every candidate skipped
    before one was made, each with its reason - nothing the search returned
    is silently dropped.
    """
    search_payload = fetch_json(SEARCH_URL)
    kept, skipped = select(search_payload, limit=limit)

    artefacts: list[Artefact] = []
    for candidate in kept:
        artefact = Artefact(
            stratum="mcp-servers",
            id=candidate.full_name.replace("/", "__"),
            source_url=candidate.html_url,
            retrieved_at=now_iso(),
            popularity=candidate.stargazers_count,
        )
        try:
            text = fetch_readme_text(candidate, fetch_json=fetch_json)
        except HttpError as exc:
            artefact.excluded = f"README unreachable: {exc}"
            artefacts.append(artefact)
            continue

        artefact.content_sha256 = sha256_hex(text.encode("utf-8"))
        artefact.files = extract_fenced_files(text)
        artefacts.append(materialise(artefact, workspace / artefact.id))

    skip_reasons = [(candidate.full_name, reason) for candidate, reason in skipped]
    return artefacts, skip_reasons
