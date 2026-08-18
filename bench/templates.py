"""Study 1: the `templates` stratum.

Same ranking and mechanical-exclusion machinery as `bench/mcp_servers.py`
(see its module docstring for the rationale), over a different population
and query: agent-starter repositories, fixed in
`research/studies/s1/selection-criteria.md`.

**Materialisation source** is the README, parsed exactly as `mcp-servers`
parses it, plus - only when present at the repository root, fetched by exact
name and never invented - `requirements.txt`, `pyproject.toml` and
`.env.example`. These three are what
`toolseal.core.audit.extract._collect_dependencies` actually reads; a
template whose configuration lives somewhere that function does not look is
audited on what is visible to the engine, which is what a developer who
cloned the repository and ran `toolseal audit` would see too.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from pathlib import Path
from typing import Any, Final

from bench.corpus import Artefact, extract_fenced_files, materialise, now_iso, sha256_hex
from bench.mcp_servers import Candidate, fetch_readme_text, select
from toolseal.core.net import HttpError, get_json

SEARCH_URL: Final = (
    "https://api.github.com/search/repositories"
    "?q=agent+starter+template+in:name,description&sort=stars&order=desc&per_page=25"
)
SAMPLE_SIZE: Final = 6

POPULATION_NOTE: Final = (
    "Top 6 GitHub repositories matching 'agent starter template' in name or "
    "description, ranked by stars, that survive the fork/archived/"
    "18-month-staleness filter in research/studies/s1/selection-criteria.md."
)

# Fetched by exact name only if present - never invented. These are exactly
# what toolseal.core.audit.extract._collect_dependencies reads.
ROOT_FILES: Final[tuple[str, ...]] = ("requirements.txt", "pyproject.toml", ".env.example")


def fetch_root_file(
    candidate: Candidate, name: str, *, fetch_json: Callable[[str], Any]
) -> str | None:
    """One root-level file's decoded text, or None if it does not exist."""
    url = f"https://api.github.com/repos/{candidate.full_name}/contents/{name}"
    try:
        payload = fetch_json(url)
    except HttpError:
        return None
    encoded = str(payload.get("content", ""))
    if not encoded:
        return None
    return base64.b64decode(encoded).decode("utf-8", errors="replace")


def run(
    workspace: Path,
    *,
    fetch_json: Callable[[str], Any] = get_json,
    limit: int = SAMPLE_SIZE,
) -> tuple[list[Artefact], list[tuple[str, str]]]:
    """Collect, materialise and audit the templates stratum."""
    search_payload = fetch_json(SEARCH_URL)
    kept, skipped = select(search_payload, limit=limit)

    artefacts: list[Artefact] = []
    for candidate in kept:
        artefact = Artefact(
            stratum="templates",
            id=candidate.full_name.replace("/", "__"),
            source_url=candidate.html_url,
            retrieved_at=now_iso(),
            popularity=candidate.stargazers_count,
        )
        try:
            readme = fetch_readme_text(candidate, fetch_json=fetch_json)
        except HttpError as exc:
            artefact.excluded = f"README unreachable: {exc}"
            artefacts.append(artefact)
            continue

        files = extract_fenced_files(readme)
        for name in ROOT_FILES:
            content = fetch_root_file(candidate, name, fetch_json=fetch_json)
            if content is not None:
                files[name] = content

        artefact.content_sha256 = sha256_hex(
            "\x00".join([readme, *(files.get(n, "") for n in ROOT_FILES)]).encode("utf-8")
        )
        artefact.files = files
        artefacts.append(materialise(artefact, workspace / artefact.id))

    skip_reasons = [(candidate.full_name, reason) for candidate, reason in skipped]
    return artefacts, skip_reasons
