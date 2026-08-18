"""Study 1: the `official-docs` stratum.

Population and per-URL rationale are fixed in
`research/studies/s1/selection-criteria.md`, committed before this module
existed. "The frameworks in scope" is a census, not a sample: `langgraph`,
`crewai`, `claude-code` - the three `toolseal` scaffolds for
(`TARGETS_BY_FRAMEWORK` in `src/toolseal/core/adapters/mcp_targets.py`).

Each entry is that framework's own MCP / tool-integration page rather than a
plain "hello world" quickstart, because the protocol's inclusion rule 2
requires a provider credential step *and* a tool/MCP binding on the same
artefact - a page that only calls a model never reaches that bar. If a listed
page does not actually carry a credential step once fetched, it is not
swapped for a more favourable one; it is excluded and the exclusion is the
finding (see `selection-criteria.md`, "if a listed page turns out not to
satisfy...").
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from bench.corpus import (
    Artefact,
    extract_html_files,
    materialise,
    mentions_credential_step,
    now_iso,
    sha256_hex,
)
from toolseal.core.net import HttpError, get_text

POPULATION_NOTE: Final = (
    "Census of the frameworks toolseal scaffolds for (langgraph, crewai, "
    "claude-code), fixed by URL in research/studies/s1/selection-criteria.md."
)


@dataclass(frozen=True)
class DocPage:
    framework_id: str
    url: str


POPULATION: Final[tuple[DocPage, ...]] = (
    DocPage("claude-code", "https://docs.claude.com/en/docs/claude-code/mcp"),
    DocPage("langgraph", "https://docs.langchain.com/oss/python/langchain/mcp"),
    DocPage("crewai", "https://docs.crewai.com/en/mcp/overview"),
)


def run(
    workspace: Path,
    *,
    fetch_text: Callable[[str], str] = get_text,
    population: tuple[DocPage, ...] = POPULATION,
) -> list[Artefact]:
    """Fetch, filter and materialise every page in *population*."""
    artefacts: list[Artefact] = []
    for page in population:
        artefact = Artefact(
            stratum="official-docs",
            id=page.framework_id,
            source_url=page.url,
            retrieved_at=now_iso(),
        )
        try:
            html = fetch_text(page.url)
        except HttpError as exc:
            artefact.excluded = f"page unreachable: {exc}"
            artefacts.append(artefact)
            continue

        artefact.content_sha256 = sha256_hex(html.encode("utf-8"))

        if not mentions_credential_step(html):
            artefact.excluded = (
                "no provider credential step visible on this page (inclusion "
                "rule 2 of selection-criteria.md) - materialising would "
                "require inventing one; the credential setup and the tool "
                "binding live on different pages"
            )
            artefacts.append(artefact)
            continue

        artefact.files = extract_html_files(html)
        artefacts.append(materialise(artefact, workspace / page.framework_id))
    return artefacts
