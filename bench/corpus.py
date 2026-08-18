"""Shared collection and reporting machinery for Study 1's three
network-collected strata: `official-docs`, `mcp-servers`, `templates`.

`bench/generated.py` fixed the shape this follows: fetch, extract named files
without inventing anything, materialise, audit, and count what could not be
materialised rather than dropping it. What differs here is the source - a
documentation page or a repository, not a model completion - so the fetching
and extraction are new, but the discipline is the same one that stratum
already committed to.

**Filename recovery** is the same idea as `bench/generated.py`'s
`_LOOKBACK_LINES` heuristic - an unnamed fenced block is not guessed at, but a
name given in the prose immediately around it is used - widened here to also
cover JSON, YAML and plain-text config, because a published MCP server's own
quick start is overwhelmingly an `mcpServers` JSON block, not Python.
`bench/generated.py` excludes JSON deliberately (see its module docstring);
that reason does not apply to these strata, so the sets are kept separate
rather than shared.

**Snapshotting.** Every fetch is hashed (`content_sha256`) and timestamped
(`retrieved_at`), per `research/evaluation-protocol.md`. What is committed to
this repository is the hash plus exactly the files that were extracted and
handed to `toolseal audit` (`materialised/`) - not a verbatim copy of the
whole fetched page or README, which would redistribute far more of a
third party's text than the audit result depends on. `meta.json` records
enough to notice upstream drift (`DISCLOSURE.md` §6) without needing to
re-store the moving target itself.

**Credential values never reach a committed file.** `Artefact.findings`
stores only `Finding.check_id` - never `Finding.detail`, which is where a
matched value would live - matching the discipline `bench/generated.py` and
`bench/harness.py` already established and that P38 added regression tests
for.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from typing import Any, Final

from toolseal.core.audit import audit

# ```python title=agent.py  /  ```mcp.json  /  ```json
_FENCE: Final = re.compile(r"```(?P<info>[^\n`]*)\n(?P<body>.*?)```", re.DOTALL)

# Wider than bench/generated.py's set: JSON/YAML config is the normal shape
# for a published MCP server's or template's example, not an exception to it.
_FILENAME: Final = re.compile(r"([A-Za-z0-9_.\-/]+\.(?:py|txt|env|toml|cfg|ini|json|ya?ml))")
MATERIALISABLE_SUFFIXES: Final = frozenset(
    {".py", ".txt", ".env", ".toml", ".cfg", ".ini", ".json", ".yaml", ".yml"}
)

# How many lines above a markdown fence, or characters of plain text before an
# HTML <pre>, to search for a filename the source gave but did not put on the
# fence itself.
_LOOKBACK_LINES: Final = 3
_HTML_LOOKBACK_CHARS: Final = 400

# A provider credential step, per selection-criteria.md's inclusion rule 2:
# an environment-variable-shaped name ending in API_KEY/TOKEN/SECRET, the
# vocabulary every framework's own quickstart uses for this.
_CREDENTIAL_MENTION: Final = re.compile(r"\b[A-Z][A-Z0-9]*_(?:API_KEY|TOKEN|SECRET)\b")


def _reject_path(candidate: str) -> str | None:
    """A safe, normalised relative name, or None if the candidate is hostile.

    Rejected before any normalisation - stripping a leading ``../`` first
    would turn a hostile path into an accepted one rather than refusing it,
    exactly the concern bench/generated.py documents for the same check.
    """
    if candidate.startswith("/") or ".." in PurePosixPath(candidate).parts:
        return None
    name = candidate[2:] if candidate.startswith("./") else candidate
    if PurePosixPath(name).suffix.lower() not in MATERIALISABLE_SUFFIXES:
        return None
    return name


def _name_from_markdown(text: str, info: str, fence_start: int) -> str | None:
    named = _FILENAME.search(info)
    if named is not None:
        return named.group(1)
    preceding = text[:fence_start].splitlines()[-_LOOKBACK_LINES:]
    for line in reversed(preceding):
        named = _FILENAME.search(line)
        if named is not None:
            return named.group(1)
    return None


def extract_fenced_files(text: str) -> dict[str, str]:
    """Recover named files from Markdown fences, without inventing a name."""
    files: dict[str, str] = {}
    for match in _FENCE.finditer(text):
        candidate = _name_from_markdown(text, match.group("info"), match.start())
        if candidate is None:
            continue
        name = _reject_path(candidate)
        if name is None:
            continue
        files[name] = match.group("body")
    return files


class _PreBlockExtractor(HTMLParser):
    """The text of every `<pre>` block plus the plain text just before it.

    Deliberately shallow - this is not a browser and does not lay out the
    page. `<script>`/`<style>` content is skipped so it never leaks into the
    "text before the block" window a filename is recovered from.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.blocks: list[tuple[str, str]] = []
        self._pre_depth = 0
        self._skip_depth = 0
        self._current_pre: list[str] = []
        self._context: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "pre":
            self._pre_depth += 1
            if self._pre_depth == 1:
                self._current_pre = []
        elif tag in ("script", "style"):
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "pre" and self._pre_depth:
            self._pre_depth -= 1
            if self._pre_depth == 0:
                code = "".join(self._current_pre)
                context = "".join(self._context)[-_HTML_LOOKBACK_CHARS:]
                self.blocks.append((context, code))
        elif tag in ("script", "style") and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        if self._pre_depth:
            self._current_pre.append(data)
            return
        self._context.append(data)
        joined = "".join(self._context)
        bound = _HTML_LOOKBACK_CHARS * 4
        if len(joined) > bound:
            self._context = [joined[-bound:]]


def extract_html_code_blocks(html: str) -> list[tuple[str, str]]:
    """Every `<pre>` block's text, paired with the plain text just before it."""
    parser = _PreBlockExtractor()
    parser.feed(html)
    return parser.blocks


def extract_html_files(html: str) -> dict[str, str]:
    """Recover named files from an HTML page's `<pre>` blocks.

    HTML has no fence-line metadata the way Markdown does, so every name
    comes from the surrounding prose - the same "just above it" idea
    bench/generated.py uses, widened from a few lines to a character window
    because HTML text is not reliably line-broken at points that matter.
    """
    files: dict[str, str] = {}
    for context, code in extract_html_code_blocks(html):
        matches = list(_FILENAME.finditer(context))
        if not matches:
            continue
        name = _reject_path(matches[-1].group(1))
        if name is None:
            continue
        files[name] = code
    return files


def mentions_credential_step(text: str) -> bool:
    """Whether *text* names an environment variable for a provider credential."""
    return _CREDENTIAL_MENTION.search(text) is not None


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class Artefact:
    """One candidate for a stratum, from first contact through audit."""

    stratum: str
    id: str
    source_url: str
    retrieved_at: str
    content_sha256: str = ""
    popularity: int | None = None
    files: dict[str, str] = field(default_factory=dict)
    excluded: str = ""
    audit_score: int | None = None
    blocking: bool | None = None
    findings: list[str] = field(default_factory=list)

    @property
    def materialised(self) -> bool:
        return not self.excluded


def materialise(artefact: Artefact, root: Path) -> Artefact:
    """Write exactly the recovered files to *root* and audit it.

    Mirrors `bench/generated.py`'s `evaluate`: no repair, no filling in a
    missing file, no invented name.
    """
    if not artefact.files:
        artefact.excluded = artefact.excluded or "no named file blocks recovered"
        return artefact

    root.mkdir(parents=True, exist_ok=True)
    for name, content in artefact.files.items():
        target = root / PurePosixPath(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="\n")

    report = audit(root)
    artefact.audit_score = report.score
    artefact.blocking = report.blocking
    # Only the check id, never `Finding.detail` - see the module docstring.
    artefact.findings = sorted({finding.check_id for finding in report.findings})
    return artefact


def write_snapshot(artefact: Artefact, snapshot_root: Path) -> None:
    """Persist *artefact*'s metadata and materialised files, never its raw fetch."""
    entry_dir = snapshot_root / artefact.id
    entry_dir.mkdir(parents=True, exist_ok=True)

    meta = {
        "source_url": artefact.source_url,
        "retrieved_at": artefact.retrieved_at,
        "content_sha256": artefact.content_sha256,
        "popularity": artefact.popularity,
        "materialised": artefact.materialised,
        "excluded": artefact.excluded,
    }
    (entry_dir / "meta.json").write_text(
        json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    if not artefact.files:
        return
    materialised_dir = entry_dir / "materialised"
    for name, content in artefact.files.items():
        target = materialised_dir / PurePosixPath(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="\n")


def to_dict(
    stratum: str,
    population_note: str,
    artefacts: list[Artefact],
    *,
    skipped: list[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    """*skipped* is candidates the ranking step passed over before a fetch was
    even attempted (fork, archived, stale, outside the fixed sample size) -
    counted in ``candidates_considered`` alongside every materialisation
    attempt, so nothing the search returned is silently absent from the
    report.
    """
    skipped = skipped or []
    scored = [a for a in artefacts if a.audit_score is not None]
    check_counts: dict[str, int] = {}
    for item in scored:
        for check in item.findings:
            check_counts[check] = check_counts.get(check, 0) + 1

    return {
        "study": f"S1 {stratum} stratum",
        "stratum": stratum,
        "population": population_note,
        "entries": [
            {
                "id": a.id,
                "source_url": a.source_url,
                "retrieved_at": a.retrieved_at,
                "content_sha256": a.content_sha256,
                "popularity": a.popularity,
                "materialised": a.materialised,
                "excluded": a.excluded,
                "files": sorted(a.files),
                "audit_score": a.audit_score,
                "blocking": a.blocking,
                "findings": a.findings,
            }
            for a in artefacts
        ],
        "mechanically_skipped": [
            {"id": identifier, "reason": reason} for identifier, reason in skipped
        ],
        "aggregate": {
            "candidates_considered": len(artefacts) + len(skipped),
            "materialised": len(scored),
            "excluded": len(artefacts) - len(scored) + len(skipped),
            "mean_score": (
                round(sum(a.audit_score or 0 for a in scored) / len(scored), 1) if scored else None
            ),
            "with_critical_finding": sum(1 for a in scored if a.blocking),
            "check_failure_counts": dict(sorted(check_counts.items())),
        },
    }


def to_markdown(payload: dict[str, Any], *, heading_level: str = "##") -> str:
    aggregate = payload["aggregate"]
    h = heading_level
    lines = [
        f"{h} Stratum: `{payload['stratum']}`",
        "",
        payload["population"],
        "",
        f"- Candidates considered: {aggregate['candidates_considered']}",
        f"- Materialised into an auditable project: {aggregate['materialised']}",
        f"- Excluded (counted, not dropped): {aggregate['excluded']}",
        f"- Mean audit score: {aggregate['mean_score']}",
        f"- With at least one critical finding: {aggregate['with_critical_finding']}",
        "",
        f"{h}# Entries",
        "",
        "| id | source | materialised | score | blocking | exclusion reason |",
        "| --- | --- | --- | ---: | --- | --- |",
    ]
    for entry in payload["entries"]:
        lines.append(
            f"| `{entry['id']}` | {entry['source_url']} | "
            f"{'yes' if entry['materialised'] else 'no'} | "
            f"{entry['audit_score'] if entry['audit_score'] is not None else '-'} | "
            f"{entry['blocking'] if entry['blocking'] is not None else '-'} | "
            f"{entry['excluded'] or '-'} |"
        )
    lines += [
        "",
        f"{h}# Which checks fail most often",
        "",
        "| check | entries failing |",
        "| --- | ---: |",
    ]
    lines += [
        f"| `{check}` | {count} |"
        for check, count in sorted(
            aggregate["check_failure_counts"].items(), key=lambda kv: (-kv[1], kv[0])
        )
    ]

    skipped = payload.get("mechanically_skipped") or []
    if skipped:
        lines += [
            "",
            f"{h}# Ranked but skipped before a fetch was attempted",
            "",
            "A higher-ranked candidate that fails a mechanical criterion (fork, "
            "archived, stale, or outside the fixed sample size) is recorded here "
            "rather than silently passed over.",
            "",
            "| id | reason |",
            "| --- | --- |",
        ]
        lines += [f"| `{item['id']}` | {item['reason']} |" for item in skipped]

    return "\n".join(lines) + "\n"


def write(
    payload: dict[str, Any],
    artefacts: list[Artefact],
    out_dir: Path,
    *,
    heading_level: str = "##",
) -> None:
    """Write `results.json`, `RESULTS.md` and the per-artefact snapshot."""
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "results.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out_dir / "RESULTS.md").write_text(
        to_markdown(payload, heading_level=heading_level), encoding="utf-8"
    )
    snapshot_root = out_dir / "snapshot"
    for artefact in artefacts:
        write_snapshot(artefact, snapshot_root)


def write_flat_index(payload: dict[str, Any], s1_root: Path, stratum: str) -> None:
    """A flat `results.<stratum>.json` copy alongside the per-stratum directory.

    `bench/coverage.py`'s Study 5 re-cut (`OTHER_S1_STRATA`) checks for
    exactly this filename to know whether a stratum has been collected at
    all. It is a copy, not a replacement for the fuller per-stratum output
    `write` produces in `<stratum>/` - two different consumers, two different
    shapes of "where did this stratum's results go".
    """
    s1_root.mkdir(parents=True, exist_ok=True)
    (s1_root / f"results.{stratum}.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
