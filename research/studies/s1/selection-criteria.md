# Study 1 — selection criteria for `official-docs`, `mcp-servers`, `templates`

Fixed in writing, before any of these three strata is collected. `llm-generated`
already ran (see `RESULTS.md`) and is unaffected by this document.

The general include/exclude rules and the disclosure obligations are in
[`../../evaluation-protocol.md`](../../evaluation-protocol.md#study-1--posture-of-ecosystem-setup-guidance-rq1)
and [`../../../DISCLOSURE.md`](../../../DISCLOSURE.md). This document only fixes
the per-stratum specifics the protocol leaves open: which frameworks, which
query, which *N*, which URLs.

## `official-docs` — census, N = 3

"The frameworks in scope" means the frameworks `toolseal` scaffolds for:
`langgraph`, `crewai`, `claude-code` (`TARGETS_BY_FRAMEWORK` in
`src/toolseal/core/adapters/mcp_targets.py`). A census takes all three, not a
sample.

A plain "hello world" getting-started page for these frameworks calls a model
and stops — it does not bind a tool. The protocol's inclusion rule #2 requires
"a provider credential step **and** a tool or MCP server binding" on the same
artefact, so the entry per framework is its official MCP / tool-integration
page, fixed here by URL rather than chosen after collection:

| Framework | URL |
| --- | --- |
| `claude-code` | `https://docs.claude.com/en/docs/claude-code/mcp` |
| `langgraph` | `https://docs.langchain.com/oss/python/langchain/mcp` |
| `crewai` | `https://docs.crewai.com/en/mcp/overview` |

If a listed page turns out not to satisfy inclusion rule #2 once fetched (no
credential step visible on that page, or no tool/MCP binding), it is **not**
swapped for a different page. It is scored against the rule as written and
excluded with the reason recorded — that outcome is itself a finding about how
the framework's documentation is organised (credential setup and tool wiring
living on separate pages, so neither page alone is enough to get a bound agent
running), not a reason to go looking for a more favourable page.

## `mcp-servers` — top *N* by stars, N = 6

**Popularity signal.** GitHub's `stargazers_count`, read at snapshot time from
the GitHub REST search API:

```
GET https://api.github.com/search/repositories?q=topic:mcp-server&sort=stars&order=desc&per_page=25
```

**Ranking.** The top 25 results are fetched; the first 6 that pass every
inclusion/exclusion rule below, in ranked order, form the corpus. Repositories
skipped over are recorded with a reason, same as any other exclusion — passing
over a highly-starred repository that fails a criterion is not silently
dropping it.

**Mechanical exclusions**, applied on top of the protocol's general rules,
using fields the GitHub API already returns so no judgement is exercised
per-repository:

- `fork: true` → excluded (protocol exclusion rule #2, fork or near-duplicate).
- `archived: true` → excluded (this is no longer maintained guidance).
- `pushed_at` older than 18 months before the snapshot date → excluded
  (protocol inclusion rule #4).

**Materialisation source.** The repository's `README` (fetched via the GitHub
Contents API and decoded, not rendered HTML) is parsed for fenced code blocks
the same way `bench/generated.py` parses a completion: a named fence, or a
filename in the text immediately above it, is used; an unnamed block is not
guessed at. JSON is a materialisable suffix here (`.json`, `.yaml`, `.yml`
join the set `bench/generated.py` uses), because a published MCP server's
"quick start" is overwhelmingly an `mcpServers` JSON block, not Python.

**Query caveat, stated in advance.** `topic:mcp-server` is a self-applied
GitHub topic, not a `toolseal` judgement of what counts as an MCP server; it
returns some repositories that are broader products with an MCP surface
(workflow tools, CLIs) rather than single-purpose servers. These are not
filtered out by hand before collection — inclusion rule #1 ("presents itself
as a way to get an agent running, not as an API reference") is applied
mechanically at materialisation time instead, and a repository that fails it
is excluded with that reason. Hand-curating the query after seeing which
repositories it returns is exactly the selection-after-seeing-results bias
this document exists to prevent.

## `templates` — top *N* by stars, N = 6

**Popularity signal and query:**

```
GET https://api.github.com/search/repositories?q=agent+starter+template+in:name,description&sort=stars&order=desc&per_page=25
```

Same ranking procedure, same mechanical exclusions (`fork`, `archived`,
`pushed_at` > 18 months), same top-6-that-pass rule, same caveat about the
query being a fixed heuristic rather than a hand-picked list.

**Materialisation source.** The `README`, parsed the same way as
`mcp-servers`, plus — only if present at the repository root, fetched by exact
name and never invented — `requirements.txt`, `pyproject.toml`, and
`.env.example`. These three are the files `toolseal`'s own audit engine reads
(`_collect_dependencies` in `src/toolseal/core/audit/extract.py`), so their
absence is not compensated for by reading deeper into the tree; a template
whose configuration lives somewhere `_collect_dependencies` cannot see is
audited on what is actually visible to the engine, exactly as a developer
who ran `toolseal audit` against a checkout would see it.

## Why *N* = 6 and not larger

The protocol requires a 10% independently-double-materialised sample with
agreement reported (`evaluation-protocol.md`, Study 1 Procedure). No second
person is available to this collection run — recorded as a deviation in
`evaluation-protocol.md` rather than silently skipped. A small, fixed *N* keeps
the corpus a size a single person can materialise carefully and keeps the
single-materialiser limitation visible rather than diluted across dozens of
entries that all inherit the same unverified judgement calls.

## Snapshotting

Each artefact is stored under `research/studies/s1/<stratum>/snapshot/<id>/`:

- `meta.json` — `source_url`, `retrieved_at` (UTC, ISO 8601), `content_sha256`
  of the raw fetched bytes, the popularity signal recorded at snapshot time,
  and the inclusion/exclusion verdict with reason.
- `materialised/` — exactly the files that were extracted and handed to
  `toolseal audit`; empty when the artefact was excluded before
  materialisation.

The full raw page/README text is hashed but not committed verbatim into this
repository — `content_sha256` is what a later re-fetch is checked against
(per `DISCLOSURE.md` §6, a correction states what was true of the snapshot
without silently re-auditing the live page), while what actually gets
re-run through `toolseal audit` for reproducibility is `materialised/`, which
*is* committed in full. This keeps the corpus small and avoids redistributing
large verbatim copies of third-party documentation beyond what the audit
result depends on.

## Live secrets

If anything fetched under this stratum looks like a working credential rather
than a placeholder, collection stops for that artefact immediately per
`DISCLOSURE.md` §5: the value is never written to `meta.json`,
`materialised/`, or any results file, only the fact that a secret was found
(check id, provider/shape, file path, date), and the owner is notified through
the channel `DISCLOSURE.md` §2 prescribes.
