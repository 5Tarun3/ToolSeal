# Registry selection: utility coverage

Supersedes the mechanical selection described in
[`registry-curation-criteria.md`](registry-curation-criteria.md) as the basis
for what the package ships. That document is kept, unchanged, because the
reasoning in it about circularity still holds and the shipped set must still
satisfy its score-blind rules. What changed is the *sampling frame*, and this
document exists to say so plainly rather than let a quiet swap pass as a
refinement.

## Why the previous set was withdrawn

P16 selected mechanically from an already-crawled index. The selection rules
were sound; the corpus they ran over was not. `crawl_mcp_registry` walks the
registry's listing from the start and stops after a page bound, and the
listing is ordered such that a bounded walk returns an alphabetical prefix:
1988 of 2000 entries fell under `ai.*`, one namespace supplying roughly a
third. The 113 entries shipped from that were a slice of the alphabet, not a
sample of anything.

The practical consequence was measurable and was measured: `database` returned
zero results against all 113, because the slice contained no database tool at
all. A registry that cannot answer "which tool talks to Postgres" is not
earning the space it occupies, whatever its entries individually score.

## What replaces it

Purposive selection across the utilities developers use daily, one canonical
server per capability. Stated as such: **this is not a random sample and no
proportion computed over it describes the MCP ecosystem.** It is a coverage
set, chosen so that a realistic query has a correct answer to find.

Selection rule, applied per capability:

1. **The capability is one people use daily.** Filesystem, git, shell, a SQL
   database, a document store, a vector store, HTTP fetch, a browser, a
   container runtime, an orchestrator, issue tracking, documentation lookup.
2. **The canonical implementation wins.** Where a vendor or the protocol's own
   maintainers publish a server, that one is taken - `@playwright/mcp` from
   Microsoft, `mongodb-mcp-server` from mongodb-js, `chroma-mcp` from
   chroma-core - rather than whichever third-party wrapper ranks highest.
3. **Existence is verified against the publishing registry, not the MCP
   registry.** Every package below was fetched from npm or PyPI directly and
   its latest version, license and deprecation status recorded at selection
   time. The MCP registry is a directory, and an incomplete one; it is not
   the authority on whether a package exists.
4. **A deprecated or archived package is excluded**, however well known. Where
   that leaves a capability unfilled, the gap is recorded below rather than
   filled with a substitute nobody uses.
5. **The score-blind rule from P16 still holds.** No entry is chosen, ordered
   or excluded by reference to `EntryAudit`. Several entries below score
   poorly and are included anyway, because the capability is real and the
   assessment's job is to report that honestly, not to gate the catalogue.

## The finding this surfaced

Most daily-driver MCP servers **are not in the MCP registry at all.** Searching
it for each capability and applying P16's own `included()` predicate returns,
for the common cases, third-party wrappers rather than the canonical server:
`@ai-capabilities-suite/mcp-filesystem` rather than
`@modelcontextprotocol/server-filesystem`, `mcparmory-github` rather than
anything official. The protocol's own reference servers - filesystem, git,
fetch, memory, sequential-thinking, time - are published on npm and PyPI and
absent from the registry that exists to list them.

For three capabilities the ecosystem has no maintained canonical server at all:

| Capability | Status |
| --- | --- |
| Slack | The official server was archived; nothing replaced it. |
| Gmail | No server published by Google. Candidates are third-party. |
| Jira | No server published by Atlassian in the registry. |
| GitHub | Official server exists but ships as a Go binary and Docker image, so `C3` cannot resolve it through npm or PyPI. |

These are recorded as absences rather than filled. An absence a reader can see
is worth more than a substitute that implies coverage the ecosystem does not
have.

## The set

Every row was verified live at selection time. Versions are as recorded then
and will drift; the point of recording them is that a later reader can check
what was true when the choice was made.

| Capability | Package | Registry | Version | License |
| --- | --- | --- | --- | --- |
| Filesystem | `@modelcontextprotocol/server-filesystem` | npm | 2026.7.10 | unspecified* |
| Git | `mcp-server-git` | PyPI | 2026.8.18 | MIT |
| Shell | `mcp-shell-server` | PyPI | 1.1.9 | MIT |
| Python execution | `mcp-run-python` | PyPI | 0.0.22 | MIT |
| HTTP fetch | `mcp-server-fetch` | PyPI | 2026.8.18 | MIT |
| Time | `mcp-server-time` | PyPI | 2026.8.18 | MIT |
| Memory | `@modelcontextprotocol/server-memory` | npm | 2026.7.4 | unspecified* |
| Sequential thinking | `@modelcontextprotocol/server-sequential-thinking` | npm | 2026.7.4 | unspecified* |
| PostgreSQL | `postgres-mcp` | PyPI | 0.3.0 | MIT |
| MongoDB | `mongodb-mcp-server` | npm | 2.1.0 | Apache-2.0 |
| SQLite | `mcp-server-sqlite` | PyPI | 2025.4.25 | unspecified |
| Redis | `@upstash/redis-mcp` | npm | 0.1.1 | MIT |
| Vector store | `chroma-mcp` | PyPI | 0.2.6 | Apache-2.0 |
| Browser | `@playwright/mcp` | npm | 0.0.79 | Apache-2.0 |
| Documentation | `@upstash/context7-mcp` | npm | 4.0.3 | MIT |
| Containers | `docker-mcp` | npm | 1.0.0 | MIT |
| Orchestration | `kubernetes-mcp-server` | npm | 0.0.66 | Apache-2.0 |
| Pixel art | `aseprite-live-mcp` | PyPI | 0.2.0 | MIT |
| Error tracking | `@sentry/mcp-server` | npm | 0.25.0 | FSL-1.1-ALv2 |
| Documents | `@notionhq/notion-mcp-server` | npm | 2.5.1 | MIT |
| Issue tracking | Linear (remote only) | - | - | - |

\* npm reports `"SEE LICENSE IN LICENSE"` for the reference servers rather than
an SPDX identifier. The repositories are MIT; the package metadata does not say
so. That is a real provenance gap in the protocol's own reference
implementations and `C4` reports it rather than resolving it by inference.

Sentry, Notion and Linear additionally carry **tool-level entries**, captured
by [P1](probes/p1_remote_mcp_annotations/README.md) from servers an operator
authenticated to. Those 92 tools are why `registry search` can answer a
question about a capability rather than only about a package.
