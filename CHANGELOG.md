# Changelog

All notable changes to this project are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Entries are grouped by what someone installing or auditing with `toolseal`
would notice, not by the internal step numbers used to plan the work.

## [Unreleased]

### Added

- `toolseal init` with no project name, or with `-i`, now runs a guided prompt
  flow covering provider, framework and regime profile, each listed with its
  security trade-off, and prints the equivalent non-interactive command when
  it finishes.

## [0.1.1] - 2026-08-28

### Changed

- The shipped registry is no longer a slice of the alphabet. The previous 113
  entries came from a bounded crawl of a listing ordered such that a bounded
  walk returns an alphabetical prefix, which put 1988 of 2000 crawled entries
  under one namespace prefix and left the set with no database tool at all -
  `registry search database` returned nothing. It is replaced by one canonical
  server per capability people use daily (filesystem, git, shell, Python,
  fetch, time, memory, sequential thinking, PostgreSQL, MongoDB, SQLite,
  Redis, Chroma, browser, docs, Docker, Kubernetes, Aseprite, Sentry, Notion,
  Linear), each verified against npm or PyPI directly. Recorded as a coverage
  set rather than a sample: no proportion computed over it describes the
  ecosystem.
- `registry search` ranks by relevance instead of testing whether the query is
  a contiguous substring. The old matcher required the whole query to appear
  verbatim and in order, so "postgres database" and "browser automation"
  returned nothing at all. Replaced with BM25 over weighted fields, with
  stopword removal and light stemming. Measured against twenty queries fixed
  before the ranker was written: MRR 0.000 to 0.604, recall@5 0.042 to 0.717.
- Search results report each entry's posture inline. The `tools` column, which
  only ever said `1` or `-`, becomes `hints` and carries what a row declares
  about itself - destructive, read-only, enumerated-but-undeclared, or not
  enumerated - each with a spelled-out legend.
- Relevance now decides result position and the assessment is reported beside
  it rather than ranked on. A blocking entry remains floored below everything
  that is not blocking, but is still returned: hiding a result someone asked
  for teaches them the search is not answering them.

### Added

- The registry indexes **tools**, not only servers. 203 tool entries across 21
  capabilities carry real input schemas and annotation hints, where every
  previous entry reported `tools_enumerated: false` with both fields empty.
- `toolseal registry ingest` adds a server's tools from a captured
  `tools/list` response. `sync` still crawls metadata and still executes
  nothing; this is the other half, reading a response an operator already
  obtained from a server they chose to authenticate to.

### Fixed

- `add tool` no longer wraps a tool in an approval guard when its author
  declared `destructiveHint: false`. Guard synthesis keyed on whether the hint
  was present rather than what it said, so a real 92-tool corpus produced 92
  approval gates where 23 tools declared themselves destructive - and each
  generated decorator claimed the tool was "declared destructive by its
  author", which for those tools was untrue. Compensation for an *undeclared*
  hint is unchanged: it still fails closed and gates.

## [0.1.0] - 2026-08-26

The first public release. Everything below had landed on `main` over the
course of development; this section is the initial feature set as published,
not a list of changes since some earlier release.

Released from the same pipeline rehearsed by `0.1.0rc1` on TestPyPI: PyPI
Trusted Publishing (OIDC, no stored token), PEP 740 attestations, and sigstore
keyless signing of the wheel, sdist, and SBOM.

### Added

- `toolseal init` scaffolds a secure-by-default agent project for a chosen
  provider and framework (providers: Anthropic, OpenAI, Gemini, Ollama;
  frameworks: LangGraph, CrewAI, Claude Code), with credentials provisioned
  through the OS keychain instead of a file on disk.
- `toolseal audit` scores any project — toolseal-created or not — against a
  misconfiguration taxonomy of checks grouped into seven families: credential
  exposure, capability overprovisioning, supply-chain integrity, transport and
  endpoint, execution containment, accountability, and translation integrity.
  Supports `--json`, SARIF 2.1.0 output (`--sarif`), and `--min-severity`
  filtering.
- `toolseal policy` command group for inspecting and managing the checks
  `audit` runs: `list` (published standards and their coverage), `explain`
  (a browsable catalogue of every check and control), `show`, `apply`,
  `check`, `relax` (a justified, expiring deviation from a check), and
  `enforce` / `enforce --release` to seal a resolved policy and later verify
  nothing has drifted from what was sealed.
- Regulatory regime profiles for GDPR, HIPAA, and DORA, selectable at scaffold
  time with `init --profile` or adopted afterward with `policy apply`, which
  narrow the baseline policy to what each regime specifies.
- `toolseal registry` command group over a curated index of open-source tools
  and MCP servers: `sync` (crawl and rebuild the local index, optionally
  narrowed with `--search` to a name known in advance — default pagination is
  alphabetically biased, so this is how a specific server is found reliably
  without raising `--max-pages`), `search` (ranked by relevance, ties broken
  by name and then by assessment), and `show` (full detail on one entry).
  `search`/`show` work immediately after install, before `sync` has ever run,
  against a 113-entry set selected by fixed, published, score-blind criteria
  (`research/registry-curation-criteria.md`) and shipped inside the package;
  a local `sync` supersedes it with the user's own, larger crawl.
- A cross-framework translation layer: a tool normalized into the registry's
  descriptor can be lowered into any supported framework's native tool-binding
  idiom. Wherever a target framework can't express a security property the
  source declared — for example a destructive-operation annotation — a
  compensating guard is generated instead of the property being silently
  dropped.
- `toolseal add tool <id>` lowers one registry entry into the current
  project: it looks the entry up in the index, generates a guarded binding
  for the project's target framework, and writes a `compensation.json`
  manifest recording what survived translation, what was compensated by a
  generated guard, and what could not be. `toolseal audit` reads that
  manifest back, so family G (translation integrity) now fires against a
  real project instead of only against a test-constructed one.
- `toolseal doctor` reports environment information (OS, keychain backend,
  Python and toolseal versions) for diagnosing a broken setup.
- CycloneDX SBOM generation (check `C5`): every scaffolded project is given
  its own `sbom.json`, generated from what was actually resolved rather than
  the declared version ranges.
- A managed, delimited block in a scaffolded project's `CLAUDE.md` rather than
  a full overwrite, so `toolseal revert` can remove exactly what it added and
  nothing else.
- The Claude Code sandbox is enabled by default in scaffolded projects, with
  an explicit warning when the host environment can't actually engage it.
- A coordinated disclosure policy (`DISCLOSURE.md`) for findings this
  project's own studies turn up in third-party quickstarts, templates, and
  MCP servers.

### Changed

- CLI output was redesigned around one shared visual language: the audit
  report is verdict-first, `--help` is grouped by pillar (Scaffold, Audit,
  Diagnostics, Registry), the doctor and registry reports are framed in
  panels, and colour is applied consistently across `policy`, `audit`, `mcp`,
  `doctor`, `init`, and `registry`.
- Error output now names the exit code the process is about to return and
  points at `--verbose` for detail.
- MCP name resolution (check `C3`) now verifies the resolved package at audit
  time, resolves a server by its args-derived package rather than its config
  key, and strips version suffixes instead of treating them as part of the
  name — closing a gap where a lookalike package name could pass unnoticed.

### Fixed

- Guard synthesis respects what an annotation *says*, not merely that it is
  present. `add tool` keyed on the presence of `destructiveHint`, so a tool
  whose author declared `destructiveHint: false` was still wrapped in an
  approval guard — and the generated decorator read "declared destructive by
  its author", which for those tools was untrue. Enumerating three production
  MCP servers (probe `P1`) and lowering the resulting 92-tool corpus produced
  92 approval gates against 23 tools that actually declared themselves
  destructive; an approval prompt on nearly every call is one nobody reads.
  A hint declared `false` is now recorded in the compensation manifest rather
  than gating the call. An *undeclared* hint is unchanged and still gates:
  compensation fails closed, so only an explicit `false` relaxes a guard.
- Three Windows-specific rendering defects in the audit report.
- CLI table cells now truncate in plain ASCII rather than rich's Unicode
  ellipsis, which did not render correctly in every terminal encoding.
- The taxonomy's coverage-to-control mapping is now checked row by row, so one
  mis-mapped check is caught instead of being masked by an otherwise-correct
  document.
- `CLAUDE.md`'s guidance no longer implies that permissions alone are the
  whole security posture.

### Security

- `rich` is now declared as an explicit runtime dependency rather than an
  implicit one, and the project's own SBOM — previously stale and missing it
  entirely — is regenerated from the environment actually installed.

[Unreleased]: https://github.com/5Tarun3/ToolSeal/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/5Tarun3/ToolSeal/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/5Tarun3/ToolSeal/releases/tag/v0.1.0
