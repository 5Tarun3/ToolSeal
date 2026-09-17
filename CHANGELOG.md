# Changelog

All notable changes to this project are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Entries are grouped by what someone installing or auditing with `toolseal`
would notice, not by the internal step numbers used to plan the work.

## [Unreleased]

### Added

- **A second credential backend.** `CredentialStore` gains `EnvironmentStore`,
  which reads a credential a secret manager, orchestrator or CI runner exported
  as `TOOLSEAL_CREDENTIAL_<PROVIDER>`. This is what lets a credential reach a
  deployed agent: `KeyringStore` correctly refuses rather than degrading when no
  keychain exists, but a container has no keychain and a systemd unit has no
  unlocked session, so until now the credential story assumed a developer
  workstation.

  The environment backend is **deliberately read-only**. Assigning `os.environ`
  reaches only the current process, so `set()` and `delete()` refuse and name
  the exact variable to configure instead. A store that reported success while
  persisting nothing would be the same failure toolseal exists to prevent.

- **Explicit backend selection, recorded.** `[credentials] backend` in
  `toolseal.toml` declares which store a project expects. A declared backend is
  honoured or the command fails - never silently substituted for a weaker one.
  Declaring nothing keeps today's behaviour: resolve the strongest available.

- **Posture is reported, and the two backends are not presented as equivalent.**
  An environment variable is visible to every child process and to anything that
  can read the process table, and the audit now says so. `toolseal audit --json`
  gains a `credentials` object, the human report names the weaker backend when
  that is what resolved, and `toolseal doctor` lists every backend with its
  availability and posture.

- **MITRE ATLAS as a sixth standards catalogue.** `mitre-atlas`, content
  version `2026.09`, Apache-2.0. It is the only adversary-behaviour catalogue
  here - the other five enumerate obligations, ATLAS enumerates what an
  attacker does - which is the gap a reviewer notices first in an
  adversarial-surface argument. All 28 checks now cite an ATLAS technique.

  **The percentage measures a curated subset, not ATLAS.** ATLAS 2026.09
  publishes 120 techniques and 88 sub-techniques; this catalogue lists 16,
  selected as the ones a configuration check bears on. `toolseal policy list`
  reports `mitre-atlas 100%* 14/14`, and the `*` means what it means for
  `nist-ai-rmf` and `iso-42001` - coverage of our selection, not of the
  standard. A test now also requires every checkable entry to be cited by
  something, so that figure cannot quietly drift downward.

  Two techniques are listed and marked `checkable = false`: `AML.T0051`
  (LLM Prompt Injection) and `AML.T0080` (AI Agent Context Poisoning). They
  are named rather than omitted so the gap appears in `policy list` instead
  of being hidden behind a narrower denominator, and a test refuses any check
  that tries to cite one.

  Sourced from the primary distribution (`mitre-atlas/atlas-data`), not the
  website, which is a JavaScript application. Two files there look
  authoritative and are not: `dist/ATLAS.yaml` declares itself deprecated in
  its own first line, and `dist/ATLAS-latest.yaml` is a symlink.

- **The drift guard now covers severities.** `reference/taxonomy.md` recorded
  this against itself: the guard compared control sets per check but never
  severities, so a severity could drift between the document and the code
  unnoticed. That is not cosmetic - `blocking` is defined as any applicable
  `critical` check failing, and the score is a severity-weighted pass rate,
  so a drifted severity changes both the verdict and the number. `C2` is a
  named exemption, because it takes its severity from the advisory it reports.

- **Every guard decision is recorded, and never its arguments.** The five
  call-path guards in a generated `guards.py` write one JSON line per decision -
  guard, tool, outcome, a reason from a closed vocabulary, and the guard's own
  cost - to `.toolseal/evidence.jsonl` (rotated), or wherever
  `TOOLSEAL_EVIDENCE` points: a path, `-` for stderr, or `off`. No argument
  value ever reaches a record. A call allowed by `TOOLSEAL_ASSUME_YES` is
  recorded as `approval_override`, never as an approval. Evidence is
  best-effort: an unwritable sink warns once and the guard's decision stands.

- **A fresh project ships with a guard in its tool's call path.** `guard_tool`
  binds the guards a `[policy.tool.<name>]` table declares, and a new LangGraph
  or CrewAI project declares `timeout_seconds = 30` for `read_workspace_file` -
  with a comment saying it bounds how long the agent waits, not how long the
  tool runs. Previously the scaffold shipped a guard library and applied none of
  it. `.toolseal/evidence*` is added to the scaffold's `.gitignore`.

- **Study 6's decorator layer is measured.** `python -m bench s6` runs the
  registered attack suite against the real generated guards. **H4 is supported:
  34 of 34 cases** matched their pre-registered expectation - each guard blocked
  and missed exactly what its code says. The finding the registration did not
  anticipate: a guard's decision costs about 1-2 us and writing its evidence
  record about 85 us, so the record is 98-99% of a shipped guard's cost. H1-H3
  need the proxy layer and remain open.

### Changed

- **Family A's remediations no longer name the OS keychain as the only answer.**
  In five places they told the reader to use a keychain; for a deployed project
  that advice is impossible to follow. They now name both paths. The keychain is
  still named - it remains the right answer on a workstation.
- `toolseal init` reports which backend stored a credential rather than assuming
  the keychain. Where none exists, the failure names the variable to set.

### Notes

- **Across all of the above, no check ids were added and no score changed.**
  ATLAS citations are metadata and carry no weight; the severity guard found
  the document and code already in agreement. Credential posture is
  information, not a check: it is resolved in the CLI from the manifest and
  never enters `ProjectModel`, so no check can read it. A fresh `toolseal init`
  still audits 100/100 on either backend.
- `audit --json` gained one key and changed none of the existing ones.
  `tests/test_audit_contract.py` now pins every key that existed at 0.1.3, so a
  future rename fails in CI rather than in a downstream pipeline.
- No new runtime dependencies; `keyring`, `rich` and `typer` remain the three.

## [0.1.3] - 2026-09-16

### Removed

- **`toolseal registry sync` is withdrawn.** It crawled the public MCP registry
  into `~/.cache/toolseal/index.json`, and the registry paginates
  alphabetically, so a bounded crawl returned the front of the alphabet and
  presented it as an index. A real 2000-entry cache on a developer machine
  began at `ac.inference.sh` and never reached `s` - which is why
  `registry search slack` answered with `ai.linkdeal.www` and `ai.backengine`
  rather than nothing. Those rows also carry no tools, since registry metadata
  cannot describe a server's tools without running it, so 2000 of them diluted
  every query against the entries that had been verified by hand.

  This is a removal rather than a fix because an alphabetically truncated
  sample of a registry is not a lower-quality index - it is not an index, and
  no ranking change recovers the servers the crawl never fetched.
  `registry search` and `show` now answer from the curated set shipped in the
  package, plus anything `registry ingest` has added locally.

  **If you ever ran `registry sync`, delete `~/.cache/toolseal/index.json`.**
  It is still merged into search results if present, and it is still mostly
  alphabet.
- The weekly `registry-index` workflow goes with it. It ran `registry sync` on
  a schedule and committed the result, holding `contents: write` to do so, so
  leaving it in place would have left a scheduled job with repository write
  access pointed at a command that no longer parses.

### Added

- `pixel-mcp` 0.5.0 (`willibrandon/pixel-plugin`) joins the curated set with
  all 50 of its tools enumerated. It is the Aseprite server that currently
  runs; the previously indexed `aseprite-live-mcp` does not start at all (see
  below) and is kept alongside it rather than replaced, because a real package
  broken in a way check `C1` predicts is worth keeping in the index.
- The curated set is now 22 servers and 253 tools, up from 21 and 203.

### Fixed

- The tool-enumeration harness wrote its JSON-RPC through a text-mode pipe, so
  on Windows every message was newline-translated from `\n` to `\r\n`. MCP's
  stdio transport frames on a newline, and a strict server reads the stray
  `\r` as trailing garbage after a complete JSON value - `pixel-mcp` rejected
  every message with "invalid trailing data" and was recorded as answering
  nothing. Most servers tolerate it, which is how this survived a full sweep.
  This is the second harness control found manufacturing the failure it then
  reported, after the stripped `HOME` that made `chroma-mcp` look broken.
- The harness can now write a server's non-secret startup configuration into
  the throwaway home before launch. Never a credential: a server that needs a
  secret to answer `tools/list` is a finding the sweep exists to count.
- `toolseal init -i` no longer hangs when its answers arrive on a pipe. The
  credential question read through `getpass`, which takes input from the
  console device rather than stdin, so a piped answer never reached it and the
  prompt waited for a keypress that could not come. Anyone driving the guided
  flow from a script, a CI job or an agent harness hit a hang rather than an
  error. Echo suppression still applies on a real terminal, where it means
  something.
- **The sweep's redaction never ran.** `bench/sweep.py` defines `redact()` to
  strip host-identifying strings from everything written to `results/`, which
  is committed to a public repository - and neither write path ever called it,
  from the commit that introduced it onward. The committed captures looked
  clean only because they had been scrubbed by hand. It surfaced when a
  single-server re-run wrote the operator's IANA timezone back into
  `time-tools.json` in place of the `<LOCAL_TZ>` already committed there. Both
  write paths now call it, and `tests/test_bench_sweep.py` asserts the file on
  disk is redacted rather than only that the function can redact.

### Changed

- `cells.yml` pins its GitHub Actions by commit digest, like every other
  workflow in the repository. It was the one place an action floated on a
  major tag, where the tag could be repointed at different code without the
  repository recording a change - the thing this project's own `C`-family
  checks exist to object to. `actions/upload-artifact` also moves 4 to 7, and
  `softprops/action-gh-release` 3.0.2 to 3.0.3.

### Notes

Two servers in the curated set still carry no tools, and neither is a harness
defect - both were re-probed with the fixes above:

- `postgres-mcp` does not start. It imports `mcp.server.fastmcp`, renamed in
  mcp 2.x, and its own dependency on `mcp` is unpinned, so a fresh install
  resolves to a release that breaks it. `aseprite-live-mcp` fails identically.
  This is check `C1` happening to published packages.
- `docker-mcp` cannot reach the Docker daemon on Windows even with the daemon
  running and reachable from the same restricted environment, and with
  `DOCKER_HOST` set to each of the three plausible values. It also refuses to
  answer `tools/list` before connecting, which the protocol does not require.

## [0.1.2] - 2026-09-15

### Fixed

- A mistake the user made is no longer reported as a bug in this tool. A typo
  in your own `toolseal.toml`, or an `audit` pointed at a path that is not a
  directory, exited `3` - documented as "an unexpected failure, always a bug
  worth reporting" - and now exits `2` (usage). A malformed catalogue or
  profile *shipped with* toolseal still exits `3`, because that genuinely is a
  fault worth reporting. Scripts branching on exit codes for these cases will
  see `2` where they previously saw `3`.
- `-p` no longer means two things. It was `--provider` in `init` and
  `add framework` but `--page` in `registry search`, so the habit learned in
  one command silently did something else in the other. `--page` keeps its long
  form and loses the alias.
- `revert` in a scaffolded project no longer claims "toolseal has not written
  to" a directory that `toolseal init` created. It now says no `add` has been
  recorded there, and names what `revert` does and does not undo.
- `mcp add` resolved a package name against npm/PyPI and stopped looking the
  moment it found a hit, so a registered typosquat - which resolves
  successfully by definition - was reported as verified rather than flagged.
  Resemblance to a known package is now checked on that path too, not only
  when the name is missing entirely.

### Changed

- `toolseal init` now runs its guided prompt flow by default on any
  interactive terminal, not only when the project name is omitted - a name
  given on the command line no longer opts out of being asked about provider,
  framework, regime and credential. `--no-interactive` (new) restores the old
  flag-only behaviour even on a TTY, for a CI runner or agent harness that
  attaches one without a human present to answer; `--json` alone has the same
  effect. `-i`/`--interactive` still forces the flow off a TTY.

### Added

- `toolseal init`'s guided prompt flow covers provider, framework and regime
  profile, each listed with its security trade-off, and prints the equivalent
  non-interactive command when it finishes.
- `toolseal policy check --json`, for the one command in the policy group that
  is explicitly a machine-readable evidence report. The payload carries
  `not_assessed` and the "this is not a verdict" disclaimer alongside the
  counts, so a consumer cannot serialise the numbers free of the qualifier
  that governs them.
- `toolseal registry` help now points at the order the commands are actually
  used in: `search`, then `show`, then `add tool`.
- `toolseal init --api-key` stores a hosted provider's credential in the OS
  keychain (check A1) at scaffold time, via the same `KeyringStore` `doctor`
  already reports on. A credential-free provider (Ollama) reports nothing; a
  keychain that refuses the write is reported rather than raised, so the
  project is still created. The guided flow prompts for it too, hidden, as
  its last question, rather than adding a second place credentials enter.

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

[Unreleased]: https://github.com/5Tarun3/ToolSeal/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/5Tarun3/ToolSeal/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/5Tarun3/ToolSeal/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/5Tarun3/ToolSeal/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/5Tarun3/ToolSeal/releases/tag/v0.1.0
