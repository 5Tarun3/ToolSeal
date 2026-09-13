# toolseal

**Secure-by-default scaffolding and a cross-framework tool registry for agentic systems.**

[![CI](https://github.com/5Tarun3/ToolSeal/actions/workflows/ci.yml/badge.svg)](https://github.com/5Tarun3/ToolSeal/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/toolseal.svg)](https://pypi.org/project/toolseal/)
[![Python](https://img.shields.io/pypi/pyversions/toolseal.svg)](https://pypi.org/project/toolseal/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/5Tarun3/ToolSeal/blob/main/LICENSE)

Setting up an agent means reconciling a provider SDK, a framework's tool-binding
idiom, and MCP server configuration. That reconciliation is usually done by
copying a quickstart — and it is where the system's permanent security posture
gets written, in the first ten minutes, by someone optimising for "does it run".

toolseal makes the secure arrangement the default one, and makes the insecure
arrangement *visible* when it already exists.

```console
$ toolseal audit .

+--------------------------------------------------+
| score 32/100   BLOCKING: 1 critical check failed |
| 1 critical, 6 high, 2 medium, 1 low              |
+--------------------------------------------------+

  CRITICAL   A1  Credential literal in project file
             .env:1 - OpenAI-style key found in .env
             fix  Move the value into the OS keychain and revoke the exposed
                  credential; it must be treated as compromised.

  HIGH       C1  Unpinned dependency
             langchain is declared as >=0.1.0
             fix  Pin langchain to an exact version.

  HIGH       E2  Agent inherits the full host environment
             Cloud CLI profiles, SSH agent sockets and every exported secret
             are visible to the agent and to any tool it calls
             fix  Launch with an explicit, minimal environment.
```

---

## Install

```bash
pip install toolseal          # or: uv tool install toolseal
toolseal doctor               # verify the install
```

Requires Python 3.11+. Three runtime dependencies (`typer`, `rich`, `keyring`) —
a tool that counts other people's dependencies should be able to justify each of
its own.

## Quickstart

Create a hardened project:

```bash
toolseal init myagent --framework crewai --provider anthropic
cd myagent
toolseal audit .              # 100/100 — the scaffold passes its own checks
```

Or point it at a project you already have — toolseal did not need to create it:

```bash
toolseal audit /path/to/existing-project
toolseal audit . --json       # machine-readable
toolseal audit . --sarif      # SARIF 2.1.0, for GitHub code scanning
```

Start under a regulatory regime instead of the baseline policy:

```bash
toolseal init myagent --profile hipaa      # or gdpr, dora
toolseal policy apply gdpr                 # or adopt one later
```

### Guided setup

```bash
toolseal init
```

With no project name, `init` asks: which provider, which framework, and
whether to scaffold under a regulatory regime — each option listed with what
choosing it costs you. It finishes by printing the equivalent one-line
command, so the second project does not need the questions.

Pass `-i` to get the prompts even when you already know the name. Any flag you
supply is taken as decided rather than asked about:

```bash
toolseal init myagent -i --provider ollama
```

`--json` and `-i` cannot be combined, and a missing name outside a terminal is
an error rather than a prompt nobody can answer.

## What it does

### Scaffold — secure defaults, not a blank page

`toolseal init` wires a provider and framework together with least-privilege
configuration, credentials resolved from the OS keychain instead of a file on
disk, a redacting log filter, a pinned dependency set, and a generated SBOM.

`toolseal add framework` and `add mcp` extend a project that already exists.
Everything written is recorded, and `toolseal revert` removes exactly what was
added — including restoring files that existed beforehand, and refusing to
clobber edits you made since.

`add mcp` resolves a server's package name against npm and PyPI before writing
it anywhere, and **refuses a name that resolves nowhere**:

```console
$ toolseal add mcp @invented/definitely-not-real
error: '@invented/definitely-not-real' resolves in no registry checked. A name
that does not exist today is one an attacker can register tomorrow. Re-run with
--skip-verify if you are certain. (exit 2: usage)
```

### Audit — 28 checks, mapped to published standards

`toolseal audit` scores any project against a misconfiguration taxonomy of 28
checks in seven families:

| Family | Concern |
| --- | --- |
| **A** | Credential exposure |
| **B** | Capability overprovisioning |
| **C** | Supply-chain integrity |
| **D** | Transport and endpoint |
| **E** | Execution containment |
| **F** | Accountability |
| **G** | Translation integrity |

Every check documents itself, including which external obligations it serves:

```console
$ toolseal policy explain B3

+- B3 - Filesystem capability with unbounded or home-directory root -+
|                                                                    |
| How to fix it                                                      |
|   Confine filesystem access to the workspace.                      |
|                                                                    |
| Obligations this serves                                            |
|   owasp-llm-top10:LLM06      Excessive Agency                      |
|   owasp-agentic-threats:T3   Privilege Compromise                  |
|   owasp-agentic-top10:ASI03  Identity & Privilege Abuse            |
+--------------------------------------------------- severity: high -+
```

A check that could not be evaluated is reported as `not evaluated — data
unavailable, not a pass`. The distinction is deliberate and load-bearing: a
missing answer is never quietly scored as a good one.

### Registry — normalised, provenance-checked tool descriptors

`toolseal registry` indexes open-source tools and MCP servers into a **Unified
Tool Descriptor** carrying capability schema, security annotations, and
provenance. Every entry ships with its own assessment — the security review *is*
the entry, not an afterthought bolted on:

```console
$ toolseal registry search context7

+--------------------------------------------------------------------------+
|  | score | name                 | package@version     | registry | tools |
| -+-------+----------------------+---------------------+----------+------ |
|  |    90 | io.github.upstash... | @upstash/context... | npm      |     - |
+--------------------------------------------------------------------------+

-  tools not enumerated (would require running the server)
```

A curated set ships inside the package, so `search` and `show` work immediately
after install — before `registry sync` has ever run. Curation criteria are
[fixed and published](https://github.com/5Tarun3/ToolSeal/blob/main/research/registry-curation-criteria.md), applied by a
script rather than a person, and deliberately **blind to the audit score**: a
registry that selects entries because they scored well and then reports that its
entries score well has measured nothing.

Nothing in the index is ever executed. Enumerating a server's tools means
running it, so entries record `tools_enumerated: false` rather than implying an
empty tool set. A gap you can see beats a number you cannot trust.

### Translate — compensating guards for what a framework cannot express

This is the part that does not exist elsewhere. A tool declares security
properties at its source; each target framework can represent some subset of
them. The difference is **translation loss**, and toolseal computes it instead of
letting you discover it in production.

Measurement (probe P0) found the loss is *adapter-dependent*, not inherent:
`langchain-mcp-adapters` preserves MCP annotation hints, `crewai-tools` drops all
of them and rewrites every description. Because the loss is a choice rather than
a law, it can be repaired.

```console
$ toolseal add tool mcp/example/db@1.0.0 --framework crewai

Lowered delete_records into crewai (compensated)
  + tools/delete_records.py
  + compensation.json

guards emitted:
  - require_approval: G1: the source declared destructiveHint, which this
    framework cannot carry. The consequence is restored as an approval step.
  - preserve_description: G5: this framework rewrites tool descriptions, so the
    author's text is preserved verbatim as SOURCE_DESCRIPTION.
```

The guards are **behaviour, not annotation**. Restoring `destructiveHint` into a
framework with no field for it means wrapping the call in an approval step —
re-establishing the *consequence* of the hint, since the hint itself has nowhere
to live:

```python
# G1: the source declared destructiveHint, which this framework cannot carry.
# The consequence is restored as an approval step.
@require_approval("declared destructive by its author")
@tool
def delete_records(**kwargs: object) -> object:
    """Permanently delete rows matching a filter. This cannot be undone."""
    return DISPATCH("delete_records", kwargs)
```

Whatever happened is written to a compensation manifest, which `toolseal audit`
reads back through family `G` — so a property that was dropped with no guard in
its place becomes a finding rather than a silence.

## Policy, regimes, and sealing

```console
$ toolseal policy list

standard              | coverage | checkable
----------------------+----------+----------
iso-42001             |     33%* |       1/3
nist-ai-rmf           |     80%* |       4/5
owasp-agentic-threats |     100% |       6/6
owasp-agentic-top10   |     100% |       5/5
owasp-llm-top10       |     100% |       5/5

* curated subset of the standard, not a full enumeration -
  the percentage measures our selection, not the standard's reach.
```

Regulatory regimes — **GDPR**, **HIPAA**, **DORA** — pin severities on top of the
baseline. They are never scored, and a report run under one never ends in a
verdict, only in `not_assessed`. A configuration auditor cannot certify
compliance, and this one does not pretend to: it produces *evidence toward* an
assessment, never the assessment itself.

Two more commands close the loop:

- `toolseal policy relax <check>` — a justified, **expiring** deviation, written
  into `toolseal.toml` with its reason and expiry date.
- `toolseal policy enforce` / `verify` — seal a resolved policy, then later prove
  nothing has drifted from what was sealed.

## Command reference

| Command | Purpose |
| --- | --- |
| `init` | Create a new agent project with secure defaults |
| `audit` | Score a project against the misconfiguration taxonomy |
| `add framework` | Write a framework's configuration into an existing project |
| `add mcp` | Add an MCP server, refusing a name that resolves nowhere |
| `add tool` | Lower a registry entry into the project, compensating what is lost |
| `revert` | Undo what toolseal wrote into this project |
| `policy list` / `explain` / `show` | Inspect checks, standards, and regimes |
| `policy apply` / `relax` / `enforce` / `verify` | Adopt, deviate from, and seal a policy |
| `registry sync` / `search` / `show` | Crawl, query, and inspect the tool index |
| `doctor` | Report environment information for diagnosing a problem |

## Supported targets

| Axis | Supported |
| --- | --- |
| Providers | Anthropic, OpenAI, Gemini, Ollama |
| Frameworks | LangGraph, CrewAI, Claude Code |
| Regulatory regimes | GDPR, HIPAA, DORA |
| Standards mapped | OWASP LLM Top 10, OWASP Agentic Threats (T1–T15), OWASP Agentic Top 10 (ASI01–ASI10), NIST AI RMF, ISO/IEC 42001 |
| Output formats | Human-readable, `--json`, SARIF 2.1.0 |

**Out of scope**, deliberately: runtime proxying, sandboxing, malicious-code
detection, and trust scoring. Each is covered by existing work, and toolseal is a
*configuration* tool — it reasons about what a project declares, not about what
its code does at runtime.

## Using it in CI

Exit codes are a stable contract: `0` clean, `1` findings, `2` usage error,
`3` internal error.

```yaml
- run: pip install toolseal
- run: toolseal audit . --min-severity high
```

Or upload SARIF to GitHub code scanning:

```yaml
- run: toolseal audit . --sarif > toolseal.sarif
  continue-on-error: true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: toolseal.sarif
```

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](https://github.com/5Tarun3/ToolSeal/blob/main/CONTRIBUTING.md) for the full
guide.

```bash
git clone https://github.com/5Tarun3/ToolSeal
cd ToolSeal
uv sync
uv run pre-commit install
```

CI runs exactly four commands — run them locally first:

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest
```

Two project-specific rules worth knowing before your first PR:

- **`toolseal audit .` must report 100/100 on this repository.** A security tool
  that fails its own checks is not making an argument.
- **`--json` and SARIF output are inviolable machine contracts**, as are the exit
  codes above. A research harness parses this output.

## Documentation

- [`reference/taxonomy.md`](https://github.com/5Tarun3/ToolSeal/blob/main/reference/taxonomy.md) — the normative
  misconfiguration taxonomy: every check, its severity, and its mapping to
  published standards.
- [`research/`](https://github.com/5Tarun3/ToolSeal/tree/main/research) — probes, measurement harnesses, and the evidence
  behind the project's claims, including the
  [registry curation criteria](https://github.com/5Tarun3/ToolSeal/blob/main/research/registry-curation-criteria.md) and the
  [evaluation protocol](https://github.com/5Tarun3/ToolSeal/blob/main/research/evaluation-protocol.md).
- [`CHANGELOG.md`](https://github.com/5Tarun3/ToolSeal/blob/main/CHANGELOG.md) — release history.

## Security

To report a vulnerability **in toolseal**, see [SECURITY.md](https://github.com/5Tarun3/ToolSeal/blob/main/SECURITY.md).

For how this project handles vulnerabilities it finds in *other people's*
quickstarts, templates, and MCP servers during its own research, see
[DISCLOSURE.md](https://github.com/5Tarun3/ToolSeal/blob/main/DISCLOSURE.md).

## License

[Apache-2.0](https://github.com/5Tarun3/ToolSeal/blob/main/LICENSE).
