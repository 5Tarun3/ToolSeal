# toolseal

Secure-by-default scaffolding and a cross-framework tool registry for agentic systems.

> **Status: functional, not yet published.** Every command below runs today
> from a source checkout. It has not yet been published to PyPI — see
> [Installing](#installing).

## What it does

Setting up an agent means reconciling a provider SDK, a framework's tool-binding
idiom, and MCP server configuration. That reconciliation is usually done by
copying a quickstart — and it is where the system's permanent security posture
gets written, in the first ten minutes, by someone optimising for "does it run".

toolseal does three things:

- **Scaffold** — `toolseal init` wires a provider and framework together with a
  least-privilege configuration and credentials kept in the OS keychain, never
  a file on disk. `toolseal add framework` / `add mcp` extend an existing
  project the same way; `toolseal revert` undoes exactly what was added.
- **Index** — `toolseal registry` normalises open-source tools and MCP servers
  into a single descriptor carrying capability schema, security annotations
  and provenance, and ships a curated, pre-audited starting set so `search`
  and `show` work immediately, before anyone has crawled anything.
- **Translate** — `toolseal add tool` lowers any indexed tool into any
  supported framework's native tool-binding idiom, emitting a compensating
  guard wherever the target can't express a security property the source
  declared, and recording the substitution in an auditable manifest.

`toolseal audit` scores any project — toolseal-created or not — against a
28-check misconfiguration taxonomy, with `--json` and SARIF 2.1.0 output for
CI. `toolseal policy` browses that taxonomy (`explain`), narrows it to a
regulatory regime (`apply`), and seals a resolved policy so drift from it is
caught later (`enforce`).

## Quickstart

```bash
uv run toolseal init myagent --framework crewai --provider anthropic
cd myagent
uv run toolseal audit .
```

`init` also accepts `--profile gdpr` / `hipaa` / `dora` to start under a
regulatory regime instead of the baseline policy. To add a tool from the
registry once a project exists:

```bash
uv run toolseal registry search context7
uv run toolseal add tool <id-from-search> --framework crewai
```

## Current scope

| Axis | Supported today |
| --- | --- |
| Providers | Anthropic, OpenAI, Gemini, Ollama |
| Frameworks | LangGraph, CrewAI, Claude Code |
| Regulatory regimes | GDPR, HIPAA, DORA |
| Checks | 7 families (credential exposure, capability overprovisioning, supply-chain integrity, transport and endpoint, execution containment, accountability, translation integrity), 28 checks total |
| Registry | 113 curated entries shipped in the package; `registry sync` crawls the live MCP registry for a larger, current index |

Runtime proxying, sandboxing, malicious-code detection and trust scoring are out
of scope. Each is covered by existing work.

## Installing

Not yet published to PyPI. Until then, run it from a source checkout — see
[Development](#development) below, then `uv run toolseal ...` in place of
`toolseal ...` throughout this document.

## Development

Requires [uv](https://docs.astral.sh/uv/) and Python 3.11 or newer.

```bash
uv sync                  # create the environment
uv run toolseal doctor   # check the environment
uv run ruff check .      # lint
uv run ruff format .     # format
uv run mypy              # types
uv run pytest            # tests
```

Optionally install the pre-commit hooks, which run the same lint and format
checks as CI:

```bash
uv run pre-commit install
```

## Documentation

- [`reference/`](reference/) — normative specifications, starting with the
  [misconfiguration taxonomy](reference/taxonomy.md).
- [`research/`](research/) — probes and measurement harnesses that produce
  evidence for the project's claims.

## License

Apache-2.0. See [LICENSE](LICENSE).
