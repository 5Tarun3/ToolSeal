# toolseal

Secure-by-default scaffolding and a cross-framework tool registry for agentic systems.

> **Status: pre-alpha.** The skeleton is in place; commands land incrementally.
> Nothing here is published or usable yet.

## What it will do

Setting up an agent means reconciling a provider SDK, a framework's tool-binding
idiom, and MCP server configuration. That reconciliation is usually done by
copying a quickstart — and it is where the system's permanent security posture
gets written, in the first ten minutes, by someone optimising for "does it run".

toolseal does three things:

- **Scaffold** — wire a provider and framework together with a least-privilege
  configuration and credentials kept off disk.
- **Index** — normalise open-source tools and MCP servers into a single
  descriptor carrying capability schema, security annotations and provenance.
- **Translate** — make any indexed tool usable from any supported framework,
  emitting a compensating guard wherever the target cannot express a security
  property the source declared.

`toolseal audit` scores any project against the misconfiguration taxonomy,
including projects toolseal did not create.

## Scope of the first version

| Axis | Version 1 |
| --- | --- |
| Providers | Anthropic, OpenAI, Ollama |
| Frameworks | LangGraph, CrewAI |
| Registry | 100–200 curated entries, served as a static index |
| Checks | 7 families, ~25 checks, SARIF output |

Runtime proxying, sandboxing, malicious-code detection and trust scoring are out
of scope. Each is covered by existing work.

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
