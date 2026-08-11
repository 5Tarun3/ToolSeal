# Contributing

## Setup

```bash
uv sync
uv run pre-commit install
```

## Before opening a pull request

CI runs exactly these four commands. Run them locally first:

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest
```

If you change dependencies, commit the updated `uv.lock` — CI installs with
`--locked` and will fail if the lockfile is stale.

## Conventions

**Errors.** Every failure raises a subclass of `ToolsealError` from
`toolseal.errors`. Library code does not call `sys.exit` and does not catch
exceptions it cannot handle. The CLI boundary in `toolseal.cli` is the only
place an exception becomes an exit code.

**Exit codes.** `0` clean · `1` findings reported · `2` usage error ·
`3` internal failure. These are a public contract; CI and the evaluation harness
branch on them.

**Output.** Diagnostics go to stderr. Stdout carries command output only, and
every command that reports data supports `--json`.

**Secrets.** Never log a credential. Redaction in `toolseal.logging` is defence
in depth, not permission.

**Tests.** Write the test the change actually needs. Boundary contracts and
security controls are tested; obvious glue is not. Tests are not a coverage
target.

**Attribution.** This project does not track code ownership. Do not add author
names, email addresses or personal identifiers to source files, documentation or
commit metadata.
