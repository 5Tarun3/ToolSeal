# Study 6 — Baseline selection criteria

Committed before any candidate was examined. The survey result
(`baselines.toml`) is judged against these rules and no other; a rule added
after the survey began is a deviation and is recorded as one.

## Inclusion

A system is **included** when it:

1. belongs to one of three categories:
   - `framework-middleware` — guardrail middleware native to an agent framework;
   - `guardrail-library` — a standalone guardrail or filter library;
   - `mcp-proxy` — an MCP-layer proxy or gateway;
2. **intercepts a tool call** — evaluates, or can refuse, a tool invocation,
   not only model input or output text;
3. has a public source repository.

## Reproduction

An included system is **reproduced** when it additionally:

4. carries an OSI-approved licence;
5. installs from a public package index or from source without an account, API
   key or hosted service;
6. runs offline once installed.

Otherwise it is **quoted**: figures are taken from its own publication and
labelled `quoted, not reproduced`.

## Exclusion

A system that only classifies prompts or model outputs, and never sees a tool
invocation, is **excluded** — it is not a comparable interception point.
Excluded candidates are still recorded, with the reason.

## Evidence

Each record is built from primary evidence only: repository metadata from the
GitHub API, and a verbatim excerpt from the system's own README or
documentation. No claim about a baseline's behaviour is recorded without such
an excerpt. Search queries used to find candidates are recorded in the result
file.

A category in which no candidate qualifies is stated explicitly as empty, not
omitted.
