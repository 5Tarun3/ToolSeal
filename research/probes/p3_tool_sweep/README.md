# P3 - Tool sweep over the utility-coverage servers

**Question.** Of the MCP servers people actually install, how many can be
enumerated at all, and how many declare security annotations when they are?

**Why it was run.** [P1](../p1_remote_mcp_annotations/README.md) captured three
remote servers and found 92 of 92 tools annotated. That is a suspiciously tidy
number to generalise from: all three are commercial SaaS with a paid engineer
maintaining the integration. The stdio servers a developer installs with
`npx -y` are a different population, and both contribution C5 and check family
G act on annotation hints, so whether those hints exist in the wild is not a
detail.

## Method

The 18 stdio servers in
[`research/registry-utility-coverage.md`](../../registry-utility-coverage.md)
were each started and asked one question - `tools/list` - by
`bench/mcp_probe.py`, a minimal MCP client written for this (newline-delimited
JSON-RPC; no dependency added). `bench/sweep.py` drives it.

**This executes third-party code**, which is the cost of the answer. What
bounds it:

- The child environment is an allowlist, so no credential in the calling shell
  is visible to a probed server.
- `HOME` is **synthesised** inside each server's throwaway workspace rather
  than inherited. A server gets somewhere to write without getting
  `~/.aws/credentials` or `~/.ssh`.
- Each server is killed on timeout, run with `shell=False`, and given a fresh
  workspace.
- Nothing is passed a real credential.

**Isolation actually used: host, not container.** Docker was installed but its
daemon was not running. `sweep.py` checks by running `docker info` rather than
by looking for the binary on `PATH`, records the mode in `results/summary.json`,
and offers `--require-container` to refuse a host-mode run outright. In host
mode network egress and reads outside the workspace are *not* bounded. A reader
who considers that disqualifying should treat these numbers as unverified.

Each server's expected requirement was written down **before** the run
(`Launch.needs`), so a failure could not be rationalised afterwards. That
turned out to matter: see below.

## Results

Reproduce with `uv run python bench/sweep.py`. Full data in
`results/summary.json`; per-server tool lists in `results/<capability>-tools.json`.

**11 of 18 servers enumerated. 111 tools. 95 annotated.**

Measured at a 300-second per-server timeout. That number is load-bearing:
at 120s and 180s, `mongodb-mcp-server` was scored a failure, and it is in
fact simply slow to start (see the harness defects below).

| Capability | Tools | Annotated |
| --- | ---: | ---: |
| mongodb (`mongodb-mcp-server`) | 31 | 31 |
| browser (`@playwright/mcp`) | 24 | 24 |
| filesystem | 14 | 14 |
| vector-store (`chroma-mcp`) | 13 | **0** |
| git | 12 | 12 |
| memory | 9 | 9 |
| time | 2 | 2 |
| documentation (`context7`) | 2 | 2 |
| redis (`@upstash/redis-mcp`) | 2 | **0** |
| reasoning (sequential-thinking) | 1 | 1 |
| http-fetch | 1 | **0** |

### Finding 1: annotation coverage is not what P1 suggested

P1's remote SaaS servers annotated 92/92. Here **16 of 111 tools (14%) carry no
annotations at all**, concentrated in three servers that annotate nothing
whatsoever: `chroma-mcp` (13 tools), `@upstash/redis-mcp` (2), and
`mcp-server-fetch` (1).

`mcp-server-fetch` is a protocol *reference* server. A tool that fetches
arbitrary URLs is exactly the kind that should declare `openWorldHint`, and it
declares nothing. This is the gap C5 exists to compensate, in the population
that matters, rather than in a fixture built to demonstrate it.

### Finding 2: three servers are dead on arrival from an unpinned SDK

`postgres-mcp` and `aseprite-live-mcp` both fail identically:

```
ModuleNotFoundError: No module named 'mcp.server.fastmcp'. This is mcp 2.x,
where FastMCP was renamed to MCPServer ... or pin 'mcp<2' to keep running v1 code.
```

`mcp-server-sqlite` fails to the same underlying cause a layer up:
`AttributeError: 'Server' object has no attribute 'list_resources'`.

All three are published, listed as active, and install without error. The MCP
Python SDK released a 2.0 with renamed APIs; these packages never constrained
their dependency on it, so every fresh install now resolves to an SDK they
cannot run against.

This is check **`C1` (unpinned dependency)** occurring in the wild, in packages
a developer would reasonably reach for. The project has argued that unpinned
dependencies are a live risk rather than a hygiene preference; this is that
argument as an observation.

### Finding 3: one server cannot run on Windows and does not say so

`mcp-shell-server` fails with `ModuleNotFoundError: No module named 'pwd'`.
`pwd` is a Unix-only standard-library module. The package declares no platform
marker, so it installs cleanly on Windows and then cannot start.

### Finding 4: every genuine failure was a dependency failure, not the one predicted

Each server's expected requirement was recorded before the run. Almost none
of them were why it actually failed:

| Capability | Predicted need | Actual outcome |
| --- | --- | --- |
| pixel-art | a running Aseprite instance | broken: unpinned SDK |
| postgresql | a database connection string | broken: unpinned SDK |
| sqlite | a database path | broken: SDK API removed |
| shell | an `ALLOW_COMMANDS` allowlist | cannot run on Windows |
| mongodb | a connection string | **works** - merely slow to start |
| vector-store | a Chroma client configuration | **works** - the harness broke it |
| containers | a running Docker daemon | correct |
| python-execution | a deno runtime | correct |
| orchestration | a reachable cluster | prints usage; cause not established |

`kubernetes-mcp-server` is the one genuine unknown left. It responds to the
bare invocation its own `--help` documents as "start STDIO server" by
printing that help instead, and no error accompanies it. Whether npx is
interposing an argument or the server rejects something silently was not
established, and it is left as unknown rather than assigned a cause.

Two of nine predictions held. The rest were wrong in the direction that
matters: a missing prerequisite is a property of the environment, while an
unpinned dependency is a property of the package, and only reading each
server's own stderr told the two apart. Guessing would have produced a tidy,
wrong table.

`docker-mcp` refusing to answer `tools/list` without a reachable daemon is
worth noting on its own. Enumeration is how a client discovers what a server
offers; a server that will not describe itself until it can connect to its
backend cannot be catalogued by anyone, including its own registry.

## Threats to validity

**Purposive corpus, small n.** Eighteen servers chosen for capability coverage,
not sampled. No proportion here describes the MCP ecosystem.

**One platform.** Windows. The `pwd` finding is real but a Linux run would not
reproduce it, and other servers may fail here for reasons that are equally
local. A cross-platform sweep is the obvious next step and has not been done.

**Host isolation.** See Method. Network egress was not bounded.

**The harness was wrong seven times before it was right.** Recorded in full
below, because a measurement instrument that produced plausible wrong answers
seven times is a fact a reader should weigh more heavily than any number above.

## Harness defects found while building this

Every one produced believable but wrong output rather than an error, which is
the failure mode a measurement harness must be assumed to have:

1. **`stderr_tail` was declared and never populated.** Every failure read
   `no response to initialize` regardless of cause, making a missing argument
   indistinguishable from a crash.
2. **`--only` overwrote `summary.json`**, replacing an 18-server result with a
   one-server file of identical shape.
3. **`HOME` was omitted from the child environment.** `chroma-mcp` was recorded
   as a broken server; with a home it returns 13 tools. The harness
   manufactured the failure it then reported, and this would have shipped as a
   finding about the ecosystem.
4. **No retries.** `mongodb-mcp-server` scored failed, then 31 tools, then
   failed, across identical runs.
5. **A module comment stating `HOME` was never passed** survived the change
   that started passing it.
6. **The per-server timeout was too short.** At 120s and 180s
   `mongodb-mcp-server` was scored a failure; at 300s it returns 31 tools
   with an empty stderr. An arbitrary constant in the instrument was being
   reported as a property of the server.
7. **The stderr tail captured npm's chatter, not the error.** npm prints
   `npm notice New major version...` *after* a failing package's stack
   trace, so the last lines of stderr were the runner talking about itself.
   `docker-mcp`'s actual message - "Docker daemon is not accessible" - only
   became visible once the runner's own output was filtered out.

Defect 3 is the one worth dwelling on: the instrument's own security control
caused a false negative, and nothing about the output looked wrong.
