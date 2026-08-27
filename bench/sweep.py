"""P3: enumerate the tools of every stdio server in the utility-coverage set.

Answers a question nothing in this project could answer before: of the servers
people actually run, how many declare security annotations at all? P1 captured
three remote servers and found 92/92 tools annotated, which is a suspiciously
tidy number to generalise from - all three are commercial SaaS with a paid
engineer maintaining the integration. The stdio servers people install with
`npx -y` are a different population.

**This executes third-party code.** That is the whole cost of the answer, and
it is bounded rather than waved at:

* The child environment is an allowlist (`mcp_probe.child_environment`), so no
  credential in the calling shell is visible to a probed server.
* Each server runs in its own throwaway workspace and is killed on timeout.
* Nothing is passed a real credential. A server that needs one to list its
  tools fails, and that failure is the finding - `tools/list` is supposed to
  be answerable before authentication.

What this does *not* bound, when run without a container, is network egress or
reads outside the workspace. `--require-container` refuses to run at all
unless a container runtime is available, and the report records which mode
produced it so a reader can tell the two apart.

Usage:

    uv run python bench/sweep.py [--only NAME] [--timeout N] [--require-container]
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mcp_probe import ProbeResult, list_tools  # type: ignore[import-not-found]

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "research" / "probes" / "p3_tool_sweep" / "results"


@dataclass(frozen=True)
class Launch:
    """How to start one server, and what it needs that we will not give it."""

    capability: str
    entry_id: str
    command: tuple[str, ...]
    needs: str = ""
    """What the server requires beyond a bare launch, if anything.

    Recorded before the run, not after. A server that fails having declared
    `needs` was expected to; one that fails without is a genuine surprise, and
    keeping the two apart is the difference between a result and an excuse.
    """

    workspace_arg: bool = False
    """Append the throwaway workspace path as the final argument."""


LAUNCHES: tuple[Launch, ...] = (
    Launch(
        "time",
        "mcp/io.modelcontextprotocol/server-time@2026.8.18",
        ("uvx", "mcp-server-time"),
    ),
    Launch(
        "http-fetch",
        "mcp/io.modelcontextprotocol/server-fetch@2026.8.18",
        ("uvx", "mcp-server-fetch"),
    ),
    Launch(
        "memory",
        "mcp/io.modelcontextprotocol/server-memory@2026.7.4",
        ("npx", "-y", "@modelcontextprotocol/server-memory"),
    ),
    Launch(
        "reasoning",
        "mcp/io.modelcontextprotocol/server-sequential-thinking@2026.7.4",
        ("npx", "-y", "@modelcontextprotocol/server-sequential-thinking"),
    ),
    Launch(
        "filesystem",
        "mcp/io.modelcontextprotocol/server-filesystem@2026.7.10",
        ("npx", "-y", "@modelcontextprotocol/server-filesystem"),
        needs="a directory to confine itself to",
        workspace_arg=True,
    ),
    Launch(
        "git",
        "mcp/io.modelcontextprotocol/server-git@2026.8.18",
        ("uvx", "mcp-server-git"),
        needs="a repository path",
    ),
    Launch(
        "documentation",
        "mcp/io.github.upstash/context7@4.0.3",
        ("npx", "-y", "@upstash/context7-mcp"),
    ),
    Launch(
        "browser",
        "mcp/io.github.microsoft/playwright-mcp@0.0.79",
        ("npx", "-y", "@playwright/mcp"),
        needs="browser binaries installed",
    ),
    Launch(
        "sqlite",
        "mcp/io.modelcontextprotocol/server-sqlite@2025.4.25",
        ("uvx", "mcp-server-sqlite"),
        needs="a database path",
    ),
    Launch(
        "python-execution",
        "mcp/io.github.pydantic/mcp-run-python@0.0.22",
        ("uvx", "mcp-run-python", "stdio"),
        needs="a deno runtime for its sandbox",
    ),
    Launch(
        "shell",
        "mcp/io.github.tumf/mcp-shell-server@1.1.9",
        ("uvx", "mcp-shell-server"),
        needs="an ALLOW_COMMANDS allowlist in the environment",
    ),
    Launch(
        "postgresql",
        "mcp/io.github.crystaldba/postgres-mcp@0.3.0",
        ("uvx", "postgres-mcp"),
        needs="a database connection string",
    ),
    Launch(
        "mongodb",
        "mcp/io.github.mongodb-js/mongodb-mcp-server@2.1.0",
        ("npx", "-y", "mongodb-mcp-server"),
        needs="a connection string",
    ),
    Launch(
        "redis",
        "mcp/io.github.upstash/redis-mcp@0.1.1",
        ("npx", "-y", "@upstash/redis-mcp"),
        needs="Upstash credentials",
    ),
    Launch(
        "vector-store",
        "mcp/io.github.chroma-core/chroma-mcp@0.2.6",
        ("uvx", "chroma-mcp"),
        needs="a Chroma client configuration",
    ),
    Launch(
        "containers",
        "mcp/io.github.quantgeekdev/docker-mcp@1.0.0",
        ("npx", "-y", "docker-mcp"),
        needs="a running Docker daemon",
    ),
    Launch(
        "orchestration",
        "mcp/io.github.containers/kubernetes-mcp-server@0.0.66",
        ("npx", "-y", "kubernetes-mcp-server"),
        needs="a reachable cluster",
    ),
    Launch(
        "pixel-art",
        "mcp/io.github.oaktreegames/aseprite-live-mcp@0.2.0",
        ("uvx", "aseprite-live-mcp"),
        needs="a running Aseprite instance",
    ),
)


def _redactions() -> tuple[tuple[str, str], ...]:
    """Host-identifying strings to strip from anything written to disk.

    These captures are committed to a public repository, so whatever the host
    leaks into them is published. Two sources were observed rather than
    imagined:

    * **Tool descriptions.** `mcp-server-time` reads the machine's timezone and
      writes it into the text a model sees - "Use 'Asia/Calcutta' as local
      timezone if no timezone provided". That is the operator's approximate
      location, embedded in what looks like static metadata. It is also a small
      finding in its own right: a description that varies by machine is not
      reproducible, and `descriptionIntegrity` is a property this project
      tracks.
    * **Stack traces.** Every `npx`/`uvx` path in a captured traceback contains
      the account name.

    Ordered longest-first so a home directory is replaced before the username
    inside it, which would otherwise leave a half-redacted path behind.
    """
    home = str(Path.home())
    user = Path.home().name
    return tuple(
        sorted(
            [
                (home, "<HOME>"),
                (home.replace("\\", "/"), "<HOME>"),
                (home.replace("\\", "\\\\"), "<HOME>"),
                (user, "<USER>"),
            ],
            key=lambda pair: len(pair[0]),
            reverse=True,
        )
    )


# The timezone leak is matched by *shape* rather than by value. Python cannot
# portably report the host's IANA zone - `time.tzname` gives Windows' display
# name ("India Standard Time") while the server writes the IANA form
# ("Asia/Calcutta"), so a literal comparison finds nothing. Matching the
# sentence the server generates catches it on any host, which is what a
# redaction rule has to do to be worth trusting.
_LOCAL_TZ_SENTENCE: Final = re.compile(r"Use '[^']+' as local timezone")


def redact(text: str) -> str:
    """*text* with host-identifying strings replaced.

    Applied to everything written to `results/`, because those files are
    committed to a public repository and whatever the host leaked into them
    would be published with them.
    """
    for needle, replacement in _redactions():
        if needle:
            text = text.replace(needle, replacement)
    return _LOCAL_TZ_SENTENCE.sub("Use '<LOCAL_TZ>' as local timezone", text)


def container_runtime() -> str | None:
    """A usable container runtime, or None.

    Presence of the binary is not enough - Docker Desktop is commonly
    installed with its daemon stopped, and reporting a sweep as sandboxed
    because `docker` was on PATH would be the worst kind of wrong.
    """
    for runtime in ("docker", "podman"):
        if shutil.which(runtime) is None:
            continue
        try:
            probe = subprocess.run(  # noqa: S603
                [runtime, "info"], capture_output=True, timeout=20, check=False
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode == 0:
            return runtime
    return None


def _attempt(launch: Launch, executable: str, *, timeout: float) -> ProbeResult:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as workspace:
        command = [executable, *launch.command[1:]]
        if launch.workspace_arg:
            command.append(workspace)
        return list_tools(command, server_id=launch.entry_id, cwd=Path(workspace), timeout=timeout)


def run(launch: Launch, *, timeout: float, attempts: int = 3) -> tuple[ProbeResult, int]:
    """Probe *launch*, retrying a failure. Returns the result and attempts used.

    Retries exist because the first pass through `npx -y` or `uvx` downloads
    the package, and a download that overruns the timeout is indistinguishable
    here from a server that never answers. `mongodb-mcp-server` demonstrated
    it: three full sweeps scored it failed, then 31 tools, then failed again,
    purely on whether its download finished in time.

    A count that changes between runs is not a measurement, so the number of
    attempts is recorded alongside the outcome. A server needing two tries is
    slow to start; one failing all three is reported as failing, and the
    distinction is visible rather than averaged away.
    """
    executable = shutil.which(launch.command[0])
    if executable is None:
        return (
            ProbeResult(
                server_id=launch.entry_id,
                ok=False,
                error=f"{launch.command[0]} is not on PATH",
            ),
            0,
        )

    outcome = ProbeResult(server_id=launch.entry_id, ok=False, error="not attempted")
    for attempt in range(1, attempts + 1):
        outcome = _attempt(launch, executable, timeout=timeout)
        if outcome.ok:
            return outcome, attempt
    return outcome, attempts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", help="Run one capability by name.")
    parser.add_argument("--timeout", type=float, default=120.0, help="Per-server seconds.")
    parser.add_argument(
        "--attempts", type=int, default=3, help="Retries before a server is called failed."
    )
    parser.add_argument(
        "--require-container",
        action="store_true",
        help="Refuse to run unless a container runtime is usable.",
    )
    args = parser.parse_args()

    runtime = container_runtime()
    if args.require_container and runtime is None:
        print("error: no usable container runtime; refusing to run", file=sys.stderr)
        return 1

    mode = f"container:{runtime}" if runtime else "host (no container isolation)"
    print(f"isolation: {mode}")

    launches = LAUNCHES
    if args.only:
        launches = tuple(entry for entry in LAUNCHES if entry.capability == args.only)
        if not launches:
            print(f"error: no capability named {args.only!r}", file=sys.stderr)
            return 1

    RESULTS.mkdir(parents=True, exist_ok=True)
    summary: list[dict[str, Any]] = []

    for launch in launches:
        print(f"  {launch.capability:18} ", end="", flush=True)
        outcome, attempts = run(launch, timeout=args.timeout, attempts=args.attempts)
        if outcome.ok:
            annotated = sum(1 for tool in outcome.tools if tool.get("annotations"))
            slow = f"  (took {attempts} attempts)" if attempts > 1 else ""
            print(f"ok  {len(outcome.tools):3d} tools, {annotated} annotated{slow}")
            path = RESULTS / f"{launch.capability}-tools.json"
            path.write_text(
                json.dumps({"tools": outcome.tools}, indent=2) + "\n",
                encoding="utf-8",
                newline="\n",
            )
        else:
            print(f"--  {outcome.error[:60]}")
        summary.append(
            {
                "capability": launch.capability,
                "server_id": launch.entry_id,
                "command": list(launch.command),
                "needs": launch.needs,
                "ok": outcome.ok,
                "tool_count": len(outcome.tools),
                "annotated": sum(1 for tool in outcome.tools if tool.get("annotations")),
                "error": outcome.error,
                "attempts": attempts,
                "stderr_tail": outcome.stderr_tail,
            }
        )

    report = {
        "isolation": mode,
        "attempted": len(summary),
        "enumerated": sum(1 for row in summary if row["ok"]),
        "tools": sum(int(row["tool_count"]) for row in summary),
        "annotated": sum(int(row["annotated"]) for row in summary),
        "servers": summary,
    }
    # Only a full run may write the summary. A `--only` run covers one server,
    # and letting it overwrite the file would silently replace an 18-server
    # result with a one-server file of identical shape - which happened once
    # while this was being built, and looked exactly like a working sweep.
    if args.only:
        print("(--only: summary.json left untouched)")
    else:
        (RESULTS / "summary.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
        )

    print()
    print(f"enumerated {report['enumerated']}/{report['attempted']} servers")
    print(f"tools: {report['tools']}   annotated: {report['annotated']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
