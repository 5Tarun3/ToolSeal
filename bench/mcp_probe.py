"""A minimal MCP stdio client, for enumerating a server's tools.

Speaks just enough of the protocol to ask one question - `tools/list` - and
nothing else. Written rather than taken from a library for the reason the rest
of this project gives: a tool that counts other people's dependencies should
justify each of its own, and MCP's stdio transport is newline-delimited
JSON-RPC, which needs no help.

**This module starts a subprocess and therefore executes code it did not
write.** Everything here is arranged around limiting what that code can reach:

* The child's environment is an allowlist, not the parent's. Nothing is
  inherited by default, so an API key exported in the shell that runs a sweep
  cannot be read by the server being swept. This is the single most valuable
  control available without a container, because the credential is the thing
  worth stealing.
* The working directory is one the caller supplies, expected to be a
  throwaway. A server that writes state on startup writes it there.
* Every call is bounded and the process group is killed on expiry. A server
  that hangs waiting for input does not hang the sweep.
* `shell=False` always, with the command supplied as a list, so nothing in a
  package name or argument can be interpreted by a shell.

What it does *not* provide is network isolation or a filesystem boundary. A
server can still open sockets and read files the user can read. Those need a
container; see `bench/sweep.py` for how the caller is told which of the two
modes it is running in, and `research/probes/p3_tool_sweep/README.md` for what
each mode does and does not support.
"""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO = {"name": "toolseal-probe", "version": "0"}

# Passed through to the child. `PATH` so the interpreter can be found at all,
# and the platform's loader variables because npx and uvx will not start
# without them on Windows. Deliberately no credentials and no proxy settings:
# a server that needs a secret to list its tools is a finding, not a reason to
# hand it one. `HOME` is not inherited either, but is synthesised per-run by
# `child_environment` - see there for why neither omitting nor inheriting it
# was correct.
_ENV_ALLOWLIST = ("PATH", "SYSTEMROOT", "COMSPEC", "PATHEXT", "TEMP", "TMP", "APPDATA")


@dataclass
class ProbeResult:
    """What happened when one server was asked to list its tools."""

    server_id: str
    ok: bool
    tools: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""
    stderr_tail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "server_id": self.server_id,
            "ok": self.ok,
            "tool_count": len(self.tools),
            "tools": self.tools,
            "error": self.error,
            "stderr_tail": self.stderr_tail,
        }


def child_environment(home: Path | None = None) -> dict[str, str]:
    """The allowlisted environment a probed server is started with.

    *home* becomes the child's `HOME`/`USERPROFILE`, and callers are expected
    to pass the throwaway workspace. Omitting the variable entirely was the
    first attempt and it was wrong in a way worth recording: `chroma-mcp` died
    with "Could not determine home directory" and was scored as a broken
    server, when re-running it with a home produced 13 tools perfectly well.
    The harness was manufacturing the failure it then reported.

    Passing the *real* home would be the other wrong answer, since that is
    where `~/.aws/credentials`, `~/.ssh` and every cloud CLI token live. A
    synthetic home inside the workspace gives a server somewhere to write
    without giving it anywhere to steal from.
    """
    environment = {name: os.environ[name] for name in _ENV_ALLOWLIST if name in os.environ}
    if home is not None:
        environment["HOME"] = str(home)
        environment["USERPROFILE"] = str(home)
    return environment


def _message(identifier: int | None, method: str, params: dict[str, Any]) -> str:
    payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method, "params": params}
    if identifier is not None:
        payload["id"] = identifier
    return json.dumps(payload) + "\n"


def list_tools(
    command: list[str],
    *,
    server_id: str,
    cwd: Path,
    timeout: float = 60.0,
) -> ProbeResult:
    """Start *command*, ask it for its tools, and stop it.

    Returns a result either way. A server that cannot start, refuses to
    initialise, or never answers is recorded with the reason rather than
    raising: the sweep's whole point is to count how many of them do that, so
    a failure is data, not an exception.
    """
    try:
        process = subprocess.Popen(  # noqa: S603 - list form, shell=False, see module docstring
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(cwd),
            env=child_environment(home=cwd),
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
    except (OSError, ValueError) as exc:
        return ProbeResult(server_id=server_id, ok=False, error=f"could not start: {exc}")

    stderr_lines: list[str] = []
    _drain_stderr(process, stderr_lines)

    stdin, stdout = process.stdin, process.stdout
    if stdin is None or stdout is None:  # pragma: no cover - Popen was given PIPEs
        _terminate(process)
        return _fail(server_id, "no pipes to the child process", stderr_lines)

    try:
        stdin.write(
            _message(
                1,
                "initialize",
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": CLIENT_INFO,
                },
            )
        )
        stdin.flush()

        initialised = _read_response(process, wanted_id=1, timeout=timeout)
        if initialised is None:
            return _fail(server_id, "no response to initialize", stderr_lines)

        stdin.write(_message(None, "notifications/initialized", {}))
        stdin.write(_message(2, "tools/list", {}))
        stdin.flush()

        listed = _read_response(process, wanted_id=2, timeout=timeout)
        if listed is None:
            return _fail(server_id, "no response to tools/list", stderr_lines)
        if "error" in listed:
            return _fail(server_id, f"tools/list error: {listed['error']}", stderr_lines)

        tools = listed.get("result", {}).get("tools", [])
        if not isinstance(tools, list):
            return _fail(server_id, "tools/list result was not a list", stderr_lines)

        return ProbeResult(server_id=server_id, ok=True, tools=tools)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return _fail(server_id, f"{type(exc).__name__}: {exc}", stderr_lines)
    finally:
        _terminate(process)


def _read_response(
    process: subprocess.Popen[str], *, wanted_id: int, timeout: float
) -> dict[str, Any] | None:
    """The next JSON-RPC response carrying *wanted_id*.

    Skips notifications and log lines the server may interleave, which several
    real servers do - writing a banner to stdout before their first response is
    a protocol violation but a common one, and refusing to tolerate it would
    record working servers as broken.
    """
    result: list[dict[str, Any] | None] = [None]

    def reader() -> None:
        if process.stdout is None:  # pragma: no cover
            return
        for line in process.stdout:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if message.get("id") == wanted_id:
                result[0] = message
                return

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    thread.join(timeout)
    return result[0]


def _drain_stderr(process: subprocess.Popen[str], sink: list[str]) -> threading.Thread:
    """Collect the child's stderr in the background.

    Started before the first write, for two reasons. A server that fails on
    startup writes its traceback and exits before any response could arrive,
    so reading stderr only after the failure races the process teardown and
    usually gets nothing. And a chatty server that fills the stderr pipe
    buffer blocks on the write, which looks from here exactly like a hang.
    """

    def reader() -> None:
        if process.stderr is None:
            return
        try:
            for line in process.stderr:
                sink.append(line.rstrip())
        except (OSError, ValueError):
            pass

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    return thread


def _fail(server_id: str, error: str, stderr_lines: list[str]) -> ProbeResult:
    """A failure, carrying the last of what the server said about it.

    The tail rather than the head: a Python traceback puts the actual
    exception on its final line, and "TypeError: expected str, got None" is
    the finding while the frames above it are noise.
    """
    # npm prints its own notices *after* a failing package's stack trace, so a
    # naive tail returns "New major version of npm available" as the diagnosis
    # and buries the actual error. Dropping the runner's chatter first is what
    # makes the tail the server's last word rather than the runner's.
    meaningful = [
        line
        for line in stderr_lines
        if line.strip() and not line.lstrip().startswith(("npm notice", "npm warn", "npm WARN"))
    ]
    tail = "\n".join(meaningful[-8:])
    return ProbeResult(server_id=server_id, ok=False, error=error, stderr_tail=tail)


def _terminate(process: subprocess.Popen[str]) -> None:
    """Stop the child, escalating if it ignores the first request."""
    if process.poll() is not None:
        return
    try:
        process.terminate()
        process.wait(timeout=5)
    except (subprocess.TimeoutExpired, OSError):
        with contextlib.suppress(OSError):
            process.kill()


if __name__ == "__main__":  # A smoke check against one server, by argv.
    import tempfile

    if len(sys.argv) < 2:
        print("usage: mcp_probe.py <command> [args...]", file=sys.stderr)
        raise SystemExit(2)
    # `ignore_cleanup_errors`: on Windows a probed server can still hold a
    # handle inside the workspace when the block exits, and failing the whole
    # probe over an undeletable scratch directory would report a working
    # server as broken.
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as workspace:
        outcome = list_tools(sys.argv[1:], server_id="cli", cwd=Path(workspace))
    print(json.dumps(outcome.to_dict(), indent=2)[:4000])
