"""Reading and writing MCP server configuration, per framework.

The format is nearly but not quite shared. Claude Code reads `.mcp.json`;
Python frameworks have no convention of their own and load whatever the project
hands `langchain-mcp-adapters`, for which `mcp.json` is the de facto choice.
Both wrap the same ``mcpServers`` object, so one parser serves both and only the
filename differs.

Parsing matters more than writing here. Until this existed, extraction never
populated ``ProjectModel.mcp_servers``, so checks ``A5``, ``B4``, ``D1`` and
``D2`` could never fire on a real project - they were implemented and untriggered.
Reading the config is what turns them on.

Every value is treated as untrusted. An `env` block is exactly where a pasted
credential lives (check ``A5``), and a `url` is what decides whether ``D1`` and
``D2`` apply, so both are classified rather than copied.
"""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Any, Final

from toolseal.core.adapters.base import RenderedFile
from toolseal.core.credentials import is_placeholder
from toolseal.core.model import CredentialRef, CredentialSource, MCPServerBinding, Transport
from toolseal.errors import ConfigError

CLAUDE_CODE_CONFIG: Final = PurePosixPath(".mcp.json")
GENERIC_CONFIG: Final = PurePosixPath("mcp.json")

# Names whose value is a credential rather than a setting. Matches the family A
# vocabulary so one idea is spelled one way across the codebase.
_CREDENTIAL_NAMES: Final = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL")

# Values that reference a credential rather than containing one.
_REFERENCE_PREFIXES: Final = ("${", "$(", "keychain:", "op://", "vault:")


def _classify(name: str, value: str, location: PurePosixPath) -> CredentialRef:
    """Decide whether an env entry holds a credential, references one, or neither."""
    upper = name.upper()
    if not any(marker in upper for marker in _CREDENTIAL_NAMES):
        source = CredentialSource.ENV_REFERENCE
    elif not value or is_placeholder(value):
        source = CredentialSource.ABSENT
    elif value.startswith(_REFERENCE_PREFIXES):
        source = CredentialSource.ENV_REFERENCE
    else:
        # A credential-named variable with a literal value, sitting in a config
        # file. This is check A5, and it is the dominant pattern in published
        # mcp.json examples.
        source = CredentialSource.LITERAL

    return CredentialRef(name=name, source=source, location=location)


def _transport_for(entry: dict[str, Any]) -> Transport:
    declared = str(entry.get("type") or "").lower()
    if declared in ("http", "streamable-http", "streamable_http"):
        return Transport.STREAMABLE_HTTP
    if declared == "sse":
        return Transport.SSE
    if entry.get("url"):
        return Transport.STREAMABLE_HTTP
    return Transport.STDIO


def _authenticated(entry: dict[str, Any]) -> bool:
    """Whether a remote server is reached with any credential at all (check D2)."""
    headers = entry.get("headers")
    if isinstance(headers, dict) and any(
        key.lower() in ("authorization", "x-api-key") for key in headers
    ):
        return True
    return bool(entry.get("auth") or entry.get("oauth"))


def parse(text: str, location: PurePosixPath) -> tuple[MCPServerBinding, ...]:
    """Parse an mcpServers document into bindings the checks can read."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        message = f"{location} is not valid JSON: {exc}"
        raise ConfigError(message) from None

    if not isinstance(data, dict):
        message = f"{location} must be an object"
        raise ConfigError(message)

    servers = data.get("mcpServers")
    if servers is None:
        return ()
    if not isinstance(servers, dict):
        message = f"{location} field 'mcpServers' must be an object"
        raise ConfigError(message)

    bindings: list[MCPServerBinding] = []
    for name, raw in sorted(servers.items()):
        if not isinstance(raw, dict):
            continue

        env = raw.get("env")
        credentials = (
            tuple(_classify(str(key), str(value), location) for key, value in sorted(env.items()))
            if isinstance(env, dict)
            else ()
        )

        args = raw.get("args")
        bindings.append(
            MCPServerBinding(
                name=str(name),
                transport=_transport_for(raw),
                command=str(raw["command"]) if raw.get("command") else None,
                args=tuple(str(item) for item in args) if isinstance(args, list) else (),
                url=str(raw["url"]) if raw.get("url") else None,
                child_environment=credentials,
                authenticated=_authenticated(raw),
            )
        )
    return tuple(bindings)


def render(servers: tuple[MCPServerBinding, ...]) -> str:
    """Render bindings back to an mcpServers document.

    Credential values are never written. A binding carries the *name* of a
    credential, and that is all that reaches the file - resolving it is the
    launcher's job, which is what keeps A5 satisfied.
    """
    entries: dict[str, Any] = {}
    for server in sorted(servers, key=lambda item: item.name):
        entry: dict[str, Any] = {}
        if server.command:
            entry["command"] = server.command
            if server.args:
                entry["args"] = list(server.args)
        if server.url:
            entry["type"] = "http"
            entry["url"] = server.url
        if server.child_environment:
            entry["env"] = {
                ref.name: f"${{{ref.name}}}"
                for ref in sorted(server.child_environment, key=lambda item: item.name)
            }
        entries[server.name] = entry

    return json.dumps({"mcpServers": entries}, indent=2, sort_keys=True) + "\n"


class _JsonMCPTarget:
    """Shared behaviour: the format is identical, only the filename differs."""

    def __init__(self, target_id: str, config_path: PurePosixPath) -> None:
        self._id = target_id
        self._config_path = config_path

    @property
    def id(self) -> str:
        return self._id

    @property
    def config_path(self) -> PurePosixPath:
        return self._config_path

    def read(self, root: Path) -> tuple[MCPServerBinding, ...]:
        path = root / self._config_path
        if not path.is_file():
            return ()
        return parse(path.read_text(encoding="utf-8"), self._config_path)

    def write(self, root: Path, servers: tuple[MCPServerBinding, ...]) -> tuple[RenderedFile, ...]:
        # Merged, not replaced: a user's other servers must survive being handed
        # one more. Overwriting the file would be the config equivalent of
        # clobbering their work.
        existing = {server.name: server for server in self.read(root)}
        existing.update({server.name: server for server in servers})

        return (RenderedFile(self._config_path, render(tuple(existing.values()))),)


def claude_code_target() -> _JsonMCPTarget:
    return _JsonMCPTarget("claude-code", CLAUDE_CODE_CONFIG)


def generic_target() -> _JsonMCPTarget:
    return _JsonMCPTarget("generic", GENERIC_CONFIG)


#: Which config file each framework reads.
TARGETS_BY_FRAMEWORK: Final[dict[str, PurePosixPath]] = {
    "claude-code": CLAUDE_CODE_CONFIG,
    "langgraph": GENERIC_CONFIG,
    "crewai": GENERIC_CONFIG,
}


def target_for(framework_id: str) -> _JsonMCPTarget:
    """The MCP target a framework uses, or the generic one."""
    path = TARGETS_BY_FRAMEWORK.get(framework_id, GENERIC_CONFIG)
    return _JsonMCPTarget(framework_id, path)


def discover(root: Path) -> tuple[MCPServerBinding, ...]:
    """Every MCP server configured in *root*, whichever file declares it.

    Both filenames are read because a project may target more than one runtime,
    and a server the audit cannot see is a server it cannot check.
    """
    seen: dict[str, MCPServerBinding] = {}
    for config in (CLAUDE_CODE_CONFIG, GENERIC_CONFIG):
        path = root / config
        if not path.is_file():
            continue
        try:
            found = parse(path.read_text(encoding="utf-8"), config)
        except ConfigError:
            # A malformed config is reported by the check that reads it, not by
            # extraction. Aborting here would take every other check with it.
            continue
        for server in found:
            seen.setdefault(server.name, server)
    return tuple(seen.values())
