"""MCP configuration: parsing, writing, and the checks it finally switches on.

Until this existed, `ProjectModel.mcp_servers` was always empty, so checks A5,
B4, D1 and D2 were implemented and unreachable. Half the tests here assert those
checks now fire on a real config file - a check that cannot be triggered is
indistinguishable from one that does not exist.

The other half is `add mcp`, which is where C3 stops being a unit test: adding a
server resolves the name first, and refuses one that resolves nowhere.
"""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath

import pytest
from typer.testing import CliRunner

from toolseal.cli import app
from toolseal.core.adapters.mcp_targets import discover, parse, render, target_for
from toolseal.core.audit import audit
from toolseal.core.model import CredentialSource, Transport
from toolseal.errors import ConfigError, ExitCode

runner = CliRunner()
HERE = PurePosixPath(".mcp.json")


def write_config(root: Path, servers: dict[str, object], name: str = ".mcp.json") -> None:
    (root / name).write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")


# --- parsing ---------------------------------------------------------------


def test_stdio_server_is_parsed() -> None:
    servers = parse(
        json.dumps({"mcpServers": {"pg": {"command": "npx", "args": ["-y", "@e/pg"]}}}), HERE
    )

    assert servers[0].name == "pg"
    assert servers[0].transport is Transport.STDIO
    assert servers[0].args == ("-y", "@e/pg")


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        ({"type": "http", "url": "https://x"}, Transport.STREAMABLE_HTTP),
        ({"type": "sse", "url": "https://x"}, Transport.SSE),
        ({"url": "https://x"}, Transport.STREAMABLE_HTTP),
        ({"command": "npx"}, Transport.STDIO),
    ],
)
def test_transport_is_inferred(entry: dict[str, object], expected: Transport) -> None:
    assert parse(json.dumps({"mcpServers": {"s": entry}}), HERE)[0].transport is expected


def test_literal_credential_in_env_is_recognised() -> None:
    # The dominant pattern in published mcp.json examples, and check A5.
    servers = parse(
        json.dumps({"mcpServers": {"pg": {"command": "npx", "env": {"PGPASSWORD": "hunter2"}}}}),
        HERE,
    )

    assert servers[0].child_environment[0].source is CredentialSource.LITERAL
    assert servers[0].child_environment[0].is_exposed


@pytest.mark.parametrize("value", ["${PGPASSWORD}", "keychain:pg", "op://vault/pg", ""])
def test_referenced_or_absent_credentials_are_not_exposures(value: str) -> None:
    servers = parse(
        json.dumps({"mcpServers": {"pg": {"command": "npx", "env": {"PGPASSWORD": value}}}}), HERE
    )

    assert not servers[0].child_environment[0].is_exposed


def test_a_non_credential_env_var_is_not_a_credential() -> None:
    servers = parse(
        json.dumps({"mcpServers": {"pg": {"command": "npx", "env": {"PGHOST": "db.internal"}}}}),
        HERE,
    )

    assert not servers[0].child_environment[0].is_exposed


def test_authorization_header_counts_as_authenticated() -> None:
    servers = parse(
        json.dumps(
            {"mcpServers": {"r": {"url": "https://x", "headers": {"Authorization": "Bearer y"}}}}
        ),
        HERE,
    )

    assert servers[0].authenticated


def test_malformed_json_is_refused() -> None:
    with pytest.raises(ConfigError, match="not valid JSON"):
        parse("{not json", HERE)


def test_absent_mcp_servers_key_is_empty_not_an_error() -> None:
    assert parse(json.dumps({"other": 1}), HERE) == ()


# --- the checks this switches on -------------------------------------------


def test_literal_credential_in_config_triggers_a5(tmp_path: Path) -> None:
    write_config(tmp_path, {"pg": {"command": "npx", "env": {"PGPASSWORD": "hunter2reallylong"}}})

    assert [f for f in audit(tmp_path).findings if f.check_id == "A5"]


def test_plaintext_remote_endpoint_triggers_d1(tmp_path: Path) -> None:
    write_config(tmp_path, {"r": {"type": "http", "url": "http://mcp.example.com"}})

    findings = [f for f in audit(tmp_path).findings if f.check_id == "D1"]
    assert findings
    assert findings[0].severity.value == "critical"


def test_loopback_endpoint_does_not_trigger_d1(tmp_path: Path) -> None:
    # Matches the HTTP client and the taxonomy: plaintext to localhost never
    # crosses a network.
    write_config(tmp_path, {"r": {"type": "http", "url": "http://127.0.0.1:3000"}})

    assert not [f for f in audit(tmp_path).findings if f.check_id == "D1"]


def test_unauthenticated_remote_triggers_d2(tmp_path: Path) -> None:
    write_config(tmp_path, {"r": {"type": "http", "url": "https://mcp.example.com"}})

    assert [f for f in audit(tmp_path).findings if f.check_id == "D2"]


def test_a_local_stdio_server_triggers_neither(tmp_path: Path) -> None:
    write_config(tmp_path, {"pg": {"command": "npx", "args": ["-y", "@e/pg"]}})

    failing = {f.check_id for f in audit(tmp_path).findings}
    assert "D1" not in failing
    assert "D2" not in failing


def test_both_config_filenames_are_discovered(tmp_path: Path) -> None:
    # A project may target more than one runtime, and a server the audit cannot
    # see is a server it cannot check.
    write_config(tmp_path, {"a": {"command": "npx"}}, name=".mcp.json")
    write_config(tmp_path, {"b": {"command": "npx"}}, name="mcp.json")

    assert {server.name for server in discover(tmp_path)} == {"a", "b"}


def test_a_malformed_config_does_not_abort_extraction(tmp_path: Path) -> None:
    # One broken file must not take every other check with it.
    (tmp_path / ".mcp.json").write_text("{broken", encoding="utf-8")
    (tmp_path / "main.py").write_text("x = 1\n", encoding="utf-8")

    assert audit(tmp_path).results


# --- writing ---------------------------------------------------------------


def test_render_never_writes_a_credential_value() -> None:
    from toolseal.core.model import CredentialRef, MCPServerBinding

    binding = MCPServerBinding(
        name="pg",
        transport=Transport.STDIO,
        command="npx",
        child_environment=(CredentialRef("PGPASSWORD", CredentialSource.LITERAL),),
    )

    text = render((binding,))

    assert "${PGPASSWORD}" in text
    assert "hunter2" not in text


def test_write_merges_rather_than_replacing(tmp_path: Path) -> None:
    # A user's other servers must survive being handed one more.
    write_config(tmp_path, {"existing": {"command": "npx"}})
    from toolseal.core.model import MCPServerBinding

    files = target_for("claude-code").write(
        tmp_path, (MCPServerBinding(name="added", transport=Transport.STDIO, command="npx"),)
    )

    servers = json.loads(files[0].content)["mcpServers"]
    assert set(servers) == {"existing", "added"}


def test_frameworks_map_to_their_config_file() -> None:
    assert str(target_for("claude-code").config_path) == ".mcp.json"
    assert str(target_for("langgraph").config_path) == "mcp.json"
    assert str(target_for("crewai").config_path) == "mcp.json"


# --- add mcp, and C3 in anger ----------------------------------------------


def test_phantom_name_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The whole point: a name that does not exist today is one an attacker can
    # register tomorrow, and this is the last moment anyone looks.
    monkeypatch.setattr("toolseal.core.registry.resolve.exists", lambda url, **_: False)

    result = runner.invoke(
        app, ["add", "mcp", "@invented/definitely-not-real", "--directory", str(tmp_path)]
    )

    assert result.exit_code == ExitCode.USAGE
    assert "resolves in no registry" in result.output
    assert not (tmp_path / ".mcp.json").exists()


def test_verified_name_is_added(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("toolseal.core.registry.resolve.exists", lambda url, **_: True)

    result = runner.invoke(
        app, ["add", "mcp", "@modelcontextprotocol/server-postgres", "--directory", str(tmp_path)]
    )

    assert result.exit_code == ExitCode.OK, result.output
    servers = json.loads((tmp_path / "mcp.json").read_text(encoding="utf-8"))["mcpServers"]
    assert "server-postgres" in servers


def test_skip_verify_adds_but_reports_findings(tmp_path: Path) -> None:
    # The escape hatch exists and is not free: exit 1 means CI notices.
    result = runner.invoke(
        app, ["add", "mcp", "@invented/thing", "--directory", str(tmp_path), "--skip-verify"]
    )

    assert result.exit_code == ExitCode.FINDINGS
    assert "UNVERIFIED" in result.output


def test_unreachable_registry_refuses_rather_than_guessing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from toolseal.core.net import HttpError

    def unreachable(url: str, **_: object) -> bool:
        message = "network down"
        raise HttpError(message)

    monkeypatch.setattr("toolseal.core.registry.resolve.exists", unreachable)

    result = runner.invoke(app, ["add", "mcp", "@e/thing", "--directory", str(tmp_path)])

    assert result.exit_code == ExitCode.USAGE
    assert "no registry could be reached" in result.output


def test_added_server_is_revertible(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("toolseal.core.registry.resolve.exists", lambda url, **_: True)
    runner.invoke(app, ["add", "mcp", "@e/thing", "--directory", str(tmp_path)])

    reverted = runner.invoke(app, ["revert", "--directory", str(tmp_path)])

    assert reverted.exit_code == ExitCode.OK
    assert not (tmp_path / "mcp.json").exists()
