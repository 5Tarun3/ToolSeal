"""The model's derived predicates are what checks actually branch on.

Each test here pins one taxonomy check's notion of "bad". If a predicate is
wrong, the check built on it is wrong in a way no amount of extractor testing
would catch.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath

import pytest

from toolseal.core.model import (
    CredentialRef,
    CredentialSource,
    InstallSource,
    MCPServerBinding,
    ProjectModel,
    ProviderBinding,
    ToolBinding,
    ToolKind,
    TranslationRecord,
    Transport,
)


def test_literal_credential_is_the_only_exposed_source() -> None:
    exposed = CredentialRef("ANTHROPIC_API_KEY", CredentialSource.LITERAL)
    assert exposed.is_exposed

    for safe in (
        CredentialSource.KEYCHAIN,
        CredentialSource.ENV_REFERENCE,
        CredentialSource.ABSENT,
    ):
        assert not CredentialRef("ANTHROPIC_API_KEY", safe).is_exposed


def test_install_source_needs_both_pinning_and_integrity() -> None:
    assert InstallSource("pypi", "x==1.0", pinned=True, integrity_checked=True).is_verified
    assert not InstallSource("pypi", "x==1.0", pinned=True).is_verified
    assert not InstallSource("git", "main", integrity_checked=True).is_verified


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://mcp.example.com", True),
        ("http://localhost:3000", True),
        ("http://127.0.0.1:3000", True),
        ("http://[::1]:3000", True),
        ("http://mcp.example.com", False),
    ],
)
def test_tls_check_permits_loopback_only(url: str, expected: bool) -> None:
    server = MCPServerBinding(name="s", transport=Transport.STREAMABLE_HTTP, url=url)
    assert server.uses_tls is expected


def test_stdio_server_is_never_a_transport_finding() -> None:
    server = MCPServerBinding(name="s", transport=Transport.STDIO, command="npx")
    assert not server.is_remote
    assert server.uses_tls


def test_scope_excess_reports_only_the_surplus() -> None:
    server = MCPServerBinding(
        name="db",
        transport=Transport.STDIO,
        declared_scope=frozenset({"read"}),
        advertised_scope=frozenset({"read", "write", "delete"}),
    )
    assert server.scope_excess == frozenset({"write", "delete"})


@pytest.mark.parametrize("root", ["/", "~", "~/", "$HOME", "%USERPROFILE%", "  /  "])
def test_broad_filesystem_roots_are_flagged(root: str) -> None:
    tool = ToolBinding("fs", ToolKind.FILESYSTEM, "mcp:fs", filesystem_roots=(root,))
    assert tool.has_unbounded_root


def test_workspace_root_is_not_flagged() -> None:
    tool = ToolBinding("fs", ToolKind.FILESYSTEM, "mcp:fs", filesystem_roots=("./workspace",))
    assert not tool.has_unbounded_root


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        (ToolKind.SHELL, True),
        (ToolKind.CODE_EXECUTION, True),
        (ToolKind.FILESYSTEM, False),
        (ToolKind.NETWORK, False),
    ],
)
def test_executor_classification(kind: ToolKind, expected: bool) -> None:
    assert ToolBinding("t", kind, "native").is_executor is expected


def test_uncompensated_excludes_properties_that_got_a_guard() -> None:
    record = TranslationRecord(
        tool_name="delete_records",
        source_abstraction="mcp",
        target_abstraction="crewai",
        dropped_properties=frozenset({"destructiveHint", "openWorldHint"}),
        guards_emitted=frozenset({"destructiveHint"}),
    )
    assert record.uncompensated == frozenset({"openWorldHint"})


def test_family_d_applies_only_when_something_is_remote() -> None:
    local = ProjectModel(
        root=Path(),
        mcp_servers=(MCPServerBinding(name="s", transport=Transport.STDIO, command="npx"),),
    )
    assert not local.has_remote_endpoint

    remote = ProjectModel(
        root=Path(),
        mcp_servers=(MCPServerBinding(name="s", transport=Transport.SSE, url="https://x"),),
    )
    assert remote.has_remote_endpoint


def test_overridden_provider_endpoint_also_triggers_family_d() -> None:
    model = ProjectModel(
        root=Path(),
        providers=(ProviderBinding("openai", base_url="https://proxy.internal"),),
    )
    assert model.has_remote_endpoint


def test_credentials_gathers_provider_and_server_references() -> None:
    model = ProjectModel(
        root=Path(),
        providers=(
            ProviderBinding(
                "anthropic",
                credential=CredentialRef("ANTHROPIC_API_KEY", CredentialSource.KEYCHAIN),
            ),
        ),
        mcp_servers=(
            MCPServerBinding(
                name="pg",
                transport=Transport.STDIO,
                child_environment=(CredentialRef("PGPASSWORD", CredentialSource.LITERAL),),
            ),
        ),
    )

    names = {ref.name for ref in model.credentials()}
    assert names == {"ANTHROPIC_API_KEY", "PGPASSWORD"}
    assert any(ref.is_exposed for ref in model.credentials())


def test_lookups_return_none_when_absent() -> None:
    model = ProjectModel(root=Path())
    assert model.tool("nope") is None
    assert model.server("nope") is None
    assert model.file(PurePosixPath("nope.txt")) is None
