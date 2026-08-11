"""The normalised view of a project that the audit engine consumes.

Checks never touch raw files. Extraction produces a :class:`ProjectModel`, and
every check in `reference/taxonomy.md` is answerable from it. That boundary is
what lets a check be written once and work across frameworks, and what lets a
new framework be supported by writing an extractor rather than editing checks.

The model is therefore shaped by the taxonomy, not by any framework's file
layout. When a new check needs a fact this model cannot express, the model gains
a field; when a framework stores that fact somewhere unusual, its extractor
absorbs the difference.

Everything here is frozen. A model is a snapshot of a project at one instant,
and a check that could mutate it could change another check's result.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path, PurePosixPath


class ToolKind(StrEnum):
    """What a tool can do, independent of which framework wraps it."""

    SHELL = "shell"
    CODE_EXECUTION = "code_execution"
    FILESYSTEM = "filesystem"
    NETWORK = "network"
    DATABASE = "database"
    MESSAGING = "messaging"
    VERSION_CONTROL = "version_control"
    OTHER = "other"


class Transport(StrEnum):
    """How an MCP server is reached. Determines whether family D applies."""

    STDIO = "stdio"
    HTTP = "http"
    SSE = "sse"
    STREAMABLE_HTTP = "streamable_http"

    @property
    def is_remote(self) -> bool:
        return self is not Transport.STDIO


class CredentialSource(StrEnum):
    """Where a credential's value actually comes from.

    ``LITERAL`` is the finding: the value is present in a file. Everything else
    is an indirection of some kind.
    """

    KEYCHAIN = "keychain"
    ENV_REFERENCE = "env_reference"
    LITERAL = "literal"
    ABSENT = "absent"


@dataclass(frozen=True)
class CredentialRef:
    """A credential as the project refers to it, plus where that reference lives."""

    name: str
    source: CredentialSource
    location: PurePosixPath | None = None
    line: int | None = None

    @property
    def is_exposed(self) -> bool:
        """True when the value itself sits in a file (check ``A1``)."""
        return self.source is CredentialSource.LITERAL


@dataclass(frozen=True)
class InstallSource:
    """Where an artifact is fetched from, and whether that fetch is verifiable."""

    kind: str
    reference: str
    pinned: bool = False
    integrity_checked: bool = False

    @property
    def is_verified(self) -> bool:
        """True when the artifact is both pinned and integrity-checked (``C4``)."""
        return self.pinned and self.integrity_checked


@dataclass(frozen=True)
class ProjectFile:
    """A file in the project, with the version-control facts family A needs."""

    path: PurePosixPath
    tracked: bool
    ignored: bool


@dataclass(frozen=True)
class Dependency:
    name: str
    specifier: str
    pinned: bool = False
    resolved_version: str | None = None
    source: InstallSource | None = None


@dataclass(frozen=True)
class DependencySet:
    """The project's declared dependencies and the artifacts describing them."""

    declared: tuple[Dependency, ...] = ()
    lockfile: PurePosixPath | None = None
    sbom: PurePosixPath | None = None

    @property
    def has_unpinned(self) -> bool:
        return any(not dependency.pinned for dependency in self.declared)


@dataclass(frozen=True)
class ProviderBinding:
    """A configured LLM provider."""

    provider_id: str
    credential: CredentialRef | None = None
    base_url: str | None = None
    model: str | None = None

    @property
    def overrides_endpoint(self) -> bool:
        """True when traffic is pointed somewhere other than the vendor default (``D3``)."""
        return self.base_url is not None


@dataclass(frozen=True)
class MCPServerBinding:
    """A configured MCP server, local or remote."""

    name: str
    transport: Transport
    command: str | None = None
    args: tuple[str, ...] = ()
    url: str | None = None
    child_environment: tuple[CredentialRef, ...] = ()
    authenticated: bool = False
    declared_scope: frozenset[str] = frozenset()
    advertised_scope: frozenset[str] = frozenset()
    source: InstallSource | None = None
    name_verified: bool = False

    @property
    def is_remote(self) -> bool:
        return self.transport.is_remote

    @property
    def uses_tls(self) -> bool:
        """False only for a non-loopback plaintext endpoint (``D1``)."""
        if not self.is_remote or self.url is None:
            return True
        if self.url.startswith("https://"):
            return True
        return self.url.startswith(("http://localhost", "http://127.0.0.1", "http://[::1]"))

    @property
    def scope_excess(self) -> frozenset[str]:
        """Capabilities advertised beyond what the project declared it for (``B4``)."""
        return self.advertised_scope - self.declared_scope


@dataclass(frozen=True)
class ToolBinding:
    """A tool available to the project, normalised across frameworks."""

    name: str
    kind: ToolKind
    origin: str
    filesystem_roots: tuple[str, ...] = ()
    isolation: str | None = None
    timeout_seconds: float | None = None
    justification: str | None = None
    destructive: bool | None = None
    requires_approval: bool = False

    @property
    def is_executor(self) -> bool:
        """True for tools that can run arbitrary code (``B2``, ``E1``)."""
        return self.kind in (ToolKind.SHELL, ToolKind.CODE_EXECUTION)

    @property
    def has_unbounded_root(self) -> bool:
        """True when filesystem access is rooted at a directory that is too broad (``B3``)."""
        broad = {"/", "~", "~/", "$HOME", "%USERPROFILE%"}
        return any(root.strip() in broad for root in self.filesystem_roots)


@dataclass(frozen=True)
class AgentBinding:
    """An agent and the tools it is given."""

    name: str
    framework_id: str
    tool_names: tuple[str, ...] = ()
    binds_all_tools: bool = False
    allowlist_pinned: bool = True


@dataclass(frozen=True)
class TranslationRecord:
    """What happened when a tool crossed a framework boundary.

    Populated by the translation layer and consumed by family ``G``. Field names
    mirror the verdicts used by probe P0 so that measured evidence and audit
    findings stay directly comparable.
    """

    tool_name: str
    source_abstraction: str
    target_abstraction: str
    dropped_properties: frozenset[str] = frozenset()
    mutated_properties: frozenset[str] = frozenset()
    guards_emitted: frozenset[str] = frozenset()
    validates_client_side: bool = False
    maps_error_channel: bool = False

    @property
    def uncompensated(self) -> frozenset[str]:
        """Properties lost with no guard emitted in their place (``G4``)."""
        return self.dropped_properties - self.guards_emitted


@dataclass(frozen=True)
class RuntimeConfig:
    """Configuration governing how the agent runs, as declared by the project."""

    logs_tool_invocations: bool = False
    redacts_credentials: bool = False
    inherits_host_environment: bool = True
    approval_required_for_destructive: bool = False
    default_timeout_seconds: float | None = None


@dataclass(frozen=True)
class ProjectModel:
    """Everything the audit engine is allowed to know about a project."""

    root: Path
    files: tuple[ProjectFile, ...] = ()
    dependencies: DependencySet = field(default_factory=DependencySet)
    providers: tuple[ProviderBinding, ...] = ()
    mcp_servers: tuple[MCPServerBinding, ...] = ()
    tools: tuple[ToolBinding, ...] = ()
    agents: tuple[AgentBinding, ...] = ()
    translations: tuple[TranslationRecord, ...] = ()
    runtime: RuntimeConfig = field(default_factory=RuntimeConfig)

    # -- applicability -----------------------------------------------------
    # Scoring excludes inapplicable checks from the denominator, so a project
    # is never penalised for not having a feature it never configured.

    @property
    def has_remote_endpoint(self) -> bool:
        """Whether family D applies."""
        return any(server.is_remote for server in self.mcp_servers) or any(
            provider.overrides_endpoint for provider in self.providers
        )

    @property
    def has_translations(self) -> bool:
        """Whether family G applies."""
        return bool(self.translations)

    # -- lookups -----------------------------------------------------------

    def tool(self, name: str) -> ToolBinding | None:
        return next((tool for tool in self.tools if tool.name == name), None)

    def server(self, name: str) -> MCPServerBinding | None:
        return next((server for server in self.mcp_servers if server.name == name), None)

    def file(self, path: str | PurePosixPath) -> ProjectFile | None:
        wanted = PurePosixPath(path)
        return next((entry for entry in self.files if entry.path == wanted), None)

    def credentials(self) -> tuple[CredentialRef, ...]:
        """Every credential reference in the project, wherever it was declared."""
        refs: list[CredentialRef] = [
            provider.credential for provider in self.providers if provider.credential is not None
        ]
        for server in self.mcp_servers:
            refs.extend(server.child_environment)
        return tuple(refs)
