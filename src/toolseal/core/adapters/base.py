"""Contracts every provider, framework and MCP target implements.

These are :class:`~typing.Protocol` definitions rather than base classes, so an
adapter is defined by what it offers rather than by what it inherits. Conformance
is checked by mypy at build time; there is no runtime registration ceremony and
no import cycle between an adapter and the machinery that uses it.

The division of labour matters, because the provider x framework matrix would
otherwise grow a class per cell:

* a :class:`Provider` supplies **facts** - package names, the credential it
  needs, its default endpoint and model;
* a :class:`Framework` supplies **rendering** - it turns those facts into files;
* an :class:`MCPTarget` reads and writes one framework's MCP server
  configuration, which is a separate concern because several frameworks share a
  config format while rendering entirely differently.

Adapters know nothing about checks, and checks know nothing about adapters. They
meet only at :mod:`toolseal.core.model`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Generic, Protocol, TypeVar

from toolseal.core.model import MCPServerBinding
from toolseal.errors import UsageError

DEFAULT_FILE_MODE = 0o644
PRIVATE_FILE_MODE = 0o600


@dataclass(frozen=True)
class RenderedFile:
    """A file an adapter wants written, produced before anything touches disk.

    Rendering returns values rather than writing directly so that a scaffold can
    be inspected, diffed and audited before it exists - which is what makes
    ``init`` testable without a filesystem.
    """

    path: PurePosixPath
    content: str
    mode: int = DEFAULT_FILE_MODE
    overwrite: bool = False
    block_managed: bool = False
    """True when toolseal owns only a delimited block inside this file, not the
    whole thing.

    Set this per file rather than special-casing a filename in the writer: a
    file like `.claude/settings.json` is entirely toolseal's, and gets
    overwritten outright; a file like `CLAUDE.md` belongs to the project and
    toolseal must only touch the block it manages inside it. See
    :mod:`toolseal.core.injection` for how the two modes differ.
    """

    @property
    def is_sensitive(self) -> bool:
        return self.mode == PRIVATE_FILE_MODE


@dataclass(frozen=True)
class ScaffoldSpec:
    """Everything an adapter needs in order to render a project."""

    project_name: str
    provider_id: str
    framework_id: str
    workspace_root: Path
    model: str | None = None

    base_url: str | None = None
    """Endpoint override, or ``None`` for the provider default.

    Exists for self-hosted and proxied deployments, and for verifying a
    hosted provider against a local stand-in. Setting it is what check ``D3``
    reports, which is correct: an overridden endpoint is where traffic and
    credentials get silently redirected, so it should be a visible choice.
    """

    mcp_servers: tuple[MCPServerBinding, ...] = ()
    extras: dict[str, str] = field(default_factory=dict)

    profile_id: str | None = None
    """A regime/standard to scaffold under from the start (P47, ``init --profile``).

    Read by :func:`toolseal.core.scaffold.build_plan` when it constructs the
    project's manifest, so the very first ``toolseal.toml`` this project ever
    sees already declares the profile - rather than the project starting bare
    and needing ``toolseal policy apply`` as a follow-up step.
    """


class Provider(Protocol):
    """An LLM provider: the facts needed to talk to it, and nothing else.

    Identity is declared read-only throughout. These are facts about an adapter,
    not mutable state, and a settable protocol member would both permit
    rebinding at runtime and force every implementation to spell the exact
    declared type - mutable protocol attributes are invariant.
    """

    @property
    def id(self) -> str: ...

    @property
    def display_name(self) -> str: ...

    @property
    def default_model(self) -> str: ...

    @property
    def default_base_url(self) -> str: ...

    @property
    def credential_env_var(self) -> str | None:
        """Environment variable carrying this provider's credential.

        ``None`` means the provider genuinely needs no credential - a locally
        hosted runtime, for example. That is different from a credential this
        project has not been given, and the distinction matters: family A must
        not report a missing secret for a provider that never had one.

        Declared read-only rather than as a plain attribute so that an
        implementation may narrow it. A mutable protocol attribute is invariant,
        which would force every provider to spell the type ``str | None`` even
        when it is always one or the other - and adapter identity should not be
        rebindable at runtime regardless.
        """
        ...

    def packages(self) -> tuple[str, ...]:
        """Requirement specifiers this provider needs, pinned by the adapter."""
        ...

    def supports_model(self, model: str) -> bool:
        """Whether this provider can serve *model*."""
        ...


class Framework(Protocol):
    """An agent framework: renders a project, and declares what it can express."""

    @property
    def id(self) -> str: ...

    @property
    def display_name(self) -> str: ...

    def packages(self, provider: Provider) -> tuple[str, ...]:
        """Requirements for this framework combined with *provider*."""
        ...

    def render(self, spec: ScaffoldSpec, provider: Provider) -> tuple[RenderedFile, ...]:
        """Produce the project's files. Must not touch the filesystem."""
        ...

    def expressible_properties(self) -> frozenset[str]:
        """Security properties this framework's tool abstraction can represent.

        Anything a source tool declares that is absent from this set must be
        compensated by a generated guard, and the substitution recorded. Probe
        P0 measured these sets for the v1 targets.
        """
        ...


class MCPTarget(Protocol):
    """Reads and writes one framework's MCP server configuration."""

    @property
    def id(self) -> str: ...

    @property
    def config_path(self) -> PurePosixPath: ...

    def read(self, root: Path) -> tuple[MCPServerBinding, ...]:
        """Parse configured servers. Returns empty when no config exists."""
        ...

    def write(self, root: Path, servers: tuple[MCPServerBinding, ...]) -> tuple[RenderedFile, ...]:
        """Render the configuration for *servers*. Must not touch the filesystem."""
        ...


T = TypeVar("T")


class _Registry(Generic[T]):
    """A name-to-adapter lookup that fails loudly and lists what it does have."""

    def __init__(self, kind: str) -> None:
        self._kind = kind
        self._items: dict[str, T] = {}

    def register(self, key: str, item: T) -> None:
        if key in self._items:
            message = f"{self._kind} {key!r} is already registered"
            raise UsageError(message)
        self._items[key] = item

    def get(self, key: str) -> T:
        try:
            return self._items[key]
        except KeyError:
            known = ", ".join(sorted(self._items)) or "none"
            message = f"unknown {self._kind} {key!r}; available: {known}"
            raise UsageError(message) from None

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._items))


provider_registry: _Registry[Provider] = _Registry("provider")
framework_registry: _Registry[Framework] = _Registry("framework")
mcp_target_registry: _Registry[MCPTarget] = _Registry("mcp target")
