"""Adapter contracts and the registries that resolve them by name."""

from __future__ import annotations

from toolseal.core.adapters.base import (
    DEFAULT_FILE_MODE,
    PRIVATE_FILE_MODE,
    Framework,
    MCPTarget,
    Provider,
    RenderedFile,
    ScaffoldSpec,
    framework_registry,
    mcp_target_registry,
    provider_registry,
)

__all__ = [
    "DEFAULT_FILE_MODE",
    "PRIVATE_FILE_MODE",
    "Framework",
    "MCPTarget",
    "Provider",
    "RenderedFile",
    "ScaffoldSpec",
    "framework_registry",
    "mcp_target_registry",
    "provider_registry",
]

# Imported last, and for their side effect: each subpackage registers its
# adapters on import. Placing this at the bottom avoids a cycle (the subpackages
# import `base`, which is already loaded by the time this runs) and means the
# registries are populated by anyone who touches this package - rather than
# depending on some caller having imported the right module first.
from toolseal.core.adapters import frameworks as _frameworks  # noqa: F401
from toolseal.core.adapters import providers as _providers  # noqa: F401
