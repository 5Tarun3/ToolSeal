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
