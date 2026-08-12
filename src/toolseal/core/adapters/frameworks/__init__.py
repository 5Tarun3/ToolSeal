"""Framework adapters, registered by id.

Importing this package registers every framework, so `frameworks.get("langgraph")`
works without the caller knowing which module defines it.
"""

from __future__ import annotations

from toolseal.core.adapters.base import framework_registry
from toolseal.core.adapters.frameworks.langgraph import LangGraphFramework

framework_registry.register(LangGraphFramework.id, LangGraphFramework())

__all__ = ["LangGraphFramework"]
