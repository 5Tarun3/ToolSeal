"""Provider adapters, registered by id.

Importing this package registers every provider, so `providers.get("ollama")`
works without the caller knowing which module defines it.
"""

from __future__ import annotations

from toolseal.core.adapters.base import providers
from toolseal.core.adapters.providers.ollama import OllamaProvider

providers.register(OllamaProvider.id, OllamaProvider())

__all__ = ["OllamaProvider"]
