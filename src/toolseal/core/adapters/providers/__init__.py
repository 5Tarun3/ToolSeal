"""Provider adapters, registered by id.

Importing this package registers every provider, so `providers.get("ollama")`
works without the caller knowing which module defines it.
"""

from __future__ import annotations

from toolseal.core.adapters.base import provider_registry
from toolseal.core.adapters.providers.hosted import (
    AnthropicProvider,
    GeminiProvider,
    OpenAIProvider,
)
from toolseal.core.adapters.providers.ollama import OllamaProvider

provider_registry.register(OllamaProvider.id, OllamaProvider())
provider_registry.register(OpenAIProvider.id, OpenAIProvider())
provider_registry.register(AnthropicProvider.id, AnthropicProvider())
provider_registry.register(GeminiProvider.id, GeminiProvider())

__all__ = [
    "AnthropicProvider",
    "GeminiProvider",
    "OllamaProvider",
    "OpenAIProvider",
]
