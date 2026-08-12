"""Ollama: a locally hosted runtime, and the project's reference provider.

Ollama is the provider the vertical slice is verified against, for a reason that
is practical rather than architectural: it needs no credential and no network,
so a scaffolded project can be run end to end by anyone who checks out the
repository. Cells that require a paid key are contract-tested instead.

Two consequences shape this adapter:

* :attr:`credential_env_var` is ``None``. Ollama has no API key, and family A
  must not report a missing secret for a provider that never had one.
* :attr:`default_base_url` points at loopback. A base URL is normally a finding
  worth reporting (check ``D3``), so the *default* has to be stated here rather
  than inferred, otherwise every Ollama project would look like an endpoint
  override.
"""

from __future__ import annotations

import re
from typing import Final

# Ollama model references are `name`, `name:tag`, or `namespace/name:tag`.
# Validating shape is all that can be done offline; whether a tag is actually
# pulled is a question for `doctor`, which may talk to the local daemon.
_MODEL_REFERENCE: Final = re.compile(
    r"^[a-z0-9]+(?:[._-][a-z0-9]+)*"
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)?"
    r"(?::[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)*)?$"
)

DEFAULT_HOST: Final = "http://127.0.0.1:11434"


class OllamaProvider:
    """Facts about a local Ollama runtime."""

    id: Final = "ollama"
    display_name: Final = "Ollama"

    # A small tool-capable model, so a scaffolded project runs on a laptop
    # without a large download. Tool calling is the requirement: an agent whose
    # model cannot call tools cannot exercise anything this project audits.
    default_model: Final = "qwen2.5:3b"
    default_base_url: Final = DEFAULT_HOST
    credential_env_var: Final[str | None] = None

    def packages(self) -> tuple[str, ...]:
        """The provider SDK only.

        Framework integration packages are the framework's business, since they
        are named after the pairing rather than after the provider.
        """
        return ("ollama>=0.4.0",)

    def supports_model(self, model: str) -> bool:
        """Whether *model* is a well-formed Ollama model reference.

        This is a shape check, not an availability check. Ollama serves whatever
        has been pulled locally, so an offline adapter cannot know more than
        this without contacting the daemon.
        """
        return bool(model) and _MODEL_REFERENCE.match(model) is not None
