"""Hosted providers: OpenAI and Anthropic.

Both are declared, neither is exercised against its real endpoint. No key was
available for this work, so these adapters are verified two ways instead:

* **OpenAI** is exercised end to end against a local Ollama, which serves the
  same wire protocol at ``/v1``. The generated project is therefore genuinely
  run, just not against api.openai.com.
* **Anthropic** has no local equivalent, so it is contract-tested only - the
  facts it declares are checked, the code that consumes them is not run.

That distinction is recorded here rather than left implicit, because a paper
claiming three working provider cells when one has never made a request would be
overclaiming. `research/evaluation-protocol.md` carries the same caveat.

Model identifiers move faster than any pinned adapter can track, so
:meth:`supports_model` validates *shape* rather than membership of a list.
Rejecting a model that shipped last week would be worse than accepting a typo,
which the provider itself will reject on the first call with a clearer message
than this adapter could produce.
"""

from __future__ import annotations

import re
from typing import Final

# Provider model ids are lowercase alphanumerics with dashes, dots and colons.
# Whitespace is the useful thing to catch: it means a prose string reached a
# field that wanted an identifier.
_MODEL_ID: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")


def _valid_model_id(model: str) -> bool:
    return bool(model) and _MODEL_ID.match(model) is not None


class OpenAIProvider:
    """OpenAI, or anything serving its wire protocol."""

    id: Final = "openai"
    display_name: Final = "OpenAI"

    default_model: Final = "gpt-4o-mini"
    default_base_url: Final = "https://api.openai.com/v1"
    credential_env_var: Final[str | None] = "OPENAI_API_KEY"

    def packages(self) -> tuple[str, ...]:
        # Verified against OSV before pinning. The first version pinned here
        # carried two advisories, which check C2 caught on our own output -
        # a pinned version is only as good as the day it was chosen.
        return ("openai==2.54.0",)

    def supports_model(self, model: str) -> bool:
        return _valid_model_id(model)


class AnthropicProvider:
    """Anthropic.

    The one cell in the matrix with no local stand-in: the Messages API has no
    open-source server speaking it, so nothing here has been run against a real
    endpoint.
    """

    id: Final = "anthropic"
    display_name: Final = "Anthropic"

    default_model: Final = "claude-sonnet-5"
    default_base_url: Final = "https://api.anthropic.com"
    credential_env_var: Final[str | None] = "ANTHROPIC_API_KEY"

    def packages(self) -> tuple[str, ...]:
        return ("anthropic==0.121.0",)

    def supports_model(self, model: str) -> bool:
        return _valid_model_id(model)


class GeminiProvider:
    """Google Gemini.

    Added because a key is available for it, which makes it the second hosted
    cell that can be exercised rather than only contract-tested.
    """

    id: Final = "gemini"
    display_name: Final = "Google Gemini"

    default_model: Final = "gemini-2.5-flash"
    default_base_url: Final = "https://generativelanguage.googleapis.com/v1beta"
    credential_env_var: Final[str | None] = "GEMINI_API_KEY"

    def packages(self) -> tuple[str, ...]:
        # Verified against OSV before pinning, as every pin here is.
        return ("google-genai==1.51.0",)

    def supports_model(self, model: str) -> bool:
        return _valid_model_id(model)
