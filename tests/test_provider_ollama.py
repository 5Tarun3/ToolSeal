"""The Ollama adapter, and the credential-optional contract it exercises.

Ollama is the first provider with no credential at all, which is why
`credential_env_var` is optional on the protocol. The tests that matter here are
the ones pinning that distinction: *needs no secret* must never be confused with
*secret is missing*, or family A will report a finding on a correct project.
"""

from __future__ import annotations

import pytest

from toolseal.core.adapters import Provider, provider_registry
from toolseal.core.adapters.providers import OllamaProvider


def test_registered_under_its_id() -> None:
    # Importing the package registers the adapter; the registry name must not be
    # shadowed by the subpackage that shares its concept.
    import toolseal.core.adapters.providers as _registration  # noqa: F401

    assert "ollama" in provider_registry.names()
    assert provider_registry.get("ollama").id == "ollama"


def test_satisfies_the_provider_protocol() -> None:
    provider: Provider = OllamaProvider()
    assert provider.display_name
    assert provider.default_model
    assert provider.packages()


def test_needs_no_credential() -> None:
    assert OllamaProvider().credential_env_var is None


def test_default_endpoint_is_loopback() -> None:
    # A base URL is normally check D3 territory. The default must be stated so a
    # correct Ollama project is not read as an endpoint override.
    assert OllamaProvider().default_base_url.startswith("http://127.0.0.1")


def test_default_model_is_accepted_by_its_own_validator() -> None:
    provider = OllamaProvider()
    assert provider.supports_model(provider.default_model)


@pytest.mark.parametrize(
    "model",
    ["llama3", "qwen2.5:3b", "qwen3-embedding:0.6b", "library/mistral:7b-instruct", "phi4:latest"],
)
def test_valid_model_references_are_accepted(model: str) -> None:
    assert OllamaProvider().supports_model(model)


@pytest.mark.parametrize(
    "model",
    ["", "  ", "Qwen2.5:3b", "model with spaces", "model::tag", ":tag", "model:", "a/b/c:tag"],
)
def test_malformed_model_references_are_rejected(model: str) -> None:
    assert not OllamaProvider().supports_model(model)


def test_packages_exclude_framework_integrations() -> None:
    # Integration packages are named after the pairing, so they belong to the
    # framework adapter. A provider that guessed them would be wrong for every
    # framework but one.
    packages = OllamaProvider().packages()

    assert any(spec.startswith("ollama") for spec in packages)
    assert not any("langchain" in spec or "crewai" in spec for spec in packages)


def test_packages_are_version_constrained() -> None:
    # An unpinned dependency in a generated project is check C1 against us.
    assert all(any(op in spec for op in (">=", "==", "~=")) for spec in OllamaProvider().packages())
