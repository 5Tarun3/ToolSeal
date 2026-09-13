"""Registry behaviour, and static conformance to the adapter protocols.

`test_fake_provider_satisfies_protocol` looks trivial at runtime; its value is at
type-check time. The annotated assignment forces mypy to verify that a class
implementing the protocol structurally really does satisfy it, which is how
adapter conformance is enforced in the absence of a base class.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath

import pytest

from toolseal.core.adapters import (
    Framework,
    Provider,
    RenderedFile,
    ScaffoldSpec,
    framework_registry,
    provider_registry,
)
from toolseal.core.adapters.base import _Registry
from toolseal.errors import ExitCode, UsageError

SUMMARY_MAX = 78


class FakeProvider:
    id = "fake"
    display_name = "Fake"
    summary = "A fake provider. Exists to be type-checked, never to be called."
    default_model = "fake-1"
    default_base_url = "https://api.fake.test"
    credential_env_var = "FAKE_API_KEY"

    def packages(self) -> tuple[str, ...]:
        return ("fake-sdk==1.0.0",)

    def supports_model(self, model: str) -> bool:
        return model.startswith("fake-")


class FakeFramework:
    id = "fakeframework"
    display_name = "Fake Framework"
    summary = "A fake framework. Exists to be type-checked, never to be called."

    def packages(self, provider: Provider) -> tuple[str, ...]:
        return provider.packages()

    def render(self, spec: ScaffoldSpec, provider: Provider) -> tuple[RenderedFile, ...]:
        return (
            RenderedFile(
                path=PurePosixPath("main.py"),
                content=f"# {spec.project_name} on {provider.display_name}\n",
            ),
        )

    def expressible_properties(self) -> frozenset[str]:
        return frozenset({"destructiveHint"})


def test_fake_provider_satisfies_protocol() -> None:
    provider: Provider = FakeProvider()
    assert provider.packages() == ("fake-sdk==1.0.0",)
    assert provider.supports_model("fake-1")
    assert not provider.supports_model("other-1")


def test_fake_framework_satisfies_protocol() -> None:
    framework: Framework = FakeFramework()
    spec = ScaffoldSpec(
        project_name="demo",
        provider_id="fake",
        framework_id="fakeframework",
        workspace_root=Path(),
    )

    rendered = framework.render(spec, FakeProvider())

    assert len(rendered) == 1
    assert rendered[0].path == PurePosixPath("main.py")
    assert "demo" in rendered[0].content


def test_rendering_does_not_touch_the_filesystem(tmp_path: Path) -> None:
    spec = ScaffoldSpec(
        project_name="demo",
        provider_id="fake",
        framework_id="fakeframework",
        workspace_root=tmp_path,
    )

    FakeFramework().render(spec, FakeProvider())

    assert list(tmp_path.iterdir()) == []


def test_sensitive_files_are_flagged_by_mode() -> None:
    assert RenderedFile(PurePosixPath(".env"), "", mode=0o600).is_sensitive
    assert not RenderedFile(PurePosixPath("main.py"), "").is_sensitive


def test_registry_rejects_duplicate_registration() -> None:
    registry: _Registry[object] = _Registry("provider")
    registry.register("a", object())

    with pytest.raises(UsageError, match="already registered"):
        registry.register("a", object())


def test_unknown_lookup_lists_what_is_available() -> None:
    registry: _Registry[object] = _Registry("provider")
    registry.register("anthropic", object())
    registry.register("ollama", object())

    with pytest.raises(UsageError) as caught:
        registry.get("gemini")

    message = str(caught.value)
    assert "gemini" in message
    assert "anthropic, ollama" in message
    assert caught.value.exit_code == ExitCode.USAGE


def test_empty_registry_says_so_rather_than_showing_nothing() -> None:
    registry: _Registry[object] = _Registry("framework")

    with pytest.raises(UsageError, match="available: none"):
        registry.get("langgraph")


def test_registry_names_are_sorted() -> None:
    registry: _Registry[object] = _Registry("provider")
    for name in ("ollama", "anthropic", "openai"):
        registry.register(name, object())

    assert registry.names() == ("anthropic", "ollama", "openai")


# --- self-description ------------------------------------------------------


@pytest.mark.parametrize("name", provider_registry.names())
def test_every_provider_summarises_itself(name: str) -> None:
    summary = provider_registry.get(name).summary
    assert summary.strip(), f"provider {name} has an empty summary"
    assert len(summary) <= SUMMARY_MAX
    assert summary.isascii(), f"provider {name} summary is not ASCII"


@pytest.mark.parametrize("name", framework_registry.names())
def test_every_framework_summarises_itself(name: str) -> None:
    summary = framework_registry.get(name).summary
    assert summary.strip(), f"framework {name} has an empty summary"
    assert len(summary) <= SUMMARY_MAX
    assert summary.isascii(), f"framework {name} summary is not ASCII"
