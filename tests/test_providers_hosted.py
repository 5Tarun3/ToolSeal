"""OpenAI and Anthropic, and the full provider x framework matrix.

Verification here is uneven and the tests say so. OpenAI is exercised end to end
against a local Ollama, which serves the same wire protocol at `/v1`, so the
generated project genuinely runs. Anthropic has no local stand-in and is
contract-tested only.

That asymmetry is the honest state of the matrix, and pretending otherwise in a
paper would be overclaiming. The test names carry it.
"""

from __future__ import annotations

import socket
import subprocess
import sys
from pathlib import Path

import pytest

from toolseal.core.adapters import Provider, ScaffoldSpec, provider_registry
from toolseal.core.adapters.providers import (
    AnthropicProvider,
    GeminiProvider,
    OllamaProvider,
    OpenAIProvider,
)
from toolseal.core.audit import audit
from toolseal.core.scaffold import apply_plan, build_plan

HOSTED = (OpenAIProvider(), AnthropicProvider(), GeminiProvider())
CELLS = [
    (provider, framework)
    for provider in ("ollama", "openai", "anthropic", "gemini")
    for framework in ("langgraph", "crewai")
]


def ollama_reachable() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 11434), timeout=1):
            return True
    except OSError:
        return False


# --- provider facts --------------------------------------------------------


def test_every_provider_is_registered() -> None:
    assert set(provider_registry.names()) == {"anthropic", "gemini", "ollama", "openai"}


@pytest.mark.parametrize("provider", HOSTED, ids=lambda p: p.id)
def test_satisfies_the_protocol(provider: Provider) -> None:
    declared: Provider = provider
    assert declared.display_name
    assert declared.packages()


@pytest.mark.parametrize("provider", HOSTED, ids=lambda p: p.id)
def test_hosted_providers_require_a_credential(provider: Provider) -> None:
    # The distinction that matters: Ollama needs none, these need one, and
    # family A must be able to tell those apart.
    assert provider.credential_env_var
    assert provider.credential_env_var.endswith("_API_KEY")


def test_ollama_remains_the_only_credential_free_provider() -> None:
    assert OllamaProvider().credential_env_var is None


@pytest.mark.parametrize("provider", HOSTED, ids=lambda p: p.id)
def test_endpoints_are_https(provider: Provider) -> None:
    assert provider.default_base_url.startswith("https://")


@pytest.mark.parametrize("provider", HOSTED, ids=lambda p: p.id)
def test_packages_are_pinned_exactly(provider: Provider) -> None:
    assert all("==" in spec for spec in provider.packages())


@pytest.mark.parametrize("provider", HOSTED, ids=lambda p: p.id)
def test_default_model_passes_its_own_validator(provider: Provider) -> None:
    assert provider.supports_model(provider.default_model)


@pytest.mark.parametrize("provider", HOSTED, ids=lambda p: p.id)
@pytest.mark.parametrize("model", ["", "   ", "a model with spaces", "model\twith\ttabs"])
def test_malformed_model_ids_are_rejected(provider: Provider, model: str) -> None:
    assert not provider.supports_model(model)


@pytest.mark.parametrize("provider", HOSTED, ids=lambda p: p.id)
def test_unknown_but_well_formed_models_are_accepted(provider: Provider) -> None:
    # Model ids move faster than a pinned adapter can track. Rejecting one that
    # shipped last week is worse than accepting a typo the provider will reject
    # with a clearer message than this adapter could produce.
    assert provider.supports_model("some-model-released-tomorrow-1")


# --- the matrix ------------------------------------------------------------


@pytest.mark.parametrize(("provider_id", "framework_id"), CELLS)
def test_every_cell_scaffolds_and_audits_clean(
    tmp_path: Path, provider_id: str, framework_id: str
) -> None:
    root = tmp_path / f"{provider_id}-{framework_id}"
    apply_plan(
        build_plan(
            ScaffoldSpec(
                project_name="cell",
                provider_id=provider_id,
                framework_id=framework_id,
                workspace_root=root,
            )
        )
    )

    report = audit(root)

    assert report.score == 100, [f"{f.check_id}: {f.detail}" for f in report.findings]


@pytest.mark.parametrize(("provider_id", "framework_id"), CELLS)
def test_every_cell_generates_compiling_python(
    tmp_path: Path, provider_id: str, framework_id: str
) -> None:
    root = tmp_path / f"{provider_id}-{framework_id}"
    apply_plan(
        build_plan(
            ScaffoldSpec(
                project_name="cell",
                provider_id=provider_id,
                framework_id=framework_id,
                workspace_root=root,
            )
        )
    )

    for name in ("agent.py", "tools.py", "guards.py"):
        compile((root / name).read_text(encoding="utf-8"), name, "exec")


@pytest.mark.parametrize(("provider_id", "framework_id"), CELLS)
def test_no_cell_writes_a_credential_value(
    tmp_path: Path, provider_id: str, framework_id: str
) -> None:
    # A1 across the whole matrix: the env example names a variable and stops.
    root = tmp_path / f"{provider_id}-{framework_id}"
    apply_plan(
        build_plan(
            ScaffoldSpec(
                project_name="cell",
                provider_id=provider_id,
                framework_id=framework_id,
                workspace_root=root,
            )
        )
    )

    for line in (root / ".env.example").read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            assert line.rstrip().endswith("="), line


# --- endpoint override -----------------------------------------------------


def test_base_url_override_reaches_the_generated_code(tmp_path: Path) -> None:
    root = tmp_path / "proxied"
    apply_plan(
        build_plan(
            ScaffoldSpec(
                project_name="proxied",
                provider_id="openai",
                framework_id="langgraph",
                workspace_root=root,
                base_url="http://127.0.0.1:11434/v1",
            )
        )
    )

    assert "http://127.0.0.1:11434/v1" in (root / "agent.py").read_text(encoding="utf-8")


@pytest.mark.skipif(not ollama_reachable(), reason="no local Ollama on 127.0.0.1:11434")
def test_openai_cell_runs_against_an_openai_compatible_endpoint(tmp_path: Path) -> None:
    """The OpenAI cell, genuinely run - just not against api.openai.com.

    Ollama serves the OpenAI wire protocol at /v1, so this exercises the real
    generated code path with no key. Anthropic has no equivalent, which is why
    it stays contract-tested.
    """
    root = tmp_path / "openai-cell"
    apply_plan(
        build_plan(
            ScaffoldSpec(
                project_name="openaicell",
                provider_id="openai",
                framework_id="langgraph",
                workspace_root=root,
                model="qwen2.5:3b",
                base_url="http://127.0.0.1:11434/v1",
            )
        )
    )
    (root / "workspace" / "note.txt").write_text("the token is 7742", encoding="utf-8")

    prompt = "Read note.txt from the workspace and tell me the token."
    # S603: literal argv and sys.executable, against a tree this test just wrote.
    result = subprocess.run(  # noqa: S603
        [sys.executable, "agent.py", prompt],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
        env={**dict(__import__("os").environ), "OPENAI_API_KEY": "not-used-by-ollama"},
    )

    assert result.returncode == 0, f"stderr={result.stderr[-2000:]!r}"
    assert "7742" in result.stdout, f"stdout={result.stdout[-800:]!r}"
