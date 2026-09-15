"""OpenAI and Anthropic, and the full provider x framework matrix.

Verification here is uneven and the tests say so. OpenAI is exercised end to end
against a local Ollama, which serves the same wire protocol at `/v1`, so the
generated project genuinely runs. Anthropic has no local stand-in and is
contract-tested only.

That asymmetry is the honest state of the matrix, and pretending otherwise in a
paper would be overclaiming. The test names carry it.
"""

from __future__ import annotations

import logging
import os
import socket
import subprocess
import sys
import types
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


# --- runtime credential resolution ------------------------------------------
#
# Storing a credential's *name* in a file (above) is only half of check A1's
# remediation. The other half is that the generated project actually reads the
# value back from the keychain at run time, in preference to whatever the
# ambient environment already holds - otherwise a credential some earlier,
# unrelated shell session exported would silently outlive the one toolseal
# manages, while every static signal (`.env`, `toolseal audit`) still reads
# clean. This is the failure mode `agent.py`'s `_resolve_credential` exists to
# close, and the two tests below hold it in place at two different levels.


@pytest.mark.parametrize(("provider_id", "framework_id"), CELLS)
def test_credentialed_cells_pin_keyring(
    tmp_path: Path, provider_id: str, framework_id: str
) -> None:
    # Runtime credential resolution needs `keyring` installed; a provider
    # needing no credential (ollama) should not gain a dependency for nothing.
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

    requirements = (root / "requirements.txt").read_text(encoding="utf-8")
    needs_credential = provider_id != "ollama"
    assert ("keyring==" in requirements) is needs_credential


@pytest.mark.parametrize("framework_id", ["langgraph", "crewai"])
def test_keychain_credential_overrides_a_stale_ambient_value(
    tmp_path: Path, framework_id: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The exact attack A1/A5 exist to prevent.

    A shell that exported `OPENAI_API_KEY` for something unrelated, earlier,
    is exactly the "stale session" that must not be able to override a
    credential this project actually manages through the keychain.
    """
    root = tmp_path / f"stale-session-{framework_id}"
    apply_plan(
        build_plan(
            ScaffoldSpec(
                project_name="stalesession",
                provider_id="openai",
                framework_id=framework_id,
                workspace_root=root,
            )
        )
    )

    source = (root / "agent.py").read_text(encoding="utf-8")
    start = source.index("def _resolve_credential")
    end = source.index("\ndef ", start + 1)
    namespace: dict[str, object] = {
        "CREDENTIAL_ENV_VAR": "OPENAI_API_KEY",
        "PROVIDER_ID": "openai",
        "os": os,
        "log": logging.getLogger("test-agent"),
    }
    exec(compile(source[start:end], str(root / "agent.py"), "exec"), namespace)  # noqa: S102

    # Short enough to stay under A1's own credential-shape threshold - this
    # repo's own audit must stay at 100/100, and these are not real secrets.
    fake_keyring = types.ModuleType("keyring")
    fake_keyring.get_password = lambda service, account: "sk-keychain"  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "keyring", fake_keyring)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-stale-session")

    namespace["_resolve_credential"]()  # type: ignore[operator]

    assert os.environ["OPENAI_API_KEY"] == "sk-keychain"


def test_credential_resolution_falls_back_to_ambient_when_keychain_is_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A keychain with nothing stored must not erase a value the caller already
    # provided another way (e.g. CI secrets injected as plain env vars).
    root = tmp_path / "no-keychain-entry"
    apply_plan(
        build_plan(
            ScaffoldSpec(
                project_name="nokeychainentry",
                provider_id="openai",
                framework_id="langgraph",
                workspace_root=root,
            )
        )
    )

    source = (root / "agent.py").read_text(encoding="utf-8")
    start = source.index("def _resolve_credential")
    end = source.index("\ndef ", start + 1)
    namespace: dict[str, object] = {
        "CREDENTIAL_ENV_VAR": "OPENAI_API_KEY",
        "PROVIDER_ID": "openai",
        "os": os,
        "log": logging.getLogger("test-agent"),
    }
    exec(compile(source[start:end], str(root / "agent.py"), "exec"), namespace)  # noqa: S102

    fake_keyring = types.ModuleType("keyring")
    fake_keyring.get_password = lambda service, account: None  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "keyring", fake_keyring)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-from-ci")

    namespace["_resolve_credential"]()  # type: ignore[operator]

    assert os.environ["OPENAI_API_KEY"] == "sk-from-ci"


# --- endpoint override -----------------------------------------------------


def test_base_url_override_reaches_the_generated_code(tmp_path: Path) -> None:
    # The override is no longer baked into agent.py's source: it is recorded
    # once in toolseal.toml, and agent_config.py reads it from there at run
    # time, so this is verified by importing the generated module rather than
    # by grepping agent.py for a literal.
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

    assert 'base_url = "http://127.0.0.1:11434/v1"' in (root / "toolseal.toml").read_text(
        encoding="utf-8"
    )

    sys.path.insert(0, str(root))
    sys.modules.pop("agent_config", None)
    try:
        import agent_config  # type: ignore[import-not-found]

        assert agent_config.BASE_URL == "http://127.0.0.1:11434/v1"
    finally:
        sys.path.remove(str(root))
        sys.modules.pop("agent_config", None)


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
