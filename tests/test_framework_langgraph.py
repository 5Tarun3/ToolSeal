"""The LangGraph adapter, and the security properties of what it emits.

Rendering tests assert on the *defaults*, not on formatting. A generated project
whose tool list is explicit, whose filesystem access is confined and whose
timeouts are set is the product claim; if any of those regress, the audit would
catch it later but a reviewer should catch it here.

`test_generated_agent_runs_against_ollama` is the honest one: rendering source
that compiles is not the same as rendering source that works. It skips when no
local Ollama is reachable, which is the case in CI.
"""

from __future__ import annotations

import socket
import subprocess
import sys
from pathlib import Path, PurePosixPath

import pytest

from toolseal.core.adapters import (
    RenderedFile,
    ScaffoldSpec,
    framework_registry,
    provider_registry,
)
from toolseal.core.adapters.frameworks import LangGraphFramework
from toolseal.core.adapters.providers import OllamaProvider
from toolseal.core.translate.lattice import profile
from toolseal.errors import UsageError

FRAMEWORK = LangGraphFramework()
PROVIDER = OllamaProvider()


def spec(tmp_path: Path, **overrides: object) -> ScaffoldSpec:
    defaults: dict[str, object] = {
        "project_name": "demo-agent",
        "provider_id": "ollama",
        "framework_id": "langgraph",
        "workspace_root": tmp_path,
    }
    return ScaffoldSpec(**{**defaults, **overrides})  # type: ignore[arg-type]


def rendered(tmp_path: Path, **overrides: object) -> dict[str, RenderedFile]:
    files = FRAMEWORK.render(spec(tmp_path, **overrides), PROVIDER)
    return {str(item.path): item for item in files}


def ollama_reachable() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 11434), timeout=1):
            return True
    except OSError:
        return False


# --- registration and contracts -------------------------------------------


def test_registered_under_its_id() -> None:
    assert "langgraph" in framework_registry.names()
    assert framework_registry.get("langgraph").id == "langgraph"


def test_expressible_properties_come_from_the_lattice() -> None:
    # Restating the set here would eventually disagree with the measurement, and
    # the disagreeing copy would be the one deciding whether a guard is emitted.
    assert FRAMEWORK.expressible_properties() == frozenset(
        str(prop) for prop in profile("langchain").expressible
    )


def test_unknown_provider_is_a_usage_error(tmp_path: Path) -> None:
    class UnknownProvider:
        id = "cohere"
        display_name = "Cohere"
        default_model = "command-r"
        default_base_url = "https://example.test"
        credential_env_var = "COHERE_API_KEY"

        def packages(self) -> tuple[str, ...]:
            return ()

        def supports_model(self, model: str) -> bool:
            return True

    with pytest.raises(UsageError, match="no integration for provider"):
        FRAMEWORK.render(spec(tmp_path), UnknownProvider())


def test_model_the_provider_rejects_is_a_usage_error(tmp_path: Path) -> None:
    with pytest.raises(UsageError, match="does not accept model"):
        FRAMEWORK.render(spec(tmp_path, model="Not A Valid Tag"), PROVIDER)


def test_render_touches_no_filesystem(tmp_path: Path) -> None:
    FRAMEWORK.render(spec(tmp_path), PROVIDER)
    assert list(tmp_path.iterdir()) == []


def test_render_is_deterministic(tmp_path: Path) -> None:
    first = FRAMEWORK.render(spec(tmp_path), PROVIDER)
    second = FRAMEWORK.render(spec(tmp_path), PROVIDER)
    assert first == second


# --- what gets produced ----------------------------------------------------


def test_emits_the_expected_file_set(tmp_path: Path) -> None:
    assert set(rendered(tmp_path)) == {
        "agent.py",
        "tools.py",
        "guards.py",
        "requirements.txt",
        ".env.example",
        "README.md",
        "workspace/.gitkeep",
    }


@pytest.mark.parametrize("name", ["agent.py", "tools.py", "guards.py"])
def test_generated_python_compiles(tmp_path: Path, name: str) -> None:
    source = rendered(tmp_path)[name].content
    compile(source, name, "exec")


def test_no_placeholder_survives_substitution(tmp_path: Path) -> None:
    for item in rendered(tmp_path).values():
        assert "$" not in item.content, f"unsubstituted placeholder in {item.path}"


# --- security defaults -----------------------------------------------------


def test_requirements_are_all_version_constrained(tmp_path: Path) -> None:
    # C1: an unpinned dependency in a generated project is our own check
    # firing on us.
    lines = [line for line in rendered(tmp_path)["requirements.txt"].content.splitlines() if line]
    assert lines
    assert all(any(op in line for op in (">=", "==", "~=")) for line in lines)


def test_requirements_order_is_stable(tmp_path: Path) -> None:
    # A regenerated file should diff empty, not reshuffle.
    assert rendered(tmp_path)["requirements.txt"].content == (
        rendered(tmp_path)["requirements.txt"].content
    )


def test_env_example_declares_names_but_never_values(tmp_path: Path) -> None:
    # A1: placeholders only. Ollama needs no credential at all, so the file
    # should say so rather than look like something is missing.
    content = rendered(tmp_path)[".env.example"].content
    assert "needs no API key" in content
    for line in content.splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            assert line.rstrip().endswith("="), f"value present in .env.example: {line!r}"


def test_agent_binds_an_explicit_tool_list(tmp_path: Path) -> None:
    # B1: the overprovisioning default this scaffold exists to avoid.
    agent = rendered(tmp_path)["agent.py"].content
    assert "create_agent(model, list(TOOLS))" in agent
    assert "B1" in agent


def test_agent_sets_both_bounds(tmp_path: Path) -> None:
    # E3: a timeout without a recursion limit still permits an unbounded loop.
    agent = rendered(tmp_path)["agent.py"].content
    assert "REQUEST_TIMEOUT_SECONDS" in agent
    assert "recursion_limit" in agent


def test_filesystem_tool_confines_after_resolution(tmp_path: Path) -> None:
    # B3: checking the string before resolving would let `../` and symlinks out.
    tools = rendered(tmp_path)["tools.py"].content
    assert ".resolve()" in tools
    assert "is_relative_to(WORKSPACE)" in tools


def test_no_shell_or_exec_tool_by_default(tmp_path: Path) -> None:
    # B2: the scaffold never ships an executor.
    tools = rendered(tmp_path)["tools.py"].content
    for forbidden in ("subprocess", "os.system", "eval(", "exec("):
        assert forbidden not in tools


def test_guards_module_provides_redaction_and_approval(tmp_path: Path) -> None:
    # A4 and F2 respectively; F2's decorator is also what a compensating guard
    # reuses when a target cannot carry destructiveHint.
    guards = rendered(tmp_path)["guards.py"].content
    assert "class RedactingFilter" in guards
    assert "def require_approval" in guards


def test_approval_bypass_is_environmental_not_an_argument(tmp_path: Path) -> None:
    # A model can pass an argument; it cannot set the environment the process
    # already started with.
    guards = rendered(tmp_path)["guards.py"].content
    assert "TOOLSEAL_ASSUME_YES" in guards
    assert "def require_approval(reason: str)" in guards


def test_generated_redaction_actually_redacts(tmp_path: Path) -> None:
    # The guards module is copied into user projects, so its redaction is tested
    # by executing it rather than by reading it.
    namespace: dict[str, object] = {}
    exec(compile(rendered(tmp_path)["guards.py"].content, "guards.py", "exec"), namespace)  # noqa: S102
    redact = namespace["redact"]
    assert callable(redact)

    assert "sk-abcdefghijklmnop1234" not in redact('OPENAI_API_KEY="sk-abcdefghijklmnop1234"')
    assert redact("resolved 14 dependencies") == "resolved 14 dependencies"


# --- the honest one --------------------------------------------------------


@pytest.mark.skipif(not ollama_reachable(), reason="no local Ollama on 127.0.0.1:11434")
def test_generated_agent_runs_against_ollama(tmp_path: Path) -> None:
    """Write the scaffold to disk and actually run it.

    Source that compiles is not source that works: this is what catches a
    deprecated import or a renamed framework entry point.
    """
    for item in FRAMEWORK.render(spec(tmp_path), PROVIDER):
        target = tmp_path / PurePosixPath(item.path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(item.content, encoding="utf-8")

    (tmp_path / "workspace" / "note.txt").write_text("the answer is 42", encoding="utf-8")

    prompt = "Read note.txt from the workspace and tell me what it says."
    # S603: the argv is a literal and sys.executable, run against a tree this
    # test just wrote. Nothing here comes from outside the test.
    result = subprocess.run(  # noqa: S603
        [sys.executable, "agent.py", prompt],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )

    assert result.returncode == 0, f"stdout={result.stdout!r} stderr={result.stderr[-2000:]!r}"
    assert "42" in result.stdout, f"stdout={result.stdout!r}"


def test_provider_is_registered_for_the_matrix() -> None:
    assert provider_registry.get("ollama").id == PROVIDER.id
