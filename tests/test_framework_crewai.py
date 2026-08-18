"""The CrewAI adapter - the target where translation actually costs something.

LangGraph proves the pipeline works; CrewAI proves it is needed. P0 measured that
its MCP adapter drops every annotation hint, so this is the framework where
lowering has to emit compensating guards rather than pass properties through.

With only one framework, "lossless translation" would be true by construction.
The tests that matter most here are the ones asserting the two targets genuinely
differ.
"""

from __future__ import annotations

import socket
import subprocess
import sys
from pathlib import Path, PurePosixPath

import pytest

from tests.test_gate_vertical_slice import KNOWN_OPEN
from toolseal.core.adapters import RenderedFile, ScaffoldSpec, framework_registry
from toolseal.core.adapters.frameworks import CrewAIFramework, LangGraphFramework
from toolseal.core.adapters.providers import OllamaProvider
from toolseal.core.audit import audit
from toolseal.core.registry.utd import (
    SecurityAnnotations,
    ToolSource,
    UnifiedToolDescriptor,
)
from toolseal.core.scaffold import apply_plan, build_plan
from toolseal.core.translate.lattice import GuardKind, SecurityProperty, profile
from toolseal.core.translate.lower import lower
from toolseal.errors import UsageError

FRAMEWORK = CrewAIFramework()
PROVIDER = OllamaProvider()


def spec(tmp_path: Path, **overrides: object) -> ScaffoldSpec:
    defaults: dict[str, object] = {
        "project_name": "demo-crew",
        "provider_id": "ollama",
        "framework_id": "crewai",
        "workspace_root": tmp_path,
    }
    return ScaffoldSpec(**{**defaults, **overrides})  # type: ignore[arg-type]


def rendered(tmp_path: Path, **overrides: object) -> dict[str, RenderedFile]:
    return {str(f.path): f for f in FRAMEWORK.render(spec(tmp_path, **overrides), PROVIDER)}


def ollama_reachable() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 11434), timeout=1):
            return True
    except OSError:
        return False


def test_registered_alongside_langgraph() -> None:
    assert {"crewai", "langgraph"} <= set(framework_registry.names())


def test_expressible_set_comes_from_the_lattice() -> None:
    assert FRAMEWORK.expressible_properties() == frozenset(
        str(prop) for prop in profile("crewai").expressible
    )


def test_the_two_targets_genuinely_differ() -> None:
    # If both frameworks expressed the same set, every lowering would be lossless
    # by construction and the guard machinery would never run.
    assert FRAMEWORK.expressible_properties() != LangGraphFramework().expressible_properties()
    assert "destructiveHint" not in FRAMEWORK.expressible_properties()
    assert "destructiveHint" in LangGraphFramework().expressible_properties()


def test_lowering_a_destructive_tool_into_crewai_emits_an_approval_guard() -> None:
    # The point of a second target: a property CrewAI cannot carry comes back as
    # behaviour instead of vanishing.
    descriptor = UnifiedToolDescriptor(
        id="mcp/fs@1#delete",
        name="delete_records",
        description="Permanently delete rows.",
        source=ToolSource("mcp", "npm", "@example/fs", "1.0.0"),
        annotations=SecurityAnnotations(destructive=True),
    )

    result = lower(descriptor, "crewai")

    assert result.plan.status == "compensated"
    assert SecurityProperty.DESTRUCTIVE in result.plan.compensated
    assert GuardKind.REQUIRE_APPROVAL in {guard.kind for guard in result.guards}


def test_unknown_provider_is_a_usage_error(tmp_path: Path) -> None:
    class Unknown:
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
        FRAMEWORK.render(spec(tmp_path), Unknown())


def test_render_touches_no_filesystem(tmp_path: Path) -> None:
    FRAMEWORK.render(spec(tmp_path), PROVIDER)
    assert list(tmp_path.iterdir()) == []


def test_emits_the_expected_file_set(tmp_path: Path) -> None:
    assert set(rendered(tmp_path)) == {
        "agent.py",
        "agent_config.py",
        "tools.py",
        "guards.py",
        "requirements.txt",
        ".env.example",
        "README.md",
        "workspace/.gitkeep",
    }


@pytest.mark.parametrize("name", ["agent.py", "tools.py", "guards.py", "agent_config.py"])
def test_generated_python_compiles(tmp_path: Path, name: str) -> None:
    compile(rendered(tmp_path)[name].content, name, "exec")


def test_no_placeholder_survives_substitution(tmp_path: Path) -> None:
    for item in rendered(tmp_path).values():
        assert "$" not in item.content, f"unsubstituted placeholder in {item.path}"


def test_model_carries_the_litellm_provider_prefix(tmp_path: Path) -> None:
    # CrewAI routes through LiteLLM, which identifies a model as provider/model.
    # Without the prefix it silently resolves to the wrong backend. The prefix
    # is fixed at scaffold time; the model id itself now comes from
    # `agent_config` at run time, which is exercised end-to-end in
    # tests/test_agent_config.py rather than read as a literal here.
    agent = rendered(tmp_path)["agent.py"].content
    assert 'LITELLM_PREFIX = "ollama"' in agent
    assert 'model=f"{LITELLM_PREFIX}/{MODEL}"' in agent


def test_guards_are_the_shared_ones(tmp_path: Path) -> None:
    # One copy across frameworks, so a compensating guard behaves identically
    # wherever a tool is lowered.
    guards = rendered(tmp_path)["guards.py"].content
    assert "def require_approval" in guards
    assert "class RedactingFilter" in guards


def test_requirements_are_pinned_exactly(tmp_path: Path) -> None:
    lines = [
        line for line in rendered(tmp_path)["requirements.txt"].content.splitlines() if line.strip()
    ]
    assert lines
    assert all("==" in line for line in lines), lines


def test_agent_bounds_its_loop_and_its_calls(tmp_path: Path) -> None:
    agent = rendered(tmp_path)["agent.py"].content
    assert "max_iter" in agent
    assert "REQUEST_TIMEOUT_SECONDS" in agent


def test_no_executor_tool_by_default(tmp_path: Path) -> None:
    tools = rendered(tmp_path)["tools.py"].content
    for forbidden in ("subprocess", "os.system", "eval(", "exec("):
        assert forbidden not in tools


# --- the scaffolded project ------------------------------------------------


@pytest.fixture
def scaffolded(tmp_path: Path) -> Path:
    root = tmp_path / "crew"
    apply_plan(
        build_plan(
            ScaffoldSpec(
                project_name="crew",
                provider_id="ollama",
                framework_id="crewai",
                workspace_root=root,
            )
        )
    )
    return root


def test_scaffolded_crewai_project_matches_the_langgraph_posture(scaffolded: Path) -> None:
    # Both cells must reach the same audit outcome. A framework that scored worse
    # would mean the secure defaults are LangGraph-specific rather than real.
    failing = {finding.check_id for finding in audit(scaffolded).findings}

    assert failing <= KNOWN_OPEN, sorted(failing - KNOWN_OPEN)


def test_scaffolded_crewai_project_has_no_blocking_findings(scaffolded: Path) -> None:
    assert not audit(scaffolded).blocking


def test_workspace_placeholder_is_created(scaffolded: Path) -> None:
    assert (scaffolded / "workspace").is_dir()
    assert (scaffolded / PurePosixPath("workspace/.gitkeep")).exists()


@pytest.mark.skipif(not ollama_reachable(), reason="no local Ollama on 127.0.0.1:11434")
def test_generated_crew_runs_against_ollama(scaffolded: Path) -> None:
    """Source that compiles is not source that works."""
    (scaffolded / "workspace" / "note.txt").write_text("the code is 5591", encoding="utf-8")

    prompt = "Use read_workspace_file on note.txt and report the code it contains."
    # S603: literal argv and sys.executable, against a tree this test just wrote.
    result = subprocess.run(  # noqa: S603
        [sys.executable, "agent.py", prompt],
        cwd=scaffolded,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )

    assert result.returncode == 0, f"stderr={result.stderr[-2000:]!r}"
    assert "5591" in result.stdout, f"stdout={result.stdout[-1000:]!r}"
