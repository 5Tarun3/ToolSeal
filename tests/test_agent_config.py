"""`agent_config.py`: one shared module, read from one `toolseal.toml`.

The design for LangGraph/CrewAI overhead: generate a module that resolves the
provider binding once at scaffold time and reads the model, endpoint override
and tool list from `toolseal.toml` at run time, so both frameworks'
entrypoints read one source of truth instead of each hard-coding its own copy.

Three things matter enough to run rather than read, following the precedent in
`tests/test_executable_guards.py`:

* that the generated module actually imports and resolves the right values;
* that a project scaffolded for one framework genuinely does not need the
  other installed - not merely that it happens not to import it in the
  version written today;
* that a scaffolded project genuinely does not need *toolseal itself*
  installed - the scaffolder is a setup-time tool, and a project generated
  today must still run after a user moves it to a machine that has never
  seen toolseal.

The isolation tests prove all three the hard way, by making the target
package's import fail even though it is installed in this environment, and
checking the scaffolded project still runs.
"""

from __future__ import annotations

import importlib
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

from toolseal.core.adapters import ScaffoldSpec
from toolseal.core.adapters.frameworks import CrewAIFramework, LangGraphFramework
from toolseal.core.adapters.providers import OllamaProvider
from toolseal.core.scaffold import apply_plan, build_plan

PROVIDER = OllamaProvider()


def _scaffold(root: Path, framework_id: str, *, model: str | None = None) -> Path:
    apply_plan(
        build_plan(
            ScaffoldSpec(
                project_name=root.name,
                provider_id="ollama",
                framework_id=framework_id,
                workspace_root=root,
                model=model,
            )
        )
    )
    return root


def _import_agent_config(root: Path) -> ModuleType:
    sys.path.insert(0, str(root))
    sys.modules.pop("agent_config", None)
    try:
        return importlib.import_module("agent_config")
    finally:
        sys.path.remove(str(root))


# --- the shared module itself -----------------------------------------------


def test_the_generated_module_is_byte_identical_for_both_frameworks(tmp_path: Path) -> None:
    # "One toolseal config, both frameworks read it" only holds if there is
    # genuinely one implementation, not two templates that happen to agree
    # today and can drift tomorrow.
    spec = ScaffoldSpec(
        project_name="demo",
        provider_id="ollama",
        framework_id="langgraph",
        workspace_root=tmp_path,
        model="qwen2.5:3b",
    )
    langgraph_files = {str(f.path): f.content for f in LangGraphFramework().render(spec, PROVIDER)}
    crewai_files = {str(f.path): f.content for f in CrewAIFramework().render(spec, PROVIDER)}

    assert langgraph_files["agent_config.py"] == crewai_files["agent_config.py"]


def test_agent_config_reads_model_provider_and_tools_from_the_manifest(tmp_path: Path) -> None:
    root = _scaffold(tmp_path / "demo", "langgraph", model="qwen2.5:3b")

    module = _import_agent_config(root)
    try:
        # Read live from toolseal.toml.
        assert module.MODEL == "qwen2.5:3b"
        assert module.TOOL_NAMES == ("read_workspace_file",)
        # Baked in at scaffold time from the provider registry.
        assert module.PROVIDER_ID == "ollama"
        assert PROVIDER.display_name == module.PROVIDER_NAME
        assert PROVIDER.default_model == module.DEFAULT_MODEL
        assert PROVIDER.default_base_url == module.DEFAULT_BASE_URL == module.BASE_URL
        assert module.CREDENTIAL_ENV_VAR is None
        assert PROVIDER.credential_env_var is None
    finally:
        sys.modules.pop("agent_config", None)


def test_missing_manifest_fails_loudly_rather_than_guessing(tmp_path: Path) -> None:
    # The generated module reads toolseal.toml directly with tomllib; without
    # one alongside it, it should refuse rather than fall back to silent
    # defaults.
    root = tmp_path / "no_manifest"
    root.mkdir()

    from toolseal.templates.common import render_agent_config

    (root / "agent_config.py").write_text(
        render_agent_config(
            project_name="x",
            provider_id="ollama",
            provider_name="Ollama",
            default_model="qwen2.5:3b",
            default_base_url="http://127.0.0.1:11434",
            credential_env_var=None,
        ),
        encoding="utf-8",
    )

    sys.path.insert(0, str(root))
    sys.modules.pop("agent_config", None)
    try:
        with pytest.raises(RuntimeError, match=r"toolseal\.toml"):
            import agent_config  # type: ignore[import-not-found]  # noqa: F401
    finally:
        sys.path.remove(str(root))
        sys.modules.pop("agent_config", None)


# --- two entrypoints, one manifest -------------------------------------------


def test_both_frameworks_agree_on_the_model_from_independent_scaffolds(tmp_path: Path) -> None:
    # Each framework gets its own project directory - that part of the CLI is
    # unchanged - but both toolseal.toml files are produced by the same
    # formula in `scaffold.py`, and both agent_config.py modules read theirs
    # with the same `tomllib` logic. Nothing about the model resolution is
    # framework-specific, so the two must agree.
    langgraph_root = _scaffold(tmp_path / "lg", "langgraph", model="qwen2.5:3b")
    crewai_root = _scaffold(tmp_path / "cw", "crewai", model="qwen2.5:3b")

    langgraph_config = _import_agent_config(langgraph_root)
    try:
        langgraph_model = langgraph_config.MODEL
        langgraph_tools = langgraph_config.TOOL_NAMES
    finally:
        sys.modules.pop("agent_config", None)

    crewai_config = _import_agent_config(crewai_root)
    try:
        crewai_model = crewai_config.MODEL
        crewai_tools = crewai_config.TOOL_NAMES
    finally:
        sys.modules.pop("agent_config", None)

    assert langgraph_model == crewai_model == "qwen2.5:3b"
    assert langgraph_tools == crewai_tools == ("read_workspace_file",)


# --- isolation: one framework does not need the other installed -------------

_BLOCKER = """
import sys


class _Blocker:
    def __init__(self, blocked):
        self._blocked = blocked

    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in self._blocked:
            raise ImportError(f"blocked for test: {{name}}")
        return None


sys.meta_path.insert(0, _Blocker({blocked!r}))
"""


def _run(root: Path, script: str) -> subprocess.CompletedProcess[str]:
    """Run *script* in a fresh interpreter with *root* as the working directory."""
    return subprocess.run(  # noqa: S603
        [sys.executable, "-c", script],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def _run_blocked(root: Path, blocked: frozenset[str], imports: tuple[str, ...]) -> None:
    """Run *imports* in a fresh interpreter with *blocked* packages unimportable.

    Every blocked package is actually installed in this dev environment
    (langchain, crewai and toolseal are all present here), so simply checking
    that today's template text has no `import crewai` line would only prove
    the current wording, not the property. Making the import genuinely fail
    and then asserting the scaffold still runs is the real test.
    """
    script = _BLOCKER.format(blocked=blocked) + "\n".join(f"import {name}" for name in imports)
    result = _run(root, script)
    assert result.returncode == 0, f"stdout={result.stdout!r} stderr={result.stderr!r}"


def test_langgraph_scaffold_runs_with_crewai_unimportable(tmp_path: Path) -> None:
    root = _scaffold(tmp_path / "lg_only", "langgraph")

    _run_blocked(root, frozenset({"crewai", "crewai_tools"}), ("agent_config", "tools", "agent"))


def test_crewai_scaffold_runs_with_langchain_unimportable(tmp_path: Path) -> None:
    root = _scaffold(tmp_path / "cw_only", "crewai")

    blocked = frozenset(
        {
            "langchain",
            "langchain_core",
            "langgraph",
            "langchain_ollama",
            "langchain_openai",
            "langchain_anthropic",
            "langchain_google_genai",
        }
    )
    _run_blocked(root, blocked, ("agent_config", "tools", "agent"))


# --- isolation: a scaffolded project does not need toolseal installed -------
#
# This is the demo the project exists to protect: a fresh laptop that never
# ran `pip install toolseal`, running a project toolseal generated. toolseal
# is actually installed in this dev environment - which is exactly why every
# other test in this module could pass against a generated module that
# secretly still imported it - so the import is made to genuinely fail here,
# the same way the other-framework isolation tests above do it.


def test_langgraph_scaffold_runs_with_toolseal_unimportable(tmp_path: Path) -> None:
    root = _scaffold(tmp_path / "lg_no_toolseal", "langgraph", model="qwen2.5:3b")

    _run_blocked(root, frozenset({"toolseal"}), ("agent_config", "tools", "agent"))


def test_crewai_scaffold_runs_with_toolseal_unimportable(tmp_path: Path) -> None:
    root = _scaffold(tmp_path / "cw_no_toolseal", "crewai", model="qwen2.5:3b")

    _run_blocked(root, frozenset({"toolseal"}), ("agent_config", "tools", "agent"))


def test_agent_config_exposes_correct_values_with_toolseal_unimportable(tmp_path: Path) -> None:
    # Importing without crashing is necessary but not sufficient: prove the
    # module resolved the *right* model, provider and tool list with toolseal
    # unavailable, not merely that it resolved something.
    root = _scaffold(tmp_path / "values_no_toolseal", "langgraph", model="qwen2.5:3b")

    script = _BLOCKER.format(blocked=frozenset({"toolseal"})) + (
        "import agent_config\n"
        "assert agent_config.MODEL == 'qwen2.5:3b', agent_config.MODEL\n"
        "assert agent_config.TOOL_NAMES == ('read_workspace_file',), agent_config.TOOL_NAMES\n"
        "assert agent_config.PROVIDER_ID == 'ollama', agent_config.PROVIDER_ID\n"
        "assert agent_config.DEFAULT_BASE_URL == 'http://127.0.0.1:11434', "
        "agent_config.DEFAULT_BASE_URL\n"
        "print('agent_config-ok')\n"
    )
    result = _run(root, script)
    assert result.returncode == 0, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    assert "agent_config-ok" in result.stdout


def test_generated_agent_config_never_imports_toolseal(tmp_path: Path) -> None:
    # Direct proof the source carries no import, so a future edit that
    # reintroduces one fails loudly here rather than only under subprocess
    # isolation. The docstring legitimately mentions `toolseal.toml` and the
    # word "toolseal" itself, so this checks import statements specifically
    # rather than the whole file for the substring.
    root = _scaffold(tmp_path / "demo", "langgraph")
    content = (root / "agent_config.py").read_text(encoding="utf-8")

    for line in content.splitlines():
        stripped = line.strip()
        assert not stripped.startswith("import toolseal"), line
        assert not stripped.startswith("from toolseal"), line


def test_langgraph_agent_config_needs_no_crewai_when_read_directly(tmp_path: Path) -> None:
    # The narrowest form of the claim: agent_config.py alone, blocking both
    # frameworks at once, still imports and resolves real values.
    root = _scaffold(tmp_path / "either", "langgraph")

    blocked = frozenset({"crewai", "crewai_tools", "langchain", "langgraph", "langchain_core"})
    _run_blocked(root, blocked, ("agent_config",))
