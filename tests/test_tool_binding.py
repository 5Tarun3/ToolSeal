# mypy: disable-error-code="untyped-decorator"
# The guards under test come from executing the generated template, so the
# namespace they are read from is untyped by construction.
"""Guards bound from `[policy.tool.<name>]`, and a fresh project that has one.

Until this existed the scaffold shipped a guard library and applied none of it:
guards reached a call path only when `translate/lower.py` lowered a registry
tool. A fresh project had a timeout guard sitting unused beside a tool with no
timeout. These tests pin both halves - the binding mechanism, and the default
that puts a guard in the one tool a new project starts with.
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from toolseal.core.adapters import ScaffoldSpec
from toolseal.core.credentials import merge_gitignore
from toolseal.core.scaffold import apply_plan, build_plan
from toolseal.templates.common import (
    EVIDENCE_GITIGNORE_ENTRIES,
    EVIDENCE_GITIGNORE_HEADER,
    GUARDS_PY,
)


class _NoTerminal:
    def isatty(self) -> bool:
        return False


def load_guards(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, evidence: str) -> Any:
    monkeypatch.setenv("TOOLSEAL_EVIDENCE", evidence)
    monkeypatch.delenv("TOOLSEAL_ASSUME_YES", raising=False)
    namespace: dict[str, Any] = {
        "__name__": "guards_under_test",
        "__file__": str(tmp_path / "guards.py"),
    }
    source = GUARDS_PY.substitute(project_name="binding", package_name="binding")
    exec(compile(source, "guards.py", "exec"), namespace)  # noqa: S102
    return namespace


def scaffold(root: Path, framework_id: str) -> Path:
    apply_plan(
        build_plan(
            ScaffoldSpec(
                project_name=root.name,
                provider_id="ollama",
                framework_id=framework_id,
                workspace_root=root,
            )
        )
    )
    return root


def import_agent_config(root: Path) -> ModuleType:
    sys.path.insert(0, str(root))
    sys.modules.pop("agent_config", None)
    try:
        return importlib.import_module("agent_config")
    finally:
        sys.path.remove(str(root))
        sys.modules.pop("agent_config", None)


# --- guard_tool ------------------------------------------------------------


@pytest.mark.parametrize("policy", [None, {}])
def test_an_empty_policy_leaves_the_tool_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, policy: dict[str, Any] | None
) -> None:
    guards = load_guards(tmp_path, monkeypatch, "off")

    def tool() -> str:
        return "ok"

    assert guards["guard_tool"](policy)(tool) is tool


def test_approval_is_asked_before_egress_is_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A human must never be asked about a call the egress rule would refuse
    # anyway, and without a terminal the approval refusal comes first.
    guards = load_guards(tmp_path, monkeypatch, "off")
    monkeypatch.setattr(sys, "stdin", _NoTerminal())
    policy = {"approval": "always", "egress_allow": ["api.allowed.invalid"], "timeout_seconds": 5}

    @guards["guard_tool"](policy)
    def fetch(url: str) -> str:
        return "reached"

    with pytest.raises(PermissionError):
        fetch(url="https://exfil.invalid/upload")


def test_guards_decide_outermost_first_and_only_the_call_is_timed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sink = tmp_path / "evidence.jsonl"
    guards = load_guards(tmp_path, monkeypatch, str(sink))
    # The override is set so the approval layer passes without a terminal;
    # this is a unit test of binding order, not a Study 6 measurement.
    monkeypatch.setenv("TOOLSEAL_ASSUME_YES", "1")
    policy = {"approval": "always", "egress_allow": ["api.allowed.invalid"], "timeout_seconds": 5}

    @guards["guard_tool"](policy)
    def fetch(url: str) -> str:
        return "reached"

    assert fetch(url="https://api.allowed.invalid/v1") == "reached"

    order = [json.loads(line)["guard"] for line in sink.read_text(encoding="utf-8").splitlines()]
    # Records are written as each guard decides: approval, then egress, and the
    # timeout guard last, once the call it bounds has returned.
    assert order == ["require_approval", "restrict_egress", "bound_runtime"]


def test_a_timeout_policy_alone_binds_bound_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guards = load_guards(tmp_path, monkeypatch, "off")
    released: list[bool] = []

    @guards["guard_tool"]({"timeout_seconds": 0.05})
    def hangs() -> str:
        import time

        while not released:
            time.sleep(0.01)
        return "late"

    try:
        with pytest.raises(guards["GuardTimeoutError"]):
            hangs()
    finally:
        released.append(True)


# --- the scaffolded default ------------------------------------------------


@pytest.mark.parametrize("framework_id", ["langgraph", "crewai"])
def test_a_fresh_project_declares_a_timeout_for_its_tool(tmp_path: Path, framework_id: str) -> None:
    root = scaffold(tmp_path / "demo", framework_id)
    manifest = (root / "toolseal.toml").read_text(encoding="utf-8")

    assert "[policy.tool.read_workspace_file]" in manifest
    assert "timeout_seconds = 30.0" in manifest
    # The comment says what the guard does not do, not only what it does.
    assert "not how long the tool runs" in manifest


@pytest.mark.parametrize("framework_id", ["langgraph", "crewai"])
def test_agent_config_exposes_the_tool_policies(tmp_path: Path, framework_id: str) -> None:
    root = scaffold(tmp_path / "demo", framework_id)

    module = import_agent_config(root)

    assert module.TOOL_POLICIES == {"read_workspace_file": {"timeout_seconds": 30.0}}


def test_agent_config_ignores_malformed_policy_tables(tmp_path: Path) -> None:
    root = scaffold(tmp_path / "demo", "langgraph")
    manifest = root / "toolseal.toml"
    text = manifest.read_text(encoding="utf-8")
    start = text.index("[policy.tool.read_workspace_file]")
    end = text.index("\n\n", start) if "\n\n" in text[start:] else len(text)
    manifest.write_text(
        text[:start] + '[policy.tool]\nread_workspace_file = "not a table"' + text[end:],
        encoding="utf-8",
    )

    module = import_agent_config(root)

    assert module.TOOL_POLICIES == {}


def test_claude_code_projects_declare_no_tool_policy(tmp_path: Path) -> None:
    # Claude Code configures a runtime rather than generating tools.py, so there
    # is no tool for a policy to bind to.
    root = scaffold(tmp_path / "demo", "claude-code")

    assert "[policy.tool." not in (root / "toolseal.toml").read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("framework_id", "decorator"),
    [("langgraph", "@tool"), ("crewai", '@tool("read_workspace_file")')],
)
def test_generated_tools_bind_guard_tool_under_the_framework_decorator(
    tmp_path: Path, framework_id: str, decorator: str
) -> None:
    root = scaffold(tmp_path / "demo", framework_id)
    source = (root / "tools.py").read_text(encoding="utf-8")

    lines = source.splitlines()
    index = lines.index(decorator)
    assert lines[index + 1] == '@guard_tool(TOOL_POLICIES.get("read_workspace_file"))'
    assert lines[index + 2].startswith("def read_workspace_file(")
    compile(source, "tools.py", "exec")


# --- keeping evidence out of version control -------------------------------


def test_the_evidence_ignore_rule_is_added_once() -> None:
    once = merge_gitignore("", EVIDENCE_GITIGNORE_ENTRIES, EVIDENCE_GITIGNORE_HEADER)
    twice = merge_gitignore(once, EVIDENCE_GITIGNORE_ENTRIES, EVIDENCE_GITIGNORE_HEADER)

    assert twice == once
    assert once.splitlines().count(".toolseal/evidence*") == 1


def test_a_fresh_project_ignores_its_evidence(tmp_path: Path) -> None:
    root = scaffold(tmp_path / "demo", "langgraph")
    rules = (root / ".gitignore").read_text(encoding="utf-8").splitlines()

    assert ".toolseal/evidence*" in rules
    # The credential rules are still there, unchanged.
    assert ".env" in rules
