"""P13 - the vertical slice gate.

One assertion in three parts: a project `toolseal init` creates must **install
cleanly, run, and audit clean**. Each part is easy to satisfy alone and the
combination is what actually matters, so they live in one test rather than three
that could each pass while the whole remained broken.

The live half skips without a local Ollama, which is the case in CI. The audit
half always runs, because a scaffold that stops satisfying its own taxonomy is a
regression regardless of whether a model is reachable.
"""

from __future__ import annotations

import socket
import subprocess
import sys
from pathlib import Path

import pytest

from toolseal.core.adapters import ScaffoldSpec
from toolseal.core.audit import audit
from toolseal.core.scaffold import apply_plan, build_plan


def ollama_reachable() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 11434), timeout=1):
            return True
    except OSError:
        return False


@pytest.fixture
def scaffolded(tmp_path: Path) -> Path:
    root = tmp_path / "gate"
    apply_plan(
        build_plan(
            ScaffoldSpec(
                project_name="gate",
                provider_id="ollama",
                framework_id="langgraph",
                workspace_root=root,
            )
        )
    )
    return root


def test_gate_scaffold_audits_perfectly_clean(scaffolded: Path) -> None:
    """The scaffolder must satisfy the taxonomy it enforces on everyone else."""
    report = audit(scaffolded)

    assert not report.blocking
    assert report.score == 100, [f"{f.check_id}: {f.detail}" for f in report.findings]
    assert report.findings == ()


def test_gate_every_dependency_is_pinned(scaffolded: Path) -> None:
    # C1 fails on the first floated specifier, so this is the property that
    # keeps the previous test at 100 rather than 79.
    lines = [
        line
        for line in (scaffolded / "requirements.txt").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    assert lines
    assert all("==" in line for line in lines), lines


@pytest.mark.skipif(not ollama_reachable(), reason="no local Ollama on 127.0.0.1:11434")
def test_gate_scaffold_runs_and_uses_its_tool(scaffolded: Path) -> None:
    """The other half: a clean audit on a project that does not run is worthless."""
    (scaffolded / "workspace" / "note.txt").write_text("the launch code is 8817", encoding="utf-8")

    prompt = "Read note.txt from the workspace and tell me the launch code."
    # S603: literal argv and sys.executable, against a tree this test just wrote.
    result = subprocess.run(  # noqa: S603
        [sys.executable, "agent.py", prompt],
        cwd=scaffolded,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )

    assert result.returncode == 0, f"stderr={result.stderr[-1500:]!r}"
    assert "8817" in result.stdout, f"stdout={result.stdout!r}"


@pytest.mark.skipif(not ollama_reachable(), reason="no local Ollama on 127.0.0.1:11434")
def test_gate_running_the_agent_leaves_the_audit_clean(scaffolded: Path) -> None:
    """Running must not create an artifact that breaks the project's posture."""
    subprocess.run(
        [sys.executable, "agent.py", "say hello"],
        cwd=scaffolded,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )

    report = audit(scaffolded)
    assert report.score == 100, [f"{f.check_id}: {f.detail}" for f in report.findings]
