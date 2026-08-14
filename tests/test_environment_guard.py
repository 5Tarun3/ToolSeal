"""The environment allowlist in generated projects (check E2).

A tool that inherits the parent environment inherits every cloud CLI profile,
SSH agent socket and exported API key with it. The generated guard is an
allowlist, and the test that matters is the one proving a secret does not
survive it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from toolseal.core.adapters import ScaffoldSpec
from toolseal.core.audit import audit
from toolseal.core.scaffold import apply_plan, build_plan
from toolseal.templates.common import GUARDS_PY


def guards_namespace() -> dict[str, Any]:
    source = GUARDS_PY.substitute(project_name="demo", package_name="demo")
    namespace: dict[str, Any] = {}
    exec(compile(source, "guards.py", "exec"), namespace)  # noqa: S102
    return namespace


def test_allowlist_excludes_credential_bearing_variables() -> None:
    allowed = guards_namespace()["ALLOWED_ENVIRONMENT"]

    for name in ("AWS_SECRET_ACCESS_KEY", "ANTHROPIC_API_KEY", "SSH_AUTH_SOCK", "GITHUB_TOKEN"):
        assert name not in allowed


def test_a_secret_in_the_parent_environment_does_not_survive(
    monkeypatch: Any,
) -> None:
    value = "sk-ant-should-not-propagate"  # toolseal:allow A1 - must not reach minimal_environment
    monkeypatch.setenv("ANTHROPIC_API_KEY", value)
    monkeypatch.setenv("PATH", "/usr/bin")

    env = guards_namespace()["minimal_environment"]()

    assert "ANTHROPIC_API_KEY" not in env
    assert env.get("PATH") == "/usr/bin"


def test_extra_values_are_passed_deliberately(monkeypatch: Any) -> None:
    # The escape hatch exists, but using it is an explicit act at the call site
    # rather than something that happens by default.
    monkeypatch.setenv("PATH", "/usr/bin")

    env = guards_namespace()["minimal_environment"]({"PGPASSWORD": "resolved-at-launch"})

    assert env["PGPASSWORD"] == "resolved-at-launch"


def test_restricting_the_environment_closes_e2(tmp_path: Path) -> None:
    root = tmp_path / "demo"
    apply_plan(
        build_plan(
            ScaffoldSpec(
                project_name="demo",
                provider_id="ollama",
                framework_id="langgraph",
                workspace_root=root,
            )
        )
    )

    assert not [f for f in audit(root).findings if f.check_id == "E2"]
