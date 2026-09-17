"""`audit --json` is a machine contract. This is the guard on it.

Keys may be **added**. Keys may not be renamed, removed, or have their type or
meaning changed - that is a major-version event. Pinning the shape here means a
change that would break a downstream consumer fails in CI rather than in
someone's pipeline, months later, with no obvious cause.

The list below is deliberately a snapshot of a released version rather than a
mirror of the current code. A guard generated from the thing it guards proves
nothing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from toolseal.cli import app
from toolseal.core.adapters import ScaffoldSpec
from toolseal.core.scaffold import apply_plan, build_plan

runner = CliRunner()

#: Every key `audit --json` emitted at 0.1.3, with its type. Removing an entry
#: from this mapping is a breaking change and must be a deliberate, versioned
#: act - not a quiet edit to make a failing test pass.
CONTRACT_0_1_3: dict[str, type] = {
    "root": str,
    "profiles": list,
    "score": int,
    "blocking": bool,
    "families": list,
    "findings": list,
    "unknown_checks": list,
}


def _audit_payload(tmp_path: Path) -> dict[str, Any]:
    """Scaffold a clean project and return its `audit --json` payload.

    The same construction `tests/test_audit.py::test_clean_project_exits_zero`
    uses, including the empty `uv.lock` - without it the project reports a
    finding, and the payload under test is no longer the clean-project one.
    """
    spec = ScaffoldSpec(
        project_name="demo",
        provider_id="ollama",
        framework_id="langgraph",
        workspace_root=tmp_path / "demo",
    )
    apply_plan(build_plan(spec))
    (tmp_path / "demo" / "uv.lock").write_text("", encoding="utf-8")

    result = runner.invoke(app, ["audit", str(tmp_path / "demo"), "--json"])
    payload: dict[str, Any] = json.loads(result.stdout)
    return payload


def test_the_contract_list_is_non_vacuous() -> None:
    # A sweep over an empty mapping passes silently, which would make both
    # tests below meaningless.
    assert len(CONTRACT_0_1_3) >= 7


def test_every_contracted_key_is_still_present(tmp_path: Path) -> None:
    payload = _audit_payload(tmp_path)

    missing = [key for key in CONTRACT_0_1_3 if key not in payload]
    assert missing == [], f"audit --json dropped contracted keys: {missing}"


def test_every_contracted_key_keeps_its_type(tmp_path: Path) -> None:
    payload = _audit_payload(tmp_path)

    wrong = {
        key: type(payload[key]).__name__
        for key, expected in CONTRACT_0_1_3.items()
        if key in payload and not isinstance(payload[key], expected)
    }
    assert wrong == {}, f"audit --json changed key types: {wrong}"


def test_finding_entries_keep_their_shape(tmp_path: Path) -> None:
    # The findings list is the part consumers actually parse, so its element
    # shape is as much a contract as the top-level keys. A clean project has
    # no findings, so this drives one deliberately.
    (tmp_path / "leak.py").write_text(
        'OPENAI_API_KEY = "sk-abcdefghijklmnopqrst"\n',  # toolseal:allow A1 - drives a finding
        encoding="utf-8",
    )
    result = runner.invoke(app, ["audit", str(tmp_path), "--json"])
    payload = json.loads(result.stdout)

    assert payload["findings"], "expected the planted credential to produce a finding"
    for finding in payload["findings"]:
        for key in ("check", "severity", "title", "detail", "location", "line", "remediation"):
            assert key in finding, f"findings entry lost {key!r}"
