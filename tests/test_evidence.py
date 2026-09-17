# mypy: disable-error-code="untyped-decorator"
# The guards under test come from executing the generated template, so the
# namespace they are read from is untyped by construction.
"""The evidence channel: every guard decision leaves one record, and only the fact.

Two properties matter more than the rest. A record never carries a tool's
arguments - an evidence log holding every payload that crossed a guard would be
the most valuable file in a deployed agent. And a broken sink never changes a
guard's decision or takes the agent down: evidence is best-effort, warned about
once, and a refusal is still a refusal.

These tests execute the real generated `guards.py`, not a reimplementation.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from toolseal.templates.common import GUARDS_PY

KEYS = ["schema", "ts", "layer", "guard", "tool", "outcome", "reason", "elapsed_us"]


class _NoTerminal:
    def isatty(self) -> bool:
        return False


def load_guards(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, evidence: str | None) -> Any:
    if evidence is None:
        monkeypatch.delenv("TOOLSEAL_EVIDENCE", raising=False)
    else:
        monkeypatch.setenv("TOOLSEAL_EVIDENCE", evidence)
    monkeypatch.delenv("TOOLSEAL_ASSUME_YES", raising=False)
    namespace: dict[str, Any] = {
        "__name__": "guards_under_test",
        "__file__": str(tmp_path / "guards.py"),
    }
    source = GUARDS_PY.substitute(project_name="evidence", package_name="evidence")
    exec(compile(source, "guards.py", "exec"), namespace)  # noqa: S102
    return namespace


def records(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


@pytest.fixture
def sink(tmp_path: Path) -> Path:
    return tmp_path / "evidence.jsonl"


def only_record(path: Path) -> dict[str, Any]:
    written = records(path)
    assert len(written) == 1, written
    return written[0]


# --- the record ------------------------------------------------------------


def test_a_record_has_schema_v1_keys_in_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sink: Path
) -> None:
    guards = load_guards(tmp_path, monkeypatch, str(sink))

    @guards["restrict_egress"](["api.allowed.invalid"])
    def fetch(url: str) -> str:
        return "ok"

    fetch(url="https://api.allowed.invalid/v1")

    record = only_record(sink)
    assert list(record) == KEYS
    assert record["schema"] == 1
    assert record["layer"] == "decorator"
    assert record["guard"] == "restrict_egress"
    assert record["tool"] == "fetch"
    assert (record["outcome"], record["reason"]) == ("allowed", "checked")
    assert record["ts"].endswith("Z")
    assert isinstance(record["elapsed_us"], float)
    assert record["elapsed_us"] >= 0


def test_egress_refusal_is_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sink: Path
) -> None:
    guards = load_guards(tmp_path, monkeypatch, str(sink))

    @guards["restrict_egress"](["api.allowed.invalid"])
    def fetch(url: str) -> str:
        return "ok"

    with pytest.raises(guards["EgressPolicyError"]):
        fetch(url="https://exfil.invalid/upload")

    record = only_record(sink)
    assert (record["outcome"], record["reason"]) == ("refused", "egress")


@pytest.mark.parametrize(
    ("limit", "expected"), [(100000, ("refused", "schema")), (10, ("allowed", "checked"))]
)
def test_schema_decisions_are_recorded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    sink: Path,
    limit: int,
    expected: tuple[str, str],
) -> None:
    guards = load_guards(tmp_path, monkeypatch, str(sink))
    schema = {"properties": {"limit": {"type": "integer", "maximum": 1000}}}

    @guards["validate_against_schema"](schema)
    def query(limit: int) -> int:
        return limit

    try:
        query(limit=limit)
    except guards["SchemaViolationError"]:
        pass

    record = only_record(sink)
    assert (record["outcome"], record["reason"]) == expected


def test_a_timeout_is_recorded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sink: Path) -> None:
    guards = load_guards(tmp_path, monkeypatch, str(sink))

    @guards["bound_runtime"](0.05)
    def slow() -> str:
        time.sleep(0.3)
        return "late"

    with pytest.raises(guards["GuardTimeoutError"]):
        slow()

    record = only_record(sink)
    assert (record["outcome"], record["reason"]) == ("refused", "timeout")
    # On a timeout the caller's actual wait is what the record reports.
    assert record["elapsed_us"] >= 50_000


def test_a_raising_callee_under_bound_runtime_is_recorded_as_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sink: Path
) -> None:
    guards = load_guards(tmp_path, monkeypatch, str(sink))

    @guards["bound_runtime"](2.0)
    def broken() -> str:
        message = "upstream failed"
        raise RuntimeError(message)

    with pytest.raises(RuntimeError):
        broken()

    record = only_record(sink)
    assert (record["outcome"], record["reason"]) == ("error", "tool_error")


def test_a_completed_call_under_bound_runtime_excludes_the_tool_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sink: Path
) -> None:
    guards = load_guards(tmp_path, monkeypatch, str(sink))

    @guards["bound_runtime"](2.0)
    def takes_a_while() -> str:
        time.sleep(0.2)
        return "done"

    assert takes_a_while() == "done"

    record = only_record(sink)
    assert (record["outcome"], record["reason"]) == ("allowed", "checked")
    # elapsed_us is the guard's own cost; the 200 ms the tool spent is excluded.
    assert record["elapsed_us"] < 150_000


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        ("Error executing tool: permission denied", ("error", "tool_error")),
        ("ok", ("allowed", "checked")),
    ],
)
def test_error_channel_decisions_are_recorded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    sink: Path,
    result: str,
    expected: tuple[str, str],
) -> None:
    guards = load_guards(tmp_path, monkeypatch, str(sink))

    @guards["raise_on_tool_error"]
    def tool() -> str:
        return result

    try:
        tool()
    except guards["ToolCallError"]:
        pass

    record = only_record(sink)
    assert (record["outcome"], record["reason"]) == expected


def test_a_no_terminal_refusal_is_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sink: Path
) -> None:
    guards = load_guards(tmp_path, monkeypatch, str(sink))
    monkeypatch.setattr(sys, "stdin", _NoTerminal())

    @guards["require_approval"]("declared destructive")
    def delete_rows() -> str:
        return "deleted"

    with pytest.raises(PermissionError):
        delete_rows()

    record = only_record(sink)
    assert (record["outcome"], record["reason"]) == ("refused", "no_tty")


def test_the_approval_override_is_recorded_as_such(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sink: Path
) -> None:
    # The branch Study 3 timed without noticing. In a deployed agent, a call
    # that went through because the override was set must be distinguishable
    # from one a human approved.
    guards = load_guards(tmp_path, monkeypatch, str(sink))
    monkeypatch.setenv("TOOLSEAL_ASSUME_YES", "1")

    @guards["require_approval"]("declared destructive")
    def delete_rows() -> str:
        return "deleted"

    assert delete_rows() == "deleted"

    record = only_record(sink)
    assert (record["outcome"], record["reason"]) == ("allowed", "approval_override")


def test_a_reason_outside_the_vocabulary_is_a_programming_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sink: Path
) -> None:
    guards = load_guards(tmp_path, monkeypatch, str(sink))

    with pytest.raises(ValueError, match="vibes"):
        guards["_record"]("restrict_egress", "fetch", "allowed", "vibes", 0.0)


# --- what a record must never contain ---------------------------------------


def test_argument_values_never_reach_the_sink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sink: Path
) -> None:
    guards = load_guards(tmp_path, monkeypatch, str(sink))
    secret = "sk-live-never-in-evidence-0123456789"  # noqa: S105  # toolseal:allow A1 - must never reach the sink

    @guards["restrict_egress"](["api.allowed.invalid"])
    def fetch(url: str, token: str) -> str:
        return "ok"

    @guards["validate_against_schema"]({"properties": {"token": {"maxLength": 4}}})
    def check(token: str) -> str:
        return token

    @guards["raise_on_tool_error"]
    def echo(token: str) -> str:
        return f"Error executing tool: {token}"

    @guards["bound_runtime"](1.0)
    def wait(token: str) -> str:
        return token

    fetch(url="https://api.allowed.invalid/v1", token=secret)
    with pytest.raises(guards["SchemaViolationError"]):
        check(token=secret)
    with pytest.raises(guards["ToolCallError"]):
        echo(token=secret)
    wait(token=secret)

    assert len(records(sink)) == 4
    assert secret not in sink.read_text(encoding="utf-8")


# --- the sink --------------------------------------------------------------


def test_off_writes_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guards = load_guards(tmp_path, monkeypatch, "off")

    @guards["raise_on_tool_error"]
    def tool() -> str:
        return "ok"

    tool()

    assert not (tmp_path / ".toolseal").exists()


def test_a_dash_writes_to_stderr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    guards = load_guards(tmp_path, monkeypatch, "-")

    @guards["raise_on_tool_error"]
    def tool() -> str:
        return "ok"

    tool()

    record = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
    assert record["guard"] == "raise_on_tool_error"


def test_the_default_sink_sits_next_to_guards_py(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guards = load_guards(tmp_path, monkeypatch, None)

    @guards["raise_on_tool_error"]
    def tool() -> str:
        return "ok"

    tool()

    assert only_record(tmp_path / ".toolseal" / "evidence.jsonl")["guard"] == "raise_on_tool_error"


def test_rotation_limits() -> None:
    namespace: dict[str, Any] = {"__name__": "limits"}
    exec(  # noqa: S102
        compile(GUARDS_PY.substitute(project_name="x", package_name="x"), "guards.py", "exec"),
        namespace,
    )
    assert namespace["EVIDENCE_MAX_BYTES"] == 5_000_000
    assert namespace["EVIDENCE_BACKUPS"] == 3


# --- a broken sink ---------------------------------------------------------


@pytest.fixture
def broken_sink(tmp_path: Path) -> Path:
    # A regular file where a directory is needed: the sink cannot be created.
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("", encoding="utf-8")
    return blocker / "evidence.jsonl"


def test_an_unwritable_sink_warns_once_and_calls_still_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    broken_sink: Path,
) -> None:
    guards = load_guards(tmp_path, monkeypatch, str(broken_sink))

    @guards["raise_on_tool_error"]
    def tool() -> str:
        return "ok"

    assert [tool() for _ in range(5)] == ["ok"] * 5

    assert capsys.readouterr().err.count("evidence not recorded") == 1


def test_a_refusal_is_still_enforced_when_the_sink_is_broken(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, broken_sink: Path
) -> None:
    guards = load_guards(tmp_path, monkeypatch, str(broken_sink))

    @guards["restrict_egress"](["api.allowed.invalid"])
    def fetch(url: str) -> str:
        return "reached"

    with pytest.raises(guards["EgressPolicyError"]):
        fetch(url="https://exfil.invalid/upload")
