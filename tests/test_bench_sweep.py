"""The P3 sweep harness, and specifically its redaction.

`bench/sweep.py` writes files that are committed to a public repository, so
whatever a probed server leaks into them gets published. `redact()` exists to
prevent that, and for the whole of its first life it was defined, documented
and never called - the committed captures only looked clean because someone
had scrubbed them by hand.

So the tests that matter here are not "can `redact` redact". They are "is the
file on disk redacted", which is the property the repository actually needs and
the one whose absence went unnoticed.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from bench import sweep
from bench.mcp_probe import ProbeResult

# A tool description carrying both leak shapes the harness knows about: an
# absolute path under the operator's home, and mcp-server-time's habit of
# baking the machine's IANA zone into text a model reads.
LEAKY_TOOL: dict[str, Any] = {
    "name": "leaky",
    "description": (
        "Reads {home}/secrets. Use 'Antarctica/Troll' as local timezone if no timezone provided."
    ),
    "inputSchema": {"type": "object", "properties": {}},
}


def _leaky_tools() -> list[dict[str, Any]]:
    tool = dict(LEAKY_TOOL)
    tool["description"] = str(tool["description"]).format(home=Path.home())
    return [tool]


@pytest.fixture
def sweep_into(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Point the sweep's output at a temp directory and stub the probing."""
    results = tmp_path / "results"
    monkeypatch.setattr(sweep, "RESULTS", results)
    # Never start a real server from a unit test, and never let the container
    # check shell out either - `docker info` takes seconds and its answer
    # would make these tests depend on whether Docker happens to be running.
    monkeypatch.setattr(sweep, "container_runtime", lambda: None)

    def fake_run(launch: sweep.Launch, **_kwargs: object) -> tuple[ProbeResult, int]:
        return ProbeResult(server_id=launch.entry_id, ok=True, tools=_leaky_tools()), 1

    monkeypatch.setattr(sweep, "run", fake_run)
    yield results


def test_the_written_capture_is_redacted(sweep_into: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.argv", ["sweep.py", "--only", "time"])
    assert sweep.main() == 0

    raw = (sweep_into / "time-tools.json").read_text(encoding="utf-8")
    assert str(Path.home()) not in raw
    assert "Antarctica/Troll" not in raw
    assert "<HOME>" in raw
    assert "<LOCAL_TZ>" in raw


def test_the_written_summary_is_redacted(sweep_into: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A *failing* server's stderr tail is the summary's real leak.

    The per-server capture only exists when a server answered, so the path
    that publishes a traceback - full of `<HOME>\\AppData\\...` frames from the
    throwaway workspace - is this one. Stubbing a success here would write an
    empty `stderr_tail` and the test would pass whether or not `redact` was
    ever called, which is the exact failure mode that let the real defect
    survive.
    """

    def fake_failure(launch: sweep.Launch, **_kwargs: object) -> tuple[ProbeResult, int]:
        return (
            ProbeResult(
                server_id=launch.entry_id,
                ok=False,
                error="no response to initialize",
                stderr_tail=f'  File "{Path.home()}\\AppData\\Local\\Temp\\x\\server.py", line 1',
            ),
            3,
        )

    monkeypatch.setattr(sweep, "run", fake_failure)
    monkeypatch.setattr("sys.argv", ["sweep.py"])
    assert sweep.main() == 0

    raw = (sweep_into / "summary.json").read_text(encoding="utf-8")
    assert "<HOME>" in raw, "the leak fixture never reached the summary"
    assert str(Path.home()) not in raw
    assert Path.home().name not in raw


def test_redaction_survives_a_username_inside_its_own_home_path() -> None:
    # `_redactions` sorts longest-first so the home directory is replaced
    # before the username nested inside it. Reversed, this leaves a
    # half-redacted path like `C:\Users\<USER>\AppData` behind.
    text = f"{Path.home()}\\AppData\\Local"
    assert Path.home().name not in sweep.redact(text)


def test_the_timezone_sentence_is_matched_by_shape_not_by_value() -> None:
    # Python cannot portably report the host's IANA zone, so the rule matches
    # the sentence mcp-server-time generates rather than any particular zone.
    # A zone this host will never be in still has to be caught.
    assert "Antarctica/Troll" not in sweep.redact(
        "Use 'Antarctica/Troll' as local timezone if no timezone provided."
    )


def test_a_capability_with_no_launch_is_an_error_not_an_empty_sweep(
    sweep_into: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A typo in `--only` that silently enumerated nothing would look exactly
    # like a sweep in which every server failed.
    monkeypatch.setattr("sys.argv", ["sweep.py", "--only", "no-such-capability"])
    assert sweep.main() == 1


def test_only_does_not_overwrite_the_full_summary(
    sweep_into: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Regression guard for harness defect 2: a one-server run replacing an
    # all-server summary with a file of identical shape.
    sweep_into.mkdir(parents=True, exist_ok=True)
    (sweep_into / "summary.json").write_text('{"servers": "full run"}', encoding="utf-8")

    monkeypatch.setattr("sys.argv", ["sweep.py", "--only", "time"])
    assert sweep.main() == 0

    kept = json.loads((sweep_into / "summary.json").read_text(encoding="utf-8"))
    assert kept == {"servers": "full run"}


def test_a_server_named_by_env_is_skipped_with_a_reason_when_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # `pixel-mcp` ships only as a GitHub release binary, so it is reached
    # through `executable_env` rather than PATH. On a machine without it, the
    # skip must say how to supply it rather than read as a server failure.
    launch = sweep.Launch(
        "pixel-art-local",
        "mcp/io.github.willibrandon/pixel-mcp@0.5.0",
        ("pixel-mcp",),
        executable_env="TOOLSEAL_PIXEL_MCP",
    )
    monkeypatch.delenv("TOOLSEAL_PIXEL_MCP", raising=False)

    resolved, why_not = sweep._executable(launch)
    assert resolved is None
    assert "TOOLSEAL_PIXEL_MCP" in why_not


def test_the_pixel_mcp_config_carries_no_credential(tmp_path: Path) -> None:
    # The config hook exists for non-secret startup configuration only. If a
    # future edit taught it to pass a token, this is the test that should fail.
    sweep._pixel_mcp_config(tmp_path)
    written = json.loads(
        (tmp_path / ".config" / "pixel-mcp" / "config.json").read_text(encoding="utf-8")
    )
    assert set(written) == {"aseprite_path", "temp_dir", "timeout", "log_level"}
