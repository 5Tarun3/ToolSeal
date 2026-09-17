"""The Study 6 runner: its preconditions and its shape, never its verdict.

These tests deliberately do not assert that observed outcomes match the
registered expectations. That match *is* H4, a research result; pinning it in
CI would turn a finding into a gate, and a falsified H4 would then fail the
build and invite someone to "fix" the expectation. What is pinned instead is
everything that makes the result trustworthy: the right suite, no override,
a fixture for every case, outcomes in the registered vocabulary, and a report
that never collapses the study into a single ratio.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from bench.attack_suite import ATTACK_OUTCOMES, BENIGN_OUTCOMES, PROTOCOL_PATH, SUITE_PATH, load
from bench.study6 import (
    FIXTURES,
    CaseResult,
    StudyError,
    check_preconditions,
    h4,
    run_protection,
    to_markdown,
)


def test_every_registered_case_has_exactly_one_fixture() -> None:
    assert set(FIXTURES) == {case.id for case in load()}


def test_the_runner_refuses_under_the_approval_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TOOLSEAL_ASSUME_YES", "1")

    with pytest.raises(StudyError, match="TOOLSEAL_ASSUME_YES"):
        check_preconditions()


def test_the_runner_refuses_a_suite_that_is_not_the_registered_one(tmp_path: Path) -> None:
    tampered = tmp_path / "attack-suite.toml"
    shutil.copyfile(SUITE_PATH, tampered)
    with tampered.open("a", encoding="utf-8") as handle:
        handle.write("\n# edited after registration\n")

    with pytest.raises(StudyError, match="digest"):
        check_preconditions(tampered, PROTOCOL_PATH)


def test_the_registered_suite_passes_the_preconditions(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TOOLSEAL_ASSUME_YES", raising=False)

    check_preconditions()


@pytest.fixture(scope="module")
def protection_run(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, tuple[CaseResult, ...]]:
    # One run shared by the shape tests: BR-01 alone waits out a 3 s tool.
    work = tmp_path_factory.mktemp("study6")
    return work, run_protection(work)


def test_a_protection_run_covers_every_case_in_the_vocabulary(
    protection_run: tuple[Path, tuple[CaseResult, ...]],
) -> None:
    _, results = protection_run
    cases = {case.id: case for case in load()}

    assert len(results) == len(cases)
    for result in results:
        vocabulary = ATTACK_OUTCOMES if result.kind == "attack" else BENIGN_OUTCOMES
        assert result.observed in vocabulary
        assert result.expected == cases[result.id].expected_decorator


def test_a_protection_run_leaves_evidence(
    protection_run: tuple[Path, tuple[CaseResult, ...]],
) -> None:
    # The run measures a project as it ships, and a shipped project records
    # its guard decisions. An empty evidence log would mean the run was not
    # measuring the shipped configuration.
    work, _ = protection_run
    evidence = work / "evidence.jsonl"
    assert evidence.is_file(), "no evidence file was written during the protection run"
    assert evidence.read_text(encoding="utf-8").strip()


def test_h4_reports_every_mismatch_rather_than_a_bare_verdict(
    protection_run: tuple[Path, tuple[CaseResult, ...]],
) -> None:
    _, results = protection_run
    verdict = h4(results)

    assert verdict["cases"] == len(load())
    assert verdict["supported"] is (not verdict["mismatches"])


def test_the_report_never_publishes_a_single_ratio() -> None:
    payload = {
        "platform": {
            "os": "X", "release": "1", "python": "3", "runner": "local", "toolseal_commit": "c",
        },
        "suite_sha256": "0" * 64,
        "hypotheses": {
            "H1": "open", "H2": "open", "H3": "open",
            "H4": {"supported": True, "cases": 0, "mismatches": []},
        },
        "rates": {},
        "latency": {"evidence_on (shipped default, primary)": {}, "evidence_off": {}},
        "cases": [],
    }  # fmt: skip

    report = to_markdown(payload).lower()

    assert "per millisecond" not in report.replace("security per millisecond:", "")
    assert "x cheaper" not in report
    assert "h1-h3 are open" in report


def test_latency_covers_every_guard_on_the_paths_the_protocol_defines(tmp_path: Path) -> None:
    from bench.attack_suite import GUARDS
    from bench.study6 import measure_latency

    # Tiny repeat counts: this checks the shape of the result, not the numbers.
    points = measure_latency(True, tmp_path, micro_repeats=5, milli_repeats=3)

    assert set(points) == set(GUARDS)
    for guard, entry in points.items():
        assert {"enforcing", "allowing"} <= set(entry), guard
    # The allowing path the protocol cannot reach is stated, not silently absent.
    assert isinstance(points["require_approval"]["allowing"], str)
    assert "override" in points["require_approval"]["allowing"]
    # bound_runtime's enforcing path is reported as overshoot past the bound.
    assert "overshoot" in points["bound_runtime"]["enforcing"]["measure"]
    for guard in ("restrict_egress", "validate_against_schema", "raise_on_tool_error", "redact"):
        for path in ("enforcing", "allowing"):
            summary = points[guard][path]
            assert {"repeats", "median_us", "p95_us", "p99_us"} <= set(summary), (guard, path)


def test_latency_never_runs_under_the_approval_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from bench.study6 import measure_latency

    # Even if the caller's environment carries the override, the measurement
    # clears it for its duration, and restores the caller's value afterwards.
    monkeypatch.setenv("TOOLSEAL_ASSUME_YES", "1")
    seen: list[str | None] = []

    import bench.study6 as study6

    real = study6._paired

    def spy(*args: object, **kwargs: object) -> dict[str, float | int]:
        import os

        seen.append(os.environ.get("TOOLSEAL_ASSUME_YES"))
        return real(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(study6, "_paired", spy)
    measure_latency(False, tmp_path, micro_repeats=2, milli_repeats=2)

    assert seen
    assert set(seen) == {None}
    import os

    assert os.environ.get("TOOLSEAL_ASSUME_YES") == "1"


def test_a_run_releases_its_evidence_file(tmp_path: Path) -> None:
    # On Windows an open file cannot be deleted, so a run that kept its sink
    # open crashed when its temporary directory was cleaned up.
    from bench.study6 import measure_latency

    measure_latency(True, tmp_path, micro_repeats=2, milli_repeats=2)

    for evidence in tmp_path.glob("latency-evidence-*.jsonl"):
        evidence.unlink()  # raises PermissionError on Windows if still open
    assert not list(tmp_path.glob("latency-evidence-*.jsonl"))


def test_bound_runtime_reports_an_exploratory_control(tmp_path: Path) -> None:
    from bench.study6 import measure_latency

    points = measure_latency(False, tmp_path, micro_repeats=2, milli_repeats=3)

    control = points["bound_runtime"]["enforcing_net_of_control"]
    assert "exploratory" in control["measure"]
    # The registered overshoot figure is still reported beside it, unchanged.
    assert "overshoot" in points["bound_runtime"]["enforcing"]["measure"]


def test_the_report_explains_what_the_numbers_mean(tmp_path: Path) -> None:
    from bench.study6 import measure_latency

    on = measure_latency(True, tmp_path, micro_repeats=20, milli_repeats=3)
    off = measure_latency(False, tmp_path, micro_repeats=20, milli_repeats=3)
    payload = {
        "platform": {
            "os": "X", "release": "1", "python": "3", "runner": "local", "toolseal_commit": "c",
        },
        "suite_sha256": "0" * 64,
        "hypotheses": {
            "H1": "open", "H2": "open", "H3": "open",
            "H4": {"supported": True, "cases": 0, "mismatches": []},
        },
        "rates": {},
        "latency": {"evidence_on (shipped default, primary)": on, "evidence_off": off},
        "cases": [],
    }  # fmt: skip

    report = to_markdown(payload)

    assert "## Reading these numbers" in report
    assert "dict(os.environ)" in report
    assert "exploratory" in report
