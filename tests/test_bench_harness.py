"""The Study 2 harness.

An evaluation harness that flatters its own tool is worse than no harness, so
the tests here are mostly about the guards against that: the adverse-task
requirement, the refusal to fabricate a baseline, and the fact that per-task
figures always survive into the report.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from bench.baseline import build as build_baseline
from bench.baseline import materialise
from bench.harness import (
    TASKS,
    TOOLSEAL_STEPS,
    Task,
    run,
    run_manual,
    run_toolseal,
    to_dict,
    to_markdown,
    write,
)

from toolseal.core.audit import audit


def test_task_set_contains_adverse_cases() -> None:
    # The protocol requires them. Without at least one, the benchmark measures
    # only the cases the tool was built for.
    assert any(task.adverse for task in TASKS)


def test_run_refuses_a_task_set_with_no_adverse_cases(tmp_path: Path) -> None:
    favourable = (Task("easy", "ollama", "langgraph", "the happy path"),)

    with pytest.raises(ValueError, match="no adverse cases"):
        run(tmp_path, favourable)


def test_adverse_flag_is_declared_on_the_task(tmp_path: Path) -> None:
    # Recorded up front rather than decided at reporting time, so an
    # inconvenient result cannot be reclassified afterwards.
    adverse = [task for task in TASKS if task.adverse]

    assert adverse
    assert all(task.adverse is True for task in adverse)


# --- the manual baseline ---------------------------------------------------


def test_baseline_reproduces_the_insecure_quickstart_defaults(tmp_path: Path) -> None:
    baseline = build_baseline("openai", "langgraph")
    materialise(baseline, tmp_path)

    report = audit(tmp_path)
    failing = {finding.check_id for finding in report.findings}

    # A pasted key, an unpinned requirement set, an unbounded filesystem tool
    # and a shell tool. These are what the official pages actually show.
    assert "A1" in failing
    assert "C1" in failing
    assert report.blocking


def test_ollama_baseline_has_no_credential_finding(tmp_path: Path) -> None:
    # Ollama needs no key, so the manual arm is genuinely less bad here. A
    # baseline that reported A1 anyway would be inflating the comparison.
    materialise(build_baseline("ollama", "langgraph"), tmp_path)

    assert "A1" not in {f.check_id for f in audit(tmp_path).findings}


def test_baseline_refuses_a_framework_it_has_no_template_for() -> None:
    # Producing a CrewAI project and labelling it AutoGen would put a fabricated
    # data point into the study.
    with pytest.raises(KeyError, match="no baseline template"):
        build_baseline("ollama", "autogen")


def test_manual_arm_reports_a_missing_template_as_a_harness_limit(tmp_path: Path) -> None:
    result = run_manual(Task("x", "ollama", "autogen", "unsupported"), tmp_path)

    assert not result.succeeded
    assert "no baseline template" in result.note
    assert result.audit_score is None


# --- the toolseal arm ------------------------------------------------------


def test_toolseal_arm_produces_a_clean_project(tmp_path: Path) -> None:
    result = run_toolseal(Task("x", "ollama", "langgraph", "supported"), tmp_path)

    assert result.succeeded
    assert result.audit_score == 100
    assert result.hand_written_files == 0
    assert result.manual_steps == TOOLSEAL_STEPS


def test_toolseal_arm_records_a_refusal_rather_than_crashing(tmp_path: Path) -> None:
    result = run_toolseal(Task("x", "gemini", "langgraph", "unsupported"), tmp_path)

    assert not result.succeeded
    assert "gemini" in result.note


# --- reporting -------------------------------------------------------------


def test_report_keeps_every_task_separately(tmp_path: Path) -> None:
    payload = to_dict(run(tmp_path))

    assert len(payload["tasks"]) == len(TASKS)
    assert {t["id"] for t in payload["tasks"]} == {task.id for task in TASKS}


def test_aggregate_excludes_tasks_that_did_not_produce_both_arms(tmp_path: Path) -> None:
    # An adverse task where one arm refused has no comparable score, and
    # counting it as zero would understate the manual arm.
    payload = to_dict(run(tmp_path))

    comparable = [t for t in payload["tasks"] if t["score_delta"] is not None]
    assert len(comparable) < payload["aggregate"]["tasks_total"]


def test_markdown_states_the_manual_arm_is_idealised(tmp_path: Path) -> None:
    # The single most important caveat in the study. If it ever falls out of the
    # rendered report, the numbers read as stronger than they are.
    text = to_markdown(to_dict(run(tmp_path)))

    assert "idealised" in text
    assert "conservative" in text


def test_markdown_marks_adverse_tasks(tmp_path: Path) -> None:
    text = to_markdown(to_dict(run(tmp_path)))

    assert "adverse" in text


def test_write_emits_both_artifacts(tmp_path: Path) -> None:
    results = run(tmp_path / "work")
    out = tmp_path / "out"

    write(results, out)

    payload = json.loads((out / "results.json").read_text(encoding="utf-8"))
    assert payload["tasks"]
    assert (out / "RESULTS.md").read_text(encoding="utf-8").startswith("# Study 2")


def test_toolseal_outscores_the_baseline_on_every_supported_cell(tmp_path: Path) -> None:
    # The headline claim, asserted rather than eyeballed. If a future change
    # made a scaffolded project worse than a quickstart, this fails.
    for result in run(tmp_path):
        if result.score_delta is None:
            continue
        assert result.score_delta > 0, result.task.id
