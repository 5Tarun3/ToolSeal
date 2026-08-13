"""Study 2: the with/without measurement.

The same procedure produces both results the project needs. Each task is set up
twice - once as an idealised manual run, once with `toolseal init` - and both
arms are measured on the same axes:

* **developer experience** - manual steps, files written by hand, wall clock
* **security posture** - the audit score of what each arm produced

Running one experiment for both is not a shortcut. It is why a four-study
evaluation fits the schedule at all, and it means the demo and the paper cannot
drift apart: the number on stage is the number in the table.

Three things are deliberate about how this reports.

**The manual arm is idealised.** No mistakes, no debugging, no re-reading. That
makes it a lower bound on manual effort, so the measured advantage is
conservative rather than flattering.

**Adverse tasks are mandatory.** `TASKS` includes cases toolseal handles badly,
and :func:`run` refuses to produce a report without them. A benchmark composed
only of favourable cases measures nothing, and the temptation to quietly drop
the awkward ones is exactly what pre-registration exists to prevent.

**Per-task results are always emitted.** An aggregate that hides one dominant
task is worse than no aggregate.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Final

from bench.baseline import build as build_baseline
from bench.baseline import materialise
from toolseal.core.adapters import ScaffoldSpec
from toolseal.core.audit import audit
from toolseal.core.scaffold import apply_plan, build_plan

# Steps a `toolseal init` run costs the developer: read the docs once, run one
# command. Counted the same way as the manual arm so the comparison is like for
# like.
TOOLSEAL_STEPS: Final = 2


@dataclass(frozen=True)
class Task:
    """One setup task, run in both conditions."""

    id: str
    provider_id: str
    framework_id: str
    description: str
    adverse: bool = False
    """Whether toolseal is expected to do badly here.

    Recorded on the task rather than decided at reporting time, so an
    inconvenient result cannot be reclassified after the fact.
    """


TASKS: Final[tuple[Task, ...]] = (
    Task("ollama-langgraph", "ollama", "langgraph", "Local model, LangGraph agent"),
    Task("ollama-crewai", "ollama", "crewai", "Local model, CrewAI crew"),
    Task("openai-langgraph", "openai", "langgraph", "Hosted OpenAI, LangGraph agent"),
    Task("openai-crewai", "openai", "crewai", "Hosted OpenAI, CrewAI crew"),
    Task("anthropic-langgraph", "anthropic", "langgraph", "Hosted Anthropic, LangGraph agent"),
    Task("anthropic-crewai", "anthropic", "crewai", "Hosted Anthropic, CrewAI crew"),
    # --- adverse cases, required by the protocol ---------------------------
    Task(
        "adverse-unsupported-framework",
        "ollama",
        "autogen",
        "A framework toolseal does not support: the manual arm succeeds and "
        "toolseal cannot help at all",
        adverse=True,
    ),
    Task(
        "adverse-unsupported-provider",
        "cohere",
        "langgraph",
        "A provider toolseal does not support: same shape, other axis",
        adverse=True,
    ),
)


@dataclass
class ArmResult:
    """What one condition produced for one task."""

    arm: str
    succeeded: bool
    manual_steps: int = 0
    hand_written_files: int = 0
    seconds: float = 0.0
    audit_score: int | None = None
    blocking: bool | None = None
    findings: list[str] = field(default_factory=list)
    note: str = ""


@dataclass
class TaskResult:
    task: Task
    manual: ArmResult
    toolseal: ArmResult

    @property
    def step_delta(self) -> int | None:
        if not (self.manual.succeeded and self.toolseal.succeeded):
            return None
        return self.manual.manual_steps - self.toolseal.manual_steps

    @property
    def score_delta(self) -> int | None:
        if self.manual.audit_score is None or self.toolseal.audit_score is None:
            return None
        return self.toolseal.audit_score - self.manual.audit_score


def _audit_into(result: ArmResult, root: Path) -> ArmResult:
    report = audit(root)
    result.audit_score = report.score
    result.blocking = report.blocking
    result.findings = sorted({finding.check_id for finding in report.findings})
    return result


def run_manual(task: Task, root: Path) -> ArmResult:
    """The idealised manual arm: the official quickstart, performed perfectly."""
    started = time.perf_counter()
    try:
        baseline = build_baseline(task.provider_id, task.framework_id)
    except Exception as exc:
        return ArmResult(
            arm="manual",
            succeeded=False,
            seconds=time.perf_counter() - started,
            # A harness limitation, not a finding about manual setup: a
            # developer could follow this framework's docs perfectly well.
            note=f"no baseline template authored ({exc})",
        )

    materialise(baseline, root)
    result = ArmResult(
        arm="manual",
        succeeded=True,
        manual_steps=baseline.manual_steps,
        hand_written_files=baseline.hand_written_files,
        seconds=time.perf_counter() - started,
        note="idealised: no mistakes, no debugging",
    )
    return _audit_into(result, root)


def run_toolseal(task: Task, root: Path) -> ArmResult:
    """The toolseal arm: one command."""
    started = time.perf_counter()
    try:
        apply_plan(
            build_plan(
                ScaffoldSpec(
                    project_name="bench",
                    provider_id=task.provider_id,
                    framework_id=task.framework_id,
                    workspace_root=root,
                )
            )
        )
    except Exception as exc:
        return ArmResult(
            arm="toolseal",
            succeeded=False,
            seconds=time.perf_counter() - started,
            note=f"{type(exc).__name__}: {exc}",
        )

    result = ArmResult(
        arm="toolseal",
        succeeded=True,
        manual_steps=TOOLSEAL_STEPS,
        hand_written_files=0,
        seconds=time.perf_counter() - started,
    )
    return _audit_into(result, root)


def run(workspace: Path, tasks: tuple[Task, ...] = TASKS) -> list[TaskResult]:
    """Run every task in both conditions under *workspace*.

    Refuses a task set with no adverse cases: a benchmark of only favourable
    tasks measures nothing, and dropping the awkward ones is the failure mode
    pre-registration exists to prevent.
    """
    if not any(task.adverse for task in tasks):
        message = (
            "refusing to run: the task set contains no adverse cases. "
            "The protocol requires at least one task toolseal handles badly."
        )
        raise ValueError(message)

    results = []
    for task in tasks:
        manual = run_manual(task, workspace / task.id / "manual")
        seal = run_toolseal(task, workspace / task.id / "toolseal")
        results.append(TaskResult(task=task, manual=manual, toolseal=seal))
    return results


def to_dict(results: list[TaskResult]) -> dict[str, Any]:
    """The machine-readable result. Per-task first; aggregates are derived."""
    comparable = [r for r in results if r.score_delta is not None]

    return {
        "study": "S2 with/without",
        "manual_arm": "idealised quickstart; lower bound on manual effort",
        "tasks": [
            {
                "id": r.task.id,
                "description": r.task.description,
                "adverse": r.task.adverse,
                "manual": asdict(r.manual),
                "toolseal": asdict(r.toolseal),
                "step_delta": r.step_delta,
                "score_delta": r.score_delta,
            }
            for r in results
        ],
        "aggregate": {
            "tasks_total": len(results),
            "tasks_adverse": sum(1 for r in results if r.task.adverse),
            "toolseal_succeeded": sum(1 for r in results if r.toolseal.succeeded),
            "manual_succeeded": sum(1 for r in results if r.manual.succeeded),
            "mean_score_manual": (
                round(sum(r.manual.audit_score or 0 for r in comparable) / len(comparable), 1)
                if comparable
                else None
            ),
            "mean_score_toolseal": (
                round(sum(r.toolseal.audit_score or 0 for r in comparable) / len(comparable), 1)
                if comparable
                else None
            ),
            "manual_blocking": sum(1 for r in comparable if r.manual.blocking),
            "toolseal_blocking": sum(1 for r in comparable if r.toolseal.blocking),
        },
    }


def to_markdown(payload: dict[str, Any]) -> str:
    """A table a reader can check against the JSON beside it."""
    aggregate = payload["aggregate"]
    lines = [
        "# Study 2 - with/without setup comparison",
        "",
        f"Manual arm: {payload['manual_arm']}.",
        "Any advantage shown here is therefore a conservative estimate.",
        "",
        "| task | adverse | manual steps | toolseal steps | manual score | toolseal score |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for task in payload["tasks"]:
        manual, seal = task["manual"], task["toolseal"]
        lines.append(
            f"| `{task['id']}` | {'yes' if task['adverse'] else ''} "
            f"| {manual['manual_steps'] if manual['succeeded'] else 'n/a'} "
            f"| {seal['manual_steps'] if seal['succeeded'] else 'refused'} "
            f"| {manual['audit_score'] if manual['audit_score'] is not None else 'n/a'} "
            f"| {seal['audit_score'] if seal['audit_score'] is not None else 'n/a'} |"
        )

    lines += [
        "",
        "## Aggregate",
        "",
        f"- Tasks: {aggregate['tasks_total']} ({aggregate['tasks_adverse']} adverse)",
        f"- Mean audit score, manual: {aggregate['mean_score_manual']}",
        f"- Mean audit score, toolseal: {aggregate['mean_score_toolseal']}",
        f"- Projects with a critical finding, manual: {aggregate['manual_blocking']}",
        f"- Projects with a critical finding, toolseal: {aggregate['toolseal_blocking']}",
        "",
        "Per-task figures are above and in `results.json`. An aggregate that hides",
        "one dominant task is worse than no aggregate.",
    ]
    return "\n".join(lines) + "\n"


def write(results: list[TaskResult], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = to_dict(results)
    (out_dir / "results.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8", newline="\n"
    )
    (out_dir / "RESULTS.md").write_text(to_markdown(payload), encoding="utf-8", newline="\n")
