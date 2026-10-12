"""Study 4's scoring, tested without any adapter installed.

The adapters live in the `research` dependency group, so CI never has them.
What can silently fabricate a result is the scoring - schema flattening, the
verdict rules, the loss-rate denominator - and that is pure, so it is tested
here against hand-built inputs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from bench import study4
from bench.study4 import (
    DROPPED,
    MUTATED,
    PRESERVED,
    UNKNOWN,
    Finding,
    Outcome,
    Translated,
    Unit,
    behaviour,
    compare,
    flatten,
    lattice_agreement,
    loss_rates,
)

NESTED: dict[str, Any] = {
    "$defs": {
        "Reporter": {
            "properties": {
                "email": {"pattern": "^x$", "maxLength": 64},
                "team": {"enum": ["a", "b"]},
            },
            "required": ["email", "team"],
        }
    },
    "properties": {
        "reporter": {"$ref": "#/$defs/Reporter"},
        "assignee": {
            "anyOf": [{"maxLength": 32, "type": "string"}, {"type": "null"}],
            "default": None,
        },
        "tags": {"items": {"enum": ["p"]}, "maxItems": 3},
    },
    "required": ["reporter"],
}


def _unit(unit_id: str = "u", abstraction: str | None = None) -> Unit:
    return Unit(id=unit_id, route="r", abstraction=abstraction, packages=(), open=None)  # type: ignore[arg-type]


def test_flatten_resolves_refs_and_reads_nested_constraints() -> None:
    facts = flatten(NESTED)

    assert facts["reporter.email.pattern"] == "^x$"
    assert facts["reporter.team.enum"] == ["a", "b"]
    assert facts["required:reporter"] == ["email", "team"]
    assert facts["required:<root>"] == ["reporter"]


def test_flatten_reads_a_nullable_fields_constraint_from_its_branch() -> None:
    assert flatten(NESTED)["assignee.maxLength"] == 32


def test_flatten_reads_array_items_and_array_level_keywords() -> None:
    facts = flatten(NESTED)

    assert facts["tags[].enum"] == ["p"]
    assert facts["tags.maxItems"] == 3


def test_an_unresolvable_ref_is_recorded_not_skipped() -> None:
    # Skipping it would make a schema that lost its definitions look like one
    # with nothing to lose.
    facts = flatten({"properties": {"x": {"$ref": "#/$defs/Missing"}}})

    assert facts["x.$ref"] == "unresolvable"


def _truth() -> dict[str, dict[str, Any]]:
    return {
        "t": {
            "name": "t",
            "description": "Do the thing.",
            "inputSchema": NESTED,
            "annotations": {"destructiveHint": True, "title": "T"},
        }
    }


def test_identical_translation_is_preserved_throughout() -> None:
    translated = [
        Translated(
            "t", "Do the thing.", NESTED, {"destructiveHint": True, "title": "T"}, "metadata"
        )
    ]

    findings = compare(_unit(), _truth(), translated)

    assert findings
    assert {f.verdict for f in findings} == {PRESERVED}


def test_a_lost_nested_constraint_is_dropped() -> None:
    schema = {
        "properties": {"reporter": {"properties": {"email": {}, "team": {"enum": ["a", "b"]}}}},
        "required": ["reporter"],
    }
    translated = [Translated("t", "Do the thing.", schema, {})]

    verdicts = {f.prop: f.verdict for f in compare(_unit(), _truth(), translated)}

    assert verdicts["constraint.reporter.email.pattern"] == DROPPED
    assert verdicts["annotation.destructiveHint"] == DROPPED


def test_a_requirement_the_adapter_added_is_a_mutation() -> None:
    # openai-agents' strict mode makes optional fields required.
    schema = {**NESTED, "required": ["reporter", "assignee"]}
    translated = [Translated("t", "Do the thing.", schema, {})]

    verdicts = {f.prop: f.verdict for f in compare(_unit(), _truth(), translated)}

    assert verdicts["required.required:<root>"] == MUTATED


def test_a_wrapped_description_is_mutated_and_a_replaced_one_dropped() -> None:
    wrapped = [Translated("t", "Tool Name: t\nDo the thing.", NESTED, {})]
    replaced = [Translated("t", "Something else.", NESTED, {})]

    wrapped_verdict = {f.prop: f.verdict for f in compare(_unit(), _truth(), wrapped)}
    replaced_verdict = {f.prop: f.verdict for f in compare(_unit(), _truth(), replaced)}

    assert wrapped_verdict["description"] == MUTATED
    assert replaced_verdict["description"] == DROPPED


def test_labels_score_a_hint_as_mutated_only_for_the_labelling_unit() -> None:
    translated = [Translated("t", "Do the thing.", NESTED, {}, extra={"labels": {"x": 1}})]

    labelled = compare(_unit("af (FIDES labels)"), _truth(), translated)
    plain = compare(_unit("af"), _truth(), translated)

    hint = "annotation.destructiveHint"
    assert next(f for f in labelled if f.prop == hint).verdict == MUTATED
    assert next(f for f in plain if f.prop == hint).verdict == DROPPED


class _FakeServer:
    """Invoke that writes the call log the way the fixture server does."""

    def __init__(self, log: Path, *, refuse: set[str], raise_on_error: bool) -> None:
        self.log = log
        self.refuse = refuse
        self.raise_on_error = raise_on_error

    def __call__(self, tool: str, arguments: dict[str, Any]) -> Outcome:
        constraint = next(
            (
                v.constraint
                for v in study4.VIOLATIONS
                if v.tool == tool and v.arguments == arguments
            ),
            None,
        )
        if constraint in self.refuse:
            return Outcome(raised="ValueError: refused locally", output="")
        with self.log.open("a", encoding="utf-8") as handle:
            handle.write(f'{{"tool": "{tool}"}}\n')
        if tool == study4.ERROR_TOOL:
            if self.raise_on_error:
                return Outcome(raised="ToolError: boom", output="")
            return Outcome(raised=None, output="Error executing tool: refused by the fixture")
        return Outcome(raised=None, output="ok")


def test_enforcement_is_credited_only_when_the_call_never_left(tmp_path: Path) -> None:
    log = tmp_path / "calls.log"
    server = _FakeServer(log, refuse={"table.enum"}, raise_on_error=False)

    findings, working = behaviour(_unit(), server, log)

    verdicts = {f.prop: f.verdict for f in findings}
    assert working == set(study4.VALID_CALLS)
    assert verdicts["enforcement.table.enum"] == PRESERVED
    assert verdicts["enforcement.limit.maximum"] == DROPPED
    assert verdicts["error.isError"] == MUTATED


def test_an_error_raised_to_the_caller_is_preserved(tmp_path: Path) -> None:
    log = tmp_path / "calls.log"

    findings, _ = behaviour(_unit(), _FakeServer(log, refuse=set(), raise_on_error=True), log)

    assert next(f for f in findings if f.prop == "error.isError").verdict == PRESERVED


def test_a_broken_invocation_path_withholds_verdicts(tmp_path: Path) -> None:
    # If valid calls never arrive, an invalid one not arriving proves nothing.
    log = tmp_path / "calls.log"

    findings, working = behaviour(
        _unit(), lambda tool, arguments: Outcome(raised="OSError: no server", output=""), log
    )

    assert working == set()
    enforcement = [f for f in findings if f.prop.startswith("enforcement.")]
    assert enforcement
    assert {f.verdict for f in enforcement} == {UNKNOWN}


def test_unknown_leaves_the_loss_rate_denominator() -> None:
    unit = {
        "id": "u",
        "findings": [
            {"prop": "enforcement.a", "verdict": DROPPED},
            {"prop": "enforcement.b", "verdict": PRESERVED},
            {"prop": "enforcement.c", "verdict": UNKNOWN},
            {"prop": "restore.enforcement.a", "verdict": DROPPED},
        ],
    }

    (row,) = loss_rates([unit])

    assert (row["lost"], row["decided"], row["loss_rate"]) == (1, 2, 0.5)


def test_lattice_agreement_flags_a_wrong_claim() -> None:
    # The lattice says crewai expresses input constraints; a dropped nested
    # constraint must show as disagreement, not be averaged away.
    findings = [
        Finding("u", "t", "constraint.a.enum", PRESERVED),
        Finding("u", "t", "constraint.b.pattern", DROPPED),
    ]

    rows = {r["property"]: r for r in lattice_agreement(_unit("u", "crewai"), findings)}

    assert rows["inputConstraints"]["lattice_says_expressible"] is True
    assert rows["inputConstraints"]["agrees"] is False
    assert rows["readOnlyHint"]["agrees"] is None


def test_every_violation_breaks_a_constraint_the_fixture_declares() -> None:
    # Guards against a violation keyed to a constraint path that does not exist,
    # which would be measured but could never be compared. Needs the fixture's
    # `mcp` dependency, which only the research group installs.
    pytest.importorskip("mcp")
    from bench.s4_fixture_server import mcp

    declared: set[str] = set()
    for tool in mcp._tool_manager.list_tools():
        declared |= {key for key in flatten(tool.parameters) if not key.startswith("required:")}

    for violation in study4.VIOLATIONS:
        assert violation.constraint in declared, violation.constraint
