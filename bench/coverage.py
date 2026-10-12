"""Study 5: coverage analysis for C6, plus Study 1 re-cut by control.

Part (a) is a direct computation from the shipped catalogues and the check
registry - the same data `toolseal policy list` prints, gathered here into one
committed report so the numbers in the write-up trace back to a run rather
than to someone typing a percentage by hand.

Part (b) asks whether Study 1's existing corpus (`research/studies/s1/`) can
be re-reported per control instead of per family, with no new corpus and no
new harness (spec §11). This module answers that question from the actual
`results.json` on disk rather than assuming either way: if the data supports
it, it produces the re-cut table; if it does not, it says exactly why not.
Both outcomes are legitimate results of running this script - the point is
that neither is invented.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from toolseal.core.policy.controls import load_catalogues
from toolseal.core.policy.coverage import coverage_for, unmapped_checks
from toolseal.core.policy.model import all_checks

S1_RESULTS: Path = Path("research/studies/s1/results.json")
OTHER_S1_STRATA: tuple[str, ...] = ("official-docs", "mcp-servers", "templates")
"""The three strata `research/evaluation-protocol.md` defines for Study 1
besides `llm-generated`. Each, once collected, writes a flat
`results.<stratum>.json` alongside `S1_RESULTS`
(`bench.corpus.write_flat_index`); `recut_study1_by_control` checks for that
file explicitly, per stratum, rather than silently only ever looking at the
one stratum this module itself reads."""


# --- part (a): coverage analysis -------------------------------------------


def _catalogue_summary(catalogue_id: str) -> dict[str, Any]:
    report = coverage_for(catalogue_id)
    catalogue = load_catalogues()[catalogue_id]
    return {
        "id": catalogue_id,
        "name": catalogue.name,
        "complete_enumeration": report.complete_enumeration,
        "controls_published": len(catalogue.controls),
        "checkable_total": report.checkable_total,
        "covered": report.covered,
        "percentage": report.percentage,
        "uncovered": [
            {"id": entry.control.id, "title": entry.control.title} for entry in report.uncovered
        ],
    }


def coverage_analysis() -> dict[str, Any]:
    """What fraction of each standard's checkable controls a check reaches,
    and which checks cite no standard at all - both margins of the matrix
    (spec §4.4), neither one summarised away."""
    catalogues = load_catalogues()
    summaries = [_catalogue_summary(catalogue_id) for catalogue_id in sorted(catalogues)]
    return {
        "catalogues": summaries,
        "unmapped_checks": [check.id for check in unmapped_checks()],
        "checks_total": len(all_checks()),
    }


# --- part (b): the attempted Study 1 re-cut --------------------------------


def _load_s1() -> dict[str, Any] | None:
    if not S1_RESULTS.is_file():
        return None
    payload: dict[str, Any] = json.loads(S1_RESULTS.read_text(encoding="utf-8"))
    return payload


def _other_strata_missing() -> list[str]:
    return [
        stratum
        for stratum in OTHER_S1_STRATA
        if not (S1_RESULTS.parent / f"results.{stratum}.json").is_file()
    ]


def _control_failures(check_counts: dict[str, int]) -> dict[str, int]:
    """Per-check failure counts summed onto every control each check cites.

    A sum of check failures, not a count of completions: two failing checks
    that cite one control add two. The aggregates Study 1 commits do not record
    which completion failed which check, so a per-completion count cannot be
    recovered, and the report's header says what is actually counted.
    """
    check_to_controls = {check.id: [str(ref) for ref in check.controls] for check in all_checks()}
    control_failures: dict[str, int] = {}
    for check_id, count in check_counts.items():
        for control_ref in check_to_controls.get(check_id, ()):
            control_failures[control_ref] = control_failures.get(control_ref, 0) + count
    return dict(sorted(control_failures.items(), key=lambda kv: (-kv[1], kv[0])))


def _stratum_recut(stratum: str, payload: dict[str, Any]) -> dict[str, Any]:
    aggregate = payload.get("aggregate", {})
    return {
        "stratum": stratum,
        "status": str(payload.get("status", "")),
        "materialised": int(aggregate.get("materialised", 0)),
        "completions_total": int(
            aggregate.get("completions_total", aggregate.get("candidates_considered", 0))
        ),
        "control_failure_counts": _control_failures(aggregate.get("check_failure_counts", {})),
    }


def recut_study1_by_control() -> dict[str, Any]:
    """Re-report Study 1's per-check failure counts as per-control counts.

    Uses the same `Check.controls` map `coverage_for` uses. The top-level
    figures are the `llm-generated` stratum's, the one this study was first
    written against; ``strata`` carries the re-cut for every collected
    stratum, reported separately because Study 1 is.

    Until 2026-10-09 the `llm-generated` stratum had 0 of 12 completions
    materialised and this returned infeasible. That zero was a
    filename-recovery defect, since fixed; the stratum's payload is labelled
    exploratory as a result, and ``status`` carries the label through.
    """
    payload = _load_s1()
    if payload is None:
        return {
            "possible": False,
            "reason": f"{S1_RESULTS} does not exist; Study 1 has not been run.",
        }

    llm = _stratum_recut("llm-generated", payload)
    missing_strata = _other_strata_missing()

    if llm["materialised"] == 0 or not llm["control_failure_counts"]:
        return {
            "possible": False,
            "reason": (
                f"{llm['materialised']} of {llm['completions_total']} completions in "
                "the llm-generated stratum materialised into an auditable project, "
                "so aggregate.check_failure_counts is empty - there is nothing to "
                "re-derive a per-control table from."
            ),
            "materialised": llm["materialised"],
            "completions_total": llm["completions_total"],
            "missing_strata": missing_strata,
        }

    strata = [llm]
    for stratum in OTHER_S1_STRATA:
        index = S1_RESULTS.parent / f"results.{stratum}.json"
        if index.is_file():
            strata.append(_stratum_recut(stratum, json.loads(index.read_text(encoding="utf-8"))))

    return {
        "possible": True,
        "status": llm["status"],
        "materialised": llm["materialised"],
        "completions_total": llm["completions_total"],
        "control_failure_counts": llm["control_failure_counts"],
        "missing_strata": missing_strata,
        "strata": strata,
    }


# --- assembling and rendering ------------------------------------------------


def run() -> dict[str, Any]:
    return {
        "study": "S5 control coverage (C6)",
        "note": (
            "Coverage counts citations, not adequacy: a checkable control is "
            "reported as covered the moment one check cites it, which is not "
            "evidence the check discharges the obligation. C6 is explicitly "
            "secondary (spec §11) - the control-mapping feature is justified "
            "by operator ease, not by this analysis."
        ),
        "coverage": coverage_analysis(),
        "study1_recut": recut_study1_by_control(),
    }


def _catalogue_row(entry: dict[str, Any]) -> str:
    marker = "" if entry["complete_enumeration"] else "*"
    return (
        f"| `{entry['id']}` | {entry['percentage']}%{marker} "
        f"| {entry['covered']}/{entry['checkable_total']} "
        f"| {entry['controls_published']} | {entry['name']} |"
    )


def to_markdown(payload: dict[str, Any]) -> str:
    coverage = payload["coverage"]
    recut = payload["study1_recut"]

    lines = [
        "# Study 5 - control coverage (C6)",
        "",
        payload["note"],
        "",
        "## Part (a): coverage of each standard's checkable controls",
        "",
        "| standard | coverage | checkable | published controls | name |",
        "| --- | ---: | ---: | ---: | --- |",
    ]
    for entry in coverage["catalogues"]:
        lines.append(_catalogue_row(entry))

    lines += [
        "",
        "`*` marks a catalogue whose file is a curated subset drawn up before "
        "any check mapping existed, not the full published standard - its "
        "percentage measures coverage of that selection, not of the standard. "
        "The complete-enumeration catalogues (unmarked above) list every "
        "published entry, `checkable = false` ones included, so their "
        "denominator is the whole standard.",
        "",
    ]

    curated = [c for c in coverage["catalogues"] if not c["complete_enumeration"]]
    if curated:
        lines.append("Curated subsets in this run:")
        for entry in curated:
            lines.append(
                f"- `{entry['id']}`: {entry['controls_published']} controls carried "
                "here, not the full published standard."
            )
        lines.append("")

    lines.append("### Uncovered checkable controls (the honest remainder)")
    lines.append("")
    any_uncovered = False
    for entry in coverage["catalogues"]:
        if not entry["uncovered"]:
            continue
        any_uncovered = True
        lines.append(f"**`{entry['id']}`**")
        for control in entry["uncovered"]:
            lines.append(f"- `{control['id']}` - {control['title']}")
        lines.append("")
    if not any_uncovered:
        lines.append(
            "None - every checkable control in every shipped catalogue is cited by "
            "at least one check."
        )
        lines.append("")

    lines.append(
        f"**Checks citing no external control at all:** "
        f"{len(coverage['unmapped_checks']) or 'none'} "
        f"of {coverage['checks_total']}."
    )
    if coverage["unmapped_checks"]:
        lines.append(f"({', '.join(coverage['unmapped_checks'])})")
    lines.append("")

    lines += [
        "## Part (b): Study 1 re-cut by control",
        "",
    ]
    if recut["possible"]:
        if recut.get("status"):
            lines += [f"Status: {recut['status']}.", ""]
        lines += [
            "Each stratum's per-check failures re-derived per control. Counts are "
            "check failures summed onto every control the failing check cites, so "
            "they can exceed the number of projects; Study 1's aggregates do not "
            "record which project failed which check.",
            "",
        ]
        for stratum in recut["strata"]:
            lines += [
                f"### `{stratum['stratum']}` - {stratum['materialised']} of "
                f"{stratum['completions_total']} materialised",
                "",
            ]
            if not stratum["control_failure_counts"]:
                lines += ["Nothing materialised, so nothing to re-cut.", ""]
                continue
            lines += ["| control | check failures citing it |", "| --- | ---: |"]
            for control_ref, count in stratum["control_failure_counts"].items():
                lines.append(f"| `{control_ref}` | {count} |")
            lines.append("")
    else:
        lines.append("**Not delivered.** " + recut["reason"])
        lines.append("")
        lines.append(
            "Per §11 of the design spec and the instructions for this study: "
            "an honest gap beats a fabricated table. Part (a) above is the "
            "evidence for C6 on its own."
        )
    lines.append("")

    return "\n".join(lines) + "\n"


def write(payload: dict[str, Any], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "results.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8", newline="\n"
    )
    (out_dir / "RESULTS.md").write_text(to_markdown(payload), encoding="utf-8", newline="\n")
