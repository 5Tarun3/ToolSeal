"""SARIF 2.1.0 output.

SARIF is what puts findings where developers already look - GitHub code
scanning, IDE problem panes, other analysis dashboards - rather than in a
terminal they have to remember to run. For a tool whose adoption argument is
"security you get for free", meeting people inside their existing workflow is
the whole point.

Two details decide whether the output is useful rather than merely valid:

* Every check is declared in ``rules``, including the ones that passed. A
  consumer that can say "24 of 28 rules passed" is more informative than one
  that only ever learns about failures.
* Locations are relative URIs. An absolute path from a build machine resolves
  in nobody else's checkout.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any, Final

from toolseal import __version__
from toolseal.core.policy import all_checks
from toolseal.core.policy.model import AuditReport, Finding, Severity

SARIF_VERSION: Final = "2.1.0"
SARIF_SCHEMA: Final = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)

# SARIF has three levels; the taxonomy has four. `critical` and `high` both map
# to `error` because both should fail a gate, and the original severity is kept
# verbatim in properties so the narrowing loses nothing.
_LEVELS: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def _relative_uri(root: Path, location: str | None) -> str | None:
    """Express *location* relative to *root* so it resolves in any checkout."""
    if not location:
        return None

    as_path = Path(location)
    if not as_path.is_absolute():
        return PurePosixPath(as_path.as_posix()).as_posix()
    try:
        return as_path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        # Outside the project entirely; the bare name is the most that can be
        # said without leaking a machine-specific path into the report.
        return as_path.name


def _result(finding: Finding, root: Path) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "ruleId": finding.check_id,
        "level": _LEVELS[finding.severity],
        "message": {"text": f"{finding.title}: {finding.detail}"},
        "properties": {"severity": str(finding.severity)},
    }

    uri = _relative_uri(root, finding.location)
    if uri:
        physical: dict[str, Any] = {"artifactLocation": {"uri": uri}}
        if finding.line:
            physical["region"] = {"startLine": finding.line}
        entry["locations"] = [{"physicalLocation": physical}]
    return entry


def to_sarif(report: AuditReport) -> dict[str, Any]:
    """Render *report* as a SARIF 2.1.0 log."""
    root = Path(report.root)

    rules = [
        {
            "id": check.id,
            "name": check.id,
            "shortDescription": {"text": check.title},
            "fullDescription": {"text": check.title},
            "help": {"text": check.remediation},
            "defaultConfiguration": {"level": _LEVELS[check.severity]},
            "properties": {"severity": str(check.severity), "family": check.family},
        }
        for check in all_checks()
    ]

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "toolseal",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": [_result(finding, root) for finding in report.findings],
                "properties": {
                    "score": report.score,
                    "blocking": report.blocking,
                    "familyScores": {
                        family.family: family.score for family in report.family_scores()
                    },
                },
            }
        ],
    }
