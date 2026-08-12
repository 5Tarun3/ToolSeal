"""`toolseal audit` - score any project against the taxonomy.

Advisory by design. It reports and exits; it never blocks and never edits. The
product claim is that setup gets *faster*, and a tool that refuses to proceed on
a false positive forfeits that argument on the first bad match.

The outcome travels in the exit code rather than in prose, so CI can branch on
it: `0` clean, `1` findings present.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any

import typer

from toolseal.core.audit import audit as run_audit
from toolseal.core.policy.model import AuditReport, Severity, Verdict
from toolseal.errors import ExitCode

GOOD_SCORE = 80

_SEVERITY_COLOUR = {
    Severity.CRITICAL: typer.colors.RED,
    Severity.HIGH: typer.colors.RED,
    Severity.MEDIUM: typer.colors.YELLOW,
    Severity.LOW: typer.colors.CYAN,
}


def audit(
    path: Annotated[
        Path | None, typer.Argument(help="Project to audit. Defaults to the current directory.")
    ] = None,
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable output on stdout.")
    ] = False,
    min_severity: Annotated[
        Severity | None,
        typer.Option("--min-severity", help="Only report findings at or above this severity."),
    ] = None,
) -> None:
    """Score a project against the misconfiguration taxonomy."""
    report = run_audit(path or Path.cwd())
    findings = _filtered(report, min_severity)

    if as_json:
        typer.echo(json.dumps(_as_dict(report, findings), indent=2, sort_keys=True))
    else:
        _print_report(report, findings)

    raise typer.Exit(ExitCode.FINDINGS if findings else ExitCode.OK)


def _filtered(report: AuditReport, minimum: Severity | None) -> tuple[Any, ...]:
    if minimum is None:
        return report.findings
    order = list(Severity)
    ceiling = order.index(minimum)
    return tuple(f for f in report.findings if order.index(f.severity) <= ceiling)


def _as_dict(report: AuditReport, findings: tuple[Any, ...]) -> dict[str, Any]:
    return {
        "root": report.root,
        "score": report.score,
        "blocking": report.blocking,
        "families": [
            {
                "family": family.family,
                "score": family.score,
                "passed": family.passed,
                "failed": family.failed,
                "not_applicable": family.not_applicable,
                "unknown": family.unknown,
            }
            for family in report.family_scores()
        ],
        "findings": [
            {
                "check": finding.check_id,
                "severity": str(finding.severity),
                "title": finding.title,
                "detail": finding.detail,
                "location": finding.location,
                "line": finding.line,
                "remediation": finding.remediation,
            }
            for finding in findings
        ],
        "unknown_checks": [
            result.check.id for result in report.results if result.verdict is Verdict.UNKNOWN
        ],
    }


def _print_report(report: AuditReport, findings: tuple[Any, ...]) -> None:
    typer.echo(f"{report.root}\n")

    for finding in findings:
        colour = _SEVERITY_COLOUR[finding.severity]
        where = f" {finding.location}" + (f":{finding.line}" if finding.line else "")
        typer.secho(f"  {finding.severity.upper():<8}", fg=colour, nl=False)
        typer.echo(f"{finding.check_id}  {finding.title}{where}")
        typer.echo(f"           {finding.detail}")
        if finding.remediation:
            typer.secho(f"           fix: {finding.remediation}", fg=typer.colors.BRIGHT_BLACK)
        typer.echo("")

    typer.echo("  family   score   pass  fail   n/a")
    for family in report.family_scores():
        typer.echo(
            f"  {family.family:<8} {family.score:>4}   {family.passed:>4}  "
            f"{family.failed:>4}  {family.not_applicable:>4}"
        )

    # `blocking` is printed separately from the score on purpose: an average can
    # hide one critical finding behind a long tail of passes.
    typer.echo("")
    typer.secho(
        f"  score {report.score}/100",
        fg=typer.colors.GREEN if report.score >= GOOD_SCORE else typer.colors.YELLOW,
    )
    if report.blocking:
        typer.secho("  BLOCKING: a critical check failed", fg=typer.colors.RED, bold=True)

    unknown = [r.check.id for r in report.results if r.verdict is Verdict.UNKNOWN]
    if unknown:
        typer.secho(
            f"  not evaluated: {', '.join(unknown)} (data unavailable, not a pass)",
            fg=typer.colors.YELLOW,
        )
