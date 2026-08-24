"""`toolseal audit` - score any project against the taxonomy.

Advisory by design. It reports and exits; it never blocks and never edits. The
product claim is that setup gets *faster*, and a tool that refuses to proceed on
a false positive forfeits that argument on the first bad match.

The outcome travels in the exit code rather than in prose, so CI can branch on
it: `0` clean, `1` findings present.

The human-readable report is verdict-first (spec `docs/superpowers/specs/
2026-08-19-cli-visual-language.md` §3): a summary panel carrying the score,
`BLOCKING`, and the severity counts renders *before* the findings, so the wall
of detail below is optional reading. `--json`/`--sarif` are untouched by any
of this - `_as_dict` and `to_sarif` are the machine contract and this module
never changes what they produce.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.panel import Panel
from rich.text import Text

from toolseal.cli._ui import (
    accent_text,
    blocking_text,
    console,
    count_style,
    new_progress_observer,
    new_table,
    print_table,
    print_text,
    print_wrapped,
    score_style,
    severity_style,
)
from toolseal.core.audit import audit as run_audit
from toolseal.core.manifest import Manifest
from toolseal.core.policy import progress as progress_hook
from toolseal.core.policy.model import AuditReport, Finding, Severity, Verdict
from toolseal.core.policy.profile import apply_resolution, load_profile, resolve
from toolseal.core.report import to_sarif
from toolseal.errors import ExitCode


def audit(
    path: Annotated[
        Path | None, typer.Argument(help="Project to audit. Defaults to the current directory.")
    ] = None,
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable output on stdout.")
    ] = False,
    as_sarif: Annotated[
        bool,
        typer.Option("--sarif", help="Emit SARIF 2.1.0 on stdout, for code scanning."),
    ] = False,
    min_severity: Annotated[
        Severity | None,
        typer.Option("--min-severity", help="Only report findings at or above this severity."),
    ] = None,
) -> None:
    """Score a project against the misconfiguration taxonomy."""
    root = path or Path.cwd()

    # C3's per-name resolution and C2's advisory query are the two phases of
    # an audit that can run long enough to look like a hang (spec §4/§1) - a
    # forty-dependency project spends on the order of twenty seconds in C3
    # alone. The observer installed here is what turns that silence into
    # "resolving package names 14/40" on stderr; `core/` itself never learns
    # a terminal exists (see `core/policy/progress.py`).
    with progress_hook.observe(new_progress_observer()):
        report = run_audit(root)

    # No-flag integration (spec §10): a profile declared in toolseal.toml
    # applies automatically. Resolution happens here, in the CLI/core-policy
    # layer, entirely *after* `run_audit` has already produced its report -
    # `core/audit/engine.py` is never touched and never learns a profile
    # exists (see `apply_resolution`'s docstring for why that is equivalent
    # to resolving first).
    manifest = Manifest.load(root)
    active_profiles = manifest.profiles if manifest else ()
    if active_profiles:
        resolution = resolve([load_profile(profile_id) for profile_id in active_profiles])
        report = apply_resolution(report, resolution)

    findings = _filtered(report, min_severity)

    if as_sarif:
        typer.echo(json.dumps(to_sarif(report), indent=2, sort_keys=True))
    elif as_json:
        payload = _as_dict(report, findings, active_profiles)
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        _print_report(report, findings, active_profiles)

    raise typer.Exit(ExitCode.FINDINGS if findings else ExitCode.OK)


def _filtered(report: AuditReport, minimum: Severity | None) -> tuple[Any, ...]:
    if minimum is None:
        return report.findings
    order = list(Severity)
    ceiling = order.index(minimum)
    return tuple(f for f in report.findings if order.index(f.severity) <= ceiling)


def _as_dict(
    report: AuditReport, findings: tuple[Any, ...], active_profiles: tuple[str, ...] = ()
) -> dict[str, Any]:
    return {
        "root": report.root,
        "profiles": list(active_profiles),
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


# Severity label column: wide enough that "CRITICAL" (the longest value) still
# leaves a one-space gap before the check id, so every check id lands in the
# same column down the page regardless of which severity precedes it.
_SEVERITY_GUTTER = 10
_CONTINUATION_WIDTH = 2 + _SEVERITY_GUTTER + 1


def _blocking_count(report: AuditReport) -> int:
    return sum(
        1
        for result in report.results
        if result.verdict is Verdict.FAIL and result.check.severity is Severity.CRITICAL
    )


def _summary_panel(report: AuditReport) -> Panel:
    """Verdict first (spec §3): score and `BLOCKING` in the same panel,
    adjacent to each other and above every finding. They belong together on
    purpose - a severity-weighted average can hide one critical finding
    behind a long tail of passes, and this panel is where that tension has
    to stay visible, never as a line trailing the findings wall below.
    """
    headline = Text(f"score {report.score}/100", style=score_style(report.score))
    blocking = _blocking_count(report)
    if blocking:
        headline.append("   ")
        headline.append_text(blocking_text(blocking))

    counts = Counter(finding.severity for finding in report.findings)
    unknown = sum(1 for result in report.results if result.verdict is Verdict.UNKNOWN)

    # ", " rather than " | " (spec §8: ASCII punctuation only): the panel
    # this line lives in is itself drawn with `|` side walls on a console
    # that cannot render rich's box-drawing characters, and a `|` separator
    # here would read as a badly-aligned continuation of that same border
    # rather than as four counts in a line (defect: the two glyphs collide).
    detail = Text()
    pieces = [(severity, counts[severity]) for severity in Severity if counts[severity]]
    for index, (severity, count) in enumerate(pieces):
        if index:
            detail.append(", ")
        # Severity is spelled out as text, not carried by colour alone (spec
        # §8): a colour-blind reader or a plain-text log still gets "3
        # critical", not just a coloured "3".
        detail.append(f"{count} {severity.value}", style=severity_style(severity))
    if unknown:
        if pieces:
            detail.append(", ")
        detail.append(f"{unknown} not evaluated", style="caveat")
    if not pieces and not unknown:
        detail.append("no findings", style="verdict.good")

    body = Text()
    body.append_text(headline)
    body.append("\n")
    body.append_text(detail)
    # The border itself carries the verdict colour too - not the only carrier
    # of it (the score and every count are still spelled out in text), but a
    # border that matches `--help`'s rounded, coloured panels rather than
    # sitting there in the terminal's default foreground.
    return Panel(body, expand=False, border_style=score_style(report.score))


def _print_finding(finding: Finding) -> None:
    gutter = Text(f"{finding.severity.value.upper():<{_SEVERITY_GUTTER}} ")
    gutter.stylize(severity_style(finding.severity), 0, len(finding.severity.value))
    header = Text("  ")
    header.append_text(gutter)
    header.append_text(accent_text(finding.check_id))
    header.append(f"  {finding.title}")
    print_text(console, header)

    # Location and detail are muted; `fix` is the loudest line, inverting the
    # old dim-grey remediation - it is the reason the tool exists (spec §1).
    # `print_wrapped` rather than `rich.padding.Padding`, so a detail long
    # enough to wrap keeps its hanging indent on every wrapped line - under
    # the text, never under a label - without padding any line out to the
    # container width.
    where = ""
    if finding.location:
        where = finding.location + (f":{finding.line}" if finding.line else "")
    detail_body = f"{where} - {finding.detail}" if where else finding.detail
    print_wrapped(console, detail_body, indent=_CONTINUATION_WIDTH, style="muted")

    if finding.remediation:
        print_wrapped(
            console, finding.remediation, indent=_CONTINUATION_WIDTH, style="fix", label="fix  "
        )

    console.print()


def _family_table(report: AuditReport) -> None:
    table = new_table()
    table.add_column("Family")
    table.add_column("Score", justify="right")
    table.add_column("Pass", justify="right")
    table.add_column("Fail", justify="right")
    table.add_column("N/A", justify="right")
    for family in report.family_scores():
        table.add_row(
            accent_text(family.family),
            Text(str(family.score), style=score_style(family.score)),
            Text(str(family.passed), style=count_style(family.passed)),
            Text(str(family.failed), style=count_style(family.failed)),
            Text(str(family.not_applicable), style=count_style(family.not_applicable)),
        )
    print_table(console, table)


def _print_report(
    report: AuditReport, findings: tuple[Any, ...], active_profiles: tuple[str, ...] = ()
) -> None:
    print_text(console, accent_text(report.root))
    console.print()

    if active_profiles:
        line = Text("  profile: ")
        line.append_text(accent_text(", ".join(active_profiles)))
        line.append(" (see `toolseal policy show`)")
        print_text(console, line)
        console.print()

    console.print(_summary_panel(report))
    console.print()

    for finding in findings:
        _print_finding(finding)

    _family_table(report)

    unknown = [r.check.id for r in report.results if r.verdict is Verdict.UNKNOWN]
    if unknown:
        console.print()
        caveat = Text("  not evaluated: ", style="caveat")
        caveat.append(", ".join(unknown), style="caveat")
        # Load-bearing text (spec §7): "data unavailable, not a pass" must
        # survive verbatim - it is what stops "we could not look" from being
        # read as "we looked and it passed".
        caveat.append(" - data unavailable, not a pass", style="caveat")
        print_text(console, caveat)
