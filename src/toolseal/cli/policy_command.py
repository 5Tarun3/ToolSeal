"""`toolseal policy` - what the rules are, and why.

A check id on its own tells an operator nothing. This command turns the control
mapping into a help system: what the rule means, which published obligations it
serves, and the command that fixes it. That is the mapping's primary job; the
coverage figures it also produces are a by-product.
"""

from __future__ import annotations

from typing import Annotated

import typer

from toolseal.cli.errors import command as error_boundary
from toolseal.core.policy.controls import ControlRef, load_catalogues, resolve
from toolseal.core.policy.coverage import coverage_for
from toolseal.core.policy.model import Check, all_checks
from toolseal.errors import ConfigError, UsageError

policy_app = typer.Typer(
    name="policy",
    help="Inspect security checks and the standards they answer to.",
    no_args_is_help=True,
)


def _find_check(check_id: str) -> Check | None:
    wanted = check_id.strip().upper()
    return next((check for check in all_checks() if check.id == wanted), None)


def _explain_check(check: Check) -> None:
    typer.echo(f"{check.id}  {check.title}")
    typer.echo(f"severity: {check.severity}")
    typer.echo("")
    typer.echo("How to fix it")
    typer.echo(f"  {check.remediation}")
    typer.echo("")

    if not check.controls:
        typer.echo("Obligations")
        reason = check.unmapped_reason or "no reason recorded"
        typer.echo(f"  none mapped - {reason}")
        return

    typer.echo("Obligations this serves")
    catalogues = load_catalogues()
    for ref in check.controls:
        control = resolve(ref, catalogues)
        typer.echo(f"  {ref.standard}:{control.id}  {control.title}")


def _explain_control(raw: str) -> None:
    standard, _, control_id = raw.partition(":")
    ref = ControlRef(standard.strip(), control_id.strip())
    try:
        control = resolve(ref)
    except ConfigError as exc:
        # A malformed subject typed at the CLI is a usage mistake, not an
        # internal failure - `resolve()` itself keeps raising `ConfigError`
        # unchanged for its other callers, this is a boundary-only translation.
        raise UsageError(str(exc)) from None

    typer.echo(f"{ref}  {control.title}")
    typer.echo("")

    serving = sorted(check.id for check in all_checks() if ref in check.controls)

    if not control.checkable:
        typer.echo("This control is not assessable from configuration alone.")
        typer.echo("It is recorded so the coverage denominator stays honest.")
        if serving:
            typer.echo("")
            typer.echo(f"Related checks: {', '.join(serving)}")
        return

    if serving:
        typer.echo(f"Checks that serve it: {', '.join(serving)}")
    else:
        typer.echo("No check covers this yet.")


def list_standards() -> None:
    """List the standards and regimes shipped with toolseal."""
    catalogues = load_catalogues()
    width = max(len(key) for key in catalogues)

    partial_seen = False
    for key in sorted(catalogues):
        catalogue = catalogues[key]
        report = coverage_for(key)
        covered = f"{report.covered}/{report.checkable_total}"
        marker = "" if report.complete_enumeration else " *"
        if marker:
            partial_seen = True
        typer.echo(
            f"{key.ljust(width)}  {report.percentage:3d}%{marker.ljust(2)} "
            f"{covered.rjust(6)} checkable controls  {catalogue.name}"
        )

    if partial_seen:
        typer.echo("")
        typer.echo("* curated subset of the standard, not a full enumeration -")
        typer.echo("  the percentage measures our selection, not the standard's reach.")


def explain(
    subject: Annotated[
        str,
        typer.Argument(help="A check id (B3) or a control (owasp-llm-top10:LLM02)."),
    ],
) -> None:
    """Explain a check or a control: what it means, and what to do about it."""
    if ":" in subject:
        _explain_control(subject)
        return

    check = _find_check(subject)
    if check is None:
        message = f"no check named {subject!r}; try `toolseal policy list`"
        raise UsageError(message)

    _explain_check(check)


policy_app.command("list")(error_boundary(list_standards))
policy_app.command("explain")(error_boundary(explain))
