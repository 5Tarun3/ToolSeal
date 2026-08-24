"""`toolseal policy` - what the rules are, and why.

A check id on its own tells an operator nothing. This command turns the control
mapping into a help system: what the rule means, which published obligations it
serves, and the command that fixes it. That is the mapping's primary job; the
coverage figures it also produces are a by-product.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace as dataclass_replace
from datetime import date
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Group, RenderableType
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from toolseal.cli._ui import (
    accent_text,
    console,
    count_style,
    new_grid,
    new_table,
    print_line,
    print_table,
    print_text,
    severity_style,
    verdict_style,
)
from toolseal.cli.errors import command as error_boundary
from toolseal.core.audit import audit as run_audit
from toolseal.core.manifest import MANIFEST_NAME, Manifest
from toolseal.core.policy import lock as policy_lock
from toolseal.core.policy.controls import ControlRef, load_catalogues, resolve
from toolseal.core.policy.coverage import coverage_for
from toolseal.core.policy.model import Check, Verdict, all_checks
from toolseal.core.policy.profile import (
    Profile,
    Resolution,
    apply_resolution,
    load_profile,
)
from toolseal.core.policy.profile import (
    resolve as resolve_profiles,
)
from toolseal.core.policy.relax import (
    Relaxation,
    RelaxationOutcome,
    apply_relaxations,
    parse_relaxations,
)
from toolseal.errors import ConfigError, ExitCode, UsageError

policy_app = typer.Typer(
    name="policy",
    help="Inspect security checks and the standards they answer to.",
    no_args_is_help=True,
)


def _find_check(check_id: str) -> Check | None:
    wanted = check_id.strip().upper()
    return next((check for check in all_checks() if check.id == wanted), None)


def _explain_check(check: Check) -> None:
    """The keystone command (spec §6): what a check means, what to run, and
    which published obligations it serves - one panel, so a developer never
    has to leave the terminal to open a standards document.
    """
    sections: list[RenderableType] = [
        Text(""),
        Text("How to fix it", style="heading"),
        Text(f"  {check.remediation}", style="fix"),
        Text(""),
    ]

    if not check.controls:
        # A non-checkable control keeps its explanatory sentence (spec §6):
        # an empty section reads as a bug, which is why this text exists.
        reason = check.unmapped_reason or "no reason recorded"
        sections.append(Text("Obligations", style="heading"))
        sections.append(Text(f"  none mapped - {reason}"))
    else:
        sections.append(Text("Obligations this serves", style="heading"))
        catalogues = load_catalogues()
        # `new_grid` (`Table.grid` under the shared `_ui` factory, spec §5):
        # rich's own column-alignment, not hand-rolled width arithmetic -
        # each obligation's id and title line up without this module
        # computing a padding width itself. Routed through `_ui` rather than
        # `rich.table.Table.grid` directly so a control title too long to
        # fit on one line wraps (spec §8: ASCII only) instead of picking up
        # rich's own non-ASCII ellipsis.
        obligations = new_grid(padding=(0, 2, 0, 2))
        obligations.add_column()
        obligations.add_column()
        for ref in check.controls:
            control = resolve(ref, catalogues)
            obligations.add_row(accent_text(f"{ref.standard}:{control.id}"), control.title)
        # Indented by 2, matching "How to fix it"'s body above (defect: this
        # section used to sit flush against the panel's left edge while the
        # other section indented its content - same structure, two
        # treatments). `rich.padding.Padding` does the indenting, not a
        # hand-rolled leading-space prefix on every row.
        sections.append(Padding(obligations, (0, 0, 0, 2)))

    title = Text()
    title.append_text(accent_text(check.id))
    title.append(f" - {check.title}")
    panel = Panel(
        Group(*sections),
        title=title,
        title_align="left",
        subtitle=Text(f"severity: {check.severity.value}", style=severity_style(check.severity)),
        subtitle_align="right",
        expand=False,
        # The border echoes the same severity colour as the subtitle - the
        # panel's frame, not only its footer, marks how serious this check
        # is, matching the weight `--help`'s own coloured panels carry.
        border_style=severity_style(check.severity),
    )
    console.print(panel)


def _explain_control(raw: str) -> None:
    standard, _, control_id = raw.partition(":")
    ref = ControlRef(standard.strip(), control_id.strip())

    # Loading the catalogues happens outside the try: a malformed *shipped*
    # catalogue is a packaging fault, and must keep surfacing as INTERNAL, not
    # get relabelled as the caller's mistake just because it also raises
    # ConfigError. Only the reference lookup below - unknown standard, unknown
    # control id, both genuine typos in what the user typed - is a usage error.
    catalogues = load_catalogues()
    try:
        control = resolve(ref, catalogues)
    except ConfigError as exc:
        # A malformed subject typed at the CLI is a usage mistake, not an
        # internal failure - `resolve()` itself keeps raising `ConfigError`
        # unchanged for its other callers, this is a boundary-only translation.
        raise UsageError(str(exc)) from None

    header = accent_text(str(ref))
    header.append(f"  {control.title}", style="heading")
    print_text(console, header)
    typer.echo("")

    serving = sorted(check.id for check in all_checks() if ref in check.controls)

    if not control.checkable:
        # The explanatory sentence a non-checkable control keeps (spec §6):
        # an empty section here would read as a bug, not as an honest "we
        # cannot check this from configuration".
        print_line(
            console,
            "This control is not assessable from configuration alone.",
            style="caveat",
        )
        typer.echo("It is recorded so the coverage denominator stays honest.")
        if serving:
            typer.echo("")
            related = Text("Related checks: ")
            related.append_text(accent_text(", ".join(serving)))
            print_text(console, related)
        return

    if serving:
        line = Text("Checks that serve it: ")
        line.append_text(accent_text(", ".join(serving)))
        print_text(console, line)
    else:
        typer.echo("No check covers this yet.")


def _standards_table(rows: Sequence[tuple[str, Text, str, str]]) -> Table:
    """Build the `policy list` table, dropping the `name` column when the
    terminal is too narrow to hold every column on one line.

    `name` is the least important column here - a reader scans `standard`,
    `coverage`, and `checkable` down the page, and the full standard name is
    reference detail, not something compared row to row. Letting it wrap
    instead doubled every row's height and broke that scan (defect: the
    id/coverage/checkable columns no longer lined up visually). Dropping the
    column is the fix rather than clipping its text, because an ellipsis
    would need a non-ASCII character (spec §8 bans that outside `_ui.py`) and
    a hard character-count crop has no way to signal that it truncated -
    dropping the whole column is honest about what happened instead.

    The fit check is `rich`'s own measurement, not hand-rolled width
    arithmetic (spec §5): `console.measure` with `max_width` raised well
    past any real terminal reports how wide the table would be if nothing
    in it wrapped, which is then compared against the terminal's actual
    width.
    """
    full = new_table()
    full.add_column("standard")
    full.add_column("coverage", justify="right")
    full.add_column("checkable", justify="right")
    full.add_column("name", no_wrap=True)
    for standard, coverage, checkable, name in rows:
        full.add_row(accent_text(standard), coverage, checkable, name)

    unclamped = console.options.update(max_width=10_000)
    natural_width = console.measure(full, options=unclamped).maximum
    if natural_width <= console.size.width:
        return full

    narrow = new_table()
    narrow.add_column("standard")
    narrow.add_column("coverage", justify="right")
    narrow.add_column("checkable", justify="right")
    for standard, coverage, checkable, _name in rows:
        narrow.add_row(accent_text(standard), coverage, checkable)
    return narrow


def list_standards() -> None:
    """List the standards and regimes shipped with toolseal."""
    catalogues = load_catalogues()

    rows: list[tuple[str, Text, str, str]] = []
    partial_seen = False
    for key in sorted(catalogues):
        catalogue = catalogues[key]
        report = coverage_for(key)

        coverage = Text(f"{report.percentage}%")
        if not report.complete_enumeration:
            # Visible, not dim (spec §2): the mark exists so a percentage is
            # never read as coverage of the full standard when it is only
            # coverage of our curated subset.
            coverage.append("*", style="caveat")
            partial_seen = True

        rows.append((key, coverage, f"{report.covered}/{report.checkable_total}", catalogue.name))

    print_table(console, _standards_table(rows))

    if partial_seen:
        console.print()
        console.print("* curated subset of the standard, not a full enumeration -")
        console.print("  the percentage measures our selection, not the standard's reach.")


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


DISCLAIMER = "This is evidence toward an assessment. It is not one."
"""The exact sentence §5 mandates every `policy check` report end with."""


def _load_profile_or_usage_error(profile_id: str) -> Profile:
    """Resolve a profile id the user typed at the CLI, not one read from a file.

    `load_profile` raises `ConfigError` both for an unknown id (the caller's
    typo) and for a malformed *shipped* profile (a packaging fault). Only a
    value typed directly at this command's own argument/option is translated
    here - the same boundary-only distinction `_explain_control` already
    draws for a mistyped standard name.
    """
    try:
        return load_profile(profile_id)
    except ConfigError as exc:
        raise UsageError(str(exc)) from None


def _manifest_text(root: Path) -> str | None:
    path = root / MANIFEST_NAME
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8")


def _active_profile_ids(explicit: str | None, manifest: Manifest | None) -> tuple[str, ...]:
    if explicit is not None:
        return (explicit,)
    if manifest is not None:
        return manifest.profiles
    return ()


def _severity_source(check_id: str, resolution: Resolution) -> str:
    decision = next((d for d in resolution.decisions if d.check_id == check_id), None)
    if decision is None:
        return "baseline"
    return f"profile:{decision.winner}"


# --- show ----------------------------------------------------------------------


def show(
    tool: Annotated[
        str | None,
        typer.Argument(help="Show policy for one tool only, instead of the whole project."),
    ] = None,
    directory: Annotated[
        Path | None, typer.Option("--directory", "-d", help="Project to inspect.")
    ] = None,
) -> None:
    """What applies here, and where each rule came from - baseline, profile, or relax."""
    root = (directory or Path.cwd()).resolve()
    manifest = Manifest.load(root)
    profile_ids = _active_profile_ids(None, manifest)
    resolution = resolve_profiles([_load_profile_or_usage_error(pid) for pid in profile_ids])

    text = _manifest_text(root)
    relaxations = parse_relaxations(text) if text is not None else ()

    if tool is not None:
        _show_tool(root, tool, manifest, resolution, relaxations)
        return

    _show_project(profile_ids, resolution, relaxations)


def _show_project(
    profile_ids: tuple[str, ...],
    resolution: Resolution,
    relaxations: tuple[Relaxation, ...],
) -> None:
    if profile_ids:
        typer.echo(f"active profile(s): {', '.join(profile_ids)}")
    else:
        typer.echo("active profile(s): none declared in toolseal.toml")
    typer.echo("")

    relaxed_ids = {r.check_id for r in relaxations}

    table = new_table()
    table.add_column("check")
    table.add_column("severity")
    table.add_column("source")
    for check in resolution.checks:
        source = Text(_severity_source(check.id, resolution))
        if check.id in relaxed_ids:
            source.append(" (relaxed - see below)", style="verdict.relaxed")
        table.add_row(
            accent_text(check.id),
            Text(check.severity.value, style=severity_style(check.severity)),
            source,
        )
    print_table(console, table)

    _print_relaxations_table(relaxations)


def _show_tool(
    root: Path,
    tool: str,
    manifest: Manifest | None,
    resolution: Resolution,
    relaxations: tuple[Relaxation, ...],
) -> None:
    header = Text("policy for ", style="heading")
    header.append_text(accent_text(tool))
    print_text(console, header)
    typer.echo("")

    tool_policy = manifest.policy_for(tool) if manifest is not None else None
    if tool_policy is None:
        typer.echo(f"no [policy.tool.{tool}] declared in {MANIFEST_NAME}")
    else:
        typer.echo(f"declared in {MANIFEST_NAME} [policy.tool.{tool}]:")
        if tool_policy.approval is not None:
            typer.echo(f"  approval = {tool_policy.approval!r}")
        if tool_policy.timeout_seconds is not None:
            typer.echo(f"  timeout_seconds = {tool_policy.timeout_seconds}")
        if tool_policy.egress_allow is not None:
            typer.echo(f"  egress_allow = {list(tool_policy.egress_allow)}")
    typer.echo("")

    naming_this_tool = [r for r in relaxations if not r.tools or tool in r.tools]
    if naming_this_tool:
        typer.echo(f"relaxations covering {tool}:")
        _print_relaxations_table(naming_this_tool)
    else:
        typer.echo(f"no relaxation covers {tool}")
    typer.echo("")

    report = run_audit(root)
    by_id = {check.id: check for check in resolution.checks}
    concerning = [f for f in report.findings if f.subject == tool]
    if concerning:
        typer.echo(f"current findings naming {tool}:")
        for finding in concerning:
            # `resolution.checks` always has one entry per baseline check id
            # (`resolve()` returns the full baseline, adjusted or not), so
            # every finding's check id resolves here.
            severity = by_id[finding.check_id].severity
            source = _severity_source(finding.check_id, resolution)
            line = Text("  ")
            line.append_text(accent_text(finding.check_id))
            line.append("  ")
            line.append(severity.value, style=severity_style(severity))
            line.append(f"  ({source})  {finding.title}")
            print_text(console, line)
    else:
        typer.echo(f"no current findings name {tool}")


def _print_relaxations_table(relaxations: Sequence[Relaxation]) -> None:
    if not relaxations:
        typer.echo("relaxations declared: none")
        return

    today = date.today()
    for relaxation in relaxations:
        expired = relaxation.is_expired(today)
        status = "expired" if expired else "active"
        scope = ", ".join(relaxation.tools) if relaxation.tools else "project-wide"
        line = Text("  ")
        line.append_text(accent_text(relaxation.check_id))
        line.append(f"  expires {relaxation.expires}  (")
        line.append(status, style="verdict.warn" if expired else "verdict.relaxed")
        line.append(f")  scope: {scope}  reason: {relaxation.reason}")
        print_text(console, line)


# --- apply -----------------------------------------------------------------


def apply_regime(
    regime: Annotated[str, typer.Argument(help="Regime or standard id to adopt, e.g. hipaa.")],
    directory: Annotated[
        Path | None, typer.Option("--directory", "-d", help="Project to change.")
    ] = None,
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Apply without an interactive confirmation."),
    ] = False,
) -> None:
    """Adopt a regime or standard, after showing exactly what it would change."""
    root = (directory or Path.cwd()).resolve()
    manifest = Manifest.load(root)
    if manifest is None:
        message = f"no {MANIFEST_NAME} found in {root}; run `toolseal init` first"
        raise UsageError(message)

    profile = _load_profile_or_usage_error(regime)

    if regime in manifest.profiles:
        typer.echo(f"{regime} is already applied to this project.")
        return

    declared = [_load_profile_or_usage_error(p) for p in manifest.profiles]
    before = resolve_profiles(declared)
    after = resolve_profiles([*declared, profile])

    _print_apply_diff(regime, profile, manifest, before, after)

    if not yes and not typer.confirm("\nApply this regime?"):
        typer.echo("Not applied.")
        return

    updated = dataclass_replace(
        manifest,
        profiles=(*manifest.profiles, regime),
        approval_required_for_destructive=manifest.approval_required_for_destructive
        or bool(profile.require.get("policy.approval_required_for_destructive", False)),
    )
    (root / MANIFEST_NAME).write_text(updated.to_toml(), encoding="utf-8")
    console.print()
    print_line(console, f"Applied {regime}.", style="verdict.good")


def _print_apply_diff(
    regime: str,
    profile: Profile,
    manifest: Manifest,
    before: Resolution,
    after: Resolution,
) -> None:
    header = accent_text(regime)
    header.append(f" ({profile.name})", style="heading")
    print_text(console, header)
    if profile.source:
        typer.echo(f"  source: {profile.source}")
    if profile.source_url:
        typer.echo(f"  {profile.source_url}")
    typer.echo("")

    before_by_id = {check.id: check for check in before.checks}
    changed = sorted(
        (check.id, before_by_id[check.id].severity, check.severity)
        for check in after.checks
        if check.id in before_by_id and before_by_id[check.id].severity != check.severity
    )
    print_line(console, "severity changes:", style="heading")
    if changed:
        id_w = max(len(row[0]) for row in changed)
        for check_id, old, new in changed:
            line = Text("  ")
            line.append_text(accent_text(check_id.ljust(id_w)))
            line.append("  ")
            line.append(old.value, style=severity_style(old))
            line.append(" -> ")
            line.append(new.value, style=severity_style(new))
            print_text(console, line)
    else:
        typer.echo("  none")
    typer.echo("")

    require_changes = [
        (key, manifest.approval_required_for_destructive, wanted)
        for key, wanted in profile.require.items()
        if key == "policy.approval_required_for_destructive"
        and manifest.approval_required_for_destructive != wanted
    ]
    print_line(console, "settings:", style="heading")
    if require_changes:
        for setting_key, was, now in require_changes:
            typer.echo(f"  {setting_key}: {was} -> {now}")
    else:
        typer.echo("  none")

    if profile.not_assessed:
        typer.echo("")
        print_line(
            console,
            f"scope this regime does not reach ({len(profile.not_assessed)} items):",
            style="heading",
        )
        for item in profile.not_assessed:
            typer.echo(f"  - {item}")


# --- check -------------------------------------------------------------------


def check(
    profile: Annotated[
        str | None,
        typer.Option("--profile", help="Regime or standard to check against."),
    ] = None,
    directory: Annotated[
        Path | None, typer.Option("--directory", "-d", help="Project to check.")
    ] = None,
) -> None:
    """The configuration-evidence report. Coverage of what is checkable - never a verdict."""
    root = (directory or Path.cwd()).resolve()
    manifest = Manifest.load(root)
    profile_ids = _active_profile_ids(profile, manifest)
    profiles = [_load_profile_or_usage_error(pid) for pid in profile_ids]
    resolution = resolve_profiles(profiles)

    report = apply_resolution(run_audit(root), resolution)

    text = _manifest_text(root)
    relaxations = parse_relaxations(text) if text is not None else ()
    outcome = apply_relaxations(report, relaxations)

    _print_check_report(root, profile_ids, resolution, outcome)

    has_fail = any(result.verdict is Verdict.FAIL for result in outcome.report.results)
    raise typer.Exit(ExitCode.FINDINGS if has_fail else ExitCode.OK)


def _print_check_report(
    root: Path,
    profile_ids: tuple[str, ...],
    resolution: Resolution,
    outcome: RelaxationOutcome,
) -> None:
    report = outcome.report
    print_text(console, accent_text(str(root)))
    console.print()

    if profile_ids:
        line = Text("profile: ")
        line.append_text(accent_text(", ".join(profile_ids)))
        print_text(console, line)
    else:
        typer.echo("profile: none declared - showing baseline checks only")
    typer.echo("")

    counts: dict[Verdict, int] = {}
    for result in report.results:
        counts[result.verdict] = counts.get(result.verdict, 0) + 1

    print_line(console, "coverage of the technically checkable obligations", style="heading")
    for verdict in Verdict:
        count = counts.get(verdict, 0)
        line = Text(f"  {verdict.value:<15} ", style=verdict_style(verdict))
        line.append(str(count), style=count_style(count))
        print_text(console, line)
    typer.echo("")

    failing = sorted(
        (r for r in report.results if r.verdict is Verdict.FAIL), key=lambda r: r.check.id
    )
    if failing:
        print_line(console, "failing:", style="heading")
        id_w = max(len(r.check.id) for r in failing)
        for result in failing:
            line = Text("  ")
            line.append_text(accent_text(result.check.id.ljust(id_w)))
            line.append("  ")
            severity = result.check.severity
            line.append(f"{severity.value:<8}", style=severity_style(severity))
            line.append(f"  {result.check.title}")
            print_text(console, line)
        typer.echo("")

    if outcome.applied:
        print_line(
            console, "relaxed (covered by a declared, unexpired relaxation):", style="heading"
        )
        for relaxation in outcome.applied:
            line = Text("  ")
            line.append_text(accent_text(relaxation.check_id))
            line.append(f"  expires {relaxation.expires}  {relaxation.reason}")
            print_text(console, line)
        typer.echo("")

    if outcome.expired:
        print_line(
            console, "expired relaxations (lapsed - no longer applied):", style="verdict.warn"
        )
        for relaxation in outcome.expired:
            line = Text("  ")
            line.append_text(accent_text(relaxation.check_id))
            line.append(f"  expired {relaxation.expires}")
            print_text(console, line)
        typer.echo("")

    if report.relaxed_critical:
        # `sev.critical` (bold red, spec §2) - the same treatment `audit`
        # gives a critical finding, because that is exactly what this is:
        # a critical finding, waived rather than fixed.
        print_line(
            console,
            "a critical finding was relaxed, not fixed - it is waived, not resolved",
            style="sev.critical",
        )
        typer.echo("")

    print_line(
        console,
        f"not_assessed ({len(resolution.not_assessed)} items outside this tool's reach):",
        style="heading",
    )
    if resolution.not_assessed:
        for item in resolution.not_assessed:
            typer.echo(f"  - {item}")
    else:
        typer.echo("  (none declared by the active profile(s))")
    typer.echo("")

    print_line(console, DISCLAIMER, style="heading")


# --- relax -------------------------------------------------------------------


def _toml_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _render_relaxation_block(
    check_id: str, reason: str, expires: str, tools: tuple[str, ...]
) -> str:
    lines = [
        f"\n[policy.relax.{check_id}]",
        f"reason = {_toml_string(reason)}",
        f"expires = {_toml_string(expires)}",
    ]
    if tools:
        rendered = ", ".join(_toml_string(t) for t in tools)
        lines.append(f"tools = [{rendered}]")
    return "\n".join(lines) + "\n"


def relax(
    check_id: Annotated[str, typer.Argument(help="Check id to relax, e.g. B2.")],
    reason: Annotated[str, typer.Option("--reason", help="Why this deviation is justified.")],
    expires: Annotated[
        str,
        typer.Option("--expires", help="ISO date (YYYY-MM-DD) this relaxation lapses."),
    ],
    tools: Annotated[
        list[str] | None,
        typer.Option("--tools", help="Restrict to these subjects. Omit for project-wide."),
    ] = None,
    directory: Annotated[
        Path | None, typer.Option("--directory", "-d", help="Project to change.")
    ] = None,
) -> None:
    """Write a justified, expiring relaxation for one check into toolseal.toml.

    Hand-editing `[policy.relax.<ID>]` is where people get it wrong - a
    mistyped id, an omitted expiry, the wrong scope (§6). This validates the
    check exists and that both `reason` and `expires` are present *before*
    writing anything, so the safe path is also the easy one.
    """
    root = (directory or Path.cwd()).resolve()

    matched = _find_check(check_id)
    if matched is None:
        message = f"no check named {check_id!r}; try `toolseal policy list`"
        raise UsageError(message)

    # §8: `enforce` seals the resolved policy and marks every check
    # non-relaxable while sealed - this is the hook P47 left open. A sealed
    # check is refused rather than silently accepted, naming the lock so the
    # fix (`enforce --release`) is obvious rather than merely "no".
    sealing_lock = policy_lock.sealed_check(root, matched.id)
    if sealing_lock is not None:
        message = (
            f"{matched.id} is sealed by {policy_lock.LOCK_DIR}/{policy_lock.LOCK_NAME}; "
            "run `toolseal policy enforce --release` before relaxing it"
        )
        raise UsageError(message)

    if not reason.strip():
        message = "relax requires a non-empty --reason"
        raise UsageError(message)

    try:
        parsed_expiry = date.fromisoformat(expires)
    except ValueError:
        message = f"--expires must be an ISO date (YYYY-MM-DD), found {expires!r}"
        raise UsageError(message) from None

    manifest_path = root / MANIFEST_NAME
    if not manifest_path.is_file():
        message = f"no {MANIFEST_NAME} found in {root}; run `toolseal init` first"
        raise UsageError(message)

    text = manifest_path.read_text(encoding="utf-8")
    existing = parse_relaxations(text)
    if any(r.check_id == matched.id for r in existing):
        message = (
            f"{matched.id} already has a relaxation in {MANIFEST_NAME}; edit or remove the "
            f"existing [policy.relax.{matched.id}] block first"
        )
        raise UsageError(message)

    block = _render_relaxation_block(matched.id, reason.strip(), expires, tuple(tools or ()))
    new_text = (text if text.endswith("\n") else text + "\n") + block

    # `parse_relaxations` is `relax.py`'s own parser - re-running it on what
    # was just written is the round-trip proof that the block is well
    # formed, not merely well intentioned.
    parse_relaxations(new_text)
    manifest_path.write_text(new_text, encoding="utf-8")

    line = Text("Relaxed ", style="verdict.good")
    line.append_text(accent_text(matched.id))
    line.append(f" until {parsed_expiry.isoformat()}.", style="verdict.good")
    print_text(console, line)
    typer.echo(f"  reason: {reason.strip()}")
    typer.echo(f"  scope: {', '.join(tools) if tools else 'project-wide'}")


# --- enforce / verify: the policy lock (spec §8) ------------------------------


def enforce(
    release: Annotated[
        bool,
        typer.Option("--release", help="Unseal instead of sealing - requires this explicit flag."),
    ] = False,
    directory: Annotated[
        Path | None, typer.Option("--directory", "-d", help="Project to seal or unseal.")
    ] = None,
) -> None:
    """Seal the resolved policy, or unseal it with `--release`.

    Sealing writes `.toolseal/policy.lock` (the resolved severities, active
    profiles, declared relaxations, and every check id `relax` will refuse to
    act on) and sets that file read-only. Read-only is a speed bump, not a
    boundary: anyone who can run the agent can clear it. `toolseal policy
    verify` - run in CI, where that is not true - is the check that actually
    holds.
    """
    root = (directory or Path.cwd()).resolve()

    if release:
        _release(root)
        return

    _seal(root)


def _seal(root: Path) -> None:
    if Manifest.load(root) is None:
        message = f"no {MANIFEST_NAME} found in {root}; run `toolseal init` first"
        raise UsageError(message)

    if policy_lock.is_sealed(root):
        message = (
            f"{policy_lock.LOCK_DIR}/{policy_lock.LOCK_NAME} already exists; run "
            "`toolseal policy enforce --release` first, or `toolseal policy verify` to check it"
        )
        raise UsageError(message)

    sealed = policy_lock.seal(root)

    print_line(console, f"Sealed {len(sealed.non_relaxable)} checks.", style="verdict.good")
    if sealed.profiles:
        typer.echo(f"  profiles: {', '.join(sealed.profiles)}")
    typer.echo(f"  wrote {policy_lock.LOCK_DIR}/{policy_lock.LOCK_NAME} (read-only)")
    hash_line = Text("  hash: ")
    hash_line.append_text(accent_text(sealed.policy_hash))
    print_text(console, hash_line)
    typer.echo("")
    typer.echo(policy_lock.TAMPER_EVIDENT_NOTICE)
    typer.echo("")
    typer.echo("`toolseal policy verify` is already a pre-commit hook if this project's")
    typer.echo(".pre-commit-config.yaml came from `toolseal init`. Add it to CI too - that")
    typer.echo("is where this lock actually holds, not the read-only bit on a developer's")
    typer.echo("machine. Example step:")
    typer.echo(policy_lock.CI_VERIFY_STEP_EXAMPLE)


def _release(root: Path) -> None:
    if not policy_lock.is_sealed(root):
        message = (
            f"no {policy_lock.LOCK_DIR}/{policy_lock.LOCK_NAME} found in {root}; nothing to release"
        )
        raise UsageError(message)

    policy_lock.release(root)

    print_line(console, "Unsealed.", style="verdict.good")
    typer.echo(f"  removed {policy_lock.LOCK_DIR}/{policy_lock.LOCK_NAME}")
    typer.echo("  `toolseal policy relax` can act on any check again.")


def verify(
    directory: Annotated[
        Path | None, typer.Option("--directory", "-d", help="Project to check.")
    ] = None,
) -> None:
    """Re-derive the policy and compare it against what was sealed.

    Exit 0 when nothing is sealed, or when nothing has drifted. Non-zero the
    moment either the lock file itself or the underlying `toolseal.toml` no
    longer matches what `enforce` recorded - and the output names the field
    that changed, not merely that something did. This is the check meant to
    run unconditionally in CI and as a pre-commit hook: it is safe to add to
    both before a project has ever run `enforce`.
    """
    root = (directory or Path.cwd()).resolve()
    report = policy_lock.verify(root)

    if not report.sealed:
        typer.echo(f"no {policy_lock.LOCK_DIR}/{policy_lock.LOCK_NAME} found; nothing sealed.")
        typer.echo("Run `toolseal policy enforce` to seal the current policy.")
        raise typer.Exit(ExitCode.OK)

    if not report.drifted:
        print_line(
            console, "No drift: the sealed policy still matches the project.", style="verdict.good"
        )
        raise typer.Exit(ExitCode.OK)

    # `sev.critical` (bold red, spec §2): a tampered or drifted lock is
    # exactly the severity of event this token exists to mark.
    print_line(console, "Drift detected.", style="sev.critical")
    if report.lock_tampered:
        typer.echo(
            f"  {policy_lock.LOCK_DIR}/{policy_lock.LOCK_NAME} was edited directly: its "
            "recorded hash no longer matches its own recorded content."
        )
    for line in report.profile_changes:
        typer.echo(f"  {line}")
    for line in report.severity_changes:
        typer.echo(f"  {line}")
    for line in report.relaxation_changes:
        typer.echo(f"  {line}")
    for line in report.non_relaxable_changes:
        typer.echo(f"  {line}")
    typer.echo("")
    typer.echo(
        "If this drift is intentional: `toolseal policy enforce --release` then "
        "`toolseal policy enforce` to reseal. If it is not, treat it as a security "
        "finding - this is exactly what `verify` in CI exists to catch."
    )

    raise typer.Exit(ExitCode.FINDINGS)


policy_app.command("list")(error_boundary(list_standards))
policy_app.command("explain")(error_boundary(explain))
policy_app.command("show")(error_boundary(show))
policy_app.command("apply")(error_boundary(apply_regime))
policy_app.command("check")(error_boundary(check))
policy_app.command("relax")(error_boundary(relax))
policy_app.command("enforce")(error_boundary(enforce))
policy_app.command("verify")(error_boundary(verify))
