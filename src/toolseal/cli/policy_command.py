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

from toolseal.cli._columns import col_width
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

    rows = []
    for key in sorted(catalogues):
        catalogue = catalogues[key]
        report = coverage_for(key)
        marker = "" if report.complete_enumeration else "*"
        rows.append(
            (
                key,
                f"{report.percentage}%{marker}",
                f"{report.covered}/{report.checkable_total}",
                catalogue.name,
            )
        )

    standard_w = col_width("standard", (row[0] for row in rows))
    coverage_w = col_width("coverage", (row[1] for row in rows))
    checkable_w = col_width("checkable", (row[2] for row in rows))

    typer.secho(
        f"{'standard'.ljust(standard_w)}  {'coverage'.rjust(coverage_w)}  "
        f"{'checkable'.rjust(checkable_w)}  name",
        bold=True,
    )

    partial_seen = False
    for key, coverage, checkable, name in rows:
        if "*" in coverage:
            partial_seen = True
        typer.echo(
            f"{key.ljust(standard_w)}  {coverage.rjust(coverage_w)}  "
            f"{checkable.rjust(checkable_w)}  {name}"
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
    rows = [
        (check.id, check.severity.value, _severity_source(check.id, resolution))
        for check in resolution.checks
    ]

    id_w = col_width("check", (r[0] for r in rows))
    sev_w = col_width("severity", (r[1] for r in rows))
    src_w = col_width("source", (r[2] for r in rows))

    typer.secho(
        f"{'check'.ljust(id_w)}  {'severity'.ljust(sev_w)}  {'source'.ljust(src_w)}",
        bold=True,
    )
    for check_id, severity, source in rows:
        marker = " (relaxed - see below)" if check_id in relaxed_ids else ""
        typer.echo(
            f"{check_id.ljust(id_w)}  {severity.ljust(sev_w)}  {source.ljust(src_w)}{marker}"
        )

    _print_relaxations_table(relaxations)


def _show_tool(
    root: Path,
    tool: str,
    manifest: Manifest | None,
    resolution: Resolution,
    relaxations: tuple[Relaxation, ...],
) -> None:
    typer.secho(f"policy for {tool}", bold=True)
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
            severity = by_id[finding.check_id].severity.value
            source = _severity_source(finding.check_id, resolution)
            typer.echo(f"  {finding.check_id}  {severity}  ({source})  {finding.title}")
    else:
        typer.echo(f"no current findings name {tool}")


def _print_relaxations_table(relaxations: Sequence[Relaxation]) -> None:
    if not relaxations:
        typer.echo("relaxations declared: none")
        return

    today = date.today()
    for relaxation in relaxations:
        status = "expired" if relaxation.is_expired(today) else "active"
        scope = ", ".join(relaxation.tools) if relaxation.tools else "project-wide"
        typer.echo(
            f"  {relaxation.check_id}  expires {relaxation.expires}  ({status})  "
            f"scope: {scope}  reason: {relaxation.reason}"
        )


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
    typer.secho(f"\nApplied {regime}.", fg=typer.colors.GREEN)


def _print_apply_diff(
    regime: str,
    profile: Profile,
    manifest: Manifest,
    before: Resolution,
    after: Resolution,
) -> None:
    typer.secho(f"Adopting {regime} ({profile.name})", bold=True)
    if profile.source:
        typer.echo(f"  source: {profile.source}")
    if profile.source_url:
        typer.echo(f"  {profile.source_url}")
    typer.echo("")

    before_by_id = {check.id: check for check in before.checks}
    changed = sorted(
        (check.id, before_by_id[check.id].severity.value, check.severity.value)
        for check in after.checks
        if check.id in before_by_id and before_by_id[check.id].severity != check.severity
    )
    typer.echo("severity changes:")
    if changed:
        id_w = max(len(row[0]) for row in changed)
        for check_id, old, new in changed:
            typer.echo(f"  {check_id.ljust(id_w)}  {old} -> {new}")
    else:
        typer.echo("  none")
    typer.echo("")

    require_changes = [
        (key, manifest.approval_required_for_destructive, wanted)
        for key, wanted in profile.require.items()
        if key == "policy.approval_required_for_destructive"
        and manifest.approval_required_for_destructive != wanted
    ]
    typer.echo("settings:")
    if require_changes:
        for setting_key, was, now in require_changes:
            typer.echo(f"  {setting_key}: {was} -> {now}")
    else:
        typer.echo("  none")

    if profile.not_assessed:
        typer.echo("")
        typer.echo(f"scope this regime does not reach ({len(profile.not_assessed)} items):")
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
    typer.echo(f"{root}\n")

    if profile_ids:
        typer.echo(f"profile: {', '.join(profile_ids)}")
    else:
        typer.echo("profile: none declared - showing baseline checks only")
    typer.echo("")

    counts: dict[Verdict, int] = {}
    for result in report.results:
        counts[result.verdict] = counts.get(result.verdict, 0) + 1

    typer.secho("coverage of the technically checkable obligations", bold=True)
    for verdict in Verdict:
        typer.echo(f"  {verdict.value:<15} {counts.get(verdict, 0)}")
    typer.echo("")

    failing = sorted(
        (r for r in report.results if r.verdict is Verdict.FAIL), key=lambda r: r.check.id
    )
    if failing:
        typer.echo("failing:")
        id_w = max(len(r.check.id) for r in failing)
        for result in failing:
            typer.echo(
                f"  {result.check.id.ljust(id_w)}  {result.check.severity.value:<8}  "
                f"{result.check.title}"
            )
        typer.echo("")

    if outcome.applied:
        typer.echo("relaxed (covered by a declared, unexpired relaxation):")
        for relaxation in outcome.applied:
            typer.echo(
                f"  {relaxation.check_id}  expires {relaxation.expires}  {relaxation.reason}"
            )
        typer.echo("")

    if outcome.expired:
        typer.secho("expired relaxations (lapsed - no longer applied):", fg=typer.colors.YELLOW)
        for relaxation in outcome.expired:
            typer.echo(f"  {relaxation.check_id}  expired {relaxation.expires}")
        typer.echo("")

    if report.relaxed_critical:
        typer.secho(
            "a critical finding was relaxed, not fixed - it is waived, not resolved",
            fg=typer.colors.RED,
            bold=True,
        )
        typer.echo("")

    typer.echo(f"not_assessed ({len(resolution.not_assessed)} items outside this tool's reach):")
    if resolution.not_assessed:
        for item in resolution.not_assessed:
            typer.echo(f"  - {item}")
    else:
        typer.echo("  (none declared by the active profile(s))")
    typer.echo("")

    typer.secho(DISCLAIMER, bold=True)


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

    typer.secho(f"Relaxed {matched.id} until {parsed_expiry.isoformat()}.", fg=typer.colors.GREEN)
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

    typer.secho(f"Sealed {len(sealed.non_relaxable)} checks.", fg=typer.colors.GREEN)
    if sealed.profiles:
        typer.echo(f"  profiles: {', '.join(sealed.profiles)}")
    typer.echo(f"  wrote {policy_lock.LOCK_DIR}/{policy_lock.LOCK_NAME} (read-only)")
    typer.echo(f"  hash: {sealed.policy_hash}")
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

    typer.secho("Unsealed.", fg=typer.colors.GREEN)
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
        typer.secho("No drift: the sealed policy still matches the project.", fg=typer.colors.GREEN)
        raise typer.Exit(ExitCode.OK)

    typer.secho("Drift detected.", fg=typer.colors.RED, bold=True)
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
