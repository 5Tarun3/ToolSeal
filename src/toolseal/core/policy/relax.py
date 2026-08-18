"""Justified deviations from the baseline, parsed from `toolseal.toml` (§6).

Every relaxation is a recorded, expiring exception, never a way to make a
finding vanish. `toolseal.toml` carries them:

```toml
[policy.relax.B2]
reason = "CI runner needs shell; container-isolated, no network egress"
expires = "2026-12-31"
tools = ["ci_shell"]        # omit for project-wide
```

`reason` and `expires` are both mandatory - a relaxation that never lapses is a
permanent hole with a note attached - and a relaxation naming an unknown check
id is refused rather than silently ignored. This is the same discipline the
existing `# toolseal:allow <ID> - reason` line comment already applies to one
line, extended to a project (see `policy/suppress.py`).

Where `policy/profile.py` resolves *before* the audit engine runs (it edits the
check set), relaxation resolves *after*: `apply_relaxations` takes the
`AuditReport` the engine actually produced and turns a covered `FAIL` into
`Verdict.RELAXED`, because whether a relaxation applies depends on the
concrete findings a check produced - specifically, on `Finding.subject`, which
is exactly what per-tool relaxation (`tools = [...]`) matches against. A
relaxation that names no tools is project-wide and covers every finding on its
check id; a relaxation naming tools covers only the findings whose subject
matches, so a check keeps failing on the parts a relaxation does not name.

No field records who approved a relaxation. Attribution belongs in version
control (§6) - this module carries no personally identifying data.
"""

from __future__ import annotations

import tomllib
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date
from typing import Any

from toolseal.core.manifest import MANIFEST_NAME
from toolseal.core.policy.model import AuditReport, CheckResult, Verdict, all_checks
from toolseal.errors import ConfigError


@dataclass(frozen=True)
class Relaxation:
    """One justified, time-boxed deviation from a check."""

    check_id: str
    reason: str
    expires: date
    tools: tuple[str, ...] = ()
    """Which subjects this relaxation covers. Empty means project-wide - every
    finding on `check_id` is covered, not only ones naming a subject."""

    def is_expired(self, today: date) -> bool:
        return today > self.expires

    def covers(self, subject: str | None) -> bool:
        """Whether this relaxation applies to a finding naming *subject*."""
        if not self.tools:
            return True
        return subject in self.tools


@dataclass(frozen=True)
class RelaxationOutcome:
    """What happened when a project's declared relaxations met an audit report."""

    report: AuditReport
    """The report with every covered, unexpired failure turned into `RELAXED`."""

    applied: tuple[Relaxation, ...]
    """Relaxations that actually changed a verdict."""

    expired: tuple[Relaxation, ...]
    """Relaxations that would have applied but have lapsed - named here so a
    report can say so by name rather than resuming as an ordinary, unexplained
    failure."""


def _parse_expires(value: Any, *, check_id: str) -> date:
    if not isinstance(value, str):
        found = type(value).__name__
        message = f"relaxation for {check_id} field 'expires' must be a date string, found {found}"
        raise ConfigError(message)
    try:
        return date.fromisoformat(value)
    except ValueError:
        message = f"relaxation for {check_id} field 'expires' is not a valid date: {value!r}"
        raise ConfigError(message) from None


def _parse_tools(value: Any, *, check_id: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        message = f"relaxation for {check_id} field 'tools' must be a list of strings"
        raise ConfigError(message)
    return tuple(value)


def _known_check_ids() -> frozenset[str]:
    return frozenset(check.id for check in all_checks())


def parse_relaxations(
    text: str, *, known_check_ids: frozenset[str] | None = None
) -> tuple[Relaxation, ...]:
    """Parse every `[policy.relax.<ID>]` block in *text* (a `toolseal.toml` document).

    *known_check_ids* defaults to the live registry so a real manifest is
    always validated against the taxonomy as it exists today; tests pass a
    small fixed set instead.
    """
    try:
        data: dict[str, Any] = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        message = f"{MANIFEST_NAME} is not valid TOML: {exc}"
        raise ConfigError(message) from None

    known = known_check_ids if known_check_ids is not None else _known_check_ids()

    policy = data.get("policy") or {}
    if not isinstance(policy, dict):
        message = "[policy] must be a table"
        raise ConfigError(message)
    raw_relax = policy.get("relax") or {}
    if not isinstance(raw_relax, dict):
        message = "[policy.relax] must be a table of check ids"
        raise ConfigError(message)

    relaxations: list[Relaxation] = []
    for check_id, block in raw_relax.items():
        if check_id not in known:
            message = f"relaxation names unknown check {check_id!r}"
            raise ConfigError(message)
        if not isinstance(block, dict):
            message = f"[policy.relax.{check_id}] must be a table"
            raise ConfigError(message)

        reason = block.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            message = f"relaxation for {check_id} is missing required field 'reason'"
            raise ConfigError(message)

        if "expires" not in block:
            message = f"relaxation for {check_id} is missing required field 'expires'"
            raise ConfigError(message)
        expires = _parse_expires(block["expires"], check_id=check_id)

        tools = _parse_tools(block.get("tools", []), check_id=check_id)

        relaxations.append(
            Relaxation(check_id=check_id, reason=reason.strip(), expires=expires, tools=tools)
        )

    return tuple(sorted(relaxations, key=lambda r: r.check_id))


def apply_relaxations(
    report: AuditReport, relaxations: Sequence[Relaxation], *, today: date | None = None
) -> RelaxationOutcome:
    """Overlay *relaxations* onto *report*, turning covered failures into `RELAXED`.

    Only `FAIL` results are touched - a passing check has nothing to relax, and
    `NOT_APPLICABLE`/`UNKNOWN` are states relaxation has no opinion about. An
    expired relaxation is recorded in `RelaxationOutcome.expired` and left to
    keep failing, exactly as if it had never been declared, so lapsing is
    visible rather than a silent resumption of red.
    """
    as_of = today if today is not None else date.today()
    by_check = {relaxation.check_id: relaxation for relaxation in relaxations}

    applied: list[Relaxation] = []
    expired: list[Relaxation] = []
    new_results: list[CheckResult] = []

    for result in report.results:
        relaxation = by_check.get(result.check.id)
        if relaxation is None or result.verdict is not Verdict.FAIL:
            new_results.append(result)
            continue

        if relaxation.is_expired(as_of):
            expired.append(relaxation)
            new_results.append(result)
            continue

        remaining = tuple(
            finding for finding in result.findings if not relaxation.covers(finding.subject)
        )
        if remaining:
            # A relaxation naming specific tools covers only their findings; a
            # finding on an unnamed subject keeps the check failing.
            new_results.append(CheckResult(result.check, Verdict.FAIL, remaining))
        else:
            applied.append(relaxation)
            new_results.append(CheckResult(result.check, Verdict.RELAXED, result.findings))

    return RelaxationOutcome(
        report=AuditReport(root=report.root, results=tuple(new_results)),
        applied=tuple(applied),
        expired=tuple(expired),
    )
