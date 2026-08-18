"""Policy profiles: declarative overlays over the 28-check baseline.

A profile selects nothing by inventing new checks - it is data layered over the
taxonomy, and both kinds share one shape (`docs/superpowers/specs/
2026-08-13-standards-compliance-policy-design.md` §5):

* ``kind = "standard"``  a catalogue mapped *to* (OWASP, NIST AI RMF, ...);
* ``kind = "regime"``    an overlay run *under* (GDPR, HIPAA, DORA, ...).

Resolution (`resolve`) produces a modified check set **before the audit engine
runs**: it takes the baseline checks and zero or more active profiles and
returns new `Check` objects with adjusted severities. `audit/engine.py` is
never told a profile exists - it only ever sees a tuple of `Check`. This module
owns the one place a severity can be raised by policy rather than by a check's
own definition.

Two rules are load-bearing:

* **A profile may not weaken the baseline.** Lowering a severity is rejected at
  load time, with the profile id and the check id named in the error.
  Weakening is exclusively relaxation's job (`policy/relax.py`), because
  relaxation demands a reason and an expiry and a profile file carries neither.
* **Conflicts resolve strictest-wins, and the report names the winner.** When
  two active profiles disagree on a severity, the higher one is taken, and
  `SeverityDecision.winner` records which profile set it - never silently.

Regime files ship under `toolseal.data.regimes` as data, read the same way
`policy/controls.py` reads `toolseal.data.standards`: through
`importlib.resources`, so this works from an installed wheel as well as from a
checkout. P45 adds the three regime files this package carries: GDPR, HIPAA
and DORA (`toolseal/data/regimes/{gdpr,hipaa,dora}.toml`).
"""

from __future__ import annotations

import tomllib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from importlib import resources
from typing import Any, Final

from toolseal.core.policy.model import Check, Severity, all_checks
from toolseal.errors import ConfigError

DATA_PACKAGE: Final = "toolseal.data.regimes"

VALID_KINDS: Final = frozenset({"standard", "regime"})

# Ordinal ranking used to compare severities without depending on `Severity`'s
# `.weight` (a scoring concept, not an ordering one - the two happen to agree
# today, but "may not weaken" is about rank, not about score contribution).
_RANK: Final[dict[Severity, int]] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


@dataclass(frozen=True)
class Profile:
    """One overlay: a standard mapped to, or a regime run under."""

    id: str
    kind: str
    name: str
    source: str = ""
    source_url: str = ""
    license: str = ""
    not_assessed: tuple[str, ...] = ()
    """Printed with every report produced under this profile (§5). A profile
    never emits an overall pass/fail for the regime it names - this is the
    honest list of what it does not reach."""

    severity: dict[str, Severity] = field(default_factory=dict)
    """Baseline check id -> the severity this profile pins it to. Only ever
    equal to or stricter than the baseline; `parse_profile` enforces that."""

    require: dict[str, Any] = field(default_factory=dict)
    """Settings this profile pins, e.g. `"policy.approval_required_for_destructive"
    -> True`. Carried as data; P44 does not interpret or enforce it."""


@dataclass(frozen=True)
class SeverityDecision:
    """Which profile's `[severity]` entry for one check id won, and why."""

    check_id: str
    severity: Severity
    winner: str
    """The id of the profile whose entry set the resolved severity."""


@dataclass(frozen=True)
class Resolution:
    """The baseline, overlaid by every active profile."""

    checks: tuple[Check, ...]
    decisions: tuple[SeverityDecision, ...]
    not_assessed: tuple[str, ...]


def _require(data: dict[str, Any], key: str, kind: type) -> Any:
    if key not in data:
        message = f"profile is missing required field {key!r}"
        raise ConfigError(message)
    value = data[key]
    if not isinstance(value, kind):
        found = type(value).__name__
        message = f"profile field {key!r} must be {kind.__name__}, found {found}"
        raise ConfigError(message)
    return value


def _baseline_severities() -> dict[str, Severity]:
    return {check.id: check.severity for check in all_checks()}


def _parse_not_assessed(data: dict[str, Any]) -> tuple[str, ...]:
    scope = data.get("scope") or {}
    if not isinstance(scope, dict):
        message = "profile field 'scope' must be a table"
        raise ConfigError(message)
    raw = scope.get("not_assessed", [])
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        message = "profile field 'scope.not_assessed' must be a list of strings"
        raise ConfigError(message)
    return tuple(raw)


def _parse_severity(
    data: dict[str, Any], *, profile_id: str, baseline: Mapping[str, Severity]
) -> dict[str, Severity]:
    raw = data.get("severity") or {}
    if not isinstance(raw, dict):
        message = "profile field 'severity' must be a table"
        raise ConfigError(message)

    resolved: dict[str, Severity] = {}
    for check_id, raw_value in raw.items():
        if not isinstance(raw_value, str):
            found = type(raw_value).__name__
            message = (
                f"profile {profile_id!r} severity for {check_id!r} must be a string, found {found}"
            )
            raise ConfigError(message)
        try:
            wanted = Severity(raw_value)
        except ValueError:
            valid = ", ".join(s.value for s in Severity)
            message = (
                f"profile {profile_id!r} sets {check_id} to unknown severity "
                f"{raw_value!r}; must be one of {valid}"
            )
            raise ConfigError(message) from None

        current = baseline.get(check_id)
        if current is None:
            message = f"profile {profile_id!r} references unknown check {check_id!r}"
            raise ConfigError(message)

        if _RANK[wanted] < _RANK[current]:
            message = (
                f"profile {profile_id!r} lowers {check_id} from {current.value} to "
                f"{wanted.value}; a profile may not weaken the baseline - that is what "
                "relaxation (with a mandatory reason and expiry) is for"
            )
            raise ConfigError(message)

        resolved[check_id] = wanted

    return resolved


def _parse_require(data: dict[str, Any]) -> dict[str, Any]:
    raw = data.get("require") or {}
    if not isinstance(raw, dict):
        message = "profile field 'require' must be a table"
        raise ConfigError(message)
    return dict(raw)


def parse_profile(text: str, *, baseline: Mapping[str, Severity] | None = None) -> Profile:
    """Parse one profile, rejecting anything that could weaken the baseline.

    *baseline* maps check id to its current severity; it defaults to the live
    registry (`all_checks()`) so a shipped profile is always validated against
    the taxonomy as it exists today. Tests pass a small fixed mapping so a
    profile fixture does not have to import the whole check registry.
    """
    try:
        data: dict[str, Any] = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        message = f"profile is not valid TOML: {exc}"
        raise ConfigError(message) from None

    profile_id = str(_require(data, "id", str))
    kind = str(_require(data, "kind", str))
    if kind not in VALID_KINDS:
        message = f"profile field 'kind' must be one of {sorted(VALID_KINDS)}, found {kind!r}"
        raise ConfigError(message)
    name = str(_require(data, "name", str))

    resolved_baseline = baseline if baseline is not None else _baseline_severities()

    return Profile(
        id=profile_id,
        kind=kind,
        name=name,
        source=str(data.get("source", "")),
        source_url=str(data.get("source_url", "")),
        license=str(data.get("license", "")),
        not_assessed=_parse_not_assessed(data),
        severity=_parse_severity(data, profile_id=profile_id, baseline=resolved_baseline),
        require=_parse_require(data),
    )


def load_profiles() -> dict[str, Profile]:
    """Every regime profile shipped with the package, keyed by id.

    Read through `importlib.resources`, mirroring
    `policy.controls.load_catalogues()`. P45 ships GDPR, HIPAA and DORA.
    """
    profiles: dict[str, Profile] = {}
    for entry in resources.files(DATA_PACKAGE).iterdir():
        if not entry.name.endswith(".toml"):
            continue
        profile = parse_profile(entry.read_text(encoding="utf-8"))
        if profile.id in profiles:
            message = f"two profiles both declare id {profile.id!r}"
            raise ConfigError(message)
        profiles[profile.id] = profile
    return profiles


def load_profile(profile_id: str) -> Profile:
    """The shipped profile named *profile_id*, or a `ConfigError` naming what's known."""
    profiles = load_profiles()
    found = profiles.get(profile_id)
    if found is None:
        known = ", ".join(sorted(profiles)) or "none"
        message = f"unknown profile {profile_id!r}; loaded profiles: {known}"
        raise ConfigError(message)
    return found


def resolve(profiles: Sequence[Profile], baseline: Iterable[Check] | None = None) -> Resolution:
    """Overlay *profiles* onto *baseline* (defaults to `all_checks()`).

    Strictest wins: when more than one profile pins a severity for the same
    check id, the highest is kept and `SeverityDecision.winner` names the
    profile that set it. A profile referencing a check id the baseline does
    not have is refused rather than silently ignored - the same rule
    `parse_profile` applies when a baseline is supplied at parse time, applied
    again here because `Profile` instances can also be built directly (by
    `toolseal policy apply`, for instance) without ever passing through
    `parse_profile`.
    """
    base_checks = tuple(baseline) if baseline is not None else all_checks()
    by_id = {check.id: check for check in base_checks}

    winning: dict[str, tuple[Severity, str]] = {}
    for profile in profiles:
        for check_id, wanted in profile.severity.items():
            if check_id not in by_id:
                message = f"profile {profile.id!r} references unknown check {check_id!r}"
                raise ConfigError(message)

            current = winning.get(check_id)
            if current is None or _RANK[wanted] > _RANK[current[0]]:
                winning[check_id] = (wanted, profile.id)

    resolved_checks = tuple(
        replace(check, severity=winning[check.id][0]) if check.id in winning else check
        for check in base_checks
    )

    decisions = tuple(
        SeverityDecision(check_id=check_id, severity=severity, winner=winner)
        for check_id, (severity, winner) in sorted(winning.items())
    )

    seen_not_assessed: dict[str, None] = {}
    for profile in profiles:
        for item in profile.not_assessed:
            seen_not_assessed[item] = None

    return Resolution(
        checks=resolved_checks,
        decisions=decisions,
        not_assessed=tuple(seen_not_assessed),
    )
