"""Check definitions, findings, and how a score is computed from them.

The taxonomy in `reference/taxonomy.md` is normative; this module is its
executable form. Every check declares the same four things the document does -
id, severity, detection, remediation - so a finding can always be traced back to
a written rule rather than to someone's opinion in code.

Two scoring decisions carry weight:

* **Inapplicable checks leave the denominator.** A project with no remote
  endpoint is not penalised for family D. Scoring it out of a total it could
  never reach would make the number meaningless and the tool annoying.
* **`blocking` is reported separately from the score.** A severity-weighted
  average can hide one critical finding behind a long tail of passes, so the
  presence of a critical failure is surfaced on its own and never averaged away.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from toolseal.core.model import ProjectModel


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def weight(self) -> int:
        return _WEIGHTS[self]


_WEIGHTS: Final[dict[Severity, int]] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 6,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
}


class Verdict(StrEnum):
    PASS = "pass"  # noqa: S105 - a verdict, not a credential
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"
    """The check could not run - missing advisory data, for instance.

    Distinct from `pass` on purpose: "we did not look" must never be reported as
    "we looked and it was fine".
    """


@dataclass(frozen=True)
class Finding:
    """One concrete defect, located precisely enough to fix."""

    check_id: str
    severity: Severity
    title: str
    detail: str
    location: str | None = None
    line: int | None = None
    remediation: str = ""


@dataclass(frozen=True)
class Check:
    """One rule from the taxonomy, in executable form."""

    id: str
    family: str
    title: str
    severity: Severity
    remediation: str
    run: Callable[[ProjectModel], Sequence[Finding]]
    applies: Callable[[ProjectModel], bool] = lambda _model: True

    def evaluate(self, model: ProjectModel) -> CheckResult:
        if not self.applies(model):
            return CheckResult(self, Verdict.NOT_APPLICABLE, ())
        findings = tuple(self.run(model))
        verdict = Verdict.FAIL if findings else Verdict.PASS
        return CheckResult(self, verdict, findings)


@dataclass(frozen=True)
class CheckResult:
    check: Check
    verdict: Verdict
    findings: tuple[Finding, ...]

    @property
    def counts_towards_score(self) -> bool:
        return self.verdict in (Verdict.PASS, Verdict.FAIL)


@dataclass(frozen=True)
class FamilyScore:
    family: str
    score: int
    passed: int
    failed: int
    not_applicable: int
    unknown: int


@dataclass(frozen=True)
class AuditReport:
    """Everything an audit produced, ready for any reporter to render."""

    root: str
    results: tuple[CheckResult, ...] = ()

    @property
    def findings(self) -> tuple[Finding, ...]:
        """All findings, most severe first, then by check id for stability."""
        order = list(Severity)
        return tuple(
            sorted(
                (finding for result in self.results for finding in result.findings),
                key=lambda f: (order.index(f.severity), f.check_id),
            )
        )

    @property
    def blocking(self) -> bool:
        """Whether any critical check failed. Reported apart from the score."""
        return any(
            result.verdict is Verdict.FAIL and result.check.severity is Severity.CRITICAL
            for result in self.results
        )

    @property
    def score(self) -> int:
        return _score(self.results)

    def family_scores(self) -> tuple[FamilyScore, ...]:
        families: dict[str, list[CheckResult]] = {}
        for result in self.results:
            families.setdefault(result.check.family, []).append(result)

        return tuple(
            FamilyScore(
                family=family,
                score=_score(results),
                passed=sum(1 for r in results if r.verdict is Verdict.PASS),
                failed=sum(1 for r in results if r.verdict is Verdict.FAIL),
                not_applicable=sum(1 for r in results if r.verdict is Verdict.NOT_APPLICABLE),
                unknown=sum(1 for r in results if r.verdict is Verdict.UNKNOWN),
            )
            for family, results in sorted(families.items())
        )


def _score(results: Sequence[CheckResult]) -> int:
    """Severity-weighted pass rate over applicable checks, as a percentage."""
    applicable = [r for r in results if r.counts_towards_score]
    total = sum(r.check.severity.weight for r in applicable)
    if total == 0:
        # Nothing applied. 100 would claim an assurance that was never tested.
        return 100
    lost = sum(r.check.severity.weight for r in applicable if r.verdict is Verdict.FAIL)
    return round(100 * (1 - lost / total))


_REGISTRY: dict[str, Check] = {}


def register(check: Check) -> Check:
    """Add *check* to the registry, refusing a duplicate id.

    Identifiers are permanent and never reused, so a collision is a mistake
    rather than an override.
    """
    if check.id in _REGISTRY:
        message = f"check {check.id} is already registered"
        raise ValueError(message)
    _REGISTRY[check.id] = check
    return check


def all_checks() -> tuple[Check, ...]:
    return tuple(_REGISTRY[key] for key in sorted(_REGISTRY))


def checks_in(family: str) -> tuple[Check, ...]:
    return tuple(check for check in all_checks() if check.family == family)
