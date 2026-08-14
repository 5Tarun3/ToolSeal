"""How much of a published standard a configuration auditor can actually reach.

The matrix has two margins and both are results.

A *checkable* control with no check is a scope boundary - an honest statement
of what this tool does not reach. A check with no control is either finding a
gap ahead of the standards or is an opinion; the project's risk table names
"taxonomy reads as arbitrary" as a high severity risk, and this is where that
gets measured rather than argued.

Coverage is computed over checkable controls only. Scoring against controls no
configuration file could ever satisfy - workforce training, signed agreements -
would produce a number that says more about the standard's breadth than about
this tool.

Not every catalogue's denominator is the whole standard, though. Some were
drawn up as curated subsets before any check mapping existed. `CoverageReport`
carries `complete_enumeration` through from the catalogue so a percentage is
never presented without saying which kind of denominator produced it.

What "covered" means is narrower than it sounds, and worth being explicit
about: `ControlCoverage.is_covered` is `bool(self.check_ids)` — a control
counts as covered the moment one check cites it. That citation is not evidence
the check adequately discharges the obligation, only that someone judged it
relevant enough to reference. A coverage percentage says how much of a
standard has a check pointed at it, not how well any obligation is met; the
latter is not something this module measures, and nothing here should be read
as claiming it does.
"""

from __future__ import annotations

from dataclasses import dataclass

from toolseal.core.policy.controls import Catalogue, Control, load_catalogues
from toolseal.core.policy.model import Check, all_checks
from toolseal.errors import ConfigError


@dataclass(frozen=True)
class ControlCoverage:
    """One control, and the checks that bear on it."""

    control: Control
    standard: str
    check_ids: tuple[str, ...] = ()

    @property
    def is_covered(self) -> bool:
        return bool(self.check_ids)


@dataclass(frozen=True)
class CoverageReport:
    """What one standard's checkable controls look like against the taxonomy."""

    standard: str
    catalogue_name: str
    entries: tuple[ControlCoverage, ...] = ()
    unmapped_checks: tuple[str, ...] = ()
    complete_enumeration: bool = False
    """Copied from the catalogue: whether `checkable_total` is the standard's
    full checkable list, or a curated subset. A consumer formatting
    `percentage` alongside other standards' percentages must see this - a
    100% over a curated subset and a 100% over the full standard are not the
    same claim."""

    @property
    def checkable_total(self) -> int:
        return len(self.entries)

    @property
    def covered(self) -> int:
        return sum(1 for entry in self.entries if entry.is_covered)

    @property
    def percentage(self) -> int:
        if self.checkable_total == 0:
            # Nothing assessable. 100 would claim an assurance never tested.
            return 0
        return round(100 * self.covered / self.checkable_total)

    @property
    def uncovered(self) -> tuple[ControlCoverage, ...]:
        return tuple(entry for entry in self.entries if not entry.is_covered)


def _catalogue(standard: str) -> Catalogue:
    catalogues = load_catalogues()
    found = catalogues.get(standard)
    if found is None:
        known = ", ".join(sorted(catalogues)) or "none"
        message = f"unknown standard {standard!r}; loaded catalogues: {known}"
        raise ConfigError(message)
    return found


def unmapped_checks() -> tuple[Check, ...]:
    """Checks citing no external control at all."""
    return tuple(check for check in all_checks() if not check.controls)


def coverage_for(standard: str) -> CoverageReport:
    """Coverage of *standard*'s checkable controls by the current taxonomy."""
    catalogue = _catalogue(standard)

    covering: dict[str, list[str]] = {}
    for check in all_checks():
        for ref in check.controls:
            if ref.standard == standard:
                covering.setdefault(ref.control, []).append(check.id)

    entries = tuple(
        ControlCoverage(
            control=control,
            standard=standard,
            check_ids=tuple(sorted(covering.get(control.id, ()))),
        )
        for control in catalogue.checkable()
    )

    return CoverageReport(
        standard=standard,
        catalogue_name=catalogue.name,
        entries=entries,
        unmapped_checks=tuple(check.id for check in unmapped_checks()),
        complete_enumeration=catalogue.complete_enumeration,
    )
