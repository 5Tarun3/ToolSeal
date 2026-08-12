"""Running every check against a project model.

A check that raises is a bug in the check, not a verdict on the project. Rather
than aborting the audit - which would let one defective rule suppress every
other finding - the failure is recorded as `unknown` for that check alone and
everything else still reports.
"""

from __future__ import annotations

import logging
from pathlib import Path

from toolseal.core.audit.extract import extract
from toolseal.core.model import ProjectModel
from toolseal.core.policy import all_checks
from toolseal.core.policy.model import AuditReport, CheckResult, Verdict

log = logging.getLogger(__name__)


def audit_model(model: ProjectModel) -> AuditReport:
    """Evaluate every registered check against *model*."""
    results: list[CheckResult] = []

    for check in all_checks():
        try:
            results.append(check.evaluate(model))
        except Exception:
            # Broad by design: one broken check must not silence the rest.
            log.exception("check %s raised; reporting it as unknown", check.id)
            results.append(CheckResult(check, Verdict.UNKNOWN, ()))

    return AuditReport(root=str(model.root), results=tuple(results))


def audit(root: Path) -> AuditReport:
    """Extract the project at *root* and evaluate every check against it."""
    return audit_model(extract(root))
