"""The taxonomy in executable form.

Importing this package registers every check, so the engine can enumerate them
without knowing which module defines which family.
"""

from __future__ import annotations

from toolseal.core.policy import (  # noqa: F401  (registration side effect)
    family_a,
    family_b,
    family_c,
    family_def,
    family_g,
)
from toolseal.core.policy.model import (
    AuditReport,
    Check,
    CheckResult,
    FamilyScore,
    Finding,
    Severity,
    Verdict,
    all_checks,
    checks_in,
    register,
)

__all__ = [
    "AuditReport",
    "Check",
    "CheckResult",
    "FamilyScore",
    "Finding",
    "Severity",
    "Verdict",
    "all_checks",
    "checks_in",
    "register",
]
