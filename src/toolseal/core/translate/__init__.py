"""Lifting into the descriptor, lowering out of it, and compensating the loss."""

from __future__ import annotations

from toolseal.core.translate.lattice import (
    ANNOTATION_PROPERTIES,
    PROFILES,
    AbstractionProfile,
    Evidence,
    Guard,
    GuardKind,
    SecurityProperty,
    TranslationPlan,
    plan_translation,
    profile,
)
from toolseal.core.translate.lift import (
    Lifted,
    from_framework_tool,
    from_mcp,
    round_trip_loss,
)
from toolseal.core.translate.lower import GuardCode, Lowering, guards_for, lower

__all__ = [
    "ANNOTATION_PROPERTIES",
    "PROFILES",
    "AbstractionProfile",
    "Evidence",
    "Guard",
    "GuardCode",
    "GuardKind",
    "Lifted",
    "Lowering",
    "SecurityProperty",
    "TranslationPlan",
    "from_framework_tool",
    "from_mcp",
    "guards_for",
    "lower",
    "plan_translation",
    "profile",
    "round_trip_loss",
]
