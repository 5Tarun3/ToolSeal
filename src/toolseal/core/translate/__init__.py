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

__all__ = [
    "ANNOTATION_PROPERTIES",
    "PROFILES",
    "AbstractionProfile",
    "Evidence",
    "Guard",
    "GuardKind",
    "SecurityProperty",
    "TranslationPlan",
    "plan_translation",
    "profile",
]
