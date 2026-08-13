"""What each tool abstraction can express, and what must be compensated.

A tool declares security properties at its source. Each target abstraction can
represent some subset of them. The difference is translation loss, and this
module is where that difference is computed rather than discovered in
production.

The entries below are **evidence-tagged**. Probe P0 measured the LangChain and
CrewAI rows against a live fixture server; the rest are read from specification
or reasoned from an abstraction's shape. A claim's strength is part of the
claim, so :class:`Evidence` travels with every entry and any analysis built on
this table can report how well grounded it is.

Adding an abstraction means adding a row. Rows tagged ``ASSUMED`` are invitations
to run a probe, not conclusions.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from toolseal.errors import UsageError


class SecurityProperty(StrEnum):
    """The vocabulary shared by descriptors, the lattice, and taxonomy family G.

    One vocabulary rather than three keeps measured evidence, audit findings and
    generated guards directly comparable.
    """

    READ_ONLY = "readOnlyHint"
    DESTRUCTIVE = "destructiveHint"
    IDEMPOTENT = "idempotentHint"
    OPEN_WORLD = "openWorldHint"
    INPUT_CONSTRAINTS = "inputConstraints"
    CLIENT_VALIDATION = "clientValidation"
    ERROR_CHANNEL = "errorChannel"
    DESCRIPTION_INTEGRITY = "descriptionIntegrity"


ANNOTATION_PROPERTIES = frozenset(
    {
        SecurityProperty.READ_ONLY,
        SecurityProperty.DESTRUCTIVE,
        SecurityProperty.IDEMPOTENT,
        SecurityProperty.OPEN_WORLD,
    }
)


class Evidence(StrEnum):
    """How a lattice entry is known."""

    MEASURED = "measured"
    SPECIFIED = "specified"
    ASSUMED = "assumed"


class GuardKind(StrEnum):
    """A behaviour emitted to stand in for a property the target cannot express."""

    ANNOTATE_SIDECAR = "annotate_sidecar"
    REQUIRE_APPROVAL = "require_approval"
    VALIDATE_INPUT = "validate_input"
    MAP_ERROR_CHANNEL = "map_error_channel"
    PRESERVE_DESCRIPTION = "preserve_description"


# Which guard restores which property. A property absent from this mapping
# cannot be compensated, and translation must report it as unsupported rather
# than pretend otherwise.
_COMPENSATION: dict[SecurityProperty, GuardKind] = {
    SecurityProperty.DESTRUCTIVE: GuardKind.REQUIRE_APPROVAL,
    SecurityProperty.READ_ONLY: GuardKind.ANNOTATE_SIDECAR,
    SecurityProperty.IDEMPOTENT: GuardKind.ANNOTATE_SIDECAR,
    SecurityProperty.OPEN_WORLD: GuardKind.ANNOTATE_SIDECAR,
    SecurityProperty.CLIENT_VALIDATION: GuardKind.VALIDATE_INPUT,
    SecurityProperty.ERROR_CHANNEL: GuardKind.MAP_ERROR_CHANNEL,
    SecurityProperty.DESCRIPTION_INTEGRITY: GuardKind.PRESERVE_DESCRIPTION,
}


@dataclass(frozen=True)
class AbstractionProfile:
    """One abstraction's expressive power, with the evidence behind it."""

    id: str
    display_name: str
    expressible: frozenset[SecurityProperty]
    evidence: Evidence
    note: str = ""

    def expresses(self, prop: SecurityProperty) -> bool:
        return prop in self.expressible


_ALL = frozenset(SecurityProperty)

PROFILES: dict[str, AbstractionProfile] = {
    "mcp": AbstractionProfile(
        id="mcp",
        display_name="Model Context Protocol",
        # The reference abstraction: annotation hints, JSON Schema constraints,
        # and an isError channel are all part of the protocol.
        expressible=_ALL - {SecurityProperty.CLIENT_VALIDATION},
        evidence=Evidence.SPECIFIED,
        note=(
            "Validation is the server's responsibility, so the protocol has no "
            "client-side notion of it."
        ),
    ),
    "langchain": AbstractionProfile(
        id="langchain",
        display_name="LangChain / LangGraph",
        expressible=frozenset(
            {
                SecurityProperty.READ_ONLY,
                SecurityProperty.DESTRUCTIVE,
                SecurityProperty.IDEMPOTENT,
                SecurityProperty.OPEN_WORLD,
                SecurityProperty.INPUT_CONSTRAINTS,
                SecurityProperty.DESCRIPTION_INTEGRITY,
            }
        ),
        evidence=Evidence.MEASURED,
        note=(
            "P0: annotations preserved on StructuredTool.metadata, constraints preserved in "
            "args_schema, description verbatim. No client-side validation; MCP error results "
            "arrive as ordinary tool content."
        ),
    ),
    "crewai": AbstractionProfile(
        id="crewai",
        display_name="CrewAI",
        expressible=frozenset({SecurityProperty.INPUT_CONSTRAINTS}),
        evidence=Evidence.MEASURED,
        note=(
            "P0: CrewAIMCPTool exposes no carrier for annotation hints, and the adapter "
            "prepends a serialised argument schema to every description. Constraints survive "
            "as a rebuilt Pydantic model."
        ),
    ),
    "claude-code": AbstractionProfile(
        id="claude-code",
        display_name="Claude Code",
        # The widest set of any target. Permission rules are evaluated before a
        # tool runs, so client-side validation and the consequence of
        # destructiveHint are both expressible without generating any code.
        expressible=frozenset(
            {
                SecurityProperty.READ_ONLY,
                SecurityProperty.DESTRUCTIVE,
                SecurityProperty.IDEMPOTENT,
                SecurityProperty.OPEN_WORLD,
                SecurityProperty.INPUT_CONSTRAINTS,
                SecurityProperty.CLIENT_VALIDATION,
                SecurityProperty.ERROR_CHANNEL,
                SecurityProperty.DESCRIPTION_INTEGRITY,
            }
        ),
        evidence=Evidence.SPECIFIED,
        note=(
            "Permission allow/ask/deny rules are evaluated before a tool runs, which "
            "is what makes destructiveHint actionable rather than merely stored. Read "
            "from documented behaviour; not yet measured against a live session."
        ),
    ),
    "openai_fc": AbstractionProfile(
        id="openai_fc",
        display_name="OpenAI function calling",
        expressible=frozenset(
            {SecurityProperty.INPUT_CONSTRAINTS, SecurityProperty.DESCRIPTION_INTEGRITY}
        ),
        evidence=Evidence.SPECIFIED,
        note=(
            "The function schema carries name, description and JSON Schema parameters and has "
            "no field for behavioural hints. Not yet measured against a live client."
        ),
    ),
}


@dataclass(frozen=True)
class Guard:
    """A compensating behaviour to emit, and the property it stands in for."""

    kind: GuardKind
    compensates: SecurityProperty


@dataclass(frozen=True)
class TranslationPlan:
    """The outcome of lowering one tool's properties into one target.

    Computed before any code is generated, so a lossy translation is a decision
    the caller can see rather than a silent degradation.
    """

    source: str
    target: str
    declared: frozenset[SecurityProperty]
    preserved: frozenset[SecurityProperty]
    compensated: frozenset[SecurityProperty]
    unsupported: frozenset[SecurityProperty]
    guards: tuple[Guard, ...]

    @property
    def is_lossless(self) -> bool:
        return not self.compensated and not self.unsupported

    @property
    def status(self) -> str:
        """The value recorded in a registry entry's ``compat`` block."""
        if self.unsupported:
            return "unsupported"
        if self.compensated:
            return "compensated"
        return "full"


def profile(abstraction_id: str) -> AbstractionProfile:
    """Look up an abstraction, failing with the list of known ids."""
    try:
        return PROFILES[abstraction_id]
    except KeyError:
        known = ", ".join(sorted(PROFILES))
        message = f"unknown abstraction {abstraction_id!r}; available: {known}"
        raise UsageError(message) from None


def plan_translation(
    declared: frozenset[SecurityProperty],
    source: str,
    target: str,
) -> TranslationPlan:
    """Decide what survives lowering *declared* properties from *source* to *target*.

    A property the target expresses is preserved. One it cannot express is
    compensated when a guard exists for it, and reported as unsupported when
    none does. Nothing is silently dropped.
    """
    profile(source)
    target_profile = profile(target)

    preserved: set[SecurityProperty] = set()
    compensated: set[SecurityProperty] = set()
    unsupported: set[SecurityProperty] = set()
    guards: list[Guard] = []

    for prop in sorted(declared, key=str):
        if target_profile.expresses(prop):
            preserved.add(prop)
            continue
        guard_kind = _COMPENSATION.get(prop)
        if guard_kind is None:
            unsupported.add(prop)
            continue
        compensated.add(prop)
        guards.append(Guard(kind=guard_kind, compensates=prop))

    return TranslationPlan(
        source=source,
        target=target,
        declared=frozenset(declared),
        preserved=frozenset(preserved),
        compensated=frozenset(compensated),
        unsupported=frozenset(unsupported),
        guards=tuple(guards),
    )
