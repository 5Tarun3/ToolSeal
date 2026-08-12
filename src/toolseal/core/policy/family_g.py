"""Family G - translation integrity.

The only family grounded in a measurement this project made rather than in
published work. Probe P0 compared what an MCP server declares against what
survives loading it into two frameworks, and found the loss is
**adapter-dependent**: `langchain-mcp-adapters` preserves every annotation hint,
`crewai-tools` drops all of them and rewrites every description.

That asymmetry is why these checks exist. If loss were inherent to translation
the honest advice would be "do not translate tools". Because it is one adapter's
choice, it can be compensated - and a check can insist that it was.

Every check here applies only when a translation actually happened. A project
that binds tools natively has no translation to be unfaithful about.
"""

from __future__ import annotations

from collections.abc import Sequence

from toolseal.core.model import ProjectModel, TranslationRecord
from toolseal.core.policy.model import Check, Finding, Severity, register
from toolseal.core.translate.lattice import ANNOTATION_PROPERTIES

_ANNOTATION_NAMES = frozenset(str(prop) for prop in ANNOTATION_PROPERTIES)


def _translated(model: ProjectModel) -> bool:
    return model.has_translations


def _dropped_annotations(record: TranslationRecord) -> frozenset[str]:
    return frozenset(record.dropped_properties) & _ANNOTATION_NAMES


def _g1(model: ProjectModel) -> Sequence[Finding]:
    return [
        Finding(
            check_id="G1",
            severity=Severity.HIGH,
            title="Security annotation dropped in translation",
            detail=(
                f"{record.tool_name}: {', '.join(sorted(dropped))} declared in "
                f"{record.source_abstraction} but not carried by "
                f"{record.target_abstraction}"
            ),
            location=record.tool_name,
            remediation=(
                "Emit a compensating guard so the consequence of the hint survives, "
                "and record the substitution in the compensation manifest."
            ),
        )
        for record in model.translations
        # Only uncompensated losses are findings. A dropped hint whose behaviour
        # was reinstated is the system working, not a defect.
        if (dropped := _dropped_annotations(record) & record.uncompensated)
    ]


def _g2(model: ProjectModel) -> Sequence[Finding]:
    return [
        Finding(
            check_id="G2",
            severity=Severity.MEDIUM,
            title="Declared constraints are not enforced before dispatch",
            detail=(
                f"{record.tool_name}: input constraints survive translation but nothing "
                "validates them client-side, so an out-of-range call is sent and only "
                "the server refuses it"
            ),
            location=record.tool_name,
            remediation="Validate arguments against the declared schema before dispatch.",
        )
        for record in model.translations
        if not record.validates_client_side
    ]


def _g3(model: ProjectModel) -> Sequence[Finding]:
    return [
        Finding(
            check_id="G3",
            severity=Severity.MEDIUM,
            title="Tool failure is indistinguishable from success",
            detail=(
                f"{record.tool_name}: an error result arrives as ordinary tool content, so "
                "failure cannot be detected without parsing prose"
            ),
            location=record.tool_name,
            remediation="Map error results onto the framework's failure channel.",
        )
        for record in model.translations
        if not record.maps_error_channel
    ]


def _g4(model: ProjectModel) -> Sequence[Finding]:
    return [
        Finding(
            check_id="G4",
            severity=Severity.HIGH,
            title="Property lost with no compensating guard",
            detail=(
                f"{record.tool_name}: {', '.join(sorted(record.uncompensated))} was dropped "
                f"by {record.target_abstraction} and nothing was emitted in its place"
            ),
            location=record.tool_name,
            remediation=(
                "Emit a guard, or record the property as unsupported so the gap is "
                "visible rather than silent."
            ),
        )
        for record in model.translations
        if record.uncompensated
    ]


def _g5(model: ProjectModel) -> Sequence[Finding]:
    return [
        Finding(
            check_id="G5",
            severity=Severity.MEDIUM,
            title="Tool description was rewritten in translation",
            detail=(
                f"{record.tool_name}: {record.target_abstraction} altered the author's "
                "description, so the text reaching the model is not the text that was written"
            ),
            location=record.tool_name,
            remediation=(
                "Preserve the author's description verbatim alongside the binding so the "
                "difference is auditable."
            ),
        )
        for record in model.translations
        if record.mutated_properties
    ]


G1 = register(
    Check(
        id="G1",
        family="G",
        title="Security annotation dropped in translation",
        severity=Severity.HIGH,
        remediation="Emit a compensating guard and record the substitution.",
        run=_g1,
        applies=_translated,
    )
)

G2 = register(
    Check(
        id="G2",
        family="G",
        title="Constraint declared but not enforced client-side",
        severity=Severity.MEDIUM,
        remediation="Validate arguments against the declared schema before dispatch.",
        run=_g2,
        applies=_translated,
    )
)

G3 = register(
    Check(
        id="G3",
        family="G",
        title="Error result indistinguishable from success",
        severity=Severity.MEDIUM,
        remediation="Map error results onto the framework's failure channel.",
        run=_g3,
        applies=_translated,
    )
)

G4 = register(
    Check(
        id="G4",
        family="G",
        title="Unexpressible property with no compensating guard",
        severity=Severity.HIGH,
        remediation="Emit a guard, or record the property as unsupported.",
        run=_g4,
        applies=_translated,
    )
)

G5 = register(
    Check(
        id="G5",
        family="G",
        title="Tool description mutated in translation",
        severity=Severity.MEDIUM,
        remediation="Preserve the author's description verbatim.",
        run=_g5,
        applies=_translated,
    )
)
