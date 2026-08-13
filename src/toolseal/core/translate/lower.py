"""Lowering a descriptor into a framework, and compensating what is lost.

This is the mechanism behind contribution C5. Probe P0 measured that translation
loss is *adapter-dependent* rather than inherent - `langchain-mcp-adapters`
preserves MCP annotation hints, `crewai-tools` drops all of them. Because the
loss is a choice rather than a law, it can be repaired.

Lowering therefore never silently degrades a tool. Each declared property is
either carried by the target, replaced by a generated guard, or reported as
unsupported. Whatever happened is written into a **compensation manifest**, so a
reviewer can see what the target could not express and what was put there
instead.

The guards are behaviour, not annotation. Restoring `destructiveHint` into a
framework with no field for it means wrapping the call in an approval step -
re-establishing the *consequence* of the hint, since the hint itself has nowhere
to live.
"""

from __future__ import annotations

from dataclasses import dataclass
from string import Template
from typing import Any, Final

from toolseal.core.model import TranslationRecord
from toolseal.core.registry.utd import UnifiedToolDescriptor
from toolseal.core.translate.lattice import (
    GuardKind,
    SecurityProperty,
    TranslationPlan,
    plan_translation,
)

MANIFEST_NAME: Final = "compensation.json"


@dataclass(frozen=True)
class GuardCode:
    """A generated guard: the decorator to apply and what it needs imported."""

    kind: GuardKind
    decorator: str
    imports: tuple[str, ...]
    comment: str


# One entry per guard the lattice can synthesise. Keeping the generated source
# here rather than in a framework adapter means a new target inherits every
# guard at once instead of reimplementing them.
_GUARD_CODE: Final[dict[GuardKind, GuardCode]] = {
    GuardKind.REQUIRE_APPROVAL: GuardCode(
        kind=GuardKind.REQUIRE_APPROVAL,
        decorator='@require_approval("declared destructive by its author")',
        imports=("from guards import require_approval",),
        comment=(
            "G1: the source declared destructiveHint, which this framework cannot "
            "carry. The consequence is restored as an approval step."
        ),
    ),
    GuardKind.VALIDATE_INPUT: GuardCode(
        kind=GuardKind.VALIDATE_INPUT,
        decorator="@validate_against_schema(SCHEMA)",
        imports=("from guards import validate_against_schema",),
        comment=(
            "G2: constraints are declared but nothing validates them before "
            "dispatch, so they are enforced here."
        ),
    ),
    GuardKind.MAP_ERROR_CHANNEL: GuardCode(
        kind=GuardKind.MAP_ERROR_CHANNEL,
        decorator="@raise_on_tool_error",
        imports=("from guards import raise_on_tool_error",),
        comment=(
            "G3: an error result arrives as ordinary content, so failure is "
            "mapped onto the framework's failure channel."
        ),
    ),
    GuardKind.ANNOTATE_SIDECAR: GuardCode(
        kind=GuardKind.ANNOTATE_SIDECAR,
        decorator="",
        imports=(),
        comment=(
            "recorded in the compensation manifest: this framework has no field "
            "for the hint, and the hint carries no behaviour to restore."
        ),
    ),
    GuardKind.PRESERVE_DESCRIPTION: GuardCode(
        kind=GuardKind.PRESERVE_DESCRIPTION,
        decorator="",
        imports=(),
        comment=(
            "G5: this framework rewrites tool descriptions, so the author's text "
            "is preserved verbatim as SOURCE_DESCRIPTION."
        ),
    ),
}

_BINDING = Template(
    '"""Generated binding for $tool_name.\n'
    "\n"
    "Lowered from $source into $target by toolseal. Do not edit by hand:\n"
    "regenerating overwrites this file, and the compensation manifest records why\n"
    "each guard is present.\n"
    "\n"
    "Translation status: $status\n"
    '"""\n'
    "\n"
    "from __future__ import annotations\n"
    "\n"
    "from langchain_core.tools import tool\n"
    "$imports\n"
    "\n"
    "# The author's description, verbatim. Recorded because the target framework\n"
    "# may rewrite what the model actually sees.\n"
    "SOURCE_DESCRIPTION = $description\n"
    "\n"
    "SCHEMA = $schema\n"
    "\n"
    "\n"
    "def _not_wired(name: str, arguments: dict[str, object]) -> object:\n"
    "    # A generated binding cannot know how to reach the upstream server.\n"
    "    # Raising beats returning something: a guarded tool that silently did\n"
    "    # nothing would look exactly like one that had worked.\n"
    '    message = name + " is not wired; set DISPATCH to your upstream client."\n'
    "    raise NotImplementedError(message)\n"
    "\n"
    "\n"
    "#: Replace with the callable that performs the upstream call.\n"
    "DISPATCH = _not_wired\n"
    "\n"
    "$guard_comments\n"
    "$decorators@tool\n"
    "def $function_name(**kwargs: object) -> object:\n"
    '    """$short_description"""\n'
    "    return DISPATCH($tool_name_literal, kwargs)\n"
)


def guards_for(plan: TranslationPlan) -> tuple[GuardCode, ...]:
    """The generated guards a plan calls for, deduplicated and ordered."""
    seen: dict[GuardKind, GuardCode] = {}
    for guard in plan.guards:
        code = _GUARD_CODE.get(guard.kind)
        if code is not None:
            seen.setdefault(guard.kind, code)
    return tuple(seen[kind] for kind in sorted(seen, key=str))


def record_for(descriptor: UnifiedToolDescriptor, plan: TranslationPlan) -> TranslationRecord:
    """The auditable trace of one lowering, consumed by check family G."""
    return TranslationRecord(
        tool_name=descriptor.name,
        source_abstraction=plan.source,
        target_abstraction=plan.target,
        dropped_properties=frozenset(str(p) for p in plan.compensated | plan.unsupported),
        mutated_properties=frozenset(),
        guards_emitted=frozenset(str(guard.compensates) for guard in plan.guards),
        validates_client_side=(
            any(guard.kind is GuardKind.VALIDATE_INPUT for guard in plan.guards)
            or SecurityProperty.CLIENT_VALIDATION in plan.preserved
        ),
        maps_error_channel=(
            any(guard.kind is GuardKind.MAP_ERROR_CHANNEL for guard in plan.guards)
            or SecurityProperty.ERROR_CHANNEL in plan.preserved
        ),
    )


def _identifier(name: str) -> str:
    cleaned = "".join(char if char.isalnum() else "_" for char in name.strip().lower())
    cleaned = cleaned.strip("_") or "tool"
    return f"_{cleaned}" if cleaned[0].isdigit() else cleaned


@dataclass(frozen=True)
class Lowering:
    """The complete result of lowering one descriptor into one target."""

    descriptor: UnifiedToolDescriptor
    plan: TranslationPlan
    record: TranslationRecord
    source: str
    guards: tuple[GuardCode, ...]

    @property
    def is_lossless(self) -> bool:
        return self.plan.is_lossless

    def manifest_entry(self) -> dict[str, Any]:
        """One row of the compensation manifest."""
        return {
            "tool": self.descriptor.name,
            "source": self.plan.source,
            "target": self.plan.target,
            "status": self.plan.status,
            "declared": sorted(str(p) for p in self.plan.declared),
            "preserved": sorted(str(p) for p in self.plan.preserved),
            "compensated": sorted(str(p) for p in self.plan.compensated),
            "unsupported": sorted(str(p) for p in self.plan.unsupported),
            "guards": [str(guard.kind) for guard in self.plan.guards],
            "source_description": self.descriptor.description,
        }


def lower(descriptor: UnifiedToolDescriptor, target: str) -> Lowering:
    """Lower *descriptor* into *target*, generating guards for anything lost."""
    plan = plan_translation(
        descriptor.declared_properties(), source=descriptor.source.kind, target=target
    )
    guards = guards_for(plan)

    imports = sorted({line for guard in guards for line in guard.imports})
    decorators = "".join(f"{guard.decorator}\n" for guard in guards if guard.decorator)
    comments = "\n".join(f"# {guard.comment}" for guard in guards)

    first_line = descriptor.description.splitlines()[0] if descriptor.description else ""
    source = _BINDING.substitute(
        tool_name=descriptor.name,
        tool_name_literal=repr(descriptor.name),
        function_name=_identifier(descriptor.name),
        source=plan.source,
        target=plan.target,
        status=plan.status,
        imports="\n".join(imports),
        description=repr(descriptor.description),
        short_description=first_line.replace('"', "'") or "Generated tool binding.",
        schema=repr(descriptor.input_schema),
        guard_comments=comments,
        decorators=decorators,
    )

    return Lowering(
        descriptor=descriptor,
        plan=plan,
        record=record_for(descriptor, plan),
        source=source,
        guards=guards,
    )


def ungeneratable_guard_kinds() -> frozenset[GuardKind]:
    """Guard kinds the lattice can promise but this module cannot generate.

    Empty today, and a test keeps it that way. A non-empty set would mean the
    lattice offers a compensation the generator cannot deliver, which must fail
    loudly rather than quietly emit a binding with a missing guard.
    """
    return frozenset(GuardKind) - frozenset(_GUARD_CODE)
