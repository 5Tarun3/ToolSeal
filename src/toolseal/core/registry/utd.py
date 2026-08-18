"""The Unified Tool Descriptor: the registry's normal form for a tool.

A descriptor is a superset of what the supported abstractions can express, so
**lifting into it is lossless and lowering out of it is the only lossy
direction**. That asymmetry is deliberate: it means every loss has exactly one
place where it can be detected, reported and compensated.

Descriptors are the unit the registry stores, `search` queries, and `add tool`
lowers into a project. They are plain data with explicit parsing, not a
validation framework, because the registry index is fetched over the network and
the parse boundary is a trust boundary: malformed input must fail loudly with a
:class:`~toolseal.errors.RegistryError` rather than produce a half-built object.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, ClassVar

from toolseal.core.properties import SecurityProperty
from toolseal.errors import RegistryError

SCHEMA_VERSION = 1


def _require(data: dict[str, Any], key: str, kind: type) -> Any:
    """Fetch a required key of an expected type, or explain precisely what is wrong."""
    if key not in data:
        message = f"descriptor is missing required field {key!r}"
        raise RegistryError(message)
    value = data[key]
    if not isinstance(value, kind):
        found = type(value).__name__
        message = f"descriptor field {key!r} must be {kind.__name__}, found {found}"
        raise RegistryError(message)
    return value


@dataclass(frozen=True)
class ToolSource:
    """Where the tool comes from, precisely enough to fetch it again."""

    kind: str
    registry: str
    package: str
    version: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "registry": self.registry,
            "package": self.package,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolSource:
        return cls(
            kind=_require(data, "kind", str),
            registry=_require(data, "registry", str),
            package=_require(data, "package", str),
            version=_require(data, "version", str),
        )


@dataclass(frozen=True)
class SecurityAnnotations:
    """The author's behavioural declarations.

    ``None`` means *not declared*, which is different from ``False``. A tool that
    never said whether it is destructive is not a tool that said it is safe, and
    conflating the two is how an unannotated tool acquires a reassuring default.
    """

    read_only: bool | None = None
    destructive: bool | None = None
    idempotent: bool | None = None
    open_world: bool | None = None

    _FIELD_TO_PROPERTY: ClassVar[dict[str, SecurityProperty]] = {
        "read_only": SecurityProperty.READ_ONLY,
        "destructive": SecurityProperty.DESTRUCTIVE,
        "idempotent": SecurityProperty.IDEMPOTENT,
        "open_world": SecurityProperty.OPEN_WORLD,
    }

    def declared(self) -> frozenset[SecurityProperty]:
        """Only the hints the author actually set."""
        return frozenset(
            prop
            for name, prop in self._FIELD_TO_PROPERTY.items()
            if getattr(self, name) is not None
        )

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self._FIELD_TO_PROPERTY}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SecurityAnnotations:
        for name in cls._FIELD_TO_PROPERTY:
            value = data.get(name)
            if value is not None and not isinstance(value, bool):
                message = f"annotation {name!r} must be a boolean or absent"
                raise RegistryError(message)
        return cls(
            read_only=data.get("read_only"),
            destructive=data.get("destructive"),
            idempotent=data.get("idempotent"),
            open_world=data.get("open_world"),
        )


@dataclass(frozen=True)
class Provenance:
    """Who published the tool and whether that claim can be checked."""

    repository: str | None = None
    publisher: str | None = None
    signature: str = "none"
    license: str | None = None

    @property
    def is_signed(self) -> bool:
        return self.signature != "none"

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository": self.repository,
            "publisher": self.publisher,
            "signature": self.signature,
            "license": self.license,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Provenance:
        return cls(
            repository=data.get("repository"),
            publisher=data.get("publisher"),
            signature=data.get("signature", "none"),
            license=data.get("license"),
        )


class ComplianceEvidence(StrEnum):
    """How a compliance claim is known.

    Mirrors the ``Evidence`` idiom already established in
    :mod:`toolseal.core.translate.lattice` - a claim's strength travels with
    the claim - with a vocabulary suited to this block rather than reusing
    that enum's members, which describe how well grounded a translation-loss
    table entry is, a different question.

    ``DECLARED`` - the tool's author or a curator stated it.
    ``DERIVED`` - computed from a field the descriptor already measures
    (``permissions``, ``egress_hosts``, ``filesystem_scope``), with the
    derivation recorded in the owning claim's ``derivation``.
    ``UNKNOWN`` - nothing was said. This is the explicit value a claim gets
    when it is absent, following the same rule :class:`SecurityAnnotations`
    already applies to ``None``: a tool that never said whether it touches
    personal data is not a tool that said it does not.
    """

    DECLARED = "DECLARED"
    DERIVED = "DERIVED"
    UNKNOWN = "UNKNOWN"


def _parse_evidence(data: dict[str, Any], context: str) -> tuple[ComplianceEvidence, str | None]:
    """Parse an ``evidence``/``from`` pair, enforcing that DERIVED cites its source.

    A `DERIVED` claim with no recorded derivation is worse than an honest
    `UNKNOWN`: it carries the authority of a computation that never happened.
    """
    raw = _require(data, "evidence", str)
    try:
        evidence = ComplianceEvidence(raw)
    except ValueError:
        valid = ", ".join(e.value for e in ComplianceEvidence)
        message = f"{context} field 'evidence' must be one of {valid}, found {raw!r}"
        raise RegistryError(message) from None

    derivation = data.get("from")
    if derivation is not None and not isinstance(derivation, str):
        found = type(derivation).__name__
        message = f"{context} field 'from' must be str, found {found}"
        raise RegistryError(message)

    if evidence is ComplianceEvidence.DERIVED and not derivation:
        message = (
            f"{context} claims DERIVED evidence but records no 'from' derivation - "
            "an unjustified DERIVED tag is worse than an honest UNKNOWN"
        )
        raise RegistryError(message)

    return evidence, derivation


@dataclass(frozen=True)
class DataClassClaim:
    """One data-classification claim about a tool, with its evidence.

    ``data_class`` is an open vocabulary (``personal_data``, ``health_data``,
    ...); this block does not enumerate one, because the taxonomy of data
    classes belongs to whichever regime cites it, not to the descriptor.
    """

    data_class: str
    evidence: ComplianceEvidence
    derivation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"class": self.data_class, "evidence": self.evidence.value}
        if self.derivation is not None:
            payload["from"] = self.derivation
        return payload

    @classmethod
    def from_dict(cls, data: Any, *, index: int) -> DataClassClaim:
        if not isinstance(data, dict):
            found = type(data).__name__
            message = f"compliance.data_classes[{index}] must be an object, found {found}"
            raise RegistryError(message)
        context = f"compliance.data_classes[{index}]"
        data_class = _require(data, "class", str)
        evidence, derivation = _parse_evidence(data, context)
        return cls(data_class=data_class, evidence=evidence, derivation=derivation)


@dataclass(frozen=True)
class Residency:
    """A jurisdiction claim, bounded to what a host-suffix table can support.

    Deriving a jurisdiction from an arbitrary hostname is not something a
    configuration auditor can do, so the default is ``UNKNOWN`` with no
    regions - never a guess. See ``core/policy/profile.py`` for the bounded
    derivation this block is the output of: each regime file carries a
    ``[residency]`` table mapping host suffixes to regions, and a host
    matching no entry leaves this at its default.
    """

    regions: tuple[str, ...] = ()
    evidence: ComplianceEvidence = ComplianceEvidence.UNKNOWN
    derivation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "regions": list(self.regions),
            "evidence": self.evidence.value,
        }
        if self.derivation is not None:
            payload["from"] = self.derivation
        return payload

    @classmethod
    def from_dict(cls, data: Any) -> Residency:
        if data is None or data == {}:
            return cls()
        if not isinstance(data, dict):
            found = type(data).__name__
            message = f"compliance field 'residency' must be an object, found {found}"
            raise RegistryError(message)

        regions_raw = data.get("regions", [])
        if not isinstance(regions_raw, list) or not all(
            isinstance(region, str) for region in regions_raw
        ):
            message = "compliance.residency field 'regions' must be a list of strings"
            raise RegistryError(message)

        evidence, derivation = _parse_evidence(data, "compliance.residency")
        return cls(regions=tuple(regions_raw), evidence=evidence, derivation=derivation)


@dataclass(frozen=True)
class ControlBearing:
    """One external obligation this tool's configuration bears on.

    Deliberately shallow: this records that a curator or author asserts the
    tool bears on control ``id``, the same way ``Provenance.license`` records
    a claim without validating it against an external list. Resolving ``id``
    against a loaded catalogue is `core/policy/controls.py`'s job, not a
    network-facing parser's.
    """

    id: str
    relation: str = "bears_on"

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "relation": self.relation}

    @classmethod
    def from_dict(cls, data: Any, *, index: int) -> ControlBearing:
        if not isinstance(data, dict):
            found = type(data).__name__
            message = f"compliance.controls[{index}] must be an object, found {found}"
            raise RegistryError(message)
        return cls(
            id=_require(data, "id", str),
            relation=str(data.get("relation", "bears_on")),
        )


@dataclass(frozen=True)
class Compliance:
    """Data-classification, residency, and control-bearing claims for a tool.

    Absent means UNKNOWN, never "clean" - the same rule
    :class:`SecurityAnnotations` applies to an unset boolean, restated here
    for evidence tags. A descriptor that never mentions compliance at all
    parses to ``Compliance()``, whose fields are empty or UNKNOWN rather than
    a negative assertion about the tool.

    Heuristic inference from a tool's name or description is deliberately not
    something this module does anywhere: every claim here is either supplied
    (`DECLARED`) or computed from a field the descriptor already measures
    (`DERIVED`, `core/policy/profile.py`'s bounded residency derivation being
    the one example this project ships).
    """

    data_classes: tuple[DataClassClaim, ...] = ()
    residency: Residency = field(default_factory=Residency)
    controls: tuple[ControlBearing, ...] = ()

    def evidence_for(self, data_class: str) -> ComplianceEvidence:
        """The evidence tag for *data_class*, or UNKNOWN if it was never claimed."""
        for claim in self.data_classes:
            if claim.data_class == data_class:
                return claim.evidence
        return ComplianceEvidence.UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        return {
            "data_classes": [claim.to_dict() for claim in self.data_classes],
            "residency": self.residency.to_dict(),
            "controls": [bearing.to_dict() for bearing in self.controls],
        }

    @classmethod
    def from_dict(cls, data: Any) -> Compliance:
        if data is None:
            return cls()
        if not isinstance(data, dict):
            found = type(data).__name__
            message = f"descriptor field 'compliance' must be an object, found {found}"
            raise RegistryError(message)

        raw_classes = data.get("data_classes", [])
        if not isinstance(raw_classes, list):
            found = type(raw_classes).__name__
            message = f"compliance field 'data_classes' must be a list, found {found}"
            raise RegistryError(message)
        data_classes = tuple(
            DataClassClaim.from_dict(item, index=index) for index, item in enumerate(raw_classes)
        )

        raw_controls = data.get("controls", [])
        if not isinstance(raw_controls, list):
            found = type(raw_controls).__name__
            message = f"compliance field 'controls' must be a list, found {found}"
            raise RegistryError(message)
        controls = tuple(
            ControlBearing.from_dict(item, index=index) for index, item in enumerate(raw_controls)
        )

        return cls(
            data_classes=data_classes,
            residency=Residency.from_dict(data.get("residency")),
            controls=controls,
        )


# JSON Schema keywords that narrow what a caller may pass. Their presence is what
# makes INPUT_CONSTRAINTS a declared property rather than an assumed one.
CONSTRAINT_KEYWORDS = frozenset(
    {
        "enum",
        "const",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "minLength",
        "maxLength",
        "pattern",
        "minItems",
        "maxItems",
    }
)


@dataclass(frozen=True)
class UnifiedToolDescriptor:
    """One tool, normalised. The registry's storage unit.

    ``input_schema`` and ``output_schema`` hold JSON Schema as plain dicts. The
    dataclass is frozen, which prevents rebinding but not mutation of those
    dicts; treat them as read-only.
    """

    id: str
    name: str
    description: str
    source: ToolSource
    input_schema: dict[str, Any] = field(default_factory=dict)
    output_schema: dict[str, Any] | None = None
    annotations: SecurityAnnotations = field(default_factory=SecurityAnnotations)
    permissions: frozenset[str] = frozenset()
    egress_hosts: tuple[str, ...] = ()
    filesystem_scope: str | None = None
    provenance: Provenance = field(default_factory=Provenance)
    compliance: Compliance = field(default_factory=Compliance)
    """Data-classification, residency and control-bearing claims (P49, spec §9).

    Optional and additive: a descriptor that predates this field, or a curator
    who never populated it, parses to ``Compliance()`` rather than failing or
    silently asserting a negative.
    """

    status: str = "unknown"
    """Lifecycle state as the source registry reports it (active, deleted, ...)."""

    is_latest: bool = True
    """Whether this is the newest published version the registry knows of."""

    def has_input_constraints(self) -> bool:
        """Whether any property in the input schema narrows its accepted values."""
        properties = self.input_schema.get("properties")
        if not isinstance(properties, dict):
            return False
        return any(
            isinstance(spec, dict) and CONSTRAINT_KEYWORDS & spec.keys()
            for spec in properties.values()
        )

    def declared_properties(self) -> frozenset[SecurityProperty]:
        """Every security property this descriptor actually asserts.

        This is the input to :func:`~toolseal.core.translate.lattice.plan_translation`.
        Only asserted properties are included, so an undeclared tool produces an
        empty set rather than a set of defaults.
        """
        properties = set(self.annotations.declared())
        if self.has_input_constraints():
            properties.add(SecurityProperty.INPUT_CONSTRAINTS)
        if self.description:
            properties.add(SecurityProperty.DESCRIPTION_INTEGRITY)
        if self.output_schema is not None:
            properties.add(SecurityProperty.ERROR_CHANNEL)
        return frozenset(properties)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "source": self.source.to_dict(),
            "interface": {
                "input_schema": self.input_schema,
                "output_schema": self.output_schema,
            },
            "security": {
                "annotations": self.annotations.to_dict(),
                "permissions": sorted(self.permissions),
                "egress_hosts": list(self.egress_hosts),
                "filesystem_scope": self.filesystem_scope,
            },
            "provenance": self.provenance.to_dict(),
            "compliance": self.compliance.to_dict(),
            "status": self.status,
            "is_latest": self.is_latest,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UnifiedToolDescriptor:
        """Parse a descriptor, rejecting anything malformed.

        This is a trust boundary: index entries arrive over the network.
        """
        version = data.get("schema_version", SCHEMA_VERSION)
        if version != SCHEMA_VERSION:
            message = (
                f"unsupported descriptor schema_version {version!r}; expected {SCHEMA_VERSION}"
            )
            raise RegistryError(message)

        interface = data.get("interface") or {}
        security = data.get("security") or {}
        if not isinstance(interface, dict) or not isinstance(security, dict):
            message = "descriptor fields 'interface' and 'security' must be objects"
            raise RegistryError(message)

        input_schema = interface.get("input_schema") or {}
        if not isinstance(input_schema, dict):
            message = "descriptor field 'interface.input_schema' must be an object"
            raise RegistryError(message)

        output_schema = interface.get("output_schema")
        if output_schema is not None and not isinstance(output_schema, dict):
            message = "descriptor field 'interface.output_schema' must be an object or null"
            raise RegistryError(message)

        egress = security.get("egress_hosts") or []
        if not isinstance(egress, list):
            message = "descriptor field 'security.egress_hosts' must be a list"
            raise RegistryError(message)

        return cls(
            id=_require(data, "id", str),
            name=_require(data, "name", str),
            description=_require(data, "description", str),
            source=ToolSource.from_dict(_require(data, "source", dict)),
            input_schema=input_schema,
            output_schema=output_schema,
            annotations=SecurityAnnotations.from_dict(security.get("annotations") or {}),
            permissions=frozenset(security.get("permissions") or []),
            egress_hosts=tuple(str(host) for host in egress),
            filesystem_scope=security.get("filesystem_scope"),
            provenance=Provenance.from_dict(data.get("provenance") or {}),
            compliance=Compliance.from_dict(data.get("compliance")),
            status=str(data.get("status", "unknown")),
            is_latest=bool(data.get("is_latest", True)),
        )
