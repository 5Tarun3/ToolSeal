"""Control catalogues: the external obligations a check answers to.

`reference/taxonomy.md` rule 1 requires every check to cite a reason to exist.
This module makes that citation machine-readable, so a failing check can name
the obligation it serves instead of only its own identifier.

Catalogues are data rather than code. A new standard is a file, not a release,
and the loader is deliberately strict: these files decide what the tool claims
about compliance, so a malformed one must fail loudly rather than quietly
shrink the coverage denominator.

Paywalled standards are a real constraint. ISO/IEC 42001 control text cannot be
redistributed, so its catalogue carries identifiers and titles only and sets
``text_included = false``. A test enforces that.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from importlib import resources
from typing import Any, Final

from toolseal.errors import ConfigError

DATA_PACKAGE: Final = "toolseal.data.standards"

VALID_KINDS: Final = frozenset({"standard", "regime"})


@dataclass(frozen=True)
class ControlRef:
    """A pointer from a check to one control in one catalogue."""

    standard: str
    control: str

    def __str__(self) -> str:
        return f"{self.standard}:{self.control}"


@dataclass(frozen=True)
class Control:
    """One obligation within a catalogue."""

    id: str
    title: str
    checkable: bool = True
    """Whether a configuration auditor can assess this at all.

    ``False`` covers obligations no file can answer - workforce training, a
    signed agreement, a documented procedure. They stay in the catalogue so the
    coverage denominator reflects the whole standard rather than the convenient
    part of it.
    """

    url: str | None = None


@dataclass(frozen=True)
class Catalogue:
    """A published standard or regime, and the controls it defines."""

    id: str
    kind: str
    name: str
    version: str
    license: str
    source_url: str
    controls: tuple[Control, ...] = ()
    text_included: bool = False
    """Whether control body text is reproduced here. False for paywalled sources."""

    complete_enumeration: bool = False
    """Whether ``controls`` lists the standard's controls as published, or a
    curated subset.

    A coverage percentage only means "coverage of the standard" when the
    denominator is the standard's full list. Several catalogues here were
    drawn up as shortlists before any check mapping existed, and their
    percentages measure coverage of that shortlist, not of the standard.
    Defaults to ``False`` - the safer assumption is incompleteness, since a
    reader who assumes completeness by default would misread a curated
    catalogue's percentage as reaching further than it does.
    """

    def get(self, control_id: str) -> Control | None:
        return next((c for c in self.controls if c.id == control_id), None)

    def checkable(self) -> tuple[Control, ...]:
        return tuple(c for c in self.controls if c.checkable)


def _require(data: dict[str, Any], key: str, kind: type) -> Any:
    if key not in data:
        message = f"catalogue is missing required field {key!r}"
        raise ConfigError(message)
    value = data[key]
    if not isinstance(value, kind):
        found = type(value).__name__
        message = f"catalogue field {key!r} must be {kind.__name__}, found {found}"
        raise ConfigError(message)
    return value


def _optional_bool(data: dict[str, Any], key: str, default: bool, label: str) -> bool:
    """Fetch an optional boolean field, or explain precisely what is wrong.

    A quoted TOML value (``checkable = "false"``) is a real typo, not a value
    that merely needs coercing. Coercing it with a bare ``bool()`` would turn a
    typo into a silent ``True`` - exactly the wrong direction for a field the
    coverage denominator depends on - so this rejects anything that is not
    TOML's actual boolean type.
    """
    if key not in data:
        return default
    value = data[key]
    if not isinstance(value, bool):
        found = type(value).__name__
        message = f"{label} field {key!r} must be bool, found {found}"
        raise ConfigError(message)
    return value


def _parse_control(raw: Any, index: int) -> Control:
    if not isinstance(raw, dict):
        message = f"control at position {index} must be a table"
        raise ConfigError(message)
    if "id" not in raw:
        message = f"control at position {index} is missing required field 'id'"
        raise ConfigError(message)
    return Control(
        id=str(raw["id"]),
        title=str(raw.get("title", "")),
        checkable=_optional_bool(raw, "checkable", True, f"control at position {index}"),
        url=str(raw["url"]) if raw.get("url") else None,
    )


def parse_catalogue(text: str) -> Catalogue:
    """Parse one catalogue, naming precisely what is wrong when it is malformed."""
    try:
        data: dict[str, Any] = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        message = f"catalogue is not valid TOML: {exc}"
        raise ConfigError(message) from None

    kind = str(_require(data, "kind", str))
    if kind not in VALID_KINDS:
        message = f"catalogue field 'kind' must be one of {sorted(VALID_KINDS)}, found {kind!r}"
        raise ConfigError(message)

    controls = tuple(
        _parse_control(raw, index) for index, raw in enumerate(data.get("control") or ())
    )

    seen: set[str] = set()
    for control in controls:
        if control.id in seen:
            message = f"catalogue defines control {control.id!r} more than once"
            raise ConfigError(message)
        seen.add(control.id)

    return Catalogue(
        id=str(_require(data, "id", str)),
        kind=kind,
        name=str(data.get("name", "")),
        version=str(data.get("version", "")),
        license=str(data.get("license", "")),
        source_url=str(data.get("source_url", "")),
        controls=controls,
        text_included=_optional_bool(data, "text_included", False, "catalogue"),
        complete_enumeration=_optional_bool(data, "complete_enumeration", False, "catalogue"),
    )


def load_catalogues() -> dict[str, Catalogue]:
    """Every catalogue shipped with the package, keyed by id.

    Read through ``importlib.resources`` rather than a filesystem path so this
    works from an installed wheel as well as from a checkout.
    """
    catalogues: dict[str, Catalogue] = {}
    for entry in resources.files(DATA_PACKAGE).iterdir():
        if not entry.name.endswith(".toml"):
            continue
        catalogue = parse_catalogue(entry.read_text(encoding="utf-8"))
        if catalogue.id in catalogues:
            message = f"two catalogues both declare id {catalogue.id!r}"
            raise ConfigError(message)
        catalogues[catalogue.id] = catalogue
    return catalogues


def resolve(ref: ControlRef, catalogues: dict[str, Catalogue] | None = None) -> Control:
    """The control *ref* points at, or a `ConfigError` naming what is missing."""
    available = load_catalogues() if catalogues is None else catalogues

    catalogue = available.get(ref.standard)
    if catalogue is None:
        known = ", ".join(sorted(available)) or "none"
        message = f"unknown standard {ref.standard!r}; loaded catalogues: {known}"
        raise ConfigError(message)

    control = catalogue.get(ref.control)
    if control is None:
        message = f"standard {ref.standard!r} defines no control {ref.control!r}"
        raise ConfigError(message)
    return control
