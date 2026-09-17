"""Study 6's attack suite: the protection numerator, loaded and validated.

The suite is pre-registered. Its cases, their observables and the outcome each
layer is *expected* to produce were committed before any guard was run against
them, and the file's digest is recorded in `research/evaluation-protocol.md`.
This module only reads and validates; it runs nothing.

Expectations were read from source, not observed. A case whose observed outcome
differs from its declared one is a result (Study 6, H4), not a fixture to fix.
"""

from __future__ import annotations

import hashlib
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

SUITE_PATH: Final = Path("research/studies/s6/attack-suite.toml")
PROTOCOL_PATH: Final = Path("research/evaluation-protocol.md")

GUARDS: Final[tuple[str, ...]] = (
    "require_approval",
    "bound_runtime",
    "restrict_egress",
    "validate_against_schema",
    "raise_on_tool_error",
    "redact",
    "minimal_environment",
)
OBSERVABLES: Final = frozenset({"side_effect", "signal", "log_content", "child_env"})
ATTACK_OUTCOMES: Final = frozenset({"blocked", "missed", "not_applicable"})
BENIGN_OUTCOMES: Final = frozenset({"allowed", "false_block", "not_applicable"})
KINDS: Final = frozenset({"attack", "benign"})

_REGISTERED: Final = re.compile(r"attack-suite\.toml` sha256: `([0-9a-f]{64})`")


class SuiteError(ValueError):
    """The suite file does not satisfy the pre-registered schema."""


@dataclass(frozen=True)
class Case:
    id: str
    guard: str
    kind: str
    atlas: str | None
    description: str
    observable: str
    input: str
    expected_decorator: str
    expected_proxy: str
    basis: str


def _text(raw: dict[str, Any], key: str, case_id: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        message = f"case {case_id}: {key!r} must be a non-empty string"
        raise SuiteError(message)
    return value


def _case(raw: dict[str, Any], position: int) -> Case:
    raw_id = raw.get("id")
    case_id = raw_id if isinstance(raw_id, str) else f"#{position}"
    guard = _text(raw, "guard", case_id)
    kind = _text(raw, "kind", case_id)
    observable = _text(raw, "observable", case_id)

    if guard not in GUARDS:
        message = f"case {case_id}: unknown guard {guard!r}"
        raise SuiteError(message)
    if kind not in KINDS:
        message = f"case {case_id}: unknown kind {kind!r}"
        raise SuiteError(message)
    if observable not in OBSERVABLES:
        message = f"case {case_id}: unknown observable {observable!r}"
        raise SuiteError(message)

    expected = raw.get("expected")
    if not isinstance(expected, dict):
        message = f"case {case_id}: 'expected' must be a table with decorator and proxy"
        raise SuiteError(message)
    vocabulary = ATTACK_OUTCOMES if kind == "attack" else BENIGN_OUTCOMES
    outcomes: dict[str, str] = {}
    for layer in ("decorator", "proxy"):
        value = expected.get(layer)
        if value not in vocabulary:
            message = (
                f"case {case_id}: expected.{layer} = {value!r} is not one of "
                f"{sorted(vocabulary)} for a {kind} case"
            )
            raise SuiteError(message)
        outcomes[layer] = value

    atlas = raw.get("atlas")
    if kind == "attack" and not (isinstance(atlas, str) and atlas):
        message = f"case {case_id}: an attack must cite an ATLAS technique"
        raise SuiteError(message)

    return Case(
        id=_text(raw, "id", case_id),
        guard=guard,
        kind=kind,
        atlas=atlas if isinstance(atlas, str) else None,
        description=_text(raw, "description", case_id),
        observable=observable,
        input=_text(raw, "input", case_id),
        expected_decorator=outcomes["decorator"],
        expected_proxy=outcomes["proxy"],
        basis=_text(raw, "basis", case_id),
    )


def load(path: Path = SUITE_PATH) -> tuple[Case, ...]:
    """Every case in the suite, validated. Raises `SuiteError` on any violation."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        message = f"{path} is not valid TOML: {exc}"
        raise SuiteError(message) from None
    raw_cases = data.get("case")
    if not isinstance(raw_cases, list):
        message = f"{path} defines no [[case]] entries"
        raise SuiteError(message)
    return tuple(_case(raw, index) for index, raw in enumerate(raw_cases))


def normalised_digest(path: Path = SUITE_PATH) -> str:
    """SHA-256 of the file with line endings normalised to LF.

    Git converts line endings on Windows checkouts; hashing raw bytes would give
    each platform a different digest and make the registration pin unusable.
    """
    content = path.read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(content).hexdigest()


def registered_digest(protocol: Path = PROTOCOL_PATH) -> str | None:
    """The digest the protocol records for the suite, or None if none is recorded."""
    match = _REGISTERED.search(protocol.read_text(encoding="utf-8"))
    return match.group(1) if match else None
