"""Control catalogues: the external obligations a check answers to.

A catalogue is data, not code, so that adding a standard needs no release. The
tests below care about two things: that a malformed catalogue fails loudly at
the parse boundary rather than producing a half-built object, and that
`checkable` is honoured - a control no configuration auditor can assess must
stay in the denominator as *not assessable*, never silently vanish.
"""

from __future__ import annotations

import pytest

from toolseal.core.policy.controls import (
    Catalogue,
    Control,
    ControlRef,
    parse_catalogue,
)
from toolseal.errors import ConfigError

CATALOGUE = """
id = "example-std"
kind = "standard"
name = "Example Standard"
version = "2025"
license = "CC-BY-SA-4.0"
source_url = "https://example.invalid/std"

[[control]]
id = "EX01"
title = "First control"
checkable = true

[[control]]
id = "EX02"
title = "Second control"
checkable = false
"""


def test_catalogue_parses() -> None:
    catalogue = parse_catalogue(CATALOGUE)

    assert catalogue.id == "example-std"
    assert catalogue.license == "CC-BY-SA-4.0"
    assert len(catalogue.controls) == 2


def test_control_lookup() -> None:
    catalogue = parse_catalogue(CATALOGUE)

    assert catalogue.get("EX01") == Control(
        id="EX01", title="First control", checkable=True, url=None
    )
    assert catalogue.get("NOPE") is None


def test_only_checkable_controls_are_assessable() -> None:
    # A control a config auditor cannot assess stays in the catalogue so the
    # coverage denominator is honest, but never counts as coverable.
    catalogue = parse_catalogue(CATALOGUE)

    assert tuple(c.id for c in catalogue.checkable()) == ("EX01",)


def test_text_included_defaults_false() -> None:
    # Paywalled standards ship identifiers only; the flag records that.
    assert parse_catalogue(CATALOGUE).text_included is False


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ("kind = 'standard'", "id"),
        ("id = 'x'\nkind = 'nonsense'", "kind"),
        ("id = 'x'\nkind = 'standard'\n[[control]]\ntitle = 'no id'", "control"),
    ],
)
def test_malformed_catalogue_is_refused(source: str, message: str) -> None:
    # The parse boundary is a trust boundary: a half-built catalogue would
    # silently under-report coverage.
    with pytest.raises(ConfigError, match=message):
        parse_catalogue(source)


def test_duplicate_control_id_is_refused() -> None:
    doubled = CATALOGUE + "\n[[control]]\nid = 'EX01'\ntitle = 'again'\n"

    with pytest.raises(ConfigError, match="EX01"):
        parse_catalogue(doubled)


def test_control_ref_renders_readably() -> None:
    assert str(ControlRef("owasp-llm-top10", "LLM02")) == "owasp-llm-top10:LLM02"


def test_catalogue_is_frozen() -> None:
    catalogue = parse_catalogue(CATALOGUE)

    with pytest.raises(AttributeError):
        catalogue.id = "changed"  # type: ignore[misc]

    assert isinstance(catalogue, Catalogue)
