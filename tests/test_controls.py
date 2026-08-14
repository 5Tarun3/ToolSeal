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
    load_catalogues,
    parse_catalogue,
    resolve,
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


def test_quoted_checkable_is_refused() -> None:
    # A quoted boolean is a real typo, not something to coerce. Coercing it
    # would silently mark an excluded control assessable, inflating the
    # coverage denominator this module is supposed to keep honest.
    source = CATALOGUE.replace("checkable = true", 'checkable = "true"')

    with pytest.raises(ConfigError, match="checkable"):
        parse_catalogue(source)


def test_quoted_text_included_is_refused() -> None:
    source = """
    id = "example-std"
    kind = "standard"
    text_included = "true"
    """

    with pytest.raises(ConfigError, match="text_included"):
        parse_catalogue(source)


def test_complete_enumeration_defaults_false() -> None:
    # The dangerous direction is assuming completeness, so an unlisted flag
    # must mean "curated subset", not "the whole standard".
    assert parse_catalogue(CATALOGUE).complete_enumeration is False


def test_quoted_complete_enumeration_is_refused() -> None:
    # Same trap as checkable and text_included: a quoted value is a typo, not
    # something to coerce toward the safe default.
    source = """
    id = "example-std"
    kind = "standard"
    complete_enumeration = "true"
    """

    with pytest.raises(ConfigError, match="complete_enumeration"):
        parse_catalogue(source)


def test_resolve_returns_control() -> None:
    catalogue = parse_catalogue(CATALOGUE)

    control = resolve(ControlRef("example-std", "EX01"), {"example-std": catalogue})

    assert control == Control(id="EX01", title="First control", checkable=True, url=None)


def test_resolve_unknown_standard_names_what_was_loaded() -> None:
    catalogue = parse_catalogue(CATALOGUE)

    with pytest.raises(ConfigError) as excinfo:
        resolve(ControlRef("nonexistent-std", "EX01"), {"example-std": catalogue})

    message = str(excinfo.value)
    assert "nonexistent-std" in message
    assert "example-std" in message


def test_resolve_unknown_control_names_the_standard() -> None:
    catalogue = parse_catalogue(CATALOGUE)

    with pytest.raises(ConfigError) as excinfo:
        resolve(ControlRef("example-std", "NOPE"), {"example-std": catalogue})

    message = str(excinfo.value)
    assert "example-std" in message
    assert "NOPE" in message


def test_control_ref_renders_readably() -> None:
    assert str(ControlRef("owasp-llm-top10", "LLM02")) == "owasp-llm-top10:LLM02"


def test_catalogue_is_frozen() -> None:
    catalogue = parse_catalogue(CATALOGUE)

    with pytest.raises(AttributeError):
        catalogue.id = "changed"  # type: ignore[misc]

    assert isinstance(catalogue, Catalogue)


# --- shipped catalogues ----------------------------------------------------


def test_owasp_llm_catalogue_ships_and_loads() -> None:
    # Loaded through importlib.resources, so this also proves the data
    # directory is a real package and will survive being installed as a wheel.
    catalogue = load_catalogues()["owasp-llm-top10"]

    assert catalogue.kind == "standard"
    assert len(catalogue.controls) == 10
    assert catalogue.get("LLM06") is not None


def test_owasp_llm_controls_are_all_checkable_or_say_why() -> None:
    catalogue = load_catalogues()["owasp-llm-top10"]

    for control in catalogue.controls:
        assert control.title, f"{control.id} has no title"


def test_every_shipped_catalogue_declares_a_licence() -> None:
    # A catalogue with no stated licence cannot be safely redistributed.
    for catalogue in load_catalogues().values():
        assert catalogue.license, f"{catalogue.id} declares no licence"
        assert catalogue.source_url, f"{catalogue.id} declares no source"


# --- the licence guard -----------------------------------------------------

ISO_MAX_TITLE_WORDS = 12


def test_iso_catalogue_carries_no_control_text() -> None:
    # ISO/IEC 42001 is paywalled and its text is not redistributable. This test
    # is a licence control, not a style check: it fails if anyone pastes clause
    # bodies in. Titles are short labels; a long one means prose crept in.
    catalogue = load_catalogues()["iso-42001"]

    assert catalogue.text_included is False
    assert catalogue.license == "proprietary-reference-only"
    for control in catalogue.controls:
        assert len(control.title.split()) <= ISO_MAX_TITLE_WORDS, (
            f"{control.id} title looks like reproduced text, not a label"
        )


def test_no_catalogue_claims_to_include_text() -> None:
    # v1 ships identifiers and titles only, for every standard.
    for catalogue in load_catalogues().values():
        assert catalogue.text_included is False


def test_all_expected_catalogues_are_present() -> None:
    assert set(load_catalogues()) == {
        "owasp-llm-top10",
        "owasp-agentic-threats",
        "owasp-agentic-top10",
        "nist-ai-rmf",
        "iso-42001",
    }


def test_agentic_threats_and_agentic_top10_are_distinct_documents() -> None:
    # owasp-agentic-threats (T1-T15, Feb 2025) and owasp-agentic-top10
    # (ASI01-ASI10, Dec 2025) are two different OWASP publications that
    # happen to share a topic. They must not collapse into one catalogue or
    # bleed control ids into each other.
    catalogues = load_catalogues()
    threats = catalogues["owasp-agentic-threats"]
    top10 = catalogues["owasp-agentic-top10"]

    assert threats.id != top10.id

    threat_ids = {c.id for c in threats.controls}
    top10_ids = {c.id for c in top10.controls}

    assert all(control_id.startswith("T") for control_id in threat_ids)
    assert all(control_id.startswith("ASI") for control_id in top10_ids)
    assert threat_ids.isdisjoint(top10_ids)


def test_only_the_fully_enumerated_owasp_catalogues_claim_completeness() -> None:
    # owasp-llm-top10, owasp-agentic-top10 and owasp-agentic-threats each list
    # every published item, flagging non-assessable ones individually rather
    # than omitting them - their percentage is coverage of the whole standard.
    # nist-ai-rmf and iso-42001 ship curated shortlists drawn up before any
    # check mapping existed; a coverage percentage over them is a percentage
    # of that shortlist, not of the published standard, and must not claim
    # otherwise.
    catalogues = load_catalogues()

    complete = {
        "owasp-llm-top10",
        "owasp-agentic-top10",
        "owasp-agentic-threats",
    }
    curated = {"nist-ai-rmf", "iso-42001"}

    for catalogue_id in complete:
        assert catalogues[catalogue_id].complete_enumeration is True, catalogue_id
    for catalogue_id in curated:
        assert catalogues[catalogue_id].complete_enumeration is False, catalogue_id
