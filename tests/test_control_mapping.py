"""Every check cites a published obligation, or says why it cannot.

`reference/taxonomy.md` rule 1 requires a grounding citation per check. Until
now that citation lived only in prose, where nothing could verify it. These
tests make the citation load-bearing: a control reference that resolves to
nothing fails the suite, and a check with neither a mapping nor a stated reason
fails it too.

The second condition is the uncomfortable one, and it is deliberate. A check
that cites no standard is either ahead of the standards or is an opinion, and
the project's own risk table lists "taxonomy reads as arbitrary" as a high
severity risk. This is the test that keeps us honest about which we have.
"""

from __future__ import annotations

import re

from toolseal.core.policy.controls import load_catalogues, resolve
from toolseal.core.policy.model import all_checks

REGISTERED_CHECK_COUNT = 28
DOCUMENTED_CHECK_COUNT = 28


def test_the_engine_registers_every_check_it_claims_to() -> None:
    registered = {check.id for check in all_checks()}

    assert len(registered) == REGISTERED_CHECK_COUNT
    assert REGISTERED_CHECK_COUNT == DOCUMENTED_CHECK_COUNT


def test_every_control_reference_resolves() -> None:
    # A citation to a control that does not exist is worse than no citation.
    catalogues = load_catalogues()

    for check in all_checks():
        for ref in check.controls:
            resolve(ref, catalogues)  # raises ConfigError if it does not exist


def test_every_check_is_mapped_or_explains_why_not() -> None:
    for check in all_checks():
        assert check.controls or check.unmapped_reason, (
            f"{check.id} cites no standard and gives no reason"
        )


def test_a_mapped_check_does_not_also_claim_to_be_unmapped() -> None:
    for check in all_checks():
        assert not (check.controls and check.unmapped_reason), (
            f"{check.id} is both mapped and marked unmapped"
        )


def test_credential_checks_cite_sensitive_information_disclosure() -> None:
    # Spot check with a known-correct answer, so a wholesale mis-wiring of the
    # mapping is caught rather than only a structural error.
    a1 = next(check for check in all_checks() if check.id == "A1")

    assert any(ref.control == "LLM02" for ref in a1.controls)


def test_overprovisioning_checks_cite_excessive_agency() -> None:
    b1 = next(check for check in all_checks() if check.id == "B1")

    assert any(ref.control == "LLM06" for ref in b1.controls)


def test_accountability_has_no_checkable_home_in_either_ranked_list() -> None:
    # F1 cites owasp-agentic-top10:ASI08 and ASI09 - the OWASP threat
    # taxonomy's own crosswalk for T8 says it is "carried directly into"
    # both - but every control resolved from that catalogue on F1 is
    # checkable = false: accountability is absorbed into two composite,
    # runtime failure categories rather than named as its own checkable
    # ranked-list entry. The OWASP LLM Top 10 still has no place for it at
    # all. That is a finding about the standards rather than about our
    # taxonomy, so it is pinned here: if a future revision of either ranked
    # list adds a *checkable* accountability entry, this test fails and
    # reminds us to map it.
    catalogues = load_catalogues()
    f1 = next(check for check in all_checks() if check.id == "F1")

    assert not any(ref.standard == "owasp-llm-top10" for ref in f1.controls)
    assert any(ref.standard == "owasp-agentic-threats" for ref in f1.controls)
    assert any(ref.standard == "nist-ai-rmf" for ref in f1.controls)

    agentic_top10_refs = [ref for ref in f1.controls if ref.standard == "owasp-agentic-top10"]
    assert {ref.control for ref in agentic_top10_refs} == {"ASI08", "ASI09"}
    assert all(not resolve(ref, catalogues).checkable for ref in agentic_top10_refs)


# --- the drift guard -------------------------------------------------------

_TABLE_ROW: re.Pattern[str] = re.compile(r"^\| `([A-Z]\d+)` \| (.+) \|$", re.MULTILINE)


def _table_in(document: str) -> dict[str, frozenset[str]]:
    """Parse the `## Control mapping` table into ``{check_id: {"std:ctrl", ...}}``.

    Bounded to the section between the `## Control mapping` and `## Totals`
    headings, so the family tables above it (`| ID | Check | Severity |`) and
    anything below Totals can never be mistaken for this one.
    """
    start = document.index("## Control mapping")
    end = document.index("## Totals", start)
    section = document[start:end]
    return {
        check_id: frozenset(ref.strip() for ref in cell.split("·"))
        for check_id, cell in _TABLE_ROW.findall(section)
    }


def test_the_document_table_matches_the_code_row_for_row() -> None:
    # `str(ref) in document` only proves a citation survives *somewhere* in the
    # file - it cannot catch two rows swapped, a row left behind for a check
    # that was withdrawn or never registered, or a row carrying one control the
    # code does not. Parsing the table and comparing it to the code set-for-set
    # closes all three; this is what makes the intro's "cannot drift apart" and
    # Open items' "this document agree" literally true rather than aspirational.
    from pathlib import Path

    document = Path("reference/taxonomy.md").read_text(encoding="utf-8")
    documented = _table_in(document)
    coded = {check.id: frozenset(str(ref) for ref in check.controls) for check in all_checks()}

    missing_rows = set(coded) - set(documented)
    assert not missing_rows, f"checks with no row in taxonomy.md: {sorted(missing_rows)}"

    stale_rows = set(documented) - set(coded)
    assert not stale_rows, f"taxonomy.md rows for unregistered checks: {sorted(stale_rows)}"

    for check_id in coded:
        assert documented[check_id] == coded[check_id], (
            f"{check_id}: taxonomy.md says {sorted(documented[check_id])}, "
            f"code says {sorted(coded[check_id])}"
        )


def test_the_document_declares_the_catalogues_it_cites() -> None:
    from pathlib import Path

    document = Path("reference/taxonomy.md").read_text(encoding="utf-8")

    for catalogue_id in load_catalogues():
        assert catalogue_id in document, f"taxonomy.md never mentions {catalogue_id}"


# --- MITRE ATLAS -----------------------------------------------------------


def test_atlas_is_loaded_as_a_catalogue() -> None:
    catalogues = load_catalogues()

    assert "mitre-atlas" in catalogues
    atlas = catalogues["mitre-atlas"]
    assert atlas.name
    assert atlas.version == "2026.09"


def test_atlas_records_its_licence() -> None:
    # The sourcing discipline every other catalogue follows: a third-party
    # taxonomy is redistributed under a licence, and the file says which.
    assert load_catalogues()["mitre-atlas"].license == "Apache-2.0"


def test_atlas_is_declared_a_curated_subset() -> None:
    # ATLAS 2026.09 publishes 120 techniques and 88 sub-techniques. This
    # catalogue lists the handful a configuration auditor can bear on, so a
    # coverage figure over it measures the selection, not ATLAS. Claiming
    # complete_enumeration would make that percentage a lie.
    assert not load_catalogues()["mitre-atlas"].complete_enumeration


def test_atlas_ids_use_the_published_form() -> None:
    # AML.Txxxx or AML.Txxxx.yyy. A typo'd id resolves to nothing, which would
    # silently drop a citation rather than failing loudly.
    pattern = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")
    controls = load_catalogues()["mitre-atlas"].controls

    assert controls, "catalogue is empty"
    for control in controls:
        assert pattern.match(control.id), f"{control.id} is not an ATLAS technique id"
        assert control.title, f"{control.id} has no title"


def test_atlas_is_actually_cited() -> None:
    # A catalogue nothing cites is dead weight: it lengthens the standards
    # list while answering for nothing.
    cited = {ref.standard for check in all_checks() for ref in check.controls}

    assert "mitre-atlas" in cited


def test_credential_checks_cite_the_atlas_credential_technique() -> None:
    # Spot check with a known-correct answer, in the style of the OWASP spot
    # checks above: A1 is "credential literal in tracked source", which is
    # exactly AML.T0083, "Credentials from AI Agent Configuration".
    a1 = next(check for check in all_checks() if check.id == "A1")
    atlas = {ref.control for ref in a1.controls if ref.standard == "mitre-atlas"}

    assert "AML.T0083" in atlas


def test_supply_chain_checks_cite_the_atlas_supply_chain_techniques() -> None:
    c_checks = [check for check in all_checks() if check.id.startswith("C")]
    assert c_checks, "family C is empty"

    cited = {
        ref.control for check in c_checks for ref in check.controls if ref.standard == "mitre-atlas"
    }

    assert "AML.T0010" in cited
    # C3 is the typosquat check; Malicious Package is its ATLAS name.
    assert "AML.T0011.001" in cited


def test_no_check_cites_an_uncheckable_atlas_technique() -> None:
    # AML.T0051 and AML.T0080 are listed so the gap is visible, not so a check
    # can claim to answer them. A citation to one would be the catalogue lying
    # about this project's reach - the exact failure `checkable = false`
    # exists to prevent.
    catalogues = load_catalogues()

    for check in all_checks():
        for ref in check.controls:
            if ref.standard == "mitre-atlas":
                assert resolve(ref, catalogues).checkable, (
                    f"{check.id} cites {ref.control}, which is marked not checkable"
                )


def test_every_checkable_atlas_technique_is_cited_by_something() -> None:
    # This catalogue is a curated subset chosen as "what our checks bear on".
    # A checkable entry nothing cites means the selection rule was not
    # followed, and it would quietly drag the coverage percentage down while
    # looking like a gap in the checks rather than a gap in the curation.
    catalogues = load_catalogues()
    checkable = {c.id for c in catalogues["mitre-atlas"].checkable()}
    assert checkable, "no checkable ATLAS controls"

    cited = {
        ref.control
        for check in all_checks()
        for ref in check.controls
        if ref.standard == "mitre-atlas"
    }

    assert checkable - cited == set(), f"checkable but uncited: {sorted(checkable - cited)}"
