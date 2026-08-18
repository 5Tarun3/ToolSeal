"""The UTD compliance block (P49): data classification and control references.

Spec: `docs/superpowers/specs/2026-08-13-standards-compliance-policy-design.md`
§9. Reuses the Evidence idiom already established in `translate/lattice.py`: a
claim's strength travels with the claim. `DECLARED` is asserted by an author or
curator; `DERIVED` is computed from a field the descriptor already measures,
with the derivation recorded in `from`; absent means `UNKNOWN`, never "clean" -
the same rule `SecurityAnnotations` already applies to an unset boolean.

This is a trust boundary the same way the rest of `utd.py` is: index entries
arrive over the network, so a malformed compliance block must fail loudly
rather than parse into a half-built claim.
"""

from __future__ import annotations

import pytest

from toolseal.core.registry import (
    Compliance,
    ComplianceEvidence,
    ControlBearing,
    DataClassClaim,
    Provenance,
    Residency,
    SecurityAnnotations,
    ToolSource,
    UnifiedToolDescriptor,
)
from toolseal.errors import RegistryError

MINIMAL = {
    "id": "mcp/postgres@0.5.1#query",
    "name": "query_postgres",
    "description": "Run a read-only query.",
    "source": {
        "kind": "mcp",
        "registry": "npm",
        "package": "@modelcontextprotocol/server-postgres",
        "version": "0.5.1",
    },
}


def descriptor(**overrides: object) -> UnifiedToolDescriptor:
    data: dict[str, object] = {**MINIMAL, **overrides}
    return UnifiedToolDescriptor.from_dict(data)


# --- a descriptor with no compliance block still parses (compatibility) ------


def test_a_descriptor_with_no_compliance_block_still_parses() -> None:
    tool = descriptor()

    assert tool.compliance == Compliance()
    assert tool.compliance.data_classes == ()
    assert tool.compliance.controls == ()


def test_an_absent_compliance_block_reads_residency_as_unknown() -> None:
    tool = descriptor()

    assert tool.compliance.residency.evidence is ComplianceEvidence.UNKNOWN
    assert tool.compliance.residency.regions == ()


# --- absent means UNKNOWN, never "clean" --------------------------------------


def test_an_unclaimed_data_class_reads_as_unknown_not_clean() -> None:
    tool = descriptor(
        compliance={"data_classes": [{"class": "health_data", "evidence": "DECLARED"}]}
    )

    # personal_data was never mentioned - that is not the same as "this tool
    # does not process personal data".
    assert tool.compliance.evidence_for("personal_data") is ComplianceEvidence.UNKNOWN
    assert tool.compliance.evidence_for("health_data") is ComplianceEvidence.DECLARED


def test_an_empty_compliance_table_still_reads_as_unknown() -> None:
    tool = descriptor(compliance={})

    assert tool.compliance.evidence_for("personal_data") is ComplianceEvidence.UNKNOWN


# --- round trip through to_dict/from_dict is lossless -------------------------


def test_round_trip_preserves_every_compliance_field() -> None:
    original = UnifiedToolDescriptor(
        id="mcp/fs@1.0#delete",
        name="delete_file",
        description="Delete a file.",
        source=ToolSource("mcp", "npm", "@example/fs", "1.0.0"),
        annotations=SecurityAnnotations(),
        provenance=Provenance(),
        compliance=Compliance(
            data_classes=(
                DataClassClaim(
                    data_class="personal_data",
                    evidence=ComplianceEvidence.DERIVED,
                    derivation="egress_hosts contains api.example.us",
                ),
                DataClassClaim(data_class="health_data", evidence=ComplianceEvidence.DECLARED),
            ),
            residency=Residency(
                regions=("US",),
                evidence=ComplianceEvidence.DERIVED,
                derivation="egress_hosts",
            ),
            controls=(ControlBearing(id="GDPR-Art44", relation="bears_on"),),
        ),
    )

    restored = UnifiedToolDescriptor.from_dict(original.to_dict())

    assert restored == original
    assert restored.compliance.data_classes[0].derivation == (
        "egress_hosts contains api.example.us"
    )
    assert restored.compliance.data_classes[1].derivation is None


def test_round_trip_with_no_compliance_data_is_still_lossless() -> None:
    original = UnifiedToolDescriptor(
        id="mcp/fs@1.0#delete",
        name="delete_file",
        description="Delete a file.",
        source=ToolSource("mcp", "npm", "@example/fs", "1.0.0"),
    )

    restored = UnifiedToolDescriptor.from_dict(original.to_dict())

    assert restored == original
    assert restored.compliance == Compliance()


# --- malformed input raises RegistryError naming the bad field ----------------


def test_compliance_block_must_be_an_object() -> None:
    with pytest.raises(RegistryError, match="compliance"):
        descriptor(compliance=["not", "an", "object"])


def test_data_classes_must_be_a_list() -> None:
    with pytest.raises(RegistryError, match="data_classes"):
        descriptor(compliance={"data_classes": "personal_data"})


def test_a_data_class_entry_must_be_an_object() -> None:
    with pytest.raises(RegistryError, match="data_classes"):
        descriptor(compliance={"data_classes": ["personal_data"]})


def test_a_data_class_entry_needs_its_class_field() -> None:
    with pytest.raises(RegistryError, match="class"):
        descriptor(compliance={"data_classes": [{"evidence": "DECLARED"}]})


def test_an_unknown_evidence_value_is_refused() -> None:
    with pytest.raises(RegistryError, match="evidence"):
        descriptor(compliance={"data_classes": [{"class": "personal_data", "evidence": "MAYBE"}]})


def test_a_derived_claim_without_a_derivation_is_refused() -> None:
    with pytest.raises(RegistryError, match="from"):
        descriptor(compliance={"data_classes": [{"class": "personal_data", "evidence": "DERIVED"}]})


def test_a_derived_value_records_its_derivation_naming_a_measured_field() -> None:
    tool = descriptor(
        compliance={
            "data_classes": [
                {
                    "class": "personal_data",
                    "evidence": "DERIVED",
                    "from": "egress_hosts contains api.example.us",
                }
            ]
        }
    )

    claim = tool.compliance.data_classes[0]
    assert claim.evidence is ComplianceEvidence.DERIVED
    # The recorded derivation names the actual descriptor field it came from.
    assert "egress_hosts" in (claim.derivation or "")


def test_residency_must_be_an_object() -> None:
    with pytest.raises(RegistryError, match="residency"):
        descriptor(compliance={"residency": ["US"]})


def test_residency_regions_must_be_a_list_of_strings() -> None:
    with pytest.raises(RegistryError, match="regions"):
        descriptor(
            compliance={
                "residency": {"regions": "US", "evidence": "DERIVED", "from": "egress_hosts"}
            }
        )


def test_residency_derived_without_a_derivation_is_refused() -> None:
    with pytest.raises(RegistryError, match="from"):
        descriptor(compliance={"residency": {"regions": ["US"], "evidence": "DERIVED"}})


def test_controls_must_be_a_list() -> None:
    with pytest.raises(RegistryError, match="controls"):
        descriptor(compliance={"controls": "GDPR-Art44"})


def test_a_control_entry_must_be_an_object() -> None:
    with pytest.raises(RegistryError, match="controls"):
        descriptor(compliance={"controls": ["GDPR-Art44"]})


def test_a_control_entry_needs_its_id_field() -> None:
    with pytest.raises(RegistryError, match="id"):
        descriptor(compliance={"controls": [{"relation": "bears_on"}]})


def test_a_control_bearing_defaults_its_relation() -> None:
    tool = descriptor(compliance={"controls": [{"id": "GDPR-Art44"}]})

    assert tool.compliance.controls[0].relation == "bears_on"


def test_wrong_type_reports_both_expected_and_found() -> None:
    with pytest.raises(RegistryError) as caught:
        descriptor(compliance={"data_classes": [{"class": 42, "evidence": "DECLARED"}]})

    message = str(caught.value)
    assert "str" in message and "int" in message
