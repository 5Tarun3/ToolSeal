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

from toolseal.core.policy.controls import load_catalogues, resolve
from toolseal.core.policy.model import all_checks

REGISTERED_CHECK_COUNT = 27
DOCUMENTED_CHECK_COUNT = 28


def test_the_engine_registers_every_check_it_claims_to_except_c3() -> None:
    # reference/taxonomy.md documents 28 checks; the engine registers 27.
    # C3 - unverified package or MCP server name - is enforced by ToolGate at
    # `add` time and is never evaluated by `audit`, so a project toolseal did
    # not scaffold is never checked for phantom or lookalike names.
    #
    # Asserted rather than quietly accepted: an audit that silently omits a
    # documented check over-reports the posture of everything it scans. If C3
    # is ever registered, this test fails and is the reminder to attach its
    # control mapping and update the count.
    registered = {check.id for check in all_checks()}

    assert len(registered) == REGISTERED_CHECK_COUNT
    assert "C3" not in registered
    assert REGISTERED_CHECK_COUNT == DOCUMENTED_CHECK_COUNT - 1


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


def test_accountability_has_no_home_in_either_ranked_list() -> None:
    # F1 is the sharpest margin in the mapping. Tool-invocation logging is
    # absent from both the OWASP LLM Top 10 and the agentic Top 10; it survives
    # only in the broader threat taxonomy (T8) and in NIST (MANAGE-4.1). That is
    # a finding about the standards rather than about our taxonomy, so it is
    # pinned here: if a future revision of either ranked list adds an
    # accountability entry, this test fails and reminds us to map it.
    f1 = next(check for check in all_checks() if check.id == "F1")

    assert not any(ref.standard == "owasp-llm-top10" for ref in f1.controls)
    assert not any(ref.standard == "owasp-agentic-top10" for ref in f1.controls)
    assert any(ref.standard == "owasp-agentic-threats" for ref in f1.controls)
    assert any(ref.standard == "nist-ai-rmf" for ref in f1.controls)
