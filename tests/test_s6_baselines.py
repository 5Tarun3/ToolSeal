"""Study 6's baseline survey, held to the criteria committed before it began."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

BASELINES = Path("research/studies/s6/baselines.toml")
CATEGORIES = {"framework-middleware", "guardrail-library", "mcp-proxy"}
DISPOSITIONS = {"reproduced", "quoted", "excluded"}
VERIFICATION = {"verified", "unverified", "n/a"}
REQUIRED = (
    "name",
    "category",
    "repository",
    "licence",
    "evidence",
    "disposition",
    "criteria_5_6",
    "reason",
)


def _data() -> dict[str, Any]:
    return tomllib.loads(BASELINES.read_text(encoding="utf-8"))


def _records() -> list[dict[str, Any]]:
    records = _data().get("baseline")
    assert isinstance(records, list), "no [[baseline]] records"
    assert records, "the survey is empty"
    return records


def test_every_record_has_the_required_fields() -> None:
    for record in _records():
        for field in REQUIRED:
            value = record.get(field)
            assert isinstance(value, str), f"{record.get('name')}: {field} missing"
            assert value.strip(), f"{record.get('name')}: {field} empty"


def test_categories_dispositions_and_verification_use_the_vocabulary() -> None:
    for record in _records():
        assert record["category"] in CATEGORIES, record["name"]
        assert record["disposition"] in DISPOSITIONS, record["name"]
        assert record["criteria_5_6"] in VERIFICATION, record["name"]


def test_every_category_has_an_included_system() -> None:
    # Criteria: a category with no qualifying system is stated as empty, never
    # silently omitted. This survey found one in each, so none is declared.
    included = {r["category"] for r in _records() if r["disposition"] != "excluded"}
    assert included == CATEGORIES, f"no included system in: {sorted(CATEGORIES - included)}"


def test_a_reproduced_baseline_carries_a_licence() -> None:
    # Criterion 4. A system with no licence cannot be reproduced.
    for record in _records():
        if record["disposition"] == "reproduced":
            assert record["licence"] not in {"NOASSERTION", "none", "unknown"}, record["name"]


def test_verification_status_matches_the_disposition() -> None:
    # Excluded systems were never assessed for reproduction. Reproduced ones
    # must say whether criteria 5-6 are evidenced. A quoted one may carry either
    # - Fides Gateway is quoted precisely because criterion 5 is unverified.
    for record in _records():
        status, disposition = record["criteria_5_6"], record["disposition"]
        if disposition == "excluded":
            assert status == "n/a", record["name"]
        elif disposition == "reproduced":
            assert status in {"verified", "unverified"}, record["name"]


def test_an_included_baseline_quotes_evidence() -> None:
    # No behavioural claim without the source's own words.
    for record in _records():
        if record["disposition"] != "excluded":
            assert not record["evidence"].startswith("no excerpt"), record["name"]
            assert not record["evidence"].startswith("none"), record["name"]
