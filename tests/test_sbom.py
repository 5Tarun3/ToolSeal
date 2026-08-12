"""The generated SBOM (check C5).

Determinism is the property under test. A committed inventory that changes on
every regeneration is one nobody reviews, and reviewability is why it exists.
"""

from __future__ import annotations

import json
from pathlib import Path

from toolseal.core.adapters import ScaffoldSpec
from toolseal.core.audit import audit
from toolseal.core.sbom import SBOM_FILENAME, build, render
from toolseal.core.scaffold import apply_plan, build_plan

PINNED = ("crewai==1.15.14", "ollama==0.6.2")


def test_document_declares_cyclonedx() -> None:
    doc = build("demo", PINNED)

    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"


def test_every_pinned_requirement_becomes_a_component() -> None:
    components = build("demo", PINNED)["components"]

    assert {c["name"] for c in components} == {"crewai", "ollama"}
    assert all(c["purl"].startswith("pkg:pypi/") for c in components)


def test_unpinned_requirements_are_skipped_not_guessed() -> None:
    # A range does not identify a component, and resolving it here would put a
    # claim into the document that nothing verified. C1 reports it separately.
    components = build("demo", ("requests>=2.0", "crewai==1.15.14"))["components"]

    assert {c["name"] for c in components} == {"crewai"}


def test_render_is_byte_identical_across_runs() -> None:
    assert render("demo", PINNED) == render("demo", PINNED)


def test_render_is_order_independent() -> None:
    assert render("demo", PINNED) == render("demo", tuple(reversed(PINNED)))


def test_no_timestamp_or_serial_number() -> None:
    # Both are conventional in CycloneDX and both would make the file churn on
    # every regeneration.
    text = render("demo", PINNED)

    assert "timestamp" not in text
    assert "serialNumber" not in text


def test_scaffold_emits_a_valid_sbom(tmp_path: Path) -> None:
    root = tmp_path / "demo"
    apply_plan(
        build_plan(
            ScaffoldSpec(
                project_name="demo",
                provider_id="ollama",
                framework_id="langgraph",
                workspace_root=root,
            )
        )
    )

    doc = json.loads((root / SBOM_FILENAME).read_text(encoding="utf-8"))

    assert doc["bomFormat"] == "CycloneDX"
    assert doc["components"]
    assert doc["metadata"]["component"]["name"] == "demo"


def test_emitting_the_sbom_closes_c5(tmp_path: Path) -> None:
    root = tmp_path / "demo"
    apply_plan(
        build_plan(
            ScaffoldSpec(
                project_name="demo",
                provider_id="ollama",
                framework_id="langgraph",
                workspace_root=root,
            )
        )
    )

    assert not [f for f in audit(root).findings if f.check_id == "C5"]
