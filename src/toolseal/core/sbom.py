"""CycloneDX software bill of materials for a generated project.

Check `C5` asks for a component inventory so that a newly disclosed advisory can
be matched against a project without re-resolving it. The scaffolder already
knows every direct dependency and its exact version, so it can emit one at
creation time rather than telling the user to go and generate it.

Written by hand against the CycloneDX 1.6 schema rather than through a library.
The document is small and entirely predictable, and a supply-chain tool taking a
dependency in order to describe its dependencies is a poor advert for itself.

**Deliberately undated.** A real CycloneDX document usually carries a
`serialNumber` and a `timestamp`; both are omitted here so that regenerating an
unchanged project produces a byte-identical file. A committed SBOM that changes
on every run is one nobody reviews, and reviewability is the entire point.
"""

from __future__ import annotations

import json
import re
from typing import Any, Final

from toolseal import __version__

SPEC_VERSION: Final = "1.6"
SBOM_FILENAME: Final = "sbom.json"

# `name==version`. Only exact pins produce a component: a range does not identify
# a component, and guessing which version it resolves to would put a claim into
# the document that nothing verified.
PINNED_REQUIREMENT: Final = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*(?P<version>[^\s;]+)\s*$"
)


def _component(name: str, version: str) -> dict[str, Any]:
    purl = f"pkg:pypi/{name}@{version}"
    return {
        "type": "library",
        "bom-ref": purl,
        "name": name,
        "version": version,
        "purl": purl,
    }


def build(project_name: str, requirements: tuple[str, ...]) -> dict[str, Any]:
    """Build a CycloneDX document for *project_name* from pinned *requirements*.

    Unpinned entries are skipped rather than guessed. They are separately a `C1`
    finding, so the omission is already reported elsewhere and does not need to
    be invented here.
    """
    components = []
    for requirement in requirements:
        match = PINNED_REQUIREMENT.match(requirement)
        if match is not None:
            components.append(_component(match.group("name"), match.group("version")))

    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": project_name,
                "name": project_name,
            },
            "tools": {
                "components": [{"type": "application", "name": "toolseal", "version": __version__}]
            },
        },
        "components": sorted(components, key=lambda item: item["bom-ref"]),
    }


def render(project_name: str, requirements: tuple[str, ...]) -> str:
    """The document as it is written to disk: sorted, indented, newline-ended."""
    return json.dumps(build(project_name, requirements), indent=2, sort_keys=True) + "\n"
