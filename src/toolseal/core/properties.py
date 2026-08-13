"""The security-property vocabulary, owned by neither side that uses it.

`registry.utd` needs these names to describe a tool; `translate.lattice` needs
them to reason about what a target can express. Putting them in either package
makes the two import each other, which is a cycle that only shows up depending
on which one a caller happens to touch first - the test suite imported them in
the working order for weeks.

A shared vocabulary with no dependencies of its own is the fix. Nothing here
imports from either package, and nothing ever should.
"""

from __future__ import annotations

from enum import StrEnum


class SecurityProperty(StrEnum):
    """The vocabulary shared by descriptors, the lattice, and taxonomy family G.

    One vocabulary rather than three keeps measured evidence, audit findings and
    generated guards directly comparable.
    """

    READ_ONLY = "readOnlyHint"
    DESTRUCTIVE = "destructiveHint"
    IDEMPOTENT = "idempotentHint"
    OPEN_WORLD = "openWorldHint"
    INPUT_CONSTRAINTS = "inputConstraints"
    CLIENT_VALIDATION = "clientValidation"
    ERROR_CHANNEL = "errorChannel"
    DESCRIPTION_INTEGRITY = "descriptionIntegrity"


ANNOTATION_PROPERTIES = frozenset(
    {
        SecurityProperty.READ_ONLY,
        SecurityProperty.DESTRUCTIVE,
        SecurityProperty.IDEMPOTENT,
        SecurityProperty.OPEN_WORLD,
    }
)
