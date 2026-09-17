"""Family A's remediation text, checked for advice a deployed project can follow.

Family A asserted the OS keychain was *the* answer in five places. Once a second
backend is legitimate that advice is not merely incomplete, it is impossible to
follow: a container has no keychain, and a container is exactly where the
deployment work points. A check whose remediation cannot be performed is worse
than one with no remediation at all, because it reads as actionable.

These tests read the module's source rather than running the checks. The
alternative - constructing a project that triggers all five - would couple this
file to five unrelated detection paths to assert something about strings.
"""

from __future__ import annotations

import re
from pathlib import Path

from toolseal.core.policy import family_a

#: `remediation=` followed by either a bare string or a parenthesised run of
#: implicitly-concatenated ones. Both forms appear in the module.
_REMEDIATION = re.compile(r"remediation=\(?\s*((?:\"[^\"]*\"\s*)+)", re.MULTILINE)


def _remediations() -> list[str]:
    """Every remediation string family A can emit, findings and checks alike."""
    source = Path(family_a.__file__).read_text(encoding="utf-8")
    return [match.group(1) for match in _REMEDIATION.finditer(source)]


def test_the_sweep_is_non_vacuous() -> None:
    # A sweep over an empty list passes silently, which would make the test
    # below meaningless the moment the regex stopped matching. Family A had
    # five keychain remediations plus A2's and A4's, so the floor is well
    # above zero.
    assert len(_remediations()) >= 5


def test_no_remediation_names_the_keychain_as_the_only_answer() -> None:
    offenders = [
        text
        for text in _remediations()
        if "keychain" in text.lower() and "environment" not in text.lower()
    ]
    assert offenders == [], f"keychain-only remediations remain: {offenders}"


def test_credential_remediations_still_name_the_keychain() -> None:
    # The opposite failure: dropping the keychain entirely would make the
    # advice worse on a workstation, where it is the right answer. Both paths
    # must appear, not one replaced by the other.
    mentions = [text for text in _remediations() if "keychain" in text.lower()]
    assert len(mentions) >= 4
