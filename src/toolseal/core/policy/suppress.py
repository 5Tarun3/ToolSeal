"""Inline suppression of a finding on a specific line.

Every credential scanner needs this, because test fixtures and documentation
legitimately contain credential-shaped strings. Without a way to say so, the
report fills with known-good noise and people stop reading it - which costs more
than the false positives did.

The syntax is deliberately awkward to type by accident and impossible to apply
broadly:

    api_key = "sk-not-a-real-key"  # toolseal:allow A1 - fixture for the redaction test

* A check id is **required**. A blanket suppression would silence findings
  nobody considered.
* A reason is **required**. A suppression without a justification is
  indistinguishable from someone silencing an inconvenient result.
* It applies to one line only. There is no file-level or directory-level form.
"""

from __future__ import annotations

import re
from typing import Final

MARKER: Final = re.compile(
    r"toolseal:allow\s+(?P<checks>[A-Z]\d+(?:\s*,\s*[A-Z]\d+)*)\s*-\s*(?P<reason>\S.*)"
)


def suppression_for(line: str, check_id: str) -> str | None:
    """The stated reason this line is allowed to fail *check_id*, if any."""
    match = MARKER.search(line)
    if match is None:
        return None

    allowed = {item.strip() for item in match.group("checks").split(",")}
    if check_id not in allowed:
        return None
    return match.group("reason").strip()


def is_suppressed(line: str, check_id: str) -> bool:
    """Whether *line* carries a valid suppression for *check_id*."""
    return suppression_for(line, check_id) is not None
